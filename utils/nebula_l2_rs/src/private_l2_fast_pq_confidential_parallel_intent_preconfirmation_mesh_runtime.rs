use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelIntentPreconfirmationMeshRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime-v1";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_KEM_SUITE:
    &str = "ML-KEM-1024-intent-envelope";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_CHAIN_ID:
    &str = "nebula-l2-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MESH_LANES: usize = 8;
pub const DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_REPLAY_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_GRANTS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 65_536;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 450;
pub const DEFAULT_QUORUM_THRESHOLD_BPS: u64 = 6_700;
pub const DEFAULT_LOW_FEE_THRESHOLD_BPS: u64 = 12;
pub const DEFAULT_REBATE_BPS: u64 = 5;
pub const DEFAULT_REDACTION_BUDGET_BYTES: u64 = 64 * 1024;
pub const DEFAULT_REPLAY_FENCE_TTL_SLOTS: u64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MeshLaneKind {
    PrivateContractCall,
    ConfidentialSwap,
    BridgeExit,
    TokenMintBurn,
    PaymentChannelClose,
    OracleUpdate,
    GovernanceAction,
    Emergency,
}

impl MeshLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialSwap => "confidential_swap",
            Self::BridgeExit => "bridge_exit",
            Self::TokenMintBurn => "token_mint_burn",
            Self::PaymentChannelClose => "payment_channel_close",
            Self::OracleUpdate => "oracle_update",
            Self::GovernanceAction => "governance_action",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::PaymentChannelClose => 8_800,
            Self::PrivateContractCall => 8_200,
            Self::ConfidentialSwap => 7_700,
            Self::BridgeExit => 7_100,
            Self::TokenMintBurn => 6_000,
            Self::OracleUpdate => 4_800,
            Self::GovernanceAction => 3_600,
        }
    }

    pub fn default_target_ms(self) -> u64 {
        match self {
            Self::Emergency => 160,
            Self::PaymentChannelClose => 280,
            Self::PrivateContractCall => 350,
            Self::ConfidentialSwap => 420,
            Self::BridgeExit => 650,
            Self::TokenMintBurn => 500,
            Self::OracleUpdate => 750,
            Self::GovernanceAction => 1_200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BatchStatus {
    Open,
    Sealed,
    Preconfirmed,
    Included,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Preconfirmed => "preconfirmed",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReceiptStatus {
    Pending,
    Active,
    Included,
    Settled,
    Challenged,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttestationStatus {
    Collected,
    QuorumReached,
    Rejected,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collected => "collected",
            Self::QuorumReached => "quorum_reached",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReplayFenceKind {
    IntentNullifier,
    CiphertextNonce,
    OperatorSequence,
    LaneEpoch,
    ReceiptBinding,
}

impl ReplayFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentNullifier => "intent_nullifier",
            Self::CiphertextNonce => "ciphertext_nonce",
            Self::OperatorSequence => "operator_sequence",
            Self::LaneEpoch => "lane_epoch",
            Self::ReceiptBinding => "receipt_binding",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThrottleMode {
    Observe,
    SoftCap,
    HardCap,
    Paused,
}

impl ThrottleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::SoftCap => "soft_cap",
            Self::HardCap => "hard_cap",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Paid,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Paid => "paid",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RedactionClass {
    PublicSummary,
    OperatorOnly,
    AuditorOnly,
    Sealed,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicSummary => "public_summary",
            Self::OperatorOnly => "operator_only",
            Self::AuditorOnly => "auditor_only",
            Self::Sealed => "sealed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub signature_suite: String,
    pub kem_suite: String,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_attestations: usize,
    pub max_replay_fences: usize,
    pub max_rebates: usize,
    pub max_redaction_grants: usize,
    pub max_operator_summaries: usize,
    pub target_preconfirmation_ms: u64,
    pub quorum_threshold_bps: u64,
    pub low_fee_threshold_bps: u64,
    pub rebate_bps: u64,
    pub redaction_budget_bytes: u64,
    pub replay_fence_ttl_slots: u64,
    pub allow_emergency_lane: bool,
    pub allow_low_fee_rebates: bool,
    pub require_pq_quorum: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_HASH_SUITE.to_string(),
            signature_suite: PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_SIGNATURE_SUITE.to_string(),
            kem_suite: PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_KEM_SUITE.to_string(),
            max_batches: DEFAULT_MAX_BATCHES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_replay_fences: DEFAULT_MAX_REPLAY_FENCES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_grants: DEFAULT_MAX_REDACTION_GRANTS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            quorum_threshold_bps: DEFAULT_QUORUM_THRESHOLD_BPS,
            low_fee_threshold_bps: DEFAULT_LOW_FEE_THRESHOLD_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            redaction_budget_bytes: DEFAULT_REDACTION_BUDGET_BYTES,
            replay_fence_ttl_slots: DEFAULT_REPLAY_FENCE_TTL_SLOTS,
            allow_emergency_lane: true,
            allow_low_fee_rebates: true,
            require_pq_quorum: true,
        }
    }
}

impl Config {
    pub fn state_root(&self) -> String {
        root_for_json("config", &json!(self))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub batches_opened: u64,
    pub batches_sealed: u64,
    pub batches_preconfirmed: u64,
    pub intents_encrypted: u64,
    pub receipts_issued: u64,
    pub attestations_collected: u64,
    pub quorum_attestations: u64,
    pub replay_fences_written: u64,
    pub throttle_events: u64,
    pub low_fee_rebates_accrued: u64,
    pub low_fee_rebates_paid: u64,
    pub redaction_grants_opened: u64,
    pub redaction_bytes_reserved: u64,
    pub redaction_bytes_spent: u64,
    pub operator_summaries_published: u64,
    pub disputes_opened: u64,
    pub expired_objects: u64,
}

impl Counters {
    pub fn state_root(&self) -> String {
        root_for_json("counters", &json!(self))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lane_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub attestation_root: String,
    pub replay_fence_root: String,
    pub throttle_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn state_root(&self) -> String {
        root_for_json("roots", &json!(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshLane {
    pub lane_id: String,
    pub lane_kind: MeshLaneKind,
    pub operator_id: String,
    pub epoch: u64,
    pub target_preconfirmation_ms: u64,
    pub weight: u64,
    pub max_batch_weight: u64,
    pub fee_cap_bps: u64,
    pub throttle_mode: ThrottleMode,
    pub paused: bool,
    pub encrypted_mempool_root: String,
    pub latest_batch_id: Option<String>,
}

impl MeshLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "weight": self.weight,
            "max_batch_weight": self.max_batch_weight,
            "fee_cap_bps": self.fee_cap_bps,
            "throttle_mode": self.throttle_mode.as_str(),
            "paused": self.paused,
            "encrypted_mempool_root": self.encrypted_mempool_root,
            "latest_batch_id": self.latest_batch_id,
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("lane", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub nullifier: String,
    pub ciphertext_commitment: String,
    pub pq_envelope_commitment: String,
    pub fee_bps: u64,
    pub max_latency_ms: u64,
    pub redaction_class: RedactionClass,
    pub redacted_bytes: u64,
    pub replay_fence_id: String,
}

impl EncryptedIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "nullifier": self.nullifier,
            "ciphertext_commitment": self.ciphertext_commitment,
            "pq_envelope_commitment": self.pq_envelope_commitment,
            "fee_bps": self.fee_bps,
            "max_latency_ms": self.max_latency_ms,
            "redaction_class": self.redaction_class.as_str(),
            "redacted_bytes": self.redacted_bytes,
            "replay_fence_id": self.replay_fence_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntentBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub status: BatchStatus,
    pub opened_slot: u64,
    pub sealed_slot: Option<u64>,
    pub preconfirmed_slot: Option<u64>,
    pub intent_count: u64,
    pub aggregate_fee_bps: u64,
    pub aggregate_weight: u64,
    pub privacy_set_size: u64,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub intent_commitment_root: String,
    pub intents: Vec<EncryptedIntent>,
}

impl EncryptedIntentBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "opened_slot": self.opened_slot,
            "sealed_slot": self.sealed_slot,
            "preconfirmed_slot": self.preconfirmed_slot,
            "intent_count": self.intent_count,
            "aggregate_fee_bps": self.aggregate_fee_bps,
            "aggregate_weight": self.aggregate_weight,
            "privacy_set_size": self.privacy_set_size,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "intent_commitment_root": self.intent_commitment_root,
            "intents": self.intents.iter().map(EncryptedIntent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("encrypted_intent_batch", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub status: ReceiptStatus,
    pub issued_slot: u64,
    pub expires_slot: u64,
    pub preconfirmation_root: String,
    pub attestation_root: String,
    pub replay_fence_root: String,
    pub redaction_root: String,
    pub operator_id: String,
    pub latency_ms: u64,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "issued_slot": self.issued_slot,
            "expires_slot": self.expires_slot,
            "preconfirmation_root": self.preconfirmation_root,
            "attestation_root": self.attestation_root,
            "replay_fence_root": self.replay_fence_root,
            "redaction_root": self.redaction_root,
            "operator_id": self.operator_id,
            "latency_ms": self.latency_ms,
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("preconfirmation_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqQuorumAttestation {
    pub attestation_id: String,
    pub receipt_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub status: AttestationStatus,
    pub signer_count: u64,
    pub quorum_power_bps: u64,
    pub threshold_bps: u64,
    pub pq_signature_root: String,
    pub signer_set_root: String,
    pub transcript_root: String,
    pub collected_slot: u64,
}

impl PqQuorumAttestation {
    pub fn has_quorum(&self) -> bool {
        self.quorum_power_bps >= self.threshold_bps
            && self.status == AttestationStatus::QuorumReached
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "signer_count": self.signer_count,
            "quorum_power_bps": self.quorum_power_bps,
            "threshold_bps": self.threshold_bps,
            "pq_signature_root": self.pq_signature_root,
            "signer_set_root": self.signer_set_root,
            "transcript_root": self.transcript_root,
            "collected_slot": self.collected_slot,
            "has_quorum": self.has_quorum(),
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("pq_quorum_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub kind: ReplayFenceKind,
    pub lane_id: String,
    pub object_id: String,
    pub commitment: String,
    pub first_seen_slot: u64,
    pub expires_slot: u64,
    pub consumed: bool,
}

impl ReplayFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "lane_id": self.lane_id,
            "object_id": self.object_id,
            "commitment": self.commitment,
            "first_seen_slot": self.first_seen_slot,
            "expires_slot": self.expires_slot,
            "consumed": self.consumed,
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("replay_fence", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneThrottle {
    pub throttle_id: String,
    pub lane_id: String,
    pub mode: ThrottleMode,
    pub window_start_slot: u64,
    pub window_end_slot: u64,
    pub max_intents: u64,
    pub observed_intents: u64,
    pub max_weight: u64,
    pub observed_weight: u64,
    pub reason: String,
}

impl LaneThrottle {
    pub fn is_exceeded(&self) -> bool {
        self.observed_intents > self.max_intents || self.observed_weight > self.max_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "lane_id": self.lane_id,
            "mode": self.mode.as_str(),
            "window_start_slot": self.window_start_slot,
            "window_end_slot": self.window_end_slot,
            "max_intents": self.max_intents,
            "observed_intents": self.observed_intents,
            "max_weight": self.max_weight,
            "observed_weight": self.observed_weight,
            "reason": self.reason,
            "is_exceeded": self.is_exceeded(),
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("lane_throttle", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub status: RebateStatus,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub confidential_amount_commitment: String,
    pub claimant_commitment: String,
    pub accrued_slot: u64,
    pub paid_slot: Option<u64>,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "confidential_amount_commitment": self.confidential_amount_commitment,
            "claimant_commitment": self.claimant_commitment,
            "accrued_slot": self.accrued_slot,
            "paid_slot": self.paid_slot,
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("low_fee_rebate", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionBudget {
    pub grant_id: String,
    pub lane_id: String,
    pub batch_id: String,
    pub redaction_class: RedactionClass,
    pub bytes_granted: u64,
    pub bytes_spent: u64,
    pub auditor_commitment: String,
    pub expires_slot: u64,
}

impl RedactionBudget {
    pub fn remaining_bytes(&self) -> u64 {
        self.bytes_granted.saturating_sub(self.bytes_spent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "grant_id": self.grant_id,
            "lane_id": self.lane_id,
            "batch_id": self.batch_id,
            "redaction_class": self.redaction_class.as_str(),
            "bytes_granted": self.bytes_granted,
            "bytes_spent": self.bytes_spent,
            "remaining_bytes": self.remaining_bytes(),
            "auditor_commitment": self.auditor_commitment,
            "expires_slot": self.expires_slot,
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("redaction_budget", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub lane_ids: Vec<String>,
    pub batches_preconfirmed: u64,
    pub receipts_issued: u64,
    pub quorum_rate_bps: u64,
    pub median_latency_ms: u64,
    pub low_fee_rebate_bps: u64,
    pub throttle_events: u64,
    pub redaction_bytes_spent: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "lane_ids": self.lane_ids,
            "batches_preconfirmed": self.batches_preconfirmed,
            "receipts_issued": self.receipts_issued,
            "quorum_rate_bps": self.quorum_rate_bps,
            "median_latency_ms": self.median_latency_ms,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "throttle_events": self.throttle_events,
            "redaction_bytes_spent": self.redaction_bytes_spent,
            "summary_root": self.summary_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_for_json("operator_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_slot: u64,
    pub lanes: BTreeMap<String, MeshLane>,
    pub batches: BTreeMap<String, EncryptedIntentBatch>,
    pub receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub attestations: BTreeMap<String, PqQuorumAttestation>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub throttles: BTreeMap<String, LaneThrottle>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            current_slot: 1_730_000,
            lanes: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            throttles: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.install_devnet_lanes();
        let _ = state.open_encrypted_batch(
            "batch-private-contract-0001",
            "lane-private-contract",
            vec![
                state.devnet_intent("intent-contract-0001", "lane-private-contract", 7, 11_000),
                state.devnet_intent("intent-contract-0002", "lane-private-contract", 8, 9_500),
                state.devnet_intent("intent-contract-0003", "lane-private-contract", 5, 7_750),
            ],
            4_096,
        );
        let _ = state.open_encrypted_batch(
            "batch-swap-0001",
            "lane-confidential-swap",
            vec![
                state.devnet_intent("intent-swap-0001", "lane-confidential-swap", 4, 6_400),
                state.devnet_intent("intent-swap-0002", "lane-confidential-swap", 6, 8_200),
            ],
            8_192,
        );
        let _ = state.seal_batch("batch-private-contract-0001", state.current_slot + 1);
        let _ = state.collect_quorum_for_batch(
            "batch-private-contract-0001",
            "receipt-private-contract-0001",
            "attestation-private-contract-0001",
            19,
            7_420,
            state.current_slot + 2,
        );
        let _ = state.seal_batch("batch-swap-0001", state.current_slot + 2);
        let _ = state.collect_quorum_for_batch(
            "batch-swap-0001",
            "receipt-swap-0001",
            "attestation-swap-0001",
            17,
            7_010,
            state.current_slot + 3,
        );
        let _ = state.apply_lane_throttle(
            "throttle-private-contract-0001",
            "lane-private-contract",
            ThrottleMode::SoftCap,
            1_730_000,
            1_730_032,
            5_000,
            3,
            250_000,
            28_250,
            "devnet warm path capacity guard",
        );
        let _ = state.grant_redaction_budget(
            "redaction-contract-0001",
            "lane-private-contract",
            "batch-private-contract-0001",
            RedactionClass::AuditorOnly,
            DEFAULT_REDACTION_BUDGET_BYTES,
            4_352,
            state.current_slot + 512,
        );
        let _ = state.publish_operator_summary("summary-operator-alpha-0001", "operator-alpha", 11);
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut map) = record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        root_for_json("state", &self.public_record_without_state_root())
    }

    pub fn roots(&self) -> Roots {
        self.compute_roots()
    }

    pub fn advance_slot(&mut self, slot: u64) -> Result<String> {
        if slot < self.current_slot {
            return Err(format!(
                "slot regression rejected: current={} requested={}",
                self.current_slot, slot
            ));
        }
        self.current_slot = slot;
        self.expire_objects();
        self.refresh_roots();
        Ok(self.state_root())
    }

    pub fn register_lane(
        &mut self,
        lane_id: impl Into<String>,
        lane_kind: MeshLaneKind,
        operator_id: impl Into<String>,
    ) -> Result<String> {
        let lane_id = lane_id.into();
        if self.lanes.contains_key(&lane_id) {
            return Err(format!("lane already registered: {lane_id}"));
        }
        if lane_kind == MeshLaneKind::Emergency && !self.config.allow_emergency_lane {
            return Err("emergency lane disabled by config".to_string());
        }
        let operator_id = operator_id.into();
        let encrypted_mempool_root = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:lane:mempool",
            &[HashPart::Str(&lane_id), HashPart::Str(&operator_id)],
            32,
        );
        let lane = MeshLane {
            lane_id: lane_id.clone(),
            lane_kind,
            operator_id,
            epoch: 0,
            target_preconfirmation_ms: lane_kind.default_target_ms(),
            weight: lane_kind.default_weight(),
            max_batch_weight: lane_kind.default_weight() * 64,
            fee_cap_bps: self.config.low_fee_threshold_bps.saturating_mul(3),
            throttle_mode: ThrottleMode::Observe,
            paused: false,
            encrypted_mempool_root,
            latest_batch_id: None,
        };
        self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_registered += 1;
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_encrypted_batch(
        &mut self,
        batch_id: impl Into<String>,
        lane_id: impl Into<String>,
        intents: Vec<EncryptedIntent>,
        privacy_set_size: u64,
    ) -> Result<String> {
        let batch_id = batch_id.into();
        let lane_id = lane_id.into();
        if self.batches.len() >= self.config.max_batches {
            return Err("batch capacity exhausted".to_string());
        }
        if self.batches.contains_key(&batch_id) {
            return Err(format!("batch already exists: {batch_id}"));
        }
        let lane = self
            .lanes
            .get(&lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        if lane.paused || lane.throttle_mode == ThrottleMode::Paused {
            return Err(format!("lane paused: {lane_id}"));
        }
        self.check_intents(&lane_id, &intents)?;
        let aggregate_fee_bps = average_fee_bps(&intents);
        let aggregate_weight = intents.iter().map(|intent| intent.max_latency_ms).sum();
        let ciphertext_root = merkle_values(
            "batch:ciphertexts",
            intents
                .iter()
                .map(|intent| Value::String(intent.ciphertext_commitment.clone()))
                .collect(),
        );
        let nullifier_root = merkle_values(
            "batch:nullifiers",
            intents
                .iter()
                .map(|intent| Value::String(intent.nullifier.clone()))
                .collect(),
        );
        let intent_commitment_root = merkle_values(
            "batch:intents",
            intents
                .iter()
                .map(EncryptedIntent::public_record)
                .collect::<Vec<_>>(),
        );
        for intent in &intents {
            self.write_replay_fence(
                intent.replay_fence_id.clone(),
                ReplayFenceKind::IntentNullifier,
                lane_id.clone(),
                intent.intent_id.clone(),
                intent.nullifier.clone(),
            )?;
            self.consumed_nullifiers.insert(intent.nullifier.clone());
            if self.config.allow_low_fee_rebates
                && intent.fee_bps <= self.config.low_fee_threshold_bps
            {
                self.accrue_low_fee_rebate(&batch_id, &lane_id, intent)?;
            }
        }
        let intent_count = intents.len() as u64;
        let batch = EncryptedIntentBatch {
            batch_id: batch_id.clone(),
            lane_id: lane_id.clone(),
            status: BatchStatus::Open,
            opened_slot: self.current_slot,
            sealed_slot: None,
            preconfirmed_slot: None,
            intent_count,
            aggregate_fee_bps,
            aggregate_weight,
            privacy_set_size,
            ciphertext_root,
            nullifier_root,
            intent_commitment_root,
            intents,
        };
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.latest_batch_id = Some(batch_id.clone());
            lane.encrypted_mempool_root = batch.intent_commitment_root.clone();
        }
        self.batches.insert(batch_id.clone(), batch);
        self.counters.batches_opened += 1;
        self.counters.intents_encrypted += intent_count;
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn seal_batch(&mut self, batch_id: &str, sealed_slot: u64) -> Result<String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
        if batch.status != BatchStatus::Open {
            return Err(format!("batch not open: {batch_id}"));
        }
        if sealed_slot < batch.opened_slot {
            return Err(format!("sealed slot before open slot: {batch_id}"));
        }
        batch.status = BatchStatus::Sealed;
        batch.sealed_slot = Some(sealed_slot);
        let batch_root = batch.state_root();
        self.current_slot = self.current_slot.max(sealed_slot);
        self.counters.batches_sealed += 1;
        self.refresh_roots();
        Ok(batch_root)
    }

    pub fn collect_quorum_for_batch(
        &mut self,
        batch_id: &str,
        receipt_id: impl Into<String>,
        attestation_id: impl Into<String>,
        signer_count: u64,
        quorum_power_bps: u64,
        collected_slot: u64,
    ) -> Result<String> {
        let receipt_id = receipt_id.into();
        let attestation_id = attestation_id.into();
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exhausted".to_string());
        }
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation capacity exhausted".to_string());
        }
        if self.receipts.contains_key(&receipt_id) {
            return Err(format!("receipt already exists: {receipt_id}"));
        }
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation already exists: {attestation_id}"));
        }
        let (lane_id, batch_root, replay_fence_root, redaction_root, opened_slot) = {
            let batch = self
                .batches
                .get(batch_id)
                .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
            if batch.status != BatchStatus::Sealed {
                return Err(format!("batch not sealed: {batch_id}"));
            }
            (
                batch.lane_id.clone(),
                batch.state_root(),
                self.roots.replay_fence_root.clone(),
                self.roots.redaction_budget_root.clone(),
                batch.opened_slot,
            )
        };
        let lane = self
            .lanes
            .get(&lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        let status = if quorum_power_bps >= self.config.quorum_threshold_bps {
            AttestationStatus::QuorumReached
        } else {
            AttestationStatus::Collected
        };
        if self.config.require_pq_quorum && status != AttestationStatus::QuorumReached {
            return Err(format!(
                "quorum below threshold: power={} threshold={}",
                quorum_power_bps, self.config.quorum_threshold_bps
            ));
        }
        let signer_set_root = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:signers",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(&receipt_id),
                HashPart::U64(signer_count),
            ],
            32,
        );
        let transcript_root = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:transcript",
            &[
                HashPart::Str(batch_id),
                HashPart::Str(&lane_id),
                HashPart::Str(&batch_root),
                HashPart::U64(collected_slot),
            ],
            32,
        );
        let pq_signature_root = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:pq-signature-root",
            &[
                HashPart::Str(&signer_set_root),
                HashPart::Str(&transcript_root),
                HashPart::U64(quorum_power_bps),
            ],
            32,
        );
        let attestation = PqQuorumAttestation {
            attestation_id: attestation_id.clone(),
            receipt_id: receipt_id.clone(),
            batch_id: batch_id.to_string(),
            lane_id: lane_id.clone(),
            status,
            signer_count,
            quorum_power_bps: quorum_power_bps.min(MAX_BPS),
            threshold_bps: self.config.quorum_threshold_bps,
            pq_signature_root,
            signer_set_root,
            transcript_root,
            collected_slot,
        };
        let receipt = PreconfirmationReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: batch_id.to_string(),
            lane_id: lane_id.clone(),
            status: ReceiptStatus::Active,
            issued_slot: collected_slot,
            expires_slot: collected_slot + self.config.replay_fence_ttl_slots,
            preconfirmation_root: batch_root,
            attestation_root: attestation.state_root(),
            replay_fence_root,
            redaction_root,
            operator_id: lane.operator_id.clone(),
            latency_ms: collected_slot.saturating_sub(opened_slot) * 100,
        };
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = BatchStatus::Preconfirmed;
            batch.preconfirmed_slot = Some(collected_slot);
        }
        self.attestations.insert(attestation_id, attestation);
        self.receipts.insert(receipt_id.clone(), receipt);
        self.current_slot = self.current_slot.max(collected_slot);
        self.counters.attestations_collected += 1;
        self.counters.quorum_attestations += 1;
        self.counters.receipts_issued += 1;
        self.counters.batches_preconfirmed += 1;
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn apply_lane_throttle(
        &mut self,
        throttle_id: impl Into<String>,
        lane_id: impl Into<String>,
        mode: ThrottleMode,
        window_start_slot: u64,
        window_end_slot: u64,
        max_intents: u64,
        observed_intents: u64,
        max_weight: u64,
        observed_weight: u64,
        reason: impl Into<String>,
    ) -> Result<String> {
        let throttle_id = throttle_id.into();
        let lane_id = lane_id.into();
        if self.throttles.contains_key(&throttle_id) {
            return Err(format!("throttle already exists: {throttle_id}"));
        }
        let lane = self
            .lanes
            .get_mut(&lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        lane.throttle_mode = mode;
        lane.paused = mode == ThrottleMode::Paused;
        let throttle = LaneThrottle {
            throttle_id: throttle_id.clone(),
            lane_id,
            mode,
            window_start_slot,
            window_end_slot,
            max_intents,
            observed_intents,
            max_weight,
            observed_weight,
            reason: reason.into(),
        };
        self.throttles.insert(throttle_id.clone(), throttle);
        self.counters.throttle_events += 1;
        self.refresh_roots();
        Ok(throttle_id)
    }

    pub fn grant_redaction_budget(
        &mut self,
        grant_id: impl Into<String>,
        lane_id: impl Into<String>,
        batch_id: impl Into<String>,
        redaction_class: RedactionClass,
        bytes_granted: u64,
        bytes_spent: u64,
        expires_slot: u64,
    ) -> Result<String> {
        let grant_id = grant_id.into();
        let lane_id = lane_id.into();
        let batch_id = batch_id.into();
        if self.redaction_budgets.len() >= self.config.max_redaction_grants {
            return Err("redaction grant capacity exhausted".to_string());
        }
        if self.redaction_budgets.contains_key(&grant_id) {
            return Err(format!("redaction grant already exists: {grant_id}"));
        }
        if !self.lanes.contains_key(&lane_id) {
            return Err(format!("unknown lane: {lane_id}"));
        }
        if !self.batches.contains_key(&batch_id) {
            return Err(format!("unknown batch: {batch_id}"));
        }
        if bytes_granted > self.config.redaction_budget_bytes {
            return Err(format!(
                "redaction budget exceeds config: {} > {}",
                bytes_granted, self.config.redaction_budget_bytes
            ));
        }
        let auditor_commitment = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:redaction-auditor",
            &[
                HashPart::Str(&grant_id),
                HashPart::Str(&lane_id),
                HashPart::Str(&batch_id),
                HashPart::U64(bytes_granted),
            ],
            32,
        );
        let grant = RedactionBudget {
            grant_id: grant_id.clone(),
            lane_id,
            batch_id,
            redaction_class,
            bytes_granted,
            bytes_spent: bytes_spent.min(bytes_granted),
            auditor_commitment,
            expires_slot,
        };
        self.counters.redaction_grants_opened += 1;
        self.counters.redaction_bytes_reserved += bytes_granted;
        self.counters.redaction_bytes_spent += grant.bytes_spent;
        self.redaction_budgets.insert(grant_id.clone(), grant);
        self.refresh_roots();
        Ok(grant_id)
    }

    pub fn pay_rebate(&mut self, rebate_id: &str, paid_slot: u64) -> Result<String> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate: {rebate_id}"))?;
        if matches!(rebate.status, RebateStatus::Paid | RebateStatus::Cancelled) {
            return Err(format!("rebate not payable: {rebate_id}"));
        }
        rebate.status = RebateStatus::Paid;
        rebate.paid_slot = Some(paid_slot);
        let rebate_root = rebate.state_root();
        self.counters.low_fee_rebates_paid += 1;
        self.current_slot = self.current_slot.max(paid_slot);
        self.refresh_roots();
        Ok(rebate_root)
    }

    pub fn publish_operator_summary(
        &mut self,
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
        epoch: u64,
    ) -> Result<String> {
        let summary_id = summary_id.into();
        let operator_id = operator_id.into();
        if self.operator_summaries.len() >= self.config.max_operator_summaries {
            return Err("operator summary capacity exhausted".to_string());
        }
        if self.operator_summaries.contains_key(&summary_id) {
            return Err(format!("summary already exists: {summary_id}"));
        }
        let lane_ids = self
            .lanes
            .values()
            .filter(|lane| lane.operator_id == operator_id)
            .map(|lane| lane.lane_id.clone())
            .collect::<Vec<_>>();
        let receipt_count = self
            .receipts
            .values()
            .filter(|receipt| receipt.operator_id == operator_id)
            .count() as u64;
        let batches_preconfirmed = self
            .batches
            .values()
            .filter(|batch| {
                batch.status == BatchStatus::Preconfirmed && lane_ids.contains(&batch.lane_id)
            })
            .count() as u64;
        let mut latencies = self
            .receipts
            .values()
            .filter(|receipt| receipt.operator_id == operator_id)
            .map(|receipt| receipt.latency_ms)
            .collect::<Vec<_>>();
        latencies.sort_unstable();
        let median_latency_ms = latencies
            .get(latencies.len().saturating_sub(1) / 2)
            .copied()
            .unwrap_or(0);
        let quorum_rate_bps = if receipt_count == 0 {
            0
        } else {
            self.attestations
                .values()
                .filter(|attestation| {
                    attestation.has_quorum() && lane_ids.contains(&attestation.lane_id)
                })
                .count() as u64
                * MAX_BPS
                / receipt_count
        };
        let redaction_bytes_spent = self
            .redaction_budgets
            .values()
            .filter(|budget| lane_ids.contains(&budget.lane_id))
            .map(|budget| budget.bytes_spent)
            .sum::<u64>();
        let summary_payload = json!({
            "summary_id": summary_id,
            "operator_id": operator_id,
            "epoch": epoch,
            "lane_ids": lane_ids,
            "receipt_count": receipt_count,
            "batches_preconfirmed": batches_preconfirmed,
            "quorum_rate_bps": quorum_rate_bps,
            "median_latency_ms": median_latency_ms,
            "redaction_bytes_spent": redaction_bytes_spent,
        });
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_id,
            epoch,
            lane_ids,
            batches_preconfirmed,
            receipts_issued: receipt_count,
            quorum_rate_bps,
            median_latency_ms,
            low_fee_rebate_bps: self.config.rebate_bps,
            throttle_events: self.counters.throttle_events,
            redaction_bytes_spent,
            summary_root: root_for_json("operator_summary_payload", &summary_payload),
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.operator_summaries_published += 1;
        self.refresh_roots();
        Ok(summary_id)
    }

    fn install_devnet_lanes(&mut self) {
        let lanes = [
            (
                "lane-private-contract",
                MeshLaneKind::PrivateContractCall,
                "operator-alpha",
            ),
            (
                "lane-confidential-swap",
                MeshLaneKind::ConfidentialSwap,
                "operator-alpha",
            ),
            (
                "lane-bridge-exit",
                MeshLaneKind::BridgeExit,
                "operator-beta",
            ),
            (
                "lane-token-mint-burn",
                MeshLaneKind::TokenMintBurn,
                "operator-beta",
            ),
            (
                "lane-payment-channel",
                MeshLaneKind::PaymentChannelClose,
                "operator-gamma",
            ),
            ("lane-oracle", MeshLaneKind::OracleUpdate, "operator-gamma"),
            (
                "lane-governance",
                MeshLaneKind::GovernanceAction,
                "operator-delta",
            ),
            ("lane-emergency", MeshLaneKind::Emergency, "operator-delta"),
        ];
        for (lane_id, lane_kind, operator_id) in lanes {
            let _ = self.register_lane(lane_id, lane_kind, operator_id);
        }
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.compute_roots_without_state_root();
        json!({
            "protocol_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_SCHEMA_VERSION,
            "current_slot": self.current_slot,
            "config": self.config,
            "counters": self.counters,
            "roots": roots,
            "lanes": self.lanes.values().map(MeshLane::public_record).collect::<Vec<_>>(),
            "batches": self.batches.values().map(EncryptedIntentBatch::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(PreconfirmationReceipt::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqQuorumAttestation::public_record).collect::<Vec<_>>(),
            "replay_fences": self.replay_fences.values().map(ReplayFence::public_record).collect::<Vec<_>>(),
            "throttles": self.throttles.values().map(LaneThrottle::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
            "consumed_nullifier_root": merkle_values(
                "consumed_nullifiers",
                self.consumed_nullifiers.iter().cloned().map(Value::String).collect()
            ),
        })
    }

    fn compute_roots_without_state_root(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            lane_root: merkle_values(
                "lanes",
                self.lanes.values().map(MeshLane::public_record).collect(),
            ),
            batch_root: merkle_values(
                "batches",
                self.batches
                    .values()
                    .map(EncryptedIntentBatch::public_record)
                    .collect(),
            ),
            receipt_root: merkle_values(
                "receipts",
                self.receipts
                    .values()
                    .map(PreconfirmationReceipt::public_record)
                    .collect(),
            ),
            attestation_root: merkle_values(
                "attestations",
                self.attestations
                    .values()
                    .map(PqQuorumAttestation::public_record)
                    .collect(),
            ),
            replay_fence_root: merkle_values(
                "replay_fences",
                self.replay_fences
                    .values()
                    .map(ReplayFence::public_record)
                    .collect(),
            ),
            throttle_root: merkle_values(
                "throttles",
                self.throttles
                    .values()
                    .map(LaneThrottle::public_record)
                    .collect(),
            ),
            rebate_root: merkle_values(
                "rebates",
                self.rebates
                    .values()
                    .map(LowFeeRebate::public_record)
                    .collect(),
            ),
            redaction_budget_root: merkle_values(
                "redaction_budgets",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record)
                    .collect(),
            ),
            operator_summary_root: merkle_values(
                "operator_summaries",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record)
                    .collect(),
            ),
            state_root: String::new(),
        }
    }

    fn compute_roots(&self) -> Roots {
        let mut roots = self.compute_roots_without_state_root();
        roots.state_root = self.state_root();
        roots
    }

    fn refresh_roots(&mut self) {
        self.roots = self.compute_roots();
    }

    fn check_intents(&self, lane_id: &str, intents: &[EncryptedIntent]) -> Result<()> {
        if intents.is_empty() {
            return Err("empty encrypted intent batch rejected".to_string());
        }
        let mut local_nullifiers = BTreeSet::new();
        for intent in intents {
            if intent.fee_bps > MAX_BPS {
                return Err(format!("fee bps out of range for {}", intent.intent_id));
            }
            if intent.max_latency_ms == 0 {
                return Err(format!(
                    "zero latency intent rejected: {}",
                    intent.intent_id
                ));
            }
            if intent.redacted_bytes > self.config.redaction_budget_bytes {
                return Err(format!(
                    "redaction bytes exceed budget: {}",
                    intent.intent_id
                ));
            }
            if !local_nullifiers.insert(intent.nullifier.clone()) {
                return Err(format!(
                    "duplicate nullifier in batch: {}",
                    intent.nullifier
                ));
            }
            if self.consumed_nullifiers.contains(&intent.nullifier) {
                return Err(format!("replayed nullifier rejected: {}", intent.nullifier));
            }
            if self.replay_fences.contains_key(&intent.replay_fence_id) {
                return Err(format!(
                    "replayed fence rejected: {}",
                    intent.replay_fence_id
                ));
            }
            let expected_prefix = format!("fence-{lane_id}-");
            if !intent.replay_fence_id.starts_with(&expected_prefix) {
                return Err(format!(
                    "replay fence lane mismatch: {} expected prefix {}",
                    intent.replay_fence_id, expected_prefix
                ));
            }
        }
        Ok(())
    }

    fn write_replay_fence(
        &mut self,
        fence_id: String,
        kind: ReplayFenceKind,
        lane_id: String,
        object_id: String,
        commitment: String,
    ) -> Result<()> {
        if self.replay_fences.len() >= self.config.max_replay_fences {
            return Err("replay fence capacity exhausted".to_string());
        }
        if self.replay_fences.contains_key(&fence_id) {
            return Err(format!("replay fence already exists: {fence_id}"));
        }
        let fence = ReplayFence {
            fence_id: fence_id.clone(),
            kind,
            lane_id,
            object_id,
            commitment,
            first_seen_slot: self.current_slot,
            expires_slot: self.current_slot + self.config.replay_fence_ttl_slots,
            consumed: true,
        };
        self.replay_fences.insert(fence_id, fence);
        self.counters.replay_fences_written += 1;
        Ok(())
    }

    fn accrue_low_fee_rebate(
        &mut self,
        batch_id: &str,
        lane_id: &str,
        intent: &EncryptedIntent,
    ) -> Result<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exhausted".to_string());
        }
        let rebate_id = format!("rebate-{}", intent.intent_id);
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!("rebate already exists: {rebate_id}"));
        }
        let confidential_amount_commitment = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:rebate-amount",
            &[
                HashPart::Str(&rebate_id),
                HashPart::Str(batch_id),
                HashPart::U64(intent.fee_bps),
                HashPart::U64(self.config.rebate_bps),
            ],
            32,
        );
        let claimant_commitment = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:rebate-claimant",
            &[
                HashPart::Str(&rebate_id),
                HashPart::Str(&intent.nullifier),
                HashPart::Str(&intent.pq_envelope_commitment),
            ],
            32,
        );
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            intent_id: intent.intent_id.clone(),
            batch_id: batch_id.to_string(),
            lane_id: lane_id.to_string(),
            status: RebateStatus::Accrued,
            fee_bps: intent.fee_bps,
            rebate_bps: self.config.rebate_bps,
            confidential_amount_commitment,
            claimant_commitment,
            accrued_slot: self.current_slot,
            paid_slot: None,
        };
        self.rebates.insert(rebate_id, rebate);
        self.counters.low_fee_rebates_accrued += 1;
        Ok(())
    }

    fn expire_objects(&mut self) {
        for batch in self.batches.values_mut() {
            if matches!(batch.status, BatchStatus::Open | BatchStatus::Sealed)
                && self.current_slot > batch.opened_slot + self.config.replay_fence_ttl_slots
            {
                batch.status = BatchStatus::Expired;
                self.counters.expired_objects += 1;
            }
        }
        for receipt in self.receipts.values_mut() {
            if matches!(
                receipt.status,
                ReceiptStatus::Pending | ReceiptStatus::Active
            ) && self.current_slot > receipt.expires_slot
            {
                receipt.status = ReceiptStatus::Revoked;
                self.counters.expired_objects += 1;
            }
        }
        for fence in self.replay_fences.values_mut() {
            if self.current_slot > fence.expires_slot {
                fence.consumed = false;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.status == RebateStatus::Accrued
                && self.current_slot > rebate.accrued_slot + self.config.replay_fence_ttl_slots
            {
                rebate.status = RebateStatus::Claimable;
            }
        }
    }

    fn devnet_intent(
        &self,
        intent_id: &str,
        lane_id: &str,
        fee_bps: u64,
        max_latency_ms: u64,
    ) -> EncryptedIntent {
        let nullifier = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:devnet-nullifier",
            &[HashPart::Str(intent_id), HashPart::Str(lane_id)],
            32,
        );
        let ciphertext_commitment = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:devnet-ciphertext",
            &[HashPart::Str(intent_id), HashPart::Str(&nullifier)],
            32,
        );
        let pq_envelope_commitment = domain_hash(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:devnet-pq-envelope",
            &[HashPart::Str(intent_id), HashPart::Str(&ciphertext_commitment)],
            32,
        );
        EncryptedIntent {
            intent_id: intent_id.to_string(),
            nullifier,
            ciphertext_commitment,
            pq_envelope_commitment,
            fee_bps,
            max_latency_ms,
            redaction_class: RedactionClass::AuditorOnly,
            redacted_bytes: 512 + fee_bps * 8,
            replay_fence_id: format!("fence-{lane_id}-{intent_id}"),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_fast_pq_confidential_parallel_intent_preconfirmation_mesh_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_fast_pq_confidential_parallel_intent_preconfirmation_mesh_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

fn average_fee_bps(intents: &[EncryptedIntent]) -> u64 {
    if intents.is_empty() {
        0
    } else {
        intents.iter().map(|intent| intent.fee_bps).sum::<u64>() / intents.len() as u64
    }
}

fn merkle_values(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(
        &format!(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:{domain}"
        ),
        &leaves,
    )
}

fn root_for_json(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!(
            "private-l2-fast-pq-confidential-parallel-intent-preconfirmation-mesh-runtime:{domain}"
        ),
        &[HashPart::Json(value)],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_has_stable_public_record() {
        let state = State::devnet();
        let record = state.public_record();
        assert_eq!(
            record["protocol_version"],
            PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_INTENT_PRECONFIRMATION_MESH_RUNTIME_PROTOCOL_VERSION
        );
        assert_eq!(record["state_root"], json!(state.state_root()));
        assert_eq!(state.lanes.len(), DEFAULT_MESH_LANES);
    }

    #[test]
    fn replayed_nullifier_is_rejected() {
        let mut state = State::devnet();
        let intent = state.devnet_intent("intent-contract-0001", "lane-private-contract", 9, 900);
        let err = state
            .open_encrypted_batch("batch-replay", "lane-private-contract", vec![intent], 4_096)
            .expect_err("duplicate nullifier must be rejected");
        assert!(err.contains("replayed nullifier"));
    }
}
