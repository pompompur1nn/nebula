use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeRecursiveProofMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-recursive-proof-market-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-recursive-proof-market-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_JOB_SCHEME: &str =
    "private-l2-recursive-proof-job-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_QUOTE_SCHEME: &str =
    "roots-only-recursive-proof-prover-quote-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_BATCH_SCHEME: &str =
    "private-l2-recursive-proof-batch-settlement-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_REBATE_SCHEME: &str =
    "low-fee-recursive-proof-rebate-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 372_000;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_JOBS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_QUOTES: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_BATCHES: usize = 262_144;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    8_192;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    131_072;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_JOB_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobKind {
    PrivateTransfer,
    ContractExecution,
    DefiSettlement,
    MoneroBridge,
    OracleAttestation,
    GovernanceTally,
    StateTransition,
    RecursiveBatch,
}

impl ProofJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractExecution => "contract_execution",
            Self::DefiSettlement => "defi_settlement",
            Self::MoneroBridge => "monero_bridge",
            Self::OracleAttestation => "oracle_attestation",
            Self::GovernanceTally => "governance_tally",
            Self::StateTransition => "state_transition",
            Self::RecursiveBatch => "recursive_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLane {
    FastFinality,
    LowFeeBatch,
    ContractCall,
    DefiBatch,
    BridgeSafety,
    Emergency,
}

impl ProofLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastFinality => "fast_finality",
            Self::LowFeeBatch => "low_fee_batch",
            Self::ContractCall => "contract_call",
            Self::DefiBatch => "defi_batch",
            Self::BridgeSafety => "bridge_safety",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Submitted,
    Quoted,
    Reserved,
    Batched,
    Proved,
    Settled,
    Rejected,
    Expired,
}

impl ProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Submitted | Self::Quoted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverQuoteStatus {
    Posted,
    Accepted,
    Replaced,
    Expired,
    Slashed,
}

impl ProverQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::Replaced => "replaced",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl CapacityReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveBatchStatus {
    Built,
    Proving,
    Settled,
    Rejected,
    Expired,
}

impl RecursiveBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub max_jobs: usize,
    pub max_quotes: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub job_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            max_jobs: PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_JOBS,
            max_quotes: PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_QUOTES,
            max_reservations:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_BATCHES,
            max_batch_items:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            job_ttl_blocks:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_JOB_TTL_BLOCKS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_market_config",
            "chain_id": self.chain_id,
            "max_jobs": self.max_jobs,
            "max_quotes": self.max_quotes,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "job_ttl_blocks": self.job_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-MARKET-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub jobs_submitted: u64,
    pub quotes_posted: u64,
    pub reservations_opened: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub rebates_published: u64,
    pub jobs_settled: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_market_counters",
            "jobs_submitted": self.jobs_submitted,
            "quotes_posted": self.quotes_posted,
            "reservations_opened": self.reservations_opened,
            "batches_built": self.batches_built,
            "receipts_published": self.receipts_published,
            "rebates_published": self.rebates_published,
            "jobs_settled": self.jobs_settled,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitProofJobRequest {
    pub job_kind: ProofJobKind,
    pub lane: ProofLane,
    pub requester_commitment: String,
    pub witness_commitment_root: String,
    pub circuit_id_root: String,
    pub public_input_root: String,
    pub private_input_commitment_root: String,
    pub dependency_root: String,
    pub fee_commitment_root: String,
    pub sponsor_hint_root: Option<String>,
    pub pq_authorization_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitProofJobRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "job_kind": self.job_kind.as_str(),
            "lane": self.lane.as_str(),
            "requester_commitment": self.requester_commitment,
            "witness_commitment_root": self.witness_commitment_root,
            "circuit_id_root": self.circuit_id_root,
            "public_input_root": self.public_input_root,
            "private_input_commitment_root": self.private_input_commitment_root,
            "dependency_root": self.dependency_root,
            "fee_commitment_root": self.fee_commitment_root,
            "sponsor_hint_root": self.sponsor_hint_root,
            "pq_authorization_root": self.pq_authorization_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostProverQuoteRequest {
    pub job_id: String,
    pub prover_commitment: String,
    pub prover_capacity_root: String,
    pub proving_profile_root: String,
    pub quoted_fee_bps: u64,
    pub latency_target_ms: u64,
    pub recursive_depth: u16,
    pub pq_quote_root: String,
    pub quoted_at_height: u64,
    pub expires_at_height: u64,
}

impl PostProverQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "prover_commitment": self.prover_commitment,
            "prover_capacity_root": self.prover_capacity_root,
            "proving_profile_root": self.proving_profile_root,
            "quoted_fee_bps": self.quoted_fee_bps,
            "latency_target_ms": self.latency_target_ms,
            "recursive_depth": self.recursive_depth,
            "pq_quote_root": self.pq_quote_root,
            "quoted_at_height": self.quoted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveProofCapacityRequest {
    pub job_id: String,
    pub quote_id: String,
    pub sponsor_commitment: String,
    pub capacity_budget_root: String,
    pub reserved_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveProofCapacityRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "quote_id": self.quote_id,
            "sponsor_commitment": self.sponsor_commitment,
            "capacity_budget_root": self.capacity_budget_root,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "pq_reservation_root": self.pq_reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildRecursiveProofBatchRequest {
    pub operator_commitment: String,
    pub lane: ProofLane,
    pub job_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub aggregate_witness_root: String,
    pub aggregate_circuit_root: String,
    pub aggregate_public_input_root: String,
    pub aggregate_dependency_root: String,
    pub aggregate_fee_root: String,
    pub recursive_proof_request_root: String,
    pub pq_batch_authorization_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl BuildRecursiveProofBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "lane": self.lane.as_str(),
            "job_ids": self.job_ids,
            "quote_ids": self.quote_ids,
            "reservation_ids": self.reservation_ids,
            "aggregate_witness_root": self.aggregate_witness_root,
            "aggregate_circuit_root": self.aggregate_circuit_root,
            "aggregate_public_input_root": self.aggregate_public_input_root,
            "aggregate_dependency_root": self.aggregate_dependency_root,
            "aggregate_fee_root": self.aggregate_fee_root,
            "recursive_proof_request_root": self.recursive_proof_request_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleRecursiveProofBatchRequest {
    pub batch_id: String,
    pub recursive_proof_root: String,
    pub verifier_transcript_root: String,
    pub settlement_tx_root: String,
    pub fee_receipt_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleRecursiveProofBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "recursive_proof_root": self.recursive_proof_root,
            "verifier_transcript_root": self.verifier_transcript_root,
            "settlement_tx_root": self.settlement_tx_root,
            "fee_receipt_root": self.fee_receipt_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishProofRebateRequest {
    pub batch_id: String,
    pub receipt_id: String,
    pub rebate_note_root: String,
    pub rebate_proof_root: String,
    pub sponsor_commitment: String,
    pub pq_rebate_authorization_root: String,
    pub published_at_height: u64,
}

impl PublishProofRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "rebate_note_root": self.rebate_note_root,
            "rebate_proof_root": self.rebate_proof_root,
            "sponsor_commitment": self.sponsor_commitment,
            "pq_rebate_authorization_root": self.pq_rebate_authorization_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofJobRecord {
    pub job_id: String,
    pub request: SubmitProofJobRequest,
    pub status: ProofJobStatus,
    pub quote_id: Option<String>,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
}

impl ProofJobRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_job",
            "job_id": self.job_id,
            "job_kind": self.request.job_kind.as_str(),
            "lane": self.request.lane.as_str(),
            "requester_commitment": self.request.requester_commitment,
            "witness_commitment_root": self.request.witness_commitment_root,
            "circuit_id_root": self.request.circuit_id_root,
            "public_input_root": self.request.public_input_root,
            "private_input_commitment_root": self.request.private_input_commitment_root,
            "dependency_root": self.request.dependency_root,
            "fee_commitment_root": self.request.fee_commitment_root,
            "sponsor_hint_root": self.request.sponsor_hint_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "max_fee_bps": self.request.max_fee_bps,
            "privacy_set_size": self.request.privacy_set_size,
            "pq_security_bits": self.request.pq_security_bits,
            "status": self.status.as_str(),
            "quote_id": self.quote_id,
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "submitted_at_height": self.request.submitted_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverQuoteRecord {
    pub quote_id: String,
    pub request: PostProverQuoteRequest,
    pub status: ProverQuoteStatus,
}

impl ProverQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_prover_quote",
            "quote_id": self.quote_id,
            "job_id": self.request.job_id,
            "prover_commitment": self.request.prover_commitment,
            "prover_capacity_root": self.request.prover_capacity_root,
            "proving_profile_root": self.request.proving_profile_root,
            "quoted_fee_bps": self.request.quoted_fee_bps,
            "latency_target_ms": self.request.latency_target_ms,
            "recursive_depth": self.request.recursive_depth,
            "pq_quote_root": self.request.pq_quote_root,
            "status": self.status.as_str(),
            "quoted_at_height": self.request.quoted_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofCapacityReservationRecord {
    pub reservation_id: String,
    pub request: ReserveProofCapacityRequest,
    pub status: CapacityReservationStatus,
}

impl ProofCapacityReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_capacity_reservation",
            "reservation_id": self.reservation_id,
            "job_id": self.request.job_id,
            "quote_id": self.request.quote_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "capacity_budget_root": self.request.capacity_budget_root,
            "reserved_fee_bps": self.request.reserved_fee_bps,
            "rebate_commitment_root": self.request.rebate_commitment_root,
            "pq_reservation_root": self.request.pq_reservation_root,
            "status": self.status.as_str(),
            "reserved_at_height": self.request.reserved_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveProofBatchRecord {
    pub batch_id: String,
    pub request: BuildRecursiveProofBatchRequest,
    pub status: RecursiveBatchStatus,
    pub receipt_id: Option<String>,
}

impl RecursiveProofBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_batch",
            "batch_id": self.batch_id,
            "operator_commitment": self.request.operator_commitment,
            "lane": self.request.lane.as_str(),
            "job_ids": self.request.job_ids,
            "quote_ids": self.request.quote_ids,
            "reservation_ids": self.request.reservation_ids,
            "aggregate_witness_root": self.request.aggregate_witness_root,
            "aggregate_circuit_root": self.request.aggregate_circuit_root,
            "aggregate_public_input_root": self.request.aggregate_public_input_root,
            "aggregate_dependency_root": self.request.aggregate_dependency_root,
            "aggregate_fee_root": self.request.aggregate_fee_root,
            "recursive_proof_request_root": self.request.recursive_proof_request_root,
            "pq_batch_authorization_root": self.request.pq_batch_authorization_root,
            "max_fee_bps": self.request.max_fee_bps,
            "privacy_set_size": self.request.privacy_set_size,
            "status": self.status.as_str(),
            "receipt_id": self.receipt_id,
            "built_at_height": self.request.built_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveProofSettlementReceipt {
    pub receipt_id: String,
    pub request: SettleRecursiveProofBatchRequest,
    pub status: ReceiptStatus,
    pub settled_job_ids: Vec<String>,
}

impl RecursiveProofSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.request.batch_id,
            "recursive_proof_root": self.request.recursive_proof_root,
            "verifier_transcript_root": self.request.verifier_transcript_root,
            "settlement_tx_root": self.request.settlement_tx_root,
            "fee_receipt_root": self.request.fee_receipt_root,
            "state_root_before": self.request.state_root_before,
            "state_root_after": self.request.state_root_after,
            "pq_settlement_root": self.request.pq_settlement_root,
            "settled_fee_bps": self.request.settled_fee_bps,
            "settled_job_ids": self.settled_job_ids,
            "status": self.status.as_str(),
            "settled_at_height": self.request.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofRebateReceipt {
    pub rebate_id: String,
    pub request: PublishProofRebateRequest,
}

impl ProofRebateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_rebate_receipt",
            "rebate_id": self.rebate_id,
            "batch_id": self.request.batch_id,
            "receipt_id": self.request.receipt_id,
            "rebate_note_root": self.request.rebate_note_root,
            "rebate_proof_root": self.request.rebate_proof_root,
            "sponsor_commitment": self.request.sponsor_commitment,
            "pq_rebate_authorization_root": self.request.pq_rebate_authorization_root,
            "published_at_height": self.request.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub job_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "job_root": self.job_root,
            "quote_root": self.quote_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub jobs: BTreeMap<String, ProofJobRecord>,
    pub quotes: BTreeMap<String, ProverQuoteRecord>,
    pub reservations: BTreeMap<String, ProofCapacityReservationRecord>,
    pub batches: BTreeMap<String, RecursiveProofBatchRecord>,
    pub receipts: BTreeMap<String, RecursiveProofSettlementReceipt>,
    pub rebates: BTreeMap<String, ProofRebateReceipt>,
    pub seen_witness_roots: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn devnet() -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<Self> {
        Self::with_config(Config::devnet())
    }

    pub fn with_config(config: Config) -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<Self> {
        if config.min_privacy_set_size == 0 {
            return Err("min privacy set must be non-zero".to_string());
        }
        if config.batch_privacy_set_size < config.min_privacy_set_size {
            return Err("batch privacy set must cover min privacy set".to_string());
        }
        if config.min_pq_security_bits < 192 {
            return Err("minimum pq security bits must be at least 192".to_string());
        }
        if config.max_user_fee_bps > PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_MAX_BPS {
            return Err("max user fee exceeds bps denominator".to_string());
        }
        if config.target_rebate_bps > config.max_user_fee_bps {
            return Err("target rebate must not exceed max user fee".to_string());
        }
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_DEVNET_HEIGHT,
            jobs: BTreeMap::new(),
            quotes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            seen_witness_roots: BTreeSet::new(),
            public_records: Vec::new(),
        })
    }

    pub fn submit_proof_job(
        &mut self,
        request: SubmitProofJobRequest,
    ) -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<ProofJobRecord> {
        if self.jobs.len() >= self.config.max_jobs {
            return Err("proof job queue is full".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("proof job max fee exceeds runtime fee cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("proof job privacy set below runtime minimum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("proof job pq security bits below runtime minimum".to_string());
        }
        if request.expires_at_height <= request.submitted_at_height {
            return Err("proof job expiry must be after submit height".to_string());
        }
        if self
            .seen_witness_roots
            .contains(&request.witness_commitment_root)
        {
            return Err("proof job witness root already submitted".to_string());
        }
        self.counters.jobs_submitted = self.counters.jobs_submitted.saturating_add(1);
        let job_id = proof_job_id(&request, self.counters.jobs_submitted);
        self.seen_witness_roots
            .insert(request.witness_commitment_root.clone());
        let record = ProofJobRecord {
            job_id,
            request,
            status: ProofJobStatus::Submitted,
            quote_id: None,
            reservation_id: None,
            batch_id: None,
        };
        self.public_records.push(record.public_record());
        self.jobs.insert(record.job_id.clone(), record.clone());
        Ok(record)
    }

    pub fn post_prover_quote(
        &mut self,
        request: PostProverQuoteRequest,
    ) -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<ProverQuoteRecord> {
        if self.quotes.len() >= self.config.max_quotes {
            return Err("prover quote store is full".to_string());
        }
        let job = self
            .jobs
            .get_mut(&request.job_id)
            .ok_or_else(|| "proof job missing for prover quote".to_string())?;
        if !job.status.batchable() {
            return Err("proof job is not quoteable".to_string());
        }
        if request.quoted_fee_bps > job.request.max_fee_bps {
            return Err("prover quote exceeds proof job fee cap".to_string());
        }
        if request.expires_at_height <= request.quoted_at_height {
            return Err("prover quote expiry must be after quote height".to_string());
        }
        self.counters.quotes_posted = self.counters.quotes_posted.saturating_add(1);
        let quote_id = prover_quote_id(&request, self.counters.quotes_posted);
        job.quote_id = Some(quote_id.clone());
        job.status = ProofJobStatus::Quoted;
        let record = ProverQuoteRecord {
            quote_id,
            request,
            status: ProverQuoteStatus::Posted,
        };
        self.public_records.push(record.public_record());
        self.quotes.insert(record.quote_id.clone(), record.clone());
        Ok(record)
    }

    pub fn reserve_proof_capacity(
        &mut self,
        request: ReserveProofCapacityRequest,
    ) -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<ProofCapacityReservationRecord> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("proof capacity reservation store is full".to_string());
        }
        let job = self
            .jobs
            .get_mut(&request.job_id)
            .ok_or_else(|| "proof job missing for capacity reservation".to_string())?;
        if job.quote_id.as_deref() != Some(request.quote_id.as_str()) {
            return Err("proof capacity reservation quote does not match job quote".to_string());
        }
        if request.reserved_fee_bps > job.request.max_fee_bps {
            return Err("reserved proof fee exceeds job cap".to_string());
        }
        if request.expires_at_height <= request.reserved_at_height {
            return Err("capacity reservation expiry must be after reservation height".to_string());
        }
        self.counters.reservations_opened = self.counters.reservations_opened.saturating_add(1);
        let reservation_id =
            proof_capacity_reservation_id(&request, self.counters.reservations_opened);
        job.reservation_id = Some(reservation_id.clone());
        job.status = ProofJobStatus::Reserved;
        if let Some(quote) = self.quotes.get_mut(&request.quote_id) {
            quote.status = ProverQuoteStatus::Accepted;
        }
        let record = ProofCapacityReservationRecord {
            reservation_id,
            request,
            status: CapacityReservationStatus::Reserved,
        };
        self.public_records.push(record.public_record());
        self.reservations
            .insert(record.reservation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn build_recursive_batch(
        &mut self,
        request: BuildRecursiveProofBatchRequest,
    ) -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<RecursiveProofBatchRecord> {
        if self.batches.len() >= self.config.max_batches {
            return Err("recursive proof batch store is full".to_string());
        }
        if request.job_ids.is_empty() {
            return Err("recursive proof batch must include jobs".to_string());
        }
        if request.job_ids.len() > self.config.max_batch_items {
            return Err("recursive proof batch exceeds max batch items".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("recursive proof batch fee exceeds runtime cap".to_string());
        }
        if request.privacy_set_size < self.config.batch_privacy_set_size {
            return Err("recursive proof batch privacy set below runtime target".to_string());
        }
        let mut unique_jobs = BTreeSet::new();
        for job_id in &request.job_ids {
            if !unique_jobs.insert(job_id.clone()) {
                return Err("recursive proof batch contains duplicate job id".to_string());
            }
            let job = self
                .jobs
                .get(job_id)
                .ok_or_else(|| format!("proof job missing from runtime: {job_id}"))?;
            if !job.status.batchable() {
                return Err(format!("proof job is not batchable: {job_id}"));
            }
        }
        for quote_id in &request.quote_ids {
            if !self.quotes.contains_key(quote_id) {
                return Err(format!("prover quote missing from runtime: {quote_id}"));
            }
        }
        for reservation_id in &request.reservation_ids {
            if !self.reservations.contains_key(reservation_id) {
                return Err(format!(
                    "proof capacity reservation missing from runtime: {reservation_id}"
                ));
            }
        }
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        let batch_id = recursive_batch_id(&request, self.counters.batches_built);
        for job_id in &request.job_ids {
            if let Some(job) = self.jobs.get_mut(job_id) {
                job.status = ProofJobStatus::Batched;
                job.batch_id = Some(batch_id.clone());
            }
        }
        let record = RecursiveProofBatchRecord {
            batch_id,
            request,
            status: RecursiveBatchStatus::Built,
            receipt_id: None,
        };
        self.public_records.push(record.public_record());
        self.batches.insert(record.batch_id.clone(), record.clone());
        Ok(record)
    }

    pub fn settle_recursive_batch(
        &mut self,
        request: SettleRecursiveProofBatchRequest,
    ) -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<RecursiveProofSettlementReceipt> {
        if self.receipts.len() >= self.config.max_batches {
            return Err("recursive proof receipt store is full".to_string());
        }
        if request.settled_fee_bps > self.config.max_user_fee_bps {
            return Err("settled proof fee exceeds runtime cap".to_string());
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "recursive proof batch missing for settlement".to_string())?;
        if !matches!(
            batch.status,
            RecursiveBatchStatus::Built | RecursiveBatchStatus::Proving
        ) {
            return Err("recursive proof batch cannot be settled from current status".to_string());
        }
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        let receipt_id = proof_settlement_receipt_id(&request, self.counters.receipts_published);
        let settled_job_ids = batch.request.job_ids.clone();
        batch.status = RecursiveBatchStatus::Settled;
        batch.receipt_id = Some(receipt_id.clone());
        for job_id in &settled_job_ids {
            if let Some(job) = self.jobs.get_mut(job_id) {
                job.status = ProofJobStatus::Settled;
                self.counters.jobs_settled = self.counters.jobs_settled.saturating_add(1);
            }
        }
        for reservation in self.reservations.values_mut() {
            if settled_job_ids.contains(&reservation.request.job_id) {
                reservation.status = CapacityReservationStatus::Consumed;
            }
        }
        let receipt = RecursiveProofSettlementReceipt {
            receipt_id,
            request,
            status: ReceiptStatus::Published,
            settled_job_ids,
        };
        self.public_records.push(receipt.public_record());
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishProofRebateRequest,
    ) -> PrivateL2LowFeeRecursiveProofMarketRuntimeResult<ProofRebateReceipt> {
        if !self.batches.contains_key(&request.batch_id) {
            return Err("recursive proof batch missing for rebate".to_string());
        }
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("recursive proof receipt missing for rebate".to_string());
        }
        self.counters.rebates_published = self.counters.rebates_published.saturating_add(1);
        let rebate_id = proof_rebate_id(&request, self.counters.rebates_published);
        let record = ProofRebateReceipt { rebate_id, request };
        self.public_records.push(record.public_record());
        self.rebates
            .insert(record.rebate_id.clone(), record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let job_records = self
            .jobs
            .values()
            .map(ProofJobRecord::public_record)
            .collect::<Vec<_>>();
        let quote_records = self
            .quotes
            .values()
            .map(ProverQuoteRecord::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .reservations
            .values()
            .map(ProofCapacityReservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(RecursiveProofBatchRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(RecursiveProofSettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .map(ProofRebateReceipt::public_record)
            .collect::<Vec<_>>();
        Roots {
            job_root: merkle_root("PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-JOB", &job_records),
            quote_root: merkle_root("PRIVATE-L2-LOW-FEE-RECURSIVE-PROVER-QUOTE", &quote_records),
            reservation_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-RESERVATION",
                &reservation_records,
            ),
            batch_root: merkle_root("PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-BATCH", &batch_records),
            receipt_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-RECEIPT",
                &receipt_records,
            ),
            rebate_root: merkle_root("PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-REBATE", &rebate_records),
            public_record_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-PUBLIC-RECORD",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_recursive_proof_market_runtime",
            "protocol_version": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_PQ_AUTH_SUITE,
            "job_scheme": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_JOB_SCHEME,
            "quote_scheme": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_QUOTE_SCHEME,
            "batch_scheme": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_BATCH_SCHEME,
            "rebate_scheme": PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_REBATE_SCHEME,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = root_from_record("PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-STATE", &record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-STATE",
            &self.public_record_without_state_root(),
        )
    }
}

pub fn proof_job_id(request: &SubmitProofJobRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-JOB-ID",
        &[
            HashPart::Str(request.job_kind.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.requester_commitment),
            HashPart::Str(&request.witness_commitment_root),
            HashPart::Str(&request.circuit_id_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn prover_quote_id(request: &PostProverQuoteRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-PROVER-QUOTE-ID",
        &[
            HashPart::Str(&request.job_id),
            HashPart::Str(&request.prover_commitment),
            HashPart::Str(&request.prover_capacity_root),
            HashPart::Str(&request.pq_quote_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn proof_capacity_reservation_id(
    request: &ReserveProofCapacityRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-RESERVATION-ID",
        &[
            HashPart::Str(&request.job_id),
            HashPart::Str(&request.quote_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.capacity_budget_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn recursive_batch_id(request: &BuildRecursiveProofBatchRequest, counter: u64) -> String {
    let record = request.public_record();
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-BATCH-ID",
        &[HashPart::Json(&record), HashPart::Int(counter as i128)],
        32,
    )
}

pub fn proof_settlement_receipt_id(
    request: &SettleRecursiveProofBatchRequest,
    counter: u64,
) -> String {
    let record = request.public_record();
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-RECEIPT-ID",
        &[HashPart::Json(&record), HashPart::Int(counter as i128)],
        32,
    )
}

pub fn proof_rebate_id(request: &PublishProofRebateRequest, counter: u64) -> String {
    let record = request.public_record();
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-PROOF-REBATE-ID",
        &[HashPart::Json(&record), HashPart::Int(counter as i128)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_RECURSIVE_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}
