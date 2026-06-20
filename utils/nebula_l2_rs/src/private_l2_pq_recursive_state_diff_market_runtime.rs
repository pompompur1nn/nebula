use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqRecursiveStateDiffMarketRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-recursive-state-diff-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_PQ_PROOF_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-recursive-state-diff-proof-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DIFF_SCHEME: &str =
    "private-state-diff-commitment-root-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_COMPRESSION_SCHEME: &str =
    "low-fee-recursive-state-diff-compression-bid-root-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_CACHE_SCHEME: &str =
    "private-state-diff-witness-cache-reservation-root-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_BATCH_SCHEME: &str =
    "recursive-state-diff-settlement-batch-root-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_RECEIPT_SCHEME: &str =
    "pq-recursive-state-diff-settlement-receipt-root-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_REBATE_SCHEME: &str =
    "low-fee-state-diff-rebate-root-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_SLASHING_SCHEME: &str =
    "recursive-state-diff-market-slashing-evidence-root-v1";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 1_764_000;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_DIFF_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_BID_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_CACHE_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    524_288;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_SLASHING_BPS: u64 = 2_000;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_DIFFS: usize = 4_194_304;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_BIDS: usize = 2_097_152;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_CACHE_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_RECEIPTS: usize = 4_194_304;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_REBATES: usize = 4_194_304;
pub const PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_SLASHES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateDiffDomain {
    Account,
    ContractStorage,
    TokenBalance,
    DefiPosition,
    BridgeReserve,
    OracleFeed,
    GovernanceState,
    WalletPolicy,
}

impl StateDiffDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::ContractStorage => "contract_storage",
            Self::TokenBalance => "token_balance",
            Self::DefiPosition => "defi_position",
            Self::BridgeReserve => "bridge_reserve",
            Self::OracleFeed => "oracle_feed",
            Self::GovernanceState => "governance_state",
            Self::WalletPolicy => "wallet_policy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffPriority {
    Background,
    LowFee,
    Interactive,
    FastLane,
    Emergency,
}

impl DiffPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::LowFee => "low_fee",
            Self::Interactive => "interactive",
            Self::FastLane => "fast_lane",
            Self::Emergency => "emergency",
        }
    }

    pub fn weight(self) -> u64 {
        match self {
            Self::Background => 1,
            Self::LowFee => 2,
            Self::Interactive => 4,
            Self::FastLane => 8,
            Self::Emergency => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Submitted,
    ProofAttached,
    BidMatched,
    CacheReserved,
    Batched,
    Settled,
    Expired,
    Rejected,
    Slashed,
}

impl DiffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ProofAttached => "proof_attached",
            Self::BidMatched => "bid_matched",
            Self::CacheReserved => "cache_reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::ProofAttached
                | Self::BidMatched
                | Self::CacheReserved
                | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionBidStatus {
    Posted,
    Matched,
    Consumed,
    Expired,
    Slashed,
}

impl CompressionBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheReservationStatus {
    Reserved,
    Materialized,
    Consumed,
    Expired,
    Slashed,
}

impl CacheReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Materialized => "materialized",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Proved,
    Settled,
    Expired,
    Slashed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
    Failed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Issued,
    Claimed,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidRecursiveProof,
    InvalidPqSignature,
    StaleStateDiff,
    CacheMiss,
    ExcessiveFee,
    PrivacySetTooSmall,
    DoubleSpendNullifier,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRecursiveProof => "invalid_recursive_proof",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::StaleStateDiff => "stale_state_diff",
            Self::CacheMiss => "cache_miss",
            Self::ExcessiveFee => "excessive_fee",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_proof_suite: String,
    pub diff_scheme: String,
    pub compression_scheme: String,
    pub cache_scheme: String,
    pub batch_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub slashing_scheme: String,
    pub genesis_height: u64,
    pub diff_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub cache_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_bps: u64,
    pub max_diffs: usize,
    pub max_bids: usize,
    pub max_cache_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_slashes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_SCHEMA_VERSION,
            l2_network: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            monero_network: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            hash_suite: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_HASH_SUITE.to_string(),
            pq_proof_suite: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_PQ_PROOF_SUITE
                .to_string(),
            diff_scheme: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DIFF_SCHEME.to_string(),
            compression_scheme:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_COMPRESSION_SCHEME.to_string(),
            cache_scheme: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_CACHE_SCHEME
                .to_string(),
            batch_scheme: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_BATCH_SCHEME
                .to_string(),
            receipt_scheme: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            rebate_scheme: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_REBATE_SCHEME
                .to_string(),
            slashing_scheme: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_SLASHING_SCHEME
                .to_string(),
            genesis_height: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEVNET_HEIGHT,
            diff_ttl_blocks:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_DIFF_TTL_BLOCKS,
            bid_ttl_blocks:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            cache_ttl_blocks:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_CACHE_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            slashing_bps: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_DEFAULT_SLASHING_BPS,
            max_diffs: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_DIFFS,
            max_bids: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_BIDS,
            max_cache_reservations:
                PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_CACHE_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_BATCHES,
            max_receipts: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_REBATES,
            max_slashes: PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_SLASHES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub diffs_submitted: u64,
    pub pq_proofs_attached: u64,
    pub compression_bids_posted: u64,
    pub compression_bids_matched: u64,
    pub cache_reservations_opened: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub slashes_recorded: u64,
    pub expired_items: u64,
    pub total_input_bytes: u128,
    pub total_compressed_bytes: u128,
    pub total_fee_units: u128,
    pub total_rebate_units: u128,
    pub total_slashed_bond_units: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub diff_root: String,
    pub proof_root: String,
    pub bid_root: String,
    pub cache_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub slash_root: String,
    pub consumed_nullifier_root: String,
    pub checkpoint_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateDiffCommitment {
    pub id: String,
    pub domain: StateDiffDomain,
    pub priority: DiffPriority,
    pub submitter_commitment: String,
    pub before_state_root: String,
    pub after_state_root: String,
    pub diff_commitment_root: String,
    pub witness_root: String,
    pub privacy_nullifier: String,
    pub input_bytes: u64,
    pub compressed_bytes_hint: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: DiffStatus,
    pub pq_proof_id: Option<String>,
    pub compression_bid_id: Option<String>,
    pub cache_reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
}

impl StateDiffCommitment {
    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height && self.status.live()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqDiffProof {
    pub id: String,
    pub diff_id: String,
    pub proof_root: String,
    pub signature_root: String,
    pub verifier_key_root: String,
    pub recursion_program_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionBid {
    pub id: String,
    pub diff_id: String,
    pub prover_commitment: String,
    pub bid_root: String,
    pub output_witness_root: String,
    pub fee_bps: u64,
    pub promised_compressed_bytes: u64,
    pub bond_units: u128,
    pub posted_height: u64,
    pub expires_height: u64,
    pub status: CompressionBidStatus,
}

impl CompressionBid {
    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height && self.status == CompressionBidStatus::Posted
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheReservation {
    pub id: String,
    pub diff_id: String,
    pub cache_operator_commitment: String,
    pub cache_key_root: String,
    pub witness_availability_root: String,
    pub byte_capacity: u64,
    pub fee_units: u64,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub status: CacheReservationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveDiffBatch {
    pub id: String,
    pub domain: StateDiffDomain,
    pub priority: DiffPriority,
    pub diff_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub cache_reservation_ids: Vec<String>,
    pub batch_root: String,
    pub aggregate_proof_root: String,
    pub aggregate_signature_root: String,
    pub total_input_bytes: u128,
    pub total_compressed_bytes: u128,
    pub max_fee_bps: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub status: BatchStatus,
}

impl RecursiveDiffBatch {
    pub fn expired_at(&self, height: u64) -> bool {
        self.expires_height <= height
            && matches!(
                self.status,
                BatchStatus::Open | BatchStatus::Sealed | BatchStatus::Proved
            )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub id: String,
    pub batch_id: String,
    pub state_transition_root: String,
    pub recursive_receipt_root: String,
    pub fee_root: String,
    pub pq_receipt_signature_root: String,
    pub published_height: u64,
    pub status: ReceiptStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub id: String,
    pub diff_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub issued_height: u64,
    pub status: RebateStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub id: String,
    pub subject_commitment: String,
    pub reason: SlashReason,
    pub diff_id: Option<String>,
    pub batch_id: Option<String>,
    pub evidence_root: String,
    pub penalty_units: u128,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketCheckpoint {
    pub id: String,
    pub height: u64,
    pub state_root: String,
    pub live_diff_count: u64,
    pub open_batch_count: u64,
    pub total_input_bytes: u128,
    pub total_compressed_bytes: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitDiffRequest {
    pub domain: StateDiffDomain,
    pub priority: DiffPriority,
    pub submitter_commitment: String,
    pub before_state_root: String,
    pub after_state_root: String,
    pub diff_commitment_root: String,
    pub witness_root: String,
    pub privacy_nullifier: String,
    pub input_bytes: u64,
    pub compressed_bytes_hint: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqProofRequest {
    pub diff_id: String,
    pub proof_root: String,
    pub signature_root: String,
    pub verifier_key_root: String,
    pub recursion_program_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostCompressionBidRequest {
    pub diff_id: String,
    pub prover_commitment: String,
    pub bid_root: String,
    pub output_witness_root: String,
    pub fee_bps: u64,
    pub promised_compressed_bytes: u64,
    pub bond_units: u128,
    pub posted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveCacheRequest {
    pub diff_id: String,
    pub cache_operator_commitment: String,
    pub cache_key_root: String,
    pub witness_availability_root: String,
    pub byte_capacity: u64,
    pub fee_units: u64,
    pub reserved_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildBatchRequest {
    pub domain: StateDiffDomain,
    pub priority: DiffPriority,
    pub diff_ids: Vec<String>,
    pub aggregate_proof_root: String,
    pub aggregate_signature_root: String,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishReceiptRequest {
    pub batch_id: String,
    pub state_transition_root: String,
    pub recursive_receipt_root: String,
    pub fee_root: String,
    pub pq_receipt_signature_root: String,
    pub published_height: u64,
    pub finalize: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashRequest {
    pub subject_commitment: String,
    pub reason: SlashReason,
    pub diff_id: Option<String>,
    pub batch_id: Option<String>,
    pub evidence_root: String,
    pub bond_units: u128,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub diffs: BTreeMap<String, StateDiffCommitment>,
    pub pq_proofs: BTreeMap<String, PqDiffProof>,
    pub compression_bids: BTreeMap<String, CompressionBid>,
    pub cache_reservations: BTreeMap<String, CacheReservation>,
    pub batches: BTreeMap<String, RecursiveDiffBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub checkpoints: BTreeMap<String, MarketCheckpoint>,
}

impl Default for State {
    fn default() -> Self {
        Self::with_config(Config::default())
    }
}

impl State {
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            diffs: BTreeMap::new(),
            pq_proofs: BTreeMap::new(),
            compression_bids: BTreeMap::new(),
            cache_reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            checkpoints: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let diff = state
            .submit_diff(SubmitDiffRequest {
                domain: StateDiffDomain::ContractStorage,
                priority: DiffPriority::FastLane,
                submitter_commitment: "devnet-state-diff-submitter".to_string(),
                before_state_root: "devnet-before-contract-root".to_string(),
                after_state_root: "devnet-after-contract-root".to_string(),
                diff_commitment_root: root_from_strings(
                    "private-l2-pq-recursive-state-diff-market:devnet-diff",
                    &["storage-slot-a", "storage-slot-b", "token-balance-c"],
                ),
                witness_root: root_from_strings(
                    "private-l2-pq-recursive-state-diff-market:devnet-witness",
                    &["sealed-witness-a", "sealed-witness-b"],
                ),
                privacy_nullifier: "devnet-state-diff-nullifier".to_string(),
                input_bytes: 64_000,
                compressed_bytes_hint: 8_192,
                max_fee_bps: 6,
                privacy_set_size: state.config.batch_privacy_set_size,
                submitted_height: state.config.genesis_height + 1,
            })
            .expect("devnet diff");
        state
            .attach_pq_proof(AttachPqProofRequest {
                diff_id: diff.id.clone(),
                proof_root: root_from_strings(
                    "private-l2-pq-recursive-state-diff-market:devnet-proof",
                    &["recursive-proof", "state-diff-valid", "privacy-ok"],
                ),
                signature_root: root_from_strings(
                    "private-l2-pq-recursive-state-diff-market:devnet-signature",
                    &["ml-dsa", "slh-dsa"],
                ),
                verifier_key_root: "devnet-state-diff-vk-root".to_string(),
                recursion_program_root: "devnet-recursive-program-root".to_string(),
                pq_security_bits: state.config.min_pq_security_bits,
                privacy_set_size: state.config.batch_privacy_set_size,
                submitted_height: state.config.genesis_height + 2,
            })
            .expect("devnet proof");
        let bid = state
            .post_compression_bid(PostCompressionBidRequest {
                diff_id: diff.id.clone(),
                prover_commitment: "devnet-state-diff-prover".to_string(),
                bid_root: root_from_strings(
                    "private-l2-pq-recursive-state-diff-market:devnet-bid",
                    &["low-fee", "fast-cache", "recursive"],
                ),
                output_witness_root: "devnet-compressed-witness-root".to_string(),
                fee_bps: 4,
                promised_compressed_bytes: 7_936,
                bond_units: 2_000_000,
                posted_height: state.config.genesis_height + 3,
            })
            .expect("devnet bid");
        state
            .reserve_cache(ReserveCacheRequest {
                diff_id: diff.id.clone(),
                cache_operator_commitment: "devnet-state-diff-cache".to_string(),
                cache_key_root: "devnet-cache-key-root".to_string(),
                witness_availability_root: "devnet-witness-availability-root".to_string(),
                byte_capacity: 16_384,
                fee_units: 64,
                reserved_height: state.config.genesis_height + 4,
            })
            .expect("devnet cache");
        state
            .match_compression_bid(&diff.id, &bid.id, state.config.genesis_height + 5)
            .expect("devnet match bid");
        let batch = state
            .build_batch(BuildBatchRequest {
                domain: StateDiffDomain::ContractStorage,
                priority: DiffPriority::FastLane,
                diff_ids: vec![diff.id.clone()],
                aggregate_proof_root: "devnet-aggregate-state-diff-proof".to_string(),
                aggregate_signature_root: "devnet-aggregate-pq-signature".to_string(),
                created_height: state.config.genesis_height + 6,
            })
            .expect("devnet batch");
        state
            .publish_receipt(PublishReceiptRequest {
                batch_id: batch.id,
                state_transition_root: "devnet-state-transition-root".to_string(),
                recursive_receipt_root: "devnet-recursive-receipt-root".to_string(),
                fee_root: "devnet-low-fee-root".to_string(),
                pq_receipt_signature_root: "devnet-receipt-pq-signature-root".to_string(),
                published_height: state.config.genesis_height + 7,
                finalize: true,
            })
            .expect("devnet receipt");
        state.checkpoint(state.config.genesis_height + 8);
        state
    }

    pub fn submit_diff(
        &mut self,
        request: SubmitDiffRequest,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<StateDiffCommitment> {
        if self.diffs.len() >= self.config.max_diffs {
            return Err("state diff capacity exceeded".to_string());
        }
        if self
            .consumed_nullifiers
            .contains(&request.privacy_nullifier)
        {
            return Err("state diff privacy nullifier already consumed".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("state diff fee cap exceeds runtime maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("state diff privacy set is too small".to_string());
        }
        if request.input_bytes == 0 || request.compressed_bytes_hint > request.input_bytes {
            return Err("state diff byte hints are invalid".to_string());
        }

        let id = state_diff_id(
            request.domain,
            request.priority,
            &request.before_state_root,
            &request.after_state_root,
            &request.privacy_nullifier,
            request.submitted_height,
        );
        if self.diffs.contains_key(&id) {
            return Err("state diff already exists".to_string());
        }

        let diff = StateDiffCommitment {
            id: id.clone(),
            domain: request.domain,
            priority: request.priority,
            submitter_commitment: request.submitter_commitment,
            before_state_root: request.before_state_root,
            after_state_root: request.after_state_root,
            diff_commitment_root: request.diff_commitment_root,
            witness_root: request.witness_root,
            privacy_nullifier: request.privacy_nullifier,
            input_bytes: request.input_bytes,
            compressed_bytes_hint: request.compressed_bytes_hint,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            submitted_height: request.submitted_height,
            expires_height: request.submitted_height + self.config.diff_ttl_blocks,
            status: DiffStatus::Submitted,
            pq_proof_id: None,
            compression_bid_id: None,
            cache_reservation_id: None,
            batch_id: None,
            receipt_id: None,
        };
        self.consumed_nullifiers
            .insert(diff.privacy_nullifier.clone());
        self.counters.diffs_submitted += 1;
        self.counters.total_input_bytes = self
            .counters
            .total_input_bytes
            .saturating_add(diff.input_bytes as u128);
        self.diffs.insert(id, diff.clone());
        Ok(diff)
    }

    pub fn attach_pq_proof(
        &mut self,
        request: AttachPqProofRequest,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<PqDiffProof> {
        if self.pq_proofs.len() >= self.config.max_diffs {
            return Err("PQ proof capacity exceeded".to_string());
        }
        let diff = self
            .diffs
            .get_mut(&request.diff_id)
            .ok_or_else(|| "unknown state diff".to_string())?;
        if !matches!(
            diff.status,
            DiffStatus::Submitted | DiffStatus::ProofAttached
        ) {
            return Err("state diff is not accepting PQ proofs".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ proof security level is too low".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("PQ proof privacy set is too small".to_string());
        }

        let id = pq_diff_proof_id(
            &request.diff_id,
            &request.proof_root,
            &request.signature_root,
            request.submitted_height,
        );
        let proof = PqDiffProof {
            id: id.clone(),
            diff_id: request.diff_id.clone(),
            proof_root: request.proof_root,
            signature_root: request.signature_root,
            verifier_key_root: request.verifier_key_root,
            recursion_program_root: request.recursion_program_root,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            submitted_height: request.submitted_height,
        };
        self.pq_proofs.insert(id.clone(), proof.clone());
        diff.pq_proof_id = Some(id);
        diff.status = DiffStatus::ProofAttached;
        self.counters.pq_proofs_attached += 1;
        Ok(proof)
    }

    pub fn post_compression_bid(
        &mut self,
        request: PostCompressionBidRequest,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<CompressionBid> {
        if self.compression_bids.len() >= self.config.max_bids {
            return Err("compression bid capacity exceeded".to_string());
        }
        let diff = self
            .diffs
            .get(&request.diff_id)
            .ok_or_else(|| "unknown state diff".to_string())?;
        if request.fee_bps > diff.max_fee_bps || request.fee_bps > self.config.max_user_fee_bps {
            return Err("compression bid fee exceeds cap".to_string());
        }
        if request.promised_compressed_bytes > diff.input_bytes {
            return Err("compression bid does not compress the diff".to_string());
        }

        let id = compression_bid_id(
            &request.diff_id,
            &request.prover_commitment,
            &request.bid_root,
            request.posted_height,
        );
        let bid = CompressionBid {
            id: id.clone(),
            diff_id: request.diff_id,
            prover_commitment: request.prover_commitment,
            bid_root: request.bid_root,
            output_witness_root: request.output_witness_root,
            fee_bps: request.fee_bps,
            promised_compressed_bytes: request.promised_compressed_bytes,
            bond_units: request.bond_units,
            posted_height: request.posted_height,
            expires_height: request.posted_height + self.config.bid_ttl_blocks,
            status: CompressionBidStatus::Posted,
        };
        self.compression_bids.insert(id, bid.clone());
        self.counters.compression_bids_posted += 1;
        Ok(bid)
    }

    pub fn match_compression_bid(
        &mut self,
        diff_id: &str,
        bid_id: &str,
        height: u64,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<()> {
        let diff = self
            .diffs
            .get_mut(diff_id)
            .ok_or_else(|| "unknown state diff".to_string())?;
        if diff.expired_at(height) {
            diff.status = DiffStatus::Expired;
            return Err("state diff expired".to_string());
        }
        if diff.pq_proof_id.is_none() {
            return Err("state diff needs a PQ proof before bid matching".to_string());
        }
        let bid = self
            .compression_bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown compression bid".to_string())?;
        if bid.diff_id != diff_id {
            return Err("compression bid belongs to another diff".to_string());
        }
        if bid.expired_at(height) {
            bid.status = CompressionBidStatus::Expired;
            return Err("compression bid expired".to_string());
        }
        bid.status = CompressionBidStatus::Matched;
        diff.compression_bid_id = Some(bid_id.to_string());
        diff.status = DiffStatus::BidMatched;
        self.counters.compression_bids_matched += 1;
        Ok(())
    }

    pub fn reserve_cache(
        &mut self,
        request: ReserveCacheRequest,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<CacheReservation> {
        if self.cache_reservations.len() >= self.config.max_cache_reservations {
            return Err("cache reservation capacity exceeded".to_string());
        }
        let diff = self
            .diffs
            .get_mut(&request.diff_id)
            .ok_or_else(|| "unknown state diff".to_string())?;
        if request.byte_capacity < diff.compressed_bytes_hint {
            return Err("cache reservation cannot hold compressed witness".to_string());
        }
        let id = cache_reservation_id(
            &request.diff_id,
            &request.cache_operator_commitment,
            &request.cache_key_root,
            request.reserved_height,
        );
        let reservation = CacheReservation {
            id: id.clone(),
            diff_id: request.diff_id.clone(),
            cache_operator_commitment: request.cache_operator_commitment,
            cache_key_root: request.cache_key_root,
            witness_availability_root: request.witness_availability_root,
            byte_capacity: request.byte_capacity,
            fee_units: request.fee_units,
            reserved_height: request.reserved_height,
            expires_height: request.reserved_height + self.config.cache_ttl_blocks,
            status: CacheReservationStatus::Reserved,
        };
        self.cache_reservations
            .insert(id.clone(), reservation.clone());
        diff.cache_reservation_id = Some(id);
        if matches!(
            diff.status,
            DiffStatus::BidMatched | DiffStatus::ProofAttached
        ) {
            diff.status = DiffStatus::CacheReserved;
        }
        self.counters.cache_reservations_opened += 1;
        self.counters.total_fee_units = self
            .counters
            .total_fee_units
            .saturating_add(reservation.fee_units as u128);
        Ok(reservation)
    }

    pub fn build_batch(
        &mut self,
        request: BuildBatchRequest,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<RecursiveDiffBatch> {
        if self.batches.len() >= self.config.max_batches {
            return Err("recursive diff batch capacity exceeded".to_string());
        }
        if request.diff_ids.is_empty() {
            return Err("recursive diff batch requires at least one diff".to_string());
        }

        let mut bid_ids = Vec::new();
        let mut cache_reservation_ids = Vec::new();
        let mut leaves = Vec::new();
        let mut total_input_bytes = 0_u128;
        let mut total_compressed_bytes = 0_u128;
        let mut max_fee_bps = 0_u64;

        for diff_id in &request.diff_ids {
            let diff = self
                .diffs
                .get(diff_id)
                .ok_or_else(|| format!("unknown state diff {diff_id}"))?;
            if diff.domain != request.domain || diff.priority != request.priority {
                return Err("batch diffs must share domain and priority".to_string());
            }
            if diff.expired_at(request.created_height) {
                return Err("batch contains an expired diff".to_string());
            }
            if diff.pq_proof_id.is_none()
                || diff.compression_bid_id.is_none()
                || diff.cache_reservation_id.is_none()
            {
                return Err("batch diff is missing proof, bid, or cache reservation".to_string());
            }
            total_input_bytes = total_input_bytes.saturating_add(diff.input_bytes as u128);
            total_compressed_bytes =
                total_compressed_bytes.saturating_add(diff.compressed_bytes_hint as u128);
            max_fee_bps = max_fee_bps.max(diff.max_fee_bps);
            bid_ids.push(diff.compression_bid_id.clone().expect("checked"));
            cache_reservation_ids.push(diff.cache_reservation_id.clone().expect("checked"));
            leaves.push(json!({
                "diff_id": diff.id,
                "after_state_root": diff.after_state_root,
                "diff_commitment_root": diff.diff_commitment_root,
                "witness_root": diff.witness_root,
            }));
        }

        let diff_set_root = merkle_root(
            "private-l2-pq-recursive-state-diff-market:batch-diff-set",
            &leaves,
        );
        let batch_root = recursive_batch_root(
            request.domain,
            request.priority,
            &request.diff_ids,
            &bid_ids,
            &cache_reservation_ids,
            &diff_set_root,
            &request.aggregate_proof_root,
        );
        let id = recursive_batch_id(
            request.domain,
            request.priority,
            &batch_root,
            request.created_height,
        );
        let batch = RecursiveDiffBatch {
            id: id.clone(),
            domain: request.domain,
            priority: request.priority,
            diff_ids: request.diff_ids.clone(),
            bid_ids,
            cache_reservation_ids,
            batch_root,
            aggregate_proof_root: request.aggregate_proof_root,
            aggregate_signature_root: request.aggregate_signature_root,
            total_input_bytes,
            total_compressed_bytes,
            max_fee_bps,
            created_height: request.created_height,
            expires_height: request.created_height + self.config.batch_ttl_blocks,
            status: BatchStatus::Proved,
        };
        for diff_id in &request.diff_ids {
            if let Some(diff) = self.diffs.get_mut(diff_id) {
                diff.batch_id = Some(id.clone());
                diff.status = DiffStatus::Batched;
            }
        }
        self.batches.insert(id, batch.clone());
        self.counters.batches_built += 1;
        self.counters.total_compressed_bytes = self
            .counters
            .total_compressed_bytes
            .saturating_add(batch.total_compressed_bytes);
        Ok(batch)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishReceiptRequest,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<SettlementReceipt> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("settlement receipt capacity exceeded".to_string());
        }
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "unknown recursive diff batch".to_string())?;
        if batch.expired_at(request.published_height) {
            return Err("recursive diff batch expired".to_string());
        }
        let id = settlement_receipt_id(
            &request.batch_id,
            &request.recursive_receipt_root,
            &request.pq_receipt_signature_root,
            request.published_height,
        );
        let status = if request.finalize {
            ReceiptStatus::Finalized
        } else {
            ReceiptStatus::Published
        };
        let diff_ids = batch.diff_ids.clone();
        let bid_ids = batch.bid_ids.clone();
        let cache_ids = batch.cache_reservation_ids.clone();
        let receipt = SettlementReceipt {
            id: id.clone(),
            batch_id: request.batch_id.clone(),
            state_transition_root: request.state_transition_root,
            recursive_receipt_root: request.recursive_receipt_root,
            fee_root: request.fee_root,
            pq_receipt_signature_root: request.pq_receipt_signature_root,
            published_height: request.published_height,
            status,
        };
        self.receipts.insert(id.clone(), receipt.clone());
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = if request.finalize {
                BatchStatus::Settled
            } else {
                BatchStatus::Proved
            };
        }
        for bid_id in bid_ids {
            if let Some(bid) = self.compression_bids.get_mut(&bid_id) {
                bid.status = CompressionBidStatus::Consumed;
            }
        }
        for cache_id in cache_ids {
            if let Some(cache) = self.cache_reservations.get_mut(&cache_id) {
                cache.status = CacheReservationStatus::Consumed;
            }
        }
        for diff_id in diff_ids {
            if let Some(diff) = self.diffs.get_mut(&diff_id) {
                diff.receipt_id = Some(id.clone());
                if request.finalize {
                    diff.status = DiffStatus::Settled;
                }
            }
            if request.finalize {
                self.issue_rebate(&diff_id, &id, request.published_height)?;
            }
        }
        self.counters.receipts_published += 1;
        Ok(receipt)
    }

    pub fn issue_rebate(
        &mut self,
        diff_id: &str,
        receipt_id: &str,
        issued_height: u64,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<Option<FeeRebate>> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        let diff = self
            .diffs
            .get(diff_id)
            .ok_or_else(|| "unknown state diff".to_string())?;
        let rebate_units = ((diff.input_bytes.saturating_sub(diff.compressed_bytes_hint))
            .saturating_mul(self.config.target_rebate_bps as u64))
            / PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_BPS;
        if rebate_units == 0 {
            return Ok(None);
        }
        let id = rebate_id(
            diff_id,
            receipt_id,
            &diff.submitter_commitment,
            issued_height,
        );
        if let Some(existing) = self.rebates.get(&id) {
            return Ok(Some(existing.clone()));
        }
        let rebate = FeeRebate {
            id: id.clone(),
            diff_id: diff_id.to_string(),
            receipt_id: receipt_id.to_string(),
            beneficiary_commitment: diff.submitter_commitment.clone(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_units,
            rebate_bps: self.config.target_rebate_bps,
            issued_height,
            status: RebateStatus::Issued,
        };
        self.rebates.insert(id, rebate.clone());
        self.counters.rebates_issued += 1;
        self.counters.total_rebate_units = self
            .counters
            .total_rebate_units
            .saturating_add(rebate.rebate_units as u128);
        Ok(Some(rebate))
    }

    pub fn slash(
        &mut self,
        request: SlashRequest,
    ) -> PrivateL2PqRecursiveStateDiffMarketRuntimeResult<SlashingEvidence> {
        if self.slashing_evidence.len() >= self.config.max_slashes {
            return Err("slashing capacity exceeded".to_string());
        }
        let penalty_units = request
            .bond_units
            .saturating_mul(self.config.slashing_bps as u128)
            / PRIVATE_L2_PQ_RECURSIVE_STATE_DIFF_MARKET_RUNTIME_MAX_BPS as u128;
        let id = slashing_evidence_id(
            &request.subject_commitment,
            request.reason,
            &request.evidence_root,
            request.submitted_height,
        );
        let evidence = SlashingEvidence {
            id: id.clone(),
            subject_commitment: request.subject_commitment,
            reason: request.reason,
            diff_id: request.diff_id.clone(),
            batch_id: request.batch_id.clone(),
            evidence_root: request.evidence_root,
            penalty_units,
            submitted_height: request.submitted_height,
        };
        self.slashing_evidence.insert(id, evidence.clone());
        if let Some(diff_id) = request.diff_id {
            if let Some(diff) = self.diffs.get_mut(&diff_id) {
                diff.status = DiffStatus::Slashed;
            }
        }
        if let Some(batch_id) = request.batch_id {
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                batch.status = BatchStatus::Slashed;
            }
        }
        self.counters.slashes_recorded += 1;
        self.counters.total_slashed_bond_units = self
            .counters
            .total_slashed_bond_units
            .saturating_add(penalty_units);
        Ok(evidence)
    }

    pub fn expire_stale(&mut self, height: u64) -> usize {
        let mut expired = 0_usize;
        for diff in self.diffs.values_mut() {
            if diff.expired_at(height) {
                diff.status = DiffStatus::Expired;
                expired += 1;
            }
        }
        for bid in self.compression_bids.values_mut() {
            if bid.expired_at(height) {
                bid.status = CompressionBidStatus::Expired;
                expired += 1;
            }
        }
        for cache in self.cache_reservations.values_mut() {
            if cache.expires_height <= height && cache.status == CacheReservationStatus::Reserved {
                cache.status = CacheReservationStatus::Expired;
                expired += 1;
            }
        }
        for batch in self.batches.values_mut() {
            if batch.expired_at(height) {
                batch.status = BatchStatus::Expired;
                expired += 1;
            }
        }
        self.counters.expired_items = self.counters.expired_items.saturating_add(expired as u64);
        expired
    }

    pub fn roots(&self) -> Roots {
        Roots {
            diff_root: map_root(
                "private-l2-pq-recursive-state-diff-market:diffs",
                &self.diffs,
            ),
            proof_root: map_root(
                "private-l2-pq-recursive-state-diff-market:pq-proofs",
                &self.pq_proofs,
            ),
            bid_root: map_root(
                "private-l2-pq-recursive-state-diff-market:bids",
                &self.compression_bids,
            ),
            cache_root: map_root(
                "private-l2-pq-recursive-state-diff-market:cache",
                &self.cache_reservations,
            ),
            batch_root: map_root(
                "private-l2-pq-recursive-state-diff-market:batches",
                &self.batches,
            ),
            receipt_root: map_root(
                "private-l2-pq-recursive-state-diff-market:receipts",
                &self.receipts,
            ),
            rebate_root: map_root(
                "private-l2-pq-recursive-state-diff-market:rebates",
                &self.rebates,
            ),
            slash_root: map_root(
                "private-l2-pq-recursive-state-diff-market:slashes",
                &self.slashing_evidence,
            ),
            consumed_nullifier_root: set_root(
                "private-l2-pq-recursive-state-diff-market:nullifiers",
                &self.consumed_nullifiers,
            ),
            checkpoint_root: map_root(
                "private-l2-pq-recursive-state-diff-market:checkpoints",
                &self.checkpoints,
            ),
        }
    }

    pub fn live_diff_count(&self) -> u64 {
        self.diffs
            .values()
            .filter(|diff| diff.status.live())
            .count() as u64
    }

    pub fn open_batch_count(&self) -> u64 {
        self.batches
            .values()
            .filter(|batch| {
                matches!(
                    batch.status,
                    BatchStatus::Open | BatchStatus::Sealed | BatchStatus::Proved
                )
            })
            .count() as u64
    }

    pub fn checkpoint(&mut self, height: u64) -> MarketCheckpoint {
        let state_root = self.state_root();
        let id = checkpoint_id(&state_root, height);
        let checkpoint = MarketCheckpoint {
            id: id.clone(),
            height,
            state_root,
            live_diff_count: self.live_diff_count(),
            open_batch_count: self.open_batch_count(),
            total_input_bytes: self.counters.total_input_bytes,
            total_compressed_bytes: self.counters.total_compressed_bytes,
        };
        self.checkpoints.insert(id, checkpoint.clone());
        checkpoint
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "hash_suite": self.config.hash_suite,
            "pq_proof_suite": self.config.pq_proof_suite,
            "config": self.config,
            "counters": self.counters,
            "roots": roots,
            "diff_count": self.diffs.len(),
            "pq_proof_count": self.pq_proofs.len(),
            "compression_bid_count": self.compression_bids.len(),
            "cache_reservation_count": self.cache_reservations.len(),
            "batch_count": self.batches.len(),
            "receipt_count": self.receipts.len(),
            "rebate_count": self.rebates.len(),
            "slashing_evidence_count": self.slashing_evidence.len(),
            "consumed_nullifier_count": self.consumed_nullifiers.len(),
            "checkpoint_count": self.checkpoints.len(),
            "live_diff_count": self.live_diff_count(),
            "open_batch_count": self.open_batch_count(),
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_recursive_state_diff_market_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_recursive_state_diff_market_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_diff_id(
    domain: StateDiffDomain,
    priority: DiffPriority,
    before_state_root: &str,
    after_state_root: &str,
    privacy_nullifier: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:diff-id",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(priority.as_str()),
            HashPart::Str(before_state_root),
            HashPart::Str(after_state_root),
            HashPart::Str(privacy_nullifier),
            HashPart::U64(submitted_height),
        ],
        16,
    )
}

pub fn pq_diff_proof_id(
    diff_id: &str,
    proof_root: &str,
    signature_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:pq-proof-id",
        &[
            HashPart::Str(diff_id),
            HashPart::Str(proof_root),
            HashPart::Str(signature_root),
            HashPart::U64(submitted_height),
        ],
        16,
    )
}

pub fn compression_bid_id(
    diff_id: &str,
    prover_commitment: &str,
    bid_root: &str,
    posted_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:compression-bid-id",
        &[
            HashPart::Str(diff_id),
            HashPart::Str(prover_commitment),
            HashPart::Str(bid_root),
            HashPart::U64(posted_height),
        ],
        16,
    )
}

pub fn cache_reservation_id(
    diff_id: &str,
    cache_operator_commitment: &str,
    cache_key_root: &str,
    reserved_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:cache-reservation-id",
        &[
            HashPart::Str(diff_id),
            HashPart::Str(cache_operator_commitment),
            HashPart::Str(cache_key_root),
            HashPart::U64(reserved_height),
        ],
        16,
    )
}

pub fn recursive_batch_id(
    domain: StateDiffDomain,
    priority: DiffPriority,
    batch_root: &str,
    created_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:batch-id",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(priority.as_str()),
            HashPart::Str(batch_root),
            HashPart::U64(created_height),
        ],
        16,
    )
}

pub fn settlement_receipt_id(
    batch_id: &str,
    recursive_receipt_root: &str,
    pq_receipt_signature_root: &str,
    published_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:receipt-id",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(recursive_receipt_root),
            HashPart::Str(pq_receipt_signature_root),
            HashPart::U64(published_height),
        ],
        16,
    )
}

pub fn rebate_id(
    diff_id: &str,
    receipt_id: &str,
    beneficiary_commitment: &str,
    issued_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:rebate-id",
        &[
            HashPart::Str(diff_id),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(issued_height),
        ],
        16,
    )
}

pub fn slashing_evidence_id(
    subject_commitment: &str,
    reason: SlashReason,
    evidence_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:slash-id",
        &[
            HashPart::Str(subject_commitment),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(submitted_height),
        ],
        16,
    )
}

pub fn checkpoint_id(state_root: &str, height: u64) -> String {
    domain_hash(
        "private-l2-pq-recursive-state-diff-market:checkpoint-id",
        &[HashPart::Str(state_root), HashPart::U64(height)],
        16,
    )
}

pub fn recursive_batch_root(
    domain: StateDiffDomain,
    priority: DiffPriority,
    diff_ids: &[String],
    bid_ids: &[String],
    cache_reservation_ids: &[String],
    diff_set_root: &str,
    aggregate_proof_root: &str,
) -> String {
    let record = json!({
        "domain": domain.as_str(),
        "priority": priority.as_str(),
        "diff_ids": diff_ids,
        "bid_ids": bid_ids,
        "cache_reservation_ids": cache_reservation_ids,
        "diff_set_root": diff_set_root,
        "aggregate_proof_root": aggregate_proof_root,
    });
    root_from_record(
        "private-l2-pq-recursive-state-diff-market:batch-root",
        &record,
    )
}

pub fn root_from_strings(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "private-l2-pq-recursive-state-diff-market:state-root",
        record,
    )
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).expect("serializable map value"),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
