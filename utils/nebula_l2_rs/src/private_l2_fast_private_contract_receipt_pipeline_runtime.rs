use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-private-contract-receipt-pipeline-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-private-contract-receipts-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024+xwing-sealed-contract-call-notes-v1";
pub const RECEIPT_PROOF_SUITE: &str = "recursive-stark-private-contract-receipt-inclusion-proof-v1";
pub const LOW_FEE_CACHE_SUITE: &str = "low-fee-calldata-proof-cache-pipeline-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 2_510_000;
pub const DEFAULT_DEVNET_EPOCH: u64 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_PRERECEIPT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 6;
pub const DEFAULT_MAX_ACTIVE_SLOTS: usize = 262_144;
pub const DEFAULT_MAX_PRERECEIPTS: usize = 524_288;
pub const DEFAULT_MAX_BATCHES: usize = 131_072;
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS_PER_BATCH: usize = 8_192;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_REBATE_BPS: u64 = 9;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractLane {
    PrivateCall,
    ConfidentialToken,
    PrivateDefi,
    ConfidentialAmm,
    Lending,
    Perpetuals,
    Oracle,
    Paymaster,
    MoneroBridge,
    Emergency,
}

impl ContractLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCall => "private_call",
            Self::ConfidentialToken => "confidential_token",
            Self::PrivateDefi => "private_defi",
            Self::ConfidentialAmm => "confidential_amm",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Oracle => "oracle",
            Self::Paymaster => "paymaster",
            Self::MoneroBridge => "monero_bridge",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::MoneroBridge => 9_600,
            Self::Perpetuals => 9_200,
            Self::PrivateDefi => 8_900,
            Self::ConfidentialAmm => 8_700,
            Self::Lending => 8_500,
            Self::ConfidentialToken => 8_200,
            Self::PrivateCall => 8_000,
            Self::Paymaster => 7_700,
            Self::Oracle => 7_300,
        }
    }

    pub fn latency_target_ms(self) -> u64 {
        match self {
            Self::Emergency => 350,
            Self::MoneroBridge => 500,
            Self::Perpetuals => 550,
            Self::PrivateDefi | Self::ConfidentialAmm => 650,
            Self::Lending => 750,
            Self::ConfidentialToken => 850,
            Self::PrivateCall => 900,
            Self::Paymaster => 1_000,
            Self::Oracle => 1_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Reserved,
    Filled,
    Released,
    Expired,
    Slashed,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_prereceipt(self) -> bool {
        matches!(self, Self::Reserved | Self::Filled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    PrivatePreReceipt,
    SignatureVerified,
    CacheCoordinated,
    Batched,
    Finalized,
    Rejected,
    Slashed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivatePreReceipt => "private_pre_receipt",
            Self::SignatureVerified => "signature_verified",
            Self::CacheCoordinated => "cache_coordinated",
            Self::Batched => "batched",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn finalizable(self) -> bool {
        matches!(
            self,
            Self::SignatureVerified | Self::CacheCoordinated | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Aggregated,
    CacheReady,
    Finalized,
    Disputed,
    Slashed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Aggregated => "aggregated",
            Self::CacheReady => "cache_ready",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheKind {
    Calldata,
    ProofWitness,
    RecursiveProof,
    InclusionPath,
    FeeQuote,
    PrivacyPad,
}

impl CacheKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Calldata => "calldata",
            Self::ProofWitness => "proof_witness",
            Self::RecursiveProof => "recursive_proof",
            Self::InclusionPath => "inclusion_path",
            Self::FeeQuote => "fee_quote",
            Self::PrivacyPad => "privacy_pad",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    Reserved,
    Warm,
    Pinned,
    Consumed,
    Expired,
}

impl CacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Warm => "warm",
            Self::Pinned => "pinned",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Issued,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Issued => "issued",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    BadPqSignature,
    WrongReceiptRoot,
    DoubleReceipt,
    MissingCalldata,
    InvalidProof,
    FeeOvercharge,
    PrivacySetTooSmall,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadPqSignature => "bad_pq_signature",
            Self::WrongReceiptRoot => "wrong_receipt_root",
            Self::DoubleReceipt => "double_receipt",
            Self::MissingCalldata => "missing_calldata",
            Self::InvalidProof => "invalid_proof",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub slot_ttl_blocks: u64,
    pub prereceipt_ttl_blocks: u64,
    pub cache_ttl_blocks: u64,
    pub finality_delay_blocks: u64,
    pub max_active_slots: usize,
    pub max_prereceipts: usize,
    pub max_batches: usize,
    pub max_cache_entries: usize,
    pub max_receipts_per_batch: usize,
    pub target_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            prereceipt_ttl_blocks: DEFAULT_PRERECEIPT_TTL_BLOCKS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            finality_delay_blocks: DEFAULT_FINALITY_DELAY_BLOCKS,
            max_active_slots: DEFAULT_MAX_ACTIVE_SLOTS,
            max_prereceipts: DEFAULT_MAX_PRERECEIPTS,
            max_batches: DEFAULT_MAX_BATCHES,
            max_cache_entries: DEFAULT_MAX_CACHE_ENTRIES,
            max_receipts_per_batch: DEFAULT_MAX_RECEIPTS_PER_BATCH,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.schema_version,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "slot_ttl_blocks": self.slot_ttl_blocks,
            "prereceipt_ttl_blocks": self.prereceipt_ttl_blocks,
            "cache_ttl_blocks": self.cache_ttl_blocks,
            "finality_delay_blocks": self.finality_delay_blocks,
            "max_active_slots": self.max_active_slots,
            "max_prereceipts": self.max_prereceipts,
            "max_batches": self.max_batches,
            "max_cache_entries": self.max_cache_entries,
            "max_receipts_per_batch": self.max_receipts_per_batch,
            "target_fee_bps": self.target_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "slash_bps": self.slash_bps,
            "hash_suite": HASH_SUITE,
            "pq_signature_suite": PQ_SIGNATURE_SUITE,
            "pq_kem_suite": PQ_KEM_SUITE,
            "receipt_proof_suite": RECEIPT_PROOF_SUITE,
            "low_fee_cache_suite": LOW_FEE_CACHE_SUITE,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub slot_count: u64,
    pub prereceipt_count: u64,
    pub signature_verified_count: u64,
    pub cache_entry_count: u64,
    pub batch_count: u64,
    pub finalized_receipt_count: u64,
    pub rebate_count: u64,
    pub slash_count: u64,
    pub public_record_count: u64,
    pub total_reserved_fee: u128,
    pub total_rebated_fee: u128,
    pub total_slashed_bond: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_count": self.slot_count,
            "prereceipt_count": self.prereceipt_count,
            "signature_verified_count": self.signature_verified_count,
            "cache_entry_count": self.cache_entry_count,
            "batch_count": self.batch_count,
            "finalized_receipt_count": self.finalized_receipt_count,
            "rebate_count": self.rebate_count,
            "slash_count": self.slash_count,
            "public_record_count": self.public_record_count,
            "total_reserved_fee": self.total_reserved_fee.to_string(),
            "total_rebated_fee": self.total_rebated_fee.to_string(),
            "total_slashed_bond": self.total_slashed_bond.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub slot_root: String,
    pub prereceipt_root: String,
    pub batch_root: String,
    pub cache_root: String,
    pub finalized_receipt_root: String,
    pub rebate_root: String,
    pub slash_root: String,
    pub public_record_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_root": self.slot_root,
            "prereceipt_root": self.prereceipt_root,
            "batch_root": self.batch_root,
            "cache_root": self.cache_root,
            "finalized_receipt_root": self.finalized_receipt_root,
            "rebate_root": self.rebate_root,
            "slash_root": self.slash_root,
            "public_record_root": self.public_record_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlotReservationRequest {
    pub lane: ContractLane,
    pub sequencer_id: String,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub encrypted_call_root: String,
    pub max_fee: u128,
    pub priority_fee: u128,
    pub privacy_set_size: u64,
    pub requested_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreReceiptRequest {
    pub slot_id: String,
    pub sequencer_id: String,
    pub private_receipt_root: String,
    pub execution_trace_root: String,
    pub state_diff_root: String,
    pub nullifier_root: String,
    pub calldata_commitment: String,
    pub proof_commitment: String,
    pub fee_charged: u128,
    pub privacy_set_size: u64,
    pub pq_public_key_commitment: String,
    pub pq_signature: String,
    pub published_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateBatchRequest {
    pub sequencer_id: String,
    pub receipt_ids: Vec<String>,
    pub aggregation_height: u64,
    pub da_commitment_root: String,
    pub recursive_proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheCoordinateRequest {
    pub batch_id: String,
    pub cache_operator_id: String,
    pub calldata_bytes: u64,
    pub proof_bytes: u64,
    pub calldata_dedup_root: String,
    pub proof_cache_root: String,
    pub quoted_fee: u128,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalizeReceiptRequest {
    pub batch_id: String,
    pub finalizer_id: String,
    pub settlement_height: u64,
    pub settlement_root: String,
    pub proof_verification_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateRequest {
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashRequest {
    pub receipt_id: String,
    pub reporter_commitment: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub challenged_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionSlot {
    pub slot_id: String,
    pub lane: ContractLane,
    pub status: SlotStatus,
    pub sequencer_id: String,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub encrypted_call_root: String,
    pub max_fee: u128,
    pub priority_fee: u128,
    pub privacy_set_size: u64,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
}

impl ExecutionSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "sequencer_id": self.sequencer_id,
            "contract_commitment": self.contract_commitment,
            "caller_commitment": self.caller_commitment,
            "encrypted_call_root": self.encrypted_call_root,
            "max_fee": self.max_fee.to_string(),
            "priority_fee": self.priority_fee.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivatePreReceipt {
    pub receipt_id: String,
    pub slot_id: String,
    pub status: ReceiptStatus,
    pub sequencer_id: String,
    pub private_receipt_root: String,
    pub execution_trace_root: String,
    pub state_diff_root: String,
    pub nullifier_root: String,
    pub calldata_commitment: String,
    pub proof_commitment: String,
    pub fee_charged: u128,
    pub privacy_set_size: u64,
    pub pq_public_key_commitment: String,
    pub pq_signature: String,
    pub signature_transcript_root: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivatePreReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "slot_id": self.slot_id,
            "status": self.status.as_str(),
            "sequencer_id": self.sequencer_id,
            "private_receipt_root": self.private_receipt_root,
            "execution_trace_root": self.execution_trace_root,
            "state_diff_root": self.state_diff_root,
            "nullifier_root": self.nullifier_root,
            "calldata_commitment": self.calldata_commitment,
            "proof_commitment": self.proof_commitment,
            "fee_charged": self.fee_charged.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "pq_signature": self.pq_signature,
            "signature_transcript_root": self.signature_transcript_root,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub sequencer_id: String,
    pub receipt_ids: Vec<String>,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub state_diff_root: String,
    pub da_commitment_root: String,
    pub recursive_proof_root: String,
    pub total_fee: u128,
    pub aggregate_privacy_set_size: u64,
    pub aggregation_height: u64,
}

impl ReceiptBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "sequencer_id": self.sequencer_id,
            "receipt_ids": self.receipt_ids,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_diff_root": self.state_diff_root,
            "da_commitment_root": self.da_commitment_root,
            "recursive_proof_root": self.recursive_proof_root,
            "total_fee": self.total_fee.to_string(),
            "aggregate_privacy_set_size": self.aggregate_privacy_set_size,
            "aggregation_height": self.aggregation_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeCacheEntry {
    pub cache_id: String,
    pub batch_id: String,
    pub cache_operator_id: String,
    pub kind: CacheKind,
    pub status: CacheStatus,
    pub byte_size: u64,
    pub cache_root: String,
    pub quoted_fee: u128,
    pub expires_at_height: u64,
}

impl LowFeeCacheEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "cache_id": self.cache_id,
            "batch_id": self.batch_id,
            "cache_operator_id": self.cache_operator_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "byte_size": self.byte_size,
            "cache_root": self.cache_root,
            "quoted_fee": self.quoted_fee.to_string(),
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalizedReceipt {
    pub final_receipt_id: String,
    pub receipt_id: String,
    pub batch_id: String,
    pub finalizer_id: String,
    pub settlement_height: u64,
    pub settlement_root: String,
    pub proof_verification_root: String,
    pub finality_root: String,
}

impl FinalizedReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "final_receipt_id": self.final_receipt_id,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "finalizer_id": self.finalizer_id,
            "settlement_height": self.settlement_height,
            "settlement_root": self.settlement_root,
            "proof_verification_root": self.proof_verification_root,
            "finality_root": self.finality_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub status: RebateStatus,
    pub beneficiary_commitment: String,
    pub fee_charged: u128,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_charged": self.fee_charged.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashRecord {
    pub slash_id: String,
    pub receipt_id: String,
    pub sequencer_id: String,
    pub reporter_commitment: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub slashed_amount: u128,
    pub challenged_at_height: u64,
}

impl SlashRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "receipt_id": self.receipt_id,
            "sequencer_id": self.sequencer_id,
            "reporter_commitment": self.reporter_commitment,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slashed_amount": self.slashed_amount.to_string(),
            "challenged_at_height": self.challenged_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub slots: BTreeMap<String, ExecutionSlot>,
    pub prereceipts: BTreeMap<String, PrivatePreReceipt>,
    pub batches: BTreeMap<String, ReceiptBatch>,
    pub caches: BTreeMap<String, LowFeeCacheEntry>,
    pub finalized_receipts: BTreeMap<String, FinalizedReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashes: BTreeMap<String, SlashRecord>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub nullifiers: BTreeSet<String>,
    pub verified_signature_transcripts: BTreeSet<String>,
    pub bad_receipt_ids: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(
            Config::default(),
            DEFAULT_DEVNET_HEIGHT,
            DEFAULT_DEVNET_EPOCH,
        )
    }
}

impl State {
    pub fn new(config: Config, current_height: u64, current_epoch: u64) -> Self {
        Self {
            config,
            current_height,
            current_epoch,
            slots: BTreeMap::new(),
            prereceipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            caches: BTreeMap::new(),
            finalized_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashes: BTreeMap::new(),
            public_records: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            verified_signature_transcripts: BTreeSet::new(),
            bad_receipt_ids: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEFAULT_DEVNET_HEIGHT,
            DEFAULT_DEVNET_EPOCH,
        );
        let slot = state
            .reserve_fast_contract_execution_slot(SlotReservationRequest {
                lane: ContractLane::PrivateDefi,
                sequencer_id: "devnet-pq-fast-sequencer-0".to_string(),
                contract_commitment: deterministic_root("DEVNET-CONTRACT", "private-amm"),
                caller_commitment: deterministic_root("DEVNET-CALLER", "alice"),
                encrypted_call_root: deterministic_root("DEVNET-ENCRYPTED-CALL", "swap-xmr-usd"),
                max_fee: 25_000,
                priority_fee: 750,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                requested_at_height: DEFAULT_DEVNET_HEIGHT,
            })
            .expect("devnet slot");
        let transcript = receipt_signature_transcript_root(
            &slot.slot_id,
            "devnet-pq-fast-sequencer-0",
            &deterministic_root("DEVNET-PRIVATE-RECEIPT", "swap-xmr-usd"),
            &deterministic_root("DEVNET-TRACE", "swap-xmr-usd"),
            &deterministic_root("DEVNET-STATE-DIFF", "swap-xmr-usd"),
            &deterministic_root("DEVNET-NULLIFIER", "swap-xmr-usd"),
            21_000,
        );
        let signature = devnet_pq_signature("devnet-pq-fast-sequencer-0", &transcript);
        let receipt = state
            .publish_private_prereceipt(PreReceiptRequest {
                slot_id: slot.slot_id.clone(),
                sequencer_id: "devnet-pq-fast-sequencer-0".to_string(),
                private_receipt_root: deterministic_root("DEVNET-PRIVATE-RECEIPT", "swap-xmr-usd"),
                execution_trace_root: deterministic_root("DEVNET-TRACE", "swap-xmr-usd"),
                state_diff_root: deterministic_root("DEVNET-STATE-DIFF", "swap-xmr-usd"),
                nullifier_root: deterministic_root("DEVNET-NULLIFIER", "swap-xmr-usd"),
                calldata_commitment: deterministic_root("DEVNET-CALLDATA", "swap-xmr-usd"),
                proof_commitment: deterministic_root("DEVNET-PROOF", "swap-xmr-usd"),
                fee_charged: 21_000,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                pq_public_key_commitment: deterministic_root("DEVNET-PQ-PUBKEY", "sequencer-0"),
                pq_signature: signature,
                published_at_height: DEFAULT_DEVNET_HEIGHT + 1,
            })
            .expect("devnet prereceipt");
        state
            .verify_pq_receipt_signature(&receipt.receipt_id)
            .expect("devnet signature");
        let batch = state
            .aggregate_receipt_batch(AggregateBatchRequest {
                sequencer_id: "devnet-pq-fast-sequencer-0".to_string(),
                receipt_ids: vec![receipt.receipt_id.clone()],
                aggregation_height: DEFAULT_DEVNET_HEIGHT + 2,
                da_commitment_root: deterministic_root("DEVNET-DA", "batch-0"),
                recursive_proof_root: deterministic_root("DEVNET-RECURSIVE-PROOF", "batch-0"),
            })
            .expect("devnet batch");
        state
            .coordinate_low_fee_cache(CacheCoordinateRequest {
                batch_id: batch.batch_id.clone(),
                cache_operator_id: "devnet-low-fee-cache-0".to_string(),
                calldata_bytes: 4_096,
                proof_bytes: 16_384,
                calldata_dedup_root: deterministic_root("DEVNET-CALLDATA-DEDUP", "batch-0"),
                proof_cache_root: deterministic_root("DEVNET-PROOF-CACHE", "batch-0"),
                quoted_fee: 1_400,
                expires_at_height: DEFAULT_DEVNET_HEIGHT + DEFAULT_CACHE_TTL_BLOCKS,
            })
            .expect("devnet cache");
        state
    }

    pub fn reserve_fast_contract_execution_slot(
        &mut self,
        request: SlotReservationRequest,
    ) -> Result<ExecutionSlot> {
        ensure_non_empty(&request.sequencer_id, "sequencer_id")?;
        ensure_non_empty(&request.contract_commitment, "contract_commitment")?;
        ensure_non_empty(&request.caller_commitment, "caller_commitment")?;
        ensure_non_empty(&request.encrypted_call_root, "encrypted_call_root")?;
        if self.slots.len() >= self.config.max_active_slots {
            return Err("slot capacity exhausted".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below minimum".to_string());
        }
        if fee_bps(request.priority_fee, request.max_fee) > self.config.max_user_fee_bps {
            return Err("priority fee exceeds max user fee bps".to_string());
        }
        let slot_id = execution_slot_id(
            request.lane,
            &request.sequencer_id,
            &request.contract_commitment,
            &request.caller_commitment,
            request.requested_at_height,
            self.slots.len() as u64,
        );
        if self.slots.contains_key(&slot_id) {
            return Err("slot already exists".to_string());
        }
        let slot = ExecutionSlot {
            slot_id: slot_id.clone(),
            lane: request.lane,
            status: SlotStatus::Reserved,
            sequencer_id: request.sequencer_id,
            contract_commitment: request.contract_commitment,
            caller_commitment: request.caller_commitment,
            encrypted_call_root: request.encrypted_call_root,
            max_fee: request.max_fee,
            priority_fee: request.priority_fee,
            privacy_set_size: request.privacy_set_size,
            requested_at_height: request.requested_at_height,
            expires_at_height: request
                .requested_at_height
                .saturating_add(self.config.slot_ttl_blocks),
        };
        self.slots.insert(slot_id.clone(), slot.clone());
        self.publish_public_record(
            "slot",
            &slot_id,
            slot.requested_at_height,
            &slot.public_record(),
        )?;
        Ok(slot)
    }

    pub fn publish_private_prereceipt(
        &mut self,
        request: PreReceiptRequest,
    ) -> Result<PrivatePreReceipt> {
        ensure_non_empty(&request.slot_id, "slot_id")?;
        ensure_non_empty(&request.private_receipt_root, "private_receipt_root")?;
        ensure_non_empty(&request.nullifier_root, "nullifier_root")?;
        if self.prereceipts.len() >= self.config.max_prereceipts {
            return Err("prereceipt capacity exhausted".to_string());
        }
        if self.nullifiers.contains(&request.nullifier_root) {
            return Err("duplicate nullifier".to_string());
        }
        let slot = self
            .slots
            .get_mut(&request.slot_id)
            .ok_or_else(|| "slot missing".to_string())?;
        if slot.sequencer_id != request.sequencer_id {
            return Err("slot sequencer mismatch".to_string());
        }
        if !slot.status.accepts_prereceipt() {
            return Err("slot does not accept prereceipts".to_string());
        }
        if request.fee_charged > slot.max_fee {
            return Err("fee exceeds slot max fee".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below minimum".to_string());
        }
        let transcript = receipt_signature_transcript_root(
            &request.slot_id,
            &request.sequencer_id,
            &request.private_receipt_root,
            &request.execution_trace_root,
            &request.state_diff_root,
            &request.nullifier_root,
            request.fee_charged,
        );
        let receipt_id = private_prereceipt_id(
            &request.slot_id,
            &request.sequencer_id,
            &request.private_receipt_root,
            &request.nullifier_root,
            request.published_at_height,
        );
        let receipt = PrivatePreReceipt {
            receipt_id: receipt_id.clone(),
            slot_id: request.slot_id,
            status: ReceiptStatus::PrivatePreReceipt,
            sequencer_id: request.sequencer_id,
            private_receipt_root: request.private_receipt_root,
            execution_trace_root: request.execution_trace_root,
            state_diff_root: request.state_diff_root,
            nullifier_root: request.nullifier_root,
            calldata_commitment: request.calldata_commitment,
            proof_commitment: request.proof_commitment,
            fee_charged: request.fee_charged,
            privacy_set_size: request.privacy_set_size,
            pq_public_key_commitment: request.pq_public_key_commitment,
            pq_signature: request.pq_signature,
            signature_transcript_root: transcript,
            published_at_height: request.published_at_height,
            expires_at_height: request
                .published_at_height
                .saturating_add(self.config.prereceipt_ttl_blocks),
        };
        slot.status = SlotStatus::Filled;
        self.nullifiers.insert(receipt.nullifier_root.clone());
        self.prereceipts.insert(receipt_id.clone(), receipt.clone());
        self.publish_public_record(
            "private_pre_receipt",
            &receipt_id,
            receipt.published_at_height,
            &receipt.public_record(),
        )?;
        Ok(receipt)
    }

    pub fn verify_pq_receipt_signature(&mut self, receipt_id: &str) -> Result<String> {
        let expected = {
            let receipt = self
                .prereceipts
                .get(receipt_id)
                .ok_or_else(|| "receipt missing".to_string())?;
            devnet_pq_signature(&receipt.sequencer_id, &receipt.signature_transcript_root)
        };
        let receipt = self
            .prereceipts
            .get_mut(receipt_id)
            .ok_or_else(|| "receipt missing".to_string())?;
        if receipt.pq_signature != expected {
            receipt.status = ReceiptStatus::Rejected;
            return Err("pq receipt signature mismatch".to_string());
        }
        receipt.status = ReceiptStatus::SignatureVerified;
        let transcript = receipt.signature_transcript_root.clone();
        let public_record = receipt.public_record();
        let height = receipt.published_at_height;
        self.verified_signature_transcripts
            .insert(transcript.clone());
        self.publish_public_record("pq_signature_verified", receipt_id, height, &public_record)?;
        Ok(transcript)
    }

    pub fn aggregate_receipt_batch(
        &mut self,
        request: AggregateBatchRequest,
    ) -> Result<ReceiptBatch> {
        ensure_non_empty(&request.sequencer_id, "sequencer_id")?;
        ensure_non_empty(&request.da_commitment_root, "da_commitment_root")?;
        ensure_non_empty(&request.recursive_proof_root, "recursive_proof_root")?;
        if request.receipt_ids.is_empty() {
            return Err("empty receipt batch".to_string());
        }
        if request.receipt_ids.len() > self.config.max_receipts_per_batch {
            return Err("too many receipts in batch".to_string());
        }
        if self.batches.len() >= self.config.max_batches {
            return Err("batch capacity exhausted".to_string());
        }
        let mut receipt_records = Vec::with_capacity(request.receipt_ids.len());
        let mut nullifier_records = Vec::with_capacity(request.receipt_ids.len());
        let mut state_diff_records = Vec::with_capacity(request.receipt_ids.len());
        let mut total_fee = 0_u128;
        let mut aggregate_privacy_set_size = 0_u64;
        for receipt_id in &request.receipt_ids {
            let receipt = self
                .prereceipts
                .get(receipt_id)
                .ok_or_else(|| format!("receipt missing: {receipt_id}"))?;
            if receipt.sequencer_id != request.sequencer_id {
                return Err("batch sequencer mismatch".to_string());
            }
            if !receipt.status.finalizable() {
                return Err("receipt is not ready for batching".to_string());
            }
            receipt_records.push(receipt.public_record());
            nullifier_records.push(Value::String(receipt.nullifier_root.clone()));
            state_diff_records.push(Value::String(receipt.state_diff_root.clone()));
            total_fee = total_fee.saturating_add(receipt.fee_charged);
            aggregate_privacy_set_size =
                aggregate_privacy_set_size.saturating_add(receipt.privacy_set_size);
        }
        let receipt_root = merkle_root(
            "PRIVATE-L2-CONTRACT-RECEIPT-BATCH-RECEIPTS",
            &receipt_records,
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONTRACT-RECEIPT-BATCH-NULLIFIERS",
            &nullifier_records,
        );
        let state_diff_root = merkle_root(
            "PRIVATE-L2-CONTRACT-RECEIPT-BATCH-STATE-DIFFS",
            &state_diff_records,
        );
        let batch_id = receipt_batch_id(
            &request.sequencer_id,
            &receipt_root,
            &request.da_commitment_root,
            request.aggregation_height,
        );
        let batch = ReceiptBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Aggregated,
            sequencer_id: request.sequencer_id,
            receipt_ids: request.receipt_ids,
            receipt_root,
            nullifier_root,
            state_diff_root,
            da_commitment_root: request.da_commitment_root,
            recursive_proof_root: request.recursive_proof_root,
            total_fee,
            aggregate_privacy_set_size,
            aggregation_height: request.aggregation_height,
        };
        for receipt_id in &batch.receipt_ids {
            if let Some(receipt) = self.prereceipts.get_mut(receipt_id) {
                receipt.status = ReceiptStatus::Batched;
            }
        }
        self.batches.insert(batch_id.clone(), batch.clone());
        self.publish_public_record(
            "receipt_batch",
            &batch_id,
            batch.aggregation_height,
            &batch.public_record(),
        )?;
        Ok(batch)
    }

    pub fn coordinate_low_fee_cache(
        &mut self,
        request: CacheCoordinateRequest,
    ) -> Result<Vec<LowFeeCacheEntry>> {
        ensure_non_empty(&request.batch_id, "batch_id")?;
        ensure_non_empty(&request.cache_operator_id, "cache_operator_id")?;
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        if self.caches.len().saturating_add(2) > self.config.max_cache_entries {
            return Err("cache capacity exhausted".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("cache expiry must be in the future".to_string());
        }
        let calldata = LowFeeCacheEntry {
            cache_id: low_fee_cache_id(
                &request.batch_id,
                &request.cache_operator_id,
                CacheKind::Calldata,
                &request.calldata_dedup_root,
            ),
            batch_id: request.batch_id.clone(),
            cache_operator_id: request.cache_operator_id.clone(),
            kind: CacheKind::Calldata,
            status: CacheStatus::Pinned,
            byte_size: request.calldata_bytes,
            cache_root: request.calldata_dedup_root,
            quoted_fee: request.quoted_fee / 2,
            expires_at_height: request.expires_at_height,
        };
        let proof = LowFeeCacheEntry {
            cache_id: low_fee_cache_id(
                &request.batch_id,
                &request.cache_operator_id,
                CacheKind::ProofWitness,
                &request.proof_cache_root,
            ),
            batch_id: request.batch_id.clone(),
            cache_operator_id: request.cache_operator_id,
            kind: CacheKind::ProofWitness,
            status: CacheStatus::Pinned,
            byte_size: request.proof_bytes,
            cache_root: request.proof_cache_root,
            quoted_fee: request.quoted_fee.saturating_sub(request.quoted_fee / 2),
            expires_at_height: request.expires_at_height,
        };
        batch.status = BatchStatus::CacheReady;
        for receipt_id in &batch.receipt_ids {
            if let Some(receipt) = self.prereceipts.get_mut(receipt_id) {
                receipt.status = ReceiptStatus::CacheCoordinated;
            }
        }
        self.caches
            .insert(calldata.cache_id.clone(), calldata.clone());
        self.caches.insert(proof.cache_id.clone(), proof.clone());
        self.publish_public_record(
            "low_fee_calldata_cache",
            &calldata.cache_id,
            self.current_height,
            &calldata.public_record(),
        )?;
        self.publish_public_record(
            "low_fee_proof_cache",
            &proof.cache_id,
            self.current_height,
            &proof.public_record(),
        )?;
        Ok(vec![calldata, proof])
    }

    pub fn finalize_contract_receipts(
        &mut self,
        request: FinalizeReceiptRequest,
    ) -> Result<Vec<FinalizedReceipt>> {
        ensure_non_empty(&request.finalizer_id, "finalizer_id")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        ensure_non_empty(&request.proof_verification_root, "proof_verification_root")?;
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        if !matches!(
            batch.status,
            BatchStatus::Aggregated | BatchStatus::CacheReady
        ) {
            return Err("batch is not finalizable".to_string());
        }
        if request.settlement_height
            < batch
                .aggregation_height
                .saturating_add(self.config.finality_delay_blocks)
        {
            return Err("finality delay not elapsed".to_string());
        }
        let mut finalized = Vec::with_capacity(batch.receipt_ids.len());
        for receipt_id in batch.receipt_ids.clone() {
            let receipt = self
                .prereceipts
                .get_mut(&receipt_id)
                .ok_or_else(|| format!("receipt missing: {receipt_id}"))?;
            if !receipt.status.finalizable() {
                return Err("receipt is not finalizable".to_string());
            }
            receipt.status = ReceiptStatus::Finalized;
            let finality_root = finality_root(
                &receipt_id,
                &request.batch_id,
                &request.settlement_root,
                &request.proof_verification_root,
            );
            let final_receipt_id =
                finalized_receipt_id(&receipt_id, &request.batch_id, request.settlement_height);
            let record = FinalizedReceipt {
                final_receipt_id: final_receipt_id.clone(),
                receipt_id,
                batch_id: request.batch_id.clone(),
                finalizer_id: request.finalizer_id.clone(),
                settlement_height: request.settlement_height,
                settlement_root: request.settlement_root.clone(),
                proof_verification_root: request.proof_verification_root.clone(),
                finality_root,
            };
            self.finalized_receipts
                .insert(final_receipt_id.clone(), record.clone());
            finalized.push(record);
        }
        batch.status = BatchStatus::Finalized;
        for record in &finalized {
            self.publish_public_record(
                "finalized_contract_receipt",
                &record.final_receipt_id,
                record.settlement_height,
                &record.public_record(),
            )?;
        }
        Ok(finalized)
    }

    pub fn issue_rebate(&mut self, request: RebateRequest) -> Result<FeeRebate> {
        ensure_non_empty(&request.beneficiary_commitment, "beneficiary_commitment")?;
        if request.rebate_bps > self.config.max_user_fee_bps.max(self.config.rebate_bps) {
            return Err("rebate bps exceeds policy".to_string());
        }
        let receipt = self
            .prereceipts
            .get(&request.receipt_id)
            .ok_or_else(|| "receipt missing".to_string())?;
        if receipt.status != ReceiptStatus::Finalized {
            return Err("rebate requires finalized receipt".to_string());
        }
        let rebate_amount = receipt
            .fee_charged
            .saturating_mul(request.rebate_bps as u128)
            / MAX_BPS as u128;
        let rebate_id = rebate_id(
            &request.receipt_id,
            &request.beneficiary_commitment,
            request.issued_at_height,
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: request.receipt_id,
            status: RebateStatus::Issued,
            beneficiary_commitment: request.beneficiary_commitment,
            fee_charged: receipt.fee_charged,
            rebate_amount,
            rebate_bps: request.rebate_bps,
            issued_at_height: request.issued_at_height,
        };
        self.rebates.insert(rebate_id.clone(), rebate.clone());
        self.publish_public_record(
            "fee_rebate",
            &rebate_id,
            rebate.issued_at_height,
            &rebate.public_record(),
        )?;
        Ok(rebate)
    }

    pub fn slash_bad_sequencer_receipt(&mut self, request: SlashRequest) -> Result<SlashRecord> {
        ensure_non_empty(&request.reporter_commitment, "reporter_commitment")?;
        ensure_non_empty(&request.evidence_root, "evidence_root")?;
        let receipt = self
            .prereceipts
            .get_mut(&request.receipt_id)
            .ok_or_else(|| "receipt missing".to_string())?;
        let slashable = match request.reason {
            SlashReason::BadPqSignature => {
                receipt.pq_signature
                    != devnet_pq_signature(
                        &receipt.sequencer_id,
                        &receipt.signature_transcript_root,
                    )
            }
            SlashReason::WrongReceiptRoot | SlashReason::InvalidProof => {
                request.evidence_root != receipt.proof_commitment
            }
            SlashReason::DoubleReceipt => {
                self.bad_receipt_ids.contains(&request.receipt_id)
                    || self.nullifiers.contains(&receipt.nullifier_root)
            }
            SlashReason::MissingCalldata => request.evidence_root != receipt.calldata_commitment,
            SlashReason::FeeOvercharge => {
                receipt.fee_charged
                    > self
                        .slots
                        .get(&receipt.slot_id)
                        .map(|slot| slot.max_fee)
                        .unwrap_or_default()
            }
            SlashReason::PrivacySetTooSmall => {
                receipt.privacy_set_size < self.config.min_privacy_set_size
            }
        };
        if !slashable {
            return Err("evidence does not establish slashable receipt".to_string());
        }
        receipt.status = ReceiptStatus::Slashed;
        self.bad_receipt_ids.insert(request.receipt_id.clone());
        if let Some(slot) = self.slots.get_mut(&receipt.slot_id) {
            slot.status = SlotStatus::Slashed;
        }
        let base = receipt.fee_charged.max(1);
        let slashed_amount = base.saturating_mul(self.config.slash_bps as u128) / MAX_BPS as u128;
        let slash_id = slash_id(
            &request.receipt_id,
            &receipt.sequencer_id,
            request.reason,
            request.challenged_at_height,
        );
        let slash = SlashRecord {
            slash_id: slash_id.clone(),
            receipt_id: request.receipt_id,
            sequencer_id: receipt.sequencer_id.clone(),
            reporter_commitment: request.reporter_commitment,
            reason: request.reason,
            evidence_root: request.evidence_root,
            slashed_amount,
            challenged_at_height: request.challenged_at_height,
        };
        self.slashes.insert(slash_id.clone(), slash.clone());
        self.publish_public_record(
            "sequencer_slash",
            &slash_id,
            slash.challenged_at_height,
            &slash.public_record(),
        )?;
        Ok(slash)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            slot_root: map_root("PRIVATE-L2-CONTRACT-RECEIPT-SLOTS", &self.slots, |slot| {
                slot.public_record()
            }),
            prereceipt_root: map_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-PRERECEIPTS",
                &self.prereceipts,
                |receipt| receipt.public_record(),
            ),
            batch_root: map_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-BATCHES",
                &self.batches,
                |batch| batch.public_record(),
            ),
            cache_root: map_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-CACHES",
                &self.caches,
                |cache| cache.public_record(),
            ),
            finalized_receipt_root: map_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-FINALIZED",
                &self.finalized_receipts,
                |receipt| receipt.public_record(),
            ),
            rebate_root: map_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-REBATES",
                &self.rebates,
                |rebate| rebate.public_record(),
            ),
            slash_root: map_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-SLASHES",
                &self.slashes,
                |slash| slash.public_record(),
            ),
            public_record_root: map_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-PUBLIC-RECORDS",
                &self.public_records,
                |record| record.public_record(),
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-CONTRACT-RECEIPT-NULLIFIER-SET",
                &self
                    .nullifiers
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            slot_count: self.slots.len() as u64,
            prereceipt_count: self.prereceipts.len() as u64,
            signature_verified_count: self.verified_signature_transcripts.len() as u64,
            cache_entry_count: self.caches.len() as u64,
            batch_count: self.batches.len() as u64,
            finalized_receipt_count: self.finalized_receipts.len() as u64,
            rebate_count: self.rebates.len() as u64,
            slash_count: self.slashes.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_reserved_fee: self.slots.values().map(|slot| slot.max_fee).sum(),
            total_rebated_fee: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_amount)
                .sum(),
            total_slashed_bond: self
                .slashes
                .values()
                .map(|slash| slash.slashed_amount)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(map) = &mut record {
            map.insert(
                "private_l2_fast_private_contract_receipt_pipeline_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn publish_public_record(
        &mut self,
        kind: &str,
        subject_id: &str,
        height: u64,
        payload: &Value,
    ) -> Result<PublicRecord> {
        ensure_non_empty(kind, "public record kind")?;
        ensure_non_empty(subject_id, "public record subject")?;
        let payload_root = payload_root("PRIVATE-L2-CONTRACT-RECEIPT-PUBLIC-PAYLOAD", payload);
        let record_id = public_record_id(kind, subject_id, height, &payload_root);
        let record = PublicRecord {
            record_id: record_id.clone(),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            height,
            payload_root,
        };
        self.public_records.insert(record_id, record.clone());
        Ok(record)
    }
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn fee_bps(part: u128, total: u128) -> u64 {
    if total == 0 {
        return 0;
    }
    part.saturating_mul(MAX_BPS as u128)
        .saturating_div(total)
        .min(MAX_BPS as u128) as u64
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, to_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values
        .iter()
        .map(|(key, value)| json!({"key": key, "record": to_record(value)}))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-CONTRACT-RECEIPT-PIPELINE-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn execution_slot_id(
    lane: ContractLane,
    sequencer_id: &str,
    contract_commitment: &str,
    caller_commitment: &str,
    requested_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-EXECUTION-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sequencer_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(caller_commitment),
            HashPart::U64(requested_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn receipt_signature_transcript_root(
    slot_id: &str,
    sequencer_id: &str,
    private_receipt_root: &str,
    execution_trace_root: &str,
    state_diff_root: &str,
    nullifier_root: &str,
    fee_charged: u128,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-PQ-SIGNATURE-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(PQ_SIGNATURE_SUITE),
            HashPart::Str(slot_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(private_receipt_root),
            HashPart::Str(execution_trace_root),
            HashPart::Str(state_diff_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(fee_charged as i128),
        ],
        32,
    )
}

pub fn private_prereceipt_id(
    slot_id: &str,
    sequencer_id: &str,
    private_receipt_root: &str,
    nullifier_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-PRERECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(slot_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(private_receipt_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(published_at_height),
        ],
        32,
    )
}

pub fn receipt_batch_id(
    sequencer_id: &str,
    receipt_root: &str,
    da_commitment_root: &str,
    aggregation_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sequencer_id),
            HashPart::Str(receipt_root),
            HashPart::Str(da_commitment_root),
            HashPart::U64(aggregation_height),
        ],
        32,
    )
}

pub fn low_fee_cache_id(
    batch_id: &str,
    cache_operator_id: &str,
    kind: CacheKind,
    cache_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-LOW-FEE-CACHE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(cache_operator_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(cache_root),
        ],
        32,
    )
}

pub fn finalized_receipt_id(receipt_id: &str, batch_id: &str, settlement_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-FINALIZED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(batch_id),
            HashPart::U64(settlement_height),
        ],
        32,
    )
}

pub fn finality_root(
    receipt_id: &str,
    batch_id: &str,
    settlement_root: &str,
    proof_verification_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-FINALITY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_root),
            HashPart::Str(proof_verification_root),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, beneficiary_commitment: &str, issued_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn slash_id(
    receipt_id: &str,
    sequencer_id: &str,
    reason: SlashReason,
    challenged_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-SLASH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(sequencer_id),
            HashPart::Str(reason.as_str()),
            HashPart::U64(challenged_at_height),
        ],
        32,
    )
}

pub fn public_record_id(kind: &str, subject_id: &str, height: u64, payload_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn devnet_pq_signature(sequencer_id: &str, transcript_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RECEIPT-DEVNET-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(PQ_SIGNATURE_SUITE),
            HashPart::Str(sequencer_id),
            HashPart::Str(transcript_root),
        ],
        64,
    )
}
