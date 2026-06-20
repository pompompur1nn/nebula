use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<T> = Result<T>;

pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-state-diff-compression-market-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_COMPRESSION_SUITE: &str =
    "pq-private-state-diff-ticket-compression-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PQ_PROOF_SLOT_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-compression-committee-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROOF_BATCHING_SUITE: &str =
    "recursive-stark-compressed-batch-settlement-v1";
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 880_000;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_LANES: usize = 128;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_TICKETS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_BIDS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_PROOF_SLOTS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    4_194_304;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_REBATES: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 8_192;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    14;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    9;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 =
    8_500;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS: u64 =
    48;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT:
    u64 = 67;
pub const PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCH_TICKETS:
    usize = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateDiffLaneKind {
    PrivateContractCall,
    ConfidentialTokenTransfer,
    PrivateDefiSwap,
    PrivateLending,
    PrivatePerpMargin,
    MoneroFastExit,
    SequencerInbox,
    RuntimeCheckpoint,
    EmergencyEscape,
}

impl StateDiffLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerpMargin => "private_perp_margin",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::SequencerInbox => "sequencer_inbox",
            Self::RuntimeCheckpoint => "runtime_checkpoint",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_latency_target_ms(self) -> u64 {
        match self {
            Self::EmergencyEscape => 450,
            Self::MoneroFastExit => 600,
            Self::PrivatePerpMargin => 650,
            Self::PrivateDefiSwap => 700,
            Self::PrivateLending => 800,
            Self::ConfidentialTokenTransfer => 900,
            Self::PrivateContractCall => 1_000,
            Self::SequencerInbox => 1_200,
            Self::RuntimeCheckpoint => 2_000,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::MoneroFastExit => 9_600,
            Self::PrivatePerpMargin => 9_200,
            Self::PrivateDefiSwap => 8_900,
            Self::PrivateLending => 8_600,
            Self::ConfidentialTokenTransfer => 8_300,
            Self::PrivateContractCall => 8_000,
            Self::SequencerInbox => 7_500,
            Self::RuntimeCheckpoint => 6_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_tickets(self) -> bool {
        matches!(self, Self::Open | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketEncoding {
    CiphertextChunks,
    ErasureShardSet,
    ReedSolomonCiphertext,
    KzgBackedCiphertext,
    FecTreeCiphertext,
    RecursiveProofWitness,
}

impl TicketEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CiphertextChunks => "ciphertext_chunks",
            Self::ErasureShardSet => "erasure_shard_set",
            Self::ReedSolomonCiphertext => "reed_solomon_ciphertext",
            Self::KzgBackedCiphertext => "kzg_backed_ciphertext",
            Self::FecTreeCiphertext => "fec_tree_ciphertext",
            Self::RecursiveProofWitness => "recursive_proof_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Submitted,
    BidSelected,
    Reserved,
    Attested,
    BatchReady,
    Settled,
    Delivered,
    Rebated,
    Expired,
    Rejected,
}

impl TicketStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::BidSelected
                | Self::Reserved
                | Self::Attested
                | Self::BatchReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCompressorClass {
    SequencerOperated,
    CommunityArchive,
    FastEdgeCache,
    ColdProofArchive,
    SponsorBacked,
    MoneroBridgeRelay,
}

impl CompressionCompressorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerOperated => "sequencer_operated",
            Self::CommunityArchive => "community_archive",
            Self::FastEdgeCache => "fast_edge_cache",
            Self::ColdProofArchive => "cold_proof_archive",
            Self::SponsorBacked => "sponsor_backed",
            Self::MoneroBridgeRelay => "monero_bridge_relay",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Selected,
    Reserved,
    Filled,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSlotStatus {
    Proposed,
    QuorumMet,
    BatchBound,
    Settled,
    Expired,
    Disputed,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Attested,
    BatchBound,
    Settled,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Proposed,
    ProofBundled,
    Submitted,
    Settled,
    Rebated,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryReceiptKind {
    TicketAccepted,
    CompressorBidSelected,
    SponsorReserved,
    PqProofSlotQuorum,
    BatchProofPublished,
    CompressionSettled,
    TicketDelivered,
    RebatePaid,
    CompressorSlashed,
}

impl DeliveryReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TicketAccepted => "ticket_accepted",
            Self::CompressorBidSelected => "compressor_bid_selected",
            Self::SponsorReserved => "sponsor_reserved",
            Self::PqProofSlotQuorum => "pq_proof_slot_quorum",
            Self::BatchProofPublished => "batch_proof_published",
            Self::CompressionSettled => "compression_settled",
            Self::TicketDelivered => "ticket_delivered",
            Self::RebatePaid => "rebate_paid",
            Self::CompressorSlashed => "compressor_slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub compression_suite: String,
    pub pq_proof_slot_suite: String,
    pub proof_batching_suite: String,
    pub max_lanes: usize,
    pub max_tickets: usize,
    pub max_bids: usize,
    pub max_proof_slots: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub bid_ttl_blocks: u64,
    pub sponsor_reservation_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_committee_weight: u64,
    pub max_batch_tickets: usize,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_HASH_SUITE.to_string(),
            compression_suite:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_COMPRESSION_SUITE
                    .to_string(),
            pq_proof_slot_suite:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PQ_PROOF_SLOT_SUITE.to_string(),
            proof_batching_suite:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROOF_BATCHING_SUITE.to_string(),
            max_lanes: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_LANES,
            max_tickets: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_TICKETS,
            max_bids: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_BIDS,
            max_proof_slots:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_PROOF_SLOTS,
            max_sponsor_reservations:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_REBATES,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            bid_ttl_blocks:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            sponsor_reservation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            ticket_ttl_blocks: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_committee_weight:
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT,
            max_batch_tickets: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCH_TICKETS,
            devnet_height: PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        ensure_eq(
            &self.chain_id,
            CHAIN_ID,
            "private l2 low fee State-diff compression market chain id",
        )?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("compression_suite", &self.compression_suite)?;
        require_non_empty("pq_proof_slot_suite", &self.pq_proof_slot_suite)?;
        require_non_empty("proof_batching_suite", &self.proof_batching_suite)?;
        require_positive_usize("max_lanes", self.max_lanes)?;
        require_positive_usize("max_tickets", self.max_tickets)?;
        require_positive_usize("max_bids", self.max_bids)?;
        require_positive_usize("max_proof_slots", self.max_proof_slots)?;
        require_positive_usize("max_sponsor_reservations", self.max_sponsor_reservations)?;
        require_positive_usize("max_batches", self.max_batches)?;
        require_positive_usize("max_receipts", self.max_receipts)?;
        require_positive_usize("max_rebates", self.max_rebates)?;
        require_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive_u64("batch_privacy_set_size", self.batch_privacy_set_size)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must be at least 192".to_string());
        }
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.target_rebate_bps > self.max_user_fee_bps {
            return Err("target_rebate_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.bid_ttl_blocks == 0
            || self.sponsor_reservation_ttl_blocks == 0
            || self.ticket_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
        {
            return Err("ttl blocks must be positive".to_string());
        }
        if self.min_committee_weight == 0 || self.min_committee_weight > 100 {
            return Err("min_committee_weight must be in 1..=100".to_string());
        }
        require_positive_usize("max_batch_tickets", self.max_batch_tickets)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_counter: u64,
    pub ticket_counter: u64,
    pub bid_counter: u64,
    pub proof_slot_counter: u64,
    pub sponsor_reservation_counter: u64,
    pub batch_counter: u64,
    pub receipt_counter: u64,
    pub rebate_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterStateDiffLaneRequest {
    pub lane_owner_commitment: String,
    pub lane_kind: StateDiffLaneKind,
    pub lane_policy_root: String,
    pub encryption_policy_root: String,
    pub fee_policy_root: String,
    pub max_user_fee_bps: u64,
    pub target_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub lane_nonce: String,
}

impl RegisterStateDiffLaneRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty("lane_owner_commitment", &self.lane_owner_commitment)?;
        require_root("lane_policy_root", &self.lane_policy_root)?;
        require_root("encryption_policy_root", &self.encryption_policy_root)?;
        require_root("fee_policy_root", &self.fee_policy_root)?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("lane max_user_fee_bps exceeds runtime maximum".to_string());
        }
        require_positive_u64("target_latency_ms", self.target_latency_ms)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("lane min_privacy_set_size below runtime floor".to_string());
        }
        require_non_empty("lane_nonce", &self.lane_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateDiffLaneRecord {
    pub lane_id: String,
    pub sequence: u64,
    pub request: RegisterStateDiffLaneRequest,
    pub status: LaneStatus,
    pub registered_at_height: u64,
    pub accepted_ticket_count: u64,
    pub settled_ticket_count: u64,
    pub cumulative_fee_bps: u64,
    pub lane_score: u64,
}

impl StateDiffLaneRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitStateDiffTicketRequest {
    pub lane_id: String,
    pub owner_commitment: String,
    pub ciphertext_root: String,
    pub erasure_root: String,
    pub metadata_root: String,
    pub retrieval_hint_root: String,
    pub nullifier_root: String,
    pub encoding: TicketEncoding,
    pub byte_size: u64,
    pub shard_count: u32,
    pub required_attester_count: u16,
    pub max_fee_bps: u64,
    pub priority_fee_micros: u64,
    pub expires_at_height: u64,
    pub ticket_nonce: String,
}

impl SubmitStateDiffTicketRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("owner_commitment", &self.owner_commitment)?;
        require_root("ciphertext_root", &self.ciphertext_root)?;
        require_root("erasure_root", &self.erasure_root)?;
        require_root("metadata_root", &self.metadata_root)?;
        require_root("retrieval_hint_root", &self.retrieval_hint_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_positive_u64("byte_size", self.byte_size)?;
        if self.shard_count == 0 {
            return Err("shard_count must be positive".to_string());
        }
        if self.required_attester_count == 0 {
            return Err("required_attester_count must be positive".to_string());
        }
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("ticket max_fee_bps exceeds runtime low-fee ceiling".to_string());
        }
        if self.expires_at_height <= current_height {
            return Err("expires_at_height must be in the future".to_string());
        }
        if self.expires_at_height > current_height.saturating_add(config.ticket_ttl_blocks) {
            return Err("ticket expiry exceeds runtime ticket ttl".to_string());
        }
        require_non_empty("ticket_nonce", &self.ticket_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateDiffTicketRecord {
    pub ticket_id: String,
    pub sequence: u64,
    pub request: SubmitStateDiffTicketRequest,
    pub status: TicketStatus,
    pub submitted_at_height: u64,
    pub selected_bid_ids: Vec<String>,
    pub proof_slot_ids: Vec<String>,
    pub sponsor_reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_ids: Vec<String>,
    pub effective_fee_bps: u64,
    pub privacy_set_size: u64,
}

impl StateDiffTicketRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostCompressionCompressorBidRequest {
    pub ticket_id: String,
    pub compressor_commitment: String,
    pub compressor_class: CompressionCompressorClass,
    pub storage_price_bps: u64,
    pub retrieval_price_bps: u64,
    pub settlement_price_bps: u64,
    pub latency_ms: u64,
    pub retention_blocks: u64,
    pub capacity_root: String,
    pub pq_compressor_key_root: String,
    pub bid_expires_at_height: u64,
    pub bid_nonce: String,
}

impl PostCompressionCompressorBidRequest {
    pub fn total_fee_bps(&self) -> u64 {
        self.storage_price_bps
            .saturating_add(self.retrieval_price_bps)
            .saturating_add(self.settlement_price_bps)
    }

    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("compressor_commitment", &self.compressor_commitment)?;
        require_bps("storage_price_bps", self.storage_price_bps)?;
        require_bps("retrieval_price_bps", self.retrieval_price_bps)?;
        require_bps("settlement_price_bps", self.settlement_price_bps)?;
        require_bps("total_fee_bps", self.total_fee_bps())?;
        require_positive_u64("latency_ms", self.latency_ms)?;
        require_positive_u64("retention_blocks", self.retention_blocks)?;
        require_root("capacity_root", &self.capacity_root)?;
        require_root("pq_compressor_key_root", &self.pq_compressor_key_root)?;
        if self.bid_expires_at_height <= current_height {
            return Err("bid_expires_at_height must be in the future".to_string());
        }
        if self.bid_expires_at_height > current_height.saturating_add(config.bid_ttl_blocks) {
            return Err("bid expiry exceeds runtime bid ttl".to_string());
        }
        require_non_empty("bid_nonce", &self.bid_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionCompressorBidRecord {
    pub bid_id: String,
    pub sequence: u64,
    pub request: PostCompressionCompressorBidRequest,
    pub status: BidStatus,
    pub posted_at_height: u64,
    pub bid_score: u64,
}

impl CompressionCompressorBidRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishPqProofSlotRequest {
    pub ticket_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub committee_id: String,
    pub committee_epoch: u64,
    pub committee_public_key_root: String,
    pub signed_payload_root: String,
    pub availability_bitmap_root: String,
    pub pq_proof_slot_share_root: String,
    pub aggregate_signature_root: String,
    pub committee_weight: u64,
    pub pq_security_bits: u16,
    pub valid_until_height: u64,
    pub proof_slot_nonce: String,
}

impl PublishPqProofSlotRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty_vec("ticket_ids", &self.ticket_ids)?;
        require_non_empty_vec("bid_ids", &self.bid_ids)?;
        ensure_unique("ticket_ids", &self.ticket_ids)?;
        ensure_unique("bid_ids", &self.bid_ids)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_positive_u64("committee_epoch", self.committee_epoch)?;
        require_root("committee_public_key_root", &self.committee_public_key_root)?;
        require_root("signed_payload_root", &self.signed_payload_root)?;
        require_root("availability_bitmap_root", &self.availability_bitmap_root)?;
        require_root("pq_proof_slot_share_root", &self.pq_proof_slot_share_root)?;
        require_root("aggregate_signature_root", &self.aggregate_signature_root)?;
        if self.committee_weight < config.min_committee_weight {
            return Err("committee_weight below runtime quorum".to_string());
        }
        if self.committee_weight > 100 {
            return Err("committee_weight cannot exceed 100".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq_security_bits below runtime floor".to_string());
        }
        if self.valid_until_height <= current_height {
            return Err("valid_until_height must be in the future".to_string());
        }
        require_non_empty("proof_slot_nonce", &self.proof_slot_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqProofSlotRecord {
    pub proof_slot_id: String,
    pub sequence: u64,
    pub request: PublishPqProofSlotRequest,
    pub status: ProofSlotStatus,
    pub attested_at_height: u64,
    pub attested_ticket_count: u64,
}

impl PqProofSlotRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLowFeeSponsorRequest {
    pub ticket_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub budget_commitment_root: String,
    pub max_total_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_target_bps: u64,
    pub sponsor_reservation_expires_at_height: u64,
    pub sponsor_reservation_nonce: String,
}

impl ReserveLowFeeSponsorRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty_vec("ticket_ids", &self.ticket_ids)?;
        require_non_empty_vec("bid_ids", &self.bid_ids)?;
        ensure_unique("ticket_ids", &self.ticket_ids)?;
        ensure_unique("bid_ids", &self.bid_ids)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_root("budget_commitment_root", &self.budget_commitment_root)?;
        require_bps("max_total_fee_bps", self.max_total_fee_bps)?;
        if self.max_total_fee_bps > config.max_user_fee_bps {
            return Err("max_total_fee_bps exceeds runtime low-fee ceiling".to_string());
        }
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.sponsor_cover_bps < config.sponsor_cover_bps {
            return Err("sponsor_cover_bps below runtime floor".to_string());
        }
        require_bps("rebate_target_bps", self.rebate_target_bps)?;
        if self.rebate_target_bps > config.max_user_fee_bps {
            return Err("rebate_target_bps exceeds runtime low-fee ceiling".to_string());
        }
        if self.sponsor_reservation_expires_at_height <= current_height {
            return Err("sponsor_reservation_expires_at_height must be in the future".to_string());
        }
        if self.sponsor_reservation_expires_at_height
            > current_height.saturating_add(config.sponsor_reservation_ttl_blocks)
        {
            return Err(
                "sponsor_reservation expiry exceeds runtime sponsor_reservation ttl".to_string(),
            );
        }
        require_non_empty("sponsor_reservation_nonce", &self.sponsor_reservation_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorReservationRecord {
    pub sponsor_reservation_id: String,
    pub sequence: u64,
    pub request: ReserveLowFeeSponsorRequest,
    pub status: SponsorReservationStatus,
    pub reserved_at_height: u64,
    pub covered_ticket_count: u64,
}

impl LowFeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildCompressionSettlementBatchRequest {
    pub ticket_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub proof_slot_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub settlement_payload_root: String,
    pub proof_batch_root: String,
    pub compressed_payload_commitment_root: String,
    pub delivery_manifest_root: String,
    pub fee_manifest_root: String,
    pub state_root_before: String,
    pub runtime_state_root_after: String,
    pub batch_expires_at_height: u64,
    pub batch_nonce: String,
}

impl BuildCompressionSettlementBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty_vec("ticket_ids", &self.ticket_ids)?;
        require_non_empty_vec("bid_ids", &self.bid_ids)?;
        require_non_empty_vec("proof_slot_ids", &self.proof_slot_ids)?;
        ensure_unique("ticket_ids", &self.ticket_ids)?;
        ensure_unique("bid_ids", &self.bid_ids)?;
        ensure_unique("proof_slot_ids", &self.proof_slot_ids)?;
        ensure_unique("sponsor_reservation_ids", &self.sponsor_reservation_ids)?;
        if self.ticket_ids.len() > config.max_batch_tickets {
            return Err("settlement batch exceeds max_batch_tickets".to_string());
        }
        require_root("settlement_payload_root", &self.settlement_payload_root)?;
        require_root("proof_batch_root", &self.proof_batch_root)?;
        require_root(
            "compressed_payload_commitment_root",
            &self.compressed_payload_commitment_root,
        )?;
        require_root("delivery_manifest_root", &self.delivery_manifest_root)?;
        require_root("fee_manifest_root", &self.fee_manifest_root)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("runtime_state_root_after", &self.runtime_state_root_after)?;
        if self.batch_expires_at_height <= current_height {
            return Err("batch_expires_at_height must be in the future".to_string());
        }
        if self.batch_expires_at_height
            > current_height.saturating_add(config.settlement_ttl_blocks)
        {
            return Err("batch expiry exceeds runtime settlement ttl".to_string());
        }
        require_non_empty("batch_nonce", &self.batch_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionSettlementBatchRecord {
    pub batch_id: String,
    pub sequence: u64,
    pub request: BuildCompressionSettlementBatchRequest,
    pub status: SettlementBatchStatus,
    pub built_at_height: u64,
    pub total_ticket_count: u64,
    pub total_effective_fee_bps: u64,
}

impl CompressionSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishDeliveryReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: DeliveryReceiptKind,
    pub lane_id: Option<String>,
    pub ticket_id: Option<String>,
    pub bid_id: Option<String>,
    pub proof_slot_id: Option<String>,
    pub sponsor_reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub delivered_payload_root: String,
    pub delivery_proof_root: String,
    pub fee_paid_bps: u64,
    pub observed_latency_ms: u64,
    pub receipt_nonce: String,
}

impl PublishDeliveryReceiptRequest {
    pub fn validate(&self) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("delivered_payload_root", &self.delivered_payload_root)?;
        require_root("delivery_proof_root", &self.delivery_proof_root)?;
        require_bps("fee_paid_bps", self.fee_paid_bps)?;
        require_non_empty("receipt_nonce", &self.receipt_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryReceiptRecord {
    pub receipt_id: String,
    pub sequence: u64,
    pub request: PublishDeliveryReceiptRequest,
    pub published_at_height: u64,
}

impl DeliveryReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRebatePayoutRequest {
    pub sponsor_reservation_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment_root: String,
    pub rebate_commitment_root: String,
    pub paid_fee_bps: u64,
    pub rebate_bps: u64,
    pub payout_nullifier_root: String,
    pub payout_nonce: String,
}

impl PublishRebatePayoutRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        require_non_empty("sponsor_reservation_id", &self.sponsor_reservation_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_root(
            "beneficiary_commitment_root",
            &self.beneficiary_commitment_root,
        )?;
        require_root("rebate_commitment_root", &self.rebate_commitment_root)?;
        require_bps("paid_fee_bps", self.paid_fee_bps)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.max_user_fee_bps {
            return Err("rebate_bps exceeds runtime low-fee ceiling".to_string());
        }
        if self.rebate_bps > self.paid_fee_bps {
            return Err("rebate_bps cannot exceed paid_fee_bps".to_string());
        }
        require_root("payout_nullifier_root", &self.payout_nullifier_root)?;
        require_non_empty("payout_nonce", &self.payout_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebatePayoutRecord {
    pub rebate_id: String,
    pub sequence: u64,
    pub request: PublishRebatePayoutRequest,
    pub paid_at_height: u64,
}

impl RebatePayoutRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub lane_root: String,
    pub ticket_root: String,
    pub bid_root: String,
    pub proof_slot_root: String,
    pub sponsor_reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub public_record_root: String,
    pub runtime_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub runtime_root: String,
    pub counters: Counters,
    pub lanes: BTreeMap<String, StateDiffLaneRecord>,
    pub tickets: BTreeMap<String, StateDiffTicketRecord>,
    pub bids: BTreeMap<String, CompressionCompressorBidRecord>,
    pub proof_slots: BTreeMap<String, PqProofSlotRecord>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservationRecord>,
    pub settlement_batches: BTreeMap<String, CompressionSettlementBatchRecord>,
    pub receipts: BTreeMap<String, DeliveryReceiptRecord>,
    pub rebates: BTreeMap<String, RebatePayoutRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, current_height: u64) -> Self {
        let runtime_root = payload_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-RUNTIME-GENESIS",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
                "current_height": current_height,
            }),
        );
        Self {
            config,
            current_height,
            runtime_root,
            counters: Counters::default(),
            lanes: BTreeMap::new(),
            tickets: BTreeMap::new(),
            bids: BTreeMap::new(),
            proof_slots: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn validate_config(&self) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
        self.config.validate()
    }

    pub fn advance_height(&mut self, new_height: u64) {
        if new_height > self.current_height {
            self.current_height = new_height;
        }
    }

    pub fn register_lane(
        &mut self,
        request: RegisterStateDiffLaneRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<StateDiffLaneRecord> {
        self.config.validate()?;
        if self.lanes.len() >= self.config.max_lanes {
            return Err("lane limit reached".to_string());
        }
        request.validate(&self.config)?;
        self.counters.lane_counter = self.counters.lane_counter.saturating_add(1);
        let lane_id = state_diff_lane_id(&request, self.counters.lane_counter);
        if self.lanes.contains_key(&lane_id) {
            return Err("lane already registered".to_string());
        }
        let lane_score = lane_score(&request);
        let record = StateDiffLaneRecord {
            lane_id: lane_id.clone(),
            sequence: self.counters.lane_counter,
            request,
            status: LaneStatus::Open,
            registered_at_height: self.current_height,
            accepted_ticket_count: 0,
            settled_ticket_count: 0,
            cumulative_fee_bps: 0,
            lane_score,
        };
        self.lanes.insert(lane_id.clone(), record.clone());
        self.publish_public_record("state_diff_lane", &lane_id, record.public_record());
        Ok(record)
    }

    pub fn submit_ticket(
        &mut self,
        request: SubmitStateDiffTicketRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<StateDiffTicketRecord> {
        self.config.validate()?;
        if self.tickets.len() >= self.config.max_tickets {
            return Err("ticket limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "unknown lane_id".to_string())?;
        if !lane.status.accepts_tickets() {
            return Err("lane is not accepting tickets".to_string());
        }
        if request.max_fee_bps > lane.request.max_user_fee_bps {
            return Err("ticket max_fee_bps exceeds lane fee ceiling".to_string());
        }
        self.counters.ticket_counter = self.counters.ticket_counter.saturating_add(1);
        let ticket_id = state_diff_ticket_id(&request, self.counters.ticket_counter);
        if self.tickets.contains_key(&ticket_id) {
            return Err("ticket already submitted".to_string());
        }
        lane.accepted_ticket_count = lane.accepted_ticket_count.saturating_add(1);
        let record = StateDiffTicketRecord {
            ticket_id: ticket_id.clone(),
            sequence: self.counters.ticket_counter,
            request,
            status: TicketStatus::Submitted,
            submitted_at_height: self.current_height,
            selected_bid_ids: Vec::new(),
            proof_slot_ids: Vec::new(),
            sponsor_reservation_id: None,
            batch_id: None,
            receipt_ids: Vec::new(),
            effective_fee_bps: 0,
            privacy_set_size: self.config.min_privacy_set_size,
        };
        self.tickets.insert(ticket_id.clone(), record.clone());
        self.publish_public_record("state_diff_ticket", &ticket_id, record.public_record());
        Ok(record)
    }

    pub fn post_compressor_bid(
        &mut self,
        request: PostCompressionCompressorBidRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<CompressionCompressorBidRecord>
    {
        self.config.validate()?;
        if self.bids.len() >= self.config.max_bids {
            return Err("bid limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        let ticket = self
            .tickets
            .get_mut(&request.ticket_id)
            .ok_or_else(|| "unknown ticket_id".to_string())?;
        if !ticket.status.live() {
            return Err("ticket is not live".to_string());
        }
        if request.total_fee_bps() > ticket.request.max_fee_bps {
            return Err("bid total fee exceeds ticket max_fee_bps".to_string());
        }
        self.counters.bid_counter = self.counters.bid_counter.saturating_add(1);
        let bid_id = compression_compressor_bid_id(&request, self.counters.bid_counter);
        if self.bids.contains_key(&bid_id) {
            return Err("bid already posted".to_string());
        }
        ticket.status = TicketStatus::BidSelected;
        ticket.selected_bid_ids.push(bid_id.clone());
        ticket.effective_fee_bps = if ticket.effective_fee_bps == 0 {
            request.total_fee_bps()
        } else {
            ticket.effective_fee_bps.min(request.total_fee_bps())
        };
        let record = CompressionCompressorBidRecord {
            bid_id: bid_id.clone(),
            sequence: self.counters.bid_counter,
            request: request.clone(),
            status: BidStatus::Posted,
            posted_at_height: self.current_height,
            bid_score: bid_score(&request, ticket.request.priority_fee_micros),
        };
        self.bids.insert(bid_id.clone(), record.clone());
        self.publish_public_record(
            "compression_compressor_bid",
            &bid_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn publish_pq_proof_slot(
        &mut self,
        request: PublishPqProofSlotRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<PqProofSlotRecord> {
        self.config.validate()?;
        if self.proof_slots.len() >= self.config.max_proof_slots {
            return Err("proof_slot limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        for ticket_id in &request.ticket_ids {
            if !self.tickets.contains_key(ticket_id) {
                return Err(format!("unknown ticket_id: {ticket_id}"));
            }
        }
        for bid_id in &request.bid_ids {
            let bid = self
                .bids
                .get(bid_id)
                .ok_or_else(|| format!("unknown bid_id: {bid_id}"))?;
            if !bid.status.selectable() {
                return Err(format!("bid is not selectable: {bid_id}"));
            }
        }
        self.counters.proof_slot_counter = self.counters.proof_slot_counter.saturating_add(1);
        let proof_slot_id = pq_proof_slot_id(&request, self.counters.proof_slot_counter);
        if self.proof_slots.contains_key(&proof_slot_id) {
            return Err("proof_slot already published".to_string());
        }
        for bid_id in &request.bid_ids {
            if let Some(bid) = self.bids.get_mut(bid_id) {
                bid.status = BidStatus::Selected;
            }
        }
        for ticket_id in &request.ticket_ids {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Attested;
                ticket.proof_slot_ids.push(proof_slot_id.clone());
                ticket.privacy_set_size = ticket
                    .privacy_set_size
                    .max(self.config.batch_privacy_set_size);
            }
        }
        let record = PqProofSlotRecord {
            proof_slot_id: proof_slot_id.clone(),
            sequence: self.counters.proof_slot_counter,
            attested_ticket_count: request.ticket_ids.len() as u64,
            request,
            status: ProofSlotStatus::QuorumMet,
            attested_at_height: self.current_height,
        };
        self.proof_slots
            .insert(proof_slot_id.clone(), record.clone());
        self.publish_public_record("pq_proof_slot", &proof_slot_id, record.public_record());
        Ok(record)
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: ReserveLowFeeSponsorRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<LowFeeSponsorReservationRecord>
    {
        self.config.validate()?;
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("sponsor_reservation limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        for ticket_id in &request.ticket_ids {
            let ticket = self
                .tickets
                .get(ticket_id)
                .ok_or_else(|| format!("unknown ticket_id: {ticket_id}"))?;
            if !matches!(
                ticket.status,
                TicketStatus::BidSelected | TicketStatus::Attested
            ) {
                return Err(format!("ticket is not sponsor-reservable: {ticket_id}"));
            }
        }
        for bid_id in &request.bid_ids {
            let bid = self
                .bids
                .get(bid_id)
                .ok_or_else(|| format!("unknown bid_id: {bid_id}"))?;
            if bid.request.total_fee_bps() > request.max_total_fee_bps {
                return Err(format!("bid exceeds sponsor_reservation fee cap: {bid_id}"));
            }
        }
        self.counters.sponsor_reservation_counter =
            self.counters.sponsor_reservation_counter.saturating_add(1);
        let sponsor_reservation_id = low_fee_sponsor_sponsor_reservation_id(
            &request,
            self.counters.sponsor_reservation_counter,
        );
        if self
            .sponsor_reservations
            .contains_key(&sponsor_reservation_id)
        {
            return Err("sponsor_reservation already exists".to_string());
        }
        for bid_id in &request.bid_ids {
            if let Some(bid) = self.bids.get_mut(bid_id) {
                bid.status = BidStatus::Reserved;
            }
        }
        for ticket_id in &request.ticket_ids {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Reserved;
                ticket.sponsor_reservation_id = Some(sponsor_reservation_id.clone());
                ticket.effective_fee_bps = ticket.effective_fee_bps.min(request.max_total_fee_bps);
            }
        }
        let record = LowFeeSponsorReservationRecord {
            sponsor_reservation_id: sponsor_reservation_id.clone(),
            sequence: self.counters.sponsor_reservation_counter,
            covered_ticket_count: request.ticket_ids.len() as u64,
            request,
            status: SponsorReservationStatus::Reserved,
            reserved_at_height: self.current_height,
        };
        self.sponsor_reservations
            .insert(sponsor_reservation_id.clone(), record.clone());
        self.publish_public_record(
            "low_fee_sponsor_sponsor_reservation",
            &sponsor_reservation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn build_compression_settlement_batch(
        &mut self,
        request: BuildCompressionSettlementBatchRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<CompressionSettlementBatchRecord>
    {
        self.config.validate()?;
        if self.settlement_batches.len() >= self.config.max_batches {
            return Err("settlement batch limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        if request.state_root_before != self.state_root() {
            return Err("state_root_before does not match current state root".to_string());
        }
        if !covers_all_bids(&self.bids, &request.bid_ids, &request.ticket_ids) {
            return Err("bid_ids do not cover every ticket_id".to_string());
        }
        if !covers_all_proof_slots(
            &self.proof_slots,
            &request.proof_slot_ids,
            &request.ticket_ids,
        ) {
            return Err("proof_slot_ids do not cover every ticket_id".to_string());
        }
        if !request.sponsor_reservation_ids.is_empty()
            && !covers_all_sponsor_reservations(
                &self.sponsor_reservations,
                &request.sponsor_reservation_ids,
                &request.ticket_ids,
            )
        {
            return Err("sponsor_reservation_ids do not cover every ticket_id".to_string());
        }
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        let batch_id = compression_settlement_batch_id(&request, self.counters.batch_counter);
        if self.settlement_batches.contains_key(&batch_id) {
            return Err("settlement batch already exists".to_string());
        }
        let total_effective_fee_bps = request
            .ticket_ids
            .iter()
            .filter_map(|ticket_id| self.tickets.get(ticket_id))
            .map(|ticket| ticket.effective_fee_bps)
            .sum::<u64>();
        for bid_id in &request.bid_ids {
            if let Some(bid) = self.bids.get_mut(bid_id) {
                bid.status = BidStatus::Filled;
            }
        }
        for proof_slot_id in &request.proof_slot_ids {
            if let Some(proof_slot) = self.proof_slots.get_mut(proof_slot_id) {
                proof_slot.status = ProofSlotStatus::BatchBound;
            }
        }
        for sponsor_reservation_id in &request.sponsor_reservation_ids {
            if let Some(sponsor_reservation) =
                self.sponsor_reservations.get_mut(sponsor_reservation_id)
            {
                sponsor_reservation.status = SponsorReservationStatus::BatchBound;
            }
        }
        for ticket_id in &request.ticket_ids {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::BatchReady;
                ticket.batch_id = Some(batch_id.clone());
            }
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        let record = CompressionSettlementBatchRecord {
            batch_id: batch_id.clone(),
            sequence: self.counters.batch_counter,
            total_ticket_count: request.ticket_ids.len() as u64,
            total_effective_fee_bps,
            request,
            status: SettlementBatchStatus::ProofBundled,
            built_at_height: self.current_height,
        };
        self.settlement_batches
            .insert(batch_id.clone(), record.clone());
        self.publish_public_record(
            "compression_settlement_batch",
            &batch_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn publish_delivery_receipt(
        &mut self,
        request: PublishDeliveryReceiptRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<DeliveryReceiptRecord> {
        self.config.validate()?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt limit reached".to_string());
        }
        request.validate()?;
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let receipt_id = delivery_receipt_id(&request, self.counters.receipt_counter);
        if self.receipts.contains_key(&receipt_id) {
            return Err("receipt already exists".to_string());
        }
        if let Some(ticket_id) = &request.ticket_id {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.receipt_ids.push(receipt_id.clone());
                if request.receipt_kind == DeliveryReceiptKind::TicketDelivered {
                    ticket.status = TicketStatus::Delivered;
                }
            }
        }
        if let Some(batch_id) = &request.batch_id {
            if let Some(batch) = self.settlement_batches.get_mut(batch_id) {
                if request.receipt_kind == DeliveryReceiptKind::CompressionSettled {
                    batch.status = SettlementBatchStatus::Settled;
                    for ticket_id in &batch.request.ticket_ids {
                        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                            ticket.status = TicketStatus::Settled;
                            if let Some(lane) = self.lanes.get_mut(&ticket.request.lane_id) {
                                lane.settled_ticket_count =
                                    lane.settled_ticket_count.saturating_add(1);
                                lane.cumulative_fee_bps = lane
                                    .cumulative_fee_bps
                                    .saturating_add(ticket.effective_fee_bps);
                            }
                        }
                    }
                    for proof_slot_id in &batch.request.proof_slot_ids {
                        if let Some(proof_slot) = self.proof_slots.get_mut(proof_slot_id) {
                            proof_slot.status = ProofSlotStatus::Settled;
                        }
                    }
                    for sponsor_reservation_id in &batch.request.sponsor_reservation_ids {
                        if let Some(sponsor_reservation) =
                            self.sponsor_reservations.get_mut(sponsor_reservation_id)
                        {
                            sponsor_reservation.status = SponsorReservationStatus::Settled;
                        }
                    }
                }
            }
        }
        let record = DeliveryReceiptRecord {
            receipt_id: receipt_id.clone(),
            sequence: self.counters.receipt_counter,
            request,
            published_at_height: self.current_height,
        };
        self.receipts.insert(receipt_id.clone(), record.clone());
        self.publish_public_record("delivery_receipt", &receipt_id, record.public_record());
        Ok(record)
    }

    pub fn publish_rebate_payout(
        &mut self,
        request: PublishRebatePayoutRequest,
    ) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<RebatePayoutRecord> {
        self.config.validate()?;
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate limit reached".to_string());
        }
        request.validate(&self.config)?;
        let sponsor_reservation = self
            .sponsor_reservations
            .get(&request.sponsor_reservation_id)
            .ok_or_else(|| "unknown sponsor_reservation_id".to_string())?;
        if !matches!(
            sponsor_reservation.status,
            SponsorReservationStatus::Settled | SponsorReservationStatus::BatchBound
        ) {
            return Err("sponsor_reservation is not rebate eligible".to_string());
        }
        let batch = self
            .settlement_batches
            .get(&request.batch_id)
            .ok_or_else(|| "unknown batch_id".to_string())?;
        if !matches!(
            batch.status,
            SettlementBatchStatus::Settled | SettlementBatchStatus::ProofBundled
        ) {
            return Err("batch is not rebate eligible".to_string());
        }
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        let rebate_id = rebate_payout_id(&request, self.counters.rebate_counter);
        if self.rebates.contains_key(&rebate_id) {
            return Err("rebate already exists".to_string());
        }
        if let Some(sponsor_reservation) = self
            .sponsor_reservations
            .get_mut(&request.sponsor_reservation_id)
        {
            sponsor_reservation.status = SponsorReservationStatus::Settled;
        }
        if let Some(batch) = self.settlement_batches.get_mut(&request.batch_id) {
            batch.status = SettlementBatchStatus::Rebated;
            for ticket_id in &batch.request.ticket_ids {
                if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                    ticket.status = TicketStatus::Rebated;
                }
            }
        }
        let record = RebatePayoutRecord {
            rebate_id: rebate_id.clone(),
            sequence: self.counters.rebate_counter,
            request,
            paid_at_height: self.current_height,
        };
        self.rebates.insert(rebate_id.clone(), record.clone());
        self.publish_public_record("rebate_payout", &rebate_id, record.public_record());
        Ok(record)
    }

    pub fn expire_stale_records(&mut self) {
        for ticket in self.tickets.values_mut() {
            if ticket.status.live() && ticket.request.expires_at_height <= self.current_height {
                ticket.status = TicketStatus::Expired;
            }
        }
        for bid in self.bids.values_mut() {
            if bid.status.selectable() && bid.request.bid_expires_at_height <= self.current_height {
                bid.status = BidStatus::Expired;
            }
        }
        for proof_slot in self.proof_slots.values_mut() {
            if matches!(
                proof_slot.status,
                ProofSlotStatus::Proposed | ProofSlotStatus::QuorumMet
            ) && proof_slot.request.valid_until_height <= self.current_height
            {
                proof_slot.status = ProofSlotStatus::Expired;
            }
        }
        for sponsor_reservation in self.sponsor_reservations.values_mut() {
            if sponsor_reservation.status == SponsorReservationStatus::Reserved
                && sponsor_reservation
                    .request
                    .sponsor_reservation_expires_at_height
                    <= self.current_height
            {
                sponsor_reservation.status = SponsorReservationStatus::Expired;
            }
        }
        for batch in self.settlement_batches.values_mut() {
            if matches!(
                batch.status,
                SettlementBatchStatus::Proposed | SettlementBatchStatus::ProofBundled
            ) && batch.request.batch_expires_at_height <= self.current_height
            {
                batch.status = SettlementBatchStatus::Cancelled;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = payload_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-COUNTERS",
            &self.counters.public_record(),
        );
        let lane_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-LANES",
            &self
                .lanes
                .values()
                .map(StateDiffLaneRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let ticket_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-TICKETS",
            &self
                .tickets
                .values()
                .map(StateDiffTicketRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let bid_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-BIDS",
            &self
                .bids
                .values()
                .map(CompressionCompressorBidRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let proof_slot_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-PROOF-SLOTS",
            &self
                .proof_slots
                .values()
                .map(PqProofSlotRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-RESERVATIONS",
            &self
                .sponsor_reservations
                .values()
                .map(LowFeeSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-BATCHES",
            &self
                .settlement_batches
                .values()
                .map(CompressionSettlementBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-RECEIPTS",
            &self
                .receipts
                .values()
                .map(DeliveryReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-REBATES",
            &self
                .rebates
                .values()
                .map(RebatePayoutRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let public_records = self.public_records.values().cloned().collect::<Vec<_>>();
        let public_record_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-PUBLIC-RECORDS",
            &public_records,
        );
        let roots_without_state = json!({
            "config_root": config_root,
            "counter_root": counter_root,
            "lane_root": lane_root,
            "ticket_root": ticket_root,
            "bid_root": bid_root,
            "proof_slot_root": proof_slot_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "batch_root": batch_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "public_record_root": public_record_root,
            "runtime_root": self.runtime_root,
        });
        let state_root = state_root_from_record(&json!({
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "roots": roots_without_state,
        }));
        Roots {
            config_root,
            counter_root,
            lane_root,
            ticket_root,
            bid_root,
            proof_slot_root,
            sponsor_reservation_root,
            batch_root,
            receipt_root,
            rebate_root,
            public_record_root,
            runtime_root: self.runtime_root.clone(),
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_state_diff_compression_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_SCHEMA_VERSION,
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            roots_only_payload(record_kind, subject_id, &payload),
        );
    }
}

pub fn state_diff_lane_id(request: &RegisterStateDiffLaneRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.lane_owner_commitment),
            HashPart::Str(request.lane_kind.as_str()),
            HashPart::Str(&request.lane_policy_root),
            HashPart::Str(&request.lane_nonce),
        ],
        32,
    )
}

pub fn state_diff_ticket_id(request: &SubmitStateDiffTicketRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-ticket-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.ciphertext_root),
            HashPart::Str(&request.erasure_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(request.encoding.as_str()),
            HashPart::Str(&request.ticket_nonce),
        ],
        32,
    )
}

pub fn compression_compressor_bid_id(
    request: &PostCompressionCompressorBidRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.ticket_id),
            HashPart::Str(&request.compressor_commitment),
            HashPart::Str(request.compressor_class.as_str()),
            HashPart::Int(request.total_fee_bps() as i128),
            HashPart::Str(&request.capacity_root),
            HashPart::Str(&request.bid_nonce),
        ],
        32,
    )
}

pub fn pq_proof_slot_id(request: &PublishPqProofSlotRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-PQ-PROOF-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("ticket_ids", &request.ticket_ids)),
            HashPart::Str(&id_list_root("bid_ids", &request.bid_ids)),
            HashPart::Str(&request.committee_id),
            HashPart::Int(request.committee_epoch as i128),
            HashPart::Str(&request.signed_payload_root),
            HashPart::Str(&request.aggregate_signature_root),
            HashPart::Str(&request.proof_slot_nonce),
        ],
        32,
    )
}

pub fn low_fee_sponsor_sponsor_reservation_id(
    request: &ReserveLowFeeSponsorRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("ticket_ids", &request.ticket_ids)),
            HashPart::Str(&id_list_root("bid_ids", &request.bid_ids)),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.budget_commitment_root),
            HashPart::Str(&request.sponsor_reservation_nonce),
        ],
        32,
    )
}

pub fn compression_settlement_batch_id(
    request: &BuildCompressionSettlementBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("ticket_ids", &request.ticket_ids)),
            HashPart::Str(&id_list_root("proof_slot_ids", &request.proof_slot_ids)),
            HashPart::Str(&request.settlement_payload_root),
            HashPart::Str(&request.proof_batch_root),
            HashPart::Str(&request.state_root_before),
            HashPart::Str(&request.runtime_state_root_after),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn delivery_receipt_id(request: &PublishDeliveryReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-DELIVERY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.delivered_payload_root),
            HashPart::Str(&request.delivery_proof_root),
            HashPart::Str(&request.receipt_nonce),
        ],
        32,
    )
}

pub fn rebate_payout_id(request: &PublishRebatePayoutRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-REBATE-PAYOUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_reservation_id),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Str(&request.payout_nullifier_root),
            HashPart::Str(&request.payout_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-STATE",
        record,
    )
}

pub fn private_l2_low_fee_state_diff_compression_market_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_state_diff_compression_market_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    payload_root(domain, payload)
}

pub fn private_l2_low_fee_state_diff_compression_market_public_record_root(
    domain: &str,
    records: &[Value],
) -> String {
    public_record_root(domain, records)
}

pub fn private_l2_low_fee_state_diff_compression_market_state_root_from_record(
    record: &Value,
) -> String {
    state_root_from_record(record)
}

fn lane_score(request: &RegisterStateDiffLaneRequest) -> u64 {
    let priority = request.lane_kind.priority_weight();
    let latency_bonus = request
        .lane_kind
        .default_latency_target_ms()
        .saturating_mul(1_000)
        / request.target_latency_ms.max(1);
    let fee_penalty = request.max_user_fee_bps.saturating_mul(100);
    priority
        .saturating_add(latency_bonus)
        .saturating_add(request.min_privacy_set_size / 128)
        .saturating_sub(fee_penalty)
}

fn bid_score(request: &PostCompressionCompressorBidRequest, priority_fee_micros: u64) -> u64 {
    let fee_penalty = request.total_fee_bps().saturating_mul(1_000);
    let latency_penalty = request.latency_ms.saturating_mul(2);
    let retention_bonus = request.retention_blocks / 32;
    let class_bonus = match request.compressor_class {
        CompressionCompressorClass::FastEdgeCache => 2_000,
        CompressionCompressorClass::SequencerOperated => 1_500,
        CompressionCompressorClass::SponsorBacked => 1_250,
        CompressionCompressorClass::MoneroBridgeRelay => 1_100,
        CompressionCompressorClass::CommunityArchive => 900,
        CompressionCompressorClass::ColdProofArchive => 500,
    };
    100_000_u64
        .saturating_add(class_bonus)
        .saturating_add(retention_bonus)
        .saturating_add(priority_fee_micros / 1_000)
        .saturating_sub(fee_penalty)
        .saturating_sub(latency_penalty)
}

fn covers_all_bids(
    bids: &BTreeMap<String, CompressionCompressorBidRecord>,
    bid_ids: &[String],
    ticket_ids: &[String],
) -> bool {
    let covered = bid_ids
        .iter()
        .filter_map(|bid_id| bids.get(bid_id))
        .filter(|bid| matches!(bid.status, BidStatus::Selected | BidStatus::Reserved))
        .map(|bid| &bid.request.ticket_id)
        .collect::<BTreeSet<_>>();
    ticket_ids
        .iter()
        .all(|ticket_id| covered.contains(ticket_id))
}

fn covers_all_proof_slots(
    proof_slots: &BTreeMap<String, PqProofSlotRecord>,
    proof_slot_ids: &[String],
    ticket_ids: &[String],
) -> bool {
    let covered = proof_slot_ids
        .iter()
        .filter_map(|proof_slot_id| proof_slots.get(proof_slot_id))
        .filter(|proof_slot| proof_slot.status == ProofSlotStatus::QuorumMet)
        .flat_map(|proof_slot| proof_slot.request.ticket_ids.iter())
        .collect::<BTreeSet<_>>();
    ticket_ids
        .iter()
        .all(|ticket_id| covered.contains(ticket_id))
}

fn covers_all_sponsor_reservations(
    sponsor_reservations: &BTreeMap<String, LowFeeSponsorReservationRecord>,
    sponsor_reservation_ids: &[String],
    ticket_ids: &[String],
) -> bool {
    let covered = sponsor_reservation_ids
        .iter()
        .filter_map(|sponsor_reservation_id| sponsor_reservations.get(sponsor_reservation_id))
        .filter(|sponsor_reservation| {
            sponsor_reservation.status == SponsorReservationStatus::Reserved
        })
        .flat_map(|sponsor_reservation| sponsor_reservation.request.ticket_ids.iter())
        .collect::<BTreeSet<_>>();
    ticket_ids
        .iter()
        .all(|ticket_id| covered.contains(ticket_id))
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-ID-LIST-{label}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn roots_only_payload(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "kind": "private_l2_low_fee_state_diff_compression_market_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": payload_root(
            "PRIVATE-L2-LOW-FEE-STATE-DIFF-COMPRESSION-MARKET-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_non_empty_vec(
    field: &str,
    values: &[String],
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    for value in values {
        require_non_empty(field, value)?;
    }
    Ok(())
}

fn require_root(
    field: &str,
    value: &str,
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_positive_usize(
    field: &str,
    value: usize,
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(
    field: &str,
    value: u64,
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(
    field: &str,
    value: u64,
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    if value > PRIVATE_L2_LOW_FEE_STATE_DIFF_COMPRESSION_MARKET_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_unique(
    field: &str,
    values: &[String],
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}

fn ensure_eq(
    actual: &str,
    expected: &str,
    label: &str,
) -> PrivateL2LowFeeStateDiffCompressionMarketRuntimeResult<()> {
    if actual != expected {
        Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ))
    } else {
        Ok(())
    }
}
