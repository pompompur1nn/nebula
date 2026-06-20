use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-confidential-calldata-dedup-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_COMPRESSION_SUITE: &str =
    "pq-confidential-calldata-dedup-compression-market-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-calldata-dedup-committee-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROOF_BATCHING_SUITE: &str =
    "recursive-stark-confidential-calldata-dedup-settlement-v1";
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEVNET_HEIGHT: u64 = 880_000;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_LANES: usize = 128;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_BLOBS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_QUOTES: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    4_194_304;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_REBATES: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    8_192;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 =
    8_500;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 8;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_BLOB_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT: u64 =
    67;
pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_BATCH_BLOBS: usize =
    16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataDedupLaneKind {
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

impl CalldataDedupLaneKind {
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
    pub fn accepts_calldata(self) -> bool {
        matches!(self, Self::Open | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataBlobEncoding {
    CiphertextChunks,
    ErasureShardSet,
    ReedSolomonCiphertext,
    KzgBackedCiphertext,
    FecTreeCiphertext,
    RecursiveProofWitness,
}

impl CalldataBlobEncoding {
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
pub enum CalldataBlobStatus {
    Submitted,
    Quoted,
    Reserved,
    Attested,
    BatchReady,
    Settled,
    Delivered,
    Rebated,
    Expired,
    Rejected,
}

impl CalldataBlobStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Quoted | Self::Reserved | Self::Attested | Self::BatchReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupSolverClass {
    SequencerOperated,
    CommunityArchive,
    FastEdgeCache,
    ColdProofArchive,
    SponsorBacked,
    MoneroBridgeRelay,
}

impl DedupSolverClass {
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
pub enum QuoteStatus {
    Posted,
    Selected,
    Reserved,
    Filled,
    Expired,
    Slashed,
}

impl QuoteStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
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
pub enum ReservationStatus {
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
    BlobAccepted,
    SolverQuoted,
    SponsorReserved,
    PqAvailabilityQuorum,
    BatchProofPublished,
    DedupSettled,
    blobDelivered,
    RebatePaid,
    SolverSlashed,
}

impl DeliveryReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobAccepted => "blob_accepted",
            Self::SolverQuoted => "solver_quoted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::PqAvailabilityQuorum => "pq_availability_quorum",
            Self::BatchProofPublished => "batch_proof_published",
            Self::DedupSettled => "dedup_settled",
            Self::blobDelivered => "blob_delivered",
            Self::RebatePaid => "rebate_paid",
            Self::SolverSlashed => "solver_slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub dedup_suite: String,
    pub pq_attestation_suite: String,
    pub proof_batching_suite: String,
    pub max_lanes: usize,
    pub max_blobs: usize,
    pub max_quotes: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub blob_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_committee_weight: u64,
    pub max_batch_blobs: usize,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_HASH_SUITE.to_string(),
            dedup_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_COMPRESSION_SUITE
                    .to_string(),
            pq_attestation_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PQ_ATTESTATION_SUITE.to_string(),
            proof_batching_suite:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROOF_BATCHING_SUITE.to_string(),
            max_lanes: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_LANES,
            max_blobs: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_BLOBS,
            max_quotes: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_QUOTES,
            max_attestations:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_reservations:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_REBATES,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            blob_ttl_blocks: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_BLOB_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_committee_weight:
                PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT,
            max_batch_blobs: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEFAULT_MAX_BATCH_BLOBS,
            devnet_height: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        ensure_eq(
            &self.chain_id,
            CHAIN_ID,
            "private l2 low fee confidential calldata dedup runtime chain id",
        )?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("dedup_suite", &self.dedup_suite)?;
        require_non_empty("pq_attestation_suite", &self.pq_attestation_suite)?;
        require_non_empty("proof_batching_suite", &self.proof_batching_suite)?;
        require_positive_usize("max_lanes", self.max_lanes)?;
        require_positive_usize("max_blobs", self.max_blobs)?;
        require_positive_usize("max_quotes", self.max_quotes)?;
        require_positive_usize("max_attestations", self.max_attestations)?;
        require_positive_usize("max_reservations", self.max_reservations)?;
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
        if self.quote_ttl_blocks == 0
            || self.reservation_ttl_blocks == 0
            || self.blob_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
        {
            return Err("ttl blocks must be positive".to_string());
        }
        if self.min_committee_weight == 0 || self.min_committee_weight > 100 {
            return Err("min_committee_weight must be in 1..=100".to_string());
        }
        require_positive_usize("max_batch_blobs", self.max_batch_blobs)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_counter: u64,
    pub blob_counter: u64,
    pub quote_counter: u64,
    pub attestation_counter: u64,
    pub reservation_counter: u64,
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
pub struct RegisterCalldataLaneRequest {
    pub lane_owner_commitment: String,
    pub lane_kind: CalldataDedupLaneKind,
    pub lane_policy_root: String,
    pub encryption_policy_root: String,
    pub fee_policy_root: String,
    pub max_user_fee_bps: u64,
    pub target_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub lane_nonce: String,
}

impl RegisterCalldataLaneRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
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
pub struct CalldataLaneRecord {
    pub lane_id: String,
    pub sequence: u64,
    pub request: RegisterCalldataLaneRequest,
    pub status: LaneStatus,
    pub registered_at_height: u64,
    pub accepted_blob_count: u64,
    pub settled_blob_count: u64,
    pub cumulative_fee_bps: u64,
    pub lane_score: u64,
}

impl CalldataLaneRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEncryptedCalldataBlobRequest {
    pub lane_id: String,
    pub owner_commitment: String,
    pub ciphertext_root: String,
    pub erasure_root: String,
    pub metadata_root: String,
    pub retrieval_hint_root: String,
    pub nullifier_root: String,
    pub encoding: CalldataBlobEncoding,
    pub byte_size: u64,
    pub shard_count: u32,
    pub required_attester_count: u16,
    pub max_fee_bps: u64,
    pub priority_fee_micros: u64,
    pub expires_at_height: u64,
    pub blob_nonce: String,
}

impl SubmitEncryptedCalldataBlobRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
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
            return Err("blob max_fee_bps exceeds runtime low-fee ceiling".to_string());
        }
        if self.expires_at_height <= current_height {
            return Err("expires_at_height must be in the future".to_string());
        }
        if self.expires_at_height > current_height.saturating_add(config.blob_ttl_blocks) {
            return Err("blob expiry exceeds runtime blob ttl".to_string());
        }
        require_non_empty("blob_nonce", &self.blob_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCalldataBlobRecord {
    pub blob_id: String,
    pub sequence: u64,
    pub request: SubmitEncryptedCalldataBlobRequest,
    pub status: CalldataBlobStatus,
    pub submitted_at_height: u64,
    pub selected_quote_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_ids: Vec<String>,
    pub effective_fee_bps: u64,
    pub privacy_set_size: u64,
}

impl EncryptedCalldataBlobRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostProverBidRequest {
    pub blob_id: String,
    pub solver_commitment: String,
    pub solver_class: DedupSolverClass,
    pub storage_price_bps: u64,
    pub retrieval_price_bps: u64,
    pub settlement_price_bps: u64,
    pub latency_ms: u64,
    pub retention_blocks: u64,
    pub capacity_root: String,
    pub pq_solver_key_root: String,
    pub quote_expires_at_height: u64,
    pub quote_nonce: String,
}

impl PostProverBidRequest {
    pub fn total_fee_bps(&self) -> u64 {
        self.storage_price_bps
            .saturating_add(self.retrieval_price_bps)
            .saturating_add(self.settlement_price_bps)
    }

    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
        require_non_empty("blob_id", &self.blob_id)?;
        require_non_empty("solver_commitment", &self.solver_commitment)?;
        require_bps("storage_price_bps", self.storage_price_bps)?;
        require_bps("retrieval_price_bps", self.retrieval_price_bps)?;
        require_bps("settlement_price_bps", self.settlement_price_bps)?;
        require_bps("total_fee_bps", self.total_fee_bps())?;
        require_positive_u64("latency_ms", self.latency_ms)?;
        require_positive_u64("retention_blocks", self.retention_blocks)?;
        require_root("capacity_root", &self.capacity_root)?;
        require_root("pq_solver_key_root", &self.pq_solver_key_root)?;
        if self.quote_expires_at_height <= current_height {
            return Err("quote_expires_at_height must be in the future".to_string());
        }
        if self.quote_expires_at_height > current_height.saturating_add(config.quote_ttl_blocks) {
            return Err("quote expiry exceeds runtime quote ttl".to_string());
        }
        require_non_empty("quote_nonce", &self.quote_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverBidRecord {
    pub quote_id: String,
    pub sequence: u64,
    pub request: PostProverBidRequest,
    pub status: QuoteStatus,
    pub posted_at_height: u64,
    pub quote_score: u64,
}

impl ProverBidRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishPqAvailabilityAttestationRequest {
    pub blob_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub committee_id: String,
    pub committee_epoch: u64,
    pub committee_public_key_root: String,
    pub signed_payload_root: String,
    pub availability_bitmap_root: String,
    pub pq_availability_share_root: String,
    pub aggregate_signature_root: String,
    pub committee_weight: u64,
    pub pq_security_bits: u16,
    pub valid_until_height: u64,
    pub attestation_nonce: String,
}

impl PublishPqAvailabilityAttestationRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
        require_non_empty_vec("blob_ids", &self.blob_ids)?;
        require_non_empty_vec("quote_ids", &self.quote_ids)?;
        ensure_unique("blob_ids", &self.blob_ids)?;
        ensure_unique("quote_ids", &self.quote_ids)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_positive_u64("committee_epoch", self.committee_epoch)?;
        require_root("committee_public_key_root", &self.committee_public_key_root)?;
        require_root("signed_payload_root", &self.signed_payload_root)?;
        require_root("availability_bitmap_root", &self.availability_bitmap_root)?;
        require_root(
            "pq_availability_share_root",
            &self.pq_availability_share_root,
        )?;
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
        require_non_empty("attestation_nonce", &self.attestation_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DedupAttestationRecord {
    pub attestation_id: String,
    pub sequence: u64,
    pub request: PublishPqAvailabilityAttestationRequest,
    pub status: AttestationStatus,
    pub attested_at_height: u64,
    pub attested_blob_count: u64,
}

impl DedupAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveDaVoucherRequest {
    pub blob_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub budget_commitment_root: String,
    pub max_total_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_target_bps: u64,
    pub reservation_expires_at_height: u64,
    pub reservation_nonce: String,
}

impl ReserveDaVoucherRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
        require_non_empty_vec("blob_ids", &self.blob_ids)?;
        require_non_empty_vec("quote_ids", &self.quote_ids)?;
        ensure_unique("blob_ids", &self.blob_ids)?;
        ensure_unique("quote_ids", &self.quote_ids)?;
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
        if self.reservation_expires_at_height <= current_height {
            return Err("reservation_expires_at_height must be in the future".to_string());
        }
        if self.reservation_expires_at_height
            > current_height.saturating_add(config.reservation_ttl_blocks)
        {
            return Err("reservation expiry exceeds runtime reservation ttl".to_string());
        }
        require_non_empty("reservation_nonce", &self.reservation_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucherReservationRecord {
    pub reservation_id: String,
    pub sequence: u64,
    pub request: ReserveDaVoucherRequest,
    pub status: ReservationStatus,
    pub reserved_at_height: u64,
    pub covered_blob_count: u64,
    pub covered_fee_micros: u64,
    pub expires_at_height: u64,
}

impl DaVoucherReservationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildCompressionBundleRequest {
    pub blob_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub settlement_payload_root: String,
    pub proof_batch_root: String,
    pub deduped_payload_commitment_root: String,
    pub delivery_manifest_root: String,
    pub fee_manifest_root: String,
    pub state_root_before: String,
    pub runtime_state_root_after: String,
    pub batch_expires_at_height: u64,
    pub batch_nonce: String,
}

impl BuildCompressionBundleRequest {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
        require_non_empty_vec("blob_ids", &self.blob_ids)?;
        require_non_empty_vec("quote_ids", &self.quote_ids)?;
        require_non_empty_vec("attestation_ids", &self.attestation_ids)?;
        ensure_unique("blob_ids", &self.blob_ids)?;
        ensure_unique("quote_ids", &self.quote_ids)?;
        ensure_unique("attestation_ids", &self.attestation_ids)?;
        ensure_unique("reservation_ids", &self.reservation_ids)?;
        if self.blob_ids.len() > config.max_batch_blobs {
            return Err("settlement batch exceeds max_batch_blobs".to_string());
        }
        require_root("settlement_payload_root", &self.settlement_payload_root)?;
        require_root("proof_batch_root", &self.proof_batch_root)?;
        require_root(
            "deduped_payload_commitment_root",
            &self.deduped_payload_commitment_root,
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
pub struct CompressionBundleRecord {
    pub batch_id: String,
    pub sequence: u64,
    pub request: BuildCompressionBundleRequest,
    pub status: SettlementBatchStatus,
    pub built_at_height: u64,
    pub total_blob_count: u64,
    pub total_effective_fee_bps: u64,
}

impl CompressionBundleRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishDeliveryReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: DeliveryReceiptKind,
    pub lane_id: Option<String>,
    pub blob_id: Option<String>,
    pub quote_id: Option<String>,
    pub attestation_id: Option<String>,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub delivered_payload_root: String,
    pub delivery_proof_root: String,
    pub fee_paid_bps: u64,
    pub observed_latency_ms: u64,
    pub receipt_nonce: String,
}

impl PublishDeliveryReceiptRequest {
    pub fn validate(&self) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
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
pub struct PublishFeeRebateRequest {
    pub reservation_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment_root: String,
    pub rebate_commitment_root: String,
    pub paid_fee_bps: u64,
    pub rebate_bps: u64,
    pub payout_nullifier_root: String,
    pub payout_nonce: String,
}

impl PublishFeeRebateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
        require_non_empty("reservation_id", &self.reservation_id)?;
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
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub sequence: u64,
    pub request: PublishFeeRebateRequest,
    pub paid_at_height: u64,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub lane_root: String,
    pub blob_root: String,
    pub quote_root: String,
    pub attestation_root: String,
    pub reservation_root: String,
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
    pub lanes: BTreeMap<String, CalldataLaneRecord>,
    pub blobs: BTreeMap<String, EncryptedCalldataBlobRecord>,
    pub quotes: BTreeMap<String, ProverBidRecord>,
    pub attestations: BTreeMap<String, DedupAttestationRecord>,
    pub reservations: BTreeMap<String, DaVoucherReservationRecord>,
    pub settlement_batches: BTreeMap<String, CompressionBundleRecord>,
    pub receipts: BTreeMap<String, DeliveryReceiptRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, current_height: u64) -> Self {
        let runtime_root = payload_root(
            "private-l2-low-fee-confidential-calldata-dedup-runtime-GENESIS",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION,
                "current_height": current_height,
            }),
        );
        Self {
            config,
            current_height,
            runtime_root,
            counters: Counters::default(),
            lanes: BTreeMap::new(),
            blobs: BTreeMap::new(),
            quotes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn validate_config(&self) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
        self.config.validate()
    }

    pub fn advance_height(&mut self, new_height: u64) {
        if new_height > self.current_height {
            self.current_height = new_height;
        }
    }

    pub fn register_lane(
        &mut self,
        request: RegisterCalldataLaneRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<CalldataLaneRecord> {
        self.config.validate()?;
        if self.lanes.len() >= self.config.max_lanes {
            return Err("lane limit reached".to_string());
        }
        request.validate(&self.config)?;
        self.counters.lane_counter = self.counters.lane_counter.saturating_add(1);
        let lane_id = calldata_lane_id(&request, self.counters.lane_counter);
        if self.lanes.contains_key(&lane_id) {
            return Err("lane already registered".to_string());
        }
        let lane_score = lane_score(&request);
        let record = CalldataLaneRecord {
            lane_id: lane_id.clone(),
            sequence: self.counters.lane_counter,
            request,
            status: LaneStatus::Open,
            registered_at_height: self.current_height,
            accepted_blob_count: 0,
            settled_blob_count: 0,
            cumulative_fee_bps: 0,
            lane_score,
        };
        self.lanes.insert(lane_id.clone(), record.clone());
        self.publish_public_record("calldata_lane", &lane_id, record.public_record());
        Ok(record)
    }

    pub fn submit_blob(
        &mut self,
        request: SubmitEncryptedCalldataBlobRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<EncryptedCalldataBlobRecord> {
        self.config.validate()?;
        if self.blobs.len() >= self.config.max_blobs {
            return Err("blob limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "unknown lane_id".to_string())?;
        if !lane.status.accepts_calldata() {
            return Err("lane is not accepting blobs".to_string());
        }
        if request.max_fee_bps > lane.request.max_user_fee_bps {
            return Err("blob max_fee_bps exceeds lane fee ceiling".to_string());
        }
        self.counters.blob_counter = self.counters.blob_counter.saturating_add(1);
        let blob_id = calldata_blob_id(&request, self.counters.blob_counter);
        if self.blobs.contains_key(&blob_id) {
            return Err("blob already submitted".to_string());
        }
        lane.accepted_blob_count = lane.accepted_blob_count.saturating_add(1);
        let record = EncryptedCalldataBlobRecord {
            blob_id: blob_id.clone(),
            sequence: self.counters.blob_counter,
            request,
            status: CalldataBlobStatus::Submitted,
            submitted_at_height: self.current_height,
            selected_quote_ids: Vec::new(),
            attestation_ids: Vec::new(),
            reservation_id: None,
            batch_id: None,
            receipt_ids: Vec::new(),
            effective_fee_bps: 0,
            privacy_set_size: self.config.min_privacy_set_size,
        };
        self.blobs.insert(blob_id.clone(), record.clone());
        self.publish_public_record("calldata_blob", &blob_id, record.public_record());
        Ok(record)
    }

    pub fn post_solver_quote(
        &mut self,
        request: PostProverBidRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<ProverBidRecord> {
        self.config.validate()?;
        if self.quotes.len() >= self.config.max_quotes {
            return Err("quote limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        let blob = self
            .blobs
            .get_mut(&request.blob_id)
            .ok_or_else(|| "unknown blob_id".to_string())?;
        if !blob.status.live() {
            return Err("blob is not live".to_string());
        }
        if request.total_fee_bps() > blob.request.max_fee_bps {
            return Err("quote total fee exceeds blob max_fee_bps".to_string());
        }
        self.counters.quote_counter = self.counters.quote_counter.saturating_add(1);
        let quote_id = dedup_solver_quote_id(&request, self.counters.quote_counter);
        if self.quotes.contains_key(&quote_id) {
            return Err("quote already posted".to_string());
        }
        blob.status = CalldataBlobStatus::Quoted;
        blob.selected_quote_ids.push(quote_id.clone());
        blob.effective_fee_bps = if blob.effective_fee_bps == 0 {
            request.total_fee_bps()
        } else {
            blob.effective_fee_bps.min(request.total_fee_bps())
        };
        let record = ProverBidRecord {
            quote_id: quote_id.clone(),
            sequence: self.counters.quote_counter,
            request: request.clone(),
            status: QuoteStatus::Posted,
            posted_at_height: self.current_height,
            quote_score: quote_score(&request, blob.request.priority_fee_micros),
        };
        self.quotes.insert(quote_id.clone(), record.clone());
        self.publish_public_record("dedup_solver_quote", &quote_id, record.public_record());
        Ok(record)
    }

    pub fn publish_pq_availability_attestation(
        &mut self,
        request: PublishPqAvailabilityAttestationRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<DedupAttestationRecord> {
        self.config.validate()?;
        if self.attestations.len() >= self.config.max_attestations {
            return Err("attestation limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        for blob_id in &request.blob_ids {
            if !self.blobs.contains_key(blob_id) {
                return Err(format!("unknown blob_id: {blob_id}"));
            }
        }
        for quote_id in &request.quote_ids {
            let quote = self
                .quotes
                .get(quote_id)
                .ok_or_else(|| format!("unknown quote_id: {quote_id}"))?;
            if !quote.status.selectable() {
                return Err(format!("quote is not selectable: {quote_id}"));
            }
        }
        self.counters.attestation_counter = self.counters.attestation_counter.saturating_add(1);
        let attestation_id =
            pq_availability_attestation_id(&request, self.counters.attestation_counter);
        if self.attestations.contains_key(&attestation_id) {
            return Err("attestation already published".to_string());
        }
        for quote_id in &request.quote_ids {
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Selected;
            }
        }
        for blob_id in &request.blob_ids {
            if let Some(blob) = self.blobs.get_mut(blob_id) {
                blob.status = CalldataBlobStatus::Attested;
                blob.attestation_ids.push(attestation_id.clone());
                blob.privacy_set_size = blob
                    .privacy_set_size
                    .max(self.config.batch_privacy_set_size);
            }
        }
        let record = DedupAttestationRecord {
            attestation_id: attestation_id.clone(),
            sequence: self.counters.attestation_counter,
            attested_blob_count: request.blob_ids.len() as u64,
            request,
            status: AttestationStatus::QuorumMet,
            attested_at_height: self.current_height,
        };
        self.attestations
            .insert(attestation_id.clone(), record.clone());
        self.publish_public_record(
            "pq_availability_attestation",
            &attestation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: ReserveDaVoucherRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<DaVoucherReservationRecord> {
        self.config.validate()?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("reservation limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        for blob_id in &request.blob_ids {
            let blob = self
                .blobs
                .get(blob_id)
                .ok_or_else(|| format!("unknown blob_id: {blob_id}"))?;
            if !matches!(
                blob.status,
                CalldataBlobStatus::Quoted | CalldataBlobStatus::Attested
            ) {
                return Err(format!("blob is not sponsor-reservable: {blob_id}"));
            }
        }
        for quote_id in &request.quote_ids {
            let quote = self
                .quotes
                .get(quote_id)
                .ok_or_else(|| format!("unknown quote_id: {quote_id}"))?;
            if quote.request.total_fee_bps() > request.max_total_fee_bps {
                return Err(format!("quote exceeds reservation fee cap: {quote_id}"));
            }
        }
        self.counters.reservation_counter = self.counters.reservation_counter.saturating_add(1);
        let reservation_id =
            low_fee_sponsor_reservation_id(&request, self.counters.reservation_counter);
        if self.reservations.contains_key(&reservation_id) {
            return Err("reservation already exists".to_string());
        }
        for quote_id in &request.quote_ids {
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Reserved;
            }
        }
        for blob_id in &request.blob_ids {
            if let Some(blob) = self.blobs.get_mut(blob_id) {
                blob.status = CalldataBlobStatus::Reserved;
                blob.reservation_id = Some(reservation_id.clone());
                blob.effective_fee_bps = blob.effective_fee_bps.min(request.max_total_fee_bps);
            }
        }
        let record = DaVoucherReservationRecord {
            reservation_id: reservation_id.clone(),
            sequence: self.counters.reservation_counter,
            covered_blob_count: request.blob_ids.len() as u64,
            covered_fee_micros: request.max_total_fee_bps,
            expires_at_height: request.reservation_expires_at_height,
            request,
            status: ReservationStatus::Reserved,
            reserved_at_height: self.current_height,
        };
        self.reservations
            .insert(reservation_id.clone(), record.clone());
        self.publish_public_record(
            "low_fee_sponsor_reservation",
            &reservation_id,
            record.public_record(),
        );
        Ok(record)
    }

    pub fn build_dedup_settlement_batch(
        &mut self,
        request: BuildCompressionBundleRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<CompressionBundleRecord> {
        self.config.validate()?;
        if self.settlement_batches.len() >= self.config.max_batches {
            return Err("settlement batch limit reached".to_string());
        }
        request.validate(&self.config, self.current_height)?;
        if request.state_root_before != self.state_root() {
            return Err("state_root_before does not match current state root".to_string());
        }
        if !covers_all_quotes(&self.quotes, &request.quote_ids, &request.blob_ids) {
            return Err("quote_ids do not cover every blob_id".to_string());
        }
        if !covers_all_attestations(
            &self.attestations,
            &request.attestation_ids,
            &request.blob_ids,
        ) {
            return Err("attestation_ids do not cover every blob_id".to_string());
        }
        if !request.reservation_ids.is_empty()
            && !covers_all_reservations(
                &self.reservations,
                &request.reservation_ids,
                &request.blob_ids,
            )
        {
            return Err("reservation_ids do not cover every blob_id".to_string());
        }
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        let batch_id = dedup_settlement_batch_id(&request, self.counters.batch_counter);
        if self.settlement_batches.contains_key(&batch_id) {
            return Err("settlement batch already exists".to_string());
        }
        let total_effective_fee_bps = request
            .blob_ids
            .iter()
            .filter_map(|blob_id| self.blobs.get(blob_id))
            .map(|blob| blob.effective_fee_bps)
            .sum::<u64>();
        for quote_id in &request.quote_ids {
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Filled;
            }
        }
        for attestation_id in &request.attestation_ids {
            if let Some(attestation) = self.attestations.get_mut(attestation_id) {
                attestation.status = AttestationStatus::BatchBound;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::BatchBound;
            }
        }
        for blob_id in &request.blob_ids {
            if let Some(blob) = self.blobs.get_mut(blob_id) {
                blob.status = CalldataBlobStatus::BatchReady;
                blob.batch_id = Some(batch_id.clone());
            }
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        let record = CompressionBundleRecord {
            batch_id: batch_id.clone(),
            sequence: self.counters.batch_counter,
            total_blob_count: request.blob_ids.len() as u64,
            total_effective_fee_bps,
            request,
            status: SettlementBatchStatus::ProofBundled,
            built_at_height: self.current_height,
        };
        self.settlement_batches
            .insert(batch_id.clone(), record.clone());
        self.publish_public_record("dedup_settlement_batch", &batch_id, record.public_record());
        Ok(record)
    }

    pub fn publish_delivery_receipt(
        &mut self,
        request: PublishDeliveryReceiptRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<DeliveryReceiptRecord> {
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
        if let Some(blob_id) = &request.blob_id {
            if let Some(blob) = self.blobs.get_mut(blob_id) {
                blob.receipt_ids.push(receipt_id.clone());
                if request.receipt_kind == DeliveryReceiptKind::blobDelivered {
                    blob.status = CalldataBlobStatus::Delivered;
                }
            }
        }
        if let Some(batch_id) = &request.batch_id {
            if let Some(batch) = self.settlement_batches.get_mut(batch_id) {
                if request.receipt_kind == DeliveryReceiptKind::DedupSettled {
                    batch.status = SettlementBatchStatus::Settled;
                    for blob_id in &batch.request.blob_ids {
                        if let Some(blob) = self.blobs.get_mut(blob_id) {
                            blob.status = CalldataBlobStatus::Settled;
                            if let Some(lane) = self.lanes.get_mut(&blob.request.lane_id) {
                                lane.settled_blob_count = lane.settled_blob_count.saturating_add(1);
                                lane.cumulative_fee_bps = lane
                                    .cumulative_fee_bps
                                    .saturating_add(blob.effective_fee_bps);
                            }
                        }
                    }
                    for attestation_id in &batch.request.attestation_ids {
                        if let Some(attestation) = self.attestations.get_mut(attestation_id) {
                            attestation.status = AttestationStatus::Settled;
                        }
                    }
                    for reservation_id in &batch.request.reservation_ids {
                        if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                            reservation.status = ReservationStatus::Settled;
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
        request: PublishFeeRebateRequest,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<FeeRebateRecord> {
        self.config.validate()?;
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate limit reached".to_string());
        }
        request.validate(&self.config)?;
        let reservation = self
            .reservations
            .get(&request.reservation_id)
            .ok_or_else(|| "unknown reservation_id".to_string())?;
        if !matches!(
            reservation.status,
            ReservationStatus::Settled | ReservationStatus::BatchBound
        ) {
            return Err("reservation is not rebate eligible".to_string());
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
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::Settled;
        }
        if let Some(batch) = self.settlement_batches.get_mut(&request.batch_id) {
            batch.status = SettlementBatchStatus::Rebated;
            for blob_id in &batch.request.blob_ids {
                if let Some(blob) = self.blobs.get_mut(blob_id) {
                    blob.status = CalldataBlobStatus::Rebated;
                }
            }
        }
        let record = FeeRebateRecord {
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
        for blob in self.blobs.values_mut() {
            if blob.status.live() && blob.request.expires_at_height <= self.current_height {
                blob.status = CalldataBlobStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if quote.status.selectable()
                && quote.request.quote_expires_at_height <= self.current_height
            {
                quote.status = QuoteStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            if matches!(
                attestation.status,
                AttestationStatus::Proposed | AttestationStatus::QuorumMet
            ) && attestation.request.valid_until_height <= self.current_height
            {
                attestation.status = AttestationStatus::Expired;
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.status == ReservationStatus::Reserved
                && reservation.request.reservation_expires_at_height <= self.current_height
            {
                reservation.status = ReservationStatus::Expired;
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
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = payload_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-COUNTERS",
            &self.counters.public_record(),
        );
        let lane_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-LANES",
            &self
                .lanes
                .values()
                .map(CalldataLaneRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let blob_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-blobs",
            &self
                .blobs
                .values()
                .map(EncryptedCalldataBlobRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let quote_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-QUOTES",
            &self
                .quotes
                .values()
                .map(ProverBidRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-ATTESTATIONS",
            &self
                .attestations
                .values()
                .map(DedupAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(DaVoucherReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-BATCHES",
            &self
                .settlement_batches
                .values()
                .map(CompressionBundleRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-RECEIPTS",
            &self
                .receipts
                .values()
                .map(DeliveryReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-REBATES",
            &self
                .rebates
                .values()
                .map(FeeRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let public_records = self.public_records.values().cloned().collect::<Vec<_>>();
        let public_record_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-PUBLIC-RECORDS",
            &public_records,
        );
        let roots_without_state = json!({
            "config_root": config_root,
            "counter_root": counter_root,
            "lane_root": lane_root,
            "blob_root": blob_root,
            "quote_root": quote_root,
            "attestation_root": attestation_root,
            "reservation_root": reservation_root,
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
            blob_root,
            quote_root,
            attestation_root,
            reservation_root,
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
            "kind": "private_l2_low_fee_confidential_calldata_dedup_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_SCHEMA_VERSION,
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

pub fn calldata_lane_id(request: &RegisterCalldataLaneRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.lane_owner_commitment),
            HashPart::Str(request.lane_kind.as_str()),
            HashPart::Str(&request.lane_policy_root),
            HashPart::Str(&request.lane_nonce),
        ],
        32,
    )
}

pub fn calldata_blob_id(request: &SubmitEncryptedCalldataBlobRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-blob-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.ciphertext_root),
            HashPart::Str(&request.erasure_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(request.encoding.as_str()),
            HashPart::Str(&request.blob_nonce),
        ],
        32,
    )
}

pub fn dedup_solver_quote_id(request: &PostProverBidRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.blob_id),
            HashPart::Str(&request.solver_commitment),
            HashPart::Str(request.solver_class.as_str()),
            HashPart::Int(request.total_fee_bps() as i128),
            HashPart::Str(&request.capacity_root),
            HashPart::Str(&request.quote_nonce),
        ],
        32,
    )
}

pub fn pq_availability_attestation_id(
    request: &PublishPqAvailabilityAttestationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("blob_ids", &request.blob_ids)),
            HashPart::Str(&id_list_root("quote_ids", &request.quote_ids)),
            HashPart::Str(&request.committee_id),
            HashPart::Int(request.committee_epoch as i128),
            HashPart::Str(&request.signed_payload_root),
            HashPart::Str(&request.aggregate_signature_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn low_fee_sponsor_reservation_id(request: &ReserveDaVoucherRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("blob_ids", &request.blob_ids)),
            HashPart::Str(&id_list_root("quote_ids", &request.quote_ids)),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.budget_commitment_root),
            HashPart::Str(&request.reservation_nonce),
        ],
        32,
    )
}

pub fn dedup_settlement_batch_id(request: &BuildCompressionBundleRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("blob_ids", &request.blob_ids)),
            HashPart::Str(&id_list_root("attestation_ids", &request.attestation_ids)),
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
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-DELIVERY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
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

pub fn rebate_payout_id(request: &PublishFeeRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-REBATE-PAYOUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.reservation_id),
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
            HashPart::Str(PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_PROTOCOL_VERSION),
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
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-STATE",
        record,
    )
}

pub fn private_l2_low_fee_confidential_calldata_dedup_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_confidential_calldata_dedup_runtime_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    payload_root(domain, payload)
}

pub fn private_l2_low_fee_confidential_calldata_dedup_runtime_public_record_root(
    domain: &str,
    records: &[Value],
) -> String {
    public_record_root(domain, records)
}

pub fn private_l2_low_fee_confidential_calldata_dedup_runtime_state_root_from_record(
    record: &Value,
) -> String {
    state_root_from_record(record)
}

fn lane_score(request: &RegisterCalldataLaneRequest) -> u64 {
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

fn quote_score(request: &PostProverBidRequest, priority_fee_micros: u64) -> u64 {
    let fee_penalty = request.total_fee_bps().saturating_mul(1_000);
    let latency_penalty = request.latency_ms.saturating_mul(2);
    let retention_bonus = request.retention_blocks / 32;
    let class_bonus = match request.solver_class {
        DedupSolverClass::FastEdgeCache => 2_000,
        DedupSolverClass::SequencerOperated => 1_500,
        DedupSolverClass::SponsorBacked => 1_250,
        DedupSolverClass::MoneroBridgeRelay => 1_100,
        DedupSolverClass::CommunityArchive => 900,
        DedupSolverClass::ColdProofArchive => 500,
    };
    100_000_u64
        .saturating_add(class_bonus)
        .saturating_add(retention_bonus)
        .saturating_add(priority_fee_micros / 1_000)
        .saturating_sub(fee_penalty)
        .saturating_sub(latency_penalty)
}

fn covers_all_quotes(
    quotes: &BTreeMap<String, ProverBidRecord>,
    quote_ids: &[String],
    blob_ids: &[String],
) -> bool {
    let covered = quote_ids
        .iter()
        .filter_map(|quote_id| quotes.get(quote_id))
        .filter(|quote| matches!(quote.status, QuoteStatus::Selected | QuoteStatus::Reserved))
        .map(|quote| &quote.request.blob_id)
        .collect::<BTreeSet<_>>();
    blob_ids.iter().all(|blob_id| covered.contains(blob_id))
}

fn covers_all_attestations(
    attestations: &BTreeMap<String, DedupAttestationRecord>,
    attestation_ids: &[String],
    blob_ids: &[String],
) -> bool {
    let covered = attestation_ids
        .iter()
        .filter_map(|attestation_id| attestations.get(attestation_id))
        .filter(|attestation| attestation.status == AttestationStatus::QuorumMet)
        .flat_map(|attestation| attestation.request.blob_ids.iter())
        .collect::<BTreeSet<_>>();
    blob_ids.iter().all(|blob_id| covered.contains(blob_id))
}

fn covers_all_reservations(
    reservations: &BTreeMap<String, DaVoucherReservationRecord>,
    reservation_ids: &[String],
    blob_ids: &[String],
) -> bool {
    let covered = reservation_ids
        .iter()
        .filter_map(|reservation_id| reservations.get(reservation_id))
        .filter(|reservation| reservation.status == ReservationStatus::Reserved)
        .flat_map(|reservation| reservation.request.blob_ids.iter())
        .collect::<BTreeSet<_>>();
    blob_ids.iter().all(|blob_id| covered.contains(blob_id))
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-ID-LIST-{label}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-PUBLIC-RECORD-ID",
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
        "kind": "private_l2_low_fee_confidential_calldata_dedup_runtime_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": payload_root(
            "PRIVATE-L2-LOW-FEE-Confidential calldata-dedup-MARKET-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CalldataDedupCommitmentRecord {
    pub commitment_id: String,
    pub contract_address_root: String,
    pub selector_root: String,
    pub encrypted_calldata_root: String,
    pub plaintext_shape_root: String,
    pub dedup_key_commitment: String,
    pub duplicate_class_root: String,
    pub salt_root: String,
    pub created_height: u64,
}

impl CalldataDedupCommitmentRecord {
    pub fn new(
        contract_address_root: impl Into<String>,
        selector_root: impl Into<String>,
        encrypted_calldata_root: impl Into<String>,
        plaintext_shape_root: impl Into<String>,
        dedup_key_commitment: impl Into<String>,
        duplicate_class_root: impl Into<String>,
        salt_root: impl Into<String>,
        created_height: u64,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<Self> {
        let contract_address_root = contract_address_root.into();
        let selector_root = selector_root.into();
        let encrypted_calldata_root = encrypted_calldata_root.into();
        let plaintext_shape_root = plaintext_shape_root.into();
        let dedup_key_commitment = dedup_key_commitment.into();
        let duplicate_class_root = duplicate_class_root.into();
        let salt_root = salt_root.into();
        require_root("commitment contract address root", &contract_address_root)?;
        require_root("commitment selector root", &selector_root)?;
        require_root(
            "commitment encrypted calldata root",
            &encrypted_calldata_root,
        )?;
        require_root("commitment plaintext shape root", &plaintext_shape_root)?;
        require_root("commitment dedup key", &dedup_key_commitment)?;
        require_root("commitment duplicate class root", &duplicate_class_root)?;
        require_root("commitment salt root", &salt_root)?;
        require_positive_u64("commitment created height", created_height)?;
        let commitment_id = calldata_dedup_commitment_id(
            &contract_address_root,
            &selector_root,
            &encrypted_calldata_root,
            &dedup_key_commitment,
            created_height,
        );
        Ok(Self {
            commitment_id,
            contract_address_root,
            selector_root,
            encrypted_calldata_root,
            plaintext_shape_root,
            dedup_key_commitment,
            duplicate_class_root,
            salt_root,
            created_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "calldata_dedup_commitment",
            "commitment_id": self.commitment_id,
            "contract_address_root": self.contract_address_root,
            "selector_root": self.selector_root,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "plaintext_shape_root": self.plaintext_shape_root,
            "dedup_key_commitment": self.dedup_key_commitment,
            "duplicate_class_root": self.duplicate_class_root,
            "salt_root": self.salt_root,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionBundlePublicSummary {
    pub bundle_id: String,
    pub bundle_root: String,
    pub blob_count: usize,
    pub da_voucher_root: String,
    pub quote_root: String,
    pub attestation_root: String,
    pub proof_batch_root: String,
    pub deduped_payload_commitment_root: String,
    pub delivery_manifest_root: String,
    pub fee_manifest_root: String,
    pub proof_transcript_root: String,
}

impl CompressionBundlePublicSummary {
    pub fn from_bundle(record: &CompressionBundleRecord) -> Self {
        let bundle_root = payload_root(
            "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-BUNDLE-SUMMARY",
            &record.public_record(),
        );
        Self {
            bundle_id: record.batch_id.clone(),
            bundle_root,
            blob_count: record.request.blob_ids.len(),
            da_voucher_root: id_list_root("BUNDLE-DA-VOUCHERS", &record.request.reservation_ids),
            quote_root: id_list_root("BUNDLE-PROVER-BIDS", &record.request.quote_ids),
            attestation_root: id_list_root(
                "BUNDLE-DEDUP-ATTESTATIONS",
                &record.request.attestation_ids,
            ),
            proof_batch_root: record.request.proof_batch_root.clone(),
            deduped_payload_commitment_root: record.request.deduped_payload_commitment_root.clone(),
            delivery_manifest_root: record.request.delivery_manifest_root.clone(),
            fee_manifest_root: record.request.fee_manifest_root.clone(),
            proof_transcript_root: payload_root(
                "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-BUNDLE-PROOF-TRANSCRIPT",
                &json!({
                    "proof_batch_root": &record.request.proof_batch_root,
                    "settlement_payload_root": &record.request.settlement_payload_root,
                    "state_root_before": &record.request.state_root_before,
                    "runtime_state_root_after": &record.request.runtime_state_root_after,
                }),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_bundle_public_summary",
            "bundle_id": self.bundle_id,
            "bundle_root": self.bundle_root,
            "blob_count": self.blob_count,
            "da_voucher_root": self.da_voucher_root,
            "quote_root": self.quote_root,
            "attestation_root": self.attestation_root,
            "proof_batch_root": self.proof_batch_root,
            "deduped_payload_commitment_root": self.deduped_payload_commitment_root,
            "delivery_manifest_root": self.delivery_manifest_root,
            "fee_manifest_root": self.fee_manifest_root,
            "proof_transcript_root": self.proof_transcript_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucherPublicRecord {
    pub voucher_id: String,
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub covered_blob_root: String,
    pub covered_fee_micros: u64,
    pub expiry_height: u64,
}

impl DaVoucherPublicRecord {
    pub fn from_reservation(record: &DaVoucherReservationRecord) -> Self {
        let covered_blob_root = id_list_root("DA-VOUCHER-COVERED-BLOBS", &record.request.blob_ids);
        let voucher_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-DA-VOUCHER-ID",
            &[
                HashPart::Str(&record.reservation_id),
                HashPart::Str(&record.request.sponsor_commitment),
                HashPart::Str(&covered_blob_root),
                HashPart::U64(record.expires_at_height),
            ],
            32,
        );
        Self {
            voucher_id,
            reservation_id: record.reservation_id.clone(),
            sponsor_commitment: record.request.sponsor_commitment.clone(),
            covered_blob_root,
            covered_fee_micros: record.covered_fee_micros,
            expiry_height: record.expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_voucher_public_record",
            "voucher_id": self.voucher_id,
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "covered_blob_root": self.covered_blob_root,
            "covered_fee_micros": self.covered_fee_micros,
            "expiry_height": self.expiry_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialCalldataPrivacyFenceRecord {
    pub fence_id: String,
    pub lane_id: String,
    pub contract_group_root: String,
    pub allowed_selector_root: String,
    pub denied_observer_root: String,
    pub min_anonymity_set: u64,
    pub fence_epoch: u64,
}

impl ConfidentialCalldataPrivacyFenceRecord {
    pub fn new(
        lane_id: impl Into<String>,
        contract_group_root: impl Into<String>,
        allowed_selector_root: impl Into<String>,
        denied_observer_root: impl Into<String>,
        min_anonymity_set: u64,
        fence_epoch: u64,
    ) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<Self> {
        let lane_id = lane_id.into();
        let contract_group_root = contract_group_root.into();
        let allowed_selector_root = allowed_selector_root.into();
        let denied_observer_root = denied_observer_root.into();
        require_non_empty("privacy fence lane id", &lane_id)?;
        require_root("privacy fence contract group root", &contract_group_root)?;
        require_root("privacy fence selector root", &allowed_selector_root)?;
        require_root("privacy fence denied observer root", &denied_observer_root)?;
        require_positive_u64("privacy fence anonymity set", min_anonymity_set)?;
        let fence_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-PRIVACY-FENCE-ID",
            &[
                HashPart::Str(&lane_id),
                HashPart::Str(&contract_group_root),
                HashPart::Str(&allowed_selector_root),
                HashPart::U64(min_anonymity_set),
                HashPart::U64(fence_epoch),
            ],
            32,
        );
        Ok(Self {
            fence_id,
            lane_id,
            contract_group_root,
            allowed_selector_root,
            denied_observer_root,
            min_anonymity_set,
            fence_epoch,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_calldata_privacy_fence",
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "contract_group_root": self.contract_group_root,
            "allowed_selector_root": self.allowed_selector_root,
            "denied_observer_root": self.denied_observer_root,
            "min_anonymity_set": self.min_anonymity_set,
            "fence_epoch": self.fence_epoch,
        })
    }
}

pub fn calldata_dedup_commitment_id(
    contract_address_root: &str,
    selector_root: &str,
    encrypted_calldata_root: &str,
    dedup_key_commitment: &str,
    created_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_address_root),
            HashPart::Str(selector_root),
            HashPart::Str(encrypted_calldata_root),
            HashPart::Str(dedup_key_commitment),
            HashPart::U64(created_height),
        ],
        32,
    )
}

pub fn calldata_dedup_commitment_root(records: &[CalldataDedupCommitmentRecord]) -> String {
    public_record_root(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-COMMITMENT-ROOT",
        &records
            .iter()
            .map(CalldataDedupCommitmentRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn compression_bundle_summary_root(records: &[CompressionBundlePublicSummary]) -> String {
    public_record_root(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-BUNDLE-SUMMARY-ROOT",
        &records
            .iter()
            .map(CompressionBundlePublicSummary::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn da_voucher_public_root(records: &[DaVoucherPublicRecord]) -> String {
    public_record_root(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-DA-VOUCHER-ROOT",
        &records
            .iter()
            .map(DaVoucherPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_fence_public_root(records: &[ConfidentialCalldataPrivacyFenceRecord]) -> String {
    public_record_root(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-CALLDATA-DEDUP-PRIVACY-FENCE-ROOT",
        &records
            .iter()
            .map(ConfidentialCalldataPrivacyFenceRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn deterministic_calldata_public_record_id(record_kind: &str, subject_id: &str) -> String {
    public_record_id(
        record_kind,
        subject_id,
        &json!({
            "chain_id": CHAIN_ID,
            "record_kind": record_kind,
            "subject_id": subject_id,
        }),
    )
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_non_empty_vec(
    field: &str,
    values: &[String],
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
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
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_positive_usize(
    field: &str,
    value: usize,
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(
    field: &str,
    value: u64,
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(
    field: &str,
    value: u64,
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
    if value > PRIVATE_L2_LOW_FEE_CONFIDENTIAL_CALLDATA_DEDUP_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_unique(
    field: &str,
    values: &[String],
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
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
) -> PrivateL2LowFeeConfidentialCalldataDedupRuntimeResult<()> {
    if actual != expected {
        Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ))
    } else {
        Ok(())
    }
}
