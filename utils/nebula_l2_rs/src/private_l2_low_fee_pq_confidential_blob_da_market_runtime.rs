use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBlobDaMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_DA_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-blob-da-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_DA_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const CONFIDENTIAL_BLOB_DA_MARKET_SUITE: &str =
    "low-fee-pq-confidential-encrypted-blob-erasure-da-market-v1";
pub const ENCRYPTED_BLOB_COMMITMENT_SCHEME: &str =
    "pq-confidential-blob-ciphertext-commitment-root-v1";
pub const ERASURE_SHARD_SCHEME: &str = "pq-confidential-erasure-shard-tree-v1";
pub const PQ_STORAGE_ATTESTATION_SCHEME: &str =
    "pq-storage-attestation-ml-dsa-slh-dsa-da-provider-v1";
pub const PRIVATE_CALLDATA_BATCH_SCHEME: &str =
    "private-contract-calldata-batch-confidential-da-v1";
pub const PROOF_COUPON_SCHEME: &str = "low-fee-da-proof-coupon-v1";
pub const SPONSOR_RESERVATION_SCHEME: &str = "anonymous-da-sponsor-reservation-v1";
pub const REBATE_RECEIPT_SCHEME: &str = "confidential-da-rebate-receipt-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "confidential-da-nullifier-fence-v1";
pub const WITHHOLDING_CHALLENGE_SCHEME: &str = "da-data-withholding-challenge-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-da-provider-slashing-evidence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_730_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_750;
pub const DEFAULT_PROVIDER_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_BLOB_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_CALLDATA_BATCH_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_CERTIFICATE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 192;
pub const DEFAULT_MAX_BATCH_BLOBS: usize = 16_384;
pub const DEFAULT_MAX_SHARDS_PER_BLOB: usize = 4_096;
pub const MAX_MARKET_LANES: usize = 262_144;
pub const MAX_PROVIDERS: usize = 1_048_576;
pub const MAX_BLOB_QUOTES: usize = 4_194_304;
pub const MAX_RESERVATIONS: usize = 4_194_304;
pub const MAX_BLOB_COMMITMENTS: usize = 4_194_304;
pub const MAX_SHARD_SETS: usize = 4_194_304;
pub const MAX_STORAGE_ATTESTATIONS: usize = 8_388_608;
pub const MAX_CALLDATA_BATCHES: usize = 2_097_152;
pub const MAX_DA_CERTIFICATES: usize = 2_097_152;
pub const MAX_PROOF_COUPONS: usize = 4_194_304;
pub const MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const MAX_REBATE_RECEIPTS: usize = 4_194_304;
pub const MAX_NULLIFIER_FENCES: usize = 8_388_608;
pub const MAX_WITHHOLDING_CHALLENGES: usize = 1_048_576;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketLaneKind {
    PrivateContractCalldata,
    DefiSettlement,
    ConfidentialTokenTransfer,
    MoneroFastExit,
    OracleUpdate,
    BridgeMessage,
    SequencerInbox,
    RecursiveProofWitness,
    EmergencyEscape,
}
impl MarketLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCalldata => "private_contract_calldata",
            Self::DefiSettlement => "defi_settlement",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeMessage => "bridge_message",
            Self::SequencerInbox => "sequencer_inbox",
            Self::RecursiveProofWitness => "recursive_proof_witness",
            Self::EmergencyEscape => "emergency_escape",
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
    pub fn accepts_blobs(self) -> bool {
        matches!(self, Self::Open | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderClass {
    SequencerOperated,
    CommunityEdge,
    ColdArchive,
    FastCache,
    SponsorBacked,
    MoneroBridgeRelay,
    EmergencyGuardian,
}
impl ProviderClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerOperated => "sequencer_operated",
            Self::CommunityEdge => "community_edge",
            Self::ColdArchive => "cold_archive",
            Self::FastCache => "fast_cache",
            Self::SponsorBacked => "sponsor_backed",
            Self::MoneroBridgeRelay => "monero_bridge_relay",
            Self::EmergencyGuardian => "emergency_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Active,
    Throttled,
    Probation,
    Paused,
    Slashed,
    Retired,
}
impl ProviderStatus {
    pub fn accepts_reservations(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Probation)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobEncoding {
    CiphertextChunks,
    ReedSolomonCiphertext,
    FecTreeCiphertext,
    KzgBackedCiphertext,
    RecursiveWitnessCiphertext,
    CalldataCiphertext,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobStatus {
    Committed,
    Quoted,
    Reserved,
    Sharded,
    Attested,
    Batched,
    Certified,
    CouponIssued,
    Settled,
    Rebated,
    Expired,
    Rejected,
    Challenged,
    Slashed,
}
impl BlobStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Quoted
                | Self::Reserved
                | Self::Sharded
                | Self::Attested
                | Self::Batched
                | Self::Certified
                | Self::CouponIssued
                | Self::Challenged
        )
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
    Cancelled,
    Slashed,
}
impl QuoteStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Held,
    BatchBound,
    CertificateBound,
    Settled,
    Released,
    Expired,
    Slashed,
}
impl ReservationStatus {
    pub fn locked(self) -> bool {
        matches!(self, Self::Held | Self::BatchBound | Self::CertificateBound)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Committed,
    Reserved,
    Stored,
    Attested,
    Unavailable,
    Recovered,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    QuorumMet,
    CertificateBound,
    Settled,
    Expired,
    Disputed,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CalldataBatchStatus {
    Draft,
    Sealed,
    DaBound,
    Certified,
    Settled,
    Expired,
    Rejected,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Published,
    CouponReady,
    Settled,
    Challenged,
    Invalidated,
    Expired,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Redeemed,
    Rebated,
    Expired,
    Cancelled,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Open,
    PartiallyConsumed,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimed,
    Expired,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Opened,
    EvidenceSubmitted,
    Upheld,
    Rejected,
    TimedOut,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Filed,
    Accepted,
    Rejected,
    Executed,
    Appealed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyDomain {
    Defi,
    Token,
    Lending,
    Derivatives,
    Oracle,
    Bridge,
    Governance,
    Treasury,
    General,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithholdingFaultKind {
    MissingShard,
    BadShardOpening,
    LateAttestation,
    UnavailableProvider,
    FraudulentCertificate,
    FenceViolation,
    EquivocatedRoot,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponKind {
    DaAvailability,
    CalldataBatch,
    ErasureRepair,
    RecursiveProof,
    SponsorRebate,
    EmergencyRecovery,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub max_market_lanes: usize,
    pub max_providers: usize,
    pub max_blob_quotes: usize,
    pub max_reservations: usize,
    pub max_blob_commitments: usize,
    pub max_shard_sets: usize,
    pub max_storage_attestations: usize,
    pub max_calldata_batches: usize,
    pub max_da_certificates: usize,
    pub max_proof_coupons: usize,
    pub max_sponsor_reservations: usize,
    pub max_rebate_receipts: usize,
    pub max_nullifier_fences: usize,
    pub max_withholding_challenges: usize,
    pub max_slashing_evidence: usize,
    pub max_events: usize,
    pub max_batch_blobs: usize,
    pub max_shards_per_blob: usize,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub blob_ttl_blocks: u64,
    pub calldata_batch_ttl_blocks: u64,
    pub certificate_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub provider_slash_bps: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub require_pq_signatures: bool,
    pub require_encrypted_blobs: bool,
    pub require_erasure_coding: bool,
    pub require_nullifier_fences: bool,
    pub allow_devnet_shortcuts: bool,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            max_market_lanes: MAX_MARKET_LANES,
            max_providers: MAX_PROVIDERS,
            max_blob_quotes: MAX_BLOB_QUOTES,
            max_reservations: MAX_RESERVATIONS,
            max_blob_commitments: MAX_BLOB_COMMITMENTS,
            max_shard_sets: MAX_SHARD_SETS,
            max_storage_attestations: MAX_STORAGE_ATTESTATIONS,
            max_calldata_batches: MAX_CALLDATA_BATCHES,
            max_da_certificates: MAX_DA_CERTIFICATES,
            max_proof_coupons: MAX_PROOF_COUPONS,
            max_sponsor_reservations: MAX_SPONSOR_RESERVATIONS,
            max_rebate_receipts: MAX_REBATE_RECEIPTS,
            max_nullifier_fences: MAX_NULLIFIER_FENCES,
            max_withholding_challenges: MAX_WITHHOLDING_CHALLENGES,
            max_slashing_evidence: MAX_SLASHING_EVIDENCE,
            max_events: MAX_EVENTS,
            max_batch_blobs: DEFAULT_MAX_BATCH_BLOBS,
            max_shards_per_blob: DEFAULT_MAX_SHARDS_PER_BLOB,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            blob_ttl_blocks: DEFAULT_BLOB_TTL_BLOCKS,
            calldata_batch_ttl_blocks: DEFAULT_CALLDATA_BATCH_TTL_BLOCKS,
            certificate_ttl_blocks: DEFAULT_CERTIFICATE_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            provider_slash_bps: DEFAULT_PROVIDER_SLASH_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            require_pq_signatures: true,
            require_encrypted_blobs: true,
            require_erasure_coding: true,
            require_nullifier_fences: true,
            allow_devnet_shortcuts: false,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure(!self.l2_network.is_empty(), "l2 network is required")?;
        ensure(
            !self.monero_network.is_empty(),
            "monero network is required",
        )?;
        ensure(!self.fee_asset_id.is_empty(), "fee asset id is required")?;
        ensure(self.max_market_lanes > 0, "market lane capacity is zero")?;
        ensure(self.max_providers > 0, "provider capacity is zero")?;
        ensure(self.max_batch_blobs > 0, "batch blob capacity is zero")?;
        ensure(self.max_shards_per_blob > 0, "shard capacity is zero")?;
        ensure(
            self.min_pq_security_bits >= 192,
            "pq security floor is too low",
        )?;
        ensure(
            self.min_privacy_set_size >= 128,
            "privacy set floor is too low",
        )?;
        ensure(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        ensure(
            self.max_user_fee_bps <= MAX_BPS,
            "user fee cap exceeds bps scale",
        )?;
        ensure(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "target rebate exceeds fee cap",
        )?;
        ensure(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover exceeds bps scale",
        )?;
        ensure(
            self.provider_slash_bps <= MAX_BPS,
            "slash bps exceeds scale",
        )?;
        ensure(
            self.quorum_bps <= self.strong_quorum_bps,
            "quorum exceeds strong quorum",
        )?;
        ensure(
            self.strong_quorum_bps <= MAX_BPS,
            "strong quorum exceeds bps scale",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub next_lane_nonce: u64,
    pub next_provider_nonce: u64,
    pub next_blob_nonce: u64,
    pub next_quote_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_shard_set_nonce: u64,
    pub next_attestation_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_certificate_nonce: u64,
    pub next_coupon_nonce: u64,
    pub next_sponsor_nonce: u64,
    pub next_rebate_nonce: u64,
    pub next_challenge_nonce: u64,
    pub next_slashing_nonce: u64,
    pub event_count: u64,
    pub total_reserved_bytes: u128,
    pub total_certified_bytes: u128,
    pub total_fees_charged: u128,
    pub total_rebates_paid: u128,
    pub total_slashed: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub provider_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub blob_root: String,
    pub shard_root: String,
    pub attestation_root: String,
    pub calldata_batch_root: String,
    pub certificate_root: String,
    pub coupon_root: String,
    pub sponsor_root: String,
    pub rebate_root: String,
    pub nullifier_fence_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketLane {
    pub lane_id: String,
    pub kind: MarketLaneKind,
    pub status: LaneStatus,
    pub owner_commitment: String,
    pub fee_asset_id: String,
    pub max_blob_bytes: u64,
    pub target_latency_ms: u64,
    pub base_fee_microunits: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub lane_root: String,
}

impl MarketLane {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("MARKETLANE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProvider {
    pub provider_id: String,
    pub class: ProviderClass,
    pub status: ProviderStatus,
    pub operator_commitment: String,
    pub pq_attestation_key_commitment: String,
    pub stake_commitment: String,
    pub available_bytes: u128,
    pub reserved_bytes: u128,
    pub served_bytes: u128,
    pub reputation_score: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub joined_at_height: u64,
    pub updated_at_height: u64,
    pub provider_root: String,
}

impl StorageProvider {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("STORAGEPROVIDER", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBlobCommitment {
    pub blob_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub encoding: BlobEncoding,
    pub status: BlobStatus,
    pub ciphertext_root: String,
    pub ciphertext_bytes: u64,
    pub erasure_k: u16,
    pub erasure_m: u16,
    pub privacy_domain: PrivacyDomain,
    pub fee_limit_microunits: u128,
    pub nullifier_hash: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub commitment_root: String,
}

impl EncryptedBlobCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("ENCRYPTEDBLOBCOMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobQuote {
    pub quote_id: String,
    pub blob_id: String,
    pub lane_id: String,
    pub provider_id: String,
    pub status: QuoteStatus,
    pub price_microunits: u128,
    pub fee_bps: u64,
    pub reserved_bytes: u64,
    pub shard_count: u32,
    pub expires_at_height: u64,
    pub quote_root: String,
}

impl BlobQuote {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("BLOBQUOTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardReservation {
    pub reservation_id: String,
    pub quote_id: String,
    pub blob_id: String,
    pub provider_id: String,
    pub sponsor_id: Option<String>,
    pub status: ReservationStatus,
    pub reserved_bytes: u64,
    pub locked_fee_microunits: u128,
    pub rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub reservation_root: String,
}

impl ShardReservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("SHARDRESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErasureShardSet {
    pub shard_set_id: String,
    pub blob_id: String,
    pub reservation_id: String,
    pub provider_id: String,
    pub status: ShardStatus,
    pub shard_roots: Vec<String>,
    pub parity_roots: Vec<String>,
    pub required_shards: u16,
    pub total_shards: u16,
    pub availability_root: String,
    pub published_at_height: u64,
    pub shard_set_root: String,
}

impl ErasureShardSet {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("ERASURESHARDSET", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqStorageAttestation {
    pub attestation_id: String,
    pub shard_set_id: String,
    pub provider_id: String,
    pub status: AttestationStatus,
    pub signature_commitment: String,
    pub challenge_transcript_root: String,
    pub sample_root: String,
    pub attested_bytes: u64,
    pub attester_weight_bps: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub attestation_root: String,
}

impl PqStorageAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("PQSTORAGEATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateCalldataBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub status: CalldataBatchStatus,
    pub blob_ids: Vec<String>,
    pub contract_commitments: Vec<String>,
    pub private_call_root: String,
    pub encrypted_witness_root: String,
    pub aggregate_nullifier_root: String,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub batch_root: String,
}

impl PrivateCalldataBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("PRIVATECALLDATABATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaCertificate {
    pub certificate_id: String,
    pub batch_id: String,
    pub status: CertificateStatus,
    pub blob_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub provider_ids: Vec<String>,
    pub availability_root: String,
    pub quorum_bps: u64,
    pub certified_bytes: u128,
    pub fee_charged_microunits: u128,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub certificate_root: String,
}

impl DaCertificate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("DACERTIFICATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofCoupon {
    pub coupon_id: String,
    pub certificate_id: String,
    pub kind: CouponKind,
    pub status: CouponStatus,
    pub owner_commitment: String,
    pub face_value_microunits: u128,
    pub fee_discount_bps: u64,
    pub nullifier_hash: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub coupon_root: String,
}

impl ProofCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("PROOFCOUPON", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub sponsor_id: String,
    pub lane_id: String,
    pub status: SponsorReservationStatus,
    pub sponsor_commitment: String,
    pub budget_microunits: u128,
    pub consumed_microunits: u128,
    pub cover_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_root: String,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("SPONSORRESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub coupon_id: String,
    pub reservation_id: String,
    pub status: RebateStatus,
    pub recipient_commitment: String,
    pub amount_microunits: u128,
    pub rebate_bps: u64,
    pub nullifier_hash: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub rebate_root: String,
}

impl RebateReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("REBATERECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub scope: String,
    pub nullifier_hash: String,
    pub owner_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub fence_root: String,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("NULLIFIERFENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithholdingChallenge {
    pub challenge_id: String,
    pub blob_id: String,
    pub provider_id: String,
    pub certificate_id: Option<String>,
    pub fault_kind: WithholdingFaultKind,
    pub status: ChallengeStatus,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond_microunits: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_root: String,
}

impl WithholdingChallenge {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("WITHHOLDINGCHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub slashing_id: String,
    pub challenge_id: String,
    pub provider_id: String,
    pub status: SlashingStatus,
    pub fault_kind: WithholdingFaultKind,
    pub evidence_root: String,
    pub slash_amount_microunits: u128,
    pub reward_commitment: String,
    pub filed_at_height: u64,
    pub slashing_root: String,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("SLASHINGEVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub record_root: String,
    pub event_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        record_root("RUNTIMEEVENT", &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            next_lane_nonce: 0,
            next_provider_nonce: 0,
            next_blob_nonce: 0,
            next_quote_nonce: 0,
            next_reservation_nonce: 0,
            next_shard_set_nonce: 0,
            next_attestation_nonce: 0,
            next_batch_nonce: 0,
            next_certificate_nonce: 0,
            next_coupon_nonce: 0,
            next_sponsor_nonce: 0,
            next_rebate_nonce: 0,
            next_challenge_nonce: 0,
            next_slashing_nonce: 0,
            event_count: 0,
            total_reserved_bytes: 0,
            total_certified_bytes: 0,
            total_fees_charged: 0,
            total_rebates_paid: 0,
            total_slashed: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, MarketLane>,
    pub providers: BTreeMap<String, StorageProvider>,
    pub blob_commitments: BTreeMap<String, EncryptedBlobCommitment>,
    pub quotes: BTreeMap<String, BlobQuote>,
    pub reservations: BTreeMap<String, ShardReservation>,
    pub shard_sets: BTreeMap<String, ErasureShardSet>,
    pub attestations: BTreeMap<String, PqStorageAttestation>,
    pub calldata_batches: BTreeMap<String, PrivateCalldataBatch>,
    pub da_certificates: BTreeMap<String, DaCertificate>,
    pub proof_coupons: BTreeMap<String, ProofCoupon>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub rebate_receipts: BTreeMap<String, RebateReceipt>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub withholding_challenges: BTreeMap<String, WithholdingChallenge>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: Vec<RuntimeEvent>,
    pub used_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default blob da market config")
    }
}

#[rustfmt::skip]
impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            lanes: BTreeMap::new(),
            providers: BTreeMap::new(),
            blob_commitments: BTreeMap::new(),
            quotes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            shard_sets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            calldata_batches: BTreeMap::new(),
            da_certificates: BTreeMap::new(),
            proof_coupons: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            rebate_receipts: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            withholding_challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: Vec::new(),
            used_nullifiers: BTreeSet::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn public_record(&self) -> Value {
        json!({"protocol_version": PROTOCOL_VERSION, "chain_id": CHAIN_ID, "config": self.config, "counters": self.counters, "roots": self.roots})
    }

    pub fn state_root(&self) -> String { self.roots.state_root.clone() }
    pub fn devnet() -> Self { devnet_state() }

    fn push_event(&mut self, height: u64, kind: &str, record_root_value: String) {
        let event_id = event_id(self.counters.event_count + 1, kind, &record_root_value);
        let event_root = record_root("EVENT", &json!({"event_id": event_id, "height": height, "kind": kind, "record_root": record_root_value}));
        self.counters.event_count += 1;
        self.events.push(RuntimeEvent { event_id, height, kind: kind.to_string(), record_root: record_root_value, event_root });
        trim_vec(&mut self.events, self.config.max_events);
    }

    pub fn open_market_lane(&mut self, kind: MarketLaneKind, owner_commitment: impl Into<String>, fee_asset_id: impl Into<String>, max_blob_bytes: u64, target_latency_ms: u64, base_fee_microunits: u64, max_fee_bps: u64, privacy_set_size: u64, height: u64) -> Result<String> {
        ensure(self.lanes.len() < self.config.max_market_lanes, "lane capacity reached")?;
        ensure(max_blob_bytes > 0, "max blob bytes is zero")?;
        ensure(max_fee_bps <= self.config.max_user_fee_bps, "lane fee cap too high")?;
        ensure(privacy_set_size >= self.config.min_privacy_set_size, "lane privacy set too small")?;
        self.counters.next_lane_nonce += 1;
        let owner_commitment = owner_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        ensure(!owner_commitment.is_empty(), "owner commitment is required")?;
        ensure(!fee_asset_id.is_empty(), "fee asset id is required")?;
        let lane_id = lane_id(self.counters.next_lane_nonce, kind, &owner_commitment);
        let mut lane = MarketLane { lane_id: lane_id.clone(), kind, status: LaneStatus::Open, owner_commitment, fee_asset_id, max_blob_bytes, target_latency_ms, base_fee_microunits, max_fee_bps, privacy_set_size, opened_at_height: height, updated_at_height: height, lane_root: String::new() };
        lane.lane_root = lane.root();
        self.lanes.insert(lane_id.clone(), lane.clone());
        self.push_event(height, "market_lane_opened", lane.lane_root);
        self.recompute_roots();
        Ok(lane_id)
    }

    pub fn register_provider(&mut self, class: ProviderClass, operator_commitment: impl Into<String>, pq_attestation_key_commitment: impl Into<String>, stake_commitment: impl Into<String>, available_bytes: u128, max_fee_bps: u64, pq_security_bits: u16, height: u64) -> Result<String> {
        ensure(self.providers.len() < self.config.max_providers, "provider capacity reached")?;
        ensure(available_bytes > 0, "available bytes is zero")?;
        ensure(max_fee_bps <= self.config.max_user_fee_bps, "provider fee too high")?;
        ensure(pq_security_bits >= self.config.min_pq_security_bits, "provider pq security too low")?;
        let operator_commitment = operator_commitment.into();
        let pq_attestation_key_commitment = pq_attestation_key_commitment.into();
        let stake_commitment = stake_commitment.into();
        ensure(!operator_commitment.is_empty(), "operator commitment required")?;
        ensure(!pq_attestation_key_commitment.is_empty(), "pq attestation key required")?;
        self.counters.next_provider_nonce += 1;
        let provider_id = provider_id(self.counters.next_provider_nonce, class, &operator_commitment);
        let mut provider = StorageProvider { provider_id: provider_id.clone(), class, status: ProviderStatus::Active, operator_commitment, pq_attestation_key_commitment, stake_commitment, available_bytes, reserved_bytes: 0, served_bytes: 0, reputation_score: 1_000, max_fee_bps, pq_security_bits, joined_at_height: height, updated_at_height: height, provider_root: String::new() };
        provider.provider_root = provider.root();
        self.providers.insert(provider_id.clone(), provider.clone());
        self.push_event(height, "provider_registered", provider.provider_root);
        self.recompute_roots();
        Ok(provider_id)
    }

    pub fn commit_encrypted_blob(&mut self, lane_id: impl Into<String>, submitter_commitment: impl Into<String>, encoding: BlobEncoding, ciphertext_root: impl Into<String>, ciphertext_bytes: u64, erasure_k: u16, erasure_m: u16, privacy_domain: PrivacyDomain, fee_limit_microunits: u128, nullifier_hash: impl Into<String>, height: u64) -> Result<String> {
        ensure(self.blob_commitments.len() < self.config.max_blob_commitments, "blob capacity reached")?;
        let lane_id = lane_id.into();
        let submitter_commitment = submitter_commitment.into();
        let ciphertext_root = ciphertext_root.into();
        let nullifier_hash = nullifier_hash.into();
        let lane = self.lanes.get(&lane_id).ok_or_else(|| "lane not found".to_string())?;
        ensure(lane.status.accepts_blobs(), "lane does not accept blobs")?;
        ensure(ciphertext_bytes > 0 && ciphertext_bytes <= lane.max_blob_bytes, "blob size outside lane limit")?;
        ensure(erasure_k > 0 && erasure_m >= erasure_k, "invalid erasure parameters")?;
        ensure((erasure_m as usize) <= self.config.max_shards_per_blob, "too many erasure shards")?;
        ensure(!ciphertext_root.is_empty(), "ciphertext root required")?;
        self.check_and_insert_nullifier("blob", &nullifier_hash, height, self.config.blob_ttl_blocks)?;
        self.counters.next_blob_nonce += 1;
        let blob_id = blob_id(self.counters.next_blob_nonce, &lane_id, &ciphertext_root, &nullifier_hash);
        let mut blob = EncryptedBlobCommitment { blob_id: blob_id.clone(), lane_id, submitter_commitment, encoding, status: BlobStatus::Committed, ciphertext_root, ciphertext_bytes, erasure_k, erasure_m, privacy_domain, fee_limit_microunits, nullifier_hash, opened_at_height: height, expires_at_height: height.saturating_add(self.config.blob_ttl_blocks), commitment_root: String::new() };
        blob.commitment_root = blob.root();
        self.blob_commitments.insert(blob_id.clone(), blob.clone());
        self.push_event(height, "encrypted_blob_committed", blob.commitment_root);
        self.recompute_roots();
        Ok(blob_id)
    }

    pub fn post_encrypted_blob_quote(&mut self, blob_id: impl Into<String>, provider_id: impl Into<String>, price_microunits: u128, fee_bps: u64, reserved_bytes: u64, shard_count: u32, height: u64) -> Result<String> {
        ensure(self.quotes.len() < self.config.max_blob_quotes, "quote capacity reached")?;
        let blob_id = blob_id.into();
        let provider_id = provider_id.into();
        let (lane_id, fee_limit) = { let blob = self.blob_commitments.get(&blob_id).ok_or_else(|| "blob not found".to_string())?; ensure(blob.status == BlobStatus::Committed || blob.status == BlobStatus::Quoted, "blob not quoteable")?; ensure(height <= blob.expires_at_height, "blob expired")?; (blob.lane_id.clone(), blob.fee_limit_microunits) };
        let provider = self.providers.get(&provider_id).ok_or_else(|| "provider not found".to_string())?;
        ensure(provider.status.accepts_reservations(), "provider does not accept reservations")?;
        ensure(fee_bps <= provider.max_fee_bps && fee_bps <= self.config.max_user_fee_bps, "quote fee too high")?;
        ensure(price_microunits <= fee_limit, "quote exceeds blob fee limit")?;
        ensure(reserved_bytes > 0, "reserved bytes is zero")?;
        ensure(shard_count > 0, "shard count is zero")?;
        self.counters.next_quote_nonce += 1;
        let quote_id = quote_id(self.counters.next_quote_nonce, &blob_id, &provider_id, price_microunits);
        let mut quote = BlobQuote { quote_id: quote_id.clone(), blob_id: blob_id.clone(), lane_id, provider_id, status: QuoteStatus::Posted, price_microunits, fee_bps, reserved_bytes, shard_count, expires_at_height: height.saturating_add(self.config.quote_ttl_blocks), quote_root: String::new() };
        quote.quote_root = quote.root();
        self.quotes.insert(quote_id.clone(), quote.clone());
        self.blob_commitments.get_mut(&blob_id).unwrap().status = BlobStatus::Quoted;
        refresh_blob_root(self.blob_commitments.get_mut(&blob_id).unwrap());
        self.push_event(height, "encrypted_blob_quote_posted", quote.quote_root);
        self.recompute_roots();
        Ok(quote_id)
    }

    pub fn open_sponsor_reservation(&mut self, lane_id: impl Into<String>, sponsor_commitment: impl Into<String>, budget_microunits: u128, cover_bps: u64, privacy_set_size: u64, height: u64) -> Result<String> {
        ensure(self.sponsor_reservations.len() < self.config.max_sponsor_reservations, "sponsor capacity reached")?;
        let lane_id = lane_id.into();
        let sponsor_commitment = sponsor_commitment.into();
        ensure(self.lanes.contains_key(&lane_id), "lane not found")?;
        ensure(budget_microunits > 0, "sponsor budget is zero")?;
        ensure(cover_bps <= self.config.sponsor_cover_bps, "sponsor cover too high")?;
        ensure(privacy_set_size >= self.config.min_privacy_set_size, "sponsor privacy set too small")?;
        self.counters.next_sponsor_nonce += 1;
        let sponsor_id = sponsor_id(self.counters.next_sponsor_nonce, &lane_id, &sponsor_commitment);
        let mut sponsor = SponsorReservation { sponsor_id: sponsor_id.clone(), lane_id, status: SponsorReservationStatus::Open, sponsor_commitment, budget_microunits, consumed_microunits: 0, cover_bps, privacy_set_size, opened_at_height: height, expires_at_height: height.saturating_add(self.config.rebate_ttl_blocks), sponsor_root: String::new() };
        sponsor.sponsor_root = sponsor.root();
        self.sponsor_reservations.insert(sponsor_id.clone(), sponsor.clone());
        self.push_event(height, "sponsor_reservation_opened", sponsor.sponsor_root);
        self.recompute_roots();
        Ok(sponsor_id)
    }

    pub fn reserve_shard_capacity(&mut self, quote_id: impl Into<String>, sponsor_id: Option<String>, rebate_bps: u64, height: u64) -> Result<String> {
        ensure(self.reservations.len() < self.config.max_reservations, "reservation capacity reached")?;
        let quote_id = quote_id.into();
        let quote_snapshot = self.quotes.get(&quote_id).cloned().ok_or_else(|| "quote not found".to_string())?;
        ensure(quote_snapshot.status.selectable(), "quote not selectable")?;
        ensure(height <= quote_snapshot.expires_at_height, "quote expired")?;
        ensure(rebate_bps <= self.config.target_rebate_bps, "rebate above target")?;
        { let provider = self.providers.get(&quote_snapshot.provider_id).ok_or_else(|| "provider not found".to_string())?; ensure(provider.available_bytes.saturating_sub(provider.reserved_bytes) >= quote_snapshot.reserved_bytes as u128, "provider capacity unavailable")?; }
        if let Some(id) = sponsor_id.as_ref() { let sponsor = self.sponsor_reservations.get(id).ok_or_else(|| "sponsor not found".to_string())?; ensure(matches!(sponsor.status, SponsorReservationStatus::Open | SponsorReservationStatus::PartiallyConsumed), "sponsor not open")?; ensure(sponsor.lane_id == quote_snapshot.lane_id, "sponsor lane mismatch")?; ensure(sponsor.budget_microunits.saturating_sub(sponsor.consumed_microunits) >= quote_snapshot.price_microunits, "sponsor budget exhausted")?; }
        self.counters.next_reservation_nonce += 1;
        let reservation_id = reservation_id(self.counters.next_reservation_nonce, &quote_id, &quote_snapshot.provider_id);
        let mut reservation = ShardReservation { reservation_id: reservation_id.clone(), quote_id: quote_id.clone(), blob_id: quote_snapshot.blob_id.clone(), provider_id: quote_snapshot.provider_id.clone(), sponsor_id: sponsor_id.clone(), status: ReservationStatus::Held, reserved_bytes: quote_snapshot.reserved_bytes, locked_fee_microunits: quote_snapshot.price_microunits, rebate_bps, opened_at_height: height, expires_at_height: height.saturating_add(self.config.reservation_ttl_blocks), reservation_root: String::new() };
        reservation.reservation_root = reservation.root();
        self.reservations.insert(reservation_id.clone(), reservation.clone());
        self.quotes.get_mut(&quote_id).unwrap().status = QuoteStatus::Reserved;
        refresh_quote_root(self.quotes.get_mut(&quote_id).unwrap());
        self.providers.get_mut(&quote_snapshot.provider_id).unwrap().reserved_bytes += quote_snapshot.reserved_bytes as u128;
        refresh_provider_root(self.providers.get_mut(&quote_snapshot.provider_id).unwrap());
        if let Some(id) = sponsor_id { let s = self.sponsor_reservations.get_mut(&id).unwrap(); s.consumed_microunits += quote_snapshot.price_microunits; s.status = if s.consumed_microunits >= s.budget_microunits { SponsorReservationStatus::Consumed } else { SponsorReservationStatus::PartiallyConsumed }; refresh_sponsor_root(s); }
        self.blob_commitments.get_mut(&quote_snapshot.blob_id).unwrap().status = BlobStatus::Reserved;
        refresh_blob_root(self.blob_commitments.get_mut(&quote_snapshot.blob_id).unwrap());
        self.counters.total_reserved_bytes += quote_snapshot.reserved_bytes as u128;
        self.push_event(height, "shard_capacity_reserved", reservation.reservation_root);
        self.recompute_roots();
        Ok(reservation_id)
    }

    pub fn publish_erasure_shards(&mut self, reservation_id: impl Into<String>, shard_roots: Vec<String>, parity_roots: Vec<String>, availability_root: impl Into<String>, height: u64) -> Result<String> {
        ensure(self.shard_sets.len() < self.config.max_shard_sets, "shard set capacity reached")?;
        let reservation_id = reservation_id.into();
        let availability_root = availability_root.into();
        let reservation = self.reservations.get(&reservation_id).cloned().ok_or_else(|| "reservation not found".to_string())?;
        ensure(reservation.status == ReservationStatus::Held, "reservation not held")?;
        ensure(height <= reservation.expires_at_height, "reservation expired")?;
        ensure(!shard_roots.is_empty(), "shard roots required")?;
        ensure(shard_roots.len() + parity_roots.len() <= self.config.max_shards_per_blob, "too many shards")?;
        ensure(!availability_root.is_empty(), "availability root required")?;
        self.counters.next_shard_set_nonce += 1;
        let shard_set_id = shard_set_id(self.counters.next_shard_set_nonce, &reservation.blob_id, &availability_root);
        let mut shard_set = ErasureShardSet { shard_set_id: shard_set_id.clone(), blob_id: reservation.blob_id.clone(), reservation_id: reservation_id.clone(), provider_id: reservation.provider_id.clone(), status: ShardStatus::Stored, required_shards: shard_roots.len() as u16, total_shards: (shard_roots.len() + parity_roots.len()) as u16, shard_roots, parity_roots, availability_root, published_at_height: height, shard_set_root: String::new() };
        shard_set.shard_set_root = shard_set.root();
        self.shard_sets.insert(shard_set_id.clone(), shard_set.clone());
        self.reservations.get_mut(&reservation_id).unwrap().status = ReservationStatus::BatchBound;
        refresh_reservation_root(self.reservations.get_mut(&reservation_id).unwrap());
        self.blob_commitments.get_mut(&reservation.blob_id).unwrap().status = BlobStatus::Sharded;
        refresh_blob_root(self.blob_commitments.get_mut(&reservation.blob_id).unwrap());
        self.push_event(height, "erasure_shards_published", shard_set.shard_set_root);
        self.recompute_roots();
        Ok(shard_set_id)
    }

    pub fn submit_pq_storage_attestation(&mut self, shard_set_id: impl Into<String>, signature_commitment: impl Into<String>, challenge_transcript_root: impl Into<String>, sample_root: impl Into<String>, attested_bytes: u64, attester_weight_bps: u64, pq_security_bits: u16, height: u64) -> Result<String> {
        ensure(self.attestations.len() < self.config.max_storage_attestations, "attestation capacity reached")?;
        let shard_set_id = shard_set_id.into();
        let signature_commitment = signature_commitment.into();
        let challenge_transcript_root = challenge_transcript_root.into();
        let sample_root = sample_root.into();
        let shard_set = self.shard_sets.get(&shard_set_id).cloned().ok_or_else(|| "shard set not found".to_string())?;
        ensure(shard_set.status == ShardStatus::Stored || shard_set.status == ShardStatus::Attested, "shard set not attestable")?;
        ensure(attester_weight_bps > 0 && attester_weight_bps <= MAX_BPS, "bad attester weight")?;
        ensure(pq_security_bits >= self.config.min_pq_security_bits, "attestation pq security too low")?;
        ensure(!signature_commitment.is_empty(), "signature commitment required")?;
        ensure(!challenge_transcript_root.is_empty(), "challenge transcript root required")?;
        ensure(!sample_root.is_empty(), "sample root required")?;
        self.counters.next_attestation_nonce += 1;
        let attestation_id = attestation_id(self.counters.next_attestation_nonce, &shard_set_id, &signature_commitment);
        let status = if attester_weight_bps >= self.config.quorum_bps { AttestationStatus::QuorumMet } else { AttestationStatus::Proposed };
        let mut attestation = PqStorageAttestation { attestation_id: attestation_id.clone(), shard_set_id: shard_set_id.clone(), provider_id: shard_set.provider_id.clone(), status, signature_commitment, challenge_transcript_root, sample_root, attested_bytes, attester_weight_bps, pq_security_bits, attested_at_height: height, attestation_root: String::new() };
        attestation.attestation_root = attestation.root();
        self.attestations.insert(attestation_id.clone(), attestation.clone());
        self.shard_sets.get_mut(&shard_set_id).unwrap().status = ShardStatus::Attested;
        refresh_shard_root(self.shard_sets.get_mut(&shard_set_id).unwrap());
        self.blob_commitments.get_mut(&shard_set.blob_id).unwrap().status = BlobStatus::Attested;
        refresh_blob_root(self.blob_commitments.get_mut(&shard_set.blob_id).unwrap());
        self.push_event(height, "pq_storage_attestation_submitted", attestation.attestation_root);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn attach_calldata_batch(&mut self, lane_id: impl Into<String>, blob_ids: Vec<String>, contract_commitments: Vec<String>, private_call_root: impl Into<String>, encrypted_witness_root: impl Into<String>, aggregate_nullifier_root: impl Into<String>, max_fee_bps: u64, height: u64) -> Result<String> {
        ensure(self.calldata_batches.len() < self.config.max_calldata_batches, "batch capacity reached")?;
        let lane_id = lane_id.into();
        ensure(self.lanes.contains_key(&lane_id), "lane not found")?;
        ensure(!blob_ids.is_empty(), "batch requires blobs")?;
        ensure(blob_ids.len() <= self.config.max_batch_blobs, "too many batch blobs")?;
        ensure(max_fee_bps <= self.config.max_user_fee_bps, "batch fee too high")?;
        for blob_id in &blob_ids { let blob = self.blob_commitments.get(blob_id).ok_or_else(|| format!("blob {blob_id} not found"))?; ensure(blob.lane_id == lane_id, "batch blob lane mismatch")?; ensure(matches!(blob.status, BlobStatus::Attested | BlobStatus::Sharded | BlobStatus::Reserved), "blob not ready for batch")?; }
        self.counters.next_batch_nonce += 1;
        let private_call_root = private_call_root.into();
        let encrypted_witness_root = encrypted_witness_root.into();
        let aggregate_nullifier_root = aggregate_nullifier_root.into();
        ensure(!private_call_root.is_empty(), "private call root required")?;
        ensure(!encrypted_witness_root.is_empty(), "encrypted witness root required")?;
        ensure(!aggregate_nullifier_root.is_empty(), "aggregate nullifier root required")?;
        let batch_id = batch_id(self.counters.next_batch_nonce, &lane_id, &private_call_root);
        let mut batch = PrivateCalldataBatch { batch_id: batch_id.clone(), lane_id, status: CalldataBatchStatus::DaBound, blob_ids: blob_ids.clone(), contract_commitments, private_call_root, encrypted_witness_root, aggregate_nullifier_root, max_fee_bps, opened_at_height: height, expires_at_height: height.saturating_add(self.config.calldata_batch_ttl_blocks), batch_root: String::new() };
        batch.batch_root = batch.root();
        for blob_id in &blob_ids { self.blob_commitments.get_mut(blob_id).unwrap().status = BlobStatus::Batched; refresh_blob_root(self.blob_commitments.get_mut(blob_id).unwrap()); }
        self.calldata_batches.insert(batch_id.clone(), batch.clone());
        self.push_event(height, "private_calldata_batch_attached", batch.batch_root);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn publish_da_certificate(&mut self, batch_id: impl Into<String>, attestation_ids: Vec<String>, availability_root: impl Into<String>, quorum_bps: u64, fee_charged_microunits: u128, height: u64) -> Result<String> {
        ensure(self.da_certificates.len() < self.config.max_da_certificates, "certificate capacity reached")?;
        let batch_id = batch_id.into();
        let availability_root = availability_root.into();
        let batch = self.calldata_batches.get(&batch_id).cloned().ok_or_else(|| "batch not found".to_string())?;
        ensure(batch.status == CalldataBatchStatus::DaBound || batch.status == CalldataBatchStatus::Sealed, "batch not certificate ready")?;
        ensure(height <= batch.expires_at_height, "batch expired")?;
        ensure(quorum_bps >= self.config.quorum_bps, "certificate quorum too low")?;
        ensure(!attestation_ids.is_empty(), "certificate requires attestations")?;
        ensure(!availability_root.is_empty(), "availability root required")?;
        let mut provider_ids = BTreeSet::new();
        let mut certified_bytes = 0_u128;
        for attestation_id in &attestation_ids { let att = self.attestations.get(attestation_id).ok_or_else(|| format!("attestation {attestation_id} not found"))?; ensure(matches!(att.status, AttestationStatus::QuorumMet | AttestationStatus::Proposed), "attestation not usable")?; provider_ids.insert(att.provider_id.clone()); certified_bytes += att.attested_bytes as u128; }
        self.counters.next_certificate_nonce += 1;
        let certificate_id = certificate_id(self.counters.next_certificate_nonce, &batch_id, &availability_root);
        let mut cert = DaCertificate { certificate_id: certificate_id.clone(), batch_id: batch_id.clone(), status: CertificateStatus::Published, blob_ids: batch.blob_ids.clone(), attestation_ids: attestation_ids.clone(), provider_ids: provider_ids.into_iter().collect(), availability_root, quorum_bps, certified_bytes, fee_charged_microunits, published_at_height: height, expires_at_height: height.saturating_add(self.config.certificate_ttl_blocks), certificate_root: String::new() };
        cert.certificate_root = cert.root();
        for blob_id in &cert.blob_ids { self.blob_commitments.get_mut(blob_id).unwrap().status = BlobStatus::Certified; refresh_blob_root(self.blob_commitments.get_mut(blob_id).unwrap()); }
        for attestation_id in &attestation_ids { self.attestations.get_mut(attestation_id).unwrap().status = AttestationStatus::CertificateBound; refresh_attestation_root(self.attestations.get_mut(attestation_id).unwrap()); }
        self.calldata_batches.get_mut(&batch_id).unwrap().status = CalldataBatchStatus::Certified;
        refresh_batch_root(self.calldata_batches.get_mut(&batch_id).unwrap());
        self.counters.total_certified_bytes += certified_bytes;
        self.counters.total_fees_charged += fee_charged_microunits;
        self.da_certificates.insert(certificate_id.clone(), cert.clone());
        self.push_event(height, "da_certificate_published", cert.certificate_root);
        self.recompute_roots();
        Ok(certificate_id)
    }

    pub fn issue_proof_coupon(&mut self, certificate_id: impl Into<String>, kind: CouponKind, owner_commitment: impl Into<String>, face_value_microunits: u128, fee_discount_bps: u64, nullifier_hash: impl Into<String>, height: u64) -> Result<String> {
        ensure(self.proof_coupons.len() < self.config.max_proof_coupons, "coupon capacity reached")?;
        let certificate_id = certificate_id.into();
        let owner_commitment = owner_commitment.into();
        let nullifier_hash = nullifier_hash.into();
        let cert = self.da_certificates.get(&certificate_id).ok_or_else(|| "certificate not found".to_string())?;
        ensure(cert.status == CertificateStatus::Published || cert.status == CertificateStatus::CouponReady, "certificate not coupon ready")?;
        ensure(height <= cert.expires_at_height, "certificate expired")?;
        ensure(fee_discount_bps <= self.config.max_user_fee_bps, "coupon discount too high")?;
        self.check_and_insert_nullifier("coupon", &nullifier_hash, height, self.config.coupon_ttl_blocks)?;
        self.counters.next_coupon_nonce += 1;
        let coupon_id = coupon_id(self.counters.next_coupon_nonce, &certificate_id, &nullifier_hash);
        let mut coupon = ProofCoupon { coupon_id: coupon_id.clone(), certificate_id: certificate_id.clone(), kind, status: CouponStatus::Issued, owner_commitment, face_value_microunits, fee_discount_bps, nullifier_hash, issued_at_height: height, expires_at_height: height.saturating_add(self.config.coupon_ttl_blocks), coupon_root: String::new() };
        coupon.coupon_root = coupon.root();
        self.proof_coupons.insert(coupon_id.clone(), coupon.clone());
        self.da_certificates.get_mut(&certificate_id).unwrap().status = CertificateStatus::CouponReady;
        refresh_certificate_root(self.da_certificates.get_mut(&certificate_id).unwrap());
        self.push_event(height, "proof_coupon_issued", coupon.coupon_root);
        self.recompute_roots();
        Ok(coupon_id)
    }

    pub fn settle_coupon_rebate(&mut self, coupon_id: impl Into<String>, reservation_id: impl Into<String>, recipient_commitment: impl Into<String>, nullifier_hash: impl Into<String>, height: u64) -> Result<String> {
        ensure(self.rebate_receipts.len() < self.config.max_rebate_receipts, "rebate capacity reached")?;
        let coupon_id = coupon_id.into();
        let reservation_id = reservation_id.into();
        let recipient_commitment = recipient_commitment.into();
        let nullifier_hash = nullifier_hash.into();
        let coupon = self.proof_coupons.get(&coupon_id).cloned().ok_or_else(|| "coupon not found".to_string())?;
        let reservation = self.reservations.get(&reservation_id).cloned().ok_or_else(|| "reservation not found".to_string())?;
        ensure(coupon.status == CouponStatus::Issued || coupon.status == CouponStatus::Redeemed, "coupon not settleable")?;
        ensure(reservation.status.locked(), "reservation not locked")?;
        ensure(height <= coupon.expires_at_height, "coupon expired")?;
        self.check_and_insert_nullifier("rebate", &nullifier_hash, height, self.config.rebate_ttl_blocks)?;
        let amount = coupon.face_value_microunits.saturating_mul(reservation.rebate_bps as u128) / MAX_BPS as u128;
        self.counters.next_rebate_nonce += 1;
        let rebate_id = rebate_id(self.counters.next_rebate_nonce, &coupon_id, &reservation_id);
        let mut receipt = RebateReceipt { rebate_id: rebate_id.clone(), coupon_id: coupon_id.clone(), reservation_id: reservation_id.clone(), status: RebateStatus::Pending, recipient_commitment, amount_microunits: amount, rebate_bps: reservation.rebate_bps, nullifier_hash, issued_at_height: height, expires_at_height: height.saturating_add(self.config.rebate_ttl_blocks), rebate_root: String::new() };
        receipt.rebate_root = receipt.root();
        self.rebate_receipts.insert(rebate_id.clone(), receipt.clone());
        self.proof_coupons.get_mut(&coupon_id).unwrap().status = CouponStatus::Rebated;
        refresh_coupon_root(self.proof_coupons.get_mut(&coupon_id).unwrap());
        self.reservations.get_mut(&reservation_id).unwrap().status = ReservationStatus::Settled;
        refresh_reservation_root(self.reservations.get_mut(&reservation_id).unwrap());
        self.counters.total_rebates_paid += amount;
        self.push_event(height, "coupon_rebate_settled", receipt.rebate_root);
        self.recompute_roots();
        Ok(rebate_id)
    }

    pub fn challenge_withholding(&mut self, blob_id: impl Into<String>, provider_id: impl Into<String>, certificate_id: Option<String>, fault_kind: WithholdingFaultKind, challenger_commitment: impl Into<String>, evidence_root: impl Into<String>, bond_microunits: u128, height: u64) -> Result<String> {
        ensure(self.withholding_challenges.len() < self.config.max_withholding_challenges, "challenge capacity reached")?;
        let blob_id = blob_id.into();
        let provider_id = provider_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        ensure(self.blob_commitments.contains_key(&blob_id), "blob not found")?;
        ensure(self.providers.contains_key(&provider_id), "provider not found")?;
        ensure(!evidence_root.is_empty(), "evidence root required")?;
        ensure(bond_microunits > 0, "challenge bond is zero")?;
        if let Some(id) = certificate_id.as_ref() { ensure(self.da_certificates.contains_key(id), "certificate not found")?; }
        self.counters.next_challenge_nonce += 1;
        let challenge_id = challenge_id(self.counters.next_challenge_nonce, &blob_id, &provider_id, &evidence_root);
        let mut challenge = WithholdingChallenge { challenge_id: challenge_id.clone(), blob_id: blob_id.clone(), provider_id: provider_id.clone(), certificate_id, fault_kind, status: ChallengeStatus::Opened, challenger_commitment, evidence_root, bond_microunits, opened_at_height: height, expires_at_height: height.saturating_add(self.config.challenge_window_blocks), challenge_root: String::new() };
        challenge.challenge_root = challenge.root();
        self.withholding_challenges.insert(challenge_id.clone(), challenge.clone());
        self.blob_commitments.get_mut(&blob_id).unwrap().status = BlobStatus::Challenged;
        refresh_blob_root(self.blob_commitments.get_mut(&blob_id).unwrap());
        self.push_event(height, "withholding_challenge_opened", challenge.challenge_root);
        self.recompute_roots();
        Ok(challenge_id)
    }

    pub fn slash_provider(&mut self, challenge_id: impl Into<String>, evidence_root: impl Into<String>, slash_amount_microunits: u128, reward_commitment: impl Into<String>, height: u64) -> Result<String> {
        ensure(self.slashing_evidence.len() < self.config.max_slashing_evidence, "slashing capacity reached")?;
        let challenge_id = challenge_id.into();
        let evidence_root = evidence_root.into();
        let reward_commitment = reward_commitment.into();
        let challenge = self.withholding_challenges.get(&challenge_id).cloned().ok_or_else(|| "challenge not found".to_string())?;
        ensure(matches!(challenge.status, ChallengeStatus::Opened | ChallengeStatus::EvidenceSubmitted | ChallengeStatus::Upheld), "challenge not slashable")?;
        ensure(height <= challenge.expires_at_height || self.config.allow_devnet_shortcuts, "challenge window closed")?;
        ensure(slash_amount_microunits > 0, "slash amount is zero")?;
        ensure(!evidence_root.is_empty(), "evidence root required")?;
        self.counters.next_slashing_nonce += 1;
        let slashing_id = slashing_id(self.counters.next_slashing_nonce, &challenge_id, &challenge.provider_id);
        let mut evidence = SlashingEvidence { slashing_id: slashing_id.clone(), challenge_id: challenge_id.clone(), provider_id: challenge.provider_id.clone(), status: SlashingStatus::Executed, fault_kind: challenge.fault_kind, evidence_root, slash_amount_microunits, reward_commitment, filed_at_height: height, slashing_root: String::new() };
        evidence.slashing_root = evidence.root();
        self.slashing_evidence.insert(slashing_id.clone(), evidence.clone());
        self.withholding_challenges.get_mut(&challenge_id).unwrap().status = ChallengeStatus::Slashed;
        refresh_challenge_root(self.withholding_challenges.get_mut(&challenge_id).unwrap());
        let provider = self.providers.get_mut(&challenge.provider_id).unwrap();
        provider.status = ProviderStatus::Slashed;
        provider.reputation_score = provider.reputation_score.saturating_sub(500);
        refresh_provider_root(provider);
        if let Some(blob) = self.blob_commitments.get_mut(&challenge.blob_id) { blob.status = BlobStatus::Slashed; refresh_blob_root(blob); }
        self.counters.total_slashed += slash_amount_microunits;
        self.push_event(height, "provider_slashed", evidence.slashing_root);
        self.recompute_roots();
        Ok(slashing_id)
    }

    fn check_and_insert_nullifier(&mut self, scope: &str, nullifier_hash: &str, height: u64, ttl: u64) -> Result<()> {
        ensure(!nullifier_hash.is_empty(), "nullifier hash required")?;
        ensure(!self.used_nullifiers.contains(nullifier_hash), "nullifier already used")?;
        ensure(self.nullifier_fences.len() < self.config.max_nullifier_fences, "nullifier fence capacity reached")?;
        let fence_id = fence_id(scope, nullifier_hash);
        let mut fence = NullifierFence { fence_id: fence_id.clone(), scope: scope.to_string(), nullifier_hash: nullifier_hash.to_string(), owner_commitment: scope.to_string(), opened_at_height: height, expires_at_height: height.saturating_add(ttl), fence_root: String::new() };
        fence.fence_root = fence.root();
        self.used_nullifiers.insert(nullifier_hash.to_string());
        self.nullifier_fences.insert(fence_id, fence);
        Ok(())
    }

    pub fn recompute_roots(&mut self) { self.roots = Roots::from_state(self); }
}

impl Roots {
    pub fn empty() -> Self {
        let empty = merkle_root("EMPTY", &[]);
        Self {
            config_root: empty.clone(),
            lane_root: empty.clone(),
            provider_root: empty.clone(),
            quote_root: empty.clone(),
            reservation_root: empty.clone(),
            blob_root: empty.clone(),
            shard_root: empty.clone(),
            attestation_root: empty.clone(),
            calldata_batch_root: empty.clone(),
            certificate_root: empty.clone(),
            coupon_root: empty.clone(),
            sponsor_root: empty.clone(),
            rebate_root: empty.clone(),
            nullifier_fence_root: empty.clone(),
            challenge_root: empty.clone(),
            slashing_root: empty.clone(),
            event_root: empty.clone(),
            state_root: empty,
        }
    }
    pub fn from_state(state: &State) -> Self {
        let config_root = state.config.root();
        let lane_root = collection_root(
            "LANE_ROOT",
            state.lanes.values().map(|v| v.public_record()).collect(),
        );
        let provider_root = collection_root(
            "PROVIDER_ROOT",
            state
                .providers
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let quote_root = collection_root(
            "QUOTE_ROOT",
            state.quotes.values().map(|v| v.public_record()).collect(),
        );
        let reservation_root = collection_root(
            "RESERVATION_ROOT",
            state
                .reservations
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let blob_root = collection_root(
            "BLOB_ROOT",
            state
                .blob_commitments
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let shard_root = collection_root(
            "SHARD_ROOT",
            state
                .shard_sets
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let attestation_root = collection_root(
            "ATTESTATION_ROOT",
            state
                .attestations
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let calldata_batch_root = collection_root(
            "CALLDATA_BATCH_ROOT",
            state
                .calldata_batches
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let certificate_root = collection_root(
            "CERTIFICATE_ROOT",
            state
                .da_certificates
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let coupon_root = collection_root(
            "COUPON_ROOT",
            state
                .proof_coupons
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let sponsor_root = collection_root(
            "SPONSOR_ROOT",
            state
                .sponsor_reservations
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let rebate_root = collection_root(
            "REBATE_ROOT",
            state
                .rebate_receipts
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let nullifier_fence_root = collection_root(
            "NULLIFIER_FENCE_ROOT",
            state
                .nullifier_fences
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let challenge_root = collection_root(
            "CHALLENGE_ROOT",
            state
                .withholding_challenges
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let slashing_root = collection_root(
            "SLASHING_ROOT",
            state
                .slashing_evidence
                .values()
                .map(|v| v.public_record())
                .collect(),
        );
        let event_root = collection_root(
            "EVENTS",
            state.events.iter().map(|v| v.public_record()).collect(),
        );
        let state_root = record_root(
            "STATE",
            &json!({"protocol_version": PROTOCOL_VERSION, "chain_id": CHAIN_ID, "config_root": config_root, "lane_root": lane_root, "provider_root": provider_root, "quote_root": quote_root, "reservation_root": reservation_root, "blob_root": blob_root, "shard_root": shard_root, "attestation_root": attestation_root, "calldata_batch_root": calldata_batch_root, "certificate_root": certificate_root, "coupon_root": coupon_root, "sponsor_root": sponsor_root, "rebate_root": rebate_root, "nullifier_fence_root": nullifier_fence_root, "challenge_root": challenge_root, "slashing_root": slashing_root, "event_root": event_root, "counters": state.counters}),
        );
        Self {
            config_root,
            lane_root,
            provider_root,
            quote_root,
            reservation_root,
            blob_root,
            shard_root,
            attestation_root,
            calldata_batch_root,
            certificate_root,
            coupon_root,
            sponsor_root,
            rebate_root,
            nullifier_fence_root,
            challenge_root,
            slashing_root,
            event_root,
            state_root,
        }
    }
}

fn refresh_blob_root(value: &mut EncryptedBlobCommitment) {
    value.commitment_root = value.root();
}
fn refresh_quote_root(value: &mut BlobQuote) {
    value.quote_root = value.root();
}
fn refresh_provider_root(value: &mut StorageProvider) {
    value.provider_root = value.root();
}
fn refresh_reservation_root(value: &mut ShardReservation) {
    value.reservation_root = value.root();
}
fn refresh_shard_root(value: &mut ErasureShardSet) {
    value.shard_set_root = value.root();
}
fn refresh_attestation_root(value: &mut PqStorageAttestation) {
    value.attestation_root = value.root();
}
fn refresh_batch_root(value: &mut PrivateCalldataBatch) {
    value.batch_root = value.root();
}
fn refresh_certificate_root(value: &mut DaCertificate) {
    value.certificate_root = value.root();
}
fn refresh_coupon_root(value: &mut ProofCoupon) {
    value.coupon_root = value.root();
}
fn refresh_sponsor_root(value: &mut SponsorReservation) {
    value.sponsor_root = value.root();
}
fn refresh_challenge_root(value: &mut WithholdingChallenge) {
    value.challenge_root = value.root();
}

pub fn devnet_state() -> State {
    let mut config = Config::default();
    config.allow_devnet_shortcuts = true;
    let mut state = State::new(config).expect("devnet state");
    let lane = state
        .open_market_lane(
            MarketLaneKind::PrivateContractCalldata,
            "devnet-lane-owner",
            DEFAULT_FEE_ASSET_ID,
            1_048_576,
            600,
            1,
            DEFAULT_MAX_USER_FEE_BPS,
            DEFAULT_BATCH_PRIVACY_SET_SIZE,
            DEVNET_HEIGHT,
        )
        .expect("devnet lane");
    let provider = state
        .register_provider(
            ProviderClass::FastCache,
            "devnet-provider",
            "devnet-pq-key",
            "devnet-stake",
            1_099_511_627_776,
            DEFAULT_MAX_USER_FEE_BPS,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEVNET_HEIGHT,
        )
        .expect("devnet provider");
    let blob = state
        .commit_encrypted_blob(
            lane.clone(),
            "devnet-submitter",
            BlobEncoding::ReedSolomonCiphertext,
            "devnet-ciphertext-root",
            65_536,
            32,
            64,
            PrivacyDomain::Defi,
            10_000,
            "devnet-blob-nullifier",
            DEVNET_HEIGHT,
        )
        .expect("devnet blob");
    let quote = state
        .post_encrypted_blob_quote(
            blob.clone(),
            provider.clone(),
            900,
            4,
            65_536,
            64,
            DEVNET_HEIGHT,
        )
        .expect("devnet quote");
    let sponsor = state
        .open_sponsor_reservation(
            lane.clone(),
            "devnet-sponsor",
            1_000_000,
            DEFAULT_SPONSOR_COVER_BPS,
            DEFAULT_BATCH_PRIVACY_SET_SIZE,
            DEVNET_HEIGHT,
        )
        .expect("devnet sponsor");
    let reservation = state
        .reserve_shard_capacity(
            quote,
            Some(sponsor),
            DEFAULT_TARGET_REBATE_BPS,
            DEVNET_HEIGHT,
        )
        .expect("devnet reservation");
    let shards = state
        .publish_erasure_shards(
            reservation.clone(),
            vec!["devnet-shard-a".to_string(), "devnet-shard-b".to_string()],
            vec!["devnet-parity-a".to_string()],
            "devnet-availability-root",
            DEVNET_HEIGHT,
        )
        .expect("devnet shards");
    let attestation = state
        .submit_pq_storage_attestation(
            shards,
            "devnet-pq-signature",
            "devnet-transcript",
            "devnet-sample",
            65_536,
            DEFAULT_STRONG_QUORUM_BPS,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEVNET_HEIGHT,
        )
        .expect("devnet attestation");
    let batch = state
        .attach_calldata_batch(
            lane,
            vec![blob],
            vec!["devnet-contract".to_string()],
            "devnet-private-call-root",
            "devnet-witness-root",
            "devnet-nullifier-root",
            DEFAULT_MAX_USER_FEE_BPS,
            DEVNET_HEIGHT,
        )
        .expect("devnet batch");
    let cert = state
        .publish_da_certificate(
            batch,
            vec![attestation],
            "devnet-certificate-availability",
            DEFAULT_STRONG_QUORUM_BPS,
            900,
            DEVNET_HEIGHT,
        )
        .expect("devnet certificate");
    let coupon = state
        .issue_proof_coupon(
            cert,
            CouponKind::DaAvailability,
            "devnet-coupon-owner",
            900,
            DEFAULT_TARGET_REBATE_BPS,
            "devnet-coupon-nullifier",
            DEVNET_HEIGHT,
        )
        .expect("devnet coupon");
    let _rebate = state
        .settle_coupon_rebate(
            coupon,
            reservation,
            "devnet-rebate-recipient",
            "devnet-rebate-nullifier",
            DEVNET_HEIGHT,
        )
        .expect("devnet rebate");
    state
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}
pub fn lane_id(nonce: u64, kind: MarketLaneKind, owner_commitment: &str) -> String {
    deterministic_id(
        "BLOB_DA_LANE_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner_commitment),
        ],
    )
}
pub fn provider_id(nonce: u64, class: ProviderClass, operator_commitment: &str) -> String {
    deterministic_id(
        "BLOB_DA_PROVIDER_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(class.as_str()),
            HashPart::Str(operator_commitment),
        ],
    )
}
pub fn blob_id(nonce: u64, lane_id: &str, ciphertext_root: &str, nullifier_hash: &str) -> String {
    deterministic_id(
        "BLOB_DA_BLOB_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(lane_id),
            HashPart::Str(ciphertext_root),
            HashPart::Str(nullifier_hash),
        ],
    )
}
pub fn quote_id(nonce: u64, blob_id: &str, provider_id: &str, price: u128) -> String {
    deterministic_id(
        "BLOB_DA_QUOTE_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(blob_id),
            HashPart::Str(provider_id),
            HashPart::Int(price as i128),
        ],
    )
}
pub fn reservation_id(nonce: u64, quote_id: &str, provider_id: &str) -> String {
    deterministic_id(
        "BLOB_DA_RESERVATION_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(quote_id),
            HashPart::Str(provider_id),
        ],
    )
}
pub fn shard_set_id(nonce: u64, blob_id: &str, availability_root: &str) -> String {
    deterministic_id(
        "BLOB_DA_SHARD_SET_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(blob_id),
            HashPart::Str(availability_root),
        ],
    )
}
pub fn attestation_id(nonce: u64, shard_set_id: &str, signature_commitment: &str) -> String {
    deterministic_id(
        "BLOB_DA_ATTESTATION_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(shard_set_id),
            HashPart::Str(signature_commitment),
        ],
    )
}
pub fn batch_id(nonce: u64, lane_id: &str, private_call_root: &str) -> String {
    deterministic_id(
        "BLOB_DA_BATCH_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(lane_id),
            HashPart::Str(private_call_root),
        ],
    )
}
pub fn certificate_id(nonce: u64, batch_id: &str, availability_root: &str) -> String {
    deterministic_id(
        "BLOB_DA_CERTIFICATE_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(batch_id),
            HashPart::Str(availability_root),
        ],
    )
}
pub fn coupon_id(nonce: u64, certificate_id: &str, nullifier_hash: &str) -> String {
    deterministic_id(
        "BLOB_DA_COUPON_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(certificate_id),
            HashPart::Str(nullifier_hash),
        ],
    )
}
pub fn sponsor_id(nonce: u64, lane_id: &str, sponsor_commitment: &str) -> String {
    deterministic_id(
        "BLOB_DA_SPONSOR_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_commitment),
        ],
    )
}
pub fn rebate_id(nonce: u64, coupon_id: &str, reservation_id: &str) -> String {
    deterministic_id(
        "BLOB_DA_REBATE_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(coupon_id),
            HashPart::Str(reservation_id),
        ],
    )
}
pub fn challenge_id(nonce: u64, blob_id: &str, provider_id: &str, evidence_root: &str) -> String {
    deterministic_id(
        "BLOB_DA_CHALLENGE_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(blob_id),
            HashPart::Str(provider_id),
            HashPart::Str(evidence_root),
        ],
    )
}
pub fn slashing_id(nonce: u64, challenge_id: &str, provider_id: &str) -> String {
    deterministic_id(
        "BLOB_DA_SLASHING_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(challenge_id),
            HashPart::Str(provider_id),
        ],
    )
}
pub fn fence_id(scope: &str, nullifier_hash: &str) -> String {
    deterministic_id(
        "BLOB_DA_NULLIFIER_FENCE_ID",
        &[HashPart::Str(scope), HashPart::Str(nullifier_hash)],
    )
}
pub fn event_id(nonce: u64, kind: &str, record_root: &str) -> String {
    deterministic_id(
        "BLOB_DA_EVENT_ID",
        &[
            HashPart::U64(nonce),
            HashPart::Str(kind),
            HashPart::Str(record_root),
        ],
    )
}
fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn trim_vec<T>(values: &mut Vec<T>, max_len: usize) {
    if values.len() > max_len {
        let excess = values.len() - max_len;
        values.drain(0..excess);
    }
}
