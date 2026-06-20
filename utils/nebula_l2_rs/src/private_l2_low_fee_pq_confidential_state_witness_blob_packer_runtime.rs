use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialStateWitnessBlobPackerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_STATE_WITNESS_BLOB_PACKER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-state-witness-blob-packer-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_STATE_WITNESS_BLOB_PACKER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const WITNESS_CHUNK_SCHEME: &str = "pq-confidential-encrypted-state-witness-chunk-v1";
pub const BLOB_PACKING_SCHEME: &str = "low-fee-state-witness-blob-packing-lanes-v1";
pub const DICTIONARY_SCHEME: &str = "recursive-proof-state-diff-dictionary-root-v1";
pub const DA_VOUCHER_SCHEME: &str = "confidential-da-voucher-claim-root-v1";
pub const RECURSIVE_PROOF_HINT_SCHEME: &str = "pq-recursive-proof-speed-hint-root-v1";
pub const CONTRACT_STATE_DIFF_SCHEME: &str = "private-contract-state-diff-manifest-root-v1";
pub const PACKER_BID_SCHEME: &str = "sealed-low-fee-packer-bid-root-v1";
pub const REBATE_COUPON_SCHEME: &str = "state-witness-da-rebate-coupon-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "state-witness-nullifier-privacy-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "state-witness-packer-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_730_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_COMPRESSION_BPS: u64 = 3_200;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_DA_DISCOUNT_BPS: u64 = 7_500;
pub const DEFAULT_RECURSIVE_HINT_WEIGHT_BPS: u64 = 6_400;
pub const DEFAULT_CHUNK_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 192;
pub const DEFAULT_MAX_CHUNKS: usize = 4_194_304;
pub const DEFAULT_MAX_LANES: usize = 262_144;
pub const DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_VOUCHERS: usize = 2_097_152;
pub const DEFAULT_MAX_BIDS: usize = 2_097_152;
pub const DEFAULT_MAX_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_EVIDENCE: usize = 1_048_576;
pub const DEFAULT_MAX_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessChunkKind {
    ContractStateDiff,
    RecursiveProofWitness,
    ConfidentialTransfer,
    PrivateContractCall,
    MoneroBridgeExit,
    OracleUpdate,
    LiquidityNetting,
    FeeRebateSettlement,
}
impl WitnessChunkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractStateDiff => "contract_state_diff",
            Self::RecursiveProofWitness => "recursive_proof_witness",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::PrivateContractCall => "private_contract_call",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::LiquidityNetting => "liquidity_netting",
            Self::FeeRebateSettlement => "fee_rebate_settlement",
        }
    }
    pub fn proof_weight(self) -> u64 {
        match self {
            Self::RecursiveProofWitness => 1_000,
            Self::ContractStateDiff => 940,
            Self::PrivateContractCall => 900,
            Self::LiquidityNetting => 820,
            Self::MoneroBridgeExit => 780,
            Self::ConfidentialTransfer => 720,
            Self::OracleUpdate => 660,
            Self::FeeRebateSettlement => 600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    Registered,
    DictionaryLinked,
    LaneQueued,
    Packed,
    VoucherClaimed,
    Settled,
    Expired,
    Rejected,
}
impl ChunkStatus {
    pub fn packable(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::DictionaryLinked | Self::LaneQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    HotRecursive,
    PrivateContract,
    StateDiff,
    MoneroBridge,
    Oracle,
    DefiNetting,
    FeeSponsor,
    EscapeHatch,
}
impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotRecursive => "hot_recursive",
            Self::PrivateContract => "private_contract",
            Self::StateDiff => "state_diff",
            Self::MoneroBridge => "monero_bridge",
            Self::Oracle => "oracle",
            Self::DefiNetting => "defi_netting",
            Self::FeeSponsor => "fee_sponsor",
            Self::EscapeHatch => "escape_hatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    Packing,
    Draining,
    Paused,
    Retired,
}
impl LaneStatus {
    pub fn accepts_chunks(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::Packing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Assembled,
    VoucherAllocated,
    BidSelected,
    Published,
    Settled,
    Challenged,
    Slashed,
    Expired,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Allocated,
    Claimed,
    Settled,
    Expired,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Accepted,
    Settled,
    Replaced,
    Expired,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DuplicateChunk,
    InvalidDictionaryRoot,
    UnavailableBlob,
    FeeOvercharge,
    NullifierLeak,
    InvalidRecursiveHint,
    BadVoucherClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_compression_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub da_discount_bps: u64,
    pub recursive_hint_weight_bps: u64,
    pub chunk_ttl_blocks: u64,
    pub lane_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_chunks: usize,
    pub max_lanes: usize,
    pub max_batches: usize,
    pub max_vouchers: usize,
    pub max_bids: usize,
    pub max_coupons: usize,
    pub max_fences: usize,
    pub max_evidence: usize,
    pub max_events: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_compression_bps: DEFAULT_TARGET_COMPRESSION_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            da_discount_bps: DEFAULT_DA_DISCOUNT_BPS,
            recursive_hint_weight_bps: DEFAULT_RECURSIVE_HINT_WEIGHT_BPS,
            chunk_ttl_blocks: DEFAULT_CHUNK_TTL_BLOCKS,
            lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_chunks: DEFAULT_MAX_CHUNKS,
            max_lanes: DEFAULT_MAX_LANES,
            max_batches: DEFAULT_MAX_BATCHES,
            max_vouchers: DEFAULT_MAX_VOUCHERS,
            max_bids: DEFAULT_MAX_BIDS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_fences: DEFAULT_MAX_FENCES,
            max_evidence: DEFAULT_MAX_EVIDENCE,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        ensure(self.min_pq_security_bits >= 192, "pq security bits too low")?;
        ensure(self.min_privacy_set_size >= 16_384, "privacy set too small")?;
        ensure(
            self.target_compression_bps <= MAX_BPS,
            "compression target out of range",
        )?;
        ensure(self.max_user_fee_bps <= 100, "user fee cap too high")?;
        ensure(self.target_rebate_bps <= 500, "rebate target too high")?;
        ensure(self.da_discount_bps <= MAX_BPS, "da discount out of range")?;
        ensure(
            self.recursive_hint_weight_bps <= MAX_BPS,
            "hint weight out of range",
        )?;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub current_height: u64,
    pub next_chunk_seq: u64,
    pub next_lane_seq: u64,
    pub next_batch_seq: u64,
    pub next_voucher_seq: u64,
    pub next_bid_seq: u64,
    pub next_coupon_seq: u64,
    pub next_fence_seq: u64,
    pub next_evidence_seq: u64,
    pub total_raw_bytes: u64,
    pub total_packed_bytes: u64,
    pub total_fee_atomic: u64,
    pub total_rebate_atomic: u64,
    pub settled_batches: u64,
    pub slashed_bids: u64,
    pub event_count: u64,
}
impl Counters {
    pub fn devnet() -> Self {
        Self {
            current_height: DEVNET_HEIGHT,
            next_chunk_seq: 1,
            next_lane_seq: 1,
            next_batch_seq: 1,
            next_voucher_seq: 1,
            next_bid_seq: 1,
            next_coupon_seq: 1,
            next_fence_seq: 1,
            next_evidence_seq: 1,
            total_raw_bytes: 0,
            total_packed_bytes: 0,
            total_fee_atomic: 0,
            total_rebate_atomic: 0,
            settled_batches: 0,
            slashed_bids: 0,
            event_count: 0,
        }
    }
    pub fn compression_bps(&self) -> u64 {
        ratio_bps(self.total_packed_bytes, self.total_raw_bytes)
    }
    pub fn public_record(&self) -> Value {
        let mut value = json!(self);
        value["compression_bps"] = json!(self.compression_bps());
        value
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub witness_chunk_root: String,
    pub blob_lane_root: String,
    pub dictionary_root: String,
    pub da_voucher_root: String,
    pub recursive_hint_root: String,
    pub compression_ratio_root: String,
    pub contract_state_diff_root: String,
    pub packer_bid_root: String,
    pub rebate_coupon_root: String,
    pub privacy_fence_root: String,
    pub slashing_evidence_root: String,
    pub nullifier_root: String,
    pub packer_index_root: String,
    pub lane_queue_root: String,
    pub event_root: String,
}
impl Roots {
    pub fn empty() -> Self {
        Self {
            witness_chunk_root: empty_root("STATE-WITNESS-PACKER-CHUNKS"),
            blob_lane_root: empty_root("STATE-WITNESS-PACKER-LANES"),
            dictionary_root: empty_root("STATE-WITNESS-PACKER-DICTIONARIES"),
            da_voucher_root: empty_root("STATE-WITNESS-PACKER-VOUCHERS"),
            recursive_hint_root: empty_root("STATE-WITNESS-PACKER-HINTS"),
            compression_ratio_root: empty_root("STATE-WITNESS-PACKER-RATIOS"),
            contract_state_diff_root: empty_root("STATE-WITNESS-PACKER-DIFFS"),
            packer_bid_root: empty_root("STATE-WITNESS-PACKER-BIDS"),
            rebate_coupon_root: empty_root("STATE-WITNESS-PACKER-COUPONS"),
            privacy_fence_root: empty_root("STATE-WITNESS-PACKER-FENCES"),
            slashing_evidence_root: empty_root("STATE-WITNESS-PACKER-EVIDENCE"),
            nullifier_root: empty_root("STATE-WITNESS-PACKER-NULLIFIERS"),
            packer_index_root: empty_root("STATE-WITNESS-PACKER-INDEX"),
            lane_queue_root: empty_root("STATE-WITNESS-PACKER-LANE-QUEUE"),
            event_root: empty_root("STATE-WITNESS-PACKER-EVENTS"),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessChunk {
    pub chunk_id: String,
    pub sequence: u64,
    pub kind: WitnessChunkKind,
    pub status: ChunkStatus,
    pub owner_commitment: String,
    pub contract_id: String,
    pub encrypted_payload_root: String,
    pub ciphertext_bytes: u64,
    pub estimated_plaintext_bytes: u64,
    pub dictionary_id: String,
    pub diff_manifest_id: String,
    pub recursive_hint_id: String,
    pub privacy_fence_id: String,
    pub lane_id: String,
    pub batch_id: String,
    pub fee_budget_atomic: u64,
    pub min_rebate_atomic: u64,
    pub expires_at_height: u64,
    pub pq_key_commitment: String,
    pub nullifier: String,
}
impl WitnessChunk {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobLane {
    pub lane_id: String,
    pub sequence: u64,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub packer_committee_root: String,
    pub max_raw_bytes: u64,
    pub target_packed_bytes: u64,
    pub base_fee_atomic: u64,
    pub compression_floor_bps: u64,
    pub recursive_priority_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub queued_chunk_ids: BTreeSet<String>,
    pub packed_batch_ids: BTreeSet<String>,
}
impl BlobLane {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DictionaryRoot {
    pub dictionary_id: String,
    pub contract_id: String,
    pub root: String,
    pub entry_count: u64,
    pub raw_bytes_saved: u64,
    pub pq_attestation_root: String,
}
impl DictionaryRoot {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofHint {
    pub hint_id: String,
    pub chunk_id: String,
    pub circuit_family: String,
    pub expected_constraints: u64,
    pub witness_column_count: u64,
    pub aggregation_depth: u64,
    pub proving_speedup_bps: u64,
    pub hint_root: String,
}
impl RecursiveProofHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractStateDiffManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub nullifier_root: String,
    pub dictionary_id: String,
    pub raw_bytes: u64,
    pub compressed_bytes: u64,
}
impl ContractStateDiffManifest {
    pub fn compression_bps(&self) -> u64 {
        ratio_bps(self.compressed_bytes, self.raw_bytes)
    }
    pub fn public_record(&self) -> Value {
        let mut value = json!(self);
        value["compression_bps"] = json!(self.compression_bps());
        value
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub lane_id: String,
    pub status: BatchStatus,
    pub chunk_ids: BTreeSet<String>,
    pub packed_blob_root: String,
    pub dictionary_root: String,
    pub recursive_hint_root: String,
    pub privacy_fence_root: String,
    pub raw_bytes: u64,
    pub packed_bytes: u64,
    pub fee_atomic: u64,
    pub rebate_atomic: u64,
    pub voucher_id: String,
    pub accepted_bid_id: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}
impl BlobBatch {
    pub fn compression_bps(&self) -> u64 {
        ratio_bps(self.packed_bytes, self.raw_bytes)
    }
    pub fn public_record(&self) -> Value {
        let mut value = json!(self);
        value["compression_bps"] = json!(self.compression_bps());
        value
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucherClaim {
    pub voucher_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub claim_root: String,
    pub covered_bytes: u64,
    pub discount_bps: u64,
    pub max_claim_atomic: u64,
    pub status: VoucherStatus,
    pub expires_at_height: u64,
}
impl DaVoucherClaim {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackerBid {
    pub bid_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub packer_commitment: String,
    pub sealed_quote_root: String,
    pub max_fee_atomic: u64,
    pub promised_packed_bytes: u64,
    pub promised_latency_blocks: u64,
    pub bond_atomic: u64,
    pub status: BidStatus,
    pub expires_at_height: u64,
}
impl PackerBid {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub sequence: u64,
    pub batch_id: String,
    pub voucher_id: String,
    pub owner_commitment: String,
    pub amount_atomic: u64,
    pub fee_asset_id: String,
    pub redemption_nullifier: String,
    pub expires_at_height: u64,
}
impl RebateCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub sequence: u64,
    pub chunk_id: String,
    pub nullifier: String,
    pub privacy_set_root: String,
    pub min_privacy_set_size: u64,
    pub expires_at_height: u64,
}
impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub sequence: u64,
    pub kind: EvidenceKind,
    pub accused_commitment: String,
    pub batch_id: String,
    pub bid_id: String,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub slash_amount_atomic: u64,
    pub opened_at_height: u64,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub witness_chunks: BTreeMap<String, WitnessChunk>,
    pub blob_lanes: BTreeMap<String, BlobLane>,
    pub dictionary_roots: BTreeMap<String, DictionaryRoot>,
    pub recursive_hints: BTreeMap<String, RecursiveProofHint>,
    pub contract_state_diffs: BTreeMap<String, ContractStateDiffManifest>,
    pub blob_batches: BTreeMap<String, BlobBatch>,
    pub da_vouchers: BTreeMap<String, DaVoucherClaim>,
    pub packer_bids: BTreeMap<String, PackerBid>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub packer_index: BTreeMap<String, BTreeSet<String>>,
    pub lane_queue_index: BTreeMap<String, BTreeSet<String>>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        let mut counters = Counters::devnet();
        counters.current_height = current_height;
        let mut state = Self {
            config,
            counters,
            roots: Roots::empty(),
            witness_chunks: BTreeMap::new(),
            blob_lanes: BTreeMap::new(),
            dictionary_roots: BTreeMap::new(),
            recursive_hints: BTreeMap::new(),
            contract_state_diffs: BTreeMap::new(),
            blob_batches: BTreeMap::new(),
            da_vouchers: BTreeMap::new(),
            packer_bids: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            packer_index: BTreeMap::new(),
            lane_queue_index: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        let lane_id = state
            .open_blob_lane(
                LaneKind::HotRecursive,
                deterministic_id("devnet-packer-committee", "hot-recursive"),
                1_048_576,
                318_000,
                2_000,
                3_500,
                8_000,
            )
            .unwrap_or_else(stable_error_id);
        let chunk_a = state
            .register_witness_chunk(
                WitnessChunkKind::ContractStateDiff,
                "owner_commitment_devnet_alpha",
                "contract_private_swap_pool",
                "ciphertext_root_devnet_alpha",
                184_320,
                612_000,
                "dictionary_contract_swap_pool_v1",
                "diff_manifest_swap_pool_epoch_0001",
                "recursive_hint_swap_pool_epoch_0001",
                24_000,
                1_200,
                "pq_key_commitment_alpha",
            )
            .unwrap_or_else(stable_error_id);
        let chunk_b = state
            .register_witness_chunk(
                WitnessChunkKind::RecursiveProofWitness,
                "owner_commitment_devnet_beta",
                "contract_private_margin_vault",
                "ciphertext_root_devnet_beta",
                221_184,
                702_000,
                "dictionary_margin_vault_v1",
                "diff_manifest_margin_vault_epoch_0001",
                "recursive_hint_margin_vault_epoch_0001",
                31_000,
                1_800,
                "pq_key_commitment_beta",
            )
            .unwrap_or_else(stable_error_id);
        let _ = state.attach_dictionary_root(
            "dictionary_contract_swap_pool_v1",
            "contract_private_swap_pool",
            "dictionary_root_swap_pool_v1",
            4_096,
            427_680,
            "pq_dictionary_attestation_swap_pool_v1",
        );
        let _ = state.attach_dictionary_root(
            "dictionary_margin_vault_v1",
            "contract_private_margin_vault",
            "dictionary_root_margin_vault_v1",
            5_120,
            480_816,
            "pq_dictionary_attestation_margin_vault_v1",
        );
        let _ = state.add_contract_state_diff_manifest(
            "diff_manifest_swap_pool_epoch_0001",
            "contract_private_swap_pool",
            "read_set_root_swap_pool_epoch_0001",
            "write_set_root_swap_pool_epoch_0001",
            "nullifier_root_swap_pool_epoch_0001",
            "dictionary_contract_swap_pool_v1",
            612_000,
            184_320,
        );
        let _ = state.add_contract_state_diff_manifest(
            "diff_manifest_margin_vault_epoch_0001",
            "contract_private_margin_vault",
            "read_set_root_margin_vault_epoch_0001",
            "write_set_root_margin_vault_epoch_0001",
            "nullifier_root_margin_vault_epoch_0001",
            "dictionary_margin_vault_v1",
            702_000,
            221_184,
        );
        let _ = state.add_recursive_proof_hint(
            "recursive_hint_swap_pool_epoch_0001",
            &chunk_a,
            "plonkish-state-diff-folding",
            2_400_000,
            48,
            3,
            6_800,
            "hint_root_swap_pool_epoch_0001",
        );
        let _ = state.add_recursive_proof_hint(
            "recursive_hint_margin_vault_epoch_0001",
            &chunk_b,
            "stark-to-snark-witness-folding",
            3_100_000,
            64,
            4,
            7_200,
            "hint_root_margin_vault_epoch_0001",
        );
        let _ = state.queue_chunk_for_lane(&lane_id, &chunk_a);
        let _ = state.queue_chunk_for_lane(&lane_id, &chunk_b);
        let batch_id = state
            .pack_blob_batch(
                &lane_id,
                &[chunk_a.clone(), chunk_b.clone()],
                "packed_blob_root_devnet_0001",
            )
            .unwrap_or_else(stable_error_id);
        let voucher_id = state
            .allocate_da_voucher(
                &batch_id,
                "sponsor_commitment_devnet_rebate_pool",
                "voucher_claim_root_devnet_0001",
                405_504,
                7_500,
                42_000,
            )
            .unwrap_or_else(stable_error_id);
        let bid_id = state
            .post_packer_bid(
                &batch_id,
                "packer_commitment_devnet_fast_lane",
                "sealed_quote_root_devnet_fast_lane",
                37_000,
                405_504,
                2,
                75_000,
            )
            .unwrap_or_else(stable_error_id);
        let _ = state.settle_packer_bid(&bid_id, 35_800, 3_000, "owner_commitment_devnet_coupon");
        let _ = state.claim_da_voucher(&voucher_id);
        state.recompute_roots();
        state
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure(
            self.events.len() <= self.config.max_events,
            "too many events",
        )?;
        ensure(
            self.witness_chunks.len() <= self.config.max_chunks,
            "too many chunks",
        )?;
        ensure(
            self.blob_lanes.len() <= self.config.max_lanes,
            "too many lanes",
        )?;
        ensure(
            self.blob_batches.len() <= self.config.max_batches,
            "too many batches",
        )?;
        ensure(
            self.da_vouchers.len() <= self.config.max_vouchers,
            "too many vouchers",
        )?;
        ensure(
            self.packer_bids.len() <= self.config.max_bids,
            "too many bids",
        )?;
        ensure(
            self.rebate_coupons.len() <= self.config.max_coupons,
            "too many coupons",
        )?;
        ensure(
            self.privacy_fences.len() <= self.config.max_fences,
            "too many fences",
        )?;
        ensure(
            self.slashing_evidence.len() <= self.config.max_evidence,
            "too much evidence",
        )?;
        Ok(())
    }
    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "hash_suite": HASH_SUITE, "pq_auth_suite": PQ_AUTH_SUITE, "witness_chunk_scheme": WITNESS_CHUNK_SCHEME, "blob_packing_scheme": BLOB_PACKING_SCHEME, "dictionary_scheme": DICTIONARY_SCHEME, "da_voucher_scheme": DA_VOUCHER_SCHEME, "recursive_proof_hint_scheme": RECURSIVE_PROOF_HINT_SCHEME, "contract_state_diff_scheme": CONTRACT_STATE_DIFF_SCHEME, "packer_bid_scheme": PACKER_BID_SCHEME, "rebate_coupon_scheme": REBATE_COUPON_SCHEME, "privacy_fence_scheme": PRIVACY_FENCE_SCHEME, "slashing_evidence_scheme": SLASHING_EVIDENCE_SCHEME, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record() })
    }
    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        ensure(
            height >= self.counters.current_height,
            "height cannot decrease",
        )?;
        self.counters.current_height = height;
        self.record_event("height_advanced", json!({ "height": height }));
        self.recompute_roots();
        Ok(())
    }
    pub fn open_blob_lane(
        &mut self,
        kind: LaneKind,
        packer_committee_root: String,
        max_raw_bytes: u64,
        target_packed_bytes: u64,
        base_fee_atomic: u64,
        compression_floor_bps: u64,
        recursive_priority_bps: u64,
    ) -> Result<String> {
        self.validate()?;
        ensure(max_raw_bytes > 0, "lane max raw bytes must be positive")?;
        ensure(
            target_packed_bytes > 0 && target_packed_bytes <= max_raw_bytes,
            "invalid target packed bytes",
        )?;
        ensure(
            compression_floor_bps <= MAX_BPS,
            "compression floor out of range",
        )?;
        ensure(
            recursive_priority_bps <= MAX_BPS,
            "recursive priority out of range",
        )?;
        let sequence = self.counters.next_lane_seq;
        let lane_id = sequence_id(
            "lane",
            sequence,
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&packer_committee_root),
            ],
        );
        let lane = BlobLane {
            lane_id: lane_id.clone(),
            sequence,
            kind,
            status: LaneStatus::Open,
            packer_committee_root,
            max_raw_bytes,
            target_packed_bytes,
            base_fee_atomic,
            compression_floor_bps,
            recursive_priority_bps,
            opened_at_height: self.counters.current_height,
            expires_at_height: self.counters.current_height + self.config.lane_ttl_blocks,
            queued_chunk_ids: BTreeSet::new(),
            packed_batch_ids: BTreeSet::new(),
        };
        self.counters.next_lane_seq += 1;
        self.blob_lanes.insert(lane_id.clone(), lane);
        self.record_event("blob_lane_opened", json!({ "lane_id": lane_id }));
        self.recompute_roots();
        Ok(lane_id)
    }
    pub fn register_witness_chunk(
        &mut self,
        kind: WitnessChunkKind,
        owner_commitment: &str,
        contract_id: &str,
        encrypted_payload_root: &str,
        ciphertext_bytes: u64,
        estimated_plaintext_bytes: u64,
        dictionary_id: &str,
        diff_manifest_id: &str,
        recursive_hint_id: &str,
        fee_budget_atomic: u64,
        min_rebate_atomic: u64,
        pq_key_commitment: &str,
    ) -> Result<String> {
        self.validate()?;
        ensure(ciphertext_bytes > 0, "ciphertext bytes must be positive")?;
        ensure(
            estimated_plaintext_bytes >= ciphertext_bytes,
            "estimated plaintext must cover ciphertext",
        )?;
        ensure(
            fee_budget_atomic >= min_rebate_atomic,
            "rebate exceeds fee budget",
        )?;
        let sequence = self.counters.next_chunk_seq;
        let nullifier = sequence_id(
            "chunk-nullifier",
            sequence,
            &[
                HashPart::Str(owner_commitment),
                HashPart::Str(contract_id),
                HashPart::Str(encrypted_payload_root),
            ],
        );
        ensure(
            !self.consumed_nullifiers.contains(&nullifier),
            "chunk nullifier already consumed",
        )?;
        let chunk_id = sequence_id(
            "chunk",
            sequence,
            &[HashPart::Str(kind.as_str()), HashPart::Str(&nullifier)],
        );
        let fence_id = sequence_id(
            "fence",
            self.counters.next_fence_seq,
            &[HashPart::Str(&chunk_id), HashPart::Str(&nullifier)],
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            sequence: self.counters.next_fence_seq,
            chunk_id: chunk_id.clone(),
            nullifier: nullifier.clone(),
            privacy_set_root: deterministic_id("privacy-set", owner_commitment),
            min_privacy_set_size: self.config.min_privacy_set_size,
            expires_at_height: self.counters.current_height + self.config.chunk_ttl_blocks,
        };
        let chunk = WitnessChunk {
            chunk_id: chunk_id.clone(),
            sequence,
            kind,
            status: ChunkStatus::Registered,
            owner_commitment: owner_commitment.to_string(),
            contract_id: contract_id.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            ciphertext_bytes,
            estimated_plaintext_bytes,
            dictionary_id: dictionary_id.to_string(),
            diff_manifest_id: diff_manifest_id.to_string(),
            recursive_hint_id: recursive_hint_id.to_string(),
            privacy_fence_id: fence_id.clone(),
            lane_id: String::new(),
            batch_id: String::new(),
            fee_budget_atomic,
            min_rebate_atomic,
            expires_at_height: self.counters.current_height + self.config.chunk_ttl_blocks,
            pq_key_commitment: pq_key_commitment.to_string(),
            nullifier: nullifier.clone(),
        };
        self.counters.next_chunk_seq += 1;
        self.counters.next_fence_seq += 1;
        self.counters.total_raw_bytes += estimated_plaintext_bytes;
        self.consumed_nullifiers.insert(nullifier);
        self.privacy_fences.insert(fence_id, fence);
        self.witness_chunks.insert(chunk_id.clone(), chunk);
        self.record_event("witness_chunk_registered", json!({ "chunk_id": chunk_id }));
        self.recompute_roots();
        Ok(chunk_id)
    }
    pub fn attach_dictionary_root(
        &mut self,
        dictionary_id: &str,
        contract_id: &str,
        root: &str,
        entry_count: u64,
        raw_bytes_saved: u64,
        pq_attestation_root: &str,
    ) -> Result<()> {
        ensure(entry_count > 0, "dictionary must have entries")?;
        let record = DictionaryRoot {
            dictionary_id: dictionary_id.to_string(),
            contract_id: contract_id.to_string(),
            root: root.to_string(),
            entry_count,
            raw_bytes_saved,
            pq_attestation_root: pq_attestation_root.to_string(),
        };
        self.dictionary_roots
            .insert(dictionary_id.to_string(), record);
        self.record_event(
            "dictionary_root_attached",
            json!({ "dictionary_id": dictionary_id }),
        );
        self.recompute_roots();
        Ok(())
    }
    pub fn add_contract_state_diff_manifest(
        &mut self,
        manifest_id: &str,
        contract_id: &str,
        read_set_root: &str,
        write_set_root: &str,
        nullifier_root: &str,
        dictionary_id: &str,
        raw_bytes: u64,
        compressed_bytes: u64,
    ) -> Result<()> {
        ensure(raw_bytes > 0, "raw bytes must be positive")?;
        ensure(
            compressed_bytes <= raw_bytes,
            "compressed bytes exceed raw bytes",
        )?;
        let manifest = ContractStateDiffManifest {
            manifest_id: manifest_id.to_string(),
            contract_id: contract_id.to_string(),
            read_set_root: read_set_root.to_string(),
            write_set_root: write_set_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            dictionary_id: dictionary_id.to_string(),
            raw_bytes,
            compressed_bytes,
        };
        self.contract_state_diffs
            .insert(manifest_id.to_string(), manifest);
        self.record_event(
            "contract_state_diff_manifest_added",
            json!({ "manifest_id": manifest_id }),
        );
        self.recompute_roots();
        Ok(())
    }
    pub fn add_recursive_proof_hint(
        &mut self,
        hint_id: &str,
        chunk_id: &str,
        circuit_family: &str,
        expected_constraints: u64,
        witness_column_count: u64,
        aggregation_depth: u64,
        proving_speedup_bps: u64,
        hint_root: &str,
    ) -> Result<()> {
        ensure(
            self.witness_chunks.contains_key(chunk_id),
            "unknown chunk for hint",
        )?;
        ensure(proving_speedup_bps <= MAX_BPS, "speedup out of range")?;
        let hint = RecursiveProofHint {
            hint_id: hint_id.to_string(),
            chunk_id: chunk_id.to_string(),
            circuit_family: circuit_family.to_string(),
            expected_constraints,
            witness_column_count,
            aggregation_depth,
            proving_speedup_bps,
            hint_root: hint_root.to_string(),
        };
        self.recursive_hints.insert(hint_id.to_string(), hint);
        if let Some(chunk) = self.witness_chunks.get_mut(chunk_id) {
            chunk.status = ChunkStatus::DictionaryLinked;
        }
        self.record_event(
            "recursive_proof_hint_added",
            json!({ "hint_id": hint_id, "chunk_id": chunk_id }),
        );
        self.recompute_roots();
        Ok(())
    }
    pub fn queue_chunk_for_lane(&mut self, lane_id: &str, chunk_id: &str) -> Result<()> {
        let lane = self
            .blob_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown lane".to_string())?;
        ensure(lane.status.accepts_chunks(), "lane does not accept chunks")?;
        let chunk = self
            .witness_chunks
            .get_mut(chunk_id)
            .ok_or_else(|| "unknown chunk".to_string())?;
        ensure(chunk.status.packable(), "chunk is not packable")?;
        ensure(
            chunk.expires_at_height >= self.counters.current_height,
            "chunk expired",
        )?;
        lane.queued_chunk_ids.insert(chunk_id.to_string());
        chunk.lane_id = lane_id.to_string();
        chunk.status = ChunkStatus::LaneQueued;
        self.lane_queue_index
            .entry(lane_id.to_string())
            .or_default()
            .insert(chunk_id.to_string());
        self.record_event(
            "chunk_queued_for_lane",
            json!({ "lane_id": lane_id, "chunk_id": chunk_id }),
        );
        self.recompute_roots();
        Ok(())
    }
    pub fn pack_blob_batch(
        &mut self,
        lane_id: &str,
        chunk_ids: &[String],
        packed_blob_root: &str,
    ) -> Result<String> {
        ensure(!chunk_ids.is_empty(), "batch requires chunks")?;
        let lane = self
            .blob_lanes
            .get(lane_id)
            .ok_or_else(|| "unknown lane".to_string())?
            .clone();
        ensure(lane.status.accepts_chunks(), "lane cannot pack")?;
        let mut raw_bytes = 0_u64;
        let mut packed_bytes = 0_u64;
        let mut chunk_set = BTreeSet::new();
        let mut dict_records = Vec::new();
        let mut hint_records = Vec::new();
        let mut fence_records = Vec::new();
        for chunk_id in chunk_ids {
            let chunk = self
                .witness_chunks
                .get(chunk_id)
                .ok_or_else(|| "unknown batch chunk".to_string())?;
            ensure(chunk.lane_id == lane_id, "chunk queued on different lane")?;
            ensure(chunk.status.packable(), "chunk already packed")?;
            raw_bytes += chunk.estimated_plaintext_bytes;
            packed_bytes += chunk.ciphertext_bytes;
            chunk_set.insert(chunk_id.clone());
            if let Some(dict) = self.dictionary_roots.get(&chunk.dictionary_id) {
                dict_records.push(dict.public_record());
            }
            if let Some(hint) = self.recursive_hints.get(&chunk.recursive_hint_id) {
                hint_records.push(hint.public_record());
            }
            if let Some(fence) = self.privacy_fences.get(&chunk.privacy_fence_id) {
                fence_records.push(fence.public_record());
            }
        }
        ensure(
            raw_bytes <= lane.max_raw_bytes,
            "batch exceeds lane raw byte cap",
        )?;
        ensure(
            packed_bytes <= lane.max_raw_bytes,
            "batch exceeds lane packed byte cap",
        )?;
        let sequence = self.counters.next_batch_seq;
        let batch_id = sequence_id(
            "batch",
            sequence,
            &[HashPart::Str(lane_id), HashPart::Str(packed_blob_root)],
        );
        let fee_atomic = lane.base_fee_atomic
            + packed_bytes.saturating_mul(self.config.max_user_fee_bps) / MAX_BPS;
        let rebate_atomic = fee_atomic.saturating_mul(self.config.target_rebate_bps) / MAX_BPS;
        let batch = BlobBatch {
            batch_id: batch_id.clone(),
            sequence,
            lane_id: lane_id.to_string(),
            status: BatchStatus::Assembled,
            chunk_ids: chunk_set.clone(),
            packed_blob_root: packed_blob_root.to_string(),
            dictionary_root: merkle_root("STATE-WITNESS-PACKER-BATCH-DICTIONARIES", &dict_records),
            recursive_hint_root: merkle_root("STATE-WITNESS-PACKER-BATCH-HINTS", &hint_records),
            privacy_fence_root: merkle_root("STATE-WITNESS-PACKER-BATCH-FENCES", &fence_records),
            raw_bytes,
            packed_bytes,
            fee_atomic,
            rebate_atomic,
            voucher_id: String::new(),
            accepted_bid_id: String::new(),
            published_at_height: self.counters.current_height,
            expires_at_height: self.counters.current_height + self.config.batch_ttl_blocks,
        };
        for chunk_id in &chunk_set {
            if let Some(chunk) = self.witness_chunks.get_mut(chunk_id) {
                chunk.status = ChunkStatus::Packed;
                chunk.batch_id = batch_id.clone();
            }
        }
        if let Some(lane) = self.blob_lanes.get_mut(lane_id) {
            lane.packed_batch_ids.insert(batch_id.clone());
            for chunk_id in &chunk_set {
                lane.queued_chunk_ids.remove(chunk_id);
            }
        }
        if let Some(queue) = self.lane_queue_index.get_mut(lane_id) {
            for chunk_id in &chunk_set {
                queue.remove(chunk_id);
            }
        }
        self.counters.next_batch_seq += 1;
        self.counters.total_packed_bytes += packed_bytes;
        self.counters.total_fee_atomic += fee_atomic;
        self.blob_batches.insert(batch_id.clone(), batch);
        self.record_event(
            "blob_batch_packed",
            json!({ "batch_id": batch_id, "lane_id": lane_id }),
        );
        self.recompute_roots();
        Ok(batch_id)
    }
    pub fn allocate_da_voucher(
        &mut self,
        batch_id: &str,
        sponsor_commitment: &str,
        claim_root: &str,
        covered_bytes: u64,
        discount_bps: u64,
        max_claim_atomic: u64,
    ) -> Result<String> {
        ensure(discount_bps <= MAX_BPS, "discount out of range")?;
        let batch = self
            .blob_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        ensure(
            matches!(
                batch.status,
                BatchStatus::Assembled | BatchStatus::BidSelected
            ),
            "batch cannot receive voucher",
        )?;
        let sequence = self.counters.next_voucher_seq;
        let voucher_id = sequence_id(
            "voucher",
            sequence,
            &[
                HashPart::Str(batch_id),
                HashPart::Str(sponsor_commitment),
                HashPart::Str(claim_root),
            ],
        );
        let voucher = DaVoucherClaim {
            voucher_id: voucher_id.clone(),
            sequence,
            batch_id: batch_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            claim_root: claim_root.to_string(),
            covered_bytes,
            discount_bps,
            max_claim_atomic,
            status: VoucherStatus::Allocated,
            expires_at_height: self.counters.current_height + self.config.voucher_ttl_blocks,
        };
        batch.voucher_id = voucher_id.clone();
        batch.status = BatchStatus::VoucherAllocated;
        self.counters.next_voucher_seq += 1;
        self.da_vouchers.insert(voucher_id.clone(), voucher);
        self.record_event(
            "da_voucher_allocated",
            json!({ "voucher_id": voucher_id, "batch_id": batch_id }),
        );
        self.recompute_roots();
        Ok(voucher_id)
    }
    pub fn claim_da_voucher(&mut self, voucher_id: &str) -> Result<()> {
        let voucher = self
            .da_vouchers
            .get_mut(voucher_id)
            .ok_or_else(|| "unknown voucher".to_string())?;
        ensure(
            matches!(voucher.status, VoucherStatus::Allocated),
            "voucher not claimable",
        )?;
        voucher.status = VoucherStatus::Claimed;
        if let Some(batch) = self.blob_batches.get_mut(&voucher.batch_id) {
            if matches!(batch.status, BatchStatus::VoucherAllocated) {
                batch.status = BatchStatus::Published;
            }
        }
        self.record_event("da_voucher_claimed", json!({ "voucher_id": voucher_id }));
        self.recompute_roots();
        Ok(())
    }
    pub fn post_packer_bid(
        &mut self,
        batch_id: &str,
        packer_commitment: &str,
        sealed_quote_root: &str,
        max_fee_atomic: u64,
        promised_packed_bytes: u64,
        promised_latency_blocks: u64,
        bond_atomic: u64,
    ) -> Result<String> {
        let batch = self
            .blob_batches
            .get(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        ensure(max_fee_atomic <= batch.fee_atomic, "bid exceeds batch fee")?;
        ensure(
            promised_packed_bytes <= batch.packed_bytes,
            "bid promises larger packed size",
        )?;
        let sequence = self.counters.next_bid_seq;
        let bid_id = sequence_id(
            "packer-bid",
            sequence,
            &[
                HashPart::Str(batch_id),
                HashPart::Str(packer_commitment),
                HashPart::Str(sealed_quote_root),
            ],
        );
        let bid = PackerBid {
            bid_id: bid_id.clone(),
            sequence,
            batch_id: batch_id.to_string(),
            packer_commitment: packer_commitment.to_string(),
            sealed_quote_root: sealed_quote_root.to_string(),
            max_fee_atomic,
            promised_packed_bytes,
            promised_latency_blocks,
            bond_atomic,
            status: BidStatus::Posted,
            expires_at_height: self.counters.current_height + self.config.bid_ttl_blocks,
        };
        self.counters.next_bid_seq += 1;
        self.packer_index
            .entry(packer_commitment.to_string())
            .or_default()
            .insert(bid_id.clone());
        self.packer_bids.insert(bid_id.clone(), bid);
        self.record_event(
            "packer_bid_posted",
            json!({ "bid_id": bid_id, "batch_id": batch_id }),
        );
        self.recompute_roots();
        Ok(bid_id)
    }
    pub fn settle_packer_bid(
        &mut self,
        bid_id: &str,
        settled_fee_atomic: u64,
        rebate_atomic: u64,
        coupon_owner_commitment: &str,
    ) -> Result<String> {
        let bid = self
            .packer_bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown bid".to_string())?;
        ensure(
            matches!(bid.status, BidStatus::Posted | BidStatus::Accepted),
            "bid not settleable",
        )?;
        ensure(
            settled_fee_atomic <= bid.max_fee_atomic,
            "settled fee exceeds bid",
        )?;
        let batch = self
            .blob_batches
            .get_mut(&bid.batch_id)
            .ok_or_else(|| "missing batch for bid".to_string())?;
        ensure(
            rebate_atomic <= settled_fee_atomic,
            "rebate exceeds settlement",
        )?;
        bid.status = BidStatus::Settled;
        batch.status = BatchStatus::Settled;
        batch.accepted_bid_id = bid_id.to_string();
        batch.fee_atomic = settled_fee_atomic;
        batch.rebate_atomic = rebate_atomic;
        self.counters.settled_batches += 1;
        self.counters.total_rebate_atomic += rebate_atomic;
        let coupon_id = sequence_id(
            "rebate-coupon",
            self.counters.next_coupon_seq,
            &[
                HashPart::Str(&batch.batch_id),
                HashPart::Str(coupon_owner_commitment),
                HashPart::U64(rebate_atomic),
            ],
        );
        let redemption_nullifier = deterministic_id("coupon-redemption", &coupon_id);
        let coupon = RebateCoupon {
            coupon_id: coupon_id.clone(),
            sequence: self.counters.next_coupon_seq,
            batch_id: batch.batch_id.clone(),
            voucher_id: batch.voucher_id.clone(),
            owner_commitment: coupon_owner_commitment.to_string(),
            amount_atomic: rebate_atomic,
            fee_asset_id: self.config.fee_asset_id.clone(),
            redemption_nullifier,
            expires_at_height: self.counters.current_height + self.config.coupon_ttl_blocks,
        };
        self.counters.next_coupon_seq += 1;
        self.rebate_coupons.insert(coupon_id.clone(), coupon);
        self.record_event(
            "packer_bid_settled",
            json!({ "bid_id": bid_id, "coupon_id": coupon_id }),
        );
        self.recompute_roots();
        Ok(coupon_id)
    }
    pub fn submit_slashing_evidence(
        &mut self,
        kind: EvidenceKind,
        accused_commitment: &str,
        batch_id: &str,
        bid_id: &str,
        evidence_root: &str,
        reporter_commitment: &str,
        slash_amount_atomic: u64,
    ) -> Result<String> {
        ensure(
            self.blob_batches.contains_key(batch_id),
            "unknown batch for evidence",
        )?;
        ensure(
            self.packer_bids.contains_key(bid_id),
            "unknown bid for evidence",
        )?;
        let sequence = self.counters.next_evidence_seq;
        let evidence_id = sequence_id(
            "slashing-evidence",
            sequence,
            &[
                HashPart::Str(accused_commitment),
                HashPart::Str(batch_id),
                HashPart::Str(evidence_root),
            ],
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            sequence,
            kind,
            accused_commitment: accused_commitment.to_string(),
            batch_id: batch_id.to_string(),
            bid_id: bid_id.to_string(),
            evidence_root: evidence_root.to_string(),
            reporter_commitment: reporter_commitment.to_string(),
            slash_amount_atomic,
            opened_at_height: self.counters.current_height,
        };
        self.counters.next_evidence_seq += 1;
        self.counters.slashed_bids += 1;
        if let Some(batch) = self.blob_batches.get_mut(batch_id) {
            batch.status = BatchStatus::Challenged;
        }
        if let Some(bid) = self.packer_bids.get_mut(bid_id) {
            bid.status = BidStatus::Slashed;
        }
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.record_event(
            "slashing_evidence_submitted",
            json!({ "evidence_id": evidence_id }),
        );
        self.recompute_roots();
        Ok(evidence_id)
    }
    pub fn recompute_roots(&mut self) {
        let chunk_records = values(
            self.witness_chunks
                .values()
                .map(WitnessChunk::public_record),
        );
        let lane_records = values(self.blob_lanes.values().map(BlobLane::public_record));
        let dict_records = values(
            self.dictionary_roots
                .values()
                .map(DictionaryRoot::public_record),
        );
        let voucher_records = values(self.da_vouchers.values().map(DaVoucherClaim::public_record));
        let hint_records = values(
            self.recursive_hints
                .values()
                .map(RecursiveProofHint::public_record),
        );
        let ratio_records = values(self.blob_batches.values().map(|batch| json!({ "batch_id": batch.batch_id, "compression_bps": batch.compression_bps(), "raw_bytes": batch.raw_bytes, "packed_bytes": batch.packed_bytes })));
        let diff_records = values(
            self.contract_state_diffs
                .values()
                .map(ContractStateDiffManifest::public_record),
        );
        let bid_records = values(self.packer_bids.values().map(PackerBid::public_record));
        let coupon_records = values(
            self.rebate_coupons
                .values()
                .map(RebateCoupon::public_record),
        );
        let fence_records = values(
            self.privacy_fences
                .values()
                .map(PrivacyFence::public_record),
        );
        let evidence_records = values(
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record),
        );
        let nullifier_records = values(
            self.consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "chain_id": CHAIN_ID, "nullifier": nullifier })),
        );
        let packer_records = values(
            self.packer_index
                .iter()
                .map(|(packer, bids)| json!({ "packer_commitment": packer, "bid_ids": bids })),
        );
        let queue_records = values(
            self.lane_queue_index
                .iter()
                .map(|(lane, chunks)| json!({ "lane_id": lane, "chunk_ids": chunks })),
        );
        self.roots = Roots {
            witness_chunk_root: merkle_root("STATE-WITNESS-PACKER-CHUNKS", &chunk_records),
            blob_lane_root: merkle_root("STATE-WITNESS-PACKER-LANES", &lane_records),
            dictionary_root: merkle_root("STATE-WITNESS-PACKER-DICTIONARIES", &dict_records),
            da_voucher_root: merkle_root("STATE-WITNESS-PACKER-VOUCHERS", &voucher_records),
            recursive_hint_root: merkle_root("STATE-WITNESS-PACKER-HINTS", &hint_records),
            compression_ratio_root: merkle_root("STATE-WITNESS-PACKER-RATIOS", &ratio_records),
            contract_state_diff_root: merkle_root("STATE-WITNESS-PACKER-DIFFS", &diff_records),
            packer_bid_root: merkle_root("STATE-WITNESS-PACKER-BIDS", &bid_records),
            rebate_coupon_root: merkle_root("STATE-WITNESS-PACKER-COUPONS", &coupon_records),
            privacy_fence_root: merkle_root("STATE-WITNESS-PACKER-FENCES", &fence_records),
            slashing_evidence_root: merkle_root("STATE-WITNESS-PACKER-EVIDENCE", &evidence_records),
            nullifier_root: merkle_root("STATE-WITNESS-PACKER-NULLIFIERS", &nullifier_records),
            packer_index_root: merkle_root("STATE-WITNESS-PACKER-INDEX", &packer_records),
            lane_queue_root: merkle_root("STATE-WITNESS-PACKER-LANE-QUEUE", &queue_records),
            event_root: merkle_root("STATE-WITNESS-PACKER-EVENTS", &self.events),
        };
    }
    fn record_event(&mut self, kind: &str, payload: Value) {
        let event = json!({ "chain_id": CHAIN_ID, "event_index": self.counters.event_count, "height": self.counters.current_height, "kind": kind, "payload": payload });
        self.counters.event_count += 1;
        self.events.push(event);
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "STATE-WITNESS-PACKER-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}
pub fn deterministic_id(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("STATE-WITNESS-PACKER-ID:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
fn sequence_id(domain: &str, sequence: u64, parts: &[HashPart<'_>]) -> String {
    let mut full_parts = Vec::with_capacity(parts.len() + 3);
    full_parts.push(HashPart::Str(CHAIN_ID));
    full_parts.push(HashPart::Str(PROTOCOL_VERSION));
    full_parts.push(HashPart::U64(sequence));
    for part in parts {
        full_parts.push(match part {
            HashPart::Bytes(value) => HashPart::Bytes(value),
            HashPart::Str(value) => HashPart::Str(value),
            HashPart::U64(value) => HashPart::U64(*value),
            HashPart::Int(value) => HashPart::Int(*value),
            HashPart::Json(value) => HashPart::Json(value),
        });
    }
    domain_hash(
        &format!("STATE-WITNESS-PACKER-SEQUENCE:{domain}"),
        &full_parts,
        32,
    )
}
fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}
fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        MAX_BPS
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}
fn values<I>(iter: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    iter.into_iter().collect::<Vec<_>>()
}
fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn stable_error_id(message: String) -> String {
    deterministic_id("devnet-error", &message)
}
pub fn policy_001_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_001", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7600, "recursive_speed_weight_bps": 6200, "private_contract_weight_bps": 7000, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_002_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_002", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7611, "recursive_speed_weight_bps": 6213, "private_contract_weight_bps": 7007, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_003_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_003", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7622, "recursive_speed_weight_bps": 6226, "private_contract_weight_bps": 7014, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_004_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_004", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7633, "recursive_speed_weight_bps": 6239, "private_contract_weight_bps": 7021, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_005_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_005", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7644, "recursive_speed_weight_bps": 6252, "private_contract_weight_bps": 7028, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_006_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_006", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7655, "recursive_speed_weight_bps": 6265, "private_contract_weight_bps": 7035, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_007_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_007", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7666, "recursive_speed_weight_bps": 6278, "private_contract_weight_bps": 7042, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_008_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_008", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7677, "recursive_speed_weight_bps": 6291, "private_contract_weight_bps": 7049, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_009_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_009", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7688, "recursive_speed_weight_bps": 6304, "private_contract_weight_bps": 7056, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_010_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_010", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7699, "recursive_speed_weight_bps": 6317, "private_contract_weight_bps": 7063, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_011_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_011", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7710, "recursive_speed_weight_bps": 6330, "private_contract_weight_bps": 7070, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_012_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_012", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7721, "recursive_speed_weight_bps": 6343, "private_contract_weight_bps": 7077, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_013_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_013", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7732, "recursive_speed_weight_bps": 6356, "private_contract_weight_bps": 7084, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_014_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_014", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7743, "recursive_speed_weight_bps": 6369, "private_contract_weight_bps": 7091, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_015_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_015", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7754, "recursive_speed_weight_bps": 6382, "private_contract_weight_bps": 7098, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_016_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_016", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7765, "recursive_speed_weight_bps": 6395, "private_contract_weight_bps": 7105, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_017_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_017", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7776, "recursive_speed_weight_bps": 6408, "private_contract_weight_bps": 7112, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_018_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_018", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7600, "recursive_speed_weight_bps": 6421, "private_contract_weight_bps": 7119, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_019_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_019", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7611, "recursive_speed_weight_bps": 6434, "private_contract_weight_bps": 7126, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_020_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_020", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7622, "recursive_speed_weight_bps": 6200, "private_contract_weight_bps": 7133, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_021_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_021", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7633, "recursive_speed_weight_bps": 6213, "private_contract_weight_bps": 7140, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_022_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_022", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7644, "recursive_speed_weight_bps": 6226, "private_contract_weight_bps": 7147, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_023_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_023", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7655, "recursive_speed_weight_bps": 6239, "private_contract_weight_bps": 7154, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_024_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_024", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7666, "recursive_speed_weight_bps": 6252, "private_contract_weight_bps": 7000, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_025_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_025", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7677, "recursive_speed_weight_bps": 6265, "private_contract_weight_bps": 7007, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_026_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_026", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7688, "recursive_speed_weight_bps": 6278, "private_contract_weight_bps": 7014, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_027_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_027", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7699, "recursive_speed_weight_bps": 6291, "private_contract_weight_bps": 7021, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_028_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_028", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7710, "recursive_speed_weight_bps": 6304, "private_contract_weight_bps": 7028, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_029_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_029", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7721, "recursive_speed_weight_bps": 6317, "private_contract_weight_bps": 7035, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_030_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_030", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7732, "recursive_speed_weight_bps": 6330, "private_contract_weight_bps": 7042, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_031_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_031", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7743, "recursive_speed_weight_bps": 6343, "private_contract_weight_bps": 7049, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_032_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_032", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7754, "recursive_speed_weight_bps": 6356, "private_contract_weight_bps": 7056, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_033_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_033", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7765, "recursive_speed_weight_bps": 6369, "private_contract_weight_bps": 7063, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_034_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_034", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7776, "recursive_speed_weight_bps": 6382, "private_contract_weight_bps": 7070, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_035_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_035", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7600, "recursive_speed_weight_bps": 6395, "private_contract_weight_bps": 7077, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_036_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_036", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7611, "recursive_speed_weight_bps": 6408, "private_contract_weight_bps": 7084, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_037_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_037", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7622, "recursive_speed_weight_bps": 6421, "private_contract_weight_bps": 7091, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_038_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_038", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7633, "recursive_speed_weight_bps": 6434, "private_contract_weight_bps": 7098, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_039_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_039", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7644, "recursive_speed_weight_bps": 6200, "private_contract_weight_bps": 7105, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_040_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_040", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7655, "recursive_speed_weight_bps": 6213, "private_contract_weight_bps": 7112, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_041_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_041", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7666, "recursive_speed_weight_bps": 6226, "private_contract_weight_bps": 7119, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_042_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_042", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7677, "recursive_speed_weight_bps": 6239, "private_contract_weight_bps": 7126, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_043_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_043", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7688, "recursive_speed_weight_bps": 6252, "private_contract_weight_bps": 7133, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_044_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_044", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7699, "recursive_speed_weight_bps": 6265, "private_contract_weight_bps": 7140, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_045_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_045", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7710, "recursive_speed_weight_bps": 6278, "private_contract_weight_bps": 7147, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_046_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_046", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7721, "recursive_speed_weight_bps": 6291, "private_contract_weight_bps": 7154, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_047_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_047", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7732, "recursive_speed_weight_bps": 6304, "private_contract_weight_bps": 7000, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_048_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_048", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7743, "recursive_speed_weight_bps": 6317, "private_contract_weight_bps": 7007, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_049_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_049", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7754, "recursive_speed_weight_bps": 6330, "private_contract_weight_bps": 7014, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_050_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_050", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7765, "recursive_speed_weight_bps": 6343, "private_contract_weight_bps": 7021, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_051_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_051", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7776, "recursive_speed_weight_bps": 6356, "private_contract_weight_bps": 7028, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_052_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_052", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7600, "recursive_speed_weight_bps": 6369, "private_contract_weight_bps": 7035, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_053_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_053", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7611, "recursive_speed_weight_bps": 6382, "private_contract_weight_bps": 7042, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_054_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_054", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7622, "recursive_speed_weight_bps": 6395, "private_contract_weight_bps": 7049, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_055_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_055", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7633, "recursive_speed_weight_bps": 6408, "private_contract_weight_bps": 7056, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_056_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_056", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7644, "recursive_speed_weight_bps": 6421, "private_contract_weight_bps": 7063, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_057_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_057", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7655, "recursive_speed_weight_bps": 6434, "private_contract_weight_bps": 7070, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_058_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_058", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7666, "recursive_speed_weight_bps": 6200, "private_contract_weight_bps": 7077, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_059_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_059", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7677, "recursive_speed_weight_bps": 6213, "private_contract_weight_bps": 7084, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_060_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_060", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7688, "recursive_speed_weight_bps": 6226, "private_contract_weight_bps": 7091, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_061_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_061", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7699, "recursive_speed_weight_bps": 6239, "private_contract_weight_bps": 7098, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_062_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_062", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7710, "recursive_speed_weight_bps": 6252, "private_contract_weight_bps": 7105, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_063_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_063", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7721, "recursive_speed_weight_bps": 6265, "private_contract_weight_bps": 7112, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_064_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_064", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7732, "recursive_speed_weight_bps": 6278, "private_contract_weight_bps": 7119, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_065_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_065", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7743, "recursive_speed_weight_bps": 6291, "private_contract_weight_bps": 7126, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_066_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_066", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7754, "recursive_speed_weight_bps": 6304, "private_contract_weight_bps": 7133, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_067_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_067", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7765, "recursive_speed_weight_bps": 6317, "private_contract_weight_bps": 7140, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_068_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_068", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7776, "recursive_speed_weight_bps": 6330, "private_contract_weight_bps": 7147, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_069_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_069", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7600, "recursive_speed_weight_bps": 6343, "private_contract_weight_bps": 7154, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_070_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_070", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7611, "recursive_speed_weight_bps": 6356, "private_contract_weight_bps": 7000, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_071_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_071", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7622, "recursive_speed_weight_bps": 6369, "private_contract_weight_bps": 7007, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_072_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_072", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7633, "recursive_speed_weight_bps": 6382, "private_contract_weight_bps": 7014, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_073_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_073", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7644, "recursive_speed_weight_bps": 6395, "private_contract_weight_bps": 7021, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_074_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_074", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7655, "recursive_speed_weight_bps": 6408, "private_contract_weight_bps": 7028, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_075_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_075", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7666, "recursive_speed_weight_bps": 6421, "private_contract_weight_bps": 7035, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_076_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_076", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7677, "recursive_speed_weight_bps": 6434, "private_contract_weight_bps": 7042, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_077_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_077", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7688, "recursive_speed_weight_bps": 6200, "private_contract_weight_bps": 7049, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_078_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_078", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7699, "recursive_speed_weight_bps": 6213, "private_contract_weight_bps": 7056, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_079_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_079", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7710, "recursive_speed_weight_bps": 6226, "private_contract_weight_bps": 7063, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
pub fn policy_080_record() -> Value {
    json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "policy_id": "state_witness_blob_packer_policy_080", "objective": "deterministic low fee pq confidential state witness blob packing", "da_cost_reduction_bps": 7721, "recursive_speed_weight_bps": 6239, "private_contract_weight_bps": 7070, "quantum_resistance_bits": DEFAULT_MIN_PQ_SECURITY_BITS })
}
