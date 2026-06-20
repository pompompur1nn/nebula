use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialBlobFeeRebateClearinghouseRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialBlobFeeRebateClearinghouseRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_FEE_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-blob-fee-rebate-clearinghouse-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_FEE_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTED_FEE_ROOT_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-attested-blob-fee-root-v1";
pub const CONFIDENTIAL_COUPON_SUITE: &str =
    "ML-KEM-1024-sealed-blob-fee-rebate-coupon-settlement-v1";
pub const LOW_FEE_BATCH_COMPRESSION_SUITE: &str =
    "private-l2-low-fee-batch-compression-ratio-root-v1";
pub const CONGESTION_BAND_SUITE: &str = "private-l2-blob-fee-congestion-band-clearing-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_blob_payloads_coupon_plaintexts_wallet_addresses_view_keys_or_fee_witnesses";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-blob-fee-rebate-clearinghouse-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "blob-fee-rebate-coupon-devnet";
pub const DEVNET_HEIGHT: u64 = 5_230_000;
pub const DEVNET_EPOCH: u64 = 26_144;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BASE_BLOB_FEE_MICRO_UNITS: u64 = 8_200;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_BASE_REBATE_BPS: u64 = 1_250;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 6_500;
pub const DEFAULT_MIN_COMPRESSION_BPS: u64 = 2_000;
pub const DEFAULT_TARGET_COMPRESSION_BPS: u64 = 6_800;
pub const DEFAULT_ATTESTED_ROOT_TTL_SLOTS: u64 = 2_048;
pub const DEFAULT_COUPON_TTL_SLOTS: u64 = 8_192;
pub const DEFAULT_CLEARING_WINDOW_SLOTS: u64 = 384;
pub const DEFAULT_SETTLEMENT_FINALITY_SLOTS: u64 = 32;
pub const DEFAULT_MAX_BLOB_BYTES_PER_BATCH: u64 = 16 * 1_048_576;
pub const DEFAULT_MAX_COUPONS_PER_CLEARING: usize = 65_536;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:COUNTERS";
const D_MARKETS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:MARKETS";
const D_FEE_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:FEE-ROOTS";
const D_BATCHES: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:BATCHES";
const D_COUPONS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:COUPONS";
const D_CLEARINGS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:CLEARINGS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-BLOB-FEE-REBATE-CLEARINGHOUSE:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionBand {
    Idle,
    Low,
    Normal,
    Busy,
    Surge,
    Crisis,
}

impl CongestionBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Busy => "busy",
            Self::Surge => "surge",
            Self::Crisis => "crisis",
        }
    }

    pub fn rebate_multiplier_bps(self) -> u64 {
        match self {
            Self::Idle => 2_500,
            Self::Low => 5_000,
            Self::Normal => 10_000,
            Self::Busy => 13_500,
            Self::Surge => 18_000,
            Self::Crisis => 25_000,
        }
    }

    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Idle => 5_500,
            Self::Low => 7_500,
            Self::Normal => 10_000,
            Self::Busy => 14_000,
            Self::Surge => 20_000,
            Self::Crisis => 32_000,
        }
    }

    pub fn from_blob_pressure_bps(blob_pressure_bps: u64) -> Self {
        match blob_pressure_bps {
            0..=2_499 => Self::Idle,
            2_500..=5_999 => Self::Low,
            6_000..=10_999 => Self::Normal,
            11_000..=17_499 => Self::Busy,
            17_500..=26_999 => Self::Surge,
            _ => Self::Crisis,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearinghouseStatus {
    Open,
    Attesting,
    Clearing,
    Settling,
    Settled,
}

impl ClearinghouseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attesting => "attesting",
            Self::Clearing => "clearing",
            Self::Settling => "settling",
            Self::Settled => "settled",
        }
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Open | Self::Attesting | Self::Clearing)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(self, Self::Clearing | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    PartiallySettled,
    Settled,
    Expired,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn redeemable(self) -> bool {
        matches!(self, Self::Issued | Self::PartiallySettled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchLane {
    WalletMicroBatch,
    MerchantRollup,
    BridgeExit,
    DexBundle,
    ProofAggregation,
    StateWitness,
}

impl BatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletMicroBatch => "wallet_micro_batch",
            Self::MerchantRollup => "merchant_rollup",
            Self::BridgeExit => "bridge_exit",
            Self::DexBundle => "dex_bundle",
            Self::ProofAggregation => "proof_aggregation",
            Self::StateWitness => "state_witness",
        }
    }

    pub fn compression_floor_bps(self) -> u64 {
        match self {
            Self::WalletMicroBatch => 4_500,
            Self::MerchantRollup => 5_200,
            Self::BridgeExit => 3_400,
            Self::DexBundle => 4_000,
            Self::ProofAggregation => 6_000,
            Self::StateWitness => 6_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRootPurpose {
    BlobBaseFee,
    CongestionBand,
}

impl FeeRootPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobBaseFee => "blob_base_fee",
            Self::CongestionBand => "congestion_band",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub base_blob_fee_micro_units: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub base_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_compression_bps: u64,
    pub target_compression_bps: u64,
    pub attested_root_ttl_slots: u64,
    pub coupon_ttl_slots: u64,
    pub clearing_window_slots: u64,
    pub settlement_finality_slots: u64,
    pub max_blob_bytes_per_batch: u64,
    pub max_coupons_per_clearing: usize,
    pub devnet_l2_network: String,
    pub devnet_monero_network: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            base_blob_fee_micro_units: DEFAULT_BASE_BLOB_FEE_MICRO_UNITS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            base_rebate_bps: DEFAULT_BASE_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_compression_bps: DEFAULT_MIN_COMPRESSION_BPS,
            target_compression_bps: DEFAULT_TARGET_COMPRESSION_BPS,
            attested_root_ttl_slots: DEFAULT_ATTESTED_ROOT_TTL_SLOTS,
            coupon_ttl_slots: DEFAULT_COUPON_TTL_SLOTS,
            clearing_window_slots: DEFAULT_CLEARING_WINDOW_SLOTS,
            settlement_finality_slots: DEFAULT_SETTLEMENT_FINALITY_SLOTS,
            max_blob_bytes_per_batch: DEFAULT_MAX_BLOB_BYTES_PER_BATCH,
            max_coupons_per_clearing: DEFAULT_MAX_COUPONS_PER_CLEARING,
            devnet_l2_network: DEVNET_L2_NETWORK.to_string(),
            devnet_monero_network: DEVNET_MONERO_NETWORK.to_string(),
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attested_fee_root_suite": PQ_ATTESTED_FEE_ROOT_SUITE,
            "confidential_coupon_suite": CONFIDENTIAL_COUPON_SUITE,
            "low_fee_batch_compression_suite": LOW_FEE_BATCH_COMPRESSION_SUITE,
            "congestion_band_suite": CONGESTION_BAND_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "base_blob_fee_micro_units": self.base_blob_fee_micro_units,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "base_rebate_bps": self.base_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_compression_bps": self.min_compression_bps,
            "target_compression_bps": self.target_compression_bps,
            "attested_root_ttl_slots": self.attested_root_ttl_slots,
            "coupon_ttl_slots": self.coupon_ttl_slots,
            "clearing_window_slots": self.clearing_window_slots,
            "settlement_finality_slots": self.settlement_finality_slots,
            "max_blob_bytes_per_batch": self.max_blob_bytes_per_batch,
            "max_coupons_per_clearing": self.max_coupons_per_clearing,
            "devnet_l2_network": self.devnet_l2_network,
            "devnet_monero_network": self.devnet_monero_network,
            "devnet_height": self.devnet_height,
            "devnet_epoch": self.devnet_epoch
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub clearinghouses: u64,
    pub pq_attested_fee_roots: u64,
    pub compressed_batches: u64,
    pub rebate_coupons: u64,
    pub coupon_settlements: u64,
    pub nullifiers: u64,
    pub public_events: u64,
    pub total_blob_bytes_before_compression: u64,
    pub total_blob_bytes_after_compression: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_settled_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearinghouseInput {
    pub sponsor_commitment: String,
    pub reserve_root: String,
    pub congestion_band: CongestionBand,
    pub opens_at_slot: u64,
    pub expires_at_slot: u64,
    pub reserve_micro_units: u64,
    pub max_rebate_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearinghouseEntry {
    pub clearinghouse_id: String,
    pub sponsor_commitment_redacted: String,
    pub reserve_root: String,
    pub congestion_band: CongestionBand,
    pub status: ClearinghouseStatus,
    pub opens_at_slot: u64,
    pub expires_at_slot: u64,
    pub reserve_micro_units: u64,
    pub available_micro_units: u64,
    pub max_rebate_bps: u64,
}

impl ClearinghouseEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "clearinghouse_id": self.clearinghouse_id,
            "sponsor_commitment": self.sponsor_commitment_redacted,
            "reserve_root": self.reserve_root,
            "congestion_band": self.congestion_band.as_str(),
            "status": self.status.as_str(),
            "opens_at_slot": self.opens_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "reserve_micro_units": self.reserve_micro_units,
            "available_micro_units": self.available_micro_units,
            "max_rebate_bps": self.max_rebate_bps
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestedFeeRootInput {
    pub purpose: FeeRootPurpose,
    pub fee_root: String,
    pub attestor_committee_root: String,
    pub signature_root: String,
    pub l1_blob_base_fee_micro_units: u64,
    pub l2_blob_pressure_bps: u64,
    pub observed_at_slot: u64,
    pub expires_at_slot: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestedFeeRootEntry {
    pub fee_root_id: String,
    pub purpose: FeeRootPurpose,
    pub fee_root: String,
    pub attestor_committee_root: String,
    pub signature_root: String,
    pub congestion_band: CongestionBand,
    pub l1_blob_base_fee_micro_units: u64,
    pub l2_blob_pressure_bps: u64,
    pub observed_at_slot: u64,
    pub expires_at_slot: u64,
    pub pq_security_bits: u16,
}

impl PqAttestedFeeRootEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_root_id": self.fee_root_id,
            "purpose": self.purpose.as_str(),
            "fee_root": self.fee_root,
            "attestor_committee_root": self.attestor_committee_root,
            "signature_root": self.signature_root,
            "congestion_band": self.congestion_band.as_str(),
            "l1_blob_base_fee_micro_units": self.l1_blob_base_fee_micro_units,
            "l2_blob_pressure_bps": self.l2_blob_pressure_bps,
            "observed_at_slot": self.observed_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "pq_security_bits": self.pq_security_bits
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressedBatchInput {
    pub clearinghouse_id: String,
    pub fee_root_id: String,
    pub lane: BatchLane,
    pub batch_commitment: String,
    pub compressed_blob_root: String,
    pub witness_root: String,
    pub original_blob_bytes: u64,
    pub compressed_blob_bytes: u64,
    pub user_fee_micro_units: u64,
    pub submitted_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressedBatchEntry {
    pub batch_id: String,
    pub clearinghouse_id: String,
    pub fee_root_id: String,
    pub lane: BatchLane,
    pub batch_commitment_redacted: String,
    pub compressed_blob_root: String,
    pub witness_root: String,
    pub congestion_band: CongestionBand,
    pub original_blob_bytes: u64,
    pub compressed_blob_bytes: u64,
    pub compression_bps: u64,
    pub estimated_fee_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub rebate_budget_micro_units: u64,
    pub submitted_at_slot: u64,
}

impl CompressedBatchEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "clearinghouse_id": self.clearinghouse_id,
            "fee_root_id": self.fee_root_id,
            "lane": self.lane.as_str(),
            "batch_commitment": self.batch_commitment_redacted,
            "compressed_blob_root": self.compressed_blob_root,
            "witness_root": self.witness_root,
            "congestion_band": self.congestion_band.as_str(),
            "original_blob_bytes": self.original_blob_bytes,
            "compressed_blob_bytes": self.compressed_blob_bytes,
            "compression_bps": self.compression_bps,
            "estimated_fee_micro_units": self.estimated_fee_micro_units,
            "user_fee_micro_units": self.user_fee_micro_units,
            "rebate_budget_micro_units": self.rebate_budget_micro_units,
            "submitted_at_slot": self.submitted_at_slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCouponInput {
    pub batch_id: String,
    pub owner_commitment: String,
    pub coupon_note_root: String,
    pub coupon_nullifier: String,
    pub requested_rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub issued_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCouponEntry {
    pub coupon_id: String,
    pub batch_id: String,
    pub owner_commitment_redacted: String,
    pub coupon_note_root: String,
    pub coupon_nullifier_hash: String,
    pub status: CouponStatus,
    pub requested_rebate_micro_units: u64,
    pub settled_rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub issued_at_slot: u64,
    pub expires_at_slot: u64,
}

impl RebateCouponEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "batch_id": self.batch_id,
            "owner_commitment": self.owner_commitment_redacted,
            "coupon_note_root": self.coupon_note_root,
            "coupon_nullifier_hash": self.coupon_nullifier_hash,
            "status": self.status.as_str(),
            "requested_rebate_micro_units": self.requested_rebate_micro_units,
            "settled_rebate_micro_units": self.settled_rebate_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_slot": self.issued_at_slot,
            "expires_at_slot": self.expires_at_slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponSettlementInput {
    pub clearinghouse_id: String,
    pub settlement_root: String,
    pub coupon_ids: Vec<String>,
    pub settlement_nullifier: String,
    pub settled_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponSettlementEntry {
    pub settlement_id: String,
    pub clearinghouse_id: String,
    pub settlement_root: String,
    pub coupon_count: usize,
    pub settled_rebate_micro_units: u64,
    pub remainder_micro_units: u64,
    pub settlement_nullifier_hash: String,
    pub settled_at_slot: u64,
    pub finality_slot: u64,
}

impl CouponSettlementEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "clearinghouse_id": self.clearinghouse_id,
            "settlement_root": self.settlement_root,
            "coupon_count": self.coupon_count,
            "settled_rebate_micro_units": self.settled_rebate_micro_units,
            "remainder_micro_units": self.remainder_micro_units,
            "settlement_nullifier_hash": self.settlement_nullifier_hash,
            "settled_at_slot": self.settled_at_slot,
            "finality_slot": self.finality_slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub clearinghouses: BTreeMap<String, ClearinghouseEntry>,
    pub pq_attested_fee_roots: BTreeMap<String, PqAttestedFeeRootEntry>,
    pub compressed_batches: BTreeMap<String, CompressedBatchEntry>,
    pub rebate_coupons: BTreeMap<String, RebateCouponEntry>,
    pub coupon_settlements: BTreeMap<String, CouponSettlementEntry>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
    pub roots: BTreeMap<String, String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            clearinghouses: BTreeMap::new(),
            pq_attested_fee_roots: BTreeMap::new(),
            compressed_batches: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            coupon_settlements: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
            roots: BTreeMap::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn open_clearinghouse(&mut self, input: ClearinghouseInput) -> Result<String> {
        if input.expires_at_slot <= input.opens_at_slot {
            return Err("clearinghouse expiry must be after open slot".to_string());
        }
        if input.max_rebate_bps > self.config.max_rebate_bps {
            return Err(format!(
                "max rebate bps {} exceeds configured limit {}",
                input.max_rebate_bps, self.config.max_rebate_bps
            ));
        }
        if input.reserve_micro_units == 0 {
            return Err("clearinghouse reserve must be non-zero".to_string());
        }
        let clearinghouse_id = deterministic_id(
            "blob-fee-rebate-clearinghouse",
            &[
                &input.sponsor_commitment,
                &input.reserve_root,
                input.congestion_band.as_str(),
                &input.opens_at_slot.to_string(),
            ],
        );
        if self.clearinghouses.contains_key(&clearinghouse_id) {
            return Err(format!("clearinghouse {clearinghouse_id} already exists"));
        }
        let entry = ClearinghouseEntry {
            clearinghouse_id: clearinghouse_id.clone(),
            sponsor_commitment_redacted: redacted_commitment(&input.sponsor_commitment),
            reserve_root: input.reserve_root,
            congestion_band: input.congestion_band,
            status: ClearinghouseStatus::Open,
            opens_at_slot: input.opens_at_slot,
            expires_at_slot: input.expires_at_slot,
            reserve_micro_units: input.reserve_micro_units,
            available_micro_units: input.reserve_micro_units,
            max_rebate_bps: input.max_rebate_bps,
        };
        self.clearinghouses.insert(clearinghouse_id.clone(), entry);
        self.counters.clearinghouses = self.clearinghouses.len() as u64;
        self.push_event("clearinghouse_opened", &clearinghouse_id);
        self.recompute_roots();
        Ok(clearinghouse_id)
    }

    pub fn attest_fee_root(&mut self, input: PqAttestedFeeRootInput) -> Result<String> {
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "pq security bits {} below minimum {}",
                input.pq_security_bits, self.config.min_pq_security_bits
            ));
        }
        if input.expires_at_slot <= input.observed_at_slot {
            return Err("attested fee root expiry must be after observation slot".to_string());
        }
        if input.expires_at_slot - input.observed_at_slot > self.config.attested_root_ttl_slots {
            return Err("attested fee root ttl exceeds configured maximum".to_string());
        }
        let congestion_band = CongestionBand::from_blob_pressure_bps(input.l2_blob_pressure_bps);
        let fee_root_id = deterministic_id(
            "pq-attested-blob-fee-root",
            &[
                input.purpose.as_str(),
                &input.fee_root,
                &input.attestor_committee_root,
                &input.observed_at_slot.to_string(),
            ],
        );
        if self.pq_attested_fee_roots.contains_key(&fee_root_id) {
            return Err(format!("attested fee root {fee_root_id} already exists"));
        }
        let entry = PqAttestedFeeRootEntry {
            fee_root_id: fee_root_id.clone(),
            purpose: input.purpose,
            fee_root: input.fee_root,
            attestor_committee_root: input.attestor_committee_root,
            signature_root: input.signature_root,
            congestion_band,
            l1_blob_base_fee_micro_units: input.l1_blob_base_fee_micro_units,
            l2_blob_pressure_bps: input.l2_blob_pressure_bps,
            observed_at_slot: input.observed_at_slot,
            expires_at_slot: input.expires_at_slot,
            pq_security_bits: input.pq_security_bits,
        };
        self.pq_attested_fee_roots
            .insert(fee_root_id.clone(), entry);
        self.counters.pq_attested_fee_roots = self.pq_attested_fee_roots.len() as u64;
        self.push_event("pq_attested_fee_root_accepted", &fee_root_id);
        self.recompute_roots();
        Ok(fee_root_id)
    }

    pub fn submit_compressed_batch(&mut self, input: CompressedBatchInput) -> Result<String> {
        let clearinghouse = self
            .clearinghouses
            .get(&input.clearinghouse_id)
            .ok_or_else(|| format!("missing clearinghouse {}", input.clearinghouse_id))?;
        if !clearinghouse.status.accepts_batches() {
            return Err(format!(
                "clearinghouse {} does not accept batches",
                input.clearinghouse_id
            ));
        }
        if input.submitted_at_slot < clearinghouse.opens_at_slot
            || input.submitted_at_slot > clearinghouse.expires_at_slot
        {
            return Err("batch submitted outside clearinghouse window".to_string());
        }
        let fee_root = self
            .pq_attested_fee_roots
            .get(&input.fee_root_id)
            .ok_or_else(|| format!("missing attested fee root {}", input.fee_root_id))?;
        if input.submitted_at_slot > fee_root.expires_at_slot {
            return Err("batch submitted against expired attested fee root".to_string());
        }
        if input.original_blob_bytes == 0 || input.compressed_blob_bytes == 0 {
            return Err("blob batch byte sizes must be non-zero".to_string());
        }
        if input.compressed_blob_bytes > input.original_blob_bytes {
            return Err("compressed blob bytes exceed original blob bytes".to_string());
        }
        if input.original_blob_bytes > self.config.max_blob_bytes_per_batch {
            return Err("batch exceeds maximum blob bytes".to_string());
        }
        let compression_bps =
            compression_savings_bps(input.original_blob_bytes, input.compressed_blob_bytes);
        let required_floor = self
            .config
            .min_compression_bps
            .max(input.lane.compression_floor_bps());
        if compression_bps < required_floor {
            return Err(format!(
                "compression savings {compression_bps} bps below required floor {required_floor}"
            ));
        }
        let estimated_fee_micro_units = estimated_blob_fee(
            &self.config,
            fee_root.congestion_band,
            fee_root.l1_blob_base_fee_micro_units,
            input.compressed_blob_bytes,
        );
        let rebate_budget_micro_units = rebate_budget(
            &self.config,
            fee_root.congestion_band,
            compression_bps,
            estimated_fee_micro_units,
            input.user_fee_micro_units,
            clearinghouse.max_rebate_bps,
        );
        let batch_id = deterministic_id(
            "low-fee-compressed-blob-batch",
            &[
                &input.clearinghouse_id,
                &input.fee_root_id,
                &input.batch_commitment,
                &input.submitted_at_slot.to_string(),
            ],
        );
        if self.compressed_batches.contains_key(&batch_id) {
            return Err(format!("compressed batch {batch_id} already exists"));
        }
        let entry = CompressedBatchEntry {
            batch_id: batch_id.clone(),
            clearinghouse_id: input.clearinghouse_id,
            fee_root_id: input.fee_root_id,
            lane: input.lane,
            batch_commitment_redacted: redacted_commitment(&input.batch_commitment),
            compressed_blob_root: input.compressed_blob_root,
            witness_root: input.witness_root,
            congestion_band: fee_root.congestion_band,
            original_blob_bytes: input.original_blob_bytes,
            compressed_blob_bytes: input.compressed_blob_bytes,
            compression_bps,
            estimated_fee_micro_units,
            user_fee_micro_units: input.user_fee_micro_units,
            rebate_budget_micro_units,
            submitted_at_slot: input.submitted_at_slot,
        };
        self.counters.total_blob_bytes_before_compression = self
            .counters
            .total_blob_bytes_before_compression
            .saturating_add(entry.original_blob_bytes);
        self.counters.total_blob_bytes_after_compression = self
            .counters
            .total_blob_bytes_after_compression
            .saturating_add(entry.compressed_blob_bytes);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(entry.estimated_fee_micro_units);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(entry.rebate_budget_micro_units);
        self.compressed_batches.insert(batch_id.clone(), entry);
        self.counters.compressed_batches = self.compressed_batches.len() as u64;
        self.push_event("compressed_blob_batch_submitted", &batch_id);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn issue_rebate_coupon(&mut self, input: RebateCouponInput) -> Result<String> {
        ensure_nullifier_available(&self.consumed_nullifiers, &input.coupon_nullifier)?;
        let batch = self
            .compressed_batches
            .get(&input.batch_id)
            .ok_or_else(|| format!("missing compressed batch {}", input.batch_id))?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("coupon privacy set below configured minimum".to_string());
        }
        if input.requested_rebate_micro_units == 0 {
            return Err("requested rebate must be non-zero".to_string());
        }
        if input.requested_rebate_micro_units > batch.rebate_budget_micro_units {
            return Err("requested rebate exceeds batch rebate budget".to_string());
        }
        let coupon_id = deterministic_id(
            "blob-fee-rebate-coupon",
            &[
                &input.batch_id,
                &input.owner_commitment,
                &input.coupon_note_root,
                &input.issued_at_slot.to_string(),
            ],
        );
        if self.rebate_coupons.contains_key(&coupon_id) {
            return Err(format!("coupon {coupon_id} already exists"));
        }
        let entry = RebateCouponEntry {
            coupon_id: coupon_id.clone(),
            batch_id: input.batch_id,
            owner_commitment_redacted: redacted_commitment(&input.owner_commitment),
            coupon_note_root: input.coupon_note_root,
            coupon_nullifier_hash: nullifier_hash(&input.coupon_nullifier),
            status: CouponStatus::Issued,
            requested_rebate_micro_units: input.requested_rebate_micro_units,
            settled_rebate_micro_units: 0,
            privacy_set_size: input.privacy_set_size,
            issued_at_slot: input.issued_at_slot,
            expires_at_slot: input
                .issued_at_slot
                .saturating_add(self.config.coupon_ttl_slots),
        };
        self.consumed_nullifiers.insert(input.coupon_nullifier);
        self.rebate_coupons.insert(coupon_id.clone(), entry);
        self.counters.rebate_coupons = self.rebate_coupons.len() as u64;
        self.counters.nullifiers = self.consumed_nullifiers.len() as u64;
        self.push_event("rebate_coupon_issued", &coupon_id);
        self.recompute_roots();
        Ok(coupon_id)
    }

    pub fn settle_coupons(&mut self, input: CouponSettlementInput) -> Result<String> {
        ensure_nullifier_available(&self.consumed_nullifiers, &input.settlement_nullifier)?;
        if input.coupon_ids.is_empty() {
            return Err("settlement must include at least one coupon".to_string());
        }
        if input.coupon_ids.len() > self.config.max_coupons_per_clearing {
            return Err("settlement exceeds maximum coupons per clearing".to_string());
        }
        let clearinghouse = self
            .clearinghouses
            .get(&input.clearinghouse_id)
            .ok_or_else(|| format!("missing clearinghouse {}", input.clearinghouse_id))?;
        if !clearinghouse.status.accepts_settlement()
            && clearinghouse.status != ClearinghouseStatus::Open
        {
            return Err("clearinghouse does not accept coupon settlement".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut requested_total = 0_u64;
        for coupon_id in &input.coupon_ids {
            if !seen.insert(coupon_id.clone()) {
                return Err(format!("coupon {coupon_id} duplicated in settlement"));
            }
            let coupon = self
                .rebate_coupons
                .get(coupon_id)
                .ok_or_else(|| format!("missing coupon {coupon_id}"))?;
            if !coupon.status.redeemable() {
                return Err(format!("coupon {coupon_id} is not redeemable"));
            }
            if input.settled_at_slot > coupon.expires_at_slot {
                return Err(format!("coupon {coupon_id} expired before settlement"));
            }
            let batch = self
                .compressed_batches
                .get(&coupon.batch_id)
                .ok_or_else(|| format!("missing batch {}", coupon.batch_id))?;
            if batch.clearinghouse_id != input.clearinghouse_id {
                return Err(format!(
                    "coupon {coupon_id} belongs to clearinghouse {}",
                    batch.clearinghouse_id
                ));
            }
            requested_total = requested_total.saturating_add(
                coupon
                    .requested_rebate_micro_units
                    .saturating_sub(coupon.settled_rebate_micro_units),
            );
        }
        let available = clearinghouse.available_micro_units;
        let settled_total = requested_total.min(available);
        let mut remaining = settled_total;
        for coupon_id in &input.coupon_ids {
            let coupon = self
                .rebate_coupons
                .get_mut(coupon_id)
                .expect("coupon checked above");
            let unsettled = coupon
                .requested_rebate_micro_units
                .saturating_sub(coupon.settled_rebate_micro_units);
            let credit = unsettled.min(remaining);
            coupon.settled_rebate_micro_units =
                coupon.settled_rebate_micro_units.saturating_add(credit);
            remaining = remaining.saturating_sub(credit);
            coupon.status =
                if coupon.settled_rebate_micro_units >= coupon.requested_rebate_micro_units {
                    CouponStatus::Settled
                } else {
                    CouponStatus::PartiallySettled
                };
        }
        let clearinghouse = self
            .clearinghouses
            .get_mut(&input.clearinghouse_id)
            .expect("clearinghouse checked above");
        clearinghouse.available_micro_units = clearinghouse
            .available_micro_units
            .saturating_sub(settled_total);
        clearinghouse.status = if clearinghouse.available_micro_units == 0 {
            ClearinghouseStatus::Settled
        } else {
            ClearinghouseStatus::Settling
        };
        let settlement_id = deterministic_id(
            "blob-fee-rebate-coupon-settlement",
            &[
                &input.clearinghouse_id,
                &input.settlement_root,
                &input.settled_at_slot.to_string(),
            ],
        );
        if self.coupon_settlements.contains_key(&settlement_id) {
            return Err(format!("settlement {settlement_id} already exists"));
        }
        let entry = CouponSettlementEntry {
            settlement_id: settlement_id.clone(),
            clearinghouse_id: input.clearinghouse_id,
            settlement_root: input.settlement_root,
            coupon_count: input.coupon_ids.len(),
            settled_rebate_micro_units: settled_total,
            remainder_micro_units: requested_total.saturating_sub(settled_total),
            settlement_nullifier_hash: nullifier_hash(&input.settlement_nullifier),
            settled_at_slot: input.settled_at_slot,
            finality_slot: input
                .settled_at_slot
                .saturating_add(self.config.settlement_finality_slots),
        };
        self.consumed_nullifiers.insert(input.settlement_nullifier);
        self.coupon_settlements.insert(settlement_id.clone(), entry);
        self.counters.coupon_settlements = self.coupon_settlements.len() as u64;
        self.counters.nullifiers = self.consumed_nullifiers.len() as u64;
        self.counters.total_settled_micro_units = self
            .counters
            .total_settled_micro_units
            .saturating_add(settled_total);
        self.push_event("rebate_coupons_settled", &settlement_id);
        self.recompute_roots();
        Ok(settlement_id)
    }

    pub fn roots_record(&self) -> Value {
        json!({
            "config": self.config.state_root(),
            "counters": self.counters.state_root(),
            "clearinghouses": map_root(D_MARKETS, &self.clearinghouses, ClearinghouseEntry::public_record),
            "pq_attested_fee_roots": map_root(D_FEE_ROOTS, &self.pq_attested_fee_roots, PqAttestedFeeRootEntry::public_record),
            "compressed_batches": map_root(D_BATCHES, &self.compressed_batches, CompressedBatchEntry::public_record),
            "rebate_coupons": map_root(D_COUPONS, &self.rebate_coupons, RebateCouponEntry::public_record),
            "coupon_settlements": map_root(D_CLEARINGS, &self.coupon_settlements, CouponSettlementEntry::public_record),
            "consumed_nullifiers": set_root(D_NULLIFIERS, &self.consumed_nullifiers),
            "public_events": list_root(D_EVENTS, &self.public_events)
        })
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots_record(),
            "public_events": self.public_events
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(
            &mut record,
            "state_root",
            json!(state_root_from_public_record(&record)),
        );
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn recompute_roots(&mut self) {
        let roots = self.roots_record();
        self.roots.clear();
        if let Value::Object(values) = roots {
            for (key, value) in values {
                if let Some(value) = value.as_str() {
                    self.roots.insert(key, value.to_string());
                }
            }
        }
    }

    fn push_event(&mut self, event_type: &str, subject_id: &str) {
        if self.public_events.len() >= DEFAULT_MAX_PUBLIC_EVENTS {
            return;
        }
        self.public_events.push(json!({
            "event_index": self.public_events.len(),
            "event_type": event_type,
            "subject_id": subject_id,
            "event_root": record_root(
                D_EVENTS,
                &json!({
                    "event_type": event_type,
                    "subject_id": subject_id,
                    "protocol_version": PROTOCOL_VERSION
                })
            )
        }));
        self.counters.public_events = self.public_events.len() as u64;
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let clearinghouse_id = state
        .open_clearinghouse(ClearinghouseInput {
            sponsor_commitment: "devnet-sponsor-blob-fee-rebate-clearinghouse".to_string(),
            reserve_root: demo_root("rebate-reserve-root"),
            congestion_band: CongestionBand::Normal,
            opens_at_slot: DEVNET_EPOCH,
            expires_at_slot: DEVNET_EPOCH + DEFAULT_CLEARING_WINDOW_SLOTS,
            reserve_micro_units: 9_500_000_000,
            max_rebate_bps: 5_200,
        })
        .expect("devnet clearinghouse opens");
    let fee_root_id = state
        .attest_fee_root(PqAttestedFeeRootInput {
            purpose: FeeRootPurpose::BlobBaseFee,
            fee_root: demo_root("pq-attested-blob-base-fee-root"),
            attestor_committee_root: demo_root("pq-attestor-committee-root"),
            signature_root: demo_root("pq-signature-aggregate-root"),
            l1_blob_base_fee_micro_units: 11_400,
            l2_blob_pressure_bps: 14_200,
            observed_at_slot: DEVNET_EPOCH + 2,
            expires_at_slot: DEVNET_EPOCH + 2 + DEFAULT_ATTESTED_ROOT_TTL_SLOTS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet fee root attests");
    let batch_id = state
        .submit_compressed_batch(CompressedBatchInput {
            clearinghouse_id: clearinghouse_id.clone(),
            fee_root_id,
            lane: BatchLane::ProofAggregation,
            batch_commitment: "devnet-compressed-blob-batch-commitment".to_string(),
            compressed_blob_root: demo_root("compressed-blob-root"),
            witness_root: demo_root("compressed-witness-root"),
            original_blob_bytes: 5_242_880,
            compressed_blob_bytes: 1_572_864,
            user_fee_micro_units: 6_900,
            submitted_at_slot: DEVNET_EPOCH + 8,
        })
        .expect("devnet compressed batch submits");
    let coupon_a = state
        .issue_rebate_coupon(RebateCouponInput {
            batch_id: batch_id.clone(),
            owner_commitment: "devnet-wallet-owner-commitment-a".to_string(),
            coupon_note_root: demo_root("coupon-note-root-a"),
            coupon_nullifier: "nullifier:devnet-blob-fee-rebate-coupon-a".to_string(),
            requested_rebate_micro_units: 420_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            issued_at_slot: DEVNET_EPOCH + 10,
        })
        .expect("devnet coupon a issues");
    let coupon_b = state
        .issue_rebate_coupon(RebateCouponInput {
            batch_id,
            owner_commitment: "devnet-wallet-owner-commitment-b".to_string(),
            coupon_note_root: demo_root("coupon-note-root-b"),
            coupon_nullifier: "nullifier:devnet-blob-fee-rebate-coupon-b".to_string(),
            requested_rebate_micro_units: 380_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            issued_at_slot: DEVNET_EPOCH + 11,
        })
        .expect("devnet coupon b issues");
    state
        .settle_coupons(CouponSettlementInput {
            clearinghouse_id,
            settlement_root: demo_root("coupon-settlement-root"),
            coupon_ids: vec![coupon_a, coupon_b],
            settlement_nullifier: "nullifier:devnet-blob-fee-rebate-settlement".to_string(),
            settled_at_slot: DEVNET_EPOCH + 24,
        })
        .expect("devnet coupons settle");
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record_root": record_root(domain, &json!({ "key": key, "record": public_record(value) }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set.iter().map(|value| json!({ "value": value })).collect();
    merkle_root(domain, &leaves)
}

fn list_root(domain: &str, values: &[Value]) -> String {
    let leaves: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json!({
                "index": index,
                "record_root": record_root(domain, &json!({ "index": index, "record": value }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn state_root_from_public_record(record: &Value) -> String {
    record_root(D_STATE, record)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn deterministic_id(label: &str, parts: &[&str]) -> String {
    format!("{label}:{}", deterministic_leaf(label, parts))
}

fn deterministic_leaf(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-FEE-REBATE-CLEARINGHOUSE:{domain}"),
        &hash_parts,
        32,
    )
}

fn demo_root(label: &str) -> String {
    deterministic_leaf("demo-root", &[label])
}

fn compression_savings_bps(original_blob_bytes: u64, compressed_blob_bytes: u64) -> u64 {
    if original_blob_bytes == 0 || compressed_blob_bytes >= original_blob_bytes {
        return 0;
    }
    original_blob_bytes
        .saturating_sub(compressed_blob_bytes)
        .saturating_mul(MAX_BPS)
        .saturating_div(original_blob_bytes)
}

fn estimated_blob_fee(
    config: &Config,
    congestion_band: CongestionBand,
    l1_blob_base_fee_micro_units: u64,
    compressed_blob_bytes: u64,
) -> u64 {
    let chunks = compressed_blob_bytes
        .saturating_add(131_071)
        .saturating_div(131_072);
    let base = config
        .base_blob_fee_micro_units
        .saturating_add(l1_blob_base_fee_micro_units);
    base.saturating_mul(chunks)
        .saturating_mul(congestion_band.fee_multiplier_bps())
        .saturating_div(MAX_BPS)
}

fn rebate_budget(
    config: &Config,
    congestion_band: CongestionBand,
    compression_bps: u64,
    estimated_fee_micro_units: u64,
    user_fee_micro_units: u64,
    clearinghouse_max_rebate_bps: u64,
) -> u64 {
    let user_fee_cap = estimated_fee_micro_units
        .saturating_mul(config.max_user_fee_bps)
        .saturating_div(MAX_BPS);
    let overage = estimated_fee_micro_units.saturating_sub(user_fee_micro_units.min(user_fee_cap));
    let compression_bonus_bps = compression_bps
        .saturating_mul(config.base_rebate_bps)
        .saturating_div(config.target_compression_bps.max(1))
        .min(config.max_rebate_bps);
    let band_adjusted_bps = compression_bonus_bps
        .saturating_mul(congestion_band.rebate_multiplier_bps())
        .saturating_div(MAX_BPS)
        .min(clearinghouse_max_rebate_bps)
        .min(config.max_rebate_bps);
    overage
        .saturating_mul(band_adjusted_bps)
        .saturating_div(MAX_BPS)
}

fn ensure_nullifier_available(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    if nullifiers.contains(nullifier) {
        Err(format!("nullifier {nullifier} already consumed"))
    } else {
        Ok(())
    }
}

fn nullifier_hash(nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-FEE-REBATE-CLEARINGHOUSE:NULLIFIER-HASH",
        &[HashPart::Str(nullifier)],
        32,
    )
}

fn redacted_commitment(commitment: &str) -> String {
    if commitment.is_empty() {
        return "redacted:empty".to_string();
    }
    let digest = domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-FEE-REBATE-CLEARINGHOUSE:REDACTED-COMMITMENT",
        &[HashPart::Str(commitment)],
        16,
    );
    format!("redacted:{digest}")
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(object) = record {
        object.insert(key.to_string(), value);
    }
}
