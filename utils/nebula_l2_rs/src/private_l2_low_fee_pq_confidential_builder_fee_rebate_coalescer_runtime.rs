use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialBuilderFeeRebateCoalescerRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialBuilderFeeRebateCoalescerRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BUILDER_FEE_REBATE_COALESCER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-BUILDER-FEE-REBATE-coalescer-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BUILDER_FEE_REBATE_COALESCER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BLOCK_BUILDER_COUPON_LANE_SUITE: &str =
    "ML-KEM-1024-sealed-private-l2-builder-fee-block-builder-coupon-lanes-v1";
pub const CONGESTION_DISCOUNT_SUITE: &str =
    "private-l2-low-fee-builder-fee-congestion-discount-coalescer-v1";
pub const PQ_ATTESTED_BUILDER_FEE_ROOT_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-attested-builder-fee-root-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str =
    "private-l2-low-fee-BUILDER-FEE-REBATE-settlement-batch-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-BUILDER-FEE-REBATE-coalescer-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_tx_plaintexts_sender_addresses_builder_wallets_view_keys_coupon_plaintexts_builder_fee_witnesses_or_bid_traces";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "BUILDER-FEE-REBATE-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 5_590_000;
pub const DEVNET_EPOCH: u64 = 54_400;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_USER_BUILDER_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_USER_BUILDER_FEE_BPS: u64 = 12;
pub const DEFAULT_BASE_BUILDER_COVER_BPS: u64 = 8_900;
pub const DEFAULT_MAX_BUILDER_COVER_BPS: u64 = 9_950;
pub const DEFAULT_BASE_REBATE_BPS: u64 = 1_100;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 7_200;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2_097_152;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BUILDER_FEE_ROOT_TTL_SLOTS: u64 = 540;
pub const DEFAULT_COUPON_LANE_TTL_SLOTS: u64 = 8_640;
pub const DEFAULT_COALESCING_WINDOW_SLOTS: u64 = 72;
pub const DEFAULT_SETTLEMENT_FINALITY_SLOTS: u64 = 42;
pub const DEFAULT_MAX_CLAIMS_PER_BATCH: usize = 98_304;
pub const DEFAULT_MAX_LANES_PER_BATCH: usize = 320;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:ROOTS";
const D_LANES: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:LANES";
const D_CLAIMS: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:CLAIMS";
const D_DISCOUNTS: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:DISCOUNTS";
const D_BUILDER_FEE_ROOTS: &str =
    "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:BUILDER-FEE-ROOTS";
const D_BATCHES: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:BATCHES";
const D_RECEIPTS: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:RECEIPTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:EVENTS";
const D_PUBLIC: &str = "PL2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:PUBLIC";

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockBuilderCouponLaneKind {
    WalletOnboarding,
    MerchantCheckout,
    BridgeExit,
    ContractCall,
    PaymasterIntent,
    BatchAuction,
    BuilderAuction,
    BlockBuilderRelief,
    EmergencyWithdrawal,
}

impl BlockBuilderCouponLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletOnboarding => "wallet_onboarding",
            Self::MerchantCheckout => "merchant_checkout",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::PaymasterIntent => "paymaster_intent",
            Self::BatchAuction => "batch_auction",
            Self::BuilderAuction => "builder_auction",
            Self::BlockBuilderRelief => "block_builder_relief",
            Self::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }

    pub fn builder_lane_weight(self) -> u64 {
        match self {
            Self::EmergencyWithdrawal => 10_000,
            Self::BridgeExit => 9_650,
            Self::BuilderAuction => 9_250,
            Self::ContractCall => 8_850,
            Self::PaymasterIntent => 8_450,
            Self::BlockBuilderRelief => 8_150,
            Self::BatchAuction => 7_700,
            Self::MerchantCheckout => 7_150,
            Self::WalletOnboarding => 6_800,
        }
    }

    pub fn default_cover_bps(self, config: &Config) -> u64 {
        let bump = match self {
            Self::EmergencyWithdrawal => 1_000,
            Self::BridgeExit => 700,
            Self::BuilderAuction => 520,
            Self::ContractCall => 300,
            Self::PaymasterIntent => 360,
            Self::BlockBuilderRelief => 260,
            Self::BatchAuction => 160,
            Self::MerchantCheckout => 90,
            Self::WalletOnboarding => 50,
        };
        config
            .base_builder_cover_bps
            .saturating_add(bump)
            .min(config.max_builder_cover_bps)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Draft,
    Attested,
    Open,
    Throttled,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Attested => "attested",
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Attested | Self::Open | Self::Throttled)
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuilderFeeClaimStatus {
    Observed,
    Attested,
    Coalesced,
    Settled,
    Expired,
    Quarantined,
}

impl BuilderFeeClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Attested => "attested",
            Self::Coalesced => "coalesced",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Observed | Self::Attested | Self::Coalesced)
    }
}

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

    pub fn from_builder_pressure_bps(pressure_bps: u64) -> Self {
        match pressure_bps {
            0..=1_999 => Self::Idle,
            2_000..=5_499 => Self::Low,
            5_500..=9_999 => Self::Normal,
            10_000..=16_999 => Self::Busy,
            17_000..=25_999 => Self::Surge,
            _ => Self::Crisis,
        }
    }

    pub fn discount_bps(self) -> u64 {
        match self {
            Self::Idle => 220,
            Self::Low => 620,
            Self::Normal => 1_180,
            Self::Busy => 2_250,
            Self::Surge => 3_700,
            Self::Crisis => 5_100,
        }
    }

    pub fn coalescing_weight(self) -> u64 {
        match self {
            Self::Idle => 5_300,
            Self::Low => 6_300,
            Self::Normal => 7_500,
            Self::Busy => 8_800,
            Self::Surge => 9_600,
            Self::Crisis => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuilderFeeRootPurpose {
    PendingBuilderSnapshot,
    CouponLaneInventory,
    CongestionDiscountWindow,
    CoalescedRebateQueue,
    LowFeeSettlementBatch,
    ReceiptAccumulator,
}

impl BuilderFeeRootPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingBuilderSnapshot => "pending_builder_snapshot",
            Self::CouponLaneInventory => "coupon_lane_inventory",
            Self::CongestionDiscountWindow => "congestion_discount_window",
            Self::CoalescedRebateQueue => "coalesced_rebate_queue",
            Self::LowFeeSettlementBatch => "low_fee_settlement_batch",
            Self::ReceiptAccumulator => "receipt_accumulator",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Draft,
    Built,
    Attested,
    Submitted,
    Settled,
    ReorgBuffered,
    Rejected,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Built => "built",
            Self::Attested => "attested",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::ReorgBuffered => "reorg_buffered",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub target_user_builder_fee_bps: u64,
    pub max_user_builder_fee_bps: u64,
    pub base_builder_cover_bps: u64,
    pub max_builder_cover_bps: u64,
    pub base_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub builder_root_ttl_slots: u64,
    pub coupon_lane_ttl_slots: u64,
    pub coalescing_window_slots: u64,
    pub settlement_finality_slots: u64,
    pub max_claims_per_batch: usize,
    pub max_lanes_per_batch: usize,
    pub max_public_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            target_user_builder_fee_bps: DEFAULT_TARGET_USER_BUILDER_FEE_BPS,
            max_user_builder_fee_bps: DEFAULT_MAX_USER_BUILDER_FEE_BPS,
            base_builder_cover_bps: DEFAULT_BASE_BUILDER_COVER_BPS,
            max_builder_cover_bps: DEFAULT_MAX_BUILDER_COVER_BPS,
            base_rebate_bps: DEFAULT_BASE_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            builder_root_ttl_slots: DEFAULT_BUILDER_FEE_ROOT_TTL_SLOTS,
            coupon_lane_ttl_slots: DEFAULT_COUPON_LANE_TTL_SLOTS,
            coalescing_window_slots: DEFAULT_COALESCING_WINDOW_SLOTS,
            settlement_finality_slots: DEFAULT_SETTLEMENT_FINALITY_SLOTS,
            max_claims_per_batch: DEFAULT_MAX_CLAIMS_PER_BATCH,
            max_lanes_per_batch: DEFAULT_MAX_LANES_PER_BATCH,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "target_user_builder_fee_bps": self.target_user_builder_fee_bps,
            "max_user_builder_fee_bps": self.max_user_builder_fee_bps,
            "base_builder_cover_bps": self.base_builder_cover_bps,
            "max_builder_cover_bps": self.max_builder_cover_bps,
            "base_rebate_bps": self.base_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "builder_root_ttl_slots": self.builder_root_ttl_slots,
            "coupon_lane_ttl_slots": self.coupon_lane_ttl_slots,
            "coalescing_window_slots": self.coalescing_window_slots,
            "settlement_finality_slots": self.settlement_finality_slots,
            "max_claims_per_batch": self.max_claims_per_batch,
            "max_lanes_per_batch": self.max_lanes_per_batch,
            "max_public_events": self.max_public_events,
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_bps(
            "target_user_builder_fee_bps",
            self.target_user_builder_fee_bps,
        )?;
        ensure_bps("max_user_builder_fee_bps", self.max_user_builder_fee_bps)?;
        ensure_bps("base_builder_cover_bps", self.base_builder_cover_bps)?;
        ensure_bps("max_builder_cover_bps", self.max_builder_cover_bps)?;
        ensure_bps("base_rebate_bps", self.base_rebate_bps)?;
        ensure_bps("max_rebate_bps", self.max_rebate_bps)?;
        ensure!(
            self.target_user_builder_fee_bps <= self.max_user_builder_fee_bps,
            "target builder fee bps exceeds max builder fee bps"
        );
        ensure!(
            self.base_builder_cover_bps <= self.max_builder_cover_bps,
            "base builder cover bps exceeds max builder cover bps"
        );
        ensure!(
            self.base_rebate_bps <= self.max_rebate_bps,
            "base rebate bps exceeds max rebate bps"
        );
        ensure!(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "min privacy set exceeds target privacy set"
        );
        ensure!(
            self.min_pq_security_bits >= 192,
            "minimum pq security bits is below policy floor"
        );
        ensure!(
            self.builder_root_ttl_slots > self.coalescing_window_slots,
            "builder root ttl must exceed coalescing window"
        );
        ensure!(
            self.max_claims_per_batch > 0 && self.max_lanes_per_batch > 0,
            "batch limits must be non-zero"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub block_builder_coupon_lanes_opened: u64,
    pub block_builder_coupon_lanes_retired: u64,
    pub builder_fee_claims_observed: u64,
    pub builder_fee_claims_coalesced: u64,
    pub builder_fee_claims_settled: u64,
    pub congestion_discounts_recorded: u64,
    pub pq_builder_roots_attested: u64,
    pub settlement_batches_built: u64,
    pub settlement_batches_settled: u64,
    pub settlement_receipts_recorded: u64,
    pub total_builder_fee_piconero: u128,
    pub total_user_builder_fee_piconero: u128,
    pub total_builder_covered_piconero: u128,
    pub total_rebate_piconero: u128,
    pub total_discount_piconero: u128,
    pub events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "block_builder_coupon_lanes_opened": self.block_builder_coupon_lanes_opened,
            "block_builder_coupon_lanes_retired": self.block_builder_coupon_lanes_retired,
            "builder_fee_claims_observed": self.builder_fee_claims_observed,
            "builder_fee_claims_coalesced": self.builder_fee_claims_coalesced,
            "builder_fee_claims_settled": self.builder_fee_claims_settled,
            "congestion_discounts_recorded": self.congestion_discounts_recorded,
            "pq_builder_roots_attested": self.pq_builder_roots_attested,
            "settlement_batches_built": self.settlement_batches_built,
            "settlement_batches_settled": self.settlement_batches_settled,
            "settlement_receipts_recorded": self.settlement_receipts_recorded,
            "total_builder_fee_piconero": self.total_builder_fee_piconero,
            "total_user_builder_fee_piconero": self.total_user_builder_fee_piconero,
            "total_builder_covered_piconero": self.total_builder_covered_piconero,
            "total_rebate_piconero": self.total_rebate_piconero,
            "total_discount_piconero": self.total_discount_piconero,
            "events_emitted": self.events_emitted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub block_builder_coupon_lane_root: String,
    pub builder_fee_claim_root: String,
    pub congestion_discount_root: String,
    pub pq_attested_builder_fee_root_root: String,
    pub low_fee_settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub claim_nullifier_root: String,
    pub indexes_root: String,
    pub events_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            block_builder_coupon_lane_root: merkle_root(D_LANES, &[]),
            builder_fee_claim_root: merkle_root(D_CLAIMS, &[]),
            congestion_discount_root: merkle_root(D_DISCOUNTS, &[]),
            pq_attested_builder_fee_root_root: merkle_root(D_BUILDER_FEE_ROOTS, &[]),
            low_fee_settlement_batch_root: merkle_root(D_BATCHES, &[]),
            settlement_receipt_root: merkle_root(D_RECEIPTS, &[]),
            claim_nullifier_root: merkle_root(D_NULLIFIERS, &[]),
            indexes_root: merkle_root(D_PUBLIC, &[]),
            events_root: merkle_root(D_EVENTS, &[]),
            public_record_root: merkle_root(D_PUBLIC, &[]),
            state_root: merkle_root(D_STATE, &[]),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "block_builder_coupon_lane_root": self.block_builder_coupon_lane_root,
            "builder_fee_claim_root": self.builder_fee_claim_root,
            "congestion_discount_root": self.congestion_discount_root,
            "pq_attested_builder_fee_root_root": self.pq_attested_builder_fee_root_root,
            "low_fee_settlement_batch_root": self.low_fee_settlement_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "indexes_root": self.indexes_root,
            "events_root": self.events_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockBuilderCouponLaneInput {
    pub builder_commitment: String,
    pub lane_kind: BlockBuilderCouponLaneKind,
    pub lane_policy_root: String,
    pub coupon_inventory_root: String,
    pub attestation_root: String,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub cover_bps: Option<u64>,
    pub max_builder_fee_piconero: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockBuilderCouponLane {
    pub lane_id: String,
    pub builder_commitment: String,
    pub lane_kind: BlockBuilderCouponLaneKind,
    pub status: LaneStatus,
    pub lane_policy_root: String,
    pub coupon_inventory_root: String,
    pub attestation_root: String,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub cover_bps: u64,
    pub max_builder_fee_piconero: u128,
    pub reserved_builder_fee_piconero: u128,
    pub coalesced_claims: u64,
    pub settled_claims: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl BlockBuilderCouponLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "status": self.status.as_str(),
            "lane_policy_root": self.lane_policy_root,
            "coupon_inventory_root": self.coupon_inventory_root,
            "attestation_root": self.attestation_root,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "cover_bps": self.cover_bps,
            "max_builder_fee_piconero": self.max_builder_fee_piconero,
            "reserved_builder_fee_piconero": self.reserved_builder_fee_piconero,
            "coalesced_claims": self.coalesced_claims,
            "settled_claims": self.settled_claims,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuilderFeeClaimInput {
    pub lane_id: String,
    pub claim_commitment: String,
    pub builder_fee_commitment: String,
    pub builder_fee_piconero: u128,
    pub target_user_fee_bps: Option<u64>,
    pub observed_slot: u64,
    pub expires_slot: u64,
    pub claim_nullifier: String,
    pub pq_attestation_root_id: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuilderFeeClaim {
    pub claim_id: String,
    pub lane_id: String,
    pub claim_commitment: String,
    pub builder_fee_commitment: String,
    pub status: BuilderFeeClaimStatus,
    pub builder_fee_piconero: u128,
    pub user_builder_fee_piconero: u128,
    pub builder_covered_piconero: u128,
    pub congestion_discount_piconero: u128,
    pub rebate_piconero: u128,
    pub observed_slot: u64,
    pub expires_slot: u64,
    pub claim_nullifier: String,
    pub pq_attestation_root_id: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl BuilderFeeClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "lane_id": self.lane_id,
            "claim_commitment": self.claim_commitment,
            "builder_fee_commitment": self.builder_fee_commitment,
            "status": self.status.as_str(),
            "builder_fee_piconero": self.builder_fee_piconero,
            "user_builder_fee_piconero": self.user_builder_fee_piconero,
            "builder_covered_piconero": self.builder_covered_piconero,
            "congestion_discount_piconero": self.congestion_discount_piconero,
            "rebate_piconero": self.rebate_piconero,
            "observed_slot": self.observed_slot,
            "expires_slot": self.expires_slot,
            "pq_attestation_root_id": self.pq_attestation_root_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionDiscountInput {
    pub lane_id: String,
    pub band: CongestionBand,
    pub builder_pressure_bps: u64,
    pub discount_bps: Option<u64>,
    pub effective_slot: u64,
    pub expires_slot: u64,
    pub discount_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionDiscount {
    pub discount_id: String,
    pub lane_id: String,
    pub band: CongestionBand,
    pub builder_pressure_bps: u64,
    pub discount_bps: u64,
    pub effective_slot: u64,
    pub expires_slot: u64,
    pub discount_root: String,
}

impl CongestionDiscount {
    pub fn public_record(&self) -> Value {
        json!({
            "discount_id": self.discount_id,
            "lane_id": self.lane_id,
            "band": self.band.as_str(),
            "builder_pressure_bps": self.builder_pressure_bps,
            "discount_bps": self.discount_bps,
            "effective_slot": self.effective_slot,
            "expires_slot": self.expires_slot,
            "discount_root": self.discount_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestedBuilderFeeRootInput {
    pub purpose: BuilderFeeRootPurpose,
    pub builder_fee_root: String,
    pub builder_lane_root: String,
    pub congestion_discount_root: String,
    pub pq_attestation_root: String,
    pub committee_root: String,
    pub slot: u64,
    pub expires_slot: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestedBuilderFeeRoot {
    pub root_id: String,
    pub purpose: BuilderFeeRootPurpose,
    pub builder_fee_root: String,
    pub builder_lane_root: String,
    pub congestion_discount_root: String,
    pub pq_attestation_root: String,
    pub committee_root: String,
    pub slot: u64,
    pub expires_slot: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PqAttestedBuilderFeeRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "purpose": self.purpose.as_str(),
            "builder_fee_root": self.builder_fee_root,
            "builder_lane_root": self.builder_lane_root,
            "congestion_discount_root": self.congestion_discount_root,
            "pq_attestation_root": self.pq_attestation_root,
            "committee_root": self.committee_root,
            "slot": self.slot,
            "expires_slot": self.expires_slot,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeSettlementBatchInput {
    pub builder_fee_root_id: String,
    pub batch_commitment: String,
    pub claim_ids: Vec<String>,
    pub lane_ids: Vec<String>,
    pub settlement_root: String,
    pub rebate_output_root: String,
    pub built_slot: u64,
    pub target_settlement_slot: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub builder_fee_root_id: String,
    pub batch_commitment: String,
    pub status: SettlementBatchStatus,
    pub claim_count: usize,
    pub lane_count: usize,
    pub total_builder_fee_piconero: u128,
    pub total_user_builder_fee_piconero: u128,
    pub total_builder_covered_piconero: u128,
    pub total_rebate_piconero: u128,
    pub total_discount_piconero: u128,
    pub settlement_root: String,
    pub rebate_output_root: String,
    pub built_slot: u64,
    pub target_settlement_slot: u64,
}

impl LowFeeSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "builder_fee_root_id": self.builder_fee_root_id,
            "batch_commitment": self.batch_commitment,
            "status": self.status.as_str(),
            "claim_count": self.claim_count,
            "lane_count": self.lane_count,
            "total_builder_fee_piconero": self.total_builder_fee_piconero,
            "total_user_builder_fee_piconero": self.total_user_builder_fee_piconero,
            "total_builder_covered_piconero": self.total_builder_covered_piconero,
            "total_rebate_piconero": self.total_rebate_piconero,
            "total_discount_piconero": self.total_discount_piconero,
            "settlement_root": self.settlement_root,
            "rebate_output_root": self.rebate_output_root,
            "built_slot": self.built_slot,
            "target_settlement_slot": self.target_settlement_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settled_slot: u64,
    pub finality_slot: u64,
    pub settled_claim_count: usize,
    pub total_rebate_piconero: u128,
}

impl SettlementReceipt {
    pub fn new(
        batch_id: impl Into<String>,
        settlement_tx_root: impl Into<String>,
        settled_slot: u64,
        finality_slot: u64,
        settled_claim_count: usize,
        total_rebate_piconero: u128,
        nonce: u64,
    ) -> Self {
        let batch_id = batch_id.into();
        Self {
            receipt_id: settlement_receipt_id(&batch_id, nonce),
            batch_id,
            settlement_tx_root: settlement_tx_root.into(),
            settled_slot,
            finality_slot,
            settled_claim_count,
            total_rebate_piconero,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settled_slot": self.settled_slot,
            "finality_slot": self.finality_slot,
            "settled_claim_count": self.settled_claim_count,
            "total_rebate_piconero": self.total_rebate_piconero,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn new(kind: impl Into<String>, subject_id: impl Into<String>, sequence: u64) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        Self {
            event_id: event_id(&kind, &subject_id, sequence),
            kind,
            subject_id,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub block_builder_coupon_lanes: BTreeMap<String, BlockBuilderCouponLane>,
    pub builder_fee_claims: BTreeMap<String, BuilderFeeClaim>,
    pub congestion_discounts: BTreeMap<String, CongestionDiscount>,
    pub pq_attested_builder_fee_roots: BTreeMap<String, PqAttestedBuilderFeeRoot>,
    pub low_fee_settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub claim_nullifiers: BTreeSet<String>,
    pub claims_by_lane: BTreeMap<String, Vec<String>>,
    pub discounts_by_lane: BTreeMap<String, Vec<String>>,
    pub batches_by_builder_root: BTreeMap<String, Vec<String>>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            block_builder_coupon_lanes: BTreeMap::new(),
            builder_fee_claims: BTreeMap::new(),
            congestion_discounts: BTreeMap::new(),
            pq_attested_builder_fee_roots: BTreeMap::new(),
            low_fee_settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            claim_nullifiers: BTreeSet::new(),
            claims_by_lane: BTreeMap::new(),
            discounts_by_lane: BTreeMap::new(),
            batches_by_builder_root: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
}

impl State {
    pub fn with_config(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();

        let root_input = PqAttestedBuilderFeeRootInput {
            purpose: BuilderFeeRootPurpose::PendingBuilderSnapshot,
            builder_fee_root: commitment("DEVNET-BUILDER-FEE-ROOT", &["pending", "540"]),
            builder_lane_root: commitment("DEVNET-BUILDER-LANE-ROOT", &["lanes", "540"]),
            congestion_discount_root: commitment("DEVNET-DISCOUNT-ROOT", &["discounts", "540"]),
            pq_attestation_root: commitment("DEVNET-PQ-ATTESTATION", &["committee", "ml-dsa"]),
            committee_root: commitment("DEVNET-COMMITTEE", &["builder", "rebate"]),
            slot: DEVNET_HEIGHT,
            expires_slot: DEVNET_HEIGHT + DEFAULT_BUILDER_FEE_ROOT_TTL_SLOTS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            nonce: 1,
        };
        let builder_root_id = state.attest_builder_fee_root(root_input).unwrap();

        let lane_input = BlockBuilderCouponLaneInput {
            builder_commitment: commitment("DEVNET-BUILDER", &["lane", "builder-auction"]),
            lane_kind: BlockBuilderCouponLaneKind::BuilderAuction,
            lane_policy_root: commitment("DEVNET-LANE-POLICY", &["builder-auction", "cover"]),
            coupon_inventory_root: commitment("DEVNET-COUPON-INVENTORY", &["builder", "sealed"]),
            attestation_root: commitment("DEVNET-LANE-ATTESTATION", &["builder", "pq"]),
            opened_slot: DEVNET_HEIGHT,
            expires_slot: DEVNET_HEIGHT + DEFAULT_COUPON_LANE_TTL_SLOTS,
            cover_bps: None,
            max_builder_fee_piconero: 18_000_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            nonce: 7,
        };
        let lane_id = state.open_block_builder_coupon_lane(lane_input).unwrap();

        let discount_input = CongestionDiscountInput {
            lane_id: lane_id.clone(),
            band: CongestionBand::Busy,
            builder_pressure_bps: 12_600,
            discount_bps: None,
            effective_slot: DEVNET_HEIGHT,
            expires_slot: DEVNET_HEIGHT + DEFAULT_COALESCING_WINDOW_SLOTS,
            discount_root: commitment("DEVNET-CONGESTION-DISCOUNT", &["busy", "builder"]),
            nonce: 3,
        };
        state.record_congestion_discount(discount_input).unwrap();

        for (nonce, amount) in [(11, 2_100_000_u128), (12, 3_400_000), (13, 1_600_000)] {
            let claim_input = BuilderFeeClaimInput {
                lane_id: lane_id.clone(),
                claim_commitment: commitment("DEVNET-BUILDER-CLAIM", &[&nonce.to_string()]),
                builder_fee_commitment: commitment("DEVNET-BUILDER-FEE", &[&amount.to_string()]),
                builder_fee_piconero: amount,
                target_user_fee_bps: None,
                observed_slot: DEVNET_HEIGHT + nonce,
                expires_slot: DEVNET_HEIGHT + DEFAULT_COALESCING_WINDOW_SLOTS,
                claim_nullifier: commitment("DEVNET-CLAIM-NULLIFIER", &[&nonce.to_string()]),
                pq_attestation_root_id: builder_root_id.clone(),
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                nonce,
            };
            state.observe_builder_fee_claim(claim_input).unwrap();
        }

        let claim_ids = state
            .claims_by_lane
            .get(&lane_id)
            .cloned()
            .unwrap_or_default();
        let batch_input = LowFeeSettlementBatchInput {
            builder_fee_root_id: builder_root_id,
            batch_commitment: commitment("DEVNET-LOW-FEE-BATCH", &["builder", "coalesced"]),
            claim_ids,
            lane_ids: vec![lane_id],
            settlement_root: commitment("DEVNET-SETTLEMENT", &["builder", "rebate"]),
            rebate_output_root: commitment("DEVNET-REBATE-OUTPUT", &["private", "credits"]),
            built_slot: DEVNET_HEIGHT + 24,
            target_settlement_slot: DEVNET_HEIGHT + 42,
            nonce: 17,
        };
        let batch_id = state.build_low_fee_settlement_batch(batch_input).unwrap();
        state
            .record_settlement_receipt(
                &batch_id,
                commitment("DEVNET-SETTLEMENT-TX", &[&batch_id]),
                DEVNET_HEIGHT + 45,
                23,
            )
            .unwrap();

        state.recompute_roots();
        state
    }

    pub fn open_block_builder_coupon_lane(
        &mut self,
        input: BlockBuilderCouponLaneInput,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_hash_like("builder_commitment", &input.builder_commitment)?;
        ensure_hash_like("lane_policy_root", &input.lane_policy_root)?;
        ensure_hash_like("coupon_inventory_root", &input.coupon_inventory_root)?;
        ensure_hash_like("attestation_root", &input.attestation_root)?;
        ensure!(
            input.expires_slot > input.opened_slot,
            "lane expires before it opens"
        );
        ensure!(
            input.expires_slot - input.opened_slot <= self.config.coupon_lane_ttl_slots,
            "lane ttl exceeds configured coupon lane ttl"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set below minimum"
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "lane pq security below minimum"
        );

        let cover_bps = input
            .cover_bps
            .unwrap_or_else(|| input.lane_kind.default_cover_bps(&self.config));
        ensure_bps("cover_bps", cover_bps)?;
        ensure!(
            cover_bps <= self.config.max_builder_cover_bps,
            "lane cover bps exceeds max builder cover"
        );

        let lane_id = builder_lane_id(
            &input.builder_commitment,
            input.lane_kind,
            &input.lane_policy_root,
            input.nonce,
        );
        ensure!(
            !self.block_builder_coupon_lanes.contains_key(&lane_id),
            "block-builder coupon lane already exists"
        );

        let lane = BlockBuilderCouponLane {
            lane_id: lane_id.clone(),
            builder_commitment: input.builder_commitment,
            lane_kind: input.lane_kind,
            status: LaneStatus::Open,
            lane_policy_root: input.lane_policy_root,
            coupon_inventory_root: input.coupon_inventory_root,
            attestation_root: input.attestation_root,
            opened_slot: input.opened_slot,
            expires_slot: input.expires_slot,
            cover_bps,
            max_builder_fee_piconero: input.max_builder_fee_piconero,
            reserved_builder_fee_piconero: 0,
            coalesced_claims: 0,
            settled_claims: 0,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.block_builder_coupon_lanes
            .insert(lane_id.clone(), lane);
        self.counters.block_builder_coupon_lanes_opened = self
            .counters
            .block_builder_coupon_lanes_opened
            .saturating_add(1);
        self.emit("block_builder_coupon_lane_opened", &lane_id);
        self.recompute_roots();
        Ok(lane_id)
    }

    pub fn record_congestion_discount(&mut self, input: CongestionDiscountInput) -> Result<String> {
        ensure_hash_like("discount_root", &input.discount_root)?;
        let lane = self
            .block_builder_coupon_lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown block-builder coupon lane {}", input.lane_id))?;
        ensure!(
            lane.status.accepts_claims(),
            "lane does not accept discounts"
        );
        ensure!(
            input.expires_slot > input.effective_slot,
            "discount expires before it is effective"
        );
        ensure_bps("builder_pressure_bps", input.builder_pressure_bps)?;
        let inferred_band = CongestionBand::from_builder_pressure_bps(input.builder_pressure_bps);
        ensure!(
            inferred_band == input.band || input.band >= CongestionBand::Normal,
            "discount band is lower than inferred pressure band"
        );
        let discount_bps = input
            .discount_bps
            .unwrap_or_else(|| input.band.discount_bps());
        ensure_bps("discount_bps", discount_bps)?;

        let discount_id = congestion_discount_id(
            &input.lane_id,
            input.band,
            input.effective_slot,
            input.nonce,
        );
        let discount = CongestionDiscount {
            discount_id: discount_id.clone(),
            lane_id: input.lane_id.clone(),
            band: input.band,
            builder_pressure_bps: input.builder_pressure_bps,
            discount_bps,
            effective_slot: input.effective_slot,
            expires_slot: input.expires_slot,
            discount_root: input.discount_root,
        };
        self.congestion_discounts
            .insert(discount_id.clone(), discount);
        self.discounts_by_lane
            .entry(input.lane_id)
            .or_default()
            .push(discount_id.clone());
        self.counters.congestion_discounts_recorded = self
            .counters
            .congestion_discounts_recorded
            .saturating_add(1);
        self.emit("congestion_discount_recorded", &discount_id);
        self.recompute_roots();
        Ok(discount_id)
    }

    pub fn attest_builder_fee_root(
        &mut self,
        input: PqAttestedBuilderFeeRootInput,
    ) -> Result<String> {
        ensure_hash_like("builder_fee_root", &input.builder_fee_root)?;
        ensure_hash_like("builder_lane_root", &input.builder_lane_root)?;
        ensure_hash_like("congestion_discount_root", &input.congestion_discount_root)?;
        ensure_hash_like("pq_attestation_root", &input.pq_attestation_root)?;
        ensure_hash_like("committee_root", &input.committee_root)?;
        ensure!(
            input.expires_slot > input.slot,
            "builder fee root expires before attested slot"
        );
        ensure!(
            input.expires_slot - input.slot <= self.config.builder_root_ttl_slots,
            "builder fee root ttl exceeds configured ttl"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "builder fee root privacy set below minimum"
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "builder fee root pq security below minimum"
        );
        let root_id = builder_fee_root_id(
            input.purpose,
            &input.builder_fee_root,
            input.slot,
            input.nonce,
        );
        let attested = PqAttestedBuilderFeeRoot {
            root_id: root_id.clone(),
            purpose: input.purpose,
            builder_fee_root: input.builder_fee_root,
            builder_lane_root: input.builder_lane_root,
            congestion_discount_root: input.congestion_discount_root,
            pq_attestation_root: input.pq_attestation_root,
            committee_root: input.committee_root,
            slot: input.slot,
            expires_slot: input.expires_slot,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.pq_attested_builder_fee_roots
            .insert(root_id.clone(), attested);
        self.counters.pq_builder_roots_attested =
            self.counters.pq_builder_roots_attested.saturating_add(1);
        self.emit("pq_attested_builder_fee_root", &root_id);
        self.recompute_roots();
        Ok(root_id)
    }

    pub fn observe_builder_fee_claim(&mut self, input: BuilderFeeClaimInput) -> Result<String> {
        ensure_hash_like("claim_commitment", &input.claim_commitment)?;
        ensure_hash_like("builder_fee_commitment", &input.builder_fee_commitment)?;
        ensure_hash_like("claim_nullifier", &input.claim_nullifier)?;
        ensure_nonempty("pq_attestation_root_id", &input.pq_attestation_root_id)?;
        ensure!(
            !self.claim_nullifiers.contains(&input.claim_nullifier),
            "claim nullifier already consumed"
        );
        let lane = self
            .block_builder_coupon_lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown block-builder coupon lane {}", input.lane_id))?;
        ensure!(lane.status.accepts_claims(), "lane does not accept claims");
        ensure!(
            input.observed_slot >= lane.opened_slot && input.expires_slot <= lane.expires_slot,
            "claim is outside lane lifetime"
        );
        ensure!(
            self.pq_attested_builder_fee_roots
                .contains_key(&input.pq_attestation_root_id),
            "unknown pq attested builder fee root"
        );
        ensure!(
            input.privacy_set_size >= self.config.min_privacy_set_size,
            "claim privacy set below minimum"
        );
        ensure!(
            input.pq_security_bits >= self.config.min_pq_security_bits,
            "claim pq security below minimum"
        );
        let target_bps = input
            .target_user_fee_bps
            .unwrap_or(self.config.target_user_builder_fee_bps)
            .min(self.config.max_user_builder_fee_bps);
        ensure_bps("target_user_fee_bps", target_bps)?;

        let discount_bps = self.active_lane_discount_bps(&input.lane_id, input.observed_slot);
        let congestion_discount_piconero = bps_amount(input.builder_fee_piconero, discount_bps);
        let net_fee = input
            .builder_fee_piconero
            .saturating_sub(congestion_discount_piconero);
        let user_builder_fee_piconero = bps_amount(net_fee, target_bps);
        let builder_cover_piconero = bps_amount(net_fee, lane.cover_bps);
        let rebate_piconero = net_fee
            .saturating_sub(user_builder_fee_piconero)
            .min(builder_cover_piconero)
            .min(bps_amount(
                input.builder_fee_piconero,
                self.config.max_rebate_bps,
            ));
        let builder_covered_piconero = rebate_piconero.saturating_add(congestion_discount_piconero);

        ensure!(
            lane.reserved_builder_fee_piconero
                .saturating_add(builder_covered_piconero)
                <= lane.max_builder_fee_piconero,
            "lane builder fee capacity exceeded"
        );

        let claim_id = builder_fee_claim_id(&input.lane_id, &input.claim_commitment, input.nonce);
        let claim = BuilderFeeClaim {
            claim_id: claim_id.clone(),
            lane_id: input.lane_id.clone(),
            claim_commitment: input.claim_commitment,
            builder_fee_commitment: input.builder_fee_commitment,
            status: BuilderFeeClaimStatus::Coalesced,
            builder_fee_piconero: input.builder_fee_piconero,
            user_builder_fee_piconero,
            builder_covered_piconero,
            congestion_discount_piconero,
            rebate_piconero,
            observed_slot: input.observed_slot,
            expires_slot: input.expires_slot,
            claim_nullifier: input.claim_nullifier.clone(),
            pq_attestation_root_id: input.pq_attestation_root_id,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        self.builder_fee_claims.insert(claim_id.clone(), claim);
        self.claim_nullifiers.insert(input.claim_nullifier);
        self.claims_by_lane
            .entry(input.lane_id.clone())
            .or_default()
            .push(claim_id.clone());
        if let Some(lane) = self.block_builder_coupon_lanes.get_mut(&input.lane_id) {
            lane.reserved_builder_fee_piconero = lane
                .reserved_builder_fee_piconero
                .saturating_add(builder_covered_piconero);
            lane.coalesced_claims = lane.coalesced_claims.saturating_add(1);
        }
        self.counters.builder_fee_claims_observed =
            self.counters.builder_fee_claims_observed.saturating_add(1);
        self.counters.builder_fee_claims_coalesced =
            self.counters.builder_fee_claims_coalesced.saturating_add(1);
        self.counters.total_builder_fee_piconero = self
            .counters
            .total_builder_fee_piconero
            .saturating_add(input.builder_fee_piconero);
        self.counters.total_user_builder_fee_piconero = self
            .counters
            .total_user_builder_fee_piconero
            .saturating_add(user_builder_fee_piconero);
        self.counters.total_builder_covered_piconero = self
            .counters
            .total_builder_covered_piconero
            .saturating_add(builder_covered_piconero);
        self.counters.total_rebate_piconero = self
            .counters
            .total_rebate_piconero
            .saturating_add(rebate_piconero);
        self.counters.total_discount_piconero = self
            .counters
            .total_discount_piconero
            .saturating_add(congestion_discount_piconero);
        self.emit("builder_fee_claim_coalesced", &claim_id);
        self.recompute_roots();
        Ok(claim_id)
    }

    pub fn build_low_fee_settlement_batch(
        &mut self,
        input: LowFeeSettlementBatchInput,
    ) -> Result<String> {
        ensure_hash_like("batch_commitment", &input.batch_commitment)?;
        ensure_hash_like("settlement_root", &input.settlement_root)?;
        ensure_hash_like("rebate_output_root", &input.rebate_output_root)?;
        ensure!(
            self.pq_attested_builder_fee_roots
                .contains_key(&input.builder_fee_root_id),
            "unknown builder fee root id"
        );
        ensure!(
            !input.claim_ids.is_empty(),
            "settlement batch must include claims"
        );
        ensure!(
            input.claim_ids.len() <= self.config.max_claims_per_batch,
            "settlement batch exceeds claim limit"
        );
        ensure!(
            input.lane_ids.len() <= self.config.max_lanes_per_batch,
            "settlement batch exceeds lane limit"
        );
        ensure!(
            input.target_settlement_slot >= input.built_slot,
            "target settlement slot precedes built slot"
        );

        let mut lane_set = BTreeSet::new();
        let mut total_builder_fee_piconero = 0_u128;
        let mut total_user_builder_fee_piconero = 0_u128;
        let mut total_builder_covered_piconero = 0_u128;
        let mut total_rebate_piconero = 0_u128;
        let mut total_discount_piconero = 0_u128;

        for lane_id in &input.lane_ids {
            let lane = self
                .block_builder_coupon_lanes
                .get(lane_id)
                .ok_or_else(|| format!("unknown block-builder coupon lane {lane_id}"))?;
            ensure!(
                lane.status.accepts_batches(),
                "lane does not accept batches"
            );
            lane_set.insert(lane_id.clone());
        }

        for claim_id in &input.claim_ids {
            let claim = self
                .builder_fee_claims
                .get(claim_id)
                .ok_or_else(|| format!("unknown builder fee claim {claim_id}"))?;
            ensure!(claim.status.batchable(), "claim is not batchable");
            ensure!(
                lane_set.contains(&claim.lane_id),
                "claim lane is missing from batch lane set"
            );
            total_builder_fee_piconero =
                total_builder_fee_piconero.saturating_add(claim.builder_fee_piconero);
            total_user_builder_fee_piconero =
                total_user_builder_fee_piconero.saturating_add(claim.user_builder_fee_piconero);
            total_builder_covered_piconero =
                total_builder_covered_piconero.saturating_add(claim.builder_covered_piconero);
            total_rebate_piconero = total_rebate_piconero.saturating_add(claim.rebate_piconero);
            total_discount_piconero =
                total_discount_piconero.saturating_add(claim.congestion_discount_piconero);
        }

        let batch_id = settlement_batch_id(
            &input.builder_fee_root_id,
            &input.batch_commitment,
            input.nonce,
        );
        let batch = LowFeeSettlementBatch {
            batch_id: batch_id.clone(),
            builder_fee_root_id: input.builder_fee_root_id.clone(),
            batch_commitment: input.batch_commitment,
            status: SettlementBatchStatus::Built,
            claim_count: input.claim_ids.len(),
            lane_count: lane_set.len(),
            total_builder_fee_piconero,
            total_user_builder_fee_piconero,
            total_builder_covered_piconero,
            total_rebate_piconero,
            total_discount_piconero,
            settlement_root: input.settlement_root,
            rebate_output_root: input.rebate_output_root,
            built_slot: input.built_slot,
            target_settlement_slot: input.target_settlement_slot,
        };
        for claim_id in input.claim_ids {
            if let Some(claim) = self.builder_fee_claims.get_mut(&claim_id) {
                claim.status = BuilderFeeClaimStatus::Coalesced;
            }
        }
        self.low_fee_settlement_batches
            .insert(batch_id.clone(), batch);
        self.batches_by_builder_root
            .entry(input.builder_fee_root_id)
            .or_default()
            .push(batch_id.clone());
        self.counters.settlement_batches_built =
            self.counters.settlement_batches_built.saturating_add(1);
        self.emit("low_fee_settlement_batch_built", &batch_id);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn record_settlement_receipt(
        &mut self,
        batch_id: &str,
        settlement_tx_root: String,
        settled_slot: u64,
        nonce: u64,
    ) -> Result<String> {
        ensure_hash_like("settlement_tx_root", &settlement_tx_root)?;
        let batch = self
            .low_fee_settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown settlement batch {batch_id}"))?;
        ensure!(
            settled_slot >= batch.built_slot,
            "settlement slot precedes batch build"
        );
        batch.status = SettlementBatchStatus::Settled;
        let finality_slot = settled_slot.saturating_add(self.config.settlement_finality_slots);
        let receipt = SettlementReceipt::new(
            batch_id,
            settlement_tx_root,
            settled_slot,
            finality_slot,
            batch.claim_count,
            batch.total_rebate_piconero,
            nonce,
        );
        let receipt_id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        for claim in self.builder_fee_claims.values_mut() {
            if claim.status == BuilderFeeClaimStatus::Coalesced {
                claim.status = BuilderFeeClaimStatus::Settled;
            }
        }
        for lane in self.block_builder_coupon_lanes.values_mut() {
            lane.settled_claims = lane.settled_claims.saturating_add(batch.claim_count as u64);
        }
        self.counters.builder_fee_claims_settled = self
            .counters
            .builder_fee_claims_settled
            .saturating_add(batch.claim_count as u64);
        self.counters.settlement_batches_settled =
            self.counters.settlement_batches_settled.saturating_add(1);
        self.counters.settlement_receipts_recorded =
            self.counters.settlement_receipts_recorded.saturating_add(1);
        self.emit("settlement_receipt_recorded", &receipt_id);
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["roots"]["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "BLOCK_BUILDER_COUPON_LANE_SUITE": BLOCK_BUILDER_COUPON_LANE_SUITE,
            "congestion_discount_suite": CONGESTION_DISCOUNT_SUITE,
            "PQ_ATTESTED_BUILDER_FEE_ROOT_SUITE": PQ_ATTESTED_BUILDER_FEE_ROOT_SUITE,
            "low_fee_settlement_batch_suite": LOW_FEE_SETTLEMENT_BATCH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config_root": record_root(D_CONFIG, &self.config.public_record()),
            "counters_root": record_root(D_COUNTERS, &self.counters.public_record()),
            "roots": {
                let mut roots = self.roots.public_record();
                roots["state_root"] = json!(null);
                roots
            },
            "block_builder_coupon_lane_count": self.block_builder_coupon_lanes.len(),
            "builder_fee_claim_count": self.builder_fee_claims.len(),
            "congestion_discount_count": self.congestion_discounts.len(),
            "pq_attested_builder_fee_root_count": self.pq_attested_builder_fee_roots.len(),
            "low_fee_settlement_batch_count": self.low_fee_settlement_batches.len(),
            "settlement_receipt_count": self.settlement_receipts.len(),
            "claim_nullifier_count": self.claim_nullifiers.len(),
            "events_count": self.events.len(),
        })
    }

    pub fn recompute_roots(&mut self) {
        self.roots.block_builder_coupon_lane_root = map_root(
            D_LANES,
            &self.block_builder_coupon_lanes,
            BlockBuilderCouponLane::public_record,
        );
        self.roots.builder_fee_claim_root = map_root(
            D_CLAIMS,
            &self.builder_fee_claims,
            BuilderFeeClaim::public_record,
        );
        self.roots.congestion_discount_root = map_root(
            D_DISCOUNTS,
            &self.congestion_discounts,
            CongestionDiscount::public_record,
        );
        self.roots.pq_attested_builder_fee_root_root = map_root(
            D_BUILDER_FEE_ROOTS,
            &self.pq_attested_builder_fee_roots,
            PqAttestedBuilderFeeRoot::public_record,
        );
        self.roots.low_fee_settlement_batch_root = map_root(
            D_BATCHES,
            &self.low_fee_settlement_batches,
            LowFeeSettlementBatch::public_record,
        );
        self.roots.settlement_receipt_root = map_root(
            D_RECEIPTS,
            &self.settlement_receipts,
            SettlementReceipt::public_record,
        );
        self.roots.claim_nullifier_root = set_root(D_NULLIFIERS, &self.claim_nullifiers);
        self.roots.indexes_root = self.indexes_root();
        self.roots.events_root = merkle_root(
            D_EVENTS,
            &self
                .events
                .iter()
                .map(RuntimeEvent::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.public_record_root =
            record_root(D_PUBLIC, &self.public_record_without_state_root());
        self.roots.state_root = self.state_root();
    }

    fn active_lane_discount_bps(&self, lane_id: &str, slot: u64) -> u64 {
        self.discounts_by_lane
            .get(lane_id)
            .into_iter()
            .flatten()
            .filter_map(|discount_id| self.congestion_discounts.get(discount_id))
            .filter(|discount| discount.effective_slot <= slot && slot <= discount.expires_slot)
            .map(|discount| discount.discount_bps)
            .max()
            .unwrap_or(self.config.base_rebate_bps.min(self.config.max_rebate_bps))
    }

    fn indexes_root(&self) -> String {
        merkle_root(
            D_PUBLIC,
            &[
                json!({"claims_by_lane": self.claims_by_lane}),
                json!({"discounts_by_lane": self.discounts_by_lane}),
                json!({"batches_by_builder_root": self.batches_by_builder_root}),
            ],
        )
    }

    fn emit(&mut self, kind: impl Into<String>, subject_id: impl Into<String>) {
        if self.events.len() >= self.config.max_public_events {
            return;
        }
        let sequence = self.counters.events_emitted.saturating_add(1);
        self.events
            .push(RuntimeEvent::new(kind, subject_id, sequence));
        self.counters.events_emitted = sequence;
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

pub fn private_l2_low_fee_pq_confidential_builder_fee_rebate_coalescer_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_low_fee_pq_confidential_builder_fee_rebate_coalescer_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_builder_fee_rebate_coalescer_runtime_state_root_from_record(
    record: &Value,
) -> String {
    state_root_from_public_record(record)
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:{domain}"),
        &hash_parts,
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record_root": record_root(domain, &json!({"key": key, "record": public_record(value)})),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!({
                "value": value,
                "record_root": record_root(domain, &json!({"value": value})),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(D_STATE, &[HashPart::Json(record)], 32)
}

fn builder_lane_id(
    builder_commitment: &str,
    lane_kind: BlockBuilderCouponLaneKind,
    lane_policy_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:LANE-ID",
        &[
            HashPart::Str(builder_commitment),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(lane_policy_root),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn builder_fee_claim_id(lane_id: &str, claim_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:CLAIM-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(claim_commitment),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn congestion_discount_id(
    lane_id: &str,
    band: CongestionBand,
    effective_slot: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:DISCOUNT-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(band.as_str()),
            HashPart::U64(effective_slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn builder_fee_root_id(
    purpose: BuilderFeeRootPurpose,
    builder_fee_root: &str,
    slot: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:builder-fee-ROOT-ID",
        &[
            HashPart::Str(purpose.as_str()),
            HashPart::Str(builder_fee_root),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn settlement_batch_id(builder_fee_root_id: &str, batch_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:BATCH-ID",
        &[
            HashPart::Str(builder_fee_root_id),
            HashPart::Str(batch_commitment),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn settlement_receipt_id(batch_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:RECEIPT-ID",
        &[HashPart::Str(batch_id), HashPart::U64(nonce)],
        20,
    )
}

fn event_id(kind: &str, subject_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-BUILDER-FEE-REBATE-COALESCER:EVENT-ID",
        &[
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::U64(sequence),
        ],
        20,
    )
}

fn ensure_nonempty(name: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{name} is empty");
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    ensure!(value <= MAX_BPS, "{name} exceeds 10000 bps");
    Ok(())
}

fn ensure_hash_like(name: &str, value: &str) -> Result<()> {
    ensure_nonempty(name, value)?;
    ensure!(
        value.len() >= 32,
        "{name} must be a commitment/root with at least 32 chars"
    );
    Ok(())
}
