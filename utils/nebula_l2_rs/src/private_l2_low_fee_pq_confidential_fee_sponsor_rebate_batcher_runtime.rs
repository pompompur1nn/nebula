use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialFeeSponsorRebateBatcherRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialFeeSponsorRebateBatcherRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_SPONSOR_REBATE_BATCHER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-fee-sponsor-rebate-batcher-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_SPONSOR_REBATE_BATCHER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SPONSOR_COUPON_LANE_SUITE: &str = "ML-KEM-1024-sealed-private-l2-sponsor-coupon-lanes-v1";
pub const CONGESTION_DISCOUNT_SUITE: &str =
    "private-l2-low-fee-congestion-discount-sponsor-rebate-v1";
pub const PQ_ATTESTED_FEE_ROOT_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-attested-fee-sponsor-root-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str =
    "private-l2-low-fee-sponsor-rebate-settlement-batch-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-fee-sponsor-rebate-batcher-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_coupon_plaintexts_sponsor_wallets_beneficiary_addresses_view_keys_or_fee_witnesses";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "sponsor-rebate-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 5_590_000;
pub const DEVNET_EPOCH: u64 = 54_400;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_BASE_SPONSOR_COVER_BPS: u64 = 8_750;
pub const DEFAULT_MAX_SPONSOR_COVER_BPS: u64 = 9_900;
pub const DEFAULT_BASE_REBATE_BPS: u64 = 1_250;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 6_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ATTESTED_ROOT_TTL_SLOTS: u64 = 1_440;
pub const DEFAULT_COUPON_LANE_TTL_SLOTS: u64 = 8_640;
pub const DEFAULT_BATCH_WINDOW_SLOTS: u64 = 144;
pub const DEFAULT_SETTLEMENT_FINALITY_SLOTS: u64 = 42;
pub const DEFAULT_MAX_COUPONS_PER_BATCH: usize = 65_536;
pub const DEFAULT_MAX_LANES_PER_BATCH: usize = 256;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:ROOTS";
const D_POOLS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:POOLS";
const D_LANES: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:LANES";
const D_COUPONS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:COUPONS";
const D_DISCOUNTS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:DISCOUNTS";
const D_FEE_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:FEE-ROOTS";
const D_BATCHES: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:BATCHES";
const D_RECEIPTS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:RECEIPTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:EVENTS";
const D_PUBLIC: &str = "PL2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:PUBLIC";

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Draft,
    Attested,
    Open,
    Draining,
    Paused,
    Sealed,
    Retired,
}

impl SponsorPoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Attested => "attested",
            Self::Open => "open",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Sealed => "sealed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_lanes(self) -> bool {
        matches!(self, Self::Attested | Self::Open)
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Open | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCouponLaneKind {
    WalletOnboarding,
    MerchantCheckout,
    BridgeExit,
    ContractCall,
    PaymasterIntent,
    BatchAuction,
    OracleUpdate,
    EmergencyWithdrawal,
}

impl SponsorCouponLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletOnboarding => "wallet_onboarding",
            Self::MerchantCheckout => "merchant_checkout",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::PaymasterIntent => "paymaster_intent",
            Self::BatchAuction => "batch_auction",
            Self::OracleUpdate => "oracle_update",
            Self::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyWithdrawal => 10_000,
            Self::BridgeExit => 9_400,
            Self::ContractCall => 8_800,
            Self::PaymasterIntent => 8_400,
            Self::BatchAuction => 7_900,
            Self::MerchantCheckout => 7_300,
            Self::WalletOnboarding => 6_900,
            Self::OracleUpdate => 6_200,
        }
    }

    pub fn default_cover_bps(self, config: &Config) -> u64 {
        let bump = match self {
            Self::EmergencyWithdrawal => 900,
            Self::BridgeExit => 600,
            Self::ContractCall => 250,
            Self::PaymasterIntent => 350,
            Self::BatchAuction => 200,
            Self::MerchantCheckout => 100,
            Self::WalletOnboarding => 50,
            Self::OracleUpdate => 0,
        };
        config
            .base_sponsor_cover_bps
            .saturating_add(bump)
            .min(config.max_sponsor_cover_bps)
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

    pub fn from_pressure_bps(pressure_bps: u64) -> Self {
        match pressure_bps {
            0..=2_499 => Self::Idle,
            2_500..=5_999 => Self::Low,
            6_000..=10_999 => Self::Normal,
            11_000..=17_999 => Self::Busy,
            18_000..=27_999 => Self::Surge,
            _ => Self::Crisis,
        }
    }

    pub fn discount_bps(self) -> u64 {
        match self {
            Self::Idle => 300,
            Self::Low => 700,
            Self::Normal => 1_200,
            Self::Busy => 2_100,
            Self::Surge => 3_400,
            Self::Crisis => 4_800,
        }
    }

    pub fn sponsor_haircut_bps(self) -> u64 {
        match self {
            Self::Idle => 0,
            Self::Low => 50,
            Self::Normal => 150,
            Self::Busy => 350,
            Self::Surge => 750,
            Self::Crisis => 1_250,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Draft,
    Sealed,
    Attested,
    Queued,
    Settled,
    Expired,
    Quarantined,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Queued => "queued",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Sealed | Self::Attested | Self::Queued)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRootPurpose {
    SponsorInventory,
    CouponEligibility,
    CongestionOracle,
    SettlementBatch,
    RebateAccounting,
}

impl FeeRootPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorInventory => "sponsor_inventory",
            Self::CouponEligibility => "coupon_eligibility",
            Self::CongestionOracle => "congestion_oracle",
            Self::SettlementBatch => "settlement_batch",
            Self::RebateAccounting => "rebate_accounting",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Allow,
    Observe,
    Quarantine,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Observe => "observe",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn permits_settlement(self) -> bool {
        matches!(self, Self::Allow | Self::Observe)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Locked,
    Submitted,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_coupons(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub base_sponsor_cover_bps: u64,
    pub max_sponsor_cover_bps: u64,
    pub base_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub attested_root_ttl_slots: u64,
    pub coupon_lane_ttl_slots: u64,
    pub batch_window_slots: u64,
    pub settlement_finality_slots: u64,
    pub max_coupons_per_batch: usize,
    pub max_lanes_per_batch: usize,
    pub max_public_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            base_sponsor_cover_bps: DEFAULT_BASE_SPONSOR_COVER_BPS,
            max_sponsor_cover_bps: DEFAULT_MAX_SPONSOR_COVER_BPS,
            base_rebate_bps: DEFAULT_BASE_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attested_root_ttl_slots: DEFAULT_ATTESTED_ROOT_TTL_SLOTS,
            coupon_lane_ttl_slots: DEFAULT_COUPON_LANE_TTL_SLOTS,
            batch_window_slots: DEFAULT_BATCH_WINDOW_SLOTS,
            settlement_finality_slots: DEFAULT_SETTLEMENT_FINALITY_SLOTS,
            max_coupons_per_batch: DEFAULT_MAX_COUPONS_PER_BATCH,
            max_lanes_per_batch: DEFAULT_MAX_LANES_PER_BATCH,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("rebate_asset_id", &self.rebate_asset_id)?;
        ensure_bps("target_user_fee_bps", self.target_user_fee_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("base_sponsor_cover_bps", self.base_sponsor_cover_bps)?;
        ensure_bps("max_sponsor_cover_bps", self.max_sponsor_cover_bps)?;
        ensure_bps("base_rebate_bps", self.base_rebate_bps)?;
        ensure_bps("max_rebate_bps", self.max_rebate_bps)?;
        ensure!(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target_user_fee_bps must be <= max_user_fee_bps"
        );
        ensure!(
            self.base_sponsor_cover_bps <= self.max_sponsor_cover_bps,
            "base_sponsor_cover_bps must be <= max_sponsor_cover_bps"
        );
        ensure!(
            self.base_rebate_bps <= self.max_rebate_bps,
            "base_rebate_bps must be <= max_rebate_bps"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size
                && self.min_privacy_set_size > 0,
            "target_privacy_set_size must be >= min_privacy_set_size"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "min_pq_security_bits below runtime floor"
        );
        ensure!(
            self.max_coupons_per_batch > 0,
            "max_coupons_per_batch is zero"
        );
        ensure!(self.max_lanes_per_batch > 0, "max_lanes_per_batch is zero");
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_fee_sponsor_rebate_batcher_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "base_sponsor_cover_bps": self.base_sponsor_cover_bps,
            "max_sponsor_cover_bps": self.max_sponsor_cover_bps,
            "base_rebate_bps": self.base_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "attested_root_ttl_slots": self.attested_root_ttl_slots,
            "coupon_lane_ttl_slots": self.coupon_lane_ttl_slots,
            "batch_window_slots": self.batch_window_slots,
            "settlement_finality_slots": self.settlement_finality_slots,
            "max_coupons_per_batch": self.max_coupons_per_batch,
            "max_lanes_per_batch": self.max_lanes_per_batch,
            "hash_suite": HASH_SUITE,
            "sponsor_coupon_lane_suite": SPONSOR_COUPON_LANE_SUITE,
            "congestion_discount_suite": CONGESTION_DISCOUNT_SUITE,
            "pq_attested_fee_root_suite": PQ_ATTESTED_FEE_ROOT_SUITE,
            "low_fee_settlement_batch_suite": LOW_FEE_SETTLEMENT_BATCH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub sponsor_pools: u64,
    pub sponsor_coupon_lanes: u64,
    pub sealed_coupons: u64,
    pub congestion_discounts: u64,
    pub pq_attested_fee_roots: u64,
    pub settlement_batches: u64,
    pub settlement_receipts: u64,
    pub coupon_nullifiers: u64,
    pub public_records: u64,
    pub events_emitted: u64,
    pub total_sponsor_capacity: u128,
    pub available_sponsor_capacity: u128,
    pub queued_coupon_face_value: u128,
    pub settled_coupon_face_value: u128,
    pub user_fee_due: u128,
    pub sponsor_fee_paid: u128,
    pub congestion_discount_amount: u128,
    pub rebate_amount: u128,
    pub quarantined_amount: u128,
}

impl Counters {
    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_fee_sponsor_rebate_batcher_counters",
            "sponsor_pools": self.sponsor_pools,
            "sponsor_coupon_lanes": self.sponsor_coupon_lanes,
            "sealed_coupons": self.sealed_coupons,
            "congestion_discounts": self.congestion_discounts,
            "pq_attested_fee_roots": self.pq_attested_fee_roots,
            "settlement_batches": self.settlement_batches,
            "settlement_receipts": self.settlement_receipts,
            "coupon_nullifiers": self.coupon_nullifiers,
            "public_records": self.public_records,
            "events_emitted": self.events_emitted,
            "total_sponsor_capacity": self.total_sponsor_capacity.to_string(),
            "available_sponsor_capacity": self.available_sponsor_capacity.to_string(),
            "queued_coupon_face_value": self.queued_coupon_face_value.to_string(),
            "settled_coupon_face_value": self.settled_coupon_face_value.to_string(),
            "user_fee_due": self.user_fee_due.to_string(),
            "sponsor_fee_paid": self.sponsor_fee_paid.to_string(),
            "congestion_discount_amount": self.congestion_discount_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "quarantined_amount": self.quarantined_amount.to_string(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub sponsor_pool_root: String,
    pub sponsor_coupon_lane_root: String,
    pub sealed_coupon_root: String,
    pub congestion_discount_root: String,
    pub pq_attested_fee_root_root: String,
    pub settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub coupon_nullifier_root: String,
    pub indexes_root: String,
    pub events_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            sponsor_pool_root: merkle_root(D_POOLS, &[]),
            sponsor_coupon_lane_root: merkle_root(D_LANES, &[]),
            sealed_coupon_root: merkle_root(D_COUPONS, &[]),
            congestion_discount_root: merkle_root(D_DISCOUNTS, &[]),
            pq_attested_fee_root_root: merkle_root(D_FEE_ROOTS, &[]),
            settlement_batch_root: merkle_root(D_BATCHES, &[]),
            settlement_receipt_root: merkle_root(D_RECEIPTS, &[]),
            coupon_nullifier_root: merkle_root(D_NULLIFIERS, &[]),
            indexes_root: merkle_root(D_PUBLIC, &[]),
            events_root: merkle_root(D_EVENTS, &[]),
            public_record_root: merkle_root(D_PUBLIC, &[]),
            state_root: domain_hash(D_STATE, &[], 32),
        }
    }
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_fee_sponsor_rebate_batcher_roots",
            "sponsor_pool_root": self.sponsor_pool_root,
            "sponsor_coupon_lane_root": self.sponsor_coupon_lane_root,
            "sealed_coupon_root": self.sealed_coupon_root,
            "congestion_discount_root": self.congestion_discount_root,
            "pq_attested_fee_root_root": self.pq_attested_fee_root_root,
            "settlement_batch_root": self.settlement_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "coupon_nullifier_root": self.coupon_nullifier_root,
            "indexes_root": self.indexes_root,
            "events_root": self.events_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorPoolInput {
    pub operator_commitment: String,
    pub sponsor_set_root: String,
    pub coupon_policy_root: String,
    pub rebate_policy_root: String,
    pub capacity_amount: u128,
    pub max_cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_slot: u64,
}

impl SponsorPoolInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_hash_like("operator_commitment", &self.operator_commitment)?;
        ensure_hash_like("sponsor_set_root", &self.sponsor_set_root)?;
        ensure_hash_like("coupon_policy_root", &self.coupon_policy_root)?;
        ensure_hash_like("rebate_policy_root", &self.rebate_policy_root)?;
        ensure!(self.capacity_amount > 0, "capacity_amount is zero");
        ensure_bps("max_cover_bps", self.max_cover_bps)?;
        ensure!(
            self.max_cover_bps <= config.max_sponsor_cover_bps,
            "max_cover_bps exceeds runtime cap"
        );
        ensure!(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "min_privacy_set_size below runtime floor"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub operator_commitment: String,
    pub sponsor_set_root: String,
    pub coupon_policy_root: String,
    pub rebate_policy_root: String,
    pub capacity_amount: u128,
    pub available_amount: u128,
    pub max_cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_slot: u64,
    pub status: SponsorPoolStatus,
}

impl SponsorPool {
    pub fn from_input(input: SponsorPoolInput, nonce: u64) -> Self {
        let pool_id = sponsor_pool_id(&input.operator_commitment, input.opened_slot, nonce);
        Self {
            pool_id,
            operator_commitment: input.operator_commitment,
            sponsor_set_root: input.sponsor_set_root,
            coupon_policy_root: input.coupon_policy_root,
            rebate_policy_root: input.rebate_policy_root,
            capacity_amount: input.capacity_amount,
            available_amount: input.capacity_amount,
            max_cover_bps: input.max_cover_bps,
            min_privacy_set_size: input.min_privacy_set_size,
            opened_slot: input.opened_slot,
            status: SponsorPoolStatus::Attested,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "operator_commitment": self.operator_commitment,
            "sponsor_set_root": self.sponsor_set_root,
            "coupon_policy_root": self.coupon_policy_root,
            "rebate_policy_root": self.rebate_policy_root,
            "capacity_amount": self.capacity_amount.to_string(),
            "available_amount": self.available_amount.to_string(),
            "max_cover_bps": self.max_cover_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_slot": self.opened_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCouponLaneInput {
    pub pool_id: String,
    pub lane_kind: SponsorCouponLaneKind,
    pub lane_policy_root: String,
    pub encrypted_lane_key_root: String,
    pub lane_capacity_amount: u128,
    pub cover_bps: u64,
    pub start_slot: u64,
    pub end_slot: u64,
}

impl SponsorCouponLaneInput {
    pub fn validate(&self, config: &Config, pool: &SponsorPool) -> Result<()> {
        ensure_nonempty("pool_id", &self.pool_id)?;
        ensure_hash_like("lane_policy_root", &self.lane_policy_root)?;
        ensure_hash_like("encrypted_lane_key_root", &self.encrypted_lane_key_root)?;
        ensure!(
            self.lane_capacity_amount > 0,
            "lane_capacity_amount is zero"
        );
        ensure!(
            self.lane_capacity_amount <= pool.available_amount,
            "lane capacity exceeds pool availability"
        );
        ensure_bps("cover_bps", self.cover_bps)?;
        ensure!(
            self.cover_bps <= pool.max_cover_bps,
            "cover_bps exceeds pool cap"
        );
        ensure!(
            self.end_slot > self.start_slot,
            "end_slot must be greater than start_slot"
        );
        ensure!(
            self.end_slot.saturating_sub(self.start_slot) <= config.coupon_lane_ttl_slots,
            "lane exceeds coupon_lane_ttl_slots"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCouponLane {
    pub lane_id: String,
    pub pool_id: String,
    pub lane_kind: SponsorCouponLaneKind,
    pub lane_policy_root: String,
    pub encrypted_lane_key_root: String,
    pub lane_capacity_amount: u128,
    pub available_amount: u128,
    pub cover_bps: u64,
    pub priority_weight: u64,
    pub start_slot: u64,
    pub end_slot: u64,
}

impl SponsorCouponLane {
    pub fn from_input(input: SponsorCouponLaneInput, nonce: u64) -> Self {
        let lane_id = sponsor_lane_id(
            &input.pool_id,
            input.lane_kind,
            &input.lane_policy_root,
            nonce,
        );
        Self {
            lane_id,
            pool_id: input.pool_id,
            lane_kind: input.lane_kind,
            lane_policy_root: input.lane_policy_root,
            encrypted_lane_key_root: input.encrypted_lane_key_root,
            lane_capacity_amount: input.lane_capacity_amount,
            available_amount: input.lane_capacity_amount,
            cover_bps: input.cover_bps,
            priority_weight: input.lane_kind.priority_weight(),
            start_slot: input.start_slot,
            end_slot: input.end_slot,
        }
    }

    pub fn active_at(&self, slot: u64) -> bool {
        self.start_slot <= slot && slot <= self.end_slot
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "pool_id": self.pool_id,
            "lane_kind": self.lane_kind.as_str(),
            "lane_policy_root": self.lane_policy_root,
            "encrypted_lane_key_root": self.encrypted_lane_key_root,
            "lane_capacity_amount": self.lane_capacity_amount.to_string(),
            "available_amount": self.available_amount.to_string(),
            "cover_bps": self.cover_bps,
            "priority_weight": self.priority_weight,
            "start_slot": self.start_slot,
            "end_slot": self.end_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedCouponInput {
    pub lane_id: String,
    pub coupon_commitment: String,
    pub coupon_nullifier: String,
    pub beneficiary_bucket_root: String,
    pub fee_face_value: u128,
    pub user_fee_bps: u64,
    pub observed_slot: u64,
}

impl SealedCouponInput {
    pub fn validate(&self, config: &Config, lane: &SponsorCouponLane) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_hash_like("coupon_commitment", &self.coupon_commitment)?;
        ensure_hash_like("coupon_nullifier", &self.coupon_nullifier)?;
        ensure_hash_like("beneficiary_bucket_root", &self.beneficiary_bucket_root)?;
        ensure!(self.fee_face_value > 0, "fee_face_value is zero");
        ensure!(
            self.fee_face_value <= lane.available_amount,
            "coupon exceeds lane availability"
        );
        ensure_bps("user_fee_bps", self.user_fee_bps)?;
        ensure!(
            self.user_fee_bps <= config.max_user_fee_bps,
            "user_fee_bps exceeds runtime maximum"
        );
        ensure!(
            lane.active_at(self.observed_slot),
            "lane is not active at observed_slot"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedCoupon {
    pub coupon_id: String,
    pub lane_id: String,
    pub coupon_commitment: String,
    pub coupon_nullifier: String,
    pub beneficiary_bucket_root: String,
    pub fee_face_value: u128,
    pub sponsor_cover_amount: u128,
    pub user_fee_due: u128,
    pub user_fee_bps: u64,
    pub observed_slot: u64,
    pub status: CouponStatus,
}

impl SealedCoupon {
    pub fn from_input(input: SealedCouponInput, lane: &SponsorCouponLane, nonce: u64) -> Self {
        let coupon_id = sealed_coupon_id(&input.lane_id, &input.coupon_commitment, nonce);
        let sponsor_cover_amount = bps_amount(input.fee_face_value, lane.cover_bps);
        let user_fee_due = bps_amount(input.fee_face_value, input.user_fee_bps);
        Self {
            coupon_id,
            lane_id: input.lane_id,
            coupon_commitment: input.coupon_commitment,
            coupon_nullifier: input.coupon_nullifier,
            beneficiary_bucket_root: input.beneficiary_bucket_root,
            fee_face_value: input.fee_face_value,
            sponsor_cover_amount,
            user_fee_due,
            user_fee_bps: input.user_fee_bps,
            observed_slot: input.observed_slot,
            status: CouponStatus::Sealed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "lane_id": self.lane_id,
            "coupon_commitment": self.coupon_commitment,
            "beneficiary_bucket_root": self.beneficiary_bucket_root,
            "fee_face_value": self.fee_face_value.to_string(),
            "sponsor_cover_amount": self.sponsor_cover_amount.to_string(),
            "user_fee_due": self.user_fee_due.to_string(),
            "user_fee_bps": self.user_fee_bps,
            "observed_slot": self.observed_slot,
            "status": self.status.as_str(),
            "coupon_nullifier_redacted": true,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionDiscountInput {
    pub lane_id: String,
    pub pressure_bps: u64,
    pub sampled_fee_root: String,
    pub discount_policy_root: String,
    pub effective_slot: u64,
}

impl CongestionDiscountInput {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_hash_like("sampled_fee_root", &self.sampled_fee_root)?;
        ensure_hash_like("discount_policy_root", &self.discount_policy_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionDiscount {
    pub discount_id: String,
    pub lane_id: String,
    pub band: CongestionBand,
    pub pressure_bps: u64,
    pub discount_bps: u64,
    pub sponsor_haircut_bps: u64,
    pub sampled_fee_root: String,
    pub discount_policy_root: String,
    pub effective_slot: u64,
}

impl CongestionDiscount {
    pub fn from_input(input: CongestionDiscountInput, nonce: u64) -> Self {
        let band = CongestionBand::from_pressure_bps(input.pressure_bps);
        let discount_id = congestion_discount_id(&input.lane_id, band, input.effective_slot, nonce);
        Self {
            discount_id,
            lane_id: input.lane_id,
            band,
            pressure_bps: input.pressure_bps,
            discount_bps: band.discount_bps(),
            sponsor_haircut_bps: band.sponsor_haircut_bps(),
            sampled_fee_root: input.sampled_fee_root,
            discount_policy_root: input.discount_policy_root,
            effective_slot: input.effective_slot,
        }
    }

    pub fn discounted_sponsor_amount(&self, amount: u128) -> u128 {
        amount
            .saturating_sub(bps_amount(amount, self.discount_bps))
            .saturating_sub(bps_amount(amount, self.sponsor_haircut_bps))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "discount_id": self.discount_id,
            "lane_id": self.lane_id,
            "band": self.band.as_str(),
            "pressure_bps": self.pressure_bps,
            "discount_bps": self.discount_bps,
            "sponsor_haircut_bps": self.sponsor_haircut_bps,
            "sampled_fee_root": self.sampled_fee_root,
            "discount_policy_root": self.discount_policy_root,
            "effective_slot": self.effective_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestedFeeRootInput {
    pub pool_id: String,
    pub purpose: FeeRootPurpose,
    pub fee_root: String,
    pub attestation_root: String,
    pub signer_set_root: String,
    pub pq_security_bits: u16,
    pub attested_slot: u64,
    pub expires_slot: u64,
    pub verdict: AttestationVerdict,
}

impl PqAttestedFeeRootInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("pool_id", &self.pool_id)?;
        ensure_hash_like("fee_root", &self.fee_root)?;
        ensure_hash_like("attestation_root", &self.attestation_root)?;
        ensure_hash_like("signer_set_root", &self.signer_set_root)?;
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "pq_security_bits below runtime minimum"
        );
        ensure!(
            self.expires_slot > self.attested_slot,
            "expires_slot must be greater than attested_slot"
        );
        ensure!(
            self.expires_slot.saturating_sub(self.attested_slot) <= config.attested_root_ttl_slots,
            "attested fee root exceeds ttl"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestedFeeRoot {
    pub root_id: String,
    pub pool_id: String,
    pub purpose: FeeRootPurpose,
    pub fee_root: String,
    pub attestation_root: String,
    pub signer_set_root: String,
    pub pq_security_bits: u16,
    pub attested_slot: u64,
    pub expires_slot: u64,
    pub verdict: AttestationVerdict,
}

impl PqAttestedFeeRoot {
    pub fn from_input(input: PqAttestedFeeRootInput, nonce: u64) -> Self {
        let root_id = fee_root_id(&input.pool_id, input.purpose, input.attested_slot, nonce);
        Self {
            root_id,
            pool_id: input.pool_id,
            purpose: input.purpose,
            fee_root: input.fee_root,
            attestation_root: input.attestation_root,
            signer_set_root: input.signer_set_root,
            pq_security_bits: input.pq_security_bits,
            attested_slot: input.attested_slot,
            expires_slot: input.expires_slot,
            verdict: input.verdict,
        }
    }

    pub fn active_at(&self, slot: u64) -> bool {
        self.verdict.permits_settlement() && self.attested_slot <= slot && slot <= self.expires_slot
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "pool_id": self.pool_id,
            "purpose": self.purpose.as_str(),
            "fee_root": self.fee_root,
            "attestation_root": self.attestation_root,
            "signer_set_root": self.signer_set_root,
            "pq_security_bits": self.pq_security_bits,
            "attested_slot": self.attested_slot,
            "expires_slot": self.expires_slot,
            "verdict": self.verdict.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementBatchInput {
    pub pool_id: String,
    pub batch_fee_root_id: String,
    pub coupon_ids: Vec<String>,
    pub discount_ids: Vec<String>,
    pub batch_commitment: String,
    pub settlement_slot: u64,
}

impl SettlementBatchInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("pool_id", &self.pool_id)?;
        ensure_nonempty("batch_fee_root_id", &self.batch_fee_root_id)?;
        ensure_hash_like("batch_commitment", &self.batch_commitment)?;
        ensure!(
            !self.coupon_ids.is_empty(),
            "settlement batch must include coupons"
        );
        ensure!(
            self.coupon_ids.len() <= config.max_coupons_per_batch,
            "too many coupons in settlement batch"
        );
        ensure!(
            self.discount_ids.len() <= config.max_lanes_per_batch,
            "too many discount lanes in settlement batch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub pool_id: String,
    pub batch_fee_root_id: String,
    pub coupon_ids: Vec<String>,
    pub discount_ids: Vec<String>,
    pub batch_commitment: String,
    pub gross_face_value: u128,
    pub user_fee_due: u128,
    pub sponsor_fee_paid: u128,
    pub congestion_discount_amount: u128,
    pub rebate_amount: u128,
    pub settlement_slot: u64,
    pub status: BatchStatus,
}

impl LowFeeSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "batch_fee_root_id": self.batch_fee_root_id,
            "coupon_ids": self.coupon_ids,
            "discount_ids": self.discount_ids,
            "batch_commitment": self.batch_commitment,
            "gross_face_value": self.gross_face_value.to_string(),
            "user_fee_due": self.user_fee_due.to_string(),
            "sponsor_fee_paid": self.sponsor_fee_paid.to_string(),
            "congestion_discount_amount": self.congestion_discount_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "settlement_slot": self.settlement_slot,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub finality_slot: u64,
    pub settled_coupon_count: u64,
    pub settled_face_value: u128,
    pub sponsor_paid: u128,
    pub status: BatchStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "finality_slot": self.finality_slot,
            "settled_coupon_count": self.settled_coupon_count,
            "settled_face_value": self.settled_face_value.to_string(),
            "sponsor_paid": self.sponsor_paid.to_string(),
            "status": self.status.as_str(),
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
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub sponsor_coupon_lanes: BTreeMap<String, SponsorCouponLane>,
    pub sealed_coupons: BTreeMap<String, SealedCoupon>,
    pub congestion_discounts: BTreeMap<String, CongestionDiscount>,
    pub pq_attested_fee_roots: BTreeMap<String, PqAttestedFeeRoot>,
    pub settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub coupon_nullifiers: BTreeSet<String>,
    pub lanes_by_pool: BTreeMap<String, Vec<String>>,
    pub coupons_by_lane: BTreeMap<String, Vec<String>>,
    pub discounts_by_lane: BTreeMap<String, Vec<String>>,
    pub batches_by_pool: BTreeMap<String, Vec<String>>,
    pub fee_roots_by_pool: BTreeMap<String, Vec<String>>,
    pub events: Vec<RuntimeEvent>,
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
            roots: Roots::default(),
            sponsor_pools: BTreeMap::new(),
            sponsor_coupon_lanes: BTreeMap::new(),
            sealed_coupons: BTreeMap::new(),
            congestion_discounts: BTreeMap::new(),
            pq_attested_fee_roots: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            coupon_nullifiers: BTreeSet::new(),
            lanes_by_pool: BTreeMap::new(),
            coupons_by_lane: BTreeMap::new(),
            discounts_by_lane: BTreeMap::new(),
            batches_by_pool: BTreeMap::new(),
            fee_roots_by_pool: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let pool = state
            .open_sponsor_pool(SponsorPoolInput {
                operator_commitment: commitment("devnet-operator", &["fee-sponsor-batcher"]),
                sponsor_set_root: commitment(
                    "devnet-sponsor-set",
                    &["wallet", "merchant", "bridge"],
                ),
                coupon_policy_root: commitment("devnet-coupon-policy", &["low-fee", "sealed"]),
                rebate_policy_root: commitment("devnet-rebate-policy", &["congestion", "discount"]),
                capacity_amount: 50_000_000_000,
                max_cover_bps: DEFAULT_MAX_SPONSOR_COVER_BPS,
                min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                opened_slot: DEVNET_HEIGHT,
            })
            .expect("valid devnet sponsor pool");
        let wallet_lane = state
            .open_sponsor_coupon_lane(SponsorCouponLaneInput {
                pool_id: pool.pool_id.clone(),
                lane_kind: SponsorCouponLaneKind::WalletOnboarding,
                lane_policy_root: commitment("devnet-wallet-lane", &["coupon", "privacy"]),
                encrypted_lane_key_root: commitment("devnet-wallet-lane-key", &["ml-kem"]),
                lane_capacity_amount: 12_000_000_000,
                cover_bps: SponsorCouponLaneKind::WalletOnboarding.default_cover_bps(&state.config),
                start_slot: DEVNET_HEIGHT,
                end_slot: DEVNET_HEIGHT + 720,
            })
            .expect("valid devnet wallet lane");
        let bridge_lane = state
            .open_sponsor_coupon_lane(SponsorCouponLaneInput {
                pool_id: pool.pool_id.clone(),
                lane_kind: SponsorCouponLaneKind::BridgeExit,
                lane_policy_root: commitment("devnet-bridge-lane", &["exit", "coupon"]),
                encrypted_lane_key_root: commitment("devnet-bridge-lane-key", &["ml-kem"]),
                lane_capacity_amount: 18_000_000_000,
                cover_bps: SponsorCouponLaneKind::BridgeExit.default_cover_bps(&state.config),
                start_slot: DEVNET_HEIGHT,
                end_slot: DEVNET_HEIGHT + 720,
            })
            .expect("valid devnet bridge lane");
        state
            .attest_fee_root(PqAttestedFeeRootInput {
                pool_id: pool.pool_id.clone(),
                purpose: FeeRootPurpose::SettlementBatch,
                fee_root: commitment("devnet-fee-root", &["batch", "fees"]),
                attestation_root: commitment("devnet-attestation-root", &["ml-dsa", "slh-dsa"]),
                signer_set_root: commitment("devnet-signer-set", &["committee"]),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                attested_slot: DEVNET_HEIGHT,
                expires_slot: DEVNET_HEIGHT + 256,
                verdict: AttestationVerdict::Allow,
            })
            .expect("valid devnet fee root");
        let coupon_a = state
            .seal_coupon(SealedCouponInput {
                lane_id: wallet_lane.lane_id.clone(),
                coupon_commitment: commitment("devnet-coupon-a", &["wallet", "a"]),
                coupon_nullifier: commitment("devnet-nullifier-a", &["wallet", "a"]),
                beneficiary_bucket_root: commitment("devnet-beneficiary-a", &["bucket"]),
                fee_face_value: 1_500_000,
                user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
                observed_slot: DEVNET_HEIGHT + 4,
            })
            .expect("valid devnet coupon a");
        let coupon_b = state
            .seal_coupon(SealedCouponInput {
                lane_id: bridge_lane.lane_id.clone(),
                coupon_commitment: commitment("devnet-coupon-b", &["bridge", "b"]),
                coupon_nullifier: commitment("devnet-nullifier-b", &["bridge", "b"]),
                beneficiary_bucket_root: commitment("devnet-beneficiary-b", &["bucket"]),
                fee_face_value: 4_200_000,
                user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS + 2,
                observed_slot: DEVNET_HEIGHT + 5,
            })
            .expect("valid devnet coupon b");
        let discount = state
            .record_congestion_discount(CongestionDiscountInput {
                lane_id: bridge_lane.lane_id.clone(),
                pressure_bps: 18_500,
                sampled_fee_root: commitment("devnet-sampled-fee-root", &["surge"]),
                discount_policy_root: commitment("devnet-discount-policy", &["bridge"]),
                effective_slot: DEVNET_HEIGHT + 6,
            })
            .expect("valid devnet discount");
        let fee_root_id = state
            .fee_roots_by_pool
            .get(&pool.pool_id)
            .and_then(|ids| ids.first())
            .cloned()
            .expect("devnet fee root id");
        state
            .build_settlement_batch(SettlementBatchInput {
                pool_id: pool.pool_id.clone(),
                batch_fee_root_id: fee_root_id,
                coupon_ids: vec![coupon_a.coupon_id.clone(), coupon_b.coupon_id.clone()],
                discount_ids: vec![discount.discount_id.clone()],
                batch_commitment: commitment("devnet-settlement-batch", &["two-coupons"]),
                settlement_slot: DEVNET_HEIGHT + 12,
            })
            .expect("valid devnet settlement batch");
        state
    }

    pub fn open_sponsor_pool(&mut self, input: SponsorPoolInput) -> Result<SponsorPool> {
        self.config.validate()?;
        input.validate(&self.config)?;
        let pool = SponsorPool::from_input(input, self.counters.sponsor_pools + 1);
        self.counters.sponsor_pools += 1;
        self.counters.total_sponsor_capacity = self
            .counters
            .total_sponsor_capacity
            .saturating_add(pool.capacity_amount);
        self.counters.available_sponsor_capacity = self
            .counters
            .available_sponsor_capacity
            .saturating_add(pool.available_amount);
        self.sponsor_pools
            .insert(pool.pool_id.clone(), pool.clone());
        self.emit("sponsor_pool_opened", &pool.pool_id);
        self.recompute_roots();
        Ok(pool)
    }

    pub fn open_sponsor_coupon_lane(
        &mut self,
        input: SponsorCouponLaneInput,
    ) -> Result<SponsorCouponLane> {
        self.config.validate()?;
        let pool = self
            .sponsor_pools
            .get_mut(&input.pool_id)
            .ok_or_else(|| "unknown sponsor pool".to_string())?;
        ensure!(
            pool.status.accepts_lanes(),
            "sponsor pool does not accept coupon lanes"
        );
        input.validate(&self.config, pool)?;
        let lane = SponsorCouponLane::from_input(input, self.counters.sponsor_coupon_lanes + 1);
        pool.available_amount = pool
            .available_amount
            .saturating_sub(lane.lane_capacity_amount);
        self.counters.sponsor_coupon_lanes += 1;
        self.counters.available_sponsor_capacity = self
            .counters
            .available_sponsor_capacity
            .saturating_sub(lane.lane_capacity_amount);
        self.lanes_by_pool
            .entry(lane.pool_id.clone())
            .or_default()
            .push(lane.lane_id.clone());
        self.sponsor_coupon_lanes
            .insert(lane.lane_id.clone(), lane.clone());
        self.emit("sponsor_coupon_lane_opened", &lane.lane_id);
        self.recompute_roots();
        Ok(lane)
    }

    pub fn seal_coupon(&mut self, input: SealedCouponInput) -> Result<SealedCoupon> {
        self.config.validate()?;
        ensure!(
            !self.coupon_nullifiers.contains(&input.coupon_nullifier),
            "coupon nullifier already used"
        );
        let lane = self
            .sponsor_coupon_lanes
            .get_mut(&input.lane_id)
            .ok_or_else(|| "unknown sponsor coupon lane".to_string())?;
        input.validate(&self.config, lane)?;
        let coupon = SealedCoupon::from_input(input, lane, self.counters.sealed_coupons + 1);
        lane.available_amount = lane.available_amount.saturating_sub(coupon.fee_face_value);
        self.coupon_nullifiers
            .insert(coupon.coupon_nullifier.clone());
        self.counters.sealed_coupons += 1;
        self.counters.coupon_nullifiers += 1;
        self.counters.queued_coupon_face_value = self
            .counters
            .queued_coupon_face_value
            .saturating_add(coupon.fee_face_value);
        self.counters.user_fee_due = self
            .counters
            .user_fee_due
            .saturating_add(coupon.user_fee_due);
        self.coupons_by_lane
            .entry(coupon.lane_id.clone())
            .or_default()
            .push(coupon.coupon_id.clone());
        self.sealed_coupons
            .insert(coupon.coupon_id.clone(), coupon.clone());
        self.emit("sealed_coupon_queued", &coupon.coupon_id);
        self.recompute_roots();
        Ok(coupon)
    }

    pub fn record_congestion_discount(
        &mut self,
        input: CongestionDiscountInput,
    ) -> Result<CongestionDiscount> {
        input.validate()?;
        ensure!(
            self.sponsor_coupon_lanes.contains_key(&input.lane_id),
            "unknown sponsor coupon lane"
        );
        let discount =
            CongestionDiscount::from_input(input, self.counters.congestion_discounts + 1);
        self.counters.congestion_discounts += 1;
        self.discounts_by_lane
            .entry(discount.lane_id.clone())
            .or_default()
            .push(discount.discount_id.clone());
        self.congestion_discounts
            .insert(discount.discount_id.clone(), discount.clone());
        self.emit("congestion_discount_recorded", &discount.discount_id);
        self.recompute_roots();
        Ok(discount)
    }

    pub fn attest_fee_root(&mut self, input: PqAttestedFeeRootInput) -> Result<PqAttestedFeeRoot> {
        self.config.validate()?;
        input.validate(&self.config)?;
        ensure!(
            self.sponsor_pools.contains_key(&input.pool_id),
            "unknown sponsor pool"
        );
        let attested =
            PqAttestedFeeRoot::from_input(input, self.counters.pq_attested_fee_roots + 1);
        self.counters.pq_attested_fee_roots += 1;
        self.fee_roots_by_pool
            .entry(attested.pool_id.clone())
            .or_default()
            .push(attested.root_id.clone());
        self.pq_attested_fee_roots
            .insert(attested.root_id.clone(), attested.clone());
        self.emit("pq_attested_fee_root_recorded", &attested.root_id);
        self.recompute_roots();
        Ok(attested)
    }

    pub fn build_settlement_batch(
        &mut self,
        input: SettlementBatchInput,
    ) -> Result<LowFeeSettlementBatch> {
        self.config.validate()?;
        input.validate(&self.config)?;
        let pool = self
            .sponsor_pools
            .get(&input.pool_id)
            .ok_or_else(|| "unknown sponsor pool".to_string())?;
        ensure!(
            pool.status.accepts_batches(),
            "sponsor pool does not accept settlement batches"
        );
        let fee_root = self
            .pq_attested_fee_roots
            .get(&input.batch_fee_root_id)
            .ok_or_else(|| "unknown batch fee root".to_string())?;
        ensure!(
            fee_root.pool_id == input.pool_id,
            "batch fee root belongs to another pool"
        );
        ensure!(
            fee_root.active_at(input.settlement_slot),
            "batch fee root is not active at settlement_slot"
        );

        let mut lane_ids = BTreeSet::new();
        let mut gross_face_value = 0_u128;
        let mut user_fee_due = 0_u128;
        let mut sponsor_fee_before_discount = 0_u128;
        for coupon_id in &input.coupon_ids {
            let coupon = self
                .sealed_coupons
                .get(coupon_id)
                .ok_or_else(|| format!("unknown coupon {coupon_id}"))?;
            ensure!(
                coupon.status.batchable(),
                "coupon {coupon_id} is not batchable"
            );
            gross_face_value = gross_face_value.saturating_add(coupon.fee_face_value);
            user_fee_due = user_fee_due.saturating_add(coupon.user_fee_due);
            sponsor_fee_before_discount =
                sponsor_fee_before_discount.saturating_add(coupon.sponsor_cover_amount);
            lane_ids.insert(coupon.lane_id.clone());
        }

        let mut congestion_discount_amount = 0_u128;
        for discount_id in &input.discount_ids {
            let discount = self
                .congestion_discounts
                .get(discount_id)
                .ok_or_else(|| format!("unknown congestion discount {discount_id}"))?;
            ensure!(
                lane_ids.contains(&discount.lane_id),
                "discount {discount_id} does not match batch lanes"
            );
            congestion_discount_amount = congestion_discount_amount.saturating_add(bps_amount(
                sponsor_fee_before_discount,
                discount
                    .discount_bps
                    .saturating_add(discount.sponsor_haircut_bps),
            ));
        }
        let sponsor_fee_paid =
            sponsor_fee_before_discount.saturating_sub(congestion_discount_amount);
        let rebate_amount = bps_amount(
            gross_face_value.saturating_sub(user_fee_due),
            self.config.base_rebate_bps,
        )
        .min(bps_amount(gross_face_value, self.config.max_rebate_bps));
        let batch_id = settlement_batch_id(
            &input.pool_id,
            &input.batch_commitment,
            self.counters.settlement_batches + 1,
        );
        let batch = LowFeeSettlementBatch {
            batch_id: batch_id.clone(),
            pool_id: input.pool_id,
            batch_fee_root_id: input.batch_fee_root_id,
            coupon_ids: input.coupon_ids,
            discount_ids: input.discount_ids,
            batch_commitment: input.batch_commitment,
            gross_face_value,
            user_fee_due,
            sponsor_fee_paid,
            congestion_discount_amount,
            rebate_amount,
            settlement_slot: input.settlement_slot,
            status: BatchStatus::Submitted,
        };

        for coupon_id in &batch.coupon_ids {
            if let Some(coupon) = self.sealed_coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Queued;
            }
        }
        self.counters.settlement_batches += 1;
        self.counters.sponsor_fee_paid = self
            .counters
            .sponsor_fee_paid
            .saturating_add(batch.sponsor_fee_paid);
        self.counters.congestion_discount_amount = self
            .counters
            .congestion_discount_amount
            .saturating_add(batch.congestion_discount_amount);
        self.counters.rebate_amount = self
            .counters
            .rebate_amount
            .saturating_add(batch.rebate_amount);
        self.batches_by_pool
            .entry(batch.pool_id.clone())
            .or_default()
            .push(batch.batch_id.clone());
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch.clone());
        self.emit("low_fee_settlement_batch_submitted", &batch.batch_id);
        self.recompute_roots();
        Ok(batch)
    }

    pub fn finalize_settlement_batch(
        &mut self,
        batch_id: &str,
        settlement_root: String,
        rebate_root: String,
        finality_slot: u64,
    ) -> Result<SettlementReceipt> {
        ensure_hash_like("settlement_root", &settlement_root)?;
        ensure_hash_like("rebate_root", &rebate_root)?;
        let batch = self
            .settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        ensure!(
            matches!(batch.status, BatchStatus::Submitted | BatchStatus::Locked),
            "settlement batch is not finalizable"
        );
        ensure!(
            finality_slot >= batch.settlement_slot + self.config.settlement_finality_slots,
            "finality_slot is before settlement finality"
        );
        batch.status = BatchStatus::Settled;
        for coupon_id in &batch.coupon_ids {
            if let Some(coupon) = self.sealed_coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Settled;
            }
        }
        let receipt = SettlementReceipt {
            receipt_id: settlement_receipt_id(batch_id, self.counters.settlement_receipts + 1),
            batch_id: batch_id.to_string(),
            settlement_root,
            rebate_root,
            finality_slot,
            settled_coupon_count: batch.coupon_ids.len() as u64,
            settled_face_value: batch.gross_face_value,
            sponsor_paid: batch.sponsor_fee_paid,
            status: BatchStatus::Settled,
        };
        self.counters.settlement_receipts += 1;
        self.counters.queued_coupon_face_value = self
            .counters
            .queued_coupon_face_value
            .saturating_sub(batch.gross_face_value);
        self.counters.settled_coupon_face_value = self
            .counters
            .settled_coupon_face_value
            .saturating_add(batch.gross_face_value);
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.emit("settlement_batch_finalized", &receipt.receipt_id);
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        let record = json!({
            "kind": "private_l2_low_fee_pq_confidential_fee_sponsor_rebate_batcher_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "sponsor_pools": self.sponsor_pools.values().map(SponsorPool::public_record).collect::<Vec<_>>(),
            "sponsor_coupon_lanes": self.sponsor_coupon_lanes.values().map(SponsorCouponLane::public_record).collect::<Vec<_>>(),
            "sealed_coupons": self.sealed_coupons.values().map(SealedCoupon::public_record).collect::<Vec<_>>(),
            "congestion_discounts": self.congestion_discounts.values().map(CongestionDiscount::public_record).collect::<Vec<_>>(),
            "pq_attested_fee_roots": self.pq_attested_fee_roots.values().map(PqAttestedFeeRoot::public_record).collect::<Vec<_>>(),
            "settlement_batches": self.settlement_batches.values().map(LowFeeSettlementBatch::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "coupon_nullifier_root": set_root(D_NULLIFIERS, &self.coupon_nullifiers),
            "indexes_root": self.indexes_root(),
            "events": self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
        });
        let state_root = state_root_from_public_record(&record);
        let mut with_root = record;
        with_root["state_root"] = json!(state_root);
        with_root
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config_root": self.config.state_root(),
            "counters_root": self.counters.state_root(),
            "roots": self.roots.public_record_without_state_root(),
            "sponsor_pool_root": map_root(D_POOLS, &self.sponsor_pools, SponsorPool::public_record),
            "sponsor_coupon_lane_root": map_root(D_LANES, &self.sponsor_coupon_lanes, SponsorCouponLane::public_record),
            "sealed_coupon_root": map_root(D_COUPONS, &self.sealed_coupons, SealedCoupon::public_record),
            "congestion_discount_root": map_root(D_DISCOUNTS, &self.congestion_discounts, CongestionDiscount::public_record),
            "pq_attested_fee_root_root": map_root(D_FEE_ROOTS, &self.pq_attested_fee_roots, PqAttestedFeeRoot::public_record),
            "settlement_batch_root": map_root(D_BATCHES, &self.settlement_batches, LowFeeSettlementBatch::public_record),
            "settlement_receipt_root": map_root(D_RECEIPTS, &self.settlement_receipts, SettlementReceipt::public_record),
            "coupon_nullifier_root": set_root(D_NULLIFIERS, &self.coupon_nullifiers),
            "indexes_root": self.indexes_root(),
            "events_root": merkle_root(D_EVENTS, &self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>()),
        })
    }

    pub fn recompute_roots(&mut self) {
        self.roots.sponsor_pool_root =
            map_root(D_POOLS, &self.sponsor_pools, SponsorPool::public_record);
        self.roots.sponsor_coupon_lane_root = map_root(
            D_LANES,
            &self.sponsor_coupon_lanes,
            SponsorCouponLane::public_record,
        );
        self.roots.sealed_coupon_root =
            map_root(D_COUPONS, &self.sealed_coupons, SealedCoupon::public_record);
        self.roots.congestion_discount_root = map_root(
            D_DISCOUNTS,
            &self.congestion_discounts,
            CongestionDiscount::public_record,
        );
        self.roots.pq_attested_fee_root_root = map_root(
            D_FEE_ROOTS,
            &self.pq_attested_fee_roots,
            PqAttestedFeeRoot::public_record,
        );
        self.roots.settlement_batch_root = map_root(
            D_BATCHES,
            &self.settlement_batches,
            LowFeeSettlementBatch::public_record,
        );
        self.roots.settlement_receipt_root = map_root(
            D_RECEIPTS,
            &self.settlement_receipts,
            SettlementReceipt::public_record,
        );
        self.roots.coupon_nullifier_root = set_root(D_NULLIFIERS, &self.coupon_nullifiers);
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

    fn indexes_root(&self) -> String {
        merkle_root(
            D_PUBLIC,
            &[
                json!({"lanes_by_pool": self.lanes_by_pool}),
                json!({"coupons_by_lane": self.coupons_by_lane}),
                json!({"discounts_by_lane": self.discounts_by_lane}),
                json!({"batches_by_pool": self.batches_by_pool}),
                json!({"fee_roots_by_pool": self.fee_roots_by_pool}),
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

pub fn private_l2_low_fee_pq_confidential_fee_sponsor_rebate_batcher_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_low_fee_pq_confidential_fee_sponsor_rebate_batcher_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_fee_sponsor_rebate_batcher_runtime_state_root_from_record(
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
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:{domain}"),
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

fn sponsor_pool_id(operator_commitment: &str, opened_slot: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:POOL-ID",
        &[
            HashPart::Str(operator_commitment),
            HashPart::U64(opened_slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn sponsor_lane_id(
    pool_id: &str,
    lane_kind: SponsorCouponLaneKind,
    lane_policy_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:LANE-ID",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(lane_policy_root),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn sealed_coupon_id(lane_id: &str, coupon_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:COUPON-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(coupon_commitment),
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
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:DISCOUNT-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(band.as_str()),
            HashPart::U64(effective_slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn fee_root_id(pool_id: &str, purpose: FeeRootPurpose, slot: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:FEE-ROOT-ID",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(purpose.as_str()),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn settlement_batch_id(pool_id: &str, batch_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:BATCH-ID",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(batch_commitment),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn settlement_receipt_id(batch_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:RECEIPT-ID",
        &[HashPart::Str(batch_id), HashPart::U64(nonce)],
        20,
    )
}

fn event_id(kind: &str, subject_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-FEE-SPONSOR-REBATE-BATCHER:EVENT-ID",
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
