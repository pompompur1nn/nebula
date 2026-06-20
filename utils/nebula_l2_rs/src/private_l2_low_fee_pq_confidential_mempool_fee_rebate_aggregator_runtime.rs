use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialMempoolFeeRebateAggregatorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialMempoolFeeRebateAggregatorRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MEMPOOL_FEE_REBATE_AGGREGATOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-mempool-fee-rebate-aggregator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MEMPOOL_FEE_REBATE_AGGREGATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SPONSOR_COUPON_LANE_SUITE: &str =
    "ML-KEM-1024-sealed-private-l2-mempool-sponsor-coupon-lanes-v1";
pub const CONGESTION_DISCOUNT_SUITE: &str =
    "private-l2-low-fee-mempool-congestion-discount-aggregator-v1";
pub const PQ_ATTESTED_MEMPOOL_FEE_ROOT_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-attested-mempool-fee-root-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str =
    "private-l2-low-fee-mempool-rebate-settlement-batch-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-mempool-fee-rebate-aggregator-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_tx_plaintexts_sender_addresses_sponsor_wallets_view_keys_mempool_witnesses_or_coupon_plaintexts";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "mempool-fee-rebate-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 5_590_000;
pub const DEVNET_EPOCH: u64 = 54_400;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_BASE_SPONSOR_COVER_BPS: u64 = 8_600;
pub const DEFAULT_MAX_SPONSOR_COVER_BPS: u64 = 9_850;
pub const DEFAULT_BASE_REBATE_BPS: u64 = 1_400;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 6_800;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 196_608;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_572_864;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MEMPOOL_ROOT_TTL_SLOTS: u64 = 720;
pub const DEFAULT_COUPON_LANE_TTL_SLOTS: u64 = 8_640;
pub const DEFAULT_AGGREGATION_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_SETTLEMENT_FINALITY_SLOTS: u64 = 42;
pub const DEFAULT_MAX_ENTRIES_PER_BATCH: usize = 131_072;
pub const DEFAULT_MAX_LANES_PER_BATCH: usize = 384;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:ROOTS";
const D_LANES: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:LANES";
const D_ENTRIES: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:ENTRIES";
const D_DISCOUNTS: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:DISCOUNTS";
const D_FEE_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:FEE-ROOTS";
const D_BATCHES: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:BATCHES";
const D_RECEIPTS: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:RECEIPTS";
const D_NULLIFIERS: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:NULLIFIERS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:EVENTS";
const D_PUBLIC: &str = "PL2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:PUBLIC";

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
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
    SearcherBundle,
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
            Self::SearcherBundle => "searcher_bundle",
            Self::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyWithdrawal => 10_000,
            Self::BridgeExit => 9_500,
            Self::ContractCall => 8_900,
            Self::PaymasterIntent => 8_500,
            Self::SearcherBundle => 8_100,
            Self::BatchAuction => 7_800,
            Self::MerchantCheckout => 7_200,
            Self::WalletOnboarding => 6_900,
        }
    }

    pub fn default_cover_bps(self, config: &Config) -> u64 {
        let bump = match self {
            Self::EmergencyWithdrawal => 1_000,
            Self::BridgeExit => 650,
            Self::ContractCall => 280,
            Self::PaymasterIntent => 380,
            Self::SearcherBundle => 240,
            Self::BatchAuction => 180,
            Self::MerchantCheckout => 100,
            Self::WalletOnboarding => 60,
        };
        config
            .base_sponsor_cover_bps
            .saturating_add(bump)
            .min(config.max_sponsor_cover_bps)
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

    pub fn accepts_entries(self) -> bool {
        matches!(self, Self::Attested | Self::Open | Self::Throttled)
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MempoolEntryStatus {
    Observed,
    Attested,
    Aggregated,
    Settled,
    Expired,
    Quarantined,
}

impl MempoolEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Attested => "attested",
            Self::Aggregated => "aggregated",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Observed | Self::Attested | Self::Aggregated)
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
            Self::Idle => 250,
            Self::Low => 650,
            Self::Normal => 1_150,
            Self::Busy => 2_000,
            Self::Surge => 3_300,
            Self::Crisis => 4_600,
        }
    }

    pub fn aggregation_weight(self) -> u64 {
        match self {
            Self::Idle => 5_500,
            Self::Low => 6_500,
            Self::Normal => 7_500,
            Self::Busy => 8_500,
            Self::Surge => 9_300,
            Self::Crisis => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MempoolFeeRootPurpose {
    PendingFeeSnapshot,
    CouponEligibility,
    CongestionOracle,
    RebateAccumulator,
    SettlementBatch,
}

impl MempoolFeeRootPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingFeeSnapshot => "pending_fee_snapshot",
            Self::CouponEligibility => "coupon_eligibility",
            Self::CongestionOracle => "congestion_oracle",
            Self::RebateAccumulator => "rebate_accumulator",
            Self::SettlementBatch => "settlement_batch",
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
pub enum SettlementBatchStatus {
    Open,
    Submitted,
    Settled,
    Disputed,
    Expired,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
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
    pub mempool_root_ttl_slots: u64,
    pub coupon_lane_ttl_slots: u64,
    pub aggregation_window_slots: u64,
    pub settlement_finality_slots: u64,
    pub max_entries_per_batch: usize,
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
            mempool_root_ttl_slots: DEFAULT_MEMPOOL_ROOT_TTL_SLOTS,
            coupon_lane_ttl_slots: DEFAULT_COUPON_LANE_TTL_SLOTS,
            aggregation_window_slots: DEFAULT_AGGREGATION_WINDOW_SLOTS,
            settlement_finality_slots: DEFAULT_SETTLEMENT_FINALITY_SLOTS,
            max_entries_per_batch: DEFAULT_MAX_ENTRIES_PER_BATCH,
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
            self.mempool_root_ttl_slots > 0,
            "mempool_root_ttl_slots is zero"
        );
        ensure!(
            self.aggregation_window_slots > 0,
            "aggregation_window_slots is zero"
        );
        ensure!(
            self.max_entries_per_batch > 0,
            "max_entries_per_batch is zero"
        );
        ensure!(self.max_lanes_per_batch > 0, "max_lanes_per_batch is zero");
        Ok(())
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_mempool_fee_rebate_aggregator_config",
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
            "mempool_root_ttl_slots": self.mempool_root_ttl_slots,
            "coupon_lane_ttl_slots": self.coupon_lane_ttl_slots,
            "aggregation_window_slots": self.aggregation_window_slots,
            "settlement_finality_slots": self.settlement_finality_slots,
            "max_entries_per_batch": self.max_entries_per_batch,
            "max_lanes_per_batch": self.max_lanes_per_batch,
            "hash_suite": HASH_SUITE,
            "sponsor_coupon_lane_suite": SPONSOR_COUPON_LANE_SUITE,
            "congestion_discount_suite": CONGESTION_DISCOUNT_SUITE,
            "pq_attested_mempool_fee_root_suite": PQ_ATTESTED_MEMPOOL_FEE_ROOT_SUITE,
            "low_fee_settlement_batch_suite": LOW_FEE_SETTLEMENT_BATCH_SUITE,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub sponsor_coupon_lanes: u64,
    pub mempool_fee_entries: u64,
    pub congestion_discounts: u64,
    pub pq_attested_mempool_fee_roots: u64,
    pub low_fee_settlement_batches: u64,
    pub settlement_receipts: u64,
    pub entry_nullifiers: u64,
    pub public_records: u64,
    pub events_emitted: u64,
    pub total_lane_capacity: u128,
    pub available_lane_capacity: u128,
    pub observed_fee_face_value: u128,
    pub aggregated_fee_face_value: u128,
    pub settled_fee_face_value: u128,
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
            "kind": "private_l2_low_fee_pq_confidential_mempool_fee_rebate_aggregator_counters",
            "sponsor_coupon_lanes": self.sponsor_coupon_lanes,
            "mempool_fee_entries": self.mempool_fee_entries,
            "congestion_discounts": self.congestion_discounts,
            "pq_attested_mempool_fee_roots": self.pq_attested_mempool_fee_roots,
            "low_fee_settlement_batches": self.low_fee_settlement_batches,
            "settlement_receipts": self.settlement_receipts,
            "entry_nullifiers": self.entry_nullifiers,
            "public_records": self.public_records,
            "events_emitted": self.events_emitted,
            "total_lane_capacity": self.total_lane_capacity.to_string(),
            "available_lane_capacity": self.available_lane_capacity.to_string(),
            "observed_fee_face_value": self.observed_fee_face_value.to_string(),
            "aggregated_fee_face_value": self.aggregated_fee_face_value.to_string(),
            "settled_fee_face_value": self.settled_fee_face_value.to_string(),
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
    pub sponsor_coupon_lane_root: String,
    pub mempool_fee_entry_root: String,
    pub congestion_discount_root: String,
    pub pq_attested_mempool_fee_root_root: String,
    pub low_fee_settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub entry_nullifier_root: String,
    pub indexes_root: String,
    pub events_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            sponsor_coupon_lane_root: merkle_root(D_LANES, &[]),
            mempool_fee_entry_root: merkle_root(D_ENTRIES, &[]),
            congestion_discount_root: merkle_root(D_DISCOUNTS, &[]),
            pq_attested_mempool_fee_root_root: merkle_root(D_FEE_ROOTS, &[]),
            low_fee_settlement_batch_root: merkle_root(D_BATCHES, &[]),
            settlement_receipt_root: merkle_root(D_RECEIPTS, &[]),
            entry_nullifier_root: merkle_root(D_NULLIFIERS, &[]),
            indexes_root: merkle_root(D_PUBLIC, &[]),
            events_root: merkle_root(D_EVENTS, &[]),
            public_record_root: merkle_root(D_PUBLIC, &[]),
            state_root: merkle_root(D_STATE, &[]),
        }
    }
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_mempool_fee_rebate_aggregator_roots",
            "sponsor_coupon_lane_root": self.sponsor_coupon_lane_root,
            "mempool_fee_entry_root": self.mempool_fee_entry_root,
            "congestion_discount_root": self.congestion_discount_root,
            "pq_attested_mempool_fee_root_root": self.pq_attested_mempool_fee_root_root,
            "low_fee_settlement_batch_root": self.low_fee_settlement_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "entry_nullifier_root": self.entry_nullifier_root,
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

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCouponLaneInput {
    pub sponsor_commitment: String,
    pub lane_kind: SponsorCouponLaneKind,
    pub lane_policy_root: String,
    pub coupon_root: String,
    pub capacity: u128,
    pub sponsor_cover_bps: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub pq_attestation_root: String,
    pub privacy_set_size: u64,
}

impl SponsorCouponLaneInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_hash_like("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_hash_like("lane_policy_root", &self.lane_policy_root)?;
        ensure_hash_like("coupon_root", &self.coupon_root)?;
        ensure_hash_like("pq_attestation_root", &self.pq_attestation_root)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        ensure!(self.capacity > 0, "capacity is zero");
        ensure!(
            self.sponsor_cover_bps <= config.max_sponsor_cover_bps,
            "sponsor_cover_bps exceeds max"
        );
        ensure!(
            self.expires_slot > self.opened_slot,
            "expires_slot must be after opened_slot"
        );
        ensure!(
            self.expires_slot - self.opened_slot <= config.coupon_lane_ttl_slots,
            "coupon lane ttl exceeds config"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "privacy set below config minimum"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCouponLane {
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub lane_kind: SponsorCouponLaneKind,
    pub status: LaneStatus,
    pub lane_policy_root: String,
    pub coupon_root: String,
    pub capacity: u128,
    pub available_capacity: u128,
    pub sponsor_cover_bps: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub pq_attestation_root: String,
    pub privacy_set_size: u64,
    pub priority_weight: u64,
}

impl SponsorCouponLane {
    pub fn from_input(input: SponsorCouponLaneInput, nonce: u64) -> Self {
        let lane_id = sponsor_lane_id(
            &input.sponsor_commitment,
            input.lane_kind,
            &input.lane_policy_root,
            nonce,
        );
        Self {
            lane_id,
            sponsor_commitment: input.sponsor_commitment,
            lane_kind: input.lane_kind,
            status: LaneStatus::Attested,
            lane_policy_root: input.lane_policy_root,
            coupon_root: input.coupon_root,
            capacity: input.capacity,
            available_capacity: input.capacity,
            sponsor_cover_bps: input.sponsor_cover_bps,
            opened_slot: input.opened_slot,
            expires_slot: input.expires_slot,
            pq_attestation_root: input.pq_attestation_root,
            privacy_set_size: input.privacy_set_size,
            priority_weight: input.lane_kind.priority_weight(),
        }
    }

    pub fn active_at(&self, slot: u64) -> bool {
        self.opened_slot <= slot && slot <= self.expires_slot && self.status.accepts_entries()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_coupon_lane",
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "status": self.status.as_str(),
            "lane_policy_root": self.lane_policy_root,
            "coupon_root": self.coupon_root,
            "capacity": self.capacity.to_string(),
            "available_capacity": self.available_capacity.to_string(),
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_set_size": self.privacy_set_size,
            "priority_weight": self.priority_weight,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MempoolFeeEntryInput {
    pub lane_id: String,
    pub entry_commitment: String,
    pub entry_nullifier: String,
    pub mempool_fee_root_id: String,
    pub fee_face_value: u128,
    pub declared_user_fee_bps: u64,
    pub observed_slot: u64,
    pub congestion_pressure_bps: u64,
    pub privacy_set_size: u64,
}

impl MempoolFeeEntryInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_hash_like("entry_commitment", &self.entry_commitment)?;
        ensure_hash_like("entry_nullifier", &self.entry_nullifier)?;
        ensure_nonempty("mempool_fee_root_id", &self.mempool_fee_root_id)?;
        ensure!(self.fee_face_value > 0, "fee_face_value is zero");
        ensure_bps("declared_user_fee_bps", self.declared_user_fee_bps)?;
        ensure_bps(
            "congestion_pressure_bps",
            self.congestion_pressure_bps.min(MAX_BPS),
        )?;
        ensure!(
            self.declared_user_fee_bps <= config.max_user_fee_bps,
            "declared_user_fee_bps exceeds max"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "privacy set below config minimum"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MempoolFeeEntry {
    pub entry_id: String,
    pub lane_id: String,
    pub entry_commitment: String,
    pub entry_nullifier: String,
    pub mempool_fee_root_id: String,
    pub fee_face_value: u128,
    pub user_fee_due: u128,
    pub sponsor_cover_amount: u128,
    pub rebate_floor_amount: u128,
    pub observed_slot: u64,
    pub congestion_band: CongestionBand,
    pub privacy_set_size: u64,
    pub status: MempoolEntryStatus,
}

impl MempoolFeeEntry {
    pub fn from_input(input: MempoolFeeEntryInput, lane: &SponsorCouponLane, nonce: u64) -> Self {
        let user_fee_due = bps_amount(input.fee_face_value, input.declared_user_fee_bps);
        let sponsor_cover_amount = bps_amount(input.fee_face_value, lane.sponsor_cover_bps);
        let rebate_floor_amount = input
            .fee_face_value
            .saturating_sub(user_fee_due)
            .saturating_sub(sponsor_cover_amount.min(input.fee_face_value));
        Self {
            entry_id: mempool_entry_id(&input.lane_id, &input.entry_commitment, nonce),
            lane_id: input.lane_id,
            entry_commitment: input.entry_commitment,
            entry_nullifier: input.entry_nullifier,
            mempool_fee_root_id: input.mempool_fee_root_id,
            fee_face_value: input.fee_face_value,
            user_fee_due,
            sponsor_cover_amount,
            rebate_floor_amount,
            observed_slot: input.observed_slot,
            congestion_band: CongestionBand::from_pressure_bps(input.congestion_pressure_bps),
            privacy_set_size: input.privacy_set_size,
            status: MempoolEntryStatus::Observed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "mempool_fee_entry",
            "entry_id": self.entry_id,
            "lane_id": self.lane_id,
            "entry_commitment": self.entry_commitment,
            "entry_nullifier": self.entry_nullifier,
            "mempool_fee_root_id": self.mempool_fee_root_id,
            "fee_face_value": self.fee_face_value.to_string(),
            "user_fee_due": self.user_fee_due.to_string(),
            "sponsor_cover_amount": self.sponsor_cover_amount.to_string(),
            "rebate_floor_amount": self.rebate_floor_amount.to_string(),
            "observed_slot": self.observed_slot,
            "congestion_band": self.congestion_band.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionDiscountInput {
    pub lane_id: String,
    pub discount_policy_root: String,
    pub effective_slot: u64,
    pub expires_slot: u64,
    pub pressure_bps: u64,
    pub override_discount_bps: Option<u64>,
}

impl CongestionDiscountInput {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_hash_like("discount_policy_root", &self.discount_policy_root)?;
        ensure!(
            self.expires_slot > self.effective_slot,
            "expires_slot must be after effective_slot"
        );
        if let Some(override_discount_bps) = self.override_discount_bps {
            ensure_bps("override_discount_bps", override_discount_bps)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CongestionDiscount {
    pub discount_id: String,
    pub lane_id: String,
    pub discount_policy_root: String,
    pub effective_slot: u64,
    pub expires_slot: u64,
    pub congestion_band: CongestionBand,
    pub discount_bps: u64,
    pub aggregation_weight: u64,
}

impl CongestionDiscount {
    pub fn from_input(input: CongestionDiscountInput, nonce: u64) -> Self {
        let band = CongestionBand::from_pressure_bps(input.pressure_bps);
        let discount_bps = input
            .override_discount_bps
            .unwrap_or_else(|| band.discount_bps());
        Self {
            discount_id: congestion_discount_id(&input.lane_id, band, input.effective_slot, nonce),
            lane_id: input.lane_id,
            discount_policy_root: input.discount_policy_root,
            effective_slot: input.effective_slot,
            expires_slot: input.expires_slot,
            congestion_band: band,
            discount_bps,
            aggregation_weight: band.aggregation_weight(),
        }
    }

    pub fn active_at(&self, slot: u64) -> bool {
        self.effective_slot <= slot && slot <= self.expires_slot
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "congestion_discount",
            "discount_id": self.discount_id,
            "lane_id": self.lane_id,
            "discount_policy_root": self.discount_policy_root,
            "effective_slot": self.effective_slot,
            "expires_slot": self.expires_slot,
            "congestion_band": self.congestion_band.as_str(),
            "discount_bps": self.discount_bps,
            "aggregation_weight": self.aggregation_weight,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestedMempoolFeeRootInput {
    pub purpose: MempoolFeeRootPurpose,
    pub mempool_fee_root: String,
    pub attestation_root: String,
    pub signer_set_root: String,
    pub slot: u64,
    pub expires_slot: u64,
    pub pq_security_bits: u16,
    pub verdict: AttestationVerdict,
}

impl PqAttestedMempoolFeeRootInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_hash_like("mempool_fee_root", &self.mempool_fee_root)?;
        ensure_hash_like("attestation_root", &self.attestation_root)?;
        ensure_hash_like("signer_set_root", &self.signer_set_root)?;
        ensure!(
            self.expires_slot > self.slot,
            "expires_slot must be after slot"
        );
        ensure!(
            self.expires_slot - self.slot <= config.mempool_root_ttl_slots,
            "mempool fee root ttl exceeds config"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "pq security bits below config minimum"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAttestedMempoolFeeRoot {
    pub root_id: String,
    pub purpose: MempoolFeeRootPurpose,
    pub mempool_fee_root: String,
    pub attestation_root: String,
    pub signer_set_root: String,
    pub slot: u64,
    pub expires_slot: u64,
    pub pq_security_bits: u16,
    pub verdict: AttestationVerdict,
}

impl PqAttestedMempoolFeeRoot {
    pub fn from_input(input: PqAttestedMempoolFeeRootInput, nonce: u64) -> Self {
        Self {
            root_id: mempool_fee_root_id(input.purpose, &input.mempool_fee_root, input.slot, nonce),
            purpose: input.purpose,
            mempool_fee_root: input.mempool_fee_root,
            attestation_root: input.attestation_root,
            signer_set_root: input.signer_set_root,
            slot: input.slot,
            expires_slot: input.expires_slot,
            pq_security_bits: input.pq_security_bits,
            verdict: input.verdict,
        }
    }

    pub fn active_at(&self, slot: u64) -> bool {
        self.slot <= slot && slot <= self.expires_slot && self.verdict.permits_settlement()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_attested_mempool_fee_root",
            "root_id": self.root_id,
            "purpose": self.purpose.as_str(),
            "mempool_fee_root": self.mempool_fee_root,
            "attestation_root": self.attestation_root,
            "signer_set_root": self.signer_set_root,
            "slot": self.slot,
            "expires_slot": self.expires_slot,
            "pq_security_bits": self.pq_security_bits,
            "verdict": self.verdict.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeSettlementBatchInput {
    pub batch_fee_root_id: String,
    pub entry_ids: Vec<String>,
    pub discount_ids: Vec<String>,
    pub batch_commitment: String,
    pub settlement_slot: u64,
}

impl LowFeeSettlementBatchInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("batch_fee_root_id", &self.batch_fee_root_id)?;
        ensure_hash_like("batch_commitment", &self.batch_commitment)?;
        ensure!(!self.entry_ids.is_empty(), "entry_ids is empty");
        ensure!(
            self.entry_ids.len() <= config.max_entries_per_batch,
            "entry_ids exceeds max_entries_per_batch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub batch_fee_root_id: String,
    pub entry_ids: Vec<String>,
    pub discount_ids: Vec<String>,
    pub batch_commitment: String,
    pub gross_fee_face_value: u128,
    pub user_fee_due: u128,
    pub sponsor_fee_paid: u128,
    pub congestion_discount_amount: u128,
    pub rebate_amount: u128,
    pub lane_count: u64,
    pub settlement_slot: u64,
    pub status: SettlementBatchStatus,
}

impl LowFeeSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_settlement_batch",
            "batch_id": self.batch_id,
            "batch_fee_root_id": self.batch_fee_root_id,
            "entry_ids": self.entry_ids,
            "discount_ids": self.discount_ids,
            "batch_commitment": self.batch_commitment,
            "gross_fee_face_value": self.gross_fee_face_value.to_string(),
            "user_fee_due": self.user_fee_due.to_string(),
            "sponsor_fee_paid": self.sponsor_fee_paid.to_string(),
            "congestion_discount_amount": self.congestion_discount_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "lane_count": self.lane_count,
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
    pub settled_entry_count: u64,
    pub settled_fee_face_value: u128,
    pub sponsor_paid: u128,
    pub rebate_amount: u128,
    pub status: SettlementBatchStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "finality_slot": self.finality_slot,
            "settled_entry_count": self.settled_entry_count,
            "settled_fee_face_value": self.settled_fee_face_value.to_string(),
            "sponsor_paid": self.sponsor_paid.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
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
            "kind": self.kind,
            "event_id": self.event_id,
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
    pub sponsor_coupon_lanes: BTreeMap<String, SponsorCouponLane>,
    pub mempool_fee_entries: BTreeMap<String, MempoolFeeEntry>,
    pub congestion_discounts: BTreeMap<String, CongestionDiscount>,
    pub pq_attested_mempool_fee_roots: BTreeMap<String, PqAttestedMempoolFeeRoot>,
    pub low_fee_settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub entry_nullifiers: BTreeSet<String>,
    pub entries_by_lane: BTreeMap<String, Vec<String>>,
    pub discounts_by_lane: BTreeMap<String, Vec<String>>,
    pub batches_by_root: BTreeMap<String, Vec<String>>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sponsor_coupon_lanes: BTreeMap::new(),
            mempool_fee_entries: BTreeMap::new(),
            congestion_discounts: BTreeMap::new(),
            pq_attested_mempool_fee_roots: BTreeMap::new(),
            low_fee_settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            entry_nullifiers: BTreeSet::new(),
            entries_by_lane: BTreeMap::new(),
            discounts_by_lane: BTreeMap::new(),
            batches_by_root: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet mempool fee rebate aggregator config is valid")
    }

    pub fn open_sponsor_coupon_lane(
        &mut self,
        input: SponsorCouponLaneInput,
    ) -> Result<SponsorCouponLane> {
        self.config.validate()?;
        input.validate(&self.config)?;
        let lane = SponsorCouponLane::from_input(input, self.counters.sponsor_coupon_lanes + 1);
        self.counters.sponsor_coupon_lanes += 1;
        self.counters.total_lane_capacity = self
            .counters
            .total_lane_capacity
            .saturating_add(lane.capacity);
        self.counters.available_lane_capacity = self
            .counters
            .available_lane_capacity
            .saturating_add(lane.available_capacity);
        self.sponsor_coupon_lanes
            .insert(lane.lane_id.clone(), lane.clone());
        self.emit("sponsor_coupon_lane_opened", &lane.lane_id);
        self.recompute_roots();
        Ok(lane)
    }

    pub fn set_lane_status(&mut self, lane_id: &str, status: LaneStatus) -> Result<()> {
        let lane = self
            .sponsor_coupon_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown sponsor coupon lane".to_string())?;
        lane.status = status;
        self.emit("sponsor_coupon_lane_status_changed", lane_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn attest_mempool_fee_root(
        &mut self,
        input: PqAttestedMempoolFeeRootInput,
    ) -> Result<PqAttestedMempoolFeeRoot> {
        self.config.validate()?;
        input.validate(&self.config)?;
        let root = PqAttestedMempoolFeeRoot::from_input(
            input,
            self.counters.pq_attested_mempool_fee_roots + 1,
        );
        self.counters.pq_attested_mempool_fee_roots += 1;
        self.pq_attested_mempool_fee_roots
            .insert(root.root_id.clone(), root.clone());
        self.emit("pq_attested_mempool_fee_root_recorded", &root.root_id);
        self.recompute_roots();
        Ok(root)
    }

    pub fn observe_mempool_fee_entry(
        &mut self,
        input: MempoolFeeEntryInput,
    ) -> Result<MempoolFeeEntry> {
        self.config.validate()?;
        input.validate(&self.config)?;
        ensure!(
            !self.entry_nullifiers.contains(&input.entry_nullifier),
            "entry nullifier already observed"
        );
        let lane = self
            .sponsor_coupon_lanes
            .get(&input.lane_id)
            .ok_or_else(|| "unknown sponsor coupon lane".to_string())?;
        ensure!(
            lane.active_at(input.observed_slot),
            "sponsor coupon lane is not active at observed_slot"
        );
        ensure!(
            lane.status.accepts_entries(),
            "sponsor coupon lane does not accept entries"
        );
        let fee_root = self
            .pq_attested_mempool_fee_roots
            .get(&input.mempool_fee_root_id)
            .ok_or_else(|| "unknown pq-attested mempool fee root".to_string())?;
        ensure!(
            fee_root.active_at(input.observed_slot),
            "pq-attested mempool fee root is not active at observed_slot"
        );
        let entry = MempoolFeeEntry::from_input(input, lane, self.counters.mempool_fee_entries + 1);
        ensure!(
            entry.sponsor_cover_amount <= lane.available_capacity,
            "lane capacity insufficient for entry sponsor cover"
        );
        if let Some(lane) = self.sponsor_coupon_lanes.get_mut(&entry.lane_id) {
            lane.available_capacity = lane
                .available_capacity
                .saturating_sub(entry.sponsor_cover_amount);
        }
        self.counters.mempool_fee_entries += 1;
        self.counters.entry_nullifiers += 1;
        self.counters.observed_fee_face_value = self
            .counters
            .observed_fee_face_value
            .saturating_add(entry.fee_face_value);
        self.counters.user_fee_due = self
            .counters
            .user_fee_due
            .saturating_add(entry.user_fee_due);
        self.counters.available_lane_capacity = self
            .counters
            .available_lane_capacity
            .saturating_sub(entry.sponsor_cover_amount);
        self.entry_nullifiers.insert(entry.entry_nullifier.clone());
        self.entries_by_lane
            .entry(entry.lane_id.clone())
            .or_default()
            .push(entry.entry_id.clone());
        self.mempool_fee_entries
            .insert(entry.entry_id.clone(), entry.clone());
        self.emit("mempool_fee_entry_observed", &entry.entry_id);
        self.recompute_roots();
        Ok(entry)
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

    pub fn build_low_fee_settlement_batch(
        &mut self,
        input: LowFeeSettlementBatchInput,
    ) -> Result<LowFeeSettlementBatch> {
        self.config.validate()?;
        input.validate(&self.config)?;
        let fee_root = self
            .pq_attested_mempool_fee_roots
            .get(&input.batch_fee_root_id)
            .ok_or_else(|| "unknown batch fee root".to_string())?;
        ensure!(
            fee_root.purpose == MempoolFeeRootPurpose::SettlementBatch,
            "batch fee root has wrong purpose"
        );
        ensure!(
            fee_root.active_at(input.settlement_slot),
            "batch fee root is not active at settlement_slot"
        );

        let mut lane_ids = BTreeSet::new();
        let mut gross_fee_face_value = 0_u128;
        let mut user_fee_due = 0_u128;
        let mut sponsor_fee_before_discount = 0_u128;
        for entry_id in &input.entry_ids {
            let entry = self
                .mempool_fee_entries
                .get(entry_id)
                .ok_or_else(|| format!("unknown mempool fee entry {entry_id}"))?;
            ensure!(
                entry.status.batchable(),
                "entry {entry_id} is not batchable"
            );
            let lane = self
                .sponsor_coupon_lanes
                .get(&entry.lane_id)
                .ok_or_else(|| format!("unknown lane {}", entry.lane_id))?;
            ensure!(
                lane.status.accepts_batches(),
                "lane {} does not accept batches",
                entry.lane_id
            );
            gross_fee_face_value = gross_fee_face_value.saturating_add(entry.fee_face_value);
            user_fee_due = user_fee_due.saturating_add(entry.user_fee_due);
            sponsor_fee_before_discount =
                sponsor_fee_before_discount.saturating_add(entry.sponsor_cover_amount);
            lane_ids.insert(entry.lane_id.clone());
        }
        ensure!(
            lane_ids.len() <= self.config.max_lanes_per_batch,
            "lane count exceeds max_lanes_per_batch"
        );

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
            ensure!(
                discount.active_at(input.settlement_slot),
                "discount {discount_id} is not active at settlement_slot"
            );
            congestion_discount_amount = congestion_discount_amount.saturating_add(bps_amount(
                sponsor_fee_before_discount,
                discount.discount_bps,
            ));
        }
        let sponsor_fee_paid =
            sponsor_fee_before_discount.saturating_sub(congestion_discount_amount);
        let rebate_base = gross_fee_face_value.saturating_sub(user_fee_due);
        let rebate_amount = bps_amount(rebate_base, self.config.base_rebate_bps)
            .min(bps_amount(gross_fee_face_value, self.config.max_rebate_bps));
        let batch_id = settlement_batch_id(
            &input.batch_fee_root_id,
            &input.batch_commitment,
            self.counters.low_fee_settlement_batches + 1,
        );
        let batch = LowFeeSettlementBatch {
            batch_id: batch_id.clone(),
            batch_fee_root_id: input.batch_fee_root_id,
            entry_ids: input.entry_ids,
            discount_ids: input.discount_ids,
            batch_commitment: input.batch_commitment,
            gross_fee_face_value,
            user_fee_due,
            sponsor_fee_paid,
            congestion_discount_amount,
            rebate_amount,
            lane_count: lane_ids.len() as u64,
            settlement_slot: input.settlement_slot,
            status: SettlementBatchStatus::Submitted,
        };

        for entry_id in &batch.entry_ids {
            if let Some(entry) = self.mempool_fee_entries.get_mut(entry_id) {
                entry.status = MempoolEntryStatus::Aggregated;
            }
        }
        self.counters.low_fee_settlement_batches += 1;
        self.counters.aggregated_fee_face_value = self
            .counters
            .aggregated_fee_face_value
            .saturating_add(batch.gross_fee_face_value);
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
        self.batches_by_root
            .entry(batch.batch_fee_root_id.clone())
            .or_default()
            .push(batch.batch_id.clone());
        self.low_fee_settlement_batches
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
            .low_fee_settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        ensure!(
            matches!(batch.status, SettlementBatchStatus::Submitted),
            "settlement batch is not finalizable"
        );
        ensure!(
            finality_slot >= batch.settlement_slot + self.config.settlement_finality_slots,
            "finality_slot is before settlement finality"
        );
        batch.status = SettlementBatchStatus::Settled;
        for entry_id in &batch.entry_ids {
            if let Some(entry) = self.mempool_fee_entries.get_mut(entry_id) {
                entry.status = MempoolEntryStatus::Settled;
            }
        }
        let receipt = SettlementReceipt {
            receipt_id: settlement_receipt_id(batch_id, self.counters.settlement_receipts + 1),
            batch_id: batch_id.to_string(),
            settlement_root,
            rebate_root,
            finality_slot,
            settled_entry_count: batch.entry_ids.len() as u64,
            settled_fee_face_value: batch.gross_fee_face_value,
            sponsor_paid: batch.sponsor_fee_paid,
            rebate_amount: batch.rebate_amount,
            status: SettlementBatchStatus::Settled,
        };
        self.counters.settlement_receipts += 1;
        self.counters.settled_fee_face_value = self
            .counters
            .settled_fee_face_value
            .saturating_add(batch.gross_fee_face_value);
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.emit("settlement_batch_finalized", &receipt.receipt_id);
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        let record = json!({
            "kind": "private_l2_low_fee_pq_confidential_mempool_fee_rebate_aggregator_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "sponsor_coupon_lanes": self.sponsor_coupon_lanes.values().map(SponsorCouponLane::public_record).collect::<Vec<_>>(),
            "mempool_fee_entries": self.mempool_fee_entries.values().map(MempoolFeeEntry::public_record).collect::<Vec<_>>(),
            "congestion_discounts": self.congestion_discounts.values().map(CongestionDiscount::public_record).collect::<Vec<_>>(),
            "pq_attested_mempool_fee_roots": self.pq_attested_mempool_fee_roots.values().map(PqAttestedMempoolFeeRoot::public_record).collect::<Vec<_>>(),
            "low_fee_settlement_batches": self.low_fee_settlement_batches.values().map(LowFeeSettlementBatch::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "entry_nullifier_root": set_root(D_NULLIFIERS, &self.entry_nullifiers),
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
            "sponsor_coupon_lane_root": map_root(D_LANES, &self.sponsor_coupon_lanes, SponsorCouponLane::public_record),
            "mempool_fee_entry_root": map_root(D_ENTRIES, &self.mempool_fee_entries, MempoolFeeEntry::public_record),
            "congestion_discount_root": map_root(D_DISCOUNTS, &self.congestion_discounts, CongestionDiscount::public_record),
            "pq_attested_mempool_fee_root_root": map_root(D_FEE_ROOTS, &self.pq_attested_mempool_fee_roots, PqAttestedMempoolFeeRoot::public_record),
            "low_fee_settlement_batch_root": map_root(D_BATCHES, &self.low_fee_settlement_batches, LowFeeSettlementBatch::public_record),
            "settlement_receipt_root": map_root(D_RECEIPTS, &self.settlement_receipts, SettlementReceipt::public_record),
            "entry_nullifier_root": set_root(D_NULLIFIERS, &self.entry_nullifiers),
            "indexes_root": self.indexes_root(),
            "events_root": merkle_root(D_EVENTS, &self.events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>()),
        })
    }

    pub fn recompute_roots(&mut self) {
        self.roots.sponsor_coupon_lane_root = map_root(
            D_LANES,
            &self.sponsor_coupon_lanes,
            SponsorCouponLane::public_record,
        );
        self.roots.mempool_fee_entry_root = map_root(
            D_ENTRIES,
            &self.mempool_fee_entries,
            MempoolFeeEntry::public_record,
        );
        self.roots.congestion_discount_root = map_root(
            D_DISCOUNTS,
            &self.congestion_discounts,
            CongestionDiscount::public_record,
        );
        self.roots.pq_attested_mempool_fee_root_root = map_root(
            D_FEE_ROOTS,
            &self.pq_attested_mempool_fee_roots,
            PqAttestedMempoolFeeRoot::public_record,
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
        self.roots.entry_nullifier_root = set_root(D_NULLIFIERS, &self.entry_nullifiers);
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
                json!({"entries_by_lane": self.entries_by_lane}),
                json!({"discounts_by_lane": self.discounts_by_lane}),
                json!({"batches_by_root": self.batches_by_root}),
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

pub fn private_l2_low_fee_pq_confidential_mempool_fee_rebate_aggregator_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_low_fee_pq_confidential_mempool_fee_rebate_aggregator_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_mempool_fee_rebate_aggregator_runtime_state_root_from_record(
    record: &Value,
) -> String {
    state_root_from_public_record(record)
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
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

fn sponsor_lane_id(
    sponsor_commitment: &str,
    lane_kind: SponsorCouponLaneKind,
    lane_policy_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:LANE-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(lane_policy_root),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn mempool_entry_id(lane_id: &str, entry_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:ENTRY-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(entry_commitment),
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
        "PRIVATE-L2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:DISCOUNT-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(band.as_str()),
            HashPart::U64(effective_slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn mempool_fee_root_id(
    purpose: MempoolFeeRootPurpose,
    mempool_fee_root: &str,
    slot: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:FEE-ROOT-ID",
        &[
            HashPart::Str(purpose.as_str()),
            HashPart::Str(mempool_fee_root),
            HashPart::U64(slot),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn settlement_batch_id(batch_fee_root_id: &str, batch_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:BATCH-ID",
        &[
            HashPart::Str(batch_fee_root_id),
            HashPart::Str(batch_commitment),
            HashPart::U64(nonce),
        ],
        20,
    )
}

fn settlement_receipt_id(batch_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:RECEIPT-ID",
        &[HashPart::Str(batch_id), HashPart::U64(nonce)],
        20,
    )
}

fn event_id(kind: &str, subject_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONF-MEMPOOL-FEE-REBATE-AGGREGATOR:EVENT-ID",
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
