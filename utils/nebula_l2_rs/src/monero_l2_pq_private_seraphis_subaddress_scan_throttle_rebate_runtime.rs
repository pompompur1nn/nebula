use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateSeraphisSubaddressScanThrottleRebateRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_SERAPHIS_SUBADDRESS_SCAN_THROTTLE_REBATE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-seraphis-subaddress-scan-throttle-rebate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SERAPHIS_SUBADDRESS_SCAN_THROTTLE_REBATE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SERAPHIS_SUBADDRESS_LANE_SCHEME: &str =
    "seraphis-subaddress-scan-lane-commitment-root-v1";
pub const SCAN_THROTTLE_WINDOW_SCHEME: &str = "seraphis-subaddress-scan-throttle-window-root-v1";
pub const REBATE_POOL_SCHEME: &str = "seraphis-subaddress-scan-rebate-pool-root-v1";
pub const PQ_SPONSOR_RECEIPT_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-seraphis-scan-rebate-sponsor-receipt-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "seraphis-subaddress-privacy-budget-root-v1";
pub const DECOY_SCAN_SHIELDING_SCHEME: &str = "seraphis-decoy-scan-shielding-root-v1";
pub const NULLIFIER_GUARD_SCHEME: &str = "seraphis-scan-rebate-nullifier-guard-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-seraphis-subaddress-scan-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "seraphis-subaddress-scan-throttle-rebate-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_addresses_amounts_view_keys_key_images_subaddress_indices_or_wallet_graphs";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_MARKET_ID: &str =
    "monero-l2-pq-private-seraphis-subaddress-scan-throttle-rebate-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "xmr-seraphis-scan-credit-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_317_120;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_994_560;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 786_432;
pub const DEFAULT_MIN_SUBADDRESS_BUCKET_OUTPUTS: u32 = 128;
pub const DEFAULT_TARGET_SUBADDRESS_BUCKET_OUTPUTS: u32 = 2_048;
pub const DEFAULT_MIN_DECOY_COUNT: u16 = 16;
pub const DEFAULT_TARGET_DECOY_COUNT: u16 = 96;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 8_850;
pub const DEFAULT_MIN_SCAN_SPEEDUP_BPS: u64 = 5_500;
pub const DEFAULT_TARGET_SCAN_SPEEDUP_BPS: u64 = 8_600;
pub const DEFAULT_MAX_SCAN_FEE_PICONERO: u64 = 3_200;
pub const DEFAULT_TARGET_SCAN_FEE_PICONERO: u64 = 700;
pub const DEFAULT_REBATE_BPS: u64 = 8_750;
pub const DEFAULT_SPONSOR_BUFFER_BPS: u64 = 1_500;
pub const DEFAULT_OPERATOR_FEE_SHARE_BPS: u64 = 650;
pub const DEFAULT_RESERVE_BPS: u64 = 900;
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_WINDOW_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_NULLIFIER_TTL_BLOCKS: u64 = 20_160;
pub const DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 65_536;
pub const DEFAULT_MAX_DISCLOSURE_FIELDS: u32 = 4;
pub const DEFAULT_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_MAX_WINDOW_LOAD_BPS: u64 = 8_200;
pub const DEFAULT_HARD_WINDOW_LOAD_BPS: u64 = 9_300;
pub const DEFAULT_DAILY_WALLET_CAP_PICONERO: u64 = 96_000;
pub const MAX_SCAN_LANES: usize = 1_048_576;
pub const MAX_THROTTLE_WINDOWS: usize = 524_288;
pub const MAX_REBATE_POOLS: usize = 262_144;
pub const MAX_SPONSOR_RECEIPTS: usize = 2_097_152;
pub const MAX_PRIVACY_BUDGETS: usize = 2_097_152;
pub const MAX_DECOY_SHIELDS: usize = 4_194_304;
pub const MAX_NULLIFIER_GUARDS: usize = 8_388_608;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_PUBLIC_HINTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeraphisSubaddressLaneKind {
    WalletForeground,
    WalletBackground,
    WalletRestore,
    MerchantReceive,
    BridgeDeposit,
    BridgeWithdrawal,
    AtomicSwap,
    WatchOnlyAudit,
    ReorgRepair,
    EmergencyPrivacy,
}

impl SeraphisSubaddressLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletForeground => "wallet_foreground",
            Self::WalletBackground => "wallet_background",
            Self::WalletRestore => "wallet_restore",
            Self::MerchantReceive => "merchant_receive",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::AtomicSwap => "atomic_swap",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::ReorgRepair => "reorg_repair",
            Self::EmergencyPrivacy => "emergency_privacy",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPrivacy => 1_000,
            Self::ReorgRepair => 970,
            Self::BridgeWithdrawal => 940,
            Self::BridgeDeposit => 910,
            Self::WalletForeground => 880,
            Self::WalletRestore => 850,
            Self::AtomicSwap => 820,
            Self::MerchantReceive => 790,
            Self::WatchOnlyAudit => 740,
            Self::WalletBackground => 680,
        }
    }
    pub fn fee_cap(self, config: &Config) -> u64 {
        match self {
            Self::WalletBackground => config.target_scan_fee_piconero,
            Self::WalletForeground | Self::MerchantReceive => config.max_scan_fee_piconero * 3 / 5,
            Self::WalletRestore | Self::WatchOnlyAudit | Self::AtomicSwap => {
                config.max_scan_fee_piconero * 4 / 5
            }
            Self::BridgeDeposit
            | Self::BridgeWithdrawal
            | Self::ReorgRepair
            | Self::EmergencyPrivacy => config.max_scan_fee_piconero,
        }
    }
    pub fn default_speedup_floor_bps(self) -> u64 {
        match self {
            Self::EmergencyPrivacy | Self::ReorgRepair => 7_800,
            Self::BridgeDeposit | Self::BridgeWithdrawal => 7_200,
            Self::WalletForeground | Self::WalletRestore => 6_500,
            Self::AtomicSwap | Self::MerchantReceive => 6_000,
            Self::WatchOnlyAudit => 5_600,
            Self::WalletBackground => 5_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Draft,
    Committed,
    Bucketed,
    WindowReserved,
    Shielded,
    Sponsored,
    RebateReady,
    Settled,
    Expired,
    Rejected,
}
impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::Bucketed => "bucketed",
            Self::WindowReserved => "window_reserved",
            Self::Shielded => "shielded",
            Self::Sponsored => "sponsored",
            Self::RebateReady => "rebate_ready",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Bucketed
                | Self::WindowReserved
                | Self::Shielded
                | Self::Sponsored
                | Self::RebateReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    SoftThrottled,
    HardThrottled,
    RebateOnly,
    Settling,
    Closed,
    Expired,
}
impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SoftThrottled => "soft_throttled",
            Self::HardThrottled => "hard_throttled",
            Self::RebateOnly => "rebate_only",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }
    pub fn accepts_lanes(self) -> bool {
        matches!(self, Self::Open | Self::SoftThrottled | Self::RebateOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebatePoolStatus {
    Funding,
    Active,
    LowReserve,
    Rebalancing,
    Settling,
    Closed,
    Slashed,
}
impl RebatePoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::LowReserve => "low_reserve",
            Self::Rebalancing => "rebalancing",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
        }
    }
    pub fn payable(self) -> bool {
        matches!(self, Self::Active | Self::LowReserve | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReceiptStatus {
    Submitted,
    Accepted,
    WeakPqQuorum,
    Stale,
    Replayed,
    Challenged,
    Slashed,
    Settled,
}
impl SponsorReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakPqQuorum => "weak_pq_quorum",
            Self::Stale => "stale",
            Self::Replayed => "replayed",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Settled => "settled",
        }
    }
    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetStatus {
    Open,
    Reserved,
    Exhausted,
    Refilled,
    Frozen,
    Expired,
}
impl PrivacyBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Exhausted => "exhausted",
            Self::Refilled => "refilled",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyShieldStatus {
    Proposed,
    EntropyChecked,
    AgeBalanced,
    Shielded,
    WeakEntropy,
    LinkabilityRisk,
    Expired,
}
impl DecoyShieldStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::EntropyChecked => "entropy_checked",
            Self::AgeBalanced => "age_balanced",
            Self::Shielded => "shielded",
            Self::WeakEntropy => "weak_entropy",
            Self::LinkabilityRisk => "linkability_risk",
            Self::Expired => "expired",
        }
    }
    pub fn safe(self) -> bool {
        matches!(
            self,
            Self::EntropyChecked | Self::AgeBalanced | Self::Shielded
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Reserved,
    Consumed,
    Replayed,
    Expired,
}
impl NullifierStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Replayed => "replayed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub market_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub privacy_boundary: String,
    pub hash_suite: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_subaddress_bucket_outputs: u32,
    pub target_subaddress_bucket_outputs: u32,
    pub min_decoy_count: u16,
    pub target_decoy_count: u16,
    pub min_decoy_entropy_bps: u64,
    pub min_scan_speedup_bps: u64,
    pub target_scan_speedup_bps: u64,
    pub max_scan_fee_piconero: u64,
    pub target_scan_fee_piconero: u64,
    pub rebate_bps: u64,
    pub sponsor_buffer_bps: u64,
    pub operator_fee_share_bps: u64,
    pub reserve_bps: u64,
    pub lane_ttl_blocks: u64,
    pub window_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub nullifier_ttl_blocks: u64,
    pub privacy_budget_units: u64,
    pub max_disclosure_fields: u32,
    pub window_blocks: u64,
    pub max_window_load_bps: u64,
    pub hard_window_load_bps: u64,
    pub daily_wallet_cap_piconero: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_subaddress_bucket_outputs: DEFAULT_MIN_SUBADDRESS_BUCKET_OUTPUTS,
            target_subaddress_bucket_outputs: DEFAULT_TARGET_SUBADDRESS_BUCKET_OUTPUTS,
            min_decoy_count: DEFAULT_MIN_DECOY_COUNT,
            target_decoy_count: DEFAULT_TARGET_DECOY_COUNT,
            min_decoy_entropy_bps: DEFAULT_MIN_DECOY_ENTROPY_BPS,
            min_scan_speedup_bps: DEFAULT_MIN_SCAN_SPEEDUP_BPS,
            target_scan_speedup_bps: DEFAULT_TARGET_SCAN_SPEEDUP_BPS,
            max_scan_fee_piconero: DEFAULT_MAX_SCAN_FEE_PICONERO,
            target_scan_fee_piconero: DEFAULT_TARGET_SCAN_FEE_PICONERO,
            rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_buffer_bps: DEFAULT_SPONSOR_BUFFER_BPS,
            operator_fee_share_bps: DEFAULT_OPERATOR_FEE_SHARE_BPS,
            reserve_bps: DEFAULT_RESERVE_BPS,
            lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS,
            window_ttl_blocks: DEFAULT_WINDOW_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            nullifier_ttl_blocks: DEFAULT_NULLIFIER_TTL_BLOCKS,
            privacy_budget_units: DEFAULT_PRIVACY_BUDGET_UNITS,
            max_disclosure_fields: DEFAULT_MAX_DISCLOSURE_FIELDS,
            window_blocks: DEFAULT_WINDOW_BLOCKS,
            max_window_load_bps: DEFAULT_MAX_WINDOW_LOAD_BPS,
            hard_window_load_bps: DEFAULT_HARD_WINDOW_LOAD_BPS,
            daily_wallet_cap_piconero: DEFAULT_DAILY_WALLET_CAP_PICONERO,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version: {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version: {}",
            self.schema_version
        );
        ensure!(self.min_pq_security_bits >= 128, "min pq security too low");
        ensure!(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security below minimum"
        );
        ensure!(
            self.min_privacy_set_size > 0,
            "privacy set must be non-zero"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(
            self.target_subaddress_bucket_outputs >= self.min_subaddress_bucket_outputs,
            "target bucket below minimum"
        );
        ensure!(
            self.target_decoy_count >= self.min_decoy_count,
            "target decoys below minimum"
        );
        ensure!(
            self.min_decoy_entropy_bps <= MAX_BPS,
            "decoy entropy exceeds bps range"
        );
        ensure!(
            self.target_scan_speedup_bps >= self.min_scan_speedup_bps,
            "target speedup below minimum"
        );
        ensure!(self.rebate_bps <= MAX_BPS, "rebate bps exceeds range");
        ensure!(
            self.sponsor_buffer_bps <= MAX_BPS,
            "sponsor buffer exceeds range"
        );
        ensure!(
            self.operator_fee_share_bps + self.reserve_bps <= MAX_BPS,
            "operator and reserve shares exceed range"
        );
        ensure!(self.window_blocks > 0, "window blocks must be positive");
        ensure!(
            self.max_window_load_bps <= self.hard_window_load_bps,
            "soft load exceeds hard load"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "protocol_version": self.protocol_version, "schema_version": self.schema_version, "l2_network": self.l2_network, "monero_network": self.monero_network, "market_id": self.market_id, "fee_asset_id": self.fee_asset_id, "rebate_asset_id": self.rebate_asset_id, "privacy_boundary": self.privacy_boundary, "hash_suite": self.hash_suite, "min_pq_security_bits": self.min_pq_security_bits, "target_pq_security_bits": self.target_pq_security_bits, "min_privacy_set_size": self.min_privacy_set_size, "target_privacy_set_size": self.target_privacy_set_size, "min_subaddress_bucket_outputs": self.min_subaddress_bucket_outputs, "target_subaddress_bucket_outputs": self.target_subaddress_bucket_outputs, "min_decoy_count": self.min_decoy_count, "target_decoy_count": self.target_decoy_count, "min_decoy_entropy_bps": self.min_decoy_entropy_bps, "min_scan_speedup_bps": self.min_scan_speedup_bps, "target_scan_speedup_bps": self.target_scan_speedup_bps, "max_scan_fee_piconero": self.max_scan_fee_piconero, "target_scan_fee_piconero": self.target_scan_fee_piconero, "rebate_bps": self.rebate_bps, "sponsor_buffer_bps": self.sponsor_buffer_bps, "operator_fee_share_bps": self.operator_fee_share_bps, "reserve_bps": self.reserve_bps, "lane_ttl_blocks": self.lane_ttl_blocks, "window_ttl_blocks": self.window_ttl_blocks, "receipt_ttl_blocks": self.receipt_ttl_blocks, "nullifier_ttl_blocks": self.nullifier_ttl_blocks, "privacy_budget_units": self.privacy_budget_units, "max_disclosure_fields": self.max_disclosure_fields, "window_blocks": self.window_blocks, "max_window_load_bps": self.max_window_load_bps, "hard_window_load_bps": self.hard_window_load_bps, "daily_wallet_cap_piconero": self.daily_wallet_cap_piconero })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub scan_lanes: u64,
    pub active_scan_lanes: u64,
    pub throttle_windows: u64,
    pub open_throttle_windows: u64,
    pub rebate_pools: u64,
    pub payable_rebate_pools: u64,
    pub sponsor_receipts: u64,
    pub accepted_sponsor_receipts: u64,
    pub privacy_budgets: u64,
    pub exhausted_privacy_budgets: u64,
    pub decoy_shields: u64,
    pub safe_decoy_shields: u64,
    pub nullifier_guards: u64,
    pub consumed_nullifiers: u64,
    pub replayed_nullifiers: u64,
    pub operator_summaries: u64,
    pub public_hints: u64,
    pub total_requested_scans: u64,
    pub total_approved_scans: u64,
    pub total_throttled_scans: u64,
    pub total_scan_fee_piconero: u64,
    pub total_rebate_piconero: u64,
    pub total_sponsor_reserve_piconero: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({ "scan_lanes": self.scan_lanes, "active_scan_lanes": self.active_scan_lanes, "throttle_windows": self.throttle_windows, "open_throttle_windows": self.open_throttle_windows, "rebate_pools": self.rebate_pools, "payable_rebate_pools": self.payable_rebate_pools, "sponsor_receipts": self.sponsor_receipts, "accepted_sponsor_receipts": self.accepted_sponsor_receipts, "privacy_budgets": self.privacy_budgets, "exhausted_privacy_budgets": self.exhausted_privacy_budgets, "decoy_shields": self.decoy_shields, "safe_decoy_shields": self.safe_decoy_shields, "nullifier_guards": self.nullifier_guards, "consumed_nullifiers": self.consumed_nullifiers, "replayed_nullifiers": self.replayed_nullifiers, "operator_summaries": self.operator_summaries, "public_hints": self.public_hints, "total_requested_scans": self.total_requested_scans, "total_approved_scans": self.total_approved_scans, "total_throttled_scans": self.total_throttled_scans, "total_scan_fee_piconero": self.total_scan_fee_piconero, "total_rebate_piconero": self.total_rebate_piconero, "total_sponsor_reserve_piconero": self.total_sponsor_reserve_piconero })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub scan_lane_root: String,
    pub throttle_window_root: String,
    pub rebate_pool_root: String,
    pub sponsor_receipt_root: String,
    pub privacy_budget_root: String,
    pub decoy_shield_root: String,
    pub nullifier_guard_root: String,
    pub operator_summary_root: String,
    pub public_hint_root: String,
    pub public_record_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "config_root": self.config_root, "counters_root": self.counters_root, "scan_lane_root": self.scan_lane_root, "throttle_window_root": self.throttle_window_root, "rebate_pool_root": self.rebate_pool_root, "sponsor_receipt_root": self.sponsor_receipt_root, "privacy_budget_root": self.privacy_budget_root, "decoy_shield_root": self.decoy_shield_root, "nullifier_guard_root": self.nullifier_guard_root, "operator_summary_root": self.operator_summary_root, "public_hint_root": self.public_hint_root, "public_record_root": self.public_record_root, "state_root": self.state_root })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SeraphisSubaddressScanLane {
    pub lane_id: String,
    pub lane_kind: SeraphisSubaddressLaneKind,
    pub status: LaneStatus,
    pub wallet_cohort_commitment: String,
    pub subaddress_bucket_commitment: String,
    pub seraphis_view_tag_commitment: String,
    pub encrypted_scan_hint_root: String,
    pub privacy_budget_id: String,
    pub throttle_window_id: String,
    pub rebate_pool_id: String,
    pub operator_id: String,
    pub requested_scan_count: u64,
    pub approved_scan_count: u64,
    pub throttled_scan_count: u64,
    pub expected_speedup_bps: u64,
    pub quoted_fee_piconero: u64,
    pub max_fee_piconero: u64,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}

impl SeraphisSubaddressScanLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: SeraphisSubaddressLaneKind,
        wallet_cohort_commitment: impl Into<String>,
        subaddress_bucket_commitment: impl Into<String>,
        seraphis_view_tag_commitment: impl Into<String>,
        encrypted_scan_hint_root: impl Into<String>,
        privacy_budget_id: impl Into<String>,
        throttle_window_id: impl Into<String>,
        rebate_pool_id: impl Into<String>,
        operator_id: impl Into<String>,
        requested_scan_count: u64,
        quoted_fee_piconero: u64,
        created_l2_height: u64,
        config: &Config,
    ) -> Self {
        let wallet_cohort_commitment = wallet_cohort_commitment.into();
        let subaddress_bucket_commitment = subaddress_bucket_commitment.into();
        let seraphis_view_tag_commitment = seraphis_view_tag_commitment.into();
        let encrypted_scan_hint_root = encrypted_scan_hint_root.into();
        let record = json!({ "lane_kind": lane_kind.as_str(), "wallet_cohort_commitment": wallet_cohort_commitment, "subaddress_bucket_commitment": subaddress_bucket_commitment, "seraphis_view_tag_commitment": seraphis_view_tag_commitment, "encrypted_scan_hint_root": encrypted_scan_hint_root, "requested_scan_count": requested_scan_count, "created_l2_height": created_l2_height });
        Self {
            lane_id: deterministic_id("seraphis_scan_lane", &record, created_l2_height),
            lane_kind,
            status: LaneStatus::Committed,
            wallet_cohort_commitment,
            subaddress_bucket_commitment,
            seraphis_view_tag_commitment,
            encrypted_scan_hint_root,
            privacy_budget_id: privacy_budget_id.into(),
            throttle_window_id: throttle_window_id.into(),
            rebate_pool_id: rebate_pool_id.into(),
            operator_id: operator_id.into(),
            requested_scan_count,
            approved_scan_count: 0,
            throttled_scan_count: 0,
            expected_speedup_bps: lane_kind
                .default_speedup_floor_bps()
                .max(config.min_scan_speedup_bps),
            quoted_fee_piconero,
            max_fee_piconero: lane_kind.fee_cap(config),
            created_l2_height,
            expires_l2_height: created_l2_height + config.lane_ttl_blocks,
        }
    }
    pub fn approve_scans(&mut self, approved_scan_count: u64) {
        self.approved_scan_count = approved_scan_count.min(self.requested_scan_count);
        self.throttled_scan_count = self
            .requested_scan_count
            .saturating_sub(self.approved_scan_count);
        self.status = if self.throttled_scan_count == 0 {
            LaneStatus::Shielded
        } else {
            LaneStatus::WindowReserved
        };
    }
    pub fn estimated_rebate_piconero(&self, config: &Config) -> u64 {
        self.quoted_fee_piconero.saturating_mul(config.rebate_bps) / MAX_BPS
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.lane_id.is_empty(), "lane id must be present");
        ensure!(
            !self.wallet_cohort_commitment.is_empty(),
            "wallet cohort commitment missing"
        );
        ensure!(
            !self.subaddress_bucket_commitment.is_empty(),
            "subaddress bucket commitment missing"
        );
        ensure!(
            !self.seraphis_view_tag_commitment.is_empty(),
            "seraphis view tag commitment missing"
        );
        ensure!(
            self.requested_scan_count > 0,
            "requested scans must be positive"
        );
        ensure!(
            self.approved_scan_count <= self.requested_scan_count,
            "approved scans exceed request"
        );
        ensure!(
            self.quoted_fee_piconero <= self.max_fee_piconero,
            "quoted fee exceeds lane cap"
        );
        ensure!(
            self.max_fee_piconero <= config.max_scan_fee_piconero,
            "lane fee cap exceeds config cap"
        );
        ensure!(
            self.expected_speedup_bps >= config.min_scan_speedup_bps,
            "scan speedup below minimum"
        );
        ensure!(
            self.expires_l2_height > self.created_l2_height,
            "lane expiry must be after creation"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "lane_id": self.lane_id, "lane_kind": self.lane_kind.as_str(), "status": self.status.as_str(), "wallet_cohort_commitment": self.wallet_cohort_commitment, "subaddress_bucket_commitment": self.subaddress_bucket_commitment, "seraphis_view_tag_commitment": self.seraphis_view_tag_commitment, "encrypted_scan_hint_root": self.encrypted_scan_hint_root, "privacy_budget_id": self.privacy_budget_id, "throttle_window_id": self.throttle_window_id, "rebate_pool_id": self.rebate_pool_id, "operator_id": self.operator_id, "requested_scan_count": self.requested_scan_count, "approved_scan_count": self.approved_scan_count, "throttled_scan_count": self.throttled_scan_count, "expected_speedup_bps": self.expected_speedup_bps, "quoted_fee_piconero": self.quoted_fee_piconero, "max_fee_piconero": self.max_fee_piconero, "created_l2_height": self.created_l2_height, "expires_l2_height": self.expires_l2_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanThrottleWindow {
    pub window_id: String,
    pub status: WindowStatus,
    pub lane_kind: SeraphisSubaddressLaneKind,
    pub operator_id: String,
    pub start_l2_height: u64,
    pub end_l2_height: u64,
    pub max_scan_slots: u64,
    pub reserved_scan_slots: u64,
    pub approved_scan_slots: u64,
    pub load_bps: u64,
    pub throttle_reason_root: String,
    pub price_floor_piconero: u64,
    pub rebate_boost_bps: u64,
}
impl ScanThrottleWindow {
    pub fn new(
        lane_kind: SeraphisSubaddressLaneKind,
        operator_id: impl Into<String>,
        start_l2_height: u64,
        max_scan_slots: u64,
        price_floor_piconero: u64,
        config: &Config,
    ) -> Self {
        let operator_id = operator_id.into();
        let record = json!({ "lane_kind": lane_kind.as_str(), "operator_id": operator_id, "start_l2_height": start_l2_height, "max_scan_slots": max_scan_slots });
        Self {
            window_id: deterministic_id("scan_throttle_window", &record, start_l2_height),
            status: WindowStatus::Open,
            lane_kind,
            operator_id,
            start_l2_height,
            end_l2_height: start_l2_height + config.window_blocks,
            max_scan_slots,
            reserved_scan_slots: 0,
            approved_scan_slots: 0,
            load_bps: 0,
            throttle_reason_root: root_from_record("EMPTY-THROTTLE-REASON", &json!({})),
            price_floor_piconero,
            rebate_boost_bps: 0,
        }
    }
    pub fn reserve(&mut self, requested_slots: u64, config: &Config) -> u64 {
        let remaining = self.max_scan_slots.saturating_sub(self.reserved_scan_slots);
        let approved = requested_slots.min(remaining);
        self.reserved_scan_slots = self.reserved_scan_slots.saturating_add(requested_slots);
        self.approved_scan_slots = self.approved_scan_slots.saturating_add(approved);
        self.load_bps = if self.max_scan_slots == 0 {
            MAX_BPS
        } else {
            self.reserved_scan_slots.saturating_mul(MAX_BPS) / self.max_scan_slots
        };
        self.status = if self.load_bps >= config.hard_window_load_bps {
            WindowStatus::HardThrottled
        } else if self.load_bps >= config.max_window_load_bps {
            WindowStatus::SoftThrottled
        } else {
            WindowStatus::Open
        };
        approved
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.window_id.is_empty(), "window id must be present");
        ensure!(
            self.end_l2_height > self.start_l2_height,
            "window end must be after start"
        );
        ensure!(self.max_scan_slots > 0, "window slots must be positive");
        ensure!(
            self.approved_scan_slots <= self.reserved_scan_slots,
            "approved slots exceed reservations"
        );
        ensure!(
            self.load_bps <= MAX_BPS.saturating_mul(2),
            "window load out of expected range"
        );
        ensure!(
            self.price_floor_piconero <= config.max_scan_fee_piconero,
            "price floor exceeds fee cap"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "window_id": self.window_id, "status": self.status.as_str(), "lane_kind": self.lane_kind.as_str(), "operator_id": self.operator_id, "start_l2_height": self.start_l2_height, "end_l2_height": self.end_l2_height, "max_scan_slots": self.max_scan_slots, "reserved_scan_slots": self.reserved_scan_slots, "approved_scan_slots": self.approved_scan_slots, "load_bps": self.load_bps, "throttle_reason_root": self.throttle_reason_root, "price_floor_piconero": self.price_floor_piconero, "rebate_boost_bps": self.rebate_boost_bps })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebatePool {
    pub pool_id: String,
    pub status: RebatePoolStatus,
    pub sponsor_commitment: String,
    pub operator_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub available_piconero: u64,
    pub reserved_piconero: u64,
    pub paid_piconero: u64,
    pub reserve_piconero: u64,
    pub min_pq_security_bits: u16,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}
impl RebatePool {
    pub fn new(
        sponsor_commitment: impl Into<String>,
        operator_id: impl Into<String>,
        available_piconero: u64,
        created_l2_height: u64,
        config: &Config,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let operator_id = operator_id.into();
        let record = json!({ "sponsor_commitment": sponsor_commitment, "operator_id": operator_id, "available_piconero": available_piconero, "created_l2_height": created_l2_height });
        Self {
            pool_id: deterministic_id("rebate_pool", &record, created_l2_height),
            status: RebatePoolStatus::Active,
            sponsor_commitment,
            operator_id,
            fee_asset_id: config.fee_asset_id.clone(),
            rebate_asset_id: config.rebate_asset_id.clone(),
            available_piconero,
            reserved_piconero: 0,
            paid_piconero: 0,
            reserve_piconero: available_piconero.saturating_mul(config.reserve_bps) / MAX_BPS,
            min_pq_security_bits: config.min_pq_security_bits,
            created_l2_height,
            expires_l2_height: created_l2_height + config.receipt_ttl_blocks,
        }
    }
    pub fn reserve_rebate(&mut self, requested_piconero: u64) -> u64 {
        let liquid = self
            .available_piconero
            .saturating_sub(self.reserved_piconero + self.reserve_piconero);
        let approved = requested_piconero.min(liquid);
        self.reserved_piconero = self.reserved_piconero.saturating_add(approved);
        if liquid <= requested_piconero {
            self.status = RebatePoolStatus::LowReserve;
        }
        approved
    }
    pub fn settle_rebate(&mut self, amount_piconero: u64) {
        let paid = amount_piconero.min(self.reserved_piconero);
        self.reserved_piconero = self.reserved_piconero.saturating_sub(paid);
        self.paid_piconero = self.paid_piconero.saturating_add(paid);
        self.available_piconero = self.available_piconero.saturating_sub(paid);
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.pool_id.is_empty(), "pool id must be present");
        ensure!(
            !self.sponsor_commitment.is_empty(),
            "sponsor commitment missing"
        );
        ensure!(
            self.min_pq_security_bits >= config.min_pq_security_bits,
            "pool pq security below config"
        );
        ensure!(
            self.expires_l2_height > self.created_l2_height,
            "pool expiry must be after creation"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "pool_id": self.pool_id, "status": self.status.as_str(), "sponsor_commitment": self.sponsor_commitment, "operator_id": self.operator_id, "fee_asset_id": self.fee_asset_id, "rebate_asset_id": self.rebate_asset_id, "available_piconero": self.available_piconero, "reserved_piconero": self.reserved_piconero, "paid_piconero": self.paid_piconero, "reserve_piconero": self.reserve_piconero, "min_pq_security_bits": self.min_pq_security_bits, "created_l2_height": self.created_l2_height, "expires_l2_height": self.expires_l2_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSponsorReceipt {
    pub receipt_id: String,
    pub status: SponsorReceiptStatus,
    pub pool_id: String,
    pub lane_id: String,
    pub nullifier: String,
    pub sponsor_authorization_root: String,
    pub pq_signature_scheme: String,
    pub pq_security_bits: u16,
    pub fee_paid_piconero: u64,
    pub rebate_reserved_piconero: u64,
    pub operator_fee_piconero: u64,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}
impl PqSponsorReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: impl Into<String>,
        lane_id: impl Into<String>,
        nullifier: impl Into<String>,
        sponsor_authorization_root: impl Into<String>,
        pq_security_bits: u16,
        fee_paid_piconero: u64,
        rebate_reserved_piconero: u64,
        created_l2_height: u64,
        config: &Config,
    ) -> Self {
        let pool_id = pool_id.into();
        let lane_id = lane_id.into();
        let nullifier = nullifier.into();
        let sponsor_authorization_root = sponsor_authorization_root.into();
        let record = json!({ "pool_id": pool_id, "lane_id": lane_id, "nullifier": nullifier, "sponsor_authorization_root": sponsor_authorization_root, "fee_paid_piconero": fee_paid_piconero, "created_l2_height": created_l2_height });
        Self {
            receipt_id: deterministic_id("pq_sponsor_receipt", &record, created_l2_height),
            status: if pq_security_bits >= config.min_pq_security_bits {
                SponsorReceiptStatus::Accepted
            } else {
                SponsorReceiptStatus::WeakPqQuorum
            },
            pool_id,
            lane_id,
            nullifier,
            sponsor_authorization_root,
            pq_signature_scheme: PQ_SPONSOR_RECEIPT_SCHEME.to_string(),
            pq_security_bits,
            fee_paid_piconero,
            rebate_reserved_piconero,
            operator_fee_piconero: fee_paid_piconero.saturating_mul(config.operator_fee_share_bps)
                / MAX_BPS,
            created_l2_height,
            expires_l2_height: created_l2_height + config.receipt_ttl_blocks,
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.receipt_id.is_empty(), "receipt id must be present");
        ensure!(!self.pool_id.is_empty(), "receipt pool id missing");
        ensure!(!self.lane_id.is_empty(), "receipt lane id missing");
        ensure!(!self.nullifier.is_empty(), "receipt nullifier missing");
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "receipt pq security below minimum"
        );
        ensure!(
            self.fee_paid_piconero <= config.max_scan_fee_piconero,
            "receipt fee exceeds cap"
        );
        ensure!(
            self.expires_l2_height > self.created_l2_height,
            "receipt expiry must be after creation"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "receipt_id": self.receipt_id, "status": self.status.as_str(), "pool_id": self.pool_id, "lane_id": self.lane_id, "nullifier": self.nullifier, "sponsor_authorization_root": self.sponsor_authorization_root, "pq_signature_scheme": self.pq_signature_scheme, "pq_security_bits": self.pq_security_bits, "fee_paid_piconero": self.fee_paid_piconero, "rebate_reserved_piconero": self.rebate_reserved_piconero, "operator_fee_piconero": self.operator_fee_piconero, "created_l2_height": self.created_l2_height, "expires_l2_height": self.expires_l2_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub status: PrivacyBudgetStatus,
    pub wallet_cohort_commitment: String,
    pub epoch: u64,
    pub total_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_disclosure_fields: u32,
    pub public_hint_policy_root: String,
    pub created_l2_height: u64,
}
impl PrivacyBudget {
    pub fn new(
        wallet_cohort_commitment: impl Into<String>,
        epoch: u64,
        public_hint_policy_root: impl Into<String>,
        created_l2_height: u64,
        config: &Config,
    ) -> Self {
        let wallet_cohort_commitment = wallet_cohort_commitment.into();
        let record = json!({"wallet_cohort_commitment": wallet_cohort_commitment, "epoch": epoch});
        Self {
            budget_id: deterministic_id("privacy_budget", &record, epoch),
            status: PrivacyBudgetStatus::Open,
            wallet_cohort_commitment,
            epoch,
            total_units: config.privacy_budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_disclosure_fields: config.max_disclosure_fields,
            public_hint_policy_root: public_hint_policy_root.into(),
            created_l2_height,
        }
    }
    pub fn reserve(&mut self, units: u64) -> bool {
        let available = self
            .total_units
            .saturating_sub(self.reserved_units + self.spent_units);
        if units <= available {
            self.reserved_units += units;
            self.status = PrivacyBudgetStatus::Reserved;
            true
        } else {
            self.status = PrivacyBudgetStatus::Exhausted;
            false
        }
    }
    pub fn spend_reserved(&mut self, units: u64) {
        let spend = units.min(self.reserved_units);
        self.reserved_units -= spend;
        self.spent_units += spend;
        if self.spent_units >= self.total_units {
            self.status = PrivacyBudgetStatus::Exhausted;
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.budget_id.is_empty(), "budget id must be present");
        ensure!(
            self.total_units >= self.spent_units + self.reserved_units,
            "budget overspent"
        );
        ensure!(
            self.max_disclosure_fields <= config.max_disclosure_fields,
            "disclosure fields exceed config"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "budget_id": self.budget_id, "status": self.status.as_str(), "wallet_cohort_commitment": self.wallet_cohort_commitment, "epoch": self.epoch, "total_units": self.total_units, "reserved_units": self.reserved_units, "spent_units": self.spent_units, "max_disclosure_fields": self.max_disclosure_fields, "public_hint_policy_root": self.public_hint_policy_root, "created_l2_height": self.created_l2_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyScanShield {
    pub shield_id: String,
    pub status: DecoyShieldStatus,
    pub lane_id: String,
    pub decoy_set_commitment: String,
    pub age_distribution_root: String,
    pub ring_member_entropy_bps: u64,
    pub decoy_count: u16,
    pub privacy_set_size: u64,
    pub linkability_risk_bps: u64,
    pub created_l2_height: u64,
}
impl DecoyScanShield {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: impl Into<String>,
        decoy_set_commitment: impl Into<String>,
        age_distribution_root: impl Into<String>,
        ring_member_entropy_bps: u64,
        decoy_count: u16,
        privacy_set_size: u64,
        created_l2_height: u64,
        config: &Config,
    ) -> Self {
        let lane_id = lane_id.into();
        let decoy_set_commitment = decoy_set_commitment.into();
        let age_distribution_root = age_distribution_root.into();
        let record = json!({ "lane_id": lane_id, "decoy_set_commitment": decoy_set_commitment, "age_distribution_root": age_distribution_root, "created_l2_height": created_l2_height });
        let status = if ring_member_entropy_bps >= config.min_decoy_entropy_bps
            && decoy_count >= config.min_decoy_count
            && privacy_set_size >= config.min_privacy_set_size
        {
            DecoyShieldStatus::Shielded
        } else if ring_member_entropy_bps < config.min_decoy_entropy_bps {
            DecoyShieldStatus::WeakEntropy
        } else {
            DecoyShieldStatus::LinkabilityRisk
        };
        Self {
            shield_id: deterministic_id("decoy_scan_shield", &record, created_l2_height),
            status,
            lane_id,
            decoy_set_commitment,
            age_distribution_root,
            ring_member_entropy_bps,
            decoy_count,
            privacy_set_size,
            linkability_risk_bps: MAX_BPS.saturating_sub(ring_member_entropy_bps.min(MAX_BPS)),
            created_l2_height,
        }
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.shield_id.is_empty(), "shield id must be present");
        ensure!(!self.lane_id.is_empty(), "shield lane id missing");
        ensure!(
            self.ring_member_entropy_bps <= MAX_BPS,
            "entropy bps exceeds range"
        );
        ensure!(
            self.decoy_count >= config.min_decoy_count,
            "decoy count below minimum"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "privacy set below minimum"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "shield_id": self.shield_id, "status": self.status.as_str(), "lane_id": self.lane_id, "decoy_set_commitment": self.decoy_set_commitment, "age_distribution_root": self.age_distribution_root, "ring_member_entropy_bps": self.ring_member_entropy_bps, "decoy_count": self.decoy_count, "privacy_set_size": self.privacy_set_size, "linkability_risk_bps": self.linkability_risk_bps, "created_l2_height": self.created_l2_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierReplayGuard {
    pub guard_id: String,
    pub status: NullifierStatus,
    pub nullifier: String,
    pub lane_id: String,
    pub receipt_id: String,
    pub first_seen_l2_height: u64,
    pub expires_l2_height: u64,
}
impl NullifierReplayGuard {
    pub fn new(
        nullifier: impl Into<String>,
        lane_id: impl Into<String>,
        receipt_id: impl Into<String>,
        first_seen_l2_height: u64,
        config: &Config,
    ) -> Self {
        let nullifier = nullifier.into();
        let lane_id = lane_id.into();
        let receipt_id = receipt_id.into();
        let record = json!({"nullifier": nullifier, "lane_id": lane_id, "receipt_id": receipt_id});
        Self {
            guard_id: deterministic_id("nullifier_replay_guard", &record, first_seen_l2_height),
            status: NullifierStatus::Reserved,
            nullifier,
            lane_id,
            receipt_id,
            first_seen_l2_height,
            expires_l2_height: first_seen_l2_height + config.nullifier_ttl_blocks,
        }
    }
    pub fn consume(&mut self) {
        self.status = NullifierStatus::Consumed;
    }
    pub fn replay(&mut self) {
        self.status = NullifierStatus::Replayed;
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.guard_id.is_empty(), "guard id must be present");
        ensure!(!self.nullifier.is_empty(), "nullifier missing");
        ensure!(
            self.expires_l2_height > self.first_seen_l2_height,
            "guard expiry must be after first seen"
        );
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "guard_id": self.guard_id, "status": self.status.as_str(), "nullifier": self.nullifier, "lane_id": self.lane_id, "receipt_id": self.receipt_id, "first_seen_l2_height": self.first_seen_l2_height, "expires_l2_height": self.expires_l2_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub lanes_served: u64,
    pub scans_requested: u64,
    pub scans_approved: u64,
    pub scans_throttled: u64,
    pub avg_speedup_bps: u64,
    pub avg_fee_piconero: u64,
    pub rebates_paid_piconero: u64,
    pub pq_receipts_accepted: u64,
    pub decoy_shields_safe: u64,
    pub public_note_root: String,
}
impl OperatorSummary {
    pub fn new(
        operator_id: impl Into<String>,
        epoch: u64,
        public_note_root: impl Into<String>,
    ) -> Self {
        let operator_id = operator_id.into();
        let record = json!({"operator_id": operator_id, "epoch": epoch});
        Self {
            summary_id: deterministic_id("operator_summary", &record, epoch),
            operator_id,
            epoch,
            lanes_served: 0,
            scans_requested: 0,
            scans_approved: 0,
            scans_throttled: 0,
            avg_speedup_bps: 0,
            avg_fee_piconero: 0,
            rebates_paid_piconero: 0,
            pq_receipts_accepted: 0,
            decoy_shields_safe: 0,
            public_note_root: public_note_root.into(),
        }
    }
    pub fn observe_lane(&mut self, lane: &SeraphisSubaddressScanLane) {
        self.lanes_served += 1;
        self.scans_requested += lane.requested_scan_count;
        self.scans_approved += lane.approved_scan_count;
        self.scans_throttled += lane.throttled_scan_count;
        self.avg_speedup_bps = rolling_average(
            self.avg_speedup_bps,
            lane.expected_speedup_bps,
            self.lanes_served,
        );
        self.avg_fee_piconero = rolling_average(
            self.avg_fee_piconero,
            lane.quoted_fee_piconero,
            self.lanes_served,
        );
    }
    pub fn public_record(&self) -> Value {
        json!({ "summary_id": self.summary_id, "operator_id": self.operator_id, "epoch": self.epoch, "lanes_served": self.lanes_served, "scans_requested": self.scans_requested, "scans_approved": self.scans_approved, "scans_throttled": self.scans_throttled, "avg_speedup_bps": self.avg_speedup_bps, "avg_fee_piconero": self.avg_fee_piconero, "rebates_paid_piconero": self.rebates_paid_piconero, "pq_receipts_accepted": self.pq_receipts_accepted, "decoy_shields_safe": self.decoy_shields_safe, "public_note_root": self.public_note_root })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicHint {
    pub hint_id: String,
    pub lane_id: String,
    pub hint_kind: String,
    pub redacted_payload_root: String,
    pub disclosure_units: u64,
    pub created_l2_height: u64,
}
impl PublicHint {
    pub fn new(
        lane_id: impl Into<String>,
        hint_kind: impl Into<String>,
        redacted_payload_root: impl Into<String>,
        disclosure_units: u64,
        created_l2_height: u64,
    ) -> Self {
        let lane_id = lane_id.into();
        let hint_kind = hint_kind.into();
        let redacted_payload_root = redacted_payload_root.into();
        let record = json!({ "lane_id": lane_id, "hint_kind": hint_kind, "redacted_payload_root": redacted_payload_root, "created_l2_height": created_l2_height });
        Self {
            hint_id: deterministic_id("public_hint", &record, created_l2_height),
            lane_id,
            hint_kind,
            redacted_payload_root,
            disclosure_units,
            created_l2_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({ "hint_id": self.hint_id, "lane_id": self.lane_id, "hint_kind": self.hint_kind, "redacted_payload_root": self.redacted_payload_root, "disclosure_units": self.disclosure_units, "created_l2_height": self.created_l2_height })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub scan_lanes: BTreeMap<String, SeraphisSubaddressScanLane>,
    pub throttle_windows: BTreeMap<String, ScanThrottleWindow>,
    pub rebate_pools: BTreeMap<String, RebatePool>,
    pub sponsor_receipts: BTreeMap<String, PqSponsorReceipt>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub decoy_shields: BTreeMap<String, DecoyScanShield>,
    pub nullifier_guards: BTreeMap<String, NullifierReplayGuard>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_hints: BTreeMap<String, PublicHint>,
    pub seen_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Self {
        Self {
            config,
            l2_height,
            monero_height,
            epoch,
            scan_lanes: BTreeMap::new(),
            throttle_windows: BTreeMap::new(),
            rebate_pools: BTreeMap::new(),
            sponsor_receipts: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            decoy_shields: BTreeMap::new(),
            nullifier_guards: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_hints: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        );
        state.seed_devnet();
        state
    }
    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let operator = "operator-demo-seraphis-scan-throttle";
        let mut summary = OperatorSummary::new(
            operator,
            state.epoch + 1,
            root_from_record("DEMO-OPERATOR-NOTE", &json!({"note": "redacted-demo"})),
        );
        for lane in state.scan_lanes.values() {
            summary.observe_lane(lane);
        }
        summary.rebates_paid_piconero = state
            .sponsor_receipts
            .values()
            .map(|receipt| receipt.rebate_reserved_piconero)
            .sum();
        summary.pq_receipts_accepted = state
            .sponsor_receipts
            .values()
            .filter(|receipt| receipt.status.accepted())
            .count() as u64;
        summary.decoy_shields_safe = state
            .decoy_shields
            .values()
            .filter(|shield| shield.status.safe())
            .count() as u64;
        state
            .operator_summaries
            .insert(summary.summary_id.clone(), summary);
        state
    }
    fn seed_devnet(&mut self) {
        let mut window = ScanThrottleWindow::new(
            SeraphisSubaddressLaneKind::WalletForeground,
            "operator-demo-seraphis-scan-throttle",
            self.l2_height,
            160_000,
            self.config.target_scan_fee_piconero,
            &self.config,
        );
        let pool = RebatePool::new(
            root_from_record("DEVNET-SPONSOR", &json!({"sponsor": "devnet-sponsor-a"})),
            "operator-demo-seraphis-scan-throttle",
            12_000_000,
            self.l2_height,
            &self.config,
        );
        let budget = PrivacyBudget::new(
            root_from_record(
                "DEVNET-WALLET-COHORT",
                &json!({"cohort": "foreground-wallets"}),
            ),
            self.epoch,
            root_from_record(
                "DEVNET-HINT-POLICY",
                &json!({"fields": ["viewtag", "bucket"]}),
            ),
            self.l2_height,
            &self.config,
        );
        let mut lane = SeraphisSubaddressScanLane::new(
            SeraphisSubaddressLaneKind::WalletForeground,
            budget.wallet_cohort_commitment.clone(),
            root_from_record("DEVNET-SUBADDRESS-BUCKET", &json!({"bucket": "redacted-0"})),
            root_from_record("DEVNET-SERAPHIS-VIEWTAG", &json!({"viewtag": "redacted"})),
            root_from_record("DEVNET-ENCRYPTED-SCAN-HINTS", &json!({"hint_count": 8})),
            budget.budget_id.clone(),
            window.window_id.clone(),
            pool.pool_id.clone(),
            "operator-demo-seraphis-scan-throttle",
            24_000,
            620,
            self.l2_height,
            &self.config,
        );
        let approved = window.reserve(lane.requested_scan_count, &self.config);
        lane.approve_scans(approved);
        let shield = DecoyScanShield::new(
            lane.lane_id.clone(),
            root_from_record("DEVNET-DECOY-SET", &json!({"set": "redacted-decoys"})),
            root_from_record("DEVNET-DECOY-AGE", &json!({"age": "balanced"})),
            9_240,
            self.config.target_decoy_count,
            self.config.target_privacy_set_size,
            self.l2_height,
            &self.config,
        );
        let rebate = lane.estimated_rebate_piconero(&self.config);
        let mut pool = pool;
        let reserved = pool.reserve_rebate(rebate);
        let receipt = PqSponsorReceipt::new(
            pool.pool_id.clone(),
            lane.lane_id.clone(),
            root_from_record("DEVNET-NULLIFIER", &json!({"lane": lane.lane_id})),
            root_from_record(
                "DEVNET-PQ-AUTH",
                &json!({"scheme": PQ_SPONSOR_RECEIPT_SCHEME}),
            ),
            self.config.target_pq_security_bits,
            lane.quoted_fee_piconero,
            reserved,
            self.l2_height,
            &self.config,
        );
        let mut guard = NullifierReplayGuard::new(
            receipt.nullifier.clone(),
            lane.lane_id.clone(),
            receipt.receipt_id.clone(),
            self.l2_height,
            &self.config,
        );
        guard.consume();
        let hint = PublicHint::new(
            lane.lane_id.clone(),
            "coarse_scan_pressure",
            root_from_record("DEVNET-PUBLIC-HINT", &json!({"pressure": "normal"})),
            64,
            self.l2_height,
        );
        self.throttle_windows
            .insert(window.window_id.clone(), window);
        self.rebate_pools.insert(pool.pool_id.clone(), pool);
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        self.decoy_shields.insert(shield.shield_id.clone(), shield);
        self.seen_nullifiers.insert(receipt.nullifier.clone());
        self.nullifier_guards.insert(guard.guard_id.clone(), guard);
        self.public_hints.insert(hint.hint_id.clone(), hint);
        self.sponsor_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.scan_lanes.insert(lane.lane_id.clone(), lane);
    }
    pub fn add_throttle_window(&mut self, window: ScanThrottleWindow) -> Result<()> {
        ensure!(
            self.throttle_windows.len() < MAX_THROTTLE_WINDOWS,
            "too many throttle windows"
        );
        window.validate(&self.config)?;
        self.throttle_windows
            .insert(window.window_id.clone(), window);
        Ok(())
    }
    pub fn add_rebate_pool(&mut self, pool: RebatePool) -> Result<()> {
        ensure!(
            self.rebate_pools.len() < MAX_REBATE_POOLS,
            "too many rebate pools"
        );
        pool.validate(&self.config)?;
        self.rebate_pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }
    pub fn add_privacy_budget(&mut self, budget: PrivacyBudget) -> Result<()> {
        ensure!(
            self.privacy_budgets.len() < MAX_PRIVACY_BUDGETS,
            "too many privacy budgets"
        );
        budget.validate(&self.config)?;
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }
    pub fn submit_scan_lane(&mut self, mut lane: SeraphisSubaddressScanLane) -> Result<String> {
        ensure!(
            self.scan_lanes.len() < MAX_SCAN_LANES,
            "too many scan lanes"
        );
        self.config.validate()?;
        lane.validate(&self.config)?;
        let window = self
            .throttle_windows
            .get_mut(&lane.throttle_window_id)
            .ok_or_else(|| format!("unknown throttle window: {}", lane.throttle_window_id))?;
        ensure!(
            window.status.accepts_lanes(),
            "window does not accept lanes: {}",
            window.window_id
        );
        let budget = self
            .privacy_budgets
            .get_mut(&lane.privacy_budget_id)
            .ok_or_else(|| format!("unknown privacy budget: {}", lane.privacy_budget_id))?;
        ensure!(
            budget.reserve(lane.requested_scan_count / 16 + 1),
            "privacy budget exhausted: {}",
            budget.budget_id
        );
        let approved = window.reserve(lane.requested_scan_count, &self.config);
        lane.approve_scans(approved);
        let lane_id = lane.lane_id.clone();
        self.scan_lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }
    pub fn attach_decoy_shield(&mut self, shield: DecoyScanShield) -> Result<()> {
        ensure!(
            self.decoy_shields.len() < MAX_DECOY_SHIELDS,
            "too many decoy shields"
        );
        shield.validate(&self.config)?;
        ensure!(
            self.scan_lanes.contains_key(&shield.lane_id),
            "unknown lane for shield: {}",
            shield.lane_id
        );
        if let Some(lane) = self.scan_lanes.get_mut(&shield.lane_id) {
            if shield.status.safe() {
                lane.status = LaneStatus::Shielded;
            }
        }
        self.decoy_shields.insert(shield.shield_id.clone(), shield);
        Ok(())
    }
    pub fn accept_sponsor_receipt(&mut self, receipt: PqSponsorReceipt) -> Result<String> {
        ensure!(
            self.sponsor_receipts.len() < MAX_SPONSOR_RECEIPTS,
            "too many sponsor receipts"
        );
        receipt.validate(&self.config)?;
        ensure!(
            !self.seen_nullifiers.contains(&receipt.nullifier),
            "replayed sponsor nullifier: {}",
            receipt.nullifier
        );
        ensure!(
            self.scan_lanes.contains_key(&receipt.lane_id),
            "unknown lane for receipt: {}",
            receipt.lane_id
        );
        let pool = self
            .rebate_pools
            .get_mut(&receipt.pool_id)
            .ok_or_else(|| format!("unknown rebate pool: {}", receipt.pool_id))?;
        ensure!(
            pool.status.payable(),
            "rebate pool is not payable: {}",
            pool.pool_id
        );
        let reserved = pool.reserve_rebate(receipt.rebate_reserved_piconero);
        ensure!(
            reserved == receipt.rebate_reserved_piconero,
            "rebate pool could not reserve full receipt amount"
        );
        self.seen_nullifiers.insert(receipt.nullifier.clone());
        let mut guard = NullifierReplayGuard::new(
            receipt.nullifier.clone(),
            receipt.lane_id.clone(),
            receipt.receipt_id.clone(),
            self.l2_height,
            &self.config,
        );
        guard.consume();
        self.nullifier_guards.insert(guard.guard_id.clone(), guard);
        if let Some(lane) = self.scan_lanes.get_mut(&receipt.lane_id) {
            lane.status = LaneStatus::Sponsored;
        }
        let receipt_id = receipt.receipt_id.clone();
        self.sponsor_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }
    pub fn settle_rebate(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .sponsor_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown sponsor receipt: {}", receipt_id))?;
        ensure!(
            receipt.status.accepted(),
            "receipt is not accepted: {}",
            receipt_id
        );
        let pool = self
            .rebate_pools
            .get_mut(&receipt.pool_id)
            .ok_or_else(|| format!("unknown rebate pool: {}", receipt.pool_id))?;
        pool.settle_rebate(receipt.rebate_reserved_piconero);
        receipt.status = SponsorReceiptStatus::Settled;
        if let Some(lane) = self.scan_lanes.get_mut(&receipt.lane_id) {
            lane.status = LaneStatus::Settled;
        }
        Ok(())
    }
    pub fn counters(&self) -> Counters {
        let mut counters = Counters::default();
        counters.scan_lanes = self.scan_lanes.len() as u64;
        counters.active_scan_lanes = self
            .scan_lanes
            .values()
            .filter(|lane| lane.status.live())
            .count() as u64;
        counters.throttle_windows = self.throttle_windows.len() as u64;
        counters.open_throttle_windows = self
            .throttle_windows
            .values()
            .filter(|window| window.status.accepts_lanes())
            .count() as u64;
        counters.rebate_pools = self.rebate_pools.len() as u64;
        counters.payable_rebate_pools = self
            .rebate_pools
            .values()
            .filter(|pool| pool.status.payable())
            .count() as u64;
        counters.sponsor_receipts = self.sponsor_receipts.len() as u64;
        counters.accepted_sponsor_receipts = self
            .sponsor_receipts
            .values()
            .filter(|receipt| receipt.status.accepted())
            .count() as u64;
        counters.privacy_budgets = self.privacy_budgets.len() as u64;
        counters.exhausted_privacy_budgets = self
            .privacy_budgets
            .values()
            .filter(|budget| budget.status == PrivacyBudgetStatus::Exhausted)
            .count() as u64;
        counters.decoy_shields = self.decoy_shields.len() as u64;
        counters.safe_decoy_shields = self
            .decoy_shields
            .values()
            .filter(|shield| shield.status.safe())
            .count() as u64;
        counters.nullifier_guards = self.nullifier_guards.len() as u64;
        counters.consumed_nullifiers = self
            .nullifier_guards
            .values()
            .filter(|guard| guard.status == NullifierStatus::Consumed)
            .count() as u64;
        counters.replayed_nullifiers = self
            .nullifier_guards
            .values()
            .filter(|guard| guard.status == NullifierStatus::Replayed)
            .count() as u64;
        counters.operator_summaries = self.operator_summaries.len() as u64;
        counters.public_hints = self.public_hints.len() as u64;
        counters.total_requested_scans = self
            .scan_lanes
            .values()
            .map(|lane| lane.requested_scan_count)
            .sum();
        counters.total_approved_scans = self
            .scan_lanes
            .values()
            .map(|lane| lane.approved_scan_count)
            .sum();
        counters.total_throttled_scans = self
            .scan_lanes
            .values()
            .map(|lane| lane.throttled_scan_count)
            .sum();
        counters.total_scan_fee_piconero = self
            .scan_lanes
            .values()
            .map(|lane| lane.quoted_fee_piconero)
            .sum();
        counters.total_rebate_piconero = self
            .sponsor_receipts
            .values()
            .map(|receipt| receipt.rebate_reserved_piconero)
            .sum();
        counters.total_sponsor_reserve_piconero = self
            .rebate_pools
            .values()
            .map(|pool| pool.reserve_piconero)
            .sum();
        counters
    }
    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: root_from_record("CONFIG", &self.config.public_record()),
            counters_root: root_from_record("COUNTERS", &counters.public_record()),
            scan_lane_root: map_root(
                SERAPHIS_SUBADDRESS_LANE_SCHEME,
                &self.scan_lanes,
                SeraphisSubaddressScanLane::public_record,
            ),
            throttle_window_root: map_root(
                SCAN_THROTTLE_WINDOW_SCHEME,
                &self.throttle_windows,
                ScanThrottleWindow::public_record,
            ),
            rebate_pool_root: map_root(
                REBATE_POOL_SCHEME,
                &self.rebate_pools,
                RebatePool::public_record,
            ),
            sponsor_receipt_root: map_root(
                PQ_SPONSOR_RECEIPT_SCHEME,
                &self.sponsor_receipts,
                PqSponsorReceipt::public_record,
            ),
            privacy_budget_root: map_root(
                PRIVACY_BUDGET_SCHEME,
                &self.privacy_budgets,
                PrivacyBudget::public_record,
            ),
            decoy_shield_root: map_root(
                DECOY_SCAN_SHIELDING_SCHEME,
                &self.decoy_shields,
                DecoyScanShield::public_record,
            ),
            nullifier_guard_root: map_root(
                NULLIFIER_GUARD_SCHEME,
                &self.nullifier_guards,
                NullifierReplayGuard::public_record,
            ),
            operator_summary_root: map_root(
                OPERATOR_SUMMARY_SCHEME,
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            public_hint_root: map_root(
                "SERAPHIS-SUBADDRESS-PUBLIC-HINTS",
                &self.public_hints,
                PublicHint::public_record,
            ),
            public_record_root: String::new(),
            state_root: String::new(),
        };
        roots.public_record_root = public_record_root(
            &json!({ "config": roots.config_root, "counters": roots.counters_root, "scan_lanes": roots.scan_lane_root, "throttle_windows": roots.throttle_window_root, "rebate_pools": roots.rebate_pool_root, "sponsor_receipts": roots.sponsor_receipt_root, "privacy_budgets": roots.privacy_budget_root, "decoy_shields": roots.decoy_shield_root, "nullifier_guards": roots.nullifier_guard_root, "operator_summaries": roots.operator_summary_root, "public_hints": roots.public_hint_root }),
        );
        roots.state_root = state_root_from_record(
            &json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "l2_height": self.l2_height, "monero_height": self.monero_height, "epoch": self.epoch, "roots": roots.public_record() }),
        );
        roots
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": CHAIN_ID, "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "l2_height": self.l2_height, "monero_height": self.monero_height, "epoch": self.epoch, "privacy_boundary": PRIVACY_BOUNDARY, "config": self.config.public_record(), "counters": self.counters().public_record(), "roots": self.roots().public_record(), "scan_lanes": self.scan_lanes.values().map(SeraphisSubaddressScanLane::public_record).collect::<Vec<_>>(), "throttle_windows": self.throttle_windows.values().map(ScanThrottleWindow::public_record).collect::<Vec<_>>(), "rebate_pools": self.rebate_pools.values().map(RebatePool::public_record).collect::<Vec<_>>(), "sponsor_receipts": self.sponsor_receipts.values().map(PqSponsorReceipt::public_record).collect::<Vec<_>>(), "privacy_budgets": self.privacy_budgets.values().map(PrivacyBudget::public_record).collect::<Vec<_>>(), "decoy_shields": self.decoy_shields.values().map(DecoyScanShield::public_record).collect::<Vec<_>>(), "nullifier_guards": self.nullifier_guards.values().map(NullifierReplayGuard::public_record).collect::<Vec<_>>(), "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(), "public_hints": self.public_hints.values().map(PublicHint::public_record).collect::<Vec<_>>() })
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn demo() -> State {
    State::demo()
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn public_record_root(record: &Value) -> String {
    root_from_record(PUBLIC_RECORD_SCHEME, record)
}
pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("SERAPHIS-SUBADDRESS-SCAN-THROTTLE-REBATE-STATE", record)
}
fn rolling_average(current_average: u64, next: u64, count: u64) -> u64 {
    if count <= 1 {
        next
    } else {
        ((current_average.saturating_mul(count - 1)).saturating_add(next)) / count
    }
}
fn deterministic_id(prefix: &str, record: &Value, sequence: u64) -> String {
    format!(
        "{}-{}",
        prefix,
        domain_hash(
            "SERAPHIS-SUBADDRESS-SCAN-THROTTLE-REBATE-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Json(record),
            ],
            32,
        )
    )
}
fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Json(record),
        ],
        32,
    )
}
fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!(domain_hash(
                domain,
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(key),
                    HashPart::Json(&record_fn(value)),
                ],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
