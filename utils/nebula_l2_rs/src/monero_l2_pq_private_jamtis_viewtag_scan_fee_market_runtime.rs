use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateJamtisViewtagScanFeeMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_SCAN_FEE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-viewtag-scan-fee-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_VIEWTAG_SCAN_FEE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_426_400;
pub const DEVNET_EPOCH: u64 = 2_048;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MARKET_ID: &str = "monero-l2-pq-private-jamtis-viewtag-scan-fee-market-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const JAMTIS_SCAN_WINDOW_SCHEME: &str = "jamtis-viewtag-private-scan-window-root-v1";
pub const VIEWTAG_BUCKET_SCHEME: &str = "monero-viewtag-fee-market-bucket-root-v1";
pub const WALLET_SCAN_COUPON_SCHEME: &str = "private-wallet-scan-coupon-root-v1";
pub const PQ_SCANNER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-viewtag-scanner-attestation-v1";
pub const DECOY_FLOOR_SCHEME: &str = "jamtis-scan-decoy-floor-root-v1";
pub const MOBILE_SCAN_LANE_SCHEME: &str = "private-mobile-viewtag-scan-lane-root-v1";
pub const FEE_REBATE_SCHEME: &str = "viewtag-scan-low-fee-rebate-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "operator-safe-viewtag-scan-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "roots-only-viewtag-scan-operator-summary-root-v1";
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_BUCKET_SPAN_BLOCKS: u64 = 24;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REORG_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u32 = 16;
pub const DEFAULT_MAX_BUCKET_OUTPUTS: u32 = 16_384;
pub const DEFAULT_MIN_DECOY_FLOOR: u16 = 96;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_VIEWTAG_ENTROPY_BPS: u64 = 8_800;
pub const DEFAULT_MIN_SCANNER_COUNT: u16 = 3;
pub const DEFAULT_SCANNER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 = 1_200;
pub const DEFAULT_BACKGROUND_FEE_MICRO_UNITS: u64 = 500;
pub const DEFAULT_MERCHANT_FEE_MICRO_UNITS: u64 = 900;
pub const DEFAULT_EXPRESS_FEE_MICRO_UNITS: u64 = 1_800;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_MOBILE_REBATE_BPS: u64 = 2_000;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const DEFAULT_DAILY_LINKABILITY_BUDGET: u64 = 64;
pub const DEFAULT_EPOCH_REDACTION_BUDGET: u64 = 16;
pub const DEFAULT_MAX_MOBILE_BATCH_BYTES: u32 = 196_608;
pub const DEFAULT_MAX_BUCKET_HINT_BYTES: u32 = 8_192;
pub const DEFAULT_MAX_OPERATOR_DELAY_BLOCKS: u64 = 10;
pub const DEFAULT_MAX_COUPONS_PER_WALLET_EPOCH: u32 = 64;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SCAN_WINDOWS: usize = 1_048_576;
pub const MAX_VIEWTAG_BUCKETS: usize = 2_097_152;
pub const MAX_WALLET_SCAN_COUPONS: usize = 4_194_304;
pub const MAX_PQ_SCANNER_ATTESTATIONS: usize = 4_194_304;
pub const MAX_DECOY_FLOORS: usize = 1_048_576;
pub const MAX_MOBILE_SCAN_LANES: usize = 524_288;
pub const MAX_FEE_REBATES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLane {
    LowFee,
    BackgroundWallet,
    ForegroundWallet,
    MerchantCheckout,
    ExpressRecovery,
    WatchOnlyAudit,
    MobileSparse,
    ReorgRepair,
}

impl ScanLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::BackgroundWallet => "background_wallet",
            Self::ForegroundWallet => "foreground_wallet",
            Self::MerchantCheckout => "merchant_checkout",
            Self::ExpressRecovery => "express_recovery",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::MobileSparse => "mobile_sparse",
            Self::ReorgRepair => "reorg_repair",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::ReorgRepair => 1_000,
            Self::ExpressRecovery => 980,
            Self::MerchantCheckout => 930,
            Self::ForegroundWallet => 900,
            Self::WatchOnlyAudit => 820,
            Self::MobileSparse => 790,
            Self::BackgroundWallet => 720,
            Self::LowFee => 680,
        }
    }

    pub fn fee_cap(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::BackgroundWallet | Self::MobileSparse => {
                config.background_fee_micro_units
            }
            Self::ForegroundWallet | Self::WatchOnlyAudit => config.max_user_fee_micro_units,
            Self::MerchantCheckout => config.merchant_fee_micro_units,
            Self::ExpressRecovery | Self::ReorgRepair => config.express_fee_micro_units,
        }
    }

    pub fn mobile(self) -> bool {
        matches!(self, Self::MobileSparse | Self::BackgroundWallet)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Draft,
    Open,
    Bucketed,
    Attested,
    ReorgHeld,
    Settled,
    Expired,
    Disputed,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Bucketed => "bucketed",
            Self::Attested => "attested",
            Self::ReorgHeld => "reorg_held",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Bucketed | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Draft,
    Sealed,
    Couponed,
    Attested,
    MobilePacked,
    ReorgHeld,
    Settled,
    Expired,
    Disputed,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Couponed => "couponed",
            Self::Attested => "attested",
            Self::MobilePacked => "mobile_packed",
            Self::ReorgHeld => "reorg_held",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn scannable(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Couponed | Self::Attested | Self::MobilePacked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Reserved,
    Redeemable,
    Redeemed,
    Rebated,
    Expired,
    Revoked,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Redeemable => "redeemable",
            Self::Redeemed => "redeemed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Reserved | Self::Redeemable | Self::Redeemed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Quorum,
    Stale,
    Slashed,
    Disputed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Quorum => "quorum",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
            Self::Disputed => "disputed",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    LowFeeLane,
    MobileSparseScan,
    SponsorCovered,
    OperatorDelay,
    PrivacyFloorBoost,
    ReorgRepair,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeLane => "low_fee_lane",
            Self::MobileSparseScan => "mobile_sparse_scan",
            Self::SponsorCovered => "sponsor_covered",
            Self::OperatorDelay => "operator_delay",
            Self::PrivacyFloorBoost => "privacy_floor_boost",
            Self::ReorgRepair => "reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    ViewTagPrefix,
    BucketOccupancy,
    WalletCohort,
    OperatorTiming,
    ScannerIdentity,
    CouponAmount,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTagPrefix => "viewtag_prefix",
            Self::BucketOccupancy => "bucket_occupancy",
            Self::WalletCohort => "wallet_cohort",
            Self::OperatorTiming => "operator_timing",
            Self::ScannerIdentity => "scanner_identity",
            Self::CouponAmount => "coupon_amount",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub market_id: String,
    pub fee_asset_id: String,
    pub scan_window_blocks: u64,
    pub bucket_span_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub reorg_hold_blocks: u64,
    pub min_bucket_outputs: u32,
    pub max_bucket_outputs: u32,
    pub min_decoy_floor: u16,
    pub min_privacy_set_size: u64,
    pub min_viewtag_entropy_bps: u64,
    pub min_scanner_count: u16,
    pub scanner_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_micro_units: u64,
    pub background_fee_micro_units: u64,
    pub merchant_fee_micro_units: u64,
    pub express_fee_micro_units: u64,
    pub low_fee_rebate_bps: u64,
    pub mobile_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub daily_linkability_budget: u64,
    pub epoch_redaction_budget: u64,
    pub max_mobile_batch_bytes: u32,
    pub max_bucket_hint_bytes: u32,
    pub max_operator_delay_blocks: u64,
    pub max_coupons_per_wallet_epoch: u32,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            bucket_span_blocks: DEFAULT_BUCKET_SPAN_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            reorg_hold_blocks: DEFAULT_REORG_HOLD_BLOCKS,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            max_bucket_outputs: DEFAULT_MAX_BUCKET_OUTPUTS,
            min_decoy_floor: DEFAULT_MIN_DECOY_FLOOR,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_viewtag_entropy_bps: DEFAULT_MIN_VIEWTAG_ENTROPY_BPS,
            min_scanner_count: DEFAULT_MIN_SCANNER_COUNT,
            scanner_quorum_bps: DEFAULT_SCANNER_QUORUM_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            background_fee_micro_units: DEFAULT_BACKGROUND_FEE_MICRO_UNITS,
            merchant_fee_micro_units: DEFAULT_MERCHANT_FEE_MICRO_UNITS,
            express_fee_micro_units: DEFAULT_EXPRESS_FEE_MICRO_UNITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            mobile_rebate_bps: DEFAULT_MOBILE_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            daily_linkability_budget: DEFAULT_DAILY_LINKABILITY_BUDGET,
            epoch_redaction_budget: DEFAULT_EPOCH_REDACTION_BUDGET,
            max_mobile_batch_bytes: DEFAULT_MAX_MOBILE_BATCH_BYTES,
            max_bucket_hint_bytes: DEFAULT_MAX_BUCKET_HINT_BYTES,
            max_operator_delay_blocks: DEFAULT_MAX_OPERATOR_DELAY_BLOCKS,
            max_coupons_per_wallet_epoch: DEFAULT_MAX_COUPONS_PER_WALLET_EPOCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version: {}",
            self.protocol_version
        );
        ensure!(self.scan_window_blocks > 0, "scan window cannot be zero");
        ensure!(self.bucket_span_blocks > 0, "bucket span cannot be zero");
        ensure!(
            self.bucket_span_blocks <= self.scan_window_blocks,
            "bucket span cannot exceed scan window"
        );
        ensure!(
            self.min_bucket_outputs <= self.max_bucket_outputs,
            "min bucket outputs exceeds max"
        );
        ensure!(
            self.min_decoy_floor >= 16,
            "Monero decoy floor below privacy-safe minimum"
        );
        ensure!(
            self.min_privacy_set_size >= self.max_bucket_outputs as u64,
            "privacy set must cover at least one max bucket"
        );
        ensure!(
            self.min_viewtag_entropy_bps <= MAX_BPS,
            "viewtag entropy bps exceeds max"
        );
        ensure!(
            self.scanner_quorum_bps <= MAX_BPS,
            "scanner quorum bps exceeds max"
        );
        ensure!(
            self.low_fee_rebate_bps <= MAX_BPS && self.mobile_rebate_bps <= MAX_BPS,
            "rebate bps exceeds max"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps exceeds max"
        );
        ensure!(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security below minimum"
        );
        Ok(())
    }

    pub fn lane_fee_cap(&self, lane: ScanLane) -> u64 {
        lane.fee_cap(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "market_id": self.market_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "jamtis_scan_window_scheme": JAMTIS_SCAN_WINDOW_SCHEME,
            "viewtag_bucket_scheme": VIEWTAG_BUCKET_SCHEME,
            "wallet_scan_coupon_scheme": WALLET_SCAN_COUPON_SCHEME,
            "pq_scanner_attestation_scheme": PQ_SCANNER_ATTESTATION_SCHEME,
            "decoy_floor_scheme": DECOY_FLOOR_SCHEME,
            "mobile_scan_lane_scheme": MOBILE_SCAN_LANE_SCHEME,
            "fee_rebate_scheme": FEE_REBATE_SCHEME,
            "redaction_budget_scheme": REDACTION_BUDGET_SCHEME,
            "operator_summary_scheme": OPERATOR_SUMMARY_SCHEME,
            "scan_window_blocks": self.scan_window_blocks,
            "bucket_span_blocks": self.bucket_span_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "reorg_hold_blocks": self.reorg_hold_blocks,
            "min_bucket_outputs": self.min_bucket_outputs,
            "max_bucket_outputs": self.max_bucket_outputs,
            "min_decoy_floor": self.min_decoy_floor,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_viewtag_entropy_bps": self.min_viewtag_entropy_bps,
            "min_scanner_count": self.min_scanner_count,
            "scanner_quorum_bps": self.scanner_quorum_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "background_fee_micro_units": self.background_fee_micro_units,
            "merchant_fee_micro_units": self.merchant_fee_micro_units,
            "express_fee_micro_units": self.express_fee_micro_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "mobile_rebate_bps": self.mobile_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "daily_linkability_budget": self.daily_linkability_budget,
            "epoch_redaction_budget": self.epoch_redaction_budget,
            "max_mobile_batch_bytes": self.max_mobile_batch_bytes,
            "max_bucket_hint_bytes": self.max_bucket_hint_bytes,
            "max_operator_delay_blocks": self.max_operator_delay_blocks,
            "max_coupons_per_wallet_epoch": self.max_coupons_per_wallet_epoch,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub scan_windows: u64,
    pub viewtag_buckets: u64,
    pub wallet_scan_coupons: u64,
    pub pq_scanner_attestations: u64,
    pub decoy_floors: u64,
    pub mobile_scan_lanes: u64,
    pub fee_rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub live_windows: u64,
    pub active_coupons: u64,
    pub settled_buckets: u64,
    pub disputed_items: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_windows": self.scan_windows,
            "viewtag_buckets": self.viewtag_buckets,
            "wallet_scan_coupons": self.wallet_scan_coupons,
            "pq_scanner_attestations": self.pq_scanner_attestations,
            "decoy_floors": self.decoy_floors,
            "mobile_scan_lanes": self.mobile_scan_lanes,
            "fee_rebates": self.fee_rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "live_windows": self.live_windows,
            "active_coupons": self.active_coupons,
            "settled_buckets": self.settled_buckets,
            "disputed_items": self.disputed_items,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub scan_window_root: String,
    pub viewtag_bucket_root: String,
    pub wallet_scan_coupon_root: String,
    pub pq_scanner_attestation_root: String,
    pub decoy_floor_root: String,
    pub mobile_scan_lane_root: String,
    pub fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            scan_window_root: empty_root("scan_windows"),
            viewtag_bucket_root: empty_root("viewtag_buckets"),
            wallet_scan_coupon_root: empty_root("wallet_scan_coupons"),
            pq_scanner_attestation_root: empty_root("pq_scanner_attestations"),
            decoy_floor_root: empty_root("decoy_floors"),
            mobile_scan_lane_root: empty_root("mobile_scan_lanes"),
            fee_rebate_root: empty_root("fee_rebates"),
            redaction_budget_root: empty_root("redaction_budgets"),
            operator_summary_root: empty_root("operator_summaries"),
            state_root: String::new(),
        };
        roots.state_root = record_root("roots", &roots.public_record_without_state_root());
        roots
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "scan_window_root": self.scan_window_root,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "wallet_scan_coupon_root": self.wallet_scan_coupon_root,
            "pq_scanner_attestation_root": self.pq_scanner_attestation_root,
            "decoy_floor_root": self.decoy_floor_root,
            "mobile_scan_lane_root": self.mobile_scan_lane_root,
            "fee_rebate_root": self.fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JamtisScanWindow {
    pub window_id: String,
    pub epoch: u64,
    pub lane: ScanLane,
    pub start_height: u64,
    pub end_height: u64,
    pub jamtis_scan_root: String,
    pub viewtag_prefix_root: String,
    pub bucket_ids: Vec<String>,
    pub privacy_set_size: u64,
    pub expected_outputs: u64,
    pub max_fee_micro_units: u64,
    pub sponsor_commitment_root: Option<String>,
    pub status: WindowStatus,
}

impl JamtisScanWindow {
    pub fn new(
        epoch: u64,
        lane: ScanLane,
        start_height: u64,
        window_blocks: u64,
        privacy_set_size: u64,
        expected_outputs: u64,
        max_fee_micro_units: u64,
    ) -> Self {
        let end_height = start_height.saturating_add(window_blocks.saturating_sub(1));
        let window_id = id_root(
            "scan-window-id",
            &json!({
                "epoch": epoch,
                "lane": lane.as_str(),
                "start_height": start_height,
                "end_height": end_height,
            }),
        );
        Self {
            window_id,
            epoch,
            lane,
            start_height,
            end_height,
            jamtis_scan_root: id_root("jamtis-scan-root", &json!([epoch, lane.as_str()])),
            viewtag_prefix_root: id_root("viewtag-prefix-root", &json!([epoch, start_height])),
            bucket_ids: Vec::new(),
            privacy_set_size,
            expected_outputs,
            max_fee_micro_units,
            sponsor_commitment_root: None,
            status: WindowStatus::Draft,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.window_id.is_empty(), "window id cannot be empty");
        ensure!(
            self.start_height <= self.end_height,
            "scan window start exceeds end"
        );
        ensure!(
            self.end_height - self.start_height + 1 <= config.scan_window_blocks,
            "scan window exceeds configured span"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "scan window privacy set below minimum"
        );
        ensure!(
            self.max_fee_micro_units <= self.lane.fee_cap(config),
            "scan window fee exceeds lane cap"
        );
        Ok(())
    }

    pub fn attach_bucket(&mut self, bucket_id: impl Into<String>) {
        let bucket_id = bucket_id.into();
        if !self.bucket_ids.contains(&bucket_id) {
            self.bucket_ids.push(bucket_id);
            self.bucket_ids.sort();
            self.status = WindowStatus::Bucketed;
        }
    }

    pub fn with_sponsor(mut self, sponsor_commitment_root: impl Into<String>) -> Self {
        self.sponsor_commitment_root = Some(sponsor_commitment_root.into());
        self
    }

    pub fn settle(&mut self) {
        self.status = WindowStatus::Settled;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": JAMTIS_SCAN_WINDOW_SCHEME,
            "window_id": self.window_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "lane_priority_weight": self.lane.priority_weight(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "jamtis_scan_root": self.jamtis_scan_root,
            "viewtag_prefix_root": self.viewtag_prefix_root,
            "bucket_ids": self.bucket_ids,
            "privacy_set_size": self.privacy_set_size,
            "expected_outputs": self.expected_outputs,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "status": self.status.as_str(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("jamtis-scan-window", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": JAMTIS_SCAN_WINDOW_SCHEME,
            "window_id": self.window_id,
            "epoch": self.epoch,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "jamtis_scan_root": self.jamtis_scan_root,
            "viewtag_prefix_root": self.viewtag_prefix_root,
            "bucket_ids": self.bucket_ids,
            "privacy_set_size": self.privacy_set_size,
            "expected_outputs": self.expected_outputs,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ViewtagBucket {
    pub bucket_id: String,
    pub window_id: String,
    pub prefix_hex: String,
    pub start_height: u64,
    pub end_height: u64,
    pub output_count: u32,
    pub encrypted_hint_root: String,
    pub coupon_ids: Vec<String>,
    pub scanner_ids: BTreeSet<String>,
    pub entropy_bps: u64,
    pub fee_micro_units: u64,
    pub status: BucketStatus,
}

impl ViewtagBucket {
    pub fn new(
        window_id: impl Into<String>,
        prefix_hex: impl Into<String>,
        start_height: u64,
        end_height: u64,
        output_count: u32,
        entropy_bps: u64,
        fee_micro_units: u64,
    ) -> Self {
        let window_id = window_id.into();
        let prefix_hex = prefix_hex.into();
        let bucket_id = id_root(
            "viewtag-bucket-id",
            &json!({
                "window_id": window_id,
                "prefix_hex": prefix_hex,
                "start_height": start_height,
                "end_height": end_height,
            }),
        );
        Self {
            bucket_id,
            window_id,
            prefix_hex,
            start_height,
            end_height,
            output_count,
            encrypted_hint_root: id_root("viewtag-bucket-hint", &json!([start_height, end_height])),
            coupon_ids: Vec::new(),
            scanner_ids: BTreeSet::new(),
            entropy_bps,
            fee_micro_units,
            status: BucketStatus::Draft,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.bucket_id.is_empty(), "bucket id cannot be empty");
        ensure!(
            !self.window_id.is_empty(),
            "bucket window id cannot be empty"
        );
        ensure!(
            self.start_height <= self.end_height,
            "bucket start exceeds end"
        );
        ensure!(
            self.output_count >= config.min_bucket_outputs,
            "bucket output count below minimum"
        );
        ensure!(
            self.output_count <= config.max_bucket_outputs,
            "bucket output count above maximum"
        );
        ensure!(
            self.entropy_bps >= config.min_viewtag_entropy_bps,
            "bucket viewtag entropy below floor"
        );
        ensure!(
            self.fee_micro_units <= config.express_fee_micro_units,
            "bucket fee above express cap"
        );
        Ok(())
    }

    pub fn seal(&mut self) {
        self.status = BucketStatus::Sealed;
    }

    pub fn attach_coupon(&mut self, coupon_id: impl Into<String>) {
        let coupon_id = coupon_id.into();
        if !self.coupon_ids.contains(&coupon_id) {
            self.coupon_ids.push(coupon_id);
            self.coupon_ids.sort();
        }
        if self.status == BucketStatus::Sealed {
            self.status = BucketStatus::Couponed;
        }
    }

    pub fn attach_scanner(&mut self, scanner_id: impl Into<String>) {
        self.scanner_ids.insert(scanner_id.into());
        if matches!(self.status, BucketStatus::Couponed | BucketStatus::Sealed) {
            self.status = BucketStatus::Attested;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": VIEWTAG_BUCKET_SCHEME,
            "bucket_id": self.bucket_id,
            "window_id": self.window_id,
            "prefix_hex": self.prefix_hex,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "output_count": self.output_count,
            "encrypted_hint_root": self.encrypted_hint_root,
            "coupon_ids": self.coupon_ids,
            "scanner_ids": self.scanner_ids,
            "entropy_bps": self.entropy_bps,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("viewtag-bucket", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": VIEWTAG_BUCKET_SCHEME,
            "bucket_id": self.bucket_id,
            "window_id": self.window_id,
            "prefix_hex": self.prefix_hex,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "output_count": self.output_count,
            "encrypted_hint_root": self.encrypted_hint_root,
            "coupon_ids": self.coupon_ids,
            "scanner_ids": self.scanner_ids,
            "entropy_bps": self.entropy_bps,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanCoupon {
    pub coupon_id: String,
    pub wallet_cohort_root: String,
    pub bucket_id: String,
    pub lane: ScanLane,
    pub issued_height: u64,
    pub expires_height: u64,
    pub prepaid_fee_micro_units: u64,
    pub sponsor_covered_micro_units: u64,
    pub redemption_nullifier_root: String,
    pub status: CouponStatus,
}

impl WalletScanCoupon {
    pub fn new(
        wallet_cohort_root: impl Into<String>,
        bucket_id: impl Into<String>,
        lane: ScanLane,
        issued_height: u64,
        ttl_blocks: u64,
        prepaid_fee_micro_units: u64,
        sponsor_covered_micro_units: u64,
    ) -> Self {
        let wallet_cohort_root = wallet_cohort_root.into();
        let bucket_id = bucket_id.into();
        let expires_height = issued_height.saturating_add(ttl_blocks);
        let coupon_id = id_root(
            "wallet-scan-coupon-id",
            &json!({
                "wallet_cohort_root": wallet_cohort_root,
                "bucket_id": bucket_id,
                "lane": lane.as_str(),
                "issued_height": issued_height,
            }),
        );
        Self {
            coupon_id,
            wallet_cohort_root,
            bucket_id,
            lane,
            issued_height,
            expires_height,
            prepaid_fee_micro_units,
            sponsor_covered_micro_units,
            redemption_nullifier_root: id_root(
                "coupon-redemption-nullifier",
                &json!(issued_height),
            ),
            status: CouponStatus::Reserved,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.coupon_id.is_empty(), "coupon id cannot be empty");
        ensure!(
            self.issued_height < self.expires_height,
            "coupon expiry must be after issue height"
        );
        ensure!(
            self.expires_height - self.issued_height <= config.coupon_ttl_blocks,
            "coupon ttl exceeds configuration"
        );
        ensure!(
            self.prepaid_fee_micro_units <= self.lane.fee_cap(config),
            "coupon fee exceeds lane cap"
        );
        let sponsor_cover_cap = mul_bps(self.prepaid_fee_micro_units, config.sponsor_cover_bps);
        ensure!(
            self.sponsor_covered_micro_units <= sponsor_cover_cap,
            "coupon sponsor cover exceeds cap"
        );
        Ok(())
    }

    pub fn make_redeemable(&mut self) {
        self.status = CouponStatus::Redeemable;
    }

    pub fn redeem(&mut self) {
        self.status = CouponStatus::Redeemed;
    }

    pub fn rebate_amount(&self, config: &Config) -> u64 {
        let lane_rebate = if self.lane.mobile() {
            config.mobile_rebate_bps
        } else {
            config.low_fee_rebate_bps
        };
        mul_bps(self.prepaid_fee_micro_units, lane_rebate)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": WALLET_SCAN_COUPON_SCHEME,
            "coupon_id": self.coupon_id,
            "wallet_cohort_root": self.wallet_cohort_root,
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "prepaid_fee_micro_units": self.prepaid_fee_micro_units,
            "sponsor_covered_micro_units": self.sponsor_covered_micro_units,
            "redemption_nullifier_root": self.redemption_nullifier_root,
            "status": self.status.as_str(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet-scan-coupon", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": WALLET_SCAN_COUPON_SCHEME,
            "coupon_id": self.coupon_id,
            "wallet_cohort_root": self.wallet_cohort_root,
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "prepaid_fee_micro_units": self.prepaid_fee_micro_units,
            "sponsor_covered_micro_units": self.sponsor_covered_micro_units,
            "redemption_nullifier_root": self.redemption_nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqScannerAttestation {
    pub attestation_id: String,
    pub scanner_id: String,
    pub bucket_id: String,
    pub window_id: String,
    pub pq_key_commitment_root: String,
    pub signature_root: String,
    pub observed_output_count: u32,
    pub observed_entropy_bps: u64,
    pub decoy_floor: u16,
    pub pq_security_bits: u16,
    pub issued_height: u64,
    pub expires_height: u64,
    pub status: AttestationStatus,
}

impl PqScannerAttestation {
    pub fn new(
        scanner_id: impl Into<String>,
        bucket_id: impl Into<String>,
        window_id: impl Into<String>,
        observed_output_count: u32,
        observed_entropy_bps: u64,
        decoy_floor: u16,
        pq_security_bits: u16,
        issued_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let scanner_id = scanner_id.into();
        let bucket_id = bucket_id.into();
        let window_id = window_id.into();
        let expires_height = issued_height.saturating_add(ttl_blocks);
        let attestation_id = id_root(
            "pq-scanner-attestation-id",
            &json!({
                "scanner_id": scanner_id,
                "bucket_id": bucket_id,
                "window_id": window_id,
                "issued_height": issued_height,
            }),
        );
        Self {
            attestation_id,
            scanner_id: scanner_id.clone(),
            bucket_id,
            window_id,
            pq_key_commitment_root: id_root("pq-scanner-key", &json!(scanner_id)),
            signature_root: id_root("pq-scanner-signature", &json!(issued_height)),
            observed_output_count,
            observed_entropy_bps,
            decoy_floor,
            pq_security_bits,
            issued_height,
            expires_height,
            status: AttestationStatus::Pending,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "scanner attestation pq security below minimum"
        );
        ensure!(
            self.observed_output_count >= config.min_bucket_outputs,
            "scanner observed too few outputs"
        );
        ensure!(
            self.observed_entropy_bps >= config.min_viewtag_entropy_bps,
            "scanner observed entropy below floor"
        );
        ensure!(
            self.decoy_floor >= config.min_decoy_floor,
            "scanner decoy floor below configured floor"
        );
        ensure!(
            self.expires_height - self.issued_height <= config.attestation_ttl_blocks,
            "attestation ttl exceeds configuration"
        );
        Ok(())
    }

    pub fn accept(&mut self) {
        self.status = AttestationStatus::Accepted;
    }

    pub fn quorum(&mut self) {
        self.status = AttestationStatus::Quorum;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": PQ_SCANNER_ATTESTATION_SCHEME,
            "attestation_id": self.attestation_id,
            "scanner_id": self.scanner_id,
            "bucket_id": self.bucket_id,
            "window_id": self.window_id,
            "pq_key_commitment_root": self.pq_key_commitment_root,
            "signature_root": self.signature_root,
            "observed_output_count": self.observed_output_count,
            "observed_entropy_bps": self.observed_entropy_bps,
            "decoy_floor": self.decoy_floor,
            "pq_security_bits": self.pq_security_bits,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq-scanner-attestation", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": PQ_SCANNER_ATTESTATION_SCHEME,
            "attestation_id": self.attestation_id,
            "scanner_id": self.scanner_id,
            "bucket_id": self.bucket_id,
            "window_id": self.window_id,
            "pq_key_commitment_root": self.pq_key_commitment_root,
            "signature_root": self.signature_root,
            "observed_output_count": self.observed_output_count,
            "observed_entropy_bps": self.observed_entropy_bps,
            "decoy_floor": self.decoy_floor,
            "pq_security_bits": self.pq_security_bits,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecoyFloor {
    pub floor_id: String,
    pub window_id: String,
    pub lane: ScanLane,
    pub min_decoys: u16,
    pub privacy_set_size: u64,
    pub ring_member_age_floor_blocks: u64,
    pub churn_entropy_bps: u64,
    pub enforced_height: u64,
}

impl DecoyFloor {
    pub fn new(
        window_id: impl Into<String>,
        lane: ScanLane,
        min_decoys: u16,
        privacy_set_size: u64,
        ring_member_age_floor_blocks: u64,
        churn_entropy_bps: u64,
        enforced_height: u64,
    ) -> Self {
        let window_id = window_id.into();
        let floor_id = id_root(
            "decoy-floor-id",
            &json!([window_id, lane.as_str(), enforced_height]),
        );
        Self {
            floor_id,
            window_id,
            lane,
            min_decoys,
            privacy_set_size,
            ring_member_age_floor_blocks,
            churn_entropy_bps,
            enforced_height,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.min_decoys >= config.min_decoy_floor,
            "decoy floor below minimum"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "decoy floor privacy set below minimum"
        );
        ensure!(
            self.churn_entropy_bps >= config.min_viewtag_entropy_bps,
            "decoy floor churn entropy below minimum"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": DECOY_FLOOR_SCHEME,
            "floor_id": self.floor_id,
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "min_decoys": self.min_decoys,
            "privacy_set_size": self.privacy_set_size,
            "ring_member_age_floor_blocks": self.ring_member_age_floor_blocks,
            "churn_entropy_bps": self.churn_entropy_bps,
            "enforced_height": self.enforced_height,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("decoy-floor", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": DECOY_FLOOR_SCHEME,
            "floor_id": self.floor_id,
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "min_decoys": self.min_decoys,
            "privacy_set_size": self.privacy_set_size,
            "ring_member_age_floor_blocks": self.ring_member_age_floor_blocks,
            "churn_entropy_bps": self.churn_entropy_bps,
            "enforced_height": self.enforced_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MobileScanLane {
    pub mobile_lane_id: String,
    pub lane: ScanLane,
    pub window_id: String,
    pub bucket_ids: Vec<String>,
    pub max_batch_bytes: u32,
    pub compressed_hint_root: String,
    pub offline_valid_until_height: u64,
    pub sponsor_rebate_bps: u64,
}

impl MobileScanLane {
    pub fn new(
        lane: ScanLane,
        window_id: impl Into<String>,
        bucket_ids: Vec<String>,
        max_batch_bytes: u32,
        offline_valid_until_height: u64,
        sponsor_rebate_bps: u64,
    ) -> Self {
        let window_id = window_id.into();
        let mobile_lane_id = id_root(
            "mobile-scan-lane-id",
            &json!([lane.as_str(), window_id, bucket_ids]),
        );
        Self {
            mobile_lane_id,
            lane,
            window_id,
            bucket_ids,
            max_batch_bytes,
            compressed_hint_root: id_root(
                "mobile-compressed-hints",
                &json!(offline_valid_until_height),
            ),
            offline_valid_until_height,
            sponsor_rebate_bps,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(
            self.lane.mobile(),
            "mobile scan lane must use a mobile-friendly lane"
        );
        ensure!(
            self.max_batch_bytes <= config.max_mobile_batch_bytes,
            "mobile batch bytes exceeds cap"
        );
        ensure!(
            self.sponsor_rebate_bps <= config.mobile_rebate_bps,
            "mobile sponsor rebate exceeds cap"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": MOBILE_SCAN_LANE_SCHEME,
            "mobile_lane_id": self.mobile_lane_id,
            "lane": self.lane.as_str(),
            "window_id": self.window_id,
            "bucket_ids": self.bucket_ids,
            "max_batch_bytes": self.max_batch_bytes,
            "compressed_hint_root": self.compressed_hint_root,
            "offline_valid_until_height": self.offline_valid_until_height,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("mobile-scan-lane", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": MOBILE_SCAN_LANE_SCHEME,
            "mobile_lane_id": self.mobile_lane_id,
            "lane": self.lane.as_str(),
            "window_id": self.window_id,
            "bucket_ids": self.bucket_ids,
            "max_batch_bytes": self.max_batch_bytes,
            "compressed_hint_root": self.compressed_hint_root,
            "offline_valid_until_height": self.offline_valid_until_height,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub coupon_id: String,
    pub lane: ScanLane,
    pub reason: RebateReason,
    pub original_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub settlement_height: u64,
    pub claim_commitment_root: String,
}

impl FeeRebate {
    pub fn new(
        coupon: &WalletScanCoupon,
        reason: RebateReason,
        rebate_micro_units: u64,
        settlement_height: u64,
    ) -> Self {
        let rebate_id = id_root(
            "fee-rebate-id",
            &json!([coupon.coupon_id, reason.as_str(), settlement_height]),
        );
        Self {
            rebate_id,
            coupon_id: coupon.coupon_id.clone(),
            lane: coupon.lane,
            reason,
            original_fee_micro_units: coupon.prepaid_fee_micro_units,
            rebate_micro_units,
            settlement_height,
            claim_commitment_root: id_root("fee-rebate-claim", &json!(settlement_height)),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.rebate_micro_units <= self.original_fee_micro_units,
            "rebate cannot exceed original fee"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": FEE_REBATE_SCHEME,
            "rebate_id": self.rebate_id,
            "coupon_id": self.coupon_id,
            "lane": self.lane.as_str(),
            "reason": self.reason.as_str(),
            "original_fee_micro_units": self.original_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "settlement_height": self.settlement_height,
            "claim_commitment_root": self.claim_commitment_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fee-rebate", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": FEE_REBATE_SCHEME,
            "rebate_id": self.rebate_id,
            "coupon_id": self.coupon_id,
            "lane": self.lane.as_str(),
            "reason": self.reason.as_str(),
            "original_fee_micro_units": self.original_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "settlement_height": self.settlement_height,
            "claim_commitment_root": self.claim_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub redaction_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub classes: BTreeMap<RedactionClass, u64>,
    pub spent_units: u64,
    pub max_units: u64,
    pub audit_commitment_root: String,
}

impl RedactionBudget {
    pub fn new(operator_id: impl Into<String>, epoch: u64, max_units: u64) -> Self {
        let operator_id = operator_id.into();
        let classes = BTreeMap::from([
            (RedactionClass::ViewTagPrefix, max_units / 4),
            (RedactionClass::BucketOccupancy, max_units / 4),
            (RedactionClass::WalletCohort, max_units / 8),
            (RedactionClass::OperatorTiming, max_units / 8),
            (RedactionClass::ScannerIdentity, max_units / 8),
            (RedactionClass::CouponAmount, max_units / 8),
        ]);
        let redaction_id = id_root("redaction-budget-id", &json!([operator_id, epoch]));
        Self {
            redaction_id,
            operator_id,
            epoch,
            classes,
            spent_units: 0,
            max_units,
            audit_commitment_root: id_root("redaction-audit", &json!(epoch)),
        }
    }

    pub fn spend(&mut self, class: RedactionClass, units: u64) -> Result<()> {
        let class_budget = self.classes.get(&class).copied().unwrap_or_default();
        ensure!(
            units <= class_budget,
            "redaction class spend exceeds budget"
        );
        ensure!(
            self.spent_units.saturating_add(units) <= self.max_units,
            "redaction spend exceeds epoch budget"
        );
        self.spent_units += units;
        self.classes.insert(class, class_budget - units);
        Ok(())
    }

    pub fn remaining_units(&self) -> u64 {
        self.max_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        let classes: BTreeMap<String, u64> = self
            .classes
            .iter()
            .map(|(class, units)| (class.as_str().to_string(), *units))
            .collect();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": REDACTION_BUDGET_SCHEME,
            "redaction_id": self.redaction_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "classes": classes,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_units": self.max_units,
            "audit_commitment_root": self.audit_commitment_root,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("redaction-budget", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        let classes: BTreeMap<String, u64> = self
            .classes
            .iter()
            .map(|(class, units)| (class.as_str().to_string(), *units))
            .collect();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": REDACTION_BUDGET_SCHEME,
            "redaction_id": self.redaction_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "classes": classes,
            "spent_units": self.spent_units,
            "max_units": self.max_units,
            "audit_commitment_root": self.audit_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub window_root: String,
    pub bucket_root: String,
    pub coupon_root: String,
    pub attestation_root: String,
    pub rebate_root: String,
    pub public_window_count: u64,
    pub public_bucket_count: u64,
    pub public_coupon_count: u64,
    pub median_fee_micro_units: u64,
    pub max_delay_blocks: u64,
}

impl OperatorSummary {
    pub fn from_state(operator_id: impl Into<String>, epoch: u64, state: &State) -> Self {
        let operator_id = operator_id.into();
        let roots = state.roots();
        let fees: Vec<u64> = state
            .viewtag_buckets
            .values()
            .map(|bucket| bucket.fee_micro_units)
            .collect();
        let median_fee_micro_units = median(fees);
        let summary_id = id_root(
            "operator-summary-id",
            &json!([operator_id, epoch, roots.state_root]),
        );
        Self {
            summary_id,
            operator_id,
            epoch,
            window_root: roots.scan_window_root,
            bucket_root: roots.viewtag_bucket_root,
            coupon_root: roots.wallet_scan_coupon_root,
            attestation_root: roots.pq_scanner_attestation_root,
            rebate_root: roots.fee_rebate_root,
            public_window_count: state.scan_windows.len() as u64,
            public_bucket_count: state.viewtag_buckets.len() as u64,
            public_coupon_count: state.wallet_scan_coupons.len() as u64,
            median_fee_micro_units,
            max_delay_blocks: state.config.max_operator_delay_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": OPERATOR_SUMMARY_SCHEME,
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "window_root": self.window_root,
            "bucket_root": self.bucket_root,
            "coupon_root": self.coupon_root,
            "attestation_root": self.attestation_root,
            "rebate_root": self.rebate_root,
            "public_window_count": self.public_window_count,
            "public_bucket_count": self.public_bucket_count,
            "public_coupon_count": self.public_coupon_count,
            "median_fee_micro_units": self.median_fee_micro_units,
            "max_delay_blocks": self.max_delay_blocks,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator-summary", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "scheme": OPERATOR_SUMMARY_SCHEME,
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "window_root": self.window_root,
            "bucket_root": self.bucket_root,
            "coupon_root": self.coupon_root,
            "attestation_root": self.attestation_root,
            "rebate_root": self.rebate_root,
            "public_window_count": self.public_window_count,
            "public_bucket_count": self.public_bucket_count,
            "public_coupon_count": self.public_coupon_count,
            "median_fee_micro_units": self.median_fee_micro_units,
            "max_delay_blocks": self.max_delay_blocks,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub scan_windows: BTreeMap<String, JamtisScanWindow>,
    pub viewtag_buckets: BTreeMap<String, ViewtagBucket>,
    pub wallet_scan_coupons: BTreeMap<String, WalletScanCoupon>,
    pub pq_scanner_attestations: BTreeMap<String, PqScannerAttestation>,
    pub decoy_floors: BTreeMap<String, DecoyFloor>,
    pub mobile_scan_lanes: BTreeMap<String, MobileScanLane>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            scan_windows: BTreeMap::new(),
            viewtag_buckets: BTreeMap::new(),
            wallet_scan_coupons: BTreeMap::new(),
            pq_scanner_attestations: BTreeMap::new(),
            decoy_floors: BTreeMap::new(),
            mobile_scan_lanes: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        build_devnet().expect("devnet JAMTIS viewtag scan fee market")
    }

    pub fn insert_scan_window(&mut self, mut window: JamtisScanWindow) -> Result<String> {
        ensure!(
            self.scan_windows.len() < MAX_SCAN_WINDOWS,
            "scan window capacity reached"
        );
        window.validate(&self.config)?;
        if window.status == WindowStatus::Draft {
            window.status = WindowStatus::Open;
        }
        let window_id = window.window_id.clone();
        self.scan_windows.insert(window_id.clone(), window);
        self.refresh_counters();
        Ok(window_id)
    }

    pub fn insert_viewtag_bucket(&mut self, mut bucket: ViewtagBucket) -> Result<String> {
        ensure!(
            self.viewtag_buckets.len() < MAX_VIEWTAG_BUCKETS,
            "viewtag bucket capacity reached"
        );
        bucket.validate(&self.config)?;
        ensure!(
            self.scan_windows.contains_key(&bucket.window_id),
            "bucket references unknown window"
        );
        if bucket.status == BucketStatus::Draft {
            bucket.seal();
        }
        let bucket_id = bucket.bucket_id.clone();
        if let Some(window) = self.scan_windows.get_mut(&bucket.window_id) {
            window.attach_bucket(bucket_id.clone());
        }
        self.viewtag_buckets.insert(bucket_id.clone(), bucket);
        self.refresh_counters();
        Ok(bucket_id)
    }

    pub fn issue_coupon(&mut self, mut coupon: WalletScanCoupon) -> Result<String> {
        ensure!(
            self.wallet_scan_coupons.len() < MAX_WALLET_SCAN_COUPONS,
            "wallet scan coupon capacity reached"
        );
        coupon.validate(&self.config)?;
        ensure!(
            self.viewtag_buckets.contains_key(&coupon.bucket_id),
            "coupon references unknown bucket"
        );
        coupon.make_redeemable();
        let coupon_id = coupon.coupon_id.clone();
        if let Some(bucket) = self.viewtag_buckets.get_mut(&coupon.bucket_id) {
            bucket.attach_coupon(coupon_id.clone());
        }
        self.wallet_scan_coupons.insert(coupon_id.clone(), coupon);
        self.refresh_counters();
        Ok(coupon_id)
    }

    pub fn accept_scanner_attestation(
        &mut self,
        mut attestation: PqScannerAttestation,
    ) -> Result<String> {
        ensure!(
            self.pq_scanner_attestations.len() < MAX_PQ_SCANNER_ATTESTATIONS,
            "pq scanner attestation capacity reached"
        );
        attestation.validate(&self.config)?;
        ensure!(
            self.viewtag_buckets.contains_key(&attestation.bucket_id),
            "attestation references unknown bucket"
        );
        attestation.accept();
        let attestation_id = attestation.attestation_id.clone();
        if let Some(bucket) = self.viewtag_buckets.get_mut(&attestation.bucket_id) {
            bucket.attach_scanner(attestation.scanner_id.clone());
        }
        self.pq_scanner_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_scanner_quorums();
        self.refresh_counters();
        Ok(attestation_id)
    }

    pub fn insert_decoy_floor(&mut self, floor: DecoyFloor) -> Result<String> {
        ensure!(
            self.decoy_floors.len() < MAX_DECOY_FLOORS,
            "decoy floor capacity reached"
        );
        floor.validate(&self.config)?;
        ensure!(
            self.scan_windows.contains_key(&floor.window_id),
            "decoy floor references unknown window"
        );
        let floor_id = floor.floor_id.clone();
        self.decoy_floors.insert(floor_id.clone(), floor);
        self.refresh_counters();
        Ok(floor_id)
    }

    pub fn insert_mobile_scan_lane(&mut self, lane: MobileScanLane) -> Result<String> {
        ensure!(
            self.mobile_scan_lanes.len() < MAX_MOBILE_SCAN_LANES,
            "mobile scan lane capacity reached"
        );
        lane.validate(&self.config)?;
        ensure!(
            self.scan_windows.contains_key(&lane.window_id),
            "mobile lane references unknown window"
        );
        for bucket_id in &lane.bucket_ids {
            ensure!(
                self.viewtag_buckets.contains_key(bucket_id),
                "mobile lane references unknown bucket {}",
                bucket_id
            );
        }
        let mobile_lane_id = lane.mobile_lane_id.clone();
        for bucket_id in &lane.bucket_ids {
            if let Some(bucket) = self.viewtag_buckets.get_mut(bucket_id) {
                bucket.status = BucketStatus::MobilePacked;
            }
        }
        self.mobile_scan_lanes.insert(mobile_lane_id.clone(), lane);
        self.refresh_counters();
        Ok(mobile_lane_id)
    }

    pub fn settle_coupon_rebate(
        &mut self,
        coupon_id: &str,
        reason: RebateReason,
        settlement_height: u64,
    ) -> Result<String> {
        ensure!(
            self.fee_rebates.len() < MAX_FEE_REBATES,
            "rebate capacity reached"
        );
        let coupon = self
            .wallet_scan_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("unknown coupon: {}", coupon_id))?;
        let rebate_micro_units = coupon.rebate_amount(&self.config);
        coupon.status = CouponStatus::Rebated;
        let rebate = FeeRebate::new(coupon, reason, rebate_micro_units, settlement_height);
        rebate.validate()?;
        let rebate_id = rebate.rebate_id.clone();
        self.fee_rebates.insert(rebate_id.clone(), rebate);
        self.refresh_counters();
        Ok(rebate_id)
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        ensure!(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity reached"
        );
        ensure!(
            budget.max_units <= self.config.epoch_redaction_budget,
            "redaction budget exceeds config"
        );
        let redaction_id = budget.redaction_id.clone();
        self.redaction_budgets.insert(redaction_id.clone(), budget);
        self.refresh_counters();
        Ok(redaction_id)
    }

    pub fn publish_operator_summary(
        &mut self,
        operator_id: impl Into<String>,
        epoch: u64,
    ) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity reached"
        );
        let summary = OperatorSummary::from_state(operator_id, epoch, self);
        let summary_id = summary.summary_id.clone();
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.refresh_counters();
        Ok(summary_id)
    }

    pub fn expected_fee_for_lane(&self, lane: ScanLane, bucket_count: u64) -> u64 {
        let base = self.config.lane_fee_cap(lane);
        let priority_discount = 1_000u64.saturating_sub(lane.priority_weight().min(1_000));
        let congestion = bucket_count.saturating_mul(7).min(250);
        base.saturating_mul(1_000 + congestion)
            .saturating_div(1_000 + priority_discount)
            .min(self.config.express_fee_micro_units)
    }

    pub fn privacy_health_bps(&self) -> u64 {
        if self.viewtag_buckets.is_empty() {
            return MAX_BPS;
        }
        let entropy: u64 = self
            .viewtag_buckets
            .values()
            .map(|bucket| bucket.entropy_bps.min(MAX_BPS))
            .sum();
        let decoy: u64 = self
            .decoy_floors
            .values()
            .map(|floor| {
                floor
                    .min_decoys
                    .saturating_mul(100)
                    .saturating_div(self.config.min_decoy_floor.max(1)) as u64
            })
            .sum();
        let entropy_avg = entropy / self.viewtag_buckets.len() as u64;
        let decoy_avg = if self.decoy_floors.is_empty() {
            MAX_BPS
        } else {
            decoy
                .saturating_mul(100)
                .min(MAX_BPS * self.decoy_floors.len() as u64)
                / self.decoy_floors.len() as u64
        };
        ((entropy_avg + decoy_avg) / 2).min(MAX_BPS)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: record_root("config", &self.config.public_record()),
            counters_root: record_root("counters", &self.counters.public_record()),
            scan_window_root: map_root(
                "scan-windows",
                self.scan_windows
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            viewtag_bucket_root: map_root(
                "viewtag-buckets",
                self.viewtag_buckets
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            wallet_scan_coupon_root: map_root(
                "wallet-scan-coupons",
                self.wallet_scan_coupons
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            pq_scanner_attestation_root: map_root(
                "pq-scanner-attestations",
                self.pq_scanner_attestations
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            decoy_floor_root: map_root(
                "decoy-floors",
                self.decoy_floors
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            mobile_scan_lane_root: map_root(
                "mobile-scan-lanes",
                self.mobile_scan_lanes
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            fee_rebate_root: map_root(
                "fee-rebates",
                self.fee_rebates
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            redaction_budget_root: map_root(
                "redaction-budgets",
                self.redaction_budgets
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            operator_summary_root: map_root(
                "operator-summaries",
                self.operator_summaries
                    .iter()
                    .map(|(id, record)| (id.as_str(), record.public_record())),
            ),
            state_root: String::new(),
        };
        roots.state_root = record_root("state-roots", &roots.public_record_without_state_root());
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "market_id": self.config.market_id,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "privacy_health_bps": self.privacy_health_bps(),
            "scan_windows": public_map(&self.scan_windows, JamtisScanWindow::public_record),
            "viewtag_buckets": public_map(&self.viewtag_buckets, ViewtagBucket::public_record),
            "wallet_scan_coupons": public_map(&self.wallet_scan_coupons, WalletScanCoupon::public_record),
            "pq_scanner_attestations": public_map(&self.pq_scanner_attestations, PqScannerAttestation::public_record),
            "decoy_floors": public_map(&self.decoy_floors, DecoyFloor::public_record),
            "mobile_scan_lanes": public_map(&self.mobile_scan_lanes, MobileScanLane::public_record),
            "fee_rebates": public_map(&self.fee_rebates, FeeRebate::public_record),
            "redaction_budgets": public_map(&self.redaction_budgets, RedactionBudget::public_record),
            "operator_summaries": public_map(&self.operator_summaries, OperatorSummary::public_record),
            "state_root": roots.state_root,
        })
    }

    fn refresh_scanner_quorums(&mut self) {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for attestation in self.pq_scanner_attestations.values() {
            if attestation.status.counts_for_quorum() {
                *counts.entry(attestation.bucket_id.clone()).or_default() += 1;
            }
        }
        for attestation in self.pq_scanner_attestations.values_mut() {
            let scanner_count = counts
                .get(&attestation.bucket_id)
                .copied()
                .unwrap_or_default();
            if scanner_count >= self.config.min_scanner_count as u64 {
                attestation.quorum();
            }
        }
    }

    fn refresh_counters(&mut self) {
        self.counters.scan_windows = self.scan_windows.len() as u64;
        self.counters.viewtag_buckets = self.viewtag_buckets.len() as u64;
        self.counters.wallet_scan_coupons = self.wallet_scan_coupons.len() as u64;
        self.counters.pq_scanner_attestations = self.pq_scanner_attestations.len() as u64;
        self.counters.decoy_floors = self.decoy_floors.len() as u64;
        self.counters.mobile_scan_lanes = self.mobile_scan_lanes.len() as u64;
        self.counters.fee_rebates = self.fee_rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.live_windows = self
            .scan_windows
            .values()
            .filter(|window| window.status.live())
            .count() as u64;
        self.counters.active_coupons = self
            .wallet_scan_coupons
            .values()
            .filter(|coupon| coupon.status.active())
            .count() as u64;
        self.counters.settled_buckets = self
            .viewtag_buckets
            .values()
            .filter(|bucket| bucket.status == BucketStatus::Settled)
            .count() as u64;
        self.counters.disputed_items = self
            .scan_windows
            .values()
            .filter(|window| window.status == WindowStatus::Disputed)
            .count() as u64
            + self
                .viewtag_buckets
                .values()
                .filter(|bucket| bucket.status == BucketStatus::Disputed)
                .count() as u64
            + self
                .pq_scanner_attestations
                .values()
                .filter(|attestation| attestation.status == AttestationStatus::Disputed)
                .count() as u64;
        self.counters.public_records = self.counters.scan_windows
            + self.counters.viewtag_buckets
            + self.counters.wallet_scan_coupons
            + self.counters.pq_scanner_attestations
            + self.counters.decoy_floors
            + self.counters.mobile_scan_lanes
            + self.counters.fee_rebates
            + self.counters.redaction_budgets
            + self.counters.operator_summaries;
    }
}

fn build_devnet() -> Result<State> {
    let mut state = State::new(Config::devnet())?;
    let window = JamtisScanWindow::new(
        DEVNET_EPOCH,
        ScanLane::BackgroundWallet,
        DEVNET_HEIGHT,
        DEFAULT_SCAN_WINDOW_BLOCKS,
        DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        24_000,
        DEFAULT_BACKGROUND_FEE_MICRO_UNITS,
    )
    .with_sponsor(id_root("devnet-sponsor", &json!("low-fee-wallet-sponsor")));
    let window_id = state.insert_scan_window(window)?;

    let bucket_a = ViewtagBucket::new(
        window_id.clone(),
        "4a",
        DEVNET_HEIGHT,
        DEVNET_HEIGHT + DEFAULT_BUCKET_SPAN_BLOCKS - 1,
        1_024,
        9_250,
        420,
    );
    let bucket_a_id = state.insert_viewtag_bucket(bucket_a)?;

    let bucket_b = ViewtagBucket::new(
        window_id.clone(),
        "9f",
        DEVNET_HEIGHT + DEFAULT_BUCKET_SPAN_BLOCKS,
        DEVNET_HEIGHT + DEFAULT_BUCKET_SPAN_BLOCKS * 2 - 1,
        2_048,
        9_100,
        460,
    );
    let bucket_b_id = state.insert_viewtag_bucket(bucket_b)?;

    let coupon = WalletScanCoupon::new(
        id_root("wallet-cohort", &json!("background-devnet-wallets")),
        bucket_a_id.clone(),
        ScanLane::BackgroundWallet,
        DEVNET_HEIGHT + 2,
        DEFAULT_COUPON_TTL_BLOCKS,
        420,
        360,
    );
    let coupon_id = state.issue_coupon(coupon)?;

    for scanner_index in 0..DEFAULT_MIN_SCANNER_COUNT {
        let scanner_id = format!("devnet-pq-scanner-{}", scanner_index + 1);
        let attestation = PqScannerAttestation::new(
            scanner_id,
            bucket_a_id.clone(),
            window_id.clone(),
            1_024,
            9_250,
            DEFAULT_MIN_DECOY_FLOOR,
            DEFAULT_TARGET_PQ_SECURITY_BITS,
            DEVNET_HEIGHT + 4 + scanner_index as u64,
            DEFAULT_ATTESTATION_TTL_BLOCKS,
        );
        state.accept_scanner_attestation(attestation)?;
    }

    let floor = DecoyFloor::new(
        window_id.clone(),
        ScanLane::BackgroundWallet,
        DEFAULT_MIN_DECOY_FLOOR + 32,
        DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        720,
        9_300,
        DEVNET_HEIGHT,
    );
    state.insert_decoy_floor(floor)?;

    let mobile_lane = MobileScanLane::new(
        ScanLane::MobileSparse,
        window_id.clone(),
        vec![bucket_a_id.clone(), bucket_b_id],
        DEFAULT_MAX_MOBILE_BATCH_BYTES / 2,
        DEVNET_HEIGHT + DEFAULT_COUPON_TTL_BLOCKS,
        DEFAULT_MOBILE_REBATE_BPS,
    );
    state.insert_mobile_scan_lane(mobile_lane)?;

    state.settle_coupon_rebate(
        &coupon_id,
        RebateReason::MobileSparseScan,
        DEVNET_HEIGHT + 18,
    )?;

    let mut redaction = RedactionBudget::new(
        "devnet-scan-operator-1",
        DEVNET_EPOCH,
        DEFAULT_EPOCH_REDACTION_BUDGET,
    );
    redaction.spend(RedactionClass::WalletCohort, 1)?;
    redaction.spend(RedactionClass::BucketOccupancy, 2)?;
    state.insert_redaction_budget(redaction)?;

    state.publish_operator_summary("devnet-scan-operator-1", DEVNET_EPOCH)?;
    Ok(state)
}

fn build_demo() -> Result<State> {
    let mut state = build_devnet()?;
    let express_window = JamtisScanWindow::new(
        DEVNET_EPOCH + 1,
        ScanLane::ExpressRecovery,
        DEVNET_HEIGHT + DEFAULT_SCAN_WINDOW_BLOCKS,
        DEFAULT_SCAN_WINDOW_BLOCKS,
        DEFAULT_MIN_PRIVACY_SET_SIZE * 3,
        8_000,
        DEFAULT_EXPRESS_FEE_MICRO_UNITS,
    );
    let express_window_id = state.insert_scan_window(express_window)?;
    let express_bucket = ViewtagBucket::new(
        express_window_id.clone(),
        "c7",
        DEVNET_HEIGHT + DEFAULT_SCAN_WINDOW_BLOCKS,
        DEVNET_HEIGHT + DEFAULT_SCAN_WINDOW_BLOCKS + DEFAULT_BUCKET_SPAN_BLOCKS - 1,
        768,
        9_400,
        DEFAULT_MAX_USER_FEE_MICRO_UNITS,
    );
    let express_bucket_id = state.insert_viewtag_bucket(express_bucket)?;
    let coupon = WalletScanCoupon::new(
        id_root("wallet-cohort", &json!("recovery-demo-wallets")),
        express_bucket_id.clone(),
        ScanLane::ExpressRecovery,
        DEVNET_HEIGHT + DEFAULT_SCAN_WINDOW_BLOCKS + 3,
        DEFAULT_COUPON_TTL_BLOCKS / 2,
        DEFAULT_MAX_USER_FEE_MICRO_UNITS,
        0,
    );
    let coupon_id = state.issue_coupon(coupon)?;
    let attestation = PqScannerAttestation::new(
        "demo-recovery-scanner",
        express_bucket_id,
        express_window_id,
        768,
        9_400,
        DEFAULT_MIN_DECOY_FLOOR + 64,
        DEFAULT_TARGET_PQ_SECURITY_BITS,
        DEVNET_HEIGHT + DEFAULT_SCAN_WINDOW_BLOCKS + 5,
        DEFAULT_ATTESTATION_TTL_BLOCKS,
    );
    state.accept_scanner_attestation(attestation)?;
    state.settle_coupon_rebate(
        &coupon_id,
        RebateReason::PrivacyFloorBoost,
        DEVNET_HEIGHT + 800,
    )?;
    state.publish_operator_summary("demo-fast-scan-operator", DEVNET_EPOCH + 1)?;
    Ok(state)
}

pub fn devnet() -> State {
    build_devnet().expect("devnet JAMTIS viewtag scan fee market")
}

pub fn demo() -> State {
    build_demo().expect("demo JAMTIS viewtag scan fee market")
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn empty_root(label: &str) -> String {
    record_root(label, &json!([]))
}

fn id_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("JAMTIS-VIEWTAG-SCAN-FEE-MARKET-ID-{}", label),
        &[HashPart::Json(record)],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("JAMTIS-VIEWTAG-SCAN-FEE-MARKET-{}", label),
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<'a, I>(label: &str, records: I) -> String
where
    I: IntoIterator<Item = (&'a str, Value)>,
{
    let leaves: Vec<String> = records
        .into_iter()
        .map(|(id, record)| record_root(&format!("{}-{}", label, id), &record))
        .collect();
    if leaves.is_empty() {
        empty_root(label)
    } else {
        merkle_root(
            &format!("JAMTIS-VIEWTAG-SCAN-FEE-MARKET-{}", label),
            &leaves,
        )
    }
}

fn public_map<T>(
    records: &BTreeMap<String, T>,
    render: impl Fn(&T) -> Value,
) -> BTreeMap<String, Value> {
    records
        .iter()
        .map(|(id, record)| (id.clone(), render(record)))
        .collect()
}

fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps).saturating_div(MAX_BPS)
}

fn median(mut values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[values.len() / 2]
}
