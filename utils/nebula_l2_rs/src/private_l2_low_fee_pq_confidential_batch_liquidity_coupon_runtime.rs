use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialBatchLiquidityCouponRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialBatchLiquidityCouponRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_LIQUIDITY_COUPON_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-batch-liquidity-coupon-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_LIQUIDITY_COUPON_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-batch-liquidity-coupon-v1";
pub const COUPON_BOOK_SCHEME: &str =
    "monero-private-l2-confidential-batch-liquidity-coupon-book-root-v1";
pub const LIQUIDITY_SPONSOR_SCHEME: &str =
    "monero-private-l2-pq-liquidity-sponsor-attested-root-v1";
pub const BATCH_REDEMPTION_SCHEME: &str =
    "monero-private-l2-low-fee-liquidity-coupon-batch-redemption-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "monero-private-l2-pq-sponsor-liquidity-attestation-root-v1";
pub const FEE_REBATE_SCHEME: &str =
    "monero-private-l2-confidential-liquidity-coupon-fee-rebate-root-v1";
pub const THROTTLE_SCHEME: &str = "monero-private-l2-liquidity-coupon-anti-abuse-throttle-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "monero-private-l2-liquidity-coupon-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "roots-only-private-l2-batch-liquidity-coupon-operator-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-batch-liquidity-coupon-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_COUPON_ASSET_ID: &str = "plc-devnet";
pub const DEVNET_HEIGHT: u64 = 3_940_000;
pub const DEVNET_EPOCH: u64 = 22_400;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_400;
pub const DEFAULT_LIQUIDITY_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_MIN_SPONSOR_RESERVE_MICRO: u64 = 100_000_000;
pub const DEFAULT_BATCH_TARGET_BLOCKS: u64 = 4;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDEMPTION_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_WALLET_CAP_MICRO: u64 = 2_000_000;
pub const DEFAULT_SPONSOR_BATCH_CAP_MICRO: u64 = 500_000_000;
pub const DEFAULT_MAX_COUPONS_PER_BATCH: usize = 65_536;
pub const DEFAULT_MAX_SPONSORS_PER_BATCH: usize = 256;
pub const DEFAULT_OPERATOR_SUMMARY_LIMIT: usize = 128;
pub const DEFAULT_MAX_REDACTIONS_PER_WINDOW: u32 = 16;
pub const MAX_COUPON_BOOKS: usize = 1_048_576;
pub const MAX_LIQUIDITY_SPONSORS: usize = 1_048_576;
pub const MAX_BATCH_REDEMPTIONS: usize = 2_097_152;
pub const MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const MAX_FEE_REBATES: usize = 4_194_304;
pub const MAX_THROTTLES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_SUMMARIES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityLane {
    MoneroPrivateTransfer,
    FastBridgeExit,
    DexSwap,
    MerchantBatch,
    PayrollBatch,
    WalletSession,
    DefiNetting,
    EmergencyWithdrawal,
}

impl LiquidityLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroPrivateTransfer => "monero_private_transfer",
            Self::FastBridgeExit => "fast_bridge_exit",
            Self::DexSwap => "dex_swap",
            Self::MerchantBatch => "merchant_batch",
            Self::PayrollBatch => "payroll_batch",
            Self::WalletSession => "wallet_session",
            Self::DefiNetting => "defi_netting",
            Self::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponBookStatus {
    Draft,
    Open,
    Issuing,
    Sealed,
    Redeeming,
    Settled,
    Expired,
    Quarantined,
}

impl CouponBookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Issuing => "issuing",
            Self::Sealed => "sealed",
            Self::Redeeming => "redeeming",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_issuance(self) -> bool {
        matches!(self, Self::Open | Self::Issuing)
    }

    pub fn accepts_redemption(self) -> bool {
        matches!(self, Self::Sealed | Self::Redeeming)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Reserved,
    Attested,
    Active,
    Throttled,
    Depleted,
    Paused,
    Slashed,
    Retired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Depleted => "depleted",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_issue(self) -> bool {
        matches!(self, Self::Attested | Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionStatus {
    Proposed,
    Attested,
    Netting,
    Settled,
    PartiallySettled,
    Disputed,
    Reversed,
    Expired,
}

impl RedemptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Netting => "netting",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPurpose {
    SponsorOnboarding,
    CouponIssuance,
    BatchRedemption,
    FeeRebate,
    ThrottleRelease,
    RedactionDisclosure,
}

impl AttestationPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorOnboarding => "sponsor_onboarding",
            Self::CouponIssuance => "coupon_issuance",
            Self::BatchRedemption => "batch_redemption",
            Self::FeeRebate => "fee_rebate",
            Self::ThrottleRelease => "throttle_release",
            Self::RedactionDisclosure => "redaction_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approved,
    NeedsMorePrivacy,
    FeeCapExceeded,
    SponsorReserveLow,
    Throttled,
    DuplicateNullifier,
    Rejected,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::NeedsMorePrivacy => "needs_more_privacy",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::SponsorReserveLow => "sponsor_reserve_low",
            Self::Throttled => "throttled",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::Rejected => "rejected",
        }
    }

    pub fn approves(self) -> bool {
        matches!(self, Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Queued,
    Netting,
    Paid,
    ClawedBack,
    Forfeited,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Queued => "queued",
            Self::Netting => "netting",
            Self::Paid => "paid",
            Self::ClawedBack => "clawed_back",
            Self::Forfeited => "forfeited",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleStatus {
    Watching,
    Active,
    CoolingDown,
    Suspended,
    Released,
    Retired,
}

impl ThrottleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watching => "watching",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Suspended => "suspended",
            Self::Released => "released",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseSeverity {
    Watch,
    SoftLimit,
    HardLimit,
    Slashable,
    Critical,
}

impl AbuseSeverity {
    pub fn slash_bps(self) -> u64 {
        match self {
            Self::Watch => 0,
            Self::SoftLimit => 100,
            Self::HardLimit => 500,
            Self::Slashable => 2_000,
            Self::Critical => 5_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub liquidity_rebate_bps: u64,
    pub min_sponsor_reserve_micro: u64,
    pub batch_target_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub redemption_finality_blocks: u64,
    pub throttle_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub wallet_cap_micro: u64,
    pub sponsor_batch_cap_micro: u64,
    pub max_coupons_per_batch: usize,
    pub max_sponsors_per_batch: usize,
    pub max_redactions_per_window: u32,
    pub operator_summary_limit: usize,
    pub accepted_lanes: BTreeSet<LiquidityLane>,
    pub accepted_fee_assets: BTreeSet<String>,
    pub sponsor_allowlist_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let mut accepted_lanes = BTreeSet::new();
        accepted_lanes.insert(LiquidityLane::MoneroPrivateTransfer);
        accepted_lanes.insert(LiquidityLane::FastBridgeExit);
        accepted_lanes.insert(LiquidityLane::DexSwap);
        accepted_lanes.insert(LiquidityLane::MerchantBatch);
        accepted_lanes.insert(LiquidityLane::WalletSession);

        let mut accepted_fee_assets = BTreeSet::new();
        accepted_fee_assets.insert(DEVNET_FEE_ASSET_ID.to_string());
        accepted_fee_assets.insert("pxmr-l2-devnet".to_string());
        accepted_fee_assets.insert("pdusd-devnet".to_string());

        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            coupon_asset_id: DEVNET_COUPON_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            liquidity_rebate_bps: DEFAULT_LIQUIDITY_REBATE_BPS,
            min_sponsor_reserve_micro: DEFAULT_MIN_SPONSOR_RESERVE_MICRO,
            batch_target_blocks: DEFAULT_BATCH_TARGET_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redemption_finality_blocks: DEFAULT_REDEMPTION_FINALITY_BLOCKS,
            throttle_window_blocks: DEFAULT_THROTTLE_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            wallet_cap_micro: DEFAULT_WALLET_CAP_MICRO,
            sponsor_batch_cap_micro: DEFAULT_SPONSOR_BATCH_CAP_MICRO,
            max_coupons_per_batch: DEFAULT_MAX_COUPONS_PER_BATCH,
            max_sponsors_per_batch: DEFAULT_MAX_SPONSORS_PER_BATCH,
            max_redactions_per_window: DEFAULT_MAX_REDACTIONS_PER_WINDOW,
            operator_summary_limit: DEFAULT_OPERATOR_SUMMARY_LIMIT,
            accepted_lanes,
            accepted_fee_assets,
            sponsor_allowlist_root: root_from_values("devnet-sponsor-allowlist", &[]),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(self.chain_id == CHAIN_ID, "config chain id mismatch")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below policy",
        )?;
        require(
            self.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE,
            "privacy set below policy",
        )?;
        require(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target fee above max fee",
        )?;
        require(
            self.max_user_fee_bps <= MAX_BPS,
            "max user fee above bps range",
        )?;
        require(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover above bps range",
        )?;
        require(
            self.liquidity_rebate_bps <= MAX_BPS,
            "liquidity rebate above bps range",
        )?;
        require(
            !self.accepted_lanes.is_empty(),
            "no accepted liquidity lanes configured",
        )?;
        require(
            !self.accepted_fee_assets.is_empty(),
            "no accepted fee assets configured",
        )?;
        require(self.max_coupons_per_batch > 0, "batch coupon limit is zero")?;
        require(
            self.max_sponsors_per_batch > 0,
            "batch sponsor limit is zero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "devnet_height": self.devnet_height,
            "devnet_epoch": self.devnet_epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "liquidity_rebate_bps": self.liquidity_rebate_bps,
            "batch_target_blocks": self.batch_target_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "redemption_finality_blocks": self.redemption_finality_blocks,
            "throttle_window_blocks": self.throttle_window_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "max_coupons_per_batch": self.max_coupons_per_batch,
            "max_sponsors_per_batch": self.max_sponsors_per_batch,
            "operator_summary_limit": self.operator_summary_limit,
            "accepted_lanes": self.accepted_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "accepted_fee_assets": self.accepted_fee_assets,
            "sponsor_allowlist_root": self.sponsor_allowlist_root,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub coupon_books: u64,
    pub liquidity_sponsors: u64,
    pub batch_redemptions: u64,
    pub pq_attestations: u64,
    pub fee_rebates: u64,
    pub throttles: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub issued_coupon_notes: u64,
    pub redeemed_coupon_notes: u64,
    pub total_rebate_micro: u64,
    pub total_sponsored_fee_micro: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_books": self.coupon_books,
            "liquidity_sponsors": self.liquidity_sponsors,
            "batch_redemptions": self.batch_redemptions,
            "pq_attestations": self.pq_attestations,
            "fee_rebates": self.fee_rebates,
            "throttles": self.throttles,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "issued_coupon_notes": self.issued_coupon_notes,
            "redeemed_coupon_notes": self.redeemed_coupon_notes,
            "total_rebate_micro": self.total_rebate_micro,
            "total_sponsored_fee_micro": self.total_sponsored_fee_micro,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub coupon_books_root: String,
    pub liquidity_sponsors_root: String,
    pub batch_redemptions_root: String,
    pub pq_attestations_root: String,
    pub fee_rebates_root: String,
    pub throttles_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = root_from_values("empty", &[]);
        Self {
            config_root: empty.clone(),
            counters_root: empty.clone(),
            coupon_books_root: empty.clone(),
            liquidity_sponsors_root: empty.clone(),
            batch_redemptions_root: empty.clone(),
            pq_attestations_root: empty.clone(),
            fee_rebates_root: empty.clone(),
            throttles_root: empty.clone(),
            redaction_budgets_root: empty.clone(),
            operator_summaries_root: empty.clone(),
            state_root: empty,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "coupon_books_root": self.coupon_books_root,
            "liquidity_sponsors_root": self.liquidity_sponsors_root,
            "batch_redemptions_root": self.batch_redemptions_root,
            "pq_attestations_root": self.pq_attestations_root,
            "fee_rebates_root": self.fee_rebates_root,
            "throttles_root": self.throttles_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "state_root": self.state_root,
        })
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponBookRequest {
    pub sponsor_id: String,
    pub lane: LiquidityLane,
    pub book_label_commitment: String,
    pub coupon_note_root: String,
    pub issuer_view_tag_root: String,
    pub max_coupon_notes: u64,
    pub max_notional_micro: u64,
    pub user_fee_bps: u64,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponBookRecord {
    pub book_id: String,
    pub sponsor_id: String,
    pub lane: LiquidityLane,
    pub book_label_commitment: String,
    pub coupon_note_root: String,
    pub issuer_view_tag_root: String,
    pub issued_note_count: u64,
    pub redeemed_note_count: u64,
    pub max_coupon_notes: u64,
    pub max_notional_commitment: String,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub status: CouponBookStatus,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub last_attestation_id: Option<String>,
}

impl CouponBookRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "sponsor_id": self.sponsor_id,
            "lane": self.lane.as_str(),
            "book_label_commitment": self.book_label_commitment,
            "coupon_note_root": self.coupon_note_root,
            "issuer_view_tag_root": self.issuer_view_tag_root,
            "issued_note_count": self.issued_note_count,
            "redeemed_note_count": self.redeemed_note_count,
            "max_coupon_notes": self.max_coupon_notes,
            "max_notional_commitment": self.max_notional_commitment,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "status": self.status.as_str(),
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "last_attestation_id": self.last_attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquiditySponsorRequest {
    pub sponsor_namespace: String,
    pub sponsor_commitment: String,
    pub reserve_commitment_root: String,
    pub liquidity_asset_root: String,
    pub max_batch_cover_micro: u64,
    pub reserve_floor_micro: u64,
    pub pq_key_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquiditySponsorRecord {
    pub sponsor_id: String,
    pub sponsor_namespace: String,
    pub sponsor_commitment: String,
    pub reserve_commitment_root: String,
    pub liquidity_asset_root: String,
    pub max_batch_cover_micro: u64,
    pub reserve_floor_commitment: String,
    pub consumed_cover_micro: u64,
    pub pq_key_commitment: String,
    pub status: SponsorStatus,
    pub activated_at_height: u64,
    pub last_attestation_id: Option<String>,
}

impl LiquiditySponsorRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_namespace": self.sponsor_namespace,
            "sponsor_commitment": self.sponsor_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "liquidity_asset_root": self.liquidity_asset_root,
            "max_batch_cover_micro": self.max_batch_cover_micro,
            "reserve_floor_commitment": self.reserve_floor_commitment,
            "consumed_cover_micro": self.consumed_cover_micro,
            "pq_key_commitment": self.pq_key_commitment,
            "status": self.status.as_str(),
            "activated_at_height": self.activated_at_height,
            "last_attestation_id": self.last_attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRedemptionRequest {
    pub book_id: String,
    pub sponsor_id: String,
    pub coupon_nullifier_root: String,
    pub redemption_note_root: String,
    pub accounting_balance_commitment: String,
    pub coupon_count: u64,
    pub gross_fee_micro: u64,
    pub requested_rebate_micro: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRedemptionRecord {
    pub batch_id: String,
    pub book_id: String,
    pub sponsor_id: String,
    pub coupon_nullifier_root: String,
    pub redemption_note_root: String,
    pub accounting_balance_commitment: String,
    pub coupon_count: u64,
    pub gross_fee_micro: u64,
    pub sponsored_fee_micro: u64,
    pub requested_rebate_micro: u64,
    pub status: RedemptionStatus,
    pub proposed_at_height: u64,
    pub target_settlement_height: u64,
    pub settled_at_height: Option<u64>,
    pub attestation_id: Option<String>,
}

impl BatchRedemptionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "book_id": self.book_id,
            "sponsor_id": self.sponsor_id,
            "coupon_nullifier_root": self.coupon_nullifier_root,
            "redemption_note_root": self.redemption_note_root,
            "accounting_balance_commitment": self.accounting_balance_commitment,
            "coupon_count": self.coupon_count,
            "gross_fee_micro": self.gross_fee_micro,
            "sponsored_fee_micro": self.sponsored_fee_micro,
            "requested_rebate_micro": self.requested_rebate_micro,
            "status": self.status.as_str(),
            "proposed_at_height": self.proposed_at_height,
            "target_settlement_height": self.target_settlement_height,
            "settled_at_height": self.settled_at_height,
            "attestation_id": self.attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub purpose: AttestationPurpose,
    pub subject_id: String,
    pub sponsor_id: String,
    pub attested_record_root: String,
    pub pq_key_commitment: String,
    pub signature_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub verdict: AttestationVerdict,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "purpose": self.purpose.as_str(),
            "subject_id": self.subject_id,
            "sponsor_id": self.sponsor_id,
            "attested_record_root": self.attested_record_root,
            "pq_key_commitment": self.pq_key_commitment,
            "signature_commitment": self.signature_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "verdict": self.verdict.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub batch_id: String,
    pub book_id: String,
    pub sponsor_id: String,
    pub recipient_commitment: String,
    pub rebate_commitment: String,
    pub rebate_micro: u64,
    pub status: RebateStatus,
    pub queued_at_height: u64,
    pub paid_at_height: Option<u64>,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "book_id": self.book_id,
            "sponsor_id": self.sponsor_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_micro": self.rebate_micro,
            "status": self.status.as_str(),
            "queued_at_height": self.queued_at_height,
            "paid_at_height": self.paid_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseThrottleRecord {
    pub throttle_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub sponsor_id: Option<String>,
    pub lane: Option<LiquidityLane>,
    pub nullifier_root: String,
    pub severity: AbuseSeverity,
    pub status: ThrottleStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub allowed_coupon_count: u64,
    pub observed_coupon_count: u64,
    pub slash_bps: u64,
}

impl AbuseThrottleRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "throttle_id": self.throttle_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "sponsor_id": self.sponsor_id,
            "lane": self.lane.map(|lane| lane.as_str()),
            "nullifier_root": self.nullifier_root,
            "severity_slash_bps": self.severity.slash_bps(),
            "status": self.status.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "allowed_coupon_count": self.allowed_coupon_count,
            "observed_coupon_count": self.observed_coupon_count,
            "slash_bps": self.slash_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRecord {
    pub budget_id: String,
    pub auditor_commitment: String,
    pub subject_id: String,
    pub purpose: AttestationPurpose,
    pub disclosure_root: String,
    pub max_redactions: u32,
    pub used_redactions: u32,
    pub window_start_height: u64,
    pub window_end_height: u64,
}

impl RedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "auditor_commitment": self.auditor_commitment,
            "subject_id": self.subject_id,
            "purpose": self.purpose.as_str(),
            "disclosure_root": self.disclosure_root,
            "max_redactions": self.max_redactions,
            "used_redactions": self.used_redactions,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub height: u64,
    pub epoch: u64,
    pub coupon_books_root: String,
    pub liquidity_sponsors_root: String,
    pub batch_redemptions_root: String,
    pub fee_rebates_root: String,
    pub throttles_root: String,
    pub open_books: u64,
    pub active_sponsors: u64,
    pub pending_batches: u64,
    pub target_user_fee_bps: u64,
    pub observed_rebate_micro: u64,
}

impl OperatorSummaryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "height": self.height,
            "epoch": self.epoch,
            "coupon_books_root": self.coupon_books_root,
            "liquidity_sponsors_root": self.liquidity_sponsors_root,
            "batch_redemptions_root": self.batch_redemptions_root,
            "fee_rebates_root": self.fee_rebates_root,
            "throttles_root": self.throttles_root,
            "open_books": self.open_books,
            "active_sponsors": self.active_sponsors,
            "pending_batches": self.pending_batches,
            "target_user_fee_bps": self.target_user_fee_bps,
            "observed_rebate_micro": self.observed_rebate_micro,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_epoch: u64,
    pub coupon_books: BTreeMap<String, CouponBookRecord>,
    pub liquidity_sponsors: BTreeMap<String, LiquiditySponsorRecord>,
    pub batch_redemptions: BTreeMap<String, BatchRedemptionRecord>,
    pub pq_attestations: BTreeMap<String, PqAttestationRecord>,
    pub fee_rebates: BTreeMap<String, FeeRebateRecord>,
    pub throttles: BTreeMap<String, AbuseThrottleRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            current_height: config.devnet_height,
            current_epoch: config.devnet_epoch,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            coupon_books: BTreeMap::new(),
            liquidity_sponsors: BTreeMap::new(),
            batch_redemptions: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            throttles: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("valid devnet batch liquidity coupon config")
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let sponsor_id = state
            .register_liquidity_sponsor(LiquiditySponsorRequest {
                sponsor_namespace: "devnet-liquidity-sponsor-a".to_string(),
                sponsor_commitment: "commitment:sponsor-a".to_string(),
                reserve_commitment_root: root_from_values("demo-reserve", &[]),
                liquidity_asset_root: root_from_values("demo-liquidity-assets", &[]),
                max_batch_cover_micro: 120_000_000,
                reserve_floor_micro: DEFAULT_MIN_SPONSOR_RESERVE_MICRO,
                pq_key_commitment: "pq-key:sponsor-a".to_string(),
            })
            .expect("demo sponsor registration");
        let _sponsor_attestation = state
            .record_pq_attestation(
                AttestationPurpose::SponsorOnboarding,
                sponsor_id.clone(),
                sponsor_id.clone(),
                "pq-sig:sponsor-a".to_string(),
                DEFAULT_MIN_PRIVACY_SET_SIZE,
                DEFAULT_MIN_PQ_SECURITY_BITS,
                AttestationVerdict::Approved,
            )
            .expect("demo sponsor attestation");
        let book_id = state
            .open_coupon_book(CouponBookRequest {
                sponsor_id: sponsor_id.clone(),
                lane: LiquidityLane::FastBridgeExit,
                book_label_commitment: "book:fast-exit-devnet".to_string(),
                coupon_note_root: root_from_values("demo-coupon-notes", &[]),
                issuer_view_tag_root: root_from_values("demo-view-tags", &[]),
                max_coupon_notes: 8_192,
                max_notional_micro: 60_000_000,
                user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
                opens_at_height: state.current_height,
                expires_at_height: state.current_height + DEFAULT_COUPON_TTL_BLOCKS,
            })
            .expect("demo coupon book");
        let _book_attestation = state
            .record_pq_attestation(
                AttestationPurpose::CouponIssuance,
                book_id.clone(),
                sponsor_id.clone(),
                "pq-sig:book".to_string(),
                DEFAULT_MIN_PRIVACY_SET_SIZE,
                DEFAULT_MIN_PQ_SECURITY_BITS,
                AttestationVerdict::Approved,
            )
            .expect("demo book attestation");
        let batch_id = state
            .propose_batch_redemption(BatchRedemptionRequest {
                book_id: book_id.clone(),
                sponsor_id: sponsor_id.clone(),
                coupon_nullifier_root: root_from_values("demo-nullifiers", &[]),
                redemption_note_root: root_from_values("demo-redemption-notes", &[]),
                accounting_balance_commitment: "balance:demo-batch".to_string(),
                coupon_count: 512,
                gross_fee_micro: 120_000,
                requested_rebate_micro: 18_000,
            })
            .expect("demo batch redemption");
        let _batch_attestation = state
            .record_pq_attestation(
                AttestationPurpose::BatchRedemption,
                batch_id.clone(),
                sponsor_id.clone(),
                "pq-sig:batch".to_string(),
                DEFAULT_MIN_PRIVACY_SET_SIZE,
                DEFAULT_MIN_PQ_SECURITY_BITS,
                AttestationVerdict::Approved,
            )
            .expect("demo batch attestation");
        let _rebate = state
            .queue_fee_rebate(
                &batch_id,
                "recipient:demo-wallet".to_string(),
                "rebate:demo-commitment".to_string(),
            )
            .expect("demo fee rebate");
        state
            .issue_redaction_budget(
                "auditor:devnet".to_string(),
                batch_id.clone(),
                AttestationPurpose::RedactionDisclosure,
                root_from_values("demo-disclosure", &[]),
            )
            .expect("demo redaction budget");
        state
            .publish_operator_summary()
            .expect("demo operator summary");
        state
    }

    pub fn register_liquidity_sponsor(
        &mut self,
        request: LiquiditySponsorRequest,
    ) -> Result<String> {
        require(
            self.liquidity_sponsors.len() < MAX_LIQUIDITY_SPONSORS,
            "liquidity sponsor capacity reached",
        )?;
        require(
            request.reserve_floor_micro >= self.config.min_sponsor_reserve_micro,
            "sponsor reserve below floor",
        )?;
        let sponsor_id = record_id(
            "SPONSOR",
            &request.sponsor_namespace,
            self.counters.liquidity_sponsors + 1,
        );
        let record = LiquiditySponsorRecord {
            sponsor_id: sponsor_id.clone(),
            sponsor_namespace: request.sponsor_namespace,
            sponsor_commitment: request.sponsor_commitment,
            reserve_commitment_root: request.reserve_commitment_root,
            liquidity_asset_root: request.liquidity_asset_root,
            max_batch_cover_micro: request.max_batch_cover_micro,
            reserve_floor_commitment: commitment_from_amount(
                "sponsor-reserve-floor",
                request.reserve_floor_micro,
            ),
            consumed_cover_micro: 0,
            pq_key_commitment: request.pq_key_commitment,
            status: SponsorStatus::Reserved,
            activated_at_height: self.current_height,
            last_attestation_id: None,
        };
        self.counters.liquidity_sponsors += 1;
        self.liquidity_sponsors.insert(sponsor_id.clone(), record);
        self.refresh_roots();
        Ok(sponsor_id)
    }

    pub fn open_coupon_book(&mut self, request: CouponBookRequest) -> Result<String> {
        require(
            self.coupon_books.len() < MAX_COUPON_BOOKS,
            "coupon book capacity reached",
        )?;
        require(
            self.config.accepted_lanes.contains(&request.lane),
            "liquidity lane not accepted",
        )?;
        require(
            request.user_fee_bps <= self.config.max_user_fee_bps,
            "coupon user fee above cap",
        )?;
        require(request.max_coupon_notes > 0, "coupon note cap is zero")?;
        require(
            request.expires_at_height > request.opens_at_height,
            "coupon book expiry before open",
        )?;
        let sponsor = self
            .liquidity_sponsors
            .get(&request.sponsor_id)
            .ok_or_else(|| "sponsor not found".to_string())?;
        require(sponsor.status.can_issue(), "sponsor cannot issue coupons")?;
        let book_id = record_id(
            "COUPON-BOOK",
            &request.book_label_commitment,
            self.counters.coupon_books + 1,
        );
        let record = CouponBookRecord {
            book_id: book_id.clone(),
            sponsor_id: request.sponsor_id,
            lane: request.lane,
            book_label_commitment: request.book_label_commitment,
            coupon_note_root: request.coupon_note_root,
            issuer_view_tag_root: request.issuer_view_tag_root,
            issued_note_count: 0,
            redeemed_note_count: 0,
            max_coupon_notes: request.max_coupon_notes,
            max_notional_commitment: commitment_from_amount(
                "coupon-book-max-notional",
                request.max_notional_micro,
            ),
            user_fee_bps: request.user_fee_bps,
            sponsor_cover_bps: self.config.sponsor_cover_bps,
            status: CouponBookStatus::Open,
            opens_at_height: request.opens_at_height,
            expires_at_height: request.expires_at_height,
            last_attestation_id: None,
        };
        self.counters.coupon_books += 1;
        self.coupon_books.insert(book_id.clone(), record);
        self.refresh_roots();
        Ok(book_id)
    }

    pub fn record_pq_attestation(
        &mut self,
        purpose: AttestationPurpose,
        subject_id: String,
        sponsor_id: String,
        signature_commitment: String,
        privacy_set_size: u64,
        pq_security_bits: u16,
        verdict: AttestationVerdict,
    ) -> Result<String> {
        require(
            self.pq_attestations.len() < MAX_PQ_ATTESTATIONS,
            "pq attestation capacity reached",
        )?;
        require(
            privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below policy",
        )?;
        require(
            pq_security_bits >= self.config.min_pq_security_bits,
            "pq security below policy",
        )?;
        let sponsor = self
            .liquidity_sponsors
            .get(&sponsor_id)
            .ok_or_else(|| "sponsor not found".to_string())?;
        let subject_root = subject_record_root(self, &subject_id);
        let attestation_id = record_id(
            "PQ-ATTESTATION",
            &subject_id,
            self.counters.pq_attestations + 1,
        );
        let record = PqAttestationRecord {
            attestation_id: attestation_id.clone(),
            purpose,
            subject_id: subject_id.clone(),
            sponsor_id: sponsor_id.clone(),
            attested_record_root: subject_root,
            pq_key_commitment: sponsor.pq_key_commitment.clone(),
            signature_commitment,
            privacy_set_size,
            pq_security_bits,
            verdict,
            issued_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.attestation_ttl_blocks,
        };
        self.counters.pq_attestations += 1;
        self.pq_attestations.insert(attestation_id.clone(), record);
        if verdict.approves() {
            if let Some(sponsor) = self.liquidity_sponsors.get_mut(&sponsor_id) {
                sponsor.status = SponsorStatus::Active;
                sponsor.last_attestation_id = Some(attestation_id.clone());
            }
            if let Some(book) = self.coupon_books.get_mut(&subject_id) {
                book.status = CouponBookStatus::Issuing;
                book.last_attestation_id = Some(attestation_id.clone());
            }
            if let Some(batch) = self.batch_redemptions.get_mut(&subject_id) {
                batch.status = RedemptionStatus::Attested;
                batch.attestation_id = Some(attestation_id.clone());
            }
        }
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn propose_batch_redemption(&mut self, request: BatchRedemptionRequest) -> Result<String> {
        require(
            self.batch_redemptions.len() < MAX_BATCH_REDEMPTIONS,
            "batch redemption capacity reached",
        )?;
        require(
            request.coupon_count > 0
                && request.coupon_count as usize <= self.config.max_coupons_per_batch,
            "coupon count outside batch policy",
        )?;
        let book = self
            .coupon_books
            .get(&request.book_id)
            .ok_or_else(|| "coupon book not found".to_string())?;
        require(book.status.accepts_issuance(), "coupon book not issuing")?;
        require(
            book.sponsor_id == request.sponsor_id,
            "sponsor/book mismatch",
        )?;
        require(
            book.issued_note_count + request.coupon_count <= book.max_coupon_notes,
            "coupon book note cap exceeded",
        )?;
        let sponsor = self
            .liquidity_sponsors
            .get(&request.sponsor_id)
            .ok_or_else(|| "sponsor not found".to_string())?;
        require(
            sponsor.status.can_issue(),
            "sponsor cannot cover redemption",
        )?;
        let sponsored_fee_micro =
            bps_amount(request.gross_fee_micro, self.config.sponsor_cover_bps);
        require(
            sponsored_fee_micro <= self.config.sponsor_batch_cap_micro,
            "sponsored fee exceeds batch cap",
        )?;
        require(
            sponsor.consumed_cover_micro + sponsored_fee_micro <= sponsor.max_batch_cover_micro,
            "sponsor cover exhausted",
        )?;
        let batch_id = record_id(
            "BATCH-REDEMPTION",
            &request.coupon_nullifier_root,
            self.counters.batch_redemptions + 1,
        );
        let record = BatchRedemptionRecord {
            batch_id: batch_id.clone(),
            book_id: request.book_id.clone(),
            sponsor_id: request.sponsor_id.clone(),
            coupon_nullifier_root: request.coupon_nullifier_root,
            redemption_note_root: request.redemption_note_root,
            accounting_balance_commitment: request.accounting_balance_commitment,
            coupon_count: request.coupon_count,
            gross_fee_micro: request.gross_fee_micro,
            sponsored_fee_micro,
            requested_rebate_micro: request.requested_rebate_micro,
            status: RedemptionStatus::Proposed,
            proposed_at_height: self.current_height,
            target_settlement_height: self.current_height + self.config.batch_target_blocks,
            settled_at_height: None,
            attestation_id: None,
        };
        self.counters.batch_redemptions += 1;
        self.counters.issued_coupon_notes += request.coupon_count;
        self.counters.total_sponsored_fee_micro += sponsored_fee_micro;
        if let Some(book) = self.coupon_books.get_mut(&request.book_id) {
            book.issued_note_count += request.coupon_count;
            book.status = CouponBookStatus::Redeeming;
        }
        if let Some(sponsor) = self.liquidity_sponsors.get_mut(&request.sponsor_id) {
            sponsor.consumed_cover_micro += sponsored_fee_micro;
        }
        self.batch_redemptions.insert(batch_id.clone(), record);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn settle_batch_redemption(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .batch_redemptions
            .get_mut(batch_id)
            .ok_or_else(|| "batch redemption not found".to_string())?;
        require(
            matches!(
                batch.status,
                RedemptionStatus::Attested | RedemptionStatus::Netting
            ),
            "batch not ready for settlement",
        )?;
        batch.status = RedemptionStatus::Settled;
        batch.settled_at_height =
            Some(self.current_height + self.config.redemption_finality_blocks);
        self.counters.redeemed_coupon_notes += batch.coupon_count;
        if let Some(book) = self.coupon_books.get_mut(&batch.book_id) {
            book.redeemed_note_count += batch.coupon_count;
            if book.redeemed_note_count >= book.issued_note_count {
                book.status = CouponBookStatus::Settled;
            }
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn queue_fee_rebate(
        &mut self,
        batch_id: &str,
        recipient_commitment: String,
        rebate_commitment: String,
    ) -> Result<String> {
        require(
            self.fee_rebates.len() < MAX_FEE_REBATES,
            "fee rebate capacity reached",
        )?;
        let batch = self
            .batch_redemptions
            .get(batch_id)
            .ok_or_else(|| "batch redemption not found".to_string())?;
        let rebate_micro = batch.requested_rebate_micro.min(bps_amount(
            batch.gross_fee_micro,
            self.config.liquidity_rebate_bps,
        ));
        let rebate_id = record_id("FEE-REBATE", batch_id, self.counters.fee_rebates + 1);
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            batch_id: batch_id.to_string(),
            book_id: batch.book_id.clone(),
            sponsor_id: batch.sponsor_id.clone(),
            recipient_commitment,
            rebate_commitment,
            rebate_micro,
            status: RebateStatus::Queued,
            queued_at_height: self.current_height,
            paid_at_height: None,
        };
        self.counters.fee_rebates += 1;
        self.counters.total_rebate_micro += rebate_micro;
        self.fee_rebates.insert(rebate_id.clone(), record);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn apply_throttle(
        &mut self,
        subject_id: String,
        subject_kind: String,
        sponsor_id: Option<String>,
        lane: Option<LiquidityLane>,
        nullifier_root: String,
        severity: AbuseSeverity,
        observed_coupon_count: u64,
    ) -> Result<String> {
        require(
            self.throttles.len() < MAX_THROTTLES,
            "throttle capacity reached",
        )?;
        let throttle_id = record_id("THROTTLE", &subject_id, self.counters.throttles + 1);
        let slash_bps = severity.slash_bps();
        let record = AbuseThrottleRecord {
            throttle_id: throttle_id.clone(),
            subject_id,
            subject_kind,
            sponsor_id: sponsor_id.clone(),
            lane,
            nullifier_root,
            severity,
            status: ThrottleStatus::Active,
            window_start_height: self.current_height,
            window_end_height: self.current_height + self.config.throttle_window_blocks,
            allowed_coupon_count: self.config.max_coupons_per_batch as u64,
            observed_coupon_count,
            slash_bps,
        };
        if let Some(sponsor_id) = sponsor_id {
            if let Some(sponsor) = self.liquidity_sponsors.get_mut(&sponsor_id) {
                sponsor.status = if slash_bps > 0 {
                    SponsorStatus::Throttled
                } else {
                    sponsor.status
                };
            }
        }
        self.counters.throttles += 1;
        self.throttles.insert(throttle_id.clone(), record);
        self.refresh_roots();
        Ok(throttle_id)
    }

    pub fn issue_redaction_budget(
        &mut self,
        auditor_commitment: String,
        subject_id: String,
        purpose: AttestationPurpose,
        disclosure_root: String,
    ) -> Result<String> {
        require(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity reached",
        )?;
        let budget_id = record_id(
            "REDACTION-BUDGET",
            &subject_id,
            self.counters.redaction_budgets + 1,
        );
        let record = RedactionBudgetRecord {
            budget_id: budget_id.clone(),
            auditor_commitment,
            subject_id,
            purpose,
            disclosure_root,
            max_redactions: self.config.max_redactions_per_window,
            used_redactions: 0,
            window_start_height: self.current_height,
            window_end_height: self.current_height + self.config.redaction_window_blocks,
        };
        self.counters.redaction_budgets += 1;
        self.redaction_budgets.insert(budget_id.clone(), record);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(&mut self) -> Result<String> {
        require(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity reached",
        )?;
        self.refresh_roots();
        let open_books = self
            .coupon_books
            .values()
            .filter(|book| book.status.accepts_issuance() || book.status.accepts_redemption())
            .count() as u64;
        let active_sponsors = self
            .liquidity_sponsors
            .values()
            .filter(|sponsor| sponsor.status.can_issue())
            .count() as u64;
        let pending_batches = self
            .batch_redemptions
            .values()
            .filter(|batch| {
                matches!(
                    batch.status,
                    RedemptionStatus::Proposed
                        | RedemptionStatus::Attested
                        | RedemptionStatus::Netting
                )
            })
            .count() as u64;
        let summary_id = record_id(
            "OPERATOR-SUMMARY",
            &self.current_height.to_string(),
            self.counters.operator_summaries + 1,
        );
        let record = OperatorSummaryRecord {
            summary_id: summary_id.clone(),
            height: self.current_height,
            epoch: self.current_epoch,
            coupon_books_root: self.roots.coupon_books_root.clone(),
            liquidity_sponsors_root: self.roots.liquidity_sponsors_root.clone(),
            batch_redemptions_root: self.roots.batch_redemptions_root.clone(),
            fee_rebates_root: self.roots.fee_rebates_root.clone(),
            throttles_root: self.roots.throttles_root.clone(),
            open_books,
            active_sponsors,
            pending_batches,
            target_user_fee_bps: self.config.target_user_fee_bps,
            observed_rebate_micro: self.counters.total_rebate_micro,
        };
        self.counters.operator_summaries += 1;
        self.operator_summaries.insert(summary_id.clone(), record);
        self.prune_operator_summaries();
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_batch_liquidity_coupon_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = root_from_record("CONFIG", &self.config.public_record());
        self.roots.counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        self.roots.coupon_books_root = map_root(
            COUPON_BOOK_SCHEME,
            self.coupon_books
                .values()
                .map(CouponBookRecord::public_record),
        );
        self.roots.liquidity_sponsors_root = map_root(
            LIQUIDITY_SPONSOR_SCHEME,
            self.liquidity_sponsors
                .values()
                .map(LiquiditySponsorRecord::public_record),
        );
        self.roots.batch_redemptions_root = map_root(
            BATCH_REDEMPTION_SCHEME,
            self.batch_redemptions
                .values()
                .map(BatchRedemptionRecord::public_record),
        );
        self.roots.pq_attestations_root = map_root(
            PQ_ATTESTATION_SCHEME,
            self.pq_attestations
                .values()
                .map(PqAttestationRecord::public_record),
        );
        self.roots.fee_rebates_root = map_root(
            FEE_REBATE_SCHEME,
            self.fee_rebates
                .values()
                .map(FeeRebateRecord::public_record),
        );
        self.roots.throttles_root = map_root(
            THROTTLE_SCHEME,
            self.throttles
                .values()
                .map(AbuseThrottleRecord::public_record),
        );
        self.roots.redaction_budgets_root = map_root(
            REDACTION_BUDGET_SCHEME,
            self.redaction_budgets
                .values()
                .map(RedactionBudgetRecord::public_record),
        );
        self.roots.operator_summaries_root = map_root(
            OPERATOR_SUMMARY_SCHEME,
            self.operator_summaries
                .values()
                .map(OperatorSummaryRecord::public_record),
        );
        let record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "roots": {
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "coupon_books_root": self.roots.coupon_books_root,
                "liquidity_sponsors_root": self.roots.liquidity_sponsors_root,
                "batch_redemptions_root": self.roots.batch_redemptions_root,
                "pq_attestations_root": self.roots.pq_attestations_root,
                "fee_rebates_root": self.roots.fee_rebates_root,
                "throttles_root": self.roots.throttles_root,
                "redaction_budgets_root": self.roots.redaction_budgets_root,
                "operator_summaries_root": self.roots.operator_summaries_root,
            }
        });
        self.roots.state_root = root_from_record("STATE", &record);
    }

    fn prune_operator_summaries(&mut self) {
        while self.operator_summaries.len() > self.config.operator_summary_limit {
            if let Some(first_key) = self.operator_summaries.keys().next().cloned() {
                self.operator_summaries.remove(&first_key);
            } else {
                break;
            }
        }
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

pub fn coupon_book_root(book: &CouponBookRecord) -> String {
    root_from_record("COUPON-BOOK", &book.public_record())
}

pub fn liquidity_sponsor_root(sponsor: &LiquiditySponsorRecord) -> String {
    root_from_record("LIQUIDITY-SPONSOR", &sponsor.public_record())
}

pub fn batch_redemption_root(batch: &BatchRedemptionRecord) -> String {
    root_from_record("BATCH-REDEMPTION", &batch.public_record())
}

pub fn pq_attestation_root(attestation: &PqAttestationRecord) -> String {
    root_from_record("PQ-ATTESTATION", &attestation.public_record())
}

fn subject_record_root(state: &State, subject_id: &str) -> String {
    if let Some(book) = state.coupon_books.get(subject_id) {
        return coupon_book_root(book);
    }
    if let Some(sponsor) = state.liquidity_sponsors.get(subject_id) {
        return liquidity_sponsor_root(sponsor);
    }
    if let Some(batch) = state.batch_redemptions.get(subject_id) {
        return batch_redemption_root(batch);
    }
    root_from_record("UNKNOWN-SUBJECT", &json!({ "subject_id": subject_id }))
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn commitment_from_amount(domain: &str, amount: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-LIQUIDITY-COUPON:AMOUNT-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::U64(amount),
        ],
    )
}

fn record_id(kind: &str, subject: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-LIQUIDITY-COUPON:RECORD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(subject),
            HashPart::U64(sequence),
        ],
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &values)
}

fn root_from_values(domain: &str, leaves: &[Value]) -> String {
    let domain = format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-LIQUIDITY-COUPON:{domain}");
    merkle_root(&domain, leaves)
}

fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-LIQUIDITY-COUPON:RECORD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
    )
}
