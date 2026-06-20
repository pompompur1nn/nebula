use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateMerchantPaymentChannelRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-merchant-payment-channel-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_HEIGHT: u64 = 913_000;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_CHANNEL_BOOK: &str =
    "devnet-monero-l2-private-merchant-channel-book";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_MERCHANT_REGISTRY: &str =
    "devnet-monero-l2-private-merchant-registry";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_WATCHER_SET_ID: &str =
    "devnet-monero-l2-private-merchant-watchers";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MERCHANT_LANE_SCHEME: &str =
    "roots-only-private-merchant-lane-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_INVOICE_SCHEME: &str =
    "ml-kem-1024-encrypted-merchant-invoice-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_AUTHORIZATION_SCHEME: &str =
    "monero-ringct-payer-authorization-nullifier-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_RECEIPT_SCHEME: &str =
    "ml-dsa-87-pq-merchant-receipt-attestation-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_LIQUIDITY_SCHEME: &str =
    "low-fee-private-merchant-liquidity-reservation-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-private-merchant-sponsor-reservation-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_SETTLEMENT_SCHEME: &str =
    "fast-private-merchant-payment-settlement-batch-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_REBATE_SCHEME: &str =
    "private-merchant-low-fee-rebate-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DISPUTE_SCHEME: &str =
    "private-merchant-payment-dispute-window-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_PRIVACY_CHECK_SCHEME: &str =
    "monero-ringct-merchant-payment-privacy-set-check-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_REPLAY_FENCE_SCHEME: &str =
    "monero-l2-private-merchant-payment-replay-fence-root-v1";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-private-merchant-payment-channel-devnet";
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_INVOICE_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_AUTHORIZATION_TTL_BLOCKS: u64 =
    18;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 32;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    36;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 =
    6;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 =
    96;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS: u64 = 288;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 =
    131_072;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    192;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 =
    256;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MERCHANT_REBATE_BPS: u64 = 8;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 9_400;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_RESERVE_BPS: u64 = 10_500;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_TARGET_RESERVE_BPS: u64 =
    12_500;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MAX_LANE_IMBALANCE_BPS: u64 =
    120;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 512;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_MERCHANT_LANES: usize = 262_144;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_ENCRYPTED_INVOICES: usize =
    1_048_576;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_PAYER_AUTHORIZATIONS: usize =
    1_048_576;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_RECEIPT_ATTESTATIONS: usize =
    1_048_576;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_RESERVATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_SETTLEMENT_BATCHES: usize =
    524_288;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_REBATES: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_DISPUTES: usize = 524_288;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_PRIVACY_CHECKS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_REPLAY_FENCES: usize = 2_097_152;
pub const MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MerchantLaneKind {
    RetailTap,
    OnlineCheckout,
    Subscription,
    InvoiceOnly,
    BulkSettlement,
    EmergencyRefund,
}

impl MerchantLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailTap => "retail_tap",
            Self::OnlineCheckout => "online_checkout",
            Self::Subscription => "subscription",
            Self::InvoiceOnly => "invoice_only",
            Self::BulkSettlement => "bulk_settlement",
            Self::EmergencyRefund => "emergency_refund",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRefund => 10_000,
            Self::RetailTap => 9_600,
            Self::OnlineCheckout => 9_200,
            Self::Subscription => 8_300,
            Self::InvoiceOnly => 7_800,
            Self::BulkSettlement => 6_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSpeed {
    Instant,
    Fast,
    Standard,
    Bulk,
    Emergency,
}

impl PaymentSpeed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Bulk => "bulk",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::Bulk => config.low_fee_bps,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::Instant | Self::Fast | Self::Emergency => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Issued,
    PrivacyChecked,
    Authorized,
    Reserved,
    Receipted,
    Batched,
    Settled,
    Cancelled,
    Expired,
    Disputed,
}

impl InvoiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::PrivacyChecked => "privacy_checked",
            Self::Authorized => "authorized",
            Self::Reserved => "reserved",
            Self::Receipted => "receipted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Issued
                | Self::PrivacyChecked
                | Self::Authorized
                | Self::Reserved
                | Self::Receipted
                | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Submitted,
    RingChecked,
    NullifierLocked,
    Accepted,
    Consumed,
    Replayed,
    Expired,
    Rejected,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::RingChecked => "ring_checked",
            Self::NullifierLocked => "nullifier_locked",
            Self::Accepted => "accepted",
            Self::Consumed => "consumed",
            Self::Replayed => "replayed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Proposed,
    PqVerified,
    Published,
    Finalized,
    Disputed,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PqVerified => "pq_verified",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationKind {
    MerchantLiquidity,
    SponsorFee,
    RefundLiquidity,
    BatchSettlement,
    DisputeBond,
}

impl ReservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MerchantLiquidity => "merchant_liquidity",
            Self::SponsorFee => "sponsor_fee",
            Self::RefundLiquidity => "refund_liquidity",
            Self::BatchSettlement => "batch_settlement",
            Self::DisputeBond => "dispute_bond",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Open,
    Locked,
    Consumed,
    Released,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Sealed,
    Posted,
    Finalized,
    Disputed,
    RolledBack,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Posted => "posted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    EvidenceSubmitted,
    MerchantWon,
    PayerWon,
    TimedOut,
    Cancelled,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::MerchantWon => "merchant_won",
            Self::PayerWon => "payer_won",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub channel_book: String,
    pub merchant_registry: String,
    pub watcher_set_id: String,
    pub hash_suite: String,
    pub merchant_lane_scheme: String,
    pub invoice_scheme: String,
    pub authorization_scheme: String,
    pub receipt_scheme: String,
    pub liquidity_scheme: String,
    pub sponsor_scheme: String,
    pub settlement_scheme: String,
    pub rebate_scheme: String,
    pub dispute_scheme: String,
    pub privacy_check_scheme: String,
    pub replay_fence_scheme: String,
    pub replay_domain: String,
    pub genesis_height: u64,
    pub invoice_ttl_blocks: u64,
    pub authorization_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub dispute_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub merchant_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_reserve_bps: u64,
    pub target_reserve_bps: u64,
    pub max_lane_imbalance_bps: u64,
    pub max_batch_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_SCHEMA_VERSION,
            monero_network:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            l2_network: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            asset_id: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_ASSET_ID
                .to_string(),
            fee_asset_id: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            channel_book: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_CHANNEL_BOOK
                .to_string(),
            merchant_registry:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_MERCHANT_REGISTRY
                    .to_string(),
            watcher_set_id:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_WATCHER_SET_ID
                    .to_string(),
            hash_suite: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_HASH_SUITE.to_string(),
            merchant_lane_scheme:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MERCHANT_LANE_SCHEME
                    .to_string(),
            invoice_scheme: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_INVOICE_SCHEME
                .to_string(),
            authorization_scheme:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_AUTHORIZATION_SCHEME
                    .to_string(),
            receipt_scheme: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            liquidity_scheme: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_LIQUIDITY_SCHEME
                .to_string(),
            sponsor_scheme: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            settlement_scheme:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_SETTLEMENT_SCHEME.to_string(),
            rebate_scheme: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_REBATE_SCHEME
                .to_string(),
            dispute_scheme: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DISPUTE_SCHEME
                .to_string(),
            privacy_check_scheme:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_PRIVACY_CHECK_SCHEME
                    .to_string(),
            replay_fence_scheme:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_REPLAY_FENCE_SCHEME.to_string(),
            replay_domain: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_REPLAY_DOMAIN
                .to_string(),
            genesis_height: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEVNET_HEIGHT,
            invoice_ttl_blocks:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_INVOICE_TTL_BLOCKS,
            authorization_ttl_blocks:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_AUTHORIZATION_TTL_BLOCKS,
            receipt_ttl_blocks:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_window_blocks:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            dispute_window_blocks:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            rebate_ttl_blocks:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            merchant_rebate_bps:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MERCHANT_REBATE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            min_reserve_bps:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MIN_RESERVE_BPS,
            target_reserve_bps:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_TARGET_RESERVE_BPS,
            max_lane_imbalance_bps:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MAX_LANE_IMBALANCE_BPS,
            max_batch_items:
                MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
        }
    }

    pub fn validate(&self) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("private merchant channel config chain id mismatch".to_string());
        }
        if self.schema_version == 0 {
            return Err("private merchant channel schema version must be non-zero".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
            || self.min_batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("private merchant channel privacy set thresholds are invalid".to_string());
        }
        if self.min_pq_security_bits < 128
            || self.target_pq_security_bits < self.min_pq_security_bits
        {
            return Err("private merchant channel pq security threshold is too low".to_string());
        }
        for (name, value) in [
            ("low_fee_bps", self.low_fee_bps),
            ("max_user_fee_bps", self.max_user_fee_bps),
            ("merchant_rebate_bps", self.merchant_rebate_bps),
            ("sponsor_cover_bps", self.sponsor_cover_bps),
            ("min_reserve_bps", self.min_reserve_bps),
            ("target_reserve_bps", self.target_reserve_bps),
            ("max_lane_imbalance_bps", self.max_lane_imbalance_bps),
        ] {
            if value > MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_BPS * 2 {
                return Err(format!("private merchant channel {name} is out of range"));
            }
        }
        if self.low_fee_bps > self.max_user_fee_bps {
            return Err("private merchant channel low fee exceeds max user fee".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub merchant_lanes: u64,
    pub encrypted_invoices: u64,
    pub payer_authorizations: u64,
    pub receipt_attestations: u64,
    pub liquidity_reservations: u64,
    pub sponsor_reservations: u64,
    pub settlement_batches: u64,
    pub rebates: u64,
    pub disputes: u64,
    pub privacy_checks: u64,
    pub replay_fences: u64,
    pub public_records: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub merchant_lanes_root: String,
    pub encrypted_invoices_root: String,
    pub payer_authorizations_root: String,
    pub receipt_attestations_root: String,
    pub liquidity_reservations_root: String,
    pub sponsor_reservations_root: String,
    pub settlement_batches_root: String,
    pub rebates_root: String,
    pub disputes_root: String,
    pub privacy_checks_root: String,
    pub replay_fences_root: String,
    pub public_records_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MerchantLane {
    pub lane_id: String,
    pub merchant_commitment: String,
    pub lane_kind: MerchantLaneKind,
    pub lane_nonce: String,
    pub lane_epoch: u64,
    pub privacy_pool_id: String,
    pub encrypted_descriptor_root: String,
    pub settlement_address_commitment: String,
    pub min_invoice_amount_atomic: u64,
    pub max_invoice_amount_atomic: u64,
    pub reserved_liquidity_atomic: u64,
    pub spent_liquidity_atomic: u64,
    pub reserve_ratio_bps: u64,
    pub pq_attestation_key_root: String,
    pub created_height: u64,
}

impl MerchantLane {
    pub fn deterministic_id(
        merchant_commitment: &str,
        lane_nonce: &str,
        lane_epoch: u64,
    ) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:merchant-lane-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(merchant_commitment),
                HashPart::Str(lane_nonce),
                HashPart::Int(lane_epoch as i128),
            ],
            32,
        )
    }

    pub fn privacy_capacity_left(&self) -> u64 {
        self.reserved_liquidity_atomic
            .saturating_sub(self.spent_liquidity_atomic)
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "merchant_lane",
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "lane_epoch": self.lane_epoch,
            "privacy_pool_id": self.privacy_pool_id,
            "reserve_ratio_bps": self.reserve_ratio_bps,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedInvoice {
    pub invoice_id: String,
    pub lane_id: String,
    pub merchant_invoice_commitment: String,
    pub encrypted_invoice_blob_root: String,
    pub amount_commitment: String,
    pub amount_upper_bound_atomic: u64,
    pub fee_commitment: String,
    pub speed: PaymentSpeed,
    pub status: InvoiceStatus,
    pub issued_height: u64,
    pub expires_height: u64,
    pub payer_view_tag_root: String,
    pub merchant_refund_commitment: String,
    pub memo_ciphertext_root: String,
}

impl EncryptedInvoice {
    pub fn deterministic_id(lane_id: &str, merchant_invoice_commitment: &str) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:invoice-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane_id),
                HashPart::Str(merchant_invoice_commitment),
            ],
            32,
        )
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_height
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "encrypted_invoice",
            "invoice_id": self.invoice_id,
            "lane_id": self.lane_id,
            "speed": self.speed.as_str(),
            "status": self.status.as_str(),
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayerAuthorization {
    pub authorization_id: String,
    pub invoice_id: String,
    pub payer_commitment: String,
    pub ring_members_root: String,
    pub authorization_nullifier: String,
    pub replay_domain: String,
    pub max_amount_commitment: String,
    pub payer_fee_commitment: String,
    pub status: AuthorizationStatus,
    pub authorized_height: u64,
    pub expires_height: u64,
    pub pq_session_key_root: String,
}

impl PayerAuthorization {
    pub fn deterministic_id(invoice_id: &str, payer_commitment: &str, nullifier: &str) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:authorization-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(invoice_id),
                HashPart::Str(payer_commitment),
                HashPart::Str(nullifier),
            ],
            32,
        )
    }

    pub fn replay_key(&self) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:authorization-replay-key",
            &[
                HashPart::Str(&self.replay_domain),
                HashPart::Str(&self.authorization_nullifier),
            ],
            32,
        )
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "payer_authorization",
            "authorization_id": self.authorization_id,
            "invoice_id": self.invoice_id,
            "status": self.status.as_str(),
            "authorized_height": self.authorized_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptAttestation {
    pub receipt_id: String,
    pub invoice_id: String,
    pub authorization_id: String,
    pub lane_id: String,
    pub amount_commitment: String,
    pub merchant_receipt_commitment: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub status: ReceiptStatus,
    pub attested_height: u64,
    pub finality_height: u64,
}

impl PqReceiptAttestation {
    pub fn deterministic_id(
        invoice_id: &str,
        authorization_id: &str,
        receipt_commitment: &str,
    ) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:receipt-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(invoice_id),
                HashPart::Str(authorization_id),
                HashPart::Str(receipt_commitment),
            ],
            32,
        )
    }

    pub fn quantum_resistant(&self, config: &Config) -> bool {
        self.pq_security_bits >= config.min_pq_security_bits
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "pq_receipt_attestation",
            "receipt_id": self.receipt_id,
            "invoice_id": self.invoice_id,
            "lane_id": self.lane_id,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "attested_height": self.attested_height,
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Reservation {
    pub reservation_id: String,
    pub invoice_id: String,
    pub lane_id: String,
    pub kind: ReservationKind,
    pub status: ReservationStatus,
    pub amount_commitment: String,
    pub amount_upper_bound_atomic: u64,
    pub sponsor_commitment: Option<String>,
    pub reserve_ratio_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl Reservation {
    pub fn deterministic_id(
        invoice_id: &str,
        lane_id: &str,
        kind: ReservationKind,
        nonce: &str,
    ) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:reservation-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(invoice_id),
                HashPart::Str(lane_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(nonce),
            ],
            32,
        )
    }

    pub fn is_sponsor(&self) -> bool {
        matches!(self.kind, ReservationKind::SponsorFee)
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "reservation",
            "reservation_id": self.reservation_id,
            "invoice_id": self.invoice_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "reserve_ratio_bps": self.reserve_ratio_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub invoice_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub batch_amount_commitment: String,
    pub fee_commitment: String,
    pub privacy_set_size: u64,
    pub status: SettlementStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub settlement_root: String,
}

impl SettlementBatch {
    pub fn deterministic_id(lane_id: &str, opened_height: u64, invoice_ids: &[String]) -> String {
        let invoice_root = merkle_root(
            "monero-l2-private-merchant-payment-channel:batch-invoice-id-root",
            &invoice_ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
        );
        domain_hash(
            "monero-l2-private-merchant-payment-channel:settlement-batch-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane_id),
                HashPart::Int(opened_height as i128),
                HashPart::Str(&invoice_root),
            ],
            32,
        )
    }

    pub fn batch_full(&self, config: &Config) -> bool {
        self.invoice_ids.len() >= config.max_batch_items
    }

    pub fn privacy_ready(&self, config: &Config) -> bool {
        self.privacy_set_size >= config.min_batch_privacy_set_size
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "settlement_batch",
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "invoice_count": self.invoice_ids.len(),
            "receipt_count": self.receipt_ids.len(),
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub invoice_id: String,
    pub lane_id: String,
    pub payer_rebate_commitment: String,
    pub merchant_rebate_commitment: String,
    pub rebate_bps: u64,
    pub sponsor_commitment: Option<String>,
    pub issued_height: u64,
    pub expires_height: u64,
    pub claimed_nullifier: Option<String>,
}

impl Rebate {
    pub fn deterministic_id(
        invoice_id: &str,
        lane_id: &str,
        payer_rebate_commitment: &str,
    ) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:rebate-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(invoice_id),
                HashPart::Str(lane_id),
                HashPart::Str(payer_rebate_commitment),
            ],
            32,
        )
    }

    pub fn claimed(&self) -> bool {
        self.claimed_nullifier.is_some()
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "rebate",
            "rebate_id": self.rebate_id,
            "invoice_id": self.invoice_id,
            "lane_id": self.lane_id,
            "rebate_bps": self.rebate_bps,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "claimed": self.claimed(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Dispute {
    pub dispute_id: String,
    pub invoice_id: String,
    pub receipt_id: String,
    pub lane_id: String,
    pub dispute_nullifier: String,
    pub evidence_root: String,
    pub status: DisputeStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub bond_commitment: String,
}

impl Dispute {
    pub fn deterministic_id(invoice_id: &str, receipt_id: &str, dispute_nullifier: &str) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:dispute-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(invoice_id),
                HashPart::Str(receipt_id),
                HashPart::Str(dispute_nullifier),
            ],
            32,
        )
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "dispute",
            "dispute_id": self.dispute_id,
            "invoice_id": self.invoice_id,
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacySetCheck {
    pub check_id: String,
    pub subject_id: String,
    pub privacy_pool_id: String,
    pub ring_members_root: String,
    pub decoy_distribution_root: String,
    pub observed_privacy_set_size: u64,
    pub required_privacy_set_size: u64,
    pub pq_transcript_root: String,
    pub checked_height: u64,
}

impl PrivacySetCheck {
    pub fn deterministic_id(
        subject_id: &str,
        privacy_pool_id: &str,
        checked_height: u64,
    ) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:privacy-check-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(subject_id),
                HashPart::Str(privacy_pool_id),
                HashPart::Int(checked_height as i128),
            ],
            32,
        )
    }

    pub fn passed(&self) -> bool {
        self.observed_privacy_set_size >= self.required_privacy_set_size
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "privacy_set_check",
            "check_id": self.check_id,
            "subject_id": self.subject_id,
            "privacy_pool_id": self.privacy_pool_id,
            "observed_privacy_set_size": self.observed_privacy_set_size,
            "required_privacy_set_size": self.required_privacy_set_size,
            "checked_height": self.checked_height,
            "passed": self.passed(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub domain: String,
    pub nullifier: String,
    pub subject_id: String,
    pub source_height: u64,
}

impl ReplayFence {
    pub fn deterministic_id(domain: &str, nullifier: &str, subject_id: &str) -> String {
        domain_hash(
            "monero-l2-private-merchant-payment-channel:replay-fence-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(domain),
                HashPart::Str(nullifier),
                HashPart::Str(subject_id),
            ],
            32,
        )
    }

    pub fn to_public_record(&self) -> Value {
        json!({
            "type": "replay_fence",
            "fence_id": self.fence_id,
            "domain": self.domain,
            "subject_id": self.subject_id,
            "source_height": self.source_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub merchant_lanes: BTreeMap<String, MerchantLane>,
    pub encrypted_invoices: BTreeMap<String, EncryptedInvoice>,
    pub payer_authorizations: BTreeMap<String, PayerAuthorization>,
    pub receipt_attestations: BTreeMap<String, PqReceiptAttestation>,
    pub liquidity_reservations: BTreeMap<String, Reservation>,
    pub sponsor_reservations: BTreeMap<String, Reservation>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub rebates: BTreeMap<String, Rebate>,
    pub disputes: BTreeMap<String, Dispute>,
    pub privacy_checks: BTreeMap<String, PrivacySetCheck>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config: config.clone(),
            counters: Counters::default(),
            merchant_lanes: BTreeMap::new(),
            encrypted_invoices: BTreeMap::new(),
            payer_authorizations: BTreeMap::new(),
            receipt_attestations: BTreeMap::new(),
            liquidity_reservations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            rebates: BTreeMap::new(),
            disputes: BTreeMap::new(),
            privacy_checks: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };

        let lane_nonce = domain_hash(
            "monero-l2-private-merchant-payment-channel:devnet-lane-nonce",
            &[
                HashPart::Str("retail-tap"),
                HashPart::Str(&config.channel_book),
            ],
            16,
        );
        let lane_id =
            MerchantLane::deterministic_id("merchant-commitment-devnet-cafe", &lane_nonce, 0);
        let lane = MerchantLane {
            lane_id: lane_id.clone(),
            merchant_commitment: "merchant-commitment-devnet-cafe".to_string(),
            lane_kind: MerchantLaneKind::RetailTap,
            lane_nonce,
            lane_epoch: 0,
            privacy_pool_id: "monero-devnet-ringct-retail-privacy-pool".to_string(),
            encrypted_descriptor_root: devnet_commitment("lane-descriptor", 0),
            settlement_address_commitment: devnet_commitment("settlement-address", 0),
            min_invoice_amount_atomic: 100_000,
            max_invoice_amount_atomic: 25_000_000_000,
            reserved_liquidity_atomic: 250_000_000_000,
            spent_liquidity_atomic: 0,
            reserve_ratio_bps: config.target_reserve_bps,
            pq_attestation_key_root: devnet_commitment("pq-attestation-key", 0),
            created_height: config.genesis_height,
        };
        state.insert_merchant_lane(lane).expect("valid devnet lane");

        let invoice_commitment = devnet_commitment("invoice", 0);
        let invoice_id = EncryptedInvoice::deterministic_id(&lane_id, &invoice_commitment);
        let invoice = EncryptedInvoice {
            invoice_id: invoice_id.clone(),
            lane_id: lane_id.clone(),
            merchant_invoice_commitment: invoice_commitment,
            encrypted_invoice_blob_root: devnet_commitment("invoice-blob", 0),
            amount_commitment: devnet_commitment("invoice-amount", 0),
            amount_upper_bound_atomic: 4_200_000_000,
            fee_commitment: devnet_commitment("invoice-fee", 0),
            speed: PaymentSpeed::Instant,
            status: InvoiceStatus::Reserved,
            issued_height: config.genesis_height + 1,
            expires_height: config.genesis_height + config.invoice_ttl_blocks + 1,
            payer_view_tag_root: devnet_commitment("payer-view-tag", 0),
            merchant_refund_commitment: devnet_commitment("merchant-refund", 0),
            memo_ciphertext_root: devnet_commitment("memo", 0),
        };
        state
            .insert_encrypted_invoice(invoice)
            .expect("valid devnet invoice");

        let auth_nullifier = devnet_commitment("authorization-nullifier", 0);
        let authorization_id = PayerAuthorization::deterministic_id(
            &invoice_id,
            "payer-commitment-devnet-0",
            &auth_nullifier,
        );
        let authorization = PayerAuthorization {
            authorization_id: authorization_id.clone(),
            invoice_id: invoice_id.clone(),
            payer_commitment: "payer-commitment-devnet-0".to_string(),
            ring_members_root: devnet_commitment("ring-members", 0),
            authorization_nullifier: auth_nullifier,
            replay_domain: config.replay_domain.clone(),
            max_amount_commitment: devnet_commitment("max-amount", 0),
            payer_fee_commitment: devnet_commitment("payer-fee", 0),
            status: AuthorizationStatus::Accepted,
            authorized_height: config.genesis_height + 2,
            expires_height: config.genesis_height + config.authorization_ttl_blocks + 2,
            pq_session_key_root: devnet_commitment("pq-session-key", 0),
        };
        state
            .insert_payer_authorization(authorization)
            .expect("valid devnet authorization");

        let receipt_commitment = devnet_commitment("receipt", 0);
        let receipt_id = PqReceiptAttestation::deterministic_id(
            &invoice_id,
            &authorization_id,
            &receipt_commitment,
        );
        let receipt = PqReceiptAttestation {
            receipt_id: receipt_id.clone(),
            invoice_id: invoice_id.clone(),
            authorization_id: authorization_id.clone(),
            lane_id: lane_id.clone(),
            amount_commitment: devnet_commitment("receipt-amount", 0),
            merchant_receipt_commitment: receipt_commitment,
            pq_signature_root: devnet_commitment("receipt-pq-signature", 0),
            pq_security_bits: config.target_pq_security_bits,
            status: ReceiptStatus::Finalized,
            attested_height: config.genesis_height + 3,
            finality_height: config.genesis_height + config.settlement_window_blocks + 3,
        };
        state
            .insert_receipt_attestation(receipt)
            .expect("valid devnet receipt");

        let liquidity = Reservation {
            reservation_id: Reservation::deterministic_id(
                &invoice_id,
                &lane_id,
                ReservationKind::MerchantLiquidity,
                "devnet-liquidity",
            ),
            invoice_id: invoice_id.clone(),
            lane_id: lane_id.clone(),
            kind: ReservationKind::MerchantLiquidity,
            status: ReservationStatus::Locked,
            amount_commitment: devnet_commitment("liquidity-amount", 0),
            amount_upper_bound_atomic: 4_300_000_000,
            sponsor_commitment: None,
            reserve_ratio_bps: config.target_reserve_bps,
            opened_height: config.genesis_height + 2,
            expires_height: config.genesis_height + config.reservation_ttl_blocks + 2,
        };
        state
            .insert_reservation(liquidity)
            .expect("valid devnet liquidity reservation");

        let sponsor = Reservation {
            reservation_id: Reservation::deterministic_id(
                &invoice_id,
                &lane_id,
                ReservationKind::SponsorFee,
                "devnet-sponsor",
            ),
            invoice_id: invoice_id.clone(),
            lane_id: lane_id.clone(),
            kind: ReservationKind::SponsorFee,
            status: ReservationStatus::Locked,
            amount_commitment: devnet_commitment("sponsor-amount", 0),
            amount_upper_bound_atomic: 7_000_000,
            sponsor_commitment: Some("merchant-sponsor-commitment-devnet".to_string()),
            reserve_ratio_bps: config.sponsor_cover_bps,
            opened_height: config.genesis_height + 2,
            expires_height: config.genesis_height + config.reservation_ttl_blocks + 2,
        };
        state
            .insert_reservation(sponsor)
            .expect("valid devnet sponsor reservation");

        let privacy_check = PrivacySetCheck {
            check_id: PrivacySetCheck::deterministic_id(
                &invoice_id,
                "monero-devnet-ringct-retail-privacy-pool",
                config.genesis_height + 2,
            ),
            subject_id: invoice_id.clone(),
            privacy_pool_id: "monero-devnet-ringct-retail-privacy-pool".to_string(),
            ring_members_root: devnet_commitment("ring-members", 0),
            decoy_distribution_root: devnet_commitment("decoy-distribution", 0),
            observed_privacy_set_size: config.target_privacy_set_size,
            required_privacy_set_size: config.min_privacy_set_size,
            pq_transcript_root: devnet_commitment("privacy-pq-transcript", 0),
            checked_height: config.genesis_height + 2,
        };
        state
            .insert_privacy_check(privacy_check)
            .expect("valid devnet privacy check");

        let batch_id = SettlementBatch::deterministic_id(
            &lane_id,
            config.genesis_height + 4,
            &[invoice_id.clone()],
        );
        let settlement_batch = SettlementBatch {
            batch_id,
            lane_id: lane_id.clone(),
            invoice_ids: vec![invoice_id.clone()],
            receipt_ids: vec![receipt_id.clone()],
            reservation_ids: state.reservation_ids_for_invoice(&invoice_id),
            batch_amount_commitment: devnet_commitment("batch-amount", 0),
            fee_commitment: devnet_commitment("batch-fee", 0),
            privacy_set_size: config.min_batch_privacy_set_size,
            status: SettlementStatus::Finalized,
            opened_height: config.genesis_height + 4,
            sealed_height: config.genesis_height + 5,
            settlement_root: devnet_commitment("settlement-root", 0),
        };
        state
            .insert_settlement_batch(settlement_batch)
            .expect("valid devnet settlement batch");

        let rebate = Rebate {
            rebate_id: Rebate::deterministic_id(
                &invoice_id,
                &lane_id,
                &devnet_commitment("payer-rebate", 0),
            ),
            invoice_id: invoice_id.clone(),
            lane_id: lane_id.clone(),
            payer_rebate_commitment: devnet_commitment("payer-rebate", 0),
            merchant_rebate_commitment: devnet_commitment("merchant-rebate", 0),
            rebate_bps: config.merchant_rebate_bps,
            sponsor_commitment: Some("merchant-sponsor-commitment-devnet".to_string()),
            issued_height: config.genesis_height + 6,
            expires_height: config.genesis_height + config.rebate_ttl_blocks + 6,
            claimed_nullifier: None,
        };
        state.insert_rebate(rebate).expect("valid devnet rebate");

        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "asset_id": self.config.asset_id,
            "fee_asset_id": self.config.fee_asset_id,
            "roots": self.roots(),
            "counters": self.counters,
            "public_records": self.public_records,
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        domain_hash(
            "monero-l2-private-merchant-payment-channel:state-root",
            &[
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.counters_root),
                HashPart::Str(&roots.merchant_lanes_root),
                HashPart::Str(&roots.encrypted_invoices_root),
                HashPart::Str(&roots.payer_authorizations_root),
                HashPart::Str(&roots.receipt_attestations_root),
                HashPart::Str(&roots.liquidity_reservations_root),
                HashPart::Str(&roots.sponsor_reservations_root),
                HashPart::Str(&roots.settlement_batches_root),
                HashPart::Str(&roots.rebates_root),
                HashPart::Str(&roots.disputes_root),
                HashPart::Str(&roots.privacy_checks_root),
                HashPart::Str(&roots.replay_fences_root),
                HashPart::Str(&roots.public_records_root),
            ],
            32,
        )
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_json("config", &self.config),
            counters_root: root_json("counters", &self.counters),
            merchant_lanes_root: root_map("merchant-lanes", &self.merchant_lanes),
            encrypted_invoices_root: root_map("encrypted-invoices", &self.encrypted_invoices),
            payer_authorizations_root: root_map("payer-authorizations", &self.payer_authorizations),
            receipt_attestations_root: root_map("receipt-attestations", &self.receipt_attestations),
            liquidity_reservations_root: root_map(
                "liquidity-reservations",
                &self.liquidity_reservations,
            ),
            sponsor_reservations_root: root_map("sponsor-reservations", &self.sponsor_reservations),
            settlement_batches_root: root_map("settlement-batches", &self.settlement_batches),
            rebates_root: root_map("rebates", &self.rebates),
            disputes_root: root_map("disputes", &self.disputes),
            privacy_checks_root: root_map("privacy-checks", &self.privacy_checks),
            replay_fences_root: root_map("replay-fences", &self.replay_fences),
            public_records_root: root_map("public-records", &self.public_records),
        }
    }

    pub fn insert_merchant_lane(
        &mut self,
        lane: MerchantLane,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.merchant_lanes.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_MERCHANT_LANES
        {
            return Err("private merchant channel lane capacity exceeded".to_string());
        }
        if lane.reserve_ratio_bps < self.config.min_reserve_bps {
            return Err("private merchant channel lane reserve ratio is too low".to_string());
        }
        self.public_records
            .insert(lane.lane_id.clone(), lane.to_public_record());
        self.merchant_lanes.insert(lane.lane_id.clone(), lane);
        self.counters.merchant_lanes = self.merchant_lanes.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_encrypted_invoice(
        &mut self,
        invoice: EncryptedInvoice,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.encrypted_invoices.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_ENCRYPTED_INVOICES
        {
            return Err("private merchant channel invoice capacity exceeded".to_string());
        }
        if !self.merchant_lanes.contains_key(&invoice.lane_id) {
            return Err("private merchant channel invoice references missing lane".to_string());
        }
        self.public_records
            .insert(invoice.invoice_id.clone(), invoice.to_public_record());
        self.encrypted_invoices
            .insert(invoice.invoice_id.clone(), invoice);
        self.counters.encrypted_invoices = self.encrypted_invoices.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_payer_authorization(
        &mut self,
        authorization: PayerAuthorization,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.payer_authorizations.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_PAYER_AUTHORIZATIONS
        {
            return Err("private merchant channel authorization capacity exceeded".to_string());
        }
        if !self
            .encrypted_invoices
            .contains_key(&authorization.invoice_id)
        {
            return Err(
                "private merchant channel authorization references missing invoice".to_string(),
            );
        }
        let replay_key = authorization.replay_key();
        if self.consumed_nullifiers.contains(&replay_key) {
            return Err("private merchant channel authorization replay detected".to_string());
        }
        let fence = ReplayFence {
            fence_id: ReplayFence::deterministic_id(
                &authorization.replay_domain,
                &authorization.authorization_nullifier,
                &authorization.authorization_id,
            ),
            domain: authorization.replay_domain.clone(),
            nullifier: authorization.authorization_nullifier.clone(),
            subject_id: authorization.authorization_id.clone(),
            source_height: authorization.authorized_height,
        };
        self.consumed_nullifiers.insert(replay_key);
        self.insert_replay_fence(fence)?;
        self.public_records.insert(
            authorization.authorization_id.clone(),
            authorization.to_public_record(),
        );
        self.payer_authorizations
            .insert(authorization.authorization_id.clone(), authorization);
        self.counters.payer_authorizations = self.payer_authorizations.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_receipt_attestation(
        &mut self,
        receipt: PqReceiptAttestation,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.receipt_attestations.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_RECEIPT_ATTESTATIONS
        {
            return Err("private merchant channel receipt capacity exceeded".to_string());
        }
        if !receipt.quantum_resistant(&self.config) {
            return Err("private merchant channel receipt pq security is too low".to_string());
        }
        if !self.encrypted_invoices.contains_key(&receipt.invoice_id)
            || !self
                .payer_authorizations
                .contains_key(&receipt.authorization_id)
        {
            return Err(
                "private merchant channel receipt references missing payment state".to_string(),
            );
        }
        self.public_records
            .insert(receipt.receipt_id.clone(), receipt.to_public_record());
        self.receipt_attestations
            .insert(receipt.receipt_id.clone(), receipt);
        self.counters.receipt_attestations = self.receipt_attestations.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_reservation(
        &mut self,
        reservation: Reservation,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.liquidity_reservations.len() + self.sponsor_reservations.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_RESERVATIONS
        {
            return Err("private merchant channel reservation capacity exceeded".to_string());
        }
        if reservation.reserve_ratio_bps < self.config.low_fee_bps && reservation.is_sponsor() {
            return Err("private merchant channel sponsor reservation is underfunded".to_string());
        }
        self.public_records.insert(
            reservation.reservation_id.clone(),
            reservation.to_public_record(),
        );
        if reservation.is_sponsor() {
            self.sponsor_reservations
                .insert(reservation.reservation_id.clone(), reservation);
            self.counters.sponsor_reservations = self.sponsor_reservations.len() as u64;
        } else {
            self.liquidity_reservations
                .insert(reservation.reservation_id.clone(), reservation);
            self.counters.liquidity_reservations = self.liquidity_reservations.len() as u64;
        }
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_settlement_batch(
        &mut self,
        batch: SettlementBatch,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.settlement_batches.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_SETTLEMENT_BATCHES
        {
            return Err("private merchant channel settlement batch capacity exceeded".to_string());
        }
        if !batch.privacy_ready(&self.config) {
            return Err(
                "private merchant channel settlement batch privacy set is too small".to_string(),
            );
        }
        self.public_records
            .insert(batch.batch_id.clone(), batch.to_public_record());
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch);
        self.counters.settlement_batches = self.settlement_batches.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_rebate(
        &mut self,
        rebate: Rebate,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.rebates.len() >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_REBATES {
            return Err("private merchant channel rebate capacity exceeded".to_string());
        }
        if rebate.rebate_bps > self.config.max_user_fee_bps {
            return Err("private merchant channel rebate exceeds max user fee".to_string());
        }
        self.public_records
            .insert(rebate.rebate_id.clone(), rebate.to_public_record());
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_dispute(
        &mut self,
        dispute: Dispute,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.disputes.len() >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_DISPUTES {
            return Err("private merchant channel dispute capacity exceeded".to_string());
        }
        if self
            .consumed_nullifiers
            .contains(&dispute.dispute_nullifier)
        {
            return Err("private merchant channel dispute replay detected".to_string());
        }
        self.consumed_nullifiers
            .insert(dispute.dispute_nullifier.clone());
        self.public_records
            .insert(dispute.dispute_id.clone(), dispute.to_public_record());
        self.disputes.insert(dispute.dispute_id.clone(), dispute);
        self.counters.disputes = self.disputes.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_privacy_check(
        &mut self,
        check: PrivacySetCheck,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.privacy_checks.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_PRIVACY_CHECKS
        {
            return Err("private merchant channel privacy check capacity exceeded".to_string());
        }
        if !check.passed() {
            return Err("private merchant channel privacy set check failed".to_string());
        }
        self.public_records
            .insert(check.check_id.clone(), check.to_public_record());
        self.privacy_checks.insert(check.check_id.clone(), check);
        self.counters.privacy_checks = self.privacy_checks.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn insert_replay_fence(
        &mut self,
        fence: ReplayFence,
    ) -> MoneroL2PrivateMerchantPaymentChannelRuntimeResult<()> {
        if self.replay_fences.len()
            >= MONERO_L2_PRIVATE_MERCHANT_PAYMENT_CHANNEL_RUNTIME_MAX_REPLAY_FENCES
        {
            return Err("private merchant channel replay fence capacity exceeded".to_string());
        }
        self.public_records
            .insert(fence.fence_id.clone(), fence.to_public_record());
        self.replay_fences.insert(fence.fence_id.clone(), fence);
        self.counters.replay_fences = self.replay_fences.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    pub fn reservation_ids_for_invoice(&self, invoice_id: &str) -> Vec<String> {
        self.liquidity_reservations
            .values()
            .chain(self.sponsor_reservations.values())
            .filter(|reservation| reservation.invoice_id == invoice_id)
            .map(|reservation| reservation.reservation_id.clone())
            .collect()
    }
}

pub type Runtime = State;

pub fn root_json<T: Serialize>(label: &str, value: &T) -> String {
    let value = serde_json::to_value(value).expect("private merchant channel root serialization");
    domain_hash(
        &format!("monero-l2-private-merchant-payment-channel:{label}-root"),
        &[HashPart::Json(&value)],
        32,
    )
}

pub fn root_map<T: Serialize>(label: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-private-merchant-payment-channel:{label}"),
        &leaves,
    )
}

pub fn root_values<T: Serialize>(label: &str, values: &[T]) -> String {
    let leaves = values
        .iter()
        .map(|value| serde_json::to_value(value).expect("private merchant channel value root"))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-private-merchant-payment-channel:{label}"),
        &leaves,
    )
}

pub fn devnet_commitment(label: &str, index: u64) -> String {
    domain_hash(
        "monero-l2-private-merchant-payment-channel:devnet-commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(index as i128),
        ],
        32,
    )
}
