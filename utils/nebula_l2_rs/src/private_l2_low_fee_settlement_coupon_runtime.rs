use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeSettlementCouponRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-settlement-coupon-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-settlement-coupon-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_MINT_SUITE: &str =
    "encrypted-private-l2-settlement-coupon-mint-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_QUOTE_LOCK_SUITE: &str =
    "private-l2-low-fee-fee-quote-lock-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_SPONSOR_SUITE: &str =
    "roots-only-low-fee-sponsor-reservation-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_BATCH_SUITE: &str =
    "zk-private-l2-settlement-coupon-batch-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_RECEIPT_SUITE: &str =
    "zk-pq-settlement-coupon-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_REBATE_SUITE: &str =
    "roots-only-low-fee-coupon-rebate-v1";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEVNET_HEIGHT: u64 = 812_000;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_BOOKS: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_MINTS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_QUOTE_LOCKS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 512;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize = 8_192;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_REBATE_BPS: u64 = 8_000;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_BOOK_TTL_BLOCKS: u64 = 21_600;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MINT_TTL_BLOCKS: u64 = 2_400;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_QUOTE_LOCK_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponLane {
    PrivateTransfer,
    PrivateContractCall,
    ConfidentialToken,
    DefiSwap,
    DefiLending,
    PerpMargin,
    StablecoinPayment,
    BridgeExit,
    AccountSession,
    EmergencySettlement,
}

impl CouponLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialToken => "confidential_token",
            Self::DefiSwap => "defi_swap",
            Self::DefiLending => "defi_lending",
            Self::PerpMargin => "perp_margin",
            Self::StablecoinPayment => "stablecoin_payment",
            Self::BridgeExit => "bridge_exit",
            Self::AccountSession => "account_session",
            Self::EmergencySettlement => "emergency_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponBookStatus {
    Proposed,
    Open,
    Sponsored,
    Throttled,
    Settling,
    Closed,
    Revoked,
    Expired,
}

impl CouponBookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Open => "open",
            Self::Sponsored => "sponsored",
            Self::Throttled => "throttled",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MintStatus {
    Encrypted,
    QuoteLocked,
    Sponsored,
    Batched,
    Settled,
    Rebated,
    Revoked,
    Expired,
    Rejected,
}

impl MintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::QuoteLocked => "quote_locked",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeQuoteLockStatus {
    Locked,
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl FeeQuoteLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    PartiallyConsumed,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::PartiallyConsumed => "partially_consumed",
            Self::Consumed => "consumed",
            Self::RebateQueued => "rebate_queued",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Proposed,
    QuoteLocked,
    SponsorReserved,
    Executing,
    SettlementReady,
    Settled,
    Rebated,
    Revoked,
    Expired,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuoteLocked => "quote_locked",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Executing => "executing",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    ProofLinked,
    Paid,
    Recycled,
    Expired,
    Rejected,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ProofLinked => "proof_linked",
            Self::Paid => "paid",
            Self::Recycled => "recycled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserCancelled,
    SponsorCancelled,
    QuoteExpired,
    PrivacySetTooSmall,
    ReplayFenceTripped,
    NullifierAlreadySeen,
    FeeCeilingBreached,
    BatchTimeout,
    GovernanceEmergency,
}

impl RevocationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserCancelled => "user_cancelled",
            Self::SponsorCancelled => "sponsor_cancelled",
            Self::QuoteExpired => "quote_expired",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::ReplayFenceTripped => "replay_fence_tripped",
            Self::NullifierAlreadySeen => "nullifier_already_seen",
            Self::FeeCeilingBreached => "fee_ceiling_breached",
            Self::BatchTimeout => "batch_timeout",
            Self::GovernanceEmergency => "governance_emergency",
        }
    }
}

impl CouponLane {
    pub fn latency_weight(self) -> u64 {
        match self {
            Self::EmergencySettlement => 10_000,
            Self::BridgeExit => 9_700,
            Self::PerpMargin => 9_500,
            Self::DefiSwap => 9_200,
            Self::DefiLending => 8_900,
            Self::StablecoinPayment => 8_700,
            Self::PrivateContractCall => 8_500,
            Self::ConfidentialToken => 8_200,
            Self::PrivateTransfer => 8_000,
            Self::AccountSession => 7_700,
        }
    }

    pub fn defi(self) -> bool {
        matches!(
            self,
            Self::DefiSwap | Self::DefiLending | Self::PerpMargin | Self::StablecoinPayment
        )
    }
}

impl CouponBookStatus {
    pub fn accepts_mints(self) -> bool {
        matches!(self, Self::Open | Self::Sponsored | Self::Throttled)
    }
}

impl MintStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::QuoteLocked | Self::Sponsored | Self::Batched
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub mint_suite: String,
    pub quote_lock_suite: String,
    pub sponsor_suite: String,
    pub batch_suite: String,
    pub receipt_suite: String,
    pub rebate_suite: String,
    pub max_books: usize,
    pub max_mints: usize,
    pub max_quote_locks: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub book_ttl_blocks: u64,
    pub mint_ttl_blocks: u64,
    pub quote_lock_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub allow_contract_call_coupons: bool,
    pub allow_sponsor_rebates: bool,
    pub require_replay_fence: bool,
    pub require_nullifier_fence: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_PQ_AUTH_SUITE.to_string(),
            mint_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_MINT_SUITE.to_string(),
            quote_lock_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_QUOTE_LOCK_SUITE
                .to_string(),
            sponsor_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_SPONSOR_SUITE.to_string(),
            batch_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_BATCH_SUITE.to_string(),
            receipt_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_RECEIPT_SUITE.to_string(),
            rebate_suite: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_REBATE_SUITE.to_string(),
            max_books: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_BOOKS,
            max_mints: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_MINTS,
            max_quote_locks: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_QUOTE_LOCKS,
            max_reservations: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_REBATES,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_REBATE_BPS,
            book_ttl_blocks: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_BOOK_TTL_BLOCKS,
            mint_ttl_blocks: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_MINT_TTL_BLOCKS,
            quote_lock_ttl_blocks:
                PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_QUOTE_LOCK_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            allow_contract_call_coupons: true,
            allow_sponsor_rebates: true,
            require_replay_fence: true,
            require_nullifier_fence: true,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeSettlementCouponRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("batch privacy set must cover the minimum privacy set".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "mint_suite": self.mint_suite,
            "quote_lock_suite": self.quote_lock_suite,
            "sponsor_suite": self.sponsor_suite,
            "batch_suite": self.batch_suite,
            "receipt_suite": self.receipt_suite,
            "rebate_suite": self.rebate_suite,
            "max_books": self.max_books,
            "max_mints": self.max_mints,
            "max_quote_locks": self.max_quote_locks,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "book_ttl_blocks": self.book_ttl_blocks,
            "mint_ttl_blocks": self.mint_ttl_blocks,
            "quote_lock_ttl_blocks": self.quote_lock_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "allow_contract_call_coupons": self.allow_contract_call_coupons,
            "allow_sponsor_rebates": self.allow_sponsor_rebates,
            "require_replay_fence": self.require_replay_fence,
            "require_nullifier_fence": self.require_nullifier_fence,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_book_nonce: u64,
    pub next_mint_nonce: u64,
    pub next_quote_lock_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_receipt_nonce: u64,
    pub next_rebate_nonce: u64,
    pub next_revocation_nonce: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_counters",
            "next_book_nonce": self.next_book_nonce,
            "next_mint_nonce": self.next_mint_nonce,
            "next_quote_lock_nonce": self.next_quote_lock_nonce,
            "next_reservation_nonce": self.next_reservation_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "next_rebate_nonce": self.next_rebate_nonce,
            "next_revocation_nonce": self.next_revocation_nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponBook {
    pub book_id: String,
    pub lane: CouponLane,
    pub status: CouponBookStatus,
    pub sponsor_commitment: String,
    pub owner_commitment: String,
    pub contract_commitment: String,
    pub coupon_denomination_micro_units: u64,
    pub total_coupons: u64,
    pub remaining_coupons: u64,
    pub max_fee_per_coupon_micro_units: u64,
    pub privacy_set_size: usize,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
    pub policy_root: String,
    pub replay_fence_root: String,
}

impl CouponBook {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_coupon_book",
            "book_id": self.book_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "owner_commitment": self.owner_commitment,
            "contract_commitment": self.contract_commitment,
            "coupon_denomination_micro_units": self.coupon_denomination_micro_units,
            "total_coupons": self.total_coupons,
            "remaining_coupons": self.remaining_coupons,
            "max_fee_per_coupon_micro_units": self.max_fee_per_coupon_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
            "policy_root": self.policy_root,
            "replay_fence_root": self.replay_fence_root,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root("COUPONBOOK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCouponMint {
    pub mint_id: String,
    pub book_id: String,
    pub lane: CouponLane,
    pub status: MintStatus,
    pub owner_commitment: String,
    pub recipient_commitment: String,
    pub encrypted_coupon_root: String,
    pub coupon_commitment_root: String,
    pub fee_asset_id: String,
    pub coupon_count: u64,
    pub face_value_micro_units: u64,
    pub max_fee_bps: u64,
    pub minted_height: u64,
    pub expires_at_height: u64,
    pub nullifier: String,
    pub replay_tag: String,
}

impl EncryptedCouponMint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_encrypted_coupon_mint",
            "mint_id": self.mint_id,
            "book_id": self.book_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "recipient_commitment": self.recipient_commitment,
            "encrypted_coupon_root": self.encrypted_coupon_root,
            "coupon_commitment_root": self.coupon_commitment_root,
            "fee_asset_id": self.fee_asset_id,
            "coupon_count": self.coupon_count,
            "face_value_micro_units": self.face_value_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "minted_height": self.minted_height,
            "expires_at_height": self.expires_at_height,
            "nullifier": self.nullifier,
            "replay_tag": self.replay_tag,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root(
            "ENCRYPTEDCOUPONMINT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeQuoteLock {
    pub quote_lock_id: String,
    pub mint_id: String,
    pub book_id: String,
    pub lane: CouponLane,
    pub status: FeeQuoteLockStatus,
    pub quoter_commitment: String,
    pub fee_asset_id: String,
    pub locked_fee_micro_units: u64,
    pub max_execution_delay_blocks: u64,
    pub quote_score: u64,
    pub locked_height: u64,
    pub expires_at_height: u64,
    pub quote_root: String,
    pub solver_policy_root: String,
}

impl FeeQuoteLock {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_fee_quote_lock",
            "quote_lock_id": self.quote_lock_id,
            "mint_id": self.mint_id,
            "book_id": self.book_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "quoter_commitment": self.quoter_commitment,
            "fee_asset_id": self.fee_asset_id,
            "locked_fee_micro_units": self.locked_fee_micro_units,
            "max_execution_delay_blocks": self.max_execution_delay_blocks,
            "quote_score": self.quote_score,
            "locked_height": self.locked_height,
            "expires_at_height": self.expires_at_height,
            "quote_root": self.quote_root,
            "solver_policy_root": self.solver_policy_root,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root("FEEQUOTELOCK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub mint_id: String,
    pub quote_lock_id: String,
    pub book_id: String,
    pub status: SponsorReservationStatus,
    pub sponsor_commitment: String,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub rebate_micro_units: u64,
    pub reserved_height: u64,
    pub expires_at_height: u64,
    pub reservation_root: String,
    pub budget_root: String,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "mint_id": self.mint_id,
            "quote_lock_id": self.quote_lock_id,
            "book_id": self.book_id,
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "reserved_micro_units": self.reserved_micro_units,
            "consumed_micro_units": self.consumed_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "reserved_height": self.reserved_height,
            "expires_at_height": self.expires_at_height,
            "reservation_root": self.reservation_root,
            "budget_root": self.budget_root,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root(
            "SPONSORRESERVATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementCouponBatch {
    pub batch_id: String,
    pub lane: CouponLane,
    pub status: SettlementBatchStatus,
    pub aggregator_commitment: String,
    pub mint_ids: Vec<String>,
    pub quote_lock_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub batch_fee_micro_units: u64,
    pub sponsored_micro_units: u64,
    pub privacy_set_size: usize,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub execution_root: String,
    pub proof_root: String,
    pub nullifier_root: String,
}

impl SettlementCouponBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_settlement_coupon_batch",
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "aggregator_commitment": self.aggregator_commitment,
            "mint_ids": self.mint_ids,
            "quote_lock_ids": self.quote_lock_ids,
            "reservation_ids": self.reservation_ids,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "sponsored_micro_units": self.sponsored_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
            "execution_root": self.execution_root,
            "proof_root": self.proof_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root(
            "SETTLEMENTCOUPONBATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub mint_id: String,
    pub reservation_id: String,
    pub status: ReceiptStatus,
    pub settlement_height: u64,
    pub fee_paid_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub user_paid_micro_units: u64,
    pub receipt_root: String,
    pub state_transition_root: String,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "mint_id": self.mint_id,
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "settlement_height": self.settlement_height,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "user_paid_micro_units": self.user_paid_micro_units,
            "receipt_root": self.receipt_root,
            "state_transition_root": self.state_transition_root,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root(
            "SETTLEMENTRECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub batch_id: String,
    pub mint_id: String,
    pub reservation_id: String,
    pub status: RebateStatus,
    pub beneficiary_commitment: String,
    pub rebate_micro_units: u64,
    pub queued_height: u64,
    pub paid_height: u64,
    pub rebate_root: String,
}

impl CouponRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_coupon_rebate",
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "mint_id": self.mint_id,
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_micro_units": self.rebate_micro_units,
            "queued_height": self.queued_height,
            "paid_height": self.paid_height,
            "rebate_root": self.rebate_root,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root("COUPONREBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationFence {
    pub revocation_id: String,
    pub subject_id: String,
    pub reason: RevocationReason,
    pub revoked_height: u64,
    pub authority_commitment: String,
    pub revocation_root: String,
    pub replay_tag: String,
    pub nullifier: String,
}

impl RevocationFence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_revocation_fence",
            "revocation_id": self.revocation_id,
            "subject_id": self.subject_id,
            "reason": self.reason.as_str(),
            "revoked_height": self.revoked_height,
            "authority_commitment": self.authority_commitment,
            "revocation_root": self.revocation_root,
            "replay_tag": self.replay_tag,
            "nullifier": self.nullifier,
        })
    }

    pub fn root(&self) -> String {
        private_l2_low_fee_settlement_coupon_payload_root("REVOCATIONFENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub coupon_book_root: String,
    pub encrypted_mint_root: String,
    pub fee_quote_lock_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub revocation_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub runtime_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "coupon_book_root": self.coupon_book_root,
            "encrypted_mint_root": self.encrypted_mint_root,
            "fee_quote_lock_root": self.fee_quote_lock_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "revocation_root": self.revocation_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "runtime_root": self.runtime_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub coupon_books: BTreeMap<String, CouponBook>,
    pub encrypted_mints: BTreeMap<String, EncryptedCouponMint>,
    pub fee_quote_locks: BTreeMap<String, FeeQuoteLock>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub settlement_batches: BTreeMap<String, SettlementCouponBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, CouponRebate>,
    pub revocations: BTreeMap<String, RevocationFence>,
    pub nullifier_fence: BTreeSet<String>,
    pub replay_fence: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2LowFeeSettlementCouponRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_DEVNET_HEIGHT,
            runtime_root: String::new(),
            coupon_books: BTreeMap::new(),
            encrypted_mints: BTreeMap::new(),
            fee_quote_locks: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            revocations: BTreeMap::new(),
            nullifier_fence: BTreeSet::new(),
            replay_fence: BTreeSet::new(),
        };
        let book = state.open_coupon_book(
            CouponLane::PrivateContractCall,
            "devnet-sponsor-commitment-0000000000000001".to_string(),
            "devnet-owner-commitment-000000000000000001".to_string(),
            "devnet-contract-commitment-00000000000001".to_string(),
            1_000,
            100_000,
            12,
            "devnet-book-metadata-root-0000000000000001".to_string(),
            "devnet-book-policy-root-00000000000000001".to_string(),
        )?;
        let mint = state.mint_encrypted_coupon(
            &book,
            "devnet-recipient-commitment-00000000000001".to_string(),
            "devnet-encrypted-coupon-root-0000000000001".to_string(),
            "devnet-coupon-commitment-root-000000000001".to_string(),
            "NEBULA_MICRO".to_string(),
            8,
            "devnet-mint-nullifier-000000000000000001".to_string(),
            "devnet-mint-replay-tag-000000000000000001".to_string(),
        )?;
        let quote = state.lock_fee_quote(
            &mint,
            "devnet-quoter-commitment-000000000000001".to_string(),
            6_000,
            2,
            "devnet-quote-root-000000000000000000001".to_string(),
            "devnet-solver-policy-root-00000000000001".to_string(),
        )?;
        let reservation = state.reserve_sponsor(
            &mint,
            &quote,
            5_700,
            "devnet-budget-root-0000000000000000001".to_string(),
        )?;
        let batch = state.propose_batch(
            CouponLane::PrivateContractCall,
            "devnet-aggregator-commitment-00000000001".to_string(),
            vec![mint],
            vec![quote],
            vec![reservation],
            "devnet-execution-root-000000000000000001".to_string(),
            "devnet-proof-root-0000000000000000000001".to_string(),
        )?;
        state.settle_batch(
            &batch,
            "devnet-state-transition-root-000000000001".to_string(),
        )?;
        state.runtime_root = state.state_root();
        Ok(state)
    }
    pub fn open_coupon_book(
        &mut self,
        lane: CouponLane,
        sponsor_commitment: String,
        owner_commitment: String,
        contract_commitment: String,
        coupon_denomination_micro_units: u64,
        total_coupons: u64,
        max_fee_per_coupon_micro_units: u64,
        metadata_root: String,
        policy_root: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<String> {
        self.config.validate()?;
        if self.coupon_books.len() >= self.config.max_books {
            return Err("coupon book capacity reached".to_string());
        }
        require_non_empty("sponsor_commitment", &sponsor_commitment)?;
        require_non_empty("owner_commitment", &owner_commitment)?;
        require_non_empty("contract_commitment", &contract_commitment)?;
        require_non_empty("metadata_root", &metadata_root)?;
        require_non_empty("policy_root", &policy_root)?;
        let nonce = self.counters.next_book_nonce;
        self.counters.next_book_nonce = self.counters.next_book_nonce.saturating_add(1);
        let book_id = deterministic_id(
            "BOOK",
            nonce,
            &[&owner_commitment, &contract_commitment, lane.as_str()],
        );
        let replay_fence_root =
            id_list_root("BOOK-REPLAY-FENCE", &[book_id.clone(), policy_root.clone()]);
        self.coupon_books.insert(
            book_id.clone(),
            CouponBook {
                book_id: book_id.clone(),
                lane,
                status: CouponBookStatus::Open,
                sponsor_commitment,
                owner_commitment,
                contract_commitment,
                coupon_denomination_micro_units,
                total_coupons,
                remaining_coupons: total_coupons,
                max_fee_per_coupon_micro_units,
                privacy_set_size: self.config.min_privacy_set_size,
                opened_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.book_ttl_blocks),
                metadata_root,
                policy_root,
                replay_fence_root,
            },
        );
        Ok(book_id)
    }

    pub fn mint_encrypted_coupon(
        &mut self,
        book_id: &str,
        recipient_commitment: String,
        encrypted_coupon_root: String,
        coupon_commitment_root: String,
        fee_asset_id: String,
        coupon_count: u64,
        nullifier: String,
        replay_tag: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<String> {
        if self.encrypted_mints.len() >= self.config.max_mints {
            return Err("encrypted mint capacity reached".to_string());
        }
        self.consume_nullifier(&nullifier)?;
        self.consume_replay_tag(&replay_tag)?;
        let book = self
            .coupon_books
            .get_mut(book_id)
            .ok_or_else(|| format!("unknown coupon book {book_id}"))?;
        if !book.status.accepts_mints() {
            return Err("coupon book does not accept mints".to_string());
        }
        if book.remaining_coupons < coupon_count {
            return Err("coupon book remaining coupons too small".to_string());
        }
        book.remaining_coupons = book.remaining_coupons.saturating_sub(coupon_count);
        let nonce = self.counters.next_mint_nonce;
        self.counters.next_mint_nonce = self.counters.next_mint_nonce.saturating_add(1);
        let mint_id = deterministic_id(
            "MINT",
            nonce,
            &[book_id, &recipient_commitment, &nullifier, &replay_tag],
        );
        self.encrypted_mints.insert(
            mint_id.clone(),
            EncryptedCouponMint {
                mint_id: mint_id.clone(),
                book_id: book_id.to_string(),
                lane: book.lane,
                status: MintStatus::Encrypted,
                owner_commitment: book.owner_commitment.clone(),
                recipient_commitment,
                encrypted_coupon_root,
                coupon_commitment_root,
                fee_asset_id,
                coupon_count,
                face_value_micro_units: book
                    .coupon_denomination_micro_units
                    .saturating_mul(coupon_count),
                max_fee_bps: self.config.max_user_fee_bps,
                minted_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.mint_ttl_blocks),
                nullifier,
                replay_tag,
            },
        );
        Ok(mint_id)
    }

    pub fn lock_fee_quote(
        &mut self,
        mint_id: &str,
        quoter_commitment: String,
        locked_fee_micro_units: u64,
        max_execution_delay_blocks: u64,
        quote_root: String,
        solver_policy_root: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<String> {
        if self.fee_quote_locks.len() >= self.config.max_quote_locks {
            return Err("fee quote lock capacity reached".to_string());
        }
        let mint = self
            .encrypted_mints
            .get_mut(mint_id)
            .ok_or_else(|| format!("unknown mint {mint_id}"))?;
        if !mint.status.live() {
            return Err("mint is not live".to_string());
        }
        require_non_empty("quoter_commitment", &quoter_commitment)?;
        require_non_empty("quote_root", &quote_root)?;
        let nonce = self.counters.next_quote_lock_nonce;
        self.counters.next_quote_lock_nonce = self.counters.next_quote_lock_nonce.saturating_add(1);
        let quote_lock_id = deterministic_id(
            "QUOTE-LOCK",
            nonce,
            &[mint_id, &quoter_commitment, &quote_root],
        );
        let quote_score = low_fee_score(
            locked_fee_micro_units,
            max_execution_delay_blocks,
            mint.lane.latency_weight(),
        );
        self.fee_quote_locks.insert(
            quote_lock_id.clone(),
            FeeQuoteLock {
                quote_lock_id: quote_lock_id.clone(),
                mint_id: mint_id.to_string(),
                book_id: mint.book_id.clone(),
                lane: mint.lane,
                status: FeeQuoteLockStatus::Locked,
                quoter_commitment,
                fee_asset_id: mint.fee_asset_id.clone(),
                locked_fee_micro_units,
                max_execution_delay_blocks,
                quote_score,
                locked_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.quote_lock_ttl_blocks),
                quote_root,
                solver_policy_root,
            },
        );
        mint.status = MintStatus::QuoteLocked;
        Ok(quote_lock_id)
    }

    pub fn reserve_sponsor(
        &mut self,
        mint_id: &str,
        quote_lock_id: &str,
        reserved_micro_units: u64,
        budget_root: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<String> {
        if self.sponsor_reservations.len() >= self.config.max_reservations {
            return Err("sponsor reservation capacity reached".to_string());
        }
        let mint = self
            .encrypted_mints
            .get_mut(mint_id)
            .ok_or_else(|| format!("unknown mint {mint_id}"))?;
        let quote = self
            .fee_quote_locks
            .get_mut(quote_lock_id)
            .ok_or_else(|| format!("unknown quote lock {quote_lock_id}"))?;
        if quote.mint_id != mint_id {
            return Err("quote lock does not target mint".to_string());
        }
        let book = self
            .coupon_books
            .get(&mint.book_id)
            .ok_or_else(|| format!("unknown coupon book {}", mint.book_id))?;
        let nonce = self.counters.next_reservation_nonce;
        self.counters.next_reservation_nonce =
            self.counters.next_reservation_nonce.saturating_add(1);
        let reservation_id = deterministic_id(
            "SPONSOR-RESERVATION",
            nonce,
            &[mint_id, quote_lock_id, &book.sponsor_commitment],
        );
        let rebate_micro_units = reserved_micro_units.saturating_mul(self.config.rebate_bps)
            / PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_MAX_BPS;
        let reservation_root = roots_only_payload(
            "sponsor_reservation",
            &reservation_id,
            &json!({
                "mint_id": mint_id,
                "quote_lock_id": quote_lock_id,
                "reserved_micro_units": reserved_micro_units
            }),
        );
        self.sponsor_reservations.insert(
            reservation_id.clone(),
            SponsorReservation {
                reservation_id: reservation_id.clone(),
                mint_id: mint_id.to_string(),
                quote_lock_id: quote_lock_id.to_string(),
                book_id: mint.book_id.clone(),
                status: SponsorReservationStatus::Reserved,
                sponsor_commitment: book.sponsor_commitment.clone(),
                reserved_micro_units,
                consumed_micro_units: 0,
                rebate_micro_units,
                reserved_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.reservation_ttl_blocks),
                reservation_root: private_l2_low_fee_settlement_coupon_payload_root(
                    "SPONSOR-RESERVATION-PAYLOAD",
                    &reservation_root,
                ),
                budget_root,
            },
        );
        mint.status = MintStatus::Sponsored;
        quote.status = FeeQuoteLockStatus::Reserved;
        Ok(reservation_id)
    }

    pub fn propose_batch(
        &mut self,
        lane: CouponLane,
        aggregator_commitment: String,
        mint_ids: Vec<String>,
        quote_lock_ids: Vec<String>,
        reservation_ids: Vec<String>,
        execution_root: String,
        proof_root: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<String> {
        if self.settlement_batches.len() >= self.config.max_batches {
            return Err("settlement batch capacity reached".to_string());
        }
        if mint_ids.is_empty() {
            return Err("batch must include at least one mint".to_string());
        }
        for mint_id in &mint_ids {
            self.encrypted_mints
                .get(mint_id)
                .ok_or_else(|| format!("unknown mint {mint_id}"))?;
        }
        let nonce = self.counters.next_batch_nonce;
        self.counters.next_batch_nonce = self.counters.next_batch_nonce.saturating_add(1);
        let batch_id = deterministic_id(
            "BATCH",
            nonce,
            &[&aggregator_commitment, &execution_root, &proof_root],
        );
        let batch_fee_micro_units = quote_lock_ids
            .iter()
            .filter_map(|id| self.fee_quote_locks.get(id))
            .map(|q| q.locked_fee_micro_units)
            .sum();
        let sponsored_micro_units = reservation_ids
            .iter()
            .filter_map(|id| self.sponsor_reservations.get(id))
            .map(|r| r.reserved_micro_units)
            .sum();
        let nullifier_root = id_list_root("BATCH-NULLIFIERS", &mint_ids);
        self.settlement_batches.insert(
            batch_id.clone(),
            SettlementCouponBatch {
                batch_id: batch_id.clone(),
                lane,
                status: SettlementBatchStatus::Proposed,
                aggregator_commitment,
                mint_ids,
                quote_lock_ids,
                reservation_ids,
                batch_fee_micro_units,
                sponsored_micro_units,
                privacy_set_size: self.config.batch_privacy_set_size,
                opened_height: self.current_height,
                expires_at_height: self
                    .current_height
                    .saturating_add(self.config.batch_ttl_blocks),
                execution_root,
                proof_root,
                nullifier_root,
            },
        );
        Ok(batch_id)
    }

    pub fn settle_batch(
        &mut self,
        batch_id: &str,
        state_transition_root: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<Vec<String>> {
        let batch = self
            .settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch {batch_id}"))?;
        batch.status = SettlementBatchStatus::Settled;
        let mut receipt_ids = Vec::new();
        let mint_ids = batch.mint_ids.clone();
        for mint_id in mint_ids {
            let mint = self
                .encrypted_mints
                .get_mut(&mint_id)
                .ok_or_else(|| format!("unknown mint {mint_id}"))?;
            mint.status = MintStatus::Settled;
            let reservation_id = batch.reservation_ids.first().cloned().unwrap_or_default();
            let nonce = self.counters.next_receipt_nonce;
            self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
            let receipt_id = deterministic_id(
                "RECEIPT",
                nonce,
                &[batch_id, &mint_id, &state_transition_root],
            );
            let receipt_root = roots_only_payload(
                "settlement_receipt",
                &receipt_id,
                &json!({
                    "batch_id": batch_id,
                    "mint_id": mint_id,
                    "state_transition_root": state_transition_root
                }),
            );
            self.settlement_receipts.insert(
                receipt_id.clone(),
                SettlementReceipt {
                    receipt_id: receipt_id.clone(),
                    batch_id: batch_id.to_string(),
                    mint_id: mint_id.clone(),
                    reservation_id: reservation_id.clone(),
                    status: ReceiptStatus::Published,
                    settlement_height: self.current_height,
                    fee_paid_micro_units: batch.batch_fee_micro_units,
                    sponsor_paid_micro_units: batch.sponsored_micro_units,
                    user_paid_micro_units: batch
                        .batch_fee_micro_units
                        .saturating_sub(batch.sponsored_micro_units),
                    receipt_root: private_l2_low_fee_settlement_coupon_payload_root(
                        "SETTLEMENT-RECEIPT-PAYLOAD",
                        &receipt_root,
                    ),
                    state_transition_root: state_transition_root.clone(),
                },
            );
            receipt_ids.push(receipt_id);
        }
        Ok(receipt_ids)
    }

    pub fn queue_rebate(
        &mut self,
        receipt_id: &str,
        beneficiary_commitment: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<String> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity reached".to_string());
        }
        let receipt = self
            .settlement_receipts
            .get(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?;
        let reservation = self.sponsor_reservations.get(&receipt.reservation_id);
        let rebate_micro_units = reservation.map(|r| r.rebate_micro_units).unwrap_or(0);
        let nonce = self.counters.next_rebate_nonce;
        self.counters.next_rebate_nonce = self.counters.next_rebate_nonce.saturating_add(1);
        let rebate_id = deterministic_id("REBATE", nonce, &[receipt_id, &beneficiary_commitment]);
        let rebate_root = roots_only_payload(
            "coupon_rebate",
            &rebate_id,
            &json!({
                "receipt_id": receipt_id,
                "rebate_micro_units": rebate_micro_units
            }),
        );
        self.rebates.insert(
            rebate_id.clone(),
            CouponRebate {
                rebate_id: rebate_id.clone(),
                receipt_id: receipt_id.to_string(),
                batch_id: receipt.batch_id.clone(),
                mint_id: receipt.mint_id.clone(),
                reservation_id: receipt.reservation_id.clone(),
                status: RebateStatus::Queued,
                beneficiary_commitment,
                rebate_micro_units,
                queued_height: self.current_height,
                paid_height: 0,
                rebate_root: private_l2_low_fee_settlement_coupon_payload_root(
                    "REBATE-PAYLOAD",
                    &rebate_root,
                ),
            },
        );
        Ok(rebate_id)
    }

    pub fn revoke_subject(
        &mut self,
        subject_id: String,
        reason: RevocationReason,
        authority_commitment: String,
        replay_tag: String,
        nullifier: String,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<String> {
        self.consume_replay_tag(&replay_tag)?;
        self.consume_nullifier(&nullifier)?;
        let nonce = self.counters.next_revocation_nonce;
        self.counters.next_revocation_nonce = self.counters.next_revocation_nonce.saturating_add(1);
        let revocation_id = deterministic_id(
            "REVOCATION",
            nonce,
            &[&subject_id, reason.as_str(), &authority_commitment],
        );
        let revocation_root = roots_only_payload(
            "revocation_fence",
            &revocation_id,
            &json!({
                "subject_id": subject_id,
                "reason": reason.as_str()
            }),
        );
        self.revocations.insert(
            revocation_id.clone(),
            RevocationFence {
                revocation_id: revocation_id.clone(),
                subject_id,
                reason,
                revoked_height: self.current_height,
                authority_commitment,
                revocation_root: private_l2_low_fee_settlement_coupon_payload_root(
                    "REVOCATION-PAYLOAD",
                    &revocation_root,
                ),
                replay_tag,
                nullifier,
            },
        );
        Ok(revocation_id)
    }

    pub fn expire_old_records(&mut self) -> usize {
        let mut changed = 0;
        for book in self.coupon_books.values_mut() {
            if book.expires_at_height <= self.current_height && book.status.accepts_mints() {
                book.status = CouponBookStatus::Expired;
                changed += 1;
            }
        }
        for mint in self.encrypted_mints.values_mut() {
            if mint.expires_at_height <= self.current_height && mint.status.live() {
                mint.status = MintStatus::Expired;
                changed += 1;
            }
        }
        for quote in self.fee_quote_locks.values_mut() {
            if quote.expires_at_height <= self.current_height
                && matches!(
                    quote.status,
                    FeeQuoteLockStatus::Locked | FeeQuoteLockStatus::Reserved
                )
            {
                quote.status = FeeQuoteLockStatus::Expired;
                changed += 1;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.expires_at_height <= self.current_height
                && matches!(
                    reservation.status,
                    SponsorReservationStatus::Reserved
                        | SponsorReservationStatus::PartiallyConsumed
                )
            {
                reservation.status = SponsorReservationStatus::Expired;
                changed += 1;
            }
        }
        for batch in self.settlement_batches.values_mut() {
            if batch.expires_at_height <= self.current_height
                && !matches!(
                    batch.status,
                    SettlementBatchStatus::Settled | SettlementBatchStatus::Rebated
                )
            {
                batch.status = SettlementBatchStatus::Expired;
                changed += 1;
            }
        }
        changed
    }

    pub fn roots(&self) -> Roots {
        let config_root = private_l2_low_fee_settlement_coupon_payload_root(
            "CONFIG",
            &self.config.public_record(),
        );
        let counters_root = private_l2_low_fee_settlement_coupon_payload_root(
            "COUNTERS",
            &self.counters.public_record(),
        );
        let coupon_book_root = map_root("COUPON-BOOKS", &self.coupon_books);
        let encrypted_mint_root = map_root("ENCRYPTED-MINTS", &self.encrypted_mints);
        let fee_quote_lock_root = map_root("FEE-QUOTE-LOCKS", &self.fee_quote_locks);
        let sponsor_reservation_root = map_root("SPONSOR-RESERVATIONS", &self.sponsor_reservations);
        let settlement_batch_root = map_root("SETTLEMENT-BATCHES", &self.settlement_batches);
        let receipt_root = map_root("RECEIPTS", &self.settlement_receipts);
        let rebate_root = map_root("REBATES", &self.rebates);
        let revocation_root = map_root("REVOCATIONS", &self.revocations);
        let nullifier_root = set_root("NULLIFIER-FENCE", &self.nullifier_fence);
        let replay_fence_root = set_root("REPLAY-FENCE", &self.replay_fence);
        let runtime_root = private_l2_low_fee_settlement_coupon_merkle_root(
            "PRIVATE-L2-LOW-FEE-SETTLEMENT-COUPON-RUNTIME",
            vec![
                json!(config_root),
                json!(counters_root),
                json!(coupon_book_root),
                json!(encrypted_mint_root),
                json!(fee_quote_lock_root),
                json!(sponsor_reservation_root),
                json!(settlement_batch_root),
                json!(receipt_root),
                json!(rebate_root),
                json!(revocation_root),
                json!(nullifier_root),
                json!(replay_fence_root),
            ],
        );
        let state_root = private_l2_low_fee_settlement_coupon_payload_root(
            "STATE",
            &json!({
                "runtime_root": runtime_root,
                "height": self.current_height,
                "chain_id": CHAIN_ID
            }),
        );
        Roots {
            config_root,
            counters_root,
            coupon_book_root,
            encrypted_mint_root,
            fee_quote_lock_root,
            sponsor_reservation_root,
            settlement_batch_root,
            receipt_root,
            rebate_root,
            revocation_root,
            nullifier_root,
            replay_fence_root,
            runtime_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_low_fee_settlement_coupon_runtime",
            "protocol_version": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "runtime_root": roots.runtime_root,
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
            "book_count": self.coupon_books.len(),
            "mint_count": self.encrypted_mints.len(),
            "quote_lock_count": self.fee_quote_locks.len(),
            "reservation_count": self.sponsor_reservations.len(),
            "batch_count": self.settlement_batches.len(),
            "receipt_count": self.settlement_receipts.len(),
            "rebate_count": self.rebates.len(),
            "revocation_count": self.revocations.len(),
            "nullifier_fence_count": self.nullifier_fence.len(),
            "replay_fence_count": self.replay_fence.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": private_l2_low_fee_settlement_coupon_state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_low_fee_settlement_coupon_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<()> {
        if self.config.require_nullifier_fence
            && !self.nullifier_fence.insert(nullifier.to_string())
        {
            return Err(format!("nullifier already consumed: {nullifier}"));
        }
        Ok(())
    }

    fn consume_replay_tag(
        &mut self,
        replay_tag: &str,
    ) -> PrivateL2LowFeeSettlementCouponRuntimeResult<()> {
        if self.config.require_replay_fence && !self.replay_fence.insert(replay_tag.to_string()) {
            return Err(format!("replay tag already consumed: {replay_tag}"));
        }
        Ok(())
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for CouponBook {
    fn public_record(&self) -> Value {
        CouponBook::public_record(self)
    }
}

impl PublicRecord for EncryptedCouponMint {
    fn public_record(&self) -> Value {
        EncryptedCouponMint::public_record(self)
    }
}

impl PublicRecord for FeeQuoteLock {
    fn public_record(&self) -> Value {
        FeeQuoteLock::public_record(self)
    }
}

impl PublicRecord for SponsorReservation {
    fn public_record(&self) -> Value {
        SponsorReservation::public_record(self)
    }
}

impl PublicRecord for SettlementCouponBatch {
    fn public_record(&self) -> Value {
        SettlementCouponBatch::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for CouponRebate {
    fn public_record(&self) -> Value {
        CouponRebate::public_record(self)
    }
}

impl PublicRecord for RevocationFence {
    fn public_record(&self) -> Value {
        RevocationFence::public_record(self)
    }
}

pub type Runtime = State;

pub fn private_l2_low_fee_settlement_coupon_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_l2_low_fee_settlement_coupon_state_root_from_record(record: &Value) -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "PRIVATE-L2-LOW-FEE-SETTLEMENT-COUPON-STATE",
        record,
    )
}

pub fn private_l2_low_fee_settlement_coupon_merkle_root(
    domain: &str,
    leaves: Vec<Value>,
) -> String {
    merkle_root(domain, &leaves)
}

pub fn deterministic_id(label: &str, nonce: u64, parts: &[&str]) -> String {
    let parts_json = json!(parts);
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-SETTLEMENT-COUPON-ID-{label}"),
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Json(&parts_json),
        ],
        32,
    )
}

pub fn roots_only_payload(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "kind": "private_l2_low_fee_settlement_coupon_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": private_l2_low_fee_settlement_coupon_payload_root("ROOTS-ONLY-PAYLOAD", payload),
    })
}

fn map_root<T: PublicRecord>(label: &str, values: &BTreeMap<String, T>) -> String {
    private_l2_low_fee_settlement_coupon_merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-SETTLEMENT-COUPON-{label}"),
        values.values().map(|value| value.public_record()).collect(),
    )
}

fn set_root(label: &str, values: &BTreeSet<String>) -> String {
    private_l2_low_fee_settlement_coupon_merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-SETTLEMENT-COUPON-{label}"),
        values.iter().map(|value| json!(value)).collect(),
    )
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    private_l2_low_fee_settlement_coupon_merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-SETTLEMENT-COUPON-{label}"),
        ids.iter().map(|id| json!(id)).collect(),
    )
}

fn low_fee_score(
    locked_fee_micro_units: u64,
    max_execution_delay_blocks: u64,
    latency_weight: u64,
) -> u64 {
    let fee_penalty = locked_fee_micro_units / 10;
    let delay_penalty = max_execution_delay_blocks.saturating_mul(100);
    latency_weight
        .saturating_mul(1_000)
        .saturating_sub(fee_penalty)
        .saturating_sub(delay_penalty)
}

fn require_non_empty(label: &str, value: &str) -> PrivateL2LowFeeSettlementCouponRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> PrivateL2LowFeeSettlementCouponRuntimeResult<()> {
    if value > PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_MAX_BPS {
        return Err(format!("{label} must be <= 10000 bps"));
    }
    Ok(())
}

pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_001: &str =
    "coupon_fast_path_hint_001";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_002: &str =
    "coupon_fast_path_hint_002";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_003: &str =
    "coupon_fast_path_hint_003";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_004: &str =
    "coupon_fast_path_hint_004";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_005: &str =
    "coupon_fast_path_hint_005";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_006: &str =
    "coupon_fast_path_hint_006";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_007: &str =
    "coupon_fast_path_hint_007";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_008: &str =
    "coupon_fast_path_hint_008";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_009: &str =
    "coupon_fast_path_hint_009";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_010: &str =
    "coupon_fast_path_hint_010";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_011: &str =
    "coupon_fast_path_hint_011";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_012: &str =
    "coupon_fast_path_hint_012";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_013: &str =
    "coupon_fast_path_hint_013";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_014: &str =
    "coupon_fast_path_hint_014";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_015: &str =
    "coupon_fast_path_hint_015";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_016: &str =
    "coupon_fast_path_hint_016";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_017: &str =
    "coupon_fast_path_hint_017";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_018: &str =
    "coupon_fast_path_hint_018";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_019: &str =
    "coupon_fast_path_hint_019";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_020: &str =
    "coupon_fast_path_hint_020";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_021: &str =
    "coupon_fast_path_hint_021";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_022: &str =
    "coupon_fast_path_hint_022";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_023: &str =
    "coupon_fast_path_hint_023";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_024: &str =
    "coupon_fast_path_hint_024";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_025: &str =
    "coupon_fast_path_hint_025";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_026: &str =
    "coupon_fast_path_hint_026";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_027: &str =
    "coupon_fast_path_hint_027";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_028: &str =
    "coupon_fast_path_hint_028";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_029: &str =
    "coupon_fast_path_hint_029";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_030: &str =
    "coupon_fast_path_hint_030";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_031: &str =
    "coupon_fast_path_hint_031";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_032: &str =
    "coupon_fast_path_hint_032";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_033: &str =
    "coupon_fast_path_hint_033";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_034: &str =
    "coupon_fast_path_hint_034";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_035: &str =
    "coupon_fast_path_hint_035";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_036: &str =
    "coupon_fast_path_hint_036";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_037: &str =
    "coupon_fast_path_hint_037";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_038: &str =
    "coupon_fast_path_hint_038";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_039: &str =
    "coupon_fast_path_hint_039";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_040: &str =
    "coupon_fast_path_hint_040";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_041: &str =
    "coupon_fast_path_hint_041";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_042: &str =
    "coupon_fast_path_hint_042";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_043: &str =
    "coupon_fast_path_hint_043";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_044: &str =
    "coupon_fast_path_hint_044";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_045: &str =
    "coupon_fast_path_hint_045";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_046: &str =
    "coupon_fast_path_hint_046";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_047: &str =
    "coupon_fast_path_hint_047";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_048: &str =
    "coupon_fast_path_hint_048";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_049: &str =
    "coupon_fast_path_hint_049";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_050: &str =
    "coupon_fast_path_hint_050";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_051: &str =
    "coupon_fast_path_hint_051";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_052: &str =
    "coupon_fast_path_hint_052";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_053: &str =
    "coupon_fast_path_hint_053";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_054: &str =
    "coupon_fast_path_hint_054";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_055: &str =
    "coupon_fast_path_hint_055";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_056: &str =
    "coupon_fast_path_hint_056";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_057: &str =
    "coupon_fast_path_hint_057";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_058: &str =
    "coupon_fast_path_hint_058";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_059: &str =
    "coupon_fast_path_hint_059";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_060: &str =
    "coupon_fast_path_hint_060";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_061: &str =
    "coupon_fast_path_hint_061";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_062: &str =
    "coupon_fast_path_hint_062";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_063: &str =
    "coupon_fast_path_hint_063";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_064: &str =
    "coupon_fast_path_hint_064";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_065: &str =
    "coupon_fast_path_hint_065";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_066: &str =
    "coupon_fast_path_hint_066";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_067: &str =
    "coupon_fast_path_hint_067";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_068: &str =
    "coupon_fast_path_hint_068";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_069: &str =
    "coupon_fast_path_hint_069";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_070: &str =
    "coupon_fast_path_hint_070";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_071: &str =
    "coupon_fast_path_hint_071";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_072: &str =
    "coupon_fast_path_hint_072";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_073: &str =
    "coupon_fast_path_hint_073";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_074: &str =
    "coupon_fast_path_hint_074";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_075: &str =
    "coupon_fast_path_hint_075";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_076: &str =
    "coupon_fast_path_hint_076";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_077: &str =
    "coupon_fast_path_hint_077";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_078: &str =
    "coupon_fast_path_hint_078";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_079: &str =
    "coupon_fast_path_hint_079";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_080: &str =
    "coupon_fast_path_hint_080";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_081: &str =
    "coupon_fast_path_hint_081";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_082: &str =
    "coupon_fast_path_hint_082";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_083: &str =
    "coupon_fast_path_hint_083";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_084: &str =
    "coupon_fast_path_hint_084";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_085: &str =
    "coupon_fast_path_hint_085";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_086: &str =
    "coupon_fast_path_hint_086";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_087: &str =
    "coupon_fast_path_hint_087";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_088: &str =
    "coupon_fast_path_hint_088";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_089: &str =
    "coupon_fast_path_hint_089";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_090: &str =
    "coupon_fast_path_hint_090";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_091: &str =
    "coupon_fast_path_hint_091";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_092: &str =
    "coupon_fast_path_hint_092";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_093: &str =
    "coupon_fast_path_hint_093";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_094: &str =
    "coupon_fast_path_hint_094";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_095: &str =
    "coupon_fast_path_hint_095";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_096: &str =
    "coupon_fast_path_hint_096";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_097: &str =
    "coupon_fast_path_hint_097";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_098: &str =
    "coupon_fast_path_hint_098";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_099: &str =
    "coupon_fast_path_hint_099";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_100: &str =
    "coupon_fast_path_hint_100";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_101: &str =
    "coupon_fast_path_hint_101";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_102: &str =
    "coupon_fast_path_hint_102";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_103: &str =
    "coupon_fast_path_hint_103";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_104: &str =
    "coupon_fast_path_hint_104";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_105: &str =
    "coupon_fast_path_hint_105";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_106: &str =
    "coupon_fast_path_hint_106";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_107: &str =
    "coupon_fast_path_hint_107";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_108: &str =
    "coupon_fast_path_hint_108";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_109: &str =
    "coupon_fast_path_hint_109";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_110: &str =
    "coupon_fast_path_hint_110";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_111: &str =
    "coupon_fast_path_hint_111";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_112: &str =
    "coupon_fast_path_hint_112";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_113: &str =
    "coupon_fast_path_hint_113";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_114: &str =
    "coupon_fast_path_hint_114";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_115: &str =
    "coupon_fast_path_hint_115";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_116: &str =
    "coupon_fast_path_hint_116";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_117: &str =
    "coupon_fast_path_hint_117";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_118: &str =
    "coupon_fast_path_hint_118";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_119: &str =
    "coupon_fast_path_hint_119";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_120: &str =
    "coupon_fast_path_hint_120";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_121: &str =
    "coupon_fast_path_hint_121";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_122: &str =
    "coupon_fast_path_hint_122";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_123: &str =
    "coupon_fast_path_hint_123";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_124: &str =
    "coupon_fast_path_hint_124";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_125: &str =
    "coupon_fast_path_hint_125";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_126: &str =
    "coupon_fast_path_hint_126";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_127: &str =
    "coupon_fast_path_hint_127";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_128: &str =
    "coupon_fast_path_hint_128";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_129: &str =
    "coupon_fast_path_hint_129";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_130: &str =
    "coupon_fast_path_hint_130";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_131: &str =
    "coupon_fast_path_hint_131";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_132: &str =
    "coupon_fast_path_hint_132";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_133: &str =
    "coupon_fast_path_hint_133";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_134: &str =
    "coupon_fast_path_hint_134";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_135: &str =
    "coupon_fast_path_hint_135";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_136: &str =
    "coupon_fast_path_hint_136";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_137: &str =
    "coupon_fast_path_hint_137";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_138: &str =
    "coupon_fast_path_hint_138";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_139: &str =
    "coupon_fast_path_hint_139";
pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_140: &str =
    "coupon_fast_path_hint_140";

pub fn coupon_fast_path_hint_catalog() -> Vec<&'static str> {
    vec![
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_001,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_002,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_003,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_004,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_005,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_006,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_007,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_008,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_009,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_010,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_011,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_012,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_013,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_014,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_015,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_016,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_017,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_018,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_019,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_020,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_021,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_022,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_023,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_024,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_025,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_026,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_027,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_028,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_029,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_030,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_031,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_032,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_033,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_034,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_035,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_036,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_037,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_038,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_039,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_040,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_041,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_042,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_043,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_044,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_045,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_046,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_047,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_048,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_049,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_050,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_051,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_052,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_053,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_054,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_055,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_056,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_057,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_058,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_059,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_060,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_061,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_062,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_063,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_064,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_065,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_066,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_067,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_068,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_069,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_070,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_071,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_072,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_073,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_074,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_075,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_076,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_077,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_078,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_079,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_080,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_081,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_082,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_083,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_084,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_085,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_086,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_087,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_088,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_089,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_090,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_091,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_092,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_093,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_094,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_095,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_096,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_097,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_098,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_099,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_100,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_101,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_102,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_103,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_104,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_105,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_106,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_107,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_108,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_109,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_110,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_111,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_112,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_113,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_114,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_115,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_116,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_117,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_118,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_119,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_120,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_121,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_122,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_123,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_124,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_125,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_126,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_127,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_128,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_129,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_130,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_131,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_132,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_133,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_134,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_135,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_136,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_137,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_138,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_139,
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_140,
    ]
}

pub fn coupon_policy_hint_001_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-001",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_001, "priority": 1}),
    )
}

pub fn coupon_policy_hint_002_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-002",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_002, "priority": 2}),
    )
}

pub fn coupon_policy_hint_003_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-003",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_003, "priority": 3}),
    )
}

pub fn coupon_policy_hint_004_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-004",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_004, "priority": 4}),
    )
}

pub fn coupon_policy_hint_005_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-005",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_005, "priority": 5}),
    )
}

pub fn coupon_policy_hint_006_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-006",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_006, "priority": 6}),
    )
}

pub fn coupon_policy_hint_007_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-007",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_007, "priority": 7}),
    )
}

pub fn coupon_policy_hint_008_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-008",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_008, "priority": 8}),
    )
}

pub fn coupon_policy_hint_009_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-009",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_009, "priority": 9}),
    )
}

pub fn coupon_policy_hint_010_root() -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "POLICY-HINT-010",
        &json!({"hint": PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_FAST_PATH_HINT_010, "priority": 10}),
    )
}

pub const PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_INDEX_LABELS: [&str; 24] = [
    "coupon_book_by_lane",
    "coupon_book_by_sponsor",
    "coupon_book_by_contract",
    "encrypted_mint_by_book",
    "encrypted_mint_by_owner",
    "encrypted_mint_by_recipient",
    "encrypted_mint_by_fee_asset",
    "fee_quote_lock_by_mint",
    "fee_quote_lock_by_quoter",
    "fee_quote_lock_by_score",
    "sponsor_reservation_by_mint",
    "sponsor_reservation_by_sponsor",
    "sponsor_reservation_by_budget",
    "settlement_batch_by_lane",
    "settlement_batch_by_aggregator",
    "settlement_batch_by_status",
    "settlement_receipt_by_batch",
    "settlement_receipt_by_mint",
    "settlement_receipt_by_reservation",
    "coupon_rebate_by_receipt",
    "coupon_rebate_by_beneficiary",
    "revocation_by_subject",
    "replay_fence_by_tag",
    "nullifier_fence_by_commitment",
];

pub fn coupon_index_label_root(label: &str) -> String {
    private_l2_low_fee_settlement_coupon_payload_root(
        "INDEX-LABEL",
        &json!({
            "label": label,
            "chain_id": CHAIN_ID,
        }),
    )
}

pub fn coupon_index_catalog_root() -> String {
    private_l2_low_fee_settlement_coupon_merkle_root(
        "PRIVATE-L2-LOW-FEE-SETTLEMENT-COUPON-INDEX-CATALOG",
        PRIVATE_L2_LOW_FEE_SETTLEMENT_COUPON_RUNTIME_INDEX_LABELS
            .iter()
            .map(|label| {
                json!({
                    "label": label,
                    "root": coupon_index_label_root(label),
                })
            })
            .collect(),
    )
}
