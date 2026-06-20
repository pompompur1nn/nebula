use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenCollateralVaultRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = PrivateL2ConfidentialTokenCollateralVaultRuntimeResult<T>;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-collateral-vault-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-collateral-vault-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_VAULT_SCHEME: &str =
    "monero-private-l2-confidential-token-collateral-vault-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEPOSIT_NOTE_SCHEME: &str =
    "monero-private-l2-encrypted-token-collateral-deposit-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_LOCK_SCHEME: &str =
    "monero-private-l2-confidential-token-collateral-lock-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_BORROW_CAPACITY_SCHEME: &str =
    "monero-private-l2-borrow-capacity-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_LIQUIDATION_GUARD_SCHEME: &str =
    "monero-private-l2-confidential-token-liquidation-guard-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_REDEMPTION_BATCH_SCHEME: &str =
    "monero-private-l2-confidential-token-redemption-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_SPONSOR_RESERVATION_SCHEME: &str =
    "monero-private-l2-collateral-vault-sponsor-reservation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-token-collateral-vault-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_REBATE_SCHEME: &str =
    "monero-private-l2-confidential-token-collateral-vault-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_PRIVACY_FENCE_SCHEME: &str =
    "monero-private-l2-confidential-token-collateral-nullifier-fence-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_EVENT_SCHEME: &str =
    "monero-private-l2-confidential-token-collateral-vault-event-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEVNET_HEIGHT: u64 = 812_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-token-collateral-vault-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID: &str =
    "asset:wxmr";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_DEBT_ASSET_ID: &str =
    "asset:private-dusd";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_VAULTS: usize =
    131_072;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_DEPOSIT_NOTES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_LOCKS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_REDEMPTIONS: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    8_192;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 131_072;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MIN_COLLATERAL_FACTOR_BPS:
    u64 = 15_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_LIQUIDATION_THRESHOLD_BPS:
    u64 = 12_500;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_LOCK_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    MoneroBacked,
    PrivateTokenBasket,
    StablecoinBorrow,
    CrossMargin,
    IsolatedCollateral,
    InstitutionalCustody,
}

impl VaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBacked => "monero_backed",
            Self::PrivateTokenBasket => "private_token_basket",
            Self::StablecoinBorrow => "stablecoin_borrow",
            Self::CrossMargin => "cross_margin",
            Self::IsolatedCollateral => "isolated_collateral",
            Self::InstitutionalCustody => "institutional_custody",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    DepositOnly,
    BorrowOnly,
    RedemptionOnly,
    LiquidationOnly,
    Paused,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::BorrowOnly => "borrow_only",
            Self::RedemptionOnly => "redemption_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }

    pub fn accepts_borrows(self) -> bool {
        matches!(self, Self::Active | Self::BorrowOnly)
    }

    pub fn accepts_redemptions(self) -> bool {
        matches!(self, Self::Active | Self::RedemptionOnly)
    }

    pub fn accepts_liquidations(self) -> bool {
        matches!(self, Self::Active | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositNoteStatus {
    Submitted,
    Accepted,
    Locked,
    Encumbered,
    Redeemed,
    LiquidationPending,
    Liquidated,
    Expired,
    Rejected,
}

impl DepositNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Locked => "locked",
            Self::Encumbered => "encumbered",
            Self::Redeemed => "redeemed",
            Self::LiquidationPending => "liquidation_pending",
            Self::Liquidated => "liquidated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Accepted | Self::Locked | Self::Encumbered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStatus {
    Pending,
    Active,
    CapacityAttested,
    Sponsored,
    Settled,
    Released,
    LiquidationPending,
    Liquidated,
    Expired,
    Cancelled,
}

impl LockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::CapacityAttested => "capacity_attested",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::LiquidationPending => "liquidation_pending",
            Self::Liquidated => "liquidated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityVerdict {
    Pending,
    Healthy,
    Watch,
    ReduceOnly,
    BorrowBlocked,
    Liquidatable,
    Rejected,
}

impl CapacityVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::BorrowBlocked => "borrow_blocked",
            Self::Liquidatable => "liquidatable",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_borrow(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(self, Self::ReduceOnly | Self::Liquidatable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationGuardStatus {
    Armed,
    GracePeriod,
    AuctionReady,
    BlockedByOracle,
    BlockedByFence,
    Executed,
    Cancelled,
}

impl LiquidationGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::GracePeriod => "grace_period",
            Self::AuctionReady => "auction_ready",
            Self::BlockedByOracle => "blocked_by_oracle",
            Self::BlockedByFence => "blocked_by_fence",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionBatchStatus {
    Open,
    Sealed,
    Sponsored,
    Settled,
    PartiallySettled,
    Expired,
    Cancelled,
}

impl RedemptionBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Rebated,
    Expired,
    Cancelled,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementKind {
    DepositAccepted,
    CollateralLocked,
    BorrowDrawn,
    RedemptionSettled,
    LiquidationSettled,
    SponsorConsumed,
    RebateIssued,
}

impl SettlementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositAccepted => "deposit_accepted",
            Self::CollateralLocked => "collateral_locked",
            Self::BorrowDrawn => "borrow_drawn",
            Self::RedemptionSettled => "redemption_settled",
            Self::LiquidationSettled => "liquidation_settled",
            Self::SponsorConsumed => "sponsor_consumed",
            Self::RebateIssued => "rebate_issued",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    NullifierSpent,
    ViewTagCollision,
    AmountBucketReuse,
    RingSetTooSmall,
    OracleEpochMismatch,
    SponsorLinkage,
    RedemptionBatchLeakage,
}

impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierSpent => "nullifier_spent",
            Self::ViewTagCollision => "view_tag_collision",
            Self::AmountBucketReuse => "amount_bucket_reuse",
            Self::RingSetTooSmall => "ring_set_too_small",
            Self::OracleEpochMismatch => "oracle_epoch_mismatch",
            Self::SponsorLinkage => "sponsor_linkage",
            Self::RedemptionBatchLeakage => "redemption_batch_leakage",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub low_fee_lane_id: String,
    pub default_collateral_asset_id: String,
    pub default_debt_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub min_collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub target_rebate_bps: u64,
    pub note_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_vaults: usize,
    pub max_deposit_notes: usize,
    pub max_locks: usize,
    pub max_attestations: usize,
    pub max_redemption_batches: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            monero_network:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            low_fee_lane_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE
                    .to_string(),
            default_collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            default_debt_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_DEBT_ASSET_ID
                    .to_string(),
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            min_collateral_factor_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MIN_COLLATERAL_FACTOR_BPS,
            liquidation_threshold_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_LIQUIDATION_THRESHOLD_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            note_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_NOTE_TTL_BLOCKS,
            lock_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_LOCK_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_vaults: PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_VAULTS,
            max_deposit_notes:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_DEPOSIT_NOTES,
            max_locks: PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_LOCKS,
            max_attestations:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_redemption_batches:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_MAX_REDEMPTIONS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub vaults: u64,
    pub deposit_notes: u64,
    pub collateral_locks: u64,
    pub borrow_capacity_attestations: u64,
    pub liquidation_guards: u64,
    pub redemption_batches: u64,
    pub sponsor_reservations: u64,
    pub settlement_receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub events: u64,
    pub active_vaults: u64,
    pub live_notes: u64,
    pub locked_notes: u64,
    pub open_redemption_batches: u64,
    pub total_collateral_bucket_units: u128,
    pub total_debt_bucket_units: u128,
    pub total_reserved_fee_units: u128,
    pub total_rebate_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub deposit_note_root: String,
    pub collateral_lock_root: String,
    pub borrow_capacity_root: String,
    pub liquidation_guard_root: String,
    pub redemption_batch_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub risk_metric_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-TOKEN-COLLATERAL-VAULT-CONFIG", &[]),
            vault_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_VAULT_SCHEME,
                &[],
            ),
            deposit_note_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEPOSIT_NOTE_SCHEME,
                &[],
            ),
            collateral_lock_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_LOCK_SCHEME,
                &[],
            ),
            borrow_capacity_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_BORROW_CAPACITY_SCHEME,
                &[],
            ),
            liquidation_guard_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_LIQUIDATION_GUARD_SCHEME,
                &[],
            ),
            redemption_batch_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_REDEMPTION_BATCH_SCHEME,
                &[],
            ),
            sponsor_reservation_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_SPONSOR_RESERVATION_SCHEME,
                &[],
            ),
            settlement_receipt_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_RECEIPT_SCHEME,
                &[],
            ),
            rebate_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_REBATE_SCHEME,
                &[],
            ),
            privacy_fence_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_PRIVACY_FENCE_SCHEME,
                &[],
            ),
            nullifier_root: merkle_root("PRIVATE-L2-TOKEN-COLLATERAL-VAULT-NULLIFIER", &[]),
            event_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_EVENT_SCHEME,
                &[],
            ),
            risk_metric_root: merkle_root("PRIVATE-L2-TOKEN-COLLATERAL-VAULT-RISK-METRIC", &[]),
            public_record_root: merkle_root("PRIVATE-L2-TOKEN-COLLATERAL-VAULT-PUBLIC-RECORD", &[]),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollateralVault {
    pub vault_id: String,
    pub label: String,
    pub kind: VaultKind,
    pub status: VaultStatus,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub oracle_feed_id: String,
    pub amount_bucket_root: String,
    pub accepted_note_root: String,
    pub lock_root: String,
    pub borrow_capacity_root: String,
    pub redemption_policy_root: String,
    pub sponsor_policy_root: String,
    pub liquidation_policy_root: String,
    pub operator_commitment: String,
    pub governance_commitment: String,
    pub min_collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub metadata_root: String,
}

impl CollateralVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "label": self.label,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "amount_bucket_root": self.amount_bucket_root,
            "accepted_note_root": self.accepted_note_root,
            "lock_root": self.lock_root,
            "borrow_capacity_root": self.borrow_capacity_root,
            "redemption_policy_root": self.redemption_policy_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "liquidation_policy_root": self.liquidation_policy_root,
            "operator_commitment": self.operator_commitment,
            "governance_commitment": self.governance_commitment,
            "min_collateral_factor_bps": self.min_collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDepositNote {
    pub note_id: String,
    pub vault_id: String,
    pub owner_commitment: String,
    pub encrypted_note_payload_root: String,
    pub ciphertext_digest: String,
    pub amount_commitment: String,
    pub amount_bucket: u64,
    pub collateral_asset_id: String,
    pub deposit_nullifier_hash: String,
    pub redemption_nullifier_hash: String,
    pub view_tag_hash: String,
    pub ring_root: String,
    pub range_proof_root: String,
    pub pq_recipient_root: String,
    pub status: DepositNoteStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl EncryptedDepositNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "encrypted_note_payload_root": self.encrypted_note_payload_root,
            "ciphertext_digest": self.ciphertext_digest,
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "collateral_asset_id": self.collateral_asset_id,
            "deposit_nullifier_hash": self.deposit_nullifier_hash,
            "redemption_nullifier_hash": self.redemption_nullifier_hash,
            "view_tag_hash": self.view_tag_hash,
            "ring_root": self.ring_root,
            "range_proof_root": self.range_proof_root,
            "pq_recipient_root": self.pq_recipient_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollateralLock {
    pub lock_id: String,
    pub vault_id: String,
    pub note_id: String,
    pub borrower_commitment: String,
    pub borrow_intent_root: String,
    pub collateral_amount_bucket: u64,
    pub debt_ceiling_bucket: u64,
    pub debt_asset_id: String,
    pub capacity_attestation_id: String,
    pub sponsor_reservation_id: String,
    pub lock_nullifier_hash: String,
    pub unlock_nullifier_hash: String,
    pub status: LockStatus,
    pub locked_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl CollateralLock {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "vault_id": self.vault_id,
            "note_id": self.note_id,
            "borrower_commitment": self.borrower_commitment,
            "borrow_intent_root": self.borrow_intent_root,
            "collateral_amount_bucket": self.collateral_amount_bucket,
            "debt_ceiling_bucket": self.debt_ceiling_bucket,
            "debt_asset_id": self.debt_asset_id,
            "capacity_attestation_id": self.capacity_attestation_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "lock_nullifier_hash": self.lock_nullifier_hash,
            "unlock_nullifier_hash": self.unlock_nullifier_hash,
            "status": self.status.as_str(),
            "locked_at_height": self.locked_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BorrowCapacityAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub lock_id: String,
    pub oracle_epoch: u64,
    pub price_root: String,
    pub collateral_value_bucket: u64,
    pub debt_ceiling_bucket: u64,
    pub current_debt_bucket: u64,
    pub available_borrow_bucket: u64,
    pub collateral_factor_bps: u64,
    pub health_factor_bps: u64,
    pub verdict: CapacityVerdict,
    pub attestor_commitment: String,
    pub proof_root: String,
    pub attested_at_height: u64,
    pub valid_until_height: u64,
}

impl BorrowCapacityAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "lock_id": self.lock_id,
            "oracle_epoch": self.oracle_epoch,
            "price_root": self.price_root,
            "collateral_value_bucket": self.collateral_value_bucket,
            "debt_ceiling_bucket": self.debt_ceiling_bucket,
            "current_debt_bucket": self.current_debt_bucket,
            "available_borrow_bucket": self.available_borrow_bucket,
            "collateral_factor_bps": self.collateral_factor_bps,
            "health_factor_bps": self.health_factor_bps,
            "verdict": self.verdict.as_str(),
            "attestor_commitment": self.attestor_commitment,
            "proof_root": self.proof_root,
            "attested_at_height": self.attested_at_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidationGuard {
    pub guard_id: String,
    pub vault_id: String,
    pub lock_id: String,
    pub attestation_id: String,
    pub guard_status: LiquidationGuardStatus,
    pub protected_until_height: u64,
    pub liquidation_not_before_height: u64,
    pub oracle_guard_root: String,
    pub privacy_guard_root: String,
    pub keeper_set_root: String,
    pub max_slippage_bps: u64,
    pub penalty_bps: u64,
    pub proof_root: String,
}

impl LiquidationGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "vault_id": self.vault_id,
            "lock_id": self.lock_id,
            "attestation_id": self.attestation_id,
            "guard_status": self.guard_status.as_str(),
            "protected_until_height": self.protected_until_height,
            "liquidation_not_before_height": self.liquidation_not_before_height,
            "oracle_guard_root": self.oracle_guard_root,
            "privacy_guard_root": self.privacy_guard_root,
            "keeper_set_root": self.keeper_set_root,
            "max_slippage_bps": self.max_slippage_bps,
            "penalty_bps": self.penalty_bps,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedemptionBatch {
    pub batch_id: String,
    pub vault_id: String,
    pub status: RedemptionBatchStatus,
    pub note_root: String,
    pub redemption_nullifier_root: String,
    pub output_commitment_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub requested_collateral_bucket: u64,
    pub released_collateral_bucket: u64,
    pub fee_bucket: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settle_before_height: u64,
}

impl RedemptionBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "note_root": self.note_root,
            "redemption_nullifier_root": self.redemption_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "requested_collateral_bucket": self.requested_collateral_bucket,
            "released_collateral_bucket": self.released_collateral_bucket,
            "fee_bucket": self.fee_bucket,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settle_before_height": self.settle_before_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub kind: SettlementKind,
    pub vault_id: String,
    pub subject_id: String,
    pub input_root: String,
    pub output_root: String,
    pub consumed_nullifier_root: String,
    pub created_commitment_root: String,
    pub fee_units: u64,
    pub rebate_units: u64,
    pub sequencer_commitment: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "kind": self.kind.as_str(),
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "created_commitment_root": self.created_commitment_root,
            "fee_units": self.fee_units,
            "rebate_units": self.rebate_units,
            "sequencer_commitment": self.sequencer_commitment,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub reservation_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub claim_nullifier_hash: String,
    pub proof_root: String,
    pub issued_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.reservation_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "rebate_units": self.rebate_units,
            "rebate_bps": self.rebate_bps,
            "claim_nullifier_hash": self.claim_nullifier_hash,
            "proof_root": self.proof_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: PrivacyFenceKind,
    pub subject_id: String,
    pub vault_id: String,
    pub nullifier_hash: String,
    pub evidence_root: String,
    pub action_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "vault_id": self.vault_id,
            "nullifier_hash": self.nullifier_hash,
            "evidence_root": self.evidence_root,
            "action_root": self.action_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RiskMetrics {
    pub total_collateral_bucket_units: u128,
    pub total_debt_bucket_units: u128,
    pub available_borrow_bucket_units: u128,
    pub weighted_collateral_factor_bps: u64,
    pub lowest_health_factor_bps: u64,
    pub liquidatable_lock_count: u64,
    pub guarded_lock_count: u64,
    pub redemption_queue_bucket_units: u128,
    pub privacy_fence_count: u64,
    pub oracle_epoch: u64,
    pub updated_at_height: u64,
}

impl RiskMetrics {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub counters: Counters,
    pub vaults: BTreeMap<String, CollateralVault>,
    pub deposit_notes: BTreeMap<String, EncryptedDepositNote>,
    pub collateral_locks: BTreeMap<String, CollateralLock>,
    pub borrow_capacity_attestations: BTreeMap<String, BorrowCapacityAttestation>,
    pub liquidation_guards: BTreeMap<String, LiquidationGuard>,
    pub redemption_batches: BTreeMap<String, RedemptionBatch>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub risk_metrics: RiskMetrics,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub public_records: BTreeMap<String, Value>,
}

pub type Runtime = State;

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            current_height: 0,
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            deposit_notes: BTreeMap::new(),
            collateral_locks: BTreeMap::new(),
            borrow_capacity_attestations: BTreeMap::new(),
            liquidation_guards: BTreeMap::new(),
            redemption_batches: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            risk_metrics: RiskMetrics::default(),
            events: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            current_height: PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEVNET_HEIGHT,
            ..Self::default()
        };

        let base_height = state.current_height;
        let vault_id = deterministic_vault_id(
            "devnet-wxmr-collateral",
            VaultKind::MoneroBacked,
            PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID,
            PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_DEBT_ASSET_ID,
            base_height - 240,
        );
        let note_id = deterministic_deposit_note_id(&vault_id, "devnet-borrower-alpha", 1);
        let lock_id = deterministic_collateral_lock_id(&vault_id, &note_id, "devnet-borrow-alpha");
        let attestation_id = deterministic_borrow_capacity_attestation_id(&lock_id, 42);
        let reservation_id = deterministic_sponsor_reservation_id(&lock_id, "devnet-sponsor-01");
        let receipt_id =
            deterministic_settlement_receipt_id(&lock_id, "borrow-drawn", base_height - 8);
        let rebate_id = deterministic_rebate_id(&reservation_id, &receipt_id);
        let guard_id = deterministic_liquidation_guard_id(&lock_id, &attestation_id);
        let batch_id = deterministic_redemption_batch_id(&vault_id, base_height / 16);
        let fence_id = deterministic_privacy_fence_id(&vault_id, &note_id, "view-tag-watch");

        let vault = CollateralVault {
            vault_id: vault_id.clone(),
            label: "Devnet wXMR private collateral vault".to_string(),
            kind: VaultKind::MoneroBacked,
            status: VaultStatus::Active,
            collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            debt_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEFAULT_DEBT_ASSET_ID
                    .to_string(),
            oracle_feed_id: "oracle:wxmr-usd-devnet-v3".to_string(),
            amount_bucket_root: root_from_record(
                "DEVNET-COLLATERAL-AMOUNT-BUCKET",
                &json!([64, 128, 256]),
            ),
            accepted_note_root: root_from_record("DEVNET-ACCEPTED-DEPOSIT-NOTE", &json!([note_id])),
            lock_root: root_from_record("DEVNET-COLLATERAL-LOCK", &json!([lock_id])),
            borrow_capacity_root: root_from_record(
                "DEVNET-BORROW-CAPACITY",
                &json!([attestation_id]),
            ),
            redemption_policy_root: root_from_record(
                "DEVNET-REDEMPTION-POLICY",
                &json!({"batch_size": 8192, "min_delay": 6}),
            ),
            sponsor_policy_root: root_from_record(
                "DEVNET-SPONSOR-POLICY",
                &json!({"lane": state.config.low_fee_lane_id, "rebate_bps": state.config.target_rebate_bps}),
            ),
            liquidation_policy_root: root_from_record(
                "DEVNET-LIQUIDATION-POLICY",
                &json!({"threshold_bps": state.config.liquidation_threshold_bps, "bonus_bps": 650}),
            ),
            operator_commitment: deterministic_commitment("operator", "devnet-vault-operator"),
            governance_commitment: deterministic_commitment("governance", "devnet-risk-council"),
            min_collateral_factor_bps: state.config.min_collateral_factor_bps,
            liquidation_threshold_bps: state.config.liquidation_threshold_bps,
            liquidation_bonus_bps: 650,
            max_user_fee_bps: state.config.max_user_fee_bps,
            privacy_set_size: state.config.batch_privacy_set_size,
            created_at_height: base_height - 240,
            updated_at_height: base_height - 2,
            metadata_root: root_from_record(
                "DEVNET-VAULT-METADATA",
                &json!({"region": "devnet", "mode": "confidential-collateral"}),
            ),
        };

        let note = EncryptedDepositNote {
            note_id: note_id.clone(),
            vault_id: vault_id.clone(),
            owner_commitment: deterministic_commitment("owner", "devnet-borrower-alpha"),
            encrypted_note_payload_root: root_from_record(
                "DEVNET-ENCRYPTED-NOTE-PAYLOAD",
                &json!({"cipher": "devnet-pq-sealed", "bucket": 128}),
            ),
            ciphertext_digest: deterministic_commitment("ciphertext", "note-alpha"),
            amount_commitment: deterministic_commitment("amount", "128-wxmr-bucket"),
            amount_bucket: 128,
            collateral_asset_id: vault.collateral_asset_id.clone(),
            deposit_nullifier_hash: deterministic_nullifier("deposit", &note_id),
            redemption_nullifier_hash: deterministic_nullifier("redeem", &note_id),
            view_tag_hash: deterministic_commitment("view-tag", "alpha"),
            ring_root: root_from_record("DEVNET-RING", &json!(["ring-a", "ring-b", "ring-c"])),
            range_proof_root: deterministic_commitment("range-proof", "note-alpha"),
            pq_recipient_root: deterministic_commitment("pq-recipient", "alpha"),
            status: DepositNoteStatus::Encumbered,
            submitted_at_height: base_height - 42,
            expires_at_height: base_height + state.config.note_ttl_blocks,
            metadata_root: root_from_record(
                "DEVNET-NOTE-METADATA",
                &json!({"deposit_lane": "wxmr"}),
            ),
        };

        let lock = CollateralLock {
            lock_id: lock_id.clone(),
            vault_id: vault_id.clone(),
            note_id: note_id.clone(),
            borrower_commitment: note.owner_commitment.clone(),
            borrow_intent_root: root_from_record(
                "DEVNET-BORROW-INTENT",
                &json!({"debt_bucket": 72, "debt_asset": vault.debt_asset_id}),
            ),
            collateral_amount_bucket: 128,
            debt_ceiling_bucket: 85,
            debt_asset_id: vault.debt_asset_id.clone(),
            capacity_attestation_id: attestation_id.clone(),
            sponsor_reservation_id: reservation_id.clone(),
            lock_nullifier_hash: deterministic_nullifier("lock", &lock_id),
            unlock_nullifier_hash: deterministic_nullifier("unlock", &lock_id),
            status: LockStatus::Sponsored,
            locked_at_height: base_height - 28,
            expires_at_height: base_height + state.config.lock_ttl_blocks,
            metadata_root: root_from_record(
                "DEVNET-LOCK-METADATA",
                &json!({"purpose": "stablecoin-borrow"}),
            ),
        };

        let attestation = BorrowCapacityAttestation {
            attestation_id: attestation_id.clone(),
            vault_id: vault_id.clone(),
            lock_id: lock_id.clone(),
            oracle_epoch: 42,
            price_root: deterministic_commitment("oracle-price-root", "wxmr-usd-42"),
            collateral_value_bucket: 192,
            debt_ceiling_bucket: 85,
            current_debt_bucket: 72,
            available_borrow_bucket: 13,
            collateral_factor_bps: 26_666,
            health_factor_bps: 17_800,
            verdict: CapacityVerdict::Healthy,
            attestor_commitment: deterministic_commitment("attestor", "devnet-risk-attestor"),
            proof_root: deterministic_commitment("capacity-proof", "lock-alpha"),
            attested_at_height: base_height - 24,
            valid_until_height: base_height + 24,
        };

        let guard = LiquidationGuard {
            guard_id: guard_id.clone(),
            vault_id: vault_id.clone(),
            lock_id: lock_id.clone(),
            attestation_id: attestation_id.clone(),
            guard_status: LiquidationGuardStatus::Armed,
            protected_until_height: base_height + 6,
            liquidation_not_before_height: base_height + 7,
            oracle_guard_root: deterministic_commitment("oracle-guard", "wxmr-devnet"),
            privacy_guard_root: deterministic_commitment("privacy-guard", "alpha"),
            keeper_set_root: deterministic_commitment("keeper-set", "devnet-keepers"),
            max_slippage_bps: 350,
            penalty_bps: 650,
            proof_root: deterministic_commitment("liquidation-guard-proof", "alpha"),
        };

        let batch = RedemptionBatch {
            batch_id: batch_id.clone(),
            vault_id: vault_id.clone(),
            status: RedemptionBatchStatus::Sealed,
            note_root: root_from_record("DEVNET-REDEMPTION-NOTES", &json!([note_id])),
            redemption_nullifier_root: root_from_record(
                "DEVNET-REDEMPTION-NULLIFIERS",
                &json!([note.redemption_nullifier_hash]),
            ),
            output_commitment_root: deterministic_commitment("redemption-output", "batch-alpha"),
            sponsor_reservation_root: root_from_record(
                "DEVNET-REDEMPTION-SPONSORS",
                &json!([reservation_id]),
            ),
            settlement_receipt_root: root_from_record("DEVNET-REDEMPTION-RECEIPTS", &json!([])),
            requested_collateral_bucket: 16,
            released_collateral_bucket: 0,
            fee_bucket: 1,
            privacy_set_size: state.config.batch_privacy_set_size,
            opened_at_height: base_height - 10,
            sealed_at_height: base_height - 4,
            settle_before_height: base_height + state.config.settlement_ttl_blocks,
        };

        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_commitment: deterministic_commitment("sponsor", "devnet-sponsor-01"),
            subject_id: lock_id.clone(),
            subject_kind: "collateral_lock".to_string(),
            fee_asset_id: "asset:private-dusd".to_string(),
            reserved_fee_units: 44,
            max_user_fee_bps: state.config.max_user_fee_bps,
            rebate_bps: state.config.target_rebate_bps,
            status: ReservationStatus::Consumed,
            reserved_at_height: base_height - 22,
            expires_at_height: base_height + 12,
            policy_root: deterministic_commitment("sponsor-policy", "low-fee-alpha"),
        };

        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            kind: SettlementKind::BorrowDrawn,
            vault_id: vault_id.clone(),
            subject_id: lock_id.clone(),
            input_root: root_from_record("DEVNET-BORROW-INPUTS", &json!([lock_id])),
            output_root: deterministic_commitment("borrow-output", "72-dusd"),
            consumed_nullifier_root: root_from_record(
                "DEVNET-CONSUMED-NULLIFIERS",
                &json!([lock.lock_nullifier_hash]),
            ),
            created_commitment_root: deterministic_commitment("created-debt-note", "alpha"),
            fee_units: 44,
            rebate_units: 3,
            sequencer_commitment: deterministic_commitment("sequencer", "devnet-sequencer-03"),
            settled_at_height: base_height - 8,
        };

        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            reservation_id: reservation_id.clone(),
            receipt_id: receipt_id.clone(),
            beneficiary_commitment: deterministic_commitment(
                "beneficiary",
                "devnet-borrower-alpha",
            ),
            asset_id: "asset:private-dusd".to_string(),
            rebate_units: 3,
            rebate_bps: state.config.target_rebate_bps,
            claim_nullifier_hash: deterministic_nullifier("rebate-claim", &rebate_id),
            proof_root: deterministic_commitment("rebate-proof", "alpha"),
            issued_at_height: base_height - 7,
        };

        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind: PrivacyFenceKind::ViewTagCollision,
            subject_id: note_id.clone(),
            vault_id: vault_id.clone(),
            nullifier_hash: deterministic_nullifier("fence", &note_id),
            evidence_root: deterministic_commitment("fence-evidence", "view-tag-watch"),
            action_root: deterministic_commitment("fence-action", "increase-ring"),
            opened_at_height: base_height - 6,
            expires_at_height: base_height + 30,
        };

        state
            .spent_nullifiers
            .insert(note.deposit_nullifier_hash.clone());
        state
            .spent_nullifiers
            .insert(lock.lock_nullifier_hash.clone());
        state.vaults.insert(vault_id.clone(), vault);
        state.deposit_notes.insert(note_id.clone(), note);
        state.collateral_locks.insert(lock_id.clone(), lock);
        state
            .borrow_capacity_attestations
            .insert(attestation_id.clone(), attestation);
        state.liquidation_guards.insert(guard_id, guard);
        state.redemption_batches.insert(batch_id, batch);
        state
            .sponsor_reservations
            .insert(reservation_id, reservation);
        state.settlement_receipts.insert(receipt_id, receipt);
        state.rebates.insert(rebate_id, rebate);
        state.privacy_fences.insert(fence_id, fence);
        state.refresh_derived_state();
        let bootstrap_record = state.public_record();
        state.emit_event("devnet_bootstrap", &vault_id, &bootstrap_record);
        state.refresh_derived_state();
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root(
                "PRIVATE-L2-TOKEN-COLLATERAL-VAULT-CONFIG",
                &self.config.public_record(),
            ),
            vault_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_VAULT_SCHEME,
                &self.vaults,
                CollateralVault::public_record,
            ),
            deposit_note_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_DEPOSIT_NOTE_SCHEME,
                &self.deposit_notes,
                EncryptedDepositNote::public_record,
            ),
            collateral_lock_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_LOCK_SCHEME,
                &self.collateral_locks,
                CollateralLock::public_record,
            ),
            borrow_capacity_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_BORROW_CAPACITY_SCHEME,
                &self.borrow_capacity_attestations,
                BorrowCapacityAttestation::public_record,
            ),
            liquidation_guard_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_LIQUIDATION_GUARD_SCHEME,
                &self.liquidation_guards,
                LiquidationGuard::public_record,
            ),
            redemption_batch_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_REDEMPTION_BATCH_SCHEME,
                &self.redemption_batches,
                RedemptionBatch::public_record,
            ),
            sponsor_reservation_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_SPONSOR_RESERVATION_SCHEME,
                &self.sponsor_reservations,
                SponsorReservation::public_record,
            ),
            settlement_receipt_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_RECEIPT_SCHEME,
                &self.settlement_receipts,
                SettlementReceipt::public_record,
            ),
            rebate_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_REBATE_SCHEME,
                &self.rebates,
                FeeRebate::public_record,
            ),
            privacy_fence_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_PRIVACY_FENCE_SCHEME,
                &self.privacy_fences,
                PrivacyFence::public_record,
            ),
            nullifier_root: set_root(
                "PRIVATE-L2-TOKEN-COLLATERAL-VAULT-NULLIFIER",
                &self.spent_nullifiers,
            ),
            event_root: map_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_COLLATERAL_VAULT_RUNTIME_EVENT_SCHEME,
                &self.events,
                RuntimeEvent::public_record,
            ),
            risk_metric_root: payload_root(
                "PRIVATE-L2-TOKEN-COLLATERAL-VAULT-RISK-METRIC",
                &self.risk_metrics.public_record(),
            ),
            public_record_root: map_value_root(
                "PRIVATE-L2-TOKEN-COLLATERAL-VAULT-PUBLIC-RECORD",
                &self.public_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.current_counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
            "risk_metrics": self.risk_metrics.public_record(),
            "state_root": state_root_from_record(&json!({
                "current_height": self.current_height,
                "counters": counters.public_record(),
                "roots": roots.public_record(),
                "risk_metrics": self.risk_metrics.public_record(),
            })),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn refresh_derived_state(&mut self) {
        self.counters = self.current_counters();
        self.risk_metrics = self.current_risk_metrics();
    }

    pub fn insert_public_record(&mut self, label: impl Into<String>, record: Value) {
        self.public_records.insert(label.into(), record);
    }

    pub fn emit_event(&mut self, event_kind: &str, subject_id: &str, payload: &Value) -> String {
        let payload_root = payload_root("PRIVATE-L2-TOKEN-COLLATERAL-VAULT-EVENT-PAYLOAD", payload);
        let subject_root = deterministic_commitment("event-subject", subject_id);
        let event_id =
            deterministic_event_id(event_kind, subject_id, &payload_root, self.current_height);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            payload_root,
            emitted_at_height: self.current_height,
        };
        self.events.insert(event_id.clone(), event);
        event_id
    }

    fn current_counters(&self) -> Counters {
        Counters {
            vaults: self.vaults.len() as u64,
            deposit_notes: self.deposit_notes.len() as u64,
            collateral_locks: self.collateral_locks.len() as u64,
            borrow_capacity_attestations: self.borrow_capacity_attestations.len() as u64,
            liquidation_guards: self.liquidation_guards.len() as u64,
            redemption_batches: self.redemption_batches.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            events: self.events.len() as u64,
            active_vaults: self
                .vaults
                .values()
                .filter(|vault| vault.status == VaultStatus::Active)
                .count() as u64,
            live_notes: self
                .deposit_notes
                .values()
                .filter(|note| note.status.live())
                .count() as u64,
            locked_notes: self
                .deposit_notes
                .values()
                .filter(|note| {
                    matches!(
                        note.status,
                        DepositNoteStatus::Locked | DepositNoteStatus::Encumbered
                    )
                })
                .count() as u64,
            open_redemption_batches: self
                .redemption_batches
                .values()
                .filter(|batch| {
                    matches!(
                        batch.status,
                        RedemptionBatchStatus::Open | RedemptionBatchStatus::Sealed
                    )
                })
                .count() as u64,
            total_collateral_bucket_units: self
                .deposit_notes
                .values()
                .map(|note| note.amount_bucket as u128)
                .sum(),
            total_debt_bucket_units: self
                .borrow_capacity_attestations
                .values()
                .map(|attestation| attestation.current_debt_bucket as u128)
                .sum(),
            total_reserved_fee_units: self
                .sponsor_reservations
                .values()
                .map(|reservation| reservation.reserved_fee_units as u128)
                .sum(),
            total_rebate_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_units as u128)
                .sum(),
        }
    }

    fn current_risk_metrics(&self) -> RiskMetrics {
        let attestations: Vec<&BorrowCapacityAttestation> =
            self.borrow_capacity_attestations.values().collect();
        let attestation_count = attestations.len() as u64;
        let collateral_total: u128 = attestations
            .iter()
            .map(|attestation| attestation.collateral_value_bucket as u128)
            .sum();
        let weighted_collateral_factor_bps = if collateral_total == 0 {
            0
        } else {
            let weighted: u128 = attestations
                .iter()
                .map(|attestation| {
                    attestation.collateral_value_bucket as u128
                        * attestation.collateral_factor_bps as u128
                })
                .sum();
            (weighted / collateral_total) as u64
        };
        let lowest_health_factor_bps = attestations
            .iter()
            .map(|attestation| attestation.health_factor_bps)
            .min()
            .unwrap_or(0);

        RiskMetrics {
            total_collateral_bucket_units: self
                .deposit_notes
                .values()
                .map(|note| note.amount_bucket as u128)
                .sum(),
            total_debt_bucket_units: attestations
                .iter()
                .map(|attestation| attestation.current_debt_bucket as u128)
                .sum(),
            available_borrow_bucket_units: attestations
                .iter()
                .map(|attestation| attestation.available_borrow_bucket as u128)
                .sum(),
            weighted_collateral_factor_bps,
            lowest_health_factor_bps,
            liquidatable_lock_count: attestations
                .iter()
                .filter(|attestation| attestation.verdict.allows_liquidation())
                .count() as u64,
            guarded_lock_count: self.liquidation_guards.len() as u64,
            redemption_queue_bucket_units: self
                .redemption_batches
                .values()
                .map(|batch| batch.requested_collateral_bucket as u128)
                .sum(),
            privacy_fence_count: self.privacy_fences.len() as u64,
            oracle_epoch: attestations
                .iter()
                .map(|attestation| attestation.oracle_epoch)
                .max()
                .unwrap_or(attestation_count),
            updated_at_height: self.current_height,
        }
    }
}

pub fn deterministic_vault_id(
    label: &str,
    kind: VaultKind,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(kind.as_str()),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn deterministic_deposit_note_id(vault_id: &str, owner_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-DEPOSIT-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn deterministic_collateral_lock_id(
    vault_id: &str,
    note_id: &str,
    borrow_intent_label: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-LOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(note_id),
            HashPart::Str(borrow_intent_label),
        ],
        32,
    )
}

pub fn deterministic_borrow_capacity_attestation_id(lock_id: &str, oracle_epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-BORROW-CAPACITY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lock_id),
            HashPart::Int(oracle_epoch as i128),
        ],
        32,
    )
}

pub fn deterministic_liquidation_guard_id(lock_id: &str, attestation_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-LIQUIDATION-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lock_id),
            HashPart::Str(attestation_id),
        ],
        32,
    )
}

pub fn deterministic_redemption_batch_id(vault_id: &str, batch_nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-REDEMPTION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Int(batch_nonce as i128),
        ],
        32,
    )
}

pub fn deterministic_sponsor_reservation_id(subject_id: &str, sponsor_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(sponsor_commitment),
        ],
        32,
    )
}

pub fn deterministic_settlement_receipt_id(
    subject_id: &str,
    settlement_label: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(settlement_label),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn deterministic_rebate_id(reservation_id: &str, receipt_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reservation_id),
            HashPart::Str(receipt_id),
        ],
        32,
    )
}

pub fn deterministic_privacy_fence_id(vault_id: &str, subject_id: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(subject_id),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn deterministic_event_id(
    event_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
        ],
        32,
    )
}

pub fn deterministic_commitment(label: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn deterministic_nullifier(label: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-L2-TOKEN-COLLATERAL-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-TOKEN-COLLATERAL-VAULT-PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-TOKEN-COLLATERAL-VAULT-STATE", record)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, project: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| {
            json!(root_from_record(
                domain,
                &json!({"id": id, "record": project(value)})
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(id, value)| {
            json!(root_from_record(
                domain,
                &json!({"id": id, "record": value})
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!(domain_hash(
                domain,
                &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
                32
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
