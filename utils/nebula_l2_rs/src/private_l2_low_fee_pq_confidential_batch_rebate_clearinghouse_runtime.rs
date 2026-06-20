use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-batch-rebate-clearinghouse-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_PQ_AUTH_SUITE:
    &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-low-fee-rebate-clearinghouse-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_POOL_SCHEME: &str =
    "confidential-batch-rebate-pool-commitment-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_SPONSOR_SCHEME:
    &str = "pq-sponsor-confidential-low-fee-commitment-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_COHORT_SCHEME:
    &str = "eligible-transaction-cohort-confidential-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_ATTESTATION_SCHEME:
    &str = "pq-sponsor-attestation-low-fee-rebate-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_RECEIPT_SCHEME:
    &str = "coupon-settlement-receipt-confidential-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_QUARANTINE_SCHEME:
    &str = "overspend-quarantine-control-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_REDACTION_SCHEME:
    &str = "privacy-redaction-budget-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_REPLAY_DOMAIN:
    &str = "private-l2-low-fee-pq-confidential-batch-rebate-clearinghouse-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_HEIGHT: u64 =
    918_000;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_L2_NETWORK:
    &str = "nebula-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_FEE_ASSET_ID:
    &str = "piconero-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_COUPON_ASSET_ID:
    &str = "private-l2-low-fee-coupon-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_BPS: u64 =
    10_000;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_POOL_TTL_BLOCKS:
    u64 = 288;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_COHORT_TTL_BLOCKS:
    u64 = 36;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS:
    u64 = 720;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_QUARANTINE_TTL_BLOCKS:
    u64 = 1_440;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE:
    u64 = 262_144;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 7;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 12;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MAX_SPONSOR_DRAWDOWN_BPS:
    u64 = 2_500;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS:
    usize = 65_536;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_POOLS: usize =
    524_288;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_SPONSOR_COMMITMENTS:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_COHORTS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_ATTESTATIONS:
    usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_RECEIPTS:
    usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_QUARANTINES:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_PRIVACY_BUDGETS:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_PUBLIC_RECORDS:
    usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebatePoolStatus {
    Draft,
    Open,
    Funding,
    Sealed,
    Settling,
    Drained,
    Expired,
    Quarantined,
}

impl RebatePoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Funding => "funding",
            Self::Sealed => "sealed",
            Self::Settling => "settling",
            Self::Drained => "drained",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_sponsor(self) -> bool {
        matches!(self, Self::Open | Self::Funding)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(self, Self::Sealed | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCommitmentStatus {
    Reserved,
    Attested,
    Active,
    PartiallySpent,
    Exhausted,
    Expired,
    Quarantined,
}

impl SponsorCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::PartiallySpent => "partially_spent",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Attested | Self::Active | Self::PartiallySpent)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortKind {
    MoneroPrivateTransfer,
    PrivateSwap,
    PrivateWithdrawal,
    ShieldedDeposit,
    MerchantBatch,
    PayrollBatch,
    MicroPayment,
    DandelionRelay,
}

impl CohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroPrivateTransfer => "monero_private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::PrivateWithdrawal => "private_withdrawal",
            Self::ShieldedDeposit => "shielded_deposit",
            Self::MerchantBatch => "merchant_batch",
            Self::PayrollBatch => "payroll_batch",
            Self::MicroPayment => "micro_payment",
            Self::DandelionRelay => "dandelion_relay",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Proposed,
    Eligible,
    Batched,
    Settled,
    Expired,
    Quarantined,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Eligible => "eligible",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPurpose {
    SponsorFunding,
    PoolEligibility,
    SpendAuthorization,
    CouponSettlement,
    QuarantineRelease,
    RedactionDisclosure,
}

impl AttestationPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorFunding => "sponsor_funding",
            Self::PoolEligibility => "pool_eligibility",
            Self::SpendAuthorization => "spend_authorization",
            Self::CouponSettlement => "coupon_settlement",
            Self::QuarantineRelease => "quarantine_release",
            Self::RedactionDisclosure => "redaction_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Issued,
    Settled,
    Replayed,
    Expired,
    Quarantined,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Settled => "settled",
            Self::Replayed => "replayed",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    SponsorOverspend,
    DuplicateNullifier,
    ExpiredWindow,
    PrivacyBudgetExceeded,
    InvalidPqAttestation,
    CohortMismatch,
    OperatorHold,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorOverspend => "sponsor_overspend",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::ExpiredWindow => "expired_window",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::CohortMismatch => "cohort_mismatch",
            Self::OperatorHold => "operator_hold",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub clearinghouse_id: String,
    pub pool_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub cohort_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_rebate_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_drawdown_bps: u64,
    pub max_batch_items: usize,
    pub max_pools: usize,
    pub max_sponsor_commitments: usize,
    pub max_cohorts: usize,
    pub max_attestations: usize,
    pub max_receipts: usize,
    pub max_quarantines: usize,
    pub max_privacy_budgets: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID,
            monero_network: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_FEE_ASSET_ID.to_string(),
            coupon_asset_id: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_COUPON_ASSET_ID.to_string(),
            clearinghouse_id: "private-l2-low-fee-rebate-clearinghouse-devnet".to_string(),
            pool_ttl_blocks: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_POOL_TTL_BLOCKS,
            sponsor_ttl_blocks: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            cohort_ttl_blocks: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_COHORT_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            quarantine_ttl_blocks: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_QUARANTINE_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_rebate_bps: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            max_user_fee_bps: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_drawdown_bps: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MAX_SPONSOR_DRAWDOWN_BPS,
            max_batch_items: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_pools: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_POOLS,
            max_sponsor_commitments: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_SPONSOR_COMMITMENTS,
            max_cohorts: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_COHORTS,
            max_attestations: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_ATTESTATIONS,
            max_receipts: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_RECEIPTS,
            max_quarantines: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_QUARANTINES,
            max_privacy_budgets: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_PRIVACY_BUDGETS,
            max_public_records: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "clearinghouse_id": self.clearinghouse_id,
            "pool_ttl_blocks": self.pool_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "cohort_ttl_blocks": self.cohort_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_rebate_bps": self.target_rebate_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_drawdown_bps": self.max_sponsor_drawdown_bps,
            "max_batch_items": self.max_batch_items,
            "max_pools": self.max_pools,
            "max_sponsor_commitments": self.max_sponsor_commitments,
            "max_cohorts": self.max_cohorts,
            "max_attestations": self.max_attestations,
            "max_receipts": self.max_receipts,
            "max_quarantines": self.max_quarantines,
            "max_privacy_budgets": self.max_privacy_budgets,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub sponsor_commitments: u64,
    pub cohorts: u64,
    pub attestations: u64,
    pub receipts: u64,
    pub quarantines: u64,
    pub privacy_budgets: u64,
    pub public_records: u64,
    pub expired_windows: u64,
    pub overspend_blocks: u64,
    pub coupon_settlements: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pools": self.pools,
            "sponsor_commitments": self.sponsor_commitments,
            "cohorts": self.cohorts,
            "attestations": self.attestations,
            "receipts": self.receipts,
            "quarantines": self.quarantines,
            "privacy_budgets": self.privacy_budgets,
            "public_records": self.public_records,
            "expired_windows": self.expired_windows,
            "overspend_blocks": self.overspend_blocks,
            "coupon_settlements": self.coupon_settlements,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub pool_root: String,
    pub sponsor_commitment_root: String,
    pub cohort_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub quarantine_root: String,
    pub privacy_budget_root: String,
    pub spent_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "pool_root": self.pool_root,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "cohort_root": self.cohort_root,
            "attestation_root": self.attestation_root,
            "receipt_root": self.receipt_root,
            "quarantine_root": self.quarantine_root,
            "privacy_budget_root": self.privacy_budget_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRebatePoolRequest {
    pub sponsor_namespace: String,
    pub pool_label: String,
    pub funding_commitment_root: String,
    pub coupon_commitment_root: String,
    pub eligible_cohort_root: String,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub target_rebate_bps: u64,
    pub max_user_fee_bps: u64,
    pub capacity_commitment: u64,
    pub privacy_set_size: u64,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub operator_commitment: String,
}

impl BatchRebatePoolRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_namespace": self.sponsor_namespace,
            "pool_label": self.pool_label,
            "funding_commitment_root": self.funding_commitment_root,
            "coupon_commitment_root": self.coupon_commitment_root,
            "eligible_cohort_root": self.eligible_cohort_root,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "target_rebate_bps": self.target_rebate_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "capacity_commitment": self.capacity_commitment,
            "privacy_set_size": self.privacy_set_size,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "operator_commitment": self.operator_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRebatePoolRecord {
    pub pool_id: String,
    pub sponsor_namespace: String,
    pub pool_label: String,
    pub funding_commitment_root: String,
    pub coupon_commitment_root: String,
    pub eligible_cohort_root: String,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub target_rebate_bps: u64,
    pub max_user_fee_bps: u64,
    pub capacity_commitment: u64,
    pub spent_commitment: u64,
    pub privacy_set_size: u64,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub created_at_height: u64,
    pub status: RebatePoolStatus,
    pub operator_commitment: String,
}

impl BatchRebatePoolRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_namespace": self.sponsor_namespace,
            "pool_label": self.pool_label,
            "funding_commitment_root": self.funding_commitment_root,
            "coupon_commitment_root": self.coupon_commitment_root,
            "eligible_cohort_root": self.eligible_cohort_root,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "target_rebate_bps": self.target_rebate_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "capacity_commitment": self.capacity_commitment,
            "spent_commitment": self.spent_commitment,
            "privacy_set_size": self.privacy_set_size,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("BATCH_REBATE_POOL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCommitmentRequest {
    pub pool_id: String,
    pub sponsor_id: String,
    pub sponsor_commitment_root: String,
    pub funding_note_root: String,
    pub max_rebate_commitment: u64,
    pub drawdown_limit_bps: u64,
    pub pq_public_key_root: String,
    pub expires_at_height: u64,
}

impl SponsorCommitmentRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "funding_note_root": self.funding_note_root,
            "max_rebate_commitment": self.max_rebate_commitment,
            "drawdown_limit_bps": self.drawdown_limit_bps,
            "pq_public_key_root": self.pq_public_key_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCommitmentRecord {
    pub commitment_id: String,
    pub pool_id: String,
    pub sponsor_id: String,
    pub sponsor_commitment_root: String,
    pub funding_note_root: String,
    pub max_rebate_commitment: u64,
    pub spent_rebate_commitment: u64,
    pub drawdown_limit_bps: u64,
    pub pq_public_key_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorCommitmentStatus,
}

impl SponsorCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "pool_id": self.pool_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "funding_note_root": self.funding_note_root,
            "max_rebate_commitment": self.max_rebate_commitment,
            "spent_rebate_commitment": self.spent_rebate_commitment,
            "drawdown_limit_bps": self.drawdown_limit_bps,
            "pq_public_key_root": self.pq_public_key_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EligibleTransactionCohortRequest {
    pub pool_id: String,
    pub cohort_kind: CohortKind,
    pub cohort_commitment_root: String,
    pub tx_nullifier_root: String,
    pub fee_commitment_root: String,
    pub min_transaction_count: u64,
    pub max_transaction_count: u64,
    pub aggregate_fee_commitment: u64,
    pub privacy_set_size: u64,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
}

impl EligibleTransactionCohortRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "cohort_kind": self.cohort_kind.as_str(),
            "cohort_commitment_root": self.cohort_commitment_root,
            "tx_nullifier_root": self.tx_nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "min_transaction_count": self.min_transaction_count,
            "max_transaction_count": self.max_transaction_count,
            "aggregate_fee_commitment": self.aggregate_fee_commitment,
            "privacy_set_size": self.privacy_set_size,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EligibleTransactionCohortRecord {
    pub cohort_id: String,
    pub pool_id: String,
    pub cohort_kind: CohortKind,
    pub cohort_commitment_root: String,
    pub tx_nullifier_root: String,
    pub fee_commitment_root: String,
    pub min_transaction_count: u64,
    pub max_transaction_count: u64,
    pub aggregate_fee_commitment: u64,
    pub privacy_set_size: u64,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub created_at_height: u64,
    pub status: CohortStatus,
}

impl EligibleTransactionCohortRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "pool_id": self.pool_id,
            "cohort_kind": self.cohort_kind.as_str(),
            "cohort_commitment_root": self.cohort_commitment_root,
            "tx_nullifier_root": self.tx_nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "min_transaction_count": self.min_transaction_count,
            "max_transaction_count": self.max_transaction_count,
            "aggregate_fee_commitment": self.aggregate_fee_commitment,
            "privacy_set_size": self.privacy_set_size,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestationRequest {
    pub commitment_id: String,
    pub purpose: AttestationPurpose,
    pub attested_record_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub signer_key_root: String,
    pub expires_at_height: u64,
}

impl PqSponsorAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "purpose": self.purpose.as_str(),
            "attested_record_root": self.attested_record_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "signer_key_root": self.signer_key_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestationRecord {
    pub attestation_id: String,
    pub commitment_id: String,
    pub pool_id: String,
    pub sponsor_id: String,
    pub purpose: AttestationPurpose,
    pub attested_record_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub signer_key_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSponsorAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "pool_id": self.pool_id,
            "sponsor_id": self.sponsor_id,
            "purpose": self.purpose.as_str(),
            "attested_record_root": self.attested_record_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "signer_key_root": self.signer_key_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponSettlementReceiptRequest {
    pub pool_id: String,
    pub cohort_id: String,
    pub commitment_id: String,
    pub coupon_nullifier: String,
    pub coupon_commitment_root: String,
    pub settlement_batch_root: String,
    pub rebate_amount_commitment: u64,
    pub user_fee_bps: u64,
    pub privacy_redaction_budget_id: String,
    pub expires_at_height: u64,
}

impl CouponSettlementReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "cohort_id": self.cohort_id,
            "commitment_id": self.commitment_id,
            "coupon_nullifier": self.coupon_nullifier,
            "coupon_commitment_root": self.coupon_commitment_root,
            "settlement_batch_root": self.settlement_batch_root,
            "rebate_amount_commitment": self.rebate_amount_commitment,
            "user_fee_bps": self.user_fee_bps,
            "privacy_redaction_budget_id": self.privacy_redaction_budget_id,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponSettlementReceiptRecord {
    pub receipt_id: String,
    pub pool_id: String,
    pub cohort_id: String,
    pub commitment_id: String,
    pub coupon_nullifier: String,
    pub coupon_commitment_root: String,
    pub settlement_batch_root: String,
    pub rebate_amount_commitment: u64,
    pub user_fee_bps: u64,
    pub privacy_redaction_budget_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReceiptStatus,
}

impl CouponSettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "pool_id": self.pool_id,
            "cohort_id": self.cohort_id,
            "commitment_id": self.commitment_id,
            "coupon_nullifier": self.coupon_nullifier,
            "coupon_commitment_root": self.coupon_commitment_root,
            "settlement_batch_root": self.settlement_batch_root,
            "rebate_amount_commitment": self.rebate_amount_commitment,
            "user_fee_bps": self.user_fee_bps,
            "privacy_redaction_budget_id": self.privacy_redaction_budget_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineControlRecord {
    pub quarantine_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub released: bool,
}

impl QuarantineControlRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "released": self.released,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudgetRecord {
    pub budget_id: String,
    pub pool_id: String,
    pub cohort_id: String,
    pub disclosure_root: String,
    pub allowed_fields: BTreeSet<String>,
    pub max_receipts: u64,
    pub receipts_used: u64,
    pub max_redacted_bytes: u64,
    pub redacted_bytes_used: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyRedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "pool_id": self.pool_id,
            "cohort_id": self.cohort_id,
            "disclosure_root": self.disclosure_root,
            "allowed_fields": self.allowed_fields,
            "max_receipts": self.max_receipts,
            "receipts_used": self.receipts_used,
            "max_redacted_bytes": self.max_redacted_bytes,
            "redacted_bytes_used": self.redacted_bytes_used,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn can_spend(&self, redacted_bytes: u64) -> bool {
        self.receipts_used < self.max_receipts
            && self.redacted_bytes_used.saturating_add(redacted_bytes) <= self.max_redacted_bytes
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub pools: BTreeMap<String, BatchRebatePoolRecord>,
    pub sponsor_commitments: BTreeMap<String, SponsorCommitmentRecord>,
    pub cohorts: BTreeMap<String, EligibleTransactionCohortRecord>,
    pub attestations: BTreeMap<String, PqSponsorAttestationRecord>,
    pub receipts: BTreeMap<String, CouponSettlementReceiptRecord>,
    pub quarantines: BTreeMap<String, QuarantineControlRecord>,
    pub privacy_budgets: BTreeMap<String, PrivacyRedactionBudgetRecord>,
    pub spent_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            current_height,
            pools: BTreeMap::new(),
            sponsor_commitments: BTreeMap::new(),
            cohorts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.pools = self.pools.len() as u64;
        counters.sponsor_commitments = self.sponsor_commitments.len() as u64;
        counters.cohorts = self.cohorts.len() as u64;
        counters.attestations = self.attestations.len() as u64;
        counters.receipts = self.receipts.len() as u64;
        counters.quarantines = self.quarantines.len() as u64;
        counters.privacy_budgets = self.privacy_budgets.len() as u64;
        counters.public_records = self.public_records.len() as u64;
        counters
    }

    pub fn open_pool(
        &mut self,
        request: BatchRebatePoolRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<String> {
        self.ensure_capacity(self.pools.len(), self.config.max_pools, "pools")?;
        require_nonempty("sponsor_namespace", &request.sponsor_namespace)?;
        require_nonempty("pool_label", &request.pool_label)?;
        require_root("funding_commitment_root", &request.funding_commitment_root)?;
        require_root("coupon_commitment_root", &request.coupon_commitment_root)?;
        require_root("eligible_cohort_root", &request.eligible_cohort_root)?;
        require_bps("target_rebate_bps", request.target_rebate_bps)?;
        require_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        require_window(
            "pool",
            self.current_height,
            request.opens_at_height,
            request.expires_at_height,
        )?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("pool privacy set below runtime minimum".to_string());
        }
        let sequence = self.pools.len() as u64;
        let pool_id = deterministic_id("pool", &request.public_record(), sequence);
        let record = BatchRebatePoolRecord {
            pool_id: pool_id.clone(),
            sponsor_namespace: request.sponsor_namespace,
            pool_label: request.pool_label,
            funding_commitment_root: request.funding_commitment_root,
            coupon_commitment_root: request.coupon_commitment_root,
            eligible_cohort_root: request.eligible_cohort_root,
            fee_asset_id: request.fee_asset_id,
            coupon_asset_id: request.coupon_asset_id,
            target_rebate_bps: request.target_rebate_bps,
            max_user_fee_bps: request.max_user_fee_bps,
            capacity_commitment: request.capacity_commitment,
            spent_commitment: 0,
            privacy_set_size: request.privacy_set_size,
            opens_at_height: request.opens_at_height,
            expires_at_height: request.expires_at_height,
            created_at_height: self.current_height,
            status: RebatePoolStatus::Open,
            operator_commitment: request.operator_commitment,
        };
        self.record_public(format!("pool:{pool_id}"), record.public_record())?;
        self.pools.insert(pool_id.clone(), record);
        Ok(pool_id)
    }

    pub fn reserve_sponsor_commitment(
        &mut self,
        request: SponsorCommitmentRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<String> {
        self.ensure_capacity(
            self.sponsor_commitments.len(),
            self.config.max_sponsor_commitments,
            "sponsor_commitments",
        )?;
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        if !pool.status.accepts_sponsor() {
            return Err("pool does not accept sponsor commitments".to_string());
        }
        if self.current_height > pool.expires_at_height {
            return Err("pool sponsor window expired".to_string());
        }
        require_nonempty("sponsor_id", &request.sponsor_id)?;
        require_root("sponsor_commitment_root", &request.sponsor_commitment_root)?;
        require_root("funding_note_root", &request.funding_note_root)?;
        require_root("pq_public_key_root", &request.pq_public_key_root)?;
        require_bps("drawdown_limit_bps", request.drawdown_limit_bps)?;
        if request.drawdown_limit_bps > self.config.max_sponsor_drawdown_bps {
            return Err("sponsor drawdown limit exceeds runtime cap".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("sponsor commitment expires before current height".to_string());
        }
        let sequence = self.sponsor_commitments.len() as u64;
        let commitment_id =
            deterministic_id("sponsor_commitment", &request.public_record(), sequence);
        let record = SponsorCommitmentRecord {
            commitment_id: commitment_id.clone(),
            pool_id: request.pool_id,
            sponsor_id: request.sponsor_id,
            sponsor_commitment_root: request.sponsor_commitment_root,
            funding_note_root: request.funding_note_root,
            max_rebate_commitment: request.max_rebate_commitment,
            spent_rebate_commitment: 0,
            drawdown_limit_bps: request.drawdown_limit_bps,
            pq_public_key_root: request.pq_public_key_root,
            created_at_height: self.current_height,
            expires_at_height: request.expires_at_height,
            status: SponsorCommitmentStatus::Reserved,
        };
        self.record_public(
            format!("sponsor_commitment:{commitment_id}"),
            record.public_record(),
        )?;
        self.sponsor_commitments
            .insert(commitment_id.clone(), record);
        Ok(commitment_id)
    }

    pub fn register_cohort(
        &mut self,
        request: EligibleTransactionCohortRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<String> {
        self.ensure_capacity(self.cohorts.len(), self.config.max_cohorts, "cohorts")?;
        if !self.pools.contains_key(&request.pool_id) {
            return Err(format!("unknown pool {}", request.pool_id));
        }
        require_root("cohort_commitment_root", &request.cohort_commitment_root)?;
        require_root("tx_nullifier_root", &request.tx_nullifier_root)?;
        require_root("fee_commitment_root", &request.fee_commitment_root)?;
        require_window(
            "cohort",
            self.current_height,
            request.opens_at_height,
            request.expires_at_height,
        )?;
        if request.min_transaction_count == 0
            || request.min_transaction_count > request.max_transaction_count
        {
            return Err("invalid cohort transaction bounds".to_string());
        }
        if request.max_transaction_count as usize > self.config.max_batch_items {
            return Err("cohort exceeds max batch items".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("cohort privacy set below runtime minimum".to_string());
        }
        let sequence = self.cohorts.len() as u64;
        let cohort_id = deterministic_id("eligible_cohort", &request.public_record(), sequence);
        let record = EligibleTransactionCohortRecord {
            cohort_id: cohort_id.clone(),
            pool_id: request.pool_id,
            cohort_kind: request.cohort_kind,
            cohort_commitment_root: request.cohort_commitment_root,
            tx_nullifier_root: request.tx_nullifier_root,
            fee_commitment_root: request.fee_commitment_root,
            min_transaction_count: request.min_transaction_count,
            max_transaction_count: request.max_transaction_count,
            aggregate_fee_commitment: request.aggregate_fee_commitment,
            privacy_set_size: request.privacy_set_size,
            opens_at_height: request.opens_at_height,
            expires_at_height: request.expires_at_height,
            created_at_height: self.current_height,
            status: CohortStatus::Eligible,
        };
        self.record_public(format!("cohort:{cohort_id}"), record.public_record())?;
        self.cohorts.insert(cohort_id.clone(), record);
        Ok(cohort_id)
    }

    pub fn attest_sponsor(
        &mut self,
        request: PqSponsorAttestationRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<String> {
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        let commitment = self
            .sponsor_commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| format!("unknown sponsor commitment {}", request.commitment_id))?;
        if self.current_height > commitment.expires_at_height {
            return Err("sponsor commitment expired".to_string());
        }
        require_root("attested_record_root", &request.attested_record_root)?;
        require_root("pq_signature_root", &request.pq_signature_root)?;
        require_root("transcript_root", &request.transcript_root)?;
        require_root("signer_key_root", &request.signer_key_root)?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("pq sponsor attestation below runtime security floor".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("pq sponsor attestation expires before current height".to_string());
        }
        let sequence = self.attestations.len() as u64;
        let attestation_id =
            deterministic_id("pq_sponsor_attestation", &request.public_record(), sequence);
        let record = PqSponsorAttestationRecord {
            attestation_id: attestation_id.clone(),
            commitment_id: request.commitment_id,
            pool_id: commitment.pool_id.clone(),
            sponsor_id: commitment.sponsor_id.clone(),
            purpose: request.purpose,
            attested_record_root: request.attested_record_root,
            pq_signature_root: request.pq_signature_root,
            transcript_root: request.transcript_root,
            security_bits: request.security_bits,
            signer_key_root: request.signer_key_root,
            created_at_height: self.current_height,
            expires_at_height: request.expires_at_height,
        };
        commitment.status = SponsorCommitmentStatus::Attested;
        self.record_public(
            format!("pq_sponsor_attestation:{attestation_id}"),
            record.public_record(),
        )?;
        self.attestations.insert(attestation_id.clone(), record);
        Ok(attestation_id)
    }

    pub fn create_privacy_budget(
        &mut self,
        pool_id: String,
        cohort_id: String,
        disclosure_root: String,
        allowed_fields: BTreeSet<String>,
        max_receipts: u64,
        max_redacted_bytes: u64,
        expires_at_height: u64,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<String> {
        self.ensure_capacity(
            self.privacy_budgets.len(),
            self.config.max_privacy_budgets,
            "privacy_budgets",
        )?;
        if !self.pools.contains_key(&pool_id) {
            return Err(format!("unknown pool {pool_id}"));
        }
        if !self.cohorts.contains_key(&cohort_id) {
            return Err(format!("unknown cohort {cohort_id}"));
        }
        require_root("disclosure_root", &disclosure_root)?;
        if allowed_fields.is_empty() {
            return Err("privacy redaction budget requires at least one allowed field".to_string());
        }
        if max_receipts == 0 || max_redacted_bytes == 0 {
            return Err("privacy redaction budget limits must be nonzero".to_string());
        }
        if expires_at_height <= self.current_height {
            return Err("privacy redaction budget expires before current height".to_string());
        }
        let request = json!({
            "pool_id": pool_id,
            "cohort_id": cohort_id,
            "disclosure_root": disclosure_root,
            "allowed_fields": allowed_fields,
            "max_receipts": max_receipts,
            "max_redacted_bytes": max_redacted_bytes,
            "expires_at_height": expires_at_height,
        });
        let sequence = self.privacy_budgets.len() as u64;
        let budget_id = deterministic_id("privacy_redaction_budget", &request, sequence);
        let record = PrivacyRedactionBudgetRecord {
            budget_id: budget_id.clone(),
            pool_id,
            cohort_id,
            disclosure_root,
            allowed_fields,
            max_receipts,
            receipts_used: 0,
            max_redacted_bytes,
            redacted_bytes_used: 0,
            created_at_height: self.current_height,
            expires_at_height,
        };
        self.record_public(
            format!("privacy_budget:{budget_id}"),
            record.public_record(),
        )?;
        self.privacy_budgets.insert(budget_id.clone(), record);
        Ok(budget_id)
    }

    pub fn settle_coupon_receipt(
        &mut self,
        request: CouponSettlementReceiptRequest,
        redacted_bytes: u64,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<String> {
        self.ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        if self.spent_nullifiers.contains(&request.coupon_nullifier) {
            self.counters.overspend_blocks = self.counters.overspend_blocks.saturating_add(1);
            return Err("coupon nullifier already spent".to_string());
        }
        require_root("coupon_commitment_root", &request.coupon_commitment_root)?;
        require_root("settlement_batch_root", &request.settlement_batch_root)?;
        require_nonempty("coupon_nullifier", &request.coupon_nullifier)?;
        require_bps("user_fee_bps", request.user_fee_bps)?;
        if request.user_fee_bps > self.config.max_user_fee_bps {
            return Err("user fee exceeds low-fee cap".to_string());
        }
        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        let cohort = self
            .cohorts
            .get_mut(&request.cohort_id)
            .ok_or_else(|| format!("unknown cohort {}", request.cohort_id))?;
        let commitment = self
            .sponsor_commitments
            .get_mut(&request.commitment_id)
            .ok_or_else(|| format!("unknown sponsor commitment {}", request.commitment_id))?;
        let budget = self
            .privacy_budgets
            .get_mut(&request.privacy_redaction_budget_id)
            .ok_or_else(|| {
                format!(
                    "unknown privacy redaction budget {}",
                    request.privacy_redaction_budget_id
                )
            })?;
        if cohort.pool_id != pool.pool_id || commitment.pool_id != pool.pool_id {
            return Err("receipt pool, cohort, and sponsor commitment mismatch".to_string());
        }
        if self.current_height > pool.expires_at_height
            || self.current_height > cohort.expires_at_height
            || self.current_height > commitment.expires_at_height
            || self.current_height > budget.expires_at_height
        {
            self.counters.expired_windows = self.counters.expired_windows.saturating_add(1);
            return Err("settlement window expired".to_string());
        }
        if !commitment.status.spendable() {
            return Err("sponsor commitment is not spendable".to_string());
        }
        if !budget.can_spend(redacted_bytes) {
            return Err("privacy redaction budget exceeded".to_string());
        }
        let pool_next_spent = pool
            .spent_commitment
            .saturating_add(request.rebate_amount_commitment);
        let sponsor_next_spent = commitment
            .spent_rebate_commitment
            .saturating_add(request.rebate_amount_commitment);
        if pool_next_spent > pool.capacity_commitment
            || sponsor_next_spent > commitment.max_rebate_commitment
        {
            self.counters.overspend_blocks = self.counters.overspend_blocks.saturating_add(1);
            return Err("rebate settlement would overspend pool or sponsor commitment".to_string());
        }
        let sequence = self.receipts.len() as u64;
        let receipt_id = deterministic_id(
            "coupon_settlement_receipt",
            &request.public_record(),
            sequence,
        );
        let record = CouponSettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            pool_id: request.pool_id,
            cohort_id: request.cohort_id,
            commitment_id: request.commitment_id,
            coupon_nullifier: request.coupon_nullifier.clone(),
            coupon_commitment_root: request.coupon_commitment_root,
            settlement_batch_root: request.settlement_batch_root,
            rebate_amount_commitment: request.rebate_amount_commitment,
            user_fee_bps: request.user_fee_bps,
            privacy_redaction_budget_id: request.privacy_redaction_budget_id,
            created_at_height: self.current_height,
            expires_at_height: request.expires_at_height,
            status: ReceiptStatus::Settled,
        };
        pool.spent_commitment = pool_next_spent;
        pool.status = RebatePoolStatus::Settling;
        cohort.status = CohortStatus::Settled;
        commitment.spent_rebate_commitment = sponsor_next_spent;
        commitment.status = if sponsor_next_spent == commitment.max_rebate_commitment {
            SponsorCommitmentStatus::Exhausted
        } else {
            SponsorCommitmentStatus::PartiallySpent
        };
        budget.receipts_used = budget.receipts_used.saturating_add(1);
        budget.redacted_bytes_used = budget.redacted_bytes_used.saturating_add(redacted_bytes);
        self.spent_nullifiers.insert(request.coupon_nullifier);
        self.counters.coupon_settlements = self.counters.coupon_settlements.saturating_add(1);
        self.record_public(
            format!("coupon_receipt:{receipt_id}"),
            record.public_record(),
        )?;
        self.receipts.insert(receipt_id.clone(), record);
        Ok(receipt_id)
    }

    pub fn quarantine_subject(
        &mut self,
        subject_id: String,
        subject_kind: String,
        reason: QuarantineReason,
        evidence_root: String,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<String> {
        self.ensure_capacity(
            self.quarantines.len(),
            self.config.max_quarantines,
            "quarantines",
        )?;
        require_nonempty("subject_id", &subject_id)?;
        require_nonempty("subject_kind", &subject_kind)?;
        require_root("evidence_root", &evidence_root)?;
        let request = json!({
            "subject_id": subject_id,
            "subject_kind": subject_kind,
            "reason": reason.as_str(),
            "evidence_root": evidence_root,
        });
        let sequence = self.quarantines.len() as u64;
        let quarantine_id = deterministic_id("quarantine", &request, sequence);
        let record = QuarantineControlRecord {
            quarantine_id: quarantine_id.clone(),
            subject_id: subject_id.clone(),
            subject_kind: subject_kind.clone(),
            reason,
            evidence_root,
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.quarantine_ttl_blocks),
            released: false,
        };
        self.apply_quarantine_marker(&subject_kind, &subject_id);
        self.record_public(
            format!("quarantine:{quarantine_id}"),
            record.public_record(),
        )?;
        self.quarantines.insert(quarantine_id.clone(), record);
        Ok(quarantine_id)
    }

    pub fn expire_windows(&mut self, at_height: u64) -> u64 {
        self.current_height = at_height;
        let mut expired = 0_u64;
        for pool in self.pools.values_mut() {
            if at_height > pool.expires_at_height
                && !matches!(
                    pool.status,
                    RebatePoolStatus::Expired
                        | RebatePoolStatus::Drained
                        | RebatePoolStatus::Quarantined
                )
            {
                pool.status = RebatePoolStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for commitment in self.sponsor_commitments.values_mut() {
            if at_height > commitment.expires_at_height
                && !matches!(
                    commitment.status,
                    SponsorCommitmentStatus::Expired
                        | SponsorCommitmentStatus::Exhausted
                        | SponsorCommitmentStatus::Quarantined
                )
            {
                commitment.status = SponsorCommitmentStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for cohort in self.cohorts.values_mut() {
            if at_height > cohort.expires_at_height
                && !matches!(
                    cohort.status,
                    CohortStatus::Expired | CohortStatus::Settled | CohortStatus::Quarantined
                )
            {
                cohort.status = CohortStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for receipt in self.receipts.values_mut() {
            if at_height > receipt.expires_at_height
                && !matches!(
                    receipt.status,
                    ReceiptStatus::Expired | ReceiptStatus::Settled | ReceiptStatus::Quarantined
                )
            {
                receipt.status = ReceiptStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        self.counters.expired_windows = self.counters.expired_windows.saturating_add(expired);
        expired
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters().state_root(),
            pool_root: map_root("POOLS", &self.pools, BatchRebatePoolRecord::public_record),
            sponsor_commitment_root: map_root(
                "SPONSOR_COMMITMENTS",
                &self.sponsor_commitments,
                SponsorCommitmentRecord::public_record,
            ),
            cohort_root: map_root(
                "COHORTS",
                &self.cohorts,
                EligibleTransactionCohortRecord::public_record,
            ),
            attestation_root: map_root(
                "PQ_SPONSOR_ATTESTATIONS",
                &self.attestations,
                PqSponsorAttestationRecord::public_record,
            ),
            receipt_root: map_root(
                "COUPON_SETTLEMENT_RECEIPTS",
                &self.receipts,
                CouponSettlementReceiptRecord::public_record,
            ),
            quarantine_root: map_root(
                "QUARANTINES",
                &self.quarantines,
                QuarantineControlRecord::public_record,
            ),
            privacy_budget_root: map_root(
                "PRIVACY_BUDGETS",
                &self.privacy_budgets,
                PrivacyRedactionBudgetRecord::public_record,
            ),
            spent_nullifier_root: set_root("SPENT_NULLIFIERS", &self.spent_nullifiers),
            public_record_root: map_value_root("PUBLIC_RECORDS", &self.public_records),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_low_fee_pq_confidential_batch_rebate_clearinghouse_runtime",
            "protocol_version": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_PQ_AUTH_SUITE,
            "pool_scheme": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_POOL_SCHEME,
            "sponsor_scheme": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_SPONSOR_SCHEME,
            "cohort_scheme": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_COHORT_SCHEME,
            "attestation_scheme": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_ATTESTATION_SCHEME,
            "receipt_scheme": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_RECEIPT_SCHEME,
            "quarantine_scheme": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_QUARANTINE_SCHEME,
            "redaction_scheme": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_REDACTION_SCHEME,
            "replay_domain": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_REPLAY_DOMAIN,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root(),
            "record": self.public_record_without_state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_low_fee_pq_confidential_batch_rebate_clearinghouse_runtime_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn record_public(
        &mut self,
        key: String,
        value: Value,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<()> {
        if !self.public_records.contains_key(&key) {
            self.ensure_capacity(
                self.public_records.len(),
                self.config.max_public_records,
                "public_records",
            )?;
        }
        self.public_records.insert(key, value);
        self.counters.public_records = self.public_records.len() as u64;
        Ok(())
    }

    fn ensure_capacity(
        &self,
        len: usize,
        max: usize,
        label: &str,
    ) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<()> {
        if len >= max {
            Err(format!("{label} capacity exceeded: {len}/{max}"))
        } else {
            Ok(())
        }
    }

    fn apply_quarantine_marker(&mut self, subject_kind: &str, subject_id: &str) {
        match subject_kind {
            "pool" => {
                if let Some(pool) = self.pools.get_mut(subject_id) {
                    pool.status = RebatePoolStatus::Quarantined;
                }
            }
            "sponsor_commitment" => {
                if let Some(commitment) = self.sponsor_commitments.get_mut(subject_id) {
                    commitment.status = SponsorCommitmentStatus::Quarantined;
                }
            }
            "cohort" => {
                if let Some(cohort) = self.cohorts.get_mut(subject_id) {
                    cohort.status = CohortStatus::Quarantined;
                }
            }
            "receipt" => {
                if let Some(receipt) = self.receipts.get_mut(subject_id) {
                    receipt.status = ReceiptStatus::Quarantined;
                }
            }
            _ => {}
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let pool_id = state
        .open_pool(BatchRebatePoolRequest {
            sponsor_namespace: "devnet-low-fee-sponsors".to_string(),
            pool_label: "monero-private-l2-low-fee-batch-rebates".to_string(),
            funding_commitment_root: seeded("devnet-pool-funding-commitment-root"),
            coupon_commitment_root: seeded("devnet-pool-coupon-commitment-root"),
            eligible_cohort_root: seeded("devnet-pool-eligible-cohort-root"),
            fee_asset_id: state.config.fee_asset_id.clone(),
            coupon_asset_id: state.config.coupon_asset_id.clone(),
            target_rebate_bps: state.config.target_rebate_bps,
            max_user_fee_bps: state.config.max_user_fee_bps,
            capacity_commitment: 5_000_000_000,
            privacy_set_size: state.config.target_privacy_set_size,
            opens_at_height: state.current_height,
            expires_at_height: state.current_height + state.config.pool_ttl_blocks,
            operator_commitment: seeded("devnet-clearinghouse-operator-commitment"),
        })
        .expect("demo pool");
    let commitment_id = state
        .reserve_sponsor_commitment(SponsorCommitmentRequest {
            pool_id: pool_id.clone(),
            sponsor_id: "devnet-sponsor-alpha".to_string(),
            sponsor_commitment_root: seeded("devnet-sponsor-alpha-commitment-root"),
            funding_note_root: seeded("devnet-sponsor-alpha-funding-note-root"),
            max_rebate_commitment: 2_000_000_000,
            drawdown_limit_bps: 1_000,
            pq_public_key_root: seeded("devnet-sponsor-alpha-pq-public-key-root"),
            expires_at_height: state.current_height + state.config.sponsor_ttl_blocks,
        })
        .expect("demo sponsor commitment");
    let cohort_id = state
        .register_cohort(EligibleTransactionCohortRequest {
            pool_id: pool_id.clone(),
            cohort_kind: CohortKind::MoneroPrivateTransfer,
            cohort_commitment_root: seeded("devnet-cohort-private-transfer-root"),
            tx_nullifier_root: seeded("devnet-cohort-nullifier-root"),
            fee_commitment_root: seeded("devnet-cohort-fee-root"),
            min_transaction_count: 128,
            max_transaction_count: 512,
            aggregate_fee_commitment: 7_500_000,
            privacy_set_size: state.config.target_privacy_set_size,
            opens_at_height: state.current_height,
            expires_at_height: state.current_height + state.config.cohort_ttl_blocks,
        })
        .expect("demo cohort");
    state
        .attest_sponsor(PqSponsorAttestationRequest {
            commitment_id: commitment_id.clone(),
            purpose: AttestationPurpose::SponsorFunding,
            attested_record_root: seeded("devnet-sponsor-attested-record-root"),
            pq_signature_root: seeded("devnet-sponsor-pq-signature-root"),
            transcript_root: seeded("devnet-sponsor-transcript-root"),
            security_bits: state.config.min_pq_security_bits,
            signer_key_root: seeded("devnet-sponsor-signer-key-root"),
            expires_at_height: state.current_height + state.config.sponsor_ttl_blocks,
        })
        .expect("demo attestation");
    let mut allowed_fields = BTreeSet::new();
    allowed_fields.insert("pool_id".to_string());
    allowed_fields.insert("cohort_id".to_string());
    allowed_fields.insert("settlement_batch_root".to_string());
    let budget_id = state
        .create_privacy_budget(
            pool_id.clone(),
            cohort_id.clone(),
            seeded("devnet-redaction-disclosure-root"),
            allowed_fields,
            10_000,
            4_194_304,
            state.current_height + state.config.receipt_ttl_blocks,
        )
        .expect("demo privacy budget");
    state
        .settle_coupon_receipt(
            CouponSettlementReceiptRequest {
                pool_id,
                cohort_id,
                commitment_id,
                coupon_nullifier: seeded("devnet-coupon-nullifier-0001"),
                coupon_commitment_root: seeded("devnet-coupon-commitment-root-0001"),
                settlement_batch_root: seeded("devnet-settlement-batch-root-0001"),
                rebate_amount_commitment: 25_000,
                user_fee_bps: 4,
                privacy_redaction_budget_id: budget_id,
                expires_at_height: state.current_height + state.config.receipt_ttl_blocks,
            },
            384,
        )
        .expect("demo coupon settlement");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_batch_rebate_clearinghouse_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_low_fee_pq_confidential_batch_rebate_clearinghouse_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_batch_rebate_clearinghouse_runtime_state_root_from_record(
    record: &Value,
) -> String {
    root_from_record("STATE", record)
}

fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn deterministic_id(domain: &str, record: &Value, sequence: u64) -> String {
    domain_hash(
        &format!(
            "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME:{domain}:ID"
        ),
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        20,
    )
}

fn seeded(label: &str) -> String {
    domain_hash(
        "PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME:DEVNET_FIXTURE",
        &[HashPart::Str(label)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME:{domain}"),
        &leaves,
    )
}

fn map_value_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME:{domain}"),
        &leaves,
    )
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME:{domain}"),
        &leaves,
    )
}

fn require_nonempty(
    field: &str,
    value: &str,
) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be nonempty"))
    } else {
        Ok(())
    }
}

fn require_root(
    field: &str,
    value: &str,
) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<()> {
    require_nonempty(field, value)?;
    if value.len() < 32 {
        Err(format!("{field} must look like a deterministic root"))
    } else {
        Ok(())
    }
}

fn require_bps(
    field: &str,
    value: u64,
) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<()> {
    if value > PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_CLEARINGHOUSE_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds bps maximum"))
    } else {
        Ok(())
    }
}

fn require_window(
    label: &str,
    current_height: u64,
    opens_at_height: u64,
    expires_at_height: u64,
) -> PrivateL2LowFeePqConfidentialBatchRebateClearinghouseRuntimeResult<()> {
    if expires_at_height <= opens_at_height {
        return Err(format!("{label} expiry must be after open height"));
    }
    if expires_at_height <= current_height {
        return Err(format!("{label} expiry must be after current height"));
    }
    Ok(())
}
