use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialGasCouponClearingRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialGasCouponClearingRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-gas-coupon-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_SCHEMA_VERSION;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const HASH_SUITE: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_HASH_SUITE;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-gas-coupon-clearing-v1";
pub const PQ_AUTH_SUITE: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_PQ_AUTH_SUITE;
pub const COUPON_LOT_SCHEME: &str = "monero-private-l2-encrypted-gas-coupon-lot-root-v1";
pub const SPONSOR_POOL_SCHEME: &str = "monero-private-l2-low-fee-gas-sponsor-pool-root-v1";
pub const CLEARING_ATTESTATION_SCHEME: &str =
    "monero-private-l2-pq-gas-coupon-clearing-attestation-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str =
    "monero-private-l2-confidential-gas-coupon-batch-settlement-root-v1";
pub const REBATE_ACCOUNTING_SCHEME: &str = "monero-private-l2-gas-coupon-rebate-accounting-root-v1";
pub const RISK_LIMIT_SCHEME: &str = "monero-private-l2-gas-coupon-risk-limit-root-v1";
pub const QUARANTINE_SCHEME: &str = "monero-private-l2-gas-coupon-abuse-quarantine-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "monero-private-l2-gas-coupon-redaction-budget-root-v1";
pub const EVENT_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-gas-coupon-clearing-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_GAS_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_REBATE_ASSET_ID: &str = "asset:xusd-devnet";
pub const DEVNET_HEIGHT: u64 = 2_248_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_CLEARING_DRIFT_BPS: u64 = 25;
pub const DEFAULT_MIN_SPONSOR_ESCROW: u64 = 25_000;
pub const DEFAULT_MIN_LOT_NOTIONAL: u64 = 1_000;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_QUARANTINE_WINDOW_BLOCKS: u64 = 2_880;
pub const DEFAULT_COUPON_LOT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_LOTS_PER_BATCH: usize = 2_048;
pub const DEFAULT_MAX_SPONSORS_PER_BATCH: usize = 256;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_COUPON_LOTS: usize = 4_194_304;
pub const MAX_SPONSOR_POOLS: usize = 1_048_576;
pub const MAX_CLEARING_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENT_BATCHES: usize = 1_048_576;
pub const MAX_REBATE_ACCOUNTS: usize = 2_097_152;
pub const MAX_RISK_LIMITS: usize = 2_097_152;
pub const MAX_QUARANTINE_CASES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponLotStatus {
    Submitted,
    Attested,
    Clearing,
    Settled,
    RebateQueued,
    Expired,
    Quarantined,
    Cancelled,
}

impl CouponLotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Attested => "attested",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::RebateQueued => "rebate_queued",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn clearable(self) -> bool {
        matches!(self, Self::Submitted | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Draft,
    Active,
    Depleted,
    Paused,
    Slashed,
    Retired,
}

impl SponsorPoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Depleted => "depleted",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_lots(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingVerdict {
    Approved,
    NeedsMoreLiquidity,
    NeedsMorePrivacy,
    RiskLimited,
    Quarantined,
    Rejected,
}

impl ClearingVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::NeedsMoreLiquidity => "needs_more_liquidity",
            Self::NeedsMorePrivacy => "needs_more_privacy",
            Self::RiskLimited => "risk_limited",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }

    pub fn approves_settlement(self) -> bool {
        matches!(self, Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    Locked,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Locked => "locked",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Queued,
    Paid,
    ClawedBack,
    Forfeited,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Queued => "queued",
            Self::Paid => "paid",
            Self::ClawedBack => "clawed_back",
            Self::Forfeited => "forfeited",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitStatus {
    Active,
    Saturated,
    CoolingDown,
    Paused,
    Retired,
}

impl RiskLimitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::CoolingDown => "cooling_down",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    EvidenceCollecting,
    Cleared,
    Slashed,
    Expired,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceCollecting => "evidence_collecting",
            Self::Cleared => "cleared",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    CouponLotSubmitted,
    SponsorPoolOpened,
    ClearingAttested,
    SettlementBatchBuilt,
    RebatePosted,
    RiskLimitUpdated,
    AbuseQuarantined,
    RedactionBudgetGranted,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CouponLotSubmitted => "coupon_lot_submitted",
            Self::SponsorPoolOpened => "sponsor_pool_opened",
            Self::ClearingAttested => "clearing_attested",
            Self::SettlementBatchBuilt => "settlement_batch_built",
            Self::RebatePosted => "rebate_posted",
            Self::RiskLimitUpdated => "risk_limit_updated",
            Self::AbuseQuarantined => "abuse_quarantined",
            Self::RedactionBudgetGranted => "redaction_budget_granted",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub gas_asset_id: String,
    pub rebate_asset_id: String,
    pub devnet_height: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_clearing_drift_bps: u64,
    pub min_sponsor_escrow: u64,
    pub min_lot_notional: u64,
    pub redaction_window_blocks: u64,
    pub quarantine_window_blocks: u64,
    pub coupon_lot_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub max_lots_per_batch: usize,
    pub max_sponsors_per_batch: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_GAS_COUPON_CLEARING_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            gas_asset_id: DEVNET_GAS_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_clearing_drift_bps: DEFAULT_MAX_CLEARING_DRIFT_BPS,
            min_sponsor_escrow: DEFAULT_MIN_SPONSOR_ESCROW,
            min_lot_notional: DEFAULT_MIN_LOT_NOTIONAL,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            quarantine_window_blocks: DEFAULT_QUARANTINE_WINDOW_BLOCKS,
            coupon_lot_ttl_blocks: DEFAULT_COUPON_LOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            max_lots_per_batch: DEFAULT_MAX_LOTS_PER_BATCH,
            max_sponsors_per_batch: DEFAULT_MAX_SPONSORS_PER_BATCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        ensure_non_empty("gas_asset_id", &self.gas_asset_id)?;
        ensure_non_empty("rebate_asset_id", &self.rebate_asset_id)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("max_clearing_drift_bps", self.max_clearing_drift_bps)?;
        ensure_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive_u64("batch_privacy_set_size", self.batch_privacy_set_size)?;
        ensure_positive_u64("min_sponsor_escrow", self.min_sponsor_escrow)?;
        ensure_positive_u64("min_lot_notional", self.min_lot_notional)?;
        ensure_positive_usize("max_lots_per_batch", self.max_lots_per_batch)?;
        ensure_positive_usize("max_sponsors_per_batch", self.max_sponsors_per_batch)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size must cover min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits is below runtime floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "gas_asset_id": self.gas_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "devnet_height": self.devnet_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_clearing_drift_bps": self.max_clearing_drift_bps,
            "min_sponsor_escrow": self.min_sponsor_escrow,
            "min_lot_notional": self.min_lot_notional,
            "redaction_window_blocks": self.redaction_window_blocks,
            "quarantine_window_blocks": self.quarantine_window_blocks,
            "coupon_lot_ttl_blocks": self.coupon_lot_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "max_lots_per_batch": self.max_lots_per_batch,
            "max_sponsors_per_batch": self.max_sponsors_per_batch
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub coupon_lots: u64,
    pub sponsor_pools: u64,
    pub clearing_attestations: u64,
    pub settlement_batches: u64,
    pub rebate_accounts: u64,
    pub risk_limits: u64,
    pub quarantine_cases: u64,
    pub redaction_budgets: u64,
    pub events: u64,
    pub settled_lots: u64,
    pub quarantined_lots: u64,
    pub total_coupon_notional: u128,
    pub total_sponsor_capacity: u128,
    pub total_rebates_accrued: u128,
    pub total_rebates_paid: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_lots": self.coupon_lots,
            "sponsor_pools": self.sponsor_pools,
            "clearing_attestations": self.clearing_attestations,
            "settlement_batches": self.settlement_batches,
            "rebate_accounts": self.rebate_accounts,
            "risk_limits": self.risk_limits,
            "quarantine_cases": self.quarantine_cases,
            "redaction_budgets": self.redaction_budgets,
            "events": self.events,
            "settled_lots": self.settled_lots,
            "quarantined_lots": self.quarantined_lots,
            "total_coupon_notional": self.total_coupon_notional.to_string(),
            "total_sponsor_capacity": self.total_sponsor_capacity.to_string(),
            "total_rebates_accrued": self.total_rebates_accrued.to_string(),
            "total_rebates_paid": self.total_rebates_paid.to_string()
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub coupon_lots_root: String,
    pub sponsor_pools_root: String,
    pub clearing_attestations_root: String,
    pub settlement_batches_root: String,
    pub rebate_accounts_root: String,
    pub risk_limits_root: String,
    pub quarantine_cases_root: String,
    pub redaction_budgets_root: String,
    pub events_root: String,
    pub counters_root: String,
    pub config_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_lots_root": self.coupon_lots_root,
            "sponsor_pools_root": self.sponsor_pools_root,
            "clearing_attestations_root": self.clearing_attestations_root,
            "settlement_batches_root": self.settlement_batches_root,
            "rebate_accounts_root": self.rebate_accounts_root,
            "risk_limits_root": self.risk_limits_root,
            "quarantine_cases_root": self.quarantine_cases_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "events_root": self.events_root,
            "counters_root": self.counters_root,
            "config_root": self.config_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCouponLotRequest {
    pub owner_commitment: String,
    pub sponsor_pool_id: String,
    pub encrypted_coupon_root: String,
    pub coupon_nullifier_root: String,
    pub gas_asset_id: String,
    pub committed_notional: u64,
    pub max_user_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_envelope_root: String,
    pub range_proof_root: String,
    pub expiry_height: u64,
    pub lot_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorPoolRequest {
    pub sponsor_commitment: String,
    pub pool_label_commitment: String,
    pub escrow_root: String,
    pub policy_root: String,
    pub capacity: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub settlement_asset_id: String,
    pub pq_public_root: String,
    pub pool_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingAttestationRequest {
    pub coupon_lot_id: String,
    pub sponsor_pool_id: String,
    pub attester_commitment: String,
    pub verdict: ClearingVerdict,
    pub clearing_price_root: String,
    pub liquidity_witness_root: String,
    pub privacy_witness_root: String,
    pub risk_witness_root: String,
    pub pq_signature_root: String,
    pub valid_until_height: u64,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatchRequest {
    pub coupon_lot_ids: Vec<String>,
    pub sponsor_pool_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub batch_operator_commitment: String,
    pub netting_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub residual_root: String,
    pub finality_height: u64,
    pub batch_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAccountingRequest {
    pub account_commitment: String,
    pub coupon_lot_id: String,
    pub sponsor_pool_id: String,
    pub settlement_batch_id: String,
    pub accrued_rebate: u64,
    pub paid_rebate: u64,
    pub clawback_amount: u64,
    pub accounting_root: String,
    pub status: RebateStatus,
    pub rebate_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskLimitRequest {
    pub subject_commitment: String,
    pub sponsor_pool_id: String,
    pub exposure_root: String,
    pub limit_root: String,
    pub max_notional: u64,
    pub consumed_notional: u64,
    pub max_lots_per_epoch: u64,
    pub epoch: u64,
    pub status: RiskLimitStatus,
    pub risk_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseQuarantineRequest {
    pub subject_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub affected_lot_ids: Vec<String>,
    pub quarantine_reason_code: String,
    pub release_height: u64,
    pub status: QuarantineStatus,
    pub quarantine_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub auditor_commitment: String,
    pub subject_id: String,
    pub budget_root: String,
    pub max_redactions: u64,
    pub spent_redactions: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub disclosure_policy_root: String,
    pub redaction_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponLotRecord {
    pub coupon_lot_id: String,
    pub owner_commitment: String,
    pub sponsor_pool_id: String,
    pub encrypted_coupon_root: String,
    pub coupon_nullifier_root: String,
    pub gas_asset_id: String,
    pub committed_notional: u64,
    pub max_user_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_envelope_root: String,
    pub range_proof_root: String,
    pub expiry_height: u64,
    pub status: CouponLotStatus,
    pub created_height: u64,
    pub updated_height: u64,
    pub public_record_id: String,
}

impl CouponLotRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_lot_id": self.coupon_lot_id,
            "owner_commitment": self.owner_commitment,
            "sponsor_pool_id": self.sponsor_pool_id,
            "encrypted_coupon_root": self.encrypted_coupon_root,
            "coupon_nullifier_root": self.coupon_nullifier_root,
            "gas_asset_id": self.gas_asset_id,
            "committed_notional": self.committed_notional,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_envelope_root": self.pq_envelope_root,
            "range_proof_root": self.range_proof_root,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorPoolRecord {
    pub sponsor_pool_id: String,
    pub sponsor_commitment: String,
    pub pool_label_commitment: String,
    pub escrow_root: String,
    pub policy_root: String,
    pub capacity: u64,
    pub reserved_capacity: u64,
    pub consumed_capacity: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub settlement_asset_id: String,
    pub pq_public_root: String,
    pub status: SponsorPoolStatus,
    pub created_height: u64,
    pub updated_height: u64,
    pub public_record_id: String,
}

impl SponsorPoolRecord {
    pub fn available_capacity(&self) -> u64 {
        self.capacity.saturating_sub(self.reserved_capacity)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_pool_id": self.sponsor_pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "pool_label_commitment": self.pool_label_commitment,
            "escrow_root": self.escrow_root,
            "policy_root": self.policy_root,
            "capacity": self.capacity,
            "reserved_capacity": self.reserved_capacity,
            "consumed_capacity": self.consumed_capacity,
            "available_capacity": self.available_capacity(),
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "settlement_asset_id": self.settlement_asset_id,
            "pq_public_root": self.pq_public_root,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingAttestationRecord {
    pub attestation_id: String,
    pub coupon_lot_id: String,
    pub sponsor_pool_id: String,
    pub attester_commitment: String,
    pub verdict: ClearingVerdict,
    pub clearing_price_root: String,
    pub liquidity_witness_root: String,
    pub privacy_witness_root: String,
    pub risk_witness_root: String,
    pub pq_signature_root: String,
    pub valid_until_height: u64,
    pub created_height: u64,
    pub public_record_id: String,
}

impl ClearingAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "coupon_lot_id": self.coupon_lot_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "attester_commitment": self.attester_commitment,
            "verdict": self.verdict.as_str(),
            "clearing_price_root": self.clearing_price_root,
            "liquidity_witness_root": self.liquidity_witness_root,
            "privacy_witness_root": self.privacy_witness_root,
            "risk_witness_root": self.risk_witness_root,
            "pq_signature_root": self.pq_signature_root,
            "valid_until_height": self.valid_until_height,
            "created_height": self.created_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatchRecord {
    pub settlement_batch_id: String,
    pub coupon_lot_ids: Vec<String>,
    pub sponsor_pool_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub batch_operator_commitment: String,
    pub netting_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub residual_root: String,
    pub finality_height: u64,
    pub status: SettlementStatus,
    pub created_height: u64,
    pub settled_height: Option<u64>,
    pub public_record_id: String,
}

impl SettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_batch_id": self.settlement_batch_id,
            "coupon_lot_ids_root": id_list_root("settlement-batch-lots", &self.coupon_lot_ids),
            "coupon_lot_count": self.coupon_lot_ids.len(),
            "sponsor_pool_ids_root": id_list_root("settlement-batch-sponsors", &self.sponsor_pool_ids),
            "sponsor_pool_count": self.sponsor_pool_ids.len(),
            "attestation_ids_root": id_list_root("settlement-batch-attestations", &self.attestation_ids),
            "attestation_count": self.attestation_ids.len(),
            "batch_operator_commitment": self.batch_operator_commitment,
            "netting_root": self.netting_root,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "residual_root": self.residual_root,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "settled_height": self.settled_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAccountRecord {
    pub rebate_account_id: String,
    pub account_commitment: String,
    pub coupon_lot_id: String,
    pub sponsor_pool_id: String,
    pub settlement_batch_id: String,
    pub accrued_rebate: u64,
    pub paid_rebate: u64,
    pub clawback_amount: u64,
    pub accounting_root: String,
    pub status: RebateStatus,
    pub created_height: u64,
    pub updated_height: u64,
    pub public_record_id: String,
}

impl RebateAccountRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_account_id": self.rebate_account_id,
            "account_commitment": self.account_commitment,
            "coupon_lot_id": self.coupon_lot_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "settlement_batch_id": self.settlement_batch_id,
            "accrued_rebate": self.accrued_rebate,
            "paid_rebate": self.paid_rebate,
            "clawback_amount": self.clawback_amount,
            "accounting_root": self.accounting_root,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskLimitRecord {
    pub risk_limit_id: String,
    pub subject_commitment: String,
    pub sponsor_pool_id: String,
    pub exposure_root: String,
    pub limit_root: String,
    pub max_notional: u64,
    pub consumed_notional: u64,
    pub max_lots_per_epoch: u64,
    pub epoch: u64,
    pub status: RiskLimitStatus,
    pub created_height: u64,
    pub updated_height: u64,
    pub public_record_id: String,
}

impl RiskLimitRecord {
    pub fn remaining_notional(&self) -> u64 {
        self.max_notional.saturating_sub(self.consumed_notional)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "risk_limit_id": self.risk_limit_id,
            "subject_commitment": self.subject_commitment,
            "sponsor_pool_id": self.sponsor_pool_id,
            "exposure_root": self.exposure_root,
            "limit_root": self.limit_root,
            "max_notional": self.max_notional,
            "consumed_notional": self.consumed_notional,
            "remaining_notional": self.remaining_notional(),
            "max_lots_per_epoch": self.max_lots_per_epoch,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub subject_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub affected_lot_ids: Vec<String>,
    pub quarantine_reason_code: String,
    pub release_height: u64,
    pub status: QuarantineStatus,
    pub created_height: u64,
    pub updated_height: u64,
    pub public_record_id: String,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "affected_lot_ids_root": id_list_root("quarantine-lots", &self.affected_lot_ids),
            "affected_lot_count": self.affected_lot_ids.len(),
            "quarantine_reason_code": self.quarantine_reason_code,
            "release_height": self.release_height,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRecord {
    pub redaction_budget_id: String,
    pub auditor_commitment: String,
    pub subject_id: String,
    pub budget_root: String,
    pub max_redactions: u64,
    pub spent_redactions: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub disclosure_policy_root: String,
    pub created_height: u64,
    pub updated_height: u64,
    pub public_record_id: String,
}

impl RedactionBudgetRecord {
    pub fn remaining_redactions(&self) -> u64 {
        self.max_redactions.saturating_sub(self.spent_redactions)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_budget_id": self.redaction_budget_id,
            "auditor_commitment": self.auditor_commitment,
            "subject_id": self.subject_id,
            "budget_root": self.budget_root,
            "max_redactions": self.max_redactions,
            "spent_redactions": self.spent_redactions,
            "remaining_redactions": self.remaining_redactions(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "disclosure_policy_root": self.disclosure_policy_root,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "public_record_id": self.public_record_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEventRecord {
    pub event_id: String,
    pub event_kind: EventKind,
    pub subject_id: String,
    pub height: u64,
    pub event_root: String,
}

impl RuntimeEventRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "event_root": self.event_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub coupon_lots: BTreeMap<String, CouponLotRecord>,
    pub sponsor_pools: BTreeMap<String, SponsorPoolRecord>,
    pub clearing_attestations: BTreeMap<String, ClearingAttestationRecord>,
    pub settlement_batches: BTreeMap<String, SettlementBatchRecord>,
    pub rebate_accounts: BTreeMap<String, RebateAccountRecord>,
    pub risk_limits: BTreeMap<String, RiskLimitRecord>,
    pub quarantine_cases: BTreeMap<String, QuarantineRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub events: BTreeMap<String, RuntimeEventRecord>,
    pub current_height: u64,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            current_height: config.devnet_height,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            coupon_lots: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            clearing_attestations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            rebate_accounts: BTreeMap::new(),
            risk_limits: BTreeMap::new(),
            quarantine_cases: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet gas coupon clearing config is valid")
    }

    pub fn submit_coupon_lot(&mut self, request: EncryptedCouponLotRequest) -> Result<String> {
        self.ensure_capacity("coupon_lots", self.coupon_lots.len(), MAX_COUPON_LOTS)?;
        self.validate_coupon_lot_request(&request)?;
        let pool = self
            .sponsor_pools
            .get(&request.sponsor_pool_id)
            .ok_or_else(|| format!("unknown sponsor pool {}", request.sponsor_pool_id))?;
        if !pool.status.accepts_lots() {
            return Err(format!(
                "sponsor pool {} is not active",
                request.sponsor_pool_id
            ));
        }
        if pool.available_capacity() < request.committed_notional {
            return Err("sponsor pool does not have enough available capacity".to_string());
        }
        let sequence = self.counters.coupon_lots + 1;
        let coupon_lot_id = coupon_lot_id(&request, sequence);
        let payload = json!({
            "coupon_lot_id": &coupon_lot_id,
            "request": {
                "owner_commitment": &request.owner_commitment,
                "sponsor_pool_id": &request.sponsor_pool_id,
                "encrypted_coupon_root": &request.encrypted_coupon_root,
                "coupon_nullifier_root": &request.coupon_nullifier_root,
                "gas_asset_id": &request.gas_asset_id,
                "committed_notional": request.committed_notional,
                "max_user_fee_bps": request.max_user_fee_bps,
                "min_rebate_bps": request.min_rebate_bps,
                "privacy_set_size": request.privacy_set_size,
                "pq_envelope_root": &request.pq_envelope_root,
                "range_proof_root": &request.range_proof_root,
                "expiry_height": request.expiry_height
            }
        });
        let public_record_id = public_record_id("coupon-lot", &coupon_lot_id, &payload);
        let record = CouponLotRecord {
            coupon_lot_id: coupon_lot_id.clone(),
            owner_commitment: request.owner_commitment,
            sponsor_pool_id: request.sponsor_pool_id.clone(),
            encrypted_coupon_root: request.encrypted_coupon_root,
            coupon_nullifier_root: request.coupon_nullifier_root,
            gas_asset_id: request.gas_asset_id,
            committed_notional: request.committed_notional,
            max_user_fee_bps: request.max_user_fee_bps,
            min_rebate_bps: request.min_rebate_bps,
            privacy_set_size: request.privacy_set_size,
            pq_envelope_root: request.pq_envelope_root,
            range_proof_root: request.range_proof_root,
            expiry_height: request.expiry_height,
            status: CouponLotStatus::Submitted,
            created_height: self.current_height,
            updated_height: self.current_height,
            public_record_id,
        };
        self.coupon_lots.insert(coupon_lot_id.clone(), record);
        if let Some(pool) = self.sponsor_pools.get_mut(&request.sponsor_pool_id) {
            pool.reserved_capacity = pool
                .reserved_capacity
                .saturating_add(request.committed_notional);
            pool.updated_height = self.current_height;
        }
        self.counters.coupon_lots = sequence;
        self.counters.total_coupon_notional = self
            .counters
            .total_coupon_notional
            .saturating_add(request.committed_notional as u128);
        self.push_event(EventKind::CouponLotSubmitted, &coupon_lot_id)?;
        self.refresh_roots();
        Ok(coupon_lot_id)
    }

    pub fn open_sponsor_pool(&mut self, request: SponsorPoolRequest) -> Result<String> {
        self.ensure_capacity("sponsor_pools", self.sponsor_pools.len(), MAX_SPONSOR_POOLS)?;
        self.validate_sponsor_pool_request(&request)?;
        let sequence = self.counters.sponsor_pools + 1;
        let sponsor_pool_id = sponsor_pool_id(&request, sequence);
        let payload = json!({
            "sponsor_pool_id": &sponsor_pool_id,
            "sponsor_commitment": &request.sponsor_commitment,
            "pool_label_commitment": &request.pool_label_commitment,
            "escrow_root": &request.escrow_root,
            "policy_root": &request.policy_root,
            "capacity": request.capacity,
            "max_sponsor_fee_bps": request.max_sponsor_fee_bps,
            "target_rebate_bps": request.target_rebate_bps,
            "min_privacy_set_size": request.min_privacy_set_size,
            "settlement_asset_id": &request.settlement_asset_id,
            "pq_public_root": &request.pq_public_root
        });
        let public_record_id = public_record_id("sponsor-pool", &sponsor_pool_id, &payload);
        let record = SponsorPoolRecord {
            sponsor_pool_id: sponsor_pool_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            pool_label_commitment: request.pool_label_commitment,
            escrow_root: request.escrow_root,
            policy_root: request.policy_root,
            capacity: request.capacity,
            reserved_capacity: 0,
            consumed_capacity: 0,
            max_sponsor_fee_bps: request.max_sponsor_fee_bps,
            target_rebate_bps: request.target_rebate_bps,
            min_privacy_set_size: request.min_privacy_set_size,
            settlement_asset_id: request.settlement_asset_id,
            pq_public_root: request.pq_public_root,
            status: SponsorPoolStatus::Active,
            created_height: self.current_height,
            updated_height: self.current_height,
            public_record_id,
        };
        self.sponsor_pools.insert(sponsor_pool_id.clone(), record);
        self.counters.sponsor_pools = sequence;
        self.counters.total_sponsor_capacity = self
            .counters
            .total_sponsor_capacity
            .saturating_add(request.capacity as u128);
        self.push_event(EventKind::SponsorPoolOpened, &sponsor_pool_id)?;
        self.refresh_roots();
        Ok(sponsor_pool_id)
    }

    pub fn publish_clearing_attestation(
        &mut self,
        request: ClearingAttestationRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "clearing_attestations",
            self.clearing_attestations.len(),
            MAX_CLEARING_ATTESTATIONS,
        )?;
        self.validate_clearing_attestation_request(&request)?;
        let lot = self.require_coupon_lot(&request.coupon_lot_id)?;
        if lot.sponsor_pool_id != request.sponsor_pool_id {
            return Err("attestation sponsor pool does not match coupon lot".to_string());
        }
        if !lot.status.clearable() {
            return Err(format!(
                "coupon lot {} is not clearable",
                request.coupon_lot_id
            ));
        }
        self.require_sponsor_pool(&request.sponsor_pool_id)?;
        let sequence = self.counters.clearing_attestations + 1;
        let attestation_id = clearing_attestation_id(&request, sequence);
        let payload = json!({
            "attestation_id": &attestation_id,
            "coupon_lot_id": &request.coupon_lot_id,
            "sponsor_pool_id": &request.sponsor_pool_id,
            "attester_commitment": &request.attester_commitment,
            "verdict": request.verdict.as_str(),
            "clearing_price_root": &request.clearing_price_root,
            "liquidity_witness_root": &request.liquidity_witness_root,
            "privacy_witness_root": &request.privacy_witness_root,
            "risk_witness_root": &request.risk_witness_root,
            "pq_signature_root": &request.pq_signature_root
        });
        let public_record_id = public_record_id("clearing-attestation", &attestation_id, &payload);
        let record = ClearingAttestationRecord {
            attestation_id: attestation_id.clone(),
            coupon_lot_id: request.coupon_lot_id.clone(),
            sponsor_pool_id: request.sponsor_pool_id,
            attester_commitment: request.attester_commitment,
            verdict: request.verdict,
            clearing_price_root: request.clearing_price_root,
            liquidity_witness_root: request.liquidity_witness_root,
            privacy_witness_root: request.privacy_witness_root,
            risk_witness_root: request.risk_witness_root,
            pq_signature_root: request.pq_signature_root,
            valid_until_height: request.valid_until_height,
            created_height: self.current_height,
            public_record_id,
        };
        self.clearing_attestations
            .insert(attestation_id.clone(), record);
        if let Some(lot) = self.coupon_lots.get_mut(&request.coupon_lot_id) {
            lot.status = if request.verdict.approves_settlement() {
                CouponLotStatus::Attested
            } else {
                CouponLotStatus::Quarantined
            };
            lot.updated_height = self.current_height;
        }
        if !request.verdict.approves_settlement() {
            self.counters.quarantined_lots = self.counters.quarantined_lots.saturating_add(1);
        }
        self.counters.clearing_attestations = sequence;
        self.push_event(EventKind::ClearingAttested, &attestation_id)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn build_settlement_batch(&mut self, request: SettlementBatchRequest) -> Result<String> {
        self.ensure_capacity(
            "settlement_batches",
            self.settlement_batches.len(),
            MAX_SETTLEMENT_BATCHES,
        )?;
        self.validate_settlement_batch_request(&request)?;
        for lot_id in &request.coupon_lot_ids {
            let lot = self.require_coupon_lot(lot_id)?;
            if lot.status != CouponLotStatus::Attested {
                return Err(format!("coupon lot {lot_id} is not attested"));
            }
        }
        for sponsor_id in &request.sponsor_pool_ids {
            self.require_sponsor_pool(sponsor_id)?;
        }
        for attestation_id in &request.attestation_ids {
            let attestation = self.require_attestation(attestation_id)?;
            if !attestation.verdict.approves_settlement() {
                return Err(format!(
                    "attestation {attestation_id} does not approve settlement"
                ));
            }
        }
        let sequence = self.counters.settlement_batches + 1;
        let settlement_batch_id = settlement_batch_id(&request, sequence);
        let payload = json!({
            "settlement_batch_id": &settlement_batch_id,
            "coupon_lot_ids_root": id_list_root("batch-lots", &request.coupon_lot_ids),
            "sponsor_pool_ids_root": id_list_root("batch-sponsors", &request.sponsor_pool_ids),
            "attestation_ids_root": id_list_root("batch-attestations", &request.attestation_ids),
            "batch_operator_commitment": &request.batch_operator_commitment,
            "netting_root": &request.netting_root,
            "settlement_root": &request.settlement_root,
            "rebate_root": &request.rebate_root,
            "residual_root": &request.residual_root,
            "finality_height": request.finality_height
        });
        let public_record_id = public_record_id("settlement-batch", &settlement_batch_id, &payload);
        let record = SettlementBatchRecord {
            settlement_batch_id: settlement_batch_id.clone(),
            coupon_lot_ids: request.coupon_lot_ids.clone(),
            sponsor_pool_ids: request.sponsor_pool_ids,
            attestation_ids: request.attestation_ids,
            batch_operator_commitment: request.batch_operator_commitment,
            netting_root: request.netting_root,
            settlement_root: request.settlement_root,
            rebate_root: request.rebate_root,
            residual_root: request.residual_root,
            finality_height: request.finality_height,
            status: SettlementStatus::Settled,
            created_height: self.current_height,
            settled_height: Some(self.current_height),
            public_record_id,
        };
        self.settlement_batches
            .insert(settlement_batch_id.clone(), record);
        for lot_id in &request.coupon_lot_ids {
            if let Some(lot) = self.coupon_lots.get_mut(lot_id) {
                lot.status = CouponLotStatus::Settled;
                lot.updated_height = self.current_height;
            }
        }
        self.counters.settlement_batches = sequence;
        self.counters.settled_lots = self
            .counters
            .settled_lots
            .saturating_add(request.coupon_lot_ids.len() as u64);
        self.push_event(EventKind::SettlementBatchBuilt, &settlement_batch_id)?;
        self.refresh_roots();
        Ok(settlement_batch_id)
    }

    pub fn post_rebate_accounting(&mut self, request: RebateAccountingRequest) -> Result<String> {
        self.ensure_capacity(
            "rebate_accounts",
            self.rebate_accounts.len(),
            MAX_REBATE_ACCOUNTS,
        )?;
        self.validate_rebate_accounting_request(&request)?;
        self.require_coupon_lot(&request.coupon_lot_id)?;
        self.require_sponsor_pool(&request.sponsor_pool_id)?;
        self.require_settlement_batch(&request.settlement_batch_id)?;
        let sequence = self.counters.rebate_accounts + 1;
        let rebate_account_id = rebate_account_id(&request, sequence);
        let payload = json!({
            "rebate_account_id": &rebate_account_id,
            "account_commitment": &request.account_commitment,
            "coupon_lot_id": &request.coupon_lot_id,
            "sponsor_pool_id": &request.sponsor_pool_id,
            "settlement_batch_id": &request.settlement_batch_id,
            "accrued_rebate": request.accrued_rebate,
            "paid_rebate": request.paid_rebate,
            "clawback_amount": request.clawback_amount,
            "accounting_root": &request.accounting_root,
            "status": request.status.as_str()
        });
        let public_record_id = public_record_id("rebate-account", &rebate_account_id, &payload);
        let record = RebateAccountRecord {
            rebate_account_id: rebate_account_id.clone(),
            account_commitment: request.account_commitment,
            coupon_lot_id: request.coupon_lot_id.clone(),
            sponsor_pool_id: request.sponsor_pool_id,
            settlement_batch_id: request.settlement_batch_id,
            accrued_rebate: request.accrued_rebate,
            paid_rebate: request.paid_rebate,
            clawback_amount: request.clawback_amount,
            accounting_root: request.accounting_root,
            status: request.status,
            created_height: self.current_height,
            updated_height: self.current_height,
            public_record_id,
        };
        self.rebate_accounts
            .insert(rebate_account_id.clone(), record);
        if let Some(lot) = self.coupon_lots.get_mut(&request.coupon_lot_id) {
            lot.status = CouponLotStatus::RebateQueued;
            lot.updated_height = self.current_height;
        }
        self.counters.rebate_accounts = sequence;
        self.counters.total_rebates_accrued = self
            .counters
            .total_rebates_accrued
            .saturating_add(request.accrued_rebate as u128);
        self.counters.total_rebates_paid = self
            .counters
            .total_rebates_paid
            .saturating_add(request.paid_rebate as u128);
        self.push_event(EventKind::RebatePosted, &rebate_account_id)?;
        self.refresh_roots();
        Ok(rebate_account_id)
    }

    pub fn set_risk_limit(&mut self, request: RiskLimitRequest) -> Result<String> {
        self.ensure_capacity("risk_limits", self.risk_limits.len(), MAX_RISK_LIMITS)?;
        self.validate_risk_limit_request(&request)?;
        self.require_sponsor_pool(&request.sponsor_pool_id)?;
        let sequence = self.counters.risk_limits + 1;
        let risk_limit_id = risk_limit_id(&request, sequence);
        let payload = json!({
            "risk_limit_id": &risk_limit_id,
            "subject_commitment": &request.subject_commitment,
            "sponsor_pool_id": &request.sponsor_pool_id,
            "exposure_root": &request.exposure_root,
            "limit_root": &request.limit_root,
            "max_notional": request.max_notional,
            "consumed_notional": request.consumed_notional,
            "max_lots_per_epoch": request.max_lots_per_epoch,
            "epoch": request.epoch,
            "status": request.status.as_str()
        });
        let public_record_id = public_record_id("risk-limit", &risk_limit_id, &payload);
        let record = RiskLimitRecord {
            risk_limit_id: risk_limit_id.clone(),
            subject_commitment: request.subject_commitment,
            sponsor_pool_id: request.sponsor_pool_id,
            exposure_root: request.exposure_root,
            limit_root: request.limit_root,
            max_notional: request.max_notional,
            consumed_notional: request.consumed_notional,
            max_lots_per_epoch: request.max_lots_per_epoch,
            epoch: request.epoch,
            status: request.status,
            created_height: self.current_height,
            updated_height: self.current_height,
            public_record_id,
        };
        self.risk_limits.insert(risk_limit_id.clone(), record);
        self.counters.risk_limits = sequence;
        self.push_event(EventKind::RiskLimitUpdated, &risk_limit_id)?;
        self.refresh_roots();
        Ok(risk_limit_id)
    }

    pub fn quarantine_abuse(&mut self, request: AbuseQuarantineRequest) -> Result<String> {
        self.ensure_capacity(
            "quarantine_cases",
            self.quarantine_cases.len(),
            MAX_QUARANTINE_CASES,
        )?;
        self.validate_quarantine_request(&request)?;
        for lot_id in &request.affected_lot_ids {
            self.require_coupon_lot(lot_id)?;
        }
        let sequence = self.counters.quarantine_cases + 1;
        let quarantine_id = quarantine_id(&request, sequence);
        let payload = json!({
            "quarantine_id": &quarantine_id,
            "subject_id": &request.subject_id,
            "reporter_commitment": &request.reporter_commitment,
            "evidence_root": &request.evidence_root,
            "affected_lot_ids_root": id_list_root("abuse-quarantine-lots", &request.affected_lot_ids),
            "quarantine_reason_code": &request.quarantine_reason_code,
            "release_height": request.release_height,
            "status": request.status.as_str()
        });
        let public_record_id = public_record_id("abuse-quarantine", &quarantine_id, &payload);
        let record = QuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            subject_id: request.subject_id,
            reporter_commitment: request.reporter_commitment,
            evidence_root: request.evidence_root,
            affected_lot_ids: request.affected_lot_ids.clone(),
            quarantine_reason_code: request.quarantine_reason_code,
            release_height: request.release_height,
            status: request.status,
            created_height: self.current_height,
            updated_height: self.current_height,
            public_record_id,
        };
        self.quarantine_cases.insert(quarantine_id.clone(), record);
        for lot_id in request.affected_lot_ids {
            if let Some(lot) = self.coupon_lots.get_mut(&lot_id) {
                if lot.status != CouponLotStatus::Quarantined {
                    self.counters.quarantined_lots =
                        self.counters.quarantined_lots.saturating_add(1);
                }
                lot.status = CouponLotStatus::Quarantined;
                lot.updated_height = self.current_height;
            }
        }
        self.counters.quarantine_cases = sequence;
        self.push_event(EventKind::AbuseQuarantined, &quarantine_id)?;
        self.refresh_roots();
        Ok(quarantine_id)
    }

    pub fn grant_redaction_budget(&mut self, request: RedactionBudgetRequest) -> Result<String> {
        self.ensure_capacity(
            "redaction_budgets",
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
        )?;
        self.validate_redaction_budget_request(&request)?;
        let sequence = self.counters.redaction_budgets + 1;
        let redaction_budget_id = redaction_budget_id(&request, sequence);
        let payload = json!({
            "redaction_budget_id": &redaction_budget_id,
            "auditor_commitment": &request.auditor_commitment,
            "subject_id": &request.subject_id,
            "budget_root": &request.budget_root,
            "max_redactions": request.max_redactions,
            "spent_redactions": request.spent_redactions,
            "window_start_height": request.window_start_height,
            "window_end_height": request.window_end_height,
            "disclosure_policy_root": &request.disclosure_policy_root
        });
        let public_record_id = public_record_id("redaction-budget", &redaction_budget_id, &payload);
        let record = RedactionBudgetRecord {
            redaction_budget_id: redaction_budget_id.clone(),
            auditor_commitment: request.auditor_commitment,
            subject_id: request.subject_id,
            budget_root: request.budget_root,
            max_redactions: request.max_redactions,
            spent_redactions: request.spent_redactions,
            window_start_height: request.window_start_height,
            window_end_height: request.window_end_height,
            disclosure_policy_root: request.disclosure_policy_root,
            created_height: self.current_height,
            updated_height: self.current_height,
            public_record_id,
        };
        self.redaction_budgets
            .insert(redaction_budget_id.clone(), record);
        self.counters.redaction_budgets = sequence;
        self.push_event(EventKind::RedactionBudgetGranted, &redaction_budget_id)?;
        self.refresh_roots();
        Ok(redaction_budget_id)
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.current_height {
            return Err("height cannot move backwards".to_string());
        }
        self.current_height = height;
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "coupon_lots_root": self.roots.coupon_lots_root,
                "sponsor_pools_root": self.roots.sponsor_pools_root,
                "clearing_attestations_root": self.roots.clearing_attestations_root,
                "settlement_batches_root": self.roots.settlement_batches_root,
                "rebate_accounts_root": self.roots.rebate_accounts_root,
                "risk_limits_root": self.roots.risk_limits_root,
                "quarantine_cases_root": self.roots.quarantine_cases_root,
                "redaction_budgets_root": self.roots.redaction_budgets_root,
                "events_root": self.roots.events_root,
                "counters_root": self.roots.counters_root,
                "config_root": self.roots.config_root
            }
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert(
                "state_root".to_string(),
                Value::String(self.roots.state_root.clone()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.coupon_lots_root = public_record_root(
            COUPON_LOT_SCHEME,
            self.coupon_lots
                .values()
                .map(CouponLotRecord::public_record)
                .collect(),
        );
        self.roots.sponsor_pools_root = public_record_root(
            SPONSOR_POOL_SCHEME,
            self.sponsor_pools
                .values()
                .map(SponsorPoolRecord::public_record)
                .collect(),
        );
        self.roots.clearing_attestations_root = public_record_root(
            CLEARING_ATTESTATION_SCHEME,
            self.clearing_attestations
                .values()
                .map(ClearingAttestationRecord::public_record)
                .collect(),
        );
        self.roots.settlement_batches_root = public_record_root(
            SETTLEMENT_BATCH_SCHEME,
            self.settlement_batches
                .values()
                .map(SettlementBatchRecord::public_record)
                .collect(),
        );
        self.roots.rebate_accounts_root = public_record_root(
            REBATE_ACCOUNTING_SCHEME,
            self.rebate_accounts
                .values()
                .map(RebateAccountRecord::public_record)
                .collect(),
        );
        self.roots.risk_limits_root = public_record_root(
            RISK_LIMIT_SCHEME,
            self.risk_limits
                .values()
                .map(RiskLimitRecord::public_record)
                .collect(),
        );
        self.roots.quarantine_cases_root = public_record_root(
            QUARANTINE_SCHEME,
            self.quarantine_cases
                .values()
                .map(QuarantineRecord::public_record)
                .collect(),
        );
        self.roots.redaction_budgets_root = public_record_root(
            REDACTION_BUDGET_SCHEME,
            self.redaction_budgets
                .values()
                .map(RedactionBudgetRecord::public_record)
                .collect(),
        );
        self.roots.events_root = public_record_root(
            EVENT_SCHEME,
            self.events
                .values()
                .map(RuntimeEventRecord::public_record)
                .collect(),
        );
        self.roots.counters_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots.config_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-CONFIG",
            &self.config.public_record(),
        );
        self.roots.state_root = state_root_from_record(&self.public_record_without_state_root());
    }

    fn push_event(&mut self, event_kind: EventKind, subject_id: &str) -> Result<()> {
        self.ensure_capacity("events", self.events.len(), MAX_EVENTS)?;
        let sequence = self.counters.events + 1;
        let event_root = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-EVENT-ROOT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Int(sequence as i128),
                HashPart::Str(event_kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Int(self.current_height as i128),
            ],
            32,
        );
        let event_id = domain_hash(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-EVENT-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Int(sequence as i128),
                HashPart::Str(&event_root),
            ],
            32,
        );
        let record = RuntimeEventRecord {
            event_id: event_id.clone(),
            event_kind,
            subject_id: subject_id.to_string(),
            height: self.current_height,
            event_root,
        };
        self.events.insert(event_id, record);
        self.counters.events = sequence;
        Ok(())
    }

    fn validate_coupon_lot_request(&self, request: &EncryptedCouponLotRequest) -> Result<()> {
        ensure_non_empty("owner_commitment", &request.owner_commitment)?;
        ensure_non_empty("sponsor_pool_id", &request.sponsor_pool_id)?;
        ensure_root("encrypted_coupon_root", &request.encrypted_coupon_root)?;
        ensure_root("coupon_nullifier_root", &request.coupon_nullifier_root)?;
        ensure_non_empty("gas_asset_id", &request.gas_asset_id)?;
        ensure_root("pq_envelope_root", &request.pq_envelope_root)?;
        ensure_root("range_proof_root", &request.range_proof_root)?;
        ensure_non_empty("lot_nonce", &request.lot_nonce)?;
        ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        ensure_bps("min_rebate_bps", request.min_rebate_bps)?;
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("coupon lot exceeds runtime max_user_fee_bps".to_string());
        }
        if request.committed_notional < self.config.min_lot_notional {
            return Err("coupon lot committed_notional is below runtime minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("coupon lot privacy set is below runtime minimum".to_string());
        }
        if request.expiry_height <= self.current_height {
            return Err("coupon lot expiry_height must be in the future".to_string());
        }
        Ok(())
    }

    fn validate_sponsor_pool_request(&self, request: &SponsorPoolRequest) -> Result<()> {
        ensure_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        ensure_non_empty("pool_label_commitment", &request.pool_label_commitment)?;
        ensure_root("escrow_root", &request.escrow_root)?;
        ensure_root("policy_root", &request.policy_root)?;
        ensure_root("pq_public_root", &request.pq_public_root)?;
        ensure_non_empty("settlement_asset_id", &request.settlement_asset_id)?;
        ensure_non_empty("pool_nonce", &request.pool_nonce)?;
        ensure_bps("max_sponsor_fee_bps", request.max_sponsor_fee_bps)?;
        ensure_bps("target_rebate_bps", request.target_rebate_bps)?;
        if request.capacity < self.config.min_sponsor_escrow {
            return Err("sponsor pool capacity is below runtime escrow minimum".to_string());
        }
        if request.max_sponsor_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("sponsor pool exceeds runtime max_sponsor_fee_bps".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("sponsor pool min privacy set is below runtime minimum".to_string());
        }
        Ok(())
    }

    fn validate_clearing_attestation_request(
        &self,
        request: &ClearingAttestationRequest,
    ) -> Result<()> {
        ensure_non_empty("coupon_lot_id", &request.coupon_lot_id)?;
        ensure_non_empty("sponsor_pool_id", &request.sponsor_pool_id)?;
        ensure_non_empty("attester_commitment", &request.attester_commitment)?;
        ensure_root("clearing_price_root", &request.clearing_price_root)?;
        ensure_root("liquidity_witness_root", &request.liquidity_witness_root)?;
        ensure_root("privacy_witness_root", &request.privacy_witness_root)?;
        ensure_root("risk_witness_root", &request.risk_witness_root)?;
        ensure_root("pq_signature_root", &request.pq_signature_root)?;
        ensure_non_empty("attestation_nonce", &request.attestation_nonce)?;
        if request.valid_until_height <= self.current_height {
            return Err(
                "clearing attestation valid_until_height must be in the future".to_string(),
            );
        }
        Ok(())
    }

    fn validate_settlement_batch_request(&self, request: &SettlementBatchRequest) -> Result<()> {
        ensure_unique("coupon_lot_ids", &request.coupon_lot_ids)?;
        ensure_unique("sponsor_pool_ids", &request.sponsor_pool_ids)?;
        ensure_unique("attestation_ids", &request.attestation_ids)?;
        ensure_non_empty(
            "batch_operator_commitment",
            &request.batch_operator_commitment,
        )?;
        ensure_root("netting_root", &request.netting_root)?;
        ensure_root("settlement_root", &request.settlement_root)?;
        ensure_root("rebate_root", &request.rebate_root)?;
        ensure_root("residual_root", &request.residual_root)?;
        ensure_non_empty("batch_nonce", &request.batch_nonce)?;
        if request.coupon_lot_ids.len() > self.config.max_lots_per_batch {
            return Err("settlement batch exceeds max_lots_per_batch".to_string());
        }
        if request.sponsor_pool_ids.len() > self.config.max_sponsors_per_batch {
            return Err("settlement batch exceeds max_sponsors_per_batch".to_string());
        }
        if request.finality_height < self.current_height + self.config.settlement_finality_blocks {
            return Err("settlement batch finality_height is too early".to_string());
        }
        Ok(())
    }

    fn validate_rebate_accounting_request(&self, request: &RebateAccountingRequest) -> Result<()> {
        ensure_non_empty("account_commitment", &request.account_commitment)?;
        ensure_non_empty("coupon_lot_id", &request.coupon_lot_id)?;
        ensure_non_empty("sponsor_pool_id", &request.sponsor_pool_id)?;
        ensure_non_empty("settlement_batch_id", &request.settlement_batch_id)?;
        ensure_root("accounting_root", &request.accounting_root)?;
        ensure_non_empty("rebate_nonce", &request.rebate_nonce)?;
        if request.paid_rebate > request.accrued_rebate {
            return Err("paid_rebate cannot exceed accrued_rebate".to_string());
        }
        if request.clawback_amount > request.accrued_rebate {
            return Err("clawback_amount cannot exceed accrued_rebate".to_string());
        }
        Ok(())
    }

    fn validate_risk_limit_request(&self, request: &RiskLimitRequest) -> Result<()> {
        ensure_non_empty("subject_commitment", &request.subject_commitment)?;
        ensure_non_empty("sponsor_pool_id", &request.sponsor_pool_id)?;
        ensure_root("exposure_root", &request.exposure_root)?;
        ensure_root("limit_root", &request.limit_root)?;
        ensure_non_empty("risk_nonce", &request.risk_nonce)?;
        ensure_positive_u64("max_notional", request.max_notional)?;
        ensure_positive_u64("max_lots_per_epoch", request.max_lots_per_epoch)?;
        if request.consumed_notional > request.max_notional {
            return Err("risk consumed_notional exceeds max_notional".to_string());
        }
        Ok(())
    }

    fn validate_quarantine_request(&self, request: &AbuseQuarantineRequest) -> Result<()> {
        ensure_non_empty("subject_id", &request.subject_id)?;
        ensure_non_empty("reporter_commitment", &request.reporter_commitment)?;
        ensure_root("evidence_root", &request.evidence_root)?;
        ensure_unique("affected_lot_ids", &request.affected_lot_ids)?;
        ensure_non_empty("quarantine_reason_code", &request.quarantine_reason_code)?;
        ensure_non_empty("quarantine_nonce", &request.quarantine_nonce)?;
        if request.release_height <= self.current_height {
            return Err("quarantine release_height must be in the future".to_string());
        }
        Ok(())
    }

    fn validate_redaction_budget_request(&self, request: &RedactionBudgetRequest) -> Result<()> {
        ensure_non_empty("auditor_commitment", &request.auditor_commitment)?;
        ensure_non_empty("subject_id", &request.subject_id)?;
        ensure_root("budget_root", &request.budget_root)?;
        ensure_root("disclosure_policy_root", &request.disclosure_policy_root)?;
        ensure_non_empty("redaction_nonce", &request.redaction_nonce)?;
        ensure_positive_u64("max_redactions", request.max_redactions)?;
        if request.spent_redactions > request.max_redactions {
            return Err("spent_redactions exceeds max_redactions".to_string());
        }
        if request.window_end_height <= request.window_start_height {
            return Err("redaction budget window is empty".to_string());
        }
        Ok(())
    }

    fn ensure_capacity(&self, label: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            Err(format!("{label} capacity exhausted"))
        } else {
            Ok(())
        }
    }

    fn require_coupon_lot(&self, coupon_lot_id: &str) -> Result<&CouponLotRecord> {
        self.coupon_lots
            .get(coupon_lot_id)
            .ok_or_else(|| format!("unknown coupon lot {coupon_lot_id}"))
    }

    fn require_sponsor_pool(&self, sponsor_pool_id: &str) -> Result<&SponsorPoolRecord> {
        self.sponsor_pools
            .get(sponsor_pool_id)
            .ok_or_else(|| format!("unknown sponsor pool {sponsor_pool_id}"))
    }

    fn require_attestation(&self, attestation_id: &str) -> Result<&ClearingAttestationRecord> {
        self.clearing_attestations
            .get(attestation_id)
            .ok_or_else(|| format!("unknown clearing attestation {attestation_id}"))
    }

    fn require_settlement_batch(
        &self,
        settlement_batch_id: &str,
    ) -> Result<&SettlementBatchRecord> {
        self.settlement_batches
            .get(settlement_batch_id)
            .ok_or_else(|| format!("unknown settlement batch {settlement_batch_id}"))
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = devnet();
    let sponsor_pool_id = state
        .open_sponsor_pool(SponsorPoolRequest {
            sponsor_commitment: sample_root("sponsor-alpha"),
            pool_label_commitment: sample_root("low-fee-wallet-gas"),
            escrow_root: sample_root("escrow-alpha"),
            policy_root: sample_root("policy-alpha"),
            capacity: 1_000_000,
            max_sponsor_fee_bps: 5,
            target_rebate_bps: 6,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            settlement_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            pq_public_root: sample_root("pq-public-alpha"),
            pool_nonce: "demo-sponsor-pool-0".to_string(),
        })
        .expect("demo sponsor pool opens");
    let coupon_lot_id = state
        .submit_coupon_lot(EncryptedCouponLotRequest {
            owner_commitment: sample_root("owner-alpha"),
            sponsor_pool_id: sponsor_pool_id.clone(),
            encrypted_coupon_root: sample_root("encrypted-coupon-lot-alpha"),
            coupon_nullifier_root: sample_root("coupon-nullifier-alpha"),
            gas_asset_id: DEVNET_GAS_ASSET_ID.to_string(),
            committed_notional: 25_000,
            max_user_fee_bps: 10,
            min_rebate_bps: 4,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_envelope_root: sample_root("pq-envelope-alpha"),
            range_proof_root: sample_root("range-proof-alpha"),
            expiry_height: DEVNET_HEIGHT + DEFAULT_COUPON_LOT_TTL_BLOCKS,
            lot_nonce: "demo-coupon-lot-0".to_string(),
        })
        .expect("demo coupon lot submits");
    let attestation_id = state
        .publish_clearing_attestation(ClearingAttestationRequest {
            coupon_lot_id: coupon_lot_id.clone(),
            sponsor_pool_id: sponsor_pool_id.clone(),
            attester_commitment: sample_root("attester-alpha"),
            verdict: ClearingVerdict::Approved,
            clearing_price_root: sample_root("clearing-price-alpha"),
            liquidity_witness_root: sample_root("liquidity-witness-alpha"),
            privacy_witness_root: sample_root("privacy-witness-alpha"),
            risk_witness_root: sample_root("risk-witness-alpha"),
            pq_signature_root: sample_root("pq-signature-alpha"),
            valid_until_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
            attestation_nonce: "demo-attestation-0".to_string(),
        })
        .expect("demo clearing attestation publishes");
    let settlement_batch_id = state
        .build_settlement_batch(SettlementBatchRequest {
            coupon_lot_ids: vec![coupon_lot_id.clone()],
            sponsor_pool_ids: vec![sponsor_pool_id.clone()],
            attestation_ids: vec![attestation_id],
            batch_operator_commitment: sample_root("batch-operator-alpha"),
            netting_root: sample_root("netting-alpha"),
            settlement_root: sample_root("settlement-alpha"),
            rebate_root: sample_root("rebate-alpha"),
            residual_root: sample_root("residual-alpha"),
            finality_height: DEVNET_HEIGHT + DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            batch_nonce: "demo-settlement-batch-0".to_string(),
        })
        .expect("demo settlement batch builds");
    state
        .post_rebate_accounting(RebateAccountingRequest {
            account_commitment: sample_root("rebate-account-alpha"),
            coupon_lot_id: coupon_lot_id.clone(),
            sponsor_pool_id: sponsor_pool_id.clone(),
            settlement_batch_id,
            accrued_rebate: 150,
            paid_rebate: 150,
            clawback_amount: 0,
            accounting_root: sample_root("rebate-accounting-alpha"),
            status: RebateStatus::Paid,
            rebate_nonce: "demo-rebate-0".to_string(),
        })
        .expect("demo rebate posts");
    state
        .set_risk_limit(RiskLimitRequest {
            subject_commitment: sample_root("owner-alpha"),
            sponsor_pool_id: sponsor_pool_id.clone(),
            exposure_root: sample_root("exposure-alpha"),
            limit_root: sample_root("limit-alpha"),
            max_notional: 250_000,
            consumed_notional: 25_000,
            max_lots_per_epoch: 32,
            epoch: DEVNET_HEIGHT / 720,
            status: RiskLimitStatus::Active,
            risk_nonce: "demo-risk-limit-0".to_string(),
        })
        .expect("demo risk limit records");
    state
        .grant_redaction_budget(RedactionBudgetRequest {
            auditor_commitment: sample_root("auditor-alpha"),
            subject_id: coupon_lot_id.clone(),
            budget_root: sample_root("redaction-budget-alpha"),
            max_redactions: 8,
            spent_redactions: 1,
            window_start_height: DEVNET_HEIGHT,
            window_end_height: DEVNET_HEIGHT + DEFAULT_REDACTION_WINDOW_BLOCKS,
            disclosure_policy_root: sample_root("disclosure-policy-alpha"),
            redaction_nonce: "demo-redaction-budget-0".to_string(),
        })
        .expect("demo redaction budget records");
    state
        .quarantine_abuse(AbuseQuarantineRequest {
            subject_id: sample_root("abuse-subject-alpha"),
            reporter_commitment: sample_root("reporter-alpha"),
            evidence_root: sample_root("abuse-evidence-alpha"),
            affected_lot_ids: vec![coupon_lot_id],
            quarantine_reason_code: "velocity_replay_probe".to_string(),
            release_height: DEVNET_HEIGHT + DEFAULT_QUARANTINE_WINDOW_BLOCKS,
            status: QuarantineStatus::EvidenceCollecting,
            quarantine_nonce: "demo-quarantine-0".to_string(),
        })
        .expect("demo quarantine records");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn coupon_lot_id(request: &EncryptedCouponLotRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-LOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.sponsor_pool_id),
            HashPart::Str(&request.encrypted_coupon_root),
            HashPart::Str(&request.coupon_nullifier_root),
            HashPart::Str(&request.lot_nonce),
        ],
        32,
    )
}

pub fn sponsor_pool_id(request: &SponsorPoolRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-SPONSOR-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.pool_label_commitment),
            HashPart::Str(&request.escrow_root),
            HashPart::Str(&request.pool_nonce),
        ],
        32,
    )
}

pub fn clearing_attestation_id(request: &ClearingAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-CLEARING-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.coupon_lot_id),
            HashPart::Str(&request.sponsor_pool_id),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn settlement_batch_id(request: &SettlementBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("settlement-id-lots", &request.coupon_lot_ids)),
            HashPart::Str(&id_list_root(
                "settlement-id-sponsors",
                &request.sponsor_pool_ids,
            )),
            HashPart::Str(&id_list_root(
                "settlement-id-attestations",
                &request.attestation_ids,
            )),
            HashPart::Str(&request.batch_operator_commitment),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn rebate_account_id(request: &RebateAccountingRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-REBATE-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.coupon_lot_id),
            HashPart::Str(&request.settlement_batch_id),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

pub fn risk_limit_id(request: &RiskLimitRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-RISK-LIMIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_commitment),
            HashPart::Str(&request.sponsor_pool_id),
            HashPart::Int(request.epoch as i128),
            HashPart::Str(&request.risk_nonce),
        ],
        32,
    )
}

pub fn quarantine_id(request: &AbuseQuarantineRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&id_list_root(
                "quarantine-id-lots",
                &request.affected_lot_ids,
            )),
            HashPart::Str(&request.quarantine_nonce),
        ],
        32,
    )
}

pub fn redaction_budget_id(request: &RedactionBudgetRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.auditor_commitment),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.budget_root),
            HashPart::Str(&request.redaction_nonce),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-STATE",
        record,
    )
}

pub fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-ID-LIST-{domain}"),
        ids.iter().map(|id| json!(id)).collect(),
    )
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-GAS-COUPON-DEMO-SAMPLE",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_root(field: &str, value: &str) -> Result<()> {
    ensure_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn ensure_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_unique(field: &str, values: &[String]) -> Result<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}
