use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<T> =
    Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_FEE_SPONSOR_DERIVATIVES_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-batch-fee-sponsor-derivatives-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_FEE_SPONSOR_DERIVATIVES_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-confidential-batch-fee-sponsor-derivatives-v1";
pub const PQ_SEALING_SUITE: &str =
    "ml-kem-1024+xwing-sealed-batch-fee-sponsor-derivative-position-v1";
pub const SPONSOR_TRANCHE_SCHEME: &str = "private-low-fee-sponsor-tranche-root-v1";
pub const FEE_COUPON_FORWARD_SCHEME: &str = "private-low-fee-coupon-forward-root-v1";
pub const ENCRYPTED_BENEFICIARY_POOL_SCHEME: &str =
    "ringct-style-sealed-batch-fee-beneficiary-pool-root-v1";
pub const PQ_SPONSOR_ATTESTATION_SCHEME: &str =
    "pq-sponsor-capacity-attestation-and-redaction-root-v1";
pub const SETTLEMENT_NETTING_SCHEME: &str = "private-batch-fee-sponsor-settlement-netting-root-v1";
pub const RISK_LIMIT_SCHEME: &str = "private-low-fee-sponsor-risk-limit-root-v1";
pub const REBATE_SCHEME: &str = "roots-only-private-batch-fee-rebate-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "deterministic-redaction-budget-nullifier-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_911_040;
pub const DEVNET_EPOCH: u64 = 2_654;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_TRANCHE_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_FORWARD_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_POOL_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_NETTING_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 6;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_SPONSOR_FEE_BPS: u64 = 2;
pub const DEFAULT_FORWARD_FEE_BPS: u64 = 1;
pub const DEFAULT_REBATE_BPS: u64 = 8;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_RESERVE_BPS: u64 = 1_750;
pub const DEFAULT_JUNIOR_ATTACHMENT_BPS: u64 = 0;
pub const DEFAULT_MEZZANINE_ATTACHMENT_BPS: u64 = 2_500;
pub const DEFAULT_SENIOR_ATTACHMENT_BPS: u64 = 7_500;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 40_000;
pub const DEFAULT_RED_ACTION_QUOTA: u64 = 64;
pub const DEFAULT_MAX_SPONSOR_TRANCHES: usize = 1_048_576;
pub const DEFAULT_MAX_FEE_COUPON_FORWARDS: usize = 2_097_152;
pub const DEFAULT_MAX_BENEFICIARY_POOLS: usize = 1_048_576;
pub const DEFAULT_MAX_PQ_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_SETTLEMENT_NETTINGS: usize = 1_048_576;
pub const DEFAULT_MAX_RISK_LIMITS: usize = 524_288;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheKind {
    Junior,
    Mezzanine,
    Senior,
    SuperSenior,
    FirstLoss,
    RebateReserve,
    OracleBackstop,
    LiquidityBuffer,
}

impl TrancheKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Junior => "junior",
            Self::Mezzanine => "mezzanine",
            Self::Senior => "senior",
            Self::SuperSenior => "super_senior",
            Self::FirstLoss => "first_loss",
            Self::RebateReserve => "rebate_reserve",
            Self::OracleBackstop => "oracle_backstop",
            Self::LiquidityBuffer => "liquidity_buffer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheStatus {
    Proposed,
    Active,
    Reserving,
    Hedging,
    Settling,
    Settled,
    Paused,
    Slashed,
    Retired,
}

impl TrancheStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserving | Self::Hedging)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponForwardKind {
    FixedFee,
    FloatingFee,
    Corridor,
    BatchFloor,
    BatchCap,
    RebateLinked,
    SponsorSpread,
    OracleIndexed,
}

impl CouponForwardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixedFee => "fixed_fee",
            Self::FloatingFee => "floating_fee",
            Self::Corridor => "corridor",
            Self::BatchFloor => "batch_floor",
            Self::BatchCap => "batch_cap",
            Self::RebateLinked => "rebate_linked",
            Self::SponsorSpread => "sponsor_spread",
            Self::OracleIndexed => "oracle_indexed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponForwardStatus {
    Quoted,
    Open,
    Matched,
    Netted,
    Exercised,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl CouponForwardStatus {
    pub fn nettable(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Netted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BeneficiaryPoolKind {
    WalletBatch,
    MerchantBatch,
    BridgeExitBatch,
    DefiBatch,
    PayrollBatch,
    ContractBatch,
    RelayerBatch,
    RecoveryBatch,
}

impl BeneficiaryPoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletBatch => "wallet_batch",
            Self::MerchantBatch => "merchant_batch",
            Self::BridgeExitBatch => "bridge_exit_batch",
            Self::DefiBatch => "defi_batch",
            Self::PayrollBatch => "payroll_batch",
            Self::ContractBatch => "contract_batch",
            Self::RelayerBatch => "relayer_batch",
            Self::RecoveryBatch => "recovery_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BeneficiaryPoolStatus {
    Sealed,
    Admitted,
    SponsorReserved,
    Netted,
    Rebating,
    Settled,
    Disputed,
    Expired,
}

impl BeneficiaryPoolStatus {
    pub fn reservable(self) -> bool {
        matches!(self, Self::Sealed | Self::Admitted | Self::SponsorReserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Quorum,
    Usable,
    Superseded,
    Redacted,
    Disputed,
    Expired,
    Slashed,
}

impl AttestationStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Quorum | Self::Usable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Draft,
    Balanced,
    Publishing,
    Settled,
    Rebating,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitKind {
    SponsorNotional,
    TrancheExposure,
    BeneficiaryConcentration,
    ForwardDelta,
    RebateLiability,
    RedactionBudget,
    SettlementVaR,
    OracleFreshness,
}

impl RiskLimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorNotional => "sponsor_notional",
            Self::TrancheExposure => "tranche_exposure",
            Self::BeneficiaryConcentration => "beneficiary_concentration",
            Self::ForwardDelta => "forward_delta",
            Self::RebateLiability => "rebate_liability",
            Self::RedactionBudget => "redaction_budget",
            Self::SettlementVaR => "settlement_var",
            Self::OracleFreshness => "oracle_freshness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitStatus {
    Proposed,
    Active,
    Warning,
    Breached,
    Remediating,
    Cleared,
    Paused,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Queued,
    Proven,
    Published,
    Claimed,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionBudgetStatus {
    Open,
    Reserved,
    Spent,
    Replenishing,
    Exhausted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub pq_sealing_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub tranche_ttl_blocks: u64,
    pub forward_ttl_blocks: u64,
    pub pool_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub netting_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_fee_bps: u64,
    pub forward_fee_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub reserve_bps: u64,
    pub junior_attachment_bps: u64,
    pub mezzanine_attachment_bps: u64,
    pub senior_attachment_bps: u64,
    pub max_leverage_bps: u64,
    pub default_redaction_quota: u64,
    pub max_sponsor_tranches: usize,
    pub max_fee_coupon_forwards: usize,
    pub max_beneficiary_pools: usize,
    pub max_pq_attestations: usize,
    pub max_settlement_nettings: usize,
    pub max_risk_limits: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            pq_sealing_suite: PQ_SEALING_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            tranche_ttl_blocks: DEFAULT_TRANCHE_TTL_BLOCKS,
            forward_ttl_blocks: DEFAULT_FORWARD_TTL_BLOCKS,
            pool_ttl_blocks: DEFAULT_POOL_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            netting_ttl_blocks: DEFAULT_NETTING_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_fee_bps: DEFAULT_SPONSOR_FEE_BPS,
            forward_fee_bps: DEFAULT_FORWARD_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            reserve_bps: DEFAULT_RESERVE_BPS,
            junior_attachment_bps: DEFAULT_JUNIOR_ATTACHMENT_BPS,
            mezzanine_attachment_bps: DEFAULT_MEZZANINE_ATTACHMENT_BPS,
            senior_attachment_bps: DEFAULT_SENIOR_ATTACHMENT_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            default_redaction_quota: DEFAULT_RED_ACTION_QUOTA,
            max_sponsor_tranches: DEFAULT_MAX_SPONSOR_TRANCHES,
            max_fee_coupon_forwards: DEFAULT_MAX_FEE_COUPON_FORWARDS,
            max_beneficiary_pools: DEFAULT_MAX_BENEFICIARY_POOLS,
            max_pq_attestations: DEFAULT_MAX_PQ_ATTESTATIONS,
            max_settlement_nettings: DEFAULT_MAX_SETTLEMENT_NETTINGS,
            max_risk_limits: DEFAULT_MAX_RISK_LIMITS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_tranches: u64,
    pub fee_coupon_forwards: u64,
    pub beneficiary_pools: u64,
    pub pq_sponsor_attestations: u64,
    pub settlement_nettings: u64,
    pub risk_limits: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub sponsor_tranches_root: String,
    pub fee_coupon_forwards_root: String,
    pub beneficiary_pools_root: String,
    pub pq_sponsor_attestations_root: String,
    pub settlement_nettings_root: String,
    pub risk_limits_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub counters_root: String,
    pub config_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorTrancheRequest {
    pub sponsor_commitment: String,
    pub tranche_kind: TrancheKind,
    pub capacity_commitment_root: String,
    pub reserve_commitment_root: String,
    pub attachment_bps: u64,
    pub detachment_bps: u64,
    pub maturity_height: u64,
    pub risk_limit_id: Option<String>,
    pub attestation_id: Option<String>,
    pub tranche_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorTrancheRecord {
    pub tranche_id: String,
    pub sponsor_commitment: String,
    pub tranche_kind: TrancheKind,
    pub capacity_commitment_root: String,
    pub reserve_commitment_root: String,
    pub attachment_bps: u64,
    pub detachment_bps: u64,
    pub maturity_height: u64,
    pub risk_limit_id: Option<String>,
    pub attestation_id: Option<String>,
    pub status: TrancheStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub tranche_nonce_root: String,
    pub public_root: String,
}

impl SponsorTrancheRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "sponsor_commitment": self.sponsor_commitment,
            "tranche_kind": self.tranche_kind,
            "capacity_commitment_root": self.capacity_commitment_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "attachment_bps": self.attachment_bps,
            "detachment_bps": self.detachment_bps,
            "maturity_height": self.maturity_height,
            "risk_limit_id": self.risk_limit_id,
            "attestation_id": self.attestation_id,
            "status": self.status,
            "opened_height": self.opened_height,
            "sequence": self.sequence,
            "tranche_nonce_root": self.tranche_nonce_root,
            "public_root": self.public_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCouponForwardRequest {
    pub tranche_id: String,
    pub pool_id: Option<String>,
    pub forward_kind: CouponForwardKind,
    pub payer_commitment: String,
    pub receiver_commitment: String,
    pub notional_commitment_root: String,
    pub strike_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub start_height: u64,
    pub maturity_height: u64,
    pub forward_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCouponForwardRecord {
    pub forward_id: String,
    pub tranche_id: String,
    pub pool_id: Option<String>,
    pub forward_kind: CouponForwardKind,
    pub payer_commitment: String,
    pub receiver_commitment: String,
    pub notional_commitment_root: String,
    pub strike_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub start_height: u64,
    pub maturity_height: u64,
    pub status: CouponForwardStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub forward_nonce_root: String,
    pub public_root: String,
}

impl FeeCouponForwardRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BeneficiaryPoolRequest {
    pub pool_kind: BeneficiaryPoolKind,
    pub sponsor_tranche_ids: Vec<String>,
    pub encrypted_beneficiary_root: String,
    pub encrypted_fee_obligation_root: String,
    pub batch_commitment_root: String,
    pub membership_nullifier_root: String,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub pool_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BeneficiaryPoolRecord {
    pub pool_id: String,
    pub pool_kind: BeneficiaryPoolKind,
    pub sponsor_tranche_ids: Vec<String>,
    pub encrypted_beneficiary_root: String,
    pub encrypted_fee_obligation_root: String,
    pub batch_commitment_root: String,
    pub membership_nullifier_root: String,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub status: BeneficiaryPoolStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub pool_nonce_root: String,
    pub public_root: String,
}

impl BeneficiaryPoolRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestationRequest {
    pub sponsor_commitment: String,
    pub tranche_ids: Vec<String>,
    pub capacity_statement_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub freshness_height: u64,
    pub security_bits: u16,
    pub attestation_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestationRecord {
    pub attestation_id: String,
    pub sponsor_commitment: String,
    pub tranche_ids: Vec<String>,
    pub capacity_statement_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub freshness_height: u64,
    pub security_bits: u16,
    pub status: AttestationStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub attestation_nonce_root: String,
    pub public_root: String,
}

impl PqSponsorAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementNettingRequest {
    pub pool_ids: Vec<String>,
    pub forward_ids: Vec<String>,
    pub tranche_ids: Vec<String>,
    pub gross_fee_commitment_root: String,
    pub net_fee_commitment_root: String,
    pub sponsor_payment_root: String,
    pub beneficiary_rebate_root: String,
    pub settlement_proof_root: String,
    pub netting_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementNettingRecord {
    pub netting_id: String,
    pub pool_ids: Vec<String>,
    pub forward_ids: Vec<String>,
    pub tranche_ids: Vec<String>,
    pub gross_fee_commitment_root: String,
    pub net_fee_commitment_root: String,
    pub sponsor_payment_root: String,
    pub beneficiary_rebate_root: String,
    pub settlement_proof_root: String,
    pub status: NettingStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub netting_nonce_root: String,
    pub public_root: String,
}

impl SettlementNettingRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskLimitRequest {
    pub sponsor_commitment: String,
    pub limit_kind: RiskLimitKind,
    pub subject_id: String,
    pub limit_commitment_root: String,
    pub utilization_commitment_root: String,
    pub warning_bps: u64,
    pub breach_bps: u64,
    pub limit_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskLimitRecord {
    pub risk_limit_id: String,
    pub sponsor_commitment: String,
    pub limit_kind: RiskLimitKind,
    pub subject_id: String,
    pub limit_commitment_root: String,
    pub utilization_commitment_root: String,
    pub warning_bps: u64,
    pub breach_bps: u64,
    pub status: RiskLimitStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub limit_nonce_root: String,
    pub public_root: String,
}

impl RiskLimitRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRequest {
    pub netting_id: String,
    pub pool_id: String,
    pub tranche_id: String,
    pub rebate_commitment_root: String,
    pub beneficiary_claim_root: String,
    pub coupon_forward_id: Option<String>,
    pub rebate_bps: u64,
    pub rebate_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub netting_id: String,
    pub pool_id: String,
    pub tranche_id: String,
    pub rebate_commitment_root: String,
    pub beneficiary_claim_root: String,
    pub coupon_forward_id: Option<String>,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub rebate_nonce_root: String,
    pub public_root: String,
}

impl RebateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub sponsor_commitment: String,
    pub subject_id: String,
    pub budget_commitment_root: String,
    pub redaction_nullifier_root: String,
    pub quota: u64,
    pub expires_height: u64,
    pub budget_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRecord {
    pub budget_id: String,
    pub sponsor_commitment: String,
    pub subject_id: String,
    pub budget_commitment_root: String,
    pub redaction_nullifier_root: String,
    pub quota: u64,
    pub spent: u64,
    pub expires_height: u64,
    pub status: RedactionBudgetStatus,
    pub opened_height: u64,
    pub sequence: u64,
    pub budget_nonce_root: String,
    pub public_root: String,
}

impl RedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub sponsor_tranches: BTreeMap<String, SponsorTrancheRecord>,
    pub fee_coupon_forwards: BTreeMap<String, FeeCouponForwardRecord>,
    pub beneficiary_pools: BTreeMap<String, BeneficiaryPoolRecord>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestationRecord>,
    pub settlement_nettings: BTreeMap<String, SettlementNettingRecord>,
    pub risk_limits: BTreeMap<String, RiskLimitRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub public_record_roots: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            sponsor_tranches: BTreeMap::new(),
            fee_coupon_forwards: BTreeMap::new(),
            beneficiary_pools: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            settlement_nettings: BTreeMap::new(),
            risk_limits: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_record_roots: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();

        let risk_limit = state
            .register_risk_limit(RiskLimitRequest {
                sponsor_commitment: commitment("sponsor-alpha"),
                limit_kind: RiskLimitKind::SponsorNotional,
                subject_id: "sponsor-alpha".to_string(),
                limit_commitment_root: demo_root("risk-limit-alpha"),
                utilization_commitment_root: demo_root("risk-utilization-alpha"),
                warning_bps: 7_500,
                breach_bps: 9_000,
                limit_nonce: "risk-limit-alpha-nonce".to_string(),
            })
            .expect("demo risk limit");

        let tranche = state
            .open_sponsor_tranche(SponsorTrancheRequest {
                sponsor_commitment: commitment("sponsor-alpha"),
                tranche_kind: TrancheKind::Mezzanine,
                capacity_commitment_root: demo_root("tranche-capacity-alpha"),
                reserve_commitment_root: demo_root("tranche-reserve-alpha"),
                attachment_bps: DEFAULT_MEZZANINE_ATTACHMENT_BPS,
                detachment_bps: DEFAULT_SENIOR_ATTACHMENT_BPS,
                maturity_height: DEVNET_HEIGHT + DEFAULT_TRANCHE_TTL_BLOCKS,
                risk_limit_id: Some(risk_limit.risk_limit_id.clone()),
                attestation_id: None,
                tranche_nonce: "tranche-alpha-nonce".to_string(),
            })
            .expect("demo tranche");

        let pool = state
            .open_beneficiary_pool(BeneficiaryPoolRequest {
                pool_kind: BeneficiaryPoolKind::MerchantBatch,
                sponsor_tranche_ids: vec![tranche.tranche_id.clone()],
                encrypted_beneficiary_root: demo_root("merchant-beneficiaries"),
                encrypted_fee_obligation_root: demo_root("merchant-fee-obligations"),
                batch_commitment_root: demo_root("merchant-batch"),
                membership_nullifier_root: demo_root("merchant-membership-nullifiers"),
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
                pool_nonce: "pool-alpha-nonce".to_string(),
            })
            .expect("demo pool");

        let forward = state
            .quote_fee_coupon_forward(FeeCouponForwardRequest {
                tranche_id: tranche.tranche_id.clone(),
                pool_id: Some(pool.pool_id.clone()),
                forward_kind: CouponForwardKind::Corridor,
                payer_commitment: commitment("payer-alpha"),
                receiver_commitment: commitment("receiver-alpha"),
                notional_commitment_root: demo_root("forward-notional-alpha"),
                strike_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS + 2,
                max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                start_height: DEVNET_HEIGHT,
                maturity_height: DEVNET_HEIGHT + DEFAULT_FORWARD_TTL_BLOCKS,
                forward_nonce: "forward-alpha-nonce".to_string(),
            })
            .expect("demo forward");

        let attestation = state
            .submit_pq_sponsor_attestation(PqSponsorAttestationRequest {
                sponsor_commitment: commitment("sponsor-alpha"),
                tranche_ids: vec![tranche.tranche_id.clone()],
                capacity_statement_root: demo_root("attestation-capacity-alpha"),
                pq_public_key_root: demo_root("attestation-key-alpha"),
                pq_signature_root: demo_root("attestation-signature-alpha"),
                freshness_height: DEVNET_HEIGHT,
                security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                attestation_nonce: "attestation-alpha-nonce".to_string(),
            })
            .expect("demo attestation");

        let netting = state
            .publish_settlement_netting(SettlementNettingRequest {
                pool_ids: vec![pool.pool_id.clone()],
                forward_ids: vec![forward.forward_id.clone()],
                tranche_ids: vec![tranche.tranche_id.clone()],
                gross_fee_commitment_root: demo_root("gross-fees-alpha"),
                net_fee_commitment_root: demo_root("net-fees-alpha"),
                sponsor_payment_root: demo_root("sponsor-payments-alpha"),
                beneficiary_rebate_root: demo_root("beneficiary-rebates-alpha"),
                settlement_proof_root: demo_root("settlement-proof-alpha"),
                netting_nonce: "netting-alpha-nonce".to_string(),
            })
            .expect("demo netting");

        state
            .publish_rebate(RebateRequest {
                netting_id: netting.netting_id.clone(),
                pool_id: pool.pool_id.clone(),
                tranche_id: tranche.tranche_id.clone(),
                rebate_commitment_root: demo_root("rebate-alpha"),
                beneficiary_claim_root: demo_root("rebate-claims-alpha"),
                coupon_forward_id: Some(forward.forward_id.clone()),
                rebate_bps: DEFAULT_REBATE_BPS,
                rebate_nonce: "rebate-alpha-nonce".to_string(),
            })
            .expect("demo rebate");

        state
            .open_redaction_budget(RedactionBudgetRequest {
                sponsor_commitment: commitment("sponsor-alpha"),
                subject_id: attestation.attestation_id,
                budget_commitment_root: demo_root("redaction-budget-alpha"),
                redaction_nullifier_root: demo_root("redaction-nullifiers-alpha"),
                quota: DEFAULT_RED_ACTION_QUOTA,
                expires_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
                budget_nonce: "redaction-budget-alpha-nonce".to_string(),
            })
            .expect("demo redaction budget");

        state
    }

    pub fn open_sponsor_tranche(
        &mut self,
        request: SponsorTrancheRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<SponsorTrancheRecord>
    {
        require_capacity(
            "sponsor_tranches",
            self.sponsor_tranches.len(),
            self.config.max_sponsor_tranches,
        )?;
        require_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        require_root(
            "capacity_commitment_root",
            &request.capacity_commitment_root,
        )?;
        require_root("reserve_commitment_root", &request.reserve_commitment_root)?;
        require_bps("attachment_bps", request.attachment_bps)?;
        require_bps("detachment_bps", request.detachment_bps)?;
        if request.attachment_bps >= request.detachment_bps {
            return Err("attachment_bps must be below detachment_bps".to_string());
        }
        if let Some(risk_limit_id) = &request.risk_limit_id {
            self.require_risk_limit(risk_limit_id)?;
        }
        if let Some(attestation_id) = &request.attestation_id {
            self.require_attestation(attestation_id)?;
        }

        let sequence = self.counters.sponsor_tranches + 1;
        let tranche_id = sponsor_tranche_id(&request, sequence);
        let nonce_root = payload_root("SPONSOR-TRANCHE-NONCE", &json!(request.tranche_nonce));
        let mut record = SponsorTrancheRecord {
            tranche_id: tranche_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            tranche_kind: request.tranche_kind,
            capacity_commitment_root: request.capacity_commitment_root,
            reserve_commitment_root: request.reserve_commitment_root,
            attachment_bps: request.attachment_bps,
            detachment_bps: request.detachment_bps,
            maturity_height: request.maturity_height,
            risk_limit_id: request.risk_limit_id,
            attestation_id: request.attestation_id,
            status: TrancheStatus::Active,
            opened_height: self.config.devnet_height,
            sequence,
            tranche_nonce_root: nonce_root,
            public_root: String::new(),
        };
        record.public_root = root_from_record(SPONSOR_TRANCHE_SCHEME, &record.public_record());
        self.sponsor_tranches.insert(tranche_id, record.clone());
        self.counters.sponsor_tranches = sequence;
        self.remember_public_root(&record.tranche_id, &record.public_root);
        Ok(record)
    }

    pub fn quote_fee_coupon_forward(
        &mut self,
        request: FeeCouponForwardRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<FeeCouponForwardRecord>
    {
        require_capacity(
            "fee_coupon_forwards",
            self.fee_coupon_forwards.len(),
            self.config.max_fee_coupon_forwards,
        )?;
        let tranche = self.require_tranche(&request.tranche_id)?;
        if !tranche.status.usable() {
            return Err(format!("tranche {} is not usable", request.tranche_id));
        }
        if let Some(pool_id) = &request.pool_id {
            self.require_pool(pool_id)?;
        }
        require_non_empty("payer_commitment", &request.payer_commitment)?;
        require_non_empty("receiver_commitment", &request.receiver_commitment)?;
        require_root(
            "notional_commitment_root",
            &request.notional_commitment_root,
        )?;
        require_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        if request.start_height >= request.maturity_height {
            return Err("start_height must be below maturity_height".to_string());
        }

        let sequence = self.counters.fee_coupon_forwards + 1;
        let forward_id = fee_coupon_forward_id(&request, sequence);
        let mut record = FeeCouponForwardRecord {
            forward_id: forward_id.clone(),
            tranche_id: request.tranche_id,
            pool_id: request.pool_id,
            forward_kind: request.forward_kind,
            payer_commitment: request.payer_commitment,
            receiver_commitment: request.receiver_commitment,
            notional_commitment_root: request.notional_commitment_root,
            strike_fee_micro_units: request.strike_fee_micro_units,
            max_user_fee_bps: request.max_user_fee_bps,
            start_height: request.start_height,
            maturity_height: request.maturity_height,
            status: CouponForwardStatus::Open,
            opened_height: self.config.devnet_height,
            sequence,
            forward_nonce_root: payload_root(
                "FEE-COUPON-FORWARD-NONCE",
                &json!(request.forward_nonce),
            ),
            public_root: String::new(),
        };
        record.public_root = root_from_record(FEE_COUPON_FORWARD_SCHEME, &record.public_record());
        self.fee_coupon_forwards.insert(forward_id, record.clone());
        self.counters.fee_coupon_forwards = sequence;
        self.remember_public_root(&record.forward_id, &record.public_root);
        Ok(record)
    }

    pub fn open_beneficiary_pool(
        &mut self,
        request: BeneficiaryPoolRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<BeneficiaryPoolRecord>
    {
        require_capacity(
            "beneficiary_pools",
            self.beneficiary_pools.len(),
            self.config.max_beneficiary_pools,
        )?;
        require_unique("sponsor_tranche_ids", &request.sponsor_tranche_ids)?;
        for tranche_id in &request.sponsor_tranche_ids {
            let tranche = self.require_tranche(tranche_id)?;
            if !tranche.status.usable() {
                return Err(format!("tranche {tranche_id} is not reservable"));
            }
        }
        require_root(
            "encrypted_beneficiary_root",
            &request.encrypted_beneficiary_root,
        )?;
        require_root(
            "encrypted_fee_obligation_root",
            &request.encrypted_fee_obligation_root,
        )?;
        require_root("batch_commitment_root", &request.batch_commitment_root)?;
        require_root(
            "membership_nullifier_root",
            &request.membership_nullifier_root,
        )?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size is below configured minimum".to_string());
        }
        if request.decoy_set_size < self.config.min_decoy_set_size {
            return Err("decoy_set_size is below configured minimum".to_string());
        }

        let sequence = self.counters.beneficiary_pools + 1;
        let pool_id = beneficiary_pool_id(&request, sequence);
        let mut record = BeneficiaryPoolRecord {
            pool_id: pool_id.clone(),
            pool_kind: request.pool_kind,
            sponsor_tranche_ids: request.sponsor_tranche_ids,
            encrypted_beneficiary_root: request.encrypted_beneficiary_root,
            encrypted_fee_obligation_root: request.encrypted_fee_obligation_root,
            batch_commitment_root: request.batch_commitment_root,
            membership_nullifier_root: request.membership_nullifier_root,
            privacy_set_size: request.privacy_set_size,
            decoy_set_size: request.decoy_set_size,
            status: BeneficiaryPoolStatus::Admitted,
            opened_height: self.config.devnet_height,
            sequence,
            pool_nonce_root: payload_root("BENEFICIARY-POOL-NONCE", &json!(request.pool_nonce)),
            public_root: String::new(),
        };
        record.public_root =
            root_from_record(ENCRYPTED_BENEFICIARY_POOL_SCHEME, &record.public_record());
        self.beneficiary_pools.insert(pool_id, record.clone());
        self.counters.beneficiary_pools = sequence;
        self.remember_public_root(&record.pool_id, &record.public_root);
        Ok(record)
    }

    pub fn submit_pq_sponsor_attestation(
        &mut self,
        request: PqSponsorAttestationRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<
        PqSponsorAttestationRecord,
    > {
        require_capacity(
            "pq_sponsor_attestations",
            self.pq_sponsor_attestations.len(),
            self.config.max_pq_attestations,
        )?;
        require_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        require_unique("tranche_ids", &request.tranche_ids)?;
        for tranche_id in &request.tranche_ids {
            self.require_tranche(tranche_id)?;
        }
        require_root("capacity_statement_root", &request.capacity_statement_root)?;
        require_root("pq_public_key_root", &request.pq_public_key_root)?;
        require_root("pq_signature_root", &request.pq_signature_root)?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("security_bits is below configured PQ minimum".to_string());
        }

        let sequence = self.counters.pq_sponsor_attestations + 1;
        let attestation_id = pq_sponsor_attestation_id(&request, sequence);
        let mut record = PqSponsorAttestationRecord {
            attestation_id: attestation_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            tranche_ids: request.tranche_ids,
            capacity_statement_root: request.capacity_statement_root,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            freshness_height: request.freshness_height,
            security_bits: request.security_bits,
            status: AttestationStatus::Usable,
            opened_height: self.config.devnet_height,
            sequence,
            attestation_nonce_root: payload_root(
                "PQ-SPONSOR-ATTESTATION-NONCE",
                &json!(request.attestation_nonce),
            ),
            public_root: String::new(),
        };
        record.public_root =
            root_from_record(PQ_SPONSOR_ATTESTATION_SCHEME, &record.public_record());
        self.pq_sponsor_attestations
            .insert(attestation_id, record.clone());
        self.counters.pq_sponsor_attestations = sequence;
        self.remember_public_root(&record.attestation_id, &record.public_root);
        Ok(record)
    }

    pub fn publish_settlement_netting(
        &mut self,
        request: SettlementNettingRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<SettlementNettingRecord>
    {
        require_capacity(
            "settlement_nettings",
            self.settlement_nettings.len(),
            self.config.max_settlement_nettings,
        )?;
        require_unique("pool_ids", &request.pool_ids)?;
        require_unique("forward_ids", &request.forward_ids)?;
        require_unique("tranche_ids", &request.tranche_ids)?;
        for pool_id in &request.pool_ids {
            let pool = self.require_pool(pool_id)?;
            if !pool.status.reservable() {
                return Err(format!("pool {pool_id} is not nettable"));
            }
        }
        for forward_id in &request.forward_ids {
            let forward = self.require_forward(forward_id)?;
            if !forward.status.nettable() {
                return Err(format!("forward {forward_id} is not nettable"));
            }
        }
        for tranche_id in &request.tranche_ids {
            self.require_tranche(tranche_id)?;
        }
        require_root(
            "gross_fee_commitment_root",
            &request.gross_fee_commitment_root,
        )?;
        require_root("net_fee_commitment_root", &request.net_fee_commitment_root)?;
        require_root("sponsor_payment_root", &request.sponsor_payment_root)?;
        require_root("beneficiary_rebate_root", &request.beneficiary_rebate_root)?;
        require_root("settlement_proof_root", &request.settlement_proof_root)?;

        let sequence = self.counters.settlement_nettings + 1;
        let netting_id = settlement_netting_id(&request, sequence);
        let mut record = SettlementNettingRecord {
            netting_id: netting_id.clone(),
            pool_ids: request.pool_ids,
            forward_ids: request.forward_ids,
            tranche_ids: request.tranche_ids,
            gross_fee_commitment_root: request.gross_fee_commitment_root,
            net_fee_commitment_root: request.net_fee_commitment_root,
            sponsor_payment_root: request.sponsor_payment_root,
            beneficiary_rebate_root: request.beneficiary_rebate_root,
            settlement_proof_root: request.settlement_proof_root,
            status: NettingStatus::Balanced,
            opened_height: self.config.devnet_height,
            sequence,
            netting_nonce_root: payload_root(
                "SETTLEMENT-NETTING-NONCE",
                &json!(request.netting_nonce),
            ),
            public_root: String::new(),
        };
        record.public_root = root_from_record(SETTLEMENT_NETTING_SCHEME, &record.public_record());
        self.settlement_nettings.insert(netting_id, record.clone());
        self.counters.settlement_nettings = sequence;
        self.remember_public_root(&record.netting_id, &record.public_root);
        Ok(record)
    }

    pub fn register_risk_limit(
        &mut self,
        request: RiskLimitRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<RiskLimitRecord> {
        require_capacity(
            "risk_limits",
            self.risk_limits.len(),
            self.config.max_risk_limits,
        )?;
        require_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        require_non_empty("subject_id", &request.subject_id)?;
        require_root("limit_commitment_root", &request.limit_commitment_root)?;
        require_root(
            "utilization_commitment_root",
            &request.utilization_commitment_root,
        )?;
        require_bps("warning_bps", request.warning_bps)?;
        require_bps("breach_bps", request.breach_bps)?;
        if request.warning_bps >= request.breach_bps {
            return Err("warning_bps must be below breach_bps".to_string());
        }

        let sequence = self.counters.risk_limits + 1;
        let risk_limit_id = risk_limit_id(&request, sequence);
        let mut record = RiskLimitRecord {
            risk_limit_id: risk_limit_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            limit_kind: request.limit_kind,
            subject_id: request.subject_id,
            limit_commitment_root: request.limit_commitment_root,
            utilization_commitment_root: request.utilization_commitment_root,
            warning_bps: request.warning_bps,
            breach_bps: request.breach_bps,
            status: RiskLimitStatus::Active,
            opened_height: self.config.devnet_height,
            sequence,
            limit_nonce_root: payload_root("RISK-LIMIT-NONCE", &json!(request.limit_nonce)),
            public_root: String::new(),
        };
        record.public_root = root_from_record(RISK_LIMIT_SCHEME, &record.public_record());
        self.risk_limits.insert(risk_limit_id, record.clone());
        self.counters.risk_limits = sequence;
        self.remember_public_root(&record.risk_limit_id, &record.public_root);
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: RebateRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<RebateRecord> {
        require_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        self.require_netting(&request.netting_id)?;
        self.require_pool(&request.pool_id)?;
        self.require_tranche(&request.tranche_id)?;
        if let Some(forward_id) = &request.coupon_forward_id {
            self.require_forward(forward_id)?;
        }
        require_root("rebate_commitment_root", &request.rebate_commitment_root)?;
        require_root("beneficiary_claim_root", &request.beneficiary_claim_root)?;
        require_bps("rebate_bps", request.rebate_bps)?;

        let sequence = self.counters.rebates + 1;
        let rebate_id = rebate_id(&request, sequence);
        let mut record = RebateRecord {
            rebate_id: rebate_id.clone(),
            netting_id: request.netting_id,
            pool_id: request.pool_id,
            tranche_id: request.tranche_id,
            rebate_commitment_root: request.rebate_commitment_root,
            beneficiary_claim_root: request.beneficiary_claim_root,
            coupon_forward_id: request.coupon_forward_id,
            rebate_bps: request.rebate_bps,
            status: RebateStatus::Published,
            opened_height: self.config.devnet_height,
            sequence,
            rebate_nonce_root: payload_root("REBATE-NONCE", &json!(request.rebate_nonce)),
            public_root: String::new(),
        };
        record.public_root = root_from_record(REBATE_SCHEME, &record.public_record());
        self.rebates.insert(rebate_id, record.clone());
        self.counters.rebates = sequence;
        self.remember_public_root(&record.rebate_id, &record.public_root);
        Ok(record)
    }

    pub fn open_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<RedactionBudgetRecord>
    {
        require_capacity(
            "redaction_budgets",
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        require_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        require_non_empty("subject_id", &request.subject_id)?;
        require_root("budget_commitment_root", &request.budget_commitment_root)?;
        require_root(
            "redaction_nullifier_root",
            &request.redaction_nullifier_root,
        )?;
        if request.quota == 0 {
            return Err("quota must be positive".to_string());
        }

        let sequence = self.counters.redaction_budgets + 1;
        let budget_id = redaction_budget_id(&request, sequence);
        let mut record = RedactionBudgetRecord {
            budget_id: budget_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            subject_id: request.subject_id,
            budget_commitment_root: request.budget_commitment_root,
            redaction_nullifier_root: request.redaction_nullifier_root,
            quota: request.quota,
            spent: 0,
            expires_height: request.expires_height,
            status: RedactionBudgetStatus::Open,
            opened_height: self.config.devnet_height,
            sequence,
            budget_nonce_root: payload_root("REDACTION-BUDGET-NONCE", &json!(request.budget_nonce)),
            public_root: String::new(),
        };
        record.public_root = root_from_record(REDACTION_BUDGET_SCHEME, &record.public_record());
        self.redaction_budgets.insert(budget_id, record.clone());
        self.counters.redaction_budgets = sequence;
        self.remember_public_root(&record.budget_id, &record.public_root);
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let sponsor_tranches = values(&self.sponsor_tranches);
        let fee_coupon_forwards = values(&self.fee_coupon_forwards);
        let beneficiary_pools = values(&self.beneficiary_pools);
        let pq_sponsor_attestations = values(&self.pq_sponsor_attestations);
        let settlement_nettings = values(&self.settlement_nettings);
        let risk_limits = values(&self.risk_limits);
        let rebates = values(&self.rebates);
        let redaction_budgets = values(&self.redaction_budgets);
        let public_roots = self
            .public_record_roots
            .iter()
            .map(|(id, root)| json!({"id": id, "root": root}))
            .collect::<Vec<_>>();
        let mut roots = Roots {
            sponsor_tranches_root: public_record_root("SPONSOR-TRANCHES", &sponsor_tranches),
            fee_coupon_forwards_root: public_record_root(
                "FEE-COUPON-FORWARDS",
                &fee_coupon_forwards,
            ),
            beneficiary_pools_root: public_record_root("BENEFICIARY-POOLS", &beneficiary_pools),
            pq_sponsor_attestations_root: public_record_root(
                "PQ-SPONSOR-ATTESTATIONS",
                &pq_sponsor_attestations,
            ),
            settlement_nettings_root: public_record_root(
                "SETTLEMENT-NETTINGS",
                &settlement_nettings,
            ),
            risk_limits_root: public_record_root("RISK-LIMITS", &risk_limits),
            rebates_root: public_record_root("REBATES", &rebates),
            redaction_budgets_root: public_record_root("REDACTION-BUDGETS", &redaction_budgets),
            counters_root: root_from_record("COUNTERS", &self.counters.public_record()),
            config_root: root_from_record("CONFIG", &self.config.public_record()),
            public_records_root: public_record_root("PUBLIC-RECORD-ROOTS", &public_roots),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "sponsor_tranches_root": roots.sponsor_tranches_root,
            "fee_coupon_forwards_root": roots.fee_coupon_forwards_root,
            "beneficiary_pools_root": roots.beneficiary_pools_root,
            "pq_sponsor_attestations_root": roots.pq_sponsor_attestations_root,
            "settlement_nettings_root": roots.settlement_nettings_root,
            "risk_limits_root": roots.risk_limits_root,
            "rebates_root": roots.rebates_root,
            "redaction_budgets_root": roots.redaction_budgets_root,
            "counters_root": roots.counters_root,
            "config_root": roots.config_root,
            "public_records_root": roots.public_records_root
        }));
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "sponsor_tranches": values(&self.sponsor_tranches),
            "fee_coupon_forwards": values(&self.fee_coupon_forwards),
            "beneficiary_pools": values(&self.beneficiary_pools),
            "pq_sponsor_attestations": values(&self.pq_sponsor_attestations),
            "settlement_nettings": values(&self.settlement_nettings),
            "risk_limits": values(&self.risk_limits),
            "rebates": values(&self.rebates),
            "redaction_budgets": values(&self.redaction_budgets),
            "state_root": roots.state_root
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn remember_public_root(&mut self, id: &str, root: &str) {
        self.public_record_roots
            .insert(id.to_string(), root.to_string());
        self.counters.public_records = self.public_record_roots.len() as u64;
    }

    fn require_tranche(
        &self,
        id: &str,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<&SponsorTrancheRecord>
    {
        self.sponsor_tranches
            .get(id)
            .ok_or_else(|| format!("unknown sponsor tranche {id}"))
    }

    fn require_forward(
        &self,
        id: &str,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<&FeeCouponForwardRecord>
    {
        self.fee_coupon_forwards
            .get(id)
            .ok_or_else(|| format!("unknown fee coupon forward {id}"))
    }

    fn require_pool(
        &self,
        id: &str,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<&BeneficiaryPoolRecord>
    {
        self.beneficiary_pools
            .get(id)
            .ok_or_else(|| format!("unknown beneficiary pool {id}"))
    }

    fn require_attestation(
        &self,
        id: &str,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<
        &PqSponsorAttestationRecord,
    > {
        self.pq_sponsor_attestations
            .get(id)
            .ok_or_else(|| format!("unknown PQ sponsor attestation {id}"))
    }

    fn require_netting(
        &self,
        id: &str,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<
        &SettlementNettingRecord,
    > {
        self.settlement_nettings
            .get(id)
            .ok_or_else(|| format!("unknown settlement netting {id}"))
    }

    fn require_risk_limit(
        &self,
        id: &str,
    ) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<&RiskLimitRecord>
    {
        self.risk_limits
            .get(id)
            .ok_or_else(|| format!("unknown risk limit {id}"))
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

pub fn sponsor_tranche_id(request: &SponsorTrancheRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-SPONSOR-TRANCHE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(request.tranche_kind.as_str()),
            HashPart::Str(&request.capacity_commitment_root),
            HashPart::Str(&request.reserve_commitment_root),
            HashPart::Int(request.attachment_bps as i128),
            HashPart::Int(request.detachment_bps as i128),
            HashPart::Str(&request.tranche_nonce),
        ],
        32,
    )
}

pub fn fee_coupon_forward_id(request: &FeeCouponForwardRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-COUPON-FORWARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.tranche_id),
            HashPart::Str(request.pool_id.as_deref().unwrap_or("")),
            HashPart::Str(request.forward_kind.as_str()),
            HashPart::Str(&request.payer_commitment),
            HashPart::Str(&request.receiver_commitment),
            HashPart::Str(&request.notional_commitment_root),
            HashPart::Int(request.strike_fee_micro_units as i128),
            HashPart::Str(&request.forward_nonce),
        ],
        32,
    )
}

pub fn beneficiary_pool_id(request: &BeneficiaryPoolRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-BENEFICIARY-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.pool_kind.as_str()),
            HashPart::Str(&id_list_root("POOL-TRANCHES", &request.sponsor_tranche_ids)),
            HashPart::Str(&request.encrypted_beneficiary_root),
            HashPart::Str(&request.batch_commitment_root),
            HashPart::Str(&request.membership_nullifier_root),
            HashPart::Str(&request.pool_nonce),
        ],
        32,
    )
}

pub fn pq_sponsor_attestation_id(request: &PqSponsorAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-SPONSOR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&id_list_root("ATTESTATION-TRANCHES", &request.tranche_ids)),
            HashPart::Str(&request.capacity_statement_root),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Int(request.security_bits as i128),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn settlement_netting_id(request: &SettlementNettingRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-SETTLEMENT-NETTING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("NETTING-POOLS", &request.pool_ids)),
            HashPart::Str(&id_list_root("NETTING-FORWARDS", &request.forward_ids)),
            HashPart::Str(&id_list_root("NETTING-TRANCHES", &request.tranche_ids)),
            HashPart::Str(&request.gross_fee_commitment_root),
            HashPart::Str(&request.net_fee_commitment_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.netting_nonce),
        ],
        32,
    )
}

pub fn risk_limit_id(request: &RiskLimitRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-RISK-LIMIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(request.limit_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.limit_commitment_root),
            HashPart::Str(&request.utilization_commitment_root),
            HashPart::Str(&request.limit_nonce),
        ],
        32,
    )
}

pub fn rebate_id(request: &RebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.netting_id),
            HashPart::Str(&request.pool_id),
            HashPart::Str(&request.tranche_id),
            HashPart::Str(request.coupon_forward_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Str(&request.beneficiary_claim_root),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

pub fn redaction_budget_id(request: &RedactionBudgetRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.budget_commitment_root),
            HashPart::Str(&request.redaction_nullifier_root),
            HashPart::Int(request.quota as i128),
            HashPart::Str(&request.budget_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-SPONSOR-DERIVATIVES-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-SPONSOR-DERIVATIVES-{domain}"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

fn values<T>(map: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    map.values().map(PublicRecord::to_public_record).collect()
}

trait PublicRecord {
    fn to_public_record(&self) -> Value;
}

impl PublicRecord for SponsorTrancheRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for FeeCouponForwardRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for BeneficiaryPoolRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PqSponsorAttestationRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for SettlementNettingRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for RiskLimitRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for RebateRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for RedactionBudgetRecord {
    fn to_public_record(&self) -> Value {
        self.public_record()
    }
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(domain, &ids.iter().map(|id| json!(id)).collect::<Vec<_>>())
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_root(
    field: &str,
    value: &str,
) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_bps(
    field: &str,
    value: u64,
) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_capacity(
    field: &str,
    current: usize,
    maximum: usize,
) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<()> {
    if current >= maximum {
        Err(format!("{field} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2LowFeePqConfidentialBatchFeeSponsorDerivativesRuntimeResult<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}

fn demo_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-SPONSOR-DERIVATIVES-DEMO-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BATCH-FEE-SPONSOR-DERIVATIVES-COMMITMENT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}
