use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedProverFailureInsuranceOptionsRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_OPTIONS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-prover-failure-insurance-options-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_OPTIONS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-prover-failure-claim-coupon-v1";
pub const SEALED_TRANCHE_SUITE: &str = "sealed-confidential-prover-failure-option-tranche-root-v1";
pub const PQ_COUPON_ROOT_SUITE: &str = "pq-claim-coupon-nullifier-root-v1";
pub const PREMIUM_CURVE_ROOT_SUITE: &str = "private-premium-curve-commitment-root-v1";
pub const PROVER_FAILURE_SETTLEMENT_SUITE: &str = "prover-failure-payout-settlement-root-v1";
pub const PROVER_FAILURE_OBSERVATION_SUITE: &str = "private-prover-failure-observation-root-v1";
pub const COLLATERAL_ROOT_SUITE: &str = "confidential-prover-failure-collateral-root-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-exercise-batch-root-v1";
pub const ANTI_REPLAY_NULLIFIER_SUITE: &str = "anti-replay-prover-failure-nullifier-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-prover-failure-insurance-options-public-record-v1";
pub const STATE_ROOT_SUITE: &str = "prover-failure-insurance-options-state-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-prover-failure-insurance-options-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-prover-failure-insurance-options-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_260_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_940_000;
pub const DEVNET_INSURED_ASSET_ID: &str = "pxmr-private-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_PREMIUM_ASSET_ID: &str = "nebula-premium-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 3;
pub const DEFAULT_LP_FEE_BPS: u64 = 4;
pub const DEFAULT_TARGET_BATCH_FEE_BPS: u64 = 6;
pub const DEFAULT_PREMIUM_REBATE_BPS: u64 = 4_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_SETTLEMENT_QUORUM: u16 = 3;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_500;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_800;
pub const DEFAULT_MIN_FAILURE_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_FAILURE_BLOCKS: u64 = 2_880;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 4096;
pub const DEFAULT_MAX_TRANCHES: usize = 8192;
pub const DEFAULT_MAX_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 1_048_576;
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    FailurePut,
    FailureCall,
    BinaryFailure,
    WitnessJumpRebate,
    LiquidityBackstop,
    CatastrophicFailure,
}
impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailurePut => "failure_put",
            Self::FailureCall => "failure_call",
            Self::BinaryFailure => "binary_failure",
            Self::WitnessJumpRebate => "witness_jump_rebate",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::CatastrophicFailure => "catastrophic_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseStyle {
    European,
    American,
    Bermudan,
    OracleTriggered,
}
impl ExerciseStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::European => "european",
            Self::American => "american",
            Self::Bermudan => "bermudan",
            Self::OracleTriggered => "oracle_triggered",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheStatus {
    Draft,
    Sealed,
    Open,
    Paused,
    Expired,
    Settling,
    Settled,
    Retired,
    Quarantined,
}
impl TrancheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Retired => "retired",
            Self::Quarantined => "quarantined",
        }
    }
    pub fn accepts_exercises(self) -> bool {
        matches!(self, Self::Open | Self::Settling)
    }
    pub fn accepts_premiums(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Draft,
    PqSigned,
    Admitted,
    Batched,
    Settled,
    Redeemed,
    Expired,
    Disputed,
    Rejected,
}
impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PqSigned => "pq_signed",
            Self::Admitted => "admitted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Redeemed => "redeemed",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }
    pub fn is_live(self) -> bool {
        matches!(self, Self::PqSigned | Self::Admitted | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    OracleAttested,
    CollateralLocked,
    Paying,
    Settled,
    PartiallySettled,
    Rejected,
    Quarantined,
}
impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::OracleAttested => "oracle_attested",
            Self::CollateralLocked => "collateral_locked",
            Self::Paying => "paying",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Collecting,
    Frozen,
    Submitted,
    Settled,
    PartiallySettled,
    Quarantined,
}
impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Collecting => "collecting",
            Self::Frozen => "frozen",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Quarantined => "quarantined",
        }
    }
    pub fn accepts_items(self) -> bool {
        matches!(self, Self::Open | Self::Collecting)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PremiumCurveKind {
    Flat,
    LinearFailure,
    SigmoidCongestion,
    UtilizationKink,
    OracleVolatility,
    PrivateDutch,
}
impl PremiumCurveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flat => "flat",
            Self::LinearFailure => "linear_failure",
            Self::SigmoidCongestion => "sigmoid_congestion",
            Self::UtilizationKink => "utilization_kink",
            Self::OracleVolatility => "oracle_volatility",
            Self::PrivateDutch => "private_dutch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralStatus {
    Warm,
    Active,
    Stressed,
    Paused,
    Draining,
    Settled,
}
impl CollateralStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Active => "active",
            Self::Stressed => "stressed",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayScope {
    Tranche,
    Observation,
    Coupon,
    Exercise,
    Settlement,
    Batch,
    Collateral,
}
impl ReplayScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tranche => "tranche",
            Self::Observation => "observation",
            Self::Coupon => "coupon",
            Self::Exercise => "exercise",
            Self::Settlement => "settlement",
            Self::Batch => "batch",
            Self::Collateral => "collateral",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Reject,
    NeedsReview,
}
impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::NeedsReview => "needs_review",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyGrade {
    Bronze,
    Silver,
    Gold,
    Platinum,
    Blackout,
}
impl PrivacyGrade {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bronze => "bronze",
            Self::Silver => "silver",
            Self::Gold => "gold",
            Self::Platinum => "platinum",
            Self::Blackout => "blackout",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_claim_coupon_suite: String,
    pub market_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub insured_asset_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub settlement_quorum: u16,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub target_batch_fee_bps: u64,
    pub premium_rebate_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub max_payout_bps: u64,
    pub min_failure_blocks: u64,
    pub max_failure_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_batch_items: usize,
    pub max_tranches: usize,
    pub max_coupons: usize,
    pub max_settlements: usize,
    pub require_roots_only_public_records: bool,
    pub require_pq_coupons: bool,
    pub allow_low_fee_batching: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_coupon_suite: PQ_CLAIM_COUPON_SUITE.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            insured_asset_id: DEVNET_INSURED_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            settlement_quorum: DEFAULT_SETTLEMENT_QUORUM,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            lp_fee_bps: DEFAULT_LP_FEE_BPS,
            target_batch_fee_bps: DEFAULT_TARGET_BATCH_FEE_BPS,
            premium_rebate_bps: DEFAULT_PREMIUM_REBATE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            min_failure_blocks: DEFAULT_MIN_FAILURE_BLOCKS,
            max_failure_blocks: DEFAULT_MAX_FAILURE_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_tranches: DEFAULT_MAX_TRANCHES,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            require_roots_only_public_records: true,
            require_pq_coupons: true,
            allow_low_fee_batching: true,
        }
    }
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn validate(&self) -> Result<()> {
        ensure_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        ensure_bps("lp_fee_bps", self.lp_fee_bps)?;
        ensure_bps("target_batch_fee_bps", self.target_batch_fee_bps)?;
        ensure_bps("premium_rebate_bps", self.premium_rebate_bps)?;
        ensure_bps(
            "min_collateral_coverage_bps",
            self.min_collateral_coverage_bps,
        )?;
        ensure_bps("max_payout_bps", self.max_payout_bps)?;
        if self.min_failure_blocks > self.max_failure_blocks {
            return Err("min_failure_blocks exceeds max_failure_blocks".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security bits below policy floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub tranches: u64,
    pub observations: u64,
    pub premium_curves: u64,
    pub coupons: u64,
    pub settlements: u64,
    pub batches: u64,
    pub collateral_roots: u64,
    pub nullifiers: u64,
    pub public_records: u64,
    pub rejected: u64,
    pub quarantined: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub tranche_root: String,
    pub observation_root: String,
    pub premium_curve_root: String,
    pub coupon_root: String,
    pub settlement_root: String,
    pub collateral_root: String,
    pub batch_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedOptionTranche {
    pub tranche_id: String,
    pub series_commitment: String,
    pub option_kind: OptionKind,
    pub exercise_style: ExerciseStyle,
    pub status: TrancheStatus,
    pub notional_commitment: String,
    pub strike_failure_blocks: u64,
    pub max_failure_blocks: u64,
    pub maturity_l2_height: u64,
    pub collateral_root: String,
    pub premium_curve_root: String,
    pub holder_root: String,
    pub terms_root: String,
    pub privacy_grade: PrivacyGrade,
    pub pq_security_bits: u16,
    pub created_l2_height: u64,
    pub updated_l2_height: u64,
}

impl SealedOptionTranche {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("SealedOptionTranche", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PremiumCurveCommitment {
    pub curve_id: String,
    pub tranche_id: String,
    pub curve_kind: PremiumCurveKind,
    pub sealed_coefficients_root: String,
    pub utilization_bucket_root: String,
    pub failure_bucket_root: String,
    pub premium_asset_id: String,
    pub min_premium_commitment: String,
    pub max_premium_commitment: String,
    pub rebate_bps: u64,
    pub oracle_volatility_root: String,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}

impl PremiumCurveCommitment {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("PremiumCurveCommitment", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimCoupon {
    pub coupon_id: String,
    pub tranche_id: String,
    pub claim_nullifier: String,
    pub coupon_commitment: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub failure_evidence_root: String,
    pub premium_paid_commitment: String,
    pub max_payout_commitment: String,
    pub status: CouponStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub issued_l2_height: u64,
    pub expires_l2_height: u64,
}

impl PqClaimCoupon {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("PqClaimCoupon", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverFailureObservation {
    pub observation_id: String,
    pub tranche_id: String,
    pub observation_nullifier: String,
    pub prover_set_root: String,
    pub circuit_root: String,
    pub failed_proof_root: String,
    pub fallback_proof_root: String,
    pub latency_bucket_root: String,
    pub failure_blocks: u64,
    pub attestation_root: String,
    pub observer_quorum: u16,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub observed_l2_height: u64,
    pub monero_anchor_height: u64,
}

impl ProverFailureObservation {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("ProverFailureObservation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProverFailurePayoutSettlement {
    pub settlement_id: String,
    pub coupon_id: String,
    pub batch_id: String,
    pub settlement_nullifier: String,
    pub proof_witness_root: String,
    pub failure_attestation_root: String,
    pub payout_commitment: String,
    pub fee_commitment: String,
    pub collateral_release_root: String,
    pub status: SettlementStatus,
    pub attestation_count: u16,
    pub settle_after_l2_height: u64,
    pub created_l2_height: u64,
    pub settled_l2_height: Option<u64>,
}

impl ProverFailurePayoutSettlement {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("ProverFailurePayoutSettlement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralSnapshot {
    pub collateral_root_id: String,
    pub vault_commitment: String,
    pub asset_id: String,
    pub collateral_root: String,
    pub liability_root: String,
    pub coverage_bps: u64,
    pub status: CollateralStatus,
    pub l2_height: u64,
    pub monero_height: u64,
}

impl CollateralSnapshot {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("CollateralSnapshot", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeExerciseBatch {
    pub batch_id: String,
    pub batch_nullifier: String,
    pub coupon_root: String,
    pub settlement_root: String,
    pub fee_pool_commitment: String,
    pub rebate_root: String,
    pub status: BatchStatus,
    pub item_count: usize,
    pub target_fee_bps: u64,
    pub opened_l2_height: u64,
    pub closes_l2_height: u64,
}

impl LowFeeExerciseBatch {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("LowFeeExerciseBatch", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AntiReplayNullifier {
    pub nullifier: String,
    pub scope: ReplayScope,
    pub subject_id: String,
    pub root: String,
    pub l2_height: u64,
}

impl AntiReplayNullifier {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("AntiReplayNullifier", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivatePremiumQuoteInput {
    pub tranche_id: String,
    pub quote_commitment: String,
    pub failure_bucket_root: String,
    pub utilization_root: String,
    pub premium_limit_commitment: String,
    pub privacy_set_size: u64,
}

impl PrivatePremiumQuoteInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("PrivatePremiumQuoteInput", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealTrancheInput {
    pub series_commitment: String,
    pub option_kind: OptionKind,
    pub exercise_style: ExerciseStyle,
    pub notional_commitment: String,
    pub strike_failure_blocks: u64,
    pub max_failure_blocks: u64,
    pub maturity_l2_height: u64,
    pub collateral_root: String,
    pub premium_curve_root: String,
    pub holder_root: String,
    pub terms_root: String,
    pub privacy_grade: PrivacyGrade,
    pub pq_security_bits: u16,
}

impl SealTrancheInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("SealTrancheInput", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmitCouponInput {
    pub tranche_id: String,
    pub claim_nullifier: String,
    pub coupon_commitment: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub failure_evidence_root: String,
    pub premium_paid_commitment: String,
    pub max_payout_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl AdmitCouponInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("AdmitCouponInput", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObserveProverFailureInput {
    pub tranche_id: String,
    pub observation_nullifier: String,
    pub prover_set_root: String,
    pub circuit_root: String,
    pub failed_proof_root: String,
    pub fallback_proof_root: String,
    pub latency_bucket_root: String,
    pub failure_blocks: u64,
    pub attestation_root: String,
    pub observer_quorum: u16,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub monero_anchor_height: u64,
}

impl ObserveProverFailureInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("ObserveProverFailureInput", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementInput {
    pub coupon_id: String,
    pub batch_id: String,
    pub settlement_nullifier: String,
    pub proof_witness_root: String,
    pub failure_attestation_root: String,
    pub payout_commitment: String,
    pub fee_commitment: String,
    pub collateral_release_root: String,
    pub attestation_count: u16,
    pub settle_after_l2_height: u64,
}

impl SettlementInput {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
    pub fn commitment_root(&self) -> String {
        root_from_record("SettlementInput", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub tranches: BTreeMap<String, SealedOptionTranche>,
    pub observations: BTreeMap<String, ProverFailureObservation>,
    pub premium_curves: BTreeMap<String, PremiumCurveCommitment>,
    pub coupons: BTreeMap<String, PqClaimCoupon>,
    pub settlements: BTreeMap<String, ProverFailurePayoutSettlement>,
    pub collateral_snapshots: BTreeMap<String, CollateralSnapshot>,
    pub batches: BTreeMap<String, LowFeeExerciseBatch>,
    pub nullifiers: BTreeMap<String, AntiReplayNullifier>,
    pub spent_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            tranches: BTreeMap::new(),
            observations: BTreeMap::new(),
            premium_curves: BTreeMap::new(),
            coupons: BTreeMap::new(),
            settlements: BTreeMap::new(),
            collateral_snapshots: BTreeMap::new(),
            batches: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet config");
        let collateral = CollateralSnapshot {
            collateral_root_id: "devnet-collateral-root".to_string(),
            vault_commitment: "vault:prover-failure-insurance:devnet".to_string(),
            asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            collateral_root: root_from_parts(
                "devnet-collateral",
                &["seed", DEVNET_COLLATERAL_ASSET_ID],
            ),
            liability_root: root_from_parts("devnet-liability", &["seed", DEVNET_INSURED_ASSET_ID]),
            coverage_bps: 12_750,
            status: CollateralStatus::Active,
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
        };
        state
            .record_collateral_snapshot(collateral)
            .expect("devnet collateral");
        let curve = PremiumCurveCommitment {
            curve_id: "devnet-premium-curve".to_string(),
            tranche_id: "devnet-failure-put-tranche".to_string(),
            curve_kind: PremiumCurveKind::UtilizationKink,
            sealed_coefficients_root: root_from_parts("devnet-curve-coefficients", &["sealed"]),
            utilization_bucket_root: root_from_parts(
                "devnet-utilization",
                &["low", "medium", "high"],
            ),
            failure_bucket_root: root_from_parts("devnet-failure", &["12", "144", "720"]),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            min_premium_commitment: commitment("min-premium", 1),
            max_premium_commitment: commitment("max-premium", 9),
            rebate_bps: DEFAULT_PREMIUM_REBATE_BPS,
            oracle_volatility_root: root_from_parts("devnet-volatility", &["oracle"]),
            created_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: DEVNET_L2_HEIGHT + 86_400,
        };
        state.commit_premium_curve(curve).expect("devnet curve");
        let tranche = SealTrancheInput {
            series_commitment: "series:prover-failure:devnet".to_string(),
            option_kind: OptionKind::FailurePut,
            exercise_style: ExerciseStyle::Bermudan,
            notional_commitment: commitment("notional", 100),
            strike_failure_blocks: 144,
            max_failure_blocks: 720,
            maturity_l2_height: DEVNET_L2_HEIGHT + 43_200,
            collateral_root: state.roots.collateral_root.clone(),
            premium_curve_root: state.roots.premium_curve_root.clone(),
            holder_root: root_from_parts("devnet-holders", &["sealed"]),
            terms_root: root_from_parts("devnet-terms", &["failure-put"]),
            privacy_grade: PrivacyGrade::Gold,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        };
        state.seal_option_tranche(tranche).expect("devnet tranche");
        let devnet_tranche_id = state.tranches.keys().next().cloned().unwrap();
        state
            .open_tranche(&devnet_tranche_id)
            .expect("open devnet tranche");
        state
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }
    pub fn roots(&self) -> Roots {
        self.compute_roots()
    }
    pub fn state_root(&self) -> String {
        self.compute_roots().state_root
    }
    pub fn public_record(&self) -> Value {
        json!({ "chain_id": self.config.chain_id, "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "roots_only": true, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.compute_roots().public_record() })
    }

    pub fn seal_option_tranche(&mut self, input: SealTrancheInput) -> Result<SealedOptionTranche> {
        self.validate_tranche_input(&input)?;
        let id = deterministic_id(
            "sealed_tranche",
            &input.public_record(),
            self.counters.tranches + 1,
        );
        self.ensure_replay(&id, ReplayScope::Tranche, &id)?;
        let record = SealedOptionTranche {
            tranche_id: id.clone(),
            series_commitment: input.series_commitment,
            option_kind: input.option_kind,
            exercise_style: input.exercise_style,
            status: TrancheStatus::Sealed,
            notional_commitment: input.notional_commitment,
            strike_failure_blocks: input.strike_failure_blocks,
            max_failure_blocks: input.max_failure_blocks,
            maturity_l2_height: input.maturity_l2_height,
            collateral_root: input.collateral_root,
            premium_curve_root: input.premium_curve_root,
            holder_root: input.holder_root,
            terms_root: input.terms_root,
            privacy_grade: input.privacy_grade,
            pq_security_bits: input.pq_security_bits,
            created_l2_height: self.config.l2_height,
            updated_l2_height: self.config.l2_height,
        };
        self.insert_public_record(
            format!("tranche:{id}"),
            roots_only_record("tranche", &record.tranche_id, &record.commitment_root()),
        )?;
        self.tranches.insert(id.clone(), record.clone());
        self.counters.tranches += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_tranche(&mut self, tranche_id: &str) -> Result<()> {
        let record = self
            .tranches
            .get_mut(tranche_id)
            .ok_or_else(|| format!("unknown tranche {tranche_id}"))?;
        if record.status != TrancheStatus::Sealed && record.status != TrancheStatus::Paused {
            return Err("tranche is not openable".to_string());
        }
        record.status = TrancheStatus::Open;
        record.updated_l2_height = self.config.l2_height;
        self.refresh_roots();
        Ok(())
    }

    pub fn pause_tranche(&mut self, tranche_id: &str) -> Result<()> {
        let record = self
            .tranches
            .get_mut(tranche_id)
            .ok_or_else(|| format!("unknown tranche {tranche_id}"))?;
        record.status = TrancheStatus::Paused;
        record.updated_l2_height = self.config.l2_height;
        self.refresh_roots();
        Ok(())
    }

    pub fn commit_premium_curve(
        &mut self,
        curve: PremiumCurveCommitment,
    ) -> Result<PremiumCurveCommitment> {
        ensure_bps("rebate_bps", curve.rebate_bps)?;
        if curve.expires_l2_height <= curve.created_l2_height {
            return Err("premium curve expiry must be after creation".to_string());
        }
        self.insert_public_record(
            format!("premium_curve:{}", curve.curve_id),
            roots_only_record("premium_curve", &curve.curve_id, &curve.commitment_root()),
        )?;
        self.premium_curves
            .insert(curve.curve_id.clone(), curve.clone());
        self.counters.premium_curves += 1;
        self.refresh_roots();
        Ok(curve)
    }

    pub fn quote_private_premium(&self, input: PrivatePremiumQuoteInput) -> Result<Value> {
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("premium quote privacy set too small".to_string());
        }
        let tranche = self
            .tranches
            .get(&input.tranche_id)
            .ok_or_else(|| format!("unknown tranche {}", input.tranche_id))?;
        if !tranche.status.accepts_premiums() {
            return Err("tranche does not accept premiums".to_string());
        }
        let root = root_from_record("PRIVATE_PREMIUM_QUOTE", &input.public_record());
        Ok(
            json!({ "tranche_id": input.tranche_id, "quote_root": root, "premium_curve_root": tranche.premium_curve_root, "roots_only": true }),
        )
    }

    pub fn observe_prover_failure(
        &mut self,
        input: ObserveProverFailureInput,
    ) -> Result<ProverFailureObservation> {
        self.validate_observation_input(&input)?;
        self.ensure_replay(
            &input.observation_nullifier,
            ReplayScope::Observation,
            &input.tranche_id,
        )?;
        let id = deterministic_id(
            "prover_failure_observation",
            &input.public_record(),
            self.counters.observations + 1,
        );
        let record = ProverFailureObservation {
            observation_id: id.clone(),
            tranche_id: input.tranche_id,
            observation_nullifier: input.observation_nullifier,
            prover_set_root: input.prover_set_root,
            circuit_root: input.circuit_root,
            failed_proof_root: input.failed_proof_root,
            fallback_proof_root: input.fallback_proof_root,
            latency_bucket_root: input.latency_bucket_root,
            failure_blocks: input.failure_blocks,
            attestation_root: input.attestation_root,
            observer_quorum: input.observer_quorum,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            observed_l2_height: self.config.l2_height,
            monero_anchor_height: input.monero_anchor_height,
        };
        self.insert_public_record(
            format!("observation:{id}"),
            roots_only_record(
                "observation",
                &record.observation_id,
                &record.commitment_root(),
            ),
        )?;
        self.observations.insert(id.clone(), record.clone());
        self.counters.observations += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn admit_pq_claim_coupon(&mut self, input: AdmitCouponInput) -> Result<PqClaimCoupon> {
        self.validate_coupon_input(&input)?;
        self.ensure_replay(
            &input.claim_nullifier,
            ReplayScope::Coupon,
            &input.tranche_id,
        )?;
        let id = deterministic_id(
            "pq_claim_coupon",
            &input.public_record(),
            self.counters.coupons + 1,
        );
        let record = PqClaimCoupon {
            coupon_id: id.clone(),
            tranche_id: input.tranche_id,
            claim_nullifier: input.claim_nullifier,
            coupon_commitment: input.coupon_commitment,
            pq_public_key_root: input.pq_public_key_root,
            pq_signature_root: input.pq_signature_root,
            failure_evidence_root: input.failure_evidence_root,
            premium_paid_commitment: input.premium_paid_commitment,
            max_payout_commitment: input.max_payout_commitment,
            status: CouponStatus::Admitted,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            issued_l2_height: self.config.l2_height,
            expires_l2_height: self.config.l2_height + self.config.coupon_ttl_blocks,
        };
        self.insert_public_record(
            format!("coupon:{id}"),
            roots_only_record("coupon", &record.coupon_id, &record.commitment_root()),
        )?;
        self.coupons.insert(id.clone(), record.clone());
        self.counters.coupons += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_low_fee_batch(
        &mut self,
        fee_pool_commitment: String,
        rebate_root: String,
    ) -> Result<LowFeeExerciseBatch> {
        if !self.config.allow_low_fee_batching {
            return Err("low fee batching disabled".to_string());
        }
        let seed = json!({"fee_pool_commitment": fee_pool_commitment, "rebate_root": rebate_root, "height": self.config.l2_height});
        let id = deterministic_id("low_fee_exercise_batch", &seed, self.counters.batches + 1);
        self.ensure_replay(&id, ReplayScope::Batch, &id)?;
        let record = LowFeeExerciseBatch {
            batch_id: id.clone(),
            batch_nullifier: root_from_parts("batch-nullifier", &[&id, &self.config.replay_domain]),
            coupon_root: merkle_root(LOW_FEE_BATCH_SUITE, &[]),
            settlement_root: merkle_root(PROVER_FAILURE_SETTLEMENT_SUITE, &[]),
            fee_pool_commitment,
            rebate_root,
            status: BatchStatus::Open,
            item_count: 0,
            target_fee_bps: self.config.target_batch_fee_bps,
            opened_l2_height: self.config.l2_height,
            closes_l2_height: self.config.l2_height + self.config.batch_window_blocks,
        };
        self.insert_public_record(
            format!("batch:{id}"),
            roots_only_record("batch", &record.batch_id, &record.commitment_root()),
        )?;
        self.batches.insert(id.clone(), record.clone());
        self.counters.batches += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn add_coupon_to_batch(&mut self, batch_id: &str, coupon_id: &str) -> Result<()> {
        let coupon = self
            .coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("unknown coupon {coupon_id}"))?;
        if !coupon.status.is_live() {
            return Err("coupon is not live".to_string());
        }
        coupon.status = CouponStatus::Batched;
        let leaves = vec![json!(coupon_id), json!(coupon.commitment_root())];
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch {batch_id}"))?;
        if !batch.status.accepts_items() {
            return Err("batch does not accept items".to_string());
        }
        if batch.item_count >= self.config.max_batch_items {
            return Err("batch is full".to_string());
        }
        batch.item_count += 1;
        batch.status = BatchStatus::Collecting;
        batch.coupon_root = merkle_root(LOW_FEE_BATCH_SUITE, &leaves);
        self.refresh_roots();
        Ok(())
    }

    pub fn witness_prover_failure_settlement(
        &mut self,
        input: SettlementInput,
    ) -> Result<ProverFailurePayoutSettlement> {
        self.validate_settlement_input(&input)?;
        self.ensure_replay(
            &input.settlement_nullifier,
            ReplayScope::Settlement,
            &input.coupon_id,
        )?;
        let id = deterministic_id(
            "prover_failure_payout_settlement",
            &input.public_record(),
            self.counters.settlements + 1,
        );
        let record = ProverFailurePayoutSettlement {
            settlement_id: id.clone(),
            coupon_id: input.coupon_id,
            batch_id: input.batch_id,
            settlement_nullifier: input.settlement_nullifier,
            proof_witness_root: input.proof_witness_root,
            failure_attestation_root: input.failure_attestation_root,
            payout_commitment: input.payout_commitment,
            fee_commitment: input.fee_commitment,
            collateral_release_root: input.collateral_release_root,
            status: SettlementStatus::Queued,
            attestation_count: input.attestation_count,
            settle_after_l2_height: input.settle_after_l2_height,
            created_l2_height: self.config.l2_height,
            settled_l2_height: None,
        };
        self.insert_public_record(
            format!("settlement:{id}"),
            roots_only_record(
                "settlement",
                &record.settlement_id,
                &record.commitment_root(),
            ),
        )?;
        self.settlements.insert(id.clone(), record.clone());
        self.counters.settlements += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn settle_prover_failure(&mut self, settlement_id: &str) -> Result<()> {
        let settlement = self
            .settlements
            .get_mut(settlement_id)
            .ok_or_else(|| format!("unknown settlement {settlement_id}"))?;
        if self.config.l2_height < settlement.settle_after_l2_height {
            return Err("settlement failure has not elapsed".to_string());
        }
        if settlement.attestation_count < self.config.settlement_quorum {
            return Err("settlement quorum not met".to_string());
        }
        settlement.status = SettlementStatus::Settled;
        settlement.settled_l2_height = Some(self.config.l2_height);
        if let Some(coupon) = self.coupons.get_mut(&settlement.coupon_id) {
            coupon.status = CouponStatus::Settled;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn record_collateral_snapshot(
        &mut self,
        snapshot: CollateralSnapshot,
    ) -> Result<CollateralSnapshot> {
        ensure_bps("coverage_bps", snapshot.coverage_bps)?;
        if snapshot.coverage_bps < self.config.min_collateral_coverage_bps {
            return Err("collateral coverage below policy floor".to_string());
        }
        self.insert_public_record(
            format!("collateral:{}", snapshot.collateral_root_id),
            roots_only_record(
                "collateral",
                &snapshot.collateral_root_id,
                &snapshot.commitment_root(),
            ),
        )?;
        self.collateral_snapshots
            .insert(snapshot.collateral_root_id.clone(), snapshot.clone());
        self.counters.collateral_roots += 1;
        self.refresh_roots();
        Ok(snapshot)
    }

    pub fn publish_nullifier(
        &mut self,
        nullifier: String,
        scope: ReplayScope,
        subject_id: String,
    ) -> Result<AntiReplayNullifier> {
        self.ensure_replay(&nullifier, scope, &subject_id)?;
        let record = self
            .nullifiers
            .get(&nullifier)
            .cloned()
            .expect("inserted nullifier");
        self.refresh_roots();
        Ok(record)
    }

    fn ensure_replay(
        &mut self,
        nullifier: &str,
        scope: ReplayScope,
        subject_id: &str,
    ) -> Result<()> {
        if self.spent_nullifiers.contains(nullifier) {
            self.counters.rejected += 1;
            return Err(format!("duplicate nullifier {nullifier}"));
        }
        let record = AntiReplayNullifier {
            nullifier: nullifier.to_string(),
            scope,
            subject_id: subject_id.to_string(),
            root: root_from_parts(
                "anti-replay-nullifier",
                &[nullifier, scope.as_str(), subject_id],
            ),
            l2_height: self.config.l2_height,
        };
        self.nullifiers.insert(nullifier.to_string(), record);
        self.spent_nullifiers.insert(nullifier.to_string());
        self.counters.nullifiers += 1;
        Ok(())
    }

    fn validate_tranche_input(&self, input: &SealTrancheInput) -> Result<()> {
        if self.tranches.len() >= self.config.max_tranches {
            return Err("tranche capacity exhausted".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("tranche pq security below policy floor".to_string());
        }
        if input.strike_failure_blocks < self.config.min_failure_blocks
            || input.max_failure_blocks > self.config.max_failure_blocks
            || input.strike_failure_blocks > input.max_failure_blocks
        {
            return Err("failure bounds invalid".to_string());
        }
        if input.maturity_l2_height <= self.config.l2_height {
            return Err("maturity must be in the future".to_string());
        }
        Ok(())
    }

    fn validate_coupon_input(&self, input: &AdmitCouponInput) -> Result<()> {
        if self.coupons.len() >= self.config.max_coupons {
            return Err("coupon capacity exhausted".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("coupon privacy set too small".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("coupon pq security below policy floor".to_string());
        }
        let tranche = self
            .tranches
            .get(&input.tranche_id)
            .ok_or_else(|| format!("unknown tranche {}", input.tranche_id))?;
        if !tranche.status.accepts_exercises() {
            return Err("tranche does not accept exercises".to_string());
        }
        Ok(())
    }

    fn validate_observation_input(&self, input: &ObserveProverFailureInput) -> Result<()> {
        let tranche = self
            .tranches
            .get(&input.tranche_id)
            .ok_or_else(|| format!("unknown tranche {}", input.tranche_id))?;
        if !tranche.status.accepts_exercises() {
            return Err("tranche does not accept prover failure observations".to_string());
        }
        if input.failure_blocks < self.config.min_failure_blocks {
            return Err("observed failure below insured threshold".to_string());
        }
        if input.failure_blocks > self.config.max_failure_blocks {
            return Err("observed failure exceeds configured bound".to_string());
        }
        if input.observer_quorum < self.config.oracle_quorum {
            return Err("observation quorum not met".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("observation privacy set too small".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("observation pq security below policy".to_string());
        }
        if input.monero_anchor_height < self.config.monero_height {
            return Err("observation monero anchor is stale".to_string());
        }
        Ok(())
    }

    fn validate_settlement_input(&self, input: &SettlementInput) -> Result<()> {
        if self.settlements.len() >= self.config.max_settlements {
            return Err("settlement capacity exhausted".to_string());
        }
        if input.attestation_count < self.config.settlement_quorum {
            return Err("settlement attestation quorum not met".to_string());
        }
        if input.settle_after_l2_height < self.config.l2_height + self.config.min_failure_blocks {
            return Err("settlement failure too short".to_string());
        }
        if !self.coupons.contains_key(&input.coupon_id) {
            return Err(format!("unknown coupon {}", input.coupon_id));
        }
        if !self.batches.contains_key(&input.batch_id) {
            return Err(format!("unknown batch {}", input.batch_id));
        }
        Ok(())
    }

    fn compute_roots(&self) -> Roots {
        let config_root = root_from_record("CONFIG", &self.config.public_record());
        let tranche_root = map_root(SEALED_TRANCHE_SUITE, &self.tranches);
        let observation_root = map_root(PROVER_FAILURE_OBSERVATION_SUITE, &self.observations);
        let premium_curve_root = map_root(PREMIUM_CURVE_ROOT_SUITE, &self.premium_curves);
        let coupon_root = map_root(PQ_COUPON_ROOT_SUITE, &self.coupons);
        let settlement_root = map_root(PROVER_FAILURE_SETTLEMENT_SUITE, &self.settlements);
        let collateral_root = map_root(COLLATERAL_ROOT_SUITE, &self.collateral_snapshots);
        let batch_root = map_root(LOW_FEE_BATCH_SUITE, &self.batches);
        let nullifier_root = map_root(ANTI_REPLAY_NULLIFIER_SUITE, &self.nullifiers);
        let public_record_root = value_map_root(PUBLIC_RECORD_SUITE, &self.public_records);
        let counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        let state_payload = json!({ "config_root": config_root, "tranche_root": tranche_root, "observation_root": observation_root, "premium_curve_root": premium_curve_root, "coupon_root": coupon_root, "settlement_root": settlement_root, "collateral_root": collateral_root, "batch_root": batch_root, "nullifier_root": nullifier_root, "public_record_root": public_record_root, "counters_root": counters_root });
        let state_root = root_from_record(STATE_ROOT_SUITE, &state_payload);
        Roots {
            config_root,
            tranche_root,
            observation_root,
            premium_curve_root,
            coupon_root,
            settlement_root,
            collateral_root,
            batch_root,
            nullifier_root,
            public_record_root,
            counters_root,
            state_root,
        }
    }

    fn refresh_roots(&mut self) {
        self.roots = self.compute_roots();
    }

    fn insert_public_record(&mut self, key: String, value: Value) -> Result<()> {
        if !value
            .get("roots_only")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err("public record must be roots-only".to_string());
        }
        self.public_records.insert(key, value);
        self.counters.public_records += 1;
        Ok(())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            tranches: 0,
            premium_curves: 0,
            coupons: 0,
            settlements: 0,
            batches: 0,
            collateral_roots: 0,
            nullifiers: 0,
            public_records: 0,
            rejected: 0,
            quarantined: 0,
        }
    }
}

impl Default for Roots {
    fn default() -> Self {
        let empty = merkle_root(PUBLIC_RECORD_SUITE, &[]);
        Self {
            config_root: empty.clone(),
            tranche_root: empty.clone(),
            premium_curve_root: empty.clone(),
            coupon_root: empty.clone(),
            settlement_root: empty.clone(),
            collateral_root: empty.clone(),
            batch_root: empty.clone(),
            nullifier_root: empty.clone(),
            public_record_root: empty.clone(),
            counters_root: empty.clone(),
            state_root: empty,
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}
pub fn deterministic_id(domain: &str, record: &Value, sequence: u64) -> String {
    domain_hash(
        domain,
        &[HashPart::Json(record), HashPart::U64(sequence)],
        20,
    )
}
pub fn commitment(label: &str, value: u64) -> String {
    domain_hash(
        "PROVER-FAILURE-COMMITMENT",
        &[HashPart::Str(label), HashPart::U64(value)],
        32,
    )
}
pub fn root_from_parts(domain: &str, parts: &[&str]) -> String {
    let values = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    merkle_root(domain, &values)
}
fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds bps scale"))
    } else {
        Ok(())
    }
}
fn roots_only_record(kind: &str, id: &str, commitment_root: &str) -> Value {
    json!({ "kind": kind, "id": id, "commitment_root": commitment_root, "roots_only": true, "protocol_version": PROTOCOL_VERSION })
}
fn public_record_for<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime record serialization")
}
trait RuntimePublicRecord {
    fn public_record(&self) -> Value;
}
impl RuntimePublicRecord for SealedOptionTranche {
    fn public_record(&self) -> Value {
        SealedOptionTranche::public_record(self)
    }
}
impl RuntimePublicRecord for PremiumCurveCommitment {
    fn public_record(&self) -> Value {
        PremiumCurveCommitment::public_record(self)
    }
}
impl RuntimePublicRecord for PqClaimCoupon {
    fn public_record(&self) -> Value {
        PqClaimCoupon::public_record(self)
    }
}
impl RuntimePublicRecord for ProverFailureObservation {
    fn public_record(&self) -> Value {
        ProverFailureObservation::public_record(self)
    }
}
impl RuntimePublicRecord for ProverFailurePayoutSettlement {
    fn public_record(&self) -> Value {
        ProverFailurePayoutSettlement::public_record(self)
    }
}
impl RuntimePublicRecord for CollateralSnapshot {
    fn public_record(&self) -> Value {
        CollateralSnapshot::public_record(self)
    }
}
impl RuntimePublicRecord for LowFeeExerciseBatch {
    fn public_record(&self) -> Value {
        LowFeeExerciseBatch::public_record(self)
    }
}
impl RuntimePublicRecord for AntiReplayNullifier {
    fn public_record(&self) -> Value {
        AntiReplayNullifier::public_record(self)
    }
}
fn map_root<T: RuntimePublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn value_map_root(domain: &str, values: &BTreeMap<String, Value>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeSurfaceMarker {
    pub name: String,
    pub category: String,
    pub root_suite: String,
    pub privacy_note: String,
}

impl RuntimeSurfaceMarker {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}
pub fn surface_markers() -> Vec<RuntimeSurfaceMarker> {
    vec![
        RuntimeSurfaceMarker {
            name: "sealed_option_tranches".to_string(),
            category: "defi_options".to_string(),
            root_suite: SEALED_TRANCHE_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "pq_claim_coupons".to_string(),
            category: "post_quantum_claims".to_string(),
            root_suite: PQ_COUPON_ROOT_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "private_premium_curves".to_string(),
            category: "private_pricing".to_string(),
            root_suite: PREMIUM_CURVE_ROOT_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "prover_failure_observations".to_string(),
            category: "prover_failure".to_string(),
            root_suite: PROVER_FAILURE_OBSERVATION_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "prover_failure_payout_settlement".to_string(),
            category: "prover_failure".to_string(),
            root_suite: PROVER_FAILURE_SETTLEMENT_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "collateral_roots".to_string(),
            category: "collateral".to_string(),
            root_suite: COLLATERAL_ROOT_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "low_fee_exercise_batching".to_string(),
            category: "low_fee".to_string(),
            root_suite: LOW_FEE_BATCH_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "anti_replay_nullifiers".to_string(),
            category: "privacy".to_string(),
            root_suite: ANTI_REPLAY_NULLIFIER_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
        RuntimeSurfaceMarker {
            name: "roots_only_public_records".to_string(),
            category: "public_audit".to_string(),
            root_suite: PUBLIC_RECORD_SUITE.to_string(),
            privacy_note: "commitments-and-roots-only".to_string(),
        },
    ]
}
