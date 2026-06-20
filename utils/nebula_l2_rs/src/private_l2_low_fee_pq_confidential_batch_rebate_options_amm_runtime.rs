use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBatchRebateOptionsAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_OPTIONS_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-batch-rebate-options-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_OPTIONS_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_QUOTE_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-low-fee-options-amm-quote-v1";
pub const CONFIDENTIAL_OPTIONS_POOL_SCHEME: &str =
    "low-fee-confidential-batch-rebate-options-amm-pool-root-v1";
pub const BATCH_REBATE_ROUTE_SCHEME: &str =
    "low-fee-confidential-options-amm-batch-rebate-route-root-v1";
pub const OPTION_EXERCISE_INTENT_SCHEME: &str =
    "sealed-confidential-options-amm-exercise-intent-nullifier-root-v1";
pub const FEE_CREDIT_BUCKET_SCHEME: &str = "private-low-fee-options-amm-fee-credit-bucket-root-v1";
pub const PQ_QUOTE_ATTESTATION_SCHEME: &str =
    "pq-confidential-options-amm-quote-attestation-root-v1";
pub const LIQUIDITY_GUARDRAIL_SCHEME: &str = "confidential-options-amm-liquidity-guardrail-root-v1";
pub const BATCH_CLEARING_SCHEME: &str =
    "private-options-amm-batch-clearing-rebate-settlement-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "private-options-amm-operator-low-fee-summary-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-low-fee-pq-confidential-batch-rebate-options-amm-public-record-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "private-l2-low-fee-pq-confidential-batch-rebate-options-amm-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_732_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_344_000;
pub const DEVNET_AMM_ID: &str = "private-low-fee-options-rebate-amm-devnet";
pub const DEVNET_UNDERLYING_ASSET_ID: &str = "pxmr-private-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "nebula-fee-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_LP_FEE_BPS: u64 = 3;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_REBATE_COVER_BPS: u64 = 9_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUOTE_QUORUM: u16 = 3;
pub const DEFAULT_EXERCISE_QUORUM: u16 = 2;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_CLEARING_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 2_048;
pub const DEFAULT_MIN_LIQUIDITY_UNITS: u128 = 25_000;
pub const DEFAULT_MIN_VAULT_COVERAGE_BPS: u64 = 10_750;
pub const DEFAULT_MAX_POOL_DELTA_ABS_BPS: i64 = 6_250;
pub const DEFAULT_MAX_POOL_GAMMA_BPS: u64 = 1_150;
pub const DEFAULT_MAX_UTILIZATION_BPS: u64 = 8_250;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 75;
pub const MAX_POOLS: usize = 262_144;
pub const MAX_ROUTES: usize = 524_288;
pub const MAX_INTENTS: usize = 1_048_576;
pub const MAX_BUCKETS: usize = 524_288;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_GUARDRAILS: usize = 524_288;
pub const MAX_BATCHES: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const MAX_NULLIFIERS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    Call,
    Put,
    BinaryCall,
    BinaryPut,
    BarrierCall,
    BarrierPut,
}
impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::BinaryCall => "binary_call",
            Self::BinaryPut => "binary_put",
            Self::BarrierCall => "barrier_call",
            Self::BarrierPut => "barrier_put",
        }
    }
    pub fn is_call(self) -> bool {
        matches!(self, Self::Call | Self::BinaryCall | Self::BarrierCall)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStyle {
    European,
    American,
    Bermudan,
}
impl OptionStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::European => "european",
            Self::American => "american",
            Self::Bermudan => "bermudan",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Warmup,
    Active,
    Paused,
    Degraded,
    Draining,
    Settled,
    Retired,
}
impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Warmup | Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    DirectExercise,
    PremiumNetting,
    RebateSweep,
    FeeCreditNetting,
    VolatilityAuction,
    PrivacyRebalance,
}
impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectExercise => "direct_exercise",
            Self::PremiumNetting => "premium_netting",
            Self::RebateSweep => "rebate_sweep",
            Self::FeeCreditNetting => "fee_credit_netting",
            Self::VolatilityAuction => "volatility_auction",
            Self::PrivacyRebalance => "privacy_rebalance",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::RebateSweep => 980,
            Self::FeeCreditNetting => 940,
            Self::PremiumNetting => 900,
            Self::DirectExercise => 850,
            Self::VolatilityAuction => 780,
            Self::PrivacyRebalance => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseIntentStatus {
    Submitted,
    PrivacyChecked,
    Quoted,
    Attested,
    Batched,
    Exercised,
    Rebated,
    Expired,
    Rejected,
    Cancelled,
}
impl ExerciseIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PrivacyChecked => "privacy_checked",
            Self::Quoted => "quoted",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Exercised => "exercised",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn clearable(self) -> bool {
        matches!(self, Self::Attested | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Funding,
    Active,
    Reserved,
    Draining,
    Exhausted,
    Expired,
    Quarantined,
}
impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved | Self::Draining)
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
pub enum ClearingStatus {
    Open,
    Netting,
    Settled,
    PartiallySettled,
    Disputed,
    Quarantined,
    Rejected,
}
impl ClearingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Netting => "netting",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Disputed => "disputed",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_quote_attestation_suite: String,
    pub amm_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub underlying_asset_id: String,
    pub quote_asset_id: String,
    pub rebate_asset_id: String,
    pub fee_asset_id: String,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub rebate_cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quote_quorum: u16,
    pub exercise_quorum: u16,
    pub intent_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub clearing_window_blocks: u64,
    pub dispute_window_blocks: u64,
    pub max_batch_items: usize,
    pub min_liquidity_units: u128,
    pub min_vault_coverage_bps: u64,
    pub max_pool_delta_abs_bps: i64,
    pub max_pool_gamma_bps: u64,
    pub max_utilization_bps: u64,
    pub max_price_impact_bps: u64,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_quote_attestation_suite: PQ_QUOTE_ATTESTATION_SUITE.to_string(),
            amm_id: DEVNET_AMM_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            underlying_asset_id: DEVNET_UNDERLYING_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            lp_fee_bps: DEFAULT_LP_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            rebate_cover_bps: DEFAULT_REBATE_COVER_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quote_quorum: DEFAULT_QUOTE_QUORUM,
            exercise_quorum: DEFAULT_EXERCISE_QUORUM,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            clearing_window_blocks: DEFAULT_CLEARING_WINDOW_BLOCKS,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            min_liquidity_units: DEFAULT_MIN_LIQUIDITY_UNITS,
            min_vault_coverage_bps: DEFAULT_MIN_VAULT_COVERAGE_BPS,
            max_pool_delta_abs_bps: DEFAULT_MAX_POOL_DELTA_ABS_BPS,
            max_pool_gamma_bps: DEFAULT_MAX_POOL_GAMMA_BPS,
            max_utilization_bps: DEFAULT_MAX_UTILIZATION_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
        }
    }
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root(&self) -> String {
        hash_json("CONFIG", &self.public_record())
    }
}
impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub routes: u64,
    pub exercise_intents: u64,
    pub fee_credit_buckets: u64,
    pub pq_quote_attestations: u64,
    pub liquidity_guardrails: u64,
    pub batch_clearings: u64,
    pub operator_summaries: u64,
    pub consumed_nullifiers: u64,
    pub public_records: u64,
    pub total_intent_items: u64,
    pub settled_intent_items: u64,
    pub rejected_intent_items: u64,
    pub rebate_notes_issued: u64,
    pub max_observed_fee_bps: u64,
    pub min_observed_privacy_set_size: u64,
}
impl Counters {
    pub fn new() -> Self {
        Self {
            min_observed_privacy_set_size: u64::MAX,
            ..Self::default()
        }
    }
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root(&self) -> String {
        hash_json("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub routes_root: String,
    pub exercise_intents_root: String,
    pub fee_credit_buckets_root: String,
    pub pq_quote_attestations_root: String,
    pub liquidity_guardrails_root: String,
    pub batch_clearings_root: String,
    pub operator_summaries_root: String,
    pub consumed_nullifiers_root: String,
    pub public_records_root: String,
    pub state_root: String,
}
impl Default for Roots {
    fn default() -> Self {
        let empty = domain_hash(
            "empty-low-fee-pq-confidential-batch-rebate-options-amm-root",
            &[HashPart::Str("empty")],
            32,
        );
        Self {
            config_root: empty.clone(),
            counters_root: empty.clone(),
            pools_root: empty.clone(),
            routes_root: empty.clone(),
            exercise_intents_root: empty.clone(),
            fee_credit_buckets_root: empty.clone(),
            pq_quote_attestations_root: empty.clone(),
            liquidity_guardrails_root: empty.clone(),
            batch_clearings_root: empty.clone(),
            operator_summaries_root: empty.clone(),
            consumed_nullifiers_root: empty.clone(),
            public_records_root: empty.clone(),
            state_root: empty,
        }
    }
}
impl Roots {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialOptionsPool {
    pub pool_id: String,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub underlying_asset_id: String,
    pub quote_asset_id: String,
    pub rebate_asset_id: String,
    pub strike_price_micro_units: u128,
    pub expiry_l2_height: u64,
    pub barrier_price_micro_units: Option<u128>,
    pub encrypted_underlying_reserve_commitment: String,
    pub encrypted_quote_reserve_commitment: String,
    pub option_inventory_commitment: String,
    pub lp_supply_commitment: String,
    pub greeks_commitment: String,
    pub premium_curve_root: String,
    pub status: PoolStatus,
    pub coverage_bps: u64,
    pub utilization_bps: u64,
    pub low_fee_lane_bps: u64,
    pub opened_at_l2_height: u64,
}
impl ConfidentialOptionsPool {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(CONFIDENTIAL_OPTIONS_POOL_SCHEME, &self.public_record())
    }
    pub fn is_expired_at(&self, height: u64) -> bool {
        height >= self.expiry_l2_height
    }
    pub fn remaining_blocks(&self, height: u64) -> u64 {
        self.expiry_l2_height.saturating_sub(height)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteHop {
    pub pool_id: String,
    pub action: String,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_floor: u64,
}
impl RouteHop {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRebateRoute {
    pub route_id: String,
    pub route_kind: RouteKind,
    pub pool_ids: Vec<String>,
    pub hops: Vec<RouteHop>,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub rebate_asset_id: String,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub priority: u64,
    pub privacy_floor: u64,
    pub route_transcript_root: String,
    pub active: bool,
}
impl BatchRebateRoute {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(BATCH_REBATE_ROUTE_SCHEME, &self.public_record())
    }
    pub fn effective_priority(&self) -> u64 {
        self.priority + self.route_kind.priority_weight() + self.target_rebate_bps.saturating_mul(2)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OptionExerciseIntent {
    pub intent_id: String,
    pub route_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub position_note_commitment: String,
    pub exercise_nullifier: String,
    pub encrypted_exercise_payload_root: String,
    pub max_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub sealed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: ExerciseIntentStatus,
}
impl OptionExerciseIntent {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(OPTION_EXERCISE_INTENT_SCHEME, &self.public_record())
    }
    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_l2_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditBucket {
    pub bucket_id: String,
    pub rebate_asset_id: String,
    pub sponsor_commitment: String,
    pub available_credit_commitment: String,
    pub reserved_credit_commitment: String,
    pub spent_credit_commitment: String,
    pub min_privacy_set_size: u64,
    pub rebate_cover_bps: u64,
    pub status: BucketStatus,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}
impl FeeCreditBucket {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(FEE_CREDIT_BUCKET_SCHEME, &self.public_record())
    }
    pub fn spendable_at(&self, height: u64) -> bool {
        self.status.spendable() && height <= self.expires_at_l2_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqQuoteAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub intent_id: String,
    pub pool_id: String,
    pub operator_id: String,
    pub pq_scheme: String,
    pub mark_price_micro_units: u128,
    pub implied_volatility_bps: u64,
    pub confidence_bps: u64,
    pub max_fee_bps: u64,
    pub quote_round: u64,
    pub ml_kem_ciphertext_commitment: String,
    pub ml_dsa_signature_commitment: String,
    pub slh_dsa_signature_commitment: String,
    pub quote_transcript_root: String,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub verdict: AttestationVerdict,
}
impl PqQuoteAttestation {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(PQ_QUOTE_ATTESTATION_SCHEME, &self.public_record())
    }
    pub fn valid_at(&self, height: u64) -> bool {
        self.verdict == AttestationVerdict::Accept && height <= self.expires_at_l2_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityGuardrail {
    pub guardrail_id: String,
    pub pool_id: String,
    pub min_liquidity_commitment: String,
    pub observed_liquidity_commitment: String,
    pub min_vault_coverage_bps: u64,
    pub observed_coverage_bps: u64,
    pub max_delta_abs_bps: i64,
    pub observed_delta_bps: i64,
    pub max_gamma_bps: u64,
    pub observed_gamma_bps: u64,
    pub max_utilization_bps: u64,
    pub observed_utilization_bps: u64,
    pub max_price_impact_bps: u64,
    pub observed_price_impact_bps: u64,
    pub risk_proof_root: String,
    pub active: bool,
}
impl LiquidityGuardrail {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(LIQUIDITY_GUARDRAIL_SCHEME, &self.public_record())
    }
    pub fn passes(&self) -> bool {
        self.active
            && self.observed_coverage_bps >= self.min_vault_coverage_bps
            && self.observed_delta_bps.abs() <= self.max_delta_abs_bps
            && self.observed_gamma_bps <= self.max_gamma_bps
            && self.observed_utilization_bps <= self.max_utilization_bps
            && self.observed_price_impact_bps <= self.max_price_impact_bps
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchClearing {
    pub batch_id: String,
    pub route_ids: Vec<String>,
    pub intent_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub bucket_ids: Vec<String>,
    pub matched_intents_root: String,
    pub rejected_intents_root: String,
    pub encrypted_netting_root: String,
    pub premium_settlement_root: String,
    pub exercise_settlement_root: String,
    pub private_rebate_settlement_root: String,
    pub charged_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_note_count: u64,
    pub cleared_at_l2_height: u64,
    pub dispute_deadline_l2_height: u64,
    pub status: ClearingStatus,
}
impl BatchClearing {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(BATCH_CLEARING_SCHEME, &self.public_record())
    }
    pub fn settled(&self) -> bool {
        matches!(
            self.status,
            ClearingStatus::Settled | ClearingStatus::PartiallySettled
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub pq_key_commitment: String,
    pub pool_count: u64,
    pub route_count: u64,
    pub attestation_count: u64,
    pub settled_batch_count: u64,
    pub total_rebate_units_commitment: String,
    pub avg_fee_bps: u64,
    pub low_fee_score: u64,
    pub privacy_score: u64,
    pub last_seen_l2_height: u64,
}
impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(OPERATOR_SUMMARY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub l2_height: u64,
}
impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
    pub fn root_leaf(&self) -> String {
        hash_json(PUBLIC_RECORD_SUITE, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, ConfidentialOptionsPool>,
    pub routes: BTreeMap<String, BatchRebateRoute>,
    pub exercise_intents: BTreeMap<String, OptionExerciseIntent>,
    pub fee_credit_buckets: BTreeMap<String, FeeCreditBucket>,
    pub pq_quote_attestations: BTreeMap<String, PqQuoteAttestation>,
    pub liquidity_guardrails: BTreeMap<String, LiquidityGuardrail>,
    pub batch_clearings: BTreeMap<String, BatchClearing>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}
impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::new(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            routes: BTreeMap::new(),
            exercise_intents: BTreeMap::new(),
            fee_credit_buckets: BTreeMap::new(),
            pq_quote_attestations: BTreeMap::new(),
            liquidity_guardrails: BTreeMap::new(),
            batch_clearings: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.install_devnet_fixtures();
        state
    }
    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let route_id = state.routes.keys().next().cloned().expect("devnet route");
        let pool_id = state.pools.keys().next().cloned().expect("devnet pool");
        let bucket_id = state
            .fee_credit_buckets
            .keys()
            .next()
            .cloned()
            .expect("devnet bucket");
        let intent_id = state
            .submit_exercise_intent(OptionExerciseIntent {
                intent_id: String::new(),
                route_id: route_id.clone(),
                pool_id: pool_id.clone(),
                owner_commitment: hex_root("demo-owner", 1),
                position_note_commitment: hex_root("demo-position", 1),
                exercise_nullifier: hex_root("demo-nullifier", 1),
                encrypted_exercise_payload_root: hex_root("demo-payload", 1),
                max_fee_bps: 10,
                requested_rebate_bps: 7,
                privacy_set_size: 262_144,
                sealed_at_l2_height: state.config.l2_height + 2,
                expires_at_l2_height: state.config.l2_height + DEFAULT_INTENT_TTL_BLOCKS,
                status: ExerciseIntentStatus::Attested,
            })
            .expect("demo intent");
        let attestation_id = state
            .record_pq_quote_attestation(PqQuoteAttestation {
                attestation_id: String::new(),
                route_id: route_id.clone(),
                intent_id: intent_id.clone(),
                pool_id: pool_id.clone(),
                operator_id: "operator-low-fee-devnet".to_string(),
                pq_scheme: PQ_QUOTE_ATTESTATION_SUITE.to_string(),
                mark_price_micro_units: 184_250_000,
                implied_volatility_bps: 6_850,
                confidence_bps: 9_860,
                max_fee_bps: 10,
                quote_round: 44,
                ml_kem_ciphertext_commitment: hex_root("demo-kem", 1),
                ml_dsa_signature_commitment: hex_root("demo-mldsa", 1),
                slh_dsa_signature_commitment: hex_root("demo-slh", 1),
                quote_transcript_root: hex_root("demo-quote", 1),
                attested_at_l2_height: state.config.l2_height + 3,
                expires_at_l2_height: state.config.l2_height + 3 + DEFAULT_ATTESTATION_TTL_BLOCKS,
                verdict: AttestationVerdict::Accept,
            })
            .expect("demo attestation");
        state
            .clear_batch(BatchClearing {
                batch_id: String::new(),
                route_ids: vec![route_id],
                intent_ids: vec![intent_id],
                attestation_ids: vec![attestation_id],
                bucket_ids: vec![bucket_id],
                matched_intents_root: hex_root("demo-matched", 1),
                rejected_intents_root: hex_root("demo-rejected", 1),
                encrypted_netting_root: hex_root("demo-netting", 1),
                premium_settlement_root: hex_root("demo-premium", 1),
                exercise_settlement_root: hex_root("demo-exercise", 1),
                private_rebate_settlement_root: hex_root("demo-rebate", 1),
                charged_fee_bps: 10,
                target_fee_bps: DEFAULT_LOW_FEE_BPS,
                rebate_note_count: 1,
                cleared_at_l2_height: state.config.l2_height + 6,
                dispute_deadline_l2_height: state.config.l2_height
                    + 6
                    + DEFAULT_DISPUTE_WINDOW_BLOCKS,
                status: ClearingStatus::Settled,
            })
            .expect("demo clearing");
        state
    }
    pub fn public_record(&self) -> Value {
        public_record(self)
    }
    pub fn state_root(&self) -> String {
        state_root(self)
    }
    pub fn upsert_pool(&mut self, mut pool: ConfidentialOptionsPool) -> Result<String> {
        ensure_capacity(self.pools.len(), MAX_POOLS, "pools")?;
        require_non_empty("underlying_asset_id", &pool.underlying_asset_id)?;
        require_non_empty("quote_asset_id", &pool.quote_asset_id)?;
        require(
            pool.low_fee_lane_bps <= self.config.max_user_fee_bps,
            "pool low fee lane exceeds max user fee",
        )?;
        require(
            pool.coverage_bps >= self.config.min_vault_coverage_bps,
            "pool coverage below vault guardrail",
        )?;
        require(
            pool.utilization_bps <= self.config.max_utilization_bps,
            "pool utilization above guardrail",
        )?;
        require_roots(&[
            &pool.encrypted_underlying_reserve_commitment,
            &pool.encrypted_quote_reserve_commitment,
            &pool.option_inventory_commitment,
            &pool.lp_supply_commitment,
            &pool.greeks_commitment,
            &pool.premium_curve_root,
        ])?;
        if pool.pool_id.is_empty() {
            pool.pool_id = deterministic_id(
                "options-pool",
                &[
                    HashPart::Str(&pool.underlying_asset_id),
                    HashPart::Str(&pool.quote_asset_id),
                    HashPart::U64(pool.expiry_l2_height),
                    HashPart::Int(pool.strike_price_micro_units as i128),
                ],
            );
        }
        let id = pool.pool_id.clone();
        self.pools.insert(id.clone(), pool);
        self.record_public("pool", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn upsert_route(&mut self, mut route: BatchRebateRoute) -> Result<String> {
        ensure_capacity(self.routes.len(), MAX_ROUTES, "routes")?;
        require(
            !route.pool_ids.is_empty(),
            "route requires at least one pool",
        )?;
        require(
            unique_strings(&route.pool_ids),
            "route pool ids must be unique",
        )?;
        require(
            route.max_user_fee_bps <= self.config.max_user_fee_bps,
            "route max user fee too high",
        )?;
        require(
            route.target_rebate_bps <= MAX_BPS,
            "route rebate bps too high",
        )?;
        require(
            route.privacy_floor >= self.config.min_privacy_set_size,
            "route privacy floor too low",
        )?;
        for pool_id in &route.pool_ids {
            require(
                self.pools.contains_key(pool_id),
                "route references unknown pool",
            )?;
        }
        if route.route_id.is_empty() {
            route.route_id = deterministic_id(
                "batch-rebate-route",
                &[
                    HashPart::Str(&route.input_asset_id),
                    HashPart::Str(&route.output_asset_id),
                    HashPart::Str(&route.rebate_asset_id),
                    HashPart::U64(route.priority),
                ],
            );
        }
        let id = route.route_id.clone();
        self.routes.insert(id.clone(), route);
        self.record_public("route", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn submit_exercise_intent(&mut self, mut intent: OptionExerciseIntent) -> Result<String> {
        ensure_capacity(self.exercise_intents.len(), MAX_INTENTS, "exercise intents")?;
        require(
            self.routes.contains_key(&intent.route_id),
            "intent references unknown route",
        )?;
        require(
            self.pools.contains_key(&intent.pool_id),
            "intent references unknown pool",
        )?;
        require(
            intent.max_fee_bps <= self.config.max_user_fee_bps,
            "intent max fee too high",
        )?;
        require(
            intent.privacy_set_size >= self.config.min_privacy_set_size,
            "intent privacy set too small",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&intent.exercise_nullifier),
            "intent nullifier already consumed",
        )?;
        require_roots(&[
            &intent.owner_commitment,
            &intent.position_note_commitment,
            &intent.exercise_nullifier,
            &intent.encrypted_exercise_payload_root,
        ])?;
        if intent.intent_id.is_empty() {
            intent.intent_id = deterministic_id(
                "exercise-intent",
                &[
                    HashPart::Str(&intent.route_id),
                    HashPart::Str(&intent.pool_id),
                    HashPart::Str(&intent.exercise_nullifier),
                ],
            );
        }
        let id = intent.intent_id.clone();
        self.exercise_intents.insert(id.clone(), intent);
        self.record_public("exercise_intent", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn upsert_fee_credit_bucket(&mut self, mut bucket: FeeCreditBucket) -> Result<String> {
        ensure_capacity(
            self.fee_credit_buckets.len(),
            MAX_BUCKETS,
            "fee credit buckets",
        )?;
        require(
            bucket.rebate_cover_bps <= MAX_BPS,
            "rebate cover bps too high",
        )?;
        require(
            bucket.min_privacy_set_size >= self.config.min_privacy_set_size,
            "bucket privacy floor too low",
        )?;
        require_roots(&[
            &bucket.sponsor_commitment,
            &bucket.available_credit_commitment,
            &bucket.reserved_credit_commitment,
            &bucket.spent_credit_commitment,
        ])?;
        if bucket.bucket_id.is_empty() {
            bucket.bucket_id = deterministic_id(
                "fee-credit-bucket",
                &[
                    HashPart::Str(&bucket.rebate_asset_id),
                    HashPart::Str(&bucket.sponsor_commitment),
                    HashPart::U64(bucket.expires_at_l2_height),
                ],
            );
        }
        let id = bucket.bucket_id.clone();
        self.fee_credit_buckets.insert(id.clone(), bucket);
        self.record_public("fee_credit_bucket", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn record_pq_quote_attestation(
        &mut self,
        mut attestation: PqQuoteAttestation,
    ) -> Result<String> {
        ensure_capacity(
            self.pq_quote_attestations.len(),
            MAX_ATTESTATIONS,
            "pq quote attestations",
        )?;
        require(
            self.routes.contains_key(&attestation.route_id),
            "attestation references unknown route",
        )?;
        require(
            self.exercise_intents.contains_key(&attestation.intent_id),
            "attestation references unknown intent",
        )?;
        require(
            attestation.confidence_bps <= MAX_BPS,
            "attestation confidence too high",
        )?;
        require(
            attestation.max_fee_bps <= self.config.max_user_fee_bps,
            "attestation fee too high",
        )?;
        require_roots(&[
            &attestation.ml_kem_ciphertext_commitment,
            &attestation.ml_dsa_signature_commitment,
            &attestation.slh_dsa_signature_commitment,
            &attestation.quote_transcript_root,
        ])?;
        if attestation.attestation_id.is_empty() {
            attestation.attestation_id = deterministic_id(
                "pq-quote-attestation",
                &[
                    HashPart::Str(&attestation.intent_id),
                    HashPart::Str(&attestation.operator_id),
                    HashPart::U64(attestation.quote_round),
                ],
            );
        }
        let id = attestation.attestation_id.clone();
        self.pq_quote_attestations.insert(id.clone(), attestation);
        self.record_public("pq_quote_attestation", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn upsert_liquidity_guardrail(
        &mut self,
        mut guardrail: LiquidityGuardrail,
    ) -> Result<String> {
        ensure_capacity(
            self.liquidity_guardrails.len(),
            MAX_GUARDRAILS,
            "liquidity guardrails",
        )?;
        require(
            self.pools.contains_key(&guardrail.pool_id),
            "guardrail references unknown pool",
        )?;
        require(
            guardrail.max_delta_abs_bps >= 0,
            "max delta must be positive",
        )?;
        require_roots(&[
            &guardrail.min_liquidity_commitment,
            &guardrail.observed_liquidity_commitment,
            &guardrail.risk_proof_root,
        ])?;
        if guardrail.guardrail_id.is_empty() {
            guardrail.guardrail_id = deterministic_id(
                "liquidity-guardrail",
                &[
                    HashPart::Str(&guardrail.pool_id),
                    HashPart::U64(guardrail.observed_utilization_bps),
                ],
            );
        }
        let id = guardrail.guardrail_id.clone();
        self.liquidity_guardrails.insert(id.clone(), guardrail);
        self.record_public("liquidity_guardrail", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn clear_batch(&mut self, mut batch: BatchClearing) -> Result<String> {
        ensure_capacity(self.batch_clearings.len(), MAX_BATCHES, "batch clearings")?;
        require(!batch.intent_ids.is_empty(), "batch requires intents")?;
        require(
            batch.intent_ids.len() <= self.config.max_batch_items,
            "batch item count too high",
        )?;
        require(
            unique_strings(&batch.intent_ids),
            "batch intent ids must be unique",
        )?;
        require(
            batch.charged_fee_bps <= self.config.max_user_fee_bps,
            "batch charged fee too high",
        )?;
        require(
            batch.target_fee_bps <= batch.charged_fee_bps,
            "target fee cannot exceed charged fee",
        )?;
        for intent_id in &batch.intent_ids {
            let intent = self
                .exercise_intents
                .get(intent_id)
                .ok_or_else(|| "batch references unknown intent".to_string())?;
            require(intent.status.clearable(), "batch intent is not clearable")?;
        }
        for attestation_id in &batch.attestation_ids {
            let attestation = self
                .pq_quote_attestations
                .get(attestation_id)
                .ok_or_else(|| "batch references unknown attestation".to_string())?;
            require(
                attestation.valid_at(batch.cleared_at_l2_height),
                "batch attestation is not valid",
            )?;
        }
        for bucket_id in &batch.bucket_ids {
            let bucket = self
                .fee_credit_buckets
                .get(bucket_id)
                .ok_or_else(|| "batch references unknown bucket".to_string())?;
            require(
                bucket.spendable_at(batch.cleared_at_l2_height),
                "batch bucket is not spendable",
            )?;
        }
        require_roots(&[
            &batch.matched_intents_root,
            &batch.rejected_intents_root,
            &batch.encrypted_netting_root,
            &batch.premium_settlement_root,
            &batch.exercise_settlement_root,
            &batch.private_rebate_settlement_root,
        ])?;
        if batch.batch_id.is_empty() {
            batch.batch_id = deterministic_id(
                "batch-clearing",
                &[
                    HashPart::Str(&batch.matched_intents_root),
                    HashPart::U64(batch.cleared_at_l2_height),
                    HashPart::U64(batch.intent_ids.len() as u64),
                ],
            );
        }
        let id = batch.batch_id.clone();
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.exercise_intents.get_mut(intent_id) {
                intent.status = if batch.settled() {
                    ExerciseIntentStatus::Rebated
                } else {
                    ExerciseIntentStatus::Rejected
                };
                self.consumed_nullifiers
                    .insert(intent.exercise_nullifier.clone());
            }
        }
        self.batch_clearings.insert(id.clone(), batch);
        self.record_public("batch_clearing", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn upsert_operator_summary(&mut self, mut summary: OperatorSummary) -> Result<String> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator summaries",
        )?;
        require_non_empty("operator_id", &summary.operator_id)?;
        require(
            summary.avg_fee_bps <= self.config.max_user_fee_bps,
            "operator average fee too high",
        )?;
        require_roots(&[
            &summary.pq_key_commitment,
            &summary.total_rebate_units_commitment,
        ])?;
        if summary.low_fee_score == 0 {
            summary.low_fee_score = MAX_BPS.saturating_sub(summary.avg_fee_bps.saturating_mul(100));
        }
        let id = summary.operator_id.clone();
        self.operator_summaries.insert(id.clone(), summary);
        self.record_public("operator_summary", &id);
        self.refresh_roots();
        Ok(id)
    }
    pub fn refresh_counters(&mut self) {
        let max_fee = self
            .exercise_intents
            .values()
            .map(|intent| intent.max_fee_bps)
            .max()
            .unwrap_or(0);
        let min_privacy = self
            .exercise_intents
            .values()
            .map(|intent| intent.privacy_set_size)
            .min()
            .unwrap_or(0);
        self.counters = Counters {
            pools: self.pools.len() as u64,
            routes: self.routes.len() as u64,
            exercise_intents: self.exercise_intents.len() as u64,
            fee_credit_buckets: self.fee_credit_buckets.len() as u64,
            pq_quote_attestations: self.pq_quote_attestations.len() as u64,
            liquidity_guardrails: self.liquidity_guardrails.len() as u64,
            batch_clearings: self.batch_clearings.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            public_records: self.public_records.len() as u64,
            total_intent_items: self
                .batch_clearings
                .values()
                .map(|batch| batch.intent_ids.len() as u64)
                .sum(),
            settled_intent_items: self
                .batch_clearings
                .values()
                .filter(|batch| batch.settled())
                .map(|batch| batch.intent_ids.len() as u64)
                .sum(),
            rejected_intent_items: self
                .batch_clearings
                .values()
                .filter(|batch| {
                    matches!(
                        batch.status,
                        ClearingStatus::Rejected | ClearingStatus::PartiallySettled
                    )
                })
                .map(|batch| batch.intent_ids.len() as u64)
                .sum(),
            rebate_notes_issued: self
                .batch_clearings
                .values()
                .map(|batch| batch.rebate_note_count)
                .sum(),
            max_observed_fee_bps: max_fee,
            min_observed_privacy_set_size: min_privacy,
        };
    }
    pub fn refresh_roots(&mut self) {
        self.refresh_counters();
        self.roots.config_root = self.config.root();
        self.roots.counters_root = self.counters.root();
        self.roots.pools_root =
            merkle_root_from(self.pools.values().map(ConfidentialOptionsPool::root_leaf));
        self.roots.routes_root =
            merkle_root_from(self.routes.values().map(BatchRebateRoute::root_leaf));
        self.roots.exercise_intents_root = merkle_root_from(
            self.exercise_intents
                .values()
                .map(OptionExerciseIntent::root_leaf),
        );
        self.roots.fee_credit_buckets_root = merkle_root_from(
            self.fee_credit_buckets
                .values()
                .map(FeeCreditBucket::root_leaf),
        );
        self.roots.pq_quote_attestations_root = merkle_root_from(
            self.pq_quote_attestations
                .values()
                .map(PqQuoteAttestation::root_leaf),
        );
        self.roots.liquidity_guardrails_root = merkle_root_from(
            self.liquidity_guardrails
                .values()
                .map(LiquidityGuardrail::root_leaf),
        );
        self.roots.batch_clearings_root =
            merkle_root_from(self.batch_clearings.values().map(BatchClearing::root_leaf));
        self.roots.operator_summaries_root = merkle_root_from(
            self.operator_summaries
                .values()
                .map(OperatorSummary::root_leaf),
        );
        self.roots.consumed_nullifiers_root = merkle_root(
            "consumed-options-amm-nullifiers",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        self.roots.public_records_root = merkle_root_from(
            self.public_records
                .values()
                .map(DeterministicPublicRecord::root_leaf),
        );
        self.roots.state_root = domain_hash(
            "private-l2-low-fee-pq-confidential-batch-rebate-options-amm-state-root",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.config.l2_height),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.pools_root),
                HashPart::Str(&self.roots.routes_root),
                HashPart::Str(&self.roots.exercise_intents_root),
                HashPart::Str(&self.roots.fee_credit_buckets_root),
                HashPart::Str(&self.roots.pq_quote_attestations_root),
                HashPart::Str(&self.roots.liquidity_guardrails_root),
                HashPart::Str(&self.roots.batch_clearings_root),
                HashPart::Str(&self.roots.operator_summaries_root),
                HashPart::Str(&self.roots.consumed_nullifiers_root),
                HashPart::Str(&self.roots.public_records_root),
            ],
            32,
        );
    }
    fn record_public(&mut self, kind: &str, id: &str) {
        let payload = domain_hash(
            "private-options-amm-public-record-payload",
            &[
                HashPart::Str(kind),
                HashPart::Str(id),
                HashPart::U64(self.config.l2_height),
            ],
            32,
        );
        let record_id =
            deterministic_id("public-record", &[HashPart::Str(kind), HashPart::Str(id)]);
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                record_kind: kind.to_string(),
                payload_root: payload,
                l2_height: self.config.l2_height,
            },
        );
    }
    fn install_devnet_fixtures(&mut self) {
        let pool_id = self
            .upsert_pool(ConfidentialOptionsPool {
                pool_id: "options-pxmr-dusd-30d-low-fee-devnet".to_string(),
                option_kind: OptionKind::Call,
                option_style: OptionStyle::European,
                underlying_asset_id: self.config.underlying_asset_id.clone(),
                quote_asset_id: self.config.quote_asset_id.clone(),
                rebate_asset_id: self.config.rebate_asset_id.clone(),
                strike_price_micro_units: 175_000_000,
                expiry_l2_height: self.config.l2_height + 21_600,
                barrier_price_micro_units: None,
                encrypted_underlying_reserve_commitment: hex_root("pool-underlying", 1),
                encrypted_quote_reserve_commitment: hex_root("pool-quote", 1),
                option_inventory_commitment: hex_root("pool-inventory", 1),
                lp_supply_commitment: hex_root("pool-lp", 1),
                greeks_commitment: hex_root("pool-greeks", 1),
                premium_curve_root: hex_root("pool-premium", 1),
                status: PoolStatus::Active,
                coverage_bps: 11_350,
                utilization_bps: 6_100,
                low_fee_lane_bps: DEFAULT_LOW_FEE_BPS,
                opened_at_l2_height: self.config.l2_height,
            })
            .expect("devnet pool");
        let route_id = self
            .upsert_route(BatchRebateRoute {
                route_id: "rebate-route-direct-exercise-devnet".to_string(),
                route_kind: RouteKind::RebateSweep,
                pool_ids: vec![pool_id.clone()],
                hops: vec![RouteHop {
                    pool_id: pool_id.clone(),
                    action: "exercise_and_rebate".to_string(),
                    max_fee_bps: 12,
                    rebate_bps: DEFAULT_TARGET_REBATE_BPS,
                    privacy_floor: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                }],
                input_asset_id: self.config.underlying_asset_id.clone(),
                output_asset_id: self.config.quote_asset_id.clone(),
                rebate_asset_id: self.config.rebate_asset_id.clone(),
                max_user_fee_bps: 12,
                target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
                priority: 900,
                privacy_floor: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                route_transcript_root: hex_root("route-transcript", 1),
                active: true,
            })
            .expect("devnet route");
        self.upsert_fee_credit_bucket(FeeCreditBucket {
            bucket_id: "fee-credit-sponsored-options-devnet".to_string(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            sponsor_commitment: hex_root("bucket-sponsor", 1),
            available_credit_commitment: hex_root("bucket-available", 1),
            reserved_credit_commitment: hex_root("bucket-reserved", 1),
            spent_credit_commitment: hex_root("bucket-spent", 1),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            rebate_cover_bps: DEFAULT_REBATE_COVER_BPS,
            status: BucketStatus::Active,
            opened_at_l2_height: self.config.l2_height,
            expires_at_l2_height: self.config.l2_height + DEFAULT_BUCKET_TTL_BLOCKS,
        })
        .expect("devnet bucket");
        self.upsert_liquidity_guardrail(LiquidityGuardrail {
            guardrail_id: "guardrail-options-pxmr-dusd-devnet".to_string(),
            pool_id: pool_id.clone(),
            min_liquidity_commitment: hex_root("guard-min", 1),
            observed_liquidity_commitment: hex_root("guard-observed", 1),
            min_vault_coverage_bps: DEFAULT_MIN_VAULT_COVERAGE_BPS,
            observed_coverage_bps: 11_350,
            max_delta_abs_bps: DEFAULT_MAX_POOL_DELTA_ABS_BPS,
            observed_delta_bps: 3_050,
            max_gamma_bps: DEFAULT_MAX_POOL_GAMMA_BPS,
            observed_gamma_bps: 430,
            max_utilization_bps: DEFAULT_MAX_UTILIZATION_BPS,
            observed_utilization_bps: 6_100,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            observed_price_impact_bps: 24,
            risk_proof_root: hex_root("guard-proof", 1),
            active: true,
        })
        .expect("devnet guardrail");
        self.upsert_operator_summary(OperatorSummary {
            operator_id: "operator-low-fee-devnet".to_string(),
            pq_key_commitment: hex_root("operator-pq-key", 1),
            pool_count: 1,
            route_count: 1,
            attestation_count: 0,
            settled_batch_count: 0,
            total_rebate_units_commitment: hex_root("operator-rebate-total", 1),
            avg_fee_bps: DEFAULT_LOW_FEE_BPS,
            low_fee_score: 9_600,
            privacy_score: 9_700,
            last_seen_l2_height: self.config.l2_height,
        })
        .expect("devnet operator");
        require(self.routes.contains_key(&route_id), "devnet route missing")
            .expect("devnet route installed");
    }
}
impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}
pub fn demo() -> State {
    State::demo()
}
pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": state.config.protocol_version,
        "schema_version": state.config.schema_version,
        "chain_id": state.config.chain_id,
        "amm_id": state.config.amm_id,
        "l2_height": state.config.l2_height,
        "monero_height": state.config.monero_height,
        "fee_policy": { "low_fee_bps": state.config.low_fee_bps, "max_user_fee_bps": state.config.max_user_fee_bps, "protocol_fee_bps": state.config.protocol_fee_bps, "lp_fee_bps": state.config.lp_fee_bps, "target_rebate_bps": state.config.target_rebate_bps, "rebate_cover_bps": state.config.rebate_cover_bps },
        "privacy_policy": { "min_privacy_set_size": state.config.min_privacy_set_size, "batch_privacy_set_size": state.config.batch_privacy_set_size, "min_pq_security_bits": state.config.min_pq_security_bits, "quote_quorum": state.config.quote_quorum, "exercise_quorum": state.config.exercise_quorum },
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "pools": state.pools.values().map(ConfidentialOptionsPool::public_record).collect::<Vec<_>>(),
        "routes": state.routes.values().map(BatchRebateRoute::public_record).collect::<Vec<_>>(),
        "exercise_intents": state.exercise_intents.values().map(OptionExerciseIntent::public_record).collect::<Vec<_>>(),
        "fee_credit_buckets": state.fee_credit_buckets.values().map(FeeCreditBucket::public_record).collect::<Vec<_>>(),
        "pq_quote_attestations": state.pq_quote_attestations.values().map(PqQuoteAttestation::public_record).collect::<Vec<_>>(),
        "liquidity_guardrails": state.liquidity_guardrails.values().map(LiquidityGuardrail::public_record).collect::<Vec<_>>(),
        "batch_clearings": state.batch_clearings.values().map(BatchClearing::public_record).collect::<Vec<_>>(),
        "operator_summaries": state.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>()
    })
}
pub fn state_root(state: &State) -> String {
    state.roots.state_root.clone()
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}
fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{domain}:{}", domain_hash(domain, parts, 16))
}
fn hash_json(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Str(domain), HashPart::Json(value)], 32)
}
fn stable_record<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime record serialization")
}
fn unique_strings(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}
fn require_root(value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Err("commitment/root must be hex with at least 32 chars".to_string())
    } else {
        Ok(())
    }
}
fn require_roots(values: &[&String]) -> Result<()> {
    for value in values {
        require_root(value)?;
    }
    Ok(())
}
fn merkle_root_from<I>(leaves: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(
        "private-l2-low-fee-pq-confidential-batch-rebate-options-amm-merkle-root",
        &leaves,
    )
}
fn hex_root(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-low-fee-pq-confidential-batch-rebate-options-amm-demo-root",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BATCH_REBATE_OPTIONS_AMM_RUNTIME_GENERATED_NOTES: &[&str] = &[
    "000: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "001: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "002: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "003: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "004: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "005: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "006: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "007: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "008: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "009: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "010: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "011: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "012: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "013: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "014: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "015: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "016: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "017: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "018: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "019: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "020: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "021: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "022: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "023: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "024: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "025: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "026: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "027: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "028: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "029: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "030: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "031: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "032: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "033: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "034: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "035: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "036: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "037: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "038: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "039: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "040: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "041: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "042: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "043: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "044: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "045: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "046: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "047: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "048: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "049: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "050: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "051: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "052: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "053: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "054: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "055: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "056: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "057: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "058: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "059: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "060: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "061: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "062: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "063: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "064: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "065: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "066: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "067: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "068: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "069: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "070: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "071: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "072: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "073: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "074: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "075: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "076: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "077: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "078: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "079: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "080: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "081: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "082: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "083: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "084: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "085: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "086: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "087: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "088: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "089: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "090: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "091: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "092: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "093: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "094: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "095: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "096: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "097: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "098: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "099: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "100: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "101: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "102: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "103: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "104: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "105: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "106: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "107: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "108: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "109: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "110: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "111: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "112: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "113: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "114: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "115: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "116: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "117: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "118: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "119: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "120: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "121: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "122: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "123: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "124: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "125: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "126: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "127: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "128: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "129: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "130: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "131: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "132: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "133: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "134: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "135: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "136: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "137: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "138: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "139: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "140: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "141: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "142: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "143: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "144: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "145: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "146: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "147: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "148: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "149: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "150: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "151: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "152: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "153: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "154: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "155: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "156: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "157: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "158: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "159: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "160: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "161: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "162: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "163: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "164: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "165: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "166: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "167: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "168: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "169: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "170: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "171: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "172: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "173: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "174: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "175: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "176: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "177: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "178: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "179: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "180: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "181: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "182: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "183: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "184: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "185: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "186: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "187: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "188: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "189: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "190: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "191: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "192: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "193: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "194: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "195: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "196: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "197: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "198: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "199: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "200: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "201: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "202: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "203: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "204: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "205: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "206: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "207: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "208: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "209: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "210: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "211: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "212: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "213: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "214: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "215: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "216: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "217: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "218: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "219: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "220: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "221: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "222: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "223: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "224: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "225: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "226: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "227: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "228: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "229: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "230: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "231: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "232: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "233: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "234: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "235: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "236: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "237: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "238: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "239: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "240: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "241: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "242: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "243: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "244: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "245: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "246: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "247: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "248: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "249: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "250: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "251: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "252: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "253: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "254: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "255: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "256: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "257: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "258: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "259: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "260: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "261: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "262: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "263: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "264: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "265: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "266: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "267: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "268: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "269: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "270: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "271: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "272: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "273: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "274: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "275: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "276: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "277: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "278: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "279: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "280: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "281: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "282: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "283: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "284: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "285: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "286: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "287: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "288: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "289: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "290: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "291: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "292: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "293: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "294: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "295: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "296: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "297: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "298: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "299: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "300: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "301: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "302: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "303: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "304: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "305: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "306: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "307: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "308: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "309: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "310: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "311: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "312: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "313: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "314: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "315: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "316: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "317: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "318: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "319: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "320: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "321: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "322: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "323: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "324: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "325: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "326: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "327: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "328: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "329: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "330: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "331: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "332: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "333: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "334: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "335: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "336: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "337: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "338: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "339: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "340: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "341: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "342: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "343: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "344: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "345: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "346: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "347: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "348: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "349: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "350: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "351: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "352: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "353: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "354: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "355: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "356: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "357: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "358: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "359: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "360: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "361: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "362: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "363: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "364: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "365: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "366: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "367: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "368: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "369: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "370: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "371: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "372: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "373: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "374: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "375: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "376: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "377: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "378: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "379: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "380: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "381: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "382: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "383: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "384: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "385: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "386: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "387: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "388: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "389: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "390: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "391: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "392: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "393: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "394: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "395: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "396: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "397: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "398: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "399: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "400: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "401: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "402: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "403: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "404: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "405: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "406: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "407: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "408: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "409: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "410: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "411: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "412: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "413: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "414: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "415: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "416: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "417: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "418: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "419: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "420: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "421: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "422: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "423: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "424: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "425: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "426: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "427: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "428: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "429: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "430: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "431: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "432: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "433: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "434: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "435: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "436: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "437: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "438: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "439: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "440: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "441: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "442: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "443: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "444: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "445: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "446: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "447: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "448: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "449: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "450: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "451: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "452: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "453: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "454: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "455: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "456: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "457: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "458: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "459: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "460: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "461: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "462: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "463: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "464: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "465: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "466: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "467: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "468: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "469: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "470: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "471: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "472: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "473: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "474: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "475: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "476: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "477: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "478: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "479: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "480: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "481: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "482: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "483: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "484: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "485: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "486: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "487: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "488: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "489: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "490: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "491: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "492: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "493: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "494: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "495: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "496: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "497: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "498: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "499: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "500: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "501: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "502: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "503: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "504: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "505: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "506: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "507: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "508: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "509: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "510: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "511: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "512: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "513: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "514: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "515: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "516: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "517: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "518: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "519: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "520: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "521: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "522: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "523: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "524: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "525: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "526: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "527: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "528: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "529: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "530: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "531: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "532: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "533: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "534: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "535: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "536: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "537: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "538: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "539: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "540: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "541: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "542: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "543: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "544: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "545: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "546: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "547: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "548: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "549: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
    "550: generated policy note: low fee option AMM clearing keeps premium and exercise notionals shielded while exporting roots only",
    "551: generated policy note: batch rebate routes net exercise fees against sponsor credits without revealing account balances",
    "552: generated policy note: PQ quote attestations bind oracle marks, volatility bands, and encrypted route transcripts",
    "553: generated policy note: liquidity guardrails cap delta, gamma, utilization, and price impact before settlement",
    "554: generated policy note: fee credit buckets reserve private rebates before batch clearing consumes nullifiers",
    "555: generated policy note: operator summaries expose service quality and fee discipline without disclosing positions",
    "556: generated policy note: confidential pools publish commitments for reserves, inventory, greeks, and LP shares",
    "557: generated policy note: private rebate settlement separates charged fee proofs from recipient note commitments",
    "558: generated policy note: clearing batches root matched intents, rejected intents, attestations, and rebate notes",
    "559: generated policy note: devnet fixtures model options, AMM, PQ attestations, and low fee rebate settlement",
];
