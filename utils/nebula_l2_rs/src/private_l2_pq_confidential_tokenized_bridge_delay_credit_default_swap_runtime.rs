use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedBridgeDelayCreditDefaultSwapRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BRIDGE_DELAY_CREDIT_DEFAULT_SWAP_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-bridge-delay-credit-default-swap-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BRIDGE_DELAY_CREDIT_DEFAULT_SWAP_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_CDS_TRANCHE_SUITE: &str = "sealed-confidential-bridge-delay-cds-tranche-root-v1";
pub const PRIVATE_PREMIUM_CURVE_SUITE: &str = "private-bridge-delay-cds-premium-curve-root-v1";
pub const BRIDGE_DELAY_OBSERVATION_SUITE: &str = "pq-oracle-bridge-delay-observation-root-v1";
pub const PQ_CLAIM_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-delay-cds-claim-coupon-v1";
pub const COLLATERAL_MARGIN_ROOT_SUITE: &str =
    "confidential-bridge-delay-cds-collateral-margin-root-v1";
pub const LOW_FEE_NETTED_SETTLEMENT_SUITE: &str =
    "low-fee-netted-bridge-delay-cds-settlement-root-v1";
pub const ANTI_REPLAY_NULLIFIER_SUITE: &str = "anti-replay-bridge-delay-cds-nullifier-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-bridge-delay-credit-default-swap-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-bridge-delay-cds-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-bridge-delay-cds-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str = "nebula-private-l2-pq-bridge-delay-cds-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-bridge-delay-cds-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-private-l2-bridge-delay-cds-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_336_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 5_004_000;
pub const DEVNET_EPOCH: u64 = 19_200;
pub const DEVNET_REFERENCE_TOKEN_ID: &str = "tbdcds-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_PREMIUM_ASSET_ID: &str = "nebula-premium-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_NETTING_FEE_BPS: u64 = 1;
pub const DEFAULT_PREMIUM_REBATE_BPS: u64 = 4_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_MARGIN_QUORUM: u16 = 3;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_250;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 1_450;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 2_000;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_750;
pub const DEFAULT_SOFT_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_HARD_DELAY_BLOCKS: u64 = 144;
pub const DEFAULT_CATASTROPHIC_DELAY_BLOCKS: u64 = 720;
pub const DEFAULT_OBSERVATION_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_NETTING_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_TRANCHES: usize = 16_384;
pub const DEFAULT_MAX_PREMIUM_CURVES: usize = 262_144;
pub const DEFAULT_MAX_OBSERVATIONS: usize = 524_288;
pub const DEFAULT_MAX_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDelayRiskKind {
    FinalityLag,
    WithdrawalQueueLag,
    WatchtowerCensorship,
    LiquidityRouteOutage,
    ReserveProofStaleness,
    KeyImageConflictHold,
    ReorgReviewHold,
    MultichainRelayBackpressure,
}
impl BridgeDelayRiskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FinalityLag => "finality_lag",
            Self::WithdrawalQueueLag => "withdrawal_queue_lag",
            Self::WatchtowerCensorship => "watchtower_censorship",
            Self::LiquidityRouteOutage => "liquidity_route_outage",
            Self::ReserveProofStaleness => "reserve_proof_staleness",
            Self::KeyImageConflictHold => "key_image_conflict_hold",
            Self::ReorgReviewHold => "reorg_review_hold",
            Self::MultichainRelayBackpressure => "multichain_relay_backpressure",
        }
    }
    pub fn base_weight_bps(self) -> u64 {
        match self {
            Self::FinalityLag => 850,
            Self::WithdrawalQueueLag => 1_050,
            Self::WatchtowerCensorship => 1_250,
            Self::LiquidityRouteOutage => 1_375,
            Self::ReserveProofStaleness => 1_100,
            Self::KeyImageConflictHold => 1_700,
            Self::ReorgReviewHold => 1_500,
            Self::MultichainRelayBackpressure => 1_900,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheSeniority {
    SuperSenior,
    Senior,
    Mezzanine,
    Junior,
    EquityFirstLoss,
}
impl TrancheSeniority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperSenior => "super_senior",
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::EquityFirstLoss => "equity_first_loss",
        }
    }
    pub fn loss_attachment_bps(self) -> u64 {
        match self {
            Self::SuperSenior => 7_500,
            Self::Senior => 5_000,
            Self::Mezzanine => 2_500,
            Self::Junior => 750,
            Self::EquityFirstLoss => 0,
        }
    }
    pub fn margin_multiplier_bps(self) -> u64 {
        match self {
            Self::SuperSenior => 7_500,
            Self::Senior => 8_750,
            Self::Mezzanine => 10_000,
            Self::Junior => 12_500,
            Self::EquityFirstLoss => 15_000,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheStatus {
    Draft,
    Sealed,
    Open,
    PremiumAccruing,
    DelayObserved,
    Couponed,
    Netted,
    Settling,
    Settled,
    Paused,
    Quarantined,
    Retired,
}
impl TrancheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Open => "open",
            Self::PremiumAccruing => "premium_accruing",
            Self::DelayObserved => "delay_observed",
            Self::Couponed => "couponed",
            Self::Netted => "netted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
    pub fn accepts_premiums(self) -> bool {
        matches!(
            self,
            Self::Open | Self::PremiumAccruing | Self::DelayObserved
        )
    }
    pub fn accepts_claims(self) -> bool {
        matches!(
            self,
            Self::DelayObserved | Self::Couponed | Self::Netted | Self::Settling
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Draft,
    PqSigned,
    Admitted,
    Netted,
    Settling,
    Settled,
    Redeemed,
    Disputed,
    Expired,
    Rejected,
}
impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PqSigned => "pq_signed",
            Self::Admitted => "admitted",
            Self::Netted => "netted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Redeemed => "redeemed",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::PqSigned | Self::Admitted | Self::Netted | Self::Settling
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Draft,
    CommitteeSigned,
    Admitted,
    CouponEligible,
    Disputed,
    Expired,
    Quarantined,
}
impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::CommitteeSigned => "committee_signed",
            Self::Admitted => "admitted",
            Self::CouponEligible => "coupon_eligible",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Open,
    Collecting,
    Frozen,
    Submitted,
    Settling,
    Settled,
    PartiallySettled,
    Quarantined,
}
impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Collecting => "collecting",
            Self::Frozen => "frozen",
            Self::Submitted => "submitted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Quarantined => "quarantined",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginStatus {
    Healthy,
    Warning,
    MarginCall,
    LiquidationQueued,
    Liquidated,
    Released,
}
impl MarginStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::MarginCall => "margin_call",
            Self::LiquidationQueued => "liquidation_queued",
            Self::Liquidated => "liquidated",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub market_id: String,
    pub bridge_id: String,
    pub reference_token_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub protocol_fee_bps: u64,
    pub netting_fee_bps: u64,
    pub premium_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub margin_quorum: u16,
    pub min_collateral_coverage_bps: u64,
    pub maintenance_margin_bps: u64,
    pub initial_margin_bps: u64,
    pub max_payout_bps: u64,
    pub soft_delay_blocks: u64,
    pub hard_delay_blocks: u64,
    pub catastrophic_delay_blocks: u64,
    pub observation_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub netting_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub max_batch_items: usize,
    pub max_tranches: usize,
    pub max_premium_curves: usize,
    pub max_observations: usize,
    pub max_coupons: usize,
    pub max_settlements: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            reference_token_id: DEVNET_REFERENCE_TOKEN_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            netting_fee_bps: DEFAULT_NETTING_FEE_BPS,
            premium_rebate_bps: DEFAULT_PREMIUM_REBATE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            margin_quorum: DEFAULT_MARGIN_QUORUM,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            soft_delay_blocks: DEFAULT_SOFT_DELAY_BLOCKS,
            hard_delay_blocks: DEFAULT_HARD_DELAY_BLOCKS,
            catastrophic_delay_blocks: DEFAULT_CATASTROPHIC_DELAY_BLOCKS,
            observation_ttl_blocks: DEFAULT_OBSERVATION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            netting_window_blocks: DEFAULT_NETTING_WINDOW_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_tranches: DEFAULT_MAX_TRANCHES,
            max_premium_curves: DEFAULT_MAX_PREMIUM_CURVES,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub tranches: u64,
    pub premium_curves: u64,
    pub observations: u64,
    pub coupons: u64,
    pub margin_accounts: u64,
    pub settlements: u64,
    pub nullifiers: u64,
    pub premium_notional: u128,
    pub protected_notional: u128,
    pub collateral_locked: u128,
    pub claims_couponed: u128,
    pub claims_settled: u128,
    pub fees_collected: u128,
    pub replay_rejections: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub tranche_root: String,
    pub premium_curve_root: String,
    pub observation_root: String,
    pub claim_coupon_root: String,
    pub collateral_margin_root: String,
    pub settlement_root: String,
    pub nullifier_root: String,
    pub payload_root: String,
    pub public_record_root: String,
}
impl Default for Roots {
    fn default() -> Self {
        Self {
            tranche_root: empty_root(SEALED_CDS_TRANCHE_SUITE),
            premium_curve_root: empty_root(PRIVATE_PREMIUM_CURVE_SUITE),
            observation_root: empty_root(BRIDGE_DELAY_OBSERVATION_SUITE),
            claim_coupon_root: empty_root(PQ_CLAIM_COUPON_SUITE),
            collateral_margin_root: empty_root(COLLATERAL_MARGIN_ROOT_SUITE),
            settlement_root: empty_root(LOW_FEE_NETTED_SETTLEMENT_SUITE),
            nullifier_root: empty_root(ANTI_REPLAY_NULLIFIER_SUITE),
            payload_root: empty_root(PAYLOAD_ROOT_SUITE),
            public_record_root: empty_root(PUBLIC_RECORD_SUITE),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCdsTranche {
    pub tranche_id: String,
    pub risk_kind: BridgeDelayRiskKind,
    pub seniority: TrancheSeniority,
    pub status: TrancheStatus,
    pub sealed_terms_root: String,
    pub buyer_commitment_root: String,
    pub seller_commitment_root: String,
    pub reference_delay_root: String,
    pub premium_curve_id: String,
    pub notional_commitment: u128,
    pub outstanding_protected_notional: u128,
    pub attachment_bps: u64,
    pub detachment_bps: u64,
    pub max_payout_bps: u64,
    pub maturity_l2_height: u64,
    pub created_l2_height: u64,
    pub pq_verifier_root: String,
    pub selective_disclosure_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivatePremiumCurve {
    pub curve_id: String,
    pub tranche_id: String,
    pub curve_commitment_root: String,
    pub sealed_rate_ladder_root: String,
    pub volatility_hint_root: String,
    pub min_premium_bps: u64,
    pub max_premium_bps: u64,
    pub current_premium_bps: u64,
    pub rebate_bps: u64,
    pub last_update_l2_height: u64,
    pub oracle_signature_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeDelayObservation {
    pub observation_id: String,
    pub bridge_id: String,
    pub risk_kind: BridgeDelayRiskKind,
    pub status: ObservationStatus,
    pub source_height: u64,
    pub destination_height: u64,
    pub observed_delay_blocks: u64,
    pub threshold_delay_blocks: u64,
    pub severity_bps: u64,
    pub attestation_root: String,
    pub committee_signature_root: String,
    pub evidence_root: String,
    pub expires_l2_height: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimCoupon {
    pub coupon_id: String,
    pub tranche_id: String,
    pub observation_id: String,
    pub holder_note_commitment: String,
    pub payout_commitment: String,
    pub status: CouponStatus,
    pub delay_blocks: u64,
    pub severity_bps: u64,
    pub payout_bps: u64,
    pub claim_notional: u128,
    pub coupon_nullifier: String,
    pub pq_signature_root: String,
    pub expires_l2_height: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralMarginAccount {
    pub account_id: String,
    pub tranche_id: String,
    pub owner_commitment: String,
    pub status: MarginStatus,
    pub collateral_commitment: String,
    pub margin_root: String,
    pub locked_collateral: u128,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub last_mark_bps: u64,
    pub last_update_l2_height: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettedSettlementBatch {
    pub batch_id: String,
    pub status: SettlementStatus,
    pub l2_height: u64,
    pub window_start: u64,
    pub window_end: u64,
    pub tranche_root: String,
    pub coupon_root: String,
    pub margin_root: String,
    pub debit_commitment_root: String,
    pub credit_commitment_root: String,
    pub fee_commitment_root: String,
    pub net_payout_commitment: u128,
    pub net_premium_commitment: u128,
    pub net_fee_commitment: u128,
    pub item_count: usize,
    pub settlement_nullifier_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AntiReplayNullifier {
    pub nullifier: String,
    pub domain: String,
    pub purpose: String,
    pub l2_height: u64,
    pub note_commitment: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealTrancheInput {
    pub risk_kind: BridgeDelayRiskKind,
    pub seniority: TrancheSeniority,
    pub sealed_terms_root: String,
    pub buyer_commitment_root: String,
    pub seller_commitment_root: String,
    pub reference_delay_root: String,
    pub notional_commitment: u128,
    pub detachment_bps: u64,
    pub maturity_l2_height: u64,
    pub pq_verifier_root: String,
    pub selective_disclosure_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PremiumCurveInput {
    pub tranche_id: String,
    pub curve_commitment_root: String,
    pub sealed_rate_ladder_root: String,
    pub volatility_hint_root: String,
    pub min_premium_bps: u64,
    pub max_premium_bps: u64,
    pub current_premium_bps: u64,
    pub oracle_signature_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DelayObservationInput {
    pub risk_kind: BridgeDelayRiskKind,
    pub source_height: u64,
    pub destination_height: u64,
    pub observed_delay_blocks: u64,
    pub threshold_delay_blocks: u64,
    pub attestation_root: String,
    pub committee_signature_root: String,
    pub evidence_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimCouponInput {
    pub tranche_id: String,
    pub observation_id: String,
    pub holder_note_commitment: String,
    pub payout_commitment: String,
    pub claim_notional: u128,
    pub coupon_nullifier: String,
    pub pq_signature_root: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginAccountInput {
    pub tranche_id: String,
    pub owner_commitment: String,
    pub collateral_commitment: String,
    pub margin_root: String,
    pub locked_collateral: u128,
    pub last_mark_bps: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatchInput {
    pub window_start: u64,
    pub window_end: u64,
    pub coupon_ids: Vec<String>,
    pub debit_commitment_root: String,
    pub credit_commitment_root: String,
    pub fee_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub tranches: BTreeMap<String, SealedCdsTranche>,
    pub premium_curves: BTreeMap<String, PrivatePremiumCurve>,
    pub observations: BTreeMap<String, BridgeDelayObservation>,
    pub claim_coupons: BTreeMap<String, PqClaimCoupon>,
    pub margin_accounts: BTreeMap<String, CollateralMarginAccount>,
    pub settlements: BTreeMap<String, NettedSettlementBatch>,
    pub nullifiers: BTreeMap<String, AntiReplayNullifier>,
    pub replay_guard: BTreeSet<String>,
}
impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}
impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            tranches: BTreeMap::new(),
            premium_curves: BTreeMap::new(),
            observations: BTreeMap::new(),
            claim_coupons: BTreeMap::new(),
            margin_accounts: BTreeMap::new(),
            settlements: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            replay_guard: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }
    pub fn counters(&self) -> &Counters {
        &self.counters
    }
    pub fn roots(&self) -> &Roots {
        &self.roots
    }
    pub fn state_root(&self) -> String {
        state_root(self)
    }
    pub fn public_record(&self) -> Value {
        public_record(self)
    }
    pub fn seal_tranche(&mut self, input: SealTrancheInput) -> Result<String> {
        self.ensure_capacity(self.tranches.len(), self.config.max_tranches, "tranche")?;
        require_nonempty(&input.sealed_terms_root, "sealed_terms_root")?;
        require_bps(input.detachment_bps, "detachment_bps")?;
        if input.notional_commitment == 0 {
            return Err("notional commitment must be positive".to_string());
        }
        let id = self.next_id(
            "tranche",
            self.counters.tranches + 1,
            &[
                HashPart::Str(&input.sealed_terms_root),
                HashPart::Str(input.risk_kind.as_str()),
                HashPart::Str(input.seniority.as_str()),
            ],
        );
        if self.tranches.contains_key(&id) {
            return Err(format!("duplicate tranche {id}"));
        }
        let attachment_bps = input.seniority.loss_attachment_bps();
        if input.detachment_bps <= attachment_bps {
            return Err("detachment must exceed attachment".to_string());
        }
        let tranche = SealedCdsTranche {
            tranche_id: id.clone(),
            risk_kind: input.risk_kind,
            seniority: input.seniority,
            status: TrancheStatus::Sealed,
            sealed_terms_root: input.sealed_terms_root,
            buyer_commitment_root: input.buyer_commitment_root,
            seller_commitment_root: input.seller_commitment_root,
            reference_delay_root: input.reference_delay_root,
            premium_curve_id: String::new(),
            notional_commitment: input.notional_commitment,
            outstanding_protected_notional: input.notional_commitment,
            attachment_bps,
            detachment_bps: input.detachment_bps,
            max_payout_bps: self.config.max_payout_bps,
            maturity_l2_height: input.maturity_l2_height,
            created_l2_height: self.config.l2_height,
            pq_verifier_root: input.pq_verifier_root,
            selective_disclosure_root: input.selective_disclosure_root,
        };
        self.counters.tranches += 1;
        self.counters.protected_notional = self
            .counters
            .protected_notional
            .saturating_add(tranche.outstanding_protected_notional);
        self.tranches.insert(id.clone(), tranche);
        self.refresh_roots();
        Ok(id)
    }
    pub fn attach_premium_curve(&mut self, input: PremiumCurveInput) -> Result<String> {
        self.ensure_capacity(
            self.premium_curves.len(),
            self.config.max_premium_curves,
            "premium curve",
        )?;
        require_bps(input.min_premium_bps, "min_premium_bps")?;
        require_bps(input.max_premium_bps, "max_premium_bps")?;
        require_bps(input.current_premium_bps, "current_premium_bps")?;
        if input.min_premium_bps > input.current_premium_bps
            || input.current_premium_bps > input.max_premium_bps
        {
            return Err("premium bps outside curve bounds".to_string());
        }
        let id = self.next_id(
            "curve",
            self.counters.premium_curves + 1,
            &[
                HashPart::Str(&input.tranche_id),
                HashPart::Str(&input.curve_commitment_root),
            ],
        );
        let tranche = self
            .tranches
            .get_mut(&input.tranche_id)
            .ok_or_else(|| format!("unknown tranche {}", input.tranche_id))?;
        if !matches!(
            tranche.status,
            TrancheStatus::Sealed | TrancheStatus::Open | TrancheStatus::PremiumAccruing
        ) {
            return Err("tranche cannot accept premium curve".to_string());
        }
        let curve = PrivatePremiumCurve {
            curve_id: id.clone(),
            tranche_id: input.tranche_id.clone(),
            curve_commitment_root: input.curve_commitment_root,
            sealed_rate_ladder_root: input.sealed_rate_ladder_root,
            volatility_hint_root: input.volatility_hint_root,
            min_premium_bps: input.min_premium_bps,
            max_premium_bps: input.max_premium_bps,
            current_premium_bps: input.current_premium_bps,
            rebate_bps: self.config.premium_rebate_bps,
            last_update_l2_height: self.config.l2_height,
            oracle_signature_root: input.oracle_signature_root,
        };
        tranche.premium_curve_id = id.clone();
        tranche.status = TrancheStatus::PremiumAccruing;
        self.counters.premium_curves += 1;
        self.counters.premium_notional = self.counters.premium_notional.saturating_add(
            tranche
                .outstanding_protected_notional
                .saturating_mul(input.current_premium_bps as u128)
                / MAX_BPS as u128,
        );
        self.premium_curves.insert(id.clone(), curve);
        self.refresh_roots();
        Ok(id)
    }
    pub fn admit_delay_observation(&mut self, input: DelayObservationInput) -> Result<String> {
        self.ensure_capacity(
            self.observations.len(),
            self.config.max_observations,
            "observation",
        )?;
        if input.observed_delay_blocks < input.threshold_delay_blocks {
            return Err("delay observation is below threshold".to_string());
        }
        let status = if input.observed_delay_blocks >= self.config.hard_delay_blocks {
            ObservationStatus::CouponEligible
        } else {
            ObservationStatus::Admitted
        };
        let severity_bps = self.delay_severity_bps(input.risk_kind, input.observed_delay_blocks);
        let id = self.next_id(
            "observation",
            self.counters.observations + 1,
            &[
                HashPart::Str(input.risk_kind.as_str()),
                HashPart::U64(input.source_height),
                HashPart::U64(input.destination_height),
            ],
        );
        let observation = BridgeDelayObservation {
            observation_id: id.clone(),
            bridge_id: self.config.bridge_id.clone(),
            risk_kind: input.risk_kind,
            status,
            source_height: input.source_height,
            destination_height: input.destination_height,
            observed_delay_blocks: input.observed_delay_blocks,
            threshold_delay_blocks: input.threshold_delay_blocks,
            severity_bps,
            attestation_root: input.attestation_root,
            committee_signature_root: input.committee_signature_root,
            evidence_root: input.evidence_root,
            expires_l2_height: self.config.l2_height + self.config.observation_ttl_blocks,
        };
        for tranche in self
            .tranches
            .values_mut()
            .filter(|t| t.risk_kind == input.risk_kind && t.status.accepts_premiums())
        {
            tranche.status = TrancheStatus::DelayObserved;
        }
        self.counters.observations += 1;
        self.observations.insert(id.clone(), observation);
        self.refresh_roots();
        Ok(id)
    }
    pub fn open_margin_account(&mut self, input: MarginAccountInput) -> Result<String> {
        let tranche = self
            .tranches
            .get(&input.tranche_id)
            .ok_or_else(|| format!("unknown tranche {}", input.tranche_id))?;
        let required = required_margin(
            tranche.outstanding_protected_notional,
            self.config.initial_margin_bps,
            tranche.seniority.margin_multiplier_bps(),
        );
        if input.locked_collateral < required {
            return Err("insufficient confidential collateral for initial margin".to_string());
        }
        let id = self.next_id(
            "margin",
            self.counters.margin_accounts + 1,
            &[
                HashPart::Str(&input.tranche_id),
                HashPart::Str(&input.owner_commitment),
            ],
        );
        let account = CollateralMarginAccount {
            account_id: id.clone(),
            tranche_id: input.tranche_id,
            owner_commitment: input.owner_commitment,
            status: MarginStatus::Healthy,
            collateral_commitment: input.collateral_commitment,
            margin_root: input.margin_root,
            locked_collateral: input.locked_collateral,
            initial_margin_bps: self.config.initial_margin_bps,
            maintenance_margin_bps: self.config.maintenance_margin_bps,
            last_mark_bps: input.last_mark_bps,
            last_update_l2_height: self.config.l2_height,
        };
        self.counters.margin_accounts += 1;
        self.counters.collateral_locked = self
            .counters
            .collateral_locked
            .saturating_add(input.locked_collateral);
        self.margin_accounts.insert(id.clone(), account);
        self.refresh_roots();
        Ok(id)
    }
    pub fn mint_claim_coupon(&mut self, input: ClaimCouponInput) -> Result<String> {
        self.ensure_capacity(
            self.claim_coupons.len(),
            self.config.max_coupons,
            "claim coupon",
        )?;
        self.consume_nullifier(
            input.coupon_nullifier.clone(),
            "claim_coupon",
            &input.holder_note_commitment,
        )?;
        let id = self.next_id(
            "coupon",
            self.counters.coupons + 1,
            &[
                HashPart::Str(&input.tranche_id),
                HashPart::Str(&input.observation_id),
                HashPart::Str(&input.coupon_nullifier),
            ],
        );
        let tranche = self
            .tranches
            .get_mut(&input.tranche_id)
            .ok_or_else(|| format!("unknown tranche {}", input.tranche_id))?;
        if !tranche.status.accepts_claims() {
            return Err("tranche is not claimable".to_string());
        }
        let observation = self
            .observations
            .get(&input.observation_id)
            .ok_or_else(|| format!("unknown observation {}", input.observation_id))?;
        if observation.risk_kind != tranche.risk_kind {
            return Err("observation risk kind does not match tranche".to_string());
        }
        if observation.expires_l2_height < self.config.l2_height {
            return Err("observation expired".to_string());
        }
        let payout_bps = compute_payout_bps(
            observation.severity_bps,
            tranche.attachment_bps,
            tranche.detachment_bps,
            tranche.max_payout_bps,
        );
        let coupon = PqClaimCoupon {
            coupon_id: id.clone(),
            tranche_id: input.tranche_id,
            observation_id: input.observation_id,
            holder_note_commitment: input.holder_note_commitment,
            payout_commitment: input.payout_commitment,
            status: CouponStatus::Admitted,
            delay_blocks: observation.observed_delay_blocks,
            severity_bps: observation.severity_bps,
            payout_bps,
            claim_notional: input.claim_notional,
            coupon_nullifier: input.coupon_nullifier,
            pq_signature_root: input.pq_signature_root,
            expires_l2_height: self.config.l2_height + self.config.coupon_ttl_blocks,
        };
        tranche.status = TrancheStatus::Couponed;
        self.counters.coupons += 1;
        self.counters.claims_couponed = self
            .counters
            .claims_couponed
            .saturating_add(input.claim_notional);
        self.claim_coupons.insert(id.clone(), coupon);
        self.refresh_roots();
        Ok(id)
    }
    pub fn settle_low_fee_batch(&mut self, input: SettlementBatchInput) -> Result<String> {
        self.ensure_capacity(
            self.settlements.len(),
            self.config.max_settlements,
            "settlement",
        )?;
        if input.coupon_ids.is_empty() {
            return Err("settlement batch requires coupons".to_string());
        }
        if input.coupon_ids.len() > self.config.max_batch_items {
            return Err("settlement batch exceeds max items".to_string());
        }
        let mut total_payout = 0_u128;
        let mut total_premium = 0_u128;
        for id in &input.coupon_ids {
            let coupon = self
                .claim_coupons
                .get_mut(id)
                .ok_or_else(|| format!("unknown coupon {id}"))?;
            if !coupon.status.is_live() {
                return Err(format!("coupon {id} is not live"));
            }
            total_payout = total_payout.saturating_add(
                coupon
                    .claim_notional
                    .saturating_mul(coupon.payout_bps as u128)
                    / MAX_BPS as u128,
            );
            total_premium = total_premium.saturating_add(coupon.claim_notional / 10_000);
            coupon.status = CouponStatus::Netted;
        }
        let fee =
            total_payout.saturating_mul(self.config.netting_fee_bps as u128) / MAX_BPS as u128;
        let id = self.next_id(
            "settlement",
            self.counters.settlements + 1,
            &[
                HashPart::U64(input.window_start),
                HashPart::U64(input.window_end),
                HashPart::Str(&input.debit_commitment_root),
            ],
        );
        let batch = NettedSettlementBatch {
            batch_id: id.clone(),
            status: SettlementStatus::Submitted,
            l2_height: self.config.l2_height,
            window_start: input.window_start,
            window_end: input.window_end,
            tranche_root: self.roots.tranche_root.clone(),
            coupon_root: self.roots.claim_coupon_root.clone(),
            margin_root: self.roots.collateral_margin_root.clone(),
            debit_commitment_root: input.debit_commitment_root,
            credit_commitment_root: input.credit_commitment_root,
            fee_commitment_root: input.fee_commitment_root,
            net_payout_commitment: total_payout,
            net_premium_commitment: total_premium,
            net_fee_commitment: fee,
            item_count: input.coupon_ids.len(),
            settlement_nullifier_root: self.roots.nullifier_root.clone(),
        };
        self.counters.settlements += 1;
        self.counters.claims_settled = self.counters.claims_settled.saturating_add(total_payout);
        self.counters.fees_collected = self.counters.fees_collected.saturating_add(fee);
        self.settlements.insert(id.clone(), batch);
        self.refresh_roots();
        Ok(id)
    }
    pub fn refresh_roots(&mut self) {
        self.roots.tranche_root = merkle_root(
            SEALED_CDS_TRANCHE_SUITE,
            &self.tranches.values().map(tranche_leaf).collect::<Vec<_>>(),
        );
        self.roots.premium_curve_root = merkle_root(
            PRIVATE_PREMIUM_CURVE_SUITE,
            &self
                .premium_curves
                .values()
                .map(premium_curve_leaf)
                .collect::<Vec<_>>(),
        );
        self.roots.observation_root = merkle_root(
            BRIDGE_DELAY_OBSERVATION_SUITE,
            &self
                .observations
                .values()
                .map(observation_leaf)
                .collect::<Vec<_>>(),
        );
        self.roots.claim_coupon_root = merkle_root(
            PQ_CLAIM_COUPON_SUITE,
            &self
                .claim_coupons
                .values()
                .map(coupon_leaf)
                .collect::<Vec<_>>(),
        );
        self.roots.collateral_margin_root = merkle_root(
            COLLATERAL_MARGIN_ROOT_SUITE,
            &self
                .margin_accounts
                .values()
                .map(margin_leaf)
                .collect::<Vec<_>>(),
        );
        self.roots.settlement_root = merkle_root(
            LOW_FEE_NETTED_SETTLEMENT_SUITE,
            &self
                .settlements
                .values()
                .map(settlement_leaf)
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = merkle_root(
            ANTI_REPLAY_NULLIFIER_SUITE,
            &self
                .nullifiers
                .values()
                .map(nullifier_leaf)
                .collect::<Vec<_>>(),
        );
        self.roots.payload_root = merkle_root(
            PAYLOAD_ROOT_SUITE,
            &[
                json!({"tranche_root": self.roots.tranche_root, "premium_curve_root": self.roots.premium_curve_root, "observation_root": self.roots.observation_root, "claim_coupon_root": self.roots.claim_coupon_root, "collateral_margin_root": self.roots.collateral_margin_root, "settlement_root": self.roots.settlement_root, "nullifier_root": self.roots.nullifier_root}),
            ],
        );
        self.roots.public_record_root = domain_hash(
            PUBLIC_RECORD_SUITE,
            &[HashPart::Json(&public_record(self))],
            32,
        );
    }
    fn consume_nullifier(
        &mut self,
        nullifier: String,
        purpose: &str,
        note_commitment: &str,
    ) -> Result<()> {
        require_nonempty(&nullifier, "nullifier")?;
        if !self.replay_guard.insert(nullifier.clone()) {
            self.counters.replay_rejections += 1;
            return Err("anti-replay nullifier already consumed".to_string());
        }
        let record = AntiReplayNullifier {
            nullifier: nullifier.clone(),
            domain: DEVNET_REPLAY_DOMAIN.to_string(),
            purpose: purpose.to_string(),
            l2_height: self.config.l2_height,
            note_commitment: note_commitment.to_string(),
        };
        self.counters.nullifiers += 1;
        self.nullifiers.insert(nullifier, record);
        Ok(())
    }
    fn ensure_capacity(&self, len: usize, max: usize, label: &str) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity reached"))
        } else {
            Ok(())
        }
    }
    fn delay_severity_bps(&self, risk_kind: BridgeDelayRiskKind, delay_blocks: u64) -> u64 {
        let threshold = self.config.hard_delay_blocks.max(1);
        let scaled = delay_blocks.saturating_mul(MAX_BPS) / threshold;
        scaled
            .saturating_add(risk_kind.base_weight_bps())
            .min(MAX_BPS)
    }
    fn next_id(&self, label: &str, nonce: u64, parts: &[HashPart<'_>]) -> String {
        let mut all = Vec::with_capacity(parts.len() + 4);
        all.push(HashPart::Str(PROTOCOL_VERSION));
        all.push(HashPart::Str(label));
        all.push(HashPart::U64(self.config.epoch));
        all.push(HashPart::U64(nonce));
        for part in parts {
            match part {
                HashPart::Bytes(value) => all.push(HashPart::Bytes(value)),
                HashPart::Str(value) => all.push(HashPart::Str(value)),
                HashPart::U64(value) => all.push(HashPart::U64(*value)),
                HashPart::Int(value) => all.push(HashPart::Int(*value)),
                HashPart::Json(value) => all.push(HashPart::Json(value)),
            }
        }
        domain_hash("bridge-delay-cds-id", &all, 16)
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let tranche_id = state
        .seal_tranche(SealTrancheInput {
            risk_kind: BridgeDelayRiskKind::WithdrawalQueueLag,
            seniority: TrancheSeniority::Mezzanine,
            sealed_terms_root: devnet_hash("sealed-terms"),
            buyer_commitment_root: devnet_hash("buyers"),
            seller_commitment_root: devnet_hash("sellers"),
            reference_delay_root: devnet_hash("reference-delay"),
            notional_commitment: 25_000_000_000_000,
            detachment_bps: 6_500,
            maturity_l2_height: DEVNET_L2_HEIGHT + 86_400,
            pq_verifier_root: devnet_hash("pq-verifier"),
            selective_disclosure_root: devnet_hash("selective-disclosure"),
        })
        .expect("devnet tranche");
    state
        .attach_premium_curve(PremiumCurveInput {
            tranche_id: tranche_id.clone(),
            curve_commitment_root: devnet_hash("premium-curve"),
            sealed_rate_ladder_root: devnet_hash("rate-ladder"),
            volatility_hint_root: devnet_hash("volatility"),
            min_premium_bps: 8,
            max_premium_bps: 420,
            current_premium_bps: 64,
            oracle_signature_root: devnet_hash("premium-oracle"),
        })
        .expect("devnet curve");
    let observation_id = state
        .admit_delay_observation(DelayObservationInput {
            risk_kind: BridgeDelayRiskKind::WithdrawalQueueLag,
            source_height: DEVNET_MONERO_HEIGHT - 164,
            destination_height: DEVNET_L2_HEIGHT - 4,
            observed_delay_blocks: 188,
            threshold_delay_blocks: DEFAULT_SOFT_DELAY_BLOCKS,
            attestation_root: devnet_hash("delay-attestation"),
            committee_signature_root: devnet_hash("delay-committee"),
            evidence_root: devnet_hash("delay-evidence"),
        })
        .expect("devnet observation");
    state
        .open_margin_account(MarginAccountInput {
            tranche_id: tranche_id.clone(),
            owner_commitment: devnet_hash("seller-owner"),
            collateral_commitment: devnet_hash("seller-collateral"),
            margin_root: devnet_hash("seller-margin"),
            locked_collateral: 8_500_000_000_000,
            last_mark_bps: 5_800,
        })
        .expect("devnet margin");
    let coupon_id = state
        .mint_claim_coupon(ClaimCouponInput {
            tranche_id,
            observation_id,
            holder_note_commitment: devnet_hash("holder-note"),
            payout_commitment: devnet_hash("payout-note"),
            claim_notional: 2_000_000_000_000,
            coupon_nullifier: devnet_hash("coupon-nullifier"),
            pq_signature_root: devnet_hash("coupon-pq-signature"),
        })
        .expect("devnet coupon");
    state
        .settle_low_fee_batch(SettlementBatchInput {
            window_start: DEVNET_L2_HEIGHT,
            window_end: DEVNET_L2_HEIGHT + DEFAULT_NETTING_WINDOW_BLOCKS,
            coupon_ids: vec![coupon_id],
            debit_commitment_root: devnet_hash("debits"),
            credit_commitment_root: devnet_hash("credits"),
            fee_commitment_root: devnet_hash("fees"),
        })
        .expect("devnet settlement");
    state
}
pub fn state_root(state: &State) -> String {
    let record = json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "chain_id": state.config.chain_id, "market_id": state.config.market_id, "roots": state.roots, "counters": state.counters });
    domain_hash(STATE_ROOT_SUITE, &[HashPart::Json(&record)], 32)
}
pub fn public_record(state: &State) -> Value {
    json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "hash_suite": HASH_SUITE, "roots_only": true, "chain_id": state.config.chain_id, "market_id": state.config.market_id, "bridge_id": state.config.bridge_id, "l2_height": state.config.l2_height, "monero_height": state.config.monero_height, "epoch": state.config.epoch, "state_root": state_root(state), "tranche_root": state.roots.tranche_root, "premium_curve_root": state.roots.premium_curve_root, "observation_root": state.roots.observation_root, "claim_coupon_root": state.roots.claim_coupon_root, "collateral_margin_root": state.roots.collateral_margin_root, "settlement_root": state.roots.settlement_root, "nullifier_root": state.roots.nullifier_root, "payload_root": state.roots.payload_root, "counters": state.counters })
}
fn tranche_leaf(t: &SealedCdsTranche) -> Value {
    json!({ "tranche_id": t.tranche_id, "risk_kind": t.risk_kind.as_str(), "seniority": t.seniority.as_str(), "status": t.status.as_str(), "sealed_terms_root": t.sealed_terms_root, "buyer_commitment_root": t.buyer_commitment_root, "seller_commitment_root": t.seller_commitment_root, "reference_delay_root": t.reference_delay_root, "premium_curve_id": t.premium_curve_id, "notional_commitment": t.notional_commitment.to_string(), "outstanding_protected_notional": t.outstanding_protected_notional.to_string(), "attachment_bps": t.attachment_bps, "detachment_bps": t.detachment_bps, "maturity_l2_height": t.maturity_l2_height, "pq_verifier_root": t.pq_verifier_root, "selective_disclosure_root": t.selective_disclosure_root })
}
fn premium_curve_leaf(c: &PrivatePremiumCurve) -> Value {
    json!({ "curve_id": c.curve_id, "tranche_id": c.tranche_id, "curve_commitment_root": c.curve_commitment_root, "sealed_rate_ladder_root": c.sealed_rate_ladder_root, "volatility_hint_root": c.volatility_hint_root, "min_premium_bps": c.min_premium_bps, "max_premium_bps": c.max_premium_bps, "current_premium_bps": c.current_premium_bps, "rebate_bps": c.rebate_bps, "oracle_signature_root": c.oracle_signature_root })
}
fn observation_leaf(o: &BridgeDelayObservation) -> Value {
    json!({ "observation_id": o.observation_id, "bridge_id": o.bridge_id, "risk_kind": o.risk_kind.as_str(), "status": o.status.as_str(), "source_height": o.source_height, "destination_height": o.destination_height, "observed_delay_blocks": o.observed_delay_blocks, "threshold_delay_blocks": o.threshold_delay_blocks, "severity_bps": o.severity_bps, "attestation_root": o.attestation_root, "committee_signature_root": o.committee_signature_root, "evidence_root": o.evidence_root, "expires_l2_height": o.expires_l2_height })
}
fn coupon_leaf(c: &PqClaimCoupon) -> Value {
    json!({ "coupon_id": c.coupon_id, "tranche_id": c.tranche_id, "observation_id": c.observation_id, "holder_note_commitment": c.holder_note_commitment, "payout_commitment": c.payout_commitment, "status": c.status.as_str(), "delay_blocks": c.delay_blocks, "severity_bps": c.severity_bps, "payout_bps": c.payout_bps, "claim_notional": c.claim_notional.to_string(), "coupon_nullifier": c.coupon_nullifier, "pq_signature_root": c.pq_signature_root, "expires_l2_height": c.expires_l2_height })
}
fn margin_leaf(m: &CollateralMarginAccount) -> Value {
    json!({ "account_id": m.account_id, "tranche_id": m.tranche_id, "owner_commitment": m.owner_commitment, "status": m.status.as_str(), "collateral_commitment": m.collateral_commitment, "margin_root": m.margin_root, "locked_collateral": m.locked_collateral.to_string(), "initial_margin_bps": m.initial_margin_bps, "maintenance_margin_bps": m.maintenance_margin_bps, "last_mark_bps": m.last_mark_bps })
}
fn settlement_leaf(b: &NettedSettlementBatch) -> Value {
    json!({ "batch_id": b.batch_id, "status": b.status.as_str(), "l2_height": b.l2_height, "window_start": b.window_start, "window_end": b.window_end, "tranche_root": b.tranche_root, "coupon_root": b.coupon_root, "margin_root": b.margin_root, "debit_commitment_root": b.debit_commitment_root, "credit_commitment_root": b.credit_commitment_root, "fee_commitment_root": b.fee_commitment_root, "net_payout_commitment": b.net_payout_commitment.to_string(), "net_premium_commitment": b.net_premium_commitment.to_string(), "net_fee_commitment": b.net_fee_commitment.to_string(), "item_count": b.item_count, "settlement_nullifier_root": b.settlement_nullifier_root })
}
fn nullifier_leaf(n: &AntiReplayNullifier) -> Value {
    json!({ "nullifier": n.nullifier, "domain": n.domain, "purpose": n.purpose, "l2_height": n.l2_height, "note_commitment": n.note_commitment })
}
fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}
fn devnet_hash(label: &str) -> String {
    domain_hash(
        "bridge-delay-cds-devnet-fixture",
        &[HashPart::Str(label), HashPart::Str(DEVNET_MARKET_ID)],
        32,
    )
}
fn require_nonempty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}
fn require_bps(value: u64, label: &str) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds max bps"))
    } else {
        Ok(())
    }
}
fn required_margin(notional: u128, margin_bps: u64, multiplier_bps: u64) -> u128 {
    notional
        .saturating_mul(margin_bps as u128)
        .saturating_mul(multiplier_bps as u128)
        / (MAX_BPS as u128 * MAX_BPS as u128)
}
fn compute_payout_bps(
    severity_bps: u64,
    attachment_bps: u64,
    detachment_bps: u64,
    max_payout_bps: u64,
) -> u64 {
    if severity_bps <= attachment_bps {
        0
    } else if severity_bps >= detachment_bps {
        max_payout_bps
    } else {
        let width = detachment_bps.saturating_sub(attachment_bps).max(1);
        let in_band = severity_bps.saturating_sub(attachment_bps);
        max_payout_bps.saturating_mul(in_band) / width
    }
}

pub fn bridge_delay_cds_policy_checkpoint_001(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_001";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_002(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_002";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_003(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_003";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_004(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_004";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_005(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_005";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_006(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_006";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_007(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_007";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_008(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_008";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_009(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_009";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_010(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_010";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_011(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_011";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_012(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_012";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_013(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_013";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_014(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_014";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_015(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_015";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_016(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_016";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_017(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_017";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_018(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_018";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_019(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_019";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_020(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_020";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_021(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_021";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_022(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_022";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_023(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_023";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_024(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_024";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_025(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_025";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_026(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_026";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_027(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_027";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_028(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_028";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_029(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_029";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_030(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_030";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_031(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_031";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_032(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_032";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_033(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_033";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_034(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_034";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_035(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_035";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_036(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_036";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_037(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_037";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_038(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_038";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_039(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_039";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}

pub fn bridge_delay_cds_policy_checkpoint_040(state: &State) -> Value {
    let marker = "bridge_delay_cds_policy_checkpoint_040";
    json!({
        "marker": marker,
        "protocol_version": PROTOCOL_VERSION,
        "roots_only": true,
        "state_root": state.state_root(),
        "tranche_root": state.roots().tranche_root,
        "premium_curve_root": state.roots().premium_curve_root,
        "observation_root": state.roots().observation_root,
        "claim_coupon_root": state.roots().claim_coupon_root,
        "collateral_margin_root": state.roots().collateral_margin_root,
        "settlement_root": state.roots().settlement_root,
        "nullifier_root": state.roots().nullifier_root,
    })
}
