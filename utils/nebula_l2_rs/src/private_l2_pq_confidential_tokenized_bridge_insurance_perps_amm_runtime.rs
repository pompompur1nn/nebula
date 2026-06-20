use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedBridgeInsurancePerpsAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BRIDGE_INSURANCE_PERPS_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-bridge-insurance-perps-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BRIDGE_INSURANCE_PERPS_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-bridge-insurance-perps-claim-coupon-v1";
pub const CONFIDENTIAL_FUNDING_CURVE_SUITE: &str =
    "confidential-tokenized-bridge-insurance-perps-funding-curve-root-v1";
pub const TOKENIZED_INSURANCE_POOL_SUITE: &str =
    "tokenized-confidential-bridge-insurance-perps-amm-pool-root-v1";
pub const POSITION_NOTE_SUITE: &str =
    "sealed-tokenized-bridge-insurance-perps-position-note-root-v1";
pub const COLLATERAL_ROOT_SUITE: &str =
    "privacy-preserving-bridge-insurance-perps-collateral-root-v1";
pub const PREMIUM_ROOT_SUITE: &str = "privacy-preserving-bridge-insurance-perps-premium-root-v1";
pub const CLAIM_COUPON_ROOT_SUITE: &str = "pq-signed-bridge-insurance-perps-claim-coupon-root-v1";
pub const LOW_FEE_NETTING_SUITE: &str =
    "low-fee-bridge-insurance-perps-claim-premium-netting-window-root-v1";
pub const ORACLE_REPORT_SUITE: &str = "pq-confidential-bridge-failure-oracle-report-root-v1";
pub const RISK_BUCKET_SUITE: &str = "tokenized-bridge-insurance-perps-risk-bucket-exposure-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "privacy-preserving-roots-only-bridge-insurance-perps-amm-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-bridge-insurance-perps-amm-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-bridge-insurance-perps-amm-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-bridge-insurance-perps-amm-devnet";
pub const DEVNET_AMM_ID: &str = "private-l2-pq-bridge-insurance-perps-amm-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-private-l2-bridge-insurance-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_126_400;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_732_800;
pub const DEVNET_EPOCH: u64 = 18_240;
pub const DEVNET_INSURANCE_TOKEN_ID: &str = "tbip-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_PREMIUM_ASSET_ID: &str = "nebula-premium-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_LP_FEE_BPS: u64 = 3;
pub const DEFAULT_LOW_FEE_NETTING_BPS: u64 = 1;
pub const DEFAULT_INSURANCE_PREMIUM_BPS: u64 = 12;
pub const DEFAULT_TARGET_NET_CLAIM_FEE_BPS: u64 = 4;
pub const DEFAULT_PREMIUM_REBATE_SHARE_BPS: u64 = 5_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_FUNDING_QUORUM: u16 = 5;
pub const DEFAULT_POSITION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FUNDING_INTERVAL_BLOCKS: u64 = 20;
pub const DEFAULT_NETTING_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_000;
pub const DEFAULT_MIN_PREMIUM_COVERAGE_BPS: u64 = 1_075;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_750;
pub const DEFAULT_MAX_POOL_UTILIZATION_BPS: u64 = 8_250;
pub const DEFAULT_MAX_SKEW_BPS: u64 = 5_500;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 350;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 65;
pub const DEFAULT_MIN_LIQUIDITY_UNITS: u128 = 50_000_000_000;
pub const DEFAULT_MAX_NETTING_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_POOLS: usize = 4_096;
pub const DEFAULT_MAX_POSITIONS: usize = 1_048_576;
pub const DEFAULT_MAX_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_FUNDING_CURVES: usize = 262_144;
pub const DEFAULT_MAX_ORACLE_REPORTS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeRiskKind {
    Reorg,
    DelayedFinality,
    WatchtowerFailure,
    WithdrawalCensorship,
    LiquidityShortfall,
    KeyImageConflict,
    RouterOutage,
    MultichainContagion,
}

impl BridgeRiskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::DelayedFinality => "delayed_finality",
            Self::WatchtowerFailure => "watchtower_failure",
            Self::WithdrawalCensorship => "withdrawal_censorship",
            Self::LiquidityShortfall => "liquidity_shortfall",
            Self::KeyImageConflict => "key_image_conflict",
            Self::RouterOutage => "router_outage",
            Self::MultichainContagion => "multichain_contagion",
        }
    }

    pub fn base_risk_weight_bps(self) -> u64 {
        match self {
            Self::Reorg => 1_150,
            Self::DelayedFinality => 900,
            Self::WatchtowerFailure => 1_050,
            Self::WithdrawalCensorship => 1_250,
            Self::LiquidityShortfall => 1_400,
            Self::KeyImageConflict => 1_700,
            Self::RouterOutage => 1_325,
            Self::MultichainContagion => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongInsurance,
    ShortInsurance,
    LpInsurance,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongInsurance => "long_insurance",
            Self::ShortInsurance => "short_insurance",
            Self::LpInsurance => "lp_insurance",
        }
    }

    pub fn sign(self) -> i128 {
        match self {
            Self::LongInsurance => 1,
            Self::ShortInsurance => -1,
            Self::LpInsurance => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Warmup,
    Active,
    FundingPaused,
    ClaimsOnly,
    ReduceOnly,
    Degraded,
    Draining,
    Settled,
    Retired,
}

impl PoolStatus {
    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(
            self,
            Self::Active | Self::ClaimsOnly | Self::Degraded | Self::Draining
        )
    }

    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Active | Self::ReduceOnly | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Draft,
    Open,
    FundingAccruing,
    Netted,
    ClaimPending,
    ClaimCouponed,
    Settling,
    Settled,
    Liquidated,
    Expired,
    Quarantined,
}

impl PositionStatus {
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::FundingAccruing | Self::Netted | Self::ClaimPending
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
    Settled,
    Redeemed,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingCurveStatus {
    Proposed,
    PqQuorumSigned,
    Active,
    Frozen,
    Superseded,
    Disputed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Open,
    Collecting,
    Frozen,
    Settled,
    PartiallySettled,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleVerdict {
    NoLoss,
    ProbableLoss,
    ConfirmedLoss,
    NeedsReview,
    Rejected,
}

impl OracleVerdict {
    pub fn claimable(self) -> bool {
        matches!(self, Self::ProbableLoss | Self::ConfirmedLoss)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_claim_coupon_suite: String,
    pub confidential_funding_curve_suite: String,
    pub amm_id: String,
    pub bridge_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub insurance_token_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub funding_quorum: u16,
    pub position_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub funding_interval_blocks: u64,
    pub netting_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub low_fee_netting_bps: u64,
    pub insurance_premium_bps: u64,
    pub target_net_claim_fee_bps: u64,
    pub premium_rebate_share_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub min_premium_coverage_bps: u64,
    pub max_payout_bps: u64,
    pub max_pool_utilization_bps: u64,
    pub max_skew_bps: u64,
    pub max_funding_rate_bps: i64,
    pub max_price_impact_bps: u64,
    pub min_liquidity_units: u128,
    pub max_netting_items: usize,
    pub max_pools: usize,
    pub max_positions: usize,
    pub max_coupons: usize,
    pub max_funding_curves: usize,
    pub max_oracle_reports: usize,
    pub require_confidential_notes: bool,
    pub require_pq_claim_coupons: bool,
    pub enable_low_fee_netting: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_coupon_suite: PQ_CLAIM_COUPON_SUITE.to_string(),
            confidential_funding_curve_suite: CONFIDENTIAL_FUNDING_CURVE_SUITE.to_string(),
            amm_id: DEVNET_AMM_ID.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            insurance_token_id: DEVNET_INSURANCE_TOKEN_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            funding_quorum: DEFAULT_FUNDING_QUORUM,
            position_ttl_blocks: DEFAULT_POSITION_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            funding_interval_blocks: DEFAULT_FUNDING_INTERVAL_BLOCKS,
            netting_window_blocks: DEFAULT_NETTING_WINDOW_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            lp_fee_bps: DEFAULT_LP_FEE_BPS,
            low_fee_netting_bps: DEFAULT_LOW_FEE_NETTING_BPS,
            insurance_premium_bps: DEFAULT_INSURANCE_PREMIUM_BPS,
            target_net_claim_fee_bps: DEFAULT_TARGET_NET_CLAIM_FEE_BPS,
            premium_rebate_share_bps: DEFAULT_PREMIUM_REBATE_SHARE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            min_premium_coverage_bps: DEFAULT_MIN_PREMIUM_COVERAGE_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_pool_utilization_bps: DEFAULT_MAX_POOL_UTILIZATION_BPS,
            max_skew_bps: DEFAULT_MAX_SKEW_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            min_liquidity_units: DEFAULT_MIN_LIQUIDITY_UNITS,
            max_netting_items: DEFAULT_MAX_NETTING_ITEMS,
            max_pools: DEFAULT_MAX_POOLS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_funding_curves: DEFAULT_MAX_FUNDING_CURVES,
            max_oracle_reports: DEFAULT_MAX_ORACLE_REPORTS,
            require_confidential_notes: true,
            require_pq_claim_coupons: true,
            enable_low_fee_netting: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("config", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require(!self.chain_id.is_empty(), "chain id is empty")?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "unexpected schema version",
        )?;
        require(!self.amm_id.trim().is_empty(), "amm id is empty")?;
        require(!self.bridge_id.trim().is_empty(), "bridge id is empty")?;
        require(
            !self.insurance_token_id.trim().is_empty(),
            "insurance token id is empty",
        )?;
        require(
            !self.collateral_asset_id.trim().is_empty(),
            "collateral asset id is empty",
        )?;
        require(
            !self.premium_asset_id.trim().is_empty(),
            "premium asset id is empty",
        )?;
        require(
            !self.fee_asset_id.trim().is_empty(),
            "fee asset id is empty",
        )?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "minimum privacy set exceeds target privacy set",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(self.oracle_quorum > 0, "oracle quorum is zero")?;
        require(self.coupon_quorum > 0, "coupon quorum is zero")?;
        require(self.funding_quorum > 0, "funding quorum is zero")?;
        require(self.position_ttl_blocks > 0, "position ttl is zero")?;
        require(self.claim_ttl_blocks > 0, "claim ttl is zero")?;
        require(self.funding_interval_blocks > 0, "funding interval is zero")?;
        require(self.netting_window_blocks > 0, "netting window is zero")?;
        require(
            self.settlement_window_blocks > 0,
            "settlement window is zero",
        )?;
        require_bps("protocol fee bps", self.protocol_fee_bps)?;
        require_bps("lp fee bps", self.lp_fee_bps)?;
        require_bps("low fee netting bps", self.low_fee_netting_bps)?;
        require_bps("insurance premium bps", self.insurance_premium_bps)?;
        require_bps("target net claim fee bps", self.target_net_claim_fee_bps)?;
        require_bps("premium rebate share bps", self.premium_rebate_share_bps)?;
        require_bps(
            "minimum premium coverage bps",
            self.min_premium_coverage_bps,
        )?;
        require_bps("maximum payout bps", self.max_payout_bps)?;
        require_bps("maximum utilization bps", self.max_pool_utilization_bps)?;
        require_bps("maximum skew bps", self.max_skew_bps)?;
        require_bps("maximum price impact bps", self.max_price_impact_bps)?;
        require(
            self.max_funding_rate_bps.unsigned_abs() <= MAX_BPS,
            "funding cap exceeds bps maximum",
        )?;
        require(self.min_liquidity_units > 0, "minimum liquidity is zero")?;
        require(self.max_netting_items > 0, "max netting items is zero")?;
        require(self.max_pools > 0, "max pools is zero")?;
        require(self.max_positions > 0, "max positions is zero")?;
        require(self.max_coupons > 0, "max coupons is zero")?;
        require(self.max_funding_curves > 0, "max funding curves is zero")?;
        require(self.max_oracle_reports > 0, "max oracle reports is zero")
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub positions: u64,
    pub collateral_accounts: u64,
    pub premium_accounts: u64,
    pub funding_curves: u64,
    pub pq_claim_coupons: u64,
    pub oracle_reports: u64,
    pub netting_windows: u64,
    pub risk_buckets: u64,
    pub consumed_nullifiers: u64,
    pub privacy_redactions: u64,
    pub total_open_notional_units: u128,
    pub total_collateral_commitment_units: u128,
    pub total_premium_commitment_units: u128,
    pub total_claim_coupon_units: u128,
    pub total_netted_fee_units: u128,
    pub total_funding_delta_units: i128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pool_root: String,
    pub position_root: String,
    pub collateral_root: String,
    pub premium_root: String,
    pub funding_curve_root: String,
    pub claim_coupon_root: String,
    pub oracle_report_root: String,
    pub netting_window_root: String,
    pub risk_bucket_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeInsurancePool {
    pub pool_id: String,
    pub bridge_id: String,
    pub risk_kind: BridgeRiskKind,
    pub status: PoolStatus,
    pub insurance_token_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub sealed_long_reserve_root: String,
    pub sealed_short_reserve_root: String,
    pub lp_token_commitment_root: String,
    pub invariant_commitment_root: String,
    pub utilization_root: String,
    pub risk_bucket_root: String,
    pub current_funding_curve_id: String,
    pub base_premium_bps: u64,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub max_payout_bps: u64,
    pub liquidity_units: u128,
    pub open_interest_units: u128,
    pub utilization_bps: u64,
    pub skew_bps: i64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl BridgeInsurancePool {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(!self.pool_id.trim().is_empty(), "pool id is empty")?;
        require(
            self.bridge_id == config.bridge_id,
            "pool bridge id mismatch",
        )?;
        require(
            self.insurance_token_id == config.insurance_token_id,
            "pool token mismatch",
        )?;
        require(
            self.collateral_asset_id == config.collateral_asset_id,
            "pool collateral mismatch",
        )?;
        require(
            self.premium_asset_id == config.premium_asset_id,
            "pool premium mismatch",
        )?;
        require(
            self.status.accepts_positions() || self.open_interest_units == 0,
            "inactive pool has open interest",
        )?;
        require_bps("pool base premium", self.base_premium_bps)?;
        require_bps("pool protocol fee", self.protocol_fee_bps)?;
        require_bps("pool lp fee", self.lp_fee_bps)?;
        require_bps("pool max payout", self.max_payout_bps)?;
        require_bps("pool utilization", self.utilization_bps)?;
        require(
            self.utilization_bps <= config.max_pool_utilization_bps,
            "pool utilization exceeds cap",
        )?;
        require(
            self.skew_bps.unsigned_abs() <= config.max_skew_bps,
            "pool skew exceeds cap",
        )?;
        require(
            self.liquidity_units >= config.min_liquidity_units,
            "pool liquidity below minimum",
        )?;
        require(
            self.updated_height >= self.created_height,
            "pool updated before created",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialPositionNote {
    pub position_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub side: PositionSide,
    pub risk_kind: BridgeRiskKind,
    pub notional_units: u128,
    pub collateral_commitment_root: String,
    pub premium_commitment_root: String,
    pub entry_funding_curve_root: String,
    pub liquidation_threshold_root: String,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
    pub opened_height: u64,
    pub last_funding_height: u64,
    pub expiry_height: u64,
    pub leverage_bps: u64,
    pub max_payout_bps: u64,
    pub status: PositionStatus,
}

impl ConfidentialPositionNote {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, pool: &BridgeInsurancePool, config: &Config) -> Result<()> {
        require(!self.position_id.trim().is_empty(), "position id is empty")?;
        require(self.pool_id == pool.pool_id, "position pool mismatch")?;
        require(
            pool.status.accepts_positions() || !self.status.is_open(),
            "pool does not accept open positions",
        )?;
        require(
            self.risk_kind == pool.risk_kind,
            "position risk kind mismatch",
        )?;
        require(self.notional_units > 0, "position notional is zero")?;
        require_bps("position leverage", self.leverage_bps)?;
        require_bps("position max payout", self.max_payout_bps)?;
        require(
            self.max_payout_bps <= config.max_payout_bps,
            "position payout exceeds configured cap",
        )?;
        require(
            self.expiry_height > self.opened_height,
            "position expiry must be after open",
        )?;
        require(
            self.expiry_height - self.opened_height <= config.position_ttl_blocks,
            "position ttl exceeds configured maximum",
        )?;
        require(
            self.last_funding_height >= self.opened_height,
            "position funding height before open",
        )?;
        require_root("owner commitment", &self.owner_commitment)?;
        require_root(
            "collateral commitment root",
            &self.collateral_commitment_root,
        )?;
        require_root("premium commitment root", &self.premium_commitment_root)?;
        require_root("entry funding curve root", &self.entry_funding_curve_root)?;
        require_root("encrypted terms root", &self.encrypted_terms_root)?;
        require_root("nullifier commitment", &self.nullifier_commitment)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralAccount {
    pub account_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub collateral_asset_id: String,
    pub collateral_commitment: String,
    pub locked_liability_commitment: String,
    pub payout_reserve_commitment: String,
    pub coverage_bps: u64,
    pub opened_height: u64,
    pub updated_height: u64,
}

impl CollateralAccount {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PremiumAccount {
    pub account_id: String,
    pub pool_id: String,
    pub payer_commitment: String,
    pub premium_asset_id: String,
    pub premium_commitment: String,
    pub accrued_fee_commitment: String,
    pub rebate_commitment: String,
    pub coverage_bps: u64,
    pub opened_height: u64,
    pub updated_height: u64,
}

impl PremiumAccount {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialFundingCurve {
    pub curve_id: String,
    pub pool_id: String,
    pub risk_kind: BridgeRiskKind,
    pub status: FundingCurveStatus,
    pub epoch: u64,
    pub utilization_curve_root: String,
    pub skew_curve_root: String,
    pub premium_curve_root: String,
    pub payout_curve_root: String,
    pub volatility_oracle_root: String,
    pub bridge_health_root: String,
    pub net_funding_rate_bps: i64,
    pub long_rate_bps: i64,
    pub short_rate_bps: i64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub pq_signature_root: String,
    pub committee_root: String,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl ConfidentialFundingCurve {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, pool: &BridgeInsurancePool, config: &Config) -> Result<()> {
        require(
            !self.curve_id.trim().is_empty(),
            "funding curve id is empty",
        )?;
        require(self.pool_id == pool.pool_id, "funding curve pool mismatch")?;
        require(
            self.risk_kind == pool.risk_kind,
            "funding curve risk mismatch",
        )?;
        require(
            self.net_funding_rate_bps.unsigned_abs() <= config.max_funding_rate_bps.unsigned_abs(),
            "net funding rate exceeds configured cap",
        )?;
        require(
            self.long_rate_bps.unsigned_abs() <= config.max_funding_rate_bps.unsigned_abs(),
            "long funding rate exceeds configured cap",
        )?;
        require(
            self.short_rate_bps.unsigned_abs() <= config.max_funding_rate_bps.unsigned_abs(),
            "short funding rate exceeds configured cap",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require(
            self.expires_height > self.effective_height,
            "funding curve expires before effective height",
        )?;
        require_root("funding pq signature root", &self.pq_signature_root)?;
        require_root("funding committee root", &self.committee_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimCoupon {
    pub coupon_id: String,
    pub position_id: String,
    pub pool_id: String,
    pub risk_kind: BridgeRiskKind,
    pub status: CouponStatus,
    pub claim_nullifier: String,
    pub payout_commitment_root: String,
    pub premium_offset_root: String,
    pub collateral_release_root: String,
    pub oracle_report_id: String,
    pub coupon_quorum_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub payout_units: u128,
    pub net_fee_units: u128,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqClaimCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, position: &ConfidentialPositionNote, config: &Config) -> Result<()> {
        require(!self.coupon_id.trim().is_empty(), "coupon id is empty")?;
        require(
            self.position_id == position.position_id,
            "coupon position mismatch",
        )?;
        require(self.pool_id == position.pool_id, "coupon pool mismatch")?;
        require(self.risk_kind == position.risk_kind, "coupon risk mismatch")?;
        require(self.payout_units > 0, "coupon payout is zero")?;
        require(
            self.expires_height > self.issued_height,
            "coupon expires before issued height",
        )?;
        require(
            self.expires_height - self.issued_height <= config.claim_ttl_blocks,
            "coupon ttl exceeds configured maximum",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require_root("coupon nullifier", &self.claim_nullifier)?;
        require_root("coupon payout root", &self.payout_commitment_root)?;
        require_root("coupon quorum root", &self.coupon_quorum_root)?;
        require_root("coupon pq signature root", &self.pq_signature_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeOracleReport {
    pub report_id: String,
    pub pool_id: String,
    pub risk_kind: BridgeRiskKind,
    pub verdict: OracleVerdict,
    pub event_height: u64,
    pub monero_event_height: u64,
    pub bridge_state_root: String,
    pub watcher_quorum_root: String,
    pub loss_evidence_root: String,
    pub affected_receipt_root: String,
    pub recommended_payout_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub pq_signature_root: String,
    pub issued_height: u64,
}

impl BridgeOracleReport {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, pool: &BridgeInsurancePool, config: &Config) -> Result<()> {
        require(
            !self.report_id.trim().is_empty(),
            "oracle report id is empty",
        )?;
        require(self.pool_id == pool.pool_id, "oracle report pool mismatch")?;
        require(
            self.risk_kind == pool.risk_kind,
            "oracle report risk mismatch",
        )?;
        require_bps("recommended payout bps", self.recommended_payout_bps)?;
        require(
            self.recommended_payout_bps <= config.max_payout_bps,
            "oracle payout exceeds cap",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require_root("bridge state root", &self.bridge_state_root)?;
        require_root("watcher quorum root", &self.watcher_quorum_root)?;
        require_root("loss evidence root", &self.loss_evidence_root)?;
        require_root("oracle pq signature root", &self.pq_signature_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeNettingWindow {
    pub window_id: String,
    pub pool_id: String,
    pub status: NettingStatus,
    pub opens_height: u64,
    pub closes_height: u64,
    pub claim_coupon_root: String,
    pub premium_offset_root: String,
    pub collateral_release_root: String,
    pub funding_delta_root: String,
    pub fee_rebate_root: String,
    pub netted_item_count: usize,
    pub gross_claim_units: u128,
    pub gross_premium_units: u128,
    pub net_fee_units: u128,
    pub target_fee_bps: u64,
}

impl LowFeeNettingWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            !self.window_id.trim().is_empty(),
            "netting window id is empty",
        )?;
        require(
            self.closes_height > self.opens_height,
            "netting window closes before opening",
        )?;
        require(
            self.closes_height - self.opens_height <= config.netting_window_blocks,
            "netting window exceeds configured maximum",
        )?;
        require(
            self.netted_item_count <= config.max_netting_items,
            "netting item count exceeds cap",
        )?;
        require_bps("netting target fee bps", self.target_fee_bps)?;
        require(
            self.target_fee_bps <= config.target_net_claim_fee_bps,
            "netting target fee exceeds configured target",
        )?;
        require_root("netting claim coupon root", &self.claim_coupon_root)?;
        require_root("netting premium offset root", &self.premium_offset_root)?;
        require_root("netting funding delta root", &self.funding_delta_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskBucket {
    pub bucket_id: String,
    pub pool_id: String,
    pub risk_kind: BridgeRiskKind,
    pub bucket_label: String,
    pub exposure_commitment_root: String,
    pub premium_commitment_root: String,
    pub claim_coupon_root: String,
    pub funding_curve_root: String,
    pub utilization_bps: u64,
    pub risk_weight_bps: u64,
    pub active: bool,
}

impl RiskBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPositionInput {
    pub pool_id: String,
    pub owner_commitment: String,
    pub side: PositionSide,
    pub notional_units: u128,
    pub collateral_commitment_root: String,
    pub premium_commitment_root: String,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
    pub leverage_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimCouponInput {
    pub position_id: String,
    pub oracle_report_id: String,
    pub claim_nullifier: String,
    pub payout_commitment_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingCurveInput {
    pub pool_id: String,
    pub utilization_curve_root: String,
    pub skew_curve_root: String,
    pub premium_curve_root: String,
    pub payout_curve_root: String,
    pub net_funding_rate_bps: i64,
    pub long_rate_bps: i64,
    pub short_rate_bps: i64,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingEntryInput {
    pub pool_id: String,
    pub coupon_ids: Vec<String>,
    pub premium_account_ids: Vec<String>,
    pub funding_curve_ids: Vec<String>,
    pub opens_height: u64,
    pub closes_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub current_epoch: u64,
    pub pools: BTreeMap<String, BridgeInsurancePool>,
    pub positions: BTreeMap<String, ConfidentialPositionNote>,
    pub collateral_accounts: BTreeMap<String, CollateralAccount>,
    pub premium_accounts: BTreeMap<String, PremiumAccount>,
    pub funding_curves: BTreeMap<String, ConfidentialFundingCurve>,
    pub claim_coupons: BTreeMap<String, PqClaimCoupon>,
    pub oracle_reports: BTreeMap<String, BridgeOracleReport>,
    pub netting_windows: BTreeMap<String, LowFeeNettingWindow>,
    pub risk_buckets: BTreeMap<String, RiskBucket>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub privacy_redaction_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            current_l2_height: config.l2_height,
            current_monero_height: config.monero_height,
            current_epoch: config.epoch,
            config,
            pools: BTreeMap::new(),
            positions: BTreeMap::new(),
            collateral_accounts: BTreeMap::new(),
            premium_accounts: BTreeMap::new(),
            funding_curves: BTreeMap::new(),
            claim_coupons: BTreeMap::new(),
            oracle_reports: BTreeMap::new(),
            netting_windows: BTreeMap::new(),
            risk_buckets: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            privacy_redaction_roots: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone()).expect("devnet config");
        let pool = demo_pool(&config, "bridge-reorg", BridgeRiskKind::Reorg);
        let curve = demo_funding_curve(&config, &pool, "bridge-reorg");
        let position = demo_position(&config, &pool, &curve, "alice", PositionSide::LongInsurance);
        let collateral = demo_collateral(&config, &pool, "alice");
        let premium = demo_premium(&config, &pool, "alice");
        let report = demo_oracle_report(&config, &pool, "bridge-reorg");
        let coupon = demo_coupon(&config, &position, &report, "alice");
        let netting = demo_netting_window(&config, &pool, &coupon, "bridge-reorg");
        let bucket = demo_risk_bucket(&pool, &curve, "reorg-primary");

        state.insert_pool(pool).expect("devnet pool");
        state
            .insert_funding_curve(curve)
            .expect("devnet funding curve");
        state.insert_position(position).expect("devnet position");
        state
            .insert_collateral_account(collateral)
            .expect("devnet collateral");
        state
            .insert_premium_account(premium)
            .expect("devnet premium");
        state.insert_oracle_report(report).expect("devnet oracle");
        state.insert_claim_coupon(coupon).expect("devnet coupon");
        state
            .insert_netting_window(netting)
            .expect("devnet netting");
        state
            .insert_risk_bucket(bucket)
            .expect("devnet risk bucket");
        state
            .privacy_redaction_roots
            .insert(demo_root("privacy-redaction-root", "devnet"));
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.pools.len() <= self.config.max_pools,
            "pool count exceeds maximum",
        )?;
        require(
            self.positions.len() <= self.config.max_positions,
            "position count exceeds maximum",
        )?;
        require(
            self.claim_coupons.len() <= self.config.max_coupons,
            "claim coupon count exceeds maximum",
        )?;
        require(
            self.funding_curves.len() <= self.config.max_funding_curves,
            "funding curve count exceeds maximum",
        )?;
        require(
            self.oracle_reports.len() <= self.config.max_oracle_reports,
            "oracle report count exceeds maximum",
        )?;
        for pool in self.pools.values() {
            pool.validate(&self.config)?;
        }
        for curve in self.funding_curves.values() {
            let pool = self
                .pools
                .get(&curve.pool_id)
                .ok_or_else(|| format!("missing pool for funding curve {}", curve.curve_id))?;
            curve.validate(pool, &self.config)?;
        }
        for position in self.positions.values() {
            let pool = self
                .pools
                .get(&position.pool_id)
                .ok_or_else(|| format!("missing pool for position {}", position.position_id))?;
            position.validate(pool, &self.config)?;
        }
        for report in self.oracle_reports.values() {
            let pool = self
                .pools
                .get(&report.pool_id)
                .ok_or_else(|| format!("missing pool for oracle report {}", report.report_id))?;
            report.validate(pool, &self.config)?;
        }
        for coupon in self.claim_coupons.values() {
            let position = self
                .positions
                .get(&coupon.position_id)
                .ok_or_else(|| format!("missing position for coupon {}", coupon.coupon_id))?;
            coupon.validate(position, &self.config)?;
            require(
                self.oracle_reports.contains_key(&coupon.oracle_report_id),
                "coupon references unknown oracle report",
            )?;
        }
        for window in self.netting_windows.values() {
            require(
                self.pools.contains_key(&window.pool_id),
                "netting window references unknown pool",
            )?;
            window.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn insert_pool(&mut self, pool: BridgeInsurancePool) -> Result<()> {
        pool.validate(&self.config)?;
        insert_unique(&mut self.pools, pool.pool_id.clone(), pool)
    }

    pub fn insert_position(&mut self, position: ConfidentialPositionNote) -> Result<()> {
        let pool = self
            .pools
            .get(&position.pool_id)
            .ok_or_else(|| "position references unknown pool".to_string())?;
        position.validate(pool, &self.config)?;
        require(
            !self
                .consumed_nullifiers
                .contains(&position.nullifier_commitment),
            "position nullifier already consumed",
        )?;
        self.consumed_nullifiers
            .insert(position.nullifier_commitment.clone());
        insert_unique(&mut self.positions, position.position_id.clone(), position)
    }

    pub fn insert_collateral_account(&mut self, account: CollateralAccount) -> Result<()> {
        require(
            self.pools.contains_key(&account.pool_id),
            "collateral account references unknown pool",
        )?;
        require(
            account.collateral_asset_id == self.config.collateral_asset_id,
            "collateral account asset mismatch",
        )?;
        require_bps("collateral account coverage", account.coverage_bps)?;
        require(
            account.coverage_bps >= self.config.min_collateral_coverage_bps,
            "collateral account below coverage minimum",
        )?;
        require_root("collateral account owner", &account.owner_commitment)?;
        require_root("collateral commitment", &account.collateral_commitment)?;
        insert_unique(
            &mut self.collateral_accounts,
            account.account_id.clone(),
            account,
        )
    }

    pub fn insert_premium_account(&mut self, account: PremiumAccount) -> Result<()> {
        require(
            self.pools.contains_key(&account.pool_id),
            "premium account references unknown pool",
        )?;
        require(
            account.premium_asset_id == self.config.premium_asset_id,
            "premium account asset mismatch",
        )?;
        require_bps("premium account coverage", account.coverage_bps)?;
        require(
            account.coverage_bps >= self.config.min_premium_coverage_bps,
            "premium account below coverage minimum",
        )?;
        require_root("premium payer commitment", &account.payer_commitment)?;
        require_root("premium commitment", &account.premium_commitment)?;
        insert_unique(
            &mut self.premium_accounts,
            account.account_id.clone(),
            account,
        )
    }

    pub fn insert_funding_curve(&mut self, curve: ConfidentialFundingCurve) -> Result<()> {
        let pool = self
            .pools
            .get(&curve.pool_id)
            .ok_or_else(|| "funding curve references unknown pool".to_string())?;
        curve.validate(pool, &self.config)?;
        insert_unique(&mut self.funding_curves, curve.curve_id.clone(), curve)
    }

    pub fn insert_oracle_report(&mut self, report: BridgeOracleReport) -> Result<()> {
        let pool = self
            .pools
            .get(&report.pool_id)
            .ok_or_else(|| "oracle report references unknown pool".to_string())?;
        report.validate(pool, &self.config)?;
        insert_unique(&mut self.oracle_reports, report.report_id.clone(), report)
    }

    pub fn insert_claim_coupon(&mut self, coupon: PqClaimCoupon) -> Result<()> {
        let position = self
            .positions
            .get(&coupon.position_id)
            .ok_or_else(|| "claim coupon references unknown position".to_string())?;
        coupon.validate(position, &self.config)?;
        let report = self
            .oracle_reports
            .get(&coupon.oracle_report_id)
            .ok_or_else(|| "claim coupon references unknown oracle report".to_string())?;
        require(report.verdict.claimable(), "oracle report is not claimable")?;
        require(
            !self.consumed_nullifiers.contains(&coupon.claim_nullifier),
            "claim nullifier already consumed",
        )?;
        self.consumed_nullifiers
            .insert(coupon.claim_nullifier.clone());
        insert_unique(&mut self.claim_coupons, coupon.coupon_id.clone(), coupon)
    }

    pub fn insert_netting_window(&mut self, window: LowFeeNettingWindow) -> Result<()> {
        require(
            self.config.enable_low_fee_netting,
            "low fee netting is disabled",
        )?;
        require(
            self.pools.contains_key(&window.pool_id),
            "netting window references unknown pool",
        )?;
        window.validate(&self.config)?;
        insert_unique(&mut self.netting_windows, window.window_id.clone(), window)
    }

    pub fn insert_risk_bucket(&mut self, bucket: RiskBucket) -> Result<()> {
        let pool = self
            .pools
            .get(&bucket.pool_id)
            .ok_or_else(|| "risk bucket references unknown pool".to_string())?;
        require(
            bucket.risk_kind == pool.risk_kind,
            "risk bucket kind mismatch",
        )?;
        require_bps("risk bucket utilization", bucket.utilization_bps)?;
        require_bps("risk bucket weight", bucket.risk_weight_bps)?;
        require_root("risk exposure root", &bucket.exposure_commitment_root)?;
        insert_unique(&mut self.risk_buckets, bucket.bucket_id.clone(), bucket)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            pools: self.pools.len() as u64,
            positions: self.positions.len() as u64,
            collateral_accounts: self.collateral_accounts.len() as u64,
            premium_accounts: self.premium_accounts.len() as u64,
            funding_curves: self.funding_curves.len() as u64,
            pq_claim_coupons: self.claim_coupons.len() as u64,
            oracle_reports: self.oracle_reports.len() as u64,
            netting_windows: self.netting_windows.len() as u64,
            risk_buckets: self.risk_buckets.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            privacy_redactions: self.privacy_redaction_roots.len() as u64,
            total_open_notional_units: self
                .positions
                .values()
                .filter(|position| position.status.is_open())
                .map(|position| position.notional_units)
                .sum(),
            total_collateral_commitment_units: self
                .collateral_accounts
                .values()
                .map(|account| commitment_weight(&account.collateral_commitment))
                .sum(),
            total_premium_commitment_units: self
                .premium_accounts
                .values()
                .map(|account| commitment_weight(&account.premium_commitment))
                .sum(),
            total_claim_coupon_units: self
                .claim_coupons
                .values()
                .map(|coupon| coupon.payout_units)
                .sum(),
            total_netted_fee_units: self
                .netting_windows
                .values()
                .map(|window| window.net_fee_units)
                .sum(),
            total_funding_delta_units: self
                .funding_curves
                .values()
                .map(|curve| curve.net_funding_rate_bps as i128)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.state_root();
        let pool_root = merkle_root(
            TOKENIZED_INSURANCE_POOL_SUITE,
            &self
                .pools
                .values()
                .map(BridgeInsurancePool::public_record)
                .collect::<Vec<_>>(),
        );
        let position_root = merkle_root(
            POSITION_NOTE_SUITE,
            &self
                .positions
                .values()
                .map(ConfidentialPositionNote::public_record)
                .collect::<Vec<_>>(),
        );
        let collateral_root = merkle_root(
            COLLATERAL_ROOT_SUITE,
            &self
                .collateral_accounts
                .values()
                .map(CollateralAccount::public_record)
                .collect::<Vec<_>>(),
        );
        let premium_root = merkle_root(
            PREMIUM_ROOT_SUITE,
            &self
                .premium_accounts
                .values()
                .map(PremiumAccount::public_record)
                .collect::<Vec<_>>(),
        );
        let funding_curve_root = merkle_root(
            CONFIDENTIAL_FUNDING_CURVE_SUITE,
            &self
                .funding_curves
                .values()
                .map(ConfidentialFundingCurve::public_record)
                .collect::<Vec<_>>(),
        );
        let claim_coupon_root = merkle_root(
            CLAIM_COUPON_ROOT_SUITE,
            &self
                .claim_coupons
                .values()
                .map(PqClaimCoupon::public_record)
                .collect::<Vec<_>>(),
        );
        let oracle_report_root = merkle_root(
            ORACLE_REPORT_SUITE,
            &self
                .oracle_reports
                .values()
                .map(BridgeOracleReport::public_record)
                .collect::<Vec<_>>(),
        );
        let netting_window_root = merkle_root(
            LOW_FEE_NETTING_SUITE,
            &self
                .netting_windows
                .values()
                .map(LowFeeNettingWindow::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_bucket_root = merkle_root(
            RISK_BUCKET_SUITE,
            &self
                .risk_buckets
                .values()
                .map(RiskBucket::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "bridge-insurance-perps-consumed-nullifier-root-v1",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let counters = self.counters();
        let counters_root = payload_root("counters", &counters.public_record());
        let state_root = domain_hash(
            STATE_ROOT_SUITE,
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&pool_root),
                HashPart::Str(&position_root),
                HashPart::Str(&collateral_root),
                HashPart::Str(&premium_root),
                HashPart::Str(&funding_curve_root),
                HashPart::Str(&claim_coupon_root),
                HashPart::Str(&oracle_report_root),
                HashPart::Str(&netting_window_root),
                HashPart::Str(&risk_bucket_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&counters_root),
                HashPart::U64(self.current_l2_height),
                HashPart::U64(self.current_monero_height),
                HashPart::U64(self.current_epoch),
            ],
            32,
        );
        Roots {
            config_root,
            pool_root,
            position_root,
            collateral_root,
            premium_root,
            funding_curve_root,
            claim_coupon_root,
            oracle_report_root,
            netting_window_root,
            risk_bucket_root,
            nullifier_root,
            counters_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_confidential_tokenized_bridge_insurance_perps_amm_runtime_public_record(
) -> Value {
    State::devnet().public_record()
}

pub fn private_l2_pq_confidential_tokenized_bridge_insurance_perps_amm_runtime_state_root() -> String
{
    State::devnet().state_root()
}

fn demo_pool(config: &Config, label: &str, risk_kind: BridgeRiskKind) -> BridgeInsurancePool {
    let liquidity_units = 85_000_000_000;
    let open_interest_units = 18_750_000_000;
    BridgeInsurancePool {
        pool_id: format!("devnet-bridge-insurance-perps-pool-{label}"),
        bridge_id: config.bridge_id.clone(),
        risk_kind,
        status: PoolStatus::Active,
        insurance_token_id: config.insurance_token_id.clone(),
        collateral_asset_id: config.collateral_asset_id.clone(),
        premium_asset_id: config.premium_asset_id.clone(),
        sealed_long_reserve_root: demo_root("sealed-long-reserve", label),
        sealed_short_reserve_root: demo_root("sealed-short-reserve", label),
        lp_token_commitment_root: demo_root("lp-token-commitment", label),
        invariant_commitment_root: demo_root("perps-amm-invariant", label),
        utilization_root: demo_root("pool-utilization", label),
        risk_bucket_root: demo_root("risk-bucket", label),
        current_funding_curve_id: format!("devnet-bridge-insurance-funding-curve-{label}"),
        base_premium_bps: config.insurance_premium_bps + risk_kind.base_risk_weight_bps() / 100,
        protocol_fee_bps: config.protocol_fee_bps,
        lp_fee_bps: config.lp_fee_bps,
        max_payout_bps: config.max_payout_bps,
        liquidity_units,
        open_interest_units,
        utilization_bps: bps(open_interest_units, liquidity_units),
        skew_bps: 420,
        created_height: config.l2_height,
        updated_height: config.l2_height + 3,
    }
}

fn demo_position(
    config: &Config,
    pool: &BridgeInsurancePool,
    curve: &ConfidentialFundingCurve,
    owner: &str,
    side: PositionSide,
) -> ConfidentialPositionNote {
    ConfidentialPositionNote {
        position_id: format!("devnet-bridge-insurance-perps-position-{owner}"),
        pool_id: pool.pool_id.clone(),
        owner_commitment: demo_root("owner-commitment", owner),
        side,
        risk_kind: pool.risk_kind,
        notional_units: 4_200_000_000,
        collateral_commitment_root: demo_root("position-collateral", owner),
        premium_commitment_root: demo_root("position-premium", owner),
        entry_funding_curve_root: payload_root("entry-funding-curve", &curve.public_record()),
        liquidation_threshold_root: demo_root("liquidation-threshold", owner),
        encrypted_terms_root: demo_root("encrypted-perps-terms", owner),
        nullifier_commitment: demo_root("position-nullifier", owner),
        opened_height: config.l2_height + 4,
        last_funding_height: config.l2_height + 8,
        expiry_height: config.l2_height + config.position_ttl_blocks,
        leverage_bps: 4_000,
        max_payout_bps: config.max_payout_bps,
        status: PositionStatus::FundingAccruing,
    }
}

fn demo_collateral(config: &Config, pool: &BridgeInsurancePool, owner: &str) -> CollateralAccount {
    CollateralAccount {
        account_id: format!("devnet-bridge-insurance-collateral-{owner}"),
        pool_id: pool.pool_id.clone(),
        owner_commitment: demo_root("collateral-owner", owner),
        collateral_asset_id: config.collateral_asset_id.clone(),
        collateral_commitment: demo_root("collateral-commitment", owner),
        locked_liability_commitment: demo_root("locked-liability", owner),
        payout_reserve_commitment: demo_root("payout-reserve", owner),
        coverage_bps: config.min_collateral_coverage_bps + 250,
        opened_height: config.l2_height + 1,
        updated_height: config.l2_height + 7,
    }
}

fn demo_premium(config: &Config, pool: &BridgeInsurancePool, owner: &str) -> PremiumAccount {
    PremiumAccount {
        account_id: format!("devnet-bridge-insurance-premium-{owner}"),
        pool_id: pool.pool_id.clone(),
        payer_commitment: demo_root("premium-payer", owner),
        premium_asset_id: config.premium_asset_id.clone(),
        premium_commitment: demo_root("premium-commitment", owner),
        accrued_fee_commitment: demo_root("accrued-fee", owner),
        rebate_commitment: demo_root("premium-rebate", owner),
        coverage_bps: config.min_premium_coverage_bps + 125,
        opened_height: config.l2_height + 1,
        updated_height: config.l2_height + 7,
    }
}

fn demo_funding_curve(
    config: &Config,
    pool: &BridgeInsurancePool,
    label: &str,
) -> ConfidentialFundingCurve {
    ConfidentialFundingCurve {
        curve_id: format!("devnet-bridge-insurance-funding-curve-{label}"),
        pool_id: pool.pool_id.clone(),
        risk_kind: pool.risk_kind,
        status: FundingCurveStatus::Active,
        epoch: config.epoch,
        utilization_curve_root: demo_root("utilization-curve", label),
        skew_curve_root: demo_root("skew-curve", label),
        premium_curve_root: demo_root("premium-curve", label),
        payout_curve_root: demo_root("payout-curve", label),
        volatility_oracle_root: demo_root("volatility-oracle", label),
        bridge_health_root: demo_root("bridge-health", label),
        net_funding_rate_bps: 28,
        long_rate_bps: 34,
        short_rate_bps: -22,
        privacy_set_size: config.target_privacy_set_size,
        pq_security_bits: config.min_pq_security_bits,
        pq_signature_root: demo_root("funding-pq-signature", label),
        committee_root: payload_root(
            "funding-committee",
            &json!({
                "quorum": config.funding_quorum,
                "suite": config.confidential_funding_curve_suite,
            }),
        ),
        effective_height: config.l2_height + 2,
        expires_height: config.l2_height + config.funding_interval_blocks + 2,
    }
}

fn demo_oracle_report(
    config: &Config,
    pool: &BridgeInsurancePool,
    label: &str,
) -> BridgeOracleReport {
    BridgeOracleReport {
        report_id: format!("devnet-bridge-insurance-oracle-report-{label}"),
        pool_id: pool.pool_id.clone(),
        risk_kind: pool.risk_kind,
        verdict: OracleVerdict::ConfirmedLoss,
        event_height: config.l2_height + 12,
        monero_event_height: config.monero_height + 6,
        bridge_state_root: demo_root("bridge-state", label),
        watcher_quorum_root: payload_root(
            "watcher-quorum",
            &json!({
                "bridge_id": config.bridge_id,
                "oracle_quorum": config.oracle_quorum,
            }),
        ),
        loss_evidence_root: demo_root("loss-evidence", label),
        affected_receipt_root: demo_root("affected-receipts", label),
        recommended_payout_bps: 6_250,
        privacy_set_size: config.target_privacy_set_size,
        pq_security_bits: config.min_pq_security_bits,
        pq_signature_root: demo_root("oracle-pq-signature", label),
        issued_height: config.l2_height + 14,
    }
}

fn demo_coupon(
    config: &Config,
    position: &ConfidentialPositionNote,
    report: &BridgeOracleReport,
    owner: &str,
) -> PqClaimCoupon {
    PqClaimCoupon {
        coupon_id: format!("devnet-bridge-insurance-claim-coupon-{owner}"),
        position_id: position.position_id.clone(),
        pool_id: position.pool_id.clone(),
        risk_kind: position.risk_kind,
        status: CouponStatus::PqSigned,
        claim_nullifier: demo_root("claim-nullifier", owner),
        payout_commitment_root: demo_root("claim-payout", owner),
        premium_offset_root: demo_root("premium-offset", owner),
        collateral_release_root: demo_root("collateral-release", owner),
        oracle_report_id: report.report_id.clone(),
        coupon_quorum_root: payload_root(
            "claim-coupon-quorum",
            &json!({
                "coupon_quorum": config.coupon_quorum,
                "report_id": report.report_id,
            }),
        ),
        pq_signature_root: demo_root("claim-coupon-pq-signature", owner),
        privacy_set_size: config.target_privacy_set_size,
        pq_security_bits: config.min_pq_security_bits,
        payout_units: 2_625_000_000,
        net_fee_units: 1_050_000,
        issued_height: report.issued_height + 1,
        expires_height: report.issued_height + config.claim_ttl_blocks,
    }
}

fn demo_netting_window(
    config: &Config,
    pool: &BridgeInsurancePool,
    coupon: &PqClaimCoupon,
    label: &str,
) -> LowFeeNettingWindow {
    LowFeeNettingWindow {
        window_id: format!("devnet-bridge-insurance-netting-window-{label}"),
        pool_id: pool.pool_id.clone(),
        status: NettingStatus::Settled,
        opens_height: coupon.issued_height,
        closes_height: coupon.issued_height + config.netting_window_blocks,
        claim_coupon_root: payload_root("netted-coupon", &coupon.public_record()),
        premium_offset_root: demo_root("netted-premium-offset", label),
        collateral_release_root: demo_root("netted-collateral-release", label),
        funding_delta_root: demo_root("netted-funding-delta", label),
        fee_rebate_root: demo_root("netting-fee-rebate", label),
        netted_item_count: 3,
        gross_claim_units: coupon.payout_units,
        gross_premium_units: 318_000_000,
        net_fee_units: coupon.net_fee_units,
        target_fee_bps: config.target_net_claim_fee_bps,
    }
}

fn demo_risk_bucket(
    pool: &BridgeInsurancePool,
    curve: &ConfidentialFundingCurve,
    label: &str,
) -> RiskBucket {
    RiskBucket {
        bucket_id: format!("devnet-bridge-insurance-risk-bucket-{label}"),
        pool_id: pool.pool_id.clone(),
        risk_kind: pool.risk_kind,
        bucket_label: label.to_string(),
        exposure_commitment_root: demo_root("bucket-exposure", label),
        premium_commitment_root: demo_root("bucket-premium", label),
        claim_coupon_root: demo_root("bucket-claim-coupon", label),
        funding_curve_root: payload_root("bucket-funding-curve", &curve.public_record()),
        utilization_bps: pool.utilization_bps,
        risk_weight_bps: pool.risk_kind.base_risk_weight_bps(),
        active: true,
    }
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!(
        "{}:{}",
        domain.to_ascii_lowercase().replace('_', "-"),
        domain_hash(
            &format!(
                "{}:{}",
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BRIDGE_INSURANCE_PERPS_AMM_RUNTIME_PROTOCOL_VERSION,
                domain
            ),
            parts,
            16,
        )
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    domain_hash(
        &format!("{PAYLOAD_ROOT_SUITE}:devnet:{label}"),
        &[HashPart::Str(salt)],
        32,
    )
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        PAYLOAD_ROOT_SUITE,
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn commitment_weight(root: &str) -> u128 {
    u128::from_str_radix(&root[..16.min(root.len())], 16).unwrap_or(0) % 1_000_000_000
}

fn bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        0
    } else {
        ((numerator.saturating_mul(MAX_BPS as u128)) / denominator) as u64
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(
        value <= MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require(
        value.len() >= 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()),
        &format!("{label} must be a hex commitment/root of at least 32 chars"),
    )
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "privacy set is below configured anonymity threshold",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "PQ authorization security bits below configured minimum",
    )
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    if map.contains_key(&key) {
        Err(format!("duplicate key {key}"))
    } else {
        map.insert(key, value);
        Ok(())
    }
}

#[allow(dead_code)]
fn entry_id(domain: &str, label: &str, height: u64) -> String {
    deterministic_id(domain, &[HashPart::Str(label), HashPart::U64(height)])
}
