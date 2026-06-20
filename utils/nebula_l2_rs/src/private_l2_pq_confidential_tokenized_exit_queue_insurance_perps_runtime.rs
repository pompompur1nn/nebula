use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedExitQueueInsurancePerpsRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_EXIT_QUEUE_INSURANCE_PERPS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-exit-queue-insurance-perps-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_EXIT_QUEUE_INSURANCE_PERPS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-exit-queue-insurance-claim-coupon-v1";
pub const CONFIDENTIAL_FUNDING_CURVE_SUITE: &str =
    "confidential-tokenized-exit-queue-insurance-perps-funding-curve-root-v1";
pub const TOKENIZED_EXIT_QUEUE_MARKET_SUITE: &str =
    "tokenized-confidential-exit-queue-insurance-perps-market-root-v1";
pub const EXIT_QUEUE_NOTE_SUITE: &str =
    "sealed-confidential-exit-queue-insurance-perps-queue-note-root-v1";
pub const POSITION_NOTE_SUITE: &str =
    "sealed-confidential-exit-queue-insurance-perps-position-note-root-v1";
pub const COLLATERAL_ROOT_SUITE: &str =
    "privacy-preserving-exit-queue-insurance-perps-collateral-root-v1";
pub const PREMIUM_ROOT_SUITE: &str =
    "privacy-preserving-exit-queue-insurance-perps-premium-root-v1";
pub const CLAIM_COUPON_ROOT_SUITE: &str =
    "pq-signed-exit-queue-insurance-perps-claim-coupon-root-v1";
pub const LOW_FEE_QUEUE_SETTLEMENT_SUITE: &str =
    "low-fee-confidential-exit-queue-insurance-perps-settlement-root-v1";
pub const QUEUE_ORACLE_REPORT_SUITE: &str = "pq-confidential-exit-queue-oracle-report-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "privacy-preserving-roots-only-exit-queue-insurance-perps-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-exit-queue-insurance-perps-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-exit-queue-insurance-perps-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-exit-queue-insurance-perps-devnet";
pub const DEVNET_RUNTIME_ID: &str = "private-l2-pq-exit-queue-insurance-perps-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_318_720;
pub const DEVNET_MONERO_HEIGHT: u64 = 5_006_400;
pub const DEVNET_EPOCH: u64 = 21_504;
pub const DEVNET_EXIT_QUEUE_ID: &str = "monero-private-l2-exit-queue-devnet";
pub const DEVNET_INSURANCE_TOKEN_ID: &str = "teqip-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_PREMIUM_ASSET_ID: &str = "nebula-premium-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_LOW_FEE_SETTLEMENT_BPS: u64 = 2;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 1;
pub const DEFAULT_PREMIUM_FEE_BPS: u64 = 8;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 1_750;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_FUNDING_QUORUM: u16 = 5;
pub const DEFAULT_POSITION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_FUNDING_INTERVAL_BLOCKS: u64 = 20;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_QUEUE_OBSERVATION_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_250;
pub const DEFAULT_MIN_PREMIUM_COVERAGE_BPS: u64 = 1_100;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_750;
pub const DEFAULT_MAX_QUEUE_UTILIZATION_BPS: u64 = 8_500;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 400;
pub const DEFAULT_MAX_WAIT_BLOCKS: u64 = 720;
pub const DEFAULT_FAST_EXIT_TARGET_BLOCKS: u64 = 30;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 4_096;
pub const DEFAULT_MAX_MARKETS: usize = 131_072;
pub const DEFAULT_MAX_QUEUE_NOTES: usize = 1_048_576;
pub const DEFAULT_MAX_POSITIONS: usize = 1_048_576;
pub const DEFAULT_MAX_FUNDING_CURVES: usize = 262_144;
pub const DEFAULT_MAX_CLAIM_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 262_144;
pub const DEFAULT_MAX_ORACLE_REPORTS: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitQueueRiskKind {
    WithdrawalDelay,
    QueueCensorship,
    LiquidityShortfall,
    SequencerHalt,
    FinalityDelay,
    BridgeExitCongestion,
    EmergencyEscape,
    FeeSpike,
}

impl ExitQueueRiskKind {
    pub fn base_weight_bps(self) -> u64 {
        match self {
            Self::WithdrawalDelay => 950,
            Self::QueueCensorship => 1_400,
            Self::LiquidityShortfall => 1_650,
            Self::SequencerHalt => 1_250,
            Self::FinalityDelay => 1_050,
            Self::BridgeExitCongestion => 1_300,
            Self::EmergencyEscape => 1_850,
            Self::FeeSpike => 825,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongQueueProtection,
    ShortQueueProtection,
    QueueBackstop,
    PremiumMaker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Draft,
    Active,
    FundingOnly,
    ClaimsOnly,
    QueueGuarded,
    ReduceOnly,
    Halted,
    Settled,
    Retired,
}

impl MarketStatus {
    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Active | Self::QueueGuarded)
    }

    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Active | Self::FundingOnly | Self::ReduceOnly)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::ClaimsOnly | Self::QueueGuarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueNoteStatus {
    Committed,
    Observed,
    Delayed,
    Matched,
    Claimed,
    Settled,
    Expired,
    Quarantined,
}

impl QueueNoteStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Observed | Self::Delayed | Self::Matched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    Open,
    FundingAccruing,
    QueueObserved,
    ClaimPending,
    Couponed,
    Settling,
    Settled,
    Liquidated,
    Expired,
    Quarantined,
}

impl PositionStatus {
    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::FundingAccruing
                | Self::QueueObserved
                | Self::ClaimPending
                | Self::Couponed
                | Self::Settling
        )
    }
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
pub enum CouponStatus {
    Draft,
    PqSigned,
    Admitted,
    Netted,
    SettlementQueued,
    Settled,
    Redeemed,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Collecting,
    Proving,
    Posted,
    PartiallySettled,
    Settled,
    Rejected,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleVerdict {
    QueueHealthy,
    DelayProbable,
    DelayConfirmed,
    CensorshipConfirmed,
    LiquidityShortfall,
    NeedsReview,
    Rejected,
}

impl OracleVerdict {
    pub fn claimable(self) -> bool {
        matches!(
            self,
            Self::DelayProbable
                | Self::DelayConfirmed
                | Self::CensorshipConfirmed
                | Self::LiquidityShortfall
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub runtime_id: String,
    pub exit_queue_id: String,
    pub insurance_token_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_claim_coupon_suite: String,
    pub confidential_funding_curve_suite: String,
    pub low_fee_queue_settlement_suite: String,
    pub replay_domain: String,
    pub low_fee_settlement_bps: u64,
    pub protocol_fee_bps: u64,
    pub premium_fee_bps: u64,
    pub maker_rebate_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub min_premium_coverage_bps: u64,
    pub max_payout_bps: u64,
    pub max_queue_utilization_bps: u64,
    pub max_funding_rate_bps: i64,
    pub max_wait_blocks: u64,
    pub fast_exit_target_blocks: u64,
    pub funding_interval_blocks: u64,
    pub position_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub queue_observation_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub funding_quorum: u16,
    pub low_fee_batch_limit: usize,
    pub max_markets: usize,
    pub max_queue_notes: usize,
    pub max_positions: usize,
    pub max_funding_curves: usize,
    pub max_claim_coupons: usize,
    pub max_settlements: usize,
    pub max_oracle_reports: usize,
    pub max_nullifiers: usize,
    pub require_confidential_notes: bool,
    pub require_pq_claim_coupons: bool,
    pub enable_low_fee_queue_settlement: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            exit_queue_id: DEVNET_EXIT_QUEUE_ID.to_string(),
            insurance_token_id: DEVNET_INSURANCE_TOKEN_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_coupon_suite: PQ_CLAIM_COUPON_SUITE.to_string(),
            confidential_funding_curve_suite: CONFIDENTIAL_FUNDING_CURVE_SUITE.to_string(),
            low_fee_queue_settlement_suite: LOW_FEE_QUEUE_SETTLEMENT_SUITE.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            low_fee_settlement_bps: DEFAULT_LOW_FEE_SETTLEMENT_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            premium_fee_bps: DEFAULT_PREMIUM_FEE_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            min_premium_coverage_bps: DEFAULT_MIN_PREMIUM_COVERAGE_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_queue_utilization_bps: DEFAULT_MAX_QUEUE_UTILIZATION_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            max_wait_blocks: DEFAULT_MAX_WAIT_BLOCKS,
            fast_exit_target_blocks: DEFAULT_FAST_EXIT_TARGET_BLOCKS,
            funding_interval_blocks: DEFAULT_FUNDING_INTERVAL_BLOCKS,
            position_ttl_blocks: DEFAULT_POSITION_TTL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            queue_observation_window_blocks: DEFAULT_QUEUE_OBSERVATION_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            funding_quorum: DEFAULT_FUNDING_QUORUM,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_markets: DEFAULT_MAX_MARKETS,
            max_queue_notes: DEFAULT_MAX_QUEUE_NOTES,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_funding_curves: DEFAULT_MAX_FUNDING_CURVES,
            max_claim_coupons: DEFAULT_MAX_CLAIM_COUPONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_oracle_reports: DEFAULT_MAX_ORACLE_REPORTS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            require_confidential_notes: true,
            require_pq_claim_coupons: true,
            enable_low_fee_queue_settlement: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol_version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema_version mismatch",
        )?;
        require(self.chain_id == CHAIN_ID, "chain_id mismatch")?;
        require_nonempty("runtime_id", &self.runtime_id)?;
        require_nonempty("exit_queue_id", &self.exit_queue_id)?;
        require_nonempty("insurance_token_id", &self.insurance_token_id)?;
        require_nonempty("collateral_asset_id", &self.collateral_asset_id)?;
        require_nonempty("premium_asset_id", &self.premium_asset_id)?;
        require_nonempty("fee_asset_id", &self.fee_asset_id)?;
        for (label, value) in [
            ("low_fee_settlement_bps", self.low_fee_settlement_bps),
            ("protocol_fee_bps", self.protocol_fee_bps),
            ("premium_fee_bps", self.premium_fee_bps),
            ("maker_rebate_bps", self.maker_rebate_bps),
            (
                "min_collateral_coverage_bps",
                self.min_collateral_coverage_bps,
            ),
            ("min_premium_coverage_bps", self.min_premium_coverage_bps),
            ("max_payout_bps", self.max_payout_bps),
            ("max_queue_utilization_bps", self.max_queue_utilization_bps),
        ] {
            require_bps(label, value)?;
        }
        require(
            self.max_funding_rate_bps.unsigned_abs() <= MAX_BPS,
            "funding cap exceeds bps",
        )?;
        require(self.max_wait_blocks > 0, "max_wait_blocks must be positive")?;
        require(
            self.fast_exit_target_blocks > 0
                && self.fast_exit_target_blocks <= self.max_wait_blocks,
            "fast exit target must be positive and below max wait",
        )?;
        require(
            self.funding_interval_blocks > 0,
            "funding_interval_blocks is zero",
        )?;
        require(self.position_ttl_blocks > 0, "position_ttl_blocks is zero")?;
        require(self.claim_ttl_blocks > 0, "claim_ttl_blocks is zero")?;
        require(
            self.settlement_window_blocks > 0,
            "settlement_window_blocks is zero",
        )?;
        require(
            self.queue_observation_window_blocks > 0,
            "queue_observation_window_blocks is zero",
        )?;
        require(
            self.min_privacy_set_size > 0
                && self.target_privacy_set_size >= self.min_privacy_set_size,
            "invalid privacy set sizes",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "min_pq_security_bits below runtime floor",
        )?;
        require(self.oracle_quorum > 0, "oracle_quorum is zero")?;
        require(self.coupon_quorum > 0, "coupon_quorum is zero")?;
        require(self.funding_quorum > 0, "funding_quorum is zero")?;
        require(self.low_fee_batch_limit > 0, "low_fee_batch_limit is zero")?;
        require(
            self.max_markets > 0 && self.max_queue_notes > 0,
            "market or queue capacity is zero",
        )?;
        require(
            self.max_positions > 0 && self.max_claim_coupons > 0,
            "position or coupon capacity is zero",
        )?;
        require(
            self.max_settlements > 0 && self.max_oracle_reports > 0,
            "settlement or oracle capacity is zero",
        )?;
        require(
            self.max_funding_curves > 0 && self.max_nullifiers > 0,
            "funding curve or nullifier capacity is zero",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub queue_notes: u64,
    pub positions: u64,
    pub funding_curves: u64,
    pub pq_claim_coupons: u64,
    pub low_fee_settlements: u64,
    pub oracle_reports: u64,
    pub collateral_roots: u64,
    pub premium_roots: u64,
    pub consumed_nullifiers: u64,
    pub public_summaries: u64,
    pub active_queue_notes: u64,
    pub open_positions: u64,
    pub claimable_coupons: u64,
    pub total_queue_liability_units: u128,
    pub total_open_notional_units: u128,
    pub total_collateral_commitment_units: u128,
    pub total_premium_commitment_units: u128,
    pub total_claim_commitment_units: u128,
    pub total_settlement_fee_units: u128,
    pub net_funding_rate_bps: i128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        payload_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub markets_root: String,
    pub queue_notes_root: String,
    pub positions_root: String,
    pub funding_curves_root: String,
    pub claim_coupons_root: String,
    pub settlements_root: String,
    pub oracle_reports_root: String,
    pub collateral_root: String,
    pub premium_root: String,
    pub nullifiers_root: String,
    pub public_summaries_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        let counters = Counters::default();
        let counters_root = counters.state_root();
        let mut roots = Self {
            config_root: config.state_root(),
            markets_root: empty_root(TOKENIZED_EXIT_QUEUE_MARKET_SUITE),
            queue_notes_root: empty_root(EXIT_QUEUE_NOTE_SUITE),
            positions_root: empty_root(POSITION_NOTE_SUITE),
            funding_curves_root: empty_root(CONFIDENTIAL_FUNDING_CURVE_SUITE),
            claim_coupons_root: empty_root(CLAIM_COUPON_ROOT_SUITE),
            settlements_root: empty_root(LOW_FEE_QUEUE_SETTLEMENT_SUITE),
            oracle_reports_root: empty_root(QUEUE_ORACLE_REPORT_SUITE),
            collateral_root: empty_root(COLLATERAL_ROOT_SUITE),
            premium_root: empty_root(PREMIUM_ROOT_SUITE),
            nullifiers_root: empty_root("exit_queue_insurance_nullifiers"),
            public_summaries_root: empty_root("exit_queue_insurance_public_summaries"),
            counters_root,
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root(0, 0, 0);
        roots
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn compute_state_root(&self, l2_height: u64, monero_height: u64, epoch: u64) -> String {
        domain_hash(
            STATE_ROOT_SUITE,
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.markets_root),
                HashPart::Str(&self.queue_notes_root),
                HashPart::Str(&self.positions_root),
                HashPart::Str(&self.funding_curves_root),
                HashPart::Str(&self.claim_coupons_root),
                HashPart::Str(&self.settlements_root),
                HashPart::Str(&self.oracle_reports_root),
                HashPart::Str(&self.collateral_root),
                HashPart::Str(&self.premium_root),
                HashPart::Str(&self.nullifiers_root),
                HashPart::Str(&self.public_summaries_root),
                HashPart::Str(&self.counters_root),
                HashPart::U64(l2_height),
                HashPart::U64(monero_height),
                HashPart::U64(epoch),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitQueueMarket {
    pub market_id: String,
    pub exit_queue_id: String,
    pub risk_kind: ExitQueueRiskKind,
    pub status: MarketStatus,
    pub insurance_token_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub queue_commitment_root: String,
    pub collateral_pool_root: String,
    pub premium_pool_root: String,
    pub funding_curve_root: String,
    pub oracle_committee_root: String,
    pub backstop_commitment_root: String,
    pub base_premium_bps: u64,
    pub protocol_fee_bps: u64,
    pub max_payout_bps: u64,
    pub max_wait_blocks: u64,
    pub fast_exit_target_blocks: u64,
    pub queue_utilization_bps: u64,
    pub open_interest_units: u128,
    pub queue_liability_units: u128,
    pub created_height: u64,
    pub updated_height: u64,
}

impl ExitQueueMarket {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("market_id", &self.market_id)?;
        require_nonempty("exit_queue_id", &self.exit_queue_id)?;
        require_nonempty("insurance_token_id", &self.insurance_token_id)?;
        for (label, root) in [
            ("queue_commitment_root", &self.queue_commitment_root),
            ("collateral_pool_root", &self.collateral_pool_root),
            ("premium_pool_root", &self.premium_pool_root),
            ("funding_curve_root", &self.funding_curve_root),
            ("oracle_committee_root", &self.oracle_committee_root),
            ("backstop_commitment_root", &self.backstop_commitment_root),
        ] {
            require_root(label, root)?;
        }
        require_bps("base_premium_bps", self.base_premium_bps)?;
        require_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("max_payout_bps", self.max_payout_bps)?;
        require_bps("queue_utilization_bps", self.queue_utilization_bps)?;
        require(
            self.queue_utilization_bps <= config.max_queue_utilization_bps,
            "queue utilization exceeds configured cap",
        )?;
        require(
            self.max_wait_blocks <= config.max_wait_blocks,
            "market max wait exceeds config",
        )?;
        require(
            self.fast_exit_target_blocks > 0
                && self.fast_exit_target_blocks <= self.max_wait_blocks,
            "market fast exit target is invalid",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitQueueNote {
    pub queue_note_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub status: QueueNoteStatus,
    pub exit_intent_root: String,
    pub queue_position_commitment_root: String,
    pub withdrawal_note_root: String,
    pub settlement_asset_id: String,
    pub queued_amount_commitment_units: u128,
    pub protected_amount_commitment_units: u128,
    pub observed_wait_blocks: u64,
    pub max_wait_blocks: u64,
    pub priority_fee_commitment_root: String,
    pub viewing_key_commitment: String,
    pub nullifier: String,
    pub committed_height: u64,
    pub observed_height: u64,
    pub expires_height: u64,
}

impl ExitQueueNote {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("queue_note_id", &self.queue_note_id)?;
        require_nonempty("market_id", &self.market_id)?;
        for (label, root) in [
            ("owner_commitment", &self.owner_commitment),
            ("exit_intent_root", &self.exit_intent_root),
            (
                "queue_position_commitment_root",
                &self.queue_position_commitment_root,
            ),
            ("withdrawal_note_root", &self.withdrawal_note_root),
            (
                "priority_fee_commitment_root",
                &self.priority_fee_commitment_root,
            ),
            ("viewing_key_commitment", &self.viewing_key_commitment),
            ("nullifier", &self.nullifier),
        ] {
            require_root(label, root)?;
        }
        require_nonzero_u128(
            "queued_amount_commitment_units",
            self.queued_amount_commitment_units,
        )?;
        require(
            self.protected_amount_commitment_units <= self.queued_amount_commitment_units,
            "protected amount exceeds queued amount",
        )?;
        require(
            self.max_wait_blocks <= config.max_wait_blocks,
            "queue note max wait exceeds configured cap",
        )?;
        require(
            self.expires_height > self.committed_height,
            "queue note expires before commitment",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialPosition {
    pub position_id: String,
    pub market_id: String,
    pub queue_note_id: String,
    pub owner_commitment: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub notional_units: u128,
    pub collateral_commitment_units: u128,
    pub premium_commitment_units: u128,
    pub entry_funding_curve_root: String,
    pub last_funding_curve_root: String,
    pub liquidation_threshold_root: String,
    pub collateral_note_root: String,
    pub premium_note_root: String,
    pub encrypted_terms_root: String,
    pub viewing_key_commitment: String,
    pub nullifier: String,
    pub opened_height: u64,
    pub last_funding_height: u64,
    pub expires_height: u64,
}

impl ConfidentialPosition {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("position_id", &self.position_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_nonempty("queue_note_id", &self.queue_note_id)?;
        require_nonzero_u128("notional_units", self.notional_units)?;
        require_nonzero_u128(
            "collateral_commitment_units",
            self.collateral_commitment_units,
        )?;
        require_nonzero_u128("premium_commitment_units", self.premium_commitment_units)?;
        for (label, root) in [
            ("owner_commitment", &self.owner_commitment),
            ("entry_funding_curve_root", &self.entry_funding_curve_root),
            ("last_funding_curve_root", &self.last_funding_curve_root),
            (
                "liquidation_threshold_root",
                &self.liquidation_threshold_root,
            ),
            ("collateral_note_root", &self.collateral_note_root),
            ("premium_note_root", &self.premium_note_root),
            ("encrypted_terms_root", &self.encrypted_terms_root),
            ("viewing_key_commitment", &self.viewing_key_commitment),
            ("nullifier", &self.nullifier),
        ] {
            require_root(label, root)?;
        }
        require(
            self.expires_height <= self.opened_height + config.position_ttl_blocks,
            "position expiry exceeds configured ttl",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialFundingCurve {
    pub curve_id: String,
    pub market_id: String,
    pub status: FundingCurveStatus,
    pub epoch: u64,
    pub queue_depth_curve_root: String,
    pub wait_time_curve_root: String,
    pub premium_curve_root: String,
    pub payout_curve_root: String,
    pub fee_pressure_curve_root: String,
    pub oracle_report_id: String,
    pub long_rate_bps: i64,
    pub short_rate_bps: i64,
    pub backstop_rate_bps: i64,
    pub net_funding_rate_bps: i64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub pq_signature_root: String,
    pub committee_root: String,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl ConfidentialFundingCurve {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("curve_id", &self.curve_id)?;
        require_nonempty("market_id", &self.market_id)?;
        for (label, root) in [
            ("queue_depth_curve_root", &self.queue_depth_curve_root),
            ("wait_time_curve_root", &self.wait_time_curve_root),
            ("premium_curve_root", &self.premium_curve_root),
            ("payout_curve_root", &self.payout_curve_root),
            ("fee_pressure_curve_root", &self.fee_pressure_curve_root),
            ("pq_signature_root", &self.pq_signature_root),
            ("committee_root", &self.committee_root),
        ] {
            require_root(label, root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require(
            self.net_funding_rate_bps.unsigned_abs() <= config.max_funding_rate_bps.unsigned_abs(),
            "net funding rate exceeds configured cap",
        )?;
        require(
            self.expires_height > self.effective_height,
            "funding curve expires too early",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueOracleReport {
    pub report_id: String,
    pub market_id: String,
    pub queue_note_id: String,
    pub risk_kind: ExitQueueRiskKind,
    pub verdict: OracleVerdict,
    pub l2_event_height: u64,
    pub monero_event_height: u64,
    pub queue_state_root: String,
    pub queue_depth_root: String,
    pub wait_time_evidence_root: String,
    pub liquidity_evidence_root: String,
    pub watcher_quorum_root: String,
    pub recommended_payout_bps: u64,
    pub observed_wait_blocks: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub pq_signature_root: String,
    pub issued_height: u64,
}

impl QueueOracleReport {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("report_id", &self.report_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_nonempty("queue_note_id", &self.queue_note_id)?;
        for (label, root) in [
            ("queue_state_root", &self.queue_state_root),
            ("queue_depth_root", &self.queue_depth_root),
            ("wait_time_evidence_root", &self.wait_time_evidence_root),
            ("liquidity_evidence_root", &self.liquidity_evidence_root),
            ("watcher_quorum_root", &self.watcher_quorum_root),
            ("pq_signature_root", &self.pq_signature_root),
        ] {
            require_root(label, root)?;
        }
        require_bps("recommended_payout_bps", self.recommended_payout_bps)?;
        require(
            self.recommended_payout_bps <= config.max_payout_bps,
            "recommended payout exceeds configured cap",
        )?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimCoupon {
    pub coupon_id: String,
    pub market_id: String,
    pub position_id: String,
    pub queue_note_id: String,
    pub oracle_report_id: String,
    pub status: CouponStatus,
    pub claim_nullifier: String,
    pub payout_commitment_root: String,
    pub premium_offset_root: String,
    pub collateral_release_root: String,
    pub queue_delay_evidence_root: String,
    pub coupon_quorum_root: String,
    pub pq_signature_root: String,
    pub payout_units: u128,
    pub net_fee_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqClaimCoupon {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("coupon_id", &self.coupon_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_nonempty("position_id", &self.position_id)?;
        require_nonempty("queue_note_id", &self.queue_note_id)?;
        require_nonempty("oracle_report_id", &self.oracle_report_id)?;
        for (label, root) in [
            ("claim_nullifier", &self.claim_nullifier),
            ("payout_commitment_root", &self.payout_commitment_root),
            ("premium_offset_root", &self.premium_offset_root),
            ("collateral_release_root", &self.collateral_release_root),
            ("queue_delay_evidence_root", &self.queue_delay_evidence_root),
            ("coupon_quorum_root", &self.coupon_quorum_root),
            ("pq_signature_root", &self.pq_signature_root),
        ] {
            require_root(label, root)?;
        }
        require_nonzero_u128("payout_units", self.payout_units)?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        require(
            self.expires_height > self.issued_height,
            "coupon expires before issue",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeQueueSettlement {
    pub settlement_id: String,
    pub market_id: String,
    pub status: SettlementStatus,
    pub queue_note_ids: Vec<String>,
    pub position_ids: Vec<String>,
    pub coupon_ids: Vec<String>,
    pub low_fee_proof_root: String,
    pub queue_delta_root: String,
    pub collateral_delta_root: String,
    pub premium_delta_root: String,
    pub payout_delta_root: String,
    pub fee_rebate_root: String,
    pub settled_item_count: u64,
    pub gross_claim_units: u128,
    pub gross_premium_units: u128,
    pub net_collateral_units: u128,
    pub net_fee_units: u128,
    pub target_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub settled_height: Option<u64>,
}

impl LowFeeQueueSettlement {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("settlement_id", &self.settlement_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require(
            !self.queue_note_ids.is_empty()
                || !self.position_ids.is_empty()
                || !self.coupon_ids.is_empty(),
            "settlement must include at least one item",
        )?;
        require(
            self.queue_note_ids.len() + self.position_ids.len() + self.coupon_ids.len()
                <= config.low_fee_batch_limit,
            "settlement exceeds low fee batch limit",
        )?;
        for (label, root) in [
            ("low_fee_proof_root", &self.low_fee_proof_root),
            ("queue_delta_root", &self.queue_delta_root),
            ("collateral_delta_root", &self.collateral_delta_root),
            ("premium_delta_root", &self.premium_delta_root),
            ("payout_delta_root", &self.payout_delta_root),
            ("fee_rebate_root", &self.fee_rebate_root),
        ] {
            require_root(label, root)?;
        }
        require_bps("target_fee_bps", self.target_fee_bps)?;
        require(
            self.target_fee_bps <= config.low_fee_settlement_bps,
            "target settlement fee exceeds configured low fee cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "settlement privacy set below floor",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicSummary {
    pub summary_id: String,
    pub height: u64,
    pub markets: u64,
    pub active_queue_notes: u64,
    pub open_positions: u64,
    pub claimable_coupons: u64,
    pub low_fee_settlements: u64,
    pub collateral_root: String,
    pub premium_root: String,
    pub queue_notes_root: String,
    pub claim_coupon_root: String,
    pub settlement_root: String,
    pub state_root: String,
}

impl PublicSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterMarketInput {
    pub market: ExitQueueMarket,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitQueueNoteInput {
    pub queue_note: ExitQueueNote,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenPositionInput {
    pub position: ConfidentialPosition,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishFundingCurveInput {
    pub curve: ConfidentialFundingCurve,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishOracleReportInput {
    pub report: QueueOracleReport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdmitClaimCouponInput {
    pub coupon: PqClaimCoupon,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleLowFeeQueueInput {
    pub settlement: LowFeeQueueSettlement,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub markets: BTreeMap<String, ExitQueueMarket>,
    pub queue_notes: BTreeMap<String, ExitQueueNote>,
    pub positions: BTreeMap<String, ConfidentialPosition>,
    pub funding_curves: BTreeMap<String, ConfidentialFundingCurve>,
    pub oracle_reports: BTreeMap<String, QueueOracleReport>,
    pub claim_coupons: BTreeMap<String, PqClaimCoupon>,
    pub settlements: BTreeMap<String, LowFeeQueueSettlement>,
    pub collateral_roots: BTreeMap<String, String>,
    pub premium_roots: BTreeMap<String, String>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_summaries: BTreeMap<String, PublicSummary>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            l2_height,
            monero_height,
            epoch,
            markets: BTreeMap::new(),
            queue_notes: BTreeMap::new(),
            positions: BTreeMap::new(),
            funding_curves: BTreeMap::new(),
            oracle_reports: BTreeMap::new(),
            claim_coupons: BTreeMap::new(),
            settlements: BTreeMap::new(),
            collateral_roots: BTreeMap::new(),
            premium_roots: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_summaries: BTreeMap::new(),
            counters: Counters::default(),
            roots,
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self::new(config, DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT, DEVNET_EPOCH)
            .expect("devnet config is valid")
    }

    pub fn register_market(&mut self, input: RegisterMarketInput) -> Result<String> {
        input.market.validate(&self.config)?;
        ensure_capacity("markets", self.markets.len(), self.config.max_markets)?;
        let market_id = input.market.market_id.clone();
        insert_unique(&mut self.markets, market_id, input.market)?;
        self.refresh();
        Ok(self.state_root())
    }

    pub fn commit_queue_note(&mut self, input: CommitQueueNoteInput) -> Result<String> {
        input.queue_note.validate(&self.config)?;
        ensure_capacity(
            "queue_notes",
            self.queue_notes.len(),
            self.config.max_queue_notes,
        )?;
        require(
            self.markets.contains_key(&input.queue_note.market_id),
            "queue note references unknown market",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&input.queue_note.nullifier),
            "queue note nullifier already consumed",
        )?;
        let queue_note_id = input.queue_note.queue_note_id.clone();
        self.consumed_nullifiers
            .insert(input.queue_note.nullifier.clone());
        insert_unique(&mut self.queue_notes, queue_note_id, input.queue_note)?;
        self.refresh();
        Ok(self.state_root())
    }

    pub fn open_position(&mut self, input: OpenPositionInput) -> Result<String> {
        input.position.validate(&self.config)?;
        ensure_capacity("positions", self.positions.len(), self.config.max_positions)?;
        let market = self
            .markets
            .get(&input.position.market_id)
            .ok_or_else(|| "position references unknown market".to_string())?;
        require(
            market.status.accepts_positions(),
            "market does not accept exit queue insurance positions",
        )?;
        require(
            self.queue_notes.contains_key(&input.position.queue_note_id),
            "position references unknown queue note",
        )?;
        require(
            !self.consumed_nullifiers.contains(&input.position.nullifier),
            "position nullifier already consumed",
        )?;
        let position_id = input.position.position_id.clone();
        self.consumed_nullifiers
            .insert(input.position.nullifier.clone());
        self.collateral_roots.insert(
            position_id.clone(),
            input.position.collateral_note_root.clone(),
        );
        self.premium_roots.insert(
            position_id.clone(),
            input.position.premium_note_root.clone(),
        );
        insert_unique(&mut self.positions, position_id, input.position)?;
        self.refresh();
        Ok(self.state_root())
    }

    pub fn publish_funding_curve(&mut self, input: PublishFundingCurveInput) -> Result<String> {
        input.curve.validate(&self.config)?;
        ensure_capacity(
            "funding_curves",
            self.funding_curves.len(),
            self.config.max_funding_curves,
        )?;
        let market = self
            .markets
            .get(&input.curve.market_id)
            .ok_or_else(|| "funding curve references unknown market".to_string())?;
        require(
            market.status.accepts_funding(),
            "market does not accept funding curves",
        )?;
        if !input.curve.oracle_report_id.is_empty() {
            require(
                self.oracle_reports
                    .contains_key(&input.curve.oracle_report_id),
                "funding curve references unknown oracle report",
            )?;
        }
        let curve_id = input.curve.curve_id.clone();
        insert_unique(&mut self.funding_curves, curve_id, input.curve)?;
        self.refresh();
        Ok(self.state_root())
    }

    pub fn publish_oracle_report(&mut self, input: PublishOracleReportInput) -> Result<String> {
        input.report.validate(&self.config)?;
        ensure_capacity(
            "oracle_reports",
            self.oracle_reports.len(),
            self.config.max_oracle_reports,
        )?;
        require(
            self.markets.contains_key(&input.report.market_id),
            "oracle report references unknown market",
        )?;
        require(
            self.queue_notes.contains_key(&input.report.queue_note_id),
            "oracle report references unknown queue note",
        )?;
        let report_id = input.report.report_id.clone();
        insert_unique(&mut self.oracle_reports, report_id, input.report)?;
        self.refresh();
        Ok(self.state_root())
    }

    pub fn admit_claim_coupon(&mut self, input: AdmitClaimCouponInput) -> Result<String> {
        input.coupon.validate(&self.config)?;
        ensure_capacity(
            "claim_coupons",
            self.claim_coupons.len(),
            self.config.max_claim_coupons,
        )?;
        let market = self
            .markets
            .get(&input.coupon.market_id)
            .ok_or_else(|| "claim coupon references unknown market".to_string())?;
        require(
            market.status.accepts_claims(),
            "market does not accept claim coupons",
        )?;
        require(
            self.positions.contains_key(&input.coupon.position_id),
            "claim coupon references unknown position",
        )?;
        require(
            self.queue_notes.contains_key(&input.coupon.queue_note_id),
            "claim coupon references unknown queue note",
        )?;
        let report = self
            .oracle_reports
            .get(&input.coupon.oracle_report_id)
            .ok_or_else(|| "claim coupon references unknown oracle report".to_string())?;
        require(report.verdict.claimable(), "oracle report is not claimable")?;
        require(
            !self
                .consumed_nullifiers
                .contains(&input.coupon.claim_nullifier),
            "claim coupon nullifier already consumed",
        )?;
        let coupon_id = input.coupon.coupon_id.clone();
        self.consumed_nullifiers
            .insert(input.coupon.claim_nullifier.clone());
        insert_unique(&mut self.claim_coupons, coupon_id, input.coupon)?;
        self.refresh();
        Ok(self.state_root())
    }

    pub fn settle_low_fee_queue(&mut self, input: SettleLowFeeQueueInput) -> Result<String> {
        input.settlement.validate(&self.config)?;
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        require(
            self.markets.contains_key(&input.settlement.market_id),
            "settlement references unknown market",
        )?;
        for queue_note_id in &input.settlement.queue_note_ids {
            require(
                self.queue_notes.contains_key(queue_note_id),
                &format!("settlement references unknown queue note {queue_note_id}"),
            )?;
        }
        for position_id in &input.settlement.position_ids {
            require(
                self.positions.contains_key(position_id),
                &format!("settlement references unknown position {position_id}"),
            )?;
        }
        for coupon_id in &input.settlement.coupon_ids {
            require(
                self.claim_coupons.contains_key(coupon_id),
                &format!("settlement references unknown claim coupon {coupon_id}"),
            )?;
        }
        let settlement_id = input.settlement.settlement_id.clone();
        for queue_note_id in &input.settlement.queue_note_ids {
            if let Some(note) = self.queue_notes.get_mut(queue_note_id) {
                note.status = QueueNoteStatus::Settled;
            }
        }
        for position_id in &input.settlement.position_ids {
            if let Some(position) = self.positions.get_mut(position_id) {
                position.status = PositionStatus::Settled;
            }
        }
        for coupon_id in &input.settlement.coupon_ids {
            if let Some(coupon) = self.claim_coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Settled;
            }
        }
        self.collateral_roots.insert(
            format!("settlement:{settlement_id}:collateral_delta"),
            input.settlement.collateral_delta_root.clone(),
        );
        self.premium_roots.insert(
            format!("settlement:{settlement_id}:premium_delta"),
            input.settlement.premium_delta_root.clone(),
        );
        insert_unique(&mut self.settlements, settlement_id, input.settlement)?;
        self.refresh();
        Ok(self.state_root())
    }

    pub fn publish_public_summary(&mut self, summary_id: String, height: u64) -> Result<String> {
        require_nonempty("summary_id", &summary_id)?;
        let roots = self.roots();
        let counters = self.counters();
        let summary = PublicSummary {
            summary_id: summary_id.clone(),
            height,
            markets: counters.markets,
            active_queue_notes: counters.active_queue_notes,
            open_positions: counters.open_positions,
            claimable_coupons: counters.claimable_coupons,
            low_fee_settlements: counters.low_fee_settlements,
            collateral_root: roots.collateral_root,
            premium_root: roots.premium_root,
            queue_notes_root: roots.queue_notes_root,
            claim_coupon_root: roots.claim_coupons_root,
            settlement_root: roots.settlements_root,
            state_root: self.state_root(),
        };
        self.public_summaries.insert(summary_id, summary);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            markets: self.markets.len() as u64,
            queue_notes: self.queue_notes.len() as u64,
            positions: self.positions.len() as u64,
            funding_curves: self.funding_curves.len() as u64,
            pq_claim_coupons: self.claim_coupons.len() as u64,
            low_fee_settlements: self
                .settlements
                .values()
                .filter(|settlement| settlement.status == SettlementStatus::Settled)
                .count() as u64,
            oracle_reports: self.oracle_reports.len() as u64,
            collateral_roots: self.collateral_roots.len() as u64,
            premium_roots: self.premium_roots.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            public_summaries: self.public_summaries.len() as u64,
            active_queue_notes: self
                .queue_notes
                .values()
                .filter(|note| note.status.active())
                .count() as u64,
            open_positions: self
                .positions
                .values()
                .filter(|position| position.status.open())
                .count() as u64,
            claimable_coupons: self
                .claim_coupons
                .values()
                .filter(|coupon| {
                    matches!(
                        coupon.status,
                        CouponStatus::Admitted
                            | CouponStatus::Netted
                            | CouponStatus::SettlementQueued
                    )
                })
                .count() as u64,
            total_queue_liability_units: self
                .queue_notes
                .values()
                .map(|note| note.protected_amount_commitment_units)
                .fold(0_u128, u128::saturating_add),
            total_open_notional_units: self
                .positions
                .values()
                .filter(|position| position.status.open())
                .map(|position| position.notional_units)
                .fold(0_u128, u128::saturating_add),
            total_collateral_commitment_units: self
                .positions
                .values()
                .map(|position| position.collateral_commitment_units)
                .fold(0_u128, u128::saturating_add),
            total_premium_commitment_units: self
                .positions
                .values()
                .map(|position| position.premium_commitment_units)
                .fold(0_u128, u128::saturating_add),
            total_claim_commitment_units: self
                .claim_coupons
                .values()
                .map(|coupon| coupon.payout_units)
                .fold(0_u128, u128::saturating_add),
            total_settlement_fee_units: self
                .settlements
                .values()
                .map(|settlement| settlement.net_fee_units)
                .fold(0_u128, u128::saturating_add),
            net_funding_rate_bps: self
                .funding_curves
                .values()
                .map(|curve| curve.net_funding_rate_bps as i128)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: self.config.state_root(),
            markets_root: map_public_root(
                TOKENIZED_EXIT_QUEUE_MARKET_SUITE,
                &self.markets,
                ExitQueueMarket::public_record,
            ),
            queue_notes_root: map_public_root(
                EXIT_QUEUE_NOTE_SUITE,
                &self.queue_notes,
                ExitQueueNote::public_record,
            ),
            positions_root: map_public_root(
                POSITION_NOTE_SUITE,
                &self.positions,
                ConfidentialPosition::public_record,
            ),
            funding_curves_root: map_public_root(
                CONFIDENTIAL_FUNDING_CURVE_SUITE,
                &self.funding_curves,
                ConfidentialFundingCurve::public_record,
            ),
            claim_coupons_root: map_public_root(
                CLAIM_COUPON_ROOT_SUITE,
                &self.claim_coupons,
                PqClaimCoupon::public_record,
            ),
            settlements_root: map_public_root(
                LOW_FEE_QUEUE_SETTLEMENT_SUITE,
                &self.settlements,
                LowFeeQueueSettlement::public_record,
            ),
            oracle_reports_root: map_public_root(
                QUEUE_ORACLE_REPORT_SUITE,
                &self.oracle_reports,
                QueueOracleReport::public_record,
            ),
            collateral_root: map_root(COLLATERAL_ROOT_SUITE, &self.collateral_roots),
            premium_root: map_root(PREMIUM_ROOT_SUITE, &self.premium_roots),
            nullifiers_root: set_root("exit_queue_insurance_nullifiers", &self.consumed_nullifiers),
            public_summaries_root: map_public_root(
                "exit_queue_insurance_public_summaries",
                &self.public_summaries,
                PublicSummary::public_record,
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root(self.l2_height, self.monero_height, self.epoch);
        roots
    }

    pub fn refresh(&mut self) {
        self.counters = self.counters();
        self.roots = self.roots();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "state_root_suite": STATE_ROOT_SUITE,
            "chain_id": self.config.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

pub fn private_l2_pq_confidential_tokenized_exit_queue_insurance_perps_runtime_public_record(
) -> Value {
    public_record()
}

pub fn private_l2_pq_confidential_tokenized_exit_queue_insurance_perps_runtime_state_root() -> String
{
    state_root()
}

fn map_public_root<T, F>(label: &str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": f(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn map_root(label: &str, map: &BTreeMap<String, String>) -> String {
    let leaves = map
        .iter()
        .map(|(key, root)| {
            json!({
                "label": label,
                "key": key,
                "root": root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn empty_root(label: &str) -> String {
    merkle_root(label, &[])
}

fn demo_root(label: &str, salt: &str) -> String {
    domain_hash(
        &format!("{PAYLOAD_ROOT_SUITE}:devnet:{label}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(salt)],
        32,
    )
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        PAYLOAD_ROOT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(value),
        ],
        32,
    )
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Some(object) = record.as_object_mut() {
        object.insert(key.to_string(), value);
    }
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    if map.contains_key(&key) {
        Err(format!("duplicate key {key}"))
    } else {
        map.insert(key, value);
        Ok(())
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require(
        value.len() >= 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()),
        &format!("{label} must be a hex commitment/root of at least 32 chars"),
    )
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(value <= MAX_BPS, &format!("{label} exceeds MAX_BPS"))
}

fn require_nonzero_u128(label: &str, value: u128) -> Result<()> {
    require(value > 0, &format!("{label} must be positive"))
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
