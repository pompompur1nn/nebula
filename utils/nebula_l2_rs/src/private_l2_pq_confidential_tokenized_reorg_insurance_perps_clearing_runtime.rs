use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedReorgInsurancePerpsClearingRuntimeResult<T> = Result<T>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_REORG_INSURANCE_PERPS_CLEARING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-reorg-insurance-perps-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_REORG_INSURANCE_PERPS_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-reorg-insurance-claim-coupon-v1";
pub const CONFIDENTIAL_FUNDING_CURVE_SUITE: &str =
    "confidential-tokenized-reorg-insurance-perps-funding-curve-root-v1";
pub const COLLATERAL_ROOT_SUITE: &str =
    "privacy-preserving-reorg-insurance-perps-collateral-root-v1";
pub const PREMIUM_ROOT_SUITE: &str = "privacy-preserving-reorg-insurance-perps-premium-root-v1";
pub const CLAIM_COUPON_ROOT_SUITE: &str = "pq-signed-reorg-insurance-perps-claim-coupon-root-v1";
pub const LOW_FEE_CLEARING_SUITE: &str =
    "low-fee-confidential-reorg-insurance-perps-clearing-batch-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "privacy-preserving-roots-only-reorg-insurance-perps-clearing-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-reorg-insurance-perps-clearing-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-reorg-insurance-perps-clearing-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-reorg-insurance-perps-clearing-devnet";
pub const DEVNET_CLEARING_ID: &str = "private-l2-pq-reorg-insurance-perps-clearing-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_220_800;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_861_120;
pub const DEVNET_EPOCH: u64 = 20_160;
pub const DEVNET_REORG_TOKEN_ID: &str = "trip-reorg-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_PREMIUM_ASSET_ID: &str = "nebula-premium-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_LOW_FEE_CLEARING_BPS: u64 = 2;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 1;
pub const DEFAULT_PREMIUM_FEE_BPS: u64 = 7;
pub const DEFAULT_FUNDING_INTERVAL_BLOCKS: u64 = 20;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_NETTING_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_FUNDING_QUORUM: u16 = 5;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_500;
pub const DEFAULT_MIN_PREMIUM_COVERAGE_BPS: u64 = 1_100;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_500;
pub const DEFAULT_MAX_POOL_UTILIZATION_BPS: u64 = 8_000;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 300;
pub const DEFAULT_MAX_REORG_DEPTH: u16 = 128;
pub const DEFAULT_FINALITY_GRACE_BLOCKS: u64 = 18;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 4_096;
pub const DEFAULT_MAX_MARKETS: usize = 262_144;
pub const DEFAULT_MAX_POSITIONS: usize = 1_048_576;
pub const DEFAULT_MAX_FUNDING_CURVES: usize = 262_144;
pub const DEFAULT_MAX_CLAIM_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_CLEARING_BATCHES: usize = 262_144;
pub const DEFAULT_MAX_ORACLE_REPORTS: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgRiskKind {
    ShallowReorg,
    DeepReorg,
    FinalityRegression,
    SequencerRollback,
    BridgeReplay,
    CheckpointInvalidation,
    CrossDomainDispute,
    EmergencyHalt,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongProtection,
    ShortProtection,
    ClearingBackstop,
    PremiumMaker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Draft,
    Active,
    FundingOnly,
    ClaimsOnly,
    ReduceOnly,
    OracleGuarded,
    Halted,
    Settled,
    Retired,
}

impl MarketStatus {
    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Active | Self::OracleGuarded)
    }

    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Active | Self::FundingOnly | Self::ReduceOnly)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::ClaimsOnly | Self::OracleGuarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    Open,
    FundingAccruing,
    Netted,
    ClaimPending,
    Couponed,
    Settling,
    Settled,
    Liquidated,
    Expired,
    Quarantined,
}

impl PositionStatus {
    pub fn counts_open(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::FundingAccruing
                | Self::Netted
                | Self::ClaimPending
                | Self::Couponed
                | Self::Settling
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
    Clearing,
    Settled,
    Redeemed,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBatchStatus {
    Draft,
    Collecting,
    Proving,
    Posted,
    Settled,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub clearing_id: String,
    pub reorg_token_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_claim_coupon_suite: String,
    pub confidential_funding_curve_suite: String,
    pub low_fee_clearing_suite: String,
    pub replay_domain: String,
    pub low_fee_clearing_bps: u64,
    pub protocol_fee_bps: u64,
    pub premium_fee_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub min_premium_coverage_bps: u64,
    pub max_payout_bps: u64,
    pub max_pool_utilization_bps: u64,
    pub max_funding_rate_bps: i64,
    pub max_reorg_depth: u16,
    pub finality_grace_blocks: u64,
    pub funding_interval_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub netting_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub funding_quorum: u16,
    pub low_fee_batch_limit: usize,
    pub max_markets: usize,
    pub max_positions: usize,
    pub max_funding_curves: usize,
    pub max_claim_coupons: usize,
    pub max_clearing_batches: usize,
    pub max_oracle_reports: usize,
    pub max_nullifiers: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            clearing_id: DEVNET_CLEARING_ID.to_string(),
            reorg_token_id: DEVNET_REORG_TOKEN_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_coupon_suite: PQ_CLAIM_COUPON_SUITE.to_string(),
            confidential_funding_curve_suite: CONFIDENTIAL_FUNDING_CURVE_SUITE.to_string(),
            low_fee_clearing_suite: LOW_FEE_CLEARING_SUITE.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            low_fee_clearing_bps: DEFAULT_LOW_FEE_CLEARING_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            premium_fee_bps: DEFAULT_PREMIUM_FEE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            min_premium_coverage_bps: DEFAULT_MIN_PREMIUM_COVERAGE_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_pool_utilization_bps: DEFAULT_MAX_POOL_UTILIZATION_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            max_reorg_depth: DEFAULT_MAX_REORG_DEPTH,
            finality_grace_blocks: DEFAULT_FINALITY_GRACE_BLOCKS,
            funding_interval_blocks: DEFAULT_FUNDING_INTERVAL_BLOCKS,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            netting_window_blocks: DEFAULT_NETTING_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            funding_quorum: DEFAULT_FUNDING_QUORUM,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_markets: DEFAULT_MAX_MARKETS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_funding_curves: DEFAULT_MAX_FUNDING_CURVES,
            max_claim_coupons: DEFAULT_MAX_CLAIM_COUPONS,
            max_clearing_batches: DEFAULT_MAX_CLEARING_BATCHES,
            max_oracle_reports: DEFAULT_MAX_ORACLE_REPORTS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol_version mismatch".to_string());
        }
        require_nonempty("chain_id", &self.chain_id)?;
        require_nonempty("clearing_id", &self.clearing_id)?;
        require_nonempty("reorg_token_id", &self.reorg_token_id)?;
        require_nonempty("collateral_asset_id", &self.collateral_asset_id)?;
        require_nonempty("premium_asset_id", &self.premium_asset_id)?;
        require_nonempty("fee_asset_id", &self.fee_asset_id)?;
        require_bps("low_fee_clearing_bps", self.low_fee_clearing_bps)?;
        require_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("premium_fee_bps", self.premium_fee_bps)?;
        require_bps(
            "min_collateral_coverage_bps",
            self.min_collateral_coverage_bps,
        )?;
        require_bps("min_premium_coverage_bps", self.min_premium_coverage_bps)?;
        require_bps("max_payout_bps", self.max_payout_bps)?;
        require_bps("max_pool_utilization_bps", self.max_pool_utilization_bps)?;
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("invalid privacy set sizes".to_string());
        }
        if self.max_reorg_depth == 0 {
            return Err("max_reorg_depth must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "clearing_id": self.clearing_id,
            "reorg_token_id": self.reorg_token_id,
            "collateral_asset_id": self.collateral_asset_id,
            "premium_asset_id": self.premium_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_claim_coupon_suite": self.pq_claim_coupon_suite,
            "confidential_funding_curve_suite": self.confidential_funding_curve_suite,
            "low_fee_clearing_suite": self.low_fee_clearing_suite,
            "replay_domain": self.replay_domain,
            "low_fee_clearing_bps": self.low_fee_clearing_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "premium_fee_bps": self.premium_fee_bps,
            "min_collateral_coverage_bps": self.min_collateral_coverage_bps,
            "min_premium_coverage_bps": self.min_premium_coverage_bps,
            "max_payout_bps": self.max_payout_bps,
            "max_pool_utilization_bps": self.max_pool_utilization_bps,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "max_reorg_depth": self.max_reorg_depth,
            "finality_grace_blocks": self.finality_grace_blocks,
            "funding_interval_blocks": self.funding_interval_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "netting_window_blocks": self.netting_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "oracle_quorum": self.oracle_quorum,
            "coupon_quorum": self.coupon_quorum,
            "funding_quorum": self.funding_quorum,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "max_markets": self.max_markets,
            "max_positions": self.max_positions,
            "max_funding_curves": self.max_funding_curves,
            "max_claim_coupons": self.max_claim_coupons,
            "max_clearing_batches": self.max_clearing_batches,
            "max_oracle_reports": self.max_oracle_reports,
            "max_nullifiers": self.max_nullifiers,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub positions: u64,
    pub funding_curves: u64,
    pub claim_coupons: u64,
    pub clearing_batches: u64,
    pub oracle_reports: u64,
    pub premium_ledgers: u64,
    pub collateral_ledgers: u64,
    pub public_summaries: u64,
    pub nullifiers: u64,
    pub low_fee_settlements: u64,
    pub total_notional: u128,
    pub total_collateral_commitments: u128,
    pub total_premium_commitments: u128,
    pub total_claim_commitments: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets,
            "positions": self.positions,
            "funding_curves": self.funding_curves,
            "claim_coupons": self.claim_coupons,
            "clearing_batches": self.clearing_batches,
            "oracle_reports": self.oracle_reports,
            "premium_ledgers": self.premium_ledgers,
            "collateral_ledgers": self.collateral_ledgers,
            "public_summaries": self.public_summaries,
            "nullifiers": self.nullifiers,
            "low_fee_settlements": self.low_fee_settlements,
            "total_notional": self.total_notional,
            "total_collateral_commitments": self.total_collateral_commitments,
            "total_premium_commitments": self.total_premium_commitments,
            "total_claim_commitments": self.total_claim_commitments,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub markets_root: String,
    pub positions_root: String,
    pub funding_curves_root: String,
    pub claim_coupons_root: String,
    pub clearing_batches_root: String,
    pub oracle_reports_root: String,
    pub collateral_root: String,
    pub premium_root: String,
    pub nullifiers_root: String,
    pub public_summaries_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            markets_root: empty_root("markets"),
            positions_root: empty_root("positions"),
            funding_curves_root: empty_root("funding_curves"),
            claim_coupons_root: empty_root("claim_coupons"),
            clearing_batches_root: empty_root("clearing_batches"),
            oracle_reports_root: empty_root("oracle_reports"),
            collateral_root: empty_root(COLLATERAL_ROOT_SUITE),
            premium_root: empty_root(PREMIUM_ROOT_SUITE),
            nullifiers_root: empty_root("nullifiers"),
            public_summaries_root: empty_root("public_summaries"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "markets_root": self.markets_root,
            "positions_root": self.positions_root,
            "funding_curves_root": self.funding_curves_root,
            "claim_coupons_root": self.claim_coupons_root,
            "clearing_batches_root": self.clearing_batches_root,
            "oracle_reports_root": self.oracle_reports_root,
            "collateral_root": self.collateral_root,
            "premium_root": self.premium_root,
            "nullifiers_root": self.nullifiers_root,
            "public_summaries_root": self.public_summaries_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReorgMarket {
    pub market_id: String,
    pub risk_kind: ReorgRiskKind,
    pub status: MarketStatus,
    pub settlement_asset_id: String,
    pub collateral_pool_root: String,
    pub premium_pool_root: String,
    pub funding_curve_root: String,
    pub oracle_committee_root: String,
    pub max_reorg_depth: u16,
    pub finality_depth: u64,
    pub insurance_horizon_blocks: u64,
    pub base_premium_bps: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl ReorgMarket {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("market_id", &self.market_id)?;
        require_nonempty("settlement_asset_id", &self.settlement_asset_id)?;
        require_root("collateral_pool_root", &self.collateral_pool_root)?;
        require_root("premium_pool_root", &self.premium_pool_root)?;
        require_root("funding_curve_root", &self.funding_curve_root)?;
        require_root("oracle_committee_root", &self.oracle_committee_root)?;
        require_bps("base_premium_bps", self.base_premium_bps)?;
        if self.max_reorg_depth == 0 || self.max_reorg_depth > config.max_reorg_depth {
            return Err("market max_reorg_depth outside config bound".to_string());
        }
        if self.finality_depth == 0 {
            return Err("market finality_depth must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "risk_kind": self.risk_kind,
            "status": self.status,
            "settlement_asset_id": self.settlement_asset_id,
            "collateral_pool_root": self.collateral_pool_root,
            "premium_pool_root": self.premium_pool_root,
            "funding_curve_root": self.funding_curve_root,
            "oracle_committee_root": self.oracle_committee_root,
            "max_reorg_depth": self.max_reorg_depth,
            "finality_depth": self.finality_depth,
            "insurance_horizon_blocks": self.insurance_horizon_blocks,
            "base_premium_bps": self.base_premium_bps,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PositionNote {
    pub position_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub notional_commitment: u128,
    pub collateral_commitment: u128,
    pub premium_commitment: u128,
    pub entry_funding_index: i128,
    pub last_funding_index: i128,
    pub liquidation_threshold_bps: u64,
    pub collateral_note_root: String,
    pub premium_note_root: String,
    pub viewing_key_commitment: String,
    pub nullifier: String,
    pub opened_height: u64,
    pub updated_height: u64,
}

impl PositionNote {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("position_id", &self.position_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_nonempty("owner_commitment", &self.owner_commitment)?;
        require_nonzero_u128("notional_commitment", self.notional_commitment)?;
        require_nonzero_u128("collateral_commitment", self.collateral_commitment)?;
        require_root("collateral_note_root", &self.collateral_note_root)?;
        require_root("premium_note_root", &self.premium_note_root)?;
        require_nonempty("viewing_key_commitment", &self.viewing_key_commitment)?;
        require_nonempty("nullifier", &self.nullifier)?;
        require_bps("liquidation_threshold_bps", self.liquidation_threshold_bps)?;
        let required = apply_bps_up(self.notional_commitment, config.min_collateral_coverage_bps);
        if self.collateral_commitment < required {
            return Err("position collateral below confidential coverage floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side,
            "status": self.status,
            "notional_commitment": self.notional_commitment,
            "collateral_commitment": self.collateral_commitment,
            "premium_commitment": self.premium_commitment,
            "entry_funding_index": self.entry_funding_index,
            "last_funding_index": self.last_funding_index,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "collateral_note_root": self.collateral_note_root,
            "premium_note_root": self.premium_note_root,
            "viewing_key_commitment": self.viewing_key_commitment,
            "nullifier": self.nullifier,
            "opened_height": self.opened_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FundingCurve {
    pub curve_id: String,
    pub market_id: String,
    pub status: MarketStatus,
    pub curve_root: String,
    pub sealed_slope_commitment: String,
    pub sealed_intercept_commitment: String,
    pub utilization_commitment: String,
    pub premium_skew_commitment: String,
    pub funding_rate_bps: i64,
    pub funding_index: i128,
    pub oracle_report_id: String,
    pub pq_signature_root: String,
    pub effective_height: u64,
    pub expires_height: u64,
}

impl FundingCurve {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("curve_id", &self.curve_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_root("curve_root", &self.curve_root)?;
        require_nonempty("sealed_slope_commitment", &self.sealed_slope_commitment)?;
        require_nonempty(
            "sealed_intercept_commitment",
            &self.sealed_intercept_commitment,
        )?;
        require_nonempty("utilization_commitment", &self.utilization_commitment)?;
        require_nonempty("premium_skew_commitment", &self.premium_skew_commitment)?;
        require_nonempty("oracle_report_id", &self.oracle_report_id)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        if self.funding_rate_bps.abs() > config.max_funding_rate_bps {
            return Err("funding_rate_bps exceeds configured bound".to_string());
        }
        if self.expires_height <= self.effective_height {
            return Err("funding curve expires before it becomes effective".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "curve_id": self.curve_id,
            "market_id": self.market_id,
            "status": self.status,
            "curve_root": self.curve_root,
            "sealed_slope_commitment": self.sealed_slope_commitment,
            "sealed_intercept_commitment": self.sealed_intercept_commitment,
            "utilization_commitment": self.utilization_commitment,
            "premium_skew_commitment": self.premium_skew_commitment,
            "funding_rate_bps": self.funding_rate_bps,
            "funding_index": self.funding_index,
            "oracle_report_id": self.oracle_report_id,
            "pq_signature_root": self.pq_signature_root,
            "effective_height": self.effective_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimCoupon {
    pub coupon_id: String,
    pub market_id: String,
    pub position_id: String,
    pub status: CouponStatus,
    pub claim_event_root: String,
    pub claim_amount_commitment: u128,
    pub payout_asset_id: String,
    pub reorg_depth: u16,
    pub canonical_height: u64,
    pub orphaned_height: u64,
    pub pq_authorization_root: String,
    pub claimant_note_root: String,
    pub coupon_nullifier: String,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl ClaimCoupon {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("coupon_id", &self.coupon_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_nonempty("position_id", &self.position_id)?;
        require_root("claim_event_root", &self.claim_event_root)?;
        require_nonzero_u128("claim_amount_commitment", self.claim_amount_commitment)?;
        require_nonempty("payout_asset_id", &self.payout_asset_id)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_root("claimant_note_root", &self.claimant_note_root)?;
        require_nonempty("coupon_nullifier", &self.coupon_nullifier)?;
        if self.reorg_depth == 0 || self.reorg_depth > config.max_reorg_depth {
            return Err("coupon reorg_depth outside config bound".to_string());
        }
        if self.expires_height <= self.issued_height {
            return Err("claim coupon expires before issue height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "status": self.status,
            "claim_event_root": self.claim_event_root,
            "claim_amount_commitment": self.claim_amount_commitment,
            "payout_asset_id": self.payout_asset_id,
            "reorg_depth": self.reorg_depth,
            "canonical_height": self.canonical_height,
            "orphaned_height": self.orphaned_height,
            "pq_authorization_root": self.pq_authorization_root,
            "claimant_note_root": self.claimant_note_root,
            "coupon_nullifier": self.coupon_nullifier,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub market_id: String,
    pub status: ClearingBatchStatus,
    pub position_ids: Vec<String>,
    pub coupon_ids: Vec<String>,
    pub low_fee_proof_root: String,
    pub collateral_delta_root: String,
    pub premium_delta_root: String,
    pub claim_payout_root: String,
    pub fee_commitment: u128,
    pub net_premium_commitment: u128,
    pub net_collateral_commitment: u128,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub settled_height: Option<u64>,
}

impl ClearingBatch {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("batch_id", &self.batch_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_root("low_fee_proof_root", &self.low_fee_proof_root)?;
        require_root("collateral_delta_root", &self.collateral_delta_root)?;
        require_root("premium_delta_root", &self.premium_delta_root)?;
        require_root("claim_payout_root", &self.claim_payout_root)?;
        if self.position_ids.len() + self.coupon_ids.len() > config.low_fee_batch_limit {
            return Err("low fee clearing batch exceeds configured item limit".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("clearing batch privacy set below runtime minimum".to_string());
        }
        if let Some(settled_height) = self.settled_height {
            if settled_height < self.opened_height {
                return Err("clearing batch settled before opened".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "market_id": self.market_id,
            "status": self.status,
            "position_ids": self.position_ids,
            "coupon_ids": self.coupon_ids,
            "low_fee_proof_root": self.low_fee_proof_root,
            "collateral_delta_root": self.collateral_delta_root,
            "premium_delta_root": self.premium_delta_root,
            "claim_payout_root": self.claim_payout_root,
            "fee_commitment": self.fee_commitment,
            "net_premium_commitment": self.net_premium_commitment,
            "net_collateral_commitment": self.net_collateral_commitment,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleReport {
    pub report_id: String,
    pub market_id: String,
    pub risk_kind: ReorgRiskKind,
    pub canonical_tip_root: String,
    pub orphaned_tip_root: String,
    pub reorg_evidence_root: String,
    pub finality_proof_root: String,
    pub observed_reorg_depth: u16,
    pub median_confidence_bps: u64,
    pub quorum: u16,
    pub pq_signature_root: String,
    pub height: u64,
}

impl OracleReport {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_nonempty("report_id", &self.report_id)?;
        require_nonempty("market_id", &self.market_id)?;
        require_root("canonical_tip_root", &self.canonical_tip_root)?;
        require_root("orphaned_tip_root", &self.orphaned_tip_root)?;
        require_root("reorg_evidence_root", &self.reorg_evidence_root)?;
        require_root("finality_proof_root", &self.finality_proof_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_bps("median_confidence_bps", self.median_confidence_bps)?;
        if self.observed_reorg_depth > config.max_reorg_depth {
            return Err("oracle observed_reorg_depth exceeds configured max".to_string());
        }
        if self.quorum < config.oracle_quorum {
            return Err("oracle report quorum below runtime threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "market_id": self.market_id,
            "risk_kind": self.risk_kind,
            "canonical_tip_root": self.canonical_tip_root,
            "orphaned_tip_root": self.orphaned_tip_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "finality_proof_root": self.finality_proof_root,
            "observed_reorg_depth": self.observed_reorg_depth,
            "median_confidence_bps": self.median_confidence_bps,
            "quorum": self.quorum,
            "pq_signature_root": self.pq_signature_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicSummary {
    pub summary_id: String,
    pub height: u64,
    pub markets: u64,
    pub open_positions: u64,
    pub active_claim_coupons: u64,
    pub clearing_batches: u64,
    pub collateral_root: String,
    pub premium_root: String,
    pub claim_coupon_root: String,
    pub low_fee_clearing_root: String,
    pub state_root: String,
}

impl PublicSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "height": self.height,
            "markets": self.markets,
            "open_positions": self.open_positions,
            "active_claim_coupons": self.active_claim_coupons,
            "clearing_batches": self.clearing_batches,
            "collateral_root": self.collateral_root,
            "premium_root": self.premium_root,
            "claim_coupon_root": self.claim_coupon_root,
            "low_fee_clearing_root": self.low_fee_clearing_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterMarketInput {
    pub market: ReorgMarket,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenPositionInput {
    pub position: PositionNote,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishFundingCurveInput {
    pub curve: FundingCurve,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdmitClaimCouponInput {
    pub coupon: ClaimCoupon,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearLowFeeBatchInput {
    pub batch: ClearingBatch,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishOracleReportInput {
    pub report: OracleReport,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub markets: BTreeMap<String, ReorgMarket>,
    pub positions: BTreeMap<String, PositionNote>,
    pub funding_curves: BTreeMap<String, FundingCurve>,
    pub claim_coupons: BTreeMap<String, ClaimCoupon>,
    pub clearing_batches: BTreeMap<String, ClearingBatch>,
    pub oracle_reports: BTreeMap<String, OracleReport>,
    pub public_summaries: BTreeMap<String, PublicSummary>,
    pub collateral_commitment_roots: BTreeMap<String, String>,
    pub premium_commitment_roots: BTreeMap<String, String>,
    pub spent_nullifiers: BTreeSet<String>,
    pub roots: Roots,
    pub counters: Counters,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            markets: BTreeMap::new(),
            positions: BTreeMap::new(),
            funding_curves: BTreeMap::new(),
            claim_coupons: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            oracle_reports: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
            collateral_commitment_roots: BTreeMap::new(),
            premium_commitment_roots: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            roots: Roots::empty(),
            counters: Counters::default(),
            l2_height,
            monero_height,
            epoch,
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config, DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT, DEVNET_EPOCH)
            .expect("devnet config is valid");
        let market_id = "market:reorg:monero-finality:0001".to_string();
        let market = ReorgMarket {
            market_id: market_id.clone(),
            risk_kind: ReorgRiskKind::DeepReorg,
            status: MarketStatus::Active,
            settlement_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            collateral_pool_root: demo_root(COLLATERAL_ROOT_SUITE, "market-collateral"),
            premium_pool_root: demo_root(PREMIUM_ROOT_SUITE, "market-premium"),
            funding_curve_root: demo_root(CONFIDENTIAL_FUNDING_CURVE_SUITE, "market-curve"),
            oracle_committee_root: demo_root("oracle-committee", "market"),
            max_reorg_depth: 96,
            finality_depth: 20,
            insurance_horizon_blocks: 720,
            base_premium_bps: 18,
            created_height: DEVNET_L2_HEIGHT,
            updated_height: DEVNET_L2_HEIGHT,
        };
        let _ = state.register_market(RegisterMarketInput { market });
        let _ = state.publish_oracle_report(PublishOracleReportInput {
            report: OracleReport {
                report_id: "oracle:reorg:0001".to_string(),
                market_id: market_id.clone(),
                risk_kind: ReorgRiskKind::DeepReorg,
                canonical_tip_root: demo_root("canonical-tip", "0001"),
                orphaned_tip_root: demo_root("orphaned-tip", "0001"),
                reorg_evidence_root: demo_root("reorg-evidence", "0001"),
                finality_proof_root: demo_root("finality-proof", "0001"),
                observed_reorg_depth: 24,
                median_confidence_bps: 9_850,
                quorum: DEFAULT_ORACLE_QUORUM,
                pq_signature_root: demo_root("oracle-pq-signature", "0001"),
                height: DEVNET_L2_HEIGHT + 1,
            },
        });
        let _ = state.publish_funding_curve(PublishFundingCurveInput {
            curve: FundingCurve {
                curve_id: "curve:reorg:0001".to_string(),
                market_id: market_id.clone(),
                status: MarketStatus::Active,
                curve_root: demo_root(CONFIDENTIAL_FUNDING_CURVE_SUITE, "curve-0001"),
                sealed_slope_commitment: "sealed:slope:curve:0001".to_string(),
                sealed_intercept_commitment: "sealed:intercept:curve:0001".to_string(),
                utilization_commitment: "commitment:utilization:0001".to_string(),
                premium_skew_commitment: "commitment:premium-skew:0001".to_string(),
                funding_rate_bps: 42,
                funding_index: 42,
                oracle_report_id: "oracle:reorg:0001".to_string(),
                pq_signature_root: demo_root("funding-pq-signature", "0001"),
                effective_height: DEVNET_L2_HEIGHT + 2,
                expires_height: DEVNET_L2_HEIGHT + DEFAULT_FUNDING_INTERVAL_BLOCKS + 2,
            },
        });
        let _ = state.open_position(OpenPositionInput {
            position: PositionNote {
                position_id: "position:alice:reorg-long:0001".to_string(),
                market_id: market_id.clone(),
                owner_commitment: "owner:commitment:alice:0001".to_string(),
                side: PositionSide::LongProtection,
                status: PositionStatus::Open,
                notional_commitment: 100_000_000,
                collateral_commitment: 116_000_000,
                premium_commitment: 190_000,
                entry_funding_index: 42,
                last_funding_index: 42,
                liquidation_threshold_bps: 10_800,
                collateral_note_root: demo_root(COLLATERAL_ROOT_SUITE, "alice-position"),
                premium_note_root: demo_root(PREMIUM_ROOT_SUITE, "alice-position"),
                viewing_key_commitment: "viewkey:commitment:alice:0001".to_string(),
                nullifier: "nullifier:position:alice:0001".to_string(),
                opened_height: DEVNET_L2_HEIGHT + 3,
                updated_height: DEVNET_L2_HEIGHT + 3,
            },
        });
        let _ = state.admit_claim_coupon(AdmitClaimCouponInput {
            coupon: ClaimCoupon {
                coupon_id: "coupon:reorg-claim:0001".to_string(),
                market_id: market_id.clone(),
                position_id: "position:alice:reorg-long:0001".to_string(),
                status: CouponStatus::Admitted,
                claim_event_root: demo_root("claim-event", "0001"),
                claim_amount_commitment: 24_000_000,
                payout_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
                reorg_depth: 24,
                canonical_height: DEVNET_MONERO_HEIGHT + 24,
                orphaned_height: DEVNET_MONERO_HEIGHT,
                pq_authorization_root: demo_root(CLAIM_COUPON_ROOT_SUITE, "coupon-pq"),
                claimant_note_root: demo_root("claimant-note", "0001"),
                coupon_nullifier: "nullifier:coupon:0001".to_string(),
                issued_height: DEVNET_L2_HEIGHT + 4,
                expires_height: DEVNET_L2_HEIGHT + DEFAULT_CLAIM_TTL_BLOCKS + 4,
            },
        });
        let _ = state.clear_low_fee_batch(ClearLowFeeBatchInput {
            batch: ClearingBatch {
                batch_id: "batch:low-fee-reorg:0001".to_string(),
                market_id,
                status: ClearingBatchStatus::Settled,
                position_ids: vec!["position:alice:reorg-long:0001".to_string()],
                coupon_ids: vec!["coupon:reorg-claim:0001".to_string()],
                low_fee_proof_root: demo_root(LOW_FEE_CLEARING_SUITE, "batch-proof"),
                collateral_delta_root: demo_root(COLLATERAL_ROOT_SUITE, "batch-delta"),
                premium_delta_root: demo_root(PREMIUM_ROOT_SUITE, "batch-delta"),
                claim_payout_root: demo_root("claim-payout", "batch"),
                fee_commitment: 2_000,
                net_premium_commitment: 188_000,
                net_collateral_commitment: 24_000_000,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                opened_height: DEVNET_L2_HEIGHT + 5,
                settled_height: Some(DEVNET_L2_HEIGHT + 6),
            },
        });
        let _ =
            state.publish_public_summary("summary:devnet:0001".to_string(), DEVNET_L2_HEIGHT + 7);
        state
    }

    pub fn register_market(&mut self, input: RegisterMarketInput) -> Result<String> {
        input.market.validate(&self.config)?;
        ensure_capacity("markets", self.markets.len(), self.config.max_markets)?;
        if self.markets.contains_key(&input.market.market_id) {
            return Err("market already registered".to_string());
        }
        let market_id = input.market.market_id.clone();
        self.markets.insert(market_id.clone(), input.market);
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
        if !market.status.accepts_positions() {
            return Err("market does not accept new reorg insurance positions".to_string());
        }
        if self.spent_nullifiers.contains(&input.position.nullifier) {
            return Err("position nullifier already spent".to_string());
        }
        let position_id = input.position.position_id.clone();
        self.spent_nullifiers
            .insert(input.position.nullifier.clone());
        self.collateral_commitment_roots.insert(
            position_id.clone(),
            input.position.collateral_note_root.clone(),
        );
        self.premium_commitment_roots.insert(
            position_id.clone(),
            input.position.premium_note_root.clone(),
        );
        self.positions.insert(position_id, input.position);
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
        if !market.status.accepts_funding() {
            return Err("market does not accept funding curves".to_string());
        }
        if !self
            .oracle_reports
            .contains_key(&input.curve.oracle_report_id)
        {
            return Err("funding curve references unknown oracle report".to_string());
        }
        let curve_id = input.curve.curve_id.clone();
        self.funding_curves.insert(curve_id, input.curve);
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
        if !market.status.accepts_claims() {
            return Err("market does not accept claim coupons".to_string());
        }
        if !self.positions.contains_key(&input.coupon.position_id) {
            return Err("claim coupon references unknown position".to_string());
        }
        if self
            .spent_nullifiers
            .contains(&input.coupon.coupon_nullifier)
        {
            return Err("claim coupon nullifier already spent".to_string());
        }
        let coupon_id = input.coupon.coupon_id.clone();
        self.spent_nullifiers
            .insert(input.coupon.coupon_nullifier.clone());
        self.claim_coupons.insert(coupon_id, input.coupon);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn clear_low_fee_batch(&mut self, input: ClearLowFeeBatchInput) -> Result<String> {
        input.batch.validate(&self.config)?;
        ensure_capacity(
            "clearing_batches",
            self.clearing_batches.len(),
            self.config.max_clearing_batches,
        )?;
        if !self.markets.contains_key(&input.batch.market_id) {
            return Err("clearing batch references unknown market".to_string());
        }
        for position_id in &input.batch.position_ids {
            if !self.positions.contains_key(position_id) {
                return Err(format!(
                    "clearing batch references unknown position {position_id}"
                ));
            }
        }
        for coupon_id in &input.batch.coupon_ids {
            if !self.claim_coupons.contains_key(coupon_id) {
                return Err(format!(
                    "clearing batch references unknown coupon {coupon_id}"
                ));
            }
        }
        let batch_id = input.batch.batch_id.clone();
        for position_id in &input.batch.position_ids {
            if let Some(position) = self.positions.get_mut(position_id) {
                position.status = PositionStatus::Netted;
                position.updated_height = input
                    .batch
                    .settled_height
                    .unwrap_or(input.batch.opened_height);
            }
        }
        for coupon_id in &input.batch.coupon_ids {
            if let Some(coupon) = self.claim_coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Netted;
            }
        }
        self.collateral_commitment_roots.insert(
            format!("batch:{batch_id}:collateral_delta"),
            input.batch.collateral_delta_root.clone(),
        );
        self.premium_commitment_roots.insert(
            format!("batch:{batch_id}:premium_delta"),
            input.batch.premium_delta_root.clone(),
        );
        self.clearing_batches.insert(batch_id, input.batch);
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
        if !self.markets.contains_key(&input.report.market_id) {
            return Err("oracle report references unknown market".to_string());
        }
        let report_id = input.report.report_id.clone();
        self.oracle_reports.insert(report_id, input.report);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn publish_public_summary(&mut self, summary_id: String, height: u64) -> Result<String> {
        require_nonempty("summary_id", &summary_id)?;
        let roots = self.roots();
        let summary = PublicSummary {
            summary_id: summary_id.clone(),
            height,
            markets: self.markets.len() as u64,
            open_positions: self
                .positions
                .values()
                .filter(|position| position.status.counts_open())
                .count() as u64,
            active_claim_coupons: self
                .claim_coupons
                .values()
                .filter(|coupon| {
                    matches!(
                        coupon.status,
                        CouponStatus::Admitted | CouponStatus::Netted | CouponStatus::Clearing
                    )
                })
                .count() as u64,
            clearing_batches: self.clearing_batches.len() as u64,
            collateral_root: roots.collateral_root,
            premium_root: roots.premium_root,
            claim_coupon_root: roots.claim_coupons_root,
            low_fee_clearing_root: roots.clearing_batches_root,
            state_root: self.state_root(),
        };
        self.public_summaries.insert(summary_id, summary);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            markets_root: map_public_root("markets", &self.markets, ReorgMarket::public_record),
            positions_root: map_public_root(
                "positions",
                &self.positions,
                PositionNote::public_record,
            ),
            funding_curves_root: map_public_root(
                CONFIDENTIAL_FUNDING_CURVE_SUITE,
                &self.funding_curves,
                FundingCurve::public_record,
            ),
            claim_coupons_root: map_public_root(
                CLAIM_COUPON_ROOT_SUITE,
                &self.claim_coupons,
                ClaimCoupon::public_record,
            ),
            clearing_batches_root: map_public_root(
                LOW_FEE_CLEARING_SUITE,
                &self.clearing_batches,
                ClearingBatch::public_record,
            ),
            oracle_reports_root: map_public_root(
                "oracle_reports",
                &self.oracle_reports,
                OracleReport::public_record,
            ),
            collateral_root: map_root(COLLATERAL_ROOT_SUITE, &self.collateral_commitment_roots),
            premium_root: map_root(PREMIUM_ROOT_SUITE, &self.premium_commitment_roots),
            nullifiers_root: set_root("spent_nullifiers", &self.spent_nullifiers),
            public_summaries_root: map_public_root(
                "public_summaries",
                &self.public_summaries,
                PublicSummary::public_record,
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            markets: self.markets.len() as u64,
            positions: self.positions.len() as u64,
            funding_curves: self.funding_curves.len() as u64,
            claim_coupons: self.claim_coupons.len() as u64,
            clearing_batches: self.clearing_batches.len() as u64,
            oracle_reports: self.oracle_reports.len() as u64,
            premium_ledgers: self.premium_commitment_roots.len() as u64,
            collateral_ledgers: self.collateral_commitment_roots.len() as u64,
            public_summaries: self.public_summaries.len() as u64,
            nullifiers: self.spent_nullifiers.len() as u64,
            low_fee_settlements: self
                .clearing_batches
                .values()
                .filter(|batch| batch.status == ClearingBatchStatus::Settled)
                .count() as u64,
            total_notional: self
                .positions
                .values()
                .map(|position| position.notional_commitment)
                .fold(0_u128, u128::saturating_add),
            total_collateral_commitments: self
                .positions
                .values()
                .map(|position| position.collateral_commitment)
                .fold(0_u128, u128::saturating_add),
            total_premium_commitments: self
                .positions
                .values()
                .map(|position| position.premium_commitment)
                .fold(0_u128, u128::saturating_add),
            total_claim_commitments: self
                .claim_coupons
                .values()
                .map(|coupon| coupon.claim_amount_commitment)
                .fold(0_u128, u128::saturating_add),
        }
    }

    pub fn refresh(&mut self) {
        self.roots = self.roots();
        self.counters = self.counters();
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
            "roots_root": roots.state_root(),
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
        domain_hash(
            STATE_ROOT_SUITE,
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.chain_id),
                HashPart::Json(&self.public_record_without_state_root()),
            ],
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn map_public_root<T, F>(label: &str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": f(value),
            })
        })
        .collect();
    merkle_root(label, &leaves)
}

fn map_root(label: &str, map: &BTreeMap<String, String>) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "root": value,
            })
        })
        .collect();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value": value,
            })
        })
        .collect();
    merkle_root(label, &leaves)
}

fn empty_root(label: &str) -> String {
    merkle_root(label, &[])
}

fn demo_root(label: &str, salt: &str) -> String {
    domain_hash(
        PAYLOAD_ROOT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(salt),
        ],
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
    )
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Some(object) = record.as_object_mut() {
        object.insert(key.to_string(), value);
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require_nonempty(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} root is too short"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds MAX_BPS"))
    } else {
        Ok(())
    }
}

fn require_nonzero_u128(label: &str, value: u128) -> Result<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn apply_bps_up(amount: u128, bps: u64) -> u128 {
    amount
        .saturating_mul(bps as u128)
        .saturating_add((MAX_BPS - 1) as u128)
        / MAX_BPS as u128
}
