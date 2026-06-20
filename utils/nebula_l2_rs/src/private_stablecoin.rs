use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateStablecoinResult<T> = Result<T, String>;

pub const PRIVATE_STABLECOIN_PROTOCOL_VERSION: &str = "nebula-private-stablecoin-v1";
pub const PRIVATE_STABLECOIN_COMMITMENT_SCHEME: &str = "devnet-shake256-sealed-cdp-v1";
pub const PRIVATE_STABLECOIN_RANGE_PROOF_SCHEME: &str = "devnet-mock-pq-range-proof-v1";
pub const PRIVATE_STABLECOIN_SOLVENCY_PROOF_SCHEME: &str = "devnet-private-cdp-solvency-proof-v1";
pub const PRIVATE_STABLECOIN_PQ_SIGNATURE_SCHEME: &str = "ml-dsa-87-devnet-attestation-v1";
pub const PRIVATE_STABLECOIN_ORACLE_SCHEME: &str = "threshold-oracle-root-v1";
pub const PRIVATE_STABLECOIN_AUCTION_SCHEME: &str = "private-liquidation-auction-root-v1";
pub const PRIVATE_STABLECOIN_TOKEN_FACTORY_SCHEME: &str = "stable-token-factory-hook-root-v1";
pub const PRIVATE_STABLECOIN_CONTRACT_ADAPTER_SCHEME: &str =
    "zk-contract-stablecoin-adapter-root-v1";
pub const PRIVATE_STABLECOIN_DISCLOSURE_SCHEME: &str = "bucket-only-privacy-disclosure-root-v1";
pub const PRIVATE_STABLECOIN_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_STABLECOIN_INDEX_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_STABLECOIN_MAX_BPS: u64 = 10_000;
pub const PRIVATE_STABLECOIN_BLOCKS_PER_YEAR: u64 = 2_628_000;
pub const PRIVATE_STABLECOIN_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const PRIVATE_STABLECOIN_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_STABLECOIN_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_STABLECOIN_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_STABLECOIN_DEFAULT_GLOBAL_SETTLEMENT_DELAY_BLOCKS: u64 = 36;
pub const PRIVATE_STABLECOIN_DEFAULT_LOW_FEE_LANE: &str = "small-private-stablecoin";
pub const PRIVATE_STABLECOIN_DEVNET_HEIGHT: u64 = 88;
pub const PRIVATE_STABLECOIN_DEVNET_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_STABLECOIN_DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_STABLECOIN_DEVNET_RESERVE_ASSET_ID: &str = "wxmr-reserve-devnet";
pub const PRIVATE_STABLECOIN_DEVNET_ORACLE_FEED_ID: &str = "feed-wxmr-usd-devnet";
pub const PRIVATE_STABLECOIN_DEVNET_WXMR_PRICE: u64 = 165 * PRIVATE_STABLECOIN_PRICE_SCALE;
pub const PRIVATE_STABLECOIN_DEVNET_MAX_SUPPLY_UNITS: u64 = 10_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StablecoinMarketStatus {
    Active,
    MintPaused,
    RedeemPaused,
    LiquidationOnly,
    GlobalSettlement,
    Paused,
    Retired,
}

impl StablecoinMarketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::MintPaused => "mint_paused",
            Self::RedeemPaused => "redeem_paused",
            Self::LiquidationOnly => "liquidation_only",
            Self::GlobalSettlement => "global_settlement",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn allows_mint(&self) -> bool {
        matches!(self, Self::Active | Self::RedeemPaused)
    }

    pub fn allows_redeem(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::MintPaused | Self::GlobalSettlement
        )
    }

    pub fn allows_liquidation(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::MintPaused | Self::RedeemPaused | Self::LiquidationOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StablecoinVaultStatus {
    Open,
    Frozen,
    Liquidating,
    Settled,
    Closed,
}

impl StablecoinVaultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Frozen => "frozen",
            Self::Liquidating => "liquidating",
            Self::Settled => "settled",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebtPositionStatus {
    Open,
    PendingMint,
    PendingRedeem,
    Liquidating,
    Challenged,
    Settled,
    Closed,
}

impl DebtPositionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PendingMint => "pending_mint",
            Self::PendingRedeem => "pending_redeem",
            Self::Liquidating => "liquidating",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralRatioBucket {
    NoDebt,
    SuperSafe,
    Healthy,
    Watch,
    Unsafe,
    Liquidatable,
    Insolvent,
}

impl CollateralRatioBucket {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoDebt => "no_debt",
            Self::SuperSafe => "super_safe",
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Unsafe => "unsafe",
            Self::Liquidatable => "liquidatable",
            Self::Insolvent => "insolvent",
        }
    }

    pub fn floor_bps(&self) -> u64 {
        match self {
            Self::NoDebt => u64::MAX,
            Self::SuperSafe => 30_000,
            Self::Healthy => 20_000,
            Self::Watch => 17_500,
            Self::Unsafe => 15_000,
            Self::Liquidatable => 12_500,
            Self::Insolvent => 0,
        }
    }

    pub fn can_liquidate(&self) -> bool {
        matches!(self, Self::Liquidatable | Self::Insolvent)
    }

    pub fn from_ratio_bps(ratio_bps: u64) -> Self {
        if ratio_bps == u64::MAX {
            Self::NoDebt
        } else if ratio_bps >= 30_000 {
            Self::SuperSafe
        } else if ratio_bps >= 20_000 {
            Self::Healthy
        } else if ratio_bps >= 17_500 {
            Self::Watch
        } else if ratio_bps >= 15_000 {
            Self::Unsafe
        } else if ratio_bps >= 12_500 {
            Self::Liquidatable
        } else {
            Self::Insolvent
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StablecoinAmountBucket {
    Dust,
    Small,
    Medium,
    Large,
    Whale,
}

impl StablecoinAmountBucket {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dust => "dust",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Whale => "whale",
        }
    }

    pub fn ceiling_units(&self) -> u64 {
        match self {
            Self::Dust => 1_000_000,
            Self::Small => 25_000_000,
            Self::Medium => 250_000_000,
            Self::Large => 5_000_000_000,
            Self::Whale => u64::MAX,
        }
    }

    pub fn is_sponsor_eligible(&self) -> bool {
        matches!(self, Self::Dust | Self::Small)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StablecoinOperationKind {
    Mint,
    Redeem,
    Burn,
}

impl StablecoinOperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Redeem => "redeem",
            Self::Burn => "burn",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StablecoinOperationStatus {
    Pending,
    Sponsored,
    Committed,
    Applied,
    Reverted,
    Expired,
}

impl StablecoinOperationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sponsored => "sponsored",
            Self::Committed => "committed",
            Self::Applied => "applied",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleRootStatus {
    Active,
    Stale,
    Disputed,
    Revoked,
}

impl OracleRootStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationQueueStatus {
    Queued,
    ChallengeOpen,
    Executable,
    AuctionOpen,
    Settled,
    Cancelled,
    Expired,
}

impl LiquidationQueueStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ChallengeOpen => "challenge_open",
            Self::Executable => "executable",
            Self::AuctionOpen => "auction_open",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Preview,
    Open,
    ChallengeOpen,
    Clearing,
    Settled,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Open => "open",
            Self::ChallengeOpen => "challenge_open",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StabilityFeeEventKind {
    MintOrigination,
    PeriodicAccrual,
    RedemptionSpread,
    LiquidationPenalty,
    ReserveRebalance,
}

impl StabilityFeeEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MintOrigination => "mint_origination",
            Self::PeriodicAccrual => "periodic_accrual",
            Self::RedemptionSpread => "redemption_spread",
            Self::LiquidationPenalty => "liquidation_penalty",
            Self::ReserveRebalance => "reserve_rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDecision {
    Approve,
    Watch,
    ReduceCaps,
    PauseMint,
    TriggerSettlement,
    Reject,
}

impl RiskDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Watch => "watch",
            Self::ReduceCaps => "reduce_caps",
            Self::PauseMint => "pause_mint",
            Self::TriggerSettlement => "trigger_settlement",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Info,
    Watch,
    Elevated,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            Self::Info => 500,
            Self::Watch => 2_000,
            Self::Elevated => 6_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalSettlementStatus {
    Proposed,
    ChallengeOpen,
    Active,
    Finalized,
    Cancelled,
}

impl GlobalSettlementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ChallengeOpen => "challenge_open",
            Self::Active => "active",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Active,
    Consumed,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStatus {
    Active,
    Paused,
    Retired,
}

impl AdapterStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenFactoryHookKind {
    RegisterStableAsset,
    Mint,
    Burn,
    Freeze,
    GlobalSettlement,
}

impl TokenFactoryHookKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RegisterStableAsset => "register_stable_asset",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Freeze => "freeze",
            Self::GlobalSettlement => "global_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyDisclosureScope {
    MarketBuckets,
    ReserveBuckets,
    MintRedeemBuckets,
    LiquidationBuckets,
    GlobalSettlementBuckets,
}

impl PrivacyDisclosureScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MarketBuckets => "market_buckets",
            Self::ReserveBuckets => "reserve_buckets",
            Self::MintRedeemBuckets => "mint_redeem_buckets",
            Self::LiquidationBuckets => "liquidation_buckets",
            Self::GlobalSettlementBuckets => "global_settlement_buckets",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStablecoinConfig {
    pub protocol_version: String,
    pub collateral_asset_id: String,
    pub stable_asset_id: String,
    pub reserve_asset_id: String,
    pub commitment_scheme: String,
    pub range_proof_scheme: String,
    pub solvency_proof_scheme: String,
    pub pq_signature_scheme: String,
    pub oracle_scheme: String,
    pub auction_scheme: String,
    pub token_factory_scheme: String,
    pub contract_adapter_scheme: String,
    pub disclosure_scheme: String,
    pub default_low_fee_lane: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub max_supply_units: u64,
    pub minimum_collateral_ratio_bps: u64,
    pub liquidation_ratio_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub stability_fee_annual_bps: u64,
    pub reserve_factor_bps: u64,
    pub redemption_spread_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub default_auction_ttl_blocks: u64,
    pub sponsored_small_mint_limit_units: u64,
    pub sponsored_small_redeem_limit_units: u64,
    pub sponsored_max_fee_units: u64,
    pub global_settlement_delay_blocks: u64,
}

impl Default for PrivateStablecoinConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl PrivateStablecoinConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_STABLECOIN_PROTOCOL_VERSION.to_string(),
            collateral_asset_id: PRIVATE_STABLECOIN_DEVNET_COLLATERAL_ASSET_ID.to_string(),
            stable_asset_id: PRIVATE_STABLECOIN_DEVNET_STABLE_ASSET_ID.to_string(),
            reserve_asset_id: PRIVATE_STABLECOIN_DEVNET_RESERVE_ASSET_ID.to_string(),
            commitment_scheme: PRIVATE_STABLECOIN_COMMITMENT_SCHEME.to_string(),
            range_proof_scheme: PRIVATE_STABLECOIN_RANGE_PROOF_SCHEME.to_string(),
            solvency_proof_scheme: PRIVATE_STABLECOIN_SOLVENCY_PROOF_SCHEME.to_string(),
            pq_signature_scheme: PRIVATE_STABLECOIN_PQ_SIGNATURE_SCHEME.to_string(),
            oracle_scheme: PRIVATE_STABLECOIN_ORACLE_SCHEME.to_string(),
            auction_scheme: PRIVATE_STABLECOIN_AUCTION_SCHEME.to_string(),
            token_factory_scheme: PRIVATE_STABLECOIN_TOKEN_FACTORY_SCHEME.to_string(),
            contract_adapter_scheme: PRIVATE_STABLECOIN_CONTRACT_ADAPTER_SCHEME.to_string(),
            disclosure_scheme: PRIVATE_STABLECOIN_DISCLOSURE_SCHEME.to_string(),
            default_low_fee_lane: PRIVATE_STABLECOIN_DEFAULT_LOW_FEE_LANE.to_string(),
            price_scale: PRIVATE_STABLECOIN_PRICE_SCALE,
            index_scale: PRIVATE_STABLECOIN_INDEX_SCALE,
            max_supply_units: PRIVATE_STABLECOIN_DEVNET_MAX_SUPPLY_UNITS,
            minimum_collateral_ratio_bps: 18_000,
            liquidation_ratio_bps: 13_500,
            liquidation_penalty_bps: 800,
            stability_fee_annual_bps: 250,
            reserve_factor_bps: 1_500,
            redemption_spread_bps: 25,
            max_oracle_staleness_blocks: PRIVATE_STABLECOIN_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            default_challenge_window_blocks: PRIVATE_STABLECOIN_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            default_auction_ttl_blocks: PRIVATE_STABLECOIN_DEFAULT_AUCTION_TTL_BLOCKS,
            sponsored_small_mint_limit_units: 25_000_000,
            sponsored_small_redeem_limit_units: 25_000_000,
            sponsored_max_fee_units: 5_000,
            global_settlement_delay_blocks:
                PRIVATE_STABLECOIN_DEFAULT_GLOBAL_SETTLEMENT_DELAY_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_stablecoin_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "collateral_asset_id": self.collateral_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "commitment_scheme": self.commitment_scheme,
            "range_proof_scheme": self.range_proof_scheme,
            "solvency_proof_scheme": self.solvency_proof_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "oracle_scheme": self.oracle_scheme,
            "auction_scheme": self.auction_scheme,
            "token_factory_scheme": self.token_factory_scheme,
            "contract_adapter_scheme": self.contract_adapter_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "default_low_fee_lane": self.default_low_fee_lane,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "max_supply_units": self.max_supply_units,
            "minimum_collateral_ratio_bps": self.minimum_collateral_ratio_bps,
            "liquidation_ratio_bps": self.liquidation_ratio_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "stability_fee_annual_bps": self.stability_fee_annual_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "redemption_spread_bps": self.redemption_spread_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "default_auction_ttl_blocks": self.default_auction_ttl_blocks,
            "sponsored_small_mint_limit_units": self.sponsored_small_mint_limit_units,
            "sponsored_small_redeem_limit_units": self.sponsored_small_redeem_limit_units,
            "sponsored_max_fee_units": self.sponsored_max_fee_units,
            "global_settlement_delay_blocks": self.global_settlement_delay_blocks,
        })
    }

    pub fn config_root(&self) -> String {
        private_stablecoin_payload_root("PRIVATE-STABLECOIN-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateStablecoinResult<()> {
        ensure_non_empty(&self.protocol_version, "stablecoin config protocol_version")?;
        ensure_non_empty(
            &self.collateral_asset_id,
            "stablecoin config collateral asset",
        )?;
        ensure_non_empty(&self.stable_asset_id, "stablecoin config stable asset")?;
        ensure_non_empty(&self.reserve_asset_id, "stablecoin config reserve asset")?;
        ensure_non_empty(
            &self.commitment_scheme,
            "stablecoin config commitment scheme",
        )?;
        ensure_non_empty(
            &self.range_proof_scheme,
            "stablecoin config range proof scheme",
        )?;
        ensure_non_empty(
            &self.solvency_proof_scheme,
            "stablecoin config solvency proof scheme",
        )?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "stablecoin config pq signature scheme",
        )?;
        ensure_non_empty(&self.oracle_scheme, "stablecoin config oracle scheme")?;
        ensure_non_empty(&self.auction_scheme, "stablecoin config auction scheme")?;
        ensure_non_empty(
            &self.token_factory_scheme,
            "stablecoin config token factory scheme",
        )?;
        ensure_non_empty(
            &self.contract_adapter_scheme,
            "stablecoin config contract adapter scheme",
        )?;
        ensure_non_empty(
            &self.disclosure_scheme,
            "stablecoin config disclosure scheme",
        )?;
        ensure_non_empty(&self.default_low_fee_lane, "stablecoin config low fee lane")?;
        if self.collateral_asset_id == self.stable_asset_id {
            return Err("stablecoin collateral and debt assets must differ".to_string());
        }
        if self.price_scale == 0 || self.index_scale == 0 {
            return Err("stablecoin price and index scales must be non-zero".to_string());
        }
        if self.max_supply_units == 0 {
            return Err("stablecoin max supply must be non-zero".to_string());
        }
        validate_bps(
            "stablecoin minimum collateral ratio bps",
            self.minimum_collateral_ratio_bps,
            100_000,
        )?;
        validate_bps(
            "stablecoin liquidation ratio bps",
            self.liquidation_ratio_bps,
            100_000,
        )?;
        if self.liquidation_ratio_bps >= self.minimum_collateral_ratio_bps {
            return Err(
                "stablecoin liquidation ratio must be below minimum collateral ratio".to_string(),
            );
        }
        validate_bps(
            "stablecoin liquidation penalty bps",
            self.liquidation_penalty_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        validate_bps(
            "stablecoin stability fee annual bps",
            self.stability_fee_annual_bps,
            100_000,
        )?;
        validate_bps(
            "stablecoin reserve factor bps",
            self.reserve_factor_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        validate_bps(
            "stablecoin redemption spread bps",
            self.redemption_spread_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        if self.max_oracle_staleness_blocks == 0
            || self.default_challenge_window_blocks == 0
            || self.default_auction_ttl_blocks == 0
        {
            return Err("stablecoin timing guards must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStablecoinMarket {
    pub market_id: String,
    pub market_label: String,
    pub collateral_asset_id: String,
    pub stable_asset_id: String,
    pub reserve_asset_id: String,
    pub oracle_feed_id: String,
    pub low_fee_lane: String,
    pub max_supply_units: u64,
    pub issued_units: u64,
    pub burned_units: u64,
    pub redeemed_units: u64,
    pub reserve_floor_units: u64,
    pub current_fee_index: u64,
    pub minimum_collateral_ratio_bps: u64,
    pub liquidation_ratio_bps: u64,
    pub stability_fee_annual_bps: u64,
    pub reserve_factor_bps: u64,
    pub supply_cap_root: String,
    pub oracle_guard_root: String,
    pub token_hook_root: String,
    pub adapter_root: String,
    pub disclosure_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub last_accrual_height: u64,
    pub status: StablecoinMarketStatus,
}

impl PrivateStablecoinMarket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_label: impl Into<String>,
        collateral_asset_id: impl Into<String>,
        stable_asset_id: impl Into<String>,
        reserve_asset_id: impl Into<String>,
        oracle_feed_id: impl Into<String>,
        low_fee_lane: impl Into<String>,
        max_supply_units: u64,
        minimum_collateral_ratio_bps: u64,
        liquidation_ratio_bps: u64,
        stability_fee_annual_bps: u64,
        reserve_factor_bps: u64,
        metadata: &Value,
        created_at_height: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_label = normalize_label(market_label.into());
        let collateral_asset_id = collateral_asset_id.into();
        let stable_asset_id = stable_asset_id.into();
        let reserve_asset_id = reserve_asset_id.into();
        let oracle_feed_id = oracle_feed_id.into();
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&market_label, "stablecoin market label")?;
        ensure_non_empty(&collateral_asset_id, "stablecoin collateral asset")?;
        ensure_non_empty(&stable_asset_id, "stablecoin stable asset")?;
        ensure_non_empty(&reserve_asset_id, "stablecoin reserve asset")?;
        ensure_non_empty(&oracle_feed_id, "stablecoin oracle feed")?;
        ensure_non_empty(&low_fee_lane, "stablecoin low fee lane")?;
        let market_id = private_stablecoin_market_id(
            &market_label,
            &collateral_asset_id,
            &stable_asset_id,
            &oracle_feed_id,
        );
        let mut market = Self {
            market_id,
            market_label,
            collateral_asset_id,
            stable_asset_id,
            reserve_asset_id,
            oracle_feed_id,
            low_fee_lane,
            max_supply_units,
            issued_units: 0,
            burned_units: 0,
            redeemed_units: 0,
            reserve_floor_units: 0,
            current_fee_index: PRIVATE_STABLECOIN_INDEX_SCALE,
            minimum_collateral_ratio_bps,
            liquidation_ratio_bps,
            stability_fee_annual_bps,
            reserve_factor_bps,
            supply_cap_root: private_stablecoin_string_root(
                "PRIVATE-STABLECOIN-EMPTY-SUPPLY-CAP",
                "empty",
            ),
            oracle_guard_root: private_stablecoin_string_root(
                "PRIVATE-STABLECOIN-EMPTY-ORACLE-GUARD",
                "empty",
            ),
            token_hook_root: private_stablecoin_string_root(
                "PRIVATE-STABLECOIN-EMPTY-TOKEN-HOOK",
                "empty",
            ),
            adapter_root: private_stablecoin_string_root(
                "PRIVATE-STABLECOIN-EMPTY-ADAPTER",
                "empty",
            ),
            disclosure_root: private_stablecoin_payload_root(
                "PRIVATE-STABLECOIN-MARKET-METADATA",
                metadata,
            ),
            metadata_root: private_stablecoin_payload_root(
                "PRIVATE-STABLECOIN-MARKET-METADATA",
                metadata,
            ),
            created_at_height,
            last_accrual_height: created_at_height,
            status: StablecoinMarketStatus::Active,
        };
        market.supply_cap_root =
            private_stablecoin_supply_cap_root(&[StablecoinSupplyCapSnapshot::from_market(
                &market,
                created_at_height,
            )]);
        market.validate()?;
        Ok(market)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_stablecoin_market",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "market_label": self.market_label,
            "collateral_asset_id": self.collateral_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "low_fee_lane": self.low_fee_lane,
            "max_supply_units": self.max_supply_units,
            "issued_units": self.issued_units,
            "burned_units": self.burned_units,
            "redeemed_units": self.redeemed_units,
            "circulating_units": self.circulating_units(),
            "remaining_mint_capacity_units": self.remaining_mint_capacity_units(),
            "reserve_floor_units": self.reserve_floor_units,
            "current_fee_index": self.current_fee_index,
            "minimum_collateral_ratio_bps": self.minimum_collateral_ratio_bps,
            "liquidation_ratio_bps": self.liquidation_ratio_bps,
            "stability_fee_annual_bps": self.stability_fee_annual_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "supply_cap_root": self.supply_cap_root,
            "oracle_guard_root": self.oracle_guard_root,
            "token_hook_root": self.token_hook_root,
            "adapter_root": self.adapter_root,
            "disclosure_root": self.disclosure_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "last_accrual_height": self.last_accrual_height,
            "status": self.status.as_str(),
        })
    }

    pub fn circulating_units(&self) -> u64 {
        self.issued_units
            .saturating_sub(self.burned_units)
            .saturating_sub(self.redeemed_units)
    }

    pub fn remaining_mint_capacity_units(&self) -> u64 {
        self.max_supply_units
            .saturating_sub(self.circulating_units())
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.market_id, "stablecoin market id")?;
        ensure_non_empty(&self.market_label, "stablecoin market label")?;
        ensure_non_empty(
            &self.collateral_asset_id,
            "stablecoin market collateral asset",
        )?;
        ensure_non_empty(&self.stable_asset_id, "stablecoin market stable asset")?;
        ensure_non_empty(&self.reserve_asset_id, "stablecoin market reserve asset")?;
        ensure_non_empty(&self.oracle_feed_id, "stablecoin market oracle feed")?;
        ensure_non_empty(&self.low_fee_lane, "stablecoin market low fee lane")?;
        ensure_non_empty(&self.supply_cap_root, "stablecoin market supply cap root")?;
        ensure_non_empty(
            &self.oracle_guard_root,
            "stablecoin market oracle guard root",
        )?;
        ensure_non_empty(&self.token_hook_root, "stablecoin market token hook root")?;
        ensure_non_empty(&self.adapter_root, "stablecoin market adapter root")?;
        ensure_non_empty(&self.disclosure_root, "stablecoin market disclosure root")?;
        ensure_non_empty(&self.metadata_root, "stablecoin market metadata root")?;
        if self.max_supply_units == 0 {
            return Err("stablecoin market max supply must be non-zero".to_string());
        }
        if self.circulating_units() > self.max_supply_units {
            return Err("stablecoin market circulating supply exceeds cap".to_string());
        }
        if self.current_fee_index == 0 {
            return Err("stablecoin market fee index must be non-zero".to_string());
        }
        validate_bps(
            "stablecoin market minimum collateral ratio",
            self.minimum_collateral_ratio_bps,
            100_000,
        )?;
        validate_bps(
            "stablecoin market liquidation ratio",
            self.liquidation_ratio_bps,
            100_000,
        )?;
        if self.liquidation_ratio_bps >= self.minimum_collateral_ratio_bps {
            return Err(
                "stablecoin market liquidation ratio must be below minimum ratio".to_string(),
            );
        }
        validate_bps(
            "stablecoin market stability fee",
            self.stability_fee_annual_bps,
            100_000,
        )?;
        validate_bps(
            "stablecoin market reserve factor",
            self.reserve_factor_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        if self.market_id
            != private_stablecoin_market_id(
                &self.market_label,
                &self.collateral_asset_id,
                &self.stable_asset_id,
                &self.oracle_feed_id,
            )
        {
            return Err("stablecoin market id mismatch".to_string());
        }
        Ok(self.market_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialCollateralVault {
    pub vault_id: String,
    pub owner_commitment: String,
    pub collateral_asset_id: String,
    pub stable_asset_id: String,
    pub collateral_commitment: String,
    pub collateral_bucket_commitment: String,
    pub encrypted_balance_root: String,
    pub nullifier_root: String,
    pub spend_authorization_root: String,
    pub proof_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
    pub status: StablecoinVaultStatus,
}

impl ConfidentialCollateralVault {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: impl Into<String>,
        collateral_asset_id: impl Into<String>,
        stable_asset_id: impl Into<String>,
        collateral_bucket: impl Into<String>,
        blinding_seed: impl Into<String>,
        encrypted_balance: &Value,
        spend_authorization: &Value,
        opened_at_height: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let owner_label = owner_label.into();
        let collateral_asset_id = collateral_asset_id.into();
        let stable_asset_id = stable_asset_id.into();
        let collateral_bucket = collateral_bucket.into();
        let blinding_seed = blinding_seed.into();
        ensure_non_empty(&owner_label, "vault owner label")?;
        ensure_non_empty(&collateral_asset_id, "vault collateral asset")?;
        ensure_non_empty(&stable_asset_id, "vault stable asset")?;
        ensure_non_empty(&collateral_bucket, "vault collateral bucket")?;
        ensure_non_empty(&blinding_seed, "vault blinding seed")?;
        let owner_commitment = private_stablecoin_account_commitment(&owner_label);
        let collateral_commitment = private_stablecoin_amount_commitment(
            &collateral_asset_id,
            &collateral_bucket,
            &blinding_seed,
        );
        let collateral_bucket_commitment =
            private_stablecoin_bucket_commitment("collateral_amount", &collateral_bucket);
        let encrypted_balance_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-VAULT-ENCRYPTED-BALANCE",
            encrypted_balance,
        );
        let spend_authorization_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-VAULT-SPEND-AUTHORIZATION",
            spend_authorization,
        );
        let nullifier_root = private_stablecoin_string_root(
            "PRIVATE-STABLECOIN-VAULT-NULLIFIER",
            &format!("{owner_commitment}:{nonce}"),
        );
        let proof_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-VAULT-PROOF",
            &json!({
                "range_proof_scheme": PRIVATE_STABLECOIN_RANGE_PROOF_SCHEME,
                "commitment_scheme": PRIVATE_STABLECOIN_COMMITMENT_SCHEME,
                "collateral_bucket_commitment": collateral_bucket_commitment,
                "encrypted_balance_root": encrypted_balance_root,
            }),
        );
        let vault_id = private_stablecoin_vault_id(
            &owner_commitment,
            &collateral_asset_id,
            &collateral_commitment,
            opened_at_height,
            nonce,
        );
        let vault = Self {
            vault_id,
            owner_commitment,
            collateral_asset_id,
            stable_asset_id,
            collateral_commitment,
            collateral_bucket_commitment,
            encrypted_balance_root,
            nullifier_root,
            spend_authorization_root,
            proof_root,
            opened_at_height,
            updated_at_height: opened_at_height,
            nonce,
            status: StablecoinVaultStatus::Open,
        };
        vault.validate()?;
        Ok(vault)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_collateral_vault",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "collateral_commitment": self.collateral_commitment,
            "collateral_bucket_commitment": self.collateral_bucket_commitment,
            "encrypted_balance_root": self.encrypted_balance_root,
            "nullifier_root": self.nullifier_root,
            "spend_authorization_root": self.spend_authorization_root,
            "proof_root": self.proof_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.vault_id, "vault id")?;
        ensure_non_empty(&self.owner_commitment, "vault owner commitment")?;
        ensure_non_empty(&self.collateral_asset_id, "vault collateral asset")?;
        ensure_non_empty(&self.stable_asset_id, "vault stable asset")?;
        ensure_non_empty(&self.collateral_commitment, "vault collateral commitment")?;
        ensure_non_empty(
            &self.collateral_bucket_commitment,
            "vault collateral bucket commitment",
        )?;
        ensure_non_empty(&self.encrypted_balance_root, "vault encrypted balance root")?;
        ensure_non_empty(&self.nullifier_root, "vault nullifier root")?;
        ensure_non_empty(
            &self.spend_authorization_root,
            "vault spend authorization root",
        )?;
        ensure_non_empty(&self.proof_root, "vault proof root")?;
        if self.updated_at_height < self.opened_at_height {
            return Err("vault update cannot precede open".to_string());
        }
        if self.vault_id
            != private_stablecoin_vault_id(
                &self.owner_commitment,
                &self.collateral_asset_id,
                &self.collateral_commitment,
                self.opened_at_height,
                self.nonce,
            )
        {
            return Err("vault id mismatch".to_string());
        }
        Ok(self.vault_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDebtPosition {
    pub position_id: String,
    pub market_id: String,
    pub vault_id: String,
    pub owner_commitment: String,
    pub debt_commitment: String,
    pub minted_supply_commitment: String,
    pub collateral_ratio_bucket_commitment: String,
    pub collateral_value_commitment: String,
    pub liquidation_threshold_commitment: String,
    pub fee_index_checkpoint: u64,
    pub oracle_root_id: String,
    pub privacy_budget_id: String,
    pub encrypted_terms_root: String,
    pub solvency_proof_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: DebtPositionStatus,
}

impl SealedDebtPosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        vault_id: impl Into<String>,
        owner_label: impl Into<String>,
        debt_bucket: impl Into<String>,
        collateral_ratio_bucket: CollateralRatioBucket,
        collateral_value_bucket: impl Into<String>,
        oracle_root_id: impl Into<String>,
        privacy_budget_id: impl Into<String>,
        encrypted_terms: &Value,
        solvency_witness: &Value,
        fee_index_checkpoint: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let vault_id = vault_id.into();
        let owner_label = owner_label.into();
        let debt_bucket = debt_bucket.into();
        let collateral_value_bucket = collateral_value_bucket.into();
        let oracle_root_id = oracle_root_id.into();
        let privacy_budget_id = privacy_budget_id.into();
        ensure_non_empty(&market_id, "debt position market id")?;
        ensure_non_empty(&vault_id, "debt position vault id")?;
        ensure_non_empty(&owner_label, "debt position owner label")?;
        ensure_non_empty(&debt_bucket, "debt position debt bucket")?;
        ensure_non_empty(
            &collateral_value_bucket,
            "debt position collateral value bucket",
        )?;
        ensure_non_empty(&oracle_root_id, "debt position oracle root")?;
        ensure_non_empty(&privacy_budget_id, "debt position privacy budget")?;
        if expires_at_height <= opened_at_height {
            return Err("debt position expiry must be after open".to_string());
        }
        if fee_index_checkpoint == 0 {
            return Err("debt position fee checkpoint must be non-zero".to_string());
        }
        let owner_commitment = private_stablecoin_account_commitment(&owner_label);
        let debt_commitment =
            private_stablecoin_amount_commitment("stable_debt", &debt_bucket, &owner_commitment);
        let minted_supply_commitment = private_stablecoin_amount_commitment(
            "stable_minted_supply",
            &debt_bucket,
            &format!("{owner_commitment}:{nonce}"),
        );
        let collateral_ratio_bucket_commitment = private_stablecoin_bucket_commitment(
            "collateral_ratio",
            collateral_ratio_bucket.as_str(),
        );
        let collateral_value_commitment = private_stablecoin_amount_commitment(
            "collateral_value",
            &collateral_value_bucket,
            &owner_commitment,
        );
        let liquidation_threshold_commitment = private_stablecoin_bucket_commitment(
            "liquidation_threshold",
            collateral_ratio_bucket.as_str(),
        );
        let encrypted_terms_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-DEBT-TERMS", encrypted_terms);
        let public_input_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-DEBT-SOLVENCY-PUBLIC",
            &json!({
                "market_id": market_id,
                "vault_id": vault_id,
                "oracle_root_id": oracle_root_id,
                "collateral_ratio_bucket_commitment": collateral_ratio_bucket_commitment,
            }),
        );
        let private_witness_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-DEBT-SOLVENCY-WITNESS",
            solvency_witness,
        );
        let solvency_proof_root = private_stablecoin_proof_root(
            PRIVATE_STABLECOIN_SOLVENCY_PROOF_SCHEME,
            &public_input_root,
            &private_witness_root,
        );
        let position_id = private_stablecoin_debt_position_id(
            &market_id,
            &vault_id,
            &owner_commitment,
            &debt_commitment,
            opened_at_height,
            nonce,
        );
        let position = Self {
            position_id,
            market_id,
            vault_id,
            owner_commitment,
            debt_commitment,
            minted_supply_commitment,
            collateral_ratio_bucket_commitment,
            collateral_value_commitment,
            liquidation_threshold_commitment,
            fee_index_checkpoint,
            oracle_root_id,
            privacy_budget_id,
            encrypted_terms_root,
            solvency_proof_root,
            opened_at_height,
            updated_at_height: opened_at_height,
            expires_at_height,
            nonce,
            status: DebtPositionStatus::Open,
        };
        position.validate()?;
        Ok(position)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_debt_position",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "debt_commitment": self.debt_commitment,
            "minted_supply_commitment": self.minted_supply_commitment,
            "collateral_ratio_bucket_commitment": self.collateral_ratio_bucket_commitment,
            "collateral_value_commitment": self.collateral_value_commitment,
            "liquidation_threshold_commitment": self.liquidation_threshold_commitment,
            "fee_index_checkpoint": self.fee_index_checkpoint,
            "oracle_root_id": self.oracle_root_id,
            "privacy_budget_id": self.privacy_budget_id,
            "encrypted_terms_root": self.encrypted_terms_root,
            "solvency_proof_root": self.solvency_proof_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.position_id, "debt position id")?;
        ensure_non_empty(&self.market_id, "debt position market id")?;
        ensure_non_empty(&self.vault_id, "debt position vault id")?;
        ensure_non_empty(&self.owner_commitment, "debt position owner commitment")?;
        ensure_non_empty(&self.debt_commitment, "debt position debt commitment")?;
        ensure_non_empty(
            &self.minted_supply_commitment,
            "debt position minted supply commitment",
        )?;
        ensure_non_empty(
            &self.collateral_ratio_bucket_commitment,
            "debt position ratio bucket commitment",
        )?;
        ensure_non_empty(
            &self.collateral_value_commitment,
            "debt position collateral value commitment",
        )?;
        ensure_non_empty(
            &self.liquidation_threshold_commitment,
            "debt position liquidation threshold commitment",
        )?;
        ensure_non_empty(&self.oracle_root_id, "debt position oracle root")?;
        ensure_non_empty(&self.privacy_budget_id, "debt position privacy budget")?;
        ensure_non_empty(
            &self.encrypted_terms_root,
            "debt position encrypted terms root",
        )?;
        ensure_non_empty(
            &self.solvency_proof_root,
            "debt position solvency proof root",
        )?;
        if self.fee_index_checkpoint == 0 {
            return Err("debt position fee index checkpoint must be non-zero".to_string());
        }
        if self.updated_at_height < self.opened_at_height {
            return Err("debt position update cannot precede open".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("debt position expiry must be after open".to_string());
        }
        if self.position_id
            != private_stablecoin_debt_position_id(
                &self.market_id,
                &self.vault_id,
                &self.owner_commitment,
                &self.debt_commitment,
                self.opened_at_height,
                self.nonce,
            )
        {
            return Err("debt position id mismatch".to_string());
        }
        Ok(self.position_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRedeemBurnCommitment {
    pub operation_id: String,
    pub market_id: String,
    pub position_id: String,
    pub vault_id: String,
    pub operation_kind: StablecoinOperationKind,
    pub account_commitment: String,
    pub asset_id: String,
    pub amount_bucket: StablecoinAmountBucket,
    pub amount_bucket_commitment: String,
    pub amount_commitment: String,
    pub supply_delta_commitment: String,
    pub fee_commitment: String,
    pub nullifier: String,
    pub recipient_commitment: String,
    pub quote_root: String,
    pub proof_root: String,
    pub sponsor_id: String,
    pub low_fee_lane: String,
    pub max_fee_units: u64,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: StablecoinOperationStatus,
}

impl MintRedeemBurnCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        position_id: impl Into<String>,
        vault_id: impl Into<String>,
        operation_kind: StablecoinOperationKind,
        account_label: impl Into<String>,
        asset_id: impl Into<String>,
        amount_bucket: StablecoinAmountBucket,
        amount_blinding: impl Into<String>,
        recipient_label: impl Into<String>,
        quote: &Value,
        witness: &Value,
        sponsor_id: impl Into<String>,
        low_fee_lane: impl Into<String>,
        max_fee_units: u64,
        requested_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let position_id = position_id.into();
        let vault_id = vault_id.into();
        let account_label = account_label.into();
        let asset_id = asset_id.into();
        let amount_blinding = amount_blinding.into();
        let recipient_label = recipient_label.into();
        let sponsor_id = sponsor_id.into();
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty(&market_id, "operation market id")?;
        ensure_non_empty(&account_label, "operation account label")?;
        ensure_non_empty(&asset_id, "operation asset id")?;
        ensure_non_empty(&amount_blinding, "operation amount blinding")?;
        ensure_non_empty(&recipient_label, "operation recipient label")?;
        if expires_at_height <= requested_at_height {
            return Err("operation expiry must be after request height".to_string());
        }
        let account_commitment = private_stablecoin_account_commitment(&account_label);
        let recipient_commitment = private_stablecoin_account_commitment(&recipient_label);
        let amount_bucket_commitment =
            private_stablecoin_bucket_commitment("operation_amount", amount_bucket.as_str());
        let amount_commitment = private_stablecoin_amount_commitment(
            &asset_id,
            amount_bucket.as_str(),
            &amount_blinding,
        );
        let supply_delta_commitment = private_stablecoin_supply_delta_commitment(
            operation_kind,
            &amount_commitment,
            &account_commitment,
        );
        let fee_commitment = private_stablecoin_amount_commitment(
            "operation_fee",
            &format!("max_fee_units:{max_fee_units}"),
            &amount_blinding,
        );
        let nullifier = private_stablecoin_operation_nullifier(
            &account_commitment,
            &amount_commitment,
            operation_kind,
            nonce,
        );
        let quote_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-OPERATION-QUOTE", quote);
        let public_input_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-OPERATION-PUBLIC",
            &json!({
                "market_id": market_id,
                "position_id": position_id,
                "vault_id": vault_id,
                "operation_kind": operation_kind.as_str(),
                "asset_id": asset_id,
                "amount_bucket_commitment": amount_bucket_commitment,
                "quote_root": quote_root,
            }),
        );
        let private_witness_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-OPERATION-WITNESS", witness);
        let proof_root = private_stablecoin_proof_root(
            PRIVATE_STABLECOIN_SOLVENCY_PROOF_SCHEME,
            &public_input_root,
            &private_witness_root,
        );
        let operation_id = private_stablecoin_operation_id(
            &market_id,
            &account_commitment,
            operation_kind,
            &nullifier,
            requested_at_height,
            nonce,
        );
        let status = if sponsor_id.is_empty() {
            StablecoinOperationStatus::Pending
        } else {
            StablecoinOperationStatus::Sponsored
        };
        let operation = Self {
            operation_id,
            market_id,
            position_id,
            vault_id,
            operation_kind,
            account_commitment,
            asset_id,
            amount_bucket,
            amount_bucket_commitment,
            amount_commitment,
            supply_delta_commitment,
            fee_commitment,
            nullifier,
            recipient_commitment,
            quote_root,
            proof_root,
            sponsor_id,
            low_fee_lane,
            max_fee_units,
            requested_at_height,
            expires_at_height,
            nonce,
            status,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "mint_redeem_burn_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "operation_id": self.operation_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "vault_id": self.vault_id,
            "operation_kind": self.operation_kind.as_str(),
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "amount_bucket": self.amount_bucket.as_str(),
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "amount_commitment": self.amount_commitment,
            "supply_delta_commitment": self.supply_delta_commitment,
            "fee_commitment": self.fee_commitment,
            "nullifier": self.nullifier,
            "recipient_commitment": self.recipient_commitment,
            "quote_root": self.quote_root,
            "proof_root": self.proof_root,
            "sponsor_id": self.sponsor_id,
            "low_fee_lane": self.low_fee_lane,
            "max_fee_units": self.max_fee_units,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn amount_upper_bound_units(&self) -> u64 {
        self.amount_bucket.ceiling_units()
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.operation_id, "operation id")?;
        ensure_non_empty(&self.market_id, "operation market id")?;
        if !matches!(self.operation_kind, StablecoinOperationKind::Burn) {
            ensure_non_empty(&self.position_id, "operation position id")?;
            ensure_non_empty(&self.vault_id, "operation vault id")?;
        }
        ensure_non_empty(&self.account_commitment, "operation account commitment")?;
        ensure_non_empty(&self.asset_id, "operation asset id")?;
        ensure_non_empty(
            &self.amount_bucket_commitment,
            "operation amount bucket commitment",
        )?;
        ensure_non_empty(&self.amount_commitment, "operation amount commitment")?;
        ensure_non_empty(
            &self.supply_delta_commitment,
            "operation supply delta commitment",
        )?;
        ensure_non_empty(&self.fee_commitment, "operation fee commitment")?;
        ensure_non_empty(&self.nullifier, "operation nullifier")?;
        ensure_non_empty(&self.recipient_commitment, "operation recipient commitment")?;
        ensure_non_empty(&self.quote_root, "operation quote root")?;
        ensure_non_empty(&self.proof_root, "operation proof root")?;
        if self.expires_at_height <= self.requested_at_height {
            return Err("operation expiry must be after request height".to_string());
        }
        if !self.sponsor_id.is_empty() {
            ensure_non_empty(&self.low_fee_lane, "operation sponsored lane")?;
        }
        if self.operation_id
            != private_stablecoin_operation_id(
                &self.market_id,
                &self.account_commitment,
                self.operation_kind,
                &self.nullifier,
                self.requested_at_height,
                self.nonce,
            )
        {
            return Err("operation id mismatch".to_string());
        }
        Ok(self.operation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StablecoinSupplyCapSnapshot {
    pub cap_id: String,
    pub market_id: String,
    pub stable_asset_id: String,
    pub max_supply_units: u64,
    pub issued_units: u64,
    pub burned_units: u64,
    pub redeemed_units: u64,
    pub pending_mint_root: String,
    pub pending_burn_root: String,
    pub utilization_bps: u64,
    pub recorded_at_height: u64,
}

impl StablecoinSupplyCapSnapshot {
    pub fn from_market(market: &PrivateStablecoinMarket, recorded_at_height: u64) -> Self {
        let pending_mint_root =
            private_stablecoin_string_root("PRIVATE-STABLECOIN-PENDING-MINT", "empty");
        let pending_burn_root =
            private_stablecoin_string_root("PRIVATE-STABLECOIN-PENDING-BURN", "empty");
        let utilization_bps = if market.max_supply_units == 0 {
            0
        } else {
            ratio_bps(market.circulating_units(), market.max_supply_units)
        };
        let cap_id = private_stablecoin_supply_cap_id(
            &market.market_id,
            &market.stable_asset_id,
            market.max_supply_units,
            market.circulating_units(),
            recorded_at_height,
        );
        Self {
            cap_id,
            market_id: market.market_id.clone(),
            stable_asset_id: market.stable_asset_id.clone(),
            max_supply_units: market.max_supply_units,
            issued_units: market.issued_units,
            burned_units: market.burned_units,
            redeemed_units: market.redeemed_units,
            pending_mint_root,
            pending_burn_root,
            utilization_bps,
            recorded_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stablecoin_supply_cap_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "cap_id": self.cap_id,
            "market_id": self.market_id,
            "stable_asset_id": self.stable_asset_id,
            "max_supply_units": self.max_supply_units,
            "issued_units": self.issued_units,
            "burned_units": self.burned_units,
            "redeemed_units": self.redeemed_units,
            "circulating_units": self.circulating_units(),
            "pending_mint_root": self.pending_mint_root,
            "pending_burn_root": self.pending_burn_root,
            "utilization_bps": self.utilization_bps,
            "recorded_at_height": self.recorded_at_height,
        })
    }

    pub fn circulating_units(&self) -> u64 {
        self.issued_units
            .saturating_sub(self.burned_units)
            .saturating_sub(self.redeemed_units)
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.cap_id, "supply cap id")?;
        ensure_non_empty(&self.market_id, "supply cap market id")?;
        ensure_non_empty(&self.stable_asset_id, "supply cap stable asset")?;
        ensure_non_empty(&self.pending_mint_root, "supply cap pending mint root")?;
        ensure_non_empty(&self.pending_burn_root, "supply cap pending burn root")?;
        if self.max_supply_units == 0 {
            return Err("supply cap max supply must be non-zero".to_string());
        }
        if self.circulating_units() > self.max_supply_units {
            return Err("supply cap circulating supply exceeds max".to_string());
        }
        validate_bps(
            "supply cap utilization",
            self.utilization_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        if self.cap_id
            != private_stablecoin_supply_cap_id(
                &self.market_id,
                &self.stable_asset_id,
                self.max_supply_units,
                self.circulating_units(),
                self.recorded_at_height,
            )
        {
            return Err("supply cap id mismatch".to_string());
        }
        Ok(self.cap_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePriceRootCommitment {
    pub oracle_root_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub price_commitment: String,
    pub twap_commitment: String,
    pub confidence_bps: u64,
    pub source_root: String,
    pub posted_at_height: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub max_staleness_blocks: u64,
    pub attestation_root: String,
    pub status: OracleRootStatus,
}

impl OraclePriceRootCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        feed_id: impl Into<String>,
        price_units: u64,
        twap_units: u64,
        confidence_bps: u64,
        sources: &[Value],
        committee_label: impl Into<String>,
        posted_at_height: u64,
        observed_at_height: u64,
        max_staleness_blocks: u64,
        attestation_payload: &Value,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let feed_id = feed_id.into();
        let committee_label = committee_label.into();
        ensure_non_empty(&market_id, "oracle market id")?;
        ensure_non_empty(&feed_id, "oracle feed id")?;
        ensure_non_empty(&committee_label, "oracle committee label")?;
        if price_units == 0 || twap_units == 0 {
            return Err("oracle price and twap must be non-zero".to_string());
        }
        validate_bps(
            "oracle confidence bps",
            confidence_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        if max_staleness_blocks == 0 {
            return Err("oracle staleness window must be non-zero".to_string());
        }
        if posted_at_height < observed_at_height {
            return Err("oracle posted height cannot precede observed height".to_string());
        }
        let price_commitment = private_stablecoin_amount_commitment(
            "oracle_price",
            &price_units.to_string(),
            &feed_id,
        );
        let twap_commitment =
            private_stablecoin_amount_commitment("oracle_twap", &twap_units.to_string(), &feed_id);
        let source_root = merkle_root("PRIVATE-STABLECOIN-ORACLE-SOURCE", sources);
        let attestation_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-ORACLE-ATTESTATION",
            &json!({
                "committee": committee_label,
                "payload_root": private_stablecoin_payload_root("PRIVATE-STABLECOIN-ORACLE-ATTESTATION-PAYLOAD", attestation_payload),
                "pq_signature_scheme": PRIVATE_STABLECOIN_PQ_SIGNATURE_SCHEME,
            }),
        );
        let expires_at_height = observed_at_height.saturating_add(max_staleness_blocks);
        let oracle_root_id = private_stablecoin_oracle_root_id(
            &market_id,
            &feed_id,
            &price_commitment,
            observed_at_height,
            posted_at_height,
        );
        let oracle = Self {
            oracle_root_id,
            market_id,
            feed_id,
            price_commitment,
            twap_commitment,
            confidence_bps,
            source_root,
            posted_at_height,
            observed_at_height,
            expires_at_height,
            max_staleness_blocks,
            attestation_root,
            status: OracleRootStatus::Active,
        };
        oracle.validate()?;
        Ok(oracle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_price_root_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "oracle_root_id": self.oracle_root_id,
            "market_id": self.market_id,
            "feed_id": self.feed_id,
            "price_commitment": self.price_commitment,
            "twap_commitment": self.twap_commitment,
            "confidence_bps": self.confidence_bps,
            "source_root": self.source_root,
            "posted_at_height": self.posted_at_height,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "max_staleness_blocks": self.max_staleness_blocks,
            "attestation_root": self.attestation_root,
            "status": self.status.as_str(),
        })
    }

    pub fn is_stale_at(&self, height: u64) -> bool {
        height > self.expires_at_height || !matches!(self.status, OracleRootStatus::Active)
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.oracle_root_id, "oracle root id")?;
        ensure_non_empty(&self.market_id, "oracle market id")?;
        ensure_non_empty(&self.feed_id, "oracle feed id")?;
        ensure_non_empty(&self.price_commitment, "oracle price commitment")?;
        ensure_non_empty(&self.twap_commitment, "oracle twap commitment")?;
        ensure_non_empty(&self.source_root, "oracle source root")?;
        ensure_non_empty(&self.attestation_root, "oracle attestation root")?;
        validate_bps(
            "oracle confidence bps",
            self.confidence_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        if self.max_staleness_blocks == 0 {
            return Err("oracle max staleness must be non-zero".to_string());
        }
        if self.posted_at_height < self.observed_at_height {
            return Err("oracle posted height cannot precede observed height".to_string());
        }
        if self.expires_at_height
            < self
                .observed_at_height
                .saturating_add(self.max_staleness_blocks)
        {
            return Err("oracle expiry must include staleness window".to_string());
        }
        if self.oracle_root_id
            != private_stablecoin_oracle_root_id(
                &self.market_id,
                &self.feed_id,
                &self.price_commitment,
                self.observed_at_height,
                self.posted_at_height,
            )
        {
            return Err("oracle root id mismatch".to_string());
        }
        Ok(self.oracle_root_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralRatioBucketDisclosure {
    pub bucket_id: String,
    pub market_id: String,
    pub bucket: CollateralRatioBucket,
    pub position_count: u64,
    pub debt_bucket_root: String,
    pub collateral_bucket_root: String,
    pub position_commitment_root: String,
    pub proof_root: String,
    pub recorded_at_height: u64,
    pub expires_at_height: u64,
}

impl CollateralRatioBucketDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        bucket: CollateralRatioBucket,
        position_count: u64,
        debt_commitments: &[String],
        collateral_commitments: &[String],
        position_commitments: &[String],
        recorded_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        ensure_non_empty(&market_id, "bucket disclosure market id")?;
        let debt_bucket_root =
            private_stablecoin_string_list_root("PRIVATE-STABLECOIN-BUCKET-DEBT", debt_commitments);
        let collateral_bucket_root = private_stablecoin_string_list_root(
            "PRIVATE-STABLECOIN-BUCKET-COLLATERAL",
            collateral_commitments,
        );
        let position_commitment_root = private_stablecoin_string_list_root(
            "PRIVATE-STABLECOIN-BUCKET-POSITION",
            position_commitments,
        );
        let proof_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-BUCKET-PROOF",
            &json!({
                "scheme": PRIVATE_STABLECOIN_DISCLOSURE_SCHEME,
                "bucket": bucket.as_str(),
                "position_count": position_count,
                "position_commitment_root": position_commitment_root,
            }),
        );
        let bucket_id = private_stablecoin_bucket_disclosure_id(
            &market_id,
            bucket,
            &position_commitment_root,
            recorded_at_height,
        );
        let disclosure = Self {
            bucket_id,
            market_id,
            bucket,
            position_count,
            debt_bucket_root,
            collateral_bucket_root,
            position_commitment_root,
            proof_root,
            recorded_at_height,
            expires_at_height: recorded_at_height.saturating_add(ttl_blocks),
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "collateral_ratio_bucket_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "market_id": self.market_id,
            "bucket": self.bucket.as_str(),
            "position_count": self.position_count,
            "debt_bucket_root": self.debt_bucket_root,
            "collateral_bucket_root": self.collateral_bucket_root,
            "position_commitment_root": self.position_commitment_root,
            "proof_root": self.proof_root,
            "recorded_at_height": self.recorded_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.bucket_id, "bucket disclosure id")?;
        ensure_non_empty(&self.market_id, "bucket disclosure market id")?;
        ensure_non_empty(&self.debt_bucket_root, "bucket disclosure debt root")?;
        ensure_non_empty(
            &self.collateral_bucket_root,
            "bucket disclosure collateral root",
        )?;
        ensure_non_empty(
            &self.position_commitment_root,
            "bucket disclosure position root",
        )?;
        ensure_non_empty(&self.proof_root, "bucket disclosure proof root")?;
        if self.expires_at_height <= self.recorded_at_height {
            return Err("bucket disclosure expiry must be after record height".to_string());
        }
        if self.bucket_id
            != private_stablecoin_bucket_disclosure_id(
                &self.market_id,
                self.bucket,
                &self.position_commitment_root,
                self.recorded_at_height,
            )
        {
            return Err("bucket disclosure id mismatch".to_string());
        }
        Ok(self.bucket_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationQueueEntry {
    pub liquidation_id: String,
    pub market_id: String,
    pub position_id: String,
    pub vault_id: String,
    pub keeper_commitment: String,
    pub ratio_bucket_commitment: String,
    pub debt_commitment: String,
    pub collateral_commitment: String,
    pub oracle_root_id: String,
    pub evidence_root: String,
    pub queued_at_height: u64,
    pub challenge_ends_at_height: u64,
    pub nonce: u64,
    pub status: LiquidationQueueStatus,
}

impl LiquidationQueueEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        position_id: impl Into<String>,
        vault_id: impl Into<String>,
        keeper_label: impl Into<String>,
        ratio_bucket: CollateralRatioBucket,
        debt_bucket: impl Into<String>,
        collateral_bucket: impl Into<String>,
        oracle_root_id: impl Into<String>,
        evidence: &Value,
        queued_at_height: u64,
        challenge_window_blocks: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let position_id = position_id.into();
        let vault_id = vault_id.into();
        let keeper_label = keeper_label.into();
        let debt_bucket = debt_bucket.into();
        let collateral_bucket = collateral_bucket.into();
        let oracle_root_id = oracle_root_id.into();
        ensure_non_empty(&market_id, "liquidation market id")?;
        ensure_non_empty(&position_id, "liquidation position id")?;
        ensure_non_empty(&vault_id, "liquidation vault id")?;
        ensure_non_empty(&keeper_label, "liquidation keeper label")?;
        ensure_non_empty(&debt_bucket, "liquidation debt bucket")?;
        ensure_non_empty(&collateral_bucket, "liquidation collateral bucket")?;
        ensure_non_empty(&oracle_root_id, "liquidation oracle root")?;
        if !ratio_bucket.can_liquidate() {
            return Err("liquidation bucket must be liquidatable or insolvent".to_string());
        }
        if challenge_window_blocks == 0 {
            return Err("liquidation challenge window must be non-zero".to_string());
        }
        let keeper_commitment = private_stablecoin_account_commitment(&keeper_label);
        let ratio_bucket_commitment =
            private_stablecoin_bucket_commitment("liquidation_ratio", ratio_bucket.as_str());
        let debt_commitment =
            private_stablecoin_amount_commitment("liquidation_debt", &debt_bucket, &position_id);
        let collateral_commitment = private_stablecoin_amount_commitment(
            "liquidation_collateral",
            &collateral_bucket,
            &vault_id,
        );
        let evidence_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-LIQUIDATION-EVIDENCE", evidence);
        let liquidation_id = private_stablecoin_liquidation_id(
            &market_id,
            &position_id,
            &keeper_commitment,
            &evidence_root,
            queued_at_height,
            nonce,
        );
        let entry = Self {
            liquidation_id,
            market_id,
            position_id,
            vault_id,
            keeper_commitment,
            ratio_bucket_commitment,
            debt_commitment,
            collateral_commitment,
            oracle_root_id,
            evidence_root,
            queued_at_height,
            challenge_ends_at_height: queued_at_height.saturating_add(challenge_window_blocks),
            nonce,
            status: LiquidationQueueStatus::ChallengeOpen,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_queue_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "liquidation_id": self.liquidation_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "vault_id": self.vault_id,
            "keeper_commitment": self.keeper_commitment,
            "ratio_bucket_commitment": self.ratio_bucket_commitment,
            "debt_commitment": self.debt_commitment,
            "collateral_commitment": self.collateral_commitment,
            "oracle_root_id": self.oracle_root_id,
            "evidence_root": self.evidence_root,
            "queued_at_height": self.queued_at_height,
            "challenge_ends_at_height": self.challenge_ends_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn challenge_window_open_at(&self, height: u64) -> bool {
        height <= self.challenge_ends_at_height
            && matches!(self.status, LiquidationQueueStatus::ChallengeOpen)
    }

    pub fn executable_at(&self, height: u64) -> bool {
        height > self.challenge_ends_at_height
            && matches!(
                self.status,
                LiquidationQueueStatus::Queued
                    | LiquidationQueueStatus::ChallengeOpen
                    | LiquidationQueueStatus::Executable
            )
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.liquidation_id, "liquidation id")?;
        ensure_non_empty(&self.market_id, "liquidation market id")?;
        ensure_non_empty(&self.position_id, "liquidation position id")?;
        ensure_non_empty(&self.vault_id, "liquidation vault id")?;
        ensure_non_empty(&self.keeper_commitment, "liquidation keeper commitment")?;
        ensure_non_empty(
            &self.ratio_bucket_commitment,
            "liquidation ratio bucket commitment",
        )?;
        ensure_non_empty(&self.debt_commitment, "liquidation debt commitment")?;
        ensure_non_empty(
            &self.collateral_commitment,
            "liquidation collateral commitment",
        )?;
        ensure_non_empty(&self.oracle_root_id, "liquidation oracle root")?;
        ensure_non_empty(&self.evidence_root, "liquidation evidence root")?;
        if self.challenge_ends_at_height <= self.queued_at_height {
            return Err("liquidation challenge end must be after queue height".to_string());
        }
        if self.liquidation_id
            != private_stablecoin_liquidation_id(
                &self.market_id,
                &self.position_id,
                &self.keeper_commitment,
                &self.evidence_root,
                self.queued_at_height,
                self.nonce,
            )
        {
            return Err("liquidation id mismatch".to_string());
        }
        Ok(self.liquidation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationAuction {
    pub auction_id: String,
    pub liquidation_id: String,
    pub market_id: String,
    pub position_id: String,
    pub debt_to_cover_commitment: String,
    pub collateral_lot_commitment: String,
    pub start_price_commitment: String,
    pub floor_price_commitment: String,
    pub bid_root: String,
    pub clearing_root: String,
    pub reserve_take_commitment: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub challenge_ends_at_height: u64,
    pub nonce: u64,
    pub status: AuctionStatus,
}

impl PrivateLiquidationAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        liquidation_id: impl Into<String>,
        market_id: impl Into<String>,
        position_id: impl Into<String>,
        debt_bucket: impl Into<String>,
        collateral_bucket: impl Into<String>,
        start_price_bucket: impl Into<String>,
        floor_price_bucket: impl Into<String>,
        bid_commitments: &[String],
        opened_at_height: u64,
        ttl_blocks: u64,
        challenge_window_blocks: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let liquidation_id = liquidation_id.into();
        let market_id = market_id.into();
        let position_id = position_id.into();
        let debt_bucket = debt_bucket.into();
        let collateral_bucket = collateral_bucket.into();
        let start_price_bucket = start_price_bucket.into();
        let floor_price_bucket = floor_price_bucket.into();
        ensure_non_empty(&liquidation_id, "auction liquidation id")?;
        ensure_non_empty(&market_id, "auction market id")?;
        ensure_non_empty(&position_id, "auction position id")?;
        ensure_non_empty(&debt_bucket, "auction debt bucket")?;
        ensure_non_empty(&collateral_bucket, "auction collateral bucket")?;
        ensure_non_empty(&start_price_bucket, "auction start price bucket")?;
        ensure_non_empty(&floor_price_bucket, "auction floor price bucket")?;
        if ttl_blocks == 0 || challenge_window_blocks == 0 {
            return Err("auction ttl and challenge window must be non-zero".to_string());
        }
        let debt_to_cover_commitment =
            private_stablecoin_amount_commitment("auction_debt", &debt_bucket, &liquidation_id);
        let collateral_lot_commitment = private_stablecoin_amount_commitment(
            "auction_collateral",
            &collateral_bucket,
            &liquidation_id,
        );
        let start_price_commitment = private_stablecoin_amount_commitment(
            "auction_start_price",
            &start_price_bucket,
            &market_id,
        );
        let floor_price_commitment = private_stablecoin_amount_commitment(
            "auction_floor_price",
            &floor_price_bucket,
            &market_id,
        );
        let bid_root =
            private_stablecoin_string_list_root("PRIVATE-STABLECOIN-AUCTION-BID", bid_commitments);
        let clearing_root =
            private_stablecoin_string_root("PRIVATE-STABLECOIN-AUCTION-CLEARING", "pending");
        let reserve_take_commitment = private_stablecoin_amount_commitment(
            "auction_reserve_take",
            "pending",
            &liquidation_id,
        );
        let challenge_ends_at_height = opened_at_height.saturating_add(challenge_window_blocks);
        let closes_at_height = opened_at_height.saturating_add(ttl_blocks);
        let auction_id = private_stablecoin_auction_id(
            &liquidation_id,
            &market_id,
            &position_id,
            &debt_to_cover_commitment,
            opened_at_height,
            nonce,
        );
        let auction = Self {
            auction_id,
            liquidation_id,
            market_id,
            position_id,
            debt_to_cover_commitment,
            collateral_lot_commitment,
            start_price_commitment,
            floor_price_commitment,
            bid_root,
            clearing_root,
            reserve_take_commitment,
            opened_at_height,
            closes_at_height,
            challenge_ends_at_height,
            nonce,
            status: AuctionStatus::ChallengeOpen,
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidation_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "liquidation_id": self.liquidation_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "debt_to_cover_commitment": self.debt_to_cover_commitment,
            "collateral_lot_commitment": self.collateral_lot_commitment,
            "start_price_commitment": self.start_price_commitment,
            "floor_price_commitment": self.floor_price_commitment,
            "bid_root": self.bid_root,
            "clearing_root": self.clearing_root,
            "reserve_take_commitment": self.reserve_take_commitment,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "challenge_ends_at_height": self.challenge_ends_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn refresh_status(&mut self, height: u64) {
        if matches!(
            self.status,
            AuctionStatus::Settled | AuctionStatus::Cancelled
        ) {
            return;
        }
        if height > self.closes_at_height {
            self.status = AuctionStatus::Expired;
        } else if height > self.challenge_ends_at_height {
            self.status = AuctionStatus::Open;
        }
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.liquidation_id, "auction liquidation id")?;
        ensure_non_empty(&self.market_id, "auction market id")?;
        ensure_non_empty(&self.position_id, "auction position id")?;
        ensure_non_empty(&self.debt_to_cover_commitment, "auction debt commitment")?;
        ensure_non_empty(
            &self.collateral_lot_commitment,
            "auction collateral lot commitment",
        )?;
        ensure_non_empty(
            &self.start_price_commitment,
            "auction start price commitment",
        )?;
        ensure_non_empty(
            &self.floor_price_commitment,
            "auction floor price commitment",
        )?;
        ensure_non_empty(&self.bid_root, "auction bid root")?;
        ensure_non_empty(&self.clearing_root, "auction clearing root")?;
        ensure_non_empty(
            &self.reserve_take_commitment,
            "auction reserve take commitment",
        )?;
        if self.challenge_ends_at_height <= self.opened_at_height {
            return Err("auction challenge end must be after open height".to_string());
        }
        if self.closes_at_height <= self.challenge_ends_at_height {
            return Err("auction close must be after challenge end".to_string());
        }
        if self.auction_id
            != private_stablecoin_auction_id(
                &self.liquidation_id,
                &self.market_id,
                &self.position_id,
                &self.debt_to_cover_commitment,
                self.opened_at_height,
                self.nonce,
            )
        {
            return Err("auction id mismatch".to_string());
        }
        Ok(self.auction_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationChallenge {
    pub challenge_id: String,
    pub liquidation_id: String,
    pub auction_id: String,
    pub challenger_commitment: String,
    pub bond_commitment: String,
    pub claim_root: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ChallengeStatus,
}

impl LiquidationChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        liquidation_id: impl Into<String>,
        auction_id: impl Into<String>,
        challenger_label: impl Into<String>,
        bond_bucket: impl Into<String>,
        claim: &Value,
        evidence: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateStablecoinResult<Self> {
        let liquidation_id = liquidation_id.into();
        let auction_id = auction_id.into();
        let challenger_label = challenger_label.into();
        let bond_bucket = bond_bucket.into();
        ensure_non_empty(&liquidation_id, "challenge liquidation id")?;
        ensure_non_empty(&challenger_label, "challenge challenger label")?;
        ensure_non_empty(&bond_bucket, "challenge bond bucket")?;
        if expires_at_height <= opened_at_height {
            return Err("challenge expiry must be after open height".to_string());
        }
        let challenger_commitment = private_stablecoin_account_commitment(&challenger_label);
        let bond_commitment = private_stablecoin_amount_commitment(
            "liquidation_challenge_bond",
            &bond_bucket,
            &challenger_commitment,
        );
        let claim_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-CHALLENGE-CLAIM", claim);
        let evidence_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-CHALLENGE-EVIDENCE", evidence);
        let challenge_id = private_stablecoin_challenge_id(
            &liquidation_id,
            &auction_id,
            &challenger_commitment,
            &claim_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            liquidation_id,
            auction_id,
            challenger_commitment,
            bond_commitment,
            claim_root,
            evidence_root,
            opened_at_height,
            expires_at_height,
            status: ChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "liquidation_id": self.liquidation_id,
            "auction_id": self.auction_id,
            "challenger_commitment": self.challenger_commitment,
            "bond_commitment": self.bond_commitment,
            "claim_root": self.claim_root,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height && matches!(self.status, ChallengeStatus::Open)
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.liquidation_id, "challenge liquidation id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        ensure_non_empty(&self.bond_commitment, "challenge bond commitment")?;
        ensure_non_empty(&self.claim_root, "challenge claim root")?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("challenge expiry must be after open height".to_string());
        }
        if self.challenge_id
            != private_stablecoin_challenge_id(
                &self.liquidation_id,
                &self.auction_id,
                &self.challenger_commitment,
                &self.claim_root,
                self.opened_at_height,
            )
        {
            return Err("challenge id mismatch".to_string());
        }
        Ok(self.challenge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabilityFeeAccrual {
    pub accrual_id: String,
    pub market_id: String,
    pub position_id: String,
    pub event_kind: StabilityFeeEventKind,
    pub debt_commitment: String,
    pub fee_index_before: u64,
    pub fee_index_after: u64,
    pub annual_rate_bps: u64,
    pub elapsed_blocks: u64,
    pub fee_commitment: String,
    pub reserve_share_commitment: String,
    pub protocol_share_commitment: String,
    pub reserve_factor_bps: u64,
    pub recorded_at_height: u64,
}

impl StabilityFeeAccrual {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        position_id: impl Into<String>,
        event_kind: StabilityFeeEventKind,
        debt_bucket: impl Into<String>,
        fee_index_before: u64,
        annual_rate_bps: u64,
        elapsed_blocks: u64,
        reserve_factor_bps: u64,
        recorded_at_height: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let position_id = position_id.into();
        let debt_bucket = debt_bucket.into();
        ensure_non_empty(&market_id, "fee accrual market id")?;
        ensure_non_empty(&debt_bucket, "fee accrual debt bucket")?;
        if fee_index_before == 0 {
            return Err("fee accrual index before must be non-zero".to_string());
        }
        validate_bps("fee accrual annual rate", annual_rate_bps, 100_000)?;
        validate_bps(
            "fee accrual reserve factor",
            reserve_factor_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        let index_delta = annualized_bps_accrual(
            PRIVATE_STABLECOIN_INDEX_SCALE,
            annual_rate_bps,
            elapsed_blocks,
        );
        let fee_index_after = fee_index_before.saturating_add(index_delta);
        let debt_commitment =
            private_stablecoin_amount_commitment("fee_accrual_debt", &debt_bucket, &market_id);
        let fee_commitment = private_stablecoin_amount_commitment(
            "stability_fee",
            &format!("index_delta:{index_delta}"),
            &debt_commitment,
        );
        let reserve_share_commitment = private_stablecoin_amount_commitment(
            "stability_fee_reserve_share",
            &reserve_factor_bps.to_string(),
            &fee_commitment,
        );
        let protocol_share_commitment = private_stablecoin_amount_commitment(
            "stability_fee_protocol_share",
            &PRIVATE_STABLECOIN_MAX_BPS
                .saturating_sub(reserve_factor_bps)
                .to_string(),
            &fee_commitment,
        );
        let accrual_id = private_stablecoin_fee_accrual_id(
            &market_id,
            &position_id,
            event_kind,
            &fee_commitment,
            recorded_at_height,
            nonce,
        );
        let accrual = Self {
            accrual_id,
            market_id,
            position_id,
            event_kind,
            debt_commitment,
            fee_index_before,
            fee_index_after,
            annual_rate_bps,
            elapsed_blocks,
            fee_commitment,
            reserve_share_commitment,
            protocol_share_commitment,
            reserve_factor_bps,
            recorded_at_height,
        };
        accrual.validate()?;
        Ok(accrual)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stability_fee_accrual",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "accrual_id": self.accrual_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "event_kind": self.event_kind.as_str(),
            "debt_commitment": self.debt_commitment,
            "fee_index_before": self.fee_index_before,
            "fee_index_after": self.fee_index_after,
            "annual_rate_bps": self.annual_rate_bps,
            "elapsed_blocks": self.elapsed_blocks,
            "fee_commitment": self.fee_commitment,
            "reserve_share_commitment": self.reserve_share_commitment,
            "protocol_share_commitment": self.protocol_share_commitment,
            "reserve_factor_bps": self.reserve_factor_bps,
            "recorded_at_height": self.recorded_at_height,
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.accrual_id, "fee accrual id")?;
        ensure_non_empty(&self.market_id, "fee accrual market id")?;
        ensure_non_empty(&self.debt_commitment, "fee accrual debt commitment")?;
        ensure_non_empty(&self.fee_commitment, "fee accrual fee commitment")?;
        ensure_non_empty(
            &self.reserve_share_commitment,
            "fee accrual reserve share commitment",
        )?;
        ensure_non_empty(
            &self.protocol_share_commitment,
            "fee accrual protocol share commitment",
        )?;
        if self.fee_index_before == 0 || self.fee_index_after < self.fee_index_before {
            return Err("fee accrual index must be monotonic".to_string());
        }
        validate_bps("fee accrual annual rate", self.annual_rate_bps, 100_000)?;
        validate_bps(
            "fee accrual reserve factor",
            self.reserve_factor_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        Ok(self.accrual_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveFundAccounting {
    pub fund_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub controller_commitment: String,
    pub balance_commitment: String,
    pub balance_floor_units: u64,
    pub target_ratio_bps: u64,
    pub accrued_fee_commitment: String,
    pub liquidation_payout_commitment: String,
    pub global_settlement_commitment: String,
    pub sponsor_root: String,
    pub last_accounting_height: u64,
    pub status: String,
}

impl ReserveFundAccounting {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        asset_id: impl Into<String>,
        controller_label: impl Into<String>,
        balance_bucket: impl Into<String>,
        balance_floor_units: u64,
        target_ratio_bps: u64,
        sponsors: &[Value],
        last_accounting_height: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let asset_id = asset_id.into();
        let controller_label = controller_label.into();
        let balance_bucket = balance_bucket.into();
        ensure_non_empty(&market_id, "reserve fund market id")?;
        ensure_non_empty(&asset_id, "reserve fund asset id")?;
        ensure_non_empty(&controller_label, "reserve fund controller")?;
        ensure_non_empty(&balance_bucket, "reserve fund balance bucket")?;
        validate_bps(
            "reserve fund target ratio",
            target_ratio_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        let controller_commitment = private_stablecoin_account_commitment(&controller_label);
        let balance_commitment = private_stablecoin_amount_commitment(
            "reserve_balance",
            &balance_bucket,
            &controller_commitment,
        );
        let accrued_fee_commitment =
            private_stablecoin_amount_commitment("reserve_accrued_fee", "none", &market_id);
        let liquidation_payout_commitment =
            private_stablecoin_amount_commitment("reserve_liquidation_payout", "none", &market_id);
        let global_settlement_commitment =
            private_stablecoin_amount_commitment("reserve_global_settlement", "none", &market_id);
        let sponsor_root = merkle_root("PRIVATE-STABLECOIN-RESERVE-SPONSOR", sponsors);
        let fund_id = private_stablecoin_reserve_fund_id(
            &market_id,
            &asset_id,
            &controller_commitment,
            &balance_commitment,
        );
        let fund = Self {
            fund_id,
            market_id,
            asset_id,
            controller_commitment,
            balance_commitment,
            balance_floor_units,
            target_ratio_bps,
            accrued_fee_commitment,
            liquidation_payout_commitment,
            global_settlement_commitment,
            sponsor_root,
            last_accounting_height,
            status: "active".to_string(),
        };
        fund.validate()?;
        Ok(fund)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_fund_accounting",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "fund_id": self.fund_id,
            "market_id": self.market_id,
            "asset_id": self.asset_id,
            "controller_commitment": self.controller_commitment,
            "balance_commitment": self.balance_commitment,
            "balance_floor_units": self.balance_floor_units,
            "target_ratio_bps": self.target_ratio_bps,
            "accrued_fee_commitment": self.accrued_fee_commitment,
            "liquidation_payout_commitment": self.liquidation_payout_commitment,
            "global_settlement_commitment": self.global_settlement_commitment,
            "sponsor_root": self.sponsor_root,
            "last_accounting_height": self.last_accounting_height,
            "status": self.status,
        })
    }

    pub fn coverage_bps(&self, circulating_units: u64) -> u64 {
        if circulating_units == 0 {
            PRIVATE_STABLECOIN_MAX_BPS
        } else {
            ratio_bps(self.balance_floor_units, circulating_units)
        }
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.fund_id, "reserve fund id")?;
        ensure_non_empty(&self.market_id, "reserve fund market id")?;
        ensure_non_empty(&self.asset_id, "reserve fund asset id")?;
        ensure_non_empty(
            &self.controller_commitment,
            "reserve fund controller commitment",
        )?;
        ensure_non_empty(&self.balance_commitment, "reserve fund balance commitment")?;
        ensure_non_empty(
            &self.accrued_fee_commitment,
            "reserve fund accrued fee commitment",
        )?;
        ensure_non_empty(
            &self.liquidation_payout_commitment,
            "reserve fund liquidation payout commitment",
        )?;
        ensure_non_empty(
            &self.global_settlement_commitment,
            "reserve fund settlement commitment",
        )?;
        ensure_non_empty(&self.sponsor_root, "reserve fund sponsor root")?;
        ensure_status(&self.status, &["active", "draining", "settling", "retired"])?;
        validate_bps(
            "reserve fund target ratio",
            self.target_ratio_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        if self.fund_id
            != private_stablecoin_reserve_fund_id(
                &self.market_id,
                &self.asset_id,
                &self.controller_commitment,
                &self.balance_commitment,
            )
        {
            return Err("reserve fund id mismatch".to_string());
        }
        Ok(self.fund_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskCommitteeAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub member_commitment: String,
    pub market_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub decision: RiskDecision,
    pub severity: RiskSeverity,
    pub risk_score_bps: u64,
    pub payload_root: String,
    pub pq_signature_root: String,
    pub signature_scheme: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRiskCommitteeAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        committee_id: impl Into<String>,
        member_label: impl Into<String>,
        market_id: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        decision: RiskDecision,
        severity: RiskSeverity,
        risk_score_bps: u64,
        payload: &Value,
        pq_signature: &Value,
        attested_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateStablecoinResult<Self> {
        let committee_id = committee_id.into();
        let member_label = member_label.into();
        let market_id = market_id.into();
        let subject_kind = normalize_label(subject_kind.into());
        let subject_id = subject_id.into();
        ensure_non_empty(&committee_id, "attestation committee id")?;
        ensure_non_empty(&member_label, "attestation member label")?;
        ensure_non_empty(&market_id, "attestation market id")?;
        ensure_non_empty(&subject_kind, "attestation subject kind")?;
        ensure_non_empty(&subject_id, "attestation subject id")?;
        if expires_at_height <= attested_at_height {
            return Err("attestation expiry must be after attestation height".to_string());
        }
        validate_bps(
            "attestation risk score",
            risk_score_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        let member_commitment = private_stablecoin_account_commitment(&member_label);
        let payload_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-PQ-ATTESTATION-PAYLOAD", payload);
        let pq_signature_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-PQ-SIGNATURE", pq_signature);
        let signature_scheme = PRIVATE_STABLECOIN_PQ_SIGNATURE_SCHEME.to_string();
        let attestation_id = private_stablecoin_attestation_id(
            &committee_id,
            &member_commitment,
            &market_id,
            &subject_kind,
            &subject_id,
            &payload_root,
            attested_at_height,
        );
        let attestation = Self {
            attestation_id,
            committee_id,
            member_commitment,
            market_id,
            subject_kind,
            subject_id,
            decision,
            severity,
            risk_score_bps,
            payload_root,
            pq_signature_root,
            signature_scheme,
            attested_at_height,
            expires_at_height,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_risk_committee_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "member_commitment": self.member_commitment,
            "market_id": self.market_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "decision": self.decision.as_str(),
            "severity": self.severity.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "payload_root": self.payload_root,
            "pq_signature_root": self.pq_signature_root,
            "signature_scheme": self.signature_scheme,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.committee_id, "attestation committee id")?;
        ensure_non_empty(&self.member_commitment, "attestation member commitment")?;
        ensure_non_empty(&self.market_id, "attestation market id")?;
        ensure_non_empty(&self.subject_kind, "attestation subject kind")?;
        ensure_non_empty(&self.subject_id, "attestation subject id")?;
        ensure_non_empty(&self.payload_root, "attestation payload root")?;
        ensure_non_empty(&self.pq_signature_root, "attestation signature root")?;
        ensure_non_empty(&self.signature_scheme, "attestation signature scheme")?;
        validate_bps(
            "attestation risk score",
            self.risk_score_bps,
            PRIVATE_STABLECOIN_MAX_BPS,
        )?;
        if self.expires_at_height <= self.attested_at_height {
            return Err("attestation expiry must be after attestation height".to_string());
        }
        if self.signature_scheme != PRIVATE_STABLECOIN_PQ_SIGNATURE_SCHEME {
            return Err("attestation signature scheme mismatch".to_string());
        }
        if self.attestation_id
            != private_stablecoin_attestation_id(
                &self.committee_id,
                &self.member_commitment,
                &self.market_id,
                &self.subject_kind,
                &self.subject_id,
                &self.payload_root,
                self.attested_at_height,
            )
        {
            return Err("attestation id mismatch".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyGlobalSettlement {
    pub settlement_id: String,
    pub market_id: String,
    pub initiator_commitment: String,
    pub settlement_price_root: String,
    pub reserve_snapshot_root: String,
    pub debt_snapshot_root: String,
    pub bucket_payout_root: String,
    pub attestation_root: String,
    pub initiated_at_height: u64,
    pub challenge_ends_at_height: u64,
    pub finalizes_at_height: u64,
    pub status: GlobalSettlementStatus,
}

impl EmergencyGlobalSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        initiator_label: impl Into<String>,
        settlement_price: &Value,
        reserve_snapshot: &Value,
        debt_snapshot: &Value,
        bucket_payouts: &[Value],
        attestation_root: impl Into<String>,
        initiated_at_height: u64,
        challenge_window_blocks: u64,
        settlement_delay_blocks: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let initiator_label = initiator_label.into();
        let attestation_root = attestation_root.into();
        ensure_non_empty(&market_id, "global settlement market id")?;
        ensure_non_empty(&initiator_label, "global settlement initiator")?;
        ensure_non_empty(&attestation_root, "global settlement attestation root")?;
        if challenge_window_blocks == 0 || settlement_delay_blocks == 0 {
            return Err("global settlement windows must be non-zero".to_string());
        }
        let initiator_commitment = private_stablecoin_account_commitment(&initiator_label);
        let settlement_price_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-GLOBAL-SETTLEMENT-PRICE",
            settlement_price,
        );
        let reserve_snapshot_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-GLOBAL-SETTLEMENT-RESERVE",
            reserve_snapshot,
        );
        let debt_snapshot_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-GLOBAL-SETTLEMENT-DEBT",
            debt_snapshot,
        );
        let bucket_payout_root = merkle_root(
            "PRIVATE-STABLECOIN-GLOBAL-SETTLEMENT-BUCKET-PAYOUT",
            bucket_payouts,
        );
        let challenge_ends_at_height = initiated_at_height.saturating_add(challenge_window_blocks);
        let finalizes_at_height = initiated_at_height.saturating_add(settlement_delay_blocks);
        let settlement_id = private_stablecoin_global_settlement_id(
            &market_id,
            &initiator_commitment,
            &settlement_price_root,
            initiated_at_height,
        );
        let settlement = Self {
            settlement_id,
            market_id,
            initiator_commitment,
            settlement_price_root,
            reserve_snapshot_root,
            debt_snapshot_root,
            bucket_payout_root,
            attestation_root,
            initiated_at_height,
            challenge_ends_at_height,
            finalizes_at_height,
            status: GlobalSettlementStatus::ChallengeOpen,
        };
        settlement.validate()?;
        Ok(settlement)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_global_settlement",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "settlement_id": self.settlement_id,
            "market_id": self.market_id,
            "initiator_commitment": self.initiator_commitment,
            "settlement_price_root": self.settlement_price_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "debt_snapshot_root": self.debt_snapshot_root,
            "bucket_payout_root": self.bucket_payout_root,
            "attestation_root": self.attestation_root,
            "initiated_at_height": self.initiated_at_height,
            "challenge_ends_at_height": self.challenge_ends_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height > self.challenge_ends_at_height
            && matches!(
                self.status,
                GlobalSettlementStatus::ChallengeOpen | GlobalSettlementStatus::Active
            )
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.settlement_id, "global settlement id")?;
        ensure_non_empty(&self.market_id, "global settlement market id")?;
        ensure_non_empty(
            &self.initiator_commitment,
            "global settlement initiator commitment",
        )?;
        ensure_non_empty(&self.settlement_price_root, "global settlement price root")?;
        ensure_non_empty(
            &self.reserve_snapshot_root,
            "global settlement reserve root",
        )?;
        ensure_non_empty(&self.debt_snapshot_root, "global settlement debt root")?;
        ensure_non_empty(
            &self.bucket_payout_root,
            "global settlement bucket payout root",
        )?;
        ensure_non_empty(&self.attestation_root, "global settlement attestation root")?;
        if self.challenge_ends_at_height <= self.initiated_at_height {
            return Err("global settlement challenge end must be after initiation".to_string());
        }
        if self.finalizes_at_height <= self.initiated_at_height {
            return Err("global settlement finalize height must be after initiation".to_string());
        }
        if self.settlement_id
            != private_stablecoin_global_settlement_id(
                &self.market_id,
                &self.initiator_commitment,
                &self.settlement_price_root,
                self.initiated_at_height,
            )
        {
            return Err("global settlement id mismatch".to_string());
        }
        Ok(self.settlement_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeStablecoinSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub market_id: String,
    pub operation_kind: StablecoinOperationKind,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub max_notional_units: u64,
    pub budget_commitment: String,
    pub max_fee_units: u64,
    pub uses_remaining: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeStablecoinSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: impl Into<String>,
        beneficiary_label: impl Into<String>,
        market_id: impl Into<String>,
        operation_kind: StablecoinOperationKind,
        low_fee_lane: impl Into<String>,
        fee_asset_id: impl Into<String>,
        max_notional_units: u64,
        budget_bucket: impl Into<String>,
        max_fee_units: u64,
        uses_remaining: u64,
        reserved_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let sponsor_label = sponsor_label.into();
        let beneficiary_label = beneficiary_label.into();
        let market_id = market_id.into();
        let low_fee_lane = low_fee_lane.into();
        let fee_asset_id = fee_asset_id.into();
        let budget_bucket = budget_bucket.into();
        ensure_non_empty(&sponsor_label, "sponsorship sponsor")?;
        ensure_non_empty(&beneficiary_label, "sponsorship beneficiary")?;
        ensure_non_empty(&market_id, "sponsorship market id")?;
        ensure_non_empty(&low_fee_lane, "sponsorship low fee lane")?;
        ensure_non_empty(&fee_asset_id, "sponsorship fee asset")?;
        ensure_non_empty(&budget_bucket, "sponsorship budget bucket")?;
        if max_notional_units == 0 || max_fee_units == 0 || uses_remaining == 0 {
            return Err("sponsorship limits must be non-zero".to_string());
        }
        if expires_at_height <= reserved_at_height {
            return Err("sponsorship expiry must be after reservation".to_string());
        }
        let sponsor_commitment = private_stablecoin_account_commitment(&sponsor_label);
        let beneficiary_commitment = private_stablecoin_account_commitment(&beneficiary_label);
        let budget_commitment = private_stablecoin_amount_commitment(
            "sponsorship_budget",
            &budget_bucket,
            &sponsor_commitment,
        );
        let sponsorship_id = private_stablecoin_sponsorship_id(
            &sponsor_commitment,
            &beneficiary_commitment,
            &market_id,
            operation_kind,
            reserved_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            beneficiary_commitment,
            market_id,
            operation_kind,
            low_fee_lane,
            fee_asset_id,
            max_notional_units,
            budget_commitment,
            max_fee_units,
            uses_remaining,
            reserved_at_height,
            expires_at_height,
            nonce,
            status: SponsorshipStatus::Active,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_stablecoin_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "market_id": self.market_id,
            "operation_kind": self.operation_kind.as_str(),
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "max_notional_units": self.max_notional_units,
            "budget_commitment": self.budget_commitment,
            "max_fee_units": self.max_fee_units,
            "uses_remaining": self.uses_remaining,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
            && self.uses_remaining > 0
            && matches!(
                self.status,
                SponsorshipStatus::Active | SponsorshipStatus::Reserved
            )
    }

    pub fn supports(&self, operation: &MintRedeemBurnCommitment, height: u64) -> bool {
        self.is_active_at(height)
            && self.market_id == operation.market_id
            && self.operation_kind == operation.operation_kind
            && self.low_fee_lane == operation.low_fee_lane
            && self.beneficiary_commitment == operation.account_commitment
            && operation.amount_upper_bound_units() <= self.max_notional_units
            && operation.max_fee_units <= self.max_fee_units
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor commitment")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship beneficiary commitment",
        )?;
        ensure_non_empty(&self.market_id, "sponsorship market id")?;
        ensure_non_empty(&self.low_fee_lane, "sponsorship low fee lane")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        ensure_non_empty(&self.budget_commitment, "sponsorship budget commitment")?;
        if self.max_notional_units == 0 || self.max_fee_units == 0 {
            return Err("sponsorship limits must be non-zero".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err("sponsorship expiry must be after reservation".to_string());
        }
        if self.sponsorship_id
            != private_stablecoin_sponsorship_id(
                &self.sponsor_commitment,
                &self.beneficiary_commitment,
                &self.market_id,
                self.operation_kind,
                self.reserved_at_height,
                self.nonce,
            )
        {
            return Err("sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAdapterRoot {
    pub adapter_id: String,
    pub market_id: String,
    pub adapter_kind: String,
    pub contract_id: String,
    pub selector_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub event_root: String,
    pub token_registry_root: String,
    pub privacy_adapter_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: AdapterStatus,
}

impl ContractAdapterRoot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        adapter_kind: impl Into<String>,
        contract_id: impl Into<String>,
        selectors: &[Value],
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
        events: &[Value],
        token_registry_root: impl Into<String>,
        privacy_adapter_root: impl Into<String>,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let adapter_kind = normalize_label(adapter_kind.into());
        let contract_id = contract_id.into();
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let token_registry_root = token_registry_root.into();
        let privacy_adapter_root = privacy_adapter_root.into();
        ensure_non_empty(&market_id, "adapter market id")?;
        ensure_non_empty(&adapter_kind, "adapter kind")?;
        ensure_non_empty(&contract_id, "adapter contract id")?;
        ensure_non_empty(&pre_state_root, "adapter pre state root")?;
        ensure_non_empty(&post_state_root, "adapter post state root")?;
        ensure_non_empty(&token_registry_root, "adapter token registry root")?;
        ensure_non_empty(&privacy_adapter_root, "adapter privacy root")?;
        if expires_at_height <= valid_from_height {
            return Err("adapter expiry must be after valid-from height".to_string());
        }
        let selector_root = merkle_root("PRIVATE-STABLECOIN-CONTRACT-SELECTOR", selectors);
        let event_root = merkle_root("PRIVATE-STABLECOIN-CONTRACT-EVENT", events);
        let adapter_id = private_stablecoin_contract_adapter_id(
            &market_id,
            &adapter_kind,
            &contract_id,
            &selector_root,
            valid_from_height,
        );
        let adapter = Self {
            adapter_id,
            market_id,
            adapter_kind,
            contract_id,
            selector_root,
            pre_state_root,
            post_state_root,
            event_root,
            token_registry_root,
            privacy_adapter_root,
            valid_from_height,
            expires_at_height,
            status: AdapterStatus::Active,
        };
        adapter.validate()?;
        Ok(adapter)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_adapter_root",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "adapter_id": self.adapter_id,
            "market_id": self.market_id,
            "adapter_kind": self.adapter_kind,
            "contract_id": self.contract_id,
            "selector_root": self.selector_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "event_root": self.event_root,
            "token_registry_root": self.token_registry_root,
            "privacy_adapter_root": self.privacy_adapter_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.adapter_id, "adapter id")?;
        ensure_non_empty(&self.market_id, "adapter market id")?;
        ensure_non_empty(&self.adapter_kind, "adapter kind")?;
        ensure_non_empty(&self.contract_id, "adapter contract id")?;
        ensure_non_empty(&self.selector_root, "adapter selector root")?;
        ensure_non_empty(&self.pre_state_root, "adapter pre state root")?;
        ensure_non_empty(&self.post_state_root, "adapter post state root")?;
        ensure_non_empty(&self.event_root, "adapter event root")?;
        ensure_non_empty(&self.token_registry_root, "adapter token registry root")?;
        ensure_non_empty(&self.privacy_adapter_root, "adapter privacy root")?;
        if self.expires_at_height <= self.valid_from_height {
            return Err("adapter expiry must be after valid-from height".to_string());
        }
        if self.adapter_id
            != private_stablecoin_contract_adapter_id(
                &self.market_id,
                &self.adapter_kind,
                &self.contract_id,
                &self.selector_root,
                self.valid_from_height,
            )
        {
            return Err("adapter id mismatch".to_string());
        }
        Ok(self.adapter_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryHook {
    pub hook_id: String,
    pub market_id: String,
    pub stable_asset_id: String,
    pub factory_contract_id: String,
    pub hook_kind: TokenFactoryHookKind,
    pub token_metadata_root: String,
    pub supply_cap_root: String,
    pub permissions_root: String,
    pub issuer_commitment: String,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub status: AdapterStatus,
}

impl TokenFactoryHook {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        stable_asset_id: impl Into<String>,
        factory_contract_id: impl Into<String>,
        hook_kind: TokenFactoryHookKind,
        token_metadata: &Value,
        supply_cap_root: impl Into<String>,
        permissions: &[Value],
        issuer_label: impl Into<String>,
        registered_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let stable_asset_id = stable_asset_id.into();
        let factory_contract_id = factory_contract_id.into();
        let supply_cap_root = supply_cap_root.into();
        let issuer_label = issuer_label.into();
        ensure_non_empty(&market_id, "token hook market id")?;
        ensure_non_empty(&stable_asset_id, "token hook stable asset")?;
        ensure_non_empty(&factory_contract_id, "token hook factory contract")?;
        ensure_non_empty(&supply_cap_root, "token hook supply cap root")?;
        ensure_non_empty(&issuer_label, "token hook issuer")?;
        if expires_at_height <= registered_at_height {
            return Err("token hook expiry must be after registration".to_string());
        }
        let token_metadata_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-TOKEN-METADATA", token_metadata);
        let permissions_root = merkle_root("PRIVATE-STABLECOIN-TOKEN-PERMISSION", permissions);
        let issuer_commitment = private_stablecoin_account_commitment(&issuer_label);
        let hook_id = private_stablecoin_token_hook_id(
            &market_id,
            &stable_asset_id,
            &factory_contract_id,
            hook_kind,
            registered_at_height,
        );
        let hook = Self {
            hook_id,
            market_id,
            stable_asset_id,
            factory_contract_id,
            hook_kind,
            token_metadata_root,
            supply_cap_root,
            permissions_root,
            issuer_commitment,
            registered_at_height,
            expires_at_height,
            status: AdapterStatus::Active,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "hook_id": self.hook_id,
            "market_id": self.market_id,
            "stable_asset_id": self.stable_asset_id,
            "factory_contract_id": self.factory_contract_id,
            "hook_kind": self.hook_kind.as_str(),
            "token_metadata_root": self.token_metadata_root,
            "supply_cap_root": self.supply_cap_root,
            "permissions_root": self.permissions_root,
            "issuer_commitment": self.issuer_commitment,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.hook_id, "token hook id")?;
        ensure_non_empty(&self.market_id, "token hook market id")?;
        ensure_non_empty(&self.stable_asset_id, "token hook stable asset")?;
        ensure_non_empty(&self.factory_contract_id, "token hook factory contract")?;
        ensure_non_empty(&self.token_metadata_root, "token hook metadata root")?;
        ensure_non_empty(&self.supply_cap_root, "token hook supply cap root")?;
        ensure_non_empty(&self.permissions_root, "token hook permissions root")?;
        ensure_non_empty(&self.issuer_commitment, "token hook issuer commitment")?;
        if self.expires_at_height <= self.registered_at_height {
            return Err("token hook expiry must be after registration".to_string());
        }
        if self.hook_id
            != private_stablecoin_token_hook_id(
                &self.market_id,
                &self.stable_asset_id,
                &self.factory_contract_id,
                self.hook_kind,
                self.registered_at_height,
            )
        {
            return Err("token hook id mismatch".to_string());
        }
        Ok(self.hook_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBucketDisclosure {
    pub disclosure_id: String,
    pub market_id: String,
    pub scope: PrivacyDisclosureScope,
    pub viewer_commitment: String,
    pub bucket_root: String,
    pub ratio_bucket_root: String,
    pub operation_bucket_root: String,
    pub reserve_bucket_root: String,
    pub revealed_field_root: String,
    pub statement_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PrivacyBucketDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        scope: PrivacyDisclosureScope,
        viewer_label: impl Into<String>,
        buckets: &[Value],
        revealed_fields: &[String],
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateStablecoinResult<Self> {
        let market_id = market_id.into();
        let viewer_label = viewer_label.into();
        ensure_non_empty(&market_id, "privacy disclosure market id")?;
        ensure_non_empty(&viewer_label, "privacy disclosure viewer")?;
        if ttl_blocks == 0 {
            return Err("privacy disclosure ttl must be non-zero".to_string());
        }
        let viewer_commitment = private_stablecoin_account_commitment(&viewer_label);
        let bucket_root = merkle_root("PRIVATE-STABLECOIN-DISCLOSURE-BUCKET", buckets);
        let ratio_bucket_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-DISCLOSURE-RATIO-BUCKETS",
            &json!({ "scope": scope.as_str(), "bucket_root": bucket_root }),
        );
        let operation_bucket_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-DISCLOSURE-OPERATION-BUCKETS",
            &json!({ "scope": scope.as_str(), "bucket_root": bucket_root }),
        );
        let reserve_bucket_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-DISCLOSURE-RESERVE-BUCKETS",
            &json!({ "scope": scope.as_str(), "bucket_root": bucket_root }),
        );
        let revealed_field_root = private_stablecoin_string_list_root(
            "PRIVATE-STABLECOIN-DISCLOSURE-FIELD",
            revealed_fields,
        );
        let statement_root = private_stablecoin_payload_root(
            "PRIVATE-STABLECOIN-DISCLOSURE-STATEMENT",
            &json!({
                "scheme": PRIVATE_STABLECOIN_DISCLOSURE_SCHEME,
                "market_id": market_id,
                "scope": scope.as_str(),
                "viewer_commitment": viewer_commitment,
                "bucket_root": bucket_root,
                "revealed_field_root": revealed_field_root,
            }),
        );
        let disclosure_id = private_stablecoin_privacy_disclosure_id(
            &market_id,
            scope,
            &viewer_commitment,
            &statement_root,
            created_at_height,
        );
        let disclosure = Self {
            disclosure_id,
            market_id,
            scope,
            viewer_commitment,
            bucket_root,
            ratio_bucket_root,
            operation_bucket_root,
            reserve_bucket_root,
            revealed_field_root,
            statement_root,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: "active".to_string(),
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_bucket_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "market_id": self.market_id,
            "scope": self.scope.as_str(),
            "viewer_commitment": self.viewer_commitment,
            "bucket_root": self.bucket_root,
            "ratio_bucket_root": self.ratio_bucket_root,
            "operation_bucket_root": self.operation_bucket_root,
            "reserve_bucket_root": self.reserve_bucket_root,
            "revealed_field_root": self.revealed_field_root,
            "statement_root": self.statement_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.disclosure_id, "privacy disclosure id")?;
        ensure_non_empty(&self.market_id, "privacy disclosure market id")?;
        ensure_non_empty(
            &self.viewer_commitment,
            "privacy disclosure viewer commitment",
        )?;
        ensure_non_empty(&self.bucket_root, "privacy disclosure bucket root")?;
        ensure_non_empty(
            &self.ratio_bucket_root,
            "privacy disclosure ratio bucket root",
        )?;
        ensure_non_empty(
            &self.operation_bucket_root,
            "privacy disclosure operation bucket root",
        )?;
        ensure_non_empty(
            &self.reserve_bucket_root,
            "privacy disclosure reserve bucket root",
        )?;
        ensure_non_empty(&self.revealed_field_root, "privacy disclosure field root")?;
        ensure_non_empty(&self.statement_root, "privacy disclosure statement root")?;
        ensure_status(&self.status, &["active", "expired", "revoked"])?;
        if self.expires_at_height <= self.created_at_height {
            return Err("privacy disclosure expiry must be after creation".to_string());
        }
        if self.disclosure_id
            != private_stablecoin_privacy_disclosure_id(
                &self.market_id,
                self.scope,
                &self.viewer_commitment,
                &self.statement_root,
                self.created_at_height,
            )
        {
            return Err("privacy disclosure id mismatch".to_string());
        }
        Ok(self.disclosure_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStablecoinPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub payload_root: String,
    pub recorded_at_height: u64,
    pub nonce: u64,
}

impl PrivateStablecoinPublicRecord {
    pub fn new(
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        payload: &Value,
        recorded_at_height: u64,
        nonce: u64,
    ) -> PrivateStablecoinResult<Self> {
        let object_kind = normalize_label(object_kind.into());
        let object_id = object_id.into();
        ensure_non_empty(&object_kind, "public record object kind")?;
        ensure_non_empty(&object_id, "public record object id")?;
        let payload_root =
            private_stablecoin_payload_root("PRIVATE-STABLECOIN-PUBLIC-PAYLOAD", payload);
        let record_id = private_stablecoin_public_record_id(
            &object_kind,
            &object_id,
            &payload_root,
            recorded_at_height,
            nonce,
        );
        let record = Self {
            record_id,
            object_kind,
            object_id,
            payload_root,
            recorded_at_height,
            nonce,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_stablecoin_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "payload_root": self.payload_root,
            "recorded_at_height": self.recorded_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.object_kind, "public record object kind")?;
        ensure_non_empty(&self.object_id, "public record object id")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        if self.record_id
            != private_stablecoin_public_record_id(
                &self.object_kind,
                &self.object_id,
                &self.payload_root,
                self.recorded_at_height,
                self.nonce,
            )
        {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStablecoinStateRoots {
    pub config_root: String,
    pub market_root: String,
    pub vault_root: String,
    pub debt_position_root: String,
    pub operation_root: String,
    pub supply_cap_root: String,
    pub oracle_root: String,
    pub collateral_bucket_root: String,
    pub liquidation_queue_root: String,
    pub liquidation_auction_root: String,
    pub liquidation_challenge_root: String,
    pub stability_fee_root: String,
    pub reserve_fund_root: String,
    pub pq_attestation_root: String,
    pub global_settlement_root: String,
    pub low_fee_sponsorship_root: String,
    pub contract_adapter_root: String,
    pub token_factory_hook_root: String,
    pub privacy_disclosure_root: String,
    pub public_record_root: String,
}

impl PrivateStablecoinStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_stablecoin_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "market_root": self.market_root,
            "vault_root": self.vault_root,
            "debt_position_root": self.debt_position_root,
            "operation_root": self.operation_root,
            "supply_cap_root": self.supply_cap_root,
            "oracle_root": self.oracle_root,
            "collateral_bucket_root": self.collateral_bucket_root,
            "liquidation_queue_root": self.liquidation_queue_root,
            "liquidation_auction_root": self.liquidation_auction_root,
            "liquidation_challenge_root": self.liquidation_challenge_root,
            "stability_fee_root": self.stability_fee_root,
            "reserve_fund_root": self.reserve_fund_root,
            "pq_attestation_root": self.pq_attestation_root,
            "global_settlement_root": self.global_settlement_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "contract_adapter_root": self.contract_adapter_root,
            "token_factory_hook_root": self.token_factory_hook_root,
            "privacy_disclosure_root": self.privacy_disclosure_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_stablecoin_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStablecoinState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateStablecoinConfig,
    pub markets: BTreeMap<String, PrivateStablecoinMarket>,
    pub collateral_vaults: BTreeMap<String, ConfidentialCollateralVault>,
    pub debt_positions: BTreeMap<String, SealedDebtPosition>,
    pub operations: BTreeMap<String, MintRedeemBurnCommitment>,
    pub supply_caps: BTreeMap<String, StablecoinSupplyCapSnapshot>,
    pub oracle_roots: BTreeMap<String, OraclePriceRootCommitment>,
    pub collateral_bucket_disclosures: BTreeMap<String, CollateralRatioBucketDisclosure>,
    pub liquidation_queue: BTreeMap<String, LiquidationQueueEntry>,
    pub liquidation_auctions: BTreeMap<String, PrivateLiquidationAuction>,
    pub liquidation_challenges: BTreeMap<String, LiquidationChallenge>,
    pub stability_fee_accruals: BTreeMap<String, StabilityFeeAccrual>,
    pub reserve_funds: BTreeMap<String, ReserveFundAccounting>,
    pub pq_attestations: BTreeMap<String, PqRiskCommitteeAttestation>,
    pub global_settlements: BTreeMap<String, EmergencyGlobalSettlement>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeStablecoinSponsorship>,
    pub contract_adapters: BTreeMap<String, ContractAdapterRoot>,
    pub token_factory_hooks: BTreeMap<String, TokenFactoryHook>,
    pub privacy_disclosures: BTreeMap<String, PrivacyBucketDisclosure>,
    pub public_records: BTreeMap<String, PrivateStablecoinPublicRecord>,
}

impl Default for PrivateStablecoinState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateStablecoinState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: PrivateStablecoinConfig::default(),
            markets: BTreeMap::new(),
            collateral_vaults: BTreeMap::new(),
            debt_positions: BTreeMap::new(),
            operations: BTreeMap::new(),
            supply_caps: BTreeMap::new(),
            oracle_roots: BTreeMap::new(),
            collateral_bucket_disclosures: BTreeMap::new(),
            liquidation_queue: BTreeMap::new(),
            liquidation_auctions: BTreeMap::new(),
            liquidation_challenges: BTreeMap::new(),
            stability_fee_accruals: BTreeMap::new(),
            reserve_funds: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            global_settlements: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            contract_adapters: BTreeMap::new(),
            token_factory_hooks: BTreeMap::new(),
            privacy_disclosures: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateStablecoinResult<Self> {
        let mut state = Self::new();
        state.height = PRIVATE_STABLECOIN_DEVNET_HEIGHT;
        let collateral_asset_id = state.config.collateral_asset_id.clone();
        let stable_asset_id = state.config.stable_asset_id.clone();
        let reserve_asset_id = state.config.reserve_asset_id.clone();
        let default_low_fee_lane = state.config.default_low_fee_lane.clone();
        let max_supply_units = state.config.max_supply_units;
        let minimum_collateral_ratio_bps = state.config.minimum_collateral_ratio_bps;
        let liquidation_ratio_bps = state.config.liquidation_ratio_bps;
        let stability_fee_annual_bps = state.config.stability_fee_annual_bps;
        let reserve_factor_bps = state.config.reserve_factor_bps;
        let max_oracle_staleness_blocks = state.config.max_oracle_staleness_blocks;
        let default_challenge_window_blocks = state.config.default_challenge_window_blocks;
        let default_auction_ttl_blocks = state.config.default_auction_ttl_blocks;
        let sponsored_small_mint_limit_units = state.config.sponsored_small_mint_limit_units;
        let sponsored_max_fee_units = state.config.sponsored_max_fee_units;
        let global_settlement_delay_blocks = state.config.global_settlement_delay_blocks;

        let mut market = PrivateStablecoinMarket::new(
            "wXMR private stablecoin devnet",
            &collateral_asset_id,
            &stable_asset_id,
            &reserve_asset_id,
            PRIVATE_STABLECOIN_DEVNET_ORACLE_FEED_ID,
            &default_low_fee_lane,
            max_supply_units,
            minimum_collateral_ratio_bps,
            liquidation_ratio_bps,
            stability_fee_annual_bps,
            reserve_factor_bps,
            &json!({
                "mode": "devnet",
                "purpose": "privacy-preserving wxmr-backed cdp stablecoin",
                "contract_surface": "root-only"
            }),
            state.height.saturating_sub(64),
        )?;
        let market_id = market.market_id.clone();

        let oracle = OraclePriceRootCommitment::new(
            &market_id,
            PRIVATE_STABLECOIN_DEVNET_ORACLE_FEED_ID,
            PRIVATE_STABLECOIN_DEVNET_WXMR_PRICE,
            PRIVATE_STABLECOIN_DEVNET_WXMR_PRICE.saturating_sub(PRIVATE_STABLECOIN_PRICE_SCALE),
            9_250,
            &[
                json!({"source": "devnet-median-1", "height": state.height - 2}),
                json!({"source": "devnet-median-2", "height": state.height - 1}),
                json!({"source": "devnet-median-3", "height": state.height - 1}),
            ],
            "devnet-oracle-pq-committee",
            state.height.saturating_sub(1),
            state.height.saturating_sub(2),
            max_oracle_staleness_blocks,
            &json!({
                "threshold": "3-of-5",
                "signature_scheme": PRIVATE_STABLECOIN_PQ_SIGNATURE_SCHEME
            }),
        )?;
        let oracle_root_id = oracle.oracle_root_id.clone();
        state.insert_oracle_root(oracle)?;

        let adapter = ContractAdapterRoot::new(
            &market_id,
            "contract_vm_private_stablecoin",
            "contract-private-stablecoin-devnet",
            &[
                json!({"method": "commit_private_mint", "selector": "0xcdp01"}),
                json!({"method": "commit_private_redeem", "selector": "0xcdp02"}),
                json!({"method": "settle_private_liquidation", "selector": "0xcdp03"}),
                json!({"method": "global_settlement_root", "selector": "0xcdp04"}),
            ],
            private_stablecoin_string_root("PRIVATE-STABLECOIN-DEVNET-PRE-STATE", "pre"),
            private_stablecoin_string_root("PRIVATE-STABLECOIN-DEVNET-POST-STATE", "post"),
            &[json!({"event": "PrivateStablecoinRoot", "version": 1})],
            private_stablecoin_string_root("PRIVATE-STABLECOIN-DEVNET-TOKEN-REGISTRY", "tokens"),
            private_stablecoin_string_root("PRIVATE-STABLECOIN-DEVNET-PRIVACY-ADAPTER", "privacy"),
            state.height.saturating_sub(32),
            state.height.saturating_add(7_200),
        )?;
        let adapter_root = private_stablecoin_contract_adapter_root(&[adapter.clone()]);

        let token_hook = TokenFactoryHook::new(
            &market_id,
            &stable_asset_id,
            "token-factory-devnet",
            TokenFactoryHookKind::RegisterStableAsset,
            &json!({
                "symbol": "dUSD",
                "decimals": 12,
                "privacy": "commitment_mint_burn"
            }),
            market.supply_cap_root.clone(),
            &[
                json!({"role": "minter", "root": "stablecoin-adapter-root"}),
                json!({"role": "burner", "root": "stablecoin-adapter-root"}),
            ],
            "devnet-stablecoin-issuer",
            state.height.saturating_sub(32),
            state.height.saturating_add(7_200),
        )?;
        let token_hook_root = private_stablecoin_token_factory_hook_root(&[token_hook.clone()]);
        market.adapter_root = adapter_root.clone();
        market.token_hook_root = token_hook_root.clone();

        state.insert_market(market)?;
        state.insert_contract_adapter(adapter)?;
        state.insert_token_factory_hook(token_hook)?;

        let reserve = ReserveFundAccounting::new(
            &market_id,
            &reserve_asset_id,
            "devnet-reserve-council",
            "reserve_1m_10m",
            750_000_000,
            1_500,
            &[
                json!({"sponsor": "devnet-foundation", "floor_units": 500_000_000_u64}),
                json!({"sponsor": "devnet-sequencer-safety", "floor_units": 250_000_000_u64}),
            ],
            state.height.saturating_sub(16),
        )?;
        state.insert_reserve_fund(reserve)?;

        let vault = ConfidentialCollateralVault::new(
            "devnet-alice-cdp",
            &collateral_asset_id,
            &stable_asset_id,
            "wxmr_100_500",
            "alice-cdp-vault-blinding",
            &json!({"ciphertext_root": "devnet-alice-collateral-ciphertext"}),
            &json!({"spend_policy": "pq-session-and-nullifier"}),
            state.height.saturating_sub(24),
            state.next_nonce(),
        )?;
        let vault_id = vault.vault_id.clone();
        state.insert_collateral_vault(vault)?;

        let position = SealedDebtPosition::new(
            &market_id,
            &vault_id,
            "devnet-alice-cdp",
            "stable_10k_25k",
            CollateralRatioBucket::Healthy,
            "value_50k_100k",
            &oracle_root_id,
            "devnet-alice-cdp-privacy-budget",
            &json!({"maturity": "30d", "fee_mode": "compounded_index"}),
            &json!({"solvency": "private_ratio_above_180pct"}),
            PRIVATE_STABLECOIN_INDEX_SCALE,
            state.height.saturating_sub(20),
            state.height.saturating_add(21_600),
            state.next_nonce(),
        )?;
        let position_id = position.position_id.clone();
        state.insert_debt_position(position)?;

        let sponsorship = LowFeeStablecoinSponsorship::new(
            "devnet-foundation-paymaster",
            "devnet-alice-cdp",
            &market_id,
            StablecoinOperationKind::Mint,
            &default_low_fee_lane,
            &stable_asset_id,
            sponsored_small_mint_limit_units,
            "stable_sponsor_10k",
            sponsored_max_fee_units,
            64,
            state.height.saturating_sub(12),
            state.height.saturating_add(360),
            state.next_nonce(),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_low_fee_sponsorship(sponsorship)?;

        let mint = MintRedeemBurnCommitment::new(
            &market_id,
            &position_id,
            &vault_id,
            StablecoinOperationKind::Mint,
            "devnet-alice-cdp",
            &stable_asset_id,
            StablecoinAmountBucket::Small,
            "alice-mint-blinding-1",
            "devnet-alice-private-wallet",
            &json!({"oracle_root_id": oracle_root_id, "max_slippage_bps": 15}),
            &json!({"private_debt_delta": "bucket-small", "ratio_after": "healthy"}),
            &sponsorship_id,
            &default_low_fee_lane,
            sponsored_max_fee_units,
            state.height.saturating_sub(10),
            state.height.saturating_add(64),
            state.next_nonce(),
        )?;
        state.commit_operation(mint)?;

        let redeem = MintRedeemBurnCommitment::new(
            &market_id,
            &position_id,
            &vault_id,
            StablecoinOperationKind::Redeem,
            "devnet-alice-cdp",
            &stable_asset_id,
            StablecoinAmountBucket::Dust,
            "alice-redeem-blinding-1",
            "devnet-alice-private-wallet",
            &json!({"mode": "partial_redeem", "reserve_route": "wxmr"}),
            &json!({"burn_proof": "small-private-redeem"}),
            "",
            &default_low_fee_lane,
            sponsored_max_fee_units,
            state.height.saturating_sub(8),
            state.height.saturating_add(72),
            state.next_nonce(),
        )?;
        state.commit_operation(redeem)?;

        let burn = MintRedeemBurnCommitment::new(
            &market_id,
            "",
            "",
            StablecoinOperationKind::Burn,
            "devnet-alice-cdp",
            &stable_asset_id,
            StablecoinAmountBucket::Dust,
            "alice-burn-blinding-1",
            "devnet-burn-null-address",
            &json!({"mode": "fee_cleanup"}),
            &json!({"burn_nullifier": "devnet-burn-nullifier"}),
            "",
            &default_low_fee_lane,
            sponsored_max_fee_units,
            state.height.saturating_sub(6),
            state.height.saturating_add(96),
            state.next_nonce(),
        )?;
        state.commit_operation(burn)?;

        let disclosure = CollateralRatioBucketDisclosure::new(
            &market_id,
            CollateralRatioBucket::Healthy,
            1,
            &[private_stablecoin_string_root(
                "PRIVATE-STABLECOIN-DEVNET-DEBT-BUCKET",
                "stable_10k_25k",
            )],
            &[private_stablecoin_string_root(
                "PRIVATE-STABLECOIN-DEVNET-COLLATERAL-BUCKET",
                "wxmr_100_500",
            )],
            &[position_id.clone()],
            state.height.saturating_sub(5),
            PRIVATE_STABLECOIN_DEFAULT_DISCLOSURE_TTL_BLOCKS,
        )?;
        state.insert_collateral_bucket_disclosure(disclosure)?;

        let privacy_disclosure = PrivacyBucketDisclosure::new(
            &market_id,
            PrivacyDisclosureScope::MarketBuckets,
            "devnet-risk-dashboard",
            &[
                json!({"bucket": "healthy", "position_count": 1}),
                json!({"bucket": "liquidatable", "position_count": 1}),
            ],
            &[
                "ratio_bucket_root".to_string(),
                "operation_bucket_root".to_string(),
                "reserve_bucket_root".to_string(),
            ],
            state.height.saturating_sub(4),
            PRIVATE_STABLECOIN_DEFAULT_DISCLOSURE_TTL_BLOCKS,
        )?;
        state.insert_privacy_disclosure(privacy_disclosure)?;

        let liquidation = LiquidationQueueEntry::new(
            &market_id,
            &position_id,
            &vault_id,
            "devnet-keeper-1",
            CollateralRatioBucket::Liquidatable,
            "stable_10k_25k",
            "wxmr_50_100",
            &oracle_root_id,
            &json!({"reason": "private_ratio_bucket_crossed", "bucket": "liquidatable"}),
            state.height.saturating_sub(3),
            default_challenge_window_blocks,
            state.next_nonce(),
        )?;
        let liquidation_id = liquidation.liquidation_id.clone();
        state.insert_liquidation_queue_entry(liquidation)?;

        let auction = PrivateLiquidationAuction::new(
            &liquidation_id,
            &market_id,
            &position_id,
            "stable_10k_25k",
            "wxmr_50_100",
            "price_150_170",
            "price_110_130",
            &[private_stablecoin_account_commitment(
                "devnet-liquidation-keeper",
            )],
            state.height.saturating_sub(2),
            default_auction_ttl_blocks,
            default_challenge_window_blocks,
            state.next_nonce(),
        )?;
        let auction_id = auction.auction_id.clone();
        state.insert_liquidation_auction(auction)?;

        let challenge = LiquidationChallenge::new(
            &liquidation_id,
            &auction_id,
            "devnet-alice-watchtower",
            "bond_1k",
            &json!({"claim": "oracle_staleness_guard", "root_only": true}),
            &json!({"counter_root": "devnet-counter-oracle-root"}),
            state.height.saturating_sub(1),
            state.height.saturating_add(18),
        )?;
        state.insert_liquidation_challenge(challenge)?;

        let fee = StabilityFeeAccrual::new(
            &market_id,
            &position_id,
            StabilityFeeEventKind::PeriodicAccrual,
            "stable_10k_25k",
            PRIVATE_STABLECOIN_INDEX_SCALE,
            stability_fee_annual_bps,
            32,
            reserve_factor_bps,
            state.height,
            state.next_nonce(),
        )?;
        state.insert_stability_fee_accrual(fee)?;

        let attestation = PqRiskCommitteeAttestation::new(
            "devnet-stablecoin-risk-committee",
            "committee-member-ml-dsa-1",
            &market_id,
            "supply_cap",
            &market_id,
            RiskDecision::Approve,
            RiskSeverity::Watch,
            2_000,
            &json!({
                "launch_caps": "devnet",
                "quantum_resistant_signatures": true,
                "stale_oracle_guard_blocks": max_oracle_staleness_blocks
            }),
            &json!({"signature": "devnet-pq-signature-root"}),
            state.height.saturating_sub(2),
            state.height.saturating_add(720),
        )?;
        let attestation_root = private_stablecoin_pq_attestation_root(&[attestation.clone()]);
        state.insert_pq_attestation(attestation)?;

        let settlement = EmergencyGlobalSettlement::new(
            &market_id,
            "devnet-stablecoin-risk-committee",
            &json!({"settlement_price_root": "devnet-settlement-oracle-root"}),
            &json!({"reserve_bucket_root": state.reserve_fund_root()}),
            &json!({"debt_bucket_root": state.debt_position_root()}),
            &[
                json!({"bucket": "small", "payout_root": "devnet-small-payout-root"}),
                json!({"bucket": "medium", "payout_root": "devnet-medium-payout-root"}),
            ],
            &attestation_root,
            state.height.saturating_add(1),
            default_challenge_window_blocks,
            global_settlement_delay_blocks,
        )?;
        state.insert_global_settlement(settlement)?;

        state.refresh_supply_cap_snapshot(&market_id)?;
        let public_record = PrivateStablecoinPublicRecord::new(
            "devnet_state_root",
            &market_id,
            &json!({
                "state_root": state.state_root(),
                "market_id": market_id,
                "height": state.height,
                "privacy": "bucketed_roots_only"
            }),
            state.height,
            state.next_nonce(),
        )?;
        state.insert_public_record(public_record)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for operation in self.operations.values_mut() {
            if operation.is_expired_at(height)
                && matches!(
                    operation.status,
                    StablecoinOperationStatus::Pending | StablecoinOperationStatus::Sponsored
                )
            {
                operation.status = StablecoinOperationStatus::Expired;
            }
        }
        for challenge in self.liquidation_challenges.values_mut() {
            if challenge.is_expired_at(height) {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        for auction in self.liquidation_auctions.values_mut() {
            auction.refresh_status(height);
        }
        for sponsorship in self.low_fee_sponsorships.values_mut() {
            if height > sponsorship.expires_at_height
                && matches!(
                    sponsorship.status,
                    SponsorshipStatus::Active | SponsorshipStatus::Reserved
                )
            {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_market(
        &mut self,
        market: PrivateStablecoinMarket,
    ) -> PrivateStablecoinResult<PrivateStablecoinMarket> {
        market.validate()?;
        self.markets
            .insert(market.market_id.clone(), market.clone());
        Ok(market)
    }

    pub fn insert_collateral_vault(
        &mut self,
        vault: ConfidentialCollateralVault,
    ) -> PrivateStablecoinResult<ConfidentialCollateralVault> {
        vault.validate()?;
        self.collateral_vaults
            .insert(vault.vault_id.clone(), vault.clone());
        Ok(vault)
    }

    pub fn insert_debt_position(
        &mut self,
        position: SealedDebtPosition,
    ) -> PrivateStablecoinResult<SealedDebtPosition> {
        position.validate()?;
        if !self.markets.contains_key(&position.market_id) {
            return Err("debt position references unknown market".to_string());
        }
        if !self.collateral_vaults.contains_key(&position.vault_id) {
            return Err("debt position references unknown collateral vault".to_string());
        }
        if !self.oracle_roots.contains_key(&position.oracle_root_id) {
            return Err("debt position references unknown oracle root".to_string());
        }
        self.debt_positions
            .insert(position.position_id.clone(), position.clone());
        Ok(position)
    }

    pub fn insert_operation(
        &mut self,
        operation: MintRedeemBurnCommitment,
    ) -> PrivateStablecoinResult<MintRedeemBurnCommitment> {
        operation.validate()?;
        self.operations
            .insert(operation.operation_id.clone(), operation.clone());
        Ok(operation)
    }

    pub fn commit_operation(
        &mut self,
        mut operation: MintRedeemBurnCommitment,
    ) -> PrivateStablecoinResult<MintRedeemBurnCommitment> {
        operation.validate()?;
        let market = self
            .markets
            .get(&operation.market_id)
            .ok_or_else(|| "operation references unknown market".to_string())?
            .clone();
        match operation.operation_kind {
            StablecoinOperationKind::Mint => {
                if !market.status.allows_mint() {
                    return Err("stablecoin market does not allow mints".to_string());
                }
                if !self.oracle_allows_mint(&operation.market_id, self.height) {
                    return Err("stablecoin mint blocked by stale oracle".to_string());
                }
                if operation.amount_upper_bound_units() > market.remaining_mint_capacity_units() {
                    return Err("stablecoin mint exceeds supply cap bucket".to_string());
                }
                if operation.sponsor_id.is_empty() && operation.amount_bucket.is_sponsor_eligible()
                {
                    operation.status = StablecoinOperationStatus::Pending;
                }
                if !operation.sponsor_id.is_empty() {
                    let sponsorship = self
                        .low_fee_sponsorships
                        .get(&operation.sponsor_id)
                        .ok_or_else(|| "operation references unknown sponsorship".to_string())?;
                    if !sponsorship.supports(&operation, self.height) {
                        return Err("sponsorship does not support operation".to_string());
                    }
                    operation.status = StablecoinOperationStatus::Sponsored;
                }
                if let Some(market) = self.markets.get_mut(&operation.market_id) {
                    market.issued_units = market
                        .issued_units
                        .saturating_add(operation.amount_upper_bound_units());
                }
            }
            StablecoinOperationKind::Redeem => {
                if !market.status.allows_redeem() {
                    return Err("stablecoin market does not allow redeems".to_string());
                }
                if let Some(market) = self.markets.get_mut(&operation.market_id) {
                    market.redeemed_units = market
                        .redeemed_units
                        .saturating_add(operation.amount_upper_bound_units());
                }
            }
            StablecoinOperationKind::Burn => {
                if let Some(market) = self.markets.get_mut(&operation.market_id) {
                    market.burned_units = market
                        .burned_units
                        .saturating_add(operation.amount_upper_bound_units());
                }
            }
        }
        self.operations
            .insert(operation.operation_id.clone(), operation.clone());
        self.refresh_supply_cap_snapshot(&operation.market_id)?;
        Ok(operation)
    }

    pub fn insert_supply_cap_snapshot(
        &mut self,
        cap: StablecoinSupplyCapSnapshot,
    ) -> PrivateStablecoinResult<StablecoinSupplyCapSnapshot> {
        cap.validate()?;
        self.supply_caps.insert(cap.cap_id.clone(), cap.clone());
        Ok(cap)
    }

    pub fn insert_oracle_root(
        &mut self,
        oracle: OraclePriceRootCommitment,
    ) -> PrivateStablecoinResult<OraclePriceRootCommitment> {
        oracle.validate()?;
        self.oracle_roots
            .insert(oracle.oracle_root_id.clone(), oracle.clone());
        Ok(oracle)
    }

    pub fn insert_collateral_bucket_disclosure(
        &mut self,
        disclosure: CollateralRatioBucketDisclosure,
    ) -> PrivateStablecoinResult<CollateralRatioBucketDisclosure> {
        disclosure.validate()?;
        if !self.markets.contains_key(&disclosure.market_id) {
            return Err("bucket disclosure references unknown market".to_string());
        }
        self.collateral_bucket_disclosures
            .insert(disclosure.bucket_id.clone(), disclosure.clone());
        Ok(disclosure)
    }

    pub fn insert_liquidation_queue_entry(
        &mut self,
        liquidation: LiquidationQueueEntry,
    ) -> PrivateStablecoinResult<LiquidationQueueEntry> {
        liquidation.validate()?;
        if !self.markets.contains_key(&liquidation.market_id) {
            return Err("liquidation references unknown market".to_string());
        }
        if !self.debt_positions.contains_key(&liquidation.position_id) {
            return Err("liquidation references unknown debt position".to_string());
        }
        self.liquidation_queue
            .insert(liquidation.liquidation_id.clone(), liquidation.clone());
        Ok(liquidation)
    }

    pub fn insert_liquidation_auction(
        &mut self,
        auction: PrivateLiquidationAuction,
    ) -> PrivateStablecoinResult<PrivateLiquidationAuction> {
        auction.validate()?;
        if !self.liquidation_queue.contains_key(&auction.liquidation_id) {
            return Err("auction references unknown liquidation".to_string());
        }
        self.liquidation_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        Ok(auction)
    }

    pub fn insert_liquidation_challenge(
        &mut self,
        challenge: LiquidationChallenge,
    ) -> PrivateStablecoinResult<LiquidationChallenge> {
        challenge.validate()?;
        if !self
            .liquidation_queue
            .contains_key(&challenge.liquidation_id)
        {
            return Err("challenge references unknown liquidation".to_string());
        }
        if !challenge.auction_id.is_empty()
            && !self
                .liquidation_auctions
                .contains_key(&challenge.auction_id)
        {
            return Err("challenge references unknown auction".to_string());
        }
        self.liquidation_challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    pub fn insert_stability_fee_accrual(
        &mut self,
        accrual: StabilityFeeAccrual,
    ) -> PrivateStablecoinResult<StabilityFeeAccrual> {
        accrual.validate()?;
        if !self.markets.contains_key(&accrual.market_id) {
            return Err("fee accrual references unknown market".to_string());
        }
        if let Some(market) = self.markets.get_mut(&accrual.market_id) {
            market.current_fee_index = market.current_fee_index.max(accrual.fee_index_after);
            market.last_accrual_height = market.last_accrual_height.max(accrual.recorded_at_height);
        }
        self.stability_fee_accruals
            .insert(accrual.accrual_id.clone(), accrual.clone());
        Ok(accrual)
    }

    pub fn insert_reserve_fund(
        &mut self,
        fund: ReserveFundAccounting,
    ) -> PrivateStablecoinResult<ReserveFundAccounting> {
        fund.validate()?;
        if !self.markets.contains_key(&fund.market_id) {
            return Err("reserve fund references unknown market".to_string());
        }
        if let Some(market) = self.markets.get_mut(&fund.market_id) {
            market.reserve_floor_units = market.reserve_floor_units.max(fund.balance_floor_units);
        }
        self.reserve_funds
            .insert(fund.fund_id.clone(), fund.clone());
        Ok(fund)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqRiskCommitteeAttestation,
    ) -> PrivateStablecoinResult<PqRiskCommitteeAttestation> {
        attestation.validate()?;
        if !self.markets.contains_key(&attestation.market_id) {
            return Err("attestation references unknown market".to_string());
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    pub fn insert_global_settlement(
        &mut self,
        settlement: EmergencyGlobalSettlement,
    ) -> PrivateStablecoinResult<EmergencyGlobalSettlement> {
        settlement.validate()?;
        if !self.markets.contains_key(&settlement.market_id) {
            return Err("global settlement references unknown market".to_string());
        }
        if let Some(market) = self.markets.get_mut(&settlement.market_id) {
            market.status = StablecoinMarketStatus::GlobalSettlement;
        }
        self.global_settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        Ok(settlement)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeStablecoinSponsorship,
    ) -> PrivateStablecoinResult<LowFeeStablecoinSponsorship> {
        sponsorship.validate()?;
        if !self.markets.contains_key(&sponsorship.market_id) {
            return Err("sponsorship references unknown market".to_string());
        }
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn insert_contract_adapter(
        &mut self,
        adapter: ContractAdapterRoot,
    ) -> PrivateStablecoinResult<ContractAdapterRoot> {
        adapter.validate()?;
        if !self.markets.contains_key(&adapter.market_id) {
            return Err("contract adapter references unknown market".to_string());
        }
        self.contract_adapters
            .insert(adapter.adapter_id.clone(), adapter.clone());
        Ok(adapter)
    }

    pub fn insert_token_factory_hook(
        &mut self,
        hook: TokenFactoryHook,
    ) -> PrivateStablecoinResult<TokenFactoryHook> {
        hook.validate()?;
        if !self.markets.contains_key(&hook.market_id) {
            return Err("token hook references unknown market".to_string());
        }
        self.token_factory_hooks
            .insert(hook.hook_id.clone(), hook.clone());
        Ok(hook)
    }

    pub fn insert_privacy_disclosure(
        &mut self,
        disclosure: PrivacyBucketDisclosure,
    ) -> PrivateStablecoinResult<PrivacyBucketDisclosure> {
        disclosure.validate()?;
        if !self.markets.contains_key(&disclosure.market_id) {
            return Err("privacy disclosure references unknown market".to_string());
        }
        self.privacy_disclosures
            .insert(disclosure.disclosure_id.clone(), disclosure.clone());
        Ok(disclosure)
    }

    pub fn insert_public_record(
        &mut self,
        record: PrivateStablecoinPublicRecord,
    ) -> PrivateStablecoinResult<PrivateStablecoinPublicRecord> {
        record.validate()?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn oracle_allows_mint(&self, market_id: &str, height: u64) -> bool {
        self.oracle_roots
            .values()
            .filter(|oracle| oracle.market_id == market_id)
            .any(|oracle| !oracle.is_stale_at(height))
    }

    pub fn refresh_supply_cap_snapshot(
        &mut self,
        market_id: &str,
    ) -> PrivateStablecoinResult<StablecoinSupplyCapSnapshot> {
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| "unknown market for supply cap refresh".to_string())?
            .clone();
        let cap = StablecoinSupplyCapSnapshot::from_market(&market, self.height);
        if let Some(market) = self.markets.get_mut(market_id) {
            market.supply_cap_root = private_stablecoin_supply_cap_root(&[cap.clone()]);
        }
        self.supply_caps.insert(cap.cap_id.clone(), cap.clone());
        Ok(cap)
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn market_root(&self) -> String {
        private_stablecoin_market_root(&self.markets.values().cloned().collect::<Vec<_>>())
    }

    pub fn collateral_vault_root(&self) -> String {
        private_stablecoin_collateral_vault_root(
            &self.collateral_vaults.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn debt_position_root(&self) -> String {
        private_stablecoin_debt_position_root(
            &self.debt_positions.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn operation_root(&self) -> String {
        private_stablecoin_operation_root(&self.operations.values().cloned().collect::<Vec<_>>())
    }

    pub fn supply_cap_root(&self) -> String {
        private_stablecoin_supply_cap_root(&self.supply_caps.values().cloned().collect::<Vec<_>>())
    }

    pub fn oracle_root(&self) -> String {
        private_stablecoin_oracle_root(&self.oracle_roots.values().cloned().collect::<Vec<_>>())
    }

    pub fn collateral_bucket_root(&self) -> String {
        private_stablecoin_collateral_bucket_root(
            &self
                .collateral_bucket_disclosures
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_queue_root(&self) -> String {
        private_stablecoin_liquidation_queue_root(
            &self.liquidation_queue.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_auction_root(&self) -> String {
        private_stablecoin_liquidation_auction_root(
            &self
                .liquidation_auctions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_challenge_root(&self) -> String {
        private_stablecoin_liquidation_challenge_root(
            &self
                .liquidation_challenges
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn stability_fee_root(&self) -> String {
        private_stablecoin_stability_fee_root(
            &self
                .stability_fee_accruals
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn reserve_fund_root(&self) -> String {
        private_stablecoin_reserve_fund_root(
            &self.reserve_funds.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        private_stablecoin_pq_attestation_root(
            &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn global_settlement_root(&self) -> String {
        private_stablecoin_global_settlement_root(
            &self
                .global_settlements
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        private_stablecoin_low_fee_sponsorship_root(
            &self
                .low_fee_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn contract_adapter_root(&self) -> String {
        private_stablecoin_contract_adapter_root(
            &self.contract_adapters.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn token_factory_hook_root(&self) -> String {
        private_stablecoin_token_factory_hook_root(
            &self
                .token_factory_hooks
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn privacy_disclosure_root(&self) -> String {
        private_stablecoin_privacy_disclosure_root(
            &self
                .privacy_disclosures
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        private_stablecoin_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn state_roots(&self) -> PrivateStablecoinStateRoots {
        PrivateStablecoinStateRoots {
            config_root: self.config_root(),
            market_root: self.market_root(),
            vault_root: self.collateral_vault_root(),
            debt_position_root: self.debt_position_root(),
            operation_root: self.operation_root(),
            supply_cap_root: self.supply_cap_root(),
            oracle_root: self.oracle_root(),
            collateral_bucket_root: self.collateral_bucket_root(),
            liquidation_queue_root: self.liquidation_queue_root(),
            liquidation_auction_root: self.liquidation_auction_root(),
            liquidation_challenge_root: self.liquidation_challenge_root(),
            stability_fee_root: self.stability_fee_root(),
            reserve_fund_root: self.reserve_fund_root(),
            pq_attestation_root: self.pq_attestation_root(),
            global_settlement_root: self.global_settlement_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            contract_adapter_root: self.contract_adapter_root(),
            token_factory_hook_root: self.token_factory_hook_root(),
            privacy_disclosure_root: self.privacy_disclosure_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn active_market_ids(&self) -> Vec<String> {
        self.markets
            .values()
            .filter(|market| {
                matches!(
                    market.status,
                    StablecoinMarketStatus::Active
                        | StablecoinMarketStatus::MintPaused
                        | StablecoinMarketStatus::RedeemPaused
                )
            })
            .map(|market| market.market_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn global_settlement_market_ids(&self) -> Vec<String> {
        self.global_settlements
            .values()
            .filter(|settlement| settlement.active_at(self.height))
            .map(|settlement| settlement.market_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn active_sponsorship_count(&self) -> u64 {
        self.low_fee_sponsorships
            .values()
            .filter(|sponsorship| sponsorship.is_active_at(self.height))
            .count() as u64
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        self.pq_attestations
            .values()
            .filter(|attestation| attestation.is_active_at(self.height))
            .map(|attestation| {
                attestation
                    .risk_score_bps
                    .max(attestation.severity.score_bps())
            })
            .max()
            .unwrap_or(0)
    }

    pub fn state_root(&self) -> String {
        private_stablecoin_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("private stablecoin state public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.state_roots();
        json!({
            "kind": "private_stablecoin_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_STABLECOIN_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "market_count": self.markets.len() as u64,
            "collateral_vault_count": self.collateral_vaults.len() as u64,
            "debt_position_count": self.debt_positions.len() as u64,
            "operation_count": self.operations.len() as u64,
            "supply_cap_count": self.supply_caps.len() as u64,
            "oracle_root_count": self.oracle_roots.len() as u64,
            "collateral_bucket_disclosure_count": self.collateral_bucket_disclosures.len() as u64,
            "liquidation_queue_count": self.liquidation_queue.len() as u64,
            "liquidation_auction_count": self.liquidation_auctions.len() as u64,
            "liquidation_challenge_count": self.liquidation_challenges.len() as u64,
            "stability_fee_accrual_count": self.stability_fee_accruals.len() as u64,
            "reserve_fund_count": self.reserve_funds.len() as u64,
            "pq_attestation_count": self.pq_attestations.len() as u64,
            "global_settlement_count": self.global_settlements.len() as u64,
            "low_fee_sponsorship_count": self.low_fee_sponsorships.len() as u64,
            "contract_adapter_count": self.contract_adapters.len() as u64,
            "token_factory_hook_count": self.token_factory_hooks.len() as u64,
            "privacy_disclosure_count": self.privacy_disclosures.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "active_market_ids": self.active_market_ids(),
            "global_settlement_market_ids": self.global_settlement_market_ids(),
            "active_sponsorship_count": self.active_sponsorship_count(),
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps(),
            "risk_status": private_stablecoin_risk_status(self.aggregate_risk_score_bps()),
            "roots": roots.public_record(),
        })
    }

    pub fn validate(&self) -> PrivateStablecoinResult<String> {
        self.config.validate()?;
        for (id, market) in &self.markets {
            if id != &market.market_id {
                return Err("state market map key does not match market id".to_string());
            }
            market.validate()?;
        }
        for (id, vault) in &self.collateral_vaults {
            if id != &vault.vault_id {
                return Err("state vault map key does not match vault id".to_string());
            }
            vault.validate()?;
        }
        for (id, position) in &self.debt_positions {
            if id != &position.position_id {
                return Err("state debt position map key does not match position id".to_string());
            }
            position.validate()?;
            ensure_state_market(&self.markets, &position.market_id, "debt position")?;
            if !self.collateral_vaults.contains_key(&position.vault_id) {
                return Err("debt position references missing vault".to_string());
            }
            if !self.oracle_roots.contains_key(&position.oracle_root_id) {
                return Err("debt position references missing oracle root".to_string());
            }
        }
        for (id, operation) in &self.operations {
            if id != &operation.operation_id {
                return Err("state operation map key does not match operation id".to_string());
            }
            operation.validate()?;
            ensure_state_market(&self.markets, &operation.market_id, "operation")?;
            if !operation.position_id.is_empty()
                && !self.debt_positions.contains_key(&operation.position_id)
            {
                return Err("operation references missing debt position".to_string());
            }
            if !operation.vault_id.is_empty()
                && !self.collateral_vaults.contains_key(&operation.vault_id)
            {
                return Err("operation references missing vault".to_string());
            }
            if !operation.sponsor_id.is_empty()
                && !self
                    .low_fee_sponsorships
                    .contains_key(&operation.sponsor_id)
            {
                return Err("operation references missing sponsorship".to_string());
            }
        }
        for (id, cap) in &self.supply_caps {
            if id != &cap.cap_id {
                return Err("state supply cap map key does not match cap id".to_string());
            }
            cap.validate()?;
            ensure_state_market(&self.markets, &cap.market_id, "supply cap")?;
        }
        for (id, oracle) in &self.oracle_roots {
            if id != &oracle.oracle_root_id {
                return Err("state oracle map key does not match oracle id".to_string());
            }
            oracle.validate()?;
            ensure_state_market(&self.markets, &oracle.market_id, "oracle root")?;
        }
        for (id, disclosure) in &self.collateral_bucket_disclosures {
            if id != &disclosure.bucket_id {
                return Err("state bucket map key does not match bucket id".to_string());
            }
            disclosure.validate()?;
            ensure_state_market(&self.markets, &disclosure.market_id, "bucket disclosure")?;
        }
        for (id, liquidation) in &self.liquidation_queue {
            if id != &liquidation.liquidation_id {
                return Err("state liquidation map key does not match liquidation id".to_string());
            }
            liquidation.validate()?;
            ensure_state_market(&self.markets, &liquidation.market_id, "liquidation")?;
            if !self.debt_positions.contains_key(&liquidation.position_id) {
                return Err("liquidation references missing debt position".to_string());
            }
        }
        for (id, auction) in &self.liquidation_auctions {
            if id != &auction.auction_id {
                return Err("state auction map key does not match auction id".to_string());
            }
            auction.validate()?;
            if !self.liquidation_queue.contains_key(&auction.liquidation_id) {
                return Err("auction references missing liquidation".to_string());
            }
        }
        for (id, challenge) in &self.liquidation_challenges {
            if id != &challenge.challenge_id {
                return Err("state challenge map key does not match challenge id".to_string());
            }
            challenge.validate()?;
            if !self
                .liquidation_queue
                .contains_key(&challenge.liquidation_id)
            {
                return Err("challenge references missing liquidation".to_string());
            }
        }
        for (id, accrual) in &self.stability_fee_accruals {
            if id != &accrual.accrual_id {
                return Err("state fee accrual map key does not match accrual id".to_string());
            }
            accrual.validate()?;
            ensure_state_market(&self.markets, &accrual.market_id, "fee accrual")?;
        }
        for (id, fund) in &self.reserve_funds {
            if id != &fund.fund_id {
                return Err("state reserve fund map key does not match fund id".to_string());
            }
            fund.validate()?;
            ensure_state_market(&self.markets, &fund.market_id, "reserve fund")?;
        }
        for (id, attestation) in &self.pq_attestations {
            if id != &attestation.attestation_id {
                return Err("state attestation map key does not match attestation id".to_string());
            }
            attestation.validate()?;
            ensure_state_market(&self.markets, &attestation.market_id, "attestation")?;
        }
        for (id, settlement) in &self.global_settlements {
            if id != &settlement.settlement_id {
                return Err(
                    "state global settlement map key does not match settlement id".to_string(),
                );
            }
            settlement.validate()?;
            ensure_state_market(&self.markets, &settlement.market_id, "global settlement")?;
        }
        for (id, sponsorship) in &self.low_fee_sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("state sponsorship map key does not match sponsorship id".to_string());
            }
            sponsorship.validate()?;
            ensure_state_market(&self.markets, &sponsorship.market_id, "sponsorship")?;
        }
        for (id, adapter) in &self.contract_adapters {
            if id != &adapter.adapter_id {
                return Err("state adapter map key does not match adapter id".to_string());
            }
            adapter.validate()?;
            ensure_state_market(&self.markets, &adapter.market_id, "contract adapter")?;
        }
        for (id, hook) in &self.token_factory_hooks {
            if id != &hook.hook_id {
                return Err("state token hook map key does not match hook id".to_string());
            }
            hook.validate()?;
            ensure_state_market(&self.markets, &hook.market_id, "token hook")?;
        }
        for (id, disclosure) in &self.privacy_disclosures {
            if id != &disclosure.disclosure_id {
                return Err(
                    "state privacy disclosure map key does not match disclosure id".to_string(),
                );
            }
            disclosure.validate()?;
            ensure_state_market(&self.markets, &disclosure.market_id, "privacy disclosure")?;
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record map key does not match record id".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn private_stablecoin_state_root(state: &PrivateStablecoinState) -> String {
    state.state_root()
}

pub fn private_stablecoin_market_id(
    market_label: &str,
    collateral_asset_id: &str,
    stable_asset_id: &str,
    oracle_feed_id: &str,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_label),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(stable_asset_id),
            HashPart::Str(oracle_feed_id),
        ],
        32,
    )
}

pub fn private_stablecoin_account_commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn private_stablecoin_amount_commitment(
    asset_id: &str,
    amount_bucket: &str,
    blinding_seed: &str,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(asset_id),
            HashPart::Str(amount_bucket),
            HashPart::Str(blinding_seed),
        ],
        32,
    )
}

pub fn private_stablecoin_bucket_commitment(bucket_kind: &str, bucket_label: &str) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-BUCKET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bucket_kind),
            HashPart::Str(bucket_label),
        ],
        32,
    )
}

pub fn private_stablecoin_vault_id(
    owner_commitment: &str,
    collateral_asset_id: &str,
    collateral_commitment: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(collateral_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_debt_position_id(
    market_id: &str,
    vault_id: &str,
    owner_commitment: &str,
    debt_commitment: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-DEBT-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(vault_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(debt_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_supply_delta_commitment(
    operation_kind: StablecoinOperationKind,
    amount_commitment: &str,
    account_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-SUPPLY-DELTA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operation_kind.as_str()),
            HashPart::Str(amount_commitment),
            HashPart::Str(account_commitment),
        ],
        32,
    )
}

pub fn private_stablecoin_operation_nullifier(
    account_commitment: &str,
    amount_commitment: &str,
    operation_kind: StablecoinOperationKind,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-OPERATION-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(operation_kind.as_str()),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_operation_id(
    market_id: &str,
    account_commitment: &str,
    operation_kind: StablecoinOperationKind,
    nullifier: &str,
    requested_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-OPERATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(account_commitment),
            HashPart::Str(operation_kind.as_str()),
            HashPart::Str(nullifier),
            HashPart::Int(requested_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_supply_cap_id(
    market_id: &str,
    stable_asset_id: &str,
    max_supply_units: u64,
    circulating_units: u64,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-SUPPLY-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(stable_asset_id),
            HashPart::Int(max_supply_units as i128),
            HashPart::Int(circulating_units as i128),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_oracle_root_id(
    market_id: &str,
    feed_id: &str,
    price_commitment: &str,
    observed_at_height: u64,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-ORACLE-ROOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(feed_id),
            HashPart::Str(price_commitment),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_bucket_disclosure_id(
    market_id: &str,
    bucket: CollateralRatioBucket,
    position_commitment_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-BUCKET-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(bucket.as_str()),
            HashPart::Str(position_commitment_root),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_liquidation_id(
    market_id: &str,
    position_id: &str,
    keeper_commitment: &str,
    evidence_root: &str,
    queued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-LIQUIDATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(keeper_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(queued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_auction_id(
    liquidation_id: &str,
    market_id: &str,
    position_id: &str,
    debt_to_cover_commitment: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(liquidation_id),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(debt_to_cover_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_challenge_id(
    liquidation_id: &str,
    auction_id: &str,
    challenger_commitment: &str,
    claim_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(liquidation_id),
            HashPart::Str(auction_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(claim_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_fee_accrual_id(
    market_id: &str,
    position_id: &str,
    event_kind: StabilityFeeEventKind,
    fee_commitment: &str,
    recorded_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-FEE-ACCRUAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(fee_commitment),
            HashPart::Int(recorded_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_reserve_fund_id(
    market_id: &str,
    asset_id: &str,
    controller_commitment: &str,
    balance_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-RESERVE-FUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(asset_id),
            HashPart::Str(controller_commitment),
            HashPart::Str(balance_commitment),
        ],
        32,
    )
}

pub fn private_stablecoin_attestation_id(
    committee_id: &str,
    member_commitment: &str,
    market_id: &str,
    subject_kind: &str,
    subject_id: &str,
    payload_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(member_commitment),
            HashPart::Str(market_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_global_settlement_id(
    market_id: &str,
    initiator_commitment: &str,
    settlement_price_root: &str,
    initiated_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-GLOBAL-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(initiator_commitment),
            HashPart::Str(settlement_price_root),
            HashPart::Int(initiated_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_sponsorship_id(
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    market_id: &str,
    operation_kind: StablecoinOperationKind,
    reserved_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(market_id),
            HashPart::Str(operation_kind.as_str()),
            HashPart::Int(reserved_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_contract_adapter_id(
    market_id: &str,
    adapter_kind: &str,
    contract_id: &str,
    selector_root: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-CONTRACT-ADAPTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(adapter_kind),
            HashPart::Str(contract_id),
            HashPart::Str(selector_root),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_token_hook_id(
    market_id: &str,
    stable_asset_id: &str,
    factory_contract_id: &str,
    hook_kind: TokenFactoryHookKind,
    registered_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-TOKEN-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(stable_asset_id),
            HashPart::Str(factory_contract_id),
            HashPart::Str(hook_kind.as_str()),
            HashPart::Int(registered_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_privacy_disclosure_id(
    market_id: &str,
    scope: PrivacyDisclosureScope,
    viewer_commitment: &str,
    statement_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-PRIVACY-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(viewer_commitment),
            HashPart::Str(statement_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_public_record_id(
    object_kind: &str,
    object_id: &str,
    payload_root: &str,
    recorded_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Str(payload_root),
            HashPart::Int(recorded_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_stablecoin_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_stablecoin_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_stablecoin_proof_root(
    proof_system: &str,
    public_input_root: &str,
    private_witness_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-STABLECOIN-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_root),
        ],
        32,
    )
}

pub fn private_stablecoin_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn private_stablecoin_string_list_root(domain: &str, values: &[String]) -> String {
    let mut values = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    merkle_root(
        domain,
        &values.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

pub fn private_stablecoin_market_root(markets: &[PrivateStablecoinMarket]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-MARKET",
        markets
            .iter()
            .map(PrivateStablecoinMarket::public_record)
            .collect(),
        "market_id",
    )
}

pub fn private_stablecoin_collateral_vault_root(vaults: &[ConfidentialCollateralVault]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-COLLATERAL-VAULT",
        vaults
            .iter()
            .map(ConfidentialCollateralVault::public_record)
            .collect(),
        "vault_id",
    )
}

pub fn private_stablecoin_debt_position_root(positions: &[SealedDebtPosition]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-DEBT-POSITION",
        positions
            .iter()
            .map(SealedDebtPosition::public_record)
            .collect(),
        "position_id",
    )
}

pub fn private_stablecoin_operation_root(operations: &[MintRedeemBurnCommitment]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-OPERATION",
        operations
            .iter()
            .map(MintRedeemBurnCommitment::public_record)
            .collect(),
        "operation_id",
    )
}

pub fn private_stablecoin_supply_cap_root(caps: &[StablecoinSupplyCapSnapshot]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-SUPPLY-CAP",
        caps.iter()
            .map(StablecoinSupplyCapSnapshot::public_record)
            .collect(),
        "cap_id",
    )
}

pub fn private_stablecoin_oracle_root(oracles: &[OraclePriceRootCommitment]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-ORACLE-ROOT",
        oracles
            .iter()
            .map(OraclePriceRootCommitment::public_record)
            .collect(),
        "oracle_root_id",
    )
}

pub fn private_stablecoin_collateral_bucket_root(
    disclosures: &[CollateralRatioBucketDisclosure],
) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-COLLATERAL-BUCKET",
        disclosures
            .iter()
            .map(CollateralRatioBucketDisclosure::public_record)
            .collect(),
        "bucket_id",
    )
}

pub fn private_stablecoin_liquidation_queue_root(liquidations: &[LiquidationQueueEntry]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-LIQUIDATION-QUEUE",
        liquidations
            .iter()
            .map(LiquidationQueueEntry::public_record)
            .collect(),
        "liquidation_id",
    )
}

pub fn private_stablecoin_liquidation_auction_root(
    auctions: &[PrivateLiquidationAuction],
) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-LIQUIDATION-AUCTION",
        auctions
            .iter()
            .map(PrivateLiquidationAuction::public_record)
            .collect(),
        "auction_id",
    )
}

pub fn private_stablecoin_liquidation_challenge_root(
    challenges: &[LiquidationChallenge],
) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-LIQUIDATION-CHALLENGE",
        challenges
            .iter()
            .map(LiquidationChallenge::public_record)
            .collect(),
        "challenge_id",
    )
}

pub fn private_stablecoin_stability_fee_root(accruals: &[StabilityFeeAccrual]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-STABILITY-FEE",
        accruals
            .iter()
            .map(StabilityFeeAccrual::public_record)
            .collect(),
        "accrual_id",
    )
}

pub fn private_stablecoin_reserve_fund_root(funds: &[ReserveFundAccounting]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-RESERVE-FUND",
        funds
            .iter()
            .map(ReserveFundAccounting::public_record)
            .collect(),
        "fund_id",
    )
}

pub fn private_stablecoin_pq_attestation_root(
    attestations: &[PqRiskCommitteeAttestation],
) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-PQ-ATTESTATION",
        attestations
            .iter()
            .map(PqRiskCommitteeAttestation::public_record)
            .collect(),
        "attestation_id",
    )
}

pub fn private_stablecoin_global_settlement_root(
    settlements: &[EmergencyGlobalSettlement],
) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-GLOBAL-SETTLEMENT",
        settlements
            .iter()
            .map(EmergencyGlobalSettlement::public_record)
            .collect(),
        "settlement_id",
    )
}

pub fn private_stablecoin_low_fee_sponsorship_root(
    sponsorships: &[LowFeeStablecoinSponsorship],
) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-LOW-FEE-SPONSORSHIP",
        sponsorships
            .iter()
            .map(LowFeeStablecoinSponsorship::public_record)
            .collect(),
        "sponsorship_id",
    )
}

pub fn private_stablecoin_contract_adapter_root(adapters: &[ContractAdapterRoot]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-CONTRACT-ADAPTER",
        adapters
            .iter()
            .map(ContractAdapterRoot::public_record)
            .collect(),
        "adapter_id",
    )
}

pub fn private_stablecoin_token_factory_hook_root(hooks: &[TokenFactoryHook]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-TOKEN-FACTORY-HOOK",
        hooks.iter().map(TokenFactoryHook::public_record).collect(),
        "hook_id",
    )
}

pub fn private_stablecoin_privacy_disclosure_root(
    disclosures: &[PrivacyBucketDisclosure],
) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-PRIVACY-DISCLOSURE",
        disclosures
            .iter()
            .map(PrivacyBucketDisclosure::public_record)
            .collect(),
        "disclosure_id",
    )
}

pub fn private_stablecoin_public_record_root(records: &[PrivateStablecoinPublicRecord]) -> String {
    sorted_merkle_root(
        "PRIVATE-STABLECOIN-PUBLIC-RECORD",
        records
            .iter()
            .map(PrivateStablecoinPublicRecord::public_record)
            .collect(),
        "record_id",
    )
}

pub fn private_stablecoin_risk_status(score_bps: u64) -> &'static str {
    if score_bps >= 9_000 {
        "critical"
    } else if score_bps >= 6_000 {
        "elevated"
    } else if score_bps >= 2_000 {
        "watch"
    } else {
        "normal"
    }
}

fn sorted_merkle_root(domain: &str, mut leaves: Vec<Value>, sort_key: &str) -> String {
    leaves.sort_by_key(|record| {
        record
            .get(sort_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    merkle_root(domain, &leaves)
}

fn normalize_label(value: String) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for character in value.trim().chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    normalized.trim_matches('_').to_string()
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateStablecoinResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_status(value: &str, allowed: &[&str]) -> PrivateStablecoinResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("status {value} is not allowed"))
    }
}

fn validate_bps(label: &str, value: u64, max_bps: u64) -> PrivateStablecoinResult<()> {
    if value > max_bps {
        Err(format!("{label} exceeds {max_bps} bps"))
    } else {
        Ok(())
    }
}

fn ensure_state_market(
    markets: &BTreeMap<String, PrivateStablecoinMarket>,
    market_id: &str,
    label: &str,
) -> PrivateStablecoinResult<()> {
    if markets.contains_key(market_id) {
        Ok(())
    } else {
        Err(format!("{label} references unknown stablecoin market"))
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let value = (numerator as u128).saturating_mul(PRIVATE_STABLECOIN_MAX_BPS as u128)
        / denominator as u128;
    value.min(u64::MAX as u128) as u64
}

fn annualized_bps_accrual(amount_units: u64, annual_bps: u64, blocks: u64) -> u64 {
    let numerator = (amount_units as u128)
        .saturating_mul(annual_bps as u128)
        .saturating_mul(blocks as u128);
    let denominator = (PRIVATE_STABLECOIN_MAX_BPS as u128)
        .saturating_mul(PRIVATE_STABLECOIN_BLOCKS_PER_YEAR as u128);
    if denominator == 0 {
        return 0;
    }
    (numerator / denominator).min(u64::MAX as u128) as u64
}
