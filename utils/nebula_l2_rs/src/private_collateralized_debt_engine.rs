use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PrivateCollateralizedDebtEngineResult<T> = Result<T, String>;

pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION: &str =
    "nebula-private-collateralized-debt-engine-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_COLLATERAL_COMMITMENT_SCHEME: &str =
    "shake256-confidential-collateral-vault-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEBT_COMMITMENT_SCHEME: &str =
    "shake256-private-stable-debt-position-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_TRIGGER_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+shake256-encrypted-liquidation-trigger-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_KEEPER_BID_SCHEME: &str = "zk-sealed-keeper-bid-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_RATE_EPOCH_SCHEME: &str =
    "deterministic-private-rate-epoch-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-cdp-sponsorship-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_PQ_AUTHORITY_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-risk-authority-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_PRIVACY_BUDGET_SCHEME: &str =
    "bucketed-selective-disclosure-budget-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_SOLVENCY_RECEIPT_SCHEME: &str =
    "zk-private-cdp-solvency-receipt-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-record-root-v1";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_HEIGHT: u64 = 144;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_INDEX_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_LOW_FEE_LANE: &str =
    "small-private-collateralized-debt";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_RESERVE_ASSET_ID: &str = "pcde-reserve-devnet";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_ORACLE_FEED_ID: &str = "feed-wxmr-dusd-devnet";
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_WXMR_PRICE: u64 =
    166 * PRIVATE_COLLATERALIZED_DEBT_ENGINE_PRICE_SCALE;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_TRIGGER_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_BID_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_RATE_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS: u64 = 21_600;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_MARKETS: usize = 65_536;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_VAULTS: usize = 262_144;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_POSITIONS: usize = 262_144;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_TRIGGERS: usize = 262_144;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_BIDS: usize = 524_288;
pub const PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_PUBLIC_RECORDS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebtEngineMarketStatus {
    Active,
    MintPaused,
    RepayOnly,
    LiquidationOnly,
    EmergencySettlement,
    Paused,
    Retired,
}

impl DebtEngineMarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::MintPaused => "mint_paused",
            Self::RepayOnly => "repay_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::EmergencySettlement => "emergency_settlement",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn allows_new_debt(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn allows_repayment(self) -> bool {
        matches!(
            self,
            Self::Active | Self::MintPaused | Self::RepayOnly | Self::EmergencySettlement
        )
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(
            self,
            Self::Active | Self::MintPaused | Self::RepayOnly | Self::LiquidationOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialVaultStatus {
    Pending,
    Open,
    Encumbered,
    Frozen,
    Liquidating,
    Settled,
    Closed,
    Expired,
}

impl ConfidentialVaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Encumbered => "encumbered",
            Self::Frozen => "frozen",
            Self::Liquidating => "liquidating",
            Self::Settled => "settled",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Open | Self::Encumbered | Self::Frozen | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDebtPositionStatus {
    Pending,
    Open,
    RateLocked,
    RepayOnly,
    Triggered,
    Liquidating,
    Settled,
    Closed,
    Expired,
}

impl PrivateDebtPositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::RateLocked => "rate_locked",
            Self::RepayOnly => "repay_only",
            Self::Triggered => "triggered",
            Self::Liquidating => "liquidating",
            Self::Settled => "settled",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_debt(self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Open
                | Self::RateLocked
                | Self::RepayOnly
                | Self::Triggered
                | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralHealthBucket {
    NoDebt,
    SuperSafe,
    Healthy,
    Watch,
    Unsafe,
    Liquidatable,
    Insolvent,
}

impl CollateralHealthBucket {
    pub fn as_str(self) -> &'static str {
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

    pub fn floor_bps(self) -> u64 {
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

    pub fn liquidatable(self) -> bool {
        matches!(self, Self::Liquidatable | Self::Insolvent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebtAmountBucket {
    Dust,
    Small,
    Medium,
    Large,
    Whale,
}

impl DebtAmountBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dust => "dust",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Whale => "whale",
        }
    }

    pub fn max_units(self) -> u64 {
        match self {
            Self::Dust => 1_000_000,
            Self::Small => 25_000_000,
            Self::Medium => 250_000_000,
            Self::Large => 5_000_000_000,
            Self::Whale => u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationTriggerStatus {
    Armed,
    Observed,
    Eligible,
    BidWindow,
    Settled,
    Cancelled,
    Expired,
}

impl LiquidationTriggerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Observed => "observed",
            Self::Eligible => "eligible",
            Self::BidWindow => "bid_window",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Armed | Self::Observed | Self::Eligible | Self::BidWindow
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeeperBidStatus {
    Submitted,
    Eligible,
    Winning,
    Outbid,
    Revealed,
    Settled,
    Rejected,
    Expired,
}

impl KeeperBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Eligible => "eligible",
            Self::Winning => "winning",
            Self::Outbid => "outbid",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Submitted | Self::Eligible | Self::Winning)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRiskDecision {
    Approve,
    Watch,
    ReduceOnly,
    PauseMint,
    LiquidationOnly,
    EmergencySettlement,
    Revoke,
}

impl PqRiskDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::PauseMint => "pause_mint",
            Self::LiquidationOnly => "liquidation_only",
            Self::EmergencySettlement => "emergency_settlement",
            Self::Revoke => "revoke",
        }
    }

    pub fn allows_new_debt(self) -> bool {
        matches!(self, Self::Approve | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Active,
    Superseded,
    Suspended,
    Revoked,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Active,
    Exhausted,
    Frozen,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
        }
    }

    pub fn can_spend(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetStatus {
    Active,
    Constrained,
    Exhausted,
    Frozen,
    Expired,
}

impl PrivacyBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Constrained => "constrained",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Constrained)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencyReceiptStatus {
    Posted,
    Accepted,
    Challenged,
    Finalized,
    Superseded,
    Expired,
}

impl SolvencyReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    MarketOpened,
    VaultCommitted,
    DebtPositionCommitted,
    TriggerArmed,
    KeeperBidSealed,
    RateEpochPosted,
    SponsorshipPosted,
    PqAttestationPosted,
    PrivacyBudgetPosted,
    SolvencyReceiptPosted,
    StateCheckpoint,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketOpened => "market_opened",
            Self::VaultCommitted => "vault_committed",
            Self::DebtPositionCommitted => "debt_position_committed",
            Self::TriggerArmed => "trigger_armed",
            Self::KeeperBidSealed => "keeper_bid_sealed",
            Self::RateEpochPosted => "rate_epoch_posted",
            Self::SponsorshipPosted => "sponsorship_posted",
            Self::PqAttestationPosted => "pq_attestation_posted",
            Self::PrivacyBudgetPosted => "privacy_budget_posted",
            Self::SolvencyReceiptPosted => "solvency_receipt_posted",
            Self::StateCheckpoint => "state_checkpoint",
        }
    }
}

fn debt_engine_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn debt_engine_collection_root(domain: &str, records: &[Value]) -> String {
    let payload = Value::Array(records.to_vec());
    debt_engine_record_root(domain, &payload)
}

fn debt_engine_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn debt_engine_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn non_empty(field: &str, value: &str) -> PrivateCollateralizedDebtEngineResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_bps(field: &str, value: u64) -> PrivateCollateralizedDebtEngineResult<()> {
    if value > PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn validate_window(
    starts_at_height: u64,
    expires_at_height: u64,
    label: &str,
) -> PrivateCollateralizedDebtEngineResult<()> {
    if expires_at_height <= starts_at_height {
        Err(format!("{label} expiry must be after start height"))
    } else {
        Ok(())
    }
}

fn value_records<T>(values: &BTreeMap<String, T>, record: fn(&T) -> Value) -> Vec<Value> {
    values.values().map(record).collect::<Vec<_>>()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCollateralizedDebtEngineConfig {
    pub protocol_version: String,
    pub collateral_asset_id: String,
    pub stable_asset_id: String,
    pub reserve_asset_id: String,
    pub collateral_commitment_scheme: String,
    pub debt_commitment_scheme: String,
    pub trigger_encryption_scheme: String,
    pub keeper_bid_scheme: String,
    pub rate_epoch_scheme: String,
    pub sponsorship_scheme: String,
    pub pq_authority_scheme: String,
    pub privacy_budget_scheme: String,
    pub solvency_receipt_scheme: String,
    pub public_record_scheme: String,
    pub default_low_fee_lane: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub minimum_collateral_ratio_bps: u64,
    pub liquidation_ratio_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub reserve_factor_bps: u64,
    pub stability_fee_annual_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub default_trigger_ttl_blocks: u64,
    pub default_bid_ttl_blocks: u64,
    pub default_rate_epoch_blocks: u64,
    pub default_privacy_budget_ttl_blocks: u64,
    pub default_sponsorship_ttl_blocks: u64,
    pub default_attestation_ttl_blocks: u64,
    pub default_receipt_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub sponsored_small_debt_limit_units: u64,
    pub sponsored_max_fee_units: u64,
    pub metadata_root: String,
}

impl Default for PrivateCollateralizedDebtEngineConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl PrivateCollateralizedDebtEngineConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION.to_string(),
            collateral_asset_id: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_COLLATERAL_ASSET_ID
                .to_string(),
            stable_asset_id: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_STABLE_ASSET_ID.to_string(),
            reserve_asset_id: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_RESERVE_ASSET_ID
                .to_string(),
            collateral_commitment_scheme:
                PRIVATE_COLLATERALIZED_DEBT_ENGINE_COLLATERAL_COMMITMENT_SCHEME.to_string(),
            debt_commitment_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEBT_COMMITMENT_SCHEME
                .to_string(),
            trigger_encryption_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_TRIGGER_ENCRYPTION_SCHEME
                .to_string(),
            keeper_bid_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_KEEPER_BID_SCHEME.to_string(),
            rate_epoch_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_RATE_EPOCH_SCHEME.to_string(),
            sponsorship_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_SPONSORSHIP_SCHEME.to_string(),
            pq_authority_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_PQ_AUTHORITY_SCHEME.to_string(),
            privacy_budget_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_PRIVACY_BUDGET_SCHEME
                .to_string(),
            solvency_receipt_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_SOLVENCY_RECEIPT_SCHEME
                .to_string(),
            public_record_scheme: PRIVATE_COLLATERALIZED_DEBT_ENGINE_PUBLIC_RECORD_SCHEME
                .to_string(),
            default_low_fee_lane: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_LOW_FEE_LANE
                .to_string(),
            price_scale: PRIVATE_COLLATERALIZED_DEBT_ENGINE_PRICE_SCALE,
            index_scale: PRIVATE_COLLATERALIZED_DEBT_ENGINE_INDEX_SCALE,
            minimum_collateral_ratio_bps: 18_000,
            liquidation_ratio_bps: 13_500,
            liquidation_penalty_bps: 800,
            reserve_factor_bps: 1_500,
            stability_fee_annual_bps: 250,
            max_oracle_staleness_blocks: 12,
            default_trigger_ttl_blocks:
                PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_TRIGGER_TTL_BLOCKS,
            default_bid_ttl_blocks: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_BID_TTL_BLOCKS,
            default_rate_epoch_blocks: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_RATE_EPOCH_BLOCKS,
            default_privacy_budget_ttl_blocks:
                PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS,
            default_sponsorship_ttl_blocks:
                PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            default_attestation_ttl_blocks:
                PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            default_receipt_ttl_blocks:
                PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_RECEIPT_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS,
            sponsored_small_debt_limit_units: 25_000_000,
            sponsored_max_fee_units: 5_000,
            metadata_root: debt_engine_payload_root(
                "PRIVATE-COLLATERALIZED-DEBT-ENGINE-CONFIG-METADATA",
                &json!({
                    "mode": "devnet",
                    "privacy": "bucketed-collateral-and-debt",
                    "pq_resistance": "ml-kem+ml-dsa+slh-dsa",
                    "fees": "sponsored-small-private-debt"
                }),
            ),
        }
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("protocol_version", &self.protocol_version)?;
        non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        non_empty("stable_asset_id", &self.stable_asset_id)?;
        non_empty("reserve_asset_id", &self.reserve_asset_id)?;
        non_empty(
            "collateral_commitment_scheme",
            &self.collateral_commitment_scheme,
        )?;
        non_empty("debt_commitment_scheme", &self.debt_commitment_scheme)?;
        non_empty("trigger_encryption_scheme", &self.trigger_encryption_scheme)?;
        non_empty("keeper_bid_scheme", &self.keeper_bid_scheme)?;
        non_empty("rate_epoch_scheme", &self.rate_epoch_scheme)?;
        non_empty("sponsorship_scheme", &self.sponsorship_scheme)?;
        non_empty("pq_authority_scheme", &self.pq_authority_scheme)?;
        non_empty("privacy_budget_scheme", &self.privacy_budget_scheme)?;
        non_empty("solvency_receipt_scheme", &self.solvency_receipt_scheme)?;
        non_empty("public_record_scheme", &self.public_record_scheme)?;
        non_empty("default_low_fee_lane", &self.default_low_fee_lane)?;
        validate_bps(
            "minimum_collateral_ratio_bps",
            self.minimum_collateral_ratio_bps,
        )?;
        validate_bps("liquidation_ratio_bps", self.liquidation_ratio_bps)?;
        validate_bps("liquidation_penalty_bps", self.liquidation_penalty_bps)?;
        validate_bps("reserve_factor_bps", self.reserve_factor_bps)?;
        validate_bps("stability_fee_annual_bps", self.stability_fee_annual_bps)?;
        if self.liquidation_ratio_bps >= self.minimum_collateral_ratio_bps {
            return Err("liquidation ratio must be below minimum collateral ratio".to_string());
        }
        if self.price_scale == 0 || self.index_scale == 0 {
            return Err("price and index scales must be non-zero".to_string());
        }
        if self.min_pq_security_bits
            < PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("min pq security bits below protocol floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_collateralized_debt_engine_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "collateral_asset_id": self.collateral_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "collateral_commitment_scheme": self.collateral_commitment_scheme,
            "debt_commitment_scheme": self.debt_commitment_scheme,
            "trigger_encryption_scheme": self.trigger_encryption_scheme,
            "keeper_bid_scheme": self.keeper_bid_scheme,
            "rate_epoch_scheme": self.rate_epoch_scheme,
            "sponsorship_scheme": self.sponsorship_scheme,
            "pq_authority_scheme": self.pq_authority_scheme,
            "privacy_budget_scheme": self.privacy_budget_scheme,
            "solvency_receipt_scheme": self.solvency_receipt_scheme,
            "public_record_scheme": self.public_record_scheme,
            "default_low_fee_lane": self.default_low_fee_lane,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "minimum_collateral_ratio_bps": self.minimum_collateral_ratio_bps,
            "liquidation_ratio_bps": self.liquidation_ratio_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "stability_fee_annual_bps": self.stability_fee_annual_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "default_trigger_ttl_blocks": self.default_trigger_ttl_blocks,
            "default_bid_ttl_blocks": self.default_bid_ttl_blocks,
            "default_rate_epoch_blocks": self.default_rate_epoch_blocks,
            "default_privacy_budget_ttl_blocks": self.default_privacy_budget_ttl_blocks,
            "default_sponsorship_ttl_blocks": self.default_sponsorship_ttl_blocks,
            "default_attestation_ttl_blocks": self.default_attestation_ttl_blocks,
            "default_receipt_ttl_blocks": self.default_receipt_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "sponsored_small_debt_limit_units": self.sponsored_small_debt_limit_units,
            "sponsored_max_fee_units": self.sponsored_max_fee_units,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root(
            "PRIVATE-COLLATERALIZED-DEBT-ENGINE-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebtEngineMarket {
    pub market_id: String,
    pub label: String,
    pub collateral_asset_id: String,
    pub stable_asset_id: String,
    pub reserve_asset_id: String,
    pub oracle_feed_id: String,
    pub low_fee_lane: String,
    pub status: DebtEngineMarketStatus,
    pub collateral_commitment_root: String,
    pub debt_commitment_root: String,
    pub trigger_root: String,
    pub keeper_bid_root: String,
    pub rate_epoch_root: String,
    pub pq_authority_root: String,
    pub privacy_budget_root: String,
    pub solvency_receipt_root: String,
    pub minimum_collateral_ratio_bps: u64,
    pub liquidation_ratio_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub stability_fee_annual_bps: u64,
    pub reserve_factor_bps: u64,
    pub supply_ceiling_units: u64,
    pub private_debt_upper_bound_units: u64,
    pub created_at_height: u64,
    pub metadata_root: String,
}

impl DebtEngineMarket {
    pub fn new(
        label: &str,
        collateral_asset_id: &str,
        stable_asset_id: &str,
        reserve_asset_id: &str,
        oracle_feed_id: &str,
        low_fee_lane: &str,
        minimum_collateral_ratio_bps: u64,
        liquidation_ratio_bps: u64,
        liquidation_penalty_bps: u64,
        stability_fee_annual_bps: u64,
        reserve_factor_bps: u64,
        supply_ceiling_units: u64,
        created_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("label", label)?;
        non_empty("collateral_asset_id", collateral_asset_id)?;
        non_empty("stable_asset_id", stable_asset_id)?;
        non_empty("reserve_asset_id", reserve_asset_id)?;
        non_empty("oracle_feed_id", oracle_feed_id)?;
        non_empty("low_fee_lane", low_fee_lane)?;
        validate_bps("minimum_collateral_ratio_bps", minimum_collateral_ratio_bps)?;
        validate_bps("liquidation_ratio_bps", liquidation_ratio_bps)?;
        validate_bps("liquidation_penalty_bps", liquidation_penalty_bps)?;
        validate_bps("stability_fee_annual_bps", stability_fee_annual_bps)?;
        validate_bps("reserve_factor_bps", reserve_factor_bps)?;
        if liquidation_ratio_bps >= minimum_collateral_ratio_bps {
            return Err(
                "market liquidation ratio must be below minimum collateral ratio".to_string(),
            );
        }
        let market_id = debt_engine_payload_root(
            "PRIVATE-COLLATERALIZED-DEBT-ENGINE-MARKET-ID",
            &json!({
                "label": label,
                "collateral_asset_id": collateral_asset_id,
                "stable_asset_id": stable_asset_id,
                "oracle_feed_id": oracle_feed_id,
                "created_at_height": created_at_height,
            }),
        );
        Ok(Self {
            market_id,
            label: label.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            stable_asset_id: stable_asset_id.to_string(),
            reserve_asset_id: reserve_asset_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            status: DebtEngineMarketStatus::Active,
            collateral_commitment_root: debt_engine_string_root("PCDE-EMPTY-COLLATERAL", label),
            debt_commitment_root: debt_engine_string_root("PCDE-EMPTY-DEBT", label),
            trigger_root: debt_engine_string_root("PCDE-EMPTY-TRIGGERS", label),
            keeper_bid_root: debt_engine_string_root("PCDE-EMPTY-BIDS", label),
            rate_epoch_root: debt_engine_string_root("PCDE-EMPTY-RATES", label),
            pq_authority_root: debt_engine_string_root("PCDE-EMPTY-PQ-AUTH", label),
            privacy_budget_root: debt_engine_string_root("PCDE-EMPTY-PRIVACY-BUDGET", label),
            solvency_receipt_root: debt_engine_string_root("PCDE-EMPTY-SOLVENCY", label),
            minimum_collateral_ratio_bps,
            liquidation_ratio_bps,
            liquidation_penalty_bps,
            stability_fee_annual_bps,
            reserve_factor_bps,
            supply_ceiling_units,
            private_debt_upper_bound_units: 0,
            created_at_height,
            metadata_root: debt_engine_payload_root("PCDE-MARKET-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("market_id", &self.market_id)?;
        non_empty("label", &self.label)?;
        non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        non_empty("stable_asset_id", &self.stable_asset_id)?;
        non_empty("reserve_asset_id", &self.reserve_asset_id)?;
        non_empty("oracle_feed_id", &self.oracle_feed_id)?;
        non_empty("low_fee_lane", &self.low_fee_lane)?;
        validate_bps(
            "minimum_collateral_ratio_bps",
            self.minimum_collateral_ratio_bps,
        )?;
        validate_bps("liquidation_ratio_bps", self.liquidation_ratio_bps)?;
        validate_bps("liquidation_penalty_bps", self.liquidation_penalty_bps)?;
        validate_bps("stability_fee_annual_bps", self.stability_fee_annual_bps)?;
        validate_bps("reserve_factor_bps", self.reserve_factor_bps)?;
        if self.private_debt_upper_bound_units > self.supply_ceiling_units {
            return Err("private debt upper bound exceeds supply ceiling".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "debt_engine_market",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "label": self.label,
            "collateral_asset_id": self.collateral_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "low_fee_lane": self.low_fee_lane,
            "status": self.status.as_str(),
            "collateral_commitment_root": self.collateral_commitment_root,
            "debt_commitment_root": self.debt_commitment_root,
            "trigger_root": self.trigger_root,
            "keeper_bid_root": self.keeper_bid_root,
            "rate_epoch_root": self.rate_epoch_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_budget_root": self.privacy_budget_root,
            "solvency_receipt_root": self.solvency_receipt_root,
            "minimum_collateral_ratio_bps": self.minimum_collateral_ratio_bps,
            "liquidation_ratio_bps": self.liquidation_ratio_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "stability_fee_annual_bps": self.stability_fee_annual_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "supply_ceiling_units": self.supply_ceiling_units,
            "private_debt_upper_bound_units": self.private_debt_upper_bound_units,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-MARKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialCollateralVault {
    pub vault_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub collateral_asset_id: String,
    pub amount_bucket: String,
    pub amount_upper_bound_units: u64,
    pub collateral_commitment: String,
    pub blinding_commitment: String,
    pub encrypted_note_root: String,
    pub spend_authorization_root: String,
    pub nullifier_root: String,
    pub status: ConfidentialVaultStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl ConfidentialCollateralVault {
    pub fn new(
        market_id: &str,
        owner_commitment: &str,
        collateral_asset_id: &str,
        amount_bucket: &str,
        amount_upper_bound_units: u64,
        blinding_hint: &str,
        encrypted_note: &Value,
        spend_policy: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("market_id", market_id)?;
        non_empty("owner_commitment", owner_commitment)?;
        non_empty("collateral_asset_id", collateral_asset_id)?;
        non_empty("amount_bucket", amount_bucket)?;
        non_empty("blinding_hint", blinding_hint)?;
        validate_window(created_at_height, expires_at_height, "vault")?;
        let collateral_commitment = debt_engine_payload_root(
            "PCDE-COLLATERAL-COMMITMENT",
            &json!({
                "market_id": market_id,
                "owner_commitment": owner_commitment,
                "asset": collateral_asset_id,
                "amount_bucket": amount_bucket,
                "amount_upper_bound_units": amount_upper_bound_units,
                "blinding_hint": blinding_hint,
            }),
        );
        let vault_id = debt_engine_payload_root(
            "PCDE-COLLATERAL-VAULT-ID",
            &json!({
                "market_id": market_id,
                "owner_commitment": owner_commitment,
                "collateral_commitment": collateral_commitment,
                "created_at_height": created_at_height,
            }),
        );
        Ok(Self {
            vault_id,
            market_id: market_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            amount_bucket: amount_bucket.to_string(),
            amount_upper_bound_units,
            collateral_commitment,
            blinding_commitment: debt_engine_string_root("PCDE-VAULT-BLINDING", blinding_hint),
            encrypted_note_root: debt_engine_payload_root(
                "PCDE-VAULT-ENCRYPTED-NOTE",
                encrypted_note,
            ),
            spend_authorization_root: debt_engine_payload_root(
                "PCDE-VAULT-SPEND-POLICY",
                spend_policy,
            ),
            nullifier_root: debt_engine_string_root("PCDE-VAULT-NULLIFIER", owner_commitment),
            status: ConfidentialVaultStatus::Open,
            created_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-VAULT-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("vault_id", &self.vault_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("owner_commitment", &self.owner_commitment)?;
        non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        non_empty("amount_bucket", &self.amount_bucket)?;
        validate_window(self.created_at_height, self.expires_at_height, "vault")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_collateral_vault",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "vault_id": self.vault_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "amount_bucket": self.amount_bucket,
            "amount_upper_bound_units": self.amount_upper_bound_units,
            "collateral_commitment": self.collateral_commitment,
            "blinding_commitment": self.blinding_commitment,
            "encrypted_note_root": self.encrypted_note_root,
            "spend_authorization_root": self.spend_authorization_root,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-CONFIDENTIAL-COLLATERAL-VAULT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStableDebtPosition {
    pub position_id: String,
    pub market_id: String,
    pub vault_id: String,
    pub borrower_commitment: String,
    pub stable_asset_id: String,
    pub debt_amount_bucket: DebtAmountBucket,
    pub debt_upper_bound_units: u64,
    pub collateral_health_bucket: CollateralHealthBucket,
    pub rate_epoch_id: String,
    pub debt_commitment: String,
    pub encrypted_terms_root: String,
    pub solvency_proof_root: String,
    pub privacy_budget_id: String,
    pub status: PrivateDebtPositionStatus,
    pub rate_index_snapshot: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl PrivateStableDebtPosition {
    pub fn new(
        market_id: &str,
        vault_id: &str,
        borrower_commitment: &str,
        stable_asset_id: &str,
        debt_amount_bucket: DebtAmountBucket,
        debt_upper_bound_units: u64,
        collateral_health_bucket: CollateralHealthBucket,
        rate_epoch_id: &str,
        terms: &Value,
        solvency_proof: &Value,
        privacy_budget_id: &str,
        rate_index_snapshot: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("market_id", market_id)?;
        non_empty("vault_id", vault_id)?;
        non_empty("borrower_commitment", borrower_commitment)?;
        non_empty("stable_asset_id", stable_asset_id)?;
        non_empty("rate_epoch_id", rate_epoch_id)?;
        non_empty("privacy_budget_id", privacy_budget_id)?;
        validate_window(opened_at_height, expires_at_height, "debt position")?;
        if debt_upper_bound_units > debt_amount_bucket.max_units() {
            return Err("debt upper bound exceeds bucket maximum".to_string());
        }
        let debt_commitment = debt_engine_payload_root(
            "PCDE-STABLE-DEBT-COMMITMENT",
            &json!({
                "market_id": market_id,
                "vault_id": vault_id,
                "borrower_commitment": borrower_commitment,
                "stable_asset_id": stable_asset_id,
                "bucket": debt_amount_bucket.as_str(),
                "debt_upper_bound_units": debt_upper_bound_units,
                "rate_epoch_id": rate_epoch_id,
            }),
        );
        let position_id = debt_engine_payload_root(
            "PCDE-STABLE-DEBT-POSITION-ID",
            &json!({
                "market_id": market_id,
                "vault_id": vault_id,
                "debt_commitment": debt_commitment,
                "opened_at_height": opened_at_height,
            }),
        );
        Ok(Self {
            position_id,
            market_id: market_id.to_string(),
            vault_id: vault_id.to_string(),
            borrower_commitment: borrower_commitment.to_string(),
            stable_asset_id: stable_asset_id.to_string(),
            debt_amount_bucket,
            debt_upper_bound_units,
            collateral_health_bucket,
            rate_epoch_id: rate_epoch_id.to_string(),
            debt_commitment,
            encrypted_terms_root: debt_engine_payload_root("PCDE-DEBT-ENCRYPTED-TERMS", terms),
            solvency_proof_root: debt_engine_payload_root(
                "PCDE-DEBT-SOLVENCY-PROOF",
                solvency_proof,
            ),
            privacy_budget_id: privacy_budget_id.to_string(),
            status: PrivateDebtPositionStatus::Open,
            rate_index_snapshot,
            opened_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-DEBT-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("position_id", &self.position_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("vault_id", &self.vault_id)?;
        non_empty("borrower_commitment", &self.borrower_commitment)?;
        non_empty("stable_asset_id", &self.stable_asset_id)?;
        non_empty("rate_epoch_id", &self.rate_epoch_id)?;
        non_empty("privacy_budget_id", &self.privacy_budget_id)?;
        if self.debt_upper_bound_units > self.debt_amount_bucket.max_units() {
            return Err("debt upper bound exceeds bucket maximum".to_string());
        }
        validate_window(
            self.opened_at_height,
            self.expires_at_height,
            "debt position",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_stable_debt_position",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "vault_id": self.vault_id,
            "borrower_commitment": self.borrower_commitment,
            "stable_asset_id": self.stable_asset_id,
            "debt_amount_bucket": self.debt_amount_bucket.as_str(),
            "debt_upper_bound_units": self.debt_upper_bound_units,
            "collateral_health_bucket": self.collateral_health_bucket.as_str(),
            "rate_epoch_id": self.rate_epoch_id,
            "debt_commitment": self.debt_commitment,
            "encrypted_terms_root": self.encrypted_terms_root,
            "solvency_proof_root": self.solvency_proof_root,
            "privacy_budget_id": self.privacy_budget_id,
            "status": self.status.as_str(),
            "rate_index_snapshot": self.rate_index_snapshot,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-STABLE-DEBT-POSITION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedLiquidationTrigger {
    pub trigger_id: String,
    pub market_id: String,
    pub position_id: String,
    pub vault_id: String,
    pub encrypted_trigger_root: String,
    pub observed_health_bucket: CollateralHealthBucket,
    pub oracle_feed_id: String,
    pub oracle_price_root: String,
    pub keeper_committee_root: String,
    pub status: LiquidationTriggerStatus,
    pub armed_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl EncryptedLiquidationTrigger {
    pub fn new(
        market_id: &str,
        position_id: &str,
        vault_id: &str,
        observed_health_bucket: CollateralHealthBucket,
        oracle_feed_id: &str,
        trigger_payload: &Value,
        keeper_committee: &Value,
        armed_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("market_id", market_id)?;
        non_empty("position_id", position_id)?;
        non_empty("vault_id", vault_id)?;
        non_empty("oracle_feed_id", oracle_feed_id)?;
        validate_window(armed_at_height, expires_at_height, "liquidation trigger")?;
        let encrypted_trigger_root =
            debt_engine_payload_root("PCDE-ENCRYPTED-LIQUIDATION-TRIGGER", trigger_payload);
        let trigger_id = debt_engine_payload_root(
            "PCDE-LIQUIDATION-TRIGGER-ID",
            &json!({
                "market_id": market_id,
                "position_id": position_id,
                "vault_id": vault_id,
                "encrypted_trigger_root": encrypted_trigger_root,
                "armed_at_height": armed_at_height,
            }),
        );
        Ok(Self {
            trigger_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            vault_id: vault_id.to_string(),
            encrypted_trigger_root,
            observed_health_bucket,
            oracle_feed_id: oracle_feed_id.to_string(),
            oracle_price_root: debt_engine_payload_root(
                "PCDE-TRIGGER-ORACLE-PRICE",
                trigger_payload,
            ),
            keeper_committee_root: debt_engine_payload_root(
                "PCDE-TRIGGER-KEEPER-COMMITTEE",
                keeper_committee,
            ),
            status: if observed_health_bucket.liquidatable() {
                LiquidationTriggerStatus::Eligible
            } else {
                LiquidationTriggerStatus::Observed
            },
            armed_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-TRIGGER-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("trigger_id", &self.trigger_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("position_id", &self.position_id)?;
        non_empty("vault_id", &self.vault_id)?;
        non_empty("oracle_feed_id", &self.oracle_feed_id)?;
        validate_window(
            self.armed_at_height,
            self.expires_at_height,
            "liquidation trigger",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_liquidation_trigger",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "trigger_id": self.trigger_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "vault_id": self.vault_id,
            "encrypted_trigger_root": self.encrypted_trigger_root,
            "observed_health_bucket": self.observed_health_bucket.as_str(),
            "oracle_feed_id": self.oracle_feed_id,
            "oracle_price_root": self.oracle_price_root,
            "keeper_committee_root": self.keeper_committee_root,
            "status": self.status.as_str(),
            "armed_at_height": self.armed_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-ENCRYPTED-LIQUIDATION-TRIGGER", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKeeperBid {
    pub bid_id: String,
    pub trigger_id: String,
    pub market_id: String,
    pub keeper_commitment: String,
    pub sealed_bid_root: String,
    pub discount_bucket: String,
    pub repay_amount_bucket: DebtAmountBucket,
    pub max_fee_units: u64,
    pub bond_commitment: String,
    pub status: KeeperBidStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl SealedKeeperBid {
    pub fn new(
        trigger_id: &str,
        market_id: &str,
        keeper_commitment: &str,
        bid_payload: &Value,
        discount_bucket: &str,
        repay_amount_bucket: DebtAmountBucket,
        max_fee_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("trigger_id", trigger_id)?;
        non_empty("market_id", market_id)?;
        non_empty("keeper_commitment", keeper_commitment)?;
        non_empty("discount_bucket", discount_bucket)?;
        validate_window(submitted_at_height, expires_at_height, "keeper bid")?;
        let sealed_bid_root = debt_engine_payload_root("PCDE-SEALED-KEEPER-BID", bid_payload);
        let bid_id = debt_engine_payload_root(
            "PCDE-KEEPER-BID-ID",
            &json!({
                "trigger_id": trigger_id,
                "market_id": market_id,
                "keeper_commitment": keeper_commitment,
                "sealed_bid_root": sealed_bid_root,
                "submitted_at_height": submitted_at_height,
            }),
        );
        Ok(Self {
            bid_id,
            trigger_id: trigger_id.to_string(),
            market_id: market_id.to_string(),
            keeper_commitment: keeper_commitment.to_string(),
            sealed_bid_root,
            discount_bucket: discount_bucket.to_string(),
            repay_amount_bucket,
            max_fee_units,
            bond_commitment: debt_engine_string_root("PCDE-KEEPER-BID-BOND", keeper_commitment),
            status: KeeperBidStatus::Submitted,
            submitted_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-KEEPER-BID-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("bid_id", &self.bid_id)?;
        non_empty("trigger_id", &self.trigger_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("keeper_commitment", &self.keeper_commitment)?;
        non_empty("discount_bucket", &self.discount_bucket)?;
        validate_window(
            self.submitted_at_height,
            self.expires_at_height,
            "keeper bid",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_keeper_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "trigger_id": self.trigger_id,
            "market_id": self.market_id,
            "keeper_commitment": self.keeper_commitment,
            "sealed_bid_root": self.sealed_bid_root,
            "discount_bucket": self.discount_bucket,
            "repay_amount_bucket": self.repay_amount_bucket.as_str(),
            "max_fee_units": self.max_fee_units,
            "bond_commitment": self.bond_commitment,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-SEALED-KEEPER-BID", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateEpoch {
    pub epoch_id: String,
    pub market_id: String,
    pub epoch_number: u64,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub base_rate_bps: u64,
    pub stability_fee_bps: u64,
    pub reserve_factor_bps: u64,
    pub debt_index: u64,
    pub utilization_bucket: String,
    pub oracle_root: String,
    pub status: String,
    pub metadata_root: String,
}

impl RateEpoch {
    pub fn new(
        market_id: &str,
        epoch_number: u64,
        starts_at_height: u64,
        ends_at_height: u64,
        base_rate_bps: u64,
        stability_fee_bps: u64,
        reserve_factor_bps: u64,
        debt_index: u64,
        utilization_bucket: &str,
        oracle_payload: &Value,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("market_id", market_id)?;
        non_empty("utilization_bucket", utilization_bucket)?;
        validate_window(starts_at_height, ends_at_height, "rate epoch")?;
        validate_bps("base_rate_bps", base_rate_bps)?;
        validate_bps("stability_fee_bps", stability_fee_bps)?;
        validate_bps("reserve_factor_bps", reserve_factor_bps)?;
        if debt_index == 0 {
            return Err("debt index must be non-zero".to_string());
        }
        let epoch_id = debt_engine_payload_root(
            "PCDE-RATE-EPOCH-ID",
            &json!({
                "market_id": market_id,
                "epoch_number": epoch_number,
                "starts_at_height": starts_at_height,
                "ends_at_height": ends_at_height,
            }),
        );
        Ok(Self {
            epoch_id,
            market_id: market_id.to_string(),
            epoch_number,
            starts_at_height,
            ends_at_height,
            base_rate_bps,
            stability_fee_bps,
            reserve_factor_bps,
            debt_index,
            utilization_bucket: utilization_bucket.to_string(),
            oracle_root: debt_engine_payload_root("PCDE-RATE-EPOCH-ORACLE", oracle_payload),
            status: "active".to_string(),
            metadata_root: debt_engine_payload_root("PCDE-RATE-EPOCH-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("epoch_id", &self.epoch_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("utilization_bucket", &self.utilization_bucket)?;
        validate_window(self.starts_at_height, self.ends_at_height, "rate epoch")?;
        validate_bps("base_rate_bps", self.base_rate_bps)?;
        validate_bps("stability_fee_bps", self.stability_fee_bps)?;
        validate_bps("reserve_factor_bps", self.reserve_factor_bps)?;
        if self.debt_index == 0 {
            Err("debt index must be non-zero".to_string())
        } else {
            Ok(())
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rate_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "market_id": self.market_id,
            "epoch_number": self.epoch_number,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "base_rate_bps": self.base_rate_bps,
            "stability_fee_bps": self.stability_fee_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "debt_index": self.debt_index,
            "utilization_bucket": self.utilization_bucket,
            "oracle_root": self.oracle_root,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-RATE-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub market_id: String,
    pub beneficiary_commitment: String,
    pub low_fee_lane: String,
    pub stable_asset_id: String,
    pub covered_debt_bucket: DebtAmountBucket,
    pub fee_budget_units: u64,
    pub spent_fee_units: u64,
    pub max_fee_per_operation_units: u64,
    pub privacy_set_size: u64,
    pub status: SponsorshipStatus,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl LowFeeSponsorship {
    pub fn new(
        sponsor_commitment: &str,
        market_id: &str,
        beneficiary_commitment: &str,
        low_fee_lane: &str,
        stable_asset_id: &str,
        covered_debt_bucket: DebtAmountBucket,
        fee_budget_units: u64,
        max_fee_per_operation_units: u64,
        privacy_set_size: u64,
        starts_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("sponsor_commitment", sponsor_commitment)?;
        non_empty("market_id", market_id)?;
        non_empty("beneficiary_commitment", beneficiary_commitment)?;
        non_empty("low_fee_lane", low_fee_lane)?;
        non_empty("stable_asset_id", stable_asset_id)?;
        validate_window(starts_at_height, expires_at_height, "low fee sponsorship")?;
        if max_fee_per_operation_units > fee_budget_units {
            return Err("max fee per operation exceeds sponsorship budget".to_string());
        }
        let sponsorship_id = debt_engine_payload_root(
            "PCDE-LOW-FEE-SPONSORSHIP-ID",
            &json!({
                "sponsor_commitment": sponsor_commitment,
                "market_id": market_id,
                "beneficiary_commitment": beneficiary_commitment,
                "starts_at_height": starts_at_height,
            }),
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            market_id: market_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            stable_asset_id: stable_asset_id.to_string(),
            covered_debt_bucket,
            fee_budget_units,
            spent_fee_units: 0,
            max_fee_per_operation_units,
            privacy_set_size,
            status: SponsorshipStatus::Active,
            starts_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-SPONSORSHIP-METADATA", metadata),
        })
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.fee_budget_units.saturating_sub(self.spent_fee_units)
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("sponsorship_id", &self.sponsorship_id)?;
        non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        non_empty("low_fee_lane", &self.low_fee_lane)?;
        non_empty("stable_asset_id", &self.stable_asset_id)?;
        validate_window(
            self.starts_at_height,
            self.expires_at_height,
            "low fee sponsorship",
        )?;
        if self.spent_fee_units > self.fee_budget_units {
            return Err("sponsorship spent fees exceed budget".to_string());
        }
        if self.max_fee_per_operation_units > self.fee_budget_units {
            return Err("max fee per operation exceeds sponsorship budget".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "market_id": self.market_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "low_fee_lane": self.low_fee_lane,
            "stable_asset_id": self.stable_asset_id,
            "covered_debt_bucket": self.covered_debt_bucket.as_str(),
            "fee_budget_units": self.fee_budget_units,
            "spent_fee_units": self.spent_fee_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "max_fee_per_operation_units": self.max_fee_per_operation_units,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-LOW-FEE-SPONSORSHIP", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAuthorityAttestation {
    pub attestation_id: String,
    pub market_id: String,
    pub authority_committee_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub decision: PqRiskDecision,
    pub security_bits: u16,
    pub signer_commitments: BTreeSet<String>,
    pub aggregate_signature_root: String,
    pub evidence_root: String,
    pub status: AttestationStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl PqRiskAuthorityAttestation {
    pub fn new(
        market_id: &str,
        authority_committee_id: &str,
        subject_kind: &str,
        subject_id: &str,
        decision: PqRiskDecision,
        security_bits: u16,
        signers: &[String],
        evidence: &Value,
        aggregate_signature: &Value,
        issued_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("market_id", market_id)?;
        non_empty("authority_committee_id", authority_committee_id)?;
        non_empty("subject_kind", subject_kind)?;
        non_empty("subject_id", subject_id)?;
        validate_window(issued_at_height, expires_at_height, "pq attestation")?;
        if security_bits < PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq attestation below security floor".to_string());
        }
        let signer_commitments = signers.iter().cloned().collect::<BTreeSet<_>>();
        if signer_commitments.is_empty() {
            return Err("pq attestation requires at least one signer".to_string());
        }
        let evidence_root = debt_engine_payload_root("PCDE-PQ-ATTESTATION-EVIDENCE", evidence);
        let attestation_id = debt_engine_payload_root(
            "PCDE-PQ-ATTESTATION-ID",
            &json!({
                "market_id": market_id,
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "decision": decision.as_str(),
                "evidence_root": evidence_root,
                "issued_at_height": issued_at_height,
            }),
        );
        Ok(Self {
            attestation_id,
            market_id: market_id.to_string(),
            authority_committee_id: authority_committee_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            decision,
            security_bits,
            signer_commitments,
            aggregate_signature_root: debt_engine_payload_root(
                "PCDE-PQ-ATTESTATION-AGGREGATE-SIGNATURE",
                aggregate_signature,
            ),
            evidence_root,
            status: AttestationStatus::Active,
            issued_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-PQ-ATTESTATION-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("attestation_id", &self.attestation_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("authority_committee_id", &self.authority_committee_id)?;
        non_empty("subject_kind", &self.subject_kind)?;
        non_empty("subject_id", &self.subject_id)?;
        validate_window(
            self.issued_at_height,
            self.expires_at_height,
            "pq attestation",
        )?;
        if self.security_bits < PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq attestation below security floor".to_string());
        }
        if self.signer_commitments.is_empty() {
            return Err("pq attestation requires at least one signer".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_risk_authority_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "market_id": self.market_id,
            "authority_committee_id": self.authority_committee_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "decision": self.decision.as_str(),
            "security_bits": self.security_bits,
            "signer_commitments": self.signer_commitments,
            "aggregate_signature_root": self.aggregate_signature_root,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-PQ-RISK-AUTHORITY-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetConstraint {
    pub budget_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub allowed_disclosure_tags: BTreeSet<String>,
    pub nullifier_domain_root: String,
    pub max_public_events: u64,
    pub used_public_events: u64,
    pub min_anonymity_set_size: u64,
    pub max_bucket_precision_bits: u8,
    pub selective_disclosure_root: String,
    pub status: PrivacyBudgetStatus,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl PrivacyBudgetConstraint {
    pub fn new(
        market_id: &str,
        owner_commitment: &str,
        allowed_tags: &[String],
        max_public_events: u64,
        min_anonymity_set_size: u64,
        max_bucket_precision_bits: u8,
        disclosure_policy: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("market_id", market_id)?;
        non_empty("owner_commitment", owner_commitment)?;
        validate_window(starts_at_height, expires_at_height, "privacy budget")?;
        if max_public_events == 0 {
            return Err("privacy budget must allow at least one public event".to_string());
        }
        let allowed_disclosure_tags = allowed_tags.iter().cloned().collect::<BTreeSet<_>>();
        if allowed_disclosure_tags.is_empty() {
            return Err("privacy budget requires disclosure tags".to_string());
        }
        let selective_disclosure_root =
            debt_engine_payload_root("PCDE-PRIVACY-BUDGET-DISCLOSURE-POLICY", disclosure_policy);
        let budget_id = debt_engine_payload_root(
            "PCDE-PRIVACY-BUDGET-ID",
            &json!({
                "market_id": market_id,
                "owner_commitment": owner_commitment,
                "selective_disclosure_root": selective_disclosure_root,
                "starts_at_height": starts_at_height,
            }),
        );
        Ok(Self {
            budget_id,
            market_id: market_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            allowed_disclosure_tags,
            nullifier_domain_root: debt_engine_string_root(
                "PCDE-PRIVACY-BUDGET-NULLIFIER",
                owner_commitment,
            ),
            max_public_events,
            used_public_events: 0,
            min_anonymity_set_size,
            max_bucket_precision_bits,
            selective_disclosure_root,
            status: PrivacyBudgetStatus::Active,
            starts_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-PRIVACY-BUDGET-METADATA", metadata),
        })
    }

    pub fn remaining_public_events(&self) -> u64 {
        self.max_public_events
            .saturating_sub(self.used_public_events)
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("budget_id", &self.budget_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("owner_commitment", &self.owner_commitment)?;
        validate_window(
            self.starts_at_height,
            self.expires_at_height,
            "privacy budget",
        )?;
        if self.allowed_disclosure_tags.is_empty() {
            return Err("privacy budget requires disclosure tags".to_string());
        }
        if self.used_public_events > self.max_public_events {
            return Err("privacy budget over-spent".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_constraint",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "allowed_disclosure_tags": self.allowed_disclosure_tags,
            "nullifier_domain_root": self.nullifier_domain_root,
            "max_public_events": self.max_public_events,
            "used_public_events": self.used_public_events,
            "remaining_public_events": self.remaining_public_events(),
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "max_bucket_precision_bits": self.max_bucket_precision_bits,
            "selective_disclosure_root": self.selective_disclosure_root,
            "status": self.status.as_str(),
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-PRIVACY-BUDGET-CONSTRAINT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencyReceipt {
    pub receipt_id: String,
    pub market_id: String,
    pub position_id: String,
    pub vault_id: String,
    pub receipt_root: String,
    pub collateral_bucket: String,
    pub debt_bucket: DebtAmountBucket,
    pub health_bucket: CollateralHealthBucket,
    pub oracle_root: String,
    pub rate_epoch_id: String,
    pub pq_attestation_id: String,
    pub status: SolvencyReceiptStatus,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl SolvencyReceipt {
    pub fn new(
        market_id: &str,
        position_id: &str,
        vault_id: &str,
        receipt_payload: &Value,
        collateral_bucket: &str,
        debt_bucket: DebtAmountBucket,
        health_bucket: CollateralHealthBucket,
        oracle_payload: &Value,
        rate_epoch_id: &str,
        pq_attestation_id: &str,
        posted_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("market_id", market_id)?;
        non_empty("position_id", position_id)?;
        non_empty("vault_id", vault_id)?;
        non_empty("collateral_bucket", collateral_bucket)?;
        non_empty("rate_epoch_id", rate_epoch_id)?;
        non_empty("pq_attestation_id", pq_attestation_id)?;
        validate_window(posted_at_height, expires_at_height, "solvency receipt")?;
        let receipt_root =
            debt_engine_payload_root("PCDE-SOLVENCY-RECEIPT-PAYLOAD", receipt_payload);
        let receipt_id = debt_engine_payload_root(
            "PCDE-SOLVENCY-RECEIPT-ID",
            &json!({
                "market_id": market_id,
                "position_id": position_id,
                "vault_id": vault_id,
                "receipt_root": receipt_root,
                "posted_at_height": posted_at_height,
            }),
        );
        Ok(Self {
            receipt_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            vault_id: vault_id.to_string(),
            receipt_root,
            collateral_bucket: collateral_bucket.to_string(),
            debt_bucket,
            health_bucket,
            oracle_root: debt_engine_payload_root("PCDE-SOLVENCY-RECEIPT-ORACLE", oracle_payload),
            rate_epoch_id: rate_epoch_id.to_string(),
            pq_attestation_id: pq_attestation_id.to_string(),
            status: SolvencyReceiptStatus::Posted,
            posted_at_height,
            expires_at_height,
            metadata_root: debt_engine_payload_root("PCDE-SOLVENCY-RECEIPT-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("receipt_id", &self.receipt_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("position_id", &self.position_id)?;
        non_empty("vault_id", &self.vault_id)?;
        non_empty("collateral_bucket", &self.collateral_bucket)?;
        non_empty("rate_epoch_id", &self.rate_epoch_id)?;
        non_empty("pq_attestation_id", &self.pq_attestation_id)?;
        validate_window(
            self.posted_at_height,
            self.expires_at_height,
            "solvency receipt",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solvency_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "vault_id": self.vault_id,
            "receipt_root": self.receipt_root,
            "collateral_bucket": self.collateral_bucket,
            "debt_bucket": self.debt_bucket.as_str(),
            "health_bucket": self.health_bucket.as_str(),
            "oracle_root": self.oracle_root,
            "rate_epoch_id": self.rate_epoch_id,
            "pq_attestation_id": self.pq_attestation_id,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-SOLVENCY-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub subject_root: String,
    pub state_height: u64,
    pub sequence: u64,
    pub disclosure_root: String,
    pub metadata_root: String,
}

impl DeterministicPublicRecord {
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: &str,
        subject_record: &Value,
        state_height: u64,
        sequence: u64,
        disclosure: &Value,
        metadata: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        non_empty("subject_id", subject_id)?;
        let subject_root = debt_engine_record_root("PCDE-PUBLIC-RECORD-SUBJECT", subject_record);
        let disclosure_root = debt_engine_payload_root("PCDE-PUBLIC-RECORD-DISCLOSURE", disclosure);
        let record_id = debt_engine_payload_root(
            "PCDE-PUBLIC-RECORD-ID",
            &json!({
                "record_kind": record_kind.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "state_height": state_height,
                "sequence": sequence,
            }),
        );
        Ok(Self {
            record_id,
            record_kind,
            subject_id: subject_id.to_string(),
            subject_root,
            state_height,
            sequence,
            disclosure_root,
            metadata_root: debt_engine_payload_root("PCDE-PUBLIC-RECORD-METADATA", metadata),
        })
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("record_id", &self.record_id)?;
        non_empty("subject_id", &self.subject_id)?;
        non_empty("subject_root", &self.subject_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deterministic_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "state_height": self.state_height,
            "sequence": self.sequence,
            "disclosure_root": self.disclosure_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        debt_engine_record_root("PCDE-DETERMINISTIC-PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCollateralizedDebtEngineCounters {
    pub market_count: u64,
    pub active_market_count: u64,
    pub collateral_vault_count: u64,
    pub live_collateral_vault_count: u64,
    pub debt_position_count: u64,
    pub live_debt_position_count: u64,
    pub liquidatable_position_count: u64,
    pub encrypted_trigger_count: u64,
    pub live_encrypted_trigger_count: u64,
    pub sealed_keeper_bid_count: u64,
    pub live_sealed_keeper_bid_count: u64,
    pub rate_epoch_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub privacy_budget_count: u64,
    pub spendable_privacy_budget_count: u64,
    pub solvency_receipt_count: u64,
    pub public_record_count: u64,
    pub total_debt_upper_bound_units: u64,
    pub total_collateral_upper_bound_units: u64,
    pub aggregate_fee_budget_units: u64,
    pub aggregate_remaining_fee_budget_units: u64,
    pub minimum_privacy_set_size: u64,
    pub minimum_pq_security_bits: u16,
}

impl PrivateCollateralizedDebtEngineCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_collateralized_debt_engine_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "market_count": self.market_count,
            "active_market_count": self.active_market_count,
            "collateral_vault_count": self.collateral_vault_count,
            "live_collateral_vault_count": self.live_collateral_vault_count,
            "debt_position_count": self.debt_position_count,
            "live_debt_position_count": self.live_debt_position_count,
            "liquidatable_position_count": self.liquidatable_position_count,
            "encrypted_trigger_count": self.encrypted_trigger_count,
            "live_encrypted_trigger_count": self.live_encrypted_trigger_count,
            "sealed_keeper_bid_count": self.sealed_keeper_bid_count,
            "live_sealed_keeper_bid_count": self.live_sealed_keeper_bid_count,
            "rate_epoch_count": self.rate_epoch_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "privacy_budget_count": self.privacy_budget_count,
            "spendable_privacy_budget_count": self.spendable_privacy_budget_count,
            "solvency_receipt_count": self.solvency_receipt_count,
            "public_record_count": self.public_record_count,
            "total_debt_upper_bound_units": self.total_debt_upper_bound_units,
            "total_collateral_upper_bound_units": self.total_collateral_upper_bound_units,
            "aggregate_fee_budget_units": self.aggregate_fee_budget_units,
            "aggregate_remaining_fee_budget_units": self.aggregate_remaining_fee_budget_units,
            "minimum_privacy_set_size": self.minimum_privacy_set_size,
            "minimum_pq_security_bits": self.minimum_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCollateralizedDebtEngineRoots {
    pub config_root: String,
    pub market_root: String,
    pub collateral_vault_root: String,
    pub debt_position_root: String,
    pub encrypted_trigger_root: String,
    pub sealed_keeper_bid_root: String,
    pub rate_epoch_root: String,
    pub low_fee_sponsorship_root: String,
    pub pq_attestation_root: String,
    pub privacy_budget_root: String,
    pub solvency_receipt_root: String,
    pub public_record_root: String,
    pub counters_root: String,
}

impl PrivateCollateralizedDebtEngineRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_collateralized_debt_engine_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "market_root": self.market_root,
            "collateral_vault_root": self.collateral_vault_root,
            "debt_position_root": self.debt_position_root,
            "encrypted_trigger_root": self.encrypted_trigger_root,
            "sealed_keeper_bid_root": self.sealed_keeper_bid_root,
            "rate_epoch_root": self.rate_epoch_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_budget_root": self.privacy_budget_root,
            "solvency_receipt_root": self.solvency_receipt_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_collateralized_debt_engine_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCollateralizedDebtEngineState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateCollateralizedDebtEngineConfig,
    pub markets: BTreeMap<String, DebtEngineMarket>,
    pub collateral_vaults: BTreeMap<String, ConfidentialCollateralVault>,
    pub debt_positions: BTreeMap<String, PrivateStableDebtPosition>,
    pub encrypted_triggers: BTreeMap<String, EncryptedLiquidationTrigger>,
    pub sealed_keeper_bids: BTreeMap<String, SealedKeeperBid>,
    pub rate_epochs: BTreeMap<String, RateEpoch>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub pq_attestations: BTreeMap<String, PqRiskAuthorityAttestation>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetConstraint>,
    pub solvency_receipts: BTreeMap<String, SolvencyReceipt>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl Default for PrivateCollateralizedDebtEngineState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateCollateralizedDebtEngineState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: PrivateCollateralizedDebtEngineConfig::default(),
            markets: BTreeMap::new(),
            collateral_vaults: BTreeMap::new(),
            debt_positions: BTreeMap::new(),
            encrypted_triggers: BTreeMap::new(),
            sealed_keeper_bids: BTreeMap::new(),
            rate_epochs: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            solvency_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: PrivateCollateralizedDebtEngineConfig,
    ) -> PrivateCollateralizedDebtEngineResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> PrivateCollateralizedDebtEngineResult<Self> {
        let mut state = Self::with_config(PrivateCollateralizedDebtEngineConfig::devnet())?;
        state.set_height(PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_HEIGHT)?;

        let market = DebtEngineMarket::new(
            "wXMR private collateralized debt engine devnet",
            &state.config.collateral_asset_id,
            &state.config.stable_asset_id,
            &state.config.reserve_asset_id,
            PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_ORACLE_FEED_ID,
            &state.config.default_low_fee_lane,
            state.config.minimum_collateral_ratio_bps,
            state.config.liquidation_ratio_bps,
            state.config.liquidation_penalty_bps,
            state.config.stability_fee_annual_bps,
            state.config.reserve_factor_bps,
            10_000_000_000_000,
            state.height.saturating_sub(72),
            &json!({
                "mode": "devnet",
                "private_defi": "confidential collateralized stable debt",
                "execution": "root-only public surface"
            }),
        )?;
        let market_id = market.market_id.clone();
        state.insert_market(market)?;

        let rate_epoch = RateEpoch::new(
            &market_id,
            1,
            state.height.saturating_sub(24),
            state
                .height
                .saturating_add(state.config.default_rate_epoch_blocks),
            125,
            state.config.stability_fee_annual_bps,
            state.config.reserve_factor_bps,
            state.config.index_scale.saturating_add(2_500_000),
            "utilization_10_30",
            &json!({
                "feed_id": PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_ORACLE_FEED_ID,
                "price": PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_WXMR_PRICE,
                "sources": ["devnet-median-1", "devnet-median-2", "devnet-median-3"]
            }),
            &json!({"rate_mode": "low-volatility-devnet", "privacy": "aggregate-only"}),
        )?;
        let rate_epoch_id = rate_epoch.epoch_id.clone();
        state.insert_rate_epoch(rate_epoch)?;

        let pq = PqRiskAuthorityAttestation::new(
            &market_id,
            "devnet-private-cdp-risk-committee",
            "market",
            &market_id,
            PqRiskDecision::Approve,
            state.config.min_pq_security_bits,
            &[
                "ml-dsa-risk-member-1".to_string(),
                "ml-dsa-risk-member-2".to_string(),
                "slh-dsa-risk-member-3".to_string(),
            ],
            &json!({
                "caps": "devnet",
                "collateral": state.config.collateral_asset_id,
                "stable": state.config.stable_asset_id,
                "oracle": PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_ORACLE_FEED_ID
            }),
            &json!({
                "threshold": "2-of-3",
                "scheme": state.config.pq_authority_scheme
            }),
            state.height.saturating_sub(12),
            state
                .height
                .saturating_add(state.config.default_attestation_ttl_blocks),
            &json!({"review": "initial launch risk envelope"}),
        )?;
        let pq_attestation_id = pq.attestation_id.clone();
        state.insert_pq_attestation(pq)?;

        let budget = PrivacyBudgetConstraint::new(
            &market_id,
            "devnet-alice-private-cdp",
            &[
                "collateral_bucket".to_string(),
                "debt_bucket".to_string(),
                "health_bucket".to_string(),
                "solvency_receipt".to_string(),
            ],
            12,
            state.config.min_privacy_set_size,
            12,
            &json!({
                "disclosures": "bucket-only",
                "forbidden": ["exact_amount", "raw_oracle_path", "owner_address"]
            }),
            state.height.saturating_sub(18),
            state
                .height
                .saturating_add(state.config.default_privacy_budget_ttl_blocks),
            &json!({"wallet": "alice", "purpose": "private cdp lifecycle"}),
        )?;
        let budget_id = budget.budget_id.clone();
        state.insert_privacy_budget(budget)?;

        let vault = ConfidentialCollateralVault::new(
            &market_id,
            "devnet-alice-private-cdp",
            &state.config.collateral_asset_id,
            "wxmr_100_500",
            250_000_000_000,
            "alice-pcde-collateral-blinding",
            &json!({
                "kem": state.config.trigger_encryption_scheme,
                "ciphertext_root_hint": "alice-wxmr-cdp-collateral"
            }),
            &json!({
                "spend_policy": "pq-session-nullifier",
                "view_policy": "owner+auditor-selective"
            }),
            state.height.saturating_sub(16),
            state.height.saturating_add(21_600),
            &json!({"amount_bucket": "100-500 wxmr", "role": "primary collateral"}),
        )?;
        let vault_id = vault.vault_id.clone();
        state.insert_collateral_vault(vault)?;

        let position = PrivateStableDebtPosition::new(
            &market_id,
            &vault_id,
            "devnet-alice-private-cdp",
            &state.config.stable_asset_id,
            DebtAmountBucket::Small,
            18_000_000,
            CollateralHealthBucket::Healthy,
            &rate_epoch_id,
            &json!({
                "maturity": "rolling",
                "fee_mode": "epoch-indexed",
                "repayment": "private burn proof"
            }),
            &json!({
                "ratio": "above-180pct",
                "range_proof": "bucketed",
                "oracle_root": PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_ORACLE_FEED_ID
            }),
            &budget_id,
            state.config.index_scale,
            state.height.saturating_sub(14),
            state.height.saturating_add(21_600),
            &json!({"borrower": "alice", "debt": "private dusd mint"}),
        )?;
        let position_id = position.position_id.clone();
        state.insert_debt_position(position)?;

        let sponsorship = LowFeeSponsorship::new(
            "devnet-foundation-paymaster",
            &market_id,
            "devnet-alice-private-cdp",
            &state.config.default_low_fee_lane,
            &state.config.stable_asset_id,
            DebtAmountBucket::Small,
            250_000,
            state.config.sponsored_max_fee_units,
            state.config.min_privacy_set_size,
            state.height.saturating_sub(8),
            state
                .height
                .saturating_add(state.config.default_sponsorship_ttl_blocks),
            &json!({"campaign": "private-small-cdp", "fee_policy": "cap-per-op"}),
        )?;
        state.insert_low_fee_sponsorship(sponsorship)?;

        let trigger = EncryptedLiquidationTrigger::new(
            &market_id,
            &position_id,
            &vault_id,
            CollateralHealthBucket::Watch,
            PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_ORACLE_FEED_ID,
            &json!({
                "encrypted_condition": "health-bucket-watch",
                "oracle_price_bucket": "160_170",
                "ciphertext": "devnet-alice-trigger-ciphertext"
            }),
            &json!({"keepers": "devnet-approved-set", "threshold": "1-of-n"}),
            state.height.saturating_sub(4),
            state
                .height
                .saturating_add(state.config.default_trigger_ttl_blocks),
            &json!({"purpose": "encrypted early warning trigger"}),
        )?;
        let trigger_id = trigger.trigger_id.clone();
        state.insert_encrypted_trigger(trigger)?;

        let bid = SealedKeeperBid::new(
            &trigger_id,
            &market_id,
            "devnet-keeper-1",
            &json!({
                "sealed_repay": "stable_10k_25k",
                "sealed_discount": "bps_300_500",
                "route": "private-auction-router"
            }),
            "discount_300_500_bps",
            DebtAmountBucket::Small,
            state.config.sponsored_max_fee_units,
            state.height.saturating_sub(2),
            state
                .height
                .saturating_add(state.config.default_bid_ttl_blocks),
            &json!({"bidder": "keeper-1", "visibility": "sealed"}),
        )?;
        state.insert_sealed_keeper_bid(bid)?;

        let receipt = SolvencyReceipt::new(
            &market_id,
            &position_id,
            &vault_id,
            &json!({
                "solvency": "healthy",
                "collateral_ratio": "bucket-above-200pct",
                "proof": state.config.solvency_receipt_scheme
            }),
            "wxmr_100_500",
            DebtAmountBucket::Small,
            CollateralHealthBucket::Healthy,
            &json!({
                "feed_id": PRIVATE_COLLATERALIZED_DEBT_ENGINE_DEVNET_ORACLE_FEED_ID,
                "price_bucket": "160_170"
            }),
            &rate_epoch_id,
            &pq_attestation_id,
            state.height.saturating_sub(1),
            state
                .height
                .saturating_add(state.config.default_receipt_ttl_blocks),
            &json!({"receipt": "initial-private-solvency"}),
        )?;
        state.insert_solvency_receipt(receipt)?;

        state.refresh_market_roots()?;
        state.insert_public_checkpoint("devnet-private-cdp-checkpoint")?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateCollateralizedDebtEngineResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> PrivateCollateralizedDebtEngineRoots {
        let counters = self.counters();
        PrivateCollateralizedDebtEngineRoots {
            config_root: self.config.root(),
            market_root: debt_engine_collection_root(
                "PCDE-MARKETS",
                &value_records(&self.markets, DebtEngineMarket::public_record),
            ),
            collateral_vault_root: debt_engine_collection_root(
                "PCDE-COLLATERAL-VAULTS",
                &value_records(
                    &self.collateral_vaults,
                    ConfidentialCollateralVault::public_record,
                ),
            ),
            debt_position_root: debt_engine_collection_root(
                "PCDE-DEBT-POSITIONS",
                &value_records(
                    &self.debt_positions,
                    PrivateStableDebtPosition::public_record,
                ),
            ),
            encrypted_trigger_root: debt_engine_collection_root(
                "PCDE-ENCRYPTED-TRIGGERS",
                &value_records(
                    &self.encrypted_triggers,
                    EncryptedLiquidationTrigger::public_record,
                ),
            ),
            sealed_keeper_bid_root: debt_engine_collection_root(
                "PCDE-SEALED-KEEPER-BIDS",
                &value_records(&self.sealed_keeper_bids, SealedKeeperBid::public_record),
            ),
            rate_epoch_root: debt_engine_collection_root(
                "PCDE-RATE-EPOCHS",
                &value_records(&self.rate_epochs, RateEpoch::public_record),
            ),
            low_fee_sponsorship_root: debt_engine_collection_root(
                "PCDE-LOW-FEE-SPONSORSHIPS",
                &value_records(&self.low_fee_sponsorships, LowFeeSponsorship::public_record),
            ),
            pq_attestation_root: debt_engine_collection_root(
                "PCDE-PQ-ATTESTATIONS",
                &value_records(
                    &self.pq_attestations,
                    PqRiskAuthorityAttestation::public_record,
                ),
            ),
            privacy_budget_root: debt_engine_collection_root(
                "PCDE-PRIVACY-BUDGETS",
                &value_records(
                    &self.privacy_budgets,
                    PrivacyBudgetConstraint::public_record,
                ),
            ),
            solvency_receipt_root: debt_engine_collection_root(
                "PCDE-SOLVENCY-RECEIPTS",
                &value_records(&self.solvency_receipts, SolvencyReceipt::public_record),
            ),
            public_record_root: debt_engine_collection_root(
                "PCDE-PUBLIC-RECORDS",
                &value_records(
                    &self.public_records,
                    DeterministicPublicRecord::public_record,
                ),
            ),
            counters_root: debt_engine_record_root("PCDE-COUNTERS", &counters.public_record()),
        }
    }

    pub fn counters(&self) -> PrivateCollateralizedDebtEngineCounters {
        let total_debt_upper_bound_units = self
            .debt_positions
            .values()
            .map(|position| position.debt_upper_bound_units)
            .fold(0_u64, u64::saturating_add);
        let total_collateral_upper_bound_units = self
            .collateral_vaults
            .values()
            .map(|vault| vault.amount_upper_bound_units)
            .fold(0_u64, u64::saturating_add);
        let aggregate_fee_budget_units = self
            .low_fee_sponsorships
            .values()
            .map(|sponsorship| sponsorship.fee_budget_units)
            .fold(0_u64, u64::saturating_add);
        let aggregate_remaining_fee_budget_units = self
            .low_fee_sponsorships
            .values()
            .map(LowFeeSponsorship::remaining_fee_units)
            .fold(0_u64, u64::saturating_add);
        let minimum_privacy_set_size = match self
            .privacy_budgets
            .values()
            .map(|budget| budget.min_anonymity_set_size)
            .min()
        {
            Some(value) => value,
            None => self.config.min_privacy_set_size,
        };
        let minimum_pq_security_bits = match self
            .pq_attestations
            .values()
            .map(|attestation| attestation.security_bits)
            .min()
        {
            Some(value) => value,
            None => self.config.min_pq_security_bits,
        };

        PrivateCollateralizedDebtEngineCounters {
            market_count: self.markets.len() as u64,
            active_market_count: self
                .markets
                .values()
                .filter(|market| market.status.allows_new_debt())
                .count() as u64,
            collateral_vault_count: self.collateral_vaults.len() as u64,
            live_collateral_vault_count: self
                .collateral_vaults
                .values()
                .filter(|vault| vault.status.counts_as_live())
                .count() as u64,
            debt_position_count: self.debt_positions.len() as u64,
            live_debt_position_count: self
                .debt_positions
                .values()
                .filter(|position| position.status.counts_as_debt())
                .count() as u64,
            liquidatable_position_count: self
                .debt_positions
                .values()
                .filter(|position| position.collateral_health_bucket.liquidatable())
                .count() as u64,
            encrypted_trigger_count: self.encrypted_triggers.len() as u64,
            live_encrypted_trigger_count: self
                .encrypted_triggers
                .values()
                .filter(|trigger| trigger.status.live())
                .count() as u64,
            sealed_keeper_bid_count: self.sealed_keeper_bids.len() as u64,
            live_sealed_keeper_bid_count: self
                .sealed_keeper_bids
                .values()
                .filter(|bid| bid.status.live())
                .count() as u64,
            rate_epoch_count: self.rate_epochs.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.can_spend())
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.usable())
                .count() as u64,
            privacy_budget_count: self.privacy_budgets.len() as u64,
            spendable_privacy_budget_count: self
                .privacy_budgets
                .values()
                .filter(|budget| budget.status.spendable())
                .count() as u64,
            solvency_receipt_count: self.solvency_receipts.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_debt_upper_bound_units,
            total_collateral_upper_bound_units,
            aggregate_fee_budget_units,
            aggregate_remaining_fee_budget_units,
            minimum_privacy_set_size,
            minimum_pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_collateralized_debt_engine_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_collateralized_debt_engine_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateCollateralizedDebtEngineResult<()> {
        self.config.validate()?;
        if self.markets.len() > PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_MARKETS {
            return Err("too many markets".to_string());
        }
        if self.collateral_vaults.len() > PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_VAULTS {
            return Err("too many collateral vaults".to_string());
        }
        if self.debt_positions.len() > PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_POSITIONS {
            return Err("too many debt positions".to_string());
        }
        if self.encrypted_triggers.len() > PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_TRIGGERS {
            return Err("too many encrypted triggers".to_string());
        }
        if self.sealed_keeper_bids.len() > PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_BIDS {
            return Err("too many sealed keeper bids".to_string());
        }
        if self.public_records.len() > PRIVATE_COLLATERALIZED_DEBT_ENGINE_MAX_PUBLIC_RECORDS {
            return Err("too many public records".to_string());
        }

        for market in self.markets.values() {
            market.validate()?;
        }
        for vault in self.collateral_vaults.values() {
            vault.validate()?;
            if !self.markets.contains_key(&vault.market_id) {
                return Err(format!(
                    "vault {} references missing market",
                    vault.vault_id
                ));
            }
        }
        for position in self.debt_positions.values() {
            position.validate()?;
            if !self.markets.contains_key(&position.market_id) {
                return Err(format!(
                    "position {} references missing market",
                    position.position_id
                ));
            }
            if !self.collateral_vaults.contains_key(&position.vault_id) {
                return Err(format!(
                    "position {} references missing vault",
                    position.position_id
                ));
            }
            if !self
                .privacy_budgets
                .contains_key(&position.privacy_budget_id)
            {
                return Err(format!(
                    "position {} references missing privacy budget",
                    position.position_id
                ));
            }
        }
        for trigger in self.encrypted_triggers.values() {
            trigger.validate()?;
            if !self.debt_positions.contains_key(&trigger.position_id) {
                return Err(format!(
                    "trigger {} references missing position",
                    trigger.trigger_id
                ));
            }
        }
        for bid in self.sealed_keeper_bids.values() {
            bid.validate()?;
            if !self.encrypted_triggers.contains_key(&bid.trigger_id) {
                return Err(format!("bid {} references missing trigger", bid.bid_id));
            }
        }
        for epoch in self.rate_epochs.values() {
            epoch.validate()?;
            if !self.markets.contains_key(&epoch.market_id) {
                return Err(format!(
                    "epoch {} references missing market",
                    epoch.epoch_id
                ));
            }
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
            if !self.markets.contains_key(&sponsorship.market_id) {
                return Err(format!(
                    "sponsorship {} references missing market",
                    sponsorship.sponsorship_id
                ));
            }
            if sponsorship.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "sponsorship {} below privacy set floor",
                    sponsorship.sponsorship_id
                ));
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
        }
        for budget in self.privacy_budgets.values() {
            budget.validate()?;
            if budget.min_anonymity_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "privacy budget {} below anonymity floor",
                    budget.budget_id
                ));
            }
        }
        for receipt in self.solvency_receipts.values() {
            receipt.validate()?;
            if !self.debt_positions.contains_key(&receipt.position_id) {
                return Err(format!(
                    "receipt {} references missing position",
                    receipt.receipt_id
                ));
            }
            if !self
                .pq_attestations
                .contains_key(&receipt.pq_attestation_id)
            {
                return Err(format!(
                    "receipt {} references missing pq attestation",
                    receipt.receipt_id
                ));
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(())
    }

    pub fn next_nonce(&mut self) -> u64 {
        let nonce = self.nonce;
        self.nonce = self.nonce.saturating_add(1);
        nonce
    }

    pub fn insert_market(
        &mut self,
        market: DebtEngineMarket,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        market.validate()?;
        if self.markets.contains_key(&market.market_id) {
            return Err("market already exists".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::MarketOpened,
            &market.market_id,
            &market.public_record(),
        )?;
        self.markets.insert(market.market_id.clone(), market);
        Ok(())
    }

    pub fn insert_collateral_vault(
        &mut self,
        vault: ConfidentialCollateralVault,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        vault.validate()?;
        if !self.markets.contains_key(&vault.market_id) {
            return Err("collateral vault references unknown market".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::VaultCommitted,
            &vault.vault_id,
            &vault.public_record(),
        )?;
        self.collateral_vaults.insert(vault.vault_id.clone(), vault);
        Ok(())
    }

    pub fn insert_debt_position(
        &mut self,
        position: PrivateStableDebtPosition,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        position.validate()?;
        if !self.markets.contains_key(&position.market_id) {
            return Err("debt position references unknown market".to_string());
        }
        if !self.collateral_vaults.contains_key(&position.vault_id) {
            return Err("debt position references unknown vault".to_string());
        }
        if !self
            .privacy_budgets
            .contains_key(&position.privacy_budget_id)
        {
            return Err("debt position references unknown privacy budget".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::DebtPositionCommitted,
            &position.position_id,
            &position.public_record(),
        )?;
        self.debt_positions
            .insert(position.position_id.clone(), position);
        Ok(())
    }

    pub fn insert_encrypted_trigger(
        &mut self,
        trigger: EncryptedLiquidationTrigger,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        trigger.validate()?;
        if !self.debt_positions.contains_key(&trigger.position_id) {
            return Err("liquidation trigger references unknown position".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::TriggerArmed,
            &trigger.trigger_id,
            &trigger.public_record(),
        )?;
        self.encrypted_triggers
            .insert(trigger.trigger_id.clone(), trigger);
        Ok(())
    }

    pub fn insert_sealed_keeper_bid(
        &mut self,
        bid: SealedKeeperBid,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        bid.validate()?;
        if !self.encrypted_triggers.contains_key(&bid.trigger_id) {
            return Err("keeper bid references unknown trigger".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::KeeperBidSealed,
            &bid.bid_id,
            &bid.public_record(),
        )?;
        self.sealed_keeper_bids.insert(bid.bid_id.clone(), bid);
        Ok(())
    }

    pub fn insert_rate_epoch(
        &mut self,
        rate_epoch: RateEpoch,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        rate_epoch.validate()?;
        if !self.markets.contains_key(&rate_epoch.market_id) {
            return Err("rate epoch references unknown market".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::RateEpochPosted,
            &rate_epoch.epoch_id,
            &rate_epoch.public_record(),
        )?;
        self.rate_epochs
            .insert(rate_epoch.epoch_id.clone(), rate_epoch);
        Ok(())
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeSponsorship,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        sponsorship.validate()?;
        if !self.markets.contains_key(&sponsorship.market_id) {
            return Err("low fee sponsorship references unknown market".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::SponsorshipPosted,
            &sponsorship.sponsorship_id,
            &sponsorship.public_record(),
        )?;
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqRiskAuthorityAttestation,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        attestation.validate()?;
        self.add_subject_record(
            PublicRecordKind::PqAttestationPosted,
            &attestation.attestation_id,
            &attestation.public_record(),
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_privacy_budget(
        &mut self,
        budget: PrivacyBudgetConstraint,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        budget.validate()?;
        if !self.markets.contains_key(&budget.market_id) {
            return Err("privacy budget references unknown market".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::PrivacyBudgetPosted,
            &budget.budget_id,
            &budget.public_record(),
        )?;
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn insert_solvency_receipt(
        &mut self,
        receipt: SolvencyReceipt,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        receipt.validate()?;
        if !self.debt_positions.contains_key(&receipt.position_id) {
            return Err("solvency receipt references unknown position".to_string());
        }
        if !self
            .pq_attestations
            .contains_key(&receipt.pq_attestation_id)
        {
            return Err("solvency receipt references unknown pq attestation".to_string());
        }
        self.add_subject_record(
            PublicRecordKind::SolvencyReceiptPosted,
            &receipt.receipt_id,
            &receipt.public_record(),
        )?;
        self.solvency_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_public_checkpoint(
        &mut self,
        label: &str,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        non_empty("label", label)?;
        let roots = self.roots().public_record();
        self.add_subject_record(
            PublicRecordKind::StateCheckpoint,
            label,
            &json!({
                "label": label,
                "height": self.height,
                "roots": roots,
            }),
        )
    }

    fn add_subject_record(
        &mut self,
        kind: PublicRecordKind,
        subject_id: &str,
        subject_record: &Value,
    ) -> PrivateCollateralizedDebtEngineResult<()> {
        let sequence = self.next_nonce();
        let public_record = DeterministicPublicRecord::new(
            kind,
            subject_id,
            subject_record,
            self.height,
            sequence,
            &json!({
                "public_surface": "deterministic-root-only",
                "privacy": "no plaintext amounts or owners"
            }),
            &json!({"engine": "private_collateralized_debt"}),
        )?;
        self.public_records
            .insert(public_record.record_id.clone(), public_record);
        Ok(())
    }

    fn refresh_market_roots(&mut self) -> PrivateCollateralizedDebtEngineResult<()> {
        let roots = self.roots();
        for market in self.markets.values_mut() {
            market.collateral_commitment_root = roots.collateral_vault_root.clone();
            market.debt_commitment_root = roots.debt_position_root.clone();
            market.trigger_root = roots.encrypted_trigger_root.clone();
            market.keeper_bid_root = roots.sealed_keeper_bid_root.clone();
            market.rate_epoch_root = roots.rate_epoch_root.clone();
            market.pq_authority_root = roots.pq_attestation_root.clone();
            market.privacy_budget_root = roots.privacy_budget_root.clone();
            market.solvency_receipt_root = roots.solvency_receipt_root.clone();
            market.private_debt_upper_bound_units = self
                .debt_positions
                .values()
                .filter(|position| position.market_id == market.market_id)
                .map(|position| position.debt_upper_bound_units)
                .fold(0_u64, u64::saturating_add);
            market.validate()?;
        }
        Ok(())
    }
}

pub fn private_collateralized_debt_engine_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-COLLATERALIZED-DEBT-ENGINE-STATE-ROOT",
        &[
            HashPart::Str(PRIVATE_COLLATERALIZED_DEBT_ENGINE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
