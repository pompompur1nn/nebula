use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type ConfidentialCrossMarginEngineResult<T> = Result<T, String>;

pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION: u32 = 1;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_NAME: &str =
    "nebula-confidential-cross-margin-engine";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_COMMITMENT_SCHEME: &str =
    "shake256-confidential-cross-margin-account-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+xwing-sealed-margin-state-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_RISK_BUCKET_SCHEME: &str =
    "zk-private-risk-bucket-disclosure-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_LIQUIDATION_GUARD_SCHEME: &str =
    "threshold-encrypted-liquidation-guard-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_ORACLE_COMMITMENT_SCHEME: &str =
    "threshold-oracle-commitment-root-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_REBALANCE_SPONSOR_SCHEME: &str =
    "low-fee-private-rebalance-sponsorship-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-policy-root-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_MONERO_ANCHOR_SCHEME: &str =
    "monero-view-key-settlement-anchor-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-cross-margin-public-record-v1";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_HEIGHT: u64 = 224;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_INDEX_SCALE: u64 = 1_000_000_000_000;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_LOW_FEE_LANE: &str =
    "small-private-cross-margin-rebalance";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_STABLE_ASSET_ID: &str = "usdd-devnet";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_INSURANCE_ASSET_ID: &str =
    "cross-margin-insurance-devnet";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_ORACLE_FEED_ID: &str = "feed-wxmr-usdd-devnet";
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_REBALANCE_TTL_BLOCKS: u64 = 24;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_LIQUIDATION_GUARD_TTL_BLOCKS: u64 = 18;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MARGIN_EPOCH_BLOCKS: u64 = 24;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_ACCOUNTS: usize = 262_144;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_RISK_BUCKETS: usize = 1_048_576;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_NETS: usize = 1_048_576;
pub const CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossMarginAccountStatus {
    Pending,
    Active,
    RebalanceOnly,
    MarginCall,
    LiquidationGuarded,
    Frozen,
    Settling,
    Closed,
}

impl CrossMarginAccountStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::RebalanceOnly => "rebalance_only",
            Self::MarginCall => "margin_call",
            Self::LiquidationGuarded => "liquidation_guarded",
            Self::Frozen => "frozen",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Active
                | Self::RebalanceOnly
                | Self::MarginCall
                | Self::LiquidationGuarded
                | Self::Frozen
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossMarginRiskBucketKind {
    NoBorrow,
    SuperCollateralized,
    Healthy,
    Watch,
    Maintenance,
    Liquidatable,
    Insolvent,
}

impl CrossMarginRiskBucketKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoBorrow => "no_borrow",
            Self::SuperCollateralized => "super_collateralized",
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Maintenance => "maintenance",
            Self::Liquidatable => "liquidatable",
            Self::Insolvent => "insolvent",
        }
    }

    pub fn floor_bps(&self) -> u64 {
        match self {
            Self::NoBorrow => u64::MAX,
            Self::SuperCollateralized => 25_000,
            Self::Healthy => 17_500,
            Self::Watch => 14_000,
            Self::Maintenance => 11_500,
            Self::Liquidatable => 8_500,
            Self::Insolvent => 0,
        }
    }

    pub fn can_liquidate(&self) -> bool {
        matches!(self, Self::Liquidatable | Self::Insolvent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginProductKind {
    Perpetual,
    EuropeanOption,
    AmericanOption,
    ConfidentialLending,
    CollateralizedDebt,
    SpotCollateral,
    InsuranceReserve,
}

impl MarginProductKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Perpetual => "perpetual",
            Self::EuropeanOption => "european_option",
            Self::AmericanOption => "american_option",
            Self::ConfidentialLending => "confidential_lending",
            Self::CollateralizedDebt => "collateralized_debt",
            Self::SpotCollateral => "spot_collateral",
            Self::InsuranceReserve => "insurance_reserve",
        }
    }

    pub fn consumes_margin(&self) -> bool {
        !matches!(self, Self::SpotCollateral | Self::InsuranceReserve)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginNetStatus {
    Pending,
    Open,
    Netting,
    Rebalanced,
    Guarded,
    Settled,
    Expired,
}

impl MarginNetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Netting => "netting",
            Self::Rebalanced => "rebalanced",
            Self::Guarded => "guarded",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Open | Self::Netting | Self::Guarded
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationGuardStatus {
    Armed,
    ChallengeOpen,
    Executable,
    Executed,
    Cancelled,
    Expired,
}

impl LiquidationGuardStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::ChallengeOpen => "challenge_open",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Armed | Self::ChallengeOpen | Self::Executable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleCommitmentStatus {
    Pending,
    Active,
    Disputed,
    Superseded,
    Expired,
}

impl OracleCommitmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Disputed => "disputed",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceSponsorshipStatus {
    Active,
    Throttled,
    Exhausted,
    Paused,
    Expired,
}

impl RebalanceSponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Expired => "expired",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationScope {
    AccountOpen,
    MarginNet,
    OraclePost,
    LiquidationGuard,
    RebalanceSponsor,
    MoneroSettlement,
    EmergencyFreeze,
}

impl PqAuthorizationScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountOpen => "account_open",
            Self::MarginNet => "margin_net",
            Self::OraclePost => "oracle_post",
            Self::LiquidationGuard => "liquidation_guard",
            Self::RebalanceSponsor => "rebalance_sponsor",
            Self::MoneroSettlement => "monero_settlement",
            Self::EmergencyFreeze => "emergency_freeze",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroAnchorKind {
    CollateralDeposit,
    SettlementOutput,
    ReserveProof,
    ViewTagWindow,
    ReorgInsurance,
}

impl MoneroAnchorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CollateralDeposit => "collateral_deposit",
            Self::SettlementOutput => "settlement_output",
            Self::ReserveProof => "reserve_proof",
            Self::ViewTagWindow => "view_tag_window",
            Self::ReorgInsurance => "reorg_insurance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    AccountCommitted,
    RiskBucketPosted,
    MarginNetCommitted,
    OracleCommitted,
    LiquidationGuardArmed,
    RebalanceSponsored,
    PqPolicyPosted,
    MoneroAnchorPosted,
    StateCheckpoint,
}

impl PublicRecordKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountCommitted => "account_committed",
            Self::RiskBucketPosted => "risk_bucket_posted",
            Self::MarginNetCommitted => "margin_net_committed",
            Self::OracleCommitted => "oracle_committed",
            Self::LiquidationGuardArmed => "liquidation_guard_armed",
            Self::RebalanceSponsored => "rebalance_sponsored",
            Self::PqPolicyPosted => "pq_policy_posted",
            Self::MoneroAnchorPosted => "monero_anchor_posted",
            Self::StateCheckpoint => "state_checkpoint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialCrossMarginEngineConfig {
    pub protocol_version: u32,
    pub protocol_name: String,
    pub collateral_asset_id: String,
    pub stable_asset_id: String,
    pub insurance_asset_id: String,
    pub default_oracle_feed_id: String,
    pub commitment_scheme: String,
    pub encryption_scheme: String,
    pub risk_bucket_scheme: String,
    pub liquidation_guard_scheme: String,
    pub oracle_commitment_scheme: String,
    pub rebalance_sponsor_scheme: String,
    pub pq_authorization_scheme: String,
    pub monero_anchor_scheme: String,
    pub public_record_scheme: String,
    pub default_low_fee_lane: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub net_credit_haircut_bps: u64,
    pub lending_debt_weight_bps: u64,
    pub option_short_weight_bps: u64,
    pub perp_notional_weight_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub margin_epoch_blocks: u64,
    pub liquidation_guard_ttl_blocks: u64,
    pub rebalance_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub monero_finality_depth: u64,
}

impl ConfidentialCrossMarginEngineConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION,
            protocol_name: CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_NAME.to_string(),
            collateral_asset_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_COLLATERAL_ASSET_ID
                .to_string(),
            stable_asset_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_STABLE_ASSET_ID.to_string(),
            insurance_asset_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_INSURANCE_ASSET_ID
                .to_string(),
            default_oracle_feed_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_ORACLE_FEED_ID
                .to_string(),
            commitment_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_COMMITMENT_SCHEME.to_string(),
            encryption_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_ENCRYPTION_SCHEME.to_string(),
            risk_bucket_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_RISK_BUCKET_SCHEME.to_string(),
            liquidation_guard_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_LIQUIDATION_GUARD_SCHEME
                .to_string(),
            oracle_commitment_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_ORACLE_COMMITMENT_SCHEME
                .to_string(),
            rebalance_sponsor_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_REBALANCE_SPONSOR_SCHEME
                .to_string(),
            pq_authorization_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_PQ_AUTH_SCHEME.to_string(),
            monero_anchor_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_MONERO_ANCHOR_SCHEME.to_string(),
            public_record_scheme: CONFIDENTIAL_CROSS_MARGIN_ENGINE_PUBLIC_RECORD_SCHEME.to_string(),
            default_low_fee_lane: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_LOW_FEE_LANE.to_string(),
            price_scale: CONFIDENTIAL_CROSS_MARGIN_ENGINE_PRICE_SCALE,
            index_scale: CONFIDENTIAL_CROSS_MARGIN_ENGINE_INDEX_SCALE,
            initial_margin_bps: 2_500,
            maintenance_margin_bps: 1_450,
            liquidation_penalty_bps: 650,
            net_credit_haircut_bps: 8_500,
            lending_debt_weight_bps: 11_500,
            option_short_weight_bps: 13_000,
            perp_notional_weight_bps: 10_500,
            max_oracle_staleness_blocks:
                CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            margin_epoch_blocks: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MARGIN_EPOCH_BLOCKS,
            liquidation_guard_ttl_blocks:
                CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_LIQUIDATION_GUARD_TTL_BLOCKS,
            rebalance_ttl_blocks: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_REBALANCE_TTL_BLOCKS,
            min_privacy_set_size: 64,
            min_pq_security_bits: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS,
            monero_finality_depth: 20,
        }
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        validate_positive("protocol_version", self.protocol_version as u64)?;
        non_empty("protocol_name", &self.protocol_name)?;
        non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        non_empty("stable_asset_id", &self.stable_asset_id)?;
        non_empty("insurance_asset_id", &self.insurance_asset_id)?;
        non_empty("default_oracle_feed_id", &self.default_oracle_feed_id)?;
        non_empty("commitment_scheme", &self.commitment_scheme)?;
        non_empty("encryption_scheme", &self.encryption_scheme)?;
        non_empty("risk_bucket_scheme", &self.risk_bucket_scheme)?;
        non_empty("liquidation_guard_scheme", &self.liquidation_guard_scheme)?;
        non_empty("oracle_commitment_scheme", &self.oracle_commitment_scheme)?;
        non_empty("rebalance_sponsor_scheme", &self.rebalance_sponsor_scheme)?;
        non_empty("pq_authorization_scheme", &self.pq_authorization_scheme)?;
        non_empty("monero_anchor_scheme", &self.monero_anchor_scheme)?;
        non_empty("public_record_scheme", &self.public_record_scheme)?;
        non_empty("default_low_fee_lane", &self.default_low_fee_lane)?;
        validate_positive("price_scale", self.price_scale)?;
        validate_positive("index_scale", self.index_scale)?;
        validate_bps("initial_margin_bps", self.initial_margin_bps)?;
        validate_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        validate_bps("liquidation_penalty_bps", self.liquidation_penalty_bps)?;
        validate_bps("net_credit_haircut_bps", self.net_credit_haircut_bps)?;
        validate_bps_floor("lending_debt_weight_bps", self.lending_debt_weight_bps)?;
        validate_bps_floor("option_short_weight_bps", self.option_short_weight_bps)?;
        validate_bps_floor("perp_notional_weight_bps", self.perp_notional_weight_bps)?;
        validate_positive(
            "max_oracle_staleness_blocks",
            self.max_oracle_staleness_blocks,
        )?;
        validate_positive("margin_epoch_blocks", self.margin_epoch_blocks)?;
        validate_positive(
            "liquidation_guard_ttl_blocks",
            self.liquidation_guard_ttl_blocks,
        )?;
        validate_positive("rebalance_ttl_blocks", self.rebalance_ttl_blocks)?;
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        validate_positive("monero_finality_depth", self.monero_finality_depth)?;
        if self.maintenance_margin_bps > self.initial_margin_bps {
            return Err("maintenance margin cannot exceed initial margin".to_string());
        }
        if self.min_pq_security_bits < CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("minimum pq security bits below protocol floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_cross_margin_engine_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "protocol_name": self.protocol_name,
            "collateral_asset_id": self.collateral_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "insurance_asset_id": self.insurance_asset_id,
            "default_oracle_feed_id": self.default_oracle_feed_id,
            "commitment_scheme": self.commitment_scheme,
            "encryption_scheme": self.encryption_scheme,
            "risk_bucket_scheme": self.risk_bucket_scheme,
            "liquidation_guard_scheme": self.liquidation_guard_scheme,
            "oracle_commitment_scheme": self.oracle_commitment_scheme,
            "rebalance_sponsor_scheme": self.rebalance_sponsor_scheme,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "monero_anchor_scheme": self.monero_anchor_scheme,
            "public_record_scheme": self.public_record_scheme,
            "default_low_fee_lane": self.default_low_fee_lane,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "net_credit_haircut_bps": self.net_credit_haircut_bps,
            "lending_debt_weight_bps": self.lending_debt_weight_bps,
            "option_short_weight_bps": self.option_short_weight_bps,
            "perp_notional_weight_bps": self.perp_notional_weight_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "margin_epoch_blocks": self.margin_epoch_blocks,
            "liquidation_guard_ttl_blocks": self.liquidation_guard_ttl_blocks,
            "rebalance_ttl_blocks": self.rebalance_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "monero_finality_depth": self.monero_finality_depth,
        })
    }

    pub fn root(&self) -> String {
        cross_margin_payload_root("CONFIDENTIAL-CROSS-MARGIN-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCollateralAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub collateral_asset_id: String,
    pub stable_asset_id: String,
    pub ciphertext_root: String,
    pub balance_commitment: String,
    pub locked_collateral_commitment: String,
    pub pending_settlement_commitment: String,
    pub nullifier_root: String,
    pub view_policy_root: String,
    pub privacy_budget_id: String,
    pub monero_anchor_id: String,
    pub status: CrossMarginAccountStatus,
    pub opened_at_height: u64,
    pub last_rebalanced_height: u64,
    pub metadata: Value,
}

impl EncryptedCollateralAccount {
    pub fn new(
        account_id: &str,
        owner_label: &str,
        privacy_budget_id: &str,
        monero_anchor_id: &str,
        height: u64,
        status: CrossMarginAccountStatus,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let account = Self {
            account_id: account_id.to_string(),
            owner_commitment: deterministic_id("OWNER-COMMITMENT", &[owner_label, account_id]),
            collateral_asset_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_COLLATERAL_ASSET_ID
                .to_string(),
            stable_asset_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_STABLE_ASSET_ID.to_string(),
            ciphertext_root: deterministic_id("ACCOUNT-CIPHERTEXT", &[account_id, owner_label]),
            balance_commitment: deterministic_id("ACCOUNT-BALANCE", &[account_id]),
            locked_collateral_commitment: deterministic_id("ACCOUNT-LOCKED", &[account_id]),
            pending_settlement_commitment: deterministic_id("ACCOUNT-PENDING", &[account_id]),
            nullifier_root: deterministic_id("ACCOUNT-NULLIFIERS", &[account_id]),
            view_policy_root: deterministic_id("ACCOUNT-VIEW-POLICY", &[account_id]),
            privacy_budget_id: privacy_budget_id.to_string(),
            monero_anchor_id: monero_anchor_id.to_string(),
            status,
            opened_at_height: height,
            last_rebalanced_height: height,
            metadata: json!({
                "devnet_owner_label": owner_label,
                "plaintext": "not published",
            }),
        };
        account.validate()?;
        Ok(account)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("account_id", &self.account_id)?;
        non_empty("owner_commitment", &self.owner_commitment)?;
        non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        non_empty("stable_asset_id", &self.stable_asset_id)?;
        non_empty("ciphertext_root", &self.ciphertext_root)?;
        non_empty("balance_commitment", &self.balance_commitment)?;
        non_empty(
            "locked_collateral_commitment",
            &self.locked_collateral_commitment,
        )?;
        non_empty(
            "pending_settlement_commitment",
            &self.pending_settlement_commitment,
        )?;
        non_empty("nullifier_root", &self.nullifier_root)?;
        non_empty("view_policy_root", &self.view_policy_root)?;
        non_empty("privacy_budget_id", &self.privacy_budget_id)?;
        non_empty("monero_anchor_id", &self.monero_anchor_id)?;
        validate_positive("opened_at_height", self.opened_at_height)?;
        if self.last_rebalanced_height < self.opened_at_height {
            return Err("account rebalance height cannot predate open height".to_string());
        }
        validate_public_payload("account metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_collateral_account",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "ciphertext_root": self.ciphertext_root,
            "balance_commitment": self.balance_commitment,
            "locked_collateral_commitment": self.locked_collateral_commitment,
            "pending_settlement_commitment": self.pending_settlement_commitment,
            "nullifier_root": self.nullifier_root,
            "view_policy_root": self.view_policy_root,
            "privacy_budget_id": self.privacy_budget_id,
            "monero_anchor_id": self.monero_anchor_id,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "last_rebalanced_height": self.last_rebalanced_height,
            "metadata": self.metadata,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRiskBucket {
    pub bucket_id: String,
    pub account_id: String,
    pub bucket_kind: CrossMarginRiskBucketKind,
    pub health_factor_commitment: String,
    pub collateral_value_commitment: String,
    pub debt_value_commitment: String,
    pub margin_requirement_commitment: String,
    pub disclosure_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub min_anonymity_set_size: u64,
}

impl PrivateRiskBucket {
    pub fn new(
        bucket_id: &str,
        account_id: &str,
        bucket_kind: CrossMarginRiskBucketKind,
        starts_at_height: u64,
        ttl_blocks: u64,
        min_anonymity_set_size: u64,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let bucket = Self {
            bucket_id: bucket_id.to_string(),
            account_id: account_id.to_string(),
            bucket_kind,
            health_factor_commitment: deterministic_id("RISK-HEALTH", &[bucket_id, account_id]),
            collateral_value_commitment: deterministic_id("RISK-COLLATERAL", &[bucket_id]),
            debt_value_commitment: deterministic_id("RISK-DEBT", &[bucket_id]),
            margin_requirement_commitment: deterministic_id("RISK-MARGIN", &[bucket_id]),
            disclosure_root: deterministic_id("RISK-DISCLOSURE", &[bucket_id]),
            starts_at_height,
            expires_at_height: starts_at_height.saturating_add(ttl_blocks),
            min_anonymity_set_size,
        };
        bucket.validate()?;
        Ok(bucket)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("bucket_id", &self.bucket_id)?;
        non_empty("account_id", &self.account_id)?;
        non_empty("health_factor_commitment", &self.health_factor_commitment)?;
        non_empty(
            "collateral_value_commitment",
            &self.collateral_value_commitment,
        )?;
        non_empty("debt_value_commitment", &self.debt_value_commitment)?;
        non_empty(
            "margin_requirement_commitment",
            &self.margin_requirement_commitment,
        )?;
        non_empty("disclosure_root", &self.disclosure_root)?;
        validate_window(self.starts_at_height, self.expires_at_height, "risk bucket")?;
        validate_positive("min_anonymity_set_size", self.min_anonymity_set_size)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_risk_bucket",
            "chain_id": CHAIN_ID,
            "bucket_scheme": CONFIDENTIAL_CROSS_MARGIN_ENGINE_RISK_BUCKET_SCHEME,
            "bucket_id": self.bucket_id,
            "account_id": self.account_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "bucket_floor_bps": self.bucket_kind.floor_bps(),
            "can_liquidate": self.bucket_kind.can_liquidate(),
            "health_factor_commitment": self.health_factor_commitment,
            "collateral_value_commitment": self.collateral_value_commitment,
            "debt_value_commitment": self.debt_value_commitment,
            "margin_requirement_commitment": self.margin_requirement_commitment,
            "disclosure_root": self.disclosure_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "min_anonymity_set_size": self.min_anonymity_set_size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductMarginNet {
    pub net_id: String,
    pub account_id: String,
    pub product_kind: MarginProductKind,
    pub market_id: String,
    pub position_commitment_root: String,
    pub gross_notional_commitment: String,
    pub net_exposure_commitment: String,
    pub margin_debit_commitment: String,
    pub margin_credit_commitment: String,
    pub funding_or_interest_commitment: String,
    pub risk_weight_bps: u64,
    pub status: MarginNetStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ProductMarginNet {
    pub fn new(
        net_id: &str,
        account_id: &str,
        product_kind: MarginProductKind,
        market_id: &str,
        risk_weight_bps: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let net = Self {
            net_id: net_id.to_string(),
            account_id: account_id.to_string(),
            product_kind,
            market_id: market_id.to_string(),
            position_commitment_root: deterministic_id("NET-POSITIONS", &[net_id, market_id]),
            gross_notional_commitment: deterministic_id("NET-GROSS", &[net_id]),
            net_exposure_commitment: deterministic_id("NET-EXPOSURE", &[net_id]),
            margin_debit_commitment: deterministic_id("NET-DEBIT", &[net_id]),
            margin_credit_commitment: deterministic_id("NET-CREDIT", &[net_id]),
            funding_or_interest_commitment: deterministic_id("NET-FUNDING-INTEREST", &[net_id]),
            risk_weight_bps,
            status: MarginNetStatus::Open,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
        };
        net.validate()?;
        Ok(net)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("net_id", &self.net_id)?;
        non_empty("account_id", &self.account_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("position_commitment_root", &self.position_commitment_root)?;
        non_empty("gross_notional_commitment", &self.gross_notional_commitment)?;
        non_empty("net_exposure_commitment", &self.net_exposure_commitment)?;
        non_empty("margin_debit_commitment", &self.margin_debit_commitment)?;
        non_empty("margin_credit_commitment", &self.margin_credit_commitment)?;
        non_empty(
            "funding_or_interest_commitment",
            &self.funding_or_interest_commitment,
        )?;
        validate_bps_floor("risk_weight_bps", self.risk_weight_bps)?;
        validate_window(self.opened_at_height, self.expires_at_height, "margin net")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "product_margin_net",
            "chain_id": CHAIN_ID,
            "net_id": self.net_id,
            "account_id": self.account_id,
            "product_kind": self.product_kind.as_str(),
            "consumes_margin": self.product_kind.consumes_margin(),
            "market_id": self.market_id,
            "position_commitment_root": self.position_commitment_root,
            "gross_notional_commitment": self.gross_notional_commitment,
            "net_exposure_commitment": self.net_exposure_commitment,
            "margin_debit_commitment": self.margin_debit_commitment,
            "margin_credit_commitment": self.margin_credit_commitment,
            "funding_or_interest_commitment": self.funding_or_interest_commitment,
            "risk_weight_bps": self.risk_weight_bps,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationGuard {
    pub guard_id: String,
    pub account_id: String,
    pub risk_bucket_id: String,
    pub keeper_commitment: String,
    pub trigger_ciphertext_root: String,
    pub partial_liquidation_plan_root: String,
    pub challenge_bond_commitment: String,
    pub oracle_commitment_id: String,
    pub status: LiquidationGuardStatus,
    pub armed_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidationGuard {
    pub fn new(
        guard_id: &str,
        account_id: &str,
        risk_bucket_id: &str,
        oracle_commitment_id: &str,
        armed_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let guard = Self {
            guard_id: guard_id.to_string(),
            account_id: account_id.to_string(),
            risk_bucket_id: risk_bucket_id.to_string(),
            keeper_commitment: deterministic_id("KEEPER-COMMITMENT", &[guard_id]),
            trigger_ciphertext_root: deterministic_id("GUARD-TRIGGER", &[guard_id]),
            partial_liquidation_plan_root: deterministic_id("GUARD-PLAN", &[guard_id]),
            challenge_bond_commitment: deterministic_id("GUARD-BOND", &[guard_id]),
            oracle_commitment_id: oracle_commitment_id.to_string(),
            status: LiquidationGuardStatus::Armed,
            armed_at_height,
            executable_at_height: armed_at_height.saturating_add(6),
            expires_at_height: armed_at_height.saturating_add(ttl_blocks),
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("guard_id", &self.guard_id)?;
        non_empty("account_id", &self.account_id)?;
        non_empty("risk_bucket_id", &self.risk_bucket_id)?;
        non_empty("keeper_commitment", &self.keeper_commitment)?;
        non_empty("trigger_ciphertext_root", &self.trigger_ciphertext_root)?;
        non_empty(
            "partial_liquidation_plan_root",
            &self.partial_liquidation_plan_root,
        )?;
        non_empty("challenge_bond_commitment", &self.challenge_bond_commitment)?;
        non_empty("oracle_commitment_id", &self.oracle_commitment_id)?;
        validate_window(
            self.armed_at_height,
            self.expires_at_height,
            "liquidation guard",
        )?;
        if self.executable_at_height < self.armed_at_height {
            return Err("liquidation guard executable height predates armed height".to_string());
        }
        if self.executable_at_height > self.expires_at_height {
            return Err("liquidation guard executable height exceeds expiry".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_guard",
            "chain_id": CHAIN_ID,
            "guard_scheme": CONFIDENTIAL_CROSS_MARGIN_ENGINE_LIQUIDATION_GUARD_SCHEME,
            "guard_id": self.guard_id,
            "account_id": self.account_id,
            "risk_bucket_id": self.risk_bucket_id,
            "keeper_commitment": self.keeper_commitment,
            "trigger_ciphertext_root": self.trigger_ciphertext_root,
            "partial_liquidation_plan_root": self.partial_liquidation_plan_root,
            "challenge_bond_commitment": self.challenge_bond_commitment,
            "oracle_commitment_id": self.oracle_commitment_id,
            "status": self.status.as_str(),
            "active": self.status.active(),
            "armed_at_height": self.armed_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCommitment {
    pub oracle_commitment_id: String,
    pub feed_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub price_commitment: String,
    pub confidence_commitment: String,
    pub mark_vector_root: String,
    pub committee_attestation_root: String,
    pub status: OracleCommitmentStatus,
    pub posted_at_height: u64,
    pub valid_until_height: u64,
}

impl OracleCommitment {
    pub fn devnet(
        oracle_commitment_id: &str,
        posted_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let oracle = Self {
            oracle_commitment_id: oracle_commitment_id.to_string(),
            feed_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_ORACLE_FEED_ID.to_string(),
            base_asset_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_COLLATERAL_ASSET_ID.to_string(),
            quote_asset_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_STABLE_ASSET_ID.to_string(),
            price_commitment: deterministic_id("ORACLE-PRICE", &[oracle_commitment_id]),
            confidence_commitment: deterministic_id("ORACLE-CONFIDENCE", &[oracle_commitment_id]),
            mark_vector_root: deterministic_id("ORACLE-MARK-VECTOR", &[oracle_commitment_id]),
            committee_attestation_root: deterministic_id(
                "ORACLE-COMMITTEE",
                &[oracle_commitment_id],
            ),
            status: OracleCommitmentStatus::Active,
            posted_at_height,
            valid_until_height: posted_at_height.saturating_add(ttl_blocks),
        };
        oracle.validate()?;
        Ok(oracle)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("oracle_commitment_id", &self.oracle_commitment_id)?;
        non_empty("feed_id", &self.feed_id)?;
        non_empty("base_asset_id", &self.base_asset_id)?;
        non_empty("quote_asset_id", &self.quote_asset_id)?;
        non_empty("price_commitment", &self.price_commitment)?;
        non_empty("confidence_commitment", &self.confidence_commitment)?;
        non_empty("mark_vector_root", &self.mark_vector_root)?;
        non_empty(
            "committee_attestation_root",
            &self.committee_attestation_root,
        )?;
        validate_window(
            self.posted_at_height,
            self.valid_until_height,
            "oracle commitment",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_commitment",
            "chain_id": CHAIN_ID,
            "oracle_scheme": CONFIDENTIAL_CROSS_MARGIN_ENGINE_ORACLE_COMMITMENT_SCHEME,
            "oracle_commitment_id": self.oracle_commitment_id,
            "feed_id": self.feed_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "price_commitment": self.price_commitment,
            "confidence_commitment": self.confidence_commitment,
            "mark_vector_root": self.mark_vector_root,
            "committee_attestation_root": self.committee_attestation_root,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebalanceSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub account_class_root: String,
    pub max_fee_units: u64,
    pub remaining_budget_units: u64,
    pub min_notional_units: u64,
    pub max_notional_units: u64,
    pub min_privacy_set_size: u64,
    pub status: RebalanceSponsorshipStatus,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
}

impl RebalanceSponsorship {
    pub fn devnet(
        sponsorship_id: &str,
        starts_at_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let sponsorship = Self {
            sponsorship_id: sponsorship_id.to_string(),
            sponsor_commitment: deterministic_id("REBALANCE-SPONSOR", &[sponsorship_id]),
            lane_id: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_LOW_FEE_LANE.to_string(),
            account_class_root: deterministic_id("REBALANCE-ACCOUNT-CLASS", &[sponsorship_id]),
            max_fee_units: 4_500,
            remaining_budget_units: 12_500_000,
            min_notional_units: 1_000_000,
            max_notional_units: 75_000_000_000,
            min_privacy_set_size: 64,
            status: RebalanceSponsorshipStatus::Active,
            starts_at_height,
            expires_at_height: starts_at_height.saturating_add(ttl_blocks),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("sponsorship_id", &self.sponsorship_id)?;
        non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        non_empty("lane_id", &self.lane_id)?;
        non_empty("account_class_root", &self.account_class_root)?;
        validate_positive("max_fee_units", self.max_fee_units)?;
        validate_positive("min_notional_units", self.min_notional_units)?;
        validate_positive("max_notional_units", self.max_notional_units)?;
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        validate_window(
            self.starts_at_height,
            self.expires_at_height,
            "rebalance sponsorship",
        )?;
        if self.min_notional_units > self.max_notional_units {
            return Err("rebalance sponsorship min notional exceeds max notional".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rebalance_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsor_scheme": CONFIDENTIAL_CROSS_MARGIN_ENGINE_REBALANCE_SPONSOR_SCHEME,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "account_class_root": self.account_class_root,
            "max_fee_units": self.max_fee_units,
            "remaining_budget_units": self.remaining_budget_units,
            "min_notional_units": self.min_notional_units,
            "max_notional_units": self.max_notional_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "status": self.status.as_str(),
            "usable": self.status.usable(),
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorizationPolicy {
    pub policy_id: String,
    pub subject_id: String,
    pub scope: PqAuthorizationScope,
    pub ml_dsa_public_key_commitment: String,
    pub slh_dsa_public_key_commitment: String,
    pub aggregate_authority_root: String,
    pub revocation_root: String,
    pub threshold: u16,
    pub committee_size: u16,
    pub pq_security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl PqAuthorizationPolicy {
    pub fn new(
        policy_id: &str,
        subject_id: &str,
        scope: PqAuthorizationScope,
        valid_from_height: u64,
        ttl_blocks: u64,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let policy = Self {
            policy_id: policy_id.to_string(),
            subject_id: subject_id.to_string(),
            scope,
            ml_dsa_public_key_commitment: deterministic_id("PQ-ML-DSA", &[policy_id]),
            slh_dsa_public_key_commitment: deterministic_id("PQ-SLH-DSA", &[policy_id]),
            aggregate_authority_root: deterministic_id("PQ-AUTHORITY", &[policy_id]),
            revocation_root: deterministic_id("PQ-REVOCATION", &[policy_id]),
            threshold: 4,
            committee_size: 7,
            pq_security_bits: CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_from_height,
            valid_until_height: valid_from_height.saturating_add(ttl_blocks),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("policy_id", &self.policy_id)?;
        non_empty("subject_id", &self.subject_id)?;
        non_empty(
            "ml_dsa_public_key_commitment",
            &self.ml_dsa_public_key_commitment,
        )?;
        non_empty(
            "slh_dsa_public_key_commitment",
            &self.slh_dsa_public_key_commitment,
        )?;
        non_empty("aggregate_authority_root", &self.aggregate_authority_root)?;
        non_empty("revocation_root", &self.revocation_root)?;
        if self.threshold == 0 || self.committee_size == 0 {
            return Err(
                "pq authorization threshold and committee size must be positive".to_string(),
            );
        }
        if self.threshold > self.committee_size {
            return Err("pq authorization threshold exceeds committee size".to_string());
        }
        if self.pq_security_bits < CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq authorization below protocol security floor".to_string());
        }
        validate_window(
            self.valid_from_height,
            self.valid_until_height,
            "pq authorization policy",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_authorization_policy",
            "chain_id": CHAIN_ID,
            "pq_authorization_scheme": CONFIDENTIAL_CROSS_MARGIN_ENGINE_PQ_AUTH_SCHEME,
            "policy_id": self.policy_id,
            "subject_id": self.subject_id,
            "scope": self.scope.as_str(),
            "ml_dsa_public_key_commitment": self.ml_dsa_public_key_commitment,
            "slh_dsa_public_key_commitment": self.slh_dsa_public_key_commitment,
            "aggregate_authority_root": self.aggregate_authority_root,
            "revocation_root": self.revocation_root,
            "threshold": self.threshold,
            "committee_size": self.committee_size,
            "pq_security_bits": self.pq_security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroSettlementAnchor {
    pub anchor_id: String,
    pub account_id: String,
    pub anchor_kind: MoneroAnchorKind,
    pub txid_commitment: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub view_tag_root: String,
    pub reserve_proof_root: String,
    pub monero_height: u64,
    pub finalized_at_l2_height: u64,
    pub finality_depth: u64,
}

impl MoneroSettlementAnchor {
    pub fn new(
        anchor_id: &str,
        account_id: &str,
        anchor_kind: MoneroAnchorKind,
        monero_height: u64,
        finalized_at_l2_height: u64,
        finality_depth: u64,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let anchor = Self {
            anchor_id: anchor_id.to_string(),
            account_id: account_id.to_string(),
            anchor_kind,
            txid_commitment: deterministic_id("MONERO-TXID", &[anchor_id]),
            output_commitment_root: deterministic_id("MONERO-OUTPUTS", &[anchor_id]),
            key_image_root: deterministic_id("MONERO-KEY-IMAGES", &[anchor_id]),
            view_tag_root: deterministic_id("MONERO-VIEW-TAGS", &[anchor_id]),
            reserve_proof_root: deterministic_id("MONERO-RESERVE", &[anchor_id]),
            monero_height,
            finalized_at_l2_height,
            finality_depth,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("anchor_id", &self.anchor_id)?;
        non_empty("account_id", &self.account_id)?;
        non_empty("txid_commitment", &self.txid_commitment)?;
        non_empty("output_commitment_root", &self.output_commitment_root)?;
        non_empty("key_image_root", &self.key_image_root)?;
        non_empty("view_tag_root", &self.view_tag_root)?;
        non_empty("reserve_proof_root", &self.reserve_proof_root)?;
        validate_positive("monero_height", self.monero_height)?;
        validate_positive("finalized_at_l2_height", self.finalized_at_l2_height)?;
        validate_positive("finality_depth", self.finality_depth)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_settlement_anchor",
            "chain_id": CHAIN_ID,
            "anchor_scheme": CONFIDENTIAL_CROSS_MARGIN_ENGINE_MONERO_ANCHOR_SCHEME,
            "anchor_id": self.anchor_id,
            "account_id": self.account_id,
            "anchor_kind": self.anchor_kind.as_str(),
            "txid_commitment": self.txid_commitment,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "view_tag_root": self.view_tag_root,
            "reserve_proof_root": self.reserve_proof_root,
            "monero_height": self.monero_height,
            "finalized_at_l2_height": self.finalized_at_l2_height,
            "finality_depth": self.finality_depth,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossMarginPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
    pub metadata: Value,
}

impl CrossMarginPublicRecord {
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: &str,
        subject_record: &Value,
        emitted_at_height: u64,
        sequence: u64,
        metadata: &Value,
    ) -> ConfidentialCrossMarginEngineResult<Self> {
        let payload_root =
            cross_margin_payload_root("CONFIDENTIAL-CROSS-MARGIN-PUBLIC-PAYLOAD", subject_record);
        let record_id = cross_margin_public_record_id(
            record_kind.as_str(),
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            record_kind,
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
            metadata: metadata.clone(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("record_id", &self.record_id)?;
        non_empty("subject_id", &self.subject_id)?;
        non_empty("payload_root", &self.payload_root)?;
        validate_positive("emitted_at_height", self.emitted_at_height)?;
        validate_public_payload("public record metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_margin_public_record",
            "chain_id": CHAIN_ID,
            "public_record_scheme": CONFIDENTIAL_CROSS_MARGIN_ENGINE_PUBLIC_RECORD_SCHEME,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
            "metadata": self.metadata,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialCrossMarginEngineRoots {
    pub config_root: String,
    pub account_root: String,
    pub risk_bucket_root: String,
    pub margin_net_root: String,
    pub liquidation_guard_root: String,
    pub oracle_commitment_root: String,
    pub rebalance_sponsorship_root: String,
    pub pq_authorization_policy_root: String,
    pub monero_anchor_root: String,
    pub public_record_root: String,
    pub counters_root: String,
}

impl ConfidentialCrossMarginEngineRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_cross_margin_engine_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "account_root": self.account_root,
            "risk_bucket_root": self.risk_bucket_root,
            "margin_net_root": self.margin_net_root,
            "liquidation_guard_root": self.liquidation_guard_root,
            "oracle_commitment_root": self.oracle_commitment_root,
            "rebalance_sponsorship_root": self.rebalance_sponsorship_root,
            "pq_authorization_policy_root": self.pq_authorization_policy_root,
            "monero_anchor_root": self.monero_anchor_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        cross_margin_payload_root("CONFIDENTIAL-CROSS-MARGIN-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialCrossMarginEngineCounters {
    pub account_count: u64,
    pub open_account_count: u64,
    pub risk_bucket_count: u64,
    pub liquidatable_bucket_count: u64,
    pub margin_net_count: u64,
    pub live_margin_net_count: u64,
    pub liquidation_guard_count: u64,
    pub active_liquidation_guard_count: u64,
    pub oracle_commitment_count: u64,
    pub active_oracle_commitment_count: u64,
    pub rebalance_sponsorship_count: u64,
    pub active_rebalance_sponsorship_count: u64,
    pub pq_authorization_policy_count: u64,
    pub monero_anchor_count: u64,
    pub public_record_count: u64,
    pub total_rebalance_budget_units: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
}

impl ConfidentialCrossMarginEngineCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_cross_margin_engine_counters",
            "chain_id": CHAIN_ID,
            "account_count": self.account_count,
            "open_account_count": self.open_account_count,
            "risk_bucket_count": self.risk_bucket_count,
            "liquidatable_bucket_count": self.liquidatable_bucket_count,
            "margin_net_count": self.margin_net_count,
            "live_margin_net_count": self.live_margin_net_count,
            "liquidation_guard_count": self.liquidation_guard_count,
            "active_liquidation_guard_count": self.active_liquidation_guard_count,
            "oracle_commitment_count": self.oracle_commitment_count,
            "active_oracle_commitment_count": self.active_oracle_commitment_count,
            "rebalance_sponsorship_count": self.rebalance_sponsorship_count,
            "active_rebalance_sponsorship_count": self.active_rebalance_sponsorship_count,
            "pq_authorization_policy_count": self.pq_authorization_policy_count,
            "monero_anchor_count": self.monero_anchor_count,
            "public_record_count": self.public_record_count,
            "total_rebalance_budget_units": self.total_rebalance_budget_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn root(&self) -> String {
        cross_margin_payload_root("CONFIDENTIAL-CROSS-MARGIN-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialCrossMarginEngineState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialCrossMarginEngineConfig,
    pub accounts: BTreeMap<String, EncryptedCollateralAccount>,
    pub risk_buckets: BTreeMap<String, PrivateRiskBucket>,
    pub margin_nets: BTreeMap<String, ProductMarginNet>,
    pub liquidation_guards: BTreeMap<String, LiquidationGuard>,
    pub oracle_commitments: BTreeMap<String, OracleCommitment>,
    pub rebalance_sponsorships: BTreeMap<String, RebalanceSponsorship>,
    pub pq_authorization_policies: BTreeMap<String, PqAuthorizationPolicy>,
    pub monero_anchors: BTreeMap<String, MoneroSettlementAnchor>,
    pub public_records: BTreeMap<String, CrossMarginPublicRecord>,
}

impl ConfidentialCrossMarginEngineState {
    pub fn devnet() -> ConfidentialCrossMarginEngineResult<Self> {
        let height = CONFIDENTIAL_CROSS_MARGIN_ENGINE_DEVNET_HEIGHT;
        let config = ConfidentialCrossMarginEngineConfig::devnet();
        let mut state = Self {
            height,
            nonce: 0,
            config,
            accounts: BTreeMap::new(),
            risk_buckets: BTreeMap::new(),
            margin_nets: BTreeMap::new(),
            liquidation_guards: BTreeMap::new(),
            oracle_commitments: BTreeMap::new(),
            rebalance_sponsorships: BTreeMap::new(),
            pq_authorization_policies: BTreeMap::new(),
            monero_anchors: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };

        let monero_anchor_a = MoneroSettlementAnchor::new(
            "xmargin-monero-anchor-alice-001",
            "xmargin-account-alice-001",
            MoneroAnchorKind::CollateralDeposit,
            3_200_144,
            height.saturating_sub(8),
            state.config.monero_finality_depth,
        )?;
        let monero_anchor_b = MoneroSettlementAnchor::new(
            "xmargin-monero-anchor-bob-001",
            "xmargin-account-bob-001",
            MoneroAnchorKind::SettlementOutput,
            3_200_152,
            height.saturating_sub(4),
            state.config.monero_finality_depth,
        )?;
        let monero_anchor_c = MoneroSettlementAnchor::new(
            "xmargin-monero-anchor-reserve-001",
            "xmargin-account-reserve-001",
            MoneroAnchorKind::ReserveProof,
            3_200_160,
            height.saturating_sub(2),
            state.config.monero_finality_depth,
        )?;
        state.insert_monero_anchor(monero_anchor_a)?;
        state.insert_monero_anchor(monero_anchor_b)?;
        state.insert_monero_anchor(monero_anchor_c)?;

        let alice = EncryptedCollateralAccount::new(
            "xmargin-account-alice-001",
            "alice-market-maker",
            "privacy-budget-devnet-major",
            "xmargin-monero-anchor-alice-001",
            height.saturating_sub(96),
            CrossMarginAccountStatus::Active,
        )?;
        let bob = EncryptedCollateralAccount::new(
            "xmargin-account-bob-001",
            "bob-basis-trader",
            "privacy-budget-devnet-major",
            "xmargin-monero-anchor-bob-001",
            height.saturating_sub(72),
            CrossMarginAccountStatus::MarginCall,
        )?;
        let reserve = EncryptedCollateralAccount::new(
            "xmargin-account-reserve-001",
            "insurance-reserve",
            "privacy-budget-devnet-reserve",
            "xmargin-monero-anchor-reserve-001",
            height.saturating_sub(120),
            CrossMarginAccountStatus::RebalanceOnly,
        )?;
        state.insert_account(alice)?;
        state.insert_account(bob)?;
        state.insert_account(reserve)?;

        let oracle = OracleCommitment::devnet(
            "xmargin-oracle-wxmr-usdd-001",
            height.saturating_sub(3),
            state.config.max_oracle_staleness_blocks,
        )?;
        state.insert_oracle_commitment(oracle)?;

        state.insert_risk_bucket(PrivateRiskBucket::new(
            "xmargin-risk-alice-001",
            "xmargin-account-alice-001",
            CrossMarginRiskBucketKind::Healthy,
            height.saturating_sub(2),
            state.config.margin_epoch_blocks,
            state.config.min_privacy_set_size,
        )?)?;
        state.insert_risk_bucket(PrivateRiskBucket::new(
            "xmargin-risk-bob-001",
            "xmargin-account-bob-001",
            CrossMarginRiskBucketKind::Liquidatable,
            height.saturating_sub(2),
            state.config.margin_epoch_blocks,
            state.config.min_privacy_set_size,
        )?)?;
        state.insert_risk_bucket(PrivateRiskBucket::new(
            "xmargin-risk-reserve-001",
            "xmargin-account-reserve-001",
            CrossMarginRiskBucketKind::NoBorrow,
            height.saturating_sub(2),
            state.config.margin_epoch_blocks,
            state.config.min_privacy_set_size,
        )?)?;

        state.insert_margin_net(ProductMarginNet::new(
            "xmargin-net-alice-perps-001",
            "xmargin-account-alice-001",
            MarginProductKind::Perpetual,
            "confidential-perps-wxmr-usdd",
            state.config.perp_notional_weight_bps,
            height.saturating_sub(48),
            7_200,
        )?)?;
        state.insert_margin_net(ProductMarginNet::new(
            "xmargin-net-alice-options-001",
            "xmargin-account-alice-001",
            MarginProductKind::EuropeanOption,
            "confidential-options-wxmr-weekly",
            state.config.option_short_weight_bps,
            height.saturating_sub(36),
            2_016,
        )?)?;
        state.insert_margin_net(ProductMarginNet::new(
            "xmargin-net-bob-lending-001",
            "xmargin-account-bob-001",
            MarginProductKind::ConfidentialLending,
            "confidential-lending-wxmr-usdd",
            state.config.lending_debt_weight_bps,
            height.saturating_sub(40),
            21_600,
        )?)?;
        state.insert_margin_net(ProductMarginNet::new(
            "xmargin-net-bob-perps-001",
            "xmargin-account-bob-001",
            MarginProductKind::Perpetual,
            "confidential-perps-wxmr-usdd",
            state.config.perp_notional_weight_bps,
            height.saturating_sub(30),
            7_200,
        )?)?;
        state.insert_margin_net(ProductMarginNet::new(
            "xmargin-net-reserve-spot-001",
            "xmargin-account-reserve-001",
            MarginProductKind::InsuranceReserve,
            "cross-margin-insurance-reserve",
            CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_BPS,
            height.saturating_sub(90),
            43_200,
        )?)?;

        state.insert_liquidation_guard(LiquidationGuard::new(
            "xmargin-guard-bob-001",
            "xmargin-account-bob-001",
            "xmargin-risk-bob-001",
            "xmargin-oracle-wxmr-usdd-001",
            height.saturating_sub(1),
            state.config.liquidation_guard_ttl_blocks,
        )?)?;

        state.insert_rebalance_sponsorship(RebalanceSponsorship::devnet(
            "xmargin-rebalance-sponsor-001",
            height.saturating_sub(16),
            state.config.rebalance_ttl_blocks,
        )?)?;

        state.insert_pq_authorization_policy(PqAuthorizationPolicy::new(
            "xmargin-pq-policy-alice-001",
            "xmargin-account-alice-001",
            PqAuthorizationScope::MarginNet,
            height.saturating_sub(100),
            21_600,
        )?)?;
        state.insert_pq_authorization_policy(PqAuthorizationPolicy::new(
            "xmargin-pq-policy-bob-liquidation-001",
            "xmargin-guard-bob-001",
            PqAuthorizationScope::LiquidationGuard,
            height.saturating_sub(12),
            240,
        )?)?;
        state.insert_pq_authorization_policy(PqAuthorizationPolicy::new(
            "xmargin-pq-policy-monero-settlement-001",
            "xmargin-monero-anchor-bob-001",
            PqAuthorizationScope::MoneroSettlement,
            height.saturating_sub(24),
            1_440,
        )?)?;
        state.insert_public_checkpoint("devnet-cross-margin-checkpoint")?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ConfidentialCrossMarginEngineResult<()> {
        validate_positive("height", height)?;
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.nonce = self.nonce.saturating_add(1);
        Ok(())
    }

    pub fn roots(&self) -> ConfidentialCrossMarginEngineRoots {
        let account_records = values_public_records(&self.accounts);
        let risk_bucket_records = values_public_records(&self.risk_buckets);
        let margin_net_records = values_public_records(&self.margin_nets);
        let liquidation_guard_records = values_public_records(&self.liquidation_guards);
        let oracle_records = values_public_records(&self.oracle_commitments);
        let sponsorship_records = values_public_records(&self.rebalance_sponsorships);
        let pq_policy_records = values_public_records(&self.pq_authorization_policies);
        let monero_anchor_records = values_public_records(&self.monero_anchors);
        let public_records = values_public_records(&self.public_records);
        let counters = self.counters();

        ConfidentialCrossMarginEngineRoots {
            config_root: self.config.root(),
            account_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-ACCOUNTS",
                &account_records,
            ),
            risk_bucket_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-RISK-BUCKETS",
                &risk_bucket_records,
            ),
            margin_net_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-MARGIN-NETS",
                &margin_net_records,
            ),
            liquidation_guard_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-LIQUIDATION-GUARDS",
                &liquidation_guard_records,
            ),
            oracle_commitment_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-ORACLES",
                &oracle_records,
            ),
            rebalance_sponsorship_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-REBALANCE-SPONSORSHIPS",
                &sponsorship_records,
            ),
            pq_authorization_policy_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-PQ-POLICIES",
                &pq_policy_records,
            ),
            monero_anchor_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-MONERO-ANCHORS",
                &monero_anchor_records,
            ),
            public_record_root: cross_margin_collection_root(
                "CONFIDENTIAL-CROSS-MARGIN-PUBLIC-RECORDS",
                &public_records,
            ),
            counters_root: counters.root(),
        }
    }

    pub fn counters(&self) -> ConfidentialCrossMarginEngineCounters {
        ConfidentialCrossMarginEngineCounters {
            account_count: self.accounts.len() as u64,
            open_account_count: self
                .accounts
                .values()
                .filter(|account| account.status.is_open())
                .count() as u64,
            risk_bucket_count: self.risk_buckets.len() as u64,
            liquidatable_bucket_count: self
                .risk_buckets
                .values()
                .filter(|bucket| bucket.bucket_kind.can_liquidate())
                .count() as u64,
            margin_net_count: self.margin_nets.len() as u64,
            live_margin_net_count: self
                .margin_nets
                .values()
                .filter(|net| net.status.is_live())
                .count() as u64,
            liquidation_guard_count: self.liquidation_guards.len() as u64,
            active_liquidation_guard_count: self
                .liquidation_guards
                .values()
                .filter(|guard| guard.status.active())
                .count() as u64,
            oracle_commitment_count: self.oracle_commitments.len() as u64,
            active_oracle_commitment_count: self
                .oracle_commitments
                .values()
                .filter(|oracle| oracle.status == OracleCommitmentStatus::Active)
                .count() as u64,
            rebalance_sponsorship_count: self.rebalance_sponsorships.len() as u64,
            active_rebalance_sponsorship_count: self
                .rebalance_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.usable())
                .count() as u64,
            pq_authorization_policy_count: self.pq_authorization_policies.len() as u64,
            monero_anchor_count: self.monero_anchors.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_rebalance_budget_units: self
                .rebalance_sponsorships
                .values()
                .map(|sponsorship| sponsorship.remaining_budget_units)
                .fold(0_u64, u64::saturating_add),
            min_privacy_set_size: self.config.min_privacy_set_size,
            min_pq_security_bits: self.config.min_pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "confidential_cross_margin_engine_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION,
            "protocol_name": CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_NAME,
            "height": self.height,
            "nonce": self.nonce,
            "account_ids": self.accounts.keys().cloned().collect::<Vec<_>>(),
            "live_product_markets": self.live_product_markets(),
            "guarded_account_ids": self.guarded_account_ids(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        confidential_cross_margin_engine_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> ConfidentialCrossMarginEngineResult<String> {
        self.config.validate()?;
        validate_positive("height", self.height)?;
        if self.accounts.len() > CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_ACCOUNTS {
            return Err("too many cross margin accounts".to_string());
        }
        if self.risk_buckets.len() > CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_RISK_BUCKETS {
            return Err("too many risk buckets".to_string());
        }
        if self.margin_nets.len() > CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_NETS {
            return Err("too many margin nets".to_string());
        }
        if self.public_records.len() > CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_PUBLIC_RECORDS {
            return Err("too many public records".to_string());
        }

        for (id, anchor) in &self.monero_anchors {
            if id != &anchor.anchor_id {
                return Err("monero anchor map key does not match anchor id".to_string());
            }
            anchor.validate()?;
        }
        for (id, account) in &self.accounts {
            if id != &account.account_id {
                return Err("account map key does not match account id".to_string());
            }
            account.validate()?;
            if !self.monero_anchors.contains_key(&account.monero_anchor_id) {
                return Err(format!(
                    "account {} references missing monero anchor",
                    account.account_id
                ));
            }
        }
        for (id, bucket) in &self.risk_buckets {
            if id != &bucket.bucket_id {
                return Err("risk bucket map key does not match bucket id".to_string());
            }
            bucket.validate()?;
            require_account(&self.accounts, &bucket.account_id, "risk bucket")?;
            if bucket.min_anonymity_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "risk bucket {} below privacy floor",
                    bucket.bucket_id
                ));
            }
        }
        for (id, net) in &self.margin_nets {
            if id != &net.net_id {
                return Err("margin net map key does not match net id".to_string());
            }
            net.validate()?;
            require_account(&self.accounts, &net.account_id, "margin net")?;
        }
        for (id, oracle) in &self.oracle_commitments {
            if id != &oracle.oracle_commitment_id {
                return Err("oracle map key does not match oracle commitment id".to_string());
            }
            oracle.validate()?;
            if oracle
                .valid_until_height
                .saturating_add(self.config.max_oracle_staleness_blocks)
                < self.height
            {
                return Err(format!(
                    "oracle commitment {} is stale",
                    oracle.oracle_commitment_id
                ));
            }
        }
        for (id, guard) in &self.liquidation_guards {
            if id != &guard.guard_id {
                return Err("liquidation guard map key does not match guard id".to_string());
            }
            guard.validate()?;
            require_account(&self.accounts, &guard.account_id, "liquidation guard")?;
            if !self.risk_buckets.contains_key(&guard.risk_bucket_id) {
                return Err(format!(
                    "guard {} references missing risk bucket",
                    guard.guard_id
                ));
            }
            if !self
                .oracle_commitments
                .contains_key(&guard.oracle_commitment_id)
            {
                return Err(format!(
                    "guard {} references missing oracle",
                    guard.guard_id
                ));
            }
        }
        for (id, sponsorship) in &self.rebalance_sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key does not match sponsorship id".to_string());
            }
            sponsorship.validate()?;
            if sponsorship.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "sponsorship {} below privacy floor",
                    sponsorship.sponsorship_id
                ));
            }
        }
        for (id, policy) in &self.pq_authorization_policies {
            if id != &policy.policy_id {
                return Err("pq policy map key does not match policy id".to_string());
            }
            policy.validate()?;
            if policy.pq_security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "pq policy {} below configured pq floor",
                    policy.policy_id
                ));
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("public record map key does not match record id".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }

    pub fn insert_account(
        &mut self,
        account: EncryptedCollateralAccount,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        account.validate()?;
        if !self.monero_anchors.contains_key(&account.monero_anchor_id) {
            return Err("account references unknown monero anchor".to_string());
        }
        self.add_public_record(
            PublicRecordKind::AccountCommitted,
            &account.account_id,
            &account.public_record(),
        )?;
        self.accounts.insert(account.account_id.clone(), account);
        Ok(())
    }

    pub fn insert_risk_bucket(
        &mut self,
        bucket: PrivateRiskBucket,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        bucket.validate()?;
        require_account(&self.accounts, &bucket.account_id, "risk bucket")?;
        self.add_public_record(
            PublicRecordKind::RiskBucketPosted,
            &bucket.bucket_id,
            &bucket.public_record(),
        )?;
        self.risk_buckets.insert(bucket.bucket_id.clone(), bucket);
        Ok(())
    }

    pub fn insert_margin_net(
        &mut self,
        net: ProductMarginNet,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        net.validate()?;
        require_account(&self.accounts, &net.account_id, "margin net")?;
        self.add_public_record(
            PublicRecordKind::MarginNetCommitted,
            &net.net_id,
            &net.public_record(),
        )?;
        self.margin_nets.insert(net.net_id.clone(), net);
        Ok(())
    }

    pub fn insert_liquidation_guard(
        &mut self,
        guard: LiquidationGuard,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        guard.validate()?;
        require_account(&self.accounts, &guard.account_id, "liquidation guard")?;
        if !self.risk_buckets.contains_key(&guard.risk_bucket_id) {
            return Err("liquidation guard references unknown risk bucket".to_string());
        }
        if !self
            .oracle_commitments
            .contains_key(&guard.oracle_commitment_id)
        {
            return Err("liquidation guard references unknown oracle commitment".to_string());
        }
        self.add_public_record(
            PublicRecordKind::LiquidationGuardArmed,
            &guard.guard_id,
            &guard.public_record(),
        )?;
        self.liquidation_guards
            .insert(guard.guard_id.clone(), guard);
        Ok(())
    }

    pub fn insert_oracle_commitment(
        &mut self,
        oracle: OracleCommitment,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        oracle.validate()?;
        self.add_public_record(
            PublicRecordKind::OracleCommitted,
            &oracle.oracle_commitment_id,
            &oracle.public_record(),
        )?;
        self.oracle_commitments
            .insert(oracle.oracle_commitment_id.clone(), oracle);
        Ok(())
    }

    pub fn insert_rebalance_sponsorship(
        &mut self,
        sponsorship: RebalanceSponsorship,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        sponsorship.validate()?;
        self.add_public_record(
            PublicRecordKind::RebalanceSponsored,
            &sponsorship.sponsorship_id,
            &sponsorship.public_record(),
        )?;
        self.rebalance_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(())
    }

    pub fn insert_pq_authorization_policy(
        &mut self,
        policy: PqAuthorizationPolicy,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        policy.validate()?;
        self.add_public_record(
            PublicRecordKind::PqPolicyPosted,
            &policy.policy_id,
            &policy.public_record(),
        )?;
        self.pq_authorization_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn insert_monero_anchor(
        &mut self,
        anchor: MoneroSettlementAnchor,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        anchor.validate()?;
        self.add_public_record(
            PublicRecordKind::MoneroAnchorPosted,
            &anchor.anchor_id,
            &anchor.public_record(),
        )?;
        self.monero_anchors.insert(anchor.anchor_id.clone(), anchor);
        Ok(())
    }

    pub fn insert_public_checkpoint(
        &mut self,
        label: &str,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        non_empty("checkpoint label", label)?;
        let roots = self.roots().public_record();
        self.add_public_record(
            PublicRecordKind::StateCheckpoint,
            label,
            &json!({
                "label": label,
                "height": self.height,
                "roots": roots,
            }),
        )
    }

    fn add_public_record(
        &mut self,
        kind: PublicRecordKind,
        subject_id: &str,
        subject_record: &Value,
    ) -> ConfidentialCrossMarginEngineResult<()> {
        let sequence = self.public_records.len() as u64;
        let record = CrossMarginPublicRecord::new(
            kind,
            subject_id,
            subject_record,
            self.height,
            sequence,
            &json!({
                "public_surface": "root-only",
                "privacy": "encrypted owners and amounts; bucket disclosure only",
            }),
        )?;
        self.public_records.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn live_product_markets(&self) -> Vec<String> {
        self.margin_nets
            .values()
            .filter(|net| net.status.is_live())
            .map(|net| net.market_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    }

    fn guarded_account_ids(&self) -> Vec<String> {
        self.liquidation_guards
            .values()
            .filter(|guard| guard.status.active())
            .map(|guard| guard.account_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    }
}

pub fn confidential_cross_margin_engine_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-CROSS-MARGIN-ENGINE-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION as i128),
            HashPart::Json(record),
        ],
        32,
    )
}

fn cross_margin_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn cross_margin_collection_root(domain: &str, records: &[Value]) -> String {
    cross_margin_payload_root(domain, &Value::Array(records.to_vec()))
}

fn cross_margin_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION as i128),
            HashPart::Str(value),
        ],
        32,
    )
}

fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let payload = json!({
        "parts": parts,
    });
    cross_margin_payload_root(domain, &payload)
}

fn cross_margin_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-CROSS-MARGIN-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_VERSION as i128),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn non_empty(field: &str, value: &str) -> ConfidentialCrossMarginEngineResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_positive(field: &str, value: u64) -> ConfidentialCrossMarginEngineResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_bps(field: &str, value: u64) -> ConfidentialCrossMarginEngineResult<()> {
    if value > CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn validate_bps_floor(field: &str, value: u64) -> ConfidentialCrossMarginEngineResult<()> {
    if value < CONFIDENTIAL_CROSS_MARGIN_ENGINE_MAX_BPS {
        Err(format!("{field} must be at least 1x bps"))
    } else {
        Ok(())
    }
}

fn validate_window(
    starts_at_height: u64,
    expires_at_height: u64,
    label: &str,
) -> ConfidentialCrossMarginEngineResult<()> {
    if expires_at_height <= starts_at_height {
        Err(format!("{label} expiry must be after start height"))
    } else {
        Ok(())
    }
}

fn validate_public_payload(
    field: &str,
    payload: &Value,
) -> ConfidentialCrossMarginEngineResult<()> {
    match payload {
        Value::Null => Err(format!("{field} must not be null")),
        _ => Ok(()),
    }
}

fn require_account(
    accounts: &BTreeMap<String, EncryptedCollateralAccount>,
    account_id: &str,
    label: &str,
) -> ConfidentialCrossMarginEngineResult<()> {
    if accounts.contains_key(account_id) {
        Ok(())
    } else {
        Err(format!("{label} references missing account {account_id}"))
    }
}

trait PublicRecordValue {
    fn as_public_record_value(&self) -> Value;
}

impl PublicRecordValue for EncryptedCollateralAccount {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for PrivateRiskBucket {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for ProductMarginNet {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for LiquidationGuard {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for OracleCommitment {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for RebalanceSponsorship {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for PqAuthorizationPolicy {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for MoneroSettlementAnchor {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for CrossMarginPublicRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

fn values_public_records<T: PublicRecordValue>(values: &BTreeMap<String, T>) -> Vec<Value> {
    values
        .values()
        .map(PublicRecordValue::as_public_record_value)
        .collect::<Vec<_>>()
}

#[allow(dead_code)]
fn _confidential_cross_margin_engine_domain_separator() -> String {
    cross_margin_string_root(
        "CONFIDENTIAL-CROSS-MARGIN-DOMAIN-SEPARATOR",
        CONFIDENTIAL_CROSS_MARGIN_ENGINE_PROTOCOL_NAME,
    )
}
