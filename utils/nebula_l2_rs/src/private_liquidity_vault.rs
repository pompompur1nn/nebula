use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateLiquidityVaultResult<T> = Result<T, String>;

pub const PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION: &str = "nebula-private-liquidity-vault-v1";
pub const PRIVATE_LIQUIDITY_VAULT_COMMITMENT_SCHEME: &str =
    "devnet-shake256-confidential-lp-vault-v1";
pub const PRIVATE_LIQUIDITY_VAULT_RESERVE_PROOF_SCHEME: &str =
    "devnet-wrapped-xmr-reserve-bucket-proof-v1";
pub const PRIVATE_LIQUIDITY_VAULT_MANDATE_ENCRYPTION_SCHEME: &str =
    "devnet-xwing-strategy-mandate-envelope-v1";
pub const PRIVATE_LIQUIDITY_VAULT_REBALANCE_INTENT_SCHEME: &str =
    "devnet-private-rebalance-intent-root-v1";
pub const PRIVATE_LIQUIDITY_VAULT_SOLVENCY_PROOF_SCHEME: &str =
    "devnet-private-lp-solvency-proof-v1";
pub const PRIVATE_LIQUIDITY_VAULT_LOW_FEE_SPONSORSHIP_SCHEME: &str =
    "private-vault-paymaster-sponsorship-root-v1";
pub const PRIVATE_LIQUIDITY_VAULT_ORACLE_BAND_SCHEME: &str = "threshold-oracle-price-band-root-v1";
pub const PRIVATE_LIQUIDITY_VAULT_PQ_APPROVAL_SCHEME: &str = "ml-dsa-87-custodian-approval-root-v1";
pub const PRIVATE_LIQUIDITY_VAULT_EMERGENCY_UNWIND_SCHEME: &str =
    "private-liquidity-emergency-unwind-root-v1";
pub const PRIVATE_LIQUIDITY_VAULT_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_LIQUIDITY_VAULT_MAX_BPS: u64 = 10_000;
pub const PRIVATE_LIQUIDITY_VAULT_BLOCKS_PER_YEAR: u64 = 2_628_000;
pub const PRIVATE_LIQUIDITY_VAULT_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const PRIVATE_LIQUIDITY_VAULT_DEFAULT_REBALANCE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_LIQUIDITY_VAULT_DEFAULT_WITHDRAWAL_COOLDOWN_BLOCKS: u64 = 10;
pub const PRIVATE_LIQUIDITY_VAULT_DEFAULT_SOLVENCY_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_LIQUIDITY_VAULT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const PRIVATE_LIQUIDITY_VAULT_DEFAULT_UNWIND_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_LIQUIDITY_VAULT_DEFAULT_LOW_FEE_LANE: &str = "small-private-lp-vault";
pub const PRIVATE_LIQUIDITY_VAULT_DEVNET_HEIGHT: u64 = 128;
pub const PRIVATE_LIQUIDITY_VAULT_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_LIQUIDITY_VAULT_DEVNET_RESERVE_ASSET_ID: &str = "wxmr-reserve-devnet";
pub const PRIVATE_LIQUIDITY_VAULT_DEVNET_LP_SHARE_ASSET_ID: &str = "plp-wxmr-devnet";
pub const PRIVATE_LIQUIDITY_VAULT_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_LIQUIDITY_VAULT_DEVNET_ORACLE_FEED_ID: &str = "feed-wxmr-usd-devnet";
pub const PRIVATE_LIQUIDITY_VAULT_DEVNET_WXMR_PRICE: u64 =
    164 * PRIVATE_LIQUIDITY_VAULT_PRICE_SCALE;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateLiquidityVaultStatus {
    Bootstrapping,
    Active,
    DepositsPaused,
    WithdrawalsPaused,
    RebalanceOnly,
    EmergencyUnwind,
    Paused,
    Retired,
}

impl PrivateLiquidityVaultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::DepositsPaused => "deposits_paused",
            Self::WithdrawalsPaused => "withdrawals_paused",
            Self::RebalanceOnly => "rebalance_only",
            Self::EmergencyUnwind => "emergency_unwind",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn allows_deposit(&self) -> bool {
        matches!(
            self,
            Self::Bootstrapping | Self::Active | Self::WithdrawalsPaused
        )
    }

    pub fn allows_withdrawal(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::DepositsPaused | Self::EmergencyUnwind
        )
    }

    pub fn allows_rebalance(&self) -> bool {
        matches!(
            self,
            Self::Active
                | Self::DepositsPaused
                | Self::WithdrawalsPaused
                | Self::RebalanceOnly
                | Self::EmergencyUnwind
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveBucketKind {
    Hot,
    Warm,
    Cold,
    Strategy,
    Insurance,
    Sponsor,
}

impl ReserveBucketKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::Strategy => "strategy",
            Self::Insurance => "insurance",
            Self::Sponsor => "sponsor",
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::Hot => 100,
            Self::Sponsor => 90,
            Self::Warm => 70,
            Self::Strategy => 50,
            Self::Insurance => 40,
            Self::Cold => 20,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveBucketStatus {
    Accepting,
    Rebalancing,
    Draining,
    Frozen,
    Exhausted,
    Retired,
}

impl ReserveBucketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::Rebalancing => "rebalancing",
            Self::Draining => "draining",
            Self::Frozen => "frozen",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }

    pub fn can_allocate(&self) -> bool {
        matches!(self, Self::Accepting | Self::Rebalancing)
    }

    pub fn can_release(&self) -> bool {
        matches!(self, Self::Accepting | Self::Rebalancing | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyRiskTier {
    Conservative,
    Balanced,
    YieldSeeking,
    Experimental,
    Emergency,
}

impl StrategyRiskTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::YieldSeeking => "yield_seeking",
            Self::Experimental => "experimental",
            Self::Emergency => "emergency",
        }
    }

    pub fn max_leverage_bps(&self) -> u64 {
        match self {
            Self::Conservative => 10_000,
            Self::Balanced => 12_500,
            Self::YieldSeeking => 15_000,
            Self::Experimental => 20_000,
            Self::Emergency => 10_000,
        }
    }

    pub fn risk_score_bps(&self) -> u64 {
        match self {
            Self::Conservative => 1_500,
            Self::Balanced => 3_000,
            Self::YieldSeeking => 5_500,
            Self::Experimental => 8_500,
            Self::Emergency => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateStatus {
    Draft,
    Active,
    Suspended,
    Rotating,
    Revoked,
    Expired,
}

impl MandateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn authorizes_rebalance(&self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceIntentStatus {
    Queued,
    Sponsored,
    Proving,
    Executed,
    Cancelled,
    Expired,
    Challenged,
}

impl RebalanceIntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sponsored => "sponsored",
            Self::Proving => "proving",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Sponsored | Self::Proving | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalQueueStatus {
    Queued,
    Matching,
    Reserved,
    Proving,
    Ready,
    Released,
    Cancelled,
    Expired,
}

impl WithdrawalQueueStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Matching => "matching",
            Self::Reserved => "reserved",
            Self::Proving => "proving",
            Self::Ready => "ready",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Matching | Self::Reserved | Self::Proving | Self::Ready
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencyAttestationStatus {
    Fresh,
    Watch,
    Stale,
    Disputed,
    Revoked,
}

impl SolvencyAttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Watch => "watch",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Fresh | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Expired,
    Revoked,
}

impl VaultSponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitScope {
    Vault,
    ReserveBucket,
    Mandate,
    Oracle,
    WithdrawalQueue,
    Sponsorship,
    Emergency,
}

impl RiskLimitScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::ReserveBucket => "reserve_bucket",
            Self::Mandate => "mandate",
            Self::Oracle => "oracle",
            Self::WithdrawalQueue => "withdrawal_queue",
            Self::Sponsorship => "sponsorship",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitAction {
    Observe,
    PauseDeposits,
    PauseWithdrawals,
    RebalanceOnly,
    FreezeBucket,
    EmergencyUnwind,
}

impl RiskLimitAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::PauseDeposits => "pause_deposits",
            Self::PauseWithdrawals => "pause_withdrawals",
            Self::RebalanceOnly => "rebalance_only",
            Self::FreezeBucket => "freeze_bucket",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitSeverity {
    Info,
    Watch,
    Elevated,
    Critical,
}

impl RiskLimitSeverity {
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
            Self::Watch => 2_500,
            Self::Elevated => 6_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitStatus {
    Monitoring,
    Warning,
    Breached,
    Enforced,
    Disabled,
}

impl RiskLimitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monitoring => "monitoring",
            Self::Warning => "warning",
            Self::Breached => "breached",
            Self::Enforced => "enforced",
            Self::Disabled => "disabled",
        }
    }

    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleBandStatus {
    Fresh,
    Widened,
    Frozen,
    Stale,
    Disputed,
}

impl OracleBandStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Widened => "widened",
            Self::Frozen => "frozen",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
        }
    }

    pub fn allows_pricing(&self) -> bool {
        matches!(self, Self::Fresh | Self::Widened)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalDecision {
    Approve,
    Deny,
    Defer,
    Emergency,
}

impl PqApprovalDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Defer => "defer",
            Self::Emergency => "emergency",
        }
    }

    pub fn allows_execution(&self) -> bool {
        matches!(self, Self::Approve | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyUnwindStatus {
    Planned,
    Armed,
    Executing,
    Completed,
    Cancelled,
    Expired,
}

impl EmergencyUnwindStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Armed => "armed",
            Self::Executing => "executing",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Planned | Self::Armed | Self::Executing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityAmountBucket {
    Dust,
    Small,
    Medium,
    Large,
    Whale,
}

impl LiquidityAmountBucket {
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

    pub fn sponsor_eligible(&self) -> bool {
        matches!(self, Self::Dust | Self::Small)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityVaultConfig {
    pub protocol_version: String,
    pub wxmr_asset_id: String,
    pub reserve_asset_id: String,
    pub lp_share_asset_id: String,
    pub monero_network: String,
    pub oracle_feed_id: String,
    pub default_low_fee_lane: String,
    pub max_total_value_units: u64,
    pub max_single_deposit_units: u64,
    pub max_single_withdrawal_units: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_idle_reserve_bps: u64,
    pub max_strategy_exposure_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub withdrawal_cooldown_blocks: u64,
    pub rebalance_intent_ttl_blocks: u64,
    pub solvency_attestation_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub unwind_plan_ttl_blocks: u64,
    pub sponsored_small_withdrawal_limit_units: u64,
    pub sponsored_max_fee_units: u64,
    pub pq_approval_threshold: u64,
}

impl Default for PrivateLiquidityVaultConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION.to_string(),
            wxmr_asset_id: PRIVATE_LIQUIDITY_VAULT_DEVNET_WXMR_ASSET_ID.to_string(),
            reserve_asset_id: PRIVATE_LIQUIDITY_VAULT_DEVNET_RESERVE_ASSET_ID.to_string(),
            lp_share_asset_id: PRIVATE_LIQUIDITY_VAULT_DEVNET_LP_SHARE_ASSET_ID.to_string(),
            monero_network: PRIVATE_LIQUIDITY_VAULT_DEVNET_MONERO_NETWORK.to_string(),
            oracle_feed_id: PRIVATE_LIQUIDITY_VAULT_DEVNET_ORACLE_FEED_ID.to_string(),
            default_low_fee_lane: PRIVATE_LIQUIDITY_VAULT_DEFAULT_LOW_FEE_LANE.to_string(),
            max_total_value_units: 25_000_000_000_000,
            max_single_deposit_units: 500_000_000_000,
            max_single_withdrawal_units: 250_000_000_000,
            min_reserve_coverage_bps: 10_500,
            target_idle_reserve_bps: 2_500,
            max_strategy_exposure_bps: 7_500,
            max_oracle_deviation_bps: 650,
            max_oracle_staleness_blocks:
                PRIVATE_LIQUIDITY_VAULT_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            withdrawal_cooldown_blocks: PRIVATE_LIQUIDITY_VAULT_DEFAULT_WITHDRAWAL_COOLDOWN_BLOCKS,
            rebalance_intent_ttl_blocks: PRIVATE_LIQUIDITY_VAULT_DEFAULT_REBALANCE_TTL_BLOCKS,
            solvency_attestation_ttl_blocks: PRIVATE_LIQUIDITY_VAULT_DEFAULT_SOLVENCY_TTL_BLOCKS,
            challenge_window_blocks: PRIVATE_LIQUIDITY_VAULT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            unwind_plan_ttl_blocks: PRIVATE_LIQUIDITY_VAULT_DEFAULT_UNWIND_TTL_BLOCKS,
            sponsored_small_withdrawal_limit_units: 25_000_000,
            sponsored_max_fee_units: 250_000,
            pq_approval_threshold: 2,
        }
    }
}

impl PrivateLiquidityVaultConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_vault_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "wxmr_asset_id": self.wxmr_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "lp_share_asset_id": self.lp_share_asset_id,
            "monero_network": self.monero_network,
            "oracle_feed_id": self.oracle_feed_id,
            "default_low_fee_lane": self.default_low_fee_lane,
            "max_total_value_units": self.max_total_value_units,
            "max_single_deposit_units": self.max_single_deposit_units,
            "max_single_withdrawal_units": self.max_single_withdrawal_units,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_idle_reserve_bps": self.target_idle_reserve_bps,
            "max_strategy_exposure_bps": self.max_strategy_exposure_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "withdrawal_cooldown_blocks": self.withdrawal_cooldown_blocks,
            "rebalance_intent_ttl_blocks": self.rebalance_intent_ttl_blocks,
            "solvency_attestation_ttl_blocks": self.solvency_attestation_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "unwind_plan_ttl_blocks": self.unwind_plan_ttl_blocks,
            "sponsored_small_withdrawal_limit_units": self.sponsored_small_withdrawal_limit_units,
            "sponsored_max_fee_units": self.sponsored_max_fee_units,
            "pq_approval_threshold": self.pq_approval_threshold,
            "commitment_scheme": PRIVATE_LIQUIDITY_VAULT_COMMITMENT_SCHEME,
            "reserve_proof_scheme": PRIVATE_LIQUIDITY_VAULT_RESERVE_PROOF_SCHEME,
            "mandate_encryption_scheme": PRIVATE_LIQUIDITY_VAULT_MANDATE_ENCRYPTION_SCHEME,
            "rebalance_intent_scheme": PRIVATE_LIQUIDITY_VAULT_REBALANCE_INTENT_SCHEME,
            "solvency_proof_scheme": PRIVATE_LIQUIDITY_VAULT_SOLVENCY_PROOF_SCHEME,
            "oracle_band_scheme": PRIVATE_LIQUIDITY_VAULT_ORACLE_BAND_SCHEME,
            "pq_approval_scheme": PRIVATE_LIQUIDITY_VAULT_PQ_APPROVAL_SCHEME,
        })
    }

    pub fn config_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-VAULT-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<()> {
        ensure_non_empty(&self.protocol_version, "vault config protocol version")?;
        ensure_non_empty(&self.wxmr_asset_id, "vault config wxmr asset")?;
        ensure_non_empty(&self.reserve_asset_id, "vault config reserve asset")?;
        ensure_non_empty(&self.lp_share_asset_id, "vault config lp share asset")?;
        ensure_non_empty(&self.monero_network, "vault config monero network")?;
        ensure_non_empty(&self.oracle_feed_id, "vault config oracle feed")?;
        ensure_non_empty(&self.default_low_fee_lane, "vault config low fee lane")?;
        ensure_positive(
            self.max_total_value_units,
            "vault config max total value units",
        )?;
        ensure_positive(
            self.max_single_deposit_units,
            "vault config max single deposit units",
        )?;
        ensure_positive(
            self.max_single_withdrawal_units,
            "vault config max single withdrawal units",
        )?;
        ensure_bps(
            self.target_idle_reserve_bps,
            "vault config target idle reserve bps",
        )?;
        ensure_bps(
            self.max_strategy_exposure_bps,
            "vault config max strategy exposure bps",
        )?;
        ensure_bps(
            self.max_oracle_deviation_bps,
            "vault config max oracle deviation bps",
        )?;
        ensure_positive(
            self.min_reserve_coverage_bps,
            "vault config min reserve coverage bps",
        )?;
        ensure_positive(
            self.max_oracle_staleness_blocks,
            "vault config max oracle staleness",
        )?;
        ensure_positive(
            self.rebalance_intent_ttl_blocks,
            "vault config rebalance ttl",
        )?;
        ensure_positive(
            self.solvency_attestation_ttl_blocks,
            "vault config solvency ttl",
        )?;
        ensure_positive(
            self.challenge_window_blocks,
            "vault config challenge window",
        )?;
        ensure_positive(self.unwind_plan_ttl_blocks, "vault config unwind ttl")?;
        ensure_positive(self.pq_approval_threshold, "vault config pq threshold")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLpVault {
    pub vault_id: String,
    pub label: String,
    pub owner_commitment: String,
    pub lp_share_asset_id: String,
    pub reserve_asset_id: String,
    pub wxmr_asset_id: String,
    pub share_commitment_root: String,
    pub nullifier_root: String,
    pub encrypted_metadata_root: String,
    pub mandate_root: String,
    pub risk_limit_root: String,
    pub total_share_supply_upper_bound: u64,
    pub total_assets_floor_units: u64,
    pub total_assets_upper_bound_units: u64,
    pub locked_withdrawal_units: u64,
    pub target_idle_reserve_bps: u64,
    pub fee_bps: u64,
    pub status: PrivateLiquidityVaultStatus,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
}

impl ConfidentialLpVault {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        owner_commitment: &str,
        lp_share_asset_id: &str,
        reserve_asset_id: &str,
        wxmr_asset_id: &str,
        share_commitment_root: &str,
        nullifier_root: &str,
        encrypted_metadata: &Value,
        total_assets_floor_units: u64,
        total_assets_upper_bound_units: u64,
        target_idle_reserve_bps: u64,
        fee_bps: u64,
        opened_at_height: u64,
        nonce: u64,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(label, "lp vault label")?;
        ensure_non_empty(owner_commitment, "lp vault owner commitment")?;
        ensure_non_empty(lp_share_asset_id, "lp vault share asset")?;
        ensure_non_empty(reserve_asset_id, "lp vault reserve asset")?;
        ensure_non_empty(wxmr_asset_id, "lp vault wxmr asset")?;
        ensure_non_empty(share_commitment_root, "lp vault share commitment root")?;
        ensure_non_empty(nullifier_root, "lp vault nullifier root")?;
        ensure_bps(target_idle_reserve_bps, "lp vault target idle reserve bps")?;
        ensure_bps(fee_bps, "lp vault fee bps")?;
        if total_assets_floor_units > total_assets_upper_bound_units {
            return Err("lp vault floor exceeds upper bound".to_string());
        }
        let encrypted_metadata_root = private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-VAULT-ENCRYPTED-METADATA",
            encrypted_metadata,
        );
        let vault_id = private_liquidity_vault_id(
            label,
            owner_commitment,
            lp_share_asset_id,
            reserve_asset_id,
            share_commitment_root,
            nonce,
        );
        Ok(Self {
            vault_id,
            label: label.to_string(),
            owner_commitment: owner_commitment.to_string(),
            lp_share_asset_id: lp_share_asset_id.to_string(),
            reserve_asset_id: reserve_asset_id.to_string(),
            wxmr_asset_id: wxmr_asset_id.to_string(),
            share_commitment_root: share_commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            encrypted_metadata_root,
            mandate_root: empty_root("PRIVATE-LIQUIDITY-VAULT-MANDATES"),
            risk_limit_root: empty_root("PRIVATE-LIQUIDITY-VAULT-RISK-LIMITS"),
            total_share_supply_upper_bound: total_assets_upper_bound_units,
            total_assets_floor_units,
            total_assets_upper_bound_units,
            locked_withdrawal_units: 0,
            target_idle_reserve_bps,
            fee_bps,
            status: PrivateLiquidityVaultStatus::Bootstrapping,
            opened_at_height,
            updated_at_height: opened_at_height,
            nonce,
        })
    }

    pub fn available_floor_units(&self) -> u64 {
        self.total_assets_floor_units
            .saturating_sub(self.locked_withdrawal_units)
    }

    pub fn reserve_coverage_bps(&self) -> u64 {
        ratio_bps(
            self.available_floor_units(),
            self.total_assets_upper_bound_units.max(1),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lp_vault",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "vault_id": self.vault_id,
            "label": self.label,
            "owner_commitment": self.owner_commitment,
            "lp_share_asset_id": self.lp_share_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "wxmr_asset_id": self.wxmr_asset_id,
            "share_commitment_root": self.share_commitment_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "mandate_root": self.mandate_root,
            "risk_limit_root": self.risk_limit_root,
            "total_share_supply_upper_bound": self.total_share_supply_upper_bound,
            "total_assets_floor_units": self.total_assets_floor_units,
            "total_assets_upper_bound_units": self.total_assets_upper_bound_units,
            "locked_withdrawal_units": self.locked_withdrawal_units,
            "available_floor_units": self.available_floor_units(),
            "reserve_coverage_bps": self.reserve_coverage_bps(),
            "target_idle_reserve_bps": self.target_idle_reserve_bps,
            "fee_bps": self.fee_bps,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn vault_root(&self) -> String {
        private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-VAULT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = private_liquidity_vault_id(
            &self.label,
            &self.owner_commitment,
            &self.lp_share_asset_id,
            &self.reserve_asset_id,
            &self.share_commitment_root,
            self.nonce,
        );
        if self.vault_id != computed_id {
            return Err("lp vault id mismatch".to_string());
        }
        ensure_non_empty(&self.nullifier_root, "lp vault nullifier root")?;
        ensure_non_empty(
            &self.encrypted_metadata_root,
            "lp vault encrypted metadata root",
        )?;
        ensure_non_empty(&self.mandate_root, "lp vault mandate root")?;
        ensure_non_empty(&self.risk_limit_root, "lp vault risk limit root")?;
        ensure_bps(
            self.target_idle_reserve_bps,
            "lp vault target idle reserve bps",
        )?;
        ensure_bps(self.fee_bps, "lp vault fee bps")?;
        if self.total_assets_floor_units > self.total_assets_upper_bound_units {
            return Err("lp vault floor exceeds upper bound".to_string());
        }
        if self.locked_withdrawal_units > self.total_assets_upper_bound_units {
            return Err("lp vault locked withdrawals exceed assets".to_string());
        }
        Ok(self.vault_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedXmrReserveBucket {
    pub bucket_id: String,
    pub vault_id: String,
    pub bucket_kind: ReserveBucketKind,
    pub asset_id: String,
    pub monero_network: String,
    pub reserve_address_root: String,
    pub proof_key_root: String,
    pub gross_units: u64,
    pub pending_inbound_units: u64,
    pub pending_outbound_units: u64,
    pub reserved_units: u64,
    pub strategy_allocated_units: u64,
    pub floor_units: u64,
    pub target_units: u64,
    pub max_release_units_per_block: u64,
    pub min_confirmations: u64,
    pub status: ReserveBucketStatus,
    pub priority: u64,
    pub last_proof_height: u64,
    pub metadata_root: String,
}

impl WrappedXmrReserveBucket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        bucket_kind: ReserveBucketKind,
        asset_id: &str,
        monero_network: &str,
        reserve_address_root: &str,
        proof_key_root: &str,
        gross_units: u64,
        floor_units: u64,
        target_units: u64,
        max_release_units_per_block: u64,
        min_confirmations: u64,
        priority: u64,
        last_proof_height: u64,
        metadata: &Value,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "reserve bucket vault id")?;
        ensure_non_empty(asset_id, "reserve bucket asset id")?;
        ensure_non_empty(monero_network, "reserve bucket monero network")?;
        ensure_non_empty(reserve_address_root, "reserve bucket address root")?;
        ensure_non_empty(proof_key_root, "reserve bucket proof key root")?;
        ensure_positive(max_release_units_per_block, "reserve bucket max release")?;
        if floor_units > target_units.max(gross_units) {
            return Err("reserve bucket floor exceeds available target".to_string());
        }
        let metadata_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-RESERVE-METADATA", metadata);
        let bucket_id = reserve_bucket_id(
            vault_id,
            &bucket_kind,
            asset_id,
            monero_network,
            reserve_address_root,
        );
        Ok(Self {
            bucket_id,
            vault_id: vault_id.to_string(),
            bucket_kind,
            asset_id: asset_id.to_string(),
            monero_network: monero_network.to_string(),
            reserve_address_root: reserve_address_root.to_string(),
            proof_key_root: proof_key_root.to_string(),
            gross_units,
            pending_inbound_units: 0,
            pending_outbound_units: 0,
            reserved_units: 0,
            strategy_allocated_units: 0,
            floor_units,
            target_units,
            max_release_units_per_block,
            min_confirmations,
            status: ReserveBucketStatus::Accepting,
            priority: priority.max(bucket_kind.default_priority()),
            last_proof_height,
            metadata_root,
        })
    }

    pub fn liability_units(&self) -> u64 {
        self.pending_outbound_units
            .saturating_add(self.reserved_units)
            .saturating_add(self.strategy_allocated_units)
    }

    pub fn available_units(&self) -> u64 {
        self.gross_units
            .saturating_add(self.pending_inbound_units)
            .saturating_sub(self.liability_units())
    }

    pub fn coverage_bps(&self) -> u64 {
        if self.liability_units() == 0 {
            PRIVATE_LIQUIDITY_VAULT_MAX_BPS
        } else {
            ratio_bps(self.gross_units, self.liability_units())
        }
    }

    pub fn utilization_bps(&self) -> u64 {
        ratio_bps(
            self.target_units.saturating_sub(self.available_units()),
            self.target_units.max(1),
        )
    }

    pub fn can_release(&self, amount_units: u64) -> bool {
        self.status.can_release() && amount_units > 0 && self.available_units() >= amount_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wrapped_xmr_reserve_bucket",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "vault_id": self.vault_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "asset_id": self.asset_id,
            "monero_network": self.monero_network,
            "reserve_address_root": self.reserve_address_root,
            "proof_key_root": self.proof_key_root,
            "gross_units": self.gross_units,
            "pending_inbound_units": self.pending_inbound_units,
            "pending_outbound_units": self.pending_outbound_units,
            "reserved_units": self.reserved_units,
            "strategy_allocated_units": self.strategy_allocated_units,
            "liability_units": self.liability_units(),
            "available_units": self.available_units(),
            "floor_units": self.floor_units,
            "target_units": self.target_units,
            "coverage_bps": self.coverage_bps(),
            "utilization_bps": self.utilization_bps(),
            "max_release_units_per_block": self.max_release_units_per_block,
            "min_confirmations": self.min_confirmations,
            "status": self.status.as_str(),
            "priority": self.priority,
            "last_proof_height": self.last_proof_height,
            "metadata_root": self.metadata_root,
            "reserve_proof_scheme": PRIVATE_LIQUIDITY_VAULT_RESERVE_PROOF_SCHEME,
        })
    }

    pub fn bucket_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-WXMR-RESERVE-BUCKET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = reserve_bucket_id(
            &self.vault_id,
            &self.bucket_kind,
            &self.asset_id,
            &self.monero_network,
            &self.reserve_address_root,
        );
        if self.bucket_id != computed_id {
            return Err("reserve bucket id mismatch".to_string());
        }
        ensure_non_empty(&self.proof_key_root, "reserve bucket proof key root")?;
        ensure_non_empty(&self.metadata_root, "reserve bucket metadata root")?;
        ensure_positive(
            self.max_release_units_per_block,
            "reserve bucket max release",
        )?;
        if self.floor_units > self.target_units.max(self.gross_units) {
            return Err("reserve bucket floor exceeds target".to_string());
        }
        if self.liability_units() > self.gross_units.saturating_add(self.pending_inbound_units) {
            return Err("reserve bucket liabilities exceed available gross units".to_string());
        }
        Ok(self.bucket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedStrategyMandate {
    pub mandate_id: String,
    pub vault_id: String,
    pub strategy_commitment: String,
    pub strategy_kind: String,
    pub risk_tier: StrategyRiskTier,
    pub encrypted_terms_root: String,
    pub allowed_asset_root: String,
    pub allowed_venue_root: String,
    pub guardrail_root: String,
    pub fee_recipient_commitment: String,
    pub max_exposure_bps: u64,
    pub max_leverage_bps: u64,
    pub max_slippage_bps: u64,
    pub rebalance_cooldown_blocks: u64,
    pub status: MandateStatus,
    pub version: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl EncryptedStrategyMandate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        strategy_commitment: &str,
        strategy_kind: &str,
        risk_tier: StrategyRiskTier,
        encrypted_terms: &Value,
        allowed_assets: &[String],
        allowed_venues: &[String],
        guardrails: &Value,
        fee_recipient_commitment: &str,
        max_exposure_bps: u64,
        max_slippage_bps: u64,
        rebalance_cooldown_blocks: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "strategy mandate vault id")?;
        ensure_non_empty(strategy_commitment, "strategy mandate commitment")?;
        ensure_non_empty(strategy_kind, "strategy mandate kind")?;
        ensure_non_empty(fee_recipient_commitment, "strategy mandate fee recipient")?;
        ensure_bps(max_exposure_bps, "strategy mandate max exposure bps")?;
        ensure_bps(max_slippage_bps, "strategy mandate max slippage bps")?;
        ensure_ordered_heights(
            issued_at_height,
            expires_at_height,
            "strategy mandate validity",
        )?;
        let allowed_asset_root = private_liquidity_vault_string_set_root(
            "PRIVATE-LIQUIDITY-MANDATE-ASSETS",
            allowed_assets,
        );
        let allowed_venue_root = private_liquidity_vault_string_set_root(
            "PRIVATE-LIQUIDITY-MANDATE-VENUES",
            allowed_venues,
        );
        let encrypted_terms_root = private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-MANDATE-TERMS",
            encrypted_terms,
        );
        let guardrail_root = private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-MANDATE-GUARDRAILS",
            guardrails,
        );
        let max_leverage_bps = risk_tier.max_leverage_bps();
        let mandate_id = strategy_mandate_id(
            vault_id,
            strategy_commitment,
            strategy_kind,
            &encrypted_terms_root,
            nonce,
        );
        Ok(Self {
            mandate_id,
            vault_id: vault_id.to_string(),
            strategy_commitment: strategy_commitment.to_string(),
            strategy_kind: strategy_kind.to_string(),
            risk_tier,
            encrypted_terms_root,
            allowed_asset_root,
            allowed_venue_root,
            guardrail_root,
            fee_recipient_commitment: fee_recipient_commitment.to_string(),
            max_exposure_bps,
            max_leverage_bps,
            max_slippage_bps,
            rebalance_cooldown_blocks,
            status: MandateStatus::Active,
            version: 1,
            issued_at_height,
            expires_at_height,
            nonce,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.authorizes_rebalance()
            && self.issued_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_strategy_mandate",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "mandate_id": self.mandate_id,
            "vault_id": self.vault_id,
            "strategy_commitment": self.strategy_commitment,
            "strategy_kind": self.strategy_kind,
            "risk_tier": self.risk_tier.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "allowed_asset_root": self.allowed_asset_root,
            "allowed_venue_root": self.allowed_venue_root,
            "guardrail_root": self.guardrail_root,
            "fee_recipient_commitment": self.fee_recipient_commitment,
            "max_exposure_bps": self.max_exposure_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "rebalance_cooldown_blocks": self.rebalance_cooldown_blocks,
            "status": self.status.as_str(),
            "version": self.version,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "mandate_encryption_scheme": PRIVATE_LIQUIDITY_VAULT_MANDATE_ENCRYPTION_SCHEME,
        })
    }

    pub fn mandate_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-STRATEGY-MANDATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = strategy_mandate_id(
            &self.vault_id,
            &self.strategy_commitment,
            &self.strategy_kind,
            &self.encrypted_terms_root,
            self.nonce,
        );
        if self.mandate_id != computed_id {
            return Err("strategy mandate id mismatch".to_string());
        }
        ensure_non_empty(
            &self.allowed_asset_root,
            "strategy mandate allowed asset root",
        )?;
        ensure_non_empty(
            &self.allowed_venue_root,
            "strategy mandate allowed venue root",
        )?;
        ensure_non_empty(&self.guardrail_root, "strategy mandate guardrail root")?;
        ensure_bps(self.max_exposure_bps, "strategy mandate max exposure bps")?;
        ensure_bps(self.max_slippage_bps, "strategy mandate max slippage bps")?;
        if self.max_leverage_bps > self.risk_tier.max_leverage_bps() {
            return Err("strategy mandate leverage exceeds risk tier".to_string());
        }
        ensure_ordered_heights(
            self.issued_at_height,
            self.expires_at_height,
            "strategy mandate validity",
        )?;
        ensure_positive(self.version, "strategy mandate version")?;
        Ok(self.mandate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRebalancingIntent {
    pub intent_id: String,
    pub vault_id: String,
    pub mandate_id: String,
    pub source_bucket_id: String,
    pub target_bucket_id: String,
    pub encrypted_action_root: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub nullifier_root: String,
    pub oracle_band_id: String,
    pub max_slippage_bps: u64,
    pub amount_bucket: LiquidityAmountBucket,
    pub fee_budget_units: u64,
    pub priority: u64,
    pub status: RebalanceIntentStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl PrivateRebalancingIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        mandate_id: &str,
        source_bucket_id: &str,
        target_bucket_id: &str,
        encrypted_action: &Value,
        input_commitment_root: &str,
        output_commitment_root: &str,
        nullifier_root: &str,
        oracle_band_id: &str,
        max_slippage_bps: u64,
        amount_bucket: LiquidityAmountBucket,
        fee_budget_units: u64,
        priority: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "rebalance intent vault id")?;
        ensure_non_empty(mandate_id, "rebalance intent mandate id")?;
        ensure_non_empty(source_bucket_id, "rebalance intent source bucket")?;
        ensure_non_empty(target_bucket_id, "rebalance intent target bucket")?;
        ensure_non_empty(input_commitment_root, "rebalance intent input root")?;
        ensure_non_empty(output_commitment_root, "rebalance intent output root")?;
        ensure_non_empty(nullifier_root, "rebalance intent nullifier root")?;
        ensure_non_empty(oracle_band_id, "rebalance intent oracle band")?;
        ensure_bps(max_slippage_bps, "rebalance intent max slippage bps")?;
        ensure_positive(ttl_blocks, "rebalance intent ttl")?;
        let encrypted_action_root = private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-REBALANCE-ACTION",
            encrypted_action,
        );
        let expires_at_height = submitted_at_height.saturating_add(ttl_blocks);
        let intent_id = rebalance_intent_id(
            vault_id,
            mandate_id,
            source_bucket_id,
            target_bucket_id,
            &encrypted_action_root,
            nonce,
        );
        Ok(Self {
            intent_id,
            vault_id: vault_id.to_string(),
            mandate_id: mandate_id.to_string(),
            source_bucket_id: source_bucket_id.to_string(),
            target_bucket_id: target_bucket_id.to_string(),
            encrypted_action_root,
            input_commitment_root: input_commitment_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            oracle_band_id: oracle_band_id.to_string(),
            max_slippage_bps,
            amount_bucket,
            fee_budget_units,
            priority,
            status: RebalanceIntentStatus::Queued,
            submitted_at_height,
            expires_at_height,
            nonce,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live()
            && self.submitted_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_rebalancing_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "vault_id": self.vault_id,
            "mandate_id": self.mandate_id,
            "source_bucket_id": self.source_bucket_id,
            "target_bucket_id": self.target_bucket_id,
            "encrypted_action_root": self.encrypted_action_root,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "nullifier_root": self.nullifier_root,
            "oracle_band_id": self.oracle_band_id,
            "max_slippage_bps": self.max_slippage_bps,
            "amount_bucket": self.amount_bucket.as_str(),
            "fee_budget_units": self.fee_budget_units,
            "priority": self.priority,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "rebalance_intent_scheme": PRIVATE_LIQUIDITY_VAULT_REBALANCE_INTENT_SCHEME,
        })
    }

    pub fn intent_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-REBALANCE-INTENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = rebalance_intent_id(
            &self.vault_id,
            &self.mandate_id,
            &self.source_bucket_id,
            &self.target_bucket_id,
            &self.encrypted_action_root,
            self.nonce,
        );
        if self.intent_id != computed_id {
            return Err("rebalance intent id mismatch".to_string());
        }
        if self.source_bucket_id == self.target_bucket_id {
            return Err("rebalance intent source and target bucket match".to_string());
        }
        ensure_non_empty(&self.input_commitment_root, "rebalance intent input root")?;
        ensure_non_empty(&self.output_commitment_root, "rebalance intent output root")?;
        ensure_non_empty(&self.nullifier_root, "rebalance intent nullifier root")?;
        ensure_non_empty(&self.oracle_band_id, "rebalance intent oracle band")?;
        ensure_bps(self.max_slippage_bps, "rebalance intent max slippage bps")?;
        ensure_ordered_heights(
            self.submitted_at_height,
            self.expires_at_height,
            "rebalance intent validity",
        )?;
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalQueueEntry {
    pub withdrawal_id: String,
    pub vault_id: String,
    pub bucket_id: String,
    pub owner_commitment: String,
    pub share_nullifier_root: String,
    pub recipient_address_hash_root: String,
    pub amount_bucket: LiquidityAmountBucket,
    pub amount_floor_units: u64,
    pub amount_ceiling_units: u64,
    pub requested_fee_units: u64,
    pub sponsor_id: String,
    pub reserve_proof_root: String,
    pub status: WithdrawalQueueStatus,
    pub requested_at_height: u64,
    pub min_release_height: u64,
    pub expires_at_height: u64,
    pub queue_position: u64,
    pub nonce: u64,
}

impl WithdrawalQueueEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        bucket_id: &str,
        owner_commitment: &str,
        share_nullifier_root: &str,
        recipient_address_hash_root: &str,
        amount_bucket: LiquidityAmountBucket,
        amount_floor_units: u64,
        amount_ceiling_units: u64,
        requested_fee_units: u64,
        reserve_proof_root: &str,
        requested_at_height: u64,
        min_release_height: u64,
        expires_at_height: u64,
        queue_position: u64,
        nonce: u64,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "withdrawal vault id")?;
        ensure_non_empty(bucket_id, "withdrawal bucket id")?;
        ensure_non_empty(owner_commitment, "withdrawal owner commitment")?;
        ensure_non_empty(share_nullifier_root, "withdrawal share nullifier")?;
        ensure_non_empty(recipient_address_hash_root, "withdrawal recipient root")?;
        ensure_non_empty(reserve_proof_root, "withdrawal reserve proof root")?;
        ensure_positive(amount_ceiling_units, "withdrawal amount ceiling")?;
        if amount_floor_units > amount_ceiling_units {
            return Err("withdrawal floor exceeds ceiling".to_string());
        }
        if amount_ceiling_units > amount_bucket.ceiling_units() {
            return Err("withdrawal amount exceeds bucket ceiling".to_string());
        }
        ensure_ordered_heights(
            requested_at_height,
            min_release_height,
            "withdrawal release window",
        )?;
        ensure_ordered_heights(min_release_height, expires_at_height, "withdrawal validity")?;
        let withdrawal_id = withdrawal_entry_id(
            vault_id,
            bucket_id,
            owner_commitment,
            share_nullifier_root,
            queue_position,
            nonce,
        );
        Ok(Self {
            withdrawal_id,
            vault_id: vault_id.to_string(),
            bucket_id: bucket_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            share_nullifier_root: share_nullifier_root.to_string(),
            recipient_address_hash_root: recipient_address_hash_root.to_string(),
            amount_bucket,
            amount_floor_units,
            amount_ceiling_units,
            requested_fee_units,
            sponsor_id: String::new(),
            reserve_proof_root: reserve_proof_root.to_string(),
            status: WithdrawalQueueStatus::Queued,
            requested_at_height,
            min_release_height,
            expires_at_height,
            queue_position,
            nonce,
        })
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status.is_open()
            && self.requested_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_withdrawal_queue_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "vault_id": self.vault_id,
            "bucket_id": self.bucket_id,
            "owner_commitment": self.owner_commitment,
            "share_nullifier_root": self.share_nullifier_root,
            "recipient_address_hash_root": self.recipient_address_hash_root,
            "amount_bucket": self.amount_bucket.as_str(),
            "amount_floor_units": self.amount_floor_units,
            "amount_ceiling_units": self.amount_ceiling_units,
            "requested_fee_units": self.requested_fee_units,
            "sponsor_id": self.sponsor_id,
            "reserve_proof_root": self.reserve_proof_root,
            "status": self.status.as_str(),
            "requested_at_height": self.requested_at_height,
            "min_release_height": self.min_release_height,
            "expires_at_height": self.expires_at_height,
            "queue_position": self.queue_position,
            "nonce": self.nonce,
        })
    }

    pub fn withdrawal_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-WITHDRAWAL-QUEUE-ENTRY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = withdrawal_entry_id(
            &self.vault_id,
            &self.bucket_id,
            &self.owner_commitment,
            &self.share_nullifier_root,
            self.queue_position,
            self.nonce,
        );
        if self.withdrawal_id != computed_id {
            return Err("withdrawal id mismatch".to_string());
        }
        ensure_non_empty(
            &self.recipient_address_hash_root,
            "withdrawal recipient root",
        )?;
        ensure_non_empty(&self.reserve_proof_root, "withdrawal reserve proof root")?;
        if self.amount_floor_units > self.amount_ceiling_units {
            return Err("withdrawal floor exceeds ceiling".to_string());
        }
        if self.amount_ceiling_units > self.amount_bucket.ceiling_units() {
            return Err("withdrawal amount exceeds bucket ceiling".to_string());
        }
        ensure_ordered_heights(
            self.requested_at_height,
            self.min_release_height,
            "withdrawal release window",
        )?;
        ensure_ordered_heights(
            self.min_release_height,
            self.expires_at_height,
            "withdrawal validity",
        )?;
        Ok(self.withdrawal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencyAttestation {
    pub attestation_id: String,
    pub vault_id: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub strategy_exposure_root: String,
    pub oracle_band_root: String,
    pub total_assets_floor_units: u64,
    pub total_liabilities_ceiling_units: u64,
    pub reserve_coverage_bps: u64,
    pub strategy_exposure_bps: u64,
    pub auditor_committee_root: String,
    pub proof_system: String,
    pub status: SolvencyAttestationStatus,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_end_height: u64,
    pub metadata_root: String,
}

impl SolvencyAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        reserve_root: &str,
        liability_root: &str,
        strategy_exposure_root: &str,
        oracle_band_root: &str,
        total_assets_floor_units: u64,
        total_liabilities_ceiling_units: u64,
        strategy_exposure_bps: u64,
        auditor_committee_root: &str,
        attested_at_height: u64,
        ttl_blocks: u64,
        challenge_window_blocks: u64,
        metadata: &Value,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "solvency attestation vault id")?;
        ensure_non_empty(reserve_root, "solvency attestation reserve root")?;
        ensure_non_empty(liability_root, "solvency attestation liability root")?;
        ensure_non_empty(
            strategy_exposure_root,
            "solvency attestation strategy exposure root",
        )?;
        ensure_non_empty(oracle_band_root, "solvency attestation oracle band root")?;
        ensure_non_empty(auditor_committee_root, "solvency attestation auditor root")?;
        ensure_bps(
            strategy_exposure_bps,
            "solvency attestation strategy exposure bps",
        )?;
        ensure_positive(ttl_blocks, "solvency attestation ttl")?;
        ensure_positive(
            challenge_window_blocks,
            "solvency attestation challenge window",
        )?;
        let reserve_coverage_bps = ratio_bps(
            total_assets_floor_units,
            total_liabilities_ceiling_units.max(1),
        );
        let expires_at_height = attested_at_height.saturating_add(ttl_blocks);
        let challenge_window_end_height =
            attested_at_height.saturating_add(challenge_window_blocks);
        let metadata_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-SOLVENCY-METADATA", metadata);
        let attestation_id = solvency_attestation_id(
            vault_id,
            reserve_root,
            liability_root,
            oracle_band_root,
            attested_at_height,
        );
        Ok(Self {
            attestation_id,
            vault_id: vault_id.to_string(),
            reserve_root: reserve_root.to_string(),
            liability_root: liability_root.to_string(),
            strategy_exposure_root: strategy_exposure_root.to_string(),
            oracle_band_root: oracle_band_root.to_string(),
            total_assets_floor_units,
            total_liabilities_ceiling_units,
            reserve_coverage_bps,
            strategy_exposure_bps,
            auditor_committee_root: auditor_committee_root.to_string(),
            proof_system: PRIVATE_LIQUIDITY_VAULT_SOLVENCY_PROOF_SCHEME.to_string(),
            status: SolvencyAttestationStatus::Fresh,
            attested_at_height,
            expires_at_height,
            challenge_window_end_height,
            metadata_root,
        })
    }

    pub fn is_fresh_at(&self, height: u64) -> bool {
        self.status.is_usable()
            && self.attested_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_solvency_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "strategy_exposure_root": self.strategy_exposure_root,
            "oracle_band_root": self.oracle_band_root,
            "total_assets_floor_units": self.total_assets_floor_units,
            "total_liabilities_ceiling_units": self.total_liabilities_ceiling_units,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "strategy_exposure_bps": self.strategy_exposure_bps,
            "auditor_committee_root": self.auditor_committee_root,
            "proof_system": self.proof_system,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn attestation_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-SOLVENCY-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = solvency_attestation_id(
            &self.vault_id,
            &self.reserve_root,
            &self.liability_root,
            &self.oracle_band_root,
            self.attested_at_height,
        );
        if self.attestation_id != computed_id {
            return Err("solvency attestation id mismatch".to_string());
        }
        ensure_non_empty(
            &self.strategy_exposure_root,
            "solvency attestation strategy exposure root",
        )?;
        ensure_non_empty(
            &self.auditor_committee_root,
            "solvency attestation auditor root",
        )?;
        ensure_non_empty(&self.proof_system, "solvency attestation proof system")?;
        ensure_non_empty(&self.metadata_root, "solvency attestation metadata root")?;
        ensure_bps(
            self.strategy_exposure_bps,
            "solvency attestation strategy exposure bps",
        )?;
        let computed_coverage = ratio_bps(
            self.total_assets_floor_units,
            self.total_liabilities_ceiling_units.max(1),
        );
        if self.reserve_coverage_bps != computed_coverage {
            return Err("solvency attestation coverage mismatch".to_string());
        }
        ensure_ordered_heights(
            self.attested_at_height,
            self.challenge_window_end_height,
            "solvency challenge window",
        )?;
        ensure_ordered_heights(
            self.attested_at_height,
            self.expires_at_height,
            "solvency attestation validity",
        )?;
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeVaultSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub vault_id: String,
    pub intent_or_withdrawal_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub applied_fee_units: u64,
    pub max_fee_units: u64,
    pub small_amount_limit_units: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: VaultSponsorshipStatus,
    pub policy_root: String,
    pub nonce: u64,
}

impl LowFeeVaultSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        beneficiary_commitment: &str,
        vault_id: &str,
        intent_or_withdrawal_id: &str,
        lane_id: &str,
        fee_asset_id: &str,
        reserved_fee_units: u64,
        max_fee_units: u64,
        small_amount_limit_units: u64,
        policy: &Value,
        valid_from_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(sponsor_commitment, "vault sponsorship sponsor")?;
        ensure_non_empty(beneficiary_commitment, "vault sponsorship beneficiary")?;
        ensure_non_empty(vault_id, "vault sponsorship vault id")?;
        ensure_non_empty(intent_or_withdrawal_id, "vault sponsorship target id")?;
        ensure_non_empty(lane_id, "vault sponsorship lane id")?;
        ensure_non_empty(fee_asset_id, "vault sponsorship fee asset")?;
        ensure_positive(max_fee_units, "vault sponsorship max fee")?;
        if reserved_fee_units > max_fee_units {
            return Err("vault sponsorship reserved fee exceeds max".to_string());
        }
        ensure_ordered_heights(
            valid_from_height,
            expires_at_height,
            "vault sponsorship validity",
        )?;
        let policy_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-SPONSORSHIP-POLICY", policy);
        let sponsorship_id = vault_sponsorship_id(
            sponsor_commitment,
            beneficiary_commitment,
            vault_id,
            intent_or_withdrawal_id,
            nonce,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            vault_id: vault_id.to_string(),
            intent_or_withdrawal_id: intent_or_withdrawal_id.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            reserved_fee_units,
            applied_fee_units: 0,
            max_fee_units,
            small_amount_limit_units,
            valid_from_height,
            expires_at_height,
            status: VaultSponsorshipStatus::Reserved,
            policy_root,
            nonce,
        })
    }

    pub fn remaining_units(&self) -> u64 {
        self.reserved_fee_units
            .saturating_sub(self.applied_fee_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && self.valid_from_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_vault_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "vault_id": self.vault_id,
            "intent_or_withdrawal_id": self.intent_or_withdrawal_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "applied_fee_units": self.applied_fee_units,
            "remaining_units": self.remaining_units(),
            "max_fee_units": self.max_fee_units,
            "small_amount_limit_units": self.small_amount_limit_units,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
            "nonce": self.nonce,
            "sponsorship_scheme": PRIVATE_LIQUIDITY_VAULT_LOW_FEE_SPONSORSHIP_SCHEME,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-LOW-FEE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = vault_sponsorship_id(
            &self.sponsor_commitment,
            &self.beneficiary_commitment,
            &self.vault_id,
            &self.intent_or_withdrawal_id,
            self.nonce,
        );
        if self.sponsorship_id != computed_id {
            return Err("vault sponsorship id mismatch".to_string());
        }
        ensure_non_empty(&self.lane_id, "vault sponsorship lane id")?;
        ensure_non_empty(&self.fee_asset_id, "vault sponsorship fee asset")?;
        ensure_non_empty(&self.policy_root, "vault sponsorship policy root")?;
        ensure_positive(self.max_fee_units, "vault sponsorship max fee")?;
        if self.reserved_fee_units > self.max_fee_units {
            return Err("vault sponsorship reserved fee exceeds max".to_string());
        }
        if self.applied_fee_units > self.reserved_fee_units {
            return Err("vault sponsorship applied fee exceeds reserve".to_string());
        }
        ensure_ordered_heights(
            self.valid_from_height,
            self.expires_at_height,
            "vault sponsorship validity",
        )?;
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRiskLimit {
    pub limit_id: String,
    pub vault_id: String,
    pub scope: RiskLimitScope,
    pub target_id: String,
    pub metric: String,
    pub soft_limit_bps: u64,
    pub hard_limit_bps: u64,
    pub observed_bps: u64,
    pub enforced_cap_units: u64,
    pub action: RiskLimitAction,
    pub severity: RiskLimitSeverity,
    pub status: RiskLimitStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub evidence_root: String,
}

impl VaultRiskLimit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        scope: RiskLimitScope,
        target_id: &str,
        metric: &str,
        soft_limit_bps: u64,
        hard_limit_bps: u64,
        observed_bps: u64,
        enforced_cap_units: u64,
        action: RiskLimitAction,
        severity: RiskLimitSeverity,
        evidence: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "risk limit vault id")?;
        ensure_non_empty(target_id, "risk limit target id")?;
        ensure_non_empty(metric, "risk limit metric")?;
        ensure_bps(soft_limit_bps, "risk limit soft limit bps")?;
        ensure_bps(hard_limit_bps, "risk limit hard limit bps")?;
        if soft_limit_bps > hard_limit_bps {
            return Err("risk limit soft limit exceeds hard limit".to_string());
        }
        ensure_ordered_heights(opened_at_height, expires_at_height, "risk limit validity")?;
        let evidence_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-RISK-EVIDENCE", evidence);
        let status = if observed_bps >= hard_limit_bps {
            RiskLimitStatus::Breached
        } else if observed_bps >= soft_limit_bps {
            RiskLimitStatus::Warning
        } else {
            RiskLimitStatus::Monitoring
        };
        let limit_id = risk_limit_id(vault_id, &scope, target_id, metric, &evidence_root);
        Ok(Self {
            limit_id,
            vault_id: vault_id.to_string(),
            scope,
            target_id: target_id.to_string(),
            metric: metric.to_string(),
            soft_limit_bps,
            hard_limit_bps,
            observed_bps,
            enforced_cap_units,
            action,
            severity,
            status,
            opened_at_height,
            expires_at_height,
            evidence_root,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && self.opened_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn effective_risk_score_bps(&self) -> u64 {
        self.observed_bps.max(self.severity.score_bps())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_risk_limit",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "limit_id": self.limit_id,
            "vault_id": self.vault_id,
            "scope": self.scope.as_str(),
            "target_id": self.target_id,
            "metric": self.metric,
            "soft_limit_bps": self.soft_limit_bps,
            "hard_limit_bps": self.hard_limit_bps,
            "observed_bps": self.observed_bps,
            "effective_risk_score_bps": self.effective_risk_score_bps(),
            "enforced_cap_units": self.enforced_cap_units,
            "action": self.action.as_str(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn limit_root(&self) -> String {
        private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-RISK-LIMIT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = risk_limit_id(
            &self.vault_id,
            &self.scope,
            &self.target_id,
            &self.metric,
            &self.evidence_root,
        );
        if self.limit_id != computed_id {
            return Err("risk limit id mismatch".to_string());
        }
        ensure_bps(self.soft_limit_bps, "risk limit soft limit bps")?;
        ensure_bps(self.hard_limit_bps, "risk limit hard limit bps")?;
        if self.soft_limit_bps > self.hard_limit_bps {
            return Err("risk limit soft limit exceeds hard limit".to_string());
        }
        ensure_non_empty(&self.evidence_root, "risk limit evidence root")?;
        ensure_ordered_heights(
            self.opened_at_height,
            self.expires_at_height,
            "risk limit validity",
        )?;
        Ok(self.limit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePriceBand {
    pub band_id: String,
    pub vault_id: String,
    pub feed_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub lower_price: u64,
    pub reference_price: u64,
    pub upper_price: u64,
    pub max_deviation_bps: u64,
    pub source_root: String,
    pub signer_set_root: String,
    pub pq_signature_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: OracleBandStatus,
}

impl OraclePriceBand {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        feed_id: &str,
        base_asset_id: &str,
        quote_asset_id: &str,
        lower_price: u64,
        reference_price: u64,
        upper_price: u64,
        max_deviation_bps: u64,
        sources: &[Value],
        signer_set_root: &str,
        pq_signature_root: &str,
        observed_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "oracle band vault id")?;
        ensure_non_empty(feed_id, "oracle band feed id")?;
        ensure_non_empty(base_asset_id, "oracle band base asset")?;
        ensure_non_empty(quote_asset_id, "oracle band quote asset")?;
        ensure_positive(lower_price, "oracle band lower price")?;
        ensure_positive(reference_price, "oracle band reference price")?;
        ensure_positive(upper_price, "oracle band upper price")?;
        ensure_bps(max_deviation_bps, "oracle band max deviation bps")?;
        ensure_non_empty(signer_set_root, "oracle band signer set root")?;
        ensure_non_empty(pq_signature_root, "oracle band pq signature root")?;
        if lower_price > reference_price || reference_price > upper_price {
            return Err("oracle band prices are not ordered".to_string());
        }
        ensure_ordered_heights(
            observed_at_height,
            expires_at_height,
            "oracle band validity",
        )?;
        let source_root = merkle_root("PRIVATE-LIQUIDITY-ORACLE-SOURCES", sources);
        let band_id = oracle_band_id(
            vault_id,
            feed_id,
            base_asset_id,
            quote_asset_id,
            reference_price,
            observed_at_height,
        );
        Ok(Self {
            band_id,
            vault_id: vault_id.to_string(),
            feed_id: feed_id.to_string(),
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            lower_price,
            reference_price,
            upper_price,
            max_deviation_bps,
            source_root,
            signer_set_root: signer_set_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            observed_at_height,
            expires_at_height,
            status: OracleBandStatus::Fresh,
        })
    }

    pub fn contains_price(&self, price: u64) -> bool {
        self.lower_price <= price && price <= self.upper_price
    }

    pub fn is_fresh_at(&self, height: u64) -> bool {
        self.status.allows_pricing()
            && self.observed_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_oracle_price_band",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "band_id": self.band_id,
            "vault_id": self.vault_id,
            "feed_id": self.feed_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "lower_price": self.lower_price,
            "reference_price": self.reference_price,
            "upper_price": self.upper_price,
            "max_deviation_bps": self.max_deviation_bps,
            "source_root": self.source_root,
            "signer_set_root": self.signer_set_root,
            "pq_signature_root": self.pq_signature_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "oracle_band_scheme": PRIVATE_LIQUIDITY_VAULT_ORACLE_BAND_SCHEME,
        })
    }

    pub fn band_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-ORACLE-PRICE-BAND",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = oracle_band_id(
            &self.vault_id,
            &self.feed_id,
            &self.base_asset_id,
            &self.quote_asset_id,
            self.reference_price,
            self.observed_at_height,
        );
        if self.band_id != computed_id {
            return Err("oracle band id mismatch".to_string());
        }
        ensure_bps(self.max_deviation_bps, "oracle band max deviation bps")?;
        ensure_non_empty(&self.source_root, "oracle band source root")?;
        ensure_non_empty(&self.signer_set_root, "oracle band signer set root")?;
        ensure_non_empty(&self.pq_signature_root, "oracle band pq signature root")?;
        if self.lower_price > self.reference_price || self.reference_price > self.upper_price {
            return Err("oracle band prices are not ordered".to_string());
        }
        let lower_deviation = price_deviation_bps(self.reference_price, self.lower_price);
        let upper_deviation = price_deviation_bps(self.reference_price, self.upper_price);
        if lower_deviation > self.max_deviation_bps || upper_deviation > self.max_deviation_bps {
            return Err("oracle band exceeds max deviation".to_string());
        }
        ensure_ordered_heights(
            self.observed_at_height,
            self.expires_at_height,
            "oracle band validity",
        )?;
        Ok(self.band_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCustodianApproval {
    pub approval_id: String,
    pub vault_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub custodian_set_root: String,
    pub approver_commitments: Vec<String>,
    pub decision: PqApprovalDecision,
    pub threshold: u64,
    pub signature_root: String,
    pub transcript_root: String,
    pub risk_score_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl PqCustodianApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        target_kind: &str,
        target_id: &str,
        custodian_set_root: &str,
        approver_commitments: &[String],
        decision: PqApprovalDecision,
        threshold: u64,
        signature: &Value,
        transcript: &Value,
        risk_score_bps: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "pq approval vault id")?;
        ensure_non_empty(target_kind, "pq approval target kind")?;
        ensure_non_empty(target_id, "pq approval target id")?;
        ensure_non_empty(custodian_set_root, "pq approval custodian set root")?;
        ensure_positive(threshold, "pq approval threshold")?;
        ensure_bps(risk_score_bps, "pq approval risk score")?;
        ensure_ordered_heights(issued_at_height, expires_at_height, "pq approval validity")?;
        let approver_commitments = sorted_non_empty_strings(approver_commitments);
        if approver_commitments.len() < threshold as usize {
            return Err("pq approval threshold exceeds approver count".to_string());
        }
        let signature_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-PQ-SIGNATURE", signature);
        let transcript_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-PQ-TRANSCRIPT", transcript);
        let metadata_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-PQ-METADATA", metadata);
        let approval_id = pq_approval_id(
            vault_id,
            target_kind,
            target_id,
            custodian_set_root,
            &transcript_root,
            issued_at_height,
        );
        Ok(Self {
            approval_id,
            vault_id: vault_id.to_string(),
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            custodian_set_root: custodian_set_root.to_string(),
            approver_commitments,
            decision,
            threshold,
            signature_root,
            transcript_root,
            risk_score_bps,
            issued_at_height,
            expires_at_height,
            metadata_root,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.decision.allows_execution()
            && self.issued_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn approver_root(&self) -> String {
        private_liquidity_vault_string_set_root(
            "PRIVATE-LIQUIDITY-PQ-APPROVERS",
            &self.approver_commitments,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_custodian_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "vault_id": self.vault_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "custodian_set_root": self.custodian_set_root,
            "approver_root": self.approver_root(),
            "decision": self.decision.as_str(),
            "threshold": self.threshold,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "risk_score_bps": self.risk_score_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
            "pq_approval_scheme": PRIVATE_LIQUIDITY_VAULT_PQ_APPROVAL_SCHEME,
        })
    }

    pub fn approval_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-PQ-CUSTODIAN-APPROVAL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = pq_approval_id(
            &self.vault_id,
            &self.target_kind,
            &self.target_id,
            &self.custodian_set_root,
            &self.transcript_root,
            self.issued_at_height,
        );
        if self.approval_id != computed_id {
            return Err("pq approval id mismatch".to_string());
        }
        ensure_positive(self.threshold, "pq approval threshold")?;
        ensure_bps(self.risk_score_bps, "pq approval risk score")?;
        ensure_non_empty(&self.signature_root, "pq approval signature root")?;
        ensure_non_empty(&self.transcript_root, "pq approval transcript root")?;
        ensure_non_empty(&self.metadata_root, "pq approval metadata root")?;
        let unique = self
            .approver_commitments
            .iter()
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>();
        if unique.len() != self.approver_commitments.len() {
            return Err("pq approval approvers are empty or duplicated".to_string());
        }
        if self.approver_commitments.len() < self.threshold as usize {
            return Err("pq approval threshold exceeds approver count".to_string());
        }
        ensure_ordered_heights(
            self.issued_at_height,
            self.expires_at_height,
            "pq approval validity",
        )?;
        Ok(self.approval_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyUnwindPlan {
    pub plan_id: String,
    pub vault_id: String,
    pub trigger_root: String,
    pub affected_bucket_root: String,
    pub unwind_route_root: String,
    pub oracle_band_root: String,
    pub custodian_approval_root: String,
    pub withdrawal_queue_root: String,
    pub target_reserve_floor_units: u64,
    pub max_loss_bps: u64,
    pub max_duration_blocks: u64,
    pub status: EmergencyUnwindStatus,
    pub armed_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl EmergencyUnwindPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: &str,
        trigger: &Value,
        affected_bucket_ids: &[String],
        unwind_route: &Value,
        oracle_band_root: &str,
        custodian_approval_root: &str,
        withdrawal_queue_root: &str,
        target_reserve_floor_units: u64,
        max_loss_bps: u64,
        max_duration_blocks: u64,
        armed_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(vault_id, "emergency unwind vault id")?;
        ensure_non_empty(oracle_band_root, "emergency unwind oracle band root")?;
        ensure_non_empty(
            custodian_approval_root,
            "emergency unwind custodian approval root",
        )?;
        ensure_non_empty(
            withdrawal_queue_root,
            "emergency unwind withdrawal queue root",
        )?;
        ensure_positive(
            target_reserve_floor_units,
            "emergency unwind target reserve floor",
        )?;
        ensure_bps(max_loss_bps, "emergency unwind max loss bps")?;
        ensure_positive(max_duration_blocks, "emergency unwind duration")?;
        ensure_ordered_heights(
            armed_at_height,
            expires_at_height,
            "emergency unwind validity",
        )?;
        let trigger_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-UNWIND-TRIGGER", trigger);
        let affected_bucket_root = private_liquidity_vault_string_set_root(
            "PRIVATE-LIQUIDITY-UNWIND-BUCKETS",
            affected_bucket_ids,
        );
        let unwind_route_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-UNWIND-ROUTE", unwind_route);
        let metadata_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-UNWIND-METADATA", metadata);
        let plan_id = emergency_unwind_plan_id(
            vault_id,
            &trigger_root,
            &affected_bucket_root,
            custodian_approval_root,
            armed_at_height,
        );
        Ok(Self {
            plan_id,
            vault_id: vault_id.to_string(),
            trigger_root,
            affected_bucket_root,
            unwind_route_root,
            oracle_band_root: oracle_band_root.to_string(),
            custodian_approval_root: custodian_approval_root.to_string(),
            withdrawal_queue_root: withdrawal_queue_root.to_string(),
            target_reserve_floor_units,
            max_loss_bps,
            max_duration_blocks,
            status: EmergencyUnwindStatus::Planned,
            armed_at_height,
            expires_at_height,
            metadata_root,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && self.armed_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_emergency_unwind_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "vault_id": self.vault_id,
            "trigger_root": self.trigger_root,
            "affected_bucket_root": self.affected_bucket_root,
            "unwind_route_root": self.unwind_route_root,
            "oracle_band_root": self.oracle_band_root,
            "custodian_approval_root": self.custodian_approval_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "target_reserve_floor_units": self.target_reserve_floor_units,
            "max_loss_bps": self.max_loss_bps,
            "max_duration_blocks": self.max_duration_blocks,
            "status": self.status.as_str(),
            "armed_at_height": self.armed_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
            "emergency_unwind_scheme": PRIVATE_LIQUIDITY_VAULT_EMERGENCY_UNWIND_SCHEME,
        })
    }

    pub fn plan_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-EMERGENCY-UNWIND-PLAN",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = emergency_unwind_plan_id(
            &self.vault_id,
            &self.trigger_root,
            &self.affected_bucket_root,
            &self.custodian_approval_root,
            self.armed_at_height,
        );
        if self.plan_id != computed_id {
            return Err("emergency unwind plan id mismatch".to_string());
        }
        ensure_non_empty(&self.unwind_route_root, "emergency unwind route root")?;
        ensure_non_empty(&self.oracle_band_root, "emergency unwind oracle band root")?;
        ensure_non_empty(
            &self.custodian_approval_root,
            "emergency unwind custodian approval root",
        )?;
        ensure_non_empty(
            &self.withdrawal_queue_root,
            "emergency unwind withdrawal queue root",
        )?;
        ensure_positive(
            self.target_reserve_floor_units,
            "emergency unwind target reserve floor",
        )?;
        ensure_bps(self.max_loss_bps, "emergency unwind max loss bps")?;
        ensure_positive(self.max_duration_blocks, "emergency unwind duration")?;
        ensure_ordered_heights(
            self.armed_at_height,
            self.expires_at_height,
            "emergency unwind validity",
        )?;
        Ok(self.plan_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityVaultPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub record_type: String,
    pub payload_root: String,
    pub publisher_commitment: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl PrivateLiquidityVaultPublicRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        record_type: &str,
        payload: &Value,
        publisher_commitment: &str,
        published_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateLiquidityVaultResult<Self> {
        ensure_non_empty(subject_kind, "public record subject kind")?;
        ensure_non_empty(subject_id, "public record subject id")?;
        ensure_non_empty(record_type, "public record type")?;
        ensure_non_empty(publisher_commitment, "public record publisher")?;
        ensure_ordered_heights(
            published_at_height,
            expires_at_height,
            "public record validity",
        )?;
        let payload_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-PUBLIC-PAYLOAD", payload);
        let metadata_root =
            private_liquidity_vault_payload_root("PRIVATE-LIQUIDITY-PUBLIC-METADATA", metadata);
        let record_id = public_record_id(
            subject_kind,
            subject_id,
            record_type,
            &payload_root,
            published_at_height,
        );
        Ok(Self {
            record_id,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            record_type: record_type.to_string(),
            payload_root,
            publisher_commitment: publisher_commitment.to_string(),
            published_at_height,
            expires_at_height,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_vault_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "record_type": self.record_type,
            "payload_root": self.payload_root,
            "publisher_commitment": self.publisher_commitment,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn record_root(&self) -> String {
        private_liquidity_vault_payload_root(
            "PRIVATE-LIQUIDITY-PUBLIC-RECORD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        let computed_id = public_record_id(
            &self.subject_kind,
            &self.subject_id,
            &self.record_type,
            &self.payload_root,
            self.published_at_height,
        );
        if self.record_id != computed_id {
            return Err("public record id mismatch".to_string());
        }
        ensure_non_empty(&self.publisher_commitment, "public record publisher")?;
        ensure_non_empty(&self.metadata_root, "public record metadata root")?;
        ensure_ordered_heights(
            self.published_at_height,
            self.expires_at_height,
            "public record validity",
        )?;
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityVaultRoots {
    pub config_root: String,
    pub vault_root: String,
    pub reserve_bucket_root: String,
    pub strategy_mandate_root: String,
    pub rebalance_intent_root: String,
    pub withdrawal_queue_root: String,
    pub solvency_attestation_root: String,
    pub low_fee_sponsorship_root: String,
    pub risk_limit_root: String,
    pub oracle_band_root: String,
    pub pq_approval_root: String,
    pub emergency_unwind_root: String,
    pub public_record_root: String,
}

impl PrivateLiquidityVaultRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_vault_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "reserve_bucket_root": self.reserve_bucket_root,
            "strategy_mandate_root": self.strategy_mandate_root,
            "rebalance_intent_root": self.rebalance_intent_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "solvency_attestation_root": self.solvency_attestation_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "risk_limit_root": self.risk_limit_root,
            "oracle_band_root": self.oracle_band_root,
            "pq_approval_root": self.pq_approval_root,
            "emergency_unwind_root": self.emergency_unwind_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidity_vault_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityVaultCounters {
    pub vault_count: u64,
    pub active_vault_count: u64,
    pub reserve_bucket_count: u64,
    pub live_reserve_bucket_count: u64,
    pub strategy_mandate_count: u64,
    pub active_strategy_mandate_count: u64,
    pub rebalance_intent_count: u64,
    pub live_rebalance_intent_count: u64,
    pub withdrawal_queue_count: u64,
    pub open_withdrawal_queue_count: u64,
    pub solvency_attestation_count: u64,
    pub fresh_solvency_attestation_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub risk_limit_count: u64,
    pub active_risk_limit_count: u64,
    pub oracle_band_count: u64,
    pub fresh_oracle_band_count: u64,
    pub pq_approval_count: u64,
    pub active_pq_approval_count: u64,
    pub emergency_unwind_plan_count: u64,
    pub active_emergency_unwind_plan_count: u64,
    pub public_record_count: u64,
    pub total_assets_floor_units: u64,
    pub total_assets_upper_bound_units: u64,
    pub total_reserve_available_units: u64,
    pub total_withdrawal_ceiling_units: u64,
    pub aggregate_risk_score_bps: u64,
}

impl PrivateLiquidityVaultCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidity_vault_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "vault_count": self.vault_count,
            "active_vault_count": self.active_vault_count,
            "reserve_bucket_count": self.reserve_bucket_count,
            "live_reserve_bucket_count": self.live_reserve_bucket_count,
            "strategy_mandate_count": self.strategy_mandate_count,
            "active_strategy_mandate_count": self.active_strategy_mandate_count,
            "rebalance_intent_count": self.rebalance_intent_count,
            "live_rebalance_intent_count": self.live_rebalance_intent_count,
            "withdrawal_queue_count": self.withdrawal_queue_count,
            "open_withdrawal_queue_count": self.open_withdrawal_queue_count,
            "solvency_attestation_count": self.solvency_attestation_count,
            "fresh_solvency_attestation_count": self.fresh_solvency_attestation_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "risk_limit_count": self.risk_limit_count,
            "active_risk_limit_count": self.active_risk_limit_count,
            "oracle_band_count": self.oracle_band_count,
            "fresh_oracle_band_count": self.fresh_oracle_band_count,
            "pq_approval_count": self.pq_approval_count,
            "active_pq_approval_count": self.active_pq_approval_count,
            "emergency_unwind_plan_count": self.emergency_unwind_plan_count,
            "active_emergency_unwind_plan_count": self.active_emergency_unwind_plan_count,
            "public_record_count": self.public_record_count,
            "total_assets_floor_units": self.total_assets_floor_units,
            "total_assets_upper_bound_units": self.total_assets_upper_bound_units,
            "total_reserve_available_units": self.total_reserve_available_units,
            "total_withdrawal_ceiling_units": self.total_withdrawal_ceiling_units,
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityVaultState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateLiquidityVaultConfig,
    pub vaults: BTreeMap<String, ConfidentialLpVault>,
    pub reserve_buckets: BTreeMap<String, WrappedXmrReserveBucket>,
    pub strategy_mandates: BTreeMap<String, EncryptedStrategyMandate>,
    pub rebalancing_intents: BTreeMap<String, PrivateRebalancingIntent>,
    pub withdrawal_queue: BTreeMap<String, WithdrawalQueueEntry>,
    pub solvency_attestations: BTreeMap<String, SolvencyAttestation>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeVaultSponsorship>,
    pub risk_limits: BTreeMap<String, VaultRiskLimit>,
    pub oracle_bands: BTreeMap<String, OraclePriceBand>,
    pub pq_approvals: BTreeMap<String, PqCustodianApproval>,
    pub emergency_unwind_plans: BTreeMap<String, EmergencyUnwindPlan>,
    pub public_records: BTreeMap<String, PrivateLiquidityVaultPublicRecord>,
}

impl Default for PrivateLiquidityVaultState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateLiquidityVaultState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: PrivateLiquidityVaultConfig::default(),
            vaults: BTreeMap::new(),
            reserve_buckets: BTreeMap::new(),
            strategy_mandates: BTreeMap::new(),
            rebalancing_intents: BTreeMap::new(),
            withdrawal_queue: BTreeMap::new(),
            solvency_attestations: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            risk_limits: BTreeMap::new(),
            oracle_bands: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            emergency_unwind_plans: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(config: PrivateLiquidityVaultConfig) -> PrivateLiquidityVaultResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> PrivateLiquidityVaultResult<Self> {
        let mut state = Self::with_config(PrivateLiquidityVaultConfig::devnet())?;
        state.set_height(PRIVATE_LIQUIDITY_VAULT_DEVNET_HEIGHT);
        let wxmr_asset_id = state.config.wxmr_asset_id.clone();
        let reserve_asset_id = state.config.reserve_asset_id.clone();
        let lp_share_asset_id = state.config.lp_share_asset_id.clone();
        let monero_network = state.config.monero_network.clone();
        let oracle_feed_id = state.config.oracle_feed_id.clone();
        let default_low_fee_lane = state.config.default_low_fee_lane.clone();

        let mut vault = ConfidentialLpVault::new(
            "devnet-private-wxmr-lp-vault",
            "devnet-lp-owner-commitment",
            &lp_share_asset_id,
            &reserve_asset_id,
            &wxmr_asset_id,
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-SHARE-COMMITMENTS",
                "devnet-lp-shares",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-LP-NULLIFIERS",
                "devnet-lp-nullifiers",
            ),
            &json!({
                "mode": "devnet",
                "privacy": "share commitments and bucket-only liquidity"
            }),
            4_000_000_000_000,
            4_250_000_000_000,
            state.config.target_idle_reserve_bps,
            25,
            state.height.saturating_sub(96),
            state.next_nonce(),
        )?;
        vault.status = PrivateLiquidityVaultStatus::Active;
        let vault_id = vault.vault_id.clone();
        state.insert_vault(vault)?;

        let oracle_band = OraclePriceBand::new(
            &vault_id,
            &oracle_feed_id,
            &wxmr_asset_id,
            "usd-devnet",
            PRIVATE_LIQUIDITY_VAULT_DEVNET_WXMR_PRICE
                .saturating_sub(6 * PRIVATE_LIQUIDITY_VAULT_PRICE_SCALE),
            PRIVATE_LIQUIDITY_VAULT_DEVNET_WXMR_PRICE,
            PRIVATE_LIQUIDITY_VAULT_DEVNET_WXMR_PRICE
                .saturating_add(6 * PRIVATE_LIQUIDITY_VAULT_PRICE_SCALE),
            state.config.max_oracle_deviation_bps,
            &[
                json!({"source": "devnet-median-1", "height": state.height.saturating_sub(2)}),
                json!({"source": "devnet-median-2", "height": state.height.saturating_sub(1)}),
                json!({"source": "devnet-median-3", "height": state.height.saturating_sub(1)}),
            ],
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-ORACLE-SIGNERS",
                "3-of-5-devnet-oracle",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-ORACLE-PQ-SIG",
                "oracle-sig-root",
            ),
            state.height.saturating_sub(1),
            state
                .height
                .saturating_add(state.config.max_oracle_staleness_blocks),
        )?;
        let oracle_band_id = oracle_band.band_id.clone();
        let oracle_band_root = oracle_band.band_root();
        state.insert_oracle_band(oracle_band)?;

        let hot_bucket = WrappedXmrReserveBucket::new(
            &vault_id,
            ReserveBucketKind::Hot,
            &wxmr_asset_id,
            &monero_network,
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-HOT-RESERVES",
                "hot-reserve-addresses",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-HOT-PROOF-KEYS",
                "hot-proof-keys",
            ),
            800_000_000_000,
            250_000_000_000,
            1_000_000_000_000,
            50_000_000_000,
            10,
            100,
            state.height.saturating_sub(4),
            &json!({"purpose": "fast private withdrawals and small LP exits"}),
        )?;
        let hot_bucket_id = hot_bucket.bucket_id.clone();
        state.insert_reserve_bucket(hot_bucket)?;

        let strategy_bucket = WrappedXmrReserveBucket::new(
            &vault_id,
            ReserveBucketKind::Strategy,
            &wxmr_asset_id,
            &monero_network,
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-STRATEGY-RESERVES",
                "strategy-reserve-addresses",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-STRATEGY-PROOF-KEYS",
                "strategy-proof-keys",
            ),
            3_200_000_000_000,
            1_500_000_000_000,
            3_500_000_000_000,
            100_000_000_000,
            20,
            60,
            state.height.saturating_sub(4),
            &json!({"purpose": "encrypted mandate execution inventory"}),
        )?;
        let strategy_bucket_id = strategy_bucket.bucket_id.clone();
        state.insert_reserve_bucket(strategy_bucket)?;

        let mandate = EncryptedStrategyMandate::new(
            &vault_id,
            "devnet-delta-neutral-strategy-commitment",
            "delta_neutral_wxmr_usd",
            StrategyRiskTier::Balanced,
            &json!({
                "ciphertext_root_hint": "devnet-mandate-ciphertext",
                "kem": PRIVATE_LIQUIDITY_VAULT_MANDATE_ENCRYPTION_SCHEME
            }),
            &[wxmr_asset_id.clone(), reserve_asset_id.clone()],
            &[
                "private-dex-devnet".to_string(),
                "intent-settlement-devnet".to_string(),
            ],
            &json!({
                "max_drawdown_bps": 450,
                "oracle_bound": true,
                "withdrawal_liquidity_floor": "hot_bucket_floor"
            }),
            "devnet-strategy-fee-recipient",
            6_000,
            120,
            12,
            state.height.saturating_sub(64),
            state.height.saturating_add(21_600),
            state.next_nonce(),
        )?;
        let mandate_id = mandate.mandate_id.clone();
        let mandate_root = mandate.mandate_root();
        state.insert_strategy_mandate(mandate)?;
        state.refresh_vault_roots(&vault_id)?;

        let approval = PqCustodianApproval::new(
            &vault_id,
            "strategy_mandate",
            &mandate_id,
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-CUSTODIAN-SET",
                "devnet-custodian-set",
            ),
            &[
                "ml-dsa-custodian-1".to_string(),
                "ml-dsa-custodian-2".to_string(),
                "slh-dsa-custodian-3".to_string(),
            ],
            PqApprovalDecision::Approve,
            state.config.pq_approval_threshold,
            &json!({"aggregate_signature_root": "devnet-pq-vault-approval-sig"}),
            &json!({"target_mandate_root": mandate_root, "oracle_band_id": oracle_band_id}),
            2_500,
            state.height.saturating_sub(8),
            state.height.saturating_add(7_200),
            &json!({"purpose": "approve initial private strategy mandate"}),
        )?;
        let approval_root = approval.approval_root();
        state.insert_pq_approval(approval)?;

        let risk_limit = VaultRiskLimit::new(
            &vault_id,
            RiskLimitScope::Mandate,
            &mandate_id,
            "strategy_exposure_bps",
            6_000,
            state.config.max_strategy_exposure_bps,
            4_200,
            3_500_000_000_000,
            RiskLimitAction::RebalanceOnly,
            RiskLimitSeverity::Watch,
            &json!({
                "mandate_id": mandate_id,
                "proof": "bucketed strategy exposure below cap"
            }),
            state.height.saturating_sub(4),
            state.height.saturating_add(1_440),
        )?;
        state.insert_risk_limit(risk_limit)?;
        state.refresh_vault_roots(&vault_id)?;

        let intent = PrivateRebalancingIntent::new(
            &vault_id,
            &mandate_id,
            &hot_bucket_id,
            &strategy_bucket_id,
            &json!({
                "action": "move_idle_wxmr_to_delta_neutral_strategy",
                "privacy": "encrypted amount and route"
            }),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-INTENT-INPUT",
                "intent-input",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-INTENT-OUTPUT",
                "intent-output",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-INTENT-NULLIFIER",
                "intent-nullifier",
            ),
            &oracle_band_id,
            95,
            LiquidityAmountBucket::Medium,
            40_000,
            80,
            state.height.saturating_sub(2),
            state.config.rebalance_intent_ttl_blocks,
            state.next_nonce(),
        )?;
        let intent_id = intent.intent_id.clone();
        state.insert_rebalancing_intent(intent)?;

        let withdrawal = WithdrawalQueueEntry::new(
            &vault_id,
            &hot_bucket_id,
            "devnet-lp-alice-owner-commitment",
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-WITHDRAWAL-NULLIFIER",
                "alice-share-nullifier",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-WITHDRAWAL-RECIPIENT",
                "alice-monero-recipient",
            ),
            LiquidityAmountBucket::Small,
            5_000_000,
            20_000_000,
            25_000,
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-WITHDRAWAL-RESERVE-PROOF",
                "withdrawal-reserve-proof",
            ),
            state.height.saturating_sub(1),
            state
                .height
                .saturating_add(state.config.withdrawal_cooldown_blocks),
            state.height.saturating_add(360),
            1,
            state.next_nonce(),
        )?;
        let withdrawal_id = withdrawal.withdrawal_id.clone();
        state.insert_withdrawal(withdrawal)?;

        let sponsorship = LowFeeVaultSponsorship::new(
            "devnet-foundation-paymaster",
            "devnet-lp-alice-owner-commitment",
            &vault_id,
            &withdrawal_id,
            &default_low_fee_lane,
            &reserve_asset_id,
            75_000,
            state.config.sponsored_max_fee_units,
            state.config.sponsored_small_withdrawal_limit_units,
            &json!({
                "target": "small_private_lp_withdrawals",
                "amount_bucket": LiquidityAmountBucket::Small.as_str()
            }),
            state.height,
            state.height.saturating_add(360),
            state.next_nonce(),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_low_fee_sponsorship(sponsorship)?;
        if let Some(withdrawal) = state.withdrawal_queue.get_mut(&withdrawal_id) {
            withdrawal.sponsor_id = sponsorship_id;
        }

        let solvency = SolvencyAttestation::new(
            &vault_id,
            &state.reserve_bucket_root(),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-LIABILITY-ROOT",
                "devnet-liabilities",
            ),
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-STRATEGY-EXPOSURE",
                "devnet-strategy-exposure",
            ),
            &oracle_band_root,
            4_000_000_000_000,
            3_600_000_000_000,
            4_200,
            &private_liquidity_vault_string_root(
                "PRIVATE-LIQUIDITY-DEVNET-SOLVENCY-AUDITORS",
                "2-of-3-devnet-auditors",
            ),
            state.height,
            state.config.solvency_attestation_ttl_blocks,
            state.config.challenge_window_blocks,
            &json!({"coverage": "floor-assets-above-liability-ceiling"}),
        )?;
        state.insert_solvency_attestation(solvency)?;

        let unwind = EmergencyUnwindPlan::new(
            &vault_id,
            &json!({"trigger": "oracle_frozen_or_reserve_proof_disputed"}),
            &[hot_bucket_id.clone(), strategy_bucket_id.clone()],
            &json!({
                "steps": [
                    "pause deposits",
                    "route strategy inventory to hot bucket",
                    "serve withdrawal queue by queue_position"
                ]
            }),
            &oracle_band_root,
            &approval_root,
            &state.withdrawal_queue_root(),
            1_000_000_000_000,
            350,
            72,
            state.height,
            state
                .height
                .saturating_add(state.config.unwind_plan_ttl_blocks),
            &json!({"mode": "devnet dry run"}),
        )?;
        state.insert_emergency_unwind_plan(unwind)?;

        let public_record = state.public_record_without_root();
        state.publish_public_record(
            "private_liquidity_vault_state",
            &vault_id,
            "devnet_bootstrap",
            &public_record,
            "devnet-vault-operator",
            state.height,
            state.height.saturating_add(7_200),
            &json!({"source": "devnet bootstrap"}),
        )?;

        if let Some(intent) = state.rebalancing_intents.get_mut(&intent_id) {
            intent.status = RebalanceIntentStatus::Sponsored;
        }
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_vault(
        &mut self,
        vault: ConfidentialLpVault,
    ) -> PrivateLiquidityVaultResult<ConfidentialLpVault> {
        vault.validate()?;
        self.vaults.insert(vault.vault_id.clone(), vault.clone());
        Ok(vault)
    }

    pub fn insert_reserve_bucket(
        &mut self,
        bucket: WrappedXmrReserveBucket,
    ) -> PrivateLiquidityVaultResult<WrappedXmrReserveBucket> {
        bucket.validate()?;
        ensure_state_vault(&self.vaults, &bucket.vault_id, "reserve bucket")?;
        self.reserve_buckets
            .insert(bucket.bucket_id.clone(), bucket.clone());
        Ok(bucket)
    }

    pub fn insert_strategy_mandate(
        &mut self,
        mandate: EncryptedStrategyMandate,
    ) -> PrivateLiquidityVaultResult<EncryptedStrategyMandate> {
        mandate.validate()?;
        ensure_state_vault(&self.vaults, &mandate.vault_id, "strategy mandate")?;
        self.strategy_mandates
            .insert(mandate.mandate_id.clone(), mandate.clone());
        Ok(mandate)
    }

    pub fn insert_rebalancing_intent(
        &mut self,
        intent: PrivateRebalancingIntent,
    ) -> PrivateLiquidityVaultResult<PrivateRebalancingIntent> {
        intent.validate()?;
        ensure_state_vault(&self.vaults, &intent.vault_id, "rebalance intent")?;
        ensure_state_mandate(&self.strategy_mandates, &intent.mandate_id)?;
        ensure_state_bucket(
            &self.reserve_buckets,
            &intent.source_bucket_id,
            "rebalance source",
        )?;
        ensure_state_bucket(
            &self.reserve_buckets,
            &intent.target_bucket_id,
            "rebalance target",
        )?;
        ensure_state_oracle_band(&self.oracle_bands, &intent.oracle_band_id)?;
        self.rebalancing_intents
            .insert(intent.intent_id.clone(), intent.clone());
        Ok(intent)
    }

    pub fn insert_withdrawal(
        &mut self,
        withdrawal: WithdrawalQueueEntry,
    ) -> PrivateLiquidityVaultResult<WithdrawalQueueEntry> {
        withdrawal.validate()?;
        ensure_state_vault(&self.vaults, &withdrawal.vault_id, "withdrawal")?;
        ensure_state_bucket(&self.reserve_buckets, &withdrawal.bucket_id, "withdrawal")?;
        self.withdrawal_queue
            .insert(withdrawal.withdrawal_id.clone(), withdrawal.clone());
        Ok(withdrawal)
    }

    pub fn insert_solvency_attestation(
        &mut self,
        attestation: SolvencyAttestation,
    ) -> PrivateLiquidityVaultResult<SolvencyAttestation> {
        attestation.validate()?;
        ensure_state_vault(&self.vaults, &attestation.vault_id, "solvency attestation")?;
        self.solvency_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeVaultSponsorship,
    ) -> PrivateLiquidityVaultResult<LowFeeVaultSponsorship> {
        sponsorship.validate()?;
        ensure_state_vault(&self.vaults, &sponsorship.vault_id, "sponsorship")?;
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn insert_risk_limit(
        &mut self,
        limit: VaultRiskLimit,
    ) -> PrivateLiquidityVaultResult<VaultRiskLimit> {
        limit.validate()?;
        ensure_state_vault(&self.vaults, &limit.vault_id, "risk limit")?;
        self.risk_limits
            .insert(limit.limit_id.clone(), limit.clone());
        Ok(limit)
    }

    pub fn insert_oracle_band(
        &mut self,
        band: OraclePriceBand,
    ) -> PrivateLiquidityVaultResult<OraclePriceBand> {
        band.validate()?;
        ensure_state_vault(&self.vaults, &band.vault_id, "oracle band")?;
        self.oracle_bands.insert(band.band_id.clone(), band.clone());
        Ok(band)
    }

    pub fn insert_pq_approval(
        &mut self,
        approval: PqCustodianApproval,
    ) -> PrivateLiquidityVaultResult<PqCustodianApproval> {
        approval.validate()?;
        ensure_state_vault(&self.vaults, &approval.vault_id, "pq approval")?;
        self.pq_approvals
            .insert(approval.approval_id.clone(), approval.clone());
        Ok(approval)
    }

    pub fn insert_emergency_unwind_plan(
        &mut self,
        plan: EmergencyUnwindPlan,
    ) -> PrivateLiquidityVaultResult<EmergencyUnwindPlan> {
        plan.validate()?;
        ensure_state_vault(&self.vaults, &plan.vault_id, "emergency unwind")?;
        self.emergency_unwind_plans
            .insert(plan.plan_id.clone(), plan.clone());
        Ok(plan)
    }

    pub fn insert_public_record(
        &mut self,
        record: PrivateLiquidityVaultPublicRecord,
    ) -> PrivateLiquidityVaultResult<PrivateLiquidityVaultPublicRecord> {
        record.validate()?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn publish_public_record(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        record_type: &str,
        payload: &Value,
        publisher_commitment: &str,
        published_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateLiquidityVaultResult<PrivateLiquidityVaultPublicRecord> {
        let record = PrivateLiquidityVaultPublicRecord::new(
            subject_kind,
            subject_id,
            record_type,
            payload,
            publisher_commitment,
            published_at_height,
            expires_at_height,
            metadata,
        )?;
        self.insert_public_record(record)
    }

    pub fn refresh_vault_roots(&mut self, vault_id: &str) -> PrivateLiquidityVaultResult<()> {
        let mandate_root = private_liquidity_vault_strategy_mandate_root(
            &self
                .strategy_mandates
                .values()
                .filter(|mandate| mandate.vault_id == vault_id)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let risk_limit_root = private_liquidity_vault_risk_limit_root(
            &self
                .risk_limits
                .values()
                .filter(|limit| limit.vault_id == vault_id)
                .cloned()
                .collect::<Vec<_>>(),
        );
        match self.vaults.get_mut(vault_id) {
            Some(vault) => {
                vault.mandate_root = mandate_root;
                vault.risk_limit_root = risk_limit_root;
                vault.updated_at_height = self.height;
                Ok(())
            }
            None => Err("cannot refresh missing vault roots".to_string()),
        }
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn vault_root(&self) -> String {
        private_liquidity_vault_vault_root(&self.vaults.values().cloned().collect::<Vec<_>>())
    }

    pub fn reserve_bucket_root(&self) -> String {
        private_liquidity_vault_reserve_bucket_root(
            &self.reserve_buckets.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn strategy_mandate_root(&self) -> String {
        private_liquidity_vault_strategy_mandate_root(
            &self.strategy_mandates.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn rebalance_intent_root(&self) -> String {
        private_liquidity_vault_rebalance_intent_root(
            &self
                .rebalancing_intents
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn withdrawal_queue_root(&self) -> String {
        private_liquidity_vault_withdrawal_root(
            &self.withdrawal_queue.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn solvency_attestation_root(&self) -> String {
        private_liquidity_vault_solvency_root(
            &self
                .solvency_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        private_liquidity_vault_sponsorship_root(
            &self
                .low_fee_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn risk_limit_root(&self) -> String {
        private_liquidity_vault_risk_limit_root(
            &self.risk_limits.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn oracle_band_root(&self) -> String {
        private_liquidity_vault_oracle_band_root(
            &self.oracle_bands.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn pq_approval_root(&self) -> String {
        private_liquidity_vault_pq_approval_root(
            &self.pq_approvals.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn emergency_unwind_root(&self) -> String {
        private_liquidity_vault_unwind_root(
            &self
                .emergency_unwind_plans
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        private_liquidity_vault_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> PrivateLiquidityVaultRoots {
        PrivateLiquidityVaultRoots {
            config_root: self.config_root(),
            vault_root: self.vault_root(),
            reserve_bucket_root: self.reserve_bucket_root(),
            strategy_mandate_root: self.strategy_mandate_root(),
            rebalance_intent_root: self.rebalance_intent_root(),
            withdrawal_queue_root: self.withdrawal_queue_root(),
            solvency_attestation_root: self.solvency_attestation_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            risk_limit_root: self.risk_limit_root(),
            oracle_band_root: self.oracle_band_root(),
            pq_approval_root: self.pq_approval_root(),
            emergency_unwind_root: self.emergency_unwind_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn state_roots(&self) -> PrivateLiquidityVaultRoots {
        self.roots()
    }

    pub fn counters(&self) -> PrivateLiquidityVaultCounters {
        PrivateLiquidityVaultCounters {
            vault_count: self.vaults.len() as u64,
            active_vault_count: self
                .vaults
                .values()
                .filter(|vault| vault.status.allows_rebalance())
                .count() as u64,
            reserve_bucket_count: self.reserve_buckets.len() as u64,
            live_reserve_bucket_count: self
                .reserve_buckets
                .values()
                .filter(|bucket| bucket.status.can_release())
                .count() as u64,
            strategy_mandate_count: self.strategy_mandates.len() as u64,
            active_strategy_mandate_count: self
                .strategy_mandates
                .values()
                .filter(|mandate| mandate.is_active_at(self.height))
                .count() as u64,
            rebalance_intent_count: self.rebalancing_intents.len() as u64,
            live_rebalance_intent_count: self
                .rebalancing_intents
                .values()
                .filter(|intent| intent.is_live_at(self.height))
                .count() as u64,
            withdrawal_queue_count: self.withdrawal_queue.len() as u64,
            open_withdrawal_queue_count: self
                .withdrawal_queue
                .values()
                .filter(|withdrawal| withdrawal.is_open_at(self.height))
                .count() as u64,
            solvency_attestation_count: self.solvency_attestations.len() as u64,
            fresh_solvency_attestation_count: self
                .solvency_attestations
                .values()
                .filter(|attestation| attestation.is_fresh_at(self.height))
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.is_active_at(self.height))
                .count() as u64,
            risk_limit_count: self.risk_limits.len() as u64,
            active_risk_limit_count: self
                .risk_limits
                .values()
                .filter(|limit| limit.is_active_at(self.height))
                .count() as u64,
            oracle_band_count: self.oracle_bands.len() as u64,
            fresh_oracle_band_count: self
                .oracle_bands
                .values()
                .filter(|band| band.is_fresh_at(self.height))
                .count() as u64,
            pq_approval_count: self.pq_approvals.len() as u64,
            active_pq_approval_count: self
                .pq_approvals
                .values()
                .filter(|approval| approval.is_active_at(self.height))
                .count() as u64,
            emergency_unwind_plan_count: self.emergency_unwind_plans.len() as u64,
            active_emergency_unwind_plan_count: self
                .emergency_unwind_plans
                .values()
                .filter(|plan| plan.is_active_at(self.height))
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_assets_floor_units: self.total_assets_floor_units(),
            total_assets_upper_bound_units: self.total_assets_upper_bound_units(),
            total_reserve_available_units: self.total_reserve_available_units(),
            total_withdrawal_ceiling_units: self.total_withdrawal_ceiling_units(),
            aggregate_risk_score_bps: self.aggregate_risk_score_bps(),
        }
    }

    pub fn active_vault_ids(&self) -> Vec<String> {
        self.vaults
            .values()
            .filter(|vault| vault.status.allows_rebalance())
            .map(|vault| vault.vault_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn total_assets_floor_units(&self) -> u64 {
        self.vaults.values().fold(0_u64, |total, vault| {
            total.saturating_add(vault.total_assets_floor_units)
        })
    }

    pub fn total_assets_upper_bound_units(&self) -> u64 {
        self.vaults.values().fold(0_u64, |total, vault| {
            total.saturating_add(vault.total_assets_upper_bound_units)
        })
    }

    pub fn total_reserve_available_units(&self) -> u64 {
        self.reserve_buckets.values().fold(0_u64, |total, bucket| {
            total.saturating_add(bucket.available_units())
        })
    }

    pub fn total_withdrawal_ceiling_units(&self) -> u64 {
        self.withdrawal_queue
            .values()
            .fold(0_u64, |total, withdrawal| {
                total.saturating_add(withdrawal.amount_ceiling_units)
            })
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        let mandate_risk = self
            .strategy_mandates
            .values()
            .filter(|mandate| mandate.is_active_at(self.height))
            .fold(0_u64, |score, mandate| {
                score.max(mandate.risk_tier.risk_score_bps())
            });
        let limit_risk = self
            .risk_limits
            .values()
            .filter(|limit| limit.is_active_at(self.height))
            .fold(0_u64, |score, limit| {
                score.max(limit.effective_risk_score_bps())
            });
        let pq_risk = self
            .pq_approvals
            .values()
            .filter(|approval| approval.is_active_at(self.height))
            .fold(0_u64, |score, approval| score.max(approval.risk_score_bps));
        mandate_risk.max(limit_risk).max(pq_risk)
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_liquidity_vault_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_LIQUIDITY_VAULT_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_vault_ids": self.active_vault_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        private_liquidity_vault_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateLiquidityVaultResult<String> {
        self.config.validate()?;
        for (id, vault) in &self.vaults {
            if id != &vault.vault_id {
                return Err("state vault map key does not match vault id".to_string());
            }
            vault.validate()?;
        }
        for (id, bucket) in &self.reserve_buckets {
            if id != &bucket.bucket_id {
                return Err("state reserve bucket key does not match bucket id".to_string());
            }
            bucket.validate()?;
            ensure_state_vault(&self.vaults, &bucket.vault_id, "reserve bucket")?;
        }
        for (id, mandate) in &self.strategy_mandates {
            if id != &mandate.mandate_id {
                return Err("state mandate key does not match mandate id".to_string());
            }
            mandate.validate()?;
            ensure_state_vault(&self.vaults, &mandate.vault_id, "strategy mandate")?;
            if mandate.max_exposure_bps > self.config.max_strategy_exposure_bps {
                return Err("strategy mandate exceeds config exposure cap".to_string());
            }
        }
        for (id, intent) in &self.rebalancing_intents {
            if id != &intent.intent_id {
                return Err("state intent key does not match intent id".to_string());
            }
            intent.validate()?;
            ensure_state_vault(&self.vaults, &intent.vault_id, "rebalance intent")?;
            ensure_state_mandate(&self.strategy_mandates, &intent.mandate_id)?;
            ensure_state_bucket(
                &self.reserve_buckets,
                &intent.source_bucket_id,
                "rebalance source",
            )?;
            ensure_state_bucket(
                &self.reserve_buckets,
                &intent.target_bucket_id,
                "rebalance target",
            )?;
            ensure_state_oracle_band(&self.oracle_bands, &intent.oracle_band_id)?;
        }
        for (id, withdrawal) in &self.withdrawal_queue {
            if id != &withdrawal.withdrawal_id {
                return Err("state withdrawal key does not match withdrawal id".to_string());
            }
            withdrawal.validate()?;
            ensure_state_vault(&self.vaults, &withdrawal.vault_id, "withdrawal")?;
            ensure_state_bucket(&self.reserve_buckets, &withdrawal.bucket_id, "withdrawal")?;
            if withdrawal.amount_ceiling_units > self.config.max_single_withdrawal_units {
                return Err("withdrawal exceeds config single withdrawal cap".to_string());
            }
            if !withdrawal.sponsor_id.is_empty()
                && !self
                    .low_fee_sponsorships
                    .contains_key(&withdrawal.sponsor_id)
            {
                return Err("withdrawal references missing sponsorship".to_string());
            }
        }
        for (id, attestation) in &self.solvency_attestations {
            if id != &attestation.attestation_id {
                return Err("state solvency key does not match attestation id".to_string());
            }
            attestation.validate()?;
            ensure_state_vault(&self.vaults, &attestation.vault_id, "solvency attestation")?;
            if attestation.reserve_coverage_bps < self.config.min_reserve_coverage_bps {
                return Err("solvency attestation below reserve coverage floor".to_string());
            }
        }
        for (id, sponsorship) in &self.low_fee_sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("state sponsorship key does not match sponsorship id".to_string());
            }
            sponsorship.validate()?;
            ensure_state_vault(&self.vaults, &sponsorship.vault_id, "sponsorship")?;
            if sponsorship.max_fee_units > self.config.sponsored_max_fee_units {
                return Err("sponsorship exceeds config fee cap".to_string());
            }
        }
        for (id, limit) in &self.risk_limits {
            if id != &limit.limit_id {
                return Err("state risk limit key does not match limit id".to_string());
            }
            limit.validate()?;
            ensure_state_vault(&self.vaults, &limit.vault_id, "risk limit")?;
        }
        for (id, band) in &self.oracle_bands {
            if id != &band.band_id {
                return Err("state oracle band key does not match band id".to_string());
            }
            band.validate()?;
            ensure_state_vault(&self.vaults, &band.vault_id, "oracle band")?;
            if band.max_deviation_bps > self.config.max_oracle_deviation_bps {
                return Err("oracle band exceeds config max deviation".to_string());
            }
        }
        for (id, approval) in &self.pq_approvals {
            if id != &approval.approval_id {
                return Err("state pq approval key does not match approval id".to_string());
            }
            approval.validate()?;
            ensure_state_vault(&self.vaults, &approval.vault_id, "pq approval")?;
            if approval.threshold < self.config.pq_approval_threshold {
                return Err("pq approval threshold below config threshold".to_string());
            }
        }
        for (id, plan) in &self.emergency_unwind_plans {
            if id != &plan.plan_id {
                return Err("state emergency plan key does not match plan id".to_string());
            }
            plan.validate()?;
            ensure_state_vault(&self.vaults, &plan.vault_id, "emergency unwind")?;
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record key does not match record id".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn private_liquidity_vault_state_root_from_record(record: &Value) -> String {
    let mut payload = record.clone();
    if let Value::Object(map) = &mut payload {
        map.remove("state_root");
    }
    domain_hash(
        "PRIVATE-LIQUIDITY-VAULT-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(&payload)],
        32,
    )
}

pub fn private_liquidity_vault_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_liquidity_vault_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn private_liquidity_vault_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn private_liquidity_amount_commitment(
    label: &str,
    amount_upper_bound_units: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(amount_upper_bound_units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_liquidity_vault_vault_root(vaults: &[ConfidentialLpVault]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-VAULTS",
        vaults
            .iter()
            .map(ConfidentialLpVault::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_reserve_bucket_root(buckets: &[WrappedXmrReserveBucket]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-RESERVE-BUCKETS",
        buckets
            .iter()
            .map(WrappedXmrReserveBucket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_strategy_mandate_root(
    mandates: &[EncryptedStrategyMandate],
) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-STRATEGY-MANDATES",
        mandates
            .iter()
            .map(EncryptedStrategyMandate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_rebalance_intent_root(
    intents: &[PrivateRebalancingIntent],
) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-REBALANCE-INTENTS",
        intents
            .iter()
            .map(PrivateRebalancingIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_withdrawal_root(withdrawals: &[WithdrawalQueueEntry]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-WITHDRAWAL-QUEUE",
        withdrawals
            .iter()
            .map(WithdrawalQueueEntry::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_solvency_root(attestations: &[SolvencyAttestation]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-SOLVENCY-ATTESTATIONS",
        attestations
            .iter()
            .map(SolvencyAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_sponsorship_root(sponsorships: &[LowFeeVaultSponsorship]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-LOW-FEE-SPONSORSHIPS",
        sponsorships
            .iter()
            .map(LowFeeVaultSponsorship::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_risk_limit_root(limits: &[VaultRiskLimit]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-RISK-LIMITS",
        limits
            .iter()
            .map(VaultRiskLimit::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_oracle_band_root(bands: &[OraclePriceBand]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-ORACLE-BANDS",
        bands
            .iter()
            .map(OraclePriceBand::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_pq_approval_root(approvals: &[PqCustodianApproval]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-PQ-APPROVALS",
        approvals
            .iter()
            .map(PqCustodianApproval::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_unwind_root(plans: &[EmergencyUnwindPlan]) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-EMERGENCY-UNWIND-PLANS",
        plans
            .iter()
            .map(EmergencyUnwindPlan::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_liquidity_vault_public_record_root(
    records: &[PrivateLiquidityVaultPublicRecord],
) -> String {
    private_liquidity_vault_merkle_root(
        "PRIVATE-LIQUIDITY-PUBLIC-RECORDS",
        records
            .iter()
            .map(PrivateLiquidityVaultPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn private_liquidity_vault_merkle_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn private_liquidity_vault_id(
    label: &str,
    owner_commitment: &str,
    lp_share_asset_id: &str,
    reserve_asset_id: &str,
    share_commitment_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(owner_commitment),
            HashPart::Str(lp_share_asset_id),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(share_commitment_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn reserve_bucket_id(
    vault_id: &str,
    bucket_kind: &ReserveBucketKind,
    asset_id: &str,
    monero_network: &str,
    reserve_address_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-RESERVE-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(bucket_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Str(monero_network),
            HashPart::Str(reserve_address_root),
        ],
        32,
    )
}

fn strategy_mandate_id(
    vault_id: &str,
    strategy_commitment: &str,
    strategy_kind: &str,
    encrypted_terms_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-STRATEGY-MANDATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(strategy_commitment),
            HashPart::Str(strategy_kind),
            HashPart::Str(encrypted_terms_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn rebalance_intent_id(
    vault_id: &str,
    mandate_id: &str,
    source_bucket_id: &str,
    target_bucket_id: &str,
    encrypted_action_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-REBALANCE-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(mandate_id),
            HashPart::Str(source_bucket_id),
            HashPart::Str(target_bucket_id),
            HashPart::Str(encrypted_action_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn withdrawal_entry_id(
    vault_id: &str,
    bucket_id: &str,
    owner_commitment: &str,
    share_nullifier_root: &str,
    queue_position: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-WITHDRAWAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(bucket_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(share_nullifier_root),
            HashPart::Int(queue_position as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn solvency_attestation_id(
    vault_id: &str,
    reserve_root: &str,
    liability_root: &str,
    oracle_band_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-SOLVENCY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(reserve_root),
            HashPart::Str(liability_root),
            HashPart::Str(oracle_band_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

fn vault_sponsorship_id(
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    vault_id: &str,
    target_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(vault_id),
            HashPart::Str(target_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn risk_limit_id(
    vault_id: &str,
    scope: &RiskLimitScope,
    target_id: &str,
    metric: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-RISK-LIMIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(metric),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn oracle_band_id(
    vault_id: &str,
    feed_id: &str,
    base_asset_id: &str,
    quote_asset_id: &str,
    reference_price: u64,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-ORACLE-BAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(feed_id),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Int(reference_price as i128),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn pq_approval_id(
    vault_id: &str,
    target_kind: &str,
    target_id: &str,
    custodian_set_root: &str,
    transcript_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-PQ-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(custodian_set_root),
            HashPart::Str(transcript_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

fn emergency_unwind_plan_id(
    vault_id: &str,
    trigger_root: &str,
    affected_bucket_root: &str,
    custodian_approval_root: &str,
    armed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-EMERGENCY-UNWIND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(trigger_root),
            HashPart::Str(affected_bucket_root),
            HashPart::Str(custodian_approval_root),
            HashPart::Int(armed_at_height as i128),
        ],
        32,
    )
}

fn public_record_id(
    subject_kind: &str,
    subject_id: &str,
    record_type: &str,
    payload_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-LIQUIDITY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(record_type),
            HashPart::Str(payload_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, field: &str) -> PrivateLiquidityVaultResult<()> {
    if value.is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> PrivateLiquidityVaultResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, field: &str) -> PrivateLiquidityVaultResult<()> {
    if value > PRIVATE_LIQUIDITY_VAULT_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    start_height: u64,
    end_height: u64,
    field: &str,
) -> PrivateLiquidityVaultResult<()> {
    if start_height > end_height {
        Err(format!("{field} has invalid height order"))
    } else {
        Ok(())
    }
}

fn ensure_state_vault(
    vaults: &BTreeMap<String, ConfidentialLpVault>,
    vault_id: &str,
    subject: &str,
) -> PrivateLiquidityVaultResult<()> {
    if vaults.contains_key(vault_id) {
        Ok(())
    } else {
        Err(format!("{subject} references missing vault"))
    }
}

fn ensure_state_bucket(
    buckets: &BTreeMap<String, WrappedXmrReserveBucket>,
    bucket_id: &str,
    subject: &str,
) -> PrivateLiquidityVaultResult<()> {
    if buckets.contains_key(bucket_id) {
        Ok(())
    } else {
        Err(format!("{subject} references missing reserve bucket"))
    }
}

fn ensure_state_mandate(
    mandates: &BTreeMap<String, EncryptedStrategyMandate>,
    mandate_id: &str,
) -> PrivateLiquidityVaultResult<()> {
    if mandates.contains_key(mandate_id) {
        Ok(())
    } else {
        Err("rebalance intent references missing mandate".to_string())
    }
}

fn ensure_state_oracle_band(
    bands: &BTreeMap<String, OraclePriceBand>,
    band_id: &str,
) -> PrivateLiquidityVaultResult<()> {
    if bands.contains_key(band_id) {
        Ok(())
    } else {
        Err("record references missing oracle band".to_string())
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let value = (numerator as u128).saturating_mul(PRIVATE_LIQUIDITY_VAULT_MAX_BPS as u128)
        / denominator as u128;
    value.min(u64::MAX as u128) as u64
}

fn price_deviation_bps(reference_price: u64, candidate_price: u64) -> u64 {
    if reference_price == 0 {
        return 0;
    }
    let delta = reference_price.abs_diff(candidate_price);
    ratio_bps(delta, reference_price)
}

fn sorted_non_empty_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
