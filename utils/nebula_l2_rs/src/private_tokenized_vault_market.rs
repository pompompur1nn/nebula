use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PrivateTokenizedVaultMarketResult<T> = Result<T, String>;

pub const PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL: &str =
    "nebula-private-tokenized-vault-market-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_SHARE_COMMITMENT_SCHEME: &str =
    "shake256-erc4626-confidential-share-class-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEPOSIT_COMMITMENT_SCHEME: &str =
    "shake256-private-vault-deposit-note-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_REDEMPTION_COMMITMENT_SCHEME: &str =
    "shake256-private-vault-redemption-nullifier-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_STRATEGY_COMMITMENT_SCHEME: &str =
    "ml-kem-1024-encrypted-strategy-commitment-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_RESERVE_RECEIPT_SCHEME: &str =
    "monero-viewkey-reserve-receipt-commitment-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-vault-manager-attestation-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_NAV_ORACLE_SCHEME: &str =
    "threshold-confidential-nav-oracle-band-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_LOW_FEE_SPONSORSHIP_SCHEME: &str =
    "private-tokenized-vault-low-fee-sponsorship-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_FEE_REBATE_SCHEME: &str = "zk-vault-share-fee-rebate-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-private-tokenized-vault-market-public-record-v1";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_HEIGHT: u64 = 512;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_SHARE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_BPS: u64 = 10_000;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_LOW_FEE_LANE: &str =
    "small-private-tokenized-vault";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_SHARE_ASSET_ID: &str = "ptv-wxmr-devnet";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_RESERVE_ASSET_ID: &str = "wxmr-reserve-devnet";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_ORACLE_FEED_ID: &str =
    "feed-private-vault-nav-devnet";
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_DEPOSIT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_REDEMPTION_TTL_BLOCKS: u64 = 144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_WITHDRAWAL_COOLDOWN_BLOCKS: u64 = 18;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_NAV_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_REBATE_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_VAULTS: usize = 65_536;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_SHARE_CLASSES: usize = 262_144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_DEPOSITS: usize = 524_288;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_REDEMPTIONS: usize = 524_288;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_STRATEGIES: usize = 262_144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_RESERVE_RECEIPTS: usize = 524_288;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_PQ_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_ORACLES: usize = 262_144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_WITHDRAWALS: usize = 524_288;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_RISK_CAPS: usize = 262_144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_SPONSORSHIPS: usize = 262_144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_REBATES: usize = 262_144;
pub const PRIVATE_TOKENIZED_VAULT_MARKET_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenizedVaultStatus {
    Bootstrapping,
    Active,
    DepositsPaused,
    RedemptionsPaused,
    WithdrawalOnly,
    StrategyRotation,
    EmergencyUnwind,
    Paused,
    Retired,
}

impl TokenizedVaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrapping => "bootstrapping",
            Self::Active => "active",
            Self::DepositsPaused => "deposits_paused",
            Self::RedemptionsPaused => "redemptions_paused",
            Self::WithdrawalOnly => "withdrawal_only",
            Self::StrategyRotation => "strategy_rotation",
            Self::EmergencyUnwind => "emergency_unwind",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(
            self,
            Self::Bootstrapping | Self::Active | Self::RedemptionsPaused
        )
    }

    pub fn accepts_redemptions(self) -> bool {
        matches!(
            self,
            Self::Active | Self::DepositsPaused | Self::WithdrawalOnly | Self::EmergencyUnwind
        )
    }

    pub fn strategy_live(self) -> bool {
        matches!(
            self,
            Self::Active
                | Self::DepositsPaused
                | Self::RedemptionsPaused
                | Self::StrategyRotation
                | Self::EmergencyUnwind
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareClassKind {
    Senior,
    Mezzanine,
    Junior,
    ProtectedPrincipal,
    YieldBoost,
    StrategySpecific,
}

impl ShareClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::ProtectedPrincipal => "protected_principal",
            Self::YieldBoost => "yield_boost",
            Self::StrategySpecific => "strategy_specific",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Senior => 100,
            Self::ProtectedPrincipal => 90,
            Self::Mezzanine => 70,
            Self::StrategySpecific => 55,
            Self::YieldBoost => 45,
            Self::Junior => 25,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareClassStatus {
    Draft,
    Active,
    DepositOnly,
    RedemptionOnly,
    Frozen,
    Settling,
    Retired,
}

impl ShareClassStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::RedemptionOnly => "redemption_only",
            Self::Frozen => "frozen",
            Self::Settling => "settling",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_deposit(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }

    pub fn accepts_redemption(self) -> bool {
        matches!(self, Self::Active | Self::RedemptionOnly | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateVaultOperationStatus {
    Submitted,
    Sponsored,
    Queued,
    Proving,
    Committed,
    Applied,
    Cancelled,
    Expired,
    Challenged,
}

impl PrivateVaultOperationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Sponsored => "sponsored",
            Self::Queued => "queued",
            Self::Proving => "proving",
            Self::Committed => "committed",
            Self::Applied => "applied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Sponsored | Self::Queued | Self::Proving | Self::Committed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyStatus {
    Draft,
    Active,
    Rebalancing,
    ReduceOnly,
    Unwinding,
    Frozen,
    Retired,
}

impl StrategyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Rebalancing => "rebalancing",
            Self::ReduceOnly => "reduce_only",
            Self::Unwinding => "unwinding",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn allocatable(self) -> bool {
        matches!(self, Self::Active | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveReceiptStatus {
    Pending,
    Confirmed,
    Matched,
    Spent,
    Reorged,
    Disputed,
    Expired,
}

impl ReserveReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Matched => "matched",
            Self::Spent => "spent",
            Self::Reorged => "reorged",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn reserve_backing(self) -> bool {
        matches!(self, Self::Confirmed | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqManagerDecision {
    Approve,
    Watch,
    ReduceCaps,
    PauseDeposits,
    PauseRedemptions,
    EmergencyUnwind,
    Reject,
}

impl PqManagerDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Watch => "watch",
            Self::ReduceCaps => "reduce_caps",
            Self::PauseDeposits => "pause_deposits",
            Self::PauseRedemptions => "pause_redemptions",
            Self::EmergencyUnwind => "emergency_unwind",
            Self::Reject => "reject",
        }
    }

    pub fn permits_market(self) -> bool {
        matches!(self, Self::Approve | Self::Watch | Self::ReduceCaps)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavOracleStatus {
    Fresh,
    Widened,
    Stale,
    Disputed,
    Revoked,
}

impl NavOracleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Widened => "widened",
            Self::Stale => "stale",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }

    pub fn prices_usable(self) -> bool {
        matches!(self, Self::Fresh | Self::Widened)
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
    Disputed,
}

impl WithdrawalQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Matching => "matching",
            Self::Reserved => "reserved",
            Self::Proving => "proving",
            Self::Ready => "ready",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Matching | Self::Reserved | Self::Proving | Self::Ready
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCapScope {
    Vault,
    ShareClass,
    Strategy,
    Reserve,
    Oracle,
    WithdrawalQueue,
    Sponsor,
}

impl RiskCapScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::ShareClass => "share_class",
            Self::Strategy => "strategy",
            Self::Reserve => "reserve",
            Self::Oracle => "oracle",
            Self::WithdrawalQueue => "withdrawal_queue",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCapStatus {
    Monitoring,
    Warning,
    Breached,
    Enforced,
    Disabled,
}

impl RiskCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monitoring => "monitoring",
            Self::Warning => "warning",
            Self::Breached => "breached",
            Self::Enforced => "enforced",
            Self::Disabled => "disabled",
        }
    }

    pub fn active(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRebateStatus {
    Posted,
    Reserved,
    Redeemable,
    Redeemed,
    Cancelled,
    Expired,
}

impl FeeRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Reserved => "reserved",
            Self::Redeemable => "redeemable",
            Self::Redeemed => "redeemed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Posted | Self::Reserved | Self::Redeemable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    VaultListed,
    ShareClassListed,
    DepositCommitted,
    RedemptionCommitted,
    StrategyCommitted,
    ReserveReceiptPosted,
    PqAttestationPosted,
    NavOraclePosted,
    WithdrawalQueued,
    RiskCapPosted,
    SponsorshipPosted,
    RebatePosted,
    StateCheckpoint,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultListed => "vault_listed",
            Self::ShareClassListed => "share_class_listed",
            Self::DepositCommitted => "deposit_committed",
            Self::RedemptionCommitted => "redemption_committed",
            Self::StrategyCommitted => "strategy_committed",
            Self::ReserveReceiptPosted => "reserve_receipt_posted",
            Self::PqAttestationPosted => "pq_attestation_posted",
            Self::NavOraclePosted => "nav_oracle_posted",
            Self::WithdrawalQueued => "withdrawal_queued",
            Self::RiskCapPosted => "risk_cap_posted",
            Self::SponsorshipPosted => "sponsorship_posted",
            Self::RebatePosted => "rebate_posted",
            Self::StateCheckpoint => "state_checkpoint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenizedVaultMarketConfig {
    pub market_id: String,
    pub underlying_asset_id: String,
    pub share_asset_id: String,
    pub reserve_asset_id: String,
    pub monero_network: String,
    pub nav_oracle_feed_id: String,
    pub default_low_fee_lane: String,
    pub max_total_assets_units: u64,
    pub max_single_deposit_units: u64,
    pub max_single_redemption_shares: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_idle_reserve_bps: u64,
    pub max_strategy_exposure_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub management_fee_bps: u64,
    pub performance_fee_bps: u64,
    pub withdrawal_cooldown_blocks: u64,
    pub deposit_ttl_blocks: u64,
    pub redemption_ttl_blocks: u64,
    pub nav_ttl_blocks: u64,
    pub pq_attestation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub sponsored_small_operation_limit_units: u64,
    pub sponsored_max_fee_units: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
}

impl Default for PrivateTokenizedVaultMarketConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl PrivateTokenizedVaultMarketConfig {
    pub fn devnet() -> Self {
        Self {
            market_id: tokenized_vault_string_root("market", "devnet-private-tokenized-vault"),
            underlying_asset_id: PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_ASSET_ID.to_string(),
            share_asset_id: PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_SHARE_ASSET_ID.to_string(),
            reserve_asset_id: PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_RESERVE_ASSET_ID.to_string(),
            monero_network: PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_MONERO_NETWORK.to_string(),
            nav_oracle_feed_id: PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_ORACLE_FEED_ID.to_string(),
            default_low_fee_lane: PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_LOW_FEE_LANE.to_string(),
            max_total_assets_units: 50_000_000_000_000,
            max_single_deposit_units: 1_000_000_000_000,
            max_single_redemption_shares: 1_000_000_000_000,
            min_reserve_coverage_bps: 10_500,
            target_idle_reserve_bps: 2_000,
            max_strategy_exposure_bps: 7_500,
            max_oracle_deviation_bps: 500,
            management_fee_bps: 75,
            performance_fee_bps: 1_000,
            withdrawal_cooldown_blocks:
                PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_WITHDRAWAL_COOLDOWN_BLOCKS,
            deposit_ttl_blocks: PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_DEPOSIT_TTL_BLOCKS,
            redemption_ttl_blocks: PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_REDEMPTION_TTL_BLOCKS,
            nav_ttl_blocks: PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_NAV_TTL_BLOCKS,
            pq_attestation_ttl_blocks:
                PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_ttl_blocks: PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_REBATE_TTL_BLOCKS,
            sponsored_small_operation_limit_units: 25_000_000,
            sponsored_max_fee_units: 7_500,
            min_privacy_set_size: PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_TOKENIZED_VAULT_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_tokenized_vault_market_config",
            "chain_id": CHAIN_ID,
            "protocol_label": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL,
            "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "underlying_asset_id": self.underlying_asset_id,
            "share_asset_id": self.share_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "monero_network": self.monero_network,
            "nav_oracle_feed_id": self.nav_oracle_feed_id,
            "default_low_fee_lane": self.default_low_fee_lane,
            "max_total_assets_units": self.max_total_assets_units,
            "max_single_deposit_units": self.max_single_deposit_units,
            "max_single_redemption_shares": self.max_single_redemption_shares,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_idle_reserve_bps": self.target_idle_reserve_bps,
            "max_strategy_exposure_bps": self.max_strategy_exposure_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "management_fee_bps": self.management_fee_bps,
            "performance_fee_bps": self.performance_fee_bps,
            "withdrawal_cooldown_blocks": self.withdrawal_cooldown_blocks,
            "deposit_ttl_blocks": self.deposit_ttl_blocks,
            "redemption_ttl_blocks": self.redemption_ttl_blocks,
            "nav_ttl_blocks": self.nav_ttl_blocks,
            "pq_attestation_ttl_blocks": self.pq_attestation_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "sponsored_small_operation_limit_units": self.sponsored_small_operation_limit_units,
            "sponsored_max_fee_units": self.sponsored_max_fee_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "share_commitment_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_SHARE_COMMITMENT_SCHEME,
            "deposit_commitment_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_DEPOSIT_COMMITMENT_SCHEME,
            "redemption_commitment_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_REDEMPTION_COMMITMENT_SCHEME,
            "strategy_commitment_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_STRATEGY_COMMITMENT_SCHEME,
            "reserve_receipt_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_RESERVE_RECEIPT_SCHEME,
            "pq_attestation_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_PQ_ATTESTATION_SCHEME,
            "nav_oracle_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_NAV_ORACLE_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        tokenized_vault_record_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
        ensure_non_empty(&self.market_id, "config market id")?;
        ensure_non_empty(&self.underlying_asset_id, "config underlying asset id")?;
        ensure_non_empty(&self.share_asset_id, "config share asset id")?;
        ensure_non_empty(&self.reserve_asset_id, "config reserve asset id")?;
        ensure_non_empty(&self.monero_network, "config monero network")?;
        ensure_non_empty(&self.nav_oracle_feed_id, "config nav oracle feed id")?;
        ensure_non_empty(&self.default_low_fee_lane, "config low fee lane")?;
        ensure_positive(self.max_total_assets_units, "config max total assets")?;
        ensure_positive(self.max_single_deposit_units, "config max single deposit")?;
        ensure_positive(
            self.max_single_redemption_shares,
            "config max single redemption shares",
        )?;
        ensure_bps_allow_overcollateral(self.min_reserve_coverage_bps, "config reserve coverage")?;
        ensure_bps(self.target_idle_reserve_bps, "config target idle reserve")?;
        ensure_bps(self.max_strategy_exposure_bps, "config strategy exposure")?;
        ensure_bps(self.max_oracle_deviation_bps, "config oracle deviation")?;
        ensure_bps(self.management_fee_bps, "config management fee")?;
        ensure_bps(self.performance_fee_bps, "config performance fee")?;
        ensure_positive(
            self.withdrawal_cooldown_blocks,
            "config withdrawal cooldown",
        )?;
        ensure_positive(self.deposit_ttl_blocks, "config deposit ttl")?;
        ensure_positive(self.redemption_ttl_blocks, "config redemption ttl")?;
        ensure_positive(self.nav_ttl_blocks, "config nav ttl")?;
        ensure_positive(self.pq_attestation_ttl_blocks, "config pq attestation ttl")?;
        ensure_positive(self.rebate_ttl_blocks, "config rebate ttl")?;
        ensure_positive(
            self.sponsored_small_operation_limit_units,
            "config sponsored small operation limit",
        )?;
        ensure_positive(self.sponsored_max_fee_units, "config sponsored fee cap")?;
        ensure_positive(self.min_privacy_set_size, "config min privacy set")?;
        if self.min_pq_security_bits == 0 {
            return Err("config min pq security bits must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTokenizedVault {
    pub vault_id: String,
    pub market_id: String,
    pub controller_commitment: String,
    pub underlying_asset_commitment: String,
    pub share_asset_commitment: String,
    pub reserve_address_root: String,
    pub share_class_root: String,
    pub strategy_root: String,
    pub accounting_policy_root: String,
    pub encrypted_metadata_root: String,
    pub total_assets_upper_bound_units: u64,
    pub total_shares_upper_bound: u64,
    pub min_deposit_units: u64,
    pub max_deposit_units: u64,
    pub min_redemption_shares: u64,
    pub max_redemption_shares: u64,
    pub management_fee_bps: u64,
    pub performance_fee_bps: u64,
    pub created_at_height: u64,
    pub status: TokenizedVaultStatus,
}

impl ShieldedTokenizedVault {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: impl Into<String>,
        controller_label: &str,
        underlying_asset_id: &str,
        share_asset_id: &str,
        reserve_payload: &Value,
        share_class_labels: &[String],
        strategy_labels: &[String],
        accounting_policy: &Value,
        metadata: &Value,
        total_assets_upper_bound_units: u64,
        total_shares_upper_bound: u64,
        created_at_height: u64,
        nonce: u64,
    ) -> PrivateTokenizedVaultMarketResult<Self> {
        let market_id = market_id.into();
        ensure_non_empty(&market_id, "vault market id")?;
        ensure_non_empty(controller_label, "vault controller")?;
        ensure_non_empty(underlying_asset_id, "vault underlying asset")?;
        ensure_non_empty(share_asset_id, "vault share asset")?;
        ensure_positive(total_shares_upper_bound, "vault share upper bound")?;
        let controller_commitment = account_commitment(controller_label);
        let underlying_asset_commitment = asset_commitment(underlying_asset_id);
        let share_asset_commitment = asset_commitment(share_asset_id);
        let reserve_address_root =
            tokenized_vault_payload_root("VAULT-RESERVE-ADDRESS", reserve_payload);
        let share_class_root =
            tokenized_vault_string_set_root("VAULT-SHARE-CLASS-LABELS", share_class_labels);
        let strategy_root =
            tokenized_vault_string_set_root("VAULT-STRATEGY-LABELS", strategy_labels);
        let accounting_policy_root =
            tokenized_vault_payload_root("VAULT-ACCOUNTING-POLICY", accounting_policy);
        let encrypted_metadata_root =
            tokenized_vault_payload_root("VAULT-ENCRYPTED-METADATA", metadata);
        let vault_id = vault_id(
            &market_id,
            &controller_commitment,
            &underlying_asset_commitment,
            &share_asset_commitment,
            &share_class_root,
            created_at_height,
            nonce,
        );
        let vault = Self {
            vault_id,
            market_id,
            controller_commitment,
            underlying_asset_commitment,
            share_asset_commitment,
            reserve_address_root,
            share_class_root,
            strategy_root,
            accounting_policy_root,
            encrypted_metadata_root,
            total_assets_upper_bound_units,
            total_shares_upper_bound,
            min_deposit_units: 1,
            max_deposit_units: total_assets_upper_bound_units,
            min_redemption_shares: 1,
            max_redemption_shares: total_shares_upper_bound,
            management_fee_bps: 75,
            performance_fee_bps: 1_000,
            created_at_height,
            status: TokenizedVaultStatus::Active,
        };
        vault.validate()?;
        Ok(vault)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_tokenized_vault",
            "chain_id": CHAIN_ID,
            "protocol_label": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL,
            "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
            "vault_id": self.vault_id,
            "market_id": self.market_id,
            "controller_commitment": self.controller_commitment,
            "underlying_asset_commitment": self.underlying_asset_commitment,
            "share_asset_commitment": self.share_asset_commitment,
            "reserve_address_root": self.reserve_address_root,
            "share_class_root": self.share_class_root,
            "strategy_root": self.strategy_root,
            "accounting_policy_root": self.accounting_policy_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "total_assets_upper_bound_units": self.total_assets_upper_bound_units,
            "total_shares_upper_bound": self.total_shares_upper_bound,
            "min_deposit_units": self.min_deposit_units,
            "max_deposit_units": self.max_deposit_units,
            "min_redemption_shares": self.min_redemption_shares,
            "max_redemption_shares": self.max_redemption_shares,
            "management_fee_bps": self.management_fee_bps,
            "performance_fee_bps": self.performance_fee_bps,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        tokenized_vault_record_root("VAULT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
        ensure_non_empty(&self.vault_id, "vault id")?;
        ensure_non_empty(&self.market_id, "vault market id")?;
        ensure_non_empty(&self.controller_commitment, "vault controller commitment")?;
        ensure_non_empty(
            &self.underlying_asset_commitment,
            "vault underlying commitment",
        )?;
        ensure_non_empty(&self.share_asset_commitment, "vault share commitment")?;
        ensure_non_empty(&self.reserve_address_root, "vault reserve root")?;
        ensure_non_empty(&self.share_class_root, "vault share class root")?;
        ensure_non_empty(&self.strategy_root, "vault strategy root")?;
        ensure_non_empty(&self.accounting_policy_root, "vault accounting policy root")?;
        ensure_non_empty(&self.encrypted_metadata_root, "vault metadata root")?;
        ensure_positive(
            self.total_shares_upper_bound,
            "vault total shares upper bound",
        )?;
        ensure_positive(self.max_deposit_units, "vault max deposit")?;
        ensure_positive(self.max_redemption_shares, "vault max redemption shares")?;
        ensure_bps(self.management_fee_bps, "vault management fee")?;
        ensure_bps(self.performance_fee_bps, "vault performance fee")?;
        if self.min_deposit_units > self.max_deposit_units {
            return Err("vault min deposit exceeds max deposit".to_string());
        }
        if self.min_redemption_shares > self.max_redemption_shares {
            return Err("vault min redemption exceeds max redemption".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedShareClass {
    pub share_class_id: String,
    pub vault_id: String,
    pub kind: ShareClassKind,
    pub class_asset_commitment: String,
    pub holder_registry_root: String,
    pub transfer_policy_root: String,
    pub nav_policy_root: String,
    pub encrypted_terms_root: String,
    pub share_supply_upper_bound: u64,
    pub asset_claim_upper_bound_units: u64,
    pub priority_weight: u64,
    pub min_privacy_set_size: u64,
    pub created_at_height: u64,
    pub status: ShareClassStatus,
}

impl EncryptedShareClass {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: impl Into<String>,
        kind: ShareClassKind,
        class_asset_id: &str,
        holder_labels: &[String],
        transfer_policy: &Value,
        nav_policy: &Value,
        encrypted_terms: &Value,
        share_supply_upper_bound: u64,
        asset_claim_upper_bound_units: u64,
        min_privacy_set_size: u64,
        created_at_height: u64,
        nonce: u64,
    ) -> PrivateTokenizedVaultMarketResult<Self> {
        let vault_id = vault_id.into();
        ensure_non_empty(&vault_id, "share class vault id")?;
        ensure_non_empty(class_asset_id, "share class asset id")?;
        ensure_positive(share_supply_upper_bound, "share class supply")?;
        ensure_positive(min_privacy_set_size, "share class privacy set")?;
        let class_asset_commitment = asset_commitment(class_asset_id);
        let holder_registry_root =
            tokenized_vault_string_set_root("SHARE-CLASS-HOLDER-REGISTRY", holder_labels);
        let transfer_policy_root =
            tokenized_vault_payload_root("SHARE-CLASS-TRANSFER-POLICY", transfer_policy);
        let nav_policy_root = tokenized_vault_payload_root("SHARE-CLASS-NAV-POLICY", nav_policy);
        let encrypted_terms_root =
            tokenized_vault_payload_root("SHARE-CLASS-ENCRYPTED-TERMS", encrypted_terms);
        let share_class_id = share_class_id(
            &vault_id,
            kind,
            &class_asset_commitment,
            &encrypted_terms_root,
            created_at_height,
            nonce,
        );
        let share_class = Self {
            share_class_id,
            vault_id,
            kind,
            class_asset_commitment,
            holder_registry_root,
            transfer_policy_root,
            nav_policy_root,
            encrypted_terms_root,
            share_supply_upper_bound,
            asset_claim_upper_bound_units,
            priority_weight: kind.priority_weight(),
            min_privacy_set_size,
            created_at_height,
            status: ShareClassStatus::Active,
        };
        share_class.validate()?;
        Ok(share_class)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_share_class",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
            "share_class_id": self.share_class_id,
            "vault_id": self.vault_id,
            "class_kind": self.kind.as_str(),
            "class_asset_commitment": self.class_asset_commitment,
            "holder_registry_root": self.holder_registry_root,
            "transfer_policy_root": self.transfer_policy_root,
            "nav_policy_root": self.nav_policy_root,
            "encrypted_terms_root": self.encrypted_terms_root,
            "share_supply_upper_bound": self.share_supply_upper_bound,
            "asset_claim_upper_bound_units": self.asset_claim_upper_bound_units,
            "priority_weight": self.priority_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
            "share_commitment_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_SHARE_COMMITMENT_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        tokenized_vault_record_root("SHARE-CLASS", &self.public_record())
    }

    pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
        ensure_non_empty(&self.share_class_id, "share class id")?;
        ensure_non_empty(&self.vault_id, "share class vault id")?;
        ensure_non_empty(&self.class_asset_commitment, "share class asset commitment")?;
        ensure_non_empty(&self.holder_registry_root, "share class holder registry")?;
        ensure_non_empty(&self.transfer_policy_root, "share class transfer policy")?;
        ensure_non_empty(&self.nav_policy_root, "share class nav policy")?;
        ensure_non_empty(&self.encrypted_terms_root, "share class terms")?;
        ensure_positive(self.share_supply_upper_bound, "share class supply")?;
        ensure_positive(self.min_privacy_set_size, "share class privacy set")?;
        if self.priority_weight == 0 {
            return Err("share class priority weight must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDepositCommitment {
    pub deposit_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub depositor_commitment: String,
    pub asset_note_commitment: String,
    pub amount_upper_bound_units: u64,
    pub min_share_commitment: String,
    pub reserve_receipt_id: String,
    pub sponsorship_id: String,
    pub proof_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: PrivateVaultOperationStatus,
}

impl PrivateDepositCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        depositor_label: &str,
        amount_upper_bound_units: u64,
        min_share_units: u64,
        reserve_receipt_id: impl Into<String>,
        sponsorship_id: impl Into<String>,
        proof_payload: &Value,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateTokenizedVaultMarketResult<Self> {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let reserve_receipt_id = reserve_receipt_id.into();
        let sponsorship_id = sponsorship_id.into();
        ensure_non_empty(&vault_id, "deposit vault id")?;
        ensure_non_empty(&share_class_id, "deposit share class id")?;
        ensure_non_empty(depositor_label, "deposit depositor")?;
        ensure_positive(amount_upper_bound_units, "deposit amount")?;
        validate_height_window(submitted_at_height, expires_at_height, "deposit")?;
        let depositor_commitment = account_commitment(depositor_label);
        let asset_note_commitment =
            amount_commitment("deposit-asset", amount_upper_bound_units, nonce);
        let min_share_commitment = amount_commitment("deposit-min-shares", min_share_units, nonce);
        let proof_root = tokenized_vault_payload_root("DEPOSIT-PROOF", proof_payload);
        let deposit_id = deposit_id(
            &vault_id,
            &share_class_id,
            &depositor_commitment,
            &asset_note_commitment,
            submitted_at_height,
            nonce,
        );
        let deposit = Self {
            deposit_id,
            vault_id,
            share_class_id,
            depositor_commitment,
            asset_note_commitment,
            amount_upper_bound_units,
            min_share_commitment,
            reserve_receipt_id,
            sponsorship_id,
            proof_root,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: PrivateVaultOperationStatus::Submitted,
        };
        deposit.validate()?;
        Ok(deposit)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_vault_deposit_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
            "deposit_id": self.deposit_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "depositor_commitment": self.depositor_commitment,
            "asset_note_commitment": self.asset_note_commitment,
            "amount_upper_bound_units": self.amount_upper_bound_units,
            "min_share_commitment": self.min_share_commitment,
            "reserve_receipt_id": self.reserve_receipt_id,
            "sponsorship_id": self.sponsorship_id,
            "proof_root": self.proof_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "deposit_commitment_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_DEPOSIT_COMMITMENT_SCHEME,
        })
    }

    pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
        ensure_non_empty(&self.deposit_id, "deposit id")?;
        ensure_non_empty(&self.vault_id, "deposit vault id")?;
        ensure_non_empty(&self.share_class_id, "deposit share class id")?;
        ensure_non_empty(&self.depositor_commitment, "deposit depositor commitment")?;
        ensure_non_empty(&self.asset_note_commitment, "deposit note commitment")?;
        ensure_positive(self.amount_upper_bound_units, "deposit amount")?;
        ensure_non_empty(&self.min_share_commitment, "deposit min share commitment")?;
        ensure_non_empty(&self.proof_root, "deposit proof root")?;
        validate_height_window(self.submitted_at_height, self.expires_at_height, "deposit")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRedemptionCommitment {
    pub redemption_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub owner_commitment: String,
    pub share_nullifier_root: String,
    pub share_amount_upper_bound: u64,
    pub min_asset_commitment: String,
    pub withdrawal_queue_id: String,
    pub sponsorship_id: String,
    pub proof_root: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: PrivateVaultOperationStatus,
}

impl PrivateRedemptionCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: impl Into<String>,
        share_class_id: impl Into<String>,
        owner_label: &str,
        share_amount_upper_bound: u64,
        min_asset_units: u64,
        withdrawal_queue_id: impl Into<String>,
        sponsorship_id: impl Into<String>,
        proof_payload: &Value,
        requested_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PrivateTokenizedVaultMarketResult<Self> {
        let vault_id = vault_id.into();
        let share_class_id = share_class_id.into();
        let withdrawal_queue_id = withdrawal_queue_id.into();
        let sponsorship_id = sponsorship_id.into();
        ensure_non_empty(&vault_id, "redemption vault id")?;
        ensure_non_empty(&share_class_id, "redemption share class id")?;
        ensure_non_empty(owner_label, "redemption owner")?;
        ensure_positive(share_amount_upper_bound, "redemption shares")?;
        validate_height_window(requested_at_height, expires_at_height, "redemption")?;
        let owner_commitment = account_commitment(owner_label);
        let share_nullifier_root = tokenized_vault_record_root(
            "REDEMPTION-SHARE-NULLIFIER",
            &json!({"owner": owner_commitment, "shares": share_amount_upper_bound, "nonce": nonce}),
        );
        let min_asset_commitment =
            amount_commitment("redemption-min-asset", min_asset_units, nonce);
        let proof_root = tokenized_vault_payload_root("REDEMPTION-PROOF", proof_payload);
        let redemption_id = redemption_id(
            &vault_id,
            &share_class_id,
            &owner_commitment,
            &share_nullifier_root,
            requested_at_height,
            nonce,
        );
        let redemption = Self {
            redemption_id,
            vault_id,
            share_class_id,
            owner_commitment,
            share_nullifier_root,
            share_amount_upper_bound,
            min_asset_commitment,
            withdrawal_queue_id,
            sponsorship_id,
            proof_root,
            requested_at_height,
            expires_at_height,
            nonce,
            status: PrivateVaultOperationStatus::Submitted,
        };
        redemption.validate()?;
        Ok(redemption)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_vault_redemption_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
            "redemption_id": self.redemption_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "owner_commitment": self.owner_commitment,
            "share_nullifier_root": self.share_nullifier_root,
            "share_amount_upper_bound": self.share_amount_upper_bound,
            "min_asset_commitment": self.min_asset_commitment,
            "withdrawal_queue_id": self.withdrawal_queue_id,
            "sponsorship_id": self.sponsorship_id,
            "proof_root": self.proof_root,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "redemption_commitment_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_REDEMPTION_COMMITMENT_SCHEME,
        })
    }

    pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
        ensure_non_empty(&self.redemption_id, "redemption id")?;
        ensure_non_empty(&self.vault_id, "redemption vault id")?;
        ensure_non_empty(&self.share_class_id, "redemption share class id")?;
        ensure_non_empty(&self.owner_commitment, "redemption owner commitment")?;
        ensure_non_empty(&self.share_nullifier_root, "redemption nullifier root")?;
        ensure_positive(self.share_amount_upper_bound, "redemption shares")?;
        ensure_non_empty(
            &self.min_asset_commitment,
            "redemption min asset commitment",
        )?;
        ensure_non_empty(&self.proof_root, "redemption proof root")?;
        validate_height_window(
            self.requested_at_height,
            self.expires_at_height,
            "redemption",
        )?;
        Ok(())
    }
}

macro_rules! simple_record {
    (
        $name:ident,
        $validate_name:literal,
        $id_field:ident,
        $kind_value:literal,
        { $($field:ident : $ty:ty),+ $(,)? },
        $status_ty:ty,
        $status_method:ident
    ) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name {
            pub $id_field: String,
            $(pub $field: $ty,)+
            pub status: $status_ty,
        }

        impl $name {
            pub fn public_record(&self) -> Value {
                json!({
                    "kind": $kind_value,
                    "chain_id": CHAIN_ID,
                    "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
                    stringify!($id_field): self.$id_field,
                    $(stringify!($field): self.$field,)+
                    "status": self.status.$status_method(),
                })
            }

            pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
                ensure_non_empty(&self.$id_field, concat!($validate_name, " id"))?;
                Ok(())
            }
        }
    };
}

simple_record!(
    StrategyCommitment,
    "strategy",
    strategy_id,
    "private_vault_strategy_commitment",
    {
        vault_id: String,
        manager_commitment: String,
        strategy_kind: String,
        encrypted_mandate_root: String,
        exposure_upper_bound_units: u64,
        leverage_bps: u64,
        risk_score_bps: u64,
        created_at_height: u64,
        expires_at_height: u64
    },
    StrategyStatus,
    as_str
);

simple_record!(
    MoneroReserveReceipt,
    "reserve receipt",
    receipt_id,
    "monero_reserve_receipt_commitment",
    {
        vault_id: String,
        reserve_asset_commitment: String,
        txid_commitment: String,
        output_commitment_root: String,
        amount_upper_bound_units: u64,
        confirmation_height: u64,
        spend_policy_root: String,
        view_tag_root: String
    },
    ReserveReceiptStatus,
    as_str
);

simple_record!(
    PqManagerAttestation,
    "pq manager attestation",
    attestation_id,
    "pq_manager_attestation",
    {
        vault_id: String,
        subject_kind: String,
        subject_id: String,
        manager_commitment: String,
        transcript_root: String,
        signature_root: String,
        pq_security_bits: u16,
        threshold: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        decision: String
    },
    PqManagerDecision,
    as_str
);

simple_record!(
    ConfidentialNavOracle,
    "nav oracle",
    oracle_id,
    "confidential_nav_oracle",
    {
        vault_id: String,
        feed_id: String,
        nav_commitment: String,
        lower_bound_price: u64,
        upper_bound_price: u64,
        share_supply_root: String,
        liability_root: String,
        observed_at_height: u64,
        expires_at_height: u64,
        committee_root: String
    },
    NavOracleStatus,
    as_str
);

simple_record!(
    WithdrawalQueueEntry,
    "withdrawal queue",
    queue_id,
    "private_vault_withdrawal_queue_entry",
    {
        vault_id: String,
        share_class_id: String,
        owner_commitment: String,
        share_nullifier_root: String,
        asset_out_commitment: String,
        queue_position: u64,
        requested_at_height: u64,
        release_after_height: u64,
        priority_weight: u64,
        sponsor_id: String
    },
    WithdrawalQueueStatus,
    as_str
);

simple_record!(
    VaultRiskCap,
    "risk cap",
    cap_id,
    "private_vault_risk_cap",
    {
        vault_id: String,
        scope: String,
        target_id: String,
        metric: String,
        cap_value_units: u64,
        observed_value_units: u64,
        evidence_root: String,
        enforced_at_height: u64
    },
    RiskCapStatus,
    as_str
);

simple_record!(
    LowFeeSponsorship,
    "low fee sponsorship",
    sponsorship_id,
    "private_vault_low_fee_sponsorship",
    {
        vault_id: String,
        sponsor_commitment: String,
        beneficiary_commitment: String,
        target_kind: String,
        target_id: String,
        fee_asset_commitment: String,
        max_fee_units: u64,
        spent_fee_units: u64,
        low_fee_lane: String,
        policy_root: String,
        starts_at_height: u64,
        expires_at_height: u64
    },
    SponsorshipStatus,
    as_str
);

simple_record!(
    FeeRebateCommitment,
    "fee rebate",
    rebate_id,
    "private_vault_fee_rebate_commitment",
    {
        vault_id: String,
        beneficiary_commitment: String,
        operation_id: String,
        rebate_asset_commitment: String,
        rebate_amount_upper_bound_units: u64,
        remaining_rebate_units: u64,
        proof_root: String,
        posted_at_height: u64,
        expires_at_height: u64
    },
    FeeRebateStatus,
    as_str
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicVaultMarketPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl DeterministicVaultMarketPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_tokenized_vault_market_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
            "public_record_scheme": PRIVATE_TOKENIZED_VAULT_MARKET_PUBLIC_RECORD_SCHEME,
        })
    }

    pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "public record subject id")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenizedVaultMarketRoots {
    pub config_root: String,
    pub vault_root: String,
    pub share_class_root: String,
    pub deposit_root: String,
    pub redemption_root: String,
    pub strategy_root: String,
    pub reserve_receipt_root: String,
    pub pq_attestation_root: String,
    pub nav_oracle_root: String,
    pub withdrawal_queue_root: String,
    pub risk_cap_root: String,
    pub low_fee_sponsorship_root: String,
    pub fee_rebate_root: String,
    pub public_record_root: String,
    pub counters_root: String,
}

impl PrivateTokenizedVaultMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "share_class_root": self.share_class_root,
            "deposit_root": self.deposit_root,
            "redemption_root": self.redemption_root,
            "strategy_root": self.strategy_root,
            "reserve_receipt_root": self.reserve_receipt_root,
            "pq_attestation_root": self.pq_attestation_root,
            "nav_oracle_root": self.nav_oracle_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "risk_cap_root": self.risk_cap_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "fee_rebate_root": self.fee_rebate_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        tokenized_vault_record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenizedVaultMarketCounters {
    pub vault_count: u64,
    pub active_vault_count: u64,
    pub share_class_count: u64,
    pub active_share_class_count: u64,
    pub deposit_count: u64,
    pub live_deposit_count: u64,
    pub redemption_count: u64,
    pub live_redemption_count: u64,
    pub strategy_count: u64,
    pub allocatable_strategy_count: u64,
    pub reserve_receipt_count: u64,
    pub backing_reserve_receipt_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub nav_oracle_count: u64,
    pub fresh_nav_oracle_count: u64,
    pub withdrawal_queue_count: u64,
    pub open_withdrawal_queue_count: u64,
    pub risk_cap_count: u64,
    pub active_risk_cap_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub fee_rebate_count: u64,
    pub spendable_fee_rebate_count: u64,
    pub public_record_count: u64,
    pub total_assets_upper_bound_units: u64,
    pub total_shares_upper_bound: u64,
    pub aggregate_strategy_exposure_units: u64,
    pub aggregate_sponsored_fee_units: u64,
    pub aggregate_remaining_rebate_units: u64,
    pub minimum_privacy_set_size: u64,
    pub minimum_pq_security_bits: u16,
}

impl PrivateTokenizedVaultMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_count": self.vault_count,
            "active_vault_count": self.active_vault_count,
            "share_class_count": self.share_class_count,
            "active_share_class_count": self.active_share_class_count,
            "deposit_count": self.deposit_count,
            "live_deposit_count": self.live_deposit_count,
            "redemption_count": self.redemption_count,
            "live_redemption_count": self.live_redemption_count,
            "strategy_count": self.strategy_count,
            "allocatable_strategy_count": self.allocatable_strategy_count,
            "reserve_receipt_count": self.reserve_receipt_count,
            "backing_reserve_receipt_count": self.backing_reserve_receipt_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "nav_oracle_count": self.nav_oracle_count,
            "fresh_nav_oracle_count": self.fresh_nav_oracle_count,
            "withdrawal_queue_count": self.withdrawal_queue_count,
            "open_withdrawal_queue_count": self.open_withdrawal_queue_count,
            "risk_cap_count": self.risk_cap_count,
            "active_risk_cap_count": self.active_risk_cap_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "fee_rebate_count": self.fee_rebate_count,
            "spendable_fee_rebate_count": self.spendable_fee_rebate_count,
            "public_record_count": self.public_record_count,
            "total_assets_upper_bound_units": self.total_assets_upper_bound_units,
            "total_shares_upper_bound": self.total_shares_upper_bound,
            "aggregate_strategy_exposure_units": self.aggregate_strategy_exposure_units,
            "aggregate_sponsored_fee_units": self.aggregate_sponsored_fee_units,
            "aggregate_remaining_rebate_units": self.aggregate_remaining_rebate_units,
            "minimum_privacy_set_size": self.minimum_privacy_set_size,
            "minimum_pq_security_bits": self.minimum_pq_security_bits,
        })
    }

    pub fn root(&self) -> String {
        tokenized_vault_record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenizedVaultMarketState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateTokenizedVaultMarketConfig,
    pub vaults: BTreeMap<String, ShieldedTokenizedVault>,
    pub share_classes: BTreeMap<String, EncryptedShareClass>,
    pub deposits: BTreeMap<String, PrivateDepositCommitment>,
    pub redemptions: BTreeMap<String, PrivateRedemptionCommitment>,
    pub strategies: BTreeMap<String, StrategyCommitment>,
    pub reserve_receipts: BTreeMap<String, MoneroReserveReceipt>,
    pub pq_attestations: BTreeMap<String, PqManagerAttestation>,
    pub nav_oracles: BTreeMap<String, ConfidentialNavOracle>,
    pub withdrawal_queue: BTreeMap<String, WithdrawalQueueEntry>,
    pub risk_caps: BTreeMap<String, VaultRiskCap>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub fee_rebates: BTreeMap<String, FeeRebateCommitment>,
    pub public_records: BTreeMap<String, DeterministicVaultMarketPublicRecord>,
}

impl PrivateTokenizedVaultMarketState {
    pub fn devnet() -> PrivateTokenizedVaultMarketResult<Self> {
        let config = PrivateTokenizedVaultMarketConfig::devnet();
        let height = PRIVATE_TOKENIZED_VAULT_MARKET_DEVNET_HEIGHT;
        let controller = account_commitment("devnet-private-vault-controller");
        let underlying = asset_commitment(&config.underlying_asset_id);
        let share = asset_commitment(&config.share_asset_id);
        let share_class_root = tokenized_vault_string_set_root(
            "DEVNET-VAULT-SHARE-CLASSES",
            &["senior".to_string(), "junior".to_string()],
        );
        let strategy_root = tokenized_vault_string_set_root(
            "DEVNET-VAULT-STRATEGIES",
            &[
                "wxmr-reserve-carry".to_string(),
                "private-stable-swap-lp".to_string(),
            ],
        );
        let reserve_address_root = tokenized_vault_payload_root(
            "DEVNET-VAULT-RESERVE",
            &json!({"network": config.monero_network, "address_kind": "stealth_subaddress_bucket"}),
        );
        let accounting_policy_root = tokenized_vault_payload_root(
            "DEVNET-VAULT-ACCOUNTING",
            &json!({"standard": "erc4626_like", "rounding": "privacy_preserving_floor"}),
        );
        let encrypted_metadata_root = tokenized_vault_payload_root(
            "DEVNET-VAULT-METADATA",
            &json!({"name": "devnet encrypted wxmr tokenized vault", "encrypted": true}),
        );
        let vault_id = vault_id(
            &config.market_id,
            &controller,
            &underlying,
            &share,
            &share_class_root,
            height,
            1,
        );
        let vault = ShieldedTokenizedVault {
            vault_id: vault_id.clone(),
            market_id: config.market_id.clone(),
            controller_commitment: controller,
            underlying_asset_commitment: underlying,
            share_asset_commitment: share,
            reserve_address_root,
            share_class_root,
            strategy_root,
            accounting_policy_root,
            encrypted_metadata_root,
            total_assets_upper_bound_units: 5_000_000_000_000,
            total_shares_upper_bound: 5_000_000 * PRIVATE_TOKENIZED_VAULT_MARKET_SHARE_SCALE,
            min_deposit_units: 1_000_000,
            max_deposit_units: config.max_single_deposit_units,
            min_redemption_shares: 1_000_000,
            max_redemption_shares: config.max_single_redemption_shares,
            management_fee_bps: config.management_fee_bps,
            performance_fee_bps: config.performance_fee_bps,
            created_at_height: height,
            status: TokenizedVaultStatus::Active,
        };

        let senior = EncryptedShareClass::new(
            vault_id.clone(),
            ShareClassKind::Senior,
            "ptv-wxmr-senior-devnet",
            &["devnet-holder-bucket-a".to_string()],
            &json!({"transfers": "shielded_allowlist"}),
            &json!({"nav": "confidential_oracle_band"}),
            &json!({"lockup": "short", "fee_preference": "rebate"}),
            3_000_000 * PRIVATE_TOKENIZED_VAULT_MARKET_SHARE_SCALE,
            3_000_000_000_000,
            config.min_privacy_set_size,
            height,
            2,
        )?;
        let junior = EncryptedShareClass::new(
            vault_id.clone(),
            ShareClassKind::Junior,
            "ptv-wxmr-junior-devnet",
            &["devnet-holder-bucket-b".to_string()],
            &json!({"transfers": "shielded_allowlist"}),
            &json!({"nav": "confidential_oracle_band"}),
            &json!({"lockup": "long", "fee_preference": "performance"}),
            2_000_000 * PRIVATE_TOKENIZED_VAULT_MARKET_SHARE_SCALE,
            2_000_000_000_000,
            config.min_privacy_set_size,
            height,
            3,
        )?;

        let strategy = StrategyCommitment {
            strategy_id: strategy_id(
                &vault_id,
                &account_commitment("devnet-strategy-manager"),
                "reserve-carry",
                height,
                4,
            ),
            vault_id: vault_id.clone(),
            manager_commitment: account_commitment("devnet-strategy-manager"),
            strategy_kind: "reserve-carry".to_string(),
            encrypted_mandate_root: tokenized_vault_payload_root(
                "DEVNET-STRATEGY-MANDATE",
                &json!({"venues": ["private-liquidity-vault"], "max_exposure_bps": 3500}),
            ),
            exposure_upper_bound_units: 1_750_000_000_000,
            leverage_bps: 10_000,
            risk_score_bps: 2_000,
            created_at_height: height,
            expires_at_height: height + 7_200,
            status: StrategyStatus::Active,
        };

        let reserve_receipt = MoneroReserveReceipt {
            receipt_id: reserve_receipt_id(&vault_id, "devnet-reserve-txid", height, 5),
            vault_id: vault_id.clone(),
            reserve_asset_commitment: asset_commitment(&config.reserve_asset_id),
            txid_commitment: tokenized_vault_string_root("reserve-txid", "devnet-reserve-txid"),
            output_commitment_root: tokenized_vault_payload_root(
                "DEVNET-RESERVE-OUTPUTS",
                &json!({"bucket": "cold", "outputs": 16}),
            ),
            amount_upper_bound_units: 2_500_000_000_000,
            confirmation_height: height.saturating_sub(6),
            spend_policy_root: tokenized_vault_payload_root(
                "DEVNET-RESERVE-SPEND-POLICY",
                &json!({"threshold": 3, "members": 5}),
            ),
            view_tag_root: tokenized_vault_string_root(
                "reserve-view-tags",
                "devnet-view-tag-bucket",
            ),
            status: ReserveReceiptStatus::Confirmed,
        };

        let oracle = ConfidentialNavOracle {
            oracle_id: nav_oracle_id(&vault_id, &config.nav_oracle_feed_id, height, 6),
            vault_id: vault_id.clone(),
            feed_id: config.nav_oracle_feed_id.clone(),
            nav_commitment: amount_commitment("nav", PRIVATE_TOKENIZED_VAULT_MARKET_PRICE_SCALE, 6),
            lower_bound_price: 995_000_000_000,
            upper_bound_price: 1_005_000_000_000,
            share_supply_root: senior.root(),
            liability_root: junior.root(),
            observed_at_height: height,
            expires_at_height: height + config.nav_ttl_blocks,
            committee_root: tokenized_vault_string_root("nav-committee", "devnet-nav-committee"),
            status: NavOracleStatus::Fresh,
        };

        let attestation = PqManagerAttestation {
            attestation_id: pq_attestation_id(&vault_id, "vault", &vault_id, height, 7),
            vault_id: vault_id.clone(),
            subject_kind: "vault".to_string(),
            subject_id: vault_id.clone(),
            manager_commitment: account_commitment("devnet-pq-manager"),
            transcript_root: tokenized_vault_payload_root(
                "DEVNET-PQ-TRANSCRIPT",
                &json!({"decision": "approve", "nav_oracle": oracle.oracle_id}),
            ),
            signature_root: tokenized_vault_string_root("pq-signature", "devnet-signature-root"),
            pq_security_bits: config.min_pq_security_bits,
            threshold: 2,
            issued_at_height: height,
            expires_at_height: height + config.pq_attestation_ttl_blocks,
            decision: PqManagerDecision::Approve.as_str().to_string(),
            status: PqManagerDecision::Approve,
        };

        let risk_cap = VaultRiskCap {
            cap_id: risk_cap_id(
                &vault_id,
                RiskCapScope::Strategy,
                &strategy.strategy_id,
                "exposure",
                8,
            ),
            vault_id: vault_id.clone(),
            scope: RiskCapScope::Strategy.as_str().to_string(),
            target_id: strategy.strategy_id.clone(),
            metric: "exposure_units".to_string(),
            cap_value_units: config.max_strategy_exposure_bps,
            observed_value_units: 3_500,
            evidence_root: strategy.encrypted_mandate_root.clone(),
            enforced_at_height: height,
            status: RiskCapStatus::Monitoring,
        };

        let public_record = DeterministicVaultMarketPublicRecord {
            record_id: public_record_id(
                PublicRecordKind::StateCheckpoint,
                &vault_id,
                &vault.root(),
                height,
                1,
            ),
            record_kind: PublicRecordKind::StateCheckpoint,
            subject_id: vault_id.clone(),
            payload_root: vault.root(),
            emitted_at_height: height,
            sequence: 1,
        };

        let mut state = Self {
            height,
            nonce: 8,
            config,
            vaults: BTreeMap::new(),
            share_classes: BTreeMap::new(),
            deposits: BTreeMap::new(),
            redemptions: BTreeMap::new(),
            strategies: BTreeMap::new(),
            reserve_receipts: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            nav_oracles: BTreeMap::new(),
            withdrawal_queue: BTreeMap::new(),
            risk_caps: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.vaults.insert(vault.vault_id.clone(), vault);
        state
            .share_classes
            .insert(senior.share_class_id.clone(), senior);
        state
            .share_classes
            .insert(junior.share_class_id.clone(), junior);
        state
            .strategies
            .insert(strategy.strategy_id.clone(), strategy);
        state
            .reserve_receipts
            .insert(reserve_receipt.receipt_id.clone(), reserve_receipt);
        state.nav_oracles.insert(oracle.oracle_id.clone(), oracle);
        state
            .pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        state.risk_caps.insert(risk_cap.cap_id.clone(), risk_cap);
        state
            .public_records
            .insert(public_record.record_id.clone(), public_record);
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateTokenizedVaultMarketResult<()> {
        if height < self.height {
            return Err("height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn roots(&self) -> PrivateTokenizedVaultMarketRoots {
        let counters = self.counters();
        PrivateTokenizedVaultMarketRoots {
            config_root: self.config.root(),
            vault_root: collection_root(
                "VAULTS",
                self.vaults
                    .values()
                    .map(ShieldedTokenizedVault::public_record)
                    .collect(),
            ),
            share_class_root: collection_root(
                "SHARE-CLASSES",
                self.share_classes
                    .values()
                    .map(EncryptedShareClass::public_record)
                    .collect(),
            ),
            deposit_root: collection_root(
                "DEPOSITS",
                self.deposits
                    .values()
                    .map(PrivateDepositCommitment::public_record)
                    .collect(),
            ),
            redemption_root: collection_root(
                "REDEMPTIONS",
                self.redemptions
                    .values()
                    .map(PrivateRedemptionCommitment::public_record)
                    .collect(),
            ),
            strategy_root: collection_root(
                "STRATEGIES",
                self.strategies
                    .values()
                    .map(StrategyCommitment::public_record)
                    .collect(),
            ),
            reserve_receipt_root: collection_root(
                "RESERVE-RECEIPTS",
                self.reserve_receipts
                    .values()
                    .map(MoneroReserveReceipt::public_record)
                    .collect(),
            ),
            pq_attestation_root: collection_root(
                "PQ-ATTESTATIONS",
                self.pq_attestations
                    .values()
                    .map(PqManagerAttestation::public_record)
                    .collect(),
            ),
            nav_oracle_root: collection_root(
                "NAV-ORACLES",
                self.nav_oracles
                    .values()
                    .map(ConfidentialNavOracle::public_record)
                    .collect(),
            ),
            withdrawal_queue_root: collection_root(
                "WITHDRAWAL-QUEUE",
                self.withdrawal_queue
                    .values()
                    .map(WithdrawalQueueEntry::public_record)
                    .collect(),
            ),
            risk_cap_root: collection_root(
                "RISK-CAPS",
                self.risk_caps
                    .values()
                    .map(VaultRiskCap::public_record)
                    .collect(),
            ),
            low_fee_sponsorship_root: collection_root(
                "LOW-FEE-SPONSORSHIPS",
                self.low_fee_sponsorships
                    .values()
                    .map(LowFeeSponsorship::public_record)
                    .collect(),
            ),
            fee_rebate_root: collection_root(
                "FEE-REBATES",
                self.fee_rebates
                    .values()
                    .map(FeeRebateCommitment::public_record)
                    .collect(),
            ),
            public_record_root: collection_root(
                "PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(DeterministicVaultMarketPublicRecord::public_record)
                    .collect(),
            ),
            counters_root: counters.root(),
        }
    }

    pub fn counters(&self) -> PrivateTokenizedVaultMarketCounters {
        let minimum_privacy_set_size = match self
            .share_classes
            .values()
            .map(|share_class| share_class.min_privacy_set_size)
            .min()
        {
            Some(value) => value,
            None => self.config.min_privacy_set_size,
        };
        let minimum_pq_security_bits = match self
            .pq_attestations
            .values()
            .map(|attestation| attestation.pq_security_bits)
            .min()
        {
            Some(value) => value,
            None => self.config.min_pq_security_bits,
        };
        PrivateTokenizedVaultMarketCounters {
            vault_count: self.vaults.len() as u64,
            active_vault_count: self
                .vaults
                .values()
                .filter(|vault| {
                    vault.status.accepts_deposits() || vault.status.accepts_redemptions()
                })
                .count() as u64,
            share_class_count: self.share_classes.len() as u64,
            active_share_class_count: self
                .share_classes
                .values()
                .filter(|share_class| {
                    share_class.status.accepts_deposit() || share_class.status.accepts_redemption()
                })
                .count() as u64,
            deposit_count: self.deposits.len() as u64,
            live_deposit_count: self
                .deposits
                .values()
                .filter(|deposit| deposit.status.live())
                .count() as u64,
            redemption_count: self.redemptions.len() as u64,
            live_redemption_count: self
                .redemptions
                .values()
                .filter(|redemption| redemption.status.live())
                .count() as u64,
            strategy_count: self.strategies.len() as u64,
            allocatable_strategy_count: self
                .strategies
                .values()
                .filter(|strategy| strategy.status.allocatable())
                .count() as u64,
            reserve_receipt_count: self.reserve_receipts.len() as u64,
            backing_reserve_receipt_count: self
                .reserve_receipts
                .values()
                .filter(|receipt| receipt.status.reserve_backing())
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| {
                    attestation.status.permits_market()
                        && attestation.expires_at_height >= self.height
                })
                .count() as u64,
            nav_oracle_count: self.nav_oracles.len() as u64,
            fresh_nav_oracle_count: self
                .nav_oracles
                .values()
                .filter(|oracle| {
                    oracle.status.prices_usable() && oracle.expires_at_height >= self.height
                })
                .count() as u64,
            withdrawal_queue_count: self.withdrawal_queue.len() as u64,
            open_withdrawal_queue_count: self
                .withdrawal_queue
                .values()
                .filter(|entry| entry.status.open())
                .count() as u64,
            risk_cap_count: self.risk_caps.len() as u64,
            active_risk_cap_count: self
                .risk_caps
                .values()
                .filter(|cap| cap.status.active())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.active())
                .count() as u64,
            fee_rebate_count: self.fee_rebates.len() as u64,
            spendable_fee_rebate_count: self
                .fee_rebates
                .values()
                .filter(|rebate| rebate.status.spendable())
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_assets_upper_bound_units: self
                .vaults
                .values()
                .map(|vault| vault.total_assets_upper_bound_units)
                .fold(0_u64, u64::saturating_add),
            total_shares_upper_bound: self
                .vaults
                .values()
                .map(|vault| vault.total_shares_upper_bound)
                .fold(0_u64, u64::saturating_add),
            aggregate_strategy_exposure_units: self
                .strategies
                .values()
                .map(|strategy| strategy.exposure_upper_bound_units)
                .fold(0_u64, u64::saturating_add),
            aggregate_sponsored_fee_units: self
                .low_fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.spent_fee_units)
                .fold(0_u64, u64::saturating_add),
            aggregate_remaining_rebate_units: self
                .fee_rebates
                .values()
                .map(|rebate| rebate.remaining_rebate_units)
                .fold(0_u64, u64::saturating_add),
            minimum_privacy_set_size,
            minimum_pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_tokenized_vault_market_state",
            "chain_id": CHAIN_ID,
            "protocol_label": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL,
            "protocol_version": PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_tokenized_vault_market_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateTokenizedVaultMarketResult<()> {
        self.config.validate()?;
        if self.vaults.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_VAULTS {
            return Err("too many tokenized vaults".to_string());
        }
        if self.share_classes.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_SHARE_CLASSES {
            return Err("too many share classes".to_string());
        }
        if self.deposits.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_DEPOSITS {
            return Err("too many deposits".to_string());
        }
        if self.redemptions.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_REDEMPTIONS {
            return Err("too many redemptions".to_string());
        }
        if self.strategies.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_STRATEGIES {
            return Err("too many strategies".to_string());
        }
        if self.reserve_receipts.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_RESERVE_RECEIPTS {
            return Err("too many reserve receipts".to_string());
        }
        if self.pq_attestations.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_PQ_ATTESTATIONS {
            return Err("too many pq attestations".to_string());
        }
        if self.nav_oracles.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_ORACLES {
            return Err("too many nav oracles".to_string());
        }
        if self.withdrawal_queue.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_WITHDRAWALS {
            return Err("too many withdrawal queue entries".to_string());
        }
        if self.risk_caps.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_RISK_CAPS {
            return Err("too many risk caps".to_string());
        }
        if self.low_fee_sponsorships.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_SPONSORSHIPS {
            return Err("too many low fee sponsorships".to_string());
        }
        if self.fee_rebates.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_REBATES {
            return Err("too many fee rebates".to_string());
        }
        if self.public_records.len() > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_PUBLIC_RECORDS {
            return Err("too many public records".to_string());
        }
        for (id, vault) in &self.vaults {
            if id != &vault.vault_id {
                return Err("vault map key does not match vault id".to_string());
            }
            vault.validate()?;
            if vault.total_assets_upper_bound_units > self.config.max_total_assets_units {
                return Err("vault exceeds configured total asset cap".to_string());
            }
            if vault.max_deposit_units > self.config.max_single_deposit_units {
                return Err("vault deposit cap exceeds config".to_string());
            }
            if vault.max_redemption_shares > self.config.max_single_redemption_shares {
                return Err("vault redemption cap exceeds config".to_string());
            }
        }
        for (id, share_class) in &self.share_classes {
            if id != &share_class.share_class_id {
                return Err("share class map key does not match share class id".to_string());
            }
            share_class.validate()?;
            ensure_state_vault(&self.vaults, &share_class.vault_id, "share class")?;
            if share_class.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("share class below configured privacy set floor".to_string());
            }
        }
        for deposit in self.deposits.values() {
            deposit.validate()?;
            ensure_state_vault(&self.vaults, &deposit.vault_id, "deposit")?;
            ensure_state_share_class(&self.share_classes, &deposit.share_class_id, "deposit")?;
            if deposit.amount_upper_bound_units > self.config.max_single_deposit_units {
                return Err("deposit exceeds configured single deposit cap".to_string());
            }
            if !deposit.reserve_receipt_id.is_empty()
                && !self
                    .reserve_receipts
                    .contains_key(&deposit.reserve_receipt_id)
            {
                return Err("deposit references missing reserve receipt".to_string());
            }
            if !deposit.sponsorship_id.is_empty()
                && !self
                    .low_fee_sponsorships
                    .contains_key(&deposit.sponsorship_id)
            {
                return Err("deposit references missing sponsorship".to_string());
            }
        }
        for redemption in self.redemptions.values() {
            redemption.validate()?;
            ensure_state_vault(&self.vaults, &redemption.vault_id, "redemption")?;
            ensure_state_share_class(
                &self.share_classes,
                &redemption.share_class_id,
                "redemption",
            )?;
            if redemption.share_amount_upper_bound > self.config.max_single_redemption_shares {
                return Err("redemption exceeds configured share cap".to_string());
            }
            if !redemption.withdrawal_queue_id.is_empty()
                && !self
                    .withdrawal_queue
                    .contains_key(&redemption.withdrawal_queue_id)
            {
                return Err("redemption references missing withdrawal queue entry".to_string());
            }
            if !redemption.sponsorship_id.is_empty()
                && !self
                    .low_fee_sponsorships
                    .contains_key(&redemption.sponsorship_id)
            {
                return Err("redemption references missing sponsorship".to_string());
            }
        }
        for strategy in self.strategies.values() {
            strategy.validate()?;
            ensure_state_vault(&self.vaults, &strategy.vault_id, "strategy")?;
            ensure_bps_allow_overcollateral(strategy.leverage_bps, "strategy leverage")?;
            ensure_bps(strategy.risk_score_bps, "strategy risk score")?;
            if strategy.exposure_upper_bound_units > self.config.max_total_assets_units {
                return Err("strategy exceeds configured total assets".to_string());
            }
            validate_height_window(
                strategy.created_at_height,
                strategy.expires_at_height,
                "strategy",
            )?;
        }
        for receipt in self.reserve_receipts.values() {
            receipt.validate()?;
            ensure_state_vault(&self.vaults, &receipt.vault_id, "reserve receipt")?;
            ensure_positive(receipt.amount_upper_bound_units, "reserve receipt amount")?;
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
            ensure_state_vault(&self.vaults, &attestation.vault_id, "pq attestation")?;
            if attestation.pq_security_bits < self.config.min_pq_security_bits {
                return Err("pq attestation below configured pq floor".to_string());
            }
            validate_height_window(
                attestation.issued_at_height,
                attestation.expires_at_height,
                "pq attestation",
            )?;
        }
        for oracle in self.nav_oracles.values() {
            oracle.validate()?;
            ensure_state_vault(&self.vaults, &oracle.vault_id, "nav oracle")?;
            if oracle.lower_bound_price > oracle.upper_bound_price {
                return Err("nav oracle lower bound exceeds upper bound".to_string());
            }
            validate_height_window(
                oracle.observed_at_height,
                oracle.expires_at_height,
                "nav oracle",
            )?;
        }
        for entry in self.withdrawal_queue.values() {
            entry.validate()?;
            ensure_state_vault(&self.vaults, &entry.vault_id, "withdrawal queue")?;
            ensure_state_share_class(
                &self.share_classes,
                &entry.share_class_id,
                "withdrawal queue",
            )?;
            if entry.release_after_height < entry.requested_at_height {
                return Err("withdrawal release height precedes request".to_string());
            }
        }
        for cap in self.risk_caps.values() {
            cap.validate()?;
            ensure_state_vault(&self.vaults, &cap.vault_id, "risk cap")?;
            ensure_non_empty(&cap.target_id, "risk cap target")?;
            ensure_non_empty(&cap.metric, "risk cap metric")?;
            ensure_non_empty(&cap.evidence_root, "risk cap evidence")?;
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
            ensure_state_vault(&self.vaults, &sponsorship.vault_id, "sponsorship")?;
            if sponsorship.max_fee_units > self.config.sponsored_max_fee_units {
                return Err("sponsorship exceeds configured fee cap".to_string());
            }
            if sponsorship.spent_fee_units > sponsorship.max_fee_units {
                return Err("sponsorship spent fee exceeds max fee".to_string());
            }
            validate_height_window(
                sponsorship.starts_at_height,
                sponsorship.expires_at_height,
                "sponsorship",
            )?;
        }
        for rebate in self.fee_rebates.values() {
            rebate.validate()?;
            ensure_state_vault(&self.vaults, &rebate.vault_id, "fee rebate")?;
            if rebate.remaining_rebate_units > rebate.rebate_amount_upper_bound_units {
                return Err("fee rebate remaining amount exceeds upper bound".to_string());
            }
            validate_height_window(
                rebate.posted_at_height,
                rebate.expires_at_height,
                "fee rebate",
            )?;
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(())
    }
}

pub fn private_tokenized_vault_market_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-STATE-ROOT",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Int(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION as i128),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn tokenized_vault_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-TOKENIZED-VAULT-MARKET-{domain}"),
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Int(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_VERSION as i128),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn tokenized_vault_record_root(domain: &str, payload: &Value) -> String {
    tokenized_vault_payload_root(domain, payload)
}

pub fn tokenized_vault_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-STRING",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn tokenized_vault_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    collection_root(domain, leaves)
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    tokenized_vault_payload_root(&format!("{domain}-COLLECTION"), &Value::Array(records))
}

fn account_commitment(label: &str) -> String {
    tokenized_vault_string_root("account", label)
}

fn asset_commitment(asset_id: &str) -> String {
    tokenized_vault_string_root("asset", asset_id)
}

fn amount_commitment(label: &str, amount_units: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(amount_units as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn vault_id(
    market_id: &str,
    controller_commitment: &str,
    underlying_asset_commitment: &str,
    share_asset_commitment: &str,
    share_class_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-VAULT-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(controller_commitment),
            HashPart::Str(underlying_asset_commitment),
            HashPart::Str(share_asset_commitment),
            HashPart::Str(share_class_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn share_class_id(
    vault_id: &str,
    kind: ShareClassKind,
    class_asset_commitment: &str,
    encrypted_terms_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-SHARE-CLASS-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(class_asset_commitment),
            HashPart::Str(encrypted_terms_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn deposit_id(
    vault_id: &str,
    share_class_id: &str,
    depositor_commitment: &str,
    asset_note_commitment: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-DEPOSIT-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(share_class_id),
            HashPart::Str(depositor_commitment),
            HashPart::Str(asset_note_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn redemption_id(
    vault_id: &str,
    share_class_id: &str,
    owner_commitment: &str,
    share_nullifier_root: &str,
    requested_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-REDEMPTION-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(share_class_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(share_nullifier_root),
            HashPart::Int(requested_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn strategy_id(
    vault_id: &str,
    manager_commitment: &str,
    strategy_kind: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-STRATEGY-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(manager_commitment),
            HashPart::Str(strategy_kind),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn reserve_receipt_id(vault_id: &str, txid_label: &str, height: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-RESERVE-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(txid_label),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn pq_attestation_id(
    vault_id: &str,
    subject_kind: &str,
    subject_id: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn nav_oracle_id(vault_id: &str, feed_id: &str, observed_at_height: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-NAV-ORACLE-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(feed_id),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn risk_cap_id(
    vault_id: &str,
    scope: RiskCapScope,
    target_id: &str,
    metric: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-RISK-CAP-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vault_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(metric),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKENIZED-VAULT-MARKET-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PRIVATE_TOKENIZED_VAULT_MARKET_PROTOCOL_LABEL),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateTokenizedVaultMarketResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> PrivateTokenizedVaultMarketResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> PrivateTokenizedVaultMarketResult<()> {
    if value > PRIVATE_TOKENIZED_VAULT_MARKET_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_bps_allow_overcollateral(
    value: u64,
    label: &str,
) -> PrivateTokenizedVaultMarketResult<()> {
    if value > 100 * PRIVATE_TOKENIZED_VAULT_MARKET_MAX_BPS {
        Err(format!("{label} exceeds overcollateralized bps bound"))
    } else {
        Ok(())
    }
}

fn validate_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> PrivateTokenizedVaultMarketResult<()> {
    if end <= start {
        Err(format!("{label} height window is invalid"))
    } else {
        Ok(())
    }
}

fn ensure_state_vault(
    vaults: &BTreeMap<String, ShieldedTokenizedVault>,
    vault_id: &str,
    subject: &str,
) -> PrivateTokenizedVaultMarketResult<()> {
    if vaults.contains_key(vault_id) {
        Ok(())
    } else {
        Err(format!("{subject} references missing vault"))
    }
}

fn ensure_state_share_class(
    share_classes: &BTreeMap<String, EncryptedShareClass>,
    share_class_id: &str,
    subject: &str,
) -> PrivateTokenizedVaultMarketResult<()> {
    if share_classes.contains_key(share_class_id) {
        Ok(())
    } else {
        Err(format!("{subject} references missing share class"))
    }
}
