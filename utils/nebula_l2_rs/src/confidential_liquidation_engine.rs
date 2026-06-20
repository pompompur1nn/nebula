use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialLiquidationEngineResult<T> = Result<T, String>;

pub const CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION: &str =
    "nebula-confidential-liquidation-engine-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_COMMITMENT_SCHEME: &str =
    "shake256-confidential-liquidation-commitment-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_ACCOUNT_ENCRYPTION_SCHEME: &str =
    "xwing-private-risk-account-envelope-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_SEALED_BID_SCHEME: &str =
    "threshold-encrypted-sealed-keeper-bid-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_SOLVENCY_PROOF_SCHEME: &str =
    "recursive-private-solvency-bucket-proof-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_ORACLE_SCHEME: &str =
    "confidence-window-zk-oracle-guard-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-slh-dsa-shake-256f-liquidation-attestation-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_AUCTION_SCHEME: &str =
    "mev-safe-commit-reveal-liquidation-auction-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_SUBSIDY_SCHEME: &str = "low-fee-keeper-subsidy-ticket-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_BACKSTOP_SCHEME: &str =
    "bad-debt-backstop-accounting-root-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_APPEAL_SCHEME: &str =
    "private-liquidation-appeal-envelope-v1";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_HEIGHT: u64 = 144;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_MAX_ORACLE_CONFIDENCE_BPS: u64 = 250;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 650;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_COMMIT_BLOCKS: u64 = 8;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_REVEAL_BLOCKS: u64 = 6;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_CHALLENGE_BLOCKS: u64 = 12;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_SETTLEMENT_GRACE_BLOCKS: u64 = 16;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_APPEAL_BLOCKS: u64 = 36;
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_LOW_FEE_LANE: &str =
    "small-confidential-liquidations";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_DEBT_ASSET_ID: &str = "usdd-devnet";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_MARKET_LABEL: &str =
    "wxmr-usdd-private-liquidations";
pub const CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_ORACLE_FEED_ID: &str =
    "feed-wxmr-usdd-confidential-devnet";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationVenue {
    Lending,
    Perps,
    Stablecoin,
    CrossMargin,
    Vault,
    Custom(String),
}

impl LiquidationVenue {
    pub fn as_str(&self) -> String {
        match self {
            Self::Lending => "lending".to_string(),
            Self::Perps => "perps".to_string(),
            Self::Stablecoin => "stablecoin".to_string(),
            Self::CrossMargin => "cross_margin".to_string(),
            Self::Vault => "vault".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationMarketStatus {
    Active,
    ReduceOnly,
    LiquidationOnly,
    OraclePaused,
    KeeperPaused,
    BackstopOnly,
    Settling,
    Retired,
}

impl LiquidationMarketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::OraclePaused => "oracle_paused",
            Self::KeeperPaused => "keeper_paused",
            Self::BackstopOnly => "backstop_only",
            Self::Settling => "settling",
            Self::Retired => "retired",
        }
    }

    pub fn allows_triggering(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::ReduceOnly | Self::LiquidationOnly
        )
    }

    pub fn allows_settlement(&self) -> bool {
        matches!(
            self,
            Self::Active
                | Self::ReduceOnly
                | Self::LiquidationOnly
                | Self::BackstopOnly
                | Self::Settling
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRiskAccountStatus {
    Pending,
    Open,
    Watch,
    Triggered,
    AuctionLocked,
    Settling,
    Appealed,
    Closed,
    Expired,
}

impl PrivateRiskAccountStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Watch => "watch",
            Self::Triggered => "triggered",
            Self::AuctionLocked => "auction_locked",
            Self::Settling => "settling",
            Self::Appealed => "appealed",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_active(&self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Open
                | Self::Watch
                | Self::Triggered
                | Self::AuctionLocked
                | Self::Settling
                | Self::Appealed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialHealthBand {
    NoDebt,
    SuperSafe,
    Healthy,
    Watch,
    LiquidationWarning,
    Liquidatable,
    Insolvent,
}

impl ConfidentialHealthBand {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoDebt => "no_debt",
            Self::SuperSafe => "super_safe",
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::LiquidationWarning => "liquidation_warning",
            Self::Liquidatable => "liquidatable",
            Self::Insolvent => "insolvent",
        }
    }

    pub fn floor_bps(&self) -> u64 {
        match self {
            Self::NoDebt => u64::MAX,
            Self::SuperSafe => 20_000,
            Self::Healthy => 15_000,
            Self::Watch => 12_000,
            Self::LiquidationWarning => 10_000,
            Self::Liquidatable => 8_000,
            Self::Insolvent => 0,
        }
    }

    pub fn ceiling_bps(&self) -> u64 {
        match self {
            Self::NoDebt => u64::MAX,
            Self::SuperSafe => u64::MAX - 1,
            Self::Healthy => 19_999,
            Self::Watch => 14_999,
            Self::LiquidationWarning => 11_999,
            Self::Liquidatable => 9_999,
            Self::Insolvent => 7_999,
        }
    }

    pub fn can_liquidate(&self) -> bool {
        matches!(self, Self::Liquidatable | Self::Insolvent)
    }

    pub fn risk_score_bps(&self) -> u64 {
        match self {
            Self::NoDebt => 0,
            Self::SuperSafe => 500,
            Self::Healthy => 1_500,
            Self::Watch => 4_500,
            Self::LiquidationWarning => 6_500,
            Self::Liquidatable => 8_500,
            Self::Insolvent => 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationTriggerKind {
    HealthFactorBelowMaintenance,
    PerpMarginBreach,
    StablecoinCollateralBreach,
    OracleConfidenceBreach,
    ExpiredGraceWindow,
    GovernanceBackstop,
    KeeperRecheck,
}

impl LiquidationTriggerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HealthFactorBelowMaintenance => "health_factor_below_maintenance",
            Self::PerpMarginBreach => "perp_margin_breach",
            Self::StablecoinCollateralBreach => "stablecoin_collateral_breach",
            Self::OracleConfidenceBreach => "oracle_confidence_breach",
            Self::ExpiredGraceWindow => "expired_grace_window",
            Self::GovernanceBackstop => "governance_backstop",
            Self::KeeperRecheck => "keeper_recheck",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationTriggerStatus {
    Queued,
    ChallengeOpen,
    AuctionOpen,
    Executable,
    Settled,
    Appealed,
    Cancelled,
    Expired,
}

impl LiquidationTriggerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ChallengeOpen => "challenge_open",
            Self::AuctionOpen => "auction_open",
            Self::Executable => "executable",
            Self::Settled => "settled",
            Self::Appealed => "appealed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_live(&self) -> bool {
        matches!(
            self,
            Self::Queued | Self::ChallengeOpen | Self::AuctionOpen | Self::Executable
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralLotStatus {
    Pending,
    Active,
    LockedForAuction,
    PartiallySettled,
    Settled,
    Released,
    Slashed,
    Expired,
}

impl CollateralLotStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::LockedForAuction => "locked_for_auction",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_locked(&self) -> bool {
        matches!(self, Self::LockedForAuction | Self::PartiallySettled)
    }

    pub fn counts_as_open(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Active | Self::LockedForAuction | Self::PartiallySettled
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleKind {
    PrivateSolvency,
    Liquidatability,
    BidValidity,
    SettlementConservation,
    OracleConfidence,
    BackstopSolvency,
    AppealEvidence,
}

impl ProofBundleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateSolvency => "private_solvency",
            Self::Liquidatability => "liquidatability",
            Self::BidValidity => "bid_validity",
            Self::SettlementConservation => "settlement_conservation",
            Self::OracleConfidence => "oracle_confidence",
            Self::BackstopSolvency => "backstop_solvency",
            Self::AppealEvidence => "appeal_evidence",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleStatus {
    Pending,
    Verified,
    Aggregated,
    Challenged,
    Rejected,
    Expired,
}

impl ProofBundleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Aggregated => "aggregated",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_accepted(&self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleWindowStatus {
    Collecting,
    Guarded,
    Degraded,
    Frozen,
    Expired,
}

impl OracleWindowStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Guarded => "guarded",
            Self::Degraded => "degraded",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
        }
    }

    pub fn allows_liquidation(&self) -> bool {
        matches!(self, Self::Guarded | Self::Degraded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionWindowStatus {
    Scheduled,
    CommitOpen,
    RevealOpen,
    SettlementOpen,
    Settled,
    Cancelled,
    Expired,
}

impl AuctionWindowStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::SettlementOpen => "settlement_open",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedBidStatus {
    Committed,
    Decrypted,
    Valid,
    Winning,
    Settled,
    Slashed,
    Refunded,
    Expired,
}

impl SealedBidStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Decrypted => "decrypted",
            Self::Valid => "valid",
            Self::Winning => "winning",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_live(&self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Decrypted | Self::Valid | Self::Winning
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeSubsidyStatus {
    Reserved,
    Active,
    Spent,
    Exhausted,
    Revoked,
    Expired,
}

impl LowFeeSubsidyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Spent => "spent",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_active(&self) -> bool {
        matches!(self, Self::Reserved | Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Applied,
    PendingFinality,
    Finalized,
    Disputed,
    Reversed,
    Expired,
}

impl SettlementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::PendingFinality => "pending_finality",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopActionKind {
    ReserveDraw,
    InsuranceFundDraw,
    BadDebtMint,
    SocializedLossAccrual,
    SurplusRepayment,
    KeeperBondSlash,
    ProtocolFeeSweep,
}

impl BackstopActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReserveDraw => "reserve_draw",
            Self::InsuranceFundDraw => "insurance_fund_draw",
            Self::BadDebtMint => "bad_debt_mint",
            Self::SocializedLossAccrual => "socialized_loss_accrual",
            Self::SurplusRepayment => "surplus_repayment",
            Self::KeeperBondSlash => "keeper_bond_slash",
            Self::ProtocolFeeSweep => "protocol_fee_sweep",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopActionStatus {
    Planned,
    Applied,
    PendingFinality,
    Finalized,
    Reversed,
    Rejected,
}

impl BackstopActionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Applied => "applied",
            Self::PendingFinality => "pending_finality",
            Self::Finalized => "finalized",
            Self::Reversed => "reversed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    Open,
    EvidenceLocked,
    Accepted,
    Rejected,
    Withdrawn,
    Expired,
}

impl AppealStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceLocked => "evidence_locked",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_pending(&self) -> bool {
        matches!(self, Self::Open | Self::EvidenceLocked)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealDecision {
    Pending,
    UpholdLiquidation,
    ReverseLiquidation,
    PartialRefund,
    SlashKeeper,
    EscalateToGovernance,
}

impl AppealDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::UpholdLiquidation => "uphold_liquidation",
            Self::ReverseLiquidation => "reverse_liquidation",
            Self::PartialRefund => "partial_refund",
            Self::SlashKeeper => "slash_keeper",
            Self::EscalateToGovernance => "escalate_to_governance",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationRiskSeverity {
    Info,
    Watch,
    Elevated,
    High,
    Critical,
}

impl LiquidationRiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            Self::Info => 250,
            Self::Watch => 2_000,
            Self::Elevated => 5_000,
            Self::High => 8_000,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLiquidationEngineConfig {
    pub protocol_version: String,
    pub commitment_scheme: String,
    pub account_encryption_scheme: String,
    pub sealed_bid_scheme: String,
    pub private_solvency_proof_scheme: String,
    pub oracle_scheme: String,
    pub pq_authorization_scheme: String,
    pub auction_scheme: String,
    pub subsidy_scheme: String,
    pub backstop_scheme: String,
    pub appeal_scheme: String,
    pub price_scale: u64,
    pub max_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub close_factor_bps: u64,
    pub max_liquidation_discount_bps: u64,
    pub keeper_reward_bps: u64,
    pub protocol_fee_bps: u64,
    pub max_bad_debt_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub max_oracle_confidence_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub commit_phase_blocks: u64,
    pub reveal_phase_blocks: u64,
    pub challenge_window_blocks: u64,
    pub settlement_grace_blocks: u64,
    pub appeal_window_blocks: u64,
    pub min_keeper_bond_units: u64,
    pub max_keeper_fee_units: u64,
    pub low_fee_subsidy_budget_units: u64,
    pub low_fee_min_notional_units: u64,
    pub low_fee_max_notional_units: u64,
    pub default_low_fee_lane: String,
    pub metadata_root: String,
}

impl Default for ConfidentialLiquidationEngineConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl ConfidentialLiquidationEngineConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION.to_string(),
            commitment_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_COMMITMENT_SCHEME.to_string(),
            account_encryption_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_ACCOUNT_ENCRYPTION_SCHEME
                .to_string(),
            sealed_bid_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_SEALED_BID_SCHEME.to_string(),
            private_solvency_proof_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_SOLVENCY_PROOF_SCHEME
                .to_string(),
            oracle_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_ORACLE_SCHEME.to_string(),
            pq_authorization_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_PQ_AUTH_SCHEME.to_string(),
            auction_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_AUCTION_SCHEME.to_string(),
            subsidy_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_SUBSIDY_SCHEME.to_string(),
            backstop_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_BACKSTOP_SCHEME.to_string(),
            appeal_scheme: CONFIDENTIAL_LIQUIDATION_ENGINE_APPEAL_SCHEME.to_string(),
            price_scale: CONFIDENTIAL_LIQUIDATION_ENGINE_PRICE_SCALE,
            max_bps: CONFIDENTIAL_LIQUIDATION_ENGINE_MAX_BPS,
            maintenance_margin_bps: 1_250,
            liquidation_threshold_bps: 8_250,
            close_factor_bps: 5_000,
            max_liquidation_discount_bps: 850,
            keeper_reward_bps: 75,
            protocol_fee_bps: 35,
            max_bad_debt_bps: 500,
            max_oracle_staleness_blocks:
                CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            max_oracle_confidence_bps:
                CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_MAX_ORACLE_CONFIDENCE_BPS,
            max_oracle_deviation_bps:
                CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            commit_phase_blocks: CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_COMMIT_BLOCKS,
            reveal_phase_blocks: CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_REVEAL_BLOCKS,
            challenge_window_blocks: CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_CHALLENGE_BLOCKS,
            settlement_grace_blocks:
                CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_SETTLEMENT_GRACE_BLOCKS,
            appeal_window_blocks: CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_APPEAL_BLOCKS,
            min_keeper_bond_units: 250_000,
            max_keeper_fee_units: 7_500,
            low_fee_subsidy_budget_units: 5_000_000,
            low_fee_min_notional_units: 100_000,
            low_fee_max_notional_units: 50_000_000,
            default_low_fee_lane: CONFIDENTIAL_LIQUIDATION_ENGINE_DEFAULT_LOW_FEE_LANE.to_string(),
            metadata_root: confidential_liquidation_engine_payload_root(
                "CONFIDENTIAL-LIQUIDATION-ENGINE-CONFIG-METADATA",
                &json!({
                    "mode": "devnet",
                    "privacy": "commitments_only",
                    "auction": "sealed_commit_reveal",
                    "quantum_resistant": true
                }),
            ),
        }
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.protocol_version, "config protocol_version")?;
        ensure_non_empty(&self.commitment_scheme, "config commitment_scheme")?;
        ensure_non_empty(
            &self.account_encryption_scheme,
            "config account_encryption_scheme",
        )?;
        ensure_non_empty(&self.sealed_bid_scheme, "config sealed_bid_scheme")?;
        ensure_non_empty(
            &self.private_solvency_proof_scheme,
            "config private_solvency_proof_scheme",
        )?;
        ensure_non_empty(&self.oracle_scheme, "config oracle_scheme")?;
        ensure_non_empty(
            &self.pq_authorization_scheme,
            "config pq_authorization_scheme",
        )?;
        ensure_non_empty(&self.auction_scheme, "config auction_scheme")?;
        ensure_non_empty(&self.subsidy_scheme, "config subsidy_scheme")?;
        ensure_non_empty(&self.backstop_scheme, "config backstop_scheme")?;
        ensure_non_empty(&self.appeal_scheme, "config appeal_scheme")?;
        ensure_non_empty(&self.default_low_fee_lane, "config default_low_fee_lane")?;
        ensure_non_empty(&self.metadata_root, "config metadata_root")?;
        if self.price_scale == 0 || self.max_bps != CONFIDENTIAL_LIQUIDATION_ENGINE_MAX_BPS {
            return Err(
                "config price_scale must be positive and max_bps must be 10000".to_string(),
            );
        }
        ensure_bps(self.maintenance_margin_bps, "config maintenance_margin_bps")?;
        ensure_bps(
            self.liquidation_threshold_bps,
            "config liquidation_threshold_bps",
        )?;
        ensure_bps(self.close_factor_bps, "config close_factor_bps")?;
        ensure_bps(
            self.max_liquidation_discount_bps,
            "config max_liquidation_discount_bps",
        )?;
        ensure_bps(self.keeper_reward_bps, "config keeper_reward_bps")?;
        ensure_bps(self.protocol_fee_bps, "config protocol_fee_bps")?;
        ensure_bps(self.max_bad_debt_bps, "config max_bad_debt_bps")?;
        ensure_bps(
            self.max_oracle_confidence_bps,
            "config max_oracle_confidence_bps",
        )?;
        ensure_bps(
            self.max_oracle_deviation_bps,
            "config max_oracle_deviation_bps",
        )?;
        if self.maintenance_margin_bps >= self.liquidation_threshold_bps {
            return Err(
                "config maintenance margin must be below liquidation threshold".to_string(),
            );
        }
        if self.close_factor_bps == 0 {
            return Err("config close_factor_bps must be positive".to_string());
        }
        if self.commit_phase_blocks == 0
            || self.reveal_phase_blocks == 0
            || self.challenge_window_blocks == 0
            || self.settlement_grace_blocks == 0
            || self.appeal_window_blocks == 0
            || self.max_oracle_staleness_blocks == 0
        {
            return Err("config block windows and oracle staleness must be positive".to_string());
        }
        if self.low_fee_min_notional_units > self.low_fee_max_notional_units {
            return Err("config low fee notional bounds are invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_liquidation_engine_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "commitment_scheme": self.commitment_scheme,
            "account_encryption_scheme": self.account_encryption_scheme,
            "sealed_bid_scheme": self.sealed_bid_scheme,
            "private_solvency_proof_scheme": self.private_solvency_proof_scheme,
            "oracle_scheme": self.oracle_scheme,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "auction_scheme": self.auction_scheme,
            "subsidy_scheme": self.subsidy_scheme,
            "backstop_scheme": self.backstop_scheme,
            "appeal_scheme": self.appeal_scheme,
            "price_scale": self.price_scale,
            "max_bps": self.max_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "close_factor_bps": self.close_factor_bps,
            "max_liquidation_discount_bps": self.max_liquidation_discount_bps,
            "keeper_reward_bps": self.keeper_reward_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "max_bad_debt_bps": self.max_bad_debt_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "max_oracle_confidence_bps": self.max_oracle_confidence_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "commit_phase_blocks": self.commit_phase_blocks,
            "reveal_phase_blocks": self.reveal_phase_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "settlement_grace_blocks": self.settlement_grace_blocks,
            "appeal_window_blocks": self.appeal_window_blocks,
            "min_keeper_bond_units": self.min_keeper_bond_units,
            "max_keeper_fee_units": self.max_keeper_fee_units,
            "low_fee_subsidy_budget_units": self.low_fee_subsidy_budget_units,
            "low_fee_min_notional_units": self.low_fee_min_notional_units,
            "low_fee_max_notional_units": self.low_fee_max_notional_units,
            "default_low_fee_lane": self.default_low_fee_lane,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "CONFIDENTIAL-LIQUIDATION-ENGINE-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLiquidationMarket {
    pub market_id: String,
    pub display_name: String,
    pub venue: LiquidationVenue,
    pub status: LiquidationMarketStatus,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub oracle_feed_id: String,
    pub maintenance_margin_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub close_factor_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub keeper_reward_bps: u64,
    pub protocol_fee_bps: u64,
    pub max_auction_notional_units: u64,
    pub min_bid_improvement_bps: u64,
    pub active_account_root: String,
    pub trigger_root: String,
    pub oracle_window_root: String,
    pub auction_window_root: String,
    pub backstop_pool_id: String,
    pub risk_committee_root: String,
    pub pq_guardian_root: String,
    pub created_at_height: u64,
    pub metadata_root: String,
}

impl ConfidentialLiquidationMarket {
    pub fn devnet(created_at_height: u64) -> ConfidentialLiquidationEngineResult<Self> {
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-MARKET-METADATA",
            &json!({
                "label": CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_MARKET_LABEL,
                "venue": "lending",
                "confidential": true
            }),
        );
        let market_id = confidential_liquidation_engine_market_id(
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_MARKET_LABEL,
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_COLLATERAL_ASSET_ID,
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_DEBT_ASSET_ID,
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_ORACLE_FEED_ID,
            created_at_height,
            &metadata_root,
        );
        let market = Self {
            market_id,
            display_name: CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_MARKET_LABEL.to_string(),
            venue: LiquidationVenue::Lending,
            status: LiquidationMarketStatus::Active,
            collateral_asset_id: CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_COLLATERAL_ASSET_ID
                .to_string(),
            debt_asset_id: CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_DEBT_ASSET_ID.to_string(),
            oracle_feed_id: CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_ORACLE_FEED_ID.to_string(),
            maintenance_margin_bps: 1_250,
            liquidation_threshold_bps: 8_250,
            close_factor_bps: 5_000,
            liquidation_penalty_bps: 700,
            keeper_reward_bps: 75,
            protocol_fee_bps: 35,
            max_auction_notional_units: 1_000_000_000_000,
            min_bid_improvement_bps: 25,
            active_account_root: empty_root("CONFIDENTIAL-LIQUIDATION-MARKET-ACCOUNTS"),
            trigger_root: empty_root("CONFIDENTIAL-LIQUIDATION-MARKET-TRIGGERS"),
            oracle_window_root: empty_root("CONFIDENTIAL-LIQUIDATION-MARKET-ORACLES"),
            auction_window_root: empty_root("CONFIDENTIAL-LIQUIDATION-MARKET-AUCTIONS"),
            backstop_pool_id: "devnet-bad-debt-backstop-pool".to_string(),
            risk_committee_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-RISK-COMMITTEE",
                "devnet-liquidation-risk-committee-2-of-3",
            ),
            pq_guardian_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-PQ-GUARDIANS",
                "ml-dsa-87-slh-dsa-devnet-guardians",
            ),
            created_at_height,
            metadata_root,
        };
        market.validate()?;
        Ok(market)
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.market_id, "market market_id")?;
        ensure_non_empty(&self.display_name, "market display_name")?;
        ensure_non_empty(&self.collateral_asset_id, "market collateral_asset_id")?;
        ensure_non_empty(&self.debt_asset_id, "market debt_asset_id")?;
        ensure_non_empty(&self.oracle_feed_id, "market oracle_feed_id")?;
        ensure_non_empty(&self.active_account_root, "market active_account_root")?;
        ensure_non_empty(&self.trigger_root, "market trigger_root")?;
        ensure_non_empty(&self.oracle_window_root, "market oracle_window_root")?;
        ensure_non_empty(&self.auction_window_root, "market auction_window_root")?;
        ensure_non_empty(&self.backstop_pool_id, "market backstop_pool_id")?;
        ensure_non_empty(&self.risk_committee_root, "market risk_committee_root")?;
        ensure_non_empty(&self.pq_guardian_root, "market pq_guardian_root")?;
        ensure_non_empty(&self.metadata_root, "market metadata_root")?;
        ensure_bps(self.maintenance_margin_bps, "market maintenance_margin_bps")?;
        ensure_bps(
            self.liquidation_threshold_bps,
            "market liquidation_threshold_bps",
        )?;
        ensure_bps(self.close_factor_bps, "market close_factor_bps")?;
        ensure_bps(
            self.liquidation_penalty_bps,
            "market liquidation_penalty_bps",
        )?;
        ensure_bps(self.keeper_reward_bps, "market keeper_reward_bps")?;
        ensure_bps(self.protocol_fee_bps, "market protocol_fee_bps")?;
        ensure_bps(
            self.min_bid_improvement_bps,
            "market min_bid_improvement_bps",
        )?;
        if self.maintenance_margin_bps >= self.liquidation_threshold_bps {
            return Err(
                "market maintenance margin must be below liquidation threshold".to_string(),
            );
        }
        if self.close_factor_bps == 0 || self.max_auction_notional_units == 0 {
            return Err(
                "market close factor and max auction notional must be positive".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_liquidation_market",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "display_name": self.display_name,
            "venue": self.venue.as_str(),
            "status": self.status.as_str(),
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "close_factor_bps": self.close_factor_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "keeper_reward_bps": self.keeper_reward_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "max_auction_notional_units": self.max_auction_notional_units,
            "min_bid_improvement_bps": self.min_bid_improvement_bps,
            "active_account_root": self.active_account_root,
            "trigger_root": self.trigger_root,
            "oracle_window_root": self.oracle_window_root,
            "auction_window_root": self.auction_window_root,
            "backstop_pool_id": self.backstop_pool_id,
            "risk_committee_root": self.risk_committee_root,
            "pq_guardian_root": self.pq_guardian_root,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRiskAccount {
    pub account_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub account_nullifier: String,
    pub account_secret_root: String,
    pub status: PrivateRiskAccountStatus,
    pub health_band: ConfidentialHealthBand,
    pub collateral_commitment_root: String,
    pub debt_commitment_root: String,
    pub margin_commitment_root: String,
    pub collateral_lot_root: String,
    pub solvency_proof_root: String,
    pub trigger_root: String,
    pub max_collateral_upper_bound_units: u64,
    pub max_debt_upper_bound_units: u64,
    pub health_factor_floor_bps: u64,
    pub health_factor_ceiling_bps: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub metadata_root: String,
}

impl PrivateRiskAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        owner_label: &str,
        account_secret_root: &str,
        health_band: ConfidentialHealthBand,
        max_collateral_upper_bound_units: u64,
        max_debt_upper_bound_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let owner_commitment = confidential_liquidation_engine_account_commitment(owner_label);
        let account_nullifier = confidential_liquidation_engine_string_root(
            "CONFIDENTIAL-LIQUIDATION-ACCOUNT-NULLIFIER",
            &format!("{market_id}:{owner_label}:{nonce}"),
        );
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-RISK-ACCOUNT-METADATA",
            metadata,
        );
        let account_id = confidential_liquidation_engine_risk_account_id(
            market_id,
            &owner_commitment,
            &account_nullifier,
            opened_at_height,
            nonce,
            &metadata_root,
        );
        let account = Self {
            account_id,
            market_id: market_id.to_string(),
            owner_commitment,
            account_nullifier,
            account_secret_root: account_secret_root.to_string(),
            status: PrivateRiskAccountStatus::Watch,
            health_band,
            collateral_commitment_root: empty_root("CONFIDENTIAL-LIQUIDATION-ACCOUNT-COLLATERAL"),
            debt_commitment_root: empty_root("CONFIDENTIAL-LIQUIDATION-ACCOUNT-DEBT"),
            margin_commitment_root: empty_root("CONFIDENTIAL-LIQUIDATION-ACCOUNT-MARGIN"),
            collateral_lot_root: empty_root("CONFIDENTIAL-LIQUIDATION-ACCOUNT-LOTS"),
            solvency_proof_root: empty_root("CONFIDENTIAL-LIQUIDATION-ACCOUNT-PROOFS"),
            trigger_root: empty_root("CONFIDENTIAL-LIQUIDATION-ACCOUNT-TRIGGERS"),
            max_collateral_upper_bound_units,
            max_debt_upper_bound_units,
            health_factor_floor_bps: health_band.floor_bps(),
            health_factor_ceiling_bps: health_band.ceiling_bps(),
            opened_at_height,
            updated_at_height: opened_at_height,
            expires_at_height,
            nonce,
            metadata_root,
        };
        account.validate()?;
        Ok(account)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.counts_as_active()
            && self.opened_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn is_liquidatable(&self) -> bool {
        self.health_band.can_liquidate()
            || matches!(
                self.status,
                PrivateRiskAccountStatus::Triggered
                    | PrivateRiskAccountStatus::AuctionLocked
                    | PrivateRiskAccountStatus::Settling
            )
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.account_id, "risk account account_id")?;
        ensure_non_empty(&self.market_id, "risk account market_id")?;
        ensure_non_empty(&self.owner_commitment, "risk account owner_commitment")?;
        ensure_non_empty(&self.account_nullifier, "risk account account_nullifier")?;
        ensure_non_empty(
            &self.account_secret_root,
            "risk account account_secret_root",
        )?;
        ensure_non_empty(
            &self.collateral_commitment_root,
            "risk account collateral_commitment_root",
        )?;
        ensure_non_empty(
            &self.debt_commitment_root,
            "risk account debt_commitment_root",
        )?;
        ensure_non_empty(
            &self.margin_commitment_root,
            "risk account margin_commitment_root",
        )?;
        ensure_non_empty(
            &self.collateral_lot_root,
            "risk account collateral_lot_root",
        )?;
        ensure_non_empty(
            &self.solvency_proof_root,
            "risk account solvency_proof_root",
        )?;
        ensure_non_empty(&self.trigger_root, "risk account trigger_root")?;
        ensure_non_empty(&self.metadata_root, "risk account metadata_root")?;
        ensure_ordered_heights(
            self.opened_at_height,
            self.updated_at_height,
            "risk account opened_at_height",
            "risk account updated_at_height",
        )?;
        ensure_ordered_heights(
            self.updated_at_height,
            self.expires_at_height,
            "risk account updated_at_height",
            "risk account expires_at_height",
        )?;
        if self.max_collateral_upper_bound_units == 0 {
            return Err("risk account collateral upper bound must be positive".to_string());
        }
        if self.health_factor_floor_bps > self.health_factor_ceiling_bps {
            return Err("risk account health factor bounds are invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_risk_account",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "account_nullifier": self.account_nullifier,
            "account_secret_root": self.account_secret_root,
            "status": self.status.as_str(),
            "health_band": self.health_band.as_str(),
            "collateral_commitment_root": self.collateral_commitment_root,
            "debt_commitment_root": self.debt_commitment_root,
            "margin_commitment_root": self.margin_commitment_root,
            "collateral_lot_root": self.collateral_lot_root,
            "solvency_proof_root": self.solvency_proof_root,
            "trigger_root": self.trigger_root,
            "max_collateral_upper_bound_units": self.max_collateral_upper_bound_units,
            "max_debt_upper_bound_units": self.max_debt_upper_bound_units,
            "health_factor_floor_bps": self.health_factor_floor_bps,
            "health_factor_ceiling_bps": self.health_factor_ceiling_bps,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialProofBundle {
    pub proof_bundle_id: String,
    pub market_id: String,
    pub account_id: String,
    pub subject_id: String,
    pub proof_kind: ProofBundleKind,
    pub status: ProofBundleStatus,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub public_input_root: String,
    pub private_witness_commitment_root: String,
    pub recursive_proof_root: String,
    pub transcript_commitment: String,
    pub pq_attestation_root: String,
    pub claimed_health_band: ConfidentialHealthBand,
    pub max_disclosed_notional_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl ConfidentialProofBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        account_id: &str,
        subject_id: &str,
        proof_kind: ProofBundleKind,
        claimed_health_band: ConfidentialHealthBand,
        public_input: &Value,
        private_witness_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let public_input_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-PROOF-PUBLIC-INPUT",
            public_input,
        );
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-PROOF-METADATA",
            metadata,
        );
        let recursive_proof_root = confidential_liquidation_engine_proof_root(
            CONFIDENTIAL_LIQUIDATION_ENGINE_SOLVENCY_PROOF_SCHEME,
            &public_input_root,
            private_witness_root,
        );
        let transcript_commitment = confidential_liquidation_engine_string_root(
            "CONFIDENTIAL-LIQUIDATION-PROOF-TRANSCRIPT",
            &format!("{market_id}:{account_id}:{subject_id}:{created_at_height}"),
        );
        let proof_bundle_id = confidential_liquidation_engine_proof_bundle_id(
            market_id,
            account_id,
            subject_id,
            proof_kind.as_str(),
            &public_input_root,
            &recursive_proof_root,
            created_at_height,
            &metadata_root,
        );
        let bundle = Self {
            proof_bundle_id,
            market_id: market_id.to_string(),
            account_id: account_id.to_string(),
            subject_id: subject_id.to_string(),
            proof_kind,
            status: ProofBundleStatus::Verified,
            proof_system: CONFIDENTIAL_LIQUIDATION_ENGINE_SOLVENCY_PROOF_SCHEME.to_string(),
            verifier_key_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-VERIFIER-KEY",
                "devnet-recursive-liquidation-verifier",
            ),
            public_input_root,
            private_witness_commitment_root: private_witness_root.to_string(),
            recursive_proof_root,
            transcript_commitment,
            pq_attestation_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-PQ-ATTESTATION",
                "devnet-proof-attester-set",
            ),
            claimed_health_band,
            max_disclosed_notional_units: 50_000_000,
            created_at_height,
            expires_at_height,
            metadata_root,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.counts_as_accepted()
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.proof_bundle_id, "proof bundle proof_bundle_id")?;
        ensure_non_empty(&self.market_id, "proof bundle market_id")?;
        ensure_non_empty(&self.account_id, "proof bundle account_id")?;
        ensure_non_empty(&self.subject_id, "proof bundle subject_id")?;
        ensure_non_empty(&self.proof_system, "proof bundle proof_system")?;
        ensure_non_empty(&self.verifier_key_root, "proof bundle verifier_key_root")?;
        ensure_non_empty(&self.public_input_root, "proof bundle public_input_root")?;
        ensure_non_empty(
            &self.private_witness_commitment_root,
            "proof bundle private_witness_commitment_root",
        )?;
        ensure_non_empty(
            &self.recursive_proof_root,
            "proof bundle recursive_proof_root",
        )?;
        ensure_non_empty(
            &self.transcript_commitment,
            "proof bundle transcript_commitment",
        )?;
        ensure_non_empty(
            &self.pq_attestation_root,
            "proof bundle pq_attestation_root",
        )?;
        ensure_non_empty(&self.metadata_root, "proof bundle metadata_root")?;
        ensure_ordered_heights(
            self.created_at_height,
            self.expires_at_height,
            "proof bundle created_at_height",
            "proof bundle expires_at_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_proof_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "proof_bundle_id": self.proof_bundle_id,
            "market_id": self.market_id,
            "account_id": self.account_id,
            "subject_id": self.subject_id,
            "proof_kind": self.proof_kind.as_str(),
            "status": self.status.as_str(),
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "public_input_root": self.public_input_root,
            "private_witness_commitment_root": self.private_witness_commitment_root,
            "recursive_proof_root": self.recursive_proof_root,
            "transcript_commitment": self.transcript_commitment,
            "pq_attestation_root": self.pq_attestation_root,
            "claimed_health_band": self.claimed_health_band.as_str(),
            "max_disclosed_notional_units": self.max_disclosed_notional_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleConfidenceWindow {
    pub window_id: String,
    pub market_id: String,
    pub feed_ids: Vec<String>,
    pub status: OracleWindowStatus,
    pub price_commitment_root: String,
    pub median_price_units: u64,
    pub twap_price_units: u64,
    pub lower_bound_price_units: u64,
    pub upper_bound_price_units: u64,
    pub confidence_bps: u64,
    pub max_confidence_bps: u64,
    pub max_deviation_bps: u64,
    pub observed_deviation_bps: u64,
    pub twap_deviation_bps: u64,
    pub publisher_weight_root: String,
    pub guardian_attestation_root: String,
    pub opened_at_height: u64,
    pub observed_at_height: u64,
    pub stale_after_height: u64,
    pub metadata_root: String,
}

impl OracleConfidenceWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        feed_ids: Vec<String>,
        median_price_units: u64,
        confidence_bps: u64,
        max_confidence_bps: u64,
        max_deviation_bps: u64,
        opened_at_height: u64,
        stale_after_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let price_record = json!({
            "market_id": market_id,
            "feeds": feed_ids,
            "median_price_units": median_price_units,
            "confidence_bps": confidence_bps,
        });
        let price_commitment_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-ORACLE-PRICE-COMMITMENT",
            &price_record,
        );
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-ORACLE-METADATA",
            metadata,
        );
        let window_id = confidential_liquidation_engine_oracle_window_id(
            market_id,
            &price_commitment_root,
            opened_at_height,
            stale_after_height,
            &metadata_root,
        );
        let lower_bound_price_units = median_price_units.saturating_sub(
            median_price_units.saturating_mul(confidence_bps)
                / CONFIDENTIAL_LIQUIDATION_ENGINE_MAX_BPS,
        );
        let upper_bound_price_units = median_price_units.saturating_add(
            median_price_units.saturating_mul(confidence_bps)
                / CONFIDENTIAL_LIQUIDATION_ENGINE_MAX_BPS,
        );
        let window = Self {
            window_id,
            market_id: market_id.to_string(),
            feed_ids,
            status: OracleWindowStatus::Guarded,
            price_commitment_root,
            median_price_units,
            twap_price_units: median_price_units.saturating_sub(median_price_units / 200),
            lower_bound_price_units,
            upper_bound_price_units,
            confidence_bps,
            max_confidence_bps,
            max_deviation_bps,
            observed_deviation_bps: 180,
            twap_deviation_bps: 90,
            publisher_weight_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-ORACLE-PUBLISHERS",
                "devnet-oracle-publisher-weight-root",
            ),
            guardian_attestation_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-ORACLE-GUARDIAN-ATTESTATION",
                "devnet-oracle-guardian-signature-root",
            ),
            opened_at_height,
            observed_at_height: opened_at_height,
            stale_after_height,
            metadata_root,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn guarded_at(&self, height: u64) -> bool {
        self.status.allows_liquidation()
            && self.opened_at_height <= height
            && height <= self.stale_after_height
            && self.confidence_bps <= self.max_confidence_bps
            && self.observed_deviation_bps <= self.max_deviation_bps
            && self.twap_deviation_bps <= self.max_deviation_bps
    }

    pub fn feed_root(&self) -> String {
        confidential_liquidation_engine_string_list_root(
            "CONFIDENTIAL-LIQUIDATION-ORACLE-FEED-ROOT",
            &self.feed_ids,
        )
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.window_id, "oracle window window_id")?;
        ensure_non_empty(&self.market_id, "oracle window market_id")?;
        ensure_non_empty(
            &self.price_commitment_root,
            "oracle window price_commitment_root",
        )?;
        ensure_non_empty(
            &self.publisher_weight_root,
            "oracle window publisher_weight_root",
        )?;
        ensure_non_empty(
            &self.guardian_attestation_root,
            "oracle window guardian_attestation_root",
        )?;
        ensure_non_empty(&self.metadata_root, "oracle window metadata_root")?;
        if self.feed_ids.is_empty() || self.feed_ids.iter().any(|feed| feed.trim().is_empty()) {
            return Err("oracle window feed_ids must be non-empty".to_string());
        }
        if self.median_price_units == 0
            || self.lower_bound_price_units == 0
            || self.upper_bound_price_units < self.lower_bound_price_units
        {
            return Err("oracle window price bounds are invalid".to_string());
        }
        ensure_bps(self.confidence_bps, "oracle window confidence_bps")?;
        ensure_bps(self.max_confidence_bps, "oracle window max_confidence_bps")?;
        ensure_bps(self.max_deviation_bps, "oracle window max_deviation_bps")?;
        ensure_bps(
            self.observed_deviation_bps,
            "oracle window observed_deviation_bps",
        )?;
        ensure_bps(self.twap_deviation_bps, "oracle window twap_deviation_bps")?;
        ensure_ordered_heights(
            self.opened_at_height,
            self.observed_at_height,
            "oracle window opened_at_height",
            "oracle window observed_at_height",
        )?;
        ensure_ordered_heights(
            self.observed_at_height,
            self.stale_after_height,
            "oracle window observed_at_height",
            "oracle window stale_after_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_confidence_window",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "market_id": self.market_id,
            "feed_ids": self.feed_ids,
            "feed_root": self.feed_root(),
            "status": self.status.as_str(),
            "price_commitment_root": self.price_commitment_root,
            "median_price_units": self.median_price_units,
            "twap_price_units": self.twap_price_units,
            "lower_bound_price_units": self.lower_bound_price_units,
            "upper_bound_price_units": self.upper_bound_price_units,
            "confidence_bps": self.confidence_bps,
            "max_confidence_bps": self.max_confidence_bps,
            "max_deviation_bps": self.max_deviation_bps,
            "observed_deviation_bps": self.observed_deviation_bps,
            "twap_deviation_bps": self.twap_deviation_bps,
            "publisher_weight_root": self.publisher_weight_root,
            "guardian_attestation_root": self.guardian_attestation_root,
            "opened_at_height": self.opened_at_height,
            "observed_at_height": self.observed_at_height,
            "stale_after_height": self.stale_after_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationTrigger {
    pub trigger_id: String,
    pub market_id: String,
    pub account_id: String,
    pub trigger_kind: LiquidationTriggerKind,
    pub status: LiquidationTriggerStatus,
    pub health_band: ConfidentialHealthBand,
    pub oracle_window_id: String,
    pub proof_bundle_id: String,
    pub account_commitment_root: String,
    pub debt_to_cover_commitment: String,
    pub liquidation_cap_commitment: String,
    pub opened_at_height: u64,
    pub challenge_ends_at_height: u64,
    pub expires_at_height: u64,
    pub priority_score_bps: u64,
    pub auction_window_root: String,
    pub sealed_bid_root: String,
    pub guardian_attestation_root: String,
    pub metadata_root: String,
}

impl LiquidationTrigger {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        account_id: &str,
        trigger_kind: LiquidationTriggerKind,
        health_band: ConfidentialHealthBand,
        oracle_window_id: &str,
        proof_bundle_id: &str,
        opened_at_height: u64,
        challenge_ends_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let account_commitment_root = confidential_liquidation_engine_string_root(
            "CONFIDENTIAL-LIQUIDATION-TRIGGER-ACCOUNT-COMMITMENT",
            account_id,
        );
        let debt_to_cover_commitment = confidential_liquidation_engine_amount_commitment(
            "devnet-private-debt-to-cover",
            15_000_000,
            "trigger-debt-blinding",
        );
        let liquidation_cap_commitment = confidential_liquidation_engine_amount_commitment(
            "devnet-private-liquidation-cap",
            35_000_000,
            "trigger-cap-blinding",
        );
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-TRIGGER-METADATA",
            metadata,
        );
        let trigger_id = confidential_liquidation_engine_trigger_id(
            market_id,
            account_id,
            trigger_kind.as_str(),
            oracle_window_id,
            proof_bundle_id,
            opened_at_height,
            &metadata_root,
        );
        let trigger = Self {
            trigger_id,
            market_id: market_id.to_string(),
            account_id: account_id.to_string(),
            trigger_kind,
            status: LiquidationTriggerStatus::AuctionOpen,
            health_band,
            oracle_window_id: oracle_window_id.to_string(),
            proof_bundle_id: proof_bundle_id.to_string(),
            account_commitment_root,
            debt_to_cover_commitment,
            liquidation_cap_commitment,
            opened_at_height,
            challenge_ends_at_height,
            expires_at_height,
            priority_score_bps: health_band.risk_score_bps(),
            auction_window_root: empty_root("CONFIDENTIAL-LIQUIDATION-TRIGGER-AUCTIONS"),
            sealed_bid_root: empty_root("CONFIDENTIAL-LIQUIDATION-TRIGGER-BIDS"),
            guardian_attestation_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-TRIGGER-GUARDIAN-ATTESTATION",
                "devnet-trigger-guardian-attestation",
            ),
            metadata_root,
        };
        trigger.validate()?;
        Ok(trigger)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.counts_as_live()
            && self.opened_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.trigger_id, "trigger trigger_id")?;
        ensure_non_empty(&self.market_id, "trigger market_id")?;
        ensure_non_empty(&self.account_id, "trigger account_id")?;
        ensure_non_empty(&self.oracle_window_id, "trigger oracle_window_id")?;
        ensure_non_empty(&self.proof_bundle_id, "trigger proof_bundle_id")?;
        ensure_non_empty(
            &self.account_commitment_root,
            "trigger account_commitment_root",
        )?;
        ensure_non_empty(
            &self.debt_to_cover_commitment,
            "trigger debt_to_cover_commitment",
        )?;
        ensure_non_empty(
            &self.liquidation_cap_commitment,
            "trigger liquidation_cap_commitment",
        )?;
        ensure_non_empty(&self.auction_window_root, "trigger auction_window_root")?;
        ensure_non_empty(&self.sealed_bid_root, "trigger sealed_bid_root")?;
        ensure_non_empty(
            &self.guardian_attestation_root,
            "trigger guardian_attestation_root",
        )?;
        ensure_non_empty(&self.metadata_root, "trigger metadata_root")?;
        ensure_bps(self.priority_score_bps, "trigger priority_score_bps")?;
        ensure_ordered_heights(
            self.opened_at_height,
            self.challenge_ends_at_height,
            "trigger opened_at_height",
            "trigger challenge_ends_at_height",
        )?;
        ensure_ordered_heights(
            self.challenge_ends_at_height,
            self.expires_at_height,
            "trigger challenge_ends_at_height",
            "trigger expires_at_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_trigger",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "trigger_id": self.trigger_id,
            "market_id": self.market_id,
            "account_id": self.account_id,
            "trigger_kind": self.trigger_kind.as_str(),
            "status": self.status.as_str(),
            "health_band": self.health_band.as_str(),
            "oracle_window_id": self.oracle_window_id,
            "proof_bundle_id": self.proof_bundle_id,
            "account_commitment_root": self.account_commitment_root,
            "debt_to_cover_commitment": self.debt_to_cover_commitment,
            "liquidation_cap_commitment": self.liquidation_cap_commitment,
            "opened_at_height": self.opened_at_height,
            "challenge_ends_at_height": self.challenge_ends_at_height,
            "expires_at_height": self.expires_at_height,
            "priority_score_bps": self.priority_score_bps,
            "auction_window_root": self.auction_window_root,
            "sealed_bid_root": self.sealed_bid_root,
            "guardian_attestation_root": self.guardian_attestation_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCollateralLot {
    pub lot_id: String,
    pub market_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub status: CollateralLotStatus,
    pub amount_commitment: String,
    pub amount_upper_bound_units: u64,
    pub oracle_value_commitment: String,
    pub liquidation_weight_bps: u64,
    pub lock_nullifier: String,
    pub ciphertext_root: String,
    pub owner_view_key_commitment: String,
    pub keeper_view_policy_root: String,
    pub created_at_height: u64,
    pub locked_until_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl EncryptedCollateralLot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        account_id: &str,
        asset_id: &str,
        amount_upper_bound_units: u64,
        liquidation_weight_bps: u64,
        created_at_height: u64,
        locked_until_height: u64,
        expires_at_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let amount_commitment = confidential_liquidation_engine_amount_commitment(
            "collateral-lot",
            amount_upper_bound_units,
            &format!("lot-blinding-{nonce}"),
        );
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-COLLATERAL-LOT-METADATA",
            metadata,
        );
        let lot_id = confidential_liquidation_engine_collateral_lot_id(
            market_id,
            account_id,
            asset_id,
            &amount_commitment,
            created_at_height,
            nonce,
            &metadata_root,
        );
        let lot = Self {
            lot_id,
            market_id: market_id.to_string(),
            account_id: account_id.to_string(),
            asset_id: asset_id.to_string(),
            status: CollateralLotStatus::LockedForAuction,
            amount_commitment,
            amount_upper_bound_units,
            oracle_value_commitment: confidential_liquidation_engine_amount_commitment(
                "collateral-lot-oracle-value",
                amount_upper_bound_units / 2,
                &format!("lot-value-blinding-{nonce}"),
            ),
            liquidation_weight_bps,
            lock_nullifier: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-COLLATERAL-LOCK-NULLIFIER",
                &format!("{market_id}:{account_id}:{nonce}"),
            ),
            ciphertext_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-COLLATERAL-CIPHERTEXT",
                &format!("ciphertext-{market_id}-{account_id}-{nonce}"),
            ),
            owner_view_key_commitment: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-OWNER-VIEW-KEY",
                &format!("owner-view-{account_id}-{nonce}"),
            ),
            keeper_view_policy_root: confidential_liquidation_engine_payload_root(
                "CONFIDENTIAL-LIQUIDATION-KEEPER-VIEW-POLICY",
                &json!({"policy": "winner_only", "lot_nonce": nonce}),
            ),
            created_at_height,
            locked_until_height,
            expires_at_height,
            metadata_root,
        };
        lot.validate()?;
        Ok(lot)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.counts_as_open()
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.lot_id, "collateral lot lot_id")?;
        ensure_non_empty(&self.market_id, "collateral lot market_id")?;
        ensure_non_empty(&self.account_id, "collateral lot account_id")?;
        ensure_non_empty(&self.asset_id, "collateral lot asset_id")?;
        ensure_non_empty(&self.amount_commitment, "collateral lot amount_commitment")?;
        ensure_non_empty(
            &self.oracle_value_commitment,
            "collateral lot oracle_value_commitment",
        )?;
        ensure_non_empty(&self.lock_nullifier, "collateral lot lock_nullifier")?;
        ensure_non_empty(&self.ciphertext_root, "collateral lot ciphertext_root")?;
        ensure_non_empty(
            &self.owner_view_key_commitment,
            "collateral lot owner_view_key_commitment",
        )?;
        ensure_non_empty(
            &self.keeper_view_policy_root,
            "collateral lot keeper_view_policy_root",
        )?;
        ensure_non_empty(&self.metadata_root, "collateral lot metadata_root")?;
        ensure_bps(
            self.liquidation_weight_bps,
            "collateral lot liquidation_weight_bps",
        )?;
        if self.amount_upper_bound_units == 0 {
            return Err("collateral lot amount upper bound must be positive".to_string());
        }
        ensure_ordered_heights(
            self.created_at_height,
            self.locked_until_height,
            "collateral lot created_at_height",
            "collateral lot locked_until_height",
        )?;
        ensure_ordered_heights(
            self.locked_until_height,
            self.expires_at_height,
            "collateral lot locked_until_height",
            "collateral lot expires_at_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_collateral_lot",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "lot_id": self.lot_id,
            "market_id": self.market_id,
            "account_id": self.account_id,
            "asset_id": self.asset_id,
            "status": self.status.as_str(),
            "amount_commitment": self.amount_commitment,
            "amount_upper_bound_units": self.amount_upper_bound_units,
            "oracle_value_commitment": self.oracle_value_commitment,
            "liquidation_weight_bps": self.liquidation_weight_bps,
            "lock_nullifier": self.lock_nullifier,
            "ciphertext_root": self.ciphertext_root,
            "owner_view_key_commitment": self.owner_view_key_commitment,
            "keeper_view_policy_root": self.keeper_view_policy_root,
            "created_at_height": self.created_at_height,
            "locked_until_height": self.locked_until_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevSafeAuctionWindow {
    pub auction_window_id: String,
    pub market_id: String,
    pub trigger_id: String,
    pub status: AuctionWindowStatus,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_start_height: u64,
    pub reveal_end_height: u64,
    pub settlement_deadline_height: u64,
    pub min_bid_count: u64,
    pub max_keeper_count: u64,
    pub bid_root: String,
    pub encrypted_orderflow_root: String,
    pub anti_mev_salt_commitment: String,
    pub threshold_decryption_committee_root: String,
    pub fair_ordering_transcript_root: String,
    pub metadata_root: String,
}

impl MevSafeAuctionWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        trigger_id: &str,
        commit_start_height: u64,
        commit_end_height: u64,
        reveal_start_height: u64,
        reveal_end_height: u64,
        settlement_deadline_height: u64,
        min_bid_count: u64,
        max_keeper_count: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-AUCTION-WINDOW-METADATA",
            metadata,
        );
        let auction_window_id = confidential_liquidation_engine_auction_window_id(
            market_id,
            trigger_id,
            commit_start_height,
            reveal_end_height,
            &metadata_root,
        );
        let window = Self {
            auction_window_id,
            market_id: market_id.to_string(),
            trigger_id: trigger_id.to_string(),
            status: AuctionWindowStatus::RevealOpen,
            commit_start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            settlement_deadline_height,
            min_bid_count,
            max_keeper_count,
            bid_root: empty_root("CONFIDENTIAL-LIQUIDATION-AUCTION-BIDS"),
            encrypted_orderflow_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-ENCRYPTED-ORDERFLOW",
                &format!("{market_id}:{trigger_id}:{commit_start_height}"),
            ),
            anti_mev_salt_commitment: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-ANTI-MEV-SALT",
                &format!("{trigger_id}:{reveal_end_height}"),
            ),
            threshold_decryption_committee_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-THRESHOLD-DECRYPTION-COMMITTEE",
                "devnet-keeper-auction-decryption-committee",
            ),
            fair_ordering_transcript_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-FAIR-ORDERING-TRANSCRIPT",
                &format!("fair-ordering-{trigger_id}"),
            ),
            metadata_root,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn is_commit_open_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            AuctionWindowStatus::CommitOpen | AuctionWindowStatus::RevealOpen
        ) && self.commit_start_height <= height
            && height <= self.commit_end_height
    }

    pub fn is_reveal_open_at(&self, height: u64) -> bool {
        matches!(self.status, AuctionWindowStatus::RevealOpen)
            && self.reveal_start_height <= height
            && height <= self.reveal_end_height
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.is_commit_open_at(height)
            || self.is_reveal_open_at(height)
            || (matches!(self.status, AuctionWindowStatus::SettlementOpen)
                && height <= self.settlement_deadline_height)
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.auction_window_id, "auction window auction_window_id")?;
        ensure_non_empty(&self.market_id, "auction window market_id")?;
        ensure_non_empty(&self.trigger_id, "auction window trigger_id")?;
        ensure_non_empty(&self.bid_root, "auction window bid_root")?;
        ensure_non_empty(
            &self.encrypted_orderflow_root,
            "auction window encrypted_orderflow_root",
        )?;
        ensure_non_empty(
            &self.anti_mev_salt_commitment,
            "auction window anti_mev_salt_commitment",
        )?;
        ensure_non_empty(
            &self.threshold_decryption_committee_root,
            "auction window threshold_decryption_committee_root",
        )?;
        ensure_non_empty(
            &self.fair_ordering_transcript_root,
            "auction window fair_ordering_transcript_root",
        )?;
        ensure_non_empty(&self.metadata_root, "auction window metadata_root")?;
        ensure_ordered_heights(
            self.commit_start_height,
            self.commit_end_height,
            "auction window commit_start_height",
            "auction window commit_end_height",
        )?;
        ensure_ordered_heights(
            self.commit_end_height,
            self.reveal_start_height,
            "auction window commit_end_height",
            "auction window reveal_start_height",
        )?;
        ensure_ordered_heights(
            self.reveal_start_height,
            self.reveal_end_height,
            "auction window reveal_start_height",
            "auction window reveal_end_height",
        )?;
        ensure_ordered_heights(
            self.reveal_end_height,
            self.settlement_deadline_height,
            "auction window reveal_end_height",
            "auction window settlement_deadline_height",
        )?;
        if self.min_bid_count == 0 || self.max_keeper_count == 0 {
            return Err("auction window bid and keeper counts must be positive".to_string());
        }
        if self.min_bid_count > self.max_keeper_count {
            return Err("auction window min_bid_count exceeds max_keeper_count".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "mev_safe_auction_window",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "auction_window_id": self.auction_window_id,
            "market_id": self.market_id,
            "trigger_id": self.trigger_id,
            "status": self.status.as_str(),
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_end_height": self.reveal_end_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "min_bid_count": self.min_bid_count,
            "max_keeper_count": self.max_keeper_count,
            "bid_root": self.bid_root,
            "encrypted_orderflow_root": self.encrypted_orderflow_root,
            "anti_mev_salt_commitment": self.anti_mev_salt_commitment,
            "threshold_decryption_committee_root": self.threshold_decryption_committee_root,
            "fair_ordering_transcript_root": self.fair_ordering_transcript_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSubsidyTicket {
    pub ticket_id: String,
    pub market_id: String,
    pub sponsor_commitment: String,
    pub keeper_commitment: String,
    pub lane_id: String,
    pub status: LowFeeSubsidyStatus,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_reimbursement_units: u64,
    pub min_notional_units: u64,
    pub max_notional_units: u64,
    pub eligible_trigger_root: String,
    pub fee_asset_id: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl LowFeeSubsidyTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        sponsor_label: &str,
        keeper_label: &str,
        lane_id: &str,
        fee_asset_id: &str,
        budget_units: u64,
        max_reimbursement_units: u64,
        issued_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let sponsor_commitment = confidential_liquidation_engine_account_commitment(sponsor_label);
        let keeper_commitment = confidential_liquidation_engine_account_commitment(keeper_label);
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-SUBSIDY-METADATA",
            metadata,
        );
        let ticket_id = confidential_liquidation_engine_subsidy_ticket_id(
            market_id,
            &sponsor_commitment,
            &keeper_commitment,
            lane_id,
            issued_at_height,
            &metadata_root,
        );
        let ticket = Self {
            ticket_id,
            market_id: market_id.to_string(),
            sponsor_commitment,
            keeper_commitment,
            lane_id: lane_id.to_string(),
            status: LowFeeSubsidyStatus::Active,
            budget_units,
            reserved_units: max_reimbursement_units,
            spent_units: 0,
            max_reimbursement_units,
            min_notional_units: 100_000,
            max_notional_units: 50_000_000,
            eligible_trigger_root: empty_root("CONFIDENTIAL-LIQUIDATION-SUBSIDY-TRIGGERS"),
            fee_asset_id: fee_asset_id.to_string(),
            issued_at_height,
            expires_at_height,
            metadata_root,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.counts_as_active()
            && self.issued_at_height <= height
            && height <= self.expires_at_height
            && self.remaining_units() > 0
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.ticket_id, "subsidy ticket ticket_id")?;
        ensure_non_empty(&self.market_id, "subsidy ticket market_id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "subsidy ticket sponsor_commitment",
        )?;
        ensure_non_empty(&self.keeper_commitment, "subsidy ticket keeper_commitment")?;
        ensure_non_empty(&self.lane_id, "subsidy ticket lane_id")?;
        ensure_non_empty(
            &self.eligible_trigger_root,
            "subsidy ticket eligible_trigger_root",
        )?;
        ensure_non_empty(&self.fee_asset_id, "subsidy ticket fee_asset_id")?;
        ensure_non_empty(&self.metadata_root, "subsidy ticket metadata_root")?;
        if self.budget_units == 0
            || self.max_reimbursement_units == 0
            || self.reserved_units > self.budget_units
            || self.spent_units > self.budget_units
        {
            return Err("subsidy ticket budget fields are invalid".to_string());
        }
        if self.min_notional_units > self.max_notional_units {
            return Err("subsidy ticket notional bounds are invalid".to_string());
        }
        ensure_ordered_heights(
            self.issued_at_height,
            self.expires_at_height,
            "subsidy ticket issued_at_height",
            "subsidy ticket expires_at_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_subsidy_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "market_id": self.market_id,
            "sponsor_commitment": self.sponsor_commitment,
            "keeper_commitment": self.keeper_commitment,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_reimbursement_units": self.max_reimbursement_units,
            "min_notional_units": self.min_notional_units,
            "max_notional_units": self.max_notional_units,
            "eligible_trigger_root": self.eligible_trigger_root,
            "fee_asset_id": self.fee_asset_id,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKeeperBid {
    pub bid_id: String,
    pub market_id: String,
    pub trigger_id: String,
    pub auction_window_id: String,
    pub collateral_lot_id: String,
    pub keeper_commitment: String,
    pub keeper_bond_commitment: String,
    pub sealed_bid_commitment: String,
    pub encrypted_reveal_root: String,
    pub repay_amount_commitment: String,
    pub collateral_take_commitment: String,
    pub price_limit_commitment: String,
    pub bid_validity_proof_id: String,
    pub subsidy_ticket_id: String,
    pub status: SealedBidStatus,
    pub discount_bps: u64,
    pub max_fee_units: u64,
    pub priority_fee_units: u64,
    pub committed_at_height: u64,
    pub reveal_after_height: u64,
    pub reveal_before_height: u64,
    pub settlement_deadline_height: u64,
    pub metadata_root: String,
}

impl SealedKeeperBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        trigger_id: &str,
        auction_window_id: &str,
        collateral_lot_id: &str,
        keeper_label: &str,
        bid_validity_proof_id: &str,
        subsidy_ticket_id: &str,
        discount_bps: u64,
        max_fee_units: u64,
        committed_at_height: u64,
        reveal_after_height: u64,
        reveal_before_height: u64,
        settlement_deadline_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let keeper_commitment = confidential_liquidation_engine_account_commitment(keeper_label);
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-BID-METADATA",
            metadata,
        );
        let sealed_bid_commitment = confidential_liquidation_engine_string_root(
            "CONFIDENTIAL-LIQUIDATION-SEALED-BID-COMMITMENT",
            &format!("{trigger_id}:{keeper_label}:{discount_bps}:{nonce}"),
        );
        let bid_id = confidential_liquidation_engine_sealed_bid_id(
            trigger_id,
            auction_window_id,
            &keeper_commitment,
            &sealed_bid_commitment,
            committed_at_height,
            &metadata_root,
        );
        let bid = Self {
            bid_id,
            market_id: market_id.to_string(),
            trigger_id: trigger_id.to_string(),
            auction_window_id: auction_window_id.to_string(),
            collateral_lot_id: collateral_lot_id.to_string(),
            keeper_commitment,
            keeper_bond_commitment: confidential_liquidation_engine_amount_commitment(
                "keeper-bond",
                250_000,
                &format!("keeper-bond-blinding-{nonce}"),
            ),
            sealed_bid_commitment,
            encrypted_reveal_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-BID-ENCRYPTED-REVEAL",
                &format!("encrypted-reveal-{trigger_id}-{nonce}"),
            ),
            repay_amount_commitment: confidential_liquidation_engine_amount_commitment(
                "bid-repay-amount",
                15_000_000,
                &format!("repay-blinding-{nonce}"),
            ),
            collateral_take_commitment: confidential_liquidation_engine_amount_commitment(
                "bid-collateral-take",
                24_000_000,
                &format!("take-blinding-{nonce}"),
            ),
            price_limit_commitment: confidential_liquidation_engine_amount_commitment(
                "bid-price-limit",
                160 * CONFIDENTIAL_LIQUIDATION_ENGINE_PRICE_SCALE,
                &format!("price-limit-blinding-{nonce}"),
            ),
            bid_validity_proof_id: bid_validity_proof_id.to_string(),
            subsidy_ticket_id: subsidy_ticket_id.to_string(),
            status: SealedBidStatus::Decrypted,
            discount_bps,
            max_fee_units,
            priority_fee_units: 0,
            committed_at_height,
            reveal_after_height,
            reveal_before_height,
            settlement_deadline_height,
            metadata_root,
        };
        bid.validate()?;
        Ok(bid)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.counts_as_live()
            && self.committed_at_height <= height
            && height <= self.settlement_deadline_height
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.bid_id, "sealed bid bid_id")?;
        ensure_non_empty(&self.market_id, "sealed bid market_id")?;
        ensure_non_empty(&self.trigger_id, "sealed bid trigger_id")?;
        ensure_non_empty(&self.auction_window_id, "sealed bid auction_window_id")?;
        ensure_non_empty(&self.collateral_lot_id, "sealed bid collateral_lot_id")?;
        ensure_non_empty(&self.keeper_commitment, "sealed bid keeper_commitment")?;
        ensure_non_empty(
            &self.keeper_bond_commitment,
            "sealed bid keeper_bond_commitment",
        )?;
        ensure_non_empty(
            &self.sealed_bid_commitment,
            "sealed bid sealed_bid_commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_reveal_root,
            "sealed bid encrypted_reveal_root",
        )?;
        ensure_non_empty(
            &self.repay_amount_commitment,
            "sealed bid repay_amount_commitment",
        )?;
        ensure_non_empty(
            &self.collateral_take_commitment,
            "sealed bid collateral_take_commitment",
        )?;
        ensure_non_empty(
            &self.price_limit_commitment,
            "sealed bid price_limit_commitment",
        )?;
        ensure_non_empty(
            &self.bid_validity_proof_id,
            "sealed bid bid_validity_proof_id",
        )?;
        ensure_non_empty(&self.metadata_root, "sealed bid metadata_root")?;
        ensure_bps(self.discount_bps, "sealed bid discount_bps")?;
        if self.max_fee_units == 0 {
            return Err("sealed bid max_fee_units must be positive".to_string());
        }
        ensure_ordered_heights(
            self.committed_at_height,
            self.reveal_after_height,
            "sealed bid committed_at_height",
            "sealed bid reveal_after_height",
        )?;
        ensure_ordered_heights(
            self.reveal_after_height,
            self.reveal_before_height,
            "sealed bid reveal_after_height",
            "sealed bid reveal_before_height",
        )?;
        ensure_ordered_heights(
            self.reveal_before_height,
            self.settlement_deadline_height,
            "sealed bid reveal_before_height",
            "sealed bid settlement_deadline_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_keeper_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "market_id": self.market_id,
            "trigger_id": self.trigger_id,
            "auction_window_id": self.auction_window_id,
            "collateral_lot_id": self.collateral_lot_id,
            "keeper_commitment": self.keeper_commitment,
            "keeper_bond_commitment": self.keeper_bond_commitment,
            "sealed_bid_commitment": self.sealed_bid_commitment,
            "encrypted_reveal_root": self.encrypted_reveal_root,
            "repay_amount_commitment": self.repay_amount_commitment,
            "collateral_take_commitment": self.collateral_take_commitment,
            "price_limit_commitment": self.price_limit_commitment,
            "bid_validity_proof_id": self.bid_validity_proof_id,
            "subsidy_ticket_id": self.subsidy_ticket_id,
            "status": self.status.as_str(),
            "discount_bps": self.discount_bps,
            "max_fee_units": self.max_fee_units,
            "priority_fee_units": self.priority_fee_units,
            "committed_at_height": self.committed_at_height,
            "reveal_after_height": self.reveal_after_height,
            "reveal_before_height": self.reveal_before_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub market_id: String,
    pub trigger_id: String,
    pub auction_window_id: String,
    pub winning_bid_id: String,
    pub account_id: String,
    pub settled_lot_ids: Vec<String>,
    pub status: SettlementStatus,
    pub repaid_debt_commitment: String,
    pub collateral_paid_commitment: String,
    pub keeper_fee_units: u64,
    pub subsidy_units: u64,
    pub protocol_fee_units: u64,
    pub bad_debt_units: u64,
    pub conservation_proof_id: String,
    pub backstop_action_root: String,
    pub appeal_root: String,
    pub settled_at_height: u64,
    pub finalizes_at_height: u64,
    pub metadata_root: String,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        trigger_id: &str,
        auction_window_id: &str,
        winning_bid_id: &str,
        account_id: &str,
        settled_lot_ids: Vec<String>,
        conservation_proof_id: &str,
        bad_debt_units: u64,
        settled_at_height: u64,
        finalizes_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-SETTLEMENT-METADATA",
            metadata,
        );
        let lot_root = confidential_liquidation_engine_string_list_root(
            "CONFIDENTIAL-LIQUIDATION-SETTLED-LOT-ROOT",
            &settled_lot_ids,
        );
        let receipt_id = confidential_liquidation_engine_settlement_receipt_id(
            market_id,
            trigger_id,
            winning_bid_id,
            &lot_root,
            settled_at_height,
            &metadata_root,
        );
        let receipt = Self {
            receipt_id,
            market_id: market_id.to_string(),
            trigger_id: trigger_id.to_string(),
            auction_window_id: auction_window_id.to_string(),
            winning_bid_id: winning_bid_id.to_string(),
            account_id: account_id.to_string(),
            settled_lot_ids,
            status: SettlementStatus::PendingFinality,
            repaid_debt_commitment: confidential_liquidation_engine_amount_commitment(
                "settlement-repaid-debt",
                15_000_000,
                "settlement-repaid-debt-blinding",
            ),
            collateral_paid_commitment: confidential_liquidation_engine_amount_commitment(
                "settlement-collateral-paid",
                24_000_000,
                "settlement-collateral-paid-blinding",
            ),
            keeper_fee_units: 4_000,
            subsidy_units: 4_000,
            protocol_fee_units: 1_250,
            bad_debt_units,
            conservation_proof_id: conservation_proof_id.to_string(),
            backstop_action_root: empty_root("CONFIDENTIAL-LIQUIDATION-SETTLEMENT-BACKSTOP"),
            appeal_root: empty_root("CONFIDENTIAL-LIQUIDATION-SETTLEMENT-APPEALS"),
            settled_at_height,
            finalizes_at_height,
            metadata_root,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn lot_root(&self) -> String {
        confidential_liquidation_engine_string_list_root(
            "CONFIDENTIAL-LIQUIDATION-SETTLED-LOT-ROOT",
            &self.settled_lot_ids,
        )
    }

    pub fn has_bad_debt(&self) -> bool {
        self.bad_debt_units > 0
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.receipt_id, "settlement receipt receipt_id")?;
        ensure_non_empty(&self.market_id, "settlement receipt market_id")?;
        ensure_non_empty(&self.trigger_id, "settlement receipt trigger_id")?;
        ensure_non_empty(
            &self.auction_window_id,
            "settlement receipt auction_window_id",
        )?;
        ensure_non_empty(&self.winning_bid_id, "settlement receipt winning_bid_id")?;
        ensure_non_empty(&self.account_id, "settlement receipt account_id")?;
        ensure_non_empty(
            &self.repaid_debt_commitment,
            "settlement receipt repaid_debt_commitment",
        )?;
        ensure_non_empty(
            &self.collateral_paid_commitment,
            "settlement receipt collateral_paid_commitment",
        )?;
        ensure_non_empty(
            &self.conservation_proof_id,
            "settlement receipt conservation_proof_id",
        )?;
        ensure_non_empty(
            &self.backstop_action_root,
            "settlement receipt backstop_action_root",
        )?;
        ensure_non_empty(&self.appeal_root, "settlement receipt appeal_root")?;
        ensure_non_empty(&self.metadata_root, "settlement receipt metadata_root")?;
        if self.settled_lot_ids.is_empty()
            || self
                .settled_lot_ids
                .iter()
                .any(|lot_id| lot_id.trim().is_empty())
        {
            return Err("settlement receipt settled_lot_ids must be non-empty".to_string());
        }
        ensure_ordered_heights(
            self.settled_at_height,
            self.finalizes_at_height,
            "settlement receipt settled_at_height",
            "settlement receipt finalizes_at_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "market_id": self.market_id,
            "trigger_id": self.trigger_id,
            "auction_window_id": self.auction_window_id,
            "winning_bid_id": self.winning_bid_id,
            "account_id": self.account_id,
            "settled_lot_ids": self.settled_lot_ids,
            "settled_lot_root": self.lot_root(),
            "status": self.status.as_str(),
            "repaid_debt_commitment": self.repaid_debt_commitment,
            "collateral_paid_commitment": self.collateral_paid_commitment,
            "keeper_fee_units": self.keeper_fee_units,
            "subsidy_units": self.subsidy_units,
            "protocol_fee_units": self.protocol_fee_units,
            "bad_debt_units": self.bad_debt_units,
            "conservation_proof_id": self.conservation_proof_id,
            "backstop_action_root": self.backstop_action_root,
            "appeal_root": self.appeal_root,
            "settled_at_height": self.settled_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackstopPoolAction {
    pub action_id: String,
    pub pool_id: String,
    pub market_id: String,
    pub receipt_id: String,
    pub action_kind: BackstopActionKind,
    pub status: BackstopActionStatus,
    pub asset_id: String,
    pub amount_units: u64,
    pub post_balance_floor_units: u64,
    pub post_liability_ceiling_units: u64,
    pub solvency_proof_id: String,
    pub pq_authorization_root: String,
    pub applied_at_height: u64,
    pub finalizes_at_height: u64,
    pub metadata_root: String,
}

impl BackstopPoolAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        market_id: &str,
        receipt_id: &str,
        action_kind: BackstopActionKind,
        asset_id: &str,
        amount_units: u64,
        solvency_proof_id: &str,
        applied_at_height: u64,
        finalizes_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-BACKSTOP-METADATA",
            metadata,
        );
        let action_id = confidential_liquidation_engine_backstop_action_id(
            pool_id,
            market_id,
            receipt_id,
            action_kind.as_str(),
            amount_units,
            applied_at_height,
            &metadata_root,
        );
        let action = Self {
            action_id,
            pool_id: pool_id.to_string(),
            market_id: market_id.to_string(),
            receipt_id: receipt_id.to_string(),
            action_kind,
            status: BackstopActionStatus::PendingFinality,
            asset_id: asset_id.to_string(),
            amount_units,
            post_balance_floor_units: 750_000_000_u64.saturating_sub(amount_units),
            post_liability_ceiling_units: amount_units,
            solvency_proof_id: solvency_proof_id.to_string(),
            pq_authorization_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-BACKSTOP-PQ-AUTH",
                "devnet-backstop-council-approval",
            ),
            applied_at_height,
            finalizes_at_height,
            metadata_root,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.action_id, "backstop action action_id")?;
        ensure_non_empty(&self.pool_id, "backstop action pool_id")?;
        ensure_non_empty(&self.market_id, "backstop action market_id")?;
        ensure_non_empty(&self.receipt_id, "backstop action receipt_id")?;
        ensure_non_empty(&self.asset_id, "backstop action asset_id")?;
        ensure_non_empty(&self.solvency_proof_id, "backstop action solvency_proof_id")?;
        ensure_non_empty(
            &self.pq_authorization_root,
            "backstop action pq_authorization_root",
        )?;
        ensure_non_empty(&self.metadata_root, "backstop action metadata_root")?;
        if self.amount_units == 0 {
            return Err("backstop action amount_units must be positive".to_string());
        }
        ensure_ordered_heights(
            self.applied_at_height,
            self.finalizes_at_height,
            "backstop action applied_at_height",
            "backstop action finalizes_at_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "backstop_pool_action",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "action_id": self.action_id,
            "pool_id": self.pool_id,
            "market_id": self.market_id,
            "receipt_id": self.receipt_id,
            "action_kind": self.action_kind.as_str(),
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "post_balance_floor_units": self.post_balance_floor_units,
            "post_liability_ceiling_units": self.post_liability_ceiling_units,
            "solvency_proof_id": self.solvency_proof_id,
            "pq_authorization_root": self.pq_authorization_root,
            "applied_at_height": self.applied_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationAppeal {
    pub appeal_id: String,
    pub market_id: String,
    pub trigger_id: String,
    pub receipt_id: String,
    pub appellant_commitment: String,
    pub status: AppealStatus,
    pub decision: AppealDecision,
    pub severity: LiquidationRiskSeverity,
    pub reason_code: String,
    pub evidence_root: String,
    pub private_disclosure_root: String,
    pub bond_commitment: String,
    pub reviewer_set_root: String,
    pub opened_at_height: u64,
    pub evidence_locked_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl LiquidationAppeal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        trigger_id: &str,
        receipt_id: &str,
        appellant_label: &str,
        reason_code: &str,
        opened_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let appellant_commitment =
            confidential_liquidation_engine_account_commitment(appellant_label);
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-APPEAL-METADATA",
            metadata,
        );
        let appeal_id = confidential_liquidation_engine_appeal_id(
            market_id,
            trigger_id,
            receipt_id,
            &appellant_commitment,
            opened_at_height,
            &metadata_root,
        );
        let appeal = Self {
            appeal_id,
            market_id: market_id.to_string(),
            trigger_id: trigger_id.to_string(),
            receipt_id: receipt_id.to_string(),
            appellant_commitment,
            status: AppealStatus::Open,
            decision: AppealDecision::Pending,
            severity: LiquidationRiskSeverity::Watch,
            reason_code: reason_code.to_string(),
            evidence_root: confidential_liquidation_engine_payload_root(
                "CONFIDENTIAL-LIQUIDATION-APPEAL-EVIDENCE",
                &json!({"reason_code": reason_code, "privacy": "selective_disclosure"}),
            ),
            private_disclosure_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-APPEAL-PRIVATE-DISCLOSURE",
                &format!("{trigger_id}:{receipt_id}:{appellant_label}"),
            ),
            bond_commitment: confidential_liquidation_engine_amount_commitment(
                "appeal-bond",
                125_000,
                "appeal-bond-blinding",
            ),
            reviewer_set_root: confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-APPEAL-REVIEWERS",
                "devnet-private-risk-review-panel",
            ),
            opened_at_height,
            evidence_locked_at_height: opened_at_height.saturating_add(4),
            expires_at_height,
            metadata_root,
        };
        appeal.validate()?;
        Ok(appeal)
    }

    pub fn pending_at(&self, height: u64) -> bool {
        self.status.counts_as_pending()
            && self.opened_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.appeal_id, "appeal appeal_id")?;
        ensure_non_empty(&self.market_id, "appeal market_id")?;
        ensure_non_empty(&self.trigger_id, "appeal trigger_id")?;
        ensure_non_empty(&self.receipt_id, "appeal receipt_id")?;
        ensure_non_empty(&self.appellant_commitment, "appeal appellant_commitment")?;
        ensure_non_empty(&self.reason_code, "appeal reason_code")?;
        ensure_non_empty(&self.evidence_root, "appeal evidence_root")?;
        ensure_non_empty(
            &self.private_disclosure_root,
            "appeal private_disclosure_root",
        )?;
        ensure_non_empty(&self.bond_commitment, "appeal bond_commitment")?;
        ensure_non_empty(&self.reviewer_set_root, "appeal reviewer_set_root")?;
        ensure_non_empty(&self.metadata_root, "appeal metadata_root")?;
        ensure_ordered_heights(
            self.opened_at_height,
            self.evidence_locked_at_height,
            "appeal opened_at_height",
            "appeal evidence_locked_at_height",
        )?;
        ensure_ordered_heights(
            self.evidence_locked_at_height,
            self.expires_at_height,
            "appeal evidence_locked_at_height",
            "appeal expires_at_height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_appeal",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "appeal_id": self.appeal_id,
            "market_id": self.market_id,
            "trigger_id": self.trigger_id,
            "receipt_id": self.receipt_id,
            "appellant_commitment": self.appellant_commitment,
            "status": self.status.as_str(),
            "decision": self.decision.as_str(),
            "severity": self.severity.as_str(),
            "reason_code": self.reason_code,
            "evidence_root": self.evidence_root,
            "private_disclosure_root": self.private_disclosure_root,
            "bond_commitment": self.bond_commitment,
            "reviewer_set_root": self.reviewer_set_root,
            "opened_at_height": self.opened_at_height,
            "evidence_locked_at_height": self.evidence_locked_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLiquidationPublicRecord {
    pub record_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub redaction_policy: String,
    pub emitted_at_height: u64,
    pub metadata_root: String,
}

impl ConfidentialLiquidationPublicRecord {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        subject_root: &str,
        redaction_policy: &str,
        emitted_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        let metadata_root = confidential_liquidation_engine_payload_root(
            "CONFIDENTIAL-LIQUIDATION-PUBLIC-RECORD-METADATA",
            metadata,
        );
        let record_id = confidential_liquidation_engine_public_record_id(
            event_kind,
            subject_id,
            subject_root,
            emitted_at_height,
            &metadata_root,
        );
        let record = Self {
            record_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            redaction_policy: redaction_policy.to_string(),
            emitted_at_height,
            metadata_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<()> {
        ensure_non_empty(&self.record_id, "public record record_id")?;
        ensure_non_empty(&self.event_kind, "public record event_kind")?;
        ensure_non_empty(&self.subject_id, "public record subject_id")?;
        ensure_non_empty(&self.subject_root, "public record subject_root")?;
        ensure_non_empty(&self.redaction_policy, "public record redaction_policy")?;
        ensure_non_empty(&self.metadata_root, "public record metadata_root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_liquidation_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "redaction_policy": self.redaction_policy,
            "emitted_at_height": self.emitted_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLiquidationEngineCounters {
    pub market_count: u64,
    pub active_market_count: u64,
    pub private_risk_account_count: u64,
    pub active_private_risk_account_count: u64,
    pub liquidatable_private_risk_account_count: u64,
    pub liquidation_trigger_count: u64,
    pub live_liquidation_trigger_count: u64,
    pub encrypted_collateral_lot_count: u64,
    pub locked_collateral_lot_count: u64,
    pub sealed_keeper_bid_count: u64,
    pub live_sealed_keeper_bid_count: u64,
    pub proof_bundle_count: u64,
    pub accepted_proof_bundle_count: u64,
    pub oracle_window_count: u64,
    pub guarded_oracle_window_count: u64,
    pub auction_window_count: u64,
    pub open_auction_window_count: u64,
    pub low_fee_subsidy_ticket_count: u64,
    pub active_low_fee_subsidy_ticket_count: u64,
    pub settlement_receipt_count: u64,
    pub bad_debt_receipt_count: u64,
    pub backstop_action_count: u64,
    pub pending_appeal_count: u64,
    pub public_record_count: u64,
    pub total_collateral_upper_bound_units: u64,
    pub total_debt_upper_bound_units: u64,
    pub total_subsidy_reserved_units: u64,
    pub total_subsidy_spent_units: u64,
    pub total_bad_debt_units: u64,
    pub total_backstop_post_balance_floor_units: u64,
    pub aggregate_risk_score_bps: u64,
}

impl ConfidentialLiquidationEngineCounters {
    pub fn risk_status(&self) -> &'static str {
        liquidation_engine_risk_status(self.aggregate_risk_score_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_liquidation_engine_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "market_count": self.market_count,
            "active_market_count": self.active_market_count,
            "private_risk_account_count": self.private_risk_account_count,
            "active_private_risk_account_count": self.active_private_risk_account_count,
            "liquidatable_private_risk_account_count": self.liquidatable_private_risk_account_count,
            "liquidation_trigger_count": self.liquidation_trigger_count,
            "live_liquidation_trigger_count": self.live_liquidation_trigger_count,
            "encrypted_collateral_lot_count": self.encrypted_collateral_lot_count,
            "locked_collateral_lot_count": self.locked_collateral_lot_count,
            "sealed_keeper_bid_count": self.sealed_keeper_bid_count,
            "live_sealed_keeper_bid_count": self.live_sealed_keeper_bid_count,
            "proof_bundle_count": self.proof_bundle_count,
            "accepted_proof_bundle_count": self.accepted_proof_bundle_count,
            "oracle_window_count": self.oracle_window_count,
            "guarded_oracle_window_count": self.guarded_oracle_window_count,
            "auction_window_count": self.auction_window_count,
            "open_auction_window_count": self.open_auction_window_count,
            "low_fee_subsidy_ticket_count": self.low_fee_subsidy_ticket_count,
            "active_low_fee_subsidy_ticket_count": self.active_low_fee_subsidy_ticket_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "bad_debt_receipt_count": self.bad_debt_receipt_count,
            "backstop_action_count": self.backstop_action_count,
            "pending_appeal_count": self.pending_appeal_count,
            "public_record_count": self.public_record_count,
            "total_collateral_upper_bound_units": self.total_collateral_upper_bound_units,
            "total_debt_upper_bound_units": self.total_debt_upper_bound_units,
            "total_subsidy_reserved_units": self.total_subsidy_reserved_units,
            "total_subsidy_spent_units": self.total_subsidy_spent_units,
            "total_bad_debt_units": self.total_bad_debt_units,
            "total_backstop_post_balance_floor_units": self.total_backstop_post_balance_floor_units,
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps,
            "risk_status": self.risk_status(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLiquidationEngineRoots {
    pub config_root: String,
    pub market_root: String,
    pub private_risk_account_root: String,
    pub liquidation_trigger_root: String,
    pub encrypted_collateral_lot_root: String,
    pub sealed_keeper_bid_root: String,
    pub proof_bundle_root: String,
    pub oracle_confidence_window_root: String,
    pub auction_window_root: String,
    pub low_fee_subsidy_ticket_root: String,
    pub settlement_receipt_root: String,
    pub backstop_action_root: String,
    pub appeal_root: String,
    pub public_record_root: String,
}

impl ConfidentialLiquidationEngineRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_liquidation_engine_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "market_root": self.market_root,
            "private_risk_account_root": self.private_risk_account_root,
            "liquidation_trigger_root": self.liquidation_trigger_root,
            "encrypted_collateral_lot_root": self.encrypted_collateral_lot_root,
            "sealed_keeper_bid_root": self.sealed_keeper_bid_root,
            "proof_bundle_root": self.proof_bundle_root,
            "oracle_confidence_window_root": self.oracle_confidence_window_root,
            "auction_window_root": self.auction_window_root,
            "low_fee_subsidy_ticket_root": self.low_fee_subsidy_ticket_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "backstop_action_root": self.backstop_action_root,
            "appeal_root": self.appeal_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_liquidation_engine_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLiquidationEngineState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialLiquidationEngineConfig,
    pub markets: BTreeMap<String, ConfidentialLiquidationMarket>,
    pub private_risk_accounts: BTreeMap<String, PrivateRiskAccount>,
    pub liquidation_triggers: BTreeMap<String, LiquidationTrigger>,
    pub encrypted_collateral_lots: BTreeMap<String, EncryptedCollateralLot>,
    pub sealed_keeper_bids: BTreeMap<String, SealedKeeperBid>,
    pub proof_bundles: BTreeMap<String, ConfidentialProofBundle>,
    pub oracle_confidence_windows: BTreeMap<String, OracleConfidenceWindow>,
    pub auction_windows: BTreeMap<String, MevSafeAuctionWindow>,
    pub low_fee_subsidy_tickets: BTreeMap<String, LowFeeSubsidyTicket>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub backstop_actions: BTreeMap<String, BackstopPoolAction>,
    pub appeals: BTreeMap<String, LiquidationAppeal>,
    pub public_records: BTreeMap<String, ConfidentialLiquidationPublicRecord>,
}

impl Default for ConfidentialLiquidationEngineState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidentialLiquidationEngineState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: ConfidentialLiquidationEngineConfig::default(),
            markets: BTreeMap::new(),
            private_risk_accounts: BTreeMap::new(),
            liquidation_triggers: BTreeMap::new(),
            encrypted_collateral_lots: BTreeMap::new(),
            sealed_keeper_bids: BTreeMap::new(),
            proof_bundles: BTreeMap::new(),
            oracle_confidence_windows: BTreeMap::new(),
            auction_windows: BTreeMap::new(),
            low_fee_subsidy_tickets: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            backstop_actions: BTreeMap::new(),
            appeals: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: ConfidentialLiquidationEngineConfig,
    ) -> ConfidentialLiquidationEngineResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> ConfidentialLiquidationEngineResult<Self> {
        let mut state = Self::with_config(ConfidentialLiquidationEngineConfig::devnet())?;
        state.set_height(CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_HEIGHT)?;

        let market = ConfidentialLiquidationMarket::devnet(state.height.saturating_sub(96))?;
        let market_id = market.market_id.clone();
        let backstop_pool_id = market.backstop_pool_id.clone();
        state.insert_market(market)?;

        let oracle_window = OracleConfidenceWindow::new(
            &market_id,
            vec![
                CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_ORACLE_FEED_ID.to_string(),
                "feed-wxmr-usdd-twap-devnet".to_string(),
                "feed-wxmr-usdd-reserve-devnet".to_string(),
            ],
            162 * CONFIDENTIAL_LIQUIDATION_ENGINE_PRICE_SCALE,
            120,
            state.config.max_oracle_confidence_bps,
            state.config.max_oracle_deviation_bps,
            state.height.saturating_sub(8),
            state
                .height
                .saturating_add(state.config.max_oracle_staleness_blocks),
            &json!({"oracle": "threshold confidence window", "guardrail": "twap bounded"}),
        )?;
        let oracle_window_id = oracle_window.window_id.clone();
        state.insert_oracle_confidence_window(oracle_window)?;

        let mut account = PrivateRiskAccount::new(
            &market_id,
            "devnet-alice-risk-account",
            &confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-DEVNET-ACCOUNT-SECRET",
                "alice-confidential-risk-secret-root",
            ),
            ConfidentialHealthBand::Liquidatable,
            125_000_000,
            92_000_000,
            state.height.saturating_sub(72),
            state.height.saturating_add(7_200),
            state.next_nonce(),
            &json!({"owner": "alice", "venue": "lending", "visible": "bucket_only"}),
        )?;
        account.status = PrivateRiskAccountStatus::AuctionLocked;
        account.updated_at_height = state.height.saturating_sub(2);
        let account_id = account.account_id.clone();
        state.insert_private_risk_account(account)?;

        let solvency_proof = ConfidentialProofBundle::new(
            &market_id,
            &account_id,
            &account_id,
            ProofBundleKind::Liquidatability,
            ConfidentialHealthBand::Liquidatable,
            &json!({
                "market_id": market_id,
                "account_id": account_id,
                "health_band": "liquidatable",
                "leaks_balances": false
            }),
            &confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-DEVNET-WITNESS",
                "alice-private-health-witness",
            ),
            state.height.saturating_sub(3),
            state.height.saturating_add(32),
            &json!({"proof": "private health bucket", "recursive": true}),
        )?;
        let solvency_proof_id = solvency_proof.proof_bundle_id.clone();
        state.insert_proof_bundle(solvency_proof)?;

        let lot_a = EncryptedCollateralLot::new(
            &market_id,
            &account_id,
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_COLLATERAL_ASSET_ID,
            75_000_000,
            6_000,
            state.height.saturating_sub(48),
            state.height.saturating_add(24),
            state.height.saturating_add(7_200),
            state.next_nonce(),
            &json!({"lot": "primary", "asset": "wxmr"}),
        )?;
        let lot_a_id = lot_a.lot_id.clone();
        state.insert_encrypted_collateral_lot(lot_a)?;

        let lot_b = EncryptedCollateralLot::new(
            &market_id,
            &account_id,
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_COLLATERAL_ASSET_ID,
            50_000_000,
            4_000,
            state.height.saturating_sub(48),
            state.height.saturating_add(24),
            state.height.saturating_add(7_200),
            state.next_nonce(),
            &json!({"lot": "secondary", "asset": "wxmr"}),
        )?;
        let lot_b_id = lot_b.lot_id.clone();
        state.insert_encrypted_collateral_lot(lot_b)?;

        let trigger = LiquidationTrigger::new(
            &market_id,
            &account_id,
            LiquidationTriggerKind::HealthFactorBelowMaintenance,
            ConfidentialHealthBand::Liquidatable,
            &oracle_window_id,
            &solvency_proof_id,
            state.height.saturating_sub(10),
            state.height.saturating_sub(4),
            state.height.saturating_add(40),
            &json!({"source": "keeper-triggered", "oracle_window": oracle_window_id}),
        )?;
        let trigger_id = trigger.trigger_id.clone();
        state.insert_liquidation_trigger(trigger)?;

        let auction_window = MevSafeAuctionWindow::new(
            &market_id,
            &trigger_id,
            state.height.saturating_sub(8),
            state.height.saturating_sub(2),
            state.height.saturating_sub(1),
            state.height.saturating_add(5),
            state.height.saturating_add(18),
            1,
            64,
            &json!({"auction": "commit-reveal", "mev_safe": true}),
        )?;
        let auction_window_id = auction_window.auction_window_id.clone();
        state.insert_auction_window(auction_window)?;

        let subsidy = LowFeeSubsidyTicket::new(
            &market_id,
            "devnet-liquidation-sponsor",
            "devnet-keeper-one",
            &state.config.default_low_fee_lane,
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_DEBT_ASSET_ID,
            state.config.low_fee_subsidy_budget_units,
            state.config.max_keeper_fee_units,
            state.height.saturating_sub(16),
            state.height.saturating_add(144),
            &json!({"subsidy": "small private liquidation"}),
        )?;
        let subsidy_ticket_id = subsidy.ticket_id.clone();
        state.insert_low_fee_subsidy_ticket(subsidy)?;

        let bid_proof = ConfidentialProofBundle::new(
            &market_id,
            &account_id,
            &trigger_id,
            ProofBundleKind::BidValidity,
            ConfidentialHealthBand::Liquidatable,
            &json!({"trigger_id": trigger_id, "bid": "sealed", "no_balance_leak": true}),
            &confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-BID-WITNESS",
                "keeper-one-private-bid-witness",
            ),
            state.height.saturating_sub(2),
            state.height.saturating_add(24),
            &json!({"proof": "bid validity"}),
        )?;
        let bid_proof_id = bid_proof.proof_bundle_id.clone();
        state.insert_proof_bundle(bid_proof)?;

        let bid_one = SealedKeeperBid::new(
            &market_id,
            &trigger_id,
            &auction_window_id,
            &lot_a_id,
            "devnet-keeper-one",
            &bid_proof_id,
            &subsidy_ticket_id,
            525,
            state.config.max_keeper_fee_units,
            state.height.saturating_sub(6),
            state.height.saturating_sub(1),
            state.height.saturating_add(5),
            state.height.saturating_add(18),
            state.next_nonce(),
            &json!({"keeper": "one", "auction": "sealed"}),
        )?;
        let bid_one_id = bid_one.bid_id.clone();
        state.insert_sealed_keeper_bid(bid_one)?;

        let bid_two = SealedKeeperBid::new(
            &market_id,
            &trigger_id,
            &auction_window_id,
            &lot_b_id,
            "devnet-keeper-two",
            &bid_proof_id,
            "",
            575,
            state.config.max_keeper_fee_units.saturating_add(1_000),
            state.height.saturating_sub(5),
            state.height.saturating_sub(1),
            state.height.saturating_add(5),
            state.height.saturating_add(18),
            state.next_nonce(),
            &json!({"keeper": "two", "auction": "sealed"}),
        )?;
        state.insert_sealed_keeper_bid(bid_two)?;

        let settlement_proof = ConfidentialProofBundle::new(
            &market_id,
            &account_id,
            &trigger_id,
            ProofBundleKind::SettlementConservation,
            ConfidentialHealthBand::Liquidatable,
            &json!({"trigger_id": trigger_id, "settlement": "conservation"}),
            &confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-SETTLEMENT-WITNESS",
                "settlement-conservation-private-witness",
            ),
            state.height,
            state.height.saturating_add(32),
            &json!({"proof": "settlement conservation"}),
        )?;
        let settlement_proof_id = settlement_proof.proof_bundle_id.clone();
        state.insert_proof_bundle(settlement_proof)?;

        let receipt = SettlementReceipt::new(
            &market_id,
            &trigger_id,
            &auction_window_id,
            &bid_one_id,
            &account_id,
            vec![lot_a_id.clone(), lot_b_id.clone()],
            &settlement_proof_id,
            2_500_000,
            state.height,
            state
                .height
                .saturating_add(state.config.settlement_grace_blocks),
            &json!({"receipt": "partial private liquidation", "bad_debt": "bounded"}),
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.insert_settlement_receipt(receipt)?;

        let backstop_proof = ConfidentialProofBundle::new(
            &market_id,
            &account_id,
            &receipt_id,
            ProofBundleKind::BackstopSolvency,
            ConfidentialHealthBand::Watch,
            &json!({"receipt_id": receipt_id, "backstop": "reserve_draw"}),
            &confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-BACKSTOP-WITNESS",
                "backstop-private-solvency-witness",
            ),
            state.height,
            state.height.saturating_add(64),
            &json!({"proof": "backstop solvency floor"}),
        )?;
        let backstop_proof_id = backstop_proof.proof_bundle_id.clone();
        state.insert_proof_bundle(backstop_proof)?;

        let backstop = BackstopPoolAction::new(
            &backstop_pool_id,
            &market_id,
            &receipt_id,
            BackstopActionKind::ReserveDraw,
            CONFIDENTIAL_LIQUIDATION_ENGINE_DEVNET_DEBT_ASSET_ID,
            2_500_000,
            &backstop_proof_id,
            state.height,
            state
                .height
                .saturating_add(state.config.settlement_grace_blocks),
            &json!({"backstop": "reserve draw for bounded bad debt"}),
        )?;
        state.insert_backstop_action(backstop)?;

        let appeal = LiquidationAppeal::new(
            &market_id,
            &trigger_id,
            &receipt_id,
            "devnet-alice-risk-account",
            "oracle_window_recheck",
            state.height.saturating_add(1),
            state
                .height
                .saturating_add(state.config.appeal_window_blocks),
            &json!({"appeal": "selective disclosure challenge"}),
        )?;
        state.insert_appeal(appeal)?;

        let trigger_record = ConfidentialLiquidationPublicRecord::new(
            "liquidation_trigger_opened",
            &trigger_id,
            &confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-PUBLIC-TRIGGER-SUBJECT",
                &trigger_id,
            ),
            "ids_roots_and_buckets_only",
            state.height.saturating_sub(10),
            &json!({"privacy": "no balances disclosed"}),
        )?;
        state.insert_public_record(trigger_record)?;

        let settlement_record = ConfidentialLiquidationPublicRecord::new(
            "settlement_pending_finality",
            &receipt_id,
            &confidential_liquidation_engine_string_root(
                "CONFIDENTIAL-LIQUIDATION-PUBLIC-SETTLEMENT-SUBJECT",
                &receipt_id,
            ),
            "bad_debt_amount_public_balance_private",
            state.height,
            &json!({"backstop": "accounted"}),
        )?;
        state.insert_public_record(settlement_record)?;

        state.refresh_derived_roots();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ConfidentialLiquidationEngineResult<String> {
        self.height = height;
        self.refresh_derived_roots();
        Ok(self.state_root())
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_market(
        &mut self,
        market: ConfidentialLiquidationMarket,
    ) -> ConfidentialLiquidationEngineResult<ConfidentialLiquidationMarket> {
        market.validate()?;
        self.markets
            .insert(market.market_id.clone(), market.clone());
        Ok(market)
    }

    pub fn insert_private_risk_account(
        &mut self,
        account: PrivateRiskAccount,
    ) -> ConfidentialLiquidationEngineResult<PrivateRiskAccount> {
        account.validate()?;
        ensure_state_market(&self.markets, &account.market_id, "private risk account")?;
        self.private_risk_accounts
            .insert(account.account_id.clone(), account.clone());
        Ok(account)
    }

    pub fn insert_liquidation_trigger(
        &mut self,
        trigger: LiquidationTrigger,
    ) -> ConfidentialLiquidationEngineResult<LiquidationTrigger> {
        trigger.validate()?;
        ensure_state_market(&self.markets, &trigger.market_id, "liquidation trigger")?;
        if !self.private_risk_accounts.contains_key(&trigger.account_id) {
            return Err("liquidation trigger references missing private risk account".to_string());
        }
        if !self
            .oracle_confidence_windows
            .contains_key(&trigger.oracle_window_id)
        {
            return Err("liquidation trigger references missing oracle window".to_string());
        }
        if !self.proof_bundles.contains_key(&trigger.proof_bundle_id) {
            return Err("liquidation trigger references missing proof bundle".to_string());
        }
        self.liquidation_triggers
            .insert(trigger.trigger_id.clone(), trigger.clone());
        Ok(trigger)
    }

    pub fn insert_encrypted_collateral_lot(
        &mut self,
        lot: EncryptedCollateralLot,
    ) -> ConfidentialLiquidationEngineResult<EncryptedCollateralLot> {
        lot.validate()?;
        ensure_state_market(&self.markets, &lot.market_id, "encrypted collateral lot")?;
        if !self.private_risk_accounts.contains_key(&lot.account_id) {
            return Err("collateral lot references missing private risk account".to_string());
        }
        self.encrypted_collateral_lots
            .insert(lot.lot_id.clone(), lot.clone());
        Ok(lot)
    }

    pub fn insert_sealed_keeper_bid(
        &mut self,
        bid: SealedKeeperBid,
    ) -> ConfidentialLiquidationEngineResult<SealedKeeperBid> {
        bid.validate()?;
        ensure_state_market(&self.markets, &bid.market_id, "sealed keeper bid")?;
        if !self.liquidation_triggers.contains_key(&bid.trigger_id) {
            return Err("sealed keeper bid references missing liquidation trigger".to_string());
        }
        if !self.auction_windows.contains_key(&bid.auction_window_id) {
            return Err("sealed keeper bid references missing auction window".to_string());
        }
        if !self
            .encrypted_collateral_lots
            .contains_key(&bid.collateral_lot_id)
        {
            return Err("sealed keeper bid references missing collateral lot".to_string());
        }
        if !self.proof_bundles.contains_key(&bid.bid_validity_proof_id) {
            return Err("sealed keeper bid references missing proof bundle".to_string());
        }
        if !bid.subsidy_ticket_id.is_empty()
            && !self
                .low_fee_subsidy_tickets
                .contains_key(&bid.subsidy_ticket_id)
        {
            return Err("sealed keeper bid references missing subsidy ticket".to_string());
        }
        self.sealed_keeper_bids
            .insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn insert_proof_bundle(
        &mut self,
        bundle: ConfidentialProofBundle,
    ) -> ConfidentialLiquidationEngineResult<ConfidentialProofBundle> {
        bundle.validate()?;
        ensure_state_market(&self.markets, &bundle.market_id, "proof bundle")?;
        if !bundle.account_id.is_empty()
            && !self.private_risk_accounts.contains_key(&bundle.account_id)
            && bundle.account_id != bundle.subject_id
        {
            return Err("proof bundle references missing private risk account".to_string());
        }
        self.proof_bundles
            .insert(bundle.proof_bundle_id.clone(), bundle.clone());
        Ok(bundle)
    }

    pub fn insert_oracle_confidence_window(
        &mut self,
        window: OracleConfidenceWindow,
    ) -> ConfidentialLiquidationEngineResult<OracleConfidenceWindow> {
        window.validate()?;
        ensure_state_market(&self.markets, &window.market_id, "oracle confidence window")?;
        self.oracle_confidence_windows
            .insert(window.window_id.clone(), window.clone());
        Ok(window)
    }

    pub fn insert_auction_window(
        &mut self,
        window: MevSafeAuctionWindow,
    ) -> ConfidentialLiquidationEngineResult<MevSafeAuctionWindow> {
        window.validate()?;
        ensure_state_market(&self.markets, &window.market_id, "auction window")?;
        if !self.liquidation_triggers.contains_key(&window.trigger_id) {
            return Err("auction window references missing liquidation trigger".to_string());
        }
        self.auction_windows
            .insert(window.auction_window_id.clone(), window.clone());
        Ok(window)
    }

    pub fn insert_low_fee_subsidy_ticket(
        &mut self,
        ticket: LowFeeSubsidyTicket,
    ) -> ConfidentialLiquidationEngineResult<LowFeeSubsidyTicket> {
        ticket.validate()?;
        ensure_state_market(&self.markets, &ticket.market_id, "low fee subsidy ticket")?;
        self.low_fee_subsidy_tickets
            .insert(ticket.ticket_id.clone(), ticket.clone());
        Ok(ticket)
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> ConfidentialLiquidationEngineResult<SettlementReceipt> {
        receipt.validate()?;
        ensure_state_market(&self.markets, &receipt.market_id, "settlement receipt")?;
        if !self.liquidation_triggers.contains_key(&receipt.trigger_id) {
            return Err("settlement receipt references missing trigger".to_string());
        }
        if !self
            .auction_windows
            .contains_key(&receipt.auction_window_id)
        {
            return Err("settlement receipt references missing auction window".to_string());
        }
        if !self
            .sealed_keeper_bids
            .contains_key(&receipt.winning_bid_id)
        {
            return Err("settlement receipt references missing winning bid".to_string());
        }
        if !self.private_risk_accounts.contains_key(&receipt.account_id) {
            return Err("settlement receipt references missing private risk account".to_string());
        }
        if !self
            .proof_bundles
            .contains_key(&receipt.conservation_proof_id)
        {
            return Err("settlement receipt references missing conservation proof".to_string());
        }
        for lot_id in &receipt.settled_lot_ids {
            if !self.encrypted_collateral_lots.contains_key(lot_id) {
                return Err("settlement receipt references missing collateral lot".to_string());
            }
        }
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn insert_backstop_action(
        &mut self,
        action: BackstopPoolAction,
    ) -> ConfidentialLiquidationEngineResult<BackstopPoolAction> {
        action.validate()?;
        ensure_state_market(&self.markets, &action.market_id, "backstop action")?;
        if !self.settlement_receipts.contains_key(&action.receipt_id) {
            return Err("backstop action references missing settlement receipt".to_string());
        }
        if !self.proof_bundles.contains_key(&action.solvency_proof_id) {
            return Err("backstop action references missing solvency proof".to_string());
        }
        self.backstop_actions
            .insert(action.action_id.clone(), action.clone());
        Ok(action)
    }

    pub fn insert_appeal(
        &mut self,
        appeal: LiquidationAppeal,
    ) -> ConfidentialLiquidationEngineResult<LiquidationAppeal> {
        appeal.validate()?;
        ensure_state_market(&self.markets, &appeal.market_id, "appeal")?;
        if !self.liquidation_triggers.contains_key(&appeal.trigger_id) {
            return Err("appeal references missing trigger".to_string());
        }
        if !self.settlement_receipts.contains_key(&appeal.receipt_id) {
            return Err("appeal references missing settlement receipt".to_string());
        }
        self.appeals
            .insert(appeal.appeal_id.clone(), appeal.clone());
        Ok(appeal)
    }

    pub fn insert_public_record(
        &mut self,
        record: ConfidentialLiquidationPublicRecord,
    ) -> ConfidentialLiquidationEngineResult<ConfidentialLiquidationPublicRecord> {
        record.validate()?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn refresh_derived_roots(&mut self) {
        let market_ids = self.markets.keys().cloned().collect::<Vec<_>>();
        for market_id in market_ids {
            let account_root = confidential_liquidation_engine_private_risk_account_root(
                &self
                    .private_risk_accounts
                    .values()
                    .filter(|account| account.market_id == market_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let trigger_root = confidential_liquidation_engine_liquidation_trigger_root(
                &self
                    .liquidation_triggers
                    .values()
                    .filter(|trigger| trigger.market_id == market_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let oracle_root = confidential_liquidation_engine_oracle_confidence_window_root(
                &self
                    .oracle_confidence_windows
                    .values()
                    .filter(|window| window.market_id == market_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let auction_root = confidential_liquidation_engine_auction_window_root(
                &self
                    .auction_windows
                    .values()
                    .filter(|window| window.market_id == market_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(market) = self.markets.get_mut(&market_id) {
                market.active_account_root = account_root;
                market.trigger_root = trigger_root;
                market.oracle_window_root = oracle_root;
                market.auction_window_root = auction_root;
            }
        }

        let account_ids = self
            .private_risk_accounts
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for account_id in account_ids {
            let collateral_lot_root = confidential_liquidation_engine_encrypted_collateral_lot_root(
                &self
                    .encrypted_collateral_lots
                    .values()
                    .filter(|lot| lot.account_id == account_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let proof_root = confidential_liquidation_engine_proof_bundle_root(
                &self
                    .proof_bundles
                    .values()
                    .filter(|bundle| bundle.account_id == account_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let trigger_root = confidential_liquidation_engine_liquidation_trigger_root(
                &self
                    .liquidation_triggers
                    .values()
                    .filter(|trigger| trigger.account_id == account_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(account) = self.private_risk_accounts.get_mut(&account_id) {
                account.collateral_lot_root = collateral_lot_root;
                account.solvency_proof_root = proof_root;
                account.trigger_root = trigger_root;
                account.updated_at_height = account.updated_at_height.min(self.height);
            }
        }

        let trigger_ids = self
            .liquidation_triggers
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for trigger_id in trigger_ids {
            let auction_window_root = confidential_liquidation_engine_auction_window_root(
                &self
                    .auction_windows
                    .values()
                    .filter(|window| window.trigger_id == trigger_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let sealed_bid_root = confidential_liquidation_engine_sealed_keeper_bid_root(
                &self
                    .sealed_keeper_bids
                    .values()
                    .filter(|bid| bid.trigger_id == trigger_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(trigger) = self.liquidation_triggers.get_mut(&trigger_id) {
                trigger.auction_window_root = auction_window_root;
                trigger.sealed_bid_root = sealed_bid_root;
            }
        }

        let auction_window_ids = self.auction_windows.keys().cloned().collect::<Vec<_>>();
        for auction_window_id in auction_window_ids {
            let bid_root = confidential_liquidation_engine_sealed_keeper_bid_root(
                &self
                    .sealed_keeper_bids
                    .values()
                    .filter(|bid| bid.auction_window_id == auction_window_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(window) = self.auction_windows.get_mut(&auction_window_id) {
                window.bid_root = bid_root;
            }
        }

        let receipt_ids = self.settlement_receipts.keys().cloned().collect::<Vec<_>>();
        for receipt_id in receipt_ids {
            let backstop_action_root = confidential_liquidation_engine_backstop_action_root(
                &self
                    .backstop_actions
                    .values()
                    .filter(|action| action.receipt_id == receipt_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let appeal_root = confidential_liquidation_engine_appeal_root(
                &self
                    .appeals
                    .values()
                    .filter(|appeal| appeal.receipt_id == receipt_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(receipt) = self.settlement_receipts.get_mut(&receipt_id) {
                receipt.backstop_action_root = backstop_action_root;
                receipt.appeal_root = appeal_root;
            }
        }
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn market_root(&self) -> String {
        confidential_liquidation_engine_market_root(
            &self.markets.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn private_risk_account_root(&self) -> String {
        confidential_liquidation_engine_private_risk_account_root(
            &self
                .private_risk_accounts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_trigger_root(&self) -> String {
        confidential_liquidation_engine_liquidation_trigger_root(
            &self
                .liquidation_triggers
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn encrypted_collateral_lot_root(&self) -> String {
        confidential_liquidation_engine_encrypted_collateral_lot_root(
            &self
                .encrypted_collateral_lots
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn sealed_keeper_bid_root(&self) -> String {
        confidential_liquidation_engine_sealed_keeper_bid_root(
            &self
                .sealed_keeper_bids
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn proof_bundle_root(&self) -> String {
        confidential_liquidation_engine_proof_bundle_root(
            &self.proof_bundles.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn oracle_confidence_window_root(&self) -> String {
        confidential_liquidation_engine_oracle_confidence_window_root(
            &self
                .oracle_confidence_windows
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn auction_window_root(&self) -> String {
        confidential_liquidation_engine_auction_window_root(
            &self.auction_windows.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_subsidy_ticket_root(&self) -> String {
        confidential_liquidation_engine_low_fee_subsidy_ticket_root(
            &self
                .low_fee_subsidy_tickets
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        confidential_liquidation_engine_settlement_receipt_root(
            &self
                .settlement_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn backstop_action_root(&self) -> String {
        confidential_liquidation_engine_backstop_action_root(
            &self.backstop_actions.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn appeal_root(&self) -> String {
        confidential_liquidation_engine_appeal_root(
            &self.appeals.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        confidential_liquidation_engine_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> ConfidentialLiquidationEngineRoots {
        ConfidentialLiquidationEngineRoots {
            config_root: self.config_root(),
            market_root: self.market_root(),
            private_risk_account_root: self.private_risk_account_root(),
            liquidation_trigger_root: self.liquidation_trigger_root(),
            encrypted_collateral_lot_root: self.encrypted_collateral_lot_root(),
            sealed_keeper_bid_root: self.sealed_keeper_bid_root(),
            proof_bundle_root: self.proof_bundle_root(),
            oracle_confidence_window_root: self.oracle_confidence_window_root(),
            auction_window_root: self.auction_window_root(),
            low_fee_subsidy_ticket_root: self.low_fee_subsidy_ticket_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            backstop_action_root: self.backstop_action_root(),
            appeal_root: self.appeal_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn state_roots(&self) -> ConfidentialLiquidationEngineRoots {
        self.roots()
    }

    pub fn counters(&self) -> ConfidentialLiquidationEngineCounters {
        ConfidentialLiquidationEngineCounters {
            market_count: self.markets.len() as u64,
            active_market_count: self
                .markets
                .values()
                .filter(|market| market.status.allows_triggering())
                .count() as u64,
            private_risk_account_count: self.private_risk_accounts.len() as u64,
            active_private_risk_account_count: self
                .private_risk_accounts
                .values()
                .filter(|account| account.active_at(self.height))
                .count() as u64,
            liquidatable_private_risk_account_count: self
                .private_risk_accounts
                .values()
                .filter(|account| account.is_liquidatable())
                .count() as u64,
            liquidation_trigger_count: self.liquidation_triggers.len() as u64,
            live_liquidation_trigger_count: self
                .liquidation_triggers
                .values()
                .filter(|trigger| trigger.is_live_at(self.height))
                .count() as u64,
            encrypted_collateral_lot_count: self.encrypted_collateral_lots.len() as u64,
            locked_collateral_lot_count: self
                .encrypted_collateral_lots
                .values()
                .filter(|lot| lot.status.counts_as_locked())
                .count() as u64,
            sealed_keeper_bid_count: self.sealed_keeper_bids.len() as u64,
            live_sealed_keeper_bid_count: self
                .sealed_keeper_bids
                .values()
                .filter(|bid| bid.is_live_at(self.height))
                .count() as u64,
            proof_bundle_count: self.proof_bundles.len() as u64,
            accepted_proof_bundle_count: self
                .proof_bundles
                .values()
                .filter(|bundle| bundle.status.counts_as_accepted())
                .count() as u64,
            oracle_window_count: self.oracle_confidence_windows.len() as u64,
            guarded_oracle_window_count: self
                .oracle_confidence_windows
                .values()
                .filter(|window| window.guarded_at(self.height))
                .count() as u64,
            auction_window_count: self.auction_windows.len() as u64,
            open_auction_window_count: self
                .auction_windows
                .values()
                .filter(|window| window.is_open_at(self.height))
                .count() as u64,
            low_fee_subsidy_ticket_count: self.low_fee_subsidy_tickets.len() as u64,
            active_low_fee_subsidy_ticket_count: self
                .low_fee_subsidy_tickets
                .values()
                .filter(|ticket| ticket.is_active_at(self.height))
                .count() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            bad_debt_receipt_count: self
                .settlement_receipts
                .values()
                .filter(|receipt| receipt.has_bad_debt())
                .count() as u64,
            backstop_action_count: self.backstop_actions.len() as u64,
            pending_appeal_count: self
                .appeals
                .values()
                .filter(|appeal| appeal.pending_at(self.height))
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_collateral_upper_bound_units: self.total_collateral_upper_bound_units(),
            total_debt_upper_bound_units: self.total_debt_upper_bound_units(),
            total_subsidy_reserved_units: self.total_subsidy_reserved_units(),
            total_subsidy_spent_units: self.total_subsidy_spent_units(),
            total_bad_debt_units: self.total_bad_debt_units(),
            total_backstop_post_balance_floor_units: self.total_backstop_post_balance_floor_units(),
            aggregate_risk_score_bps: self.aggregate_risk_score_bps(),
        }
    }

    pub fn market_ids(&self) -> Vec<String> {
        self.markets.keys().cloned().collect()
    }

    pub fn active_market_ids(&self) -> Vec<String> {
        self.markets
            .values()
            .filter(|market| market.status.allows_triggering())
            .map(|market| market.market_id.clone())
            .collect()
    }

    pub fn live_trigger_ids(&self) -> Vec<String> {
        self.liquidation_triggers
            .values()
            .filter(|trigger| trigger.is_live_at(self.height))
            .map(|trigger| trigger.trigger_id.clone())
            .collect()
    }

    pub fn total_collateral_upper_bound_units(&self) -> u64 {
        self.encrypted_collateral_lots
            .values()
            .filter(|lot| lot.status.counts_as_open())
            .fold(0_u64, |total, lot| {
                total.saturating_add(lot.amount_upper_bound_units)
            })
    }

    pub fn total_debt_upper_bound_units(&self) -> u64 {
        self.private_risk_accounts
            .values()
            .filter(|account| account.active_at(self.height))
            .fold(0_u64, |total, account| {
                total.saturating_add(account.max_debt_upper_bound_units)
            })
    }

    pub fn total_subsidy_reserved_units(&self) -> u64 {
        self.low_fee_subsidy_tickets
            .values()
            .fold(0_u64, |total, ticket| {
                total.saturating_add(ticket.reserved_units)
            })
    }

    pub fn total_subsidy_spent_units(&self) -> u64 {
        self.low_fee_subsidy_tickets
            .values()
            .fold(0_u64, |total, ticket| {
                total.saturating_add(ticket.spent_units)
            })
    }

    pub fn total_bad_debt_units(&self) -> u64 {
        self.settlement_receipts
            .values()
            .fold(0_u64, |total, receipt| {
                total.saturating_add(receipt.bad_debt_units)
            })
    }

    pub fn total_backstop_post_balance_floor_units(&self) -> u64 {
        self.backstop_actions.values().fold(0_u64, |total, action| {
            total.saturating_add(action.post_balance_floor_units)
        })
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        self.private_risk_accounts
            .values()
            .map(|account| account.health_band.risk_score_bps())
            .chain(
                self.appeals
                    .values()
                    .map(|appeal| appeal.severity.score_bps()),
            )
            .max()
            .unwrap_or(0)
    }

    pub fn state_root(&self) -> String {
        confidential_liquidation_engine_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("confidential liquidation engine public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> ConfidentialLiquidationEngineResult<String> {
        self.config.validate()?;
        for (id, market) in &self.markets {
            if id != &market.market_id {
                return Err("state market key does not match market id".to_string());
            }
            market.validate()?;
        }
        for (id, account) in &self.private_risk_accounts {
            if id != &account.account_id {
                return Err("state risk account key does not match account id".to_string());
            }
            account.validate()?;
            ensure_state_market(&self.markets, &account.market_id, "private risk account")?;
        }
        for (id, bundle) in &self.proof_bundles {
            if id != &bundle.proof_bundle_id {
                return Err("state proof bundle key does not match proof id".to_string());
            }
            bundle.validate()?;
            ensure_state_market(&self.markets, &bundle.market_id, "proof bundle")?;
            if !bundle.account_id.is_empty()
                && !self.private_risk_accounts.contains_key(&bundle.account_id)
                && bundle.account_id != bundle.subject_id
            {
                return Err("proof bundle references missing private risk account".to_string());
            }
        }
        for (id, window) in &self.oracle_confidence_windows {
            if id != &window.window_id {
                return Err("state oracle window key does not match window id".to_string());
            }
            window.validate()?;
            ensure_state_market(&self.markets, &window.market_id, "oracle confidence window")?;
        }
        for (id, lot) in &self.encrypted_collateral_lots {
            if id != &lot.lot_id {
                return Err("state collateral lot key does not match lot id".to_string());
            }
            lot.validate()?;
            ensure_state_market(&self.markets, &lot.market_id, "encrypted collateral lot")?;
            if !self.private_risk_accounts.contains_key(&lot.account_id) {
                return Err("collateral lot references missing private risk account".to_string());
            }
        }
        for (id, trigger) in &self.liquidation_triggers {
            if id != &trigger.trigger_id {
                return Err("state trigger key does not match trigger id".to_string());
            }
            trigger.validate()?;
            ensure_state_market(&self.markets, &trigger.market_id, "liquidation trigger")?;
            if !self.private_risk_accounts.contains_key(&trigger.account_id) {
                return Err("trigger references missing private risk account".to_string());
            }
            if !self
                .oracle_confidence_windows
                .contains_key(&trigger.oracle_window_id)
            {
                return Err("trigger references missing oracle window".to_string());
            }
            if !self.proof_bundles.contains_key(&trigger.proof_bundle_id) {
                return Err("trigger references missing proof bundle".to_string());
            }
        }
        for (id, window) in &self.auction_windows {
            if id != &window.auction_window_id {
                return Err("state auction window key does not match window id".to_string());
            }
            window.validate()?;
            ensure_state_market(&self.markets, &window.market_id, "auction window")?;
            if !self.liquidation_triggers.contains_key(&window.trigger_id) {
                return Err("auction window references missing trigger".to_string());
            }
        }
        for (id, ticket) in &self.low_fee_subsidy_tickets {
            if id != &ticket.ticket_id {
                return Err("state subsidy ticket key does not match ticket id".to_string());
            }
            ticket.validate()?;
            ensure_state_market(&self.markets, &ticket.market_id, "subsidy ticket")?;
        }
        for (id, bid) in &self.sealed_keeper_bids {
            if id != &bid.bid_id {
                return Err("state bid key does not match bid id".to_string());
            }
            bid.validate()?;
            ensure_state_market(&self.markets, &bid.market_id, "sealed keeper bid")?;
            if !self.liquidation_triggers.contains_key(&bid.trigger_id) {
                return Err("bid references missing trigger".to_string());
            }
            if !self.auction_windows.contains_key(&bid.auction_window_id) {
                return Err("bid references missing auction window".to_string());
            }
            if !self
                .encrypted_collateral_lots
                .contains_key(&bid.collateral_lot_id)
            {
                return Err("bid references missing collateral lot".to_string());
            }
            if !self.proof_bundles.contains_key(&bid.bid_validity_proof_id) {
                return Err("bid references missing proof bundle".to_string());
            }
            if !bid.subsidy_ticket_id.is_empty()
                && !self
                    .low_fee_subsidy_tickets
                    .contains_key(&bid.subsidy_ticket_id)
            {
                return Err("bid references missing subsidy ticket".to_string());
            }
        }
        for (id, receipt) in &self.settlement_receipts {
            if id != &receipt.receipt_id {
                return Err("state settlement receipt key does not match receipt id".to_string());
            }
            receipt.validate()?;
            ensure_state_market(&self.markets, &receipt.market_id, "settlement receipt")?;
            if !self.liquidation_triggers.contains_key(&receipt.trigger_id) {
                return Err("settlement receipt references missing trigger".to_string());
            }
            if !self
                .auction_windows
                .contains_key(&receipt.auction_window_id)
            {
                return Err("settlement receipt references missing auction window".to_string());
            }
            if !self
                .sealed_keeper_bids
                .contains_key(&receipt.winning_bid_id)
            {
                return Err("settlement receipt references missing winning bid".to_string());
            }
            if !self.private_risk_accounts.contains_key(&receipt.account_id) {
                return Err(
                    "settlement receipt references missing private risk account".to_string()
                );
            }
            if !self
                .proof_bundles
                .contains_key(&receipt.conservation_proof_id)
            {
                return Err("settlement receipt references missing conservation proof".to_string());
            }
            for lot_id in &receipt.settled_lot_ids {
                if !self.encrypted_collateral_lots.contains_key(lot_id) {
                    return Err("settlement receipt references missing collateral lot".to_string());
                }
            }
        }
        for (id, action) in &self.backstop_actions {
            if id != &action.action_id {
                return Err("state backstop action key does not match action id".to_string());
            }
            action.validate()?;
            ensure_state_market(&self.markets, &action.market_id, "backstop action")?;
            if !self.settlement_receipts.contains_key(&action.receipt_id) {
                return Err("backstop action references missing settlement receipt".to_string());
            }
            if !self.proof_bundles.contains_key(&action.solvency_proof_id) {
                return Err("backstop action references missing solvency proof".to_string());
            }
        }
        for (id, appeal) in &self.appeals {
            if id != &appeal.appeal_id {
                return Err("state appeal key does not match appeal id".to_string());
            }
            appeal.validate()?;
            ensure_state_market(&self.markets, &appeal.market_id, "appeal")?;
            if !self.liquidation_triggers.contains_key(&appeal.trigger_id) {
                return Err("appeal references missing trigger".to_string());
            }
            if !self.settlement_receipts.contains_key(&appeal.receipt_id) {
                return Err("appeal references missing settlement receipt".to_string());
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record key does not match record id".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let counters = self.counters();
        json!({
            "kind": "confidential_liquidation_engine_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LIQUIDATION_ENGINE_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "market_ids": self.market_ids(),
            "active_market_ids": self.active_market_ids(),
            "live_trigger_ids": self.live_trigger_ids(),
            "counters": counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }
}

pub fn confidential_liquidation_engine_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-ENGINE-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn confidential_liquidation_engine_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn confidential_liquidation_engine_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn confidential_liquidation_engine_string_list_root(domain: &str, values: &[String]) -> String {
    let mut leaves = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    leaves.sort();
    leaves.dedup();
    merkle_root(
        domain,
        &leaves.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

pub fn confidential_liquidation_engine_account_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-ENGINE-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_liquidation_engine_amount_commitment(
    label: &str,
    units: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-ENGINE-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_liquidation_engine_proof_root(
    proof_system: &str,
    public_input_root: &str,
    private_witness_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-ENGINE-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_root),
        ],
        32,
    )
}

pub fn confidential_liquidation_engine_market_root(
    markets: &[ConfidentialLiquidationMarket],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-MARKET",
        markets
            .iter()
            .map(ConfidentialLiquidationMarket::public_record)
            .collect(),
        "market_id",
    )
}

pub fn confidential_liquidation_engine_private_risk_account_root(
    accounts: &[PrivateRiskAccount],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-PRIVATE-RISK-ACCOUNT",
        accounts
            .iter()
            .map(PrivateRiskAccount::public_record)
            .collect(),
        "account_id",
    )
}

pub fn confidential_liquidation_engine_liquidation_trigger_root(
    triggers: &[LiquidationTrigger],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-TRIGGER",
        triggers
            .iter()
            .map(LiquidationTrigger::public_record)
            .collect(),
        "trigger_id",
    )
}

pub fn confidential_liquidation_engine_encrypted_collateral_lot_root(
    lots: &[EncryptedCollateralLot],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-COLLATERAL-LOT",
        lots.iter()
            .map(EncryptedCollateralLot::public_record)
            .collect(),
        "lot_id",
    )
}

pub fn confidential_liquidation_engine_sealed_keeper_bid_root(bids: &[SealedKeeperBid]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-SEALED-KEEPER-BID",
        bids.iter().map(SealedKeeperBid::public_record).collect(),
        "bid_id",
    )
}

pub fn confidential_liquidation_engine_proof_bundle_root(
    bundles: &[ConfidentialProofBundle],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-PROOF-BUNDLE",
        bundles
            .iter()
            .map(ConfidentialProofBundle::public_record)
            .collect(),
        "proof_bundle_id",
    )
}

pub fn confidential_liquidation_engine_oracle_confidence_window_root(
    windows: &[OracleConfidenceWindow],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-ORACLE-CONFIDENCE-WINDOW",
        windows
            .iter()
            .map(OracleConfidenceWindow::public_record)
            .collect(),
        "window_id",
    )
}

pub fn confidential_liquidation_engine_auction_window_root(
    windows: &[MevSafeAuctionWindow],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-AUCTION-WINDOW",
        windows
            .iter()
            .map(MevSafeAuctionWindow::public_record)
            .collect(),
        "auction_window_id",
    )
}

pub fn confidential_liquidation_engine_low_fee_subsidy_ticket_root(
    tickets: &[LowFeeSubsidyTicket],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-LOW-FEE-SUBSIDY-TICKET",
        tickets
            .iter()
            .map(LowFeeSubsidyTicket::public_record)
            .collect(),
        "ticket_id",
    )
}

pub fn confidential_liquidation_engine_settlement_receipt_root(
    receipts: &[SettlementReceipt],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-SETTLEMENT-RECEIPT",
        receipts
            .iter()
            .map(SettlementReceipt::public_record)
            .collect(),
        "receipt_id",
    )
}

pub fn confidential_liquidation_engine_backstop_action_root(
    actions: &[BackstopPoolAction],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-BACKSTOP-ACTION",
        actions
            .iter()
            .map(BackstopPoolAction::public_record)
            .collect(),
        "action_id",
    )
}

pub fn confidential_liquidation_engine_appeal_root(appeals: &[LiquidationAppeal]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-APPEAL",
        appeals
            .iter()
            .map(LiquidationAppeal::public_record)
            .collect(),
        "appeal_id",
    )
}

pub fn confidential_liquidation_engine_public_record_root(
    records: &[ConfidentialLiquidationPublicRecord],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LIQUIDATION-PUBLIC-RECORD",
        records
            .iter()
            .map(ConfidentialLiquidationPublicRecord::public_record)
            .collect(),
        "record_id",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_market_id(
    display_name: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    oracle_feed_id: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(display_name),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_risk_account_id(
    market_id: &str,
    owner_commitment: &str,
    account_nullifier: &str,
    opened_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-RISK-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(account_nullifier),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_proof_bundle_id(
    market_id: &str,
    account_id: &str,
    subject_id: &str,
    proof_kind: &str,
    public_input_root: &str,
    recursive_proof_root: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-PROOF-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(account_id),
            HashPart::Str(subject_id),
            HashPart::Str(proof_kind),
            HashPart::Str(public_input_root),
            HashPart::Str(recursive_proof_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_liquidation_engine_oracle_window_id(
    market_id: &str,
    price_commitment_root: &str,
    opened_at_height: u64,
    stale_after_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-ORACLE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(price_commitment_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(stale_after_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_trigger_id(
    market_id: &str,
    account_id: &str,
    trigger_kind: &str,
    oracle_window_id: &str,
    proof_bundle_id: &str,
    opened_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-TRIGGER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(account_id),
            HashPart::Str(trigger_kind),
            HashPart::Str(oracle_window_id),
            HashPart::Str(proof_bundle_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_collateral_lot_id(
    market_id: &str,
    account_id: &str,
    asset_id: &str,
    amount_commitment: &str,
    created_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-COLLATERAL-LOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(account_id),
            HashPart::Str(asset_id),
            HashPart::Str(amount_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_liquidation_engine_auction_window_id(
    market_id: &str,
    trigger_id: &str,
    commit_start_height: u64,
    reveal_end_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-AUCTION-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(trigger_id),
            HashPart::Int(commit_start_height as i128),
            HashPart::Int(reveal_end_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_subsidy_ticket_id(
    market_id: &str,
    sponsor_commitment: &str,
    keeper_commitment: &str,
    lane_id: &str,
    issued_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-SUBSIDY-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(keeper_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(issued_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_sealed_bid_id(
    trigger_id: &str,
    auction_window_id: &str,
    keeper_commitment: &str,
    sealed_bid_commitment: &str,
    committed_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-SEALED-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(trigger_id),
            HashPart::Str(auction_window_id),
            HashPart::Str(keeper_commitment),
            HashPart::Str(sealed_bid_commitment),
            HashPart::Int(committed_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_settlement_receipt_id(
    market_id: &str,
    trigger_id: &str,
    winning_bid_id: &str,
    settled_lot_root: &str,
    settled_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(trigger_id),
            HashPart::Str(winning_bid_id),
            HashPart::Str(settled_lot_root),
            HashPart::Int(settled_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_backstop_action_id(
    pool_id: &str,
    market_id: &str,
    receipt_id: &str,
    action_kind: &str,
    amount_units: u64,
    applied_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-BACKSTOP-ACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(market_id),
            HashPart::Str(receipt_id),
            HashPart::Str(action_kind),
            HashPart::Int(amount_units as i128),
            HashPart::Int(applied_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_liquidation_engine_appeal_id(
    market_id: &str,
    trigger_id: &str,
    receipt_id: &str,
    appellant_commitment: &str,
    opened_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-APPEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(trigger_id),
            HashPart::Str(receipt_id),
            HashPart::Str(appellant_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_liquidation_engine_public_record_id(
    event_kind: &str,
    subject_id: &str,
    subject_root: &str,
    emitted_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LIQUIDATION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

fn sorted_merkle_root(domain: &str, mut records: Vec<Value>, key: &str) -> String {
    records.sort_by(|left, right| record_key(left, key).cmp(&record_key(right, key)));
    merkle_root(domain, &records)
}

fn record_key(record: &Value, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn ensure_non_empty(value: &str, label: &str) -> ConfidentialLiquidationEngineResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ConfidentialLiquidationEngineResult<()> {
    if value > CONFIDENTIAL_LIQUIDATION_ENGINE_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    start: u64,
    end: u64,
    start_label: &str,
    end_label: &str,
) -> ConfidentialLiquidationEngineResult<()> {
    if start > end {
        Err(format!("{start_label} must be <= {end_label}"))
    } else {
        Ok(())
    }
}

fn ensure_state_market(
    markets: &BTreeMap<String, ConfidentialLiquidationMarket>,
    market_id: &str,
    label: &str,
) -> ConfidentialLiquidationEngineResult<()> {
    if markets.contains_key(market_id) {
        Ok(())
    } else {
        Err(format!("{label} references missing market"))
    }
}

fn liquidation_engine_risk_status(score_bps: u64) -> &'static str {
    if score_bps >= 9_000 {
        "critical"
    } else if score_bps >= 7_000 {
        "high"
    } else if score_bps >= 4_000 {
        "elevated"
    } else if score_bps >= 1_000 {
        "watch"
    } else {
        "normal"
    }
}
