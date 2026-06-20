use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_COMPOSABLE_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-cross-contract-composable-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_COMPOSABLE_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-composable-vault-runtime-v1";
pub const VAULT_STRATEGY_SCHEME: &str =
    "pq-confidential-cross-contract-composable-vault-strategy-root-v1";
pub const CROSS_CONTRACT_INTENT_SCHEME: &str = "pq-confidential-cross-contract-call-intent-root-v1";
pub const SEALED_ACCOUNTING_SCHEME: &str =
    "pq-confidential-sealed-cross-contract-accounting-leg-root-v1";
pub const TOKENIZED_SHARE_SCHEME: &str = "pq-confidential-tokenized-composable-vault-share-root-v1";
pub const COLLATERAL_TRANCHE_SCHEME: &str = "pq-confidential-collateral-risk-tranche-root-v1";
pub const ORACLE_ATTESTATION_SCHEME: &str = "pq-confidential-private-oracle-attestation-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str =
    "pq-confidential-composable-vault-settlement-receipt-root-v1";
pub const FEE_SPONSORSHIP_SCHEME: &str = "pq-confidential-composable-vault-fee-sponsorship-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str =
    "pq-confidential-composable-vault-nullifier-privacy-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-confidential-composable-vault-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "asset:xusd-devnet";
pub const DEVNET_HEIGHT: u64 = 2_468_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 15;
pub const DEFAULT_MAX_PROTOCOL_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_TRANCHE_HAIRCUT_BPS: u64 = 1_250;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 10_000;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_ACCOUNTING_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_REBALANCE_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_ROUTE_LEGS: usize = 32;
pub const DEFAULT_MAX_CALLS_PER_INTENT: usize = 16;
pub const DEFAULT_MAX_ACCOUNTING_LEGS_PER_RECEIPT: usize = 128;
pub const DEFAULT_MAX_STRATEGIES: usize = 262_144;
pub const DEFAULT_MAX_CALL_INTENTS: usize = 4_194_304;
pub const DEFAULT_MAX_ACCOUNTING_LEGS: usize = 8_388_608;
pub const DEFAULT_MAX_SHARE_CLASSES: usize = 1_048_576;
pub const DEFAULT_MAX_SHARE_POSITIONS: usize = 8_388_608;
pub const DEFAULT_MAX_COLLATERAL_TRANCHES: usize = 1_048_576;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_FEE_SPONSORSHIPS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 16_777_216;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const DEFAULT_MAX_EVENTS: usize = 16_777_216;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStrategyKind {
    YieldAggregator,
    LendingLoop,
    DeltaNeutral,
    PerpetualBasis,
    StableSwapLp,
    RwaCollateral,
    InsuranceBackstop,
    TreasuryLadder,
    LiquidStaking,
    BridgeReserve,
    SyntheticBasket,
    CreditLine,
}

impl VaultStrategyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::YieldAggregator => "yield_aggregator",
            Self::LendingLoop => "lending_loop",
            Self::DeltaNeutral => "delta_neutral",
            Self::PerpetualBasis => "perpetual_basis",
            Self::StableSwapLp => "stable_swap_lp",
            Self::RwaCollateral => "rwa_collateral",
            Self::InsuranceBackstop => "insurance_backstop",
            Self::TreasuryLadder => "treasury_ladder",
            Self::LiquidStaking => "liquid_staking",
            Self::BridgeReserve => "bridge_reserve",
            Self::SyntheticBasket => "synthetic_basket",
            Self::CreditLine => "credit_line",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyStatus {
    Draft,
    Active,
    DepositOnly,
    WithdrawOnly,
    RebalanceOnly,
    SettlementOnly,
    Paused,
    Frozen,
    Retired,
    Slashed,
}

impl StrategyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::WithdrawOnly => "withdraw_only",
            Self::RebalanceOnly => "rebalance_only",
            Self::SettlementOnly => "settlement_only",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }

    pub fn accepts_withdrawals(self) -> bool {
        matches!(self, Self::Active | Self::WithdrawOnly)
    }

    pub fn accepts_composable_calls(self) -> bool {
        matches!(
            self,
            Self::Active | Self::DepositOnly | Self::WithdrawOnly | Self::RebalanceOnly
        )
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Retired | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Vault,
    LendingPool,
    PerpEngine,
    StableSwap,
    Darkpool,
    Oracle,
    Bridge,
    Treasury,
    Paymaster,
    Governance,
    Liquidation,
    Insurance,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::LendingPool => "lending_pool",
            Self::PerpEngine => "perp_engine",
            Self::StableSwap => "stable_swap",
            Self::Darkpool => "darkpool",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::Paymaster => "paymaster",
            Self::Governance => "governance",
            Self::Liquidation => "liquidation",
            Self::Insurance => "insurance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallIntentKind {
    Deposit,
    Redeem,
    Rebalance,
    Swap,
    Borrow,
    Repay,
    Hedge,
    Liquidate,
    OracleRefresh,
    FeeSweep,
    TrancheRotate,
    EmergencyExit,
}

impl CallIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Redeem => "redeem",
            Self::Rebalance => "rebalance",
            Self::Swap => "swap",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Hedge => "hedge",
            Self::Liquidate => "liquidate",
            Self::OracleRefresh => "oracle_refresh",
            Self::FeeSweep => "fee_sweep",
            Self::TrancheRotate => "tranche_rotate",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallIntentStatus {
    Submitted,
    Fenced,
    Authorized,
    Routed,
    Reserved,
    Executing,
    Accounted,
    Receipted,
    Settled,
    Reverted,
    Expired,
    Cancelled,
    Challenged,
    Slashed,
}

impl CallIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Fenced => "fenced",
            Self::Authorized => "authorized",
            Self::Routed => "routed",
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Accounted => "accounted",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Reverted | Self::Expired | Self::Cancelled | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingLegKind {
    AssetIn,
    AssetOut,
    ShareMint,
    ShareBurn,
    CollateralLock,
    CollateralRelease,
    DebtOpen,
    DebtClose,
    FeeAccrual,
    RebateAccrual,
    OracleMark,
    SlashDebit,
}

impl AccountingLegKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AssetIn => "asset_in",
            Self::AssetOut => "asset_out",
            Self::ShareMint => "share_mint",
            Self::ShareBurn => "share_burn",
            Self::CollateralLock => "collateral_lock",
            Self::CollateralRelease => "collateral_release",
            Self::DebtOpen => "debt_open",
            Self::DebtClose => "debt_close",
            Self::FeeAccrual => "fee_accrual",
            Self::RebateAccrual => "rebate_accrual",
            Self::OracleMark => "oracle_mark",
            Self::SlashDebit => "slash_debit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingLegStatus {
    Proposed,
    Sealed,
    Matched,
    Netted,
    Receipted,
    Settled,
    Reversed,
    Disputed,
    Slashed,
}

impl AccountingLegStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Sealed => "sealed",
            Self::Matched => "matched",
            Self::Netted => "netted",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Reversed => "reversed",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Reversed | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareClassKind {
    Senior,
    Mezzanine,
    Junior,
    Levered,
    Hedged,
    Governance,
    LpReceipt,
    Insurance,
    Synthetic,
}

impl ShareClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::Levered => "levered",
            Self::Hedged => "hedged",
            Self::Governance => "governance",
            Self::LpReceipt => "lp_receipt",
            Self::Insurance => "insurance",
            Self::Synthetic => "synthetic",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Draft,
    Active,
    MintOnly,
    BurnOnly,
    TransferLocked,
    RedeemQueued,
    Retired,
    Slashed,
}

impl ShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::MintOnly => "mint_only",
            Self::BurnOnly => "burn_only",
            Self::TransferLocked => "transfer_locked",
            Self::RedeemQueued => "redeem_queued",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralTrancheKind {
    SuperSenior,
    Senior,
    Mezzanine,
    Junior,
    FirstLoss,
    Backstop,
    Insurance,
    Liquidation,
}

impl CollateralTrancheKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperSenior => "super_senior",
            Self::Senior => "senior",
            Self::Mezzanine => "mezzanine",
            Self::Junior => "junior",
            Self::FirstLoss => "first_loss",
            Self::Backstop => "backstop",
            Self::Insurance => "insurance",
            Self::Liquidation => "liquidation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    ReduceOnly,
    RebalanceRequired,
    Liquidatable,
    BackstopOnly,
    Frozen,
    Halt,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::RebalanceRequired => "rebalance_required",
            Self::Liquidatable => "liquidatable",
            Self::BackstopOnly => "backstop_only",
            Self::Frozen => "frozen",
            Self::Halt => "halt",
        }
    }

    pub fn allows_new_risk(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch | Self::RebalanceRequired)
    }

    pub fn requires_settlement_guard(self) -> bool {
        matches!(
            self,
            Self::ReduceOnly | Self::Liquidatable | Self::BackstopOnly | Self::Frozen | Self::Halt
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationKind {
    PriceMark,
    VolatilitySurface,
    CollateralFactor,
    LiquidityDepth,
    VaR,
    Solvency,
    ProofOfReserve,
    YieldCurve,
    CrossContractState,
}

impl OracleAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceMark => "price_mark",
            Self::VolatilitySurface => "volatility_surface",
            Self::CollateralFactor => "collateral_factor",
            Self::LiquidityDepth => "liquidity_depth",
            Self::VaR => "var",
            Self::Solvency => "solvency",
            Self::ProofOfReserve => "proof_of_reserve",
            Self::YieldCurve => "yield_curve",
            Self::CrossContractState => "cross_contract_state",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Rejected,
    Expired,
    Challenged,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Built,
    AccountingMatched,
    OracleChecked,
    Sponsored,
    Posted,
    Finalized,
    Reverted,
    Disputed,
    Slashed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::AccountingMatched => "accounting_matched",
            Self::OracleChecked => "oracle_checked",
            Self::Sponsored => "sponsored",
            Self::Posted => "posted",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorshipStatus {
    Offered,
    Reserved,
    Attached,
    Consumed,
    Rebated,
    Expired,
    Cancelled,
    Slashed,
}

impl FeeSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Attached => "attached",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    IntentNullifier,
    ShareNullifier,
    AccountingNullifier,
    OracleNullifier,
    SponsorNullifier,
    SettlementNullifier,
    StrategyAnchor,
    TrancheAnchor,
    CrossContractFence,
}

impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentNullifier => "intent_nullifier",
            Self::ShareNullifier => "share_nullifier",
            Self::AccountingNullifier => "accounting_nullifier",
            Self::OracleNullifier => "oracle_nullifier",
            Self::SponsorNullifier => "sponsor_nullifier",
            Self::SettlementNullifier => "settlement_nullifier",
            Self::StrategyAnchor => "strategy_anchor",
            Self::TrancheAnchor => "tranche_anchor",
            Self::CrossContractFence => "cross_contract_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    DoubleSpendNullifier,
    InvalidAccountingLeg,
    OracleEquivocation,
    UnauthorizedCrossCall,
    SponsorDefault,
    ReceiptMismatch,
    TrancheOverrun,
    StrategyPolicyViolation,
    PrivacyFenceBreak,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::InvalidAccountingLeg => "invalid_accounting_leg",
            Self::OracleEquivocation => "oracle_equivocation",
            Self::UnauthorizedCrossCall => "unauthorized_cross_call",
            Self::SponsorDefault => "sponsor_default",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::TrancheOverrun => "tranche_overrun",
            Self::StrategyPolicyViolation => "strategy_policy_violation",
            Self::PrivacyFenceBreak => "privacy_fence_break",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub max_tranche_haircut_bps: u64,
    pub max_slash_bps: u64,
    pub intent_ttl_blocks: u64,
    pub accounting_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub rebalance_epoch_blocks: u64,
    pub max_route_legs: usize,
    pub max_calls_per_intent: usize,
    pub max_accounting_legs_per_receipt: usize,
    pub max_strategies: usize,
    pub max_call_intents: usize,
    pub max_accounting_legs: usize,
    pub max_share_classes: usize,
    pub max_share_positions: usize,
    pub max_collateral_tranches: usize,
    pub max_oracle_attestations: usize,
    pub max_settlement_receipts: usize,
    pub max_fee_sponsorships: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_evidence: usize,
    pub max_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_protocol_fee_bps: DEFAULT_MAX_PROTOCOL_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            max_sponsor_rebate_bps: DEFAULT_MAX_SPONSOR_REBATE_BPS,
            max_tranche_haircut_bps: DEFAULT_MAX_TRANCHE_HAIRCUT_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            accounting_ttl_blocks: DEFAULT_ACCOUNTING_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            rebalance_epoch_blocks: DEFAULT_REBALANCE_EPOCH_BLOCKS,
            max_route_legs: DEFAULT_MAX_ROUTE_LEGS,
            max_calls_per_intent: DEFAULT_MAX_CALLS_PER_INTENT,
            max_accounting_legs_per_receipt: DEFAULT_MAX_ACCOUNTING_LEGS_PER_RECEIPT,
            max_strategies: DEFAULT_MAX_STRATEGIES,
            max_call_intents: DEFAULT_MAX_CALL_INTENTS,
            max_accounting_legs: DEFAULT_MAX_ACCOUNTING_LEGS,
            max_share_classes: DEFAULT_MAX_SHARE_CLASSES,
            max_share_positions: DEFAULT_MAX_SHARE_POSITIONS,
            max_collateral_tranches: DEFAULT_MAX_COLLATERAL_TRANCHES,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_settlement_receipts: DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            max_fee_sponsorships: DEFAULT_MAX_FEE_SPONSORSHIPS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("l2_network", &self.l2_network)?;
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("settlement_asset_id", &self.settlement_asset_id)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("max_protocol_fee_bps", self.max_protocol_fee_bps)?;
        ensure_bps("max_solver_fee_bps", self.max_solver_fee_bps)?;
        ensure_bps("max_sponsor_rebate_bps", self.max_sponsor_rebate_bps)?;
        ensure_bps("max_tranche_haircut_bps", self.max_tranche_haircut_bps)?;
        ensure_bps("max_slash_bps", self.max_slash_bps)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        ensure_positive("intent_ttl_blocks", self.intent_ttl_blocks)?;
        ensure_positive("accounting_ttl_blocks", self.accounting_ttl_blocks)?;
        ensure_positive("oracle_ttl_blocks", self.oracle_ttl_blocks)?;
        ensure_positive("receipt_finality_blocks", self.receipt_finality_blocks)?;
        ensure_positive("sponsor_ttl_blocks", self.sponsor_ttl_blocks)?;
        ensure_positive("fence_ttl_blocks", self.fence_ttl_blocks)?;
        ensure_positive("rebalance_epoch_blocks", self.rebalance_epoch_blocks)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub height: u64,
    pub strategy_sequence: u64,
    pub call_intent_sequence: u64,
    pub accounting_leg_sequence: u64,
    pub share_class_sequence: u64,
    pub share_position_sequence: u64,
    pub collateral_tranche_sequence: u64,
    pub oracle_attestation_sequence: u64,
    pub settlement_receipt_sequence: u64,
    pub fee_sponsorship_sequence: u64,
    pub privacy_fence_sequence: u64,
    pub slashing_evidence_sequence: u64,
    pub event_sequence: u64,
    pub total_committed_assets: u128,
    pub total_share_supply_commitments: u128,
    pub total_collateral_commitments: u128,
    pub total_fee_commitments: u128,
    pub total_sponsored_fee_commitments: u128,
    pub total_slashed_commitments: u128,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            height: DEVNET_HEIGHT,
            strategy_sequence: 0,
            call_intent_sequence: 0,
            accounting_leg_sequence: 0,
            share_class_sequence: 0,
            share_position_sequence: 0,
            collateral_tranche_sequence: 0,
            oracle_attestation_sequence: 0,
            settlement_receipt_sequence: 0,
            fee_sponsorship_sequence: 0,
            privacy_fence_sequence: 0,
            slashing_evidence_sequence: 0,
            event_sequence: 0,
            total_committed_assets: 0,
            total_share_supply_commitments: 0,
            total_collateral_commitments: 0,
            total_fee_commitments: 0,
            total_sponsored_fee_commitments: 0,
            total_slashed_commitments: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub strategy_root: String,
    pub strategy_index_root: String,
    pub call_intent_root: String,
    pub call_route_root: String,
    pub accounting_leg_root: String,
    pub accounting_net_root: String,
    pub share_class_root: String,
    pub share_position_root: String,
    pub collateral_tranche_root: String,
    pub risk_surface_root: String,
    pub oracle_attestation_root: String,
    pub oracle_feed_root: String,
    pub settlement_receipt_root: String,
    pub fee_sponsorship_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub slashing_evidence_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = json!({"empty": true});
        Self {
            config_root: hash_json("CVR-CONFIG-EMPTY", &empty),
            counters_root: hash_json("CVR-COUNTERS-EMPTY", &empty),
            strategy_root: merkle_root("CVR-STRATEGY", &[]),
            strategy_index_root: merkle_root("CVR-STRATEGY-INDEX", &[]),
            call_intent_root: merkle_root("CVR-CALL-INTENT", &[]),
            call_route_root: merkle_root("CVR-CALL-ROUTE", &[]),
            accounting_leg_root: merkle_root("CVR-ACCOUNTING-LEG", &[]),
            accounting_net_root: merkle_root("CVR-ACCOUNTING-NET", &[]),
            share_class_root: merkle_root("CVR-SHARE-CLASS", &[]),
            share_position_root: merkle_root("CVR-SHARE-POSITION", &[]),
            collateral_tranche_root: merkle_root("CVR-COLLATERAL-TRANCHE", &[]),
            risk_surface_root: merkle_root("CVR-RISK-SURFACE", &[]),
            oracle_attestation_root: merkle_root("CVR-ORACLE-ATTESTATION", &[]),
            oracle_feed_root: merkle_root("CVR-ORACLE-FEED", &[]),
            settlement_receipt_root: merkle_root("CVR-SETTLEMENT-RECEIPT", &[]),
            fee_sponsorship_root: merkle_root("CVR-FEE-SPONSORSHIP", &[]),
            privacy_fence_root: merkle_root("CVR-PRIVACY-FENCE", &[]),
            nullifier_root: merkle_root("CVR-NULLIFIER", &[]),
            slashing_evidence_root: merkle_root("CVR-SLASHING-EVIDENCE", &[]),
            event_root: merkle_root("CVR-EVENT", &[]),
            public_record_root: hash_json("CVR-PUBLIC-EMPTY", &empty),
            state_root: hash_json("CVR-STATE-EMPTY", &empty),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StrategyPolicy {
    pub policy_root: String,
    pub allowed_domains: BTreeSet<ContractDomain>,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub max_route_legs: usize,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub require_oracle_attestation: bool,
    pub require_fee_sponsor: bool,
    pub allow_emergency_exit: bool,
}

impl StrategyPolicy {
    pub fn conservative() -> Self {
        let allowed_domains = [
            ContractDomain::Vault,
            ContractDomain::LendingPool,
            ContractDomain::StableSwap,
            ContractDomain::Oracle,
            ContractDomain::Paymaster,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let mut policy = Self {
            policy_root: String::new(),
            allowed_domains,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            max_protocol_fee_bps: DEFAULT_MAX_PROTOCOL_FEE_BPS,
            max_route_legs: DEFAULT_MAX_ROUTE_LEGS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            require_oracle_attestation: true,
            require_fee_sponsor: false,
            allow_emergency_exit: true,
        };
        policy.policy_root = policy.compute_root();
        policy
    }

    pub fn compute_root(&self) -> String {
        let record = json!({
            "allowed_domains": sorted_domain_names(&self.allowed_domains),
            "allow_emergency_exit": self.allow_emergency_exit,
            "max_protocol_fee_bps": self.max_protocol_fee_bps,
            "max_route_legs": self.max_route_legs,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "require_fee_sponsor": self.require_fee_sponsor,
            "require_oracle_attestation": self.require_oracle_attestation,
        });
        domain_hash(
            "CVR-STRATEGY-POLICY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&record),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct VaultStrategy {
    pub strategy_id: String,
    pub strategy_kind: VaultStrategyKind,
    pub status: StrategyStatus,
    pub manager_commitment: String,
    pub vault_commitment: String,
    pub base_asset_id: String,
    pub share_namespace: String,
    pub accounting_domain: String,
    pub policy: StrategyPolicy,
    pub encrypted_metadata_root: String,
    pub route_manifest_root: String,
    pub risk_surface_root: String,
    pub total_asset_commitment: u128,
    pub total_share_commitment: u128,
    pub active_tranche_count: u64,
    pub created_height: u64,
    pub updated_height: u64,
    pub sequence: u64,
}

impl VaultStrategy {
    pub fn public_record(&self) -> Value {
        json!({
            "accounting_domain": self.accounting_domain,
            "active_tranche_count": self.active_tranche_count,
            "base_asset_id": self.base_asset_id,
            "created_height": self.created_height,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "manager_commitment": self.manager_commitment,
            "policy_root": self.policy.policy_root,
            "risk_surface_root": self.risk_surface_root,
            "route_manifest_root": self.route_manifest_root,
            "sequence": self.sequence,
            "share_namespace": self.share_namespace,
            "status": self.status.as_str(),
            "strategy_id": self.strategy_id,
            "strategy_kind": self.strategy_kind.as_str(),
            "total_asset_commitment": self.total_asset_commitment.to_string(),
            "total_share_commitment": self.total_share_commitment.to_string(),
            "updated_height": self.updated_height,
            "vault_commitment": self.vault_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractCallLeg {
    pub leg_index: u16,
    pub contract_domain: ContractDomain,
    pub target_contract_commitment: String,
    pub method_selector_commitment: String,
    pub sealed_calldata_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub value_commitment: String,
    pub max_fee_bps: u64,
}

impl ContractCallLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_domain": self.contract_domain.as_str(),
            "input_note_root": self.input_note_root,
            "leg_index": self.leg_index,
            "max_fee_bps": self.max_fee_bps,
            "method_selector_commitment": self.method_selector_commitment,
            "output_note_root": self.output_note_root,
            "sealed_calldata_root": self.sealed_calldata_root,
            "target_contract_commitment": self.target_contract_commitment,
            "value_commitment": self.value_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CrossContractCallIntent {
    pub intent_id: String,
    pub strategy_id: String,
    pub intent_kind: CallIntentKind,
    pub status: CallIntentStatus,
    pub owner_commitment: String,
    pub session_key_commitment: String,
    pub authorization_root: String,
    pub route_root: String,
    pub sealed_payload_root: String,
    pub spend_nullifier: String,
    pub privacy_anchor: String,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub expires_at_height: u64,
    pub submitted_height: u64,
    pub sequence: u64,
    pub call_legs: Vec<ContractCallLeg>,
}

impl CrossContractCallIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_root": self.authorization_root,
            "call_legs": self.call_legs.iter().map(ContractCallLeg::public_record).collect::<Vec<_>>(),
            "expires_at_height": self.expires_at_height,
            "intent_id": self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "owner_commitment": self.owner_commitment,
            "privacy_anchor": self.privacy_anchor,
            "route_root": self.route_root,
            "sealed_payload_root": self.sealed_payload_root,
            "sequence": self.sequence,
            "session_key_commitment": self.session_key_commitment,
            "spend_nullifier": self.spend_nullifier,
            "status": self.status.as_str(),
            "strategy_id": self.strategy_id,
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedAccountingLeg {
    pub accounting_leg_id: String,
    pub intent_id: String,
    pub strategy_id: String,
    pub leg_kind: AccountingLegKind,
    pub status: AccountingLegStatus,
    pub asset_id: String,
    pub account_commitment: String,
    pub counterparty_commitment: String,
    pub amount_commitment: String,
    pub balance_before_root: String,
    pub balance_after_root: String,
    pub encrypted_witness_root: String,
    pub nullifier: String,
    pub debit_credit_hint: i8,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl SealedAccountingLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "account_commitment": self.account_commitment,
            "accounting_leg_id": self.accounting_leg_id,
            "amount_commitment": self.amount_commitment,
            "asset_id": self.asset_id,
            "balance_after_root": self.balance_after_root,
            "balance_before_root": self.balance_before_root,
            "counterparty_commitment": self.counterparty_commitment,
            "debit_credit_hint": self.debit_credit_hint,
            "encrypted_witness_root": self.encrypted_witness_root,
            "expires_at_height": self.expires_at_height,
            "intent_id": self.intent_id,
            "leg_kind": self.leg_kind.as_str(),
            "nullifier": self.nullifier,
            "sealed_at_height": self.sealed_at_height,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "strategy_id": self.strategy_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct TokenizedShareClass {
    pub share_class_id: String,
    pub strategy_id: String,
    pub class_kind: ShareClassKind,
    pub status: ShareStatus,
    pub asset_id: String,
    pub controller_commitment: String,
    pub share_commitment_root: String,
    pub nav_commitment_root: String,
    pub rights_root: String,
    pub transfer_policy_root: String,
    pub seniority_rank: u16,
    pub max_supply_commitment: u128,
    pub circulating_supply_commitment: u128,
    pub created_height: u64,
    pub sequence: u64,
}

impl TokenizedShareClass {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "circulating_supply_commitment": self.circulating_supply_commitment.to_string(),
            "class_kind": self.class_kind.as_str(),
            "controller_commitment": self.controller_commitment,
            "created_height": self.created_height,
            "max_supply_commitment": self.max_supply_commitment.to_string(),
            "nav_commitment_root": self.nav_commitment_root,
            "rights_root": self.rights_root,
            "seniority_rank": self.seniority_rank,
            "sequence": self.sequence,
            "share_class_id": self.share_class_id,
            "share_commitment_root": self.share_commitment_root,
            "status": self.status.as_str(),
            "strategy_id": self.strategy_id,
            "transfer_policy_root": self.transfer_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SharePosition {
    pub share_position_id: String,
    pub share_class_id: String,
    pub strategy_id: String,
    pub owner_commitment: String,
    pub amount_commitment: String,
    pub cost_basis_root: String,
    pub lock_root: String,
    pub position_nullifier: String,
    pub opened_height: u64,
    pub sequence: u64,
}

impl SharePosition {
    pub fn public_record(&self) -> Value {
        json!({
            "amount_commitment": self.amount_commitment,
            "cost_basis_root": self.cost_basis_root,
            "lock_root": self.lock_root,
            "opened_height": self.opened_height,
            "owner_commitment": self.owner_commitment,
            "position_nullifier": self.position_nullifier,
            "sequence": self.sequence,
            "share_class_id": self.share_class_id,
            "share_position_id": self.share_position_id,
            "strategy_id": self.strategy_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CollateralRiskTranche {
    pub tranche_id: String,
    pub strategy_id: String,
    pub tranche_kind: CollateralTrancheKind,
    pub risk_verdict: RiskVerdict,
    pub collateral_asset_id: String,
    pub collateral_commitment: String,
    pub debt_commitment: String,
    pub haircut_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub coverage_root: String,
    pub risk_model_root: String,
    pub oracle_attestation_id: String,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl CollateralRiskTranche {
    pub fn public_record(&self) -> Value {
        json!({
            "collateral_asset_id": self.collateral_asset_id,
            "collateral_commitment": self.collateral_commitment,
            "coverage_root": self.coverage_root,
            "debt_commitment": self.debt_commitment,
            "expires_at_height": self.expires_at_height,
            "haircut_bps": self.haircut_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "opened_height": self.opened_height,
            "oracle_attestation_id": self.oracle_attestation_id,
            "risk_model_root": self.risk_model_root,
            "risk_verdict": self.risk_verdict.as_str(),
            "sequence": self.sequence,
            "strategy_id": self.strategy_id,
            "tranche_id": self.tranche_id,
            "tranche_kind": self.tranche_kind.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateOracleAttestation {
    pub attestation_id: String,
    pub strategy_id: String,
    pub attestation_kind: OracleAttestationKind,
    pub status: AttestationStatus,
    pub oracle_committee_id: String,
    pub subject_root: String,
    pub value_commitment_root: String,
    pub confidence_root: String,
    pub proof_root: String,
    pub signature_root: String,
    pub min_pq_security_bits: u16,
    pub observed_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl PrivateOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "confidence_root": self.confidence_root,
            "expires_at_height": self.expires_at_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "observed_height": self.observed_height,
            "oracle_committee_id": self.oracle_committee_id,
            "proof_root": self.proof_root,
            "sequence": self.sequence,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "strategy_id": self.strategy_id,
            "subject_root": self.subject_root,
            "value_commitment_root": self.value_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub strategy_id: String,
    pub intent_id: String,
    pub status: SettlementStatus,
    pub accounting_leg_root: String,
    pub oracle_attestation_root: String,
    pub share_delta_root: String,
    pub collateral_delta_root: String,
    pub fee_sponsorship_id: String,
    pub settlement_proof_root: String,
    pub recursive_receipt_root: String,
    pub posted_height: u64,
    pub finalizes_at_height: u64,
    pub sequence: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "accounting_leg_root": self.accounting_leg_root,
            "collateral_delta_root": self.collateral_delta_root,
            "fee_sponsorship_id": self.fee_sponsorship_id,
            "finalizes_at_height": self.finalizes_at_height,
            "intent_id": self.intent_id,
            "oracle_attestation_root": self.oracle_attestation_root,
            "posted_height": self.posted_height,
            "receipt_id": self.receipt_id,
            "recursive_receipt_root": self.recursive_receipt_root,
            "sequence": self.sequence,
            "settlement_proof_root": self.settlement_proof_root,
            "share_delta_root": self.share_delta_root,
            "status": self.status.as_str(),
            "strategy_id": self.strategy_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub strategy_id: String,
    pub intent_id: String,
    pub status: FeeSponsorshipStatus,
    pub fee_asset_id: String,
    pub max_fee_commitment: String,
    pub escrow_root: String,
    pub rebate_bps: u64,
    pub sponsor_policy_root: String,
    pub sponsor_nullifier: String,
    pub reserved_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl FeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_root": self.escrow_root,
            "expires_at_height": self.expires_at_height,
            "fee_asset_id": self.fee_asset_id,
            "intent_id": self.intent_id,
            "max_fee_commitment": self.max_fee_commitment,
            "rebate_bps": self.rebate_bps,
            "reserved_height": self.reserved_height,
            "sequence": self.sequence,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_nullifier": self.sponsor_nullifier,
            "sponsor_policy_root": self.sponsor_policy_root,
            "sponsorship_id": self.sponsorship_id,
            "status": self.status.as_str(),
            "strategy_id": self.strategy_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub fence_kind: PrivacyFenceKind,
    pub strategy_id: String,
    pub subject_id: String,
    pub nullifier: String,
    pub anchor_root: String,
    pub privacy_set_size: u64,
    pub fence_epoch: u64,
    pub opened_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_root": self.anchor_root,
            "expires_at_height": self.expires_at_height,
            "fence_epoch": self.fence_epoch,
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "nullifier": self.nullifier,
            "opened_height": self.opened_height,
            "privacy_set_size": self.privacy_set_size,
            "sequence": self.sequence,
            "strategy_id": self.strategy_id,
            "subject_id": self.subject_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashingReason,
    pub offender_commitment: String,
    pub strategy_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub challenged_root: String,
    pub penalty_commitment: String,
    pub slash_bps: u64,
    pub reporter_commitment: String,
    pub reported_height: u64,
    pub sequence: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "challenged_root": self.challenged_root,
            "evidence_id": self.evidence_id,
            "evidence_root": self.evidence_root,
            "offender_commitment": self.offender_commitment,
            "penalty_commitment": self.penalty_commitment,
            "reason": self.reason.as_str(),
            "reported_height": self.reported_height,
            "reporter_commitment": self.reporter_commitment,
            "sequence": self.sequence,
            "slash_bps": self.slash_bps,
            "strategy_id": self.strategy_id,
            "subject_id": self.subject_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub strategies: BTreeMap<String, VaultStrategy>,
    pub call_intents: BTreeMap<String, CrossContractCallIntent>,
    pub accounting_legs: BTreeMap<String, SealedAccountingLeg>,
    pub share_classes: BTreeMap<String, TokenizedShareClass>,
    pub share_positions: BTreeMap<String, SharePosition>,
    pub collateral_tranches: BTreeMap<String, CollateralRiskTranche>,
    pub oracle_attestations: BTreeMap<String, PrivateOracleAttestation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub fee_sponsorships: BTreeMap<String, FeeSponsorship>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub used_nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::devnet(),
            roots: Roots::empty(),
            strategies: BTreeMap::new(),
            call_intents: BTreeMap::new(),
            accounting_legs: BTreeMap::new(),
            share_classes: BTreeMap::new(),
            share_positions: BTreeMap::new(),
            collateral_tranches: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            fee_sponsorships: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        let _ = state.seed_devnet();
        state.recompute_roots();
        state
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "counters": self.counters,
            "hash_suite": HASH_SUITE,
            "protocol_version": PROTOCOL_VERSION,
            "roots": {
                "accounting_leg_root": self.roots.accounting_leg_root,
                "accounting_net_root": self.roots.accounting_net_root,
                "call_intent_root": self.roots.call_intent_root,
                "call_route_root": self.roots.call_route_root,
                "collateral_tranche_root": self.roots.collateral_tranche_root,
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "event_root": self.roots.event_root,
                "fee_sponsorship_root": self.roots.fee_sponsorship_root,
                "nullifier_root": self.roots.nullifier_root,
                "oracle_attestation_root": self.roots.oracle_attestation_root,
                "oracle_feed_root": self.roots.oracle_feed_root,
                "privacy_fence_root": self.roots.privacy_fence_root,
                "risk_surface_root": self.roots.risk_surface_root,
                "settlement_receipt_root": self.roots.settlement_receipt_root,
                "share_class_root": self.roots.share_class_root,
                "share_position_root": self.roots.share_position_root,
                "slashing_evidence_root": self.roots.slashing_evidence_root,
                "strategy_index_root": self.roots.strategy_index_root,
                "strategy_root": self.roots.strategy_root,
            },
            "schema_version": SCHEMA_VERSION,
        })
    }

    pub fn recompute_roots(&mut self) {
        self.roots.config_root = hash_json("CVR-CONFIG", &to_value(&self.config));
        self.roots.counters_root = hash_json("CVR-COUNTERS", &to_value(&self.counters));
        self.roots.strategy_root = root_from_values(
            "CVR-STRATEGY",
            self.strategies
                .values()
                .map(VaultStrategy::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.strategy_index_root =
            root_from_values("CVR-STRATEGY-INDEX", self.strategy_index_records());
        self.roots.call_intent_root = root_from_values(
            "CVR-CALL-INTENT",
            self.call_intents
                .values()
                .map(CrossContractCallIntent::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.call_route_root = root_from_values("CVR-CALL-ROUTE", self.call_route_records());
        self.roots.accounting_leg_root = root_from_values(
            "CVR-ACCOUNTING-LEG",
            self.accounting_legs
                .values()
                .map(SealedAccountingLeg::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.accounting_net_root =
            root_from_values("CVR-ACCOUNTING-NET", self.accounting_net_records());
        self.roots.share_class_root = root_from_values(
            "CVR-SHARE-CLASS",
            self.share_classes
                .values()
                .map(TokenizedShareClass::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.share_position_root = root_from_values(
            "CVR-SHARE-POSITION",
            self.share_positions
                .values()
                .map(SharePosition::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.collateral_tranche_root = root_from_values(
            "CVR-COLLATERAL-TRANCHE",
            self.collateral_tranches
                .values()
                .map(CollateralRiskTranche::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.risk_surface_root =
            root_from_values("CVR-RISK-SURFACE", self.risk_surface_records());
        self.roots.oracle_attestation_root = root_from_values(
            "CVR-ORACLE-ATTESTATION",
            self.oracle_attestations
                .values()
                .map(PrivateOracleAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.oracle_feed_root =
            root_from_values("CVR-ORACLE-FEED", self.oracle_feed_records());
        self.roots.settlement_receipt_root = root_from_values(
            "CVR-SETTLEMENT-RECEIPT",
            self.settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.fee_sponsorship_root = root_from_values(
            "CVR-FEE-SPONSORSHIP",
            self.fee_sponsorships
                .values()
                .map(FeeSponsorship::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.privacy_fence_root = root_from_values(
            "CVR-PRIVACY-FENCE",
            self.privacy_fences
                .values()
                .map(PrivacyFence::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = root_from_values("CVR-NULLIFIER", self.nullifier_records());
        self.roots.slashing_evidence_root = root_from_values(
            "CVR-SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.event_root = root_from_values("CVR-EVENT", self.events.clone());
        self.roots.public_record_root = hash_json("CVR-PUBLIC-RECORD", &self.public_record());
        self.roots.state_root = self.state_root();
    }

    pub fn register_strategy(
        &mut self,
        kind: VaultStrategyKind,
        manager_commitment: impl Into<String>,
        vault_commitment: impl Into<String>,
        base_asset_id: impl Into<String>,
        share_namespace: impl Into<String>,
        accounting_domain: impl Into<String>,
        policy: StrategyPolicy,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "strategies",
            self.strategies.len(),
            self.config.max_strategies,
        )?;
        let manager_commitment = manager_commitment.into();
        let vault_commitment = vault_commitment.into();
        let base_asset_id = base_asset_id.into();
        let share_namespace = share_namespace.into();
        let accounting_domain = accounting_domain.into();
        ensure_non_empty("manager_commitment", &manager_commitment)?;
        ensure_non_empty("vault_commitment", &vault_commitment)?;
        ensure_non_empty("base_asset_id", &base_asset_id)?;
        ensure_non_empty("share_namespace", &share_namespace)?;
        ensure_non_empty("accounting_domain", &accounting_domain)?;
        let sequence = self.next_strategy_sequence();
        let strategy_id = deterministic_id(
            "CVR-STRATEGY-ID",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&manager_commitment),
                HashPart::Str(&vault_commitment),
                HashPart::U64(sequence),
            ],
        );
        let mut policy = policy;
        policy.policy_root = policy.compute_root();
        let strategy = VaultStrategy {
            strategy_id: strategy_id.clone(),
            strategy_kind: kind,
            status: StrategyStatus::Active,
            manager_commitment,
            vault_commitment,
            base_asset_id,
            share_namespace,
            accounting_domain,
            policy,
            encrypted_metadata_root: deterministic_id(
                "CVR-STRATEGY-METADATA",
                &[HashPart::Str(&strategy_id), HashPart::U64(sequence)],
            ),
            route_manifest_root: deterministic_id(
                "CVR-STRATEGY-ROUTE-MANIFEST",
                &[HashPart::Str(&strategy_id), HashPart::U64(sequence)],
            ),
            risk_surface_root: merkle_root("CVR-STRATEGY-RISK-SURFACE-EMPTY", &[]),
            total_asset_commitment: 0,
            total_share_commitment: 0,
            active_tranche_count: 0,
            created_height: self.counters.height,
            updated_height: self.counters.height,
            sequence,
        };
        self.strategies.insert(strategy_id.clone(), strategy);
        self.push_event("strategy_registered", &strategy_id);
        self.recompute_roots();
        Ok(strategy_id)
    }

    pub fn submit_call_intent(
        &mut self,
        strategy_id: impl Into<String>,
        intent_kind: CallIntentKind,
        owner_commitment: impl Into<String>,
        session_key_commitment: impl Into<String>,
        sealed_payload_root: impl Into<String>,
        spend_nullifier: impl Into<String>,
        call_legs: Vec<ContractCallLeg>,
    ) -> Result<String> {
        ensure_capacity(
            "call_intents",
            self.call_intents.len(),
            self.config.max_call_intents,
        )?;
        let strategy_id = strategy_id.into();
        let owner_commitment = owner_commitment.into();
        let session_key_commitment = session_key_commitment.into();
        let sealed_payload_root = sealed_payload_root.into();
        let spend_nullifier = spend_nullifier.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_non_empty("owner_commitment", &owner_commitment)?;
        ensure_non_empty("session_key_commitment", &session_key_commitment)?;
        ensure_non_empty("sealed_payload_root", &sealed_payload_root)?;
        ensure_non_empty("spend_nullifier", &spend_nullifier)?;
        ensure_unique_nullifier(&self.used_nullifiers, &spend_nullifier)?;
        ensure_max_len(
            "call_legs",
            call_legs.len(),
            self.config.max_calls_per_intent,
        )?;
        validate_call_legs(&call_legs, self.config.max_user_fee_bps)?;
        let sequence = self.next_call_intent_sequence();
        let route_records = call_legs
            .iter()
            .map(ContractCallLeg::public_record)
            .collect::<Vec<_>>();
        let route_root = merkle_root("CVR-CALL-INTENT-ROUTE", &route_records);
        let privacy_anchor = deterministic_id(
            "CVR-INTENT-PRIVACY-ANCHOR",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(&owner_commitment),
                HashPart::Str(&spend_nullifier),
                HashPart::U64(sequence),
            ],
        );
        let authorization_root = deterministic_id(
            "CVR-INTENT-AUTHORIZATION",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(&session_key_commitment),
                HashPart::Str(&sealed_payload_root),
                HashPart::U64(sequence),
            ],
        );
        let intent_id = deterministic_id(
            "CVR-CALL-INTENT-ID",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(intent_kind.as_str()),
                HashPart::Str(&owner_commitment),
                HashPart::Str(&route_root),
                HashPart::U64(sequence),
            ],
        );
        self.used_nullifiers.insert(spend_nullifier.clone());
        let intent = CrossContractCallIntent {
            intent_id: intent_id.clone(),
            strategy_id,
            intent_kind,
            status: CallIntentStatus::Submitted,
            owner_commitment,
            session_key_commitment,
            authorization_root,
            route_root,
            sealed_payload_root,
            spend_nullifier,
            privacy_anchor,
            min_privacy_set_size: self.config.min_privacy_set_size,
            max_user_fee_bps: self.config.max_user_fee_bps,
            expires_at_height: self.counters.height + self.config.intent_ttl_blocks,
            submitted_height: self.counters.height,
            sequence,
            call_legs,
        };
        self.call_intents.insert(intent_id.clone(), intent);
        self.push_event("call_intent_submitted", &intent_id);
        self.recompute_roots();
        Ok(intent_id)
    }

    pub fn seal_accounting_leg(
        &mut self,
        intent_id: impl Into<String>,
        leg_kind: AccountingLegKind,
        asset_id: impl Into<String>,
        account_commitment: impl Into<String>,
        counterparty_commitment: impl Into<String>,
        amount_commitment: impl Into<String>,
        nullifier: impl Into<String>,
        debit_credit_hint: i8,
    ) -> Result<String> {
        ensure_capacity(
            "accounting_legs",
            self.accounting_legs.len(),
            self.config.max_accounting_legs,
        )?;
        let intent_id = intent_id.into();
        let intent = self
            .call_intents
            .get(&intent_id)
            .ok_or_else(|| format!("unknown intent_id {intent_id}"))?;
        if intent.status.terminal() {
            return Err(format!("intent {intent_id} is terminal"));
        }
        let asset_id = asset_id.into();
        let account_commitment = account_commitment.into();
        let counterparty_commitment = counterparty_commitment.into();
        let amount_commitment = amount_commitment.into();
        let nullifier = nullifier.into();
        ensure_non_empty("asset_id", &asset_id)?;
        ensure_non_empty("account_commitment", &account_commitment)?;
        ensure_non_empty("counterparty_commitment", &counterparty_commitment)?;
        ensure_non_empty("amount_commitment", &amount_commitment)?;
        ensure_non_empty("nullifier", &nullifier)?;
        ensure_unique_nullifier(&self.used_nullifiers, &nullifier)?;
        if !matches!(debit_credit_hint, -1 | 0 | 1) {
            return Err("debit_credit_hint must be -1, 0, or 1".to_string());
        }
        let sequence = self.next_accounting_leg_sequence();
        let balance_before_root = deterministic_id(
            "CVR-ACCOUNTING-BALANCE-BEFORE",
            &[
                HashPart::Str(&intent.strategy_id),
                HashPart::Str(&account_commitment),
                HashPart::U64(sequence),
            ],
        );
        let balance_after_root = deterministic_id(
            "CVR-ACCOUNTING-BALANCE-AFTER",
            &[
                HashPart::Str(&intent.strategy_id),
                HashPart::Str(&account_commitment),
                HashPart::Str(&amount_commitment),
                HashPart::U64(sequence),
            ],
        );
        let encrypted_witness_root = deterministic_id(
            "CVR-ACCOUNTING-WITNESS",
            &[
                HashPart::Str(&intent_id),
                HashPart::Str(leg_kind.as_str()),
                HashPart::Str(&nullifier),
                HashPart::U64(sequence),
            ],
        );
        let accounting_leg_id = deterministic_id(
            "CVR-ACCOUNTING-LEG-ID",
            &[
                HashPart::Str(&intent_id),
                HashPart::Str(leg_kind.as_str()),
                HashPart::Str(&asset_id),
                HashPart::Str(&nullifier),
                HashPart::U64(sequence),
            ],
        );
        let leg = SealedAccountingLeg {
            accounting_leg_id: accounting_leg_id.clone(),
            intent_id: intent_id.clone(),
            strategy_id: intent.strategy_id.clone(),
            leg_kind,
            status: AccountingLegStatus::Sealed,
            asset_id,
            account_commitment,
            counterparty_commitment,
            amount_commitment,
            balance_before_root,
            balance_after_root,
            encrypted_witness_root,
            nullifier: nullifier.clone(),
            debit_credit_hint,
            sealed_at_height: self.counters.height,
            expires_at_height: self.counters.height + self.config.accounting_ttl_blocks,
            sequence,
        };
        self.used_nullifiers.insert(nullifier);
        self.accounting_legs.insert(accounting_leg_id.clone(), leg);
        if let Some(intent) = self.call_intents.get_mut(&intent_id) {
            intent.status = CallIntentStatus::Accounted;
        }
        self.push_event("accounting_leg_sealed", &accounting_leg_id);
        self.recompute_roots();
        Ok(accounting_leg_id)
    }

    pub fn create_share_class(
        &mut self,
        strategy_id: impl Into<String>,
        class_kind: ShareClassKind,
        asset_id: impl Into<String>,
        controller_commitment: impl Into<String>,
        seniority_rank: u16,
        max_supply_commitment: u128,
    ) -> Result<String> {
        ensure_capacity(
            "share_classes",
            self.share_classes.len(),
            self.config.max_share_classes,
        )?;
        let strategy_id = strategy_id.into();
        let asset_id = asset_id.into();
        let controller_commitment = controller_commitment.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_non_empty("asset_id", &asset_id)?;
        ensure_non_empty("controller_commitment", &controller_commitment)?;
        let sequence = self.next_share_class_sequence();
        let share_class_id = deterministic_id(
            "CVR-SHARE-CLASS-ID",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(class_kind.as_str()),
                HashPart::Str(&asset_id),
                HashPart::U64(sequence),
            ],
        );
        let share = TokenizedShareClass {
            share_class_id: share_class_id.clone(),
            strategy_id: strategy_id.clone(),
            class_kind,
            status: ShareStatus::Active,
            asset_id,
            controller_commitment,
            share_commitment_root: deterministic_id(
                "CVR-SHARE-COMMITMENT",
                &[HashPart::Str(&share_class_id), HashPart::U64(sequence)],
            ),
            nav_commitment_root: deterministic_id(
                "CVR-SHARE-NAV",
                &[HashPart::Str(&share_class_id), HashPart::U64(sequence)],
            ),
            rights_root: deterministic_id(
                "CVR-SHARE-RIGHTS",
                &[HashPart::Str(&share_class_id), HashPart::U64(sequence)],
            ),
            transfer_policy_root: deterministic_id(
                "CVR-SHARE-TRANSFER-POLICY",
                &[HashPart::Str(&share_class_id), HashPart::U64(sequence)],
            ),
            seniority_rank,
            max_supply_commitment,
            circulating_supply_commitment: 0,
            created_height: self.counters.height,
            sequence,
        };
        self.share_classes.insert(share_class_id.clone(), share);
        self.push_event("share_class_created", &share_class_id);
        self.recompute_roots();
        Ok(share_class_id)
    }

    pub fn mint_share_position(
        &mut self,
        share_class_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        amount_commitment: impl Into<String>,
        position_nullifier: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity(
            "share_positions",
            self.share_positions.len(),
            self.config.max_share_positions,
        )?;
        let share_class_id = share_class_id.into();
        let owner_commitment = owner_commitment.into();
        let amount_commitment = amount_commitment.into();
        let position_nullifier = position_nullifier.into();
        ensure_non_empty("owner_commitment", &owner_commitment)?;
        ensure_non_empty("amount_commitment", &amount_commitment)?;
        ensure_non_empty("position_nullifier", &position_nullifier)?;
        ensure_unique_nullifier(&self.used_nullifiers, &position_nullifier)?;
        let strategy_id = self
            .share_classes
            .get(&share_class_id)
            .ok_or_else(|| format!("unknown share_class_id {share_class_id}"))?
            .strategy_id
            .clone();
        let sequence = self.next_share_position_sequence();
        let share_position_id = deterministic_id(
            "CVR-SHARE-POSITION-ID",
            &[
                HashPart::Str(&share_class_id),
                HashPart::Str(&owner_commitment),
                HashPart::Str(&position_nullifier),
                HashPart::U64(sequence),
            ],
        );
        let position = SharePosition {
            share_position_id: share_position_id.clone(),
            share_class_id: share_class_id.clone(),
            strategy_id: strategy_id.clone(),
            owner_commitment,
            amount_commitment,
            cost_basis_root: deterministic_id(
                "CVR-SHARE-COST-BASIS",
                &[HashPart::Str(&share_position_id), HashPart::U64(sequence)],
            ),
            lock_root: merkle_root("CVR-SHARE-LOCK-EMPTY", &[]),
            position_nullifier: position_nullifier.clone(),
            opened_height: self.counters.height,
            sequence,
        };
        self.used_nullifiers.insert(position_nullifier);
        self.share_positions
            .insert(share_position_id.clone(), position);
        if let Some(share_class) = self.share_classes.get_mut(&share_class_id) {
            share_class.circulating_supply_commitment =
                share_class.circulating_supply_commitment.saturating_add(1);
        }
        if let Some(strategy) = self.strategies.get_mut(&strategy_id) {
            strategy.total_share_commitment = strategy.total_share_commitment.saturating_add(1);
            strategy.updated_height = self.counters.height;
        }
        self.counters.total_share_supply_commitments = self
            .counters
            .total_share_supply_commitments
            .saturating_add(1);
        self.push_event("share_position_minted", &share_position_id);
        self.recompute_roots();
        Ok(share_position_id)
    }

    pub fn open_collateral_tranche(
        &mut self,
        strategy_id: impl Into<String>,
        tranche_kind: CollateralTrancheKind,
        collateral_asset_id: impl Into<String>,
        collateral_commitment: impl Into<String>,
        debt_commitment: impl Into<String>,
        oracle_attestation_id: impl Into<String>,
        haircut_bps: u64,
    ) -> Result<String> {
        ensure_capacity(
            "collateral_tranches",
            self.collateral_tranches.len(),
            self.config.max_collateral_tranches,
        )?;
        ensure_bps("haircut_bps", haircut_bps)?;
        if haircut_bps > self.config.max_tranche_haircut_bps {
            return Err(format!(
                "haircut_bps {haircut_bps} exceeds {}",
                self.config.max_tranche_haircut_bps
            ));
        }
        let strategy_id = strategy_id.into();
        let collateral_asset_id = collateral_asset_id.into();
        let collateral_commitment = collateral_commitment.into();
        let debt_commitment = debt_commitment.into();
        let oracle_attestation_id = oracle_attestation_id.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_non_empty("collateral_asset_id", &collateral_asset_id)?;
        ensure_non_empty("collateral_commitment", &collateral_commitment)?;
        ensure_non_empty("debt_commitment", &debt_commitment)?;
        ensure_non_empty("oracle_attestation_id", &oracle_attestation_id)?;
        let sequence = self.next_collateral_tranche_sequence();
        let tranche_id = deterministic_id(
            "CVR-COLLATERAL-TRANCHE-ID",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(tranche_kind.as_str()),
                HashPart::Str(&collateral_asset_id),
                HashPart::Str(&oracle_attestation_id),
                HashPart::U64(sequence),
            ],
        );
        let tranche = CollateralRiskTranche {
            tranche_id: tranche_id.clone(),
            strategy_id: strategy_id.clone(),
            tranche_kind,
            risk_verdict: RiskVerdict::Healthy,
            collateral_asset_id,
            collateral_commitment,
            debt_commitment,
            haircut_bps,
            liquidation_threshold_bps: MAX_BPS.saturating_sub(haircut_bps),
            coverage_root: deterministic_id(
                "CVR-TRANCHE-COVERAGE",
                &[HashPart::Str(&tranche_id), HashPart::U64(sequence)],
            ),
            risk_model_root: deterministic_id(
                "CVR-TRANCHE-RISK-MODEL",
                &[HashPart::Str(&tranche_id), HashPart::U64(sequence)],
            ),
            oracle_attestation_id,
            opened_height: self.counters.height,
            expires_at_height: self.counters.height + self.config.rebalance_epoch_blocks,
            sequence,
        };
        self.collateral_tranches.insert(tranche_id.clone(), tranche);
        if let Some(strategy) = self.strategies.get_mut(&strategy_id) {
            strategy.active_tranche_count = strategy.active_tranche_count.saturating_add(1);
            strategy.updated_height = self.counters.height;
        }
        self.counters.total_collateral_commitments =
            self.counters.total_collateral_commitments.saturating_add(1);
        self.push_event("collateral_tranche_opened", &tranche_id);
        self.recompute_roots();
        Ok(tranche_id)
    }

    pub fn attest_oracle(
        &mut self,
        strategy_id: impl Into<String>,
        attestation_kind: OracleAttestationKind,
        oracle_committee_id: impl Into<String>,
        subject_root: impl Into<String>,
        value_commitment_root: impl Into<String>,
        confidence_root: impl Into<String>,
        proof_root: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity(
            "oracle_attestations",
            self.oracle_attestations.len(),
            self.config.max_oracle_attestations,
        )?;
        let strategy_id = strategy_id.into();
        let oracle_committee_id = oracle_committee_id.into();
        let subject_root = subject_root.into();
        let value_commitment_root = value_commitment_root.into();
        let confidence_root = confidence_root.into();
        let proof_root = proof_root.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_non_empty("oracle_committee_id", &oracle_committee_id)?;
        ensure_non_empty("subject_root", &subject_root)?;
        ensure_non_empty("value_commitment_root", &value_commitment_root)?;
        ensure_non_empty("confidence_root", &confidence_root)?;
        ensure_non_empty("proof_root", &proof_root)?;
        let sequence = self.next_oracle_attestation_sequence();
        let attestation_id = deterministic_id(
            "CVR-ORACLE-ATTESTATION-ID",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(attestation_kind.as_str()),
                HashPart::Str(&oracle_committee_id),
                HashPart::Str(&subject_root),
                HashPart::U64(sequence),
            ],
        );
        let attestation = PrivateOracleAttestation {
            attestation_id: attestation_id.clone(),
            strategy_id,
            attestation_kind,
            status: AttestationStatus::Accepted,
            oracle_committee_id,
            subject_root,
            value_commitment_root,
            confidence_root,
            proof_root,
            signature_root: deterministic_id(
                "CVR-ORACLE-SIGNATURE",
                &[HashPart::Str(&attestation_id), HashPart::U64(sequence)],
            ),
            min_pq_security_bits: self.config.min_pq_security_bits,
            observed_height: self.counters.height,
            expires_at_height: self.counters.height + self.config.oracle_ttl_blocks,
            sequence,
        };
        self.oracle_attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event("oracle_attestation_accepted", &attestation_id);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn reserve_fee_sponsorship(
        &mut self,
        strategy_id: impl Into<String>,
        intent_id: impl Into<String>,
        sponsor_commitment: impl Into<String>,
        max_fee_commitment: impl Into<String>,
        sponsor_nullifier: impl Into<String>,
        rebate_bps: u64,
    ) -> Result<String> {
        ensure_capacity(
            "fee_sponsorships",
            self.fee_sponsorships.len(),
            self.config.max_fee_sponsorships,
        )?;
        ensure_bps("rebate_bps", rebate_bps)?;
        if rebate_bps > self.config.max_sponsor_rebate_bps {
            return Err(format!(
                "rebate_bps {rebate_bps} exceeds {}",
                self.config.max_sponsor_rebate_bps
            ));
        }
        let strategy_id = strategy_id.into();
        let intent_id = intent_id.into();
        let sponsor_commitment = sponsor_commitment.into();
        let max_fee_commitment = max_fee_commitment.into();
        let sponsor_nullifier = sponsor_nullifier.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_intent_exists(&self.call_intents, &intent_id)?;
        ensure_non_empty("sponsor_commitment", &sponsor_commitment)?;
        ensure_non_empty("max_fee_commitment", &max_fee_commitment)?;
        ensure_non_empty("sponsor_nullifier", &sponsor_nullifier)?;
        ensure_unique_nullifier(&self.used_nullifiers, &sponsor_nullifier)?;
        let sequence = self.next_fee_sponsorship_sequence();
        let sponsorship_id = deterministic_id(
            "CVR-FEE-SPONSORSHIP-ID",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(&intent_id),
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&sponsor_nullifier),
                HashPart::U64(sequence),
            ],
        );
        let sponsorship = FeeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            sponsor_commitment,
            strategy_id,
            intent_id,
            status: FeeSponsorshipStatus::Reserved,
            fee_asset_id: self.config.fee_asset_id.clone(),
            max_fee_commitment,
            escrow_root: deterministic_id(
                "CVR-FEE-SPONSOR-ESCROW",
                &[HashPart::Str(&sponsorship_id), HashPart::U64(sequence)],
            ),
            rebate_bps,
            sponsor_policy_root: deterministic_id(
                "CVR-FEE-SPONSOR-POLICY",
                &[HashPart::Str(&sponsorship_id), HashPart::U64(sequence)],
            ),
            sponsor_nullifier: sponsor_nullifier.clone(),
            reserved_height: self.counters.height,
            expires_at_height: self.counters.height + self.config.sponsor_ttl_blocks,
            sequence,
        };
        self.used_nullifiers.insert(sponsor_nullifier);
        self.fee_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.counters.total_sponsored_fee_commitments = self
            .counters
            .total_sponsored_fee_commitments
            .saturating_add(1);
        self.push_event("fee_sponsorship_reserved", &sponsorship_id);
        self.recompute_roots();
        Ok(sponsorship_id)
    }

    pub fn post_settlement_receipt(
        &mut self,
        strategy_id: impl Into<String>,
        intent_id: impl Into<String>,
        fee_sponsorship_id: impl Into<String>,
        accounting_leg_ids: Vec<String>,
        oracle_attestation_ids: Vec<String>,
    ) -> Result<String> {
        ensure_capacity(
            "settlement_receipts",
            self.settlement_receipts.len(),
            self.config.max_settlement_receipts,
        )?;
        let strategy_id = strategy_id.into();
        let intent_id = intent_id.into();
        let fee_sponsorship_id = fee_sponsorship_id.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_intent_exists(&self.call_intents, &intent_id)?;
        ensure_max_len(
            "accounting_leg_ids",
            accounting_leg_ids.len(),
            self.config.max_accounting_legs_per_receipt,
        )?;
        for leg_id in &accounting_leg_ids {
            if !self.accounting_legs.contains_key(leg_id) {
                return Err(format!("unknown accounting_leg_id {leg_id}"));
            }
        }
        for attestation_id in &oracle_attestation_ids {
            if !self.oracle_attestations.contains_key(attestation_id) {
                return Err(format!("unknown oracle_attestation_id {attestation_id}"));
            }
        }
        let sequence = self.next_settlement_receipt_sequence();
        let accounting_leg_root = merkle_root(
            "CVR-RECEIPT-ACCOUNTING-LEGS",
            &accounting_leg_ids
                .iter()
                .map(|leg_id| json!({ "accounting_leg_id": leg_id }))
                .collect::<Vec<_>>(),
        );
        let oracle_attestation_root = merkle_root(
            "CVR-RECEIPT-ORACLE-ATTESTATIONS",
            &oracle_attestation_ids
                .iter()
                .map(|attestation_id| json!({ "attestation_id": attestation_id }))
                .collect::<Vec<_>>(),
        );
        let receipt_id = deterministic_id(
            "CVR-SETTLEMENT-RECEIPT-ID",
            &[
                HashPart::Str(&strategy_id),
                HashPart::Str(&intent_id),
                HashPart::Str(&accounting_leg_root),
                HashPart::Str(&oracle_attestation_root),
                HashPart::U64(sequence),
            ],
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            strategy_id,
            intent_id: intent_id.clone(),
            status: SettlementStatus::Posted,
            accounting_leg_root,
            oracle_attestation_root,
            share_delta_root: deterministic_id(
                "CVR-RECEIPT-SHARE-DELTA",
                &[HashPart::Str(&receipt_id), HashPart::U64(sequence)],
            ),
            collateral_delta_root: deterministic_id(
                "CVR-RECEIPT-COLLATERAL-DELTA",
                &[HashPart::Str(&receipt_id), HashPart::U64(sequence)],
            ),
            fee_sponsorship_id,
            settlement_proof_root: deterministic_id(
                "CVR-RECEIPT-SETTLEMENT-PROOF",
                &[HashPart::Str(&receipt_id), HashPart::U64(sequence)],
            ),
            recursive_receipt_root: deterministic_id(
                "CVR-RECEIPT-RECURSIVE",
                &[HashPart::Str(&receipt_id), HashPart::U64(sequence)],
            ),
            posted_height: self.counters.height,
            finalizes_at_height: self.counters.height + self.config.receipt_finality_blocks,
            sequence,
        };
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        if let Some(intent) = self.call_intents.get_mut(&intent_id) {
            intent.status = CallIntentStatus::Receipted;
        }
        self.push_event("settlement_receipt_posted", &receipt_id);
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn open_privacy_fence(
        &mut self,
        fence_kind: PrivacyFenceKind,
        strategy_id: impl Into<String>,
        subject_id: impl Into<String>,
        nullifier: impl Into<String>,
        anchor_root: impl Into<String>,
        privacy_set_size: u64,
    ) -> Result<String> {
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        let strategy_id = strategy_id.into();
        let subject_id = subject_id.into();
        let nullifier = nullifier.into();
        let anchor_root = anchor_root.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_non_empty("subject_id", &subject_id)?;
        ensure_non_empty("nullifier", &nullifier)?;
        ensure_non_empty("anchor_root", &anchor_root)?;
        ensure_unique_nullifier(&self.used_nullifiers, &nullifier)?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "privacy_set_size {privacy_set_size} below {}",
                self.config.min_privacy_set_size
            ));
        }
        let sequence = self.next_privacy_fence_sequence();
        let fence_id = deterministic_id(
            "CVR-PRIVACY-FENCE-ID",
            &[
                HashPart::Str(fence_kind.as_str()),
                HashPart::Str(&strategy_id),
                HashPart::Str(&subject_id),
                HashPart::Str(&nullifier),
                HashPart::U64(sequence),
            ],
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            fence_kind,
            strategy_id,
            subject_id,
            nullifier: nullifier.clone(),
            anchor_root,
            privacy_set_size,
            fence_epoch: self.counters.height / self.config.fence_ttl_blocks,
            opened_height: self.counters.height,
            expires_at_height: self.counters.height + self.config.fence_ttl_blocks,
            sequence,
        };
        self.used_nullifiers.insert(nullifier);
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.push_event("privacy_fence_opened", &fence_id);
        self.recompute_roots();
        Ok(fence_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        reason: SlashingReason,
        offender_commitment: impl Into<String>,
        strategy_id: impl Into<String>,
        subject_id: impl Into<String>,
        evidence_root: impl Into<String>,
        challenged_root: impl Into<String>,
        penalty_commitment: impl Into<String>,
        reporter_commitment: impl Into<String>,
        slash_bps: u64,
    ) -> Result<String> {
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        ensure_bps("slash_bps", slash_bps)?;
        if slash_bps > self.config.max_slash_bps {
            return Err(format!(
                "slash_bps {slash_bps} exceeds {}",
                self.config.max_slash_bps
            ));
        }
        let offender_commitment = offender_commitment.into();
        let strategy_id = strategy_id.into();
        let subject_id = subject_id.into();
        let evidence_root = evidence_root.into();
        let challenged_root = challenged_root.into();
        let penalty_commitment = penalty_commitment.into();
        let reporter_commitment = reporter_commitment.into();
        ensure_strategy_exists(&self.strategies, &strategy_id)?;
        ensure_non_empty("offender_commitment", &offender_commitment)?;
        ensure_non_empty("subject_id", &subject_id)?;
        ensure_non_empty("evidence_root", &evidence_root)?;
        ensure_non_empty("challenged_root", &challenged_root)?;
        ensure_non_empty("penalty_commitment", &penalty_commitment)?;
        ensure_non_empty("reporter_commitment", &reporter_commitment)?;
        let sequence = self.next_slashing_evidence_sequence();
        let evidence_id = deterministic_id(
            "CVR-SLASHING-EVIDENCE-ID",
            &[
                HashPart::Str(reason.as_str()),
                HashPart::Str(&offender_commitment),
                HashPart::Str(&strategy_id),
                HashPart::Str(&subject_id),
                HashPart::Str(&evidence_root),
                HashPart::U64(sequence),
            ],
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            reason,
            offender_commitment,
            strategy_id: strategy_id.clone(),
            subject_id,
            evidence_root,
            challenged_root,
            penalty_commitment,
            slash_bps,
            reporter_commitment,
            reported_height: self.counters.height,
            sequence,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        if let Some(strategy) = self.strategies.get_mut(&strategy_id) {
            strategy.status = StrategyStatus::Frozen;
            strategy.updated_height = self.counters.height;
        }
        self.counters.total_slashed_commitments =
            self.counters.total_slashed_commitments.saturating_add(1);
        self.push_event("slashing_evidence_submitted", &evidence_id);
        self.recompute_roots();
        Ok(evidence_id)
    }

    fn seed_devnet(&mut self) -> Result<()> {
        let strategy_id = self.register_strategy(
            VaultStrategyKind::YieldAggregator,
            "manager:devnet-composable-vault",
            "vault:devnet-composable-vault",
            self.config.settlement_asset_id.clone(),
            "shares:devnet-composable-vault",
            "accounting:devnet-composable-vault",
            StrategyPolicy::conservative(),
        )?;
        let oracle_id = self.attest_oracle(
            strategy_id.clone(),
            OracleAttestationKind::PriceMark,
            "oracle-committee:devnet-risk",
            "subject:devnet-vault-nav",
            "value:devnet-vault-nav-commitment",
            "confidence:devnet-tight",
            "proof:devnet-oracle-pq",
        )?;
        let share_class_id = self.create_share_class(
            strategy_id.clone(),
            ShareClassKind::Senior,
            "asset:cv-share-senior-devnet",
            "controller:devnet-share",
            1,
            1_000_000_000,
        )?;
        let _position_id = self.mint_share_position(
            share_class_id,
            "owner:devnet-liquidity-provider",
            "amount:devnet-share-commitment",
            "nullifier:devnet-share-position-0",
        )?;
        let call_legs = vec![
            ContractCallLeg {
                leg_index: 0,
                contract_domain: ContractDomain::StableSwap,
                target_contract_commitment: "contract:devnet-stableswap".to_string(),
                method_selector_commitment: "selector:add_liquidity".to_string(),
                sealed_calldata_root: "calldata:devnet-add-liquidity".to_string(),
                input_note_root: "input:devnet-xusd-note".to_string(),
                output_note_root: "output:devnet-lp-note".to_string(),
                value_commitment: "value:devnet-liquidity".to_string(),
                max_fee_bps: 4,
            },
            ContractCallLeg {
                leg_index: 1,
                contract_domain: ContractDomain::LendingPool,
                target_contract_commitment: "contract:devnet-lending-pool".to_string(),
                method_selector_commitment: "selector:supply".to_string(),
                sealed_calldata_root: "calldata:devnet-supply".to_string(),
                input_note_root: "input:devnet-lp-note".to_string(),
                output_note_root: "output:devnet-receipt-note".to_string(),
                value_commitment: "value:devnet-supply".to_string(),
                max_fee_bps: 5,
            },
        ];
        let intent_id = self.submit_call_intent(
            strategy_id.clone(),
            CallIntentKind::Deposit,
            "owner:devnet-composable-depositor",
            "session:devnet-pq-session",
            "payload:devnet-sealed-deposit",
            "nullifier:devnet-intent-0",
            call_legs,
        )?;
        let leg_id = self.seal_accounting_leg(
            intent_id.clone(),
            AccountingLegKind::AssetIn,
            self.config.settlement_asset_id.clone(),
            "account:devnet-vault",
            "account:devnet-depositor",
            "amount:devnet-asset-in",
            "nullifier:devnet-accounting-0",
            1,
        )?;
        let sponsor_id = self.reserve_fee_sponsorship(
            strategy_id.clone(),
            intent_id.clone(),
            "sponsor:devnet-paymaster",
            "fee:devnet-max",
            "nullifier:devnet-sponsor-0",
            3,
        )?;
        let _tranche_id = self.open_collateral_tranche(
            strategy_id.clone(),
            CollateralTrancheKind::Senior,
            self.config.settlement_asset_id.clone(),
            "collateral:devnet-senior",
            "debt:devnet-zero",
            oracle_id.clone(),
            250,
        )?;
        let _fence_id = self.open_privacy_fence(
            PrivacyFenceKind::IntentNullifier,
            strategy_id.clone(),
            intent_id.clone(),
            "nullifier:devnet-fence-0",
            "anchor:devnet-fence",
            self.config.min_privacy_set_size,
        )?;
        let _receipt_id = self.post_settlement_receipt(
            strategy_id,
            intent_id,
            sponsor_id,
            vec![leg_id],
            vec![oracle_id],
        )?;
        Ok(())
    }

    fn strategy_index_records(&self) -> Vec<Value> {
        self.strategies
            .values()
            .map(|strategy| {
                json!({
                    "base_asset_id": strategy.base_asset_id,
                    "manager_commitment": strategy.manager_commitment,
                    "status": strategy.status.as_str(),
                    "strategy_id": strategy.strategy_id,
                    "strategy_kind": strategy.strategy_kind.as_str(),
                })
            })
            .collect()
    }

    fn call_route_records(&self) -> Vec<Value> {
        self.call_intents
            .values()
            .map(|intent| {
                json!({
                    "intent_id": intent.intent_id,
                    "route_root": intent.route_root,
                    "strategy_id": intent.strategy_id,
                })
            })
            .collect()
    }

    fn accounting_net_records(&self) -> Vec<Value> {
        self.accounting_legs
            .values()
            .map(|leg| {
                json!({
                    "accounting_leg_id": leg.accounting_leg_id,
                    "asset_id": leg.asset_id,
                    "debit_credit_hint": leg.debit_credit_hint,
                    "intent_id": leg.intent_id,
                    "leg_kind": leg.leg_kind.as_str(),
                    "status": leg.status.as_str(),
                    "strategy_id": leg.strategy_id,
                })
            })
            .collect()
    }

    fn risk_surface_records(&self) -> Vec<Value> {
        self.collateral_tranches
            .values()
            .map(|tranche| {
                json!({
                    "collateral_asset_id": tranche.collateral_asset_id,
                    "haircut_bps": tranche.haircut_bps,
                    "liquidation_threshold_bps": tranche.liquidation_threshold_bps,
                    "risk_verdict": tranche.risk_verdict.as_str(),
                    "strategy_id": tranche.strategy_id,
                    "tranche_id": tranche.tranche_id,
                    "tranche_kind": tranche.tranche_kind.as_str(),
                })
            })
            .collect()
    }

    fn oracle_feed_records(&self) -> Vec<Value> {
        self.oracle_attestations
            .values()
            .map(|attestation| {
                json!({
                    "attestation_id": attestation.attestation_id,
                    "attestation_kind": attestation.attestation_kind.as_str(),
                    "expires_at_height": attestation.expires_at_height,
                    "oracle_committee_id": attestation.oracle_committee_id,
                    "status": attestation.status.as_str(),
                    "strategy_id": attestation.strategy_id,
                    "subject_root": attestation.subject_root,
                })
            })
            .collect()
    }

    fn nullifier_records(&self) -> Vec<Value> {
        self.used_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect()
    }

    fn next_strategy_sequence(&mut self) -> u64 {
        self.counters.strategy_sequence = self.counters.strategy_sequence.saturating_add(1);
        self.counters.strategy_sequence
    }

    fn next_call_intent_sequence(&mut self) -> u64 {
        self.counters.call_intent_sequence = self.counters.call_intent_sequence.saturating_add(1);
        self.counters.call_intent_sequence
    }

    fn next_accounting_leg_sequence(&mut self) -> u64 {
        self.counters.accounting_leg_sequence =
            self.counters.accounting_leg_sequence.saturating_add(1);
        self.counters.accounting_leg_sequence
    }

    fn next_share_class_sequence(&mut self) -> u64 {
        self.counters.share_class_sequence = self.counters.share_class_sequence.saturating_add(1);
        self.counters.share_class_sequence
    }

    fn next_share_position_sequence(&mut self) -> u64 {
        self.counters.share_position_sequence =
            self.counters.share_position_sequence.saturating_add(1);
        self.counters.share_position_sequence
    }

    fn next_collateral_tranche_sequence(&mut self) -> u64 {
        self.counters.collateral_tranche_sequence =
            self.counters.collateral_tranche_sequence.saturating_add(1);
        self.counters.collateral_tranche_sequence
    }

    fn next_oracle_attestation_sequence(&mut self) -> u64 {
        self.counters.oracle_attestation_sequence =
            self.counters.oracle_attestation_sequence.saturating_add(1);
        self.counters.oracle_attestation_sequence
    }

    fn next_settlement_receipt_sequence(&mut self) -> u64 {
        self.counters.settlement_receipt_sequence =
            self.counters.settlement_receipt_sequence.saturating_add(1);
        self.counters.settlement_receipt_sequence
    }

    fn next_fee_sponsorship_sequence(&mut self) -> u64 {
        self.counters.fee_sponsorship_sequence =
            self.counters.fee_sponsorship_sequence.saturating_add(1);
        self.counters.fee_sponsorship_sequence
    }

    fn next_privacy_fence_sequence(&mut self) -> u64 {
        self.counters.privacy_fence_sequence =
            self.counters.privacy_fence_sequence.saturating_add(1);
        self.counters.privacy_fence_sequence
    }

    fn next_slashing_evidence_sequence(&mut self) -> u64 {
        self.counters.slashing_evidence_sequence =
            self.counters.slashing_evidence_sequence.saturating_add(1);
        self.counters.slashing_evidence_sequence
    }

    fn push_event(&mut self, kind: &str, subject_id: &str) {
        self.counters.event_sequence = self.counters.event_sequence.saturating_add(1);
        if self.events.len() < self.config.max_events {
            self.events.push(json!({
                "height": self.counters.height,
                "kind": kind,
                "protocol_version": PROTOCOL_VERSION,
                "sequence": self.counters.event_sequence,
                "subject_id": subject_id,
            }));
        }
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "CVR-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn hash_json(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn root_from_values(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    merkle_root(domain, &records)
}

fn to_value<T: Serialize>(value: &T) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => value,
        Err(error) => json!({ "serialization_error": error.to_string() }),
    }
}

fn sorted_domain_names(domains: &BTreeSet<ContractDomain>) -> Vec<&'static str> {
    domains.iter().map(|domain| domain.as_str()).collect()
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{name} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(name: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        Err(format!(
            "{name} capacity exceeded: {current_len} >= {max_len}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_max_len(name: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len > max_len {
        Err(format!("{name} length {current_len} exceeds {max_len}"))
    } else {
        Ok(())
    }
}

fn ensure_unique_nullifier(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    if nullifiers.contains(nullifier) {
        Err(format!("nullifier already used: {nullifier}"))
    } else {
        Ok(())
    }
}

fn ensure_strategy_exists(
    strategies: &BTreeMap<String, VaultStrategy>,
    strategy_id: &str,
) -> Result<()> {
    if strategies.contains_key(strategy_id) {
        Ok(())
    } else {
        Err(format!("unknown strategy_id {strategy_id}"))
    }
}

fn ensure_intent_exists(
    intents: &BTreeMap<String, CrossContractCallIntent>,
    intent_id: &str,
) -> Result<()> {
    if intents.contains_key(intent_id) {
        Ok(())
    } else {
        Err(format!("unknown intent_id {intent_id}"))
    }
}

fn validate_call_legs(legs: &[ContractCallLeg], max_fee_bps: u64) -> Result<()> {
    if legs.is_empty() {
        return Err("call_legs must not be empty".to_string());
    }
    let mut indices = BTreeSet::new();
    for leg in legs {
        ensure_non_empty(
            "target_contract_commitment",
            &leg.target_contract_commitment,
        )?;
        ensure_non_empty(
            "method_selector_commitment",
            &leg.method_selector_commitment,
        )?;
        ensure_non_empty("sealed_calldata_root", &leg.sealed_calldata_root)?;
        ensure_non_empty("input_note_root", &leg.input_note_root)?;
        ensure_non_empty("output_note_root", &leg.output_note_root)?;
        ensure_non_empty("value_commitment", &leg.value_commitment)?;
        ensure_bps("leg.max_fee_bps", leg.max_fee_bps)?;
        if leg.max_fee_bps > max_fee_bps {
            return Err(format!(
                "leg {} fee {} exceeds {}",
                leg.leg_index, leg.max_fee_bps, max_fee_bps
            ));
        }
        if !indices.insert(leg.leg_index) {
            return Err(format!("duplicate call leg index {}", leg.leg_index));
        }
    }
    Ok(())
}
