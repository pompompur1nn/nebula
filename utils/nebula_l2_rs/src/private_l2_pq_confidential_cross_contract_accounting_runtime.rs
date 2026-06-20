use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateL2PqConfidentialCrossContractAccountingRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialCrossContractAccountingRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_ACCOUNTING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-contract-accounting-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_ACCOUNTING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_420_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-accounting-v1";
pub const BALANCE_COMMITMENT_SCHEME: &str = "pedersen-compatible-confidential-balance-root-v1";
pub const PRIVATE_CALL_LEDGER_SCHEME: &str = "private-cross-contract-call-ledger-root-v1";
pub const TOKEN_SETTLEMENT_NET_SCHEME: &str = "confidential-token-settlement-net-root-v1";
pub const VAULT_ACCOUNTING_SCHEME: &str = "private-defi-vault-accounting-root-v1";
pub const FEE_REBATE_SCHEME: &str = "low-fee-private-rebate-accrual-root-v1";
pub const RECURSIVE_AUDIT_SCHEME: &str = "recursive-private-accounting-audit-root-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "nullifier-and-privacy-budget-root-v1";
pub const FAST_CHECKPOINT_SCHEME: &str = "fast-settlement-checkpoint-root-v1";
pub const CHALLENGE_SLASHING_SCHEME: &str = "private-accounting-challenge-slashing-root-v1";
pub const DEFAULT_MAX_ACCOUNTS: usize = 8_388_608;
pub const DEFAULT_MAX_BALANCE_COMMITMENTS: usize = 67_108_864;
pub const DEFAULT_MAX_PQ_AUTHORIZATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_PRIVATE_CALLS: usize = 33_554_432;
pub const DEFAULT_MAX_SETTLEMENT_NETS: usize = 8_388_608;
pub const DEFAULT_MAX_VAULT_POSITIONS: usize = 8_388_608;
pub const DEFAULT_MAX_FEE_REBATES: usize = 16_777_216;
pub const DEFAULT_MAX_AUDIT_PROOFS: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVACY_BUDGETS: usize = 16_777_216;
pub const DEFAULT_MAX_NULLIFIERS: usize = 134_217_728;
pub const DEFAULT_MAX_CHECKPOINTS: usize = 2_097_152;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;
pub const DEFAULT_AUTH_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_PRIVATE_CALL_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_NET_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_CHECKPOINT_INTERVAL_BLOCKS: u64 = 4;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_MAX_OPERATOR_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_SLASHING_PENALTY_BPS: u64 = 1_500;
pub const DEFAULT_MAX_PRIVACY_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_PRIVACY_BUDGET_REPLENISH_PER_BLOCK: u64 = 250;
pub const DEFAULT_MAX_CALLS_PER_NET: usize = 16_384;
pub const DEFAULT_MAX_VAULTS_PER_NET: usize = 4_096;
pub const DEFAULT_MAX_TOKENS_PER_NET: usize = 4_096;
pub const DEFAULT_MAX_RECURSIVE_DEPTH: u16 = 32;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountDomainKind {
    Wallet,
    SmartAccount,
    Contract,
    Vault,
    Market,
    Bridge,
    Treasury,
    Paymaster,
    Sequencer,
    Auditor,
}

impl AccountDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::SmartAccount => "smart_account",
            Self::Contract => "contract",
            Self::Vault => "vault",
            Self::Market => "market",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::Paymaster => "paymaster",
            Self::Sequencer => "sequencer",
            Self::Auditor => "auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Proposed,
    Authorized,
    Locked,
    Netted,
    Settled,
    Released,
    Expired,
    Challenged,
    Slashed,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authorized => "authorized",
            Self::Locked => "locked",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Released | Self::Expired | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationKind {
    Spend,
    Delegate,
    VaultMove,
    ContractCall,
    SettlementNet,
    FeeSponsor,
    RebateClaim,
    AuditOpen,
    EmergencyExit,
    Challenge,
}

impl PqAuthorizationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spend => "spend",
            Self::Delegate => "delegate",
            Self::VaultMove => "vault_move",
            Self::ContractCall => "contract_call",
            Self::SettlementNet => "settlement_net",
            Self::FeeSponsor => "fee_sponsor",
            Self::RebateClaim => "rebate_claim",
            Self::AuditOpen => "audit_open",
            Self::EmergencyExit => "emergency_exit",
            Self::Challenge => "challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Submitted,
    Verified,
    Attached,
    Consumed,
    Expired,
    Revoked,
    Challenged,
    Slashed,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Attached => "attached",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Revoked | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateCallKind {
    Swap,
    Transfer,
    VaultDeposit,
    VaultRedeem,
    Borrow,
    Repay,
    Liquidate,
    OracleUpdate,
    GovernanceAction,
    BridgeSettle,
    FeeSweep,
    RebateClaim,
}

impl PrivateCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Transfer => "transfer",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultRedeem => "vault_redeem",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Liquidate => "liquidate",
            Self::OracleUpdate => "oracle_update",
            Self::GovernanceAction => "governance_action",
            Self::BridgeSettle => "bridge_settle",
            Self::FeeSweep => "fee_sweep",
            Self::RebateClaim => "rebate_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateCallStatus {
    Queued,
    Authorized,
    Executing,
    Netted,
    Settled,
    Reverted,
    Expired,
    Challenged,
    Slashed,
}

impl PrivateCallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Authorized => "authorized",
            Self::Executing => "executing",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Reverted | Self::Expired | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementNetKind {
    TokenTransfer,
    CrossContractSwap,
    VaultRebalance,
    LendingCycle,
    LiquidationBatch,
    BridgeExit,
    FeeSweep,
    RebateDistribution,
    AuditCorrection,
}

impl SettlementNetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenTransfer => "token_transfer",
            Self::CrossContractSwap => "cross_contract_swap",
            Self::VaultRebalance => "vault_rebalance",
            Self::LendingCycle => "lending_cycle",
            Self::LiquidationBatch => "liquidation_batch",
            Self::BridgeExit => "bridge_exit",
            Self::FeeSweep => "fee_sweep",
            Self::RebateDistribution => "rebate_distribution",
            Self::AuditCorrection => "audit_correction",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementNetStatus {
    Open,
    Sealed,
    Proving,
    Settled,
    PartiallySettled,
    Expired,
    Challenged,
    Slashed,
}

impl SettlementNetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::PartiallySettled | Self::Expired | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultAccountingKind {
    Deposit,
    Redeem,
    YieldAccrual,
    LossSocialization,
    Rebalance,
    CollateralLock,
    CollateralRelease,
    LiquidationBackstop,
    StrategyFee,
}

impl VaultAccountingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Redeem => "redeem",
            Self::YieldAccrual => "yield_accrual",
            Self::LossSocialization => "loss_socialization",
            Self::Rebalance => "rebalance",
            Self::CollateralLock => "collateral_lock",
            Self::CollateralRelease => "collateral_release",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::StrategyFee => "strategy_fee",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultPositionStatus {
    Open,
    Locked,
    Netted,
    Settled,
    Redeemed,
    Paused,
    Challenged,
    Slashed,
}

impl VaultPositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Redeemed => "redeemed",
            Self::Paused => "paused",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Redeemed | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRebateKind {
    UserFee,
    SponsorFee,
    SequencerFee,
    ProofFee,
    StorageFee,
    PrivacyFee,
    RouteRebate,
    LatencyRebate,
    AuditReward,
    SlashCredit,
}

impl FeeRebateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserFee => "user_fee",
            Self::SponsorFee => "sponsor_fee",
            Self::SequencerFee => "sequencer_fee",
            Self::ProofFee => "proof_fee",
            Self::StorageFee => "storage_fee",
            Self::PrivacyFee => "privacy_fee",
            Self::RouteRebate => "route_rebate",
            Self::LatencyRebate => "latency_rebate",
            Self::AuditReward => "audit_reward",
            Self::SlashCredit => "slash_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRebateStatus {
    Accrued,
    Reserved,
    Applied,
    Rebated,
    Burned,
    Expired,
    Challenged,
}

impl FeeRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Rebated => "rebated",
            Self::Burned => "burned",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Burned | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProofKind {
    BalanceConservation,
    NoDoubleSpend,
    NetConservation,
    VaultSolvency,
    FeeBound,
    PrivacyBudget,
    NullifierSet,
    CheckpointInclusion,
    RecursiveAggregate,
}

impl AuditProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BalanceConservation => "balance_conservation",
            Self::NoDoubleSpend => "no_double_spend",
            Self::NetConservation => "net_conservation",
            Self::VaultSolvency => "vault_solvency",
            Self::FeeBound => "fee_bound",
            Self::PrivacyBudget => "privacy_budget",
            Self::NullifierSet => "nullifier_set",
            Self::CheckpointInclusion => "checkpoint_inclusion",
            Self::RecursiveAggregate => "recursive_aggregate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProofStatus {
    Submitted,
    Verified,
    Aggregated,
    Finalized,
    Rejected,
    Expired,
    Challenged,
}

impl AuditProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Aggregated => "aggregated",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyEventKind {
    BudgetDebit,
    BudgetCredit,
    NullifierInsert,
    ViewKeyDisclosure,
    AuditOpening,
    DecoyRefresh,
    LinkageAlarm,
    EpochRotate,
}

impl PrivacyEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BudgetDebit => "budget_debit",
            Self::BudgetCredit => "budget_credit",
            Self::NullifierInsert => "nullifier_insert",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::AuditOpening => "audit_opening",
            Self::DecoyRefresh => "decoy_refresh",
            Self::LinkageAlarm => "linkage_alarm",
            Self::EpochRotate => "epoch_rotate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyEventStatus {
    Open,
    Applied,
    Anchored,
    Expired,
    Challenged,
}

impl PrivacyEventStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Applied => "applied",
            Self::Anchored => "anchored",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStatus {
    Draft,
    Sealed,
    Preconfirmed,
    Proven,
    Finalized,
    Reorged,
    Challenged,
}

impl CheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Preconfirmed => "preconfirmed",
            Self::Proven => "proven",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Reorged)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidAuthorization,
    DoubleNullifier,
    BalanceMismatch,
    NetMismatch,
    VaultInsolvency,
    FeeOvercharge,
    PrivacyBudgetExceeded,
    StaleCheckpoint,
    InvalidAuditProof,
    OperatorEquivocation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidAuthorization => "invalid_authorization",
            Self::DoubleNullifier => "double_nullifier",
            Self::BalanceMismatch => "balance_mismatch",
            Self::NetMismatch => "net_mismatch",
            Self::VaultInsolvency => "vault_insolvency",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::StaleCheckpoint => "stale_checkpoint",
            Self::InvalidAuditProof => "invalid_audit_proof",
            Self::OperatorEquivocation => "operator_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    EvidenceLocked,
    Accepted,
    Rejected,
    SlashingQueued,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::EvidenceLocked => "evidence_locked",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::SlashingQueued => "slashing_queued",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Rejected | Self::Slashed | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingTargetKind {
    Sequencer,
    Prover,
    VaultOperator,
    FeeSponsor,
    ContractExecutor,
    Auditor,
    Router,
    Watcher,
}

impl SlashingTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Prover => "prover",
            Self::VaultOperator => "vault_operator",
            Self::FeeSponsor => "fee_sponsor",
            Self::ContractExecutor => "contract_executor",
            Self::Auditor => "auditor",
            Self::Router => "router",
            Self::Watcher => "watcher",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub activation_height: u64,
    pub auth_ttl_blocks: u64,
    pub private_call_ttl_blocks: u64,
    pub settlement_net_ttl_blocks: u64,
    pub checkpoint_interval_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_operator_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_penalty_bps: u64,
    pub max_privacy_budget_units: u64,
    pub privacy_budget_replenish_per_block: u64,
    pub max_accounts: usize,
    pub max_balance_commitments: usize,
    pub max_pq_authorizations: usize,
    pub max_private_calls: usize,
    pub max_settlement_nets: usize,
    pub max_vault_positions: usize,
    pub max_fee_rebates: usize,
    pub max_audit_proofs: usize,
    pub max_privacy_events: usize,
    pub max_nullifiers: usize,
    pub max_checkpoints: usize,
    pub max_challenges: usize,
    pub max_calls_per_net: usize,
    pub max_vaults_per_net: usize,
    pub max_tokens_per_net: usize,
    pub max_recursive_depth: u16,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "activation_height": self.activation_height,
            "auth_ttl_blocks": self.auth_ttl_blocks,
            "private_call_ttl_blocks": self.private_call_ttl_blocks,
            "settlement_net_ttl_blocks": self.settlement_net_ttl_blocks,
            "checkpoint_interval_blocks": self.checkpoint_interval_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_operator_fee_bps": self.max_operator_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "slashing_penalty_bps": self.slashing_penalty_bps,
            "max_privacy_budget_units": self.max_privacy_budget_units,
            "privacy_budget_replenish_per_block": self.privacy_budget_replenish_per_block,
            "max_accounts": self.max_accounts,
            "max_balance_commitments": self.max_balance_commitments,
            "max_pq_authorizations": self.max_pq_authorizations,
            "max_private_calls": self.max_private_calls,
            "max_settlement_nets": self.max_settlement_nets,
            "max_vault_positions": self.max_vault_positions,
            "max_fee_rebates": self.max_fee_rebates,
            "max_audit_proofs": self.max_audit_proofs,
            "max_privacy_events": self.max_privacy_events,
            "max_nullifiers": self.max_nullifiers,
            "max_checkpoints": self.max_checkpoints,
            "max_challenges": self.max_challenges,
            "max_calls_per_net": self.max_calls_per_net,
            "max_vaults_per_net": self.max_vaults_per_net,
            "max_tokens_per_net": self.max_tokens_per_net,
            "max_recursive_depth": self.max_recursive_depth,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub accounts: u64,
    pub balance_commitments: u64,
    pub pq_authorizations: u64,
    pub private_calls: u64,
    pub settlement_nets: u64,
    pub vault_positions: u64,
    pub fee_rebates: u64,
    pub audit_proofs: u64,
    pub privacy_events: u64,
    pub nullifiers: u64,
    pub checkpoints: u64,
    pub challenges: u64,
    pub slashings: u64,
    pub settled_units: u64,
    pub fee_units: u64,
    pub rebate_units: u64,
    pub privacy_budget_debited: u64,
    pub privacy_budget_credited: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "accounts": self.accounts,
            "balance_commitments": self.balance_commitments,
            "pq_authorizations": self.pq_authorizations,
            "private_calls": self.private_calls,
            "settlement_nets": self.settlement_nets,
            "vault_positions": self.vault_positions,
            "fee_rebates": self.fee_rebates,
            "audit_proofs": self.audit_proofs,
            "privacy_events": self.privacy_events,
            "nullifiers": self.nullifiers,
            "checkpoints": self.checkpoints,
            "challenges": self.challenges,
            "slashings": self.slashings,
            "settled_units": self.settled_units,
            "fee_units": self.fee_units,
            "rebate_units": self.rebate_units,
            "privacy_budget_debited": self.privacy_budget_debited,
            "privacy_budget_credited": self.privacy_budget_credited,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub account_root: String,
    pub balance_commitment_root: String,
    pub pq_authorization_root: String,
    pub private_call_root: String,
    pub settlement_net_root: String,
    pub vault_position_root: String,
    pub fee_rebate_root: String,
    pub audit_proof_root: String,
    pub privacy_event_root: String,
    pub nullifier_root: String,
    pub checkpoint_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub state_hint_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "account_root": self.account_root,
            "balance_commitment_root": self.balance_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "private_call_root": self.private_call_root,
            "settlement_net_root": self.settlement_net_root,
            "vault_position_root": self.vault_position_root,
            "fee_rebate_root": self.fee_rebate_root,
            "audit_proof_root": self.audit_proof_root,
            "privacy_event_root": self.privacy_event_root,
            "nullifier_root": self.nullifier_root,
            "checkpoint_root": self.checkpoint_root,
            "challenge_root": self.challenge_root,
            "slashing_root": self.slashing_root,
            "state_hint_root": self.state_hint_root,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountRecord {
    pub account_id: String,
    pub domain_kind: AccountDomainKind,
    pub owner_commitment: String,
    pub view_policy_root: String,
    pub spend_policy_root: String,
    pub recovery_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub last_activity_height: u64,
    pub nonce: u64,
    pub frozen: bool,
}

impl AccountRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "domain_kind": self.domain_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "view_policy_root": self.view_policy_root,
            "spend_policy_root": self.spend_policy_root,
            "recovery_root": self.recovery_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "last_activity_height": self.last_activity_height,
            "nonce": self.nonce,
            "frozen": self.frozen,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("ACCOUNTRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BalanceCommitmentRecord {
    pub commitment_id: String,
    pub account_id: String,
    pub contract_id: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub blinding_commitment: String,
    pub range_proof_root: String,
    pub opening_policy_root: String,
    pub status: CommitmentStatus,
    pub epoch: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: u64,
    pub nonce: u64,
}

impl BalanceCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "account_id": self.account_id,
            "contract_id": self.contract_id,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "blinding_commitment": self.blinding_commitment,
            "range_proof_root": self.range_proof_root,
            "opening_policy_root": self.opening_policy_root,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("BALANCECOMMITMENTRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorizationRecord {
    pub authorization_id: String,
    pub kind: PqAuthorizationKind,
    pub status: AuthorizationStatus,
    pub account_id: String,
    pub subject_id: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub kem_ciphertext_root: String,
    pub policy_root: String,
    pub nullifier: String,
    pub security_bits: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_at_height: u64,
    pub nonce: u64,
}

impl PqAuthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "account_id": self.account_id,
            "subject_id": self.subject_id,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "policy_root": self.policy_root,
            "nullifier": self.nullifier,
            "security_bits": self.security_bits,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed_at_height": self.consumed_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("PQAUTHORIZATIONRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateCallRecord {
    pub call_id: String,
    pub kind: PrivateCallKind,
    pub status: PrivateCallStatus,
    pub caller_account_id: String,
    pub source_contract_id: String,
    pub target_contract_id: String,
    pub calldata_commitment: String,
    pub witness_root: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub authorization_id: String,
    pub fee_rebate_id: String,
    pub max_fee_units: u64,
    pub privacy_budget_units: u64,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: u64,
}

impl PrivateCallRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "caller_account_id": self.caller_account_id,
            "source_contract_id": self.source_contract_id,
            "target_contract_id": self.target_contract_id,
            "calldata_commitment": self.calldata_commitment,
            "witness_root": self.witness_root,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "authorization_id": self.authorization_id,
            "fee_rebate_id": self.fee_rebate_id,
            "max_fee_units": self.max_fee_units,
            "privacy_budget_units": self.privacy_budget_units,
            "queued_at_height": self.queued_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("PRIVATECALLRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenSettlementNetRecord {
    pub net_id: String,
    pub kind: SettlementNetKind,
    pub status: SettlementNetStatus,
    pub asset_id: String,
    pub net_debit_root: String,
    pub net_credit_root: String,
    pub call_root: String,
    pub authorization_root: String,
    pub conservation_proof_root: String,
    pub gross_debit_units: u64,
    pub gross_credit_units: u64,
    pub fee_units: u64,
    pub rebate_units: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settled_at_height: u64,
    pub participant_count: u64,
}

impl TokenSettlementNetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "net_id": self.net_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "net_debit_root": self.net_debit_root,
            "net_credit_root": self.net_credit_root,
            "call_root": self.call_root,
            "authorization_root": self.authorization_root,
            "conservation_proof_root": self.conservation_proof_root,
            "gross_debit_units": self.gross_debit_units,
            "gross_credit_units": self.gross_credit_units,
            "fee_units": self.fee_units,
            "rebate_units": self.rebate_units,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settled_at_height": self.settled_at_height,
            "participant_count": self.participant_count,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("TOKENSETTLEMENTNETRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultAccountingRecord {
    pub vault_position_id: String,
    pub kind: VaultAccountingKind,
    pub status: VaultPositionStatus,
    pub vault_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub share_commitment: String,
    pub asset_commitment: String,
    pub strategy_root: String,
    pub solvency_proof_root: String,
    pub settlement_net_id: String,
    pub fee_units: u64,
    pub opened_at_height: u64,
    pub settled_at_height: u64,
    pub nonce: u64,
}

impl VaultAccountingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_position_id": self.vault_position_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "vault_id": self.vault_id,
            "account_id": self.account_id,
            "asset_id": self.asset_id,
            "share_commitment": self.share_commitment,
            "asset_commitment": self.asset_commitment,
            "strategy_root": self.strategy_root,
            "solvency_proof_root": self.solvency_proof_root,
            "settlement_net_id": self.settlement_net_id,
            "fee_units": self.fee_units,
            "opened_at_height": self.opened_at_height,
            "settled_at_height": self.settled_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("VAULTACCOUNTINGRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub fee_rebate_id: String,
    pub kind: FeeRebateKind,
    pub status: FeeRebateStatus,
    pub account_id: String,
    pub asset_id: String,
    pub source_id: String,
    pub fee_commitment: String,
    pub rebate_commitment: String,
    pub sponsor_commitment: String,
    pub fee_units: u64,
    pub rebate_units: u64,
    pub accrued_at_height: u64,
    pub applied_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_rebate_id": self.fee_rebate_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "account_id": self.account_id,
            "asset_id": self.asset_id,
            "source_id": self.source_id,
            "fee_commitment": self.fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_units": self.fee_units,
            "rebate_units": self.rebate_units,
            "accrued_at_height": self.accrued_at_height,
            "applied_at_height": self.applied_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("FEEREBATERECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveAuditProofRecord {
    pub audit_proof_id: String,
    pub kind: AuditProofKind,
    pub status: AuditProofStatus,
    pub subject_root: String,
    pub input_root: String,
    pub output_root: String,
    pub recursive_parent_root: String,
    pub proof_root: String,
    pub verifier_key_root: String,
    pub recursive_depth: u16,
    pub proved_at_height: u64,
    pub finalized_at_height: u64,
}

impl RecursiveAuditProofRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "audit_proof_id": self.audit_proof_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "subject_root": self.subject_root,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "recursive_parent_root": self.recursive_parent_root,
            "proof_root": self.proof_root,
            "verifier_key_root": self.verifier_key_root,
            "recursive_depth": self.recursive_depth,
            "proved_at_height": self.proved_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("RECURSIVEAUDITPROOFRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetRecord {
    pub privacy_event_id: String,
    pub kind: PrivacyEventKind,
    pub status: PrivacyEventStatus,
    pub account_id: String,
    pub scope_id: String,
    pub nullifier: String,
    pub budget_commitment: String,
    pub event_root: String,
    pub debit_units: u64,
    pub credit_units: u64,
    pub remaining_units: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub anchored_at_height: u64,
}

impl PrivacyBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "privacy_event_id": self.privacy_event_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "account_id": self.account_id,
            "scope_id": self.scope_id,
            "nullifier": self.nullifier,
            "budget_commitment": self.budget_commitment,
            "event_root": self.event_root,
            "debit_units": self.debit_units,
            "credit_units": self.credit_units,
            "remaining_units": self.remaining_units,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "anchored_at_height": self.anchored_at_height,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("PRIVACYBUDGETRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastSettlementCheckpointRecord {
    pub checkpoint_id: String,
    pub status: CheckpointStatus,
    pub previous_checkpoint_id: String,
    pub state_root: String,
    pub settlement_net_root: String,
    pub private_call_root: String,
    pub audit_root: String,
    pub nullifier_root: String,
    pub operator_attestation_root: String,
    pub height: u64,
    pub preconfirmed_at_height: u64,
    pub finalized_at_height: u64,
    pub settled_net_count: u64,
    pub settled_call_count: u64,
}

impl FastSettlementCheckpointRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "status": self.status.as_str(),
            "previous_checkpoint_id": self.previous_checkpoint_id,
            "state_root": self.state_root,
            "settlement_net_root": self.settlement_net_root,
            "private_call_root": self.private_call_root,
            "audit_root": self.audit_root,
            "nullifier_root": self.nullifier_root,
            "operator_attestation_root": self.operator_attestation_root,
            "height": self.height,
            "preconfirmed_at_height": self.preconfirmed_at_height,
            "finalized_at_height": self.finalized_at_height,
            "settled_net_count": self.settled_net_count,
            "settled_call_count": self.settled_call_count,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("FASTSETTLEMENTCHECKPOINTRECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeEvidenceRecord {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub target_kind: SlashingTargetKind,
    pub target_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub counter_evidence_root: String,
    pub bond_commitment: String,
    pub slash_receipt_root: String,
    pub filed_at_height: u64,
    pub resolved_at_height: u64,
    pub penalty_units: u64,
}

impl ChallengeEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "target_kind": self.target_kind.as_str(),
            "target_id": self.target_id,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "counter_evidence_root": self.counter_evidence_root,
            "bond_commitment": self.bond_commitment,
            "slash_receipt_root": self.slash_receipt_root,
            "filed_at_height": self.filed_at_height,
            "resolved_at_height": self.resolved_at_height,
            "penalty_units": self.penalty_units,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("CHALLENGEEVIDENCERECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidenceRecord {
    pub slashing_id: String,
    pub target_kind: SlashingTargetKind,
    pub target_id: String,
    pub challenge_id: String,
    pub evidence_root: String,
    pub penalty_commitment: String,
    pub penalty_units: u64,
    pub slashed_at_height: u64,
}

impl SlashingEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "target_kind": self.target_kind.as_str(),
            "target_id": self.target_id,
            "challenge_id": self.challenge_id,
            "evidence_root": self.evidence_root,
            "penalty_commitment": self.penalty_commitment,
            "penalty_units": self.penalty_units,
            "slashed_at_height": self.slashed_at_height,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("SLASHINGEVIDENCERECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterAccountRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl RegisterAccountRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("REGISTERACCOUNTREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitBalanceRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl CommitBalanceRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("COMMITBALANCEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPqAuthorizationRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl SubmitPqAuthorizationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("SUBMITPQAUTHORIZATIONREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueuePrivateCallRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl QueuePrivateCallRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("QUEUEPRIVATECALLREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenSettlementNetRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl OpenSettlementNetRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("OPENSETTLEMENTNETREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleNetRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl SettleNetRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("SETTLENETREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitAuditProofRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl SubmitAuditProofRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("SUBMITAUDITPROOFREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApplyPrivacyEventRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl ApplyPrivacyEventRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("APPLYPRIVACYEVENTREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileChallengeRequest {
    pub request_id: String,
    pub actor_id: String,
    pub subject_id: String,
    pub payload_root: String,
    pub authorization_root: String,
    pub height: u64,
    pub nonce: u64,
}

impl FileChallengeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "authorization_root": self.authorization_root,
            "height": self.height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        accounting_payload_root("FILECHALLENGEREQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub accounts: BTreeMap<String, AccountRecord>,
    pub balance_commitments: BTreeMap<String, BalanceCommitmentRecord>,
    pub pq_authorizations: BTreeMap<String, PqAuthorizationRecord>,
    pub private_calls: BTreeMap<String, PrivateCallRecord>,
    pub settlement_nets: BTreeMap<String, TokenSettlementNetRecord>,
    pub vault_positions: BTreeMap<String, VaultAccountingRecord>,
    pub fee_rebates: BTreeMap<String, FeeRebateRecord>,
    pub audit_proofs: BTreeMap<String, RecursiveAuditProofRecord>,
    pub privacy_events: BTreeMap<String, PrivacyBudgetRecord>,
    pub nullifiers: BTreeSet<String>,
    pub checkpoints: BTreeMap<String, FastSettlementCheckpointRecord>,
    pub challenges: BTreeMap<String, ChallengeEvidenceRecord>,
    pub slashings: BTreeMap<String, SlashingEvidenceRecord>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            activation_height: DEVNET_HEIGHT,
            auth_ttl_blocks: DEFAULT_AUTH_TTL_BLOCKS,
            private_call_ttl_blocks: DEFAULT_PRIVATE_CALL_TTL_BLOCKS,
            settlement_net_ttl_blocks: DEFAULT_NET_TTL_BLOCKS,
            checkpoint_interval_blocks: DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_operator_fee_bps: DEFAULT_MAX_OPERATOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            slashing_penalty_bps: DEFAULT_SLASHING_PENALTY_BPS,
            max_privacy_budget_units: DEFAULT_MAX_PRIVACY_BUDGET_UNITS,
            privacy_budget_replenish_per_block: DEFAULT_PRIVACY_BUDGET_REPLENISH_PER_BLOCK,
            max_accounts: DEFAULT_MAX_ACCOUNTS,
            max_balance_commitments: DEFAULT_MAX_BALANCE_COMMITMENTS,
            max_pq_authorizations: DEFAULT_MAX_PQ_AUTHORIZATIONS,
            max_private_calls: DEFAULT_MAX_PRIVATE_CALLS,
            max_settlement_nets: DEFAULT_MAX_SETTLEMENT_NETS,
            max_vault_positions: DEFAULT_MAX_VAULT_POSITIONS,
            max_fee_rebates: DEFAULT_MAX_FEE_REBATES,
            max_audit_proofs: DEFAULT_MAX_AUDIT_PROOFS,
            max_privacy_events: DEFAULT_MAX_PRIVACY_BUDGETS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            max_checkpoints: DEFAULT_MAX_CHECKPOINTS,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_calls_per_net: DEFAULT_MAX_CALLS_PER_NET,
            max_vaults_per_net: DEFAULT_MAX_VAULTS_PER_NET,
            max_tokens_per_net: DEFAULT_MAX_TOKENS_PER_NET,
            max_recursive_depth: DEFAULT_MAX_RECURSIVE_DEPTH,
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            accounts: 0,
            balance_commitments: 0,
            pq_authorizations: 0,
            private_calls: 0,
            settlement_nets: 0,
            vault_positions: 0,
            fee_rebates: 0,
            audit_proofs: 0,
            privacy_events: 0,
            nullifiers: 0,
            checkpoints: 0,
            challenges: 0,
            slashings: 0,
            settled_units: 0,
            fee_units: 0,
            rebate_units: 0,
            privacy_budget_debited: 0,
            privacy_budget_credited: 0,
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            accounts: BTreeMap::new(),
            balance_commitments: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            private_calls: BTreeMap::new(),
            settlement_nets: BTreeMap::new(),
            vault_positions: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            audit_proofs: BTreeMap::new(),
            privacy_events: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            checkpoints: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashings: BTreeMap::new(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            account_root: map_root(
                "ACCOUNT_ROOT",
                self.accounts
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            balance_commitment_root: map_root(
                "BALANCE_COMMITMENT_ROOT",
                self.balance_commitments
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            pq_authorization_root: map_root(
                "PQ_AUTHORIZATION_ROOT",
                self.pq_authorizations
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            private_call_root: map_root(
                "PRIVATE_CALL_ROOT",
                self.private_calls
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            settlement_net_root: map_root(
                "SETTLEMENT_NET_ROOT",
                self.settlement_nets
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            vault_position_root: map_root(
                "VAULT_POSITION_ROOT",
                self.vault_positions
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            fee_rebate_root: map_root(
                "FEE_REBATE_ROOT",
                self.fee_rebates
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            audit_proof_root: map_root(
                "AUDIT_PROOF_ROOT",
                self.audit_proofs
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            privacy_event_root: map_root(
                "PRIVACY_EVENT_ROOT",
                self.privacy_events
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            checkpoint_root: map_root(
                "CHECKPOINT_ROOT",
                self.checkpoints
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            challenge_root: map_root(
                "CHALLENGE_ROOT",
                self.challenges
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            slashing_root: map_root(
                "SLASHING_ROOT",
                self.slashings
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            nullifier_root: set_root("NULLIFIER", &self.nullifiers),
            state_hint_root: accounting_payload_root(
                "STATE-HINT",
                &self.public_record_without_root(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        accounting_payload_root("STATE", &self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": roots.public_record() })
    }

    pub fn register_account(&mut self, record: AccountRecord) -> Result<String> {
        ensure_capacity(self.accounts.len(), self.config.max_accounts, "accounts")?;
        if self.accounts.contains_key(&record.account_id) {
            return Err(format!("duplicate account_id: {}", record.account_id));
        }
        let id = record.account_id.clone();
        self.accounts.insert(id.clone(), record);
        self.counters.accounts = self.counters.accounts.saturating_add(1);
        Ok(id)
    }

    pub fn commit_balance(&mut self, record: BalanceCommitmentRecord) -> Result<String> {
        ensure_capacity(
            self.balance_commitments.len(),
            self.config.max_balance_commitments,
            "balance_commitments",
        )?;
        if self.balance_commitments.contains_key(&record.commitment_id) {
            return Err(format!("duplicate commitment_id: {}", record.commitment_id));
        }
        let id = record.commitment_id.clone();
        self.balance_commitments.insert(id.clone(), record);
        self.counters.balance_commitments = self.counters.balance_commitments.saturating_add(1);
        Ok(id)
    }

    pub fn submit_pq_authorization(&mut self, record: PqAuthorizationRecord) -> Result<String> {
        ensure_capacity(
            self.pq_authorizations.len(),
            self.config.max_pq_authorizations,
            "pq_authorizations",
        )?;
        if self
            .pq_authorizations
            .contains_key(&record.authorization_id)
        {
            return Err(format!(
                "duplicate authorization_id: {}",
                record.authorization_id
            ));
        }
        let id = record.authorization_id.clone();
        self.pq_authorizations.insert(id.clone(), record);
        self.counters.pq_authorizations = self.counters.pq_authorizations.saturating_add(1);
        Ok(id)
    }

    pub fn queue_private_call(&mut self, record: PrivateCallRecord) -> Result<String> {
        ensure_capacity(
            self.private_calls.len(),
            self.config.max_private_calls,
            "private_calls",
        )?;
        if self.private_calls.contains_key(&record.call_id) {
            return Err(format!("duplicate call_id: {}", record.call_id));
        }
        let id = record.call_id.clone();
        self.private_calls.insert(id.clone(), record);
        self.counters.private_calls = self.counters.private_calls.saturating_add(1);
        Ok(id)
    }

    pub fn open_settlement_net(&mut self, record: TokenSettlementNetRecord) -> Result<String> {
        ensure_capacity(
            self.settlement_nets.len(),
            self.config.max_settlement_nets,
            "settlement_nets",
        )?;
        if self.settlement_nets.contains_key(&record.net_id) {
            return Err(format!("duplicate net_id: {}", record.net_id));
        }
        let id = record.net_id.clone();
        self.settlement_nets.insert(id.clone(), record);
        self.counters.settlement_nets = self.counters.settlement_nets.saturating_add(1);
        Ok(id)
    }

    pub fn record_vault_accounting(&mut self, record: VaultAccountingRecord) -> Result<String> {
        ensure_capacity(
            self.vault_positions.len(),
            self.config.max_vault_positions,
            "vault_positions",
        )?;
        if self.vault_positions.contains_key(&record.vault_position_id) {
            return Err(format!(
                "duplicate vault_position_id: {}",
                record.vault_position_id
            ));
        }
        let id = record.vault_position_id.clone();
        self.vault_positions.insert(id.clone(), record);
        self.counters.vault_positions = self.counters.vault_positions.saturating_add(1);
        Ok(id)
    }

    pub fn accrue_fee_rebate(&mut self, record: FeeRebateRecord) -> Result<String> {
        ensure_capacity(
            self.fee_rebates.len(),
            self.config.max_fee_rebates,
            "fee_rebates",
        )?;
        if self.fee_rebates.contains_key(&record.fee_rebate_id) {
            return Err(format!("duplicate fee_rebate_id: {}", record.fee_rebate_id));
        }
        let id = record.fee_rebate_id.clone();
        self.fee_rebates.insert(id.clone(), record);
        self.counters.fee_rebates = self.counters.fee_rebates.saturating_add(1);
        Ok(id)
    }

    pub fn submit_audit_proof(&mut self, record: RecursiveAuditProofRecord) -> Result<String> {
        ensure_capacity(
            self.audit_proofs.len(),
            self.config.max_audit_proofs,
            "audit_proofs",
        )?;
        if self.audit_proofs.contains_key(&record.audit_proof_id) {
            return Err(format!(
                "duplicate audit_proof_id: {}",
                record.audit_proof_id
            ));
        }
        let id = record.audit_proof_id.clone();
        self.audit_proofs.insert(id.clone(), record);
        self.counters.audit_proofs = self.counters.audit_proofs.saturating_add(1);
        Ok(id)
    }

    pub fn apply_privacy_event(&mut self, record: PrivacyBudgetRecord) -> Result<String> {
        ensure_capacity(
            self.privacy_events.len(),
            self.config.max_privacy_events,
            "privacy_events",
        )?;
        if self.privacy_events.contains_key(&record.privacy_event_id) {
            return Err(format!(
                "duplicate privacy_event_id: {}",
                record.privacy_event_id
            ));
        }
        if !record.nullifier.is_empty() {
            self.insert_nullifier(record.nullifier.clone())?;
        }
        let id = record.privacy_event_id.clone();
        self.privacy_events.insert(id.clone(), record);
        self.counters.privacy_events = self.counters.privacy_events.saturating_add(1);
        Ok(id)
    }

    pub fn seal_checkpoint(&mut self, record: FastSettlementCheckpointRecord) -> Result<String> {
        ensure_capacity(
            self.checkpoints.len(),
            self.config.max_checkpoints,
            "checkpoints",
        )?;
        if self.checkpoints.contains_key(&record.checkpoint_id) {
            return Err(format!("duplicate checkpoint_id: {}", record.checkpoint_id));
        }
        let id = record.checkpoint_id.clone();
        self.checkpoints.insert(id.clone(), record);
        self.counters.checkpoints = self.counters.checkpoints.saturating_add(1);
        Ok(id)
    }

    pub fn file_challenge(&mut self, record: ChallengeEvidenceRecord) -> Result<String> {
        ensure_capacity(
            self.challenges.len(),
            self.config.max_challenges,
            "challenges",
        )?;
        if self.challenges.contains_key(&record.challenge_id) {
            return Err(format!("duplicate challenge_id: {}", record.challenge_id));
        }
        let id = record.challenge_id.clone();
        self.challenges.insert(id.clone(), record);
        self.counters.challenges = self.counters.challenges.saturating_add(1);
        Ok(id)
    }

    pub fn insert_nullifier(&mut self, nullifier: String) -> Result<()> {
        ensure_capacity(
            self.nullifiers.len(),
            self.config.max_nullifiers,
            "nullifiers",
        )?;
        if !self.nullifiers.insert(nullifier.clone()) {
            return Err(format!("duplicate nullifier: {nullifier}"));
        }
        self.counters.nullifiers = self.counters.nullifiers.saturating_add(1);
        Ok(())
    }

    pub fn authorize_commitment(&mut self, commitment_id: &str, height: u64) -> Result<()> {
        let record = self
            .balance_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| format!("unknown commitment_id: {commitment_id}"))?;
        if record.status.terminal() {
            return Err(format!("commitment_id is terminal: {commitment_id}"));
        }
        record.status = CommitmentStatus::Authorized;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn lock_commitment(&mut self, commitment_id: &str, height: u64) -> Result<()> {
        let record = self
            .balance_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| format!("unknown commitment_id: {commitment_id}"))?;
        if record.status.terminal() {
            return Err(format!("commitment_id is terminal: {commitment_id}"));
        }
        record.status = CommitmentStatus::Locked;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn settle_commitment(&mut self, commitment_id: &str, height: u64) -> Result<()> {
        let record = self
            .balance_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| format!("unknown commitment_id: {commitment_id}"))?;
        if record.status.terminal() {
            return Err(format!("commitment_id is terminal: {commitment_id}"));
        }
        record.status = CommitmentStatus::Settled;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn verify_authorization(&mut self, authorization_id: &str, height: u64) -> Result<()> {
        let record = self
            .pq_authorizations
            .get_mut(authorization_id)
            .ok_or_else(|| format!("unknown authorization_id: {authorization_id}"))?;
        if record.status.terminal() {
            return Err(format!("authorization_id is terminal: {authorization_id}"));
        }
        record.status = AuthorizationStatus::Verified;
        record.consumed_at_height = height;
        Ok(())
    }

    pub fn consume_authorization(&mut self, authorization_id: &str, height: u64) -> Result<()> {
        let record = self
            .pq_authorizations
            .get_mut(authorization_id)
            .ok_or_else(|| format!("unknown authorization_id: {authorization_id}"))?;
        if record.status.terminal() {
            return Err(format!("authorization_id is terminal: {authorization_id}"));
        }
        record.status = AuthorizationStatus::Consumed;
        record.consumed_at_height = height;
        Ok(())
    }

    pub fn authorize_private_call(&mut self, call_id: &str, height: u64) -> Result<()> {
        let record = self
            .private_calls
            .get_mut(call_id)
            .ok_or_else(|| format!("unknown call_id: {call_id}"))?;
        if record.status.terminal() {
            return Err(format!("call_id is terminal: {call_id}"));
        }
        record.status = PrivateCallStatus::Authorized;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn execute_private_call(&mut self, call_id: &str, height: u64) -> Result<()> {
        let record = self
            .private_calls
            .get_mut(call_id)
            .ok_or_else(|| format!("unknown call_id: {call_id}"))?;
        if record.status.terminal() {
            return Err(format!("call_id is terminal: {call_id}"));
        }
        record.status = PrivateCallStatus::Executing;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn settle_private_call(&mut self, call_id: &str, height: u64) -> Result<()> {
        let record = self
            .private_calls
            .get_mut(call_id)
            .ok_or_else(|| format!("unknown call_id: {call_id}"))?;
        if record.status.terminal() {
            return Err(format!("call_id is terminal: {call_id}"));
        }
        record.status = PrivateCallStatus::Settled;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn seal_settlement_net(&mut self, net_id: &str, height: u64) -> Result<()> {
        let record = self
            .settlement_nets
            .get_mut(net_id)
            .ok_or_else(|| format!("unknown net_id: {net_id}"))?;
        if record.status.terminal() {
            return Err(format!("net_id is terminal: {net_id}"));
        }
        record.status = SettlementNetStatus::Sealed;
        record.settled_at_height = height;
        self.counters.settled_units = self
            .counters
            .settled_units
            .saturating_add(record.gross_credit_units);
        self.counters.fee_units = self.counters.fee_units.saturating_add(record.fee_units);
        self.counters.rebate_units = self
            .counters
            .rebate_units
            .saturating_add(record.rebate_units);
        Ok(())
    }

    pub fn settle_settlement_net(&mut self, net_id: &str, height: u64) -> Result<()> {
        let record = self
            .settlement_nets
            .get_mut(net_id)
            .ok_or_else(|| format!("unknown net_id: {net_id}"))?;
        if record.status.terminal() {
            return Err(format!("net_id is terminal: {net_id}"));
        }
        record.status = SettlementNetStatus::Settled;
        record.settled_at_height = height;
        self.counters.settled_units = self
            .counters
            .settled_units
            .saturating_add(record.gross_credit_units);
        self.counters.fee_units = self.counters.fee_units.saturating_add(record.fee_units);
        self.counters.rebate_units = self
            .counters
            .rebate_units
            .saturating_add(record.rebate_units);
        Ok(())
    }

    pub fn lock_vault_position(&mut self, vault_position_id: &str, height: u64) -> Result<()> {
        let record = self
            .vault_positions
            .get_mut(vault_position_id)
            .ok_or_else(|| format!("unknown vault_position_id: {vault_position_id}"))?;
        if record.status.terminal() {
            return Err(format!(
                "vault_position_id is terminal: {vault_position_id}"
            ));
        }
        record.status = VaultPositionStatus::Locked;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn settle_vault_position(&mut self, vault_position_id: &str, height: u64) -> Result<()> {
        let record = self
            .vault_positions
            .get_mut(vault_position_id)
            .ok_or_else(|| format!("unknown vault_position_id: {vault_position_id}"))?;
        if record.status.terminal() {
            return Err(format!(
                "vault_position_id is terminal: {vault_position_id}"
            ));
        }
        record.status = VaultPositionStatus::Settled;
        record.settled_at_height = height;
        Ok(())
    }

    pub fn apply_fee_rebate(&mut self, fee_rebate_id: &str, height: u64) -> Result<()> {
        let record = self
            .fee_rebates
            .get_mut(fee_rebate_id)
            .ok_or_else(|| format!("unknown fee_rebate_id: {fee_rebate_id}"))?;
        if record.status.terminal() {
            return Err(format!("fee_rebate_id is terminal: {fee_rebate_id}"));
        }
        record.status = FeeRebateStatus::Applied;
        record.applied_at_height = height;
        Ok(())
    }

    pub fn verify_audit_proof(&mut self, audit_proof_id: &str, height: u64) -> Result<()> {
        let record = self
            .audit_proofs
            .get_mut(audit_proof_id)
            .ok_or_else(|| format!("unknown audit_proof_id: {audit_proof_id}"))?;
        if record.status.terminal() {
            return Err(format!("audit_proof_id is terminal: {audit_proof_id}"));
        }
        record.status = AuditProofStatus::Verified;
        record.finalized_at_height = height;
        Ok(())
    }

    pub fn anchor_privacy_event(&mut self, privacy_event_id: &str, height: u64) -> Result<()> {
        let record = self
            .privacy_events
            .get_mut(privacy_event_id)
            .ok_or_else(|| format!("unknown privacy_event_id: {privacy_event_id}"))?;
        if record.status.terminal() {
            return Err(format!("privacy_event_id is terminal: {privacy_event_id}"));
        }
        record.status = PrivacyEventStatus::Anchored;
        record.anchored_at_height = height;
        Ok(())
    }

    pub fn preconfirm_checkpoint(&mut self, checkpoint_id: &str, height: u64) -> Result<()> {
        let record = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint_id: {checkpoint_id}"))?;
        if record.status.terminal() {
            return Err(format!("checkpoint_id is terminal: {checkpoint_id}"));
        }
        record.status = CheckpointStatus::Preconfirmed;
        record.finalized_at_height = height;
        Ok(())
    }

    pub fn finalize_checkpoint(&mut self, checkpoint_id: &str, height: u64) -> Result<()> {
        let record = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| format!("unknown checkpoint_id: {checkpoint_id}"))?;
        if record.status.terminal() {
            return Err(format!("checkpoint_id is terminal: {checkpoint_id}"));
        }
        record.status = CheckpointStatus::Finalized;
        record.finalized_at_height = height;
        Ok(())
    }

    pub fn accept_challenge(&mut self, challenge_id: &str, height: u64) -> Result<()> {
        let record = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown challenge_id: {challenge_id}"))?;
        if record.status.terminal() {
            return Err(format!("challenge_id is terminal: {challenge_id}"));
        }
        record.status = ChallengeStatus::Accepted;
        record.resolved_at_height = height;
        Ok(())
    }

    pub fn reject_challenge(&mut self, challenge_id: &str, height: u64) -> Result<()> {
        let record = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown challenge_id: {challenge_id}"))?;
        if record.status.terminal() {
            return Err(format!("challenge_id is terminal: {challenge_id}"));
        }
        record.status = ChallengeStatus::Rejected;
        record.resolved_at_height = height;
        Ok(())
    }

    pub fn slash_from_challenge(
        &mut self,
        challenge_id: &str,
        evidence_root: String,
        height: u64,
    ) -> Result<String> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown challenge_id: {challenge_id}"))?;
        if challenge.status.terminal() {
            return Err(format!("challenge is terminal: {challenge_id}"));
        }
        challenge.status = ChallengeStatus::Slashed;
        challenge.resolved_at_height = height;
        let slashing_id = slashing_id(&challenge.target_id, challenge_id, &evidence_root, height);
        let record = SlashingEvidenceRecord {
            slashing_id: slashing_id.clone(),
            target_kind: challenge.target_kind,
            target_id: challenge.target_id.clone(),
            challenge_id: challenge_id.to_string(),
            evidence_root,
            penalty_commitment: accounting_hash(
                "PENALTY",
                &[
                    HashPart::Str(challenge_id),
                    HashPart::Int(challenge.penalty_units as i128),
                ],
            ),
            penalty_units: challenge.penalty_units,
            slashed_at_height: height,
        };
        self.slashings.insert(slashing_id.clone(), record);
        self.counters.slashings = self.counters.slashings.saturating_add(1);
        Ok(slashing_id)
    }
}

pub fn accounting_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-ACCOUNTING:{domain}"),
        parts,
        32,
    )
}

pub fn accounting_payload_root(domain: &str, payload: &Value) -> String {
    accounting_hash(domain, &[HashPart::Json(payload)])
}

pub fn map_root(domain: &str, mut leaves: Vec<Value>) -> String {
    leaves.sort_by_key(|value| value.to_string());
    merkle_root(&format!("PRIVATE-L2-PQ-ACCOUNTING:{domain}"), &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(&format!("PRIVATE-L2-PQ-ACCOUNTING:{domain}"), &leaves)
}

pub fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded: {current}/{max}"))
    } else {
        Ok(())
    }
}

pub fn account_id(domain_kind: AccountDomainKind, owner_commitment: &str, nonce: u64) -> String {
    accounting_hash(
        "ACCOUNT_ID",
        &[
            HashPart::Str(domain_kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn commitment_id(
    account_id: &str,
    contract_id: &str,
    asset_id: &str,
    amount_commitment: &str,
    nonce: u64,
) -> String {
    accounting_hash(
        "COMMITMENT_ID",
        &[
            HashPart::Str(account_id),
            HashPart::Str(contract_id),
            HashPart::Str(asset_id),
            HashPart::Str(amount_commitment),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn authorization_id(
    kind: PqAuthorizationKind,
    account_id: &str,
    subject_id: &str,
    nullifier: &str,
    nonce: u64,
) -> String {
    accounting_hash(
        "AUTHORIZATION_ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(account_id),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn private_call_id(
    kind: PrivateCallKind,
    caller_account_id: &str,
    source_contract_id: &str,
    target_contract_id: &str,
    calldata_commitment: &str,
    nonce: u64,
) -> String {
    accounting_hash(
        "PRIVATE_CALL_ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(caller_account_id),
            HashPart::Str(source_contract_id),
            HashPart::Str(target_contract_id),
            HashPart::Str(calldata_commitment),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn settlement_net_id(
    kind: SettlementNetKind,
    asset_id: &str,
    call_root: &str,
    height: u64,
) -> String {
    accounting_hash(
        "SETTLEMENT_NET_ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Str(call_root),
            HashPart::Int(height as i128),
        ],
    )
}

pub fn vault_position_id(vault_id: &str, account_id: &str, asset_id: &str, nonce: u64) -> String {
    accounting_hash(
        "VAULT_POSITION_ID",
        &[
            HashPart::Str(vault_id),
            HashPart::Str(account_id),
            HashPart::Str(asset_id),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn fee_rebate_id(
    kind: FeeRebateKind,
    account_id: &str,
    source_id: &str,
    height: u64,
) -> String {
    accounting_hash(
        "FEE_REBATE_ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(account_id),
            HashPart::Str(source_id),
            HashPart::Int(height as i128),
        ],
    )
}

pub fn audit_proof_id(
    kind: AuditProofKind,
    subject_root: &str,
    proof_root: &str,
    height: u64,
) -> String {
    accounting_hash(
        "AUDIT_PROOF_ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_root),
            HashPart::Str(proof_root),
            HashPart::Int(height as i128),
        ],
    )
}

pub fn privacy_event_id(
    kind: PrivacyEventKind,
    account_id: &str,
    scope_id: &str,
    nullifier: &str,
    height: u64,
) -> String {
    accounting_hash(
        "PRIVACY_EVENT_ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(account_id),
            HashPart::Str(scope_id),
            HashPart::Str(nullifier),
            HashPart::Int(height as i128),
        ],
    )
}

pub fn checkpoint_id(previous_checkpoint_id: &str, state_root: &str, height: u64) -> String {
    accounting_hash(
        "CHECKPOINT_ID",
        &[
            HashPart::Str(previous_checkpoint_id),
            HashPart::Str(state_root),
            HashPart::Int(height as i128),
        ],
    )
}

pub fn challenge_id(
    kind: ChallengeKind,
    target_id: &str,
    subject_id: &str,
    evidence_root: &str,
    height: u64,
) -> String {
    accounting_hash(
        "CHALLENGE_ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::Int(height as i128),
        ],
    )
}

pub fn slashing_id(
    target_id: &str,
    challenge_id: &str,
    evidence_root: &str,
    height: u64,
) -> String {
    accounting_hash(
        "SLASHING_ID",
        &[
            HashPart::Str(target_id),
            HashPart::Str(challenge_id),
            HashPart::Str(evidence_root),
            HashPart::Int(height as i128),
        ],
    )
}
