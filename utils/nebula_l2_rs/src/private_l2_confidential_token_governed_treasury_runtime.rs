use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenGovernedTreasuryRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2ConfidentialTokenGovernedTreasuryRuntimeResult<T>;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-governed-treasury-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-governed-treasury-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_BUDGET_SCHEME: &str =
    "monero-private-l2-encrypted-token-treasury-budget-proposal-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_VOTE_SCHEME: &str =
    "monero-private-l2-pq-token-treasury-vote-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_VESTING_SCHEME: &str =
    "monero-private-l2-token-treasury-vesting-stream-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INCENTIVE_SCHEME: &str =
    "monero-private-l2-confidential-liquidity-incentive-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_REBATE_SCHEME: &str =
    "monero-private-l2-fee-rebate-disbursement-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_RISK_CAP_SCHEME: &str =
    "monero-private-l2-token-treasury-risk-cap-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_TIMELOCK_SCHEME: &str =
    "monero-private-l2-token-treasury-timelocked-execution-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PRIVACY_FENCE_SCHEME: &str =
    "monero-private-l2-token-treasury-nullifier-fence-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_EVENT_SCHEME: &str =
    "monero-private-l2-confidential-token-treasury-event-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEVNET_HEIGHT: u64 = 924_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-token-governed-treasury-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_TREASURY_ASSET_ID: &str =
    "asset:private-dusd";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_GOVERNANCE_TOKEN_ID:
    &str = "asset:nebula-governance";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_BUDGETS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_VOTES: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_VESTING_STREAMS:
    usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_INCENTIVES: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_REBATES: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_RISK_CAPS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_TIMELOCKS: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_EVENTS: usize =
    4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize =
    16_384;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 131_072;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_BUDGET_TTL_BLOCKS: u64 =
    4_320;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_VOTE_TTL_BLOCKS: u64 =
    4_320;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_TIMELOCK_DELAY_BLOCKS:
    u64 = 720;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_EXECUTION_TTL_BLOCKS:
    u64 = 1_440;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_STREAM_TTL_BLOCKS: u64 =
    1_051_200;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    16;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 =
    8;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_TREASURY_DRAW_BPS:
    u64 = 1_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_QUORUM_BPS: u64 =
    2_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_APPROVAL_BPS: u64 =
    5_100;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_INCENTIVE_APR_BPS:
    u64 = 2_500;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_REBATE_BPS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetProposalKind {
    ProtocolGrant,
    LiquidityMining,
    FeeRebate,
    RiskReserve,
    InsuranceFund,
    MarketMakerIncentive,
    SecurityAudit,
    EmergencySpend,
    VestingAllocation,
    SmartContractUpgrade,
}

impl BudgetProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolGrant => "protocol_grant",
            Self::LiquidityMining => "liquidity_mining",
            Self::FeeRebate => "fee_rebate",
            Self::RiskReserve => "risk_reserve",
            Self::InsuranceFund => "insurance_fund",
            Self::MarketMakerIncentive => "market_maker_incentive",
            Self::SecurityAudit => "security_audit",
            Self::EmergencySpend => "emergency_spend",
            Self::VestingAllocation => "vesting_allocation",
            Self::SmartContractUpgrade => "smart_contract_upgrade",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Registered,
    Voting,
    Approved,
    Rejected,
    Timelocked,
    Executed,
    Cancelled,
    Expired,
}

impl BudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Voting => "voting",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Timelocked => "timelocked",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_votes(self) -> bool {
        matches!(self, Self::Registered | Self::Voting)
    }
    pub fn executable(self) -> bool {
        matches!(self, Self::Approved | Self::Timelocked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteAttestationStatus {
    Submitted,
    Authorized,
    Tallied,
    Rejected,
    Expired,
}

impl VoteAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Authorized => "authorized",
            Self::Tallied => "tallied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn tallyable(self) -> bool {
        matches!(self, Self::Submitted | Self::Authorized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryVoteChoice {
    For,
    Against,
    Abstain,
    VetoSignal,
}

impl TreasuryVoteChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::For => "for",
            Self::Against => "against",
            Self::Abstain => "abstain",
            Self::VetoSignal => "veto_signal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VestingStreamStatus {
    Scheduled,
    Active,
    PartiallyClaimed,
    Completed,
    Revoked,
    Expired,
}

impl VestingStreamStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::PartiallyClaimed => "partially_claimed",
            Self::Completed => "completed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn claimable(self) -> bool {
        matches!(
            self,
            Self::Scheduled | Self::Active | Self::PartiallyClaimed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncentiveStatus {
    Draft,
    Active,
    Paused,
    Draining,
    Settled,
    Cancelled,
    Expired,
}

impl IncentiveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Sponsored,
    Disbursed,
    Cancelled,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Sponsored => "sponsored",
            Self::Disbursed => "disbursed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCapStatus {
    Proposed,
    Active,
    Breached,
    Relaxed,
    Retired,
}

impl RiskCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Breached => "breached",
            Self::Relaxed => "relaxed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockStatus {
    Queued,
    Ready,
    Executed,
    Cancelled,
    Expired,
}

impl TimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryEventKind {
    BudgetRegistered,
    VoteAttested,
    BudgetTallied,
    TimelockQueued,
    TimelockExecuted,
    VestingStreamOpened,
    VestingClaimed,
    IncentiveOpened,
    IncentiveSettled,
    RebateReserved,
    RebateDisbursed,
    RiskCapRecorded,
    PrivacyFenceConsumed,
}

impl TreasuryEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BudgetRegistered => "budget_registered",
            Self::VoteAttested => "vote_attested",
            Self::BudgetTallied => "budget_tallied",
            Self::TimelockQueued => "timelock_queued",
            Self::TimelockExecuted => "timelock_executed",
            Self::VestingStreamOpened => "vesting_stream_opened",
            Self::VestingClaimed => "vesting_claimed",
            Self::IncentiveOpened => "incentive_opened",
            Self::IncentiveSettled => "incentive_settled",
            Self::RebateReserved => "rebate_reserved",
            Self::RebateDisbursed => "rebate_disbursed",
            Self::RiskCapRecorded => "risk_cap_recorded",
            Self::PrivacyFenceConsumed => "privacy_fence_consumed",
        }
    }
}

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0001: &str =
    "privacy-preserving-token-treasury-invariant-0001";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0002: &str =
    "privacy-preserving-token-treasury-invariant-0002";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0003: &str =
    "privacy-preserving-token-treasury-invariant-0003";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0004: &str =
    "privacy-preserving-token-treasury-invariant-0004";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0005: &str =
    "privacy-preserving-token-treasury-invariant-0005";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0006: &str =
    "privacy-preserving-token-treasury-invariant-0006";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0007: &str =
    "privacy-preserving-token-treasury-invariant-0007";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0008: &str =
    "privacy-preserving-token-treasury-invariant-0008";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0009: &str =
    "privacy-preserving-token-treasury-invariant-0009";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0010: &str =
    "privacy-preserving-token-treasury-invariant-0010";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0011: &str =
    "privacy-preserving-token-treasury-invariant-0011";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0012: &str =
    "privacy-preserving-token-treasury-invariant-0012";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0013: &str =
    "privacy-preserving-token-treasury-invariant-0013";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0014: &str =
    "privacy-preserving-token-treasury-invariant-0014";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0015: &str =
    "privacy-preserving-token-treasury-invariant-0015";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0016: &str =
    "privacy-preserving-token-treasury-invariant-0016";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0017: &str =
    "privacy-preserving-token-treasury-invariant-0017";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0018: &str =
    "privacy-preserving-token-treasury-invariant-0018";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0019: &str =
    "privacy-preserving-token-treasury-invariant-0019";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0020: &str =
    "privacy-preserving-token-treasury-invariant-0020";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0021: &str =
    "privacy-preserving-token-treasury-invariant-0021";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0022: &str =
    "privacy-preserving-token-treasury-invariant-0022";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0023: &str =
    "privacy-preserving-token-treasury-invariant-0023";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0024: &str =
    "privacy-preserving-token-treasury-invariant-0024";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0025: &str =
    "privacy-preserving-token-treasury-invariant-0025";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0026: &str =
    "privacy-preserving-token-treasury-invariant-0026";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0027: &str =
    "privacy-preserving-token-treasury-invariant-0027";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0028: &str =
    "privacy-preserving-token-treasury-invariant-0028";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0029: &str =
    "privacy-preserving-token-treasury-invariant-0029";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0030: &str =
    "privacy-preserving-token-treasury-invariant-0030";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0031: &str =
    "privacy-preserving-token-treasury-invariant-0031";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0032: &str =
    "privacy-preserving-token-treasury-invariant-0032";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0033: &str =
    "privacy-preserving-token-treasury-invariant-0033";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0034: &str =
    "privacy-preserving-token-treasury-invariant-0034";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0035: &str =
    "privacy-preserving-token-treasury-invariant-0035";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0036: &str =
    "privacy-preserving-token-treasury-invariant-0036";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0037: &str =
    "privacy-preserving-token-treasury-invariant-0037";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0038: &str =
    "privacy-preserving-token-treasury-invariant-0038";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0039: &str =
    "privacy-preserving-token-treasury-invariant-0039";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0040: &str =
    "privacy-preserving-token-treasury-invariant-0040";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0041: &str =
    "privacy-preserving-token-treasury-invariant-0041";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0042: &str =
    "privacy-preserving-token-treasury-invariant-0042";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0043: &str =
    "privacy-preserving-token-treasury-invariant-0043";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0044: &str =
    "privacy-preserving-token-treasury-invariant-0044";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0045: &str =
    "privacy-preserving-token-treasury-invariant-0045";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0046: &str =
    "privacy-preserving-token-treasury-invariant-0046";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0047: &str =
    "privacy-preserving-token-treasury-invariant-0047";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0048: &str =
    "privacy-preserving-token-treasury-invariant-0048";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0049: &str =
    "privacy-preserving-token-treasury-invariant-0049";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0050: &str =
    "privacy-preserving-token-treasury-invariant-0050";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0051: &str =
    "privacy-preserving-token-treasury-invariant-0051";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0052: &str =
    "privacy-preserving-token-treasury-invariant-0052";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0053: &str =
    "privacy-preserving-token-treasury-invariant-0053";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0054: &str =
    "privacy-preserving-token-treasury-invariant-0054";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0055: &str =
    "privacy-preserving-token-treasury-invariant-0055";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0056: &str =
    "privacy-preserving-token-treasury-invariant-0056";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0057: &str =
    "privacy-preserving-token-treasury-invariant-0057";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0058: &str =
    "privacy-preserving-token-treasury-invariant-0058";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0059: &str =
    "privacy-preserving-token-treasury-invariant-0059";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0060: &str =
    "privacy-preserving-token-treasury-invariant-0060";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0061: &str =
    "privacy-preserving-token-treasury-invariant-0061";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0062: &str =
    "privacy-preserving-token-treasury-invariant-0062";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0063: &str =
    "privacy-preserving-token-treasury-invariant-0063";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0064: &str =
    "privacy-preserving-token-treasury-invariant-0064";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0065: &str =
    "privacy-preserving-token-treasury-invariant-0065";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0066: &str =
    "privacy-preserving-token-treasury-invariant-0066";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0067: &str =
    "privacy-preserving-token-treasury-invariant-0067";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0068: &str =
    "privacy-preserving-token-treasury-invariant-0068";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0069: &str =
    "privacy-preserving-token-treasury-invariant-0069";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0070: &str =
    "privacy-preserving-token-treasury-invariant-0070";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0071: &str =
    "privacy-preserving-token-treasury-invariant-0071";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0072: &str =
    "privacy-preserving-token-treasury-invariant-0072";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0073: &str =
    "privacy-preserving-token-treasury-invariant-0073";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0074: &str =
    "privacy-preserving-token-treasury-invariant-0074";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0075: &str =
    "privacy-preserving-token-treasury-invariant-0075";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0076: &str =
    "privacy-preserving-token-treasury-invariant-0076";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0077: &str =
    "privacy-preserving-token-treasury-invariant-0077";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0078: &str =
    "privacy-preserving-token-treasury-invariant-0078";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0079: &str =
    "privacy-preserving-token-treasury-invariant-0079";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0080: &str =
    "privacy-preserving-token-treasury-invariant-0080";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0081: &str =
    "privacy-preserving-token-treasury-invariant-0081";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0082: &str =
    "privacy-preserving-token-treasury-invariant-0082";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0083: &str =
    "privacy-preserving-token-treasury-invariant-0083";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0084: &str =
    "privacy-preserving-token-treasury-invariant-0084";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0085: &str =
    "privacy-preserving-token-treasury-invariant-0085";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0086: &str =
    "privacy-preserving-token-treasury-invariant-0086";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0087: &str =
    "privacy-preserving-token-treasury-invariant-0087";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0088: &str =
    "privacy-preserving-token-treasury-invariant-0088";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0089: &str =
    "privacy-preserving-token-treasury-invariant-0089";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0090: &str =
    "privacy-preserving-token-treasury-invariant-0090";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0091: &str =
    "privacy-preserving-token-treasury-invariant-0091";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0092: &str =
    "privacy-preserving-token-treasury-invariant-0092";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0093: &str =
    "privacy-preserving-token-treasury-invariant-0093";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0094: &str =
    "privacy-preserving-token-treasury-invariant-0094";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0095: &str =
    "privacy-preserving-token-treasury-invariant-0095";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0096: &str =
    "privacy-preserving-token-treasury-invariant-0096";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0097: &str =
    "privacy-preserving-token-treasury-invariant-0097";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0098: &str =
    "privacy-preserving-token-treasury-invariant-0098";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0099: &str =
    "privacy-preserving-token-treasury-invariant-0099";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0100: &str =
    "privacy-preserving-token-treasury-invariant-0100";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0101: &str =
    "privacy-preserving-token-treasury-invariant-0101";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0102: &str =
    "privacy-preserving-token-treasury-invariant-0102";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0103: &str =
    "privacy-preserving-token-treasury-invariant-0103";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0104: &str =
    "privacy-preserving-token-treasury-invariant-0104";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0105: &str =
    "privacy-preserving-token-treasury-invariant-0105";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0106: &str =
    "privacy-preserving-token-treasury-invariant-0106";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0107: &str =
    "privacy-preserving-token-treasury-invariant-0107";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0108: &str =
    "privacy-preserving-token-treasury-invariant-0108";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0109: &str =
    "privacy-preserving-token-treasury-invariant-0109";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0110: &str =
    "privacy-preserving-token-treasury-invariant-0110";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0111: &str =
    "privacy-preserving-token-treasury-invariant-0111";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0112: &str =
    "privacy-preserving-token-treasury-invariant-0112";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0113: &str =
    "privacy-preserving-token-treasury-invariant-0113";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0114: &str =
    "privacy-preserving-token-treasury-invariant-0114";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0115: &str =
    "privacy-preserving-token-treasury-invariant-0115";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0116: &str =
    "privacy-preserving-token-treasury-invariant-0116";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0117: &str =
    "privacy-preserving-token-treasury-invariant-0117";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0118: &str =
    "privacy-preserving-token-treasury-invariant-0118";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0119: &str =
    "privacy-preserving-token-treasury-invariant-0119";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0120: &str =
    "privacy-preserving-token-treasury-invariant-0120";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0121: &str =
    "privacy-preserving-token-treasury-invariant-0121";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0122: &str =
    "privacy-preserving-token-treasury-invariant-0122";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0123: &str =
    "privacy-preserving-token-treasury-invariant-0123";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0124: &str =
    "privacy-preserving-token-treasury-invariant-0124";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0125: &str =
    "privacy-preserving-token-treasury-invariant-0125";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0126: &str =
    "privacy-preserving-token-treasury-invariant-0126";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0127: &str =
    "privacy-preserving-token-treasury-invariant-0127";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0128: &str =
    "privacy-preserving-token-treasury-invariant-0128";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0129: &str =
    "privacy-preserving-token-treasury-invariant-0129";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0130: &str =
    "privacy-preserving-token-treasury-invariant-0130";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0131: &str =
    "privacy-preserving-token-treasury-invariant-0131";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0132: &str =
    "privacy-preserving-token-treasury-invariant-0132";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0133: &str =
    "privacy-preserving-token-treasury-invariant-0133";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0134: &str =
    "privacy-preserving-token-treasury-invariant-0134";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0135: &str =
    "privacy-preserving-token-treasury-invariant-0135";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0136: &str =
    "privacy-preserving-token-treasury-invariant-0136";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0137: &str =
    "privacy-preserving-token-treasury-invariant-0137";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0138: &str =
    "privacy-preserving-token-treasury-invariant-0138";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0139: &str =
    "privacy-preserving-token-treasury-invariant-0139";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0140: &str =
    "privacy-preserving-token-treasury-invariant-0140";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0141: &str =
    "privacy-preserving-token-treasury-invariant-0141";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0142: &str =
    "privacy-preserving-token-treasury-invariant-0142";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0143: &str =
    "privacy-preserving-token-treasury-invariant-0143";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0144: &str =
    "privacy-preserving-token-treasury-invariant-0144";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0145: &str =
    "privacy-preserving-token-treasury-invariant-0145";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0146: &str =
    "privacy-preserving-token-treasury-invariant-0146";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0147: &str =
    "privacy-preserving-token-treasury-invariant-0147";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0148: &str =
    "privacy-preserving-token-treasury-invariant-0148";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0149: &str =
    "privacy-preserving-token-treasury-invariant-0149";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0150: &str =
    "privacy-preserving-token-treasury-invariant-0150";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0151: &str =
    "privacy-preserving-token-treasury-invariant-0151";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0152: &str =
    "privacy-preserving-token-treasury-invariant-0152";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0153: &str =
    "privacy-preserving-token-treasury-invariant-0153";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0154: &str =
    "privacy-preserving-token-treasury-invariant-0154";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0155: &str =
    "privacy-preserving-token-treasury-invariant-0155";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0156: &str =
    "privacy-preserving-token-treasury-invariant-0156";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0157: &str =
    "privacy-preserving-token-treasury-invariant-0157";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0158: &str =
    "privacy-preserving-token-treasury-invariant-0158";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0159: &str =
    "privacy-preserving-token-treasury-invariant-0159";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0160: &str =
    "privacy-preserving-token-treasury-invariant-0160";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0161: &str =
    "privacy-preserving-token-treasury-invariant-0161";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0162: &str =
    "privacy-preserving-token-treasury-invariant-0162";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0163: &str =
    "privacy-preserving-token-treasury-invariant-0163";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0164: &str =
    "privacy-preserving-token-treasury-invariant-0164";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0165: &str =
    "privacy-preserving-token-treasury-invariant-0165";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0166: &str =
    "privacy-preserving-token-treasury-invariant-0166";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0167: &str =
    "privacy-preserving-token-treasury-invariant-0167";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0168: &str =
    "privacy-preserving-token-treasury-invariant-0168";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0169: &str =
    "privacy-preserving-token-treasury-invariant-0169";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0170: &str =
    "privacy-preserving-token-treasury-invariant-0170";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0171: &str =
    "privacy-preserving-token-treasury-invariant-0171";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0172: &str =
    "privacy-preserving-token-treasury-invariant-0172";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0173: &str =
    "privacy-preserving-token-treasury-invariant-0173";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0174: &str =
    "privacy-preserving-token-treasury-invariant-0174";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0175: &str =
    "privacy-preserving-token-treasury-invariant-0175";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0176: &str =
    "privacy-preserving-token-treasury-invariant-0176";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0177: &str =
    "privacy-preserving-token-treasury-invariant-0177";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0178: &str =
    "privacy-preserving-token-treasury-invariant-0178";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0179: &str =
    "privacy-preserving-token-treasury-invariant-0179";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0180: &str =
    "privacy-preserving-token-treasury-invariant-0180";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0181: &str =
    "privacy-preserving-token-treasury-invariant-0181";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0182: &str =
    "privacy-preserving-token-treasury-invariant-0182";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0183: &str =
    "privacy-preserving-token-treasury-invariant-0183";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0184: &str =
    "privacy-preserving-token-treasury-invariant-0184";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0185: &str =
    "privacy-preserving-token-treasury-invariant-0185";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0186: &str =
    "privacy-preserving-token-treasury-invariant-0186";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0187: &str =
    "privacy-preserving-token-treasury-invariant-0187";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0188: &str =
    "privacy-preserving-token-treasury-invariant-0188";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0189: &str =
    "privacy-preserving-token-treasury-invariant-0189";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0190: &str =
    "privacy-preserving-token-treasury-invariant-0190";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0191: &str =
    "privacy-preserving-token-treasury-invariant-0191";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0192: &str =
    "privacy-preserving-token-treasury-invariant-0192";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0193: &str =
    "privacy-preserving-token-treasury-invariant-0193";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0194: &str =
    "privacy-preserving-token-treasury-invariant-0194";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0195: &str =
    "privacy-preserving-token-treasury-invariant-0195";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0196: &str =
    "privacy-preserving-token-treasury-invariant-0196";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0197: &str =
    "privacy-preserving-token-treasury-invariant-0197";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0198: &str =
    "privacy-preserving-token-treasury-invariant-0198";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0199: &str =
    "privacy-preserving-token-treasury-invariant-0199";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0200: &str =
    "privacy-preserving-token-treasury-invariant-0200";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0201: &str =
    "privacy-preserving-token-treasury-invariant-0201";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0202: &str =
    "privacy-preserving-token-treasury-invariant-0202";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0203: &str =
    "privacy-preserving-token-treasury-invariant-0203";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0204: &str =
    "privacy-preserving-token-treasury-invariant-0204";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0205: &str =
    "privacy-preserving-token-treasury-invariant-0205";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0206: &str =
    "privacy-preserving-token-treasury-invariant-0206";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0207: &str =
    "privacy-preserving-token-treasury-invariant-0207";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0208: &str =
    "privacy-preserving-token-treasury-invariant-0208";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0209: &str =
    "privacy-preserving-token-treasury-invariant-0209";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0210: &str =
    "privacy-preserving-token-treasury-invariant-0210";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0211: &str =
    "privacy-preserving-token-treasury-invariant-0211";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0212: &str =
    "privacy-preserving-token-treasury-invariant-0212";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0213: &str =
    "privacy-preserving-token-treasury-invariant-0213";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0214: &str =
    "privacy-preserving-token-treasury-invariant-0214";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0215: &str =
    "privacy-preserving-token-treasury-invariant-0215";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0216: &str =
    "privacy-preserving-token-treasury-invariant-0216";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0217: &str =
    "privacy-preserving-token-treasury-invariant-0217";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0218: &str =
    "privacy-preserving-token-treasury-invariant-0218";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0219: &str =
    "privacy-preserving-token-treasury-invariant-0219";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0220: &str =
    "privacy-preserving-token-treasury-invariant-0220";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0221: &str =
    "privacy-preserving-token-treasury-invariant-0221";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0222: &str =
    "privacy-preserving-token-treasury-invariant-0222";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0223: &str =
    "privacy-preserving-token-treasury-invariant-0223";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0224: &str =
    "privacy-preserving-token-treasury-invariant-0224";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0225: &str =
    "privacy-preserving-token-treasury-invariant-0225";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0226: &str =
    "privacy-preserving-token-treasury-invariant-0226";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0227: &str =
    "privacy-preserving-token-treasury-invariant-0227";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0228: &str =
    "privacy-preserving-token-treasury-invariant-0228";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0229: &str =
    "privacy-preserving-token-treasury-invariant-0229";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0230: &str =
    "privacy-preserving-token-treasury-invariant-0230";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0231: &str =
    "privacy-preserving-token-treasury-invariant-0231";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0232: &str =
    "privacy-preserving-token-treasury-invariant-0232";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0233: &str =
    "privacy-preserving-token-treasury-invariant-0233";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0234: &str =
    "privacy-preserving-token-treasury-invariant-0234";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0235: &str =
    "privacy-preserving-token-treasury-invariant-0235";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0236: &str =
    "privacy-preserving-token-treasury-invariant-0236";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0237: &str =
    "privacy-preserving-token-treasury-invariant-0237";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0238: &str =
    "privacy-preserving-token-treasury-invariant-0238";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0239: &str =
    "privacy-preserving-token-treasury-invariant-0239";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0240: &str =
    "privacy-preserving-token-treasury-invariant-0240";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0241: &str =
    "privacy-preserving-token-treasury-invariant-0241";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0242: &str =
    "privacy-preserving-token-treasury-invariant-0242";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0243: &str =
    "privacy-preserving-token-treasury-invariant-0243";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0244: &str =
    "privacy-preserving-token-treasury-invariant-0244";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0245: &str =
    "privacy-preserving-token-treasury-invariant-0245";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0246: &str =
    "privacy-preserving-token-treasury-invariant-0246";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0247: &str =
    "privacy-preserving-token-treasury-invariant-0247";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0248: &str =
    "privacy-preserving-token-treasury-invariant-0248";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0249: &str =
    "privacy-preserving-token-treasury-invariant-0249";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0250: &str =
    "privacy-preserving-token-treasury-invariant-0250";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0251: &str =
    "privacy-preserving-token-treasury-invariant-0251";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0252: &str =
    "privacy-preserving-token-treasury-invariant-0252";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0253: &str =
    "privacy-preserving-token-treasury-invariant-0253";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0254: &str =
    "privacy-preserving-token-treasury-invariant-0254";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0255: &str =
    "privacy-preserving-token-treasury-invariant-0255";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0256: &str =
    "privacy-preserving-token-treasury-invariant-0256";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0257: &str =
    "privacy-preserving-token-treasury-invariant-0257";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0258: &str =
    "privacy-preserving-token-treasury-invariant-0258";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0259: &str =
    "privacy-preserving-token-treasury-invariant-0259";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0260: &str =
    "privacy-preserving-token-treasury-invariant-0260";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0261: &str =
    "privacy-preserving-token-treasury-invariant-0261";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0262: &str =
    "privacy-preserving-token-treasury-invariant-0262";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0263: &str =
    "privacy-preserving-token-treasury-invariant-0263";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0264: &str =
    "privacy-preserving-token-treasury-invariant-0264";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0265: &str =
    "privacy-preserving-token-treasury-invariant-0265";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0266: &str =
    "privacy-preserving-token-treasury-invariant-0266";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0267: &str =
    "privacy-preserving-token-treasury-invariant-0267";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0268: &str =
    "privacy-preserving-token-treasury-invariant-0268";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0269: &str =
    "privacy-preserving-token-treasury-invariant-0269";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0270: &str =
    "privacy-preserving-token-treasury-invariant-0270";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0271: &str =
    "privacy-preserving-token-treasury-invariant-0271";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0272: &str =
    "privacy-preserving-token-treasury-invariant-0272";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0273: &str =
    "privacy-preserving-token-treasury-invariant-0273";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0274: &str =
    "privacy-preserving-token-treasury-invariant-0274";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0275: &str =
    "privacy-preserving-token-treasury-invariant-0275";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0276: &str =
    "privacy-preserving-token-treasury-invariant-0276";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0277: &str =
    "privacy-preserving-token-treasury-invariant-0277";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0278: &str =
    "privacy-preserving-token-treasury-invariant-0278";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0279: &str =
    "privacy-preserving-token-treasury-invariant-0279";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0280: &str =
    "privacy-preserving-token-treasury-invariant-0280";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0281: &str =
    "privacy-preserving-token-treasury-invariant-0281";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0282: &str =
    "privacy-preserving-token-treasury-invariant-0282";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0283: &str =
    "privacy-preserving-token-treasury-invariant-0283";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0284: &str =
    "privacy-preserving-token-treasury-invariant-0284";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0285: &str =
    "privacy-preserving-token-treasury-invariant-0285";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0286: &str =
    "privacy-preserving-token-treasury-invariant-0286";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0287: &str =
    "privacy-preserving-token-treasury-invariant-0287";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0288: &str =
    "privacy-preserving-token-treasury-invariant-0288";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0289: &str =
    "privacy-preserving-token-treasury-invariant-0289";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0290: &str =
    "privacy-preserving-token-treasury-invariant-0290";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0291: &str =
    "privacy-preserving-token-treasury-invariant-0291";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0292: &str =
    "privacy-preserving-token-treasury-invariant-0292";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0293: &str =
    "privacy-preserving-token-treasury-invariant-0293";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0294: &str =
    "privacy-preserving-token-treasury-invariant-0294";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0295: &str =
    "privacy-preserving-token-treasury-invariant-0295";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0296: &str =
    "privacy-preserving-token-treasury-invariant-0296";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0297: &str =
    "privacy-preserving-token-treasury-invariant-0297";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0298: &str =
    "privacy-preserving-token-treasury-invariant-0298";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0299: &str =
    "privacy-preserving-token-treasury-invariant-0299";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0300: &str =
    "privacy-preserving-token-treasury-invariant-0300";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0301: &str =
    "privacy-preserving-token-treasury-invariant-0301";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0302: &str =
    "privacy-preserving-token-treasury-invariant-0302";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0303: &str =
    "privacy-preserving-token-treasury-invariant-0303";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0304: &str =
    "privacy-preserving-token-treasury-invariant-0304";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0305: &str =
    "privacy-preserving-token-treasury-invariant-0305";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0306: &str =
    "privacy-preserving-token-treasury-invariant-0306";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0307: &str =
    "privacy-preserving-token-treasury-invariant-0307";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0308: &str =
    "privacy-preserving-token-treasury-invariant-0308";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0309: &str =
    "privacy-preserving-token-treasury-invariant-0309";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0310: &str =
    "privacy-preserving-token-treasury-invariant-0310";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0311: &str =
    "privacy-preserving-token-treasury-invariant-0311";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0312: &str =
    "privacy-preserving-token-treasury-invariant-0312";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0313: &str =
    "privacy-preserving-token-treasury-invariant-0313";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0314: &str =
    "privacy-preserving-token-treasury-invariant-0314";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0315: &str =
    "privacy-preserving-token-treasury-invariant-0315";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0316: &str =
    "privacy-preserving-token-treasury-invariant-0316";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0317: &str =
    "privacy-preserving-token-treasury-invariant-0317";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0318: &str =
    "privacy-preserving-token-treasury-invariant-0318";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0319: &str =
    "privacy-preserving-token-treasury-invariant-0319";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0320: &str =
    "privacy-preserving-token-treasury-invariant-0320";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0321: &str =
    "privacy-preserving-token-treasury-invariant-0321";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0322: &str =
    "privacy-preserving-token-treasury-invariant-0322";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0323: &str =
    "privacy-preserving-token-treasury-invariant-0323";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0324: &str =
    "privacy-preserving-token-treasury-invariant-0324";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0325: &str =
    "privacy-preserving-token-treasury-invariant-0325";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0326: &str =
    "privacy-preserving-token-treasury-invariant-0326";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0327: &str =
    "privacy-preserving-token-treasury-invariant-0327";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0328: &str =
    "privacy-preserving-token-treasury-invariant-0328";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0329: &str =
    "privacy-preserving-token-treasury-invariant-0329";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0330: &str =
    "privacy-preserving-token-treasury-invariant-0330";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0331: &str =
    "privacy-preserving-token-treasury-invariant-0331";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0332: &str =
    "privacy-preserving-token-treasury-invariant-0332";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0333: &str =
    "privacy-preserving-token-treasury-invariant-0333";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0334: &str =
    "privacy-preserving-token-treasury-invariant-0334";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0335: &str =
    "privacy-preserving-token-treasury-invariant-0335";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0336: &str =
    "privacy-preserving-token-treasury-invariant-0336";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0337: &str =
    "privacy-preserving-token-treasury-invariant-0337";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0338: &str =
    "privacy-preserving-token-treasury-invariant-0338";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0339: &str =
    "privacy-preserving-token-treasury-invariant-0339";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0340: &str =
    "privacy-preserving-token-treasury-invariant-0340";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0341: &str =
    "privacy-preserving-token-treasury-invariant-0341";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0342: &str =
    "privacy-preserving-token-treasury-invariant-0342";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0343: &str =
    "privacy-preserving-token-treasury-invariant-0343";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0344: &str =
    "privacy-preserving-token-treasury-invariant-0344";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0345: &str =
    "privacy-preserving-token-treasury-invariant-0345";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0346: &str =
    "privacy-preserving-token-treasury-invariant-0346";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0347: &str =
    "privacy-preserving-token-treasury-invariant-0347";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0348: &str =
    "privacy-preserving-token-treasury-invariant-0348";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0349: &str =
    "privacy-preserving-token-treasury-invariant-0349";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0350: &str =
    "privacy-preserving-token-treasury-invariant-0350";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0351: &str =
    "privacy-preserving-token-treasury-invariant-0351";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0352: &str =
    "privacy-preserving-token-treasury-invariant-0352";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0353: &str =
    "privacy-preserving-token-treasury-invariant-0353";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0354: &str =
    "privacy-preserving-token-treasury-invariant-0354";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0355: &str =
    "privacy-preserving-token-treasury-invariant-0355";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0356: &str =
    "privacy-preserving-token-treasury-invariant-0356";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0357: &str =
    "privacy-preserving-token-treasury-invariant-0357";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0358: &str =
    "privacy-preserving-token-treasury-invariant-0358";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0359: &str =
    "privacy-preserving-token-treasury-invariant-0359";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0360: &str =
    "privacy-preserving-token-treasury-invariant-0360";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0361: &str =
    "privacy-preserving-token-treasury-invariant-0361";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0362: &str =
    "privacy-preserving-token-treasury-invariant-0362";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0363: &str =
    "privacy-preserving-token-treasury-invariant-0363";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0364: &str =
    "privacy-preserving-token-treasury-invariant-0364";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0365: &str =
    "privacy-preserving-token-treasury-invariant-0365";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0366: &str =
    "privacy-preserving-token-treasury-invariant-0366";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0367: &str =
    "privacy-preserving-token-treasury-invariant-0367";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0368: &str =
    "privacy-preserving-token-treasury-invariant-0368";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0369: &str =
    "privacy-preserving-token-treasury-invariant-0369";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0370: &str =
    "privacy-preserving-token-treasury-invariant-0370";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0371: &str =
    "privacy-preserving-token-treasury-invariant-0371";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0372: &str =
    "privacy-preserving-token-treasury-invariant-0372";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0373: &str =
    "privacy-preserving-token-treasury-invariant-0373";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0374: &str =
    "privacy-preserving-token-treasury-invariant-0374";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0375: &str =
    "privacy-preserving-token-treasury-invariant-0375";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0376: &str =
    "privacy-preserving-token-treasury-invariant-0376";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0377: &str =
    "privacy-preserving-token-treasury-invariant-0377";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0378: &str =
    "privacy-preserving-token-treasury-invariant-0378";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0379: &str =
    "privacy-preserving-token-treasury-invariant-0379";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0380: &str =
    "privacy-preserving-token-treasury-invariant-0380";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0381: &str =
    "privacy-preserving-token-treasury-invariant-0381";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0382: &str =
    "privacy-preserving-token-treasury-invariant-0382";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0383: &str =
    "privacy-preserving-token-treasury-invariant-0383";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0384: &str =
    "privacy-preserving-token-treasury-invariant-0384";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0385: &str =
    "privacy-preserving-token-treasury-invariant-0385";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0386: &str =
    "privacy-preserving-token-treasury-invariant-0386";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0387: &str =
    "privacy-preserving-token-treasury-invariant-0387";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0388: &str =
    "privacy-preserving-token-treasury-invariant-0388";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0389: &str =
    "privacy-preserving-token-treasury-invariant-0389";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0390: &str =
    "privacy-preserving-token-treasury-invariant-0390";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0391: &str =
    "privacy-preserving-token-treasury-invariant-0391";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0392: &str =
    "privacy-preserving-token-treasury-invariant-0392";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0393: &str =
    "privacy-preserving-token-treasury-invariant-0393";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0394: &str =
    "privacy-preserving-token-treasury-invariant-0394";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0395: &str =
    "privacy-preserving-token-treasury-invariant-0395";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0396: &str =
    "privacy-preserving-token-treasury-invariant-0396";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0397: &str =
    "privacy-preserving-token-treasury-invariant-0397";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0398: &str =
    "privacy-preserving-token-treasury-invariant-0398";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0399: &str =
    "privacy-preserving-token-treasury-invariant-0399";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0400: &str =
    "privacy-preserving-token-treasury-invariant-0400";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0401: &str =
    "privacy-preserving-token-treasury-invariant-0401";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0402: &str =
    "privacy-preserving-token-treasury-invariant-0402";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0403: &str =
    "privacy-preserving-token-treasury-invariant-0403";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0404: &str =
    "privacy-preserving-token-treasury-invariant-0404";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0405: &str =
    "privacy-preserving-token-treasury-invariant-0405";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0406: &str =
    "privacy-preserving-token-treasury-invariant-0406";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0407: &str =
    "privacy-preserving-token-treasury-invariant-0407";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0408: &str =
    "privacy-preserving-token-treasury-invariant-0408";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0409: &str =
    "privacy-preserving-token-treasury-invariant-0409";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0410: &str =
    "privacy-preserving-token-treasury-invariant-0410";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0411: &str =
    "privacy-preserving-token-treasury-invariant-0411";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0412: &str =
    "privacy-preserving-token-treasury-invariant-0412";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0413: &str =
    "privacy-preserving-token-treasury-invariant-0413";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0414: &str =
    "privacy-preserving-token-treasury-invariant-0414";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0415: &str =
    "privacy-preserving-token-treasury-invariant-0415";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0416: &str =
    "privacy-preserving-token-treasury-invariant-0416";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0417: &str =
    "privacy-preserving-token-treasury-invariant-0417";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0418: &str =
    "privacy-preserving-token-treasury-invariant-0418";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0419: &str =
    "privacy-preserving-token-treasury-invariant-0419";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0420: &str =
    "privacy-preserving-token-treasury-invariant-0420";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0421: &str =
    "privacy-preserving-token-treasury-invariant-0421";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0422: &str =
    "privacy-preserving-token-treasury-invariant-0422";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0423: &str =
    "privacy-preserving-token-treasury-invariant-0423";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0424: &str =
    "privacy-preserving-token-treasury-invariant-0424";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0425: &str =
    "privacy-preserving-token-treasury-invariant-0425";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0426: &str =
    "privacy-preserving-token-treasury-invariant-0426";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0427: &str =
    "privacy-preserving-token-treasury-invariant-0427";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0428: &str =
    "privacy-preserving-token-treasury-invariant-0428";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0429: &str =
    "privacy-preserving-token-treasury-invariant-0429";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0430: &str =
    "privacy-preserving-token-treasury-invariant-0430";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0431: &str =
    "privacy-preserving-token-treasury-invariant-0431";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0432: &str =
    "privacy-preserving-token-treasury-invariant-0432";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0433: &str =
    "privacy-preserving-token-treasury-invariant-0433";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0434: &str =
    "privacy-preserving-token-treasury-invariant-0434";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0435: &str =
    "privacy-preserving-token-treasury-invariant-0435";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0436: &str =
    "privacy-preserving-token-treasury-invariant-0436";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0437: &str =
    "privacy-preserving-token-treasury-invariant-0437";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0438: &str =
    "privacy-preserving-token-treasury-invariant-0438";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0439: &str =
    "privacy-preserving-token-treasury-invariant-0439";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0440: &str =
    "privacy-preserving-token-treasury-invariant-0440";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0441: &str =
    "privacy-preserving-token-treasury-invariant-0441";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0442: &str =
    "privacy-preserving-token-treasury-invariant-0442";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0443: &str =
    "privacy-preserving-token-treasury-invariant-0443";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0444: &str =
    "privacy-preserving-token-treasury-invariant-0444";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0445: &str =
    "privacy-preserving-token-treasury-invariant-0445";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0446: &str =
    "privacy-preserving-token-treasury-invariant-0446";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0447: &str =
    "privacy-preserving-token-treasury-invariant-0447";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0448: &str =
    "privacy-preserving-token-treasury-invariant-0448";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0449: &str =
    "privacy-preserving-token-treasury-invariant-0449";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0450: &str =
    "privacy-preserving-token-treasury-invariant-0450";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0451: &str =
    "privacy-preserving-token-treasury-invariant-0451";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0452: &str =
    "privacy-preserving-token-treasury-invariant-0452";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0453: &str =
    "privacy-preserving-token-treasury-invariant-0453";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0454: &str =
    "privacy-preserving-token-treasury-invariant-0454";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0455: &str =
    "privacy-preserving-token-treasury-invariant-0455";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0456: &str =
    "privacy-preserving-token-treasury-invariant-0456";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0457: &str =
    "privacy-preserving-token-treasury-invariant-0457";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0458: &str =
    "privacy-preserving-token-treasury-invariant-0458";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0459: &str =
    "privacy-preserving-token-treasury-invariant-0459";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0460: &str =
    "privacy-preserving-token-treasury-invariant-0460";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0461: &str =
    "privacy-preserving-token-treasury-invariant-0461";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0462: &str =
    "privacy-preserving-token-treasury-invariant-0462";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0463: &str =
    "privacy-preserving-token-treasury-invariant-0463";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0464: &str =
    "privacy-preserving-token-treasury-invariant-0464";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0465: &str =
    "privacy-preserving-token-treasury-invariant-0465";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0466: &str =
    "privacy-preserving-token-treasury-invariant-0466";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0467: &str =
    "privacy-preserving-token-treasury-invariant-0467";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0468: &str =
    "privacy-preserving-token-treasury-invariant-0468";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0469: &str =
    "privacy-preserving-token-treasury-invariant-0469";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0470: &str =
    "privacy-preserving-token-treasury-invariant-0470";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0471: &str =
    "privacy-preserving-token-treasury-invariant-0471";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0472: &str =
    "privacy-preserving-token-treasury-invariant-0472";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0473: &str =
    "privacy-preserving-token-treasury-invariant-0473";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0474: &str =
    "privacy-preserving-token-treasury-invariant-0474";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0475: &str =
    "privacy-preserving-token-treasury-invariant-0475";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0476: &str =
    "privacy-preserving-token-treasury-invariant-0476";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0477: &str =
    "privacy-preserving-token-treasury-invariant-0477";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0478: &str =
    "privacy-preserving-token-treasury-invariant-0478";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0479: &str =
    "privacy-preserving-token-treasury-invariant-0479";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0480: &str =
    "privacy-preserving-token-treasury-invariant-0480";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0481: &str =
    "privacy-preserving-token-treasury-invariant-0481";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0482: &str =
    "privacy-preserving-token-treasury-invariant-0482";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0483: &str =
    "privacy-preserving-token-treasury-invariant-0483";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0484: &str =
    "privacy-preserving-token-treasury-invariant-0484";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0485: &str =
    "privacy-preserving-token-treasury-invariant-0485";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0486: &str =
    "privacy-preserving-token-treasury-invariant-0486";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0487: &str =
    "privacy-preserving-token-treasury-invariant-0487";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0488: &str =
    "privacy-preserving-token-treasury-invariant-0488";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0489: &str =
    "privacy-preserving-token-treasury-invariant-0489";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0490: &str =
    "privacy-preserving-token-treasury-invariant-0490";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0491: &str =
    "privacy-preserving-token-treasury-invariant-0491";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0492: &str =
    "privacy-preserving-token-treasury-invariant-0492";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0493: &str =
    "privacy-preserving-token-treasury-invariant-0493";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0494: &str =
    "privacy-preserving-token-treasury-invariant-0494";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0495: &str =
    "privacy-preserving-token-treasury-invariant-0495";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0496: &str =
    "privacy-preserving-token-treasury-invariant-0496";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0497: &str =
    "privacy-preserving-token-treasury-invariant-0497";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0498: &str =
    "privacy-preserving-token-treasury-invariant-0498";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0499: &str =
    "privacy-preserving-token-treasury-invariant-0499";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0500: &str =
    "privacy-preserving-token-treasury-invariant-0500";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0501: &str =
    "privacy-preserving-token-treasury-invariant-0501";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0502: &str =
    "privacy-preserving-token-treasury-invariant-0502";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0503: &str =
    "privacy-preserving-token-treasury-invariant-0503";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0504: &str =
    "privacy-preserving-token-treasury-invariant-0504";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0505: &str =
    "privacy-preserving-token-treasury-invariant-0505";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0506: &str =
    "privacy-preserving-token-treasury-invariant-0506";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0507: &str =
    "privacy-preserving-token-treasury-invariant-0507";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0508: &str =
    "privacy-preserving-token-treasury-invariant-0508";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0509: &str =
    "privacy-preserving-token-treasury-invariant-0509";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0510: &str =
    "privacy-preserving-token-treasury-invariant-0510";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0511: &str =
    "privacy-preserving-token-treasury-invariant-0511";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0512: &str =
    "privacy-preserving-token-treasury-invariant-0512";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0513: &str =
    "privacy-preserving-token-treasury-invariant-0513";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0514: &str =
    "privacy-preserving-token-treasury-invariant-0514";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0515: &str =
    "privacy-preserving-token-treasury-invariant-0515";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0516: &str =
    "privacy-preserving-token-treasury-invariant-0516";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0517: &str =
    "privacy-preserving-token-treasury-invariant-0517";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0518: &str =
    "privacy-preserving-token-treasury-invariant-0518";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0519: &str =
    "privacy-preserving-token-treasury-invariant-0519";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0520: &str =
    "privacy-preserving-token-treasury-invariant-0520";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0521: &str =
    "privacy-preserving-token-treasury-invariant-0521";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0522: &str =
    "privacy-preserving-token-treasury-invariant-0522";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0523: &str =
    "privacy-preserving-token-treasury-invariant-0523";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0524: &str =
    "privacy-preserving-token-treasury-invariant-0524";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0525: &str =
    "privacy-preserving-token-treasury-invariant-0525";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0526: &str =
    "privacy-preserving-token-treasury-invariant-0526";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0527: &str =
    "privacy-preserving-token-treasury-invariant-0527";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0528: &str =
    "privacy-preserving-token-treasury-invariant-0528";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0529: &str =
    "privacy-preserving-token-treasury-invariant-0529";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0530: &str =
    "privacy-preserving-token-treasury-invariant-0530";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0531: &str =
    "privacy-preserving-token-treasury-invariant-0531";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0532: &str =
    "privacy-preserving-token-treasury-invariant-0532";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0533: &str =
    "privacy-preserving-token-treasury-invariant-0533";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0534: &str =
    "privacy-preserving-token-treasury-invariant-0534";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0535: &str =
    "privacy-preserving-token-treasury-invariant-0535";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0536: &str =
    "privacy-preserving-token-treasury-invariant-0536";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0537: &str =
    "privacy-preserving-token-treasury-invariant-0537";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0538: &str =
    "privacy-preserving-token-treasury-invariant-0538";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0539: &str =
    "privacy-preserving-token-treasury-invariant-0539";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0540: &str =
    "privacy-preserving-token-treasury-invariant-0540";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0541: &str =
    "privacy-preserving-token-treasury-invariant-0541";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0542: &str =
    "privacy-preserving-token-treasury-invariant-0542";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0543: &str =
    "privacy-preserving-token-treasury-invariant-0543";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0544: &str =
    "privacy-preserving-token-treasury-invariant-0544";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0545: &str =
    "privacy-preserving-token-treasury-invariant-0545";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0546: &str =
    "privacy-preserving-token-treasury-invariant-0546";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0547: &str =
    "privacy-preserving-token-treasury-invariant-0547";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0548: &str =
    "privacy-preserving-token-treasury-invariant-0548";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0549: &str =
    "privacy-preserving-token-treasury-invariant-0549";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0550: &str =
    "privacy-preserving-token-treasury-invariant-0550";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0551: &str =
    "privacy-preserving-token-treasury-invariant-0551";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0552: &str =
    "privacy-preserving-token-treasury-invariant-0552";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0553: &str =
    "privacy-preserving-token-treasury-invariant-0553";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0554: &str =
    "privacy-preserving-token-treasury-invariant-0554";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0555: &str =
    "privacy-preserving-token-treasury-invariant-0555";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0556: &str =
    "privacy-preserving-token-treasury-invariant-0556";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0557: &str =
    "privacy-preserving-token-treasury-invariant-0557";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0558: &str =
    "privacy-preserving-token-treasury-invariant-0558";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0559: &str =
    "privacy-preserving-token-treasury-invariant-0559";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0560: &str =
    "privacy-preserving-token-treasury-invariant-0560";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0561: &str =
    "privacy-preserving-token-treasury-invariant-0561";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0562: &str =
    "privacy-preserving-token-treasury-invariant-0562";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0563: &str =
    "privacy-preserving-token-treasury-invariant-0563";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0564: &str =
    "privacy-preserving-token-treasury-invariant-0564";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0565: &str =
    "privacy-preserving-token-treasury-invariant-0565";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0566: &str =
    "privacy-preserving-token-treasury-invariant-0566";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0567: &str =
    "privacy-preserving-token-treasury-invariant-0567";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0568: &str =
    "privacy-preserving-token-treasury-invariant-0568";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0569: &str =
    "privacy-preserving-token-treasury-invariant-0569";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0570: &str =
    "privacy-preserving-token-treasury-invariant-0570";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0571: &str =
    "privacy-preserving-token-treasury-invariant-0571";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0572: &str =
    "privacy-preserving-token-treasury-invariant-0572";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0573: &str =
    "privacy-preserving-token-treasury-invariant-0573";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0574: &str =
    "privacy-preserving-token-treasury-invariant-0574";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0575: &str =
    "privacy-preserving-token-treasury-invariant-0575";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0576: &str =
    "privacy-preserving-token-treasury-invariant-0576";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0577: &str =
    "privacy-preserving-token-treasury-invariant-0577";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0578: &str =
    "privacy-preserving-token-treasury-invariant-0578";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0579: &str =
    "privacy-preserving-token-treasury-invariant-0579";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0580: &str =
    "privacy-preserving-token-treasury-invariant-0580";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0581: &str =
    "privacy-preserving-token-treasury-invariant-0581";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0582: &str =
    "privacy-preserving-token-treasury-invariant-0582";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0583: &str =
    "privacy-preserving-token-treasury-invariant-0583";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0584: &str =
    "privacy-preserving-token-treasury-invariant-0584";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0585: &str =
    "privacy-preserving-token-treasury-invariant-0585";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0586: &str =
    "privacy-preserving-token-treasury-invariant-0586";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0587: &str =
    "privacy-preserving-token-treasury-invariant-0587";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0588: &str =
    "privacy-preserving-token-treasury-invariant-0588";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0589: &str =
    "privacy-preserving-token-treasury-invariant-0589";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0590: &str =
    "privacy-preserving-token-treasury-invariant-0590";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0591: &str =
    "privacy-preserving-token-treasury-invariant-0591";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0592: &str =
    "privacy-preserving-token-treasury-invariant-0592";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0593: &str =
    "privacy-preserving-token-treasury-invariant-0593";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0594: &str =
    "privacy-preserving-token-treasury-invariant-0594";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0595: &str =
    "privacy-preserving-token-treasury-invariant-0595";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0596: &str =
    "privacy-preserving-token-treasury-invariant-0596";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0597: &str =
    "privacy-preserving-token-treasury-invariant-0597";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0598: &str =
    "privacy-preserving-token-treasury-invariant-0598";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0599: &str =
    "privacy-preserving-token-treasury-invariant-0599";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0600: &str =
    "privacy-preserving-token-treasury-invariant-0600";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0601: &str =
    "privacy-preserving-token-treasury-invariant-0601";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0602: &str =
    "privacy-preserving-token-treasury-invariant-0602";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0603: &str =
    "privacy-preserving-token-treasury-invariant-0603";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0604: &str =
    "privacy-preserving-token-treasury-invariant-0604";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0605: &str =
    "privacy-preserving-token-treasury-invariant-0605";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0606: &str =
    "privacy-preserving-token-treasury-invariant-0606";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0607: &str =
    "privacy-preserving-token-treasury-invariant-0607";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0608: &str =
    "privacy-preserving-token-treasury-invariant-0608";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0609: &str =
    "privacy-preserving-token-treasury-invariant-0609";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0610: &str =
    "privacy-preserving-token-treasury-invariant-0610";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0611: &str =
    "privacy-preserving-token-treasury-invariant-0611";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0612: &str =
    "privacy-preserving-token-treasury-invariant-0612";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0613: &str =
    "privacy-preserving-token-treasury-invariant-0613";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0614: &str =
    "privacy-preserving-token-treasury-invariant-0614";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0615: &str =
    "privacy-preserving-token-treasury-invariant-0615";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0616: &str =
    "privacy-preserving-token-treasury-invariant-0616";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0617: &str =
    "privacy-preserving-token-treasury-invariant-0617";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0618: &str =
    "privacy-preserving-token-treasury-invariant-0618";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0619: &str =
    "privacy-preserving-token-treasury-invariant-0619";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0620: &str =
    "privacy-preserving-token-treasury-invariant-0620";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0621: &str =
    "privacy-preserving-token-treasury-invariant-0621";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0622: &str =
    "privacy-preserving-token-treasury-invariant-0622";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0623: &str =
    "privacy-preserving-token-treasury-invariant-0623";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0624: &str =
    "privacy-preserving-token-treasury-invariant-0624";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0625: &str =
    "privacy-preserving-token-treasury-invariant-0625";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0626: &str =
    "privacy-preserving-token-treasury-invariant-0626";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0627: &str =
    "privacy-preserving-token-treasury-invariant-0627";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0628: &str =
    "privacy-preserving-token-treasury-invariant-0628";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0629: &str =
    "privacy-preserving-token-treasury-invariant-0629";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0630: &str =
    "privacy-preserving-token-treasury-invariant-0630";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0631: &str =
    "privacy-preserving-token-treasury-invariant-0631";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0632: &str =
    "privacy-preserving-token-treasury-invariant-0632";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0633: &str =
    "privacy-preserving-token-treasury-invariant-0633";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0634: &str =
    "privacy-preserving-token-treasury-invariant-0634";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0635: &str =
    "privacy-preserving-token-treasury-invariant-0635";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0636: &str =
    "privacy-preserving-token-treasury-invariant-0636";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0637: &str =
    "privacy-preserving-token-treasury-invariant-0637";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0638: &str =
    "privacy-preserving-token-treasury-invariant-0638";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0639: &str =
    "privacy-preserving-token-treasury-invariant-0639";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0640: &str =
    "privacy-preserving-token-treasury-invariant-0640";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0641: &str =
    "privacy-preserving-token-treasury-invariant-0641";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0642: &str =
    "privacy-preserving-token-treasury-invariant-0642";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0643: &str =
    "privacy-preserving-token-treasury-invariant-0643";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0644: &str =
    "privacy-preserving-token-treasury-invariant-0644";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0645: &str =
    "privacy-preserving-token-treasury-invariant-0645";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0646: &str =
    "privacy-preserving-token-treasury-invariant-0646";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0647: &str =
    "privacy-preserving-token-treasury-invariant-0647";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0648: &str =
    "privacy-preserving-token-treasury-invariant-0648";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0649: &str =
    "privacy-preserving-token-treasury-invariant-0649";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0650: &str =
    "privacy-preserving-token-treasury-invariant-0650";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0651: &str =
    "privacy-preserving-token-treasury-invariant-0651";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0652: &str =
    "privacy-preserving-token-treasury-invariant-0652";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0653: &str =
    "privacy-preserving-token-treasury-invariant-0653";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0654: &str =
    "privacy-preserving-token-treasury-invariant-0654";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0655: &str =
    "privacy-preserving-token-treasury-invariant-0655";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0656: &str =
    "privacy-preserving-token-treasury-invariant-0656";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0657: &str =
    "privacy-preserving-token-treasury-invariant-0657";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0658: &str =
    "privacy-preserving-token-treasury-invariant-0658";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0659: &str =
    "privacy-preserving-token-treasury-invariant-0659";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0660: &str =
    "privacy-preserving-token-treasury-invariant-0660";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0661: &str =
    "privacy-preserving-token-treasury-invariant-0661";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0662: &str =
    "privacy-preserving-token-treasury-invariant-0662";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0663: &str =
    "privacy-preserving-token-treasury-invariant-0663";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0664: &str =
    "privacy-preserving-token-treasury-invariant-0664";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0665: &str =
    "privacy-preserving-token-treasury-invariant-0665";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0666: &str =
    "privacy-preserving-token-treasury-invariant-0666";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0667: &str =
    "privacy-preserving-token-treasury-invariant-0667";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0668: &str =
    "privacy-preserving-token-treasury-invariant-0668";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0669: &str =
    "privacy-preserving-token-treasury-invariant-0669";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0670: &str =
    "privacy-preserving-token-treasury-invariant-0670";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0671: &str =
    "privacy-preserving-token-treasury-invariant-0671";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0672: &str =
    "privacy-preserving-token-treasury-invariant-0672";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0673: &str =
    "privacy-preserving-token-treasury-invariant-0673";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0674: &str =
    "privacy-preserving-token-treasury-invariant-0674";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0675: &str =
    "privacy-preserving-token-treasury-invariant-0675";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0676: &str =
    "privacy-preserving-token-treasury-invariant-0676";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0677: &str =
    "privacy-preserving-token-treasury-invariant-0677";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0678: &str =
    "privacy-preserving-token-treasury-invariant-0678";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0679: &str =
    "privacy-preserving-token-treasury-invariant-0679";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0680: &str =
    "privacy-preserving-token-treasury-invariant-0680";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0681: &str =
    "privacy-preserving-token-treasury-invariant-0681";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0682: &str =
    "privacy-preserving-token-treasury-invariant-0682";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0683: &str =
    "privacy-preserving-token-treasury-invariant-0683";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0684: &str =
    "privacy-preserving-token-treasury-invariant-0684";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0685: &str =
    "privacy-preserving-token-treasury-invariant-0685";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0686: &str =
    "privacy-preserving-token-treasury-invariant-0686";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0687: &str =
    "privacy-preserving-token-treasury-invariant-0687";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0688: &str =
    "privacy-preserving-token-treasury-invariant-0688";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0689: &str =
    "privacy-preserving-token-treasury-invariant-0689";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0690: &str =
    "privacy-preserving-token-treasury-invariant-0690";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0691: &str =
    "privacy-preserving-token-treasury-invariant-0691";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0692: &str =
    "privacy-preserving-token-treasury-invariant-0692";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0693: &str =
    "privacy-preserving-token-treasury-invariant-0693";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0694: &str =
    "privacy-preserving-token-treasury-invariant-0694";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0695: &str =
    "privacy-preserving-token-treasury-invariant-0695";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0696: &str =
    "privacy-preserving-token-treasury-invariant-0696";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0697: &str =
    "privacy-preserving-token-treasury-invariant-0697";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0698: &str =
    "privacy-preserving-token-treasury-invariant-0698";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0699: &str =
    "privacy-preserving-token-treasury-invariant-0699";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0700: &str =
    "privacy-preserving-token-treasury-invariant-0700";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0701: &str =
    "privacy-preserving-token-treasury-invariant-0701";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0702: &str =
    "privacy-preserving-token-treasury-invariant-0702";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0703: &str =
    "privacy-preserving-token-treasury-invariant-0703";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0704: &str =
    "privacy-preserving-token-treasury-invariant-0704";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0705: &str =
    "privacy-preserving-token-treasury-invariant-0705";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0706: &str =
    "privacy-preserving-token-treasury-invariant-0706";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0707: &str =
    "privacy-preserving-token-treasury-invariant-0707";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0708: &str =
    "privacy-preserving-token-treasury-invariant-0708";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0709: &str =
    "privacy-preserving-token-treasury-invariant-0709";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0710: &str =
    "privacy-preserving-token-treasury-invariant-0710";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0711: &str =
    "privacy-preserving-token-treasury-invariant-0711";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0712: &str =
    "privacy-preserving-token-treasury-invariant-0712";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0713: &str =
    "privacy-preserving-token-treasury-invariant-0713";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0714: &str =
    "privacy-preserving-token-treasury-invariant-0714";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0715: &str =
    "privacy-preserving-token-treasury-invariant-0715";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0716: &str =
    "privacy-preserving-token-treasury-invariant-0716";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0717: &str =
    "privacy-preserving-token-treasury-invariant-0717";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0718: &str =
    "privacy-preserving-token-treasury-invariant-0718";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0719: &str =
    "privacy-preserving-token-treasury-invariant-0719";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0720: &str =
    "privacy-preserving-token-treasury-invariant-0720";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0721: &str =
    "privacy-preserving-token-treasury-invariant-0721";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0722: &str =
    "privacy-preserving-token-treasury-invariant-0722";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0723: &str =
    "privacy-preserving-token-treasury-invariant-0723";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0724: &str =
    "privacy-preserving-token-treasury-invariant-0724";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0725: &str =
    "privacy-preserving-token-treasury-invariant-0725";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0726: &str =
    "privacy-preserving-token-treasury-invariant-0726";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0727: &str =
    "privacy-preserving-token-treasury-invariant-0727";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0728: &str =
    "privacy-preserving-token-treasury-invariant-0728";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0729: &str =
    "privacy-preserving-token-treasury-invariant-0729";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0730: &str =
    "privacy-preserving-token-treasury-invariant-0730";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0731: &str =
    "privacy-preserving-token-treasury-invariant-0731";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0732: &str =
    "privacy-preserving-token-treasury-invariant-0732";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0733: &str =
    "privacy-preserving-token-treasury-invariant-0733";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0734: &str =
    "privacy-preserving-token-treasury-invariant-0734";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0735: &str =
    "privacy-preserving-token-treasury-invariant-0735";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0736: &str =
    "privacy-preserving-token-treasury-invariant-0736";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0737: &str =
    "privacy-preserving-token-treasury-invariant-0737";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0738: &str =
    "privacy-preserving-token-treasury-invariant-0738";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0739: &str =
    "privacy-preserving-token-treasury-invariant-0739";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0740: &str =
    "privacy-preserving-token-treasury-invariant-0740";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0741: &str =
    "privacy-preserving-token-treasury-invariant-0741";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0742: &str =
    "privacy-preserving-token-treasury-invariant-0742";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0743: &str =
    "privacy-preserving-token-treasury-invariant-0743";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0744: &str =
    "privacy-preserving-token-treasury-invariant-0744";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0745: &str =
    "privacy-preserving-token-treasury-invariant-0745";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0746: &str =
    "privacy-preserving-token-treasury-invariant-0746";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0747: &str =
    "privacy-preserving-token-treasury-invariant-0747";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0748: &str =
    "privacy-preserving-token-treasury-invariant-0748";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0749: &str =
    "privacy-preserving-token-treasury-invariant-0749";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0750: &str =
    "privacy-preserving-token-treasury-invariant-0750";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0751: &str =
    "privacy-preserving-token-treasury-invariant-0751";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0752: &str =
    "privacy-preserving-token-treasury-invariant-0752";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0753: &str =
    "privacy-preserving-token-treasury-invariant-0753";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0754: &str =
    "privacy-preserving-token-treasury-invariant-0754";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0755: &str =
    "privacy-preserving-token-treasury-invariant-0755";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0756: &str =
    "privacy-preserving-token-treasury-invariant-0756";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0757: &str =
    "privacy-preserving-token-treasury-invariant-0757";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0758: &str =
    "privacy-preserving-token-treasury-invariant-0758";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0759: &str =
    "privacy-preserving-token-treasury-invariant-0759";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0760: &str =
    "privacy-preserving-token-treasury-invariant-0760";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0761: &str =
    "privacy-preserving-token-treasury-invariant-0761";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0762: &str =
    "privacy-preserving-token-treasury-invariant-0762";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0763: &str =
    "privacy-preserving-token-treasury-invariant-0763";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0764: &str =
    "privacy-preserving-token-treasury-invariant-0764";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0765: &str =
    "privacy-preserving-token-treasury-invariant-0765";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0766: &str =
    "privacy-preserving-token-treasury-invariant-0766";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0767: &str =
    "privacy-preserving-token-treasury-invariant-0767";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0768: &str =
    "privacy-preserving-token-treasury-invariant-0768";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0769: &str =
    "privacy-preserving-token-treasury-invariant-0769";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0770: &str =
    "privacy-preserving-token-treasury-invariant-0770";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0771: &str =
    "privacy-preserving-token-treasury-invariant-0771";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0772: &str =
    "privacy-preserving-token-treasury-invariant-0772";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0773: &str =
    "privacy-preserving-token-treasury-invariant-0773";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0774: &str =
    "privacy-preserving-token-treasury-invariant-0774";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0775: &str =
    "privacy-preserving-token-treasury-invariant-0775";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0776: &str =
    "privacy-preserving-token-treasury-invariant-0776";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0777: &str =
    "privacy-preserving-token-treasury-invariant-0777";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0778: &str =
    "privacy-preserving-token-treasury-invariant-0778";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0779: &str =
    "privacy-preserving-token-treasury-invariant-0779";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0780: &str =
    "privacy-preserving-token-treasury-invariant-0780";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0781: &str =
    "privacy-preserving-token-treasury-invariant-0781";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0782: &str =
    "privacy-preserving-token-treasury-invariant-0782";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0783: &str =
    "privacy-preserving-token-treasury-invariant-0783";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0784: &str =
    "privacy-preserving-token-treasury-invariant-0784";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0785: &str =
    "privacy-preserving-token-treasury-invariant-0785";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0786: &str =
    "privacy-preserving-token-treasury-invariant-0786";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0787: &str =
    "privacy-preserving-token-treasury-invariant-0787";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0788: &str =
    "privacy-preserving-token-treasury-invariant-0788";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0789: &str =
    "privacy-preserving-token-treasury-invariant-0789";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0790: &str =
    "privacy-preserving-token-treasury-invariant-0790";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0791: &str =
    "privacy-preserving-token-treasury-invariant-0791";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0792: &str =
    "privacy-preserving-token-treasury-invariant-0792";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0793: &str =
    "privacy-preserving-token-treasury-invariant-0793";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0794: &str =
    "privacy-preserving-token-treasury-invariant-0794";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0795: &str =
    "privacy-preserving-token-treasury-invariant-0795";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0796: &str =
    "privacy-preserving-token-treasury-invariant-0796";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0797: &str =
    "privacy-preserving-token-treasury-invariant-0797";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0798: &str =
    "privacy-preserving-token-treasury-invariant-0798";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0799: &str =
    "privacy-preserving-token-treasury-invariant-0799";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0800: &str =
    "privacy-preserving-token-treasury-invariant-0800";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0801: &str =
    "privacy-preserving-token-treasury-invariant-0801";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0802: &str =
    "privacy-preserving-token-treasury-invariant-0802";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0803: &str =
    "privacy-preserving-token-treasury-invariant-0803";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0804: &str =
    "privacy-preserving-token-treasury-invariant-0804";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0805: &str =
    "privacy-preserving-token-treasury-invariant-0805";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0806: &str =
    "privacy-preserving-token-treasury-invariant-0806";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0807: &str =
    "privacy-preserving-token-treasury-invariant-0807";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0808: &str =
    "privacy-preserving-token-treasury-invariant-0808";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0809: &str =
    "privacy-preserving-token-treasury-invariant-0809";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0810: &str =
    "privacy-preserving-token-treasury-invariant-0810";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0811: &str =
    "privacy-preserving-token-treasury-invariant-0811";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0812: &str =
    "privacy-preserving-token-treasury-invariant-0812";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0813: &str =
    "privacy-preserving-token-treasury-invariant-0813";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0814: &str =
    "privacy-preserving-token-treasury-invariant-0814";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0815: &str =
    "privacy-preserving-token-treasury-invariant-0815";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0816: &str =
    "privacy-preserving-token-treasury-invariant-0816";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0817: &str =
    "privacy-preserving-token-treasury-invariant-0817";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0818: &str =
    "privacy-preserving-token-treasury-invariant-0818";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0819: &str =
    "privacy-preserving-token-treasury-invariant-0819";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0820: &str =
    "privacy-preserving-token-treasury-invariant-0820";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0821: &str =
    "privacy-preserving-token-treasury-invariant-0821";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0822: &str =
    "privacy-preserving-token-treasury-invariant-0822";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0823: &str =
    "privacy-preserving-token-treasury-invariant-0823";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0824: &str =
    "privacy-preserving-token-treasury-invariant-0824";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0825: &str =
    "privacy-preserving-token-treasury-invariant-0825";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0826: &str =
    "privacy-preserving-token-treasury-invariant-0826";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0827: &str =
    "privacy-preserving-token-treasury-invariant-0827";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0828: &str =
    "privacy-preserving-token-treasury-invariant-0828";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0829: &str =
    "privacy-preserving-token-treasury-invariant-0829";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0830: &str =
    "privacy-preserving-token-treasury-invariant-0830";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0831: &str =
    "privacy-preserving-token-treasury-invariant-0831";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0832: &str =
    "privacy-preserving-token-treasury-invariant-0832";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0833: &str =
    "privacy-preserving-token-treasury-invariant-0833";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0834: &str =
    "privacy-preserving-token-treasury-invariant-0834";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0835: &str =
    "privacy-preserving-token-treasury-invariant-0835";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0836: &str =
    "privacy-preserving-token-treasury-invariant-0836";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0837: &str =
    "privacy-preserving-token-treasury-invariant-0837";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0838: &str =
    "privacy-preserving-token-treasury-invariant-0838";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0839: &str =
    "privacy-preserving-token-treasury-invariant-0839";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0840: &str =
    "privacy-preserving-token-treasury-invariant-0840";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0841: &str =
    "privacy-preserving-token-treasury-invariant-0841";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0842: &str =
    "privacy-preserving-token-treasury-invariant-0842";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0843: &str =
    "privacy-preserving-token-treasury-invariant-0843";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0844: &str =
    "privacy-preserving-token-treasury-invariant-0844";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0845: &str =
    "privacy-preserving-token-treasury-invariant-0845";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0846: &str =
    "privacy-preserving-token-treasury-invariant-0846";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0847: &str =
    "privacy-preserving-token-treasury-invariant-0847";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0848: &str =
    "privacy-preserving-token-treasury-invariant-0848";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0849: &str =
    "privacy-preserving-token-treasury-invariant-0849";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0850: &str =
    "privacy-preserving-token-treasury-invariant-0850";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0851: &str =
    "privacy-preserving-token-treasury-invariant-0851";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0852: &str =
    "privacy-preserving-token-treasury-invariant-0852";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0853: &str =
    "privacy-preserving-token-treasury-invariant-0853";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0854: &str =
    "privacy-preserving-token-treasury-invariant-0854";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0855: &str =
    "privacy-preserving-token-treasury-invariant-0855";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0856: &str =
    "privacy-preserving-token-treasury-invariant-0856";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0857: &str =
    "privacy-preserving-token-treasury-invariant-0857";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0858: &str =
    "privacy-preserving-token-treasury-invariant-0858";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0859: &str =
    "privacy-preserving-token-treasury-invariant-0859";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0860: &str =
    "privacy-preserving-token-treasury-invariant-0860";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0861: &str =
    "privacy-preserving-token-treasury-invariant-0861";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0862: &str =
    "privacy-preserving-token-treasury-invariant-0862";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0863: &str =
    "privacy-preserving-token-treasury-invariant-0863";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0864: &str =
    "privacy-preserving-token-treasury-invariant-0864";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0865: &str =
    "privacy-preserving-token-treasury-invariant-0865";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0866: &str =
    "privacy-preserving-token-treasury-invariant-0866";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0867: &str =
    "privacy-preserving-token-treasury-invariant-0867";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0868: &str =
    "privacy-preserving-token-treasury-invariant-0868";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0869: &str =
    "privacy-preserving-token-treasury-invariant-0869";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0870: &str =
    "privacy-preserving-token-treasury-invariant-0870";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0871: &str =
    "privacy-preserving-token-treasury-invariant-0871";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0872: &str =
    "privacy-preserving-token-treasury-invariant-0872";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0873: &str =
    "privacy-preserving-token-treasury-invariant-0873";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0874: &str =
    "privacy-preserving-token-treasury-invariant-0874";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0875: &str =
    "privacy-preserving-token-treasury-invariant-0875";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0876: &str =
    "privacy-preserving-token-treasury-invariant-0876";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0877: &str =
    "privacy-preserving-token-treasury-invariant-0877";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0878: &str =
    "privacy-preserving-token-treasury-invariant-0878";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0879: &str =
    "privacy-preserving-token-treasury-invariant-0879";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0880: &str =
    "privacy-preserving-token-treasury-invariant-0880";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0881: &str =
    "privacy-preserving-token-treasury-invariant-0881";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0882: &str =
    "privacy-preserving-token-treasury-invariant-0882";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0883: &str =
    "privacy-preserving-token-treasury-invariant-0883";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0884: &str =
    "privacy-preserving-token-treasury-invariant-0884";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0885: &str =
    "privacy-preserving-token-treasury-invariant-0885";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0886: &str =
    "privacy-preserving-token-treasury-invariant-0886";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0887: &str =
    "privacy-preserving-token-treasury-invariant-0887";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0888: &str =
    "privacy-preserving-token-treasury-invariant-0888";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0889: &str =
    "privacy-preserving-token-treasury-invariant-0889";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0890: &str =
    "privacy-preserving-token-treasury-invariant-0890";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0891: &str =
    "privacy-preserving-token-treasury-invariant-0891";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0892: &str =
    "privacy-preserving-token-treasury-invariant-0892";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0893: &str =
    "privacy-preserving-token-treasury-invariant-0893";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0894: &str =
    "privacy-preserving-token-treasury-invariant-0894";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0895: &str =
    "privacy-preserving-token-treasury-invariant-0895";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0896: &str =
    "privacy-preserving-token-treasury-invariant-0896";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0897: &str =
    "privacy-preserving-token-treasury-invariant-0897";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0898: &str =
    "privacy-preserving-token-treasury-invariant-0898";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0899: &str =
    "privacy-preserving-token-treasury-invariant-0899";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0900: &str =
    "privacy-preserving-token-treasury-invariant-0900";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0901: &str =
    "privacy-preserving-token-treasury-invariant-0901";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0902: &str =
    "privacy-preserving-token-treasury-invariant-0902";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0903: &str =
    "privacy-preserving-token-treasury-invariant-0903";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0904: &str =
    "privacy-preserving-token-treasury-invariant-0904";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0905: &str =
    "privacy-preserving-token-treasury-invariant-0905";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0906: &str =
    "privacy-preserving-token-treasury-invariant-0906";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0907: &str =
    "privacy-preserving-token-treasury-invariant-0907";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0908: &str =
    "privacy-preserving-token-treasury-invariant-0908";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0909: &str =
    "privacy-preserving-token-treasury-invariant-0909";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0910: &str =
    "privacy-preserving-token-treasury-invariant-0910";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0911: &str =
    "privacy-preserving-token-treasury-invariant-0911";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0912: &str =
    "privacy-preserving-token-treasury-invariant-0912";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0913: &str =
    "privacy-preserving-token-treasury-invariant-0913";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0914: &str =
    "privacy-preserving-token-treasury-invariant-0914";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0915: &str =
    "privacy-preserving-token-treasury-invariant-0915";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0916: &str =
    "privacy-preserving-token-treasury-invariant-0916";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0917: &str =
    "privacy-preserving-token-treasury-invariant-0917";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0918: &str =
    "privacy-preserving-token-treasury-invariant-0918";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0919: &str =
    "privacy-preserving-token-treasury-invariant-0919";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0920: &str =
    "privacy-preserving-token-treasury-invariant-0920";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0921: &str =
    "privacy-preserving-token-treasury-invariant-0921";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0922: &str =
    "privacy-preserving-token-treasury-invariant-0922";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0923: &str =
    "privacy-preserving-token-treasury-invariant-0923";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0924: &str =
    "privacy-preserving-token-treasury-invariant-0924";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0925: &str =
    "privacy-preserving-token-treasury-invariant-0925";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0926: &str =
    "privacy-preserving-token-treasury-invariant-0926";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0927: &str =
    "privacy-preserving-token-treasury-invariant-0927";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0928: &str =
    "privacy-preserving-token-treasury-invariant-0928";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0929: &str =
    "privacy-preserving-token-treasury-invariant-0929";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0930: &str =
    "privacy-preserving-token-treasury-invariant-0930";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0931: &str =
    "privacy-preserving-token-treasury-invariant-0931";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0932: &str =
    "privacy-preserving-token-treasury-invariant-0932";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0933: &str =
    "privacy-preserving-token-treasury-invariant-0933";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0934: &str =
    "privacy-preserving-token-treasury-invariant-0934";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0935: &str =
    "privacy-preserving-token-treasury-invariant-0935";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0936: &str =
    "privacy-preserving-token-treasury-invariant-0936";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0937: &str =
    "privacy-preserving-token-treasury-invariant-0937";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0938: &str =
    "privacy-preserving-token-treasury-invariant-0938";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0939: &str =
    "privacy-preserving-token-treasury-invariant-0939";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0940: &str =
    "privacy-preserving-token-treasury-invariant-0940";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0941: &str =
    "privacy-preserving-token-treasury-invariant-0941";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0942: &str =
    "privacy-preserving-token-treasury-invariant-0942";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0943: &str =
    "privacy-preserving-token-treasury-invariant-0943";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0944: &str =
    "privacy-preserving-token-treasury-invariant-0944";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0945: &str =
    "privacy-preserving-token-treasury-invariant-0945";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0946: &str =
    "privacy-preserving-token-treasury-invariant-0946";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0947: &str =
    "privacy-preserving-token-treasury-invariant-0947";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0948: &str =
    "privacy-preserving-token-treasury-invariant-0948";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0949: &str =
    "privacy-preserving-token-treasury-invariant-0949";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0950: &str =
    "privacy-preserving-token-treasury-invariant-0950";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0951: &str =
    "privacy-preserving-token-treasury-invariant-0951";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0952: &str =
    "privacy-preserving-token-treasury-invariant-0952";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0953: &str =
    "privacy-preserving-token-treasury-invariant-0953";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0954: &str =
    "privacy-preserving-token-treasury-invariant-0954";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0955: &str =
    "privacy-preserving-token-treasury-invariant-0955";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0956: &str =
    "privacy-preserving-token-treasury-invariant-0956";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0957: &str =
    "privacy-preserving-token-treasury-invariant-0957";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0958: &str =
    "privacy-preserving-token-treasury-invariant-0958";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0959: &str =
    "privacy-preserving-token-treasury-invariant-0959";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0960: &str =
    "privacy-preserving-token-treasury-invariant-0960";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0961: &str =
    "privacy-preserving-token-treasury-invariant-0961";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0962: &str =
    "privacy-preserving-token-treasury-invariant-0962";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0963: &str =
    "privacy-preserving-token-treasury-invariant-0963";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0964: &str =
    "privacy-preserving-token-treasury-invariant-0964";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0965: &str =
    "privacy-preserving-token-treasury-invariant-0965";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0966: &str =
    "privacy-preserving-token-treasury-invariant-0966";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0967: &str =
    "privacy-preserving-token-treasury-invariant-0967";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0968: &str =
    "privacy-preserving-token-treasury-invariant-0968";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0969: &str =
    "privacy-preserving-token-treasury-invariant-0969";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0970: &str =
    "privacy-preserving-token-treasury-invariant-0970";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0971: &str =
    "privacy-preserving-token-treasury-invariant-0971";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0972: &str =
    "privacy-preserving-token-treasury-invariant-0972";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0973: &str =
    "privacy-preserving-token-treasury-invariant-0973";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0974: &str =
    "privacy-preserving-token-treasury-invariant-0974";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0975: &str =
    "privacy-preserving-token-treasury-invariant-0975";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0976: &str =
    "privacy-preserving-token-treasury-invariant-0976";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0977: &str =
    "privacy-preserving-token-treasury-invariant-0977";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0978: &str =
    "privacy-preserving-token-treasury-invariant-0978";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0979: &str =
    "privacy-preserving-token-treasury-invariant-0979";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0980: &str =
    "privacy-preserving-token-treasury-invariant-0980";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0981: &str =
    "privacy-preserving-token-treasury-invariant-0981";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0982: &str =
    "privacy-preserving-token-treasury-invariant-0982";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0983: &str =
    "privacy-preserving-token-treasury-invariant-0983";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0984: &str =
    "privacy-preserving-token-treasury-invariant-0984";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0985: &str =
    "privacy-preserving-token-treasury-invariant-0985";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0986: &str =
    "privacy-preserving-token-treasury-invariant-0986";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0987: &str =
    "privacy-preserving-token-treasury-invariant-0987";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0988: &str =
    "privacy-preserving-token-treasury-invariant-0988";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0989: &str =
    "privacy-preserving-token-treasury-invariant-0989";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0990: &str =
    "privacy-preserving-token-treasury-invariant-0990";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0991: &str =
    "privacy-preserving-token-treasury-invariant-0991";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0992: &str =
    "privacy-preserving-token-treasury-invariant-0992";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0993: &str =
    "privacy-preserving-token-treasury-invariant-0993";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0994: &str =
    "privacy-preserving-token-treasury-invariant-0994";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0995: &str =
    "privacy-preserving-token-treasury-invariant-0995";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0996: &str =
    "privacy-preserving-token-treasury-invariant-0996";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0997: &str =
    "privacy-preserving-token-treasury-invariant-0997";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0998: &str =
    "privacy-preserving-token-treasury-invariant-0998";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_0999: &str =
    "privacy-preserving-token-treasury-invariant-0999";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1000: &str =
    "privacy-preserving-token-treasury-invariant-1000";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1001: &str =
    "privacy-preserving-token-treasury-invariant-1001";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1002: &str =
    "privacy-preserving-token-treasury-invariant-1002";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1003: &str =
    "privacy-preserving-token-treasury-invariant-1003";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1004: &str =
    "privacy-preserving-token-treasury-invariant-1004";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1005: &str =
    "privacy-preserving-token-treasury-invariant-1005";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1006: &str =
    "privacy-preserving-token-treasury-invariant-1006";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1007: &str =
    "privacy-preserving-token-treasury-invariant-1007";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1008: &str =
    "privacy-preserving-token-treasury-invariant-1008";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1009: &str =
    "privacy-preserving-token-treasury-invariant-1009";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1010: &str =
    "privacy-preserving-token-treasury-invariant-1010";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1011: &str =
    "privacy-preserving-token-treasury-invariant-1011";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1012: &str =
    "privacy-preserving-token-treasury-invariant-1012";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1013: &str =
    "privacy-preserving-token-treasury-invariant-1013";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1014: &str =
    "privacy-preserving-token-treasury-invariant-1014";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INVARIANT_1015: &str =
    "privacy-preserving-token-treasury-invariant-1015";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub low_fee_lane: String,
    pub treasury_asset_id: String,
    pub governance_token_id: String,
    pub fee_asset_id: String,
    pub max_budgets: usize,
    pub max_vote_attestations: usize,
    pub max_vesting_streams: usize,
    pub max_liquidity_incentives: usize,
    pub max_fee_rebates: usize,
    pub max_risk_caps: usize,
    pub max_timelocks: usize,
    pub max_events: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub budget_ttl_blocks: u64,
    pub vote_ttl_blocks: u64,
    pub timelock_delay_blocks: u64,
    pub execution_ttl_blocks: u64,
    pub stream_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub max_treasury_draw_bps: u64,
    pub min_quorum_bps: u64,
    pub min_approval_bps: u64,
    pub max_incentive_apr_bps: u64,
    pub max_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
        chain_id: CHAIN_ID.to_string(), monero_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(),
        l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_L2_NETWORK.to_string(), low_fee_lane: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(),
        treasury_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_TREASURY_ASSET_ID.to_string(), governance_token_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_GOVERNANCE_TOKEN_ID.to_string(), fee_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_FEE_ASSET_ID.to_string(),
        max_budgets: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_BUDGETS, max_vote_attestations: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_VOTES, max_vesting_streams: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_VESTING_STREAMS,
        max_liquidity_incentives: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_INCENTIVES, max_fee_rebates: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_REBATES, max_risk_caps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_RISK_CAPS,
        max_timelocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_TIMELOCKS, max_events: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_EVENTS, max_batch_items: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
        min_privacy_set_size: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE, batch_privacy_set_size: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, min_pq_security_bits: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
        budget_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_BUDGET_TTL_BLOCKS, vote_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_VOTE_TTL_BLOCKS, timelock_delay_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_TIMELOCK_DELAY_BLOCKS,
        execution_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_EXECUTION_TTL_BLOCKS, stream_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_STREAM_TTL_BLOCKS, max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
        max_sponsor_fee_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS, max_treasury_draw_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_TREASURY_DRAW_BPS, min_quorum_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_QUORUM_BPS,
        min_approval_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MIN_APPROVAL_BPS, max_incentive_apr_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_INCENTIVE_APR_BPS, max_rebate_bps: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEFAULT_MAX_REBATE_BPS,
    }
    }
    pub fn validate(&self) -> Result<()> {
        require(
            self.chain_id == CHAIN_ID,
            "config chain_id must match CHAIN_ID",
        )?;
        for (field, value) in [
            ("monero_network", &self.monero_network),
            ("l2_network", &self.l2_network),
            ("low_fee_lane", &self.low_fee_lane),
            ("treasury_asset_id", &self.treasury_asset_id),
            ("governance_token_id", &self.governance_token_id),
            ("fee_asset_id", &self.fee_asset_id),
        ] {
            validate_required(field, value)?;
        }
        require(self.max_budgets > 0, "max budgets must be positive")?;
        require(
            self.max_vote_attestations > 0,
            "max vote attestations must be positive",
        )?;
        require(self.max_batch_items > 0, "max batch items must be positive")?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        require(
            self.min_pq_security_bits >= 128,
            "min pq security bits too low",
        )?;
        require(
            self.budget_ttl_blocks > 0 && self.vote_ttl_blocks > 0,
            "budget and vote ttls must be positive",
        )?;
        require(
            self.timelock_delay_blocks > 0 && self.execution_ttl_blocks > 0,
            "timelock and execution ttl must be positive",
        )?;
        for (label, value) in [
            ("max user fee", self.max_user_fee_bps),
            ("max sponsor fee", self.max_sponsor_fee_bps),
            ("max treasury draw", self.max_treasury_draw_bps),
            ("min quorum", self.min_quorum_bps),
            ("min approval", self.min_approval_bps),
            ("max incentive apr", self.max_incentive_apr_bps),
            ("max rebate", self.max_rebate_bps),
        ] {
            require_bps(value, label)?;
        }
        require(
            self.max_sponsor_fee_bps <= self.max_user_fee_bps,
            "sponsor fee cap must not exceed user fee cap",
        )
    }
    pub fn public_record(&self) -> Value {
        json!({"kind":"private_l2_confidential_token_governed_treasury_config","chain_id":self.chain_id,"monero_network":self.monero_network,"l2_network":self.l2_network,"low_fee_lane":self.low_fee_lane,"treasury_asset_id":self.treasury_asset_id,"governance_token_id":self.governance_token_id,"fee_asset_id":self.fee_asset_id,"max_budgets":self.max_budgets,"max_vote_attestations":self.max_vote_attestations,"max_vesting_streams":self.max_vesting_streams,"max_liquidity_incentives":self.max_liquidity_incentives,"max_fee_rebates":self.max_fee_rebates,"max_risk_caps":self.max_risk_caps,"max_timelocks":self.max_timelocks,"max_events":self.max_events,"max_batch_items":self.max_batch_items,"min_privacy_set_size":self.min_privacy_set_size,"batch_privacy_set_size":self.batch_privacy_set_size,"min_pq_security_bits":self.min_pq_security_bits,"budget_ttl_blocks":self.budget_ttl_blocks,"vote_ttl_blocks":self.vote_ttl_blocks,"timelock_delay_blocks":self.timelock_delay_blocks,"execution_ttl_blocks":self.execution_ttl_blocks,"stream_ttl_blocks":self.stream_ttl_blocks,"max_user_fee_bps":self.max_user_fee_bps,"max_sponsor_fee_bps":self.max_sponsor_fee_bps,"max_treasury_draw_bps":self.max_treasury_draw_bps,"min_quorum_bps":self.min_quorum_bps,"min_approval_bps":self.min_approval_bps,"max_incentive_apr_bps":self.max_incentive_apr_bps,"max_rebate_bps":self.max_rebate_bps})
    }
    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub budgets_registered: u64,
    pub vote_attestations_submitted: u64,
    pub budgets_tallied: u64,
    pub timelocks_queued: u64,
    pub timelocks_executed: u64,
    pub vesting_streams_opened: u64,
    pub vesting_claims_settled: u64,
    pub liquidity_incentives_opened: u64,
    pub liquidity_incentives_settled: u64,
    pub fee_rebates_reserved: u64,
    pub fee_rebates_disbursed: u64,
    pub risk_caps_recorded: u64,
    pub nullifiers_consumed: u64,
    pub events_emitted: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({"kind":"private_l2_confidential_token_governed_treasury_counters","budgets_registered":self.budgets_registered,"vote_attestations_submitted":self.vote_attestations_submitted,"budgets_tallied":self.budgets_tallied,"timelocks_queued":self.timelocks_queued,"timelocks_executed":self.timelocks_executed,"vesting_streams_opened":self.vesting_streams_opened,"vesting_claims_settled":self.vesting_claims_settled,"liquidity_incentives_opened":self.liquidity_incentives_opened,"liquidity_incentives_settled":self.liquidity_incentives_settled,"fee_rebates_reserved":self.fee_rebates_reserved,"fee_rebates_disbursed":self.fee_rebates_disbursed,"risk_caps_recorded":self.risk_caps_recorded,"nullifiers_consumed":self.nullifiers_consumed,"events_emitted":self.events_emitted})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterBudgetProposalRequest {
    pub proposal_kind: BudgetProposalKind,
    pub proposer_commitment: String,
    pub encrypted_budget_root: String,
    pub encrypted_metadata_root: String,
    pub recipient_set_root: String,
    pub spend_policy_root: String,
    pub treasury_asset_id: String,
    pub amount_commitment_root: String,
    pub draw_limit_bps: u64,
    pub risk_cap_root: String,
    pub vote_policy_root: String,
    pub quorum_commitment_root: String,
    pub timelock_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_fence_root: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub vote_start_height: u64,
    pub vote_end_height: u64,
    pub expires_at_height: u64,
}

impl RegisterBudgetProposalRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "register_budget_proposal_request",
            "proposal_kind": self.proposal_kind,
            "proposer_commitment": self.proposer_commitment,
            "encrypted_budget_root": self.encrypted_budget_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "recipient_set_root": self.recipient_set_root,
            "spend_policy_root": self.spend_policy_root,
            "treasury_asset_id": self.treasury_asset_id,
            "amount_commitment_root": self.amount_commitment_root,
            "draw_limit_bps": self.draw_limit_bps,
            "risk_cap_root": self.risk_cap_root,
            "vote_policy_root": self.vote_policy_root,
            "quorum_commitment_root": self.quorum_commitment_root,
            "timelock_policy_root": self.timelock_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_fence_root": self.privacy_fence_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
            "vote_start_height": self.vote_start_height,
            "vote_end_height": self.vote_end_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitVoteAttestationRequest {
    pub budget_id: String,
    pub voter_commitment: String,
    pub encrypted_choice_root: String,
    pub vote_choice_commitment_root: String,
    pub vote_weight_commitment_root: String,
    pub eligibility_witness_root: String,
    pub governance_token_lock_root: String,
    pub pq_signature_root: String,
    pub pq_kem_ciphertext_root: String,
    pub attestation_nullifier_root: String,
    pub privacy_proof_root: String,
    pub fee_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub choice_hint: TreasuryVoteChoice,
}

impl SubmitVoteAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "submit_vote_attestation_request",
            "budget_id": self.budget_id,
            "voter_commitment": self.voter_commitment,
            "encrypted_choice_root": self.encrypted_choice_root,
            "vote_choice_commitment_root": self.vote_choice_commitment_root,
            "vote_weight_commitment_root": self.vote_weight_commitment_root,
            "eligibility_witness_root": self.eligibility_witness_root,
            "governance_token_lock_root": self.governance_token_lock_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_kem_ciphertext_root": self.pq_kem_ciphertext_root,
            "attestation_nullifier_root": self.attestation_nullifier_root,
            "privacy_proof_root": self.privacy_proof_root,
            "fee_commitment_root": self.fee_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "choice_hint": self.choice_hint,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyBudgetRequest {
    pub budget_id: String,
    pub operator_commitment: String,
    pub vote_attestation_ids: Vec<String>,
    pub aggregate_vote_root: String,
    pub aggregate_nullifier_root: String,
    pub encrypted_tally_root: String,
    pub quorum_commitment_root: String,
    pub approval_commitment_root: String,
    pub veto_commitment_root: String,
    pub tally_proof_root: String,
    pub pq_certificate_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub tallied_at_height: u64,
}

impl TallyBudgetRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "tally_budget_request",
            "budget_id": self.budget_id,
            "operator_commitment": self.operator_commitment,
            "vote_attestation_ids": self.vote_attestation_ids,
            "aggregate_vote_root": self.aggregate_vote_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "encrypted_tally_root": self.encrypted_tally_root,
            "quorum_commitment_root": self.quorum_commitment_root,
            "approval_commitment_root": self.approval_commitment_root,
            "veto_commitment_root": self.veto_commitment_root,
            "tally_proof_root": self.tally_proof_root,
            "pq_certificate_root": self.pq_certificate_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "tallied_at_height": self.tallied_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueTimelockRequest {
    pub budget_id: String,
    pub executor_commitment: String,
    pub action_root: String,
    pub pre_state_root: String,
    pub spending_intent_root: String,
    pub execution_policy_root: String,
    pub timelock_nullifier_root: String,
    pub pq_execution_root: String,
    pub queued_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
}

impl QueueTimelockRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "queue_timelock_request",
            "budget_id": self.budget_id,
            "executor_commitment": self.executor_commitment,
            "action_root": self.action_root,
            "pre_state_root": self.pre_state_root,
            "spending_intent_root": self.spending_intent_root,
            "execution_policy_root": self.execution_policy_root,
            "timelock_nullifier_root": self.timelock_nullifier_root,
            "pq_execution_root": self.pq_execution_root,
            "queued_at_height": self.queued_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteTimelockRequest {
    pub timelock_id: String,
    pub budget_id: String,
    pub executor_commitment: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub execution_receipt_root: String,
    pub settlement_proof_root: String,
    pub fee_receipt_root: String,
    pub execution_nullifier_root: String,
    pub pq_receipt_root: String,
    pub settled_fee_bps: u64,
    pub executed_at_height: u64,
}

impl ExecuteTimelockRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execute_timelock_request",
            "timelock_id": self.timelock_id,
            "budget_id": self.budget_id,
            "executor_commitment": self.executor_commitment,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "execution_receipt_root": self.execution_receipt_root,
            "settlement_proof_root": self.settlement_proof_root,
            "fee_receipt_root": self.fee_receipt_root,
            "execution_nullifier_root": self.execution_nullifier_root,
            "pq_receipt_root": self.pq_receipt_root,
            "settled_fee_bps": self.settled_fee_bps,
            "executed_at_height": self.executed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVestingStreamRequest {
    pub budget_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub total_amount_commitment_root: String,
    pub schedule_root: String,
    pub cliff_height: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub claim_policy_root: String,
    pub revocation_policy_root: String,
    pub stream_nullifier_root: String,
    pub privacy_proof_root: String,
    pub pq_beneficiary_root: String,
    pub opened_at_height: u64,
}

impl OpenVestingStreamRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "open_vesting_stream_request",
            "budget_id": self.budget_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "total_amount_commitment_root": self.total_amount_commitment_root,
            "schedule_root": self.schedule_root,
            "cliff_height": self.cliff_height,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "claim_policy_root": self.claim_policy_root,
            "revocation_policy_root": self.revocation_policy_root,
            "stream_nullifier_root": self.stream_nullifier_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_beneficiary_root": self.pq_beneficiary_root,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleVestingClaimRequest {
    pub stream_id: String,
    pub claimant_commitment: String,
    pub claim_amount_commitment_root: String,
    pub claim_window_root: String,
    pub claim_nullifier_root: String,
    pub privacy_proof_root: String,
    pub pq_claim_root: String,
    pub fee_receipt_root: String,
    pub claimed_at_height: u64,
}

impl SettleVestingClaimRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settle_vesting_claim_request",
            "stream_id": self.stream_id,
            "claimant_commitment": self.claimant_commitment,
            "claim_amount_commitment_root": self.claim_amount_commitment_root,
            "claim_window_root": self.claim_window_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_claim_root": self.pq_claim_root,
            "fee_receipt_root": self.fee_receipt_root,
            "claimed_at_height": self.claimed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenLiquidityIncentiveRequest {
    pub budget_id: String,
    pub pool_commitment: String,
    pub reward_asset_id: String,
    pub reward_budget_commitment_root: String,
    pub emission_curve_root: String,
    pub liquidity_position_root: String,
    pub oracle_policy_root: String,
    pub max_apr_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub incentive_nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl OpenLiquidityIncentiveRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "open_liquidity_incentive_request",
            "budget_id": self.budget_id,
            "pool_commitment": self.pool_commitment,
            "reward_asset_id": self.reward_asset_id,
            "reward_budget_commitment_root": self.reward_budget_commitment_root,
            "emission_curve_root": self.emission_curve_root,
            "liquidity_position_root": self.liquidity_position_root,
            "oracle_policy_root": self.oracle_policy_root,
            "max_apr_bps": self.max_apr_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "incentive_nullifier_root": self.incentive_nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveFeeRebateRequest {
    pub budget_id: String,
    pub recipient_commitment: String,
    pub fee_asset_id: String,
    pub rebate_amount_commitment_root: String,
    pub eligible_volume_root: String,
    pub rebate_policy_root: String,
    pub rebate_bps: u64,
    pub rebate_nullifier_root: String,
    pub privacy_proof_root: String,
    pub pq_recipient_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveFeeRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_fee_rebate_request",
            "budget_id": self.budget_id,
            "recipient_commitment": self.recipient_commitment,
            "fee_asset_id": self.fee_asset_id,
            "rebate_amount_commitment_root": self.rebate_amount_commitment_root,
            "eligible_volume_root": self.eligible_volume_root,
            "rebate_policy_root": self.rebate_policy_root,
            "rebate_bps": self.rebate_bps,
            "rebate_nullifier_root": self.rebate_nullifier_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_recipient_root": self.pq_recipient_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRiskCapRequest {
    pub budget_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub cap_commitment_root: String,
    pub exposure_oracle_root: String,
    pub liquidation_policy_root: String,
    pub circuit_breaker_root: String,
    pub cap_nullifier_root: String,
    pub privacy_proof_root: String,
    pub pq_risk_committee_root: String,
    pub recorded_at_height: u64,
    pub expires_at_height: u64,
}

impl RecordRiskCapRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "record_risk_cap_request",
            "budget_id": self.budget_id,
            "market_id": self.market_id,
            "asset_id": self.asset_id,
            "cap_commitment_root": self.cap_commitment_root,
            "exposure_oracle_root": self.exposure_oracle_root,
            "liquidation_policy_root": self.liquidation_policy_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "cap_nullifier_root": self.cap_nullifier_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_risk_committee_root": self.pq_risk_committee_root,
            "recorded_at_height": self.recorded_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetProposalRecord {
    pub budget_id: String,
    pub request: RegisterBudgetProposalRequest,
    pub status: BudgetStatus,
    pub tally_root: Option<String>,
    pub timelock_id: Option<String>,
    pub execution_id: Option<String>,
}
impl BudgetProposalRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"budget_proposal_record","budget_id":self.budget_id,"request":self.request.public_record(),"status":self.status.as_str(),"tally_root":self.tally_root,"timelock_id":self.timelock_id,"execution_id":self.execution_id})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteAttestationRecord {
    pub attestation_id: String,
    pub request: SubmitVoteAttestationRequest,
    pub status: VoteAttestationStatus,
}
impl VoteAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"vote_attestation_record","attestation_id":self.attestation_id,"request":self.request.public_record(),"status":self.status.as_str()})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockRecord {
    pub timelock_id: String,
    pub request: QueueTimelockRequest,
    pub status: TimelockStatus,
    pub execution_receipt_root: Option<String>,
}
impl TimelockRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"timelock_record","timelock_id":self.timelock_id,"request":self.request.public_record(),"status":self.status.as_str(),"execution_receipt_root":self.execution_receipt_root})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingStreamRecord {
    pub stream_id: String,
    pub request: OpenVestingStreamRequest,
    pub status: VestingStreamStatus,
    pub claimed_commitment_root: String,
}
impl VestingStreamRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"vesting_stream_record","stream_id":self.stream_id,"request":self.request.public_record(),"status":self.status.as_str(),"claimed_commitment_root":self.claimed_commitment_root})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityIncentiveRecord {
    pub incentive_id: String,
    pub request: OpenLiquidityIncentiveRequest,
    pub status: IncentiveStatus,
    pub settled_reward_root: Option<String>,
}
impl LiquidityIncentiveRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"liquidity_incentive_record","incentive_id":self.incentive_id,"request":self.request.public_record(),"status":self.status.as_str(),"settled_reward_root":self.settled_reward_root})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub request: ReserveFeeRebateRequest,
    pub status: RebateStatus,
    pub disbursement_root: Option<String>,
}
impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"fee_rebate_record","rebate_id":self.rebate_id,"request":self.request.public_record(),"status":self.status.as_str(),"disbursement_root":self.disbursement_root})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskCapRecord {
    pub risk_cap_id: String,
    pub request: RecordRiskCapRequest,
    pub status: RiskCapStatus,
}
impl RiskCapRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"risk_cap_record","risk_cap_id":self.risk_cap_id,"request":self.request.public_record(),"status":self.status.as_str()})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryEventRecord {
    pub event_id: String,
    pub event_kind: TreasuryEventKind,
    pub subject_id: String,
    pub event_root: String,
    pub emitted_at_height: u64,
}
impl TreasuryEventRecord {
    pub fn public_record(&self) -> Value {
        json!({"kind":"treasury_event_record","event_id":self.event_id,"event_kind":self.event_kind.as_str(),"subject_id":self.subject_id,"event_root":self.event_root,"emitted_at_height":self.emitted_at_height})
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub budget_root: String,
    pub vote_attestation_root: String,
    pub vesting_stream_root: String,
    pub liquidity_incentive_root: String,
    pub fee_rebate_root: String,
    pub risk_cap_root: String,
    pub timelock_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub public_record_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({"config_root":self.config_root,"budget_root":self.budget_root,"vote_attestation_root":self.vote_attestation_root,"vesting_stream_root":self.vesting_stream_root,"liquidity_incentive_root":self.liquidity_incentive_root,"fee_rebate_root":self.fee_rebate_root,"risk_cap_root":self.risk_cap_root,"timelock_root":self.timelock_root,"nullifier_root":self.nullifier_root,"event_root":self.event_root,"public_record_root":self.public_record_root})
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub budgets: BTreeMap<String, BudgetProposalRecord>,
    pub vote_attestations: BTreeMap<String, VoteAttestationRecord>,
    pub vesting_streams: BTreeMap<String, VestingStreamRecord>,
    pub liquidity_incentives: BTreeMap<String, LiquidityIncentiveRecord>,
    pub fee_rebates: BTreeMap<String, FeeRebateRecord>,
    pub risk_caps: BTreeMap<String, RiskCapRecord>,
    pub timelocks: BTreeMap<String, TimelockRecord>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub events: Vec<TreasuryEventRecord>,
    pub public_records: Vec<Value>,
}
pub type PrivateL2ConfidentialTokenGovernedTreasuryRuntime = State;

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_DEVNET_HEIGHT,
            budgets: BTreeMap::new(),
            vote_attestations: BTreeMap::new(),
            vesting_streams: BTreeMap::new(),
            liquidity_incentives: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            risk_caps: BTreeMap::new(),
            timelocks: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            events: Vec::new(),
            public_records: Vec::new(),
        })
    }
    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet())?;
        state.seed_devnet_records()?;
        Ok(state)
    }
    pub fn register_budget_proposal(
        &mut self,
        request: RegisterBudgetProposalRequest,
    ) -> Result<BudgetProposalRecord> {
        self.config.validate()?;
        require(
            self.budgets.len() < self.config.max_budgets,
            "budget proposal registry is full",
        )?;
        for (field, value) in [
            ("proposer_commitment", &request.proposer_commitment),
            ("encrypted_budget_root", &request.encrypted_budget_root),
            ("recipient_set_root", &request.recipient_set_root),
            ("spend_policy_root", &request.spend_policy_root),
            ("amount_commitment_root", &request.amount_commitment_root),
            ("risk_cap_root", &request.risk_cap_root),
            ("vote_policy_root", &request.vote_policy_root),
            ("pq_authority_root", &request.pq_authority_root),
            ("privacy_fence_root", &request.privacy_fence_root),
        ] {
            validate_required(field, value)?;
        }
        validate_privacy_and_pq(
            request.min_privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require_bps(request.draw_limit_bps, "budget draw limit")?;
        require(
            request.draw_limit_bps <= self.config.max_treasury_draw_bps,
            "budget draw exceeds treasury cap",
        )?;
        require(
            request.vote_start_height >= request.registered_at_height,
            "budget vote start precedes registration",
        )?;
        require(
            request.vote_end_height > request.vote_start_height,
            "budget vote end must follow vote start",
        )?;
        require(
            request.expires_at_height > request.vote_end_height,
            "budget expiry must follow vote end",
        )?;
        require(
            request.expires_at_height
                <= request
                    .registered_at_height
                    .saturating_add(self.config.budget_ttl_blocks),
            "budget expiry exceeds runtime ttl",
        )?;
        self.insert_nullifier_root(&request.privacy_fence_root)?;
        self.counters.budgets_registered = self.counters.budgets_registered.saturating_add(1);
        self.current_height = self.current_height.max(request.registered_at_height);
        let budget_id = budget_proposal_id(&request, self.counters.budgets_registered);
        let record = BudgetProposalRecord {
            budget_id: budget_id.clone(),
            request,
            status: BudgetStatus::Registered,
            tally_root: None,
            timelock_id: None,
            execution_id: None,
        };
        self.public_records.push(record.public_record());
        self.emit_event(
            TreasuryEventKind::BudgetRegistered,
            budget_id.clone(),
            root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-BUDGET-EVENT",
                &record.public_record(),
            ),
            self.current_height,
        )?;
        self.budgets.insert(budget_id, record.clone());
        Ok(record)
    }
    pub fn submit_vote_attestation(
        &mut self,
        request: SubmitVoteAttestationRequest,
    ) -> Result<VoteAttestationRecord> {
        self.config.validate()?;
        require(
            self.vote_attestations.len() < self.config.max_vote_attestations,
            "vote attestation queue is full",
        )?;
        let budget = self
            .budgets
            .get(&request.budget_id)
            .ok_or_else(|| "budget missing for vote attestation".to_string())?;
        require(
            budget.status.accepts_votes(),
            "budget is not accepting vote attestations",
        )?;
        require(
            request.submitted_at_height >= budget.request.vote_start_height
                && request.submitted_at_height <= budget.request.vote_end_height,
            "vote attestation outside budget vote window",
        )?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require_bps(request.max_fee_bps, "vote attestation max fee")?;
        require(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "vote attestation max fee exceeds cap",
        )?;
        require(
            request.expires_at_height
                <= request
                    .submitted_at_height
                    .saturating_add(self.config.vote_ttl_blocks),
            "vote attestation expiry exceeds runtime ttl",
        )?;
        self.insert_nullifier_root(&request.attestation_nullifier_root)?;
        self.counters.vote_attestations_submitted =
            self.counters.vote_attestations_submitted.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let attestation_id =
            vote_attestation_id(&request, self.counters.vote_attestations_submitted);
        let record = VoteAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            status: VoteAttestationStatus::Submitted,
        };
        self.public_records.push(record.public_record());
        self.emit_event(
            TreasuryEventKind::VoteAttested,
            attestation_id.clone(),
            root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-VOTE-EVENT",
                &record.public_record(),
            ),
            self.current_height,
        )?;
        self.vote_attestations
            .insert(attestation_id, record.clone());
        Ok(record)
    }
    pub fn tally_budget(&mut self, request: TallyBudgetRequest) -> Result<BudgetProposalRecord> {
        self.config.validate()?;
        let budget = self
            .budgets
            .get(&request.budget_id)
            .ok_or_else(|| "budget missing for tally".to_string())?;
        require(budget.status.accepts_votes(), "budget not tallyable")?;
        require(
            !request.vote_attestation_ids.is_empty(),
            "tally requires vote attestations",
        )?;
        require(
            request.vote_attestation_ids.len() <= self.config.max_batch_items,
            "tally batch too large",
        )?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            self.config.min_pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require_bps(request.max_fee_bps, "tally max fee")?;
        require(
            request.tallied_at_height >= budget.request.vote_end_height,
            "tally before vote end",
        )?;
        let mut updated = budget.clone();
        for attestation_id in &request.vote_attestation_ids {
            let attestation = self
                .vote_attestations
                .get_mut(attestation_id)
                .ok_or_else(|| format!("vote attestation {attestation_id} missing for tally"))?;
            require(
                attestation.request.budget_id == request.budget_id,
                "vote attestation belongs to a different budget",
            )?;
            require(
                attestation.status.tallyable(),
                "vote attestation is not tallyable",
            )?;
            attestation.status = VoteAttestationStatus::Tallied;
        }
        self.insert_nullifier_root(&request.aggregate_nullifier_root)?;
        self.counters.budgets_tallied = self.counters.budgets_tallied.saturating_add(1);
        self.current_height = self.current_height.max(request.tallied_at_height);
        let tally_root = tally_budget_root(&request, self.counters.budgets_tallied);
        updated.status = BudgetStatus::Approved;
        updated.tally_root = Some(tally_root.clone());
        self.budgets
            .insert(request.budget_id.clone(), updated.clone());
        self.public_records.push(updated.public_record());
        self.emit_event(
            TreasuryEventKind::BudgetTallied,
            request.budget_id,
            tally_root,
            self.current_height,
        )?;
        Ok(updated)
    }
    pub fn queue_timelock(&mut self, request: QueueTimelockRequest) -> Result<TimelockRecord> {
        self.config.validate()?;
        require(
            self.timelocks.len() < self.config.max_timelocks,
            "timelock queue is full",
        )?;
        let budget = self
            .budgets
            .get(&request.budget_id)
            .ok_or_else(|| "budget missing for timelock".to_string())?;
        require(
            budget.status.executable(),
            "budget is not approved for timelock",
        )?;
        require(
            request.executable_at_height
                >= request
                    .queued_at_height
                    .saturating_add(self.config.timelock_delay_blocks),
            "timelock delay below runtime minimum",
        )?;
        require(
            request.expires_at_height > request.executable_at_height,
            "timelock expiry must follow executable height",
        )?;
        self.insert_nullifier_root(&request.timelock_nullifier_root)?;
        self.counters.timelocks_queued = self.counters.timelocks_queued.saturating_add(1);
        self.current_height = self.current_height.max(request.queued_at_height);
        let timelock_id = timelock_id(&request, self.counters.timelocks_queued);
        let record = TimelockRecord {
            timelock_id: timelock_id.clone(),
            request,
            status: TimelockStatus::Queued,
            execution_receipt_root: None,
        };
        if let Some(budget) = self.budgets.get_mut(&record.request.budget_id) {
            budget.status = BudgetStatus::Timelocked;
            budget.timelock_id = Some(timelock_id.clone());
        }
        self.public_records.push(record.public_record());
        self.emit_event(
            TreasuryEventKind::TimelockQueued,
            timelock_id.clone(),
            root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-TIMELOCK-EVENT",
                &record.public_record(),
            ),
            self.current_height,
        )?;
        self.timelocks.insert(timelock_id, record.clone());
        Ok(record)
    }
    pub fn execute_timelock(&mut self, request: ExecuteTimelockRequest) -> Result<TimelockRecord> {
        self.config.validate()?;
        let existing = self
            .timelocks
            .get(&request.timelock_id)
            .ok_or_else(|| "timelock missing for execution".to_string())?;
        require(
            existing.request.budget_id == request.budget_id,
            "timelock budget mismatch",
        )?;
        require(
            matches!(
                existing.status,
                TimelockStatus::Queued | TimelockStatus::Ready
            ),
            "timelock is not executable",
        )?;
        require(
            request.executed_at_height >= existing.request.executable_at_height,
            "timelock executed before ready height",
        )?;
        require(
            request.executed_at_height <= existing.request.expires_at_height,
            "timelock execution expired",
        )?;
        require_bps(request.settled_fee_bps, "execution settled fee")?;
        require(
            request.settled_fee_bps <= self.config.max_user_fee_bps,
            "execution fee exceeds cap",
        )?;
        let mut updated = existing.clone();
        self.insert_nullifier_root(&request.execution_nullifier_root)?;
        self.counters.timelocks_executed = self.counters.timelocks_executed.saturating_add(1);
        self.current_height = self.current_height.max(request.executed_at_height);
        updated.status = TimelockStatus::Executed;
        updated.execution_receipt_root = Some(request.execution_receipt_root.clone());
        if let Some(budget) = self.budgets.get_mut(&request.budget_id) {
            budget.status = BudgetStatus::Executed;
            budget.execution_id = Some(execution_receipt_id(
                &request,
                self.counters.timelocks_executed,
            ));
        }
        self.timelocks
            .insert(request.timelock_id.clone(), updated.clone());
        self.public_records.push(request.public_record());
        self.emit_event(
            TreasuryEventKind::TimelockExecuted,
            request.timelock_id,
            request.execution_receipt_root,
            self.current_height,
        )?;
        Ok(updated)
    }
    pub fn open_vesting_stream(
        &mut self,
        request: OpenVestingStreamRequest,
    ) -> Result<VestingStreamRecord> {
        self.config.validate()?;
        require(
            self.vesting_streams.len() < self.config.max_vesting_streams,
            "vesting stream registry is full",
        )?;
        require(
            self.budgets.contains_key(&request.budget_id),
            "budget missing for vesting stream",
        )?;
        require(
            request.cliff_height >= request.start_height,
            "vesting cliff precedes start",
        )?;
        require(
            request.end_height > request.start_height,
            "vesting end must follow start",
        )?;
        require(
            request.end_height
                <= request
                    .opened_at_height
                    .saturating_add(self.config.stream_ttl_blocks),
            "vesting stream exceeds ttl",
        )?;
        self.insert_nullifier_root(&request.stream_nullifier_root)?;
        self.counters.vesting_streams_opened =
            self.counters.vesting_streams_opened.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let stream_id = vesting_stream_id(&request, self.counters.vesting_streams_opened);
        let record = VestingStreamRecord {
            stream_id: stream_id.clone(),
            request,
            status: VestingStreamStatus::Scheduled,
            claimed_commitment_root: seeded("zero-vesting-claimed-root"),
        };
        self.public_records.push(record.public_record());
        self.emit_event(
            TreasuryEventKind::VestingStreamOpened,
            stream_id.clone(),
            root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-VESTING-EVENT",
                &record.public_record(),
            ),
            self.current_height,
        )?;
        self.vesting_streams.insert(stream_id, record.clone());
        Ok(record)
    }
    pub fn settle_vesting_claim(
        &mut self,
        request: SettleVestingClaimRequest,
    ) -> Result<VestingStreamRecord> {
        self.config.validate()?;
        let existing = self
            .vesting_streams
            .get(&request.stream_id)
            .ok_or_else(|| "vesting stream missing for claim".to_string())?;
        require(
            existing.status.claimable(),
            "vesting stream is not claimable",
        )?;
        require(
            request.claimed_at_height >= existing.request.cliff_height,
            "vesting claim before cliff",
        )?;
        let mut updated = existing.clone();
        self.insert_nullifier_root(&request.claim_nullifier_root)?;
        self.counters.vesting_claims_settled =
            self.counters.vesting_claims_settled.saturating_add(1);
        self.current_height = self.current_height.max(request.claimed_at_height);
        updated.status = if request.claimed_at_height >= updated.request.end_height {
            VestingStreamStatus::Completed
        } else {
            VestingStreamStatus::PartiallyClaimed
        };
        updated.claimed_commitment_root =
            vesting_claim_root(&request, self.counters.vesting_claims_settled);
        self.vesting_streams
            .insert(request.stream_id.clone(), updated.clone());
        self.public_records.push(request.public_record());
        self.emit_event(
            TreasuryEventKind::VestingClaimed,
            request.stream_id,
            updated.claimed_commitment_root.clone(),
            self.current_height,
        )?;
        Ok(updated)
    }
    pub fn open_liquidity_incentive(
        &mut self,
        request: OpenLiquidityIncentiveRequest,
    ) -> Result<LiquidityIncentiveRecord> {
        self.config.validate()?;
        require(
            self.liquidity_incentives.len() < self.config.max_liquidity_incentives,
            "liquidity incentive registry is full",
        )?;
        require(
            self.budgets.contains_key(&request.budget_id),
            "budget missing for incentive",
        )?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require_bps(request.max_apr_bps, "incentive apr")?;
        require(
            request.max_apr_bps <= self.config.max_incentive_apr_bps,
            "incentive apr exceeds cap",
        )?;
        require(
            request.expires_at_height > request.opened_at_height,
            "incentive expiry must follow open height",
        )?;
        self.insert_nullifier_root(&request.incentive_nullifier_root)?;
        self.counters.liquidity_incentives_opened =
            self.counters.liquidity_incentives_opened.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let incentive_id =
            liquidity_incentive_id(&request, self.counters.liquidity_incentives_opened);
        let record = LiquidityIncentiveRecord {
            incentive_id: incentive_id.clone(),
            request,
            status: IncentiveStatus::Active,
            settled_reward_root: None,
        };
        self.public_records.push(record.public_record());
        self.emit_event(
            TreasuryEventKind::IncentiveOpened,
            incentive_id.clone(),
            root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-INCENTIVE-EVENT",
                &record.public_record(),
            ),
            self.current_height,
        )?;
        self.liquidity_incentives
            .insert(incentive_id, record.clone());
        Ok(record)
    }
    pub fn reserve_fee_rebate(
        &mut self,
        request: ReserveFeeRebateRequest,
    ) -> Result<FeeRebateRecord> {
        self.config.validate()?;
        require(
            self.fee_rebates.len() < self.config.max_fee_rebates,
            "fee rebate registry is full",
        )?;
        require(
            self.budgets.contains_key(&request.budget_id),
            "budget missing for fee rebate",
        )?;
        require_bps(request.rebate_bps, "rebate")?;
        require(
            request.rebate_bps <= self.config.max_rebate_bps,
            "rebate exceeds cap",
        )?;
        require(
            request.expires_at_height > request.reserved_at_height,
            "rebate expiry must follow reservation",
        )?;
        self.insert_nullifier_root(&request.rebate_nullifier_root)?;
        self.counters.fee_rebates_reserved = self.counters.fee_rebates_reserved.saturating_add(1);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let rebate_id = fee_rebate_id(&request, self.counters.fee_rebates_reserved);
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            status: RebateStatus::Reserved,
            disbursement_root: None,
        };
        self.public_records.push(record.public_record());
        self.emit_event(
            TreasuryEventKind::RebateReserved,
            rebate_id.clone(),
            root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-REBATE-EVENT",
                &record.public_record(),
            ),
            self.current_height,
        )?;
        self.fee_rebates.insert(rebate_id, record.clone());
        Ok(record)
    }
    pub fn disburse_fee_rebate(
        &mut self,
        rebate_id: &str,
        disbursement_root: String,
        disbursed_at_height: u64,
    ) -> Result<FeeRebateRecord> {
        self.config.validate()?;
        validate_required("disbursement_root", &disbursement_root)?;
        let existing = self
            .fee_rebates
            .get(rebate_id)
            .ok_or_else(|| "fee rebate missing for disbursement".to_string())?;
        require(
            matches!(
                existing.status,
                RebateStatus::Reserved | RebateStatus::Sponsored
            ),
            "fee rebate is not disbursable",
        )?;
        require(
            disbursed_at_height <= existing.request.expires_at_height,
            "fee rebate expired",
        )?;
        self.counters.fee_rebates_disbursed = self.counters.fee_rebates_disbursed.saturating_add(1);
        self.current_height = self.current_height.max(disbursed_at_height);
        let mut updated = existing.clone();
        updated.status = RebateStatus::Disbursed;
        updated.disbursement_root = Some(disbursement_root.clone());
        self.fee_rebates
            .insert(rebate_id.to_string(), updated.clone());
        self.public_records.push(updated.public_record());
        self.emit_event(
            TreasuryEventKind::RebateDisbursed,
            rebate_id.to_string(),
            disbursement_root,
            self.current_height,
        )?;
        Ok(updated)
    }
    pub fn record_risk_cap(&mut self, request: RecordRiskCapRequest) -> Result<RiskCapRecord> {
        self.config.validate()?;
        require(
            self.risk_caps.len() < self.config.max_risk_caps,
            "risk cap registry is full",
        )?;
        require(
            self.budgets.contains_key(&request.budget_id),
            "budget missing for risk cap",
        )?;
        require(
            request.expires_at_height > request.recorded_at_height,
            "risk cap expiry must follow record height",
        )?;
        self.insert_nullifier_root(&request.cap_nullifier_root)?;
        self.counters.risk_caps_recorded = self.counters.risk_caps_recorded.saturating_add(1);
        self.current_height = self.current_height.max(request.recorded_at_height);
        let risk_cap_id = risk_cap_id(&request, self.counters.risk_caps_recorded);
        let record = RiskCapRecord {
            risk_cap_id: risk_cap_id.clone(),
            request,
            status: RiskCapStatus::Active,
        };
        self.public_records.push(record.public_record());
        self.emit_event(
            TreasuryEventKind::RiskCapRecorded,
            risk_cap_id.clone(),
            root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-RISK-CAP-EVENT",
                &record.public_record(),
            ),
            self.current_height,
        )?;
        self.risk_caps.insert(risk_cap_id, record.clone());
        Ok(record)
    }
    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            budget_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_BUDGET_SCHEME,
                self.budgets
                    .values()
                    .map(BudgetProposalRecord::public_record)
                    .collect(),
            ),
            vote_attestation_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_VOTE_SCHEME,
                self.vote_attestations
                    .values()
                    .map(VoteAttestationRecord::public_record)
                    .collect(),
            ),
            vesting_stream_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_VESTING_SCHEME,
                self.vesting_streams
                    .values()
                    .map(VestingStreamRecord::public_record)
                    .collect(),
            ),
            liquidity_incentive_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INCENTIVE_SCHEME,
                self.liquidity_incentives
                    .values()
                    .map(LiquidityIncentiveRecord::public_record)
                    .collect(),
            ),
            fee_rebate_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_REBATE_SCHEME,
                self.fee_rebates
                    .values()
                    .map(FeeRebateRecord::public_record)
                    .collect(),
            ),
            risk_cap_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_RISK_CAP_SCHEME,
                self.risk_caps
                    .values()
                    .map(RiskCapRecord::public_record)
                    .collect(),
            ),
            timelock_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_TIMELOCK_SCHEME,
                self.timelocks
                    .values()
                    .map(TimelockRecord::public_record)
                    .collect(),
            ),
            nullifier_root: merkle_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PRIVACY_FENCE_SCHEME,
                &self
                    .consumed_nullifier_roots
                    .iter()
                    .map(|value| json!(value))
                    .collect::<Vec<_>>(),
            ),
            event_root: records_root(
                PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_EVENT_SCHEME,
                self.events
                    .iter()
                    .map(TreasuryEventRecord::public_record)
                    .collect(),
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-PUBLIC-RECORDS",
                &self.public_records,
            ),
        }
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({"kind":"private_l2_confidential_token_governed_treasury_runtime","protocol_version":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION,"schema_version":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_SCHEMA_VERSION,"hash_suite":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_HASH_SUITE,"pq_auth_suite":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PQ_AUTH_SUITE,"budget_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_BUDGET_SCHEME,"vote_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_VOTE_SCHEME,"vesting_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_VESTING_SCHEME,"incentive_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_INCENTIVE_SCHEME,"rebate_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_REBATE_SCHEME,"risk_cap_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_RISK_CAP_SCHEME,"timelock_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_TIMELOCK_SCHEME,"privacy_fence_scheme":PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PRIVACY_FENCE_SCHEME,"config":self.config.public_record(),"counters":self.counters.public_record(),"current_height":self.current_height,"roots":self.roots().public_record()})
    }
    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-STATE",
            &record,
        );
        json!({"state_root": state_root, "record": record})
    }
    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-STATE",
            &self.public_record_without_state_root(),
        )
    }
    fn insert_nullifier_root(&mut self, nullifier_root: &str) -> Result<()> {
        if !self
            .consumed_nullifier_roots
            .insert(nullifier_root.to_string())
        {
            return Err(
                "confidential token governed treasury nullifier root already consumed".to_string(),
            );
        }
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        Ok(())
    }
    fn emit_event(
        &mut self,
        event_kind: TreasuryEventKind,
        subject_id: String,
        event_root: String,
        emitted_at_height: u64,
    ) -> Result<TreasuryEventRecord> {
        require(
            self.events.len() < self.config.max_events,
            "treasury event log is full",
        )?;
        self.counters.events_emitted = self.counters.events_emitted.saturating_add(1);
        let event_id = treasury_event_id(
            event_kind,
            &subject_id,
            &event_root,
            self.counters.events_emitted,
        );
        let record = TreasuryEventRecord {
            event_id,
            event_kind,
            subject_id,
            event_root,
            emitted_at_height,
        };
        self.events.push(record.clone());
        Ok(record)
    }
    fn seed_devnet_records(&mut self) -> Result<()> {
        let budget = self.register_budget_proposal(RegisterBudgetProposalRequest {
            proposal_kind: BudgetProposalKind::LiquidityMining,
            proposer_commitment: seeded("devnet-treasury-proposer-001"),
            encrypted_budget_root: seeded("devnet-encrypted-budget-liquidity-001"),
            encrypted_metadata_root: seeded("devnet-budget-metadata-liquidity-001"),
            recipient_set_root: seeded("devnet-recipient-set-liquidity-001"),
            spend_policy_root: seeded("devnet-spend-policy-liquidity-001"),
            treasury_asset_id: self.config.treasury_asset_id.clone(),
            amount_commitment_root: seeded("devnet-budget-amount-liquidity-001"),
            draw_limit_bps: self.config.max_treasury_draw_bps,
            risk_cap_root: seeded("devnet-budget-risk-cap-liquidity-001"),
            vote_policy_root: seeded("devnet-budget-vote-policy-liquidity-001"),
            quorum_commitment_root: seeded("devnet-budget-quorum-liquidity-001"),
            timelock_policy_root: seeded("devnet-budget-timelock-policy-liquidity-001"),
            pq_authority_root: seeded("devnet-budget-pq-authority-liquidity-001"),
            privacy_fence_root: seeded("devnet-budget-nullifier-liquidity-001"),
            min_privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            registered_at_height: self.current_height,
            vote_start_height: self.current_height,
            vote_end_height: self.current_height.saturating_add(144),
            expires_at_height: self.current_height.saturating_add(720),
        })?;
        let vote = self.submit_vote_attestation(SubmitVoteAttestationRequest {
            budget_id: budget.budget_id.clone(),
            voter_commitment: seeded("devnet-treasury-voter-001"),
            encrypted_choice_root: seeded("devnet-treasury-vote-choice-001"),
            vote_choice_commitment_root: seeded("devnet-treasury-choice-commitment-001"),
            vote_weight_commitment_root: seeded("devnet-treasury-weight-commitment-001"),
            eligibility_witness_root: seeded("devnet-treasury-eligibility-001"),
            governance_token_lock_root: seeded("devnet-governance-token-lock-001"),
            pq_signature_root: seeded("devnet-treasury-pq-signature-001"),
            pq_kem_ciphertext_root: seeded("devnet-treasury-pq-kem-001"),
            attestation_nullifier_root: seeded("devnet-treasury-vote-nullifier-001"),
            privacy_proof_root: seeded("devnet-treasury-vote-privacy-001"),
            fee_commitment_root: seeded("devnet-treasury-vote-fee-001"),
            max_fee_bps: self.config.max_user_fee_bps,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            submitted_at_height: self.current_height,
            expires_at_height: self.current_height.saturating_add(144),
            choice_hint: TreasuryVoteChoice::For,
        })?;
        self.current_height = budget.request.vote_end_height;
        self.tally_budget(TallyBudgetRequest {
            budget_id: budget.budget_id.clone(),
            operator_commitment: seeded("devnet-treasury-tally-operator-001"),
            vote_attestation_ids: vec![vote.attestation_id],
            aggregate_vote_root: seeded("devnet-treasury-aggregate-vote-root"),
            aggregate_nullifier_root: seeded("devnet-treasury-aggregate-nullifier-root"),
            encrypted_tally_root: seeded("devnet-treasury-encrypted-tally-root"),
            quorum_commitment_root: seeded("devnet-treasury-quorum-root"),
            approval_commitment_root: seeded("devnet-treasury-approval-root"),
            veto_commitment_root: seeded("devnet-treasury-veto-root"),
            tally_proof_root: seeded("devnet-treasury-tally-proof-root"),
            pq_certificate_root: seeded("devnet-treasury-tally-pq-root"),
            privacy_set_size: self.config.batch_privacy_set_size,
            max_fee_bps: self.config.max_user_fee_bps,
            tallied_at_height: self.current_height,
        })?;
        let timelock = self.queue_timelock(QueueTimelockRequest {
            budget_id: budget.budget_id.clone(),
            executor_commitment: seeded("devnet-treasury-executor-001"),
            action_root: seeded("devnet-treasury-action-root-001"),
            pre_state_root: seeded("devnet-treasury-pre-state-root-001"),
            spending_intent_root: seeded("devnet-treasury-spending-intent-root-001"),
            execution_policy_root: seeded("devnet-treasury-execution-policy-root-001"),
            timelock_nullifier_root: seeded("devnet-treasury-timelock-nullifier-001"),
            pq_execution_root: seeded("devnet-treasury-pq-execution-root-001"),
            queued_at_height: self.current_height,
            executable_at_height: self
                .current_height
                .saturating_add(self.config.timelock_delay_blocks),
            expires_at_height: self
                .current_height
                .saturating_add(self.config.timelock_delay_blocks)
                .saturating_add(144),
        })?;
        self.current_height = timelock.request.executable_at_height;
        self.execute_timelock(ExecuteTimelockRequest {
            timelock_id: timelock.timelock_id,
            budget_id: budget.budget_id.clone(),
            executor_commitment: seeded("devnet-treasury-executor-001"),
            state_root_before: seeded("devnet-treasury-state-before-execution"),
            state_root_after: seeded("devnet-treasury-state-after-execution"),
            execution_receipt_root: seeded("devnet-treasury-execution-receipt-root"),
            settlement_proof_root: seeded("devnet-treasury-settlement-proof-root"),
            fee_receipt_root: seeded("devnet-treasury-fee-receipt-root"),
            execution_nullifier_root: seeded("devnet-treasury-execution-nullifier-root"),
            pq_receipt_root: seeded("devnet-treasury-pq-receipt-root"),
            settled_fee_bps: self.config.max_sponsor_fee_bps,
            executed_at_height: self.current_height,
        })?;
        self.open_liquidity_incentive(OpenLiquidityIncentiveRequest {
            budget_id: budget.budget_id.clone(),
            pool_commitment: seeded("devnet-pool-commitment-xmr-dusd"),
            reward_asset_id: self.config.treasury_asset_id.clone(),
            reward_budget_commitment_root: seeded("devnet-incentive-reward-budget"),
            emission_curve_root: seeded("devnet-incentive-emission-curve"),
            liquidity_position_root: seeded("devnet-incentive-liquidity-position"),
            oracle_policy_root: seeded("devnet-incentive-oracle-policy"),
            max_apr_bps: self.config.max_incentive_apr_bps,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            incentive_nullifier_root: seeded("devnet-incentive-nullifier"),
            opened_at_height: self.current_height,
            expires_at_height: self.current_height.saturating_add(10_080),
        })?;
        self.reserve_fee_rebate(ReserveFeeRebateRequest {
            budget_id: budget.budget_id.clone(),
            recipient_commitment: seeded("devnet-rebate-recipient-001"),
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_amount_commitment_root: seeded("devnet-rebate-amount-root"),
            eligible_volume_root: seeded("devnet-rebate-volume-root"),
            rebate_policy_root: seeded("devnet-rebate-policy-root"),
            rebate_bps: self.config.max_rebate_bps,
            rebate_nullifier_root: seeded("devnet-rebate-nullifier-root"),
            privacy_proof_root: seeded("devnet-rebate-privacy-proof-root"),
            pq_recipient_root: seeded("devnet-rebate-pq-recipient-root"),
            reserved_at_height: self.current_height,
            expires_at_height: self.current_height.saturating_add(10_080),
        })?;
        self.record_risk_cap(RecordRiskCapRequest {
            budget_id: budget.budget_id.clone(),
            market_id: "devnet-private-xmr-dusd".to_string(),
            asset_id: self.config.treasury_asset_id.clone(),
            cap_commitment_root: seeded("devnet-risk-cap-commitment-root"),
            exposure_oracle_root: seeded("devnet-risk-cap-oracle-root"),
            liquidation_policy_root: seeded("devnet-risk-cap-liquidation-root"),
            circuit_breaker_root: seeded("devnet-risk-cap-circuit-breaker-root"),
            cap_nullifier_root: seeded("devnet-risk-cap-nullifier-root"),
            privacy_proof_root: seeded("devnet-risk-cap-privacy-proof-root"),
            pq_risk_committee_root: seeded("devnet-risk-cap-pq-committee-root"),
            recorded_at_height: self.current_height,
            expires_at_height: self.current_height.saturating_add(20_160),
        })?;
        self.open_vesting_stream(OpenVestingStreamRequest {
            budget_id: budget.budget_id,
            beneficiary_commitment: seeded("devnet-vesting-beneficiary-001"),
            asset_id: self.config.treasury_asset_id.clone(),
            total_amount_commitment_root: seeded("devnet-vesting-total-amount-root"),
            schedule_root: seeded("devnet-vesting-schedule-root"),
            cliff_height: self.current_height.saturating_add(720),
            start_height: self.current_height,
            end_height: self.current_height.saturating_add(43_200),
            claim_policy_root: seeded("devnet-vesting-claim-policy-root"),
            revocation_policy_root: seeded("devnet-vesting-revocation-policy-root"),
            stream_nullifier_root: seeded("devnet-vesting-stream-nullifier-root"),
            privacy_proof_root: seeded("devnet-vesting-privacy-proof-root"),
            pq_beneficiary_root: seeded("devnet-vesting-pq-beneficiary-root"),
            opened_at_height: self.current_height,
        })?;
        Ok(())
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}
pub fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}
pub fn budget_proposal_id(request: &RegisterBudgetProposalRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-BUDGET-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.proposal_kind.as_str()),
            HashPart::Str(&request.proposer_commitment),
            HashPart::Str(&request.encrypted_budget_root),
            HashPart::Str(&request.privacy_fence_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn vote_attestation_id(request: &SubmitVoteAttestationRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-VOTE-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.budget_id),
            HashPart::Str(&request.voter_commitment),
            HashPart::Str(&request.attestation_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn tally_budget_root(request: &TallyBudgetRequest, counter: u64) -> String {
    let record = request.public_record();
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-TALLY-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn timelock_id(request: &QueueTimelockRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-TIMELOCK-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.budget_id),
            HashPart::Str(&request.action_root),
            HashPart::Str(&request.timelock_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn execution_receipt_id(request: &ExecuteTimelockRequest, counter: u64) -> String {
    let record = request.public_record();
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-EXECUTION-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn vesting_stream_id(request: &OpenVestingStreamRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-VESTING-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.budget_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.stream_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn vesting_claim_root(request: &SettleVestingClaimRequest, counter: u64) -> String {
    let record = request.public_record();
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-VESTING-CLAIM-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn liquidity_incentive_id(request: &OpenLiquidityIncentiveRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-INCENTIVE-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.budget_id),
            HashPart::Str(&request.pool_commitment),
            HashPart::Str(&request.incentive_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn fee_rebate_id(request: &ReserveFeeRebateRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-REBATE-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.budget_id),
            HashPart::Str(&request.recipient_commitment),
            HashPart::Str(&request.rebate_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn risk_cap_id(request: &RecordRiskCapRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-RISK-CAP-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.budget_id),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.cap_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn treasury_event_id(
    event_kind: TreasuryEventKind,
    subject_id: &str,
    event_root: &str,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-EVENT-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(event_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}
pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}
pub fn public_record_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-PUBLIC-RECORD",
        record,
    )
}
pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-STATE",
        record,
    )
}
pub fn seeded(seed: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-TOKEN-GOVERNED-TREASURY-DEVNET-SEED",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seed),
        ],
        32,
    )
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn require_bps(value: u64, label: &str) -> Result<()> {
    require(
        value <= PRIVATE_L2_CONFIDENTIAL_TOKEN_GOVERNED_TREASURY_RUNTIME_MAX_BPS,
        &format!("{label} bps exceeds max"),
    )
}
fn validate_required(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "confidential token governed treasury field {field} is required"
        ));
    }
    Ok(())
}
fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("confidential token governed treasury privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err(
            "confidential token governed treasury PQ security bits below minimum".to_string(),
        );
    }
    Ok(())
}
