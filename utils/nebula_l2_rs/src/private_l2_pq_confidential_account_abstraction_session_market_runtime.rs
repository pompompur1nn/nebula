use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-account-abstraction-session-market-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PQ_AUTH_SUITE:
    &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-aa-session-market-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_SESSION_GRANT_SCHEME: &str = "sealed-aa-session-grant-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_POLICY_PROOF_SCHEME: &str = "pq-aa-policy-proof-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PAYMASTER_BID_SCHEME: &str = "confidential-paymaster-sponsorship-bid-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_RECOVERY_HOOK_SCHEME: &str = "smart-account-recovery-hook-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_ALLOWANCE_SCHEME:
    &str = "contract-call-allowance-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PRIVACY_FENCE_SCHEME: &str = "account-abstraction-session-privacy-fence-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_REBATE_SCHEME:
    &str = "confidential-session-fee-rebate-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_SLASHING_SCHEME:
    &str = "aa-session-market-slashing-evidence-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEVNET_HEIGHT: u64 =
    836_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_SESSION_GRANTS: usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_POLICY_PROOFS: usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_PAYMASTER_BIDS: usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_RECOVERY_HOOKS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_ALLOWANCES: usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_SESSION_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_POLICY_PROOF_TTL_BLOCKS: u64 = 360;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_BID_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_SESSION_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_PAYMASTER_FEE_BPS: u64 = 10;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_SLASHING_PENALTY_BPS: u64 = 1_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_MAX_BPS: u64 =
    10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountSessionKind {
    ContractCall,
    DefiSwap,
    BridgeTransfer,
    GovernanceVote,
    RecoveryOperation,
    TokenTransfer,
    ViewOnly,
    EmergencyEscape,
}
impl AccountSessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::BridgeTransfer => "bridge_transfer",
            Self::GovernanceVote => "governance_vote",
            Self::RecoveryOperation => "recovery_operation",
            Self::TokenTransfer => "token_transfer",
            Self::ViewOnly => "view_only",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantStatus {
    Sealed,
    PolicyVerified,
    BidMatched,
    AllowanceReserved,
    Executing,
    Settled,
    Revoked,
    Expired,
    Slashed,
}
impl SessionGrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::PolicyVerified => "policy_verified",
            Self::BidMatched => "bid_matched",
            Self::AllowanceReserved => "allowance_reserved",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPolicyProofKind {
    SpendLimit,
    VelocityLimit,
    ContractAllowlist,
    SelectorAllowlist,
    DestinationFence,
    RecoveryQuorum,
    PaymasterBudget,
    EmergencyPolicy,
}
impl PqPolicyProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendLimit => "spend_limit",
            Self::VelocityLimit => "velocity_limit",
            Self::ContractAllowlist => "contract_allowlist",
            Self::SelectorAllowlist => "selector_allowlist",
            Self::DestinationFence => "destination_fence",
            Self::RecoveryQuorum => "recovery_quorum",
            Self::PaymasterBudget => "paymaster_budget",
            Self::EmergencyPolicy => "emergency_policy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProofStatus {
    Submitted,
    Verified,
    Linked,
    Consumed,
    Rejected,
    Expired,
    Slashed,
}
impl PolicyProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Linked => "linked",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterBidKind {
    Universal,
    ContractScoped,
    RecoveryOnly,
    BridgeOnly,
    DefiOnly,
    GovernanceOnly,
    RebateOnly,
}
impl PaymasterBidKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Universal => "universal",
            Self::ContractScoped => "contract_scoped",
            Self::RecoveryOnly => "recovery_only",
            Self::BridgeOnly => "bridge_only",
            Self::DefiOnly => "defi_only",
            Self::GovernanceOnly => "governance_only",
            Self::RebateOnly => "rebate_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterBidStatus {
    Open,
    Matched,
    Reserved,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}
impl PaymasterBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHookKind {
    RotateSessionKey,
    RotateSpendKey,
    RotateViewKey,
    GuardianChallenge,
    EmergencyFreeze,
    PolicyReset,
}
impl RecoveryHookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RotateSessionKey => "rotate_session_key",
            Self::RotateSpendKey => "rotate_spend_key",
            Self::RotateViewKey => "rotate_view_key",
            Self::GuardianChallenge => "guardian_challenge",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::PolicyReset => "policy_reset",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHookStatus {
    Registered,
    Armed,
    Triggered,
    Executed,
    Cancelled,
    Expired,
    Slashed,
}
impl RecoveryHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Armed => "armed",
            Self::Triggered => "triggered",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowanceKind {
    CallCount,
    FeeBudget,
    ValueBudget,
    Selector,
    Contract,
    Asset,
    TimeWindow,
}
impl AllowanceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallCount => "call_count",
            Self::FeeBudget => "fee_budget",
            Self::ValueBudget => "value_budget",
            Self::Selector => "selector",
            Self::Contract => "contract",
            Self::Asset => "asset",
            Self::TimeWindow => "time_window",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowanceStatus {
    Reserved,
    Active,
    PartiallyConsumed,
    Consumed,
    Revoked,
    Expired,
    Slashed,
}
impl AllowanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::PartiallyConsumed => "partially_consumed",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    NullifierSet,
    MetadataCloak,
    ContractCluster,
    CounterpartySet,
    AmountBucket,
    TimingWindow,
    RelaySet,
}
impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierSet => "nullifier_set",
            Self::MetadataCloak => "metadata_cloak",
            Self::ContractCluster => "contract_cluster",
            Self::CounterpartySet => "counterparty_set",
            Self::AmountBucket => "amount_bucket",
            Self::TimingWindow => "timing_window",
            Self::RelaySet => "relay_set",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceStatus {
    Open,
    Enforced,
    Relaxed,
    Closed,
    Expired,
    Violated,
}
impl PrivacyFenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Enforced => "enforced",
            Self::Relaxed => "relaxed",
            Self::Closed => "closed",
            Self::Expired => "expired",
            Self::Violated => "violated",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Accrued,
    Paid,
    Cancelled,
    Expired,
}
impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Accrued => "accrued",
            Self::Paid => "paid",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    InvalidPolicyProof,
    DoubleSpendNullifier,
    AllowanceOverspend,
    BidNonPayment,
    PrivacyFenceLeak,
    RecoveryHookMisuse,
    BatchWithholding,
}
impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPolicyProof => "invalid_policy_proof",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::AllowanceOverspend => "allowance_overspend",
            Self::BidNonPayment => "bid_non_payment",
            Self::PrivacyFenceLeak => "privacy_fence_leak",
            Self::RecoveryHookMisuse => "recovery_hook_misuse",
            Self::BatchWithholding => "batch_withholding",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Applied,
    Expired,
}
impl SlashingEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Applied => "applied",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionBatchStatus {
    Built,
    ProofQueued,
    Settled,
    Disputed,
    Rejected,
}
impl SessionBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::ProofQueued => "proof_queued",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    SessionGranted,
    PolicyVerified,
    BidMatched,
    AllowanceReserved,
    PrivacyFenceEnforced,
    RecoveryHookTriggered,
    RebatePaid,
    SlashingApplied,
    BatchSettled,
}
impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionGranted => "session_granted",
            Self::PolicyVerified => "policy_verified",
            Self::BidMatched => "bid_matched",
            Self::AllowanceReserved => "allowance_reserved",
            Self::PrivacyFenceEnforced => "privacy_fence_enforced",
            Self::RecoveryHookTriggered => "recovery_hook_triggered",
            Self::RebatePaid => "rebate_paid",
            Self::SlashingApplied => "slashing_applied",
            Self::BatchSettled => "batch_settled",
        }
    }
}

impl SessionGrantStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::PolicyVerified
                | Self::BidMatched
                | Self::AllowanceReserved
                | Self::Executing
        )
    }
}
impl PolicyProofStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::Linked)
    }
}
impl PaymasterBidStatus {
    pub fn fundable(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Reserved)
    }
}
impl AllowanceStatus {
    pub fn spendable(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Active | Self::PartiallyConsumed
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub session_grant_scheme: String,
    pub policy_proof_scheme: String,
    pub paymaster_bid_scheme: String,
    pub recovery_hook_scheme: String,
    pub allowance_scheme: String,
    pub privacy_fence_scheme: String,
    pub rebate_scheme: String,
    pub slashing_scheme: String,
    pub max_session_grants: usize,
    pub max_policy_proofs: usize,
    pub max_paymaster_bids: usize,
    pub max_recovery_hooks: usize,
    pub max_allowances: usize,
    pub max_privacy_fences: usize,
    pub max_rebates: usize,
    pub max_slashing_evidence: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_batch_items: usize,
    pub session_ttl_blocks: u64,
    pub policy_proof_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_session_fee_bps: u64,
    pub max_paymaster_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_penalty_bps: u64,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEVNET_HEIGHT,
            l2_network: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_L2_NETWORK.to_string(),
            monero_network: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PQ_AUTH_SUITE.to_string(),
            session_grant_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_SESSION_GRANT_SCHEME.to_string(),
            policy_proof_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_POLICY_PROOF_SCHEME.to_string(),
            paymaster_bid_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PAYMASTER_BID_SCHEME.to_string(),
            recovery_hook_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_RECOVERY_HOOK_SCHEME.to_string(),
            allowance_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_ALLOWANCE_SCHEME.to_string(),
            privacy_fence_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PRIVACY_FENCE_SCHEME.to_string(),
            rebate_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_REBATE_SCHEME.to_string(),
            slashing_scheme: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_SLASHING_SCHEME.to_string(),
            max_session_grants: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_SESSION_GRANTS,
            max_policy_proofs: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_POLICY_PROOFS,
            max_paymaster_bids: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_PAYMASTER_BIDS,
            max_recovery_hooks: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_RECOVERY_HOOKS,
            max_allowances: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_ALLOWANCES,
            max_privacy_fences: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES,
            max_rebates: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_REBATES,
            max_slashing_evidence: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_SLASHING_EVIDENCE,
            max_batches: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_items: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            session_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_SESSION_TTL_BLOCKS,
            policy_proof_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_POLICY_PROOF_TTL_BLOCKS,
            bid_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_session_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_SESSION_FEE_BPS,
            max_paymaster_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_MAX_PAYMASTER_FEE_BPS,
            target_rebate_bps: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            slashing_penalty_bps: PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_DEFAULT_SLASHING_PENALTY_BPS,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub session_grants: u64,
    pub policy_proofs: u64,
    pub paymaster_bids: u64,
    pub recovery_hooks: u64,
    pub allowances: u64,
    pub privacy_fences: u64,
    pub rebates: u64,
    pub slashing_evidence: u64,
    pub batches: u64,
    pub receipts: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedSessionGrantRequest {
    pub account_commitment: String,
    pub session_key_commitment: String,
    pub sealed_grant_ciphertext: String,
    pub grant_nullifier: String,
    pub policy_root: String,
    pub paymaster_bid_id: Option<String>,
    pub recovery_hook_id: Option<String>,
    pub allowance_ids: BTreeSet<String>,
    pub privacy_fence_ids: BTreeSet<String>,
    pub kind: AccountSessionKind,
    pub status: SessionGrantStatus,
    pub max_fee_units: u128,
    pub spent_fee_units: u128,
    pub max_call_value_units: u128,
    pub spent_call_value_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
    pub metadata_commitment: String,
}
impl SealedSessionGrantRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedSessionGrantRecord {
    pub grant_id: String,
    pub account_commitment: String,
    pub session_key_commitment: String,
    pub sealed_grant_ciphertext: String,
    pub grant_nullifier: String,
    pub policy_root: String,
    pub paymaster_bid_id: Option<String>,
    pub recovery_hook_id: Option<String>,
    pub allowance_ids: BTreeSet<String>,
    pub privacy_fence_ids: BTreeSet<String>,
    pub kind: AccountSessionKind,
    pub status: SessionGrantStatus,
    pub max_fee_units: u128,
    pub spent_fee_units: u128,
    pub max_call_value_units: u128,
    pub spent_call_value_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
    pub metadata_commitment: String,
}
impl SealedSessionGrantRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPolicyProofRequest {
    pub policy_commitment: String,
    pub proof_transcript_root: String,
    pub proof_nullifier: String,
    pub kind: PqPolicyProofKind,
    pub status: PolicyProofStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
    pub published_at_height: u64,
    pub metadata_commitment: String,
}
impl PqPolicyProofRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPolicyProofRecord {
    pub proof_id: String,
    pub grant_id: String,
    pub policy_commitment: String,
    pub proof_transcript_root: String,
    pub proof_nullifier: String,
    pub kind: PqPolicyProofKind,
    pub status: PolicyProofStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
    pub published_at_height: u64,
    pub metadata_commitment: String,
}
impl PqPolicyProofRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymasterSponsorshipBidRequest {
    pub paymaster_commitment: String,
    pub sponsor_vault_commitment: String,
    pub bid_nullifier: String,
    pub kind: PaymasterBidKind,
    pub status: PaymasterBidStatus,
    pub max_sponsored_fee_units: u128,
    pub remaining_fee_units: u128,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub matched_grant_ids: BTreeSet<String>,
    pub metadata_commitment: String,
}
impl PaymasterSponsorshipBidRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PaymasterSponsorshipBidRecord {
    pub bid_id: String,
    pub paymaster_commitment: String,
    pub sponsor_vault_commitment: String,
    pub bid_nullifier: String,
    pub kind: PaymasterBidKind,
    pub status: PaymasterBidStatus,
    pub max_sponsored_fee_units: u128,
    pub remaining_fee_units: u128,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub matched_grant_ids: BTreeSet<String>,
    pub metadata_commitment: String,
}
impl PaymasterSponsorshipBidRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmartAccountRecoveryHookRequest {
    pub account_commitment: String,
    pub guardian_policy_root: String,
    pub recovery_nullifier: String,
    pub kind: RecoveryHookKind,
    pub status: RecoveryHookStatus,
    pub threshold_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub triggered_grant_ids: BTreeSet<String>,
    pub metadata_commitment: String,
}
impl SmartAccountRecoveryHookRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SmartAccountRecoveryHookRecord {
    pub hook_id: String,
    pub account_commitment: String,
    pub guardian_policy_root: String,
    pub recovery_nullifier: String,
    pub kind: RecoveryHookKind,
    pub status: RecoveryHookStatus,
    pub threshold_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub triggered_grant_ids: BTreeSet<String>,
    pub metadata_commitment: String,
}
impl SmartAccountRecoveryHookRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallAllowanceRequest {
    pub contract_commitment: String,
    pub selector_commitment: String,
    pub asset_commitment: String,
    pub allowance_nullifier: String,
    pub kind: AllowanceKind,
    pub status: AllowanceStatus,
    pub remaining_call_count: u64,
    pub remaining_fee_units: u128,
    pub remaining_value_units: u128,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: String,
}
impl ContractCallAllowanceRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallAllowanceRecord {
    pub allowance_id: String,
    pub grant_id: String,
    pub contract_commitment: String,
    pub selector_commitment: String,
    pub asset_commitment: String,
    pub allowance_nullifier: String,
    pub kind: AllowanceKind,
    pub status: AllowanceStatus,
    pub remaining_call_count: u64,
    pub remaining_fee_units: u128,
    pub remaining_value_units: u128,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: String,
}
impl ContractCallAllowanceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFenceRequest {
    pub fence_commitment: String,
    pub fence_nullifier: String,
    pub kind: PrivacyFenceKind,
    pub status: PrivacyFenceStatus,
    pub min_privacy_set_size: u64,
    pub observed_privacy_set_size: u64,
    pub leakage_score_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: String,
}
impl PrivacyFenceRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub grant_id: String,
    pub fence_commitment: String,
    pub fence_nullifier: String,
    pub kind: PrivacyFenceKind,
    pub status: PrivacyFenceStatus,
    pub min_privacy_set_size: u64,
    pub observed_privacy_set_size: u64,
    pub leakage_score_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: String,
}
impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRequest {
    pub paymaster_bid_id: String,
    pub recipient_commitment: String,
    pub rebate_nullifier: String,
    pub status: RebateStatus,
    pub fee_paid_units: u128,
    pub rebate_units: u128,
    pub rebate_bps: u64,
    pub queued_at_height: u64,
    pub paid_at_height: Option<u64>,
    pub metadata_commitment: String,
}
impl FeeRebateRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub grant_id: String,
    pub paymaster_bid_id: String,
    pub recipient_commitment: String,
    pub rebate_nullifier: String,
    pub status: RebateStatus,
    pub fee_paid_units: u128,
    pub rebate_units: u128,
    pub rebate_bps: u64,
    pub queued_at_height: u64,
    pub paid_at_height: Option<u64>,
    pub metadata_commitment: String,
}
impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidenceRequest {
    pub target_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub evidence_nullifier: String,
    pub kind: SlashingEvidenceKind,
    pub status: SlashingEvidenceStatus,
    pub penalty_units: u128,
    pub penalty_bps: u64,
    pub published_at_height: u64,
    pub applied_at_height: Option<u64>,
    pub metadata_commitment: String,
}
impl SlashingEvidenceRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidenceRecord {
    pub evidence_id: String,
    pub target_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub evidence_nullifier: String,
    pub kind: SlashingEvidenceKind,
    pub status: SlashingEvidenceStatus,
    pub penalty_units: u128,
    pub penalty_bps: u64,
    pub published_at_height: u64,
    pub applied_at_height: Option<u64>,
    pub metadata_commitment: String,
}
impl SlashingEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionMarketBatchRequest {
    pub grant_ids: Vec<String>,
    pub policy_proof_ids: Vec<String>,
    pub paymaster_bid_ids: Vec<String>,
    pub allowance_ids: Vec<String>,
    pub privacy_fence_ids: Vec<String>,
    pub status: SessionBatchStatus,
    pub batch_root: String,
    pub settlement_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub metadata_commitment: String,
}
impl SessionMarketBatchRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionMarketBatchRecord {
    pub batch_id: String,
    pub grant_ids: Vec<String>,
    pub policy_proof_ids: Vec<String>,
    pub paymaster_bid_ids: Vec<String>,
    pub allowance_ids: Vec<String>,
    pub privacy_fence_ids: Vec<String>,
    pub status: SessionBatchStatus,
    pub batch_root: String,
    pub settlement_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub metadata_commitment: String,
}
impl SessionMarketBatchRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionMarketReceiptRequest {
    pub subject_id: String,
    pub kind: ReceiptKind,
    pub receipt_root: String,
    pub fee_debit_root: String,
    pub rebate_root: String,
    pub published_at_height: u64,
    pub metadata_commitment: String,
}
impl SessionMarketReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionMarketReceiptRecord {
    pub receipt_id: String,
    pub subject_id: String,
    pub kind: ReceiptKind,
    pub receipt_root: String,
    pub fee_debit_root: String,
    pub rebate_root: String,
    pub published_at_height: u64,
    pub metadata_commitment: String,
}
impl SessionMarketReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub session_grant_root: String,
    pub policy_proof_root: String,
    pub paymaster_bid_root: String,
    pub recovery_hook_root: String,
    pub allowance_root: String,
    pub privacy_fence_root: String,
    pub rebate_root: String,
    pub slashing_evidence_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub public_record_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub session_grants: BTreeMap<String, SealedSessionGrantRecord>,
    pub policy_proofs: BTreeMap<String, PqPolicyProofRecord>,
    pub paymaster_bids: BTreeMap<String, PaymasterSponsorshipBidRecord>,
    pub recovery_hooks: BTreeMap<String, SmartAccountRecoveryHookRecord>,
    pub allowances: BTreeMap<String, ContractCallAllowanceRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidenceRecord>,
    pub batches: BTreeMap<String, SessionMarketBatchRecord>,
    pub receipts: BTreeMap<String, SessionMarketReceiptRecord>,
}
pub type Runtime = State;

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            current_height: config.devnet_height,
            config,
            counters: Counters::default(),
            session_grants: BTreeMap::new(),
            policy_proofs: BTreeMap::new(),
            paymaster_bids: BTreeMap::new(),
            recovery_hooks: BTreeMap::new(),
            allowances: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }
    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }
    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn register_session_grant(
        &mut self,
        request: SealedSessionGrantRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<SealedSessionGrantRecord>
    {
        validate_sealedsessiongrant_request(&self.config, &request, self.current_height)?;
        ensure_capacity(
            self.session_grants.len(),
            self.config.max_session_grants,
            "session_grants",
        )?;
        let grant_id = deterministic_id("SEALEDSESSIONGRANT", &request.public_record());
        ensure_unique(&self.session_grants, &grant_id, "grant_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("grant_id".to_string(), Value::String(grant_id.clone()));
        }
        let record: SealedSessionGrantRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.session_grants.insert(grant_id, record.clone());
        self.counters.session_grants = self.counters.session_grants.saturating_add(1);
        Ok(record)
    }

    pub fn submit_policy_proof(
        &mut self,
        request: PqPolicyProofRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<PqPolicyProofRecord>
    {
        validate_pqpolicyproof_request(&self.config, &request, self.current_height)?;
        ensure_capacity(
            self.policy_proofs.len(),
            self.config.max_policy_proofs,
            "policy_proofs",
        )?;
        let proof_id = deterministic_id("PQPOLICYPROOF", &request.public_record());
        ensure_unique(&self.policy_proofs, &proof_id, "proof_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("proof_id".to_string(), Value::String(proof_id.clone()));
        }
        let record: PqPolicyProofRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.policy_proofs.insert(proof_id, record.clone());
        self.counters.policy_proofs = self.counters.policy_proofs.saturating_add(1);
        Ok(record)
    }

    pub fn submit_paymaster_bid(
        &mut self,
        request: PaymasterSponsorshipBidRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<
        PaymasterSponsorshipBidRecord,
    > {
        validate_paymastersponsorshipbid_request(&self.config, &request, self.current_height)?;
        ensure_capacity(
            self.paymaster_bids.len(),
            self.config.max_paymaster_bids,
            "paymaster_bids",
        )?;
        let bid_id = deterministic_id("PAYMASTERSPONSORSHIPBID", &request.public_record());
        ensure_unique(&self.paymaster_bids, &bid_id, "bid_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("bid_id".to_string(), Value::String(bid_id.clone()));
        }
        let record: PaymasterSponsorshipBidRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.paymaster_bids.insert(bid_id, record.clone());
        self.counters.paymaster_bids = self.counters.paymaster_bids.saturating_add(1);
        Ok(record)
    }

    pub fn register_recovery_hook(
        &mut self,
        request: SmartAccountRecoveryHookRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<
        SmartAccountRecoveryHookRecord,
    > {
        validate_smartaccountrecoveryhook_request(&self.config, &request, self.current_height)?;
        ensure_capacity(
            self.recovery_hooks.len(),
            self.config.max_recovery_hooks,
            "recovery_hooks",
        )?;
        let hook_id = deterministic_id("SMARTACCOUNTRECOVERYHOOK", &request.public_record());
        ensure_unique(&self.recovery_hooks, &hook_id, "hook_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("hook_id".to_string(), Value::String(hook_id.clone()));
        }
        let record: SmartAccountRecoveryHookRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.recovery_hooks.insert(hook_id, record.clone());
        self.counters.recovery_hooks = self.counters.recovery_hooks.saturating_add(1);
        Ok(record)
    }

    pub fn reserve_allowance(
        &mut self,
        request: ContractCallAllowanceRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<
        ContractCallAllowanceRecord,
    > {
        validate_contractcallallowance_request(&self.config, &request, self.current_height)?;
        ensure_capacity(
            self.allowances.len(),
            self.config.max_allowances,
            "allowances",
        )?;
        let allowance_id = deterministic_id("CONTRACTCALLALLOWANCE", &request.public_record());
        ensure_unique(&self.allowances, &allowance_id, "allowance_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert(
                "allowance_id".to_string(),
                Value::String(allowance_id.clone()),
            );
        }
        let record: ContractCallAllowanceRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.allowances.insert(allowance_id, record.clone());
        self.counters.allowances = self.counters.allowances.saturating_add(1);
        Ok(record)
    }

    pub fn open_privacy_fence(
        &mut self,
        request: PrivacyFenceRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<PrivacyFenceRecord>
    {
        validate_privacyfence_request(&self.config, &request, self.current_height)?;
        ensure_capacity(
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
            "privacy_fences",
        )?;
        let fence_id = deterministic_id("PRIVACYFENCE", &request.public_record());
        ensure_unique(&self.privacy_fences, &fence_id, "fence_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("fence_id".to_string(), Value::String(fence_id.clone()));
        }
        let record: PrivacyFenceRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.privacy_fences.insert(fence_id, record.clone());
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        Ok(record)
    }

    pub fn link_policy_to_grant(
        &mut self,
        grant_id: &str,
        proof_id: &str,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
        let proof = self
            .policy_proofs
            .get_mut(proof_id)
            .ok_or_else(|| format!("unknown proof_id {proof_id}"))?;
        if proof.grant_id != grant_id {
            return Err("policy proof targets a different grant".to_string());
        }
        if !proof.status.usable() {
            proof.status = PolicyProofStatus::Verified;
        }
        let grant = self
            .session_grants
            .get_mut(grant_id)
            .ok_or_else(|| format!("unknown grant_id {grant_id}"))?;
        if !grant.status.live() {
            return Err("session grant is not live".to_string());
        }
        grant.status = SessionGrantStatus::PolicyVerified;
        grant.updated_at_height = self.current_height;
        Ok(())
    }

    pub fn match_paymaster_bid(
        &mut self,
        grant_id: &str,
        bid_id: &str,
        reserved_fee_units: u128,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
        let bid = self
            .paymaster_bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("unknown bid_id {bid_id}"))?;
        if !bid.status.fundable() {
            return Err("paymaster bid is not fundable".to_string());
        }
        if bid.remaining_fee_units < reserved_fee_units {
            return Err("insufficient paymaster bid balance".to_string());
        }
        bid.remaining_fee_units -= reserved_fee_units;
        bid.matched_grant_ids.insert(grant_id.to_string());
        bid.status = PaymasterBidStatus::Reserved;
        let grant = self
            .session_grants
            .get_mut(grant_id)
            .ok_or_else(|| format!("unknown grant_id {grant_id}"))?;
        grant.paymaster_bid_id = Some(bid_id.to_string());
        grant.status = SessionGrantStatus::BidMatched;
        grant.updated_at_height = self.current_height;
        Ok(())
    }

    pub fn attach_allowance(
        &mut self,
        grant_id: &str,
        allowance_id: &str,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
        let allowance = self
            .allowances
            .get_mut(allowance_id)
            .ok_or_else(|| format!("unknown allowance_id {allowance_id}"))?;
        if allowance.grant_id != grant_id {
            return Err("allowance targets a different grant".to_string());
        }
        if !allowance.status.spendable() {
            return Err("allowance is not spendable".to_string());
        }
        allowance.status = AllowanceStatus::Active;
        let grant = self
            .session_grants
            .get_mut(grant_id)
            .ok_or_else(|| format!("unknown grant_id {grant_id}"))?;
        grant.allowance_ids.insert(allowance_id.to_string());
        grant.status = SessionGrantStatus::AllowanceReserved;
        grant.updated_at_height = self.current_height;
        Ok(())
    }

    pub fn enforce_privacy_fence(
        &mut self,
        grant_id: &str,
        fence_id: &str,
        observed_privacy_set_size: u64,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
        let fence = self
            .privacy_fences
            .get_mut(fence_id)
            .ok_or_else(|| format!("unknown fence_id {fence_id}"))?;
        if fence.grant_id != grant_id {
            return Err("privacy fence targets a different grant".to_string());
        }
        fence.observed_privacy_set_size = observed_privacy_set_size;
        fence.status = if observed_privacy_set_size >= fence.min_privacy_set_size {
            PrivacyFenceStatus::Enforced
        } else {
            PrivacyFenceStatus::Violated
        };
        let grant = self
            .session_grants
            .get_mut(grant_id)
            .ok_or_else(|| format!("unknown grant_id {grant_id}"))?;
        grant.privacy_fence_ids.insert(fence_id.to_string());
        if matches!(fence.status, PrivacyFenceStatus::Violated) {
            grant.status = SessionGrantStatus::Revoked;
        }
        grant.updated_at_height = self.current_height;
        Ok(())
    }

    pub fn queue_fee_rebate(
        &mut self,
        request: FeeRebateRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<FeeRebateRecord> {
        validate_feerebate_request(&self.config, &request, self.current_height)?;
        ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        let rebate_id = deterministic_id("FEEREBATE", &request.public_record());
        ensure_unique(&self.rebates, &rebate_id, "rebate_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("rebate_id".to_string(), Value::String(rebate_id.clone()));
        }
        let record: FeeRebateRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.rebates.insert(rebate_id, record.clone());
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        Ok(record)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        request: SlashingEvidenceRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<SlashingEvidenceRecord>
    {
        validate_slashingevidence_request(&self.config, &request, self.current_height)?;
        ensure_capacity(
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
            "slashing_evidence",
        )?;
        let evidence_id = deterministic_id("SLASHINGEVIDENCE", &request.public_record());
        ensure_unique(&self.slashing_evidence, &evidence_id, "evidence_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert(
                "evidence_id".to_string(),
                Value::String(evidence_id.clone()),
            );
        }
        let record: SlashingEvidenceRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.slashing_evidence.insert(evidence_id, record.clone());
        self.counters.slashing_evidence = self.counters.slashing_evidence.saturating_add(1);
        Ok(record)
    }

    pub fn build_batch(
        &mut self,
        request: SessionMarketBatchRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<SessionMarketBatchRecord>
    {
        validate_sessionmarketbatch_request(&self.config, &request, self.current_height)?;
        ensure_capacity(self.batches.len(), self.config.max_batches, "batches")?;
        let batch_id = deterministic_id("SESSIONMARKETBATCH", &request.public_record());
        ensure_unique(&self.batches, &batch_id, "batch_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("batch_id".to_string(), Value::String(batch_id.clone()));
        }
        let record: SessionMarketBatchRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.batches.insert(batch_id, record.clone());
        self.counters.batches = self.counters.batches.saturating_add(1);
        Ok(record)
    }

    pub fn publish_receipt(
        &mut self,
        request: SessionMarketReceiptRequest,
    ) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<
        SessionMarketReceiptRecord,
    > {
        validate_sessionmarketreceipt_request(&self.config, &request, self.current_height)?;
        ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        let receipt_id = deterministic_id("SESSIONMARKETRECEIPT", &request.public_record());
        ensure_unique(&self.receipts, &receipt_id, "receipt_id")?;
        let mut value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(ref mut object) = value {
            object.insert("receipt_id".to_string(), Value::String(receipt_id.clone()));
        }
        let record: SessionMarketReceiptRecord =
            serde_json::from_value(value).map_err(|error| error.to_string())?;
        self.receipts.insert(receipt_id, record.clone());
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let session_grants_records = self
            .session_grants
            .values()
            .map(SealedSessionGrantRecord::public_record)
            .collect::<Vec<_>>();
        let policy_proofs_records = self
            .policy_proofs
            .values()
            .map(PqPolicyProofRecord::public_record)
            .collect::<Vec<_>>();
        let paymaster_bids_records = self
            .paymaster_bids
            .values()
            .map(PaymasterSponsorshipBidRecord::public_record)
            .collect::<Vec<_>>();
        let recovery_hooks_records = self
            .recovery_hooks
            .values()
            .map(SmartAccountRecoveryHookRecord::public_record)
            .collect::<Vec<_>>();
        let allowances_records = self
            .allowances
            .values()
            .map(ContractCallAllowanceRecord::public_record)
            .collect::<Vec<_>>();
        let privacy_fences_records = self
            .privacy_fences
            .values()
            .map(PrivacyFenceRecord::public_record)
            .collect::<Vec<_>>();
        let rebates_records = self
            .rebates
            .values()
            .map(FeeRebateRecord::public_record)
            .collect::<Vec<_>>();
        let slashing_evidence_records = self
            .slashing_evidence
            .values()
            .map(SlashingEvidenceRecord::public_record)
            .collect::<Vec<_>>();
        let batches_records = self
            .batches
            .values()
            .map(SessionMarketBatchRecord::public_record)
            .collect::<Vec<_>>();
        let receipts_records = self
            .receipts
            .values()
            .map(SessionMarketReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let all_public_records = self.public_records().into_values().collect::<Vec<_>>();
        Roots {
            session_grant_root: public_record_root("SESSION_GRANT_ROOT", &session_grants_records),
            policy_proof_root: public_record_root("POLICY_PROOF_ROOT", &policy_proofs_records),
            paymaster_bid_root: public_record_root("PAYMASTER_BID_ROOT", &paymaster_bids_records),
            recovery_hook_root: public_record_root("RECOVERY_HOOK_ROOT", &recovery_hooks_records),
            allowance_root: public_record_root("ALLOWANCE_ROOT", &allowances_records),
            privacy_fence_root: public_record_root("PRIVACY_FENCE_ROOT", &privacy_fences_records),
            rebate_root: public_record_root("REBATE_ROOT", &rebates_records),
            slashing_evidence_root: public_record_root(
                "SLASHING_EVIDENCE_ROOT",
                &slashing_evidence_records,
            ),
            batch_root: public_record_root("BATCH_ROOT", &batches_records),
            receipt_root: public_record_root("RECEIPT_ROOT", &receipts_records),
            public_record_root: public_record_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-AA-SESSION-MARKET-PUBLIC-RECORDS",
                &all_public_records,
            ),
        }
    }
    pub fn public_records(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        records.insert("counters".to_string(), self.counters.public_record());
        for record in self.session_grants.values() {
            records.insert(
                format!("session_grant:{}", record.grant_id),
                record.public_record(),
            );
        }
        for record in self.policy_proofs.values() {
            records.insert(
                format!("policy_proof:{}", record.proof_id),
                record.public_record(),
            );
        }
        for record in self.paymaster_bids.values() {
            records.insert(
                format!("paymaster_bid:{}", record.bid_id),
                record.public_record(),
            );
        }
        for record in self.recovery_hooks.values() {
            records.insert(
                format!("recovery_hook:{}", record.hook_id),
                record.public_record(),
            );
        }
        for record in self.allowances.values() {
            records.insert(
                format!("allowance:{}", record.allowance_id),
                record.public_record(),
            );
        }
        for record in self.privacy_fences.values() {
            records.insert(
                format!("privacy_fence:{}", record.fence_id),
                record.public_record(),
            );
        }
        for record in self.rebates.values() {
            records.insert(
                format!("rebate:{}", record.rebate_id),
                record.public_record(),
            );
        }
        for record in self.slashing_evidence.values() {
            records.insert(
                format!("slashing_evidence:{}", record.evidence_id),
                record.public_record(),
            );
        }
        for record in self.batches.values() {
            records.insert(
                format!("batche:{}", record.batch_id),
                record.public_record(),
            );
        }
        for record in self.receipts.values() {
            records.insert(
                format!("receipt:{}", record.receipt_id),
                record.public_record(),
            );
        }
        records
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({"kind":"private_l2_pq_confidential_account_abstraction_session_market_runtime","chain_id":CHAIN_ID,"current_height":self.current_height,"config":self.config.public_record(),"counters":self.counters.public_record(),"roots":self.roots().public_record()})
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}
pub fn private_l2_pq_confidential_account_abstraction_session_market_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}
pub fn private_l2_pq_confidential_account_abstraction_session_market_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}
pub fn devnet() -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<State> {
    let config = Config::devnet();
    validate_config(&config)?;
    Ok(State::new(config))
}

pub fn deterministic_id(domain: &str, record: &Value) -> String {
    root_from_record(domain, record)
}
pub fn deterministic_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}
pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}
pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-AA-SESSION-MARKET-STATE-ROOT",
        record,
    )
}
pub fn empty_runtime_root() -> String {
    domain_hash("PRIVATE-L2-PQ-CONFIDENTIAL-AA-SESSION-MARKET-EMPTY", &[HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PROTOCOL_VERSION), HashPart::Str(CHAIN_ID)], 32)
}
pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_PROTOCOL_VERSION), HashPart::Str(CHAIN_ID), HashPart::Json(record)], 32)
}

fn validate_config(
    config: &Config,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("chain_id", &config.chain_id)?;
    ensure_non_empty("protocol_version", &config.protocol_version)?;
    ensure_non_empty("hash_suite", &config.hash_suite)?;
    ensure_non_empty("pq_auth_suite", &config.pq_auth_suite)?;
    ensure_bps("max_session_fee_bps", config.max_session_fee_bps)?;
    ensure_bps("max_paymaster_fee_bps", config.max_paymaster_fee_bps)?;
    ensure_bps("target_rebate_bps", config.target_rebate_bps)?;
    ensure_bps("slashing_penalty_bps", config.slashing_penalty_bps)?;
    if config.min_pq_security_bits < 128 {
        return Err("min_pq_security_bits must be at least 128".to_string());
    }
    if config.max_batch_items == 0 {
        return Err("max_batch_items must be positive".to_string());
    }
    Ok(())
}
fn validate_sealedsessiongrant_request(
    config: &Config,
    request: &SealedSessionGrantRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("account_commitment", &request.account_commitment)?;
    ensure_non_empty("session_key_commitment", &request.session_key_commitment)?;
    ensure_non_empty("sealed_grant_ciphertext", &request.sealed_grant_ciphertext)?;
    ensure_non_empty("grant_nullifier", &request.grant_nullifier)?;
    ensure_non_empty("policy_root", &request.policy_root)?;
    ensure_min_privacy(config, request.privacy_set_size)?;
    ensure_pq_security(config, request.pq_security_bits)?;
    ensure_future_height(
        "expires_at_height",
        request.expires_at_height,
        current_height,
    )?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_pqpolicyproof_request(
    config: &Config,
    request: &PqPolicyProofRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("policy_commitment", &request.policy_commitment)?;
    ensure_non_empty("proof_transcript_root", &request.proof_transcript_root)?;
    ensure_non_empty("proof_nullifier", &request.proof_nullifier)?;
    ensure_min_privacy(config, request.privacy_set_size)?;
    ensure_pq_security(config, request.pq_security_bits)?;
    ensure_bps("max_fee_bps", request.max_fee_bps)?;
    ensure_future_height(
        "expires_at_height",
        request.expires_at_height,
        current_height,
    )?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_paymastersponsorshipbid_request(
    config: &Config,
    request: &PaymasterSponsorshipBidRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("paymaster_commitment", &request.paymaster_commitment)?;
    ensure_non_empty(
        "sponsor_vault_commitment",
        &request.sponsor_vault_commitment,
    )?;
    ensure_non_empty("bid_nullifier", &request.bid_nullifier)?;
    ensure_bps("fee_bps", request.fee_bps)?;
    ensure_bps("rebate_bps", request.rebate_bps)?;
    ensure_min_privacy(config, request.privacy_set_size)?;
    ensure_pq_security(config, request.pq_security_bits)?;
    ensure_future_height(
        "expires_at_height",
        request.expires_at_height,
        current_height,
    )?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_smartaccountrecoveryhook_request(
    config: &Config,
    request: &SmartAccountRecoveryHookRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("account_commitment", &request.account_commitment)?;
    ensure_non_empty("guardian_policy_root", &request.guardian_policy_root)?;
    ensure_non_empty("recovery_nullifier", &request.recovery_nullifier)?;
    ensure_bps("threshold_weight_bps", request.threshold_weight_bps)?;
    ensure_min_privacy(config, request.privacy_set_size)?;
    ensure_pq_security(config, request.pq_security_bits)?;
    ensure_future_height(
        "expires_at_height",
        request.expires_at_height,
        current_height,
    )?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_contractcallallowance_request(
    config: &Config,
    request: &ContractCallAllowanceRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("contract_commitment", &request.contract_commitment)?;
    ensure_non_empty("selector_commitment", &request.selector_commitment)?;
    ensure_non_empty("asset_commitment", &request.asset_commitment)?;
    ensure_non_empty("allowance_nullifier", &request.allowance_nullifier)?;
    ensure_future_height(
        "expires_at_height",
        request.expires_at_height,
        current_height,
    )?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_privacyfence_request(
    config: &Config,
    request: &PrivacyFenceRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("fence_commitment", &request.fence_commitment)?;
    ensure_non_empty("fence_nullifier", &request.fence_nullifier)?;
    ensure_bps("leakage_score_bps", request.leakage_score_bps)?;
    ensure_future_height(
        "expires_at_height",
        request.expires_at_height,
        current_height,
    )?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_feerebate_request(
    config: &Config,
    request: &FeeRebateRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("paymaster_bid_id", &request.paymaster_bid_id)?;
    ensure_non_empty("recipient_commitment", &request.recipient_commitment)?;
    ensure_non_empty("rebate_nullifier", &request.rebate_nullifier)?;
    ensure_bps("rebate_bps", request.rebate_bps)?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_slashingevidence_request(
    config: &Config,
    request: &SlashingEvidenceRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("target_id", &request.target_id)?;
    ensure_non_empty("reporter_commitment", &request.reporter_commitment)?;
    ensure_non_empty("evidence_root", &request.evidence_root)?;
    ensure_non_empty("evidence_nullifier", &request.evidence_nullifier)?;
    ensure_bps("penalty_bps", request.penalty_bps)?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn validate_sessionmarketbatch_request(
    config: &Config,
    request: &SessionMarketBatchRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("batch_root", &request.batch_root)?;
    ensure_non_empty("settlement_root", &request.settlement_root)?;
    ensure_min_privacy(config, request.privacy_set_size)?;
    ensure_pq_security(config, request.pq_security_bits)?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    if request.grant_ids.len() > config.max_batch_items {
        return Err("batch exceeds max_batch_items".to_string());
    }
    Ok(())
}
fn validate_sessionmarketreceipt_request(
    config: &Config,
    request: &SessionMarketReceiptRequest,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    ensure_non_empty("subject_id", &request.subject_id)?;
    ensure_non_empty("receipt_root", &request.receipt_root)?;
    ensure_non_empty("fee_debit_root", &request.fee_debit_root)?;
    ensure_non_empty("rebate_root", &request.rebate_root)?;
    ensure_non_empty("metadata_commitment", &request.metadata_commitment)?;
    Ok(())
}
fn ensure_capacity(
    len: usize,
    max: usize,
    label: &str,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    if len >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}
fn ensure_unique<T>(
    map: &BTreeMap<String, T>,
    id: &str,
    label: &str,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    if map.contains_key(id) {
        Err(format!("duplicate {label} {id}"))
    } else {
        Ok(())
    }
}
fn ensure_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
fn ensure_future_height(
    label: &str,
    height: u64,
    current_height: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    if height <= current_height {
        Err(format!("{label} must be greater than current_height"))
    } else {
        Ok(())
    }
}
fn ensure_bps(
    label: &str,
    value: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNT_ABSTRACTION_SESSION_MARKET_RUNTIME_MAX_BPS {
        Err(format!("{label} exceeds max bps"))
    } else {
        Ok(())
    }
}
fn ensure_min_privacy(
    config: &Config,
    value: u64,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    if value < config.min_privacy_set_size {
        Err("privacy set below configured minimum".to_string())
    } else {
        Ok(())
    }
}
fn ensure_pq_security(
    config: &Config,
    value: u16,
) -> PrivateL2PqConfidentialAccountAbstractionSessionMarketRuntimeResult<()> {
    if value < config.min_pq_security_bits {
        Err("pq security below configured minimum".to_string())
    } else {
        Ok(())
    }
}

pub fn invariant_anchor_001(state: &State) -> Value {
    json!({"invariant":"anchor_001","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_002(state: &State) -> Value {
    json!({"invariant":"anchor_002","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_003(state: &State) -> Value {
    json!({"invariant":"anchor_003","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_004(state: &State) -> Value {
    json!({"invariant":"anchor_004","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_005(state: &State) -> Value {
    json!({"invariant":"anchor_005","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_006(state: &State) -> Value {
    json!({"invariant":"anchor_006","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_007(state: &State) -> Value {
    json!({"invariant":"anchor_007","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_008(state: &State) -> Value {
    json!({"invariant":"anchor_008","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_009(state: &State) -> Value {
    json!({"invariant":"anchor_009","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_010(state: &State) -> Value {
    json!({"invariant":"anchor_010","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_011(state: &State) -> Value {
    json!({"invariant":"anchor_011","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_012(state: &State) -> Value {
    json!({"invariant":"anchor_012","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_013(state: &State) -> Value {
    json!({"invariant":"anchor_013","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_014(state: &State) -> Value {
    json!({"invariant":"anchor_014","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_015(state: &State) -> Value {
    json!({"invariant":"anchor_015","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_016(state: &State) -> Value {
    json!({"invariant":"anchor_016","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_017(state: &State) -> Value {
    json!({"invariant":"anchor_017","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_018(state: &State) -> Value {
    json!({"invariant":"anchor_018","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_019(state: &State) -> Value {
    json!({"invariant":"anchor_019","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_020(state: &State) -> Value {
    json!({"invariant":"anchor_020","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_021(state: &State) -> Value {
    json!({"invariant":"anchor_021","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_022(state: &State) -> Value {
    json!({"invariant":"anchor_022","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_023(state: &State) -> Value {
    json!({"invariant":"anchor_023","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_024(state: &State) -> Value {
    json!({"invariant":"anchor_024","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_025(state: &State) -> Value {
    json!({"invariant":"anchor_025","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_026(state: &State) -> Value {
    json!({"invariant":"anchor_026","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_027(state: &State) -> Value {
    json!({"invariant":"anchor_027","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_028(state: &State) -> Value {
    json!({"invariant":"anchor_028","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_029(state: &State) -> Value {
    json!({"invariant":"anchor_029","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_030(state: &State) -> Value {
    json!({"invariant":"anchor_030","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_031(state: &State) -> Value {
    json!({"invariant":"anchor_031","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_032(state: &State) -> Value {
    json!({"invariant":"anchor_032","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_033(state: &State) -> Value {
    json!({"invariant":"anchor_033","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_034(state: &State) -> Value {
    json!({"invariant":"anchor_034","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_035(state: &State) -> Value {
    json!({"invariant":"anchor_035","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_036(state: &State) -> Value {
    json!({"invariant":"anchor_036","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_037(state: &State) -> Value {
    json!({"invariant":"anchor_037","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_038(state: &State) -> Value {
    json!({"invariant":"anchor_038","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_039(state: &State) -> Value {
    json!({"invariant":"anchor_039","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_040(state: &State) -> Value {
    json!({"invariant":"anchor_040","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_041(state: &State) -> Value {
    json!({"invariant":"anchor_041","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_042(state: &State) -> Value {
    json!({"invariant":"anchor_042","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_043(state: &State) -> Value {
    json!({"invariant":"anchor_043","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_044(state: &State) -> Value {
    json!({"invariant":"anchor_044","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_045(state: &State) -> Value {
    json!({"invariant":"anchor_045","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_046(state: &State) -> Value {
    json!({"invariant":"anchor_046","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_047(state: &State) -> Value {
    json!({"invariant":"anchor_047","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_048(state: &State) -> Value {
    json!({"invariant":"anchor_048","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_049(state: &State) -> Value {
    json!({"invariant":"anchor_049","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_050(state: &State) -> Value {
    json!({"invariant":"anchor_050","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_051(state: &State) -> Value {
    json!({"invariant":"anchor_051","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_052(state: &State) -> Value {
    json!({"invariant":"anchor_052","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_053(state: &State) -> Value {
    json!({"invariant":"anchor_053","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_054(state: &State) -> Value {
    json!({"invariant":"anchor_054","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_055(state: &State) -> Value {
    json!({"invariant":"anchor_055","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_056(state: &State) -> Value {
    json!({"invariant":"anchor_056","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_057(state: &State) -> Value {
    json!({"invariant":"anchor_057","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_058(state: &State) -> Value {
    json!({"invariant":"anchor_058","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_059(state: &State) -> Value {
    json!({"invariant":"anchor_059","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_060(state: &State) -> Value {
    json!({"invariant":"anchor_060","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_061(state: &State) -> Value {
    json!({"invariant":"anchor_061","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_062(state: &State) -> Value {
    json!({"invariant":"anchor_062","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_063(state: &State) -> Value {
    json!({"invariant":"anchor_063","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_064(state: &State) -> Value {
    json!({"invariant":"anchor_064","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_065(state: &State) -> Value {
    json!({"invariant":"anchor_065","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_066(state: &State) -> Value {
    json!({"invariant":"anchor_066","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_067(state: &State) -> Value {
    json!({"invariant":"anchor_067","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_068(state: &State) -> Value {
    json!({"invariant":"anchor_068","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_069(state: &State) -> Value {
    json!({"invariant":"anchor_069","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_070(state: &State) -> Value {
    json!({"invariant":"anchor_070","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_071(state: &State) -> Value {
    json!({"invariant":"anchor_071","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_072(state: &State) -> Value {
    json!({"invariant":"anchor_072","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_073(state: &State) -> Value {
    json!({"invariant":"anchor_073","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_074(state: &State) -> Value {
    json!({"invariant":"anchor_074","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_075(state: &State) -> Value {
    json!({"invariant":"anchor_075","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_076(state: &State) -> Value {
    json!({"invariant":"anchor_076","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_077(state: &State) -> Value {
    json!({"invariant":"anchor_077","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_078(state: &State) -> Value {
    json!({"invariant":"anchor_078","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_079(state: &State) -> Value {
    json!({"invariant":"anchor_079","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_080(state: &State) -> Value {
    json!({"invariant":"anchor_080","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_081(state: &State) -> Value {
    json!({"invariant":"anchor_081","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_082(state: &State) -> Value {
    json!({"invariant":"anchor_082","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_083(state: &State) -> Value {
    json!({"invariant":"anchor_083","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_084(state: &State) -> Value {
    json!({"invariant":"anchor_084","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_085(state: &State) -> Value {
    json!({"invariant":"anchor_085","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_086(state: &State) -> Value {
    json!({"invariant":"anchor_086","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_087(state: &State) -> Value {
    json!({"invariant":"anchor_087","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_088(state: &State) -> Value {
    json!({"invariant":"anchor_088","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_089(state: &State) -> Value {
    json!({"invariant":"anchor_089","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_090(state: &State) -> Value {
    json!({"invariant":"anchor_090","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_091(state: &State) -> Value {
    json!({"invariant":"anchor_091","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_092(state: &State) -> Value {
    json!({"invariant":"anchor_092","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_093(state: &State) -> Value {
    json!({"invariant":"anchor_093","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_094(state: &State) -> Value {
    json!({"invariant":"anchor_094","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_095(state: &State) -> Value {
    json!({"invariant":"anchor_095","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_096(state: &State) -> Value {
    json!({"invariant":"anchor_096","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_097(state: &State) -> Value {
    json!({"invariant":"anchor_097","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_098(state: &State) -> Value {
    json!({"invariant":"anchor_098","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_099(state: &State) -> Value {
    json!({"invariant":"anchor_099","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_100(state: &State) -> Value {
    json!({"invariant":"anchor_100","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_101(state: &State) -> Value {
    json!({"invariant":"anchor_101","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_102(state: &State) -> Value {
    json!({"invariant":"anchor_102","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_103(state: &State) -> Value {
    json!({"invariant":"anchor_103","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_104(state: &State) -> Value {
    json!({"invariant":"anchor_104","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_105(state: &State) -> Value {
    json!({"invariant":"anchor_105","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_106(state: &State) -> Value {
    json!({"invariant":"anchor_106","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_107(state: &State) -> Value {
    json!({"invariant":"anchor_107","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_108(state: &State) -> Value {
    json!({"invariant":"anchor_108","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_109(state: &State) -> Value {
    json!({"invariant":"anchor_109","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_110(state: &State) -> Value {
    json!({"invariant":"anchor_110","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_111(state: &State) -> Value {
    json!({"invariant":"anchor_111","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_112(state: &State) -> Value {
    json!({"invariant":"anchor_112","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_113(state: &State) -> Value {
    json!({"invariant":"anchor_113","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_114(state: &State) -> Value {
    json!({"invariant":"anchor_114","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_115(state: &State) -> Value {
    json!({"invariant":"anchor_115","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_116(state: &State) -> Value {
    json!({"invariant":"anchor_116","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_117(state: &State) -> Value {
    json!({"invariant":"anchor_117","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_118(state: &State) -> Value {
    json!({"invariant":"anchor_118","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_119(state: &State) -> Value {
    json!({"invariant":"anchor_119","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_120(state: &State) -> Value {
    json!({"invariant":"anchor_120","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_121(state: &State) -> Value {
    json!({"invariant":"anchor_121","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_122(state: &State) -> Value {
    json!({"invariant":"anchor_122","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_123(state: &State) -> Value {
    json!({"invariant":"anchor_123","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_124(state: &State) -> Value {
    json!({"invariant":"anchor_124","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_125(state: &State) -> Value {
    json!({"invariant":"anchor_125","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_126(state: &State) -> Value {
    json!({"invariant":"anchor_126","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_127(state: &State) -> Value {
    json!({"invariant":"anchor_127","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_128(state: &State) -> Value {
    json!({"invariant":"anchor_128","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_129(state: &State) -> Value {
    json!({"invariant":"anchor_129","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_130(state: &State) -> Value {
    json!({"invariant":"anchor_130","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_131(state: &State) -> Value {
    json!({"invariant":"anchor_131","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_132(state: &State) -> Value {
    json!({"invariant":"anchor_132","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_133(state: &State) -> Value {
    json!({"invariant":"anchor_133","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_134(state: &State) -> Value {
    json!({"invariant":"anchor_134","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_135(state: &State) -> Value {
    json!({"invariant":"anchor_135","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_136(state: &State) -> Value {
    json!({"invariant":"anchor_136","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_137(state: &State) -> Value {
    json!({"invariant":"anchor_137","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_138(state: &State) -> Value {
    json!({"invariant":"anchor_138","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_139(state: &State) -> Value {
    json!({"invariant":"anchor_139","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_140(state: &State) -> Value {
    json!({"invariant":"anchor_140","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_141(state: &State) -> Value {
    json!({"invariant":"anchor_141","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_142(state: &State) -> Value {
    json!({"invariant":"anchor_142","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_143(state: &State) -> Value {
    json!({"invariant":"anchor_143","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_144(state: &State) -> Value {
    json!({"invariant":"anchor_144","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_145(state: &State) -> Value {
    json!({"invariant":"anchor_145","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_146(state: &State) -> Value {
    json!({"invariant":"anchor_146","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_147(state: &State) -> Value {
    json!({"invariant":"anchor_147","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_148(state: &State) -> Value {
    json!({"invariant":"anchor_148","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_149(state: &State) -> Value {
    json!({"invariant":"anchor_149","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_150(state: &State) -> Value {
    json!({"invariant":"anchor_150","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_151(state: &State) -> Value {
    json!({"invariant":"anchor_151","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_152(state: &State) -> Value {
    json!({"invariant":"anchor_152","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_153(state: &State) -> Value {
    json!({"invariant":"anchor_153","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_154(state: &State) -> Value {
    json!({"invariant":"anchor_154","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_155(state: &State) -> Value {
    json!({"invariant":"anchor_155","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_156(state: &State) -> Value {
    json!({"invariant":"anchor_156","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_157(state: &State) -> Value {
    json!({"invariant":"anchor_157","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_158(state: &State) -> Value {
    json!({"invariant":"anchor_158","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_159(state: &State) -> Value {
    json!({"invariant":"anchor_159","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_160(state: &State) -> Value {
    json!({"invariant":"anchor_160","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_161(state: &State) -> Value {
    json!({"invariant":"anchor_161","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_162(state: &State) -> Value {
    json!({"invariant":"anchor_162","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_163(state: &State) -> Value {
    json!({"invariant":"anchor_163","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_164(state: &State) -> Value {
    json!({"invariant":"anchor_164","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_165(state: &State) -> Value {
    json!({"invariant":"anchor_165","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_166(state: &State) -> Value {
    json!({"invariant":"anchor_166","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_167(state: &State) -> Value {
    json!({"invariant":"anchor_167","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_168(state: &State) -> Value {
    json!({"invariant":"anchor_168","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_169(state: &State) -> Value {
    json!({"invariant":"anchor_169","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_170(state: &State) -> Value {
    json!({"invariant":"anchor_170","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_171(state: &State) -> Value {
    json!({"invariant":"anchor_171","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_172(state: &State) -> Value {
    json!({"invariant":"anchor_172","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_173(state: &State) -> Value {
    json!({"invariant":"anchor_173","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_174(state: &State) -> Value {
    json!({"invariant":"anchor_174","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_175(state: &State) -> Value {
    json!({"invariant":"anchor_175","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_176(state: &State) -> Value {
    json!({"invariant":"anchor_176","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_177(state: &State) -> Value {
    json!({"invariant":"anchor_177","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_178(state: &State) -> Value {
    json!({"invariant":"anchor_178","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_179(state: &State) -> Value {
    json!({"invariant":"anchor_179","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_180(state: &State) -> Value {
    json!({"invariant":"anchor_180","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_181(state: &State) -> Value {
    json!({"invariant":"anchor_181","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_182(state: &State) -> Value {
    json!({"invariant":"anchor_182","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_183(state: &State) -> Value {
    json!({"invariant":"anchor_183","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_184(state: &State) -> Value {
    json!({"invariant":"anchor_184","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_185(state: &State) -> Value {
    json!({"invariant":"anchor_185","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_186(state: &State) -> Value {
    json!({"invariant":"anchor_186","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_187(state: &State) -> Value {
    json!({"invariant":"anchor_187","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_188(state: &State) -> Value {
    json!({"invariant":"anchor_188","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_189(state: &State) -> Value {
    json!({"invariant":"anchor_189","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_190(state: &State) -> Value {
    json!({"invariant":"anchor_190","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_191(state: &State) -> Value {
    json!({"invariant":"anchor_191","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_192(state: &State) -> Value {
    json!({"invariant":"anchor_192","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_193(state: &State) -> Value {
    json!({"invariant":"anchor_193","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_194(state: &State) -> Value {
    json!({"invariant":"anchor_194","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_195(state: &State) -> Value {
    json!({"invariant":"anchor_195","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_196(state: &State) -> Value {
    json!({"invariant":"anchor_196","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_197(state: &State) -> Value {
    json!({"invariant":"anchor_197","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_198(state: &State) -> Value {
    json!({"invariant":"anchor_198","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_199(state: &State) -> Value {
    json!({"invariant":"anchor_199","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_200(state: &State) -> Value {
    json!({"invariant":"anchor_200","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_201(state: &State) -> Value {
    json!({"invariant":"anchor_201","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_202(state: &State) -> Value {
    json!({"invariant":"anchor_202","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_203(state: &State) -> Value {
    json!({"invariant":"anchor_203","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_204(state: &State) -> Value {
    json!({"invariant":"anchor_204","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_205(state: &State) -> Value {
    json!({"invariant":"anchor_205","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_206(state: &State) -> Value {
    json!({"invariant":"anchor_206","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_207(state: &State) -> Value {
    json!({"invariant":"anchor_207","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_208(state: &State) -> Value {
    json!({"invariant":"anchor_208","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_209(state: &State) -> Value {
    json!({"invariant":"anchor_209","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_210(state: &State) -> Value {
    json!({"invariant":"anchor_210","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_211(state: &State) -> Value {
    json!({"invariant":"anchor_211","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_212(state: &State) -> Value {
    json!({"invariant":"anchor_212","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_213(state: &State) -> Value {
    json!({"invariant":"anchor_213","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_214(state: &State) -> Value {
    json!({"invariant":"anchor_214","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_215(state: &State) -> Value {
    json!({"invariant":"anchor_215","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_216(state: &State) -> Value {
    json!({"invariant":"anchor_216","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_217(state: &State) -> Value {
    json!({"invariant":"anchor_217","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_218(state: &State) -> Value {
    json!({"invariant":"anchor_218","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_219(state: &State) -> Value {
    json!({"invariant":"anchor_219","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_220(state: &State) -> Value {
    json!({"invariant":"anchor_220","state_root":state.state_root(),"public_record_root":state.roots().public_record_root,"height":state.current_height})
}

pub fn invariant_anchor_221(state: &State) -> Value {
    json!({"invariant":"anchor_221","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_222(state: &State) -> Value {
    json!({"invariant":"anchor_222","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_223(state: &State) -> Value {
    json!({"invariant":"anchor_223","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_224(state: &State) -> Value {
    json!({"invariant":"anchor_224","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_225(state: &State) -> Value {
    json!({"invariant":"anchor_225","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_226(state: &State) -> Value {
    json!({"invariant":"anchor_226","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_227(state: &State) -> Value {
    json!({"invariant":"anchor_227","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_228(state: &State) -> Value {
    json!({"invariant":"anchor_228","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_229(state: &State) -> Value {
    json!({"invariant":"anchor_229","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_230(state: &State) -> Value {
    json!({"invariant":"anchor_230","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_231(state: &State) -> Value {
    json!({"invariant":"anchor_231","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_232(state: &State) -> Value {
    json!({"invariant":"anchor_232","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_233(state: &State) -> Value {
    json!({"invariant":"anchor_233","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_234(state: &State) -> Value {
    json!({"invariant":"anchor_234","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_235(state: &State) -> Value {
    json!({"invariant":"anchor_235","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_236(state: &State) -> Value {
    json!({"invariant":"anchor_236","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_237(state: &State) -> Value {
    json!({"invariant":"anchor_237","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_238(state: &State) -> Value {
    json!({"invariant":"anchor_238","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_239(state: &State) -> Value {
    json!({"invariant":"anchor_239","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_240(state: &State) -> Value {
    json!({"invariant":"anchor_240","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_241(state: &State) -> Value {
    json!({"invariant":"anchor_241","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_242(state: &State) -> Value {
    json!({"invariant":"anchor_242","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_243(state: &State) -> Value {
    json!({"invariant":"anchor_243","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_244(state: &State) -> Value {
    json!({"invariant":"anchor_244","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_245(state: &State) -> Value {
    json!({"invariant":"anchor_245","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}

pub fn invariant_anchor_246(state: &State) -> Value {
    json!({"invariant":"anchor_246","session_grant_root":state.roots().session_grant_root,"policy_proof_root":state.roots().policy_proof_root,"paymaster_bid_root":state.roots().paymaster_bid_root})
}
