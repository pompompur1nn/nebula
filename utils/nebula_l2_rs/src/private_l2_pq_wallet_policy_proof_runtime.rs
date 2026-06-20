use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqWalletPolicyProofRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-wallet-policy-proof-runtime-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-wallet-policy-proof-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_POLICY_SCHEME: &str =
    "shielded-wallet-policy-registration-root-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SPEND_PROOF_SCHEME: &str =
    "pq-shielded-wallet-spend-authorization-proof-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SESSION_PROOF_SCHEME: &str =
    "pq-private-wallet-session-authorization-proof-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-wallet-policy-proof-sponsor-reservation-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_BATCH_SCHEME: &str =
    "shielded-wallet-policy-proof-recursive-batch-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_RECOVERY_SCHEME: &str =
    "wallet-policy-proof-recovery-receipt-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_VIOLATION_SCHEME: &str =
    "wallet-policy-proof-violation-receipt-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_REBATE_SCHEME: &str =
    "wallet-policy-proof-low-fee-rebate-receipt-v1";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEVNET_HEIGHT: u64 = 812_000;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_POLICIES: usize = 524_288;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPEND_PROOFS: usize = 8_388_608;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SESSION_PROOFS: usize = 8_388_608;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS: u64 = 43_200;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SPEND_PROOF_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SESSION_PROOF_TTL_BLOCKS: u64 = 360;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SESSION_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPEND_FEE_BPS: u64 = 10;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SESSION_FEE_BPS: u64 = 6;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_DAILY_SPEND_LIMIT_UNITS: u128 =
    10_000_000_000_000;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SESSION_SPEND_LIMIT_UNITS: u128 =
    1_000_000_000_000;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_AUTHORIZATIONS_PER_SESSION: u64 =
    256;
pub const PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletPolicyKind {
    RetailShielded,
    HighValueVault,
    TradingHotWallet,
    BridgeOperator,
    GovernanceDelegate,
    RecoveryOnly,
    SpendingSandbox,
    SponsorManaged,
}

impl WalletPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailShielded => "retail_shielded",
            Self::HighValueVault => "high_value_vault",
            Self::TradingHotWallet => "trading_hot_wallet",
            Self::BridgeOperator => "bridge_operator",
            Self::GovernanceDelegate => "governance_delegate",
            Self::RecoveryOnly => "recovery_only",
            Self::SpendingSandbox => "spending_sandbox",
            Self::SponsorManaged => "sponsor_managed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletPolicyStatus {
    Registered,
    Active,
    GracePeriod,
    Rotating,
    Paused,
    Frozen,
    Revoked,
    Retired,
    Slashed,
}

impl WalletPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Revoked => "revoked",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_spend_proofs(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod | Self::Rotating)
    }

    pub fn accepts_session_proofs(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }

    pub fn accepts_recovery_receipts(self) -> bool {
        matches!(
            self,
            Self::Active | Self::GracePeriod | Self::Rotating | Self::Paused | Self::Frozen
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendLane {
    WalletTransfer,
    ConfidentialSwap,
    DefiDeposit,
    DefiWithdraw,
    BridgeOut,
    BridgeIn,
    GovernanceVote,
    RecoveryMove,
    SponsorRebate,
    EmergencyEscape,
}

impl SpendLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::DefiDeposit => "defi_deposit",
            Self::DefiWithdraw => "defi_withdraw",
            Self::BridgeOut => "bridge_out",
            Self::BridgeIn => "bridge_in",
            Self::GovernanceVote => "governance_vote",
            Self::RecoveryMove => "recovery_move",
            Self::SponsorRebate => "sponsor_rebate",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendProofKind {
    AmountLimit,
    VelocityLimit,
    DestinationAllowlist,
    DestinationDenylist,
    AssetAllowlist,
    SessionDelegation,
    RecoveryAuthorization,
    BridgePolicy,
    SponsorBudget,
    EmergencyPolicy,
}

impl SpendProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmountLimit => "amount_limit",
            Self::VelocityLimit => "velocity_limit",
            Self::DestinationAllowlist => "destination_allowlist",
            Self::DestinationDenylist => "destination_denylist",
            Self::AssetAllowlist => "asset_allowlist",
            Self::SessionDelegation => "session_delegation",
            Self::RecoveryAuthorization => "recovery_authorization",
            Self::BridgePolicy => "bridge_policy",
            Self::SponsorBudget => "sponsor_budget",
            Self::EmergencyPolicy => "emergency_policy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionProofKind {
    FastSpendSession,
    ContractSession,
    PaymentChannelSession,
    DelegatedTraderSession,
    RecoverySession,
    SponsorSession,
    ViewOnlySession,
    EmergencySession,
}

impl SessionProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastSpendSession => "fast_spend_session",
            Self::ContractSession => "contract_session",
            Self::PaymentChannelSession => "payment_channel_session",
            Self::DelegatedTraderSession => "delegated_trader_session",
            Self::RecoverySession => "recovery_session",
            Self::SponsorSession => "sponsor_session",
            Self::ViewOnlySession => "view_only_session",
            Self::EmergencySession => "emergency_session",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    SponsorReserved,
    Batched,
    Accepted,
    Settled,
    Rejected,
    Expired,
    Revoked,
    Slashed,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Batched => "batched",
            Self::Accepted => "accepted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::SponsorReserved | Self::Batched | Self::Accepted
        )
    }

    pub fn sponsorable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::SponsorReserved | Self::Accepted
        )
    }

    pub fn receiptable(self) -> bool {
        matches!(self, Self::Batched | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Opened,
    Authorized,
    FastPath,
    Settling,
    Settled,
    Revoked,
    Expired,
    Slashed,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Authorized => "authorized",
            Self::FastPath => "fast_path",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_spends(self) -> bool {
        matches!(self, Self::Opened | Self::Authorized | Self::FastPath)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Matched,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Cancelled,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::RebateQueued => "rebate_queued",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Reserved | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProofBatchStatus {
    Proposed,
    Proving,
    Proven,
    Settled,
    PartiallySettled,
    Disputed,
    Expired,
    Cancelled,
    Slashed,
}

impl PolicyProofBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Proving => "proving",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Proposed | Self::Proving | Self::Proven)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    PolicyRegistered,
    PolicyActivated,
    PolicyRotated,
    SpendAuthorized,
    SpendRejected,
    SessionOpened,
    SessionRevoked,
    SponsorReserved,
    BatchSettled,
    RecoveryAccepted,
    RecoveryRejected,
    ViolationProven,
    RebatePaid,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyRegistered => "policy_registered",
            Self::PolicyActivated => "policy_activated",
            Self::PolicyRotated => "policy_rotated",
            Self::SpendAuthorized => "spend_authorized",
            Self::SpendRejected => "spend_rejected",
            Self::SessionOpened => "session_opened",
            Self::SessionRevoked => "session_revoked",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchSettled => "batch_settled",
            Self::RecoveryAccepted => "recovery_accepted",
            Self::RecoveryRejected => "recovery_rejected",
            Self::ViolationProven => "violation_proven",
            Self::RebatePaid => "rebate_paid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionKind {
    RotateSpendKey,
    RotateViewKey,
    FreezeWallet,
    UnfreezeWallet,
    ResetSessionKeys,
    ReplacePolicyRoot,
    EmergencyEscape,
    SponsorMigration,
}

impl RecoveryActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RotateSpendKey => "rotate_spend_key",
            Self::RotateViewKey => "rotate_view_key",
            Self::FreezeWallet => "freeze_wallet",
            Self::UnfreezeWallet => "unfreeze_wallet",
            Self::ResetSessionKeys => "reset_session_keys",
            Self::ReplacePolicyRoot => "replace_policy_root",
            Self::EmergencyEscape => "emergency_escape",
            Self::SponsorMigration => "sponsor_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    SpendLimitExceeded,
    VelocityLimitExceeded,
    InvalidDestination,
    InvalidAsset,
    ReplayNullifier,
    SessionScopeExceeded,
    ExpiredProof,
    SponsorFeeExceeded,
    InvalidPqAuthorization,
    RecoveryPolicyMismatch,
}

impl ViolationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendLimitExceeded => "spend_limit_exceeded",
            Self::VelocityLimitExceeded => "velocity_limit_exceeded",
            Self::InvalidDestination => "invalid_destination",
            Self::InvalidAsset => "invalid_asset",
            Self::ReplayNullifier => "replay_nullifier",
            Self::SessionScopeExceeded => "session_scope_exceeded",
            Self::ExpiredProof => "expired_proof",
            Self::SponsorFeeExceeded => "sponsor_fee_exceeded",
            Self::InvalidPqAuthorization => "invalid_pq_authorization",
            Self::RecoveryPolicyMismatch => "recovery_policy_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub policy_scheme: String,
    pub spend_proof_scheme: String,
    pub session_proof_scheme: String,
    pub sponsor_scheme: String,
    pub batch_scheme: String,
    pub recovery_scheme: String,
    pub violation_scheme: String,
    pub rebate_scheme: String,
    pub fee_asset_id: String,
    pub max_policies: usize,
    pub max_spend_proofs: usize,
    pub max_session_proofs: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_batch_items: usize,
    pub policy_ttl_blocks: u64,
    pub spend_proof_ttl_blocks: u64,
    pub session_proof_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub session_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_spend_fee_bps: u64,
    pub max_session_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_daily_spend_limit_units: u128,
    pub max_session_spend_limit_units: u128,
    pub max_authorizations_per_session: u64,
    pub require_pq_authorization: bool,
    pub require_replay_fence: bool,
    pub allow_low_fee_sponsors: bool,
    pub allow_fast_sessions: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SCHEMA_VERSION,
            l2_network: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_L2_NETWORK.to_string(),
            monero_network: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            devnet_height: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PQ_AUTH_SUITE.to_string(),
            policy_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_POLICY_SCHEME.to_string(),
            spend_proof_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SPEND_PROOF_SCHEME
                .to_string(),
            session_proof_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SESSION_PROOF_SCHEME
                .to_string(),
            sponsor_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SPONSOR_SCHEME.to_string(),
            batch_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_BATCH_SCHEME.to_string(),
            recovery_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_RECOVERY_SCHEME.to_string(),
            violation_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_VIOLATION_SCHEME
                .to_string(),
            rebate_scheme: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_REBATE_SCHEME.to_string(),
            fee_asset_id: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            max_policies: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_POLICIES,
            max_spend_proofs: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPEND_PROOFS,
            max_session_proofs:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SESSION_PROOFS,
            max_sponsor_reservations:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_REBATES,
            max_batch_items: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            policy_ttl_blocks: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS,
            spend_proof_ttl_blocks:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SPEND_PROOF_TTL_BLOCKS,
            session_proof_ttl_blocks:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SESSION_PROOF_TTL_BLOCKS,
            sponsor_ttl_blocks:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            session_privacy_set_size:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_SESSION_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_spend_fee_bps: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPEND_FEE_BPS,
            max_session_fee_bps:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SESSION_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            max_daily_spend_limit_units:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_DAILY_SPEND_LIMIT_UNITS,
            max_session_spend_limit_units:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_SESSION_SPEND_LIMIT_UNITS,
            max_authorizations_per_session:
                PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_DEFAULT_MAX_AUTHORIZATIONS_PER_SESSION,
            require_pq_authorization: true,
            require_replay_fence: true,
            allow_low_fee_sponsors: true,
            allow_fast_sessions: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policies_registered: u64,
    pub policies_activated: u64,
    pub policies_rotated: u64,
    pub policies_paused: u64,
    pub policies_frozen: u64,
    pub policies_revoked: u64,
    pub policies_expired: u64,
    pub spend_proofs_submitted: u64,
    pub spend_proofs_accepted: u64,
    pub spend_proofs_rejected: u64,
    pub spend_proofs_expired: u64,
    pub session_proofs_opened: u64,
    pub session_proofs_authorized: u64,
    pub session_proofs_revoked: u64,
    pub session_proofs_expired: u64,
    pub sponsor_reservations_created: u64,
    pub sponsor_reservations_consumed: u64,
    pub sponsor_reservations_refunded: u64,
    pub sponsor_reservations_expired: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub receipts_published: u64,
    pub recovery_receipts_published: u64,
    pub violation_receipts_published: u64,
    pub rebates_published: u64,
    pub replay_rejections: u64,
    pub consumed_nullifiers: u64,
    pub total_authorized_amount_units: u128,
    pub total_reserved_fee_units: u128,
    pub total_rebate_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub policy_root: String,
    pub spend_proof_root: String,
    pub session_proof_root: String,
    pub sponsor_reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub recovery_receipt_root: String,
    pub violation_receipt_root: String,
    pub rebate_root: String,
    pub replay_nullifier_root: String,
    pub spend_nullifier_root: String,
    pub session_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterShieldedWalletPolicyRequest {
    pub policy_kind: WalletPolicyKind,
    pub account_commitment: String,
    pub wallet_policy_root: String,
    pub spend_limit_root: String,
    pub velocity_limit_root: String,
    pub destination_policy_root: String,
    pub asset_policy_root: String,
    pub recovery_policy_root: String,
    pub session_policy_root: String,
    pub sponsor_policy_root: String,
    pub pq_public_key_root: String,
    pub view_key_commitment_root: String,
    pub policy_nonce: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub daily_spend_limit_units: u128,
    pub session_spend_limit_units: u128,
    pub max_spend_fee_bps: u64,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl RegisterShieldedWalletPolicyRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedWalletPolicyRecord {
    pub policy_id: String,
    pub status: WalletPolicyStatus,
    pub request: RegisterShieldedWalletPolicyRequest,
    pub policy_root: String,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
    pub activation_receipt_root: String,
    pub current_session_nonce_root: String,
    pub spent_amount_window_root: String,
    pub sponsor_budget_root: String,
}

impl ShieldedWalletPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPqSpendAuthorizationProofRequest {
    pub policy_id: String,
    pub proof_kind: SpendProofKind,
    pub spend_lane: SpendLane,
    pub account_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub amount_upper_bound_units: u128,
    pub destination_commitment_root: String,
    pub spend_limit_witness_root: String,
    pub velocity_witness_root: String,
    pub membership_witness_root: String,
    pub encrypted_spend_payload_root: String,
    pub pq_authorization_root: String,
    pub zk_policy_proof_root: String,
    pub nullifier: String,
    pub replay_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitPqSpendAuthorizationProofRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSpendAuthorizationProofRecord {
    pub proof_id: String,
    pub status: ProofStatus,
    pub request: SubmitPqSpendAuthorizationProofRequest,
    pub proof_root: String,
    pub sponsor_reservation_id: String,
    pub batch_id: String,
    pub submitted_at_height: u64,
    pub updated_at_height: u64,
}

impl PqSpendAuthorizationProofRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPrivateSessionProofRequest {
    pub policy_id: String,
    pub session_kind: SessionProofKind,
    pub account_commitment: String,
    pub session_key_commitment: String,
    pub session_scope_root: String,
    pub allowed_lane_root: String,
    pub allowed_asset_root: String,
    pub spend_limit_root: String,
    pub expiry_nullifier: String,
    pub replay_nullifier: String,
    pub encrypted_session_payload_root: String,
    pub pq_handshake_root: String,
    pub zk_session_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub session_spend_limit_units: u128,
    pub max_authorizations: u64,
    pub max_session_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl OpenPrivateSessionProofRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSessionProofRecord {
    pub session_id: String,
    pub status: SessionStatus,
    pub request: OpenPrivateSessionProofRequest,
    pub session_root: String,
    pub authorized_spend_count: u64,
    pub authorized_amount_units: u128,
    pub sponsor_reservation_id: String,
    pub batch_id: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl PrivateSessionProofRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLowFeeSponsorRequest {
    pub target_id: String,
    pub target_kind: String,
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub fee_credit_root: String,
    pub refund_commitment_root: String,
    pub route_nullifier: String,
    pub reserved_fee_units: u128,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub pq_authorization_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSponsorReservationRecord {
    pub reservation_id: String,
    pub status: SponsorReservationStatus,
    pub request: ReserveLowFeeSponsorRequest,
    pub reservation_root: String,
    pub matched_batch_id: String,
    pub consumed_receipt_id: String,
    pub reserved_at_height: u64,
    pub updated_at_height: u64,
}

impl LowFeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildPolicyProofBatchRequest {
    pub spend_proof_ids: Vec<String>,
    pub session_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub batch_operator_commitment: String,
    pub aggregate_policy_root: String,
    pub aggregate_spend_proof_root: String,
    pub aggregate_session_proof_root: String,
    pub aggregate_sponsor_root: String,
    pub aggregate_nullifier_root: String,
    pub recursive_proof_root: String,
    pub pq_batch_signature_root: String,
    pub batch_nullifier: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl BuildPolicyProofBatchRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyProofBatchRecord {
    pub batch_id: String,
    pub status: PolicyProofBatchStatus,
    pub request: BuildPolicyProofBatchRequest,
    pub batch_root: String,
    pub settlement_receipt_id: String,
    pub built_at_height: u64,
    pub updated_at_height: u64,
}

impl PolicyProofBatchRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishPolicyProofReceiptRequest {
    pub receipt_kind: ReceiptKind,
    pub batch_id: String,
    pub proof_ids: Vec<String>,
    pub session_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub settlement_state_root: String,
    pub settlement_event_root: String,
    pub fee_debit_root: String,
    pub pq_finality_signature_root: String,
    pub receipt_nullifier: String,
    pub published_at_height: u64,
}

impl PublishPolicyProofReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyProofReceiptRecord {
    pub receipt_id: String,
    pub request: PublishPolicyProofReceiptRequest,
    pub receipt_root: String,
    pub published_at_height: u64,
}

impl PolicyProofReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRecoveryReceiptRequest {
    pub policy_id: String,
    pub action_kind: RecoveryActionKind,
    pub recovery_payload_root: String,
    pub guardian_authorization_root: String,
    pub pq_recovery_signature_root: String,
    pub replacement_policy_root: String,
    pub recovery_nullifier: String,
    pub accepted: bool,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl PublishRecoveryReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryReceiptRecord {
    pub receipt_id: String,
    pub request: PublishRecoveryReceiptRequest,
    pub receipt_root: String,
    pub published_at_height: u64,
}

impl RecoveryReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishViolationReceiptRequest {
    pub policy_id: String,
    pub target_id: String,
    pub violation_kind: ViolationKind,
    pub evidence_root: String,
    pub challenged_proof_root: String,
    pub pq_challenge_signature_root: String,
    pub penalty_commitment_root: String,
    pub violation_nullifier: String,
    pub published_at_height: u64,
}

impl PublishViolationReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViolationReceiptRecord {
    pub receipt_id: String,
    pub request: PublishViolationReceiptRequest,
    pub receipt_root: String,
    pub published_at_height: u64,
}

impl ViolationReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRebateReceiptRequest {
    pub reservation_id: String,
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_amount_units: u128,
    pub rebate_commitment_root: String,
    pub fee_savings_root: String,
    pub pq_rebate_signature_root: String,
    pub rebate_nullifier: String,
    pub published_at_height: u64,
}

impl PublishRebateReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceiptRecord {
    pub rebate_id: String,
    pub request: PublishRebateReceiptRequest,
    pub rebate_root: String,
    pub published_at_height: u64,
}

impl RebateReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub policies: BTreeMap<String, ShieldedWalletPolicyRecord>,
    pub spend_proofs: BTreeMap<String, PqSpendAuthorizationProofRecord>,
    pub session_proofs: BTreeMap<String, PrivateSessionProofRecord>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservationRecord>,
    pub batches: BTreeMap<String, PolicyProofBatchRecord>,
    pub receipts: BTreeMap<String, PolicyProofReceiptRecord>,
    pub recovery_receipts: BTreeMap<String, RecoveryReceiptRecord>,
    pub violation_receipts: BTreeMap<String, ViolationReceiptRecord>,
    pub rebates: BTreeMap<String, RebateReceiptRecord>,
    pub replay_nullifiers: BTreeSet<String>,
    pub spend_nullifiers: BTreeSet<String>,
    pub session_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqWalletPolicyProofRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2PqWalletPolicyProofRuntimeResult<Self> {
        validate_config(&config)?;
        Ok(Self {
            current_height: config.devnet_height,
            config,
            counters: Counters::default(),
            policies: BTreeMap::new(),
            spend_proofs: BTreeMap::new(),
            session_proofs: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            recovery_receipts: BTreeMap::new(),
            violation_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
            spend_nullifiers: BTreeSet::new(),
            session_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_shielded_wallet_policy(
        &mut self,
        request: RegisterShieldedWalletPolicyRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.registered_at_height);
        self.require_policy_capacity()?;
        validate_policy_request(&self.config, &request, self.current_height)?;
        let sequence = self.counters.policies_registered.saturating_add(1);
        let policy_id = shielded_wallet_policy_id(&request, sequence);
        if self.policies.contains_key(&policy_id) {
            return Err("shielded wallet policy already registered".to_string());
        }
        let policy_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-POLICY-ROOT",
            &request.public_record(),
        );
        let record = ShieldedWalletPolicyRecord {
            policy_id: policy_id.clone(),
            status: WalletPolicyStatus::Registered,
            registered_at_height: request.registered_at_height,
            updated_at_height: request.registered_at_height,
            activation_receipt_root: String::new(),
            current_session_nonce_root: String::new(),
            spent_amount_window_root: String::new(),
            sponsor_budget_root: request.sponsor_policy_root.clone(),
            request,
            policy_root,
        };
        self.policies.insert(policy_id.clone(), record);
        self.counters.policies_registered = sequence;
        Ok(policy_id)
    }

    pub fn activate_policy(
        &mut self,
        policy_id: &str,
        activation_receipt_root: String,
        current_height: u64,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        self.expire_stale(current_height);
        ensure_non_empty("policy_id", policy_id)?;
        ensure_non_empty("activation_receipt_root", &activation_receipt_root)?;
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| "unknown policy id".to_string())?;
        if !matches!(
            policy.status,
            WalletPolicyStatus::Registered
                | WalletPolicyStatus::GracePeriod
                | WalletPolicyStatus::Rotating
        ) {
            return Err("policy cannot be activated from current status".to_string());
        }
        policy.status = WalletPolicyStatus::Active;
        policy.activation_receipt_root = activation_receipt_root;
        policy.updated_at_height = current_height;
        self.counters.policies_activated = self.counters.policies_activated.saturating_add(1);
        Ok(())
    }

    pub fn rotate_policy_root(
        &mut self,
        policy_id: &str,
        replacement_policy_root: String,
        pq_rotation_signature_root: String,
        current_height: u64,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        self.expire_stale(current_height);
        ensure_non_empty("replacement_policy_root", &replacement_policy_root)?;
        ensure_non_empty("pq_rotation_signature_root", &pq_rotation_signature_root)?;
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| "unknown policy id".to_string())?;
        if !policy.status.accepts_recovery_receipts() {
            return Err("policy cannot rotate from current status".to_string());
        }
        policy.status = WalletPolicyStatus::Rotating;
        policy.policy_root = root_from_record(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-ROTATED-POLICY-ROOT",
            &json!({
                "policy_id": policy_id,
                "previous_policy_root": policy.policy_root,
                "replacement_policy_root": replacement_policy_root,
                "pq_rotation_signature_root": pq_rotation_signature_root,
                "current_height": current_height,
            }),
        );
        policy.updated_at_height = current_height;
        self.counters.policies_rotated = self.counters.policies_rotated.saturating_add(1);
        Ok(())
    }

    pub fn submit_pq_spend_authorization_proof(
        &mut self,
        request: SubmitPqSpendAuthorizationProofRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.submitted_at_height);
        self.require_spend_proof_capacity()?;
        validate_spend_proof_request(&self.config, &self.policies, &request, self.current_height)?;
        self.insert_replay_nullifier(&request.replay_nullifier)?;
        self.insert_spend_nullifier(&request.nullifier)?;
        let sequence = self.counters.spend_proofs_submitted.saturating_add(1);
        let proof_id = pq_spend_authorization_proof_id(&request, sequence);
        if self.spend_proofs.contains_key(&proof_id) {
            return Err("spend authorization proof already exists".to_string());
        }
        let proof_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SPEND-PROOF-ROOT",
            &request.public_record(),
        );
        let record = PqSpendAuthorizationProofRecord {
            proof_id: proof_id.clone(),
            status: ProofStatus::Submitted,
            submitted_at_height: request.submitted_at_height,
            updated_at_height: request.submitted_at_height,
            sponsor_reservation_id: String::new(),
            batch_id: String::new(),
            request,
            proof_root,
        };
        self.counters.spend_proofs_submitted = sequence;
        self.spend_proofs.insert(proof_id.clone(), record);
        Ok(proof_id)
    }

    pub fn accept_spend_proof(
        &mut self,
        proof_id: &str,
        current_height: u64,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        self.expire_stale(current_height);
        let proof = self
            .spend_proofs
            .get_mut(proof_id)
            .ok_or_else(|| "unknown spend proof id".to_string())?;
        if !proof.status.live() {
            return Err("spend proof is not live".to_string());
        }
        proof.status = ProofStatus::Accepted;
        proof.updated_at_height = current_height;
        self.counters.spend_proofs_accepted = self.counters.spend_proofs_accepted.saturating_add(1);
        self.counters.total_authorized_amount_units = self
            .counters
            .total_authorized_amount_units
            .saturating_add(proof.request.amount_upper_bound_units);
        Ok(())
    }

    pub fn reject_spend_proof(
        &mut self,
        proof_id: &str,
        current_height: u64,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        self.expire_stale(current_height);
        let proof = self
            .spend_proofs
            .get_mut(proof_id)
            .ok_or_else(|| "unknown spend proof id".to_string())?;
        if !proof.status.live() {
            return Err("spend proof is not live".to_string());
        }
        proof.status = ProofStatus::Rejected;
        proof.updated_at_height = current_height;
        self.counters.spend_proofs_rejected = self.counters.spend_proofs_rejected.saturating_add(1);
        Ok(())
    }

    pub fn open_private_session_proof(
        &mut self,
        request: OpenPrivateSessionProofRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.opened_at_height);
        self.require_session_proof_capacity()?;
        validate_session_proof_request(
            &self.config,
            &self.policies,
            &request,
            self.current_height,
        )?;
        self.insert_replay_nullifier(&request.replay_nullifier)?;
        self.insert_session_nullifier(&request.expiry_nullifier)?;
        let sequence = self.counters.session_proofs_opened.saturating_add(1);
        let session_id = private_session_proof_id(&request, sequence);
        if self.session_proofs.contains_key(&session_id) {
            return Err("private session proof already exists".to_string());
        }
        let session_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SESSION-ROOT",
            &request.public_record(),
        );
        let record = PrivateSessionProofRecord {
            session_id: session_id.clone(),
            status: SessionStatus::Opened,
            opened_at_height: request.opened_at_height,
            updated_at_height: request.opened_at_height,
            authorized_spend_count: 0,
            authorized_amount_units: 0,
            sponsor_reservation_id: String::new(),
            batch_id: String::new(),
            request,
            session_root,
        };
        self.counters.session_proofs_opened = sequence;
        self.session_proofs.insert(session_id.clone(), record);
        Ok(session_id)
    }

    pub fn authorize_private_session_fast_path(
        &mut self,
        session_id: &str,
        authorized_amount_units: u128,
        pq_authorization_root: String,
        current_height: u64,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        self.expire_stale(current_height);
        if !self.config.allow_fast_sessions {
            return Err("fast sessions are disabled".to_string());
        }
        ensure_non_empty("pq_authorization_root", &pq_authorization_root)?;
        let session = self
            .session_proofs
            .get_mut(session_id)
            .ok_or_else(|| "unknown private session id".to_string())?;
        if !session.status.accepts_spends() {
            return Err("session does not accept spends".to_string());
        }
        if session.authorized_spend_count >= session.request.max_authorizations {
            return Err("session authorization count exhausted".to_string());
        }
        let next_amount = session
            .authorized_amount_units
            .saturating_add(authorized_amount_units);
        if next_amount > session.request.session_spend_limit_units {
            return Err("session spend limit exceeded".to_string());
        }
        session.status = SessionStatus::FastPath;
        session.authorized_spend_count = session.authorized_spend_count.saturating_add(1);
        session.authorized_amount_units = next_amount;
        session.session_root = root_from_record(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-FAST-SESSION-AUTH-ROOT",
            &json!({
                "session_id": session_id,
                "previous_session_root": session.session_root,
                "authorized_amount_units": authorized_amount_units,
                "pq_authorization_root": pq_authorization_root,
                "current_height": current_height,
            }),
        );
        session.updated_at_height = current_height;
        self.counters.session_proofs_authorized =
            self.counters.session_proofs_authorized.saturating_add(1);
        self.counters.total_authorized_amount_units = self
            .counters
            .total_authorized_amount_units
            .saturating_add(authorized_amount_units);
        Ok(())
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: ReserveLowFeeSponsorRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.reserved_at_height);
        self.require_sponsor_capacity()?;
        validate_sponsor_request(
            &self.config,
            &self.spend_proofs,
            &self.session_proofs,
            &request,
            self.current_height,
        )?;
        self.insert_replay_nullifier(&request.route_nullifier)?;
        let sequence = self.counters.sponsor_reservations_created.saturating_add(1);
        let reservation_id = low_fee_sponsor_reservation_id(&request, sequence);
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err("low-fee sponsor reservation already exists".to_string());
        }
        let reservation_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SPONSOR-RESERVATION-ROOT",
            &request.public_record(),
        );
        let record = LowFeeSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            status: SponsorReservationStatus::Reserved,
            reserved_at_height: request.reserved_at_height,
            updated_at_height: request.reserved_at_height,
            matched_batch_id: String::new(),
            consumed_receipt_id: String::new(),
            request: request.clone(),
            reservation_root,
        };
        self.link_sponsor_target(&request, &reservation_id)?;
        self.counters.sponsor_reservations_created = sequence;
        self.counters.total_reserved_fee_units = self
            .counters
            .total_reserved_fee_units
            .saturating_add(request.reserved_fee_units);
        self.sponsor_reservations
            .insert(reservation_id.clone(), record);
        Ok(reservation_id)
    }

    pub fn build_policy_proof_batch(
        &mut self,
        request: BuildPolicyProofBatchRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.built_at_height);
        self.require_batch_capacity()?;
        validate_batch_request(
            &self.config,
            &self.spend_proofs,
            &self.session_proofs,
            &self.sponsor_reservations,
            &request,
            self.current_height,
        )?;
        self.insert_replay_nullifier(&request.batch_nullifier)?;
        let sequence = self.counters.batches_built.saturating_add(1);
        let batch_id = policy_proof_batch_id(&request, sequence);
        if self.batches.contains_key(&batch_id) {
            return Err("policy proof batch already exists".to_string());
        }
        let batch_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-BATCH-ROOT",
            &request.public_record(),
        );
        for proof_id in &request.spend_proof_ids {
            let proof = self
                .spend_proofs
                .get_mut(proof_id)
                .ok_or_else(|| format!("unknown spend proof id: {proof_id}"))?;
            proof.status = ProofStatus::Batched;
            proof.batch_id = batch_id.clone();
            proof.updated_at_height = request.built_at_height;
        }
        for session_id in &request.session_ids {
            let session = self
                .session_proofs
                .get_mut(session_id)
                .ok_or_else(|| format!("unknown session id: {session_id}"))?;
            session.status = SessionStatus::Settling;
            session.batch_id = batch_id.clone();
            session.updated_at_height = request.built_at_height;
        }
        for reservation_id in &request.sponsor_reservation_ids {
            let reservation = self
                .sponsor_reservations
                .get_mut(reservation_id)
                .ok_or_else(|| format!("unknown sponsor reservation id: {reservation_id}"))?;
            reservation.status = SponsorReservationStatus::Matched;
            reservation.matched_batch_id = batch_id.clone();
            reservation.updated_at_height = request.built_at_height;
        }
        let record = PolicyProofBatchRecord {
            batch_id: batch_id.clone(),
            status: PolicyProofBatchStatus::Proposed,
            built_at_height: request.built_at_height,
            updated_at_height: request.built_at_height,
            settlement_receipt_id: String::new(),
            request,
            batch_root,
        };
        self.batches.insert(batch_id.clone(), record);
        self.counters.batches_built = sequence;
        Ok(batch_id)
    }

    pub fn publish_policy_proof_receipt(
        &mut self,
        request: PublishPolicyProofReceiptRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.published_at_height);
        self.require_receipt_capacity()?;
        validate_receipt_request(
            &self.batches,
            &self.spend_proofs,
            &self.session_proofs,
            &self.sponsor_reservations,
            &request,
        )?;
        self.insert_replay_nullifier(&request.receipt_nullifier)?;
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt_id = policy_proof_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-RECEIPT-ROOT",
            &request.public_record(),
        );
        for proof_id in &request.proof_ids {
            if let Some(proof) = self.spend_proofs.get_mut(proof_id) {
                proof.status = ProofStatus::Settled;
                proof.updated_at_height = request.published_at_height;
            }
        }
        for session_id in &request.session_ids {
            if let Some(session) = self.session_proofs.get_mut(session_id) {
                session.status = SessionStatus::Settled;
                session.updated_at_height = request.published_at_height;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
                reservation.consumed_receipt_id = receipt_id.clone();
                reservation.updated_at_height = request.published_at_height;
                self.counters.sponsor_reservations_consumed = self
                    .counters
                    .sponsor_reservations_consumed
                    .saturating_add(1);
            }
        }
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = PolicyProofBatchStatus::Settled;
            batch.settlement_receipt_id = receipt_id.clone();
            batch.updated_at_height = request.published_at_height;
        }
        let record = PolicyProofReceiptRecord {
            receipt_id: receipt_id.clone(),
            published_at_height: request.published_at_height,
            request,
            receipt_root,
        };
        self.receipts.insert(receipt_id.clone(), record);
        self.counters.receipts_published = sequence;
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        Ok(receipt_id)
    }

    pub fn publish_recovery_receipt(
        &mut self,
        request: PublishRecoveryReceiptRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.published_at_height);
        self.require_receipt_capacity()?;
        validate_recovery_receipt_request(&self.config, &self.policies, &request)?;
        self.insert_replay_nullifier(&request.recovery_nullifier)?;
        let sequence = self.counters.recovery_receipts_published.saturating_add(1);
        let receipt_id = recovery_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-RECOVERY-RECEIPT-ROOT",
            &request.public_record(),
        );
        if let Some(policy) = self.policies.get_mut(&request.policy_id) {
            policy.updated_at_height = request.published_at_height;
            if request.accepted {
                match request.action_kind {
                    RecoveryActionKind::FreezeWallet => {
                        policy.status = WalletPolicyStatus::Frozen;
                        self.counters.policies_frozen =
                            self.counters.policies_frozen.saturating_add(1);
                    }
                    RecoveryActionKind::UnfreezeWallet => {
                        policy.status = WalletPolicyStatus::Active;
                    }
                    RecoveryActionKind::ReplacePolicyRoot => {
                        policy.status = WalletPolicyStatus::Rotating;
                        policy.policy_root = request.replacement_policy_root.clone();
                        self.counters.policies_rotated =
                            self.counters.policies_rotated.saturating_add(1);
                    }
                    RecoveryActionKind::EmergencyEscape => {
                        policy.status = WalletPolicyStatus::Paused;
                        self.counters.policies_paused =
                            self.counters.policies_paused.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        let record = RecoveryReceiptRecord {
            receipt_id: receipt_id.clone(),
            published_at_height: request.published_at_height,
            request,
            receipt_root,
        };
        self.recovery_receipts.insert(receipt_id.clone(), record);
        self.counters.recovery_receipts_published = sequence;
        Ok(receipt_id)
    }

    pub fn publish_violation_receipt(
        &mut self,
        request: PublishViolationReceiptRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.published_at_height);
        self.require_receipt_capacity()?;
        validate_violation_receipt_request(&self.config, &self.policies, &request)?;
        self.insert_replay_nullifier(&request.violation_nullifier)?;
        let sequence = self.counters.violation_receipts_published.saturating_add(1);
        let receipt_id = violation_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-VIOLATION-RECEIPT-ROOT",
            &request.public_record(),
        );
        if let Some(policy) = self.policies.get_mut(&request.policy_id) {
            policy.status = match request.violation_kind {
                ViolationKind::ReplayNullifier | ViolationKind::InvalidPqAuthorization => {
                    WalletPolicyStatus::Slashed
                }
                ViolationKind::SpendLimitExceeded | ViolationKind::VelocityLimitExceeded => {
                    WalletPolicyStatus::Frozen
                }
                _ => policy.status,
            };
            policy.updated_at_height = request.published_at_height;
        }
        if let Some(proof) = self.spend_proofs.get_mut(&request.target_id) {
            proof.status = ProofStatus::Slashed;
            proof.updated_at_height = request.published_at_height;
        }
        if let Some(session) = self.session_proofs.get_mut(&request.target_id) {
            session.status = SessionStatus::Slashed;
            session.updated_at_height = request.published_at_height;
        }
        let record = ViolationReceiptRecord {
            receipt_id: receipt_id.clone(),
            published_at_height: request.published_at_height,
            request,
            receipt_root,
        };
        self.violation_receipts.insert(receipt_id.clone(), record);
        self.counters.violation_receipts_published = sequence;
        Ok(receipt_id)
    }

    pub fn publish_rebate_receipt(
        &mut self,
        request: PublishRebateReceiptRequest,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<String> {
        self.expire_stale(request.published_at_height);
        self.require_rebate_capacity()?;
        validate_rebate_receipt_request(&self.config, &self.sponsor_reservations, &request)?;
        self.insert_replay_nullifier(&request.rebate_nullifier)?;
        let sequence = self.counters.rebates_published.saturating_add(1);
        let rebate_id = rebate_receipt_id(&request, sequence);
        let rebate_root = payload_root(
            "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-REBATE-ROOT",
            &request.public_record(),
        );
        if let Some(reservation) = self.sponsor_reservations.get_mut(&request.reservation_id) {
            reservation.status = SponsorReservationStatus::RebateQueued;
            reservation.updated_at_height = request.published_at_height;
        }
        let record = RebateReceiptRecord {
            rebate_id: rebate_id.clone(),
            published_at_height: request.published_at_height,
            request,
            rebate_root,
        };
        self.rebates.insert(rebate_id.clone(), record);
        self.counters.rebates_published = sequence;
        self.counters.total_rebate_units = self.counters.total_rebate_units.saturating_add(
            self.rebates
                .get(&rebate_id)
                .map(|rebate| rebate.request.rebate_amount_units)
                .unwrap_or(0),
        );
        Ok(rebate_id)
    }

    pub fn roots(&self) -> Roots {
        let policy_records = self
            .policies
            .values()
            .map(ShieldedWalletPolicyRecord::public_record)
            .collect::<Vec<_>>();
        let spend_records = self
            .spend_proofs
            .values()
            .map(PqSpendAuthorizationProofRecord::public_record)
            .collect::<Vec<_>>();
        let session_records = self
            .session_proofs
            .values()
            .map(PrivateSessionProofRecord::public_record)
            .collect::<Vec<_>>();
        let sponsor_records = self
            .sponsor_reservations
            .values()
            .map(LowFeeSponsorReservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(PolicyProofBatchRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(PolicyProofReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let recovery_records = self
            .recovery_receipts
            .values()
            .map(RecoveryReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let violation_records = self
            .violation_receipts
            .values()
            .map(ViolationReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .map(RebateReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let all_public_records = self.public_records().into_values().collect::<Vec<_>>();
        Roots {
            policy_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-POLICIES",
                &policy_records,
            ),
            spend_proof_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SPEND-PROOFS",
                &spend_records,
            ),
            session_proof_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SESSIONS",
                &session_records,
            ),
            sponsor_reservation_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SPONSORS",
                &sponsor_records,
            ),
            batch_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-BATCHES",
                &batch_records,
            ),
            receipt_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-RECEIPTS",
                &receipt_records,
            ),
            recovery_receipt_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-RECOVERY-RECEIPTS",
                &recovery_records,
            ),
            violation_receipt_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-VIOLATION-RECEIPTS",
                &violation_records,
            ),
            rebate_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-REBATES",
                &rebate_records,
            ),
            replay_nullifier_root: id_set_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-REPLAY-NULLIFIERS",
                &self.replay_nullifiers,
            ),
            spend_nullifier_root: id_set_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SPEND-NULLIFIERS",
                &self.spend_nullifiers,
            ),
            session_nullifier_root: id_set_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SESSION-NULLIFIERS",
                &self.session_nullifiers,
            ),
            public_record_root: public_record_root(
                "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-PUBLIC-RECORDS",
                &all_public_records,
            ),
        }
    }

    pub fn public_records(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        records.insert("counters".to_string(), self.counters.public_record());
        for policy in self.policies.values() {
            records.insert(
                format!("policy:{}", policy.policy_id),
                policy.public_record(),
            );
        }
        for proof in self.spend_proofs.values() {
            records.insert(
                format!("spend_proof:{}", proof.proof_id),
                proof.public_record(),
            );
        }
        for session in self.session_proofs.values() {
            records.insert(
                format!("session:{}", session.session_id),
                session.public_record(),
            );
        }
        for reservation in self.sponsor_reservations.values() {
            records.insert(
                format!("sponsor:{}", reservation.reservation_id),
                reservation.public_record(),
            );
        }
        for batch in self.batches.values() {
            records.insert(format!("batch:{}", batch.batch_id), batch.public_record());
        }
        for receipt in self.receipts.values() {
            records.insert(
                format!("receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        for receipt in self.recovery_receipts.values() {
            records.insert(
                format!("recovery_receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        for receipt in self.violation_receipts.values() {
            records.insert(
                format!("violation_receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        for rebate in self.rebates.values() {
            records.insert(
                format!("rebate:{}", rebate.rebate_id),
                rebate.public_record(),
            );
        }
        records
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_wallet_policy_proof_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_SCHEMA_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
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

    fn link_sponsor_target(
        &mut self,
        request: &ReserveLowFeeSponsorRequest,
        reservation_id: &str,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        if let Some(proof) = self.spend_proofs.get_mut(&request.target_id) {
            proof.status = ProofStatus::SponsorReserved;
            proof.sponsor_reservation_id = reservation_id.to_string();
            proof.updated_at_height = request.reserved_at_height;
            return Ok(());
        }
        if let Some(session) = self.session_proofs.get_mut(&request.target_id) {
            session.sponsor_reservation_id = reservation_id.to_string();
            session.updated_at_height = request.reserved_at_height;
            return Ok(());
        }
        Err("sponsor target does not exist".to_string())
    }

    fn insert_replay_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        if !self.config.require_replay_fence {
            return Ok(());
        }
        let root = nullifier_root("replay", nullifier);
        if !self.replay_nullifiers.insert(root) {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("replay nullifier already observed".to_string());
        }
        Ok(())
    }

    fn insert_spend_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        let root = nullifier_root("spend", nullifier);
        if !self.spend_nullifiers.insert(root) {
            return Err("spend nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        Ok(())
    }

    fn insert_session_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        let root = nullifier_root("session", nullifier);
        if !self.session_nullifiers.insert(root) {
            return Err("session nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        Ok(())
    }

    fn expire_stale(&mut self, current_height: u64) {
        for policy in self.policies.values_mut() {
            if matches!(
                policy.status,
                WalletPolicyStatus::Registered
                    | WalletPolicyStatus::Active
                    | WalletPolicyStatus::GracePeriod
                    | WalletPolicyStatus::Rotating
            ) && current_height > policy.request.expires_at_height
            {
                policy.status = WalletPolicyStatus::Retired;
                policy.updated_at_height = current_height;
                self.counters.policies_expired = self.counters.policies_expired.saturating_add(1);
            }
        }
        for proof in self.spend_proofs.values_mut() {
            if proof.status.live() && current_height > proof.request.expires_at_height {
                proof.status = ProofStatus::Expired;
                proof.updated_at_height = current_height;
                self.counters.spend_proofs_expired =
                    self.counters.spend_proofs_expired.saturating_add(1);
            }
        }
        for session in self.session_proofs.values_mut() {
            if session.status.accepts_spends() && current_height > session.request.expires_at_height
            {
                session.status = SessionStatus::Expired;
                session.updated_at_height = current_height;
                self.counters.session_proofs_expired =
                    self.counters.session_proofs_expired.saturating_add(1);
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.status.active() && current_height > reservation.request.expires_at_height
            {
                reservation.status = SponsorReservationStatus::Expired;
                reservation.updated_at_height = current_height;
                self.counters.sponsor_reservations_expired =
                    self.counters.sponsor_reservations_expired.saturating_add(1);
            }
        }
        for batch in self.batches.values_mut() {
            if batch.status.can_settle() && current_height > batch.request.expires_at_height {
                batch.status = PolicyProofBatchStatus::Expired;
                batch.updated_at_height = current_height;
            }
        }
        self.current_height = self.current_height.max(current_height);
    }

    fn require_policy_capacity(&self) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        ensure_capacity(
            "shielded wallet policies",
            self.policies.len(),
            self.config.max_policies,
        )
    }

    fn require_spend_proof_capacity(&self) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        ensure_capacity(
            "PQ spend authorization proofs",
            self.spend_proofs.len(),
            self.config.max_spend_proofs,
        )
    }

    fn require_session_proof_capacity(&self) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        ensure_capacity(
            "private session proofs",
            self.session_proofs.len(),
            self.config.max_session_proofs,
        )
    }

    fn require_sponsor_capacity(&self) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        ensure_capacity(
            "low-fee sponsor reservations",
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
        )
    }

    fn require_batch_capacity(&self) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        ensure_capacity(
            "policy proof batches",
            self.batches.len(),
            self.config.max_batches,
        )
    }

    fn require_receipt_capacity(&self) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        ensure_capacity(
            "policy proof receipts",
            self.receipts.len() + self.recovery_receipts.len() + self.violation_receipts.len(),
            self.config.max_receipts,
        )
    }

    fn require_rebate_capacity(&self) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
        ensure_capacity(
            "rebate receipts",
            self.rebates.len(),
            self.config.max_rebates,
        )
    }
}

pub type Runtime = State;

pub fn private_l2_pq_wallet_policy_proof_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_wallet_policy_proof_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn devnet() -> PrivateL2PqWalletPolicyProofRuntimeResult<State> {
    State::devnet()
}

pub fn shielded_wallet_policy_id(
    request: &RegisterShieldedWalletPolicyRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-POLICY-ID",
        &json!({
            "sequence": sequence,
            "policy_kind": request.policy_kind.as_str(),
            "account_commitment": request.account_commitment,
            "wallet_policy_root": request.wallet_policy_root,
            "spend_limit_root": request.spend_limit_root,
            "velocity_limit_root": request.velocity_limit_root,
            "destination_policy_root": request.destination_policy_root,
            "asset_policy_root": request.asset_policy_root,
            "recovery_policy_root": request.recovery_policy_root,
            "session_policy_root": request.session_policy_root,
            "sponsor_policy_root": request.sponsor_policy_root,
            "pq_public_key_root": request.pq_public_key_root,
            "policy_nonce": request.policy_nonce,
            "registered_at_height": request.registered_at_height,
        }),
    )
}

pub fn pq_spend_authorization_proof_id(
    request: &SubmitPqSpendAuthorizationProofRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SPEND-ID",
        &json!({
            "sequence": sequence,
            "policy_id": request.policy_id,
            "proof_kind": request.proof_kind.as_str(),
            "spend_lane": request.spend_lane.as_str(),
            "asset_id": request.asset_id,
            "amount_commitment": request.amount_commitment,
            "destination_commitment_root": request.destination_commitment_root,
            "nullifier": request.nullifier,
            "replay_nullifier": request.replay_nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn private_session_proof_id(request: &OpenPrivateSessionProofRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SESSION-ID",
        &json!({
            "sequence": sequence,
            "policy_id": request.policy_id,
            "session_kind": request.session_kind.as_str(),
            "account_commitment": request.account_commitment,
            "session_key_commitment": request.session_key_commitment,
            "session_scope_root": request.session_scope_root,
            "expiry_nullifier": request.expiry_nullifier,
            "replay_nullifier": request.replay_nullifier,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn low_fee_sponsor_reservation_id(
    request: &ReserveLowFeeSponsorRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-SPONSOR-ID",
        &json!({
            "sequence": sequence,
            "target_id": request.target_id,
            "target_kind": request.target_kind,
            "policy_id": request.policy_id,
            "sponsor_commitment": request.sponsor_commitment,
            "fee_asset_id": request.fee_asset_id,
            "fee_credit_root": request.fee_credit_root,
            "route_nullifier": request.route_nullifier,
            "reserved_at_height": request.reserved_at_height,
        }),
    )
}

pub fn policy_proof_batch_id(request: &BuildPolicyProofBatchRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-BATCH-ID",
        &json!({
            "sequence": sequence,
            "spend_proof_ids": request.spend_proof_ids,
            "session_ids": request.session_ids,
            "sponsor_reservation_ids": request.sponsor_reservation_ids,
            "batch_operator_commitment": request.batch_operator_commitment,
            "aggregate_policy_root": request.aggregate_policy_root,
            "aggregate_spend_proof_root": request.aggregate_spend_proof_root,
            "aggregate_session_proof_root": request.aggregate_session_proof_root,
            "aggregate_sponsor_root": request.aggregate_sponsor_root,
            "aggregate_nullifier_root": request.aggregate_nullifier_root,
            "batch_nullifier": request.batch_nullifier,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn policy_proof_receipt_id(
    request: &PublishPolicyProofReceiptRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-RECEIPT-ID",
        &json!({
            "sequence": sequence,
            "receipt_kind": request.receipt_kind.as_str(),
            "batch_id": request.batch_id,
            "proof_ids": request.proof_ids,
            "session_ids": request.session_ids,
            "reservation_ids": request.reservation_ids,
            "settlement_state_root": request.settlement_state_root,
            "receipt_nullifier": request.receipt_nullifier,
            "published_at_height": request.published_at_height,
        }),
    )
}

pub fn recovery_receipt_id(request: &PublishRecoveryReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-RECOVERY-RECEIPT-ID",
        &json!({
            "sequence": sequence,
            "policy_id": request.policy_id,
            "action_kind": request.action_kind.as_str(),
            "recovery_payload_root": request.recovery_payload_root,
            "recovery_nullifier": request.recovery_nullifier,
            "accepted": request.accepted,
            "published_at_height": request.published_at_height,
        }),
    )
}

pub fn violation_receipt_id(request: &PublishViolationReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-VIOLATION-RECEIPT-ID",
        &json!({
            "sequence": sequence,
            "policy_id": request.policy_id,
            "target_id": request.target_id,
            "violation_kind": request.violation_kind.as_str(),
            "evidence_root": request.evidence_root,
            "violation_nullifier": request.violation_nullifier,
            "published_at_height": request.published_at_height,
        }),
    )
}

pub fn rebate_receipt_id(request: &PublishRebateReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-REBATE-ID",
        &json!({
            "sequence": sequence,
            "reservation_id": request.reservation_id,
            "policy_id": request.policy_id,
            "sponsor_commitment": request.sponsor_commitment,
            "beneficiary_commitment": request.beneficiary_commitment,
            "rebate_asset_id": request.rebate_asset_id,
            "rebate_amount_units": request.rebate_amount_units,
            "rebate_nullifier": request.rebate_nullifier,
            "published_at_height": request.published_at_height,
        }),
    )
}

pub fn replay_fence_root(policy_id: &str, replay_nullifier: &str, proof_nullifier: &str) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-REPLAY-FENCE",
        &json!({
            "policy_id": policy_id,
            "replay_nullifier": replay_nullifier,
            "proof_nullifier": proof_nullifier,
        }),
    )
}

pub fn nullifier_root(kind: &str, nullifier: &str) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-NULLIFIER",
        &json!({
            "kind": kind,
            "nullifier": nullifier,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-WALLET-POLICY-PROOF-STATE-ROOT", record)
}

pub fn empty_runtime_root() -> String {
    domain_hash(
        "PRIVATE-L2-PQ-WALLET-POLICY-PROOF-EMPTY-RUNTIME-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
        ],
        32,
    )
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn id_set_root(domain: &str, ids: &BTreeSet<String>) -> String {
    let leaves = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            json!({
                "index": index,
                "id": id,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn validate_config(config: &Config) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("chain_id", &config.chain_id)?;
    ensure_non_empty("protocol_version", &config.protocol_version)?;
    ensure_non_empty("l2_network", &config.l2_network)?;
    ensure_non_empty("monero_network", &config.monero_network)?;
    ensure_non_empty("hash_suite", &config.hash_suite)?;
    ensure_non_empty("pq_auth_suite", &config.pq_auth_suite)?;
    ensure_non_empty("fee_asset_id", &config.fee_asset_id)?;
    ensure_capacity_nonzero("max_policies", config.max_policies)?;
    ensure_capacity_nonzero("max_spend_proofs", config.max_spend_proofs)?;
    ensure_capacity_nonzero("max_session_proofs", config.max_session_proofs)?;
    ensure_capacity_nonzero("max_sponsor_reservations", config.max_sponsor_reservations)?;
    ensure_capacity_nonzero("max_batches", config.max_batches)?;
    ensure_capacity_nonzero("max_receipts", config.max_receipts)?;
    ensure_capacity_nonzero("max_rebates", config.max_rebates)?;
    ensure_capacity_nonzero("max_batch_items", config.max_batch_items)?;
    ensure_min_u64("min_privacy_set_size", config.min_privacy_set_size, 1)?;
    ensure_min_u64(
        "session_privacy_set_size",
        config.session_privacy_set_size,
        1,
    )?;
    ensure_min_u64("batch_privacy_set_size", config.batch_privacy_set_size, 1)?;
    ensure_bps("max_spend_fee_bps", config.max_spend_fee_bps)?;
    ensure_bps("max_session_fee_bps", config.max_session_fee_bps)?;
    ensure_bps("max_sponsor_fee_bps", config.max_sponsor_fee_bps)?;
    ensure_bps("target_rebate_bps", config.target_rebate_bps)?;
    if config.max_session_fee_bps > config.max_spend_fee_bps {
        return Err("session fee cap cannot exceed spend fee cap".to_string());
    }
    if config.target_rebate_bps > config.max_sponsor_fee_bps {
        return Err("target rebate cannot exceed sponsor fee cap".to_string());
    }
    Ok(())
}

fn validate_policy_request(
    config: &Config,
    request: &RegisterShieldedWalletPolicyRequest,
    current_height: u64,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("account_commitment", &request.account_commitment)?;
    ensure_non_empty("wallet_policy_root", &request.wallet_policy_root)?;
    ensure_non_empty("spend_limit_root", &request.spend_limit_root)?;
    ensure_non_empty("velocity_limit_root", &request.velocity_limit_root)?;
    ensure_non_empty("destination_policy_root", &request.destination_policy_root)?;
    ensure_non_empty("asset_policy_root", &request.asset_policy_root)?;
    ensure_non_empty("recovery_policy_root", &request.recovery_policy_root)?;
    ensure_non_empty("session_policy_root", &request.session_policy_root)?;
    ensure_non_empty("sponsor_policy_root", &request.sponsor_policy_root)?;
    ensure_non_empty("pq_public_key_root", &request.pq_public_key_root)?;
    ensure_non_empty(
        "view_key_commitment_root",
        &request.view_key_commitment_root,
    )?;
    ensure_non_empty("policy_nonce", &request.policy_nonce)?;
    ensure_non_empty("metadata_root", &request.metadata_root)?;
    ensure_min_u64(
        "policy privacy set",
        request.min_privacy_set_size,
        config.min_privacy_set_size,
    )?;
    if request.pq_security_bits < config.min_pq_security_bits {
        return Err("policy PQ security bits below minimum".to_string());
    }
    ensure_bps("max_spend_fee_bps", request.max_spend_fee_bps)?;
    if request.max_spend_fee_bps > config.max_spend_fee_bps {
        return Err("policy spend fee exceeds configured cap".to_string());
    }
    if request.daily_spend_limit_units > config.max_daily_spend_limit_units {
        return Err("daily spend limit exceeds configured cap".to_string());
    }
    if request.session_spend_limit_units > config.max_session_spend_limit_units {
        return Err("session spend limit exceeds configured cap".to_string());
    }
    ensure_future_expiry(
        "policy",
        request.registered_at_height.max(current_height),
        request.expires_at_height,
        config.policy_ttl_blocks,
    )
}

fn validate_spend_proof_request(
    config: &Config,
    policies: &BTreeMap<String, ShieldedWalletPolicyRecord>,
    request: &SubmitPqSpendAuthorizationProofRequest,
    current_height: u64,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("policy_id", &request.policy_id)?;
    ensure_non_empty("account_commitment", &request.account_commitment)?;
    ensure_non_empty("asset_id", &request.asset_id)?;
    ensure_non_empty("amount_commitment", &request.amount_commitment)?;
    ensure_non_empty(
        "destination_commitment_root",
        &request.destination_commitment_root,
    )?;
    ensure_non_empty(
        "spend_limit_witness_root",
        &request.spend_limit_witness_root,
    )?;
    ensure_non_empty("velocity_witness_root", &request.velocity_witness_root)?;
    ensure_non_empty("membership_witness_root", &request.membership_witness_root)?;
    ensure_non_empty(
        "encrypted_spend_payload_root",
        &request.encrypted_spend_payload_root,
    )?;
    ensure_non_empty("zk_policy_proof_root", &request.zk_policy_proof_root)?;
    ensure_non_empty("nullifier", &request.nullifier)?;
    ensure_non_empty("replay_nullifier", &request.replay_nullifier)?;
    if config.require_pq_authorization {
        ensure_non_empty("pq_authorization_root", &request.pq_authorization_root)?;
    }
    ensure_min_u64(
        "spend privacy set",
        request.privacy_set_size,
        config.min_privacy_set_size,
    )?;
    if request.pq_security_bits < config.min_pq_security_bits {
        return Err("spend proof PQ security bits below minimum".to_string());
    }
    ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
    if request.max_user_fee_bps > config.max_spend_fee_bps {
        return Err("spend proof user fee exceeds configured cap".to_string());
    }
    let policy = policies
        .get(&request.policy_id)
        .ok_or_else(|| "unknown policy id".to_string())?;
    if !policy.status.accepts_spend_proofs() {
        return Err("policy does not accept spend proofs".to_string());
    }
    if policy.request.account_commitment != request.account_commitment {
        return Err("spend proof account commitment mismatches policy".to_string());
    }
    if request.amount_upper_bound_units > policy.request.daily_spend_limit_units {
        return Err("spend amount exceeds policy daily limit".to_string());
    }
    ensure_future_expiry(
        "spend proof",
        request.submitted_at_height.max(current_height),
        request.expires_at_height,
        config.spend_proof_ttl_blocks,
    )
}

fn validate_session_proof_request(
    config: &Config,
    policies: &BTreeMap<String, ShieldedWalletPolicyRecord>,
    request: &OpenPrivateSessionProofRequest,
    current_height: u64,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("policy_id", &request.policy_id)?;
    ensure_non_empty("account_commitment", &request.account_commitment)?;
    ensure_non_empty("session_key_commitment", &request.session_key_commitment)?;
    ensure_non_empty("session_scope_root", &request.session_scope_root)?;
    ensure_non_empty("allowed_lane_root", &request.allowed_lane_root)?;
    ensure_non_empty("allowed_asset_root", &request.allowed_asset_root)?;
    ensure_non_empty("spend_limit_root", &request.spend_limit_root)?;
    ensure_non_empty("expiry_nullifier", &request.expiry_nullifier)?;
    ensure_non_empty("replay_nullifier", &request.replay_nullifier)?;
    ensure_non_empty(
        "encrypted_session_payload_root",
        &request.encrypted_session_payload_root,
    )?;
    ensure_non_empty("zk_session_proof_root", &request.zk_session_proof_root)?;
    if config.require_pq_authorization {
        ensure_non_empty("pq_handshake_root", &request.pq_handshake_root)?;
    }
    ensure_min_u64(
        "session privacy set",
        request.privacy_set_size,
        config.session_privacy_set_size,
    )?;
    if request.pq_security_bits < config.min_pq_security_bits {
        return Err("session proof PQ security bits below minimum".to_string());
    }
    ensure_bps("max_session_fee_bps", request.max_session_fee_bps)?;
    if request.max_session_fee_bps > config.max_session_fee_bps {
        return Err("session fee exceeds configured cap".to_string());
    }
    if request.max_authorizations > config.max_authorizations_per_session {
        return Err("session authorization count exceeds configured cap".to_string());
    }
    let policy = policies
        .get(&request.policy_id)
        .ok_or_else(|| "unknown policy id".to_string())?;
    if !policy.status.accepts_session_proofs() {
        return Err("policy does not accept session proofs".to_string());
    }
    if policy.request.account_commitment != request.account_commitment {
        return Err("session account commitment mismatches policy".to_string());
    }
    if request.session_spend_limit_units > policy.request.session_spend_limit_units {
        return Err("session spend limit exceeds policy limit".to_string());
    }
    ensure_future_expiry(
        "session proof",
        request.opened_at_height.max(current_height),
        request.expires_at_height,
        config.session_proof_ttl_blocks,
    )
}

fn validate_sponsor_request(
    config: &Config,
    spend_proofs: &BTreeMap<String, PqSpendAuthorizationProofRecord>,
    session_proofs: &BTreeMap<String, PrivateSessionProofRecord>,
    request: &ReserveLowFeeSponsorRequest,
    current_height: u64,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    if !config.allow_low_fee_sponsors {
        return Err("low-fee sponsor reservations are disabled".to_string());
    }
    ensure_non_empty("target_id", &request.target_id)?;
    ensure_non_empty("target_kind", &request.target_kind)?;
    ensure_non_empty("policy_id", &request.policy_id)?;
    ensure_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
    ensure_non_empty("fee_asset_id", &request.fee_asset_id)?;
    ensure_non_empty("fee_credit_root", &request.fee_credit_root)?;
    ensure_non_empty("refund_commitment_root", &request.refund_commitment_root)?;
    ensure_non_empty("route_nullifier", &request.route_nullifier)?;
    if config.require_pq_authorization {
        ensure_non_empty("pq_authorization_root", &request.pq_authorization_root)?;
    }
    if request.fee_asset_id != config.fee_asset_id {
        return Err("sponsor fee asset does not match runtime fee asset".to_string());
    }
    ensure_bps("max_sponsor_fee_bps", request.max_sponsor_fee_bps)?;
    ensure_bps("target_rebate_bps", request.target_rebate_bps)?;
    if request.max_sponsor_fee_bps > config.max_sponsor_fee_bps {
        return Err("sponsor fee exceeds configured cap".to_string());
    }
    if request.target_rebate_bps > config.target_rebate_bps {
        return Err("target rebate exceeds configured target".to_string());
    }
    if request.reserved_fee_units == 0 {
        return Err("reserved fee must be greater than zero".to_string());
    }
    let target_ok = spend_proofs
        .get(&request.target_id)
        .map(|proof| proof.status.sponsorable() && proof.request.policy_id == request.policy_id)
        .or_else(|| {
            session_proofs.get(&request.target_id).map(|session| {
                session.status.accepts_spends() && session.request.policy_id == request.policy_id
            })
        })
        .unwrap_or(false);
    if !target_ok {
        return Err("sponsor target is not sponsorable".to_string());
    }
    ensure_future_expiry(
        "sponsor reservation",
        request.reserved_at_height.max(current_height),
        request.expires_at_height,
        config.sponsor_ttl_blocks,
    )
}

fn validate_batch_request(
    config: &Config,
    spend_proofs: &BTreeMap<String, PqSpendAuthorizationProofRecord>,
    session_proofs: &BTreeMap<String, PrivateSessionProofRecord>,
    reservations: &BTreeMap<String, LowFeeSponsorReservationRecord>,
    request: &BuildPolicyProofBatchRequest,
    current_height: u64,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty(
        "batch_operator_commitment",
        &request.batch_operator_commitment,
    )?;
    ensure_non_empty("aggregate_policy_root", &request.aggregate_policy_root)?;
    ensure_non_empty(
        "aggregate_spend_proof_root",
        &request.aggregate_spend_proof_root,
    )?;
    ensure_non_empty(
        "aggregate_session_proof_root",
        &request.aggregate_session_proof_root,
    )?;
    ensure_non_empty("aggregate_sponsor_root", &request.aggregate_sponsor_root)?;
    ensure_non_empty(
        "aggregate_nullifier_root",
        &request.aggregate_nullifier_root,
    )?;
    ensure_non_empty("recursive_proof_root", &request.recursive_proof_root)?;
    ensure_non_empty("pq_batch_signature_root", &request.pq_batch_signature_root)?;
    ensure_non_empty("batch_nullifier", &request.batch_nullifier)?;
    ensure_bps("max_fee_bps", request.max_fee_bps)?;
    if request.max_fee_bps > config.max_spend_fee_bps {
        return Err("batch fee exceeds configured spend fee cap".to_string());
    }
    ensure_min_u64(
        "batch privacy set",
        request.privacy_set_size,
        config.batch_privacy_set_size,
    )?;
    ensure_unique("spend_proof_ids", &request.spend_proof_ids)?;
    ensure_unique("session_ids", &request.session_ids)?;
    ensure_unique("sponsor_reservation_ids", &request.sponsor_reservation_ids)?;
    let item_count = request.spend_proof_ids.len() + request.session_ids.len();
    if item_count == 0 {
        return Err("batch must contain at least one proof or session".to_string());
    }
    if item_count > config.max_batch_items {
        return Err("batch item capacity exceeded".to_string());
    }
    for proof_id in &request.spend_proof_ids {
        let proof = spend_proofs
            .get(proof_id)
            .ok_or_else(|| format!("unknown spend proof id: {proof_id}"))?;
        if !proof.status.batchable() {
            return Err(format!("spend proof is not batchable: {proof_id}"));
        }
    }
    for session_id in &request.session_ids {
        let session = session_proofs
            .get(session_id)
            .ok_or_else(|| format!("unknown session id: {session_id}"))?;
        if !session.status.accepts_spends() {
            return Err(format!("session is not batchable: {session_id}"));
        }
    }
    for reservation_id in &request.sponsor_reservation_ids {
        let reservation = reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown sponsor reservation id: {reservation_id}"))?;
        if !reservation.status.active() {
            return Err(format!(
                "sponsor reservation is not active: {reservation_id}"
            ));
        }
        if !request
            .spend_proof_ids
            .contains(&reservation.request.target_id)
            && !request.session_ids.contains(&reservation.request.target_id)
        {
            return Err(format!(
                "sponsor reservation target not present in batch: {reservation_id}"
            ));
        }
    }
    ensure_future_expiry(
        "batch",
        request.built_at_height.max(current_height),
        request.expires_at_height,
        config.batch_ttl_blocks,
    )
}

fn validate_receipt_request(
    batches: &BTreeMap<String, PolicyProofBatchRecord>,
    spend_proofs: &BTreeMap<String, PqSpendAuthorizationProofRecord>,
    session_proofs: &BTreeMap<String, PrivateSessionProofRecord>,
    reservations: &BTreeMap<String, LowFeeSponsorReservationRecord>,
    request: &PublishPolicyProofReceiptRequest,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("batch_id", &request.batch_id)?;
    ensure_non_empty("settlement_state_root", &request.settlement_state_root)?;
    ensure_non_empty("settlement_event_root", &request.settlement_event_root)?;
    ensure_non_empty("fee_debit_root", &request.fee_debit_root)?;
    ensure_non_empty(
        "pq_finality_signature_root",
        &request.pq_finality_signature_root,
    )?;
    ensure_non_empty("receipt_nullifier", &request.receipt_nullifier)?;
    let batch = batches
        .get(&request.batch_id)
        .ok_or_else(|| "unknown batch id".to_string())?;
    if !batch.status.can_settle() {
        return Err("batch cannot be settled from current status".to_string());
    }
    if request.proof_ids.is_empty() && request.session_ids.is_empty() {
        return Err("receipt must settle at least one proof or session".to_string());
    }
    for proof_id in &request.proof_ids {
        if !batch.request.spend_proof_ids.contains(proof_id) {
            return Err(format!("receipt proof not in batch: {proof_id}"));
        }
        let proof = spend_proofs
            .get(proof_id)
            .ok_or_else(|| format!("unknown spend proof id: {proof_id}"))?;
        if !proof.status.receiptable() {
            return Err(format!("spend proof is not receiptable: {proof_id}"));
        }
    }
    for session_id in &request.session_ids {
        if !batch.request.session_ids.contains(session_id) {
            return Err(format!("receipt session not in batch: {session_id}"));
        }
        if !session_proofs.contains_key(session_id) {
            return Err(format!("unknown session id: {session_id}"));
        }
    }
    for reservation_id in &request.reservation_ids {
        if !batch
            .request
            .sponsor_reservation_ids
            .contains(reservation_id)
        {
            return Err(format!(
                "receipt reservation not in batch: {reservation_id}"
            ));
        }
        let reservation = reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown sponsor reservation id: {reservation_id}"))?;
        if !reservation.status.active() {
            return Err(format!("reservation is not consumable: {reservation_id}"));
        }
    }
    Ok(())
}

fn validate_recovery_receipt_request(
    config: &Config,
    policies: &BTreeMap<String, ShieldedWalletPolicyRecord>,
    request: &PublishRecoveryReceiptRequest,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("policy_id", &request.policy_id)?;
    ensure_non_empty("recovery_payload_root", &request.recovery_payload_root)?;
    ensure_non_empty(
        "guardian_authorization_root",
        &request.guardian_authorization_root,
    )?;
    ensure_non_empty(
        "pq_recovery_signature_root",
        &request.pq_recovery_signature_root,
    )?;
    ensure_non_empty("recovery_nullifier", &request.recovery_nullifier)?;
    if matches!(request.action_kind, RecoveryActionKind::ReplacePolicyRoot) {
        ensure_non_empty("replacement_policy_root", &request.replacement_policy_root)?;
    }
    let policy = policies
        .get(&request.policy_id)
        .ok_or_else(|| "unknown policy id".to_string())?;
    if !policy.status.accepts_recovery_receipts() {
        return Err("policy does not accept recovery receipts".to_string());
    }
    ensure_future_expiry(
        "recovery receipt",
        request.published_at_height,
        request.expires_at_height,
        config.receipt_ttl_blocks,
    )
}

fn validate_violation_receipt_request(
    config: &Config,
    policies: &BTreeMap<String, ShieldedWalletPolicyRecord>,
    request: &PublishViolationReceiptRequest,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("policy_id", &request.policy_id)?;
    ensure_non_empty("target_id", &request.target_id)?;
    ensure_non_empty("evidence_root", &request.evidence_root)?;
    ensure_non_empty("challenged_proof_root", &request.challenged_proof_root)?;
    ensure_non_empty(
        "pq_challenge_signature_root",
        &request.pq_challenge_signature_root,
    )?;
    ensure_non_empty("penalty_commitment_root", &request.penalty_commitment_root)?;
    ensure_non_empty("violation_nullifier", &request.violation_nullifier)?;
    if config.require_pq_authorization && request.pq_challenge_signature_root.is_empty() {
        return Err("PQ challenge signature required".to_string());
    }
    if !policies.contains_key(&request.policy_id) {
        return Err("unknown policy id".to_string());
    }
    Ok(())
}

fn validate_rebate_receipt_request(
    config: &Config,
    reservations: &BTreeMap<String, LowFeeSponsorReservationRecord>,
    request: &PublishRebateReceiptRequest,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    ensure_non_empty("reservation_id", &request.reservation_id)?;
    ensure_non_empty("policy_id", &request.policy_id)?;
    ensure_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
    ensure_non_empty("beneficiary_commitment", &request.beneficiary_commitment)?;
    ensure_non_empty("rebate_asset_id", &request.rebate_asset_id)?;
    ensure_non_empty("rebate_commitment_root", &request.rebate_commitment_root)?;
    ensure_non_empty("fee_savings_root", &request.fee_savings_root)?;
    ensure_non_empty(
        "pq_rebate_signature_root",
        &request.pq_rebate_signature_root,
    )?;
    ensure_non_empty("rebate_nullifier", &request.rebate_nullifier)?;
    if request.rebate_asset_id != config.fee_asset_id {
        return Err("rebate asset does not match runtime fee asset".to_string());
    }
    let reservation = reservations
        .get(&request.reservation_id)
        .ok_or_else(|| "unknown sponsor reservation id".to_string())?;
    if !matches!(
        reservation.status,
        SponsorReservationStatus::Consumed | SponsorReservationStatus::Matched
    ) {
        return Err("reservation cannot receive rebate from current status".to_string());
    }
    if reservation.request.policy_id != request.policy_id {
        return Err("rebate policy id mismatches reservation".to_string());
    }
    if reservation.request.sponsor_commitment != request.sponsor_commitment {
        return Err("rebate sponsor commitment mismatches reservation".to_string());
    }
    if request.rebate_amount_units > reservation.request.reserved_fee_units {
        return Err("rebate amount exceeds reserved fee".to_string());
    }
    Ok(())
}

fn ensure_non_empty(name: &str, value: &str) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_min_u64(
    name: &str,
    value: u64,
    min: u64,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    if value < min {
        Err(format!("{name} must be at least {min}"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_WALLET_POLICY_PROOF_RUNTIME_MAX_BPS {
        Err(format!("{name} exceeds basis-point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(
    name: &str,
    current: usize,
    max: usize,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    if current >= max {
        Err(format!("{name} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_capacity_nonzero(
    name: &str,
    value: usize,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    if value == 0 {
        Err(format!("{name} must be greater than zero"))
    } else {
        Ok(())
    }
}

fn ensure_unique(name: &str, values: &[String]) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(name, value)?;
        if !seen.insert(value) {
            return Err(format!("{name} contains duplicate id {value}"));
        }
    }
    Ok(())
}

fn ensure_future_expiry(
    name: &str,
    start_height: u64,
    expires_at_height: u64,
    ttl_blocks: u64,
) -> PrivateL2PqWalletPolicyProofRuntimeResult<()> {
    if expires_at_height <= start_height {
        return Err(format!("{name} expiry must be in the future"));
    }
    if expires_at_height - start_height > ttl_blocks {
        return Err(format!("{name} ttl exceeds configured bound"));
    }
    Ok(())
}
