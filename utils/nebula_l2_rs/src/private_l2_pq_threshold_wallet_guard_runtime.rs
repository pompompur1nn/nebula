use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqThresholdWalletGuardRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-threshold-wallet-guard-runtime-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-threshold-wallet-guard-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_ACCOUNT_POLICY_SCHEME: &str =
    "shielded-wallet-account-policy-root-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_GUARDIAN_COMMITTEE_SCHEME: &str =
    "pq-guardian-threshold-committee-root-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECOVERY_INTENT_SCHEME: &str =
    "private-wallet-recovery-intent-root-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_REPLAY_FENCE_SCHEME: &str =
    "wallet-recovery-replay-nullifier-fence-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_LOW_FEE_SPONSOR_SCHEME: &str =
    "low-fee-wallet-recovery-sponsor-reservation-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_EXECUTION_BATCH_SCHEME: &str =
    "pq-threshold-wallet-recovery-execution-batch-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECEIPT_SCHEME: &str =
    "pq-threshold-wallet-recovery-receipt-root-v1";
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEVNET_HEIGHT: u64 = 720_000;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_ACCOUNT_POLICIES: usize =
    262_144;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_COMMITTEES: usize = 131_072;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_RECOVERY_INTENTS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_BATCHES: usize = 262_144;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_BATCH_INTENTS: usize = 4_096;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS: u64 = 43_200;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 360;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_GUARDIAN_COUNT: u16 = 3;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_THRESHOLD_WEIGHT_BPS: u64 =
    6_700;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_FAST_THRESHOLD_WEIGHT_BPS: u64 =
    8_000;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_RECOVERY_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_SPONSOR_COVERAGE_BPS: u64 = 9_000;
pub const PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedAccountPolicyKind {
    StandardWallet,
    HighValueVault,
    TradingAccount,
    BridgeAccount,
    GovernanceAccount,
    EmergencyRecoveryOnly,
}

impl ShieldedAccountPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandardWallet => "standard_wallet",
            Self::HighValueVault => "high_value_vault",
            Self::TradingAccount => "trading_account",
            Self::BridgeAccount => "bridge_account",
            Self::GovernanceAccount => "governance_account",
            Self::EmergencyRecoveryOnly => "emergency_recovery_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountPolicyStatus {
    Registered,
    Active,
    Rotating,
    Frozen,
    Retired,
    Slashed,
}

impl AccountPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_recovery(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianCommitteeStatus {
    Forming,
    Active,
    Rotating,
    Paused,
    Retired,
    Slashed,
}

impl GuardianCommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_authorize(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryIntentKind {
    RotateSpendKey,
    RotateViewKey,
    ReplaceGuardianSet,
    UnfreezeAccount,
    EmergencyEscape,
    SessionKeyReset,
    PolicyMigration,
}

impl RecoveryIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RotateSpendKey => "rotate_spend_key",
            Self::RotateViewKey => "rotate_view_key",
            Self::ReplaceGuardianSet => "replace_guardian_set",
            Self::UnfreezeAccount => "unfreeze_account",
            Self::EmergencyEscape => "emergency_escape",
            Self::SessionKeyReset => "session_key_reset",
            Self::PolicyMigration => "policy_migration",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryIntentStatus {
    Submitted,
    SponsorReserved,
    GuardianApproved,
    Batched,
    Executed,
    Expired,
    Cancelled,
    Rejected,
}

impl RecoveryIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::GuardianApproved => "guardian_approved",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::SponsorReserved | Self::GuardianApproved
        )
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::SponsorReserved | Self::GuardianApproved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Refunded,
    Expired,
    Cancelled,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryBatchStatus {
    Built,
    ProofQueued,
    Executed,
    Finalized,
    Expired,
    Rejected,
}

impl RecoveryBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::ProofQueued => "proof_queued",
            Self::Executed => "executed",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_execute(self) -> bool {
        matches!(self, Self::Built | Self::ProofQueued)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReceiptStatus {
    PendingFinality,
    Finalized,
    Challenged,
    Failed,
}

impl RecoveryReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingFinality => "pending_finality",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub account_policy_scheme: String,
    pub guardian_committee_scheme: String,
    pub recovery_intent_scheme: String,
    pub replay_fence_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub execution_batch_scheme: String,
    pub receipt_scheme: String,
    pub max_account_policies: usize,
    pub max_committees: usize,
    pub max_recovery_intents: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_batch_intents: usize,
    pub policy_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_guardian_count: u16,
    pub min_threshold_weight_bps: u64,
    pub fast_threshold_weight_bps: u64,
    pub max_recovery_fee_bps: u64,
    pub default_sponsor_coverage_bps: u64,
    pub require_low_fee_sponsor: bool,
    pub require_replay_fence: bool,
    pub require_roots_only: bool,
    pub current_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            low_fee_lane: "private-l2-pq-threshold-wallet-guard".to_string(),
            hash_suite: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PQ_SUITE.to_string(),
            account_policy_scheme:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_ACCOUNT_POLICY_SCHEME.to_string(),
            guardian_committee_scheme:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_GUARDIAN_COMMITTEE_SCHEME.to_string(),
            recovery_intent_scheme:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECOVERY_INTENT_SCHEME.to_string(),
            replay_fence_scheme: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_REPLAY_FENCE_SCHEME
                .to_string(),
            low_fee_sponsor_scheme:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_LOW_FEE_SPONSOR_SCHEME.to_string(),
            execution_batch_scheme:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_EXECUTION_BATCH_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECEIPT_SCHEME.to_string(),
            max_account_policies:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_ACCOUNT_POLICIES,
            max_committees: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_COMMITTEES,
            max_recovery_intents:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_RECOVERY_INTENTS,
            max_sponsor_reservations:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_intents:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_BATCH_INTENTS,
            policy_ttl_blocks:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS,
            intent_ttl_blocks:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            sponsor_ttl_blocks:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_guardian_count:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_GUARDIAN_COUNT,
            min_threshold_weight_bps:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MIN_THRESHOLD_WEIGHT_BPS,
            fast_threshold_weight_bps:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_FAST_THRESHOLD_WEIGHT_BPS,
            max_recovery_fee_bps:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_MAX_RECOVERY_FEE_BPS,
            default_sponsor_coverage_bps:
                PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEFAULT_SPONSOR_COVERAGE_BPS,
            require_low_fee_sponsor: true,
            require_replay_fence: true,
            require_roots_only: true,
            current_height: PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require(
            self.protocol_version == PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PROTOCOL_VERSION,
            "unsupported PQ threshold wallet guard protocol version",
        )?;
        require(self.schema_version > 0, "schema version must be positive")?;
        require_non_empty("chain_id", &self.chain_id)?;
        require(
            self.chain_id == CHAIN_ID,
            "PQ threshold wallet guard chain id mismatch",
        )?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("low_fee_lane", &self.low_fee_lane)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_suite", &self.pq_suite)?;
        require_non_empty("account_policy_scheme", &self.account_policy_scheme)?;
        require_non_empty("guardian_committee_scheme", &self.guardian_committee_scheme)?;
        require_non_empty("recovery_intent_scheme", &self.recovery_intent_scheme)?;
        require_non_empty("replay_fence_scheme", &self.replay_fence_scheme)?;
        require_non_empty("low_fee_sponsor_scheme", &self.low_fee_sponsor_scheme)?;
        require_non_empty("execution_batch_scheme", &self.execution_batch_scheme)?;
        require_non_empty("receipt_scheme", &self.receipt_scheme)?;
        require(
            self.max_account_policies > 0,
            "policy capacity must be positive",
        )?;
        require(
            self.max_committees > 0,
            "committee capacity must be positive",
        )?;
        require(
            self.max_recovery_intents > 0,
            "recovery intent capacity must be positive",
        )?;
        require(
            self.max_sponsor_reservations > 0,
            "sponsor reservation capacity must be positive",
        )?;
        require(self.max_batches > 0, "batch capacity must be positive")?;
        require(self.max_receipts > 0, "receipt capacity must be positive")?;
        require(
            self.max_batch_intents > 0 && self.max_batch_intents <= self.max_recovery_intents,
            "batch intent capacity is invalid",
        )?;
        require(
            self.policy_ttl_blocks > 0
                && self.intent_ttl_blocks > 0
                && self.sponsor_ttl_blocks > 0
                && self.batch_ttl_blocks > 0,
            "block windows must be positive",
        )?;
        require(
            self.min_privacy_set_size > 0
                && self.batch_privacy_set_size >= self.min_privacy_set_size,
            "privacy set policy is invalid",
        )?;
        require(
            self.min_pq_security_bits >= 192,
            "PQ security floor is too low",
        )?;
        require(
            self.min_guardian_count > 0,
            "guardian count floor must be positive",
        )?;
        require_bps("min_threshold_weight_bps", self.min_threshold_weight_bps)?;
        require_bps("fast_threshold_weight_bps", self.fast_threshold_weight_bps)?;
        require_bps("max_recovery_fee_bps", self.max_recovery_fee_bps)?;
        require_bps(
            "default_sponsor_coverage_bps",
            self.default_sponsor_coverage_bps,
        )?;
        require(
            self.fast_threshold_weight_bps >= self.min_threshold_weight_bps,
            "fast threshold cannot be below minimum threshold",
        )?;
        require(
            self.require_roots_only,
            "PQ threshold wallet guard requires roots-only private records",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_threshold_wallet_guard_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "account_policy_scheme": self.account_policy_scheme,
            "guardian_committee_scheme": self.guardian_committee_scheme,
            "recovery_intent_scheme": self.recovery_intent_scheme,
            "replay_fence_scheme": self.replay_fence_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
            "execution_batch_scheme": self.execution_batch_scheme,
            "receipt_scheme": self.receipt_scheme,
            "max_account_policies": self.max_account_policies,
            "max_committees": self.max_committees,
            "max_recovery_intents": self.max_recovery_intents,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_batch_intents": self.max_batch_intents,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_guardian_count": self.min_guardian_count,
            "min_threshold_weight_bps": self.min_threshold_weight_bps,
            "fast_threshold_weight_bps": self.fast_threshold_weight_bps,
            "max_recovery_fee_bps": self.max_recovery_fee_bps,
            "default_sponsor_coverage_bps": self.default_sponsor_coverage_bps,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_replay_fence": self.require_replay_fence,
            "require_roots_only": self.require_roots_only,
            "current_height": self.current_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_account_policy: u64,
    pub next_guardian_committee: u64,
    pub next_recovery_intent: u64,
    pub next_sponsor_reservation: u64,
    pub next_execution_batch: u64,
    pub next_receipt: u64,
    pub policies_registered: u64,
    pub committees_registered: u64,
    pub recovery_intents_submitted: u64,
    pub recovery_intents_approved: u64,
    pub recovery_intents_batched: u64,
    pub recovery_intents_executed: u64,
    pub recovery_intents_expired: u64,
    pub replay_rejections: u64,
    pub sponsor_reservations_created: u64,
    pub sponsor_reservations_consumed: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub consumed_nullifiers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_account_policy": self.next_account_policy,
            "next_guardian_committee": self.next_guardian_committee,
            "next_recovery_intent": self.next_recovery_intent,
            "next_sponsor_reservation": self.next_sponsor_reservation,
            "next_execution_batch": self.next_execution_batch,
            "next_receipt": self.next_receipt,
            "policies_registered": self.policies_registered,
            "committees_registered": self.committees_registered,
            "recovery_intents_submitted": self.recovery_intents_submitted,
            "recovery_intents_approved": self.recovery_intents_approved,
            "recovery_intents_batched": self.recovery_intents_batched,
            "recovery_intents_executed": self.recovery_intents_executed,
            "recovery_intents_expired": self.recovery_intents_expired,
            "replay_rejections": self.replay_rejections,
            "sponsor_reservations_created": self.sponsor_reservations_created,
            "sponsor_reservations_consumed": self.sponsor_reservations_consumed,
            "batches_built": self.batches_built,
            "receipts_published": self.receipts_published,
            "consumed_nullifiers": self.consumed_nullifiers,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterShieldedAccountPolicyRequest {
    pub policy_kind: ShieldedAccountPolicyKind,
    pub account_commitment: String,
    pub wallet_policy_root: String,
    pub spend_policy_root: String,
    pub recovery_policy_root: String,
    pub guardian_committee_root: String,
    pub allowed_recovery_action_root: String,
    pub blocked_action_root: String,
    pub account_state_root: String,
    pub view_key_policy_root: String,
    pub metadata_root: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub policy_nonce: String,
}

impl RegisterShieldedAccountPolicyRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_root("wallet_policy_root", &self.wallet_policy_root)?;
        require_root("spend_policy_root", &self.spend_policy_root)?;
        require_root("recovery_policy_root", &self.recovery_policy_root)?;
        require_root("guardian_committee_root", &self.guardian_committee_root)?;
        require_root(
            "allowed_recovery_action_root",
            &self.allowed_recovery_action_root,
        )?;
        require_root("blocked_action_root", &self.blocked_action_root)?;
        require_root("account_state_root", &self.account_state_root)?;
        require_root("view_key_policy_root", &self.view_key_policy_root)?;
        require_root("metadata_root", &self.metadata_root)?;
        require_non_empty("policy_nonce", &self.policy_nonce)?;
        require(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "account policy privacy set below minimum",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "account policy PQ security below minimum",
        )?;
        require(
            self.expires_at_height > self.registered_at_height,
            "account policy expiry must follow registration height",
        )?;
        require(
            self.expires_at_height
                <= self
                    .registered_at_height
                    .saturating_add(config.policy_ttl_blocks),
            "account policy ttl exceeds config",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_kind": self.policy_kind.as_str(),
            "account_commitment": self.account_commitment,
            "wallet_policy_root": self.wallet_policy_root,
            "spend_policy_root": self.spend_policy_root,
            "recovery_policy_root": self.recovery_policy_root,
            "guardian_committee_root": self.guardian_committee_root,
            "allowed_recovery_action_root": self.allowed_recovery_action_root,
            "blocked_action_root": self.blocked_action_root,
            "account_state_root": self.account_state_root,
            "view_key_policy_root": self.view_key_policy_root,
            "metadata_root": self.metadata_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPqGuardianCommitteeRequest {
    pub committee_label: String,
    pub guardian_set_root: String,
    pub guardian_weight_root: String,
    pub pq_public_key_root: String,
    pub threshold_policy_root: String,
    pub operator_set_root: String,
    pub slashing_policy_root: String,
    pub epoch: u64,
    pub guardian_count: u16,
    pub threshold_weight_bps: u64,
    pub fast_threshold_weight_bps: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
}

impl RegisterPqGuardianCommitteeRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        require_non_empty("committee_label", &self.committee_label)?;
        require_root("guardian_set_root", &self.guardian_set_root)?;
        require_root("guardian_weight_root", &self.guardian_weight_root)?;
        require_root("pq_public_key_root", &self.pq_public_key_root)?;
        require_root("threshold_policy_root", &self.threshold_policy_root)?;
        require_root("operator_set_root", &self.operator_set_root)?;
        require_root("slashing_policy_root", &self.slashing_policy_root)?;
        require(
            self.guardian_count >= config.min_guardian_count,
            "guardian committee count below minimum",
        )?;
        require_bps("threshold_weight_bps", self.threshold_weight_bps)?;
        require_bps("fast_threshold_weight_bps", self.fast_threshold_weight_bps)?;
        require(
            self.threshold_weight_bps >= config.min_threshold_weight_bps,
            "guardian threshold below minimum",
        )?;
        require(
            self.fast_threshold_weight_bps >= self.threshold_weight_bps
                && self.fast_threshold_weight_bps >= config.fast_threshold_weight_bps,
            "fast guardian threshold is invalid",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "guardian committee PQ security below minimum",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_label": self.committee_label,
            "guardian_set_root": self.guardian_set_root,
            "guardian_weight_root": self.guardian_weight_root,
            "pq_public_key_root": self.pq_public_key_root,
            "threshold_policy_root": self.threshold_policy_root,
            "operator_set_root": self.operator_set_root,
            "slashing_policy_root": self.slashing_policy_root,
            "epoch": self.epoch,
            "guardian_count": self.guardian_count,
            "threshold_weight_bps": self.threshold_weight_bps,
            "fast_threshold_weight_bps": self.fast_threshold_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPrivateRecoveryIntentRequest {
    pub intent_kind: RecoveryIntentKind,
    pub account_policy_id: String,
    pub guardian_committee_id: String,
    pub account_commitment: String,
    pub encrypted_recovery_payload_root: String,
    pub target_account_state_root: String,
    pub recovery_action_root: String,
    pub guardian_authorization_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub replay_nullifier: String,
    pub recovery_nullifier: String,
    pub replay_fence_root: String,
    pub low_fee_sponsor_root: Option<String>,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitPrivateRecoveryIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        require_root("account_policy_id", &self.account_policy_id)?;
        require_root("guardian_committee_id", &self.guardian_committee_id)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_root(
            "encrypted_recovery_payload_root",
            &self.encrypted_recovery_payload_root,
        )?;
        require_root("target_account_state_root", &self.target_account_state_root)?;
        require_root("recovery_action_root", &self.recovery_action_root)?;
        require_root(
            "guardian_authorization_root",
            &self.guardian_authorization_root,
        )?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_root("privacy_proof_root", &self.privacy_proof_root)?;
        require_non_empty("replay_nullifier", &self.replay_nullifier)?;
        require_non_empty("recovery_nullifier", &self.recovery_nullifier)?;
        require_root("replay_fence_root", &self.replay_fence_root)?;
        if config.require_low_fee_sponsor {
            match &self.low_fee_sponsor_root {
                Some(root) => require_root("low_fee_sponsor_root", root)?,
                None => return Err("low fee sponsor root is required".to_string()),
            }
        }
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_recovery_fee_bps,
            "recovery intent fee exceeds cap",
        )?;
        require_privacy_and_pq(self.privacy_set_size, self.pq_security_bits, config)?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "recovery intent expiry must follow submission height",
        )?;
        require(
            self.expires_at_height
                <= self
                    .submitted_at_height
                    .saturating_add(config.intent_ttl_blocks),
            "recovery intent ttl exceeds config",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_kind": self.intent_kind.as_str(),
            "account_policy_id": self.account_policy_id,
            "guardian_committee_id": self.guardian_committee_id,
            "account_commitment": self.account_commitment,
            "encrypted_recovery_payload_root": self.encrypted_recovery_payload_root,
            "target_account_state_root": self.target_account_state_root,
            "recovery_action_root": self.recovery_action_root,
            "guardian_authorization_root": self.guardian_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeSponsorRequest {
    pub recovery_intent_id: String,
    pub sponsor_commitment: String,
    pub sponsor_policy_root: String,
    pub fee_credit_root: String,
    pub rebate_commitment_root: String,
    pub sponsor_pq_authorization_root: String,
    pub route_nullifier: String,
    pub coverage_bps: u64,
    pub max_fee_bps: u64,
    pub credit_micro_units: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveLowFeeSponsorRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        require_root("recovery_intent_id", &self.recovery_intent_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_root("sponsor_policy_root", &self.sponsor_policy_root)?;
        require_root("fee_credit_root", &self.fee_credit_root)?;
        require_root("rebate_commitment_root", &self.rebate_commitment_root)?;
        require_root(
            "sponsor_pq_authorization_root",
            &self.sponsor_pq_authorization_root,
        )?;
        require_non_empty("route_nullifier", &self.route_nullifier)?;
        require_bps("coverage_bps", self.coverage_bps)?;
        require(self.coverage_bps > 0, "coverage bps must be positive")?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_recovery_fee_bps,
            "sponsor fee exceeds cap",
        )?;
        require(
            self.credit_micro_units > 0,
            "sponsor credit must be positive",
        )?;
        require(
            self.expires_at_height > self.reserved_at_height,
            "sponsor reservation expiry must follow reservation height",
        )?;
        require(
            self.expires_at_height
                <= self
                    .reserved_at_height
                    .saturating_add(config.sponsor_ttl_blocks),
            "sponsor reservation ttl exceeds config",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "recovery_intent_id": self.recovery_intent_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_policy_root": self.sponsor_policy_root,
            "fee_credit_root": self.fee_credit_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "sponsor_pq_authorization_root": self.sponsor_pq_authorization_root,
            "coverage_bps": self.coverage_bps,
            "max_fee_bps": self.max_fee_bps,
            "credit_micro_units": self.credit_micro_units,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRecoveryExecutionBatchRequest {
    pub recovery_intent_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub builder_commitment: String,
    pub batch_witness_root: String,
    pub batch_proof_root: String,
    pub aggregate_guardian_authorization_root: String,
    pub aggregate_pq_signature_root: String,
    pub aggregate_privacy_proof_root: String,
    pub recovery_action_root: String,
    pub target_account_state_root: String,
    pub fee_credit_root: String,
    pub replay_fence_consumption_root: String,
    pub batch_nullifier: String,
    pub sealed_at_height: u64,
}

impl BuildRecoveryExecutionBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        require(
            !self.recovery_intent_ids.is_empty(),
            "recovery batch requires intents",
        )?;
        require(
            self.recovery_intent_ids.len() <= config.max_batch_intents,
            "recovery batch exceeds max intents",
        )?;
        require_unique("recovery_intent_ids", &self.recovery_intent_ids)?;
        require_unique("sponsor_reservation_ids", &self.sponsor_reservation_ids)?;
        require_non_empty("builder_commitment", &self.builder_commitment)?;
        require_root("batch_witness_root", &self.batch_witness_root)?;
        require_root("batch_proof_root", &self.batch_proof_root)?;
        require_root(
            "aggregate_guardian_authorization_root",
            &self.aggregate_guardian_authorization_root,
        )?;
        require_root(
            "aggregate_pq_signature_root",
            &self.aggregate_pq_signature_root,
        )?;
        require_root(
            "aggregate_privacy_proof_root",
            &self.aggregate_privacy_proof_root,
        )?;
        require_root("recovery_action_root", &self.recovery_action_root)?;
        require_root("target_account_state_root", &self.target_account_state_root)?;
        require_root("fee_credit_root", &self.fee_credit_root)?;
        require_root(
            "replay_fence_consumption_root",
            &self.replay_fence_consumption_root,
        )?;
        require_non_empty("batch_nullifier", &self.batch_nullifier)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "recovery_intent_ids": self.recovery_intent_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "builder_commitment": self.builder_commitment,
            "batch_witness_root": self.batch_witness_root,
            "batch_proof_root": self.batch_proof_root,
            "aggregate_guardian_authorization_root": self.aggregate_guardian_authorization_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "recovery_action_root": self.recovery_action_root,
            "target_account_state_root": self.target_account_state_root,
            "fee_credit_root": self.fee_credit_root,
            "replay_fence_consumption_root": self.replay_fence_consumption_root,
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishRecoveryReceiptRequest {
    pub batch_id: String,
    pub execution_tx_root: String,
    pub execution_proof_root: String,
    pub execution_witness_root: String,
    pub recovered_account_state_root: String,
    pub spent_recovery_nullifier_root: String,
    pub fee_spend_root: String,
    pub sponsor_rebate_root: String,
    pub state_transition_root: String,
    pub runtime_state_root_after: String,
    pub receipt_status: RecoveryReceiptStatus,
    pub executed_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub receipt_nullifier: String,
}

impl PublishRecoveryReceiptRequest {
    pub fn validate(&self) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        require_root("batch_id", &self.batch_id)?;
        require_root("execution_tx_root", &self.execution_tx_root)?;
        require_root("execution_proof_root", &self.execution_proof_root)?;
        require_root("execution_witness_root", &self.execution_witness_root)?;
        require_root(
            "recovered_account_state_root",
            &self.recovered_account_state_root,
        )?;
        require_root(
            "spent_recovery_nullifier_root",
            &self.spent_recovery_nullifier_root,
        )?;
        require_root("fee_spend_root", &self.fee_spend_root)?;
        require_root("sponsor_rebate_root", &self.sponsor_rebate_root)?;
        require_root("state_transition_root", &self.state_transition_root)?;
        require_root("runtime_state_root_after", &self.runtime_state_root_after)?;
        require_non_empty("receipt_nullifier", &self.receipt_nullifier)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "execution_tx_root": self.execution_tx_root,
            "execution_proof_root": self.execution_proof_root,
            "execution_witness_root": self.execution_witness_root,
            "recovered_account_state_root": self.recovered_account_state_root,
            "spent_recovery_nullifier_root": self.spent_recovery_nullifier_root,
            "fee_spend_root": self.fee_spend_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "state_transition_root": self.state_transition_root,
            "runtime_state_root_after": self.runtime_state_root_after,
            "receipt_status": self.receipt_status.as_str(),
            "executed_at_height": self.executed_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAccountPolicyRecord {
    pub account_policy_id: String,
    pub sequence: u64,
    pub status: AccountPolicyStatus,
    pub request: RegisterShieldedAccountPolicyRequest,
    pub policy_root: String,
    pub updated_at_height: u64,
}

impl ShieldedAccountPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "account_policy_id": self.account_policy_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "policy_root": self.policy_root,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGuardianCommitteeRecord {
    pub guardian_committee_id: String,
    pub sequence: u64,
    pub status: GuardianCommitteeStatus,
    pub request: RegisterPqGuardianCommitteeRequest,
    pub committee_root: String,
    pub updated_at_height: u64,
}

impl PqGuardianCommitteeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "guardian_committee_id": self.guardian_committee_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "committee_root": self.committee_root,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRecoveryIntentRecord {
    pub recovery_intent_id: String,
    pub sequence: u64,
    pub status: RecoveryIntentStatus,
    pub request: SubmitPrivateRecoveryIntentRequest,
    pub intent_root: String,
    pub sponsor_reservation_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub updated_at_height: u64,
}

impl PrivateRecoveryIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "recovery_intent_id": self.recovery_intent_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "intent_root": self.intent_root,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorReservationRecord {
    pub sponsor_reservation_id: String,
    pub sequence: u64,
    pub status: SponsorReservationStatus,
    pub request: ReserveLowFeeSponsorRequest,
    pub reservation_root: String,
    pub consumed_at_height: Option<u64>,
}

impl LowFeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "reservation_root": self.reservation_root,
            "consumed_at_height": self.consumed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryExecutionBatchRecord {
    pub batch_id: String,
    pub sequence: u64,
    pub status: RecoveryBatchStatus,
    pub request: BuildRecoveryExecutionBatchRequest,
    pub intent_root: String,
    pub sponsor_reservation_root: String,
    pub batch_root: String,
    pub total_sponsor_credit_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub settlement_deadline_height: u64,
}

impl RecoveryExecutionBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "intent_root": self.intent_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "batch_root": self.batch_root,
            "total_sponsor_credit_micro_units": self.total_sponsor_credit_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReceiptRecord {
    pub receipt_id: String,
    pub sequence: u64,
    pub status: RecoveryReceiptStatus,
    pub request: PublishRecoveryReceiptRequest,
    pub batch_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub runtime_state_root_before: String,
    pub receipt_root: String,
}

impl RecoveryReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "batch_root": self.batch_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "runtime_state_root_before": self.runtime_state_root_before,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub account_policy_root: String,
    pub guardian_committee_root: String,
    pub recovery_intent_root: String,
    pub sponsor_reservation_root: String,
    pub execution_batch_root: String,
    pub receipt_root: String,
    pub replay_nullifier_root: String,
    pub consumed_nullifier_root: String,
    pub account_state_root: String,
    pub guardian_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "account_policy_root": self.account_policy_root,
            "guardian_committee_root": self.guardian_committee_root,
            "recovery_intent_root": self.recovery_intent_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "execution_batch_root": self.execution_batch_root,
            "receipt_root": self.receipt_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "account_state_root": self.account_state_root,
            "guardian_authorization_root": self.guardian_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub account_policies: BTreeMap<String, ShieldedAccountPolicyRecord>,
    pub guardian_committees: BTreeMap<String, PqGuardianCommitteeRecord>,
    pub recovery_intents: BTreeMap<String, PrivateRecoveryIntentRecord>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservationRecord>,
    pub execution_batches: BTreeMap<String, RecoveryExecutionBatchRecord>,
    pub receipts: BTreeMap<String, RecoveryReceiptRecord>,
    pub replay_nullifiers: BTreeSet<String>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqThresholdWalletGuardRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2PqThresholdWalletGuardRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            current_height: config.current_height,
            runtime_root: empty_runtime_root(),
            config,
            counters: Counters::default(),
            account_policies: BTreeMap::new(),
            guardian_committees: BTreeMap::new(),
            recovery_intents: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_account_policy(
        &mut self,
        request: RegisterShieldedAccountPolicyRequest,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<ShieldedAccountPolicyRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.account_policies.len() < self.config.max_account_policies,
            "account policy capacity exhausted",
        )?;
        let sequence = self.counters.next_account_policy;
        self.counters.next_account_policy = self.counters.next_account_policy.saturating_add(1);
        let account_policy_id = shielded_account_policy_id(&request, sequence);
        let policy_root = payload_root(
            PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_ACCOUNT_POLICY_SCHEME,
            &json!({
                "account_policy_id": account_policy_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        let record = ShieldedAccountPolicyRecord {
            account_policy_id: account_policy_id.clone(),
            sequence,
            status: AccountPolicyStatus::Active,
            updated_at_height: request.registered_at_height,
            request,
            policy_root,
        };
        self.current_height = self.current_height.max(record.updated_at_height);
        self.account_policies
            .insert(account_policy_id, record.clone());
        self.counters.policies_registered = self.counters.policies_registered.saturating_add(1);
        Ok(record)
    }

    pub fn register_guardian_committee(
        &mut self,
        request: RegisterPqGuardianCommitteeRequest,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<PqGuardianCommitteeRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.guardian_committees.len() < self.config.max_committees,
            "guardian committee capacity exhausted",
        )?;
        let sequence = self.counters.next_guardian_committee;
        self.counters.next_guardian_committee =
            self.counters.next_guardian_committee.saturating_add(1);
        let guardian_committee_id = pq_guardian_committee_id(&request, sequence);
        let committee_root = payload_root(
            PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_GUARDIAN_COMMITTEE_SCHEME,
            &json!({
                "guardian_committee_id": guardian_committee_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        let record = PqGuardianCommitteeRecord {
            guardian_committee_id: guardian_committee_id.clone(),
            sequence,
            status: GuardianCommitteeStatus::Active,
            updated_at_height: request.registered_at_height,
            request,
            committee_root,
        };
        self.current_height = self.current_height.max(record.updated_at_height);
        self.guardian_committees
            .insert(guardian_committee_id, record.clone());
        self.counters.committees_registered = self.counters.committees_registered.saturating_add(1);
        Ok(record)
    }

    pub fn submit_recovery_intent(
        &mut self,
        request: SubmitPrivateRecoveryIntentRequest,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<PrivateRecoveryIntentRecord> {
        self.config.validate()?;
        self.expire_stale(request.submitted_at_height);
        request.validate(&self.config)?;
        require(
            self.recovery_intents.len() < self.config.max_recovery_intents,
            "recovery intent capacity exhausted",
        )?;
        let policy = self
            .account_policies
            .get(&request.account_policy_id)
            .ok_or_else(|| "recovery intent references unknown account policy".to_string())?;
        require(
            policy.status.accepts_recovery(),
            "account policy does not accept recovery intents",
        )?;
        let committee = self
            .guardian_committees
            .get(&request.guardian_committee_id)
            .ok_or_else(|| "recovery intent references unknown guardian committee".to_string())?;
        require(
            committee.status.can_authorize(),
            "guardian committee cannot authorize recovery intents",
        )?;
        self.insert_replay_nullifier(&request.replay_nullifier)?;
        let sequence = self.counters.next_recovery_intent;
        self.counters.next_recovery_intent = self.counters.next_recovery_intent.saturating_add(1);
        let recovery_intent_id = private_recovery_intent_id(&request, sequence);
        let intent_root = payload_root(
            PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECOVERY_INTENT_SCHEME,
            &json!({
                "recovery_intent_id": recovery_intent_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        let record = PrivateRecoveryIntentRecord {
            recovery_intent_id: recovery_intent_id.clone(),
            sequence,
            status: RecoveryIntentStatus::GuardianApproved,
            updated_at_height: request.submitted_at_height,
            request,
            intent_root,
            sponsor_reservation_id: None,
            batch_id: None,
            receipt_id: None,
        };
        self.current_height = self.current_height.max(record.updated_at_height);
        self.recovery_intents
            .insert(recovery_intent_id, record.clone());
        self.counters.recovery_intents_submitted =
            self.counters.recovery_intents_submitted.saturating_add(1);
        self.counters.recovery_intents_approved =
            self.counters.recovery_intents_approved.saturating_add(1);
        Ok(record)
    }

    pub fn reserve_low_fee_sponsor(
        &mut self,
        request: ReserveLowFeeSponsorRequest,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<LowFeeSponsorReservationRecord> {
        self.config.validate()?;
        self.expire_stale(request.reserved_at_height);
        request.validate(&self.config)?;
        require(
            self.sponsor_reservations.len() < self.config.max_sponsor_reservations,
            "sponsor reservation capacity exhausted",
        )?;
        let intent_status_live = self
            .recovery_intents
            .get(&request.recovery_intent_id)
            .ok_or_else(|| "sponsor reservation references unknown recovery intent".to_string())?
            .status
            .live();
        require(
            intent_status_live,
            "sponsor reservation references non-live recovery intent",
        )?;
        self.insert_consumed_nullifier("SPONSOR_ROUTE", &request.route_nullifier)?;
        let reserved_at_height = request.reserved_at_height;
        let sequence = self.counters.next_sponsor_reservation;
        self.counters.next_sponsor_reservation =
            self.counters.next_sponsor_reservation.saturating_add(1);
        let sponsor_reservation_id = low_fee_sponsor_reservation_id(&request, sequence);
        let reservation_root = payload_root(
            PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_LOW_FEE_SPONSOR_SCHEME,
            &json!({
                "sponsor_reservation_id": sponsor_reservation_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        let intent = self
            .recovery_intents
            .get_mut(&request.recovery_intent_id)
            .ok_or_else(|| "sponsor reservation references unknown recovery intent".to_string())?;
        intent.status = RecoveryIntentStatus::SponsorReserved;
        intent.sponsor_reservation_id = Some(sponsor_reservation_id.clone());
        intent.updated_at_height = reserved_at_height;
        let record = LowFeeSponsorReservationRecord {
            sponsor_reservation_id: sponsor_reservation_id.clone(),
            sequence,
            status: SponsorReservationStatus::Reserved,
            request,
            reservation_root,
            consumed_at_height: None,
        };
        self.current_height = self.current_height.max(reserved_at_height);
        self.sponsor_reservations
            .insert(sponsor_reservation_id, record.clone());
        self.counters.sponsor_reservations_created =
            self.counters.sponsor_reservations_created.saturating_add(1);
        Ok(record)
    }

    pub fn build_recovery_execution_batch(
        &mut self,
        request: BuildRecoveryExecutionBatchRequest,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<RecoveryExecutionBatchRecord> {
        self.config.validate()?;
        self.expire_stale(request.sealed_at_height);
        request.validate(&self.config)?;
        require(
            self.execution_batches.len() < self.config.max_batches,
            "execution batch capacity exhausted",
        )?;
        let mut intent_records = Vec::with_capacity(request.recovery_intent_ids.len());
        for intent_id in &request.recovery_intent_ids {
            let intent = self
                .recovery_intents
                .get(intent_id)
                .cloned()
                .ok_or_else(|| format!("unknown recovery intent {intent_id}"))?;
            require(
                intent.status.batchable(),
                "recovery intent is not batchable",
            )?;
            require(
                request.sealed_at_height <= intent.request.expires_at_height,
                "recovery intent expired before batch",
            )?;
            if self.config.require_low_fee_sponsor {
                require(
                    intent.sponsor_reservation_id.is_some(),
                    "recovery intent requires sponsor reservation",
                )?;
            }
            intent_records.push(intent);
        }
        for reservation_id in &request.sponsor_reservation_ids {
            let reservation = self
                .sponsor_reservations
                .get(reservation_id)
                .ok_or_else(|| format!("unknown sponsor reservation {reservation_id}"))?;
            require(
                matches!(reservation.status, SponsorReservationStatus::Reserved),
                "sponsor reservation is not available",
            )?;
            require(
                request.sealed_at_height <= reservation.request.expires_at_height,
                "sponsor reservation expired before batch",
            )?;
        }
        self.insert_consumed_nullifier("BATCH", &request.batch_nullifier)?;
        let intent_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-BATCH-INTENTS",
            &intent_records
                .iter()
                .map(PrivateRecoveryIntentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_records = request
            .sponsor_reservation_ids
            .iter()
            .filter_map(|reservation_id| self.sponsor_reservations.get(reservation_id))
            .map(LowFeeSponsorReservationRecord::public_record)
            .collect::<Vec<_>>();
        let sponsor_reservation_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-BATCH-SPONSORS",
            &sponsor_records,
        );
        let total_sponsor_credit_micro_units = request
            .sponsor_reservation_ids
            .iter()
            .filter_map(|reservation_id| self.sponsor_reservations.get(reservation_id))
            .map(|reservation| reservation.request.credit_micro_units)
            .sum::<u64>();
        let min_privacy_set_size = intent_records
            .iter()
            .map(|intent| intent.request.privacy_set_size)
            .min()
            .unwrap_or_default();
        let max_fee_bps = intent_records
            .iter()
            .map(|intent| intent.request.max_fee_bps)
            .max()
            .unwrap_or_default();
        require(
            min_privacy_set_size >= self.config.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        let sequence = self.counters.next_execution_batch;
        self.counters.next_execution_batch = self.counters.next_execution_batch.saturating_add(1);
        let batch_id = recovery_execution_batch_id(&request, &intent_root, sequence);
        let sealed_at_height = request.sealed_at_height;
        let batch_root = payload_root(
            PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_EXECUTION_BATCH_SCHEME,
            &json!({
                "batch_id": batch_id,
                "sequence": sequence,
                "intent_root": intent_root,
                "sponsor_reservation_root": sponsor_reservation_root,
                "request": request.public_record(),
            }),
        );
        for intent_id in &request.recovery_intent_ids {
            if let Some(intent) = self.recovery_intents.get_mut(intent_id) {
                intent.status = RecoveryIntentStatus::Batched;
                intent.batch_id = Some(batch_id.clone());
                intent.updated_at_height = request.sealed_at_height;
            }
        }
        for reservation_id in &request.sponsor_reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Matched;
            }
        }
        let record = RecoveryExecutionBatchRecord {
            batch_id: batch_id.clone(),
            sequence,
            status: RecoveryBatchStatus::Built,
            request,
            intent_root,
            sponsor_reservation_root,
            batch_root,
            total_sponsor_credit_micro_units,
            min_privacy_set_size,
            max_fee_bps,
            settlement_deadline_height: sealed_at_height
                .saturating_add(self.config.batch_ttl_blocks),
        };
        self.current_height = self.current_height.max(record.request.sealed_at_height);
        self.execution_batches.insert(batch_id, record.clone());
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.counters.recovery_intents_batched = self
            .counters
            .recovery_intents_batched
            .saturating_add(record.request.recovery_intent_ids.len() as u64);
        Ok(record)
    }

    pub fn publish_recovery_receipt(
        &mut self,
        request: PublishRecoveryReceiptRequest,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<RecoveryReceiptRecord> {
        self.config.validate()?;
        self.expire_stale(request.executed_at_height);
        request.validate()?;
        require(
            self.receipts.len() < self.config.max_receipts,
            "recovery receipt capacity exhausted",
        )?;
        let state_root_before = self.state_root();
        let runtime_state_root_before = self.runtime_root.clone();
        let batch = self
            .execution_batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| "recovery receipt references unknown batch".to_string())?;
        require(
            batch.status.can_execute(),
            "recovery batch is not executable",
        )?;
        require(
            request.executed_at_height <= batch.settlement_deadline_height,
            "recovery batch execution deadline elapsed",
        )?;
        self.insert_consumed_nullifier("RECEIPT", &request.receipt_nullifier)?;
        let sequence = self.counters.next_receipt;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        let receipt_id = recovery_receipt_id(&request, sequence);
        if let Some(batch_record) = self.execution_batches.get_mut(&request.batch_id) {
            batch_record.status = match request.receipt_status {
                RecoveryReceiptStatus::PendingFinality => RecoveryBatchStatus::Executed,
                RecoveryReceiptStatus::Finalized => RecoveryBatchStatus::Finalized,
                RecoveryReceiptStatus::Challenged | RecoveryReceiptStatus::Failed => {
                    RecoveryBatchStatus::Rejected
                }
            };
        }
        for intent_id in &batch.request.recovery_intent_ids {
            if let Some(intent) = self.recovery_intents.get_mut(intent_id) {
                intent.status = match request.receipt_status {
                    RecoveryReceiptStatus::PendingFinality | RecoveryReceiptStatus::Finalized => {
                        RecoveryIntentStatus::Executed
                    }
                    RecoveryReceiptStatus::Challenged | RecoveryReceiptStatus::Failed => {
                        RecoveryIntentStatus::Rejected
                    }
                };
                intent.receipt_id = Some(receipt_id.clone());
                intent.updated_at_height = request.executed_at_height;
            }
        }
        for reservation_id in &batch.request.sponsor_reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
                reservation.consumed_at_height = Some(request.executed_at_height);
                self.counters.sponsor_reservations_consumed = self
                    .counters
                    .sponsor_reservations_consumed
                    .saturating_add(1);
            }
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        self.current_height = self.current_height.max(request.executed_at_height);
        let receipt_root = payload_root(
            PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECEIPT_SCHEME,
            &json!({
                "receipt_id": receipt_id,
                "sequence": sequence,
                "request": request.public_record(),
                "batch_root": batch.batch_root,
                "state_root_before": state_root_before,
            }),
        );
        let state_root_after = self.state_root();
        let record = RecoveryReceiptRecord {
            receipt_id: receipt_id.clone(),
            sequence,
            status: request.receipt_status,
            request,
            batch_root: batch.batch_root,
            state_root_before,
            state_root_after,
            runtime_state_root_before,
            receipt_root,
        };
        self.receipts.insert(receipt_id, record.clone());
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        if matches!(
            record.status,
            RecoveryReceiptStatus::PendingFinality | RecoveryReceiptStatus::Finalized
        ) {
            self.counters.recovery_intents_executed = self
                .counters
                .recovery_intents_executed
                .saturating_add(batch.request.recovery_intent_ids.len() as u64);
        }
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = root_from_record(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-COUNTERS",
            &self.counters.public_record(),
        );
        let account_policy_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-ACCOUNT-POLICIES",
            &self
                .account_policies
                .values()
                .map(ShieldedAccountPolicyRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let guardian_committee_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-GUARDIAN-COMMITTEES",
            &self
                .guardian_committees
                .values()
                .map(PqGuardianCommitteeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let recovery_intent_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-RECOVERY-INTENTS",
            &self
                .recovery_intents
                .values()
                .map(PrivateRecoveryIntentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-SPONSOR-RESERVATIONS",
            &self
                .sponsor_reservations
                .values()
                .map(LowFeeSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let execution_batch_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-EXECUTION-BATCHES",
            &self
                .execution_batches
                .values()
                .map(RecoveryExecutionBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-RECEIPTS",
            &self
                .receipts
                .values()
                .map(RecoveryReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let replay_nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-REPLAY-NULLIFIERS",
            &self
                .replay_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let consumed_nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-CONSUMED-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let account_state_root = merkle_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-ACCOUNT-STATES",
            &self
                .account_policies
                .values()
                .map(|policy| {
                    json!({
                        "account_policy_id": policy.account_policy_id,
                        "account_commitment": policy.request.account_commitment,
                        "account_state_root": policy.request.account_state_root,
                    })
                })
                .chain(self.recovery_intents.values().map(|intent| {
                    json!({
                        "recovery_intent_id": intent.recovery_intent_id,
                        "target_account_state_root": intent.request.target_account_state_root,
                    })
                }))
                .collect::<Vec<_>>(),
        );
        let guardian_authorization_root = merkle_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-GUARDIAN-AUTHORIZATIONS",
            &self
                .recovery_intents
                .values()
                .map(|intent| {
                    json!({
                        "recovery_intent_id": intent.recovery_intent_id,
                        "guardian_committee_id": intent.request.guardian_committee_id,
                        "guardian_authorization_root": intent.request.guardian_authorization_root,
                        "pq_signature_root": intent.request.pq_signature_root,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let low_fee_sponsor_root = merkle_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-LOW-FEE-SPONSORS",
            &self
                .sponsor_reservations
                .values()
                .map(|reservation| {
                    json!({
                        "sponsor_reservation_id": reservation.sponsor_reservation_id,
                        "fee_credit_root": reservation.request.fee_credit_root,
                        "rebate_commitment_root": reservation.request.rebate_commitment_root,
                        "status": reservation.status.as_str(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let public_record_root = merkle_root(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-PUBLIC-RECORDS",
            &self
                .public_records_without_state_root()
                .into_iter()
                .map(|(_, record)| record)
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-STATE",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PROTOCOL_VERSION,
                "current_height": self.current_height,
                "runtime_root": self.runtime_root,
                "config_root": config_root,
                "counter_root": counter_root,
                "account_policy_root": account_policy_root,
                "guardian_committee_root": guardian_committee_root,
                "recovery_intent_root": recovery_intent_root,
                "sponsor_reservation_root": sponsor_reservation_root,
                "execution_batch_root": execution_batch_root,
                "receipt_root": receipt_root,
                "replay_nullifier_root": replay_nullifier_root,
                "consumed_nullifier_root": consumed_nullifier_root,
                "account_state_root": account_state_root,
                "guardian_authorization_root": guardian_authorization_root,
                "low_fee_sponsor_root": low_fee_sponsor_root,
                "public_record_root": public_record_root,
            }),
        );
        Roots {
            config_root,
            counter_root,
            account_policy_root,
            guardian_committee_root,
            recovery_intent_root,
            sponsor_reservation_root,
            execution_batch_root,
            receipt_root,
            replay_nullifier_root,
            consumed_nullifier_root,
            account_state_root,
            guardian_authorization_root,
            low_fee_sponsor_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_threshold_wallet_guard_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PQ_SUITE,
            "account_policy_scheme": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_ACCOUNT_POLICY_SCHEME,
            "guardian_committee_scheme": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_GUARDIAN_COMMITTEE_SCHEME,
            "recovery_intent_scheme": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECOVERY_INTENT_SCHEME,
            "replay_fence_scheme": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_REPLAY_FENCE_SCHEME,
            "low_fee_sponsor_scheme": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_LOW_FEE_SPONSOR_SCHEME,
            "execution_batch_scheme": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_EXECUTION_BATCH_SCHEME,
            "receipt_scheme": PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_RECEIPT_SCHEME,
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "account_policy_ids": self.account_policies.keys().cloned().collect::<Vec<_>>(),
            "guardian_committee_ids": self.guardian_committees.keys().cloned().collect::<Vec<_>>(),
            "recovery_intent_ids": self.recovery_intents.keys().cloned().collect::<Vec<_>>(),
            "sponsor_reservation_ids": self.sponsor_reservations.keys().cloned().collect::<Vec<_>>(),
            "execution_batch_ids": self.execution_batches.keys().cloned().collect::<Vec<_>>(),
            "receipt_ids": self.receipts.keys().cloned().collect::<Vec<_>>(),
            "privacy_boundary": "roots_only_no_plaintext_wallet_keys_no_plaintext_recovery_payloads_no_view_keys",
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn public_records_without_state_root(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        records.insert("counters".to_string(), self.counters.public_record());
        for policy in self.account_policies.values() {
            records.insert(
                format!("account_policy:{}", policy.account_policy_id),
                policy.public_record(),
            );
        }
        for committee in self.guardian_committees.values() {
            records.insert(
                format!("guardian_committee:{}", committee.guardian_committee_id),
                committee.public_record(),
            );
        }
        for intent in self.recovery_intents.values() {
            records.insert(
                format!("recovery_intent:{}", intent.recovery_intent_id),
                intent.public_record(),
            );
        }
        for reservation in self.sponsor_reservations.values() {
            records.insert(
                format!("sponsor_reservation:{}", reservation.sponsor_reservation_id),
                reservation.public_record(),
            );
        }
        for batch in self.execution_batches.values() {
            records.insert(
                format!("execution_batch:{}", batch.batch_id),
                batch.public_record(),
            );
        }
        for receipt in self.receipts.values() {
            records.insert(
                format!("receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        records
    }

    fn insert_replay_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        if !self.config.require_replay_fence {
            return Ok(());
        }
        let root = nullifier_root("REPLAY", nullifier);
        if !self.replay_nullifiers.insert(root) {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("replay nullifier already observed".to_string());
        }
        Ok(())
    }

    fn insert_consumed_nullifier(
        &mut self,
        kind: &str,
        nullifier: &str,
    ) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
        let root = nullifier_root(kind, nullifier);
        if !self.consumed_nullifiers.insert(root) {
            return Err("nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        Ok(())
    }

    fn expire_stale(&mut self, current_height: u64) {
        for intent in self.recovery_intents.values_mut() {
            if intent.status.live() && current_height > intent.request.expires_at_height {
                intent.status = RecoveryIntentStatus::Expired;
                intent.updated_at_height = current_height;
                self.counters.recovery_intents_expired =
                    self.counters.recovery_intents_expired.saturating_add(1);
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if matches!(
                reservation.status,
                SponsorReservationStatus::Reserved | SponsorReservationStatus::Matched
            ) && current_height > reservation.request.expires_at_height
            {
                reservation.status = SponsorReservationStatus::Expired;
            }
        }
        for batch in self.execution_batches.values_mut() {
            if batch.status.can_execute() && current_height > batch.settlement_deadline_height {
                batch.status = RecoveryBatchStatus::Expired;
            }
        }
        self.current_height = self.current_height.max(current_height);
    }
}

pub fn private_l2_pq_threshold_wallet_guard_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_threshold_wallet_guard_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn devnet() -> PrivateL2PqThresholdWalletGuardRuntimeResult<State> {
    State::devnet()
}

pub fn shielded_account_policy_id(
    request: &RegisterShieldedAccountPolicyRequest,
    sequence: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-ACCOUNT-POLICY-ID",
        &json!({
            "sequence": sequence,
            "policy_kind": request.policy_kind.as_str(),
            "account_commitment": request.account_commitment,
            "wallet_policy_root": request.wallet_policy_root,
            "recovery_policy_root": request.recovery_policy_root,
            "guardian_committee_root": request.guardian_committee_root,
            "registered_at_height": request.registered_at_height,
            "policy_nonce": request.policy_nonce,
        }),
    )
}

pub fn pq_guardian_committee_id(
    request: &RegisterPqGuardianCommitteeRequest,
    sequence: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-GUARDIAN-COMMITTEE-ID",
        &json!({
            "sequence": sequence,
            "committee_label": request.committee_label,
            "guardian_set_root": request.guardian_set_root,
            "guardian_weight_root": request.guardian_weight_root,
            "pq_public_key_root": request.pq_public_key_root,
            "threshold_policy_root": request.threshold_policy_root,
            "epoch": request.epoch,
        }),
    )
}

pub fn private_recovery_intent_id(
    request: &SubmitPrivateRecoveryIntentRequest,
    sequence: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-RECOVERY-INTENT-ID",
        &json!({
            "sequence": sequence,
            "intent_kind": request.intent_kind.as_str(),
            "account_policy_id": request.account_policy_id,
            "guardian_committee_id": request.guardian_committee_id,
            "account_commitment": request.account_commitment,
            "encrypted_recovery_payload_root": request.encrypted_recovery_payload_root,
            "replay_nullifier": request.replay_nullifier,
            "recovery_nullifier": request.recovery_nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn low_fee_sponsor_reservation_id(
    request: &ReserveLowFeeSponsorRequest,
    sequence: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-SPONSOR-RESERVATION-ID",
        &json!({
            "sequence": sequence,
            "recovery_intent_id": request.recovery_intent_id,
            "sponsor_commitment": request.sponsor_commitment,
            "fee_credit_root": request.fee_credit_root,
            "route_nullifier": request.route_nullifier,
            "reserved_at_height": request.reserved_at_height,
        }),
    )
}

pub fn recovery_execution_batch_id(
    request: &BuildRecoveryExecutionBatchRequest,
    intent_root: &str,
    sequence: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-EXECUTION-BATCH-ID",
        &json!({
            "sequence": sequence,
            "intent_root": intent_root,
            "recovery_intent_ids": request.recovery_intent_ids,
            "sponsor_reservation_ids": request.sponsor_reservation_ids,
            "aggregate_guardian_authorization_root": request.aggregate_guardian_authorization_root,
            "aggregate_pq_signature_root": request.aggregate_pq_signature_root,
            "batch_nullifier": request.batch_nullifier,
            "sealed_at_height": request.sealed_at_height,
        }),
    )
}

pub fn recovery_receipt_id(request: &PublishRecoveryReceiptRequest, sequence: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-RECOVERY-RECEIPT-ID",
        &json!({
            "sequence": sequence,
            "batch_id": request.batch_id,
            "execution_tx_root": request.execution_tx_root,
            "execution_proof_root": request.execution_proof_root,
            "receipt_status": request.receipt_status.as_str(),
            "receipt_nullifier": request.receipt_nullifier,
            "executed_at_height": request.executed_at_height,
        }),
    )
}

pub fn replay_fence_root(
    account_policy_id: &str,
    replay_nullifier: &str,
    recovery_nullifier: &str,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-REPLAY-FENCE",
        &json!({
            "account_policy_id": account_policy_id,
            "replay_nullifier": replay_nullifier,
            "recovery_nullifier": recovery_nullifier,
        }),
    )
}

pub fn nullifier_root(kind: &str, nullifier: &str) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-NULLIFIER",
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
            HashPart::Str(PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PROTOCOL_VERSION),
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
    root_from_record("PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-STATE-ROOT", record)
}

pub fn empty_runtime_root() -> String {
    domain_hash(
        "PRIVATE-L2-PQ-THRESHOLD-WALLET-GUARD-EMPTY-RUNTIME-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
        ],
        32,
    )
}

fn require(condition: bool, message: &str) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(label: &str, value: &str) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(label: &str, value: &str) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{label} must look like a root/commitment"),
    )
}

fn require_bps(label: &str, value: u64) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_PQ_THRESHOLD_WALLET_GUARD_RUNTIME_MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_unique(
    label: &str,
    values: &[String],
) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    config: &Config,
) -> PrivateL2PqThresholdWalletGuardRuntimeResult<()> {
    require(
        privacy_set_size >= config.min_privacy_set_size,
        "privacy set below minimum",
    )?;
    require(
        pq_security_bits >= config.min_pq_security_bits,
        "PQ security bits below minimum",
    )
}
