use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqContractUpgradeTimelockRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-contract-upgrade-timelock-runtime-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PQ_GOVERNANCE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-upgrade-governance-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROPOSAL_SCHEME: &str =
    "shielded-contract-upgrade-proposal-root-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_REVIEW_COMMITTEE_SCHEME: &str =
    "pq-upgrade-reviewer-committee-root-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PRIVATE_VOTE_SCHEME: &str =
    "private-upgrade-vote-attestation-root-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_LOW_FEE_RESERVATION_SCHEME: &str =
    "low-fee-upgrade-execution-reservation-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_EXECUTION_BATCH_SCHEME: &str =
    "timelock-contract-upgrade-execution-batch-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_ROLLBACK_SCHEME: &str =
    "contract-upgrade-rollback-receipt-root-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_EMERGENCY_PAUSE_SCHEME: &str =
    "fast-emergency-contract-upgrade-pause-receipt-root-v1";
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEVNET_HEIGHT: u64 = 760_000;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_CONTRACTS: usize = 262_144;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_PROPOSALS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_COMMITTEES: usize = 131_072;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_REVIEWS: usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_VOTES: usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCHES: usize = 262_144;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCH_PROPOSALS: usize =
    4_096;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_EMERGENCY_PRIVACY_SET_SIZE: u64 =
    1_024;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_REVIEWER_COUNT: u16 = 5;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_REVIEW_QUORUM_WEIGHT_BPS:
    u64 = 6_700;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_APPROVAL_WEIGHT_BPS: u64 =
    6_700;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_FAST_GUARD_WEIGHT_BPS: u64 =
    8_000;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_TIMELOCK_BLOCKS: u64 = 720;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_TIMELOCK_BLOCKS: u64 = 86_400;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 = 12;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 14_400;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_VOTE_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 =
    14_400;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_EXECUTION_FEE_BPS: u64 = 15;
pub const PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_SPONSOR_COVERAGE_BPS: u64 = 9_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractUpgradeKind {
    LogicUpgrade,
    StorageMigration,
    ParameterPatch,
    VerifierKeyRotation,
    PrivacyCircuitUpgrade,
    BridgeAdapterUpgrade,
    FeePolicyUpgrade,
    EmergencyHotfix,
    Rollback,
}

impl ContractUpgradeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LogicUpgrade => "logic_upgrade",
            Self::StorageMigration => "storage_migration",
            Self::ParameterPatch => "parameter_patch",
            Self::VerifierKeyRotation => "verifier_key_rotation",
            Self::PrivacyCircuitUpgrade => "privacy_circuit_upgrade",
            Self::BridgeAdapterUpgrade => "bridge_adapter_upgrade",
            Self::FeePolicyUpgrade => "fee_policy_upgrade",
            Self::EmergencyHotfix => "emergency_hotfix",
            Self::Rollback => "rollback",
        }
    }

    pub fn emergency_eligible(self) -> bool {
        matches!(self, Self::EmergencyHotfix | Self::Rollback)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractRiskTier {
    Low,
    Medium,
    High,
    Critical,
    BridgeCritical,
    GovernanceCritical,
}

impl ContractRiskTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::BridgeCritical => "bridge_critical",
            Self::GovernanceCritical => "governance_critical",
        }
    }

    pub fn requires_extended_review(self) -> bool {
        matches!(
            self,
            Self::Critical | Self::BridgeCritical | Self::GovernanceCritical
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Registered,
    Active,
    UpgradePending,
    Timelocked,
    Paused,
    RolledBack,
    Retired,
    Slashed,
}

impl ContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::UpgradePending => "upgrade_pending",
            Self::Timelocked => "timelocked",
            Self::Paused => "paused",
            Self::RolledBack => "rolled_back",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_upgrade(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::RolledBack)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Submitted,
    UnderReview,
    ReviewApproved,
    Voting,
    VoteApproved,
    Timelocked,
    Ready,
    Batched,
    Executed,
    Rejected,
    Cancelled,
    Expired,
    EmergencyPaused,
    RolledBack,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::UnderReview => "under_review",
            Self::ReviewApproved => "review_approved",
            Self::Voting => "voting",
            Self::VoteApproved => "vote_approved",
            Self::Timelocked => "timelocked",
            Self::Ready => "ready",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::EmergencyPaused => "emergency_paused",
            Self::RolledBack => "rolled_back",
        }
    }

    pub fn accepts_review(self) -> bool {
        matches!(self, Self::Submitted | Self::UnderReview)
    }

    pub fn accepts_vote(self) -> bool {
        matches!(self, Self::ReviewApproved | Self::Voting)
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Ready | Self::Timelocked | Self::VoteApproved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    EmergencyOnly,
    Paused,
    Retired,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::EmergencyOnly => "emergency_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_review(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }

    pub fn can_emergency_pause(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::EmergencyOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    Approve,
    Reject,
    NeedsMoreEvidence,
    EmergencyPause,
}

impl ReviewVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::NeedsMoreEvidence => "needs_more_evidence",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteChoice {
    Approve,
    Reject,
    Abstain,
}

impl VoteChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteStatus {
    Submitted,
    Counted,
    Rejected,
    Expired,
    NullifierReplay,
}

impl VoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::NullifierReplay => "nullifier_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Refunded,
    Expired,
    Cancelled,
}

impl ReservationStatus {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBatchStatus {
    Built,
    TimelockWaiting,
    Ready,
    Executed,
    PartiallyExecuted,
    Reverted,
    Expired,
    Cancelled,
}

impl ExecutionBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::TimelockWaiting => "timelock_waiting",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::PartiallyExecuted => "partially_executed",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_governance_suite: String,
    pub proposal_scheme: String,
    pub review_committee_scheme: String,
    pub private_vote_scheme: String,
    pub low_fee_reservation_scheme: String,
    pub execution_batch_scheme: String,
    pub rollback_scheme: String,
    pub emergency_pause_scheme: String,
    pub devnet_height: u64,
    pub max_contracts: usize,
    pub max_proposals: usize,
    pub max_committees: usize,
    pub max_reviews: usize,
    pub max_votes: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_batch_proposals: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub emergency_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_reviewer_count: u16,
    pub min_review_quorum_weight_bps: u64,
    pub min_approval_weight_bps: u64,
    pub fast_guard_weight_bps: u64,
    pub min_timelock_blocks: u64,
    pub max_timelock_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub proposal_ttl_blocks: u64,
    pub vote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub rollback_window_blocks: u64,
    pub max_execution_fee_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub require_bytecode_attestation: bool,
    pub require_private_votes: bool,
    pub require_low_fee_reservation: bool,
    pub allow_fast_emergency_pause: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_HASH_SUITE.to_string(),
            pq_governance_suite:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PQ_GOVERNANCE_SUITE.to_string(),
            proposal_scheme: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROPOSAL_SCHEME
                .to_string(),
            review_committee_scheme:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_REVIEW_COMMITTEE_SCHEME.to_string(),
            private_vote_scheme:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PRIVATE_VOTE_SCHEME.to_string(),
            low_fee_reservation_scheme:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_LOW_FEE_RESERVATION_SCHEME
                    .to_string(),
            execution_batch_scheme:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_EXECUTION_BATCH_SCHEME.to_string(),
            rollback_scheme: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_ROLLBACK_SCHEME
                .to_string(),
            emergency_pause_scheme:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_EMERGENCY_PAUSE_SCHEME.to_string(),
            devnet_height: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEVNET_HEIGHT,
            max_contracts: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_CONTRACTS,
            max_proposals: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_PROPOSALS,
            max_committees: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_COMMITTEES,
            max_reviews: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_REVIEWS,
            max_votes: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_VOTES,
            max_reservations:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_proposals:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCH_PROPOSALS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            emergency_privacy_set_size:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_EMERGENCY_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_reviewer_count:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_REVIEWER_COUNT,
            min_review_quorum_weight_bps:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_REVIEW_QUORUM_WEIGHT_BPS,
            min_approval_weight_bps:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_APPROVAL_WEIGHT_BPS,
            fast_guard_weight_bps:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_FAST_GUARD_WEIGHT_BPS,
            min_timelock_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MIN_TIMELOCK_BLOCKS,
            max_timelock_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_TIMELOCK_BLOCKS,
            emergency_delay_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_EMERGENCY_DELAY_BLOCKS,
            proposal_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_PROPOSAL_TTL_BLOCKS,
            vote_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_VOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            rollback_window_blocks:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            max_execution_fee_bps:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_MAX_EXECUTION_FEE_BPS,
            sponsor_coverage_bps:
                PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_DEFAULT_SPONSOR_COVERAGE_BPS,
            require_bytecode_attestation: true,
            require_private_votes: true,
            require_low_fee_reservation: true,
            allow_fast_emergency_pause: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("pq_governance_suite", &self.pq_governance_suite)?;
        ensure_positive("max_contracts", self.max_contracts)?;
        ensure_positive("max_proposals", self.max_proposals)?;
        ensure_positive("max_committees", self.max_committees)?;
        ensure_positive("max_reviews", self.max_reviews)?;
        ensure_positive("max_votes", self.max_votes)?;
        ensure_positive("max_reservations", self.max_reservations)?;
        ensure_positive("max_batches", self.max_batches)?;
        ensure_positive("max_receipts", self.max_receipts)?;
        ensure_positive("max_batch_proposals", self.max_batch_proposals)?;
        if self.chain_id != CHAIN_ID {
            return Err("contract upgrade timelock config chain_id mismatch".to_string());
        }
        if self.schema_version == 0 {
            return Err("contract upgrade timelock schema version must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.batch_privacy_set_size < self.min_privacy_set_size
            || self.emergency_privacy_set_size == 0
        {
            return Err("contract upgrade timelock privacy set configuration invalid".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("contract upgrade timelock PQ security floor too low".to_string());
        }
        if self.min_reviewer_count == 0 {
            return Err("contract upgrade timelock reviewer count must be positive".to_string());
        }
        if self.min_review_quorum_weight_bps
            > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
            || self.min_approval_weight_bps
                > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
            || self.fast_guard_weight_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
            || self.max_execution_fee_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
            || self.sponsor_coverage_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
        {
            return Err("contract upgrade timelock bps configuration invalid".to_string());
        }
        if self.min_timelock_blocks == 0 || self.max_timelock_blocks < self.min_timelock_blocks {
            return Err("contract upgrade timelock delay configuration invalid".to_string());
        }
        if self.proposal_ttl_blocks <= self.min_timelock_blocks {
            return Err("contract upgrade proposal TTL must exceed minimum timelock".to_string());
        }
        if self.rollback_window_blocks == 0 {
            return Err("contract upgrade rollback window must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub contract_counter: u64,
    pub proposal_counter: u64,
    pub committee_counter: u64,
    pub review_counter: u64,
    pub vote_counter: u64,
    pub reservation_counter: u64,
    pub batch_counter: u64,
    pub rollback_counter: u64,
    pub emergency_pause_counter: u64,
    pub receipt_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterUpgradeableContractRequest {
    pub contract_commitment: String,
    pub admin_commitment: String,
    pub contract_kind: String,
    pub risk_tier: ContractRiskTier,
    pub current_bytecode_root: String,
    pub current_abi_root: String,
    pub current_storage_root: String,
    pub current_policy_root: String,
    pub upgrade_authority_root: String,
    pub emergency_guard_root: String,
    pub low_fee_policy_root: String,
    pub registration_nullifier: String,
    pub registered_at_height: u64,
}

impl RegisterUpgradeableContractRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpgradeableContractRecord {
    pub contract_id: String,
    pub request: RegisterUpgradeableContractRequest,
    pub status: ContractStatus,
    pub contract_root: String,
    pub active_bytecode_root: String,
    pub active_storage_root: String,
    pub last_upgrade_id: Option<String>,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
}

impl UpgradeableContractRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "contract_root": self.contract_root,
            "active_bytecode_root": self.active_bytecode_root,
            "active_storage_root": self.active_storage_root,
            "last_upgrade_id": self.last_upgrade_id,
            "registered_at_height": self.registered_at_height,
            "updated_at_height": self.updated_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedUpgradeProposalRequest {
    pub contract_id: String,
    pub proposer_commitment: String,
    pub upgrade_kind: ContractUpgradeKind,
    pub current_bytecode_root: String,
    pub proposed_bytecode_root: String,
    pub current_storage_root: String,
    pub proposed_storage_root: String,
    pub migration_witness_root: String,
    pub compatibility_report_root: String,
    pub bytecode_attestation_root: String,
    pub privacy_invariant_root: String,
    pub rollback_plan_root: String,
    pub timelock_blocks: u64,
    pub earliest_execution_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub proposal_nullifier: String,
    pub metadata_root: String,
}

impl ShieldedUpgradeProposalRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpgradeProposalRecord {
    pub proposal_id: String,
    pub request: ShieldedUpgradeProposalRequest,
    pub status: ProposalStatus,
    pub proposal_root: String,
    pub review_weight_bps: u64,
    pub approval_weight_bps: u64,
    pub rejection_weight_bps: u64,
    pub reserved_fee_bps: u64,
    pub submitted_at_height: u64,
    pub updated_at_height: u64,
}

impl UpgradeProposalRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "status": self.status.as_str(),
            "proposal_root": self.proposal_root,
            "review_weight_bps": self.review_weight_bps,
            "approval_weight_bps": self.approval_weight_bps,
            "rejection_weight_bps": self.rejection_weight_bps,
            "reserved_fee_bps": self.reserved_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "updated_at_height": self.updated_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterReviewerCommitteeRequest {
    pub committee_commitment: String,
    pub reviewer_set_root: String,
    pub reviewer_key_root: String,
    pub coverage_contract_root: String,
    pub review_policy_root: String,
    pub emergency_guard_policy_root: String,
    pub stake_commitment_root: String,
    pub min_weight_bps: u64,
    pub reviewer_count: u16,
    pub pq_security_bits: u16,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub committee_nullifier: String,
}

impl RegisterReviewerCommitteeRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewerCommitteeRecord {
    pub committee_id: String,
    pub request: RegisterReviewerCommitteeRequest,
    pub status: CommitteeStatus,
    pub committee_root: String,
    pub activated_at_height: u64,
    pub updated_at_height: u64,
}

impl ReviewerCommitteeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "committee_root": self.committee_root,
            "activated_at_height": self.activated_at_height,
            "updated_at_height": self.updated_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitReviewAttestationRequest {
    pub proposal_id: String,
    pub committee_id: String,
    pub reviewer_commitment: String,
    pub verdict: ReviewVerdict,
    pub evidence_root: String,
    pub simulation_root: String,
    pub bytecode_diff_root: String,
    pub storage_diff_root: String,
    pub privacy_review_root: String,
    pub pq_signature_root: String,
    pub reviewer_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub review_nullifier: String,
}

impl SubmitReviewAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewAttestationRecord {
    pub review_id: String,
    pub request: SubmitReviewAttestationRequest,
    pub review_root: String,
    pub accepted: bool,
    pub submitted_at_height: u64,
}

impl ReviewAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "review_id": self.review_id,
            "review_root": self.review_root,
            "accepted": self.accepted,
            "submitted_at_height": self.submitted_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPrivateUpgradeVoteRequest {
    pub proposal_id: String,
    pub voter_commitment: String,
    pub vote_choice: VoteChoice,
    pub encrypted_vote_root: String,
    pub voting_power_commitment: String,
    pub voting_power_bps: u64,
    pub membership_proof_root: String,
    pub vote_policy_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub vote_nullifier: String,
}

impl SubmitPrivateUpgradeVoteRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateUpgradeVoteRecord {
    pub vote_id: String,
    pub request: SubmitPrivateUpgradeVoteRequest,
    pub status: VoteStatus,
    pub vote_root: String,
    pub counted_at_height: u64,
}

impl PrivateUpgradeVoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "status": self.status.as_str(),
            "vote_root": self.vote_root,
            "counted_at_height": self.counted_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLowFeeExecutionRequest {
    pub proposal_id: String,
    pub sponsor_commitment: String,
    pub executor_commitment: String,
    pub fee_asset_id: String,
    pub fee_budget_root: String,
    pub max_execution_fee_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub reservation_nullifier: String,
}

impl ReserveLowFeeExecutionRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeExecutionReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeExecutionRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
    pub reserved_at_height: u64,
}

impl LowFeeExecutionReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildTimelockExecutionBatchRequest {
    pub proposal_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub executor_commitment: String,
    pub execution_trace_root: String,
    pub pre_state_root: String,
    pub expected_post_state_root: String,
    pub fee_settlement_root: String,
    pub batch_privacy_set_size: u64,
    pub pq_signature_root: String,
    pub earliest_execution_height: u64,
    pub expires_at_height: u64,
    pub batch_nullifier: String,
}

impl BuildTimelockExecutionBatchRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimelockExecutionBatchRecord {
    pub batch_id: String,
    pub request: BuildTimelockExecutionBatchRequest,
    pub status: ExecutionBatchStatus,
    pub batch_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub built_at_height: u64,
    pub executed_at_height: Option<u64>,
}

impl TimelockExecutionBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "built_at_height": self.built_at_height,
            "executed_at_height": self.executed_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRollbackReceiptRequest {
    pub proposal_id: String,
    pub batch_id: Option<String>,
    pub contract_id: String,
    pub rollback_executor_commitment: String,
    pub rollback_plan_root: String,
    pub restored_bytecode_root: String,
    pub restored_storage_root: String,
    pub rollback_evidence_root: String,
    pub post_rollback_state_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub rollback_nullifier: String,
}

impl PublishRollbackReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackReceiptRecord {
    pub rollback_id: String,
    pub request: PublishRollbackReceiptRequest,
    pub rollback_root: String,
    pub published_at_height: u64,
}

impl RollbackReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rollback_id": self.rollback_id,
            "rollback_root": self.rollback_root,
            "published_at_height": self.published_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishEmergencyPauseReceiptRequest {
    pub proposal_id: Option<String>,
    pub contract_id: String,
    pub committee_id: String,
    pub guard_commitment: String,
    pub pause_reason_root: String,
    pub threat_evidence_root: String,
    pub emergency_action_root: String,
    pub fast_guard_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub paused_until_height: u64,
    pub pq_signature_root: String,
    pub pause_nullifier: String,
}

impl PublishEmergencyPauseReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyPauseReceiptRecord {
    pub pause_id: String,
    pub request: PublishEmergencyPauseReceiptRequest,
    pub pause_root: String,
    pub published_at_height: u64,
}

impl EmergencyPauseReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pause_id": self.pause_id,
            "pause_root": self.pause_root,
            "published_at_height": self.published_at_height,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub contract_root: String,
    pub proposal_root: String,
    pub committee_root: String,
    pub review_root: String,
    pub vote_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub rollback_root: String,
    pub emergency_pause_root: String,
    pub nullifier_root: String,
    pub state_root: String,
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
    pub contracts: BTreeMap<String, UpgradeableContractRecord>,
    pub proposals: BTreeMap<String, UpgradeProposalRecord>,
    pub committees: BTreeMap<String, ReviewerCommitteeRecord>,
    pub reviews: BTreeMap<String, ReviewAttestationRecord>,
    pub votes: BTreeMap<String, PrivateUpgradeVoteRecord>,
    pub reservations: BTreeMap<String, LowFeeExecutionReservationRecord>,
    pub batches: BTreeMap<String, TimelockExecutionBatchRecord>,
    pub rollbacks: BTreeMap<String, RollbackReceiptRecord>,
    pub emergency_pauses: BTreeMap<String, EmergencyPauseReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqContractUpgradeTimelockRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            contracts: BTreeMap::new(),
            proposals: BTreeMap::new(),
            committees: BTreeMap::new(),
            reviews: BTreeMap::new(),
            votes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            rollbacks: BTreeMap::new(),
            emergency_pauses: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_contract(
        &mut self,
        request: RegisterUpgradeableContractRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<UpgradeableContractRecord> {
        validate_contract_registration(&request)?;
        self.ensure_capacity("contracts", self.contracts.len(), self.config.max_contracts)?;
        self.ensure_unused_nullifier(&request.registration_nullifier)?;
        self.counters.contract_counter = self.counters.contract_counter.saturating_add(1);
        let contract_id = upgradeable_contract_id(&request, self.counters.contract_counter);
        let contract_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-CONTRACT",
            &request.public_record(),
        );
        let record = UpgradeableContractRecord {
            contract_id: contract_id.clone(),
            active_bytecode_root: request.current_bytecode_root.clone(),
            active_storage_root: request.current_storage_root.clone(),
            registered_at_height: request.registered_at_height,
            updated_at_height: request.registered_at_height,
            request: request.clone(),
            status: ContractStatus::Registered,
            contract_root,
            last_upgrade_id: None,
        };
        self.consumed_nullifiers
            .insert(request.registration_nullifier.clone());
        self.contracts.insert(contract_id, record.clone());
        Ok(record)
    }

    pub fn submit_shielded_upgrade_proposal(
        &mut self,
        request: ShieldedUpgradeProposalRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<UpgradeProposalRecord> {
        validate_proposal(&request, &self.config)?;
        self.ensure_capacity("proposals", self.proposals.len(), self.config.max_proposals)?;
        self.ensure_unused_nullifier(&request.proposal_nullifier)?;
        let contract = self.require_contract(&request.contract_id)?;
        if !contract.status.accepts_upgrade() {
            return Err(format!(
                "contract {} does not accept upgrades",
                request.contract_id
            ));
        }
        if contract.active_bytecode_root != request.current_bytecode_root {
            return Err(
                "proposal current bytecode root does not match active contract".to_string(),
            );
        }
        self.counters.proposal_counter = self.counters.proposal_counter.saturating_add(1);
        let proposal_id = shielded_upgrade_proposal_id(&request, self.counters.proposal_counter);
        let proposal_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-PROPOSAL",
            &request.public_record(),
        );
        let record = UpgradeProposalRecord {
            proposal_id: proposal_id.clone(),
            request: request.clone(),
            status: ProposalStatus::Submitted,
            proposal_root,
            review_weight_bps: 0,
            approval_weight_bps: 0,
            rejection_weight_bps: 0,
            reserved_fee_bps: 0,
            submitted_at_height: self.config.devnet_height,
            updated_at_height: self.config.devnet_height,
        };
        if let Some(contract) = self.contracts.get_mut(&request.contract_id) {
            contract.status = ContractStatus::UpgradePending;
            contract.updated_at_height = self.config.devnet_height;
        }
        self.consumed_nullifiers
            .insert(request.proposal_nullifier.clone());
        self.proposals.insert(proposal_id, record.clone());
        Ok(record)
    }

    pub fn register_reviewer_committee(
        &mut self,
        request: RegisterReviewerCommitteeRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<ReviewerCommitteeRecord> {
        validate_committee(&request, &self.config)?;
        self.ensure_capacity(
            "committees",
            self.committees.len(),
            self.config.max_committees,
        )?;
        self.ensure_unused_nullifier(&request.committee_nullifier)?;
        self.counters.committee_counter = self.counters.committee_counter.saturating_add(1);
        let committee_id = reviewer_committee_id(&request, self.counters.committee_counter);
        let committee_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-COMMITTEE",
            &request.public_record(),
        );
        let status = if request.active_from_height <= self.config.devnet_height {
            CommitteeStatus::Active
        } else {
            CommitteeStatus::Forming
        };
        let record = ReviewerCommitteeRecord {
            committee_id: committee_id.clone(),
            request: request.clone(),
            status,
            committee_root,
            activated_at_height: request.active_from_height,
            updated_at_height: self.config.devnet_height,
        };
        self.consumed_nullifiers
            .insert(request.committee_nullifier.clone());
        self.committees.insert(committee_id, record.clone());
        Ok(record)
    }

    pub fn submit_review_attestation(
        &mut self,
        request: SubmitReviewAttestationRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<ReviewAttestationRecord> {
        validate_review(&request, &self.config)?;
        self.ensure_capacity("reviews", self.reviews.len(), self.config.max_reviews)?;
        self.ensure_unused_nullifier(&request.review_nullifier)?;
        let committee = self.require_committee(&request.committee_id)?;
        if !committee.status.can_review()
            || committee.request.expires_at_height <= self.config.devnet_height
        {
            return Err(format!(
                "committee {} cannot review upgrades",
                request.committee_id
            ));
        }
        let proposal = self.require_proposal(&request.proposal_id)?;
        if !proposal.status.accepts_review() {
            return Err(format!(
                "proposal {} is not reviewable",
                request.proposal_id
            ));
        }
        self.counters.review_counter = self.counters.review_counter.saturating_add(1);
        let review_id = review_attestation_id(&request, self.counters.review_counter);
        let review_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-REVIEW",
            &request.public_record(),
        );
        let accepted = request.verdict != ReviewVerdict::NeedsMoreEvidence;
        let record = ReviewAttestationRecord {
            review_id: review_id.clone(),
            request: request.clone(),
            review_root,
            accepted,
            submitted_at_height: self.config.devnet_height,
        };
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            proposal.status = match request.verdict {
                ReviewVerdict::Approve => {
                    proposal.review_weight_bps = proposal
                        .review_weight_bps
                        .saturating_add(request.reviewer_weight_bps)
                        .min(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS);
                    if proposal.review_weight_bps >= self.config.min_review_quorum_weight_bps {
                        ProposalStatus::ReviewApproved
                    } else {
                        ProposalStatus::UnderReview
                    }
                }
                ReviewVerdict::Reject => ProposalStatus::Rejected,
                ReviewVerdict::NeedsMoreEvidence => ProposalStatus::UnderReview,
                ReviewVerdict::EmergencyPause => ProposalStatus::EmergencyPaused,
            };
            proposal.updated_at_height = self.config.devnet_height;
        }
        self.consumed_nullifiers
            .insert(request.review_nullifier.clone());
        self.reviews.insert(review_id, record.clone());
        Ok(record)
    }

    pub fn submit_private_upgrade_vote(
        &mut self,
        request: SubmitPrivateUpgradeVoteRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<PrivateUpgradeVoteRecord> {
        validate_vote(&request, &self.config)?;
        self.ensure_capacity("votes", self.votes.len(), self.config.max_votes)?;
        self.ensure_unused_nullifier(&request.vote_nullifier)?;
        let proposal = self.require_proposal(&request.proposal_id)?;
        if !proposal.status.accepts_vote() {
            return Err(format!("proposal {} is not votable", request.proposal_id));
        }
        self.counters.vote_counter = self.counters.vote_counter.saturating_add(1);
        let vote_id = private_upgrade_vote_id(&request, self.counters.vote_counter);
        let vote_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-VOTE",
            &request.public_record(),
        );
        let status = VoteStatus::Counted;
        let record = PrivateUpgradeVoteRecord {
            vote_id: vote_id.clone(),
            request: request.clone(),
            status,
            vote_root,
            counted_at_height: self.config.devnet_height,
        };
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            match request.vote_choice {
                VoteChoice::Approve => {
                    proposal.approval_weight_bps = proposal
                        .approval_weight_bps
                        .saturating_add(request.voting_power_bps)
                        .min(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS);
                }
                VoteChoice::Reject => {
                    proposal.rejection_weight_bps = proposal
                        .rejection_weight_bps
                        .saturating_add(request.voting_power_bps)
                        .min(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS);
                }
                VoteChoice::Abstain => {}
            }
            proposal.status = if proposal.approval_weight_bps >= self.config.min_approval_weight_bps
            {
                if self.config.devnet_height >= proposal.request.earliest_execution_height {
                    ProposalStatus::Ready
                } else {
                    ProposalStatus::Timelocked
                }
            } else if proposal.rejection_weight_bps
                > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
                    .saturating_sub(self.config.min_approval_weight_bps)
            {
                ProposalStatus::Rejected
            } else {
                ProposalStatus::Voting
            };
            proposal.updated_at_height = self.config.devnet_height;
        }
        self.consumed_nullifiers
            .insert(request.vote_nullifier.clone());
        self.votes.insert(vote_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_execution(
        &mut self,
        request: ReserveLowFeeExecutionRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<LowFeeExecutionReservationRecord> {
        validate_reservation(&request, &self.config)?;
        self.ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        self.ensure_unused_nullifier(&request.reservation_nullifier)?;
        self.require_proposal(&request.proposal_id)?;
        self.counters.reservation_counter = self.counters.reservation_counter.saturating_add(1);
        let reservation_id =
            low_fee_execution_reservation_id(&request, self.counters.reservation_counter);
        let reservation_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-RESERVATION",
            &request.public_record(),
        );
        let record = LowFeeExecutionReservationRecord {
            reservation_id: reservation_id.clone(),
            request: request.clone(),
            status: ReservationStatus::Reserved,
            reservation_root,
            reserved_at_height: request.reserved_at_height,
        };
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            proposal.reserved_fee_bps = request.max_execution_fee_bps;
            proposal.updated_at_height = self.config.devnet_height;
        }
        self.consumed_nullifiers
            .insert(request.reservation_nullifier.clone());
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_timelock_execution_batch(
        &mut self,
        request: BuildTimelockExecutionBatchRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<TimelockExecutionBatchRecord> {
        validate_batch(&request, &self.config)?;
        self.ensure_capacity("batches", self.batches.len(), self.config.max_batches)?;
        self.ensure_unused_nullifier(&request.batch_nullifier)?;
        for proposal_id in &request.proposal_ids {
            let proposal = self.require_proposal(proposal_id)?;
            if !proposal.status.batchable() {
                return Err(format!("proposal {proposal_id} is not batchable"));
            }
            if proposal.request.earliest_execution_height > request.earliest_execution_height {
                return Err(format!("proposal {proposal_id} timelock has not matured"));
            }
            if self.config.require_low_fee_reservation && proposal.reserved_fee_bps == 0 {
                return Err(format!("proposal {proposal_id} lacks low-fee reservation"));
            }
        }
        for reservation_id in &request.reservation_ids {
            self.require_reservation(reservation_id)?;
        }
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        let state_root_before = self.state_root();
        let batch_id = timelock_execution_batch_id(&request, self.counters.batch_counter);
        let batch_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-BATCH",
            &request.public_record(),
        );
        for proposal_id in &request.proposal_ids {
            if let Some(proposal) = self.proposals.get_mut(proposal_id) {
                proposal.status = ProposalStatus::Batched;
                proposal.updated_at_height = self.config.devnet_height;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Matched;
            }
        }
        let state_root_after = state_root_from_record(&json!({
            "batch_id": batch_id,
            "batch_root": batch_root,
            "state_root_before": state_root_before,
            "expected_post_state_root": request.expected_post_state_root,
            "batch_counter": self.counters.batch_counter,
        }));
        let record = TimelockExecutionBatchRecord {
            batch_id: batch_id.clone(),
            request: request.clone(),
            status: if request.earliest_execution_height <= self.config.devnet_height {
                ExecutionBatchStatus::Ready
            } else {
                ExecutionBatchStatus::TimelockWaiting
            },
            batch_root,
            state_root_before,
            state_root_after,
            built_at_height: self.config.devnet_height,
            executed_at_height: None,
        };
        self.consumed_nullifiers
            .insert(request.batch_nullifier.clone());
        self.batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn execute_timelock_batch(
        &mut self,
        batch_id: &str,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<TimelockExecutionBatchRecord> {
        let batch = self.require_batch(batch_id)?;
        if !matches!(
            batch.status,
            ExecutionBatchStatus::Ready | ExecutionBatchStatus::TimelockWaiting
        ) {
            return Err(format!("batch {batch_id} is not executable"));
        }
        if batch.request.earliest_execution_height > self.config.devnet_height {
            return Err(format!("batch {batch_id} timelock has not matured"));
        }
        let proposal_ids = batch.request.proposal_ids.clone();
        for proposal_id in &proposal_ids {
            let proposal = self.require_proposal(proposal_id)?;
            self.require_contract(&proposal.request.contract_id)?;
        }
        for proposal_id in &proposal_ids {
            if let Some(proposal) = self.proposals.get_mut(proposal_id) {
                proposal.status = ProposalStatus::Executed;
                proposal.updated_at_height = self.config.devnet_height;
                if let Some(contract) = self.contracts.get_mut(&proposal.request.contract_id) {
                    contract.status = ContractStatus::Active;
                    contract.active_bytecode_root = proposal.request.proposed_bytecode_root.clone();
                    contract.active_storage_root = proposal.request.proposed_storage_root.clone();
                    contract.last_upgrade_id = Some(proposal.proposal_id.clone());
                    contract.updated_at_height = self.config.devnet_height;
                }
            }
        }
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = ExecutionBatchStatus::Executed;
            batch.executed_at_height = Some(self.config.devnet_height);
            return Ok(batch.clone());
        }
        Err(format!("unknown timelock execution batch {batch_id}"))
    }

    pub fn publish_rollback_receipt(
        &mut self,
        request: PublishRollbackReceiptRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<RollbackReceiptRecord> {
        validate_rollback(&request, &self.config)?;
        self.ensure_capacity("rollbacks", self.rollbacks.len(), self.config.max_receipts)?;
        self.ensure_unused_nullifier(&request.rollback_nullifier)?;
        self.require_contract(&request.contract_id)?;
        self.require_proposal(&request.proposal_id)?;
        if let Some(batch_id) = &request.batch_id {
            self.require_batch(batch_id)?;
        }
        self.counters.rollback_counter = self.counters.rollback_counter.saturating_add(1);
        let rollback_id = rollback_receipt_id(&request, self.counters.rollback_counter);
        let rollback_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-ROLLBACK",
            &request.public_record(),
        );
        let record = RollbackReceiptRecord {
            rollback_id: rollback_id.clone(),
            request: request.clone(),
            rollback_root,
            published_at_height: self.config.devnet_height,
        };
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            proposal.status = ProposalStatus::RolledBack;
            proposal.updated_at_height = self.config.devnet_height;
        }
        if let Some(contract) = self.contracts.get_mut(&request.contract_id) {
            contract.status = ContractStatus::RolledBack;
            contract.active_bytecode_root = request.restored_bytecode_root.clone();
            contract.active_storage_root = request.restored_storage_root.clone();
            contract.updated_at_height = self.config.devnet_height;
        }
        self.consumed_nullifiers
            .insert(request.rollback_nullifier.clone());
        self.rollbacks.insert(rollback_id, record.clone());
        Ok(record)
    }

    pub fn publish_emergency_pause_receipt(
        &mut self,
        request: PublishEmergencyPauseReceiptRequest,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<EmergencyPauseReceiptRecord> {
        validate_emergency_pause(&request, &self.config)?;
        self.ensure_capacity(
            "emergency_pauses",
            self.emergency_pauses.len(),
            self.config.max_receipts,
        )?;
        self.ensure_unused_nullifier(&request.pause_nullifier)?;
        let committee = self.require_committee(&request.committee_id)?;
        if !committee.status.can_emergency_pause() {
            return Err(format!(
                "committee {} cannot emergency pause",
                request.committee_id
            ));
        }
        self.require_contract(&request.contract_id)?;
        if let Some(proposal_id) = &request.proposal_id {
            self.require_proposal(proposal_id)?;
        }
        self.counters.emergency_pause_counter =
            self.counters.emergency_pause_counter.saturating_add(1);
        let pause_id = emergency_pause_receipt_id(&request, self.counters.emergency_pause_counter);
        let pause_root = root_from_record(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-EMERGENCY-PAUSE",
            &request.public_record(),
        );
        let record = EmergencyPauseReceiptRecord {
            pause_id: pause_id.clone(),
            request: request.clone(),
            pause_root,
            published_at_height: self.config.devnet_height,
        };
        if let Some(contract) = self.contracts.get_mut(&request.contract_id) {
            contract.status = ContractStatus::Paused;
            contract.updated_at_height = self.config.devnet_height;
        }
        if let Some(proposal_id) = &request.proposal_id {
            if let Some(proposal) = self.proposals.get_mut(proposal_id) {
                proposal.status = ProposalStatus::EmergencyPaused;
                proposal.updated_at_height = self.config.devnet_height;
            }
        }
        self.consumed_nullifiers
            .insert(request.pause_nullifier.clone());
        self.emergency_pauses.insert(pause_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let contract_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-CONTRACTS",
            &self
                .contracts
                .values()
                .map(UpgradeableContractRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let proposal_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-PROPOSALS",
            &self
                .proposals
                .values()
                .map(UpgradeProposalRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let committee_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-COMMITTEES",
            &self
                .committees
                .values()
                .map(ReviewerCommitteeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let review_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-REVIEWS",
            &self
                .reviews
                .values()
                .map(ReviewAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let vote_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-VOTES",
            &self
                .votes
                .values()
                .map(PrivateUpgradeVoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(LowFeeExecutionReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-BATCHES",
            &self
                .batches
                .values()
                .map(TimelockExecutionBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rollback_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-ROLLBACKS",
            &self
                .rollbacks
                .values()
                .map(RollbackReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let emergency_pause_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-EMERGENCY-PAUSES",
            &self
                .emergency_pauses
                .values()
                .map(EmergencyPauseReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = public_record_root(
            "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "contract_root": contract_root,
            "proposal_root": proposal_root,
            "committee_root": committee_root,
            "review_root": review_root,
            "vote_root": vote_root,
            "reservation_root": reservation_root,
            "batch_root": batch_root,
            "rollback_root": rollback_root,
            "emergency_pause_root": emergency_pause_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            contract_root,
            proposal_root,
            committee_root,
            review_root,
            vote_root,
            reservation_root,
            batch_root,
            rollback_root,
            emergency_pause_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_governance_suite": self.config.pq_governance_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn ensure_capacity(
        &self,
        label: &str,
        len: usize,
        max: usize,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
        if len >= max {
            Err(format!(
                "contract upgrade timelock {label} capacity exhausted"
            ))
        } else {
            Ok(())
        }
    }

    fn ensure_unused_nullifier(
        &self,
        nullifier: &str,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
        if self.consumed_nullifiers.contains(nullifier) {
            Err("contract upgrade timelock nullifier replay detected".to_string())
        } else {
            Ok(())
        }
    }

    fn require_contract(
        &self,
        contract_id: &str,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<&UpgradeableContractRecord> {
        self.contracts
            .get(contract_id)
            .ok_or_else(|| format!("unknown upgradeable contract {contract_id}"))
    }

    fn require_proposal(
        &self,
        proposal_id: &str,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<&UpgradeProposalRecord> {
        self.proposals
            .get(proposal_id)
            .ok_or_else(|| format!("unknown upgrade proposal {proposal_id}"))
    }

    fn require_committee(
        &self,
        committee_id: &str,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<&ReviewerCommitteeRecord> {
        self.committees
            .get(committee_id)
            .ok_or_else(|| format!("unknown reviewer committee {committee_id}"))
    }

    fn require_reservation(
        &self,
        reservation_id: &str,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<&LowFeeExecutionReservationRecord> {
        self.reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown low-fee execution reservation {reservation_id}"))
    }

    fn require_batch(
        &self,
        batch_id: &str,
    ) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<&TimelockExecutionBatchRecord> {
        self.batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown timelock execution batch {batch_id}"))
    }
}

pub type Runtime = State;

pub fn upgradeable_contract_id(
    request: &RegisterUpgradeableContractRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-CONTRACT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.contract_commitment),
            HashPart::Str(&request.admin_commitment),
            HashPart::Str(request.risk_tier.as_str()),
            HashPart::Str(&request.current_bytecode_root),
            HashPart::Str(&request.registration_nullifier),
        ],
        32,
    )
}

pub fn shielded_upgrade_proposal_id(
    request: &ShieldedUpgradeProposalRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.proposer_commitment),
            HashPart::Str(request.upgrade_kind.as_str()),
            HashPart::Str(&request.current_bytecode_root),
            HashPart::Str(&request.proposed_bytecode_root),
            HashPart::Str(&request.proposal_nullifier),
        ],
        32,
    )
}

pub fn reviewer_committee_id(request: &RegisterReviewerCommitteeRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.committee_commitment),
            HashPart::Str(&request.reviewer_set_root),
            HashPart::Str(&request.coverage_contract_root),
            HashPart::Str(&request.committee_nullifier),
        ],
        32,
    )
}

pub fn review_attestation_id(request: &SubmitReviewAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-REVIEW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.reviewer_commitment),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.review_nullifier),
        ],
        32,
    )
}

pub fn private_upgrade_vote_id(request: &SubmitPrivateUpgradeVoteRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.voter_commitment),
            HashPart::Str(request.vote_choice.as_str()),
            HashPart::Str(&request.encrypted_vote_root),
            HashPart::Str(&request.vote_nullifier),
        ],
        32,
    )
}

pub fn low_fee_execution_reservation_id(
    request: &ReserveLowFeeExecutionRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.executor_commitment),
            HashPart::Str(&request.fee_budget_root),
            HashPart::Str(&request.reservation_nullifier),
        ],
        32,
    )
}

pub fn timelock_execution_batch_id(
    request: &BuildTimelockExecutionBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("proposals", &request.proposal_ids)),
            HashPart::Str(&id_list_root("reservations", &request.reservation_ids)),
            HashPart::Str(&request.executor_commitment),
            HashPart::Str(&request.execution_trace_root),
            HashPart::Str(&request.batch_nullifier),
        ],
        32,
    )
}

pub fn rollback_receipt_id(request: &PublishRollbackReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-ROLLBACK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.rollback_plan_root),
            HashPart::Str(&request.restored_bytecode_root),
            HashPart::Str(&request.rollback_nullifier),
        ],
        32,
    )
}

pub fn emergency_pause_receipt_id(
    request: &PublishEmergencyPauseReceiptRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-EMERGENCY-PAUSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.guard_commitment),
            HashPart::Str(&request.threat_evidence_root),
            HashPart::Str(&request.pause_nullifier),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_PROTOCOL_VERSION),
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
    root_from_record("PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-STATE", record)
}

pub fn devnet() -> PrivateL2PqContractUpgradeTimelockRuntimeResult<State> {
    State::devnet()
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-PQ-CONTRACT-UPGRADE-TIMELOCK-ID-LIST-{domain}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn validate_contract_registration(
    request: &RegisterUpgradeableContractRequest,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_root("contract_commitment", &request.contract_commitment)?;
    ensure_root("admin_commitment", &request.admin_commitment)?;
    ensure_non_empty("contract_kind", &request.contract_kind)?;
    ensure_root("current_bytecode_root", &request.current_bytecode_root)?;
    ensure_root("current_abi_root", &request.current_abi_root)?;
    ensure_root("current_storage_root", &request.current_storage_root)?;
    ensure_root("current_policy_root", &request.current_policy_root)?;
    ensure_root("upgrade_authority_root", &request.upgrade_authority_root)?;
    ensure_root("emergency_guard_root", &request.emergency_guard_root)?;
    ensure_root("low_fee_policy_root", &request.low_fee_policy_root)?;
    ensure_root("registration_nullifier", &request.registration_nullifier)?;
    Ok(())
}

fn validate_proposal(
    request: &ShieldedUpgradeProposalRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_root("contract_id", &request.contract_id)?;
    ensure_root("proposer_commitment", &request.proposer_commitment)?;
    ensure_root("current_bytecode_root", &request.current_bytecode_root)?;
    ensure_root("proposed_bytecode_root", &request.proposed_bytecode_root)?;
    ensure_root("current_storage_root", &request.current_storage_root)?;
    ensure_root("proposed_storage_root", &request.proposed_storage_root)?;
    ensure_root("migration_witness_root", &request.migration_witness_root)?;
    ensure_root(
        "compatibility_report_root",
        &request.compatibility_report_root,
    )?;
    if config.require_bytecode_attestation {
        ensure_root(
            "bytecode_attestation_root",
            &request.bytecode_attestation_root,
        )?;
    }
    ensure_root("privacy_invariant_root", &request.privacy_invariant_root)?;
    ensure_root("rollback_plan_root", &request.rollback_plan_root)?;
    ensure_root("proposal_nullifier", &request.proposal_nullifier)?;
    ensure_root("metadata_root", &request.metadata_root)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.timelock_blocks < config.min_timelock_blocks
        || request.timelock_blocks > config.max_timelock_blocks
    {
        return Err("upgrade proposal timelock outside configured bounds".to_string());
    }
    if request.expires_at_height <= request.earliest_execution_height {
        return Err("upgrade proposal expiry must follow earliest execution".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.earliest_execution_height)
        > config.proposal_ttl_blocks
    {
        return Err("upgrade proposal exceeds configured TTL".to_string());
    }
    Ok(())
}

fn validate_committee(
    request: &RegisterReviewerCommitteeRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_root("committee_commitment", &request.committee_commitment)?;
    ensure_root("reviewer_set_root", &request.reviewer_set_root)?;
    ensure_root("reviewer_key_root", &request.reviewer_key_root)?;
    ensure_root("coverage_contract_root", &request.coverage_contract_root)?;
    ensure_root("review_policy_root", &request.review_policy_root)?;
    ensure_root(
        "emergency_guard_policy_root",
        &request.emergency_guard_policy_root,
    )?;
    ensure_root("stake_commitment_root", &request.stake_commitment_root)?;
    ensure_root("committee_nullifier", &request.committee_nullifier)?;
    if request.reviewer_count < config.min_reviewer_count {
        return Err("review committee reviewer count below minimum".to_string());
    }
    if request.min_weight_bps < config.min_review_quorum_weight_bps
        || request.min_weight_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
    {
        return Err("review committee weight threshold invalid".to_string());
    }
    if request.pq_security_bits < config.min_pq_security_bits {
        return Err("review committee PQ security below minimum".to_string());
    }
    if request.expires_at_height <= request.active_from_height {
        return Err("review committee expiry must follow activation".to_string());
    }
    Ok(())
}

fn validate_review(
    request: &SubmitReviewAttestationRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_root("proposal_id", &request.proposal_id)?;
    ensure_root("committee_id", &request.committee_id)?;
    ensure_root("reviewer_commitment", &request.reviewer_commitment)?;
    ensure_root("evidence_root", &request.evidence_root)?;
    ensure_root("simulation_root", &request.simulation_root)?;
    ensure_root("bytecode_diff_root", &request.bytecode_diff_root)?;
    ensure_root("storage_diff_root", &request.storage_diff_root)?;
    ensure_root("privacy_review_root", &request.privacy_review_root)?;
    ensure_root("pq_signature_root", &request.pq_signature_root)?;
    ensure_root("review_nullifier", &request.review_nullifier)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.reviewer_weight_bps == 0
        || request.reviewer_weight_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
    {
        return Err("review attestation weight invalid".to_string());
    }
    Ok(())
}

fn validate_vote(
    request: &SubmitPrivateUpgradeVoteRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_root("proposal_id", &request.proposal_id)?;
    ensure_root("voter_commitment", &request.voter_commitment)?;
    ensure_root("encrypted_vote_root", &request.encrypted_vote_root)?;
    ensure_root("voting_power_commitment", &request.voting_power_commitment)?;
    ensure_root("membership_proof_root", &request.membership_proof_root)?;
    ensure_root("vote_policy_root", &request.vote_policy_root)?;
    ensure_root("pq_signature_root", &request.pq_signature_root)?;
    ensure_root("vote_nullifier", &request.vote_nullifier)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.voting_power_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS {
        return Err("private vote power exceeds basis point maximum".to_string());
    }
    Ok(())
}

fn validate_reservation(
    request: &ReserveLowFeeExecutionRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_root("proposal_id", &request.proposal_id)?;
    ensure_root("sponsor_commitment", &request.sponsor_commitment)?;
    ensure_root("executor_commitment", &request.executor_commitment)?;
    ensure_non_empty("fee_asset_id", &request.fee_asset_id)?;
    ensure_root("fee_budget_root", &request.fee_budget_root)?;
    ensure_root("reservation_nullifier", &request.reservation_nullifier)?;
    if request.max_execution_fee_bps > config.max_execution_fee_bps {
        return Err("low-fee execution reservation exceeds fee cap".to_string());
    }
    if request.sponsor_coverage_bps < config.sponsor_coverage_bps
        || request.sponsor_coverage_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
    {
        return Err("low-fee execution reservation coverage invalid".to_string());
    }
    if request.expires_at_height <= request.reserved_at_height {
        return Err("low-fee execution reservation expiry must follow reservation".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.reserved_at_height)
        > config.reservation_ttl_blocks
    {
        return Err("low-fee execution reservation exceeds TTL".to_string());
    }
    Ok(())
}

fn validate_batch(
    request: &BuildTimelockExecutionBatchRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_non_empty_vec("proposal_ids", &request.proposal_ids)?;
    if request.proposal_ids.len() > config.max_batch_proposals {
        return Err("timelock execution batch proposal count exceeds maximum".to_string());
    }
    ensure_root("executor_commitment", &request.executor_commitment)?;
    ensure_root("execution_trace_root", &request.execution_trace_root)?;
    ensure_root("pre_state_root", &request.pre_state_root)?;
    ensure_root(
        "expected_post_state_root",
        &request.expected_post_state_root,
    )?;
    ensure_root("fee_settlement_root", &request.fee_settlement_root)?;
    ensure_root("pq_signature_root", &request.pq_signature_root)?;
    ensure_root("batch_nullifier", &request.batch_nullifier)?;
    if request.batch_privacy_set_size < config.batch_privacy_set_size {
        return Err("timelock execution batch privacy set below minimum".to_string());
    }
    if request.expires_at_height <= request.earliest_execution_height {
        return Err("timelock execution batch expiry must follow execution height".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.earliest_execution_height)
        > config.batch_ttl_blocks
    {
        return Err("timelock execution batch exceeds TTL".to_string());
    }
    Ok(())
}

fn validate_rollback(
    request: &PublishRollbackReceiptRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_root("proposal_id", &request.proposal_id)?;
    ensure_root("contract_id", &request.contract_id)?;
    ensure_root(
        "rollback_executor_commitment",
        &request.rollback_executor_commitment,
    )?;
    ensure_root("rollback_plan_root", &request.rollback_plan_root)?;
    ensure_root("restored_bytecode_root", &request.restored_bytecode_root)?;
    ensure_root("restored_storage_root", &request.restored_storage_root)?;
    ensure_root("rollback_evidence_root", &request.rollback_evidence_root)?;
    ensure_root(
        "post_rollback_state_root",
        &request.post_rollback_state_root,
    )?;
    ensure_root("pq_signature_root", &request.pq_signature_root)?;
    ensure_root("rollback_nullifier", &request.rollback_nullifier)?;
    if request.privacy_set_size < config.emergency_privacy_set_size {
        return Err("rollback receipt privacy set below emergency minimum".to_string());
    }
    Ok(())
}

fn validate_emergency_pause(
    request: &PublishEmergencyPauseReceiptRequest,
    config: &Config,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    if !config.allow_fast_emergency_pause {
        return Err("fast emergency pause disabled by config".to_string());
    }
    ensure_root("contract_id", &request.contract_id)?;
    ensure_root("committee_id", &request.committee_id)?;
    ensure_root("guard_commitment", &request.guard_commitment)?;
    ensure_root("pause_reason_root", &request.pause_reason_root)?;
    ensure_root("threat_evidence_root", &request.threat_evidence_root)?;
    ensure_root("emergency_action_root", &request.emergency_action_root)?;
    ensure_root("pq_signature_root", &request.pq_signature_root)?;
    ensure_root("pause_nullifier", &request.pause_nullifier)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.emergency_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.fast_guard_weight_bps < config.fast_guard_weight_bps
        || request.fast_guard_weight_bps > PRIVATE_L2_PQ_CONTRACT_UPGRADE_TIMELOCK_RUNTIME_MAX_BPS
    {
        return Err("emergency pause guard weight below configured threshold".to_string());
    }
    if request.paused_until_height <= config.devnet_height + config.emergency_delay_blocks {
        return Err("emergency pause duration below configured delay".to_string());
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("contract upgrade timelock privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("contract upgrade timelock PQ security bits below minimum".to_string());
    }
    Ok(())
}

fn ensure_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!(
            "contract upgrade timelock field {field} is required"
        ))
    } else {
        Ok(())
    }
}

fn ensure_root(field: &str, value: &str) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    ensure_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!(
            "contract upgrade timelock field {field} must look like a commitment root"
        ));
    }
    Ok(())
}

fn ensure_positive(
    field: &str,
    value: usize,
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    if value == 0 {
        Err(format!(
            "contract upgrade timelock {field} must be positive"
        ))
    } else {
        Ok(())
    }
}

fn ensure_non_empty_vec(
    field: &str,
    values: &[String],
) -> PrivateL2PqContractUpgradeTimelockRuntimeResult<()> {
    if values.is_empty() {
        return Err(format!("contract upgrade timelock {field} cannot be empty"));
    }
    for value in values {
        ensure_root(field, value)?;
    }
    Ok(())
}
