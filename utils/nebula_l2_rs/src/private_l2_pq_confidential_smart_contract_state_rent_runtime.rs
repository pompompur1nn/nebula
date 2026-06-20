use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-smart-contract-state-rent-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SMART_CONTRACT_STATE_RENT_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RENT_PROOF_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f+recursive-state-rent-proof-v1";
pub const STORAGE_SEALING_SUITE: &str =
    "ML-KEM-1024+XChaCha20Poly1305+viewtagged-contract-state-envelope-v1";
pub const NAMESPACE_COMMITMENT_SUITE: &str = "monero-l2-contract-namespace-pedersen-pq-binding-v1";
pub const PRIVACY_BUDGET_SUITE: &str = "view-key-minimized-rent-budget-nullifier-ledger-v1";
pub const LOW_FEE_EVICTION_SUITE: &str = "low-fee-confidential-state-eviction-lane-v1";
pub const DEVNET_HEIGHT: u64 = 1_492_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ANONYMITY_SET: u64 = 16_384;
pub const DEFAULT_BATCH_ANONYMITY_SET: u64 = 262_144;
pub const DEFAULT_STORAGE_CELL_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_RENT_PROOF_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_CREDIT_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_EVICTION_LANE_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_NAMESPACE_TTL_BLOCKS: u64 = 172_800;
pub const DEFAULT_EVICTION_GRACE_BLOCKS: u64 = 2_880;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_BASE_RENT_MICRO_CREDITS: u64 = 125;
pub const DEFAULT_LOW_FEE_DISCOUNT_BPS: u64 = 7_500;
pub const DEFAULT_PREPAID_CREDIT_BONUS_BPS: u64 = 350;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_STORAGE_CLASSES: usize = 64;
pub const DEFAULT_MAX_NAMESPACES: usize = 1_048_576;
pub const DEFAULT_MAX_SEALED_CELLS: usize = 16_777_216;
pub const DEFAULT_MAX_RENT_PROOFS: usize = 16_777_216;
pub const DEFAULT_MAX_PREPAID_CREDITS: usize = 4_194_304;
pub const DEFAULT_MAX_EVICTION_LANES: usize = 524_288;
pub const DEFAULT_MAX_PRIVACY_BUDGETS: usize = 4_194_304;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 67_108_864;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;

macro_rules! ensure {
    ($condition:expr, $message:expr) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedStorageClass {
    ContractHotState,
    ContractWarmState,
    ContractColdState,
    ContractCodeMetadata,
    ContractEventIndex,
    ContractOracleCache,
    ContractSessionState,
    ContractBridgeState,
    ContractDefiState,
    ContractGovernanceState,
    ContractVerifyingKey,
    ContractArchiveState,
}

impl SealedStorageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractHotState => "contract_hot_state",
            Self::ContractWarmState => "contract_warm_state",
            Self::ContractColdState => "contract_cold_state",
            Self::ContractCodeMetadata => "contract_code_metadata",
            Self::ContractEventIndex => "contract_event_index",
            Self::ContractOracleCache => "contract_oracle_cache",
            Self::ContractSessionState => "contract_session_state",
            Self::ContractBridgeState => "contract_bridge_state",
            Self::ContractDefiState => "contract_defi_state",
            Self::ContractGovernanceState => "contract_governance_state",
            Self::ContractVerifyingKey => "contract_verifying_key",
            Self::ContractArchiveState => "contract_archive_state",
        }
    }

    pub fn rent_weight_bps(self) -> u64 {
        match self {
            Self::ContractHotState => 10_000,
            Self::ContractDefiState => 9_700,
            Self::ContractBridgeState => 9_400,
            Self::ContractOracleCache => 9_100,
            Self::ContractSessionState => 8_800,
            Self::ContractGovernanceState => 8_500,
            Self::ContractEventIndex => 8_200,
            Self::ContractWarmState => 7_700,
            Self::ContractVerifyingKey => 7_400,
            Self::ContractCodeMetadata => 7_000,
            Self::ContractColdState => 6_200,
            Self::ContractArchiveState => 5_600,
        }
    }

    pub fn eviction_priority_bps(self) -> u64 {
        match self {
            Self::ContractArchiveState => 10_000,
            Self::ContractColdState => 9_500,
            Self::ContractCodeMetadata => 8_800,
            Self::ContractEventIndex => 8_400,
            Self::ContractWarmState => 7_700,
            Self::ContractSessionState => 7_100,
            Self::ContractOracleCache => 6_600,
            Self::ContractGovernanceState => 5_800,
            Self::ContractVerifyingKey => 5_000,
            Self::ContractBridgeState => 3_800,
            Self::ContractDefiState => 3_100,
            Self::ContractHotState => 2_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceStatus {
    Proposed,
    Committed,
    Active,
    RentLocked,
    Draining,
    Frozen,
    Retired,
    Slashed,
}

impl NamespaceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Committed => "committed",
            Self::Active => "active",
            Self::RentLocked => "rent_locked",
            Self::Draining => "draining",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_cells(self) -> bool {
        matches!(self, Self::Committed | Self::Active | Self::RentLocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CellStatus {
    Sealed,
    RentPrepaid,
    ProofPending,
    ProofAccepted,
    GracePeriod,
    EvictionQueued,
    Evicted,
    Restored,
    Challenged,
    Slashed,
    Expired,
}

impl CellStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::RentPrepaid => "rent_prepaid",
            Self::ProofPending => "proof_pending",
            Self::ProofAccepted => "proof_accepted",
            Self::GracePeriod => "grace_period",
            Self::EvictionQueued => "eviction_queued",
            Self::Evicted => "evicted",
            Self::Restored => "restored",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::RentPrepaid
                | Self::ProofPending
                | Self::ProofAccepted
                | Self::GracePeriod
                | Self::Restored
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RentProofKind {
    Occupancy,
    Deletion,
    Compression,
    Restore,
    NonMembership,
    NamespaceBalance,
    PrivacyBudgetSpend,
    EvictionEligibility,
}

impl RentProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Occupancy => "occupancy",
            Self::Deletion => "deletion",
            Self::Compression => "compression",
            Self::Restore => "restore",
            Self::NonMembership => "non_membership",
            Self::NamespaceBalance => "namespace_balance",
            Self::PrivacyBudgetSpend => "privacy_budget_spend",
            Self::EvictionEligibility => "eviction_eligibility",
        }
    }

    pub fn required_security_bits(self) -> u16 {
        match self {
            Self::Occupancy => 256,
            Self::Deletion => 256,
            Self::Compression => 256,
            Self::Restore => 256,
            Self::NonMembership => 256,
            Self::NamespaceBalance => 256,
            Self::PrivacyBudgetSpend => 256,
            Self::EvictionEligibility => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Aggregating,
    Accepted,
    Rejected,
    Superseded,
    Expired,
    Challenged,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Aggregating => "aggregating",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Minted,
    Reserved,
    Locked,
    Spent,
    Refunded,
    Expired,
    Slashed,
}

impl CreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Reserved => "reserved",
            Self::Locked => "locked",
            Self::Spent => "spent",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionLaneKind {
    LowFeeGrace,
    LowFeeBatch,
    SponsorBacked,
    PrivacyPreserving,
    EmergencyDraining,
    ArchivePrune,
    NamespaceRetirement,
}

impl EvictionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeGrace => "low_fee_grace",
            Self::LowFeeBatch => "low_fee_batch",
            Self::SponsorBacked => "sponsor_backed",
            Self::PrivacyPreserving => "privacy_preserving",
            Self::EmergencyDraining => "emergency_draining",
            Self::ArchivePrune => "archive_prune",
            Self::NamespaceRetirement => "namespace_retirement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Proposed,
    Open,
    Congested,
    Proving,
    Settling,
    Paused,
    Closed,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Proving => "proving",
            Self::Settling => "settling",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Reserved,
    PartiallySpent,
    Exhausted,
    Refilled,
    Closed,
    Slashed,
}

impl BudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::PartiallySpent => "partially_spent",
            Self::Exhausted => "exhausted",
            Self::Refilled => "refilled",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidRentProof,
    UnderpaidRent,
    NamespaceCollision,
    PrivacyBudgetOverspend,
    IncorrectEviction,
    FalseDeletion,
    ReplayNullifier,
    WeakPqAttestation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRentProof => "invalid_rent_proof",
            Self::UnderpaidRent => "underpaid_rent",
            Self::NamespaceCollision => "namespace_collision",
            Self::PrivacyBudgetOverspend => "privacy_budget_overspend",
            Self::IncorrectEviction => "incorrect_eviction",
            Self::FalseDeletion => "false_deletion",
            Self::ReplayNullifier => "replay_nullifier",
            Self::WeakPqAttestation => "weak_pq_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    EvidenceCommitted,
    UnderReview,
    Accepted,
    Rejected,
    Settled,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::EvidenceCommitted => "evidence_committed",
            Self::UnderReview => "under_review",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_rent_proof_suite: String,
    pub storage_sealing_suite: String,
    pub namespace_commitment_suite: String,
    pub privacy_budget_suite: String,
    pub low_fee_eviction_suite: String,
    pub min_pq_security_bits: u16,
    pub min_anonymity_set: u64,
    pub batch_anonymity_set: u64,
    pub storage_cell_ttl_blocks: u64,
    pub rent_proof_ttl_blocks: u64,
    pub credit_ttl_blocks: u64,
    pub eviction_lane_ttl_blocks: u64,
    pub privacy_budget_ttl_blocks: u64,
    pub namespace_ttl_blocks: u64,
    pub eviction_grace_blocks: u64,
    pub challenge_window_blocks: u64,
    pub base_rent_micro_credits: u64,
    pub low_fee_discount_bps: u64,
    pub prepaid_credit_bonus_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_storage_classes: usize,
    pub max_namespaces: usize,
    pub max_sealed_cells: usize,
    pub max_rent_proofs: usize,
    pub max_prepaid_credits: usize,
    pub max_eviction_lanes: usize,
    pub max_privacy_budgets: usize,
    pub max_public_records: usize,
    pub max_challenges: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_rent_proof_suite: PQ_RENT_PROOF_SUITE.to_string(),
            storage_sealing_suite: STORAGE_SEALING_SUITE.to_string(),
            namespace_commitment_suite: NAMESPACE_COMMITMENT_SUITE.to_string(),
            privacy_budget_suite: PRIVACY_BUDGET_SUITE.to_string(),
            low_fee_eviction_suite: LOW_FEE_EVICTION_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            batch_anonymity_set: DEFAULT_BATCH_ANONYMITY_SET,
            storage_cell_ttl_blocks: DEFAULT_STORAGE_CELL_TTL_BLOCKS,
            rent_proof_ttl_blocks: DEFAULT_RENT_PROOF_TTL_BLOCKS,
            credit_ttl_blocks: DEFAULT_CREDIT_TTL_BLOCKS,
            eviction_lane_ttl_blocks: DEFAULT_EVICTION_LANE_TTL_BLOCKS,
            privacy_budget_ttl_blocks: DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS,
            namespace_ttl_blocks: DEFAULT_NAMESPACE_TTL_BLOCKS,
            eviction_grace_blocks: DEFAULT_EVICTION_GRACE_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            base_rent_micro_credits: DEFAULT_BASE_RENT_MICRO_CREDITS,
            low_fee_discount_bps: DEFAULT_LOW_FEE_DISCOUNT_BPS,
            prepaid_credit_bonus_bps: DEFAULT_PREPAID_CREDIT_BONUS_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_storage_classes: DEFAULT_MAX_STORAGE_CLASSES,
            max_namespaces: DEFAULT_MAX_NAMESPACES,
            max_sealed_cells: DEFAULT_MAX_SEALED_CELLS,
            max_rent_proofs: DEFAULT_MAX_RENT_PROOFS,
            max_prepaid_credits: DEFAULT_MAX_PREPAID_CREDITS,
            max_eviction_lanes: DEFAULT_MAX_EVICTION_LANES,
            max_privacy_budgets: DEFAULT_MAX_PRIVACY_BUDGETS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            max_challenges: DEFAULT_MAX_CHALLENGES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_rent_proof_suite": self.pq_rent_proof_suite,
            "storage_sealing_suite": self.storage_sealing_suite,
            "namespace_commitment_suite": self.namespace_commitment_suite,
            "privacy_budget_suite": self.privacy_budget_suite,
            "low_fee_eviction_suite": self.low_fee_eviction_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_anonymity_set": self.min_anonymity_set,
            "batch_anonymity_set": self.batch_anonymity_set,
            "storage_cell_ttl_blocks": self.storage_cell_ttl_blocks,
            "rent_proof_ttl_blocks": self.rent_proof_ttl_blocks,
            "credit_ttl_blocks": self.credit_ttl_blocks,
            "eviction_lane_ttl_blocks": self.eviction_lane_ttl_blocks,
            "privacy_budget_ttl_blocks": self.privacy_budget_ttl_blocks,
            "namespace_ttl_blocks": self.namespace_ttl_blocks,
            "eviction_grace_blocks": self.eviction_grace_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "base_rent_micro_credits": self.base_rent_micro_credits,
            "low_fee_discount_bps": self.low_fee_discount_bps,
            "prepaid_credit_bonus_bps": self.prepaid_credit_bonus_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_storage_classes": self.max_storage_classes,
            "max_namespaces": self.max_namespaces,
            "max_sealed_cells": self.max_sealed_cells,
            "max_rent_proofs": self.max_rent_proofs,
            "max_prepaid_credits": self.max_prepaid_credits,
            "max_eviction_lanes": self.max_eviction_lanes,
            "max_privacy_budgets": self.max_privacy_budgets,
            "max_public_records": self.max_public_records,
            "max_challenges": self.max_challenges
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub namespace_count: u64,
    pub sealed_cell_count: u64,
    pub live_cell_count: u64,
    pub rent_proof_count: u64,
    pub accepted_rent_proof_count: u64,
    pub prepaid_credit_count: u64,
    pub prepaid_credits_minted: u128,
    pub prepaid_credits_spent: u128,
    pub low_fee_eviction_lane_count: u64,
    pub eviction_candidate_count: u64,
    pub evicted_cell_count: u64,
    pub restored_cell_count: u64,
    pub privacy_budget_count: u64,
    pub privacy_budget_units: u64,
    pub privacy_budget_spent: u64,
    pub namespace_commitment_count: u64,
    pub public_record_count: u64,
    pub challenge_count: u64,
    pub accepted_challenge_count: u64,
    pub deterministic_root_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_count": self.namespace_count,
            "sealed_cell_count": self.sealed_cell_count,
            "live_cell_count": self.live_cell_count,
            "rent_proof_count": self.rent_proof_count,
            "accepted_rent_proof_count": self.accepted_rent_proof_count,
            "prepaid_credit_count": self.prepaid_credit_count,
            "prepaid_credits_minted": self.prepaid_credits_minted,
            "prepaid_credits_spent": self.prepaid_credits_spent,
            "low_fee_eviction_lane_count": self.low_fee_eviction_lane_count,
            "eviction_candidate_count": self.eviction_candidate_count,
            "evicted_cell_count": self.evicted_cell_count,
            "restored_cell_count": self.restored_cell_count,
            "privacy_budget_count": self.privacy_budget_count,
            "privacy_budget_units": self.privacy_budget_units,
            "privacy_budget_spent": self.privacy_budget_spent,
            "namespace_commitment_count": self.namespace_commitment_count,
            "public_record_count": self.public_record_count,
            "challenge_count": self.challenge_count,
            "accepted_challenge_count": self.accepted_challenge_count,
            "deterministic_root_count": self.deterministic_root_count
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub storage_class_root: String,
    pub namespace_root: String,
    pub namespace_commitment_root: String,
    pub sealed_cell_root: String,
    pub rent_proof_root: String,
    pub prepaid_credit_root: String,
    pub eviction_lane_root: String,
    pub eviction_candidate_root: String,
    pub privacy_budget_root: String,
    pub challenge_root: String,
    pub public_record_root: String,
    pub index_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "storage_class_root": self.storage_class_root,
            "namespace_root": self.namespace_root,
            "namespace_commitment_root": self.namespace_commitment_root,
            "sealed_cell_root": self.sealed_cell_root,
            "rent_proof_root": self.rent_proof_root,
            "prepaid_credit_root": self.prepaid_credit_root,
            "eviction_lane_root": self.eviction_lane_root,
            "eviction_candidate_root": self.eviction_candidate_root,
            "privacy_budget_root": self.privacy_budget_root,
            "challenge_root": self.challenge_root,
            "public_record_root": self.public_record_root,
            "index_root": self.index_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageClassPolicy {
    pub storage_class: SealedStorageClass,
    pub rent_weight_bps: u64,
    pub eviction_priority_bps: u64,
    pub min_prepaid_epochs: u64,
    pub max_cell_bytes: u64,
    pub proof_required: bool,
    pub low_fee_eviction_allowed: bool,
}

impl StorageClassPolicy {
    pub fn new(storage_class: SealedStorageClass) -> Self {
        Self {
            storage_class,
            rent_weight_bps: storage_class.rent_weight_bps(),
            eviction_priority_bps: storage_class.eviction_priority_bps(),
            min_prepaid_epochs: match storage_class {
                SealedStorageClass::ContractHotState
                | SealedStorageClass::ContractDefiState
                | SealedStorageClass::ContractBridgeState => 4,
                SealedStorageClass::ContractArchiveState
                | SealedStorageClass::ContractColdState => 1,
                _ => 2,
            },
            max_cell_bytes: match storage_class {
                SealedStorageClass::ContractHotState => 262_144,
                SealedStorageClass::ContractWarmState => 524_288,
                SealedStorageClass::ContractColdState => 1_048_576,
                SealedStorageClass::ContractArchiveState => 4_194_304,
                _ => 786_432,
            },
            proof_required: true,
            low_fee_eviction_allowed: !matches!(
                storage_class,
                SealedStorageClass::ContractHotState | SealedStorageClass::ContractBridgeState
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "storage_class": self.storage_class.as_str(),
            "rent_weight_bps": self.rent_weight_bps,
            "eviction_priority_bps": self.eviction_priority_bps,
            "min_prepaid_epochs": self.min_prepaid_epochs,
            "max_cell_bytes": self.max_cell_bytes,
            "proof_required": self.proof_required,
            "low_fee_eviction_allowed": self.low_fee_eviction_allowed
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractNamespaceCommitment {
    pub namespace_id: String,
    pub contract_commitment: String,
    pub namespace_commitment: String,
    pub owner_commitment: String,
    pub salt_commitment: String,
    pub namespace_label_hash: String,
    pub status: NamespaceStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub latest_cell_root: String,
    pub privacy_scope_root: String,
    pub rent_account_root: String,
}

impl ContractNamespaceCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_id": self.namespace_id,
            "contract_commitment": self.contract_commitment,
            "namespace_commitment": self.namespace_commitment,
            "owner_commitment": self.owner_commitment,
            "salt_commitment": self.salt_commitment,
            "namespace_label_hash": self.namespace_label_hash,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "latest_cell_root": self.latest_cell_root,
            "privacy_scope_root": self.privacy_scope_root,
            "rent_account_root": self.rent_account_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedStorageCell {
    pub cell_id: String,
    pub namespace_id: String,
    pub storage_class: SealedStorageClass,
    pub cell_commitment: String,
    pub encrypted_payload_root: String,
    pub prior_cell_root: String,
    pub current_cell_root: String,
    pub byte_size: u64,
    pub rent_epoch: u64,
    pub status: CellStatus,
    pub opened_at_height: u64,
    pub prepaid_until_height: u64,
    pub expires_at_height: u64,
    pub last_proof_id: Option<String>,
    pub privacy_budget_id: Option<String>,
    pub eviction_lane_id: Option<String>,
}

impl SealedStorageCell {
    pub fn public_record(&self) -> Value {
        json!({
            "cell_id": self.cell_id,
            "namespace_id": self.namespace_id,
            "storage_class": self.storage_class.as_str(),
            "cell_commitment": self.cell_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "prior_cell_root": self.prior_cell_root,
            "current_cell_root": self.current_cell_root,
            "byte_size": self.byte_size,
            "rent_epoch": self.rent_epoch,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "prepaid_until_height": self.prepaid_until_height,
            "expires_at_height": self.expires_at_height,
            "last_proof_id": self.last_proof_id,
            "privacy_budget_id": self.privacy_budget_id,
            "eviction_lane_id": self.eviction_lane_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqRentProof {
    pub proof_id: String,
    pub proof_kind: RentProofKind,
    pub namespace_id: String,
    pub cell_id: Option<String>,
    pub prover_commitment: String,
    pub proof_commitment: String,
    pub aggregate_witness_root: String,
    pub rent_charged_micro_credits: u128,
    pub privacy_units_spent: u64,
    pub pq_security_bits: u16,
    pub anonymity_set: u64,
    pub status: ProofStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRentProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind.as_str(),
            "namespace_id": self.namespace_id,
            "cell_id": self.cell_id,
            "prover_commitment": self.prover_commitment,
            "proof_commitment": self.proof_commitment,
            "aggregate_witness_root": self.aggregate_witness_root,
            "rent_charged_micro_credits": self.rent_charged_micro_credits,
            "privacy_units_spent": self.privacy_units_spent,
            "pq_security_bits": self.pq_security_bits,
            "anonymity_set": self.anonymity_set,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrepaidStateCredit {
    pub credit_id: String,
    pub owner_commitment: String,
    pub namespace_id: String,
    pub credit_commitment: String,
    pub amount_micro_credits: u128,
    pub spent_micro_credits: u128,
    pub bonus_bps: u64,
    pub status: CreditStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
}

impl PrepaidStateCredit {
    pub fn available_micro_credits(&self) -> u128 {
        self.amount_micro_credits
            .saturating_sub(self.spent_micro_credits)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "owner_commitment": self.owner_commitment,
            "namespace_id": self.namespace_id,
            "credit_commitment": self.credit_commitment,
            "amount_micro_credits": self.amount_micro_credits,
            "spent_micro_credits": self.spent_micro_credits,
            "available_micro_credits": self.available_micro_credits(),
            "bonus_bps": self.bonus_bps,
            "status": self.status.as_str(),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeEvictionLane {
    pub lane_id: String,
    pub lane_kind: EvictionLaneKind,
    pub namespace_id: String,
    pub sponsor_commitment: String,
    pub candidate_root: String,
    pub fee_cap_bps: u64,
    pub discount_bps: u64,
    pub target_cells: u64,
    pub evicted_cells: u64,
    pub status: LaneStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeEvictionLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "namespace_id": self.namespace_id,
            "sponsor_commitment": self.sponsor_commitment,
            "candidate_root": self.candidate_root,
            "fee_cap_bps": self.fee_cap_bps,
            "discount_bps": self.discount_bps,
            "target_cells": self.target_cells,
            "evicted_cells": self.evicted_cells,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub namespace_id: String,
    pub owner_commitment: String,
    pub scope_root: String,
    pub nullifier_domain: String,
    pub total_units: u64,
    pub spent_units: u64,
    pub min_anonymity_set: u64,
    pub status: BudgetStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyBudget {
    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "namespace_id": self.namespace_id,
            "owner_commitment": self.owner_commitment,
            "scope_root": self.scope_root,
            "nullifier_domain": self.nullifier_domain,
            "total_units": self.total_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "min_anonymity_set": self.min_anonymity_set,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvictionCandidate {
    pub candidate_id: String,
    pub lane_id: String,
    pub namespace_id: String,
    pub cell_id: String,
    pub storage_class: SealedStorageClass,
    pub eviction_score: u64,
    pub rent_due_micro_credits: u128,
    pub proof_id: Option<String>,
    pub queued_at_height: u64,
}

impl EvictionCandidate {
    pub fn public_record(&self) -> Value {
        json!({
            "candidate_id": self.candidate_id,
            "lane_id": self.lane_id,
            "namespace_id": self.namespace_id,
            "cell_id": self.cell_id,
            "storage_class": self.storage_class.as_str(),
            "eviction_score": self.eviction_score,
            "rent_due_micro_credits": self.rent_due_micro_credits,
            "proof_id": self.proof_id,
            "queued_at_height": self.queued_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RentChallenge {
    pub challenge_id: String,
    pub challenge_kind: ChallengeKind,
    pub challenger_commitment: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub bond_micro_credits: u128,
    pub status: ChallengeStatus,
    pub filed_at_height: u64,
    pub expires_at_height: u64,
}

impl RentChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "bond_micro_credits": self.bond_micro_credits,
            "status": self.status.as_str(),
            "filed_at_height": self.filed_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub storage_class_policies: BTreeMap<String, StorageClassPolicy>,
    pub namespaces: BTreeMap<String, ContractNamespaceCommitment>,
    pub sealed_cells: BTreeMap<String, SealedStorageCell>,
    pub rent_proofs: BTreeMap<String, PqRentProof>,
    pub prepaid_credits: BTreeMap<String, PrepaidStateCredit>,
    pub eviction_lanes: BTreeMap<String, LowFeeEvictionLane>,
    pub eviction_candidates: BTreeMap<String, EvictionCandidate>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub challenges: BTreeMap<String, RentChallenge>,
    pub namespace_cells: BTreeMap<String, BTreeSet<String>>,
    pub namespace_proofs: BTreeMap<String, BTreeSet<String>>,
    pub namespace_credits: BTreeMap<String, BTreeSet<String>>,
    pub namespace_budgets: BTreeMap<String, BTreeSet<String>>,
    pub lane_candidates: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            storage_class_policies: BTreeMap::new(),
            namespaces: BTreeMap::new(),
            sealed_cells: BTreeMap::new(),
            rent_proofs: BTreeMap::new(),
            prepaid_credits: BTreeMap::new(),
            eviction_lanes: BTreeMap::new(),
            eviction_candidates: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            challenges: BTreeMap::new(),
            namespace_cells: BTreeMap::new(),
            namespace_proofs: BTreeMap::new(),
            namespace_credits: BTreeMap::new(),
            namespace_budgets: BTreeMap::new(),
            lane_candidates: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.install_default_storage_classes();
        state.refresh_counters();
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.seed_devnet();
        state
    }

    pub fn install_default_storage_classes(&mut self) {
        let classes = [
            SealedStorageClass::ContractHotState,
            SealedStorageClass::ContractWarmState,
            SealedStorageClass::ContractColdState,
            SealedStorageClass::ContractCodeMetadata,
            SealedStorageClass::ContractEventIndex,
            SealedStorageClass::ContractOracleCache,
            SealedStorageClass::ContractSessionState,
            SealedStorageClass::ContractBridgeState,
            SealedStorageClass::ContractDefiState,
            SealedStorageClass::ContractGovernanceState,
            SealedStorageClass::ContractVerifyingKey,
            SealedStorageClass::ContractArchiveState,
        ];
        for storage_class in classes {
            self.storage_class_policies.insert(
                storage_class.as_str().to_string(),
                StorageClassPolicy::new(storage_class),
            );
        }
    }

    pub fn register_namespace(
        &mut self,
        contract_commitment: impl Into<String>,
        owner_commitment: impl Into<String>,
        salt_commitment: impl Into<String>,
        namespace_label: impl AsRef<str>,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        ensure!(
            self.namespaces.len() < self.config.max_namespaces,
            "namespace capacity exceeded"
        );
        let contract_commitment = contract_commitment.into();
        let owner_commitment = owner_commitment.into();
        let salt_commitment = salt_commitment.into();
        let namespace_label = namespace_label.as_ref();
        let namespace_label_hash = deterministic_root("namespace-label", namespace_label);
        let namespace_commitment = namespace_commitment(
            &contract_commitment,
            &owner_commitment,
            &salt_commitment,
            &namespace_label_hash,
        );
        let namespace_id = namespace_id(&namespace_commitment, self.current_height);
        ensure!(
            !self.namespaces.contains_key(&namespace_id),
            "namespace already registered"
        );
        let namespace = ContractNamespaceCommitment {
            namespace_id: namespace_id.clone(),
            contract_commitment,
            namespace_commitment,
            owner_commitment,
            salt_commitment,
            namespace_label_hash,
            status: NamespaceStatus::Active,
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.namespace_ttl_blocks),
            latest_cell_root: empty_root("namespace-cells"),
            privacy_scope_root: deterministic_root("privacy-scope", &namespace_id),
            rent_account_root: deterministic_root("rent-account", &namespace_id),
        };
        self.namespaces.insert(namespace_id.clone(), namespace);
        self.namespace_cells
            .entry(namespace_id.clone())
            .or_default();
        self.namespace_proofs
            .entry(namespace_id.clone())
            .or_default();
        self.namespace_credits
            .entry(namespace_id.clone())
            .or_default();
        self.namespace_budgets
            .entry(namespace_id.clone())
            .or_default();
        self.refresh_counters();
        self.refresh_roots();
        Ok(namespace_id)
    }

    pub fn seal_cell(
        &mut self,
        namespace_id: impl AsRef<str>,
        storage_class: SealedStorageClass,
        encrypted_payload_root: impl Into<String>,
        byte_size: u64,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        ensure!(
            self.sealed_cells.len() < self.config.max_sealed_cells,
            "sealed cell capacity exceeded"
        );
        let namespace_id = namespace_id.as_ref().to_string();
        let namespace = self
            .namespaces
            .get(&namespace_id)
            .ok_or_else(|| "namespace not found".to_string())?;
        ensure!(
            namespace.status.accepts_cells(),
            "namespace does not accept sealed cells"
        );
        let policy = self
            .storage_class_policies
            .get(storage_class.as_str())
            .ok_or_else(|| "storage class policy not found".to_string())?;
        ensure!(
            byte_size <= policy.max_cell_bytes,
            "cell byte size exceeds class cap"
        );
        let encrypted_payload_root = encrypted_payload_root.into();
        let prior_cell_root = namespace.latest_cell_root.clone();
        let current_cell_root = cell_payload_root(
            &namespace_id,
            storage_class,
            &prior_cell_root,
            &encrypted_payload_root,
            byte_size,
            self.current_height,
        );
        let cell_commitment = deterministic_root("cell-commitment", &current_cell_root);
        let cell_id = cell_id(&namespace_id, &cell_commitment, self.current_height);
        let cell = SealedStorageCell {
            cell_id: cell_id.clone(),
            namespace_id: namespace_id.clone(),
            storage_class,
            cell_commitment,
            encrypted_payload_root,
            prior_cell_root,
            current_cell_root: current_cell_root.clone(),
            byte_size,
            rent_epoch: self.current_height / self.config.storage_cell_ttl_blocks.max(1),
            status: CellStatus::Sealed,
            opened_at_height: self.current_height,
            prepaid_until_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.storage_cell_ttl_blocks),
            last_proof_id: None,
            privacy_budget_id: None,
            eviction_lane_id: None,
        };
        self.sealed_cells.insert(cell_id.clone(), cell);
        self.namespace_cells
            .entry(namespace_id.clone())
            .or_default()
            .insert(cell_id.clone());
        if let Some(namespace) = self.namespaces.get_mut(&namespace_id) {
            namespace.latest_cell_root = current_cell_root;
        }
        self.refresh_counters();
        self.refresh_roots();
        Ok(cell_id)
    }

    pub fn mint_prepaid_credit(
        &mut self,
        namespace_id: impl AsRef<str>,
        owner_commitment: impl Into<String>,
        amount_micro_credits: u128,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        ensure!(
            self.prepaid_credits.len() < self.config.max_prepaid_credits,
            "prepaid credit capacity exceeded"
        );
        ensure!(
            amount_micro_credits > 0,
            "prepaid credit amount must be nonzero"
        );
        let namespace_id = namespace_id.as_ref().to_string();
        ensure!(
            self.namespaces.contains_key(&namespace_id),
            "namespace not found"
        );
        let owner_commitment = owner_commitment.into();
        let bonus = amount_micro_credits
            .saturating_mul(self.config.prepaid_credit_bonus_bps as u128)
            / MAX_BPS as u128;
        let credit_commitment =
            prepaid_credit_commitment(&namespace_id, &owner_commitment, amount_micro_credits);
        let credit_id = prepaid_credit_id(&namespace_id, &credit_commitment, self.current_height);
        let credit = PrepaidStateCredit {
            credit_id: credit_id.clone(),
            owner_commitment,
            namespace_id: namespace_id.clone(),
            credit_commitment,
            amount_micro_credits: amount_micro_credits.saturating_add(bonus),
            spent_micro_credits: 0,
            bonus_bps: self.config.prepaid_credit_bonus_bps,
            status: CreditStatus::Minted,
            issued_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.credit_ttl_blocks),
            nullifier_root: deterministic_root("credit-nullifier", &credit_id),
        };
        self.prepaid_credits.insert(credit_id.clone(), credit);
        self.namespace_credits
            .entry(namespace_id)
            .or_default()
            .insert(credit_id.clone());
        self.refresh_counters();
        self.refresh_roots();
        Ok(credit_id)
    }

    pub fn open_privacy_budget(
        &mut self,
        namespace_id: impl AsRef<str>,
        owner_commitment: impl Into<String>,
        total_units: u64,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        ensure!(
            self.privacy_budgets.len() < self.config.max_privacy_budgets,
            "privacy budget capacity exceeded"
        );
        ensure!(
            total_units > 0,
            "privacy budget total units must be nonzero"
        );
        let namespace_id = namespace_id.as_ref().to_string();
        let namespace = self
            .namespaces
            .get(&namespace_id)
            .ok_or_else(|| "namespace not found".to_string())?;
        let owner_commitment = owner_commitment.into();
        let scope_root = namespace.privacy_scope_root.clone();
        let nullifier_domain = deterministic_root("privacy-nullifier-domain", &namespace_id);
        let budget_id = privacy_budget_id(
            &namespace_id,
            &owner_commitment,
            &scope_root,
            &nullifier_domain,
            self.current_height,
        );
        let budget = PrivacyBudget {
            budget_id: budget_id.clone(),
            namespace_id: namespace_id.clone(),
            owner_commitment,
            scope_root,
            nullifier_domain,
            total_units,
            spent_units: 0,
            min_anonymity_set: self.config.min_anonymity_set,
            status: BudgetStatus::Open,
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.privacy_budget_ttl_blocks),
        };
        self.privacy_budgets.insert(budget_id.clone(), budget);
        self.namespace_budgets
            .entry(namespace_id)
            .or_default()
            .insert(budget_id.clone());
        self.refresh_counters();
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn submit_rent_proof(
        &mut self,
        proof_kind: RentProofKind,
        namespace_id: impl AsRef<str>,
        cell_id: Option<String>,
        prover_commitment: impl Into<String>,
        proof_commitment: impl Into<String>,
        aggregate_witness_root: impl Into<String>,
        privacy_budget_id: Option<String>,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        ensure!(
            self.rent_proofs.len() < self.config.max_rent_proofs,
            "rent proof capacity exceeded"
        );
        let namespace_id = namespace_id.as_ref().to_string();
        ensure!(
            self.namespaces.contains_key(&namespace_id),
            "namespace not found"
        );
        if let Some(cell_id) = &cell_id {
            ensure!(self.sealed_cells.contains_key(cell_id), "cell not found");
        }
        let privacy_units_spent = cell_id
            .as_ref()
            .and_then(|id| self.sealed_cells.get(id))
            .map(|cell| privacy_units_for_cell(cell.byte_size))
            .unwrap_or(1);
        if let Some(budget_id) = &privacy_budget_id {
            self.spend_privacy_budget(budget_id, privacy_units_spent)?;
        }
        let rent_charged_micro_credits = cell_id
            .as_ref()
            .and_then(|id| self.sealed_cells.get(id))
            .map(|cell| self.rent_charge_for_cell(cell))
            .unwrap_or(self.config.base_rent_micro_credits as u128);
        let prover_commitment = prover_commitment.into();
        let proof_commitment = proof_commitment.into();
        let aggregate_witness_root = aggregate_witness_root.into();
        let proof_id = rent_proof_id(
            proof_kind,
            &namespace_id,
            cell_id.as_deref(),
            &prover_commitment,
            &proof_commitment,
            self.current_height,
        );
        let proof = PqRentProof {
            proof_id: proof_id.clone(),
            proof_kind,
            namespace_id: namespace_id.clone(),
            cell_id: cell_id.clone(),
            prover_commitment,
            proof_commitment,
            aggregate_witness_root,
            rent_charged_micro_credits,
            privacy_units_spent,
            pq_security_bits: proof_kind.required_security_bits(),
            anonymity_set: self.config.batch_anonymity_set,
            status: ProofStatus::Accepted,
            submitted_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.rent_proof_ttl_blocks),
        };
        self.rent_proofs.insert(proof_id.clone(), proof);
        self.namespace_proofs
            .entry(namespace_id)
            .or_default()
            .insert(proof_id.clone());
        if let Some(cell_id) = cell_id {
            let ttl = self.config.storage_cell_ttl_blocks;
            if let Some(cell) = self.sealed_cells.get_mut(&cell_id) {
                cell.status = CellStatus::ProofAccepted;
                cell.last_proof_id = Some(proof_id.clone());
                cell.privacy_budget_id = privacy_budget_id;
                cell.prepaid_until_height = self.current_height.saturating_add(ttl);
                cell.expires_at_height = self.current_height.saturating_add(ttl);
            }
        }
        self.refresh_counters();
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn open_low_fee_eviction_lane(
        &mut self,
        namespace_id: impl AsRef<str>,
        lane_kind: EvictionLaneKind,
        sponsor_commitment: impl Into<String>,
        target_cells: u64,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        ensure!(
            self.eviction_lanes.len() < self.config.max_eviction_lanes,
            "eviction lane capacity exceeded"
        );
        let namespace_id = namespace_id.as_ref().to_string();
        ensure!(
            self.namespaces.contains_key(&namespace_id),
            "namespace not found"
        );
        let sponsor_commitment = sponsor_commitment.into();
        let lane_id = eviction_lane_id(
            lane_kind,
            &namespace_id,
            &sponsor_commitment,
            self.current_height,
        );
        let lane = LowFeeEvictionLane {
            lane_id: lane_id.clone(),
            lane_kind,
            namespace_id: namespace_id.clone(),
            sponsor_commitment,
            candidate_root: empty_root("eviction-candidates"),
            fee_cap_bps: self.config.max_user_fee_bps,
            discount_bps: self.config.low_fee_discount_bps,
            target_cells,
            evicted_cells: 0,
            status: LaneStatus::Open,
            opened_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.eviction_lane_ttl_blocks),
        };
        self.eviction_lanes.insert(lane_id.clone(), lane);
        self.lane_candidates.entry(lane_id.clone()).or_default();
        self.refresh_counters();
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn queue_eviction_candidate(
        &mut self,
        lane_id: impl AsRef<str>,
        cell_id: impl AsRef<str>,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        let lane_id = lane_id.as_ref().to_string();
        let lane = self
            .eviction_lanes
            .get(&lane_id)
            .ok_or_else(|| "eviction lane not found".to_string())?;
        ensure!(lane.status == LaneStatus::Open, "eviction lane is not open");
        let cell_id = cell_id.as_ref().to_string();
        let cell = self
            .sealed_cells
            .get(&cell_id)
            .ok_or_else(|| "cell not found".to_string())?;
        ensure!(
            cell.namespace_id == lane.namespace_id,
            "cell namespace does not match lane"
        );
        ensure!(
            self.storage_class_policies
                .get(cell.storage_class.as_str())
                .map(|policy| policy.low_fee_eviction_allowed)
                .unwrap_or(false),
            "storage class cannot use low-fee eviction"
        );
        let rent_due_micro_credits = self.rent_charge_for_cell(cell);
        let eviction_score = eviction_score(cell, self.current_height);
        let candidate_id = eviction_candidate_id(&lane_id, &cell_id, self.current_height);
        let candidate = EvictionCandidate {
            candidate_id: candidate_id.clone(),
            lane_id: lane_id.clone(),
            namespace_id: cell.namespace_id.clone(),
            cell_id: cell_id.clone(),
            storage_class: cell.storage_class,
            eviction_score,
            rent_due_micro_credits,
            proof_id: cell.last_proof_id.clone(),
            queued_at_height: self.current_height,
        };
        self.eviction_candidates
            .insert(candidate_id.clone(), candidate);
        self.lane_candidates
            .entry(lane_id.clone())
            .or_default()
            .insert(candidate_id.clone());
        if let Some(cell) = self.sealed_cells.get_mut(&cell_id) {
            cell.status = CellStatus::EvictionQueued;
            cell.eviction_lane_id = Some(lane_id.clone());
        }
        let candidates = self
            .lane_candidates
            .get(&lane_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.eviction_candidates.get(id))
                    .map(EvictionCandidate::public_record)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(lane) = self.eviction_lanes.get_mut(&lane_id) {
            lane.candidate_root = record_map_root("eviction-lane-candidates", candidates);
        }
        self.refresh_counters();
        self.refresh_roots();
        Ok(candidate_id)
    }

    pub fn file_challenge(
        &mut self,
        challenge_kind: ChallengeKind,
        challenger_commitment: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        evidence_root: impl Into<String>,
        bond_micro_credits: u128,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<String> {
        ensure!(
            self.challenges.len() < self.config.max_challenges,
            "challenge capacity exceeded"
        );
        let challenger_commitment = challenger_commitment.into();
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let evidence_root = evidence_root.into();
        let challenge_id = challenge_id(
            challenge_kind,
            &challenger_commitment,
            &subject_kind,
            &subject_id,
            &evidence_root,
            self.current_height,
        );
        let challenge = RentChallenge {
            challenge_id: challenge_id.clone(),
            challenge_kind,
            challenger_commitment,
            subject_kind,
            subject_id,
            evidence_root,
            bond_micro_credits,
            status: ChallengeStatus::Filed,
            filed_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.challenge_window_blocks),
        };
        self.challenges.insert(challenge_id.clone(), challenge);
        self.refresh_counters();
        self.refresh_roots();
        Ok(challenge_id)
    }

    pub fn spend_prepaid_credit(
        &mut self,
        credit_id: impl AsRef<str>,
        amount_micro_credits: u128,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<()> {
        let credit = self
            .prepaid_credits
            .get_mut(credit_id.as_ref())
            .ok_or_else(|| "prepaid credit not found".to_string())?;
        ensure!(
            credit.available_micro_credits() >= amount_micro_credits,
            "insufficient prepaid credit"
        );
        credit.spent_micro_credits = credit
            .spent_micro_credits
            .saturating_add(amount_micro_credits);
        credit.status = if credit.available_micro_credits() == 0 {
            CreditStatus::Spent
        } else {
            CreditStatus::Reserved
        };
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn spend_privacy_budget(
        &mut self,
        budget_id: impl AsRef<str>,
        units: u64,
    ) -> PrivateL2PqConfidentialSmartContractStateRentRuntimeResult<()> {
        let budget = self
            .privacy_budgets
            .get_mut(budget_id.as_ref())
            .ok_or_else(|| "privacy budget not found".to_string())?;
        ensure!(
            budget.remaining_units() >= units,
            "privacy budget exhausted"
        );
        budget.spent_units = budget.spent_units.saturating_add(units);
        budget.status = if budget.remaining_units() == 0 {
            BudgetStatus::Exhausted
        } else {
            BudgetStatus::PartiallySpent
        };
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn rent_charge_for_cell(&self, cell: &SealedStorageCell) -> u128 {
        let weight = cell.storage_class.rent_weight_bps();
        let byte_units = cell.byte_size.div_ceil(1024).max(1);
        (self.config.base_rent_micro_credits as u128)
            .saturating_mul(byte_units as u128)
            .saturating_mul(weight as u128)
            .div_ceil(MAX_BPS as u128)
    }

    pub fn public_records(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        records.insert("counters".to_string(), self.counters.public_record());
        for (id, policy) in &self.storage_class_policies {
            records.insert(format!("storage_class:{id}"), policy.public_record());
        }
        for (id, namespace) in &self.namespaces {
            records.insert(format!("namespace:{id}"), namespace.public_record());
        }
        for (id, cell) in &self.sealed_cells {
            records.insert(format!("sealed_cell:{id}"), cell.public_record());
        }
        for (id, proof) in &self.rent_proofs {
            records.insert(format!("rent_proof:{id}"), proof.public_record());
        }
        for (id, credit) in &self.prepaid_credits {
            records.insert(format!("prepaid_credit:{id}"), credit.public_record());
        }
        for (id, lane) in &self.eviction_lanes {
            records.insert(format!("eviction_lane:{id}"), lane.public_record());
        }
        for (id, candidate) in &self.eviction_candidates {
            records.insert(
                format!("eviction_candidate:{id}"),
                candidate.public_record(),
            );
        }
        for (id, budget) in &self.privacy_budgets {
            records.insert(format!("privacy_budget:{id}"), budget.public_record());
        }
        for (id, challenge) in &self.challenges {
            records.insert(format!("challenge:{id}"), challenge.public_record());
        }
        records
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "storage_class_root": self.roots.storage_class_root,
                "namespace_root": self.roots.namespace_root,
                "namespace_commitment_root": self.roots.namespace_commitment_root,
                "sealed_cell_root": self.roots.sealed_cell_root,
                "rent_proof_root": self.roots.rent_proof_root,
                "prepaid_credit_root": self.roots.prepaid_credit_root,
                "eviction_lane_root": self.roots.eviction_lane_root,
                "eviction_candidate_root": self.roots.eviction_candidate_root,
                "privacy_budget_root": self.roots.privacy_budget_root,
                "challenge_root": self.roots.challenge_root,
                "public_record_root": self.roots.public_record_root,
                "index_root": self.roots.index_root,
                "counters_root": self.roots.counters_root
            },
            "storage_classes": self.storage_class_policies.values().map(StorageClassPolicy::public_record).collect::<Vec<_>>(),
            "namespaces": self.namespaces.values().map(ContractNamespaceCommitment::public_record).collect::<Vec<_>>(),
            "sealed_cells": self.sealed_cells.values().map(SealedStorageCell::public_record).collect::<Vec<_>>(),
            "rent_proofs": self.rent_proofs.values().map(PqRentProof::public_record).collect::<Vec<_>>(),
            "prepaid_credits": self.prepaid_credits.values().map(PrepaidStateCredit::public_record).collect::<Vec<_>>(),
            "eviction_lanes": self.eviction_lanes.values().map(LowFeeEvictionLane::public_record).collect::<Vec<_>>(),
            "eviction_candidates": self.eviction_candidates.values().map(EvictionCandidate::public_record).collect::<Vec<_>>(),
            "privacy_budgets": self.privacy_budgets.values().map(PrivacyBudget::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(RentChallenge::public_record).collect::<Vec<_>>()
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_counters(&mut self) {
        self.counters.namespace_count = self.namespaces.len() as u64;
        self.counters.sealed_cell_count = self.sealed_cells.len() as u64;
        self.counters.live_cell_count = self
            .sealed_cells
            .values()
            .filter(|cell| cell.status.live())
            .count() as u64;
        self.counters.rent_proof_count = self.rent_proofs.len() as u64;
        self.counters.accepted_rent_proof_count = self
            .rent_proofs
            .values()
            .filter(|proof| proof.status == ProofStatus::Accepted)
            .count() as u64;
        self.counters.prepaid_credit_count = self.prepaid_credits.len() as u64;
        self.counters.prepaid_credits_minted = self
            .prepaid_credits
            .values()
            .map(|credit| credit.amount_micro_credits)
            .sum();
        self.counters.prepaid_credits_spent = self
            .prepaid_credits
            .values()
            .map(|credit| credit.spent_micro_credits)
            .sum();
        self.counters.low_fee_eviction_lane_count = self.eviction_lanes.len() as u64;
        self.counters.eviction_candidate_count = self.eviction_candidates.len() as u64;
        self.counters.evicted_cell_count = self
            .sealed_cells
            .values()
            .filter(|cell| cell.status == CellStatus::Evicted)
            .count() as u64;
        self.counters.restored_cell_count = self
            .sealed_cells
            .values()
            .filter(|cell| cell.status == CellStatus::Restored)
            .count() as u64;
        self.counters.privacy_budget_count = self.privacy_budgets.len() as u64;
        self.counters.privacy_budget_units = self
            .privacy_budgets
            .values()
            .map(|budget| budget.total_units)
            .sum();
        self.counters.privacy_budget_spent = self
            .privacy_budgets
            .values()
            .map(|budget| budget.spent_units)
            .sum();
        self.counters.namespace_commitment_count = self.namespaces.len() as u64;
        self.counters.public_record_count = self.public_records().len() as u64;
        self.counters.challenge_count = self.challenges.len() as u64;
        self.counters.accepted_challenge_count = self
            .challenges
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Accepted)
            .count() as u64;
        self.counters.deterministic_root_count = 15;
    }

    pub fn refresh_roots(&mut self) {
        self.public_records = self.public_records();
        self.roots.config_root = payload_root("config", &self.config.public_record());
        self.roots.storage_class_root = record_map_root(
            "storage-classes",
            self.storage_class_policies
                .values()
                .map(StorageClassPolicy::public_record)
                .collect(),
        );
        self.roots.namespace_root = record_map_root(
            "namespaces",
            self.namespaces
                .values()
                .map(ContractNamespaceCommitment::public_record)
                .collect(),
        );
        self.roots.namespace_commitment_root = merkle_from_strings(
            "namespace-commitments",
            &self
                .namespaces
                .values()
                .map(|namespace| namespace.namespace_commitment.clone())
                .collect::<BTreeSet<_>>(),
        );
        self.roots.sealed_cell_root = record_map_root(
            "sealed-cells",
            self.sealed_cells
                .values()
                .map(SealedStorageCell::public_record)
                .collect(),
        );
        self.roots.rent_proof_root = record_map_root(
            "rent-proofs",
            self.rent_proofs
                .values()
                .map(PqRentProof::public_record)
                .collect(),
        );
        self.roots.prepaid_credit_root = record_map_root(
            "prepaid-credits",
            self.prepaid_credits
                .values()
                .map(PrepaidStateCredit::public_record)
                .collect(),
        );
        self.roots.eviction_lane_root = record_map_root(
            "eviction-lanes",
            self.eviction_lanes
                .values()
                .map(LowFeeEvictionLane::public_record)
                .collect(),
        );
        self.roots.eviction_candidate_root = record_map_root(
            "eviction-candidates",
            self.eviction_candidates
                .values()
                .map(EvictionCandidate::public_record)
                .collect(),
        );
        self.roots.privacy_budget_root = record_map_root(
            "privacy-budgets",
            self.privacy_budgets
                .values()
                .map(PrivacyBudget::public_record)
                .collect(),
        );
        self.roots.challenge_root = record_map_root(
            "challenges",
            self.challenges
                .values()
                .map(RentChallenge::public_record)
                .collect(),
        );
        self.roots.public_record_root = record_map_root(
            "public-records",
            self.public_records.values().cloned().collect::<Vec<_>>(),
        );
        self.roots.index_root = payload_root(
            "indices",
            &json!({
                "namespace_cells": map_set_root("namespace-cells", &self.namespace_cells),
                "namespace_proofs": map_set_root("namespace-proofs", &self.namespace_proofs),
                "namespace_credits": map_set_root("namespace-credits", &self.namespace_credits),
                "namespace_budgets": map_set_root("namespace-budgets", &self.namespace_budgets),
                "lane_candidates": map_set_root("lane-candidates", &self.lane_candidates)
            }),
        );
        self.roots.counters_root = payload_root("counters", &self.counters.public_record());
        self.roots.state_root = self.state_root();
    }

    pub fn seed_devnet(&mut self) {
        let namespace_id = self
            .register_namespace(
                deterministic_root("contract", "confidential-vault"),
                deterministic_root("owner", "devnet-vault-operator"),
                deterministic_root("salt", "vault-state-rent"),
                "confidential.vault.state",
            )
            .expect("devnet namespace");
        let budget_id = self
            .open_privacy_budget(
                &namespace_id,
                deterministic_root("owner", "devnet-vault-operator"),
                16_384,
            )
            .expect("devnet privacy budget");
        let credit_id = self
            .mint_prepaid_credit(
                &namespace_id,
                deterministic_root("owner", "devnet-vault-operator"),
                9_000_000,
            )
            .expect("devnet prepaid credit");
        let hot_cell = self
            .seal_cell(
                &namespace_id,
                SealedStorageClass::ContractHotState,
                deterministic_root("payload", "vault-hot-collateral-map"),
                48_128,
            )
            .expect("devnet hot cell");
        let warm_cell = self
            .seal_cell(
                &namespace_id,
                SealedStorageClass::ContractWarmState,
                deterministic_root("payload", "vault-warm-liquidation-cache"),
                188_416,
            )
            .expect("devnet warm cell");
        let proof_id = self
            .submit_rent_proof(
                RentProofKind::Occupancy,
                &namespace_id,
                Some(hot_cell),
                deterministic_root("prover", "devnet-rent-prover"),
                deterministic_root("proof", "vault-hot-occupancy"),
                deterministic_root("witness", "vault-hot-witness"),
                Some(budget_id.clone()),
            )
            .expect("devnet rent proof");
        let lane_id = self
            .open_low_fee_eviction_lane(
                &namespace_id,
                EvictionLaneKind::LowFeeBatch,
                deterministic_root("sponsor", "devnet-low-fee-sponsor"),
                64,
            )
            .expect("devnet eviction lane");
        let _candidate_id = self
            .queue_eviction_candidate(&lane_id, warm_cell)
            .expect("devnet eviction candidate");
        let due = self
            .rent_proofs
            .get(&proof_id)
            .map(|proof| proof.rent_charged_micro_credits)
            .unwrap_or(0);
        self.spend_prepaid_credit(credit_id, due)
            .expect("devnet credit spend");
        self.refresh_counters();
        self.refresh_roots();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn namespace_commitment(
    contract_commitment: &str,
    owner_commitment: &str,
    salt_commitment: &str,
    namespace_label_hash: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-NAMESPACE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(contract_commitment),
            HashPart::Str(owner_commitment),
            HashPart::Str(salt_commitment),
            HashPart::Str(namespace_label_hash),
        ],
        32,
    )
}

pub fn namespace_id(namespace_commitment: &str, opened_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-NAMESPACE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace_commitment),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn cell_payload_root(
    namespace_id: &str,
    storage_class: SealedStorageClass,
    prior_cell_root: &str,
    encrypted_payload_root: &str,
    byte_size: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-CELL-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(namespace_id),
            HashPart::Str(storage_class.as_str()),
            HashPart::Str(prior_cell_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::U64(byte_size),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn cell_id(namespace_id: &str, cell_commitment: &str, opened_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-CELL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace_id),
            HashPart::Str(cell_commitment),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn rent_proof_id(
    proof_kind: RentProofKind,
    namespace_id: &str,
    cell_id: Option<&str>,
    prover_commitment: &str,
    proof_commitment: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_kind.as_str()),
            HashPart::Str(namespace_id),
            HashPart::Str(cell_id.unwrap_or("namespace")),
            HashPart::Str(prover_commitment),
            HashPart::Str(proof_commitment),
            HashPart::U64(submitted_at_height),
        ],
        32,
    )
}

pub fn prepaid_credit_commitment(
    namespace_id: &str,
    owner_commitment: &str,
    amount_micro_credits: u128,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-PREPAID-CREDIT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(namespace_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(amount_micro_credits as i128),
        ],
        32,
    )
}

pub fn prepaid_credit_id(
    namespace_id: &str,
    credit_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-PREPAID-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace_id),
            HashPart::Str(credit_commitment),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn eviction_lane_id(
    lane_kind: EvictionLaneKind,
    namespace_id: &str,
    sponsor_commitment: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-EVICTION-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(namespace_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn eviction_candidate_id(lane_id: &str, cell_id: &str, queued_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-EVICTION-CANDIDATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(cell_id),
            HashPart::U64(queued_at_height),
        ],
        32,
    )
}

pub fn privacy_budget_id(
    namespace_id: &str,
    owner_commitment: &str,
    scope_root: &str,
    nullifier_domain: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(scope_root),
            HashPart::Str(nullifier_domain),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn challenge_id(
    challenge_kind: ChallengeKind,
    challenger_commitment: &str,
    subject_kind: &str,
    subject_id: &str,
    evidence_root: &str,
    filed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(challenger_commitment),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::U64(filed_at_height),
        ],
        32,
    )
}

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-{domain}"),
        &[],
    )
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("state", record)
}

pub fn public_record_root(records: &[Value]) -> String {
    merkle_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-PUBLIC-RECORD",
        records,
    )
}

pub fn record_map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-{domain}"),
        &records,
    )
}

pub fn merkle_from_strings(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-{domain}"),
        &leaves,
    )
}

pub fn map_set_root(domain: &str, values: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = values
        .iter()
        .map(|(key, set)| {
            json!({
                "key": key,
                "root": merkle_from_strings(domain, set),
                "len": set.len()
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-SMART-CONTRACT-STATE-RENT-{domain}-MAP"),
        &leaves,
    )
}

pub fn privacy_units_for_cell(byte_size: u64) -> u64 {
    1 + byte_size.div_ceil(16_384)
}

pub fn eviction_score(cell: &SealedStorageCell, current_height: u64) -> u64 {
    let age = current_height.saturating_sub(cell.prepaid_until_height);
    let class_priority = cell.storage_class.eviction_priority_bps();
    let size_units = cell.byte_size.div_ceil(1024).max(1);
    age.saturating_mul(class_priority)
        .saturating_add(size_units)
        .saturating_add(cell.rent_epoch)
}
