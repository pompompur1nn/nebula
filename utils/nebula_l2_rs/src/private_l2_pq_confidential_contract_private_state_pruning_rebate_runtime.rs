use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateStatePruningRebateRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STATE_PRUNING_REBATE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-private-state-pruning-rebate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STATE_PRUNING_REBATE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEGMENT_COMMITMENT_SUITE: &str =
    "private-l2-confidential-contract-segment-commitment-root-v1";
pub const PRUNING_PROOF_SUITE: &str =
    "private-l2-confidential-contract-state-pruning-proof-root-v1";
pub const STORAGE_COMMITMENT_SUITE: &str =
    "private-l2-confidential-contract-storage-commitment-root-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-state-pruning-attestation-v1";
pub const REBATE_COUPON_SUITE: &str = "low-fee-private-state-pruning-rebate-coupon-root-v1";
pub const COMPACTION_WINDOW_SUITE: &str =
    "deterministic-private-contract-compaction-window-root-v1";
pub const EVICTION_GUARD_SUITE: &str = "privacy-preserving-private-state-eviction-guard-root-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "selective-disclosure-private-state-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "roots-only-private-state-pruning-operator-summary-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-contract-private-state-pruning-rebate-public-record-v1";
pub const DEVNET_RUNTIME_ID: &str =
    "private-l2-pq-confidential-contract-private-state-pruning-rebate-devnet";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-contract-private-state-pruning-rebate-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_044_800;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_COMPACTION_WINDOW_BLOCKS: u64 = 180;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_EVICTION_GUARD_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u64 = 48;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 2_500;
pub const DEFAULT_OPERATOR_REWARD_SHARE_BPS: u64 = 1_500;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MAX_COMPACTION_DRIFT_BPS: u64 = 75;
pub const DEFAULT_SEGMENT_SIZE_BYTES: u64 = 262_144;
pub const DEFAULT_MIN_PRUNABLE_BYTES: u64 = 65_536;
pub const DEFAULT_FAST_PATH_PROOF_WEIGHT: u64 = 16;
pub const DEFAULT_MAX_SEGMENTS: usize = 524_288;
pub const DEFAULT_MAX_PRUNING_PROOFS: usize = 524_288;
pub const DEFAULT_MAX_STORAGE_COMMITMENTS: usize = 262_144;
pub const DEFAULT_MAX_PQ_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATE_COUPONS: usize = 524_288;
pub const DEFAULT_MAX_COMPACTION_WINDOWS: usize = 131_072;
pub const DEFAULT_MAX_EVICTION_GUARDS: usize = 262_144;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 65_536;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    ContractStorage,
    NullifierCache,
    EventTrace,
    WitnessCache,
    ViewKeyEnvelope,
    RollupScratch,
    ArchivedSnapshot,
}

impl SegmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractStorage => "contract_storage",
            Self::NullifierCache => "nullifier_cache",
            Self::EventTrace => "event_trace",
            Self::WitnessCache => "witness_cache",
            Self::ViewKeyEnvelope => "view_key_envelope",
            Self::RollupScratch => "rollup_scratch",
            Self::ArchivedSnapshot => "archived_snapshot",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::ContractStorage
                | Self::NullifierCache
                | Self::WitnessCache
                | Self::ViewKeyEnvelope
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentStatus {
    Active,
    Frozen,
    Proving,
    Prunable,
    Pruned,
    Quarantined,
    Retained,
}

impl SegmentStatus {
    pub fn can_prune(self) -> bool {
        matches!(self, Self::Frozen | Self::Proving | Self::Prunable)
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Frozen | Self::Proving | Self::Prunable
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PruningProofKind {
    InclusionExclusion,
    StateDiff,
    TombstoneWitness,
    RangeRetention,
    RecursiveBatch,
    EmergencyDrain,
}

impl PruningProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InclusionExclusion => "inclusion_exclusion",
            Self::StateDiff => "state_diff",
            Self::TombstoneWitness => "tombstone_witness",
            Self::RangeRetention => "range_retention",
            Self::RecursiveBatch => "recursive_batch",
            Self::EmergencyDrain => "emergency_drain",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Draft,
    Submitted,
    Attested,
    Accepted,
    Rejected,
    Expired,
    Slashed,
}

impl ProofStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Attested | Self::Accepted)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Rejected | Self::Expired | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approved,
    NeedsDelay,
    PrivacyInsufficient,
    FeeTooHigh,
    InvalidPqSignature,
    ReplayDetected,
    GuardViolated,
    Rejected,
}

impl AttestationVerdict {
    pub fn positive(self) -> bool {
        matches!(self, Self::Approved | Self::NeedsDelay)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Applied,
    Expired,
    Revoked,
    Slashed,
}

impl CouponStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Scheduled,
    Open,
    Sealing,
    Sealed,
    Cancelled,
}

impl WindowStatus {
    pub fn accepts_segments(self) -> bool {
        matches!(self, Self::Scheduled | Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardReason {
    RecentWrite,
    LiveNullifier,
    PendingWithdrawal,
    AuditHold,
    ContractUpgrade,
    PrivacyFloor,
    OperatorDispute,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Active,
    Satisfied,
    Overridden,
    Expired,
    Slashed,
}

impl GuardStatus {
    pub fn blocking(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Exhausted,
    Sealed,
    Revoked,
}

impl BudgetStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorHealth {
    Nominal,
    Watch,
    Throttled,
    Quarantined,
    Retired,
}

impl OperatorHealth {
    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Nominal | Self::Watch | Self::Throttled)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub runtime_id: String,
    pub runtime_mode: RuntimeMode,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub segment_commitment_suite: String,
    pub pruning_proof_suite: String,
    pub storage_commitment_suite: String,
    pub pq_attestation_suite: String,
    pub rebate_coupon_suite: String,
    pub compaction_window_suite: String,
    pub eviction_guard_suite: String,
    pub redaction_budget_suite: String,
    pub operator_summary_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub epoch_blocks: u64,
    pub compaction_window_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub eviction_guard_ttl_blocks: u64,
    pub redaction_budget_per_epoch: u64,
    pub max_user_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub operator_reward_share_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub max_compaction_drift_bps: u64,
    pub segment_size_bytes: u64,
    pub min_prunable_bytes: u64,
    pub fast_path_proof_weight: u64,
    pub max_segments: usize,
    pub max_pruning_proofs: usize,
    pub max_storage_commitments: usize,
    pub max_pq_attestations: usize,
    pub max_rebate_coupons: usize,
    pub max_compaction_windows: usize,
    pub max_eviction_guards: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_public_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            runtime_mode: RuntimeMode::Devnet,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            segment_commitment_suite: SEGMENT_COMMITMENT_SUITE.to_string(),
            pruning_proof_suite: PRUNING_PROOF_SUITE.to_string(),
            storage_commitment_suite: STORAGE_COMMITMENT_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            rebate_coupon_suite: REBATE_COUPON_SUITE.to_string(),
            compaction_window_suite: COMPACTION_WINDOW_SUITE.to_string(),
            eviction_guard_suite: EVICTION_GUARD_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            compaction_window_blocks: DEFAULT_COMPACTION_WINDOW_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            eviction_guard_ttl_blocks: DEFAULT_EVICTION_GUARD_TTL_BLOCKS,
            redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            operator_reward_share_bps: DEFAULT_OPERATOR_REWARD_SHARE_BPS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            max_compaction_drift_bps: DEFAULT_MAX_COMPACTION_DRIFT_BPS,
            segment_size_bytes: DEFAULT_SEGMENT_SIZE_BYTES,
            min_prunable_bytes: DEFAULT_MIN_PRUNABLE_BYTES,
            fast_path_proof_weight: DEFAULT_FAST_PATH_PROOF_WEIGHT,
            max_segments: DEFAULT_MAX_SEGMENTS,
            max_pruning_proofs: DEFAULT_MAX_PRUNING_PROOFS,
            max_storage_commitments: DEFAULT_MAX_STORAGE_COMMITMENTS,
            max_pq_attestations: DEFAULT_MAX_PQ_ATTESTATIONS,
            max_rebate_coupons: DEFAULT_MAX_REBATE_COUPONS,
            max_compaction_windows: DEFAULT_MAX_COMPACTION_WINDOWS,
            max_eviction_guards: DEFAULT_MAX_EVICTION_GUARDS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("runtime_id", &self.runtime_id)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_at_least(
            "min_pq_security_bits",
            u64::from(self.min_pq_security_bits),
            u64::from(DEFAULT_MIN_PQ_SECURITY_BITS),
        )?;
        ensure_at_least("min_privacy_set_size", self.min_privacy_set_size, 1)?;
        ensure_at_least(
            "target_privacy_set_size",
            self.target_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("compaction_window_blocks", self.compaction_window_blocks)?;
        ensure_positive("proof_ttl_blocks", self.proof_ttl_blocks)?;
        ensure_positive("rebate_ttl_blocks", self.rebate_ttl_blocks)?;
        ensure_positive("eviction_guard_ttl_blocks", self.eviction_guard_ttl_blocks)?;
        ensure_positive(
            "redaction_budget_per_epoch",
            self.redaction_budget_per_epoch,
        )?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("rebate_share_bps", self.rebate_share_bps)?;
        ensure_bps("operator_reward_share_bps", self.operator_reward_share_bps)?;
        ensure_bps(
            "min_attestation_quorum_bps",
            self.min_attestation_quorum_bps,
        )?;
        ensure_bps("max_compaction_drift_bps", self.max_compaction_drift_bps)?;
        ensure_positive("segment_size_bytes", self.segment_size_bytes)?;
        ensure_positive("min_prunable_bytes", self.min_prunable_bytes)?;
        ensure_positive("fast_path_proof_weight", self.fast_path_proof_weight)?;
        ensure_usize_positive("max_segments", self.max_segments)?;
        ensure_usize_positive("max_pruning_proofs", self.max_pruning_proofs)?;
        ensure_usize_positive("max_storage_commitments", self.max_storage_commitments)?;
        ensure_usize_positive("max_pq_attestations", self.max_pq_attestations)?;
        ensure_usize_positive("max_rebate_coupons", self.max_rebate_coupons)?;
        ensure_usize_positive("max_compaction_windows", self.max_compaction_windows)?;
        ensure_usize_positive("max_eviction_guards", self.max_eviction_guards)?;
        ensure_usize_positive("max_redaction_budgets", self.max_redaction_budgets)?;
        ensure_usize_positive("max_operator_summaries", self.max_operator_summaries)?;
        ensure_usize_positive("max_public_events", self.max_public_events)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "runtime_id": self.runtime_id,
            "runtime_mode": self.runtime_mode.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "segment_commitment_suite": self.segment_commitment_suite,
            "pruning_proof_suite": self.pruning_proof_suite,
            "storage_commitment_suite": self.storage_commitment_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "rebate_coupon_suite": self.rebate_coupon_suite,
            "compaction_window_suite": self.compaction_window_suite,
            "eviction_guard_suite": self.eviction_guard_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "operator_summary_suite": self.operator_summary_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "epoch_blocks": self.epoch_blocks,
            "compaction_window_blocks": self.compaction_window_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "eviction_guard_ttl_blocks": self.eviction_guard_ttl_blocks,
            "redaction_budget_per_epoch": self.redaction_budget_per_epoch,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_share_bps": self.rebate_share_bps,
            "operator_reward_share_bps": self.operator_reward_share_bps,
            "min_attestation_quorum_bps": self.min_attestation_quorum_bps,
            "max_compaction_drift_bps": self.max_compaction_drift_bps,
            "segment_size_bytes": self.segment_size_bytes,
            "min_prunable_bytes": self.min_prunable_bytes,
            "fast_path_proof_weight": self.fast_path_proof_weight,
            "capacity": {
                "segments": self.max_segments,
                "pruning_proofs": self.max_pruning_proofs,
                "storage_commitments": self.max_storage_commitments,
                "pq_attestations": self.max_pq_attestations,
                "rebate_coupons": self.max_rebate_coupons,
                "compaction_windows": self.max_compaction_windows,
                "eviction_guards": self.max_eviction_guards,
                "redaction_budgets": self.max_redaction_budgets,
                "operator_summaries": self.max_operator_summaries,
                "public_events": self.max_public_events,
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub segment_count: u64,
    pub live_segment_count: u64,
    pub pruned_segment_count: u64,
    pub pruning_proof_count: u64,
    pub accepted_proof_count: u64,
    pub rejected_proof_count: u64,
    pub storage_commitment_count: u64,
    pub pq_attestation_count: u64,
    pub rebate_coupon_count: u64,
    pub applied_coupon_count: u64,
    pub compaction_window_count: u64,
    pub eviction_guard_count: u64,
    pub active_guard_count: u64,
    pub redaction_budget_count: u64,
    pub operator_summary_count: u64,
    pub public_event_count: u64,
    pub prunable_bytes: u64,
    pub pruned_bytes: u64,
    pub rebate_units_minted: u64,
    pub rebate_units_applied: u64,
    pub fast_path_proofs: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "segment_count": self.segment_count,
            "live_segment_count": self.live_segment_count,
            "pruned_segment_count": self.pruned_segment_count,
            "pruning_proof_count": self.pruning_proof_count,
            "accepted_proof_count": self.accepted_proof_count,
            "rejected_proof_count": self.rejected_proof_count,
            "storage_commitment_count": self.storage_commitment_count,
            "pq_attestation_count": self.pq_attestation_count,
            "rebate_coupon_count": self.rebate_coupon_count,
            "applied_coupon_count": self.applied_coupon_count,
            "compaction_window_count": self.compaction_window_count,
            "eviction_guard_count": self.eviction_guard_count,
            "active_guard_count": self.active_guard_count,
            "redaction_budget_count": self.redaction_budget_count,
            "operator_summary_count": self.operator_summary_count,
            "public_event_count": self.public_event_count,
            "prunable_bytes": self.prunable_bytes,
            "pruned_bytes": self.pruned_bytes,
            "rebate_units_minted": self.rebate_units_minted,
            "rebate_units_applied": self.rebate_units_applied,
            "fast_path_proofs": self.fast_path_proofs,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub segment_root: String,
    pub pruning_proof_root: String,
    pub storage_commitment_root: String,
    pub pq_attestation_root: String,
    pub rebate_coupon_root: String,
    pub compaction_window_root: String,
    pub eviction_guard_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub replay_filter_root: String,
    pub public_event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root(
                "PRIVATE-STATE-PRUNING-REBATE-CONFIG",
                &config.public_record(),
            ),
            segment_root: empty_root("segments"),
            pruning_proof_root: empty_root("pruning_proofs"),
            storage_commitment_root: empty_root("storage_commitments"),
            pq_attestation_root: empty_root("pq_attestations"),
            rebate_coupon_root: empty_root("rebate_coupons"),
            compaction_window_root: empty_root("compaction_windows"),
            eviction_guard_root: empty_root("eviction_guards"),
            redaction_budget_root: empty_root("redaction_budgets"),
            operator_summary_root: empty_root("operator_summaries"),
            replay_filter_root: empty_root("replay_filter"),
            public_event_root: empty_root("public_events"),
            public_record_root: empty_root("public_record"),
            state_root: empty_root("state"),
        };
        roots.state_root = state_root_from_parts(config, counters, &roots);
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "segment_root": self.segment_root,
            "pruning_proof_root": self.pruning_proof_root,
            "storage_commitment_root": self.storage_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "rebate_coupon_root": self.rebate_coupon_root,
            "compaction_window_root": self.compaction_window_root,
            "eviction_guard_root": self.eviction_guard_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "replay_filter_root": self.replay_filter_root,
            "public_event_root": self.public_event_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateStateSegment {
    pub segment_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub kind: SegmentKind,
    pub status: SegmentStatus,
    pub epoch: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub last_write_height: u64,
    pub byte_len: u64,
    pub prunable_bytes: u64,
    pub privacy_set_size: u64,
    pub storage_root_before: String,
    pub storage_root_after: String,
    pub encrypted_payload_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub retention_tag: String,
    pub fee_lane_id: String,
    pub operator_id: String,
    pub metadata_commitment: String,
}

impl PrivateStateSegment {
    pub fn new(
        segment_id: impl Into<String>,
        contract_id: impl Into<String>,
        kind: SegmentKind,
        epoch: u64,
        byte_len: u64,
        prunable_bytes: u64,
        operator_id: impl Into<String>,
    ) -> Self {
        let segment_id = segment_id.into();
        let contract_id = contract_id.into();
        let operator_id = operator_id.into();
        let owner_commitment = commitment(
            "PRIVATE-STATE-SEGMENT-OWNER",
            &[&segment_id, &contract_id, &operator_id],
            epoch,
        );
        let storage_root_before = commitment(
            "PRIVATE-STATE-SEGMENT-STORAGE-BEFORE",
            &[&segment_id],
            byte_len,
        );
        let storage_root_after = commitment(
            "PRIVATE-STATE-SEGMENT-STORAGE-AFTER",
            &[&segment_id],
            prunable_bytes,
        );
        let encrypted_payload_root =
            commitment("PRIVATE-STATE-SEGMENT-PAYLOAD", &[&segment_id], byte_len);
        let nullifier_root = commitment("PRIVATE-STATE-SEGMENT-NULLIFIER", &[&segment_id], epoch);
        let witness_root = commitment(
            "PRIVATE-STATE-SEGMENT-WITNESS",
            &[&segment_id, kind.as_str()],
            epoch,
        );
        let retention_tag = commitment(
            "PRIVATE-STATE-SEGMENT-RETENTION",
            &[&segment_id],
            prunable_bytes,
        );
        let fee_lane_id = commitment(
            "PRIVATE-STATE-SEGMENT-FEE-LANE",
            &[&contract_id, &operator_id],
            epoch,
        );
        let metadata_commitment =
            commitment("PRIVATE-STATE-SEGMENT-METADATA", &[&segment_id], byte_len);
        Self {
            segment_id,
            contract_id,
            owner_commitment,
            kind,
            status: SegmentStatus::Active,
            epoch,
            opened_at_height: DEVNET_L2_HEIGHT,
            sealed_at_height: DEVNET_L2_HEIGHT,
            last_write_height: DEVNET_L2_HEIGHT,
            byte_len,
            prunable_bytes,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            storage_root_before,
            storage_root_after,
            encrypted_payload_root,
            nullifier_root,
            witness_root,
            retention_tag,
            fee_lane_id,
            operator_id,
            metadata_commitment,
        }
    }

    pub fn freeze(mut self, sealed_at_height: u64) -> Self {
        self.status = SegmentStatus::Frozen;
        self.sealed_at_height = sealed_at_height;
        self.last_write_height = sealed_at_height;
        self
    }

    pub fn mark_prunable(mut self) -> Self {
        self.status = SegmentStatus::Prunable;
        self
    }

    pub fn mark_pruned(mut self, pruned_at_height: u64) -> Self {
        self.status = SegmentStatus::Pruned;
        self.sealed_at_height = pruned_at_height;
        self
    }

    pub fn eligible_for_pruning(&self, config: &Config, height: u64) -> bool {
        self.status.can_prune()
            && self.prunable_bytes >= config.min_prunable_bytes
            && self.privacy_set_size >= config.min_privacy_set_size
            && height.saturating_sub(self.last_write_height) >= config.compaction_window_blocks
    }

    pub fn rebate_basis_units(&self, config: &Config) -> u64 {
        self.prunable_bytes
            .saturating_mul(config.rebate_share_bps)
            .saturating_div(MAX_BPS)
            .saturating_div(1024)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "segment_id": self.segment_id,
            "contract_id": self.contract_id,
            "owner_commitment": self.owner_commitment,
            "kind": self.kind.as_str(),
            "status": segment_status_str(self.status),
            "epoch": self.epoch,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "last_write_height": self.last_write_height,
            "byte_len": self.byte_len,
            "prunable_bytes": self.prunable_bytes,
            "privacy_set_size": self.privacy_set_size,
            "storage_root_before": self.storage_root_before,
            "storage_root_after": self.storage_root_after,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier_root": self.nullifier_root,
            "witness_root": self.witness_root,
            "retention_tag": self.retention_tag,
            "fee_lane_id": self.fee_lane_id,
            "operator_id": self.operator_id,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn root(&self) -> String {
        record_root("PRIVATE-STATE-SEGMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PruningProof {
    pub proof_id: String,
    pub segment_id: String,
    pub contract_id: String,
    pub proof_kind: PruningProofKind,
    pub status: ProofStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub pruned_bytes: u64,
    pub proof_weight: u64,
    pub privacy_set_size: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub tombstone_root: String,
    pub retained_range_root: String,
    pub proof_commitment: String,
    pub recursive_aggregate_root: String,
    pub fee_quote_commitment: String,
    pub operator_id: String,
    pub attestation_ids: Vec<String>,
}

impl PruningProof {
    pub fn for_segment(segment: &PrivateStateSegment, config: &Config, height: u64) -> Self {
        let proof_id = commitment(
            "PRIVATE-STATE-PRUNING-PROOF-ID",
            &[
                &segment.segment_id,
                &segment.contract_id,
                &segment.operator_id,
            ],
            height,
        );
        let tombstone_root = commitment(
            "PRIVATE-STATE-PRUNING-TOMBSTONE",
            &[&proof_id, &segment.segment_id],
            segment.prunable_bytes,
        );
        let retained_range_root = commitment(
            "PRIVATE-STATE-PRUNING-RETAINED-RANGE",
            &[&proof_id, &segment.retention_tag],
            segment.byte_len.saturating_sub(segment.prunable_bytes),
        );
        let proof_commitment = commitment(
            "PRIVATE-STATE-PRUNING-PROOF-COMMITMENT",
            &[&proof_id],
            segment.prunable_bytes,
        );
        let recursive_aggregate_root =
            commitment("PRIVATE-STATE-PRUNING-RECURSIVE", &[&proof_id], height);
        let fee_quote_commitment = commitment(
            "PRIVATE-STATE-PRUNING-FEE-QUOTE",
            &[&proof_id],
            config.max_user_fee_bps,
        );
        Self {
            proof_id,
            segment_id: segment.segment_id.clone(),
            contract_id: segment.contract_id.clone(),
            proof_kind: PruningProofKind::StateDiff,
            status: ProofStatus::Submitted,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(config.proof_ttl_blocks),
            pruned_bytes: segment.prunable_bytes,
            proof_weight: config.fast_path_proof_weight,
            privacy_set_size: segment.privacy_set_size,
            state_root_before: segment.storage_root_before.clone(),
            state_root_after: segment.storage_root_after.clone(),
            tombstone_root,
            retained_range_root,
            proof_commitment,
            recursive_aggregate_root,
            fee_quote_commitment,
            operator_id: segment.operator_id.clone(),
            attestation_ids: Vec::new(),
        }
    }

    pub fn attach_attestation(mut self, attestation_id: impl Into<String>) -> Self {
        self.attestation_ids.push(attestation_id.into());
        self.status = ProofStatus::Attested;
        self
    }

    pub fn accept(mut self) -> Self {
        self.status = ProofStatus::Accepted;
        self
    }

    pub fn reject(mut self) -> Self {
        self.status = ProofStatus::Rejected;
        self
    }

    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_at_height && !self.status.terminal()
    }

    pub fn fast_path_eligible(&self, config: &Config) -> bool {
        self.status.spendable()
            && self.proof_weight <= config.fast_path_proof_weight
            && self.privacy_set_size >= config.min_privacy_set_size
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "segment_id": self.segment_id,
            "contract_id": self.contract_id,
            "proof_kind": self.proof_kind.as_str(),
            "status": proof_status_str(self.status),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "pruned_bytes": self.pruned_bytes,
            "proof_weight": self.proof_weight,
            "privacy_set_size": self.privacy_set_size,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "tombstone_root": self.tombstone_root,
            "retained_range_root": self.retained_range_root,
            "proof_commitment": self.proof_commitment,
            "recursive_aggregate_root": self.recursive_aggregate_root,
            "fee_quote_commitment": self.fee_quote_commitment,
            "operator_id": self.operator_id,
            "attestation_ids": self.attestation_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractStorageCommitment {
    pub commitment_id: String,
    pub contract_id: String,
    pub segment_id: String,
    pub storage_epoch: u64,
    pub slot_root: String,
    pub value_commitment_root: String,
    pub nullifier_root: String,
    pub access_pattern_root: String,
    pub compacted_root: String,
    pub retained_root: String,
    pub byte_len: u64,
    pub retained_bytes: u64,
    pub low_fee_lane: bool,
}

impl ContractStorageCommitment {
    pub fn from_segment(segment: &PrivateStateSegment) -> Self {
        let commitment_id = commitment(
            "PRIVATE-CONTRACT-STORAGE-COMMITMENT-ID",
            &[&segment.contract_id, &segment.segment_id],
            segment.epoch,
        );
        let retained_bytes = segment.byte_len.saturating_sub(segment.prunable_bytes);
        Self {
            commitment_id,
            contract_id: segment.contract_id.clone(),
            segment_id: segment.segment_id.clone(),
            storage_epoch: segment.epoch,
            slot_root: segment.storage_root_before.clone(),
            value_commitment_root: segment.encrypted_payload_root.clone(),
            nullifier_root: segment.nullifier_root.clone(),
            access_pattern_root: commitment(
                "PRIVATE-CONTRACT-STORAGE-ACCESS",
                &[&segment.segment_id],
                retained_bytes,
            ),
            compacted_root: segment.storage_root_after.clone(),
            retained_root: commitment(
                "PRIVATE-CONTRACT-STORAGE-RETAINED",
                &[&segment.retention_tag],
                retained_bytes,
            ),
            byte_len: segment.byte_len,
            retained_bytes,
            low_fee_lane: true,
        }
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.byte_len == 0 {
            0
        } else {
            self.byte_len
                .saturating_sub(self.retained_bytes)
                .saturating_mul(MAX_BPS)
                .saturating_div(self.byte_len)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "contract_id": self.contract_id,
            "segment_id": self.segment_id,
            "storage_epoch": self.storage_epoch,
            "slot_root": self.slot_root,
            "value_commitment_root": self.value_commitment_root,
            "nullifier_root": self.nullifier_root,
            "access_pattern_root": self.access_pattern_root,
            "compacted_root": self.compacted_root,
            "retained_root": self.retained_root,
            "byte_len": self.byte_len,
            "retained_bytes": self.retained_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "low_fee_lane": self.low_fee_lane,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPruningAttestation {
    pub attestation_id: String,
    pub proof_id: String,
    pub segment_id: String,
    pub operator_id: String,
    pub signer_set_root: String,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub verdict: AttestationVerdict,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub message_root: String,
    pub signature_root: String,
    pub replay_key: String,
    pub public_inputs_root: String,
}

impl PqPruningAttestation {
    pub fn approve(proof: &PruningProof, config: &Config, height: u64) -> Self {
        let attestation_id = commitment(
            "PRIVATE-STATE-PQ-PRUNING-ATTESTATION-ID",
            &[&proof.proof_id, &proof.segment_id, &proof.operator_id],
            height,
        );
        Self {
            attestation_id: attestation_id.clone(),
            proof_id: proof.proof_id.clone(),
            segment_id: proof.segment_id.clone(),
            operator_id: proof.operator_id.clone(),
            signer_set_root: commitment(
                "PRIVATE-STATE-PQ-PRUNING-SIGNER-SET",
                &[&proof.operator_id],
                config.min_attestation_quorum_bps,
            ),
            pq_scheme: config.pq_attestation_suite.clone(),
            pq_security_bits: config.min_pq_security_bits,
            quorum_bps: config.min_attestation_quorum_bps,
            verdict: AttestationVerdict::Approved,
            attested_at_height: height,
            expires_at_height: height.saturating_add(config.proof_ttl_blocks),
            message_root: commitment(
                "PRIVATE-STATE-PQ-PRUNING-MESSAGE",
                &[&proof.proof_id],
                proof.pruned_bytes,
            ),
            signature_root: commitment(
                "PRIVATE-STATE-PQ-PRUNING-SIGNATURE",
                &[&attestation_id],
                u64::from(config.min_pq_security_bits),
            ),
            replay_key: replay_key("pq_attestation", &attestation_id),
            public_inputs_root: commitment(
                "PRIVATE-STATE-PQ-PRUNING-PUBLIC-INPUTS",
                &[&proof.state_root_before, &proof.state_root_after],
                proof.privacy_set_size,
            ),
        }
    }

    pub fn valid_for(&self, proof: &PruningProof, config: &Config, height: u64) -> bool {
        self.proof_id == proof.proof_id
            && self.verdict.positive()
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.quorum_bps >= config.min_attestation_quorum_bps
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "proof_id": self.proof_id,
            "segment_id": self.segment_id,
            "operator_id": self.operator_id,
            "signer_set_root": self.signer_set_root,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "verdict": attestation_verdict_str(self.verdict),
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "message_root": self.message_root,
            "signature_root": self.signature_root,
            "replay_key": self.replay_key,
            "public_inputs_root": self.public_inputs_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub proof_id: String,
    pub segment_id: String,
    pub contract_id: String,
    pub operator_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub status: CouponStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub pruned_bytes: u64,
    pub rebate_units: u64,
    pub operator_reward_units: u64,
    pub max_fee_bps: u64,
    pub spend_nullifier: String,
    pub coupon_commitment: String,
}

impl RebateCoupon {
    pub fn mint(
        proof: &PruningProof,
        segment: &PrivateStateSegment,
        config: &Config,
        height: u64,
    ) -> Self {
        let coupon_id = commitment(
            "PRIVATE-STATE-PRUNING-REBATE-COUPON-ID",
            &[&proof.proof_id, &segment.segment_id, &segment.contract_id],
            height,
        );
        let rebate_units = segment.rebate_basis_units(config);
        let operator_reward_units = rebate_units
            .saturating_mul(config.operator_reward_share_bps)
            .saturating_div(MAX_BPS);
        Self {
            coupon_id: coupon_id.clone(),
            proof_id: proof.proof_id.clone(),
            segment_id: segment.segment_id.clone(),
            contract_id: segment.contract_id.clone(),
            operator_id: proof.operator_id.clone(),
            beneficiary_commitment: segment.owner_commitment.clone(),
            fee_asset_id: config.fee_asset_id.clone(),
            status: CouponStatus::Minted,
            issued_at_height: height,
            expires_at_height: height.saturating_add(config.rebate_ttl_blocks),
            pruned_bytes: proof.pruned_bytes,
            rebate_units,
            operator_reward_units,
            max_fee_bps: config.max_user_fee_bps,
            spend_nullifier: replay_key("rebate_coupon", &coupon_id),
            coupon_commitment: commitment(
                "PRIVATE-STATE-PRUNING-REBATE-COUPON-COMMITMENT",
                &[&coupon_id],
                rebate_units,
            ),
        }
    }

    pub fn reserve(mut self) -> Self {
        if self.status.live() {
            self.status = CouponStatus::Reserved;
        }
        self
    }

    pub fn apply(mut self) -> Self {
        if self.status.live() {
            self.status = CouponStatus::Applied;
        }
        self
    }

    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_at_height && self.status.live()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "proof_id": self.proof_id,
            "segment_id": self.segment_id,
            "contract_id": self.contract_id,
            "operator_id": self.operator_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "status": coupon_status_str(self.status),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "pruned_bytes": self.pruned_bytes,
            "rebate_units": self.rebate_units,
            "operator_reward_units": self.operator_reward_units,
            "max_fee_bps": self.max_fee_bps,
            "spend_nullifier": self.spend_nullifier,
            "coupon_commitment": self.coupon_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompactionWindow {
    pub window_id: String,
    pub contract_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub status: WindowStatus,
    pub target_bytes: u64,
    pub committed_bytes: u64,
    pub pruned_bytes: u64,
    pub segment_ids: Vec<String>,
    pub low_fee_lane_root: String,
    pub settlement_root: String,
}

impl CompactionWindow {
    pub fn open(
        contract_id: impl Into<String>,
        operator_id: impl Into<String>,
        epoch: u64,
        start_height: u64,
        config: &Config,
    ) -> Self {
        let contract_id = contract_id.into();
        let operator_id = operator_id.into();
        let window_id = commitment(
            "PRIVATE-STATE-COMPACTION-WINDOW-ID",
            &[&contract_id, &operator_id],
            epoch,
        );
        Self {
            window_id: window_id.clone(),
            contract_id,
            operator_id,
            epoch,
            start_height,
            end_height: start_height.saturating_add(config.compaction_window_blocks),
            status: WindowStatus::Open,
            target_bytes: config.segment_size_bytes.saturating_mul(8),
            committed_bytes: 0,
            pruned_bytes: 0,
            segment_ids: Vec::new(),
            low_fee_lane_root: commitment("PRIVATE-STATE-COMPACTION-LOW-FEE", &[&window_id], epoch),
            settlement_root: commitment(
                "PRIVATE-STATE-COMPACTION-SETTLEMENT",
                &[&window_id],
                start_height,
            ),
        }
    }

    pub fn attach_segment(mut self, segment: &PrivateStateSegment) -> Self {
        if self.status.accepts_segments() && !self.segment_ids.contains(&segment.segment_id) {
            self.committed_bytes = self.committed_bytes.saturating_add(segment.byte_len);
            self.pruned_bytes = self.pruned_bytes.saturating_add(segment.prunable_bytes);
            self.segment_ids.push(segment.segment_id.clone());
        }
        self
    }

    pub fn seal(mut self) -> Self {
        self.status = WindowStatus::Sealed;
        self
    }

    pub fn drift_bps(&self) -> u64 {
        if self.target_bytes == 0 {
            0
        } else if self.committed_bytes > self.target_bytes {
            self.committed_bytes
                .saturating_sub(self.target_bytes)
                .saturating_mul(MAX_BPS)
                .saturating_div(self.target_bytes)
        } else {
            self.target_bytes
                .saturating_sub(self.committed_bytes)
                .saturating_mul(MAX_BPS)
                .saturating_div(self.target_bytes)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "contract_id": self.contract_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "status": window_status_str(self.status),
            "target_bytes": self.target_bytes,
            "committed_bytes": self.committed_bytes,
            "pruned_bytes": self.pruned_bytes,
            "drift_bps": self.drift_bps(),
            "segment_ids": self.segment_ids,
            "low_fee_lane_root": self.low_fee_lane_root,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvictionGuard {
    pub guard_id: String,
    pub segment_id: String,
    pub contract_id: String,
    pub reason: GuardReason,
    pub status: GuardStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub required_root: String,
    pub override_commitment: String,
    pub dispute_window_blocks: u64,
}

impl EvictionGuard {
    pub fn active(
        segment: &PrivateStateSegment,
        reason: GuardReason,
        config: &Config,
        height: u64,
    ) -> Self {
        let guard_id = commitment(
            "PRIVATE-STATE-EVICTION-GUARD-ID",
            &[&segment.segment_id, &segment.contract_id],
            height,
        );
        Self {
            guard_id: guard_id.clone(),
            segment_id: segment.segment_id.clone(),
            contract_id: segment.contract_id.clone(),
            reason,
            status: GuardStatus::Active,
            created_at_height: height,
            expires_at_height: height.saturating_add(config.eviction_guard_ttl_blocks),
            required_root: commitment(
                "PRIVATE-STATE-EVICTION-GUARD-REQUIRED",
                &[&segment.storage_root_after],
                segment.prunable_bytes,
            ),
            override_commitment: commitment(
                "PRIVATE-STATE-EVICTION-GUARD-OVERRIDE",
                &[&guard_id],
                height,
            ),
            dispute_window_blocks: config.compaction_window_blocks,
        }
    }

    pub fn blocks(&self, segment_id: &str, height: u64) -> bool {
        self.segment_id == segment_id && self.status.blocking() && height <= self.expires_at_height
    }

    pub fn satisfy(mut self) -> Self {
        self.status = GuardStatus::Satisfied;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "segment_id": self.segment_id,
            "contract_id": self.contract_id,
            "reason": guard_reason_str(self.reason),
            "status": guard_status_str(self.status),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "required_root": self.required_root,
            "override_commitment": self.override_commitment,
            "dispute_window_blocks": self.dispute_window_blocks,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub contract_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub status: BudgetStatus,
    pub allowance: u64,
    pub consumed: u64,
    pub min_privacy_set_size: u64,
    pub disclosure_root: String,
    pub audit_trail_root: String,
}

impl RedactionBudget {
    pub fn open(
        contract_id: impl Into<String>,
        operator_id: impl Into<String>,
        epoch: u64,
        config: &Config,
    ) -> Self {
        let contract_id = contract_id.into();
        let operator_id = operator_id.into();
        let budget_id = commitment(
            "PRIVATE-STATE-REDACTION-BUDGET-ID",
            &[&contract_id, &operator_id],
            epoch,
        );
        Self {
            budget_id: budget_id.clone(),
            contract_id,
            operator_id,
            epoch,
            status: BudgetStatus::Open,
            allowance: config.redaction_budget_per_epoch,
            consumed: 0,
            min_privacy_set_size: config.min_privacy_set_size,
            disclosure_root: commitment(
                "PRIVATE-STATE-REDACTION-DISCLOSURE",
                &[&budget_id],
                config.redaction_budget_per_epoch,
            ),
            audit_trail_root: commitment("PRIVATE-STATE-REDACTION-AUDIT", &[&budget_id], epoch),
        }
    }

    pub fn remaining(&self) -> u64 {
        self.allowance.saturating_sub(self.consumed)
    }

    pub fn consume(mut self, units: u64) -> Result<Self> {
        if !self.status.usable() {
            return Err("redaction budget is not open".to_string());
        }
        if units > self.remaining() {
            return Err("redaction budget exhausted".to_string());
        }
        self.consumed = self.consumed.saturating_add(units);
        if self.consumed >= self.allowance {
            self.status = BudgetStatus::Exhausted;
        }
        Ok(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "contract_id": self.contract_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "status": budget_status_str(self.status),
            "allowance": self.allowance,
            "consumed": self.consumed,
            "remaining": self.remaining(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "disclosure_root": self.disclosure_root,
            "audit_trail_root": self.audit_trail_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub health: OperatorHealth,
    pub epoch: u64,
    pub assigned_segments: u64,
    pub accepted_proofs: u64,
    pub rejected_proofs: u64,
    pub pruned_bytes: u64,
    pub rebate_units_earned: u64,
    pub avg_proof_weight: u64,
    pub pq_quorum_bps: u64,
    pub privacy_floor: u64,
    pub summary_root: String,
    pub low_fee_score: u64,
}

impl OperatorSummary {
    pub fn new(operator_id: impl Into<String>, epoch: u64, config: &Config) -> Self {
        let operator_id = operator_id.into();
        Self {
            operator_id: operator_id.clone(),
            health: OperatorHealth::Nominal,
            epoch,
            assigned_segments: 0,
            accepted_proofs: 0,
            rejected_proofs: 0,
            pruned_bytes: 0,
            rebate_units_earned: 0,
            avg_proof_weight: config.fast_path_proof_weight,
            pq_quorum_bps: config.min_attestation_quorum_bps,
            privacy_floor: config.min_privacy_set_size,
            summary_root: commitment("PRIVATE-STATE-OPERATOR-SUMMARY", &[&operator_id], epoch),
            low_fee_score: MAX_BPS,
        }
    }

    pub fn record_segment(mut self, segment: &PrivateStateSegment) -> Self {
        self.assigned_segments = self.assigned_segments.saturating_add(1);
        self.pruned_bytes = self.pruned_bytes.saturating_add(segment.prunable_bytes);
        self
    }

    pub fn record_coupon(mut self, coupon: &RebateCoupon) -> Self {
        self.rebate_units_earned = self
            .rebate_units_earned
            .saturating_add(coupon.operator_reward_units);
        self
    }

    pub fn record_proof(mut self, proof: &PruningProof) -> Self {
        if proof.status == ProofStatus::Accepted {
            self.accepted_proofs = self.accepted_proofs.saturating_add(1);
        } else if proof.status == ProofStatus::Rejected {
            self.rejected_proofs = self.rejected_proofs.saturating_add(1);
        }
        let total = self
            .accepted_proofs
            .saturating_add(self.rejected_proofs)
            .max(1);
        self.avg_proof_weight = self
            .avg_proof_weight
            .saturating_mul(total.saturating_sub(1))
            .saturating_add(proof.proof_weight)
            .saturating_div(total);
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "health": operator_health_str(self.health),
            "epoch": self.epoch,
            "assigned_segments": self.assigned_segments,
            "accepted_proofs": self.accepted_proofs,
            "rejected_proofs": self.rejected_proofs,
            "pruned_bytes": self.pruned_bytes,
            "rebate_units_earned": self.rebate_units_earned,
            "avg_proof_weight": self.avg_proof_weight,
            "pq_quorum_bps": self.pq_quorum_bps,
            "privacy_floor": self.privacy_floor,
            "summary_root": self.summary_root,
            "low_fee_score": self.low_fee_score,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub record_root: String,
}

impl PublicEvent {
    pub fn new(
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        height: u64,
        record: &Value,
    ) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let record_root = record_root("PRIVATE-STATE-PRUNING-EVENT-RECORD", record);
        let event_id = commitment(
            "PRIVATE-STATE-PRUNING-EVENT-ID",
            &[&kind, &subject_id, &record_root],
            height,
        );
        Self {
            event_id,
            height,
            kind,
            subject_id,
            record_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_height: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub private_state_segments: BTreeMap<String, PrivateStateSegment>,
    pub pruning_proofs: BTreeMap<String, PruningProof>,
    pub storage_commitments: BTreeMap<String, ContractStorageCommitment>,
    pub pq_attestations: BTreeMap<String, PqPruningAttestation>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub compaction_windows: BTreeMap<String, CompactionWindow>,
    pub eviction_guards: BTreeMap<String, EvictionGuard>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub replay_filter: BTreeSet<String>,
    pub public_events: Vec<PublicEvent>,
}

impl State {
    pub fn new(config: Config, l2_height: u64) -> Result<Self> {
        config.validate()?;
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Ok(Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: config.chain_id.clone(),
            l2_height,
            config,
            counters,
            roots,
            private_state_segments: BTreeMap::new(),
            pruning_proofs: BTreeMap::new(),
            storage_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            compaction_windows: BTreeMap::new(),
            eviction_guards: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            replay_filter: BTreeSet::new(),
            public_events: Vec::new(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq(
            "state protocol_version",
            &self.protocol_version,
            PROTOCOL_VERSION,
        )?;
        ensure_eq(
            "config protocol_version",
            &self.config.protocol_version,
            PROTOCOL_VERSION,
        )?;
        ensure_eq("chain_id", &self.chain_id, &self.config.chain_id)?;
        ensure_len(
            "private_state_segments",
            self.private_state_segments.len(),
            self.config.max_segments,
        )?;
        ensure_len(
            "pruning_proofs",
            self.pruning_proofs.len(),
            self.config.max_pruning_proofs,
        )?;
        ensure_len(
            "storage_commitments",
            self.storage_commitments.len(),
            self.config.max_storage_commitments,
        )?;
        ensure_len(
            "pq_attestations",
            self.pq_attestations.len(),
            self.config.max_pq_attestations,
        )?;
        ensure_len(
            "rebate_coupons",
            self.rebate_coupons.len(),
            self.config.max_rebate_coupons,
        )?;
        ensure_len(
            "compaction_windows",
            self.compaction_windows.len(),
            self.config.max_compaction_windows,
        )?;
        ensure_len(
            "eviction_guards",
            self.eviction_guards.len(),
            self.config.max_eviction_guards,
        )?;
        ensure_len(
            "redaction_budgets",
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        ensure_len(
            "operator_summaries",
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
        )?;
        ensure_len(
            "public_events",
            self.public_events.len(),
            self.config.max_public_events,
        )?;
        Ok(())
    }

    pub fn insert_segment(&mut self, segment: PrivateStateSegment) -> Result<()> {
        ensure_len(
            "private_state_segments",
            self.private_state_segments.len().saturating_add(1),
            self.config.max_segments,
        )?;
        self.counters.segment_count = self.counters.segment_count.saturating_add(1);
        if segment.status.live() {
            self.counters.live_segment_count = self.counters.live_segment_count.saturating_add(1);
        }
        if segment.status == SegmentStatus::Pruned {
            self.counters.pruned_segment_count =
                self.counters.pruned_segment_count.saturating_add(1);
        }
        self.counters.prunable_bytes = self
            .counters
            .prunable_bytes
            .saturating_add(segment.prunable_bytes);
        self.private_state_segments
            .insert(segment.segment_id.clone(), segment.clone());
        self.push_event(
            "segment_recorded",
            &segment.segment_id,
            &segment.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_storage_commitment(&mut self, storage: ContractStorageCommitment) -> Result<()> {
        ensure_len(
            "storage_commitments",
            self.storage_commitments.len().saturating_add(1),
            self.config.max_storage_commitments,
        )?;
        self.counters.storage_commitment_count =
            self.counters.storage_commitment_count.saturating_add(1);
        self.storage_commitments
            .insert(storage.commitment_id.clone(), storage.clone());
        self.push_event(
            "storage_commitment_recorded",
            &storage.commitment_id,
            &storage.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_compaction_window(&mut self, window: CompactionWindow) -> Result<()> {
        ensure_len(
            "compaction_windows",
            self.compaction_windows.len().saturating_add(1),
            self.config.max_compaction_windows,
        )?;
        if window.drift_bps() > self.config.max_compaction_drift_bps
            && window.status == WindowStatus::Sealed
        {
            return Err("sealed compaction window drift exceeds configured maximum".to_string());
        }
        self.counters.compaction_window_count =
            self.counters.compaction_window_count.saturating_add(1);
        self.compaction_windows
            .insert(window.window_id.clone(), window.clone());
        self.push_event(
            "compaction_window_recorded",
            &window.window_id,
            &window.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_eviction_guard(&mut self, guard: EvictionGuard) -> Result<()> {
        ensure_len(
            "eviction_guards",
            self.eviction_guards.len().saturating_add(1),
            self.config.max_eviction_guards,
        )?;
        if guard.status.blocking() {
            self.counters.active_guard_count = self.counters.active_guard_count.saturating_add(1);
        }
        self.counters.eviction_guard_count = self.counters.eviction_guard_count.saturating_add(1);
        self.eviction_guards
            .insert(guard.guard_id.clone(), guard.clone());
        self.push_event(
            "eviction_guard_recorded",
            &guard.guard_id,
            &guard.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure_len(
            "redaction_budgets",
            self.redaction_budgets.len().saturating_add(1),
            self.config.max_redaction_budgets,
        )?;
        self.counters.redaction_budget_count =
            self.counters.redaction_budget_count.saturating_add(1);
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget.clone());
        self.push_event(
            "redaction_budget_recorded",
            &budget.budget_id,
            &budget.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn submit_pruning_proof(&mut self, proof: PruningProof) -> Result<()> {
        ensure_len(
            "pruning_proofs",
            self.pruning_proofs.len().saturating_add(1),
            self.config.max_pruning_proofs,
        )?;
        if self
            .eviction_guards
            .values()
            .any(|guard| guard.blocks(&proof.segment_id, self.l2_height))
        {
            return Err("segment is protected by an active eviction guard".to_string());
        }
        if proof.privacy_set_size < self.config.min_privacy_set_size {
            return Err("proof privacy set below configured floor".to_string());
        }
        self.counters.pruning_proof_count = self.counters.pruning_proof_count.saturating_add(1);
        if proof.fast_path_eligible(&self.config) {
            self.counters.fast_path_proofs = self.counters.fast_path_proofs.saturating_add(1);
        }
        self.pruning_proofs
            .insert(proof.proof_id.clone(), proof.clone());
        self.push_event(
            "pruning_proof_submitted",
            &proof.proof_id,
            &proof.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn attest_proof(&mut self, attestation: PqPruningAttestation) -> Result<()> {
        ensure_len(
            "pq_attestations",
            self.pq_attestations.len().saturating_add(1),
            self.config.max_pq_attestations,
        )?;
        if self.replay_filter.contains(&attestation.replay_key) {
            return Err("pq attestation replay detected".to_string());
        }
        let proof = self
            .pruning_proofs
            .get(&attestation.proof_id)
            .ok_or_else(|| "attestation references unknown proof".to_string())?
            .clone();
        if !attestation.valid_for(&proof, &self.config, self.l2_height) {
            return Err("pq attestation does not satisfy proof policy".to_string());
        }
        let mut attested = proof.attach_attestation(attestation.attestation_id.clone());
        attested.status = ProofStatus::Attested;
        self.pruning_proofs
            .insert(attested.proof_id.clone(), attested);
        self.replay_filter.insert(attestation.replay_key.clone());
        self.counters.pq_attestation_count = self.counters.pq_attestation_count.saturating_add(1);
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.push_event(
            "pq_pruning_attestation_recorded",
            &attestation.attestation_id,
            &attestation.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn accept_pruning_proof(&mut self, proof_id: &str) -> Result<()> {
        let proof = self
            .pruning_proofs
            .get(proof_id)
            .ok_or_else(|| "unknown pruning proof".to_string())?
            .clone();
        if !proof.status.spendable() {
            return Err("proof is not attested".to_string());
        }
        let accepted = proof.accept();
        self.counters.accepted_proof_count = self.counters.accepted_proof_count.saturating_add(1);
        self.counters.pruned_bytes = self
            .counters
            .pruned_bytes
            .saturating_add(accepted.pruned_bytes);
        self.pruning_proofs
            .insert(proof_id.to_string(), accepted.clone());
        if let Some(segment) = self
            .private_state_segments
            .get(&accepted.segment_id)
            .cloned()
        {
            self.private_state_segments.insert(
                segment.segment_id.clone(),
                segment.mark_pruned(self.l2_height),
            );
        }
        self.push_event(
            "pruning_proof_accepted",
            proof_id,
            &accepted.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn reject_pruning_proof(&mut self, proof_id: &str) -> Result<()> {
        let proof = self
            .pruning_proofs
            .get(proof_id)
            .ok_or_else(|| "unknown pruning proof".to_string())?
            .clone()
            .reject();
        self.counters.rejected_proof_count = self.counters.rejected_proof_count.saturating_add(1);
        self.pruning_proofs
            .insert(proof_id.to_string(), proof.clone());
        self.push_event("pruning_proof_rejected", proof_id, &proof.public_record());
        self.recompute_roots();
        Ok(())
    }

    pub fn mint_rebate_coupon(&mut self, proof_id: &str) -> Result<RebateCoupon> {
        let proof = self
            .pruning_proofs
            .get(proof_id)
            .ok_or_else(|| "unknown pruning proof".to_string())?
            .clone();
        if proof.status != ProofStatus::Accepted {
            return Err("rebate coupon requires accepted proof".to_string());
        }
        let segment = self
            .private_state_segments
            .get(&proof.segment_id)
            .ok_or_else(|| "proof segment is missing".to_string())?
            .clone();
        let coupon = RebateCoupon::mint(&proof, &segment, &self.config, self.l2_height);
        ensure_len(
            "rebate_coupons",
            self.rebate_coupons.len().saturating_add(1),
            self.config.max_rebate_coupons,
        )?;
        self.counters.rebate_coupon_count = self.counters.rebate_coupon_count.saturating_add(1);
        self.counters.rebate_units_minted = self
            .counters
            .rebate_units_minted
            .saturating_add(coupon.rebate_units);
        self.rebate_coupons
            .insert(coupon.coupon_id.clone(), coupon.clone());
        self.push_event(
            "rebate_coupon_minted",
            &coupon.coupon_id,
            &coupon.public_record(),
        );
        self.recompute_roots();
        Ok(coupon)
    }

    pub fn apply_rebate_coupon(&mut self, coupon_id: &str) -> Result<()> {
        let coupon = self
            .rebate_coupons
            .get(coupon_id)
            .ok_or_else(|| "unknown rebate coupon".to_string())?
            .clone();
        if !coupon.status.live() {
            return Err("rebate coupon is not spendable".to_string());
        }
        if coupon.expired(self.l2_height) {
            return Err("rebate coupon has expired".to_string());
        }
        let applied = coupon.apply();
        self.counters.applied_coupon_count = self.counters.applied_coupon_count.saturating_add(1);
        self.counters.rebate_units_applied = self
            .counters
            .rebate_units_applied
            .saturating_add(applied.rebate_units);
        self.replay_filter.insert(applied.spend_nullifier.clone());
        self.rebate_coupons
            .insert(coupon_id.to_string(), applied.clone());
        self.push_event("rebate_coupon_applied", coupon_id, &applied.public_record());
        self.recompute_roots();
        Ok(())
    }

    pub fn upsert_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        ensure_len(
            "operator_summaries",
            self.operator_summaries.len().saturating_add(1),
            self.config.max_operator_summaries,
        )?;
        self.counters.operator_summary_count =
            self.operator_summaries.len().saturating_add(1) as u64;
        self.operator_summaries
            .insert(summary.operator_id.clone(), summary.clone());
        self.push_event(
            "operator_summary_recorded",
            &summary.operator_id,
            &summary.public_record(),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn advance_height(&mut self, new_height: u64) {
        self.l2_height = self.l2_height.max(new_height);
        self.recompute_roots();
    }

    pub fn recompute_roots(&mut self) {
        self.counters.live_segment_count = self
            .private_state_segments
            .values()
            .filter(|segment| segment.status.live())
            .count() as u64;
        self.counters.pruned_segment_count = self
            .private_state_segments
            .values()
            .filter(|segment| segment.status == SegmentStatus::Pruned)
            .count() as u64;
        self.counters.active_guard_count = self
            .eviction_guards
            .values()
            .filter(|guard| guard.status.blocking())
            .count() as u64;
        self.roots = Roots {
            config_root: record_root(
                "PRIVATE-STATE-PRUNING-REBATE-CONFIG",
                &self.config.public_record(),
            ),
            segment_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-SEGMENTS",
                &sorted_records(
                    self.private_state_segments
                        .values()
                        .map(PrivateStateSegment::public_record),
                ),
            ),
            pruning_proof_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-PROOFS",
                &sorted_records(
                    self.pruning_proofs
                        .values()
                        .map(PruningProof::public_record),
                ),
            ),
            storage_commitment_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-STORAGE",
                &sorted_records(
                    self.storage_commitments
                        .values()
                        .map(ContractStorageCommitment::public_record),
                ),
            ),
            pq_attestation_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-PQ-ATTESTATIONS",
                &sorted_records(
                    self.pq_attestations
                        .values()
                        .map(PqPruningAttestation::public_record),
                ),
            ),
            rebate_coupon_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-COUPONS",
                &sorted_records(
                    self.rebate_coupons
                        .values()
                        .map(RebateCoupon::public_record),
                ),
            ),
            compaction_window_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-COMPACTION-WINDOWS",
                &sorted_records(
                    self.compaction_windows
                        .values()
                        .map(CompactionWindow::public_record),
                ),
            ),
            eviction_guard_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-EVICTION-GUARDS",
                &sorted_records(
                    self.eviction_guards
                        .values()
                        .map(EvictionGuard::public_record),
                ),
            ),
            redaction_budget_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-REDACTION-BUDGETS",
                &sorted_records(
                    self.redaction_budgets
                        .values()
                        .map(RedactionBudget::public_record),
                ),
            ),
            operator_summary_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-OPERATOR-SUMMARIES",
                &sorted_records(
                    self.operator_summaries
                        .values()
                        .map(OperatorSummary::public_record),
                ),
            ),
            replay_filter_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-REPLAY-FILTER",
                &self
                    .replay_filter
                    .iter()
                    .map(|key| json!(key))
                    .collect::<Vec<_>>(),
            ),
            public_event_root: merkle_root(
                "PRIVATE-STATE-PRUNING-REBATE-PUBLIC-EVENTS",
                &sorted_records(self.public_events.iter().map(PublicEvent::public_record)),
            ),
            public_record_root: empty_root("pending-public-record"),
            state_root: empty_root("pending-state"),
        };
        let record = public_record(self);
        self.roots.public_record_root = record_root(PUBLIC_RECORD_SUITE, &record);
        self.roots.state_root = state_root_from_parts(&self.config, &self.counters, &self.roots);
    }

    fn push_event(&mut self, kind: &str, subject_id: &str, record: &Value) {
        if self.public_events.len() >= self.config.max_public_events {
            trim_vec(
                &mut self.public_events,
                self.config.max_public_events.saturating_sub(1),
            );
        }
        self.counters.public_event_count = self.counters.public_event_count.saturating_add(1);
        self.public_events
            .push(PublicEvent::new(kind, subject_id, self.l2_height, record));
    }
}

pub fn devnet() -> State {
    demo()
}

pub fn demo() -> State {
    let config = Config::devnet();
    let mut state = State::new(config.clone(), DEVNET_L2_HEIGHT)
        .expect("devnet private state pruning rebate config is valid");
    let contract_alpha = "confidential-contract-devnet-amm";
    let contract_beta = "confidential-contract-devnet-vault";
    let operator_fast = "pq-pruning-operator-fast-path";
    let operator_archive = "pq-pruning-operator-archive";
    let segment_a = PrivateStateSegment::new(
        "segment-amm-epoch-2840-a",
        contract_alpha,
        SegmentKind::ContractStorage,
        2_840,
        1_048_576,
        786_432,
        operator_fast,
    )
    .freeze(DEVNET_L2_HEIGHT.saturating_sub(240))
    .mark_prunable();
    let segment_b = PrivateStateSegment::new(
        "segment-amm-nullifiers-epoch-2840-b",
        contract_alpha,
        SegmentKind::NullifierCache,
        2_840,
        524_288,
        327_680,
        operator_fast,
    )
    .freeze(DEVNET_L2_HEIGHT.saturating_sub(260))
    .mark_prunable();
    let segment_c = PrivateStateSegment::new(
        "segment-vault-witness-epoch-2840-c",
        contract_beta,
        SegmentKind::WitnessCache,
        2_840,
        786_432,
        458_752,
        operator_archive,
    )
    .freeze(DEVNET_L2_HEIGHT.saturating_sub(220))
    .mark_prunable();
    let storage_a = ContractStorageCommitment::from_segment(&segment_a);
    let storage_b = ContractStorageCommitment::from_segment(&segment_b);
    let storage_c = ContractStorageCommitment::from_segment(&segment_c);
    state
        .insert_segment(segment_a.clone())
        .expect("insert segment a");
    state
        .insert_segment(segment_b.clone())
        .expect("insert segment b");
    state
        .insert_segment(segment_c.clone())
        .expect("insert segment c");
    state
        .insert_storage_commitment(storage_a)
        .expect("insert storage a");
    state
        .insert_storage_commitment(storage_b)
        .expect("insert storage b");
    state
        .insert_storage_commitment(storage_c)
        .expect("insert storage c");
    let window = CompactionWindow::open(
        contract_alpha,
        operator_fast,
        2_840,
        DEVNET_L2_HEIGHT,
        &config,
    )
    .attach_segment(&segment_a)
    .attach_segment(&segment_b);
    state
        .insert_compaction_window(window)
        .expect("insert compaction window");
    let guard = EvictionGuard::active(
        &segment_c,
        GuardReason::AuditHold,
        &config,
        DEVNET_L2_HEIGHT,
    )
    .satisfy();
    state.insert_eviction_guard(guard).expect("insert guard");
    let budget_a = RedactionBudget::open(contract_alpha, operator_fast, 2_840, &config)
        .consume(3)
        .expect("consume demo redaction budget");
    state
        .insert_redaction_budget(budget_a)
        .expect("insert redaction budget");
    let proof_a = PruningProof::for_segment(&segment_a, &config, DEVNET_L2_HEIGHT);
    state
        .submit_pruning_proof(proof_a.clone())
        .expect("submit proof a");
    let attestation_a = PqPruningAttestation::approve(&proof_a, &config, DEVNET_L2_HEIGHT);
    state.attest_proof(attestation_a).expect("attest proof a");
    state
        .accept_pruning_proof(&proof_a.proof_id)
        .expect("accept proof a");
    let coupon = state
        .mint_rebate_coupon(&proof_a.proof_id)
        .expect("mint rebate coupon");
    state
        .apply_rebate_coupon(&coupon.coupon_id)
        .expect("apply rebate coupon");
    let proof_b =
        PruningProof::for_segment(&segment_b, &config, DEVNET_L2_HEIGHT.saturating_add(1));
    state
        .submit_pruning_proof(proof_b.clone())
        .expect("submit proof b");
    let attestation_b =
        PqPruningAttestation::approve(&proof_b, &config, DEVNET_L2_HEIGHT.saturating_add(1));
    state.attest_proof(attestation_b).expect("attest proof b");
    state
        .accept_pruning_proof(&proof_b.proof_id)
        .expect("accept proof b");
    let summary_fast = OperatorSummary::new(operator_fast, 2_840, &config)
        .record_segment(&segment_a)
        .record_segment(&segment_b)
        .record_proof(
            state
                .pruning_proofs
                .get(&proof_a.proof_id)
                .expect("accepted proof a"),
        )
        .record_proof(
            state
                .pruning_proofs
                .get(&proof_b.proof_id)
                .expect("accepted proof b"),
        )
        .record_coupon(
            state
                .rebate_coupons
                .get(&coupon.coupon_id)
                .expect("applied coupon"),
        );
    let summary_archive =
        OperatorSummary::new(operator_archive, 2_840, &config).record_segment(&segment_c);
    state
        .upsert_operator_summary(summary_fast)
        .expect("insert operator summary fast");
    state
        .upsert_operator_summary(summary_archive)
        .expect("insert operator summary archive");
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "chain_id": state.chain_id,
        "l2_height": state.l2_height,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": {
            "config_root": state.roots.config_root,
            "segment_root": state.roots.segment_root,
            "pruning_proof_root": state.roots.pruning_proof_root,
            "storage_commitment_root": state.roots.storage_commitment_root,
            "pq_attestation_root": state.roots.pq_attestation_root,
            "rebate_coupon_root": state.roots.rebate_coupon_root,
            "compaction_window_root": state.roots.compaction_window_root,
            "eviction_guard_root": state.roots.eviction_guard_root,
            "redaction_budget_root": state.roots.redaction_budget_root,
            "operator_summary_root": state.roots.operator_summary_root,
            "replay_filter_root": state.roots.replay_filter_root,
            "public_event_root": state.roots.public_event_root,
        },
        "samples": {
            "segments": state.private_state_segments.values().take(8).map(PrivateStateSegment::public_record).collect::<Vec<_>>(),
            "pruning_proofs": state.pruning_proofs.values().take(8).map(PruningProof::public_record).collect::<Vec<_>>(),
            "storage_commitments": state.storage_commitments.values().take(8).map(ContractStorageCommitment::public_record).collect::<Vec<_>>(),
            "pq_attestations": state.pq_attestations.values().take(8).map(PqPruningAttestation::public_record).collect::<Vec<_>>(),
            "rebate_coupons": state.rebate_coupons.values().take(8).map(RebateCoupon::public_record).collect::<Vec<_>>(),
            "compaction_windows": state.compaction_windows.values().take(8).map(CompactionWindow::public_record).collect::<Vec<_>>(),
            "eviction_guards": state.eviction_guards.values().take(8).map(EvictionGuard::public_record).collect::<Vec<_>>(),
            "redaction_budgets": state.redaction_budgets.values().take(8).map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": state.operator_summaries.values().take(8).map(OperatorSummary::public_record).collect::<Vec<_>>(),
            "public_events": state.public_events.iter().rev().take(16).map(PublicEvent::public_record).collect::<Vec<_>>(),
        },
    })
}

pub fn state_root(state: &State) -> String {
    let record = public_record(state);
    record_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-PRUNING-REBATE-STATE",
        &record,
    )
}

fn state_root_from_parts(config: &Config, counters: &Counters, roots: &Roots) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-PRUNING-REBATE-STATE-PARTS",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&config.public_record()),
            HashPart::Json(&counters.public_record()),
            HashPart::Str(&roots.config_root),
            HashPart::Str(&roots.segment_root),
            HashPart::Str(&roots.pruning_proof_root),
            HashPart::Str(&roots.storage_commitment_root),
            HashPart::Str(&roots.pq_attestation_root),
            HashPart::Str(&roots.rebate_coupon_root),
            HashPart::Str(&roots.compaction_window_root),
            HashPart::Str(&roots.eviction_guard_root),
            HashPart::Str(&roots.redaction_budget_root),
            HashPart::Str(&roots.operator_summary_root),
            HashPart::Str(&roots.replay_filter_root),
            HashPart::Str(&roots.public_event_root),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-PRUNING-REBATE-EMPTY",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn commitment(domain: &str, labels: &[&str], amount: u64) -> String {
    let label_record: Vec<Value> = labels.iter().map(|label| json!(label)).collect();
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&json!(label_record)),
            HashPart::U64(amount),
        ],
        32,
    )
}

fn replay_key(kind: &str, id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-PRUNING-REBATE-REPLAY",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(id),
        ],
        32,
    )
}

fn sorted_records<I>(records: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    let mut records: Vec<Value> = records.into_iter().collect();
    records.sort_by_key(canonical_json);
    records
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn trim_vec<T>(values: &mut Vec<T>, max_len: usize) {
    if values.len() > max_len {
        let drain_len = values.len() - max_len;
        values.drain(0..drain_len);
    }
}

fn segment_status_str(status: SegmentStatus) -> &'static str {
    match status {
        SegmentStatus::Active => "active",
        SegmentStatus::Frozen => "frozen",
        SegmentStatus::Proving => "proving",
        SegmentStatus::Prunable => "prunable",
        SegmentStatus::Pruned => "pruned",
        SegmentStatus::Quarantined => "quarantined",
        SegmentStatus::Retained => "retained",
    }
}

fn proof_status_str(status: ProofStatus) -> &'static str {
    match status {
        ProofStatus::Draft => "draft",
        ProofStatus::Submitted => "submitted",
        ProofStatus::Attested => "attested",
        ProofStatus::Accepted => "accepted",
        ProofStatus::Rejected => "rejected",
        ProofStatus::Expired => "expired",
        ProofStatus::Slashed => "slashed",
    }
}

fn attestation_verdict_str(verdict: AttestationVerdict) -> &'static str {
    match verdict {
        AttestationVerdict::Approved => "approved",
        AttestationVerdict::NeedsDelay => "needs_delay",
        AttestationVerdict::PrivacyInsufficient => "privacy_insufficient",
        AttestationVerdict::FeeTooHigh => "fee_too_high",
        AttestationVerdict::InvalidPqSignature => "invalid_pq_signature",
        AttestationVerdict::ReplayDetected => "replay_detected",
        AttestationVerdict::GuardViolated => "guard_violated",
        AttestationVerdict::Rejected => "rejected",
    }
}

fn coupon_status_str(status: CouponStatus) -> &'static str {
    match status {
        CouponStatus::Minted => "minted",
        CouponStatus::Reserved => "reserved",
        CouponStatus::Applied => "applied",
        CouponStatus::Expired => "expired",
        CouponStatus::Revoked => "revoked",
        CouponStatus::Slashed => "slashed",
    }
}

fn window_status_str(status: WindowStatus) -> &'static str {
    match status {
        WindowStatus::Scheduled => "scheduled",
        WindowStatus::Open => "open",
        WindowStatus::Sealing => "sealing",
        WindowStatus::Sealed => "sealed",
        WindowStatus::Cancelled => "cancelled",
    }
}

fn guard_reason_str(reason: GuardReason) -> &'static str {
    match reason {
        GuardReason::RecentWrite => "recent_write",
        GuardReason::LiveNullifier => "live_nullifier",
        GuardReason::PendingWithdrawal => "pending_withdrawal",
        GuardReason::AuditHold => "audit_hold",
        GuardReason::ContractUpgrade => "contract_upgrade",
        GuardReason::PrivacyFloor => "privacy_floor",
        GuardReason::OperatorDispute => "operator_dispute",
    }
}

fn guard_status_str(status: GuardStatus) -> &'static str {
    match status {
        GuardStatus::Active => "active",
        GuardStatus::Satisfied => "satisfied",
        GuardStatus::Overridden => "overridden",
        GuardStatus::Expired => "expired",
        GuardStatus::Slashed => "slashed",
    }
}

fn budget_status_str(status: BudgetStatus) -> &'static str {
    match status {
        BudgetStatus::Open => "open",
        BudgetStatus::Exhausted => "exhausted",
        BudgetStatus::Sealed => "sealed",
        BudgetStatus::Revoked => "revoked",
    }
}

fn operator_health_str(health: OperatorHealth) -> &'static str {
    match health {
        OperatorHealth::Nominal => "nominal",
        OperatorHealth::Watch => "watch",
        OperatorHealth::Throttled => "throttled",
        OperatorHealth::Quarantined => "quarantined",
        OperatorHealth::Retired => "retired",
    }
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_eq<T>(name: &str, left: &T, right: &T) -> Result<()>
where
    T: std::fmt::Debug + PartialEq,
{
    if left != right {
        Err(format!("{name} mismatch: left={left:?} right={right:?}"))
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

fn ensure_at_least(name: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        Err(format!("{name} must be at least {min}"))
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

fn ensure_usize_positive(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_len(name: &str, len: usize, max_len: usize) -> Result<()> {
    if len > max_len {
        Err(format!("{name} length {len} exceeds max {max_len}"))
    } else {
        Ok(())
    }
}
