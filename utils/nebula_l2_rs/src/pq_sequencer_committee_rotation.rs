use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqSequencerCommitteeRotationResult<T> = Result<T, String>;

pub const PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION: &str =
    "nebula-pq-sequencer-committee-rotation-v1";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_SCHEMA_VERSION: u64 = 1;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_SECURITY_MODEL: &str =
    "deterministic-devnet-records-not-real-crypto";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_VRF_COMMITMENT_SCHEME: &str =
    "hash-to-sortition-threshold-devnet-v1";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_STAKE_COMMITMENT_SCHEME: &str =
    "stake-identity-binding-root-v1";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_HEIGHT: u64 = 640;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS: u64 = 10_000;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 120;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_SLOT_MS: u64 = 100;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FAST_PATH_SLOTS: u64 = 48;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FALLBACK_COMMITTEE_SIZE: u64 = 3;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MIN_STAKE_UNITS: u64 = 1_000;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MIN_IDENTITY_SCORE_BPS: u64 = 7_000;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_TARGET_COMMITTEE_SIZE: u64 = 5;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MAX_COMMITTEE_SIZE: u64 = 64;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FAST_PATH_QUORUM_BPS: u64 = 6_000;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FALLBACK_QUORUM_BPS: u64 = 7_500;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_LOW_FEE_BOND_UNITS: u64 = 250;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MAX_LOW_FEE_BOND_UNITS: u64 = 100_000;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MAX_SLOT_LATENCY_MS: u64 = 350;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MISSED_SLOT_TOLERANCE: u64 = 2;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_RETIREMENT_DELAY_BLOCKS: u64 = 240;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_KEY_ROTATION_NOTICE_BLOCKS: u64 = 32;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_SLASHING_WINDOW_BLOCKS: u64 = 720;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_PERFORMANCE_WINDOW_BLOCKS: u64 = 24;
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_BOND_ASSET_ID: &str = "sequencer-bond-dxmr";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_OPERATOR_LABEL: &str =
    "devnet-pq-sequencer-operator";
pub const PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_EPOCH_LABEL: &str = "devnet-pq-sequencer-epoch";

const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_ROTATING: &str = "rotating";
const STATE_STATUS_FALLBACK: &str = "fallback";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSequencerCapability {
    PrivateMempool,
    DefiExecution,
    SmartContracts,
    MoneroBridge,
    LowFeeLane,
    DaSampling,
    ForcedInclusion,
    Watchtower,
}

impl PqSequencerCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateMempool => "private_mempool",
            Self::DefiExecution => "defi_execution",
            Self::SmartContracts => "smart_contracts",
            Self::MoneroBridge => "monero_bridge",
            Self::LowFeeLane => "low_fee_lane",
            Self::DaSampling => "da_sampling",
            Self::ForcedInclusion => "forced_inclusion",
            Self::Watchtower => "watchtower",
        }
    }

    pub fn priority_bonus_bps(self) -> u64 {
        match self {
            Self::PrivateMempool => 450,
            Self::DefiExecution => 350,
            Self::SmartContracts => 300,
            Self::LowFeeLane => 250,
            Self::MoneroBridge => 200,
            Self::DaSampling => 150,
            Self::ForcedInclusion => 100,
            Self::Watchtower => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSequencerCandidateStatus {
    Pending,
    Eligible,
    Active,
    Standby,
    Retiring,
    Retired,
    Slashed,
    Rejected,
}

impl PqSequencerCandidateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Eligible => "eligible",
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Eligible | Self::Active | Self::Standby)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSequencerEpochStatus {
    Draft,
    Committing,
    Active,
    Fallback,
    Closing,
    Closed,
    Disputed,
}

impl PqSequencerEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committing => "committing",
            Self::Active => "active",
            Self::Fallback => "fallback",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committing | Self::Active | Self::Fallback | Self::Closing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderSlotStatus {
    Scheduled,
    Claimed,
    Produced,
    Missed,
    Reassigned,
    FallbackProduced,
    Slashed,
}

impl LeaderSlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Claimed => "claimed",
            Self::Produced => "produced",
            Self::Missed => "missed",
            Self::Reassigned => "reassigned",
            Self::FallbackProduced => "fallback_produced",
            Self::Slashed => "slashed",
        }
    }

    pub fn successful(self) -> bool {
        matches!(self, Self::Produced | Self::FallbackProduced)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackCommitteeReason {
    MissedLeader,
    NetworkPartition,
    SortitionDispute,
    KeyCompromise,
    LowFeeCongestion,
    MoneroAnchorDelay,
    EmergencyDrill,
}

impl FallbackCommitteeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissedLeader => "missed_leader",
            Self::NetworkPartition => "network_partition",
            Self::SortitionDispute => "sortition_dispute",
            Self::KeyCompromise => "key_compromise",
            Self::LowFeeCongestion => "low_fee_congestion",
            Self::MoneroAnchorDelay => "monero_anchor_delay",
            Self::EmergencyDrill => "emergency_drill",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceBondStatus {
    Posted,
    Locked,
    PartiallySlashed,
    Released,
    Forfeited,
    Expired,
}

impl PerformanceBondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Locked => "locked",
            Self::PartiallySlashed => "partially_slashed",
            Self::Released => "released",
            Self::Forfeited => "forfeited",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Posted | Self::Locked | Self::PartiallySlashed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationReceiptStatus {
    Announced,
    Verified,
    Overlap,
    Activated,
    Rejected,
    Superseded,
}

impl KeyRotationReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Verified => "verified",
            Self::Overlap => "overlap",
            Self::Activated => "activated",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::Overlap | Self::Activated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSequencerSlashKind {
    DoubleProposal,
    InvalidPqSignature,
    VrfGrinding,
    IdentityCommitmentMismatch,
    WithheldPrivateBatch,
    MissedFastPathSlots,
    BondUnderfunded,
    FallbackMisuse,
}

impl PqSequencerSlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleProposal => "double_proposal",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::VrfGrinding => "vrf_grinding",
            Self::IdentityCommitmentMismatch => "identity_commitment_mismatch",
            Self::WithheldPrivateBatch => "withheld_private_batch",
            Self::MissedFastPathSlots => "missed_fast_path_slots",
            Self::BondUnderfunded => "bond_underfunded",
            Self::FallbackMisuse => "fallback_misuse",
        }
    }

    pub fn default_slash_bps(self) -> u64 {
        match self {
            Self::DoubleProposal => 4_000,
            Self::InvalidPqSignature => 5_000,
            Self::VrfGrinding => 3_500,
            Self::IdentityCommitmentMismatch => 3_000,
            Self::WithheldPrivateBatch => 2_500,
            Self::MissedFastPathSlots => 1_000,
            Self::BondUnderfunded => 2_000,
            Self::FallbackMisuse => 2_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingRecordStatus {
    Open,
    Accepted,
    Rejected,
    Applied,
    Expired,
}

impl SlashingRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Applied => "applied",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementRecordStatus {
    Requested,
    Cooldown,
    Settled,
    Cancelled,
    Forced,
}

impl RetirementRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Cooldown => "cooldown",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Forced => "forced",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Requested | Self::Cooldown)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerCommitteeRotationConfig {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub bond_asset_id: String,
    pub epoch_length_blocks: u64,
    pub slot_ms: u64,
    pub fast_path_slots: u64,
    pub fallback_committee_size: u64,
    pub min_stake_units: u64,
    pub min_identity_score_bps: u64,
    pub target_committee_size: u64,
    pub max_committee_size: u64,
    pub quorum_bps: u64,
    pub fast_path_quorum_bps: u64,
    pub fallback_quorum_bps: u64,
    pub low_fee_bond_units: u64,
    pub max_low_fee_bond_units: u64,
    pub max_slot_latency_ms: u64,
    pub missed_slot_tolerance: u64,
    pub retirement_delay_blocks: u64,
    pub key_rotation_notice_blocks: u64,
    pub slashing_window_blocks: u64,
    pub performance_window_blocks: u64,
    pub primary_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub sortition_scheme: String,
    pub stake_commitment_scheme: String,
}

impl Default for PqSequencerCommitteeRotationConfig {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_FEE_ASSET_ID.to_string(),
            bond_asset_id: PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_BOND_ASSET_ID.to_string(),
            epoch_length_blocks: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_EPOCH_LENGTH_BLOCKS,
            slot_ms: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_SLOT_MS,
            fast_path_slots: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FAST_PATH_SLOTS,
            fallback_committee_size:
                PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FALLBACK_COMMITTEE_SIZE,
            min_stake_units: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MIN_STAKE_UNITS,
            min_identity_score_bps: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MIN_IDENTITY_SCORE_BPS,
            target_committee_size: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_TARGET_COMMITTEE_SIZE,
            max_committee_size: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MAX_COMMITTEE_SIZE,
            quorum_bps: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_QUORUM_BPS,
            fast_path_quorum_bps: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FAST_PATH_QUORUM_BPS,
            fallback_quorum_bps: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_FALLBACK_QUORUM_BPS,
            low_fee_bond_units: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_LOW_FEE_BOND_UNITS,
            max_low_fee_bond_units: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MAX_LOW_FEE_BOND_UNITS,
            max_slot_latency_ms: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MAX_SLOT_LATENCY_MS,
            missed_slot_tolerance: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_MISSED_SLOT_TOLERANCE,
            retirement_delay_blocks:
                PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_RETIREMENT_DELAY_BLOCKS,
            key_rotation_notice_blocks:
                PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_KEY_ROTATION_NOTICE_BLOCKS,
            slashing_window_blocks: PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_SLASHING_WINDOW_BLOCKS,
            performance_window_blocks:
                PQ_SEQUENCER_COMMITTEE_ROTATION_DEFAULT_PERFORMANCE_WINDOW_BLOCKS,
            primary_signature_scheme: PQ_SEQUENCER_COMMITTEE_ROTATION_PRIMARY_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme: PQ_SEQUENCER_COMMITTEE_ROTATION_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            sortition_scheme: PQ_SEQUENCER_COMMITTEE_ROTATION_VRF_COMMITMENT_SCHEME.to_string(),
            stake_commitment_scheme: PQ_SEQUENCER_COMMITTEE_ROTATION_STAKE_COMMITMENT_SCHEME
                .to_string(),
        }
    }
}

impl PqSequencerCommitteeRotationConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_committee_rotation_config",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "schema_version": PQ_SEQUENCER_COMMITTEE_ROTATION_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "bond_asset_id": self.bond_asset_id,
            "epoch_length_blocks": self.epoch_length_blocks,
            "slot_ms": self.slot_ms,
            "fast_path_slots": self.fast_path_slots,
            "fallback_committee_size": self.fallback_committee_size,
            "min_stake_units": self.min_stake_units,
            "min_identity_score_bps": self.min_identity_score_bps,
            "target_committee_size": self.target_committee_size,
            "max_committee_size": self.max_committee_size,
            "quorum_bps": self.quorum_bps,
            "fast_path_quorum_bps": self.fast_path_quorum_bps,
            "fallback_quorum_bps": self.fallback_quorum_bps,
            "low_fee_bond_units": self.low_fee_bond_units,
            "max_low_fee_bond_units": self.max_low_fee_bond_units,
            "max_slot_latency_ms": self.max_slot_latency_ms,
            "missed_slot_tolerance": self.missed_slot_tolerance,
            "retirement_delay_blocks": self.retirement_delay_blocks,
            "key_rotation_notice_blocks": self.key_rotation_notice_blocks,
            "slashing_window_blocks": self.slashing_window_blocks,
            "performance_window_blocks": self.performance_window_blocks,
            "primary_signature_scheme": self.primary_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "sortition_scheme": self.sortition_scheme,
            "stake_commitment_scheme": self.stake_commitment_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        pq_sequencer_committee_rotation_payload_root(
            "PQ-SEQUENCER-COMMITTEE-ROTATION-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.bond_asset_id", &self.bond_asset_id)?;
        ensure_non_empty(
            "config.primary_signature_scheme",
            &self.primary_signature_scheme,
        )?;
        ensure_non_empty(
            "config.backup_signature_scheme",
            &self.backup_signature_scheme,
        )?;
        ensure_non_empty("config.sortition_scheme", &self.sortition_scheme)?;
        ensure_non_empty(
            "config.stake_commitment_scheme",
            &self.stake_commitment_scheme,
        )?;
        if self.chain_id != CHAIN_ID {
            return Err("pq sequencer rotation config chain id mismatch".to_string());
        }
        if self.epoch_length_blocks == 0 {
            return Err("epoch length must be non-zero".to_string());
        }
        if self.slot_ms == 0 {
            return Err("slot duration must be non-zero".to_string());
        }
        if self.fast_path_slots == 0 {
            return Err("fast path slot count must be non-zero".to_string());
        }
        if self.fallback_committee_size == 0 {
            return Err("fallback committee size must be non-zero".to_string());
        }
        if self.target_committee_size == 0 || self.max_committee_size < self.target_committee_size {
            return Err("committee size bounds are invalid".to_string());
        }
        if self.quorum_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS
            || self.fast_path_quorum_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS
            || self.fallback_quorum_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS
            || self.min_identity_score_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS
        {
            return Err("basis point config exceeds 100%".to_string());
        }
        if self.low_fee_bond_units > self.max_low_fee_bond_units {
            return Err("low fee bond minimum exceeds maximum".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRegistration {
    pub candidate_id: String,
    pub operator_label: String,
    pub stake_commitment_root: String,
    pub identity_commitment_root: String,
    pub pq_public_key_root: String,
    pub backup_public_key_root: String,
    pub network_address_commitment_root: String,
    pub stake_units: u64,
    pub identity_score_bps: u64,
    pub declared_capabilities: BTreeSet<PqSequencerCapability>,
    pub status: PqSequencerCandidateStatus,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
}

impl CandidateRegistration {
    pub fn new(
        operator_label: &str,
        stake_units: u64,
        identity_score_bps: u64,
        capabilities: BTreeSet<PqSequencerCapability>,
        pq_key_label: &str,
        backup_key_label: &str,
        registered_at_height: u64,
        expires_at_height: u64,
        config: &PqSequencerCommitteeRotationConfig,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("candidate.operator_label", operator_label)?;
        ensure_non_empty("candidate.pq_key_label", pq_key_label)?;
        ensure_non_empty("candidate.backup_key_label", backup_key_label)?;
        if expires_at_height <= registered_at_height {
            return Err("candidate registration expiry must be after registration".to_string());
        }
        let stake_commitment_root = commitment_root(
            "PQ-SEQUENCER-STAKE-COMMITMENT",
            &json!({
                "operator_label": operator_label,
                "stake_units": stake_units,
                "asset_id": config.bond_asset_id,
            }),
        );
        let identity_commitment_root = commitment_root(
            "PQ-SEQUENCER-IDENTITY-COMMITMENT",
            &json!({
                "operator_label": operator_label,
                "identity_score_bps": identity_score_bps,
                "capabilities": capability_strings(&capabilities),
            }),
        );
        let pq_public_key_root = string_root("PQ-SEQUENCER-PQ-PUBLIC-KEY", pq_key_label);
        let backup_public_key_root =
            string_root("PQ-SEQUENCER-BACKUP-PUBLIC-KEY", backup_key_label);
        let network_address_commitment_root =
            string_root("PQ-SEQUENCER-NETWORK-ADDRESS", operator_label);
        let candidate_id = candidate_registration_id(
            operator_label,
            &stake_commitment_root,
            &identity_commitment_root,
            &pq_public_key_root,
            registered_at_height,
        );
        let status = if stake_units >= config.min_stake_units
            && identity_score_bps >= config.min_identity_score_bps
        {
            PqSequencerCandidateStatus::Eligible
        } else {
            PqSequencerCandidateStatus::Pending
        };
        let record = Self {
            candidate_id,
            operator_label: operator_label.to_string(),
            stake_commitment_root,
            identity_commitment_root,
            pq_public_key_root,
            backup_public_key_root,
            network_address_commitment_root,
            stake_units,
            identity_score_bps,
            declared_capabilities: capabilities,
            status,
            registered_at_height,
            expires_at_height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "candidate_registration",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "candidate_id": self.candidate_id,
            "operator_label": self.operator_label,
            "stake_commitment_root": self.stake_commitment_root,
            "identity_commitment_root": self.identity_commitment_root,
            "pq_public_key_root": self.pq_public_key_root,
            "backup_public_key_root": self.backup_public_key_root,
            "network_address_commitment_root": self.network_address_commitment_root,
            "stake_units": self.stake_units,
            "identity_score_bps": self.identity_score_bps,
            "declared_capabilities": capability_strings(&self.declared_capabilities),
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn selection_weight(&self) -> u64 {
        let capability_bonus = self
            .declared_capabilities
            .iter()
            .map(|capability| capability.priority_bonus_bps())
            .sum::<u64>();
        self.stake_units
            .saturating_mul(self.identity_score_bps.saturating_add(capability_bonus))
            / PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.selectable()
            && height >= self.registered_at_height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("candidate.candidate_id", &self.candidate_id)?;
        ensure_non_empty("candidate.operator_label", &self.operator_label)?;
        ensure_hex_root(
            "candidate.stake_commitment_root",
            &self.stake_commitment_root,
        )?;
        ensure_hex_root(
            "candidate.identity_commitment_root",
            &self.identity_commitment_root,
        )?;
        ensure_hex_root("candidate.pq_public_key_root", &self.pq_public_key_root)?;
        ensure_hex_root(
            "candidate.backup_public_key_root",
            &self.backup_public_key_root,
        )?;
        ensure_hex_root(
            "candidate.network_address_commitment_root",
            &self.network_address_commitment_root,
        )?;
        if self.identity_score_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("candidate identity score exceeds 100%".to_string());
        }
        if self.expires_at_height <= self.registered_at_height {
            return Err("candidate expires before registration".to_string());
        }
        let expected = candidate_registration_id(
            &self.operator_label,
            &self.stake_commitment_root,
            &self.identity_commitment_root,
            &self.pq_public_key_root,
            self.registered_at_height,
        );
        if self.candidate_id != expected {
            return Err("candidate registration id mismatch".to_string());
        }
        Ok(self.candidate_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortitionCommitment {
    pub sortition_id: String,
    pub candidate_id: String,
    pub epoch_number: u64,
    pub vrf_commitment_root: String,
    pub entropy_root: String,
    pub stake_weight: u64,
    pub selection_threshold_bps: u64,
    pub selected: bool,
    pub committed_at_height: u64,
}

impl SortitionCommitment {
    pub fn new(
        candidate_id: &str,
        epoch_number: u64,
        entropy_label: &str,
        stake_weight: u64,
        selection_threshold_bps: u64,
        committed_at_height: u64,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("sortition.candidate_id", candidate_id)?;
        ensure_non_empty("sortition.entropy_label", entropy_label)?;
        if selection_threshold_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("sortition threshold exceeds 100%".to_string());
        }
        let entropy_root = string_root("PQ-SEQUENCER-SORTITION-ENTROPY", entropy_label);
        let vrf_commitment_root = domain_hash(
            "PQ-SEQUENCER-VRF-LIKE-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(candidate_id),
                HashPart::Int(epoch_number as i128),
                HashPart::Str(&entropy_root),
                HashPart::Int(stake_weight as i128),
            ],
            32,
        );
        let sortition_id = sortition_commitment_id(
            candidate_id,
            epoch_number,
            &vrf_commitment_root,
            committed_at_height,
        );
        let selected =
            sortition_score_bps(&vrf_commitment_root) <= selection_threshold_bps.min(10_000);
        let record = Self {
            sortition_id,
            candidate_id: candidate_id.to_string(),
            epoch_number,
            vrf_commitment_root,
            entropy_root,
            stake_weight,
            selection_threshold_bps,
            selected,
            committed_at_height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sortition_commitment",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "sortition_id": self.sortition_id,
            "candidate_id": self.candidate_id,
            "epoch_number": self.epoch_number,
            "vrf_commitment_root": self.vrf_commitment_root,
            "entropy_root": self.entropy_root,
            "stake_weight": self.stake_weight,
            "selection_threshold_bps": self.selection_threshold_bps,
            "selected": self.selected,
            "committed_at_height": self.committed_at_height,
        })
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("sortition.sortition_id", &self.sortition_id)?;
        ensure_non_empty("sortition.candidate_id", &self.candidate_id)?;
        ensure_hex_root("sortition.vrf_commitment_root", &self.vrf_commitment_root)?;
        ensure_hex_root("sortition.entropy_root", &self.entropy_root)?;
        if self.selection_threshold_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("sortition threshold exceeds 100%".to_string());
        }
        let expected = sortition_commitment_id(
            &self.candidate_id,
            self.epoch_number,
            &self.vrf_commitment_root,
            self.committed_at_height,
        );
        if self.sortition_id != expected {
            return Err("sortition commitment id mismatch".to_string());
        }
        Ok(self.sortition_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeEpoch {
    pub epoch_id: String,
    pub epoch_number: u64,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub candidate_ids: Vec<String>,
    pub fallback_candidate_ids: Vec<String>,
    pub sortition_root: String,
    pub committee_root: String,
    pub quorum_bps: u64,
    pub status: PqSequencerEpochStatus,
}

impl CommitteeEpoch {
    pub fn new(
        epoch_number: u64,
        starts_at_height: u64,
        ends_at_height: u64,
        candidate_ids: Vec<String>,
        fallback_candidate_ids: Vec<String>,
        sortition_root: &str,
        quorum_bps: u64,
        status: PqSequencerEpochStatus,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        if ends_at_height <= starts_at_height {
            return Err("committee epoch end must be after start".to_string());
        }
        ensure_unique_strings("committee candidate", &candidate_ids)?;
        ensure_unique_strings("fallback candidate", &fallback_candidate_ids)?;
        ensure_hex_root("committee.sortition_root", sortition_root)?;
        if quorum_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("committee quorum exceeds 100%".to_string());
        }
        let committee_root = merkle_string_root(
            "PQ-SEQUENCER-COMMITTEE-MEMBERS",
            candidate_ids
                .iter()
                .chain(fallback_candidate_ids.iter())
                .cloned()
                .collect::<Vec<_>>(),
        );
        let epoch_id = committee_epoch_id(
            epoch_number,
            starts_at_height,
            ends_at_height,
            &committee_root,
            sortition_root,
        );
        let record = Self {
            epoch_id,
            epoch_number,
            starts_at_height,
            ends_at_height,
            candidate_ids,
            fallback_candidate_ids,
            sortition_root: sortition_root.to_string(),
            committee_root,
            quorum_bps,
            status,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "committee_epoch",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "epoch_id": self.epoch_id,
            "epoch_number": self.epoch_number,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "candidate_ids": self.candidate_ids,
            "fallback_candidate_ids": self.fallback_candidate_ids,
            "sortition_root": self.sortition_root,
            "committee_root": self.committee_root,
            "quorum_bps": self.quorum_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn live_at(&self, height: u64) -> bool {
        self.status.live() && height >= self.starts_at_height && height <= self.ends_at_height
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("committee.epoch_id", &self.epoch_id)?;
        ensure_unique_strings("committee candidate", &self.candidate_ids)?;
        ensure_unique_strings("fallback candidate", &self.fallback_candidate_ids)?;
        ensure_hex_root("committee.sortition_root", &self.sortition_root)?;
        ensure_hex_root("committee.committee_root", &self.committee_root)?;
        if self.candidate_ids.is_empty() {
            return Err("committee epoch must include candidates".to_string());
        }
        if self.ends_at_height <= self.starts_at_height {
            return Err("committee epoch end must be after start".to_string());
        }
        if self.quorum_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("committee quorum exceeds 100%".to_string());
        }
        let expected_committee_root = merkle_string_root(
            "PQ-SEQUENCER-COMMITTEE-MEMBERS",
            self.candidate_ids
                .iter()
                .chain(self.fallback_candidate_ids.iter())
                .cloned()
                .collect::<Vec<_>>(),
        );
        if self.committee_root != expected_committee_root {
            return Err("committee root mismatch".to_string());
        }
        let expected = committee_epoch_id(
            self.epoch_number,
            self.starts_at_height,
            self.ends_at_height,
            &self.committee_root,
            &self.sortition_root,
        );
        if self.epoch_id != expected {
            return Err("committee epoch id mismatch".to_string());
        }
        Ok(self.epoch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPathLeaderSlot {
    pub slot_id: String,
    pub epoch_id: String,
    pub slot_index: u64,
    pub leader_candidate_id: String,
    pub backup_candidate_id: Option<String>,
    pub scheduled_height: u64,
    pub target_latency_ms: u64,
    pub observed_latency_ms: u64,
    pub batch_commitment_root: String,
    pub status: LeaderSlotStatus,
}

impl FastPathLeaderSlot {
    pub fn new(
        epoch_id: &str,
        slot_index: u64,
        leader_candidate_id: &str,
        backup_candidate_id: Option<String>,
        scheduled_height: u64,
        target_latency_ms: u64,
        observed_latency_ms: u64,
        batch_label: &str,
        status: LeaderSlotStatus,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("leader_slot.epoch_id", epoch_id)?;
        ensure_non_empty("leader_slot.leader_candidate_id", leader_candidate_id)?;
        ensure_non_empty("leader_slot.batch_label", batch_label)?;
        if target_latency_ms == 0 {
            return Err("leader slot target latency must be non-zero".to_string());
        }
        let batch_commitment_root = string_root("PQ-SEQUENCER-FAST-BATCH", batch_label);
        let slot_id =
            fast_path_leader_slot_id(epoch_id, slot_index, leader_candidate_id, scheduled_height);
        let record = Self {
            slot_id,
            epoch_id: epoch_id.to_string(),
            slot_index,
            leader_candidate_id: leader_candidate_id.to_string(),
            backup_candidate_id,
            scheduled_height,
            target_latency_ms,
            observed_latency_ms,
            batch_commitment_root,
            status,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_path_leader_slot",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "slot_id": self.slot_id,
            "epoch_id": self.epoch_id,
            "slot_index": self.slot_index,
            "leader_candidate_id": self.leader_candidate_id,
            "backup_candidate_id": self.backup_candidate_id,
            "scheduled_height": self.scheduled_height,
            "target_latency_ms": self.target_latency_ms,
            "observed_latency_ms": self.observed_latency_ms,
            "batch_commitment_root": self.batch_commitment_root,
            "status": self.status.as_str(),
        })
    }

    pub fn low_latency_success(&self) -> bool {
        self.status.successful() && self.observed_latency_ms <= self.target_latency_ms
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("leader_slot.slot_id", &self.slot_id)?;
        ensure_non_empty("leader_slot.epoch_id", &self.epoch_id)?;
        ensure_non_empty("leader_slot.leader_candidate_id", &self.leader_candidate_id)?;
        if self.target_latency_ms == 0 {
            return Err("leader slot target latency must be non-zero".to_string());
        }
        ensure_hex_root(
            "leader_slot.batch_commitment_root",
            &self.batch_commitment_root,
        )?;
        let expected = fast_path_leader_slot_id(
            &self.epoch_id,
            self.slot_index,
            &self.leader_candidate_id,
            self.scheduled_height,
        );
        if self.slot_id != expected {
            return Err("fast path leader slot id mismatch".to_string());
        }
        Ok(self.slot_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackCommittee {
    pub fallback_id: String,
    pub epoch_id: String,
    pub reason: FallbackCommitteeReason,
    pub member_candidate_ids: Vec<String>,
    pub activation_height: u64,
    pub expires_at_height: u64,
    pub quorum_bps: u64,
    pub attestation_root: String,
    pub used: bool,
}

impl FallbackCommittee {
    pub fn new(
        epoch_id: &str,
        reason: FallbackCommitteeReason,
        member_candidate_ids: Vec<String>,
        activation_height: u64,
        expires_at_height: u64,
        quorum_bps: u64,
        attestation_label: &str,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("fallback.epoch_id", epoch_id)?;
        ensure_non_empty("fallback.attestation_label", attestation_label)?;
        ensure_unique_strings("fallback member", &member_candidate_ids)?;
        if member_candidate_ids.is_empty() {
            return Err("fallback committee must include members".to_string());
        }
        if expires_at_height <= activation_height {
            return Err("fallback expiry must be after activation".to_string());
        }
        if quorum_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("fallback quorum exceeds 100%".to_string());
        }
        let attestation_root = string_root("PQ-SEQUENCER-FALLBACK-ATTESTATION", attestation_label);
        let fallback_id = fallback_committee_id(
            epoch_id,
            reason,
            &member_candidate_ids,
            activation_height,
            &attestation_root,
        );
        let record = Self {
            fallback_id,
            epoch_id: epoch_id.to_string(),
            reason,
            member_candidate_ids,
            activation_height,
            expires_at_height,
            quorum_bps,
            attestation_root,
            used: false,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fallback_committee",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "fallback_id": self.fallback_id,
            "epoch_id": self.epoch_id,
            "reason": self.reason.as_str(),
            "member_candidate_ids": self.member_candidate_ids,
            "activation_height": self.activation_height,
            "expires_at_height": self.expires_at_height,
            "quorum_bps": self.quorum_bps,
            "attestation_root": self.attestation_root,
            "used": self.used,
        })
    }

    pub fn live_at(&self, height: u64) -> bool {
        height >= self.activation_height && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("fallback.fallback_id", &self.fallback_id)?;
        ensure_non_empty("fallback.epoch_id", &self.epoch_id)?;
        ensure_unique_strings("fallback member", &self.member_candidate_ids)?;
        ensure_hex_root("fallback.attestation_root", &self.attestation_root)?;
        if self.member_candidate_ids.is_empty() {
            return Err("fallback committee must include members".to_string());
        }
        if self.expires_at_height <= self.activation_height {
            return Err("fallback expiry must be after activation".to_string());
        }
        if self.quorum_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("fallback quorum exceeds 100%".to_string());
        }
        let expected = fallback_committee_id(
            &self.epoch_id,
            self.reason,
            &self.member_candidate_ids,
            self.activation_height,
            &self.attestation_root,
        );
        if self.fallback_id != expected {
            return Err("fallback committee id mismatch".to_string());
        }
        Ok(self.fallback_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceBond {
    pub bond_id: String,
    pub candidate_id: String,
    pub epoch_id: Option<String>,
    pub asset_id: String,
    pub amount_units: u64,
    pub low_fee_reserved_units: u64,
    pub locked_at_height: u64,
    pub expires_at_height: u64,
    pub status: PerformanceBondStatus,
}

impl PerformanceBond {
    pub fn new(
        candidate_id: &str,
        epoch_id: Option<String>,
        asset_id: &str,
        amount_units: u64,
        low_fee_reserved_units: u64,
        locked_at_height: u64,
        expires_at_height: u64,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("bond.candidate_id", candidate_id)?;
        ensure_non_empty("bond.asset_id", asset_id)?;
        if amount_units == 0 {
            return Err("performance bond amount must be non-zero".to_string());
        }
        if low_fee_reserved_units > amount_units {
            return Err("low fee reserved bond exceeds amount".to_string());
        }
        if expires_at_height <= locked_at_height {
            return Err("performance bond expiry must be after lock height".to_string());
        }
        let bond_id = performance_bond_id(
            candidate_id,
            epoch_id.as_deref(),
            asset_id,
            amount_units,
            locked_at_height,
        );
        let record = Self {
            bond_id,
            candidate_id: candidate_id.to_string(),
            epoch_id,
            asset_id: asset_id.to_string(),
            amount_units,
            low_fee_reserved_units,
            locked_at_height,
            expires_at_height,
            status: PerformanceBondStatus::Locked,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "performance_bond",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "bond_id": self.bond_id,
            "candidate_id": self.candidate_id,
            "epoch_id": self.epoch_id,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "low_fee_reserved_units": self.low_fee_reserved_units,
            "locked_at_height": self.locked_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn remaining_units_after_slash(&self, slash_bps: u64) -> u64 {
        let slash_units = self
            .amount_units
            .saturating_mul(slash_bps.min(PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS))
            / PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS;
        self.amount_units.saturating_sub(slash_units)
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("bond.bond_id", &self.bond_id)?;
        ensure_non_empty("bond.candidate_id", &self.candidate_id)?;
        ensure_non_empty("bond.asset_id", &self.asset_id)?;
        if self.amount_units == 0 {
            return Err("performance bond amount must be non-zero".to_string());
        }
        if self.low_fee_reserved_units > self.amount_units {
            return Err("low fee reserved bond exceeds amount".to_string());
        }
        if self.expires_at_height <= self.locked_at_height {
            return Err("performance bond expiry must be after lock height".to_string());
        }
        let expected = performance_bond_id(
            &self.candidate_id,
            self.epoch_id.as_deref(),
            &self.asset_id,
            self.amount_units,
            self.locked_at_height,
        );
        if self.bond_id != expected {
            return Err("performance bond id mismatch".to_string());
        }
        Ok(self.bond_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationReceipt {
    pub receipt_id: String,
    pub candidate_id: String,
    pub old_pq_key_root: String,
    pub new_pq_key_root: String,
    pub authorization_root: String,
    pub announced_at_height: u64,
    pub activates_at_height: u64,
    pub status: KeyRotationReceiptStatus,
}

impl KeyRotationReceipt {
    pub fn new(
        candidate_id: &str,
        old_pq_key_root: &str,
        new_key_label: &str,
        authorization_label: &str,
        announced_at_height: u64,
        notice_blocks: u64,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("key_rotation.candidate_id", candidate_id)?;
        ensure_hex_root("key_rotation.old_pq_key_root", old_pq_key_root)?;
        ensure_non_empty("key_rotation.new_key_label", new_key_label)?;
        ensure_non_empty("key_rotation.authorization_label", authorization_label)?;
        let new_pq_key_root = string_root("PQ-SEQUENCER-ROTATED-PQ-KEY", new_key_label);
        let authorization_root = string_root("PQ-SEQUENCER-KEY-ROTATION-AUTH", authorization_label);
        let activates_at_height = announced_at_height.saturating_add(notice_blocks.max(1));
        let receipt_id = key_rotation_receipt_id(
            candidate_id,
            old_pq_key_root,
            &new_pq_key_root,
            announced_at_height,
        );
        let record = Self {
            receipt_id,
            candidate_id: candidate_id.to_string(),
            old_pq_key_root: old_pq_key_root.to_string(),
            new_pq_key_root,
            authorization_root,
            announced_at_height,
            activates_at_height,
            status: KeyRotationReceiptStatus::Announced,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "key_rotation_receipt",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "candidate_id": self.candidate_id,
            "old_pq_key_root": self.old_pq_key_root,
            "new_pq_key_root": self.new_pq_key_root,
            "authorization_root": self.authorization_root,
            "announced_at_height": self.announced_at_height,
            "activates_at_height": self.activates_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("key_rotation.receipt_id", &self.receipt_id)?;
        ensure_non_empty("key_rotation.candidate_id", &self.candidate_id)?;
        ensure_hex_root("key_rotation.old_pq_key_root", &self.old_pq_key_root)?;
        ensure_hex_root("key_rotation.new_pq_key_root", &self.new_pq_key_root)?;
        ensure_hex_root("key_rotation.authorization_root", &self.authorization_root)?;
        if self.activates_at_height <= self.announced_at_height {
            return Err("key rotation activation must be after announcement".to_string());
        }
        let expected = key_rotation_receipt_id(
            &self.candidate_id,
            &self.old_pq_key_root,
            &self.new_pq_key_root,
            self.announced_at_height,
        );
        if self.receipt_id != expected {
            return Err("key rotation receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub slashing_id: String,
    pub candidate_id: String,
    pub epoch_id: Option<String>,
    pub slot_id: Option<String>,
    pub bond_id: Option<String>,
    pub slash_kind: PqSequencerSlashKind,
    pub evidence_root: String,
    pub reporter_label: String,
    pub slash_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SlashingRecordStatus,
}

impl SlashingRecord {
    pub fn new(
        candidate_id: &str,
        epoch_id: Option<String>,
        slot_id: Option<String>,
        bond_id: Option<String>,
        slash_kind: PqSequencerSlashKind,
        evidence_label: &str,
        reporter_label: &str,
        opened_at_height: u64,
        window_blocks: u64,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("slashing.candidate_id", candidate_id)?;
        ensure_non_empty("slashing.evidence_label", evidence_label)?;
        ensure_non_empty("slashing.reporter_label", reporter_label)?;
        let evidence_root = string_root("PQ-SEQUENCER-SLASHING-EVIDENCE", evidence_label);
        let slash_bps = slash_kind.default_slash_bps();
        let expires_at_height = opened_at_height.saturating_add(window_blocks.max(1));
        let slashing_id = slashing_record_id(
            candidate_id,
            epoch_id.as_deref(),
            slash_kind,
            &evidence_root,
            opened_at_height,
        );
        let record = Self {
            slashing_id,
            candidate_id: candidate_id.to_string(),
            epoch_id,
            slot_id,
            bond_id,
            slash_kind,
            evidence_root,
            reporter_label: reporter_label.to_string(),
            slash_bps,
            opened_at_height,
            expires_at_height,
            status: SlashingRecordStatus::Open,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_record",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "slashing_id": self.slashing_id,
            "candidate_id": self.candidate_id,
            "epoch_id": self.epoch_id,
            "slot_id": self.slot_id,
            "bond_id": self.bond_id,
            "slash_kind": self.slash_kind.as_str(),
            "evidence_root": self.evidence_root,
            "reporter_label": self.reporter_label,
            "slash_bps": self.slash_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("slashing.slashing_id", &self.slashing_id)?;
        ensure_non_empty("slashing.candidate_id", &self.candidate_id)?;
        ensure_hex_root("slashing.evidence_root", &self.evidence_root)?;
        ensure_non_empty("slashing.reporter_label", &self.reporter_label)?;
        if self.slash_bps > PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS {
            return Err("slashing bps exceeds 100%".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("slashing expiry must be after opening".to_string());
        }
        let expected = slashing_record_id(
            &self.candidate_id,
            self.epoch_id.as_deref(),
            self.slash_kind,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.slashing_id != expected {
            return Err("slashing record id mismatch".to_string());
        }
        Ok(self.slashing_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetirementRecord {
    pub retirement_id: String,
    pub candidate_id: String,
    pub requested_at_height: u64,
    pub effective_at_height: u64,
    pub exit_bond_root: String,
    pub status: RetirementRecordStatus,
}

impl RetirementRecord {
    pub fn new(
        candidate_id: &str,
        requested_at_height: u64,
        delay_blocks: u64,
        exit_bond_label: &str,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("retirement.candidate_id", candidate_id)?;
        ensure_non_empty("retirement.exit_bond_label", exit_bond_label)?;
        let effective_at_height = requested_at_height.saturating_add(delay_blocks.max(1));
        let exit_bond_root = string_root("PQ-SEQUENCER-RETIREMENT-BOND", exit_bond_label);
        let retirement_id =
            retirement_record_id(candidate_id, requested_at_height, &exit_bond_root);
        let record = Self {
            retirement_id,
            candidate_id: candidate_id.to_string(),
            requested_at_height,
            effective_at_height,
            exit_bond_root,
            status: RetirementRecordStatus::Requested,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "retirement_record",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "retirement_id": self.retirement_id,
            "candidate_id": self.candidate_id,
            "requested_at_height": self.requested_at_height,
            "effective_at_height": self.effective_at_height,
            "exit_bond_root": self.exit_bond_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("retirement.retirement_id", &self.retirement_id)?;
        ensure_non_empty("retirement.candidate_id", &self.candidate_id)?;
        ensure_hex_root("retirement.exit_bond_root", &self.exit_bond_root)?;
        if self.effective_at_height <= self.requested_at_height {
            return Err("retirement effective height must be after request".to_string());
        }
        let expected = retirement_record_id(
            &self.candidate_id,
            self.requested_at_height,
            &self.exit_bond_root,
        );
        if self.retirement_id != expected {
            return Err("retirement record id mismatch".to_string());
        }
        Ok(self.retirement_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerRotationPublicRecord {
    pub record_id: String,
    pub label: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl PqSequencerRotationPublicRecord {
    pub fn new(
        label: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        ensure_non_empty("public_record.label", label)?;
        ensure_non_empty("public_record.subject_id", subject_id)?;
        let payload_root =
            pq_sequencer_committee_rotation_payload_root("PQ-SEQUENCER-PUBLIC-PAYLOAD", payload);
        let record_id = public_record_id(
            label,
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            label: label.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_rotation_public_record",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "label": self.label,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        ensure_non_empty("public_record.record_id", &self.record_id)?;
        ensure_non_empty("public_record.label", &self.label)?;
        ensure_non_empty("public_record.subject_id", &self.subject_id)?;
        ensure_hex_root("public_record.payload_root", &self.payload_root)?;
        let expected = public_record_id(
            &self.label,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerCommitteeRotationRoots {
    pub config_root: String,
    pub candidate_registration_root: String,
    pub sortition_commitment_root: String,
    pub committee_epoch_root: String,
    pub leader_slot_root: String,
    pub fallback_committee_root: String,
    pub performance_bond_root: String,
    pub key_rotation_receipt_root: String,
    pub slashing_record_root: String,
    pub retirement_record_root: String,
    pub public_record_root: String,
}

impl PqSequencerCommitteeRotationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_committee_rotation_roots",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "candidate_registration_root": self.candidate_registration_root,
            "sortition_commitment_root": self.sortition_commitment_root,
            "committee_epoch_root": self.committee_epoch_root,
            "leader_slot_root": self.leader_slot_root,
            "fallback_committee_root": self.fallback_committee_root,
            "performance_bond_root": self.performance_bond_root,
            "key_rotation_receipt_root": self.key_rotation_receipt_root,
            "slashing_record_root": self.slashing_record_root,
            "retirement_record_root": self.retirement_record_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        pq_sequencer_committee_rotation_payload_root(
            "PQ-SEQUENCER-COMMITTEE-ROTATION-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerCommitteeRotationCounters {
    pub height: u64,
    pub epoch: u64,
    pub candidate_count: u64,
    pub eligible_candidate_count: u64,
    pub active_candidate_count: u64,
    pub selected_sortition_count: u64,
    pub committee_epoch_count: u64,
    pub live_committee_epoch_count: u64,
    pub leader_slot_count: u64,
    pub successful_fast_path_slot_count: u64,
    pub missed_fast_path_slot_count: u64,
    pub fallback_committee_count: u64,
    pub live_fallback_committee_count: u64,
    pub performance_bond_count: u64,
    pub live_performance_bond_units: u64,
    pub low_fee_reserved_bond_units: u64,
    pub key_rotation_receipt_count: u64,
    pub usable_key_rotation_receipt_count: u64,
    pub open_slashing_record_count: u64,
    pub applied_slashing_record_count: u64,
    pub live_retirement_record_count: u64,
    pub public_record_count: u64,
}

impl PqSequencerCommitteeRotationCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_committee_rotation_counters",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "candidate_count": self.candidate_count,
            "eligible_candidate_count": self.eligible_candidate_count,
            "active_candidate_count": self.active_candidate_count,
            "selected_sortition_count": self.selected_sortition_count,
            "committee_epoch_count": self.committee_epoch_count,
            "live_committee_epoch_count": self.live_committee_epoch_count,
            "leader_slot_count": self.leader_slot_count,
            "successful_fast_path_slot_count": self.successful_fast_path_slot_count,
            "missed_fast_path_slot_count": self.missed_fast_path_slot_count,
            "fallback_committee_count": self.fallback_committee_count,
            "live_fallback_committee_count": self.live_fallback_committee_count,
            "performance_bond_count": self.performance_bond_count,
            "live_performance_bond_units": self.live_performance_bond_units,
            "low_fee_reserved_bond_units": self.low_fee_reserved_bond_units,
            "key_rotation_receipt_count": self.key_rotation_receipt_count,
            "usable_key_rotation_receipt_count": self.usable_key_rotation_receipt_count,
            "open_slashing_record_count": self.open_slashing_record_count,
            "applied_slashing_record_count": self.applied_slashing_record_count,
            "live_retirement_record_count": self.live_retirement_record_count,
            "public_record_count": self.public_record_count,
        })
    }

    pub fn counters_root(&self) -> String {
        pq_sequencer_committee_rotation_payload_root(
            "PQ-SEQUENCER-COMMITTEE-ROTATION-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerCommitteeRotationState {
    pub config: PqSequencerCommitteeRotationConfig,
    pub height: u64,
    pub epoch: u64,
    pub status: String,
    pub candidate_registrations: BTreeMap<String, CandidateRegistration>,
    pub sortition_commitments: BTreeMap<String, SortitionCommitment>,
    pub committee_epochs: BTreeMap<String, CommitteeEpoch>,
    pub fast_path_leader_slots: BTreeMap<String, FastPathLeaderSlot>,
    pub fallback_committees: BTreeMap<String, FallbackCommittee>,
    pub performance_bonds: BTreeMap<String, PerformanceBond>,
    pub key_rotation_receipts: BTreeMap<String, KeyRotationReceipt>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
    pub retirement_records: BTreeMap<String, RetirementRecord>,
    pub public_records: BTreeMap<String, PqSequencerRotationPublicRecord>,
}

impl PqSequencerCommitteeRotationState {
    pub fn new(
        config: PqSequencerCommitteeRotationConfig,
    ) -> PqSequencerCommitteeRotationResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            epoch: 0,
            status: STATE_STATUS_ACTIVE.to_string(),
            candidate_registrations: BTreeMap::new(),
            sortition_commitments: BTreeMap::new(),
            committee_epochs: BTreeMap::new(),
            fast_path_leader_slots: BTreeMap::new(),
            fallback_committees: BTreeMap::new(),
            performance_bonds: BTreeMap::new(),
            key_rotation_receipts: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            retirement_records: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PqSequencerCommitteeRotationResult<Self> {
        let mut state = Self::new(PqSequencerCommitteeRotationConfig::devnet())?;
        state.set_height(PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_HEIGHT)?;
        let height = state.height;

        let candidate_specs = [
            (
                "devnet-sequencer-a",
                3_200,
                9_300,
                vec![
                    PqSequencerCapability::PrivateMempool,
                    PqSequencerCapability::DefiExecution,
                    PqSequencerCapability::LowFeeLane,
                    PqSequencerCapability::MoneroBridge,
                ],
            ),
            (
                "devnet-sequencer-b",
                2_800,
                9_000,
                vec![
                    PqSequencerCapability::PrivateMempool,
                    PqSequencerCapability::SmartContracts,
                    PqSequencerCapability::DaSampling,
                ],
            ),
            (
                "devnet-sequencer-c",
                2_400,
                8_800,
                vec![
                    PqSequencerCapability::DefiExecution,
                    PqSequencerCapability::LowFeeLane,
                    PqSequencerCapability::ForcedInclusion,
                ],
            ),
            (
                "devnet-sequencer-d",
                1_800,
                8_400,
                vec![
                    PqSequencerCapability::PrivateMempool,
                    PqSequencerCapability::Watchtower,
                    PqSequencerCapability::DaSampling,
                ],
            ),
            (
                "devnet-sequencer-e",
                1_400,
                8_100,
                vec![
                    PqSequencerCapability::SmartContracts,
                    PqSequencerCapability::LowFeeLane,
                    PqSequencerCapability::MoneroBridge,
                ],
            ),
            (
                "devnet-sequencer-f",
                1_050,
                7_600,
                vec![
                    PqSequencerCapability::ForcedInclusion,
                    PqSequencerCapability::Watchtower,
                ],
            ),
        ];

        for (index, (label, stake, identity_score, capabilities)) in
            candidate_specs.into_iter().enumerate()
        {
            let registration = CandidateRegistration::new(
                label,
                stake,
                identity_score,
                capabilities.into_iter().collect(),
                &format!("{label}-mldsa65-{index}"),
                &format!("{label}-slhdsa-backup-{index}"),
                height.saturating_sub(48).saturating_add(index as u64),
                height.saturating_add(2_880),
                &state.config,
            )?;
            state.insert_candidate_registration(registration)?;
        }

        let candidate_ids = state
            .candidate_registrations
            .values()
            .filter(|candidate| candidate.active_at(height))
            .map(|candidate| candidate.candidate_id.clone())
            .collect::<Vec<_>>();

        for (index, candidate_id) in candidate_ids.iter().enumerate() {
            let weight = state
                .candidate_registrations
                .get(candidate_id)
                .map(CandidateRegistration::selection_weight)
                .ok_or_else(|| "devnet sortition candidate missing".to_string())?;
            let sortition = SortitionCommitment::new(
                candidate_id,
                state.epoch,
                &format!("devnet-entropy-{}-{index}", state.epoch),
                weight,
                PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS,
                height.saturating_sub(12).saturating_add(index as u64),
            )?;
            state.insert_sortition_commitment(sortition)?;
        }

        let selected_ids = state.selected_candidate_ids_for_epoch(state.epoch);
        let committee_ids = selected_ids
            .iter()
            .take(state.config.target_committee_size as usize)
            .cloned()
            .collect::<Vec<_>>();
        let fallback_ids = selected_ids
            .iter()
            .rev()
            .take(state.config.fallback_committee_size as usize)
            .cloned()
            .collect::<Vec<_>>();
        let sortition_root = state.sortition_commitment_root();
        let committee = CommitteeEpoch::new(
            state.epoch,
            height.saturating_sub(10),
            height.saturating_add(state.config.epoch_length_blocks),
            committee_ids.clone(),
            fallback_ids.clone(),
            &sortition_root,
            state.config.quorum_bps,
            PqSequencerEpochStatus::Active,
        )?;
        let epoch_id = committee.epoch_id.clone();
        state.insert_committee_epoch(committee)?;

        for (index, candidate_id) in committee_ids.iter().enumerate().take(6) {
            let backup_candidate_id = committee_ids
                .get((index + 1) % committee_ids.len().max(1))
                .cloned()
                .filter(|backup| backup != candidate_id);
            let status = if index == 3 {
                LeaderSlotStatus::Missed
            } else {
                LeaderSlotStatus::Produced
            };
            let observed_latency_ms = if status == LeaderSlotStatus::Missed {
                state.config.max_slot_latency_ms.saturating_add(175)
            } else {
                state.config.max_slot_latency_ms.saturating_sub(90)
            };
            let slot = FastPathLeaderSlot::new(
                &epoch_id,
                index as u64,
                candidate_id,
                backup_candidate_id,
                height.saturating_add(index as u64),
                state.config.max_slot_latency_ms,
                observed_latency_ms,
                &format!("devnet-fast-batch-{index}"),
                status,
            )?;
            state.insert_fast_path_leader_slot(slot)?;
        }

        let mut fallback = FallbackCommittee::new(
            &epoch_id,
            FallbackCommitteeReason::MissedLeader,
            fallback_ids.clone(),
            height.saturating_add(3),
            height.saturating_add(state.config.performance_window_blocks),
            state.config.fallback_quorum_bps,
            "devnet-fallback-missed-leader-attestation",
        )?;
        fallback.used = true;
        let fallback_id = fallback.fallback_id.clone();
        state.insert_fallback_committee(fallback)?;

        for candidate_id in &committee_ids {
            let bond = PerformanceBond::new(
                candidate_id,
                Some(epoch_id.clone()),
                &state.config.bond_asset_id,
                state.config.low_fee_bond_units.saturating_mul(12),
                state.config.low_fee_bond_units,
                height.saturating_sub(20),
                height.saturating_add(state.config.epoch_length_blocks),
            )?;
            state.insert_performance_bond(bond)?;
        }

        if let Some(candidate) = committee_ids.first() {
            let old_key = state
                .candidate_registrations
                .get(candidate)
                .map(|registration| registration.pq_public_key_root.clone())
                .ok_or_else(|| "devnet key rotation candidate missing".to_string())?;
            let mut receipt = KeyRotationReceipt::new(
                candidate,
                &old_key,
                "devnet-sequencer-a-mldsa65-rotated",
                "devnet-sequencer-a-rotation-auth",
                height.saturating_sub(4),
                state.config.key_rotation_notice_blocks,
            )?;
            receipt.status = KeyRotationReceiptStatus::Verified;
            state.insert_key_rotation_receipt(receipt)?;
        }

        if let Some(offender) = committee_ids.get(3) {
            let missed_slot_id = state
                .fast_path_leader_slots
                .values()
                .find(|slot| {
                    slot.leader_candidate_id == offender.as_str()
                        && slot.status == LeaderSlotStatus::Missed
                })
                .map(|slot| slot.slot_id.clone());
            let bond_id = state
                .performance_bonds
                .values()
                .find(|bond| bond.candidate_id == offender.as_str())
                .map(|bond| bond.bond_id.clone());
            let mut slash = SlashingRecord::new(
                offender,
                Some(epoch_id.clone()),
                missed_slot_id,
                bond_id,
                PqSequencerSlashKind::MissedFastPathSlots,
                "devnet-missed-fast-path-slot-evidence",
                PQ_SEQUENCER_COMMITTEE_ROTATION_DEVNET_OPERATOR_LABEL,
                height,
                state.config.slashing_window_blocks,
            )?;
            slash.status = SlashingRecordStatus::Accepted;
            state.insert_slashing_record(slash)?;
        }

        if let Some(retiring) = committee_ids.last() {
            let retirement = RetirementRecord::new(
                retiring,
                height.saturating_add(1),
                state.config.retirement_delay_blocks,
                "devnet-retirement-exit-bond",
            )?;
            state.insert_retirement_record(retirement)?;
        }

        let public_record = PqSequencerRotationPublicRecord::new(
            "devnet-pq-sequencer-committee-rotation",
            &epoch_id,
            &json!({
                "epoch_id": epoch_id,
                "fallback_id": fallback_id,
                "goal": "quantum-resistant fast low-fee private DeFi sequencing",
                "state_root": state.roots().roots_root(),
            }),
            height,
            0,
        )?;
        state.insert_public_record(public_record)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqSequencerCommitteeRotationResult<String> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.epoch = height / self.config.epoch_length_blocks.max(1);
        for candidate in self.candidate_registrations.values_mut() {
            if height > candidate.expires_at_height && candidate.status.selectable() {
                candidate.status = PqSequencerCandidateStatus::Retired;
            }
        }
        for epoch in self.committee_epochs.values_mut() {
            if height > epoch.ends_at_height && epoch.status.live() {
                epoch.status = PqSequencerEpochStatus::Closed;
            } else if height >= epoch.ends_at_height.saturating_sub(1)
                && epoch.status == PqSequencerEpochStatus::Active
            {
                epoch.status = PqSequencerEpochStatus::Closing;
            }
        }
        for bond in self.performance_bonds.values_mut() {
            if height > bond.expires_at_height && bond.status.live() {
                bond.status = PerformanceBondStatus::Expired;
            }
        }
        for receipt in self.key_rotation_receipts.values_mut() {
            if height >= receipt.activates_at_height
                && receipt.status == KeyRotationReceiptStatus::Verified
            {
                receipt.status = KeyRotationReceiptStatus::Activated;
            }
        }
        for slash in self.slashing_records.values_mut() {
            if height > slash.expires_at_height && slash.status.live() {
                slash.status = SlashingRecordStatus::Expired;
            }
        }
        for retirement in self.retirement_records.values_mut() {
            if height >= retirement.effective_at_height && retirement.status.live() {
                retirement.status = RetirementRecordStatus::Settled;
            }
        }
        Ok(self.state_root())
    }

    pub fn insert_candidate_registration(
        &mut self,
        registration: CandidateRegistration,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = registration.validate()?;
        if registration.stake_units < self.config.min_stake_units
            && registration.status.selectable()
        {
            return Err("selectable candidate stake below configured minimum".to_string());
        }
        self.candidate_registrations
            .insert(id.clone(), registration);
        Ok(id)
    }

    pub fn insert_sortition_commitment(
        &mut self,
        commitment: SortitionCommitment,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = commitment.validate()?;
        if !self
            .candidate_registrations
            .contains_key(&commitment.candidate_id)
        {
            return Err("sortition references unknown candidate".to_string());
        }
        self.sortition_commitments.insert(id.clone(), commitment);
        Ok(id)
    }

    pub fn insert_committee_epoch(
        &mut self,
        epoch: CommitteeEpoch,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = epoch.validate()?;
        if epoch.candidate_ids.len() as u64 > self.config.max_committee_size {
            return Err("committee exceeds configured maximum size".to_string());
        }
        for candidate_id in epoch
            .candidate_ids
            .iter()
            .chain(epoch.fallback_candidate_ids.iter())
        {
            if !self.candidate_registrations.contains_key(candidate_id) {
                return Err("committee references unknown candidate".to_string());
            }
        }
        self.committee_epochs.insert(id.clone(), epoch);
        Ok(id)
    }

    pub fn insert_fast_path_leader_slot(
        &mut self,
        slot: FastPathLeaderSlot,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = slot.validate()?;
        if !self.committee_epochs.contains_key(&slot.epoch_id) {
            return Err("leader slot references unknown epoch".to_string());
        }
        if !self
            .candidate_registrations
            .contains_key(&slot.leader_candidate_id)
        {
            return Err("leader slot references unknown leader".to_string());
        }
        if let Some(backup_id) = &slot.backup_candidate_id {
            if !self.candidate_registrations.contains_key(backup_id) {
                return Err("leader slot references unknown backup".to_string());
            }
        }
        self.fast_path_leader_slots.insert(id.clone(), slot);
        Ok(id)
    }

    pub fn insert_fallback_committee(
        &mut self,
        fallback: FallbackCommittee,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = fallback.validate()?;
        if !self.committee_epochs.contains_key(&fallback.epoch_id) {
            return Err("fallback references unknown epoch".to_string());
        }
        for candidate_id in &fallback.member_candidate_ids {
            if !self.candidate_registrations.contains_key(candidate_id) {
                return Err("fallback references unknown candidate".to_string());
            }
        }
        self.fallback_committees.insert(id.clone(), fallback);
        Ok(id)
    }

    pub fn insert_performance_bond(
        &mut self,
        bond: PerformanceBond,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = bond.validate()?;
        if !self
            .candidate_registrations
            .contains_key(&bond.candidate_id)
        {
            return Err("bond references unknown candidate".to_string());
        }
        if let Some(epoch_id) = &bond.epoch_id {
            if !self.committee_epochs.contains_key(epoch_id) {
                return Err("bond references unknown epoch".to_string());
            }
        }
        if bond.low_fee_reserved_units < self.config.low_fee_bond_units {
            return Err("bond low fee reserve below configured minimum".to_string());
        }
        self.performance_bonds.insert(id.clone(), bond);
        Ok(id)
    }

    pub fn insert_key_rotation_receipt(
        &mut self,
        receipt: KeyRotationReceipt,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = receipt.validate()?;
        if !self
            .candidate_registrations
            .contains_key(&receipt.candidate_id)
        {
            return Err("key rotation references unknown candidate".to_string());
        }
        self.key_rotation_receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn insert_slashing_record(
        &mut self,
        slashing: SlashingRecord,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = slashing.validate()?;
        if !self
            .candidate_registrations
            .contains_key(&slashing.candidate_id)
        {
            return Err("slashing references unknown candidate".to_string());
        }
        if let Some(epoch_id) = &slashing.epoch_id {
            if !self.committee_epochs.contains_key(epoch_id) {
                return Err("slashing references unknown epoch".to_string());
            }
        }
        if let Some(slot_id) = &slashing.slot_id {
            if !self.fast_path_leader_slots.contains_key(slot_id) {
                return Err("slashing references unknown leader slot".to_string());
            }
        }
        if let Some(bond_id) = &slashing.bond_id {
            if !self.performance_bonds.contains_key(bond_id) {
                return Err("slashing references unknown performance bond".to_string());
            }
        }
        if slashing.status == SlashingRecordStatus::Applied {
            self.mark_candidate_slashed(&slashing.candidate_id);
        }
        self.slashing_records.insert(id.clone(), slashing);
        Ok(id)
    }

    pub fn insert_retirement_record(
        &mut self,
        retirement: RetirementRecord,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = retirement.validate()?;
        if !self
            .candidate_registrations
            .contains_key(&retirement.candidate_id)
        {
            return Err("retirement references unknown candidate".to_string());
        }
        if let Some(candidate) = self
            .candidate_registrations
            .get_mut(&retirement.candidate_id)
        {
            if candidate.status.selectable() {
                candidate.status = PqSequencerCandidateStatus::Retiring;
            }
        }
        self.retirement_records.insert(id.clone(), retirement);
        Ok(id)
    }

    pub fn insert_public_record(
        &mut self,
        record: PqSequencerRotationPublicRecord,
    ) -> PqSequencerCommitteeRotationResult<String> {
        let id = record.validate()?;
        self.public_records.insert(id.clone(), record);
        Ok(id)
    }

    pub fn selected_candidate_ids_for_epoch(&self, epoch_number: u64) -> Vec<String> {
        let mut selected = self
            .sortition_commitments
            .values()
            .filter(|commitment| commitment.epoch_number == epoch_number && commitment.selected)
            .map(|commitment| {
                (
                    commitment.stake_weight,
                    commitment.vrf_commitment_root.clone(),
                    commitment.candidate_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        selected.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        selected
            .into_iter()
            .map(|(_, _, candidate_id)| candidate_id)
            .collect()
    }

    pub fn sortition_commitment_root(&self) -> String {
        sortition_commitment_root(&self.sortition_commitments)
    }

    pub fn roots(&self) -> PqSequencerCommitteeRotationRoots {
        PqSequencerCommitteeRotationRoots {
            config_root: self.config.config_root(),
            candidate_registration_root: candidate_registration_root(&self.candidate_registrations),
            sortition_commitment_root: sortition_commitment_root(&self.sortition_commitments),
            committee_epoch_root: committee_epoch_root(&self.committee_epochs),
            leader_slot_root: leader_slot_root(&self.fast_path_leader_slots),
            fallback_committee_root: fallback_committee_root(&self.fallback_committees),
            performance_bond_root: performance_bond_root(&self.performance_bonds),
            key_rotation_receipt_root: key_rotation_receipt_root(&self.key_rotation_receipts),
            slashing_record_root: slashing_record_root(&self.slashing_records),
            retirement_record_root: retirement_record_root(&self.retirement_records),
            public_record_root: rotation_public_record_root(&self.public_records),
        }
    }

    pub fn counters(&self) -> PqSequencerCommitteeRotationCounters {
        PqSequencerCommitteeRotationCounters {
            height: self.height,
            epoch: self.epoch,
            candidate_count: self.candidate_registrations.len() as u64,
            eligible_candidate_count: self
                .candidate_registrations
                .values()
                .filter(|candidate| candidate.status.selectable())
                .count() as u64,
            active_candidate_count: self
                .candidate_registrations
                .values()
                .filter(|candidate| candidate.active_at(self.height))
                .count() as u64,
            selected_sortition_count: self
                .sortition_commitments
                .values()
                .filter(|commitment| commitment.selected)
                .count() as u64,
            committee_epoch_count: self.committee_epochs.len() as u64,
            live_committee_epoch_count: self
                .committee_epochs
                .values()
                .filter(|epoch| epoch.live_at(self.height))
                .count() as u64,
            leader_slot_count: self.fast_path_leader_slots.len() as u64,
            successful_fast_path_slot_count: self
                .fast_path_leader_slots
                .values()
                .filter(|slot| slot.low_latency_success())
                .count() as u64,
            missed_fast_path_slot_count: self
                .fast_path_leader_slots
                .values()
                .filter(|slot| slot.status == LeaderSlotStatus::Missed)
                .count() as u64,
            fallback_committee_count: self.fallback_committees.len() as u64,
            live_fallback_committee_count: self
                .fallback_committees
                .values()
                .filter(|fallback| fallback.live_at(self.height))
                .count() as u64,
            performance_bond_count: self.performance_bonds.len() as u64,
            live_performance_bond_units: self
                .performance_bonds
                .values()
                .filter(|bond| bond.status.live())
                .map(|bond| bond.amount_units)
                .sum(),
            low_fee_reserved_bond_units: self
                .performance_bonds
                .values()
                .filter(|bond| bond.status.live())
                .map(|bond| bond.low_fee_reserved_units)
                .sum(),
            key_rotation_receipt_count: self.key_rotation_receipts.len() as u64,
            usable_key_rotation_receipt_count: self
                .key_rotation_receipts
                .values()
                .filter(|receipt| receipt.status.usable())
                .count() as u64,
            open_slashing_record_count: self
                .slashing_records
                .values()
                .filter(|record| record.status.live())
                .count() as u64,
            applied_slashing_record_count: self
                .slashing_records
                .values()
                .filter(|record| record.status == SlashingRecordStatus::Applied)
                .count() as u64,
            live_retirement_record_count: self
                .retirement_records
                .values()
                .filter(|record| record.status.live())
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_sequencer_committee_rotation_state",
            "protocol_version": PQ_SEQUENCER_COMMITTEE_ROTATION_PROTOCOL_VERSION,
            "schema_version": PQ_SEQUENCER_COMMITTEE_ROTATION_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "status": self.status,
            "security_model": PQ_SEQUENCER_COMMITTEE_ROTATION_SECURITY_MODEL,
            "hash_suite": PQ_SEQUENCER_COMMITTEE_ROTATION_HASH_SUITE,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "selected_candidate_ids": self.selected_candidate_ids_for_epoch(self.epoch),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        pq_sequencer_committee_rotation_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> PqSequencerCommitteeRotationResult<String> {
        self.config.validate()?;
        require_state_status(&self.status)?;
        let selectable_count = self
            .candidate_registrations
            .values()
            .filter(|candidate| candidate.status.selectable())
            .count() as u64;
        if selectable_count < self.config.fallback_committee_size {
            return Err("selectable candidate count below fallback committee size".to_string());
        }
        for (id, candidate) in &self.candidate_registrations {
            let validated = candidate.validate()?;
            if id != &validated {
                return Err("candidate registration map key mismatch".to_string());
            }
        }
        for (id, commitment) in &self.sortition_commitments {
            let validated = commitment.validate()?;
            if id != &validated {
                return Err("sortition commitment map key mismatch".to_string());
            }
            if !self
                .candidate_registrations
                .contains_key(&commitment.candidate_id)
            {
                return Err("sortition references unknown candidate".to_string());
            }
        }
        for (id, epoch) in &self.committee_epochs {
            let validated = epoch.validate()?;
            if id != &validated {
                return Err("committee epoch map key mismatch".to_string());
            }
            if epoch.candidate_ids.len() as u64 > self.config.max_committee_size {
                return Err("committee exceeds configured maximum size".to_string());
            }
            for candidate_id in epoch
                .candidate_ids
                .iter()
                .chain(epoch.fallback_candidate_ids.iter())
            {
                if !self.candidate_registrations.contains_key(candidate_id) {
                    return Err("committee references unknown candidate".to_string());
                }
            }
        }
        for (id, slot) in &self.fast_path_leader_slots {
            let validated = slot.validate()?;
            if id != &validated {
                return Err("leader slot map key mismatch".to_string());
            }
            if !self.committee_epochs.contains_key(&slot.epoch_id) {
                return Err("leader slot references unknown epoch".to_string());
            }
            if !self
                .candidate_registrations
                .contains_key(&slot.leader_candidate_id)
            {
                return Err("leader slot references unknown leader".to_string());
            }
        }
        for (id, fallback) in &self.fallback_committees {
            let validated = fallback.validate()?;
            if id != &validated {
                return Err("fallback committee map key mismatch".to_string());
            }
            if !self.committee_epochs.contains_key(&fallback.epoch_id) {
                return Err("fallback references unknown epoch".to_string());
            }
        }
        for (id, bond) in &self.performance_bonds {
            let validated = bond.validate()?;
            if id != &validated {
                return Err("performance bond map key mismatch".to_string());
            }
            if !self
                .candidate_registrations
                .contains_key(&bond.candidate_id)
            {
                return Err("bond references unknown candidate".to_string());
            }
        }
        for (id, receipt) in &self.key_rotation_receipts {
            let validated = receipt.validate()?;
            if id != &validated {
                return Err("key rotation receipt map key mismatch".to_string());
            }
            if !self
                .candidate_registrations
                .contains_key(&receipt.candidate_id)
            {
                return Err("key rotation references unknown candidate".to_string());
            }
        }
        for (id, slashing) in &self.slashing_records {
            let validated = slashing.validate()?;
            if id != &validated {
                return Err("slashing record map key mismatch".to_string());
            }
            if !self
                .candidate_registrations
                .contains_key(&slashing.candidate_id)
            {
                return Err("slashing references unknown candidate".to_string());
            }
        }
        for (id, retirement) in &self.retirement_records {
            let validated = retirement.validate()?;
            if id != &validated {
                return Err("retirement record map key mismatch".to_string());
            }
            if !self
                .candidate_registrations
                .contains_key(&retirement.candidate_id)
            {
                return Err("retirement references unknown candidate".to_string());
            }
        }
        for (id, record) in &self.public_records {
            let validated = record.validate()?;
            if id != &validated {
                return Err("public record map key mismatch".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn mark_candidate_slashed(&mut self, candidate_id: &str) {
        if let Some(candidate) = self.candidate_registrations.get_mut(candidate_id) {
            candidate.status = PqSequencerCandidateStatus::Slashed;
        }
    }
}

pub fn pq_sequencer_committee_rotation_state_root_from_record(record: &Value) -> String {
    pq_sequencer_committee_rotation_payload_root("PQ-SEQUENCER-COMMITTEE-ROTATION-STATE", record)
}

pub fn pq_sequencer_committee_rotation_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn candidate_registration_id(
    operator_label: &str,
    stake_commitment_root: &str,
    identity_commitment_root: &str,
    pq_public_key_root: &str,
    registered_at_height: u64,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-CANDIDATE-REGISTRATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(stake_commitment_root),
            HashPart::Str(identity_commitment_root),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(registered_at_height as i128),
        ],
        32,
    )
}

pub fn sortition_commitment_id(
    candidate_id: &str,
    epoch_number: u64,
    vrf_commitment_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-SORTITION-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(candidate_id),
            HashPart::Int(epoch_number as i128),
            HashPart::Str(vrf_commitment_root),
            HashPart::Int(committed_at_height as i128),
        ],
        32,
    )
}

pub fn committee_epoch_id(
    epoch_number: u64,
    starts_at_height: u64,
    ends_at_height: u64,
    committee_root: &str,
    sortition_root: &str,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-COMMITTEE-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_number as i128),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(ends_at_height as i128),
            HashPart::Str(committee_root),
            HashPart::Str(sortition_root),
        ],
        32,
    )
}

pub fn fast_path_leader_slot_id(
    epoch_id: &str,
    slot_index: u64,
    leader_candidate_id: &str,
    scheduled_height: u64,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-FAST-PATH-LEADER-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Int(slot_index as i128),
            HashPart::Str(leader_candidate_id),
            HashPart::Int(scheduled_height as i128),
        ],
        32,
    )
}

pub fn fallback_committee_id(
    epoch_id: &str,
    reason: FallbackCommitteeReason,
    member_candidate_ids: &[String],
    activation_height: u64,
    attestation_root: &str,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-FALLBACK-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(&member_candidate_ids.join(",")),
            HashPart::Int(activation_height as i128),
            HashPart::Str(attestation_root),
        ],
        32,
    )
}

pub fn performance_bond_id(
    candidate_id: &str,
    epoch_id: Option<&str>,
    asset_id: &str,
    amount_units: u64,
    locked_at_height: u64,
) -> String {
    let epoch_component = match epoch_id {
        Some(value) => value,
        None => "",
    };
    domain_hash(
        "PQ-SEQUENCER-PERFORMANCE-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(candidate_id),
            HashPart::Str(epoch_component),
            HashPart::Str(asset_id),
            HashPart::Int(amount_units as i128),
            HashPart::Int(locked_at_height as i128),
        ],
        32,
    )
}

pub fn key_rotation_receipt_id(
    candidate_id: &str,
    old_pq_key_root: &str,
    new_pq_key_root: &str,
    announced_at_height: u64,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-KEY-ROTATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(candidate_id),
            HashPart::Str(old_pq_key_root),
            HashPart::Str(new_pq_key_root),
            HashPart::Int(announced_at_height as i128),
        ],
        32,
    )
}

pub fn slashing_record_id(
    candidate_id: &str,
    epoch_id: Option<&str>,
    slash_kind: PqSequencerSlashKind,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    let epoch_component = match epoch_id {
        Some(value) => value,
        None => "",
    };
    domain_hash(
        "PQ-SEQUENCER-SLASHING-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(candidate_id),
            HashPart::Str(epoch_component),
            HashPart::Str(slash_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn retirement_record_id(
    candidate_id: &str,
    requested_at_height: u64,
    exit_bond_root: &str,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-RETIREMENT-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(candidate_id),
            HashPart::Int(requested_at_height as i128),
            HashPart::Str(exit_bond_root),
        ],
        32,
    )
}

pub fn public_record_id(
    label: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-SEQUENCER-ROTATION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn candidate_registration_root(records: &BTreeMap<String, CandidateRegistration>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-CANDIDATE-REGISTRATION-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn sortition_commitment_root(records: &BTreeMap<String, SortitionCommitment>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-SORTITION-COMMITMENT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn committee_epoch_root(records: &BTreeMap<String, CommitteeEpoch>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-COMMITTEE-EPOCH-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn leader_slot_root(records: &BTreeMap<String, FastPathLeaderSlot>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-LEADER-SLOT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn fallback_committee_root(records: &BTreeMap<String, FallbackCommittee>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-FALLBACK-COMMITTEE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn performance_bond_root(records: &BTreeMap<String, PerformanceBond>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-PERFORMANCE-BOND-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn key_rotation_receipt_root(records: &BTreeMap<String, KeyRotationReceipt>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-KEY-ROTATION-RECEIPT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn slashing_record_root(records: &BTreeMap<String, SlashingRecord>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-SLASHING-RECORD-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn retirement_record_root(records: &BTreeMap<String, RetirementRecord>) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-RETIREMENT-RECORD-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn rotation_public_record_root(
    records: &BTreeMap<String, PqSequencerRotationPublicRecord>,
) -> String {
    keyed_record_root(
        "PQ-SEQUENCER-ROTATION-PUBLIC-RECORD-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

fn keyed_record_root<'a>(
    domain: &str,
    records: impl Iterator<Item = (&'a String, Value)>,
) -> String {
    let leaves = records
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn commitment_root(domain: &str, payload: &Value) -> String {
    pq_sequencer_committee_rotation_payload_root(domain, payload)
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

fn merkle_string_root(domain: &str, values: Vec<String>) -> String {
    let leaves = values
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn capability_strings(capabilities: &BTreeSet<PqSequencerCapability>) -> Vec<&'static str> {
    capabilities
        .iter()
        .map(|capability| capability.as_str())
        .collect()
}

fn sortition_score_bps(root: &str) -> u64 {
    let mut value = 0_u64;
    for byte in root.bytes().take(8) {
        let nibble = match hex_nibble(byte) {
            Some(value) => value,
            None => 0,
        };
        value = value.saturating_mul(16).saturating_add(nibble as u64);
    }
    value % (PQ_SEQUENCER_COMMITTEE_ROTATION_MAX_BPS + 1)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn ensure_non_empty(field: &str, value: &str) -> PqSequencerCommitteeRotationResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    Ok(())
}

fn ensure_hex_root(field: &str, value: &str) -> PqSequencerCommitteeRotationResult<()> {
    ensure_non_empty(field, value)?;
    if value.len() != 64 || !value.bytes().all(|byte| hex_nibble(byte).is_some()) {
        return Err(format!("{field} must be a 32-byte hex root"));
    }
    Ok(())
}

fn ensure_unique_strings(label: &str, values: &[String]) -> PqSequencerCommitteeRotationResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} values must be unique"));
        }
    }
    Ok(())
}

fn require_state_status(status: &str) -> PqSequencerCommitteeRotationResult<()> {
    match status {
        STATE_STATUS_ACTIVE
        | STATE_STATUS_ROTATING
        | STATE_STATUS_FALLBACK
        | STATE_STATUS_HALTED => Ok(()),
        _ => Err("unknown pq sequencer rotation state status".to_string()),
    }
}
