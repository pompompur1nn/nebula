use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MICROBATCH_COMMITTEE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-microbatch-committee-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MICROBATCH_COMMITTEE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-microbatch-committee-v1";
pub const ENCRYPTED_COMMITMENT_SUITE: &str =
    "ml-kem-threshold-confidential-microbatch-commitment-envelope-v1";
pub const PRECONFIRMATION_LANE_SUITE: &str =
    "low-latency-confidential-microbatch-preconfirmation-lane-v1";
pub const COMMITTEE_ROTATION_SUITE: &str =
    "stake-weighted-pq-confidential-microbatch-committee-rotation-v1";
pub const EQUIVOCATION_QUARANTINE_SUITE: &str =
    "deterministic-pq-microbatch-equivocation-quarantine-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_EPOCH: u64 = 24_576;
pub const DEVNET_L2_HEIGHT: u64 = 3_040_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_620_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 35;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 95;
pub const DEFAULT_COMMITTEE_EPOCH_SLOTS: u64 = 512;
pub const DEFAULT_ROTATION_OVERLAP_SLOTS: u64 = 32;
pub const DEFAULT_MICROBATCH_TTL_SLOTS: u64 = 20;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 64;
pub const DEFAULT_QUARANTINE_TTL_SLOTS: u64 = 4_096;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_FAST_QUORUM_WEIGHT_BPS: u64 = 7_500;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_EMERGENCY_FEE_CAP_BPS: u64 = 25;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MIN_COMMITTEE_BOND_MICRO_UNITS: u64 = 60_000_000;
pub const DEFAULT_MIN_SIGNER_BOND_MICRO_UNITS: u64 = 15_000_000;
pub const DEFAULT_MAX_COMMITTEES: usize = 262_144;
pub const DEFAULT_MAX_MEMBERS: usize = 2_097_152;
pub const DEFAULT_MAX_ROTATIONS: usize = 524_288;
pub const DEFAULT_MAX_LANES: usize = 16_384;
pub const DEFAULT_MAX_MICROBATCHES: usize = 2_097_152;
pub const DEFAULT_MAX_COMMITMENTS: usize = 2_097_152;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_FEE_CAPS: usize = 262_144;
pub const DEFAULT_MAX_QUARANTINES: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeKind {
    FastConfidentialSwap,
    ConfidentialPayment,
    ContractCall,
    MoneroBridgeExit,
    ProofAggregation,
    EmergencyCancel,
}

impl CommitteeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastConfidentialSwap => "fast_confidential_swap",
            Self::ConfidentialPayment => "confidential_payment",
            Self::ContractCall => "contract_call",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::ProofAggregation => "proof_aggregation",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_000,
            Self::MoneroBridgeExit => 9_600,
            Self::ContractCall => 9_100,
            Self::FastConfidentialSwap => 8_900,
            Self::ConfidentialPayment => 8_500,
            Self::ProofAggregation => 7_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Registered,
    Active,
    RotatingIn,
    RotatingOut,
    Paused,
    Quarantined,
    Slashed,
    Retired,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::RotatingIn => "rotating_in",
            Self::RotatingOut => "rotating_out",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::RotatingIn | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Candidate,
    Active,
    Standby,
    RotatingOut,
    Quarantined,
    Slashed,
    Retired,
}

impl MemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Standby => "standby",
            Self::RotatingOut => "rotating_out",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn contributes_weight(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Swap,
    Payment,
    ContractCall,
    BridgeExit,
    MakerQuote,
    ProofHint,
    EmergencyCancel,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Payment => "payment",
            Self::ContractCall => "contract_call",
            Self::BridgeExit => "bridge_exit",
            Self::MakerQuote => "maker_quote",
            Self::ProofHint => "proof_hint",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_000,
            Self::BridgeExit => 9_600,
            Self::ContractCall => 9_200,
            Self::Swap => 8_800,
            Self::Payment => 8_400,
            Self::MakerQuote => 8_000,
            Self::ProofHint => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Draining,
    Paused,
    Quarantined,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrobatchStatus {
    Encrypted,
    Committed,
    CommitteeAssigned,
    Attesting,
    Preconfirmed,
    Settled,
    Expired,
    Rejected,
    Quarantined,
}

impl MicrobatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Committed => "committed",
            Self::CommitteeAssigned => "committee_assigned",
            Self::Attesting => "attesting",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::Committed
                | Self::CommitteeAssigned
                | Self::Attesting
                | Self::Preconfirmed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Defer,
    RejectFeeCap,
    RejectPrivacySet,
    RejectEquivocation,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Defer => "defer",
            Self::RejectFeeCap => "reject_fee_cap",
            Self::RejectPrivacySet => "reject_privacy_set",
            Self::RejectEquivocation => "reject_equivocation",
        }
    }

    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Include)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Draft,
    Signed,
    FastQuorum,
    Published,
    Settled,
    Revoked,
    Expired,
}

impl PreconfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Signed => "signed",
            Self::FastQuorum => "fast_quorum",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Proposed,
    Warming,
    ActiveOverlap,
    Finalized,
    Cancelled,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Warming => "warming",
            Self::ActiveOverlap => "active_overlap",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    EvidenceLocked,
    CommitteePaused,
    Slashed,
    Released,
    Expired,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceLocked => "evidence_locked",
            Self::CommitteePaused => "committee_paused",
            Self::Slashed => "slashed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub slot_width_ms: u64,
    pub target_preconfirmation_ms: u64,
    pub committee_epoch_slots: u64,
    pub rotation_overlap_slots: u64,
    pub microbatch_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub quarantine_ttl_slots: u64,
    pub quorum_weight_bps: u64,
    pub fast_quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub emergency_fee_cap_bps: u64,
    pub slash_bps: u64,
    pub min_committee_bond_micro_units: u64,
    pub min_signer_bond_micro_units: u64,
    pub max_committees: usize,
    pub max_members: usize,
    pub max_rotations: usize,
    pub max_lanes: usize,
    pub max_microbatches: usize,
    pub max_commitments: usize,
    pub max_attestations: usize,
    pub max_preconfirmations: usize,
    pub max_fee_caps: usize,
    pub max_quarantines: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            committee_epoch_slots: DEFAULT_COMMITTEE_EPOCH_SLOTS,
            rotation_overlap_slots: DEFAULT_ROTATION_OVERLAP_SLOTS,
            microbatch_ttl_slots: DEFAULT_MICROBATCH_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            quarantine_ttl_slots: DEFAULT_QUARANTINE_TTL_SLOTS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            fast_quorum_weight_bps: DEFAULT_FAST_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            emergency_fee_cap_bps: DEFAULT_EMERGENCY_FEE_CAP_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            min_committee_bond_micro_units: DEFAULT_MIN_COMMITTEE_BOND_MICRO_UNITS,
            min_signer_bond_micro_units: DEFAULT_MIN_SIGNER_BOND_MICRO_UNITS,
            max_committees: DEFAULT_MAX_COMMITTEES,
            max_members: DEFAULT_MAX_MEMBERS,
            max_rotations: DEFAULT_MAX_ROTATIONS,
            max_lanes: DEFAULT_MAX_LANES,
            max_microbatches: DEFAULT_MAX_MICROBATCHES,
            max_commitments: DEFAULT_MAX_COMMITMENTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
            max_fee_caps: DEFAULT_MAX_FEE_CAPS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "slot_width_ms": self.slot_width_ms,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "committee_epoch_slots": self.committee_epoch_slots,
            "rotation_overlap_slots": self.rotation_overlap_slots,
            "microbatch_ttl_slots": self.microbatch_ttl_slots,
            "attestation_ttl_slots": self.attestation_ttl_slots,
            "quarantine_ttl_slots": self.quarantine_ttl_slots,
            "quorum_weight_bps": self.quorum_weight_bps,
            "fast_quorum_weight_bps": self.fast_quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "emergency_fee_cap_bps": self.emergency_fee_cap_bps,
            "slash_bps": self.slash_bps,
            "min_committee_bond_micro_units": self.min_committee_bond_micro_units,
            "min_signer_bond_micro_units": self.min_signer_bond_micro_units,
            "max_committees": self.max_committees,
            "max_members": self.max_members,
            "max_rotations": self.max_rotations,
            "max_lanes": self.max_lanes,
            "max_microbatches": self.max_microbatches,
            "max_commitments": self.max_commitments,
            "max_attestations": self.max_attestations,
            "max_preconfirmations": self.max_preconfirmations,
            "max_fee_caps": self.max_fee_caps,
            "max_quarantines": self.max_quarantines,
            "max_public_records": self.max_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub epoch: u64,
    pub slot: u64,
    pub next_committee_index: u64,
    pub next_member_index: u64,
    pub next_rotation_index: u64,
    pub next_lane_index: u64,
    pub next_microbatch_index: u64,
    pub next_commitment_index: u64,
    pub next_attestation_index: u64,
    pub next_preconfirmation_index: u64,
    pub next_fee_cap_index: u64,
    pub next_quarantine_index: u64,
    pub next_public_record_index: u64,
    pub total_committed_microbatches: u64,
    pub total_preconfirmed_microbatches: u64,
    pub total_quarantined_microbatches: u64,
    pub total_rotations_finalized: u64,
    pub total_fee_cap_rejections: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            epoch: DEVNET_EPOCH,
            slot: 0,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "slot": self.slot,
            "next_committee_index": self.next_committee_index,
            "next_member_index": self.next_member_index,
            "next_rotation_index": self.next_rotation_index,
            "next_lane_index": self.next_lane_index,
            "next_microbatch_index": self.next_microbatch_index,
            "next_commitment_index": self.next_commitment_index,
            "next_attestation_index": self.next_attestation_index,
            "next_preconfirmation_index": self.next_preconfirmation_index,
            "next_fee_cap_index": self.next_fee_cap_index,
            "next_quarantine_index": self.next_quarantine_index,
            "next_public_record_index": self.next_public_record_index,
            "total_committed_microbatches": self.total_committed_microbatches,
            "total_preconfirmed_microbatches": self.total_preconfirmed_microbatches,
            "total_quarantined_microbatches": self.total_quarantined_microbatches,
            "total_rotations_finalized": self.total_rotations_finalized,
            "total_fee_cap_rejections": self.total_fee_cap_rejections,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub committee_root: String,
    pub member_root: String,
    pub rotation_root: String,
    pub lane_root: String,
    pub microbatch_root: String,
    pub commitment_root: String,
    pub attestation_root: String,
    pub preconfirmation_root: String,
    pub fee_cap_root: String,
    pub quarantine_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "committee_root": self.committee_root,
            "member_root": self.member_root,
            "rotation_root": self.rotation_root,
            "lane_root": self.lane_root,
            "microbatch_root": self.microbatch_root,
            "commitment_root": self.commitment_root,
            "attestation_root": self.attestation_root,
            "preconfirmation_root": self.preconfirmation_root,
            "fee_cap_root": self.fee_cap_root,
            "quarantine_root": self.quarantine_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Committee {
    pub committee_id: String,
    pub kind: CommitteeKind,
    pub status: CommitteeStatus,
    pub epoch: u64,
    pub active_from_slot: u64,
    pub active_until_slot: u64,
    pub threshold_weight_bps: u64,
    pub fast_threshold_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub bonded_micro_units: u64,
    pub aggregate_pq_key_commitment: String,
    pub transcript_root: String,
    pub member_ids: BTreeSet<String>,
}

impl Committee {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "active_from_slot": self.active_from_slot,
            "active_until_slot": self.active_until_slot,
            "threshold_weight_bps": self.threshold_weight_bps,
            "fast_threshold_weight_bps": self.fast_threshold_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "bonded_micro_units": self.bonded_micro_units,
            "aggregate_pq_key_commitment": self.aggregate_pq_key_commitment,
            "transcript_root": self.transcript_root,
            "member_ids": values_for_ids(&self.member_ids),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub committee_id: String,
    pub status: MemberStatus,
    pub operator_commitment: String,
    pub pq_signing_key_commitment: String,
    pub pq_kem_key_commitment: String,
    pub view_tag_policy_root: String,
    pub weight_bps: u64,
    pub bond_micro_units: u64,
    pub joined_epoch: u64,
    pub last_attested_slot: u64,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "pq_signing_key_commitment": self.pq_signing_key_commitment,
            "pq_kem_key_commitment": self.pq_kem_key_commitment,
            "view_tag_policy_root": self.view_tag_policy_root,
            "weight_bps": self.weight_bps,
            "bond_micro_units": self.bond_micro_units,
            "joined_epoch": self.joined_epoch,
            "last_attested_slot": self.last_attested_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeRotation {
    pub rotation_id: String,
    pub status: RotationStatus,
    pub from_committee_id: String,
    pub to_committee_id: String,
    pub proposed_slot: u64,
    pub overlap_start_slot: u64,
    pub overlap_end_slot: u64,
    pub entropy_root: String,
    pub handoff_record_root: String,
}

impl CommitteeRotation {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "status": self.status.as_str(),
            "from_committee_id": self.from_committee_id,
            "to_committee_id": self.to_committee_id,
            "proposed_slot": self.proposed_slot,
            "overlap_start_slot": self.overlap_start_slot,
            "overlap_end_slot": self.overlap_end_slot,
            "entropy_root": self.entropy_root,
            "handoff_record_root": self.handoff_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationLane {
    pub lane_id: String,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub committee_id: String,
    pub priority_bps: u64,
    pub max_microbatch_bytes: u64,
    pub max_items: u32,
    pub target_latency_ms: u64,
    pub fee_cap_bps: u64,
    pub privacy_floor: u64,
    pub pending_microbatch_ids: BTreeSet<String>,
}

impl PreconfirmationLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "committee_id": self.committee_id,
            "priority_bps": self.priority_bps,
            "max_microbatch_bytes": self.max_microbatch_bytes,
            "max_items": self.max_items,
            "target_latency_ms": self.target_latency_ms,
            "fee_cap_bps": self.fee_cap_bps,
            "privacy_floor": self.privacy_floor,
            "pending_microbatch_ids": values_for_ids(&self.pending_microbatch_ids),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedMicrobatch {
    pub microbatch_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub status: MicrobatchStatus,
    pub slot: u64,
    pub expires_slot: u64,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub nullifier_root: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub fee_cap_bps: u64,
    pub item_count: u32,
    pub byte_size: u64,
    pub privacy_set_size: u64,
    pub sender_commitment: String,
    pub public_commitment_root: String,
}

impl EncryptedMicrobatch {
    pub fn public_record(&self) -> Value {
        json!({
            "microbatch_id": self.microbatch_id,
            "lane_id": self.lane_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "slot": self.slot,
            "expires_slot": self.expires_slot,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_commitment": self.ciphertext_commitment,
            "nullifier_root": self.nullifier_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "fee_cap_bps": self.fee_cap_bps,
            "item_count": self.item_count,
            "byte_size": self.byte_size,
            "privacy_set_size": self.privacy_set_size,
            "sender_commitment": self.sender_commitment,
            "public_commitment_root": self.public_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MicrobatchCommitment {
    pub commitment_id: String,
    pub microbatch_id: String,
    pub committee_id: String,
    pub lane_id: String,
    pub slot: u64,
    pub encrypted_commitment_root: String,
    pub availability_root: String,
    pub opening_hint_root: String,
    pub deterministic_public_root: String,
}

impl MicrobatchCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "microbatch_id": self.microbatch_id,
            "committee_id": self.committee_id,
            "lane_id": self.lane_id,
            "slot": self.slot,
            "encrypted_commitment_root": self.encrypted_commitment_root,
            "availability_root": self.availability_root,
            "opening_hint_root": self.opening_hint_root,
            "deterministic_public_root": self.deterministic_public_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignerAttestation {
    pub attestation_id: String,
    pub microbatch_id: String,
    pub commitment_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub slot: u64,
    pub verdict: AttestationVerdict,
    pub signer_weight_bps: u64,
    pub observed_latency_ms: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
}

impl PqSignerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "microbatch_id": self.microbatch_id,
            "commitment_id": self.commitment_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "slot": self.slot,
            "verdict": self.verdict.as_str(),
            "signer_weight_bps": self.signer_weight_bps,
            "observed_latency_ms": self.observed_latency_ms,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowLatencyPreconfirmation {
    pub preconfirmation_id: String,
    pub microbatch_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub status: PreconfirmationStatus,
    pub slot: u64,
    pub quorum_weight_bps: u64,
    pub fast_quorum_weight_bps: u64,
    pub attestation_root: String,
    pub public_receipt_root: String,
    pub latency_ms: u64,
}

impl LowLatencyPreconfirmation {
    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "microbatch_id": self.microbatch_id,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "slot": self.slot,
            "quorum_weight_bps": self.quorum_weight_bps,
            "fast_quorum_weight_bps": self.fast_quorum_weight_bps,
            "attestation_root": self.attestation_root,
            "public_receipt_root": self.public_receipt_root,
            "latency_ms": self.latency_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCap {
    pub fee_cap_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub cap_bps: u64,
    pub emergency_cap_bps: u64,
    pub fee_asset_id: String,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
    pub sponsor_commitment: Option<String>,
}

impl FeeCap {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "lane_id": self.lane_id,
            "committee_id": self.committee_id,
            "cap_bps": self.cap_bps,
            "emergency_cap_bps": self.emergency_cap_bps,
            "fee_asset_id": self.fee_asset_id,
            "valid_from_slot": self.valid_from_slot,
            "valid_until_slot": self.valid_until_slot,
            "sponsor_commitment": self.sponsor_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EquivocationQuarantine {
    pub quarantine_id: String,
    pub status: QuarantineStatus,
    pub committee_id: String,
    pub member_id: Option<String>,
    pub microbatch_id: Option<String>,
    pub first_commitment_root: String,
    pub conflicting_commitment_root: String,
    pub evidence_root: String,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub slash_bps: u64,
}

impl EquivocationQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "status": self.status.as_str(),
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "microbatch_id": self.microbatch_id,
            "first_commitment_root": self.first_commitment_root,
            "conflicting_commitment_root": self.conflicting_commitment_root,
            "evidence_root": self.evidence_root,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "slash_bps": self.slash_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecordEntry {
    pub record_id: String,
    pub slot: u64,
    pub kind: String,
    pub subject_id: String,
    pub public_root: String,
}

impl PublicRecordEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "slot": self.slot,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "public_root": self.public_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub l2_height: u64,
    pub monero_height: u64,
    pub committees: BTreeMap<String, Committee>,
    pub members: BTreeMap<String, CommitteeMember>,
    pub rotations: BTreeMap<String, CommitteeRotation>,
    pub lanes: BTreeMap<String, PreconfirmationLane>,
    pub microbatches: BTreeMap<String, EncryptedMicrobatch>,
    pub commitments: BTreeMap<String, MicrobatchCommitment>,
    pub attestations: BTreeMap<String, PqSignerAttestation>,
    pub preconfirmations: BTreeMap<String, LowLatencyPreconfirmation>,
    pub fee_caps: BTreeMap<String, FeeCap>,
    pub quarantines: BTreeMap<String, EquivocationQuarantine>,
    pub public_records: BTreeMap<String, PublicRecordEntry>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::devnet(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            committees: BTreeMap::new(),
            members: BTreeMap::new(),
            rotations: BTreeMap::new(),
            lanes: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            commitments: BTreeMap::new(),
            attestations: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.advance_slot(3);
        let lane_id = state
            .lanes
            .values()
            .find(|lane| lane.kind == LaneKind::ContractCall)
            .map(|lane| lane.lane_id.clone())
            .unwrap_or_else(|| "lane-missing".to_string());
        let _ = state.submit_microbatch(SubmitMicrobatch {
            lane_id,
            sender_commitment: "demo-sender-commitment".to_string(),
            encrypted_payload_root: "demo-encrypted-payload-root".to_string(),
            ciphertext_commitment: "demo-ciphertext-commitment".to_string(),
            nullifier_root: "demo-nullifier-root".to_string(),
            max_fee_micro_units: 900,
            fee_cap_bps: 10,
            item_count: 12,
            byte_size: 16_384,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
        });
        state
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: value_root("config", &self.config.public_record()),
            committee_root: map_root("committees", &self.committees, Committee::public_record),
            member_root: map_root("members", &self.members, CommitteeMember::public_record),
            rotation_root: map_root(
                "rotations",
                &self.rotations,
                CommitteeRotation::public_record,
            ),
            lane_root: map_root("lanes", &self.lanes, PreconfirmationLane::public_record),
            microbatch_root: map_root(
                "microbatches",
                &self.microbatches,
                EncryptedMicrobatch::public_record,
            ),
            commitment_root: map_root(
                "commitments",
                &self.commitments,
                MicrobatchCommitment::public_record,
            ),
            attestation_root: map_root(
                "attestations",
                &self.attestations,
                PqSignerAttestation::public_record,
            ),
            preconfirmation_root: map_root(
                "preconfirmations",
                &self.preconfirmations,
                LowLatencyPreconfirmation::public_record,
            ),
            fee_cap_root: map_root("fee_caps", &self.fee_caps, FeeCap::public_record),
            quarantine_root: map_root(
                "quarantines",
                &self.quarantines,
                EquivocationQuarantine::public_record,
            ),
            public_record_root: map_root(
                "public_records",
                &self.public_records,
                PublicRecordEntry::public_record,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "encrypted_commitment_suite": ENCRYPTED_COMMITMENT_SUITE,
            "preconfirmation_lane_suite": PRECONFIRMATION_LANE_SUITE,
            "committee_rotation_suite": COMMITTEE_ROTATION_SUITE,
            "equivocation_quarantine_suite": EQUIVOCATION_QUARANTINE_SUITE,
            "chain_id": CHAIN_ID,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
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
        value_root("state", &self.public_record_without_state_root())
    }

    pub fn advance_slot(&mut self, slots: u64) {
        self.counters.slot = self.counters.slot.saturating_add(slots);
        if self.config.committee_epoch_slots > 0 {
            self.counters.epoch =
                DEVNET_EPOCH + self.counters.slot / self.config.committee_epoch_slots;
        }
        self.expire_microbatches();
        self.expire_quarantines();
    }

    pub fn register_committee(
        &mut self,
        kind: CommitteeKind,
        aggregate_pq_key_commitment: &str,
        transcript_root: &str,
        bonded_micro_units: u64,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(
            self.committees.len(),
            self.config.max_committees,
            "committees",
        )?;
        ensure_non_empty(aggregate_pq_key_commitment, "aggregate pq key commitment")?;
        ensure_non_empty(transcript_root, "committee transcript root")?;
        ensure_min(
            bonded_micro_units,
            self.config.min_committee_bond_micro_units,
            "committee bond",
        )?;
        let index = self.counters.next_committee_index;
        let committee_id = prefixed(
            "committee",
            "committee-id",
            &[
                HashPart::U64(index),
                HashPart::U64(self.counters.epoch),
                HashPart::Str(kind.as_str()),
                HashPart::Str(aggregate_pq_key_commitment),
            ],
        );
        let active_from_slot = self.counters.slot;
        let active_until_slot = active_from_slot.saturating_add(self.config.committee_epoch_slots);
        let committee = Committee {
            committee_id: committee_id.clone(),
            kind,
            status: CommitteeStatus::Registered,
            epoch: self.counters.epoch,
            active_from_slot,
            active_until_slot,
            threshold_weight_bps: self.config.quorum_weight_bps,
            fast_threshold_weight_bps: self.config.fast_quorum_weight_bps,
            supermajority_weight_bps: self.config.supermajority_weight_bps,
            bonded_micro_units,
            aggregate_pq_key_commitment: aggregate_pq_key_commitment.to_string(),
            transcript_root: transcript_root.to_string(),
            member_ids: BTreeSet::new(),
        };
        self.counters.next_committee_index = self.counters.next_committee_index.saturating_add(1);
        self.committees.insert(committee_id.clone(), committee);
        self.emit_record("committee_registered", &committee_id)?;
        Ok(committee_id)
    }

    pub fn register_member(
        &mut self,
        committee_id: &str,
        operator_commitment: &str,
        pq_signing_key_commitment: &str,
        pq_kem_key_commitment: &str,
        weight_bps: u64,
        bond_micro_units: u64,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(self.members.len(), self.config.max_members, "members")?;
        ensure_bps(weight_bps, "member weight")?;
        ensure_min(
            bond_micro_units,
            self.config.min_signer_bond_micro_units,
            "member bond",
        )?;
        ensure_non_empty(operator_commitment, "operator commitment")?;
        ensure_non_empty(pq_signing_key_commitment, "pq signing key commitment")?;
        ensure_non_empty(pq_kem_key_commitment, "pq kem key commitment")?;
        require(
            self.committees.contains_key(committee_id),
            "member committee missing",
        )?;
        let index = self.counters.next_member_index;
        let member_id = prefixed(
            "member",
            "member-id",
            &[
                HashPart::Str(committee_id),
                HashPart::U64(index),
                HashPart::Str(operator_commitment),
            ],
        );
        let view_tag_policy_root = value_root(
            "member-viewtag-policy",
            &json!({
                "member_id": member_id,
                "operator_commitment": operator_commitment,
                "privacy_floor": self.config.min_privacy_set_size,
            }),
        );
        let member = CommitteeMember {
            member_id: member_id.clone(),
            committee_id: committee_id.to_string(),
            status: MemberStatus::Active,
            operator_commitment: operator_commitment.to_string(),
            pq_signing_key_commitment: pq_signing_key_commitment.to_string(),
            pq_kem_key_commitment: pq_kem_key_commitment.to_string(),
            view_tag_policy_root,
            weight_bps,
            bond_micro_units,
            joined_epoch: self.counters.epoch,
            last_attested_slot: 0,
        };
        if let Some(committee) = self.committees.get_mut(committee_id) {
            committee.member_ids.insert(member_id.clone());
            if committee.status == CommitteeStatus::Registered {
                committee.status = CommitteeStatus::Active;
            }
        }
        self.counters.next_member_index = self.counters.next_member_index.saturating_add(1);
        self.members.insert(member_id.clone(), member);
        self.emit_record("member_registered", &member_id)?;
        Ok(member_id)
    }

    pub fn open_lane(
        &mut self,
        kind: LaneKind,
        committee_id: &str,
        max_microbatch_bytes: u64,
        max_items: u32,
        fee_cap_bps: u64,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        ensure_bps(fee_cap_bps, "lane fee cap")?;
        require(
            fee_cap_bps <= self.config.emergency_fee_cap_bps,
            "lane fee cap exceeds emergency cap",
        )?;
        require(
            max_microbatch_bytes > 0,
            "lane byte capacity must be non-zero",
        )?;
        require(max_items > 0, "lane item capacity must be non-zero")?;
        let committee = self
            .committees
            .get(committee_id)
            .ok_or_else(|| format!("unknown committee: {committee_id}"))?;
        require(committee.status.can_attest(), "committee cannot attest")?;
        let index = self.counters.next_lane_index;
        let lane_id = prefixed(
            "lane",
            "lane-id",
            &[
                HashPart::U64(index),
                HashPart::Str(committee_id),
                HashPart::Str(kind.as_str()),
            ],
        );
        let lane = PreconfirmationLane {
            lane_id: lane_id.clone(),
            kind,
            status: LaneStatus::Open,
            committee_id: committee_id.to_string(),
            priority_bps: kind.default_priority(),
            max_microbatch_bytes,
            max_items,
            target_latency_ms: self.config.target_preconfirmation_ms,
            fee_cap_bps,
            privacy_floor: self.config.min_privacy_set_size,
            pending_microbatch_ids: BTreeSet::new(),
        };
        self.counters.next_lane_index = self.counters.next_lane_index.saturating_add(1);
        self.lanes.insert(lane_id.clone(), lane);
        self.install_fee_cap(&lane_id, committee_id, fee_cap_bps, None)?;
        self.emit_record("lane_opened", &lane_id)?;
        Ok(lane_id)
    }

    pub fn submit_microbatch(
        &mut self,
        request: SubmitMicrobatch,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(
            self.microbatches.len(),
            self.config.max_microbatches,
            "microbatches",
        )?;
        ensure_non_empty(&request.sender_commitment, "sender commitment")?;
        ensure_non_empty(&request.encrypted_payload_root, "encrypted payload root")?;
        ensure_non_empty(&request.ciphertext_commitment, "ciphertext commitment")?;
        ensure_non_empty(&request.nullifier_root, "nullifier root")?;
        ensure_bps(request.fee_cap_bps, "microbatch fee cap")?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "microbatch privacy set below floor",
        )?;
        let (committee_id, lane_fee_cap, lane_max_bytes, lane_max_items) = {
            let lane = self
                .lanes
                .get(&request.lane_id)
                .ok_or_else(|| format!("unknown lane: {}", request.lane_id))?;
            require(
                lane.status.accepts_commitments(),
                "lane does not accept commitments",
            )?;
            (
                lane.committee_id.clone(),
                lane.fee_cap_bps,
                lane.max_microbatch_bytes,
                lane.max_items,
            )
        };
        require(
            request.byte_size <= lane_max_bytes,
            "microbatch byte size exceeds lane cap",
        )?;
        require(
            request.item_count <= lane_max_items,
            "microbatch item count exceeds lane cap",
        )?;
        if request.fee_cap_bps > lane_fee_cap || request.fee_cap_bps > self.config.max_user_fee_bps
        {
            self.counters.total_fee_cap_rejections =
                self.counters.total_fee_cap_rejections.saturating_add(1);
            return Err("microbatch fee cap exceeds lane or user cap".to_string());
        }
        let microbatch_id = prefixed(
            "microbatch",
            "microbatch-id",
            &[
                HashPart::U64(self.counters.next_microbatch_index),
                HashPart::Str(&request.lane_id),
                HashPart::Str(&request.sender_commitment),
                HashPart::Str(&request.encrypted_payload_root),
            ],
        );
        let public_commitment_root = value_root(
            "microbatch-public-commitment",
            &json!({
                "microbatch_id": microbatch_id,
                "lane_id": request.lane_id,
                "committee_id": committee_id,
                "ciphertext_commitment": request.ciphertext_commitment,
                "nullifier_root": request.nullifier_root,
                "fee_cap_bps": request.fee_cap_bps,
                "privacy_set_size": request.privacy_set_size,
            }),
        );
        let microbatch = EncryptedMicrobatch {
            microbatch_id: microbatch_id.clone(),
            lane_id: request.lane_id.clone(),
            committee_id: committee_id.clone(),
            status: MicrobatchStatus::Committed,
            slot: self.counters.slot,
            expires_slot: self
                .counters
                .slot
                .saturating_add(self.config.microbatch_ttl_slots),
            encrypted_payload_root: request.encrypted_payload_root,
            ciphertext_commitment: request.ciphertext_commitment,
            nullifier_root: request.nullifier_root,
            fee_asset_id: self.config.fee_asset_id.clone(),
            max_fee_micro_units: request.max_fee_micro_units,
            fee_cap_bps: request.fee_cap_bps,
            item_count: request.item_count,
            byte_size: request.byte_size,
            privacy_set_size: request.privacy_set_size,
            sender_commitment: request.sender_commitment,
            public_commitment_root,
        };
        self.counters.next_microbatch_index = self.counters.next_microbatch_index.saturating_add(1);
        self.counters.total_committed_microbatches =
            self.counters.total_committed_microbatches.saturating_add(1);
        self.microbatches.insert(microbatch_id.clone(), microbatch);
        if let Some(lane) = self.lanes.get_mut(&request.lane_id) {
            lane.pending_microbatch_ids.insert(microbatch_id.clone());
        }
        let commitment_id = self.commit_microbatch(&microbatch_id)?;
        self.emit_record("microbatch_submitted", &microbatch_id)?;
        self.emit_record("microbatch_commitment", &commitment_id)?;
        Ok(microbatch_id)
    }

    pub fn commit_microbatch(
        &mut self,
        microbatch_id: &str,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(
            self.commitments.len(),
            self.config.max_commitments,
            "commitments",
        )?;
        let microbatch = self
            .microbatches
            .get(microbatch_id)
            .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?
            .clone();
        let commitment_id = prefixed(
            "commitment",
            "commitment-id",
            &[
                HashPart::U64(self.counters.next_commitment_index),
                HashPart::Str(microbatch_id),
                HashPart::Str(&microbatch.public_commitment_root),
            ],
        );
        let encrypted_commitment_root = value_root(
            "encrypted-microbatch-commitment",
            &json!({
                "microbatch_id": microbatch.microbatch_id,
                "encrypted_payload_root": microbatch.encrypted_payload_root,
                "ciphertext_commitment": microbatch.ciphertext_commitment,
                "suite": ENCRYPTED_COMMITMENT_SUITE,
            }),
        );
        let availability_root = value_root(
            "microbatch-availability",
            &json!({
                "microbatch_id": microbatch.microbatch_id,
                "byte_size": microbatch.byte_size,
                "item_count": microbatch.item_count,
                "slot": microbatch.slot,
            }),
        );
        let opening_hint_root = value_root(
            "microbatch-opening-hint",
            &json!({
                "microbatch_id": microbatch.microbatch_id,
                "committee_id": microbatch.committee_id,
                "privacy_set_size": microbatch.privacy_set_size,
            }),
        );
        let deterministic_public_root = value_root(
            "microbatch-deterministic-public",
            &json!({
                "microbatch_id": microbatch.microbatch_id,
                "lane_id": microbatch.lane_id,
                "committee_id": microbatch.committee_id,
                "nullifier_root": microbatch.nullifier_root,
                "public_commitment_root": microbatch.public_commitment_root,
            }),
        );
        let commitment = MicrobatchCommitment {
            commitment_id: commitment_id.clone(),
            microbatch_id: microbatch_id.to_string(),
            committee_id: microbatch.committee_id,
            lane_id: microbatch.lane_id,
            slot: self.counters.slot,
            encrypted_commitment_root,
            availability_root,
            opening_hint_root,
            deterministic_public_root,
        };
        self.counters.next_commitment_index = self.counters.next_commitment_index.saturating_add(1);
        self.commitments.insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn attest_microbatch(
        &mut self,
        microbatch_id: &str,
        member_id: &str,
        verdict: AttestationVerdict,
        observed_latency_ms: u64,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        let microbatch = self
            .microbatches
            .get(microbatch_id)
            .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?
            .clone();
        require(microbatch.status.live(), "microbatch is not live")?;
        let member = self
            .members
            .get(member_id)
            .ok_or_else(|| format!("unknown member: {member_id}"))?
            .clone();
        require(member.status.contributes_weight(), "member cannot attest")?;
        require(
            member.committee_id == microbatch.committee_id,
            "member committee mismatch",
        )?;
        let commitment = self
            .commitments
            .values()
            .find(|commitment| commitment.microbatch_id == microbatch_id)
            .ok_or_else(|| format!("missing commitment for microbatch: {microbatch_id}"))?
            .clone();
        let attestation_id = prefixed(
            "attestation",
            "attestation-id",
            &[
                HashPart::U64(self.counters.next_attestation_index),
                HashPart::Str(microbatch_id),
                HashPart::Str(member_id),
                HashPart::Str(verdict.as_str()),
            ],
        );
        let transcript_root = value_root(
            "attestation-transcript",
            &json!({
                "attestation_id": attestation_id,
                "microbatch_id": microbatch_id,
                "member_id": member_id,
                "commitment_id": commitment.commitment_id,
                "verdict": verdict.as_str(),
            }),
        );
        let pq_signature_root = value_root(
            "attestation-pq-signature",
            &json!({
                "suite": PQ_ATTESTATION_SUITE,
                "member_id": member_id,
                "transcript_root": transcript_root,
                "signing_key_commitment": member.pq_signing_key_commitment,
            }),
        );
        let attestation = PqSignerAttestation {
            attestation_id: attestation_id.clone(),
            microbatch_id: microbatch_id.to_string(),
            commitment_id: commitment.commitment_id,
            committee_id: microbatch.committee_id.clone(),
            member_id: member_id.to_string(),
            slot: self.counters.slot,
            verdict,
            signer_weight_bps: member.weight_bps,
            observed_latency_ms,
            pq_signature_root,
            transcript_root,
        };
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(member) = self.members.get_mut(member_id) {
            member.last_attested_slot = self.counters.slot;
        }
        if let Some(microbatch) = self.microbatches.get_mut(microbatch_id) {
            microbatch.status = MicrobatchStatus::Attesting;
        }
        self.maybe_preconfirm(microbatch_id)?;
        self.emit_record("pq_signer_attestation", &attestation_id)?;
        Ok(attestation_id)
    }

    pub fn propose_rotation(
        &mut self,
        from_committee_id: &str,
        to_committee_id: &str,
        entropy_root: &str,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(self.rotations.len(), self.config.max_rotations, "rotations")?;
        ensure_non_empty(entropy_root, "rotation entropy root")?;
        require(
            self.committees.contains_key(from_committee_id),
            "rotation source committee missing",
        )?;
        require(
            self.committees.contains_key(to_committee_id),
            "rotation target committee missing",
        )?;
        let rotation_id = prefixed(
            "rotation",
            "rotation-id",
            &[
                HashPart::U64(self.counters.next_rotation_index),
                HashPart::Str(from_committee_id),
                HashPart::Str(to_committee_id),
                HashPart::Str(entropy_root),
            ],
        );
        let overlap_start_slot = self.counters.slot;
        let overlap_end_slot =
            overlap_start_slot.saturating_add(self.config.rotation_overlap_slots);
        let handoff_record_root = value_root(
            "committee-rotation-handoff",
            &json!({
                "rotation_id": rotation_id,
                "from_committee_id": from_committee_id,
                "to_committee_id": to_committee_id,
                "overlap_start_slot": overlap_start_slot,
                "overlap_end_slot": overlap_end_slot,
            }),
        );
        let rotation = CommitteeRotation {
            rotation_id: rotation_id.clone(),
            status: RotationStatus::Proposed,
            from_committee_id: from_committee_id.to_string(),
            to_committee_id: to_committee_id.to_string(),
            proposed_slot: self.counters.slot,
            overlap_start_slot,
            overlap_end_slot,
            entropy_root: entropy_root.to_string(),
            handoff_record_root,
        };
        self.counters.next_rotation_index = self.counters.next_rotation_index.saturating_add(1);
        self.rotations.insert(rotation_id.clone(), rotation);
        if let Some(committee) = self.committees.get_mut(from_committee_id) {
            committee.status = CommitteeStatus::RotatingOut;
        }
        if let Some(committee) = self.committees.get_mut(to_committee_id) {
            committee.status = CommitteeStatus::RotatingIn;
        }
        self.emit_record("committee_rotation_proposed", &rotation_id)?;
        Ok(rotation_id)
    }

    pub fn finalize_rotation(
        &mut self,
        rotation_id: &str,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
        let (from_committee_id, to_committee_id) = {
            let rotation = self
                .rotations
                .get_mut(rotation_id)
                .ok_or_else(|| format!("unknown rotation: {rotation_id}"))?;
            rotation.status = RotationStatus::Finalized;
            (
                rotation.from_committee_id.clone(),
                rotation.to_committee_id.clone(),
            )
        };
        if let Some(committee) = self.committees.get_mut(&from_committee_id) {
            committee.status = CommitteeStatus::Retired;
        }
        if let Some(committee) = self.committees.get_mut(&to_committee_id) {
            committee.status = CommitteeStatus::Active;
        }
        for lane in self.lanes.values_mut() {
            if lane.committee_id == from_committee_id {
                lane.committee_id = to_committee_id.clone();
            }
        }
        self.counters.total_rotations_finalized =
            self.counters.total_rotations_finalized.saturating_add(1);
        self.emit_record("committee_rotation_finalized", rotation_id)?;
        Ok(())
    }

    pub fn open_equivocation_quarantine(
        &mut self,
        committee_id: &str,
        member_id: Option<String>,
        microbatch_id: Option<String>,
        first_commitment_root: &str,
        conflicting_commitment_root: &str,
        evidence_root: &str,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(
            self.quarantines.len(),
            self.config.max_quarantines,
            "quarantines",
        )?;
        ensure_non_empty(first_commitment_root, "first commitment root")?;
        ensure_non_empty(conflicting_commitment_root, "conflicting commitment root")?;
        ensure_non_empty(evidence_root, "equivocation evidence root")?;
        require(
            self.committees.contains_key(committee_id),
            "quarantine committee missing",
        )?;
        let quarantine_id = prefixed(
            "quarantine",
            "quarantine-id",
            &[
                HashPart::U64(self.counters.next_quarantine_index),
                HashPart::Str(committee_id),
                HashPart::Str(first_commitment_root),
                HashPart::Str(conflicting_commitment_root),
            ],
        );
        let quarantine = EquivocationQuarantine {
            quarantine_id: quarantine_id.clone(),
            status: QuarantineStatus::EvidenceLocked,
            committee_id: committee_id.to_string(),
            member_id: member_id.clone(),
            microbatch_id: microbatch_id.clone(),
            first_commitment_root: first_commitment_root.to_string(),
            conflicting_commitment_root: conflicting_commitment_root.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_slot: self.counters.slot,
            expires_slot: self
                .counters
                .slot
                .saturating_add(self.config.quarantine_ttl_slots),
            slash_bps: self.config.slash_bps,
        };
        if let Some(committee) = self.committees.get_mut(committee_id) {
            committee.status = CommitteeStatus::Quarantined;
        }
        if let Some(member_id) = member_id {
            if let Some(member) = self.members.get_mut(&member_id) {
                member.status = MemberStatus::Quarantined;
            }
        }
        if let Some(microbatch_id) = microbatch_id {
            if let Some(microbatch) = self.microbatches.get_mut(&microbatch_id) {
                microbatch.status = MicrobatchStatus::Quarantined;
            }
        }
        self.counters.next_quarantine_index = self.counters.next_quarantine_index.saturating_add(1);
        self.counters.total_quarantined_microbatches = self
            .counters
            .total_quarantined_microbatches
            .saturating_add(1);
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        self.emit_record("equivocation_quarantine_opened", &quarantine_id)?;
        Ok(quarantine_id)
    }

    fn install_fee_cap(
        &mut self,
        lane_id: &str,
        committee_id: &str,
        cap_bps: u64,
        sponsor_commitment: Option<String>,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<String> {
        ensure_capacity(self.fee_caps.len(), self.config.max_fee_caps, "fee caps")?;
        let fee_cap_id = prefixed(
            "fee-cap",
            "fee-cap-id",
            &[
                HashPart::U64(self.counters.next_fee_cap_index),
                HashPart::Str(lane_id),
                HashPart::Str(committee_id),
                HashPart::U64(cap_bps),
            ],
        );
        let fee_cap = FeeCap {
            fee_cap_id: fee_cap_id.clone(),
            lane_id: lane_id.to_string(),
            committee_id: committee_id.to_string(),
            cap_bps,
            emergency_cap_bps: self.config.emergency_fee_cap_bps,
            fee_asset_id: self.config.fee_asset_id.clone(),
            valid_from_slot: self.counters.slot,
            valid_until_slot: self
                .counters
                .slot
                .saturating_add(self.config.committee_epoch_slots),
            sponsor_commitment,
        };
        self.counters.next_fee_cap_index = self.counters.next_fee_cap_index.saturating_add(1);
        self.fee_caps.insert(fee_cap_id.clone(), fee_cap);
        Ok(fee_cap_id)
    }

    fn maybe_preconfirm(
        &mut self,
        microbatch_id: &str,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
        let microbatch = self
            .microbatches
            .get(microbatch_id)
            .ok_or_else(|| format!("unknown microbatch: {microbatch_id}"))?
            .clone();
        let included_weight = self
            .attestations
            .values()
            .filter(|attestation| {
                attestation.microbatch_id == microbatch_id
                    && attestation.verdict.contributes_to_quorum()
            })
            .map(|attestation| attestation.signer_weight_bps)
            .fold(0_u64, u64::saturating_add);
        if included_weight < self.config.quorum_weight_bps {
            return Ok(());
        }
        if self
            .preconfirmations
            .values()
            .any(|preconfirmation| preconfirmation.microbatch_id == microbatch_id)
        {
            return Ok(());
        }
        ensure_capacity(
            self.preconfirmations.len(),
            self.config.max_preconfirmations,
            "preconfirmations",
        )?;
        let commitment = self
            .commitments
            .values()
            .find(|commitment| commitment.microbatch_id == microbatch_id)
            .ok_or_else(|| format!("missing commitment for microbatch: {microbatch_id}"))?
            .clone();
        let preconfirmation_id = prefixed(
            "preconfirmation",
            "preconfirmation-id",
            &[
                HashPart::U64(self.counters.next_preconfirmation_index),
                HashPart::Str(microbatch_id),
                HashPart::Str(&commitment.commitment_id),
            ],
        );
        let attestation_root = self.attestation_root_for_microbatch(microbatch_id);
        let public_receipt_root = value_root(
            "low-latency-preconfirmation-receipt",
            &json!({
                "preconfirmation_id": preconfirmation_id,
                "microbatch_id": microbatch_id,
                "commitment_id": commitment.commitment_id,
                "lane_id": microbatch.lane_id,
                "committee_id": microbatch.committee_id,
                "attestation_root": attestation_root,
                "included_weight_bps": included_weight,
            }),
        );
        let status = if included_weight >= self.config.fast_quorum_weight_bps {
            PreconfirmationStatus::FastQuorum
        } else {
            PreconfirmationStatus::Signed
        };
        let latency_ms = self
            .counters
            .slot
            .saturating_sub(microbatch.slot)
            .saturating_mul(self.config.slot_width_ms);
        let preconfirmation = LowLatencyPreconfirmation {
            preconfirmation_id: preconfirmation_id.clone(),
            microbatch_id: microbatch_id.to_string(),
            commitment_id: commitment.commitment_id,
            lane_id: microbatch.lane_id.clone(),
            committee_id: microbatch.committee_id,
            status,
            slot: self.counters.slot,
            quorum_weight_bps: included_weight,
            fast_quorum_weight_bps: self.config.fast_quorum_weight_bps,
            attestation_root,
            public_receipt_root,
            latency_ms,
        };
        self.counters.next_preconfirmation_index =
            self.counters.next_preconfirmation_index.saturating_add(1);
        self.counters.total_preconfirmed_microbatches = self
            .counters
            .total_preconfirmed_microbatches
            .saturating_add(1);
        self.preconfirmations
            .insert(preconfirmation_id.clone(), preconfirmation);
        if let Some(microbatch) = self.microbatches.get_mut(microbatch_id) {
            microbatch.status = MicrobatchStatus::Preconfirmed;
        }
        if let Some(lane) = self.lanes.get_mut(&microbatch.lane_id) {
            lane.pending_microbatch_ids.remove(microbatch_id);
        }
        self.emit_record("low_latency_preconfirmation", &preconfirmation_id)?;
        Ok(())
    }

    fn attestation_root_for_microbatch(&self, microbatch_id: &str) -> String {
        let leaves = self
            .attestations
            .values()
            .filter(|attestation| attestation.microbatch_id == microbatch_id)
            .map(PqSignerAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root_for("microbatch-attestations", &leaves)
    }

    fn emit_record(
        &mut self,
        kind: &str,
        subject_id: &str,
    ) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
        ensure_capacity(
            self.public_records.len(),
            self.config.max_public_records,
            "public records",
        )?;
        let public_root = self.subject_public_root(kind, subject_id);
        let record_id = prefixed(
            "record",
            "public-record-id",
            &[
                HashPart::U64(self.counters.next_public_record_index),
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::Str(&public_root),
            ],
        );
        let entry = PublicRecordEntry {
            record_id: record_id.clone(),
            slot: self.counters.slot,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            public_root,
        };
        self.counters.next_public_record_index =
            self.counters.next_public_record_index.saturating_add(1);
        self.public_records.insert(record_id, entry);
        Ok(())
    }

    fn subject_public_root(&self, kind: &str, subject_id: &str) -> String {
        let value = self
            .committees
            .get(subject_id)
            .map(Committee::public_record)
            .or_else(|| {
                self.members
                    .get(subject_id)
                    .map(CommitteeMember::public_record)
            })
            .or_else(|| {
                self.rotations
                    .get(subject_id)
                    .map(CommitteeRotation::public_record)
            })
            .or_else(|| {
                self.lanes
                    .get(subject_id)
                    .map(PreconfirmationLane::public_record)
            })
            .or_else(|| {
                self.microbatches
                    .get(subject_id)
                    .map(EncryptedMicrobatch::public_record)
            })
            .or_else(|| {
                self.commitments
                    .get(subject_id)
                    .map(MicrobatchCommitment::public_record)
            })
            .or_else(|| {
                self.attestations
                    .get(subject_id)
                    .map(PqSignerAttestation::public_record)
            })
            .or_else(|| {
                self.preconfirmations
                    .get(subject_id)
                    .map(LowLatencyPreconfirmation::public_record)
            })
            .or_else(|| self.fee_caps.get(subject_id).map(FeeCap::public_record))
            .or_else(|| {
                self.quarantines
                    .get(subject_id)
                    .map(EquivocationQuarantine::public_record)
            })
            .unwrap_or_else(|| json!({"kind": kind, "subject_id": subject_id}));
        value_root(
            "subject-public-record",
            &json!({"kind": kind, "record": value}),
        )
    }

    fn expire_microbatches(&mut self) {
        for microbatch in self.microbatches.values_mut() {
            if microbatch.status.live() && self.counters.slot > microbatch.expires_slot {
                microbatch.status = MicrobatchStatus::Expired;
            }
        }
        for preconfirmation in self.preconfirmations.values_mut() {
            if matches!(
                preconfirmation.status,
                PreconfirmationStatus::Draft
                    | PreconfirmationStatus::Signed
                    | PreconfirmationStatus::FastQuorum
                    | PreconfirmationStatus::Published
            ) && self.counters.slot
                > preconfirmation
                    .slot
                    .saturating_add(self.config.attestation_ttl_slots)
            {
                preconfirmation.status = PreconfirmationStatus::Expired;
            }
        }
    }

    fn expire_quarantines(&mut self) {
        for quarantine in self.quarantines.values_mut() {
            if !matches!(
                quarantine.status,
                QuarantineStatus::Released | QuarantineStatus::Slashed
            ) && self.counters.slot > quarantine.expires_slot
            {
                quarantine.status = QuarantineStatus::Expired;
            }
        }
    }

    fn seed_devnet(&mut self) {
        let primary = match self.register_committee(
            CommitteeKind::FastConfidentialSwap,
            "devnet-primary-aggregate-pq-key",
            "devnet-primary-transcript-root",
            self.config.min_committee_bond_micro_units.saturating_mul(2),
        ) {
            Ok(value) => value,
            Err(_) => return,
        };
        let secondary = match self.register_committee(
            CommitteeKind::ContractCall,
            "devnet-secondary-aggregate-pq-key",
            "devnet-secondary-transcript-root",
            self.config.min_committee_bond_micro_units.saturating_mul(2),
        ) {
            Ok(value) => value,
            Err(_) => return,
        };
        for index in 0..4 {
            let _ = self.register_member(
                &primary,
                &format!("devnet-primary-operator-{index}"),
                &format!("devnet-primary-pq-signing-key-{index}"),
                &format!("devnet-primary-pq-kem-key-{index}"),
                2_500,
                self.config.min_signer_bond_micro_units,
            );
            let _ = self.register_member(
                &secondary,
                &format!("devnet-secondary-operator-{index}"),
                &format!("devnet-secondary-pq-signing-key-{index}"),
                &format!("devnet-secondary-pq-kem-key-{index}"),
                2_500,
                self.config.min_signer_bond_micro_units,
            );
        }
        let swap_lane = match self.open_lane(LaneKind::Swap, &primary, 1_048_576, 512, 10) {
            Ok(value) => value,
            Err(_) => return,
        };
        let contract_lane =
            match self.open_lane(LaneKind::ContractCall, &secondary, 786_432, 256, 12) {
                Ok(value) => value,
                Err(_) => return,
            };
        let _ = self.submit_microbatch(SubmitMicrobatch {
            lane_id: swap_lane.clone(),
            sender_commitment: "devnet-swap-sender-commitment".to_string(),
            encrypted_payload_root: "devnet-swap-encrypted-payload-root".to_string(),
            ciphertext_commitment: "devnet-swap-ciphertext-commitment".to_string(),
            nullifier_root: "devnet-swap-nullifier-root".to_string(),
            max_fee_micro_units: 640,
            fee_cap_bps: 8,
            item_count: 64,
            byte_size: 65_536,
            privacy_set_size: self.config.min_privacy_set_size.saturating_mul(2),
        });
        let _ = self.submit_microbatch(SubmitMicrobatch {
            lane_id: contract_lane,
            sender_commitment: "devnet-contract-sender-commitment".to_string(),
            encrypted_payload_root: "devnet-contract-encrypted-payload-root".to_string(),
            ciphertext_commitment: "devnet-contract-ciphertext-commitment".to_string(),
            nullifier_root: "devnet-contract-nullifier-root".to_string(),
            max_fee_micro_units: 720,
            fee_cap_bps: 10,
            item_count: 24,
            byte_size: 32_768,
            privacy_set_size: self.config.min_privacy_set_size.saturating_mul(2),
        });
        let members = self
            .members
            .values()
            .filter(|member| member.committee_id == primary)
            .map(|member| member.member_id.clone())
            .collect::<Vec<_>>();
        let microbatch = self
            .microbatches
            .values()
            .find(|microbatch| microbatch.lane_id == swap_lane)
            .map(|microbatch| microbatch.microbatch_id.clone());
        if let Some(microbatch_id) = microbatch {
            for member_id in members.iter().take(3) {
                let _ = self.attest_microbatch(
                    &microbatch_id,
                    member_id,
                    AttestationVerdict::Include,
                    80,
                );
            }
        }
        let _ = self.propose_rotation(
            &primary,
            &secondary,
            "devnet-rotation-entropy-root-from-monero-headers",
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitMicrobatch {
    pub lane_id: String,
    pub sender_commitment: String,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub nullifier_root: String,
    pub max_fee_micro_units: u64,
    pub fee_cap_bps: u64,
    pub item_count: u32,
    pub byte_size: u64,
    pub privacy_set_size: u64,
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut full_parts = Vec::with_capacity(parts.len().saturating_add(1));
    full_parts.push(HashPart::Str(CHAIN_ID));
    for part in parts {
        full_parts.push(hash_part_ref(part));
    }
    domain_hash(
        &format!("private-l2-fast-pq-confidential-microbatch-committee-runtime:{domain}"),
        &full_parts,
        32,
    )
}

fn prefixed(prefix: &str, domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{prefix}-{}", deterministic_id(domain, parts))
}

fn hash_part_ref<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("private-l2-fast-pq-confidential-microbatch-committee-runtime:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map.values().map(record_fn).collect::<Vec<_>>();
    merkle_root_for(domain, &leaves)
}

fn merkle_root_for(domain: &str, leaves: &[Value]) -> String {
    merkle_root(
        &format!("private-l2-fast-pq-confidential-microbatch-committee-runtime:{domain}"),
        leaves,
    )
}

fn values_for_ids(ids: &BTreeSet<String>) -> Vec<Value> {
    ids.iter().map(|id| json!(id)).collect()
}

fn ensure_non_empty(
    value: &str,
    label: &str,
) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("microbatch committee {label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(
    value: u64,
    label: &str,
) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
    if value <= MAX_BPS {
        Ok(())
    } else {
        Err(format!("microbatch committee {label} exceeds BPS range"))
    }
}

fn ensure_capacity(
    len: usize,
    cap: usize,
    label: &str,
) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
    if len < cap {
        Ok(())
    } else {
        Err(format!("microbatch committee {label} capacity reached"))
    }
}

fn ensure_min(
    value: u64,
    min: u64,
    label: &str,
) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
    if value >= min {
        Ok(())
    } else {
        Err(format!("microbatch committee {label} below minimum"))
    }
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2FastPqConfidentialMicrobatchCommitteeRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(format!("microbatch committee {message}"))
    }
}
