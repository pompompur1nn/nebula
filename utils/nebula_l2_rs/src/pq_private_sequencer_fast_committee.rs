use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqPrivateSequencerFastCommitteeResult<T> = Result<T, String>;

pub const PQ_PRIVATE_SEQUENCER_FAST_COMMITTEE_PROTOCOL_VERSION: &str =
    "nebula-pq-private-sequencer-fast-committee-v1";

const PROTOCOL_ID: &str = "pq-private-sequencer-fast-committee";
const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-aggregate";
const PQ_MEMBER_ATTESTATION_SUITE: &str = "ML-DSA-65-membership-attestation-v1";
const PQ_BACKUP_SIGNATURE_SUITE: &str = "SLH-DSA-SHAKE-256f";
const PQ_KEM_SUITE: &str = "ML-KEM-1024";
const PRIVATE_LEADER_COMMITMENT_SUITE: &str = "vrf-like-private-leader-commitment-v1";
const FAST_QC_SUITE: &str = "fast-threshold-quorum-certificate-v1";
const AVAILABILITY_VOTE_SUITE: &str = "privacy-preserving-availability-vote-v1";
const FINALITY_RECEIPT_SUITE: &str = "low-latency-finality-receipt-v1";
const SLASHING_EVIDENCE_SUITE: &str = "private-fast-sequencer-slashing-evidence-v1";
const DEVNET_HEIGHT: u64 = 42_240;
const DEFAULT_EPOCH_BLOCKS: u64 = 160;
const DEFAULT_ROTATION_OVERLAP_BLOCKS: u64 = 24;
const DEFAULT_LEADER_LOOKAHEAD_SLOTS: u64 = 8;
const DEFAULT_FAST_SLOT_MS: u64 = 450;
const DEFAULT_QC_DEADLINE_MS: u64 = 900;
const DEFAULT_AVAILABILITY_DEADLINE_MS: u64 = 1_200;
const DEFAULT_FINALITY_RECEIPT_TTL_BLOCKS: u64 = 12;
const DEFAULT_MEMBER_ATTESTATION_TTL_BLOCKS: u64 = 320;
const DEFAULT_FAST_QUORUM_BPS: u64 = 6_700;
const DEFAULT_AVAILABILITY_QUORUM_BPS: u64 = 7_500;
const DEFAULT_EMERGENCY_QUORUM_BPS: u64 = 8_500;
const DEFAULT_PRIVACY_QUORUM_BPS: u64 = 8_000;
const DEFAULT_MIN_SECURITY_BITS: u64 = 256;
const DEFAULT_MAX_BATCH_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_MAX_PRIVATE_PAYLOAD_BYTES: u64 = 512 * 1024;
const DEFAULT_MAX_RECEIPTS_PER_EPOCH: u64 = 4_096;
const DEFAULT_MAX_EVIDENCE_PER_EPOCH: u64 = 256;
const DEFAULT_BASE_BOND_MICRO_UNITS: u64 = 2_500_000;
const DEFAULT_SLASH_BPS: u64 = 2_500;
const DEFAULT_FAST_FEE_MICRO_UNITS: u64 = 3;
const MAX_BPS: u64 = 10_000;
const MAX_MEMBERS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Sequencer,
    AvailabilityWitness,
    FinalitySigner,
    PrivacyAuditor,
    SlashingGuardian,
    RotationCoordinator,
    EmergencyFallback,
}

impl MemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::AvailabilityWitness => "availability_witness",
            Self::FinalitySigner => "finality_signer",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::SlashingGuardian => "slashing_guardian",
            Self::RotationCoordinator => "rotation_coordinator",
            Self::EmergencyFallback => "emergency_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Pending,
    Active,
    Standby,
    Muted,
    Jailed,
    Retiring,
    Retired,
    Slashed,
}

impl MemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Muted => "muted",
            Self::Jailed => "jailed",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_vote(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Muted)
    }

    pub fn slashable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Standby | Self::Muted | Self::Jailed | Self::Retiring
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Scheduled,
    Warming,
    Active,
    Overlap,
    Draining,
    Retired,
    Emergency,
}

impl EpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Warming => "warming",
            Self::Active => "active",
            Self::Overlap => "overlap",
            Self::Draining => "draining",
            Self::Retired => "retired",
            Self::Emergency => "emergency",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Warming | Self::Active | Self::Overlap | Self::Emergency
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Draft,
    Published,
    Accepted,
    Rotated,
    Challenged,
    Revoked,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Accepted => "accepted",
            Self::Rotated => "rotated",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Published | Self::Accepted | Self::Rotated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderCommitmentStatus {
    Hidden,
    Precommitted,
    Revealed,
    Consumed,
    Skipped,
    Challenged,
    Expired,
}

impl LeaderCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Precommitted => "precommitted",
            Self::Revealed => "revealed",
            Self::Consumed => "consumed",
            Self::Skipped => "skipped",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastQcStatus {
    Proposed,
    GatheringVotes,
    Certified,
    FinalityLinked,
    Disputed,
    Superseded,
    Expired,
}

impl FastQcStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::GatheringVotes => "gathering_votes",
            Self::Certified => "certified",
            Self::FinalityLinked => "finality_linked",
            Self::Disputed => "disputed",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Certified | Self::FinalityLinked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityVoteStatus {
    Prepared,
    Committed,
    Aggregated,
    Withheld,
    Redacted,
    Challenged,
    Expired,
}

impl AvailabilityVoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::Aggregated => "aggregated",
            Self::Withheld => "withheld",
            Self::Redacted => "redacted",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Committed | Self::Aggregated | Self::Redacted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityReceiptStatus {
    Prepared,
    Broadcast,
    Anchored,
    Settled,
    Challenged,
    Revoked,
    Expired,
}

impl FinalityReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Broadcast => "broadcast",
            Self::Anchored => "anchored",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_final(self) -> bool {
        matches!(self, Self::Anchored | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    DoubleLeaderReveal,
    ConflictingFastQc,
    InvalidPqAttestation,
    AvailabilityWithholding,
    PrivacyBudgetLeak,
    LateFinalityReceipt,
    RotationKeyReuse,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleLeaderReveal => "double_leader_reveal",
            Self::ConflictingFastQc => "conflicting_fast_qc",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::AvailabilityWithholding => "availability_withholding",
            Self::PrivacyBudgetLeak => "privacy_budget_leak",
            Self::LateFinalityReceipt => "late_finality_receipt",
            Self::RotationKeyReuse => "rotation_key_reuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceStatus {
    Submitted,
    UnderReview,
    Sustained,
    Dismissed,
    Quarantined,
    PaidOut,
    Expired,
}

impl SlashingEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::UnderReview => "under_review",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Quarantined => "quarantined",
            Self::PaidOut => "paid_out",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::UnderReview | Self::Quarantined
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_id: String,
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub settlement_asset_id: String,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub pq_member_attestation_suite: String,
    pub pq_backup_signature_suite: String,
    pub pq_kem_suite: String,
    pub private_leader_commitment_suite: String,
    pub fast_qc_suite: String,
    pub availability_vote_suite: String,
    pub finality_receipt_suite: String,
    pub slashing_evidence_suite: String,
    pub epoch_blocks: u64,
    pub rotation_overlap_blocks: u64,
    pub leader_lookahead_slots: u64,
    pub fast_slot_ms: u64,
    pub qc_deadline_ms: u64,
    pub availability_deadline_ms: u64,
    pub finality_receipt_ttl_blocks: u64,
    pub member_attestation_ttl_blocks: u64,
    pub fast_quorum_bps: u64,
    pub availability_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub privacy_quorum_bps: u64,
    pub min_security_bits: u64,
    pub max_batch_bytes: u64,
    pub max_private_payload_bytes: u64,
    pub max_receipts_per_epoch: u64,
    pub max_evidence_per_epoch: u64,
    pub base_bond_micro_units: u64,
    pub slash_bps: u64,
    pub fast_fee_micro_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_id: PROTOCOL_ID.to_string(),
            protocol_version: PQ_PRIVATE_SEQUENCER_FAST_COMMITTEE_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: "stagenet".to_string(),
            settlement_asset_id: "dxmr".to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            pq_member_attestation_suite: PQ_MEMBER_ATTESTATION_SUITE.to_string(),
            pq_backup_signature_suite: PQ_BACKUP_SIGNATURE_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            private_leader_commitment_suite: PRIVATE_LEADER_COMMITMENT_SUITE.to_string(),
            fast_qc_suite: FAST_QC_SUITE.to_string(),
            availability_vote_suite: AVAILABILITY_VOTE_SUITE.to_string(),
            finality_receipt_suite: FINALITY_RECEIPT_SUITE.to_string(),
            slashing_evidence_suite: SLASHING_EVIDENCE_SUITE.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            rotation_overlap_blocks: DEFAULT_ROTATION_OVERLAP_BLOCKS,
            leader_lookahead_slots: DEFAULT_LEADER_LOOKAHEAD_SLOTS,
            fast_slot_ms: DEFAULT_FAST_SLOT_MS,
            qc_deadline_ms: DEFAULT_QC_DEADLINE_MS,
            availability_deadline_ms: DEFAULT_AVAILABILITY_DEADLINE_MS,
            finality_receipt_ttl_blocks: DEFAULT_FINALITY_RECEIPT_TTL_BLOCKS,
            member_attestation_ttl_blocks: DEFAULT_MEMBER_ATTESTATION_TTL_BLOCKS,
            fast_quorum_bps: DEFAULT_FAST_QUORUM_BPS,
            availability_quorum_bps: DEFAULT_AVAILABILITY_QUORUM_BPS,
            emergency_quorum_bps: DEFAULT_EMERGENCY_QUORUM_BPS,
            privacy_quorum_bps: DEFAULT_PRIVACY_QUORUM_BPS,
            min_security_bits: DEFAULT_MIN_SECURITY_BITS,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_private_payload_bytes: DEFAULT_MAX_PRIVATE_PAYLOAD_BYTES,
            max_receipts_per_epoch: DEFAULT_MAX_RECEIPTS_PER_EPOCH,
            max_evidence_per_epoch: DEFAULT_MAX_EVIDENCE_PER_EPOCH,
            base_bond_micro_units: DEFAULT_BASE_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            fast_fee_micro_units: DEFAULT_FAST_FEE_MICRO_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_id": self.protocol_id,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "settlement_asset_id": self.settlement_asset_id,
            "hash_suite": self.hash_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "pq_member_attestation_suite": self.pq_member_attestation_suite,
            "pq_backup_signature_suite": self.pq_backup_signature_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "private_leader_commitment_suite": self.private_leader_commitment_suite,
            "fast_qc_suite": self.fast_qc_suite,
            "availability_vote_suite": self.availability_vote_suite,
            "finality_receipt_suite": self.finality_receipt_suite,
            "slashing_evidence_suite": self.slashing_evidence_suite,
            "epoch_blocks": self.epoch_blocks,
            "rotation_overlap_blocks": self.rotation_overlap_blocks,
            "leader_lookahead_slots": self.leader_lookahead_slots,
            "fast_slot_ms": self.fast_slot_ms,
            "qc_deadline_ms": self.qc_deadline_ms,
            "availability_deadline_ms": self.availability_deadline_ms,
            "finality_receipt_ttl_blocks": self.finality_receipt_ttl_blocks,
            "member_attestation_ttl_blocks": self.member_attestation_ttl_blocks,
            "fast_quorum_bps": self.fast_quorum_bps,
            "availability_quorum_bps": self.availability_quorum_bps,
            "emergency_quorum_bps": self.emergency_quorum_bps,
            "privacy_quorum_bps": self.privacy_quorum_bps,
            "min_security_bits": self.min_security_bits,
            "max_batch_bytes": self.max_batch_bytes,
            "max_private_payload_bytes": self.max_private_payload_bytes,
            "max_receipts_per_epoch": self.max_receipts_per_epoch,
            "max_evidence_per_epoch": self.max_evidence_per_epoch,
            "base_bond_micro_units": self.base_bond_micro_units,
            "slash_bps": self.slash_bps,
            "fast_fee_micro_units": self.fast_fee_micro_units,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.protocol_version != PQ_PRIVATE_SEQUENCER_FAST_COMMITTEE_PROTOCOL_VERSION {
            return Err("unsupported protocol version".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("config chain id does not match crate chain id".to_string());
        }
        if self.epoch_blocks == 0 {
            return Err("epoch_blocks must be positive".to_string());
        }
        if self.rotation_overlap_blocks >= self.epoch_blocks {
            return Err("rotation overlap must be shorter than epoch".to_string());
        }
        if self.fast_slot_ms == 0 || self.qc_deadline_ms == 0 || self.availability_deadline_ms == 0
        {
            return Err("latency deadlines must be positive".to_string());
        }
        for (name, value) in [
            ("fast_quorum_bps", self.fast_quorum_bps),
            ("availability_quorum_bps", self.availability_quorum_bps),
            ("emergency_quorum_bps", self.emergency_quorum_bps),
            ("privacy_quorum_bps", self.privacy_quorum_bps),
            ("slash_bps", self.slash_bps),
        ] {
            if value == 0 || value > MAX_BPS {
                return Err(format!("{name} must be within 1..=10000"));
            }
        }
        if self.fast_quorum_bps > self.availability_quorum_bps {
            return Err("fast quorum cannot exceed availability quorum".to_string());
        }
        if self.availability_quorum_bps > self.emergency_quorum_bps {
            return Err("availability quorum cannot exceed emergency quorum".to_string());
        }
        if self.min_security_bits < 192 {
            return Err("minimum security bits below devnet floor".to_string());
        }
        if self.max_private_payload_bytes > self.max_batch_bytes {
            return Err("private payload limit cannot exceed batch limit".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_id: String,
    pub status: MemberStatus,
    pub roles: BTreeSet<MemberRole>,
    pub stake_micro_units: u64,
    pub weight_bps: u64,
    pub pq_signing_key_commitment: String,
    pub pq_kem_key_commitment: String,
    pub vrf_key_commitment: String,
    pub network_address_commitment: String,
    pub privacy_budget_nullifier: String,
    pub joined_height: u64,
    pub retiring_height: Option<u64>,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_id": self.operator_id,
            "status": self.status.as_str(),
            "roles": self.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "stake_micro_units": self.stake_micro_units,
            "weight_bps": self.weight_bps,
            "pq_signing_key_commitment": self.pq_signing_key_commitment,
            "pq_kem_key_commitment": self.pq_kem_key_commitment,
            "vrf_key_commitment": self.vrf_key_commitment,
            "network_address_commitment": self.network_address_commitment,
            "privacy_budget_nullifier": self.privacy_budget_nullifier,
            "joined_height": self.joined_height,
            "retiring_height": self.retiring_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.member_id.is_empty() {
            return Err("member id is empty".to_string());
        }
        if self.operator_id.is_empty() {
            return Err(format!("member {} has empty operator id", self.member_id));
        }
        if self.roles.is_empty() {
            return Err(format!("member {} has no roles", self.member_id));
        }
        if self.weight_bps == 0 || self.weight_bps > MAX_BPS {
            return Err(format!("member {} has invalid weight", self.member_id));
        }
        if self.stake_micro_units == 0 {
            return Err(format!("member {} has no bonded stake", self.member_id));
        }
        if self.pq_signing_key_commitment.is_empty()
            || self.pq_kem_key_commitment.is_empty()
            || self.vrf_key_commitment.is_empty()
        {
            return Err(format!(
                "member {} has missing key commitment",
                self.member_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub status: EpochStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub handoff_height: u64,
    pub randomness_root: String,
    pub member_root: String,
    pub member_ids: BTreeSet<String>,
    pub aggregate_weight_bps: u64,
    pub fast_quorum_weight_bps: u64,
    pub availability_quorum_weight_bps: u64,
    pub previous_epoch_id: Option<String>,
    pub next_epoch_id: Option<String>,
}

impl CommitteeEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "handoff_height": self.handoff_height,
            "randomness_root": self.randomness_root,
            "member_root": self.member_root,
            "member_ids": self.member_ids.iter().cloned().collect::<Vec<_>>(),
            "aggregate_weight_bps": self.aggregate_weight_bps,
            "fast_quorum_weight_bps": self.fast_quorum_weight_bps,
            "availability_quorum_weight_bps": self.availability_quorum_weight_bps,
            "previous_epoch_id": self.previous_epoch_id,
            "next_epoch_id": self.next_epoch_id,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.epoch_id.is_empty() {
            return Err("epoch id is empty".to_string());
        }
        if self.start_height > self.end_height {
            return Err(format!("epoch {} has inverted height range", self.epoch_id));
        }
        if self.handoff_height < self.start_height || self.handoff_height > self.end_height {
            return Err(format!(
                "epoch {} has invalid handoff height",
                self.epoch_id
            ));
        }
        if self.member_ids.is_empty() {
            return Err(format!("epoch {} has no members", self.epoch_id));
        }
        if self.aggregate_weight_bps == 0 || self.aggregate_weight_bps > MAX_BPS {
            return Err(format!(
                "epoch {} has invalid aggregate weight",
                self.epoch_id
            ));
        }
        if self.fast_quorum_weight_bps == 0
            || self.fast_quorum_weight_bps > self.aggregate_weight_bps
            || self.availability_quorum_weight_bps == 0
            || self.availability_quorum_weight_bps > self.aggregate_weight_bps
        {
            return Err(format!(
                "epoch {} has invalid quorum weights",
                self.epoch_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqMemberAttestation {
    pub attestation_id: String,
    pub epoch_id: String,
    pub member_id: String,
    pub status: AttestationStatus,
    pub key_epoch: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub signing_key_root: String,
    pub kem_key_root: String,
    pub role_root: String,
    pub stake_commitment: String,
    pub attestation_transcript: String,
    pub aggregate_signature_commitment: String,
}

impl PqMemberAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "epoch_id": self.epoch_id,
            "member_id": self.member_id,
            "status": self.status.as_str(),
            "key_epoch": self.key_epoch,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "signing_key_root": self.signing_key_root,
            "kem_key_root": self.kem_key_root,
            "role_root": self.role_root,
            "stake_commitment": self.stake_commitment,
            "attestation_transcript": self.attestation_transcript,
            "aggregate_signature_commitment": self.aggregate_signature_commitment,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.attestation_id.is_empty() || self.epoch_id.is_empty() || self.member_id.is_empty() {
            return Err("attestation has empty identity field".to_string());
        }
        if self.valid_from_height > self.valid_until_height {
            return Err(format!(
                "attestation {} has inverted validity range",
                self.attestation_id
            ));
        }
        if self.signing_key_root.is_empty()
            || self.kem_key_root.is_empty()
            || self.aggregate_signature_commitment.is_empty()
        {
            return Err(format!(
                "attestation {} has missing root",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateLeaderCommitment {
    pub commitment_id: String,
    pub epoch_id: String,
    pub slot: u64,
    pub height: u64,
    pub status: LeaderCommitmentStatus,
    pub leader_member_commitment: String,
    pub encrypted_leader_hint_root: String,
    pub vrf_output_commitment: String,
    pub reveal_deadline_height: u64,
    pub fallback_member_commitments: BTreeSet<String>,
    pub anti_grinding_nonce_root: String,
}

impl PrivateLeaderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "epoch_id": self.epoch_id,
            "slot": self.slot,
            "height": self.height,
            "status": self.status.as_str(),
            "leader_member_commitment": self.leader_member_commitment,
            "encrypted_leader_hint_root": self.encrypted_leader_hint_root,
            "vrf_output_commitment": self.vrf_output_commitment,
            "reveal_deadline_height": self.reveal_deadline_height,
            "fallback_member_commitments": self.fallback_member_commitments.iter().cloned().collect::<Vec<_>>(),
            "anti_grinding_nonce_root": self.anti_grinding_nonce_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.commitment_id.is_empty() || self.epoch_id.is_empty() {
            return Err("leader commitment has empty identity field".to_string());
        }
        if self.reveal_deadline_height < self.height {
            return Err(format!(
                "leader commitment {} reveal deadline before height",
                self.commitment_id
            ));
        }
        if self.leader_member_commitment.is_empty() || self.vrf_output_commitment.is_empty() {
            return Err(format!(
                "leader commitment {} has missing commitment",
                self.commitment_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastQuorumCertificate {
    pub qc_id: String,
    pub epoch_id: String,
    pub slot: u64,
    pub height: u64,
    pub status: FastQcStatus,
    pub block_commitment: String,
    pub private_payload_root: String,
    pub state_root_after: String,
    pub leader_commitment_id: String,
    pub signer_bitmap_commitment: String,
    pub signer_weight_bps: u64,
    pub aggregate_signature_root: String,
    pub availability_vote_root: String,
    pub created_at_ms: u64,
    pub deadline_ms: u64,
}

impl FastQuorumCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "qc_id": self.qc_id,
            "epoch_id": self.epoch_id,
            "slot": self.slot,
            "height": self.height,
            "status": self.status.as_str(),
            "block_commitment": self.block_commitment,
            "private_payload_root": self.private_payload_root,
            "state_root_after": self.state_root_after,
            "leader_commitment_id": self.leader_commitment_id,
            "signer_bitmap_commitment": self.signer_bitmap_commitment,
            "signer_weight_bps": self.signer_weight_bps,
            "aggregate_signature_root": self.aggregate_signature_root,
            "availability_vote_root": self.availability_vote_root,
            "created_at_ms": self.created_at_ms,
            "deadline_ms": self.deadline_ms,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.qc_id.is_empty() || self.epoch_id.is_empty() {
            return Err("fast qc has empty identity field".to_string());
        }
        if self.signer_weight_bps == 0 || self.signer_weight_bps > MAX_BPS {
            return Err(format!("fast qc {} has invalid signer weight", self.qc_id));
        }
        if self.created_at_ms > self.deadline_ms {
            return Err(format!("fast qc {} was created after deadline", self.qc_id));
        }
        if self.block_commitment.is_empty() || self.aggregate_signature_root.is_empty() {
            return Err(format!("fast qc {} has missing commitment", self.qc_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilityVote {
    pub vote_id: String,
    pub epoch_id: String,
    pub qc_id: String,
    pub member_id: String,
    pub status: AvailabilityVoteStatus,
    pub shard_index: u64,
    pub erasure_root: String,
    pub redacted_witness_root: String,
    pub nullifier: String,
    pub vote_weight_bps: u64,
    pub submitted_at_ms: u64,
    pub deadline_ms: u64,
}

impl AvailabilityVote {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "epoch_id": self.epoch_id,
            "qc_id": self.qc_id,
            "member_id": self.member_id,
            "status": self.status.as_str(),
            "shard_index": self.shard_index,
            "erasure_root": self.erasure_root,
            "redacted_witness_root": self.redacted_witness_root,
            "nullifier": self.nullifier,
            "vote_weight_bps": self.vote_weight_bps,
            "submitted_at_ms": self.submitted_at_ms,
            "deadline_ms": self.deadline_ms,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.vote_id.is_empty()
            || self.epoch_id.is_empty()
            || self.qc_id.is_empty()
            || self.member_id.is_empty()
        {
            return Err("availability vote has empty identity field".to_string());
        }
        if self.vote_weight_bps == 0 || self.vote_weight_bps > MAX_BPS {
            return Err(format!(
                "availability vote {} has invalid weight",
                self.vote_id
            ));
        }
        if self.submitted_at_ms > self.deadline_ms {
            return Err(format!(
                "availability vote {} missed deadline",
                self.vote_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowLatencyFinalityReceipt {
    pub receipt_id: String,
    pub epoch_id: String,
    pub qc_id: String,
    pub height: u64,
    pub slot: u64,
    pub status: FinalityReceiptStatus,
    pub finality_root: String,
    pub block_commitment: String,
    pub availability_root: String,
    pub fast_qc_root: String,
    pub client_receipt_commitment: String,
    pub issued_at_ms: u64,
    pub expires_at_height: u64,
    pub latency_ms: u64,
}

impl LowLatencyFinalityReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "epoch_id": self.epoch_id,
            "qc_id": self.qc_id,
            "height": self.height,
            "slot": self.slot,
            "status": self.status.as_str(),
            "finality_root": self.finality_root,
            "block_commitment": self.block_commitment,
            "availability_root": self.availability_root,
            "fast_qc_root": self.fast_qc_root,
            "client_receipt_commitment": self.client_receipt_commitment,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_height": self.expires_at_height,
            "latency_ms": self.latency_ms,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.receipt_id.is_empty() || self.epoch_id.is_empty() || self.qc_id.is_empty() {
            return Err("finality receipt has empty identity field".to_string());
        }
        if self.expires_at_height < self.height {
            return Err(format!(
                "receipt {} expires before block height",
                self.receipt_id
            ));
        }
        if self.finality_root.is_empty() || self.fast_qc_root.is_empty() {
            return Err(format!("receipt {} has missing roots", self.receipt_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub epoch_id: String,
    pub accused_member_id: String,
    pub reporter_commitment: String,
    pub kind: SlashingEvidenceKind,
    pub status: SlashingEvidenceStatus,
    pub evidence_root: String,
    pub conflicting_record_roots: BTreeSet<String>,
    pub privacy_preserving_summary_root: String,
    pub opened_at_height: u64,
    pub challenge_deadline_height: u64,
    pub slash_amount_micro_units: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "epoch_id": self.epoch_id,
            "accused_member_id": self.accused_member_id,
            "reporter_commitment": self.reporter_commitment,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "conflicting_record_roots": self.conflicting_record_roots.iter().cloned().collect::<Vec<_>>(),
            "privacy_preserving_summary_root": self.privacy_preserving_summary_root,
            "opened_at_height": self.opened_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "slash_amount_micro_units": self.slash_amount_micro_units,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        if self.evidence_id.is_empty()
            || self.epoch_id.is_empty()
            || self.accused_member_id.is_empty()
        {
            return Err("slashing evidence has empty identity field".to_string());
        }
        if self.challenge_deadline_height < self.opened_at_height {
            return Err(format!(
                "evidence {} challenge deadline before open height",
                self.evidence_id
            ));
        }
        if self.slash_amount_micro_units == 0 {
            return Err(format!("evidence {} has no slash amount", self.evidence_id));
        }
        if self.conflicting_record_roots.is_empty() {
            return Err(format!(
                "evidence {} has no conflicting roots",
                self.evidence_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub member_root: String,
    pub epoch_root: String,
    pub attestation_root: String,
    pub leader_commitment_root: String,
    pub fast_qc_root: String,
    pub availability_vote_root: String,
    pub finality_receipt_root: String,
    pub slashing_evidence_root: String,
    pub index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "member_root": self.member_root,
            "epoch_root": self.epoch_root,
            "attestation_root": self.attestation_root,
            "leader_commitment_root": self.leader_commitment_root,
            "fast_qc_root": self.fast_qc_root,
            "availability_vote_root": self.availability_vote_root,
            "finality_receipt_root": self.finality_receipt_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "index_root": self.index_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub member_count: u64,
    pub active_member_count: u64,
    pub live_epoch_count: u64,
    pub attestation_count: u64,
    pub usable_attestation_count: u64,
    pub leader_commitment_count: u64,
    pub fast_qc_count: u64,
    pub certified_qc_count: u64,
    pub availability_vote_count: u64,
    pub contributing_availability_vote_count: u64,
    pub finality_receipt_count: u64,
    pub final_receipt_count: u64,
    pub slashing_evidence_count: u64,
    pub active_slashing_evidence_count: u64,
    pub aggregate_active_weight_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "member_count": self.member_count,
            "active_member_count": self.active_member_count,
            "live_epoch_count": self.live_epoch_count,
            "attestation_count": self.attestation_count,
            "usable_attestation_count": self.usable_attestation_count,
            "leader_commitment_count": self.leader_commitment_count,
            "fast_qc_count": self.fast_qc_count,
            "certified_qc_count": self.certified_qc_count,
            "availability_vote_count": self.availability_vote_count,
            "contributing_availability_vote_count": self.contributing_availability_vote_count,
            "finality_receipt_count": self.finality_receipt_count,
            "final_receipt_count": self.final_receipt_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "active_slashing_evidence_count": self.active_slashing_evidence_count,
            "aggregate_active_weight_bps": self.aggregate_active_weight_bps,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub members: BTreeMap<String, CommitteeMember>,
    pub epochs: BTreeMap<String, CommitteeEpoch>,
    pub attestations: BTreeMap<String, PqMemberAttestation>,
    pub leader_commitments: BTreeMap<String, PrivateLeaderCommitment>,
    pub fast_quorum_certificates: BTreeMap<String, FastQuorumCertificate>,
    pub availability_votes: BTreeMap<String, AvailabilityVote>,
    pub finality_receipts: BTreeMap<String, LowLatencyFinalityReceipt>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub active_epoch_id: String,
    pub emergency_mode: bool,
    pub halted: bool,
}

impl State {
    pub fn devnet() -> PqPrivateSequencerFastCommitteeResult<Self> {
        let config = Config::devnet();
        let mut members = BTreeMap::new();
        for (index, role_tail) in [
            (0_u64, MemberRole::Sequencer),
            (1, MemberRole::AvailabilityWitness),
            (2, MemberRole::FinalitySigner),
            (3, MemberRole::PrivacyAuditor),
            (4, MemberRole::SlashingGuardian),
            (5, MemberRole::RotationCoordinator),
            (6, MemberRole::EmergencyFallback),
        ] {
            let member_id = format!("pq-fast-member-{index:02}");
            let mut roles = BTreeSet::new();
            roles.insert(MemberRole::Sequencer);
            roles.insert(MemberRole::AvailabilityWitness);
            roles.insert(MemberRole::FinalitySigner);
            roles.insert(role_tail);
            members.insert(
                member_id.clone(),
                CommitteeMember {
                    member_id: member_id.clone(),
                    operator_id: format!("nebula-devnet-operator-{index:02}"),
                    status: if index == 6 {
                        MemberStatus::Standby
                    } else {
                        MemberStatus::Active
                    },
                    roles,
                    stake_micro_units: 2_500_000 + index * 250_000,
                    weight_bps: if index == 6 { 1_000 } else { 1_500 },
                    pq_signing_key_commitment: fixture_hash(
                        "MEMBER-PQ-SIGNING-KEY",
                        &[&member_id, role_tail.as_str()],
                    ),
                    pq_kem_key_commitment: fixture_hash("MEMBER-PQ-KEM-KEY", &[&member_id]),
                    vrf_key_commitment: fixture_hash("MEMBER-VRF-KEY", &[&member_id]),
                    network_address_commitment: fixture_hash("MEMBER-NETWORK", &[&member_id]),
                    privacy_budget_nullifier: fixture_hash(
                        "MEMBER-PRIVACY-NULLIFIER",
                        &[&member_id],
                    ),
                    joined_height: DEVNET_HEIGHT.saturating_sub(2 * DEFAULT_EPOCH_BLOCKS),
                    retiring_height: None,
                },
            );
        }

        let member_records = members
            .values()
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>();
        let member_root = merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-MEMBERS",
            &member_records,
        );
        let active_epoch_id = "pq-fast-epoch-00264".to_string();
        let previous_epoch_id = "pq-fast-epoch-00263".to_string();
        let next_epoch_id = "pq-fast-epoch-00265".to_string();
        let mut member_ids = BTreeSet::new();
        member_ids.extend(members.keys().cloned());

        let mut epochs = BTreeMap::new();
        epochs.insert(
            previous_epoch_id.clone(),
            CommitteeEpoch {
                epoch_id: previous_epoch_id.clone(),
                epoch_index: 263,
                status: EpochStatus::Draining,
                start_height: DEVNET_HEIGHT - DEFAULT_EPOCH_BLOCKS,
                end_height: DEVNET_HEIGHT - 1,
                handoff_height: DEVNET_HEIGHT - DEFAULT_ROTATION_OVERLAP_BLOCKS,
                randomness_root: fixture_hash("EPOCH-RANDOMNESS", &[&previous_epoch_id]),
                member_root: member_root.clone(),
                member_ids: member_ids.clone(),
                aggregate_weight_bps: 10_000,
                fast_quorum_weight_bps: config.fast_quorum_bps,
                availability_quorum_weight_bps: config.availability_quorum_bps,
                previous_epoch_id: None,
                next_epoch_id: Some(active_epoch_id.clone()),
            },
        );
        epochs.insert(
            active_epoch_id.clone(),
            CommitteeEpoch {
                epoch_id: active_epoch_id.clone(),
                epoch_index: 264,
                status: EpochStatus::Active,
                start_height: DEVNET_HEIGHT,
                end_height: DEVNET_HEIGHT + DEFAULT_EPOCH_BLOCKS - 1,
                handoff_height: DEVNET_HEIGHT + DEFAULT_EPOCH_BLOCKS
                    - DEFAULT_ROTATION_OVERLAP_BLOCKS,
                randomness_root: fixture_hash("EPOCH-RANDOMNESS", &[&active_epoch_id]),
                member_root: member_root.clone(),
                member_ids: member_ids.clone(),
                aggregate_weight_bps: 10_000,
                fast_quorum_weight_bps: config.fast_quorum_bps,
                availability_quorum_weight_bps: config.availability_quorum_bps,
                previous_epoch_id: Some(previous_epoch_id.clone()),
                next_epoch_id: Some(next_epoch_id.clone()),
            },
        );
        epochs.insert(
            next_epoch_id.clone(),
            CommitteeEpoch {
                epoch_id: next_epoch_id.clone(),
                epoch_index: 265,
                status: EpochStatus::Warming,
                start_height: DEVNET_HEIGHT + DEFAULT_EPOCH_BLOCKS,
                end_height: DEVNET_HEIGHT + 2 * DEFAULT_EPOCH_BLOCKS - 1,
                handoff_height: DEVNET_HEIGHT + 2 * DEFAULT_EPOCH_BLOCKS
                    - DEFAULT_ROTATION_OVERLAP_BLOCKS,
                randomness_root: fixture_hash("EPOCH-RANDOMNESS", &[&next_epoch_id]),
                member_root,
                member_ids: member_ids.clone(),
                aggregate_weight_bps: 10_000,
                fast_quorum_weight_bps: config.fast_quorum_bps,
                availability_quorum_weight_bps: config.availability_quorum_bps,
                previous_epoch_id: Some(active_epoch_id.clone()),
                next_epoch_id: None,
            },
        );

        let mut attestations = BTreeMap::new();
        for member in members.values() {
            let role_record = json!({
                "member_id": member.member_id,
                "roles": member.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            });
            let role_root = root_from_record(&role_record);
            let attestation_id = fixture_hash(
                "MEMBER-ATTESTATION-ID",
                &[&active_epoch_id, &member.member_id],
            );
            attestations.insert(
                attestation_id.clone(),
                PqMemberAttestation {
                    attestation_id,
                    epoch_id: active_epoch_id.clone(),
                    member_id: member.member_id.clone(),
                    status: AttestationStatus::Accepted,
                    key_epoch: 264,
                    valid_from_height: DEVNET_HEIGHT,
                    valid_until_height: DEVNET_HEIGHT + config.member_attestation_ttl_blocks,
                    signing_key_root: member.pq_signing_key_commitment.clone(),
                    kem_key_root: member.pq_kem_key_commitment.clone(),
                    role_root,
                    stake_commitment: fixture_hash("MEMBER-STAKE", &[&member.member_id]),
                    attestation_transcript: fixture_hash(
                        "MEMBER-ATTESTATION-TRANSCRIPT",
                        &[&member.member_id],
                    ),
                    aggregate_signature_commitment: fixture_hash(
                        "MEMBER-ATTESTATION-SIG",
                        &[&member.member_id],
                    ),
                },
            );
        }

        let mut leader_commitments = BTreeMap::new();
        for slot in 0..4_u64 {
            let height = DEVNET_HEIGHT + slot;
            let commitment_id = format!("leader-commitment-{height}-{slot}");
            let mut fallback_member_commitments = BTreeSet::new();
            fallback_member_commitments
                .insert(fixture_hash("LEADER-FALLBACK", &[&commitment_id, "a"]));
            fallback_member_commitments
                .insert(fixture_hash("LEADER-FALLBACK", &[&commitment_id, "b"]));
            leader_commitments.insert(
                commitment_id.clone(),
                PrivateLeaderCommitment {
                    commitment_id: commitment_id.clone(),
                    epoch_id: active_epoch_id.clone(),
                    slot,
                    height,
                    status: if slot < 2 {
                        LeaderCommitmentStatus::Consumed
                    } else {
                        LeaderCommitmentStatus::Precommitted
                    },
                    leader_member_commitment: fixture_hash("LEADER-MEMBER", &[&commitment_id]),
                    encrypted_leader_hint_root: fixture_hash("LEADER-HINT", &[&commitment_id]),
                    vrf_output_commitment: fixture_hash("LEADER-VRF", &[&commitment_id]),
                    reveal_deadline_height: height + config.leader_lookahead_slots,
                    fallback_member_commitments,
                    anti_grinding_nonce_root: fixture_hash(
                        "LEADER-ANTI-GRINDING",
                        &[&commitment_id],
                    ),
                },
            );
        }

        let mut availability_votes = BTreeMap::new();
        let qc_id = "fast-qc-42240-0".to_string();
        for (index, member) in members.values().take(5).enumerate() {
            let vote_id = format!("availability-vote-42240-{index}");
            availability_votes.insert(
                vote_id.clone(),
                AvailabilityVote {
                    vote_id: vote_id.clone(),
                    epoch_id: active_epoch_id.clone(),
                    qc_id: qc_id.clone(),
                    member_id: member.member_id.clone(),
                    status: AvailabilityVoteStatus::Aggregated,
                    shard_index: index as u64,
                    erasure_root: fixture_hash("AVAILABILITY-ERASURE", &[&vote_id]),
                    redacted_witness_root: fixture_hash(
                        "AVAILABILITY-REDACTED-WITNESS",
                        &[&vote_id],
                    ),
                    nullifier: fixture_hash("AVAILABILITY-NULLIFIER", &[&vote_id]),
                    vote_weight_bps: member.weight_bps,
                    submitted_at_ms: 180 + index as u64 * 20,
                    deadline_ms: config.availability_deadline_ms,
                },
            );
        }
        let availability_vote_records = availability_votes
            .values()
            .map(AvailabilityVote::public_record)
            .collect::<Vec<_>>();
        let availability_vote_root = merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-AVAILABILITY-VOTES",
            &availability_vote_records,
        );

        let mut fast_quorum_certificates = BTreeMap::new();
        fast_quorum_certificates.insert(
            qc_id.clone(),
            FastQuorumCertificate {
                qc_id: qc_id.clone(),
                epoch_id: active_epoch_id.clone(),
                slot: 0,
                height: DEVNET_HEIGHT,
                status: FastQcStatus::FinalityLinked,
                block_commitment: fixture_hash("FAST-QC-BLOCK", &[&qc_id]),
                private_payload_root: fixture_hash("FAST-QC-PRIVATE-PAYLOAD", &[&qc_id]),
                state_root_after: fixture_hash("FAST-QC-STATE-AFTER", &[&qc_id]),
                leader_commitment_id: "leader-commitment-42240-0".to_string(),
                signer_bitmap_commitment: fixture_hash("FAST-QC-SIGNER-BITMAP", &[&qc_id]),
                signer_weight_bps: 7_500,
                aggregate_signature_root: fixture_hash("FAST-QC-AGGREGATE-SIG", &[&qc_id]),
                availability_vote_root,
                created_at_ms: 320,
                deadline_ms: config.qc_deadline_ms,
            },
        );
        let proposed_qc_id = "fast-qc-42241-1".to_string();
        fast_quorum_certificates.insert(
            proposed_qc_id.clone(),
            FastQuorumCertificate {
                qc_id: proposed_qc_id.clone(),
                epoch_id: active_epoch_id.clone(),
                slot: 1,
                height: DEVNET_HEIGHT + 1,
                status: FastQcStatus::GatheringVotes,
                block_commitment: fixture_hash("FAST-QC-BLOCK", &[&proposed_qc_id]),
                private_payload_root: fixture_hash("FAST-QC-PRIVATE-PAYLOAD", &[&proposed_qc_id]),
                state_root_after: fixture_hash("FAST-QC-STATE-AFTER", &[&proposed_qc_id]),
                leader_commitment_id: "leader-commitment-42241-1".to_string(),
                signer_bitmap_commitment: fixture_hash("FAST-QC-SIGNER-BITMAP", &[&proposed_qc_id]),
                signer_weight_bps: 4_500,
                aggregate_signature_root: fixture_hash("FAST-QC-AGGREGATE-SIG", &[&proposed_qc_id]),
                availability_vote_root: fixture_hash(
                    "FAST-QC-PENDING-AVAILABILITY",
                    &[&proposed_qc_id],
                ),
                created_at_ms: 220,
                deadline_ms: config.qc_deadline_ms,
            },
        );

        let mut finality_receipts = BTreeMap::new();
        let fast_qc_root = fast_quorum_certificates
            .get(&qc_id)
            .map(FastQuorumCertificate::root)
            .ok_or_else(|| "missing devnet fast qc".to_string())?;
        let receipt_id = "finality-receipt-42240-0".to_string();
        finality_receipts.insert(
            receipt_id.clone(),
            LowLatencyFinalityReceipt {
                receipt_id: receipt_id.clone(),
                epoch_id: active_epoch_id.clone(),
                qc_id: qc_id.clone(),
                height: DEVNET_HEIGHT,
                slot: 0,
                status: FinalityReceiptStatus::Anchored,
                finality_root: fixture_hash("FINALITY-ROOT", &[&receipt_id]),
                block_commitment: fixture_hash("FAST-QC-BLOCK", &[&qc_id]),
                availability_root: fixture_hash("FINALITY-AVAILABILITY", &[&receipt_id]),
                fast_qc_root,
                client_receipt_commitment: fixture_hash("FINALITY-CLIENT-RECEIPT", &[&receipt_id]),
                issued_at_ms: 410,
                expires_at_height: DEVNET_HEIGHT + config.finality_receipt_ttl_blocks,
                latency_ms: 410,
            },
        );

        let mut slashing_evidence = BTreeMap::new();
        let evidence_id = "slash-evidence-late-receipt-0001".to_string();
        let mut conflicting_record_roots = BTreeSet::new();
        conflicting_record_roots.insert(fixture_hash("SLASH-CONFLICT", &[&evidence_id, "primary"]));
        conflicting_record_roots
            .insert(fixture_hash("SLASH-CONFLICT", &[&evidence_id, "secondary"]));
        slashing_evidence.insert(
            evidence_id.clone(),
            SlashingEvidence {
                evidence_id: evidence_id.clone(),
                epoch_id: previous_epoch_id,
                accused_member_id: "pq-fast-member-05".to_string(),
                reporter_commitment: fixture_hash("SLASH-REPORTER", &[&evidence_id]),
                kind: SlashingEvidenceKind::LateFinalityReceipt,
                status: SlashingEvidenceStatus::UnderReview,
                evidence_root: fixture_hash("SLASH-EVIDENCE", &[&evidence_id]),
                conflicting_record_roots,
                privacy_preserving_summary_root: fixture_hash(
                    "SLASH-PRIVATE-SUMMARY",
                    &[&evidence_id],
                ),
                opened_at_height: DEVNET_HEIGHT - 3,
                challenge_deadline_height: DEVNET_HEIGHT + 21,
                slash_amount_micro_units: config.base_bond_micro_units * config.slash_bps / MAX_BPS,
            },
        );

        let state = Self {
            height: DEVNET_HEIGHT,
            config,
            members,
            epochs,
            attestations,
            leader_commitments,
            fast_quorum_certificates,
            availability_votes,
            finality_receipts,
            slashing_evidence,
            active_epoch_id,
            emergency_mode: false,
            halted: false,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqPrivateSequencerFastCommitteeResult<()> {
        self.config.validate()?;
        if self.halted && self.emergency_mode {
            return Err("state cannot be halted and in emergency mode".to_string());
        }
        if self.members.is_empty() {
            return Err("committee has no members".to_string());
        }
        if self.members.len() > MAX_MEMBERS {
            return Err("committee exceeds maximum member count".to_string());
        }
        if !self.epochs.contains_key(&self.active_epoch_id) {
            return Err("active epoch id is not present".to_string());
        }

        let mut aggregate_weight = 0_u64;
        for (member_id, member) in &self.members {
            if member_id != &member.member_id {
                return Err(format!("member map key mismatch for {member_id}"));
            }
            member.validate()?;
            if member.status.can_vote() {
                aggregate_weight = aggregate_weight.saturating_add(member.weight_bps);
            }
        }
        if aggregate_weight < self.config.emergency_quorum_bps {
            return Err("active member weight below emergency quorum".to_string());
        }

        for (epoch_id, epoch) in &self.epochs {
            if epoch_id != &epoch.epoch_id {
                return Err(format!("epoch map key mismatch for {epoch_id}"));
            }
            epoch.validate()?;
            for member_id in &epoch.member_ids {
                if !self.members.contains_key(member_id) {
                    return Err(format!(
                        "epoch {} references unknown member {}",
                        epoch_id, member_id
                    ));
                }
            }
        }

        for (attestation_id, attestation) in &self.attestations {
            if attestation_id != &attestation.attestation_id {
                return Err(format!("attestation map key mismatch for {attestation_id}"));
            }
            attestation.validate()?;
            self.require_epoch(&attestation.epoch_id)?;
            self.require_member(&attestation.member_id)?;
        }

        for (commitment_id, commitment) in &self.leader_commitments {
            if commitment_id != &commitment.commitment_id {
                return Err(format!(
                    "leader commitment map key mismatch for {commitment_id}"
                ));
            }
            commitment.validate()?;
            self.require_epoch(&commitment.epoch_id)?;
        }

        for (qc_id, qc) in &self.fast_quorum_certificates {
            if qc_id != &qc.qc_id {
                return Err(format!("fast qc map key mismatch for {qc_id}"));
            }
            qc.validate()?;
            self.require_epoch(&qc.epoch_id)?;
            if !self
                .leader_commitments
                .contains_key(&qc.leader_commitment_id)
            {
                return Err(format!(
                    "fast qc {} references unknown leader commitment {}",
                    qc_id, qc.leader_commitment_id
                ));
            }
            let epoch = self.require_epoch(&qc.epoch_id)?;
            if qc.status.accepted() && qc.signer_weight_bps < epoch.fast_quorum_weight_bps {
                return Err(format!("fast qc {} accepted below fast quorum", qc_id));
            }
        }

        for (vote_id, vote) in &self.availability_votes {
            if vote_id != &vote.vote_id {
                return Err(format!("availability vote map key mismatch for {vote_id}"));
            }
            vote.validate()?;
            self.require_epoch(&vote.epoch_id)?;
            self.require_member(&vote.member_id)?;
            if !self.fast_quorum_certificates.contains_key(&vote.qc_id) {
                return Err(format!(
                    "availability vote {} references unknown qc {}",
                    vote_id, vote.qc_id
                ));
            }
        }

        for (receipt_id, receipt) in &self.finality_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err(format!("receipt map key mismatch for {receipt_id}"));
            }
            receipt.validate()?;
            self.require_epoch(&receipt.epoch_id)?;
            if !self.fast_quorum_certificates.contains_key(&receipt.qc_id) {
                return Err(format!(
                    "receipt {} references unknown qc {}",
                    receipt_id, receipt.qc_id
                ));
            }
        }

        for (evidence_id, evidence) in &self.slashing_evidence {
            if evidence_id != &evidence.evidence_id {
                return Err(format!(
                    "slashing evidence map key mismatch for {evidence_id}"
                ));
            }
            evidence.validate()?;
            self.require_epoch(&evidence.epoch_id)?;
            let member = self.require_member(&evidence.accused_member_id)?;
            if !member.status.slashable() {
                return Err(format!(
                    "evidence {} accuses non-slashable member {}",
                    evidence_id, evidence.accused_member_id
                ));
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PqPrivateSequencerFastCommitteeResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, delta: u64) -> PqPrivateSequencerFastCommitteeResult<()> {
        let next_height = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "height update overflow".to_string())?;
        self.set_height(next_height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let member_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-MEMBER",
            self.members
                .values()
                .map(CommitteeMember::public_record)
                .collect(),
        );
        let epoch_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-EPOCH",
            self.epochs
                .values()
                .map(CommitteeEpoch::public_record)
                .collect(),
        );
        let attestation_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-ATTESTATION",
            self.attestations
                .values()
                .map(PqMemberAttestation::public_record)
                .collect(),
        );
        let leader_commitment_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-LEADER",
            self.leader_commitments
                .values()
                .map(PrivateLeaderCommitment::public_record)
                .collect(),
        );
        let fast_qc_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-QC",
            self.fast_quorum_certificates
                .values()
                .map(FastQuorumCertificate::public_record)
                .collect(),
        );
        let availability_vote_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-AVAILABILITY",
            self.availability_votes
                .values()
                .map(AvailabilityVote::public_record)
                .collect(),
        );
        let finality_receipt_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-FINALITY",
            self.finality_receipts
                .values()
                .map(LowLatencyFinalityReceipt::public_record)
                .collect(),
        );
        let slashing_evidence_root = record_merkle_root(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-SLASHING",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record)
                .collect(),
        );
        let index_record = json!({
            "active_epoch_id": self.active_epoch_id,
            "emergency_mode": self.emergency_mode,
            "halted": self.halted,
            "height": self.height,
        });
        let index_root = root_from_record(&index_record);
        let state_root = domain_hash(
            "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&member_root),
                HashPart::Str(&epoch_root),
                HashPart::Str(&attestation_root),
                HashPart::Str(&leader_commitment_root),
                HashPart::Str(&fast_qc_root),
                HashPart::Str(&availability_vote_root),
                HashPart::Str(&finality_receipt_root),
                HashPart::Str(&slashing_evidence_root),
                HashPart::Str(&index_root),
                HashPart::Int(self.height as i128),
            ],
            32,
        );
        Roots {
            config_root,
            member_root,
            epoch_root,
            attestation_root,
            leader_commitment_root,
            fast_qc_root,
            availability_vote_root,
            finality_receipt_root,
            slashing_evidence_root,
            index_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            member_count: self.members.len() as u64,
            active_member_count: self
                .members
                .values()
                .filter(|member| member.status.can_vote())
                .count() as u64,
            live_epoch_count: self
                .epochs
                .values()
                .filter(|epoch| epoch.status.live())
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            usable_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.status.usable())
                .count() as u64,
            leader_commitment_count: self.leader_commitments.len() as u64,
            fast_qc_count: self.fast_quorum_certificates.len() as u64,
            certified_qc_count: self
                .fast_quorum_certificates
                .values()
                .filter(|qc| qc.status.accepted())
                .count() as u64,
            availability_vote_count: self.availability_votes.len() as u64,
            contributing_availability_vote_count: self
                .availability_votes
                .values()
                .filter(|vote| vote.status.contributes_to_quorum())
                .count() as u64,
            finality_receipt_count: self.finality_receipts.len() as u64,
            final_receipt_count: self
                .finality_receipts
                .values()
                .filter(|receipt| receipt.status.is_final())
                .count() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            active_slashing_evidence_count: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.status.active())
                .count() as u64,
            aggregate_active_weight_bps: self
                .members
                .values()
                .filter(|member| member.status.can_vote())
                .map(|member| member.weight_bps)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PQ_PRIVATE_SEQUENCER_FAST_COMMITTEE_PROTOCOL_VERSION,
            "height": self.height,
            "active_epoch_id": self.active_epoch_id,
            "emergency_mode": self.emergency_mode,
            "halted": self.halted,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "members": self.members.values().map(CommitteeMember::public_record).collect::<Vec<_>>(),
            "epochs": self.epochs.values().map(CommitteeEpoch::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqMemberAttestation::public_record).collect::<Vec<_>>(),
            "leader_commitments": self.leader_commitments.values().map(PrivateLeaderCommitment::public_record).collect::<Vec<_>>(),
            "fast_quorum_certificates": self.fast_quorum_certificates.values().map(FastQuorumCertificate::public_record).collect::<Vec<_>>(),
            "availability_votes": self.availability_votes.values().map(AvailabilityVote::public_record).collect::<Vec<_>>(),
            "finality_receipts": self.finality_receipts.values().map(LowLatencyFinalityReceipt::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidence::public_record).collect::<Vec<_>>(),
            "state_root": roots.state_root,
        })
    }

    fn require_epoch(
        &self,
        epoch_id: &str,
    ) -> PqPrivateSequencerFastCommitteeResult<&CommitteeEpoch> {
        self.epochs
            .get(epoch_id)
            .ok_or_else(|| format!("unknown epoch {epoch_id}"))
    }

    fn require_member(
        &self,
        member_id: &str,
    ) -> PqPrivateSequencerFastCommitteeResult<&CommitteeMember> {
        self.members
            .get(member_id)
            .ok_or_else(|| format!("unknown member {member_id}"))
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PqPrivateSequencerFastCommitteeResult<State> {
    State::devnet()
}

fn record_merkle_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn fixture_hash(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    let leaf_root = merkle_root(
        &format!("PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-{domain}"),
        &leaves,
    );
    domain_hash(
        &format!("PQ-PRIVATE-SEQUENCER-FAST-COMMITTEE-{domain}-FIXTURE"),
        &[HashPart::Str(&leaf_root)],
        32,
    )
}
