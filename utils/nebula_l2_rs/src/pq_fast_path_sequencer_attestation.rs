use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqFastPathSequencerAttestationResult<T> = Result<T, String>;

pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_PROTOCOL_VERSION: &str =
    "nebula-l2-pq-fast-path-sequencer-attestation-v1";
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_SCHEMA_VERSION: u64 = 1;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_COMMITMENT_SCHEME: &str =
    "pq-fast-path-transcript-commitments-v1";
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEVNET_HEIGHT: u64 = 900;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_FAST_WINDOW_BLOCKS: u64 = 2;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_FALLBACK_CHALLENGE_BLOCKS: u64 = 48;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_COMMITTEE_EPOCH_BLOCKS: u64 = 720;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_SIGNATURE_DEADLINE_MS: u64 = 1_200;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 6;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_THRESHOLD_BPS: u64 = 6_700;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_EMERGENCY_THRESHOLD_BPS: u64 = 8_000;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_LOW_FEE_MAX_UNITS: u64 = 4;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_LOW_FEE_RESERVE_BPS: u64 = 2_000;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_BASE_BOND_UNITS: u64 = 25_000;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_MAX_BLOCK_BYTES: u64 = 2_000_000;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_MAX_PRECONF_TXS: u64 = 2_048;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_MAX_RECORDS: usize = 4_096;
pub const PQ_FAST_PATH_SEQUENCER_ATTESTATION_MAX_BPS: u64 = 10_000;

const STATE_STATUS_BOOTSTRAPPING: &str = "bootstrapping";
const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_CHALLENGE_MODE: &str = "challenge_mode";
const STATE_STATUS_PAUSED: &str = "paused";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFastPathSignatureScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    HybridTranscript,
}

impl PqFastPathSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => PQ_FAST_PATH_SEQUENCER_ATTESTATION_PRIMARY_SIGNATURE_SCHEME,
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaShake128s => PQ_FAST_PATH_SEQUENCER_ATTESTATION_BACKUP_SIGNATURE_SCHEME,
            Self::HybridTranscript => "ml-dsa-plus-slh-dsa-hybrid-transcript",
        }
    }

    pub fn fallback_ready(self) -> bool {
        matches!(self, Self::SlhDsaShake128s | Self::HybridTranscript)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFastPathLane {
    Emergency,
    BridgeExit,
    PrivateTransfer,
    PublicTransfer,
    LowFeePublicGood,
    SequencerMaintenance,
}

impl PqFastPathLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::BridgeExit => "bridge_exit",
            Self::PrivateTransfer => "private_transfer",
            Self::PublicTransfer => "public_transfer",
            Self::LowFeePublicGood => "low_fee_public_good",
            Self::SequencerMaintenance => "sequencer_maintenance",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::BridgeExit => 9_000,
            Self::PrivateTransfer => 8_000,
            Self::PublicTransfer => 6_500,
            Self::LowFeePublicGood => 5_500,
            Self::SequencerMaintenance => 2_000,
        }
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::LowFeePublicGood)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFastPathCommitteePolicy {
    WeightedThreshold,
    RotatingEpoch,
    EmergencyUnanimity,
}

impl PqFastPathCommitteePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeightedThreshold => "weighted_threshold",
            Self::RotatingEpoch => "rotating_epoch",
            Self::EmergencyUnanimity => "emergency_unanimity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFastPathAttestationStatus {
    Proposed,
    CollectingSignatures,
    FastAccepted,
    ChallengeOpen,
    FallbackRequired,
    Finalized,
    Rejected,
    Expired,
}

impl PqFastPathAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::CollectingSignatures => "collecting_signatures",
            Self::FastAccepted => "fast_accepted",
            Self::ChallengeOpen => "challenge_open",
            Self::FallbackRequired => "fallback_required",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFastPathChallengeKind {
    InvalidSignature,
    SequencerEquivocation,
    MissingData,
    InvalidStateRoot,
    FeeLaneViolation,
    CommitteeQuorumFault,
    Timeout,
}

impl PqFastPathChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::SequencerEquivocation => "sequencer_equivocation",
            Self::MissingData => "missing_data",
            Self::InvalidStateRoot => "invalid_state_root",
            Self::FeeLaneViolation => "fee_lane_violation",
            Self::CommitteeQuorumFault => "committee_quorum_fault",
            Self::Timeout => "timeout",
        }
    }

    pub fn escalates_immediately(self) -> bool {
        matches!(
            self,
            Self::SequencerEquivocation | Self::MissingData | Self::CommitteeQuorumFault
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFastPathChallengeStatus {
    Open,
    EvidenceSubmitted,
    FallbackWindow,
    Sustained,
    Dismissed,
    Expired,
}

impl PqFastPathChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::FallbackWindow => "fallback_window",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Sustained | Self::Dismissed | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFastPathSettlementAction {
    HonorPreconfirmation,
    RevertToFallbackWindow,
    SlashSequencer,
    SlashCommitteeSigner,
    RefundPriorityFee,
    PromoteLowFeeBatch,
}

impl PqFastPathSettlementAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HonorPreconfirmation => "honor_preconfirmation",
            Self::RevertToFallbackWindow => "revert_to_fallback_window",
            Self::SlashSequencer => "slash_sequencer",
            Self::SlashCommitteeSigner => "slash_committee_signer",
            Self::RefundPriorityFee => "refund_priority_fee",
            Self::PromoteLowFeeBatch => "promote_low_fee_batch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathSequencerAttestationConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub primary_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub commitment_scheme: String,
    pub fee_asset_id: String,
    pub fast_window_blocks: u64,
    pub fallback_challenge_window_blocks: u64,
    pub committee_epoch_blocks: u64,
    pub signature_deadline_ms: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub committee_threshold_bps: u64,
    pub emergency_threshold_bps: u64,
    pub low_fee_max_units: u64,
    pub low_fee_reserve_bps: u64,
    pub base_challenge_bond_units: u64,
    pub slash_bps: u64,
    pub max_block_bytes: u64,
    pub max_preconfirmation_txs: u64,
    pub max_records: usize,
}

impl PqFastPathSequencerAttestationConfig {
    pub fn devnet() -> Self {
        let config_id = pq_fast_path_config_id(
            CHAIN_ID,
            PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEVNET_FEE_ASSET_ID,
        );
        Self {
            config_id,
            protocol_version: PQ_FAST_PATH_SEQUENCER_ATTESTATION_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_FAST_PATH_SEQUENCER_ATTESTATION_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PQ_FAST_PATH_SEQUENCER_ATTESTATION_HASH_SUITE.to_string(),
            primary_signature_scheme: PQ_FAST_PATH_SEQUENCER_ATTESTATION_PRIMARY_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme: PQ_FAST_PATH_SEQUENCER_ATTESTATION_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            commitment_scheme: PQ_FAST_PATH_SEQUENCER_ATTESTATION_COMMITMENT_SCHEME.to_string(),
            fee_asset_id: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEVNET_FEE_ASSET_ID.to_string(),
            fast_window_blocks: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_FAST_WINDOW_BLOCKS,
            fallback_challenge_window_blocks:
                PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_FALLBACK_CHALLENGE_BLOCKS,
            committee_epoch_blocks:
                PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_COMMITTEE_EPOCH_BLOCKS,
            signature_deadline_ms: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_SIGNATURE_DEADLINE_MS,
            preconfirmation_ttl_blocks:
                PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            committee_threshold_bps: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_THRESHOLD_BPS,
            emergency_threshold_bps:
                PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_EMERGENCY_THRESHOLD_BPS,
            low_fee_max_units: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_LOW_FEE_MAX_UNITS,
            low_fee_reserve_bps: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_LOW_FEE_RESERVE_BPS,
            base_challenge_bond_units: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_BASE_BOND_UNITS,
            slash_bps: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_SLASH_BPS,
            max_block_bytes: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_MAX_BLOCK_BYTES,
            max_preconfirmation_txs: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_MAX_PRECONF_TXS,
            max_records: PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEFAULT_MAX_RECORDS,
        }
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("config.config_id", &self.config_id)?;
        require_nonempty("config.protocol_version", &self.protocol_version)?;
        require_nonempty("config.chain_id", &self.chain_id)?;
        require_nonempty("config.hash_suite", &self.hash_suite)?;
        require_nonempty(
            "config.primary_signature_scheme",
            &self.primary_signature_scheme,
        )?;
        require_nonempty(
            "config.backup_signature_scheme",
            &self.backup_signature_scheme,
        )?;
        require_nonempty("config.commitment_scheme", &self.commitment_scheme)?;
        require_nonempty("config.fee_asset_id", &self.fee_asset_id)?;
        require_positive("config.fast_window_blocks", self.fast_window_blocks)?;
        require_positive(
            "config.fallback_challenge_window_blocks",
            self.fallback_challenge_window_blocks,
        )?;
        require_positive("config.committee_epoch_blocks", self.committee_epoch_blocks)?;
        require_positive("config.signature_deadline_ms", self.signature_deadline_ms)?;
        require_positive(
            "config.preconfirmation_ttl_blocks",
            self.preconfirmation_ttl_blocks,
        )?;
        require_bps(
            "config.committee_threshold_bps",
            self.committee_threshold_bps,
        )?;
        require_bps(
            "config.emergency_threshold_bps",
            self.emergency_threshold_bps,
        )?;
        require_bps("config.low_fee_reserve_bps", self.low_fee_reserve_bps)?;
        require_bps("config.slash_bps", self.slash_bps)?;
        require_positive("config.max_block_bytes", self.max_block_bytes)?;
        require_positive(
            "config.max_preconfirmation_txs",
            self.max_preconfirmation_txs,
        )?;
        if self.fast_window_blocks > self.fallback_challenge_window_blocks {
            return Err("config fast window exceeds fallback challenge window".to_string());
        }
        if self.committee_threshold_bps > self.emergency_threshold_bps {
            return Err("config emergency threshold must meet baseline threshold".to_string());
        }
        if self.max_records == 0 {
            return Err("config max records must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_sequencer_attestation_config",
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "primary_signature_scheme": self.primary_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "commitment_scheme": self.commitment_scheme,
            "fee_asset_id": self.fee_asset_id,
            "fast_window_blocks": self.fast_window_blocks,
            "fallback_challenge_window_blocks": self.fallback_challenge_window_blocks,
            "committee_epoch_blocks": self.committee_epoch_blocks,
            "signature_deadline_ms": self.signature_deadline_ms,
            "preconfirmation_ttl_blocks": self.preconfirmation_ttl_blocks,
            "committee_threshold_bps": self.committee_threshold_bps,
            "emergency_threshold_bps": self.emergency_threshold_bps,
            "low_fee_max_units": self.low_fee_max_units,
            "low_fee_reserve_bps": self.low_fee_reserve_bps,
            "base_challenge_bond_units": self.base_challenge_bond_units,
            "slash_bps": self.slash_bps,
            "max_block_bytes": self.max_block_bytes,
            "max_preconfirmation_txs": self.max_preconfirmation_txs,
            "max_records": self.max_records,
        })
    }

    pub fn state_root(&self) -> String {
        pq_fast_path_payload_root("PQ-FAST-PATH-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathCommitteeMember {
    pub member_id: String,
    pub operator_label: String,
    pub pq_public_key_root: String,
    pub weight: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub supported_schemes: BTreeSet<PqFastPathSignatureScheme>,
    pub slashed: bool,
}

impl PqFastPathCommitteeMember {
    pub fn new(
        operator_label: &str,
        pq_public_key_root: &str,
        weight: u64,
        active_from_height: u64,
        active_until_height: u64,
        supported_schemes: BTreeSet<PqFastPathSignatureScheme>,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("member.operator_label", operator_label)?;
        require_nonempty("member.pq_public_key_root", pq_public_key_root)?;
        require_positive("member.weight", weight)?;
        require_ordered_heights(
            "member.active_from_height",
            active_from_height,
            "member.active_until_height",
            active_until_height,
        )?;
        if supported_schemes.is_empty() {
            return Err("member must support at least one signature scheme".to_string());
        }
        let member_id =
            pq_fast_path_member_id(operator_label, pq_public_key_root, active_from_height);
        Ok(Self {
            member_id,
            operator_label: operator_label.to_string(),
            pq_public_key_root: pq_public_key_root.to_string(),
            weight,
            active_from_height,
            active_until_height,
            supported_schemes,
            slashed: false,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        !self.slashed && self.active_from_height <= height && height <= self.active_until_height
    }

    pub fn public_record(&self) -> Value {
        let supported_schemes = self
            .supported_schemes
            .iter()
            .map(|scheme| scheme.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "pq_fast_path_committee_member",
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "pq_public_key_root": self.pq_public_key_root,
            "weight": self.weight,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "supported_schemes": supported_schemes,
            "slashed": self.slashed,
        })
    }

    pub fn state_root(&self) -> String {
        pq_fast_path_payload_root("PQ-FAST-PATH-COMMITTEE-MEMBER", &self.public_record())
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("member.member_id", &self.member_id)?;
        require_nonempty("member.operator_label", &self.operator_label)?;
        require_nonempty("member.pq_public_key_root", &self.pq_public_key_root)?;
        require_positive("member.weight", self.weight)?;
        require_ordered_heights(
            "member.active_from_height",
            self.active_from_height,
            "member.active_until_height",
            self.active_until_height,
        )?;
        if self.supported_schemes.is_empty() {
            return Err("member supported schemes must be non-empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathCommittee {
    pub committee_id: String,
    pub label: String,
    pub policy: PqFastPathCommitteePolicy,
    pub members: BTreeMap<String, PqFastPathCommitteeMember>,
    pub threshold_bps: u64,
    pub emergency_threshold_bps: u64,
    pub epoch: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl PqFastPathCommittee {
    pub fn new(
        label: &str,
        policy: PqFastPathCommitteePolicy,
        members: BTreeMap<String, PqFastPathCommitteeMember>,
        threshold_bps: u64,
        emergency_threshold_bps: u64,
        epoch: u64,
        active_from_height: u64,
        active_until_height: u64,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("committee.label", label)?;
        if members.is_empty() {
            return Err("committee must include members".to_string());
        }
        require_bps("committee.threshold_bps", threshold_bps)?;
        require_bps("committee.emergency_threshold_bps", emergency_threshold_bps)?;
        if threshold_bps > emergency_threshold_bps {
            return Err("committee emergency threshold must meet baseline threshold".to_string());
        }
        require_ordered_heights(
            "committee.active_from_height",
            active_from_height,
            "committee.active_until_height",
            active_until_height,
        )?;
        let member_root = map_root(
            "PQ-FAST-PATH-COMMITTEE-MEMBERS",
            members
                .values()
                .map(PqFastPathCommitteeMember::public_record)
                .collect(),
        );
        let committee_id = pq_fast_path_committee_id(
            label,
            policy,
            &member_root,
            threshold_bps,
            epoch,
            active_from_height,
        );
        Ok(Self {
            committee_id,
            label: label.to_string(),
            policy,
            members,
            threshold_bps,
            emergency_threshold_bps,
            epoch,
            active_from_height,
            active_until_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.active_from_height <= height && height <= self.active_until_height
    }

    pub fn total_active_weight(&self, height: u64) -> u64 {
        self.members.values().fold(0_u64, |total, member| {
            if member.active_at(height) {
                total.saturating_add(member.weight)
            } else {
                total
            }
        })
    }

    pub fn threshold_weight(&self, height: u64, emergency: bool) -> u64 {
        let bps = if emergency {
            self.emergency_threshold_bps
        } else {
            self.threshold_bps
        };
        threshold_weight(self.total_active_weight(height), bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_committee",
            "committee_id": self.committee_id,
            "label": self.label,
            "policy": self.policy.as_str(),
            "members": self.members
                .values()
                .map(PqFastPathCommitteeMember::public_record)
                .collect::<Vec<_>>(),
            "threshold_bps": self.threshold_bps,
            "emergency_threshold_bps": self.emergency_threshold_bps,
            "epoch": self.epoch,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
        })
    }

    pub fn state_root(&self) -> String {
        pq_fast_path_payload_root("PQ-FAST-PATH-COMMITTEE", &self.public_record())
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("committee.committee_id", &self.committee_id)?;
        require_nonempty("committee.label", &self.label)?;
        if self.members.is_empty() {
            return Err("committee members must be non-empty".to_string());
        }
        require_bps("committee.threshold_bps", self.threshold_bps)?;
        require_bps(
            "committee.emergency_threshold_bps",
            self.emergency_threshold_bps,
        )?;
        if self.threshold_bps > self.emergency_threshold_bps {
            return Err("committee emergency threshold must meet baseline threshold".to_string());
        }
        require_ordered_heights(
            "committee.active_from_height",
            self.active_from_height,
            "committee.active_until_height",
            self.active_until_height,
        )?;
        for (member_id, member) in &self.members {
            if member_id != &member.member_id {
                return Err("committee member map key does not match member id".to_string());
            }
            member.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathPriorityLane {
    pub lane_id: String,
    pub lane: PqFastPathLane,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub reserve_bps: u64,
    pub priority_weight: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl PqFastPathPriorityLane {
    pub fn new(
        lane: PqFastPathLane,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        reserve_bps: u64,
        active_from_height: u64,
        active_until_height: u64,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("lane.sponsor_commitment", sponsor_commitment)?;
        require_nonempty("lane.fee_asset_id", fee_asset_id)?;
        require_bps("lane.reserve_bps", reserve_bps)?;
        require_ordered_heights(
            "lane.active_from_height",
            active_from_height,
            "lane.active_until_height",
            active_until_height,
        )?;
        let lane_id =
            pq_fast_path_lane_id(lane, sponsor_commitment, fee_asset_id, active_from_height);
        Ok(Self {
            lane_id,
            lane,
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            reserve_bps,
            priority_weight: lane.default_weight(),
            active_from_height,
            active_until_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.active_from_height <= height && height <= self.active_until_height
    }

    pub fn accepts_fee(&self, fee_units: u64) -> bool {
        !self.lane.low_fee() || fee_units <= self.max_fee_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_priority_lane",
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserve_bps": self.reserve_bps,
            "priority_weight": self.priority_weight,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
        })
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("lane.lane_id", &self.lane_id)?;
        require_nonempty("lane.sponsor_commitment", &self.sponsor_commitment)?;
        require_nonempty("lane.fee_asset_id", &self.fee_asset_id)?;
        require_bps("lane.reserve_bps", self.reserve_bps)?;
        require_positive("lane.priority_weight", self.priority_weight)?;
        require_ordered_heights(
            "lane.active_from_height",
            self.active_from_height,
            "lane.active_until_height",
            self.active_until_height,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathPreconfirmation {
    pub preconfirmation_id: String,
    pub sequencer_id: String,
    pub committee_id: String,
    pub lane_id: String,
    pub lane: PqFastPathLane,
    pub parent_block_root: String,
    pub block_payload_root: String,
    pub tx_set_root: String,
    pub data_availability_root: String,
    pub state_transition_root: String,
    pub fee_receipt_root: String,
    pub l2_height: u64,
    pub proposed_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_ends_at_height: u64,
    pub fee_units: u64,
    pub tx_count: u64,
    pub block_bytes: u64,
    pub nonce: u64,
    pub status: PqFastPathAttestationStatus,
    pub aggregate_signature_root: Option<String>,
    pub accepted_weight: u64,
    pub threshold_weight: u64,
}

impl PqFastPathPreconfirmation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequencer_id: &str,
        committee: &PqFastPathCommittee,
        lane: &PqFastPathPriorityLane,
        parent_block_root: &str,
        block_payload_root: &str,
        tx_set_root: &str,
        data_availability_root: &str,
        state_transition_root: &str,
        fee_receipt_root: &str,
        l2_height: u64,
        proposed_at_height: u64,
        ttl_blocks: u64,
        challenge_window_blocks: u64,
        fee_units: u64,
        tx_count: u64,
        block_bytes: u64,
        nonce: u64,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("preconfirmation.sequencer_id", sequencer_id)?;
        require_nonempty("preconfirmation.parent_block_root", parent_block_root)?;
        require_nonempty("preconfirmation.block_payload_root", block_payload_root)?;
        require_nonempty("preconfirmation.tx_set_root", tx_set_root)?;
        require_nonempty(
            "preconfirmation.data_availability_root",
            data_availability_root,
        )?;
        require_nonempty(
            "preconfirmation.state_transition_root",
            state_transition_root,
        )?;
        require_nonempty("preconfirmation.fee_receipt_root", fee_receipt_root)?;
        require_positive("preconfirmation.ttl_blocks", ttl_blocks)?;
        require_positive(
            "preconfirmation.challenge_window_blocks",
            challenge_window_blocks,
        )?;
        require_positive("preconfirmation.tx_count", tx_count)?;
        require_positive("preconfirmation.block_bytes", block_bytes)?;
        if !lane.accepts_fee(fee_units) {
            return Err("preconfirmation fee exceeds lane cap".to_string());
        }
        let expires_at_height = proposed_at_height.saturating_add(ttl_blocks);
        let challenge_window_ends_at_height =
            proposed_at_height.saturating_add(challenge_window_blocks);
        let transcript_root = pq_fast_path_preconfirmation_transcript_root(
            sequencer_id,
            &committee.committee_id,
            &lane.lane_id,
            parent_block_root,
            block_payload_root,
            tx_set_root,
            l2_height,
            nonce,
        );
        let preconfirmation_id = pq_fast_path_preconfirmation_id(
            sequencer_id,
            &committee.committee_id,
            &lane.lane_id,
            &transcript_root,
            proposed_at_height,
        );
        Ok(Self {
            preconfirmation_id,
            sequencer_id: sequencer_id.to_string(),
            committee_id: committee.committee_id.clone(),
            lane_id: lane.lane_id.clone(),
            lane: lane.lane,
            parent_block_root: parent_block_root.to_string(),
            block_payload_root: block_payload_root.to_string(),
            tx_set_root: tx_set_root.to_string(),
            data_availability_root: data_availability_root.to_string(),
            state_transition_root: state_transition_root.to_string(),
            fee_receipt_root: fee_receipt_root.to_string(),
            l2_height,
            proposed_at_height,
            expires_at_height,
            challenge_window_ends_at_height,
            fee_units,
            tx_count,
            block_bytes,
            nonce,
            status: PqFastPathAttestationStatus::Proposed,
            aggregate_signature_root: None,
            accepted_weight: 0,
            threshold_weight: committee
                .threshold_weight(proposed_at_height, lane.lane == PqFastPathLane::Emergency),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_preconfirmation",
            "preconfirmation_id": self.preconfirmation_id,
            "sequencer_id": self.sequencer_id,
            "committee_id": self.committee_id,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "parent_block_root": self.parent_block_root,
            "block_payload_root": self.block_payload_root,
            "tx_set_root": self.tx_set_root,
            "data_availability_root": self.data_availability_root,
            "state_transition_root": self.state_transition_root,
            "fee_receipt_root": self.fee_receipt_root,
            "l2_height": self.l2_height,
            "proposed_at_height": self.proposed_at_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_ends_at_height": self.challenge_window_ends_at_height,
            "fee_units": self.fee_units,
            "tx_count": self.tx_count,
            "block_bytes": self.block_bytes,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "aggregate_signature_root": self.aggregate_signature_root,
            "accepted_weight": self.accepted_weight,
            "threshold_weight": self.threshold_weight,
        })
    }

    pub fn state_root(&self) -> String {
        pq_fast_path_payload_root("PQ-FAST-PATH-PRECONFIRMATION", &self.public_record())
    }

    pub fn fast_accepted(&self) -> bool {
        self.accepted_weight >= self.threshold_weight
            && self.status == PqFastPathAttestationStatus::FastAccepted
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty(
            "preconfirmation.preconfirmation_id",
            &self.preconfirmation_id,
        )?;
        require_nonempty("preconfirmation.sequencer_id", &self.sequencer_id)?;
        require_nonempty("preconfirmation.committee_id", &self.committee_id)?;
        require_nonempty("preconfirmation.lane_id", &self.lane_id)?;
        require_nonempty("preconfirmation.parent_block_root", &self.parent_block_root)?;
        require_nonempty(
            "preconfirmation.block_payload_root",
            &self.block_payload_root,
        )?;
        require_nonempty("preconfirmation.tx_set_root", &self.tx_set_root)?;
        require_nonempty(
            "preconfirmation.data_availability_root",
            &self.data_availability_root,
        )?;
        require_nonempty(
            "preconfirmation.state_transition_root",
            &self.state_transition_root,
        )?;
        require_nonempty("preconfirmation.fee_receipt_root", &self.fee_receipt_root)?;
        require_ordered_heights(
            "preconfirmation.proposed_at_height",
            self.proposed_at_height,
            "preconfirmation.expires_at_height",
            self.expires_at_height,
        )?;
        require_ordered_heights(
            "preconfirmation.proposed_at_height",
            self.proposed_at_height,
            "preconfirmation.challenge_window_ends_at_height",
            self.challenge_window_ends_at_height,
        )?;
        require_positive("preconfirmation.tx_count", self.tx_count)?;
        require_positive("preconfirmation.block_bytes", self.block_bytes)?;
        if self.accepted_weight > 0 && self.aggregate_signature_root.is_none() {
            return Err("preconfirmation accepted weight requires aggregate root".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathCommitteeSignature {
    pub signature_id: String,
    pub preconfirmation_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub scheme: PqFastPathSignatureScheme,
    pub signed_transcript_root: String,
    pub signature_root: String,
    pub observed_latency_ms: u64,
    pub signed_at_height: u64,
    pub accepted: bool,
}

impl PqFastPathCommitteeSignature {
    pub fn new(
        preconfirmation_id: &str,
        committee_id: &str,
        member: &PqFastPathCommitteeMember,
        scheme: PqFastPathSignatureScheme,
        signed_transcript_root: &str,
        observed_latency_ms: u64,
        signed_at_height: u64,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("signature.preconfirmation_id", preconfirmation_id)?;
        require_nonempty("signature.committee_id", committee_id)?;
        require_nonempty("signature.signed_transcript_root", signed_transcript_root)?;
        if !member.supported_schemes.contains(&scheme) {
            return Err("committee member does not support signature scheme".to_string());
        }
        let signature_root =
            pq_fast_path_signature_root(&member.member_id, signed_transcript_root, scheme);
        let signature_id = pq_fast_path_signature_id(
            preconfirmation_id,
            committee_id,
            &member.member_id,
            &signature_root,
            signed_at_height,
        );
        Ok(Self {
            signature_id,
            preconfirmation_id: preconfirmation_id.to_string(),
            committee_id: committee_id.to_string(),
            member_id: member.member_id.clone(),
            scheme,
            signed_transcript_root: signed_transcript_root.to_string(),
            signature_root,
            observed_latency_ms,
            signed_at_height,
            accepted: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_committee_signature",
            "signature_id": self.signature_id,
            "preconfirmation_id": self.preconfirmation_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "scheme": self.scheme.as_str(),
            "signed_transcript_root": self.signed_transcript_root,
            "signature_root": self.signature_root,
            "observed_latency_ms": self.observed_latency_ms,
            "signed_at_height": self.signed_at_height,
            "accepted": self.accepted,
        })
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("signature.signature_id", &self.signature_id)?;
        require_nonempty("signature.preconfirmation_id", &self.preconfirmation_id)?;
        require_nonempty("signature.committee_id", &self.committee_id)?;
        require_nonempty("signature.member_id", &self.member_id)?;
        require_nonempty(
            "signature.signed_transcript_root",
            &self.signed_transcript_root,
        )?;
        require_nonempty("signature.signature_root", &self.signature_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathChallenge {
    pub challenge_id: String,
    pub preconfirmation_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: PqFastPathChallengeKind,
    pub evidence_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub fallback_window_ends_at_height: u64,
    pub status: PqFastPathChallengeStatus,
    pub settlement_action: Option<PqFastPathSettlementAction>,
}

impl PqFastPathChallenge {
    pub fn new(
        preconfirmation_id: &str,
        challenger_commitment: &str,
        challenge_kind: PqFastPathChallengeKind,
        evidence_root: &str,
        bond_units: u64,
        opened_at_height: u64,
        fallback_window_blocks: u64,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("challenge.preconfirmation_id", preconfirmation_id)?;
        require_nonempty("challenge.challenger_commitment", challenger_commitment)?;
        require_nonempty("challenge.evidence_root", evidence_root)?;
        require_positive("challenge.bond_units", bond_units)?;
        require_positive("challenge.fallback_window_blocks", fallback_window_blocks)?;
        let fallback_window_ends_at_height =
            opened_at_height.saturating_add(fallback_window_blocks);
        let challenge_id = pq_fast_path_challenge_id(
            preconfirmation_id,
            challenger_commitment,
            challenge_kind,
            evidence_root,
            opened_at_height,
        );
        let status = if challenge_kind.escalates_immediately() {
            PqFastPathChallengeStatus::FallbackWindow
        } else {
            PqFastPathChallengeStatus::Open
        };
        Ok(Self {
            challenge_id,
            preconfirmation_id: preconfirmation_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            challenge_kind,
            evidence_root: evidence_root.to_string(),
            bond_units,
            opened_at_height,
            fallback_window_ends_at_height,
            status,
            settlement_action: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_challenge",
            "challenge_id": self.challenge_id,
            "preconfirmation_id": self.preconfirmation_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "evidence_root": self.evidence_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "fallback_window_ends_at_height": self.fallback_window_ends_at_height,
            "status": self.status.as_str(),
            "settlement_action": self.settlement_action.map(PqFastPathSettlementAction::as_str),
        })
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("challenge.challenge_id", &self.challenge_id)?;
        require_nonempty("challenge.preconfirmation_id", &self.preconfirmation_id)?;
        require_nonempty(
            "challenge.challenger_commitment",
            &self.challenger_commitment,
        )?;
        require_nonempty("challenge.evidence_root", &self.evidence_root)?;
        require_positive("challenge.bond_units", self.bond_units)?;
        require_ordered_heights(
            "challenge.opened_at_height",
            self.opened_at_height,
            "challenge.fallback_window_ends_at_height",
            self.fallback_window_ends_at_height,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathFeeLaneReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub preconfirmation_id: String,
    pub payer_commitment: String,
    pub fee_asset_id: String,
    pub charged_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub issued_at_height: u64,
}

impl PqFastPathFeeLaneReceipt {
    pub fn new(
        lane: &PqFastPathPriorityLane,
        preconfirmation_id: &str,
        payer_commitment: &str,
        charged_fee_units: u64,
        issued_at_height: u64,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("fee_receipt.preconfirmation_id", preconfirmation_id)?;
        require_nonempty("fee_receipt.payer_commitment", payer_commitment)?;
        if !lane.accepts_fee(charged_fee_units) {
            return Err("fee receipt exceeds lane cap".to_string());
        }
        let sponsored_fee_units = if lane.lane.low_fee() {
            lane.max_fee_units.saturating_sub(charged_fee_units)
        } else {
            0
        };
        let receipt_id = pq_fast_path_fee_receipt_id(
            &lane.lane_id,
            preconfirmation_id,
            payer_commitment,
            charged_fee_units,
            issued_at_height,
        );
        Ok(Self {
            receipt_id,
            lane_id: lane.lane_id.clone(),
            preconfirmation_id: preconfirmation_id.to_string(),
            payer_commitment: payer_commitment.to_string(),
            fee_asset_id: lane.fee_asset_id.clone(),
            charged_fee_units,
            sponsored_fee_units,
            issued_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_fee_lane_receipt",
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "preconfirmation_id": self.preconfirmation_id,
            "payer_commitment": self.payer_commitment,
            "fee_asset_id": self.fee_asset_id,
            "charged_fee_units": self.charged_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("fee_receipt.receipt_id", &self.receipt_id)?;
        require_nonempty("fee_receipt.lane_id", &self.lane_id)?;
        require_nonempty("fee_receipt.preconfirmation_id", &self.preconfirmation_id)?;
        require_nonempty("fee_receipt.payer_commitment", &self.payer_commitment)?;
        require_nonempty("fee_receipt.fee_asset_id", &self.fee_asset_id)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathPublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
    pub payload_root: String,
}

impl PqFastPathPublicEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> Self {
        let payload_root = pq_fast_path_payload_root("PQ-FAST-PATH-EVENT-PAYLOAD", payload);
        let event_id = pq_fast_path_event_id(event_kind, subject_id, height, sequence);
        Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            emitted_at_height: height,
            sequence,
            payload_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fast_path_public_event",
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
            "payload_root": self.payload_root,
        })
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<()> {
        require_nonempty("event.event_id", &self.event_id)?;
        require_nonempty("event.event_kind", &self.event_kind)?;
        require_nonempty("event.subject_id", &self.subject_id)?;
        require_nonempty("event.payload_root", &self.payload_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathSequencerAttestationRoots {
    pub config_root: String,
    pub committee_root: String,
    pub lane_root: String,
    pub preconfirmation_root: String,
    pub signature_root: String,
    pub challenge_root: String,
    pub fee_receipt_root: String,
    pub public_event_root: String,
}

impl PqFastPathSequencerAttestationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "committee_root": self.committee_root,
            "lane_root": self.lane_root,
            "preconfirmation_root": self.preconfirmation_root,
            "signature_root": self.signature_root,
            "challenge_root": self.challenge_root,
            "fee_receipt_root": self.fee_receipt_root,
            "public_event_root": self.public_event_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_fast_path_payload_root("PQ-FAST-PATH-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathSequencerAttestationCounters {
    pub committee_count: u64,
    pub committee_member_count: u64,
    pub active_committee_count: u64,
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub preconfirmation_count: u64,
    pub fast_accepted_count: u64,
    pub open_challenge_count: u64,
    pub signature_count: u64,
    pub fee_receipt_count: u64,
    pub public_event_count: u64,
    pub low_fee_preconfirmation_count: u64,
    pub total_fee_units: u64,
    pub sponsored_fee_units: u64,
}

impl PqFastPathSequencerAttestationCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_count": self.committee_count,
            "committee_member_count": self.committee_member_count,
            "active_committee_count": self.active_committee_count,
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "preconfirmation_count": self.preconfirmation_count,
            "fast_accepted_count": self.fast_accepted_count,
            "open_challenge_count": self.open_challenge_count,
            "signature_count": self.signature_count,
            "fee_receipt_count": self.fee_receipt_count,
            "public_event_count": self.public_event_count,
            "low_fee_preconfirmation_count": self.low_fee_preconfirmation_count,
            "total_fee_units": self.total_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFastPathSequencerAttestationState {
    pub config: PqFastPathSequencerAttestationConfig,
    pub height: u64,
    pub status: String,
    pub committees: BTreeMap<String, PqFastPathCommittee>,
    pub lanes: BTreeMap<String, PqFastPathPriorityLane>,
    pub preconfirmations: BTreeMap<String, PqFastPathPreconfirmation>,
    pub signatures: BTreeMap<String, PqFastPathCommitteeSignature>,
    pub challenges: BTreeMap<String, PqFastPathChallenge>,
    pub fee_receipts: BTreeMap<String, PqFastPathFeeLaneReceipt>,
    pub public_events: BTreeMap<String, PqFastPathPublicEvent>,
}

impl PqFastPathSequencerAttestationState {
    pub fn new(
        config: PqFastPathSequencerAttestationConfig,
        height: u64,
    ) -> PqFastPathSequencerAttestationResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            status: STATE_STATUS_BOOTSTRAPPING.to_string(),
            committees: BTreeMap::new(),
            lanes: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            signatures: BTreeMap::new(),
            challenges: BTreeMap::new(),
            fee_receipts: BTreeMap::new(),
            public_events: BTreeMap::new(),
        })
    }

    pub fn devnet(sequencer_label: &str) -> PqFastPathSequencerAttestationResult<Self> {
        require_nonempty("devnet.sequencer_label", sequencer_label)?;
        let config = PqFastPathSequencerAttestationConfig::devnet();
        let height = PQ_FAST_PATH_SEQUENCER_ATTESTATION_DEVNET_HEIGHT;
        let mut state = Self::new(config, height)?;
        let active_until_height = height.saturating_add(state.config.committee_epoch_blocks);
        let member_schemes = BTreeSet::from([
            PqFastPathSignatureScheme::MlDsa65,
            PqFastPathSignatureScheme::SlhDsaShake128s,
            PqFastPathSignatureScheme::HybridTranscript,
        ]);
        let members = [
            ("attestor-alpha", 4_u64),
            ("attestor-beta", 3_u64),
            ("attestor-gamma", 3_u64),
            ("attestor-delta", 2_u64),
        ]
        .iter()
        .map(|(label, weight)| {
            let key_root = pq_fast_path_string_commitment("PQ-FAST-PATH-DEVNET-KEY", label);
            PqFastPathCommitteeMember::new(
                label,
                &key_root,
                *weight,
                height,
                active_until_height,
                member_schemes.clone(),
            )
        })
        .collect::<PqFastPathSequencerAttestationResult<Vec<_>>>()?;
        let member_map = members
            .into_iter()
            .map(|member| (member.member_id.clone(), member))
            .collect::<BTreeMap<_, _>>();
        let committee = PqFastPathCommittee::new(
            "devnet-fast-path-attestors",
            PqFastPathCommitteePolicy::WeightedThreshold,
            member_map,
            state.config.committee_threshold_bps,
            state.config.emergency_threshold_bps,
            0,
            height,
            active_until_height,
        )?;
        let committee_id = state.register_committee(committee)?;
        let low_fee_lane = PqFastPathPriorityLane::new(
            PqFastPathLane::LowFeePublicGood,
            "devnet-low-fee-sponsor",
            &state.config.fee_asset_id,
            state.config.low_fee_max_units,
            state.config.low_fee_reserve_bps,
            height,
            active_until_height,
        )?;
        let lane_id = state.open_priority_lane(low_fee_lane)?;
        state.status = STATE_STATUS_ACTIVE.to_string();
        let sequencer_id =
            pq_fast_path_string_commitment("PQ-FAST-PATH-DEVNET-SEQUENCER", sequencer_label);
        let preconfirmation_id = state.submit_preconfirmation(
            &sequencer_id,
            &committee_id,
            &lane_id,
            "devnet-parent-block-root",
            "devnet-block-payload-root",
            "devnet-tx-set-root",
            "devnet-data-availability-root",
            "devnet-state-transition-root",
            "devnet-fee-receipt-root",
            height.saturating_add(1),
            state.config.low_fee_max_units,
            32,
            65_536,
            0,
        )?;
        let committee = match state.committees.get(&committee_id) {
            Some(committee) => committee.clone(),
            None => return Err("devnet committee not found after registration".to_string()),
        };
        let transcript_root =
            pq_fast_path_string_commitment("PQ-FAST-PATH-DEVNET-TRANSCRIPT", &preconfirmation_id);
        for member_id in committee.members.keys().take(3) {
            state.add_committee_signature(
                &preconfirmation_id,
                member_id,
                PqFastPathSignatureScheme::MlDsa65,
                &transcript_root,
                180,
            )?;
        }
        state.issue_fee_lane_receipt(
            &lane_id,
            &preconfirmation_id,
            "devnet-low-fee-payer",
            state.config.low_fee_max_units,
        )?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn register_committee(
        &mut self,
        committee: PqFastPathCommittee,
    ) -> PqFastPathSequencerAttestationResult<String> {
        committee.validate()?;
        if self.committees.len() >= self.config.max_records {
            return Err("committee record cap reached".to_string());
        }
        if self.committees.contains_key(&committee.committee_id) {
            return Err("committee already registered".to_string());
        }
        let committee_id = committee.committee_id.clone();
        self.record_event(
            "committee_registered",
            &committee_id,
            &committee.public_record(),
        );
        self.committees.insert(committee_id.clone(), committee);
        Ok(committee_id)
    }

    pub fn open_priority_lane(
        &mut self,
        lane: PqFastPathPriorityLane,
    ) -> PqFastPathSequencerAttestationResult<String> {
        lane.validate()?;
        if self.lanes.len() >= self.config.max_records {
            return Err("lane record cap reached".to_string());
        }
        if self.lanes.contains_key(&lane.lane_id) {
            return Err("priority lane already exists".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.record_event("priority_lane_opened", &lane_id, &lane.public_record());
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_preconfirmation(
        &mut self,
        sequencer_id: &str,
        committee_id: &str,
        lane_id: &str,
        parent_block_root: &str,
        block_payload_root: &str,
        tx_set_root: &str,
        data_availability_root: &str,
        state_transition_root: &str,
        fee_receipt_root: &str,
        l2_height: u64,
        fee_units: u64,
        tx_count: u64,
        block_bytes: u64,
        nonce: u64,
    ) -> PqFastPathSequencerAttestationResult<String> {
        if self.preconfirmations.len() >= self.config.max_records {
            return Err("preconfirmation record cap reached".to_string());
        }
        if tx_count > self.config.max_preconfirmation_txs {
            return Err("preconfirmation exceeds tx limit".to_string());
        }
        if block_bytes > self.config.max_block_bytes {
            return Err("preconfirmation exceeds block byte limit".to_string());
        }
        let committee = match self.committees.get(committee_id) {
            Some(committee) => committee.clone(),
            None => return Err("committee not found".to_string()),
        };
        if !committee.active_at(self.height) {
            return Err("committee inactive at current height".to_string());
        }
        let lane = match self.lanes.get(lane_id) {
            Some(lane) => lane.clone(),
            None => return Err("priority lane not found".to_string()),
        };
        if !lane.active_at(self.height) {
            return Err("priority lane inactive at current height".to_string());
        }
        let preconfirmation = PqFastPathPreconfirmation::new(
            sequencer_id,
            &committee,
            &lane,
            parent_block_root,
            block_payload_root,
            tx_set_root,
            data_availability_root,
            state_transition_root,
            fee_receipt_root,
            l2_height,
            self.height,
            self.config.preconfirmation_ttl_blocks,
            self.config.fallback_challenge_window_blocks,
            fee_units,
            tx_count,
            block_bytes,
            nonce,
        )?;
        let preconfirmation_id = preconfirmation.preconfirmation_id.clone();
        if self.preconfirmations.contains_key(&preconfirmation_id) {
            return Err("preconfirmation already exists".to_string());
        }
        self.record_event(
            "preconfirmation_submitted",
            &preconfirmation_id,
            &preconfirmation.public_record(),
        );
        self.preconfirmations
            .insert(preconfirmation_id.clone(), preconfirmation);
        Ok(preconfirmation_id)
    }

    pub fn add_committee_signature(
        &mut self,
        preconfirmation_id: &str,
        member_id: &str,
        scheme: PqFastPathSignatureScheme,
        signed_transcript_root: &str,
        observed_latency_ms: u64,
    ) -> PqFastPathSequencerAttestationResult<String> {
        if self.signatures.len() >= self.config.max_records {
            return Err("signature record cap reached".to_string());
        }
        let preconfirmation = match self.preconfirmations.get(preconfirmation_id) {
            Some(preconfirmation) => preconfirmation.clone(),
            None => return Err("preconfirmation not found".to_string()),
        };
        if preconfirmation.status.terminal() {
            return Err("preconfirmation is terminal".to_string());
        }
        if self.height > preconfirmation.expires_at_height {
            return Err("preconfirmation expired".to_string());
        }
        let committee = match self.committees.get(&preconfirmation.committee_id) {
            Some(committee) => committee.clone(),
            None => return Err("committee not found".to_string()),
        };
        let member = match committee.members.get(member_id) {
            Some(member) => member.clone(),
            None => return Err("committee member not found".to_string()),
        };
        if !member.active_at(self.height) {
            return Err("committee member inactive at current height".to_string());
        }
        let duplicate_member_signature = self.signatures.values().any(|signature| {
            signature.preconfirmation_id == preconfirmation_id && signature.member_id == member_id
        });
        if duplicate_member_signature {
            return Err("committee member already signed preconfirmation".to_string());
        }
        let signature = PqFastPathCommitteeSignature::new(
            preconfirmation_id,
            &committee.committee_id,
            &member,
            scheme,
            signed_transcript_root,
            observed_latency_ms,
            self.height,
        )?;
        let signature_id = signature.signature_id.clone();
        if self.signatures.contains_key(&signature_id) {
            return Err("committee signature already exists".to_string());
        }
        self.signatures.insert(signature_id.clone(), signature);
        self.refresh_preconfirmation_quorum(preconfirmation_id)?;
        let event_payload = match self.preconfirmations.get(preconfirmation_id) {
            Some(preconfirmation) => preconfirmation.public_record(),
            None => json!({"preconfirmation_id": preconfirmation_id}),
        };
        self.record_event("committee_signature_added", &signature_id, &event_payload);
        Ok(signature_id)
    }

    pub fn open_challenge(
        &mut self,
        preconfirmation_id: &str,
        challenger_commitment: &str,
        challenge_kind: PqFastPathChallengeKind,
        evidence_root: &str,
        bond_units: u64,
    ) -> PqFastPathSequencerAttestationResult<String> {
        if self.challenges.len() >= self.config.max_records {
            return Err("challenge record cap reached".to_string());
        }
        if bond_units < self.config.base_challenge_bond_units {
            return Err("challenge bond below configured minimum".to_string());
        }
        let preconfirmation = match self.preconfirmations.get(preconfirmation_id) {
            Some(preconfirmation) => preconfirmation.clone(),
            None => return Err("preconfirmation not found".to_string()),
        };
        if self.height > preconfirmation.challenge_window_ends_at_height {
            return Err("fallback challenge window closed".to_string());
        }
        let challenge = PqFastPathChallenge::new(
            preconfirmation_id,
            challenger_commitment,
            challenge_kind,
            evidence_root,
            bond_units,
            self.height,
            self.config.fallback_challenge_window_blocks,
        )?;
        let challenge_id = challenge.challenge_id.clone();
        if self.challenges.contains_key(&challenge_id) {
            return Err("challenge already exists".to_string());
        }
        if let Some(stored_preconfirmation) = self.preconfirmations.get_mut(preconfirmation_id) {
            stored_preconfirmation.status = if challenge_kind.escalates_immediately() {
                PqFastPathAttestationStatus::FallbackRequired
            } else {
                PqFastPathAttestationStatus::ChallengeOpen
            };
        }
        self.status = STATE_STATUS_CHALLENGE_MODE.to_string();
        self.record_event(
            "challenge_opened",
            &challenge_id,
            &challenge.public_record(),
        );
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        sustained: bool,
        settlement_action: PqFastPathSettlementAction,
    ) -> PqFastPathSequencerAttestationResult<()> {
        let preconfirmation_id = match self.challenges.get(challenge_id) {
            Some(challenge) => challenge.preconfirmation_id.clone(),
            None => return Err("challenge not found".to_string()),
        };
        if let Some(challenge) = self.challenges.get_mut(challenge_id) {
            if challenge.status.terminal() {
                return Err("challenge already terminal".to_string());
            }
            challenge.status = if sustained {
                PqFastPathChallengeStatus::Sustained
            } else {
                PqFastPathChallengeStatus::Dismissed
            };
            challenge.settlement_action = Some(settlement_action);
        }
        if let Some(preconfirmation) = self.preconfirmations.get_mut(&preconfirmation_id) {
            preconfirmation.status = if sustained {
                PqFastPathAttestationStatus::Rejected
            } else if preconfirmation.fast_accepted() {
                PqFastPathAttestationStatus::Finalized
            } else {
                PqFastPathAttestationStatus::FallbackRequired
            };
        }
        let payload = match self.challenges.get(challenge_id) {
            Some(challenge) => challenge.public_record(),
            None => json!({"challenge_id": challenge_id}),
        };
        self.record_event("challenge_resolved", challenge_id, &payload);
        if self
            .challenges
            .values()
            .all(|challenge| challenge.status.terminal())
        {
            self.status = STATE_STATUS_ACTIVE.to_string();
        }
        Ok(())
    }

    pub fn issue_fee_lane_receipt(
        &mut self,
        lane_id: &str,
        preconfirmation_id: &str,
        payer_commitment: &str,
        charged_fee_units: u64,
    ) -> PqFastPathSequencerAttestationResult<String> {
        if self.fee_receipts.len() >= self.config.max_records {
            return Err("fee receipt record cap reached".to_string());
        }
        let lane = match self.lanes.get(lane_id) {
            Some(lane) => lane.clone(),
            None => return Err("priority lane not found".to_string()),
        };
        if !self.preconfirmations.contains_key(preconfirmation_id) {
            return Err("preconfirmation not found".to_string());
        }
        let receipt = PqFastPathFeeLaneReceipt::new(
            &lane,
            preconfirmation_id,
            payer_commitment,
            charged_fee_units,
            self.height,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        if self.fee_receipts.contains_key(&receipt_id) {
            return Err("fee receipt already exists".to_string());
        }
        self.record_event(
            "fee_lane_receipt_issued",
            &receipt_id,
            &receipt.public_record(),
        );
        self.fee_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn roots(&self) -> PqFastPathSequencerAttestationRoots {
        PqFastPathSequencerAttestationRoots {
            config_root: self.config.state_root(),
            committee_root: map_root(
                "PQ-FAST-PATH-COMMITTEES",
                self.committees
                    .values()
                    .map(PqFastPathCommittee::public_record)
                    .collect(),
            ),
            lane_root: map_root(
                "PQ-FAST-PATH-LANES",
                self.lanes
                    .values()
                    .map(PqFastPathPriorityLane::public_record)
                    .collect(),
            ),
            preconfirmation_root: map_root(
                "PQ-FAST-PATH-PRECONFIRMATIONS",
                self.preconfirmations
                    .values()
                    .map(PqFastPathPreconfirmation::public_record)
                    .collect(),
            ),
            signature_root: map_root(
                "PQ-FAST-PATH-SIGNATURES",
                self.signatures
                    .values()
                    .map(PqFastPathCommitteeSignature::public_record)
                    .collect(),
            ),
            challenge_root: map_root(
                "PQ-FAST-PATH-CHALLENGES",
                self.challenges
                    .values()
                    .map(PqFastPathChallenge::public_record)
                    .collect(),
            ),
            fee_receipt_root: map_root(
                "PQ-FAST-PATH-FEE-RECEIPTS",
                self.fee_receipts
                    .values()
                    .map(PqFastPathFeeLaneReceipt::public_record)
                    .collect(),
            ),
            public_event_root: map_root(
                "PQ-FAST-PATH-PUBLIC-EVENTS",
                self.public_events
                    .values()
                    .map(PqFastPathPublicEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PqFastPathSequencerAttestationCounters {
        let committee_member_count = self.committees.values().fold(0_u64, |total, committee| {
            total.saturating_add(committee.members.len() as u64)
        });
        let active_committee_count = self
            .committees
            .values()
            .filter(|committee| committee.active_at(self.height))
            .count() as u64;
        let active_lane_count = self
            .lanes
            .values()
            .filter(|lane| lane.active_at(self.height))
            .count() as u64;
        let fast_accepted_count = self
            .preconfirmations
            .values()
            .filter(|preconfirmation| preconfirmation.fast_accepted())
            .count() as u64;
        let open_challenge_count = self
            .challenges
            .values()
            .filter(|challenge| !challenge.status.terminal())
            .count() as u64;
        let low_fee_preconfirmation_count = self
            .preconfirmations
            .values()
            .filter(|preconfirmation| preconfirmation.lane.low_fee())
            .count() as u64;
        let total_fee_units = self.fee_receipts.values().fold(0_u64, |total, receipt| {
            total.saturating_add(receipt.charged_fee_units)
        });
        let sponsored_fee_units = self.fee_receipts.values().fold(0_u64, |total, receipt| {
            total.saturating_add(receipt.sponsored_fee_units)
        });
        PqFastPathSequencerAttestationCounters {
            committee_count: self.committees.len() as u64,
            committee_member_count,
            active_committee_count,
            lane_count: self.lanes.len() as u64,
            active_lane_count,
            preconfirmation_count: self.preconfirmations.len() as u64,
            fast_accepted_count,
            open_challenge_count,
            signature_count: self.signatures.len() as u64,
            fee_receipt_count: self.fee_receipts.len() as u64,
            public_event_count: self.public_events.len() as u64,
            low_fee_preconfirmation_count,
            total_fee_units,
            sponsored_fee_units,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_fast_path_sequencer_attestation_state",
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "status": self.status,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_fast_path_payload_root("PQ-FAST-PATH-STATE", &self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PqFastPathSequencerAttestationResult<String> {
        self.config.validate()?;
        require_state_status("state.status", &self.status)?;
        for (committee_id, committee) in &self.committees {
            if committee_id != &committee.committee_id {
                return Err("committee map key does not match committee id".to_string());
            }
            committee.validate()?;
        }
        for (lane_id, lane) in &self.lanes {
            if lane_id != &lane.lane_id {
                return Err("lane map key does not match lane id".to_string());
            }
            lane.validate()?;
        }
        for (preconfirmation_id, preconfirmation) in &self.preconfirmations {
            if preconfirmation_id != &preconfirmation.preconfirmation_id {
                return Err("preconfirmation map key does not match preconfirmation id".to_string());
            }
            preconfirmation.validate()?;
            require_map_key(
                "preconfirmation.committee_id",
                &preconfirmation.committee_id,
                &self.committees,
            )?;
            require_map_key(
                "preconfirmation.lane_id",
                &preconfirmation.lane_id,
                &self.lanes,
            )?;
            if preconfirmation.tx_count > self.config.max_preconfirmation_txs {
                return Err("preconfirmation exceeds configured tx cap".to_string());
            }
            if preconfirmation.block_bytes > self.config.max_block_bytes {
                return Err("preconfirmation exceeds configured byte cap".to_string());
            }
        }
        for (signature_id, signature) in &self.signatures {
            if signature_id != &signature.signature_id {
                return Err("signature map key does not match signature id".to_string());
            }
            signature.validate()?;
            require_map_key(
                "signature.preconfirmation_id",
                &signature.preconfirmation_id,
                &self.preconfirmations,
            )?;
            require_map_key(
                "signature.committee_id",
                &signature.committee_id,
                &self.committees,
            )?;
            let committee = match self.committees.get(&signature.committee_id) {
                Some(committee) => committee,
                None => return Err("signature committee missing".to_string()),
            };
            if !committee.members.contains_key(&signature.member_id) {
                return Err("signature references unknown committee member".to_string());
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            if challenge_id != &challenge.challenge_id {
                return Err("challenge map key does not match challenge id".to_string());
            }
            challenge.validate()?;
            require_map_key(
                "challenge.preconfirmation_id",
                &challenge.preconfirmation_id,
                &self.preconfirmations,
            )?;
            if challenge.bond_units < self.config.base_challenge_bond_units {
                return Err("challenge bond below configured minimum".to_string());
            }
        }
        for (receipt_id, receipt) in &self.fee_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("fee receipt map key does not match receipt id".to_string());
            }
            receipt.validate()?;
            require_map_key("fee_receipt.lane_id", &receipt.lane_id, &self.lanes)?;
            require_map_key(
                "fee_receipt.preconfirmation_id",
                &receipt.preconfirmation_id,
                &self.preconfirmations,
            )?;
        }
        for (event_id, event) in &self.public_events {
            if event_id != &event.event_id {
                return Err("event map key does not match event id".to_string());
            }
            event.validate()?;
        }
        Ok(self.state_root())
    }

    fn refresh_preconfirmation_quorum(
        &mut self,
        preconfirmation_id: &str,
    ) -> PqFastPathSequencerAttestationResult<()> {
        let preconfirmation = match self.preconfirmations.get(preconfirmation_id) {
            Some(preconfirmation) => preconfirmation.clone(),
            None => return Err("preconfirmation not found".to_string()),
        };
        let committee = match self.committees.get(&preconfirmation.committee_id) {
            Some(committee) => committee,
            None => return Err("committee not found".to_string()),
        };
        let mut signer_ids = BTreeSet::new();
        let mut accepted_weight = 0_u64;
        for signature in self.signatures.values().filter(|signature| {
            signature.preconfirmation_id == preconfirmation_id && signature.accepted
        }) {
            if signer_ids.insert(signature.member_id.clone()) {
                if let Some(member) = committee.members.get(&signature.member_id) {
                    accepted_weight = accepted_weight.saturating_add(member.weight);
                }
            }
        }
        let aggregate_signature_root =
            pq_fast_path_ids_root("PQ-FAST-PATH-AGGREGATE-SIGNATURES", &signer_ids);
        if let Some(stored_preconfirmation) = self.preconfirmations.get_mut(preconfirmation_id) {
            stored_preconfirmation.accepted_weight = accepted_weight;
            stored_preconfirmation.aggregate_signature_root = Some(aggregate_signature_root);
            if accepted_weight >= stored_preconfirmation.threshold_weight {
                stored_preconfirmation.status = PqFastPathAttestationStatus::FastAccepted;
            } else {
                stored_preconfirmation.status = PqFastPathAttestationStatus::CollectingSignatures;
            }
        }
        Ok(())
    }

    fn record_event(&mut self, event_kind: &str, subject_id: &str, payload: &Value) {
        let sequence = self.public_events.len() as u64;
        let event =
            PqFastPathPublicEvent::new(event_kind, subject_id, payload, self.height, sequence);
        self.public_events.insert(event.event_id.clone(), event);
    }
}

pub fn pq_fast_path_config_id(chain_id: &str, fee_asset_id: &str) -> String {
    domain_hash(
        "PQ-FAST-PATH-CONFIG-ID",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(fee_asset_id),
            HashPart::Str(PQ_FAST_PATH_SEQUENCER_ATTESTATION_PROTOCOL_VERSION),
        ],
        32,
    )
}

pub fn pq_fast_path_member_id(
    operator_label: &str,
    pq_public_key_root: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_committee_id(
    label: &str,
    policy: PqFastPathCommitteePolicy,
    member_root: &str,
    threshold_bps: u64,
    epoch: u64,
    active_from_height: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(policy.as_str()),
            HashPart::Str(member_root),
            HashPart::Int(threshold_bps as i128),
            HashPart::Int(epoch as i128),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_lane_id(
    lane: PqFastPathLane,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_preconfirmation_transcript_root(
    sequencer_id: &str,
    committee_id: &str,
    lane_id: &str,
    parent_block_root: &str,
    block_payload_root: &str,
    tx_set_root: &str,
    l2_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-PRECONFIRMATION-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sequencer_id),
            HashPart::Str(committee_id),
            HashPart::Str(lane_id),
            HashPart::Str(parent_block_root),
            HashPart::Str(block_payload_root),
            HashPart::Str(tx_set_root),
            HashPart::Int(l2_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_preconfirmation_id(
    sequencer_id: &str,
    committee_id: &str,
    lane_id: &str,
    transcript_root: &str,
    proposed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-PRECONFIRMATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sequencer_id),
            HashPart::Str(committee_id),
            HashPart::Str(lane_id),
            HashPart::Str(transcript_root),
            HashPart::Int(proposed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_signature_root(
    member_id: &str,
    signed_transcript_root: &str,
    scheme: PqFastPathSignatureScheme,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-SIGNATURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(member_id),
            HashPart::Str(signed_transcript_root),
            HashPart::Str(scheme.as_str()),
        ],
        32,
    )
}

pub fn pq_fast_path_signature_id(
    preconfirmation_id: &str,
    committee_id: &str,
    member_id: &str,
    signature_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-SIGNATURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(preconfirmation_id),
            HashPart::Str(committee_id),
            HashPart::Str(member_id),
            HashPart::Str(signature_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_challenge_id(
    preconfirmation_id: &str,
    challenger_commitment: &str,
    challenge_kind: PqFastPathChallengeKind,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(preconfirmation_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_fee_receipt_id(
    lane_id: &str,
    preconfirmation_id: &str,
    payer_commitment: &str,
    charged_fee_units: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-FEE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(preconfirmation_id),
            HashPart::Str(payer_commitment),
            HashPart::Int(charged_fee_units as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_event_id(
    event_kind: &str,
    subject_id: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-FAST-PATH-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn pq_fast_path_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_FAST_PATH_SEQUENCER_ATTESTATION_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn pq_fast_path_ids_root(domain: &str, ids: &BTreeSet<String>) -> String {
    let leaves = ids.iter().map(|id| json!(id)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn pq_fast_path_string_commitment(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_FAST_PATH_SEQUENCER_ATTESTATION_COMMITMENT_SCHEME),
            HashPart::Str(value),
        ],
        32,
    )
}

fn map_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn threshold_weight(total_weight: u64, threshold_bps: u64) -> u64 {
    let numerator = (total_weight as u128).saturating_mul(threshold_bps as u128);
    let rounded = numerator
        .saturating_add((PQ_FAST_PATH_SEQUENCER_ATTESTATION_MAX_BPS - 1) as u128)
        / PQ_FAST_PATH_SEQUENCER_ATTESTATION_MAX_BPS as u128;
    if rounded > u64::MAX as u128 {
        u64::MAX
    } else {
        rounded as u64
    }
}

fn require_nonempty(field: &str, value: &str) -> PqFastPathSequencerAttestationResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    Ok(())
}

fn require_positive(field: &str, value: u64) -> PqFastPathSequencerAttestationResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> PqFastPathSequencerAttestationResult<()> {
    if value == 0 || value > PQ_FAST_PATH_SEQUENCER_ATTESTATION_MAX_BPS {
        return Err(format!("{field} must be within 1..=10000 bps"));
    }
    Ok(())
}

fn require_ordered_heights(
    left_field: &str,
    left: u64,
    right_field: &str,
    right: u64,
) -> PqFastPathSequencerAttestationResult<()> {
    if left > right {
        return Err(format!(
            "{left_field} must be less than or equal to {right_field}"
        ));
    }
    Ok(())
}

fn require_state_status(field: &str, value: &str) -> PqFastPathSequencerAttestationResult<()> {
    match value {
        STATE_STATUS_BOOTSTRAPPING
        | STATE_STATUS_ACTIVE
        | STATE_STATUS_CHALLENGE_MODE
        | STATE_STATUS_PAUSED
        | STATE_STATUS_HALTED => Ok(()),
        _ => Err(format!("{field} is not a supported fast-path state")),
    }
}

fn require_map_key<T>(
    field: &str,
    key: &str,
    map: &BTreeMap<String, T>,
) -> PqFastPathSequencerAttestationResult<()> {
    if !map.contains_key(key) {
        return Err(format!("{field} references an unknown id"));
    }
    Ok(())
}
