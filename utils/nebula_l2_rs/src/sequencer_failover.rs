use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID, RECOVERY_SIGNATURE_SCHEME, TARGET_BLOCK_MS,
};

pub type SequencerFailoverResult<T> = Result<T, String>;

pub const SEQUENCER_FAILOVER_PROTOCOL_VERSION: &str = "nebula-sequencer-failover-v1";
pub const SEQUENCER_FAILOVER_SCHEMA_VERSION: &str = "sequencer-failover-state-v1";
pub const SEQUENCER_FAILOVER_TRANSCRIPT_HASH: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEQUENCER_FAILOVER_PQ_SIGNATURE_SCHEME: &str = ACCOUNT_SIGNATURE_SCHEME;
pub const SEQUENCER_FAILOVER_PQ_RECOVERY_SCHEME: &str = RECOVERY_SIGNATURE_SCHEME;
pub const SEQUENCER_FAILOVER_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const SEQUENCER_FAILOVER_PRIVACY_POLICY: &str =
    "private-queue-roots-only-drain-manifests-with-redacted-payloads";
pub const SEQUENCER_FAILOVER_FORCED_INCLUSION_POLICY: &str =
    "forced-inclusion-cursors-survive-view-change";
pub const SEQUENCER_FAILOVER_LOW_FEE_POLICY: &str =
    "low-fee-min-share-preserved-during-emergency-sequencing";
pub const SEQUENCER_FAILOVER_MAX_BPS: u64 = 10_000;
pub const SEQUENCER_FAILOVER_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 16;
pub const SEQUENCER_FAILOVER_DEFAULT_HEARTBEAT_GRACE_BLOCKS: u64 = 3;
pub const SEQUENCER_FAILOVER_DEFAULT_HANDOFF_TIMEOUT_BLOCKS: u64 = 4;
pub const SEQUENCER_FAILOVER_DEFAULT_RECOVERY_WINDOW_BLOCKS: u64 = 24;
pub const SEQUENCER_FAILOVER_DEFAULT_PRIVATE_DRAIN_BLOCKS: u64 = 12;
pub const SEQUENCER_FAILOVER_DEFAULT_FORCED_INCLUSION_GRACE_BLOCKS: u64 = 8;
pub const SEQUENCER_FAILOVER_DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 6;
pub const SEQUENCER_FAILOVER_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_667;
pub const SEQUENCER_FAILOVER_DEFAULT_EMERGENCY_QUORUM_BPS: u64 = 8_000;
pub const SEQUENCER_FAILOVER_DEFAULT_LOW_FEE_MIN_SHARE_BPS: u64 = 2_000;
pub const SEQUENCER_FAILOVER_DEFAULT_PRIVATE_MIN_SHARE_BPS: u64 = 3_000;
pub const SEQUENCER_FAILOVER_DEFAULT_FORCED_INCLUSION_MIN_SHARE_BPS: u64 = 1_000;
pub const SEQUENCER_FAILOVER_DEFAULT_MAX_PRIVATE_QUEUE_DEPTH: u64 = 8_192;
pub const SEQUENCER_FAILOVER_DEFAULT_DRAIN_BATCH_LIMIT: u64 = 256;
pub const SEQUENCER_FAILOVER_DEFAULT_LOW_FEE_CAP_UNITS: u64 = 2_500;
pub const SEQUENCER_FAILOVER_DEFAULT_SLASH_DOWNTIME_BPS: u64 = 1_000;
pub const SEQUENCER_FAILOVER_DEFAULT_SLASH_CENSORSHIP_BPS: u64 = 2_500;
pub const SEQUENCER_FAILOVER_DEFAULT_SLASH_EQUIVOCATION_BPS: u64 = 5_000;
pub const SEQUENCER_FAILOVER_DEFAULT_MAX_EVIDENCE_AGE_BLOCKS: u64 = 128;
pub const SEQUENCER_FAILOVER_DEVNET_OPERATOR_LABEL: &str = "devnet-sequencer-failover";
pub const SEQUENCER_FAILOVER_DEVNET_PARENT_ROOT: &str = "devnet-sequencer-failover-genesis";
pub const SEQUENCER_FAILOVER_STATUS_ACTIVE: &str = "active";
pub const SEQUENCER_FAILOVER_STATUS_STANDBY: &str = "standby";
pub const SEQUENCER_FAILOVER_STATUS_EMERGENCY: &str = "emergency";
pub const SEQUENCER_FAILOVER_STATUS_RECOVERING: &str = "recovering";
pub const SEQUENCER_FAILOVER_STATUS_DRAINING: &str = "draining";
pub const SEQUENCER_FAILOVER_STATUS_FINALIZED: &str = "finalized";
pub const SEQUENCER_FAILOVER_STATUS_EXPIRED: &str = "expired";
pub const SEQUENCER_FAILOVER_STATUS_SLASHABLE: &str = "slashable";
pub const SEQUENCER_FAILOVER_STATUS_REJECTED: &str = "rejected";
pub const SEQUENCER_FAILOVER_STATUS_RESOLVED: &str = "resolved";

const VALID_STATE_STATUSES: &[&str] = &[
    SEQUENCER_FAILOVER_STATUS_ACTIVE,
    SEQUENCER_FAILOVER_STATUS_EMERGENCY,
    SEQUENCER_FAILOVER_STATUS_RECOVERING,
];

const VALID_OPEN_STATUSES: &[&str] = &[
    SEQUENCER_FAILOVER_STATUS_ACTIVE,
    SEQUENCER_FAILOVER_STATUS_STANDBY,
    SEQUENCER_FAILOVER_STATUS_EMERGENCY,
    SEQUENCER_FAILOVER_STATUS_RECOVERING,
    SEQUENCER_FAILOVER_STATUS_DRAINING,
    SEQUENCER_FAILOVER_STATUS_FINALIZED,
    SEQUENCER_FAILOVER_STATUS_EXPIRED,
    SEQUENCER_FAILOVER_STATUS_SLASHABLE,
    SEQUENCER_FAILOVER_STATUS_REJECTED,
    SEQUENCER_FAILOVER_STATUS_RESOLVED,
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequencerLeaderRole {
    Primary,
    HotStandby,
    ColdStandby,
    Emergency,
    Watchtower,
    PrivateMempoolKeyholder,
    ForcedInclusionKeeper,
    LowFeeSponsor,
}

impl SequencerLeaderRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::HotStandby => "hot_standby",
            Self::ColdStandby => "cold_standby",
            Self::Emergency => "emergency",
            Self::Watchtower => "watchtower",
            Self::PrivateMempoolKeyholder => "private_mempool_keyholder",
            Self::ForcedInclusionKeeper => "forced_inclusion_keeper",
            Self::LowFeeSponsor => "low_fee_sponsor",
        }
    }

    pub fn default_weight_bonus(&self) -> u64 {
        match self {
            Self::Primary => 200,
            Self::HotStandby => 150,
            Self::Emergency => 125,
            Self::ForcedInclusionKeeper => 100,
            Self::PrivateMempoolKeyholder => 75,
            Self::LowFeeSponsor => 50,
            Self::Watchtower => 25,
            Self::ColdStandby => 10,
        }
    }

    pub fn can_sequence(&self) -> bool {
        matches!(self, Self::Primary | Self::HotStandby | Self::Emergency)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequencerLeaderStatus {
    Active,
    Standby,
    Missing,
    Suspect,
    HandingOff,
    EmergencyOnly,
    Retired,
    Slashed,
}

impl SequencerLeaderStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Missing => "missing",
            Self::Suspect => "suspect",
            Self::HandingOff => "handing_off",
            Self::EmergencyOnly => "emergency_only",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::Standby | Self::HandingOff | Self::EmergencyOnly
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverTriggerKind {
    MissedHeartbeat,
    BlockProductionStall,
    PrivateQueueWithheld,
    ForcedInclusionDeadline,
    LowFeeLaneStarvation,
    CensorshipEvidence,
    Equivocation,
    DataAvailabilityOutage,
    QuantumKeyCompromise,
    OperatorInitiatedMaintenance,
    GovernanceEmergency,
}

impl FailoverTriggerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissedHeartbeat => "missed_heartbeat",
            Self::BlockProductionStall => "block_production_stall",
            Self::PrivateQueueWithheld => "private_queue_withheld",
            Self::ForcedInclusionDeadline => "forced_inclusion_deadline",
            Self::LowFeeLaneStarvation => "low_fee_lane_starvation",
            Self::CensorshipEvidence => "censorship_evidence",
            Self::Equivocation => "equivocation",
            Self::DataAvailabilityOutage => "data_availability_outage",
            Self::QuantumKeyCompromise => "quantum_key_compromise",
            Self::OperatorInitiatedMaintenance => "operator_initiated_maintenance",
            Self::GovernanceEmergency => "governance_emergency",
        }
    }

    pub fn default_severity(&self) -> FailoverSeverity {
        match self {
            Self::Equivocation | Self::QuantumKeyCompromise | Self::GovernanceEmergency => {
                FailoverSeverity::Critical
            }
            Self::CensorshipEvidence
            | Self::PrivateQueueWithheld
            | Self::ForcedInclusionDeadline
            | Self::BlockProductionStall => FailoverSeverity::High,
            Self::LowFeeLaneStarvation | Self::DataAvailabilityOutage => FailoverSeverity::Medium,
            Self::MissedHeartbeat | Self::OperatorInitiatedMaintenance => FailoverSeverity::Low,
        }
    }

    pub fn slashable_by_default(&self) -> bool {
        matches!(
            self,
            Self::MissedHeartbeat
                | Self::BlockProductionStall
                | Self::PrivateQueueWithheld
                | Self::ForcedInclusionDeadline
                | Self::LowFeeLaneStarvation
                | Self::CensorshipEvidence
                | Self::Equivocation
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl FailoverSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            Self::Low => 2_500,
            Self::Medium => 5_000,
            Self::High => 7_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffPhase {
    None,
    Proposed,
    QuorumCollecting,
    Certified,
    Activating,
    EmergencySequencing,
    PrivateQueueDraining,
    Finalized,
    Reverted,
}

impl HandoffPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Proposed => "proposed",
            Self::QuorumCollecting => "quorum_collecting",
            Self::Certified => "certified",
            Self::Activating => "activating",
            Self::EmergencySequencing => "emergency_sequencing",
            Self::PrivateQueueDraining => "private_queue_draining",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverLaneKind {
    System,
    ForcedInclusion,
    MoneroBridge,
    PrivateTransfer,
    PrivateDefi,
    ContractCall,
    PublicDefi,
    LowFee,
    ProofMarket,
    Bulk,
    Custom(String),
}

impl FailoverLaneKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::System => "system".to_string(),
            Self::ForcedInclusion => "forced_inclusion".to_string(),
            Self::MoneroBridge => "monero_bridge".to_string(),
            Self::PrivateTransfer => "private_transfer".to_string(),
            Self::PrivateDefi => "private_defi".to_string(),
            Self::ContractCall => "contract_call".to_string(),
            Self::PublicDefi => "public_defi".to_string(),
            Self::LowFee => "low_fee".to_string(),
            Self::ProofMarket => "proof_market".to_string(),
            Self::Bulk => "bulk".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn default_priority(&self) -> u64 {
        match self {
            Self::System => 1_000_000,
            Self::ForcedInclusion => 950_000,
            Self::MoneroBridge => 900_000,
            Self::PrivateTransfer => 850_000,
            Self::PrivateDefi => 800_000,
            Self::LowFee => 760_000,
            Self::ContractCall => 650_000,
            Self::PublicDefi => 600_000,
            Self::ProofMarket => 500_000,
            Self::Bulk => 100_000,
            Self::Custom(_) => 250_000,
        }
    }

    pub fn private_by_default(&self) -> bool {
        matches!(
            self,
            Self::MoneroBridge
                | Self::PrivateTransfer
                | Self::PrivateDefi
                | Self::ContractCall
                | Self::LowFee
        )
    }

    pub fn low_fee_eligible(&self) -> bool {
        matches!(
            self,
            Self::LowFee | Self::PrivateTransfer | Self::PrivateDefi | Self::MoneroBridge
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryWindowStatus {
    Pending,
    Open,
    Draining,
    EmergencySequencing,
    Finalizing,
    Finalized,
    Expired,
}

impl RecoveryWindowStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Draining => "draining",
            Self::EmergencySequencing => "emergency_sequencing",
            Self::Finalizing => "finalizing",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Open | Self::Draining | Self::EmergencySequencing
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainStatus {
    Pending,
    Reserved,
    Draining,
    Included,
    Deferred,
    ForcedInclusionEscalated,
    Expired,
}

impl DrainStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Reserved => "reserved",
            Self::Draining => "draining",
            Self::Included => "included",
            Self::Deferred => "deferred",
            Self::ForcedInclusionEscalated => "forced_inclusion_escalated",
            Self::Expired => "expired",
        }
    }

    pub fn is_pending_like(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Reserved | Self::Draining | Self::Deferred
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeGuaranteeStatus {
    Active,
    Preserved,
    Draining,
    Exhausted,
    Finalized,
    Expired,
}

impl LowFeeGuaranteeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Preserved => "preserved",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
        }
    }

    pub fn can_reserve(&self) -> bool {
        matches!(self, Self::Active | Self::Preserved | Self::Draining)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityReceiptKind {
    Dequeued,
    Included,
    Requeued,
    ForcedInclusionClaimed,
    LowFeeCreditPreserved,
    PreconfirmationCarried,
    PrivacyDisclosureDelayed,
}

impl ContinuityReceiptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dequeued => "dequeued",
            Self::Included => "included",
            Self::Requeued => "requeued",
            Self::ForcedInclusionClaimed => "forced_inclusion_claimed",
            Self::LowFeeCreditPreserved => "low_fee_credit_preserved",
            Self::PreconfirmationCarried => "preconfirmation_carried",
            Self::PrivacyDisclosureDelayed => "privacy_disclosure_delayed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashableEvidenceKind {
    Downtime,
    PrivateQueueWithholding,
    LowFeeStarvation,
    ForcedInclusionOmission,
    Censorship,
    Equivocation,
    InvalidHandoff,
    InvalidDrainManifest,
}

impl SlashableEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Downtime => "downtime",
            Self::PrivateQueueWithholding => "private_queue_withholding",
            Self::LowFeeStarvation => "low_fee_starvation",
            Self::ForcedInclusionOmission => "forced_inclusion_omission",
            Self::Censorship => "censorship",
            Self::Equivocation => "equivocation",
            Self::InvalidHandoff => "invalid_handoff",
            Self::InvalidDrainManifest => "invalid_drain_manifest",
        }
    }

    pub fn default_slash_bps(&self, config: &SequencerFailoverConfig) -> u64 {
        match self {
            Self::Downtime => config.slash_downtime_bps,
            Self::LowFeeStarvation
            | Self::PrivateQueueWithholding
            | Self::ForcedInclusionOmission
            | Self::Censorship => config.slash_censorship_bps,
            Self::Equivocation | Self::InvalidHandoff | Self::InvalidDrainManifest => {
                config.slash_equivocation_bps
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Observed,
    Challenged,
    Accepted,
    Slashable,
    Dismissed,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Slashable => "slashable",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }

    pub fn slashable(&self) -> bool {
        matches!(self, Self::Accepted | Self::Slashable)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyApprovalKind {
    TriggerObserved,
    HandoffApproved,
    EmergencySequencingApproved,
    PrivateQueueDrainApproved,
    ForcedInclusionContinuationApproved,
    LowFeePreservationApproved,
    SlashRecommendation,
}

impl EmergencyApprovalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TriggerObserved => "trigger_observed",
            Self::HandoffApproved => "handoff_approved",
            Self::EmergencySequencingApproved => "emergency_sequencing_approved",
            Self::PrivateQueueDrainApproved => "private_queue_drain_approved",
            Self::ForcedInclusionContinuationApproved => "forced_inclusion_continuation_approved",
            Self::LowFeePreservationApproved => "low_fee_preservation_approved",
            Self::SlashRecommendation => "slash_recommendation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyApprovalStatus {
    Pending,
    Accepted,
    Rejected,
    Superseded,
    Expired,
}

impl EmergencyApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerFailoverConfig {
    pub epoch_length_blocks: u64,
    pub heartbeat_grace_blocks: u64,
    pub handoff_timeout_blocks: u64,
    pub recovery_window_blocks: u64,
    pub private_drain_blocks: u64,
    pub forced_inclusion_grace_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub committee_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub low_fee_min_share_bps: u64,
    pub private_min_share_bps: u64,
    pub forced_inclusion_min_share_bps: u64,
    pub max_private_queue_depth: u64,
    pub drain_batch_limit: u64,
    pub low_fee_cap_units: u64,
    pub slash_downtime_bps: u64,
    pub slash_censorship_bps: u64,
    pub slash_equivocation_bps: u64,
    pub max_evidence_age_blocks: u64,
    pub target_microblock_ms: u64,
    pub pq_signature_scheme: String,
    pub pq_recovery_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub transcript_hash: String,
    pub privacy_policy: String,
    pub forced_inclusion_policy: String,
    pub low_fee_policy: String,
}

impl Default for SequencerFailoverConfig {
    fn default() -> Self {
        Self {
            epoch_length_blocks: SEQUENCER_FAILOVER_DEFAULT_EPOCH_LENGTH_BLOCKS,
            heartbeat_grace_blocks: SEQUENCER_FAILOVER_DEFAULT_HEARTBEAT_GRACE_BLOCKS,
            handoff_timeout_blocks: SEQUENCER_FAILOVER_DEFAULT_HANDOFF_TIMEOUT_BLOCKS,
            recovery_window_blocks: SEQUENCER_FAILOVER_DEFAULT_RECOVERY_WINDOW_BLOCKS,
            private_drain_blocks: SEQUENCER_FAILOVER_DEFAULT_PRIVATE_DRAIN_BLOCKS,
            forced_inclusion_grace_blocks: SEQUENCER_FAILOVER_DEFAULT_FORCED_INCLUSION_GRACE_BLOCKS,
            preconfirmation_ttl_blocks: SEQUENCER_FAILOVER_DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            committee_quorum_bps: SEQUENCER_FAILOVER_DEFAULT_COMMITTEE_QUORUM_BPS,
            emergency_quorum_bps: SEQUENCER_FAILOVER_DEFAULT_EMERGENCY_QUORUM_BPS,
            low_fee_min_share_bps: SEQUENCER_FAILOVER_DEFAULT_LOW_FEE_MIN_SHARE_BPS,
            private_min_share_bps: SEQUENCER_FAILOVER_DEFAULT_PRIVATE_MIN_SHARE_BPS,
            forced_inclusion_min_share_bps:
                SEQUENCER_FAILOVER_DEFAULT_FORCED_INCLUSION_MIN_SHARE_BPS,
            max_private_queue_depth: SEQUENCER_FAILOVER_DEFAULT_MAX_PRIVATE_QUEUE_DEPTH,
            drain_batch_limit: SEQUENCER_FAILOVER_DEFAULT_DRAIN_BATCH_LIMIT,
            low_fee_cap_units: SEQUENCER_FAILOVER_DEFAULT_LOW_FEE_CAP_UNITS,
            slash_downtime_bps: SEQUENCER_FAILOVER_DEFAULT_SLASH_DOWNTIME_BPS,
            slash_censorship_bps: SEQUENCER_FAILOVER_DEFAULT_SLASH_CENSORSHIP_BPS,
            slash_equivocation_bps: SEQUENCER_FAILOVER_DEFAULT_SLASH_EQUIVOCATION_BPS,
            max_evidence_age_blocks: SEQUENCER_FAILOVER_DEFAULT_MAX_EVIDENCE_AGE_BLOCKS,
            target_microblock_ms: (TARGET_BLOCK_MS / 5).max(1),
            pq_signature_scheme: SEQUENCER_FAILOVER_PQ_SIGNATURE_SCHEME.to_string(),
            pq_recovery_signature_scheme: SEQUENCER_FAILOVER_PQ_RECOVERY_SCHEME.to_string(),
            pq_kem_scheme: SEQUENCER_FAILOVER_PQ_KEM_SCHEME.to_string(),
            transcript_hash: SEQUENCER_FAILOVER_TRANSCRIPT_HASH.to_string(),
            privacy_policy: SEQUENCER_FAILOVER_PRIVACY_POLICY.to_string(),
            forced_inclusion_policy: SEQUENCER_FAILOVER_FORCED_INCLUSION_POLICY.to_string(),
            low_fee_policy: SEQUENCER_FAILOVER_LOW_FEE_POLICY.to_string(),
        }
    }
}

impl SequencerFailoverConfig {
    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_positive(self.epoch_length_blocks, "failover epoch length")?;
        ensure_positive(self.heartbeat_grace_blocks, "failover heartbeat grace")?;
        ensure_positive(self.handoff_timeout_blocks, "failover handoff timeout")?;
        ensure_positive(self.recovery_window_blocks, "failover recovery window")?;
        ensure_positive(self.private_drain_blocks, "failover private drain window")?;
        ensure_positive(
            self.forced_inclusion_grace_blocks,
            "failover forced inclusion grace",
        )?;
        ensure_positive(
            self.preconfirmation_ttl_blocks,
            "failover preconfirmation ttl",
        )?;
        ensure_bps(self.committee_quorum_bps, "failover committee quorum")?;
        ensure_bps(self.emergency_quorum_bps, "failover emergency quorum")?;
        ensure_bps(self.low_fee_min_share_bps, "failover low fee share")?;
        ensure_bps(self.private_min_share_bps, "failover private share")?;
        ensure_bps(
            self.forced_inclusion_min_share_bps,
            "failover forced inclusion share",
        )?;
        ensure_positive(
            self.max_private_queue_depth,
            "failover max private queue depth",
        )?;
        ensure_positive(self.drain_batch_limit, "failover drain batch limit")?;
        ensure_positive(self.low_fee_cap_units, "failover low fee cap")?;
        ensure_bps(self.slash_downtime_bps, "failover downtime slash bps")?;
        ensure_bps(self.slash_censorship_bps, "failover censorship slash bps")?;
        ensure_bps(
            self.slash_equivocation_bps,
            "failover equivocation slash bps",
        )?;
        ensure_positive(self.max_evidence_age_blocks, "failover max evidence age")?;
        ensure_positive(self.target_microblock_ms, "failover target microblock ms")?;
        ensure_non_empty(&self.pq_signature_scheme, "failover pq signature scheme")?;
        ensure_non_empty(
            &self.pq_recovery_signature_scheme,
            "failover pq recovery scheme",
        )?;
        ensure_non_empty(&self.pq_kem_scheme, "failover pq kem scheme")?;
        ensure_non_empty(&self.transcript_hash, "failover transcript hash")?;
        ensure_non_empty(&self.privacy_policy, "failover privacy policy")?;
        ensure_non_empty(
            &self.forced_inclusion_policy,
            "failover forced inclusion policy",
        )?;
        ensure_non_empty(&self.low_fee_policy, "failover low fee policy")?;
        Ok(self.config_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_config",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "schema_version": SEQUENCER_FAILOVER_SCHEMA_VERSION,
            "epoch_length_blocks": self.epoch_length_blocks,
            "heartbeat_grace_blocks": self.heartbeat_grace_blocks,
            "handoff_timeout_blocks": self.handoff_timeout_blocks,
            "recovery_window_blocks": self.recovery_window_blocks,
            "private_drain_blocks": self.private_drain_blocks,
            "forced_inclusion_grace_blocks": self.forced_inclusion_grace_blocks,
            "preconfirmation_ttl_blocks": self.preconfirmation_ttl_blocks,
            "committee_quorum_bps": self.committee_quorum_bps,
            "emergency_quorum_bps": self.emergency_quorum_bps,
            "low_fee_min_share_bps": self.low_fee_min_share_bps,
            "private_min_share_bps": self.private_min_share_bps,
            "forced_inclusion_min_share_bps": self.forced_inclusion_min_share_bps,
            "max_private_queue_depth": self.max_private_queue_depth,
            "drain_batch_limit": self.drain_batch_limit,
            "low_fee_cap_units": self.low_fee_cap_units,
            "slash_downtime_bps": self.slash_downtime_bps,
            "slash_censorship_bps": self.slash_censorship_bps,
            "slash_equivocation_bps": self.slash_equivocation_bps,
            "max_evidence_age_blocks": self.max_evidence_age_blocks,
            "target_microblock_ms": self.target_microblock_ms,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_recovery_signature_scheme": self.pq_recovery_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "transcript_hash": self.transcript_hash,
            "privacy_policy": self.privacy_policy,
            "forced_inclusion_policy": self.forced_inclusion_policy,
            "low_fee_policy": self.low_fee_policy,
        })
    }

    pub fn config_root(&self) -> String {
        sequencer_failover_payload_root("SEQUENCER-FAILOVER-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerLeader {
    pub leader_id: String,
    pub operator_label: String,
    pub role: SequencerLeaderRole,
    pub status: SequencerLeaderStatus,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
    pub stake_units: u64,
    pub weight_units: u64,
    pub endpoint_commitment: String,
    pub pq_signing_key_root: String,
    pub pq_recovery_key_root: String,
    pub vrf_key_root: String,
    pub heartbeat_root: String,
    pub last_heartbeat_height: u64,
    pub low_fee_sponsor_root: String,
    pub metadata_root: String,
}

impl SequencerLeader {
    pub fn new(
        operator_label: impl Into<String>,
        role: SequencerLeaderRole,
        stake_units: u64,
        weight_units: u64,
        activation_height: u64,
    ) -> SequencerFailoverResult<Self> {
        let operator_label = operator_label.into();
        ensure_non_empty(&operator_label, "sequencer leader operator label")?;
        ensure_positive(stake_units, "sequencer leader stake")?;
        ensure_positive(weight_units, "sequencer leader weight")?;
        let endpoint_commitment = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-LEADER-ENDPOINT",
            &format!("{operator_label}.sequencer.devnet.invalid"),
        );
        let pq_signing_key_root = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-LEADER-PQ-SIGNING-KEY",
            &format!("{operator_label}:ml-dsa-65"),
        );
        let pq_recovery_key_root = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-LEADER-PQ-RECOVERY-KEY",
            &format!("{operator_label}:slh-dsa-recovery"),
        );
        let vrf_key_root = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-LEADER-VRF-KEY",
            &format!("{operator_label}:failover-vrf"),
        );
        let heartbeat_root = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-LEADER-HEARTBEAT",
            &format!("{operator_label}:{activation_height}"),
        );
        let low_fee_sponsor_root = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-LEADER-LOW-FEE-SPONSOR",
            &format!("{operator_label}:sponsor"),
        );
        let metadata_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-LEADER-METADATA",
            &json!({
                "operator_label": operator_label,
                "role": role.as_str(),
                "quantum_resistant": true,
                "privacy_surface": "roots_only",
            }),
        );
        let leader_id = sequencer_leader_id(
            &operator_label,
            &role,
            &endpoint_commitment,
            &pq_signing_key_root,
            &pq_recovery_key_root,
            activation_height,
        );
        let leader = Self {
            leader_id,
            operator_label,
            role,
            status: SequencerLeaderStatus::Standby,
            activation_height,
            retirement_height: None,
            stake_units,
            weight_units: weight_units.saturating_add(role_weight_bonus(stake_units)),
            endpoint_commitment,
            pq_signing_key_root,
            pq_recovery_key_root,
            vrf_key_root,
            heartbeat_root,
            last_heartbeat_height: activation_height,
            low_fee_sponsor_root,
            metadata_root,
        };
        leader.validate()?;
        Ok(leader)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.activation_height <= height
            && self
                .retirement_height
                .map(|retirement_height| height < retirement_height)
                .unwrap_or(true)
            && self.status.is_available()
    }

    pub fn can_sequence_at(&self, height: u64) -> bool {
        self.active_at(height) && self.role.can_sequence()
    }

    pub fn record_heartbeat(
        &mut self,
        height: u64,
        payload: &Value,
    ) -> SequencerFailoverResult<()> {
        if height < self.last_heartbeat_height {
            return Err("sequencer leader heartbeat cannot move backward".to_string());
        }
        self.last_heartbeat_height = height;
        self.heartbeat_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-LEADER-HEARTBEAT",
            &json!({
                "leader_id": self.leader_id,
                "height": height,
                "payload": payload,
            }),
        );
        Ok(())
    }

    pub fn mark_primary(&mut self) {
        self.role = SequencerLeaderRole::Primary;
        self.status = SequencerLeaderStatus::Active;
    }

    pub fn mark_standby(&mut self) {
        if self.status != SequencerLeaderStatus::Slashed {
            self.status = SequencerLeaderStatus::Standby;
        }
    }

    pub fn mark_missing(&mut self) {
        if self.status != SequencerLeaderStatus::Slashed {
            self.status = SequencerLeaderStatus::Missing;
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_leader_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "operator_label": self.operator_label,
            "role": self.role.as_str(),
            "activation_height": self.activation_height,
            "endpoint_commitment": self.endpoint_commitment,
            "pq_signing_key_root": self.pq_signing_key_root,
            "pq_recovery_key_root": self.pq_recovery_key_root,
            "pq_signature_scheme": SEQUENCER_FAILOVER_PQ_SIGNATURE_SCHEME,
            "pq_recovery_signature_scheme": SEQUENCER_FAILOVER_PQ_RECOVERY_SCHEME,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_leader",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "leader_id": self.leader_id,
            "operator_label": self.operator_label,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "activation_height": self.activation_height,
            "retirement_height": self.retirement_height,
            "stake_units": self.stake_units,
            "weight_units": self.weight_units,
            "endpoint_commitment": self.endpoint_commitment,
            "pq_signing_key_root": self.pq_signing_key_root,
            "pq_recovery_key_root": self.pq_recovery_key_root,
            "vrf_key_root": self.vrf_key_root,
            "heartbeat_root": self.heartbeat_root,
            "last_heartbeat_height": self.last_heartbeat_height,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "metadata_root": self.metadata_root,
            "leader_root": self.leader_root(),
        })
    }

    pub fn leader_root(&self) -> String {
        sequencer_failover_payload_root("SEQUENCER-FAILOVER-LEADER", &self.identity_record())
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.leader_id, "sequencer leader id")?;
        ensure_non_empty(&self.operator_label, "sequencer leader label")?;
        ensure_positive(self.stake_units, "sequencer leader stake")?;
        ensure_positive(self.weight_units, "sequencer leader weight")?;
        ensure_non_empty(&self.endpoint_commitment, "sequencer leader endpoint")?;
        ensure_non_empty(&self.pq_signing_key_root, "sequencer leader pq signing key")?;
        ensure_non_empty(
            &self.pq_recovery_key_root,
            "sequencer leader pq recovery key",
        )?;
        ensure_non_empty(&self.vrf_key_root, "sequencer leader vrf key")?;
        ensure_non_empty(&self.heartbeat_root, "sequencer leader heartbeat root")?;
        ensure_non_empty(
            &self.low_fee_sponsor_root,
            "sequencer leader low fee sponsor root",
        )?;
        ensure_non_empty(&self.metadata_root, "sequencer leader metadata root")?;
        if let Some(retirement_height) = self.retirement_height {
            if retirement_height <= self.activation_height {
                return Err("sequencer leader retirement must follow activation".to_string());
            }
        }
        let expected = sequencer_leader_id(
            &self.operator_label,
            &self.role,
            &self.endpoint_commitment,
            &self.pq_signing_key_root,
            &self.pq_recovery_key_root,
            self.activation_height,
        );
        if self.leader_id != expected {
            return Err("sequencer leader id mismatch".to_string());
        }
        Ok(self.leader_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyCommitteeMember {
    pub member_id: String,
    pub label: String,
    pub voting_power: u64,
    pub pq_public_key_root: String,
    pub recovery_key_root: String,
    pub active_from_height: u64,
    pub retired_at_height: Option<u64>,
    pub status: String,
}

impl EmergencyCommitteeMember {
    pub fn new(
        label: impl Into<String>,
        voting_power: u64,
        active_from_height: u64,
    ) -> SequencerFailoverResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "emergency committee member label")?;
        ensure_positive(voting_power, "emergency committee voting power")?;
        let pq_public_key_root = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-EMERGENCY-MEMBER-PQ-KEY",
            &format!("{label}:ml-dsa-65"),
        );
        let recovery_key_root = sequencer_failover_string_root(
            "SEQUENCER-FAILOVER-EMERGENCY-MEMBER-RECOVERY-KEY",
            &format!("{label}:slh-dsa"),
        );
        let member_id = emergency_committee_member_id(
            &label,
            voting_power,
            &pq_public_key_root,
            active_from_height,
        );
        let member = Self {
            member_id,
            label,
            voting_power,
            pq_public_key_root,
            recovery_key_root,
            active_from_height,
            retired_at_height: None,
            status: SEQUENCER_FAILOVER_STATUS_ACTIVE.to_string(),
        };
        member.validate()?;
        Ok(member)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == SEQUENCER_FAILOVER_STATUS_ACTIVE
            && self.active_from_height <= height
            && self
                .retired_at_height
                .map(|retired| height < retired)
                .unwrap_or(true)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_emergency_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "label": self.label,
            "voting_power": self.voting_power,
            "pq_public_key_root": self.pq_public_key_root,
            "recovery_key_root": self.recovery_key_root,
            "active_from_height": self.active_from_height,
            "retired_at_height": self.retired_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.member_id, "emergency committee member id")?;
        ensure_non_empty(&self.label, "emergency committee member label")?;
        ensure_positive(self.voting_power, "emergency committee member voting power")?;
        ensure_non_empty(
            &self.pq_public_key_root,
            "emergency committee member pq public key",
        )?;
        ensure_non_empty(
            &self.recovery_key_root,
            "emergency committee member recovery key",
        )?;
        ensure_status(&self.status, VALID_OPEN_STATUSES)?;
        if let Some(retired_at_height) = self.retired_at_height {
            if retired_at_height <= self.active_from_height {
                return Err("emergency committee retirement must follow activation".to_string());
            }
        }
        let expected = emergency_committee_member_id(
            &self.label,
            self.voting_power,
            &self.pq_public_key_root,
            self.active_from_height,
        );
        if self.member_id != expected {
            return Err("emergency committee member id mismatch".to_string());
        }
        Ok(self.member_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerFailoverEpoch {
    pub epoch_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub primary_leader_id: String,
    pub backup_leader_ids: Vec<String>,
    pub leader_set_root: String,
    pub emergency_committee_root: String,
    pub forced_inclusion_cursor: u64,
    pub forced_inclusion_root: String,
    pub low_fee_lane_root: String,
    pub private_queue_root: String,
    pub status: String,
}

impl SequencerFailoverEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        start_height: u64,
        end_height: u64,
        primary_leader_id: impl Into<String>,
        backup_leader_ids: Vec<String>,
        emergency_committee_members: &BTreeMap<String, EmergencyCommitteeMember>,
        forced_inclusion_cursor: u64,
        low_fee_lane_root: impl Into<String>,
        private_queue_root: impl Into<String>,
    ) -> SequencerFailoverResult<Self> {
        let primary_leader_id = primary_leader_id.into();
        let low_fee_lane_root = low_fee_lane_root.into();
        let private_queue_root = private_queue_root.into();
        ensure_non_empty(&primary_leader_id, "failover epoch primary leader")?;
        ensure_non_empty(&low_fee_lane_root, "failover epoch low fee lane root")?;
        ensure_non_empty(&private_queue_root, "failover epoch private queue root")?;
        if end_height <= start_height {
            return Err("failover epoch end must follow start".to_string());
        }
        ensure_unique_strings(&backup_leader_ids, "failover epoch backup leaders")?;
        let leader_ids = epoch_leader_ids(&primary_leader_id, &backup_leader_ids);
        let leader_set_root =
            sequencer_failover_string_set_root("SEQUENCER-FAILOVER-EPOCH-LEADER-SET", &leader_ids);
        let emergency_committee_root =
            emergency_committee_member_root_from_map(emergency_committee_members);
        let forced_inclusion_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-EPOCH-FORCED-INCLUSION",
            &json!({
                "cursor": forced_inclusion_cursor,
                "policy": SEQUENCER_FAILOVER_FORCED_INCLUSION_POLICY,
            }),
        );
        let epoch_id = sequencer_failover_epoch_id(
            epoch,
            start_height,
            end_height,
            &primary_leader_id,
            &leader_set_root,
            &emergency_committee_root,
        );
        let record = Self {
            epoch_id,
            epoch,
            start_height,
            end_height,
            primary_leader_id,
            backup_leader_ids,
            leader_set_root,
            emergency_committee_root,
            forced_inclusion_cursor,
            forced_inclusion_root,
            low_fee_lane_root,
            private_queue_root,
            status: SEQUENCER_FAILOVER_STATUS_ACTIVE.to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.start_height <= height && height < self.end_height
    }

    pub fn leader_ids(&self) -> Vec<String> {
        epoch_leader_ids(&self.primary_leader_id, &self.backup_leader_ids)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "primary_leader_id": self.primary_leader_id,
            "backup_leader_ids": self.backup_leader_ids,
            "leader_set_root": self.leader_set_root,
            "emergency_committee_root": self.emergency_committee_root,
            "forced_inclusion_cursor": self.forced_inclusion_cursor,
            "forced_inclusion_root": self.forced_inclusion_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "private_queue_root": self.private_queue_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.epoch_id, "failover epoch id")?;
        ensure_non_empty(&self.primary_leader_id, "failover epoch primary")?;
        ensure_non_empty(&self.leader_set_root, "failover epoch leader root")?;
        ensure_non_empty(
            &self.emergency_committee_root,
            "failover epoch emergency committee root",
        )?;
        ensure_non_empty(
            &self.forced_inclusion_root,
            "failover epoch forced inclusion root",
        )?;
        ensure_non_empty(&self.low_fee_lane_root, "failover epoch low fee root")?;
        ensure_non_empty(&self.private_queue_root, "failover epoch private queue")?;
        ensure_status(&self.status, VALID_OPEN_STATUSES)?;
        if self.end_height <= self.start_height {
            return Err("failover epoch end must follow start".to_string());
        }
        ensure_unique_strings(&self.backup_leader_ids, "failover epoch backup leaders")?;
        let expected_leader_root = sequencer_failover_string_set_root(
            "SEQUENCER-FAILOVER-EPOCH-LEADER-SET",
            &self.leader_ids(),
        );
        if self.leader_set_root != expected_leader_root {
            return Err("failover epoch leader set root mismatch".to_string());
        }
        let expected = sequencer_failover_epoch_id(
            self.epoch,
            self.start_height,
            self.end_height,
            &self.primary_leader_id,
            &self.leader_set_root,
            &self.emergency_committee_root,
        );
        if self.epoch_id != expected {
            return Err("failover epoch id mismatch".to_string());
        }
        Ok(self.epoch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailoverTrigger {
    pub trigger_id: String,
    pub trigger_kind: FailoverTriggerKind,
    pub severity: FailoverSeverity,
    pub subject_leader_id: String,
    pub detected_by: String,
    pub observed_height: u64,
    pub missing_from_height: u64,
    pub missing_until_height: Option<u64>,
    pub affected_epoch: u64,
    pub evidence_payload_root: String,
    pub queue_snapshot_root: String,
    pub liveness_root: String,
    pub private_queue_root: String,
    pub forced_inclusion_root: String,
    pub low_fee_root: String,
    pub expires_at_height: u64,
    pub status: String,
}

impl FailoverTrigger {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_kind: FailoverTriggerKind,
        subject_leader_id: impl Into<String>,
        detected_by: impl Into<String>,
        observed_height: u64,
        missing_from_height: u64,
        affected_epoch: u64,
        evidence_payload: &Value,
        queue_snapshot: &Value,
        private_queue_root: impl Into<String>,
        forced_inclusion_root: impl Into<String>,
        low_fee_root: impl Into<String>,
        expires_at_height: u64,
    ) -> SequencerFailoverResult<Self> {
        let subject_leader_id = subject_leader_id.into();
        let detected_by = detected_by.into();
        let private_queue_root = private_queue_root.into();
        let forced_inclusion_root = forced_inclusion_root.into();
        let low_fee_root = low_fee_root.into();
        ensure_non_empty(&subject_leader_id, "failover trigger subject leader")?;
        ensure_non_empty(&detected_by, "failover trigger detector")?;
        ensure_non_empty(&private_queue_root, "failover trigger private queue root")?;
        ensure_non_empty(
            &forced_inclusion_root,
            "failover trigger forced inclusion root",
        )?;
        ensure_non_empty(&low_fee_root, "failover trigger low fee root")?;
        if observed_height < missing_from_height {
            return Err("failover trigger observed before missing window".to_string());
        }
        if expires_at_height <= observed_height {
            return Err("failover trigger expiry must follow observation".to_string());
        }
        let severity = trigger_kind.default_severity();
        let evidence_payload_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-TRIGGER-EVIDENCE",
            evidence_payload,
        );
        let queue_snapshot_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-TRIGGER-QUEUE", queue_snapshot);
        let liveness_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-TRIGGER-LIVENESS",
            &json!({
                "subject_leader_id": subject_leader_id,
                "observed_height": observed_height,
                "missing_from_height": missing_from_height,
                "trigger_kind": trigger_kind.as_str(),
            }),
        );
        let trigger_id = failover_trigger_id(
            &trigger_kind,
            &subject_leader_id,
            observed_height,
            missing_from_height,
            affected_epoch,
            &evidence_payload_root,
        );
        let trigger = Self {
            trigger_id,
            trigger_kind,
            severity,
            subject_leader_id,
            detected_by,
            observed_height,
            missing_from_height,
            missing_until_height: None,
            affected_epoch,
            evidence_payload_root,
            queue_snapshot_root,
            liveness_root,
            private_queue_root,
            forced_inclusion_root,
            low_fee_root,
            expires_at_height,
            status: SEQUENCER_FAILOVER_STATUS_ACTIVE.to_string(),
        };
        trigger.validate()?;
        Ok(trigger)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status == SEQUENCER_FAILOVER_STATUS_ACTIVE && height <= self.expires_at_height
    }

    pub fn slashable(&self) -> bool {
        self.trigger_kind.slashable_by_default()
            && matches!(
                self.status.as_str(),
                SEQUENCER_FAILOVER_STATUS_ACTIVE | SEQUENCER_FAILOVER_STATUS_SLASHABLE
            )
    }

    pub fn resolve(&mut self, height: u64) -> SequencerFailoverResult<()> {
        if height < self.observed_height {
            return Err("failover trigger resolution before observation".to_string());
        }
        self.missing_until_height = Some(height);
        self.status = SEQUENCER_FAILOVER_STATUS_RESOLVED.to_string();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_trigger",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "trigger_id": self.trigger_id,
            "trigger_kind": self.trigger_kind.as_str(),
            "severity": self.severity.as_str(),
            "severity_score_bps": self.severity.score_bps(),
            "subject_leader_id": self.subject_leader_id,
            "detected_by": self.detected_by,
            "observed_height": self.observed_height,
            "missing_from_height": self.missing_from_height,
            "missing_until_height": self.missing_until_height,
            "affected_epoch": self.affected_epoch,
            "evidence_payload_root": self.evidence_payload_root,
            "queue_snapshot_root": self.queue_snapshot_root,
            "liveness_root": self.liveness_root,
            "private_queue_root": self.private_queue_root,
            "forced_inclusion_root": self.forced_inclusion_root,
            "low_fee_root": self.low_fee_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.trigger_id, "failover trigger id")?;
        ensure_non_empty(&self.subject_leader_id, "failover trigger subject")?;
        ensure_non_empty(&self.detected_by, "failover trigger detector")?;
        ensure_non_empty(
            &self.evidence_payload_root,
            "failover trigger evidence root",
        )?;
        ensure_non_empty(&self.queue_snapshot_root, "failover trigger queue root")?;
        ensure_non_empty(&self.liveness_root, "failover trigger liveness root")?;
        ensure_non_empty(&self.private_queue_root, "failover trigger private queue")?;
        ensure_non_empty(
            &self.forced_inclusion_root,
            "failover trigger forced inclusion root",
        )?;
        ensure_non_empty(&self.low_fee_root, "failover trigger low fee root")?;
        ensure_status(&self.status, VALID_OPEN_STATUSES)?;
        if self.observed_height < self.missing_from_height {
            return Err("failover trigger observed before missing window".to_string());
        }
        if let Some(missing_until_height) = self.missing_until_height {
            if missing_until_height < self.missing_from_height {
                return Err("failover trigger missing window is inverted".to_string());
            }
        }
        if self.expires_at_height <= self.observed_height {
            return Err("failover trigger expiry must follow observation".to_string());
        }
        let expected = failover_trigger_id(
            &self.trigger_kind,
            &self.subject_leader_id,
            self.observed_height,
            self.missing_from_height,
            self.affected_epoch,
            &self.evidence_payload_root,
        );
        if self.trigger_id != expected {
            return Err("failover trigger id mismatch".to_string());
        }
        Ok(self.trigger_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyCommitteeApproval {
    pub approval_id: String,
    pub approval_kind: EmergencyApprovalKind,
    pub committee_member_id: String,
    pub trigger_id: String,
    pub handoff_certificate_id: Option<String>,
    pub approved_leader_id: String,
    pub voting_power: u64,
    pub approval_height: u64,
    pub expires_at_height: u64,
    pub approval_payload_root: String,
    pub pq_signature_root: String,
    pub status: EmergencyApprovalStatus,
}

impl EmergencyCommitteeApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approval_kind: EmergencyApprovalKind,
        committee_member: &EmergencyCommitteeMember,
        trigger_id: impl Into<String>,
        handoff_certificate_id: Option<String>,
        approved_leader_id: impl Into<String>,
        approval_height: u64,
        expires_at_height: u64,
        payload: &Value,
    ) -> SequencerFailoverResult<Self> {
        committee_member.validate()?;
        let trigger_id = trigger_id.into();
        let approved_leader_id = approved_leader_id.into();
        ensure_non_empty(&trigger_id, "emergency approval trigger id")?;
        ensure_non_empty(&approved_leader_id, "emergency approval leader")?;
        if expires_at_height <= approval_height {
            return Err("emergency approval expiry must follow approval height".to_string());
        }
        let approval_payload_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-EMERGENCY-APPROVAL", payload);
        let pq_signature_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-EMERGENCY-APPROVAL-PQ-SIGNATURE",
            &json!({
                "member_id": committee_member.member_id,
                "trigger_id": trigger_id,
                "approved_leader_id": approved_leader_id,
                "approval_payload_root": approval_payload_root,
                "scheme": SEQUENCER_FAILOVER_PQ_SIGNATURE_SCHEME,
            }),
        );
        let approval_id = emergency_approval_id(
            &approval_kind,
            &committee_member.member_id,
            &trigger_id,
            &approved_leader_id,
            approval_height,
            &approval_payload_root,
        );
        let approval = Self {
            approval_id,
            approval_kind,
            committee_member_id: committee_member.member_id.clone(),
            trigger_id,
            handoff_certificate_id,
            approved_leader_id,
            voting_power: committee_member.voting_power,
            approval_height,
            expires_at_height,
            approval_payload_root,
            pq_signature_root,
            status: EmergencyApprovalStatus::Accepted,
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn counts_for_quorum_at(&self, height: u64) -> bool {
        self.status.counts_for_quorum()
            && self.approval_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_emergency_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "approval_kind": self.approval_kind.as_str(),
            "committee_member_id": self.committee_member_id,
            "trigger_id": self.trigger_id,
            "handoff_certificate_id": self.handoff_certificate_id,
            "approved_leader_id": self.approved_leader_id,
            "voting_power": self.voting_power,
            "approval_height": self.approval_height,
            "expires_at_height": self.expires_at_height,
            "approval_payload_root": self.approval_payload_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.approval_id, "emergency approval id")?;
        ensure_non_empty(
            &self.committee_member_id,
            "emergency approval committee member id",
        )?;
        ensure_non_empty(&self.trigger_id, "emergency approval trigger")?;
        ensure_non_empty(&self.approved_leader_id, "emergency approval leader")?;
        ensure_positive(self.voting_power, "emergency approval voting power")?;
        ensure_non_empty(
            &self.approval_payload_root,
            "emergency approval payload root",
        )?;
        ensure_non_empty(&self.pq_signature_root, "emergency approval signature")?;
        if self.expires_at_height <= self.approval_height {
            return Err("emergency approval expiry must follow approval height".to_string());
        }
        let expected = emergency_approval_id(
            &self.approval_kind,
            &self.committee_member_id,
            &self.trigger_id,
            &self.approved_leader_id,
            self.approval_height,
            &self.approval_payload_root,
        );
        if self.approval_id != expected {
            return Err("emergency approval id mismatch".to_string());
        }
        Ok(self.approval_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderHandoffCertificate {
    pub certificate_id: String,
    pub trigger_id: String,
    pub epoch_id: String,
    pub from_leader_id: String,
    pub to_leader_id: String,
    pub handoff_phase: HandoffPhase,
    pub trigger_root: String,
    pub approval_root: String,
    pub approver_root: String,
    pub total_voting_power: u64,
    pub signed_voting_power: u64,
    pub quorum_bps: u64,
    pub quorum_reached: bool,
    pub state_root_before: String,
    pub state_root_after: String,
    pub private_queue_root_before: String,
    pub private_queue_root_after: String,
    pub forced_inclusion_cursor_before: u64,
    pub forced_inclusion_cursor_after: u64,
    pub forced_inclusion_root_after: String,
    pub low_fee_root_before: String,
    pub low_fee_root_after: String,
    pub issued_at_height: u64,
    pub effective_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl LeaderHandoffCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger: &FailoverTrigger,
        epoch: &SequencerFailoverEpoch,
        approvals: &[EmergencyCommitteeApproval],
        total_voting_power: u64,
        to_leader_id: impl Into<String>,
        state_root_before: impl Into<String>,
        state_root_after: impl Into<String>,
        private_queue_root_after: impl Into<String>,
        forced_inclusion_cursor_after: u64,
        forced_inclusion_root_after: impl Into<String>,
        low_fee_root_after: impl Into<String>,
        issued_at_height: u64,
        effective_height: u64,
        expires_at_height: u64,
        quorum_bps: u64,
    ) -> SequencerFailoverResult<Self> {
        trigger.validate()?;
        epoch.validate()?;
        ensure_bps(quorum_bps, "handoff certificate quorum bps")?;
        ensure_positive(total_voting_power, "handoff certificate total voting power")?;
        let to_leader_id = to_leader_id.into();
        let state_root_before = state_root_before.into();
        let state_root_after = state_root_after.into();
        let private_queue_root_after = private_queue_root_after.into();
        let forced_inclusion_root_after = forced_inclusion_root_after.into();
        let low_fee_root_after = low_fee_root_after.into();
        ensure_non_empty(&to_leader_id, "handoff certificate target leader")?;
        ensure_non_empty(&state_root_before, "handoff certificate before root")?;
        ensure_non_empty(&state_root_after, "handoff certificate after root")?;
        ensure_non_empty(
            &private_queue_root_after,
            "handoff certificate private queue after",
        )?;
        ensure_non_empty(
            &forced_inclusion_root_after,
            "handoff certificate forced inclusion root",
        )?;
        ensure_non_empty(&low_fee_root_after, "handoff certificate low fee after")?;
        if effective_height < issued_at_height {
            return Err("handoff certificate effective height before issue height".to_string());
        }
        if expires_at_height <= issued_at_height {
            return Err("handoff certificate expiry must follow issue height".to_string());
        }
        let valid_approvals = approvals
            .iter()
            .filter(|approval| {
                approval.trigger_id == trigger.trigger_id
                    && approval.approved_leader_id == to_leader_id
                    && approval.status.counts_for_quorum()
            })
            .cloned()
            .collect::<Vec<_>>();
        let approver_ids = valid_approvals
            .iter()
            .map(|approval| approval.committee_member_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&approver_ids, "handoff certificate approvers")?;
        let signed_voting_power = valid_approvals
            .iter()
            .map(|approval| approval.voting_power)
            .sum::<u64>();
        let quorum_reached = reaches_quorum(signed_voting_power, total_voting_power, quorum_bps);
        let trigger_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-HANDOFF-TRIGGER",
            &trigger.public_record(),
        );
        let approval_root = emergency_approval_root(&valid_approvals);
        let approver_root = sequencer_failover_string_set_root(
            "SEQUENCER-FAILOVER-HANDOFF-APPROVERS",
            &approver_ids,
        );
        let certificate_id = leader_handoff_certificate_id(
            &trigger.trigger_id,
            &epoch.epoch_id,
            &epoch.primary_leader_id,
            &to_leader_id,
            &approval_root,
            signed_voting_power,
            issued_at_height,
        );
        let certificate = Self {
            certificate_id,
            trigger_id: trigger.trigger_id.clone(),
            epoch_id: epoch.epoch_id.clone(),
            from_leader_id: epoch.primary_leader_id.clone(),
            to_leader_id,
            handoff_phase: if quorum_reached {
                HandoffPhase::Certified
            } else {
                HandoffPhase::QuorumCollecting
            },
            trigger_root,
            approval_root,
            approver_root,
            total_voting_power,
            signed_voting_power,
            quorum_bps,
            quorum_reached,
            state_root_before,
            state_root_after,
            private_queue_root_before: trigger.private_queue_root.clone(),
            private_queue_root_after,
            forced_inclusion_cursor_before: epoch.forced_inclusion_cursor,
            forced_inclusion_cursor_after,
            forced_inclusion_root_after,
            low_fee_root_before: trigger.low_fee_root.clone(),
            low_fee_root_after,
            issued_at_height,
            effective_height,
            expires_at_height,
            status: if quorum_reached {
                SEQUENCER_FAILOVER_STATUS_ACTIVE.to_string()
            } else {
                SEQUENCER_FAILOVER_STATUS_STANDBY.to_string()
            },
        };
        certificate.validate()?;
        Ok(certificate)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_handoff_certificate",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "certificate_id": self.certificate_id,
            "trigger_id": self.trigger_id,
            "epoch_id": self.epoch_id,
            "from_leader_id": self.from_leader_id,
            "to_leader_id": self.to_leader_id,
            "handoff_phase": self.handoff_phase.as_str(),
            "trigger_root": self.trigger_root,
            "approval_root": self.approval_root,
            "approver_root": self.approver_root,
            "total_voting_power": self.total_voting_power,
            "signed_voting_power": self.signed_voting_power,
            "quorum_bps": self.quorum_bps,
            "quorum_reached": self.quorum_reached,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "private_queue_root_before": self.private_queue_root_before,
            "private_queue_root_after": self.private_queue_root_after,
            "forced_inclusion_cursor_before": self.forced_inclusion_cursor_before,
            "forced_inclusion_cursor_after": self.forced_inclusion_cursor_after,
            "forced_inclusion_root_after": self.forced_inclusion_root_after,
            "low_fee_root_before": self.low_fee_root_before,
            "low_fee_root_after": self.low_fee_root_after,
            "issued_at_height": self.issued_at_height,
            "effective_height": self.effective_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.certificate_id, "handoff certificate id")?;
        ensure_non_empty(&self.trigger_id, "handoff trigger id")?;
        ensure_non_empty(&self.epoch_id, "handoff epoch id")?;
        ensure_non_empty(&self.from_leader_id, "handoff from leader")?;
        ensure_non_empty(&self.to_leader_id, "handoff to leader")?;
        ensure_non_empty(&self.trigger_root, "handoff trigger root")?;
        ensure_non_empty(&self.approval_root, "handoff approval root")?;
        ensure_non_empty(&self.approver_root, "handoff approver root")?;
        ensure_positive(self.total_voting_power, "handoff total voting power")?;
        ensure_bps(self.quorum_bps, "handoff quorum")?;
        ensure_non_empty(&self.state_root_before, "handoff state root before")?;
        ensure_non_empty(&self.state_root_after, "handoff state root after")?;
        ensure_non_empty(
            &self.private_queue_root_before,
            "handoff private queue before",
        )?;
        ensure_non_empty(
            &self.private_queue_root_after,
            "handoff private queue after",
        )?;
        ensure_non_empty(
            &self.forced_inclusion_root_after,
            "handoff forced inclusion root after",
        )?;
        ensure_non_empty(&self.low_fee_root_before, "handoff low fee before")?;
        ensure_non_empty(&self.low_fee_root_after, "handoff low fee after")?;
        ensure_status(&self.status, VALID_OPEN_STATUSES)?;
        if self.signed_voting_power > self.total_voting_power {
            return Err("handoff signed power exceeds total power".to_string());
        }
        if self.effective_height < self.issued_at_height {
            return Err("handoff effective height before issue height".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("handoff expiry must follow issue height".to_string());
        }
        let expected_quorum = reaches_quorum(
            self.signed_voting_power,
            self.total_voting_power,
            self.quorum_bps,
        );
        if self.quorum_reached != expected_quorum {
            return Err("handoff quorum flag mismatch".to_string());
        }
        let expected = leader_handoff_certificate_id(
            &self.trigger_id,
            &self.epoch_id,
            &self.from_leader_id,
            &self.to_leader_id,
            &self.approval_root,
            self.signed_voting_power,
            self.issued_at_height,
        );
        if self.certificate_id != expected {
            return Err("handoff certificate id mismatch".to_string());
        }
        Ok(self.certificate_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWindow {
    pub window_id: String,
    pub trigger_id: String,
    pub certificate_id: String,
    pub emergency_leader_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub private_draining_until_height: u64,
    pub forced_inclusion_deadline_height: u64,
    pub low_fee_guarantee_until_height: u64,
    pub recovery_committee_root: String,
    pub allowed_action_root: String,
    pub pending_queue_root: String,
    pub preconfirmation_carry_root: String,
    pub status: RecoveryWindowStatus,
}

impl RecoveryWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate: &LeaderHandoffCertificate,
        config: &SequencerFailoverConfig,
        emergency_committee_members: &BTreeMap<String, EmergencyCommitteeMember>,
        pending_queue_root: impl Into<String>,
        preconfirmation_carry_root: impl Into<String>,
    ) -> SequencerFailoverResult<Self> {
        certificate.validate()?;
        config.validate()?;
        let pending_queue_root = pending_queue_root.into();
        let preconfirmation_carry_root = preconfirmation_carry_root.into();
        ensure_non_empty(&pending_queue_root, "recovery window pending queue root")?;
        ensure_non_empty(
            &preconfirmation_carry_root,
            "recovery window preconfirmation root",
        )?;
        let start_height = certificate.effective_height;
        let end_height = start_height.saturating_add(config.recovery_window_blocks);
        let private_draining_until_height =
            start_height.saturating_add(config.private_drain_blocks);
        let forced_inclusion_deadline_height =
            start_height.saturating_add(config.forced_inclusion_grace_blocks);
        let low_fee_guarantee_until_height = end_height;
        let recovery_committee_root =
            emergency_committee_member_root_from_map(emergency_committee_members);
        let allowed_action_root = sequencer_failover_string_set_root(
            "SEQUENCER-FAILOVER-RECOVERY-ALLOWED-ACTIONS",
            &[
                "produce_emergency_microblocks".to_string(),
                "drain_private_queue".to_string(),
                "preserve_low_fee_lane".to_string(),
                "claim_forced_inclusion_tickets".to_string(),
                "publish_censorship_evidence".to_string(),
            ],
        );
        let window_id = recovery_window_id(
            &certificate.certificate_id,
            &certificate.trigger_id,
            &certificate.to_leader_id,
            start_height,
            end_height,
            &pending_queue_root,
        );
        let window = Self {
            window_id,
            trigger_id: certificate.trigger_id.clone(),
            certificate_id: certificate.certificate_id.clone(),
            emergency_leader_id: certificate.to_leader_id.clone(),
            start_height,
            end_height,
            private_draining_until_height,
            forced_inclusion_deadline_height,
            low_fee_guarantee_until_height,
            recovery_committee_root,
            allowed_action_root,
            pending_queue_root,
            preconfirmation_carry_root,
            status: RecoveryWindowStatus::Open,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.is_open() && self.start_height <= height && height <= self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_recovery_window",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "trigger_id": self.trigger_id,
            "certificate_id": self.certificate_id,
            "emergency_leader_id": self.emergency_leader_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "private_draining_until_height": self.private_draining_until_height,
            "forced_inclusion_deadline_height": self.forced_inclusion_deadline_height,
            "low_fee_guarantee_until_height": self.low_fee_guarantee_until_height,
            "recovery_committee_root": self.recovery_committee_root,
            "allowed_action_root": self.allowed_action_root,
            "pending_queue_root": self.pending_queue_root,
            "preconfirmation_carry_root": self.preconfirmation_carry_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.window_id, "recovery window id")?;
        ensure_non_empty(&self.trigger_id, "recovery window trigger")?;
        ensure_non_empty(&self.certificate_id, "recovery window certificate")?;
        ensure_non_empty(&self.emergency_leader_id, "recovery window leader")?;
        ensure_non_empty(
            &self.recovery_committee_root,
            "recovery window committee root",
        )?;
        ensure_non_empty(&self.allowed_action_root, "recovery window action root")?;
        ensure_non_empty(&self.pending_queue_root, "recovery window pending queue")?;
        ensure_non_empty(
            &self.preconfirmation_carry_root,
            "recovery window preconfirmation root",
        )?;
        if self.end_height <= self.start_height {
            return Err("recovery window end must follow start".to_string());
        }
        if self.private_draining_until_height < self.start_height {
            return Err("recovery private drain before start".to_string());
        }
        if self.forced_inclusion_deadline_height < self.start_height {
            return Err("recovery forced inclusion deadline before start".to_string());
        }
        if self.low_fee_guarantee_until_height < self.start_height {
            return Err("recovery low fee guarantee before start".to_string());
        }
        let expected = recovery_window_id(
            &self.certificate_id,
            &self.trigger_id,
            &self.emergency_leader_id,
            self.start_height,
            self.end_height,
            &self.pending_queue_root,
        );
        if self.window_id != expected {
            return Err("recovery window id mismatch".to_string());
        }
        Ok(self.window_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeLaneGuarantee {
    pub guarantee_id: String,
    pub lane_id: String,
    pub lane_label: String,
    pub lane_kind: FailoverLaneKind,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub min_share_bps: u64,
    pub reserved_capacity_units: u64,
    pub consumed_capacity_units: u64,
    pub sponsor_pool_root: String,
    pub inclusion_cursor: u64,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeGuaranteeStatus,
}

impl LowFeeLaneGuarantee {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_label: impl Into<String>,
        lane_kind: FailoverLaneKind,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        min_share_bps: u64,
        reserved_capacity_units: u64,
        active_from_height: u64,
        expires_at_height: u64,
    ) -> SequencerFailoverResult<Self> {
        let lane_label = lane_label.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&lane_label, "low fee guarantee lane label")?;
        ensure_non_empty(&fee_asset_id, "low fee guarantee fee asset")?;
        ensure_positive(max_fee_units, "low fee guarantee max fee")?;
        ensure_bps(min_share_bps, "low fee guarantee min share")?;
        ensure_positive(
            reserved_capacity_units,
            "low fee guarantee reserved capacity",
        )?;
        if !lane_kind.low_fee_eligible() {
            return Err("low fee guarantee lane kind is not low fee eligible".to_string());
        }
        if expires_at_height <= active_from_height {
            return Err("low fee guarantee expiry must follow activation".to_string());
        }
        let lane_id = low_fee_lane_id(&lane_label, &lane_kind, &fee_asset_id, active_from_height);
        let sponsor_pool_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-LOW-FEE-SPONSOR-POOL",
            &json!({
                "lane_id": lane_id,
                "fee_asset_id": fee_asset_id,
                "reserved_capacity_units": reserved_capacity_units,
            }),
        );
        let guarantee_id = low_fee_lane_guarantee_id(
            &lane_id,
            max_fee_units,
            min_share_bps,
            reserved_capacity_units,
            active_from_height,
            expires_at_height,
        );
        let guarantee = Self {
            guarantee_id,
            lane_id,
            lane_label,
            lane_kind,
            fee_asset_id,
            max_fee_units,
            min_share_bps,
            reserved_capacity_units,
            consumed_capacity_units: 0,
            sponsor_pool_root,
            inclusion_cursor: 0,
            active_from_height,
            expires_at_height,
            status: LowFeeGuaranteeStatus::Active,
        };
        guarantee.validate()?;
        Ok(guarantee)
    }

    pub fn available_capacity_units(&self) -> u64 {
        self.reserved_capacity_units
            .saturating_sub(self.consumed_capacity_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.can_reserve()
            && self.active_from_height <= height
            && height <= self.expires_at_height
    }

    pub fn consume_capacity(&mut self, units: u64, cursor: u64) -> SequencerFailoverResult<()> {
        if units > self.available_capacity_units() {
            return Err("low fee guarantee capacity exhausted".to_string());
        }
        self.consumed_capacity_units = self.consumed_capacity_units.saturating_add(units);
        self.inclusion_cursor = self.inclusion_cursor.max(cursor);
        if self.available_capacity_units() == 0 {
            self.status = LowFeeGuaranteeStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_low_fee_lane_guarantee",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "guarantee_id": self.guarantee_id,
            "lane_id": self.lane_id,
            "lane_label": self.lane_label,
            "lane_kind": self.lane_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "min_share_bps": self.min_share_bps,
            "reserved_capacity_units": self.reserved_capacity_units,
            "consumed_capacity_units": self.consumed_capacity_units,
            "available_capacity_units": self.available_capacity_units(),
            "sponsor_pool_root": self.sponsor_pool_root,
            "inclusion_cursor": self.inclusion_cursor,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.guarantee_id, "low fee guarantee id")?;
        ensure_non_empty(&self.lane_id, "low fee guarantee lane id")?;
        ensure_non_empty(&self.lane_label, "low fee guarantee label")?;
        ensure_non_empty(&self.fee_asset_id, "low fee guarantee fee asset")?;
        ensure_positive(self.max_fee_units, "low fee guarantee max fee")?;
        ensure_bps(self.min_share_bps, "low fee guarantee min share")?;
        ensure_positive(self.reserved_capacity_units, "low fee guarantee reserve")?;
        ensure_non_empty(&self.sponsor_pool_root, "low fee sponsor pool root")?;
        if !self.lane_kind.low_fee_eligible() {
            return Err("low fee guarantee lane is not eligible".to_string());
        }
        if self.consumed_capacity_units > self.reserved_capacity_units {
            return Err("low fee guarantee consumed capacity exceeds reserve".to_string());
        }
        if self.expires_at_height <= self.active_from_height {
            return Err("low fee guarantee expiry must follow activation".to_string());
        }
        let expected_lane_id = low_fee_lane_id(
            &self.lane_label,
            &self.lane_kind,
            &self.fee_asset_id,
            self.active_from_height,
        );
        if self.lane_id != expected_lane_id {
            return Err("low fee lane id mismatch".to_string());
        }
        let expected = low_fee_lane_guarantee_id(
            &self.lane_id,
            self.max_fee_units,
            self.min_share_bps,
            self.reserved_capacity_units,
            self.active_from_height,
            self.expires_at_height,
        );
        if self.guarantee_id != expected {
            return Err("low fee guarantee id mismatch".to_string());
        }
        Ok(self.guarantee_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedQueueDrainItem {
    pub item_id: String,
    pub lane_id: String,
    pub lane_kind: FailoverLaneKind,
    pub encrypted_envelope_id: String,
    pub queue_position: u64,
    pub payload_ciphertext_root: String,
    pub nullifier_root: String,
    pub fee_commitment_root: String,
    pub arrival_height: u64,
    pub target_inclusion_height: u64,
    pub forced_inclusion_ticket_id: Option<String>,
    pub low_fee_guarantee_id: Option<String>,
    pub metadata_root: String,
    pub status: DrainStatus,
}

impl EncryptedQueueDrainItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: impl Into<String>,
        lane_kind: FailoverLaneKind,
        encrypted_envelope_id: impl Into<String>,
        queue_position: u64,
        encrypted_payload: &Value,
        fee_commitment_root: impl Into<String>,
        arrival_height: u64,
        target_inclusion_height: u64,
        forced_inclusion_ticket_id: Option<String>,
        low_fee_guarantee_id: Option<String>,
        metadata: &Value,
    ) -> SequencerFailoverResult<Self> {
        let lane_id = lane_id.into();
        let encrypted_envelope_id = encrypted_envelope_id.into();
        let fee_commitment_root = fee_commitment_root.into();
        ensure_non_empty(&lane_id, "drain item lane")?;
        ensure_non_empty(&encrypted_envelope_id, "drain item envelope")?;
        ensure_non_empty(&fee_commitment_root, "drain item fee commitment")?;
        if target_inclusion_height < arrival_height {
            return Err("drain item target before arrival".to_string());
        }
        let payload_ciphertext_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-DRAIN-PAYLOAD", encrypted_payload);
        let nullifier_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-DRAIN-NULLIFIER",
            &json!({
                "lane_id": lane_id,
                "encrypted_envelope_id": encrypted_envelope_id,
                "queue_position": queue_position,
            }),
        );
        let metadata_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-DRAIN-METADATA", metadata);
        let item_id = encrypted_queue_drain_item_id(
            &lane_id,
            &lane_kind,
            &encrypted_envelope_id,
            queue_position,
            &payload_ciphertext_root,
            &nullifier_root,
        );
        let item = Self {
            item_id,
            lane_id,
            lane_kind,
            encrypted_envelope_id,
            queue_position,
            payload_ciphertext_root,
            nullifier_root,
            fee_commitment_root,
            arrival_height,
            target_inclusion_height,
            forced_inclusion_ticket_id,
            low_fee_guarantee_id,
            metadata_root,
            status: DrainStatus::Pending,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_encrypted_queue_drain_item",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "item_id": self.item_id,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "encrypted_envelope_id": self.encrypted_envelope_id,
            "queue_position": self.queue_position,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "fee_commitment_root": self.fee_commitment_root,
            "arrival_height": self.arrival_height,
            "target_inclusion_height": self.target_inclusion_height,
            "forced_inclusion_ticket_id": self.forced_inclusion_ticket_id,
            "low_fee_guarantee_id": self.low_fee_guarantee_id,
            "metadata_root": self.metadata_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.item_id, "drain item id")?;
        ensure_non_empty(&self.lane_id, "drain item lane id")?;
        ensure_non_empty(&self.encrypted_envelope_id, "drain item envelope")?;
        ensure_non_empty(&self.payload_ciphertext_root, "drain item payload")?;
        ensure_non_empty(&self.nullifier_root, "drain item nullifier")?;
        ensure_non_empty(&self.fee_commitment_root, "drain item fee root")?;
        ensure_non_empty(&self.metadata_root, "drain item metadata")?;
        if self.target_inclusion_height < self.arrival_height {
            return Err("drain item target before arrival".to_string());
        }
        let expected = encrypted_queue_drain_item_id(
            &self.lane_id,
            &self.lane_kind,
            &self.encrypted_envelope_id,
            self.queue_position,
            &self.payload_ciphertext_root,
            &self.nullifier_root,
        );
        if self.item_id != expected {
            return Err("encrypted queue drain item id mismatch".to_string());
        }
        Ok(self.item_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedQueueDrainManifest {
    pub manifest_id: String,
    pub recovery_window_id: String,
    pub source_leader_id: String,
    pub target_leader_id: String,
    pub epoch_id: String,
    pub manifest_sequence: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub drain_policy: String,
    pub item_ids: Vec<String>,
    pub queue_root: String,
    pub private_queue_before_root: String,
    pub private_queue_after_root: String,
    pub forced_inclusion_cursor_root: String,
    pub low_fee_lane_root: String,
    pub total_payload_bytes: u64,
    pub status: String,
}

impl EncryptedQueueDrainManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recovery_window: &RecoveryWindow,
        source_leader_id: impl Into<String>,
        target_leader_id: impl Into<String>,
        epoch_id: impl Into<String>,
        manifest_sequence: u64,
        items: &[EncryptedQueueDrainItem],
        private_queue_before_root: impl Into<String>,
        private_queue_after_root: impl Into<String>,
        forced_inclusion_cursor_root: impl Into<String>,
        low_fee_lane_root: impl Into<String>,
        total_payload_bytes: u64,
    ) -> SequencerFailoverResult<Self> {
        recovery_window.validate()?;
        let source_leader_id = source_leader_id.into();
        let target_leader_id = target_leader_id.into();
        let epoch_id = epoch_id.into();
        let private_queue_before_root = private_queue_before_root.into();
        let private_queue_after_root = private_queue_after_root.into();
        let forced_inclusion_cursor_root = forced_inclusion_cursor_root.into();
        let low_fee_lane_root = low_fee_lane_root.into();
        ensure_non_empty(&source_leader_id, "drain manifest source leader")?;
        ensure_non_empty(&target_leader_id, "drain manifest target leader")?;
        ensure_non_empty(&epoch_id, "drain manifest epoch")?;
        ensure_non_empty(
            &private_queue_before_root,
            "drain manifest private queue before",
        )?;
        ensure_non_empty(
            &private_queue_after_root,
            "drain manifest private queue after",
        )?;
        ensure_non_empty(
            &forced_inclusion_cursor_root,
            "drain manifest forced inclusion cursor",
        )?;
        ensure_non_empty(&low_fee_lane_root, "drain manifest low fee lane root")?;
        if items.is_empty() {
            return Err("drain manifest requires at least one item".to_string());
        }
        let item_ids = items
            .iter()
            .map(|item| item.item_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&item_ids, "drain manifest item ids")?;
        let queue_root = encrypted_queue_drain_item_root(items);
        let start_height = recovery_window.start_height;
        let end_height = recovery_window.private_draining_until_height;
        let drain_policy = SEQUENCER_FAILOVER_PRIVACY_POLICY.to_string();
        let manifest_id = encrypted_queue_drain_manifest_id(
            &recovery_window.window_id,
            &source_leader_id,
            &target_leader_id,
            manifest_sequence,
            &queue_root,
            &private_queue_before_root,
            &private_queue_after_root,
        );
        let manifest = Self {
            manifest_id,
            recovery_window_id: recovery_window.window_id.clone(),
            source_leader_id,
            target_leader_id,
            epoch_id,
            manifest_sequence,
            start_height,
            end_height,
            drain_policy,
            item_ids,
            queue_root,
            private_queue_before_root,
            private_queue_after_root,
            forced_inclusion_cursor_root,
            low_fee_lane_root,
            total_payload_bytes,
            status: SEQUENCER_FAILOVER_STATUS_DRAINING.to_string(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_encrypted_queue_drain_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "recovery_window_id": self.recovery_window_id,
            "source_leader_id": self.source_leader_id,
            "target_leader_id": self.target_leader_id,
            "epoch_id": self.epoch_id,
            "manifest_sequence": self.manifest_sequence,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "drain_policy": self.drain_policy,
            "item_ids": self.item_ids,
            "queue_root": self.queue_root,
            "private_queue_before_root": self.private_queue_before_root,
            "private_queue_after_root": self.private_queue_after_root,
            "forced_inclusion_cursor_root": self.forced_inclusion_cursor_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "total_payload_bytes": self.total_payload_bytes,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.manifest_id, "drain manifest id")?;
        ensure_non_empty(&self.recovery_window_id, "drain manifest recovery window")?;
        ensure_non_empty(&self.source_leader_id, "drain manifest source leader")?;
        ensure_non_empty(&self.target_leader_id, "drain manifest target leader")?;
        ensure_non_empty(&self.epoch_id, "drain manifest epoch")?;
        ensure_non_empty(&self.drain_policy, "drain manifest policy")?;
        ensure_non_empty(&self.queue_root, "drain manifest queue root")?;
        ensure_non_empty(
            &self.private_queue_before_root,
            "drain manifest private queue before",
        )?;
        ensure_non_empty(
            &self.private_queue_after_root,
            "drain manifest private queue after",
        )?;
        ensure_non_empty(
            &self.forced_inclusion_cursor_root,
            "drain manifest forced inclusion cursor",
        )?;
        ensure_non_empty(&self.low_fee_lane_root, "drain manifest low fee")?;
        ensure_status(&self.status, VALID_OPEN_STATUSES)?;
        if self.end_height < self.start_height {
            return Err("drain manifest end before start".to_string());
        }
        if self.item_ids.is_empty() {
            return Err("drain manifest item ids cannot be empty".to_string());
        }
        ensure_unique_strings(&self.item_ids, "drain manifest item ids")?;
        let expected = encrypted_queue_drain_manifest_id(
            &self.recovery_window_id,
            &self.source_leader_id,
            &self.target_leader_id,
            self.manifest_sequence,
            &self.queue_root,
            &self.private_queue_before_root,
            &self.private_queue_after_root,
        );
        if self.manifest_id != expected {
            return Err("encrypted queue drain manifest id mismatch".to_string());
        }
        Ok(self.manifest_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMempoolContinuityReceipt {
    pub receipt_id: String,
    pub receipt_kind: ContinuityReceiptKind,
    pub manifest_id: String,
    pub item_id: String,
    pub encrypted_envelope_id: String,
    pub included_height: u64,
    pub included_block_root: String,
    pub dequeue_proof_root: String,
    pub privacy_receipt_root: String,
    pub forced_inclusion_ticket_id: Option<String>,
    pub low_fee_guarantee_id: Option<String>,
    pub preconfirmation_id: Option<String>,
    pub status: String,
}

impl PrivateMempoolContinuityReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_kind: ContinuityReceiptKind,
        manifest: &EncryptedQueueDrainManifest,
        item: &EncryptedQueueDrainItem,
        included_height: u64,
        included_block: &Value,
        dequeue_proof: &Value,
        privacy_receipt: &Value,
        preconfirmation_id: Option<String>,
    ) -> SequencerFailoverResult<Self> {
        manifest.validate()?;
        item.validate()?;
        if !manifest.item_ids.contains(&item.item_id) {
            return Err("continuity receipt item is not in drain manifest".to_string());
        }
        let included_block_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-RECEIPT-BLOCK", included_block);
        let dequeue_proof_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-RECEIPT-DEQUEUE", dequeue_proof);
        let privacy_receipt_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-RECEIPT-PRIVACY", privacy_receipt);
        let receipt_id = private_mempool_continuity_receipt_id(
            &receipt_kind,
            &manifest.manifest_id,
            &item.item_id,
            &item.encrypted_envelope_id,
            included_height,
            &included_block_root,
            &dequeue_proof_root,
        );
        let receipt = Self {
            receipt_id,
            receipt_kind,
            manifest_id: manifest.manifest_id.clone(),
            item_id: item.item_id.clone(),
            encrypted_envelope_id: item.encrypted_envelope_id.clone(),
            included_height,
            included_block_root,
            dequeue_proof_root,
            privacy_receipt_root,
            forced_inclusion_ticket_id: item.forced_inclusion_ticket_id.clone(),
            low_fee_guarantee_id: item.low_fee_guarantee_id.clone(),
            preconfirmation_id,
            status: SEQUENCER_FAILOVER_STATUS_FINALIZED.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_private_mempool_continuity_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "manifest_id": self.manifest_id,
            "item_id": self.item_id,
            "encrypted_envelope_id": self.encrypted_envelope_id,
            "included_height": self.included_height,
            "included_block_root": self.included_block_root,
            "dequeue_proof_root": self.dequeue_proof_root,
            "privacy_receipt_root": self.privacy_receipt_root,
            "forced_inclusion_ticket_id": self.forced_inclusion_ticket_id,
            "low_fee_guarantee_id": self.low_fee_guarantee_id,
            "preconfirmation_id": self.preconfirmation_id,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.receipt_id, "continuity receipt id")?;
        ensure_non_empty(&self.manifest_id, "continuity receipt manifest")?;
        ensure_non_empty(&self.item_id, "continuity receipt item")?;
        ensure_non_empty(&self.encrypted_envelope_id, "continuity receipt envelope")?;
        ensure_non_empty(&self.included_block_root, "continuity receipt block")?;
        ensure_non_empty(&self.dequeue_proof_root, "continuity receipt dequeue")?;
        ensure_non_empty(&self.privacy_receipt_root, "continuity receipt privacy")?;
        ensure_status(&self.status, VALID_OPEN_STATUSES)?;
        let expected = private_mempool_continuity_receipt_id(
            &self.receipt_kind,
            &self.manifest_id,
            &self.item_id,
            &self.encrypted_envelope_id,
            self.included_height,
            &self.included_block_root,
            &self.dequeue_proof_root,
        );
        if self.receipt_id != expected {
            return Err("private mempool continuity receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashableSequencerEvidence {
    pub evidence_id: String,
    pub evidence_kind: SlashableEvidenceKind,
    pub offender_leader_id: String,
    pub observer_id: String,
    pub trigger_id: Option<String>,
    pub item_id: Option<String>,
    pub observed_height: u64,
    pub first_fault_height: u64,
    pub deadline_height: u64,
    pub evidence_payload_root: String,
    pub omitted_queue_root: String,
    pub forced_inclusion_ticket_root: String,
    pub low_fee_violation_root: String,
    pub expected_action_root: String,
    pub observed_action_root: String,
    pub slash_bps: u64,
    pub status: EvidenceStatus,
}

impl SlashableSequencerEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: SlashableEvidenceKind,
        offender_leader_id: impl Into<String>,
        observer_id: impl Into<String>,
        trigger_id: Option<String>,
        item_id: Option<String>,
        observed_height: u64,
        first_fault_height: u64,
        deadline_height: u64,
        evidence_payload: &Value,
        omitted_queue: &Value,
        forced_inclusion_tickets: &[String],
        low_fee_violation: &Value,
        expected_action: &Value,
        observed_action: &Value,
        config: &SequencerFailoverConfig,
    ) -> SequencerFailoverResult<Self> {
        config.validate()?;
        let offender_leader_id = offender_leader_id.into();
        let observer_id = observer_id.into();
        ensure_non_empty(&offender_leader_id, "slashable evidence offender")?;
        ensure_non_empty(&observer_id, "slashable evidence observer")?;
        if observed_height < first_fault_height {
            return Err("slashable evidence observed before first fault".to_string());
        }
        if deadline_height < observed_height {
            return Err("slashable evidence deadline before observation".to_string());
        }
        let evidence_payload_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-EVIDENCE-PAYLOAD",
            evidence_payload,
        );
        let omitted_queue_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-EVIDENCE-OMITTED-QUEUE",
            omitted_queue,
        );
        let forced_inclusion_ticket_root = sequencer_failover_string_set_root(
            "SEQUENCER-FAILOVER-EVIDENCE-FORCED-TICKETS",
            forced_inclusion_tickets,
        );
        let low_fee_violation_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-EVIDENCE-LOW-FEE",
            low_fee_violation,
        );
        let expected_action_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-EVIDENCE-EXPECTED",
            expected_action,
        );
        let observed_action_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-EVIDENCE-OBSERVED",
            observed_action,
        );
        let slash_bps = evidence_kind.default_slash_bps(config);
        let evidence_id = slashable_sequencer_evidence_id(
            &evidence_kind,
            &offender_leader_id,
            observed_height,
            first_fault_height,
            &evidence_payload_root,
            &expected_action_root,
            &observed_action_root,
        );
        let evidence = Self {
            evidence_id,
            evidence_kind,
            offender_leader_id,
            observer_id,
            trigger_id,
            item_id,
            observed_height,
            first_fault_height,
            deadline_height,
            evidence_payload_root,
            omitted_queue_root,
            forced_inclusion_ticket_root,
            low_fee_violation_root,
            expected_action_root,
            observed_action_root,
            slash_bps,
            status: EvidenceStatus::Observed,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn mark_accepted(&mut self) {
        self.status = EvidenceStatus::Accepted;
    }

    pub fn is_slashable_at(&self, height: u64) -> bool {
        self.status.slashable() && height <= self.deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_slashable_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "offender_leader_id": self.offender_leader_id,
            "observer_id": self.observer_id,
            "trigger_id": self.trigger_id,
            "item_id": self.item_id,
            "observed_height": self.observed_height,
            "first_fault_height": self.first_fault_height,
            "deadline_height": self.deadline_height,
            "evidence_payload_root": self.evidence_payload_root,
            "omitted_queue_root": self.omitted_queue_root,
            "forced_inclusion_ticket_root": self.forced_inclusion_ticket_root,
            "low_fee_violation_root": self.low_fee_violation_root,
            "expected_action_root": self.expected_action_root,
            "observed_action_root": self.observed_action_root,
            "slash_bps": self.slash_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.evidence_id, "slashable evidence id")?;
        ensure_non_empty(&self.offender_leader_id, "slashable evidence offender")?;
        ensure_non_empty(&self.observer_id, "slashable evidence observer")?;
        ensure_non_empty(&self.evidence_payload_root, "slashable evidence payload")?;
        ensure_non_empty(&self.omitted_queue_root, "slashable evidence omitted queue")?;
        ensure_non_empty(
            &self.forced_inclusion_ticket_root,
            "slashable evidence forced inclusion tickets",
        )?;
        ensure_non_empty(&self.low_fee_violation_root, "slashable evidence low fee")?;
        ensure_non_empty(
            &self.expected_action_root,
            "slashable evidence expected action",
        )?;
        ensure_non_empty(
            &self.observed_action_root,
            "slashable evidence observed action",
        )?;
        ensure_bps(self.slash_bps, "slashable evidence slash bps")?;
        if self.observed_height < self.first_fault_height {
            return Err("slashable evidence observed before first fault".to_string());
        }
        if self.deadline_height < self.observed_height {
            return Err("slashable evidence deadline before observation".to_string());
        }
        let expected = slashable_sequencer_evidence_id(
            &self.evidence_kind,
            &self.offender_leader_id,
            self.observed_height,
            self.first_fault_height,
            &self.evidence_payload_root,
            &self.expected_action_root,
            &self.observed_action_root,
        );
        if self.evidence_id != expected {
            return Err("slashable sequencer evidence id mismatch".to_string());
        }
        Ok(self.evidence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerFailoverPublicRecord {
    pub record_id: String,
    pub source_id: String,
    pub label: String,
    pub payload_kind: String,
    pub payload_root: String,
    pub height: u64,
    pub visibility: String,
}

impl SequencerFailoverPublicRecord {
    pub fn new(
        source_id: impl Into<String>,
        label: impl Into<String>,
        payload_kind: impl Into<String>,
        payload: &Value,
        height: u64,
    ) -> SequencerFailoverResult<Self> {
        let source_id = source_id.into();
        let label = label.into();
        let payload_kind = payload_kind.into();
        ensure_non_empty(&source_id, "failover public record source")?;
        ensure_non_empty(&label, "failover public record label")?;
        ensure_non_empty(&payload_kind, "failover public record kind")?;
        let payload_root =
            sequencer_failover_payload_root("SEQUENCER-FAILOVER-PUBLIC-RECORD-PAYLOAD", payload);
        let record_id = sequencer_failover_public_record_id(
            &source_id,
            &label,
            &payload_kind,
            &payload_root,
            height,
        );
        let record = Self {
            record_id,
            source_id,
            label,
            payload_kind,
            payload_root,
            height,
            visibility: "public_roots_only".to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "source_id": self.source_id,
            "label": self.label,
            "payload_kind": self.payload_kind,
            "payload_root": self.payload_root,
            "height": self.height,
            "visibility": self.visibility,
        })
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        ensure_non_empty(&self.record_id, "failover public record id")?;
        ensure_non_empty(&self.source_id, "failover public record source")?;
        ensure_non_empty(&self.label, "failover public record label")?;
        ensure_non_empty(&self.payload_kind, "failover public record kind")?;
        ensure_non_empty(&self.payload_root, "failover public record payload")?;
        ensure_non_empty(&self.visibility, "failover public record visibility")?;
        let expected = sequencer_failover_public_record_id(
            &self.source_id,
            &self.label,
            &self.payload_kind,
            &self.payload_root,
            self.height,
        );
        if self.record_id != expected {
            return Err("failover public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerFailoverRoots {
    pub config_root: String,
    pub leader_root: String,
    pub emergency_committee_root: String,
    pub epoch_root: String,
    pub trigger_root: String,
    pub emergency_approval_root: String,
    pub handoff_certificate_root: String,
    pub recovery_window_root: String,
    pub low_fee_guarantee_root: String,
    pub encrypted_queue_drain_item_root: String,
    pub encrypted_queue_drain_manifest_root: String,
    pub private_mempool_continuity_receipt_root: String,
    pub slashable_evidence_root: String,
    pub public_record_root: String,
    pub forced_inclusion_root: String,
    pub private_queue_root: String,
    pub low_fee_lane_root: String,
    pub state_root: String,
}

impl SequencerFailoverRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "leader_root": self.leader_root,
            "emergency_committee_root": self.emergency_committee_root,
            "epoch_root": self.epoch_root,
            "trigger_root": self.trigger_root,
            "emergency_approval_root": self.emergency_approval_root,
            "handoff_certificate_root": self.handoff_certificate_root,
            "recovery_window_root": self.recovery_window_root,
            "low_fee_guarantee_root": self.low_fee_guarantee_root,
            "encrypted_queue_drain_item_root": self.encrypted_queue_drain_item_root,
            "encrypted_queue_drain_manifest_root": self.encrypted_queue_drain_manifest_root,
            "private_mempool_continuity_receipt_root": self.private_mempool_continuity_receipt_root,
            "slashable_evidence_root": self.slashable_evidence_root,
            "public_record_root": self.public_record_root,
            "forced_inclusion_root": self.forced_inclusion_root,
            "private_queue_root": self.private_queue_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerFailoverCounters {
    pub leader_count: u64,
    pub active_leader_count: u64,
    pub emergency_committee_member_count: u64,
    pub epoch_count: u64,
    pub trigger_count: u64,
    pub open_trigger_count: u64,
    pub emergency_approval_count: u64,
    pub handoff_certificate_count: u64,
    pub recovery_window_count: u64,
    pub active_recovery_window_count: u64,
    pub low_fee_guarantee_count: u64,
    pub encrypted_queue_drain_item_count: u64,
    pub pending_private_queue_items: u64,
    pub drained_private_queue_items: u64,
    pub encrypted_queue_drain_manifest_count: u64,
    pub continuity_receipt_count: u64,
    pub slashable_evidence_count: u64,
    pub accepted_slashable_evidence_count: u64,
    pub public_record_count: u64,
    pub forced_inclusion_cursor: u64,
    pub low_fee_reserved_capacity_units: u64,
    pub low_fee_consumed_capacity_units: u64,
    pub private_queue_pressure_bps: u64,
}

impl SequencerFailoverCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_failover_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "leader_count": self.leader_count,
            "active_leader_count": self.active_leader_count,
            "emergency_committee_member_count": self.emergency_committee_member_count,
            "epoch_count": self.epoch_count,
            "trigger_count": self.trigger_count,
            "open_trigger_count": self.open_trigger_count,
            "emergency_approval_count": self.emergency_approval_count,
            "handoff_certificate_count": self.handoff_certificate_count,
            "recovery_window_count": self.recovery_window_count,
            "active_recovery_window_count": self.active_recovery_window_count,
            "low_fee_guarantee_count": self.low_fee_guarantee_count,
            "encrypted_queue_drain_item_count": self.encrypted_queue_drain_item_count,
            "pending_private_queue_items": self.pending_private_queue_items,
            "drained_private_queue_items": self.drained_private_queue_items,
            "encrypted_queue_drain_manifest_count": self.encrypted_queue_drain_manifest_count,
            "continuity_receipt_count": self.continuity_receipt_count,
            "slashable_evidence_count": self.slashable_evidence_count,
            "accepted_slashable_evidence_count": self.accepted_slashable_evidence_count,
            "public_record_count": self.public_record_count,
            "forced_inclusion_cursor": self.forced_inclusion_cursor,
            "low_fee_reserved_capacity_units": self.low_fee_reserved_capacity_units,
            "low_fee_consumed_capacity_units": self.low_fee_consumed_capacity_units,
            "private_queue_pressure_bps": self.private_queue_pressure_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerFailoverState {
    pub config: SequencerFailoverConfig,
    pub height: u64,
    pub epoch: u64,
    pub status: String,
    pub current_leader_id: String,
    pub emergency_mode: bool,
    pub leaders: BTreeMap<String, SequencerLeader>,
    pub emergency_committee_members: BTreeMap<String, EmergencyCommitteeMember>,
    pub epochs: BTreeMap<String, SequencerFailoverEpoch>,
    pub triggers: BTreeMap<String, FailoverTrigger>,
    pub emergency_approvals: BTreeMap<String, EmergencyCommitteeApproval>,
    pub handoff_certificates: BTreeMap<String, LeaderHandoffCertificate>,
    pub recovery_windows: BTreeMap<String, RecoveryWindow>,
    pub low_fee_guarantees: BTreeMap<String, LowFeeLaneGuarantee>,
    pub encrypted_queue_drain_items: BTreeMap<String, EncryptedQueueDrainItem>,
    pub encrypted_queue_drain_manifests: BTreeMap<String, EncryptedQueueDrainManifest>,
    pub continuity_receipts: BTreeMap<String, PrivateMempoolContinuityReceipt>,
    pub slashable_evidence: BTreeMap<String, SlashableSequencerEvidence>,
    pub public_records: BTreeMap<String, SequencerFailoverPublicRecord>,
    pub forced_inclusion_cursor: u64,
    pub last_handoff_certificate_id: Option<String>,
    pub parent_state_root: String,
}

impl Default for SequencerFailoverState {
    fn default() -> Self {
        Self::new(
            SequencerFailoverConfig::default(),
            SEQUENCER_FAILOVER_DEVNET_OPERATOR_LABEL,
            Vec::new(),
            Vec::new(),
        )
        .expect("default sequencer failover state")
    }
}

impl SequencerFailoverState {
    pub fn new(
        config: SequencerFailoverConfig,
        operator_label: &str,
        leaders: Vec<SequencerLeader>,
        emergency_committee_members: Vec<EmergencyCommitteeMember>,
    ) -> SequencerFailoverResult<Self> {
        config.validate()?;
        ensure_non_empty(operator_label, "sequencer failover operator label")?;
        let mut leader_map = BTreeMap::new();
        for leader in leaders {
            leader.validate()?;
            if leader_map
                .insert(leader.leader_id.clone(), leader)
                .is_some()
            {
                return Err("duplicate sequencer failover leader id".to_string());
            }
        }
        let mut committee_map = BTreeMap::new();
        for member in emergency_committee_members {
            member.validate()?;
            if committee_map
                .insert(member.member_id.clone(), member)
                .is_some()
            {
                return Err("duplicate sequencer failover emergency member id".to_string());
            }
        }
        let current_leader_id = leader_map
            .values()
            .find(|leader| leader.role == SequencerLeaderRole::Primary)
            .map(|leader| leader.leader_id.clone())
            .or_else(|| {
                leader_map
                    .values()
                    .next()
                    .map(|leader| leader.leader_id.clone())
            })
            .unwrap_or_else(|| {
                sequencer_failover_string_root(
                    "SEQUENCER-FAILOVER-EMPTY-CURRENT-LEADER",
                    operator_label,
                )
            });
        Ok(Self {
            config,
            height: 0,
            epoch: 0,
            status: SEQUENCER_FAILOVER_STATUS_ACTIVE.to_string(),
            current_leader_id,
            emergency_mode: false,
            leaders: leader_map,
            emergency_committee_members: committee_map,
            epochs: BTreeMap::new(),
            triggers: BTreeMap::new(),
            emergency_approvals: BTreeMap::new(),
            handoff_certificates: BTreeMap::new(),
            recovery_windows: BTreeMap::new(),
            low_fee_guarantees: BTreeMap::new(),
            encrypted_queue_drain_items: BTreeMap::new(),
            encrypted_queue_drain_manifests: BTreeMap::new(),
            continuity_receipts: BTreeMap::new(),
            slashable_evidence: BTreeMap::new(),
            public_records: BTreeMap::new(),
            forced_inclusion_cursor: 0,
            last_handoff_certificate_id: None,
            parent_state_root: sequencer_failover_string_root(
                "SEQUENCER-FAILOVER-PARENT-STATE",
                SEQUENCER_FAILOVER_DEVNET_PARENT_ROOT,
            ),
        })
    }

    pub fn devnet() -> SequencerFailoverResult<Self> {
        let config = SequencerFailoverConfig::default();
        let mut primary = SequencerLeader::new(
            "devnet-sequencer-primary",
            SequencerLeaderRole::Primary,
            50_000,
            5_000,
            0,
        )?;
        primary.status = SequencerLeaderStatus::Active;
        primary.record_heartbeat(24, &json!({ "block": 24, "private_queue": "healthy" }))?;
        let mut hot = SequencerLeader::new(
            "devnet-sequencer-hot-standby",
            SequencerLeaderRole::HotStandby,
            40_000,
            4_500,
            0,
        )?;
        hot.status = SequencerLeaderStatus::Standby;
        hot.record_heartbeat(32, &json!({ "block": 32, "ready": true }))?;
        let mut emergency = SequencerLeader::new(
            "devnet-sequencer-emergency",
            SequencerLeaderRole::Emergency,
            35_000,
            4_000,
            0,
        )?;
        emergency.status = SequencerLeaderStatus::EmergencyOnly;
        emergency.record_heartbeat(32, &json!({ "block": 32, "emergency_ready": true }))?;
        let forced_keeper = SequencerLeader::new(
            "devnet-forced-inclusion-keeper",
            SequencerLeaderRole::ForcedInclusionKeeper,
            20_000,
            2_500,
            0,
        )?;
        let low_fee_sponsor = SequencerLeader::new(
            "devnet-low-fee-sponsor",
            SequencerLeaderRole::LowFeeSponsor,
            25_000,
            2_700,
            0,
        )?;

        let committee_members = vec![
            EmergencyCommitteeMember::new("devnet-emergency-alice", 3_000, 0)?,
            EmergencyCommitteeMember::new("devnet-emergency-bob", 2_750, 0)?,
            EmergencyCommitteeMember::new("devnet-emergency-carol", 2_500, 0)?,
            EmergencyCommitteeMember::new("devnet-emergency-dave", 2_000, 0)?,
            EmergencyCommitteeMember::new("devnet-emergency-erin", 1_500, 0)?,
        ];

        let mut state = Self::new(
            config,
            SEQUENCER_FAILOVER_DEVNET_OPERATOR_LABEL,
            vec![primary, hot, emergency, forced_keeper, low_fee_sponsor],
            committee_members,
        )?;
        state.set_height(32)?;

        let private_low_fee = LowFeeLaneGuarantee::new(
            "devnet-private-low-fee",
            FailoverLaneKind::LowFee,
            "wxmr-devnet",
            state.config.low_fee_cap_units,
            state.config.low_fee_min_share_bps,
            800_000,
            24,
            96,
        )?;
        let bridge_low_fee = LowFeeLaneGuarantee::new(
            "devnet-bridge-low-fee",
            FailoverLaneKind::MoneroBridge,
            "wxmr-devnet",
            state.config.low_fee_cap_units,
            1_500,
            500_000,
            24,
            96,
        )?;
        let private_low_fee_id = state.register_low_fee_guarantee(private_low_fee)?;
        let bridge_low_fee_id = state.register_low_fee_guarantee(bridge_low_fee)?;

        let leader_ids = state.leaders.keys().cloned().collect::<Vec<_>>();
        let backup_leaders = leader_ids
            .iter()
            .filter(|leader_id| *leader_id != &state.current_leader_id)
            .cloned()
            .collect::<Vec<_>>();
        let epoch = SequencerFailoverEpoch::new(
            state.epoch,
            16,
            48,
            state.current_leader_id.clone(),
            backup_leaders,
            &state.emergency_committee_members,
            42,
            state.low_fee_lane_root(),
            state.private_queue_root(),
        )?;
        let epoch_id = state.register_epoch(epoch)?;

        let trigger = FailoverTrigger::new(
            FailoverTriggerKind::PrivateQueueWithheld,
            state.current_leader_id.clone(),
            "devnet-watchtower-a",
            32,
            28,
            state.epoch,
            &json!({
                "missing_heartbeats": 4,
                "sealed_private_queue_root": "devnet-private-root-28",
                "latest_seen_private_queue_root": "devnet-private-root-24",
                "watchtower": "devnet-watchtower-a",
            }),
            &json!({
                "pending_private_items": 4,
                "forced_inclusion_due": 1,
                "low_fee_due": 2,
            }),
            state.private_queue_root(),
            state.forced_inclusion_root(),
            state.low_fee_lane_root(),
            32 + state.config.max_evidence_age_blocks,
        )?;
        let trigger_id = state.record_trigger(trigger)?;

        let to_leader_id = state
            .leaders
            .values()
            .find(|leader| leader.role == SequencerLeaderRole::HotStandby)
            .map(|leader| leader.leader_id.clone())
            .ok_or_else(|| "devnet hot standby leader missing".to_string())?;
        let committee = state
            .emergency_committee_members
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for member in committee.iter() {
            let approval = EmergencyCommitteeApproval::new(
                EmergencyApprovalKind::HandoffApproved,
                member,
                trigger_id.clone(),
                None,
                to_leader_id.clone(),
                state.height,
                state.height + state.config.handoff_timeout_blocks + 8,
                &json!({
                    "reason": "primary withheld private queue roots",
                    "target": to_leader_id,
                    "preserve_low_fee": true,
                    "preserve_forced_inclusion_cursor": true,
                }),
            )?;
            state.record_emergency_approval(approval)?;
        }

        let trigger = state
            .triggers
            .get(&trigger_id)
            .cloned()
            .ok_or_else(|| "devnet trigger missing".to_string())?;
        let epoch = state
            .epochs
            .get(&epoch_id)
            .cloned()
            .ok_or_else(|| "devnet epoch missing".to_string())?;
        let approvals = state
            .emergency_approvals
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let total_power = state.total_emergency_voting_power_at(state.height);
        let before_root = state.state_root();
        let private_after_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-DEVNET-PRIVATE-AFTER",
            &json!({ "draining": true, "target_leader_id": to_leader_id }),
        );
        let forced_after_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-DEVNET-FORCED-AFTER",
            &json!({ "cursor": 43, "continued": true }),
        );
        let low_fee_after_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-DEVNET-LOW-FEE-AFTER",
            &json!({ "guarantees": [private_low_fee_id, bridge_low_fee_id] }),
        );
        let after_root = sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-DEVNET-AFTER",
            &json!({
                "target_leader_id": to_leader_id,
                "private_after_root": private_after_root,
                "forced_after_root": forced_after_root,
                "low_fee_after_root": low_fee_after_root,
            }),
        );
        let certificate = LeaderHandoffCertificate::new(
            &trigger,
            &epoch,
            &approvals,
            total_power,
            to_leader_id.clone(),
            before_root,
            after_root,
            private_after_root.clone(),
            43,
            forced_after_root.clone(),
            low_fee_after_root.clone(),
            state.height,
            state.height + 1,
            state.height + state.config.handoff_timeout_blocks + 8,
            state.config.emergency_quorum_bps,
        )?;
        let certificate_id = state.record_handoff_certificate(certificate)?;
        state.activate_handoff(&certificate_id)?;

        let certificate = state
            .handoff_certificates
            .get(&certificate_id)
            .cloned()
            .ok_or_else(|| "devnet certificate missing".to_string())?;
        let recovery_window = RecoveryWindow::new(
            &certificate,
            &state.config,
            &state.emergency_committee_members,
            state.private_queue_root(),
            sequencer_failover_string_root(
                "SEQUENCER-FAILOVER-DEVNET-PRECONFIRMATIONS",
                "carry-all-valid-preconfirmations",
            ),
        )?;
        let recovery_window_id = state.record_recovery_window(recovery_window)?;

        let drain_items = vec![
            EncryptedQueueDrainItem::new(
                "devnet-private-low-fee",
                FailoverLaneKind::LowFee,
                "devnet-envelope-low-fee-001",
                0,
                &json!({ "ciphertext": "redacted-low-fee-001", "view_tag": "7f" }),
                sequencer_failover_string_root("SEQUENCER-FAILOVER-DEVNET-FEE", "fee-001"),
                27,
                34,
                None,
                Some(private_low_fee_id.clone()),
                &json!({ "wallet": "alice", "privacy": "view-tag-only" }),
            )?,
            EncryptedQueueDrainItem::new(
                "devnet-bridge-low-fee",
                FailoverLaneKind::MoneroBridge,
                "devnet-envelope-bridge-001",
                1,
                &json!({ "ciphertext": "redacted-bridge-001", "monero_hint": "anchor-42" }),
                sequencer_failover_string_root("SEQUENCER-FAILOVER-DEVNET-FEE", "fee-002"),
                28,
                35,
                Some("devnet-forced-ticket-bridge-001".to_string()),
                Some(bridge_low_fee_id.clone()),
                &json!({ "wallet": "bob", "forced_inclusion": true }),
            )?,
            EncryptedQueueDrainItem::new(
                "devnet-private-defi",
                FailoverLaneKind::PrivateDefi,
                "devnet-envelope-private-defi-001",
                2,
                &json!({ "ciphertext": "redacted-defi-001", "pool": "private-amm" }),
                sequencer_failover_string_root("SEQUENCER-FAILOVER-DEVNET-FEE", "fee-003"),
                29,
                36,
                None,
                None,
                &json!({ "defi": "swap", "privacy": "decoy-batch" }),
            )?,
            EncryptedQueueDrainItem::new(
                "devnet-forced-inclusion",
                FailoverLaneKind::ForcedInclusion,
                "devnet-envelope-forced-001",
                3,
                &json!({ "ciphertext": "redacted-forced-001", "escape": true }),
                sequencer_failover_string_root("SEQUENCER-FAILOVER-DEVNET-FEE", "fee-004"),
                30,
                37,
                Some("devnet-forced-ticket-escape-001".to_string()),
                None,
                &json!({ "escape": "private-exit", "watchtower": "a" }),
            )?,
        ];
        for item in drain_items {
            state.record_encrypted_queue_drain_item(item)?;
        }

        let recovery_window = state
            .recovery_windows
            .get(&recovery_window_id)
            .cloned()
            .ok_or_else(|| "devnet recovery window missing".to_string())?;
        let items = state
            .encrypted_queue_drain_items
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let manifest = EncryptedQueueDrainManifest::new(
            &recovery_window,
            trigger.subject_leader_id.clone(),
            to_leader_id.clone(),
            epoch_id.clone(),
            0,
            &items,
            trigger.private_queue_root.clone(),
            private_after_root,
            forced_after_root,
            low_fee_after_root,
            8_704,
        )?;
        let manifest_id = state.record_encrypted_queue_drain_manifest(manifest)?;

        let manifest = state
            .encrypted_queue_drain_manifests
            .get(&manifest_id)
            .cloned()
            .ok_or_else(|| "devnet drain manifest missing".to_string())?;
        let receipt_items = state
            .encrypted_queue_drain_items
            .values()
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        for (index, item) in receipt_items.iter().enumerate() {
            let receipt = PrivateMempoolContinuityReceipt::new(
                ContinuityReceiptKind::Included,
                &manifest,
                item,
                state.height + 2 + index as u64,
                &json!({
                    "block": state.height + 2 + index as u64,
                    "emergency_leader_id": to_leader_id,
                }),
                &json!({
                    "manifest_id": manifest.manifest_id,
                    "item_id": item.item_id,
                    "queue_position": item.queue_position,
                }),
                &json!({
                    "payload": "redacted",
                    "delayed_disclosure_height": state.height + 720,
                }),
                Some(format!("devnet-preconfirmation-{index}")),
            )?;
            state.record_continuity_receipt(receipt)?;
        }

        let omitted_ticket_ids = vec!["devnet-forced-ticket-escape-001".to_string()];
        let mut evidence = SlashableSequencerEvidence::new(
            SlashableEvidenceKind::Censorship,
            trigger.subject_leader_id.clone(),
            "devnet-watchtower-a",
            Some(trigger_id.clone()),
            Some("devnet-envelope-forced-001".to_string()),
            state.height + 3,
            28,
            state.height + state.config.max_evidence_age_blocks,
            &json!({
                "reason": "forced inclusion item omitted while low-fee lane also starved",
                "manifest_id": manifest_id,
            }),
            &json!({
                "omitted_items": ["devnet-envelope-forced-001"],
                "private_queue_root": trigger.private_queue_root,
            }),
            &omitted_ticket_ids,
            &json!({
                "low_fee_min_share_bps": state.config.low_fee_min_share_bps,
                "observed_share_bps": 0,
            }),
            &json!({ "expected": "include_or_escalate_forced_ticket" }),
            &json!({ "observed": "withheld" }),
            &state.config,
        )?;
        evidence.mark_accepted();
        state.record_slashable_evidence(evidence)?;

        let snapshot = state.public_record_without_state_root();
        state.publish_public_record(
            "devnet-sequencer-failover",
            "devnet-failover-snapshot",
            "state_snapshot",
            &snapshot,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> SequencerFailoverResult<String> {
        self.height = height;
        self.epoch = epoch_for_height(height, self.config.epoch_length_blocks);
        for leader in self.leaders.values_mut() {
            if leader.status == SequencerLeaderStatus::Active
                && height
                    > leader
                        .last_heartbeat_height
                        .saturating_add(self.config.heartbeat_grace_blocks)
            {
                leader.mark_missing();
            }
        }
        for trigger in self.triggers.values_mut() {
            if trigger.status == SEQUENCER_FAILOVER_STATUS_ACTIVE
                && height > trigger.expires_at_height
            {
                trigger.status = SEQUENCER_FAILOVER_STATUS_EXPIRED.to_string();
            }
        }
        for approval in self.emergency_approvals.values_mut() {
            if approval.status == EmergencyApprovalStatus::Accepted
                && height > approval.expires_at_height
            {
                approval.status = EmergencyApprovalStatus::Expired;
            }
        }
        for window in self.recovery_windows.values_mut() {
            if window.status.is_open() && height > window.end_height {
                window.status = RecoveryWindowStatus::Expired;
            } else if window.status == RecoveryWindowStatus::Open
                && height <= window.private_draining_until_height
            {
                window.status = RecoveryWindowStatus::Draining;
            }
        }
        for guarantee in self.low_fee_guarantees.values_mut() {
            if guarantee.status.can_reserve() && height > guarantee.expires_at_height {
                guarantee.status = LowFeeGuaranteeStatus::Expired;
            }
        }
        for item in self.encrypted_queue_drain_items.values_mut() {
            if item.status.is_pending_like() && height > item.target_inclusion_height {
                if item.forced_inclusion_ticket_id.is_some() {
                    item.status = DrainStatus::ForcedInclusionEscalated;
                } else {
                    item.status = DrainStatus::Deferred;
                }
            }
        }
        for evidence in self.slashable_evidence.values_mut() {
            if matches!(
                evidence.status,
                EvidenceStatus::Observed | EvidenceStatus::Challenged
            ) && height > evidence.deadline_height
            {
                evidence.status = EvidenceStatus::Expired;
            }
        }
        Ok(self.state_root())
    }

    pub fn register_leader(&mut self, leader: SequencerLeader) -> SequencerFailoverResult<String> {
        leader.validate()?;
        let leader_id = leader.leader_id.clone();
        if self.leaders.insert(leader_id.clone(), leader).is_some() {
            return Err("sequencer failover leader already exists".to_string());
        }
        Ok(leader_id)
    }

    pub fn register_epoch(
        &mut self,
        epoch: SequencerFailoverEpoch,
    ) -> SequencerFailoverResult<String> {
        epoch.validate()?;
        if !self.leaders.contains_key(&epoch.primary_leader_id) {
            return Err("failover epoch references unknown primary leader".to_string());
        }
        for backup in &epoch.backup_leader_ids {
            if !self.leaders.contains_key(backup) {
                return Err("failover epoch references unknown backup leader".to_string());
            }
        }
        let epoch_id = epoch.epoch_id.clone();
        self.epochs.insert(epoch_id.clone(), epoch);
        Ok(epoch_id)
    }

    pub fn record_trigger(&mut self, trigger: FailoverTrigger) -> SequencerFailoverResult<String> {
        trigger.validate()?;
        if !self.leaders.contains_key(&trigger.subject_leader_id) {
            return Err("failover trigger references unknown leader".to_string());
        }
        let trigger_id = trigger.trigger_id.clone();
        self.triggers.insert(trigger_id.clone(), trigger);
        Ok(trigger_id)
    }

    pub fn record_emergency_approval(
        &mut self,
        approval: EmergencyCommitteeApproval,
    ) -> SequencerFailoverResult<String> {
        approval.validate()?;
        if !self
            .emergency_committee_members
            .contains_key(&approval.committee_member_id)
        {
            return Err("emergency approval references unknown committee member".to_string());
        }
        if !self.triggers.contains_key(&approval.trigger_id) {
            return Err("emergency approval references unknown trigger".to_string());
        }
        if !self.leaders.contains_key(&approval.approved_leader_id) {
            return Err("emergency approval references unknown target leader".to_string());
        }
        let approval_id = approval.approval_id.clone();
        self.emergency_approvals
            .insert(approval_id.clone(), approval);
        Ok(approval_id)
    }

    pub fn record_handoff_certificate(
        &mut self,
        certificate: LeaderHandoffCertificate,
    ) -> SequencerFailoverResult<String> {
        certificate.validate()?;
        if !self.triggers.contains_key(&certificate.trigger_id) {
            return Err("handoff certificate references unknown trigger".to_string());
        }
        if !self.epochs.contains_key(&certificate.epoch_id) {
            return Err("handoff certificate references unknown epoch".to_string());
        }
        if !self.leaders.contains_key(&certificate.from_leader_id)
            || !self.leaders.contains_key(&certificate.to_leader_id)
        {
            return Err("handoff certificate references unknown leader".to_string());
        }
        let certificate_id = certificate.certificate_id.clone();
        self.handoff_certificates
            .insert(certificate_id.clone(), certificate);
        self.last_handoff_certificate_id = Some(certificate_id.clone());
        Ok(certificate_id)
    }

    pub fn activate_handoff(&mut self, certificate_id: &str) -> SequencerFailoverResult<String> {
        let certificate = self
            .handoff_certificates
            .get(certificate_id)
            .cloned()
            .ok_or_else(|| "handoff certificate not found".to_string())?;
        if !certificate.quorum_reached {
            return Err("handoff certificate has not reached quorum".to_string());
        }
        if self.height > certificate.expires_at_height {
            return Err("handoff certificate expired".to_string());
        }
        for leader in self.leaders.values_mut() {
            if leader.leader_id == certificate.from_leader_id {
                leader.status = SequencerLeaderStatus::HandingOff;
            } else if leader.leader_id == certificate.to_leader_id {
                leader.mark_primary();
            } else if leader.status == SequencerLeaderStatus::Active {
                leader.mark_standby();
            }
        }
        self.current_leader_id = certificate.to_leader_id.clone();
        self.forced_inclusion_cursor = certificate.forced_inclusion_cursor_after;
        self.emergency_mode = true;
        self.status = SEQUENCER_FAILOVER_STATUS_EMERGENCY.to_string();
        Ok(self.state_root())
    }

    pub fn record_recovery_window(
        &mut self,
        window: RecoveryWindow,
    ) -> SequencerFailoverResult<String> {
        window.validate()?;
        if !self
            .handoff_certificates
            .contains_key(&window.certificate_id)
        {
            return Err("recovery window references unknown handoff certificate".to_string());
        }
        let window_id = window.window_id.clone();
        self.recovery_windows.insert(window_id.clone(), window);
        self.status = SEQUENCER_FAILOVER_STATUS_RECOVERING.to_string();
        Ok(window_id)
    }

    pub fn register_low_fee_guarantee(
        &mut self,
        guarantee: LowFeeLaneGuarantee,
    ) -> SequencerFailoverResult<String> {
        guarantee.validate()?;
        let guarantee_id = guarantee.guarantee_id.clone();
        self.low_fee_guarantees
            .insert(guarantee_id.clone(), guarantee);
        Ok(guarantee_id)
    }

    pub fn record_encrypted_queue_drain_item(
        &mut self,
        item: EncryptedQueueDrainItem,
    ) -> SequencerFailoverResult<String> {
        item.validate()?;
        if let Some(guarantee_id) = &item.low_fee_guarantee_id {
            if !self.low_fee_guarantees.contains_key(guarantee_id) {
                return Err("drain item references unknown low fee guarantee".to_string());
            }
        }
        let item_id = item.item_id.clone();
        self.encrypted_queue_drain_items
            .insert(item_id.clone(), item);
        Ok(item_id)
    }

    pub fn record_encrypted_queue_drain_manifest(
        &mut self,
        manifest: EncryptedQueueDrainManifest,
    ) -> SequencerFailoverResult<String> {
        manifest.validate()?;
        if !self
            .recovery_windows
            .contains_key(&manifest.recovery_window_id)
        {
            return Err("drain manifest references unknown recovery window".to_string());
        }
        for item_id in &manifest.item_ids {
            if !self.encrypted_queue_drain_items.contains_key(item_id) {
                return Err("drain manifest references unknown drain item".to_string());
            }
        }
        let manifest_id = manifest.manifest_id.clone();
        for item_id in &manifest.item_ids {
            if let Some(item) = self.encrypted_queue_drain_items.get_mut(item_id) {
                item.status = DrainStatus::Draining;
            }
        }
        self.encrypted_queue_drain_manifests
            .insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn record_continuity_receipt(
        &mut self,
        receipt: PrivateMempoolContinuityReceipt,
    ) -> SequencerFailoverResult<String> {
        receipt.validate()?;
        if !self
            .encrypted_queue_drain_manifests
            .contains_key(&receipt.manifest_id)
        {
            return Err("continuity receipt references unknown drain manifest".to_string());
        }
        if !self
            .encrypted_queue_drain_items
            .contains_key(&receipt.item_id)
        {
            return Err("continuity receipt references unknown drain item".to_string());
        }
        if let Some(item) = self.encrypted_queue_drain_items.get_mut(&receipt.item_id) {
            item.status = DrainStatus::Included;
        }
        if let Some(guarantee_id) = &receipt.low_fee_guarantee_id {
            if let Some(guarantee) = self.low_fee_guarantees.get_mut(guarantee_id) {
                guarantee.consume_capacity(1, receipt.included_height)?;
            }
        }
        let receipt_id = receipt.receipt_id.clone();
        self.continuity_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn record_slashable_evidence(
        &mut self,
        evidence: SlashableSequencerEvidence,
    ) -> SequencerFailoverResult<String> {
        evidence.validate()?;
        if !self.leaders.contains_key(&evidence.offender_leader_id) {
            return Err("slashable evidence references unknown offender".to_string());
        }
        if let Some(trigger_id) = &evidence.trigger_id {
            if !self.triggers.contains_key(trigger_id) {
                return Err("slashable evidence references unknown trigger".to_string());
            }
        }
        let evidence_id = evidence.evidence_id.clone();
        self.slashable_evidence
            .insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn publish_public_record(
        &mut self,
        source_id: impl Into<String>,
        label: impl Into<String>,
        payload_kind: impl Into<String>,
        payload: &Value,
    ) -> SequencerFailoverResult<String> {
        let record = SequencerFailoverPublicRecord::new(
            source_id,
            label,
            payload_kind,
            payload,
            self.height,
        )?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn total_emergency_voting_power_at(&self, height: u64) -> u64 {
        self.emergency_committee_members
            .values()
            .filter(|member| member.active_at(height))
            .map(|member| member.voting_power)
            .sum::<u64>()
    }

    pub fn active_epoch(&self) -> Option<&SequencerFailoverEpoch> {
        self.epochs
            .values()
            .filter(|epoch| epoch.contains_height(self.height))
            .max_by_key(|epoch| epoch.epoch)
    }

    pub fn active_leader(&self) -> Option<&SequencerLeader> {
        self.leaders.get(&self.current_leader_id)
    }

    pub fn forced_inclusion_root(&self) -> String {
        sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-FORCED-INCLUSION-ROOT",
            &json!({
                "cursor": self.forced_inclusion_cursor,
                "policy": SEQUENCER_FAILOVER_FORCED_INCLUSION_POLICY,
                "open_trigger_count": self
                    .triggers
                    .values()
                    .filter(|trigger| trigger.trigger_kind == FailoverTriggerKind::ForcedInclusionDeadline)
                    .count() as u64,
            }),
        )
    }

    pub fn private_queue_root(&self) -> String {
        let item_root = encrypted_queue_drain_item_root_from_map(&self.encrypted_queue_drain_items);
        let manifest_root =
            encrypted_queue_drain_manifest_root_from_map(&self.encrypted_queue_drain_manifests);
        sequencer_failover_payload_root(
            "SEQUENCER-FAILOVER-PRIVATE-QUEUE-ROOT",
            &json!({
                "item_root": item_root,
                "manifest_root": manifest_root,
                "policy": SEQUENCER_FAILOVER_PRIVACY_POLICY,
            }),
        )
    }

    pub fn low_fee_lane_root(&self) -> String {
        low_fee_lane_guarantee_root_from_map(&self.low_fee_guarantees)
    }

    pub fn counters(&self) -> SequencerFailoverCounters {
        let active_leader_count = self
            .leaders
            .values()
            .filter(|leader| leader.active_at(self.height))
            .count() as u64;
        let open_trigger_count = self
            .triggers
            .values()
            .filter(|trigger| trigger.is_open_at(self.height))
            .count() as u64;
        let active_recovery_window_count = self
            .recovery_windows
            .values()
            .filter(|window| window.active_at(self.height))
            .count() as u64;
        let pending_private_queue_items = self
            .encrypted_queue_drain_items
            .values()
            .filter(|item| item.status.is_pending_like())
            .count() as u64;
        let drained_private_queue_items = self
            .encrypted_queue_drain_items
            .values()
            .filter(|item| item.status == DrainStatus::Included)
            .count() as u64;
        let accepted_slashable_evidence_count = self
            .slashable_evidence
            .values()
            .filter(|evidence| evidence.status.slashable())
            .count() as u64;
        let low_fee_reserved_capacity_units = self
            .low_fee_guarantees
            .values()
            .map(|guarantee| guarantee.reserved_capacity_units)
            .sum::<u64>();
        let low_fee_consumed_capacity_units = self
            .low_fee_guarantees
            .values()
            .map(|guarantee| guarantee.consumed_capacity_units)
            .sum::<u64>();
        SequencerFailoverCounters {
            leader_count: self.leaders.len() as u64,
            active_leader_count,
            emergency_committee_member_count: self.emergency_committee_members.len() as u64,
            epoch_count: self.epochs.len() as u64,
            trigger_count: self.triggers.len() as u64,
            open_trigger_count,
            emergency_approval_count: self.emergency_approvals.len() as u64,
            handoff_certificate_count: self.handoff_certificates.len() as u64,
            recovery_window_count: self.recovery_windows.len() as u64,
            active_recovery_window_count,
            low_fee_guarantee_count: self.low_fee_guarantees.len() as u64,
            encrypted_queue_drain_item_count: self.encrypted_queue_drain_items.len() as u64,
            pending_private_queue_items,
            drained_private_queue_items,
            encrypted_queue_drain_manifest_count: self.encrypted_queue_drain_manifests.len() as u64,
            continuity_receipt_count: self.continuity_receipts.len() as u64,
            slashable_evidence_count: self.slashable_evidence.len() as u64,
            accepted_slashable_evidence_count,
            public_record_count: self.public_records.len() as u64,
            forced_inclusion_cursor: self.forced_inclusion_cursor,
            low_fee_reserved_capacity_units,
            low_fee_consumed_capacity_units,
            private_queue_pressure_bps: ratio_bps(
                pending_private_queue_items,
                self.config.max_private_queue_depth.max(1),
            )
            .min(SEQUENCER_FAILOVER_MAX_BPS),
        }
    }

    pub fn roots(&self) -> SequencerFailoverRoots {
        SequencerFailoverRoots {
            config_root: self.config.config_root(),
            leader_root: sequencer_leader_root_from_map(&self.leaders),
            emergency_committee_root: emergency_committee_member_root_from_map(
                &self.emergency_committee_members,
            ),
            epoch_root: sequencer_failover_epoch_root_from_map(&self.epochs),
            trigger_root: failover_trigger_root_from_map(&self.triggers),
            emergency_approval_root: emergency_approval_root_from_map(&self.emergency_approvals),
            handoff_certificate_root: leader_handoff_certificate_root_from_map(
                &self.handoff_certificates,
            ),
            recovery_window_root: recovery_window_root_from_map(&self.recovery_windows),
            low_fee_guarantee_root: low_fee_lane_guarantee_root_from_map(&self.low_fee_guarantees),
            encrypted_queue_drain_item_root: encrypted_queue_drain_item_root_from_map(
                &self.encrypted_queue_drain_items,
            ),
            encrypted_queue_drain_manifest_root: encrypted_queue_drain_manifest_root_from_map(
                &self.encrypted_queue_drain_manifests,
            ),
            private_mempool_continuity_receipt_root:
                private_mempool_continuity_receipt_root_from_map(&self.continuity_receipts),
            slashable_evidence_root: slashable_sequencer_evidence_root_from_map(
                &self.slashable_evidence,
            ),
            public_record_root: sequencer_failover_public_record_root_from_map(
                &self.public_records,
            ),
            forced_inclusion_root: self.forced_inclusion_root(),
            private_queue_root: self.private_queue_root(),
            low_fee_lane_root: self.low_fee_lane_root(),
            state_root: self.state_root(),
        }
    }

    pub fn state_root(&self) -> String {
        sequencer_failover_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("sequencer failover state record is object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots_without_state_root();
        json!({
            "kind": "sequencer_failover_state",
            "chain_id": CHAIN_ID,
            "protocol_version": SEQUENCER_FAILOVER_PROTOCOL_VERSION,
            "schema_version": SEQUENCER_FAILOVER_SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "status": self.status,
            "current_leader_id": self.current_leader_id,
            "emergency_mode": self.emergency_mode,
            "forced_inclusion_cursor": self.forced_inclusion_cursor,
            "last_handoff_certificate_id": self.last_handoff_certificate_id,
            "parent_state_root": self.parent_state_root,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "leaders": self.leaders.values().map(SequencerLeader::public_record).collect::<Vec<_>>(),
            "emergency_committee_members": self
                .emergency_committee_members
                .values()
                .map(EmergencyCommitteeMember::public_record)
                .collect::<Vec<_>>(),
            "epochs": self.epochs.values().map(SequencerFailoverEpoch::public_record).collect::<Vec<_>>(),
            "triggers": self.triggers.values().map(FailoverTrigger::public_record).collect::<Vec<_>>(),
            "emergency_approvals": self
                .emergency_approvals
                .values()
                .map(EmergencyCommitteeApproval::public_record)
                .collect::<Vec<_>>(),
            "handoff_certificates": self
                .handoff_certificates
                .values()
                .map(LeaderHandoffCertificate::public_record)
                .collect::<Vec<_>>(),
            "recovery_windows": self.recovery_windows.values().map(RecoveryWindow::public_record).collect::<Vec<_>>(),
            "low_fee_guarantees": self
                .low_fee_guarantees
                .values()
                .map(LowFeeLaneGuarantee::public_record)
                .collect::<Vec<_>>(),
            "encrypted_queue_drain_items": self
                .encrypted_queue_drain_items
                .values()
                .map(EncryptedQueueDrainItem::public_record)
                .collect::<Vec<_>>(),
            "encrypted_queue_drain_manifests": self
                .encrypted_queue_drain_manifests
                .values()
                .map(EncryptedQueueDrainManifest::public_record)
                .collect::<Vec<_>>(),
            "continuity_receipts": self
                .continuity_receipts
                .values()
                .map(PrivateMempoolContinuityReceipt::public_record)
                .collect::<Vec<_>>(),
            "slashable_evidence": self
                .slashable_evidence
                .values()
                .map(SlashableSequencerEvidence::public_record)
                .collect::<Vec<_>>(),
            "public_records": self
                .public_records
                .values()
                .map(SequencerFailoverPublicRecord::public_record)
                .collect::<Vec<_>>(),
        })
    }

    fn roots_without_state_root(&self) -> SequencerFailoverRoots {
        SequencerFailoverRoots {
            config_root: self.config.config_root(),
            leader_root: sequencer_leader_root_from_map(&self.leaders),
            emergency_committee_root: emergency_committee_member_root_from_map(
                &self.emergency_committee_members,
            ),
            epoch_root: sequencer_failover_epoch_root_from_map(&self.epochs),
            trigger_root: failover_trigger_root_from_map(&self.triggers),
            emergency_approval_root: emergency_approval_root_from_map(&self.emergency_approvals),
            handoff_certificate_root: leader_handoff_certificate_root_from_map(
                &self.handoff_certificates,
            ),
            recovery_window_root: recovery_window_root_from_map(&self.recovery_windows),
            low_fee_guarantee_root: low_fee_lane_guarantee_root_from_map(&self.low_fee_guarantees),
            encrypted_queue_drain_item_root: encrypted_queue_drain_item_root_from_map(
                &self.encrypted_queue_drain_items,
            ),
            encrypted_queue_drain_manifest_root: encrypted_queue_drain_manifest_root_from_map(
                &self.encrypted_queue_drain_manifests,
            ),
            private_mempool_continuity_receipt_root:
                private_mempool_continuity_receipt_root_from_map(&self.continuity_receipts),
            slashable_evidence_root: slashable_sequencer_evidence_root_from_map(
                &self.slashable_evidence,
            ),
            public_record_root: sequencer_failover_public_record_root_from_map(
                &self.public_records,
            ),
            forced_inclusion_root: self.forced_inclusion_root(),
            private_queue_root: self.private_queue_root(),
            low_fee_lane_root: self.low_fee_lane_root(),
            state_root: String::new(),
        }
    }

    pub fn validate(&self) -> SequencerFailoverResult<String> {
        self.config.validate()?;
        ensure_status(&self.status, VALID_STATE_STATUSES)?;
        ensure_non_empty(&self.current_leader_id, "failover current leader")?;
        ensure_non_empty(&self.parent_state_root, "failover parent state root")?;
        if !self.leaders.is_empty() && !self.leaders.contains_key(&self.current_leader_id) {
            return Err("failover current leader is unknown".to_string());
        }
        for leader in self.leaders.values() {
            leader.validate()?;
        }
        for member in self.emergency_committee_members.values() {
            member.validate()?;
        }
        for epoch in self.epochs.values() {
            epoch.validate()?;
            if !self.leaders.contains_key(&epoch.primary_leader_id) {
                return Err("failover epoch primary is unknown".to_string());
            }
            for backup in &epoch.backup_leader_ids {
                if !self.leaders.contains_key(backup) {
                    return Err("failover epoch backup is unknown".to_string());
                }
            }
        }
        for trigger in self.triggers.values() {
            trigger.validate()?;
            if !self.leaders.contains_key(&trigger.subject_leader_id) {
                return Err("failover trigger subject leader is unknown".to_string());
            }
        }
        for approval in self.emergency_approvals.values() {
            approval.validate()?;
            if !self
                .emergency_committee_members
                .contains_key(&approval.committee_member_id)
            {
                return Err("failover approval committee member is unknown".to_string());
            }
            if !self.triggers.contains_key(&approval.trigger_id) {
                return Err("failover approval trigger is unknown".to_string());
            }
            if !self.leaders.contains_key(&approval.approved_leader_id) {
                return Err("failover approval leader is unknown".to_string());
            }
        }
        for certificate in self.handoff_certificates.values() {
            certificate.validate()?;
            if !self.triggers.contains_key(&certificate.trigger_id) {
                return Err("handoff certificate trigger is unknown".to_string());
            }
            if !self.epochs.contains_key(&certificate.epoch_id) {
                return Err("handoff certificate epoch is unknown".to_string());
            }
        }
        for window in self.recovery_windows.values() {
            window.validate()?;
            if !self
                .handoff_certificates
                .contains_key(&window.certificate_id)
            {
                return Err("recovery window certificate is unknown".to_string());
            }
        }
        for guarantee in self.low_fee_guarantees.values() {
            guarantee.validate()?;
        }
        for item in self.encrypted_queue_drain_items.values() {
            item.validate()?;
            if let Some(guarantee_id) = &item.low_fee_guarantee_id {
                if !self.low_fee_guarantees.contains_key(guarantee_id) {
                    return Err("drain item low fee guarantee is unknown".to_string());
                }
            }
        }
        for manifest in self.encrypted_queue_drain_manifests.values() {
            manifest.validate()?;
            if !self
                .recovery_windows
                .contains_key(&manifest.recovery_window_id)
            {
                return Err("drain manifest recovery window is unknown".to_string());
            }
            for item_id in &manifest.item_ids {
                if !self.encrypted_queue_drain_items.contains_key(item_id) {
                    return Err("drain manifest item is unknown".to_string());
                }
            }
        }
        for receipt in self.continuity_receipts.values() {
            receipt.validate()?;
            if !self
                .encrypted_queue_drain_manifests
                .contains_key(&receipt.manifest_id)
            {
                return Err("continuity receipt manifest is unknown".to_string());
            }
            if !self
                .encrypted_queue_drain_items
                .contains_key(&receipt.item_id)
            {
                return Err("continuity receipt item is unknown".to_string());
            }
        }
        for evidence in self.slashable_evidence.values() {
            evidence.validate()?;
            if !self.leaders.contains_key(&evidence.offender_leader_id) {
                return Err("slashable evidence offender is unknown".to_string());
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn sequencer_failover_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn sequencer_failover_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn sequencer_failover_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn sequencer_failover_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn sequencer_failover_string_set_root(domain: &str, values: &[String]) -> String {
    let mut unique = BTreeMap::new();
    for value in values {
        unique.insert(value.clone(), ());
    }
    let leaves = unique
        .into_keys()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_records_by_id(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn role_weight_bonus(stake_units: u64) -> u64 {
    stake_units.saturating_div(100).max(1)
}

pub fn epoch_for_height(height: u64, epoch_length_blocks: u64) -> u64 {
    height / epoch_length_blocks.max(1)
}

pub fn reaches_quorum(signed_voting_power: u64, total_voting_power: u64, quorum_bps: u64) -> bool {
    if total_voting_power == 0 {
        return false;
    }
    signed_voting_power.saturating_mul(SEQUENCER_FAILOVER_MAX_BPS)
        >= total_voting_power.saturating_mul(quorum_bps)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(SEQUENCER_FAILOVER_MAX_BPS) / denominator
}

pub fn sequencer_leader_id(
    operator_label: &str,
    _role: &SequencerLeaderRole,
    endpoint_commitment: &str,
    pq_signing_key_root: &str,
    pq_recovery_key_root: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-LEADER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(endpoint_commitment),
            HashPart::Str(pq_signing_key_root),
            HashPart::Str(pq_recovery_key_root),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

pub fn sequencer_leader_root(values: &[SequencerLeader]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-LEADER-ROOT",
        values
            .iter()
            .map(|value| (value.leader_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn sequencer_leader_root_from_map(values: &BTreeMap<String, SequencerLeader>) -> String {
    sequencer_leader_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn emergency_committee_member_id(
    label: &str,
    voting_power: u64,
    pq_public_key_root: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-EMERGENCY-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(voting_power as i128),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn emergency_committee_member_root(values: &[EmergencyCommitteeMember]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-EMERGENCY-COMMITTEE-MEMBER-ROOT",
        values
            .iter()
            .map(|value| (value.member_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn emergency_committee_member_root_from_map(
    values: &BTreeMap<String, EmergencyCommitteeMember>,
) -> String {
    emergency_committee_member_root(&values.values().cloned().collect::<Vec<_>>())
}

fn epoch_leader_ids(primary_leader_id: &str, backup_leader_ids: &[String]) -> Vec<String> {
    let mut leader_ids = vec![primary_leader_id.to_string()];
    leader_ids.extend(backup_leader_ids.iter().cloned());
    leader_ids
}

pub fn sequencer_failover_epoch_id(
    epoch: u64,
    start_height: u64,
    end_height: u64,
    primary_leader_id: &str,
    leader_set_root: &str,
    emergency_committee_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(primary_leader_id),
            HashPart::Str(leader_set_root),
            HashPart::Str(emergency_committee_root),
        ],
        32,
    )
}

pub fn sequencer_failover_epoch_root(values: &[SequencerFailoverEpoch]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-EPOCH-ROOT",
        values
            .iter()
            .map(|value| (value.epoch_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn sequencer_failover_epoch_root_from_map(
    values: &BTreeMap<String, SequencerFailoverEpoch>,
) -> String {
    sequencer_failover_epoch_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn failover_trigger_id(
    trigger_kind: &FailoverTriggerKind,
    subject_leader_id: &str,
    observed_height: u64,
    missing_from_height: u64,
    affected_epoch: u64,
    evidence_payload_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-TRIGGER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(trigger_kind.as_str()),
            HashPart::Str(subject_leader_id),
            HashPart::Int(observed_height as i128),
            HashPart::Int(missing_from_height as i128),
            HashPart::Int(affected_epoch as i128),
            HashPart::Str(evidence_payload_root),
        ],
        32,
    )
}

pub fn failover_trigger_root(values: &[FailoverTrigger]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-TRIGGER-ROOT",
        values
            .iter()
            .map(|value| (value.trigger_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn failover_trigger_root_from_map(values: &BTreeMap<String, FailoverTrigger>) -> String {
    failover_trigger_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn emergency_approval_id(
    approval_kind: &EmergencyApprovalKind,
    committee_member_id: &str,
    trigger_id: &str,
    approved_leader_id: &str,
    approval_height: u64,
    approval_payload_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-EMERGENCY-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(approval_kind.as_str()),
            HashPart::Str(committee_member_id),
            HashPart::Str(trigger_id),
            HashPart::Str(approved_leader_id),
            HashPart::Int(approval_height as i128),
            HashPart::Str(approval_payload_root),
        ],
        32,
    )
}

pub fn emergency_approval_root(values: &[EmergencyCommitteeApproval]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-EMERGENCY-APPROVAL-ROOT",
        values
            .iter()
            .map(|value| (value.approval_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn emergency_approval_root_from_map(
    values: &BTreeMap<String, EmergencyCommitteeApproval>,
) -> String {
    emergency_approval_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn leader_handoff_certificate_id(
    trigger_id: &str,
    epoch_id: &str,
    from_leader_id: &str,
    to_leader_id: &str,
    approval_root: &str,
    signed_voting_power: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-HANDOFF-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(trigger_id),
            HashPart::Str(epoch_id),
            HashPart::Str(from_leader_id),
            HashPart::Str(to_leader_id),
            HashPart::Str(approval_root),
            HashPart::Int(signed_voting_power as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn leader_handoff_certificate_root(values: &[LeaderHandoffCertificate]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-HANDOFF-CERTIFICATE-ROOT",
        values
            .iter()
            .map(|value| (value.certificate_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn leader_handoff_certificate_root_from_map(
    values: &BTreeMap<String, LeaderHandoffCertificate>,
) -> String {
    leader_handoff_certificate_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn recovery_window_id(
    certificate_id: &str,
    trigger_id: &str,
    emergency_leader_id: &str,
    start_height: u64,
    end_height: u64,
    pending_queue_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-RECOVERY-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(certificate_id),
            HashPart::Str(trigger_id),
            HashPart::Str(emergency_leader_id),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(pending_queue_root),
        ],
        32,
    )
}

pub fn recovery_window_root(values: &[RecoveryWindow]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-RECOVERY-WINDOW-ROOT",
        values
            .iter()
            .map(|value| (value.window_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn recovery_window_root_from_map(values: &BTreeMap<String, RecoveryWindow>) -> String {
    recovery_window_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn low_fee_lane_id(
    lane_label: &str,
    lane_kind: &FailoverLaneKind,
    fee_asset_id: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-LOW-FEE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_label),
            HashPart::Str(&lane_kind.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn low_fee_lane_guarantee_id(
    lane_id: &str,
    max_fee_units: u64,
    min_share_bps: u64,
    reserved_capacity_units: u64,
    active_from_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-LOW-FEE-GUARANTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(min_share_bps as i128),
            HashPart::Int(reserved_capacity_units as i128),
            HashPart::Int(active_from_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_lane_guarantee_root(values: &[LowFeeLaneGuarantee]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-LOW-FEE-GUARANTEE-ROOT",
        values
            .iter()
            .map(|value| (value.guarantee_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn low_fee_lane_guarantee_root_from_map(
    values: &BTreeMap<String, LowFeeLaneGuarantee>,
) -> String {
    low_fee_lane_guarantee_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn encrypted_queue_drain_item_id(
    lane_id: &str,
    lane_kind: &FailoverLaneKind,
    encrypted_envelope_id: &str,
    queue_position: u64,
    payload_ciphertext_root: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-ENCRYPTED-QUEUE-DRAIN-ITEM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(&lane_kind.as_str()),
            HashPart::Str(encrypted_envelope_id),
            HashPart::Int(queue_position as i128),
            HashPart::Str(payload_ciphertext_root),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn encrypted_queue_drain_item_root(values: &[EncryptedQueueDrainItem]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-ENCRYPTED-QUEUE-DRAIN-ITEM-ROOT",
        values
            .iter()
            .map(|value| (value.item_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn encrypted_queue_drain_item_root_from_map(
    values: &BTreeMap<String, EncryptedQueueDrainItem>,
) -> String {
    encrypted_queue_drain_item_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn encrypted_queue_drain_manifest_id(
    recovery_window_id: &str,
    source_leader_id: &str,
    target_leader_id: &str,
    manifest_sequence: u64,
    queue_root: &str,
    private_queue_before_root: &str,
    private_queue_after_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-ENCRYPTED-QUEUE-DRAIN-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(recovery_window_id),
            HashPart::Str(source_leader_id),
            HashPart::Str(target_leader_id),
            HashPart::Int(manifest_sequence as i128),
            HashPart::Str(queue_root),
            HashPart::Str(private_queue_before_root),
            HashPart::Str(private_queue_after_root),
        ],
        32,
    )
}

pub fn encrypted_queue_drain_manifest_root(values: &[EncryptedQueueDrainManifest]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-ENCRYPTED-QUEUE-DRAIN-MANIFEST-ROOT",
        values
            .iter()
            .map(|value| (value.manifest_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn encrypted_queue_drain_manifest_root_from_map(
    values: &BTreeMap<String, EncryptedQueueDrainManifest>,
) -> String {
    encrypted_queue_drain_manifest_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn private_mempool_continuity_receipt_id(
    receipt_kind: &ContinuityReceiptKind,
    manifest_id: &str,
    item_id: &str,
    encrypted_envelope_id: &str,
    included_height: u64,
    included_block_root: &str,
    dequeue_proof_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-PRIVATE-MEMPOOL-CONTINUITY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_kind.as_str()),
            HashPart::Str(manifest_id),
            HashPart::Str(item_id),
            HashPart::Str(encrypted_envelope_id),
            HashPart::Int(included_height as i128),
            HashPart::Str(included_block_root),
            HashPart::Str(dequeue_proof_root),
        ],
        32,
    )
}

pub fn private_mempool_continuity_receipt_root(
    values: &[PrivateMempoolContinuityReceipt],
) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-PRIVATE-MEMPOOL-CONTINUITY-RECEIPT-ROOT",
        values
            .iter()
            .map(|value| (value.receipt_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn private_mempool_continuity_receipt_root_from_map(
    values: &BTreeMap<String, PrivateMempoolContinuityReceipt>,
) -> String {
    private_mempool_continuity_receipt_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn slashable_sequencer_evidence_id(
    evidence_kind: &SlashableEvidenceKind,
    offender_leader_id: &str,
    observed_height: u64,
    first_fault_height: u64,
    evidence_payload_root: &str,
    expected_action_root: &str,
    observed_action_root: &str,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-SLASHABLE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(offender_leader_id),
            HashPart::Int(observed_height as i128),
            HashPart::Int(first_fault_height as i128),
            HashPart::Str(evidence_payload_root),
            HashPart::Str(expected_action_root),
            HashPart::Str(observed_action_root),
        ],
        32,
    )
}

pub fn slashable_sequencer_evidence_root(values: &[SlashableSequencerEvidence]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-SLASHABLE-EVIDENCE-ROOT",
        values
            .iter()
            .map(|value| (value.evidence_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn slashable_sequencer_evidence_root_from_map(
    values: &BTreeMap<String, SlashableSequencerEvidence>,
) -> String {
    slashable_sequencer_evidence_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn sequencer_failover_public_record_id(
    source_id: &str,
    label: &str,
    payload_kind: &str,
    payload_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "SEQUENCER-FAILOVER-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_id),
            HashPart::Str(label),
            HashPart::Str(payload_kind),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn sequencer_failover_public_record_root(values: &[SequencerFailoverPublicRecord]) -> String {
    merkle_records_by_id(
        "SEQUENCER-FAILOVER-PUBLIC-RECORD-ROOT",
        values
            .iter()
            .map(|value| (value.record_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn sequencer_failover_public_record_root_from_map(
    values: &BTreeMap<String, SequencerFailoverPublicRecord>,
) -> String {
    sequencer_failover_public_record_root(&values.values().cloned().collect::<Vec<_>>())
}

fn ensure_non_empty(value: &str, label: &str) -> SequencerFailoverResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> SequencerFailoverResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> SequencerFailoverResult<()> {
    if value > SEQUENCER_FAILOVER_MAX_BPS {
        Err(format!("{label} exceeds 100%"))
    } else {
        Ok(())
    }
}

fn ensure_status(status: &str, allowed: &[&str]) -> SequencerFailoverResult<()> {
    if allowed.iter().any(|candidate| candidate == &status) {
        Ok(())
    } else {
        Err(format!("invalid sequencer failover status: {status}"))
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> SequencerFailoverResult<()> {
    let mut seen = BTreeMap::new();
    for value in values {
        if seen.insert(value.clone(), ()).is_some() {
            return Err(format!("{label} contains duplicate value: {value}"));
        }
    }
    Ok(())
}
