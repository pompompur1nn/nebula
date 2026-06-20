use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroWatchtowerMeshResult<T> = Result<T, String>;

pub const MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION: &str = "nebula-monero-watchtower-mesh-v1";
pub const MONERO_WATCHTOWER_MESH_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_WATCHTOWER_MESH_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_WATCHTOWER_MESH_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-watchtower-mesh";
pub const MONERO_WATCHTOWER_MESH_ALERT_ENCRYPTION_SCHEME: &str =
    "ML-KEM-768+XChaCha20-Poly1305-operator-alert-envelope";
pub const MONERO_WATCHTOWER_MESH_PUBLIC_RECORD_SCHEMA: &str =
    "monero-watchtower-mesh-public-record-v1";
pub const MONERO_WATCHTOWER_MESH_MAX_BPS: u64 = 10_000;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_DAEMON_QUORUM_WEIGHT: u64 = 3;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_ATTESTATION_QUORUM_WEIGHT: u64 = 2;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_FINALITY_DEPTH: u64 = 12;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_REORG_ALARM_DEPTH: u64 = 3;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_OBSERVATION_STALENESS_BLOCKS: u64 = 8;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_RESERVE_CHECK_TTL_BLOCKS: u64 = 24;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_RELEASE_SLA_BLOCKS: u64 = 18;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_SLASHING_WINDOW_BLOCKS: u64 = 144;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_ALERT_TTL_BLOCKS: u64 = 36;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_MIN_REPUTATION_SCORE: u64 = 6_000;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_LOW_FEE_SHARE_BPS: u64 = 2_000;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_LOW_FEE_USER_MAX_FEE_PICONERO: u64 = 80_000_000;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_FEE_PRESSURE_THRESHOLD_BPS: u64 = 7_500;
pub const MONERO_WATCHTOWER_MESH_DEFAULT_REPUTATION_SCORE: u64 = 8_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshWatcherRole {
    DaemonObserver,
    ReserveAuditor,
    ReleaseGuard,
    FeeSentinel,
    CensorshipProbe,
    EmergencyOperator,
}

impl MeshWatcherRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonObserver => "daemon_observer",
            Self::ReserveAuditor => "reserve_auditor",
            Self::ReleaseGuard => "release_guard",
            Self::FeeSentinel => "fee_sentinel",
            Self::CensorshipProbe => "censorship_probe",
            Self::EmergencyOperator => "emergency_operator",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshWatcherStatus {
    Active,
    Standby,
    Degraded,
    Suspended,
    Slashed,
    Retired,
}

impl MeshWatcherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Degraded => "degraded",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshSeverity {
    Info,
    Watch,
    Critical,
    Emergency,
}

impl MeshSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Info => 1,
            Self::Watch => 2,
            Self::Critical => 3,
            Self::Emergency => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityAlarmKind {
    ReorgDetected,
    DeepReorg,
    FinalityRegression,
    DaemonDivergence,
    AnchorMismatch,
}

impl FinalityAlarmKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReorgDetected => "reorg_detected",
            Self::DeepReorg => "deep_reorg",
            Self::FinalityRegression => "finality_regression",
            Self::DaemonDivergence => "daemon_divergence",
            Self::AnchorMismatch => "anchor_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmStatus {
    Open,
    QuorumConfirmed,
    Escalated,
    Resolved,
    Suppressed,
}

impl AlarmStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::QuorumConfirmed => "quorum_confirmed",
            Self::Escalated => "escalated",
            Self::Resolved => "resolved",
            Self::Suppressed => "suppressed",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Open | Self::QuorumConfirmed | Self::Escalated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveCheckStatus {
    Pending,
    Matched,
    Divergent,
    Expired,
    Challenged,
}

impl ReserveCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Matched => "matched",
            Self::Divergent => "divergent",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::Divergent | Self::Challenged)
    }

    pub fn needs_alarm(self) -> bool {
        matches!(self, Self::Divergent | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalReleaseStatus {
    Queued,
    Signed,
    Broadcast,
    Confirmed,
    Delayed,
    DoubleSpendRisk,
    Paused,
}

impl WithdrawalReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Signed => "signed",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Delayed => "delayed",
            Self::DoubleSpendRisk => "double_spend_risk",
            Self::Paused => "paused",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Signed | Self::Broadcast | Self::Delayed | Self::DoubleSpendRisk
        )
    }

    pub fn needs_operator_attention(self) -> bool {
        matches!(self, Self::Delayed | Self::DoubleSpendRisk | Self::Paused)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationSubjectKind {
    DaemonObservation,
    FinalityAlarm,
    ReserveCrossCheck,
    WithdrawalRelease,
    FailureReport,
    FeeBumpRecommendation,
    AlertEnvelope,
    ReputationUpdate,
    LowFeeProtectionLane,
    PublicRecord,
}

impl PqAttestationSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonObservation => "daemon_observation",
            Self::FinalityAlarm => "finality_alarm",
            Self::ReserveCrossCheck => "reserve_cross_check",
            Self::WithdrawalRelease => "withdrawal_release",
            Self::FailureReport => "failure_report",
            Self::FeeBumpRecommendation => "fee_bump_recommendation",
            Self::AlertEnvelope => "alert_envelope",
            Self::ReputationUpdate => "reputation_update",
            Self::LowFeeProtectionLane => "low_fee_protection_lane",
            Self::PublicRecord => "public_record",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Valid,
    Expired,
    Revoked,
    Conflicting,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Conflicting => "conflicting",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Pending | Self::Valid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReportKind {
    DaemonUnavailable,
    EndpointCensorship,
    TxSuppression,
    ReserveProofMissing,
    WatcherEquivocation,
    ReleaseDelay,
    LowFeeLaneStarved,
}

impl FailureReportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonUnavailable => "daemon_unavailable",
            Self::EndpointCensorship => "endpoint_censorship",
            Self::TxSuppression => "tx_suppression",
            Self::ReserveProofMissing => "reserve_proof_missing",
            Self::WatcherEquivocation => "watcher_equivocation",
            Self::ReleaseDelay => "release_delay",
            Self::LowFeeLaneStarved => "low_fee_lane_starved",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReportStatus {
    Filed,
    QuorumSupported,
    Mitigating,
    Resolved,
    Invalidated,
}

impl FailureReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::QuorumSupported => "quorum_supported",
            Self::Mitigating => "mitigating",
            Self::Resolved => "resolved",
            Self::Invalidated => "invalidated",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Filed | Self::QuorumSupported | Self::Mitigating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBumpAction {
    None,
    IncreaseMoneroFee,
    SplitReleaseBatch,
    AggregateReleaseBatch,
    EmergencySponsor,
    HoldForCongestion,
}

impl FeeBumpAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::IncreaseMoneroFee => "increase_monero_fee",
            Self::SplitReleaseBatch => "split_release_batch",
            Self::AggregateReleaseBatch => "aggregate_release_batch",
            Self::EmergencySponsor => "emergency_sponsor",
            Self::HoldForCongestion => "hold_for_congestion",
        }
    }

    pub fn requires_operator_action(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorAlertAudience {
    BridgeOperator,
    ReserveSigner,
    SecurityCouncil,
    FeeSponsor,
    PublicWatchdesk,
}

impl OperatorAlertAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeOperator => "bridge_operator",
            Self::ReserveSigner => "reserve_signer",
            Self::SecurityCouncil => "security_council",
            Self::FeeSponsor => "fee_sponsor",
            Self::PublicWatchdesk => "public_watchdesk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertEnvelopeStatus {
    Sealed,
    Delivered,
    Acknowledged,
    Expired,
    Revoked,
}

impl AlertEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn awaiting_ack(self) -> bool {
        matches!(self, Self::Sealed | Self::Delivered)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    FalseObservation,
    MissedQuorum,
    Equivocation,
    WithheldAttestation,
    Censorship,
    InvalidRelease,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalseObservation => "false_observation",
            Self::MissedQuorum => "missed_quorum",
            Self::Equivocation => "equivocation",
            Self::WithheldAttestation => "withheld_attestation",
            Self::Censorship => "censorship",
            Self::InvalidRelease => "invalid_release",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Proposed,
    EvidenceLocked,
    Executed,
    Appealed,
    Rejected,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::EvidenceLocked => "evidence_locked",
            Self::Executed => "executed",
            Self::Appealed => "appealed",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Proposed | Self::EvidenceLocked | Self::Appealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeLaneStatus {
    Open,
    Sponsored,
    Congested,
    Draining,
    Paused,
    Expired,
}

impl LowFeeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sponsored => "sponsored",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_users(self) -> bool {
        matches!(self, Self::Open | Self::Sponsored | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    FinalityAlarm,
    ReserveSafetySummary,
    WithdrawalReleaseWatch,
    FailureReport,
    FeeBumpRecommendation,
    LowFeeLaneCommitment,
    ReputationDigest,
    SlashingNotice,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FinalityAlarm => "finality_alarm",
            Self::ReserveSafetySummary => "reserve_safety_summary",
            Self::WithdrawalReleaseWatch => "withdrawal_release_watch",
            Self::FailureReport => "failure_report",
            Self::FeeBumpRecommendation => "fee_bump_recommendation",
            Self::LowFeeLaneCommitment => "low_fee_lane_commitment",
            Self::ReputationDigest => "reputation_digest",
            Self::SlashingNotice => "slashing_notice",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerMeshConfig {
    pub network: String,
    pub asset_id: String,
    pub daemon_quorum_weight: u64,
    pub pq_attestation_quorum_weight: u64,
    pub finality_depth: u64,
    pub reorg_alarm_depth: u64,
    pub observation_staleness_blocks: u64,
    pub reserve_cross_check_ttl_blocks: u64,
    pub withdrawal_release_sla_blocks: u64,
    pub slashing_window_blocks: u64,
    pub alert_ttl_blocks: u64,
    pub min_reputation_score: u64,
    pub low_fee_lane_min_share_bps: u64,
    pub low_fee_user_max_fee_piconero: u64,
    pub fee_pressure_threshold_bps: u64,
}

impl Default for MoneroWatchtowerMeshConfig {
    fn default() -> Self {
        Self {
            network: MONERO_WATCHTOWER_MESH_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_WATCHTOWER_MESH_DEVNET_ASSET_ID.to_string(),
            daemon_quorum_weight: MONERO_WATCHTOWER_MESH_DEFAULT_DAEMON_QUORUM_WEIGHT,
            pq_attestation_quorum_weight: MONERO_WATCHTOWER_MESH_DEFAULT_ATTESTATION_QUORUM_WEIGHT,
            finality_depth: MONERO_WATCHTOWER_MESH_DEFAULT_FINALITY_DEPTH,
            reorg_alarm_depth: MONERO_WATCHTOWER_MESH_DEFAULT_REORG_ALARM_DEPTH,
            observation_staleness_blocks:
                MONERO_WATCHTOWER_MESH_DEFAULT_OBSERVATION_STALENESS_BLOCKS,
            reserve_cross_check_ttl_blocks: MONERO_WATCHTOWER_MESH_DEFAULT_RESERVE_CHECK_TTL_BLOCKS,
            withdrawal_release_sla_blocks: MONERO_WATCHTOWER_MESH_DEFAULT_RELEASE_SLA_BLOCKS,
            slashing_window_blocks: MONERO_WATCHTOWER_MESH_DEFAULT_SLASHING_WINDOW_BLOCKS,
            alert_ttl_blocks: MONERO_WATCHTOWER_MESH_DEFAULT_ALERT_TTL_BLOCKS,
            min_reputation_score: MONERO_WATCHTOWER_MESH_DEFAULT_MIN_REPUTATION_SCORE,
            low_fee_lane_min_share_bps: MONERO_WATCHTOWER_MESH_DEFAULT_LOW_FEE_SHARE_BPS,
            low_fee_user_max_fee_piconero:
                MONERO_WATCHTOWER_MESH_DEFAULT_LOW_FEE_USER_MAX_FEE_PICONERO,
            fee_pressure_threshold_bps: MONERO_WATCHTOWER_MESH_DEFAULT_FEE_PRESSURE_THRESHOLD_BPS,
        }
    }
}

impl MoneroWatchtowerMeshConfig {
    pub fn validate(&self) -> MoneroWatchtowerMeshResult<()> {
        ensure_non_empty(&self.network, "watchtower mesh network")?;
        ensure_non_empty(&self.asset_id, "watchtower mesh asset id")?;
        ensure_positive(self.daemon_quorum_weight, "daemon quorum weight")?;
        ensure_positive(
            self.pq_attestation_quorum_weight,
            "pq attestation quorum weight",
        )?;
        ensure_positive(self.finality_depth, "finality depth")?;
        ensure_positive(self.reorg_alarm_depth, "reorg alarm depth")?;
        ensure_positive(
            self.observation_staleness_blocks,
            "observation staleness blocks",
        )?;
        ensure_positive(
            self.reserve_cross_check_ttl_blocks,
            "reserve cross-check ttl blocks",
        )?;
        ensure_positive(
            self.withdrawal_release_sla_blocks,
            "withdrawal release sla blocks",
        )?;
        ensure_positive(self.slashing_window_blocks, "slashing window blocks")?;
        ensure_positive(self.alert_ttl_blocks, "alert ttl blocks")?;
        ensure_bps(self.min_reputation_score, "min reputation score")?;
        ensure_bps(
            self.low_fee_lane_min_share_bps,
            "low fee lane min share bps",
        )?;
        ensure_bps(
            self.fee_pressure_threshold_bps,
            "fee pressure threshold bps",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_watchtower_mesh_config",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "network": self.network,
            "asset_id": self.asset_id,
            "daemon_quorum_weight": self.daemon_quorum_weight,
            "pq_attestation_quorum_weight": self.pq_attestation_quorum_weight,
            "finality_depth": self.finality_depth,
            "reorg_alarm_depth": self.reorg_alarm_depth,
            "observation_staleness_blocks": self.observation_staleness_blocks,
            "reserve_cross_check_ttl_blocks": self.reserve_cross_check_ttl_blocks,
            "withdrawal_release_sla_blocks": self.withdrawal_release_sla_blocks,
            "slashing_window_blocks": self.slashing_window_blocks,
            "alert_ttl_blocks": self.alert_ttl_blocks,
            "min_reputation_score": self.min_reputation_score,
            "low_fee_lane_min_share_bps": self.low_fee_lane_min_share_bps,
            "low_fee_user_max_fee_piconero": self.low_fee_user_max_fee_piconero,
            "fee_pressure_threshold_bps": self.fee_pressure_threshold_bps,
        })
    }

    pub fn config_root(&self) -> String {
        monero_watchtower_mesh_payload_root("MONERO-WATCHTOWER-MESH-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherIdentity {
    pub watcher_id: String,
    pub operator_label: String,
    pub role: MeshWatcherRole,
    pub status: MeshWatcherStatus,
    pub network: String,
    pub daemon_endpoint_commitment: String,
    pub network_zone_commitment: String,
    pub pq_public_key_commitment: String,
    pub alert_encryption_key_commitment: String,
    pub stake_units: u64,
    pub reputation_score: u64,
    pub slashed_units: u64,
    pub registered_at_height: u64,
    pub last_heartbeat_height: u64,
    pub metadata_root: String,
}

impl WatcherIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_label: &str,
        role: MeshWatcherRole,
        network: &str,
        daemon_endpoint_label: &str,
        network_zone_label: &str,
        pq_public_key_label: &str,
        alert_encryption_key_label: &str,
        stake_units: u64,
        reputation_score: u64,
        registered_at_height: u64,
        metadata_labels: &[String],
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(operator_label, "watcher operator label")?;
        ensure_non_empty(network, "watcher network")?;
        ensure_non_empty(pq_public_key_label, "watcher pq public key label")?;
        ensure_bps(reputation_score, "watcher reputation score")?;
        let daemon_endpoint_commitment = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-DAEMON-ENDPOINT",
            daemon_endpoint_label,
        );
        let network_zone_commitment = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-NETWORK-ZONE",
            network_zone_label,
        );
        let pq_public_key_commitment = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-PQ-PUBLIC-KEY",
            pq_public_key_label,
        );
        let alert_encryption_key_commitment = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-ALERT-ENCRYPTION-KEY",
            alert_encryption_key_label,
        );
        let metadata_root = monero_watchtower_mesh_string_set_root(
            "MONERO-WATCHTOWER-MESH-WATCHER-METADATA",
            metadata_labels,
        );
        let watcher_id = monero_watchtower_mesh_watcher_id(
            operator_label,
            role,
            network,
            &daemon_endpoint_commitment,
            &pq_public_key_commitment,
        );
        Ok(Self {
            watcher_id,
            operator_label: operator_label.to_string(),
            role,
            status: MeshWatcherStatus::Active,
            network: network.to_string(),
            daemon_endpoint_commitment,
            network_zone_commitment,
            pq_public_key_commitment,
            alert_encryption_key_commitment,
            stake_units,
            reputation_score,
            slashed_units: 0,
            registered_at_height,
            last_heartbeat_height: registered_at_height,
            metadata_root,
        })
    }

    pub fn set_heartbeat(&mut self, height: u64) {
        self.last_heartbeat_height = height;
        if self.status == MeshWatcherStatus::Degraded {
            self.status = MeshWatcherStatus::Active;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "watcher_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "watcher_id": self.watcher_id,
            "operator_label": self.operator_label,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "network": self.network,
            "daemon_endpoint_commitment": self.daemon_endpoint_commitment,
            "network_zone_commitment": self.network_zone_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "alert_encryption_key_commitment": self.alert_encryption_key_commitment,
            "stake_units": self.stake_units,
            "reputation_score": self.reputation_score,
            "slashed_units": self.slashed_units,
            "registered_at_height": self.registered_at_height,
            "last_heartbeat_height": self.last_heartbeat_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn watcher_root(&self) -> String {
        monero_watchtower_mesh_payload_root("MONERO-WATCHTOWER-MESH-WATCHER", &self.public_record())
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.watcher_id, "watcher id")?;
        ensure_non_empty(&self.operator_label, "watcher operator label")?;
        ensure_non_empty(&self.network, "watcher network")?;
        ensure_non_empty(
            &self.daemon_endpoint_commitment,
            "watcher daemon endpoint commitment",
        )?;
        ensure_non_empty(
            &self.pq_public_key_commitment,
            "watcher pq public key commitment",
        )?;
        ensure_bps(self.reputation_score, "watcher reputation score")?;
        let expected = monero_watchtower_mesh_watcher_id(
            &self.operator_label,
            self.role,
            &self.network,
            &self.daemon_endpoint_commitment,
            &self.pq_public_key_commitment,
        );
        if self.watcher_id != expected {
            return Err("watcher id mismatch".to_string());
        }
        Ok(self.watcher_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonObservation {
    pub observation_id: String,
    pub watcher_id: String,
    pub daemon_label: String,
    pub endpoint_commitment: String,
    pub block_height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub top_height: u64,
    pub tx_pool_hash: String,
    pub mempool_tx_count: u64,
    pub cumulative_difficulty_root: String,
    pub observed_at_height: u64,
    pub latency_ms: u64,
    pub status: String,
    pub attestation_id: String,
}

impl DaemonObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher_id: &str,
        daemon_label: &str,
        endpoint_label: &str,
        block_height: u64,
        block_hash: &str,
        previous_block_hash: &str,
        top_height: u64,
        tx_pool_hash: &str,
        mempool_tx_count: u64,
        cumulative_difficulty_root: &str,
        observed_at_height: u64,
        latency_ms: u64,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(watcher_id, "daemon observation watcher id")?;
        ensure_non_empty(daemon_label, "daemon observation daemon label")?;
        ensure_non_empty(block_hash, "daemon observation block hash")?;
        let endpoint_commitment = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-OBSERVED-ENDPOINT",
            endpoint_label,
        );
        let observation_id = monero_watchtower_mesh_daemon_observation_id(
            watcher_id,
            daemon_label,
            block_height,
            block_hash,
            &endpoint_commitment,
        );
        Ok(Self {
            observation_id,
            watcher_id: watcher_id.to_string(),
            daemon_label: daemon_label.to_string(),
            endpoint_commitment,
            block_height,
            block_hash: block_hash.to_string(),
            previous_block_hash: previous_block_hash.to_string(),
            top_height,
            tx_pool_hash: tx_pool_hash.to_string(),
            mempool_tx_count,
            cumulative_difficulty_root: cumulative_difficulty_root.to_string(),
            observed_at_height,
            latency_ms,
            status: "fresh".to_string(),
            attestation_id: String::new(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "watcher_id": self.watcher_id,
            "daemon_label": self.daemon_label,
            "endpoint_commitment": self.endpoint_commitment,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "previous_block_hash": self.previous_block_hash,
            "top_height": self.top_height,
            "tx_pool_hash": self.tx_pool_hash,
            "mempool_tx_count": self.mempool_tx_count,
            "cumulative_difficulty_root": self.cumulative_difficulty_root,
            "observed_at_height": self.observed_at_height,
            "latency_ms": self.latency_ms,
            "status": self.status,
            "attestation_id": self.attestation_id,
        })
    }

    pub fn observation_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-DAEMON-OBSERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.observation_id, "daemon observation id")?;
        ensure_non_empty(&self.watcher_id, "daemon observation watcher id")?;
        ensure_non_empty(&self.block_hash, "daemon observation block hash")?;
        let expected = monero_watchtower_mesh_daemon_observation_id(
            &self.watcher_id,
            &self.daemon_label,
            self.block_height,
            &self.block_hash,
            &self.endpoint_commitment,
        );
        if self.observation_id != expected {
            return Err("daemon observation id mismatch".to_string());
        }
        Ok(self.observation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityAlarm {
    pub alarm_id: String,
    pub kind: FinalityAlarmKind,
    pub severity: MeshSeverity,
    pub network: String,
    pub block_height: u64,
    pub canonical_block_hash: String,
    pub conflicting_block_hash: String,
    pub reorg_depth: u64,
    pub observation_root: String,
    pub watcher_quorum_root: String,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub status: AlarmStatus,
}

impl FinalityAlarm {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: FinalityAlarmKind,
        severity: MeshSeverity,
        network: &str,
        block_height: u64,
        canonical_block_hash: &str,
        conflicting_block_hash: &str,
        reorg_depth: u64,
        observation_root: &str,
        watcher_quorum_root: &str,
        opened_at_height: u64,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(network, "finality alarm network")?;
        ensure_non_empty(canonical_block_hash, "finality alarm canonical block hash")?;
        ensure_non_empty(
            conflicting_block_hash,
            "finality alarm conflicting block hash",
        )?;
        let alarm_id = monero_watchtower_mesh_finality_alarm_id(
            kind,
            network,
            block_height,
            canonical_block_hash,
            conflicting_block_hash,
            opened_at_height,
        );
        Ok(Self {
            alarm_id,
            kind,
            severity,
            network: network.to_string(),
            block_height,
            canonical_block_hash: canonical_block_hash.to_string(),
            conflicting_block_hash: conflicting_block_hash.to_string(),
            reorg_depth,
            observation_root: observation_root.to_string(),
            watcher_quorum_root: watcher_quorum_root.to_string(),
            opened_at_height,
            resolved_at_height: None,
            status: AlarmStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_alarm",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "alarm_id": self.alarm_id,
            "alarm_kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "network": self.network,
            "block_height": self.block_height,
            "canonical_block_hash": self.canonical_block_hash,
            "conflicting_block_hash": self.conflicting_block_hash,
            "reorg_depth": self.reorg_depth,
            "observation_root": self.observation_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn alarm_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-FINALITY-ALARM",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.alarm_id, "finality alarm id")?;
        ensure_non_empty(&self.network, "finality alarm network")?;
        ensure_non_empty(
            &self.canonical_block_hash,
            "finality alarm canonical block hash",
        )?;
        ensure_non_empty(
            &self.conflicting_block_hash,
            "finality alarm conflicting block hash",
        )?;
        let expected = monero_watchtower_mesh_finality_alarm_id(
            self.kind,
            &self.network,
            self.block_height,
            &self.canonical_block_hash,
            &self.conflicting_block_hash,
            self.opened_at_height,
        );
        if self.alarm_id != expected {
            return Err("finality alarm id mismatch".to_string());
        }
        Ok(self.alarm_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofCrossCheck {
    pub check_id: String,
    pub reserve_epoch_id: String,
    pub reserve_proof_root: String,
    pub daemon_observation_root: String,
    pub key_image_root: String,
    pub output_commitment_root: String,
    pub reported_reserve_piconero_bucket: u64,
    pub expected_liability_piconero_bucket: u64,
    pub coverage_bps: u64,
    pub watchers_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReserveCheckStatus,
    pub divergence_reason: String,
    pub attestation_id: String,
}

impl ReserveProofCrossCheck {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reserve_epoch_id: &str,
        reserve_proof_root: &str,
        daemon_observation_root: &str,
        key_image_root: &str,
        output_commitment_root: &str,
        reported_reserve_piconero_bucket: u64,
        expected_liability_piconero_bucket: u64,
        watchers_root: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(reserve_epoch_id, "reserve proof cross-check epoch id")?;
        ensure_non_empty(reserve_proof_root, "reserve proof root")?;
        let coverage_bps = ratio_bps(
            reported_reserve_piconero_bucket,
            expected_liability_piconero_bucket,
        )
        .min(u64::MAX);
        let status = if expected_liability_piconero_bucket == 0
            || reported_reserve_piconero_bucket >= expected_liability_piconero_bucket
        {
            ReserveCheckStatus::Matched
        } else {
            ReserveCheckStatus::Divergent
        };
        let check_id = monero_watchtower_mesh_reserve_cross_check_id(
            reserve_epoch_id,
            reserve_proof_root,
            daemon_observation_root,
            opened_at_height,
        );
        Ok(Self {
            check_id,
            reserve_epoch_id: reserve_epoch_id.to_string(),
            reserve_proof_root: reserve_proof_root.to_string(),
            daemon_observation_root: daemon_observation_root.to_string(),
            key_image_root: key_image_root.to_string(),
            output_commitment_root: output_commitment_root.to_string(),
            reported_reserve_piconero_bucket,
            expected_liability_piconero_bucket,
            coverage_bps,
            watchers_root: watchers_root.to_string(),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status,
            divergence_reason: if status.needs_alarm() {
                "reported_reserve_below_expected_liability".to_string()
            } else {
                "none".to_string()
            },
            attestation_id: String::new(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof_cross_check",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "check_id": self.check_id,
            "reserve_epoch_id": self.reserve_epoch_id,
            "reserve_proof_root": self.reserve_proof_root,
            "daemon_observation_root": self.daemon_observation_root,
            "key_image_root": self.key_image_root,
            "output_commitment_root": self.output_commitment_root,
            "reported_reserve_piconero_bucket": self.reported_reserve_piconero_bucket,
            "expected_liability_piconero_bucket": self.expected_liability_piconero_bucket,
            "coverage_bps": self.coverage_bps,
            "watchers_root": self.watchers_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "divergence_reason": self.divergence_reason,
            "attestation_id": self.attestation_id,
        })
    }

    pub fn check_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-RESERVE-CROSS-CHECK",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.check_id, "reserve cross-check id")?;
        ensure_non_empty(&self.reserve_epoch_id, "reserve cross-check epoch id")?;
        ensure_non_empty(&self.reserve_proof_root, "reserve proof root")?;
        let expected = monero_watchtower_mesh_reserve_cross_check_id(
            &self.reserve_epoch_id,
            &self.reserve_proof_root,
            &self.daemon_observation_root,
            self.opened_at_height,
        );
        if self.check_id != expected {
            return Err("reserve cross-check id mismatch".to_string());
        }
        Ok(self.check_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalReleaseSurveillance {
    pub release_id: String,
    pub withdrawal_id: String,
    pub recipient_commitment: String,
    pub amount_bucket_piconero: u64,
    pub expected_release_height: u64,
    pub observed_txid_hash: Option<String>,
    pub observed_block_height: Option<u64>,
    pub observed_confirmations: u64,
    pub fee_paid_piconero: u64,
    pub min_fee_recommended_piconero: u64,
    pub watcher_root: String,
    pub opened_at_height: u64,
    pub last_checked_height: u64,
    pub status: WithdrawalReleaseStatus,
    pub risk_flags_root: String,
    pub attestation_id: String,
}

impl WithdrawalReleaseSurveillance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: &str,
        recipient_label: &str,
        amount_bucket_piconero: u64,
        expected_release_height: u64,
        fee_paid_piconero: u64,
        min_fee_recommended_piconero: u64,
        watcher_root: &str,
        opened_at_height: u64,
        risk_flags: &[String],
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(withdrawal_id, "withdrawal release id")?;
        ensure_non_empty(recipient_label, "withdrawal release recipient label")?;
        let recipient_commitment = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-RELEASE-RECIPIENT",
            recipient_label,
        );
        let risk_flags_root = monero_watchtower_mesh_string_set_root(
            "MONERO-WATCHTOWER-MESH-RELEASE-RISK",
            risk_flags,
        );
        let release_id = monero_watchtower_mesh_withdrawal_release_id(
            withdrawal_id,
            &recipient_commitment,
            amount_bucket_piconero,
            expected_release_height,
        );
        Ok(Self {
            release_id,
            withdrawal_id: withdrawal_id.to_string(),
            recipient_commitment,
            amount_bucket_piconero,
            expected_release_height,
            observed_txid_hash: None,
            observed_block_height: None,
            observed_confirmations: 0,
            fee_paid_piconero,
            min_fee_recommended_piconero,
            watcher_root: watcher_root.to_string(),
            opened_at_height,
            last_checked_height: opened_at_height,
            status: WithdrawalReleaseStatus::Queued,
            risk_flags_root,
            attestation_id: String::new(),
        })
    }

    pub fn mark_observed(&mut self, txid_hash: &str, block_height: u64, current_height: u64) {
        self.observed_txid_hash = Some(txid_hash.to_string());
        self.observed_block_height = Some(block_height);
        self.observed_confirmations = confirmations(current_height, block_height);
        self.last_checked_height = current_height;
        self.status = WithdrawalReleaseStatus::Broadcast;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "withdrawal_release_surveillance",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "release_id": self.release_id,
            "withdrawal_id": self.withdrawal_id,
            "recipient_commitment": self.recipient_commitment,
            "amount_bucket_piconero": self.amount_bucket_piconero,
            "expected_release_height": self.expected_release_height,
            "observed_txid_hash": self.observed_txid_hash,
            "observed_block_height": self.observed_block_height,
            "observed_confirmations": self.observed_confirmations,
            "fee_paid_piconero": self.fee_paid_piconero,
            "min_fee_recommended_piconero": self.min_fee_recommended_piconero,
            "watcher_root": self.watcher_root,
            "opened_at_height": self.opened_at_height,
            "last_checked_height": self.last_checked_height,
            "status": self.status.as_str(),
            "risk_flags_root": self.risk_flags_root,
            "attestation_id": self.attestation_id,
        })
    }

    pub fn release_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-WITHDRAWAL-RELEASE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.release_id, "withdrawal release surveillance id")?;
        ensure_non_empty(&self.withdrawal_id, "withdrawal id")?;
        ensure_non_empty(&self.recipient_commitment, "recipient commitment")?;
        let expected = monero_watchtower_mesh_withdrawal_release_id(
            &self.withdrawal_id,
            &self.recipient_commitment,
            self.amount_bucket_piconero,
            self.expected_release_height,
        );
        if self.release_id != expected {
            return Err("withdrawal release id mismatch".to_string());
        }
        Ok(self.release_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub subject_kind: PqAttestationSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub pq_scheme: String,
    pub public_key_commitment: String,
    pub transcript_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub weight: u64,
    pub signature_commitment: String,
    pub status: AttestationStatus,
}

impl PqWatcherAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher_id: &str,
        subject_kind: PqAttestationSubjectKind,
        subject_id: &str,
        subject_root: &str,
        public_key_commitment: &str,
        transcript_label: &str,
        signed_at_height: u64,
        ttl_blocks: u64,
        weight: u64,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(watcher_id, "pq watcher attestation watcher id")?;
        ensure_non_empty(subject_id, "pq watcher attestation subject id")?;
        ensure_non_empty(subject_root, "pq watcher attestation subject root")?;
        ensure_non_empty(public_key_commitment, "pq watcher attestation public key")?;
        ensure_positive(weight, "pq watcher attestation weight")?;
        let transcript_root = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-PQ-TRANSCRIPT",
            transcript_label,
        );
        let signature_commitment = monero_watchtower_mesh_signature_commitment(
            watcher_id,
            subject_kind,
            subject_id,
            subject_root,
            &transcript_root,
            signed_at_height,
        );
        let attestation_id = monero_watchtower_mesh_pq_attestation_id(
            watcher_id,
            subject_kind,
            subject_id,
            subject_root,
            signed_at_height,
        );
        Ok(Self {
            attestation_id,
            watcher_id: watcher_id.to_string(),
            subject_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            pq_scheme: MONERO_WATCHTOWER_MESH_PQ_ATTESTATION_SCHEME.to_string(),
            public_key_commitment: public_key_commitment.to_string(),
            transcript_root,
            signed_at_height,
            expires_at_height: signed_at_height.saturating_add(ttl_blocks),
            weight,
            signature_commitment,
            status: AttestationStatus::Valid,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_watcher_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "pq_scheme": self.pq_scheme,
            "public_key_commitment": self.public_key_commitment,
            "transcript_root": self.transcript_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "weight": self.weight,
            "signature_commitment": self.signature_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-PQ-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.attestation_id, "pq watcher attestation id")?;
        ensure_non_empty(&self.watcher_id, "pq watcher attestation watcher id")?;
        ensure_non_empty(&self.subject_id, "pq watcher attestation subject id")?;
        ensure_non_empty(&self.subject_root, "pq watcher attestation subject root")?;
        ensure_positive(self.weight, "pq watcher attestation weight")?;
        let expected = monero_watchtower_mesh_pq_attestation_id(
            &self.watcher_id,
            self.subject_kind,
            &self.subject_id,
            &self.subject_root,
            self.signed_at_height,
        );
        if self.attestation_id != expected {
            return Err("pq watcher attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipFailureReport {
    pub report_id: String,
    pub kind: FailureReportKind,
    pub severity: MeshSeverity,
    pub reporter_watcher_id: String,
    pub accused_operator_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub first_seen_height: u64,
    pub last_seen_height: u64,
    pub missed_blocks: u64,
    pub watcher_quorum_root: String,
    pub mitigation_root: String,
    pub status: FailureReportStatus,
    pub attestation_id: String,
}

impl CensorshipFailureReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: FailureReportKind,
        severity: MeshSeverity,
        reporter_watcher_id: &str,
        accused_operator_id: &str,
        subject_id: &str,
        evidence_root: &str,
        first_seen_height: u64,
        last_seen_height: u64,
        missed_blocks: u64,
        watcher_quorum_root: &str,
        mitigation_notes: &[String],
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(reporter_watcher_id, "failure report reporter watcher id")?;
        ensure_non_empty(accused_operator_id, "failure report accused operator id")?;
        ensure_non_empty(subject_id, "failure report subject id")?;
        ensure_non_empty(evidence_root, "failure report evidence root")?;
        let mitigation_root = monero_watchtower_mesh_string_set_root(
            "MONERO-WATCHTOWER-MESH-FAILURE-MITIGATION",
            mitigation_notes,
        );
        let report_id = monero_watchtower_mesh_failure_report_id(
            kind,
            reporter_watcher_id,
            accused_operator_id,
            subject_id,
            evidence_root,
            first_seen_height,
        );
        Ok(Self {
            report_id,
            kind,
            severity,
            reporter_watcher_id: reporter_watcher_id.to_string(),
            accused_operator_id: accused_operator_id.to_string(),
            subject_id: subject_id.to_string(),
            evidence_root: evidence_root.to_string(),
            first_seen_height,
            last_seen_height,
            missed_blocks,
            watcher_quorum_root: watcher_quorum_root.to_string(),
            mitigation_root,
            status: FailureReportStatus::Filed,
            attestation_id: String::new(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "censorship_failure_report",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "report_kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "reporter_watcher_id": self.reporter_watcher_id,
            "accused_operator_id": self.accused_operator_id,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "first_seen_height": self.first_seen_height,
            "last_seen_height": self.last_seen_height,
            "missed_blocks": self.missed_blocks,
            "watcher_quorum_root": self.watcher_quorum_root,
            "mitigation_root": self.mitigation_root,
            "status": self.status.as_str(),
            "attestation_id": self.attestation_id,
        })
    }

    pub fn report_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-FAILURE-REPORT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.report_id, "failure report id")?;
        ensure_non_empty(
            &self.reporter_watcher_id,
            "failure report reporter watcher id",
        )?;
        ensure_non_empty(
            &self.accused_operator_id,
            "failure report accused operator id",
        )?;
        ensure_non_empty(&self.subject_id, "failure report subject id")?;
        ensure_non_empty(&self.evidence_root, "failure report evidence root")?;
        let expected = monero_watchtower_mesh_failure_report_id(
            self.kind,
            &self.reporter_watcher_id,
            &self.accused_operator_id,
            &self.subject_id,
            &self.evidence_root,
            self.first_seen_height,
        );
        if self.report_id != expected {
            return Err("failure report id mismatch".to_string());
        }
        Ok(self.report_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeBumpRecommendation {
    pub recommendation_id: String,
    pub release_id: String,
    pub watcher_id: String,
    pub action: FeeBumpAction,
    pub reason: String,
    pub current_fee_piconero: u64,
    pub recommended_fee_piconero: u64,
    pub urgency_bps: u64,
    pub mempool_pressure_bps: u64,
    pub low_fee_lane_id: Option<String>,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl FeeBumpRecommendation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        release_id: &str,
        watcher_id: &str,
        action: FeeBumpAction,
        reason: &str,
        current_fee_piconero: u64,
        recommended_fee_piconero: u64,
        urgency_bps: u64,
        mempool_pressure_bps: u64,
        low_fee_lane_id: Option<String>,
        evidence_root: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(release_id, "fee bump release id")?;
        ensure_non_empty(watcher_id, "fee bump watcher id")?;
        ensure_non_empty(reason, "fee bump reason")?;
        ensure_bps(urgency_bps, "fee bump urgency bps")?;
        ensure_bps(mempool_pressure_bps, "fee bump mempool pressure bps")?;
        let recommendation_id = monero_watchtower_mesh_fee_bump_recommendation_id(
            release_id,
            watcher_id,
            action,
            recommended_fee_piconero,
            opened_at_height,
        );
        let status = if action.requires_operator_action() {
            "open"
        } else {
            "observed"
        }
        .to_string();
        Ok(Self {
            recommendation_id,
            release_id: release_id.to_string(),
            watcher_id: watcher_id.to_string(),
            action,
            reason: reason.to_string(),
            current_fee_piconero,
            recommended_fee_piconero,
            urgency_bps,
            mempool_pressure_bps,
            low_fee_lane_id,
            evidence_root: evidence_root.to_string(),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status,
        })
    }

    pub fn fee_delta_piconero(&self) -> u64 {
        self.recommended_fee_piconero
            .saturating_sub(self.current_fee_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_bump_recommendation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "recommendation_id": self.recommendation_id,
            "release_id": self.release_id,
            "watcher_id": self.watcher_id,
            "action": self.action.as_str(),
            "reason": self.reason,
            "current_fee_piconero": self.current_fee_piconero,
            "recommended_fee_piconero": self.recommended_fee_piconero,
            "fee_delta_piconero": self.fee_delta_piconero(),
            "urgency_bps": self.urgency_bps,
            "mempool_pressure_bps": self.mempool_pressure_bps,
            "low_fee_lane_id": self.low_fee_lane_id,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn recommendation_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-FEE-BUMP-RECOMMENDATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.recommendation_id, "fee bump recommendation id")?;
        ensure_non_empty(&self.release_id, "fee bump release id")?;
        ensure_non_empty(&self.watcher_id, "fee bump watcher id")?;
        ensure_bps(self.urgency_bps, "fee bump urgency bps")?;
        ensure_bps(self.mempool_pressure_bps, "fee bump mempool pressure bps")?;
        let expected = monero_watchtower_mesh_fee_bump_recommendation_id(
            &self.release_id,
            &self.watcher_id,
            self.action,
            self.recommended_fee_piconero,
            self.opened_at_height,
        );
        if self.recommendation_id != expected {
            return Err("fee bump recommendation id mismatch".to_string());
        }
        Ok(self.recommendation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOperatorAlertEnvelope {
    pub envelope_id: String,
    pub audience: OperatorAlertAudience,
    pub recipient_commitment: String,
    pub severity: MeshSeverity,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_ciphertext_root: String,
    pub routing_hint_commitment: String,
    pub encryption_scheme: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: AlertEnvelopeStatus,
    pub ack_height: Option<u64>,
    pub attestation_root: String,
}

impl EncryptedOperatorAlertEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        audience: OperatorAlertAudience,
        recipient_label: &str,
        severity: MeshSeverity,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload_ciphertext_root: &str,
        routing_hint: &str,
        attestation_root: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(recipient_label, "operator alert recipient")?;
        ensure_non_empty(subject_kind, "operator alert subject kind")?;
        ensure_non_empty(subject_id, "operator alert subject id")?;
        ensure_non_empty(subject_root, "operator alert subject root")?;
        ensure_non_empty(payload_ciphertext_root, "operator alert ciphertext root")?;
        let recipient_commitment = monero_watchtower_mesh_string_root(
            "MONERO-WATCHTOWER-MESH-ALERT-RECIPIENT",
            recipient_label,
        );
        let routing_hint_commitment =
            monero_watchtower_mesh_string_root("MONERO-WATCHTOWER-MESH-ALERT-ROUTE", routing_hint);
        let envelope_id = monero_watchtower_mesh_alert_envelope_id(
            audience,
            &recipient_commitment,
            subject_kind,
            subject_id,
            payload_ciphertext_root,
            created_at_height,
        );
        Ok(Self {
            envelope_id,
            audience,
            recipient_commitment,
            severity,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_ciphertext_root: payload_ciphertext_root.to_string(),
            routing_hint_commitment,
            encryption_scheme: MONERO_WATCHTOWER_MESH_ALERT_ENCRYPTION_SCHEME.to_string(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: AlertEnvelopeStatus::Sealed,
            ack_height: None,
            attestation_root: attestation_root.to_string(),
        })
    }

    pub fn acknowledge(&mut self, height: u64) {
        self.ack_height = Some(height);
        self.status = AlertEnvelopeStatus::Acknowledged;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_operator_alert_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "audience": self.audience.as_str(),
            "recipient_commitment": self.recipient_commitment,
            "severity": self.severity.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "routing_hint_commitment": self.routing_hint_commitment,
            "encryption_scheme": self.encryption_scheme,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "ack_height": self.ack_height,
            "attestation_root": self.attestation_root,
        })
    }

    pub fn envelope_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-ALERT-ENVELOPE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.envelope_id, "alert envelope id")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "alert envelope recipient commitment",
        )?;
        ensure_non_empty(&self.subject_kind, "alert envelope subject kind")?;
        ensure_non_empty(&self.subject_id, "alert envelope subject id")?;
        ensure_non_empty(&self.subject_root, "alert envelope subject root")?;
        ensure_non_empty(
            &self.payload_ciphertext_root,
            "alert envelope ciphertext root",
        )?;
        let expected = monero_watchtower_mesh_alert_envelope_id(
            self.audience,
            &self.recipient_commitment,
            &self.subject_kind,
            &self.subject_id,
            &self.payload_ciphertext_root,
            self.created_at_height,
        );
        if self.envelope_id != expected {
            return Err("alert envelope id mismatch".to_string());
        }
        Ok(self.envelope_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherReputationRecord {
    pub reputation_id: String,
    pub watcher_id: String,
    pub starting_score: u64,
    pub current_score: u64,
    pub successful_attestations: u64,
    pub missed_attestations: u64,
    pub false_positive_count: u64,
    pub slash_count: u64,
    pub slashed_units: u64,
    pub last_update_height: u64,
    pub status: MeshWatcherStatus,
    pub evidence_root: String,
}

impl WatcherReputationRecord {
    pub fn new(
        watcher_id: &str,
        starting_score: u64,
        last_update_height: u64,
        evidence_root: &str,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(watcher_id, "watcher reputation watcher id")?;
        ensure_bps(starting_score, "watcher starting reputation score")?;
        let reputation_id =
            monero_watchtower_mesh_reputation_id(watcher_id, starting_score, last_update_height);
        Ok(Self {
            reputation_id,
            watcher_id: watcher_id.to_string(),
            starting_score,
            current_score: starting_score,
            successful_attestations: 0,
            missed_attestations: 0,
            false_positive_count: 0,
            slash_count: 0,
            slashed_units: 0,
            last_update_height,
            status: MeshWatcherStatus::Active,
            evidence_root: evidence_root.to_string(),
        })
    }

    pub fn apply_success(&mut self, reward_score: u64, height: u64) {
        self.successful_attestations = self.successful_attestations.saturating_add(1);
        self.current_score = self
            .current_score
            .saturating_add(reward_score)
            .min(MONERO_WATCHTOWER_MESH_MAX_BPS);
        self.last_update_height = height;
        self.refresh_reputation_id();
        if self.status == MeshWatcherStatus::Degraded {
            self.status = MeshWatcherStatus::Active;
        }
    }

    pub fn apply_miss(&mut self, penalty_score: u64, height: u64) {
        self.missed_attestations = self.missed_attestations.saturating_add(1);
        self.current_score = self.current_score.saturating_sub(penalty_score);
        self.last_update_height = height;
        self.refresh_reputation_id();
        if self.current_score < MONERO_WATCHTOWER_MESH_DEFAULT_MIN_REPUTATION_SCORE {
            self.status = MeshWatcherStatus::Degraded;
        }
    }

    pub fn apply_slash(&mut self, slash_units: u64, penalty_score: u64, height: u64) {
        self.slash_count = self.slash_count.saturating_add(1);
        self.slashed_units = self.slashed_units.saturating_add(slash_units);
        self.current_score = self.current_score.saturating_sub(penalty_score);
        self.last_update_height = height;
        self.refresh_reputation_id();
        if self.current_score == 0 {
            self.status = MeshWatcherStatus::Slashed;
        } else {
            self.status = MeshWatcherStatus::Suspended;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "watcher_reputation_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "reputation_id": self.reputation_id,
            "watcher_id": self.watcher_id,
            "starting_score": self.starting_score,
            "current_score": self.current_score,
            "successful_attestations": self.successful_attestations,
            "missed_attestations": self.missed_attestations,
            "false_positive_count": self.false_positive_count,
            "slash_count": self.slash_count,
            "slashed_units": self.slashed_units,
            "last_update_height": self.last_update_height,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
        })
    }

    pub fn reputation_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-REPUTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.reputation_id, "watcher reputation id")?;
        ensure_non_empty(&self.watcher_id, "watcher reputation watcher id")?;
        ensure_bps(self.starting_score, "watcher starting reputation score")?;
        ensure_bps(self.current_score, "watcher current reputation score")?;
        let expected = monero_watchtower_mesh_reputation_id(
            &self.watcher_id,
            self.starting_score,
            self.last_update_height,
        );
        if self.reputation_id != expected {
            return Err("watcher reputation id mismatch".to_string());
        }
        Ok(self.reputation_root())
    }

    fn refresh_reputation_id(&mut self) {
        self.reputation_id = monero_watchtower_mesh_reputation_id(
            &self.watcher_id,
            self.starting_score,
            self.last_update_height,
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerSlashingRecord {
    pub slash_id: String,
    pub watcher_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub slash_units: u64,
    pub slash_bps: u64,
    pub opened_at_height: u64,
    pub executed_at_height: Option<u64>,
    pub appeal_deadline_height: u64,
    pub status: SlashingStatus,
    pub attestation_root: String,
}

impl WatchtowerSlashingRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher_id: &str,
        reason: SlashReason,
        evidence_root: &str,
        slash_units: u64,
        slash_bps: u64,
        opened_at_height: u64,
        appeal_window_blocks: u64,
        attestation_root: &str,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(watcher_id, "slashing watcher id")?;
        ensure_non_empty(evidence_root, "slashing evidence root")?;
        ensure_bps(slash_bps, "slashing bps")?;
        let slash_id = monero_watchtower_mesh_slash_id(
            watcher_id,
            reason,
            evidence_root,
            slash_units,
            opened_at_height,
        );
        Ok(Self {
            slash_id,
            watcher_id: watcher_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            slash_units,
            slash_bps,
            opened_at_height,
            executed_at_height: None,
            appeal_deadline_height: opened_at_height.saturating_add(appeal_window_blocks),
            status: SlashingStatus::Proposed,
            attestation_root: attestation_root.to_string(),
        })
    }

    pub fn execute(&mut self, height: u64) {
        self.executed_at_height = Some(height);
        self.status = SlashingStatus::Executed;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "watchtower_slashing_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "slash_id": self.slash_id,
            "watcher_id": self.watcher_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "slash_units": self.slash_units,
            "slash_bps": self.slash_bps,
            "opened_at_height": self.opened_at_height,
            "executed_at_height": self.executed_at_height,
            "appeal_deadline_height": self.appeal_deadline_height,
            "status": self.status.as_str(),
            "attestation_root": self.attestation_root,
        })
    }

    pub fn slash_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-SLASHING",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.slash_id, "slashing id")?;
        ensure_non_empty(&self.watcher_id, "slashing watcher id")?;
        ensure_non_empty(&self.evidence_root, "slashing evidence root")?;
        ensure_bps(self.slash_bps, "slashing bps")?;
        let expected = monero_watchtower_mesh_slash_id(
            &self.watcher_id,
            self.reason,
            &self.evidence_root,
            self.slash_units,
            self.opened_at_height,
        );
        if self.slash_id != expected {
            return Err("slashing id mismatch".to_string());
        }
        Ok(self.slash_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProtectionLane {
    pub lane_id: String,
    pub sponsor_id: String,
    pub asset_id: String,
    pub min_share_bps: u64,
    pub max_user_fee_piconero: u64,
    pub reserved_budget_piconero: u64,
    pub spent_budget_piconero: u64,
    pub protected_withdrawal_root: String,
    pub watcher_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeLaneStatus,
    pub priority_score: u64,
}

impl LowFeeProtectionLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        asset_id: &str,
        min_share_bps: u64,
        max_user_fee_piconero: u64,
        reserved_budget_piconero: u64,
        protected_withdrawal_ids: &[String],
        watcher_ids: &[String],
        opened_at_height: u64,
        ttl_blocks: u64,
        priority_score: u64,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(sponsor_id, "low fee lane sponsor id")?;
        ensure_non_empty(asset_id, "low fee lane asset id")?;
        ensure_bps(min_share_bps, "low fee lane min share bps")?;
        let protected_withdrawal_root = monero_watchtower_mesh_string_set_root(
            "MONERO-WATCHTOWER-MESH-LOW-FEE-WITHDRAWALS",
            protected_withdrawal_ids,
        );
        let watcher_root = monero_watchtower_mesh_string_set_root(
            "MONERO-WATCHTOWER-MESH-LOW-FEE-WATCHERS",
            watcher_ids,
        );
        let lane_id = monero_watchtower_mesh_low_fee_lane_id(
            sponsor_id,
            asset_id,
            &protected_withdrawal_root,
            opened_at_height,
        );
        Ok(Self {
            lane_id,
            sponsor_id: sponsor_id.to_string(),
            asset_id: asset_id.to_string(),
            min_share_bps,
            max_user_fee_piconero,
            reserved_budget_piconero,
            spent_budget_piconero: 0,
            protected_withdrawal_root,
            watcher_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: LowFeeLaneStatus::Sponsored,
            priority_score,
        })
    }

    pub fn remaining_budget_piconero(&self) -> u64 {
        self.reserved_budget_piconero
            .saturating_sub(self.spent_budget_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_protection_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "asset_id": self.asset_id,
            "min_share_bps": self.min_share_bps,
            "max_user_fee_piconero": self.max_user_fee_piconero,
            "reserved_budget_piconero": self.reserved_budget_piconero,
            "spent_budget_piconero": self.spent_budget_piconero,
            "remaining_budget_piconero": self.remaining_budget_piconero(),
            "protected_withdrawal_root": self.protected_withdrawal_root,
            "watcher_root": self.watcher_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "priority_score": self.priority_score,
        })
    }

    pub fn lane_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-LOW-FEE-LANE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.lane_id, "low fee lane id")?;
        ensure_non_empty(&self.sponsor_id, "low fee lane sponsor id")?;
        ensure_non_empty(&self.asset_id, "low fee lane asset id")?;
        ensure_bps(self.min_share_bps, "low fee lane min share bps")?;
        let expected = monero_watchtower_mesh_low_fee_lane_id(
            &self.sponsor_id,
            &self.asset_id,
            &self.protected_withdrawal_root,
            self.opened_at_height,
        );
        if self.lane_id != expected {
            return Err("low fee lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerMeshPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
    pub disclosure_level: String,
}

impl MoneroWatchtowerMeshPublicRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
        disclosure_level: &str,
    ) -> MoneroWatchtowerMeshResult<Self> {
        ensure_non_empty(subject_id, "public record subject id")?;
        ensure_non_empty(subject_root, "public record subject root")?;
        ensure_non_empty(disclosure_level, "public record disclosure level")?;
        let payload_root = monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-PUBLIC-RECORD-PAYLOAD",
            payload,
        );
        let record_id = monero_watchtower_mesh_public_record_id(
            record_kind,
            subject_id,
            subject_root,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        Ok(Self {
            record_id,
            record_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
            disclosure_level: disclosure_level.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_watchtower_mesh_public_record",
            "schema": MONERO_WATCHTOWER_MESH_PUBLIC_RECORD_SCHEMA,
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
            "disclosure_level": self.disclosure_level,
        })
    }

    pub fn record_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-PUBLIC-RECORD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "public record subject id")?;
        ensure_non_empty(&self.subject_root, "public record subject root")?;
        let expected = monero_watchtower_mesh_public_record_id(
            self.record_kind,
            &self.subject_id,
            &self.subject_root,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerMeshCounters {
    pub height: u64,
    pub watcher_count: u64,
    pub active_watcher_count: u64,
    pub daemon_observation_count: u64,
    pub fresh_daemon_observation_count: u64,
    pub finality_alarm_count: u64,
    pub active_finality_alarm_count: u64,
    pub reserve_cross_check_count: u64,
    pub divergent_reserve_check_count: u64,
    pub withdrawal_release_count: u64,
    pub delayed_withdrawal_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub failure_report_count: u64,
    pub active_failure_report_count: u64,
    pub fee_recommendation_count: u64,
    pub active_fee_recommendation_count: u64,
    pub alert_envelope_count: u64,
    pub unacknowledged_alert_count: u64,
    pub reputation_record_count: u64,
    pub slashing_record_count: u64,
    pub open_slashing_record_count: u64,
    pub executed_slash_count: u64,
    pub low_fee_lane_count: u64,
    pub open_low_fee_lane_count: u64,
    pub low_fee_reserved_budget_piconero: u64,
    pub low_fee_remaining_budget_piconero: u64,
    pub public_record_count: u64,
}

impl MoneroWatchtowerMeshCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_watchtower_mesh_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "height": self.height,
            "watcher_count": self.watcher_count,
            "active_watcher_count": self.active_watcher_count,
            "daemon_observation_count": self.daemon_observation_count,
            "fresh_daemon_observation_count": self.fresh_daemon_observation_count,
            "finality_alarm_count": self.finality_alarm_count,
            "active_finality_alarm_count": self.active_finality_alarm_count,
            "reserve_cross_check_count": self.reserve_cross_check_count,
            "divergent_reserve_check_count": self.divergent_reserve_check_count,
            "withdrawal_release_count": self.withdrawal_release_count,
            "delayed_withdrawal_count": self.delayed_withdrawal_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "failure_report_count": self.failure_report_count,
            "active_failure_report_count": self.active_failure_report_count,
            "fee_recommendation_count": self.fee_recommendation_count,
            "active_fee_recommendation_count": self.active_fee_recommendation_count,
            "alert_envelope_count": self.alert_envelope_count,
            "unacknowledged_alert_count": self.unacknowledged_alert_count,
            "reputation_record_count": self.reputation_record_count,
            "slashing_record_count": self.slashing_record_count,
            "open_slashing_record_count": self.open_slashing_record_count,
            "executed_slash_count": self.executed_slash_count,
            "low_fee_lane_count": self.low_fee_lane_count,
            "open_low_fee_lane_count": self.open_low_fee_lane_count,
            "low_fee_reserved_budget_piconero": self.low_fee_reserved_budget_piconero,
            "low_fee_remaining_budget_piconero": self.low_fee_remaining_budget_piconero,
            "public_record_count": self.public_record_count,
            "counters_root": self.counters_root(),
        })
    }

    pub fn counters_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-COUNTERS",
            &json!({
                "height": self.height,
                "watcher_count": self.watcher_count,
                "active_watcher_count": self.active_watcher_count,
                "daemon_observation_count": self.daemon_observation_count,
                "finality_alarm_count": self.finality_alarm_count,
                "reserve_cross_check_count": self.reserve_cross_check_count,
                "withdrawal_release_count": self.withdrawal_release_count,
                "pq_attestation_count": self.pq_attestation_count,
                "failure_report_count": self.failure_report_count,
                "fee_recommendation_count": self.fee_recommendation_count,
                "alert_envelope_count": self.alert_envelope_count,
                "reputation_record_count": self.reputation_record_count,
                "slashing_record_count": self.slashing_record_count,
                "low_fee_lane_count": self.low_fee_lane_count,
                "public_record_count": self.public_record_count,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerMeshRoots {
    pub config_root: String,
    pub watcher_root: String,
    pub daemon_observation_root: String,
    pub finality_alarm_root: String,
    pub reserve_cross_check_root: String,
    pub withdrawal_release_root: String,
    pub pq_attestation_root: String,
    pub failure_report_root: String,
    pub fee_bump_recommendation_root: String,
    pub alert_envelope_root: String,
    pub reputation_root: String,
    pub slashing_root: String,
    pub low_fee_lane_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl MoneroWatchtowerMeshRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_watchtower_mesh_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "watcher_root": self.watcher_root,
            "daemon_observation_root": self.daemon_observation_root,
            "finality_alarm_root": self.finality_alarm_root,
            "reserve_cross_check_root": self.reserve_cross_check_root,
            "withdrawal_release_root": self.withdrawal_release_root,
            "pq_attestation_root": self.pq_attestation_root,
            "failure_report_root": self.failure_report_root,
            "fee_bump_recommendation_root": self.fee_bump_recommendation_root,
            "alert_envelope_root": self.alert_envelope_root,
            "reputation_root": self.reputation_root,
            "slashing_root": self.slashing_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_state_root(),
            "state_root",
            self.state_root.clone(),
        )
    }

    pub fn roots_root(&self) -> String {
        monero_watchtower_mesh_payload_root(
            "MONERO-WATCHTOWER-MESH-ROOTS",
            &self.public_record_without_state_root(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerMeshState {
    pub height: u64,
    pub network: String,
    pub config: MoneroWatchtowerMeshConfig,
    pub current_finality_alarm_id: String,
    pub current_reserve_check_id: String,
    pub watchers: BTreeMap<String, WatcherIdentity>,
    pub daemon_observations: BTreeMap<String, DaemonObservation>,
    pub finality_alarms: BTreeMap<String, FinalityAlarm>,
    pub reserve_cross_checks: BTreeMap<String, ReserveProofCrossCheck>,
    pub withdrawal_releases: BTreeMap<String, WithdrawalReleaseSurveillance>,
    pub pq_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub failure_reports: BTreeMap<String, CensorshipFailureReport>,
    pub fee_bump_recommendations: BTreeMap<String, FeeBumpRecommendation>,
    pub alert_envelopes: BTreeMap<String, EncryptedOperatorAlertEnvelope>,
    pub reputation_records: BTreeMap<String, WatcherReputationRecord>,
    pub slashing_records: BTreeMap<String, WatchtowerSlashingRecord>,
    pub low_fee_lanes: BTreeMap<String, LowFeeProtectionLane>,
    pub public_records: BTreeMap<String, MoneroWatchtowerMeshPublicRecord>,
}

impl MoneroWatchtowerMeshState {
    pub fn new(config: MoneroWatchtowerMeshConfig) -> MoneroWatchtowerMeshResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            network: config.network.clone(),
            config,
            current_finality_alarm_id: String::new(),
            current_reserve_check_id: String::new(),
            watchers: BTreeMap::new(),
            daemon_observations: BTreeMap::new(),
            finality_alarms: BTreeMap::new(),
            reserve_cross_checks: BTreeMap::new(),
            withdrawal_releases: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            failure_reports: BTreeMap::new(),
            fee_bump_recommendations: BTreeMap::new(),
            alert_envelopes: BTreeMap::new(),
            reputation_records: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            low_fee_lanes: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> MoneroWatchtowerMeshResult<Self> {
        let mut state = Self::new(MoneroWatchtowerMeshConfig::default())?;
        state.set_height(128);

        let watcher_a = WatcherIdentity::new(
            "devnet-watchtower-alpha",
            MeshWatcherRole::DaemonObserver,
            &state.network,
            "in-process://monero/alpha/rpc",
            "devnet-zone-a",
            "devnet-watchtower-alpha-pq-key",
            "devnet-watchtower-alpha-alert-key",
            1_000_000,
            MONERO_WATCHTOWER_MESH_DEFAULT_REPUTATION_SCORE,
            state.height,
            &[
                "independent_daemon".to_string(),
                "no_shared_rpc".to_string(),
            ],
        )?;
        let watcher_b = WatcherIdentity::new(
            "devnet-watchtower-beta",
            MeshWatcherRole::ReserveAuditor,
            &state.network,
            "in-process://monero/beta/rpc",
            "devnet-zone-b",
            "devnet-watchtower-beta-pq-key",
            "devnet-watchtower-beta-alert-key",
            1_000_000,
            8_750,
            state.height,
            &[
                "reserve_cross_check".to_string(),
                "audit_mirror".to_string(),
            ],
        )?;
        let watcher_c = WatcherIdentity::new(
            "devnet-watchtower-gamma",
            MeshWatcherRole::ReleaseGuard,
            &state.network,
            "in-process://monero/gamma/rpc",
            "devnet-zone-c",
            "devnet-watchtower-gamma-pq-key",
            "devnet-watchtower-gamma-alert-key",
            1_000_000,
            8_250,
            state.height,
            &[
                "withdrawal_release_guard".to_string(),
                "fee_sentinel".to_string(),
            ],
        )?;
        state.register_watcher(watcher_a.clone())?;
        state.register_watcher(watcher_b.clone())?;
        state.register_watcher(watcher_c.clone())?;

        let observation_a = state.record_daemon_observation(
            &watcher_a.watcher_id,
            "devnet-daemon-alpha",
            "in-process://monero/alpha/rpc",
            128,
            "devnet-block-128",
            "devnet-block-127",
            128,
            "devnet-tx-pool-root-a",
            3,
            "devnet-cumulative-difficulty-root",
            18,
        )?;
        let observation_b = state.record_daemon_observation(
            &watcher_b.watcher_id,
            "devnet-daemon-beta",
            "in-process://monero/beta/rpc",
            128,
            "devnet-block-128",
            "devnet-block-127",
            128,
            "devnet-tx-pool-root-b",
            2,
            "devnet-cumulative-difficulty-root",
            22,
        )?;
        let watcher_quorum_root = monero_watchtower_mesh_string_set_root(
            "MONERO-WATCHTOWER-MESH-DEVNET-QUORUM",
            &[watcher_a.watcher_id.clone(), watcher_b.watcher_id.clone()],
        );
        let observation_root = merkle_root(
            "MONERO-WATCHTOWER-MESH-DEVNET-OBSERVATIONS",
            &[observation_a.public_record(), observation_b.public_record()],
        );
        let _reserve_check = state.cross_check_reserve_proof(
            "devnet-reserve-epoch-128",
            "devnet-reserve-proof-root",
            &observation_root,
            "devnet-key-image-root",
            "devnet-output-commitment-root",
            1_250_000_000_000,
            1_000_000_000_000,
            &watcher_quorum_root,
        )?;
        let release = state.track_withdrawal_release(
            "devnet-withdrawal-0",
            "devnet-withdrawal-recipient-0",
            50_000_000_000,
            130,
            70_000_000,
            state.config.low_fee_user_max_fee_piconero,
            &watcher_quorum_root,
            &["low_fee_user_protected".to_string()],
        )?;
        let devnet_asset_id = state.config.asset_id.clone();
        let low_fee_min_share_bps = state.config.low_fee_lane_min_share_bps;
        let low_fee_user_max_fee_piconero = state.config.low_fee_user_max_fee_piconero;
        let lane = state.open_low_fee_lane(
            "devnet-fee-sponsor",
            &devnet_asset_id,
            low_fee_min_share_bps,
            low_fee_user_max_fee_piconero,
            5_000_000_000,
            &[release.withdrawal_id.clone()],
            &[watcher_c.watcher_id.clone()],
            96,
            900_000,
        )?;
        state.recommend_fee_bump(
            &release.release_id,
            &watcher_c.watcher_id,
            FeeBumpAction::EmergencySponsor,
            "devnet low-fee release protected by sponsor lane",
            release.fee_paid_piconero,
            release.min_fee_recommended_piconero,
            7_500,
            6_800,
            Some(lane.lane_id.clone()),
            &release.release_root(),
        )?;
        state.raise_finality_alarm(
            FinalityAlarmKind::DaemonDivergence,
            MeshSeverity::Watch,
            128,
            "devnet-block-128",
            "devnet-shadow-block-128",
            1,
            &observation_root,
            &watcher_quorum_root,
        )?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for watcher in self.watchers.values_mut() {
            if watcher.status.is_live()
                && height.saturating_sub(watcher.last_heartbeat_height)
                    > self.config.observation_staleness_blocks
            {
                watcher.status = MeshWatcherStatus::Degraded;
            }
        }
        for observation in self.daemon_observations.values_mut() {
            observation.status = if height.saturating_sub(observation.observed_at_height)
                > self.config.observation_staleness_blocks
            {
                "stale"
            } else {
                "fresh"
            }
            .to_string();
        }
        for cross_check in self.reserve_cross_checks.values_mut() {
            if cross_check.status == ReserveCheckStatus::Pending
                && height > cross_check.expires_at_height
            {
                cross_check.status = ReserveCheckStatus::Expired;
            }
        }
        for release in self.withdrawal_releases.values_mut() {
            release.last_checked_height = height;
            if release.status.is_open()
                && release.observed_txid_hash.is_none()
                && height
                    > release
                        .expected_release_height
                        .saturating_add(self.config.withdrawal_release_sla_blocks)
            {
                release.status = WithdrawalReleaseStatus::Delayed;
            }
            if let Some(block_height) = release.observed_block_height {
                release.observed_confirmations = confirmations(height, block_height);
                if release.observed_confirmations >= self.config.finality_depth {
                    release.status = WithdrawalReleaseStatus::Confirmed;
                }
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if attestation.status.is_active() && height > attestation.expires_at_height {
                attestation.status = AttestationStatus::Expired;
            }
        }
        for recommendation in self.fee_bump_recommendations.values_mut() {
            if recommendation.status == "open" && height > recommendation.expires_at_height {
                recommendation.status = "expired".to_string();
            }
        }
        for envelope in self.alert_envelopes.values_mut() {
            if envelope.status.awaiting_ack() && height > envelope.expires_at_height {
                envelope.status = AlertEnvelopeStatus::Expired;
            }
        }
        for lane in self.low_fee_lanes.values_mut() {
            if lane.status.accepts_users() && height > lane.expires_at_height {
                lane.status = LowFeeLaneStatus::Expired;
            } else if lane.remaining_budget_piconero() == 0 && lane.status.accepts_users() {
                lane.status = LowFeeLaneStatus::Draining;
            }
        }
    }

    pub fn register_watcher(&mut self, watcher: WatcherIdentity) -> MoneroWatchtowerMeshResult<()> {
        if watcher.network != self.network {
            return Err("watcher network mismatch".to_string());
        }
        watcher.validate()?;
        insert_unique_record(
            &mut self.watchers,
            watcher.watcher_id.clone(),
            watcher,
            "watcher",
        )
    }

    pub fn record_watcher_heartbeat(&mut self, watcher_id: &str) -> MoneroWatchtowerMeshResult<()> {
        let watcher = self
            .watchers
            .get_mut(watcher_id)
            .ok_or_else(|| "unknown watchtower watcher".to_string())?;
        watcher.set_heartbeat(self.height);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_daemon_observation(
        &mut self,
        watcher_id: &str,
        daemon_label: &str,
        endpoint_label: &str,
        block_height: u64,
        block_hash: &str,
        previous_block_hash: &str,
        top_height: u64,
        tx_pool_hash: &str,
        mempool_tx_count: u64,
        cumulative_difficulty_root: &str,
        latency_ms: u64,
    ) -> MoneroWatchtowerMeshResult<DaemonObservation> {
        let watcher = self.require_watcher(watcher_id)?;
        let mut observation = DaemonObservation::new(
            watcher_id,
            daemon_label,
            endpoint_label,
            block_height,
            block_hash,
            previous_block_hash,
            top_height,
            tx_pool_hash,
            mempool_tx_count,
            cumulative_difficulty_root,
            self.height,
            latency_ms,
        )?;
        let attestation = self.attest_subject(
            watcher_id,
            PqAttestationSubjectKind::DaemonObservation,
            &observation.observation_id,
            &observation.observation_root(),
            &watcher.pq_public_key_commitment,
            "daemon-observation",
            self.config.reserve_cross_check_ttl_blocks,
            1,
        )?;
        observation.attestation_id = attestation.attestation_id;
        self.daemon_observations
            .insert(observation.observation_id.clone(), observation.clone());
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn raise_finality_alarm(
        &mut self,
        kind: FinalityAlarmKind,
        severity: MeshSeverity,
        block_height: u64,
        canonical_block_hash: &str,
        conflicting_block_hash: &str,
        reorg_depth: u64,
        observation_root: &str,
        watcher_quorum_root: &str,
    ) -> MoneroWatchtowerMeshResult<FinalityAlarm> {
        let mut alarm = FinalityAlarm::new(
            kind,
            severity,
            &self.network,
            block_height,
            canonical_block_hash,
            conflicting_block_hash,
            reorg_depth,
            observation_root,
            watcher_quorum_root,
            self.height,
        )?;
        if reorg_depth >= self.config.reorg_alarm_depth {
            alarm.status = AlarmStatus::QuorumConfirmed;
        }
        self.current_finality_alarm_id = alarm.alarm_id.clone();
        self.finality_alarms
            .insert(alarm.alarm_id.clone(), alarm.clone());
        Ok(alarm)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cross_check_reserve_proof(
        &mut self,
        reserve_epoch_id: &str,
        reserve_proof_root: &str,
        daemon_observation_root: &str,
        key_image_root: &str,
        output_commitment_root: &str,
        reported_reserve_piconero_bucket: u64,
        expected_liability_piconero_bucket: u64,
        watchers_root: &str,
    ) -> MoneroWatchtowerMeshResult<ReserveProofCrossCheck> {
        let check = ReserveProofCrossCheck::new(
            reserve_epoch_id,
            reserve_proof_root,
            daemon_observation_root,
            key_image_root,
            output_commitment_root,
            reported_reserve_piconero_bucket,
            expected_liability_piconero_bucket,
            watchers_root,
            self.height,
            self.config.reserve_cross_check_ttl_blocks,
        )?;
        self.current_reserve_check_id = check.check_id.clone();
        self.reserve_cross_checks
            .insert(check.check_id.clone(), check.clone());
        Ok(check)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn track_withdrawal_release(
        &mut self,
        withdrawal_id: &str,
        recipient_label: &str,
        amount_bucket_piconero: u64,
        expected_release_height: u64,
        fee_paid_piconero: u64,
        min_fee_recommended_piconero: u64,
        watcher_root: &str,
        risk_flags: &[String],
    ) -> MoneroWatchtowerMeshResult<WithdrawalReleaseSurveillance> {
        let release = WithdrawalReleaseSurveillance::new(
            withdrawal_id,
            recipient_label,
            amount_bucket_piconero,
            expected_release_height,
            fee_paid_piconero,
            min_fee_recommended_piconero,
            watcher_root,
            self.height,
            risk_flags,
        )?;
        self.withdrawal_releases
            .insert(release.release_id.clone(), release.clone());
        Ok(release)
    }

    pub fn mark_withdrawal_observed(
        &mut self,
        release_id: &str,
        txid_hash: &str,
        block_height: u64,
    ) -> MoneroWatchtowerMeshResult<()> {
        ensure_non_empty(txid_hash, "withdrawal release txid hash")?;
        let release = self
            .withdrawal_releases
            .get_mut(release_id)
            .ok_or_else(|| "unknown withdrawal release surveillance".to_string())?;
        release.mark_observed(txid_hash, block_height, self.height);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attest_subject(
        &mut self,
        watcher_id: &str,
        subject_kind: PqAttestationSubjectKind,
        subject_id: &str,
        subject_root: &str,
        public_key_commitment: &str,
        transcript_label: &str,
        ttl_blocks: u64,
        weight: u64,
    ) -> MoneroWatchtowerMeshResult<PqWatcherAttestation> {
        self.require_watcher(watcher_id)?;
        let attestation = PqWatcherAttestation::new(
            watcher_id,
            subject_kind,
            subject_id,
            subject_root,
            public_key_commitment,
            transcript_label,
            self.height,
            ttl_blocks,
            weight,
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn file_failure_report(
        &mut self,
        kind: FailureReportKind,
        severity: MeshSeverity,
        reporter_watcher_id: &str,
        accused_operator_id: &str,
        subject_id: &str,
        evidence_root: &str,
        missed_blocks: u64,
        watcher_quorum_root: &str,
        mitigation_notes: &[String],
    ) -> MoneroWatchtowerMeshResult<CensorshipFailureReport> {
        self.require_watcher(reporter_watcher_id)?;
        let report = CensorshipFailureReport::new(
            kind,
            severity,
            reporter_watcher_id,
            accused_operator_id,
            subject_id,
            evidence_root,
            self.height,
            self.height,
            missed_blocks,
            watcher_quorum_root,
            mitigation_notes,
        )?;
        self.failure_reports
            .insert(report.report_id.clone(), report.clone());
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn recommend_fee_bump(
        &mut self,
        release_id: &str,
        watcher_id: &str,
        action: FeeBumpAction,
        reason: &str,
        current_fee_piconero: u64,
        recommended_fee_piconero: u64,
        urgency_bps: u64,
        mempool_pressure_bps: u64,
        low_fee_lane_id: Option<String>,
        evidence_root: &str,
    ) -> MoneroWatchtowerMeshResult<FeeBumpRecommendation> {
        self.require_watcher(watcher_id)?;
        if !self.withdrawal_releases.contains_key(release_id) {
            return Err("fee bump recommendation references unknown release".to_string());
        }
        if let Some(lane_id) = &low_fee_lane_id {
            if !self.low_fee_lanes.contains_key(lane_id) {
                return Err("fee bump recommendation references unknown low fee lane".to_string());
            }
        }
        let recommendation = FeeBumpRecommendation::new(
            release_id,
            watcher_id,
            action,
            reason,
            current_fee_piconero,
            recommended_fee_piconero,
            urgency_bps,
            mempool_pressure_bps,
            low_fee_lane_id,
            evidence_root,
            self.height,
            self.config.alert_ttl_blocks,
        )?;
        self.fee_bump_recommendations.insert(
            recommendation.recommendation_id.clone(),
            recommendation.clone(),
        );
        Ok(recommendation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal_operator_alert(
        &mut self,
        audience: OperatorAlertAudience,
        recipient_label: &str,
        severity: MeshSeverity,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload_ciphertext_root: &str,
        routing_hint: &str,
        attestation_root: &str,
    ) -> MoneroWatchtowerMeshResult<EncryptedOperatorAlertEnvelope> {
        let envelope = EncryptedOperatorAlertEnvelope::new(
            audience,
            recipient_label,
            severity,
            subject_kind,
            subject_id,
            subject_root,
            payload_ciphertext_root,
            routing_hint,
            attestation_root,
            self.height,
            self.config.alert_ttl_blocks,
        )?;
        self.alert_envelopes
            .insert(envelope.envelope_id.clone(), envelope.clone());
        Ok(envelope)
    }

    pub fn update_reputation_success(
        &mut self,
        watcher_id: &str,
        reward_score: u64,
    ) -> MoneroWatchtowerMeshResult<WatcherReputationRecord> {
        self.require_watcher(watcher_id)?;
        if !self.reputation_records.contains_key(watcher_id) {
            let record = WatcherReputationRecord::new(
                watcher_id,
                MONERO_WATCHTOWER_MESH_DEFAULT_REPUTATION_SCORE,
                self.height,
                &self.watcher_root(),
            )?;
            self.reputation_records
                .insert(watcher_id.to_string(), record);
        }
        let record = self
            .reputation_records
            .get_mut(watcher_id)
            .ok_or_else(|| "missing watcher reputation after insert".to_string())?;
        record.apply_success(reward_score, self.height);
        if let Some(watcher) = self.watchers.get_mut(watcher_id) {
            watcher.reputation_score = record.current_score;
            watcher.status = record.status;
        }
        Ok(record.clone())
    }

    pub fn update_reputation_miss(
        &mut self,
        watcher_id: &str,
        penalty_score: u64,
    ) -> MoneroWatchtowerMeshResult<WatcherReputationRecord> {
        self.require_watcher(watcher_id)?;
        if !self.reputation_records.contains_key(watcher_id) {
            let record = WatcherReputationRecord::new(
                watcher_id,
                MONERO_WATCHTOWER_MESH_DEFAULT_REPUTATION_SCORE,
                self.height,
                &self.watcher_root(),
            )?;
            self.reputation_records
                .insert(watcher_id.to_string(), record);
        }
        let record = self
            .reputation_records
            .get_mut(watcher_id)
            .ok_or_else(|| "missing watcher reputation after insert".to_string())?;
        record.apply_miss(penalty_score, self.height);
        if let Some(watcher) = self.watchers.get_mut(watcher_id) {
            watcher.reputation_score = record.current_score;
            watcher.status = record.status;
        }
        Ok(record.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_slashing_record(
        &mut self,
        watcher_id: &str,
        reason: SlashReason,
        evidence_root: &str,
        slash_units: u64,
        slash_bps: u64,
        attestation_root: &str,
    ) -> MoneroWatchtowerMeshResult<WatchtowerSlashingRecord> {
        self.require_watcher(watcher_id)?;
        let slash = WatchtowerSlashingRecord::new(
            watcher_id,
            reason,
            evidence_root,
            slash_units,
            slash_bps,
            self.height,
            self.config.slashing_window_blocks,
            attestation_root,
        )?;
        if let Some(watcher) = self.watchers.get_mut(watcher_id) {
            watcher.slashed_units = watcher.slashed_units.saturating_add(slash_units);
            watcher.status = MeshWatcherStatus::Suspended;
        }
        self.slashing_records
            .insert(slash.slash_id.clone(), slash.clone());
        Ok(slash)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_low_fee_lane(
        &mut self,
        sponsor_id: &str,
        asset_id: &str,
        min_share_bps: u64,
        max_user_fee_piconero: u64,
        reserved_budget_piconero: u64,
        protected_withdrawal_ids: &[String],
        watcher_ids: &[String],
        ttl_blocks: u64,
        priority_score: u64,
    ) -> MoneroWatchtowerMeshResult<LowFeeProtectionLane> {
        for watcher_id in watcher_ids {
            self.require_watcher(watcher_id)?;
        }
        let lane = LowFeeProtectionLane::new(
            sponsor_id,
            asset_id,
            min_share_bps,
            max_user_fee_piconero,
            reserved_budget_piconero,
            protected_withdrawal_ids,
            watcher_ids,
            self.height,
            ttl_blocks,
            priority_score,
        )?;
        self.low_fee_lanes
            .insert(lane.lane_id.clone(), lane.clone());
        Ok(lane)
    }

    pub fn emit_public_record(
        &mut self,
        record_kind: PublicRecordKind,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        disclosure_level: &str,
    ) -> MoneroWatchtowerMeshResult<MoneroWatchtowerMeshPublicRecord> {
        let sequence = self.public_records.len() as u64;
        let record = MoneroWatchtowerMeshPublicRecord::new(
            record_kind,
            subject_id,
            subject_root,
            payload,
            self.height,
            sequence,
            disclosure_level,
        )?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn watcher_root(&self) -> String {
        monero_watchtower_mesh_watcher_collection_root(
            &self.watchers.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn daemon_observation_root(&self) -> String {
        monero_watchtower_mesh_daemon_observation_collection_root(
            &self
                .daemon_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn finality_alarm_root(&self) -> String {
        monero_watchtower_mesh_finality_alarm_collection_root(
            &self.finality_alarms.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reserve_cross_check_root(&self) -> String {
        monero_watchtower_mesh_reserve_cross_check_collection_root(
            &self
                .reserve_cross_checks
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn withdrawal_release_root(&self) -> String {
        monero_watchtower_mesh_withdrawal_release_collection_root(
            &self
                .withdrawal_releases
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        monero_watchtower_mesh_pq_attestation_collection_root(
            &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn failure_report_root(&self) -> String {
        monero_watchtower_mesh_failure_report_collection_root(
            &self.failure_reports.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn fee_bump_recommendation_root(&self) -> String {
        monero_watchtower_mesh_fee_bump_recommendation_collection_root(
            &self
                .fee_bump_recommendations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn alert_envelope_root(&self) -> String {
        monero_watchtower_mesh_alert_envelope_collection_root(
            &self.alert_envelopes.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reputation_root(&self) -> String {
        monero_watchtower_mesh_reputation_collection_root(
            &self
                .reputation_records
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn slashing_root(&self) -> String {
        monero_watchtower_mesh_slashing_collection_root(
            &self.slashing_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_lane_root(&self) -> String {
        monero_watchtower_mesh_low_fee_lane_collection_root(
            &self.low_fee_lanes.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        monero_watchtower_mesh_public_record_collection_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn counters(&self) -> MoneroWatchtowerMeshCounters {
        MoneroWatchtowerMeshCounters {
            height: self.height,
            watcher_count: self.watchers.len() as u64,
            active_watcher_count: self
                .watchers
                .values()
                .filter(|watcher| watcher.status.is_live())
                .count() as u64,
            daemon_observation_count: self.daemon_observations.len() as u64,
            fresh_daemon_observation_count: self
                .daemon_observations
                .values()
                .filter(|observation| observation.status == "fresh")
                .count() as u64,
            finality_alarm_count: self.finality_alarms.len() as u64,
            active_finality_alarm_count: self
                .finality_alarms
                .values()
                .filter(|alarm| alarm.status.is_active())
                .count() as u64,
            reserve_cross_check_count: self.reserve_cross_checks.len() as u64,
            divergent_reserve_check_count: self
                .reserve_cross_checks
                .values()
                .filter(|check| check.status.needs_alarm())
                .count() as u64,
            withdrawal_release_count: self.withdrawal_releases.len() as u64,
            delayed_withdrawal_count: self
                .withdrawal_releases
                .values()
                .filter(|release| release.status.needs_operator_attention())
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.is_active())
                .count() as u64,
            failure_report_count: self.failure_reports.len() as u64,
            active_failure_report_count: self
                .failure_reports
                .values()
                .filter(|report| report.status.is_active())
                .count() as u64,
            fee_recommendation_count: self.fee_bump_recommendations.len() as u64,
            active_fee_recommendation_count: self
                .fee_bump_recommendations
                .values()
                .filter(|recommendation| recommendation.status == "open")
                .count() as u64,
            alert_envelope_count: self.alert_envelopes.len() as u64,
            unacknowledged_alert_count: self
                .alert_envelopes
                .values()
                .filter(|envelope| envelope.status.awaiting_ack())
                .count() as u64,
            reputation_record_count: self.reputation_records.len() as u64,
            slashing_record_count: self.slashing_records.len() as u64,
            open_slashing_record_count: self
                .slashing_records
                .values()
                .filter(|record| record.status.is_open())
                .count() as u64,
            executed_slash_count: self
                .slashing_records
                .values()
                .filter(|record| record.status == SlashingStatus::Executed)
                .count() as u64,
            low_fee_lane_count: self.low_fee_lanes.len() as u64,
            open_low_fee_lane_count: self
                .low_fee_lanes
                .values()
                .filter(|lane| lane.status.accepts_users())
                .count() as u64,
            low_fee_reserved_budget_piconero: self
                .low_fee_lanes
                .values()
                .map(|lane| lane.reserved_budget_piconero)
                .sum(),
            low_fee_remaining_budget_piconero: self
                .low_fee_lanes
                .values()
                .map(LowFeeProtectionLane::remaining_budget_piconero)
                .sum(),
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn roots(&self) -> MoneroWatchtowerMeshRoots {
        let counters = self.counters();
        let mut roots = MoneroWatchtowerMeshRoots {
            config_root: self.config.config_root(),
            watcher_root: self.watcher_root(),
            daemon_observation_root: self.daemon_observation_root(),
            finality_alarm_root: self.finality_alarm_root(),
            reserve_cross_check_root: self.reserve_cross_check_root(),
            withdrawal_release_root: self.withdrawal_release_root(),
            pq_attestation_root: self.pq_attestation_root(),
            failure_report_root: self.failure_report_root(),
            fee_bump_recommendation_root: self.fee_bump_recommendation_root(),
            alert_envelope_root: self.alert_envelope_root(),
            reputation_root: self.reputation_root(),
            slashing_root: self.slashing_root(),
            low_fee_lane_root: self.low_fee_lane_root(),
            public_record_root: self.public_record_root(),
            counters_root: counters.counters_root(),
            state_root: String::new(),
        };
        let record = self.public_record_without_state_root(&roots);
        roots.state_root = monero_watchtower_mesh_state_root_from_record(&record);
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        with_root_field(
            self.public_record_without_state_root(&roots),
            "state_root",
            roots.state_root,
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerMeshResult<String> {
        self.config.validate()?;
        ensure_non_empty(&self.network, "watchtower mesh network")?;
        if self.network != self.config.network {
            return Err("watchtower mesh network mismatch".to_string());
        }
        if !self.current_finality_alarm_id.is_empty()
            && !self
                .finality_alarms
                .contains_key(&self.current_finality_alarm_id)
        {
            return Err("current finality alarm id is unknown".to_string());
        }
        if !self.current_reserve_check_id.is_empty()
            && !self
                .reserve_cross_checks
                .contains_key(&self.current_reserve_check_id)
        {
            return Err("current reserve check id is unknown".to_string());
        }
        validate_map(&self.watchers, |watcher| watcher.validate(), "watcher")?;
        validate_map(
            &self.daemon_observations,
            |observation| observation.validate(),
            "daemon observation",
        )?;
        validate_map(
            &self.finality_alarms,
            |alarm| alarm.validate(),
            "finality alarm",
        )?;
        validate_map(
            &self.reserve_cross_checks,
            |check| check.validate(),
            "reserve cross-check",
        )?;
        validate_map(
            &self.withdrawal_releases,
            |release| release.validate(),
            "withdrawal release",
        )?;
        validate_map(
            &self.pq_attestations,
            |attestation| attestation.validate(),
            "pq watcher attestation",
        )?;
        validate_map(
            &self.failure_reports,
            |report| report.validate(),
            "failure report",
        )?;
        validate_map(
            &self.fee_bump_recommendations,
            |recommendation| recommendation.validate(),
            "fee bump recommendation",
        )?;
        validate_map(
            &self.alert_envelopes,
            |envelope| envelope.validate(),
            "alert envelope",
        )?;
        validate_map(
            &self.reputation_records,
            |record| record.validate(),
            "reputation record",
        )?;
        validate_map(
            &self.slashing_records,
            |record| record.validate(),
            "slashing record",
        )?;
        validate_map(&self.low_fee_lanes, |lane| lane.validate(), "low fee lane")?;
        validate_map(
            &self.public_records,
            |record| record.validate(),
            "public record",
        )?;
        for observation in self.daemon_observations.values() {
            if !self.watchers.contains_key(&observation.watcher_id) {
                return Err("daemon observation references unknown watcher".to_string());
            }
        }
        for attestation in self.pq_attestations.values() {
            if !self.watchers.contains_key(&attestation.watcher_id) {
                return Err("pq attestation references unknown watcher".to_string());
            }
        }
        for report in self.failure_reports.values() {
            if !self.watchers.contains_key(&report.reporter_watcher_id) {
                return Err("failure report references unknown reporter watcher".to_string());
            }
        }
        for recommendation in self.fee_bump_recommendations.values() {
            if !self.watchers.contains_key(&recommendation.watcher_id) {
                return Err("fee bump recommendation references unknown watcher".to_string());
            }
            if !self
                .withdrawal_releases
                .contains_key(&recommendation.release_id)
            {
                return Err("fee bump recommendation references unknown withdrawal".to_string());
            }
        }
        for record in self.reputation_records.values() {
            if !self.watchers.contains_key(&record.watcher_id) {
                return Err("reputation record references unknown watcher".to_string());
            }
        }
        for record in self.slashing_records.values() {
            if !self.watchers.contains_key(&record.watcher_id) {
                return Err("slashing record references unknown watcher".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self, roots: &MoneroWatchtowerMeshRoots) -> Value {
        let counters = self.counters();
        json!({
            "kind": "monero_watchtower_mesh_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION,
            "height": self.height,
            "network": self.network,
            "current_finality_alarm_id": self.current_finality_alarm_id,
            "current_reserve_check_id": self.current_reserve_check_id,
            "config": self.config.public_record(),
            "roots": roots.public_record_without_state_root(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    fn require_watcher(&self, watcher_id: &str) -> MoneroWatchtowerMeshResult<WatcherIdentity> {
        self.watchers
            .get(watcher_id)
            .cloned()
            .ok_or_else(|| "unknown watchtower watcher".to_string())
    }
}

pub fn monero_watchtower_mesh_state_root_from_record(record: &Value) -> String {
    monero_watchtower_mesh_payload_root("MONERO-WATCHTOWER-MESH-STATE", record)
}

pub fn monero_watchtower_mesh_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(MONERO_WATCHTOWER_MESH_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_string_set_root(domain: &str, values: &[String]) -> String {
    let mut ordered = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    merkle_root(domain, &ordered)
}

pub fn monero_watchtower_mesh_watcher_id(
    operator_label: &str,
    role: MeshWatcherRole,
    network: &str,
    daemon_endpoint_commitment: &str,
    pq_public_key_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-WATCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(role.as_str()),
            HashPart::Str(network),
            HashPart::Str(daemon_endpoint_commitment),
            HashPart::Str(pq_public_key_commitment),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_daemon_observation_id(
    watcher_id: &str,
    daemon_label: &str,
    block_height: u64,
    block_hash: &str,
    endpoint_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-DAEMON-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(daemon_label),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(endpoint_commitment),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_finality_alarm_id(
    kind: FinalityAlarmKind,
    network: &str,
    block_height: u64,
    canonical_block_hash: &str,
    conflicting_block_hash: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-FINALITY-ALARM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(network),
            HashPart::Int(block_height as i128),
            HashPart::Str(canonical_block_hash),
            HashPart::Str(conflicting_block_hash),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_reserve_cross_check_id(
    reserve_epoch_id: &str,
    reserve_proof_root: &str,
    daemon_observation_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-RESERVE-CROSS-CHECK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reserve_epoch_id),
            HashPart::Str(reserve_proof_root),
            HashPart::Str(daemon_observation_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_withdrawal_release_id(
    withdrawal_id: &str,
    recipient_commitment: &str,
    amount_bucket_piconero: u64,
    expected_release_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-WITHDRAWAL-RELEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(recipient_commitment),
            HashPart::Int(amount_bucket_piconero as i128),
            HashPart::Int(expected_release_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_pq_attestation_id(
    watcher_id: &str,
    subject_kind: PqAttestationSubjectKind,
    subject_id: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(subject_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_signature_commitment(
    watcher_id: &str,
    subject_kind: PqAttestationSubjectKind,
    subject_id: &str,
    subject_root: &str,
    transcript_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-PQ-SIGNATURE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCHTOWER_MESH_PQ_ATTESTATION_SCHEME),
            HashPart::Str(watcher_id),
            HashPart::Str(subject_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(transcript_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_failure_report_id(
    kind: FailureReportKind,
    reporter_watcher_id: &str,
    accused_operator_id: &str,
    subject_id: &str,
    evidence_root: &str,
    first_seen_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-FAILURE-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(reporter_watcher_id),
            HashPart::Str(accused_operator_id),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::Int(first_seen_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_fee_bump_recommendation_id(
    release_id: &str,
    watcher_id: &str,
    action: FeeBumpAction,
    recommended_fee_piconero: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-FEE-BUMP-RECOMMENDATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(release_id),
            HashPart::Str(watcher_id),
            HashPart::Str(action.as_str()),
            HashPart::Int(recommended_fee_piconero as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_alert_envelope_id(
    audience: OperatorAlertAudience,
    recipient_commitment: &str,
    subject_kind: &str,
    subject_id: &str,
    payload_ciphertext_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-ALERT-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(audience.as_str()),
            HashPart::Str(recipient_commitment),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_ciphertext_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_reputation_id(
    watcher_id: &str,
    starting_score: u64,
    last_update_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-REPUTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Int(starting_score as i128),
            HashPart::Int(last_update_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_slash_id(
    watcher_id: &str,
    reason: SlashReason,
    evidence_root: &str,
    slash_units: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-SLASH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(slash_units as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_low_fee_lane_id(
    sponsor_id: &str,
    asset_id: &str,
    protected_withdrawal_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-LOW-FEE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(asset_id),
            HashPart::Str(protected_withdrawal_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-MESH-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_mesh_watcher_collection_root(records: &[WatcherIdentity]) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-WATCHER-COLLECTION",
        records
            .iter()
            .map(|record| (record.watcher_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_daemon_observation_collection_root(
    records: &[DaemonObservation],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-DAEMON-OBSERVATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.observation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_finality_alarm_collection_root(records: &[FinalityAlarm]) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-FINALITY-ALARM-COLLECTION",
        records
            .iter()
            .map(|record| (record.alarm_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_reserve_cross_check_collection_root(
    records: &[ReserveProofCrossCheck],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-RESERVE-CROSS-CHECK-COLLECTION",
        records
            .iter()
            .map(|record| (record.check_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_withdrawal_release_collection_root(
    records: &[WithdrawalReleaseSurveillance],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-WITHDRAWAL-RELEASE-COLLECTION",
        records
            .iter()
            .map(|record| (record.release_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_pq_attestation_collection_root(
    records: &[PqWatcherAttestation],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-PQ-ATTESTATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.attestation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_failure_report_collection_root(
    records: &[CensorshipFailureReport],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-FAILURE-REPORT-COLLECTION",
        records
            .iter()
            .map(|record| (record.report_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_fee_bump_recommendation_collection_root(
    records: &[FeeBumpRecommendation],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-FEE-BUMP-RECOMMENDATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.recommendation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_alert_envelope_collection_root(
    records: &[EncryptedOperatorAlertEnvelope],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-ALERT-ENVELOPE-COLLECTION",
        records
            .iter()
            .map(|record| (record.envelope_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_reputation_collection_root(
    records: &[WatcherReputationRecord],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-REPUTATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.reputation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_slashing_collection_root(
    records: &[WatchtowerSlashingRecord],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-SLASHING-COLLECTION",
        records
            .iter()
            .map(|record| (record.slash_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_low_fee_lane_collection_root(
    records: &[LowFeeProtectionLane],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-LOW-FEE-LANE-COLLECTION",
        records
            .iter()
            .map(|record| (record.lane_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_watchtower_mesh_public_record_collection_root(
    records: &[MoneroWatchtowerMeshPublicRecord],
) -> String {
    keyed_value_root(
        "MONERO-WATCHTOWER-MESH-PUBLIC-RECORD-COLLECTION",
        records
            .iter()
            .map(|record| (record.record_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let result = (numerator as u128).saturating_mul(MONERO_WATCHTOWER_MESH_MAX_BPS as u128)
        / denominator as u128;
    result.min(u64::MAX as u128) as u64
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn confirmations(current_height: u64, observed_height: u64) -> u64 {
    if current_height >= observed_height {
        current_height
            .saturating_sub(observed_height)
            .saturating_add(1)
    } else {
        0
    }
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroWatchtowerMeshResult<()> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn validate_map<T, F>(
    records: &BTreeMap<String, T>,
    mut validator: F,
    label: &str,
) -> MoneroWatchtowerMeshResult<()>
where
    F: FnMut(&T) -> MoneroWatchtowerMeshResult<String>,
{
    let mut seen_roots = BTreeSet::new();
    for record in records.values() {
        let root = validator(record)?;
        if !seen_roots.insert(root) {
            return Err(format!("{label} contains duplicate root"));
        }
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroWatchtowerMeshResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroWatchtowerMeshResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroWatchtowerMeshResult<()> {
    if value > MONERO_WATCHTOWER_MESH_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}
