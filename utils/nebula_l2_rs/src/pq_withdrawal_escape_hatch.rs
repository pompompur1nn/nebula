use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqWithdrawalEscapeHatchResult<T> = Result<T, String>;

pub const PQ_WITHDRAWAL_ESCAPE_HATCH_PROTOCOL_VERSION: &str =
    "nebula-pq-withdrawal-escape-hatch-v1";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_SCHEMA_VERSION: u64 = 1;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_HEIGHT: u64 = 720;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-192f";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_NULLIFIER_SCHEME: &str =
    "monero-key-image-and-l2-nullifier-binding-v1";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_SPONSOR_SCHEME: &str = "private-low-fee-rescue-sponsorship-v1";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_WATCHER_SCHEME: &str = "pq-liveness-watchtower-attestation-v1";
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_APPROVAL_WINDOW_BLOCKS: u64 = 36;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_EMERGENCY_TIMELOCK_BLOCKS: u64 = 144;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_FAST_TIMELOCK_BLOCKS: u64 = 18;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WITHDRAWAL_TTL_BLOCKS: u64 = 720;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WATCHER_HEARTBEAT_BLOCKS: u64 = 12;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WATCHER_STALE_AFTER_BLOCKS: u64 = 48;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_REPLAY_RETENTION_BLOCKS: u64 = 8_640;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MAX_PENDING_EXITS: usize = 1_024;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MAX_ACTIVE_DISPUTES: usize = 256;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MIN_APPROVAL_WEIGHT_BPS: u64 = 6_700;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_EMERGENCY_APPROVAL_WEIGHT_BPS: u64 = 8_000;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WATCHER_QUORUM_WEIGHT_BPS: u64 = 5_100;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_PRIVACY_FLOOR_BPS: u64 = 9_500;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MAX_SPONSOR_REBATE_UNITS: u64 = 250_000;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MIN_RESCUE_FEE_UNITS: u64 = 1;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_CHALLENGE_BOND_UNITS: u64 = 100_000;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_SLASH_BPS: u64 = 1_000;
pub const PQ_WITHDRAWAL_ESCAPE_HATCH_MAX_BPS: u64 = 10_000;

const STATE_STATUS_BOOTSTRAPPING: &str = "bootstrapping";
const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_DEGRADED: &str = "degraded";
const STATE_STATUS_PAUSED: &str = "paused";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqEscapeHatchAlgorithm {
    MlDsa87,
    SlhDsaShake192f,
    MlKem1024,
    HashTreeTranscript,
    HybridThreshold,
}

impl PqEscapeHatchAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => PQ_WITHDRAWAL_ESCAPE_HATCH_PRIMARY_SIGNATURE_SCHEME,
            Self::SlhDsaShake192f => PQ_WITHDRAWAL_ESCAPE_HATCH_BACKUP_SIGNATURE_SCHEME,
            Self::MlKem1024 => PQ_WITHDRAWAL_ESCAPE_HATCH_KEM_SCHEME,
            Self::HashTreeTranscript => "hash-tree-transcript",
            Self::HybridThreshold => "ml-dsa-slh-dsa-hash-tree-threshold",
        }
    }

    pub fn quantum_resistant(self) -> bool {
        matches!(
            self,
            Self::MlDsa87
                | Self::SlhDsaShake192f
                | Self::MlKem1024
                | Self::HashTreeTranscript
                | Self::HybridThreshold
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeHatchRole {
    Guardian,
    Watcher,
    Challenger,
    Sponsor,
    BridgeOperator,
    PrivacyAuditor,
    SettlementRelayer,
}

impl EscapeHatchRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Guardian => "guardian",
            Self::Watcher => "watcher",
            Self::Challenger => "challenger",
            Self::Sponsor => "sponsor",
            Self::BridgeOperator => "bridge_operator",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::SettlementRelayer => "settlement_relayer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalEscapeKind {
    StandardDelayedExit,
    EmergencyTimelockedExit,
    WatcherTriggeredRescue,
    SponsoredLowFeeRescue,
    DisputeResolvedExit,
    OperatorCensoredExit,
}

impl WithdrawalEscapeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandardDelayedExit => "standard_delayed_exit",
            Self::EmergencyTimelockedExit => "emergency_timelocked_exit",
            Self::WatcherTriggeredRescue => "watcher_triggered_rescue",
            Self::SponsoredLowFeeRescue => "sponsored_low_fee_rescue",
            Self::DisputeResolvedExit => "dispute_resolved_exit",
            Self::OperatorCensoredExit => "operator_censored_exit",
        }
    }

    pub fn requires_emergency_weight(self) -> bool {
        matches!(
            self,
            Self::EmergencyTimelockedExit
                | Self::WatcherTriggeredRescue
                | Self::OperatorCensoredExit
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalEscapeStatus {
    Open,
    ApprovalPending,
    Timelocked,
    ChallengeOpen,
    Challenged,
    Approved,
    RescueSponsored,
    ReadyToSettle,
    Settled,
    Cancelled,
    Rejected,
    Expired,
}

impl WithdrawalEscapeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ApprovalPending => "approval_pending",
            Self::Timelocked => "timelocked",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::Approved => "approved",
            Self::RescueSponsored => "rescue_sponsored",
            Self::ReadyToSettle => "ready_to_settle",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::ApprovalPending
                | Self::Timelocked
                | Self::ChallengeOpen
                | Self::Challenged
                | Self::Approved
                | Self::RescueSponsored
                | Self::ReadyToSettle
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Cancelled | Self::Rejected | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    ThresholdMet,
    Superseded,
    Rejected,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ThresholdMet => "threshold_met",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::ThresholdMet)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockStatus {
    Pending,
    Armed,
    ChallengeOpen,
    Matured,
    Cancelled,
    Expired,
    Executed,
}

impl TimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Armed => "armed",
            Self::ChallengeOpen => "challenge_open",
            Self::Matured => "matured",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Executed => "executed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherStatus {
    Active,
    Stale,
    Suspect,
    Slashed,
    Retired,
}

impl WatcherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Suspect => "suspect",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherSignalKind {
    Heartbeat,
    CensorshipObserved,
    MoneroCongestion,
    ReserveDelay,
    OperatorOffline,
    ExitIncluded,
    ExitMissing,
}

impl WatcherSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Heartbeat => "heartbeat",
            Self::CensorshipObserved => "censorship_observed",
            Self::MoneroCongestion => "monero_congestion",
            Self::ReserveDelay => "reserve_delay",
            Self::OperatorOffline => "operator_offline",
            Self::ExitIncluded => "exit_included",
            Self::ExitMissing => "exit_missing",
        }
    }

    pub fn liveness_alarm(self) -> bool {
        matches!(
            self,
            Self::CensorshipObserved
                | Self::ReserveDelay
                | Self::OperatorOffline
                | Self::ExitMissing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Pledged,
    Reserved,
    Applied,
    Reimbursed,
    Slashed,
    Cancelled,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pledged => "pledged",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reimbursed => "reimbursed",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidPqApproval,
    ReplayedNullifier,
    MoneroKeyImageSeen,
    WrongRecipientCommitment,
    TimelockNotMature,
    MissingWatcherSignal,
    SponsorFraud,
    PrivacyLeak,
    AmountMismatch,
    OperatorEquivocation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqApproval => "invalid_pq_approval",
            Self::ReplayedNullifier => "replayed_nullifier",
            Self::MoneroKeyImageSeen => "monero_key_image_seen",
            Self::WrongRecipientCommitment => "wrong_recipient_commitment",
            Self::TimelockNotMature => "timelock_not_mature",
            Self::MissingWatcherSignal => "missing_watcher_signal",
            Self::SponsorFraud => "sponsor_fraud",
            Self::PrivacyLeak => "privacy_leak",
            Self::AmountMismatch => "amount_mismatch",
            Self::OperatorEquivocation => "operator_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Sustained,
    Rejected,
    Resolved,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Sustained | Self::Rejected | Self::Resolved | Self::Expired
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWithdrawalEscapeHatchConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub primary_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub kem_scheme: String,
    pub approval_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub emergency_timelock_blocks: u64,
    pub fast_timelock_blocks: u64,
    pub withdrawal_ttl_blocks: u64,
    pub watcher_heartbeat_blocks: u64,
    pub watcher_stale_after_blocks: u64,
    pub replay_retention_blocks: u64,
    pub max_pending_exits: usize,
    pub max_active_disputes: usize,
    pub min_approval_weight_bps: u64,
    pub emergency_approval_weight_bps: u64,
    pub watcher_quorum_weight_bps: u64,
    pub privacy_floor_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub max_sponsor_rebate_units: u64,
    pub min_rescue_fee_units: u64,
    pub challenge_bond_units: u64,
    pub slash_bps: u64,
}

impl Default for PqWithdrawalEscapeHatchConfig {
    fn default() -> Self {
        Self {
            protocol_version: PQ_WITHDRAWAL_ESCAPE_HATCH_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_WITHDRAWAL_ESCAPE_HATCH_SCHEMA_VERSION,
            monero_network: PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: PQ_WITHDRAWAL_ESCAPE_HATCH_HASH_SUITE.to_string(),
            primary_signature_scheme: PQ_WITHDRAWAL_ESCAPE_HATCH_PRIMARY_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme: PQ_WITHDRAWAL_ESCAPE_HATCH_BACKUP_SIGNATURE_SCHEME.to_string(),
            kem_scheme: PQ_WITHDRAWAL_ESCAPE_HATCH_KEM_SCHEME.to_string(),
            approval_window_blocks: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_APPROVAL_WINDOW_BLOCKS,
            challenge_window_blocks: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            emergency_timelock_blocks: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_EMERGENCY_TIMELOCK_BLOCKS,
            fast_timelock_blocks: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_FAST_TIMELOCK_BLOCKS,
            withdrawal_ttl_blocks: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WITHDRAWAL_TTL_BLOCKS,
            watcher_heartbeat_blocks: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WATCHER_HEARTBEAT_BLOCKS,
            watcher_stale_after_blocks:
                PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WATCHER_STALE_AFTER_BLOCKS,
            replay_retention_blocks: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_REPLAY_RETENTION_BLOCKS,
            max_pending_exits: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MAX_PENDING_EXITS,
            max_active_disputes: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MAX_ACTIVE_DISPUTES,
            min_approval_weight_bps: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MIN_APPROVAL_WEIGHT_BPS,
            emergency_approval_weight_bps:
                PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_EMERGENCY_APPROVAL_WEIGHT_BPS,
            watcher_quorum_weight_bps: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_WATCHER_QUORUM_WEIGHT_BPS,
            privacy_floor_bps: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_PRIVACY_FLOOR_BPS,
            sponsor_rebate_bps: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_SPONSOR_REBATE_BPS,
            max_sponsor_rebate_units: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MAX_SPONSOR_REBATE_UNITS,
            min_rescue_fee_units: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_MIN_RESCUE_FEE_UNITS,
            challenge_bond_units: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_CHALLENGE_BOND_UNITS,
            slash_bps: PQ_WITHDRAWAL_ESCAPE_HATCH_DEFAULT_SLASH_BPS,
        }
    }
}

impl PqWithdrawalEscapeHatchConfig {
    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        if self.protocol_version != PQ_WITHDRAWAL_ESCAPE_HATCH_PROTOCOL_VERSION {
            return Err("unsupported escape hatch protocol version".to_string());
        }
        if self.schema_version != PQ_WITHDRAWAL_ESCAPE_HATCH_SCHEMA_VERSION {
            return Err("unsupported escape hatch schema version".to_string());
        }
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("primary_signature_scheme", &self.primary_signature_scheme)?;
        require_non_empty("backup_signature_scheme", &self.backup_signature_scheme)?;
        require_non_empty("kem_scheme", &self.kem_scheme)?;
        require_positive("approval_window_blocks", self.approval_window_blocks)?;
        require_positive("challenge_window_blocks", self.challenge_window_blocks)?;
        require_positive("emergency_timelock_blocks", self.emergency_timelock_blocks)?;
        require_positive("fast_timelock_blocks", self.fast_timelock_blocks)?;
        require_positive("withdrawal_ttl_blocks", self.withdrawal_ttl_blocks)?;
        require_positive("watcher_heartbeat_blocks", self.watcher_heartbeat_blocks)?;
        require_positive(
            "watcher_stale_after_blocks",
            self.watcher_stale_after_blocks,
        )?;
        require_positive("replay_retention_blocks", self.replay_retention_blocks)?;
        if self.max_pending_exits == 0 {
            return Err("max_pending_exits must be positive".to_string());
        }
        if self.max_active_disputes == 0 {
            return Err("max_active_disputes must be positive".to_string());
        }
        require_bps("min_approval_weight_bps", self.min_approval_weight_bps)?;
        require_bps(
            "emergency_approval_weight_bps",
            self.emergency_approval_weight_bps,
        )?;
        require_bps("watcher_quorum_weight_bps", self.watcher_quorum_weight_bps)?;
        require_bps("privacy_floor_bps", self.privacy_floor_bps)?;
        require_bps("sponsor_rebate_bps", self.sponsor_rebate_bps)?;
        require_bps("slash_bps", self.slash_bps)?;
        require_positive("challenge_bond_units", self.challenge_bond_units)?;
        if self.emergency_approval_weight_bps < self.min_approval_weight_bps {
            return Err(
                "emergency approval threshold cannot be below normal threshold".to_string(),
            );
        }
        if self.watcher_stale_after_blocks < self.watcher_heartbeat_blocks {
            return Err("watcher stale window cannot be below heartbeat interval".to_string());
        }
        if self.emergency_timelock_blocks < self.challenge_window_blocks {
            return Err("emergency timelock must cover challenge window".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "primary_signature_scheme": self.primary_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "kem_scheme": self.kem_scheme,
            "approval_window_blocks": self.approval_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "emergency_timelock_blocks": self.emergency_timelock_blocks,
            "fast_timelock_blocks": self.fast_timelock_blocks,
            "withdrawal_ttl_blocks": self.withdrawal_ttl_blocks,
            "watcher_heartbeat_blocks": self.watcher_heartbeat_blocks,
            "watcher_stale_after_blocks": self.watcher_stale_after_blocks,
            "replay_retention_blocks": self.replay_retention_blocks,
            "max_pending_exits": self.max_pending_exits,
            "max_active_disputes": self.max_active_disputes,
            "min_approval_weight_bps": self.min_approval_weight_bps,
            "emergency_approval_weight_bps": self.emergency_approval_weight_bps,
            "watcher_quorum_weight_bps": self.watcher_quorum_weight_bps,
            "privacy_floor_bps": self.privacy_floor_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "max_sponsor_rebate_units": self.max_sponsor_rebate_units,
            "min_rescue_fee_units": self.min_rescue_fee_units,
            "challenge_bond_units": self.challenge_bond_units,
            "slash_bps": self.slash_bps,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGuardian {
    pub guardian_id: String,
    pub role: EscapeHatchRole,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub weight_bps: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub slashed: bool,
    pub metadata_commitment: String,
}

impl PqGuardian {
    pub fn new(
        guardian_id: impl Into<String>,
        role: EscapeHatchRole,
        pq_public_key_commitment: impl Into<String>,
        backup_public_key_commitment: impl Into<String>,
        weight_bps: u64,
        active_from_height: u64,
        active_until_height: u64,
    ) -> Self {
        let guardian_id = guardian_id.into();
        let pq_public_key_commitment = pq_public_key_commitment.into();
        let backup_public_key_commitment = backup_public_key_commitment.into();
        let metadata_commitment = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-GUARDIAN-META",
            &[
                HashPart::Str(&guardian_id),
                HashPart::Str(role.as_str()),
                HashPart::Str(&pq_public_key_commitment),
                HashPart::Str(&backup_public_key_commitment),
            ],
        );
        Self {
            guardian_id,
            role,
            pq_public_key_commitment,
            backup_public_key_commitment,
            weight_bps,
            active_from_height,
            active_until_height,
            slashed: false,
            metadata_commitment,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        !self.slashed && self.active_from_height <= height && height <= self.active_until_height
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("guardian_id", &self.guardian_id)?;
        require_non_empty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        require_non_empty(
            "backup_public_key_commitment",
            &self.backup_public_key_commitment,
        )?;
        require_non_empty("metadata_commitment", &self.metadata_commitment)?;
        require_bps("weight_bps", self.weight_bps)?;
        if self.active_until_height < self.active_from_height {
            return Err("guardian active window is inverted".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guardian_id": self.guardian_id,
            "role": self.role.as_str(),
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_public_key_commitment": self.backup_public_key_commitment,
            "weight_bps": self.weight_bps,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "slashed": self.slashed,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-GUARDIAN",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalEscapeRequest {
    pub request_id: String,
    pub kind: WithdrawalEscapeKind,
    pub account_commitment: String,
    pub monero_recipient_commitment: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub nullifier: String,
    pub monero_key_image_commitment: String,
    pub l2_burn_commitment: String,
    pub privacy_budget_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub timelock_matures_at_height: u64,
    pub challenge_window_ends_at_height: u64,
    pub sponsor_id: Option<String>,
    pub status: WithdrawalEscapeStatus,
    pub approval_id: Option<String>,
    pub dispute_ids: BTreeSet<String>,
    pub rescue_fee_units: u64,
    pub settlement_tx_commitment: Option<String>,
}

impl WithdrawalEscapeRequest {
    pub fn new(
        kind: WithdrawalEscapeKind,
        account_commitment: impl Into<String>,
        monero_recipient_commitment: impl Into<String>,
        amount_commitment: impl Into<String>,
        fee_commitment: impl Into<String>,
        nullifier: impl Into<String>,
        monero_key_image_commitment: impl Into<String>,
        l2_burn_commitment: impl Into<String>,
        privacy_budget_bps: u64,
        opened_at_height: u64,
        config: &PqWithdrawalEscapeHatchConfig,
    ) -> Self {
        let account_commitment = account_commitment.into();
        let monero_recipient_commitment = monero_recipient_commitment.into();
        let amount_commitment = amount_commitment.into();
        let fee_commitment = fee_commitment.into();
        let nullifier = nullifier.into();
        let monero_key_image_commitment = monero_key_image_commitment.into();
        let l2_burn_commitment = l2_burn_commitment.into();
        let timelock_blocks = match kind.requires_emergency_weight() {
            true => config.emergency_timelock_blocks,
            false => config.fast_timelock_blocks,
        };
        let timelock_matures_at_height = opened_at_height.saturating_add(timelock_blocks);
        let challenge_window_ends_at_height =
            opened_at_height.saturating_add(config.challenge_window_blocks);
        let expires_at_height = opened_at_height.saturating_add(config.withdrawal_ttl_blocks);
        let request_id = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-REQUEST-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&account_commitment),
                HashPart::Str(&monero_recipient_commitment),
                HashPart::Str(&amount_commitment),
                HashPart::Str(&fee_commitment),
                HashPart::Str(&nullifier),
                HashPart::Str(&monero_key_image_commitment),
                HashPart::Str(&l2_burn_commitment),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Self {
            request_id,
            kind,
            account_commitment,
            monero_recipient_commitment,
            amount_commitment,
            fee_commitment,
            nullifier,
            monero_key_image_commitment,
            l2_burn_commitment,
            privacy_budget_bps,
            opened_at_height,
            expires_at_height,
            timelock_matures_at_height,
            challenge_window_ends_at_height,
            sponsor_id: None,
            status: WithdrawalEscapeStatus::Open,
            approval_id: None,
            dispute_ids: BTreeSet::new(),
            rescue_fee_units: config.min_rescue_fee_units,
            settlement_tx_commitment: None,
        }
    }

    pub fn validate(
        &self,
        config: &PqWithdrawalEscapeHatchConfig,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_non_empty(
            "monero_recipient_commitment",
            &self.monero_recipient_commitment,
        )?;
        require_non_empty("amount_commitment", &self.amount_commitment)?;
        require_non_empty("fee_commitment", &self.fee_commitment)?;
        require_non_empty("nullifier", &self.nullifier)?;
        require_non_empty(
            "monero_key_image_commitment",
            &self.monero_key_image_commitment,
        )?;
        require_non_empty("l2_burn_commitment", &self.l2_burn_commitment)?;
        require_bps("privacy_budget_bps", self.privacy_budget_bps)?;
        if self.privacy_budget_bps < config.privacy_floor_bps {
            return Err("withdrawal escape request privacy budget below floor".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("withdrawal escape request expires before it opens".to_string());
        }
        if self.timelock_matures_at_height < self.opened_at_height {
            return Err("withdrawal escape timelock matures before open".to_string());
        }
        if self.challenge_window_ends_at_height < self.opened_at_height {
            return Err("withdrawal escape challenge window ends before open".to_string());
        }
        if self.rescue_fee_units < config.min_rescue_fee_units {
            return Err("withdrawal escape rescue fee below minimum".to_string());
        }
        Ok(())
    }

    pub fn challenge_open(&self, height: u64) -> bool {
        height <= self.challenge_window_ends_at_height && self.status.open()
    }

    pub fn timelock_matured(&self, height: u64) -> bool {
        height >= self.timelock_matures_at_height
    }

    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_at_height && !self.status.terminal()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "kind": self.kind.as_str(),
            "account_commitment": self.account_commitment,
            "monero_recipient_commitment": self.monero_recipient_commitment,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "nullifier": self.nullifier,
            "monero_key_image_commitment": self.monero_key_image_commitment,
            "l2_burn_commitment": self.l2_burn_commitment,
            "privacy_budget_bps": self.privacy_budget_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "timelock_matures_at_height": self.timelock_matures_at_height,
            "challenge_window_ends_at_height": self.challenge_window_ends_at_height,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "approval_id": self.approval_id,
            "dispute_ids": self.dispute_ids.iter().cloned().collect::<Vec<_>>(),
            "rescue_fee_units": self.rescue_fee_units,
            "settlement_tx_commitment": self.settlement_tx_commitment,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-REQUEST",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqApprovalShare {
    pub share_id: String,
    pub request_id: String,
    pub guardian_id: String,
    pub algorithm: PqEscapeHatchAlgorithm,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub weight_bps: u64,
    pub approved_at_height: u64,
}

impl PqApprovalShare {
    pub fn new(
        request_id: impl Into<String>,
        guardian_id: impl Into<String>,
        algorithm: PqEscapeHatchAlgorithm,
        transcript_hash: impl Into<String>,
        signature_commitment: impl Into<String>,
        weight_bps: u64,
        approved_at_height: u64,
    ) -> Self {
        let request_id = request_id.into();
        let guardian_id = guardian_id.into();
        let transcript_hash = transcript_hash.into();
        let signature_commitment = signature_commitment.into();
        let share_id = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVAL-SHARE-ID",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&guardian_id),
                HashPart::Str(algorithm.as_str()),
                HashPart::Str(&transcript_hash),
                HashPart::Str(&signature_commitment),
                HashPart::Int(approved_at_height as i128),
            ],
        );
        Self {
            share_id,
            request_id,
            guardian_id,
            algorithm,
            transcript_hash,
            signature_commitment,
            weight_bps,
            approved_at_height,
        }
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("share_id", &self.share_id)?;
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("guardian_id", &self.guardian_id)?;
        require_non_empty("transcript_hash", &self.transcript_hash)?;
        require_non_empty("signature_commitment", &self.signature_commitment)?;
        require_bps("weight_bps", self.weight_bps)?;
        if !self.algorithm.quantum_resistant() {
            return Err("approval share algorithm is not quantum resistant".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "share_id": self.share_id,
            "request_id": self.request_id,
            "guardian_id": self.guardian_id,
            "algorithm": self.algorithm.as_str(),
            "transcript_hash": self.transcript_hash,
            "signature_commitment": self.signature_commitment,
            "weight_bps": self.weight_bps,
            "approved_at_height": self.approved_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVAL-SHARE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqApprovalCertificate {
    pub approval_id: String,
    pub request_id: String,
    pub kind: WithdrawalEscapeKind,
    pub status: ApprovalStatus,
    pub threshold_bps: u64,
    pub signed_weight_bps: u64,
    pub guardian_ids: BTreeSet<String>,
    pub share_ids: BTreeSet<String>,
    pub transcript_hash: String,
    pub share_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub threshold_met_at_height: Option<u64>,
}

impl PqApprovalCertificate {
    pub fn new(
        request: &WithdrawalEscapeRequest,
        threshold_bps: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let transcript_hash = request.record_root();
        let approval_id = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVAL-ID",
            &[
                HashPart::Str(&request.request_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&transcript_hash),
                HashPart::Int(threshold_bps as i128),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Self {
            approval_id,
            request_id: request.request_id.clone(),
            kind: request.kind,
            status: ApprovalStatus::Pending,
            threshold_bps,
            signed_weight_bps: 0,
            guardian_ids: BTreeSet::new(),
            share_ids: BTreeSet::new(),
            transcript_hash,
            share_root: merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-EMPTY-APPROVAL-SHARES", &[]),
            opened_at_height,
            expires_at_height,
            threshold_met_at_height: None,
        }
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("approval_id", &self.approval_id)?;
        require_non_empty("request_id", &self.request_id)?;
        require_bps("threshold_bps", self.threshold_bps)?;
        require_bps("signed_weight_bps", self.signed_weight_bps)?;
        require_non_empty("transcript_hash", &self.transcript_hash)?;
        require_non_empty("share_root", &self.share_root)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("approval certificate expires before it opens".to_string());
        }
        if self.status.usable() && self.signed_weight_bps < self.threshold_bps {
            return Err("approval certificate usable without threshold weight".to_string());
        }
        Ok(())
    }

    pub fn add_share(
        &mut self,
        share: &PqApprovalShare,
        now_height: u64,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        if self.status != ApprovalStatus::Pending {
            return Err("approval certificate is not accepting shares".to_string());
        }
        if share.request_id != self.request_id {
            return Err("approval share targets different request".to_string());
        }
        if share.transcript_hash != self.transcript_hash {
            return Err("approval share transcript mismatch".to_string());
        }
        if now_height > self.expires_at_height {
            self.status = ApprovalStatus::Expired;
            return Err("approval certificate expired".to_string());
        }
        if !self.guardian_ids.insert(share.guardian_id.clone()) {
            return Err("guardian already approved request".to_string());
        }
        self.share_ids.insert(share.share_id.clone());
        self.signed_weight_bps = self
            .signed_weight_bps
            .saturating_add(share.weight_bps)
            .min(PQ_WITHDRAWAL_ESCAPE_HATCH_MAX_BPS);
        if self.signed_weight_bps >= self.threshold_bps {
            self.status = ApprovalStatus::ThresholdMet;
            self.threshold_met_at_height = Some(now_height);
        }
        Ok(())
    }

    pub fn refresh_share_root(&mut self, shares: &BTreeMap<String, PqApprovalShare>) {
        let share_records = self
            .share_ids
            .iter()
            .filter_map(|share_id| shares.get(share_id))
            .map(PqApprovalShare::public_record)
            .collect::<Vec<_>>();
        self.share_root = merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVAL-SHARES", &share_records);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "threshold_bps": self.threshold_bps,
            "signed_weight_bps": self.signed_weight_bps,
            "guardian_ids": self.guardian_ids.iter().cloned().collect::<Vec<_>>(),
            "share_ids": self.share_ids.iter().cloned().collect::<Vec<_>>(),
            "transcript_hash": self.transcript_hash,
            "share_root": self.share_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "threshold_met_at_height": self.threshold_met_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVAL-CERTIFICATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyTimelock {
    pub timelock_id: String,
    pub request_id: String,
    pub status: TimelockStatus,
    pub armed_at_height: u64,
    pub matures_at_height: u64,
    pub challenge_window_ends_at_height: u64,
    pub expires_at_height: u64,
    pub guardian_weight_bps: u64,
    pub watcher_weight_bps: u64,
    pub reason_commitment: String,
    pub execution_commitment: Option<String>,
}

impl EmergencyTimelock {
    pub fn new(
        request: &WithdrawalEscapeRequest,
        guardian_weight_bps: u64,
        watcher_weight_bps: u64,
        reason_commitment: impl Into<String>,
        config: &PqWithdrawalEscapeHatchConfig,
    ) -> Self {
        let reason_commitment = reason_commitment.into();
        let timelock_id = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-TIMELOCK-ID",
            &[
                HashPart::Str(&request.request_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&reason_commitment),
                HashPart::Int(request.opened_at_height as i128),
            ],
        );
        Self {
            timelock_id,
            request_id: request.request_id.clone(),
            status: TimelockStatus::Armed,
            armed_at_height: request.opened_at_height,
            matures_at_height: request
                .opened_at_height
                .saturating_add(config.emergency_timelock_blocks),
            challenge_window_ends_at_height: request
                .opened_at_height
                .saturating_add(config.challenge_window_blocks),
            expires_at_height: request
                .opened_at_height
                .saturating_add(config.withdrawal_ttl_blocks),
            guardian_weight_bps,
            watcher_weight_bps,
            reason_commitment,
            execution_commitment: None,
        }
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("timelock_id", &self.timelock_id)?;
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("reason_commitment", &self.reason_commitment)?;
        require_bps("guardian_weight_bps", self.guardian_weight_bps)?;
        require_bps("watcher_weight_bps", self.watcher_weight_bps)?;
        if self.matures_at_height < self.armed_at_height {
            return Err("timelock maturity is before arm height".to_string());
        }
        if self.challenge_window_ends_at_height < self.armed_at_height {
            return Err("timelock challenge window is before arm height".to_string());
        }
        if self.expires_at_height < self.matures_at_height {
            return Err("timelock expires before maturity".to_string());
        }
        Ok(())
    }

    pub fn matured(&self, height: u64) -> bool {
        height >= self.matures_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "timelock_id": self.timelock_id,
            "request_id": self.request_id,
            "status": self.status.as_str(),
            "armed_at_height": self.armed_at_height,
            "matures_at_height": self.matures_at_height,
            "challenge_window_ends_at_height": self.challenge_window_ends_at_height,
            "expires_at_height": self.expires_at_height,
            "guardian_weight_bps": self.guardian_weight_bps,
            "watcher_weight_bps": self.watcher_weight_bps,
            "reason_commitment": self.reason_commitment,
            "execution_commitment": self.execution_commitment,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-TIMELOCK",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessWatcher {
    pub watcher_id: String,
    pub guardian_id: String,
    pub endpoint_commitment: String,
    pub weight_bps: u64,
    pub status: WatcherStatus,
    pub last_heartbeat_height: u64,
    pub signal_count: u64,
    pub missed_heartbeat_count: u64,
    pub slashed_units: u64,
}

impl LivenessWatcher {
    pub fn new(
        watcher_id: impl Into<String>,
        guardian_id: impl Into<String>,
        endpoint_commitment: impl Into<String>,
        weight_bps: u64,
        height: u64,
    ) -> Self {
        Self {
            watcher_id: watcher_id.into(),
            guardian_id: guardian_id.into(),
            endpoint_commitment: endpoint_commitment.into(),
            weight_bps,
            status: WatcherStatus::Active,
            last_heartbeat_height: height,
            signal_count: 0,
            missed_heartbeat_count: 0,
            slashed_units: 0,
        }
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("watcher_id", &self.watcher_id)?;
        require_non_empty("guardian_id", &self.guardian_id)?;
        require_non_empty("endpoint_commitment", &self.endpoint_commitment)?;
        require_bps("weight_bps", self.weight_bps)?;
        Ok(())
    }

    pub fn stale_at(&self, height: u64, config: &PqWithdrawalEscapeHatchConfig) -> bool {
        height.saturating_sub(self.last_heartbeat_height) > config.watcher_stale_after_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "guardian_id": self.guardian_id,
            "endpoint_commitment": self.endpoint_commitment,
            "weight_bps": self.weight_bps,
            "status": self.status.as_str(),
            "last_heartbeat_height": self.last_heartbeat_height,
            "signal_count": self.signal_count,
            "missed_heartbeat_count": self.missed_heartbeat_count,
            "slashed_units": self.slashed_units,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-WATCHER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherSignal {
    pub signal_id: String,
    pub watcher_id: String,
    pub request_id: Option<String>,
    pub kind: WatcherSignalKind,
    pub observed_height: u64,
    pub submitted_at_height: u64,
    pub evidence_commitment: String,
    pub signature_commitment: String,
}

impl WatcherSignal {
    pub fn new(
        watcher_id: impl Into<String>,
        request_id: Option<String>,
        kind: WatcherSignalKind,
        observed_height: u64,
        submitted_at_height: u64,
        evidence_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
    ) -> Self {
        let watcher_id = watcher_id.into();
        let evidence_commitment = evidence_commitment.into();
        let signature_commitment = signature_commitment.into();
        let request_part = match request_id.as_deref() {
            Some(value) => value,
            None => "global",
        };
        let signal_id = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-WATCHER-SIGNAL-ID",
            &[
                HashPart::Str(&watcher_id),
                HashPart::Str(request_part),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&evidence_commitment),
                HashPart::Int(observed_height as i128),
                HashPart::Int(submitted_at_height as i128),
            ],
        );
        Self {
            signal_id,
            watcher_id,
            request_id,
            kind,
            observed_height,
            submitted_at_height,
            evidence_commitment,
            signature_commitment,
        }
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("signal_id", &self.signal_id)?;
        require_non_empty("watcher_id", &self.watcher_id)?;
        require_non_empty("evidence_commitment", &self.evidence_commitment)?;
        require_non_empty("signature_commitment", &self.signature_commitment)?;
        if self.submitted_at_height < self.observed_height {
            return Err("watcher signal submitted before observed height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "watcher_id": self.watcher_id,
            "request_id": self.request_id,
            "kind": self.kind.as_str(),
            "observed_height": self.observed_height,
            "submitted_at_height": self.submitted_at_height,
            "evidence_commitment": self.evidence_commitment,
            "signature_commitment": self.signature_commitment,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-WATCHER-SIGNAL",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RescueSponsorship {
    pub sponsor_id: String,
    pub request_id: String,
    pub sponsor_account_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub rebate_bps: u64,
    pub status: SponsorshipStatus,
    pub pledged_at_height: u64,
    pub expires_at_height: u64,
    pub reimbursement_commitment: Option<String>,
    pub anti_linkability_tag: String,
}

impl RescueSponsorship {
    pub fn new(
        request_id: impl Into<String>,
        sponsor_account_commitment: impl Into<String>,
        max_fee_units: u64,
        pledged_at_height: u64,
        anti_linkability_tag: impl Into<String>,
        config: &PqWithdrawalEscapeHatchConfig,
    ) -> Self {
        let request_id = request_id.into();
        let sponsor_account_commitment = sponsor_account_commitment.into();
        let anti_linkability_tag = anti_linkability_tag.into();
        let sponsor_id = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-SPONSOR-ID",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&sponsor_account_commitment),
                HashPart::Str(&anti_linkability_tag),
                HashPart::Int(max_fee_units as i128),
                HashPart::Int(pledged_at_height as i128),
            ],
        );
        Self {
            sponsor_id,
            request_id,
            sponsor_account_commitment,
            fee_asset_id: config.fee_asset_id.clone(),
            max_fee_units,
            rebate_bps: config.sponsor_rebate_bps,
            status: SponsorshipStatus::Pledged,
            pledged_at_height,
            expires_at_height: pledged_at_height.saturating_add(config.withdrawal_ttl_blocks),
            reimbursement_commitment: None,
            anti_linkability_tag,
        }
    }

    pub fn validate(
        &self,
        config: &PqWithdrawalEscapeHatchConfig,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("sponsor_id", &self.sponsor_id)?;
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty(
            "sponsor_account_commitment",
            &self.sponsor_account_commitment,
        )?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("anti_linkability_tag", &self.anti_linkability_tag)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.max_fee_units < config.min_rescue_fee_units {
            return Err("sponsorship maximum fee below rescue minimum".to_string());
        }
        if self.max_fee_units > config.max_sponsor_rebate_units {
            return Err("sponsorship maximum fee exceeds configured cap".to_string());
        }
        if self.expires_at_height <= self.pledged_at_height {
            return Err("sponsorship expires before pledge".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "request_id": self.request_id,
            "sponsor_account_commitment": self.sponsor_account_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "pledged_at_height": self.pledged_at_height,
            "expires_at_height": self.expires_at_height,
            "reimbursement_commitment": self.reimbursement_commitment,
            "anti_linkability_tag": self.anti_linkability_tag,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-SPONSORSHIP",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeChallenge {
    pub challenge_id: String,
    pub request_id: String,
    pub challenger_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub evidence_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub response_due_height: u64,
    pub resolved_at_height: Option<u64>,
    pub resolution_commitment: Option<String>,
}

impl EscapeChallenge {
    pub fn new(
        request_id: impl Into<String>,
        challenger_id: impl Into<String>,
        kind: ChallengeKind,
        evidence_root: impl Into<String>,
        opened_at_height: u64,
        config: &PqWithdrawalEscapeHatchConfig,
    ) -> Self {
        let request_id = request_id.into();
        let challenger_id = challenger_id.into();
        let evidence_root = evidence_root.into();
        let challenge_id = derive_record_id(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-CHALLENGE-ID",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&challenger_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&evidence_root),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        Self {
            challenge_id,
            request_id,
            challenger_id,
            kind,
            status: ChallengeStatus::Open,
            evidence_root,
            bond_units: config.challenge_bond_units,
            opened_at_height,
            response_due_height: opened_at_height.saturating_add(config.challenge_window_blocks),
            resolved_at_height: None,
            resolution_commitment: None,
        }
    }

    pub fn validate(
        &self,
        config: &PqWithdrawalEscapeHatchConfig,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("challenge_id", &self.challenge_id)?;
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("challenger_id", &self.challenger_id)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        if self.bond_units < config.challenge_bond_units {
            return Err("challenge bond below configured minimum".to_string());
        }
        if self.response_due_height <= self.opened_at_height {
            return Err("challenge response due before open".to_string());
        }
        if self.status.terminal() && self.resolved_at_height.is_none() {
            return Err("terminal challenge missing resolution height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "request_id": self.request_id,
            "challenger_id": self.challenger_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "response_due_height": self.response_due_height,
            "resolved_at_height": self.resolved_at_height,
            "resolution_commitment": self.resolution_commitment,
        })
    }

    pub fn record_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-CHALLENGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNullifierRecord {
    pub nullifier: String,
    pub request_id: String,
    pub monero_key_image_commitment: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
}

impl ReplayNullifierRecord {
    pub fn new(request: &WithdrawalEscapeRequest, config: &PqWithdrawalEscapeHatchConfig) -> Self {
        Self {
            nullifier: request.nullifier.clone(),
            request_id: request.request_id.clone(),
            monero_key_image_commitment: request.monero_key_image_commitment.clone(),
            first_seen_height: request.opened_at_height,
            expires_at_height: request
                .opened_at_height
                .saturating_add(config.replay_retention_blocks),
        }
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        require_non_empty("nullifier", &self.nullifier)?;
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty(
            "monero_key_image_commitment",
            &self.monero_key_image_commitment,
        )?;
        if self.expires_at_height <= self.first_seen_height {
            return Err("nullifier record expires before first seen height".to_string());
        }
        Ok(())
    }

    pub fn active_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "request_id": self.request_id,
            "monero_key_image_commitment": self.monero_key_image_commitment,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeHatchRoots {
    pub config_root: String,
    pub guardian_root: String,
    pub request_root: String,
    pub approval_root: String,
    pub approval_share_root: String,
    pub timelock_root: String,
    pub watcher_root: String,
    pub watcher_signal_root: String,
    pub sponsorship_root: String,
    pub challenge_root: String,
    pub nullifier_root: String,
}

impl EscapeHatchRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "guardian_root": self.guardian_root,
            "request_root": self.request_root,
            "approval_root": self.approval_root,
            "approval_share_root": self.approval_share_root,
            "timelock_root": self.timelock_root,
            "watcher_root": self.watcher_root,
            "watcher_signal_root": self.watcher_signal_root,
            "sponsorship_root": self.sponsorship_root,
            "challenge_root": self.challenge_root,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeHatchCounters {
    pub guardians: usize,
    pub active_guardians: usize,
    pub watchers: usize,
    pub active_watchers: usize,
    pub stale_watchers: usize,
    pub requests: usize,
    pub open_requests: usize,
    pub settled_requests: usize,
    pub expired_requests: usize,
    pub approvals: usize,
    pub threshold_approvals: usize,
    pub approval_shares: usize,
    pub timelocks: usize,
    pub matured_timelocks: usize,
    pub watcher_signals: usize,
    pub liveness_alarms: usize,
    pub sponsorships: usize,
    pub applied_sponsorships: usize,
    pub challenges: usize,
    pub open_challenges: usize,
    pub nullifiers: usize,
    pub replay_rejections: u64,
}

impl EscapeHatchCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "guardians": self.guardians,
            "active_guardians": self.active_guardians,
            "watchers": self.watchers,
            "active_watchers": self.active_watchers,
            "stale_watchers": self.stale_watchers,
            "requests": self.requests,
            "open_requests": self.open_requests,
            "settled_requests": self.settled_requests,
            "expired_requests": self.expired_requests,
            "approvals": self.approvals,
            "threshold_approvals": self.threshold_approvals,
            "approval_shares": self.approval_shares,
            "timelocks": self.timelocks,
            "matured_timelocks": self.matured_timelocks,
            "watcher_signals": self.watcher_signals,
            "liveness_alarms": self.liveness_alarms,
            "sponsorships": self.sponsorships,
            "applied_sponsorships": self.applied_sponsorships,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "nullifiers": self.nullifiers,
            "replay_rejections": self.replay_rejections,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWithdrawalEscapeHatchState {
    pub height: u64,
    pub status: String,
    pub config: PqWithdrawalEscapeHatchConfig,
    pub guardians: BTreeMap<String, PqGuardian>,
    pub requests: BTreeMap<String, WithdrawalEscapeRequest>,
    pub approvals: BTreeMap<String, PqApprovalCertificate>,
    pub approval_shares: BTreeMap<String, PqApprovalShare>,
    pub timelocks: BTreeMap<String, EmergencyTimelock>,
    pub watchers: BTreeMap<String, LivenessWatcher>,
    pub watcher_signals: BTreeMap<String, WatcherSignal>,
    pub sponsorships: BTreeMap<String, RescueSponsorship>,
    pub challenges: BTreeMap<String, EscapeChallenge>,
    pub nullifiers: BTreeMap<String, ReplayNullifierRecord>,
    pub key_images: BTreeMap<String, String>,
    pub replay_rejections: u64,
}

impl PqWithdrawalEscapeHatchState {
    pub fn new(config: PqWithdrawalEscapeHatchConfig) -> PqWithdrawalEscapeHatchResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            status: STATE_STATUS_BOOTSTRAPPING.to_string(),
            config,
            guardians: BTreeMap::new(),
            requests: BTreeMap::new(),
            approvals: BTreeMap::new(),
            approval_shares: BTreeMap::new(),
            timelocks: BTreeMap::new(),
            watchers: BTreeMap::new(),
            watcher_signals: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            key_images: BTreeMap::new(),
            replay_rejections: 0,
        })
    }

    pub fn devnet() -> Self {
        let mut state = match Self::new(PqWithdrawalEscapeHatchConfig::default()) {
            Ok(state) => state,
            Err(_) => Self::empty_devnet_fallback(),
        };
        state.set_height(PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_HEIGHT);
        let _ = state.add_guardian(PqGuardian::new(
            "guardian-alpha",
            EscapeHatchRole::Guardian,
            "ml-dsa-87-pubkey-commitment-alpha",
            "slh-dsa-pubkey-commitment-alpha",
            3_400,
            1,
            50_000,
        ));
        let _ = state.add_guardian(PqGuardian::new(
            "guardian-beta",
            EscapeHatchRole::Guardian,
            "ml-dsa-87-pubkey-commitment-beta",
            "slh-dsa-pubkey-commitment-beta",
            3_300,
            1,
            50_000,
        ));
        let _ = state.add_guardian(PqGuardian::new(
            "guardian-gamma",
            EscapeHatchRole::PrivacyAuditor,
            "ml-dsa-87-pubkey-commitment-gamma",
            "slh-dsa-pubkey-commitment-gamma",
            3_300,
            1,
            50_000,
        ));
        let _ = state.add_watcher(LivenessWatcher::new(
            "watcher-alpha",
            "guardian-alpha",
            "watcher-alpha-endpoint-commitment",
            2_600,
            state.height,
        ));
        let _ = state.add_watcher(LivenessWatcher::new(
            "watcher-beta",
            "guardian-beta",
            "watcher-beta-endpoint-commitment",
            2_500,
            state.height,
        ));
        let request = WithdrawalEscapeRequest::new(
            WithdrawalEscapeKind::EmergencyTimelockedExit,
            "account-commitment-devnet-escape",
            "monero-recipient-commitment-devnet-escape",
            "amount-commitment-125000000000",
            "fee-commitment-low-fee-rescue",
            "nullifier-devnet-escape-0001",
            "monero-key-image-commitment-devnet-0001",
            "l2-burn-commitment-devnet-0001",
            9_800,
            state.height,
            &state.config,
        );
        let request_id = request.request_id.clone();
        let _ = state.open_request(request);
        let _ = state.open_approval(&request_id);
        let transcript_hash = match state.requests.get(&request_id) {
            Some(request) => request.record_root(),
            None => merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-DEVNET-MISSING", &[]),
        };
        let _ = state.submit_approval_share(PqApprovalShare::new(
            &request_id,
            "guardian-alpha",
            PqEscapeHatchAlgorithm::MlDsa87,
            &transcript_hash,
            "sig-commitment-alpha-devnet",
            3_400,
            state.height,
        ));
        let _ = state.submit_approval_share(PqApprovalShare::new(
            &request_id,
            "guardian-beta",
            PqEscapeHatchAlgorithm::SlhDsaShake192f,
            &transcript_hash,
            "sig-commitment-beta-devnet",
            3_300,
            state.height,
        ));
        let _ = state.record_watcher_signal(WatcherSignal::new(
            "watcher-alpha",
            Some(request_id.clone()),
            WatcherSignalKind::OperatorOffline,
            state.height,
            state.height,
            "operator-offline-evidence-root-devnet",
            "watcher-alpha-sig-devnet",
        ));
        let _ = state.pledge_sponsorship(RescueSponsorship::new(
            &request_id,
            "sponsor-account-commitment-devnet",
            20_000,
            state.height,
            "unlinkable-sponsor-tag-devnet",
            &state.config,
        ));
        let _ = state.arm_timelock(&request_id, "operator-offline-devnet-reason");
        let _ = state.refresh();
        state.status = STATE_STATUS_ACTIVE.to_string();
        state
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.refresh_timeouts();
        self.refresh_watcher_statuses();
        self.refresh_state_status();
    }

    pub fn add_guardian(&mut self, guardian: PqGuardian) -> PqWithdrawalEscapeHatchResult<()> {
        guardian.validate()?;
        if self.guardians.contains_key(&guardian.guardian_id) {
            return Err("guardian already registered".to_string());
        }
        self.guardians
            .insert(guardian.guardian_id.clone(), guardian);
        self.refresh_state_status();
        Ok(())
    }

    pub fn add_watcher(&mut self, watcher: LivenessWatcher) -> PqWithdrawalEscapeHatchResult<()> {
        watcher.validate()?;
        if !self.guardians.contains_key(&watcher.guardian_id) {
            return Err("watcher guardian is not registered".to_string());
        }
        if self.watchers.contains_key(&watcher.watcher_id) {
            return Err("watcher already registered".to_string());
        }
        self.watchers.insert(watcher.watcher_id.clone(), watcher);
        self.refresh_state_status();
        Ok(())
    }

    pub fn open_request(
        &mut self,
        request: WithdrawalEscapeRequest,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        request.validate(&self.config)?;
        if self.open_request_count() >= self.config.max_pending_exits {
            return Err("too many pending withdrawal escape requests".to_string());
        }
        if self.requests.contains_key(&request.request_id) {
            return Err("withdrawal escape request already exists".to_string());
        }
        if self.nullifier_active(&request.nullifier) {
            self.replay_rejections = self.replay_rejections.saturating_add(1);
            return Err("withdrawal escape nullifier replay detected".to_string());
        }
        if self.key_image_active(&request.monero_key_image_commitment) {
            self.replay_rejections = self.replay_rejections.saturating_add(1);
            return Err("withdrawal escape key image replay detected".to_string());
        }
        let nullifier_record = ReplayNullifierRecord::new(&request, &self.config);
        nullifier_record.validate()?;
        self.key_images.insert(
            request.monero_key_image_commitment.clone(),
            request.request_id.clone(),
        );
        self.nullifiers
            .insert(nullifier_record.nullifier.clone(), nullifier_record);
        self.requests.insert(request.request_id.clone(), request);
        self.refresh_state_status();
        Ok(())
    }

    pub fn open_approval(&mut self, request_id: &str) -> PqWithdrawalEscapeHatchResult<String> {
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| "withdrawal escape request not found".to_string())?
            .clone();
        if request.status.terminal() {
            return Err("cannot approve terminal withdrawal escape request".to_string());
        }
        let threshold_bps = if request.kind.requires_emergency_weight() {
            self.config.emergency_approval_weight_bps
        } else {
            self.config.min_approval_weight_bps
        };
        let approval = PqApprovalCertificate::new(
            &request,
            threshold_bps,
            self.height,
            self.height
                .saturating_add(self.config.approval_window_blocks),
        );
        approval.validate()?;
        let approval_id = approval.approval_id.clone();
        if let Some(existing) = request.approval_id {
            if let Some(existing_approval) = self.approvals.get_mut(&existing) {
                if existing_approval.status == ApprovalStatus::Pending {
                    existing_approval.status = ApprovalStatus::Superseded;
                }
            }
        }
        if let Some(stored_request) = self.requests.get_mut(request_id) {
            stored_request.status = WithdrawalEscapeStatus::ApprovalPending;
            stored_request.approval_id = Some(approval_id.clone());
        }
        self.approvals.insert(approval_id.clone(), approval);
        Ok(approval_id)
    }

    pub fn submit_approval_share(
        &mut self,
        share: PqApprovalShare,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        share.validate()?;
        let guardian = self
            .guardians
            .get(&share.guardian_id)
            .ok_or_else(|| "approval guardian not registered".to_string())?;
        if !guardian.active_at(self.height) {
            return Err("approval guardian is not active at current height".to_string());
        }
        if guardian.weight_bps != share.weight_bps {
            return Err("approval share weight does not match guardian weight".to_string());
        }
        let approval_id = self
            .requests
            .get(&share.request_id)
            .and_then(|request| request.approval_id.clone())
            .ok_or_else(|| "request does not have an open approval certificate".to_string())?;
        if self.approval_shares.contains_key(&share.share_id) {
            return Err("approval share already recorded".to_string());
        }
        {
            let approval = self
                .approvals
                .get_mut(&approval_id)
                .ok_or_else(|| "approval certificate missing".to_string())?;
            approval.add_share(&share, self.height)?;
        }
        self.approval_shares.insert(share.share_id.clone(), share);
        if let Some(approval) = self.approvals.get_mut(&approval_id) {
            approval.refresh_share_root(&self.approval_shares);
            if approval.status == ApprovalStatus::ThresholdMet {
                if let Some(request) = self.requests.get_mut(&approval.request_id) {
                    request.status = WithdrawalEscapeStatus::Approved;
                }
            }
        }
        self.refresh_state_status();
        Ok(())
    }

    pub fn arm_timelock(
        &mut self,
        request_id: &str,
        reason_commitment: impl Into<String>,
    ) -> PqWithdrawalEscapeHatchResult<String> {
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| "withdrawal escape request not found".to_string())?
            .clone();
        if request.status.terminal() {
            return Err("cannot arm timelock for terminal request".to_string());
        }
        let approval = request
            .approval_id
            .as_ref()
            .and_then(|approval_id| self.approvals.get(approval_id))
            .ok_or_else(|| "timelock requires approval certificate".to_string())?;
        if !approval.status.usable() {
            return Err("timelock requires threshold approval".to_string());
        }
        let watcher_weight = self.active_watcher_alarm_weight(request_id);
        let timelock = EmergencyTimelock::new(
            &request,
            approval.signed_weight_bps,
            watcher_weight,
            reason_commitment,
            &self.config,
        );
        timelock.validate()?;
        let timelock_id = timelock.timelock_id.clone();
        if let Some(stored_request) = self.requests.get_mut(request_id) {
            stored_request.status = WithdrawalEscapeStatus::Timelocked;
        }
        self.timelocks.insert(timelock_id.clone(), timelock);
        Ok(timelock_id)
    }

    pub fn record_watcher_signal(
        &mut self,
        signal: WatcherSignal,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        signal.validate()?;
        if self.watcher_signals.contains_key(&signal.signal_id) {
            return Err("watcher signal already recorded".to_string());
        }
        let watcher = self
            .watchers
            .get_mut(&signal.watcher_id)
            .ok_or_else(|| "watcher not registered".to_string())?;
        if watcher.status == WatcherStatus::Slashed || watcher.status == WatcherStatus::Retired {
            return Err("watcher is not allowed to signal".to_string());
        }
        if signal.kind == WatcherSignalKind::Heartbeat {
            watcher.last_heartbeat_height = signal.submitted_at_height;
            watcher.status = WatcherStatus::Active;
        } else {
            watcher.signal_count = watcher.signal_count.saturating_add(1);
        }
        self.watcher_signals
            .insert(signal.signal_id.clone(), signal.clone());
        if signal.kind.liveness_alarm() {
            if let Some(request_id) = signal.request_id {
                if let Some(request) = self.requests.get_mut(&request_id) {
                    if request.status == WithdrawalEscapeStatus::Open
                        || request.status == WithdrawalEscapeStatus::ApprovalPending
                    {
                        request.status = WithdrawalEscapeStatus::ApprovalPending;
                    }
                }
            }
        }
        self.refresh_watcher_statuses();
        self.refresh_state_status();
        Ok(())
    }

    pub fn pledge_sponsorship(
        &mut self,
        sponsorship: RescueSponsorship,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        sponsorship.validate(&self.config)?;
        if self.sponsorships.contains_key(&sponsorship.sponsor_id) {
            return Err("sponsorship already exists".to_string());
        }
        let request = self
            .requests
            .get_mut(&sponsorship.request_id)
            .ok_or_else(|| "sponsored request not found".to_string())?;
        if request.status.terminal() {
            return Err("cannot sponsor terminal request".to_string());
        }
        if request.sponsor_id.is_some() {
            return Err("request already has a rescue sponsor".to_string());
        }
        request.sponsor_id = Some(sponsorship.sponsor_id.clone());
        request.rescue_fee_units = request.rescue_fee_units.min(sponsorship.max_fee_units);
        request.status = WithdrawalEscapeStatus::RescueSponsored;
        self.sponsorships
            .insert(sponsorship.sponsor_id.clone(), sponsorship);
        Ok(())
    }

    pub fn open_challenge(
        &mut self,
        challenge: EscapeChallenge,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        challenge.validate(&self.config)?;
        if self.active_dispute_count() >= self.config.max_active_disputes {
            return Err("too many active withdrawal escape disputes".to_string());
        }
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("challenge already exists".to_string());
        }
        let request = self
            .requests
            .get_mut(&challenge.request_id)
            .ok_or_else(|| "challenged request not found".to_string())?;
        if !request.challenge_open(self.height) {
            return Err("request challenge window is closed".to_string());
        }
        request.status = WithdrawalEscapeStatus::Challenged;
        request.dispute_ids.insert(challenge.challenge_id.clone());
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        self.refresh_state_status();
        Ok(())
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        sustained: bool,
        resolution_commitment: impl Into<String>,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        if challenge.status.terminal() {
            return Err("challenge already terminal".to_string());
        }
        let resolution_commitment = resolution_commitment.into();
        require_non_empty("resolution_commitment", &resolution_commitment)?;
        challenge.status = if sustained {
            ChallengeStatus::Sustained
        } else {
            ChallengeStatus::Rejected
        };
        challenge.resolved_at_height = Some(self.height);
        challenge.resolution_commitment = Some(resolution_commitment);
        if let Some(request) = self.requests.get_mut(&challenge.request_id) {
            request.status = if sustained {
                WithdrawalEscapeStatus::Rejected
            } else if request.timelock_matured(self.height) {
                WithdrawalEscapeStatus::ReadyToSettle
            } else {
                WithdrawalEscapeStatus::Timelocked
            };
        }
        self.refresh_state_status();
        Ok(())
    }

    pub fn settle_request(
        &mut self,
        request_id: &str,
        settlement_tx_commitment: impl Into<String>,
    ) -> PqWithdrawalEscapeHatchResult<()> {
        let settlement_tx_commitment = settlement_tx_commitment.into();
        require_non_empty("settlement_tx_commitment", &settlement_tx_commitment)?;
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "withdrawal escape request not found".to_string())?;
        if request.status.terminal() {
            return Err("withdrawal escape request already terminal".to_string());
        }
        let approval_ok = match request
            .approval_id
            .as_ref()
            .and_then(|approval_id| self.approvals.get(approval_id))
        {
            Some(approval) => approval.status.usable(),
            None => false,
        };
        if !approval_ok {
            return Err("settlement requires threshold approval".to_string());
        }
        if !request.timelock_matured(self.height) {
            return Err("settlement timelock has not matured".to_string());
        }
        if request
            .dispute_ids
            .iter()
            .filter_map(|challenge_id| self.challenges.get(challenge_id))
            .any(|challenge| !challenge.status.terminal())
        {
            return Err("settlement blocked by open challenge".to_string());
        }
        request.status = WithdrawalEscapeStatus::Settled;
        request.settlement_tx_commitment = Some(settlement_tx_commitment.clone());
        for timelock in self.timelocks.values_mut() {
            if timelock.request_id == request_id && timelock.status != TimelockStatus::Executed {
                timelock.status = TimelockStatus::Executed;
                timelock.execution_commitment = Some(settlement_tx_commitment.clone());
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.request_id == request_id {
                sponsorship.status = SponsorshipStatus::Applied;
            }
        }
        self.refresh_state_status();
        Ok(())
    }

    pub fn roots(&self) -> EscapeHatchRoots {
        let guardian_records = self
            .guardians
            .values()
            .map(PqGuardian::public_record)
            .collect::<Vec<_>>();
        let request_records = self
            .requests
            .values()
            .map(WithdrawalEscapeRequest::public_record)
            .collect::<Vec<_>>();
        let approval_records = self
            .approvals
            .values()
            .map(PqApprovalCertificate::public_record)
            .collect::<Vec<_>>();
        let approval_share_records = self
            .approval_shares
            .values()
            .map(PqApprovalShare::public_record)
            .collect::<Vec<_>>();
        let timelock_records = self
            .timelocks
            .values()
            .map(EmergencyTimelock::public_record)
            .collect::<Vec<_>>();
        let watcher_records = self
            .watchers
            .values()
            .map(LivenessWatcher::public_record)
            .collect::<Vec<_>>();
        let watcher_signal_records = self
            .watcher_signals
            .values()
            .map(WatcherSignal::public_record)
            .collect::<Vec<_>>();
        let sponsorship_records = self
            .sponsorships
            .values()
            .map(RescueSponsorship::public_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(EscapeChallenge::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .nullifiers
            .values()
            .map(ReplayNullifierRecord::public_record)
            .collect::<Vec<_>>();
        EscapeHatchRoots {
            config_root: self.config.state_root(),
            guardian_root: merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-GUARDIANS", &guardian_records),
            request_root: merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-REQUESTS", &request_records),
            approval_root: merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVALS", &approval_records),
            approval_share_root: merkle_root(
                "PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVAL-SHARES",
                &approval_share_records,
            ),
            timelock_root: merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-TIMELOCKS", &timelock_records),
            watcher_root: merkle_root("PQ-WITHDRAWAL-ESCAPE-HATCH-WATCHERS", &watcher_records),
            watcher_signal_root: merkle_root(
                "PQ-WITHDRAWAL-ESCAPE-HATCH-WATCHER-SIGNALS",
                &watcher_signal_records,
            ),
            sponsorship_root: merkle_root(
                "PQ-WITHDRAWAL-ESCAPE-HATCH-SPONSORSHIPS",
                &sponsorship_records,
            ),
            challenge_root: merkle_root(
                "PQ-WITHDRAWAL-ESCAPE-HATCH-CHALLENGES",
                &challenge_records,
            ),
            nullifier_root: merkle_root(
                "PQ-WITHDRAWAL-ESCAPE-HATCH-NULLIFIERS",
                &nullifier_records,
            ),
        }
    }

    pub fn counters(&self) -> EscapeHatchCounters {
        let active_guardians = self
            .guardians
            .values()
            .filter(|guardian| guardian.active_at(self.height))
            .count();
        let active_watchers = self
            .watchers
            .values()
            .filter(|watcher| watcher.status == WatcherStatus::Active)
            .count();
        let stale_watchers = self
            .watchers
            .values()
            .filter(|watcher| watcher.status == WatcherStatus::Stale)
            .count();
        let open_requests = self
            .requests
            .values()
            .filter(|request| request.status.open())
            .count();
        let settled_requests = self
            .requests
            .values()
            .filter(|request| request.status == WithdrawalEscapeStatus::Settled)
            .count();
        let expired_requests = self
            .requests
            .values()
            .filter(|request| request.status == WithdrawalEscapeStatus::Expired)
            .count();
        let threshold_approvals = self
            .approvals
            .values()
            .filter(|approval| approval.status == ApprovalStatus::ThresholdMet)
            .count();
        let matured_timelocks = self
            .timelocks
            .values()
            .filter(|timelock| timelock.matured(self.height))
            .count();
        let liveness_alarms = self
            .watcher_signals
            .values()
            .filter(|signal| signal.kind.liveness_alarm())
            .count();
        let applied_sponsorships = self
            .sponsorships
            .values()
            .filter(|sponsorship| sponsorship.status == SponsorshipStatus::Applied)
            .count();
        let open_challenges = self
            .challenges
            .values()
            .filter(|challenge| !challenge.status.terminal())
            .count();
        EscapeHatchCounters {
            guardians: self.guardians.len(),
            active_guardians,
            watchers: self.watchers.len(),
            active_watchers,
            stale_watchers,
            requests: self.requests.len(),
            open_requests,
            settled_requests,
            expired_requests,
            approvals: self.approvals.len(),
            threshold_approvals,
            approval_shares: self.approval_shares.len(),
            timelocks: self.timelocks.len(),
            matured_timelocks,
            watcher_signals: self.watcher_signals.len(),
            liveness_alarms,
            sponsorships: self.sponsorships.len(),
            applied_sponsorships,
            challenges: self.challenges.len(),
            open_challenges,
            nullifiers: self.nullifiers.len(),
            replay_rejections: self.replay_rejections,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_withdrawal_escape_hatch_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "status": self.status,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "guardians": self.guardians.values().map(PqGuardian::public_record).collect::<Vec<_>>(),
            "requests": self.requests.values().map(WithdrawalEscapeRequest::public_record).collect::<Vec<_>>(),
            "approvals": self.approvals.values().map(PqApprovalCertificate::public_record).collect::<Vec<_>>(),
            "approval_shares": self.approval_shares.values().map(PqApprovalShare::public_record).collect::<Vec<_>>(),
            "timelocks": self.timelocks.values().map(EmergencyTimelock::public_record).collect::<Vec<_>>(),
            "watchers": self.watchers.values().map(LivenessWatcher::public_record).collect::<Vec<_>>(),
            "watcher_signals": self.watcher_signals.values().map(WatcherSignal::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(RescueSponsorship::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(EscapeChallenge::public_record).collect::<Vec<_>>(),
            "nullifiers": self.nullifiers.values().map(ReplayNullifierRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PQ-WITHDRAWAL-ESCAPE-HATCH-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PqWithdrawalEscapeHatchResult<()> {
        self.config.validate()?;
        require_non_empty("status", &self.status)?;
        let allowed_status = [
            STATE_STATUS_BOOTSTRAPPING,
            STATE_STATUS_ACTIVE,
            STATE_STATUS_DEGRADED,
            STATE_STATUS_PAUSED,
            STATE_STATUS_HALTED,
        ];
        if !allowed_status.iter().any(|status| *status == self.status) {
            return Err("unknown escape hatch state status".to_string());
        }
        let mut guardian_weight = 0_u64;
        for guardian in self.guardians.values() {
            guardian.validate()?;
            if guardian.active_at(self.height) {
                guardian_weight = guardian_weight.saturating_add(guardian.weight_bps);
            }
        }
        if guardian_weight > PQ_WITHDRAWAL_ESCAPE_HATCH_MAX_BPS {
            return Err("active guardian weight exceeds 100 percent".to_string());
        }
        for watcher in self.watchers.values() {
            watcher.validate()?;
            if !self.guardians.contains_key(&watcher.guardian_id) {
                return Err("watcher references missing guardian".to_string());
            }
        }
        for request in self.requests.values() {
            request.validate(&self.config)?;
            if let Some(approval_id) = &request.approval_id {
                if !self.approvals.contains_key(approval_id) {
                    return Err("request references missing approval".to_string());
                }
            }
            if let Some(sponsor_id) = &request.sponsor_id {
                if !self.sponsorships.contains_key(sponsor_id) {
                    return Err("request references missing sponsor".to_string());
                }
            }
            for challenge_id in &request.dispute_ids {
                if !self.challenges.contains_key(challenge_id) {
                    return Err("request references missing challenge".to_string());
                }
            }
        }
        for approval in self.approvals.values() {
            approval.validate()?;
            if !self.requests.contains_key(&approval.request_id) {
                return Err("approval references missing request".to_string());
            }
            for guardian_id in &approval.guardian_ids {
                if !self.guardians.contains_key(guardian_id) {
                    return Err("approval references missing guardian".to_string());
                }
            }
            for share_id in &approval.share_ids {
                if !self.approval_shares.contains_key(share_id) {
                    return Err("approval references missing share".to_string());
                }
            }
        }
        for share in self.approval_shares.values() {
            share.validate()?;
            if !self.requests.contains_key(&share.request_id) {
                return Err("approval share references missing request".to_string());
            }
            if !self.guardians.contains_key(&share.guardian_id) {
                return Err("approval share references missing guardian".to_string());
            }
        }
        for timelock in self.timelocks.values() {
            timelock.validate()?;
            if !self.requests.contains_key(&timelock.request_id) {
                return Err("timelock references missing request".to_string());
            }
        }
        for signal in self.watcher_signals.values() {
            signal.validate()?;
            if !self.watchers.contains_key(&signal.watcher_id) {
                return Err("watcher signal references missing watcher".to_string());
            }
            if let Some(request_id) = &signal.request_id {
                if !self.requests.contains_key(request_id) {
                    return Err("watcher signal references missing request".to_string());
                }
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate(&self.config)?;
            if !self.requests.contains_key(&sponsorship.request_id) {
                return Err("sponsorship references missing request".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate(&self.config)?;
            if !self.requests.contains_key(&challenge.request_id) {
                return Err("challenge references missing request".to_string());
            }
        }
        for nullifier in self.nullifiers.values() {
            nullifier.validate()?;
            if !self.requests.contains_key(&nullifier.request_id) {
                return Err("nullifier references missing request".to_string());
            }
        }
        Ok(())
    }

    pub fn refresh(&mut self) -> PqWithdrawalEscapeHatchResult<()> {
        self.refresh_timeouts();
        self.refresh_watcher_statuses();
        for approval in self.approvals.values_mut() {
            approval.refresh_share_root(&self.approval_shares);
        }
        self.refresh_state_status();
        self.validate()
    }

    fn empty_devnet_fallback() -> Self {
        Self {
            height: PQ_WITHDRAWAL_ESCAPE_HATCH_DEVNET_HEIGHT,
            status: STATE_STATUS_BOOTSTRAPPING.to_string(),
            config: PqWithdrawalEscapeHatchConfig::default(),
            guardians: BTreeMap::new(),
            requests: BTreeMap::new(),
            approvals: BTreeMap::new(),
            approval_shares: BTreeMap::new(),
            timelocks: BTreeMap::new(),
            watchers: BTreeMap::new(),
            watcher_signals: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            key_images: BTreeMap::new(),
            replay_rejections: 0,
        }
    }

    fn open_request_count(&self) -> usize {
        self.requests
            .values()
            .filter(|request| request.status.open())
            .count()
    }

    fn active_dispute_count(&self) -> usize {
        self.challenges
            .values()
            .filter(|challenge| !challenge.status.terminal())
            .count()
    }

    fn nullifier_active(&self, nullifier: &str) -> bool {
        match self.nullifiers.get(nullifier) {
            Some(record) => record.active_at(self.height),
            None => false,
        }
    }

    fn key_image_active(&self, key_image: &str) -> bool {
        match self
            .key_images
            .get(key_image)
            .and_then(|request_id| self.requests.get(request_id))
        {
            Some(request) => !request.status.terminal() || request.expires_at_height >= self.height,
            None => false,
        }
    }

    fn active_watcher_alarm_weight(&self, request_id: &str) -> u64 {
        let mut watcher_ids = BTreeSet::new();
        let mut weight = 0_u64;
        for signal in self.watcher_signals.values() {
            if signal.request_id.as_deref() == Some(request_id) && signal.kind.liveness_alarm() {
                if watcher_ids.insert(signal.watcher_id.clone()) {
                    if let Some(watcher) = self.watchers.get(&signal.watcher_id) {
                        if watcher.status == WatcherStatus::Active {
                            weight = weight.saturating_add(watcher.weight_bps);
                        }
                    }
                }
            }
        }
        weight.min(PQ_WITHDRAWAL_ESCAPE_HATCH_MAX_BPS)
    }

    fn refresh_timeouts(&mut self) {
        for request in self.requests.values_mut() {
            if request.expired(self.height) {
                request.status = WithdrawalEscapeStatus::Expired;
            } else if request.status == WithdrawalEscapeStatus::Timelocked
                && request.timelock_matured(self.height)
            {
                request.status = WithdrawalEscapeStatus::ReadyToSettle;
            } else if request.status == WithdrawalEscapeStatus::Approved
                && request.challenge_window_ends_at_height < self.height
                && request.timelock_matured(self.height)
            {
                request.status = WithdrawalEscapeStatus::ReadyToSettle;
            }
        }
        for approval in self.approvals.values_mut() {
            if approval.status == ApprovalStatus::Pending
                && self.height > approval.expires_at_height
            {
                approval.status = ApprovalStatus::Expired;
            }
        }
        for timelock in self.timelocks.values_mut() {
            if timelock.status == TimelockStatus::Executed {
                continue;
            }
            if self.height > timelock.expires_at_height {
                timelock.status = TimelockStatus::Expired;
            } else if timelock.matured(self.height) {
                timelock.status = TimelockStatus::Matured;
            } else if self.height <= timelock.challenge_window_ends_at_height {
                timelock.status = TimelockStatus::ChallengeOpen;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if matches!(
                sponsorship.status,
                SponsorshipStatus::Pledged | SponsorshipStatus::Reserved
            ) && self.height > sponsorship.expires_at_height
            {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if !challenge.status.terminal() && self.height > challenge.response_due_height {
                challenge.status = ChallengeStatus::Expired;
                challenge.resolved_at_height = Some(self.height);
            }
        }
    }

    fn refresh_watcher_statuses(&mut self) {
        for watcher in self.watchers.values_mut() {
            if matches!(
                watcher.status,
                WatcherStatus::Slashed | WatcherStatus::Retired
            ) {
                continue;
            }
            if watcher.stale_at(self.height, &self.config) {
                watcher.status = WatcherStatus::Stale;
                watcher.missed_heartbeat_count = watcher.missed_heartbeat_count.saturating_add(1);
            }
        }
    }

    fn refresh_state_status(&mut self) {
        if self.status == STATE_STATUS_PAUSED || self.status == STATE_STATUS_HALTED {
            return;
        }
        let counters = self.counters();
        if counters.active_guardians == 0 {
            self.status = STATE_STATUS_BOOTSTRAPPING.to_string();
        } else if counters.stale_watchers > 0 || counters.open_challenges > 0 {
            self.status = STATE_STATUS_DEGRADED.to_string();
        } else {
            self.status = STATE_STATUS_ACTIVE.to_string();
        }
    }
}

pub fn devnet() -> PqWithdrawalEscapeHatchState {
    PqWithdrawalEscapeHatchState::devnet()
}

pub fn escape_request_id(
    kind: WithdrawalEscapeKind,
    account_commitment: &str,
    monero_recipient_commitment: &str,
    amount_commitment: &str,
    nullifier: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-WITHDRAWAL-ESCAPE-HATCH-REQUEST-ID-PREVIEW",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(account_commitment),
            HashPart::Str(monero_recipient_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(nullifier),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn approval_transcript_hash(request: &WithdrawalEscapeRequest) -> String {
    domain_hash(
        "PQ-WITHDRAWAL-ESCAPE-HATCH-APPROVAL-TRANSCRIPT",
        &[HashPart::Json(&request.public_record())],
        32,
    )
}

pub fn nullifier_binding_hash(
    nullifier: &str,
    monero_key_image_commitment: &str,
    l2_burn_commitment: &str,
) -> String {
    domain_hash(
        "PQ-WITHDRAWAL-ESCAPE-HATCH-NULLIFIER-BINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier),
            HashPart::Str(monero_key_image_commitment),
            HashPart::Str(l2_burn_commitment),
        ],
        32,
    )
}

pub fn rescue_sponsorship_quote(
    requested_fee_units: u64,
    config: &PqWithdrawalEscapeHatchConfig,
) -> u64 {
    let rebate = requested_fee_units
        .saturating_mul(config.sponsor_rebate_bps)
        .saturating_div(PQ_WITHDRAWAL_ESCAPE_HATCH_MAX_BPS);
    rebate.min(config.max_sponsor_rebate_units)
}

fn derive_record_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn require_non_empty(field: &str, value: &str) -> PqWithdrawalEscapeHatchResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn require_positive(field: &str, value: u64) -> PqWithdrawalEscapeHatchResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> PqWithdrawalEscapeHatchResult<()> {
    if value == 0 || value > PQ_WITHDRAWAL_ESCAPE_HATCH_MAX_BPS {
        return Err(format!("{field} must be within 1..=10000 basis points"));
    }
    Ok(())
}
