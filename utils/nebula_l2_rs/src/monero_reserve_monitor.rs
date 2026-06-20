use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroReserveMonitorResult<T> = Result<T, String>;

pub const MONERO_RESERVE_MONITOR_PROTOCOL_VERSION: &str = "nebula-monero-reserve-monitor-v1";
pub const MONERO_RESERVE_MONITOR_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_RESERVE_MONITOR_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_RESERVE_MONITOR_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_RESERVE_MONITOR_DEFAULT_MIN_CONFIRMATIONS: u64 = 12;
pub const MONERO_RESERVE_MONITOR_DEFAULT_DAEMON_QUORUM_WEIGHT: u64 = 3;
pub const MONERO_RESERVE_MONITOR_DEFAULT_OBSERVER_STALENESS_BLOCKS: u64 = 8;
pub const MONERO_RESERVE_MONITOR_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 24;
pub const MONERO_RESERVE_MONITOR_DEFAULT_PROOF_REQUEST_TTL_BLOCKS: u64 = 18;
pub const MONERO_RESERVE_MONITOR_DEFAULT_PROOF_GRACE_BLOCKS: u64 = 6;
pub const MONERO_RESERVE_MONITOR_DEFAULT_MIN_COVERAGE_BPS: u64 = 10_250;
pub const MONERO_RESERVE_MONITOR_DEFAULT_TARGET_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_RESERVE_MONITOR_DEFAULT_EMERGENCY_COVERAGE_BPS: u64 = 9_900;
pub const MONERO_RESERVE_MONITOR_DEFAULT_MAX_MINT_BPS_PER_WINDOW: u64 = 1_000;
pub const MONERO_RESERVE_MONITOR_DEFAULT_LOW_FEE_BUDGET_PICONERO: u64 = 250_000_000;
pub const MONERO_RESERVE_MONITOR_DEFAULT_OUTPUT_BUCKET_PICONERO: u64 = 250_000_000_000;
pub const MONERO_RESERVE_MONITOR_MAX_BPS: u64 = 10_000;
pub const MONERO_RESERVE_MONITOR_PQ_SIGNER_SCHEME: &str = "ML-DSA-65";
pub const MONERO_RESERVE_MONITOR_PQ_OBSERVER_SCHEME: &str = "SLH-DSA-SHAKE-128s";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveWalletRole {
    ColdReserve,
    HotBuffer,
    AuditMirror,
    DefiBridge,
    EmergencyRecovery,
}

impl ReserveWalletRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ColdReserve => "cold_reserve",
            Self::HotBuffer => "hot_buffer",
            Self::AuditMirror => "audit_mirror",
            Self::DefiBridge => "defi_bridge",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveWalletStatus {
    Pending,
    Active,
    Rotating,
    Suspended,
    Retired,
}

impl ReserveWalletStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveParticipantRole {
    ReserveSigner,
    DaemonObserver,
    Auditor,
    Prover,
    Sponsor,
    EmergencyCouncil,
}

impl ReserveParticipantRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveSigner => "reserve_signer",
            Self::DaemonObserver => "daemon_observer",
            Self::Auditor => "auditor",
            Self::Prover => "prover",
            Self::Sponsor => "sponsor",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonObserverRole {
    Primary,
    Independent,
    Watchtower,
    Auditor,
    Sequencer,
}

impl DaemonObserverRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Independent => "independent",
            Self::Watchtower => "watchtower",
            Self::Auditor => "auditor",
            Self::Sequencer => "sequencer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonObservationStatus {
    Pending,
    QuorumAccepted,
    Disputed,
    Stale,
    Reorged,
}

impl DaemonObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Disputed => "disputed",
            Self::Stale => "stale",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Pending | Self::QuorumAccepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonQuorumStatus {
    Pending,
    Confirmed,
    Disputed,
    Expired,
    Reorged,
}

impl DaemonQuorumStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveOutputStatus {
    Candidate,
    ConfirmedUnspent,
    Spent,
    Disputed,
    Reorged,
}

impl ReserveOutputStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::ConfirmedUnspent => "confirmed_unspent",
            Self::Spent => "spent",
            Self::Disputed => "disputed",
            Self::Reorged => "reorged",
        }
    }

    pub fn counts_as_reserve(self) -> bool {
        matches!(self, Self::ConfirmedUnspent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyImageStatus {
    NotSeen,
    SeenSpent,
    QuorumSpent,
    Disputed,
    Reorged,
}

impl KeyImageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotSeen => "not_seen",
            Self::SeenSpent => "seen_spent",
            Self::QuorumSpent => "quorum_spent",
            Self::Disputed => "disputed",
            Self::Reorged => "reorged",
        }
    }

    pub fn is_spent(self) -> bool {
        matches!(self, Self::SeenSpent | Self::QuorumSpent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencyEpochStatus {
    Open,
    Proving,
    Proven,
    BufferLow,
    Deficit,
    Emergency,
    Challenged,
    Settled,
}

impl SolvencyEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proving => "proving",
            Self::Proven => "proven",
            Self::BufferLow => "buffer_low",
            Self::Deficit => "deficit",
            Self::Emergency => "emergency",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
        }
    }

    pub fn needs_throttle(self) -> bool {
        matches!(self, Self::BufferLow | Self::Deficit | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSolvencyRisk {
    Healthy,
    BufferLow,
    UnderCovered,
    Insolvent,
    Unknown,
}

impl ReserveSolvencyRisk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::BufferLow => "buffer_low",
            Self::UnderCovered => "under_covered",
            Self::Insolvent => "insolvent",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_coverage(
        coverage_bps: u64,
        min_coverage_bps: u64,
        target_coverage_bps: u64,
        emergency_coverage_bps: u64,
    ) -> Self {
        if coverage_bps == 0 || coverage_bps == u64::MAX {
            Self::Unknown
        } else if coverage_bps < emergency_coverage_bps {
            Self::Insolvent
        } else if coverage_bps < min_coverage_bps {
            Self::UnderCovered
        } else if coverage_bps < target_coverage_bps {
            Self::BufferLow
        } else {
            Self::Healthy
        }
    }

    pub fn epoch_status(self) -> SolvencyEpochStatus {
        match self {
            Self::Healthy => SolvencyEpochStatus::Proven,
            Self::BufferLow => SolvencyEpochStatus::BufferLow,
            Self::UnderCovered => SolvencyEpochStatus::Deficit,
            Self::Insolvent => SolvencyEpochStatus::Emergency,
            Self::Unknown => SolvencyEpochStatus::Proving,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofRequestKind {
    WalletBalance,
    OutputSetInclusion,
    KeyImageAbsence,
    SolvencyEpoch,
    DefiBridgeLiquidity,
    EmergencyUnlock,
    PublicSummary,
}

impl ReserveProofRequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletBalance => "wallet_balance",
            Self::OutputSetInclusion => "output_set_inclusion",
            Self::KeyImageAbsence => "key_image_absence",
            Self::SolvencyEpoch => "solvency_epoch",
            Self::DefiBridgeLiquidity => "defi_bridge_liquidity",
            Self::EmergencyUnlock => "emergency_unlock",
            Self::PublicSummary => "public_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofRequestStatus {
    Requested,
    Sponsored,
    InProgress,
    Fulfilled,
    Expired,
    Cancelled,
}

impl ReserveProofRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Sponsored => "sponsored",
            Self::InProgress => "in_progress",
            Self::Fulfilled => "fulfilled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Requested | Self::Sponsored | Self::InProgress)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofReceiptStatus {
    Submitted,
    Verified,
    Rejected,
    Superseded,
}

impl ReserveProofReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeficitAlertSeverity {
    Info,
    Watch,
    Deficit,
    Critical,
}

impl DeficitAlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Deficit => "deficit",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeficitAlertStatus {
    Open,
    Acknowledged,
    Mitigating,
    Resolved,
    Expired,
}

impl DeficitAlertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Mitigating => "mitigating",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Open | Self::Acknowledged | Self::Mitigating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyMintThrottleMode {
    Disabled,
    Protective,
    ReserveOnly,
    Halted,
}

impl EmergencyMintThrottleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Protective => "protective",
            Self::ReserveOnly => "reserve_only",
            Self::Halted => "halted",
        }
    }

    pub fn allows_mint(self) -> bool {
        matches!(self, Self::Disabled | Self::Protective | Self::ReserveOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeSponsorshipStatus {
    Active,
    Reserved,
    Exhausted,
    Expired,
    Paused,
    Slashed,
}

impl LowFeeSponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAttestationSubjectKind {
    WalletCommitment,
    DaemonObservation,
    DaemonQuorum,
    OutputObservation,
    KeyImageObservation,
    SolvencyEpoch,
    ProofRequest,
    ProofReceipt,
    DeficitAlert,
    MintThrottle,
    Sponsorship,
    PublicSummary,
}

impl ReserveAttestationSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletCommitment => "wallet_commitment",
            Self::DaemonObservation => "daemon_observation",
            Self::DaemonQuorum => "daemon_quorum",
            Self::OutputObservation => "output_observation",
            Self::KeyImageObservation => "key_image_observation",
            Self::SolvencyEpoch => "solvency_epoch",
            Self::ProofRequest => "proof_request",
            Self::ProofReceipt => "proof_receipt",
            Self::DeficitAlert => "deficit_alert",
            Self::MintThrottle => "mint_throttle",
            Self::Sponsorship => "sponsorship",
            Self::PublicSummary => "public_summary",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveMonitorConfig {
    pub protocol_version: String,
    pub network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub min_confirmations: u64,
    pub daemon_quorum_weight: u64,
    pub observer_staleness_blocks: u64,
    pub epoch_length_blocks: u64,
    pub proof_request_ttl_blocks: u64,
    pub proof_receipt_grace_blocks: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub emergency_reserve_coverage_bps: u64,
    pub max_mint_bps_per_window: u64,
    pub default_low_fee_budget_piconero: u64,
    pub output_bucket_piconero: u64,
    pub accepted_pq_signature_schemes: BTreeSet<String>,
}

impl Default for MoneroReserveMonitorConfig {
    fn default() -> Self {
        let mut schemes = BTreeSet::new();
        schemes.insert(MONERO_RESERVE_MONITOR_PQ_SIGNER_SCHEME.to_string());
        schemes.insert(MONERO_RESERVE_MONITOR_PQ_OBSERVER_SCHEME.to_string());
        Self {
            protocol_version: MONERO_RESERVE_MONITOR_PROTOCOL_VERSION.to_string(),
            network: MONERO_RESERVE_MONITOR_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_RESERVE_MONITOR_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_RESERVE_MONITOR_DEVNET_FEE_ASSET_ID.to_string(),
            min_confirmations: MONERO_RESERVE_MONITOR_DEFAULT_MIN_CONFIRMATIONS,
            daemon_quorum_weight: MONERO_RESERVE_MONITOR_DEFAULT_DAEMON_QUORUM_WEIGHT,
            observer_staleness_blocks: MONERO_RESERVE_MONITOR_DEFAULT_OBSERVER_STALENESS_BLOCKS,
            epoch_length_blocks: MONERO_RESERVE_MONITOR_DEFAULT_EPOCH_LENGTH_BLOCKS,
            proof_request_ttl_blocks: MONERO_RESERVE_MONITOR_DEFAULT_PROOF_REQUEST_TTL_BLOCKS,
            proof_receipt_grace_blocks: MONERO_RESERVE_MONITOR_DEFAULT_PROOF_GRACE_BLOCKS,
            min_reserve_coverage_bps: MONERO_RESERVE_MONITOR_DEFAULT_MIN_COVERAGE_BPS,
            target_reserve_coverage_bps: MONERO_RESERVE_MONITOR_DEFAULT_TARGET_COVERAGE_BPS,
            emergency_reserve_coverage_bps: MONERO_RESERVE_MONITOR_DEFAULT_EMERGENCY_COVERAGE_BPS,
            max_mint_bps_per_window: MONERO_RESERVE_MONITOR_DEFAULT_MAX_MINT_BPS_PER_WINDOW,
            default_low_fee_budget_piconero: MONERO_RESERVE_MONITOR_DEFAULT_LOW_FEE_BUDGET_PICONERO,
            output_bucket_piconero: MONERO_RESERVE_MONITOR_DEFAULT_OUTPUT_BUCKET_PICONERO,
            accepted_pq_signature_schemes: schemes,
        }
    }
}

impl MoneroReserveMonitorConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reserve_monitor_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "network": self.network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_confirmations": self.min_confirmations,
            "daemon_quorum_weight": self.daemon_quorum_weight,
            "observer_staleness_blocks": self.observer_staleness_blocks,
            "epoch_length_blocks": self.epoch_length_blocks,
            "proof_request_ttl_blocks": self.proof_request_ttl_blocks,
            "proof_receipt_grace_blocks": self.proof_receipt_grace_blocks,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "emergency_reserve_coverage_bps": self.emergency_reserve_coverage_bps,
            "max_mint_bps_per_window": self.max_mint_bps_per_window,
            "default_low_fee_budget_piconero": self.default_low_fee_budget_piconero,
            "output_bucket_piconero": self.output_bucket_piconero,
            "accepted_pq_signature_schemes": self.accepted_pq_signature_schemes,
        })
    }

    pub fn config_root(&self) -> String {
        monero_reserve_monitor_payload_root("MONERO-RESERVE-MONITOR-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<()> {
        ensure_non_empty(
            &self.protocol_version,
            "monero reserve monitor protocol version",
        )?;
        if self.protocol_version != MONERO_RESERVE_MONITOR_PROTOCOL_VERSION {
            return Err("monero reserve monitor protocol version mismatch".to_string());
        }
        ensure_non_empty(&self.network, "monero reserve monitor network")?;
        ensure_non_empty(&self.asset_id, "monero reserve monitor asset id")?;
        ensure_non_empty(&self.fee_asset_id, "monero reserve monitor fee asset id")?;
        ensure_positive(
            self.min_confirmations,
            "monero reserve monitor confirmations",
        )?;
        ensure_positive(
            self.daemon_quorum_weight,
            "monero reserve monitor daemon quorum weight",
        )?;
        ensure_positive(
            self.observer_staleness_blocks,
            "monero reserve monitor observer staleness",
        )?;
        ensure_positive(
            self.epoch_length_blocks,
            "monero reserve monitor epoch length",
        )?;
        ensure_positive(
            self.proof_request_ttl_blocks,
            "monero reserve monitor proof request ttl",
        )?;
        ensure_positive(
            self.output_bucket_piconero,
            "monero reserve monitor output bucket",
        )?;
        ensure_bps(
            self.min_reserve_coverage_bps,
            "monero reserve monitor minimum coverage",
        )?;
        ensure_bps(
            self.target_reserve_coverage_bps,
            "monero reserve monitor target coverage",
        )?;
        ensure_bps(
            self.emergency_reserve_coverage_bps,
            "monero reserve monitor emergency coverage",
        )?;
        ensure_bps(
            self.max_mint_bps_per_window,
            "monero reserve monitor mint throttle",
        )?;
        if self.emergency_reserve_coverage_bps > self.min_reserve_coverage_bps {
            return Err("emergency coverage must not exceed minimum coverage".to_string());
        }
        if self.min_reserve_coverage_bps > self.target_reserve_coverage_bps {
            return Err("minimum coverage must not exceed target coverage".to_string());
        }
        if self.accepted_pq_signature_schemes.is_empty() {
            return Err("at least one PQ signature scheme is required".to_string());
        }
        for scheme in &self.accepted_pq_signature_schemes {
            ensure_non_empty(scheme, "monero reserve monitor PQ signature scheme")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReserveParticipant {
    pub participant_id: String,
    pub label: String,
    pub role: ReserveParticipantRole,
    pub signature_scheme: String,
    pub public_key_commitment: String,
    pub weight: u64,
    pub registered_height: u64,
    pub rotation_nonce: u64,
    pub active: bool,
}

impl PqReserveParticipant {
    pub fn new(
        label: impl Into<String>,
        role: ReserveParticipantRole,
        signature_scheme: impl Into<String>,
        public_key_material: impl AsRef<str>,
        weight: u64,
        registered_height: u64,
        rotation_nonce: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let label = label.into();
        let signature_scheme = signature_scheme.into();
        let public_key_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PQ-PUBLIC-KEY",
            public_key_material.as_ref(),
        );
        let participant_id = monero_reserve_monitor_participant_id(
            &label,
            role.as_str(),
            &signature_scheme,
            &public_key_commitment,
            registered_height,
            rotation_nonce,
        );
        let participant = Self {
            participant_id,
            label,
            role,
            signature_scheme,
            public_key_commitment,
            weight,
            registered_height,
            rotation_nonce,
            active: true,
        };
        participant.validate()?;
        Ok(participant)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_reserve_participant",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "participant_id": self.participant_id,
            "label": self.label,
            "role": self.role.as_str(),
            "signature_scheme": self.signature_scheme,
            "public_key_commitment": self.public_key_commitment,
            "weight": self.weight,
            "registered_height": self.registered_height,
            "rotation_nonce": self.rotation_nonce,
            "active": self.active,
        })
    }

    pub fn participant_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-PARTICIPANT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.participant_id, "reserve participant id")?;
        ensure_non_empty(&self.label, "reserve participant label")?;
        ensure_non_empty(
            &self.signature_scheme,
            "reserve participant signature scheme",
        )?;
        ensure_non_empty(
            &self.public_key_commitment,
            "reserve participant public key commitment",
        )?;
        ensure_positive(self.weight, "reserve participant weight")?;
        let expected = monero_reserve_monitor_participant_id(
            &self.label,
            self.role.as_str(),
            &self.signature_scheme,
            &self.public_key_commitment,
            self.registered_height,
            self.rotation_nonce,
        );
        if self.participant_id != expected {
            return Err("reserve participant id mismatch".to_string());
        }
        Ok(self.participant_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReserveAttestation {
    pub attestation_id: String,
    pub participant_id: String,
    pub subject_kind: ReserveAttestationSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub context_root: String,
    pub signature_scheme: String,
    pub signature_commitment: String,
    pub weight: u64,
    pub signed_at_height: u64,
}

impl PqReserveAttestation {
    pub fn new(
        participant: &PqReserveParticipant,
        subject_kind: ReserveAttestationSubjectKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        context_root: impl Into<String>,
        signature_material: impl AsRef<str>,
        signed_at_height: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let context_root = context_root.into();
        let signature_commitment = monero_reserve_monitor_signature_root(
            &participant.participant_id,
            subject_kind.as_str(),
            &subject_id,
            &subject_root,
            signature_material.as_ref(),
        );
        let attestation_id = monero_reserve_monitor_attestation_id(
            &participant.participant_id,
            subject_kind.as_str(),
            &subject_id,
            &subject_root,
            signed_at_height,
        );
        let attestation = Self {
            attestation_id,
            participant_id: participant.participant_id.clone(),
            subject_kind,
            subject_id,
            subject_root,
            context_root,
            signature_scheme: participant.signature_scheme.clone(),
            signature_commitment,
            weight: participant.weight,
            signed_at_height,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_reserve_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "participant_id": self.participant_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "context_root": self.context_root,
            "signature_scheme": self.signature_scheme,
            "signature_commitment": self.signature_commitment,
            "weight": self.weight,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-PQ-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn subject_matches(
        &self,
        subject_kind: ReserveAttestationSubjectKind,
        subject_id: &str,
        subject_root: &str,
    ) -> bool {
        self.subject_kind == subject_kind
            && self.subject_id == subject_id
            && self.subject_root == subject_root
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.attestation_id, "reserve attestation id")?;
        ensure_non_empty(&self.participant_id, "reserve attestation participant id")?;
        ensure_non_empty(&self.subject_id, "reserve attestation subject id")?;
        ensure_non_empty(&self.subject_root, "reserve attestation subject root")?;
        ensure_non_empty(&self.context_root, "reserve attestation context root")?;
        ensure_non_empty(
            &self.signature_scheme,
            "reserve attestation signature scheme",
        )?;
        ensure_non_empty(
            &self.signature_commitment,
            "reserve attestation signature commitment",
        )?;
        ensure_positive(self.weight, "reserve attestation weight")?;
        let expected = monero_reserve_monitor_attestation_id(
            &self.participant_id,
            self.subject_kind.as_str(),
            &self.subject_id,
            &self.subject_root,
            self.signed_at_height,
        );
        if self.attestation_id != expected {
            return Err("reserve attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveWalletCommitment {
    pub wallet_id: String,
    pub label: String,
    pub role: ReserveWalletRole,
    pub status: ReserveWalletStatus,
    pub account_commitment: String,
    pub address_set_root: String,
    pub view_key_commitment: String,
    pub spend_authority_root: String,
    pub privacy_policy_root: String,
    pub min_confirmations: u64,
    pub registered_height: u64,
    pub rotation_nonce: u64,
    pub tags: BTreeSet<String>,
}

impl ReserveWalletCommitment {
    pub fn new(
        label: impl Into<String>,
        role: ReserveWalletRole,
        account_material: impl AsRef<str>,
        address_labels: &[String],
        view_key_material: impl AsRef<str>,
        spend_authority_material: impl AsRef<str>,
        min_confirmations: u64,
        registered_height: u64,
        rotation_nonce: u64,
        tags: &[String],
    ) -> MoneroReserveMonitorResult<Self> {
        let label = label.into();
        let account_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-WALLET-ACCOUNT",
            account_material.as_ref(),
        );
        let address_set_root = monero_reserve_monitor_string_set_root(
            "MONERO-RESERVE-MONITOR-WALLET-ADDRESSES",
            address_labels,
        );
        let view_key_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-WALLET-VIEW-KEY",
            view_key_material.as_ref(),
        );
        let spend_authority_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-WALLET-SPEND-AUTHORITY",
            spend_authority_material.as_ref(),
        );
        let tag_set = ordered_string_set(tags);
        let tag_values = tag_set.iter().cloned().collect::<Vec<_>>();
        let privacy_policy_root = monero_reserve_monitor_string_set_root(
            "MONERO-RESERVE-MONITOR-WALLET-PRIVACY-POLICY",
            &tag_values,
        );
        let wallet_id = monero_reserve_monitor_wallet_id(
            &label,
            role.as_str(),
            &account_commitment,
            &address_set_root,
            registered_height,
            rotation_nonce,
        );
        let wallet = Self {
            wallet_id,
            label,
            role,
            status: ReserveWalletStatus::Active,
            account_commitment,
            address_set_root,
            view_key_commitment,
            spend_authority_root,
            privacy_policy_root,
            min_confirmations,
            registered_height,
            rotation_nonce,
            tags: tag_set,
        };
        wallet.validate()?;
        Ok(wallet)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_wallet_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "wallet_id": self.wallet_id,
            "label": self.label,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "account_commitment": self.account_commitment,
            "address_set_root": self.address_set_root,
            "view_key_commitment": self.view_key_commitment,
            "spend_authority_root": self.spend_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "min_confirmations": self.min_confirmations,
            "registered_height": self.registered_height,
            "rotation_nonce": self.rotation_nonce,
            "tags": self.tags,
        })
    }

    pub fn wallet_root(&self) -> String {
        monero_reserve_monitor_payload_root("MONERO-RESERVE-MONITOR-WALLET", &self.public_record())
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.wallet_id, "reserve wallet id")?;
        ensure_non_empty(&self.label, "reserve wallet label")?;
        ensure_non_empty(
            &self.account_commitment,
            "reserve wallet account commitment",
        )?;
        ensure_non_empty(&self.address_set_root, "reserve wallet address set root")?;
        ensure_non_empty(
            &self.view_key_commitment,
            "reserve wallet view key commitment",
        )?;
        ensure_non_empty(
            &self.spend_authority_root,
            "reserve wallet spend authority root",
        )?;
        ensure_non_empty(
            &self.privacy_policy_root,
            "reserve wallet privacy policy root",
        )?;
        ensure_positive(self.min_confirmations, "reserve wallet confirmations")?;
        ensure_string_set(&self.tags, "reserve wallet tag")?;
        let expected = monero_reserve_monitor_wallet_id(
            &self.label,
            self.role.as_str(),
            &self.account_commitment,
            &self.address_set_root,
            self.registered_height,
            self.rotation_nonce,
        );
        if self.wallet_id != expected {
            return Err("reserve wallet id mismatch".to_string());
        }
        Ok(self.wallet_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonObserver {
    pub observer_id: String,
    pub label: String,
    pub role: DaemonObserverRole,
    pub network: String,
    pub endpoint_commitment: String,
    pub participant_id: String,
    pub weight: u64,
    pub registered_height: u64,
    pub max_height_lag: u64,
    pub active: bool,
}

impl DaemonObserver {
    pub fn new(
        label: impl Into<String>,
        role: DaemonObserverRole,
        network: impl Into<String>,
        endpoint_material: impl AsRef<str>,
        participant_id: impl Into<String>,
        weight: u64,
        registered_height: u64,
        max_height_lag: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let label = label.into();
        let network = network.into();
        let participant_id = participant_id.into();
        let endpoint_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-DAEMON-ENDPOINT",
            endpoint_material.as_ref(),
        );
        let observer_id = monero_reserve_monitor_daemon_observer_id(
            &label,
            role.as_str(),
            &network,
            &endpoint_commitment,
            &participant_id,
            registered_height,
        );
        let observer = Self {
            observer_id,
            label,
            role,
            network,
            endpoint_commitment,
            participant_id,
            weight,
            registered_height,
            max_height_lag,
            active: true,
        };
        observer.validate()?;
        Ok(observer)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_observer",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "observer_id": self.observer_id,
            "label": self.label,
            "role": self.role.as_str(),
            "network": self.network,
            "endpoint_commitment": self.endpoint_commitment,
            "participant_id": self.participant_id,
            "weight": self.weight,
            "registered_height": self.registered_height,
            "max_height_lag": self.max_height_lag,
            "active": self.active,
        })
    }

    pub fn observer_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-DAEMON-OBSERVER",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.observer_id, "daemon observer id")?;
        ensure_non_empty(&self.label, "daemon observer label")?;
        ensure_non_empty(&self.network, "daemon observer network")?;
        ensure_non_empty(
            &self.endpoint_commitment,
            "daemon observer endpoint commitment",
        )?;
        ensure_non_empty(&self.participant_id, "daemon observer participant id")?;
        ensure_positive(self.weight, "daemon observer weight")?;
        ensure_positive(self.max_height_lag, "daemon observer height lag")?;
        let expected = monero_reserve_monitor_daemon_observer_id(
            &self.label,
            self.role.as_str(),
            &self.network,
            &self.endpoint_commitment,
            &self.participant_id,
            self.registered_height,
        );
        if self.observer_id != expected {
            return Err("daemon observer id mismatch".to_string());
        }
        Ok(self.observer_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonReserveObservation {
    pub observation_id: String,
    pub observer_id: String,
    pub network: String,
    pub monero_height: u64,
    pub block_hash: String,
    pub cumulative_difficulty_root: String,
    pub tx_pool_digest: String,
    pub output_scan_root: String,
    pub key_image_scan_root: String,
    pub fee_estimate_piconero_per_kb: u64,
    pub observed_at_l2_height: u64,
    pub status: DaemonObservationStatus,
}

impl DaemonReserveObservation {
    pub fn new(
        observer_id: impl Into<String>,
        network: impl Into<String>,
        monero_height: u64,
        block_hash: impl Into<String>,
        cumulative_difficulty_material: impl AsRef<str>,
        tx_pool_material: impl AsRef<str>,
        output_scan_root: impl Into<String>,
        key_image_scan_root: impl Into<String>,
        fee_estimate_piconero_per_kb: u64,
        observed_at_l2_height: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let observer_id = observer_id.into();
        let network = network.into();
        let block_hash = block_hash.into();
        let output_scan_root = output_scan_root.into();
        let key_image_scan_root = key_image_scan_root.into();
        let cumulative_difficulty_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-CUMULATIVE-DIFFICULTY",
            cumulative_difficulty_material.as_ref(),
        );
        let tx_pool_digest = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-TX-POOL",
            tx_pool_material.as_ref(),
        );
        let observation_id = monero_reserve_monitor_daemon_observation_id(
            &observer_id,
            &network,
            monero_height,
            &block_hash,
            &output_scan_root,
            &key_image_scan_root,
        );
        let observation = Self {
            observation_id,
            observer_id,
            network,
            monero_height,
            block_hash,
            cumulative_difficulty_root,
            tx_pool_digest,
            output_scan_root,
            key_image_scan_root,
            fee_estimate_piconero_per_kb,
            observed_at_l2_height,
            status: DaemonObservationStatus::Pending,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn set_height(&mut self, l2_height: u64, stale_after_blocks: u64) {
        if self.status.is_live()
            && l2_height
                > self
                    .observed_at_l2_height
                    .saturating_add(stale_after_blocks)
        {
            self.status = DaemonObservationStatus::Stale;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_reserve_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "observer_id": self.observer_id,
            "network": self.network,
            "monero_height": self.monero_height,
            "block_hash": self.block_hash,
            "cumulative_difficulty_root": self.cumulative_difficulty_root,
            "tx_pool_digest": self.tx_pool_digest,
            "output_scan_root": self.output_scan_root,
            "key_image_scan_root": self.key_image_scan_root,
            "fee_estimate_piconero_per_kb": self.fee_estimate_piconero_per_kb,
            "observed_at_l2_height": self.observed_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn observation_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-DAEMON-OBSERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.observation_id, "daemon observation id")?;
        ensure_non_empty(&self.observer_id, "daemon observation observer id")?;
        ensure_non_empty(&self.network, "daemon observation network")?;
        ensure_non_empty(&self.block_hash, "daemon observation block hash")?;
        ensure_non_empty(
            &self.cumulative_difficulty_root,
            "daemon observation difficulty root",
        )?;
        ensure_non_empty(&self.tx_pool_digest, "daemon observation tx pool digest")?;
        ensure_non_empty(&self.output_scan_root, "daemon observation output root")?;
        ensure_non_empty(
            &self.key_image_scan_root,
            "daemon observation key image root",
        )?;
        let expected = monero_reserve_monitor_daemon_observation_id(
            &self.observer_id,
            &self.network,
            self.monero_height,
            &self.block_hash,
            &self.output_scan_root,
            &self.key_image_scan_root,
        );
        if self.observation_id != expected {
            return Err("daemon observation id mismatch".to_string());
        }
        Ok(self.observation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonObservationQuorum {
    pub quorum_id: String,
    pub network: String,
    pub monero_height: u64,
    pub canonical_block_hash: String,
    pub observation_ids: BTreeSet<String>,
    pub observer_ids: BTreeSet<String>,
    pub quorum_weight: u64,
    pub required_weight: u64,
    pub formed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: DaemonQuorumStatus,
}

impl DaemonObservationQuorum {
    pub fn new(
        network: impl Into<String>,
        monero_height: u64,
        canonical_block_hash: impl Into<String>,
        observation_ids: &[String],
        observer_ids: &[String],
        quorum_weight: u64,
        required_weight: u64,
        formed_at_l2_height: u64,
        expires_at_l2_height: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let network = network.into();
        let canonical_block_hash = canonical_block_hash.into();
        let observation_set = ordered_string_set(observation_ids);
        let observer_set = ordered_string_set(observer_ids);
        let observation_values = observation_set.iter().cloned().collect::<Vec<_>>();
        let observer_values = observer_set.iter().cloned().collect::<Vec<_>>();
        let quorum_id = monero_reserve_monitor_daemon_quorum_id(
            &network,
            monero_height,
            &canonical_block_hash,
            &monero_reserve_monitor_string_set_root(
                "MONERO-RESERVE-MONITOR-QUORUM-OBSERVATION-IDS",
                &observation_values,
            ),
            &monero_reserve_monitor_string_set_root(
                "MONERO-RESERVE-MONITOR-QUORUM-OBSERVER-IDS",
                &observer_values,
            ),
            formed_at_l2_height,
        );
        let status = if quorum_weight >= required_weight {
            DaemonQuorumStatus::Confirmed
        } else {
            DaemonQuorumStatus::Pending
        };
        let quorum = Self {
            quorum_id,
            network,
            monero_height,
            canonical_block_hash,
            observation_ids: observation_set,
            observer_ids: observer_set,
            quorum_weight,
            required_weight,
            formed_at_l2_height,
            expires_at_l2_height,
            status,
        };
        quorum.validate()?;
        Ok(quorum)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == DaemonQuorumStatus::Pending && height > self.expires_at_l2_height {
            self.status = DaemonQuorumStatus::Expired;
        }
    }

    pub fn observation_id_root(&self) -> String {
        monero_reserve_monitor_string_set_root(
            "MONERO-RESERVE-MONITOR-QUORUM-OBSERVATION-IDS",
            &self.observation_ids.iter().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn observer_id_root(&self) -> String {
        monero_reserve_monitor_string_set_root(
            "MONERO-RESERVE-MONITOR-QUORUM-OBSERVER-IDS",
            &self.observer_ids.iter().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_observation_quorum",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "quorum_id": self.quorum_id,
            "network": self.network,
            "monero_height": self.monero_height,
            "canonical_block_hash": self.canonical_block_hash,
            "observation_ids": self.observation_ids,
            "observer_ids": self.observer_ids,
            "observation_id_root": self.observation_id_root(),
            "observer_id_root": self.observer_id_root(),
            "quorum_weight": self.quorum_weight,
            "required_weight": self.required_weight,
            "formed_at_l2_height": self.formed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn quorum_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-DAEMON-QUORUM",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.quorum_id, "daemon quorum id")?;
        ensure_non_empty(&self.network, "daemon quorum network")?;
        ensure_non_empty(&self.canonical_block_hash, "daemon quorum block hash")?;
        ensure_string_set(&self.observation_ids, "daemon quorum observation id")?;
        ensure_string_set(&self.observer_ids, "daemon quorum observer id")?;
        ensure_positive(self.required_weight, "daemon quorum required weight")?;
        if self.expires_at_l2_height < self.formed_at_l2_height {
            return Err("daemon quorum expiry precedes formation".to_string());
        }
        let expected = monero_reserve_monitor_daemon_quorum_id(
            &self.network,
            self.monero_height,
            &self.canonical_block_hash,
            &self.observation_id_root(),
            &self.observer_id_root(),
            self.formed_at_l2_height,
        );
        if self.quorum_id != expected {
            return Err("daemon quorum id mismatch".to_string());
        }
        if self.status == DaemonQuorumStatus::Confirmed && self.quorum_weight < self.required_weight
        {
            return Err("confirmed daemon quorum has insufficient weight".to_string());
        }
        Ok(self.quorum_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveOutputObservation {
    pub output_id: String,
    pub wallet_id: String,
    pub daemon_quorum_id: String,
    pub monero_txid_commitment: String,
    pub output_index: u64,
    pub output_public_key_commitment: String,
    pub one_time_address_commitment: String,
    pub amount_commitment: String,
    pub amount_bucket_piconero: u64,
    pub unlock_height: u64,
    pub observed_monero_height: u64,
    pub confirmations: u64,
    pub output_membership_root: String,
    pub status: ReserveOutputStatus,
}

impl ReserveOutputObservation {
    pub fn new(
        wallet_id: impl Into<String>,
        daemon_quorum_id: impl Into<String>,
        monero_txid_material: impl AsRef<str>,
        output_index: u64,
        output_public_key_material: impl AsRef<str>,
        one_time_address_material: impl AsRef<str>,
        amount_material: impl AsRef<str>,
        amount_bucket_piconero: u64,
        unlock_height: u64,
        observed_monero_height: u64,
        current_monero_height: u64,
        output_membership_material: impl AsRef<str>,
        min_confirmations: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let wallet_id = wallet_id.into();
        let daemon_quorum_id = daemon_quorum_id.into();
        let monero_txid_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-OUTPUT-TXID",
            monero_txid_material.as_ref(),
        );
        let output_public_key_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-OUTPUT-PUBLIC-KEY",
            output_public_key_material.as_ref(),
        );
        let one_time_address_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-ONE-TIME-ADDRESS",
            one_time_address_material.as_ref(),
        );
        let amount_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-AMOUNT-COMMITMENT",
            amount_material.as_ref(),
        );
        let output_membership_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-OUTPUT-MEMBERSHIP",
            output_membership_material.as_ref(),
        );
        let confirmations = confirmations(current_monero_height, observed_monero_height);
        let status = if confirmations >= min_confirmations {
            ReserveOutputStatus::ConfirmedUnspent
        } else {
            ReserveOutputStatus::Candidate
        };
        let output_id = monero_reserve_monitor_output_observation_id(
            &wallet_id,
            &daemon_quorum_id,
            &monero_txid_commitment,
            output_index,
            &output_public_key_commitment,
        );
        let output = Self {
            output_id,
            wallet_id,
            daemon_quorum_id,
            monero_txid_commitment,
            output_index,
            output_public_key_commitment,
            one_time_address_commitment,
            amount_commitment,
            amount_bucket_piconero,
            unlock_height,
            observed_monero_height,
            confirmations,
            output_membership_root,
            status,
        };
        output.validate()?;
        Ok(output)
    }

    pub fn reserve_value_piconero(&self) -> u64 {
        if self.status.counts_as_reserve() {
            self.amount_bucket_piconero
        } else {
            0
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_output_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "output_id": self.output_id,
            "wallet_id": self.wallet_id,
            "daemon_quorum_id": self.daemon_quorum_id,
            "monero_txid_commitment": self.monero_txid_commitment,
            "output_index": self.output_index,
            "output_public_key_commitment": self.output_public_key_commitment,
            "one_time_address_commitment": self.one_time_address_commitment,
            "amount_commitment": self.amount_commitment,
            "amount_bucket_piconero": self.amount_bucket_piconero,
            "unlock_height": self.unlock_height,
            "observed_monero_height": self.observed_monero_height,
            "confirmations": self.confirmations,
            "output_membership_root": self.output_membership_root,
            "status": self.status.as_str(),
        })
    }

    pub fn output_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-OUTPUT-OBSERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.output_id, "reserve output id")?;
        ensure_non_empty(&self.wallet_id, "reserve output wallet id")?;
        ensure_non_empty(&self.daemon_quorum_id, "reserve output daemon quorum id")?;
        ensure_non_empty(
            &self.monero_txid_commitment,
            "reserve output txid commitment",
        )?;
        ensure_non_empty(
            &self.output_public_key_commitment,
            "reserve output public key commitment",
        )?;
        ensure_non_empty(
            &self.one_time_address_commitment,
            "reserve output one-time address commitment",
        )?;
        ensure_non_empty(&self.amount_commitment, "reserve output amount commitment")?;
        ensure_positive(self.amount_bucket_piconero, "reserve output amount bucket")?;
        ensure_non_empty(
            &self.output_membership_root,
            "reserve output membership root",
        )?;
        let expected = monero_reserve_monitor_output_observation_id(
            &self.wallet_id,
            &self.daemon_quorum_id,
            &self.monero_txid_commitment,
            self.output_index,
            &self.output_public_key_commitment,
        );
        if self.output_id != expected {
            return Err("reserve output id mismatch".to_string());
        }
        Ok(self.output_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveKeyImageObservation {
    pub key_image_id: String,
    pub wallet_id: String,
    pub output_id: Option<String>,
    pub daemon_quorum_id: String,
    pub key_image_commitment: String,
    pub spend_txid_commitment: Option<String>,
    pub first_seen_monero_height: u64,
    pub observed_at_l2_height: u64,
    pub status: KeyImageStatus,
    pub observer_evidence_root: String,
}

impl ReserveKeyImageObservation {
    pub fn new_absence(
        wallet_id: impl Into<String>,
        output_id: Option<String>,
        daemon_quorum_id: impl Into<String>,
        key_image_material: impl AsRef<str>,
        first_seen_monero_height: u64,
        observed_at_l2_height: u64,
        observer_evidence_material: impl AsRef<str>,
    ) -> MoneroReserveMonitorResult<Self> {
        Self::new(
            wallet_id,
            output_id,
            daemon_quorum_id,
            key_image_material,
            None,
            first_seen_monero_height,
            observed_at_l2_height,
            KeyImageStatus::NotSeen,
            observer_evidence_material,
        )
    }

    pub fn new_spend(
        wallet_id: impl Into<String>,
        output_id: Option<String>,
        daemon_quorum_id: impl Into<String>,
        key_image_material: impl AsRef<str>,
        spend_txid_material: impl AsRef<str>,
        first_seen_monero_height: u64,
        observed_at_l2_height: u64,
        observer_evidence_material: impl AsRef<str>,
    ) -> MoneroReserveMonitorResult<Self> {
        let spend_txid_commitment = Some(monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-SPEND-TXID",
            spend_txid_material.as_ref(),
        ));
        Self::new(
            wallet_id,
            output_id,
            daemon_quorum_id,
            key_image_material,
            spend_txid_commitment,
            first_seen_monero_height,
            observed_at_l2_height,
            KeyImageStatus::QuorumSpent,
            observer_evidence_material,
        )
    }

    fn new(
        wallet_id: impl Into<String>,
        output_id: Option<String>,
        daemon_quorum_id: impl Into<String>,
        key_image_material: impl AsRef<str>,
        spend_txid_commitment: Option<String>,
        first_seen_monero_height: u64,
        observed_at_l2_height: u64,
        status: KeyImageStatus,
        observer_evidence_material: impl AsRef<str>,
    ) -> MoneroReserveMonitorResult<Self> {
        let wallet_id = wallet_id.into();
        let daemon_quorum_id = daemon_quorum_id.into();
        let key_image_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-KEY-IMAGE",
            key_image_material.as_ref(),
        );
        let observer_evidence_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-KEY-IMAGE-EVIDENCE",
            observer_evidence_material.as_ref(),
        );
        let key_image_id = monero_reserve_monitor_key_image_observation_id(
            &wallet_id,
            output_id.as_deref(),
            &daemon_quorum_id,
            &key_image_commitment,
            first_seen_monero_height,
        );
        let observation = Self {
            key_image_id,
            wallet_id,
            output_id,
            daemon_quorum_id,
            key_image_commitment,
            spend_txid_commitment,
            first_seen_monero_height,
            observed_at_l2_height,
            status,
            observer_evidence_root,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_key_image_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "key_image_id": self.key_image_id,
            "wallet_id": self.wallet_id,
            "output_id": self.output_id,
            "daemon_quorum_id": self.daemon_quorum_id,
            "key_image_commitment": self.key_image_commitment,
            "spend_txid_commitment": self.spend_txid_commitment,
            "first_seen_monero_height": self.first_seen_monero_height,
            "observed_at_l2_height": self.observed_at_l2_height,
            "status": self.status.as_str(),
            "observer_evidence_root": self.observer_evidence_root,
        })
    }

    pub fn key_image_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-KEY-IMAGE-OBSERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.key_image_id, "reserve key image id")?;
        ensure_non_empty(&self.wallet_id, "reserve key image wallet id")?;
        ensure_non_empty(&self.daemon_quorum_id, "reserve key image daemon quorum id")?;
        ensure_non_empty(&self.key_image_commitment, "reserve key image commitment")?;
        ensure_non_empty(
            &self.observer_evidence_root,
            "reserve key image evidence root",
        )?;
        if self.status.is_spent() && self.spend_txid_commitment.is_none() {
            return Err("spent key image requires spend txid commitment".to_string());
        }
        if let Some(spend_txid_commitment) = &self.spend_txid_commitment {
            ensure_non_empty(spend_txid_commitment, "reserve key image spend txid")?;
        }
        let expected = monero_reserve_monitor_key_image_observation_id(
            &self.wallet_id,
            self.output_id.as_deref(),
            &self.daemon_quorum_id,
            &self.key_image_commitment,
            self.first_seen_monero_height,
        );
        if self.key_image_id != expected {
            return Err("reserve key image id mismatch".to_string());
        }
        Ok(self.key_image_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencyEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub network: String,
    pub asset_id: String,
    pub from_l2_height: u64,
    pub to_l2_height: u64,
    pub monero_height: u64,
    pub daemon_quorum_id: String,
    pub reserve_output_root: String,
    pub spent_key_image_root: String,
    pub liability_commitment_root: String,
    pub reserve_amount_bucket_piconero: u64,
    pub liability_amount_bucket_piconero: u64,
    pub coverage_bps: u64,
    pub min_coverage_bps: u64,
    pub target_coverage_bps: u64,
    pub emergency_coverage_bps: u64,
    pub risk: ReserveSolvencyRisk,
    pub status: SolvencyEpochStatus,
    pub proof_request_id: Option<String>,
    pub proof_receipt_id: Option<String>,
    pub public_summary_id: Option<String>,
}

impl SolvencyEpoch {
    pub fn new(
        epoch_index: u64,
        network: impl Into<String>,
        asset_id: impl Into<String>,
        from_l2_height: u64,
        to_l2_height: u64,
        monero_height: u64,
        daemon_quorum_id: impl Into<String>,
        reserve_output_root: impl Into<String>,
        spent_key_image_root: impl Into<String>,
        liability_commitment_root: impl Into<String>,
        reserve_amount_bucket_piconero: u64,
        liability_amount_bucket_piconero: u64,
        min_coverage_bps: u64,
        target_coverage_bps: u64,
        emergency_coverage_bps: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let network = network.into();
        let asset_id = asset_id.into();
        let daemon_quorum_id = daemon_quorum_id.into();
        let reserve_output_root = reserve_output_root.into();
        let spent_key_image_root = spent_key_image_root.into();
        let liability_commitment_root = liability_commitment_root.into();
        let coverage_bps = ratio_bps(
            reserve_amount_bucket_piconero,
            liability_amount_bucket_piconero,
        );
        let risk = ReserveSolvencyRisk::from_coverage(
            coverage_bps,
            min_coverage_bps,
            target_coverage_bps,
            emergency_coverage_bps,
        );
        let status = risk.epoch_status();
        let epoch_id = monero_reserve_monitor_solvency_epoch_id(
            epoch_index,
            &network,
            &asset_id,
            from_l2_height,
            to_l2_height,
            monero_height,
            &daemon_quorum_id,
            &reserve_output_root,
            &liability_commitment_root,
        );
        let epoch = Self {
            epoch_id,
            epoch_index,
            network,
            asset_id,
            from_l2_height,
            to_l2_height,
            monero_height,
            daemon_quorum_id,
            reserve_output_root,
            spent_key_image_root,
            liability_commitment_root,
            reserve_amount_bucket_piconero,
            liability_amount_bucket_piconero,
            coverage_bps,
            min_coverage_bps,
            target_coverage_bps,
            emergency_coverage_bps,
            risk,
            status,
            proof_request_id: None,
            proof_receipt_id: None,
            public_summary_id: None,
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn deficit_to_minimum_piconero(&self) -> u64 {
        required_for_minimum(self.liability_amount_bucket_piconero, self.min_coverage_bps)
            .saturating_sub(self.reserve_amount_bucket_piconero)
    }

    pub fn buffer_to_target_piconero(&self) -> u64 {
        required_for_minimum(
            self.liability_amount_bucket_piconero,
            self.target_coverage_bps,
        )
        .saturating_sub(self.reserve_amount_bucket_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solvency_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "network": self.network,
            "asset_id": self.asset_id,
            "from_l2_height": self.from_l2_height,
            "to_l2_height": self.to_l2_height,
            "monero_height": self.monero_height,
            "daemon_quorum_id": self.daemon_quorum_id,
            "reserve_output_root": self.reserve_output_root,
            "spent_key_image_root": self.spent_key_image_root,
            "liability_commitment_root": self.liability_commitment_root,
            "reserve_amount_bucket_piconero": self.reserve_amount_bucket_piconero,
            "liability_amount_bucket_piconero": self.liability_amount_bucket_piconero,
            "coverage_bps": self.coverage_bps,
            "min_coverage_bps": self.min_coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "emergency_coverage_bps": self.emergency_coverage_bps,
            "risk": self.risk.as_str(),
            "status": self.status.as_str(),
            "proof_request_id": self.proof_request_id,
            "proof_receipt_id": self.proof_receipt_id,
            "public_summary_id": self.public_summary_id,
        })
    }

    pub fn epoch_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-SOLVENCY-EPOCH",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.epoch_id, "solvency epoch id")?;
        ensure_non_empty(&self.network, "solvency epoch network")?;
        ensure_non_empty(&self.asset_id, "solvency epoch asset id")?;
        ensure_non_empty(&self.daemon_quorum_id, "solvency epoch daemon quorum id")?;
        ensure_non_empty(&self.reserve_output_root, "solvency epoch output root")?;
        ensure_non_empty(
            &self.spent_key_image_root,
            "solvency epoch spent key image root",
        )?;
        ensure_non_empty(
            &self.liability_commitment_root,
            "solvency epoch liability root",
        )?;
        ensure_positive(
            self.reserve_amount_bucket_piconero,
            "solvency epoch reserve amount",
        )?;
        ensure_positive(
            self.liability_amount_bucket_piconero,
            "solvency epoch liability amount",
        )?;
        ensure_bps(self.min_coverage_bps, "solvency epoch minimum coverage")?;
        ensure_bps(self.target_coverage_bps, "solvency epoch target coverage")?;
        ensure_bps(
            self.emergency_coverage_bps,
            "solvency epoch emergency coverage",
        )?;
        if self.from_l2_height > self.to_l2_height {
            return Err("solvency epoch height range is inverted".to_string());
        }
        let expected_coverage = ratio_bps(
            self.reserve_amount_bucket_piconero,
            self.liability_amount_bucket_piconero,
        );
        if self.coverage_bps != expected_coverage {
            return Err("solvency epoch coverage mismatch".to_string());
        }
        let expected_risk = ReserveSolvencyRisk::from_coverage(
            self.coverage_bps,
            self.min_coverage_bps,
            self.target_coverage_bps,
            self.emergency_coverage_bps,
        );
        if self.risk != expected_risk {
            return Err("solvency epoch risk mismatch".to_string());
        }
        let expected = monero_reserve_monitor_solvency_epoch_id(
            self.epoch_index,
            &self.network,
            &self.asset_id,
            self.from_l2_height,
            self.to_l2_height,
            self.monero_height,
            &self.daemon_quorum_id,
            &self.reserve_output_root,
            &self.liability_commitment_root,
        );
        if self.epoch_id != expected {
            return Err("solvency epoch id mismatch".to_string());
        }
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofRequest {
    pub request_id: String,
    pub kind: ReserveProofRequestKind,
    pub subject_id: String,
    pub subject_root: String,
    pub requester_commitment: String,
    pub sponsor_id: Option<String>,
    pub privacy_budget_root: String,
    pub requested_at_height: u64,
    pub due_height: u64,
    pub max_fee_piconero: u64,
    pub status: ReserveProofRequestStatus,
}

impl ReserveProofRequest {
    pub fn new(
        kind: ReserveProofRequestKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        requester_material: impl AsRef<str>,
        sponsor_id: Option<String>,
        privacy_budget_material: impl AsRef<str>,
        requested_at_height: u64,
        due_height: u64,
        max_fee_piconero: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let requester_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PROOF-REQUESTER",
            requester_material.as_ref(),
        );
        let privacy_budget_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PROOF-PRIVACY-BUDGET",
            privacy_budget_material.as_ref(),
        );
        let request_id = monero_reserve_monitor_proof_request_id(
            kind.as_str(),
            &subject_id,
            &subject_root,
            &requester_commitment,
            requested_at_height,
        );
        let status = if sponsor_id.is_some() {
            ReserveProofRequestStatus::Sponsored
        } else {
            ReserveProofRequestStatus::Requested
        };
        let request = Self {
            request_id,
            kind,
            subject_id,
            subject_root,
            requester_commitment,
            sponsor_id,
            privacy_budget_root,
            requested_at_height,
            due_height,
            max_fee_piconero,
            status,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_open() && height > self.due_height {
            self.status = ReserveProofRequestStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof_request",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "request_id": self.request_id,
            "request_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "requester_commitment": self.requester_commitment,
            "sponsor_id": self.sponsor_id,
            "privacy_budget_root": self.privacy_budget_root,
            "requested_at_height": self.requested_at_height,
            "due_height": self.due_height,
            "max_fee_piconero": self.max_fee_piconero,
            "status": self.status.as_str(),
        })
    }

    pub fn request_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-PROOF-REQUEST",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.request_id, "reserve proof request id")?;
        ensure_non_empty(&self.subject_id, "reserve proof request subject id")?;
        ensure_non_empty(&self.subject_root, "reserve proof request subject root")?;
        ensure_non_empty(
            &self.requester_commitment,
            "reserve proof request requester commitment",
        )?;
        ensure_non_empty(
            &self.privacy_budget_root,
            "reserve proof request privacy budget",
        )?;
        if self.due_height < self.requested_at_height {
            return Err("reserve proof request due height precedes request".to_string());
        }
        let expected = monero_reserve_monitor_proof_request_id(
            self.kind.as_str(),
            &self.subject_id,
            &self.subject_root,
            &self.requester_commitment,
            self.requested_at_height,
        );
        if self.request_id != expected {
            return Err("reserve proof request id mismatch".to_string());
        }
        Ok(self.request_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub prover_commitment: String,
    pub proof_system: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub verification_key_root: String,
    pub submitted_height: u64,
    pub verified_height: Option<u64>,
    pub fee_paid_piconero: u64,
    pub status: ReserveProofReceiptStatus,
    pub attestation_root: String,
}

impl ReserveProofReceipt {
    pub fn new(
        request_id: impl Into<String>,
        prover_material: impl AsRef<str>,
        proof_system: impl Into<String>,
        proof_material: impl AsRef<str>,
        public_input_material: impl AsRef<str>,
        verification_key_material: impl AsRef<str>,
        submitted_height: u64,
        verified_height: Option<u64>,
        fee_paid_piconero: u64,
        attestation_root: impl Into<String>,
    ) -> MoneroReserveMonitorResult<Self> {
        let request_id = request_id.into();
        let proof_system = proof_system.into();
        let prover_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PROOF-PROVER",
            prover_material.as_ref(),
        );
        let proof_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PROOF-ROOT",
            proof_material.as_ref(),
        );
        let public_input_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PROOF-PUBLIC-INPUT",
            public_input_material.as_ref(),
        );
        let verification_key_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PROOF-VERIFICATION-KEY",
            verification_key_material.as_ref(),
        );
        let receipt_id = monero_reserve_monitor_proof_receipt_id(
            &request_id,
            &prover_commitment,
            &proof_system,
            &proof_root,
            submitted_height,
        );
        let status = if verified_height.is_some() {
            ReserveProofReceiptStatus::Verified
        } else {
            ReserveProofReceiptStatus::Submitted
        };
        let receipt = Self {
            receipt_id,
            request_id,
            prover_commitment,
            proof_system,
            proof_root,
            public_input_root,
            verification_key_root,
            submitted_height,
            verified_height,
            fee_paid_piconero,
            status,
            attestation_root: attestation_root.into(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_proof_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "prover_commitment": self.prover_commitment,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "public_input_root": self.public_input_root,
            "verification_key_root": self.verification_key_root,
            "submitted_height": self.submitted_height,
            "verified_height": self.verified_height,
            "fee_paid_piconero": self.fee_paid_piconero,
            "status": self.status.as_str(),
            "attestation_root": self.attestation_root,
        })
    }

    pub fn receipt_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-PROOF-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.receipt_id, "reserve proof receipt id")?;
        ensure_non_empty(&self.request_id, "reserve proof receipt request id")?;
        ensure_non_empty(
            &self.prover_commitment,
            "reserve proof receipt prover commitment",
        )?;
        ensure_non_empty(&self.proof_system, "reserve proof receipt proof system")?;
        ensure_non_empty(&self.proof_root, "reserve proof receipt proof root")?;
        ensure_non_empty(
            &self.public_input_root,
            "reserve proof receipt public input root",
        )?;
        ensure_non_empty(
            &self.verification_key_root,
            "reserve proof receipt verification key root",
        )?;
        ensure_non_empty(
            &self.attestation_root,
            "reserve proof receipt attestation root",
        )?;
        if let Some(verified_height) = self.verified_height {
            if verified_height < self.submitted_height {
                return Err("reserve proof verified before submission".to_string());
            }
        }
        if self.status.is_verified() && self.verified_height.is_none() {
            return Err("verified proof receipt requires verified height".to_string());
        }
        let expected = monero_reserve_monitor_proof_receipt_id(
            &self.request_id,
            &self.prover_commitment,
            &self.proof_system,
            &self.proof_root,
            self.submitted_height,
        );
        if self.receipt_id != expected {
            return Err("reserve proof receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeficitAlert {
    pub alert_id: String,
    pub epoch_id: String,
    pub severity: DeficitAlertSeverity,
    pub status: DeficitAlertStatus,
    pub coverage_bps: u64,
    pub minimum_coverage_bps: u64,
    pub target_coverage_bps: u64,
    pub deficit_to_minimum_piconero: u64,
    pub buffer_to_target_piconero: u64,
    pub freeze_mint: bool,
    pub require_proof_by_height: u64,
    pub opened_height: u64,
    pub message_root: String,
}

impl DeficitAlert {
    pub fn from_epoch(
        epoch: &SolvencyEpoch,
        opened_height: u64,
        require_proof_by_height: u64,
        message_material: impl AsRef<str>,
    ) -> MoneroReserveMonitorResult<Self> {
        let severity = match epoch.risk {
            ReserveSolvencyRisk::Healthy => DeficitAlertSeverity::Info,
            ReserveSolvencyRisk::BufferLow => DeficitAlertSeverity::Watch,
            ReserveSolvencyRisk::UnderCovered => DeficitAlertSeverity::Deficit,
            ReserveSolvencyRisk::Insolvent | ReserveSolvencyRisk::Unknown => {
                DeficitAlertSeverity::Critical
            }
        };
        let freeze_mint = matches!(
            severity,
            DeficitAlertSeverity::Deficit | DeficitAlertSeverity::Critical
        );
        let message_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-DEFICIT-MESSAGE",
            message_material.as_ref(),
        );
        let alert_id = monero_reserve_monitor_deficit_alert_id(
            &epoch.epoch_id,
            severity.as_str(),
            epoch.coverage_bps,
            &message_root,
            opened_height,
        );
        let alert = Self {
            alert_id,
            epoch_id: epoch.epoch_id.clone(),
            severity,
            status: DeficitAlertStatus::Open,
            coverage_bps: epoch.coverage_bps,
            minimum_coverage_bps: epoch.min_coverage_bps,
            target_coverage_bps: epoch.target_coverage_bps,
            deficit_to_minimum_piconero: epoch.deficit_to_minimum_piconero(),
            buffer_to_target_piconero: epoch.buffer_to_target_piconero(),
            freeze_mint,
            require_proof_by_height,
            opened_height,
            message_root,
        };
        alert.validate()?;
        Ok(alert)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.require_proof_by_height {
            self.status = DeficitAlertStatus::Mitigating;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deficit_alert",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "alert_id": self.alert_id,
            "epoch_id": self.epoch_id,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "coverage_bps": self.coverage_bps,
            "minimum_coverage_bps": self.minimum_coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "deficit_to_minimum_piconero": self.deficit_to_minimum_piconero,
            "buffer_to_target_piconero": self.buffer_to_target_piconero,
            "freeze_mint": self.freeze_mint,
            "require_proof_by_height": self.require_proof_by_height,
            "opened_height": self.opened_height,
            "message_root": self.message_root,
        })
    }

    pub fn alert_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-DEFICIT-ALERT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.alert_id, "deficit alert id")?;
        ensure_non_empty(&self.epoch_id, "deficit alert epoch id")?;
        ensure_bps(self.coverage_bps, "deficit alert coverage")?;
        ensure_bps(self.minimum_coverage_bps, "deficit alert minimum coverage")?;
        ensure_bps(self.target_coverage_bps, "deficit alert target coverage")?;
        ensure_non_empty(&self.message_root, "deficit alert message root")?;
        if self.require_proof_by_height < self.opened_height {
            return Err("deficit alert proof deadline precedes open height".to_string());
        }
        let expected = monero_reserve_monitor_deficit_alert_id(
            &self.epoch_id,
            self.severity.as_str(),
            self.coverage_bps,
            &self.message_root,
            self.opened_height,
        );
        if self.alert_id != expected {
            return Err("deficit alert id mismatch".to_string());
        }
        Ok(self.alert_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyMintThrottle {
    pub throttle_id: String,
    pub mode: EmergencyMintThrottleMode,
    pub reason_alert_id: Option<String>,
    pub max_mint_bps_per_window: u64,
    pub minted_bps_in_window: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub activated_height: u64,
    pub override_attestation_root: String,
}

impl EmergencyMintThrottle {
    pub fn new(
        mode: EmergencyMintThrottleMode,
        reason_alert_id: Option<String>,
        max_mint_bps_per_window: u64,
        minted_bps_in_window: u64,
        window_start_height: u64,
        window_end_height: u64,
        activated_height: u64,
        override_attestation_material: impl AsRef<str>,
    ) -> MoneroReserveMonitorResult<Self> {
        let override_attestation_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-MINT-THROTTLE-OVERRIDE",
            override_attestation_material.as_ref(),
        );
        let throttle_id = monero_reserve_monitor_mint_throttle_id(
            mode.as_str(),
            reason_alert_id.as_deref(),
            window_start_height,
            window_end_height,
            activated_height,
        );
        let throttle = Self {
            throttle_id,
            mode,
            reason_alert_id,
            max_mint_bps_per_window,
            minted_bps_in_window,
            window_start_height,
            window_end_height,
            activated_height,
            override_attestation_root,
        };
        throttle.validate()?;
        Ok(throttle)
    }

    pub fn remaining_mint_bps(&self) -> u64 {
        self.max_mint_bps_per_window
            .saturating_sub(self.minted_bps_in_window)
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.window_end_height {
            self.mode = EmergencyMintThrottleMode::Halted;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_mint_throttle",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "throttle_id": self.throttle_id,
            "mode": self.mode.as_str(),
            "reason_alert_id": self.reason_alert_id,
            "max_mint_bps_per_window": self.max_mint_bps_per_window,
            "minted_bps_in_window": self.minted_bps_in_window,
            "remaining_mint_bps": self.remaining_mint_bps(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "activated_height": self.activated_height,
            "override_attestation_root": self.override_attestation_root,
        })
    }

    pub fn throttle_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-MINT-THROTTLE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.throttle_id, "mint throttle id")?;
        ensure_bps(
            self.max_mint_bps_per_window,
            "mint throttle max mint bps per window",
        )?;
        ensure_bps(
            self.minted_bps_in_window,
            "mint throttle minted bps in window",
        )?;
        ensure_non_empty(
            &self.override_attestation_root,
            "mint throttle override attestation root",
        )?;
        if self.window_end_height < self.window_start_height {
            return Err("mint throttle window is inverted".to_string());
        }
        if self.minted_bps_in_window > self.max_mint_bps_per_window {
            return Err("mint throttle minted amount exceeds cap".to_string());
        }
        let expected = monero_reserve_monitor_mint_throttle_id(
            self.mode.as_str(),
            self.reason_alert_id.as_deref(),
            self.window_start_height,
            self.window_end_height,
            self.activated_height,
        );
        if self.throttle_id != expected {
            return Err("mint throttle id mismatch".to_string());
        }
        Ok(self.throttle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_piconero: u64,
    pub reserved_piconero: u64,
    pub spent_piconero: u64,
    pub max_fee_per_proof_piconero: u64,
    pub request_ids: BTreeSet<String>,
    pub status: LowFeeSponsorshipStatus,
    pub start_height: u64,
    pub expires_height: u64,
}

impl LowFeeProofSponsorship {
    pub fn new(
        sponsor_material: impl AsRef<str>,
        fee_asset_id: impl Into<String>,
        budget_piconero: u64,
        max_fee_per_proof_piconero: u64,
        request_ids: &[String],
        start_height: u64,
        expires_height: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let fee_asset_id = fee_asset_id.into();
        let sponsor_commitment = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PROOF-SPONSOR",
            sponsor_material.as_ref(),
        );
        let request_set = ordered_string_set(request_ids);
        let request_root = monero_reserve_monitor_string_set_root(
            "MONERO-RESERVE-MONITOR-SPONSORED-REQUESTS",
            &request_set.iter().cloned().collect::<Vec<_>>(),
        );
        let sponsorship_id = monero_reserve_monitor_low_fee_sponsorship_id(
            &sponsor_commitment,
            &fee_asset_id,
            budget_piconero,
            max_fee_per_proof_piconero,
            &request_root,
            start_height,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            fee_asset_id,
            budget_piconero,
            reserved_piconero: 0,
            spent_piconero: 0,
            max_fee_per_proof_piconero,
            request_ids: request_set,
            status: LowFeeSponsorshipStatus::Active,
            start_height,
            expires_height,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn request_root(&self) -> String {
        monero_reserve_monitor_string_set_root(
            "MONERO-RESERVE-MONITOR-SPONSORED-REQUESTS",
            &self.request_ids.iter().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn remaining_budget_piconero(&self) -> u64 {
        self.budget_piconero
            .saturating_sub(self.reserved_piconero)
            .saturating_sub(self.spent_piconero)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.expires_height {
            self.status = LowFeeSponsorshipStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "budget_piconero": self.budget_piconero,
            "reserved_piconero": self.reserved_piconero,
            "spent_piconero": self.spent_piconero,
            "remaining_budget_piconero": self.remaining_budget_piconero(),
            "max_fee_per_proof_piconero": self.max_fee_per_proof_piconero,
            "request_ids": self.request_ids,
            "request_root": self.request_root(),
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-LOW-FEE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.sponsorship_id, "low fee sponsorship id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "low fee sponsorship sponsor commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "low fee sponsorship fee asset id")?;
        ensure_positive(self.budget_piconero, "low fee sponsorship budget")?;
        ensure_positive(
            self.max_fee_per_proof_piconero,
            "low fee sponsorship max fee",
        )?;
        ensure_string_set(&self.request_ids, "low fee sponsorship request id")?;
        if self.expires_height < self.start_height {
            return Err("low fee sponsorship expiry precedes start".to_string());
        }
        if self.reserved_piconero.saturating_add(self.spent_piconero) > self.budget_piconero {
            return Err("low fee sponsorship exceeds budget".to_string());
        }
        let expected = monero_reserve_monitor_low_fee_sponsorship_id(
            &self.sponsor_commitment,
            &self.fee_asset_id,
            self.budget_piconero,
            self.max_fee_per_proof_piconero,
            &self.request_root(),
            self.start_height,
        );
        if self.sponsorship_id != expected {
            return Err("low fee sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicReserveSummary {
    pub summary_id: String,
    pub epoch_id: String,
    pub network: String,
    pub asset_id: String,
    pub coverage_band: String,
    pub coverage_floor_bps: u64,
    pub output_count_bucket: u64,
    pub spent_key_image_count_bucket: u64,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub daemon_quorum_root: String,
    pub deficit_alert_root: String,
    pub disclosure_policy_root: String,
    pub published_height: u64,
}

impl PublicReserveSummary {
    pub fn from_epoch(
        epoch: &SolvencyEpoch,
        output_count: u64,
        spent_key_image_count: u64,
        daemon_quorum_root: impl Into<String>,
        deficit_alert_root: impl Into<String>,
        disclosure_policy_material: impl AsRef<str>,
        published_height: u64,
    ) -> MoneroReserveMonitorResult<Self> {
        let coverage_floor_bps = coverage_floor_bps(epoch.coverage_bps, 100);
        let coverage_band = coverage_band(epoch.coverage_bps);
        let output_count_bucket = count_bucket(output_count, 8);
        let spent_key_image_count_bucket = count_bucket(spent_key_image_count, 4);
        let disclosure_policy_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-PUBLIC-SUMMARY-DISCLOSURE",
            disclosure_policy_material.as_ref(),
        );
        let daemon_quorum_root = daemon_quorum_root.into();
        let deficit_alert_root = deficit_alert_root.into();
        let summary_id = monero_reserve_monitor_public_summary_id(
            &epoch.epoch_id,
            &epoch.reserve_output_root,
            &epoch.liability_commitment_root,
            &daemon_quorum_root,
            coverage_floor_bps,
            published_height,
        );
        let summary = Self {
            summary_id,
            epoch_id: epoch.epoch_id.clone(),
            network: epoch.network.clone(),
            asset_id: epoch.asset_id.clone(),
            coverage_band,
            coverage_floor_bps,
            output_count_bucket,
            spent_key_image_count_bucket,
            reserve_commitment_root: epoch.reserve_output_root.clone(),
            liability_commitment_root: epoch.liability_commitment_root.clone(),
            daemon_quorum_root,
            deficit_alert_root,
            disclosure_policy_root,
            published_height,
        };
        summary.validate()?;
        Ok(summary)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_reserve_summary",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "summary_id": self.summary_id,
            "epoch_id": self.epoch_id,
            "network": self.network,
            "asset_id": self.asset_id,
            "coverage_band": self.coverage_band,
            "coverage_floor_bps": self.coverage_floor_bps,
            "output_count_bucket": self.output_count_bucket,
            "spent_key_image_count_bucket": self.spent_key_image_count_bucket,
            "reserve_commitment_root": self.reserve_commitment_root,
            "liability_commitment_root": self.liability_commitment_root,
            "daemon_quorum_root": self.daemon_quorum_root,
            "deficit_alert_root": self.deficit_alert_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "published_height": self.published_height,
        })
    }

    pub fn summary_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-PUBLIC-SUMMARY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        ensure_non_empty(&self.summary_id, "public reserve summary id")?;
        ensure_non_empty(&self.epoch_id, "public reserve summary epoch id")?;
        ensure_non_empty(&self.network, "public reserve summary network")?;
        ensure_non_empty(&self.asset_id, "public reserve summary asset id")?;
        ensure_non_empty(&self.coverage_band, "public reserve summary coverage band")?;
        ensure_bps(
            self.coverage_floor_bps,
            "public reserve summary coverage floor",
        )?;
        ensure_non_empty(
            &self.reserve_commitment_root,
            "public reserve summary reserve root",
        )?;
        ensure_non_empty(
            &self.liability_commitment_root,
            "public reserve summary liability root",
        )?;
        ensure_non_empty(
            &self.daemon_quorum_root,
            "public reserve summary daemon quorum root",
        )?;
        ensure_non_empty(
            &self.deficit_alert_root,
            "public reserve summary deficit alert root",
        )?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "public reserve summary disclosure root",
        )?;
        let expected = monero_reserve_monitor_public_summary_id(
            &self.epoch_id,
            &self.reserve_commitment_root,
            &self.liability_commitment_root,
            &self.daemon_quorum_root,
            self.coverage_floor_bps,
            self.published_height,
        );
        if self.summary_id != expected {
            return Err("public reserve summary id mismatch".to_string());
        }
        Ok(self.summary_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveMonitorCounters {
    pub height: u64,
    pub participant_count: u64,
    pub active_participant_count: u64,
    pub wallet_count: u64,
    pub active_wallet_count: u64,
    pub daemon_observer_count: u64,
    pub active_daemon_observer_count: u64,
    pub daemon_observation_count: u64,
    pub live_daemon_observation_count: u64,
    pub daemon_quorum_count: u64,
    pub usable_daemon_quorum_count: u64,
    pub output_observation_count: u64,
    pub confirmed_output_count: u64,
    pub reserve_amount_bucket_piconero: u64,
    pub key_image_observation_count: u64,
    pub spent_key_image_count: u64,
    pub solvency_epoch_count: u64,
    pub risky_epoch_count: u64,
    pub proof_request_count: u64,
    pub open_proof_request_count: u64,
    pub proof_receipt_count: u64,
    pub verified_proof_receipt_count: u64,
    pub deficit_alert_count: u64,
    pub active_deficit_alert_count: u64,
    pub mint_throttle_count: u64,
    pub active_mint_throttle_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub remaining_sponsorship_budget_piconero: u64,
    pub public_summary_count: u64,
    pub pq_attestation_count: u64,
}

impl MoneroReserveMonitorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reserve_monitor_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "height": self.height,
            "participant_count": self.participant_count,
            "active_participant_count": self.active_participant_count,
            "wallet_count": self.wallet_count,
            "active_wallet_count": self.active_wallet_count,
            "daemon_observer_count": self.daemon_observer_count,
            "active_daemon_observer_count": self.active_daemon_observer_count,
            "daemon_observation_count": self.daemon_observation_count,
            "live_daemon_observation_count": self.live_daemon_observation_count,
            "daemon_quorum_count": self.daemon_quorum_count,
            "usable_daemon_quorum_count": self.usable_daemon_quorum_count,
            "output_observation_count": self.output_observation_count,
            "confirmed_output_count": self.confirmed_output_count,
            "reserve_amount_bucket_piconero": self.reserve_amount_bucket_piconero,
            "key_image_observation_count": self.key_image_observation_count,
            "spent_key_image_count": self.spent_key_image_count,
            "solvency_epoch_count": self.solvency_epoch_count,
            "risky_epoch_count": self.risky_epoch_count,
            "proof_request_count": self.proof_request_count,
            "open_proof_request_count": self.open_proof_request_count,
            "proof_receipt_count": self.proof_receipt_count,
            "verified_proof_receipt_count": self.verified_proof_receipt_count,
            "deficit_alert_count": self.deficit_alert_count,
            "active_deficit_alert_count": self.active_deficit_alert_count,
            "mint_throttle_count": self.mint_throttle_count,
            "active_mint_throttle_count": self.active_mint_throttle_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "remaining_sponsorship_budget_piconero": self.remaining_sponsorship_budget_piconero,
            "public_summary_count": self.public_summary_count,
            "pq_attestation_count": self.pq_attestation_count,
            "counters_root": self.counters_root(),
        })
    }

    pub fn counters_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-COUNTERS",
            &json!({
                "height": self.height,
                "participant_count": self.participant_count,
                "wallet_count": self.wallet_count,
                "daemon_observer_count": self.daemon_observer_count,
                "daemon_observation_count": self.daemon_observation_count,
                "daemon_quorum_count": self.daemon_quorum_count,
                "output_observation_count": self.output_observation_count,
                "confirmed_output_count": self.confirmed_output_count,
                "reserve_amount_bucket_piconero": self.reserve_amount_bucket_piconero,
                "key_image_observation_count": self.key_image_observation_count,
                "solvency_epoch_count": self.solvency_epoch_count,
                "proof_request_count": self.proof_request_count,
                "proof_receipt_count": self.proof_receipt_count,
                "deficit_alert_count": self.deficit_alert_count,
                "mint_throttle_count": self.mint_throttle_count,
                "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
                "public_summary_count": self.public_summary_count,
                "pq_attestation_count": self.pq_attestation_count,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveMonitorRoots {
    pub config_root: String,
    pub participant_root: String,
    pub wallet_commitment_root: String,
    pub daemon_observer_root: String,
    pub daemon_observation_root: String,
    pub daemon_quorum_root: String,
    pub output_observation_root: String,
    pub key_image_observation_root: String,
    pub solvency_epoch_root: String,
    pub proof_request_root: String,
    pub proof_receipt_root: String,
    pub deficit_alert_root: String,
    pub mint_throttle_root: String,
    pub low_fee_sponsorship_root: String,
    pub public_summary_root: String,
    pub pq_attestation_root: String,
    pub counters_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl MoneroReserveMonitorRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_reserve_monitor_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "participant_root": self.participant_root,
            "wallet_commitment_root": self.wallet_commitment_root,
            "daemon_observer_root": self.daemon_observer_root,
            "daemon_observation_root": self.daemon_observation_root,
            "daemon_quorum_root": self.daemon_quorum_root,
            "output_observation_root": self.output_observation_root,
            "key_image_observation_root": self.key_image_observation_root,
            "solvency_epoch_root": self.solvency_epoch_root,
            "proof_request_root": self.proof_request_root,
            "proof_receipt_root": self.proof_receipt_root,
            "deficit_alert_root": self.deficit_alert_root,
            "mint_throttle_root": self.mint_throttle_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "public_summary_root": self.public_summary_root,
            "pq_attestation_root": self.pq_attestation_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }

    pub fn roots_root(&self) -> String {
        monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-ROOTS",
            &self.public_record_without_state_root(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveMonitorState {
    pub height: u64,
    pub network: String,
    pub config: MoneroReserveMonitorConfig,
    pub current_daemon_quorum_id: String,
    pub current_solvency_epoch_id: String,
    pub participants: BTreeMap<String, PqReserveParticipant>,
    pub wallet_commitments: BTreeMap<String, ReserveWalletCommitment>,
    pub daemon_observers: BTreeMap<String, DaemonObserver>,
    pub daemon_observations: BTreeMap<String, DaemonReserveObservation>,
    pub daemon_quorums: BTreeMap<String, DaemonObservationQuorum>,
    pub output_observations: BTreeMap<String, ReserveOutputObservation>,
    pub key_image_observations: BTreeMap<String, ReserveKeyImageObservation>,
    pub solvency_epochs: BTreeMap<String, SolvencyEpoch>,
    pub proof_requests: BTreeMap<String, ReserveProofRequest>,
    pub proof_receipts: BTreeMap<String, ReserveProofReceipt>,
    pub deficit_alerts: BTreeMap<String, DeficitAlert>,
    pub mint_throttles: BTreeMap<String, EmergencyMintThrottle>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub public_summaries: BTreeMap<String, PublicReserveSummary>,
    pub pq_attestations: BTreeMap<String, PqReserveAttestation>,
}

impl MoneroReserveMonitorState {
    pub fn new(config: MoneroReserveMonitorConfig) -> MoneroReserveMonitorResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            network: config.network.clone(),
            config,
            current_daemon_quorum_id: String::new(),
            current_solvency_epoch_id: String::new(),
            participants: BTreeMap::new(),
            wallet_commitments: BTreeMap::new(),
            daemon_observers: BTreeMap::new(),
            daemon_observations: BTreeMap::new(),
            daemon_quorums: BTreeMap::new(),
            output_observations: BTreeMap::new(),
            key_image_observations: BTreeMap::new(),
            solvency_epochs: BTreeMap::new(),
            proof_requests: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            deficit_alerts: BTreeMap::new(),
            mint_throttles: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
        })
    }

    pub fn devnet() -> MoneroReserveMonitorResult<Self> {
        let mut state = Self::new(MoneroReserveMonitorConfig::default())?;
        state.set_height(128)?;

        let operator = PqReserveParticipant::new(
            "devnet-reserve-operator",
            ReserveParticipantRole::ReserveSigner,
            MONERO_RESERVE_MONITOR_PQ_SIGNER_SCHEME,
            "devnet-reserve-operator-pq-key",
            2,
            1,
            0,
        )?;
        let observer_alpha = PqReserveParticipant::new(
            "devnet-daemon-alpha",
            ReserveParticipantRole::DaemonObserver,
            MONERO_RESERVE_MONITOR_PQ_OBSERVER_SCHEME,
            "devnet-daemon-alpha-pq-key",
            1,
            1,
            0,
        )?;
        let observer_beta = PqReserveParticipant::new(
            "devnet-daemon-beta",
            ReserveParticipantRole::DaemonObserver,
            MONERO_RESERVE_MONITOR_PQ_OBSERVER_SCHEME,
            "devnet-daemon-beta-pq-key",
            1,
            1,
            0,
        )?;
        let observer_gamma = PqReserveParticipant::new(
            "devnet-daemon-gamma",
            ReserveParticipantRole::DaemonObserver,
            MONERO_RESERVE_MONITOR_PQ_OBSERVER_SCHEME,
            "devnet-daemon-gamma-pq-key",
            1,
            1,
            0,
        )?;
        let auditor = PqReserveParticipant::new(
            "devnet-reserve-auditor",
            ReserveParticipantRole::Auditor,
            MONERO_RESERVE_MONITOR_PQ_SIGNER_SCHEME,
            "devnet-reserve-auditor-pq-key",
            1,
            1,
            0,
        )?;
        let sponsor_participant = PqReserveParticipant::new(
            "devnet-proof-sponsor",
            ReserveParticipantRole::Sponsor,
            MONERO_RESERVE_MONITOR_PQ_SIGNER_SCHEME,
            "devnet-proof-sponsor-pq-key",
            1,
            1,
            0,
        )?;

        for participant in [
            operator.clone(),
            observer_alpha.clone(),
            observer_beta.clone(),
            observer_gamma.clone(),
            auditor.clone(),
            sponsor_participant.clone(),
        ] {
            state.insert_participant(participant)?;
        }

        let reserve_wallet = ReserveWalletCommitment::new(
            "devnet-cold-reserve-wallet",
            ReserveWalletRole::ColdReserve,
            "devnet-cold-reserve-account",
            &[
                "devnet-reserve-address-a".to_string(),
                "devnet-reserve-address-b".to_string(),
                "devnet-reserve-address-c".to_string(),
            ],
            "devnet-cold-reserve-private-view-key",
            "devnet-threshold-spend-authority",
            state.config.min_confirmations,
            1,
            0,
            &[
                "no_raw_addresses_public".to_string(),
                "bucketed_amounts_only".to_string(),
                "pq_attested_rotation".to_string(),
            ],
        )?;
        let bridge_wallet = ReserveWalletCommitment::new(
            "devnet-defi-bridge-buffer",
            ReserveWalletRole::DefiBridge,
            "devnet-defi-bridge-account",
            &["devnet-bridge-buffer-address".to_string()],
            "devnet-bridge-buffer-view-key",
            "devnet-bridge-buffer-spend-authority",
            state.config.min_confirmations,
            2,
            0,
            &[
                "bridge_liquidity".to_string(),
                "low_fee_exit_buffer".to_string(),
            ],
        )?;
        state.insert_wallet_commitment(reserve_wallet.clone())?;
        state.insert_wallet_commitment(bridge_wallet.clone())?;

        state.attest_subject(
            &operator.participant_id,
            ReserveAttestationSubjectKind::WalletCommitment,
            &reserve_wallet.wallet_id,
            &reserve_wallet.wallet_root(),
            "devnet-wallet-operator-context",
            "devnet-wallet-operator-signature",
        )?;
        state.attest_subject(
            &auditor.participant_id,
            ReserveAttestationSubjectKind::WalletCommitment,
            &reserve_wallet.wallet_id,
            &reserve_wallet.wallet_root(),
            "devnet-wallet-auditor-context",
            "devnet-wallet-auditor-signature",
        )?;

        let daemon_alpha = DaemonObserver::new(
            "devnet-daemon-alpha",
            DaemonObserverRole::Primary,
            state.network.clone(),
            "http://devnet-daemon-alpha.invalid",
            observer_alpha.participant_id.clone(),
            observer_alpha.weight,
            1,
            3,
        )?;
        let daemon_beta = DaemonObserver::new(
            "devnet-daemon-beta",
            DaemonObserverRole::Independent,
            state.network.clone(),
            "http://devnet-daemon-beta.invalid",
            observer_beta.participant_id.clone(),
            observer_beta.weight,
            1,
            3,
        )?;
        let daemon_gamma = DaemonObserver::new(
            "devnet-daemon-gamma",
            DaemonObserverRole::Watchtower,
            state.network.clone(),
            "http://devnet-daemon-gamma.invalid",
            observer_gamma.participant_id.clone(),
            observer_gamma.weight,
            1,
            3,
        )?;
        state.insert_daemon_observer(daemon_alpha.clone())?;
        state.insert_daemon_observer(daemon_beta.clone())?;
        state.insert_daemon_observer(daemon_gamma.clone())?;

        let output_scan_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-DEVNET-OUTPUT-SCAN",
            "devnet-output-scan-root-120",
        );
        let key_image_scan_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-DEVNET-KEY-IMAGE-SCAN",
            "devnet-key-image-scan-root-120",
        );
        let observation_alpha = DaemonReserveObservation::new(
            daemon_alpha.observer_id.clone(),
            state.network.clone(),
            120,
            "devnet-monero-block-120",
            "devnet-cumulative-difficulty-120-a",
            "devnet-tx-pool-a",
            output_scan_root.clone(),
            key_image_scan_root.clone(),
            2_000,
            state.height,
        )?;
        let observation_beta = DaemonReserveObservation::new(
            daemon_beta.observer_id.clone(),
            state.network.clone(),
            120,
            "devnet-monero-block-120",
            "devnet-cumulative-difficulty-120-b",
            "devnet-tx-pool-b",
            output_scan_root.clone(),
            key_image_scan_root.clone(),
            2_100,
            state.height,
        )?;
        let observation_gamma = DaemonReserveObservation::new(
            daemon_gamma.observer_id.clone(),
            state.network.clone(),
            120,
            "devnet-monero-block-120",
            "devnet-cumulative-difficulty-120-c",
            "devnet-tx-pool-c",
            output_scan_root.clone(),
            key_image_scan_root.clone(),
            2_050,
            state.height,
        )?;
        state.insert_daemon_observation(observation_alpha.clone())?;
        state.insert_daemon_observation(observation_beta.clone())?;
        state.insert_daemon_observation(observation_gamma.clone())?;

        let observation_ids = vec![
            observation_alpha.observation_id.clone(),
            observation_beta.observation_id.clone(),
            observation_gamma.observation_id.clone(),
        ];
        let observer_ids = vec![
            daemon_alpha.observer_id.clone(),
            daemon_beta.observer_id.clone(),
            daemon_gamma.observer_id.clone(),
        ];
        let quorum = DaemonObservationQuorum::new(
            state.network.clone(),
            120,
            "devnet-monero-block-120",
            &observation_ids,
            &observer_ids,
            daemon_alpha
                .weight
                .saturating_add(daemon_beta.weight)
                .saturating_add(daemon_gamma.weight),
            state.config.daemon_quorum_weight,
            state.height,
            state
                .height
                .saturating_add(state.config.observer_staleness_blocks),
        )?;
        state.current_daemon_quorum_id = quorum.quorum_id.clone();
        state.insert_daemon_quorum(quorum.clone())?;
        state.mark_observations_quorum_accepted(&observation_ids)?;

        let reserve_output_a = ReserveOutputObservation::new(
            reserve_wallet.wallet_id.clone(),
            quorum.quorum_id.clone(),
            "devnet-reserve-tx-a",
            0,
            "devnet-reserve-output-key-a",
            "devnet-reserve-ota-a",
            "devnet-reserve-amount-a",
            4_000_000_000_000,
            0,
            104,
            120,
            "devnet-output-membership-a",
            state.config.min_confirmations,
        )?;
        let reserve_output_b = ReserveOutputObservation::new(
            reserve_wallet.wallet_id.clone(),
            quorum.quorum_id.clone(),
            "devnet-reserve-tx-b",
            1,
            "devnet-reserve-output-key-b",
            "devnet-reserve-ota-b",
            "devnet-reserve-amount-b",
            4_000_000_000_000,
            0,
            105,
            120,
            "devnet-output-membership-b",
            state.config.min_confirmations,
        )?;
        let reserve_output_c = ReserveOutputObservation::new(
            reserve_wallet.wallet_id.clone(),
            quorum.quorum_id.clone(),
            "devnet-reserve-tx-c",
            0,
            "devnet-reserve-output-key-c",
            "devnet-reserve-ota-c",
            "devnet-reserve-amount-c",
            2_500_000_000_000,
            0,
            106,
            120,
            "devnet-output-membership-c",
            state.config.min_confirmations,
        )?;
        let bridge_output = ReserveOutputObservation::new(
            bridge_wallet.wallet_id.clone(),
            quorum.quorum_id.clone(),
            "devnet-bridge-buffer-tx",
            0,
            "devnet-bridge-output-key",
            "devnet-bridge-ota",
            "devnet-bridge-amount",
            2_000_000_000_000,
            0,
            107,
            120,
            "devnet-output-membership-bridge",
            state.config.min_confirmations,
        )?;
        state.insert_output_observation(reserve_output_a.clone())?;
        state.insert_output_observation(reserve_output_b.clone())?;
        state.insert_output_observation(reserve_output_c.clone())?;
        state.insert_output_observation(bridge_output.clone())?;

        let key_image_absence_a = ReserveKeyImageObservation::new_absence(
            reserve_wallet.wallet_id.clone(),
            Some(reserve_output_a.output_id.clone()),
            quorum.quorum_id.clone(),
            "devnet-key-image-a",
            120,
            state.height,
            "devnet-key-image-absence-a",
        )?;
        let key_image_absence_b = ReserveKeyImageObservation::new_absence(
            reserve_wallet.wallet_id.clone(),
            Some(reserve_output_b.output_id.clone()),
            quorum.quorum_id.clone(),
            "devnet-key-image-b",
            120,
            state.height,
            "devnet-key-image-absence-b",
        )?;
        let historical_spend = ReserveKeyImageObservation::new_spend(
            bridge_wallet.wallet_id.clone(),
            None,
            quorum.quorum_id.clone(),
            "devnet-historical-buffer-spend-key-image",
            "devnet-historical-buffer-spend-tx",
            118,
            state.height,
            "devnet-historical-key-image-proof",
        )?;
        state.insert_key_image_observation(key_image_absence_a)?;
        state.insert_key_image_observation(key_image_absence_b)?;
        state.insert_key_image_observation(historical_spend)?;

        let reserve_output_root = state.output_observation_root();
        let spent_key_image_root = state.spent_key_image_root();
        let liability_commitment_root = monero_reserve_monitor_payload_root(
            "MONERO-RESERVE-MONITOR-DEVNET-LIABILITY-COMMITMENT",
            &json!({
                "asset_id": state.config.asset_id,
                "liability_bucket_piconero": 12_000_000_000_000_u64,
                "private_account_tree_root": monero_reserve_monitor_string_root(
                    "MONERO-RESERVE-MONITOR-DEVNET-PRIVATE-LIABILITY",
                    "devnet-private-liability-tree"
                ),
                "defi_bridge_liability_root": monero_reserve_monitor_string_root(
                    "MONERO-RESERVE-MONITOR-DEVNET-DEFI-LIABILITY",
                    "devnet-defi-bridge-liability-root"
                ),
            }),
        );
        let mut epoch = SolvencyEpoch::new(
            5,
            state.network.clone(),
            state.config.asset_id.clone(),
            104,
            128,
            120,
            quorum.quorum_id.clone(),
            reserve_output_root,
            spent_key_image_root,
            liability_commitment_root,
            state.confirmed_reserve_amount_bucket_piconero(),
            12_000_000_000_000,
            state.config.min_reserve_coverage_bps,
            state.config.target_reserve_coverage_bps,
            state.config.emergency_reserve_coverage_bps,
        )?;

        let sponsor = LowFeeProofSponsorship::new(
            "devnet-proof-sponsor-account",
            state.config.fee_asset_id.clone(),
            state.config.default_low_fee_budget_piconero,
            40_000_000,
            &[],
            state.height,
            state.height.saturating_add(96),
        )?;
        state.insert_low_fee_sponsorship(sponsor.clone())?;

        let proof_request = ReserveProofRequest::new(
            ReserveProofRequestKind::SolvencyEpoch,
            epoch.epoch_id.clone(),
            epoch.epoch_root(),
            "devnet-reserve-operator",
            Some(sponsor.sponsorship_id.clone()),
            "devnet-solvency-proof-privacy-budget",
            state.height,
            state
                .height
                .saturating_add(state.config.proof_request_ttl_blocks),
            40_000_000,
        )?;
        epoch.proof_request_id = Some(proof_request.request_id.clone());
        state.insert_proof_request(proof_request.clone())?;

        let empty_attestation_root = merkle_root("MONERO-RESERVE-MONITOR-PQ-ATTESTATION", &[]);
        let proof_receipt = ReserveProofReceipt::new(
            proof_request.request_id.clone(),
            "devnet-reserve-prover",
            "devnet-transparent-output-set-plus-key-image-absence",
            "devnet-solvency-proof-transcript",
            "devnet-solvency-proof-public-input",
            "devnet-solvency-vk",
            state.height.saturating_add(1),
            Some(state.height.saturating_add(2)),
            28_000_000,
            empty_attestation_root,
        )?;
        epoch.proof_receipt_id = Some(proof_receipt.receipt_id.clone());
        state.insert_proof_receipt(proof_receipt.clone())?;

        let alert = DeficitAlert::from_epoch(
            &epoch,
            state.height,
            state
                .height
                .saturating_add(state.config.proof_request_ttl_blocks),
            "coverage above minimum but below target reserve buffer",
        )?;
        state.insert_deficit_alert(alert.clone())?;

        let throttle = EmergencyMintThrottle::new(
            EmergencyMintThrottleMode::Protective,
            Some(alert.alert_id.clone()),
            state.config.max_mint_bps_per_window,
            125,
            state.height,
            state
                .height
                .saturating_add(state.config.epoch_length_blocks),
            state.height,
            "devnet-protective-throttle-attestation",
        )?;
        state.insert_mint_throttle(throttle)?;

        let summary = PublicReserveSummary::from_epoch(
            &epoch,
            state.output_observations.len() as u64,
            state
                .key_image_observations
                .values()
                .filter(|observation| observation.status.is_spent())
                .count() as u64,
            quorum.quorum_root(),
            alert.alert_root(),
            "public summary publishes bands, counts, and roots only",
            state.height.saturating_add(2),
        )?;
        epoch.public_summary_id = Some(summary.summary_id.clone());
        state.insert_public_summary(summary.clone())?;
        state.insert_solvency_epoch(epoch.clone())?;
        state.current_solvency_epoch_id = epoch.epoch_id.clone();

        state.attest_subject(
            &operator.participant_id,
            ReserveAttestationSubjectKind::SolvencyEpoch,
            &epoch.epoch_id,
            &epoch.epoch_root(),
            "devnet-solvency-operator-context",
            "devnet-solvency-operator-signature",
        )?;
        state.attest_subject(
            &auditor.participant_id,
            ReserveAttestationSubjectKind::PublicSummary,
            &summary.summary_id,
            &summary.summary_root(),
            "devnet-summary-auditor-context",
            "devnet-summary-auditor-signature",
        )?;
        state.attest_subject(
            &sponsor_participant.participant_id,
            ReserveAttestationSubjectKind::Sponsorship,
            &sponsor.sponsorship_id,
            &sponsor.sponsorship_root(),
            "devnet-sponsor-context",
            "devnet-sponsor-signature",
        )?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroReserveMonitorResult<String> {
        self.height = height;
        for observation in self.daemon_observations.values_mut() {
            observation.set_height(height, self.config.observer_staleness_blocks);
        }
        for quorum in self.daemon_quorums.values_mut() {
            quorum.set_height(height);
        }
        for request in self.proof_requests.values_mut() {
            request.set_height(height);
        }
        for alert in self.deficit_alerts.values_mut() {
            alert.set_height(height);
        }
        for throttle in self.mint_throttles.values_mut() {
            throttle.set_height(height);
        }
        for sponsorship in self.low_fee_sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        self.validate()
    }

    pub fn insert_participant(
        &mut self,
        participant: PqReserveParticipant,
    ) -> MoneroReserveMonitorResult<String> {
        let root = participant.validate()?;
        insert_unique_record(
            &mut self.participants,
            participant.participant_id.clone(),
            participant,
            "reserve participant",
        )?;
        Ok(root)
    }

    pub fn insert_wallet_commitment(
        &mut self,
        wallet: ReserveWalletCommitment,
    ) -> MoneroReserveMonitorResult<String> {
        let root = wallet.validate()?;
        insert_unique_record(
            &mut self.wallet_commitments,
            wallet.wallet_id.clone(),
            wallet,
            "reserve wallet",
        )?;
        Ok(root)
    }

    pub fn insert_daemon_observer(
        &mut self,
        observer: DaemonObserver,
    ) -> MoneroReserveMonitorResult<String> {
        let root = observer.validate()?;
        if !self.participants.contains_key(&observer.participant_id) {
            return Err("daemon observer references unknown participant".to_string());
        }
        insert_unique_record(
            &mut self.daemon_observers,
            observer.observer_id.clone(),
            observer,
            "daemon observer",
        )?;
        Ok(root)
    }

    pub fn insert_daemon_observation(
        &mut self,
        observation: DaemonReserveObservation,
    ) -> MoneroReserveMonitorResult<String> {
        let root = observation.validate()?;
        if !self.daemon_observers.contains_key(&observation.observer_id) {
            return Err("daemon observation references unknown observer".to_string());
        }
        if observation.network != self.network {
            return Err("daemon observation network mismatch".to_string());
        }
        insert_unique_record(
            &mut self.daemon_observations,
            observation.observation_id.clone(),
            observation,
            "daemon observation",
        )?;
        Ok(root)
    }

    pub fn insert_daemon_quorum(
        &mut self,
        quorum: DaemonObservationQuorum,
    ) -> MoneroReserveMonitorResult<String> {
        let root = quorum.validate()?;
        self.validate_quorum_references(&quorum)?;
        insert_unique_record(
            &mut self.daemon_quorums,
            quorum.quorum_id.clone(),
            quorum,
            "daemon quorum",
        )?;
        Ok(root)
    }

    pub fn mark_observations_quorum_accepted(
        &mut self,
        observation_ids: &[String],
    ) -> MoneroReserveMonitorResult<()> {
        for observation_id in observation_ids {
            let observation = self
                .daemon_observations
                .get_mut(observation_id)
                .ok_or_else(|| "unknown daemon observation".to_string())?;
            observation.status = DaemonObservationStatus::QuorumAccepted;
        }
        Ok(())
    }

    pub fn insert_output_observation(
        &mut self,
        output: ReserveOutputObservation,
    ) -> MoneroReserveMonitorResult<String> {
        let root = output.validate()?;
        if !self.wallet_commitments.contains_key(&output.wallet_id) {
            return Err("reserve output references unknown wallet".to_string());
        }
        if !self.daemon_quorums.contains_key(&output.daemon_quorum_id) {
            return Err("reserve output references unknown daemon quorum".to_string());
        }
        insert_unique_record(
            &mut self.output_observations,
            output.output_id.clone(),
            output,
            "reserve output observation",
        )?;
        Ok(root)
    }

    pub fn insert_key_image_observation(
        &mut self,
        observation: ReserveKeyImageObservation,
    ) -> MoneroReserveMonitorResult<String> {
        let root = observation.validate()?;
        if !self.wallet_commitments.contains_key(&observation.wallet_id) {
            return Err("key image observation references unknown wallet".to_string());
        }
        if !self
            .daemon_quorums
            .contains_key(&observation.daemon_quorum_id)
        {
            return Err("key image observation references unknown daemon quorum".to_string());
        }
        if let Some(output_id) = observation.output_id.as_deref() {
            if !self.output_observations.contains_key(output_id) {
                return Err("key image observation references unknown output".to_string());
            }
        }
        insert_unique_record(
            &mut self.key_image_observations,
            observation.key_image_id.clone(),
            observation,
            "reserve key image observation",
        )?;
        Ok(root)
    }

    pub fn insert_solvency_epoch(
        &mut self,
        epoch: SolvencyEpoch,
    ) -> MoneroReserveMonitorResult<String> {
        let root = epoch.validate()?;
        if !self.daemon_quorums.contains_key(&epoch.daemon_quorum_id) {
            return Err("solvency epoch references unknown daemon quorum".to_string());
        }
        if let Some(request_id) = epoch.proof_request_id.as_deref() {
            if !self.proof_requests.contains_key(request_id) {
                return Err("solvency epoch references unknown proof request".to_string());
            }
        }
        if let Some(receipt_id) = epoch.proof_receipt_id.as_deref() {
            if !self.proof_receipts.contains_key(receipt_id) {
                return Err("solvency epoch references unknown proof receipt".to_string());
            }
        }
        insert_unique_record(
            &mut self.solvency_epochs,
            epoch.epoch_id.clone(),
            epoch,
            "solvency epoch",
        )?;
        Ok(root)
    }

    pub fn insert_proof_request(
        &mut self,
        request: ReserveProofRequest,
    ) -> MoneroReserveMonitorResult<String> {
        let root = request.validate()?;
        if let Some(sponsor_id) = request.sponsor_id.as_deref() {
            if !self.low_fee_sponsorships.contains_key(sponsor_id) {
                return Err("proof request references unknown sponsorship".to_string());
            }
        }
        insert_unique_record(
            &mut self.proof_requests,
            request.request_id.clone(),
            request,
            "reserve proof request",
        )?;
        Ok(root)
    }

    pub fn insert_proof_receipt(
        &mut self,
        receipt: ReserveProofReceipt,
    ) -> MoneroReserveMonitorResult<String> {
        let root = receipt.validate()?;
        if !self.proof_requests.contains_key(&receipt.request_id) {
            return Err("proof receipt references unknown request".to_string());
        }
        insert_unique_record(
            &mut self.proof_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "reserve proof receipt",
        )?;
        Ok(root)
    }

    pub fn insert_deficit_alert(
        &mut self,
        alert: DeficitAlert,
    ) -> MoneroReserveMonitorResult<String> {
        let root = alert.validate()?;
        insert_unique_record(
            &mut self.deficit_alerts,
            alert.alert_id.clone(),
            alert,
            "deficit alert",
        )?;
        Ok(root)
    }

    pub fn insert_mint_throttle(
        &mut self,
        throttle: EmergencyMintThrottle,
    ) -> MoneroReserveMonitorResult<String> {
        let root = throttle.validate()?;
        if let Some(alert_id) = throttle.reason_alert_id.as_deref() {
            if !self.deficit_alerts.contains_key(alert_id) {
                return Err("mint throttle references unknown alert".to_string());
            }
        }
        insert_unique_record(
            &mut self.mint_throttles,
            throttle.throttle_id.clone(),
            throttle,
            "mint throttle",
        )?;
        Ok(root)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorship,
    ) -> MoneroReserveMonitorResult<String> {
        let root = sponsorship.validate()?;
        for request_id in &sponsorship.request_ids {
            if !self.proof_requests.contains_key(request_id) {
                return Err("low fee sponsorship references unknown request".to_string());
            }
        }
        insert_unique_record(
            &mut self.low_fee_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "low fee sponsorship",
        )?;
        Ok(root)
    }

    pub fn insert_public_summary(
        &mut self,
        summary: PublicReserveSummary,
    ) -> MoneroReserveMonitorResult<String> {
        let root = summary.validate()?;
        insert_unique_record(
            &mut self.public_summaries,
            summary.summary_id.clone(),
            summary,
            "public reserve summary",
        )?;
        Ok(root)
    }

    pub fn attest_subject(
        &mut self,
        participant_id: &str,
        subject_kind: ReserveAttestationSubjectKind,
        subject_id: &str,
        subject_root: &str,
        context_material: &str,
        signature_material: &str,
    ) -> MoneroReserveMonitorResult<String> {
        let participant = self
            .participants
            .get(participant_id)
            .ok_or_else(|| "unknown reserve attestation participant".to_string())?;
        let context_root = monero_reserve_monitor_string_root(
            "MONERO-RESERVE-MONITOR-ATTESTATION-CONTEXT",
            context_material,
        );
        let attestation = PqReserveAttestation::new(
            participant,
            subject_kind,
            subject_id,
            subject_root,
            context_root,
            signature_material,
            self.height,
        )?;
        let root = attestation.attestation_root();
        insert_unique_record(
            &mut self.pq_attestations,
            attestation.attestation_id.clone(),
            attestation,
            "reserve PQ attestation",
        )?;
        Ok(root)
    }

    pub fn confirmed_reserve_amount_bucket_piconero(&self) -> u64 {
        self.output_observations
            .values()
            .map(ReserveOutputObservation::reserve_value_piconero)
            .sum()
    }

    pub fn spent_key_image_root(&self) -> String {
        keyed_value_root(
            "MONERO-RESERVE-MONITOR-SPENT-KEY-IMAGE-ROOT",
            self.key_image_observations
                .values()
                .filter(|observation| observation.status.is_spent())
                .map(|observation| {
                    (
                        observation.key_image_id.clone(),
                        observation.public_record(),
                    )
                })
                .collect(),
        )
    }

    pub fn participant_root(&self) -> String {
        monero_reserve_monitor_participant_collection_root(
            &self.participants.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn wallet_commitment_root(&self) -> String {
        monero_reserve_monitor_wallet_collection_root(
            &self
                .wallet_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn daemon_observer_root(&self) -> String {
        monero_reserve_monitor_daemon_observer_collection_root(
            &self.daemon_observers.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn daemon_observation_root(&self) -> String {
        monero_reserve_monitor_daemon_observation_collection_root(
            &self
                .daemon_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn daemon_quorum_root(&self) -> String {
        monero_reserve_monitor_daemon_quorum_collection_root(
            &self.daemon_quorums.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn output_observation_root(&self) -> String {
        monero_reserve_monitor_output_observation_collection_root(
            &self
                .output_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn key_image_observation_root(&self) -> String {
        monero_reserve_monitor_key_image_observation_collection_root(
            &self
                .key_image_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn solvency_epoch_root(&self) -> String {
        monero_reserve_monitor_solvency_epoch_collection_root(
            &self.solvency_epochs.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn proof_request_root(&self) -> String {
        monero_reserve_monitor_proof_request_collection_root(
            &self.proof_requests.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn proof_receipt_root(&self) -> String {
        monero_reserve_monitor_proof_receipt_collection_root(
            &self.proof_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn deficit_alert_root(&self) -> String {
        monero_reserve_monitor_deficit_alert_collection_root(
            &self.deficit_alerts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn mint_throttle_root(&self) -> String {
        monero_reserve_monitor_mint_throttle_collection_root(
            &self.mint_throttles.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        monero_reserve_monitor_low_fee_sponsorship_collection_root(
            &self
                .low_fee_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_summary_root(&self) -> String {
        monero_reserve_monitor_public_summary_collection_root(
            &self.public_summaries.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        monero_reserve_monitor_attestation_collection_root(
            &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        let records = self
            .public_summaries
            .values()
            .map(PublicReserveSummary::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-RESERVE-MONITOR-PUBLIC-RECORDS", &records)
    }

    pub fn counters(&self) -> MoneroReserveMonitorCounters {
        MoneroReserveMonitorCounters {
            height: self.height,
            participant_count: self.participants.len() as u64,
            active_participant_count: self
                .participants
                .values()
                .filter(|participant| participant.active)
                .count() as u64,
            wallet_count: self.wallet_commitments.len() as u64,
            active_wallet_count: self
                .wallet_commitments
                .values()
                .filter(|wallet| wallet.status.is_live())
                .count() as u64,
            daemon_observer_count: self.daemon_observers.len() as u64,
            active_daemon_observer_count: self
                .daemon_observers
                .values()
                .filter(|observer| observer.active)
                .count() as u64,
            daemon_observation_count: self.daemon_observations.len() as u64,
            live_daemon_observation_count: self
                .daemon_observations
                .values()
                .filter(|observation| observation.status.is_live())
                .count() as u64,
            daemon_quorum_count: self.daemon_quorums.len() as u64,
            usable_daemon_quorum_count: self
                .daemon_quorums
                .values()
                .filter(|quorum| quorum.status.is_usable())
                .count() as u64,
            output_observation_count: self.output_observations.len() as u64,
            confirmed_output_count: self
                .output_observations
                .values()
                .filter(|output| output.status.counts_as_reserve())
                .count() as u64,
            reserve_amount_bucket_piconero: self.confirmed_reserve_amount_bucket_piconero(),
            key_image_observation_count: self.key_image_observations.len() as u64,
            spent_key_image_count: self
                .key_image_observations
                .values()
                .filter(|observation| observation.status.is_spent())
                .count() as u64,
            solvency_epoch_count: self.solvency_epochs.len() as u64,
            risky_epoch_count: self
                .solvency_epochs
                .values()
                .filter(|epoch| epoch.status.needs_throttle())
                .count() as u64,
            proof_request_count: self.proof_requests.len() as u64,
            open_proof_request_count: self
                .proof_requests
                .values()
                .filter(|request| request.status.is_open())
                .count() as u64,
            proof_receipt_count: self.proof_receipts.len() as u64,
            verified_proof_receipt_count: self
                .proof_receipts
                .values()
                .filter(|receipt| receipt.status.is_verified())
                .count() as u64,
            deficit_alert_count: self.deficit_alerts.len() as u64,
            active_deficit_alert_count: self
                .deficit_alerts
                .values()
                .filter(|alert| alert.status.is_active())
                .count() as u64,
            mint_throttle_count: self.mint_throttles.len() as u64,
            active_mint_throttle_count: self
                .mint_throttles
                .values()
                .filter(|throttle| throttle.mode.allows_mint())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_active())
                .count() as u64,
            remaining_sponsorship_budget_piconero: self
                .low_fee_sponsorships
                .values()
                .map(LowFeeProofSponsorship::remaining_budget_piconero)
                .sum(),
            public_summary_count: self.public_summaries.len() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
        }
    }

    pub fn roots(&self) -> MoneroReserveMonitorRoots {
        let counters = self.counters();
        let mut roots = MoneroReserveMonitorRoots {
            config_root: self.config.config_root(),
            participant_root: self.participant_root(),
            wallet_commitment_root: self.wallet_commitment_root(),
            daemon_observer_root: self.daemon_observer_root(),
            daemon_observation_root: self.daemon_observation_root(),
            daemon_quorum_root: self.daemon_quorum_root(),
            output_observation_root: self.output_observation_root(),
            key_image_observation_root: self.key_image_observation_root(),
            solvency_epoch_root: self.solvency_epoch_root(),
            proof_request_root: self.proof_request_root(),
            proof_receipt_root: self.proof_receipt_root(),
            deficit_alert_root: self.deficit_alert_root(),
            mint_throttle_root: self.mint_throttle_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            public_summary_root: self.public_summary_root(),
            pq_attestation_root: self.pq_attestation_root(),
            counters_root: counters.counters_root(),
            public_record_root: self.public_record_root(),
            state_root: String::new(),
        };
        let record = self.public_record_without_state_root(&roots);
        roots.state_root = monero_reserve_monitor_state_root_from_record(&record);
        roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root(&roots);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(roots.state_root));
        }
        record
    }

    pub fn validate(&self) -> MoneroReserveMonitorResult<String> {
        self.config.validate()?;
        ensure_non_empty(&self.network, "monero reserve monitor network")?;
        if self.network != self.config.network {
            return Err("monero reserve monitor network mismatch".to_string());
        }
        if !self.current_daemon_quorum_id.is_empty()
            && !self
                .daemon_quorums
                .contains_key(&self.current_daemon_quorum_id)
        {
            return Err("current daemon quorum id is unknown".to_string());
        }
        if !self.current_solvency_epoch_id.is_empty()
            && !self
                .solvency_epochs
                .contains_key(&self.current_solvency_epoch_id)
        {
            return Err("current solvency epoch id is unknown".to_string());
        }
        for (participant_id, participant) in &self.participants {
            if participant_id != &participant.participant_id {
                return Err("reserve participant map key mismatch".to_string());
            }
            participant.validate()?;
            if !self
                .config
                .accepted_pq_signature_schemes
                .contains(&participant.signature_scheme)
            {
                return Err("reserve participant uses unsupported PQ scheme".to_string());
            }
        }
        for (wallet_id, wallet) in &self.wallet_commitments {
            if wallet_id != &wallet.wallet_id {
                return Err("reserve wallet map key mismatch".to_string());
            }
            wallet.validate()?;
        }
        for (observer_id, observer) in &self.daemon_observers {
            if observer_id != &observer.observer_id {
                return Err("daemon observer map key mismatch".to_string());
            }
            observer.validate()?;
            if observer.network != self.network {
                return Err("daemon observer network mismatch".to_string());
            }
            if !self.participants.contains_key(&observer.participant_id) {
                return Err("daemon observer references unknown participant".to_string());
            }
        }
        for (observation_id, observation) in &self.daemon_observations {
            if observation_id != &observation.observation_id {
                return Err("daemon observation map key mismatch".to_string());
            }
            observation.validate()?;
            if !self.daemon_observers.contains_key(&observation.observer_id) {
                return Err("daemon observation references unknown observer".to_string());
            }
            if observation.network != self.network {
                return Err("daemon observation network mismatch".to_string());
            }
        }
        for (quorum_id, quorum) in &self.daemon_quorums {
            if quorum_id != &quorum.quorum_id {
                return Err("daemon quorum map key mismatch".to_string());
            }
            quorum.validate()?;
            self.validate_quorum_references(quorum)?;
        }
        for (output_id, output) in &self.output_observations {
            if output_id != &output.output_id {
                return Err("reserve output map key mismatch".to_string());
            }
            output.validate()?;
            if !self.wallet_commitments.contains_key(&output.wallet_id) {
                return Err("reserve output references unknown wallet".to_string());
            }
            if !self.daemon_quorums.contains_key(&output.daemon_quorum_id) {
                return Err("reserve output references unknown daemon quorum".to_string());
            }
        }
        for (key_image_id, observation) in &self.key_image_observations {
            if key_image_id != &observation.key_image_id {
                return Err("key image observation map key mismatch".to_string());
            }
            observation.validate()?;
            if !self.wallet_commitments.contains_key(&observation.wallet_id) {
                return Err("key image observation references unknown wallet".to_string());
            }
            if !self
                .daemon_quorums
                .contains_key(&observation.daemon_quorum_id)
            {
                return Err("key image observation references unknown daemon quorum".to_string());
            }
            if let Some(output_id) = observation.output_id.as_deref() {
                if !self.output_observations.contains_key(output_id) {
                    return Err("key image observation references unknown output".to_string());
                }
            }
        }
        for (epoch_id, epoch) in &self.solvency_epochs {
            if epoch_id != &epoch.epoch_id {
                return Err("solvency epoch map key mismatch".to_string());
            }
            epoch.validate()?;
            if epoch.network != self.network {
                return Err("solvency epoch network mismatch".to_string());
            }
            if epoch.asset_id != self.config.asset_id {
                return Err("solvency epoch asset id mismatch".to_string());
            }
            if !self.daemon_quorums.contains_key(&epoch.daemon_quorum_id) {
                return Err("solvency epoch references unknown daemon quorum".to_string());
            }
            if let Some(request_id) = epoch.proof_request_id.as_deref() {
                if !self.proof_requests.contains_key(request_id) {
                    return Err("solvency epoch references unknown proof request".to_string());
                }
            }
            if let Some(receipt_id) = epoch.proof_receipt_id.as_deref() {
                if !self.proof_receipts.contains_key(receipt_id) {
                    return Err("solvency epoch references unknown proof receipt".to_string());
                }
            }
            if let Some(summary_id) = epoch.public_summary_id.as_deref() {
                if !self.public_summaries.contains_key(summary_id) {
                    return Err("solvency epoch references unknown public summary".to_string());
                }
            }
        }
        for (request_id, request) in &self.proof_requests {
            if request_id != &request.request_id {
                return Err("proof request map key mismatch".to_string());
            }
            request.validate()?;
            if let Some(sponsor_id) = request.sponsor_id.as_deref() {
                if !self.low_fee_sponsorships.contains_key(sponsor_id) {
                    return Err("proof request references unknown sponsorship".to_string());
                }
            }
        }
        for (receipt_id, receipt) in &self.proof_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("proof receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.proof_requests.contains_key(&receipt.request_id) {
                return Err("proof receipt references unknown request".to_string());
            }
        }
        for (alert_id, alert) in &self.deficit_alerts {
            if alert_id != &alert.alert_id {
                return Err("deficit alert map key mismatch".to_string());
            }
            alert.validate()?;
            if !self.solvency_epochs.contains_key(&alert.epoch_id) {
                return Err("deficit alert references unknown epoch".to_string());
            }
        }
        for (throttle_id, throttle) in &self.mint_throttles {
            if throttle_id != &throttle.throttle_id {
                return Err("mint throttle map key mismatch".to_string());
            }
            throttle.validate()?;
            if let Some(alert_id) = throttle.reason_alert_id.as_deref() {
                if !self.deficit_alerts.contains_key(alert_id) {
                    return Err("mint throttle references unknown alert".to_string());
                }
            }
        }
        for (sponsorship_id, sponsorship) in &self.low_fee_sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("low fee sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
            for request_id in &sponsorship.request_ids {
                if !self.proof_requests.contains_key(request_id) {
                    return Err("low fee sponsorship references unknown request".to_string());
                }
            }
        }
        for (summary_id, summary) in &self.public_summaries {
            if summary_id != &summary.summary_id {
                return Err("public summary map key mismatch".to_string());
            }
            summary.validate()?;
            if !self.solvency_epochs.contains_key(&summary.epoch_id) {
                return Err("public summary references unknown epoch".to_string());
            }
        }
        for (attestation_id, attestation) in &self.pq_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("reserve attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            let participant = self
                .participants
                .get(&attestation.participant_id)
                .ok_or_else(|| "reserve attestation references unknown participant".to_string())?;
            if participant.weight != attestation.weight {
                return Err("reserve attestation weight mismatch".to_string());
            }
            if participant.signature_scheme != attestation.signature_scheme {
                return Err("reserve attestation signature scheme mismatch".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self, roots: &MoneroReserveMonitorRoots) -> Value {
        json!({
            "kind": "monero_reserve_monitor_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_RESERVE_MONITOR_PROTOCOL_VERSION,
            "height": self.height,
            "network": self.network,
            "asset_id": self.config.asset_id,
            "current_daemon_quorum_id": self.current_daemon_quorum_id,
            "current_solvency_epoch_id": self.current_solvency_epoch_id,
            "roots": roots.public_record_without_state_root(),
            "counters": self.counters().public_record(),
        })
    }

    fn validate_quorum_references(
        &self,
        quorum: &DaemonObservationQuorum,
    ) -> MoneroReserveMonitorResult<()> {
        let mut weight = 0_u64;
        for observation_id in &quorum.observation_ids {
            let observation = self
                .daemon_observations
                .get(observation_id)
                .ok_or_else(|| "daemon quorum references unknown observation".to_string())?;
            if observation.monero_height != quorum.monero_height
                || observation.block_hash != quorum.canonical_block_hash
            {
                return Err("daemon quorum observation disagrees with canonical tip".to_string());
            }
        }
        for observer_id in &quorum.observer_ids {
            let observer = self
                .daemon_observers
                .get(observer_id)
                .ok_or_else(|| "daemon quorum references unknown observer".to_string())?;
            weight = weight.saturating_add(observer.weight);
        }
        if weight != quorum.quorum_weight {
            return Err("daemon quorum weight mismatch".to_string());
        }
        if quorum.status == DaemonQuorumStatus::Confirmed && weight < quorum.required_weight {
            return Err("daemon quorum is below required weight".to_string());
        }
        Ok(())
    }
}

pub fn monero_reserve_monitor_state_root_from_record(record: &Value) -> String {
    monero_reserve_monitor_payload_root("MONERO-RESERVE-MONITOR-STATE", record)
}

pub fn monero_reserve_monitor_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_RESERVE_MONITOR_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_RESERVE_MONITOR_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_string_set_root(domain: &str, values: &[String]) -> String {
    let set = ordered_string_set(values);
    let leaves = set
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn monero_reserve_monitor_signature_root(
    participant_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    signature_material: &str,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_RESERVE_MONITOR_PROTOCOL_VERSION),
            HashPart::Str(participant_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signature_material),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_participant_id(
    label: &str,
    role: &str,
    signature_scheme: &str,
    public_key_commitment: &str,
    registered_height: u64,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-PARTICIPANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role),
            HashPart::Str(signature_scheme),
            HashPart::Str(public_key_commitment),
            HashPart::Int(registered_height as i128),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_attestation_id(
    participant_id: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(participant_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_wallet_id(
    label: &str,
    role: &str,
    account_commitment: &str,
    address_set_root: &str,
    registered_height: u64,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-WALLET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role),
            HashPart::Str(account_commitment),
            HashPart::Str(address_set_root),
            HashPart::Int(registered_height as i128),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_daemon_observer_id(
    label: &str,
    role: &str,
    network: &str,
    endpoint_commitment: &str,
    participant_id: &str,
    registered_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-DAEMON-OBSERVER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role),
            HashPart::Str(network),
            HashPart::Str(endpoint_commitment),
            HashPart::Str(participant_id),
            HashPart::Int(registered_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_daemon_observation_id(
    observer_id: &str,
    network: &str,
    monero_height: u64,
    block_hash: &str,
    output_scan_root: &str,
    key_image_scan_root: &str,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-DAEMON-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(observer_id),
            HashPart::Str(network),
            HashPart::Int(monero_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(output_scan_root),
            HashPart::Str(key_image_scan_root),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_daemon_quorum_id(
    network: &str,
    monero_height: u64,
    canonical_block_hash: &str,
    observation_id_root: &str,
    observer_id_root: &str,
    formed_at_l2_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-DAEMON-QUORUM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(network),
            HashPart::Int(monero_height as i128),
            HashPart::Str(canonical_block_hash),
            HashPart::Str(observation_id_root),
            HashPart::Str(observer_id_root),
            HashPart::Int(formed_at_l2_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_output_observation_id(
    wallet_id: &str,
    daemon_quorum_id: &str,
    monero_txid_commitment: &str,
    output_index: u64,
    output_public_key_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-OUTPUT-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(daemon_quorum_id),
            HashPart::Str(monero_txid_commitment),
            HashPart::Int(output_index as i128),
            HashPart::Str(output_public_key_commitment),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_key_image_observation_id(
    wallet_id: &str,
    output_id: Option<&str>,
    daemon_quorum_id: &str,
    key_image_commitment: &str,
    first_seen_monero_height: u64,
) -> String {
    let output_id_value = match output_id {
        Some(value) => value,
        None => "none",
    };
    domain_hash(
        "MONERO-RESERVE-MONITOR-KEY-IMAGE-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(output_id_value),
            HashPart::Str(daemon_quorum_id),
            HashPart::Str(key_image_commitment),
            HashPart::Int(first_seen_monero_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_solvency_epoch_id(
    epoch_index: u64,
    network: &str,
    asset_id: &str,
    from_l2_height: u64,
    to_l2_height: u64,
    monero_height: u64,
    daemon_quorum_id: &str,
    reserve_output_root: &str,
    liability_commitment_root: &str,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-SOLVENCY-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Str(network),
            HashPart::Str(asset_id),
            HashPart::Int(from_l2_height as i128),
            HashPart::Int(to_l2_height as i128),
            HashPart::Int(monero_height as i128),
            HashPart::Str(daemon_quorum_id),
            HashPart::Str(reserve_output_root),
            HashPart::Str(liability_commitment_root),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_proof_request_id(
    request_kind: &str,
    subject_id: &str,
    subject_root: &str,
    requester_commitment: &str,
    requested_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-PROOF-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(requester_commitment),
            HashPart::Int(requested_at_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_proof_receipt_id(
    request_id: &str,
    prover_commitment: &str,
    proof_system: &str,
    proof_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-PROOF-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Str(prover_commitment),
            HashPart::Str(proof_system),
            HashPart::Str(proof_root),
            HashPart::Int(submitted_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_deficit_alert_id(
    epoch_id: &str,
    severity: &str,
    coverage_bps: u64,
    message_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-DEFICIT-ALERT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(severity),
            HashPart::Int(coverage_bps as i128),
            HashPart::Str(message_root),
            HashPart::Int(opened_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_mint_throttle_id(
    mode: &str,
    reason_alert_id: Option<&str>,
    window_start_height: u64,
    window_end_height: u64,
    activated_height: u64,
) -> String {
    let reason_alert_id_value = match reason_alert_id {
        Some(value) => value,
        None => "none",
    };
    domain_hash(
        "MONERO-RESERVE-MONITOR-MINT-THROTTLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(mode),
            HashPart::Str(reason_alert_id_value),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
            HashPart::Int(activated_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_low_fee_sponsorship_id(
    sponsor_commitment: &str,
    fee_asset_id: &str,
    budget_piconero: u64,
    max_fee_per_proof_piconero: u64,
    request_root: &str,
    start_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(budget_piconero as i128),
            HashPart::Int(max_fee_per_proof_piconero as i128),
            HashPart::Str(request_root),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_public_summary_id(
    epoch_id: &str,
    reserve_commitment_root: &str,
    liability_commitment_root: &str,
    daemon_quorum_root: &str,
    coverage_floor_bps: u64,
    published_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-MONITOR-PUBLIC-SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(reserve_commitment_root),
            HashPart::Str(liability_commitment_root),
            HashPart::Str(daemon_quorum_root),
            HashPart::Int(coverage_floor_bps as i128),
            HashPart::Int(published_height as i128),
        ],
        32,
    )
}

pub fn monero_reserve_monitor_participant_collection_root(
    records: &[PqReserveParticipant],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-PARTICIPANT-COLLECTION",
        records
            .iter()
            .map(|record| (record.participant_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_attestation_collection_root(
    records: &[PqReserveAttestation],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-ATTESTATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.attestation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_wallet_collection_root(
    records: &[ReserveWalletCommitment],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-WALLET-COLLECTION",
        records
            .iter()
            .map(|record| (record.wallet_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_daemon_observer_collection_root(
    records: &[DaemonObserver],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-DAEMON-OBSERVER-COLLECTION",
        records
            .iter()
            .map(|record| (record.observer_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_daemon_observation_collection_root(
    records: &[DaemonReserveObservation],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-DAEMON-OBSERVATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.observation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_daemon_quorum_collection_root(
    records: &[DaemonObservationQuorum],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-DAEMON-QUORUM-COLLECTION",
        records
            .iter()
            .map(|record| (record.quorum_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_output_observation_collection_root(
    records: &[ReserveOutputObservation],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-OUTPUT-OBSERVATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.output_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_key_image_observation_collection_root(
    records: &[ReserveKeyImageObservation],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-KEY-IMAGE-OBSERVATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.key_image_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_solvency_epoch_collection_root(records: &[SolvencyEpoch]) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-SOLVENCY-EPOCH-COLLECTION",
        records
            .iter()
            .map(|record| (record.epoch_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_proof_request_collection_root(
    records: &[ReserveProofRequest],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-PROOF-REQUEST-COLLECTION",
        records
            .iter()
            .map(|record| (record.request_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_proof_receipt_collection_root(
    records: &[ReserveProofReceipt],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-PROOF-RECEIPT-COLLECTION",
        records
            .iter()
            .map(|record| (record.receipt_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_deficit_alert_collection_root(records: &[DeficitAlert]) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-DEFICIT-ALERT-COLLECTION",
        records
            .iter()
            .map(|record| (record.alert_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_mint_throttle_collection_root(
    records: &[EmergencyMintThrottle],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-MINT-THROTTLE-COLLECTION",
        records
            .iter()
            .map(|record| (record.throttle_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_low_fee_sponsorship_collection_root(
    records: &[LowFeeProofSponsorship],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-LOW-FEE-SPONSORSHIP-COLLECTION",
        records
            .iter()
            .map(|record| (record.sponsorship_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_reserve_monitor_public_summary_collection_root(
    records: &[PublicReserveSummary],
) -> String {
    keyed_value_root(
        "MONERO-RESERVE-MONITOR-PUBLIC-SUMMARY-COLLECTION",
        records
            .iter()
            .map(|record| (record.summary_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    mul_div_floor(numerator, MONERO_RESERVE_MONITOR_MAX_BPS, denominator)
}

pub fn mul_div_floor(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let result = (value as u128).saturating_mul(multiplier as u128) / denominator as u128;
    result.min(u64::MAX as u128) as u64
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, record)| json!({"key": key, "record": record}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
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

fn required_for_minimum(liability_amount: u64, coverage_bps: u64) -> u64 {
    let result = (liability_amount as u128).saturating_mul(coverage_bps as u128)
        / MONERO_RESERVE_MONITOR_MAX_BPS as u128;
    result.min(u64::MAX as u128) as u64
}

fn coverage_floor_bps(coverage_bps: u64, bucket_bps: u64) -> u64 {
    if bucket_bps == 0 || coverage_bps == u64::MAX {
        return coverage_bps;
    }
    coverage_bps.saturating_sub(coverage_bps % bucket_bps)
}

fn coverage_band(coverage_bps: u64) -> String {
    if coverage_bps == u64::MAX {
        "unbounded".to_string()
    } else if coverage_bps >= 12_000 {
        ">=120pct".to_string()
    } else if coverage_bps >= 11_000 {
        "110pct_120pct".to_string()
    } else if coverage_bps >= 10_250 {
        "102_5pct_110pct".to_string()
    } else if coverage_bps >= 10_000 {
        "100pct_102_5pct".to_string()
    } else {
        "<100pct".to_string()
    }
}

fn count_bucket(value: u64, bucket: u64) -> u64 {
    if bucket == 0 {
        return value;
    }
    value.saturating_sub(value % bucket)
}

fn ordered_string_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect()
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroReserveMonitorResult<()> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroReserveMonitorResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroReserveMonitorResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroReserveMonitorResult<()> {
    if value > MONERO_RESERVE_MONITOR_MAX_BPS.saturating_mul(2) {
        Err(format!("{label} is outside supported bps range"))
    } else {
        Ok(())
    }
}

fn ensure_string_set(values: &BTreeSet<String>, label: &str) -> MoneroReserveMonitorResult<()> {
    for value in values {
        ensure_non_empty(value, label)?;
    }
    Ok(())
}
