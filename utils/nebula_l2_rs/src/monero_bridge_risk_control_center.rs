use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroBridgeRiskControlCenterResult<T> = Result<T, String>;

pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_PROTOCOL_VERSION: &str =
    "nebula-monero-bridge-risk-control-center-v1";
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS: u64 = 10_000;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_WARNING_RESERVE_DRIFT_BPS: u64 = 250;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_CRITICAL_RESERVE_DRIFT_BPS: u64 = 650;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_HALT_RESERVE_DRIFT_BPS: u64 = 1_000;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_REORG_WARNING_DEPTH: u64 = 12;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_REORG_CRITICAL_DEPTH: u64 = 24;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_EXIT_QUEUE_WARNING: u64 = 750;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_EXIT_QUEUE_CRITICAL: u64 = 1_500;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_VIEW_KEY_EXPOSURE_BPS: u64 = 400;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_LIQUIDITY_BUFFER_BPS: u64 = 1_750;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_FRAUD_CHALLENGE_TTL_BLOCKS: u64 = 144;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_PAUSE_TTL_BLOCKS: u64 = 72;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_FEE_CAP_BPS: u64 = 180;
pub const MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Green,
    Watch,
    Elevated,
    Critical,
    Halted,
}

impl RiskSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
            Self::Halted => "halted",
        }
    }

    pub fn score_bps(self) -> u64 {
        match self {
            Self::Green => 10_000,
            Self::Watch => 8_500,
            Self::Elevated => 6_500,
            Self::Critical => 2_500,
            Self::Halted => 0,
        }
    }

    pub fn blocks_new_exits(self) -> bool {
        matches!(self, Self::Critical | Self::Halted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveDriftStatus {
    Balanced,
    SoftDrift,
    HardDrift,
    Insolvent,
    Unknown,
}

impl ReserveDriftStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::SoftDrift => "soft_drift",
            Self::HardDrift => "hard_drift",
            Self::Insolvent => "insolvent",
            Self::Unknown => "unknown",
        }
    }

    pub fn severity(self) -> RiskSeverity {
        match self {
            Self::Balanced => RiskSeverity::Green,
            Self::SoftDrift => RiskSeverity::Watch,
            Self::HardDrift => RiskSeverity::Critical,
            Self::Insolvent | Self::Unknown => RiskSeverity::Halted,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgRiskStatus {
    Nominal,
    Tracking,
    Deep,
    FinalityBroken,
}

impl ReorgRiskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Tracking => "tracking",
            Self::Deep => "deep",
            Self::FinalityBroken => "finality_broken",
        }
    }

    pub fn severity(self) -> RiskSeverity {
        match self {
            Self::Nominal => RiskSeverity::Green,
            Self::Tracking => RiskSeverity::Watch,
            Self::Deep => RiskSeverity::Critical,
            Self::FinalityBroken => RiskSeverity::Halted,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitQueueStatus {
    Normal,
    Backlogged,
    Congested,
    Frozen,
}

impl ExitQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Backlogged => "backlogged",
            Self::Congested => "congested",
            Self::Frozen => "frozen",
        }
    }

    pub fn accepts_standard_exits(self) -> bool {
        matches!(self, Self::Normal | Self::Backlogged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKeyExposureStatus {
    Sealed,
    SelectiveDisclosure,
    ElevatedDisclosure,
    Compromised,
}

impl ViewKeyExposureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::ElevatedDisclosure => "elevated_disclosure",
            Self::Compromised => "compromised",
        }
    }

    pub fn requires_rotation(self) -> bool {
        matches!(self, Self::ElevatedDisclosure | Self::Compromised)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityStressStatus {
    Covered,
    BufferThin,
    MakerStress,
    EmergencyReserveOnly,
}

impl LiquidityStressStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::BufferThin => "buffer_thin",
            Self::MakerStress => "maker_stress",
            Self::EmergencyReserveOnly => "emergency_reserve_only",
        }
    }

    pub fn severity(self) -> RiskSeverity {
        match self {
            Self::Covered => RiskSeverity::Green,
            Self::BufferThin => RiskSeverity::Watch,
            Self::MakerStress => RiskSeverity::Elevated,
            Self::EmergencyReserveOnly => RiskSeverity::Critical,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    EvidencePending,
    UnderReview,
    Sustained,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::EvidencePending => "evidence_pending",
            Self::UnderReview => "under_review",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Filed | Self::EvidencePending | Self::UnderReview
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    ReserveDrift,
    ReorgEvidence,
    ExitDoubleSpend,
    ViewKeyLeak,
    FeeCapBreach,
    AttestationFailure,
    LiquidityMisreport,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveDrift => "reserve_drift",
            Self::ReorgEvidence => "reorg_evidence",
            Self::ExitDoubleSpend => "exit_double_spend",
            Self::ViewKeyLeak => "view_key_leak",
            Self::FeeCapBreach => "fee_cap_breach",
            Self::AttestationFailure => "attestation_failure",
            Self::LiquidityMisreport => "liquidity_misreport",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationHealth {
    Fresh,
    Aging,
    MissingQuorum,
    Expired,
    Invalid,
}

impl PqAttestationHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Aging => "aging",
            Self::MissingQuorum => "missing_quorum",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Fresh | Self::Aging)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCapStatus {
    WithinCap,
    NearCap,
    Breached,
    WaivedEmergency,
}

impl FeeCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WithinCap => "within_cap",
            Self::NearCap => "near_cap",
            Self::Breached => "breached",
            Self::WaivedEmergency => "waived_emergency",
        }
    }

    pub fn counts_as_breach(self) -> bool {
        matches!(self, Self::Breached)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseLane {
    Deposits,
    StandardExits,
    PrivateExits,
    FastExits,
    Minting,
    Burning,
    SignerRotation,
    FullBridge,
}

impl PauseLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposits => "deposits",
            Self::StandardExits => "standard_exits",
            Self::PrivateExits => "private_exits",
            Self::FastExits => "fast_exits",
            Self::Minting => "minting",
            Self::Burning => "burning",
            Self::SignerRotation => "signer_rotation",
            Self::FullBridge => "full_bridge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseStatus {
    Armed,
    Active,
    CoolingDown,
    Released,
    Expired,
}

impl PauseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Armed | Self::Active | Self::CoolingDown)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u32,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub target_reserve_coverage_bps: u64,
    pub warning_reserve_drift_bps: u64,
    pub critical_reserve_drift_bps: u64,
    pub halt_reserve_drift_bps: u64,
    pub reorg_warning_depth: u64,
    pub reorg_critical_depth: u64,
    pub exit_queue_warning: u64,
    pub exit_queue_critical: u64,
    pub view_key_exposure_limit_bps: u64,
    pub liquidity_buffer_bps: u64,
    pub challenge_ttl_blocks: u64,
    pub pause_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fee_cap_bps: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: MONERO_BRIDGE_RISK_CONTROL_CENTER_PROTOCOL_VERSION.to_string(),
            schema_version: 1,
            monero_network: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEVNET_FEE_ASSET_ID.to_string(),
            target_reserve_coverage_bps:
                MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            warning_reserve_drift_bps:
                MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_WARNING_RESERVE_DRIFT_BPS,
            critical_reserve_drift_bps:
                MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_CRITICAL_RESERVE_DRIFT_BPS,
            halt_reserve_drift_bps:
                MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_HALT_RESERVE_DRIFT_BPS,
            reorg_warning_depth: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_REORG_WARNING_DEPTH,
            reorg_critical_depth: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_REORG_CRITICAL_DEPTH,
            exit_queue_warning: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_EXIT_QUEUE_WARNING,
            exit_queue_critical: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_EXIT_QUEUE_CRITICAL,
            view_key_exposure_limit_bps:
                MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_VIEW_KEY_EXPOSURE_BPS,
            liquidity_buffer_bps: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_LIQUIDITY_BUFFER_BPS,
            challenge_ttl_blocks:
                MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_FRAUD_CHALLENGE_TTL_BLOCKS,
            pause_ttl_blocks: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_PAUSE_TTL_BLOCKS,
            attestation_ttl_blocks:
                MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_ATTESTATION_TTL_BLOCKS,
            fee_cap_bps: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_FEE_CAP_BPS,
            min_pq_security_bits: MONERO_BRIDGE_RISK_CONTROL_CENTER_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("chain_id", &self.chain_id)?;
        require_id("protocol_version", &self.protocol_version)?;
        require_id("monero_network", &self.monero_network)?;
        require_id("asset_id", &self.asset_id)?;
        require_id("fee_asset_id", &self.fee_asset_id)?;
        if self.protocol_version != MONERO_BRIDGE_RISK_CONTROL_CENTER_PROTOCOL_VERSION {
            return Err("protocol_version mismatch".to_string());
        }
        if self.target_reserve_coverage_bps < MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS {
            return Err("target reserve coverage must be at least fully covered".to_string());
        }
        if self.warning_reserve_drift_bps > self.critical_reserve_drift_bps {
            return Err("warning reserve drift must not exceed critical drift".to_string());
        }
        if self.critical_reserve_drift_bps > self.halt_reserve_drift_bps {
            return Err("critical reserve drift must not exceed halt drift".to_string());
        }
        if self.reorg_warning_depth > self.reorg_critical_depth {
            return Err("reorg warning depth must not exceed critical depth".to_string());
        }
        if self.exit_queue_warning > self.exit_queue_critical {
            return Err("exit queue warning must not exceed critical threshold".to_string());
        }
        if self.view_key_exposure_limit_bps > MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS {
            return Err("view key exposure limit exceeds max bps".to_string());
        }
        if self.fee_cap_bps > MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS {
            return Err("fee cap exceeds max bps".to_string());
        }
        if self.min_pq_security_bits == 0 {
            return Err("min pq security bits must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "warning_reserve_drift_bps": self.warning_reserve_drift_bps,
            "critical_reserve_drift_bps": self.critical_reserve_drift_bps,
            "halt_reserve_drift_bps": self.halt_reserve_drift_bps,
            "reorg_warning_depth": self.reorg_warning_depth,
            "reorg_critical_depth": self.reorg_critical_depth,
            "exit_queue_warning": self.exit_queue_warning,
            "exit_queue_critical": self.exit_queue_critical,
            "view_key_exposure_limit_bps": self.view_key_exposure_limit_bps,
            "liquidity_buffer_bps": self.liquidity_buffer_bps,
            "challenge_ttl_blocks": self.challenge_ttl_blocks,
            "pause_ttl_blocks": self.pause_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fee_cap_bps": self.fee_cap_bps,
            "min_pq_security_bits": self.min_pq_security_bits
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveDriftCheck {
    pub check_id: String,
    pub reserve_root: String,
    pub minted_supply_root: String,
    pub observed_reserve_piconero: u64,
    pub minted_supply_piconero: u64,
    pub target_coverage_bps: u64,
    pub observed_coverage_bps: u64,
    pub absolute_drift_bps: u64,
    pub status: ReserveDriftStatus,
    pub watcher_set_root: String,
    pub evidence_root: String,
    pub measured_at_height: u64,
}

impl ReserveDriftCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "reserve_root": self.reserve_root,
            "minted_supply_root": self.minted_supply_root,
            "observed_reserve_piconero": self.observed_reserve_piconero,
            "minted_supply_piconero": self.minted_supply_piconero,
            "target_coverage_bps": self.target_coverage_bps,
            "observed_coverage_bps": self.observed_coverage_bps,
            "absolute_drift_bps": self.absolute_drift_bps,
            "status": self.status.as_str(),
            "severity": self.status.severity().as_str(),
            "watcher_set_root": self.watcher_set_root,
            "evidence_root": self.evidence_root,
            "measured_at_height": self.measured_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReorgDepthSignal {
    pub signal_id: String,
    pub monero_block_hash_root: String,
    pub l2_anchor_root: String,
    pub replaced_depth: u64,
    pub safe_depth: u64,
    pub status: ReorgRiskStatus,
    pub daemon_quorum_root: String,
    pub mitigation_root: String,
    pub observed_at_height: u64,
}

impl ReorgDepthSignal {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "monero_block_hash_root": self.monero_block_hash_root,
            "l2_anchor_root": self.l2_anchor_root,
            "replaced_depth": self.replaced_depth,
            "safe_depth": self.safe_depth,
            "status": self.status.as_str(),
            "severity": self.status.severity().as_str(),
            "daemon_quorum_root": self.daemon_quorum_root,
            "mitigation_root": self.mitigation_root,
            "observed_at_height": self.observed_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitQueueGuardrail {
    pub queue_id: String,
    pub lane: PauseLane,
    pub status: ExitQueueStatus,
    pub pending_exits: u64,
    pub pending_amount_bucket: u64,
    pub oldest_exit_height: u64,
    pub max_release_bps: u64,
    pub queue_commitment_root: String,
    pub liquidity_reservation_root: String,
    pub updated_at_height: u64,
}

impl ExitQueueGuardrail {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "accepts_standard_exits": self.status.accepts_standard_exits(),
            "pending_exits": self.pending_exits,
            "pending_amount_bucket": self.pending_amount_bucket,
            "oldest_exit_height": self.oldest_exit_height,
            "max_release_bps": self.max_release_bps,
            "queue_commitment_root": self.queue_commitment_root,
            "liquidity_reservation_root": self.liquidity_reservation_root,
            "updated_at_height": self.updated_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewKeyExposureWindow {
    pub window_id: String,
    pub disclosure_policy_root: String,
    pub disclosed_view_key_root: String,
    pub recipient_set_root: String,
    pub exposure_bps: u64,
    pub max_exposure_bps: u64,
    pub status: ViewKeyExposureStatus,
    pub rotation_plan_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ViewKeyExposureWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "disclosure_policy_root": self.disclosure_policy_root,
            "disclosed_view_key_root": self.disclosed_view_key_root,
            "recipient_set_root": self.recipient_set_root,
            "exposure_bps": self.exposure_bps,
            "max_exposure_bps": self.max_exposure_bps,
            "status": self.status.as_str(),
            "requires_rotation": self.status.requires_rotation(),
            "rotation_plan_root": self.rotation_plan_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidityStressSnapshot {
    pub snapshot_id: String,
    pub maker_pool_root: String,
    pub emergency_reserve_root: String,
    pub available_liquidity_piconero: u64,
    pub stressed_exit_piconero: u64,
    pub buffer_bps: u64,
    pub status: LiquidityStressStatus,
    pub auction_backstop_root: String,
    pub measured_at_height: u64,
}

impl LiquidityStressSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "maker_pool_root": self.maker_pool_root,
            "emergency_reserve_root": self.emergency_reserve_root,
            "available_liquidity_piconero": self.available_liquidity_piconero,
            "stressed_exit_piconero": self.stressed_exit_piconero,
            "buffer_bps": self.buffer_bps,
            "status": self.status.as_str(),
            "severity": self.status.severity().as_str(),
            "auction_backstop_root": self.auction_backstop_root,
            "measured_at_height": self.measured_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudChallenge {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub challenger_commitment: String,
    pub subject_id: String,
    pub subject_root: String,
    pub evidence_root: String,
    pub bond_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FraudChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "live": self.status.live(),
            "challenger_commitment": self.challenger_commitment,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "bond_commitment": self.bond_commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAttestationStatus {
    pub attestation_id: String,
    pub signer_set_root: String,
    pub subject_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub health: PqAttestationHealth,
    pub signer_weight: u64,
    pub required_weight: u64,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAttestationStatus {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "signer_set_root": self.signer_set_root,
            "subject_root": self.subject_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "health": self.health.as_str(),
            "usable": self.health.usable(),
            "signer_weight": self.signer_weight,
            "required_weight": self.required_weight,
            "security_bits": self.security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeCapBreach {
    pub breach_id: String,
    pub lane: PauseLane,
    pub status: FeeCapStatus,
    pub observed_fee_bps: u64,
    pub cap_bps: u64,
    pub quote_root: String,
    pub refund_commitment_root: String,
    pub operator_commitment: String,
    pub observed_at_height: u64,
}

impl FeeCapBreach {
    pub fn public_record(&self) -> Value {
        json!({
            "breach_id": self.breach_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "counts_as_breach": self.status.counts_as_breach(),
            "observed_fee_bps": self.observed_fee_bps,
            "cap_bps": self.cap_bps,
            "quote_root": self.quote_root,
            "refund_commitment_root": self.refund_commitment_root,
            "operator_commitment": self.operator_commitment,
            "observed_at_height": self.observed_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyPauseLane {
    pub pause_id: String,
    pub lane: PauseLane,
    pub status: PauseStatus,
    pub severity: RiskSeverity,
    pub reason_root: String,
    pub guardian_set_root: String,
    pub release_condition_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl EmergencyPauseLane {
    pub fn public_record(&self) -> Value {
        json!({
            "pause_id": self.pause_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "live": self.status.live(),
            "severity": self.severity.as_str(),
            "reason_root": self.reason_root,
            "guardian_set_root": self.guardian_set_root,
            "release_condition_root": self.release_condition_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskDecision {
    pub decision_id: String,
    pub severity: RiskSeverity,
    pub subject_id: String,
    pub subject_root: String,
    pub control_action: String,
    pub rationale_root: String,
    pub enacted_by_root: String,
    pub emitted_at_height: u64,
}

impl RiskDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "severity": self.severity.as_str(),
            "score_bps": self.severity.score_bps(),
            "blocks_new_exits": self.severity.blocks_new_exits(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "control_action": self.control_action,
            "rationale_root": self.rationale_root,
            "enacted_by_root": self.enacted_by_root,
            "emitted_at_height": self.emitted_at_height
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub reserve_drift_root: String,
    pub reorg_signal_root: String,
    pub exit_queue_root: String,
    pub view_key_exposure_root: String,
    pub liquidity_stress_root: String,
    pub fraud_challenge_root: String,
    pub pq_attestation_root: String,
    pub fee_cap_breach_root: String,
    pub pause_lane_root: String,
    pub risk_decision_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "reserve_drift_root": self.reserve_drift_root,
            "reorg_signal_root": self.reorg_signal_root,
            "exit_queue_root": self.exit_queue_root,
            "view_key_exposure_root": self.view_key_exposure_root,
            "liquidity_stress_root": self.liquidity_stress_root,
            "fraud_challenge_root": self.fraud_challenge_root,
            "pq_attestation_root": self.pq_attestation_root,
            "fee_cap_breach_root": self.fee_cap_breach_root,
            "pause_lane_root": self.pause_lane_root,
            "risk_decision_root": self.risk_decision_root
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub reserve_drift_checks: u64,
    pub critical_reserve_drift_checks: u64,
    pub reorg_signals: u64,
    pub deep_reorg_signals: u64,
    pub exit_queues: u64,
    pub congested_exit_queues: u64,
    pub view_key_windows: u64,
    pub exposed_view_key_windows: u64,
    pub liquidity_snapshots: u64,
    pub stressed_liquidity_snapshots: u64,
    pub fraud_challenges: u64,
    pub live_fraud_challenges: u64,
    pub pq_attestations: u64,
    pub unhealthy_pq_attestations: u64,
    pub fee_cap_breaches: u64,
    pub live_pause_lanes: u64,
    pub risk_decisions: u64,
    pub halted_decisions: u64,
    pub total_pending_exits: u64,
    pub total_pending_exit_amount_bucket: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_drift_checks": self.reserve_drift_checks,
            "critical_reserve_drift_checks": self.critical_reserve_drift_checks,
            "reorg_signals": self.reorg_signals,
            "deep_reorg_signals": self.deep_reorg_signals,
            "exit_queues": self.exit_queues,
            "congested_exit_queues": self.congested_exit_queues,
            "view_key_windows": self.view_key_windows,
            "exposed_view_key_windows": self.exposed_view_key_windows,
            "liquidity_snapshots": self.liquidity_snapshots,
            "stressed_liquidity_snapshots": self.stressed_liquidity_snapshots,
            "fraud_challenges": self.fraud_challenges,
            "live_fraud_challenges": self.live_fraud_challenges,
            "pq_attestations": self.pq_attestations,
            "unhealthy_pq_attestations": self.unhealthy_pq_attestations,
            "fee_cap_breaches": self.fee_cap_breaches,
            "live_pause_lanes": self.live_pause_lanes,
            "risk_decisions": self.risk_decisions,
            "halted_decisions": self.halted_decisions,
            "total_pending_exits": self.total_pending_exits,
            "total_pending_exit_amount_bucket": self.total_pending_exit_amount_bucket
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub reserve_drift_checks: BTreeMap<String, ReserveDriftCheck>,
    pub reorg_signals: BTreeMap<String, ReorgDepthSignal>,
    pub exit_queues: BTreeMap<String, ExitQueueGuardrail>,
    pub view_key_windows: BTreeMap<String, ViewKeyExposureWindow>,
    pub liquidity_snapshots: BTreeMap<String, LiquidityStressSnapshot>,
    pub fraud_challenges: BTreeMap<String, FraudChallenge>,
    pub pq_attestations: BTreeMap<String, PqAttestationStatus>,
    pub fee_cap_breaches: BTreeMap<String, FeeCapBreach>,
    pub pause_lanes: BTreeMap<String, EmergencyPauseLane>,
    pub risk_decisions: BTreeMap<String, RiskDecision>,
}

impl State {
    pub fn devnet() -> MoneroBridgeRiskControlCenterResult<Self> {
        let config = Config::devnet();
        let height = 12_000;
        let mut state = Self {
            config: config.clone(),
            height,
            reserve_drift_checks: BTreeMap::new(),
            reorg_signals: BTreeMap::new(),
            exit_queues: BTreeMap::new(),
            view_key_windows: BTreeMap::new(),
            liquidity_snapshots: BTreeMap::new(),
            fraud_challenges: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            fee_cap_breaches: BTreeMap::new(),
            pause_lanes: BTreeMap::new(),
            risk_decisions: BTreeMap::new(),
        };

        state.insert_reserve_drift_check(make_reserve_drift_check(
            &config,
            "reserve-drift-devnet-balanced",
            ReserveDriftStatus::Balanced,
            1_125_000_000_000,
            1_000_000_000_000,
            height - 9,
        ))?;
        state.insert_reserve_drift_check(make_reserve_drift_check(
            &config,
            "reserve-drift-devnet-watch",
            ReserveDriftStatus::SoftDrift,
            1_035_000_000_000,
            1_000_000_000_000,
            height - 3,
        ))?;
        state.insert_reorg_signal(make_reorg_signal(
            &config,
            "reorg-signal-devnet-nominal",
            ReorgRiskStatus::Nominal,
            2,
            height - 8,
        ))?;
        state.insert_reorg_signal(make_reorg_signal(
            &config,
            "reorg-signal-devnet-tracking",
            ReorgRiskStatus::Tracking,
            13,
            height - 1,
        ))?;
        state.insert_exit_queue(make_exit_queue(
            &config,
            "exit-queue-standard",
            PauseLane::StandardExits,
            ExitQueueStatus::Backlogged,
            820,
            220_000_000_000,
            height - 31,
        ))?;
        state.insert_exit_queue(make_exit_queue(
            &config,
            "exit-queue-private",
            PauseLane::PrivateExits,
            ExitQueueStatus::Normal,
            180,
            48_000_000_000,
            height - 16,
        ))?;
        state.insert_view_key_window(make_view_key_window(
            &config,
            "view-key-window-selective",
            ViewKeyExposureStatus::SelectiveDisclosure,
            220,
            height - 50,
        ))?;
        state.insert_view_key_window(make_view_key_window(
            &config,
            "view-key-window-rotation-watch",
            ViewKeyExposureStatus::ElevatedDisclosure,
            480,
            height - 20,
        ))?;
        state.insert_liquidity_snapshot(make_liquidity_snapshot(
            &config,
            "liquidity-stress-devnet-covered",
            LiquidityStressStatus::Covered,
            1_450_000_000_000,
            1_000_000_000_000,
            height - 11,
        ))?;
        state.insert_liquidity_snapshot(make_liquidity_snapshot(
            &config,
            "liquidity-stress-devnet-maker-watch",
            LiquidityStressStatus::MakerStress,
            780_000_000_000,
            1_000_000_000_000,
            height - 2,
        ))?;
        state.insert_fraud_challenge(make_fraud_challenge(
            &config,
            "challenge-fee-cap-devnet",
            ChallengeKind::FeeCapBreach,
            ChallengeStatus::UnderReview,
            "exit-quote-devnet-17",
            height - 4,
        ))?;
        state.insert_pq_attestation(make_pq_attestation(
            &config,
            "pq-attestation-risk-center-fresh",
            PqAttestationHealth::Fresh,
            4,
            3,
            height - 5,
        ))?;
        state.insert_pq_attestation(make_pq_attestation(
            &config,
            "pq-attestation-risk-center-aging",
            PqAttestationHealth::Aging,
            3,
            3,
            height - 80,
        ))?;
        state.insert_fee_cap_breach(make_fee_cap_breach(
            &config,
            "fee-cap-fast-exit-near",
            PauseLane::FastExits,
            FeeCapStatus::NearCap,
            170,
            height - 6,
        ))?;
        state.insert_fee_cap_breach(make_fee_cap_breach(
            &config,
            "fee-cap-standard-breach",
            PauseLane::StandardExits,
            FeeCapStatus::Breached,
            240,
            height - 2,
        ))?;
        state.insert_pause_lane(make_pause_lane(
            &config,
            "pause-standard-exits-watch",
            PauseLane::StandardExits,
            PauseStatus::Armed,
            RiskSeverity::Watch,
            height - 2,
        ))?;
        state.insert_risk_decision(make_risk_decision(
            "decision-throttle-standard-exits",
            RiskSeverity::Watch,
            "exit-queue-standard",
            "throttle_standard_exit_release",
            height - 1,
        ))?;
        state.insert_risk_decision(make_risk_decision(
            "decision-rotate-view-key-window",
            RiskSeverity::Elevated,
            "view-key-window-rotation-watch",
            "require_view_key_rotation",
            height,
        ))?;

        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroBridgeRiskControlCenterResult<()> {
        self.config.validate()?;
        check_len("reserve drift checks", self.reserve_drift_checks.len(), 512)?;
        check_len("reorg signals", self.reorg_signals.len(), 512)?;
        check_len("exit queues", self.exit_queues.len(), 128)?;
        check_len("view key windows", self.view_key_windows.len(), 512)?;
        check_len("liquidity snapshots", self.liquidity_snapshots.len(), 512)?;
        check_len("fraud challenges", self.fraud_challenges.len(), 512)?;
        check_len("pq attestations", self.pq_attestations.len(), 512)?;
        check_len("fee cap breaches", self.fee_cap_breaches.len(), 512)?;
        check_len("pause lanes", self.pause_lanes.len(), 128)?;
        check_len("risk decisions", self.risk_decisions.len(), 1_024)?;

        for (key, check) in &self.reserve_drift_checks {
            require_key_match("reserve drift check", key, &check.check_id)?;
            require_hash("reserve root", &check.reserve_root)?;
            require_hash("minted supply root", &check.minted_supply_root)?;
            require_hash("watcher set root", &check.watcher_set_root)?;
            require_hash("evidence root", &check.evidence_root)?;
            if check.observed_coverage_bps > self.config.target_reserve_coverage_bps * 2 {
                return Err("reserve drift coverage is outside expected range".to_string());
            }
        }

        for (key, signal) in &self.reorg_signals {
            require_key_match("reorg signal", key, &signal.signal_id)?;
            require_hash("monero block hash root", &signal.monero_block_hash_root)?;
            require_hash("l2 anchor root", &signal.l2_anchor_root)?;
            require_hash("daemon quorum root", &signal.daemon_quorum_root)?;
            require_hash("mitigation root", &signal.mitigation_root)?;
            if signal.safe_depth < self.config.reorg_warning_depth {
                return Err("reorg signal safe depth is below configured warning depth".to_string());
            }
        }

        for (key, queue) in &self.exit_queues {
            require_key_match("exit queue", key, &queue.queue_id)?;
            require_hash("queue commitment root", &queue.queue_commitment_root)?;
            require_hash(
                "liquidity reservation root",
                &queue.liquidity_reservation_root,
            )?;
            if queue.max_release_bps > MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS {
                return Err("exit queue max release bps exceeds max".to_string());
            }
        }

        for (key, window) in &self.view_key_windows {
            require_key_match("view key window", key, &window.window_id)?;
            require_hash("disclosure policy root", &window.disclosure_policy_root)?;
            require_hash("disclosed view key root", &window.disclosed_view_key_root)?;
            require_hash("recipient set root", &window.recipient_set_root)?;
            require_hash("rotation plan root", &window.rotation_plan_root)?;
            if window.exposure_bps > MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS {
                return Err("view key exposure exceeds max bps".to_string());
            }
            if window.opened_at_height > window.expires_at_height {
                return Err("view key exposure window opens after expiry".to_string());
            }
        }

        for (key, snapshot) in &self.liquidity_snapshots {
            require_key_match("liquidity snapshot", key, &snapshot.snapshot_id)?;
            require_hash("maker pool root", &snapshot.maker_pool_root)?;
            require_hash("emergency reserve root", &snapshot.emergency_reserve_root)?;
            require_hash("auction backstop root", &snapshot.auction_backstop_root)?;
        }

        for (key, challenge) in &self.fraud_challenges {
            require_key_match("fraud challenge", key, &challenge.challenge_id)?;
            require_id("challenge subject id", &challenge.subject_id)?;
            require_hash("challenge subject root", &challenge.subject_root)?;
            require_hash("challenge evidence root", &challenge.evidence_root)?;
            require_hash("challenge bond commitment", &challenge.bond_commitment)?;
            require_hash("challenger commitment", &challenge.challenger_commitment)?;
            if challenge.opened_at_height > challenge.expires_at_height {
                return Err("fraud challenge opens after expiry".to_string());
            }
        }

        for (key, attestation) in &self.pq_attestations {
            require_key_match("pq attestation", key, &attestation.attestation_id)?;
            require_hash("pq signer set root", &attestation.signer_set_root)?;
            require_hash("pq subject root", &attestation.subject_root)?;
            require_hash("pq transcript root", &attestation.transcript_root)?;
            require_hash("pq signature root", &attestation.signature_root)?;
            if attestation.security_bits < self.config.min_pq_security_bits {
                return Err("pq attestation security bits below minimum".to_string());
            }
            if attestation.signer_weight < attestation.required_weight
                && attestation.health.usable()
            {
                return Err("usable pq attestation lacks required signer weight".to_string());
            }
        }

        for (key, breach) in &self.fee_cap_breaches {
            require_key_match("fee cap breach", key, &breach.breach_id)?;
            require_hash("fee quote root", &breach.quote_root)?;
            require_hash("fee refund commitment root", &breach.refund_commitment_root)?;
            require_hash("fee operator commitment", &breach.operator_commitment)?;
            if breach.cap_bps > self.config.fee_cap_bps {
                return Err("fee breach cap exceeds configured fee cap".to_string());
            }
        }

        for (key, pause) in &self.pause_lanes {
            require_key_match("pause lane", key, &pause.pause_id)?;
            require_hash("pause reason root", &pause.reason_root)?;
            require_hash("guardian set root", &pause.guardian_set_root)?;
            require_hash("release condition root", &pause.release_condition_root)?;
            if pause.activated_at_height > pause.expires_at_height {
                return Err("pause lane activates after expiry".to_string());
            }
        }

        let known_subjects = self.subject_ids();
        for (key, decision) in &self.risk_decisions {
            require_key_match("risk decision", key, &decision.decision_id)?;
            require_id("risk decision action", &decision.control_action)?;
            require_hash("risk decision subject root", &decision.subject_root)?;
            require_hash("risk decision rationale root", &decision.rationale_root)?;
            require_hash("risk decision enacted by root", &decision.enacted_by_root)?;
            if !known_subjects.contains(&decision.subject_id) {
                return Err(format!(
                    "risk decision subject {} is unknown",
                    decision.subject_id
                ));
            }
        }

        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroBridgeRiskControlCenterResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> MoneroBridgeRiskControlCenterResult<()> {
        self.set_height(height)
    }

    pub fn insert_reserve_drift_check(
        &mut self,
        check: ReserveDriftCheck,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("reserve drift check id", &check.check_id)?;
        self.reserve_drift_checks
            .insert(check.check_id.clone(), check);
        Ok(())
    }

    pub fn insert_reorg_signal(
        &mut self,
        signal: ReorgDepthSignal,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("reorg signal id", &signal.signal_id)?;
        self.reorg_signals.insert(signal.signal_id.clone(), signal);
        Ok(())
    }

    pub fn insert_exit_queue(
        &mut self,
        queue: ExitQueueGuardrail,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("exit queue id", &queue.queue_id)?;
        self.exit_queues.insert(queue.queue_id.clone(), queue);
        Ok(())
    }

    pub fn insert_view_key_window(
        &mut self,
        window: ViewKeyExposureWindow,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("view key window id", &window.window_id)?;
        self.view_key_windows
            .insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn insert_liquidity_snapshot(
        &mut self,
        snapshot: LiquidityStressSnapshot,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("liquidity snapshot id", &snapshot.snapshot_id)?;
        self.liquidity_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    pub fn insert_fraud_challenge(
        &mut self,
        challenge: FraudChallenge,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("fraud challenge id", &challenge.challenge_id)?;
        self.fraud_challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqAttestationStatus,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("pq attestation id", &attestation.attestation_id)?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_fee_cap_breach(
        &mut self,
        breach: FeeCapBreach,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("fee cap breach id", &breach.breach_id)?;
        self.fee_cap_breaches
            .insert(breach.breach_id.clone(), breach);
        Ok(())
    }

    pub fn insert_pause_lane(
        &mut self,
        pause: EmergencyPauseLane,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("pause id", &pause.pause_id)?;
        self.pause_lanes.insert(pause.pause_id.clone(), pause);
        Ok(())
    }

    pub fn insert_risk_decision(
        &mut self,
        decision: RiskDecision,
    ) -> MoneroBridgeRiskControlCenterResult<()> {
        require_id("risk decision id", &decision.decision_id)?;
        self.risk_decisions
            .insert(decision.decision_id.clone(), decision);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(&self.config.public_record()),
            reserve_drift_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-RESERVE-DRIFT-ROOT",
                self.reserve_drift_checks
                    .values()
                    .map(ReserveDriftCheck::public_record),
            ),
            reorg_signal_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-REORG-SIGNAL-ROOT",
                self.reorg_signals
                    .values()
                    .map(ReorgDepthSignal::public_record),
            ),
            exit_queue_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-EXIT-QUEUE-ROOT",
                self.exit_queues
                    .values()
                    .map(ExitQueueGuardrail::public_record),
            ),
            view_key_exposure_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-VIEW-KEY-EXPOSURE-ROOT",
                self.view_key_windows
                    .values()
                    .map(ViewKeyExposureWindow::public_record),
            ),
            liquidity_stress_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-LIQUIDITY-STRESS-ROOT",
                self.liquidity_snapshots
                    .values()
                    .map(LiquidityStressSnapshot::public_record),
            ),
            fraud_challenge_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-FRAUD-CHALLENGE-ROOT",
                self.fraud_challenges
                    .values()
                    .map(FraudChallenge::public_record),
            ),
            pq_attestation_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-PQ-ATTESTATION-ROOT",
                self.pq_attestations
                    .values()
                    .map(PqAttestationStatus::public_record),
            ),
            fee_cap_breach_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-FEE-CAP-BREACH-ROOT",
                self.fee_cap_breaches
                    .values()
                    .map(FeeCapBreach::public_record),
            ),
            pause_lane_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-PAUSE-LANE-ROOT",
                self.pause_lanes
                    .values()
                    .map(EmergencyPauseLane::public_record),
            ),
            risk_decision_root: map_root(
                "MONERO-BRIDGE-RISK-CONTROL-CENTER-RISK-DECISION-ROOT",
                self.risk_decisions
                    .values()
                    .map(RiskDecision::public_record),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            reserve_drift_checks: self.reserve_drift_checks.len() as u64,
            critical_reserve_drift_checks: self
                .reserve_drift_checks
                .values()
                .filter(|check| check.status.severity() >= RiskSeverity::Critical)
                .count() as u64,
            reorg_signals: self.reorg_signals.len() as u64,
            deep_reorg_signals: self
                .reorg_signals
                .values()
                .filter(|signal| signal.status.severity() >= RiskSeverity::Critical)
                .count() as u64,
            exit_queues: self.exit_queues.len() as u64,
            congested_exit_queues: self
                .exit_queues
                .values()
                .filter(|queue| {
                    matches!(
                        queue.status,
                        ExitQueueStatus::Congested | ExitQueueStatus::Frozen
                    )
                })
                .count() as u64,
            view_key_windows: self.view_key_windows.len() as u64,
            exposed_view_key_windows: self
                .view_key_windows
                .values()
                .filter(|window| window.status.requires_rotation())
                .count() as u64,
            liquidity_snapshots: self.liquidity_snapshots.len() as u64,
            stressed_liquidity_snapshots: self
                .liquidity_snapshots
                .values()
                .filter(|snapshot| snapshot.status.severity() >= RiskSeverity::Elevated)
                .count() as u64,
            fraud_challenges: self.fraud_challenges.len() as u64,
            live_fraud_challenges: self
                .fraud_challenges
                .values()
                .filter(|challenge| challenge.status.live())
                .count() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            unhealthy_pq_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| !attestation.health.usable())
                .count() as u64,
            fee_cap_breaches: self
                .fee_cap_breaches
                .values()
                .filter(|breach| breach.status.counts_as_breach())
                .count() as u64,
            live_pause_lanes: self
                .pause_lanes
                .values()
                .filter(|pause| pause.status.live())
                .count() as u64,
            risk_decisions: self.risk_decisions.len() as u64,
            halted_decisions: self
                .risk_decisions
                .values()
                .filter(|decision| decision.severity == RiskSeverity::Halted)
                .count() as u64,
            total_pending_exits: self
                .exit_queues
                .values()
                .map(|queue| queue.pending_exits)
                .sum(),
            total_pending_exit_amount_bucket: self
                .exit_queues
                .values()
                .map(|queue| queue.pending_amount_bucket)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-BRIDGE-RISK-CONTROL-CENTER-STATE",
            &[
                HashPart::Str(&self.height.to_string()),
                HashPart::Json(&self.roots().public_record()),
                HashPart::Json(&self.counters().public_record()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "state_root": self.state_root(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "privacy": {
                "public_records_are_commitment_only": true,
                "monero_view_keys_are_root_commitments": true,
                "reserve_outputs_are_bucketed": true,
                "fraud_evidence_is_commitment_rooted": true,
                "pq_attestations_are_public_key_commitments": true
            }
        })
    }

    fn subject_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        ids.extend(self.reserve_drift_checks.keys().cloned());
        ids.extend(self.reorg_signals.keys().cloned());
        ids.extend(self.exit_queues.keys().cloned());
        ids.extend(self.view_key_windows.keys().cloned());
        ids.extend(self.liquidity_snapshots.keys().cloned());
        ids.extend(self.fraud_challenges.keys().cloned());
        ids.extend(self.pq_attestations.keys().cloned());
        ids.extend(self.fee_cap_breaches.keys().cloned());
        ids.extend(self.pause_lanes.keys().cloned());
        ids
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-BRIDGE-RISK-CONTROL-CENTER-RECORD",
        &[
            HashPart::Str(MONERO_BRIDGE_RISK_CONTROL_CENTER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> MoneroBridgeRiskControlCenterResult<State> {
    State::devnet()
}

fn make_reserve_drift_check(
    config: &Config,
    check_id: &str,
    status: ReserveDriftStatus,
    observed_reserve_piconero: u64,
    minted_supply_piconero: u64,
    measured_at_height: u64,
) -> ReserveDriftCheck {
    let observed_coverage_bps = if minted_supply_piconero == 0 {
        0
    } else {
        observed_reserve_piconero.saturating_mul(MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS)
            / minted_supply_piconero
    };
    let absolute_drift_bps = config
        .target_reserve_coverage_bps
        .abs_diff(observed_coverage_bps);
    ReserveDriftCheck {
        check_id: check_id.to_string(),
        reserve_root: record_root("reserve", check_id),
        minted_supply_root: record_root("minted-supply", check_id),
        observed_reserve_piconero,
        minted_supply_piconero,
        target_coverage_bps: config.target_reserve_coverage_bps,
        observed_coverage_bps,
        absolute_drift_bps,
        status,
        watcher_set_root: record_root("watcher-set", check_id),
        evidence_root: record_root("reserve-drift-evidence", check_id),
        measured_at_height,
    }
}

fn make_reorg_signal(
    config: &Config,
    signal_id: &str,
    status: ReorgRiskStatus,
    replaced_depth: u64,
    observed_at_height: u64,
) -> ReorgDepthSignal {
    ReorgDepthSignal {
        signal_id: signal_id.to_string(),
        monero_block_hash_root: record_root("monero-block-hash", signal_id),
        l2_anchor_root: record_root("l2-anchor", signal_id),
        replaced_depth,
        safe_depth: config.reorg_critical_depth,
        status,
        daemon_quorum_root: record_root("daemon-quorum", signal_id),
        mitigation_root: record_root("reorg-mitigation", signal_id),
        observed_at_height,
    }
}

fn make_exit_queue(
    config: &Config,
    queue_id: &str,
    lane: PauseLane,
    status: ExitQueueStatus,
    pending_exits: u64,
    pending_amount_bucket: u64,
    oldest_exit_height: u64,
) -> ExitQueueGuardrail {
    let max_release_bps = if pending_exits >= config.exit_queue_critical {
        750
    } else if pending_exits >= config.exit_queue_warning {
        2_500
    } else {
        8_000
    };
    ExitQueueGuardrail {
        queue_id: queue_id.to_string(),
        lane,
        status,
        pending_exits,
        pending_amount_bucket,
        oldest_exit_height,
        max_release_bps,
        queue_commitment_root: record_root("exit-queue", queue_id),
        liquidity_reservation_root: record_root("liquidity-reservation", queue_id),
        updated_at_height: oldest_exit_height + 1,
    }
}

fn make_view_key_window(
    config: &Config,
    window_id: &str,
    status: ViewKeyExposureStatus,
    exposure_bps: u64,
    opened_at_height: u64,
) -> ViewKeyExposureWindow {
    ViewKeyExposureWindow {
        window_id: window_id.to_string(),
        disclosure_policy_root: record_root("disclosure-policy", window_id),
        disclosed_view_key_root: record_root("view-key", window_id),
        recipient_set_root: record_root("recipient-set", window_id),
        exposure_bps,
        max_exposure_bps: config.view_key_exposure_limit_bps,
        status,
        rotation_plan_root: record_root("rotation-plan", window_id),
        opened_at_height,
        expires_at_height: opened_at_height + config.pause_ttl_blocks,
    }
}

fn make_liquidity_snapshot(
    config: &Config,
    snapshot_id: &str,
    status: LiquidityStressStatus,
    available_liquidity_piconero: u64,
    stressed_exit_piconero: u64,
    measured_at_height: u64,
) -> LiquidityStressSnapshot {
    let buffer_bps = if stressed_exit_piconero == 0 {
        MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS
    } else {
        available_liquidity_piconero.saturating_mul(MONERO_BRIDGE_RISK_CONTROL_CENTER_MAX_BPS)
            / stressed_exit_piconero
    };
    LiquidityStressSnapshot {
        snapshot_id: snapshot_id.to_string(),
        maker_pool_root: record_root("maker-pool", snapshot_id),
        emergency_reserve_root: record_root("emergency-reserve", snapshot_id),
        available_liquidity_piconero,
        stressed_exit_piconero,
        buffer_bps: buffer_bps.saturating_sub(config.liquidity_buffer_bps),
        status,
        auction_backstop_root: record_root("auction-backstop", snapshot_id),
        measured_at_height,
    }
}

fn make_fraud_challenge(
    config: &Config,
    challenge_id: &str,
    kind: ChallengeKind,
    status: ChallengeStatus,
    subject_id: &str,
    opened_at_height: u64,
) -> FraudChallenge {
    FraudChallenge {
        challenge_id: challenge_id.to_string(),
        kind,
        status,
        challenger_commitment: commitment("challenger", challenge_id),
        subject_id: subject_id.to_string(),
        subject_root: record_root("challenge-subject", subject_id),
        evidence_root: record_root("challenge-evidence", challenge_id),
        bond_commitment: commitment("challenge-bond", challenge_id),
        opened_at_height,
        expires_at_height: opened_at_height + config.challenge_ttl_blocks,
    }
}

fn make_pq_attestation(
    config: &Config,
    attestation_id: &str,
    health: PqAttestationHealth,
    signer_weight: u64,
    required_weight: u64,
    attested_at_height: u64,
) -> PqAttestationStatus {
    PqAttestationStatus {
        attestation_id: attestation_id.to_string(),
        signer_set_root: record_root("pq-signer-set", attestation_id),
        subject_root: record_root("pq-subject", attestation_id),
        transcript_root: record_root("pq-transcript", attestation_id),
        signature_root: record_root("pq-signature", attestation_id),
        health,
        signer_weight,
        required_weight,
        security_bits: config.min_pq_security_bits,
        attested_at_height,
        expires_at_height: attested_at_height + config.attestation_ttl_blocks,
    }
}

fn make_fee_cap_breach(
    config: &Config,
    breach_id: &str,
    lane: PauseLane,
    status: FeeCapStatus,
    observed_fee_bps: u64,
    observed_at_height: u64,
) -> FeeCapBreach {
    FeeCapBreach {
        breach_id: breach_id.to_string(),
        lane,
        status,
        observed_fee_bps,
        cap_bps: config.fee_cap_bps,
        quote_root: record_root("fee-quote", breach_id),
        refund_commitment_root: record_root("fee-refund", breach_id),
        operator_commitment: commitment("operator", breach_id),
        observed_at_height,
    }
}

fn make_pause_lane(
    config: &Config,
    pause_id: &str,
    lane: PauseLane,
    status: PauseStatus,
    severity: RiskSeverity,
    activated_at_height: u64,
) -> EmergencyPauseLane {
    EmergencyPauseLane {
        pause_id: pause_id.to_string(),
        lane,
        status,
        severity,
        reason_root: record_root("pause-reason", pause_id),
        guardian_set_root: record_root("guardian-set", pause_id),
        release_condition_root: record_root("release-condition", pause_id),
        activated_at_height,
        expires_at_height: activated_at_height + config.pause_ttl_blocks,
    }
}

fn make_risk_decision(
    decision_id: &str,
    severity: RiskSeverity,
    subject_id: &str,
    control_action: &str,
    emitted_at_height: u64,
) -> RiskDecision {
    RiskDecision {
        decision_id: decision_id.to_string(),
        severity,
        subject_id: subject_id.to_string(),
        subject_root: record_root("risk-decision-subject", subject_id),
        control_action: control_action.to_string(),
        rationale_root: record_root("risk-rationale", decision_id),
        enacted_by_root: record_root("risk-control-council", decision_id),
        emitted_at_height,
    }
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &records.into_iter().collect::<Vec<_>>())
}

fn record_root(label: &str, value: &str) -> String {
    let record = json!({
        "label": label,
        "value": value,
        "protocol_version": MONERO_BRIDGE_RISK_CONTROL_CENTER_PROTOCOL_VERSION
    });
    domain_hash(
        "MONERO-BRIDGE-RISK-CONTROL-CENTER-RECORD-ROOT",
        &[HashPart::Json(&record)],
        32,
    )
}

fn commitment(label: &str, value: &str) -> String {
    domain_hash(
        "MONERO-BRIDGE-RISK-CONTROL-CENTER-COMMITMENT",
        &[
            HashPart::Str(MONERO_BRIDGE_RISK_CONTROL_CENTER_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn require_id(label: &str, value: &str) -> MoneroBridgeRiskControlCenterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    if value.len() > 192 {
        return Err(format!("{label} is too long"));
    }
    Ok(())
}

fn require_hash(label: &str, value: &str) -> MoneroBridgeRiskControlCenterResult<()> {
    require_id(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} must be a commitment-like value"));
    }
    Ok(())
}

fn require_key_match(
    label: &str,
    key: &str,
    value: &str,
) -> MoneroBridgeRiskControlCenterResult<()> {
    if key != value {
        return Err(format!("{label} map key does not match embedded id"));
    }
    Ok(())
}

fn check_len(label: &str, len: usize, max: usize) -> MoneroBridgeRiskControlCenterResult<()> {
    if len > max {
        return Err(format!("{label} exceeds maximum"));
    }
    Ok(())
}
