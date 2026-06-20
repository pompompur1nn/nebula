use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroBridgeSafetyResult<T> = Result<T, String>;

pub const MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION: &str = "nebula-monero-bridge-safety-v1";
pub const MONERO_BRIDGE_SAFETY_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_BRIDGE_SAFETY_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_BRIDGE_SAFETY_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_250;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_EMERGENCY_RESERVE_COVERAGE_BPS: u64 = 9_900;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_MAX_RELEASE_BPS_PER_WINDOW: u64 = 1_500;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_PRIVATE_EXIT_MIN_SHARE_BPS: u64 = 4_000;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_LOW_FEE_EXIT_REBATE_BPS: u64 = 8_000;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_GUARDIAN_QUORUM: u64 = 2;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_REORG_DEPTH_BLOCKS: u64 = 12;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 24;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_PAUSE_TTL_BLOCKS: u64 = 48;
pub const MONERO_BRIDGE_SAFETY_DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 144;
pub const MONERO_BRIDGE_SAFETY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeSafetyStatus {
    Green,
    Watch,
    Throttled,
    Paused,
    Emergency,
}

impl BridgeSafetyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Watch => "watch",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Emergency => "emergency",
        }
    }

    pub fn is_release_allowed(self) -> bool {
        matches!(self, Self::Green | Self::Watch | Self::Throttled)
    }

    pub fn score_bps(self) -> u64 {
        match self {
            Self::Green => 10_000,
            Self::Watch => 8_000,
            Self::Throttled => 5_000,
            Self::Paused => 1_500,
            Self::Emergency => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveRiskLevel {
    Healthy,
    BufferLow,
    UnderCovered,
    Insolvent,
    Unknown,
}

impl ReserveRiskLevel {
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
    ) -> Self {
        if coverage_bps == 0 {
            Self::Unknown
        } else if coverage_bps >= target_coverage_bps {
            Self::Healthy
        } else if coverage_bps >= min_coverage_bps {
            Self::BufferLow
        } else if coverage_bps >= MONERO_BRIDGE_SAFETY_MAX_BPS {
            Self::UnderCovered
        } else {
            Self::Insolvent
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalLane {
    Standard,
    LowFee,
    Private,
    Emergency,
}

impl WithdrawalLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::LowFee => "low_fee",
            Self::Private => "private",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 0,
            Self::Private => 1,
            Self::LowFee => 2,
            Self::Standard => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerEvidenceKind {
    Reorg,
    ReserveShortfall,
    DoubleRelease,
    SignerEquivocation,
    DelayedBroadcast,
    FeeGriefing,
    ViewKeyLeak,
    Unknown,
}

impl WatchtowerEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::DoubleRelease => "double_release",
            Self::SignerEquivocation => "signer_equivocation",
            Self::DelayedBroadcast => "delayed_broadcast",
            Self::FeeGriefing => "fee_griefing",
            Self::ViewKeyLeak => "view_key_leak",
            Self::Unknown => "unknown",
        }
    }

    pub fn triggers_pause(self) -> bool {
        matches!(
            self,
            Self::ReserveShortfall
                | Self::DoubleRelease
                | Self::SignerEquivocation
                | Self::ViewKeyLeak
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseScope {
    Deposits,
    Withdrawals,
    PrivateExits,
    LowFeeExits,
    SignerSet,
    FullBridge,
}

impl PauseScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposits => "deposits",
            Self::Withdrawals => "withdrawals",
            Self::PrivateExits => "private_exits",
            Self::LowFeeExits => "low_fee_exits",
            Self::SignerSet => "signer_set",
            Self::FullBridge => "full_bridge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyEventKind {
    ReserveSnapshot,
    ThrottleUpdated,
    WatchtowerEvidence,
    EmergencyPause,
    PrivateExitGuarantee,
    LowFeeSponsorship,
    ReleaseReceipt,
    RiskTransition,
}

impl SafetyEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveSnapshot => "reserve_snapshot",
            Self::ThrottleUpdated => "throttle_updated",
            Self::WatchtowerEvidence => "watchtower_evidence",
            Self::EmergencyPause => "emergency_pause",
            Self::PrivateExitGuarantee => "private_exit_guarantee",
            Self::LowFeeSponsorship => "low_fee_sponsorship",
            Self::ReleaseReceipt => "release_receipt",
            Self::RiskTransition => "risk_transition",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyActionStatus {
    Open,
    Active,
    Settled,
    Expired,
    Revoked,
}

impl SafetyActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Active => "active",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Open | Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeSafetyConfig {
    pub protocol_version: String,
    pub monero_network: String,
    pub asset_id: String,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub emergency_reserve_coverage_bps: u64,
    pub max_release_bps_per_window: u64,
    pub private_exit_min_share_bps: u64,
    pub low_fee_exit_rebate_bps: u64,
    pub watchtower_quorum: u64,
    pub guardian_quorum: u64,
    pub reorg_depth_blocks: u64,
    pub throttle_window_blocks: u64,
    pub pause_ttl_blocks: u64,
    pub evidence_ttl_blocks: u64,
}

impl Default for MoneroBridgeSafetyConfig {
    fn default() -> Self {
        Self {
            protocol_version: MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION.to_string(),
            monero_network: MONERO_BRIDGE_SAFETY_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_BRIDGE_SAFETY_DEVNET_ASSET_ID.to_string(),
            min_reserve_coverage_bps: MONERO_BRIDGE_SAFETY_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: MONERO_BRIDGE_SAFETY_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            emergency_reserve_coverage_bps:
                MONERO_BRIDGE_SAFETY_DEFAULT_EMERGENCY_RESERVE_COVERAGE_BPS,
            max_release_bps_per_window: MONERO_BRIDGE_SAFETY_DEFAULT_MAX_RELEASE_BPS_PER_WINDOW,
            private_exit_min_share_bps: MONERO_BRIDGE_SAFETY_DEFAULT_PRIVATE_EXIT_MIN_SHARE_BPS,
            low_fee_exit_rebate_bps: MONERO_BRIDGE_SAFETY_DEFAULT_LOW_FEE_EXIT_REBATE_BPS,
            watchtower_quorum: MONERO_BRIDGE_SAFETY_DEFAULT_WATCHTOWER_QUORUM,
            guardian_quorum: MONERO_BRIDGE_SAFETY_DEFAULT_GUARDIAN_QUORUM,
            reorg_depth_blocks: MONERO_BRIDGE_SAFETY_DEFAULT_REORG_DEPTH_BLOCKS,
            throttle_window_blocks: MONERO_BRIDGE_SAFETY_DEFAULT_THROTTLE_WINDOW_BLOCKS,
            pause_ttl_blocks: MONERO_BRIDGE_SAFETY_DEFAULT_PAUSE_TTL_BLOCKS,
            evidence_ttl_blocks: MONERO_BRIDGE_SAFETY_DEFAULT_EVIDENCE_TTL_BLOCKS,
        }
    }
}

impl MoneroBridgeSafetyConfig {
    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.protocol_version, "bridge safety protocol version")?;
        ensure_non_empty(&self.monero_network, "bridge safety monero network")?;
        ensure_non_empty(&self.asset_id, "bridge safety asset id")?;
        if self.protocol_version != MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION {
            return Err("bridge safety protocol version mismatch".to_string());
        }
        ensure_bps(
            self.min_reserve_coverage_bps,
            "bridge safety min reserve coverage",
        )?;
        ensure_bps(
            self.target_reserve_coverage_bps,
            "bridge safety target reserve coverage",
        )?;
        ensure_bps(
            self.emergency_reserve_coverage_bps,
            "bridge safety emergency reserve coverage",
        )?;
        ensure_bps(
            self.max_release_bps_per_window,
            "bridge safety max release bps per window",
        )?;
        ensure_bps(
            self.private_exit_min_share_bps,
            "bridge safety private exit share",
        )?;
        ensure_bps(self.low_fee_exit_rebate_bps, "bridge safety low fee rebate")?;
        if self.emergency_reserve_coverage_bps > self.min_reserve_coverage_bps {
            return Err(
                "bridge safety emergency coverage must not exceed min coverage".to_string(),
            );
        }
        if self.min_reserve_coverage_bps > self.target_reserve_coverage_bps {
            return Err("bridge safety target coverage must cover min coverage".to_string());
        }
        if self.watchtower_quorum == 0 || self.guardian_quorum == 0 {
            return Err("bridge safety quorums must be positive".to_string());
        }
        if self.reorg_depth_blocks == 0
            || self.throttle_window_blocks == 0
            || self.pause_ttl_blocks == 0
            || self.evidence_ttl_blocks == 0
        {
            return Err("bridge safety timing windows must be positive".to_string());
        }
        Ok(self.config_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_safety_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "emergency_reserve_coverage_bps": self.emergency_reserve_coverage_bps,
            "max_release_bps_per_window": self.max_release_bps_per_window,
            "private_exit_min_share_bps": self.private_exit_min_share_bps,
            "low_fee_exit_rebate_bps": self.low_fee_exit_rebate_bps,
            "watchtower_quorum": self.watchtower_quorum,
            "guardian_quorum": self.guardian_quorum,
            "reorg_depth_blocks": self.reorg_depth_blocks,
            "throttle_window_blocks": self.throttle_window_blocks,
            "pause_ttl_blocks": self.pause_ttl_blocks,
            "evidence_ttl_blocks": self.evidence_ttl_blocks,
            "config_root": self.config_root(),
        })
    }

    pub fn config_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-CONFIG",
            &json!({
                "kind": "monero_bridge_safety_config_root",
                "protocol_version": self.protocol_version,
                "monero_network": self.monero_network,
                "asset_id": self.asset_id,
                "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
                "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
                "max_release_bps_per_window": self.max_release_bps_per_window,
                "private_exit_min_share_bps": self.private_exit_min_share_bps,
                "low_fee_exit_rebate_bps": self.low_fee_exit_rebate_bps,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSafetySnapshot {
    pub snapshot_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub height: u64,
    pub observed_monero_height: u64,
    pub reserve_address_set_root: String,
    pub reserve_output_commitment_root: String,
    pub minted_supply_units: u64,
    pub locked_reserve_units: u64,
    pub pending_release_units: u64,
    pub pending_deposit_units: u64,
    pub coverage_bps: u64,
    pub risk_level: ReserveRiskLevel,
    pub watchtower_attestation_root: String,
}

impl ReserveSafetySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        monero_network: impl Into<String>,
        asset_id: impl Into<String>,
        height: u64,
        observed_monero_height: u64,
        reserve_address_set_root: impl Into<String>,
        reserve_output_commitment_root: impl Into<String>,
        minted_supply_units: u64,
        locked_reserve_units: u64,
        pending_release_units: u64,
        pending_deposit_units: u64,
        min_reserve_coverage_bps: u64,
        target_reserve_coverage_bps: u64,
        watchtower_attestation_root: impl Into<String>,
    ) -> MoneroBridgeSafetyResult<Self> {
        let coverage_bps = if minted_supply_units == 0 {
            0
        } else {
            locked_reserve_units
                .saturating_sub(pending_release_units)
                .saturating_mul(MONERO_BRIDGE_SAFETY_MAX_BPS)
                / minted_supply_units
        };
        let risk_level = ReserveRiskLevel::from_coverage(
            coverage_bps,
            min_reserve_coverage_bps,
            target_reserve_coverage_bps,
        );
        let mut snapshot = Self {
            snapshot_id: String::new(),
            monero_network: monero_network.into(),
            asset_id: asset_id.into(),
            height,
            observed_monero_height,
            reserve_address_set_root: reserve_address_set_root.into(),
            reserve_output_commitment_root: reserve_output_commitment_root.into(),
            minted_supply_units,
            locked_reserve_units,
            pending_release_units,
            pending_deposit_units,
            coverage_bps,
            risk_level,
            watchtower_attestation_root: watchtower_attestation_root.into(),
        };
        snapshot.snapshot_id = monero_bridge_safety_snapshot_id(&snapshot.identity_record());
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "reserve_safety_snapshot_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "height": self.height,
            "observed_monero_height": self.observed_monero_height,
            "reserve_output_commitment_root": self.reserve_output_commitment_root,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "reserve_safety_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "height": self.height,
            "observed_monero_height": self.observed_monero_height,
            "reserve_address_set_root": self.reserve_address_set_root,
            "reserve_output_commitment_root": self.reserve_output_commitment_root,
            "minted_supply_units": self.minted_supply_units,
            "locked_reserve_units": self.locked_reserve_units,
            "pending_release_units": self.pending_release_units,
            "pending_deposit_units": self.pending_deposit_units,
            "coverage_bps": self.coverage_bps,
            "risk_level": self.risk_level.as_str(),
            "watchtower_attestation_root": self.watchtower_attestation_root,
        })
    }

    pub fn snapshot_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-RESERVE-SNAPSHOT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "snapshot_root",
            self.snapshot_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.snapshot_id, "bridge safety snapshot id")?;
        ensure_non_empty(&self.monero_network, "bridge safety snapshot network")?;
        ensure_non_empty(&self.asset_id, "bridge safety snapshot asset")?;
        ensure_non_empty(
            &self.reserve_address_set_root,
            "bridge safety reserve address root",
        )?;
        ensure_non_empty(
            &self.reserve_output_commitment_root,
            "bridge safety reserve output root",
        )?;
        ensure_non_empty(
            &self.watchtower_attestation_root,
            "bridge safety watchtower attestation root",
        )?;
        ensure_bps(self.coverage_bps, "bridge safety reserve coverage")?;
        if self.pending_release_units > self.locked_reserve_units {
            return Err("bridge safety pending release exceeds locked reserve".to_string());
        }
        let expected = monero_bridge_safety_snapshot_id(&self.identity_record());
        if self.snapshot_id != expected {
            return Err("bridge safety snapshot id mismatch".to_string());
        }
        Ok(self.snapshot_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalThrottleWindow {
    pub throttle_id: String,
    pub lane: WithdrawalLane,
    pub asset_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_release_units: u64,
    pub consumed_release_units: u64,
    pub reserved_private_units: u64,
    pub reserved_low_fee_units: u64,
    pub reserve_snapshot_id: String,
    pub status: SafetyActionStatus,
}

impl WithdrawalThrottleWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: WithdrawalLane,
        asset_id: impl Into<String>,
        window_start_height: u64,
        window_end_height: u64,
        max_release_units: u64,
        reserved_private_units: u64,
        reserved_low_fee_units: u64,
        reserve_snapshot_id: impl Into<String>,
    ) -> MoneroBridgeSafetyResult<Self> {
        let mut throttle = Self {
            throttle_id: String::new(),
            lane,
            asset_id: asset_id.into(),
            window_start_height,
            window_end_height,
            max_release_units,
            consumed_release_units: 0,
            reserved_private_units,
            reserved_low_fee_units,
            reserve_snapshot_id: reserve_snapshot_id.into(),
            status: SafetyActionStatus::Open,
        };
        throttle.throttle_id = monero_bridge_safety_throttle_id(&throttle.identity_record());
        throttle.validate()?;
        Ok(throttle)
    }

    pub fn consume_release(&mut self, amount_units: u64) -> MoneroBridgeSafetyResult<String> {
        let next = self.consumed_release_units.saturating_add(amount_units);
        if next > self.max_release_units {
            return Err("bridge safety throttle capacity exceeded".to_string());
        }
        self.consumed_release_units = next;
        if self.consumed_release_units == self.max_release_units {
            self.status = SafetyActionStatus::Settled;
        } else if self.consumed_release_units > 0 {
            self.status = SafetyActionStatus::Active;
        }
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.window_end_height {
            self.status = SafetyActionStatus::Expired;
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.max_release_units
            .saturating_sub(self.consumed_release_units)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "withdrawal_throttle_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "lane": self.lane.as_str(),
            "asset_id": self.asset_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "reserve_snapshot_id": self.reserve_snapshot_id,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "withdrawal_throttle_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "throttle_id": self.throttle_id,
            "lane": self.lane.as_str(),
            "asset_id": self.asset_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_release_units": self.max_release_units,
            "consumed_release_units": self.consumed_release_units,
            "remaining_units": self.remaining_units(),
            "reserved_private_units": self.reserved_private_units,
            "reserved_low_fee_units": self.reserved_low_fee_units,
            "reserve_snapshot_id": self.reserve_snapshot_id,
            "status": self.status.as_str(),
        })
    }

    pub fn throttle_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-WITHDRAWAL-THROTTLE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "throttle_root",
            self.throttle_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.throttle_id, "bridge safety throttle id")?;
        ensure_non_empty(&self.asset_id, "bridge safety throttle asset")?;
        ensure_non_empty(
            &self.reserve_snapshot_id,
            "bridge safety throttle reserve snapshot",
        )?;
        if self.window_end_height <= self.window_start_height {
            return Err("bridge safety throttle window must move forward".to_string());
        }
        if self.consumed_release_units > self.max_release_units {
            return Err("bridge safety throttle consumed exceeds max".to_string());
        }
        if self
            .reserved_private_units
            .saturating_add(self.reserved_low_fee_units)
            > self.max_release_units
        {
            return Err("bridge safety reserved lanes exceed max release".to_string());
        }
        let expected = monero_bridge_safety_throttle_id(&self.identity_record());
        if self.throttle_id != expected {
            return Err("bridge safety throttle id mismatch".to_string());
        }
        Ok(self.throttle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerSafetyEvidence {
    pub evidence_id: String,
    pub kind: WatchtowerEvidenceKind,
    pub reporter_commitment: String,
    pub subject_root: String,
    pub observed_height: u64,
    pub expires_at_height: u64,
    pub signature_root: String,
    pub encrypted_details_root: String,
    pub pause_scope: Option<PauseScope>,
    pub status: SafetyActionStatus,
}

impl WatchtowerSafetyEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: WatchtowerEvidenceKind,
        reporter_commitment: impl Into<String>,
        subject_root: impl Into<String>,
        observed_height: u64,
        expires_at_height: u64,
        signature_root: impl Into<String>,
        encrypted_details_root: impl Into<String>,
        pause_scope: Option<PauseScope>,
    ) -> MoneroBridgeSafetyResult<Self> {
        let mut evidence = Self {
            evidence_id: String::new(),
            kind,
            reporter_commitment: reporter_commitment.into(),
            subject_root: subject_root.into(),
            observed_height,
            expires_at_height,
            signature_root: signature_root.into(),
            encrypted_details_root: encrypted_details_root.into(),
            pause_scope,
            status: SafetyActionStatus::Open,
        };
        evidence.evidence_id = monero_bridge_safety_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.expires_at_height {
            self.status = SafetyActionStatus::Expired;
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "watchtower_safety_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "evidence_kind": self.kind.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "subject_root": self.subject_root,
            "observed_height": self.observed_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "watchtower_safety_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.kind.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "subject_root": self.subject_root,
            "observed_height": self.observed_height,
            "expires_at_height": self.expires_at_height,
            "signature_root": self.signature_root,
            "encrypted_details_root": self.encrypted_details_root,
            "pause_scope": self.pause_scope.map(PauseScope::as_str),
            "status": self.status.as_str(),
        })
    }

    pub fn evidence_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-WATCHTOWER-EVIDENCE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "evidence_root",
            self.evidence_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.evidence_id, "bridge safety evidence id")?;
        ensure_non_empty(&self.reporter_commitment, "bridge safety evidence reporter")?;
        ensure_non_empty(&self.subject_root, "bridge safety evidence subject")?;
        ensure_non_empty(&self.signature_root, "bridge safety evidence signature")?;
        ensure_non_empty(
            &self.encrypted_details_root,
            "bridge safety evidence details",
        )?;
        if self.expires_at_height <= self.observed_height {
            return Err("bridge safety evidence expiry must follow observation".to_string());
        }
        if self.kind.triggers_pause() && self.pause_scope.is_none() {
            return Err("bridge safety pause-triggering evidence needs scope".to_string());
        }
        let expected = monero_bridge_safety_evidence_id(&self.identity_record());
        if self.evidence_id != expected {
            return Err("bridge safety evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyBridgePause {
    pub pause_id: String,
    pub scope: PauseScope,
    pub reason: BridgeSafetyStatus,
    pub start_height: u64,
    pub expires_at_height: u64,
    pub guardian_approval_root: String,
    pub evidence_ids: Vec<String>,
    pub status: SafetyActionStatus,
}

impl EmergencyBridgePause {
    pub fn new(
        scope: PauseScope,
        reason: BridgeSafetyStatus,
        start_height: u64,
        expires_at_height: u64,
        guardian_approval_root: impl Into<String>,
        evidence_ids: Vec<String>,
    ) -> MoneroBridgeSafetyResult<Self> {
        let mut pause = Self {
            pause_id: String::new(),
            scope,
            reason,
            start_height,
            expires_at_height,
            guardian_approval_root: guardian_approval_root.into(),
            evidence_ids,
            status: SafetyActionStatus::Active,
        };
        pause.evidence_ids.sort();
        pause.evidence_ids.dedup();
        pause.pause_id = monero_bridge_safety_pause_id(&pause.identity_record());
        pause.validate()?;
        Ok(pause)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.expires_at_height {
            self.status = SafetyActionStatus::Expired;
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "emergency_bridge_pause_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "scope": self.scope.as_str(),
            "reason": self.reason.as_str(),
            "start_height": self.start_height,
            "evidence_root": monero_bridge_safety_string_set_root(
                "MONERO-BRIDGE-SAFETY-PAUSE-EVIDENCE-ID",
                &self.evidence_ids
            ),
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "emergency_bridge_pause",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "pause_id": self.pause_id,
            "scope": self.scope.as_str(),
            "reason": self.reason.as_str(),
            "start_height": self.start_height,
            "expires_at_height": self.expires_at_height,
            "guardian_approval_root": self.guardian_approval_root,
            "evidence_ids": self.evidence_ids,
            "status": self.status.as_str(),
        })
    }

    pub fn pause_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-EMERGENCY-PAUSE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "pause_root",
            self.pause_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.pause_id, "bridge safety pause id")?;
        ensure_non_empty(
            &self.guardian_approval_root,
            "bridge safety pause guardian approval",
        )?;
        if self.expires_at_height <= self.start_height {
            return Err("bridge safety pause expiry must follow start".to_string());
        }
        ensure_unique_strings(&self.evidence_ids, "bridge safety pause evidence ids")?;
        let expected = monero_bridge_safety_pause_id(&self.identity_record());
        if self.pause_id != expected {
            return Err("bridge safety pause id mismatch".to_string());
        }
        Ok(self.pause_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExitGuarantee {
    pub guarantee_id: String,
    pub account_commitment: String,
    pub withdrawal_id: String,
    pub lane: WithdrawalLane,
    pub amount_bucket: u64,
    pub reserved_fee_units: u64,
    pub anonymity_set_root: String,
    pub nullifier_root: String,
    pub throttle_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SafetyActionStatus,
}

impl PrivateExitGuarantee {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment: impl Into<String>,
        withdrawal_id: impl Into<String>,
        lane: WithdrawalLane,
        amount_bucket: u64,
        reserved_fee_units: u64,
        anonymity_set_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        throttle_id: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroBridgeSafetyResult<Self> {
        let mut guarantee = Self {
            guarantee_id: String::new(),
            account_commitment: account_commitment.into(),
            withdrawal_id: withdrawal_id.into(),
            lane,
            amount_bucket,
            reserved_fee_units,
            anonymity_set_root: anonymity_set_root.into(),
            nullifier_root: nullifier_root.into(),
            throttle_id: throttle_id.into(),
            created_at_height,
            expires_at_height,
            status: SafetyActionStatus::Open,
        };
        guarantee.guarantee_id =
            monero_bridge_safety_private_exit_guarantee_id(&guarantee.identity_record());
        guarantee.validate()?;
        Ok(guarantee)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.expires_at_height {
            self.status = SafetyActionStatus::Expired;
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "private_exit_guarantee_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "account_commitment": self.account_commitment,
            "withdrawal_id": self.withdrawal_id,
            "lane": self.lane.as_str(),
            "amount_bucket": self.amount_bucket,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_exit_guarantee",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "guarantee_id": self.guarantee_id,
            "account_commitment": self.account_commitment,
            "withdrawal_id": self.withdrawal_id,
            "lane": self.lane.as_str(),
            "amount_bucket": self.amount_bucket,
            "reserved_fee_units": self.reserved_fee_units,
            "anonymity_set_root": self.anonymity_set_root,
            "nullifier_root": self.nullifier_root,
            "throttle_id": self.throttle_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn guarantee_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-PRIVATE-EXIT-GUARANTEE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "guarantee_root",
            self.guarantee_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.guarantee_id, "bridge safety guarantee id")?;
        ensure_non_empty(&self.account_commitment, "bridge safety guarantee account")?;
        ensure_non_empty(&self.withdrawal_id, "bridge safety guarantee withdrawal")?;
        ensure_non_empty(
            &self.anonymity_set_root,
            "bridge safety guarantee anonymity set",
        )?;
        ensure_non_empty(&self.nullifier_root, "bridge safety guarantee nullifier")?;
        ensure_non_empty(&self.throttle_id, "bridge safety guarantee throttle")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("bridge safety guarantee expiry must follow creation".to_string());
        }
        if !matches!(self.lane, WithdrawalLane::Private | WithdrawalLane::LowFee) {
            return Err("bridge safety guarantee must use private or low fee lane".to_string());
        }
        let expected = monero_bridge_safety_private_exit_guarantee_id(&self.identity_record());
        if self.guarantee_id != expected {
            return Err("bridge safety guarantee id mismatch".to_string());
        }
        Ok(self.guarantee_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExitSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub withdrawal_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_sponsored_fee_units: u64,
    pub consumed_fee_units: u64,
    pub rebate_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SafetyActionStatus,
}

impl LowFeeExitSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        withdrawal_id: impl Into<String>,
        asset_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        max_sponsored_fee_units: u64,
        rebate_bps: u64,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroBridgeSafetyResult<Self> {
        let mut sponsorship = Self {
            sponsorship_id: String::new(),
            sponsor_commitment: sponsor_commitment.into(),
            withdrawal_id: withdrawal_id.into(),
            asset_id: asset_id.into(),
            fee_asset_id: fee_asset_id.into(),
            max_sponsored_fee_units,
            consumed_fee_units: 0,
            rebate_bps,
            created_at_height,
            expires_at_height,
            status: SafetyActionStatus::Open,
        };
        sponsorship.sponsorship_id =
            monero_bridge_safety_low_fee_sponsorship_id(&sponsorship.identity_record());
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn consume_fee(&mut self, fee_units: u64) -> MoneroBridgeSafetyResult<String> {
        let next = self.consumed_fee_units.saturating_add(fee_units);
        if next > self.max_sponsored_fee_units {
            return Err("bridge safety sponsorship exhausted".to_string());
        }
        self.consumed_fee_units = next;
        self.status = if self.consumed_fee_units == self.max_sponsored_fee_units {
            SafetyActionStatus::Settled
        } else {
            SafetyActionStatus::Active
        };
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.expires_at_height {
            self.status = SafetyActionStatus::Expired;
        }
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_sponsored_fee_units
            .saturating_sub(self.consumed_fee_units)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "low_fee_exit_sponsorship_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "sponsor_commitment": self.sponsor_commitment,
            "withdrawal_id": self.withdrawal_id,
            "asset_id": self.asset_id,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "low_fee_exit_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "withdrawal_id": self.withdrawal_id,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_sponsored_fee_units": self.max_sponsored_fee_units,
            "consumed_fee_units": self.consumed_fee_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "rebate_bps": self.rebate_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-LOW-FEE-SPONSORSHIP",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "sponsorship_root",
            self.sponsorship_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.sponsorship_id, "bridge safety sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "bridge safety sponsor commitment")?;
        ensure_non_empty(&self.withdrawal_id, "bridge safety sponsored withdrawal")?;
        ensure_non_empty(&self.asset_id, "bridge safety sponsorship asset")?;
        ensure_non_empty(&self.fee_asset_id, "bridge safety sponsorship fee asset")?;
        ensure_bps(self.rebate_bps, "bridge safety sponsorship rebate")?;
        if self.consumed_fee_units > self.max_sponsored_fee_units {
            return Err("bridge safety sponsorship consumed exceeds max".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("bridge safety sponsorship expiry must follow creation".to_string());
        }
        let expected = monero_bridge_safety_low_fee_sponsorship_id(&self.identity_record());
        if self.sponsorship_id != expected {
            return Err("bridge safety sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeReleaseReceipt {
    pub receipt_id: String,
    pub withdrawal_id: String,
    pub lane: WithdrawalLane,
    pub amount_units: u64,
    pub fee_units: u64,
    pub released_at_height: u64,
    pub monero_txid_hash: String,
    pub recipient_address_hash: String,
    pub privacy_receipt_root: String,
    pub sponsorship_id: Option<String>,
    pub throttle_id: String,
}

impl BridgeReleaseReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        lane: WithdrawalLane,
        amount_units: u64,
        fee_units: u64,
        released_at_height: u64,
        monero_txid_hash: impl Into<String>,
        recipient_address_hash: impl Into<String>,
        privacy_receipt_root: impl Into<String>,
        sponsorship_id: Option<String>,
        throttle_id: impl Into<String>,
    ) -> MoneroBridgeSafetyResult<Self> {
        let mut receipt = Self {
            receipt_id: String::new(),
            withdrawal_id: withdrawal_id.into(),
            lane,
            amount_units,
            fee_units,
            released_at_height,
            monero_txid_hash: monero_txid_hash.into(),
            recipient_address_hash: recipient_address_hash.into(),
            privacy_receipt_root: privacy_receipt_root.into(),
            sponsorship_id,
            throttle_id: throttle_id.into(),
        };
        receipt.receipt_id = monero_bridge_safety_release_receipt_id(&receipt.identity_record());
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_release_receipt_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "lane": self.lane.as_str(),
            "amount_units": self.amount_units,
            "released_at_height": self.released_at_height,
            "monero_txid_hash": self.monero_txid_hash,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_release_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "withdrawal_id": self.withdrawal_id,
            "lane": self.lane.as_str(),
            "amount_units": self.amount_units,
            "fee_units": self.fee_units,
            "released_at_height": self.released_at_height,
            "monero_txid_hash": self.monero_txid_hash,
            "recipient_address_hash": self.recipient_address_hash,
            "privacy_receipt_root": self.privacy_receipt_root,
            "sponsorship_id": self.sponsorship_id,
            "throttle_id": self.throttle_id,
        })
    }

    pub fn receipt_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-RELEASE-RECEIPT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "receipt_root",
            self.receipt_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.receipt_id, "bridge safety receipt id")?;
        ensure_non_empty(&self.withdrawal_id, "bridge safety receipt withdrawal")?;
        ensure_non_empty(&self.monero_txid_hash, "bridge safety monero txid")?;
        ensure_non_empty(
            &self.recipient_address_hash,
            "bridge safety recipient address",
        )?;
        ensure_non_empty(&self.privacy_receipt_root, "bridge safety privacy receipt")?;
        ensure_non_empty(&self.throttle_id, "bridge safety receipt throttle")?;
        if self.amount_units == 0 {
            return Err("bridge safety receipt amount must be positive".to_string());
        }
        let expected = monero_bridge_safety_release_receipt_id(&self.identity_record());
        if self.receipt_id != expected {
            return Err("bridge safety receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSafetyEvent {
    pub event_id: String,
    pub sequence: u64,
    pub height: u64,
    pub kind: SafetyEventKind,
    pub subject_id: String,
    pub event_root: String,
}

impl BridgeSafetyEvent {
    pub fn new(
        sequence: u64,
        height: u64,
        kind: SafetyEventKind,
        subject_id: impl Into<String>,
        event_root: impl Into<String>,
    ) -> MoneroBridgeSafetyResult<Self> {
        let mut event = Self {
            event_id: String::new(),
            sequence,
            height,
            kind,
            subject_id: subject_id.into(),
            event_root: event_root.into(),
        };
        event.event_id = monero_bridge_safety_event_id(&event.identity_record());
        event.validate()?;
        Ok(event)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_safety_event_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_safety_event",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "height": self.height,
            "event_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "event_root": self.event_root,
        })
    }

    pub fn record_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-EVENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        ensure_non_empty(&self.event_id, "bridge safety event id")?;
        ensure_non_empty(&self.subject_id, "bridge safety event subject")?;
        ensure_non_empty(&self.event_root, "bridge safety event root")?;
        let expected = monero_bridge_safety_event_id(&self.identity_record());
        if self.event_id != expected {
            return Err("bridge safety event id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeSafetyCounters {
    pub reserve_snapshot_count: u64,
    pub throttle_count: u64,
    pub active_throttle_count: u64,
    pub watchtower_evidence_count: u64,
    pub active_pause_count: u64,
    pub private_exit_guarantee_count: u64,
    pub active_private_exit_guarantee_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub available_low_fee_sponsorship_units: u64,
    pub release_receipt_count: u64,
    pub released_units: u64,
    pub event_count: u64,
}

impl MoneroBridgeSafetyCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_safety_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "reserve_snapshot_count": self.reserve_snapshot_count,
            "throttle_count": self.throttle_count,
            "active_throttle_count": self.active_throttle_count,
            "watchtower_evidence_count": self.watchtower_evidence_count,
            "active_pause_count": self.active_pause_count,
            "private_exit_guarantee_count": self.private_exit_guarantee_count,
            "active_private_exit_guarantee_count": self.active_private_exit_guarantee_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "available_low_fee_sponsorship_units": self.available_low_fee_sponsorship_units,
            "release_receipt_count": self.release_receipt_count,
            "released_units": self.released_units,
            "event_count": self.event_count,
            "counters_root": self.counters_root(),
        })
    }

    pub fn counters_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-COUNTERS",
            &json!({
                "reserve_snapshot_count": self.reserve_snapshot_count,
                "throttle_count": self.throttle_count,
                "active_throttle_count": self.active_throttle_count,
                "watchtower_evidence_count": self.watchtower_evidence_count,
                "active_pause_count": self.active_pause_count,
                "private_exit_guarantee_count": self.private_exit_guarantee_count,
                "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
                "release_receipt_count": self.release_receipt_count,
                "event_count": self.event_count,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeSafetyRoots {
    pub config_root: String,
    pub reserve_snapshot_root: String,
    pub throttle_root: String,
    pub watchtower_evidence_root: String,
    pub emergency_pause_root: String,
    pub private_exit_guarantee_root: String,
    pub low_fee_sponsorship_root: String,
    pub release_receipt_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub public_record_root: String,
}

impl MoneroBridgeSafetyRoots {
    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_bridge_safety_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "throttle_root": self.throttle_root,
            "watchtower_evidence_root": self.watchtower_evidence_root,
            "emergency_pause_root": self.emergency_pause_root,
            "private_exit_guarantee_root": self.private_exit_guarantee_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "release_receipt_root": self.release_receipt_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-ROOTS",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "roots_root",
            self.roots_root(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroBridgeSafetyState {
    pub config: MoneroBridgeSafetyConfig,
    pub height: u64,
    pub status: BridgeSafetyStatus,
    pub next_event_sequence: u64,
    pub reserve_snapshots: BTreeMap<String, ReserveSafetySnapshot>,
    pub throttles: BTreeMap<String, WithdrawalThrottleWindow>,
    pub watchtower_evidence: BTreeMap<String, WatchtowerSafetyEvidence>,
    pub emergency_pauses: BTreeMap<String, EmergencyBridgePause>,
    pub private_exit_guarantees: BTreeMap<String, PrivateExitGuarantee>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeExitSponsorship>,
    pub release_receipts: BTreeMap<String, BridgeReleaseReceipt>,
    pub events: BTreeMap<String, BridgeSafetyEvent>,
}

impl Default for MoneroBridgeSafetyState {
    fn default() -> Self {
        Self {
            config: MoneroBridgeSafetyConfig::default(),
            height: 0,
            status: BridgeSafetyStatus::Green,
            next_event_sequence: 0,
            reserve_snapshots: BTreeMap::new(),
            throttles: BTreeMap::new(),
            watchtower_evidence: BTreeMap::new(),
            emergency_pauses: BTreeMap::new(),
            private_exit_guarantees: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            release_receipts: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl MoneroBridgeSafetyState {
    pub fn new(config: MoneroBridgeSafetyConfig) -> MoneroBridgeSafetyResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> MoneroBridgeSafetyResult<Self> {
        let mut state = Self {
            height: 48,
            ..Self::default()
        };
        state.config.validate()?;

        let address_root = monero_bridge_safety_string_set_root(
            "MONERO-BRIDGE-SAFETY-DEVNET-RESERVE-ADDRESS",
            &[
                "xmr-reserve-devnet-a".to_string(),
                "xmr-reserve-devnet-b".to_string(),
                "xmr-reserve-devnet-c".to_string(),
            ],
        );
        let output_root = monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-DEVNET-RESERVE-OUTPUTS",
            &json!({
                "outputs": [
                    {"bucket": 256_000_u64, "commitment": "reserve-output-a"},
                    {"bucket": 192_000_u64, "commitment": "reserve-output-b"},
                    {"bucket": 96_000_u64, "commitment": "reserve-output-c"}
                ]
            }),
        );
        let attestation_root = monero_bridge_safety_string_set_root(
            "MONERO-BRIDGE-SAFETY-DEVNET-WATCHTOWER",
            &[
                "watchtower-alpha".to_string(),
                "watchtower-beta".to_string(),
            ],
        );
        let snapshot = ReserveSafetySnapshot::new(
            state.config.monero_network.clone(),
            state.config.asset_id.clone(),
            48,
            2_904_000,
            address_root,
            output_root,
            410_000,
            544_000,
            24_000,
            12_000,
            state.config.min_reserve_coverage_bps,
            state.config.target_reserve_coverage_bps,
            attestation_root,
        )?;
        let snapshot_id = snapshot.snapshot_id.clone();
        state.insert_reserve_snapshot(snapshot)?;

        let private_throttle = WithdrawalThrottleWindow::new(
            WithdrawalLane::Private,
            state.config.asset_id.clone(),
            48,
            48 + state.config.throttle_window_blocks,
            42_000,
            20_000,
            12_000,
            snapshot_id.clone(),
        )?;
        let private_throttle_id = private_throttle.throttle_id.clone();
        state.insert_throttle(private_throttle)?;

        let low_fee_throttle = WithdrawalThrottleWindow::new(
            WithdrawalLane::LowFee,
            state.config.asset_id.clone(),
            48,
            48 + state.config.throttle_window_blocks,
            36_000,
            8_000,
            20_000,
            snapshot_id,
        )?;
        let low_fee_throttle_id = low_fee_throttle.throttle_id.clone();
        state.insert_throttle(low_fee_throttle)?;

        let evidence = WatchtowerSafetyEvidence::new(
            WatchtowerEvidenceKind::DelayedBroadcast,
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-REPORTER", "watchtower-alpha"),
            monero_bridge_safety_string_root(
                "MONERO-BRIDGE-SAFETY-SUBJECT",
                "delayed-release-batch-0",
            ),
            49,
            49 + state.config.evidence_ttl_blocks,
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-SIGNATURE", "alpha-sig"),
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-ENCRYPTED", "details-0"),
            None,
        )?;
        state.insert_watchtower_evidence(evidence)?;

        let guarantee = PrivateExitGuarantee::new(
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-ACCOUNT", "alice"),
            "withdrawal-private-alice-0",
            WithdrawalLane::Private,
            8_192,
            240,
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-ANON-SET", "pool-a"),
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-NULLIFIER", "alice-nullifier"),
            private_throttle_id.clone(),
            50,
            50 + state.config.pause_ttl_blocks,
        )?;
        state.insert_private_exit_guarantee(guarantee)?;

        let mut sponsorship = LowFeeExitSponsorship::new(
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-SPONSOR", "fee-pool"),
            "withdrawal-low-fee-bob-0",
            state.config.asset_id.clone(),
            state.config.asset_id.clone(),
            1_600,
            state.config.low_fee_exit_rebate_bps,
            50,
            50 + state.config.pause_ttl_blocks,
        )?;
        sponsorship.consume_fee(180)?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_low_fee_sponsorship(sponsorship)?;

        state.insert_release_receipt(BridgeReleaseReceipt::new(
            "withdrawal-low-fee-bob-0",
            WithdrawalLane::LowFee,
            4_096,
            180,
            52,
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-TXID", "bob-release"),
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-RECIPIENT", "bob-address"),
            monero_bridge_safety_string_root("MONERO-BRIDGE-SAFETY-PRIVACY-RECEIPT", "bob"),
            Some(sponsorship_id),
            low_fee_throttle_id,
        )?)?;

        state.insert_emergency_pause(EmergencyBridgePause::new(
            PauseScope::SignerSet,
            BridgeSafetyStatus::Watch,
            53,
            53 + state.config.pause_ttl_blocks,
            monero_bridge_safety_string_root(
                "MONERO-BRIDGE-SAFETY-GUARDIAN-APPROVAL",
                "rotation-drill",
            ),
            Vec::new(),
        )?)?;

        state.recompute_status();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroBridgeSafetyResult<String> {
        self.height = height;
        for throttle in self.throttles.values_mut() {
            throttle.set_height(height);
        }
        for evidence in self.watchtower_evidence.values_mut() {
            evidence.set_height(height);
        }
        for pause in self.emergency_pauses.values_mut() {
            pause.set_height(height);
        }
        for guarantee in self.private_exit_guarantees.values_mut() {
            guarantee.set_height(height);
        }
        for sponsorship in self.low_fee_sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        self.recompute_status();
        self.validate()
    }

    pub fn insert_reserve_snapshot(
        &mut self,
        snapshot: ReserveSafetySnapshot,
    ) -> MoneroBridgeSafetyResult<String> {
        let root = snapshot.validate()?;
        let snapshot_id = snapshot.snapshot_id.clone();
        self.reserve_snapshots.insert(snapshot_id.clone(), snapshot);
        self.record_event(SafetyEventKind::ReserveSnapshot, snapshot_id, root.clone())?;
        self.recompute_status();
        Ok(root)
    }

    pub fn insert_throttle(
        &mut self,
        throttle: WithdrawalThrottleWindow,
    ) -> MoneroBridgeSafetyResult<String> {
        let root = throttle.validate()?;
        let throttle_id = throttle.throttle_id.clone();
        self.throttles.insert(throttle_id.clone(), throttle);
        self.record_event(SafetyEventKind::ThrottleUpdated, throttle_id, root.clone())?;
        Ok(root)
    }

    pub fn insert_watchtower_evidence(
        &mut self,
        evidence: WatchtowerSafetyEvidence,
    ) -> MoneroBridgeSafetyResult<String> {
        let root = evidence.validate()?;
        let evidence_id = evidence.evidence_id.clone();
        self.watchtower_evidence
            .insert(evidence_id.clone(), evidence);
        self.record_event(
            SafetyEventKind::WatchtowerEvidence,
            evidence_id,
            root.clone(),
        )?;
        self.recompute_status();
        Ok(root)
    }

    pub fn insert_emergency_pause(
        &mut self,
        pause: EmergencyBridgePause,
    ) -> MoneroBridgeSafetyResult<String> {
        let root = pause.validate()?;
        let pause_id = pause.pause_id.clone();
        self.emergency_pauses.insert(pause_id.clone(), pause);
        self.record_event(SafetyEventKind::EmergencyPause, pause_id, root.clone())?;
        self.recompute_status();
        Ok(root)
    }

    pub fn insert_private_exit_guarantee(
        &mut self,
        guarantee: PrivateExitGuarantee,
    ) -> MoneroBridgeSafetyResult<String> {
        let root = guarantee.validate()?;
        let guarantee_id = guarantee.guarantee_id.clone();
        self.private_exit_guarantees
            .insert(guarantee_id.clone(), guarantee);
        self.record_event(
            SafetyEventKind::PrivateExitGuarantee,
            guarantee_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeExitSponsorship,
    ) -> MoneroBridgeSafetyResult<String> {
        let root = sponsorship.validate()?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.low_fee_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.record_event(
            SafetyEventKind::LowFeeSponsorship,
            sponsorship_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_release_receipt(
        &mut self,
        receipt: BridgeReleaseReceipt,
    ) -> MoneroBridgeSafetyResult<String> {
        let root = receipt.validate()?;
        if let Some(throttle) = self.throttles.get_mut(&receipt.throttle_id) {
            throttle.consume_release(receipt.amount_units)?;
        } else {
            return Err("bridge safety receipt references missing throttle".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.release_receipts.insert(receipt_id.clone(), receipt);
        self.record_event(SafetyEventKind::ReleaseReceipt, receipt_id, root.clone())?;
        Ok(root)
    }

    pub fn counters(&self) -> MoneroBridgeSafetyCounters {
        MoneroBridgeSafetyCounters {
            reserve_snapshot_count: self.reserve_snapshots.len() as u64,
            throttle_count: self.throttles.len() as u64,
            active_throttle_count: self
                .throttles
                .values()
                .filter(|throttle| throttle.status.is_active())
                .count() as u64,
            watchtower_evidence_count: self.watchtower_evidence.len() as u64,
            active_pause_count: self
                .emergency_pauses
                .values()
                .filter(|pause| pause.status.is_active())
                .count() as u64,
            private_exit_guarantee_count: self.private_exit_guarantees.len() as u64,
            active_private_exit_guarantee_count: self
                .private_exit_guarantees
                .values()
                .filter(|guarantee| guarantee.status.is_active())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            available_low_fee_sponsorship_units: self
                .low_fee_sponsorships
                .values()
                .map(LowFeeExitSponsorship::remaining_fee_units)
                .sum(),
            release_receipt_count: self.release_receipts.len() as u64,
            released_units: self
                .release_receipts
                .values()
                .map(|receipt| receipt.amount_units)
                .sum(),
            event_count: self.events.len() as u64,
        }
    }

    pub fn roots(&self) -> MoneroBridgeSafetyRoots {
        let counters = self.counters();
        let public_record_root = monero_bridge_safety_payload_root(
            "MONERO-BRIDGE-SAFETY-PUBLIC-RECORD",
            &json!({
                "kind": "monero_bridge_safety_public_record_summary",
                "chain_id": CHAIN_ID,
                "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
                "height": self.height,
                "status": self.status.as_str(),
                "next_event_sequence": self.next_event_sequence,
                "counters_root": counters.counters_root(),
            }),
        );
        MoneroBridgeSafetyRoots {
            config_root: self.config.config_root(),
            reserve_snapshot_root: monero_bridge_safety_snapshot_collection_root(
                &self.reserve_snapshots.values().cloned().collect::<Vec<_>>(),
            ),
            throttle_root: monero_bridge_safety_throttle_collection_root(
                &self.throttles.values().cloned().collect::<Vec<_>>(),
            ),
            watchtower_evidence_root: monero_bridge_safety_evidence_collection_root(
                &self
                    .watchtower_evidence
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            emergency_pause_root: monero_bridge_safety_pause_collection_root(
                &self.emergency_pauses.values().cloned().collect::<Vec<_>>(),
            ),
            private_exit_guarantee_root:
                monero_bridge_safety_private_exit_guarantee_collection_root(
                    &self
                        .private_exit_guarantees
                        .values()
                        .cloned()
                        .collect::<Vec<_>>(),
                ),
            low_fee_sponsorship_root: monero_bridge_safety_low_fee_sponsorship_collection_root(
                &self
                    .low_fee_sponsorships
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            release_receipt_root: monero_bridge_safety_release_receipt_collection_root(
                &self.release_receipts.values().cloned().collect::<Vec<_>>(),
            ),
            event_root: monero_bridge_safety_event_collection_root(
                &self.events.values().cloned().collect::<Vec<_>>(),
            ),
            counters_root: counters.counters_root(),
            public_record_root,
        }
    }

    pub fn state_root(&self) -> String {
        monero_bridge_safety_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "state_root",
            self.state_root(),
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_bridge_safety_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION,
            "height": self.height,
            "status": self.status.as_str(),
            "status_score_bps": self.status.score_bps(),
            "next_event_sequence": self.next_event_sequence,
            "config": self.config.public_record(),
            "roots": roots.public_record_without_root(),
            "counters": counters.public_record(),
        })
    }

    pub fn validate(&self) -> MoneroBridgeSafetyResult<String> {
        self.config.validate()?;
        for snapshot in self.reserve_snapshots.values() {
            snapshot.validate()?;
        }
        for throttle in self.throttles.values() {
            throttle.validate()?;
            if !self
                .reserve_snapshots
                .contains_key(&throttle.reserve_snapshot_id)
            {
                return Err("bridge safety throttle references missing snapshot".to_string());
            }
        }
        for evidence in self.watchtower_evidence.values() {
            evidence.validate()?;
        }
        for pause in self.emergency_pauses.values() {
            pause.validate()?;
            for evidence_id in &pause.evidence_ids {
                if !self.watchtower_evidence.contains_key(evidence_id) {
                    return Err("bridge safety pause references missing evidence".to_string());
                }
            }
        }
        for guarantee in self.private_exit_guarantees.values() {
            guarantee.validate()?;
            if !self.throttles.contains_key(&guarantee.throttle_id) {
                return Err("bridge safety guarantee references missing throttle".to_string());
            }
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
        }
        for receipt in self.release_receipts.values() {
            receipt.validate()?;
            if !self.throttles.contains_key(&receipt.throttle_id) {
                return Err("bridge safety receipt references missing throttle".to_string());
            }
            if let Some(sponsorship_id) = &receipt.sponsorship_id {
                if !self.low_fee_sponsorships.contains_key(sponsorship_id) {
                    return Err("bridge safety receipt references missing sponsorship".to_string());
                }
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(self.state_root())
    }

    fn record_event(
        &mut self,
        kind: SafetyEventKind,
        subject_id: String,
        event_root: String,
    ) -> MoneroBridgeSafetyResult<String> {
        let sequence = self.next_event_sequence;
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        let event = BridgeSafetyEvent::new(sequence, self.height, kind, subject_id, event_root)?;
        let root = event.record_root();
        self.events.insert(event.event_id.clone(), event);
        Ok(root)
    }

    fn recompute_status(&mut self) {
        let latest_risk = self
            .reserve_snapshots
            .values()
            .max_by_key(|snapshot| snapshot.height)
            .map(|snapshot| snapshot.risk_level)
            .unwrap_or(ReserveRiskLevel::Unknown);
        let has_active_pause = self
            .emergency_pauses
            .values()
            .any(|pause| pause.status.is_active());
        let has_pause_evidence = self
            .watchtower_evidence
            .values()
            .filter(|evidence| evidence.status.is_active())
            .any(|evidence| evidence.kind.triggers_pause());
        self.status = if matches!(latest_risk, ReserveRiskLevel::Insolvent) || has_pause_evidence {
            BridgeSafetyStatus::Emergency
        } else if has_active_pause {
            BridgeSafetyStatus::Paused
        } else if matches!(latest_risk, ReserveRiskLevel::UnderCovered) {
            BridgeSafetyStatus::Throttled
        } else if matches!(
            latest_risk,
            ReserveRiskLevel::BufferLow | ReserveRiskLevel::Unknown
        ) {
            BridgeSafetyStatus::Watch
        } else {
            BridgeSafetyStatus::Green
        };
    }
}

pub fn monero_bridge_safety_state_root_from_record(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-STATE", record)
}

pub fn monero_bridge_safety_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_bridge_safety_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_BRIDGE_SAFETY_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_bridge_safety_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    let leaves = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn monero_bridge_safety_snapshot_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-SNAPSHOT-ID", record)
}

pub fn monero_bridge_safety_throttle_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-THROTTLE-ID", record)
}

pub fn monero_bridge_safety_evidence_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-EVIDENCE-ID", record)
}

pub fn monero_bridge_safety_pause_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-PAUSE-ID", record)
}

pub fn monero_bridge_safety_private_exit_guarantee_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-PRIVATE-EXIT-GUARANTEE-ID", record)
}

pub fn monero_bridge_safety_low_fee_sponsorship_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-LOW-FEE-SPONSORSHIP-ID", record)
}

pub fn monero_bridge_safety_release_receipt_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-RELEASE-RECEIPT-ID", record)
}

pub fn monero_bridge_safety_event_id(record: &Value) -> String {
    monero_bridge_safety_payload_root("MONERO-BRIDGE-SAFETY-EVENT-ID", record)
}

pub fn monero_bridge_safety_snapshot_collection_root(records: &[ReserveSafetySnapshot]) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-SNAPSHOT-COLLECTION",
        records
            .iter()
            .map(|record| (record.snapshot_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_safety_throttle_collection_root(
    records: &[WithdrawalThrottleWindow],
) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-THROTTLE-COLLECTION",
        records
            .iter()
            .map(|record| (record.throttle_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_safety_evidence_collection_root(
    records: &[WatchtowerSafetyEvidence],
) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-EVIDENCE-COLLECTION",
        records
            .iter()
            .map(|record| (record.evidence_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_safety_pause_collection_root(records: &[EmergencyBridgePause]) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-PAUSE-COLLECTION",
        records
            .iter()
            .map(|record| (record.pause_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_safety_private_exit_guarantee_collection_root(
    records: &[PrivateExitGuarantee],
) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-PRIVATE-EXIT-GUARANTEE-COLLECTION",
        records
            .iter()
            .map(|record| (record.guarantee_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_safety_low_fee_sponsorship_collection_root(
    records: &[LowFeeExitSponsorship],
) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-LOW-FEE-SPONSORSHIP-COLLECTION",
        records
            .iter()
            .map(|record| (record.sponsorship_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_safety_release_receipt_collection_root(
    records: &[BridgeReleaseReceipt],
) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-RELEASE-RECEIPT-COLLECTION",
        records
            .iter()
            .map(|record| (record.receipt_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_safety_event_collection_root(records: &[BridgeSafetyEvent]) -> String {
    keyed_value_root(
        "MONERO-BRIDGE-SAFETY-EVENT-COLLECTION",
        records
            .iter()
            .map(|record| (record.event_id.clone(), record.public_record()))
            .collect(),
    )
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field_name: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field_name.to_string(), Value::String(root));
    }
    record
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroBridgeSafetyResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroBridgeSafetyResult<()> {
    if value > MONERO_BRIDGE_SAFETY_MAX_BPS.saturating_mul(2) {
        Err(format!("{label} is outside supported bridge safety range"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> MoneroBridgeSafetyResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}
