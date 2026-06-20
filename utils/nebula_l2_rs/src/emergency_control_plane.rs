use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type EmergencyControlResult<T> = Result<T, String>;

pub const EMERGENCY_CONTROL_PROTOCOL_VERSION: &str = "nebula-emergency-control-v1";
pub const EMERGENCY_CONTROL_DEFAULT_TTL_BLOCKS: u64 = 144;
pub const EMERGENCY_CONTROL_DEFAULT_RECOVERY_WINDOW_BLOCKS: u64 = 288;
pub const EMERGENCY_CONTROL_DEFAULT_MIN_GUARDIAN_SIGNATURES: u64 = 3;
pub const EMERGENCY_CONTROL_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 9_000;
pub const EMERGENCY_CONTROL_DEFAULT_RECOVERY_BUDGET_UNITS: u64 = 2_500_000;
pub const EMERGENCY_CONTROL_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyScope {
    Bridge,
    Sequencer,
    DataAvailability,
    Proofs,
    Privacy,
    Defi,
    Contracts,
    Wallets,
    Governance,
    LowFeeLane,
    Global,
}

impl EmergencyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Sequencer => "sequencer",
            Self::DataAvailability => "data_availability",
            Self::Proofs => "proofs",
            Self::Privacy => "privacy",
            Self::Defi => "defi",
            Self::Contracts => "contracts",
            Self::Wallets => "wallets",
            Self::Governance => "governance",
            Self::LowFeeLane => "low_fee_lane",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyTriggerKind {
    MoneroReorg,
    BridgeReserveShortfall,
    SequencerEquivocation,
    DataAvailabilityLoss,
    InvalidProofAccepted,
    PrivacyLeak,
    OracleFault,
    LiquidityRun,
    FeeSpike,
    PqKeyCompromise,
    GovernanceEmergency,
}

impl EmergencyTriggerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroReorg => "monero_reorg",
            Self::BridgeReserveShortfall => "bridge_reserve_shortfall",
            Self::SequencerEquivocation => "sequencer_equivocation",
            Self::DataAvailabilityLoss => "data_availability_loss",
            Self::InvalidProofAccepted => "invalid_proof_accepted",
            Self::PrivacyLeak => "privacy_leak",
            Self::OracleFault => "oracle_fault",
            Self::LiquidityRun => "liquidity_run",
            Self::FeeSpike => "fee_spike",
            Self::PqKeyCompromise => "pq_key_compromise",
            Self::GovernanceEmergency => "governance_emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencySeverity {
    Watch,
    Elevated,
    Severe,
    Critical,
}

impl EmergencySeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Severe => "severe",
            Self::Critical => "critical",
        }
    }

    pub fn floor_bps(self) -> u64 {
        match self {
            Self::Watch => 1_000,
            Self::Elevated => 3_500,
            Self::Severe => 6_500,
            Self::Critical => 9_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyMode {
    Normal,
    Throttled,
    RecoveryOnly,
    Paused,
    LockedDown,
}

impl SafetyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Throttled => "throttled",
            Self::RecoveryOnly => "recovery_only",
            Self::Paused => "paused",
            Self::LockedDown => "locked_down",
        }
    }

    pub fn blocks_user_flow(self) -> bool {
        matches!(self, Self::Paused | Self::LockedDown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlActionKind {
    ThrottleSequencer,
    PauseBridgeRelease,
    FreezeContractUpgrade,
    RequirePqReauth,
    OpenEmergencyExit,
    QuarantineDaBatch,
    ForceLowFeeLane,
    EscalateWatchtower,
    LockGovernanceQueue,
}

impl ControlActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThrottleSequencer => "throttle_sequencer",
            Self::PauseBridgeRelease => "pause_bridge_release",
            Self::FreezeContractUpgrade => "freeze_contract_upgrade",
            Self::RequirePqReauth => "require_pq_reauth",
            Self::OpenEmergencyExit => "open_emergency_exit",
            Self::QuarantineDaBatch => "quarantine_da_batch",
            Self::ForceLowFeeLane => "force_low_fee_lane",
            Self::EscalateWatchtower => "escalate_watchtower",
            Self::LockGovernanceQueue => "lock_governance_queue",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Draft,
    Active,
    Superseded,
    Expired,
    Resolved,
}

impl ControlStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Resolved => "resolved",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyEventKind {
    TriggerOpened,
    GuardianAttested,
    ActionActivated,
    RecoveryWindowOpened,
    ScopeResolved,
    TriggerExpired,
}

impl EmergencyEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TriggerOpened => "trigger_opened",
            Self::GuardianAttested => "guardian_attested",
            Self::ActionActivated => "action_activated",
            Self::RecoveryWindowOpened => "recovery_window_opened",
            Self::ScopeResolved => "scope_resolved",
            Self::TriggerExpired => "trigger_expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyControlConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub operator_label: String,
    pub min_guardian_signatures: u64,
    pub default_ttl_blocks: u64,
    pub recovery_window_blocks: u64,
    pub low_fee_rebate_bps: u64,
    pub recovery_budget_units: u64,
}

impl EmergencyControlConfig {
    pub fn devnet(operator_label: impl Into<String>) -> Self {
        Self {
            protocol_version: EMERGENCY_CONTROL_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_label: operator_label.into(),
            min_guardian_signatures: EMERGENCY_CONTROL_DEFAULT_MIN_GUARDIAN_SIGNATURES,
            default_ttl_blocks: EMERGENCY_CONTROL_DEFAULT_TTL_BLOCKS,
            recovery_window_blocks: EMERGENCY_CONTROL_DEFAULT_RECOVERY_WINDOW_BLOCKS,
            low_fee_rebate_bps: EMERGENCY_CONTROL_DEFAULT_LOW_FEE_REBATE_BPS,
            recovery_budget_units: EMERGENCY_CONTROL_DEFAULT_RECOVERY_BUDGET_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_control_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "min_guardian_signatures": self.min_guardian_signatures,
            "default_ttl_blocks": self.default_ttl_blocks,
            "recovery_window_blocks": self.recovery_window_blocks,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "recovery_budget_units": self.recovery_budget_units,
        })
    }

    pub fn config_root(&self) -> String {
        emergency_control_payload_root("EMERGENCY-CONTROL-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> EmergencyControlResult<String> {
        if self.protocol_version != EMERGENCY_CONTROL_PROTOCOL_VERSION {
            return Err("emergency control protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("emergency control chain id mismatch".to_string());
        }
        require_non_empty("operator label", &self.operator_label)?;
        require_positive("min guardian signatures", self.min_guardian_signatures)?;
        require_positive("default ttl blocks", self.default_ttl_blocks)?;
        require_positive("recovery window blocks", self.recovery_window_blocks)?;
        require_bps("low fee rebate bps", self.low_fee_rebate_bps)?;
        require_positive("recovery budget units", self.recovery_budget_units)?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyTrigger {
    pub trigger_id: String,
    pub trigger_kind: EmergencyTriggerKind,
    pub scope: EmergencyScope,
    pub severity: EmergencySeverity,
    pub severity_bps: u64,
    pub evidence_root: String,
    pub reporter_label: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: ControlStatus,
}

impl SafetyTrigger {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_kind: EmergencyTriggerKind,
        scope: EmergencyScope,
        severity: EmergencySeverity,
        severity_bps: u64,
        evidence: &Value,
        reporter_label: &str,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> EmergencyControlResult<Self> {
        require_non_empty("reporter label", reporter_label)?;
        if expires_at_height <= opened_at_height {
            return Err("trigger expiry must be after open height".to_string());
        }
        require_bps("trigger severity bps", severity_bps)?;
        if severity_bps < severity.floor_bps() {
            return Err("trigger severity bps below severity floor".to_string());
        }
        let evidence_root = emergency_control_payload_root("EMERGENCY-CONTROL-EVIDENCE", evidence);
        let trigger_id = emergency_control_trigger_id(
            trigger_kind,
            scope,
            &evidence_root,
            reporter_label,
            opened_at_height,
        );
        Ok(Self {
            trigger_id,
            trigger_kind,
            scope,
            severity,
            severity_bps,
            evidence_root,
            reporter_label: reporter_label.to_string(),
            opened_at_height,
            expires_at_height,
            status: ControlStatus::Active,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height >= self.expires_at_height {
            self.status = ControlStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "safety_trigger",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "trigger_id": self.trigger_id,
            "trigger_kind": self.trigger_kind.as_str(),
            "scope": self.scope.as_str(),
            "severity": self.severity.as_str(),
            "severity_bps": self.severity_bps,
            "evidence_root": self.evidence_root,
            "reporter_label": self.reporter_label,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> EmergencyControlResult<String> {
        require_non_empty("trigger id", &self.trigger_id)?;
        require_non_empty("trigger evidence root", &self.evidence_root)?;
        require_non_empty("trigger reporter", &self.reporter_label)?;
        require_bps("trigger severity bps", self.severity_bps)?;
        if self.severity_bps < self.severity.floor_bps() {
            return Err("trigger severity bps below severity floor".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("trigger expiry must be after open height".to_string());
        }
        let expected = emergency_control_trigger_id(
            self.trigger_kind,
            self.scope,
            &self.evidence_root,
            &self.reporter_label,
            self.opened_at_height,
        );
        if self.trigger_id != expected {
            return Err("trigger id mismatch".to_string());
        }
        Ok(self.trigger_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianAttestation {
    pub attestation_id: String,
    pub trigger_id: String,
    pub guardian_id: String,
    pub weight_bps: u64,
    pub observed_root: String,
    pub signature_root: String,
    pub attested_at_height: u64,
    pub valid: bool,
}

impl GuardianAttestation {
    pub fn new(
        trigger_id: &str,
        guardian_id: &str,
        weight_bps: u64,
        observed: &Value,
        signature: &Value,
        attested_at_height: u64,
    ) -> EmergencyControlResult<Self> {
        require_non_empty("attestation trigger id", trigger_id)?;
        require_non_empty("guardian id", guardian_id)?;
        require_bps("guardian weight bps", weight_bps)?;
        let observed_root = emergency_control_payload_root("EMERGENCY-CONTROL-OBSERVED", observed);
        let signature_root =
            emergency_control_payload_root("EMERGENCY-CONTROL-GUARDIAN-SIGNATURE", signature);
        let attestation_id = emergency_control_attestation_id(
            trigger_id,
            guardian_id,
            &observed_root,
            &signature_root,
            attested_at_height,
        );
        Ok(Self {
            attestation_id,
            trigger_id: trigger_id.to_string(),
            guardian_id: guardian_id.to_string(),
            weight_bps,
            observed_root,
            signature_root,
            attested_at_height,
            valid: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "guardian_attestation",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "trigger_id": self.trigger_id,
            "guardian_id": self.guardian_id,
            "weight_bps": self.weight_bps,
            "observed_root": self.observed_root,
            "signature_root": self.signature_root,
            "attested_at_height": self.attested_at_height,
            "valid": self.valid,
        })
    }

    pub fn validate(&self) -> EmergencyControlResult<String> {
        require_non_empty("attestation id", &self.attestation_id)?;
        require_non_empty("attestation trigger id", &self.trigger_id)?;
        require_non_empty("guardian id", &self.guardian_id)?;
        require_bps("guardian weight bps", self.weight_bps)?;
        require_non_empty("observed root", &self.observed_root)?;
        require_non_empty("signature root", &self.signature_root)?;
        let expected = emergency_control_attestation_id(
            &self.trigger_id,
            &self.guardian_id,
            &self.observed_root,
            &self.signature_root,
            self.attested_at_height,
        );
        if self.attestation_id != expected {
            return Err("guardian attestation id mismatch".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlAction {
    pub action_id: String,
    pub trigger_id: String,
    pub action_kind: ControlActionKind,
    pub scope: EmergencyScope,
    pub safety_mode: SafetyMode,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub low_fee_rebate_bps: u64,
    pub requires_governance_resume: bool,
    pub status: ControlStatus,
}

impl ControlAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        action_kind: ControlActionKind,
        scope: EmergencyScope,
        safety_mode: SafetyMode,
        starts_at_height: u64,
        expires_at_height: u64,
        low_fee_rebate_bps: u64,
        requires_governance_resume: bool,
    ) -> EmergencyControlResult<Self> {
        require_non_empty("action trigger id", trigger_id)?;
        if expires_at_height <= starts_at_height {
            return Err("action expiry must be after start height".to_string());
        }
        require_bps("action low fee rebate bps", low_fee_rebate_bps)?;
        let action_id = emergency_control_action_id(
            trigger_id,
            action_kind,
            scope,
            safety_mode,
            starts_at_height,
        );
        Ok(Self {
            action_id,
            trigger_id: trigger_id.to_string(),
            action_kind,
            scope,
            safety_mode,
            starts_at_height,
            expires_at_height,
            low_fee_rebate_bps,
            requires_governance_resume,
            status: ControlStatus::Active,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height >= self.expires_at_height {
            self.status = ControlStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "control_action",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "action_id": self.action_id,
            "trigger_id": self.trigger_id,
            "action_kind": self.action_kind.as_str(),
            "scope": self.scope.as_str(),
            "safety_mode": self.safety_mode.as_str(),
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "requires_governance_resume": self.requires_governance_resume,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> EmergencyControlResult<String> {
        require_non_empty("action id", &self.action_id)?;
        require_non_empty("action trigger id", &self.trigger_id)?;
        require_bps("action low fee rebate bps", self.low_fee_rebate_bps)?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("action expiry must be after start height".to_string());
        }
        let expected = emergency_control_action_id(
            &self.trigger_id,
            self.action_kind,
            self.scope,
            self.safety_mode,
            self.starts_at_height,
        );
        if self.action_id != expected {
            return Err("control action id mismatch".to_string());
        }
        Ok(self.action_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWindow {
    pub window_id: String,
    pub scope: EmergencyScope,
    pub opened_by_action_id: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub low_fee_budget_units: u64,
    pub exit_lane_root: String,
    pub status: ControlStatus,
}

impl RecoveryWindow {
    pub fn new(
        scope: EmergencyScope,
        opened_by_action_id: &str,
        opened_at_height: u64,
        closes_at_height: u64,
        low_fee_budget_units: u64,
        exit_lane: &Value,
    ) -> EmergencyControlResult<Self> {
        require_non_empty("opened by action id", opened_by_action_id)?;
        if closes_at_height <= opened_at_height {
            return Err("recovery window close height must be after open height".to_string());
        }
        let exit_lane_root =
            emergency_control_payload_root("EMERGENCY-CONTROL-EXIT-LANE", exit_lane);
        let window_id = emergency_control_window_id(
            scope,
            opened_by_action_id,
            &exit_lane_root,
            opened_at_height,
        );
        Ok(Self {
            window_id,
            scope,
            opened_by_action_id: opened_by_action_id.to_string(),
            opened_at_height,
            closes_at_height,
            low_fee_budget_units,
            exit_lane_root,
            status: ControlStatus::Active,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height >= self.closes_at_height {
            self.status = ControlStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recovery_window",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "scope": self.scope.as_str(),
            "opened_by_action_id": self.opened_by_action_id,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "low_fee_budget_units": self.low_fee_budget_units,
            "exit_lane_root": self.exit_lane_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> EmergencyControlResult<String> {
        require_non_empty("window id", &self.window_id)?;
        require_non_empty("window action id", &self.opened_by_action_id)?;
        require_non_empty("exit lane root", &self.exit_lane_root)?;
        if self.closes_at_height <= self.opened_at_height {
            return Err("recovery window close height must be after open height".to_string());
        }
        let expected = emergency_control_window_id(
            self.scope,
            &self.opened_by_action_id,
            &self.exit_lane_root,
            self.opened_at_height,
        );
        if self.window_id != expected {
            return Err("recovery window id mismatch".to_string());
        }
        Ok(self.window_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyControlEvent {
    pub event_id: String,
    pub event_kind: EmergencyEventKind,
    pub scope: EmergencyScope,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl EmergencyControlEvent {
    pub fn new(
        event_kind: EmergencyEventKind,
        scope: EmergencyScope,
        subject_id: &str,
        height: u64,
        payload: &Value,
    ) -> EmergencyControlResult<Self> {
        require_non_empty("event subject id", subject_id)?;
        let payload_root =
            emergency_control_payload_root("EMERGENCY-CONTROL-EVENT-PAYLOAD", payload);
        let event_id =
            emergency_control_event_id(event_kind, scope, subject_id, &payload_root, height);
        Ok(Self {
            event_id,
            event_kind,
            scope,
            subject_id: subject_id.to_string(),
            height,
            payload_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_control_event",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }

    pub fn validate(&self) -> EmergencyControlResult<String> {
        require_non_empty("event id", &self.event_id)?;
        require_non_empty("event subject id", &self.subject_id)?;
        require_non_empty("event payload root", &self.payload_root)?;
        let expected = emergency_control_event_id(
            self.event_kind,
            self.scope,
            &self.subject_id,
            &self.payload_root,
            self.height,
        );
        if self.event_id != expected {
            return Err("emergency control event id mismatch".to_string());
        }
        Ok(self.event_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyControlRoots {
    pub config_root: String,
    pub trigger_root: String,
    pub guardian_attestation_root: String,
    pub control_action_root: String,
    pub recovery_window_root: String,
    pub event_root: String,
    pub scope_mode_root: String,
}

impl EmergencyControlRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_control_roots",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "trigger_root": self.trigger_root,
            "guardian_attestation_root": self.guardian_attestation_root,
            "control_action_root": self.control_action_root,
            "recovery_window_root": self.recovery_window_root,
            "event_root": self.event_root,
            "scope_mode_root": self.scope_mode_root,
        })
    }

    pub fn roots_root(&self) -> String {
        emergency_control_payload_root("EMERGENCY-CONTROL-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyControlCounters {
    pub trigger_count: u64,
    pub active_trigger_count: u64,
    pub guardian_attestation_count: u64,
    pub valid_guardian_attestation_count: u64,
    pub active_action_count: u64,
    pub active_recovery_window_count: u64,
    pub blocked_scope_count: u64,
    pub recovery_budget_available_units: u64,
}

impl EmergencyControlCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_control_counters",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "trigger_count": self.trigger_count,
            "active_trigger_count": self.active_trigger_count,
            "guardian_attestation_count": self.guardian_attestation_count,
            "valid_guardian_attestation_count": self.valid_guardian_attestation_count,
            "active_action_count": self.active_action_count,
            "active_recovery_window_count": self.active_recovery_window_count,
            "blocked_scope_count": self.blocked_scope_count,
            "recovery_budget_available_units": self.recovery_budget_available_units,
        })
    }

    pub fn counters_root(&self) -> String {
        emergency_control_payload_root("EMERGENCY-CONTROL-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyControlState {
    pub config: EmergencyControlConfig,
    pub height: u64,
    pub triggers: Vec<SafetyTrigger>,
    pub guardian_attestations: Vec<GuardianAttestation>,
    pub control_actions: Vec<ControlAction>,
    pub recovery_windows: Vec<RecoveryWindow>,
    pub events: Vec<EmergencyControlEvent>,
}

impl EmergencyControlState {
    pub fn devnet(operator_label: &str) -> EmergencyControlResult<Self> {
        let config = EmergencyControlConfig::devnet(operator_label);
        let height = 1;
        let trigger = SafetyTrigger::new(
            EmergencyTriggerKind::BridgeReserveShortfall,
            EmergencyScope::Bridge,
            EmergencySeverity::Severe,
            7_200,
            &json!({
                "reserve_root": emergency_control_string_root("DEVNET-RESERVE-WARN"),
                "bridge_epoch": "devnet-bridge-epoch-1",
                "monero_network": "monero-devnet",
            }),
            operator_label,
            height,
            height.saturating_add(config.default_ttl_blocks),
        )?;
        let guardian_attestations = ["guardian-alpha", "guardian-beta", "guardian-gamma"]
            .into_iter()
            .enumerate()
            .map(|(index, guardian)| {
                GuardianAttestation::new(
                    &trigger.trigger_id,
                    guardian,
                    2_500,
                    &json!({
                        "scope": trigger.scope.as_str(),
                        "trigger_id": trigger.trigger_id,
                        "sample": index as u64,
                    }),
                    &json!({
                        "scheme": "ML-DSA-65",
                        "signature_commitment": emergency_control_string_root(guardian),
                    }),
                    height,
                )
            })
            .collect::<EmergencyControlResult<Vec<_>>>()?;
        let action = ControlAction::new(
            &trigger.trigger_id,
            ControlActionKind::OpenEmergencyExit,
            EmergencyScope::Bridge,
            SafetyMode::RecoveryOnly,
            height,
            height.saturating_add(config.default_ttl_blocks),
            config.low_fee_rebate_bps,
            true,
        )?;
        let recovery_window = RecoveryWindow::new(
            EmergencyScope::Bridge,
            &action.action_id,
            height,
            height.saturating_add(config.recovery_window_blocks),
            config.recovery_budget_units,
            &json!({
                "lane": "bridge_emergency_exit",
                "fee_mode": "sponsored_low_fee",
                "privacy": "commitment_only_receipts",
            }),
        )?;
        let events = vec![
            EmergencyControlEvent::new(
                EmergencyEventKind::TriggerOpened,
                trigger.scope,
                &trigger.trigger_id,
                height,
                &trigger.public_record(),
            )?,
            EmergencyControlEvent::new(
                EmergencyEventKind::ActionActivated,
                action.scope,
                &action.action_id,
                height,
                &action.public_record(),
            )?,
            EmergencyControlEvent::new(
                EmergencyEventKind::RecoveryWindowOpened,
                recovery_window.scope,
                &recovery_window.window_id,
                height,
                &recovery_window.public_record(),
            )?,
        ];
        let state = Self {
            config,
            height,
            triggers: vec![trigger],
            guardian_attestations,
            control_actions: vec![action],
            recovery_windows: vec![recovery_window],
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> EmergencyControlResult<String> {
        self.height = height;
        for trigger in &mut self.triggers {
            trigger.set_height(height);
        }
        for action in &mut self.control_actions {
            action.set_height(height);
        }
        for window in &mut self.recovery_windows {
            window.set_height(height);
        }
        self.validate()?;
        Ok(self.state_root())
    }

    pub fn active_triggers(&self) -> Vec<&SafetyTrigger> {
        self.triggers
            .iter()
            .filter(|trigger| trigger.status.active())
            .collect()
    }

    pub fn active_actions(&self) -> Vec<&ControlAction> {
        self.control_actions
            .iter()
            .filter(|action| action.status.active())
            .collect()
    }

    pub fn active_recovery_windows(&self) -> Vec<&RecoveryWindow> {
        self.recovery_windows
            .iter()
            .filter(|window| window.status.active())
            .collect()
    }

    pub fn mode_for_scope(&self, scope: EmergencyScope) -> SafetyMode {
        self.active_actions()
            .into_iter()
            .filter(|action| action.scope == scope || action.scope == EmergencyScope::Global)
            .map(|action| action.safety_mode)
            .max()
            .unwrap_or(SafetyMode::Normal)
    }

    pub fn scope_mode_map(&self) -> BTreeMap<String, String> {
        [
            EmergencyScope::Bridge,
            EmergencyScope::Sequencer,
            EmergencyScope::DataAvailability,
            EmergencyScope::Proofs,
            EmergencyScope::Privacy,
            EmergencyScope::Defi,
            EmergencyScope::Contracts,
            EmergencyScope::Wallets,
            EmergencyScope::Governance,
            EmergencyScope::LowFeeLane,
            EmergencyScope::Global,
        ]
        .into_iter()
        .map(|scope| {
            (
                scope.as_str().to_string(),
                self.mode_for_scope(scope).as_str().to_string(),
            )
        })
        .collect()
    }

    pub fn recovery_budget_available_units(&self) -> u64 {
        self.active_recovery_windows()
            .into_iter()
            .map(|window| window.low_fee_budget_units)
            .sum()
    }

    pub fn guardian_signature_count_for_trigger(&self, trigger_id: &str) -> u64 {
        self.guardian_attestations
            .iter()
            .filter(|attestation| attestation.trigger_id == trigger_id && attestation.valid)
            .map(|attestation| attestation.guardian_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64
    }

    pub fn roots(&self) -> EmergencyControlRoots {
        EmergencyControlRoots {
            config_root: self.config.config_root(),
            trigger_root: emergency_control_trigger_collection_root(&self.triggers),
            guardian_attestation_root: emergency_control_attestation_collection_root(
                &self.guardian_attestations,
            ),
            control_action_root: emergency_control_action_collection_root(&self.control_actions),
            recovery_window_root: emergency_control_window_collection_root(&self.recovery_windows),
            event_root: emergency_control_event_collection_root(&self.events),
            scope_mode_root: emergency_control_payload_root(
                "EMERGENCY-CONTROL-SCOPE-MODES",
                &json!(self.scope_mode_map()),
            ),
        }
    }

    pub fn counters(&self) -> EmergencyControlCounters {
        let blocked_scope_count = self
            .scope_mode_map()
            .values()
            .filter(|mode| {
                matches!(
                    mode.as_str(),
                    "paused" | "locked_down" | "recovery_only" | "throttled"
                )
            })
            .count() as u64;
        EmergencyControlCounters {
            trigger_count: self.triggers.len() as u64,
            active_trigger_count: self.active_triggers().len() as u64,
            guardian_attestation_count: self.guardian_attestations.len() as u64,
            valid_guardian_attestation_count: self
                .guardian_attestations
                .iter()
                .filter(|attestation| attestation.valid)
                .count() as u64,
            active_action_count: self.active_actions().len() as u64,
            active_recovery_window_count: self.active_recovery_windows().len() as u64,
            blocked_scope_count,
            recovery_budget_available_units: self.recovery_budget_available_units(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "emergency_control_state",
            "protocol_version": EMERGENCY_CONTROL_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "scope_modes": self.scope_mode_map(),
        })
    }

    pub fn state_root(&self) -> String {
        emergency_control_plane_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_root();
        with_root_field(record, "emergency_control_state_root", self.state_root())
    }

    pub fn validate(&self) -> EmergencyControlResult<String> {
        self.config.validate()?;
        let trigger_ids = self
            .triggers
            .iter()
            .map(SafetyTrigger::validate)
            .collect::<EmergencyControlResult<Vec<_>>>()?;
        ensure_unique_strings(&trigger_ids, "trigger id")?;
        let trigger_set = trigger_ids.iter().cloned().collect::<BTreeSet<_>>();
        let action_ids = self
            .control_actions
            .iter()
            .map(ControlAction::validate)
            .collect::<EmergencyControlResult<Vec<_>>>()?;
        ensure_unique_strings(&action_ids, "action id")?;
        let action_set = action_ids.iter().cloned().collect::<BTreeSet<_>>();
        let attestation_ids = self
            .guardian_attestations
            .iter()
            .map(GuardianAttestation::validate)
            .collect::<EmergencyControlResult<Vec<_>>>()?;
        ensure_unique_strings(&attestation_ids, "guardian attestation id")?;
        let window_ids = self
            .recovery_windows
            .iter()
            .map(RecoveryWindow::validate)
            .collect::<EmergencyControlResult<Vec<_>>>()?;
        ensure_unique_strings(&window_ids, "recovery window id")?;
        let event_ids = self
            .events
            .iter()
            .map(EmergencyControlEvent::validate)
            .collect::<EmergencyControlResult<Vec<_>>>()?;
        ensure_unique_strings(&event_ids, "event id")?;
        for action in &self.control_actions {
            if !trigger_set.contains(&action.trigger_id) {
                return Err(format!(
                    "control action references unknown trigger {}",
                    action.trigger_id
                ));
            }
        }
        for attestation in &self.guardian_attestations {
            if !trigger_set.contains(&attestation.trigger_id) {
                return Err(format!(
                    "guardian attestation references unknown trigger {}",
                    attestation.trigger_id
                ));
            }
        }
        for window in &self.recovery_windows {
            if !action_set.contains(&window.opened_by_action_id) {
                return Err(format!(
                    "recovery window references unknown action {}",
                    window.opened_by_action_id
                ));
            }
        }
        for trigger in self.active_triggers() {
            let signatures = self.guardian_signature_count_for_trigger(&trigger.trigger_id);
            if signatures < self.config.min_guardian_signatures {
                return Err(format!(
                    "active trigger {} has insufficient guardian signatures",
                    trigger.trigger_id
                ));
            }
        }
        Ok(self.state_root())
    }
}

pub fn emergency_control_plane_state_root_from_record(record: &Value) -> String {
    emergency_control_payload_root("EMERGENCY-CONTROL-STATE", record)
}

pub fn emergency_control_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(EMERGENCY_CONTROL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn emergency_control_string_root(value: &str) -> String {
    domain_hash(
        "EMERGENCY-CONTROL-STRING",
        &[
            HashPart::Str(EMERGENCY_CONTROL_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn emergency_control_trigger_id(
    trigger_kind: EmergencyTriggerKind,
    scope: EmergencyScope,
    evidence_root: &str,
    reporter_label: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "EMERGENCY-CONTROL-TRIGGER-ID",
        &[
            HashPart::Str(trigger_kind.as_str()),
            HashPart::Str(scope.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(reporter_label),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn emergency_control_attestation_id(
    trigger_id: &str,
    guardian_id: &str,
    observed_root: &str,
    signature_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "EMERGENCY-CONTROL-ATTESTATION-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(guardian_id),
            HashPart::Str(observed_root),
            HashPart::Str(signature_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn emergency_control_action_id(
    trigger_id: &str,
    action_kind: ControlActionKind,
    scope: EmergencyScope,
    safety_mode: SafetyMode,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "EMERGENCY-CONTROL-ACTION-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(scope.as_str()),
            HashPart::Str(safety_mode.as_str()),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn emergency_control_window_id(
    scope: EmergencyScope,
    opened_by_action_id: &str,
    exit_lane_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "EMERGENCY-CONTROL-WINDOW-ID",
        &[
            HashPart::Str(scope.as_str()),
            HashPart::Str(opened_by_action_id),
            HashPart::Str(exit_lane_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn emergency_control_event_id(
    event_kind: EmergencyEventKind,
    scope: EmergencyScope,
    subject_id: &str,
    payload_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "EMERGENCY-CONTROL-EVENT-ID",
        &[
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(scope.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn emergency_control_trigger_collection_root(records: &[SafetyTrigger]) -> String {
    keyed_value_root(
        "EMERGENCY-CONTROL-TRIGGER-COLLECTION",
        records
            .iter()
            .map(|record| (record.trigger_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn emergency_control_attestation_collection_root(records: &[GuardianAttestation]) -> String {
    keyed_value_root(
        "EMERGENCY-CONTROL-ATTESTATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.attestation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn emergency_control_action_collection_root(records: &[ControlAction]) -> String {
    keyed_value_root(
        "EMERGENCY-CONTROL-ACTION-COLLECTION",
        records
            .iter()
            .map(|record| (record.action_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn emergency_control_window_collection_root(records: &[RecoveryWindow]) -> String {
    keyed_value_root(
        "EMERGENCY-CONTROL-WINDOW-COLLECTION",
        records
            .iter()
            .map(|record| (record.window_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn emergency_control_event_collection_root(records: &[EmergencyControlEvent]) -> String {
    keyed_value_root(
        "EMERGENCY-CONTROL-EVENT-COLLECTION",
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

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn require_non_empty(label: &str, value: &str) -> EmergencyControlResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> EmergencyControlResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> EmergencyControlResult<()> {
    if value > EMERGENCY_CONTROL_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> EmergencyControlResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
