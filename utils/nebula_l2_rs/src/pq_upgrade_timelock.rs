use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqUpgradeTimelockResult<T> = Result<T, String>;

pub const PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION: &str = "nebula-l2-pq-upgrade-timelock-v1";
pub const PQ_UPGRADE_TIMELOCK_SCHEMA_VERSION: u64 = 1;
pub const PQ_UPGRADE_TIMELOCK_DEFAULT_NOTICE_BLOCKS: u64 = 1_440;
pub const PQ_UPGRADE_TIMELOCK_DEFAULT_ACTIVATION_DELAY_BLOCKS: u64 = 2_880;
pub const PQ_UPGRADE_TIMELOCK_DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 = 12;
pub const PQ_UPGRADE_TIMELOCK_DEFAULT_EXECUTION_WINDOW_BLOCKS: u64 = 720;
pub const PQ_UPGRADE_TIMELOCK_DEFAULT_LOW_FEE_WINDOW_BLOCKS: u64 = 4_320;
pub const PQ_UPGRADE_TIMELOCK_DEFAULT_FREEZE_BLOCKS: u64 = 288;
pub const PQ_UPGRADE_TIMELOCK_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 9_500;
pub const PQ_UPGRADE_TIMELOCK_MAX_BPS: u64 = 10_000;
pub const PQ_UPGRADE_TIMELOCK_MAX_ACTIONS: usize = 256;
pub const PQ_UPGRADE_TIMELOCK_MAX_FREEZES: usize = 128;
pub const PQ_UPGRADE_TIMELOCK_MAX_MIGRATION_WINDOWS: usize = 128;
pub const PQ_UPGRADE_TIMELOCK_MAX_DISCLOSURES: usize = 512;
pub const PQ_UPGRADE_TIMELOCK_MAX_EVENTS: usize = 1_024;
pub const PQ_UPGRADE_TIMELOCK_DEVNET_OPERATOR: &str = "nebula-pq-upgrade-guardian-devnet";
pub const PQ_UPGRADE_TIMELOCK_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_UPGRADE_TIMELOCK_PRIVATE_DISCLOSURE_SCHEME: &str =
    "devnet-sealed-pq-upgrade-disclosure-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqUpgradeSurface {
    CryptoPolicy,
    CircuitRegistry,
    Sequencer,
    Bridge,
    ProofMarket,
    Governance,
    UserMigration,
    PrivateDisclosure,
    Global,
}

impl PqUpgradeSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CryptoPolicy => "crypto_policy",
            Self::CircuitRegistry => "circuit_registry",
            Self::Sequencer => "sequencer",
            Self::Bridge => "bridge",
            Self::ProofMarket => "proof_market",
            Self::Governance => "governance",
            Self::UserMigration => "user_migration",
            Self::PrivateDisclosure => "private_disclosure",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqUpgradeActionKind {
    RegisterPqAlgorithm,
    DisableLegacyAlgorithm,
    ActivateHybridAuthorization,
    RotateCircuitVerifier,
    ScheduleCircuitCutover,
    FreezeSequencer,
    FreezeBridge,
    OpenLowFeeMigration,
    PublishPrivateDisclosure,
    EmergencyRollback,
}

impl PqUpgradeActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterPqAlgorithm => "register_pq_algorithm",
            Self::DisableLegacyAlgorithm => "disable_legacy_algorithm",
            Self::ActivateHybridAuthorization => "activate_hybrid_authorization",
            Self::RotateCircuitVerifier => "rotate_circuit_verifier",
            Self::ScheduleCircuitCutover => "schedule_circuit_cutover",
            Self::FreezeSequencer => "freeze_sequencer",
            Self::FreezeBridge => "freeze_bridge",
            Self::OpenLowFeeMigration => "open_low_fee_migration",
            Self::PublishPrivateDisclosure => "publish_private_disclosure",
            Self::EmergencyRollback => "emergency_rollback",
        }
    }

    pub fn emergency_capable(self) -> bool {
        matches!(
            self,
            Self::FreezeSequencer | Self::FreezeBridge | Self::EmergencyRollback
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqUpgradeStatus {
    Queued,
    Waiting,
    Ready,
    Active,
    Executed,
    Expired,
    Cancelled,
}

impl PqUpgradeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Waiting => "waiting",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Waiting | Self::Ready | Self::Active
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFreezeMode {
    None,
    ReadOnly,
    DepositsOnly,
    WithdrawalsOnly,
    MigrationOnly,
    Frozen,
}

impl PqFreezeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReadOnly => "read_only",
            Self::DepositsOnly => "deposits_only",
            Self::WithdrawalsOnly => "withdrawals_only",
            Self::MigrationOnly => "migration_only",
            Self::Frozen => "frozen",
        }
    }

    pub fn blocks_regular_flow(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqDisclosureKind {
    KeyCommitment,
    CircuitWitness,
    BridgeSignerSet,
    SequencerEvidence,
    MigrationEligibility,
    EmergencyContact,
}

impl PqDisclosureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyCommitment => "key_commitment",
            Self::CircuitWitness => "circuit_witness",
            Self::BridgeSignerSet => "bridge_signer_set",
            Self::SequencerEvidence => "sequencer_evidence",
            Self::MigrationEligibility => "migration_eligibility",
            Self::EmergencyContact => "emergency_contact",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqUpgradeEventKind {
    ActionQueued,
    ActionReady,
    ActionExecuted,
    FreezeActivated,
    FreezeExpired,
    MigrationWindowOpened,
    DisclosurePublished,
    HeightAdvanced,
}

impl PqUpgradeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActionQueued => "action_queued",
            Self::ActionReady => "action_ready",
            Self::ActionExecuted => "action_executed",
            Self::FreezeActivated => "freeze_activated",
            Self::FreezeExpired => "freeze_expired",
            Self::MigrationWindowOpened => "migration_window_opened",
            Self::DisclosurePublished => "disclosure_published",
            Self::HeightAdvanced => "height_advanced",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeTimelockConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub operator_commitment: String,
    pub notice_blocks: u64,
    pub activation_delay_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub execution_window_blocks: u64,
    pub low_fee_window_blocks: u64,
    pub default_freeze_blocks: u64,
    pub low_fee_rebate_bps: u64,
    pub private_disclosure_scheme: String,
}

impl PqUpgradeTimelockConfig {
    pub fn devnet(operator_label: &str) -> Self {
        Self {
            protocol_version: PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_commitment: pq_upgrade_timelock_string_root("operator", operator_label),
            notice_blocks: PQ_UPGRADE_TIMELOCK_DEFAULT_NOTICE_BLOCKS,
            activation_delay_blocks: PQ_UPGRADE_TIMELOCK_DEFAULT_ACTIVATION_DELAY_BLOCKS,
            emergency_delay_blocks: PQ_UPGRADE_TIMELOCK_DEFAULT_EMERGENCY_DELAY_BLOCKS,
            execution_window_blocks: PQ_UPGRADE_TIMELOCK_DEFAULT_EXECUTION_WINDOW_BLOCKS,
            low_fee_window_blocks: PQ_UPGRADE_TIMELOCK_DEFAULT_LOW_FEE_WINDOW_BLOCKS,
            default_freeze_blocks: PQ_UPGRADE_TIMELOCK_DEFAULT_FREEZE_BLOCKS,
            low_fee_rebate_bps: PQ_UPGRADE_TIMELOCK_DEFAULT_LOW_FEE_REBATE_BPS,
            private_disclosure_scheme: PQ_UPGRADE_TIMELOCK_PRIVATE_DISCLOSURE_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_upgrade_timelock_config",
            "protocol_version": self.protocol_version,
            "schema_version": PQ_UPGRADE_TIMELOCK_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "operator_commitment": self.operator_commitment,
            "notice_blocks": self.notice_blocks,
            "activation_delay_blocks": self.activation_delay_blocks,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "execution_window_blocks": self.execution_window_blocks,
            "low_fee_window_blocks": self.low_fee_window_blocks,
            "default_freeze_blocks": self.default_freeze_blocks,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "private_disclosure_scheme": self.private_disclosure_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        pq_upgrade_timelock_payload_root("PQ-UPGRADE-TIMELOCK-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqUpgradeTimelockResult<String> {
        require_equal(
            "protocol version",
            &self.protocol_version,
            PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
        )?;
        require_equal("chain id", &self.chain_id, CHAIN_ID)?;
        require_non_empty("operator commitment", &self.operator_commitment)?;
        require_positive("notice blocks", self.notice_blocks)?;
        require_positive("activation delay blocks", self.activation_delay_blocks)?;
        require_positive("execution window blocks", self.execution_window_blocks)?;
        require_positive("low fee window blocks", self.low_fee_window_blocks)?;
        require_positive("default freeze blocks", self.default_freeze_blocks)?;
        require_bps("low fee rebate bps", self.low_fee_rebate_bps)?;
        require_non_empty("private disclosure scheme", &self.private_disclosure_scheme)?;
        if self.activation_delay_blocks < self.notice_blocks {
            return Err("activation delay must cover the notice window".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeAction {
    pub action_id: String,
    pub action_kind: PqUpgradeActionKind,
    pub surface: PqUpgradeSurface,
    pub target_id: String,
    pub payload_root: String,
    pub authority_commitment: String,
    pub queued_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub grace_until_height: u64,
    pub emergency: bool,
    pub private_payload: bool,
    pub status: PqUpgradeStatus,
}

impl PqUpgradeAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_kind: PqUpgradeActionKind,
        surface: PqUpgradeSurface,
        target_id: &str,
        payload: &Value,
        authority_commitment: &str,
        queued_at_height: u64,
        delay_blocks: u64,
        execution_window_blocks: u64,
        grace_blocks: u64,
        emergency: bool,
        private_payload: bool,
    ) -> PqUpgradeTimelockResult<Self> {
        require_non_empty("action target id", target_id)?;
        require_non_empty("action authority commitment", authority_commitment)?;
        require_positive("execution window blocks", execution_window_blocks)?;
        if emergency && !action_kind.emergency_capable() {
            return Err("action kind is not eligible for emergency delay".to_string());
        }
        let payload_root = pq_upgrade_timelock_payload_root("PQ-UPGRADE-ACTION-PAYLOAD", payload);
        let executable_at_height = queued_at_height.saturating_add(delay_blocks);
        let expires_at_height = executable_at_height.saturating_add(execution_window_blocks);
        let grace_until_height = expires_at_height.saturating_add(grace_blocks);
        let action_id = pq_upgrade_action_id(
            action_kind,
            surface,
            target_id,
            &payload_root,
            authority_commitment,
            queued_at_height,
        );
        let mut action = Self {
            action_id,
            action_kind,
            surface,
            target_id: target_id.to_string(),
            payload_root,
            authority_commitment: authority_commitment.to_string(),
            queued_at_height,
            executable_at_height,
            expires_at_height,
            grace_until_height,
            emergency,
            private_payload,
            status: PqUpgradeStatus::Queued,
        };
        action.set_height(queued_at_height);
        action.validate()?;
        Ok(action)
    }

    pub fn set_height(&mut self, height: u64) {
        if !self.status.open() {
            return;
        }
        self.status = if height >= self.grace_until_height {
            PqUpgradeStatus::Expired
        } else if height >= self.executable_at_height {
            PqUpgradeStatus::Ready
        } else {
            PqUpgradeStatus::Waiting
        };
    }

    pub fn is_executable_at_height(&self, height: u64) -> bool {
        self.status.open() && height >= self.executable_at_height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_upgrade_action",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "schema_version": PQ_UPGRADE_TIMELOCK_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "action_id": self.action_id,
            "action_kind": self.action_kind.as_str(),
            "surface": self.surface.as_str(),
            "target_id": self.target_id,
            "payload_root": self.payload_root,
            "authority_commitment": self.authority_commitment,
            "queued_at_height": self.queued_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "grace_until_height": self.grace_until_height,
            "emergency": self.emergency,
            "private_payload": self.private_payload,
            "status": self.status.as_str(),
        })
    }

    pub fn action_root(&self) -> String {
        pq_upgrade_timelock_payload_root("PQ-UPGRADE-ACTION", &self.public_record())
    }

    pub fn validate(&self) -> PqUpgradeTimelockResult<String> {
        require_non_empty("action id", &self.action_id)?;
        require_non_empty("action target id", &self.target_id)?;
        require_non_empty("action payload root", &self.payload_root)?;
        require_non_empty("action authority commitment", &self.authority_commitment)?;
        if self.executable_at_height < self.queued_at_height {
            return Err("action executable height cannot precede queued height".to_string());
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err("action expiry must follow executable height".to_string());
        }
        if self.grace_until_height < self.expires_at_height {
            return Err("action grace height cannot precede expiry".to_string());
        }
        if self.emergency && !self.action_kind.emergency_capable() {
            return Err("emergency action kind mismatch".to_string());
        }
        let expected = pq_upgrade_action_id(
            self.action_kind,
            self.surface,
            &self.target_id,
            &self.payload_root,
            &self.authority_commitment,
            self.queued_at_height,
        );
        if self.action_id != expected {
            return Err("pq upgrade action id mismatch".to_string());
        }
        Ok(self.action_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqEmergencyFreeze {
    pub freeze_id: String,
    pub action_id: String,
    pub surface: PqUpgradeSurface,
    pub target_id: String,
    pub mode: PqFreezeMode,
    pub reason_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqUpgradeStatus,
}

impl PqEmergencyFreeze {
    pub fn new(
        action_id: &str,
        surface: PqUpgradeSurface,
        target_id: &str,
        mode: PqFreezeMode,
        reason: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
    ) -> PqUpgradeTimelockResult<Self> {
        require_non_empty("freeze action id", action_id)?;
        require_non_empty("freeze target id", target_id)?;
        if mode == PqFreezeMode::None {
            return Err("freeze mode cannot be none".to_string());
        }
        if expires_at_height <= starts_at_height {
            return Err("freeze expiry must be after start height".to_string());
        }
        let reason_root = pq_upgrade_timelock_payload_root("PQ-UPGRADE-FREEZE-REASON", reason);
        let freeze_id = pq_emergency_freeze_id(
            action_id,
            surface,
            target_id,
            mode,
            &reason_root,
            starts_at_height,
        );
        let mut freeze = Self {
            freeze_id,
            action_id: action_id.to_string(),
            surface,
            target_id: target_id.to_string(),
            mode,
            reason_root,
            starts_at_height,
            expires_at_height,
            status: PqUpgradeStatus::Queued,
        };
        freeze.set_height(starts_at_height);
        freeze.validate()?;
        Ok(freeze)
    }

    pub fn set_height(&mut self, height: u64) {
        if !self.status.open() {
            return;
        }
        self.status = if height >= self.expires_at_height {
            PqUpgradeStatus::Expired
        } else if height >= self.starts_at_height {
            PqUpgradeStatus::Active
        } else {
            PqUpgradeStatus::Waiting
        };
    }

    pub fn active_at_height(&self, height: u64) -> bool {
        self.status.open() && height >= self.starts_at_height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_emergency_freeze",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "freeze_id": self.freeze_id,
            "action_id": self.action_id,
            "surface": self.surface.as_str(),
            "target_id": self.target_id,
            "mode": self.mode.as_str(),
            "reason_root": self.reason_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqUpgradeTimelockResult<String> {
        require_non_empty("freeze id", &self.freeze_id)?;
        require_non_empty("freeze action id", &self.action_id)?;
        require_non_empty("freeze target id", &self.target_id)?;
        require_non_empty("freeze reason root", &self.reason_root)?;
        if self.mode == PqFreezeMode::None {
            return Err("freeze mode cannot be none".to_string());
        }
        if self.expires_at_height <= self.starts_at_height {
            return Err("freeze expiry must be after start height".to_string());
        }
        let expected = pq_emergency_freeze_id(
            &self.action_id,
            self.surface,
            &self.target_id,
            self.mode,
            &self.reason_root,
            self.starts_at_height,
        );
        if self.freeze_id != expected {
            return Err("pq emergency freeze id mismatch".to_string());
        }
        Ok(self.freeze_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLowFeeMigrationWindow {
    pub window_id: String,
    pub action_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub rebate_bps: u64,
    pub user_cap: u64,
    pub spent_fee_units: u64,
    pub private_eligibility_root: String,
    pub status: PqUpgradeStatus,
}

impl PqLowFeeMigrationWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_id: &str,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        opens_at_height: u64,
        closes_at_height: u64,
        rebate_bps: u64,
        user_cap: u64,
        private_eligibility: &Value,
    ) -> PqUpgradeTimelockResult<Self> {
        require_non_empty("migration window action id", action_id)?;
        require_non_empty("migration sponsor commitment", sponsor_commitment)?;
        require_non_empty("migration fee asset id", fee_asset_id)?;
        require_positive("migration window user cap", user_cap)?;
        require_bps("migration rebate bps", rebate_bps)?;
        if closes_at_height <= opens_at_height {
            return Err("migration window close height must follow open height".to_string());
        }
        let private_eligibility_root = pq_upgrade_timelock_payload_root(
            "PQ-UPGRADE-MIGRATION-PRIVATE-ELIGIBILITY",
            private_eligibility,
        );
        let window_id = pq_low_fee_migration_window_id(
            action_id,
            sponsor_commitment,
            fee_asset_id,
            &private_eligibility_root,
            opens_at_height,
        );
        let mut window = Self {
            window_id,
            action_id: action_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            opens_at_height,
            closes_at_height,
            rebate_bps,
            user_cap,
            spent_fee_units: 0,
            private_eligibility_root,
            status: PqUpgradeStatus::Queued,
        };
        window.set_height(opens_at_height);
        window.validate()?;
        Ok(window)
    }

    pub fn set_height(&mut self, height: u64) {
        if !self.status.open() {
            return;
        }
        self.status = if height >= self.closes_at_height {
            PqUpgradeStatus::Expired
        } else if height >= self.opens_at_height {
            PqUpgradeStatus::Active
        } else {
            PqUpgradeStatus::Waiting
        };
    }

    pub fn active_at_height(&self, height: u64) -> bool {
        self.status.open() && height >= self.opens_at_height && height < self.closes_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_low_fee_migration_window",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "action_id": self.action_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "rebate_bps": self.rebate_bps,
            "user_cap": self.user_cap,
            "spent_fee_units": self.spent_fee_units,
            "private_eligibility_root": self.private_eligibility_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqUpgradeTimelockResult<String> {
        require_non_empty("migration window id", &self.window_id)?;
        require_non_empty("migration action id", &self.action_id)?;
        require_non_empty("migration sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty("migration fee asset id", &self.fee_asset_id)?;
        require_non_empty(
            "migration private eligibility root",
            &self.private_eligibility_root,
        )?;
        require_positive("migration user cap", self.user_cap)?;
        require_bps("migration rebate bps", self.rebate_bps)?;
        if self.closes_at_height <= self.opens_at_height {
            return Err("migration window close height must follow open height".to_string());
        }
        let expected = pq_low_fee_migration_window_id(
            &self.action_id,
            &self.sponsor_commitment,
            &self.fee_asset_id,
            &self.private_eligibility_root,
            self.opens_at_height,
        );
        if self.window_id != expected {
            return Err("pq low fee migration window id mismatch".to_string());
        }
        Ok(self.window_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPrivateDisclosure {
    pub disclosure_id: String,
    pub disclosure_kind: PqDisclosureKind,
    pub action_id: String,
    pub subject_commitment: String,
    pub encrypted_payload_root: String,
    pub nullifier_root: String,
    pub public_hint_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqUpgradeStatus,
}

impl PqPrivateDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        disclosure_kind: PqDisclosureKind,
        action_id: &str,
        subject_commitment: &str,
        encrypted_payload: &Value,
        nullifier_root: &str,
        public_hint: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PqUpgradeTimelockResult<Self> {
        require_non_empty("disclosure action id", action_id)?;
        require_non_empty("disclosure subject commitment", subject_commitment)?;
        require_non_empty("disclosure nullifier root", nullifier_root)?;
        if expires_at_height <= opened_at_height {
            return Err("disclosure expiry must be after open height".to_string());
        }
        let encrypted_payload_root =
            pq_upgrade_timelock_payload_root("PQ-UPGRADE-DISCLOSURE-ENCRYPTED", encrypted_payload);
        let public_hint_root =
            pq_upgrade_timelock_payload_root("PQ-UPGRADE-DISCLOSURE-HINT", public_hint);
        let disclosure_id = pq_private_disclosure_id(
            disclosure_kind,
            action_id,
            subject_commitment,
            &encrypted_payload_root,
            nullifier_root,
        );
        let disclosure = Self {
            disclosure_id,
            disclosure_kind,
            action_id: action_id.to_string(),
            subject_commitment: subject_commitment.to_string(),
            encrypted_payload_root,
            nullifier_root: nullifier_root.to_string(),
            public_hint_root,
            opened_at_height,
            expires_at_height,
            status: PqUpgradeStatus::Active,
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.open() && height >= self.expires_at_height {
            self.status = PqUpgradeStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_disclosure",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "disclosure_id": self.disclosure_id,
            "disclosure_kind": self.disclosure_kind.as_str(),
            "action_id": self.action_id,
            "subject_commitment": self.subject_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier_root": self.nullifier_root,
            "public_hint_root": self.public_hint_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqUpgradeTimelockResult<String> {
        require_non_empty("disclosure id", &self.disclosure_id)?;
        require_non_empty("disclosure action id", &self.action_id)?;
        require_non_empty("disclosure subject commitment", &self.subject_commitment)?;
        require_non_empty(
            "disclosure encrypted payload root",
            &self.encrypted_payload_root,
        )?;
        require_non_empty("disclosure nullifier root", &self.nullifier_root)?;
        require_non_empty("disclosure public hint root", &self.public_hint_root)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("disclosure expiry must be after open height".to_string());
        }
        let expected = pq_private_disclosure_id(
            self.disclosure_kind,
            &self.action_id,
            &self.subject_commitment,
            &self.encrypted_payload_root,
            &self.nullifier_root,
        );
        if self.disclosure_id != expected {
            return Err("pq private disclosure id mismatch".to_string());
        }
        Ok(self.disclosure_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeTimelockEvent {
    pub event_id: String,
    pub event_kind: PqUpgradeEventKind,
    pub surface: PqUpgradeSurface,
    pub subject_id: String,
    pub height: u64,
    pub payload_root: String,
}

impl PqUpgradeTimelockEvent {
    pub fn new(
        event_kind: PqUpgradeEventKind,
        surface: PqUpgradeSurface,
        subject_id: &str,
        height: u64,
        payload: &Value,
    ) -> PqUpgradeTimelockResult<Self> {
        require_non_empty("event subject id", subject_id)?;
        let payload_root = pq_upgrade_timelock_payload_root("PQ-UPGRADE-EVENT-PAYLOAD", payload);
        let event_id =
            pq_upgrade_timelock_event_id(event_kind, surface, subject_id, &payload_root, height);
        Ok(Self {
            event_id,
            event_kind,
            surface,
            subject_id: subject_id.to_string(),
            height,
            payload_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_upgrade_timelock_event",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "surface": self.surface.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }

    pub fn validate(&self) -> PqUpgradeTimelockResult<String> {
        require_non_empty("event id", &self.event_id)?;
        require_non_empty("event subject id", &self.subject_id)?;
        require_non_empty("event payload root", &self.payload_root)?;
        let expected = pq_upgrade_timelock_event_id(
            self.event_kind,
            self.surface,
            &self.subject_id,
            &self.payload_root,
            self.height,
        );
        if self.event_id != expected {
            return Err("pq upgrade timelock event id mismatch".to_string());
        }
        Ok(self.event_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeTimelockRoots {
    pub config_root: String,
    pub action_root: String,
    pub freeze_root: String,
    pub migration_window_root: String,
    pub disclosure_root: String,
    pub event_root: String,
    pub surface_mode_root: String,
}

impl PqUpgradeTimelockRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_upgrade_timelock_roots",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "action_root": self.action_root,
            "freeze_root": self.freeze_root,
            "migration_window_root": self.migration_window_root,
            "disclosure_root": self.disclosure_root,
            "event_root": self.event_root,
            "surface_mode_root": self.surface_mode_root,
        })
    }

    pub fn roots_root(&self) -> String {
        pq_upgrade_timelock_payload_root("PQ-UPGRADE-TIMELOCK-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeTimelockCounters {
    pub action_count: u64,
    pub ready_action_count: u64,
    pub emergency_action_count: u64,
    pub active_freeze_count: u64,
    pub active_migration_window_count: u64,
    pub active_disclosure_count: u64,
    pub blocked_surface_count: u64,
    pub low_fee_user_cap: u64,
}

impl PqUpgradeTimelockCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_upgrade_timelock_counters",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "action_count": self.action_count,
            "ready_action_count": self.ready_action_count,
            "emergency_action_count": self.emergency_action_count,
            "active_freeze_count": self.active_freeze_count,
            "active_migration_window_count": self.active_migration_window_count,
            "active_disclosure_count": self.active_disclosure_count,
            "blocked_surface_count": self.blocked_surface_count,
            "low_fee_user_cap": self.low_fee_user_cap,
        })
    }

    pub fn counters_root(&self) -> String {
        pq_upgrade_timelock_payload_root("PQ-UPGRADE-TIMELOCK-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeTimelockState {
    pub config: PqUpgradeTimelockConfig,
    pub height: u64,
    pub actions: Vec<PqUpgradeAction>,
    pub freezes: Vec<PqEmergencyFreeze>,
    pub migration_windows: Vec<PqLowFeeMigrationWindow>,
    pub disclosures: Vec<PqPrivateDisclosure>,
    pub events: Vec<PqUpgradeTimelockEvent>,
    pub devnet_notes_root: String,
}

impl PqUpgradeTimelockState {
    pub fn devnet() -> PqUpgradeTimelockResult<Self> {
        let height = 512;
        let config = PqUpgradeTimelockConfig::devnet(PQ_UPGRADE_TIMELOCK_DEVNET_OPERATOR);
        let authority_commitment = config.operator_commitment.clone();
        let circuit_action = PqUpgradeAction::new(
            PqUpgradeActionKind::RotateCircuitVerifier,
            PqUpgradeSurface::CircuitRegistry,
            "rollup-state-pq-verifier-v2",
            &json!({
                "old_verifier_root": pq_upgrade_timelock_string_root("devnet-rollup-verifier-v1", "old"),
                "new_verifier_root": pq_upgrade_timelock_string_root("devnet-rollup-verifier-v2", "new"),
                "proof_system": "shake-plonk-devnet",
                "attestation_threshold_bps": 7_500,
            }),
            &authority_commitment,
            height,
            config.activation_delay_blocks,
            config.execution_window_blocks,
            config.notice_blocks,
            false,
            false,
        )?;
        let migration_action = PqUpgradeAction::new(
            PqUpgradeActionKind::OpenLowFeeMigration,
            PqUpgradeSurface::UserMigration,
            "wallet-hybrid-rekey-window-devnet-1",
            &json!({
                "required_signature": "ML-DSA-65",
                "sealed_transport": "ML-KEM-768",
                "fee_mode": "sponsored-low-fee",
            }),
            &authority_commitment,
            height,
            config.notice_blocks,
            config.execution_window_blocks,
            config.low_fee_window_blocks,
            false,
            true,
        )?;
        let freeze_action = PqUpgradeAction::new(
            PqUpgradeActionKind::FreezeBridge,
            PqUpgradeSurface::Bridge,
            "monero-bridge-signer-set-devnet",
            &json!({
                "risk": "legacy bridge signer rotation overlap",
                "resume_requires": "pq guardian quorum",
            }),
            &authority_commitment,
            height,
            config.emergency_delay_blocks,
            config.execution_window_blocks,
            config.default_freeze_blocks,
            true,
            true,
        )?;
        let freeze = PqEmergencyFreeze::new(
            &freeze_action.action_id,
            PqUpgradeSurface::Bridge,
            "monero-bridge-signer-set-devnet",
            PqFreezeMode::MigrationOnly,
            &json!({
                "reason": "guarded signer handoff",
                "low_fee_exit": true,
            }),
            freeze_action.executable_at_height,
            freeze_action
                .executable_at_height
                .saturating_add(config.default_freeze_blocks),
        )?;
        let migration_window = PqLowFeeMigrationWindow::new(
            &migration_action.action_id,
            &authority_commitment,
            PQ_UPGRADE_TIMELOCK_DEVNET_FEE_ASSET_ID,
            migration_action.executable_at_height,
            migration_action
                .executable_at_height
                .saturating_add(config.low_fee_window_blocks),
            config.low_fee_rebate_bps,
            100_000,
            &json!({
                "eligibility_tree": "devnet-wallet-hybrid-rekey-commitments",
                "private_receipts": true,
            }),
        )?;
        let disclosure = PqPrivateDisclosure::new(
            PqDisclosureKind::BridgeSignerSet,
            &freeze_action.action_id,
            &pq_upgrade_timelock_string_root("bridge-signer-set", "devnet-committee"),
            &json!({
                "sealed_to": PQ_UPGRADE_TIMELOCK_PRIVATE_DISCLOSURE_SCHEME,
                "payload": "encrypted-devnet-bridge-signer-diff",
            }),
            &pq_upgrade_timelock_string_root("nullifier", "bridge-signer-set-devnet-1"),
            &json!({
                "surface": PqUpgradeSurface::Bridge.as_str(),
                "public_hint": "threshold signer set changed",
            }),
            height,
            height.saturating_add(config.low_fee_window_blocks),
        )?;
        let events = vec![
            PqUpgradeTimelockEvent::new(
                PqUpgradeEventKind::ActionQueued,
                circuit_action.surface,
                &circuit_action.action_id,
                height,
                &circuit_action.public_record(),
            )?,
            PqUpgradeTimelockEvent::new(
                PqUpgradeEventKind::MigrationWindowOpened,
                PqUpgradeSurface::UserMigration,
                &migration_window.window_id,
                migration_window.opens_at_height,
                &migration_window.public_record(),
            )?,
            PqUpgradeTimelockEvent::new(
                PqUpgradeEventKind::FreezeActivated,
                PqUpgradeSurface::Bridge,
                &freeze.freeze_id,
                freeze.starts_at_height,
                &freeze.public_record(),
            )?,
            PqUpgradeTimelockEvent::new(
                PqUpgradeEventKind::DisclosurePublished,
                PqUpgradeSurface::PrivateDisclosure,
                &disclosure.disclosure_id,
                disclosure.opened_at_height,
                &disclosure.public_record(),
            )?,
        ];
        let mut state = Self {
            config,
            height,
            actions: vec![circuit_action, migration_action, freeze_action],
            freezes: vec![freeze],
            migration_windows: vec![migration_window],
            disclosures: vec![disclosure],
            events,
            devnet_notes_root: pq_upgrade_timelock_payload_root(
                "PQ-UPGRADE-DEVNET-NOTES",
                &json!({
                    "purpose": "standalone post-quantum upgrade timelock fixture",
                    "integration": "main agent wires lib/devnet/operator",
                }),
            ),
        };
        state.set_height(height)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqUpgradeTimelockResult<String> {
        self.height = height;
        for action in &mut self.actions {
            action.set_height(height);
        }
        for freeze in &mut self.freezes {
            freeze.set_height(height);
        }
        for window in &mut self.migration_windows {
            window.set_height(height);
        }
        for disclosure in &mut self.disclosures {
            disclosure.set_height(height);
        }
        self.validate()
    }

    pub fn active_freezes(&self) -> Vec<&PqEmergencyFreeze> {
        self.freezes
            .iter()
            .filter(|freeze| freeze.active_at_height(self.height))
            .collect()
    }

    pub fn active_migration_windows(&self) -> Vec<&PqLowFeeMigrationWindow> {
        self.migration_windows
            .iter()
            .filter(|window| window.active_at_height(self.height))
            .collect()
    }

    pub fn freeze_mode_for_surface(&self, surface: PqUpgradeSurface) -> PqFreezeMode {
        match self
            .active_freezes()
            .into_iter()
            .filter(|freeze| {
                freeze.surface == surface || freeze.surface == PqUpgradeSurface::Global
            })
            .map(|freeze| freeze.mode)
            .max()
        {
            Some(mode) => mode,
            None => PqFreezeMode::None,
        }
    }

    pub fn surface_mode_map(&self) -> BTreeMap<String, String> {
        [
            PqUpgradeSurface::CryptoPolicy,
            PqUpgradeSurface::CircuitRegistry,
            PqUpgradeSurface::Sequencer,
            PqUpgradeSurface::Bridge,
            PqUpgradeSurface::ProofMarket,
            PqUpgradeSurface::Governance,
            PqUpgradeSurface::UserMigration,
            PqUpgradeSurface::PrivateDisclosure,
            PqUpgradeSurface::Global,
        ]
        .into_iter()
        .map(|surface| {
            (
                surface.as_str().to_string(),
                self.freeze_mode_for_surface(surface).as_str().to_string(),
            )
        })
        .collect()
    }

    pub fn roots(&self) -> PqUpgradeTimelockRoots {
        PqUpgradeTimelockRoots {
            config_root: self.config.config_root(),
            action_root: pq_upgrade_action_collection_root(&self.actions),
            freeze_root: pq_emergency_freeze_collection_root(&self.freezes),
            migration_window_root: pq_low_fee_migration_window_collection_root(
                &self.migration_windows,
            ),
            disclosure_root: pq_private_disclosure_collection_root(&self.disclosures),
            event_root: pq_upgrade_timelock_event_collection_root(&self.events),
            surface_mode_root: pq_upgrade_timelock_payload_root(
                "PQ-UPGRADE-SURFACE-MODES",
                &json!(self.surface_mode_map()),
            ),
        }
    }

    pub fn counters(&self) -> PqUpgradeTimelockCounters {
        let active_disclosure_count = self
            .disclosures
            .iter()
            .filter(|disclosure| disclosure.status.open())
            .count() as u64;
        let blocked_surface_count = self
            .surface_mode_map()
            .values()
            .filter(|mode| mode.as_str() != PqFreezeMode::None.as_str())
            .count() as u64;
        PqUpgradeTimelockCounters {
            action_count: self.actions.len() as u64,
            ready_action_count: self
                .actions
                .iter()
                .filter(|action| action.is_executable_at_height(self.height))
                .count() as u64,
            emergency_action_count: self
                .actions
                .iter()
                .filter(|action| action.emergency)
                .count() as u64,
            active_freeze_count: self.active_freezes().len() as u64,
            active_migration_window_count: self.active_migration_windows().len() as u64,
            active_disclosure_count,
            blocked_surface_count,
            low_fee_user_cap: self
                .active_migration_windows()
                .into_iter()
                .map(|window| window.user_cap)
                .sum(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_upgrade_timelock_state",
            "protocol_version": PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION,
            "schema_version": PQ_UPGRADE_TIMELOCK_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "surface_modes": self.surface_mode_map(),
            "devnet_notes_root": self.devnet_notes_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_upgrade_timelock_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "pq_upgrade_timelock_state_root".to_string(),
                Value::String(self.state_root()),
            );
        }
        record
    }

    pub fn validate(&self) -> PqUpgradeTimelockResult<String> {
        self.config.validate()?;
        require_non_empty("devnet notes root", &self.devnet_notes_root)?;
        ensure_max_len(
            self.actions.len(),
            PQ_UPGRADE_TIMELOCK_MAX_ACTIONS,
            "actions",
        )?;
        ensure_max_len(
            self.freezes.len(),
            PQ_UPGRADE_TIMELOCK_MAX_FREEZES,
            "freezes",
        )?;
        ensure_max_len(
            self.migration_windows.len(),
            PQ_UPGRADE_TIMELOCK_MAX_MIGRATION_WINDOWS,
            "migration windows",
        )?;
        ensure_max_len(
            self.disclosures.len(),
            PQ_UPGRADE_TIMELOCK_MAX_DISCLOSURES,
            "disclosures",
        )?;
        ensure_max_len(self.events.len(), PQ_UPGRADE_TIMELOCK_MAX_EVENTS, "events")?;

        let action_ids = self
            .actions
            .iter()
            .map(PqUpgradeAction::validate)
            .collect::<PqUpgradeTimelockResult<Vec<_>>>()?;
        ensure_unique_strings(&action_ids, "action id")?;
        let action_set = action_ids.iter().cloned().collect::<BTreeSet<_>>();

        let freeze_ids = self
            .freezes
            .iter()
            .map(PqEmergencyFreeze::validate)
            .collect::<PqUpgradeTimelockResult<Vec<_>>>()?;
        ensure_unique_strings(&freeze_ids, "freeze id")?;
        for freeze in &self.freezes {
            if !action_set.contains(&freeze.action_id) {
                return Err(format!(
                    "freeze references unknown action {}",
                    freeze.action_id
                ));
            }
        }

        let window_ids = self
            .migration_windows
            .iter()
            .map(PqLowFeeMigrationWindow::validate)
            .collect::<PqUpgradeTimelockResult<Vec<_>>>()?;
        ensure_unique_strings(&window_ids, "migration window id")?;
        for window in &self.migration_windows {
            if !action_set.contains(&window.action_id) {
                return Err(format!(
                    "migration window references unknown action {}",
                    window.action_id
                ));
            }
        }

        let disclosure_ids = self
            .disclosures
            .iter()
            .map(PqPrivateDisclosure::validate)
            .collect::<PqUpgradeTimelockResult<Vec<_>>>()?;
        ensure_unique_strings(&disclosure_ids, "disclosure id")?;
        for disclosure in &self.disclosures {
            if !action_set.contains(&disclosure.action_id) {
                return Err(format!(
                    "disclosure references unknown action {}",
                    disclosure.action_id
                ));
            }
        }

        let event_ids = self
            .events
            .iter()
            .map(PqUpgradeTimelockEvent::validate)
            .collect::<PqUpgradeTimelockResult<Vec<_>>>()?;
        ensure_unique_strings(&event_ids, "event id")?;
        Ok(self.state_root())
    }
}

pub fn devnet() -> PqUpgradeTimelockResult<PqUpgradeTimelockState> {
    PqUpgradeTimelockState::devnet()
}

pub fn pq_upgrade_timelock_state_root_from_record(record: &Value) -> String {
    pq_upgrade_timelock_payload_root("PQ-UPGRADE-TIMELOCK-STATE", record)
}

pub fn pq_upgrade_timelock_public_record_root(record: &Value) -> String {
    pq_upgrade_timelock_payload_root("PQ-UPGRADE-TIMELOCK-PUBLIC-RECORD", record)
}

pub fn pq_upgrade_timelock_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn pq_upgrade_timelock_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "PQ-UPGRADE-TIMELOCK-STRING",
        &[
            HashPart::Str(PQ_UPGRADE_TIMELOCK_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn pq_upgrade_action_id(
    action_kind: PqUpgradeActionKind,
    surface: PqUpgradeSurface,
    target_id: &str,
    payload_root: &str,
    authority_commitment: &str,
    queued_at_height: u64,
) -> String {
    domain_hash(
        "PQ-UPGRADE-ACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(surface.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(payload_root),
            HashPart::Str(authority_commitment),
            HashPart::Int(queued_at_height as i128),
        ],
        32,
    )
}

pub fn pq_emergency_freeze_id(
    action_id: &str,
    surface: PqUpgradeSurface,
    target_id: &str,
    mode: PqFreezeMode,
    reason_root: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PQ-UPGRADE-EMERGENCY-FREEZE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(action_id),
            HashPart::Str(surface.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(reason_root),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn pq_low_fee_migration_window_id(
    action_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    private_eligibility_root: &str,
    opens_at_height: u64,
) -> String {
    domain_hash(
        "PQ-UPGRADE-LOW-FEE-MIGRATION-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(action_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(private_eligibility_root),
            HashPart::Int(opens_at_height as i128),
        ],
        32,
    )
}

pub fn pq_private_disclosure_id(
    disclosure_kind: PqDisclosureKind,
    action_id: &str,
    subject_commitment: &str,
    encrypted_payload_root: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "PQ-UPGRADE-PRIVATE-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(disclosure_kind.as_str()),
            HashPart::Str(action_id),
            HashPart::Str(subject_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn pq_upgrade_timelock_event_id(
    event_kind: PqUpgradeEventKind,
    surface: PqUpgradeSurface,
    subject_id: &str,
    payload_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PQ-UPGRADE-TIMELOCK-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(surface.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn pq_upgrade_action_collection_root(records: &[PqUpgradeAction]) -> String {
    keyed_value_root(
        "PQ-UPGRADE-ACTION-COLLECTION",
        records
            .iter()
            .map(|record| (record.action_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_emergency_freeze_collection_root(records: &[PqEmergencyFreeze]) -> String {
    keyed_value_root(
        "PQ-UPGRADE-FREEZE-COLLECTION",
        records
            .iter()
            .map(|record| (record.freeze_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_low_fee_migration_window_collection_root(records: &[PqLowFeeMigrationWindow]) -> String {
    keyed_value_root(
        "PQ-UPGRADE-MIGRATION-WINDOW-COLLECTION",
        records
            .iter()
            .map(|record| (record.window_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_private_disclosure_collection_root(records: &[PqPrivateDisclosure]) -> String {
    keyed_value_root(
        "PQ-UPGRADE-PRIVATE-DISCLOSURE-COLLECTION",
        records
            .iter()
            .map(|record| (record.disclosure_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_upgrade_timelock_event_collection_root(records: &[PqUpgradeTimelockEvent]) -> String {
    keyed_value_root(
        "PQ-UPGRADE-TIMELOCK-EVENT-COLLECTION",
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

fn require_equal(label: &str, value: &str, expected: &str) -> PqUpgradeTimelockResult<()> {
    if value != expected {
        Err(format!("{label} mismatch"))
    } else {
        Ok(())
    }
}

fn require_non_empty(label: &str, value: &str) -> PqUpgradeTimelockResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> PqUpgradeTimelockResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> PqUpgradeTimelockResult<()> {
    if value > PQ_UPGRADE_TIMELOCK_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_max_len(count: usize, max: usize, label: &str) -> PqUpgradeTimelockResult<()> {
    if count > max {
        Err(format!("{label} exceeds maximum length {max}"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> PqUpgradeTimelockResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
