use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        public_key_for_label, sign_validator_authorization, verify_validator_authorization,
        Authorization, CryptoRole,
    },
    hash::{domain_hash, json_size, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type GovernanceResult<T> = Result<T, String>;

pub const GOVERNANCE_PROTOCOL_VERSION: &str = "nebula-l2-governance-v1";
pub const GOVERNANCE_DEFAULT_QUORUM_BPS: u64 = 6_667;
pub const GOVERNANCE_DEFAULT_APPROVAL_BPS: u64 = 5_001;
pub const GOVERNANCE_SUPERMAJORITY_APPROVAL_BPS: u64 = 7_500;
pub const GOVERNANCE_DEFAULT_TIMELOCK_BLOCKS: u64 = 20;
pub const GOVERNANCE_UPGRADE_TIMELOCK_BLOCKS: u64 = 100;
pub const GOVERNANCE_EMERGENCY_TIMELOCK_BLOCKS: u64 = 0;
pub const GOVERNANCE_DEFAULT_VOTE_WINDOW_BLOCKS: u64 = 40;
pub const GOVERNANCE_MIN_VOTE_WINDOW_BLOCKS: u64 = 5;
pub const GOVERNANCE_MAX_VOTE_WINDOW_BLOCKS: u64 = 2_880;
pub const GOVERNANCE_EXECUTION_WINDOW_BLOCKS: u64 = 7_200;
pub const GOVERNANCE_MAX_ACTION_BYTES: usize = 64 * 1024;
pub const GOVERNANCE_MAX_PARAMETER_CHANGES: usize = 64;
pub const GOVERNANCE_MAX_ALLOWLIST_CHANGES: usize = 64;
pub const GOVERNANCE_MAX_CRYPTO_MIGRATION_STEPS: usize = 32;
pub const GOVERNANCE_MAX_PAUSE_SCOPES: usize = 32;
pub const GOVERNANCE_MAX_VALIDATORS: usize = 256;
pub const GOVERNANCE_MIN_PROPOSAL_DEPOSIT_UNITS: u64 = 0;
pub const GOVERNANCE_DEFAULT_TREASURY_ACCOUNT: &str = "nebula-l2-devnet-treasury";
pub const GOVERNANCE_DEFAULT_FEE_ASSET_ID: &str = "piconero";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GovernanceProposalKind {
    ParameterChange,
    TimelockedUpgrade,
    EmergencyPause,
    EmergencyResume,
    TreasuryPolicyChange,
    FeePolicyChange,
    QuantumCryptoMigration,
    ContractAllowlistChange,
}

impl GovernanceProposalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ParameterChange => "parameter_change",
            Self::TimelockedUpgrade => "timelocked_upgrade",
            Self::EmergencyPause => "emergency_pause",
            Self::EmergencyResume => "emergency_resume",
            Self::TreasuryPolicyChange => "treasury_policy_change",
            Self::FeePolicyChange => "fee_policy_change",
            Self::QuantumCryptoMigration => "quantum_crypto_migration",
            Self::ContractAllowlistChange => "contract_allowlist_change",
        }
    }

    pub fn requires_supermajority(&self) -> bool {
        matches!(
            self,
            Self::TimelockedUpgrade
                | Self::QuantumCryptoMigration
                | Self::TreasuryPolicyChange
                | Self::EmergencyResume
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GovernanceVoteChoice {
    Approve,
    Reject,
    Abstain,
}

impl GovernanceVoteChoice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContractAllowlistAction {
    Add,
    Remove,
    Suspend,
    Resume,
}

impl ContractAllowlistAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GovernanceAuditEventKind {
    ValidatorRegistered,
    ValidatorRetired,
    ProposalCreated,
    VoteCast,
    ProposalTallied,
    ProposalExecuted,
    ProposalCancelled,
    EmergencyPauseApplied,
    EmergencyResumeApplied,
}

impl GovernanceAuditEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ValidatorRegistered => "validator_registered",
            Self::ValidatorRetired => "validator_retired",
            Self::ProposalCreated => "proposal_created",
            Self::VoteCast => "vote_cast",
            Self::ProposalTallied => "proposal_tallied",
            Self::ProposalExecuted => "proposal_executed",
            Self::ProposalCancelled => "proposal_cancelled",
            Self::EmergencyPauseApplied => "emergency_pause_applied",
            Self::EmergencyResumeApplied => "emergency_resume_applied",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernancePolicy {
    pub quorum_bps: u64,
    pub approval_bps: u64,
    pub supermajority_approval_bps: u64,
    pub default_timelock_blocks: u64,
    pub upgrade_timelock_blocks: u64,
    pub emergency_timelock_blocks: u64,
    pub default_vote_window_blocks: u64,
    pub min_vote_window_blocks: u64,
    pub max_vote_window_blocks: u64,
    pub execution_window_blocks: u64,
    pub max_action_bytes: usize,
    pub min_proposal_deposit_units: u64,
}

impl Default for GovernancePolicy {
    fn default() -> Self {
        Self {
            quorum_bps: GOVERNANCE_DEFAULT_QUORUM_BPS,
            approval_bps: GOVERNANCE_DEFAULT_APPROVAL_BPS,
            supermajority_approval_bps: GOVERNANCE_SUPERMAJORITY_APPROVAL_BPS,
            default_timelock_blocks: GOVERNANCE_DEFAULT_TIMELOCK_BLOCKS,
            upgrade_timelock_blocks: GOVERNANCE_UPGRADE_TIMELOCK_BLOCKS,
            emergency_timelock_blocks: GOVERNANCE_EMERGENCY_TIMELOCK_BLOCKS,
            default_vote_window_blocks: GOVERNANCE_DEFAULT_VOTE_WINDOW_BLOCKS,
            min_vote_window_blocks: GOVERNANCE_MIN_VOTE_WINDOW_BLOCKS,
            max_vote_window_blocks: GOVERNANCE_MAX_VOTE_WINDOW_BLOCKS,
            execution_window_blocks: GOVERNANCE_EXECUTION_WINDOW_BLOCKS,
            max_action_bytes: GOVERNANCE_MAX_ACTION_BYTES,
            min_proposal_deposit_units: GOVERNANCE_MIN_PROPOSAL_DEPOSIT_UNITS,
        }
    }
}

impl GovernancePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_policy",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "supermajority_approval_bps": self.supermajority_approval_bps,
            "default_timelock_blocks": self.default_timelock_blocks,
            "upgrade_timelock_blocks": self.upgrade_timelock_blocks,
            "emergency_timelock_blocks": self.emergency_timelock_blocks,
            "default_vote_window_blocks": self.default_vote_window_blocks,
            "min_vote_window_blocks": self.min_vote_window_blocks,
            "max_vote_window_blocks": self.max_vote_window_blocks,
            "execution_window_blocks": self.execution_window_blocks,
            "max_action_bytes": self.max_action_bytes,
            "min_proposal_deposit_units": self.min_proposal_deposit_units,
        })
    }

    pub fn policy_root(&self) -> String {
        governance_policy_root(self)
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        validate_bps(self.quorum_bps, "governance quorum")?;
        validate_bps(self.approval_bps, "governance approval")?;
        validate_bps(
            self.supermajority_approval_bps,
            "governance supermajority approval",
        )?;
        if self.approval_bps == 0 {
            return Err("governance approval threshold cannot be zero".to_string());
        }
        if self.supermajority_approval_bps < self.approval_bps {
            return Err(
                "governance supermajority threshold must exceed approval threshold".to_string(),
            );
        }
        if self.min_vote_window_blocks == 0 {
            return Err("governance vote window minimum cannot be zero".to_string());
        }
        if self.default_vote_window_blocks < self.min_vote_window_blocks {
            return Err("default vote window is below minimum".to_string());
        }
        if self.default_vote_window_blocks > self.max_vote_window_blocks {
            return Err("default vote window exceeds maximum".to_string());
        }
        if self.max_action_bytes == 0 {
            return Err("governance max action bytes cannot be zero".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceValidator {
    pub validator_id: String,
    pub label: String,
    pub consensus_public_key: String,
    pub stake_weight: u64,
    pub joined_at_height: u64,
    pub retired_at_height: u64,
    pub status: String,
}

impl GovernanceValidator {
    pub fn new(label: &str, stake_weight: u64, joined_at_height: u64) -> GovernanceResult<Self> {
        if label.trim().is_empty() {
            return Err("governance validator label cannot be empty".to_string());
        }
        if stake_weight == 0 {
            return Err("governance validator stake cannot be zero".to_string());
        }
        let public_key = public_key_for_label(CryptoRole::ValidatorSignature, label).public_key;
        let validator_id = governance_validator_id(label, &public_key);
        Ok(Self {
            validator_id,
            label: label.to_string(),
            consensus_public_key: public_key,
            stake_weight,
            joined_at_height,
            retired_at_height: 0,
            status: "active".to_string(),
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == "active"
            && self.stake_weight > 0
            && self.joined_at_height <= height
            && (self.retired_at_height == 0 || height < self.retired_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_validator",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "validator_id": self.validator_id,
            "label": self.label,
            "consensus_public_key": self.consensus_public_key,
            "stake_weight": self.stake_weight,
            "joined_at_height": self.joined_at_height,
            "retired_at_height": self.retired_at_height,
            "status": self.status,
        })
    }

    pub fn validator_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-VALIDATOR",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.label.trim().is_empty() {
            return Err("governance validator label cannot be empty".to_string());
        }
        if self.consensus_public_key.trim().is_empty() {
            return Err("governance validator consensus public key cannot be empty".to_string());
        }
        let expected_public_key =
            public_key_for_label(CryptoRole::ValidatorSignature, &self.label).public_key;
        if self.consensus_public_key != expected_public_key {
            return Err("governance validator public key mismatch".to_string());
        }
        if self.stake_weight == 0 {
            return Err("governance validator stake cannot be zero".to_string());
        }
        if self.validator_id != governance_validator_id(&self.label, &self.consensus_public_key) {
            return Err("governance validator id mismatch".to_string());
        }
        if self.status != "active" && self.status != "retired" && self.status != "suspended" {
            return Err("unsupported governance validator status".to_string());
        }
        Ok(self.validator_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryPolicy {
    pub treasury_account: String,
    pub fee_asset_id: String,
    pub reserve_floor_units: u64,
    pub spend_limit_per_epoch_units: u64,
    pub grant_limit_per_proposal_units: u64,
    pub epoch_length_blocks: u64,
    pub approver_quorum_bps: u64,
    pub public_reporting: bool,
}

impl Default for TreasuryPolicy {
    fn default() -> Self {
        Self {
            treasury_account: GOVERNANCE_DEFAULT_TREASURY_ACCOUNT.to_string(),
            fee_asset_id: GOVERNANCE_DEFAULT_FEE_ASSET_ID.to_string(),
            reserve_floor_units: 1_000_000_000,
            spend_limit_per_epoch_units: 100_000_000,
            grant_limit_per_proposal_units: 25_000_000,
            epoch_length_blocks: 720,
            approver_quorum_bps: GOVERNANCE_SUPERMAJORITY_APPROVAL_BPS,
            public_reporting: true,
        }
    }
}

impl TreasuryPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "treasury_policy",
            "chain_id": CHAIN_ID,
            "treasury_account_commitment": governance_string_root("treasury_account", &self.treasury_account),
            "fee_asset_id": self.fee_asset_id,
            "reserve_floor_units": self.reserve_floor_units,
            "spend_limit_per_epoch_units": self.spend_limit_per_epoch_units,
            "grant_limit_per_proposal_units": self.grant_limit_per_proposal_units,
            "epoch_length_blocks": self.epoch_length_blocks,
            "approver_quorum_bps": self.approver_quorum_bps,
            "public_reporting": self.public_reporting,
        })
    }

    pub fn policy_root(&self) -> String {
        governance_treasury_policy_root(self)
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.treasury_account.trim().is_empty() {
            return Err("treasury account cannot be empty".to_string());
        }
        if self.fee_asset_id.trim().is_empty() {
            return Err("treasury fee asset id cannot be empty".to_string());
        }
        if self.epoch_length_blocks == 0 {
            return Err("treasury epoch length cannot be zero".to_string());
        }
        validate_bps(self.approver_quorum_bps, "treasury approver quorum")?;
        if self.grant_limit_per_proposal_units > self.spend_limit_per_epoch_units {
            return Err("treasury grant limit cannot exceed epoch spend limit".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    pub fee_asset_id: String,
    pub base_fee_micro_units: u64,
    pub priority_multiplier_bps: u64,
    pub proof_fee_per_kib_units: u64,
    pub da_fee_per_kib_units: u64,
    pub min_fee_density_microunits: u64,
    pub low_fee_rebate_bps: u64,
    pub treasury_share_bps: u64,
    pub burn_share_bps: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            fee_asset_id: GOVERNANCE_DEFAULT_FEE_ASSET_ID.to_string(),
            base_fee_micro_units: 1_000,
            priority_multiplier_bps: 12_500,
            proof_fee_per_kib_units: 500,
            da_fee_per_kib_units: 50,
            min_fee_density_microunits: 1,
            low_fee_rebate_bps: 2_500,
            treasury_share_bps: 2_000,
            burn_share_bps: 1_000,
        }
    }
}

impl FeePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_fee_policy",
            "chain_id": CHAIN_ID,
            "fee_asset_id": self.fee_asset_id,
            "base_fee_micro_units": self.base_fee_micro_units,
            "priority_multiplier_bps": self.priority_multiplier_bps,
            "proof_fee_per_kib_units": self.proof_fee_per_kib_units,
            "da_fee_per_kib_units": self.da_fee_per_kib_units,
            "min_fee_density_microunits": self.min_fee_density_microunits,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "treasury_share_bps": self.treasury_share_bps,
            "burn_share_bps": self.burn_share_bps,
        })
    }

    pub fn policy_root(&self) -> String {
        governance_fee_policy_root(self)
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.fee_asset_id.trim().is_empty() {
            return Err("fee policy asset id cannot be empty".to_string());
        }
        if self.priority_multiplier_bps == 0 {
            return Err("fee priority multiplier cannot be zero".to_string());
        }
        if self.priority_multiplier_bps > 100_000 {
            return Err("fee priority multiplier exceeds governance safety cap".to_string());
        }
        validate_bps(self.low_fee_rebate_bps, "low fee rebate")?;
        validate_bps(self.treasury_share_bps, "treasury fee share")?;
        validate_bps(self.burn_share_bps, "burn fee share")?;
        if self.treasury_share_bps.saturating_add(self.burn_share_bps) > 10_000 {
            return Err("treasury and burn fee shares exceed 100 percent".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceParameterChange {
    pub module: String,
    pub key: String,
    pub old_value: Value,
    pub new_value: Value,
    pub reason_hash: String,
}

impl GovernanceParameterChange {
    pub fn parameter_key(&self) -> String {
        governance_parameter_key(&self.module, &self.key)
    }

    pub fn change_id(&self) -> String {
        governance_parameter_change_id(
            &self.module,
            &self.key,
            &self.old_value,
            &self.new_value,
            &self.reason_hash,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_parameter_change",
            "chain_id": CHAIN_ID,
            "change_id": self.change_id(),
            "parameter_key": self.parameter_key(),
            "module": self.module,
            "key": self.key,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "reason_hash": self.reason_hash,
        })
    }

    pub fn change_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-PARAMETER-CHANGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.module.trim().is_empty() {
            return Err("parameter change module cannot be empty".to_string());
        }
        if self.key.trim().is_empty() {
            return Err("parameter change key cannot be empty".to_string());
        }
        if self.old_value == self.new_value {
            return Err("parameter change must alter the value".to_string());
        }
        if self.reason_hash.trim().is_empty() {
            return Err("parameter change reason hash cannot be empty".to_string());
        }
        Ok(self.change_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockedUpgrade {
    pub upgrade_name: String,
    pub target_version: String,
    pub artifact_root: String,
    pub manifest_root: String,
    pub migration_root: String,
    pub rollback_root: String,
    pub expected_state_root: String,
    pub activation_height: u64,
    pub min_activation_delay_blocks: u64,
    pub requires_pause: bool,
}

impl TimelockedUpgrade {
    pub fn upgrade_id(&self) -> String {
        governance_upgrade_id(
            &self.target_version,
            &self.artifact_root,
            &self.manifest_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "timelocked_upgrade",
            "chain_id": CHAIN_ID,
            "upgrade_id": self.upgrade_id(),
            "upgrade_name": self.upgrade_name,
            "target_version": self.target_version,
            "artifact_root": self.artifact_root,
            "manifest_root": self.manifest_root,
            "migration_root": self.migration_root,
            "rollback_root": self.rollback_root,
            "expected_state_root": self.expected_state_root,
            "activation_height": self.activation_height,
            "min_activation_delay_blocks": self.min_activation_delay_blocks,
            "requires_pause": self.requires_pause,
        })
    }

    pub fn upgrade_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-TIMELOCKED-UPGRADE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.upgrade_name.trim().is_empty() {
            return Err("upgrade name cannot be empty".to_string());
        }
        if self.target_version.trim().is_empty() {
            return Err("upgrade target version cannot be empty".to_string());
        }
        validate_root_like(&self.artifact_root, "upgrade artifact root")?;
        validate_root_like(&self.manifest_root, "upgrade manifest root")?;
        validate_root_like(&self.migration_root, "upgrade migration root")?;
        validate_root_like(&self.rollback_root, "upgrade rollback root")?;
        validate_root_like(&self.expected_state_root, "upgrade expected state root")?;
        if self.activation_height < self.min_activation_delay_blocks {
            return Err("upgrade activation height is below minimum delay".to_string());
        }
        Ok(self.upgrade_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPause {
    pub scopes: Vec<String>,
    pub reason_hash: String,
    pub expires_at_height: u64,
    pub requires_resume_vote: bool,
}

impl EmergencyPause {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_pause",
            "chain_id": CHAIN_ID,
            "scope_root": string_list_root("GOVERNANCE-PAUSE-SCOPE", &self.scopes),
            "scope_count": self.scopes.len() as u64,
            "scopes": normalized_strings(&self.scopes),
            "reason_hash": self.reason_hash,
            "expires_at_height": self.expires_at_height,
            "requires_resume_vote": self.requires_resume_vote,
        })
    }

    pub fn pause_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-EMERGENCY-PAUSE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        validate_scope_list(&self.scopes, GOVERNANCE_MAX_PAUSE_SCOPES, "emergency pause")?;
        if self.reason_hash.trim().is_empty() {
            return Err("emergency pause reason hash cannot be empty".to_string());
        }
        Ok(self.pause_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyResume {
    pub scopes: Vec<String>,
    pub reason_hash: String,
    pub resume_all: bool,
}

impl EmergencyResume {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_resume",
            "chain_id": CHAIN_ID,
            "scope_root": string_list_root("GOVERNANCE-RESUME-SCOPE", &self.scopes),
            "scope_count": self.scopes.len() as u64,
            "scopes": normalized_strings(&self.scopes),
            "reason_hash": self.reason_hash,
            "resume_all": self.resume_all,
        })
    }

    pub fn resume_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-EMERGENCY-RESUME",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if !self.resume_all {
            validate_scope_list(
                &self.scopes,
                GOVERNANCE_MAX_PAUSE_SCOPES,
                "emergency resume",
            )?;
        }
        if self.reason_hash.trim().is_empty() {
            return Err("emergency resume reason hash cannot be empty".to_string());
        }
        Ok(self.resume_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoMigrationStep {
    pub role: String,
    pub current_scheme: String,
    pub target_scheme: String,
    pub dual_signing_start_height: u64,
    pub activation_height: u64,
    pub deprecation_height: u64,
    pub audit_report_root: String,
}

impl CryptoMigrationStep {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "crypto_migration_step",
            "chain_id": CHAIN_ID,
            "role": self.role,
            "current_scheme": self.current_scheme,
            "target_scheme": self.target_scheme,
            "dual_signing_start_height": self.dual_signing_start_height,
            "activation_height": self.activation_height,
            "deprecation_height": self.deprecation_height,
            "audit_report_root": self.audit_report_root,
        })
    }

    pub fn step_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-CRYPTO-MIGRATION-STEP",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.role.trim().is_empty() {
            return Err("crypto migration role cannot be empty".to_string());
        }
        if self.current_scheme.trim().is_empty() {
            return Err("crypto migration current scheme cannot be empty".to_string());
        }
        if self.target_scheme.trim().is_empty() {
            return Err("crypto migration target scheme cannot be empty".to_string());
        }
        validate_root_like(
            &self.audit_report_root,
            "crypto migration audit report root",
        )?;
        if self.dual_signing_start_height > self.activation_height {
            return Err(
                "crypto migration dual-signing height exceeds activation height".to_string(),
            );
        }
        if self.activation_height > self.deprecation_height {
            return Err(
                "crypto migration activation height exceeds deprecation height".to_string(),
            );
        }
        Ok(self.step_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumCryptoMigration {
    pub migration_name: String,
    pub target_policy_version: String,
    pub migration_artifact_root: String,
    pub wallet_notice_epoch: u64,
    pub rollback_root: String,
    pub steps: Vec<CryptoMigrationStep>,
}

impl QuantumCryptoMigration {
    pub fn migration_id(&self) -> String {
        governance_crypto_migration_id(&self.target_policy_version, &self.migration_root())
    }

    pub fn step_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-CRYPTO-MIGRATION-STEP",
            &self
                .steps
                .iter()
                .map(CryptoMigrationStep::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_crypto_migration",
            "chain_id": CHAIN_ID,
            "migration_id": self.migration_id(),
            "migration_name": self.migration_name,
            "target_policy_version": self.target_policy_version,
            "migration_artifact_root": self.migration_artifact_root,
            "wallet_notice_epoch": self.wallet_notice_epoch,
            "rollback_root": self.rollback_root,
            "step_root": self.step_root(),
            "step_count": self.steps.len() as u64,
            "steps": self.steps.iter().map(CryptoMigrationStep::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn migration_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-QUANTUM-CRYPTO-MIGRATION",
            &[HashPart::Json(&json!({
                "migration_name": self.migration_name,
                "target_policy_version": self.target_policy_version,
                "migration_artifact_root": self.migration_artifact_root,
                "wallet_notice_epoch": self.wallet_notice_epoch,
                "rollback_root": self.rollback_root,
                "step_root": self.step_root(),
            }))],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.migration_name.trim().is_empty() {
            return Err("crypto migration name cannot be empty".to_string());
        }
        if self.target_policy_version.trim().is_empty() {
            return Err("crypto migration target policy version cannot be empty".to_string());
        }
        validate_root_like(
            &self.migration_artifact_root,
            "crypto migration artifact root",
        )?;
        validate_root_like(&self.rollback_root, "crypto migration rollback root")?;
        if self.steps.is_empty() {
            return Err("crypto migration requires at least one step".to_string());
        }
        if self.steps.len() > GOVERNANCE_MAX_CRYPTO_MIGRATION_STEPS {
            return Err("crypto migration has too many steps".to_string());
        }
        let mut roles = BTreeSet::new();
        for step in &self.steps {
            step.validate()?;
            if !roles.insert(step.role.clone()) {
                return Err("crypto migration role appears more than once".to_string());
            }
        }
        Ok(self.migration_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAllowlistChange {
    pub action: ContractAllowlistAction,
    pub contract_id: String,
    pub template: String,
    pub code_hash: String,
    pub allowed_entrypoints: Vec<String>,
    pub capability_root: String,
    pub reason_hash: String,
}

impl ContractAllowlistChange {
    pub fn entry_id(&self) -> String {
        governance_contract_allowlist_entry_id(&self.contract_id, &self.code_hash)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_allowlist_change",
            "chain_id": CHAIN_ID,
            "entry_id": self.entry_id(),
            "action": self.action.as_str(),
            "contract_id": self.contract_id,
            "template": self.template,
            "code_hash": self.code_hash,
            "entrypoint_root": string_list_root("GOVERNANCE-CONTRACT-ENTRYPOINT", &self.allowed_entrypoints),
            "allowed_entrypoints": normalized_strings(&self.allowed_entrypoints),
            "capability_root": self.capability_root,
            "reason_hash": self.reason_hash,
        })
    }

    pub fn change_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-CONTRACT-ALLOWLIST-CHANGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.contract_id.trim().is_empty() {
            return Err("contract allowlist contract id cannot be empty".to_string());
        }
        if self.template.trim().is_empty() {
            return Err("contract allowlist template cannot be empty".to_string());
        }
        validate_root_like(&self.code_hash, "contract allowlist code hash")?;
        validate_root_like(&self.capability_root, "contract allowlist capability root")?;
        if self.reason_hash.trim().is_empty() {
            return Err("contract allowlist reason hash cannot be empty".to_string());
        }
        if matches!(
            &self.action,
            ContractAllowlistAction::Add | ContractAllowlistAction::Resume
        ) && self.allowed_entrypoints.is_empty()
        {
            return Err("active allowlist entries require at least one entrypoint".to_string());
        }
        validate_string_list(&self.allowed_entrypoints, "contract allowlist entrypoint")?;
        Ok(self.change_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAllowlistEntry {
    pub entry_id: String,
    pub contract_id: String,
    pub template: String,
    pub code_hash: String,
    pub allowed_entrypoints: Vec<String>,
    pub capability_root: String,
    pub status: String,
    pub last_proposal_id: String,
    pub updated_at_height: u64,
}

impl ContractAllowlistEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_allowlist_entry",
            "chain_id": CHAIN_ID,
            "entry_id": self.entry_id,
            "contract_id": self.contract_id,
            "template": self.template,
            "code_hash": self.code_hash,
            "entrypoint_root": string_list_root("GOVERNANCE-CONTRACT-ENTRYPOINT", &self.allowed_entrypoints),
            "allowed_entrypoints": normalized_strings(&self.allowed_entrypoints),
            "capability_root": self.capability_root,
            "status": self.status,
            "last_proposal_id": self.last_proposal_id,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn entry_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-CONTRACT-ALLOWLIST-ENTRY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPauseRecord {
    pub pause_id: String,
    pub scope: String,
    pub reason_hash: String,
    pub proposal_id: String,
    pub paused_at_height: u64,
    pub expires_at_height: u64,
    pub requires_resume_vote: bool,
    pub status: String,
}

impl EmergencyPauseRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_pause_record",
            "chain_id": CHAIN_ID,
            "pause_id": self.pause_id,
            "scope": self.scope,
            "reason_hash": self.reason_hash,
            "proposal_id": self.proposal_id,
            "paused_at_height": self.paused_at_height,
            "expires_at_height": self.expires_at_height,
            "requires_resume_vote": self.requires_resume_vote,
            "status": self.status,
        })
    }

    pub fn pause_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-EMERGENCY-PAUSE-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceProposalAction {
    ParameterChange {
        changes: Vec<GovernanceParameterChange>,
    },
    TimelockedUpgrade {
        upgrade: TimelockedUpgrade,
    },
    EmergencyPause {
        pause: EmergencyPause,
    },
    EmergencyResume {
        resume: EmergencyResume,
    },
    TreasuryPolicyChange {
        policy: TreasuryPolicy,
    },
    FeePolicyChange {
        policy: FeePolicy,
    },
    QuantumCryptoMigration {
        migration: QuantumCryptoMigration,
    },
    ContractAllowlistChange {
        changes: Vec<ContractAllowlistChange>,
    },
}

impl GovernanceProposalAction {
    pub fn kind(&self) -> GovernanceProposalKind {
        match self {
            Self::ParameterChange { .. } => GovernanceProposalKind::ParameterChange,
            Self::TimelockedUpgrade { .. } => GovernanceProposalKind::TimelockedUpgrade,
            Self::EmergencyPause { .. } => GovernanceProposalKind::EmergencyPause,
            Self::EmergencyResume { .. } => GovernanceProposalKind::EmergencyResume,
            Self::TreasuryPolicyChange { .. } => GovernanceProposalKind::TreasuryPolicyChange,
            Self::FeePolicyChange { .. } => GovernanceProposalKind::FeePolicyChange,
            Self::QuantumCryptoMigration { .. } => GovernanceProposalKind::QuantumCryptoMigration,
            Self::ContractAllowlistChange { .. } => GovernanceProposalKind::ContractAllowlistChange,
        }
    }

    pub fn approval_bps(&self, policy: &GovernancePolicy) -> u64 {
        if self.kind().requires_supermajority() {
            policy.supermajority_approval_bps
        } else {
            policy.approval_bps
        }
    }

    pub fn timelock_blocks(&self, policy: &GovernancePolicy) -> u64 {
        match self {
            Self::TimelockedUpgrade { upgrade } => std::cmp::max(
                policy.upgrade_timelock_blocks,
                upgrade.min_activation_delay_blocks,
            ),
            Self::QuantumCryptoMigration { .. } => policy.upgrade_timelock_blocks,
            Self::EmergencyPause { .. } | Self::EmergencyResume { .. } => {
                policy.emergency_timelock_blocks
            }
            _ => policy.default_timelock_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        match self {
            Self::ParameterChange { changes } => json!({
                "kind": GovernanceProposalKind::ParameterChange.as_str(),
                "change_root": merkle_root(
                    "GOVERNANCE-PARAMETER-CHANGE",
                    &changes.iter().map(GovernanceParameterChange::public_record).collect::<Vec<_>>(),
                ),
                "change_count": changes.len() as u64,
                "changes": changes.iter().map(GovernanceParameterChange::public_record).collect::<Vec<_>>(),
            }),
            Self::TimelockedUpgrade { upgrade } => json!({
                "kind": GovernanceProposalKind::TimelockedUpgrade.as_str(),
                "upgrade": upgrade.public_record(),
            }),
            Self::EmergencyPause { pause } => json!({
                "kind": GovernanceProposalKind::EmergencyPause.as_str(),
                "pause": pause.public_record(),
            }),
            Self::EmergencyResume { resume } => json!({
                "kind": GovernanceProposalKind::EmergencyResume.as_str(),
                "resume": resume.public_record(),
            }),
            Self::TreasuryPolicyChange { policy } => json!({
                "kind": GovernanceProposalKind::TreasuryPolicyChange.as_str(),
                "policy": policy.public_record(),
            }),
            Self::FeePolicyChange { policy } => json!({
                "kind": GovernanceProposalKind::FeePolicyChange.as_str(),
                "policy": policy.public_record(),
            }),
            Self::QuantumCryptoMigration { migration } => json!({
                "kind": GovernanceProposalKind::QuantumCryptoMigration.as_str(),
                "migration": migration.public_record(),
            }),
            Self::ContractAllowlistChange { changes } => json!({
                "kind": GovernanceProposalKind::ContractAllowlistChange.as_str(),
                "change_root": merkle_root(
                    "GOVERNANCE-CONTRACT-ALLOWLIST-CHANGE",
                    &changes.iter().map(ContractAllowlistChange::public_record).collect::<Vec<_>>(),
                ),
                "change_count": changes.len() as u64,
                "changes": changes.iter().map(ContractAllowlistChange::public_record).collect::<Vec<_>>(),
            }),
        }
    }

    pub fn action_root(&self) -> String {
        governance_action_root(self)
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        match self {
            Self::ParameterChange { changes } => {
                if changes.is_empty() {
                    return Err("parameter proposal requires at least one change".to_string());
                }
                if changes.len() > GOVERNANCE_MAX_PARAMETER_CHANGES {
                    return Err("parameter proposal has too many changes".to_string());
                }
                let mut keys = BTreeSet::new();
                for change in changes {
                    change.validate()?;
                    if !keys.insert(change.parameter_key()) {
                        return Err(
                            "parameter proposal changes the same key more than once".to_string()
                        );
                    }
                }
            }
            Self::TimelockedUpgrade { upgrade } => {
                upgrade.validate()?;
            }
            Self::EmergencyPause { pause } => {
                pause.validate()?;
            }
            Self::EmergencyResume { resume } => {
                resume.validate()?;
            }
            Self::TreasuryPolicyChange { policy } => {
                policy.validate()?;
            }
            Self::FeePolicyChange { policy } => {
                policy.validate()?;
            }
            Self::QuantumCryptoMigration { migration } => {
                migration.validate()?;
            }
            Self::ContractAllowlistChange { changes } => {
                if changes.is_empty() {
                    return Err(
                        "contract allowlist proposal requires at least one change".to_string()
                    );
                }
                if changes.len() > GOVERNANCE_MAX_ALLOWLIST_CHANGES {
                    return Err("contract allowlist proposal has too many changes".to_string());
                }
                let mut entries = BTreeSet::new();
                for change in changes {
                    change.validate()?;
                    if !entries.insert(change.entry_id()) {
                        return Err(
                            "contract allowlist proposal touches an entry more than once"
                                .to_string(),
                        );
                    }
                }
            }
        }
        Ok(self.action_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_id: String,
    pub proposal_nonce: u64,
    pub proposer_label: String,
    pub proposer_public_key: String,
    pub proposer_commitment: String,
    pub title: String,
    pub summary_hash: String,
    pub action: GovernanceProposalAction,
    pub action_root: String,
    pub created_at_height: u64,
    pub voting_start_height: u64,
    pub voting_end_height: u64,
    pub timelock_blocks: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub quorum_bps: u64,
    pub approval_bps: u64,
    pub deposit_units: u64,
    pub status: String,
    pub vote_root: String,
    pub execution_root: String,
    pub authorization: Authorization,
}

impl GovernanceProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_nonce: u64,
        proposer_label: &str,
        title: &str,
        summary_hash: &str,
        action: GovernanceProposalAction,
        created_at_height: u64,
        vote_window_blocks: u64,
        policy: &GovernancePolicy,
    ) -> GovernanceResult<Self> {
        policy.validate()?;
        action.validate()?;
        if proposer_label.trim().is_empty() {
            return Err("governance proposer label cannot be empty".to_string());
        }
        if title.trim().is_empty() {
            return Err("governance proposal title cannot be empty".to_string());
        }
        if summary_hash.trim().is_empty() {
            return Err("governance proposal summary hash cannot be empty".to_string());
        }
        if vote_window_blocks < policy.min_vote_window_blocks {
            return Err("governance proposal vote window is below minimum".to_string());
        }
        if vote_window_blocks > policy.max_vote_window_blocks {
            return Err("governance proposal vote window exceeds maximum".to_string());
        }
        let action_size = json_size(&action.public_record());
        if action_size > policy.max_action_bytes {
            return Err("governance proposal action exceeds size limit".to_string());
        }
        let proposer_key = public_key_for_label(CryptoRole::ValidatorSignature, proposer_label);
        let proposer_commitment = governance_actor_commitment(proposer_label);
        let action_root = action.action_root();
        let timelock_blocks = action.timelock_blocks(policy);
        let voting_start_height = created_at_height;
        let voting_end_height = created_at_height.saturating_add(vote_window_blocks);
        let executable_at_height = voting_end_height.saturating_add(timelock_blocks);
        let expires_at_height = executable_at_height.saturating_add(policy.execution_window_blocks);
        let proposal_id = governance_proposal_id(
            proposal_nonce,
            &proposer_commitment,
            action.kind().as_str(),
            &action_root,
        );
        let approval_bps = action.approval_bps(policy);
        let mut proposal = Self {
            proposal_id,
            proposal_nonce,
            proposer_label: proposer_label.to_string(),
            proposer_public_key: proposer_key.public_key,
            proposer_commitment,
            title: title.to_string(),
            summary_hash: summary_hash.to_string(),
            action,
            action_root,
            created_at_height,
            voting_start_height,
            voting_end_height,
            timelock_blocks,
            executable_at_height,
            expires_at_height,
            quorum_bps: policy.quorum_bps,
            approval_bps,
            deposit_units: policy.min_proposal_deposit_units,
            status: "voting".to_string(),
            vote_root: governance_empty_root("GOVERNANCE-PROPOSAL-VOTE"),
            execution_root: governance_empty_root("GOVERNANCE-PROPOSAL-EXECUTION"),
            authorization: empty_governance_authorization(proposer_label),
        };
        proposal.authorization = sign_validator_authorization(
            proposer_label,
            "governance_proposal",
            &proposal.signed_payload(),
        );
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn kind(&self) -> GovernanceProposalKind {
        self.action.kind()
    }

    pub fn signed_payload(&self) -> Value {
        json!({
            "kind": "governance_proposal",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "proposal_id": self.proposal_id,
            "proposal_nonce": self.proposal_nonce,
            "proposal_kind": self.kind().as_str(),
            "proposer_label": self.proposer_label,
            "proposer_public_key": self.proposer_public_key,
            "proposer_commitment": self.proposer_commitment,
            "title": self.title,
            "summary_hash": self.summary_hash,
            "action_root": self.action_root,
            "created_at_height": self.created_at_height,
            "voting_start_height": self.voting_start_height,
            "voting_end_height": self.voting_end_height,
            "timelock_blocks": self.timelock_blocks,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "deposit_units": self.deposit_units,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "governance_proposal",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "proposal_id": self.proposal_id,
            "proposal_nonce": self.proposal_nonce,
            "proposal_kind": self.kind().as_str(),
            "proposer_label": self.proposer_label,
            "proposer_public_key": self.proposer_public_key,
            "proposer_commitment": self.proposer_commitment,
            "title": self.title,
            "summary_hash": self.summary_hash,
            "action_root": self.action_root,
            "action": self.action.public_record(),
            "created_at_height": self.created_at_height,
            "voting_start_height": self.voting_start_height,
            "voting_end_height": self.voting_end_height,
            "timelock_blocks": self.timelock_blocks,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "deposit_units": self.deposit_units,
            "status": self.status,
            "vote_root": self.vote_root,
            "execution_root": self.execution_root,
            "auth_scheme": self.authorization.auth_scheme,
            "auth_public_key": self.authorization.auth_public_key,
            "auth_transcript_hash": self.authorization.auth_transcript_hash,
            "auth_signature": self.authorization.auth_signature,
        })
    }

    pub fn proposal_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-PROPOSAL",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("governance proposal record object")
            .insert(
                "proposal_root".to_string(),
                Value::String(self.proposal_root()),
            );
        record
    }

    pub fn is_voting_open_at(&self, height: u64) -> bool {
        self.status == "voting"
            && self.voting_start_height <= height
            && height <= self.voting_end_height
    }

    pub fn is_executable_at(&self, height: u64) -> bool {
        (self.status == "queued" || self.status == "approved")
            && self.executable_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn verify_authorization(&self) -> bool {
        verify_validator_authorization(
            &self.proposer_public_key,
            "governance_proposal",
            &self.signed_payload(),
            &self.authorization,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        self.action.validate()?;
        if self.proposal_id
            != governance_proposal_id(
                self.proposal_nonce,
                &self.proposer_commitment,
                self.kind().as_str(),
                &self.action_root,
            )
        {
            return Err("governance proposal id mismatch".to_string());
        }
        if self.action_root != self.action.action_root() {
            return Err("governance proposal action root mismatch".to_string());
        }
        if self.proposer_label.trim().is_empty() {
            return Err("governance proposal proposer cannot be empty".to_string());
        }
        if self.proposer_public_key.trim().is_empty() {
            return Err("governance proposal proposer public key cannot be empty".to_string());
        }
        if self.proposer_commitment != governance_actor_commitment(&self.proposer_label) {
            return Err("governance proposal proposer commitment mismatch".to_string());
        }
        if self.title.trim().is_empty() {
            return Err("governance proposal title cannot be empty".to_string());
        }
        if self.summary_hash.trim().is_empty() {
            return Err("governance proposal summary hash cannot be empty".to_string());
        }
        if self.voting_end_height < self.voting_start_height {
            return Err("governance proposal voting window is inverted".to_string());
        }
        if self.executable_at_height < self.voting_end_height {
            return Err("governance proposal executable height precedes vote end".to_string());
        }
        if self.expires_at_height < self.executable_at_height {
            return Err("governance proposal expiry precedes executable height".to_string());
        }
        validate_bps(self.quorum_bps, "governance proposal quorum")?;
        validate_bps(self.approval_bps, "governance proposal approval")?;
        if !self.verify_authorization() {
            return Err("governance proposal authorization failed".to_string());
        }
        Ok(self.proposal_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceVote {
    pub vote_id: String,
    pub proposal_id: String,
    pub action_root: String,
    pub validator_id: String,
    pub validator_label: String,
    pub consensus_public_key: String,
    pub stake_weight: u64,
    pub choice: GovernanceVoteChoice,
    pub rationale_hash: String,
    pub voted_at_height: u64,
    pub authorization: Authorization,
}

impl GovernanceVote {
    pub fn new(
        proposal: &GovernanceProposal,
        validator: &GovernanceValidator,
        choice: GovernanceVoteChoice,
        rationale_hash: &str,
        voted_at_height: u64,
    ) -> GovernanceResult<Self> {
        if !validator.is_active_at(voted_at_height) {
            return Err("validator is not active for governance vote".to_string());
        }
        if !proposal.is_voting_open_at(voted_at_height) {
            return Err("governance proposal is not open for voting".to_string());
        }
        let vote_id = governance_vote_id(
            &proposal.proposal_id,
            &validator.validator_id,
            choice.as_str(),
        );
        let mut vote = Self {
            vote_id,
            proposal_id: proposal.proposal_id.clone(),
            action_root: proposal.action_root.clone(),
            validator_id: validator.validator_id.clone(),
            validator_label: validator.label.clone(),
            consensus_public_key: validator.consensus_public_key.clone(),
            stake_weight: validator.stake_weight,
            choice,
            rationale_hash: rationale_hash.to_string(),
            voted_at_height,
            authorization: empty_governance_authorization(&validator.label),
        };
        vote.authorization = sign_validator_authorization(
            &validator.label,
            "governance_vote",
            &vote.signed_payload(),
        );
        vote.validate()?;
        Ok(vote)
    }

    pub fn signed_payload(&self) -> Value {
        json!({
            "kind": "governance_vote",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "action_root": self.action_root,
            "validator_id": self.validator_id,
            "validator_label": self.validator_label,
            "consensus_public_key": self.consensus_public_key,
            "stake_weight": self.stake_weight,
            "choice": self.choice.as_str(),
            "rationale_hash": self.rationale_hash,
            "voted_at_height": self.voted_at_height,
        })
    }

    pub fn vote_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-VOTE",
            &[HashPart::Json(&self.signed_payload())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_vote",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "vote_id": self.vote_id,
            "vote_root": self.vote_root(),
            "proposal_id": self.proposal_id,
            "action_root": self.action_root,
            "validator_id": self.validator_id,
            "validator_label": self.validator_label,
            "consensus_public_key": self.consensus_public_key,
            "stake_weight": self.stake_weight,
            "choice": self.choice.as_str(),
            "rationale_hash": self.rationale_hash,
            "voted_at_height": self.voted_at_height,
            "auth_scheme": self.authorization.auth_scheme,
            "auth_public_key": self.authorization.auth_public_key,
            "auth_transcript_hash": self.authorization.auth_transcript_hash,
            "auth_signature": self.authorization.auth_signature,
        })
    }

    pub fn verify_authorization(&self) -> bool {
        verify_validator_authorization(
            &self.consensus_public_key,
            "governance_vote",
            &self.signed_payload(),
            &self.authorization,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.vote_id
            != governance_vote_id(&self.proposal_id, &self.validator_id, self.choice.as_str())
        {
            return Err("governance vote id mismatch".to_string());
        }
        if self.proposal_id.trim().is_empty() {
            return Err("governance vote proposal id cannot be empty".to_string());
        }
        if self.action_root.trim().is_empty() {
            return Err("governance vote action root cannot be empty".to_string());
        }
        if self.validator_id.trim().is_empty() {
            return Err("governance vote validator id cannot be empty".to_string());
        }
        if self.consensus_public_key.trim().is_empty() {
            return Err("governance vote consensus public key cannot be empty".to_string());
        }
        if self.stake_weight == 0 {
            return Err("governance vote stake cannot be zero".to_string());
        }
        if !self.verify_authorization() {
            return Err("governance vote authorization failed".to_string());
        }
        Ok(self.vote_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceVoteTally {
    pub tally_id: String,
    pub proposal_id: String,
    pub action_root: String,
    pub total_active_stake: u64,
    pub participating_stake: u64,
    pub approve_stake: u64,
    pub reject_stake: u64,
    pub abstain_stake: u64,
    pub quorum_stake: u64,
    pub approval_stake: u64,
    pub quorum_bps: u64,
    pub approval_bps: u64,
    pub quorum_met: bool,
    pub approved: bool,
    pub vote_root: String,
    pub voter_root: String,
    pub voter_count: u64,
    pub tallied_at_height: u64,
    pub status: String,
}

impl GovernanceVoteTally {
    pub fn from_votes(
        proposal: &GovernanceProposal,
        validators: &BTreeMap<String, GovernanceValidator>,
        votes: &[GovernanceVote],
        tallied_at_height: u64,
    ) -> GovernanceResult<Self> {
        let total_active_stake = validators
            .values()
            .filter(|validator| validator.is_active_at(tallied_at_height))
            .map(|validator| validator.stake_weight)
            .sum::<u64>();
        if total_active_stake == 0 {
            return Err("cannot tally governance proposal without active stake".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut voters = Vec::new();
        let mut approve_stake = 0_u64;
        let mut reject_stake = 0_u64;
        let mut abstain_stake = 0_u64;
        for vote in votes
            .iter()
            .filter(|vote| vote.proposal_id == proposal.proposal_id)
        {
            vote.validate()?;
            if vote.action_root != proposal.action_root {
                return Err("governance vote action root mismatch".to_string());
            }
            let validator = validators
                .get(&vote.validator_id)
                .ok_or_else(|| "governance vote references unknown validator".to_string())?;
            if !validator.is_active_at(vote.voted_at_height) {
                return Err("governance vote validator was inactive".to_string());
            }
            if validator.consensus_public_key != vote.consensus_public_key {
                return Err("governance vote consensus public key mismatch".to_string());
            }
            if !seen.insert(vote.validator_id.clone()) {
                return Err("governance validator voted more than once".to_string());
            }
            voters.push(vote.validator_id.clone());
            match &vote.choice {
                GovernanceVoteChoice::Approve => {
                    approve_stake = approve_stake.saturating_add(validator.stake_weight)
                }
                GovernanceVoteChoice::Reject => {
                    reject_stake = reject_stake.saturating_add(validator.stake_weight)
                }
                GovernanceVoteChoice::Abstain => {
                    abstain_stake = abstain_stake.saturating_add(validator.stake_weight)
                }
            }
        }
        voters.sort();
        let participating_stake = approve_stake
            .saturating_add(reject_stake)
            .saturating_add(abstain_stake);
        let quorum_stake = bps_threshold(total_active_stake, proposal.quorum_bps);
        let decision_stake = approve_stake.saturating_add(reject_stake);
        let approval_stake = bps_threshold(decision_stake, proposal.approval_bps);
        let quorum_met = participating_stake >= quorum_stake;
        let approved = quorum_met && decision_stake > 0 && approve_stake >= approval_stake;
        let vote_root = governance_vote_root(votes, &proposal.proposal_id);
        let voter_root = string_list_root("GOVERNANCE-TALLY-VOTER", &voters);
        let tally_id = governance_tally_id(&proposal.proposal_id, &vote_root, tallied_at_height);
        let status = if approved { "approved" } else { "rejected" }.to_string();
        Ok(Self {
            tally_id,
            proposal_id: proposal.proposal_id.clone(),
            action_root: proposal.action_root.clone(),
            total_active_stake,
            participating_stake,
            approve_stake,
            reject_stake,
            abstain_stake,
            quorum_stake,
            approval_stake,
            quorum_bps: proposal.quorum_bps,
            approval_bps: proposal.approval_bps,
            quorum_met,
            approved,
            vote_root,
            voter_root,
            voter_count: voters.len() as u64,
            tallied_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_vote_tally",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "tally_id": self.tally_id,
            "proposal_id": self.proposal_id,
            "action_root": self.action_root,
            "total_active_stake": self.total_active_stake,
            "participating_stake": self.participating_stake,
            "approve_stake": self.approve_stake,
            "reject_stake": self.reject_stake,
            "abstain_stake": self.abstain_stake,
            "quorum_stake": self.quorum_stake,
            "approval_stake": self.approval_stake,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "quorum_met": self.quorum_met,
            "approved": self.approved,
            "vote_root": self.vote_root,
            "voter_root": self.voter_root,
            "voter_count": self.voter_count,
            "tallied_at_height": self.tallied_at_height,
            "status": self.status,
        })
    }

    pub fn tally_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-VOTE-TALLY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.tally_id
            != governance_tally_id(&self.proposal_id, &self.vote_root, self.tallied_at_height)
        {
            return Err("governance tally id mismatch".to_string());
        }
        if self.total_active_stake == 0 {
            return Err("governance tally has no active stake".to_string());
        }
        if self.participating_stake > self.total_active_stake {
            return Err("governance tally participating stake exceeds active stake".to_string());
        }
        Ok(self.tally_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceExecution {
    pub execution_id: String,
    pub proposal_id: String,
    pub proposal_kind: String,
    pub action_root: String,
    pub executor_label: String,
    pub executor_commitment: String,
    pub executed_at_height: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub applied_record_root: String,
    pub status: String,
}

impl GovernanceExecution {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_execution",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "execution_id": self.execution_id,
            "proposal_id": self.proposal_id,
            "proposal_kind": self.proposal_kind,
            "action_root": self.action_root,
            "executor_label": self.executor_label,
            "executor_commitment": self.executor_commitment,
            "executed_at_height": self.executed_at_height,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "applied_record_root": self.applied_record_root,
            "status": self.status,
        })
    }

    pub fn execution_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-EXECUTION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceAuditEvent {
    pub event_id: String,
    pub event_index: u64,
    pub event_kind: GovernanceAuditEventKind,
    pub actor_label: String,
    pub actor_commitment: String,
    pub proposal_id: String,
    pub details_root: String,
    pub details: Value,
    pub previous_state_root: String,
    pub new_state_root: String,
    pub emitted_at_height: u64,
    pub emitted_at_ms: u64,
    pub previous_event_root: String,
    pub event_chain_root: String,
}

impl GovernanceAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_index: u64,
        event_kind: GovernanceAuditEventKind,
        actor_label: &str,
        proposal_id: &str,
        details: Value,
        previous_state_root: &str,
        new_state_root: &str,
        emitted_at_height: u64,
        previous_event_root: &str,
    ) -> Self {
        let details_root = governance_payload_root("GOVERNANCE-AUDIT-DETAILS", &details);
        let actor_commitment = governance_actor_commitment(actor_label);
        let event_id = governance_audit_event_id(
            event_index,
            event_kind.as_str(),
            proposal_id,
            &details_root,
            previous_event_root,
        );
        let event_chain_root = domain_hash(
            "GOVERNANCE-AUDIT-EVENT-CHAIN",
            &[
                HashPart::Str(&event_id),
                HashPart::Str(previous_event_root),
                HashPart::Str(new_state_root),
            ],
            32,
        );
        Self {
            event_id,
            event_index,
            event_kind,
            actor_label: actor_label.to_string(),
            actor_commitment,
            proposal_id: proposal_id.to_string(),
            details_root,
            details,
            previous_state_root: previous_state_root.to_string(),
            new_state_root: new_state_root.to_string(),
            emitted_at_height,
            emitted_at_ms: emitted_at_height.saturating_mul(TARGET_BLOCK_MS),
            previous_event_root: previous_event_root.to_string(),
            event_chain_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_audit_event",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_index": self.event_index,
            "event_kind": self.event_kind.as_str(),
            "actor_label": self.actor_label,
            "actor_commitment": self.actor_commitment,
            "proposal_id": self.proposal_id,
            "details_root": self.details_root,
            "details": self.details,
            "previous_state_root": self.previous_state_root,
            "new_state_root": self.new_state_root,
            "emitted_at_height": self.emitted_at_height,
            "emitted_at_ms": self.emitted_at_ms,
            "previous_event_root": self.previous_event_root,
            "event_chain_root": self.event_chain_root,
        })
    }

    pub fn event_root(&self) -> String {
        domain_hash(
            "GOVERNANCE-AUDIT-EVENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        if self.event_id
            != governance_audit_event_id(
                self.event_index,
                self.event_kind.as_str(),
                &self.proposal_id,
                &self.details_root,
                &self.previous_event_root,
            )
        {
            return Err("governance audit event id mismatch".to_string());
        }
        Ok(self.event_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceState {
    pub policy: GovernancePolicy,
    pub validators: BTreeMap<String, GovernanceValidator>,
    pub proposals: BTreeMap<String, GovernanceProposal>,
    pub votes: BTreeMap<String, GovernanceVote>,
    pub tallies: BTreeMap<String, GovernanceVoteTally>,
    pub executions: BTreeMap<String, GovernanceExecution>,
    pub parameters: BTreeMap<String, Value>,
    pub treasury_policy: TreasuryPolicy,
    pub fee_policy: FeePolicy,
    pub timelocked_upgrades: BTreeMap<String, TimelockedUpgrade>,
    pub crypto_migrations: BTreeMap<String, QuantumCryptoMigration>,
    pub contract_allowlist: BTreeMap<String, ContractAllowlistEntry>,
    pub active_pauses: BTreeMap<String, EmergencyPauseRecord>,
    pub audit_events: BTreeMap<String, GovernanceAuditEvent>,
    pub last_audit_event_root: String,
    pub height: u64,
    pub next_proposal_nonce: u64,
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self {
            policy: GovernancePolicy::default(),
            validators: BTreeMap::new(),
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
            tallies: BTreeMap::new(),
            executions: BTreeMap::new(),
            parameters: BTreeMap::new(),
            treasury_policy: TreasuryPolicy::default(),
            fee_policy: FeePolicy::default(),
            timelocked_upgrades: BTreeMap::new(),
            crypto_migrations: BTreeMap::new(),
            contract_allowlist: BTreeMap::new(),
            active_pauses: BTreeMap::new(),
            audit_events: BTreeMap::new(),
            last_audit_event_root: governance_empty_root("GOVERNANCE-AUDIT-EVENT"),
            height: 0,
            next_proposal_nonce: 0,
        }
    }
}

impl GovernanceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn at_height(height: u64) -> Self {
        Self {
            height,
            ..Self::default()
        }
    }

    pub fn set_height(&mut self, height: u64) -> GovernanceResult<String> {
        if height < self.height {
            return Err("governance height cannot move backward".to_string());
        }
        self.height = height;
        Ok(self.state_root())
    }

    pub fn insert_validator(&mut self, validator: GovernanceValidator) -> GovernanceResult<String> {
        if self.validators.len() >= GOVERNANCE_MAX_VALIDATORS {
            return Err("governance validator set is full".to_string());
        }
        validator.validate()?;
        if self.validators.contains_key(&validator.validator_id) {
            return Err("governance validator already exists".to_string());
        }
        let state_root_before = self.state_root();
        let validator_id = validator.validator_id.clone();
        let actor = validator.label.clone();
        self.validators.insert(validator_id.clone(), validator);
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::ValidatorRegistered,
            &actor,
            "",
            json!({ "validator_id": validator_id }),
            &state_root_before,
            &state_root_after,
        );
        Ok(validator_id)
    }

    pub fn retire_validator(
        &mut self,
        validator_id: &str,
        retired_at_height: u64,
    ) -> GovernanceResult<String> {
        let state_root_before = self.state_root();
        let validator = self
            .validators
            .get_mut(validator_id)
            .ok_or_else(|| "unknown governance validator".to_string())?;
        if retired_at_height < validator.joined_at_height {
            return Err("governance validator retirement precedes join height".to_string());
        }
        validator.status = "retired".to_string();
        validator.retired_at_height = retired_at_height;
        let actor = validator.label.clone();
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::ValidatorRetired,
            &actor,
            "",
            json!({ "validator_id": validator_id, "retired_at_height": retired_at_height }),
            &state_root_before,
            &state_root_after,
        );
        Ok(validator_id.to_string())
    }

    pub fn create_proposal(
        &mut self,
        proposer_label: &str,
        title: &str,
        summary_hash: &str,
        action: GovernanceProposalAction,
        vote_window_blocks: u64,
    ) -> GovernanceResult<GovernanceProposal> {
        let proposal = GovernanceProposal::new(
            self.next_proposal_nonce,
            proposer_label,
            title,
            summary_hash,
            action,
            self.height,
            vote_window_blocks,
            &self.policy,
        )?;
        self.next_proposal_nonce = self.next_proposal_nonce.saturating_add(1);
        self.insert_proposal(proposal.clone())?;
        Ok(proposal)
    }

    pub fn insert_proposal(&mut self, proposal: GovernanceProposal) -> GovernanceResult<String> {
        proposal.validate()?;
        if self.proposals.contains_key(&proposal.proposal_id) {
            return Err("governance proposal already exists".to_string());
        }
        if !self.validators.is_empty() {
            let proposer_is_active = self.validators.values().any(|validator| {
                validator.consensus_public_key == proposal.proposer_public_key
                    && validator.is_active_at(proposal.created_at_height)
            });
            if !proposer_is_active {
                return Err("governance proposal proposer is not an active validator".to_string());
            }
        }
        if json_size(&proposal.action.public_record()) > self.policy.max_action_bytes {
            return Err("governance proposal action exceeds size limit".to_string());
        }
        let state_root_before = self.state_root();
        let proposal_id = proposal.proposal_id.clone();
        let proposer_label = proposal.proposer_label.clone();
        self.proposals.insert(proposal_id.clone(), proposal);
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::ProposalCreated,
            &proposer_label,
            &proposal_id,
            json!({ "proposal_id": proposal_id, "proposal_root": self.proposal_root() }),
            &state_root_before,
            &state_root_after,
        );
        Ok(proposal_id)
    }

    pub fn cast_vote(&mut self, vote: GovernanceVote) -> GovernanceResult<String> {
        vote.validate()?;
        let proposal = self
            .proposals
            .get(&vote.proposal_id)
            .ok_or_else(|| "unknown governance proposal".to_string())?;
        if !proposal.is_voting_open_at(vote.voted_at_height) {
            return Err("governance proposal is not open for voting".to_string());
        }
        if proposal.action_root != vote.action_root {
            return Err("governance vote action root mismatch".to_string());
        }
        let validator = self
            .validators
            .get(&vote.validator_id)
            .ok_or_else(|| "unknown governance vote validator".to_string())?;
        if !validator.is_active_at(vote.voted_at_height) {
            return Err("governance vote validator is inactive".to_string());
        }
        if validator.consensus_public_key != vote.consensus_public_key {
            return Err("governance vote validator public key mismatch".to_string());
        }
        let duplicate = self.votes.values().any(|existing| {
            existing.proposal_id == vote.proposal_id && existing.validator_id == vote.validator_id
        });
        if duplicate {
            return Err("governance validator already voted on proposal".to_string());
        }
        let state_root_before = self.state_root();
        let vote_id = vote.vote_id.clone();
        let proposal_id = vote.proposal_id.clone();
        let voter_label = vote.validator_label.clone();
        self.votes.insert(vote_id.clone(), vote);
        let vote_root = self.vote_root_for_proposal(&proposal_id);
        if let Some(proposal) = self.proposals.get_mut(&proposal_id) {
            proposal.vote_root = vote_root;
        }
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::VoteCast,
            &voter_label,
            &proposal_id,
            json!({ "vote_id": vote_id, "vote_root": self.vote_root_for_proposal(&proposal_id) }),
            &state_root_before,
            &state_root_after,
        );
        Ok(vote_id)
    }

    pub fn vote_with_validator(
        &mut self,
        proposal_id: &str,
        validator_id: &str,
        choice: GovernanceVoteChoice,
        rationale_hash: &str,
    ) -> GovernanceResult<String> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "unknown governance proposal".to_string())?
            .clone();
        let validator = self
            .validators
            .get(validator_id)
            .ok_or_else(|| "unknown governance validator".to_string())?
            .clone();
        let vote = GovernanceVote::new(&proposal, &validator, choice, rationale_hash, self.height)?;
        self.cast_vote(vote)
    }

    pub fn tally_proposal(&mut self, proposal_id: &str) -> GovernanceResult<GovernanceVoteTally> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "unknown governance proposal".to_string())?
            .clone();
        if self.height < proposal.voting_end_height {
            return Err("governance proposal voting window is still open".to_string());
        }
        if proposal.status != "voting"
            && proposal.status != "approved"
            && proposal.status != "queued"
        {
            return Err("governance proposal cannot be tallied from current status".to_string());
        }
        let proposal_votes = self
            .votes
            .values()
            .filter(|vote| vote.proposal_id == proposal_id)
            .cloned()
            .collect::<Vec<_>>();
        let tally = GovernanceVoteTally::from_votes(
            &proposal,
            &self.validators,
            &proposal_votes,
            self.height,
        )?;
        tally.validate()?;
        let state_root_before = self.state_root();
        let tally_id = tally.tally_id.clone();
        self.tallies.insert(proposal_id.to_string(), tally.clone());
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.vote_root = tally.vote_root.clone();
            proposal.status = if tally.approved {
                "queued".to_string()
            } else {
                "rejected".to_string()
            };
        }
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::ProposalTallied,
            "governance_tally",
            proposal_id,
            json!({ "tally_id": tally_id, "approved": tally.approved }),
            &state_root_before,
            &state_root_after,
        );
        Ok(tally)
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        executor_label: &str,
    ) -> GovernanceResult<String> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "unknown governance proposal".to_string())?
            .clone();
        if !proposal.is_executable_at(self.height) {
            return Err("governance proposal is not executable at current height".to_string());
        }
        let tally = self
            .tallies
            .get(proposal_id)
            .ok_or_else(|| "governance proposal has not been tallied".to_string())?;
        if !tally.approved {
            return Err("cannot execute rejected governance proposal".to_string());
        }
        let state_root_before = self.state_root();
        let applied_record = self.apply_proposal_action(proposal_id, &proposal.action)?;
        let applied_record_root =
            governance_payload_root("GOVERNANCE-APPLIED-ACTION", &applied_record);
        let state_root_after_action = self.state_root();
        let execution_id = governance_execution_id(
            proposal_id,
            &proposal.action_root,
            self.height,
            &state_root_before,
            &state_root_after_action,
        );
        let execution = GovernanceExecution {
            execution_id: execution_id.clone(),
            proposal_id: proposal_id.to_string(),
            proposal_kind: proposal.kind().as_str().to_string(),
            action_root: proposal.action_root.clone(),
            executor_label: executor_label.to_string(),
            executor_commitment: governance_actor_commitment(executor_label),
            executed_at_height: self.height,
            state_root_before: state_root_before.clone(),
            state_root_after: state_root_after_action.clone(),
            applied_record_root,
            status: "executed".to_string(),
        };
        let execution_root = execution.execution_root();
        self.executions.insert(execution_id.clone(), execution);
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = "executed".to_string();
            proposal.execution_root = execution_root;
        }
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::ProposalExecuted,
            executor_label,
            proposal_id,
            json!({ "execution_id": execution_id, "applied_record": applied_record }),
            &state_root_before,
            &state_root_after,
        );
        Ok(execution_id)
    }

    pub fn cancel_proposal(
        &mut self,
        proposal_id: &str,
        actor_label: &str,
        reason_hash: &str,
    ) -> GovernanceResult<String> {
        if reason_hash.trim().is_empty() {
            return Err("governance cancel reason hash cannot be empty".to_string());
        }
        let state_root_before = self.state_root();
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "unknown governance proposal".to_string())?;
        if proposal.status == "executed" {
            return Err("cannot cancel executed governance proposal".to_string());
        }
        proposal.status = "cancelled".to_string();
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::ProposalCancelled,
            actor_label,
            proposal_id,
            json!({ "proposal_id": proposal_id, "reason_hash": reason_hash }),
            &state_root_before,
            &state_root_after,
        );
        Ok(proposal_id.to_string())
    }

    pub fn emergency_pause(
        &mut self,
        actor_label: &str,
        pause: EmergencyPause,
    ) -> GovernanceResult<String> {
        pause.validate()?;
        let state_root_before = self.state_root();
        let applied_root = self.apply_emergency_pause("direct_emergency_pause", &pause)?;
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::EmergencyPauseApplied,
            actor_label,
            "direct_emergency_pause",
            json!({ "pause_root": applied_root, "pause": pause.public_record() }),
            &state_root_before,
            &state_root_after,
        );
        Ok(applied_root)
    }

    pub fn emergency_resume(
        &mut self,
        actor_label: &str,
        resume: EmergencyResume,
    ) -> GovernanceResult<String> {
        resume.validate()?;
        let state_root_before = self.state_root();
        let applied_root = self.apply_emergency_resume("direct_emergency_resume", &resume)?;
        let state_root_after = self.state_root();
        self.push_audit_event(
            GovernanceAuditEventKind::EmergencyResumeApplied,
            actor_label,
            "direct_emergency_resume",
            json!({ "resume_root": applied_root, "resume": resume.public_record() }),
            &state_root_before,
            &state_root_after,
        );
        Ok(applied_root)
    }

    pub fn apply_parameter_changes(
        &mut self,
        proposal_id: &str,
        changes: &[GovernanceParameterChange],
    ) -> GovernanceResult<String> {
        if changes.is_empty() {
            return Err("parameter changes cannot be empty".to_string());
        }
        for change in changes {
            change.validate()?;
            let key = change.parameter_key();
            let current = self.parameters.get(&key).cloned().unwrap_or(Value::Null);
            if current != change.old_value {
                return Err(format!("parameter old value mismatch for {key}"));
            }
        }
        for change in changes {
            let key = change.parameter_key();
            if change.new_value.is_null() {
                self.parameters.remove(&key);
            } else {
                self.parameters.insert(key, change.new_value.clone());
            }
        }
        Ok(governance_payload_root(
            "GOVERNANCE-APPLIED-PARAMETERS",
            &json!({
                "proposal_id": proposal_id,
                "parameter_root": self.parameter_root(),
                "change_root": merkle_root(
                    "GOVERNANCE-PARAMETER-CHANGE",
                    &changes.iter().map(GovernanceParameterChange::public_record).collect::<Vec<_>>(),
                ),
            }),
        ))
    }

    pub fn apply_timelocked_upgrade(
        &mut self,
        proposal_id: &str,
        upgrade: &TimelockedUpgrade,
    ) -> GovernanceResult<String> {
        upgrade.validate()?;
        if upgrade.activation_height < self.height {
            return Err("cannot schedule upgrade activation in the past".to_string());
        }
        let upgrade_id = upgrade.upgrade_id();
        self.timelocked_upgrades
            .insert(upgrade_id.clone(), upgrade.clone());
        Ok(governance_payload_root(
            "GOVERNANCE-APPLIED-UPGRADE",
            &json!({
                "proposal_id": proposal_id,
                "upgrade_id": upgrade_id,
                "upgrade_root": upgrade.upgrade_root(),
                "upgrade_schedule_root": self.timelocked_upgrade_root(),
            }),
        ))
    }

    pub fn apply_emergency_pause(
        &mut self,
        proposal_id: &str,
        pause: &EmergencyPause,
    ) -> GovernanceResult<String> {
        pause.validate()?;
        let scopes = normalized_strings(&pause.scopes);
        for scope in scopes {
            let pause_id =
                governance_pause_id(&scope, &pause.reason_hash, self.height, proposal_id);
            let record = EmergencyPauseRecord {
                pause_id,
                scope: scope.clone(),
                reason_hash: pause.reason_hash.clone(),
                proposal_id: proposal_id.to_string(),
                paused_at_height: self.height,
                expires_at_height: pause.expires_at_height,
                requires_resume_vote: pause.requires_resume_vote,
                status: "active".to_string(),
            };
            self.active_pauses.insert(scope, record);
        }
        Ok(self.pause_root())
    }

    pub fn apply_emergency_resume(
        &mut self,
        _proposal_id: &str,
        resume: &EmergencyResume,
    ) -> GovernanceResult<String> {
        resume.validate()?;
        let scopes = if resume.resume_all {
            self.active_pauses.keys().cloned().collect::<Vec<_>>()
        } else {
            normalized_strings(&resume.scopes)
        };
        if scopes.is_empty() {
            return Err("emergency resume found no paused scopes".to_string());
        }
        for scope in &scopes {
            if !self.active_pauses.contains_key(scope) {
                return Err(format!("scope is not paused: {scope}"));
            }
        }
        for scope in scopes {
            self.active_pauses.remove(&scope);
        }
        Ok(self.pause_root())
    }

    pub fn apply_treasury_policy_change(
        &mut self,
        proposal_id: &str,
        policy: &TreasuryPolicy,
    ) -> GovernanceResult<String> {
        policy.validate()?;
        self.treasury_policy = policy.clone();
        Ok(governance_payload_root(
            "GOVERNANCE-APPLIED-TREASURY-POLICY",
            &json!({
                "proposal_id": proposal_id,
                "treasury_policy_root": self.treasury_policy.policy_root(),
            }),
        ))
    }

    pub fn apply_fee_policy_change(
        &mut self,
        proposal_id: &str,
        policy: &FeePolicy,
    ) -> GovernanceResult<String> {
        policy.validate()?;
        self.fee_policy = policy.clone();
        Ok(governance_payload_root(
            "GOVERNANCE-APPLIED-FEE-POLICY",
            &json!({
                "proposal_id": proposal_id,
                "fee_policy_root": self.fee_policy.policy_root(),
            }),
        ))
    }

    pub fn apply_quantum_crypto_migration(
        &mut self,
        proposal_id: &str,
        migration: &QuantumCryptoMigration,
    ) -> GovernanceResult<String> {
        migration.validate()?;
        let migration_id = migration.migration_id();
        self.crypto_migrations
            .insert(migration_id.clone(), migration.clone());
        Ok(governance_payload_root(
            "GOVERNANCE-APPLIED-CRYPTO-MIGRATION",
            &json!({
                "proposal_id": proposal_id,
                "migration_id": migration_id,
                "migration_root": migration.migration_root(),
                "migration_state_root": self.crypto_migration_root(),
            }),
        ))
    }

    pub fn apply_contract_allowlist_changes(
        &mut self,
        proposal_id: &str,
        changes: &[ContractAllowlistChange],
    ) -> GovernanceResult<String> {
        if changes.is_empty() {
            return Err("contract allowlist changes cannot be empty".to_string());
        }
        for change in changes {
            change.validate()?;
        }
        for change in changes {
            if matches!(
                &change.action,
                ContractAllowlistAction::Suspend | ContractAllowlistAction::Remove
            ) && !self.contract_allowlist.contains_key(&change.entry_id())
            {
                return Err("contract allowlist change references unknown entry".to_string());
            }
        }
        for change in changes {
            let entry_id = change.entry_id();
            match &change.action {
                ContractAllowlistAction::Add | ContractAllowlistAction::Resume => {
                    let entry = ContractAllowlistEntry {
                        entry_id: entry_id.clone(),
                        contract_id: change.contract_id.clone(),
                        template: change.template.clone(),
                        code_hash: change.code_hash.clone(),
                        allowed_entrypoints: normalized_strings(&change.allowed_entrypoints),
                        capability_root: change.capability_root.clone(),
                        status: "active".to_string(),
                        last_proposal_id: proposal_id.to_string(),
                        updated_at_height: self.height,
                    };
                    self.contract_allowlist.insert(entry_id, entry);
                }
                ContractAllowlistAction::Suspend => {
                    let entry = self.contract_allowlist.get_mut(&entry_id).ok_or_else(|| {
                        "cannot suspend unknown contract allowlist entry".to_string()
                    })?;
                    entry.status = "suspended".to_string();
                    entry.last_proposal_id = proposal_id.to_string();
                    entry.updated_at_height = self.height;
                }
                ContractAllowlistAction::Remove => {
                    if self.contract_allowlist.remove(&entry_id).is_none() {
                        return Err("cannot remove unknown contract allowlist entry".to_string());
                    }
                }
            }
        }
        Ok(governance_payload_root(
            "GOVERNANCE-APPLIED-CONTRACT-ALLOWLIST",
            &json!({
                "proposal_id": proposal_id,
                "allowlist_root": self.contract_allowlist_root(),
            }),
        ))
    }

    fn apply_proposal_action(
        &mut self,
        proposal_id: &str,
        action: &GovernanceProposalAction,
    ) -> GovernanceResult<Value> {
        match action {
            GovernanceProposalAction::ParameterChange { changes } => {
                let applied_root = self.apply_parameter_changes(proposal_id, changes)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::ParameterChange.as_str(),
                    "applied_root": applied_root,
                    "parameter_root": self.parameter_root(),
                }))
            }
            GovernanceProposalAction::TimelockedUpgrade { upgrade } => {
                let applied_root = self.apply_timelocked_upgrade(proposal_id, upgrade)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::TimelockedUpgrade.as_str(),
                    "applied_root": applied_root,
                    "upgrade_root": self.timelocked_upgrade_root(),
                }))
            }
            GovernanceProposalAction::EmergencyPause { pause } => {
                let applied_root = self.apply_emergency_pause(proposal_id, pause)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::EmergencyPause.as_str(),
                    "applied_root": applied_root,
                    "pause_root": self.pause_root(),
                }))
            }
            GovernanceProposalAction::EmergencyResume { resume } => {
                let applied_root = self.apply_emergency_resume(proposal_id, resume)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::EmergencyResume.as_str(),
                    "applied_root": applied_root,
                    "pause_root": self.pause_root(),
                }))
            }
            GovernanceProposalAction::TreasuryPolicyChange { policy } => {
                let applied_root = self.apply_treasury_policy_change(proposal_id, policy)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::TreasuryPolicyChange.as_str(),
                    "applied_root": applied_root,
                    "treasury_policy_root": self.treasury_policy.policy_root(),
                }))
            }
            GovernanceProposalAction::FeePolicyChange { policy } => {
                let applied_root = self.apply_fee_policy_change(proposal_id, policy)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::FeePolicyChange.as_str(),
                    "applied_root": applied_root,
                    "fee_policy_root": self.fee_policy.policy_root(),
                }))
            }
            GovernanceProposalAction::QuantumCryptoMigration { migration } => {
                let applied_root = self.apply_quantum_crypto_migration(proposal_id, migration)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::QuantumCryptoMigration.as_str(),
                    "applied_root": applied_root,
                    "crypto_migration_root": self.crypto_migration_root(),
                }))
            }
            GovernanceProposalAction::ContractAllowlistChange { changes } => {
                let applied_root = self.apply_contract_allowlist_changes(proposal_id, changes)?;
                Ok(json!({
                    "kind": GovernanceProposalKind::ContractAllowlistChange.as_str(),
                    "applied_root": applied_root,
                    "contract_allowlist_root": self.contract_allowlist_root(),
                }))
            }
        }
    }

    pub fn validator_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-VALIDATOR",
            &self
                .validators
                .values()
                .map(GovernanceValidator::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn proposal_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-PROPOSAL",
            &self
                .proposals
                .values()
                .map(GovernanceProposal::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn vote_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-VOTE",
            &self
                .votes
                .values()
                .map(GovernanceVote::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn vote_root_for_proposal(&self, proposal_id: &str) -> String {
        let votes = self
            .votes
            .values()
            .filter(|vote| vote.proposal_id == proposal_id)
            .cloned()
            .collect::<Vec<_>>();
        governance_vote_root(&votes, proposal_id)
    }

    pub fn tally_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-TALLY",
            &self
                .tallies
                .values()
                .map(GovernanceVoteTally::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn execution_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-EXECUTION",
            &self
                .executions
                .values()
                .map(GovernanceExecution::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn parameter_root(&self) -> String {
        let leaves = self
            .parameters
            .iter()
            .map(|(key, value)| {
                json!({
                    "kind": "governance_parameter",
                    "chain_id": CHAIN_ID,
                    "key": key,
                    "value": value,
                })
            })
            .collect::<Vec<_>>();
        merkle_root("GOVERNANCE-PARAMETER", &leaves)
    }

    pub fn timelocked_upgrade_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-TIMELOCKED-UPGRADE",
            &self
                .timelocked_upgrades
                .values()
                .map(TimelockedUpgrade::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn crypto_migration_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-CRYPTO-MIGRATION",
            &self
                .crypto_migrations
                .values()
                .map(QuantumCryptoMigration::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn contract_allowlist_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-CONTRACT-ALLOWLIST",
            &self
                .contract_allowlist
                .values()
                .map(ContractAllowlistEntry::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pause_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-ACTIVE-PAUSE",
            &self
                .active_pauses
                .values()
                .map(EmergencyPauseRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn audit_event_root(&self) -> String {
        merkle_root(
            "GOVERNANCE-AUDIT-EVENT",
            &self
                .audit_events
                .values()
                .map(GovernanceAuditEvent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_state",
            "chain_id": CHAIN_ID,
            "governance_protocol_version": GOVERNANCE_PROTOCOL_VERSION,
            "height": self.height,
            "policy_root": self.policy.policy_root(),
            "validator_root": self.validator_root(),
            "validator_count": self.validators.len() as u64,
            "proposal_root": self.proposal_root(),
            "proposal_count": self.proposals.len() as u64,
            "vote_root": self.vote_root(),
            "vote_count": self.votes.len() as u64,
            "tally_root": self.tally_root(),
            "execution_root": self.execution_root(),
            "parameter_root": self.parameter_root(),
            "treasury_policy_root": self.treasury_policy.policy_root(),
            "fee_policy_root": self.fee_policy.policy_root(),
            "timelocked_upgrade_root": self.timelocked_upgrade_root(),
            "crypto_migration_root": self.crypto_migration_root(),
            "contract_allowlist_root": self.contract_allowlist_root(),
            "pause_root": self.pause_root(),
            "active_pause_count": self.active_pauses.len() as u64,
            "audit_event_root": self.audit_event_root(),
            "last_audit_event_root": self.last_audit_event_root,
            "next_proposal_nonce": self.next_proposal_nonce,
        })
    }

    pub fn state_root(&self) -> String {
        governance_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> GovernanceResult<String> {
        self.policy.validate()?;
        self.treasury_policy.validate()?;
        self.fee_policy.validate()?;
        for validator in self.validators.values() {
            validator.validate()?;
        }
        for proposal in self.proposals.values() {
            proposal.validate()?;
        }
        for vote in self.votes.values() {
            vote.validate()?;
        }
        for tally in self.tallies.values() {
            tally.validate()?;
        }
        for event in self.audit_events.values() {
            event.validate()?;
        }
        Ok(self.state_root())
    }

    fn push_audit_event(
        &mut self,
        event_kind: GovernanceAuditEventKind,
        actor_label: &str,
        proposal_id: &str,
        details: Value,
        previous_state_root: &str,
        new_state_root: &str,
    ) -> String {
        let previous_event_root = self.last_audit_event_root.clone();
        let event = GovernanceAuditEvent::new(
            self.audit_events.len() as u64,
            event_kind,
            actor_label,
            proposal_id,
            details,
            previous_state_root,
            new_state_root,
            self.height,
            &previous_event_root,
        );
        let event_root = event.event_root();
        let event_id = event.event_id.clone();
        self.audit_events.insert(event_id.clone(), event);
        self.last_audit_event_root = event_root;
        event_id
    }
}

pub fn governance_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn governance_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn governance_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "GOVERNANCE-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn governance_actor_commitment(label: &str) -> String {
    domain_hash(
        "GOVERNANCE-ACTOR-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn governance_validator_id(label: &str, consensus_public_key: &str) -> String {
    domain_hash(
        "GOVERNANCE-VALIDATOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(consensus_public_key),
        ],
        32,
    )
}

pub fn governance_policy_root(policy: &GovernancePolicy) -> String {
    domain_hash(
        "GOVERNANCE-POLICY",
        &[HashPart::Json(&policy.public_record())],
        32,
    )
}

pub fn governance_treasury_policy_root(policy: &TreasuryPolicy) -> String {
    domain_hash(
        "GOVERNANCE-TREASURY-POLICY",
        &[HashPart::Json(&policy.public_record())],
        32,
    )
}

pub fn governance_fee_policy_root(policy: &FeePolicy) -> String {
    domain_hash(
        "GOVERNANCE-FEE-POLICY",
        &[HashPart::Json(&policy.public_record())],
        32,
    )
}

pub fn governance_parameter_key(module: &str, key: &str) -> String {
    domain_hash(
        "GOVERNANCE-PARAMETER-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(module),
            HashPart::Str(key),
        ],
        32,
    )
}

pub fn governance_parameter_change_id(
    module: &str,
    key: &str,
    old_value: &Value,
    new_value: &Value,
    reason_hash: &str,
) -> String {
    domain_hash(
        "GOVERNANCE-PARAMETER-CHANGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(module),
            HashPart::Str(key),
            HashPart::Json(old_value),
            HashPart::Json(new_value),
            HashPart::Str(reason_hash),
        ],
        32,
    )
}

pub fn governance_upgrade_id(
    target_version: &str,
    artifact_root: &str,
    manifest_root: &str,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(target_version),
            HashPart::Str(artifact_root),
            HashPart::Str(manifest_root),
        ],
        32,
    )
}

pub fn governance_crypto_migration_id(target_policy_version: &str, migration_root: &str) -> String {
    domain_hash(
        "GOVERNANCE-CRYPTO-MIGRATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(target_policy_version),
            HashPart::Str(migration_root),
        ],
        32,
    )
}

pub fn governance_contract_allowlist_entry_id(contract_id: &str, code_hash: &str) -> String {
    domain_hash(
        "GOVERNANCE-CONTRACT-ALLOWLIST-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(code_hash),
        ],
        32,
    )
}

pub fn governance_action_root(action: &GovernanceProposalAction) -> String {
    domain_hash(
        "GOVERNANCE-ACTION",
        &[HashPart::Json(&action.public_record())],
        32,
    )
}

pub fn governance_proposal_id(
    proposal_nonce: u64,
    proposer_commitment: &str,
    proposal_kind: &str,
    action_root: &str,
) -> String {
    domain_hash(
        "GOVERNANCE-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(proposal_nonce as i128),
            HashPart::Str(proposer_commitment),
            HashPart::Str(proposal_kind),
            HashPart::Str(action_root),
        ],
        32,
    )
}

pub fn governance_vote_id(proposal_id: &str, validator_id: &str, choice: &str) -> String {
    domain_hash(
        "GOVERNANCE-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(validator_id),
            HashPart::Str(choice),
        ],
        32,
    )
}

pub fn governance_vote_root(votes: &[GovernanceVote], proposal_id: &str) -> String {
    let mut leaves = votes
        .iter()
        .filter(|vote| vote.proposal_id == proposal_id)
        .map(GovernanceVote::public_record)
        .collect::<Vec<_>>();
    leaves.sort_by(|left, right| {
        left["vote_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["vote_id"].as_str().unwrap_or_default())
    });
    merkle_root("GOVERNANCE-PROPOSAL-VOTE", &leaves)
}

pub fn governance_tally_id(proposal_id: &str, vote_root: &str, tallied_at_height: u64) -> String {
    domain_hash(
        "GOVERNANCE-TALLY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(vote_root),
            HashPart::Int(tallied_at_height as i128),
        ],
        32,
    )
}

pub fn governance_execution_id(
    proposal_id: &str,
    action_root: &str,
    executed_at_height: u64,
    state_root_before: &str,
    state_root_after: &str,
) -> String {
    domain_hash(
        "GOVERNANCE-EXECUTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(action_root),
            HashPart::Int(executed_at_height as i128),
            HashPart::Str(state_root_before),
            HashPart::Str(state_root_after),
        ],
        32,
    )
}

pub fn governance_pause_id(
    scope: &str,
    reason_hash: &str,
    paused_at_height: u64,
    proposal_id: &str,
) -> String {
    domain_hash(
        "GOVERNANCE-PAUSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(reason_hash),
            HashPart::Int(paused_at_height as i128),
            HashPart::Str(proposal_id),
        ],
        32,
    )
}

pub fn governance_audit_event_id(
    event_index: u64,
    event_kind: &str,
    proposal_id: &str,
    details_root: &str,
    previous_event_root: &str,
) -> String {
    domain_hash(
        "GOVERNANCE-AUDIT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(event_index as i128),
            HashPart::Str(event_kind),
            HashPart::Str(proposal_id),
            HashPart::Str(details_root),
            HashPart::Str(previous_event_root),
        ],
        32,
    )
}

pub fn governance_state_root_from_record(record: &Value) -> String {
    domain_hash("GOVERNANCE-STATE", &[HashPart::Json(record)], 32)
}

fn empty_governance_authorization(label: &str) -> Authorization {
    Authorization {
        signer_label: label.to_string(),
        auth_scheme: CryptoRole::ValidatorSignature.scheme().to_string(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

fn bps_threshold(total: u64, bps: u64) -> u64 {
    if total == 0 || bps == 0 {
        0
    } else {
        total.saturating_mul(bps).div_ceil(10_000)
    }
}

fn validate_bps(value: u64, label: &str) -> GovernanceResult<()> {
    if value > 10_000 {
        Err(format!("{label} basis points exceed 100 percent"))
    } else {
        Ok(())
    }
}

fn validate_root_like(value: &str, label: &str) -> GovernanceResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_string_list(values: &[String], label: &str) -> GovernanceResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(format!("{label} cannot be empty"));
        }
        if !seen.insert(value.clone()) {
            return Err(format!("{label} appears more than once"));
        }
    }
    Ok(())
}

fn validate_scope_list(values: &[String], max_len: usize, label: &str) -> GovernanceResult<()> {
    if values.is_empty() {
        return Err(format!("{label} requires at least one scope"));
    }
    if values.len() > max_len {
        return Err(format!("{label} has too many scopes"));
    }
    validate_string_list(values, "governance scope")
}

fn normalized_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}

fn string_list_root(domain: &str, values: &[String]) -> String {
    let values = normalized_strings(values);
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}
