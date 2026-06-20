use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateGovernanceResult<T> = Result<T, String>;

pub const PRIVATE_GOVERNANCE_PROTOCOL_VERSION: &str = "nebula-l2-private-governance-v1";
pub const PRIVATE_GOVERNANCE_DEFAULT_QUORUM_BPS: u64 = 6_667;
pub const PRIVATE_GOVERNANCE_DEFAULT_APPROVAL_BPS: u64 = 5_001;
pub const PRIVATE_GOVERNANCE_SUPERMAJORITY_BPS: u64 = 7_500;
pub const PRIVATE_GOVERNANCE_EMERGENCY_VETO_BPS: u64 = 3_334;
pub const PRIVATE_GOVERNANCE_DEFAULT_VOTE_WINDOW_BLOCKS: u64 = 80;
pub const PRIVATE_GOVERNANCE_MIN_VOTE_WINDOW_BLOCKS: u64 = 10;
pub const PRIVATE_GOVERNANCE_MAX_VOTE_WINDOW_BLOCKS: u64 = 10_080;
pub const PRIVATE_GOVERNANCE_DEFAULT_TIMELOCK_BLOCKS: u64 = 120;
pub const PRIVATE_GOVERNANCE_CONTRACT_TIMELOCK_BLOCKS: u64 = 240;
pub const PRIVATE_GOVERNANCE_PARAMETER_TIMELOCK_BLOCKS: u64 = 80;
pub const PRIVATE_GOVERNANCE_EMERGENCY_FREEZE_BLOCKS: u64 = 720;
pub const PRIVATE_GOVERNANCE_CHALLENGE_WINDOW_BLOCKS: u64 = 120;
pub const PRIVATE_GOVERNANCE_EXECUTION_WINDOW_BLOCKS: u64 = 14_400;
pub const PRIVATE_GOVERNANCE_MAX_COMMITTEE_MEMBERS: usize = 128;
pub const PRIVATE_GOVERNANCE_MIN_COMMITTEE_MEMBERS: usize = 3;
pub const PRIVATE_GOVERNANCE_MAX_PARAMETER_CHANGES: usize = 64;
pub const PRIVATE_GOVERNANCE_MAX_MIGRATION_STEPS: usize = 64;
pub const PRIVATE_GOVERNANCE_MAX_PRIVACY_DISCLOSURES: usize = 64;
pub const PRIVATE_GOVERNANCE_MAX_CHALLENGES_PER_PROPOSAL: usize = 16;
pub const PRIVATE_GOVERNANCE_DEFAULT_FEE_ASSET_ID: &str = "piconero";
pub const PRIVATE_GOVERNANCE_PQ_SCHEME: &str = "ML-DSA-65";
pub const PRIVATE_GOVERNANCE_KEM_SCHEME: &str = "ML-KEM-768";
pub const PRIVATE_GOVERNANCE_VETO_SCOPE_GLOBAL: &str = "global_upgrade_safety";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivateGovernanceProposalKind {
    TimelockedContractUpgrade,
    TimelockedParameterUpgrade,
    FeePolicyChange,
    QuantumMigrationBallot,
    PrivacyBudgetDisclosure,
    EmergencyVeto,
}

impl PrivateGovernanceProposalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TimelockedContractUpgrade => "timelocked_contract_upgrade",
            Self::TimelockedParameterUpgrade => "timelocked_parameter_upgrade",
            Self::FeePolicyChange => "fee_policy_change",
            Self::QuantumMigrationBallot => "quantum_migration_ballot",
            Self::PrivacyBudgetDisclosure => "privacy_budget_disclosure",
            Self::EmergencyVeto => "emergency_veto",
        }
    }

    pub fn requires_supermajority(&self) -> bool {
        matches!(
            self,
            Self::TimelockedContractUpgrade | Self::QuantumMigrationBallot | Self::EmergencyVeto
        )
    }

    pub fn opens_challenge_window(&self) -> bool {
        matches!(
            self,
            Self::TimelockedContractUpgrade
                | Self::TimelockedParameterUpgrade
                | Self::FeePolicyChange
                | Self::QuantumMigrationBallot
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivateVoteChoice {
    Approve,
    Reject,
    Abstain,
    Veto,
}

impl PrivateVoteChoice {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
            Self::Veto => "veto",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivateGovernanceChallengeKind {
    InvalidTimelock,
    InvalidStateTransition,
    PrivacyBudgetOverrun,
    CommitteeThresholdFault,
    EmergencySafetyFault,
    QuantumMigrationFault,
}

impl PrivateGovernanceChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidTimelock => "invalid_timelock",
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::PrivacyBudgetOverrun => "privacy_budget_overrun",
            Self::CommitteeThresholdFault => "committee_threshold_fault",
            Self::EmergencySafetyFault => "emergency_safety_fault",
            Self::QuantumMigrationFault => "quantum_migration_fault",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivateGovernanceExecutionStatus {
    PendingChallenge,
    Finalized,
    Reverted,
    Vetoed,
}

impl PrivateGovernanceExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PendingChallenge => "pending_challenge",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
            Self::Vetoed => "vetoed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivateGovernanceChallengeStatus {
    Open,
    Sustained,
    Rejected,
    Expired,
}

impl PrivateGovernanceChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernancePolicy {
    pub quorum_bps: u64,
    pub approval_bps: u64,
    pub supermajority_bps: u64,
    pub emergency_veto_bps: u64,
    pub default_vote_window_blocks: u64,
    pub min_vote_window_blocks: u64,
    pub max_vote_window_blocks: u64,
    pub default_timelock_blocks: u64,
    pub contract_timelock_blocks: u64,
    pub parameter_timelock_blocks: u64,
    pub emergency_freeze_blocks: u64,
    pub challenge_window_blocks: u64,
    pub execution_window_blocks: u64,
    pub min_committee_members: usize,
    pub max_committee_members: usize,
    pub max_parameter_changes: usize,
    pub max_migration_steps: usize,
    pub max_privacy_disclosures: usize,
}

impl Default for PrivateGovernancePolicy {
    fn default() -> Self {
        Self {
            quorum_bps: PRIVATE_GOVERNANCE_DEFAULT_QUORUM_BPS,
            approval_bps: PRIVATE_GOVERNANCE_DEFAULT_APPROVAL_BPS,
            supermajority_bps: PRIVATE_GOVERNANCE_SUPERMAJORITY_BPS,
            emergency_veto_bps: PRIVATE_GOVERNANCE_EMERGENCY_VETO_BPS,
            default_vote_window_blocks: PRIVATE_GOVERNANCE_DEFAULT_VOTE_WINDOW_BLOCKS,
            min_vote_window_blocks: PRIVATE_GOVERNANCE_MIN_VOTE_WINDOW_BLOCKS,
            max_vote_window_blocks: PRIVATE_GOVERNANCE_MAX_VOTE_WINDOW_BLOCKS,
            default_timelock_blocks: PRIVATE_GOVERNANCE_DEFAULT_TIMELOCK_BLOCKS,
            contract_timelock_blocks: PRIVATE_GOVERNANCE_CONTRACT_TIMELOCK_BLOCKS,
            parameter_timelock_blocks: PRIVATE_GOVERNANCE_PARAMETER_TIMELOCK_BLOCKS,
            emergency_freeze_blocks: PRIVATE_GOVERNANCE_EMERGENCY_FREEZE_BLOCKS,
            challenge_window_blocks: PRIVATE_GOVERNANCE_CHALLENGE_WINDOW_BLOCKS,
            execution_window_blocks: PRIVATE_GOVERNANCE_EXECUTION_WINDOW_BLOCKS,
            min_committee_members: PRIVATE_GOVERNANCE_MIN_COMMITTEE_MEMBERS,
            max_committee_members: PRIVATE_GOVERNANCE_MAX_COMMITTEE_MEMBERS,
            max_parameter_changes: PRIVATE_GOVERNANCE_MAX_PARAMETER_CHANGES,
            max_migration_steps: PRIVATE_GOVERNANCE_MAX_MIGRATION_STEPS,
            max_privacy_disclosures: PRIVATE_GOVERNANCE_MAX_PRIVACY_DISCLOSURES,
        }
    }
}

impl PrivateGovernancePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_governance_policy",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "supermajority_bps": self.supermajority_bps,
            "emergency_veto_bps": self.emergency_veto_bps,
            "default_vote_window_blocks": self.default_vote_window_blocks,
            "min_vote_window_blocks": self.min_vote_window_blocks,
            "max_vote_window_blocks": self.max_vote_window_blocks,
            "default_timelock_blocks": self.default_timelock_blocks,
            "contract_timelock_blocks": self.contract_timelock_blocks,
            "parameter_timelock_blocks": self.parameter_timelock_blocks,
            "emergency_freeze_blocks": self.emergency_freeze_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "execution_window_blocks": self.execution_window_blocks,
            "min_committee_members": self.min_committee_members,
            "max_committee_members": self.max_committee_members,
            "max_parameter_changes": self.max_parameter_changes,
            "max_migration_steps": self.max_migration_steps,
            "max_privacy_disclosures": self.max_privacy_disclosures,
        })
    }

    pub fn policy_root(&self) -> String {
        private_governance_policy_root(self)
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_bps(self.quorum_bps, "private governance quorum")?;
        validate_bps(self.approval_bps, "private governance approval")?;
        validate_bps(self.supermajority_bps, "private governance supermajority")?;
        validate_bps(self.emergency_veto_bps, "private governance emergency veto")?;
        if self.approval_bps == 0 {
            return Err("private governance approval threshold cannot be zero".to_string());
        }
        if self.supermajority_bps < self.approval_bps {
            return Err("private governance supermajority must exceed approval".to_string());
        }
        if self.min_vote_window_blocks == 0 {
            return Err("private governance minimum vote window cannot be zero".to_string());
        }
        if self.default_vote_window_blocks < self.min_vote_window_blocks {
            return Err("private governance default vote window is below minimum".to_string());
        }
        if self.default_vote_window_blocks > self.max_vote_window_blocks {
            return Err("private governance default vote window exceeds maximum".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("private governance challenge window cannot be zero".to_string());
        }
        if self.execution_window_blocks <= self.challenge_window_blocks {
            return Err(
                "private governance execution window must exceed challenge window".to_string(),
            );
        }
        if self.min_committee_members == 0 {
            return Err("private governance committee minimum cannot be zero".to_string());
        }
        if self.min_committee_members > self.max_committee_members {
            return Err("private governance committee minimum exceeds maximum".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeMember {
    pub member_id: String,
    pub label_commitment: String,
    pub pq_scheme: String,
    pub pq_public_key_root: String,
    pub kem_public_key_root: String,
    pub voting_weight: u64,
    pub joined_at_height: u64,
    pub retired_at_height: u64,
    pub status: String,
}

impl PqCommitteeMember {
    pub fn new(
        label: &str,
        pq_public_key_root: &str,
        voting_weight: u64,
        joined_at_height: u64,
    ) -> PrivateGovernanceResult<Self> {
        validate_nonempty(label, "committee member label")?;
        validate_nonempty(pq_public_key_root, "committee member public key root")?;
        if voting_weight == 0 {
            return Err("committee member voting weight cannot be zero".to_string());
        }
        let label_commitment = private_governance_string_commitment("committee_member", label);
        let kem_public_key_root = private_governance_string_commitment("kem_member", label);
        let member_id = private_governance_committee_member_id(
            &label_commitment,
            PRIVATE_GOVERNANCE_PQ_SCHEME,
            pq_public_key_root,
            voting_weight,
        );
        Ok(Self {
            member_id,
            label_commitment,
            pq_scheme: PRIVATE_GOVERNANCE_PQ_SCHEME.to_string(),
            pq_public_key_root: pq_public_key_root.to_string(),
            kem_public_key_root,
            voting_weight,
            joined_at_height,
            retired_at_height: 0,
            status: "active".to_string(),
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == "active"
            && self.voting_weight > 0
            && self.joined_at_height <= height
            && (self.retired_at_height == 0 || height < self.retired_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_committee_member",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "label_commitment": self.label_commitment,
            "pq_scheme": self.pq_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "kem_public_key_root": self.kem_public_key_root,
            "voting_weight": self.voting_weight,
            "joined_at_height": self.joined_at_height,
            "retired_at_height": self.retired_at_height,
            "status": self.status,
        })
    }

    pub fn member_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-COMMITTEE-MEMBER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.label_commitment, "committee member label commitment")?;
        validate_nonempty(&self.pq_scheme, "committee member pq scheme")?;
        validate_nonempty(
            &self.pq_public_key_root,
            "committee member pq public key root",
        )?;
        validate_nonempty(
            &self.kem_public_key_root,
            "committee member kem public key root",
        )?;
        if self.voting_weight == 0 {
            return Err("committee member voting weight cannot be zero".to_string());
        }
        validate_status(
            &self.status,
            &["active", "retired", "suspended"],
            "committee member",
        )?;
        let expected_member_id = private_governance_committee_member_id(
            &self.label_commitment,
            &self.pq_scheme,
            &self.pq_public_key_root,
            self.voting_weight,
        );
        if self.member_id != expected_member_id {
            return Err("committee member id mismatch".to_string());
        }
        Ok(self.member_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVotingCommittee {
    pub committee_id: String,
    pub label: String,
    pub purpose: String,
    pub members: BTreeMap<String, PqCommitteeMember>,
    pub quorum_bps: u64,
    pub approval_bps: u64,
    pub veto_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqVotingCommittee {
    pub fn new(
        label: impl Into<String>,
        purpose: impl Into<String>,
        members: Vec<PqCommitteeMember>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateGovernanceResult<Self> {
        let label = label.into();
        let purpose = purpose.into();
        validate_nonempty(&label, "committee label")?;
        validate_nonempty(&purpose, "committee purpose")?;
        let mut indexed_members = BTreeMap::new();
        for member in members {
            member.validate()?;
            if indexed_members
                .insert(member.member_id.clone(), member)
                .is_some()
            {
                return Err("committee member appears more than once".to_string());
            }
        }
        let mut committee = Self {
            committee_id: String::new(),
            label,
            purpose,
            members: indexed_members,
            quorum_bps: PRIVATE_GOVERNANCE_DEFAULT_QUORUM_BPS,
            approval_bps: PRIVATE_GOVERNANCE_DEFAULT_APPROVAL_BPS,
            veto_bps: PRIVATE_GOVERNANCE_EMERGENCY_VETO_BPS,
            created_at_height,
            expires_at_height,
            status: "active".to_string(),
        };
        committee.committee_id = private_governance_committee_id(
            &committee.label,
            &committee.purpose,
            &committee.member_root(),
            committee.created_at_height,
        );
        committee.validate()?;
        Ok(committee)
    }

    pub fn member_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-COMMITTEE-MEMBER",
            &self
                .members
                .values()
                .map(PqCommitteeMember::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_weight_at(&self, height: u64) -> u64 {
        self.members
            .values()
            .filter(|member| member.is_active_at(height))
            .map(|member| member.voting_weight)
            .sum()
    }

    pub fn total_weight(&self) -> u64 {
        self.members
            .values()
            .map(|member| member.voting_weight)
            .sum()
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == "active"
            && self.created_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_voting_committee",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "label": self.label,
            "purpose": self.purpose,
            "member_root": self.member_root(),
            "member_count": self.members.len(),
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "veto_bps": self.veto_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn committee_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-COMMITTEE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.label, "committee label")?;
        validate_nonempty(&self.purpose, "committee purpose")?;
        validate_bps(self.quorum_bps, "committee quorum")?;
        validate_bps(self.approval_bps, "committee approval")?;
        validate_bps(self.veto_bps, "committee veto")?;
        validate_status(
            &self.status,
            &["active", "retired", "suspended"],
            "committee",
        )?;
        if self.members.len() < PRIVATE_GOVERNANCE_MIN_COMMITTEE_MEMBERS {
            return Err("committee has too few members".to_string());
        }
        if self.members.len() > PRIVATE_GOVERNANCE_MAX_COMMITTEE_MEMBERS {
            return Err("committee has too many members".to_string());
        }
        if self.total_weight() == 0 {
            return Err("committee total weight cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.created_at_height {
            return Err("committee expiry must be after creation".to_string());
        }
        for (member_id, member) in &self.members {
            member.validate()?;
            if member_id != &member.member_id {
                return Err("committee member index mismatch".to_string());
            }
        }
        let expected_committee_id = private_governance_committee_id(
            &self.label,
            &self.purpose,
            &self.member_root(),
            self.created_at_height,
        );
        if self.committee_id != expected_committee_id {
            return Err("committee id mismatch".to_string());
        }
        Ok(self.committee_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockedContractUpgrade {
    pub upgrade_id: String,
    pub contract_id: String,
    pub current_code_root: String,
    pub target_code_root: String,
    pub manifest_root: String,
    pub migration_root: String,
    pub rollback_root: String,
    pub expected_pre_state_root: String,
    pub expected_post_state_root: String,
    pub safety_case_root: String,
    pub activation_height: u64,
    pub min_delay_blocks: u64,
    pub requires_pause: bool,
}

impl TimelockedContractUpgrade {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        current_code_root: impl Into<String>,
        target_code_root: impl Into<String>,
        manifest_root: impl Into<String>,
        migration_root: impl Into<String>,
        rollback_root: impl Into<String>,
        expected_pre_state_root: impl Into<String>,
        expected_post_state_root: impl Into<String>,
        safety_case_root: impl Into<String>,
        activation_height: u64,
        min_delay_blocks: u64,
        requires_pause: bool,
    ) -> PrivateGovernanceResult<Self> {
        let mut upgrade = Self {
            upgrade_id: String::new(),
            contract_id: contract_id.into(),
            current_code_root: current_code_root.into(),
            target_code_root: target_code_root.into(),
            manifest_root: manifest_root.into(),
            migration_root: migration_root.into(),
            rollback_root: rollback_root.into(),
            expected_pre_state_root: expected_pre_state_root.into(),
            expected_post_state_root: expected_post_state_root.into(),
            safety_case_root: safety_case_root.into(),
            activation_height,
            min_delay_blocks,
            requires_pause,
        };
        upgrade.upgrade_id = private_governance_contract_upgrade_id(
            &upgrade.contract_id,
            &upgrade.current_code_root,
            &upgrade.target_code_root,
            &upgrade.manifest_root,
            upgrade.activation_height,
        );
        upgrade.validate()?;
        Ok(upgrade)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "timelocked_contract_upgrade",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "upgrade_id": self.upgrade_id,
            "contract_id": self.contract_id,
            "current_code_root": self.current_code_root,
            "target_code_root": self.target_code_root,
            "manifest_root": self.manifest_root,
            "migration_root": self.migration_root,
            "rollback_root": self.rollback_root,
            "expected_pre_state_root": self.expected_pre_state_root,
            "expected_post_state_root": self.expected_post_state_root,
            "safety_case_root": self.safety_case_root,
            "activation_height": self.activation_height,
            "min_delay_blocks": self.min_delay_blocks,
            "requires_pause": self.requires_pause,
        })
    }

    pub fn upgrade_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-CONTRACT-UPGRADE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.contract_id, "contract upgrade contract id")?;
        validate_nonempty(
            &self.current_code_root,
            "contract upgrade current code root",
        )?;
        validate_nonempty(&self.target_code_root, "contract upgrade target code root")?;
        validate_nonempty(&self.manifest_root, "contract upgrade manifest root")?;
        validate_nonempty(&self.migration_root, "contract upgrade migration root")?;
        validate_nonempty(&self.rollback_root, "contract upgrade rollback root")?;
        validate_nonempty(
            &self.expected_pre_state_root,
            "contract upgrade expected pre-state root",
        )?;
        validate_nonempty(
            &self.expected_post_state_root,
            "contract upgrade expected post-state root",
        )?;
        validate_nonempty(&self.safety_case_root, "contract upgrade safety case root")?;
        if self.current_code_root == self.target_code_root {
            return Err("contract upgrade target code root must differ".to_string());
        }
        if self.min_delay_blocks == 0 {
            return Err("contract upgrade delay cannot be zero".to_string());
        }
        let expected_id = private_governance_contract_upgrade_id(
            &self.contract_id,
            &self.current_code_root,
            &self.target_code_root,
            &self.manifest_root,
            self.activation_height,
        );
        if self.upgrade_id != expected_id {
            return Err("contract upgrade id mismatch".to_string());
        }
        Ok(self.upgrade_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterUpgradeChange {
    pub change_id: String,
    pub module: String,
    pub key: String,
    pub previous_value_root: String,
    pub next_value_root: String,
    pub bounds_root: String,
    pub reason_root: String,
}

impl ParameterUpgradeChange {
    pub fn new(
        module: impl Into<String>,
        key: impl Into<String>,
        previous_value: &Value,
        next_value: &Value,
        bounds_root: impl Into<String>,
        reason_root: impl Into<String>,
    ) -> PrivateGovernanceResult<Self> {
        let module = module.into();
        let key = key.into();
        let previous_value_root =
            private_governance_payload_root("PRIVATE-GOVERNANCE-PARAMETER-OLD", previous_value);
        let next_value_root =
            private_governance_payload_root("PRIVATE-GOVERNANCE-PARAMETER-NEW", next_value);
        let bounds_root = bounds_root.into();
        let reason_root = reason_root.into();
        let change_id = private_governance_parameter_change_id(
            &module,
            &key,
            &previous_value_root,
            &next_value_root,
            &bounds_root,
            &reason_root,
        );
        let change = Self {
            change_id,
            module,
            key,
            previous_value_root,
            next_value_root,
            bounds_root,
            reason_root,
        };
        change.validate()?;
        Ok(change)
    }

    pub fn parameter_key(&self) -> String {
        private_governance_parameter_key(&self.module, &self.key)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parameter_upgrade_change",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "change_id": self.change_id,
            "parameter_key": self.parameter_key(),
            "module": self.module,
            "key": self.key,
            "previous_value_root": self.previous_value_root,
            "next_value_root": self.next_value_root,
            "bounds_root": self.bounds_root,
            "reason_root": self.reason_root,
        })
    }

    pub fn change_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-PARAMETER-CHANGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.module, "parameter change module")?;
        validate_nonempty(&self.key, "parameter change key")?;
        validate_nonempty(&self.previous_value_root, "parameter previous value root")?;
        validate_nonempty(&self.next_value_root, "parameter next value root")?;
        validate_nonempty(&self.bounds_root, "parameter bounds root")?;
        validate_nonempty(&self.reason_root, "parameter reason root")?;
        if self.previous_value_root == self.next_value_root {
            return Err("parameter change must alter committed value".to_string());
        }
        let expected_id = private_governance_parameter_change_id(
            &self.module,
            &self.key,
            &self.previous_value_root,
            &self.next_value_root,
            &self.bounds_root,
            &self.reason_root,
        );
        if self.change_id != expected_id {
            return Err("parameter change id mismatch".to_string());
        }
        Ok(self.change_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockedParameterUpgrade {
    pub upgrade_id: String,
    pub changes: Vec<ParameterUpgradeChange>,
    pub change_root: String,
    pub activation_height: u64,
    pub min_delay_blocks: u64,
    pub aggregate_reason_root: String,
}

impl TimelockedParameterUpgrade {
    pub fn new(
        changes: Vec<ParameterUpgradeChange>,
        activation_height: u64,
        min_delay_blocks: u64,
        aggregate_reason_root: impl Into<String>,
    ) -> PrivateGovernanceResult<Self> {
        let change_root = parameter_change_root(&changes);
        let aggregate_reason_root = aggregate_reason_root.into();
        let upgrade_id = private_governance_parameter_upgrade_id(
            &change_root,
            activation_height,
            min_delay_blocks,
            &aggregate_reason_root,
        );
        let upgrade = Self {
            upgrade_id,
            changes,
            change_root,
            activation_height,
            min_delay_blocks,
            aggregate_reason_root,
        };
        upgrade.validate()?;
        Ok(upgrade)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "timelocked_parameter_upgrade",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "upgrade_id": self.upgrade_id,
            "change_root": self.change_root,
            "change_count": self.changes.len(),
            "changes": self.changes.iter().map(ParameterUpgradeChange::public_record).collect::<Vec<_>>(),
            "activation_height": self.activation_height,
            "min_delay_blocks": self.min_delay_blocks,
            "aggregate_reason_root": self.aggregate_reason_root,
        })
    }

    pub fn upgrade_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-PARAMETER-UPGRADE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        if self.changes.is_empty() {
            return Err("parameter upgrade requires at least one change".to_string());
        }
        if self.changes.len() > PRIVATE_GOVERNANCE_MAX_PARAMETER_CHANGES {
            return Err("parameter upgrade has too many changes".to_string());
        }
        validate_nonempty(&self.change_root, "parameter upgrade change root")?;
        validate_nonempty(
            &self.aggregate_reason_root,
            "parameter upgrade aggregate reason root",
        )?;
        if self.min_delay_blocks == 0 {
            return Err("parameter upgrade delay cannot be zero".to_string());
        }
        let mut seen = BTreeSet::new();
        for change in &self.changes {
            change.validate()?;
            if !seen.insert(change.parameter_key()) {
                return Err("parameter upgrade includes duplicate parameter".to_string());
            }
        }
        if self.change_root != parameter_change_root(&self.changes) {
            return Err("parameter upgrade change root mismatch".to_string());
        }
        let expected_id = private_governance_parameter_upgrade_id(
            &self.change_root,
            self.activation_height,
            self.min_delay_blocks,
            &self.aggregate_reason_root,
        );
        if self.upgrade_id != expected_id {
            return Err("parameter upgrade id mismatch".to_string());
        }
        Ok(self.upgrade_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeePolicy {
    pub policy_id: String,
    pub fee_asset_id: String,
    pub base_fee_micro_units: u64,
    pub priority_multiplier_bps: u64,
    pub shielded_action_fee_units: u64,
    pub proof_fee_per_kib_units: u64,
    pub disclosure_fee_units: u64,
    pub treasury_share_bps: u64,
    pub burn_share_bps: u64,
    pub effective_height: u64,
}

impl Default for PrivateFeePolicy {
    fn default() -> Self {
        let mut policy = Self {
            policy_id: String::new(),
            fee_asset_id: PRIVATE_GOVERNANCE_DEFAULT_FEE_ASSET_ID.to_string(),
            base_fee_micro_units: 1_000,
            priority_multiplier_bps: 12_500,
            shielded_action_fee_units: 500,
            proof_fee_per_kib_units: 250,
            disclosure_fee_units: 50,
            treasury_share_bps: 2_000,
            burn_share_bps: 1_000,
            effective_height: 0,
        };
        policy.policy_id = private_governance_fee_policy_id(
            &policy.fee_asset_id,
            policy.base_fee_micro_units,
            policy.priority_multiplier_bps,
            policy.effective_height,
        );
        policy
    }
}

impl PrivateFeePolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_governance_fee_policy",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "fee_asset_id": self.fee_asset_id,
            "base_fee_micro_units": self.base_fee_micro_units,
            "priority_multiplier_bps": self.priority_multiplier_bps,
            "shielded_action_fee_units": self.shielded_action_fee_units,
            "proof_fee_per_kib_units": self.proof_fee_per_kib_units,
            "disclosure_fee_units": self.disclosure_fee_units,
            "treasury_share_bps": self.treasury_share_bps,
            "burn_share_bps": self.burn_share_bps,
            "effective_height": self.effective_height,
        })
    }

    pub fn policy_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-FEE-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.fee_asset_id, "private fee asset id")?;
        if self.priority_multiplier_bps == 0 {
            return Err("private fee priority multiplier cannot be zero".to_string());
        }
        if self.priority_multiplier_bps > 100_000 {
            return Err("private fee priority multiplier exceeds safety cap".to_string());
        }
        validate_bps(self.treasury_share_bps, "private fee treasury share")?;
        validate_bps(self.burn_share_bps, "private fee burn share")?;
        if self.treasury_share_bps.saturating_add(self.burn_share_bps) > 10_000 {
            return Err("private fee treasury and burn shares exceed total".to_string());
        }
        let expected_id = private_governance_fee_policy_id(
            &self.fee_asset_id,
            self.base_fee_micro_units,
            self.priority_multiplier_bps,
            self.effective_height,
        );
        if self.policy_id != expected_id {
            return Err("private fee policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumMigrationStep {
    pub step_id: String,
    pub role: String,
    pub source_scheme: String,
    pub target_scheme: String,
    pub source_key_root: String,
    pub target_key_root: String,
    pub starts_at_height: u64,
    pub dual_authorization_required: bool,
    pub witness_root: String,
}

impl QuantumMigrationStep {
    pub fn new(
        role: impl Into<String>,
        source_scheme: impl Into<String>,
        target_scheme: impl Into<String>,
        source_key_root: impl Into<String>,
        target_key_root: impl Into<String>,
        starts_at_height: u64,
        dual_authorization_required: bool,
        witness_root: impl Into<String>,
    ) -> PrivateGovernanceResult<Self> {
        let role = role.into();
        let source_scheme = source_scheme.into();
        let target_scheme = target_scheme.into();
        let source_key_root = source_key_root.into();
        let target_key_root = target_key_root.into();
        let witness_root = witness_root.into();
        let step_id = private_governance_quantum_migration_step_id(
            &role,
            &source_scheme,
            &target_scheme,
            &source_key_root,
            &target_key_root,
            starts_at_height,
        );
        let step = Self {
            step_id,
            role,
            source_scheme,
            target_scheme,
            source_key_root,
            target_key_root,
            starts_at_height,
            dual_authorization_required,
            witness_root,
        };
        step.validate()?;
        Ok(step)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_migration_step",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "step_id": self.step_id,
            "role": self.role,
            "source_scheme": self.source_scheme,
            "target_scheme": self.target_scheme,
            "source_key_root": self.source_key_root,
            "target_key_root": self.target_key_root,
            "starts_at_height": self.starts_at_height,
            "dual_authorization_required": self.dual_authorization_required,
            "witness_root": self.witness_root,
        })
    }

    pub fn step_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-QUANTUM-MIGRATION-STEP",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.role, "quantum migration role")?;
        validate_nonempty(&self.source_scheme, "quantum migration source scheme")?;
        validate_nonempty(&self.target_scheme, "quantum migration target scheme")?;
        validate_nonempty(&self.source_key_root, "quantum migration source key root")?;
        validate_nonempty(&self.target_key_root, "quantum migration target key root")?;
        validate_nonempty(&self.witness_root, "quantum migration witness root")?;
        if self.source_scheme == self.target_scheme {
            return Err("quantum migration target scheme must differ".to_string());
        }
        let expected_id = private_governance_quantum_migration_step_id(
            &self.role,
            &self.source_scheme,
            &self.target_scheme,
            &self.source_key_root,
            &self.target_key_root,
            self.starts_at_height,
        );
        if self.step_id != expected_id {
            return Err("quantum migration step id mismatch".to_string());
        }
        Ok(self.step_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumMigrationBallot {
    pub ballot_id: String,
    pub migration_name: String,
    pub source_policy_root: String,
    pub target_policy_root: String,
    pub step_root: String,
    pub steps: Vec<QuantumMigrationStep>,
    pub ballot_commitment_root: String,
    pub activation_height: u64,
    pub rollback_root: String,
}

impl QuantumMigrationBallot {
    pub fn new(
        migration_name: impl Into<String>,
        source_policy_root: impl Into<String>,
        target_policy_root: impl Into<String>,
        steps: Vec<QuantumMigrationStep>,
        ballot_commitment_root: impl Into<String>,
        activation_height: u64,
        rollback_root: impl Into<String>,
    ) -> PrivateGovernanceResult<Self> {
        let migration_name = migration_name.into();
        let source_policy_root = source_policy_root.into();
        let target_policy_root = target_policy_root.into();
        let ballot_commitment_root = ballot_commitment_root.into();
        let rollback_root = rollback_root.into();
        let step_root = quantum_migration_step_root(&steps);
        let ballot_id = private_governance_quantum_migration_ballot_id(
            &migration_name,
            &source_policy_root,
            &target_policy_root,
            &step_root,
            activation_height,
        );
        let ballot = Self {
            ballot_id,
            migration_name,
            source_policy_root,
            target_policy_root,
            step_root,
            steps,
            ballot_commitment_root,
            activation_height,
            rollback_root,
        };
        ballot.validate()?;
        Ok(ballot)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_migration_ballot",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "ballot_id": self.ballot_id,
            "migration_name": self.migration_name,
            "source_policy_root": self.source_policy_root,
            "target_policy_root": self.target_policy_root,
            "step_root": self.step_root,
            "step_count": self.steps.len(),
            "steps": self.steps.iter().map(QuantumMigrationStep::public_record).collect::<Vec<_>>(),
            "ballot_commitment_root": self.ballot_commitment_root,
            "activation_height": self.activation_height,
            "rollback_root": self.rollback_root,
        })
    }

    pub fn ballot_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-QUANTUM-MIGRATION-BALLOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.migration_name, "quantum migration name")?;
        validate_nonempty(
            &self.source_policy_root,
            "quantum migration source policy root",
        )?;
        validate_nonempty(
            &self.target_policy_root,
            "quantum migration target policy root",
        )?;
        validate_nonempty(&self.step_root, "quantum migration step root")?;
        validate_nonempty(
            &self.ballot_commitment_root,
            "quantum migration ballot commitment root",
        )?;
        validate_nonempty(&self.rollback_root, "quantum migration rollback root")?;
        if self.source_policy_root == self.target_policy_root {
            return Err("quantum migration target policy must differ".to_string());
        }
        if self.steps.is_empty() {
            return Err("quantum migration requires at least one step".to_string());
        }
        if self.steps.len() > PRIVATE_GOVERNANCE_MAX_MIGRATION_STEPS {
            return Err("quantum migration has too many steps".to_string());
        }
        let mut seen = BTreeSet::new();
        for step in &self.steps {
            step.validate()?;
            if !seen.insert(step.step_id.clone()) {
                return Err("quantum migration step appears more than once".to_string());
            }
        }
        if self.step_root != quantum_migration_step_root(&self.steps) {
            return Err("quantum migration step root mismatch".to_string());
        }
        let expected_id = private_governance_quantum_migration_ballot_id(
            &self.migration_name,
            &self.source_policy_root,
            &self.target_policy_root,
            &self.step_root,
            self.activation_height,
        );
        if self.ballot_id != expected_id {
            return Err("quantum migration ballot id mismatch".to_string());
        }
        Ok(self.ballot_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetDisclosure {
    pub disclosure_id: String,
    pub subject_commitment: String,
    pub budget_scope: String,
    pub epoch: u64,
    pub limit_units: u64,
    pub consumed_units: u64,
    pub remaining_units: u64,
    pub proof_root: String,
    pub auditor_commitment: String,
    pub disclosure_salt_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyBudgetDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_commitment: impl Into<String>,
        budget_scope: impl Into<String>,
        epoch: u64,
        limit_units: u64,
        consumed_units: u64,
        proof_root: impl Into<String>,
        auditor_commitment: impl Into<String>,
        disclosure_salt_root: impl Into<String>,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateGovernanceResult<Self> {
        let subject_commitment = subject_commitment.into();
        let budget_scope = budget_scope.into();
        let proof_root = proof_root.into();
        let auditor_commitment = auditor_commitment.into();
        let disclosure_salt_root = disclosure_salt_root.into();
        let remaining_units = limit_units.saturating_sub(consumed_units);
        let disclosure_id = private_governance_privacy_disclosure_id(
            &subject_commitment,
            &budget_scope,
            epoch,
            &proof_root,
            &disclosure_salt_root,
        );
        let disclosure = Self {
            disclosure_id,
            subject_commitment,
            budget_scope,
            epoch,
            limit_units,
            consumed_units,
            remaining_units,
            proof_root,
            auditor_commitment,
            disclosure_salt_root,
            opened_at_height,
            expires_at_height,
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_disclosure",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "subject_commitment": self.subject_commitment,
            "budget_scope": self.budget_scope,
            "epoch": self.epoch,
            "limit_units": self.limit_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units,
            "proof_root": self.proof_root,
            "auditor_commitment": self.auditor_commitment,
            "disclosure_salt_root": self.disclosure_salt_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn disclosure_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-PRIVACY-BUDGET-DISCLOSURE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(
            &self.subject_commitment,
            "privacy disclosure subject commitment",
        )?;
        validate_nonempty(&self.budget_scope, "privacy disclosure budget scope")?;
        validate_nonempty(&self.proof_root, "privacy disclosure proof root")?;
        validate_nonempty(
            &self.auditor_commitment,
            "privacy disclosure auditor commitment",
        )?;
        validate_nonempty(&self.disclosure_salt_root, "privacy disclosure salt root")?;
        if self.consumed_units > self.limit_units {
            return Err("privacy disclosure consumed units exceed limit".to_string());
        }
        if self.remaining_units != self.limit_units.saturating_sub(self.consumed_units) {
            return Err("privacy disclosure remaining units mismatch".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.opened_at_height {
            return Err("privacy disclosure expiry must be after opening".to_string());
        }
        let expected_id = private_governance_privacy_disclosure_id(
            &self.subject_commitment,
            &self.budget_scope,
            self.epoch,
            &self.proof_root,
            &self.disclosure_salt_root,
        );
        if self.disclosure_id != expected_id {
            return Err("privacy disclosure id mismatch".to_string());
        }
        Ok(self.disclosure_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyVeto {
    pub veto_id: String,
    pub target_proposal_id: String,
    pub veto_committee_id: String,
    pub scope: String,
    pub reason_root: String,
    pub evidence_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub freezes_execution_until_height: u64,
    pub status: String,
}

impl EmergencyVeto {
    pub fn new(
        target_proposal_id: impl Into<String>,
        veto_committee_id: impl Into<String>,
        scope: impl Into<String>,
        reason_root: impl Into<String>,
        evidence_root: impl Into<String>,
        activated_at_height: u64,
        freeze_blocks: u64,
    ) -> PrivateGovernanceResult<Self> {
        let target_proposal_id = target_proposal_id.into();
        let veto_committee_id = veto_committee_id.into();
        let scope = scope.into();
        let reason_root = reason_root.into();
        let evidence_root = evidence_root.into();
        let freezes_execution_until_height = activated_at_height.saturating_add(freeze_blocks);
        let expires_at_height = freezes_execution_until_height;
        let veto_id = private_governance_emergency_veto_id(
            &target_proposal_id,
            &veto_committee_id,
            &scope,
            &reason_root,
            activated_at_height,
        );
        let veto = Self {
            veto_id,
            target_proposal_id,
            veto_committee_id,
            scope,
            reason_root,
            evidence_root,
            activated_at_height,
            expires_at_height,
            freezes_execution_until_height,
            status: "active".to_string(),
        };
        veto.validate()?;
        Ok(veto)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == "active"
            && self.activated_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_veto",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "veto_id": self.veto_id,
            "target_proposal_id": self.target_proposal_id,
            "veto_committee_id": self.veto_committee_id,
            "scope": self.scope,
            "reason_root": self.reason_root,
            "evidence_root": self.evidence_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "freezes_execution_until_height": self.freezes_execution_until_height,
            "status": self.status,
        })
    }

    pub fn veto_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-EMERGENCY-VETO",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(
            &self.target_proposal_id,
            "emergency veto target proposal id",
        )?;
        validate_nonempty(&self.veto_committee_id, "emergency veto committee id")?;
        validate_nonempty(&self.scope, "emergency veto scope")?;
        validate_nonempty(&self.reason_root, "emergency veto reason root")?;
        validate_nonempty(&self.evidence_root, "emergency veto evidence root")?;
        validate_status(
            &self.status,
            &["active", "expired", "lifted"],
            "emergency veto",
        )?;
        if self.expires_at_height != 0 && self.expires_at_height < self.activated_at_height {
            return Err("emergency veto expiry cannot precede activation".to_string());
        }
        if self.freezes_execution_until_height < self.activated_at_height {
            return Err("emergency veto freeze cannot precede activation".to_string());
        }
        let expected_id = private_governance_emergency_veto_id(
            &self.target_proposal_id,
            &self.veto_committee_id,
            &self.scope,
            &self.reason_root,
            self.activated_at_height,
        );
        if self.veto_id != expected_id {
            return Err("emergency veto id mismatch".to_string());
        }
        Ok(self.veto_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateGovernanceAction {
    TimelockedContractUpgrade { upgrade: TimelockedContractUpgrade },
    TimelockedParameterUpgrade { upgrade: TimelockedParameterUpgrade },
    FeePolicyChange { policy: PrivateFeePolicy },
    QuantumMigrationBallot { ballot: QuantumMigrationBallot },
    PrivacyBudgetDisclosure { disclosure: PrivacyBudgetDisclosure },
    EmergencyVeto { veto: EmergencyVeto },
}

impl PrivateGovernanceAction {
    pub fn proposal_kind(&self) -> PrivateGovernanceProposalKind {
        match self {
            Self::TimelockedContractUpgrade { .. } => {
                PrivateGovernanceProposalKind::TimelockedContractUpgrade
            }
            Self::TimelockedParameterUpgrade { .. } => {
                PrivateGovernanceProposalKind::TimelockedParameterUpgrade
            }
            Self::FeePolicyChange { .. } => PrivateGovernanceProposalKind::FeePolicyChange,
            Self::QuantumMigrationBallot { .. } => {
                PrivateGovernanceProposalKind::QuantumMigrationBallot
            }
            Self::PrivacyBudgetDisclosure { .. } => {
                PrivateGovernanceProposalKind::PrivacyBudgetDisclosure
            }
            Self::EmergencyVeto { .. } => PrivateGovernanceProposalKind::EmergencyVeto,
        }
    }

    pub fn earliest_activation_height(&self) -> u64 {
        match self {
            Self::TimelockedContractUpgrade { upgrade } => upgrade.activation_height,
            Self::TimelockedParameterUpgrade { upgrade } => upgrade.activation_height,
            Self::FeePolicyChange { policy } => policy.effective_height,
            Self::QuantumMigrationBallot { ballot } => ballot.activation_height,
            Self::PrivacyBudgetDisclosure { disclosure } => disclosure.opened_at_height,
            Self::EmergencyVeto { veto } => veto.activated_at_height,
        }
    }

    pub fn min_delay_blocks(&self, policy: &PrivateGovernancePolicy) -> u64 {
        match self {
            Self::TimelockedContractUpgrade { upgrade } => upgrade.min_delay_blocks,
            Self::TimelockedParameterUpgrade { upgrade } => upgrade.min_delay_blocks,
            Self::FeePolicyChange { .. } => policy.default_timelock_blocks,
            Self::QuantumMigrationBallot { .. } => policy.contract_timelock_blocks,
            Self::PrivacyBudgetDisclosure { .. } => 0,
            Self::EmergencyVeto { .. } => 0,
        }
    }

    pub fn public_record(&self) -> Value {
        match self {
            Self::TimelockedContractUpgrade { upgrade } => json!({
                "kind": PrivateGovernanceProposalKind::TimelockedContractUpgrade.as_str(),
                "chain_id": CHAIN_ID,
                "upgrade": upgrade.public_record(),
            }),
            Self::TimelockedParameterUpgrade { upgrade } => json!({
                "kind": PrivateGovernanceProposalKind::TimelockedParameterUpgrade.as_str(),
                "chain_id": CHAIN_ID,
                "upgrade": upgrade.public_record(),
            }),
            Self::FeePolicyChange { policy } => json!({
                "kind": PrivateGovernanceProposalKind::FeePolicyChange.as_str(),
                "chain_id": CHAIN_ID,
                "policy": policy.public_record(),
            }),
            Self::QuantumMigrationBallot { ballot } => json!({
                "kind": PrivateGovernanceProposalKind::QuantumMigrationBallot.as_str(),
                "chain_id": CHAIN_ID,
                "ballot": ballot.public_record(),
            }),
            Self::PrivacyBudgetDisclosure { disclosure } => json!({
                "kind": PrivateGovernanceProposalKind::PrivacyBudgetDisclosure.as_str(),
                "chain_id": CHAIN_ID,
                "disclosure": disclosure.public_record(),
            }),
            Self::EmergencyVeto { veto } => json!({
                "kind": PrivateGovernanceProposalKind::EmergencyVeto.as_str(),
                "chain_id": CHAIN_ID,
                "veto": veto.public_record(),
            }),
        }
    }

    pub fn action_root(&self) -> String {
        private_governance_action_root(self)
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        match self {
            Self::TimelockedContractUpgrade { upgrade } => upgrade.validate()?,
            Self::TimelockedParameterUpgrade { upgrade } => upgrade.validate()?,
            Self::FeePolicyChange { policy } => policy.validate()?,
            Self::QuantumMigrationBallot { ballot } => ballot.validate()?,
            Self::PrivacyBudgetDisclosure { disclosure } => disclosure.validate()?,
            Self::EmergencyVeto { veto } => veto.validate()?,
        };
        Ok(self.action_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedGovernanceProposal {
    pub proposal_id: String,
    pub proposal_nonce: u64,
    pub proposal_kind: PrivateGovernanceProposalKind,
    pub committee_id: String,
    pub proposer_commitment: String,
    pub encrypted_payload_root: String,
    pub public_summary_root: String,
    pub privacy_budget_root: String,
    pub action: PrivateGovernanceAction,
    pub action_root: String,
    pub created_at_height: u64,
    pub voting_starts_at_height: u64,
    pub voting_ends_at_height: u64,
    pub earliest_execution_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_blocks: u64,
    pub status: String,
}

impl ShieldedGovernanceProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_nonce: u64,
        committee_id: impl Into<String>,
        proposer_commitment: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        public_summary_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        action: PrivateGovernanceAction,
        created_at_height: u64,
        vote_window_blocks: u64,
        policy: &PrivateGovernancePolicy,
    ) -> PrivateGovernanceResult<Self> {
        let committee_id = committee_id.into();
        let proposer_commitment = proposer_commitment.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let public_summary_root = public_summary_root.into();
        let privacy_budget_root = privacy_budget_root.into();
        action.validate()?;
        let proposal_kind = action.proposal_kind();
        let action_root = action.action_root();
        let voting_starts_at_height = created_at_height;
        let voting_ends_at_height = created_at_height.saturating_add(vote_window_blocks);
        let earliest_execution_height = voting_ends_at_height
            .saturating_add(action.min_delay_blocks(policy))
            .max(action.earliest_activation_height());
        let expires_at_height =
            earliest_execution_height.saturating_add(policy.execution_window_blocks);
        let proposal_id = private_governance_proposal_id(
            proposal_nonce,
            &committee_id,
            &proposer_commitment,
            proposal_kind.as_str(),
            &action_root,
        );
        let proposal = Self {
            proposal_id,
            proposal_nonce,
            proposal_kind,
            committee_id,
            proposer_commitment,
            encrypted_payload_root,
            public_summary_root,
            privacy_budget_root,
            action,
            action_root,
            created_at_height,
            voting_starts_at_height,
            voting_ends_at_height,
            earliest_execution_height,
            expires_at_height,
            challenge_window_blocks: policy.challenge_window_blocks,
            status: "open".to_string(),
        };
        proposal.validate(policy)?;
        Ok(proposal)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "shielded_governance_proposal",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "proposal_id": self.proposal_id,
            "proposal_nonce": self.proposal_nonce,
            "proposal_kind": self.proposal_kind.as_str(),
            "committee_id": self.committee_id,
            "proposer_commitment": self.proposer_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "public_summary_root": self.public_summary_root,
            "privacy_budget_root": self.privacy_budget_root,
            "action_root": self.action_root,
            "action": self.action.public_record(),
            "created_at_height": self.created_at_height,
            "voting_starts_at_height": self.voting_starts_at_height,
            "voting_ends_at_height": self.voting_ends_at_height,
            "earliest_execution_height": self.earliest_execution_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "status": self.status,
        })
    }

    pub fn proposal_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-PROPOSAL",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["proposal_root"] = Value::String(self.proposal_root());
        record
    }

    pub fn validate(&self, policy: &PrivateGovernancePolicy) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.committee_id, "proposal committee id")?;
        validate_nonempty(&self.proposer_commitment, "proposal proposer commitment")?;
        validate_nonempty(
            &self.encrypted_payload_root,
            "proposal encrypted payload root",
        )?;
        validate_nonempty(&self.public_summary_root, "proposal public summary root")?;
        validate_nonempty(&self.privacy_budget_root, "proposal privacy budget root")?;
        validate_nonempty(&self.action_root, "proposal action root")?;
        validate_status(
            &self.status,
            &[
                "open", "passed", "rejected", "executed", "expired", "vetoed",
            ],
            "proposal",
        )?;
        if self.proposal_kind != self.action.proposal_kind() {
            return Err("proposal kind does not match action".to_string());
        }
        if self.action_root != self.action.action_root() {
            return Err("proposal action root mismatch".to_string());
        }
        let vote_window = self
            .voting_ends_at_height
            .saturating_sub(self.voting_starts_at_height);
        if vote_window < policy.min_vote_window_blocks {
            return Err("proposal vote window below minimum".to_string());
        }
        if vote_window > policy.max_vote_window_blocks {
            return Err("proposal vote window exceeds maximum".to_string());
        }
        if self.voting_starts_at_height < self.created_at_height {
            return Err("proposal voting cannot start before creation".to_string());
        }
        if self.earliest_execution_height < self.voting_ends_at_height {
            return Err("proposal execution cannot precede voting end".to_string());
        }
        if self.expires_at_height <= self.earliest_execution_height {
            return Err("proposal expiry must follow earliest execution".to_string());
        }
        let expected_id = private_governance_proposal_id(
            self.proposal_nonce,
            &self.committee_id,
            &self.proposer_commitment,
            self.proposal_kind.as_str(),
            &self.action_root,
        );
        if self.proposal_id != expected_id {
            return Err("proposal id mismatch".to_string());
        }
        Ok(self.proposal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedGovernanceVote {
    pub vote_id: String,
    pub proposal_id: String,
    pub committee_id: String,
    pub voter_nullifier: String,
    pub choice: PrivateVoteChoice,
    pub vote_weight: u64,
    pub weight_commitment: String,
    pub encrypted_vote_root: String,
    pub pq_authorization_root: String,
    pub cast_at_height: u64,
}

impl ShieldedGovernanceVote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        committee_id: impl Into<String>,
        voter_secret_root: impl Into<String>,
        choice: PrivateVoteChoice,
        vote_weight: u64,
        encrypted_vote_root: impl Into<String>,
        pq_authorization_root: impl Into<String>,
        cast_at_height: u64,
    ) -> PrivateGovernanceResult<Self> {
        let proposal_id = proposal_id.into();
        let committee_id = committee_id.into();
        let voter_secret_root = voter_secret_root.into();
        let encrypted_vote_root = encrypted_vote_root.into();
        let pq_authorization_root = pq_authorization_root.into();
        let voter_nullifier = private_governance_vote_nullifier(&proposal_id, &voter_secret_root);
        let weight_commitment =
            private_governance_weight_commitment(&proposal_id, &voter_nullifier, vote_weight);
        let vote_id = private_governance_vote_id(
            &proposal_id,
            &voter_nullifier,
            choice.as_str(),
            &weight_commitment,
        );
        let vote = Self {
            vote_id,
            proposal_id,
            committee_id,
            voter_nullifier,
            choice,
            vote_weight,
            weight_commitment,
            encrypted_vote_root,
            pq_authorization_root,
            cast_at_height,
        };
        vote.validate()?;
        Ok(vote)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_governance_vote",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "committee_id": self.committee_id,
            "voter_nullifier": self.voter_nullifier,
            "choice": self.choice.as_str(),
            "vote_weight": self.vote_weight,
            "weight_commitment": self.weight_commitment,
            "encrypted_vote_root": self.encrypted_vote_root,
            "pq_authorization_root": self.pq_authorization_root,
            "cast_at_height": self.cast_at_height,
        })
    }

    pub fn vote_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-VOTE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.proposal_id, "vote proposal id")?;
        validate_nonempty(&self.committee_id, "vote committee id")?;
        validate_nonempty(&self.voter_nullifier, "vote voter nullifier")?;
        validate_nonempty(&self.weight_commitment, "vote weight commitment")?;
        validate_nonempty(&self.encrypted_vote_root, "vote encrypted root")?;
        validate_nonempty(&self.pq_authorization_root, "vote pq authorization root")?;
        if self.vote_weight == 0 {
            return Err("vote weight cannot be zero".to_string());
        }
        let expected_weight_commitment = private_governance_weight_commitment(
            &self.proposal_id,
            &self.voter_nullifier,
            self.vote_weight,
        );
        if self.weight_commitment != expected_weight_commitment {
            return Err("vote weight commitment mismatch".to_string());
        }
        let expected_vote_id = private_governance_vote_id(
            &self.proposal_id,
            &self.voter_nullifier,
            self.choice.as_str(),
            &self.weight_commitment,
        );
        if self.vote_id != expected_vote_id {
            return Err("vote id mismatch".to_string());
        }
        Ok(self.vote_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernanceTally {
    pub tally_id: String,
    pub proposal_id: String,
    pub committee_id: String,
    pub vote_root: String,
    pub approve_weight: u64,
    pub reject_weight: u64,
    pub abstain_weight: u64,
    pub veto_weight: u64,
    pub participating_weight: u64,
    pub committee_weight: u64,
    pub quorum_bps: u64,
    pub approval_bps: u64,
    pub veto_bps: u64,
    pub quorum_met: bool,
    pub approval_met: bool,
    pub veto_met: bool,
    pub passed: bool,
    pub tallied_at_height: u64,
}

impl PrivateGovernanceTally {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        committee_id: impl Into<String>,
        vote_root: impl Into<String>,
        approve_weight: u64,
        reject_weight: u64,
        abstain_weight: u64,
        veto_weight: u64,
        committee_weight: u64,
        quorum_bps: u64,
        approval_bps: u64,
        veto_bps: u64,
        tallied_at_height: u64,
    ) -> PrivateGovernanceResult<Self> {
        let proposal_id = proposal_id.into();
        let committee_id = committee_id.into();
        let vote_root = vote_root.into();
        let participating_weight = approve_weight
            .saturating_add(reject_weight)
            .saturating_add(abstain_weight)
            .saturating_add(veto_weight);
        let quorum_met = participating_weight >= bps_threshold(committee_weight, quorum_bps);
        let decisive_weight = approve_weight.saturating_add(reject_weight);
        let approval_met =
            decisive_weight > 0 && approve_weight >= bps_threshold(decisive_weight, approval_bps);
        let veto_met = veto_weight >= bps_threshold(committee_weight, veto_bps);
        let passed = quorum_met && approval_met && !veto_met;
        let tally_id =
            private_governance_tally_id(&proposal_id, &vote_root, tallied_at_height, passed);
        let tally = Self {
            tally_id,
            proposal_id,
            committee_id,
            vote_root,
            approve_weight,
            reject_weight,
            abstain_weight,
            veto_weight,
            participating_weight,
            committee_weight,
            quorum_bps,
            approval_bps,
            veto_bps,
            quorum_met,
            approval_met,
            veto_met,
            passed,
            tallied_at_height,
        };
        tally.validate()?;
        Ok(tally)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_governance_tally",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "tally_id": self.tally_id,
            "proposal_id": self.proposal_id,
            "committee_id": self.committee_id,
            "vote_root": self.vote_root,
            "approve_weight": self.approve_weight,
            "reject_weight": self.reject_weight,
            "abstain_weight": self.abstain_weight,
            "veto_weight": self.veto_weight,
            "participating_weight": self.participating_weight,
            "committee_weight": self.committee_weight,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "veto_bps": self.veto_bps,
            "quorum_met": self.quorum_met,
            "approval_met": self.approval_met,
            "veto_met": self.veto_met,
            "passed": self.passed,
            "tallied_at_height": self.tallied_at_height,
        })
    }

    pub fn tally_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-TALLY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.proposal_id, "tally proposal id")?;
        validate_nonempty(&self.committee_id, "tally committee id")?;
        validate_nonempty(&self.vote_root, "tally vote root")?;
        validate_bps(self.quorum_bps, "tally quorum")?;
        validate_bps(self.approval_bps, "tally approval")?;
        validate_bps(self.veto_bps, "tally veto")?;
        if self.committee_weight == 0 {
            return Err("tally committee weight cannot be zero".to_string());
        }
        let expected_participating = self
            .approve_weight
            .saturating_add(self.reject_weight)
            .saturating_add(self.abstain_weight)
            .saturating_add(self.veto_weight);
        if self.participating_weight != expected_participating {
            return Err("tally participating weight mismatch".to_string());
        }
        if self.participating_weight > self.committee_weight {
            return Err("tally participating weight exceeds committee weight".to_string());
        }
        let quorum_met =
            self.participating_weight >= bps_threshold(self.committee_weight, self.quorum_bps);
        let decisive_weight = self.approve_weight.saturating_add(self.reject_weight);
        let approval_met = decisive_weight > 0
            && self.approve_weight >= bps_threshold(decisive_weight, self.approval_bps);
        let veto_met = self.veto_weight >= bps_threshold(self.committee_weight, self.veto_bps);
        if self.quorum_met != quorum_met || self.approval_met != approval_met {
            return Err("tally threshold flags mismatch".to_string());
        }
        if self.veto_met != veto_met {
            return Err("tally veto flag mismatch".to_string());
        }
        if self.passed != (self.quorum_met && self.approval_met && !self.veto_met) {
            return Err("tally pass flag mismatch".to_string());
        }
        let expected_id = private_governance_tally_id(
            &self.proposal_id,
            &self.vote_root,
            self.tallied_at_height,
            self.passed,
        );
        if self.tally_id != expected_id {
            return Err("tally id mismatch".to_string());
        }
        Ok(self.tally_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernanceExecutionReceipt {
    pub receipt_id: String,
    pub proposal_id: String,
    pub action_root: String,
    pub executor_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub effects_root: String,
    pub executed_at_height: u64,
    pub challenge_window_ends_at_height: u64,
    pub status: PrivateGovernanceExecutionStatus,
}

impl PrivateGovernanceExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        action_root: impl Into<String>,
        executor_commitment: impl Into<String>,
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
        effects_root: impl Into<String>,
        executed_at_height: u64,
        challenge_window_ends_at_height: u64,
        status: PrivateGovernanceExecutionStatus,
    ) -> PrivateGovernanceResult<Self> {
        let proposal_id = proposal_id.into();
        let action_root = action_root.into();
        let executor_commitment = executor_commitment.into();
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let effects_root = effects_root.into();
        let receipt_id = private_governance_execution_receipt_id(
            &proposal_id,
            &action_root,
            &pre_state_root,
            &post_state_root,
            executed_at_height,
        );
        let receipt = Self {
            receipt_id,
            proposal_id,
            action_root,
            executor_commitment,
            pre_state_root,
            post_state_root,
            effects_root,
            executed_at_height,
            challenge_window_ends_at_height,
            status,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_governance_execution_receipt",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "proposal_id": self.proposal_id,
            "action_root": self.action_root,
            "executor_commitment": self.executor_commitment,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "effects_root": self.effects_root,
            "executed_at_height": self.executed_at_height,
            "challenge_window_ends_at_height": self.challenge_window_ends_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-EXECUTION-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.proposal_id, "execution proposal id")?;
        validate_nonempty(&self.action_root, "execution action root")?;
        validate_nonempty(&self.executor_commitment, "execution executor commitment")?;
        validate_nonempty(&self.pre_state_root, "execution pre-state root")?;
        validate_nonempty(&self.post_state_root, "execution post-state root")?;
        validate_nonempty(&self.effects_root, "execution effects root")?;
        if self.pre_state_root == self.post_state_root {
            return Err("execution must alter state root".to_string());
        }
        if self.challenge_window_ends_at_height < self.executed_at_height {
            return Err("execution challenge window cannot end before execution".to_string());
        }
        let expected_id = private_governance_execution_receipt_id(
            &self.proposal_id,
            &self.action_root,
            &self.pre_state_root,
            &self.post_state_root,
            self.executed_at_height,
        );
        if self.receipt_id != expected_id {
            return Err("execution receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernanceChallengeWindow {
    pub challenge_id: String,
    pub proposal_id: String,
    pub receipt_id: String,
    pub challenge_kind: PrivateGovernanceChallengeKind,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub response_due_height: u64,
    pub resolved_at_height: u64,
    pub resolution_root: String,
    pub status: PrivateGovernanceChallengeStatus,
}

impl PrivateGovernanceChallengeWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        receipt_id: impl Into<String>,
        challenge_kind: PrivateGovernanceChallengeKind,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        opened_at_height: u64,
        response_due_height: u64,
    ) -> PrivateGovernanceResult<Self> {
        let proposal_id = proposal_id.into();
        let receipt_id = receipt_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        let challenge_id = private_governance_challenge_id(
            &proposal_id,
            &receipt_id,
            challenge_kind.as_str(),
            &challenger_commitment,
            &evidence_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            proposal_id,
            receipt_id,
            challenge_kind,
            challenger_commitment,
            evidence_root,
            opened_at_height,
            response_due_height,
            resolved_at_height: 0,
            resolution_root: private_governance_empty_root(
                "PRIVATE-GOVERNANCE-CHALLENGE-RESOLUTION",
            ),
            status: PrivateGovernanceChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_governance_challenge_window",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "proposal_id": self.proposal_id,
            "receipt_id": self.receipt_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "response_due_height": self.response_due_height,
            "resolved_at_height": self.resolved_at_height,
            "resolution_root": self.resolution_root,
            "status": self.status.as_str(),
        })
    }

    pub fn challenge_root(&self) -> String {
        domain_hash(
            "PRIVATE-GOVERNANCE-CHALLENGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn resolve(
        &mut self,
        status: PrivateGovernanceChallengeStatus,
        resolution_root: impl Into<String>,
        resolved_at_height: u64,
    ) -> PrivateGovernanceResult<String> {
        if status == PrivateGovernanceChallengeStatus::Open {
            return Err("challenge resolution cannot remain open".to_string());
        }
        self.status = status;
        self.resolution_root = resolution_root.into();
        self.resolved_at_height = resolved_at_height;
        self.validate()
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        validate_nonempty(&self.proposal_id, "challenge proposal id")?;
        validate_nonempty(&self.receipt_id, "challenge receipt id")?;
        validate_nonempty(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        validate_nonempty(&self.evidence_root, "challenge evidence root")?;
        validate_nonempty(&self.resolution_root, "challenge resolution root")?;
        if self.response_due_height <= self.opened_at_height {
            return Err("challenge response height must follow opening".to_string());
        }
        if self.status != PrivateGovernanceChallengeStatus::Open
            && self.resolved_at_height < self.opened_at_height
        {
            return Err("challenge resolution cannot precede opening".to_string());
        }
        let expected_id = private_governance_challenge_id(
            &self.proposal_id,
            &self.receipt_id,
            self.challenge_kind.as_str(),
            &self.challenger_commitment,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.challenge_id != expected_id {
            return Err("challenge id mismatch".to_string());
        }
        Ok(self.challenge_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernanceStateRoots {
    pub policy_root: String,
    pub committee_root: String,
    pub proposal_root: String,
    pub vote_root: String,
    pub tally_root: String,
    pub contract_upgrade_root: String,
    pub parameter_upgrade_root: String,
    pub fee_policy_root: String,
    pub quantum_migration_root: String,
    pub privacy_disclosure_root: String,
    pub emergency_veto_root: String,
    pub execution_receipt_root: String,
    pub challenge_root: String,
}

impl PrivateGovernanceStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_governance_state_roots",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "policy_root": self.policy_root,
            "committee_root": self.committee_root,
            "proposal_root": self.proposal_root,
            "vote_root": self.vote_root,
            "tally_root": self.tally_root,
            "contract_upgrade_root": self.contract_upgrade_root,
            "parameter_upgrade_root": self.parameter_upgrade_root,
            "fee_policy_root": self.fee_policy_root,
            "quantum_migration_root": self.quantum_migration_root,
            "privacy_disclosure_root": self.privacy_disclosure_root,
            "emergency_veto_root": self.emergency_veto_root,
            "execution_receipt_root": self.execution_receipt_root,
            "challenge_root": self.challenge_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_governance_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernanceState {
    pub height: u64,
    pub policy: PrivateGovernancePolicy,
    pub committees: BTreeMap<String, PqVotingCommittee>,
    pub proposals: BTreeMap<String, ShieldedGovernanceProposal>,
    pub votes: BTreeMap<String, ShieldedGovernanceVote>,
    pub tallies: BTreeMap<String, PrivateGovernanceTally>,
    pub contract_upgrades: BTreeMap<String, TimelockedContractUpgrade>,
    pub parameter_upgrades: BTreeMap<String, TimelockedParameterUpgrade>,
    pub fee_policies: BTreeMap<String, PrivateFeePolicy>,
    pub quantum_migrations: BTreeMap<String, QuantumMigrationBallot>,
    pub privacy_disclosures: BTreeMap<String, PrivacyBudgetDisclosure>,
    pub emergency_vetoes: BTreeMap<String, EmergencyVeto>,
    pub execution_receipts: BTreeMap<String, PrivateGovernanceExecutionReceipt>,
    pub challenge_windows: BTreeMap<String, PrivateGovernanceChallengeWindow>,
    pub next_proposal_nonce: u64,
}

impl Default for PrivateGovernanceState {
    fn default() -> Self {
        let policy = PrivateGovernancePolicy::default();
        let fee_policy = PrivateFeePolicy::default();
        let mut fee_policies = BTreeMap::new();
        fee_policies.insert(fee_policy.policy_id.clone(), fee_policy);
        Self {
            height: 0,
            policy,
            committees: BTreeMap::new(),
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
            tallies: BTreeMap::new(),
            contract_upgrades: BTreeMap::new(),
            parameter_upgrades: BTreeMap::new(),
            fee_policies,
            quantum_migrations: BTreeMap::new(),
            privacy_disclosures: BTreeMap::new(),
            emergency_vetoes: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            next_proposal_nonce: 0,
        }
    }
}

impl PrivateGovernanceState {
    pub fn devnet() -> PrivateGovernanceResult<Self> {
        let mut state = Self::default();
        state.set_height(12)?;
        let members = vec![
            PqCommitteeMember::new(
                "private-governance-alice",
                &private_governance_string_commitment("devnet_pq_key", "alice"),
                40,
                state.height,
            )?,
            PqCommitteeMember::new(
                "private-governance-bob",
                &private_governance_string_commitment("devnet_pq_key", "bob"),
                35,
                state.height,
            )?,
            PqCommitteeMember::new(
                "private-governance-carol",
                &private_governance_string_commitment("devnet_pq_key", "carol"),
                25,
                state.height,
            )?,
        ];
        let committee = PqVotingCommittee::new(
            "devnet-private-governance-committee",
            "shielded-upgrade-safety",
            members,
            state.height,
            0,
        )?;
        let committee_id = committee.committee_id.clone();
        state.register_committee(committee)?;

        let privacy_disclosure = PrivacyBudgetDisclosure::new(
            private_governance_string_commitment("budget_subject", "devnet-governance"),
            "governance-action-disclosure",
            0,
            10_000,
            1_250,
            private_governance_string_commitment("budget_proof", "devnet"),
            private_governance_string_commitment("budget_auditor", "devnet-auditor"),
            private_governance_string_commitment("budget_salt", "devnet"),
            state.height,
            state.height.saturating_add(10_080),
        )?;
        state.privacy_disclosures.insert(
            privacy_disclosure.disclosure_id.clone(),
            privacy_disclosure.clone(),
        );

        let contract_upgrade = TimelockedContractUpgrade::new(
            "devnet-rollup-contract",
            private_governance_string_commitment("code", "rollup-v1"),
            private_governance_string_commitment("code", "rollup-v2"),
            private_governance_string_commitment("manifest", "rollup-v2"),
            private_governance_string_commitment("migration", "rollup-v2"),
            private_governance_string_commitment("rollback", "rollup-v1"),
            private_governance_string_commitment("state", "pre-rollup-v2"),
            private_governance_string_commitment("state", "post-rollup-v2"),
            private_governance_string_commitment("safety", "devnet-rollup-v2"),
            state
                .height
                .saturating_add(PRIVATE_GOVERNANCE_CONTRACT_TIMELOCK_BLOCKS),
            PRIVATE_GOVERNANCE_CONTRACT_TIMELOCK_BLOCKS,
            true,
        )?;
        let action = PrivateGovernanceAction::TimelockedContractUpgrade {
            upgrade: contract_upgrade,
        };
        let proposal = state.build_proposal(
            committee_id,
            private_governance_string_commitment("proposer", "devnet-upgrade-council"),
            private_governance_string_commitment("encrypted_payload", "rollup-v2-payload"),
            private_governance_string_commitment("public_summary", "rollup-v2-summary"),
            privacy_disclosure.disclosure_root(),
            action,
        )?;
        let proposal_id = proposal.proposal_id.clone();
        state.submit_proposal(proposal)?;
        state.set_height(state.height.saturating_add(1))?;

        for label in ["alice", "bob"] {
            let vote = ShieldedGovernanceVote::new(
                proposal_id.clone(),
                state.default_committee_id()?,
                private_governance_string_commitment("voter_secret", label),
                PrivateVoteChoice::Approve,
                if label == "alice" { 40 } else { 35 },
                private_governance_string_commitment("encrypted_vote", label),
                private_governance_string_commitment("pq_authorization", label),
                state.height,
            )?;
            state.cast_vote(vote)?;
        }
        state.set_height(
            state
                .height
                .saturating_add(PRIVATE_GOVERNANCE_DEFAULT_VOTE_WINDOW_BLOCKS)
                .saturating_add(1),
        )?;
        state.tally_proposal(&proposal_id)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateGovernanceResult<String> {
        if height < self.height {
            return Err("private governance height cannot move backward".to_string());
        }
        self.height = height;
        self.expire_vetoes();
        self.expire_challenges();
        Ok(self.state_root())
    }

    pub fn default_committee_id(&self) -> PrivateGovernanceResult<String> {
        self.committees
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "private governance committee set is empty".to_string())
    }

    pub fn register_committee(
        &mut self,
        committee: PqVotingCommittee,
    ) -> PrivateGovernanceResult<String> {
        committee.validate()?;
        if self.committees.contains_key(&committee.committee_id) {
            return Err("private governance committee already registered".to_string());
        }
        let committee_id = committee.committee_id.clone();
        self.committees.insert(committee_id.clone(), committee);
        Ok(committee_id)
    }

    pub fn build_proposal(
        &mut self,
        committee_id: impl Into<String>,
        proposer_commitment: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        public_summary_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        action: PrivateGovernanceAction,
    ) -> PrivateGovernanceResult<ShieldedGovernanceProposal> {
        let committee_id = committee_id.into();
        self.committee_at_height(&committee_id, self.height)?;
        let nonce = self.next_proposal_nonce;
        let proposal = ShieldedGovernanceProposal::new(
            nonce,
            committee_id,
            proposer_commitment,
            encrypted_payload_root,
            public_summary_root,
            privacy_budget_root,
            action,
            self.height,
            self.policy.default_vote_window_blocks,
            &self.policy,
        )?;
        self.next_proposal_nonce = self.next_proposal_nonce.saturating_add(1);
        Ok(proposal)
    }

    pub fn submit_proposal(
        &mut self,
        proposal: ShieldedGovernanceProposal,
    ) -> PrivateGovernanceResult<String> {
        proposal.validate(&self.policy)?;
        self.committee_at_height(&proposal.committee_id, proposal.created_at_height)?;
        if proposal.created_at_height != self.height {
            return Err("proposal creation height must match state height".to_string());
        }
        if self.proposals.contains_key(&proposal.proposal_id) {
            return Err("proposal already exists".to_string());
        }
        self.index_action(&proposal.action)?;
        let proposal_id = proposal.proposal_id.clone();
        self.proposals.insert(proposal_id.clone(), proposal);
        Ok(proposal_id)
    }

    pub fn cast_vote(&mut self, vote: ShieldedGovernanceVote) -> PrivateGovernanceResult<String> {
        vote.validate()?;
        let proposal = self
            .proposals
            .get(&vote.proposal_id)
            .ok_or_else(|| "vote references unknown proposal".to_string())?;
        if proposal.committee_id != vote.committee_id {
            return Err("vote committee does not match proposal".to_string());
        }
        if vote.cast_at_height < proposal.voting_starts_at_height
            || vote.cast_at_height > proposal.voting_ends_at_height
        {
            return Err("vote cast outside proposal voting window".to_string());
        }
        if vote.cast_at_height > self.height {
            return Err("vote cast height cannot be in the future".to_string());
        }
        let committee = self.committee_at_height(&vote.committee_id, vote.cast_at_height)?;
        if vote.vote_weight > committee.active_weight_at(vote.cast_at_height) {
            return Err("vote weight exceeds active committee weight".to_string());
        }
        if self.votes.values().any(|existing| {
            existing.proposal_id == vote.proposal_id
                && existing.voter_nullifier == vote.voter_nullifier
        }) {
            return Err("vote nullifier already used for proposal".to_string());
        }
        let vote_id = vote.vote_id.clone();
        self.votes.insert(vote_id.clone(), vote);
        Ok(vote_id)
    }

    pub fn tally_proposal(
        &mut self,
        proposal_id: &str,
    ) -> PrivateGovernanceResult<PrivateGovernanceTally> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "tally references unknown proposal".to_string())?
            .clone();
        if self.height <= proposal.voting_ends_at_height {
            return Err("proposal voting window is still open".to_string());
        }
        let committee =
            self.committee_at_height(&proposal.committee_id, proposal.created_at_height)?;
        let mut approve_weight = 0_u64;
        let mut reject_weight = 0_u64;
        let mut abstain_weight = 0_u64;
        let mut veto_weight = 0_u64;
        let mut seen_nullifiers = BTreeSet::new();
        for vote in self
            .votes
            .values()
            .filter(|vote| vote.proposal_id == proposal_id)
        {
            vote.validate()?;
            if !seen_nullifiers.insert(vote.voter_nullifier.clone()) {
                return Err("duplicate vote nullifier during tally".to_string());
            }
            match vote.choice {
                PrivateVoteChoice::Approve => {
                    approve_weight = approve_weight.saturating_add(vote.vote_weight)
                }
                PrivateVoteChoice::Reject => {
                    reject_weight = reject_weight.saturating_add(vote.vote_weight)
                }
                PrivateVoteChoice::Abstain => {
                    abstain_weight = abstain_weight.saturating_add(vote.vote_weight)
                }
                PrivateVoteChoice::Veto => {
                    veto_weight = veto_weight.saturating_add(vote.vote_weight)
                }
            }
        }
        let vote_root = self.vote_root_for_proposal(proposal_id);
        let approval_bps = if proposal.proposal_kind.requires_supermajority() {
            self.policy.supermajority_bps
        } else {
            committee.approval_bps
        };
        let tally = PrivateGovernanceTally::new(
            proposal_id.to_string(),
            proposal.committee_id.clone(),
            vote_root,
            approve_weight,
            reject_weight,
            abstain_weight,
            veto_weight,
            committee.active_weight_at(proposal.created_at_height),
            committee.quorum_bps,
            approval_bps,
            committee.veto_bps,
            self.height,
        )?;
        let tally_id = tally.tally_id.clone();
        self.tallies.insert(tally_id, tally.clone());
        if let Some(stored) = self.proposals.get_mut(proposal_id) {
            stored.status = if tally.passed {
                "passed".to_string()
            } else if tally.veto_met {
                "vetoed".to_string()
            } else {
                "rejected".to_string()
            };
        }
        Ok(tally)
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        executor_commitment: impl Into<String>,
        effects_root: impl Into<String>,
    ) -> PrivateGovernanceResult<PrivateGovernanceExecutionReceipt> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "execution references unknown proposal".to_string())?
            .clone();
        if proposal.status != "passed" {
            return Err("only passed proposals can execute".to_string());
        }
        if self.height < proposal.earliest_execution_height {
            return Err("proposal timelock has not elapsed".to_string());
        }
        if self.height > proposal.expires_at_height {
            return Err("proposal execution window expired".to_string());
        }
        if self.active_veto_for_proposal(proposal_id).is_some() {
            return Err("proposal is frozen by emergency veto".to_string());
        }
        let pre_state_root = self.state_root();
        let action_effects = self.apply_action(proposal_id, &proposal.action)?;
        if let Some(stored) = self.proposals.get_mut(proposal_id) {
            stored.status = "executed".to_string();
        }
        let combined_effects_root = private_governance_payload_root(
            "PRIVATE-GOVERNANCE-EXECUTION-EFFECTS",
            &json!({
                "requested_effects_root": effects_root.into(),
                "action_effects": action_effects,
            }),
        );
        let post_state_root = self.state_root();
        let challenge_window_ends_at_height = if proposal.proposal_kind.opens_challenge_window() {
            self.height.saturating_add(proposal.challenge_window_blocks)
        } else {
            self.height
        };
        let status = if challenge_window_ends_at_height > self.height {
            PrivateGovernanceExecutionStatus::PendingChallenge
        } else {
            PrivateGovernanceExecutionStatus::Finalized
        };
        let receipt = PrivateGovernanceExecutionReceipt::new(
            proposal_id.to_string(),
            proposal.action_root.clone(),
            executor_commitment,
            pre_state_root,
            post_state_root,
            combined_effects_root,
            self.height,
            challenge_window_ends_at_height,
            status,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.execution_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn activate_emergency_veto(
        &mut self,
        veto: EmergencyVeto,
    ) -> PrivateGovernanceResult<String> {
        veto.validate()?;
        if !self.proposals.contains_key(&veto.target_proposal_id) {
            return Err("emergency veto references unknown proposal".to_string());
        }
        self.committee_at_height(&veto.veto_committee_id, veto.activated_at_height)?;
        let veto_id = veto.veto_id.clone();
        self.emergency_vetoes.insert(veto_id.clone(), veto.clone());
        if let Some(proposal) = self.proposals.get_mut(&veto.target_proposal_id) {
            if proposal.status != "executed" {
                proposal.status = "vetoed".to_string();
            }
        }
        Ok(veto_id)
    }

    pub fn open_challenge(
        &mut self,
        receipt_id: &str,
        challenge_kind: PrivateGovernanceChallengeKind,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
    ) -> PrivateGovernanceResult<PrivateGovernanceChallengeWindow> {
        let receipt = self
            .execution_receipts
            .get(receipt_id)
            .ok_or_else(|| "challenge references unknown execution receipt".to_string())?;
        if self.height > receipt.challenge_window_ends_at_height {
            return Err("execution challenge window has closed".to_string());
        }
        let open_count = self
            .challenge_windows
            .values()
            .filter(|challenge| challenge.proposal_id == receipt.proposal_id)
            .count();
        if open_count >= PRIVATE_GOVERNANCE_MAX_CHALLENGES_PER_PROPOSAL {
            return Err("proposal has too many challenge windows".to_string());
        }
        let challenge = PrivateGovernanceChallengeWindow::new(
            receipt.proposal_id.clone(),
            receipt.receipt_id.clone(),
            challenge_kind,
            challenger_commitment,
            evidence_root,
            self.height,
            self.height
                .saturating_add(self.policy.challenge_window_blocks),
        )?;
        self.challenge_windows
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        status: PrivateGovernanceChallengeStatus,
        resolution_root: impl Into<String>,
    ) -> PrivateGovernanceResult<String> {
        let challenge = self
            .challenge_windows
            .get_mut(challenge_id)
            .ok_or_else(|| "unknown challenge id".to_string())?;
        challenge.resolve(status.clone(), resolution_root, self.height)?;
        if let Some(receipt) = self.execution_receipts.get_mut(&challenge.receipt_id) {
            match status {
                PrivateGovernanceChallengeStatus::Sustained => {
                    receipt.status = PrivateGovernanceExecutionStatus::Reverted
                }
                PrivateGovernanceChallengeStatus::Rejected
                | PrivateGovernanceChallengeStatus::Expired => {
                    if self.height >= receipt.challenge_window_ends_at_height {
                        receipt.status = PrivateGovernanceExecutionStatus::Finalized;
                    }
                }
                PrivateGovernanceChallengeStatus::Open => {}
            }
        }
        Ok(challenge.challenge_root())
    }

    pub fn roots(&self) -> PrivateGovernanceStateRoots {
        PrivateGovernanceStateRoots {
            policy_root: self.policy.policy_root(),
            committee_root: self.committee_root(),
            proposal_root: self.proposal_root(),
            vote_root: self.vote_root(),
            tally_root: self.tally_root(),
            contract_upgrade_root: self.contract_upgrade_root(),
            parameter_upgrade_root: self.parameter_upgrade_root(),
            fee_policy_root: self.fee_policy_root(),
            quantum_migration_root: self.quantum_migration_root(),
            privacy_disclosure_root: self.privacy_disclosure_root(),
            emergency_veto_root: self.emergency_veto_root(),
            execution_receipt_root: self.execution_receipt_root(),
            challenge_root: self.challenge_root(),
        }
    }

    pub fn committee_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-COMMITTEE",
            &self
                .committees
                .values()
                .map(PqVotingCommittee::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn proposal_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-PROPOSAL",
            &self
                .proposals
                .values()
                .map(ShieldedGovernanceProposal::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn vote_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-VOTE",
            &self
                .votes
                .values()
                .map(ShieldedGovernanceVote::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn vote_root_for_proposal(&self, proposal_id: &str) -> String {
        let mut records = self
            .votes
            .values()
            .filter(|vote| vote.proposal_id == proposal_id)
            .map(ShieldedGovernanceVote::public_record)
            .collect::<Vec<_>>();
        sort_records_by_key(&mut records, "vote_id");
        merkle_root("PRIVATE-GOVERNANCE-PROPOSAL-VOTE", &records)
    }

    pub fn tally_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-TALLY",
            &self
                .tallies
                .values()
                .map(PrivateGovernanceTally::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn contract_upgrade_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-CONTRACT-UPGRADE",
            &self
                .contract_upgrades
                .values()
                .map(TimelockedContractUpgrade::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn parameter_upgrade_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-PARAMETER-UPGRADE",
            &self
                .parameter_upgrades
                .values()
                .map(TimelockedParameterUpgrade::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn fee_policy_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-FEE-POLICY",
            &self
                .fee_policies
                .values()
                .map(PrivateFeePolicy::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn quantum_migration_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-QUANTUM-MIGRATION",
            &self
                .quantum_migrations
                .values()
                .map(QuantumMigrationBallot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn privacy_disclosure_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-PRIVACY-DISCLOSURE",
            &self
                .privacy_disclosures
                .values()
                .map(PrivacyBudgetDisclosure::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn emergency_veto_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-EMERGENCY-VETO",
            &self
                .emergency_vetoes
                .values()
                .map(EmergencyVeto::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn execution_receipt_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-EXECUTION-RECEIPT",
            &self
                .execution_receipts
                .values()
                .map(PrivateGovernanceExecutionReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn challenge_root(&self) -> String {
        merkle_root(
            "PRIVATE-GOVERNANCE-CHALLENGE",
            &self
                .challenge_windows
                .values()
                .map(PrivateGovernanceChallengeWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_governance_state",
            "chain_id": CHAIN_ID,
            "private_governance_protocol_version": PRIVATE_GOVERNANCE_PROTOCOL_VERSION,
            "height": self.height,
            "roots": roots.public_record(),
            "state_root": roots.state_root(),
            "committee_count": self.committees.len(),
            "proposal_count": self.proposals.len(),
            "vote_count": self.votes.len(),
            "tally_count": self.tallies.len(),
            "contract_upgrade_count": self.contract_upgrades.len(),
            "parameter_upgrade_count": self.parameter_upgrades.len(),
            "fee_policy_count": self.fee_policies.len(),
            "quantum_migration_count": self.quantum_migrations.len(),
            "privacy_disclosure_count": self.privacy_disclosures.len(),
            "emergency_veto_count": self.emergency_vetoes.len(),
            "execution_receipt_count": self.execution_receipts.len(),
            "challenge_count": self.challenge_windows.len(),
            "next_proposal_nonce": self.next_proposal_nonce,
        })
    }

    pub fn state_root(&self) -> String {
        private_governance_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateGovernanceResult<String> {
        self.policy.validate()?;
        for committee in self.committees.values() {
            committee.validate()?;
        }
        for proposal in self.proposals.values() {
            proposal.validate(&self.policy)?;
            if !self.committees.contains_key(&proposal.committee_id) {
                return Err("proposal references unknown committee".to_string());
            }
        }
        for vote in self.votes.values() {
            vote.validate()?;
            let proposal = self
                .proposals
                .get(&vote.proposal_id)
                .ok_or_else(|| "vote references unknown proposal".to_string())?;
            if proposal.committee_id != vote.committee_id {
                return Err("vote committee mismatch".to_string());
            }
        }
        for tally in self.tallies.values() {
            tally.validate()?;
            if !self.proposals.contains_key(&tally.proposal_id) {
                return Err("tally references unknown proposal".to_string());
            }
        }
        for upgrade in self.contract_upgrades.values() {
            upgrade.validate()?;
        }
        for upgrade in self.parameter_upgrades.values() {
            upgrade.validate()?;
        }
        for policy in self.fee_policies.values() {
            policy.validate()?;
        }
        for ballot in self.quantum_migrations.values() {
            ballot.validate()?;
        }
        for disclosure in self.privacy_disclosures.values() {
            disclosure.validate()?;
        }
        for veto in self.emergency_vetoes.values() {
            veto.validate()?;
        }
        for receipt in self.execution_receipts.values() {
            receipt.validate()?;
            if !self.proposals.contains_key(&receipt.proposal_id) {
                return Err("execution receipt references unknown proposal".to_string());
            }
        }
        for challenge in self.challenge_windows.values() {
            challenge.validate()?;
            if !self.execution_receipts.contains_key(&challenge.receipt_id) {
                return Err("challenge references unknown execution receipt".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn committee_at_height(
        &self,
        committee_id: &str,
        height: u64,
    ) -> PrivateGovernanceResult<&PqVotingCommittee> {
        let committee = self
            .committees
            .get(committee_id)
            .ok_or_else(|| "unknown private governance committee".to_string())?;
        if !committee.is_live_at(height) {
            return Err("private governance committee is not live at height".to_string());
        }
        Ok(committee)
    }

    fn index_action(&mut self, action: &PrivateGovernanceAction) -> PrivateGovernanceResult<()> {
        match action {
            PrivateGovernanceAction::TimelockedContractUpgrade { upgrade } => {
                self.contract_upgrades
                    .insert(upgrade.upgrade_id.clone(), upgrade.clone());
            }
            PrivateGovernanceAction::TimelockedParameterUpgrade { upgrade } => {
                self.parameter_upgrades
                    .insert(upgrade.upgrade_id.clone(), upgrade.clone());
            }
            PrivateGovernanceAction::FeePolicyChange { policy } => {
                self.fee_policies
                    .insert(policy.policy_id.clone(), policy.clone());
            }
            PrivateGovernanceAction::QuantumMigrationBallot { ballot } => {
                self.quantum_migrations
                    .insert(ballot.ballot_id.clone(), ballot.clone());
            }
            PrivateGovernanceAction::PrivacyBudgetDisclosure { disclosure } => {
                self.privacy_disclosures
                    .insert(disclosure.disclosure_id.clone(), disclosure.clone());
            }
            PrivateGovernanceAction::EmergencyVeto { veto } => {
                self.activate_emergency_veto(veto.clone())?;
            }
        }
        Ok(())
    }

    fn apply_action(
        &mut self,
        proposal_id: &str,
        action: &PrivateGovernanceAction,
    ) -> PrivateGovernanceResult<Value> {
        match action {
            PrivateGovernanceAction::TimelockedContractUpgrade { upgrade } => {
                self.contract_upgrades
                    .insert(upgrade.upgrade_id.clone(), upgrade.clone());
                Ok(json!({
                    "kind": PrivateGovernanceProposalKind::TimelockedContractUpgrade.as_str(),
                    "proposal_id": proposal_id,
                    "upgrade_id": upgrade.upgrade_id,
                    "contract_upgrade_root": self.contract_upgrade_root(),
                }))
            }
            PrivateGovernanceAction::TimelockedParameterUpgrade { upgrade } => {
                self.parameter_upgrades
                    .insert(upgrade.upgrade_id.clone(), upgrade.clone());
                Ok(json!({
                    "kind": PrivateGovernanceProposalKind::TimelockedParameterUpgrade.as_str(),
                    "proposal_id": proposal_id,
                    "upgrade_id": upgrade.upgrade_id,
                    "parameter_upgrade_root": self.parameter_upgrade_root(),
                }))
            }
            PrivateGovernanceAction::FeePolicyChange { policy } => {
                self.fee_policies
                    .insert(policy.policy_id.clone(), policy.clone());
                Ok(json!({
                    "kind": PrivateGovernanceProposalKind::FeePolicyChange.as_str(),
                    "proposal_id": proposal_id,
                    "policy_id": policy.policy_id,
                    "fee_policy_root": self.fee_policy_root(),
                }))
            }
            PrivateGovernanceAction::QuantumMigrationBallot { ballot } => {
                self.quantum_migrations
                    .insert(ballot.ballot_id.clone(), ballot.clone());
                Ok(json!({
                    "kind": PrivateGovernanceProposalKind::QuantumMigrationBallot.as_str(),
                    "proposal_id": proposal_id,
                    "ballot_id": ballot.ballot_id,
                    "quantum_migration_root": self.quantum_migration_root(),
                }))
            }
            PrivateGovernanceAction::PrivacyBudgetDisclosure { disclosure } => {
                self.privacy_disclosures
                    .insert(disclosure.disclosure_id.clone(), disclosure.clone());
                Ok(json!({
                    "kind": PrivateGovernanceProposalKind::PrivacyBudgetDisclosure.as_str(),
                    "proposal_id": proposal_id,
                    "disclosure_id": disclosure.disclosure_id,
                    "privacy_disclosure_root": self.privacy_disclosure_root(),
                }))
            }
            PrivateGovernanceAction::EmergencyVeto { veto } => {
                self.activate_emergency_veto(veto.clone())?;
                Ok(json!({
                    "kind": PrivateGovernanceProposalKind::EmergencyVeto.as_str(),
                    "proposal_id": proposal_id,
                    "veto_id": veto.veto_id,
                    "emergency_veto_root": self.emergency_veto_root(),
                }))
            }
        }
    }

    fn active_veto_for_proposal(&self, proposal_id: &str) -> Option<&EmergencyVeto> {
        self.emergency_vetoes.values().find(|veto| {
            veto.target_proposal_id == proposal_id
                && veto.is_active_at(self.height)
                && self.height < veto.freezes_execution_until_height
        })
    }

    fn expire_vetoes(&mut self) {
        for veto in self.emergency_vetoes.values_mut() {
            if veto.status == "active"
                && veto.expires_at_height != 0
                && self.height >= veto.expires_at_height
            {
                veto.status = "expired".to_string();
            }
        }
    }

    fn expire_challenges(&mut self) {
        for challenge in self.challenge_windows.values_mut() {
            if challenge.status == PrivateGovernanceChallengeStatus::Open
                && self.height > challenge.response_due_height
            {
                challenge.status = PrivateGovernanceChallengeStatus::Expired;
                challenge.resolved_at_height = self.height;
                challenge.resolution_root = private_governance_string_commitment(
                    "challenge_resolution",
                    "expired_without_response",
                );
            }
        }
        for receipt in self.execution_receipts.values_mut() {
            if receipt.status == PrivateGovernanceExecutionStatus::PendingChallenge
                && self.height >= receipt.challenge_window_ends_at_height
            {
                let has_open_or_sustained = self.challenge_windows.values().any(|challenge| {
                    challenge.receipt_id == receipt.receipt_id
                        && matches!(
                            challenge.status,
                            PrivateGovernanceChallengeStatus::Open
                                | PrivateGovernanceChallengeStatus::Sustained
                        )
                });
                if !has_open_or_sustained {
                    receipt.status = PrivateGovernanceExecutionStatus::Finalized;
                }
            }
        }
    }
}

pub fn private_governance_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn private_governance_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_governance_string_commitment(label: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-STRING-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_governance_blinded_commitment(label: &str, value: &str, blinding: &str) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-BLINDED-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_governance_policy_root(policy: &PrivateGovernancePolicy) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-POLICY",
        &[HashPart::Json(&policy.public_record())],
        32,
    )
}

pub fn private_governance_committee_member_id(
    label_commitment: &str,
    pq_scheme: &str,
    pq_public_key_root: &str,
    voting_weight: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label_commitment),
            HashPart::Str(pq_scheme),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(voting_weight as i128),
        ],
        32,
    )
}

pub fn private_governance_committee_id(
    label: &str,
    purpose: &str,
    member_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(purpose),
            HashPart::Str(member_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn private_governance_contract_upgrade_id(
    contract_id: &str,
    current_code_root: &str,
    target_code_root: &str,
    manifest_root: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-CONTRACT-UPGRADE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(current_code_root),
            HashPart::Str(target_code_root),
            HashPart::Str(manifest_root),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

pub fn private_governance_parameter_key(module: &str, key: &str) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-PARAMETER-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(module),
            HashPart::Str(key),
        ],
        32,
    )
}

pub fn private_governance_parameter_change_id(
    module: &str,
    key: &str,
    previous_value_root: &str,
    next_value_root: &str,
    bounds_root: &str,
    reason_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-PARAMETER-CHANGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(module),
            HashPart::Str(key),
            HashPart::Str(previous_value_root),
            HashPart::Str(next_value_root),
            HashPart::Str(bounds_root),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

pub fn private_governance_parameter_upgrade_id(
    change_root: &str,
    activation_height: u64,
    min_delay_blocks: u64,
    aggregate_reason_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-PARAMETER-UPGRADE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(change_root),
            HashPart::Int(activation_height as i128),
            HashPart::Int(min_delay_blocks as i128),
            HashPart::Str(aggregate_reason_root),
        ],
        32,
    )
}

pub fn private_governance_fee_policy_id(
    fee_asset_id: &str,
    base_fee_micro_units: u64,
    priority_multiplier_bps: u64,
    effective_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-FEE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(fee_asset_id),
            HashPart::Int(base_fee_micro_units as i128),
            HashPart::Int(priority_multiplier_bps as i128),
            HashPart::Int(effective_height as i128),
        ],
        32,
    )
}

pub fn private_governance_quantum_migration_step_id(
    role: &str,
    source_scheme: &str,
    target_scheme: &str,
    source_key_root: &str,
    target_key_root: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-QUANTUM-MIGRATION-STEP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role),
            HashPart::Str(source_scheme),
            HashPart::Str(target_scheme),
            HashPart::Str(source_key_root),
            HashPart::Str(target_key_root),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn private_governance_quantum_migration_ballot_id(
    migration_name: &str,
    source_policy_root: &str,
    target_policy_root: &str,
    step_root: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-QUANTUM-MIGRATION-BALLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(migration_name),
            HashPart::Str(source_policy_root),
            HashPart::Str(target_policy_root),
            HashPart::Str(step_root),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

pub fn private_governance_privacy_disclosure_id(
    subject_commitment: &str,
    budget_scope: &str,
    epoch: u64,
    proof_root: &str,
    disclosure_salt_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-PRIVACY-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_commitment),
            HashPart::Str(budget_scope),
            HashPart::Int(epoch as i128),
            HashPart::Str(proof_root),
            HashPart::Str(disclosure_salt_root),
        ],
        32,
    )
}

pub fn private_governance_emergency_veto_id(
    target_proposal_id: &str,
    veto_committee_id: &str,
    scope: &str,
    reason_root: &str,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-EMERGENCY-VETO-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(target_proposal_id),
            HashPart::Str(veto_committee_id),
            HashPart::Str(scope),
            HashPart::Str(reason_root),
            HashPart::Int(activated_at_height as i128),
        ],
        32,
    )
}

pub fn private_governance_action_root(action: &PrivateGovernanceAction) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-ACTION",
        &[HashPart::Json(&action.public_record())],
        32,
    )
}

pub fn private_governance_proposal_id(
    proposal_nonce: u64,
    committee_id: &str,
    proposer_commitment: &str,
    proposal_kind: &str,
    action_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(proposal_nonce as i128),
            HashPart::Str(committee_id),
            HashPart::Str(proposer_commitment),
            HashPart::Str(proposal_kind),
            HashPart::Str(action_root),
        ],
        32,
    )
}

pub fn private_governance_vote_nullifier(proposal_id: &str, voter_secret_root: &str) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-VOTE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(voter_secret_root),
        ],
        32,
    )
}

pub fn private_governance_weight_commitment(
    proposal_id: &str,
    voter_nullifier: &str,
    vote_weight: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-VOTE-WEIGHT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(voter_nullifier),
            HashPart::Int(vote_weight as i128),
        ],
        32,
    )
}

pub fn private_governance_vote_id(
    proposal_id: &str,
    voter_nullifier: &str,
    choice: &str,
    weight_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(voter_nullifier),
            HashPart::Str(choice),
            HashPart::Str(weight_commitment),
        ],
        32,
    )
}

pub fn private_governance_tally_id(
    proposal_id: &str,
    vote_root: &str,
    tallied_at_height: u64,
    passed: bool,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-TALLY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(vote_root),
            HashPart::Int(tallied_at_height as i128),
            HashPart::Str(if passed { "passed" } else { "failed" }),
        ],
        32,
    )
}

pub fn private_governance_execution_receipt_id(
    proposal_id: &str,
    action_root: &str,
    pre_state_root: &str,
    post_state_root: &str,
    executed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-EXECUTION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(action_root),
            HashPart::Str(pre_state_root),
            HashPart::Str(post_state_root),
            HashPart::Int(executed_at_height as i128),
        ],
        32,
    )
}

pub fn private_governance_challenge_id(
    proposal_id: &str,
    receipt_id: &str,
    challenge_kind: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-GOVERNANCE-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(receipt_id),
            HashPart::Str(challenge_kind),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_governance_state_root_from_record(record: &Value) -> String {
    domain_hash("PRIVATE-GOVERNANCE-STATE", &[HashPart::Json(record)], 32)
}

pub fn private_governance_state_root(state: &PrivateGovernanceState) -> String {
    state.state_root()
}

fn parameter_change_root(changes: &[ParameterUpgradeChange]) -> String {
    let mut records = changes
        .iter()
        .map(ParameterUpgradeChange::public_record)
        .collect::<Vec<_>>();
    sort_records_by_key(&mut records, "change_id");
    merkle_root("PRIVATE-GOVERNANCE-PARAMETER-CHANGE", &records)
}

fn quantum_migration_step_root(steps: &[QuantumMigrationStep]) -> String {
    let mut records = steps
        .iter()
        .map(QuantumMigrationStep::public_record)
        .collect::<Vec<_>>();
    sort_records_by_key(&mut records, "step_id");
    merkle_root("PRIVATE-GOVERNANCE-QUANTUM-MIGRATION-STEP", &records)
}

fn sort_records_by_key(records: &mut [Value], key: &str) {
    records.sort_by(|left, right| {
        left[key]
            .as_str()
            .unwrap_or_default()
            .cmp(right[key].as_str().unwrap_or_default())
    });
}

fn bps_threshold(total: u64, bps: u64) -> u64 {
    if total == 0 || bps == 0 {
        0
    } else {
        total.saturating_mul(bps).div_ceil(10_000)
    }
}

fn validate_bps(value: u64, label: &str) -> PrivateGovernanceResult<()> {
    if value > 10_000 {
        Err(format!("{label} basis points exceed 100 percent"))
    } else {
        Ok(())
    }
}

fn validate_nonempty(value: &str, label: &str) -> PrivateGovernanceResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_status(value: &str, allowed: &[&str], label: &str) -> PrivateGovernanceResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{label} status is not supported"))
    }
}
