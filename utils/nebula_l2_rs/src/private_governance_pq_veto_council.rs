use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateGovernancePqVetoCouncilResult<T> = Result<T, String>;

pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PROTOCOL_ID: &str =
    "nebula-private-governance-pq-veto-council-v1";
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PUBLIC_RECORD_SCHEMA: &str =
    "private-governance-pq-veto-council-public-record-v1";
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEVNET_HEIGHT: u64 = 2_048;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PQ_SIGNATURE_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PRIVATE_ENVELOPE_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-private-governance-envelope-v1";
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_VOTE_NOTE_SCHEME: &str =
    "shielded-delegated-governance-vote-note-v1";
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_CHALLENGE_PROOF_SYSTEM: &str =
    "pq-veto-council-challenge-evidence-v1";
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 24;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_TIMELOCK_BLOCKS: u64 = 720;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_VETO_WINDOW_BLOCKS: u64 = 360;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MIN_VETO_WEIGHT: u64 = 7;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_EMERGENCY_WEIGHT: u64 = 5;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_SLASH_BOND_UNITS: u64 = 25_000;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 500_000;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MAX_SPONSORED_FEE_UNITS: u64 = 12_000;
pub const PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_MAX_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedProposalKind {
    ProtocolUpgrade,
    FeePolicy,
    TokenParameter,
    SmartContractRuntime,
    DefiRiskParameter,
    BridgeLimit,
    TreasurySpend,
    EmergencyPause,
}

impl ShieldedProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolUpgrade => "protocol_upgrade",
            Self::FeePolicy => "fee_policy",
            Self::TokenParameter => "token_parameter",
            Self::SmartContractRuntime => "smart_contract_runtime",
            Self::DefiRiskParameter => "defi_risk_parameter",
            Self::BridgeLimit => "bridge_limit",
            Self::TreasurySpend => "treasury_spend",
            Self::EmergencyPause => "emergency_pause",
        }
    }

    pub fn high_risk(self) -> bool {
        matches!(
            self,
            Self::ProtocolUpgrade
                | Self::SmartContractRuntime
                | Self::BridgeLimit
                | Self::TreasurySpend
                | Self::EmergencyPause
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedProposalStatus {
    Draft,
    Active,
    RevealPending,
    Tallied,
    Queued,
    Executed,
    Rejected,
    Expired,
    Vetoed,
    Paused,
}

impl ShieldedProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::RevealPending => "reveal_pending",
            Self::Tallied => "tallied",
            Self::Queued => "queued",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Vetoed => "vetoed",
            Self::Paused => "paused",
        }
    }

    pub fn mutable(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Active | Self::RevealPending | Self::Tallied | Self::Queued
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VetoAttestationKind {
    PreQueueVeto,
    TimelockVeto,
    EmergencyPause,
    ScopeRestriction,
    FraudChallenge,
}

impl VetoAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreQueueVeto => "pre_queue_veto",
            Self::TimelockVeto => "timelock_veto",
            Self::EmergencyPause => "emergency_pause",
            Self::ScopeRestriction => "scope_restriction",
            Self::FraudChallenge => "fraud_challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VetoAttestationStatus {
    Collected,
    QuorumMet,
    Applied,
    Challenged,
    Rejected,
    Expired,
    Slashed,
}

impl VetoAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collected => "collected",
            Self::QuorumMet => "quorum_met",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyPauseScopeKind {
    GlobalSettlement,
    SequencerFastPath,
    BridgeExit,
    PrivateTokenTransfer,
    DefiRouter,
    SmartContractRuntime,
    FeeSponsorLane,
    GovernanceExecution,
}

impl EmergencyPauseScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GlobalSettlement => "global_settlement",
            Self::SequencerFastPath => "sequencer_fast_path",
            Self::BridgeExit => "bridge_exit",
            Self::PrivateTokenTransfer => "private_token_transfer",
            Self::DefiRouter => "defi_router",
            Self::SmartContractRuntime => "smart_contract_runtime",
            Self::FeeSponsorLane => "fee_sponsor_lane",
            Self::GovernanceExecution => "governance_execution",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseScopeStatus {
    Armed,
    Active,
    Expired,
    Released,
    Challenged,
}

impl PauseScopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Released => "released",
            Self::Challenged => "challenged",
        }
    }

    pub fn blocking(self) -> bool {
        matches!(self, Self::Armed | Self::Active | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorStatus {
    Active,
    Exhausted,
    Paused,
    Revoked,
}

impl FeeSponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedVoteStatus {
    Active,
    Paused,
    Revoked,
    Expired,
    Challenged,
}

impl DelegatedVoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidPqSignature,
    DoubleVetoNullifier,
    ExpiredTimelock,
    ScopeOverreach,
    SponsorOverspend,
    DelegationReplay,
    PrivacySetTooSmall,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::DoubleVetoNullifier => "double_veto_nullifier",
            Self::ExpiredTimelock => "expired_timelock",
            Self::ScopeOverreach => "scope_overreach",
            Self::SponsorOverspend => "sponsor_overspend",
            Self::DelegationReplay => "delegation_replay",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernancePqVetoCouncilConfig {
    pub chain_id: String,
    pub protocol_id: String,
    pub public_record_schema: String,
    pub pq_signature_scheme: String,
    pub private_envelope_scheme: String,
    pub vote_note_scheme: String,
    pub challenge_proof_system: String,
    pub proposal_ttl_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub timelock_blocks: u64,
    pub veto_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_veto_weight: u64,
    pub emergency_weight: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub default_slash_bond_units: u64,
    pub default_sponsor_budget_units: u64,
    pub max_sponsored_fee_units: u64,
}

impl PrivateGovernancePqVetoCouncilConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_id: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PROTOCOL_ID.to_string(),
            public_record_schema: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PUBLIC_RECORD_SCHEMA
                .to_string(),
            pq_signature_scheme: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PQ_SIGNATURE_SCHEME.to_string(),
            private_envelope_scheme: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PRIVATE_ENVELOPE_SCHEME
                .to_string(),
            vote_note_scheme: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_VOTE_NOTE_SCHEME.to_string(),
            challenge_proof_system: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_CHALLENGE_PROOF_SYSTEM
                .to_string(),
            proposal_ttl_blocks: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_PROPOSAL_TTL_BLOCKS,
            reveal_delay_blocks: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_REVEAL_DELAY_BLOCKS,
            timelock_blocks: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_TIMELOCK_BLOCKS,
            veto_window_blocks: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_VETO_WINDOW_BLOCKS,
            challenge_window_blocks:
                PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_veto_weight: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MIN_VETO_WEIGHT,
            emergency_weight: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_EMERGENCY_WEIGHT,
            min_privacy_set_size: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MIN_PQ_SECURITY_BITS,
            default_slash_bond_units: PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_SLASH_BOND_UNITS,
            default_sponsor_budget_units:
                PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_sponsored_fee_units:
                PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEFAULT_MAX_SPONSORED_FEE_UNITS,
        }
    }

    pub fn validate(&self) -> PrivateGovernancePqVetoCouncilResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain_id does not match crate CHAIN_ID".to_string());
        }
        if self.protocol_id.is_empty()
            || self.public_record_schema.is_empty()
            || self.pq_signature_scheme.is_empty()
            || self.private_envelope_scheme.is_empty()
            || self.vote_note_scheme.is_empty()
            || self.challenge_proof_system.is_empty()
        {
            return Err("config contains an empty scheme identifier".to_string());
        }
        if self.min_pq_security_bits < 256 {
            return Err("config min_pq_security_bits must be at least 256".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("config min_privacy_set_size must be nonzero".to_string());
        }
        if self.proposal_ttl_blocks <= self.reveal_delay_blocks {
            return Err("proposal ttl must exceed reveal delay".to_string());
        }
        if self.timelock_blocks == 0 || self.veto_window_blocks == 0 {
            return Err("timelock and veto windows must be nonzero".to_string());
        }
        if self.min_veto_weight == 0 || self.emergency_weight == 0 {
            return Err("veto and emergency weights must be nonzero".to_string());
        }
        if self.max_sponsored_fee_units == 0 || self.default_sponsor_budget_units == 0 {
            return Err("fee sponsor budgets must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_id": self.protocol_id,
            "public_record_schema": self.public_record_schema,
            "pq_signature_scheme": self.pq_signature_scheme,
            "private_envelope_scheme": self.private_envelope_scheme,
            "vote_note_scheme": self.vote_note_scheme,
            "challenge_proof_system": self.challenge_proof_system,
            "proposal_ttl_blocks": self.proposal_ttl_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "timelock_blocks": self.timelock_blocks,
            "veto_window_blocks": self.veto_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_veto_weight": self.min_veto_weight,
            "emergency_weight": self.emergency_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "default_slash_bond_units": self.default_slash_bond_units,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "max_sponsored_fee_units": self.max_sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedGovernanceProposal {
    pub proposal_id: String,
    pub kind: ShieldedProposalKind,
    pub status: ShieldedProposalStatus,
    pub proposer_commitment: String,
    pub action_commitment_root: String,
    pub encrypted_payload_root: String,
    pub metadata_commitment: String,
    pub vote_commitment_root: String,
    pub eligible_voter_root: String,
    pub sponsor_id: String,
    pub created_at_height: u64,
    pub activation_height: u64,
    pub reveal_height: u64,
    pub expires_at_height: u64,
    pub queued_at_height: u64,
    pub executable_after_height: u64,
    pub min_privacy_set_size: u64,
    pub required_veto_weight: u64,
    pub tally_commitment: String,
}

impl ShieldedGovernanceProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ShieldedProposalKind,
        proposer_commitment: impl Into<String>,
        action_commitment_root: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        metadata_commitment: impl Into<String>,
        vote_commitment_root: impl Into<String>,
        eligible_voter_root: impl Into<String>,
        sponsor_id: impl Into<String>,
        created_at_height: u64,
        config: &PrivateGovernancePqVetoCouncilConfig,
    ) -> Self {
        let proposer_commitment = proposer_commitment.into();
        let action_commitment_root = action_commitment_root.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let metadata_commitment = metadata_commitment.into();
        let vote_commitment_root = vote_commitment_root.into();
        let eligible_voter_root = eligible_voter_root.into();
        let sponsor_id = sponsor_id.into();
        let activation_height = created_at_height.saturating_add(1);
        let reveal_height = activation_height.saturating_add(config.reveal_delay_blocks);
        let expires_at_height = created_at_height.saturating_add(config.proposal_ttl_blocks);
        let queued_at_height = 0;
        let executable_after_height = 0;
        let required_veto_weight = if kind.high_risk() {
            config.min_veto_weight.saturating_add(1)
        } else {
            config.min_veto_weight
        };
        let tally_commitment = private_governance_seeded_hash(
            "PRIVATE-GOVERNANCE-PROPOSAL-TALLY-COMMITMENT",
            &[
                HashPart::Str(&proposer_commitment),
                HashPart::Str(&action_commitment_root),
                HashPart::Int(created_at_height as i128),
            ],
        );
        let proposal_id = proposal_id(
            kind,
            &proposer_commitment,
            &action_commitment_root,
            &encrypted_payload_root,
            created_at_height,
        );
        Self {
            proposal_id,
            kind,
            status: ShieldedProposalStatus::Draft,
            proposer_commitment,
            action_commitment_root,
            encrypted_payload_root,
            metadata_commitment,
            vote_commitment_root,
            eligible_voter_root,
            sponsor_id,
            created_at_height,
            activation_height,
            reveal_height,
            expires_at_height,
            queued_at_height,
            executable_after_height,
            min_privacy_set_size: config.min_privacy_set_size,
            required_veto_weight,
            tally_commitment,
        }
    }

    pub fn queue(&mut self, queued_at_height: u64, timelock_blocks: u64) {
        self.status = ShieldedProposalStatus::Queued;
        self.queued_at_height = queued_at_height;
        self.executable_after_height = queued_at_height.saturating_add(timelock_blocks);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "action_commitment_root": self.action_commitment_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "metadata_commitment": self.metadata_commitment,
            "vote_commitment_root": self.vote_commitment_root,
            "eligible_voter_root": self.eligible_voter_root,
            "sponsor_id": self.sponsor_id,
            "created_at_height": self.created_at_height,
            "activation_height": self.activation_height,
            "reveal_height": self.reveal_height,
            "expires_at_height": self.expires_at_height,
            "queued_at_height": self.queued_at_height,
            "executable_after_height": self.executable_after_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "required_veto_weight": self.required_veto_weight,
            "tally_commitment": self.tally_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVetoCouncilMember {
    pub member_id: String,
    pub member_commitment: String,
    pub pq_public_key_root: String,
    pub role_root: String,
    pub active: bool,
    pub voting_weight: u64,
    pub slash_bond_units: u64,
    pub joined_at_height: u64,
    pub suspended_until_height: u64,
    pub last_attested_height: u64,
}

impl PqVetoCouncilMember {
    pub fn new(
        member_commitment: impl Into<String>,
        pq_public_key_root: impl Into<String>,
        role_root: impl Into<String>,
        voting_weight: u64,
        slash_bond_units: u64,
        joined_at_height: u64,
    ) -> Self {
        let member_commitment = member_commitment.into();
        let pq_public_key_root = pq_public_key_root.into();
        let role_root = role_root.into();
        let member_id = council_member_id(
            &member_commitment,
            &pq_public_key_root,
            &role_root,
            joined_at_height,
        );
        Self {
            member_id,
            member_commitment,
            pq_public_key_root,
            role_root,
            active: true,
            voting_weight,
            slash_bond_units,
            joined_at_height,
            suspended_until_height: 0,
            last_attested_height: 0,
        }
    }

    pub fn can_attest(&self, height: u64) -> bool {
        self.active && self.voting_weight > 0 && height >= self.suspended_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "member_commitment": self.member_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "role_root": self.role_root,
            "active": self.active,
            "voting_weight": self.voting_weight,
            "slash_bond_units": self.slash_bond_units,
            "joined_at_height": self.joined_at_height,
            "suspended_until_height": self.suspended_until_height,
            "last_attested_height": self.last_attested_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVetoAttestation {
    pub attestation_id: String,
    pub proposal_id: String,
    pub kind: VetoAttestationKind,
    pub status: VetoAttestationStatus,
    pub signer_set_root: String,
    pub signer_weight: u64,
    pub pq_signature_root: String,
    pub veto_reason_commitment: String,
    pub evidence_root: String,
    pub nullifier_root: String,
    pub scope_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqVetoAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: impl Into<String>,
        kind: VetoAttestationKind,
        signer_set_root: impl Into<String>,
        signer_weight: u64,
        pq_signature_root: impl Into<String>,
        veto_reason_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        scope_root: impl Into<String>,
        attested_at_height: u64,
        config: &PrivateGovernancePqVetoCouncilConfig,
    ) -> Self {
        let proposal_id = proposal_id.into();
        let signer_set_root = signer_set_root.into();
        let pq_signature_root = pq_signature_root.into();
        let veto_reason_commitment = veto_reason_commitment.into();
        let evidence_root = evidence_root.into();
        let nullifier_root = nullifier_root.into();
        let scope_root = scope_root.into();
        let attestation_id = veto_attestation_id(
            &proposal_id,
            kind,
            &signer_set_root,
            &pq_signature_root,
            &nullifier_root,
            attested_at_height,
        );
        let required = match kind {
            VetoAttestationKind::EmergencyPause => config.emergency_weight,
            _ => config.min_veto_weight,
        };
        let status = if signer_weight >= required {
            VetoAttestationStatus::QuorumMet
        } else {
            VetoAttestationStatus::Collected
        };
        Self {
            attestation_id,
            proposal_id,
            kind,
            status,
            signer_set_root,
            signer_weight,
            pq_signature_root,
            veto_reason_commitment,
            evidence_root,
            nullifier_root,
            scope_root,
            attested_at_height,
            expires_at_height: attested_at_height.saturating_add(config.veto_window_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "proposal_id": self.proposal_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "signer_set_root": self.signer_set_root,
            "signer_weight": self.signer_weight,
            "pq_signature_root": self.pq_signature_root,
            "veto_reason_commitment": self.veto_reason_commitment,
            "evidence_root": self.evidence_root,
            "nullifier_root": self.nullifier_root,
            "scope_root": self.scope_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPauseScope {
    pub scope_id: String,
    pub kind: EmergencyPauseScopeKind,
    pub status: PauseScopeStatus,
    pub proposal_id: String,
    pub attestation_id: String,
    pub scope_commitment_root: String,
    pub reason_commitment: String,
    pub opened_at_height: u64,
    pub releases_at_height: u64,
    pub max_duration_blocks: u64,
}

impl EmergencyPauseScope {
    pub fn new(
        kind: EmergencyPauseScopeKind,
        proposal_id: impl Into<String>,
        attestation_id: impl Into<String>,
        scope_commitment_root: impl Into<String>,
        reason_commitment: impl Into<String>,
        opened_at_height: u64,
        max_duration_blocks: u64,
    ) -> Self {
        let proposal_id = proposal_id.into();
        let attestation_id = attestation_id.into();
        let scope_commitment_root = scope_commitment_root.into();
        let reason_commitment = reason_commitment.into();
        let scope_id = pause_scope_id(
            kind,
            &proposal_id,
            &attestation_id,
            &scope_commitment_root,
            opened_at_height,
        );
        Self {
            scope_id,
            kind,
            status: PauseScopeStatus::Armed,
            proposal_id,
            attestation_id,
            scope_commitment_root,
            reason_commitment,
            opened_at_height,
            releases_at_height: opened_at_height.saturating_add(max_duration_blocks),
            max_duration_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scope_id": self.scope_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "proposal_id": self.proposal_id,
            "attestation_id": self.attestation_id,
            "scope_commitment_root": self.scope_commitment_root,
            "reason_commitment": self.reason_commitment,
            "opened_at_height": self.opened_at_height,
            "releases_at_height": self.releases_at_height,
            "max_duration_blocks": self.max_duration_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorBudget {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: FeeSponsorStatus,
    pub budget_commitment: String,
    pub policy_root: String,
    pub total_budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_per_action_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorBudget {
    pub fn new(
        sponsor_commitment: impl Into<String>,
        budget_commitment: impl Into<String>,
        policy_root: impl Into<String>,
        total_budget_units: u64,
        max_fee_per_action_units: u64,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let budget_commitment = budget_commitment.into();
        let policy_root = policy_root.into();
        let sponsor_id = fee_sponsor_id(
            &sponsor_commitment,
            &budget_commitment,
            &policy_root,
            opened_at_height,
        );
        Self {
            sponsor_id,
            sponsor_commitment,
            status: FeeSponsorStatus::Active,
            budget_commitment,
            policy_root,
            total_budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_per_action_units,
            opened_at_height,
            expires_at_height,
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve(&mut self, units: u64) -> PrivateGovernancePqVetoCouncilResult<()> {
        if self.status != FeeSponsorStatus::Active {
            return Err("fee sponsor is not active".to_string());
        }
        if units > self.max_fee_per_action_units {
            return Err("fee request exceeds max_fee_per_action_units".to_string());
        }
        if units > self.remaining_units() {
            self.status = FeeSponsorStatus::Exhausted;
            return Err("fee sponsor budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn settle_reserved(&mut self, units: u64) -> PrivateGovernancePqVetoCouncilResult<()> {
        if units > self.reserved_units {
            return Err("cannot settle more units than reserved".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.remaining_units() == 0 {
            self.status = FeeSponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "budget_commitment": self.budget_commitment,
            "policy_root": self.policy_root,
            "total_budget_units": self.total_budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_fee_per_action_units": self.max_fee_per_action_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedPrivacyVote {
    pub delegation_id: String,
    pub delegator_commitment: String,
    pub delegate_commitment: String,
    pub proposal_scope_root: String,
    pub vote_power_commitment: String,
    pub nullifier_root: String,
    pub status: DelegatedVoteStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub min_privacy_set_size: u64,
}

impl DelegatedPrivacyVote {
    pub fn new(
        delegator_commitment: impl Into<String>,
        delegate_commitment: impl Into<String>,
        proposal_scope_root: impl Into<String>,
        vote_power_commitment: impl Into<String>,
        nullifier_root: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
        min_privacy_set_size: u64,
    ) -> Self {
        let delegator_commitment = delegator_commitment.into();
        let delegate_commitment = delegate_commitment.into();
        let proposal_scope_root = proposal_scope_root.into();
        let vote_power_commitment = vote_power_commitment.into();
        let nullifier_root = nullifier_root.into();
        let delegation_id = delegation_id(
            &delegator_commitment,
            &delegate_commitment,
            &proposal_scope_root,
            &nullifier_root,
            created_at_height,
        );
        Self {
            delegation_id,
            delegator_commitment,
            delegate_commitment,
            proposal_scope_root,
            vote_power_commitment,
            nullifier_root,
            status: DelegatedVoteStatus::Active,
            created_at_height,
            expires_at_height,
            min_privacy_set_size,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "delegation_id": self.delegation_id,
            "delegator_commitment": self.delegator_commitment,
            "delegate_commitment": self.delegate_commitment,
            "proposal_scope_root": self.proposal_scope_root,
            "vote_power_commitment": self.vote_power_commitment,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "min_privacy_set_size": self.min_privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub subject_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub pq_proof_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub slash_units: u64,
}

impl ChallengeEvidence {
    pub fn new(
        kind: ChallengeKind,
        subject_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        pq_proof_root: impl Into<String>,
        opened_at_height: u64,
        challenge_window_blocks: u64,
        slash_units: u64,
    ) -> Self {
        let subject_id = subject_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        let pq_proof_root = pq_proof_root.into();
        let challenge_id = challenge_id(
            kind,
            &subject_id,
            &challenger_commitment,
            &evidence_root,
            opened_at_height,
        );
        Self {
            challenge_id,
            kind,
            status: ChallengeStatus::Open,
            subject_id,
            challenger_commitment,
            evidence_root,
            pq_proof_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(challenge_window_blocks),
            slash_units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "subject_id": self.subject_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "pq_proof_root": self.pq_proof_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "slash_units": self.slash_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub slashing_id: String,
    pub challenge_id: String,
    pub subject_id: String,
    pub beneficiary_commitment: String,
    pub reason_root: String,
    pub slashed_units: u64,
    pub applied_at_height: u64,
}

impl SlashingRecord {
    pub fn new(
        challenge_id: impl Into<String>,
        subject_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        reason_root: impl Into<String>,
        slashed_units: u64,
        applied_at_height: u64,
    ) -> Self {
        let challenge_id = challenge_id.into();
        let subject_id = subject_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let reason_root = reason_root.into();
        let slashing_id = slashing_id(
            &challenge_id,
            &subject_id,
            &beneficiary_commitment,
            &reason_root,
            applied_at_height,
        );
        Self {
            slashing_id,
            challenge_id,
            subject_id,
            beneficiary_commitment,
            reason_root,
            slashed_units,
            applied_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "challenge_id": self.challenge_id,
            "subject_id": self.subject_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "reason_root": self.reason_root,
            "slashed_units": self.slashed_units,
            "applied_at_height": self.applied_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceCouncilEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl GovernanceCouncilEvent {
    pub fn new(
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        payload_root: impl Into<String>,
        emitted_at_height: u64,
        sequence: u64,
    ) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let payload_root = payload_root.into();
        let event_id = event_id(
            &kind,
            &subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        Self {
            event_id,
            kind,
            subject_id,
            payload_root,
            emitted_at_height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernancePqVetoCouncilRoots {
    pub config_root: String,
    pub proposal_root: String,
    pub council_member_root: String,
    pub veto_attestation_root: String,
    pub pause_scope_root: String,
    pub fee_sponsor_root: String,
    pub delegated_vote_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl PrivateGovernancePqVetoCouncilRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "proposal_root": self.proposal_root,
            "council_member_root": self.council_member_root,
            "veto_attestation_root": self.veto_attestation_root,
            "pause_scope_root": self.pause_scope_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "delegated_vote_root": self.delegated_vote_root,
            "challenge_root": self.challenge_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernancePqVetoCouncilCounters {
    pub proposals: u64,
    pub active_proposals: u64,
    pub queued_proposals: u64,
    pub vetoed_proposals: u64,
    pub council_members: u64,
    pub active_council_members: u64,
    pub veto_attestations: u64,
    pub active_pause_scopes: u64,
    pub fee_sponsors: u64,
    pub delegated_votes: u64,
    pub open_challenges: u64,
    pub slashing_records: u64,
    pub known_nullifiers: u64,
    pub events: u64,
}

impl PrivateGovernancePqVetoCouncilCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "proposals": self.proposals,
            "active_proposals": self.active_proposals,
            "queued_proposals": self.queued_proposals,
            "vetoed_proposals": self.vetoed_proposals,
            "council_members": self.council_members,
            "active_council_members": self.active_council_members,
            "veto_attestations": self.veto_attestations,
            "active_pause_scopes": self.active_pause_scopes,
            "fee_sponsors": self.fee_sponsors,
            "delegated_votes": self.delegated_votes,
            "open_challenges": self.open_challenges,
            "slashing_records": self.slashing_records,
            "known_nullifiers": self.known_nullifiers,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateGovernancePqVetoCouncilState {
    pub config: PrivateGovernancePqVetoCouncilConfig,
    pub current_height: u64,
    pub proposals: BTreeMap<String, ShieldedGovernanceProposal>,
    pub council_members: BTreeMap<String, PqVetoCouncilMember>,
    pub veto_attestations: BTreeMap<String, PqVetoAttestation>,
    pub pause_scopes: BTreeMap<String, EmergencyPauseScope>,
    pub fee_sponsors: BTreeMap<String, FeeSponsorBudget>,
    pub delegated_votes: BTreeMap<String, DelegatedPrivacyVote>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    pub slashings: BTreeMap<String, SlashingRecord>,
    pub nullifiers: BTreeSet<String>,
    pub proposal_veto_index: BTreeMap<String, BTreeSet<String>>,
    pub proposal_delegation_index: BTreeMap<String, BTreeSet<String>>,
    pub member_attestation_index: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
    pub events: BTreeMap<String, GovernanceCouncilEvent>,
    next_event_sequence: u64,
}

impl PrivateGovernancePqVetoCouncilState {
    pub fn new(config: PrivateGovernancePqVetoCouncilConfig, current_height: u64) -> Self {
        Self {
            config,
            current_height,
            proposals: BTreeMap::new(),
            council_members: BTreeMap::new(),
            veto_attestations: BTreeMap::new(),
            pause_scopes: BTreeMap::new(),
            fee_sponsors: BTreeMap::new(),
            delegated_votes: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashings: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            proposal_veto_index: BTreeMap::new(),
            proposal_delegation_index: BTreeMap::new(),
            member_attestation_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: BTreeMap::new(),
            next_event_sequence: 0,
        }
    }

    pub fn devnet() -> Self {
        let config = PrivateGovernancePqVetoCouncilConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_DEVNET_HEIGHT,
        );
        let sponsor = FeeSponsorBudget::new(
            seeded("devnet-sponsor-commitment"),
            seeded("devnet-sponsor-budget"),
            seeded("devnet-sponsor-policy"),
            config.default_sponsor_budget_units,
            config.max_sponsored_fee_units,
            state.current_height,
            state
                .current_height
                .saturating_add(config.proposal_ttl_blocks.saturating_mul(4)),
        );
        let sponsor_id = sponsor.sponsor_id.clone();
        let _ = state.insert_fee_sponsor(sponsor);
        for index in 0..5 {
            let member = PqVetoCouncilMember::new(
                seeded(&format!("devnet-member-{index}-commitment")),
                seeded(&format!("devnet-member-{index}-pq-key")),
                seeded(&format!("devnet-member-{index}-roles")),
                if index == 0 { 2 } else { 1 },
                config.default_slash_bond_units,
                state.current_height,
            );
            let _ = state.insert_council_member(member);
        }
        let mut proposal = ShieldedGovernanceProposal::new(
            ShieldedProposalKind::SmartContractRuntime,
            seeded("devnet-proposer"),
            seeded("runtime-upgrade-action-root"),
            seeded("runtime-upgrade-private-envelope-root"),
            seeded("runtime-upgrade-metadata"),
            seeded("runtime-upgrade-vote-root"),
            seeded("runtime-upgrade-voter-root"),
            sponsor_id,
            state.current_height,
            &config,
        );
        proposal.status = ShieldedProposalStatus::Active;
        let proposal_id = proposal.proposal_id.clone();
        let _ = state.insert_proposal(proposal);
        let delegation = DelegatedPrivacyVote::new(
            seeded("devnet-delegator"),
            seeded("devnet-delegate"),
            seeded("runtime-upgrade-scope"),
            seeded("runtime-upgrade-vote-power"),
            seeded("runtime-upgrade-delegation-nullifier"),
            state.current_height,
            state
                .current_height
                .saturating_add(config.proposal_ttl_blocks),
            config.min_privacy_set_size,
        );
        let _ = state.insert_delegated_vote(delegation, &proposal_id);
        let _ = state.validate();
        state
    }

    pub fn update_height(&mut self, new_height: u64) -> PrivateGovernancePqVetoCouncilResult<()> {
        if new_height < self.current_height {
            return Err("height update must be monotonic".to_string());
        }
        self.current_height = new_height;
        self.expire_records();
        self.record_event(
            "height_update",
            "state",
            private_governance_json_root("HEIGHT-UPDATE", &json!({ "height": new_height })),
        );
        Ok(())
    }

    pub fn insert_proposal(
        &mut self,
        proposal: ShieldedGovernanceProposal,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        self.ensure_capacity()?;
        if proposal.created_at_height > self.current_height {
            return Err("proposal created_at_height exceeds current height".to_string());
        }
        if proposal.expires_at_height <= proposal.created_at_height {
            return Err("proposal expiry must exceed creation height".to_string());
        }
        if proposal.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("proposal privacy set below config minimum".to_string());
        }
        let proposal_id = proposal.proposal_id.clone();
        if self.proposals.contains_key(&proposal_id) {
            return Err("proposal already exists".to_string());
        }
        let payload_root = private_governance_json_root("PROPOSAL", &proposal.public_record());
        self.public_records
            .insert(format!("proposal:{proposal_id}"), proposal.public_record());
        self.proposals.insert(proposal_id.clone(), proposal);
        self.record_event("proposal_inserted", &proposal_id, payload_root);
        Ok(proposal_id)
    }

    pub fn insert_council_member(
        &mut self,
        member: PqVetoCouncilMember,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        self.ensure_capacity()?;
        if member.voting_weight == 0 {
            return Err("council member voting weight must be nonzero".to_string());
        }
        let member_id = member.member_id.clone();
        if self.council_members.contains_key(&member_id) {
            return Err("council member already exists".to_string());
        }
        let payload_root = private_governance_json_root("COUNCIL-MEMBER", &member.public_record());
        self.public_records.insert(
            format!("council_member:{member_id}"),
            member.public_record(),
        );
        self.council_members.insert(member_id.clone(), member);
        self.record_event("council_member_inserted", &member_id, payload_root);
        Ok(member_id)
    }

    pub fn insert_fee_sponsor(
        &mut self,
        sponsor: FeeSponsorBudget,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        self.ensure_capacity()?;
        if sponsor.total_budget_units == 0 {
            return Err("fee sponsor total budget must be nonzero".to_string());
        }
        if sponsor.max_fee_per_action_units > self.config.max_sponsored_fee_units {
            return Err("fee sponsor max fee exceeds config maximum".to_string());
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        if self.fee_sponsors.contains_key(&sponsor_id) {
            return Err("fee sponsor already exists".to_string());
        }
        let payload_root = private_governance_json_root("FEE-SPONSOR", &sponsor.public_record());
        self.public_records
            .insert(format!("fee_sponsor:{sponsor_id}"), sponsor.public_record());
        self.fee_sponsors.insert(sponsor_id.clone(), sponsor);
        self.record_event("fee_sponsor_inserted", &sponsor_id, payload_root);
        Ok(sponsor_id)
    }

    pub fn reserve_sponsored_fee(
        &mut self,
        sponsor_id: &str,
        units: u64,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let sponsor = self
            .fee_sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "fee sponsor not found".to_string())?;
        sponsor.reserve(units)?;
        let root = private_governance_json_root("FEE-SPONSOR-RESERVE", &sponsor.public_record());
        self.record_event("fee_sponsor_reserved", sponsor_id, root.clone());
        Ok(root)
    }

    pub fn insert_delegated_vote(
        &mut self,
        delegation: DelegatedPrivacyVote,
        proposal_id: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        self.ensure_capacity()?;
        if !self.proposals.contains_key(proposal_id) {
            return Err("delegated vote references unknown proposal".to_string());
        }
        if delegation.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("delegated vote privacy set below config minimum".to_string());
        }
        if self.nullifiers.contains(&delegation.nullifier_root) {
            return Err("delegated vote nullifier already used".to_string());
        }
        let delegation_id = delegation.delegation_id.clone();
        self.nullifiers.insert(delegation.nullifier_root.clone());
        self.proposal_delegation_index
            .entry(proposal_id.to_string())
            .or_default()
            .insert(delegation_id.clone());
        let payload_root =
            private_governance_json_root("DELEGATED-VOTE", &delegation.public_record());
        self.public_records.insert(
            format!("delegated_vote:{delegation_id}"),
            delegation.public_record(),
        );
        self.delegated_votes
            .insert(delegation_id.clone(), delegation);
        self.record_event("delegated_vote_inserted", &delegation_id, payload_root);
        Ok(delegation_id)
    }

    pub fn insert_veto_attestation(
        &mut self,
        mut attestation: PqVetoAttestation,
        signer_member_ids: &[String],
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        self.ensure_capacity()?;
        let proposal = self
            .proposals
            .get(&attestation.proposal_id)
            .ok_or_else(|| "veto attestation references unknown proposal".to_string())?;
        if !proposal.status.mutable() {
            return Err("proposal cannot receive veto attestation in terminal status".to_string());
        }
        if self.nullifiers.contains(&attestation.nullifier_root) {
            return Err("veto nullifier already used".to_string());
        }
        let mut observed_weight = 0_u64;
        for member_id in signer_member_ids {
            let member = self
                .council_members
                .get(member_id)
                .ok_or_else(|| "veto signer is not a council member".to_string())?;
            if !member.can_attest(attestation.attested_at_height) {
                return Err("veto signer cannot attest at attestation height".to_string());
            }
            observed_weight = observed_weight.saturating_add(member.voting_weight);
        }
        if observed_weight != attestation.signer_weight {
            return Err("veto signer weight does not match council member index".to_string());
        }
        let required_weight = if attestation.kind == VetoAttestationKind::EmergencyPause {
            self.config.emergency_weight
        } else {
            proposal.required_veto_weight
        };
        if attestation.signer_weight >= required_weight {
            attestation.status = VetoAttestationStatus::QuorumMet;
        }
        let attestation_id = attestation.attestation_id.clone();
        self.nullifiers.insert(attestation.nullifier_root.clone());
        for member_id in signer_member_ids {
            if let Some(member) = self.council_members.get_mut(member_id) {
                member.last_attested_height = self.current_height;
            }
            self.member_attestation_index
                .entry(member_id.clone())
                .or_default()
                .insert(attestation_id.clone());
        }
        self.proposal_veto_index
            .entry(attestation.proposal_id.clone())
            .or_default()
            .insert(attestation_id.clone());
        let payload_root =
            private_governance_json_root("VETO-ATTESTATION", &attestation.public_record());
        self.public_records.insert(
            format!("veto_attestation:{attestation_id}"),
            attestation.public_record(),
        );
        self.veto_attestations
            .insert(attestation_id.clone(), attestation);
        self.record_event("veto_attestation_inserted", &attestation_id, payload_root);
        Ok(attestation_id)
    }

    pub fn apply_veto(
        &mut self,
        proposal_id: &str,
        attestation_id: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let attestation = self
            .veto_attestations
            .get_mut(attestation_id)
            .ok_or_else(|| "veto attestation not found".to_string())?;
        if attestation.proposal_id != proposal_id {
            return Err("veto attestation does not belong to proposal".to_string());
        }
        if attestation.status != VetoAttestationStatus::QuorumMet {
            return Err("veto attestation has not met quorum".to_string());
        }
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        if !proposal.status.mutable() {
            return Err("proposal cannot be vetoed from terminal status".to_string());
        }
        attestation.status = VetoAttestationStatus::Applied;
        proposal.status = ShieldedProposalStatus::Vetoed;
        let root = private_governance_json_root(
            "APPLIED-VETO",
            &json!({ "proposal_id": proposal_id, "attestation_id": attestation_id }),
        );
        self.record_event("veto_applied", proposal_id, root.clone());
        Ok(root)
    }

    pub fn insert_pause_scope(
        &mut self,
        mut pause_scope: EmergencyPauseScope,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        self.ensure_capacity()?;
        if !self
            .veto_attestations
            .contains_key(&pause_scope.attestation_id)
        {
            return Err("pause scope references unknown attestation".to_string());
        }
        if pause_scope.max_duration_blocks == 0 {
            return Err("pause scope max duration must be nonzero".to_string());
        }
        pause_scope.status = PauseScopeStatus::Active;
        let scope_id = pause_scope.scope_id.clone();
        let payload_root =
            private_governance_json_root("PAUSE-SCOPE", &pause_scope.public_record());
        self.public_records.insert(
            format!("pause_scope:{scope_id}"),
            pause_scope.public_record(),
        );
        self.pause_scopes.insert(scope_id.clone(), pause_scope);
        self.record_event("pause_scope_inserted", &scope_id, payload_root);
        Ok(scope_id)
    }

    pub fn queue_proposal(
        &mut self,
        proposal_id: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        if proposal.status != ShieldedProposalStatus::Tallied {
            return Err("only tallied proposals can be queued".to_string());
        }
        proposal.queue(self.current_height, self.config.timelock_blocks);
        let root = private_governance_json_root("QUEUE-PROPOSAL", &proposal.public_record());
        self.record_event("proposal_queued", proposal_id, root.clone());
        Ok(root)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: ChallengeEvidence,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        self.ensure_capacity()?;
        if challenge.slash_units == 0 {
            return Err("challenge slash units must be nonzero".to_string());
        }
        if challenge.opened_at_height > self.current_height {
            return Err("challenge opened_at_height exceeds current height".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        if self.challenges.contains_key(&challenge_id) {
            return Err("challenge already exists".to_string());
        }
        if let Some(attestation) = self.veto_attestations.get_mut(&challenge.subject_id) {
            attestation.status = VetoAttestationStatus::Challenged;
        }
        if let Some(scope) = self.pause_scopes.get_mut(&challenge.subject_id) {
            scope.status = PauseScopeStatus::Challenged;
        }
        let payload_root = private_governance_json_root("CHALLENGE", &challenge.public_record());
        self.public_records.insert(
            format!("challenge:{challenge_id}"),
            challenge.public_record(),
        );
        self.challenges.insert(challenge_id.clone(), challenge);
        self.record_event("challenge_inserted", &challenge_id, payload_root);
        Ok(challenge_id)
    }

    pub fn accept_challenge_and_slash(
        &mut self,
        challenge_id: &str,
        beneficiary_commitment: &str,
        reason_root: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        if challenge.status != ChallengeStatus::Open {
            return Err("only open challenges can be accepted".to_string());
        }
        if self.current_height > challenge.expires_at_height {
            challenge.status = ChallengeStatus::Expired;
            return Err("challenge window expired".to_string());
        }
        challenge.status = ChallengeStatus::Slashed;
        if let Some(attestation) = self.veto_attestations.get_mut(&challenge.subject_id) {
            attestation.status = VetoAttestationStatus::Slashed;
        }
        let slashing = SlashingRecord::new(
            challenge_id,
            &challenge.subject_id,
            beneficiary_commitment,
            reason_root,
            challenge.slash_units,
            self.current_height,
        );
        let slashing_id = slashing.slashing_id.clone();
        self.slashings.insert(slashing_id.clone(), slashing);
        let root = private_governance_json_root(
            "CHALLENGE-SLASH",
            &json!({ "challenge_id": challenge_id, "slashing_id": slashing_id }),
        );
        self.record_event("challenge_slashed", challenge_id, root.clone());
        Ok(slashing_id)
    }

    pub fn activate_proposal(
        &mut self,
        proposal_id: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        if proposal.status != ShieldedProposalStatus::Draft {
            return Err("only draft proposals can be activated".to_string());
        }
        if self.current_height < proposal.activation_height {
            return Err("proposal activation height has not arrived".to_string());
        }
        proposal.status = ShieldedProposalStatus::Active;
        let root = private_governance_json_root("ACTIVATE-PROPOSAL", &proposal.public_record());
        self.record_event("proposal_activated", proposal_id, root.clone());
        Ok(root)
    }

    pub fn mark_reveal_pending(
        &mut self,
        proposal_id: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        if proposal.status != ShieldedProposalStatus::Active {
            return Err("only active proposals can enter reveal pending".to_string());
        }
        if self.current_height < proposal.reveal_height {
            return Err("proposal reveal height has not arrived".to_string());
        }
        proposal.status = ShieldedProposalStatus::RevealPending;
        let root = private_governance_json_root("REVEAL-PENDING", &proposal.public_record());
        self.record_event("proposal_reveal_pending", proposal_id, root.clone());
        Ok(root)
    }

    pub fn record_tally(
        &mut self,
        proposal_id: &str,
        tally_commitment: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        if proposal.status != ShieldedProposalStatus::RevealPending {
            return Err("only reveal-pending proposals can be tallied".to_string());
        }
        if tally_commitment.is_empty() {
            return Err("tally commitment must be nonempty".to_string());
        }
        proposal.status = ShieldedProposalStatus::Tallied;
        proposal.tally_commitment = tally_commitment.to_string();
        let root = private_governance_json_root("PROPOSAL-TALLY", &proposal.public_record());
        self.record_event("proposal_tallied", proposal_id, root.clone());
        Ok(root)
    }

    pub fn execute_queued_proposal(
        &mut self,
        proposal_id: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        if self.has_blocking_pause(EmergencyPauseScopeKind::GovernanceExecution) {
            return Err("governance execution pause is active".to_string());
        }
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        if proposal.status != ShieldedProposalStatus::Queued {
            return Err("only queued proposals can execute".to_string());
        }
        if self.current_height < proposal.executable_after_height {
            return Err("proposal timelock has not elapsed".to_string());
        }
        proposal.status = ShieldedProposalStatus::Executed;
        let root = private_governance_json_root("EXECUTE-PROPOSAL", &proposal.public_record());
        self.record_event("proposal_executed", proposal_id, root.clone());
        Ok(root)
    }

    pub fn release_pause_scope(
        &mut self,
        scope_id: &str,
        release_reason_root: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let scope = self
            .pause_scopes
            .get_mut(scope_id)
            .ok_or_else(|| "pause scope not found".to_string())?;
        if !scope.status.blocking() {
            return Err("pause scope is not blocking".to_string());
        }
        if release_reason_root.is_empty() {
            return Err("release reason root must be nonempty".to_string());
        }
        scope.status = PauseScopeStatus::Released;
        let root = private_governance_json_root(
            "RELEASE-PAUSE-SCOPE",
            &json!({
                "scope_id": scope_id,
                "release_reason_root": release_reason_root,
                "released_at_height": self.current_height,
            }),
        );
        self.record_event("pause_scope_released", scope_id, root.clone());
        Ok(root)
    }

    pub fn revoke_delegated_vote(
        &mut self,
        delegation_id: &str,
        revocation_root: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let delegation = self
            .delegated_votes
            .get_mut(delegation_id)
            .ok_or_else(|| "delegated vote not found".to_string())?;
        if delegation.status != DelegatedVoteStatus::Active {
            return Err("only active delegated votes can be revoked".to_string());
        }
        if revocation_root.is_empty() {
            return Err("revocation root must be nonempty".to_string());
        }
        delegation.status = DelegatedVoteStatus::Revoked;
        let root = private_governance_json_root(
            "REVOKE-DELEGATED-VOTE",
            &json!({
                "delegation_id": delegation_id,
                "revocation_root": revocation_root,
                "revoked_at_height": self.current_height,
            }),
        );
        self.record_event("delegated_vote_revoked", delegation_id, root.clone());
        Ok(root)
    }

    pub fn settle_sponsored_fee(
        &mut self,
        sponsor_id: &str,
        units: u64,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let sponsor = self
            .fee_sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "fee sponsor not found".to_string())?;
        sponsor.settle_reserved(units)?;
        let root = private_governance_json_root("FEE-SPONSOR-SETTLE", &sponsor.public_record());
        self.record_event("fee_sponsor_settled", sponsor_id, root.clone());
        Ok(root)
    }

    pub fn suspend_council_member(
        &mut self,
        member_id: &str,
        until_height: u64,
        reason_root: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let member = self
            .council_members
            .get_mut(member_id)
            .ok_or_else(|| "council member not found".to_string())?;
        if until_height <= self.current_height {
            return Err("suspension height must be in the future".to_string());
        }
        if reason_root.is_empty() {
            return Err("suspension reason root must be nonempty".to_string());
        }
        member.suspended_until_height = until_height;
        let root = private_governance_json_root(
            "SUSPEND-COUNCIL-MEMBER",
            &json!({
                "member_id": member_id,
                "until_height": until_height,
                "reason_root": reason_root,
            }),
        );
        self.record_event("council_member_suspended", member_id, root.clone());
        Ok(root)
    }

    pub fn retire_council_member(
        &mut self,
        member_id: &str,
        retirement_root: &str,
    ) -> PrivateGovernancePqVetoCouncilResult<String> {
        let member = self
            .council_members
            .get_mut(member_id)
            .ok_or_else(|| "council member not found".to_string())?;
        if retirement_root.is_empty() {
            return Err("retirement root must be nonempty".to_string());
        }
        member.active = false;
        let root = private_governance_json_root(
            "RETIRE-COUNCIL-MEMBER",
            &json!({
                "member_id": member_id,
                "retirement_root": retirement_root,
                "retired_at_height": self.current_height,
            }),
        );
        self.record_event("council_member_retired", member_id, root.clone());
        Ok(root)
    }

    pub fn public_record_by_key(&self, key: &str) -> Option<Value> {
        self.public_records.get(key).cloned()
    }

    pub fn proposal_vetoes(&self, proposal_id: &str) -> Vec<String> {
        match self.proposal_veto_index.get(proposal_id) {
            Some(items) => items.iter().cloned().collect::<Vec<_>>(),
            None => Vec::new(),
        }
    }

    pub fn proposal_delegations(&self, proposal_id: &str) -> Vec<String> {
        match self.proposal_delegation_index.get(proposal_id) {
            Some(items) => items.iter().cloned().collect::<Vec<_>>(),
            None => Vec::new(),
        }
    }

    pub fn member_attestations(&self, member_id: &str) -> Vec<String> {
        match self.member_attestation_index.get(member_id) {
            Some(items) => items.iter().cloned().collect::<Vec<_>>(),
            None => Vec::new(),
        }
    }

    pub fn active_pause_scope_ids(&self) -> Vec<String> {
        self.pause_scopes
            .iter()
            .filter(|(_, scope)| scope.status.blocking())
            .map(|(scope_id, _)| scope_id.clone())
            .collect()
    }

    pub fn has_blocking_pause(&self, kind: EmergencyPauseScopeKind) -> bool {
        self.pause_scopes
            .values()
            .any(|scope| scope.kind == kind && scope.status.blocking())
    }

    pub fn total_active_veto_weight(&self) -> u64 {
        self.council_members
            .values()
            .filter(|member| member.can_attest(self.current_height))
            .fold(0_u64, |total, member| {
                total.saturating_add(member.voting_weight)
            })
    }

    pub fn signer_set_root_for_members(&self, member_ids: &[String]) -> String {
        let leaves = member_ids
            .iter()
            .filter_map(|member_id| self.council_members.get(member_id))
            .map(|member| member.public_record())
            .collect::<Vec<_>>();
        merkle_root("PRIVATE-GOVERNANCE-SIGNER-SET", &leaves)
    }

    pub fn roots(&self) -> PrivateGovernancePqVetoCouncilRoots {
        PrivateGovernancePqVetoCouncilRoots {
            config_root: private_governance_json_root("CONFIG", &self.config.public_record()),
            proposal_root: map_root(
                "PRIVATE-GOVERNANCE-PROPOSALS",
                self.proposals
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            council_member_root: map_root(
                "PRIVATE-GOVERNANCE-COUNCIL-MEMBERS",
                self.council_members
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            veto_attestation_root: map_root(
                "PRIVATE-GOVERNANCE-VETO-ATTESTATIONS",
                self.veto_attestations
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            pause_scope_root: map_root(
                "PRIVATE-GOVERNANCE-PAUSE-SCOPES",
                self.pause_scopes
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            fee_sponsor_root: map_root(
                "PRIVATE-GOVERNANCE-FEE-SPONSORS",
                self.fee_sponsors
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            delegated_vote_root: map_root(
                "PRIVATE-GOVERNANCE-DELEGATED-VOTES",
                self.delegated_votes
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            challenge_root: map_root(
                "PRIVATE-GOVERNANCE-CHALLENGES",
                self.challenges
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            slashing_root: map_root(
                "PRIVATE-GOVERNANCE-SLASHINGS",
                self.slashings
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            nullifier_root: set_root("PRIVATE-GOVERNANCE-NULLIFIERS", &self.nullifiers),
            event_root: map_root(
                "PRIVATE-GOVERNANCE-EVENTS",
                self.events
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
        }
    }

    pub fn counters(&self) -> PrivateGovernancePqVetoCouncilCounters {
        PrivateGovernancePqVetoCouncilCounters {
            proposals: self.proposals.len() as u64,
            active_proposals: self
                .proposals
                .values()
                .filter(|proposal| proposal.status == ShieldedProposalStatus::Active)
                .count() as u64,
            queued_proposals: self
                .proposals
                .values()
                .filter(|proposal| proposal.status == ShieldedProposalStatus::Queued)
                .count() as u64,
            vetoed_proposals: self
                .proposals
                .values()
                .filter(|proposal| proposal.status == ShieldedProposalStatus::Vetoed)
                .count() as u64,
            council_members: self.council_members.len() as u64,
            active_council_members: self
                .council_members
                .values()
                .filter(|member| member.active)
                .count() as u64,
            veto_attestations: self.veto_attestations.len() as u64,
            active_pause_scopes: self
                .pause_scopes
                .values()
                .filter(|scope| scope.status.blocking())
                .count() as u64,
            fee_sponsors: self.fee_sponsors.len() as u64,
            delegated_votes: self.delegated_votes.len() as u64,
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count() as u64,
            slashing_records: self.slashings.len() as u64,
            known_nullifiers: self.nullifiers.len() as u64,
            events: self.events.len() as u64,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "schema": PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PUBLIC_RECORD_SCHEMA,
            "protocol_id": PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PROTOCOL_ID,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        private_governance_json_root("STATE", &self.public_record_without_state_root())
    }

    pub fn validate(&self) -> PrivateGovernancePqVetoCouncilResult<()> {
        self.config.validate()?;
        if self.proposals.len() > PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_MAX_RECORDS {
            return Err("proposal record capacity exceeded".to_string());
        }
        for (proposal_id, proposal) in &self.proposals {
            if proposal_id != &proposal.proposal_id {
                return Err("proposal map key mismatch".to_string());
            }
            if proposal.expires_at_height <= proposal.created_at_height {
                return Err("proposal expiry must exceed creation height".to_string());
            }
            if proposal.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("proposal privacy set below config minimum".to_string());
            }
            if !proposal.sponsor_id.is_empty()
                && !self.fee_sponsors.contains_key(&proposal.sponsor_id)
            {
                return Err("proposal references unknown sponsor".to_string());
            }
        }
        for (member_id, member) in &self.council_members {
            if member_id != &member.member_id {
                return Err("council member map key mismatch".to_string());
            }
            if member.voting_weight == 0 {
                return Err("council member has zero voting weight".to_string());
            }
        }
        for (attestation_id, attestation) in &self.veto_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("veto attestation map key mismatch".to_string());
            }
            if !self.proposals.contains_key(&attestation.proposal_id) {
                return Err("veto attestation references unknown proposal".to_string());
            }
            if attestation.expires_at_height <= attestation.attested_at_height {
                return Err("veto attestation expiry must exceed attestation height".to_string());
            }
        }
        for (scope_id, scope) in &self.pause_scopes {
            if scope_id != &scope.scope_id {
                return Err("pause scope map key mismatch".to_string());
            }
            if !self.veto_attestations.contains_key(&scope.attestation_id) {
                return Err("pause scope references unknown attestation".to_string());
            }
        }
        for (sponsor_id, sponsor) in &self.fee_sponsors {
            if sponsor_id != &sponsor.sponsor_id {
                return Err("fee sponsor map key mismatch".to_string());
            }
            if sponsor.reserved_units.saturating_add(sponsor.spent_units)
                > sponsor.total_budget_units
            {
                return Err("fee sponsor overspent".to_string());
            }
        }
        for (delegation_id, delegation) in &self.delegated_votes {
            if delegation_id != &delegation.delegation_id {
                return Err("delegated vote map key mismatch".to_string());
            }
            if !self.nullifiers.contains(&delegation.nullifier_root) {
                return Err("delegated vote nullifier missing from global set".to_string());
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            if challenge_id != &challenge.challenge_id {
                return Err("challenge map key mismatch".to_string());
            }
            if challenge.expires_at_height <= challenge.opened_at_height {
                return Err("challenge expiry must exceed opened height".to_string());
            }
        }
        for (event_id, event) in &self.events {
            if event_id != &event.event_id {
                return Err("event map key mismatch".to_string());
            }
        }
        Ok(())
    }

    fn ensure_capacity(&self) -> PrivateGovernancePqVetoCouncilResult<()> {
        let total = self
            .proposals
            .len()
            .saturating_add(self.council_members.len())
            .saturating_add(self.veto_attestations.len())
            .saturating_add(self.pause_scopes.len())
            .saturating_add(self.fee_sponsors.len())
            .saturating_add(self.delegated_votes.len())
            .saturating_add(self.challenges.len())
            .saturating_add(self.slashings.len());
        if total >= PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_MAX_RECORDS {
            return Err("private governance pq veto council capacity exceeded".to_string());
        }
        Ok(())
    }

    fn expire_records(&mut self) {
        for proposal in self.proposals.values_mut() {
            if proposal.status.mutable() && self.current_height > proposal.expires_at_height {
                proposal.status = ShieldedProposalStatus::Expired;
            }
        }
        for attestation in self.veto_attestations.values_mut() {
            if matches!(
                attestation.status,
                VetoAttestationStatus::Collected | VetoAttestationStatus::QuorumMet
            ) && self.current_height > attestation.expires_at_height
            {
                attestation.status = VetoAttestationStatus::Expired;
            }
        }
        for scope in self.pause_scopes.values_mut() {
            if scope.status.blocking() && self.current_height > scope.releases_at_height {
                scope.status = PauseScopeStatus::Expired;
            }
        }
        for sponsor in self.fee_sponsors.values_mut() {
            if sponsor.status == FeeSponsorStatus::Active
                && self.current_height > sponsor.expires_at_height
            {
                sponsor.status = FeeSponsorStatus::Revoked;
            }
        }
        for delegation in self.delegated_votes.values_mut() {
            if delegation.status == DelegatedVoteStatus::Active
                && self.current_height > delegation.expires_at_height
            {
                delegation.status = DelegatedVoteStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open
                && self.current_height > challenge.expires_at_height
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }

    fn record_event(&mut self, kind: &str, subject_id: &str, payload_root: String) {
        let event = GovernanceCouncilEvent::new(
            kind,
            subject_id,
            payload_root,
            self.current_height,
            self.next_event_sequence,
        );
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        self.events.insert(event.event_id.clone(), event);
    }
}

pub fn devnet() -> PrivateGovernancePqVetoCouncilState {
    PrivateGovernancePqVetoCouncilState::devnet()
}

pub fn private_governance_json_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PROTOCOL_ID),
            HashPart::Json(value),
        ],
        32,
    )
}

fn private_governance_seeded_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut scoped_parts = Vec::with_capacity(parts.len().saturating_add(2));
    scoped_parts.push(HashPart::Str(CHAIN_ID));
    scoped_parts.push(HashPart::Str(
        PRIVATE_GOVERNANCE_PQ_VETO_COUNCIL_PROTOCOL_ID,
    ));
    for part in parts {
        match part {
            HashPart::Bytes(value) => scoped_parts.push(HashPart::Bytes(value)),
            HashPart::Str(value) => scoped_parts.push(HashPart::Str(value)),
            HashPart::U64(value) => scoped_parts.push(HashPart::U64(*value)),
            HashPart::Int(value) => scoped_parts.push(HashPart::Int(*value)),
            HashPart::Json(value) => scoped_parts.push(HashPart::Json(value)),
        }
    }
    domain_hash(domain, &scoped_parts, 32)
}

fn seeded(seed: &str) -> String {
    private_governance_seeded_hash("PRIVATE-GOVERNANCE-DEVNET-SEED", &[HashPart::Str(seed)])
}

fn proposal_id(
    kind: ShieldedProposalKind,
    proposer_commitment: &str,
    action_commitment_root: &str,
    encrypted_payload_root: &str,
    created_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-PROPOSAL-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(proposer_commitment),
            HashPart::Str(action_commitment_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(created_at_height as i128),
        ],
    )
}

fn council_member_id(
    member_commitment: &str,
    pq_public_key_root: &str,
    role_root: &str,
    joined_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-COUNCIL-MEMBER-ID",
        &[
            HashPart::Str(member_commitment),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(role_root),
            HashPart::Int(joined_at_height as i128),
        ],
    )
}

fn veto_attestation_id(
    proposal_id: &str,
    kind: VetoAttestationKind,
    signer_set_root: &str,
    pq_signature_root: &str,
    nullifier_root: &str,
    attested_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-VETO-ATTESTATION-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(signer_set_root),
            HashPart::Str(pq_signature_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(attested_at_height as i128),
        ],
    )
}

fn pause_scope_id(
    kind: EmergencyPauseScopeKind,
    proposal_id: &str,
    attestation_id: &str,
    scope_commitment_root: &str,
    opened_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-PAUSE-SCOPE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(proposal_id),
            HashPart::Str(attestation_id),
            HashPart::Str(scope_commitment_root),
            HashPart::Int(opened_at_height as i128),
        ],
    )
}

fn fee_sponsor_id(
    sponsor_commitment: &str,
    budget_commitment: &str,
    policy_root: &str,
    opened_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-FEE-SPONSOR-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(budget_commitment),
            HashPart::Str(policy_root),
            HashPart::Int(opened_at_height as i128),
        ],
    )
}

fn delegation_id(
    delegator_commitment: &str,
    delegate_commitment: &str,
    proposal_scope_root: &str,
    nullifier_root: &str,
    created_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-DELEGATION-ID",
        &[
            HashPart::Str(delegator_commitment),
            HashPart::Str(delegate_commitment),
            HashPart::Str(proposal_scope_root),
            HashPart::Str(nullifier_root),
            HashPart::Int(created_at_height as i128),
        ],
    )
}

fn challenge_id(
    kind: ChallengeKind,
    subject_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-CHALLENGE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
    )
}

fn slashing_id(
    challenge_id: &str,
    subject_id: &str,
    beneficiary_commitment: &str,
    reason_root: &str,
    applied_at_height: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-SLASHING-ID",
        &[
            HashPart::Str(challenge_id),
            HashPart::Str(subject_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(reason_root),
            HashPart::Int(applied_at_height as i128),
        ],
    )
}

fn event_id(
    kind: &str,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    private_governance_seeded_hash(
        "PRIVATE-GOVERNANCE-EVENT-ID",
        &[
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
    )
}

fn map_root<'a, I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = (&'a String, Value)>,
{
    let leaves = records
        .into_iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_stable_root() {
        let state = PrivateGovernancePqVetoCouncilState::devnet();
        let first = state.state_root();
        let second = PrivateGovernancePqVetoCouncilState::devnet().state_root();
        assert_eq!(first, second);
        assert!(state.validate().is_ok());
    }

    #[test]
    fn monotonic_height_rejects_rewind() {
        let mut state = PrivateGovernancePqVetoCouncilState::devnet();
        let current = state.current_height;
        assert!(state.update_height(current.saturating_sub(1)).is_err());
    }

    #[test]
    fn duplicate_delegation_nullifier_is_rejected() {
        let mut state = PrivateGovernancePqVetoCouncilState::devnet();
        let proposal_id = match state.proposals.keys().next() {
            Some(value) => value.clone(),
            None => String::new(),
        };
        let delegation = DelegatedPrivacyVote::new(
            seeded("devnet-delegator-2"),
            seeded("devnet-delegate-2"),
            seeded("runtime-upgrade-scope"),
            seeded("runtime-upgrade-vote-power-2"),
            seeded("runtime-upgrade-delegation-nullifier"),
            state.current_height,
            state
                .current_height
                .saturating_add(state.config.proposal_ttl_blocks),
            state.config.min_privacy_set_size,
        );
        assert!(state
            .insert_delegated_vote(delegation, &proposal_id)
            .is_err());
    }
}
