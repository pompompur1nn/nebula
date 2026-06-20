use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type ShieldedTokenGovernanceResult<T> = Result<T, String>;

pub const SHIELDED_TOKEN_GOVERNANCE_PROTOCOL_VERSION: u32 = 1;
pub const SHIELDED_TOKEN_GOVERNANCE_DEVNET_HEIGHT: u64 = 192;
pub const SHIELDED_TOKEN_GOVERNANCE_DEVNET_TOKEN_ID: &str = "gov-nebula-devnet";
pub const SHIELDED_TOKEN_GOVERNANCE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const SHIELDED_TOKEN_GOVERNANCE_PQ_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-governance-v1";
pub const SHIELDED_TOKEN_GOVERNANCE_VOTE_NOTE_SCHEME: &str = "shielded-governance-vote-note-v1";
pub const SHIELDED_TOKEN_GOVERNANCE_DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 2_880;
pub const SHIELDED_TOKEN_GOVERNANCE_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 16;
pub const SHIELDED_TOKEN_GOVERNANCE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const SHIELDED_TOKEN_GOVERNANCE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const SHIELDED_TOKEN_GOVERNANCE_DEFAULT_QUORUM_BPS: u64 = 2_000;
pub const SHIELDED_TOKEN_GOVERNANCE_DEFAULT_APPROVAL_BPS: u64 = 5_500;
pub const SHIELDED_TOKEN_GOVERNANCE_DEFAULT_LOW_FEE_SPONSOR_UNITS: u64 = 120_000;
pub const SHIELDED_TOKEN_GOVERNANCE_MAX_BPS: u64 = 10_000;
pub const SHIELDED_TOKEN_GOVERNANCE_MAX_PROPOSALS: usize = 131_072;
pub const SHIELDED_TOKEN_GOVERNANCE_MAX_VOTES: usize = 1_048_576;
pub const SHIELDED_TOKEN_GOVERNANCE_MAX_TALLIES: usize = 131_072;
pub const SHIELDED_TOKEN_GOVERNANCE_MAX_DELEGATIONS: usize = 262_144;
pub const SHIELDED_TOKEN_GOVERNANCE_MAX_ATTESTATIONS: usize = 262_144;
pub const SHIELDED_TOKEN_GOVERNANCE_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceProposalKind {
    ProtocolUpgrade,
    FeePolicy,
    TokenParameter,
    VaultStrategy,
    BridgeLimit,
    TreasurySpend,
    EmergencyPause,
}

impl GovernanceProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolUpgrade => "protocol_upgrade",
            Self::FeePolicy => "fee_policy",
            Self::TokenParameter => "token_parameter",
            Self::VaultStrategy => "vault_strategy",
            Self::BridgeLimit => "bridge_limit",
            Self::TreasurySpend => "treasury_spend",
            Self::EmergencyPause => "emergency_pause",
        }
    }

    pub fn high_risk(self) -> bool {
        matches!(
            self,
            Self::ProtocolUpgrade | Self::BridgeLimit | Self::TreasurySpend | Self::EmergencyPause
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceProposalStatus {
    Draft,
    Active,
    RevealPending,
    Tallied,
    Queued,
    Executed,
    Rejected,
    Expired,
    Vetoed,
}

impl GovernanceProposalStatus {
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
        }
    }

    pub fn accepts_votes(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedVoteChoice {
    Yes,
    No,
    Abstain,
    Veto,
}

impl ShieldedVoteChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Abstain => "abstain",
            Self::Veto => "veto",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedVoteStatus {
    Committed,
    NullifierChecked,
    WeightProved,
    Tallied,
    Rejected,
    Expired,
}

impl ShieldedVoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::NullifierChecked => "nullifier_checked",
            Self::WeightProved => "weight_proved",
            Self::Tallied => "tallied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::NullifierChecked | Self::WeightProved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationStatus {
    Active,
    Paused,
    Revoked,
    Expired,
}

impl DelegationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTokenGovernanceConfig {
    pub chain_id: String,
    pub token_id: String,
    pub protocol_version: u32,
    pub hash_suite: String,
    pub pq_suite: String,
    pub vote_note_scheme: String,
    pub proposal_ttl_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quorum_bps: u64,
    pub approval_bps: u64,
    pub low_fee_sponsor_units: u64,
}

impl ShieldedTokenGovernanceConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            token_id: SHIELDED_TOKEN_GOVERNANCE_DEVNET_TOKEN_ID.to_string(),
            protocol_version: SHIELDED_TOKEN_GOVERNANCE_PROTOCOL_VERSION,
            hash_suite: SHIELDED_TOKEN_GOVERNANCE_HASH_SUITE.to_string(),
            pq_suite: SHIELDED_TOKEN_GOVERNANCE_PQ_SUITE.to_string(),
            vote_note_scheme: SHIELDED_TOKEN_GOVERNANCE_VOTE_NOTE_SCHEME.to_string(),
            proposal_ttl_blocks: SHIELDED_TOKEN_GOVERNANCE_DEFAULT_PROPOSAL_TTL_BLOCKS,
            reveal_delay_blocks: SHIELDED_TOKEN_GOVERNANCE_DEFAULT_REVEAL_DELAY_BLOCKS,
            min_privacy_set_size: SHIELDED_TOKEN_GOVERNANCE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: SHIELDED_TOKEN_GOVERNANCE_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_bps: SHIELDED_TOKEN_GOVERNANCE_DEFAULT_QUORUM_BPS,
            approval_bps: SHIELDED_TOKEN_GOVERNANCE_DEFAULT_APPROVAL_BPS,
            low_fee_sponsor_units: SHIELDED_TOKEN_GOVERNANCE_DEFAULT_LOW_FEE_SPONSOR_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "token_id": self.token_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "vote_note_scheme": self.vote_note_scheme,
            "proposal_ttl_blocks": self.proposal_ttl_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
            "low_fee_sponsor_units": self.low_fee_sponsor_units,
        })
    }

    pub fn validate(&self) -> ShieldedTokenGovernanceResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("shielded token governance chain id mismatch".to_string());
        }
        if self.proposal_ttl_blocks <= self.reveal_delay_blocks {
            return Err(
                "shielded token governance proposal ttl must exceed reveal delay".to_string(),
            );
        }
        if self.quorum_bps > SHIELDED_TOKEN_GOVERNANCE_MAX_BPS
            || self.approval_bps > SHIELDED_TOKEN_GOVERNANCE_MAX_BPS
        {
            return Err("shielded token governance bps config invalid".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("shielded token governance pq security too low".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_id: String,
    pub kind: GovernanceProposalKind,
    pub status: GovernanceProposalStatus,
    pub proposer_commitment: String,
    pub action_root: String,
    pub risk_root: String,
    pub vote_start_height: u64,
    pub vote_end_height: u64,
    pub execute_after_height: u64,
    pub quorum_bps: u64,
    pub approval_bps: u64,
}

impl GovernanceProposal {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "action_root": self.action_root,
            "risk_root": self.risk_root,
            "vote_start_height": self.vote_start_height,
            "vote_end_height": self.vote_end_height,
            "execute_after_height": self.execute_after_height,
            "quorum_bps": self.quorum_bps,
            "approval_bps": self.approval_bps,
        })
    }

    pub fn validate(&self) -> ShieldedTokenGovernanceResult<()> {
        if self.proposal_id.is_empty() || self.action_root.is_empty() {
            return Err("shielded governance proposal ids must not be empty".to_string());
        }
        if self.vote_start_height >= self.vote_end_height {
            return Err(format!(
                "shielded governance proposal {} invalid voting range",
                self.proposal_id
            ));
        }
        if self.execute_after_height < self.vote_end_height {
            return Err(format!(
                "shielded governance proposal {} executable before vote end",
                self.proposal_id
            ));
        }
        if self.quorum_bps > SHIELDED_TOKEN_GOVERNANCE_MAX_BPS
            || self.approval_bps > SHIELDED_TOKEN_GOVERNANCE_MAX_BPS
        {
            return Err(format!(
                "shielded governance proposal {} bps invalid",
                self.proposal_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedVoteCommitment {
    pub vote_id: String,
    pub proposal_id: String,
    pub choice: ShieldedVoteChoice,
    pub status: ShieldedVoteStatus,
    pub voter_nullifier: String,
    pub encrypted_weight_commitment: String,
    pub voting_power_bucket: String,
    pub privacy_set_size: u64,
    pub low_fee_sponsored: bool,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl ShieldedVoteCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "choice": self.choice.as_str(),
            "status": self.status.as_str(),
            "voter_nullifier": self.voter_nullifier,
            "encrypted_weight_commitment": self.encrypted_weight_commitment,
            "voting_power_bucket": self.voting_power_bucket,
            "privacy_set_size": self.privacy_set_size,
            "low_fee_sponsored": self.low_fee_sponsored,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn validate(
        &self,
        config: &ShieldedTokenGovernanceConfig,
    ) -> ShieldedTokenGovernanceResult<()> {
        if self.vote_id.is_empty() || self.voter_nullifier.is_empty() {
            return Err("shielded governance vote ids must not be empty".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "shielded governance vote {} privacy set too small",
                self.vote_id
            ));
        }
        if self.submitted_height >= self.expires_height {
            return Err(format!(
                "shielded governance vote {} invalid expiry",
                self.vote_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceTally {
    pub tally_id: String,
    pub proposal_id: String,
    pub vote_root: String,
    pub yes_weight_units: u64,
    pub no_weight_units: u64,
    pub abstain_weight_units: u64,
    pub veto_weight_units: u64,
    pub quorum_met: bool,
    pub approved: bool,
    pub tallied_height: u64,
}

impl GovernanceTally {
    pub fn public_record(&self) -> Value {
        json!({
            "tally_id": self.tally_id,
            "proposal_id": self.proposal_id,
            "vote_root": self.vote_root,
            "yes_weight_units": self.yes_weight_units,
            "no_weight_units": self.no_weight_units,
            "abstain_weight_units": self.abstain_weight_units,
            "veto_weight_units": self.veto_weight_units,
            "quorum_met": self.quorum_met,
            "approved": self.approved,
            "tallied_height": self.tallied_height,
        })
    }

    pub fn total_weight_units(&self) -> u64 {
        self.yes_weight_units
            .saturating_add(self.no_weight_units)
            .saturating_add(self.abstain_weight_units)
            .saturating_add(self.veto_weight_units)
    }

    pub fn validate(&self) -> ShieldedTokenGovernanceResult<()> {
        if self.tally_id.is_empty() || self.vote_root.is_empty() {
            return Err("shielded governance tally ids must not be empty".to_string());
        }
        if self.approved && !self.quorum_met {
            return Err(format!(
                "shielded governance tally {} approved without quorum",
                self.tally_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedDelegation {
    pub delegation_id: String,
    pub delegator_nullifier: String,
    pub delegate_commitment: String,
    pub scope_root: String,
    pub status: DelegationStatus,
    pub voting_power_bucket: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl ShieldedDelegation {
    pub fn public_record(&self) -> Value {
        json!({
            "delegation_id": self.delegation_id,
            "delegator_nullifier": self.delegator_nullifier,
            "delegate_commitment": self.delegate_commitment,
            "scope_root": self.scope_root,
            "status": self.status.as_str(),
            "voting_power_bucket": self.voting_power_bucket,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn validate(&self) -> ShieldedTokenGovernanceResult<()> {
        if self.delegation_id.is_empty() || self.delegator_nullifier.is_empty() {
            return Err("shielded governance delegation ids must not be empty".to_string());
        }
        if self.valid_from_height >= self.valid_until_height {
            return Err(format!(
                "shielded governance delegation {} invalid validity",
                self.delegation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGovernorAttestation {
    pub attestation_id: String,
    pub governor_commitment: String,
    pub proposal_scope_root: String,
    pub signature_commitment: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub revoked: bool,
}

impl PqGovernorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "governor_commitment": self.governor_commitment,
            "proposal_scope_root": self.proposal_scope_root,
            "signature_commitment": self.signature_commitment,
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "revoked": self.revoked,
        })
    }

    pub fn validate(
        &self,
        config: &ShieldedTokenGovernanceConfig,
    ) -> ShieldedTokenGovernanceResult<()> {
        if self.attestation_id.is_empty() {
            return Err("shielded governance pq attestation id must not be empty".to_string());
        }
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "shielded governance attestation {} pq security too low",
                self.attestation_id
            ));
        }
        if self.valid_from_height >= self.valid_until_height {
            return Err(format!(
                "shielded governance attestation {} invalid validity",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_height: u64,
    pub event_root: String,
}

impl GovernanceEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "event_height": self.event_height,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTokenGovernanceRoots {
    pub config_root: String,
    pub proposal_root: String,
    pub vote_root: String,
    pub tally_root: String,
    pub delegation_root: String,
    pub pq_attestation_root: String,
    pub event_root: String,
}

impl ShieldedTokenGovernanceRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "proposal_root": self.proposal_root,
            "vote_root": self.vote_root,
            "tally_root": self.tally_root,
            "delegation_root": self.delegation_root,
            "pq_attestation_root": self.pq_attestation_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        hash32(
            "shielded_token_governance_roots",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTokenGovernanceCounters {
    pub proposal_count: u64,
    pub active_proposal_count: u64,
    pub vote_count: u64,
    pub open_vote_count: u64,
    pub tally_count: u64,
    pub approved_tally_count: u64,
    pub delegation_count: u64,
    pub active_delegation_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub event_count: u64,
    pub low_fee_sponsored_vote_count: u64,
}

impl ShieldedTokenGovernanceCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_count": self.proposal_count,
            "active_proposal_count": self.active_proposal_count,
            "vote_count": self.vote_count,
            "open_vote_count": self.open_vote_count,
            "tally_count": self.tally_count,
            "approved_tally_count": self.approved_tally_count,
            "delegation_count": self.delegation_count,
            "active_delegation_count": self.active_delegation_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "event_count": self.event_count,
            "low_fee_sponsored_vote_count": self.low_fee_sponsored_vote_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTokenGovernanceState {
    pub config: ShieldedTokenGovernanceConfig,
    pub height: u64,
    pub proposals: BTreeMap<String, GovernanceProposal>,
    pub votes: BTreeMap<String, ShieldedVoteCommitment>,
    pub tallies: BTreeMap<String, GovernanceTally>,
    pub delegations: BTreeMap<String, ShieldedDelegation>,
    pub pq_attestations: BTreeMap<String, PqGovernorAttestation>,
    pub events: BTreeMap<String, GovernanceEvent>,
}

impl ShieldedTokenGovernanceState {
    pub fn devnet() -> ShieldedTokenGovernanceResult<Self> {
        let config = ShieldedTokenGovernanceConfig::devnet();
        let height = SHIELDED_TOKEN_GOVERNANCE_DEVNET_HEIGHT;
        let mut proposals = BTreeMap::new();
        for (index, kind) in [
            GovernanceProposalKind::FeePolicy,
            GovernanceProposalKind::TokenParameter,
            GovernanceProposalKind::VaultStrategy,
            GovernanceProposalKind::BridgeLimit,
            GovernanceProposalKind::TreasurySpend,
            GovernanceProposalKind::EmergencyPause,
        ]
        .into_iter()
        .enumerate()
        {
            let proposal_id = format!("shielded-gov-proposal-{index:03}");
            proposals.insert(
                proposal_id.clone(),
                GovernanceProposal {
                    kind,
                    status: if index < 2 {
                        GovernanceProposalStatus::Tallied
                    } else {
                        GovernanceProposalStatus::Active
                    },
                    proposer_commitment: hash32(
                        "shielded_governance_proposer",
                        &[HashPart::Str(&proposal_id)],
                    ),
                    action_root: hash32(
                        "shielded_governance_action",
                        &[HashPart::Str(&proposal_id)],
                    ),
                    risk_root: hash32(
                        "shielded_governance_risk",
                        &[HashPart::Str(kind.as_str()), HashPart::Int(index as i128)],
                    ),
                    vote_start_height: height.saturating_sub(32 + index as u64),
                    vote_end_height: height.saturating_add(config.proposal_ttl_blocks / 2),
                    execute_after_height: height
                        .saturating_add(config.proposal_ttl_blocks / 2)
                        .saturating_add(config.reveal_delay_blocks),
                    quorum_bps: if kind.high_risk() {
                        config.quorum_bps.saturating_mul(2)
                    } else {
                        config.quorum_bps
                    },
                    approval_bps: if kind.high_risk() {
                        config.approval_bps.saturating_add(1_000)
                    } else {
                        config.approval_bps
                    },
                    proposal_id,
                },
            );
        }

        let proposal_ids = proposals.keys().cloned().collect::<Vec<_>>();
        let mut votes = BTreeMap::new();
        for index in 0..36 {
            let proposal_id = proposal_ids[index % proposal_ids.len()].clone();
            let vote_id = format!("shielded-gov-vote-{index:03}");
            votes.insert(
                vote_id.clone(),
                ShieldedVoteCommitment {
                    proposal_id,
                    choice: match index % 4 {
                        0 => ShieldedVoteChoice::Yes,
                        1 => ShieldedVoteChoice::No,
                        2 => ShieldedVoteChoice::Abstain,
                        _ => ShieldedVoteChoice::Veto,
                    },
                    status: match index % 5 {
                        0 => ShieldedVoteStatus::Tallied,
                        1 => ShieldedVoteStatus::WeightProved,
                        2 => ShieldedVoteStatus::NullifierChecked,
                        _ => ShieldedVoteStatus::Committed,
                    },
                    voter_nullifier: hash32(
                        "shielded_governance_vote_nullifier",
                        &[HashPart::Str(&vote_id)],
                    ),
                    encrypted_weight_commitment: hash32(
                        "shielded_governance_vote_weight",
                        &[HashPart::Str(&vote_id)],
                    ),
                    voting_power_bucket: format!("power-bucket-{}", index % 8),
                    privacy_set_size: config.min_privacy_set_size * (1 + (index % 4) as u64),
                    low_fee_sponsored: index % 3 == 0,
                    submitted_height: height.saturating_sub(index as u64 % 24),
                    expires_height: height.saturating_add(config.proposal_ttl_blocks),
                    vote_id,
                },
            );
        }

        let mut tallies = BTreeMap::new();
        for (index, proposal_id) in proposal_ids.iter().take(2).enumerate() {
            let tally_id = format!("shielded-gov-tally-{index:03}");
            tallies.insert(
                tally_id.clone(),
                GovernanceTally {
                    proposal_id: proposal_id.clone(),
                    vote_root: collection_root(
                        "shielded_governance_tally_votes",
                        &votes
                            .values()
                            .filter(|vote| &vote.proposal_id == proposal_id)
                            .map(|vote| vote.vote_id.clone())
                            .collect::<BTreeSet<_>>(),
                    ),
                    yes_weight_units: 850_000 + index as u64 * 10_000,
                    no_weight_units: 220_000,
                    abstain_weight_units: 80_000,
                    veto_weight_units: if index == 1 { 15_000 } else { 0 },
                    quorum_met: true,
                    approved: true,
                    tallied_height: height.saturating_sub(4 - index as u64),
                    tally_id,
                },
            );
        }

        let mut delegations = BTreeMap::new();
        for index in 0..12 {
            let delegation_id = format!("shielded-gov-delegation-{index:03}");
            delegations.insert(
                delegation_id.clone(),
                ShieldedDelegation {
                    delegator_nullifier: hash32(
                        "shielded_governance_delegator_nullifier",
                        &[HashPart::Str(&delegation_id)],
                    ),
                    delegate_commitment: hash32(
                        "shielded_governance_delegate",
                        &[HashPart::Str(&delegation_id)],
                    ),
                    scope_root: hash32(
                        "shielded_governance_scope",
                        &[HashPart::Str(&proposal_ids[index % proposal_ids.len()])],
                    ),
                    status: if index == 11 {
                        DelegationStatus::Paused
                    } else {
                        DelegationStatus::Active
                    },
                    voting_power_bucket: format!("delegated-power-{}", index % 6),
                    valid_from_height: height.saturating_sub(96),
                    valid_until_height: height.saturating_add(config.proposal_ttl_blocks),
                    delegation_id,
                },
            );
        }

        let mut pq_attestations = BTreeMap::new();
        for index in 0..5 {
            let attestation_id = format!("shielded-gov-pq-attestation-{index:03}");
            pq_attestations.insert(
                attestation_id.clone(),
                PqGovernorAttestation {
                    governor_commitment: hash32(
                        "shielded_governance_pq_governor",
                        &[HashPart::Str(&attestation_id)],
                    ),
                    proposal_scope_root: hash32(
                        "shielded_governance_pq_scope",
                        &[HashPart::Str(&proposal_ids[index % proposal_ids.len()])],
                    ),
                    signature_commitment: hash32(
                        "shielded_governance_pq_signature",
                        &[HashPart::Str(&attestation_id)],
                    ),
                    security_bits: config.min_pq_security_bits,
                    valid_from_height: height.saturating_sub(128),
                    valid_until_height: height.saturating_add(config.proposal_ttl_blocks * 2),
                    revoked: false,
                    attestation_id,
                },
            );
        }

        let mut events = BTreeMap::new();
        for (index, subject_id) in proposal_ids.iter().take(4).enumerate() {
            let event_id = format!("shielded-gov-event-{index:03}");
            events.insert(
                event_id.clone(),
                GovernanceEvent {
                    event_kind: if index < 2 {
                        "proposal_tallied".to_string()
                    } else {
                        "proposal_opened".to_string()
                    },
                    subject_id: subject_id.clone(),
                    event_height: height.saturating_sub(index as u64),
                    event_root: hash32(
                        "shielded_governance_event",
                        &[HashPart::Str(&event_id), HashPart::Str(subject_id)],
                    ),
                    event_id,
                },
            );
        }

        let state = Self {
            config,
            height,
            proposals,
            votes,
            tallies,
            delegations,
            pq_attestations,
            events,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ShieldedTokenGovernanceResult<()> {
        if height < self.height {
            return Err("shielded token governance cannot rewind height".to_string());
        }
        self.height = height;
        for proposal in self.proposals.values_mut() {
            if proposal.status.accepts_votes() && height > proposal.vote_end_height {
                proposal.status = GovernanceProposalStatus::RevealPending;
            }
            if proposal.status == GovernanceProposalStatus::RevealPending
                && height >= proposal.execute_after_height
            {
                proposal.status = GovernanceProposalStatus::Tallied;
            }
        }
        for vote in self.votes.values_mut() {
            if vote.status.open() && height > vote.expires_height {
                vote.status = ShieldedVoteStatus::Expired;
            }
        }
        for delegation in self.delegations.values_mut() {
            if delegation.status == DelegationStatus::Active
                && height > delegation.valid_until_height
            {
                delegation.status = DelegationStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn roots(&self) -> ShieldedTokenGovernanceRoots {
        ShieldedTokenGovernanceRoots {
            config_root: value_root(
                "shielded_token_governance_config",
                &self.config.public_record(),
            ),
            proposal_root: map_root("shielded_token_governance_proposals", &self.proposals),
            vote_root: map_root("shielded_token_governance_votes", &self.votes),
            tally_root: map_root("shielded_token_governance_tallies", &self.tallies),
            delegation_root: map_root("shielded_token_governance_delegations", &self.delegations),
            pq_attestation_root: map_root(
                "shielded_token_governance_pq_attestations",
                &self.pq_attestations,
            ),
            event_root: map_root("shielded_token_governance_events", &self.events),
        }
    }

    pub fn counters(&self) -> ShieldedTokenGovernanceCounters {
        ShieldedTokenGovernanceCounters {
            proposal_count: self.proposals.len() as u64,
            active_proposal_count: self
                .proposals
                .values()
                .filter(|proposal| proposal.status.accepts_votes())
                .count() as u64,
            vote_count: self.votes.len() as u64,
            open_vote_count: self
                .votes
                .values()
                .filter(|vote| vote.status.open())
                .count() as u64,
            tally_count: self.tallies.len() as u64,
            approved_tally_count: self.tallies.values().filter(|tally| tally.approved).count()
                as u64,
            delegation_count: self.delegations.len() as u64,
            active_delegation_count: self
                .delegations
                .values()
                .filter(|delegation| delegation.status == DelegationStatus::Active)
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            active_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| {
                    !attestation.revoked && self.height <= attestation.valid_until_height
                })
                .count() as u64,
            event_count: self.events.len() as u64,
            low_fee_sponsored_vote_count: self
                .votes
                .values()
                .filter(|vote| vote.low_fee_sponsored)
                .count() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_token_governance",
            "protocol_version": SHIELDED_TOKEN_GOVERNANCE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_proposal_ids": self.active_proposal_ids(),
            "open_vote_ids": self.open_vote_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        shielded_token_governance_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> ShieldedTokenGovernanceResult<()> {
        self.config.validate()?;
        if self.proposals.len() > SHIELDED_TOKEN_GOVERNANCE_MAX_PROPOSALS {
            return Err("shielded governance proposal limit exceeded".to_string());
        }
        if self.votes.len() > SHIELDED_TOKEN_GOVERNANCE_MAX_VOTES {
            return Err("shielded governance vote limit exceeded".to_string());
        }
        if self.tallies.len() > SHIELDED_TOKEN_GOVERNANCE_MAX_TALLIES {
            return Err("shielded governance tally limit exceeded".to_string());
        }
        if self.delegations.len() > SHIELDED_TOKEN_GOVERNANCE_MAX_DELEGATIONS {
            return Err("shielded governance delegation limit exceeded".to_string());
        }
        if self.pq_attestations.len() > SHIELDED_TOKEN_GOVERNANCE_MAX_ATTESTATIONS {
            return Err("shielded governance attestation limit exceeded".to_string());
        }
        if self.events.len() > SHIELDED_TOKEN_GOVERNANCE_MAX_EVENTS {
            return Err("shielded governance event limit exceeded".to_string());
        }
        for proposal in self.proposals.values() {
            proposal.validate()?;
        }
        let mut vote_nullifiers = BTreeSet::new();
        for vote in self.votes.values() {
            vote.validate(&self.config)?;
            if !self.proposals.contains_key(&vote.proposal_id) {
                return Err(format!(
                    "shielded governance vote {} references missing proposal",
                    vote.vote_id
                ));
            }
            if !vote_nullifiers.insert(vote.voter_nullifier.clone()) {
                return Err(format!(
                    "shielded governance duplicate vote nullifier {}",
                    vote.voter_nullifier
                ));
            }
        }
        for tally in self.tallies.values() {
            tally.validate()?;
            if !self.proposals.contains_key(&tally.proposal_id) {
                return Err(format!(
                    "shielded governance tally {} references missing proposal",
                    tally.tally_id
                ));
            }
        }
        for delegation in self.delegations.values() {
            delegation.validate()?;
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn active_proposal_ids(&self) -> Vec<String> {
        self.proposals
            .values()
            .filter(|proposal| proposal.status.accepts_votes())
            .map(|proposal| proposal.proposal_id.clone())
            .collect()
    }

    pub fn open_vote_ids(&self) -> Vec<String> {
        self.votes
            .values()
            .filter(|vote| vote.status.open())
            .map(|vote| vote.vote_id.clone())
            .collect()
    }
}

pub fn shielded_token_governance_state_root_from_record(record: &Value) -> String {
    hash32("shielded_token_governance_state", &[HashPart::Json(record)])
}

fn value_root(label: &str, value: &Value) -> String {
    hash32(label, &[HashPart::Json(value)])
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let value = json!(map);
    hash32(label, &[HashPart::Json(&value)])
}

fn collection_root(label: &str, set: &BTreeSet<String>) -> String {
    let value = json!(set.iter().cloned().collect::<Vec<_>>());
    hash32(label, &[HashPart::Json(&value)])
}

fn hash32(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
