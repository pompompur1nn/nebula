use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialGovernanceVoteRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-governance-vote-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-confidential-governance-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROPOSAL_SCHEME: &str =
    "shielded-confidential-governance-proposal-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_NOTE_SCHEME: &str =
    "confidential-governance-vote-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_AUTH_SCHEME: &str =
    "pq-confidential-governance-voter-authorization-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DELEGATION_SCHEME: &str =
    "confidential-governance-delegation-nullifier-fence-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-governance-vote-sponsor-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_TALLY_SCHEME: &str =
    "batched-confidential-governance-tally-certificate-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_SETTLEMENT_SCHEME: &str =
    "confidential-governance-vote-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEVNET_HEIGHT: u64 = 412_000;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-confidential-governance-vote";
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_PROPOSALS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_VOTE_NOTES: usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_AUTHORIZATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_DELEGATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_TALLY_CERTIFICATES: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    131_072;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_VOTE_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_DELEGATION_TTL_BLOCKS: u64 =
    20_160;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceProposalKind {
    ProtocolUpgrade,
    FeePolicy,
    TreasurySpend,
    TokenParameter,
    RuntimeParameter,
    BridgeLimit,
    RiskParameter,
    EmergencyAction,
}

impl GovernanceProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolUpgrade => "protocol_upgrade",
            Self::FeePolicy => "fee_policy",
            Self::TreasurySpend => "treasury_spend",
            Self::TokenParameter => "token_parameter",
            Self::RuntimeParameter => "runtime_parameter",
            Self::BridgeLimit => "bridge_limit",
            Self::RiskParameter => "risk_parameter",
            Self::EmergencyAction => "emergency_action",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Registered,
    Active,
    Tallied,
    Settled,
    Rejected,
    Expired,
    Cancelled,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Tallied => "tallied",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_votes(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteChoice {
    For,
    Against,
    Abstain,
    VetoSignal,
}

impl VoteChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::For => "for",
            Self::Against => "against",
            Self::Abstain => "abstain",
            Self::VetoSignal => "veto_signal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteNoteStatus {
    Submitted,
    Authorized,
    Delegated,
    SponsorReserved,
    Tallied,
    Settled,
    Rejected,
    Expired,
}

impl VoteNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Authorized => "authorized",
            Self::Delegated => "delegated",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Tallied => "tallied",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn tallyable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Authorized | Self::Delegated | Self::SponsorReserved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Recorded,
    Consumed,
    Revoked,
    Expired,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationStatus {
    Active,
    Consumed,
    Revoked,
    Expired,
}

impl DelegationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TallyStatus {
    Built,
    Certified,
    Settled,
    Rejected,
    Expired,
}

impl TallyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Certified => "certified",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub max_proposals: usize,
    pub max_vote_notes: usize,
    pub max_authorizations: usize,
    pub max_delegations: usize,
    pub max_reservations: usize,
    pub max_tally_certificates: usize,
    pub max_settlement_receipts: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub proposal_ttl_blocks: u64,
    pub vote_ttl_blocks: u64,
    pub delegation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            fee_asset_id: PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            max_proposals: PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_PROPOSALS,
            max_vote_notes: PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_VOTE_NOTES,
            max_authorizations:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_AUTHORIZATIONS,
            max_delegations:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_DELEGATIONS,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_tally_certificates:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_TALLY_CERTIFICATES,
            max_settlement_receipts:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            max_batch_items:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            proposal_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_PROPOSAL_TTL_BLOCKS,
            vote_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_VOTE_TTL_BLOCKS,
            delegation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_DELEGATION_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<()> {
        require(
            self.chain_id == CHAIN_ID,
            "config chain_id must match CHAIN_ID",
        )?;
        require(!self.l2_network.is_empty(), "config l2_network is empty")?;
        require(
            !self.low_fee_lane.is_empty(),
            "config low_fee_lane is empty",
        )?;
        require(
            !self.fee_asset_id.is_empty(),
            "config fee_asset_id is empty",
        )?;
        require(self.max_proposals > 0, "max proposals must be positive")?;
        require(self.max_vote_notes > 0, "max vote notes must be positive")?;
        require(self.max_batch_items > 0, "max batch items must be positive")?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        require(
            self.min_pq_security_bits >= 128,
            "min pq security bits too low",
        )?;
        require(
            self.proposal_ttl_blocks > 0 && self.vote_ttl_blocks > 0,
            "proposal and vote ttls must be positive",
        )?;
        require(
            self.delegation_ttl_blocks >= self.vote_ttl_blocks,
            "delegation ttl shorter than vote ttl",
        )?;
        require_bps(self.max_user_fee_bps, "max user fee")?;
        require_bps(self.max_sponsor_fee_bps, "max sponsor fee")?;
        require(
            self.max_sponsor_fee_bps <= self.max_user_fee_bps,
            "sponsor fee cap must not exceed user fee cap",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_governance_vote_config",
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "max_proposals": self.max_proposals,
            "max_vote_notes": self.max_vote_notes,
            "max_authorizations": self.max_authorizations,
            "max_delegations": self.max_delegations,
            "max_reservations": self.max_reservations,
            "max_tally_certificates": self.max_tally_certificates,
            "max_settlement_receipts": self.max_settlement_receipts,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "proposal_ttl_blocks": self.proposal_ttl_blocks,
            "vote_ttl_blocks": self.vote_ttl_blocks,
            "delegation_ttl_blocks": self.delegation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub proposals_registered: u64,
    pub vote_notes_submitted: u64,
    pub authorizations_recorded: u64,
    pub delegations_registered: u64,
    pub sponsor_reservations: u64,
    pub tally_certificates_built: u64,
    pub receipts_published: u64,
    pub votes_settled: u64,
    pub nullifiers_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_governance_vote_counters",
            "proposals_registered": self.proposals_registered,
            "vote_notes_submitted": self.vote_notes_submitted,
            "authorizations_recorded": self.authorizations_recorded,
            "delegations_registered": self.delegations_registered,
            "sponsor_reservations": self.sponsor_reservations,
            "tally_certificates_built": self.tally_certificates_built,
            "receipts_published": self.receipts_published,
            "votes_settled": self.votes_settled,
            "nullifiers_consumed": self.nullifiers_consumed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterShieldedProposalRequest {
    pub proposal_kind: GovernanceProposalKind,
    pub proposer_commitment: String,
    pub proposal_payload_root: String,
    pub encrypted_metadata_root: String,
    pub eligible_voter_root: String,
    pub vote_policy_root: String,
    pub quorum_commitment_root: String,
    pub tally_verifier_root: String,
    pub sponsor_policy_root: String,
    pub proposal_nullifier_root: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub vote_start_height: u64,
    pub vote_end_height: u64,
}

impl RegisterShieldedProposalRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_kind": self.proposal_kind.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "proposal_payload_root": self.proposal_payload_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "eligible_voter_root": self.eligible_voter_root,
            "vote_policy_root": self.vote_policy_root,
            "quorum_commitment_root": self.quorum_commitment_root,
            "tally_verifier_root": self.tally_verifier_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "proposal_nullifier_root": self.proposal_nullifier_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
            "vote_start_height": self.vote_start_height,
            "vote_end_height": self.vote_end_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitConfidentialVoteNoteRequest {
    pub proposal_id: String,
    pub voter_commitment: String,
    pub encrypted_choice_root: String,
    pub vote_choice_commitment_root: String,
    pub vote_weight_commitment_root: String,
    pub eligibility_witness_root: String,
    pub note_commitment_root: String,
    pub vote_nullifier_root: String,
    pub delegation_fence_root: Option<String>,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub fee_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub choice_hint: VoteChoice,
}

impl SubmitConfidentialVoteNoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "voter_commitment": self.voter_commitment,
            "encrypted_choice_root": self.encrypted_choice_root,
            "vote_choice_commitment_root": self.vote_choice_commitment_root,
            "vote_weight_commitment_root": self.vote_weight_commitment_root,
            "eligibility_witness_root": self.eligibility_witness_root,
            "note_commitment_root": self.note_commitment_root,
            "vote_nullifier_root": self.vote_nullifier_root,
            "delegation_fence_root": self.delegation_fence_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "fee_commitment_root": self.fee_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "choice_hint": self.choice_hint.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPqVoterAuthorizationRequest {
    pub proposal_id: String,
    pub vote_note_id: String,
    pub voter_key_commitment_root: String,
    pub authorization_policy_root: String,
    pub pq_signature_root: String,
    pub pq_kem_ciphertext_root: String,
    pub authorization_nullifier_root: String,
    pub privacy_proof_root: String,
    pub pq_security_bits: u16,
    pub authorized_at_height: u64,
    pub expires_at_height: u64,
}

impl RecordPqVoterAuthorizationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "vote_note_id": self.vote_note_id,
            "voter_key_commitment_root": self.voter_key_commitment_root,
            "authorization_policy_root": self.authorization_policy_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_kem_ciphertext_root": self.pq_kem_ciphertext_root,
            "authorization_nullifier_root": self.authorization_nullifier_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_security_bits": self.pq_security_bits,
            "authorized_at_height": self.authorized_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDelegationFenceRequest {
    pub proposal_id: String,
    pub delegator_commitment: String,
    pub delegate_commitment: String,
    pub delegation_scope_root: String,
    pub delegation_note_root: String,
    pub delegation_nullifier_root: String,
    pub revocation_commitment_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
}

impl RegisterDelegationFenceRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "delegator_commitment": self.delegator_commitment,
            "delegate_commitment": self.delegate_commitment,
            "delegation_scope_root": self.delegation_scope_root,
            "delegation_note_root": self.delegation_note_root,
            "delegation_nullifier_root": self.delegation_nullifier_root,
            "revocation_commitment_root": self.revocation_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveVoteSponsorRequest {
    pub proposal_id: String,
    pub vote_note_id: String,
    pub sponsor_commitment: String,
    pub budget_root: String,
    pub fee_asset_id: String,
    pub sponsor_policy_root: String,
    pub reserved_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveVoteSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "vote_note_id": self.vote_note_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_root": self.budget_root,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_policy_root": self.sponsor_policy_root,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "pq_reservation_root": self.pq_reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildTallyCertificateRequest {
    pub proposal_id: String,
    pub operator_commitment: String,
    pub vote_note_ids: Vec<String>,
    pub aggregate_vote_note_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_delegation_root: String,
    pub aggregate_authorization_root: String,
    pub aggregate_sponsor_root: String,
    pub encrypted_tally_root: String,
    pub tally_commitment_root: String,
    pub tally_proof_root: String,
    pub pq_certificate_root: String,
    pub for_weight_commitment_root: String,
    pub against_weight_commitment_root: String,
    pub abstain_weight_commitment_root: String,
    pub veto_signal_weight_commitment_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl BuildTallyCertificateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "operator_commitment": self.operator_commitment,
            "vote_note_ids": self.vote_note_ids,
            "aggregate_vote_note_root": self.aggregate_vote_note_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "aggregate_delegation_root": self.aggregate_delegation_root,
            "aggregate_authorization_root": self.aggregate_authorization_root,
            "aggregate_sponsor_root": self.aggregate_sponsor_root,
            "encrypted_tally_root": self.encrypted_tally_root,
            "tally_commitment_root": self.tally_commitment_root,
            "tally_proof_root": self.tally_proof_root,
            "pq_certificate_root": self.pq_certificate_root,
            "for_weight_commitment_root": self.for_weight_commitment_root,
            "against_weight_commitment_root": self.against_weight_commitment_root,
            "abstain_weight_commitment_root": self.abstain_weight_commitment_root,
            "veto_signal_weight_commitment_root": self.veto_signal_weight_commitment_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleTallyCertificateRequest {
    pub tally_certificate_id: String,
    pub proposal_id: String,
    pub settlement_operator_commitment: String,
    pub settlement_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub proposal_state_root_after: String,
    pub public_tally_root: String,
    pub fee_receipt_root: String,
    pub settlement_nullifier_root: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleTallyCertificateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "tally_certificate_id": self.tally_certificate_id,
            "proposal_id": self.proposal_id,
            "settlement_operator_commitment": self.settlement_operator_commitment,
            "settlement_proof_root": self.settlement_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "proposal_state_root_after": self.proposal_state_root_after,
            "public_tally_root": self.public_tally_root,
            "fee_receipt_root": self.fee_receipt_root,
            "settlement_nullifier_root": self.settlement_nullifier_root,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedProposalRecord {
    pub proposal_id: String,
    pub request: RegisterShieldedProposalRequest,
    pub status: ProposalStatus,
    pub tally_certificate_id: Option<String>,
    pub settlement_receipt_id: Option<String>,
}

impl ShieldedProposalRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_governance_proposal",
            "proposal_id": self.proposal_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "tally_certificate_id": self.tally_certificate_id,
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialVoteNoteRecord {
    pub vote_note_id: String,
    pub request: SubmitConfidentialVoteNoteRequest,
    pub status: VoteNoteStatus,
    pub authorization_id: Option<String>,
    pub delegation_id: Option<String>,
    pub sponsor_reservation_id: Option<String>,
    pub tally_certificate_id: Option<String>,
}

impl ConfidentialVoteNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_governance_vote_note",
            "vote_note_id": self.vote_note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "authorization_id": self.authorization_id,
            "delegation_id": self.delegation_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "tally_certificate_id": self.tally_certificate_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVoterAuthorizationRecord {
    pub authorization_id: String,
    pub request: RecordPqVoterAuthorizationRequest,
    pub status: AuthorizationStatus,
}

impl PqVoterAuthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_governance_voter_authorization",
            "authorization_id": self.authorization_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationFenceRecord {
    pub delegation_id: String,
    pub request: RegisterDelegationFenceRequest,
    pub status: DelegationStatus,
    pub linked_vote_note_id: Option<String>,
}

impl DelegationFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_governance_delegation_fence",
            "delegation_id": self.delegation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "linked_vote_note_id": self.linked_vote_note_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveVoteSponsorRequest,
    pub status: ReservationStatus,
}

impl VoteSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_governance_vote_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyCertificateRecord {
    pub tally_certificate_id: String,
    pub request: BuildTallyCertificateRequest,
    pub status: TallyStatus,
    pub settlement_receipt_id: Option<String>,
}

impl TallyCertificateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batched_confidential_governance_tally_certificate",
            "tally_certificate_id": self.tally_certificate_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub request: SettleTallyCertificateRequest,
    pub status: ReceiptStatus,
    pub settled_vote_note_ids: Vec<String>,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_governance_vote_settlement_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "settled_vote_note_ids": self.settled_vote_note_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub proposal_root: String,
    pub vote_note_root: String,
    pub authorization_root: String,
    pub delegation_root: String,
    pub reservation_root: String,
    pub tally_certificate_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "proposal_root": self.proposal_root,
            "vote_note_root": self.vote_note_root,
            "authorization_root": self.authorization_root,
            "delegation_root": self.delegation_root,
            "reservation_root": self.reservation_root,
            "tally_certificate_root": self.tally_certificate_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateL2ConfidentialGovernanceVoteRuntime {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub proposals: BTreeMap<String, ShieldedProposalRecord>,
    pub vote_notes: BTreeMap<String, ConfidentialVoteNoteRecord>,
    pub authorizations: BTreeMap<String, PqVoterAuthorizationRecord>,
    pub delegations: BTreeMap<String, DelegationFenceRecord>,
    pub reservations: BTreeMap<String, VoteSponsorReservationRecord>,
    pub tally_certificates: BTreeMap<String, TallyCertificateRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl PrivateL2ConfidentialGovernanceVoteRuntime {
    pub fn new(
        config: Config,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<PrivateL2ConfidentialGovernanceVoteRuntime>
    {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DEVNET_HEIGHT,
            proposals: BTreeMap::new(),
            vote_notes: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            delegations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            tally_certificates: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            public_records: Vec::new(),
        })
    }

    pub fn devnet() -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<Self> {
        let mut runtime = Self::new(Config::devnet())?;
        runtime.seed_devnet_records()?;
        Ok(runtime)
    }

    pub fn register_proposal(
        &mut self,
        request: RegisterShieldedProposalRequest,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<ShieldedProposalRecord> {
        self.config.validate()?;
        require(
            self.proposals.len() < self.config.max_proposals,
            "shielded proposal registry is full",
        )?;
        validate_required("proposer_commitment", &request.proposer_commitment)?;
        validate_required("proposal_payload_root", &request.proposal_payload_root)?;
        validate_required("eligible_voter_root", &request.eligible_voter_root)?;
        validate_required("vote_policy_root", &request.vote_policy_root)?;
        validate_required("proposal_nullifier_root", &request.proposal_nullifier_root)?;
        validate_privacy_and_pq(
            request.min_privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require(
            request.vote_start_height >= request.registered_at_height,
            "proposal vote start precedes registration",
        )?;
        require(
            request.vote_end_height > request.vote_start_height,
            "proposal vote end must follow vote start",
        )?;
        require(
            request.vote_end_height
                <= request
                    .registered_at_height
                    .saturating_add(self.config.proposal_ttl_blocks),
            "proposal vote window exceeds runtime ttl",
        )?;
        self.insert_nullifier_root(&request.proposal_nullifier_root)?;
        self.counters.proposals_registered = self.counters.proposals_registered.saturating_add(1);
        self.current_height = self.current_height.max(request.registered_at_height);
        let proposal_id = proposal_id(&request, self.counters.proposals_registered);
        let record = ShieldedProposalRecord {
            proposal_id: proposal_id.clone(),
            request,
            status: ProposalStatus::Registered,
            tally_certificate_id: None,
            settlement_receipt_id: None,
        };
        self.public_records.push(record.public_record());
        self.proposals.insert(proposal_id, record.clone());
        Ok(record)
    }

    pub fn submit_vote_note(
        &mut self,
        request: SubmitConfidentialVoteNoteRequest,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<ConfidentialVoteNoteRecord> {
        self.config.validate()?;
        require(
            self.vote_notes.len() < self.config.max_vote_notes,
            "confidential vote note queue is full",
        )?;
        let proposal = self
            .proposals
            .get(&request.proposal_id)
            .ok_or_else(|| "proposal missing for confidential vote note".to_string())?;
        require(
            proposal.status.accepts_votes(),
            "proposal is not accepting vote notes",
        )?;
        require(
            request.submitted_at_height >= proposal.request.vote_start_height
                && request.submitted_at_height <= proposal.request.vote_end_height,
            "vote note submitted outside proposal vote window",
        )?;
        validate_required("voter_commitment", &request.voter_commitment)?;
        validate_required("encrypted_choice_root", &request.encrypted_choice_root)?;
        validate_required("note_commitment_root", &request.note_commitment_root)?;
        validate_required("vote_nullifier_root", &request.vote_nullifier_root)?;
        validate_required("pq_authorization_root", &request.pq_authorization_root)?;
        validate_required("privacy_proof_root", &request.privacy_proof_root)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require_bps(request.max_fee_bps, "vote note max fee")?;
        require(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "vote note max fee exceeds runtime cap",
        )?;
        require(
            request.expires_at_height > request.submitted_at_height,
            "vote note expiry must follow submission",
        )?;
        require(
            request.expires_at_height
                <= request
                    .submitted_at_height
                    .saturating_add(self.config.vote_ttl_blocks),
            "vote note expiry exceeds runtime ttl",
        )?;
        self.insert_nullifier_root(&request.vote_nullifier_root)?;
        self.counters.vote_notes_submitted = self.counters.vote_notes_submitted.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let vote_note_id = vote_note_id(&request, self.counters.vote_notes_submitted);
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            if proposal.status == ProposalStatus::Registered {
                proposal.status = ProposalStatus::Active;
            }
        }
        let record = ConfidentialVoteNoteRecord {
            vote_note_id: vote_note_id.clone(),
            request,
            status: VoteNoteStatus::Submitted,
            authorization_id: None,
            delegation_id: None,
            sponsor_reservation_id: None,
            tally_certificate_id: None,
        };
        self.public_records.push(record.public_record());
        self.vote_notes.insert(vote_note_id, record.clone());
        Ok(record)
    }

    pub fn record_pq_authorization(
        &mut self,
        request: RecordPqVoterAuthorizationRequest,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<PqVoterAuthorizationRecord> {
        self.config.validate()?;
        require(
            self.authorizations.len() < self.config.max_authorizations,
            "PQ authorization store is full",
        )?;
        let vote_note = self
            .vote_notes
            .get(&request.vote_note_id)
            .ok_or_else(|| "vote note missing for PQ authorization".to_string())?;
        require(
            vote_note.request.proposal_id == request.proposal_id,
            "PQ authorization proposal mismatch",
        )?;
        require(
            vote_note.status.tallyable(),
            "vote note no longer accepts PQ authorization",
        )?;
        validate_required(
            "voter_key_commitment_root",
            &request.voter_key_commitment_root,
        )?;
        validate_required("pq_signature_root", &request.pq_signature_root)?;
        validate_required(
            "authorization_nullifier_root",
            &request.authorization_nullifier_root,
        )?;
        validate_required("privacy_proof_root", &request.privacy_proof_root)?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "PQ authorization security bits below runtime minimum",
        )?;
        require(
            request.expires_at_height > request.authorized_at_height,
            "PQ authorization expiry must follow authorization",
        )?;
        self.insert_nullifier_root(&request.authorization_nullifier_root)?;
        self.counters.authorizations_recorded =
            self.counters.authorizations_recorded.saturating_add(1);
        self.current_height = self.current_height.max(request.authorized_at_height);
        let authorization_id = pq_authorization_id(&request, self.counters.authorizations_recorded);
        if let Some(vote_note) = self.vote_notes.get_mut(&request.vote_note_id) {
            vote_note.authorization_id = Some(authorization_id.clone());
            vote_note.status = VoteNoteStatus::Authorized;
        }
        let record = PqVoterAuthorizationRecord {
            authorization_id,
            request,
            status: AuthorizationStatus::Recorded,
        };
        self.public_records.push(record.public_record());
        self.authorizations
            .insert(record.authorization_id.clone(), record.clone());
        Ok(record)
    }

    pub fn register_delegation_fence(
        &mut self,
        request: RegisterDelegationFenceRequest,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<DelegationFenceRecord> {
        self.config.validate()?;
        require(
            self.delegations.len() < self.config.max_delegations,
            "delegation fence store is full",
        )?;
        require(
            self.proposals.contains_key(&request.proposal_id),
            "delegation references unknown proposal",
        )?;
        validate_required("delegator_commitment", &request.delegator_commitment)?;
        validate_required("delegate_commitment", &request.delegate_commitment)?;
        validate_required("delegation_scope_root", &request.delegation_scope_root)?;
        validate_required(
            "delegation_nullifier_root",
            &request.delegation_nullifier_root,
        )?;
        validate_required("pq_authorization_root", &request.pq_authorization_root)?;
        validate_required("privacy_proof_root", &request.privacy_proof_root)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require(
            request.expires_at_height > request.registered_at_height,
            "delegation expiry must follow registration",
        )?;
        require(
            request.expires_at_height
                <= request
                    .registered_at_height
                    .saturating_add(self.config.delegation_ttl_blocks),
            "delegation expiry exceeds runtime ttl",
        )?;
        self.insert_nullifier_root(&request.delegation_nullifier_root)?;
        self.counters.delegations_registered =
            self.counters.delegations_registered.saturating_add(1);
        self.current_height = self.current_height.max(request.registered_at_height);
        let delegation_id = delegation_id(&request, self.counters.delegations_registered);
        let record = DelegationFenceRecord {
            delegation_id: delegation_id.clone(),
            request,
            status: DelegationStatus::Active,
            linked_vote_note_id: None,
        };
        self.public_records.push(record.public_record());
        self.delegations.insert(delegation_id, record.clone());
        Ok(record)
    }

    pub fn reserve_vote_sponsor(
        &mut self,
        request: ReserveVoteSponsorRequest,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<VoteSponsorReservationRecord> {
        self.config.validate()?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "vote sponsor reservation store is full",
        )?;
        let vote_note = self
            .vote_notes
            .get_mut(&request.vote_note_id)
            .ok_or_else(|| "vote note missing for sponsor reservation".to_string())?;
        require(
            vote_note.request.proposal_id == request.proposal_id,
            "vote sponsor reservation proposal mismatch",
        )?;
        require(
            vote_note.status.tallyable(),
            "vote note is not sponsor-reservable",
        )?;
        require(
            request.reserved_fee_bps <= self.config.max_sponsor_fee_bps,
            "reserved sponsor fee exceeds runtime cap",
        )?;
        require(
            request.fee_asset_id == self.config.fee_asset_id,
            "vote sponsor fee asset mismatch",
        )?;
        require(
            request.expires_at_height > request.reserved_at_height,
            "vote sponsor reservation expiry must follow reservation",
        )?;
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let reservation_id =
            vote_sponsor_reservation_id(&request, self.counters.sponsor_reservations);
        vote_note.sponsor_reservation_id = Some(reservation_id.clone());
        vote_note.status = VoteNoteStatus::SponsorReserved;
        let record = VoteSponsorReservationRecord {
            reservation_id,
            request,
            status: ReservationStatus::Reserved,
        };
        self.public_records.push(record.public_record());
        self.reservations
            .insert(record.reservation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn build_tally_certificate(
        &mut self,
        request: BuildTallyCertificateRequest,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<TallyCertificateRecord> {
        self.config.validate()?;
        require(
            self.tally_certificates.len() < self.config.max_tally_certificates,
            "tally certificate store is full",
        )?;
        let proposal = self
            .proposals
            .get(&request.proposal_id)
            .ok_or_else(|| "proposal missing for tally certificate".to_string())?;
        require(
            proposal.status.accepts_votes(),
            "proposal cannot be tallied from current status",
        )?;
        require(
            !request.vote_note_ids.is_empty(),
            "tally certificate must include at least one vote note",
        )?;
        require(
            request.vote_note_ids.len() <= self.config.max_batch_items,
            "tally certificate exceeds max batch item count",
        )?;
        require(
            request.privacy_set_size >= self.config.batch_privacy_set_size,
            "tally certificate privacy set below batch target",
        )?;
        require(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "tally certificate max fee exceeds runtime cap",
        )?;
        require(
            request.expires_at_height > request.built_at_height,
            "tally certificate expiry must follow build height",
        )?;
        require(
            request.expires_at_height
                <= request
                    .built_at_height
                    .saturating_add(self.config.batch_ttl_blocks),
            "tally certificate expiry exceeds runtime ttl",
        )?;
        let mut unique_vote_note_ids = BTreeSet::new();
        for vote_note_id in &request.vote_note_ids {
            require(
                unique_vote_note_ids.insert(vote_note_id.clone()),
                "tally certificate contains duplicate vote note id",
            )?;
            let vote_note = self
                .vote_notes
                .get(vote_note_id)
                .ok_or_else(|| format!("vote note missing from runtime: {vote_note_id}"))?;
            require(
                vote_note.request.proposal_id == request.proposal_id,
                "tally certificate contains vote for another proposal",
            )?;
            require(
                vote_note.status.tallyable(),
                "tally certificate contains non-tallyable vote note",
            )?;
        }
        self.counters.tally_certificates_built =
            self.counters.tally_certificates_built.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let tally_certificate_id =
            tally_certificate_id(&request, self.counters.tally_certificates_built);
        for vote_note_id in &request.vote_note_ids {
            if let Some(vote_note) = self.vote_notes.get_mut(vote_note_id) {
                vote_note.status = VoteNoteStatus::Tallied;
                vote_note.tally_certificate_id = Some(tally_certificate_id.clone());
            }
        }
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            proposal.status = ProposalStatus::Tallied;
            proposal.tally_certificate_id = Some(tally_certificate_id.clone());
        }
        let record = TallyCertificateRecord {
            tally_certificate_id,
            request,
            status: TallyStatus::Built,
            settlement_receipt_id: None,
        };
        self.public_records.push(record.public_record());
        self.tally_certificates
            .insert(record.tally_certificate_id.clone(), record.clone());
        Ok(record)
    }

    pub fn settle_tally_certificate(
        &mut self,
        request: SettleTallyCertificateRequest,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<SettlementReceiptRecord> {
        self.config.validate()?;
        require(
            self.settlement_receipts.len() < self.config.max_settlement_receipts,
            "settlement receipt store is full",
        )?;
        require(
            request.settled_fee_bps <= self.config.max_user_fee_bps,
            "settled fee exceeds runtime cap",
        )?;
        validate_required(
            "settlement_nullifier_root",
            &request.settlement_nullifier_root,
        )?;
        let tally = self
            .tally_certificates
            .get(&request.tally_certificate_id)
            .ok_or_else(|| "tally certificate missing for settlement".to_string())?;
        require(
            tally.request.proposal_id == request.proposal_id,
            "settlement proposal mismatch",
        )?;
        require(
            matches!(tally.status, TallyStatus::Built | TallyStatus::Certified),
            "tally certificate cannot settle from current status",
        )?;
        require(
            request.settled_at_height >= tally.request.built_at_height,
            "settlement precedes tally build height",
        )?;
        let settled_vote_note_ids = tally.request.vote_note_ids.clone();
        self.insert_nullifier_root(&request.settlement_nullifier_root)?;
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, self.counters.receipts_published);
        if let Some(tally) = self
            .tally_certificates
            .get_mut(&request.tally_certificate_id)
        {
            tally.status = TallyStatus::Settled;
            tally.settlement_receipt_id = Some(receipt_id.clone());
        }
        for vote_note_id in &settled_vote_note_ids {
            if let Some(vote_note) = self.vote_notes.get_mut(vote_note_id) {
                vote_note.status = VoteNoteStatus::Settled;
                self.counters.votes_settled = self.counters.votes_settled.saturating_add(1);
            }
        }
        for authorization in self.authorizations.values_mut() {
            if settled_vote_note_ids.contains(&authorization.request.vote_note_id) {
                authorization.status = AuthorizationStatus::Consumed;
            }
        }
        for reservation in self.reservations.values_mut() {
            if settled_vote_note_ids.contains(&reservation.request.vote_note_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        for delegation in self.delegations.values_mut() {
            if let Some(linked_vote_note_id) = &delegation.linked_vote_note_id {
                if settled_vote_note_ids.contains(linked_vote_note_id) {
                    delegation.status = DelegationStatus::Consumed;
                }
            }
        }
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            proposal.status = ProposalStatus::Settled;
            proposal.settlement_receipt_id = Some(receipt_id.clone());
        }
        let receipt = SettlementReceiptRecord {
            receipt_id,
            request,
            status: ReceiptStatus::Published,
            settled_vote_note_ids,
        };
        self.public_records.push(receipt.public_record());
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let nullifier_records = self
            .consumed_nullifier_roots
            .iter()
            .map(|root| json!({ "nullifier_root": root }))
            .collect::<Vec<_>>();
        Roots {
            config_root: self.config.state_root(),
            proposal_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-PROPOSAL",
                &self
                    .proposals
                    .values()
                    .map(ShieldedProposalRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            vote_note_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-NOTE",
                &self
                    .vote_notes
                    .values()
                    .map(ConfidentialVoteNoteRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            authorization_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-AUTHORIZATION",
                &self
                    .authorizations
                    .values()
                    .map(PqVoterAuthorizationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            delegation_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-DELEGATION",
                &self
                    .delegations
                    .values()
                    .map(DelegationFenceRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            reservation_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-SPONSOR",
                &self
                    .reservations
                    .values()
                    .map(VoteSponsorReservationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            tally_certificate_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-TALLY",
                &self
                    .tally_certificates
                    .values()
                    .map(TallyCertificateRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_receipt_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-RECEIPT",
                &self
                    .settlement_receipts
                    .values()
                    .map(SettlementReceiptRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-NULLIFIER",
                &nullifier_records,
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-PUBLIC-RECORD",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_governance_vote_runtime",
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PQ_AUTH_SUITE,
            "proposal_scheme": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROPOSAL_SCHEME,
            "note_scheme": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_NOTE_SCHEME,
            "auth_scheme": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_AUTH_SCHEME,
            "delegation_scheme": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_DELEGATION_SCHEME,
            "sponsor_scheme": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_SPONSOR_SCHEME,
            "tally_scheme": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_TALLY_SCHEME,
            "settlement_scheme": PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_SETTLEMENT_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = root_from_record("PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-STATE", &record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-STATE",
            &self.public_record_without_state_root(),
        )
    }

    fn insert_nullifier_root(
        &mut self,
        nullifier_root: &str,
    ) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<()> {
        if !self
            .consumed_nullifier_roots
            .insert(nullifier_root.to_string())
        {
            return Err("confidential governance nullifier root already consumed".to_string());
        }
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        Ok(())
    }

    fn seed_devnet_records(&mut self) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<()> {
        let proposal = self.register_proposal(RegisterShieldedProposalRequest {
            proposal_kind: GovernanceProposalKind::FeePolicy,
            proposer_commitment: seeded("devnet-proposer-fee-policy"),
            proposal_payload_root: seeded("devnet-proposal-payload-fee-policy"),
            encrypted_metadata_root: seeded("devnet-proposal-metadata-fee-policy"),
            eligible_voter_root: seeded("devnet-eligible-voters-fee-policy"),
            vote_policy_root: seeded("devnet-vote-policy-fee-policy"),
            quorum_commitment_root: seeded("devnet-quorum-fee-policy"),
            tally_verifier_root: seeded("devnet-tally-verifier-fee-policy"),
            sponsor_policy_root: seeded("devnet-sponsor-policy-fee-policy"),
            proposal_nullifier_root: seeded("devnet-proposal-nullifier-fee-policy"),
            min_privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            registered_at_height: self.current_height,
            vote_start_height: self.current_height,
            vote_end_height: self.current_height.saturating_add(144),
        })?;
        let vote_note = self.submit_vote_note(SubmitConfidentialVoteNoteRequest {
            proposal_id: proposal.proposal_id.clone(),
            voter_commitment: seeded("devnet-voter-commitment-001"),
            encrypted_choice_root: seeded("devnet-vote-choice-encrypted-001"),
            vote_choice_commitment_root: seeded("devnet-vote-choice-commitment-001"),
            vote_weight_commitment_root: seeded("devnet-vote-weight-commitment-001"),
            eligibility_witness_root: seeded("devnet-eligibility-witness-001"),
            note_commitment_root: seeded("devnet-vote-note-commitment-001"),
            vote_nullifier_root: seeded("devnet-vote-nullifier-001"),
            delegation_fence_root: None,
            pq_authorization_root: seeded("devnet-vote-pq-auth-001"),
            privacy_proof_root: seeded("devnet-vote-privacy-proof-001"),
            fee_commitment_root: seeded("devnet-vote-fee-commitment-001"),
            max_fee_bps: self.config.max_user_fee_bps,
            privacy_set_size: self.config.min_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            submitted_at_height: self.current_height,
            expires_at_height: self.current_height.saturating_add(144),
            choice_hint: VoteChoice::For,
        })?;
        self.record_pq_authorization(RecordPqVoterAuthorizationRequest {
            proposal_id: proposal.proposal_id.clone(),
            vote_note_id: vote_note.vote_note_id.clone(),
            voter_key_commitment_root: seeded("devnet-voter-key-root-001"),
            authorization_policy_root: seeded("devnet-auth-policy-root-001"),
            pq_signature_root: seeded("devnet-pq-signature-root-001"),
            pq_kem_ciphertext_root: seeded("devnet-pq-kem-root-001"),
            authorization_nullifier_root: seeded("devnet-auth-nullifier-001"),
            privacy_proof_root: seeded("devnet-auth-privacy-proof-001"),
            pq_security_bits: self.config.min_pq_security_bits,
            authorized_at_height: self.current_height,
            expires_at_height: self.current_height.saturating_add(144),
        })?;
        self.reserve_vote_sponsor(ReserveVoteSponsorRequest {
            proposal_id: proposal.proposal_id.clone(),
            vote_note_id: vote_note.vote_note_id.clone(),
            sponsor_commitment: seeded("devnet-sponsor-commitment-001"),
            budget_root: seeded("devnet-sponsor-budget-001"),
            fee_asset_id: self.config.fee_asset_id.clone(),
            sponsor_policy_root: seeded("devnet-sponsor-policy-001"),
            reserved_fee_bps: self.config.max_sponsor_fee_bps,
            rebate_commitment_root: seeded("devnet-sponsor-rebate-001"),
            pq_reservation_root: seeded("devnet-sponsor-pq-reservation-001"),
            reserved_at_height: self.current_height,
            expires_at_height: self.current_height.saturating_add(24),
        })?;
        let tally = self.build_tally_certificate(BuildTallyCertificateRequest {
            proposal_id: proposal.proposal_id.clone(),
            operator_commitment: seeded("devnet-tally-operator-001"),
            vote_note_ids: vec![vote_note.vote_note_id.clone()],
            aggregate_vote_note_root: seeded("devnet-aggregate-vote-note-root"),
            aggregate_nullifier_root: seeded("devnet-aggregate-nullifier-root"),
            aggregate_delegation_root: seeded("devnet-aggregate-delegation-root"),
            aggregate_authorization_root: seeded("devnet-aggregate-authorization-root"),
            aggregate_sponsor_root: seeded("devnet-aggregate-sponsor-root"),
            encrypted_tally_root: seeded("devnet-encrypted-tally-root"),
            tally_commitment_root: seeded("devnet-tally-commitment-root"),
            tally_proof_root: seeded("devnet-tally-proof-root"),
            pq_certificate_root: seeded("devnet-pq-certificate-root"),
            for_weight_commitment_root: seeded("devnet-for-weight-root"),
            against_weight_commitment_root: seeded("devnet-against-weight-root"),
            abstain_weight_commitment_root: seeded("devnet-abstain-weight-root"),
            veto_signal_weight_commitment_root: seeded("devnet-veto-weight-root"),
            privacy_set_size: self.config.batch_privacy_set_size,
            max_fee_bps: self.config.max_user_fee_bps,
            built_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.batch_ttl_blocks),
        })?;
        self.settle_tally_certificate(SettleTallyCertificateRequest {
            tally_certificate_id: tally.tally_certificate_id,
            proposal_id: proposal.proposal_id,
            settlement_operator_commitment: seeded("devnet-settlement-operator-001"),
            settlement_proof_root: seeded("devnet-settlement-proof-root"),
            state_root_before: seeded("devnet-state-root-before"),
            state_root_after: seeded("devnet-state-root-after"),
            proposal_state_root_after: seeded("devnet-proposal-state-root-after"),
            public_tally_root: seeded("devnet-public-tally-root"),
            fee_receipt_root: seeded("devnet-fee-receipt-root"),
            settlement_nullifier_root: seeded("devnet-settlement-nullifier-root"),
            pq_settlement_root: seeded("devnet-pq-settlement-root"),
            settled_fee_bps: self.config.max_sponsor_fee_bps,
            settled_at_height: self.current_height,
        })?;
        Ok(())
    }
}

pub fn devnet(
) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<PrivateL2ConfidentialGovernanceVoteRuntime> {
    PrivateL2ConfidentialGovernanceVoteRuntime::devnet()
}

pub fn proposal_id(request: &RegisterShieldedProposalRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-PROPOSAL-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.proposal_kind.as_str()),
            HashPart::Str(&request.proposer_commitment),
            HashPart::Str(&request.proposal_payload_root),
            HashPart::Str(&request.proposal_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn vote_note_id(request: &SubmitConfidentialVoteNoteRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-NOTE-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.voter_commitment),
            HashPart::Str(&request.note_commitment_root),
            HashPart::Str(&request.vote_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn pq_authorization_id(request: &RecordPqVoterAuthorizationRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.vote_note_id),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.authorization_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn delegation_id(request: &RegisterDelegationFenceRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-DELEGATION-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.delegator_commitment),
            HashPart::Str(&request.delegate_commitment),
            HashPart::Str(&request.delegation_nullifier_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn vote_sponsor_reservation_id(request: &ReserveVoteSponsorRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-SPONSOR-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.vote_note_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.budget_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn tally_certificate_id(request: &BuildTallyCertificateRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-TALLY-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &SettleTallyCertificateRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn seeded(seed: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-GOVERNANCE-VOTE-DEVNET-SEED",
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn require(condition: bool, message: &str) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_bps(value: u64, label: &str) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_CONFIDENTIAL_GOVERNANCE_VOTE_RUNTIME_MAX_BPS,
        &format!("{label} bps exceeds max"),
    )
}

fn validate_required(
    field: &str,
    value: &str,
) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("confidential governance field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialGovernanceVoteRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("confidential governance privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("confidential governance PQ security bits below minimum".to_string());
    }
    Ok(())
}
