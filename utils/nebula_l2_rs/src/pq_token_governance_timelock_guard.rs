use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqTokenGovernanceTimelockGuardResult<T> = Result<T, String>;

pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_PROTOCOL_VERSION: &str =
    "nebula-l2-pq-token-governance-timelock-guard-v1";
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_SCHEMA_VERSION: &str =
    "nebula-l2-pq-token-governance-timelock-guard-state-v1";
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_HEIGHT: u64 = 7_168;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_PQ_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-governance-v1";
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_BALLOT_KEM: &str = "ML-KEM-1024";
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_TOKEN_REGISTRY: &str =
    "nebula-devnet-private-token-registry";
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_LOW_FEE_LANE: &str =
    "private-token-governance";
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_FEE_ASSET_ID: &str = "piconero";
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_TIMELOCK_BLOCKS: u64 = 1_440;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_FAST_TRACK_BLOCKS: u64 = 96;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_EXECUTION_WINDOW_BLOCKS: u64 = 720;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_VETO_WINDOW_BLOCKS: u64 = 240;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_BALLOT_TTL_BLOCKS: u64 = 2_880;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 20_160;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MIN_QUORUM_BPS: u64 = 2_000;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_SUPERMAJORITY_BPS: u64 = 6_700;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_VETO_THRESHOLD_BPS: u64 = 3_400;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MAX_FEE_UNITS: u64 = 18;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 250_000;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MIN_ANONYMITY_SET: u64 = 1_024;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_BPS: u64 = 10_000;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_TREASURIES: usize = 65_536;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_PROPOSALS: usize = 262_144;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_BALLOTS: usize = 1_048_576;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_TIMELOCKS: usize = 262_144;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_VETOES: usize = 262_144;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_RECEIPTS: usize = 1_048_576;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_NULLIFIERS: usize = 2_097_152;
pub const PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenGovernanceAction {
    MintCapChange,
    TreasurySpend,
    FeeCapChange,
    LiquidityIncentive,
    ContractUpgrade,
    BridgeParameterChange,
    EmergencyFreeze,
    PrivacyBudgetChange,
}

impl TokenGovernanceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MintCapChange => "mint_cap_change",
            Self::TreasurySpend => "treasury_spend",
            Self::FeeCapChange => "fee_cap_change",
            Self::LiquidityIncentive => "liquidity_incentive",
            Self::ContractUpgrade => "contract_upgrade",
            Self::BridgeParameterChange => "bridge_parameter_change",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::PrivacyBudgetChange => "privacy_budget_change",
        }
    }

    pub fn is_critical(self) -> bool {
        matches!(
            self,
            Self::ContractUpgrade | Self::BridgeParameterChange | Self::EmergencyFreeze
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Draft,
    Voting,
    Queued,
    Executable,
    Executed,
    Vetoed,
    Expired,
    Cancelled,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Voting => "voting",
            Self::Queued => "queued",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Vetoed => "vetoed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_ballots(self) -> bool {
        matches!(self, Self::Voting)
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Executed | Self::Vetoed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BallotChoice {
    For,
    Against,
    Abstain,
    VetoSignal,
}

impl BallotChoice {
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
pub enum TimelockStatus {
    Pending,
    FastTracked,
    Ready,
    Executed,
    Vetoed,
    Expired,
}

impl TimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::FastTracked => "fast_tracked",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Vetoed => "vetoed",
            Self::Expired => "expired",
        }
    }

    pub fn executable(self) -> bool {
        matches!(self, Self::Ready | Self::FastTracked)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub pq_signature_suite: String,
    pub ballot_kem_suite: String,
    pub token_registry_id: String,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub timelock_blocks: u64,
    pub fast_track_blocks: u64,
    pub execution_window_blocks: u64,
    pub veto_window_blocks: u64,
    pub ballot_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub veto_threshold_bps: u64,
    pub max_fee_units: u64,
    pub sponsor_budget_units: u64,
    pub min_anonymity_set: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            pq_signature_suite: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_PQ_SUITE.to_string(),
            ballot_kem_suite: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_BALLOT_KEM.to_string(),
            token_registry_id: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_TOKEN_REGISTRY
                .to_string(),
            low_fee_lane: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_LOW_FEE_LANE.to_string(),
            fee_asset_id: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_FEE_ASSET_ID.to_string(),
            timelock_blocks: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_TIMELOCK_BLOCKS,
            fast_track_blocks: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_FAST_TRACK_BLOCKS,
            execution_window_blocks:
                PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_EXECUTION_WINDOW_BLOCKS,
            veto_window_blocks: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_VETO_WINDOW_BLOCKS,
            ballot_ttl_blocks: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_BALLOT_TTL_BLOCKS,
            receipt_ttl_blocks: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_RECEIPT_TTL_BLOCKS,
            min_quorum_bps: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MIN_QUORUM_BPS,
            supermajority_bps: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_SUPERMAJORITY_BPS,
            veto_threshold_bps: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_VETO_THRESHOLD_BPS,
            max_fee_units: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MAX_FEE_UNITS,
            sponsor_budget_units: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_SPONSOR_BUDGET_UNITS,
            min_anonymity_set: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MIN_ANONYMITY_SET,
            min_pq_security_bits: PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(!self.chain_id.is_empty(), "governance chain id is empty")?;
        require(
            self.chain_id == CHAIN_ID,
            "governance chain id does not match crate chain id",
        )?;
        require(
            self.pq_signature_suite.contains("ML-DSA"),
            "governance signature suite must include ML-DSA",
        )?;
        require(
            self.ballot_kem_suite.contains("ML-KEM"),
            "governance ballot KEM suite must include ML-KEM",
        )?;
        require(
            !self.token_registry_id.is_empty(),
            "governance token registry id is empty",
        )?;
        require(
            !self.low_fee_lane.is_empty(),
            "governance low fee lane is empty",
        )?;
        require(
            !self.fee_asset_id.is_empty(),
            "governance fee asset id is empty",
        )?;
        require(
            self.timelock_blocks > 0,
            "governance timelock must be positive",
        )?;
        require(
            self.fast_track_blocks > 0 && self.fast_track_blocks <= self.timelock_blocks,
            "governance fast track window must fit inside timelock",
        )?;
        require(
            self.execution_window_blocks >= self.fast_track_blocks,
            "governance execution window too short",
        )?;
        require(
            self.veto_window_blocks > 0,
            "governance veto window is empty",
        )?;
        require(
            self.ballot_ttl_blocks >= self.veto_window_blocks,
            "governance ballot ttl shorter than veto window",
        )?;
        require(
            self.receipt_ttl_blocks >= self.ballot_ttl_blocks,
            "governance receipt ttl shorter than ballot ttl",
        )?;
        require_bps(self.min_quorum_bps, "min quorum")?;
        require_bps(self.supermajority_bps, "supermajority")?;
        require_bps(self.veto_threshold_bps, "veto threshold")?;
        require(
            self.supermajority_bps >= self.min_quorum_bps,
            "governance supermajority below quorum",
        )?;
        require(
            self.veto_threshold_bps <= self.supermajority_bps,
            "governance veto threshold too high",
        )?;
        require(
            self.max_fee_units > 0,
            "governance max fee must be positive",
        )?;
        require(
            self.sponsor_budget_units >= self.max_fee_units,
            "governance sponsor budget below one fee",
        )?;
        require(
            self.min_anonymity_set >= 128,
            "governance anonymity set too small",
        )?;
        require(
            self.min_pq_security_bits >= 128,
            "governance pq security bits too small",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_governance_timelock_guard_config",
            "chain_id": self.chain_id,
            "pq_signature_suite": self.pq_signature_suite,
            "ballot_kem_suite": self.ballot_kem_suite,
            "token_registry_id": self.token_registry_id,
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "timelock_blocks": self.timelock_blocks,
            "fast_track_blocks": self.fast_track_blocks,
            "execution_window_blocks": self.execution_window_blocks,
            "veto_window_blocks": self.veto_window_blocks,
            "ballot_ttl_blocks": self.ballot_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "min_quorum_bps": self.min_quorum_bps,
            "supermajority_bps": self.supermajority_bps,
            "veto_threshold_bps": self.veto_threshold_bps,
            "max_fee_units": self.max_fee_units,
            "sponsor_budget_units": self.sponsor_budget_units,
            "min_anonymity_set": self.min_anonymity_set,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenGovernanceTreasury {
    pub treasury_id: String,
    pub token_id: String,
    pub policy_commitment: String,
    pub guardian_set_commitment: String,
    pub spend_limit_units: u64,
    pub daily_fee_budget_units: u64,
    pub emergency_freeze_commitment: String,
}

impl TokenGovernanceTreasury {
    pub fn new(
        token_id: &str,
        policy_commitment: &str,
        guardian_set_commitment: &str,
        spend_limit_units: u64,
        daily_fee_budget_units: u64,
        emergency_freeze_commitment: &str,
    ) -> Self {
        let treasury_id = treasury_id(
            token_id,
            policy_commitment,
            guardian_set_commitment,
            emergency_freeze_commitment,
        );
        Self {
            treasury_id,
            token_id: token_id.to_string(),
            policy_commitment: policy_commitment.to_string(),
            guardian_set_commitment: guardian_set_commitment.to_string(),
            spend_limit_units,
            daily_fee_budget_units,
            emergency_freeze_commitment: emergency_freeze_commitment.to_string(),
        }
    }

    pub fn validate(&self, config: &Config) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(!self.treasury_id.is_empty(), "treasury id is empty")?;
        require(!self.token_id.is_empty(), "treasury token id is empty")?;
        require(
            !self.policy_commitment.is_empty(),
            "treasury policy commitment is empty",
        )?;
        require(
            !self.guardian_set_commitment.is_empty(),
            "treasury guardian set commitment is empty",
        )?;
        require(
            self.spend_limit_units > 0,
            "treasury spend limit must be positive",
        )?;
        require(
            self.daily_fee_budget_units >= config.max_fee_units,
            "treasury daily fee budget below max fee",
        )?;
        require(
            !self.emergency_freeze_commitment.is_empty(),
            "treasury freeze commitment is empty",
        )?;
        require(
            self.treasury_id
                == treasury_id(
                    &self.token_id,
                    &self.policy_commitment,
                    &self.guardian_set_commitment,
                    &self.emergency_freeze_commitment,
                ),
            "treasury id mismatch",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_governance_treasury",
            "treasury_id": self.treasury_id,
            "token_id": self.token_id,
            "policy_commitment": self.policy_commitment,
            "guardian_set_commitment": self.guardian_set_commitment,
            "spend_limit_units": self.spend_limit_units,
            "daily_fee_budget_units": self.daily_fee_budget_units,
            "emergency_freeze_commitment": self.emergency_freeze_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProposal {
    pub proposal_id: String,
    pub treasury_id: String,
    pub action: TokenGovernanceAction,
    pub proposer_commitment: String,
    pub encrypted_payload_root: String,
    pub call_authorization_root: String,
    pub requested_fee_units: u64,
    pub quorum_bps: u64,
    pub created_height: u64,
    pub vote_start_height: u64,
    pub vote_end_height: u64,
    pub status: ProposalStatus,
}

impl PrivateProposal {
    pub fn new(
        treasury_id: &str,
        action: TokenGovernanceAction,
        proposer_commitment: &str,
        encrypted_payload_root: &str,
        call_authorization_root: &str,
        requested_fee_units: u64,
        quorum_bps: u64,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let vote_start_height = created_height.saturating_add(1);
        let vote_end_height = vote_start_height.saturating_add(config.ballot_ttl_blocks);
        let proposal_id = proposal_id(
            treasury_id,
            action,
            proposer_commitment,
            encrypted_payload_root,
            created_height,
        );
        Self {
            proposal_id,
            treasury_id: treasury_id.to_string(),
            action,
            proposer_commitment: proposer_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            call_authorization_root: call_authorization_root.to_string(),
            requested_fee_units,
            quorum_bps,
            created_height,
            vote_start_height,
            vote_end_height,
            status: ProposalStatus::Voting,
        }
    }

    pub fn validate(&self, config: &Config) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(!self.proposal_id.is_empty(), "proposal id is empty")?;
        require(
            !self.treasury_id.is_empty(),
            "proposal treasury id is empty",
        )?;
        require(
            !self.proposer_commitment.is_empty(),
            "proposal proposer commitment is empty",
        )?;
        require(
            !self.encrypted_payload_root.is_empty(),
            "proposal encrypted payload root is empty",
        )?;
        require(
            !self.call_authorization_root.is_empty(),
            "proposal call authorization root is empty",
        )?;
        require(
            self.requested_fee_units <= config.max_fee_units,
            "proposal requested fee exceeds cap",
        )?;
        require_bps(self.quorum_bps, "proposal quorum")?;
        require(
            self.quorum_bps >= config.min_quorum_bps,
            "proposal quorum below config minimum",
        )?;
        require(
            self.vote_start_height > self.created_height,
            "proposal vote start must follow creation",
        )?;
        require(
            self.vote_end_height > self.vote_start_height,
            "proposal vote end must follow start",
        )?;
        require(
            self.proposal_id
                == proposal_id(
                    &self.treasury_id,
                    self.action,
                    &self.proposer_commitment,
                    &self.encrypted_payload_root,
                    self.created_height,
                ),
            "proposal id mismatch",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_private_proposal",
            "proposal_id": self.proposal_id,
            "treasury_id": self.treasury_id,
            "action": self.action.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "call_authorization_root": self.call_authorization_root,
            "requested_fee_units": self.requested_fee_units,
            "quorum_bps": self.quorum_bps,
            "created_height": self.created_height,
            "vote_start_height": self.vote_start_height,
            "vote_end_height": self.vote_end_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialBallot {
    pub ballot_id: String,
    pub proposal_id: String,
    pub voter_nullifier: String,
    pub encrypted_choice_root: String,
    pub choice_commitment: String,
    pub weight_bucket_bps: u64,
    pub choice: BallotChoice,
    pub pq_signature_commitment: String,
    pub submitted_height: u64,
}

impl ConfidentialBallot {
    pub fn new(
        proposal_id: &str,
        voter_nullifier: &str,
        encrypted_choice_root: &str,
        choice_commitment: &str,
        weight_bucket_bps: u64,
        choice: BallotChoice,
        pq_signature_commitment: &str,
        submitted_height: u64,
    ) -> Self {
        let ballot_id = ballot_id(
            proposal_id,
            voter_nullifier,
            encrypted_choice_root,
            submitted_height,
        );
        Self {
            ballot_id,
            proposal_id: proposal_id.to_string(),
            voter_nullifier: voter_nullifier.to_string(),
            encrypted_choice_root: encrypted_choice_root.to_string(),
            choice_commitment: choice_commitment.to_string(),
            weight_bucket_bps,
            choice,
            pq_signature_commitment: pq_signature_commitment.to_string(),
            submitted_height,
        }
    }

    pub fn validate(&self) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(!self.ballot_id.is_empty(), "ballot id is empty")?;
        require(!self.proposal_id.is_empty(), "ballot proposal id is empty")?;
        require(
            !self.voter_nullifier.is_empty(),
            "ballot voter nullifier is empty",
        )?;
        require(
            !self.encrypted_choice_root.is_empty(),
            "ballot encrypted choice root is empty",
        )?;
        require(
            !self.choice_commitment.is_empty(),
            "ballot choice commitment is empty",
        )?;
        require_bps(self.weight_bucket_bps, "ballot weight bucket")?;
        require(
            !self.pq_signature_commitment.is_empty(),
            "ballot pq signature commitment is empty",
        )?;
        require(
            self.ballot_id
                == ballot_id(
                    &self.proposal_id,
                    &self.voter_nullifier,
                    &self.encrypted_choice_root,
                    self.submitted_height,
                ),
            "ballot id mismatch",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_confidential_ballot",
            "ballot_id": self.ballot_id,
            "proposal_id": self.proposal_id,
            "voter_nullifier": self.voter_nullifier,
            "encrypted_choice_root": self.encrypted_choice_root,
            "choice_commitment": self.choice_commitment,
            "weight_bucket_bps": self.weight_bucket_bps,
            "choice": self.choice.as_str(),
            "pq_signature_commitment": self.pq_signature_commitment,
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedTimelock {
    pub timelock_id: String,
    pub proposal_id: String,
    pub payload_commitment: String,
    pub queued_height: u64,
    pub unlock_height: u64,
    pub expire_height: u64,
    pub status: TimelockStatus,
}

impl QueuedTimelock {
    pub fn new(
        proposal_id: &str,
        payload_commitment: &str,
        queued_height: u64,
        config: &Config,
        fast_track: bool,
    ) -> Self {
        let delay = if fast_track {
            config.fast_track_blocks
        } else {
            config.timelock_blocks
        };
        let unlock_height = queued_height.saturating_add(delay);
        let expire_height = unlock_height.saturating_add(config.execution_window_blocks);
        let timelock_id = timelock_id(proposal_id, payload_commitment, queued_height);
        Self {
            timelock_id,
            proposal_id: proposal_id.to_string(),
            payload_commitment: payload_commitment.to_string(),
            queued_height,
            unlock_height,
            expire_height,
            status: if fast_track {
                TimelockStatus::FastTracked
            } else {
                TimelockStatus::Pending
            },
        }
    }

    pub fn validate(&self) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(!self.timelock_id.is_empty(), "timelock id is empty")?;
        require(
            !self.proposal_id.is_empty(),
            "timelock proposal id is empty",
        )?;
        require(
            !self.payload_commitment.is_empty(),
            "timelock payload commitment is empty",
        )?;
        require(
            self.unlock_height > self.queued_height,
            "timelock unlock must follow queue",
        )?;
        require(
            self.expire_height > self.unlock_height,
            "timelock expiry must follow unlock",
        )?;
        require(
            self.timelock_id
                == timelock_id(
                    &self.proposal_id,
                    &self.payload_commitment,
                    self.queued_height,
                ),
            "timelock id mismatch",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_queued_timelock",
            "timelock_id": self.timelock_id,
            "proposal_id": self.proposal_id,
            "payload_commitment": self.payload_commitment,
            "queued_height": self.queued_height,
            "unlock_height": self.unlock_height,
            "expire_height": self.expire_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VetoRecord {
    pub veto_id: String,
    pub proposal_id: String,
    pub guardian_nullifier: String,
    pub reason_commitment: String,
    pub veto_weight_bps: u64,
    pub submitted_height: u64,
}

impl VetoRecord {
    pub fn new(
        proposal_id: &str,
        guardian_nullifier: &str,
        reason_commitment: &str,
        veto_weight_bps: u64,
        submitted_height: u64,
    ) -> Self {
        let veto_id = veto_id(
            proposal_id,
            guardian_nullifier,
            reason_commitment,
            submitted_height,
        );
        Self {
            veto_id,
            proposal_id: proposal_id.to_string(),
            guardian_nullifier: guardian_nullifier.to_string(),
            reason_commitment: reason_commitment.to_string(),
            veto_weight_bps,
            submitted_height,
        }
    }

    pub fn validate(&self) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(!self.veto_id.is_empty(), "veto id is empty")?;
        require(!self.proposal_id.is_empty(), "veto proposal id is empty")?;
        require(
            !self.guardian_nullifier.is_empty(),
            "veto guardian nullifier is empty",
        )?;
        require(
            !self.reason_commitment.is_empty(),
            "veto reason commitment is empty",
        )?;
        require_bps(self.veto_weight_bps, "veto weight")?;
        require(
            self.veto_id
                == veto_id(
                    &self.proposal_id,
                    &self.guardian_nullifier,
                    &self.reason_commitment,
                    self.submitted_height,
                ),
            "veto id mismatch",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_veto_record",
            "veto_id": self.veto_id,
            "proposal_id": self.proposal_id,
            "guardian_nullifier": self.guardian_nullifier,
            "reason_commitment": self.reason_commitment,
            "veto_weight_bps": self.veto_weight_bps,
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub proposal_id: String,
    pub timelock_id: String,
    pub executor_commitment: String,
    pub state_transition_root: String,
    pub fee_paid_units: u64,
    pub executed_height: u64,
}

impl ExecutionReceipt {
    pub fn new(
        proposal_id: &str,
        timelock_id: &str,
        executor_commitment: &str,
        state_transition_root: &str,
        fee_paid_units: u64,
        executed_height: u64,
    ) -> Self {
        let receipt_id = receipt_id(
            proposal_id,
            timelock_id,
            executor_commitment,
            state_transition_root,
            executed_height,
        );
        Self {
            receipt_id,
            proposal_id: proposal_id.to_string(),
            timelock_id: timelock_id.to_string(),
            executor_commitment: executor_commitment.to_string(),
            state_transition_root: state_transition_root.to_string(),
            fee_paid_units,
            executed_height,
        }
    }

    pub fn validate(&self, config: &Config) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(!self.receipt_id.is_empty(), "receipt id is empty")?;
        require(!self.proposal_id.is_empty(), "receipt proposal id is empty")?;
        require(!self.timelock_id.is_empty(), "receipt timelock id is empty")?;
        require(
            !self.executor_commitment.is_empty(),
            "receipt executor commitment is empty",
        )?;
        require(
            !self.state_transition_root.is_empty(),
            "receipt state transition root is empty",
        )?;
        require(
            self.fee_paid_units <= config.max_fee_units,
            "receipt fee exceeds governance cap",
        )?;
        require(
            self.receipt_id
                == receipt_id(
                    &self.proposal_id,
                    &self.timelock_id,
                    &self.executor_commitment,
                    &self.state_transition_root,
                    self.executed_height,
                ),
            "receipt id mismatch",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_execution_receipt",
            "receipt_id": self.receipt_id,
            "proposal_id": self.proposal_id,
            "timelock_id": self.timelock_id,
            "executor_commitment": self.executor_commitment,
            "state_transition_root": self.state_transition_root,
            "fee_paid_units": self.fee_paid_units,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub treasury_root: String,
    pub proposal_root: String,
    pub ballot_root: String,
    pub timelock_root: String,
    pub veto_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "treasury_root": self.treasury_root,
            "proposal_root": self.proposal_root,
            "ballot_root": self.ballot_root,
            "timelock_root": self.timelock_root,
            "veto_root": self.veto_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub treasury_count: usize,
    pub proposal_count: usize,
    pub ballot_count: usize,
    pub timelock_count: usize,
    pub veto_count: usize,
    pub receipt_count: usize,
    pub nullifier_count: usize,
    pub event_count: usize,
    pub active_proposal_count: usize,
    pub terminal_proposal_count: usize,
    pub critical_action_count: usize,
    pub sponsored_fee_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "treasury_count": self.treasury_count,
            "proposal_count": self.proposal_count,
            "ballot_count": self.ballot_count,
            "timelock_count": self.timelock_count,
            "veto_count": self.veto_count,
            "receipt_count": self.receipt_count,
            "nullifier_count": self.nullifier_count,
            "event_count": self.event_count,
            "active_proposal_count": self.active_proposal_count,
            "terminal_proposal_count": self.terminal_proposal_count,
            "critical_action_count": self.critical_action_count,
            "sponsored_fee_units": self.sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub treasuries: BTreeMap<String, TokenGovernanceTreasury>,
    pub proposals: BTreeMap<String, PrivateProposal>,
    pub ballots: BTreeMap<String, ConfidentialBallot>,
    pub timelocks: BTreeMap<String, QueuedTimelock>,
    pub vetoes: BTreeMap<String, VetoRecord>,
    pub receipts: BTreeMap<String, ExecutionReceipt>,
    pub nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64) -> PqTokenGovernanceTimelockGuardResult<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            treasuries: BTreeMap::new(),
            proposals: BTreeMap::new(),
            ballots: BTreeMap::new(),
            timelocks: BTreeMap::new(),
            vetoes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn devnet() -> PqTokenGovernanceTimelockGuardResult<Self> {
        Self::new(
            Config::devnet(),
            PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_DEFAULT_HEIGHT,
        )
    }

    pub fn set_height(&mut self, height: u64) -> PqTokenGovernanceTimelockGuardResult<()> {
        self.height = height;
        self.update_height(height)
    }

    pub fn update_height(&mut self, height: u64) -> PqTokenGovernanceTimelockGuardResult<()> {
        self.height = height;
        for proposal in self.proposals.values_mut() {
            if proposal.status.accepts_ballots() && height > proposal.vote_end_height {
                proposal.status = ProposalStatus::Queued;
            }
        }
        for timelock in self.timelocks.values_mut() {
            if matches!(timelock.status, TimelockStatus::Pending)
                && height >= timelock.unlock_height
            {
                timelock.status = TimelockStatus::Ready;
            }
            if timelock.status.executable() && height > timelock.expire_height {
                timelock.status = TimelockStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn insert_treasury(
        &mut self,
        treasury: TokenGovernanceTreasury,
    ) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(
            self.treasuries.len() < PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_TREASURIES
                || self.treasuries.contains_key(&treasury.treasury_id),
            "governance treasury capacity exceeded",
        )?;
        treasury.validate(&self.config)?;
        self.events.push(json!({
            "kind": "governance_treasury_registered",
            "treasury_id": treasury.treasury_id,
            "height": self.height,
        }));
        self.treasuries
            .insert(treasury.treasury_id.clone(), treasury);
        self.validate()
    }

    pub fn submit_proposal(
        &mut self,
        proposal: PrivateProposal,
    ) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(
            self.proposals.len() < PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_PROPOSALS
                || self.proposals.contains_key(&proposal.proposal_id),
            "governance proposal capacity exceeded",
        )?;
        require(
            self.treasuries.contains_key(&proposal.treasury_id),
            "governance proposal references unknown treasury",
        )?;
        proposal.validate(&self.config)?;
        self.events.push(json!({
            "kind": "governance_private_proposal_submitted",
            "proposal_id": proposal.proposal_id,
            "action": proposal.action.as_str(),
            "height": self.height,
        }));
        self.proposals
            .insert(proposal.proposal_id.clone(), proposal);
        self.validate()
    }

    pub fn submit_ballot(
        &mut self,
        ballot: ConfidentialBallot,
    ) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(
            self.ballots.len() < PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_BALLOTS
                || self.ballots.contains_key(&ballot.ballot_id),
            "governance ballot capacity exceeded",
        )?;
        require(
            self.nullifiers.len() < PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_NULLIFIERS
                || self.nullifiers.contains(&ballot.voter_nullifier),
            "governance nullifier capacity exceeded",
        )?;
        let proposal = self
            .proposals
            .get(&ballot.proposal_id)
            .ok_or_else(|| "governance ballot references unknown proposal".to_string())?;
        require(
            proposal.status.accepts_ballots(),
            "governance proposal is not accepting ballots",
        )?;
        require(
            ballot.submitted_height >= proposal.vote_start_height
                && ballot.submitted_height <= proposal.vote_end_height,
            "governance ballot submitted outside voting window",
        )?;
        require(
            !self.nullifiers.contains(&ballot.voter_nullifier),
            "governance voter nullifier already spent",
        )?;
        ballot.validate()?;
        self.nullifiers.insert(ballot.voter_nullifier.clone());
        self.events.push(json!({
            "kind": "governance_confidential_ballot_submitted",
            "ballot_id": ballot.ballot_id,
            "proposal_id": ballot.proposal_id,
            "choice": ballot.choice.as_str(),
            "height": self.height,
        }));
        self.ballots.insert(ballot.ballot_id.clone(), ballot);
        self.validate()
    }

    pub fn queue_timelock(
        &mut self,
        timelock: QueuedTimelock,
    ) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(
            self.timelocks.len() < PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_TIMELOCKS
                || self.timelocks.contains_key(&timelock.timelock_id),
            "governance timelock capacity exceeded",
        )?;
        require(
            self.proposals.contains_key(&timelock.proposal_id),
            "governance timelock references unknown proposal",
        )?;
        timelock.validate()?;
        self.events.push(json!({
            "kind": "governance_timelock_queued",
            "timelock_id": timelock.timelock_id,
            "proposal_id": timelock.proposal_id,
            "height": self.height,
        }));
        self.timelocks
            .insert(timelock.timelock_id.clone(), timelock);
        self.validate()
    }

    pub fn submit_veto(&mut self, veto: VetoRecord) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(
            self.vetoes.len() < PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_VETOES
                || self.vetoes.contains_key(&veto.veto_id),
            "governance veto capacity exceeded",
        )?;
        require(
            self.proposals.contains_key(&veto.proposal_id),
            "governance veto references unknown proposal",
        )?;
        veto.validate()?;
        self.events.push(json!({
            "kind": "governance_private_veto_submitted",
            "veto_id": veto.veto_id,
            "proposal_id": veto.proposal_id,
            "height": self.height,
        }));
        self.vetoes.insert(veto.veto_id.clone(), veto);
        self.validate()
    }

    pub fn record_execution(
        &mut self,
        receipt: ExecutionReceipt,
    ) -> PqTokenGovernanceTimelockGuardResult<()> {
        require(
            self.receipts.len() < PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_RECEIPTS
                || self.receipts.contains_key(&receipt.receipt_id),
            "governance receipt capacity exceeded",
        )?;
        require(
            self.proposals.contains_key(&receipt.proposal_id),
            "governance receipt references unknown proposal",
        )?;
        require(
            self.timelocks.contains_key(&receipt.timelock_id),
            "governance receipt references unknown timelock",
        )?;
        receipt.validate(&self.config)?;
        self.events.push(json!({
            "kind": "governance_timelock_executed",
            "receipt_id": receipt.receipt_id,
            "proposal_id": receipt.proposal_id,
            "height": self.height,
        }));
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.validate()
    }

    pub fn validate(&self) -> PqTokenGovernanceTimelockGuardResult<()> {
        self.config.validate()?;
        require(
            self.treasuries.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_TREASURIES,
            "governance treasury limit exceeded",
        )?;
        require(
            self.proposals.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_PROPOSALS,
            "governance proposal limit exceeded",
        )?;
        require(
            self.ballots.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_BALLOTS,
            "governance ballot limit exceeded",
        )?;
        require(
            self.timelocks.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_TIMELOCKS,
            "governance timelock limit exceeded",
        )?;
        require(
            self.vetoes.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_VETOES,
            "governance veto limit exceeded",
        )?;
        require(
            self.receipts.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_RECEIPTS,
            "governance receipt limit exceeded",
        )?;
        require(
            self.nullifiers.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_NULLIFIERS,
            "governance nullifier limit exceeded",
        )?;
        require(
            self.events.len() <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_EVENTS,
            "governance event limit exceeded",
        )?;
        for treasury in self.treasuries.values() {
            treasury.validate(&self.config)?;
        }
        for proposal in self.proposals.values() {
            require(
                self.treasuries.contains_key(&proposal.treasury_id),
                "proposal references missing treasury",
            )?;
            proposal.validate(&self.config)?;
        }
        for ballot in self.ballots.values() {
            require(
                self.proposals.contains_key(&ballot.proposal_id),
                "ballot references missing proposal",
            )?;
            ballot.validate()?;
        }
        for timelock in self.timelocks.values() {
            require(
                self.proposals.contains_key(&timelock.proposal_id),
                "timelock references missing proposal",
            )?;
            timelock.validate()?;
        }
        for veto in self.vetoes.values() {
            require(
                self.proposals.contains_key(&veto.proposal_id),
                "veto references missing proposal",
            )?;
            veto.validate()?;
        }
        for receipt in self.receipts.values() {
            require(
                self.proposals.contains_key(&receipt.proposal_id),
                "receipt references missing proposal",
            )?;
            require(
                self.timelocks.contains_key(&receipt.timelock_id),
                "receipt references missing timelock",
            )?;
            receipt.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(&self.config.public_record()),
            treasury_root: value_root(
                "PQ-TOKEN-GOVERNANCE-TREASURY",
                self.treasuries
                    .values()
                    .map(TokenGovernanceTreasury::public_record)
                    .collect(),
            ),
            proposal_root: value_root(
                "PQ-TOKEN-GOVERNANCE-PROPOSAL",
                self.proposals
                    .values()
                    .map(PrivateProposal::public_record)
                    .collect(),
            ),
            ballot_root: value_root(
                "PQ-TOKEN-GOVERNANCE-BALLOT",
                self.ballots
                    .values()
                    .map(ConfidentialBallot::public_record)
                    .collect(),
            ),
            timelock_root: value_root(
                "PQ-TOKEN-GOVERNANCE-TIMELOCK",
                self.timelocks
                    .values()
                    .map(QueuedTimelock::public_record)
                    .collect(),
            ),
            veto_root: value_root(
                "PQ-TOKEN-GOVERNANCE-VETO",
                self.vetoes
                    .values()
                    .map(VetoRecord::public_record)
                    .collect(),
            ),
            receipt_root: value_root(
                "PQ-TOKEN-GOVERNANCE-RECEIPT",
                self.receipts
                    .values()
                    .map(ExecutionReceipt::public_record)
                    .collect(),
            ),
            nullifier_root: string_set_root(
                "PQ-TOKEN-GOVERNANCE-NULLIFIER",
                &self.nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            event_root: value_root("PQ-TOKEN-GOVERNANCE-EVENT", self.events.clone()),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            treasury_count: self.treasuries.len(),
            proposal_count: self.proposals.len(),
            ballot_count: self.ballots.len(),
            timelock_count: self.timelocks.len(),
            veto_count: self.vetoes.len(),
            receipt_count: self.receipts.len(),
            nullifier_count: self.nullifiers.len(),
            event_count: self.events.len(),
            active_proposal_count: self
                .proposals
                .values()
                .filter(|proposal| !proposal.status.is_terminal())
                .count(),
            terminal_proposal_count: self
                .proposals
                .values()
                .filter(|proposal| proposal.status.is_terminal())
                .count(),
            critical_action_count: self
                .proposals
                .values()
                .filter(|proposal| proposal.action.is_critical())
                .count(),
            sponsored_fee_units: self
                .receipts
                .values()
                .map(|receipt| receipt.fee_paid_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        let record = json!({
            "kind": "pq_token_governance_timelock_guard_state_root",
            "protocol": PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_PROTOCOL_VERSION,
            "schema": PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_SCHEMA_VERSION,
            "height": self.height,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        });
        root_from_record(&record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_governance_timelock_guard_state",
            "protocol": PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_PROTOCOL_VERSION,
            "schema": PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
        })
    }

    fn seed_devnet_records(&mut self) -> PqTokenGovernanceTimelockGuardResult<()> {
        let treasury = TokenGovernanceTreasury::new(
            "private-governance-token-devnet",
            "policy:mint-cap:low-fee-defi:001",
            "guardian-set:ml-dsa:governance:001",
            50_000_000,
            100_000,
            "freeze:selective-disclosure:001",
        );
        let treasury_id = treasury.treasury_id.clone();
        self.insert_treasury(treasury)?;

        let proposal = PrivateProposal::new(
            &treasury_id,
            TokenGovernanceAction::FeeCapChange,
            "proposer:stealth:fee-council:001",
            "encrypted-payload:fee-cap-change:001",
            "call-auth:low-fee-router:001",
            12,
            self.config.min_quorum_bps.saturating_add(600),
            self.height,
            &self.config,
        );
        let proposal_id = proposal.proposal_id.clone();
        self.submit_proposal(proposal)?;

        let ballot = ConfidentialBallot::new(
            &proposal_id,
            "nullifier:voter:fee-cap:001",
            "encrypted-choice:fee-cap:for:001",
            "choice-commitment:for:fee-cap:001",
            2_400,
            BallotChoice::For,
            "pq-signature:ml-dsa:ballot:001",
            self.height.saturating_add(2),
        );
        self.submit_ballot(ballot)?;

        let timelock = QueuedTimelock::new(
            &proposal_id,
            "payload:fee-cap-change:timelock:001",
            self.height.saturating_add(self.config.ballot_ttl_blocks),
            &self.config,
            false,
        );
        let timelock_id = timelock.timelock_id.clone();
        self.queue_timelock(timelock)?;

        let veto = VetoRecord::new(
            &proposal_id,
            "guardian-nullifier:risk-council:001",
            "veto-reason:fee-cap-review:001",
            400,
            self.height.saturating_add(4),
        );
        self.submit_veto(veto)?;

        let receipt = ExecutionReceipt::new(
            &proposal_id,
            &timelock_id,
            "executor:private-paymaster:001",
            "state-transition:fee-cap-change:001",
            9,
            self.height
                .saturating_add(self.config.ballot_ttl_blocks)
                .saturating_add(self.config.timelock_blocks)
                .saturating_add(1),
        );
        self.record_execution(receipt)
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-TOKEN-GOVERNANCE-TIMELOCK-GUARD-RECORD",
        &[
            HashPart::Str(PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> PqTokenGovernanceTimelockGuardResult<State> {
    State::devnet()
}

pub fn treasury_id(
    token_id: &str,
    policy_commitment: &str,
    guardian_set_commitment: &str,
    emergency_freeze_commitment: &str,
) -> String {
    domain_hash(
        "PQ-TOKEN-GOVERNANCE-TREASURY-ID",
        &[
            HashPart::Str(token_id),
            HashPart::Str(policy_commitment),
            HashPart::Str(guardian_set_commitment),
            HashPart::Str(emergency_freeze_commitment),
        ],
        32,
    )
}

pub fn proposal_id(
    treasury_id: &str,
    action: TokenGovernanceAction,
    proposer_commitment: &str,
    encrypted_payload_root: &str,
    created_height: u64,
) -> String {
    let created_height = created_height.to_string();
    domain_hash(
        "PQ-TOKEN-GOVERNANCE-PROPOSAL-ID",
        &[
            HashPart::Str(treasury_id),
            HashPart::Str(action.as_str()),
            HashPart::Str(proposer_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(&created_height),
        ],
        32,
    )
}

pub fn ballot_id(
    proposal_id: &str,
    voter_nullifier: &str,
    encrypted_choice_root: &str,
    submitted_height: u64,
) -> String {
    let submitted_height = submitted_height.to_string();
    domain_hash(
        "PQ-TOKEN-GOVERNANCE-BALLOT-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(voter_nullifier),
            HashPart::Str(encrypted_choice_root),
            HashPart::Str(&submitted_height),
        ],
        32,
    )
}

pub fn timelock_id(proposal_id: &str, payload_commitment: &str, queued_height: u64) -> String {
    let queued_height = queued_height.to_string();
    domain_hash(
        "PQ-TOKEN-GOVERNANCE-TIMELOCK-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(payload_commitment),
            HashPart::Str(&queued_height),
        ],
        32,
    )
}

pub fn veto_id(
    proposal_id: &str,
    guardian_nullifier: &str,
    reason_commitment: &str,
    submitted_height: u64,
) -> String {
    let submitted_height = submitted_height.to_string();
    domain_hash(
        "PQ-TOKEN-GOVERNANCE-VETO-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(guardian_nullifier),
            HashPart::Str(reason_commitment),
            HashPart::Str(&submitted_height),
        ],
        32,
    )
}

pub fn receipt_id(
    proposal_id: &str,
    timelock_id: &str,
    executor_commitment: &str,
    state_transition_root: &str,
    executed_height: u64,
) -> String {
    let executed_height = executed_height.to_string();
    domain_hash(
        "PQ-TOKEN-GOVERNANCE-RECEIPT-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(timelock_id),
            HashPart::Str(executor_commitment),
            HashPart::Str(state_transition_root),
            HashPart::Str(&executed_height),
        ],
        32,
    )
}

fn value_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require(condition: bool, message: &str) -> PqTokenGovernanceTimelockGuardResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_bps(value: u64, label: &str) -> PqTokenGovernanceTimelockGuardResult<()> {
    require(
        value <= PQ_TOKEN_GOVERNANCE_TIMELOCK_GUARD_MAX_BPS,
        &format!("{label} bps exceeds max"),
    )
}
