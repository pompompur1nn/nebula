use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqPreconfirmationQuorumRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-preconfirmation-quorum-runtime-v1";
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEVNET_HEIGHT: u64 = 204_000;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MAX_PENDING_INTENTS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MAX_CERTIFICATE_INTENTS: usize =
    8_192;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_CERTIFICATE_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationLane {
    PrivateContractCall,
    PrivateDefi,
    ConfidentialToken,
    MoneroFastExit,
    ProofDataAvailability,
    SettlementManifest,
}

impl PreconfirmationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateDefi => "private_defi",
            Self::ConfidentialToken => "confidential_token",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::ProofDataAvailability => "proof_data_availability",
            Self::SettlementManifest => "settlement_manifest",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::MoneroFastExit => 10_000,
            Self::PrivateContractCall => 9_000,
            Self::PrivateDefi => 8_700,
            Self::ConfidentialToken => 8_000,
            Self::ProofDataAvailability => 7_600,
            Self::SettlementManifest => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Pending,
    Voted,
    Certified,
    Settled,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Voted => "voted",
            Self::Certified => "certified",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn certifiable(self) -> bool {
        matches!(self, Self::Pending | Self::Voted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteVerdict {
    Approve,
    Reject,
    Abstain,
}

impl VoteVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Built,
    SettlementReady,
    Settled,
    Rejected,
    Expired,
}

impl CertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub max_pending_intents: usize,
    pub max_certificate_intents: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub certificate_ttl_blocks: u64,
    pub require_fee_sponsor: bool,
    pub require_replay_fence: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_pending_intents:
                PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MAX_PENDING_INTENTS,
            max_certificate_intents:
                PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MAX_CERTIFICATE_INTENTS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_weight_bps:
                PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS,
            max_user_fee_bps: PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            certificate_ttl_blocks:
                PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEFAULT_CERTIFICATE_TTL_BLOCKS,
            require_fee_sponsor: true,
            require_replay_fence: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
        if self.max_pending_intents == 0 || self.max_certificate_intents == 0 {
            return Err("PQ preconfirmation capacities must be positive".to_string());
        }
        if self.max_certificate_intents > self.max_pending_intents {
            return Err(
                "PQ preconfirmation certificate capacity exceeds pending capacity".to_string(),
            );
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("PQ preconfirmation privacy set policy is invalid".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("PQ preconfirmation security floor is too low".to_string());
        }
        if self.quorum_weight_bps == 0
            || self.quorum_weight_bps > PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_MAX_BPS
        {
            return Err("PQ preconfirmation quorum weight is invalid".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_MAX_BPS {
            return Err("PQ preconfirmation fee cap exceeds BPS range".to_string());
        }
        if self.certificate_ttl_blocks == 0 {
            return Err("PQ preconfirmation certificate TTL must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_pending_intents": self.max_pending_intents,
            "max_certificate_intents": self.max_certificate_intents,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "certificate_ttl_blocks": self.certificate_ttl_blocks,
            "require_fee_sponsor": self.require_fee_sponsor,
            "require_replay_fence": self.require_replay_fence,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub intent_counter: u64,
    pub vote_counter: u64,
    pub certificate_counter: u64,
    pub settlement_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_counter": self.intent_counter,
            "vote_counter": self.vote_counter,
            "certificate_counter": self.certificate_counter,
            "settlement_counter": self.settlement_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPreconfirmationIntentRequest {
    pub lane: PreconfirmationLane,
    pub account_commitment: String,
    pub encrypted_payload_root: String,
    pub state_read_root: String,
    pub state_write_hint_root: String,
    pub fee_plan_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub priority_weight: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitPreconfirmationIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
        required("account_commitment", &self.account_commitment)?;
        required("encrypted_payload_root", &self.encrypted_payload_root)?;
        required("state_read_root", &self.state_read_root)?;
        required("state_write_hint_root", &self.state_write_hint_root)?;
        required("fee_plan_root", &self.fee_plan_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("nullifier", &self.nullifier)?;
        if config.require_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        if config.require_replay_fence {
            required("replay_fence_root", &self.replay_fence_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("PQ preconfirmation fee exceeds configured low-fee cap".to_string());
        }
        if self.priority_weight == 0 {
            return Err("PQ preconfirmation priority weight must be positive".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("PQ preconfirmation intent expires before it can be included".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "account_commitment": self.account_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "state_read_root": self.state_read_root,
            "state_write_hint_root": self.state_write_hint_root,
            "fee_plan_root": self.fee_plan_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "priority_weight": self.priority_weight,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastQuorumVoteRequest {
    pub intent_id: String,
    pub committee_id: String,
    pub voter_commitment: String,
    pub verdict: VoteVerdict,
    pub vote_weight_bps: u64,
    pub availability_root: String,
    pub execution_simulation_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub vote_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub voted_at_height: u64,
}

impl CastQuorumVoteRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
        required("intent_id", &self.intent_id)?;
        required("committee_id", &self.committee_id)?;
        required("voter_commitment", &self.voter_commitment)?;
        required("availability_root", &self.availability_root)?;
        required("execution_simulation_root", &self.execution_simulation_root)?;
        required("pq_signature_root", &self.pq_signature_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("vote_nullifier", &self.vote_nullifier)?;
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.vote_weight_bps > PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_MAX_BPS {
            return Err("PQ preconfirmation vote weight exceeds BPS range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "committee_id": self.committee_id,
            "voter_commitment": self.voter_commitment,
            "verdict": self.verdict.as_str(),
            "vote_weight_bps": self.vote_weight_bps,
            "availability_root": self.availability_root,
            "execution_simulation_root": self.execution_simulation_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "vote_nullifier": self.vote_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "voted_at_height": self.voted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPreconfirmationCertificateRequest {
    pub lane: PreconfirmationLane,
    pub intent_ids: Vec<String>,
    pub builder_commitment: String,
    pub fast_runtime_block_root: String,
    pub aggregate_vote_root: String,
    pub aggregate_pq_signature_root: String,
    pub aggregate_privacy_proof_root: String,
    pub low_fee_rebate_root: String,
    pub recursive_proof_hint_root: String,
    pub min_approved_weight_bps: u64,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildPreconfirmationCertificateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
        if self.intent_ids.is_empty() || self.intent_ids.len() > config.max_certificate_intents {
            return Err(
                "PQ preconfirmation certificate intent count is outside policy".to_string(),
            );
        }
        required("builder_commitment", &self.builder_commitment)?;
        required("fast_runtime_block_root", &self.fast_runtime_block_root)?;
        required("aggregate_vote_root", &self.aggregate_vote_root)?;
        required(
            "aggregate_pq_signature_root",
            &self.aggregate_pq_signature_root,
        )?;
        required(
            "aggregate_privacy_proof_root",
            &self.aggregate_privacy_proof_root,
        )?;
        required("low_fee_rebate_root", &self.low_fee_rebate_root)?;
        required("recursive_proof_hint_root", &self.recursive_proof_hint_root)?;
        if self.min_approved_weight_bps < config.quorum_weight_bps {
            return Err("PQ preconfirmation certificate does not meet quorum floor".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("PQ preconfirmation certificate privacy set below floor".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("PQ preconfirmation certificate fee exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "intent_ids": self.intent_ids,
            "builder_commitment": self.builder_commitment,
            "fast_runtime_block_root": self.fast_runtime_block_root,
            "aggregate_vote_root": self.aggregate_vote_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "recursive_proof_hint_root": self.recursive_proof_hint_root,
            "min_approved_weight_bps": self.min_approved_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlePreconfirmationCertificateRequest {
    pub certificate_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub included_intent_root: String,
    pub failed_intent_root: String,
    pub fee_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettlePreconfirmationCertificateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
        required("certificate_id", &self.certificate_id)?;
        required("settlement_tx_root", &self.settlement_tx_root)?;
        required("settlement_proof_root", &self.settlement_proof_root)?;
        required("included_intent_root", &self.included_intent_root)?;
        required("failed_intent_root", &self.failed_intent_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("pq_settlement_root", &self.pq_settlement_root)?;
        required("state_root_after", &self.state_root_after)?;
        if self.settled_fee_bps > config.max_user_fee_bps {
            return Err("PQ preconfirmation settlement fee exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "included_intent_root": self.included_intent_root,
            "failed_intent_root": self.failed_intent_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationIntent {
    pub intent_id: String,
    pub lane: PreconfirmationLane,
    pub account_commitment: String,
    pub encrypted_payload_root: String,
    pub state_read_root: String,
    pub state_write_hint_root: String,
    pub fee_plan_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub priority_weight: u64,
    pub approved_weight_bps: u64,
    pub rejected_weight_bps: u64,
    pub status: IntentStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub vote_ids: Vec<String>,
}

impl PreconfirmationIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane": self.lane.as_str(),
            "account_commitment": self.account_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "state_read_root": self.state_read_root,
            "state_write_hint_root": self.state_write_hint_root,
            "fee_plan_root": self.fee_plan_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "priority_weight": self.priority_weight,
            "approved_weight_bps": self.approved_weight_bps,
            "rejected_weight_bps": self.rejected_weight_bps,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "vote_ids": self.vote_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumVote {
    pub vote_id: String,
    pub intent_id: String,
    pub committee_id: String,
    pub voter_commitment: String,
    pub verdict: VoteVerdict,
    pub vote_weight_bps: u64,
    pub availability_root: String,
    pub execution_simulation_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub vote_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub voted_at_height: u64,
}

impl QuorumVote {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "intent_id": self.intent_id,
            "committee_id": self.committee_id,
            "voter_commitment": self.voter_commitment,
            "verdict": self.verdict.as_str(),
            "vote_weight_bps": self.vote_weight_bps,
            "availability_root": self.availability_root,
            "execution_simulation_root": self.execution_simulation_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "vote_nullifier": self.vote_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "voted_at_height": self.voted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationCertificate {
    pub certificate_id: String,
    pub lane: PreconfirmationLane,
    pub intent_ids: Vec<String>,
    pub builder_commitment: String,
    pub fast_runtime_block_root: String,
    pub aggregate_vote_root: String,
    pub aggregate_pq_signature_root: String,
    pub aggregate_privacy_proof_root: String,
    pub low_fee_rebate_root: String,
    pub recursive_proof_hint_root: String,
    pub min_approved_weight_bps: u64,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub status: CertificateStatus,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl PreconfirmationCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "lane": self.lane.as_str(),
            "intent_ids": self.intent_ids,
            "builder_commitment": self.builder_commitment,
            "fast_runtime_block_root": self.fast_runtime_block_root,
            "aggregate_vote_root": self.aggregate_vote_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "recursive_proof_hint_root": self.recursive_proof_hint_root,
            "min_approved_weight_bps": self.min_approved_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationSettlementReceipt {
    pub receipt_id: String,
    pub certificate_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub included_intent_root: String,
    pub failed_intent_root: String,
    pub fee_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl PreconfirmationSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "certificate_id": self.certificate_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "included_intent_root": self.included_intent_root,
            "failed_intent_root": self.failed_intent_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub intent_root: String,
    pub vote_root: String,
    pub certificate_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_root": self.intent_root,
            "vote_root": self.vote_root,
            "certificate_root": self.certificate_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub chain_id: String,
    pub protocol_version: String,
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub intents: BTreeMap<String, PreconfirmationIntent>,
    pub votes: BTreeMap<String, QuorumVote>,
    pub certificates: BTreeMap<String, PreconfirmationCertificate>,
    pub receipts: BTreeMap<String, PreconfirmationSettlementReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqPreconfirmationQuorumRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        Ok(Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_DEVNET_HEIGHT,
            intents: BTreeMap::new(),
            votes: BTreeMap::new(),
            certificates: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn submit_intent(
        &mut self,
        request: SubmitPreconfirmationIntentRequest,
    ) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<PreconfirmationIntent> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.intents.len() >= self.config.max_pending_intents {
            return Err("PQ preconfirmation pending intent capacity exhausted".to_string());
        }
        self.insert_nullifier(&request.nullifier)?;
        self.counters.intent_counter = self.counters.intent_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let intent_id = intent_id(&request, self.counters.intent_counter);
        let intent = PreconfirmationIntent {
            intent_id: intent_id.clone(),
            lane: request.lane,
            account_commitment: request.account_commitment,
            encrypted_payload_root: request.encrypted_payload_root,
            state_read_root: request.state_read_root,
            state_write_hint_root: request.state_write_hint_root,
            fee_plan_root: request.fee_plan_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            replay_fence_root: request.replay_fence_root,
            nullifier: request.nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            priority_weight: request.priority_weight,
            approved_weight_bps: 0,
            rejected_weight_bps: 0,
            status: IntentStatus::Pending,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
            vote_ids: Vec::new(),
        };
        self.intents.insert(intent_id, intent.clone());
        Ok(intent)
    }

    pub fn cast_vote(
        &mut self,
        request: CastQuorumVoteRequest,
    ) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<QuorumVote> {
        self.config.validate()?;
        request.validate(&self.config)?;
        {
            let intent = self
                .intents
                .get(&request.intent_id)
                .ok_or_else(|| "PQ preconfirmation intent not found for vote".to_string())?;
            if !intent.status.certifiable() {
                return Err("PQ preconfirmation intent cannot receive votes".to_string());
            }
            if intent.expires_at_height <= request.voted_at_height {
                return Err("PQ preconfirmation intent expired before vote".to_string());
            }
        }
        self.insert_nullifier(&request.vote_nullifier)?;
        self.counters.vote_counter = self.counters.vote_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.voted_at_height);
        let vote_id = vote_id(&request, self.counters.vote_counter);
        let vote = QuorumVote {
            vote_id: vote_id.clone(),
            intent_id: request.intent_id.clone(),
            committee_id: request.committee_id,
            voter_commitment: request.voter_commitment,
            verdict: request.verdict,
            vote_weight_bps: request.vote_weight_bps,
            availability_root: request.availability_root,
            execution_simulation_root: request.execution_simulation_root,
            pq_signature_root: request.pq_signature_root,
            privacy_proof_root: request.privacy_proof_root,
            vote_nullifier: request.vote_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            voted_at_height: request.voted_at_height,
        };
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            match request.verdict {
                VoteVerdict::Approve => {
                    intent.approved_weight_bps = intent
                        .approved_weight_bps
                        .saturating_add(request.vote_weight_bps)
                        .min(PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_MAX_BPS);
                }
                VoteVerdict::Reject => {
                    intent.rejected_weight_bps = intent
                        .rejected_weight_bps
                        .saturating_add(request.vote_weight_bps)
                        .min(PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_MAX_BPS);
                }
                VoteVerdict::Abstain => {}
            }
            intent.vote_ids.push(vote_id.clone());
            intent.status = if intent.rejected_weight_bps >= self.config.quorum_weight_bps {
                IntentStatus::Rejected
            } else {
                IntentStatus::Voted
            };
        }
        self.votes.insert(vote_id, vote.clone());
        Ok(vote)
    }

    pub fn build_certificate(
        &mut self,
        request: BuildPreconfirmationCertificateRequest,
    ) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<PreconfirmationCertificate> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let mut seen = BTreeSet::new();
        for intent_id in &request.intent_ids {
            if !seen.insert(intent_id.clone()) {
                return Err("PQ preconfirmation certificate has duplicate intent".to_string());
            }
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("PQ preconfirmation intent {intent_id} missing"))?;
            if intent.lane != request.lane {
                return Err("PQ preconfirmation certificate mixed lanes".to_string());
            }
            if !intent.status.certifiable() {
                return Err("PQ preconfirmation intent is not certifiable".to_string());
            }
            if intent.approved_weight_bps < request.min_approved_weight_bps {
                return Err("PQ preconfirmation intent lacks required vote weight".to_string());
            }
            if intent.expires_at_height <= request.built_at_height {
                return Err("PQ preconfirmation intent expired before certificate".to_string());
            }
        }
        self.counters.certificate_counter = self.counters.certificate_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let certificate_id = certificate_id(&request, self.counters.certificate_counter);
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Certified;
            }
        }
        let certificate = PreconfirmationCertificate {
            certificate_id: certificate_id.clone(),
            lane: request.lane,
            intent_ids: request.intent_ids,
            builder_commitment: request.builder_commitment,
            fast_runtime_block_root: request.fast_runtime_block_root,
            aggregate_vote_root: request.aggregate_vote_root,
            aggregate_pq_signature_root: request.aggregate_pq_signature_root,
            aggregate_privacy_proof_root: request.aggregate_privacy_proof_root,
            low_fee_rebate_root: request.low_fee_rebate_root,
            recursive_proof_hint_root: request.recursive_proof_hint_root,
            min_approved_weight_bps: request.min_approved_weight_bps,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            status: CertificateStatus::SettlementReady,
            built_at_height: request.built_at_height,
            expires_at_height: request
                .built_at_height
                .saturating_add(self.config.certificate_ttl_blocks),
        };
        self.certificates
            .insert(certificate_id, certificate.clone());
        Ok(certificate)
    }

    pub fn settle_certificate(
        &mut self,
        request: SettlePreconfirmationCertificateRequest,
    ) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<PreconfirmationSettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let certificate = self
            .certificates
            .get(&request.certificate_id)
            .ok_or_else(|| "PQ preconfirmation certificate not found".to_string())?
            .clone();
        if !certificate.status.can_settle() {
            return Err("PQ preconfirmation certificate cannot settle".to_string());
        }
        if request.settled_at_height >= certificate.expires_at_height {
            return Err("PQ preconfirmation certificate expired before settlement".to_string());
        }
        self.counters.settlement_counter = self.counters.settlement_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, self.counters.settlement_counter);
        for intent_id in &certificate.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
            }
        }
        if let Some(stored) = self.certificates.get_mut(&request.certificate_id) {
            stored.status = CertificateStatus::Settled;
        }
        let receipt = PreconfirmationSettlementReceipt {
            receipt_id: receipt_id.clone(),
            certificate_id: request.certificate_id,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            included_intent_root: request.included_intent_root,
            failed_intent_root: request.failed_intent_root,
            fee_receipt_root: request.fee_receipt_root,
            pq_settlement_root: request.pq_settlement_root,
            state_root_after: request.state_root_after,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let intent_root = merkle_root(
            "PRIVATE-L2-PQ-PRECONFIRMATION-INTENTS",
            &self
                .intents
                .values()
                .map(PreconfirmationIntent::public_record)
                .collect::<Vec<_>>(),
        );
        let vote_root = merkle_root(
            "PRIVATE-L2-PQ-PRECONFIRMATION-VOTES",
            &self
                .votes
                .values()
                .map(QuorumVote::public_record)
                .collect::<Vec<_>>(),
        );
        let certificate_root = merkle_root(
            "PRIVATE-L2-PQ-PRECONFIRMATION-CERTIFICATES",
            &self
                .certificates
                .values()
                .map(PreconfirmationCertificate::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PRIVATE-L2-PQ-PRECONFIRMATION-RECEIPTS",
            &self
                .receipts
                .values()
                .map(PreconfirmationSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-PRECONFIRMATION-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-PRECONFIRMATION-STATE",
            &json!({
                "chain_id": self.chain_id,
                "protocol_version": self.protocol_version,
                "current_height": self.current_height,
                "intent_root": intent_root,
                "vote_root": vote_root,
                "certificate_root": certificate_root,
                "receipt_root": receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            intent_root,
            vote_root,
            certificate_root,
            receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_PQ_SUITE,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "intent_ids": self.intents.keys().cloned().collect::<Vec<_>>(),
            "vote_ids": self.votes.keys().cloned().collect::<Vec<_>>(),
            "certificate_ids": self.certificates.keys().cloned().collect::<Vec<_>>(),
            "receipt_ids": self.receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn insert_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
        if !self.consumed_nullifiers.insert(nullifier.to_string()) {
            return Err("PQ preconfirmation nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn intent_id(request: &SubmitPreconfirmationIntentRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-PRECONFIRMATION-INTENT-ID",
        &json!({
            "counter": counter,
            "lane": request.lane.as_str(),
            "account_commitment": request.account_commitment,
            "encrypted_payload_root": request.encrypted_payload_root,
            "nullifier": request.nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn vote_id(request: &CastQuorumVoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-PRECONFIRMATION-VOTE-ID",
        &json!({
            "counter": counter,
            "intent_id": request.intent_id,
            "committee_id": request.committee_id,
            "verdict": request.verdict.as_str(),
            "vote_nullifier": request.vote_nullifier,
            "voted_at_height": request.voted_at_height,
        }),
    )
}

pub fn certificate_id(request: &BuildPreconfirmationCertificateRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-PRECONFIRMATION-CERTIFICATE-ID",
        &json!({
            "counter": counter,
            "lane": request.lane.as_str(),
            "intent_ids": request.intent_ids,
            "aggregate_vote_root": request.aggregate_vote_root,
            "fast_runtime_block_root": request.fast_runtime_block_root,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn settlement_receipt_id(
    request: &SettlePreconfirmationCertificateRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-PRECONFIRMATION-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "certificate_id": request.certificate_id,
            "settlement_tx_root": request.settlement_tx_root,
            "state_root_after": request.state_root_after,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_PRECONFIRMATION_QUORUM_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn required(field: &str, value: &str) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("PQ preconfirmation field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2PqPreconfirmationQuorumRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("PQ preconfirmation privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("PQ preconfirmation PQ security bits below minimum".to_string());
    }
    Ok(())
}
