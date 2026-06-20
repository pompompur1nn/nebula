use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqCircuitBreakerGovernanceResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-circuit-breaker-governance-v1";
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEVNET_HEIGHT: u64 = 192_000;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MAX_OPEN_PROPOSALS: usize = 16_384;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MAX_OPEN_ACTIONS: usize = 32_768;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 32_768;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_QUORUM_WEIGHT: u64 = 6_700;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 = 2;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_UPGRADE_DELAY_BLOCKS: u64 = 16;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MAX_FEE_BPS: u64 = 20;
pub const PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitDomain {
    PqAuthorization,
    PrivateContracts,
    ConfidentialTokens,
    PrivateDefi,
    MoneroExit,
    ProofDataAvailability,
    Settlement,
    FastRuntime,
}

impl CircuitDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqAuthorization => "pq_authorization",
            Self::PrivateContracts => "private_contracts",
            Self::ConfidentialTokens => "confidential_tokens",
            Self::PrivateDefi => "private_defi",
            Self::MoneroExit => "monero_exit",
            Self::ProofDataAvailability => "proof_data_availability",
            Self::Settlement => "settlement",
            Self::FastRuntime => "fast_runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    VerifierKeyRotation,
    PqSchemeMigration,
    CircuitParameterUpgrade,
    EmergencyPatch,
    FeePolicyChange,
    PrivacySetIncrease,
}

impl ProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifierKeyRotation => "verifier_key_rotation",
            Self::PqSchemeMigration => "pq_scheme_migration",
            Self::CircuitParameterUpgrade => "circuit_parameter_upgrade",
            Self::EmergencyPatch => "emergency_patch",
            Self::FeePolicyChange => "fee_policy_change",
            Self::PrivacySetIncrease => "privacy_set_increase",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Open,
    Attested,
    QuorumReady,
    Settled,
    Rejected,
    Expired,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::QuorumReady => "quorum_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Open | Self::Attested)
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::QuorumReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approve,
    Reject,
    Abstain,
}

impl AttestationVerdict {
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
pub enum CircuitBreakerActionKind {
    PauseDomain,
    ResumeDomain,
    FreezeVerifierKey,
    ThrottleLane,
    ForceProofDataAvailability,
    RequireFallbackCircuit,
}

impl CircuitBreakerActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PauseDomain => "pause_domain",
            Self::ResumeDomain => "resume_domain",
            Self::FreezeVerifierKey => "freeze_verifier_key",
            Self::ThrottleLane => "throttle_lane",
            Self::ForceProofDataAvailability => "force_proof_data_availability",
            Self::RequireFallbackCircuit => "require_fallback_circuit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerStatus {
    Scheduled,
    Executed,
    Cancelled,
    Expired,
}

impl CircuitBreakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn can_execute(self) -> bool {
        matches!(self, Self::Scheduled)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub max_open_proposals: usize,
    pub max_open_actions: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub emergency_delay_blocks: u64,
    pub upgrade_delay_blocks: u64,
    pub max_fee_bps: u64,
    pub require_low_fee_sponsor: bool,
    pub require_timelock: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_open_proposals: PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MAX_OPEN_PROPOSALS,
            max_open_actions: PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MAX_OPEN_ACTIONS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_weight_bps: PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_QUORUM_WEIGHT,
            emergency_delay_blocks:
                PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_EMERGENCY_DELAY_BLOCKS,
            upgrade_delay_blocks:
                PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_UPGRADE_DELAY_BLOCKS,
            max_fee_bps: PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEFAULT_MAX_FEE_BPS,
            require_low_fee_sponsor: true,
            require_timelock: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
        if self.max_open_proposals == 0 {
            return Err("PQ circuit governance max_open_proposals must be positive".to_string());
        }
        if self.max_open_actions == 0 {
            return Err("PQ circuit governance max_open_actions must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("PQ circuit governance min privacy set must be positive".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("PQ circuit governance target privacy set below minimum".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("PQ circuit governance security floor too low".to_string());
        }
        if self.quorum_weight_bps == 0
            || self.quorum_weight_bps > PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_MAX_BPS
        {
            return Err("PQ circuit governance quorum weight is invalid".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_MAX_BPS {
            return Err("PQ circuit governance max fee exceeds BPS range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_open_proposals": self.max_open_proposals,
            "max_open_actions": self.max_open_actions,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "upgrade_delay_blocks": self.upgrade_delay_blocks,
            "max_fee_bps": self.max_fee_bps,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_timelock": self.require_timelock,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub proposal_counter: u64,
    pub attestation_counter: u64,
    pub circuit_breaker_counter: u64,
    pub execution_counter: u64,
    pub settlement_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_counter": self.proposal_counter,
            "attestation_counter": self.attestation_counter,
            "circuit_breaker_counter": self.circuit_breaker_counter,
            "execution_counter": self.execution_counter,
            "settlement_counter": self.settlement_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitUpgradeProposalRequest {
    pub proposal_kind: ProposalKind,
    pub circuit_domain: CircuitDomain,
    pub proposer_commitment: String,
    pub current_verifier_key_root: String,
    pub proposed_verifier_key_root: String,
    pub circuit_diff_root: String,
    pub migration_plan_root: String,
    pub compatibility_proof_root: String,
    pub rollback_plan_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub timelock_root: String,
    pub proposal_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub earliest_activation_height: u64,
    pub expires_at_height: u64,
}

impl SubmitUpgradeProposalRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
        required("proposer_commitment", &self.proposer_commitment)?;
        required("current_verifier_key_root", &self.current_verifier_key_root)?;
        required(
            "proposed_verifier_key_root",
            &self.proposed_verifier_key_root,
        )?;
        if self.current_verifier_key_root == self.proposed_verifier_key_root {
            return Err("PQ circuit proposal must change verifier key root".to_string());
        }
        required("circuit_diff_root", &self.circuit_diff_root)?;
        required("migration_plan_root", &self.migration_plan_root)?;
        required("compatibility_proof_root", &self.compatibility_proof_root)?;
        required("rollback_plan_root", &self.rollback_plan_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("proposal_nullifier", &self.proposal_nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        if config.require_timelock {
            required("timelock_root", &self.timelock_root)?;
            let min_activation = self
                .submitted_at_height
                .saturating_add(config.upgrade_delay_blocks);
            if self.earliest_activation_height < min_activation {
                return Err("PQ circuit proposal activation is before timelock".to_string());
            }
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("PQ circuit proposal fee exceeds configured max".to_string());
        }
        if self.expires_at_height <= self.earliest_activation_height {
            return Err("PQ circuit proposal expires before activation window".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proposal_kind": self.proposal_kind.as_str(),
            "circuit_domain": self.circuit_domain.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "current_verifier_key_root": self.current_verifier_key_root,
            "proposed_verifier_key_root": self.proposed_verifier_key_root,
            "circuit_diff_root": self.circuit_diff_root,
            "migration_plan_root": self.migration_plan_root,
            "compatibility_proof_root": self.compatibility_proof_root,
            "rollback_plan_root": self.rollback_plan_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "timelock_root": self.timelock_root,
            "proposal_nullifier": self.proposal_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "earliest_activation_height": self.earliest_activation_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestUpgradeProposalRequest {
    pub proposal_id: String,
    pub committee_id: String,
    pub attestor_commitment: String,
    pub verdict: AttestationVerdict,
    pub attestation_weight_bps: u64,
    pub safety_report_root: String,
    pub compatibility_report_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl AttestUpgradeProposalRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
        required("proposal_id", &self.proposal_id)?;
        required("committee_id", &self.committee_id)?;
        required("attestor_commitment", &self.attestor_commitment)?;
        required("safety_report_root", &self.safety_report_root)?;
        required("compatibility_report_root", &self.compatibility_report_root)?;
        required("pq_signature_root", &self.pq_signature_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("attestation_nullifier", &self.attestation_nullifier)?;
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.attestation_weight_bps > PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_MAX_BPS {
            return Err("PQ circuit attestation weight exceeds BPS range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "committee_id": self.committee_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "attestation_weight_bps": self.attestation_weight_bps,
            "safety_report_root": self.safety_report_root,
            "compatibility_report_root": self.compatibility_report_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleCircuitBreakerRequest {
    pub circuit_domain: CircuitDomain,
    pub action_kind: CircuitBreakerActionKind,
    pub proposal_id: Option<String>,
    pub watcher_commitment: String,
    pub evidence_root: String,
    pub affected_state_root: String,
    pub fallback_circuit_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub action_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub scheduled_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
}

impl ScheduleCircuitBreakerRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
        required("watcher_commitment", &self.watcher_commitment)?;
        required("evidence_root", &self.evidence_root)?;
        required("affected_state_root", &self.affected_state_root)?;
        required("fallback_circuit_root", &self.fallback_circuit_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("action_nullifier", &self.action_nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("PQ circuit breaker fee exceeds configured max".to_string());
        }
        let min_execute = self
            .scheduled_at_height
            .saturating_add(config.emergency_delay_blocks);
        if self.executable_at_height < min_execute {
            return Err("PQ circuit breaker execution is before delay".to_string());
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err("PQ circuit breaker expires before execution window".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "circuit_domain": self.circuit_domain.as_str(),
            "action_kind": self.action_kind.as_str(),
            "proposal_id": self.proposal_id,
            "watcher_commitment": self.watcher_commitment,
            "evidence_root": self.evidence_root,
            "affected_state_root": self.affected_state_root,
            "fallback_circuit_root": self.fallback_circuit_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "action_nullifier": self.action_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "scheduled_at_height": self.scheduled_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteCircuitBreakerRequest {
    pub action_id: String,
    pub execution_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub affected_component_root: String,
    pub pq_execution_root: String,
    pub fee_receipt_root: String,
    pub execution_nullifier: String,
    pub executed_at_height: u64,
}

impl ExecuteCircuitBreakerRequest {
    pub fn validate(&self) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
        required("action_id", &self.action_id)?;
        required("execution_proof_root", &self.execution_proof_root)?;
        required("state_root_before", &self.state_root_before)?;
        required("state_root_after", &self.state_root_after)?;
        required("affected_component_root", &self.affected_component_root)?;
        required("pq_execution_root", &self.pq_execution_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("execution_nullifier", &self.execution_nullifier)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "execution_proof_root": self.execution_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "affected_component_root": self.affected_component_root,
            "pq_execution_root": self.pq_execution_root,
            "fee_receipt_root": self.fee_receipt_root,
            "execution_nullifier": self.execution_nullifier,
            "executed_at_height": self.executed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleUpgradeProposalRequest {
    pub proposal_id: String,
    pub settlement_proof_root: String,
    pub verifier_registry_root_before: String,
    pub verifier_registry_root_after: String,
    pub activation_receipt_root: String,
    pub rollback_receipt_root: String,
    pub pq_settlement_root: String,
    pub fee_receipt_root: String,
    pub settlement_nullifier: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleUpgradeProposalRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
        required("proposal_id", &self.proposal_id)?;
        required("settlement_proof_root", &self.settlement_proof_root)?;
        required(
            "verifier_registry_root_before",
            &self.verifier_registry_root_before,
        )?;
        required(
            "verifier_registry_root_after",
            &self.verifier_registry_root_after,
        )?;
        if self.verifier_registry_root_before == self.verifier_registry_root_after {
            return Err("PQ circuit settlement must change verifier registry root".to_string());
        }
        required("activation_receipt_root", &self.activation_receipt_root)?;
        required("rollback_receipt_root", &self.rollback_receipt_root)?;
        required("pq_settlement_root", &self.pq_settlement_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("settlement_nullifier", &self.settlement_nullifier)?;
        if self.settled_fee_bps > config.max_fee_bps {
            return Err("PQ circuit settlement fee exceeds configured max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "settlement_proof_root": self.settlement_proof_root,
            "verifier_registry_root_before": self.verifier_registry_root_before,
            "verifier_registry_root_after": self.verifier_registry_root_after,
            "activation_receipt_root": self.activation_receipt_root,
            "rollback_receipt_root": self.rollback_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "fee_receipt_root": self.fee_receipt_root,
            "settlement_nullifier": self.settlement_nullifier,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeProposal {
    pub proposal_id: String,
    pub proposal_kind: ProposalKind,
    pub circuit_domain: CircuitDomain,
    pub proposer_commitment: String,
    pub current_verifier_key_root: String,
    pub proposed_verifier_key_root: String,
    pub circuit_diff_root: String,
    pub migration_plan_root: String,
    pub compatibility_proof_root: String,
    pub rollback_plan_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub timelock_root: String,
    pub proposal_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub earliest_activation_height: u64,
    pub expires_at_height: u64,
    pub approved_weight_bps: u64,
    pub rejected_weight_bps: u64,
    pub status: ProposalStatus,
    pub attestation_ids: Vec<String>,
}

impl UpgradeProposal {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "proposal_kind": self.proposal_kind.as_str(),
            "circuit_domain": self.circuit_domain.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "current_verifier_key_root": self.current_verifier_key_root,
            "proposed_verifier_key_root": self.proposed_verifier_key_root,
            "circuit_diff_root": self.circuit_diff_root,
            "migration_plan_root": self.migration_plan_root,
            "compatibility_proof_root": self.compatibility_proof_root,
            "rollback_plan_root": self.rollback_plan_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "timelock_root": self.timelock_root,
            "proposal_nullifier": self.proposal_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "earliest_activation_height": self.earliest_activation_height,
            "expires_at_height": self.expires_at_height,
            "approved_weight_bps": self.approved_weight_bps,
            "rejected_weight_bps": self.rejected_weight_bps,
            "status": self.status.as_str(),
            "attestation_ids": self.attestation_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalAttestation {
    pub attestation_id: String,
    pub proposal_id: String,
    pub committee_id: String,
    pub attestor_commitment: String,
    pub verdict: AttestationVerdict,
    pub attestation_weight_bps: u64,
    pub safety_report_root: String,
    pub compatibility_report_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl ProposalAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "proposal_id": self.proposal_id,
            "committee_id": self.committee_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "attestation_weight_bps": self.attestation_weight_bps,
            "safety_report_root": self.safety_report_root,
            "compatibility_report_root": self.compatibility_report_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerAction {
    pub action_id: String,
    pub circuit_domain: CircuitDomain,
    pub action_kind: CircuitBreakerActionKind,
    pub proposal_id: Option<String>,
    pub watcher_commitment: String,
    pub evidence_root: String,
    pub affected_state_root: String,
    pub fallback_circuit_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub action_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub scheduled_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub status: CircuitBreakerStatus,
}

impl CircuitBreakerAction {
    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "circuit_domain": self.circuit_domain.as_str(),
            "action_kind": self.action_kind.as_str(),
            "proposal_id": self.proposal_id,
            "watcher_commitment": self.watcher_commitment,
            "evidence_root": self.evidence_root,
            "affected_state_root": self.affected_state_root,
            "fallback_circuit_root": self.fallback_circuit_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "action_nullifier": self.action_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "scheduled_at_height": self.scheduled_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerExecutionReceipt {
    pub receipt_id: String,
    pub action_id: String,
    pub execution_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub affected_component_root: String,
    pub pq_execution_root: String,
    pub fee_receipt_root: String,
    pub execution_nullifier: String,
    pub executed_at_height: u64,
}

impl CircuitBreakerExecutionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "execution_proof_root": self.execution_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "affected_component_root": self.affected_component_root,
            "pq_execution_root": self.pq_execution_root,
            "fee_receipt_root": self.fee_receipt_root,
            "execution_nullifier": self.execution_nullifier,
            "executed_at_height": self.executed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeSettlementReceipt {
    pub receipt_id: String,
    pub proposal_id: String,
    pub settlement_proof_root: String,
    pub verifier_registry_root_before: String,
    pub verifier_registry_root_after: String,
    pub activation_receipt_root: String,
    pub rollback_receipt_root: String,
    pub pq_settlement_root: String,
    pub fee_receipt_root: String,
    pub settlement_nullifier: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl UpgradeSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "proposal_id": self.proposal_id,
            "settlement_proof_root": self.settlement_proof_root,
            "verifier_registry_root_before": self.verifier_registry_root_before,
            "verifier_registry_root_after": self.verifier_registry_root_after,
            "activation_receipt_root": self.activation_receipt_root,
            "rollback_receipt_root": self.rollback_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "fee_receipt_root": self.fee_receipt_root,
            "settlement_nullifier": self.settlement_nullifier,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub proposal_root: String,
    pub attestation_root: String,
    pub action_root: String,
    pub execution_receipt_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_root": self.proposal_root,
            "attestation_root": self.attestation_root,
            "action_root": self.action_root,
            "execution_receipt_root": self.execution_receipt_root,
            "settlement_receipt_root": self.settlement_receipt_root,
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
    pub verifier_registry_root: String,
    pub proposals: BTreeMap<String, UpgradeProposal>,
    pub attestations: BTreeMap<String, ProposalAttestation>,
    pub actions: BTreeMap<String, CircuitBreakerAction>,
    pub execution_receipts: BTreeMap<String, CircuitBreakerExecutionReceipt>,
    pub settlement_receipts: BTreeMap<String, UpgradeSettlementReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqCircuitBreakerGovernanceResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let verifier_registry_root = root_from_record(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-DEVNET-VERIFIER-REGISTRY",
            &json!({
                "chain_id": CHAIN_ID,
                "height": PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEVNET_HEIGHT,
                "domains": [
                    CircuitDomain::PqAuthorization.as_str(),
                    CircuitDomain::PrivateContracts.as_str(),
                    CircuitDomain::ConfidentialTokens.as_str(),
                    CircuitDomain::PrivateDefi.as_str(),
                    CircuitDomain::MoneroExit.as_str(),
                ],
            }),
        );
        Ok(Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_PROTOCOL_VERSION.to_string(),
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_DEVNET_HEIGHT,
            verifier_registry_root,
            proposals: BTreeMap::new(),
            attestations: BTreeMap::new(),
            actions: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn submit_upgrade_proposal(
        &mut self,
        request: SubmitUpgradeProposalRequest,
    ) -> PrivateL2PqCircuitBreakerGovernanceResult<UpgradeProposal> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.open_proposal_count() >= self.config.max_open_proposals {
            return Err("PQ circuit governance open proposal capacity exhausted".to_string());
        }
        self.insert_nullifier(&request.proposal_nullifier)?;
        self.counters.proposal_counter = self.counters.proposal_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let proposal_id = proposal_id(&request, self.counters.proposal_counter);
        let proposal = UpgradeProposal {
            proposal_id: proposal_id.clone(),
            proposal_kind: request.proposal_kind,
            circuit_domain: request.circuit_domain,
            proposer_commitment: request.proposer_commitment,
            current_verifier_key_root: request.current_verifier_key_root,
            proposed_verifier_key_root: request.proposed_verifier_key_root,
            circuit_diff_root: request.circuit_diff_root,
            migration_plan_root: request.migration_plan_root,
            compatibility_proof_root: request.compatibility_proof_root,
            rollback_plan_root: request.rollback_plan_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            timelock_root: request.timelock_root,
            proposal_nullifier: request.proposal_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            submitted_at_height: request.submitted_at_height,
            earliest_activation_height: request.earliest_activation_height,
            expires_at_height: request.expires_at_height,
            approved_weight_bps: 0,
            rejected_weight_bps: 0,
            status: ProposalStatus::Open,
            attestation_ids: Vec::new(),
        };
        self.proposals.insert(proposal_id, proposal.clone());
        Ok(proposal)
    }

    pub fn attest_upgrade_proposal(
        &mut self,
        request: AttestUpgradeProposalRequest,
    ) -> PrivateL2PqCircuitBreakerGovernanceResult<ProposalAttestation> {
        self.config.validate()?;
        request.validate(&self.config)?;
        {
            let proposal = self
                .proposals
                .get(&request.proposal_id)
                .ok_or_else(|| "PQ circuit proposal not found for attestation".to_string())?;
            if !proposal.status.can_attest() {
                return Err(
                    "PQ circuit proposal cannot be attested from current status".to_string()
                );
            }
            if proposal.expires_at_height <= request.attested_at_height {
                return Err("PQ circuit proposal expired before attestation".to_string());
            }
        }
        self.insert_nullifier(&request.attestation_nullifier)?;
        self.counters.attestation_counter = self.counters.attestation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let attestation_id = attestation_id(&request, self.counters.attestation_counter);
        let attestation = ProposalAttestation {
            attestation_id: attestation_id.clone(),
            proposal_id: request.proposal_id.clone(),
            committee_id: request.committee_id,
            attestor_commitment: request.attestor_commitment,
            verdict: request.verdict,
            attestation_weight_bps: request.attestation_weight_bps,
            safety_report_root: request.safety_report_root,
            compatibility_report_root: request.compatibility_report_root,
            pq_signature_root: request.pq_signature_root,
            privacy_proof_root: request.privacy_proof_root,
            attestation_nullifier: request.attestation_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            match request.verdict {
                AttestationVerdict::Approve => {
                    proposal.approved_weight_bps = proposal
                        .approved_weight_bps
                        .saturating_add(request.attestation_weight_bps)
                        .min(PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_MAX_BPS);
                }
                AttestationVerdict::Reject => {
                    proposal.rejected_weight_bps = proposal
                        .rejected_weight_bps
                        .saturating_add(request.attestation_weight_bps)
                        .min(PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_MAX_BPS);
                }
                AttestationVerdict::Abstain => {}
            }
            proposal.attestation_ids.push(attestation_id.clone());
            proposal.status = if proposal.approved_weight_bps >= self.config.quorum_weight_bps {
                ProposalStatus::QuorumReady
            } else if proposal.rejected_weight_bps >= self.config.quorum_weight_bps {
                ProposalStatus::Rejected
            } else {
                ProposalStatus::Attested
            };
        }
        self.attestations
            .insert(attestation_id, attestation.clone());
        Ok(attestation)
    }

    pub fn schedule_circuit_breaker(
        &mut self,
        request: ScheduleCircuitBreakerRequest,
    ) -> PrivateL2PqCircuitBreakerGovernanceResult<CircuitBreakerAction> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.open_action_count() >= self.config.max_open_actions {
            return Err("PQ circuit breaker open action capacity exhausted".to_string());
        }
        if let Some(proposal_id) = &request.proposal_id {
            let proposal = self
                .proposals
                .get(proposal_id)
                .ok_or_else(|| "PQ circuit breaker linked proposal not found".to_string())?;
            if proposal.circuit_domain != request.circuit_domain {
                return Err("PQ circuit breaker proposal domain mismatch".to_string());
            }
        }
        self.insert_nullifier(&request.action_nullifier)?;
        self.counters.circuit_breaker_counter =
            self.counters.circuit_breaker_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.scheduled_at_height);
        let action_id = action_id(&request, self.counters.circuit_breaker_counter);
        let action = CircuitBreakerAction {
            action_id: action_id.clone(),
            circuit_domain: request.circuit_domain,
            action_kind: request.action_kind,
            proposal_id: request.proposal_id,
            watcher_commitment: request.watcher_commitment,
            evidence_root: request.evidence_root,
            affected_state_root: request.affected_state_root,
            fallback_circuit_root: request.fallback_circuit_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            action_nullifier: request.action_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            scheduled_at_height: request.scheduled_at_height,
            executable_at_height: request.executable_at_height,
            expires_at_height: request.expires_at_height,
            status: CircuitBreakerStatus::Scheduled,
        };
        self.actions.insert(action_id, action.clone());
        Ok(action)
    }

    pub fn execute_circuit_breaker(
        &mut self,
        request: ExecuteCircuitBreakerRequest,
    ) -> PrivateL2PqCircuitBreakerGovernanceResult<CircuitBreakerExecutionReceipt> {
        request.validate()?;
        {
            let action = self
                .actions
                .get(&request.action_id)
                .ok_or_else(|| "PQ circuit breaker action not found".to_string())?;
            if !action.status.can_execute() {
                return Err("PQ circuit breaker action cannot execute from status".to_string());
            }
            if request.executed_at_height < action.executable_at_height {
                return Err("PQ circuit breaker action executed before ready height".to_string());
            }
            if request.executed_at_height >= action.expires_at_height {
                return Err("PQ circuit breaker action expired before execution".to_string());
            }
        }
        self.insert_nullifier(&request.execution_nullifier)?;
        self.counters.execution_counter = self.counters.execution_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.executed_at_height);
        let receipt_id = execution_receipt_id(&request, self.counters.execution_counter);
        if let Some(action) = self.actions.get_mut(&request.action_id) {
            action.status = CircuitBreakerStatus::Executed;
        }
        let receipt = CircuitBreakerExecutionReceipt {
            receipt_id: receipt_id.clone(),
            action_id: request.action_id,
            execution_proof_root: request.execution_proof_root,
            state_root_before: request.state_root_before,
            state_root_after: request.state_root_after,
            affected_component_root: request.affected_component_root,
            pq_execution_root: request.pq_execution_root,
            fee_receipt_root: request.fee_receipt_root,
            execution_nullifier: request.execution_nullifier,
            executed_at_height: request.executed_at_height,
        };
        self.execution_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn settle_upgrade_proposal(
        &mut self,
        request: SettleUpgradeProposalRequest,
    ) -> PrivateL2PqCircuitBreakerGovernanceResult<UpgradeSettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        {
            let proposal = self
                .proposals
                .get(&request.proposal_id)
                .ok_or_else(|| "PQ circuit proposal not found for settlement".to_string())?;
            if !proposal.status.can_settle() {
                return Err("PQ circuit proposal cannot settle from current status".to_string());
            }
            if request.settled_at_height < proposal.earliest_activation_height {
                return Err("PQ circuit proposal settled before activation height".to_string());
            }
            if request.settled_at_height >= proposal.expires_at_height {
                return Err("PQ circuit proposal expired before settlement".to_string());
            }
        }
        self.insert_nullifier(&request.settlement_nullifier)?;
        self.counters.settlement_counter = self.counters.settlement_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, self.counters.settlement_counter);
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            proposal.status = ProposalStatus::Settled;
        }
        self.verifier_registry_root = request.verifier_registry_root_after.clone();
        let receipt = UpgradeSettlementReceipt {
            receipt_id: receipt_id.clone(),
            proposal_id: request.proposal_id,
            settlement_proof_root: request.settlement_proof_root,
            verifier_registry_root_before: request.verifier_registry_root_before,
            verifier_registry_root_after: request.verifier_registry_root_after,
            activation_receipt_root: request.activation_receipt_root,
            rollback_receipt_root: request.rollback_receipt_root,
            pq_settlement_root: request.pq_settlement_root,
            fee_receipt_root: request.fee_receipt_root,
            settlement_nullifier: request.settlement_nullifier,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        self.settlement_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let proposal_root = merkle_root(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-PROPOSALS",
            &self
                .proposals
                .values()
                .map(UpgradeProposal::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = merkle_root(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-ATTESTATIONS",
            &self
                .attestations
                .values()
                .map(ProposalAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let action_root = merkle_root(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-ACTIONS",
            &self
                .actions
                .values()
                .map(CircuitBreakerAction::public_record)
                .collect::<Vec<_>>(),
        );
        let execution_receipt_root = merkle_root(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-EXECUTION-RECEIPTS",
            &self
                .execution_receipts
                .values()
                .map(CircuitBreakerExecutionReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = merkle_root(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-SETTLEMENT-RECEIPTS",
            &self
                .settlement_receipts
                .values()
                .map(UpgradeSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-STATE",
            &json!({
                "chain_id": self.chain_id,
                "protocol_version": self.protocol_version,
                "current_height": self.current_height,
                "verifier_registry_root": self.verifier_registry_root,
                "proposal_root": proposal_root,
                "attestation_root": attestation_root,
                "action_root": action_root,
                "execution_receipt_root": execution_receipt_root,
                "settlement_receipt_root": settlement_receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            proposal_root,
            attestation_root,
            action_root,
            execution_receipt_root,
            settlement_receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_HASH_SUITE,
            "current_height": self.current_height,
            "verifier_registry_root": self.verifier_registry_root,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "proposal_ids": self.proposals.keys().cloned().collect::<Vec<_>>(),
            "attestation_ids": self.attestations.keys().cloned().collect::<Vec<_>>(),
            "action_ids": self.actions.keys().cloned().collect::<Vec<_>>(),
            "execution_receipt_ids": self.execution_receipts.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn insert_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
        if !self.consumed_nullifiers.insert(nullifier.to_string()) {
            return Err("PQ circuit governance nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }

    fn open_proposal_count(&self) -> usize {
        self.proposals
            .values()
            .filter(|proposal| {
                matches!(
                    proposal.status,
                    ProposalStatus::Open | ProposalStatus::Attested | ProposalStatus::QuorumReady
                )
            })
            .count()
    }

    fn open_action_count(&self) -> usize {
        self.actions
            .values()
            .filter(|action| action.status == CircuitBreakerStatus::Scheduled)
            .count()
    }
}

pub fn proposal_id(request: &SubmitUpgradeProposalRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-PROPOSAL-ID",
        &json!({
            "counter": counter,
            "proposal_kind": request.proposal_kind.as_str(),
            "circuit_domain": request.circuit_domain.as_str(),
            "current_verifier_key_root": request.current_verifier_key_root,
            "proposed_verifier_key_root": request.proposed_verifier_key_root,
            "proposal_nullifier": request.proposal_nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn attestation_id(request: &AttestUpgradeProposalRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "proposal_id": request.proposal_id,
            "committee_id": request.committee_id,
            "verdict": request.verdict.as_str(),
            "attestation_nullifier": request.attestation_nullifier,
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn action_id(request: &ScheduleCircuitBreakerRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-ACTION-ID",
        &json!({
            "counter": counter,
            "circuit_domain": request.circuit_domain.as_str(),
            "action_kind": request.action_kind.as_str(),
            "proposal_id": request.proposal_id,
            "evidence_root": request.evidence_root,
            "action_nullifier": request.action_nullifier,
            "scheduled_at_height": request.scheduled_at_height,
        }),
    )
}

pub fn execution_receipt_id(request: &ExecuteCircuitBreakerRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-EXECUTION-RECEIPT-ID",
        &json!({
            "counter": counter,
            "action_id": request.action_id,
            "state_root_after": request.state_root_after,
            "execution_nullifier": request.execution_nullifier,
            "executed_at_height": request.executed_at_height,
        }),
    )
}

pub fn settlement_receipt_id(request: &SettleUpgradeProposalRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CIRCUIT-BREAKER-GOVERNANCE-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "proposal_id": request.proposal_id,
            "verifier_registry_root_after": request.verifier_registry_root_after,
            "settlement_nullifier": request.settlement_nullifier,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_CIRCUIT_BREAKER_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn required(field: &str, value: &str) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
    if value.trim().is_empty() {
        return Err(format!("PQ circuit governance field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2PqCircuitBreakerGovernanceResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("PQ circuit governance privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("PQ circuit governance PQ security bits below minimum".to_string());
    }
    Ok(())
}
