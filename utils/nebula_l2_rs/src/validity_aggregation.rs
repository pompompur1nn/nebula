use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ValidityAggregationResult<T> = Result<T, String>;

pub const VALIDITY_AGGREGATION_PROTOCOL_VERSION: &str = "nebula-l2-validity-aggregation-v1";
pub const VALIDITY_AGGREGATION_SCHEMA_VERSION: u64 = 1;
pub const VALIDITY_AGGREGATION_HASH_SUITE: &str = "SHAKE256";
pub const VALIDITY_AGGREGATION_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const VALIDITY_AGGREGATION_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const VALIDITY_AGGREGATION_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const VALIDITY_AGGREGATION_STATE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-state-transition-validity-v1";
pub const VALIDITY_AGGREGATION_MONERO_BRIDGE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-monero-bridge-validity-v1";
pub const VALIDITY_AGGREGATION_CONTRACT_EXECUTION_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-contract-execution-validity-v1";
pub const VALIDITY_AGGREGATION_RECURSIVE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-recursive-validity-aggregation-v1";
pub const VALIDITY_AGGREGATION_COMPRESSION_SCHEME: &str =
    "shake256-recursive-proof-compression-receipt-v1";
pub const VALIDITY_AGGREGATION_DEFAULT_SECURITY_BITS: u64 = 128;
pub const VALIDITY_AGGREGATION_DEFAULT_RECURSION_DEPTH: u64 = 2;
pub const VALIDITY_AGGREGATION_DEFAULT_MAX_CHILD_PROOFS: u64 = 64;
pub const VALIDITY_AGGREGATION_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const VALIDITY_AGGREGATION_DEFAULT_LOW_FEE_EPOCH_BLOCKS: u64 = 720;
pub const VALIDITY_AGGREGATION_DEFAULT_LOW_FEE_PROOF_BUDGET_UNITS: u64 = 80_000;
pub const VALIDITY_AGGREGATION_MAX_BPS: u64 = 10_000;
pub const VALIDITY_AGGREGATION_MIN_COMPRESSION_RATIO_BPS: u64 = 1_000;

pub const VALIDITY_STATUS_PENDING: &str = "pending";
pub const VALIDITY_STATUS_ACTIVE: &str = "active";
pub const VALIDITY_STATUS_VERIFIED: &str = "verified";
pub const VALIDITY_STATUS_REJECTED: &str = "rejected";
pub const VALIDITY_STATUS_SEALED: &str = "sealed";
pub const VALIDITY_STATUS_COMPRESSED: &str = "compressed";
pub const VALIDITY_STATUS_CHALLENGED: &str = "challenged";
pub const VALIDITY_STATUS_RESOLVED: &str = "resolved";
pub const VALIDITY_STATUS_EXPIRED: &str = "expired";
pub const VALIDITY_STATUS_PAUSED: &str = "paused";
pub const VALIDITY_STATUS_SLASHED: &str = "slashed";
pub const VALIDITY_STATUS_FALLBACK_REQUIRED: &str = "fallback_required";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityCircuitFamily {
    StateTransition,
    MoneroBridge,
    ContractExecution,
    RecursiveAggregation,
}

impl ValidityCircuitFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::MoneroBridge => "monero_bridge",
            Self::ContractExecution => "contract_execution",
            Self::RecursiveAggregation => "recursive_aggregation",
        }
    }

    pub fn default_proof_system(&self) -> &'static str {
        match self {
            Self::StateTransition => VALIDITY_AGGREGATION_STATE_PROOF_SYSTEM,
            Self::MoneroBridge => VALIDITY_AGGREGATION_MONERO_BRIDGE_PROOF_SYSTEM,
            Self::ContractExecution => VALIDITY_AGGREGATION_CONTRACT_EXECUTION_PROOF_SYSTEM,
            Self::RecursiveAggregation => VALIDITY_AGGREGATION_RECURSIVE_PROOF_SYSTEM,
        }
    }

    pub fn default_circuit_name(&self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition_batch",
            Self::MoneroBridge => "monero_bridge_event",
            Self::ContractExecution => "contract_execution_frame",
            Self::RecursiveAggregation => "recursive_validity_batch",
        }
    }

    pub fn is_recursive(&self) -> bool {
        matches!(self, Self::RecursiveAggregation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityProofKind {
    StateTransition,
    MoneroBridge,
    ContractExecution,
    RecursiveBatch,
    CompressedAggregate,
}

impl ValidityProofKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::MoneroBridge => "monero_bridge",
            Self::ContractExecution => "contract_execution",
            Self::RecursiveBatch => "recursive_batch",
            Self::CompressedAggregate => "compressed_aggregate",
        }
    }

    pub fn family(&self) -> ValidityCircuitFamily {
        match self {
            Self::StateTransition => ValidityCircuitFamily::StateTransition,
            Self::MoneroBridge => ValidityCircuitFamily::MoneroBridge,
            Self::ContractExecution => ValidityCircuitFamily::ContractExecution,
            Self::RecursiveBatch | Self::CompressedAggregate => {
                ValidityCircuitFamily::RecursiveAggregation
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierCommitteeRole {
    Aggregator,
    Verifier,
    Challenger,
    Watchtower,
}

impl PqVerifierCommitteeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aggregator => "aggregator",
            Self::Verifier => "verifier",
            Self::Challenger => "challenger",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierCommitteePolicy {
    WeightedThreshold,
    RotatingQuorum,
    EmergencyUnanimity,
}

impl PqVerifierCommitteePolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WeightedThreshold => "weighted_threshold",
            Self::RotatingQuorum => "rotating_quorum",
            Self::EmergencyUnanimity => "emergency_unanimity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeProofLaneKind {
    PublicGood,
    WalletBatch,
    MoneroBridge,
    ContractMicroBatch,
    SettlementCritical,
}

impl LowFeeProofLaneKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicGood => "public_good",
            Self::WalletBatch => "wallet_batch",
            Self::MoneroBridge => "monero_bridge",
            Self::ContractMicroBatch => "contract_micro_batch",
            Self::SettlementCritical => "settlement_critical",
        }
    }

    pub fn default_lane_key(&self) -> &'static str {
        match self {
            Self::PublicGood => "proofs_public_good",
            Self::WalletBatch => "proofs_wallet_batch",
            Self::MoneroBridge => "proofs_monero_bridge",
            Self::ContractMicroBatch => "proofs_contract_micro_batch",
            Self::SettlementCritical => "proofs_settlement_critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackChallengeKind {
    MissingChildProof,
    InvalidPublicInput,
    CommitteeQuorumFailure,
    CompressionMismatch,
    RecursiveAccumulatorMismatch,
    MoneroFinalityMismatch,
    ContractTraceMismatch,
    StateRootMismatch,
    Timeout,
}

impl FallbackChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingChildProof => "missing_child_proof",
            Self::InvalidPublicInput => "invalid_public_input",
            Self::CommitteeQuorumFailure => "committee_quorum_failure",
            Self::CompressionMismatch => "compression_mismatch",
            Self::RecursiveAccumulatorMismatch => "recursive_accumulator_mismatch",
            Self::MoneroFinalityMismatch => "monero_finality_mismatch",
            Self::ContractTraceMismatch => "contract_trace_mismatch",
            Self::StateRootMismatch => "state_root_mismatch",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackChallengeOutcome {
    Unresolved,
    ProofAccepted,
    ProofRejected,
    Reaggregate,
    SlashCommittee,
    ExtendWindow,
}

impl FallbackChallengeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::ProofAccepted => "proof_accepted",
            Self::ProofRejected => "proof_rejected",
            Self::Reaggregate => "reaggregate",
            Self::SlashCommittee => "slash_committee",
            Self::ExtendWindow => "extend_window",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitFamilyManifest {
    pub manifest_id: String,
    pub family: ValidityCircuitFamily,
    pub family_key: String,
    pub manifest_version: u64,
    pub circuit_name: String,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub public_input_schema_root: String,
    pub witness_schema_root: String,
    pub compression_policy_root: String,
    pub recursion_compatible: bool,
    pub max_public_inputs: u64,
    pub max_witness_bytes: u64,
    pub target_proof_bytes: u64,
    pub max_child_proofs: u64,
    pub security_bits: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
    pub metadata_root: String,
}

impl CircuitFamilyManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ValidityCircuitFamily,
        manifest_version: u64,
        circuit_name: impl Into<String>,
        verifier_key_root: impl Into<String>,
        max_public_inputs: u64,
        max_witness_bytes: u64,
        target_proof_bytes: u64,
        max_child_proofs: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ValidityAggregationResult<Self> {
        if manifest_version == 0 {
            return Err("circuit family manifest version cannot be zero".to_string());
        }
        let circuit_name = normalize_label(circuit_name.into());
        ensure_non_empty(&circuit_name, "circuit name")?;
        let verifier_key_root = verifier_key_root.into();
        ensure_hash_like(&verifier_key_root, "verifier key root")?;
        if max_public_inputs == 0 {
            return Err("circuit family manifest max public inputs cannot be zero".to_string());
        }
        if max_witness_bytes == 0 || target_proof_bytes == 0 {
            return Err("circuit family manifest byte bounds cannot be zero".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= activated_at_height {
            return Err("circuit family manifest expires before activation".to_string());
        }
        let proof_system = family.default_proof_system().to_string();
        let family_key = family.as_str().to_string();
        let metadata_root = validity_payload_root("VALIDITY-CIRCUIT-FAMILY-METADATA", metadata);
        let public_input_schema_root = validity_circuit_public_input_schema_root(
            family.as_str(),
            &circuit_name,
            manifest_version,
            max_public_inputs,
            &metadata_root,
        );
        let witness_schema_root = validity_circuit_witness_schema_root(
            family.as_str(),
            &circuit_name,
            manifest_version,
            max_witness_bytes,
            &metadata_root,
        );
        let compression_policy_root = validity_compression_policy_root(
            family.as_str(),
            &circuit_name,
            target_proof_bytes,
            max_child_proofs,
            &metadata_root,
        );
        let manifest_id = circuit_family_manifest_id(
            family.as_str(),
            &circuit_name,
            manifest_version,
            &proof_system,
            &verifier_key_root,
            &public_input_schema_root,
        );
        let manifest = Self {
            manifest_id,
            family,
            family_key,
            manifest_version,
            circuit_name,
            proof_system,
            verifier_key_root,
            public_input_schema_root,
            witness_schema_root,
            compression_policy_root,
            recursion_compatible: family.is_recursive() || max_child_proofs > 0,
            max_public_inputs,
            max_witness_bytes,
            target_proof_bytes,
            max_child_proofs,
            security_bits: VALIDITY_AGGREGATION_DEFAULT_SECURITY_BITS,
            activated_at_height,
            expires_at_height,
            status: VALIDITY_STATUS_ACTIVE.to_string(),
            metadata_root,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == VALIDITY_STATUS_ACTIVE
            && height >= self.activated_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "circuit_family_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDITY_AGGREGATION_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "family": self.family.as_str(),
            "family_key": self.family_key,
            "manifest_version": self.manifest_version,
            "circuit_name": self.circuit_name,
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "public_input_schema_root": self.public_input_schema_root,
            "witness_schema_root": self.witness_schema_root,
            "compression_policy_root": self.compression_policy_root,
            "recursion_compatible": self.recursion_compatible,
            "max_public_inputs": self.max_public_inputs,
            "max_witness_bytes": self.max_witness_bytes,
            "target_proof_bytes": self.target_proof_bytes,
            "max_child_proofs": self.max_child_proofs,
            "security_bits": self.security_bits,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn manifest_root(&self) -> String {
        circuit_family_manifest_root(self)
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.manifest_id, "circuit family manifest id")?;
        ensure_non_empty(&self.family_key, "circuit family key")?;
        ensure_non_empty(&self.circuit_name, "circuit name")?;
        ensure_non_empty(&self.proof_system, "proof system")?;
        ensure_hash_like(&self.verifier_key_root, "verifier key root")?;
        ensure_hash_like(&self.public_input_schema_root, "public input schema root")?;
        ensure_hash_like(&self.witness_schema_root, "witness schema root")?;
        ensure_hash_like(&self.compression_policy_root, "compression policy root")?;
        ensure_hash_like(&self.metadata_root, "metadata root")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_PAUSED,
                VALIDITY_STATUS_EXPIRED,
                VALIDITY_STATUS_REJECTED,
            ],
            "circuit family manifest status",
        )?;
        if self.manifest_version == 0 {
            return Err("circuit family manifest version cannot be zero".to_string());
        }
        if self.max_public_inputs == 0
            || self.max_witness_bytes == 0
            || self.target_proof_bytes == 0
        {
            return Err("circuit family manifest has zero-sized bounds".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("circuit family manifest expires before activation".to_string());
        }
        let expected_id = circuit_family_manifest_id(
            self.family.as_str(),
            &self.circuit_name,
            self.manifest_version,
            &self.proof_system,
            &self.verifier_key_root,
            &self.public_input_schema_root,
        );
        if self.manifest_id != expected_id {
            return Err("circuit family manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierMember {
    pub member_id: String,
    pub operator_id: String,
    pub role: PqVerifierCommitteeRole,
    pub weight: u64,
    pub pq_public_key_root: String,
    pub recovery_public_key_root: String,
    pub stake_root: String,
    pub endpoint_commitment: String,
    pub joined_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqVerifierMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        role: PqVerifierCommitteeRole,
        weight: u64,
        pq_public_key_root: impl Into<String>,
        recovery_public_key_root: impl Into<String>,
        stake_root: impl Into<String>,
        endpoint_commitment: impl Into<String>,
        joined_at_height: u64,
        expires_at_height: u64,
    ) -> ValidityAggregationResult<Self> {
        let operator_id = normalize_label(operator_id.into());
        ensure_non_empty(&operator_id, "PQ verifier operator id")?;
        if weight == 0 {
            return Err("PQ verifier member weight cannot be zero".to_string());
        }
        let pq_public_key_root = pq_public_key_root.into();
        let recovery_public_key_root = recovery_public_key_root.into();
        let stake_root = stake_root.into();
        ensure_hash_like(&pq_public_key_root, "PQ verifier public key root")?;
        ensure_hash_like(
            &recovery_public_key_root,
            "PQ verifier recovery public key root",
        )?;
        ensure_hash_like(&stake_root, "PQ verifier stake root")?;
        let endpoint_commitment = endpoint_commitment.into();
        ensure_non_empty(&endpoint_commitment, "PQ verifier endpoint commitment")?;
        if expires_at_height != 0 && expires_at_height <= joined_at_height {
            return Err("PQ verifier member expires before joining".to_string());
        }
        let member_id = pq_verifier_member_id(
            &operator_id,
            role.as_str(),
            &pq_public_key_root,
            &recovery_public_key_root,
            joined_at_height,
        );
        let member = Self {
            member_id,
            operator_id,
            role,
            weight,
            pq_public_key_root,
            recovery_public_key_root,
            stake_root,
            endpoint_commitment,
            joined_at_height,
            expires_at_height,
            status: VALIDITY_STATUS_ACTIVE.to_string(),
        };
        member.validate()?;
        Ok(member)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == VALIDITY_STATUS_ACTIVE
            && height >= self.joined_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn effective_weight_at(&self, height: u64) -> u64 {
        if self.is_active_at(height) {
            self.weight
        } else {
            0
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_member",
            "chain_id": CHAIN_ID,
            "member_id": self.member_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "weight": self.weight,
            "pq_signature_scheme": VALIDITY_AGGREGATION_PQ_SIGNATURE_SCHEME,
            "pq_recovery_scheme": VALIDITY_AGGREGATION_PQ_RECOVERY_SCHEME,
            "pq_kem_scheme": VALIDITY_AGGREGATION_PQ_KEM_SCHEME,
            "pq_public_key_root": self.pq_public_key_root,
            "recovery_public_key_root": self.recovery_public_key_root,
            "stake_root": self.stake_root,
            "endpoint_commitment": self.endpoint_commitment,
            "joined_at_height": self.joined_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.member_id, "PQ verifier member id")?;
        ensure_non_empty(&self.operator_id, "PQ verifier operator id")?;
        ensure_hash_like(&self.pq_public_key_root, "PQ verifier public key root")?;
        ensure_hash_like(
            &self.recovery_public_key_root,
            "PQ verifier recovery public key root",
        )?;
        ensure_hash_like(&self.stake_root, "PQ verifier stake root")?;
        ensure_non_empty(&self.endpoint_commitment, "PQ verifier endpoint commitment")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_PAUSED,
                VALIDITY_STATUS_EXPIRED,
                VALIDITY_STATUS_SLASHED,
            ],
            "PQ verifier member status",
        )?;
        if self.weight == 0 {
            return Err("PQ verifier member weight cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.joined_at_height {
            return Err("PQ verifier member expires before joining".to_string());
        }
        let expected_id = pq_verifier_member_id(
            &self.operator_id,
            self.role.as_str(),
            &self.pq_public_key_root,
            &self.recovery_public_key_root,
            self.joined_at_height,
        );
        if self.member_id != expected_id {
            return Err("PQ verifier member id mismatch".to_string());
        }
        Ok(pq_verifier_member_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierCommittee {
    pub committee_id: String,
    pub committee_version: u64,
    pub epoch: u64,
    pub policy: PqVerifierCommitteePolicy,
    pub member_ids: Vec<String>,
    pub member_root: String,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub quorum_bps: u64,
    pub challenge_window_blocks: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqVerifierCommittee {
    #[allow(clippy::too_many_arguments)]
    pub fn from_members(
        committee_version: u64,
        epoch: u64,
        policy: PqVerifierCommitteePolicy,
        members: &[PqVerifierMember],
        quorum_bps: u64,
        challenge_window_blocks: u64,
        activated_at_height: u64,
        expires_at_height: u64,
    ) -> ValidityAggregationResult<Self> {
        if committee_version == 0 {
            return Err("PQ verifier committee version cannot be zero".to_string());
        }
        if members.is_empty() {
            return Err("PQ verifier committee requires members".to_string());
        }
        if quorum_bps == 0 || quorum_bps > VALIDITY_AGGREGATION_MAX_BPS {
            return Err("PQ verifier committee quorum bps is out of range".to_string());
        }
        if challenge_window_blocks == 0 {
            return Err("PQ verifier committee challenge window cannot be zero".to_string());
        }
        if expires_at_height != 0 && expires_at_height <= activated_at_height {
            return Err("PQ verifier committee expires before activation".to_string());
        }
        for member in members {
            member.validate()?;
        }
        let member_ids = normalize_unique_strings(
            members
                .iter()
                .map(|member| member.member_id.clone())
                .collect(),
            "PQ verifier committee member id",
        )?;
        let member_root = pq_verifier_member_set_root(members);
        let total_weight = members
            .iter()
            .fold(0_u64, |total, member| total.saturating_add(member.weight));
        let threshold_weight = mul_bps_round_up(total_weight, quorum_bps);
        let committee_id = pq_verifier_committee_id(
            committee_version,
            epoch,
            policy.as_str(),
            &member_root,
            threshold_weight,
        );
        let committee = Self {
            committee_id,
            committee_version,
            epoch,
            policy,
            member_ids,
            member_root,
            threshold_weight,
            total_weight,
            quorum_bps,
            challenge_window_blocks,
            activated_at_height,
            expires_at_height,
            status: VALIDITY_STATUS_ACTIVE.to_string(),
        };
        committee.validate()?;
        Ok(committee)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == VALIDITY_STATUS_ACTIVE
            && height >= self.activated_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_committee",
            "chain_id": CHAIN_ID,
            "committee_id": self.committee_id,
            "committee_version": self.committee_version,
            "epoch": self.epoch,
            "policy": self.policy.as_str(),
            "member_ids": self.member_ids,
            "member_root": self.member_root,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "quorum_bps": self.quorum_bps,
            "challenge_window_blocks": self.challenge_window_blocks,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.committee_id, "PQ verifier committee id")?;
        ensure_hash_like(&self.member_root, "PQ verifier committee member root")?;
        ensure_unique_strings(&self.member_ids, "PQ verifier committee member id")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_PAUSED,
                VALIDITY_STATUS_EXPIRED,
                VALIDITY_STATUS_SLASHED,
            ],
            "PQ verifier committee status",
        )?;
        if self.committee_version == 0 || self.total_weight == 0 {
            return Err("PQ verifier committee version and weight are required".to_string());
        }
        if self.threshold_weight == 0 || self.threshold_weight > self.total_weight {
            return Err("PQ verifier committee threshold is out of range".to_string());
        }
        if self.quorum_bps == 0 || self.quorum_bps > VALIDITY_AGGREGATION_MAX_BPS {
            return Err("PQ verifier committee quorum bps is out of range".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("PQ verifier committee challenge window cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("PQ verifier committee expires before activation".to_string());
        }
        let expected_id = pq_verifier_committee_id(
            self.committee_version,
            self.epoch,
            self.policy.as_str(),
            &self.member_root,
            self.threshold_weight,
        );
        if self.committee_id != expected_id {
            return Err("PQ verifier committee id mismatch".to_string());
        }
        Ok(pq_verifier_committee_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofLane {
    pub lane_id: String,
    pub lane_kind: LowFeeProofLaneKind,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_rebate_bps: u64,
    pub max_batch_proofs: u64,
    pub priority: u64,
    pub sponsor_commitment: String,
    pub status: String,
}

impl LowFeeProofLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: LowFeeProofLaneKind,
        lane_key: impl Into<String>,
        fee_asset_id: impl Into<String>,
        epoch: u64,
        start_height: u64,
        end_height: u64,
        budget_units: u64,
        max_rebate_bps: u64,
        max_batch_proofs: u64,
        priority: u64,
        sponsor_commitment: impl Into<String>,
    ) -> ValidityAggregationResult<Self> {
        let lane_key = normalize_label(lane_key.into());
        ensure_non_empty(&lane_key, "low-fee proof lane key")?;
        let fee_asset_id = normalize_label(fee_asset_id.into());
        ensure_non_empty(&fee_asset_id, "low-fee proof lane fee asset id")?;
        if end_height < start_height {
            return Err("low-fee proof lane ends before it starts".to_string());
        }
        if budget_units == 0 || max_batch_proofs == 0 {
            return Err("low-fee proof lane budget and batch size are required".to_string());
        }
        if max_rebate_bps > VALIDITY_AGGREGATION_MAX_BPS {
            return Err("low-fee proof lane max rebate bps is out of range".to_string());
        }
        let sponsor_commitment = sponsor_commitment.into();
        ensure_non_empty(&sponsor_commitment, "low-fee proof lane sponsor commitment")?;
        let lane_id = low_fee_proof_lane_id(
            lane_kind.as_str(),
            &lane_key,
            &fee_asset_id,
            epoch,
            start_height,
        );
        let lane = Self {
            lane_id,
            lane_kind,
            lane_key,
            fee_asset_id,
            epoch,
            start_height,
            end_height,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_rebate_bps,
            max_batch_proofs,
            priority,
            sponsor_commitment,
            status: VALIDITY_STATUS_ACTIVE.to_string(),
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn reserve_units(&mut self, units: u64) -> ValidityAggregationResult<()> {
        if units == 0 {
            return Err("low-fee proof lane reserve units are required".to_string());
        }
        if self.available_units() < units {
            return Err("low-fee proof lane budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn spend_reserved_units(&mut self, reserved_units: u64, spent_units: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(reserved_units);
        self.spent_units = self.spent_units.saturating_add(spent_units);
        if self.available_units() == 0 {
            self.status = VALIDITY_STATUS_FALLBACK_REQUIRED.to_string();
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_lane",
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "lane_key": self.lane_key,
            "fee_asset_id": self.fee_asset_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_rebate_bps": self.max_rebate_bps,
            "max_batch_proofs": self.max_batch_proofs,
            "priority": self.priority,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.lane_id, "low-fee proof lane id")?;
        ensure_non_empty(&self.lane_key, "low-fee proof lane key")?;
        ensure_non_empty(&self.fee_asset_id, "low-fee proof lane fee asset id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "low-fee proof lane sponsor commitment",
        )?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_PAUSED,
                VALIDITY_STATUS_EXPIRED,
                VALIDITY_STATUS_FALLBACK_REQUIRED,
            ],
            "low-fee proof lane status",
        )?;
        if self.end_height < self.start_height {
            return Err("low-fee proof lane ends before it starts".to_string());
        }
        if self.budget_units == 0 || self.max_batch_proofs == 0 {
            return Err("low-fee proof lane budget and batch size are required".to_string());
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("low-fee proof lane accounting exceeds budget".to_string());
        }
        if self.max_rebate_bps > VALIDITY_AGGREGATION_MAX_BPS {
            return Err("low-fee proof lane max rebate bps is out of range".to_string());
        }
        let expected_id = low_fee_proof_lane_id(
            self.lane_kind.as_str(),
            &self.lane_key,
            &self.fee_asset_id,
            self.epoch,
            self.start_height,
        );
        if self.lane_id != expected_id {
            return Err("low-fee proof lane id mismatch".to_string());
        }
        Ok(low_fee_proof_lane_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransitionProofInput {
    pub input_id: String,
    pub batch_id: String,
    pub previous_state_root: String,
    pub next_state_root: String,
    pub transaction_root: String,
    pub receipt_root: String,
    pub data_availability_root: String,
    pub forced_inclusion_root: String,
    pub withdrawal_root: String,
    pub fee_accounting_root: String,
    pub sequencer_committee_root: String,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub public_input_root: String,
    pub status: String,
}

impl StateTransitionProofInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: impl Into<String>,
        previous_state_root: impl Into<String>,
        next_state_root: impl Into<String>,
        transaction_root: impl Into<String>,
        receipt_root: impl Into<String>,
        data_availability_root: impl Into<String>,
        forced_inclusion_root: impl Into<String>,
        withdrawal_root: impl Into<String>,
        fee_accounting_root: impl Into<String>,
        sequencer_committee_root: impl Into<String>,
        l2_start_height: u64,
        l2_end_height: u64,
    ) -> ValidityAggregationResult<Self> {
        if l2_end_height < l2_start_height {
            return Err("state transition proof input ends before it starts".to_string());
        }
        let batch_id = batch_id.into();
        ensure_non_empty(&batch_id, "state transition batch id")?;
        let previous_state_root = previous_state_root.into();
        let next_state_root = next_state_root.into();
        let transaction_root = transaction_root.into();
        let receipt_root = receipt_root.into();
        let data_availability_root = data_availability_root.into();
        let forced_inclusion_root = forced_inclusion_root.into();
        let withdrawal_root = withdrawal_root.into();
        let fee_accounting_root = fee_accounting_root.into();
        let sequencer_committee_root = sequencer_committee_root.into();
        let public_input_root = state_transition_public_input_root(
            &batch_id,
            &previous_state_root,
            &next_state_root,
            &transaction_root,
            &receipt_root,
            &data_availability_root,
            &forced_inclusion_root,
            &withdrawal_root,
            &fee_accounting_root,
            &sequencer_committee_root,
            l2_start_height,
            l2_end_height,
        );
        let input_id = state_transition_proof_input_id(
            &batch_id,
            &previous_state_root,
            &next_state_root,
            &public_input_root,
            l2_start_height,
            l2_end_height,
        );
        let input = Self {
            input_id,
            batch_id,
            previous_state_root,
            next_state_root,
            transaction_root,
            receipt_root,
            data_availability_root,
            forced_inclusion_root,
            withdrawal_root,
            fee_accounting_root,
            sequencer_committee_root,
            l2_start_height,
            l2_end_height,
            public_input_root,
            status: VALIDITY_STATUS_PENDING.to_string(),
        };
        input.validate()?;
        Ok(input)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_transition_proof_input",
            "chain_id": CHAIN_ID,
            "input_id": self.input_id,
            "batch_id": self.batch_id,
            "previous_state_root": self.previous_state_root,
            "next_state_root": self.next_state_root,
            "transaction_root": self.transaction_root,
            "receipt_root": self.receipt_root,
            "data_availability_root": self.data_availability_root,
            "forced_inclusion_root": self.forced_inclusion_root,
            "withdrawal_root": self.withdrawal_root,
            "fee_accounting_root": self.fee_accounting_root,
            "sequencer_committee_root": self.sequencer_committee_root,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "public_input_root": self.public_input_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.input_id, "state transition proof input id")?;
        ensure_non_empty(&self.batch_id, "state transition batch id")?;
        ensure_hash_like(&self.previous_state_root, "previous state root")?;
        ensure_hash_like(&self.next_state_root, "next state root")?;
        ensure_hash_like(&self.transaction_root, "transaction root")?;
        ensure_hash_like(&self.receipt_root, "receipt root")?;
        ensure_hash_like(&self.data_availability_root, "data availability root")?;
        ensure_hash_like(&self.forced_inclusion_root, "forced inclusion root")?;
        ensure_hash_like(&self.withdrawal_root, "withdrawal root")?;
        ensure_hash_like(&self.fee_accounting_root, "fee accounting root")?;
        ensure_hash_like(&self.sequencer_committee_root, "sequencer committee root")?;
        ensure_hash_like(
            &self.public_input_root,
            "state transition public input root",
        )?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_VERIFIED,
                VALIDITY_STATUS_REJECTED,
                VALIDITY_STATUS_CHALLENGED,
            ],
            "state transition proof input status",
        )?;
        if self.l2_end_height < self.l2_start_height {
            return Err("state transition proof input ends before it starts".to_string());
        }
        let expected_public_input_root = state_transition_public_input_root(
            &self.batch_id,
            &self.previous_state_root,
            &self.next_state_root,
            &self.transaction_root,
            &self.receipt_root,
            &self.data_availability_root,
            &self.forced_inclusion_root,
            &self.withdrawal_root,
            &self.fee_accounting_root,
            &self.sequencer_committee_root,
            self.l2_start_height,
            self.l2_end_height,
        );
        if self.public_input_root != expected_public_input_root {
            return Err("state transition public input root mismatch".to_string());
        }
        let expected_id = state_transition_proof_input_id(
            &self.batch_id,
            &self.previous_state_root,
            &self.next_state_root,
            &self.public_input_root,
            self.l2_start_height,
            self.l2_end_height,
        );
        if self.input_id != expected_id {
            return Err("state transition proof input id mismatch".to_string());
        }
        Ok(state_transition_proof_input_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeProofInput {
    pub input_id: String,
    pub bridge_event_id: String,
    pub monero_network: String,
    pub monero_txid_hash: String,
    pub monero_block_hash: String,
    pub monero_block_height: u64,
    pub confirmation_depth: u64,
    pub reserve_root: String,
    pub deposit_root: String,
    pub withdrawal_root: String,
    pub signer_set_root: String,
    pub amount_bucket: u64,
    pub recipient_commitment: String,
    pub public_input_root: String,
    pub status: String,
}

impl MoneroBridgeProofInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bridge_event_id: impl Into<String>,
        monero_network: impl Into<String>,
        monero_txid_hash: impl Into<String>,
        monero_block_hash: impl Into<String>,
        monero_block_height: u64,
        confirmation_depth: u64,
        reserve_root: impl Into<String>,
        deposit_root: impl Into<String>,
        withdrawal_root: impl Into<String>,
        signer_set_root: impl Into<String>,
        amount_bucket: u64,
        recipient_commitment: impl Into<String>,
    ) -> ValidityAggregationResult<Self> {
        let bridge_event_id = bridge_event_id.into();
        ensure_non_empty(&bridge_event_id, "Monero bridge event id")?;
        let monero_network = normalize_label(monero_network.into());
        ensure_non_empty(&monero_network, "Monero network")?;
        if confirmation_depth == 0 {
            return Err("Monero bridge proof input confirmation depth cannot be zero".to_string());
        }
        let monero_txid_hash = monero_txid_hash.into();
        let monero_block_hash = monero_block_hash.into();
        let reserve_root = reserve_root.into();
        let deposit_root = deposit_root.into();
        let withdrawal_root = withdrawal_root.into();
        let signer_set_root = signer_set_root.into();
        let recipient_commitment = recipient_commitment.into();
        let public_input_root = monero_bridge_public_input_root(
            &bridge_event_id,
            &monero_network,
            &monero_txid_hash,
            &monero_block_hash,
            monero_block_height,
            confirmation_depth,
            &reserve_root,
            &deposit_root,
            &withdrawal_root,
            &signer_set_root,
            amount_bucket,
            &recipient_commitment,
        );
        let input_id = monero_bridge_proof_input_id(
            &bridge_event_id,
            &monero_network,
            &monero_txid_hash,
            &public_input_root,
            monero_block_height,
        );
        let input = Self {
            input_id,
            bridge_event_id,
            monero_network,
            monero_txid_hash,
            monero_block_hash,
            monero_block_height,
            confirmation_depth,
            reserve_root,
            deposit_root,
            withdrawal_root,
            signer_set_root,
            amount_bucket,
            recipient_commitment,
            public_input_root,
            status: VALIDITY_STATUS_PENDING.to_string(),
        };
        input.validate()?;
        Ok(input)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_proof_input",
            "chain_id": CHAIN_ID,
            "input_id": self.input_id,
            "bridge_event_id": self.bridge_event_id,
            "monero_network": self.monero_network,
            "monero_txid_hash": self.monero_txid_hash,
            "monero_block_hash": self.monero_block_hash,
            "monero_block_height": self.monero_block_height,
            "confirmation_depth": self.confirmation_depth,
            "reserve_root": self.reserve_root,
            "deposit_root": self.deposit_root,
            "withdrawal_root": self.withdrawal_root,
            "signer_set_root": self.signer_set_root,
            "amount_bucket": self.amount_bucket,
            "recipient_commitment": self.recipient_commitment,
            "public_input_root": self.public_input_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.input_id, "Monero bridge proof input id")?;
        ensure_non_empty(&self.bridge_event_id, "Monero bridge event id")?;
        ensure_non_empty(&self.monero_network, "Monero network")?;
        ensure_hash_like(&self.monero_txid_hash, "Monero txid hash")?;
        ensure_hash_like(&self.monero_block_hash, "Monero block hash")?;
        ensure_hash_like(&self.reserve_root, "Monero bridge reserve root")?;
        ensure_hash_like(&self.deposit_root, "Monero bridge deposit root")?;
        ensure_hash_like(&self.withdrawal_root, "Monero bridge withdrawal root")?;
        ensure_hash_like(&self.signer_set_root, "Monero bridge signer set root")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "Monero bridge recipient commitment",
        )?;
        ensure_hash_like(&self.public_input_root, "Monero bridge public input root")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_VERIFIED,
                VALIDITY_STATUS_REJECTED,
                VALIDITY_STATUS_CHALLENGED,
            ],
            "Monero bridge proof input status",
        )?;
        if self.confirmation_depth == 0 {
            return Err("Monero bridge proof input confirmation depth cannot be zero".to_string());
        }
        let expected_public_input_root = monero_bridge_public_input_root(
            &self.bridge_event_id,
            &self.monero_network,
            &self.monero_txid_hash,
            &self.monero_block_hash,
            self.monero_block_height,
            self.confirmation_depth,
            &self.reserve_root,
            &self.deposit_root,
            &self.withdrawal_root,
            &self.signer_set_root,
            self.amount_bucket,
            &self.recipient_commitment,
        );
        if self.public_input_root != expected_public_input_root {
            return Err("Monero bridge public input root mismatch".to_string());
        }
        let expected_id = monero_bridge_proof_input_id(
            &self.bridge_event_id,
            &self.monero_network,
            &self.monero_txid_hash,
            &self.public_input_root,
            self.monero_block_height,
        );
        if self.input_id != expected_id {
            return Err("Monero bridge proof input id mismatch".to_string());
        }
        Ok(monero_bridge_proof_input_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecutionProofInput {
    pub input_id: String,
    pub execution_id: String,
    pub contract_id: String,
    pub call_id: String,
    pub caller_commitment: String,
    pub method_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub storage_read_root: String,
    pub storage_write_root: String,
    pub event_root: String,
    pub host_receipt_root: String,
    pub trap_root: String,
    pub gas_used: u64,
    pub public_input_root: String,
    pub status: String,
}

impl ContractExecutionProofInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_id: impl Into<String>,
        contract_id: impl Into<String>,
        call_id: impl Into<String>,
        caller_commitment: impl Into<String>,
        method_id: impl Into<String>,
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
        storage_read_root: impl Into<String>,
        storage_write_root: impl Into<String>,
        event_root: impl Into<String>,
        host_receipt_root: impl Into<String>,
        trap_root: impl Into<String>,
        gas_used: u64,
    ) -> ValidityAggregationResult<Self> {
        let execution_id = execution_id.into();
        let contract_id = contract_id.into();
        let call_id = call_id.into();
        let caller_commitment = caller_commitment.into();
        let method_id = method_id.into();
        ensure_non_empty(&execution_id, "contract execution id")?;
        ensure_non_empty(&contract_id, "contract id")?;
        ensure_non_empty(&call_id, "contract call id")?;
        ensure_non_empty(&caller_commitment, "contract caller commitment")?;
        ensure_non_empty(&method_id, "contract method id")?;
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let storage_read_root = storage_read_root.into();
        let storage_write_root = storage_write_root.into();
        let event_root = event_root.into();
        let host_receipt_root = host_receipt_root.into();
        let trap_root = trap_root.into();
        let public_input_root = contract_execution_public_input_root(
            &execution_id,
            &contract_id,
            &call_id,
            &caller_commitment,
            &method_id,
            &pre_state_root,
            &post_state_root,
            &storage_read_root,
            &storage_write_root,
            &event_root,
            &host_receipt_root,
            &trap_root,
            gas_used,
        );
        let input_id = contract_execution_proof_input_id(
            &execution_id,
            &contract_id,
            &call_id,
            &post_state_root,
            &public_input_root,
        );
        let input = Self {
            input_id,
            execution_id,
            contract_id,
            call_id,
            caller_commitment,
            method_id,
            pre_state_root,
            post_state_root,
            storage_read_root,
            storage_write_root,
            event_root,
            host_receipt_root,
            trap_root,
            gas_used,
            public_input_root,
            status: VALIDITY_STATUS_PENDING.to_string(),
        };
        input.validate()?;
        Ok(input)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_execution_proof_input",
            "chain_id": CHAIN_ID,
            "input_id": self.input_id,
            "execution_id": self.execution_id,
            "contract_id": self.contract_id,
            "call_id": self.call_id,
            "caller_commitment": self.caller_commitment,
            "method_id": self.method_id,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "storage_read_root": self.storage_read_root,
            "storage_write_root": self.storage_write_root,
            "event_root": self.event_root,
            "host_receipt_root": self.host_receipt_root,
            "trap_root": self.trap_root,
            "gas_used": self.gas_used,
            "public_input_root": self.public_input_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.input_id, "contract execution proof input id")?;
        ensure_non_empty(&self.execution_id, "contract execution id")?;
        ensure_non_empty(&self.contract_id, "contract id")?;
        ensure_non_empty(&self.call_id, "contract call id")?;
        ensure_non_empty(&self.caller_commitment, "contract caller commitment")?;
        ensure_non_empty(&self.method_id, "contract method id")?;
        ensure_hash_like(&self.pre_state_root, "contract pre-state root")?;
        ensure_hash_like(&self.post_state_root, "contract post-state root")?;
        ensure_hash_like(&self.storage_read_root, "contract storage read root")?;
        ensure_hash_like(&self.storage_write_root, "contract storage write root")?;
        ensure_hash_like(&self.event_root, "contract event root")?;
        ensure_hash_like(&self.host_receipt_root, "contract host receipt root")?;
        ensure_hash_like(&self.trap_root, "contract trap root")?;
        ensure_hash_like(&self.public_input_root, "contract public input root")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_VERIFIED,
                VALIDITY_STATUS_REJECTED,
                VALIDITY_STATUS_CHALLENGED,
            ],
            "contract execution proof input status",
        )?;
        let expected_public_input_root = contract_execution_public_input_root(
            &self.execution_id,
            &self.contract_id,
            &self.call_id,
            &self.caller_commitment,
            &self.method_id,
            &self.pre_state_root,
            &self.post_state_root,
            &self.storage_read_root,
            &self.storage_write_root,
            &self.event_root,
            &self.host_receipt_root,
            &self.trap_root,
            self.gas_used,
        );
        if self.public_input_root != expected_public_input_root {
            return Err("contract execution public input root mismatch".to_string());
        }
        let expected_id = contract_execution_proof_input_id(
            &self.execution_id,
            &self.contract_id,
            &self.call_id,
            &self.post_state_root,
            &self.public_input_root,
        );
        if self.input_id != expected_id {
            return Err("contract execution proof input id mismatch".to_string());
        }
        Ok(contract_execution_proof_input_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityProofRecord {
    pub proof_id: String,
    pub proof_kind: ValidityProofKind,
    pub manifest_id: String,
    pub committee_id: String,
    pub source_input_id: String,
    pub batch_id: String,
    pub public_input_root: String,
    pub proof_commitment: String,
    pub transcript_root: String,
    pub proof_bytes: u64,
    pub recursion_depth: u64,
    pub low_fee_lane_id: String,
    pub prover_commitment: String,
    pub submitted_at_height: u64,
    pub verified_at_height: u64,
    pub status: String,
}

impl ValidityProofRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_kind: ValidityProofKind,
        manifest_id: impl Into<String>,
        committee_id: impl Into<String>,
        source_input_id: impl Into<String>,
        batch_id: impl Into<String>,
        public_input_root: impl Into<String>,
        proof_commitment: impl Into<String>,
        transcript_root: impl Into<String>,
        proof_bytes: u64,
        recursion_depth: u64,
        low_fee_lane_id: impl Into<String>,
        prover_commitment: impl Into<String>,
        submitted_at_height: u64,
    ) -> ValidityAggregationResult<Self> {
        if proof_bytes == 0 {
            return Err("validity proof bytes cannot be zero".to_string());
        }
        let manifest_id = manifest_id.into();
        let committee_id = committee_id.into();
        let source_input_id = source_input_id.into();
        let batch_id = batch_id.into();
        let public_input_root = public_input_root.into();
        let proof_commitment = proof_commitment.into();
        let transcript_root = transcript_root.into();
        let low_fee_lane_id = low_fee_lane_id.into();
        let prover_commitment = prover_commitment.into();
        ensure_non_empty(&manifest_id, "validity proof manifest id")?;
        ensure_non_empty(&committee_id, "validity proof committee id")?;
        ensure_non_empty(&source_input_id, "validity proof source input id")?;
        ensure_non_empty(&batch_id, "validity proof batch id")?;
        ensure_hash_like(&public_input_root, "validity proof public input root")?;
        ensure_hash_like(&proof_commitment, "validity proof commitment")?;
        ensure_hash_like(&transcript_root, "validity proof transcript root")?;
        ensure_non_empty(&prover_commitment, "validity proof prover commitment")?;
        let proof_id = validity_proof_id(
            proof_kind.as_str(),
            &manifest_id,
            &committee_id,
            &source_input_id,
            &public_input_root,
            &proof_commitment,
        );
        let proof = Self {
            proof_id,
            proof_kind,
            manifest_id,
            committee_id,
            source_input_id,
            batch_id,
            public_input_root,
            proof_commitment,
            transcript_root,
            proof_bytes,
            recursion_depth,
            low_fee_lane_id,
            prover_commitment,
            submitted_at_height,
            verified_at_height: 0,
            status: VALIDITY_STATUS_PENDING.to_string(),
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn mark_verified(&self, height: u64) -> ValidityAggregationResult<Self> {
        if height < self.submitted_at_height {
            return Err("validity proof verification precedes submission".to_string());
        }
        let mut proof = self.clone();
        proof.verified_at_height = height;
        proof.status = VALIDITY_STATUS_VERIFIED.to_string();
        proof.validate()?;
        Ok(proof)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validity_proof_record",
            "chain_id": CHAIN_ID,
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind.as_str(),
            "family": self.proof_kind.family().as_str(),
            "manifest_id": self.manifest_id,
            "committee_id": self.committee_id,
            "source_input_id": self.source_input_id,
            "batch_id": self.batch_id,
            "public_input_root": self.public_input_root,
            "proof_commitment": self.proof_commitment,
            "transcript_root": self.transcript_root,
            "proof_bytes": self.proof_bytes,
            "recursion_depth": self.recursion_depth,
            "low_fee_lane_id": self.low_fee_lane_id,
            "prover_commitment": self.prover_commitment,
            "submitted_at_height": self.submitted_at_height,
            "verified_at_height": self.verified_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.proof_id, "validity proof id")?;
        ensure_non_empty(&self.manifest_id, "validity proof manifest id")?;
        ensure_non_empty(&self.committee_id, "validity proof committee id")?;
        ensure_non_empty(&self.source_input_id, "validity proof source input id")?;
        ensure_non_empty(&self.batch_id, "validity proof batch id")?;
        ensure_hash_like(&self.public_input_root, "validity proof public input root")?;
        ensure_hash_like(&self.proof_commitment, "validity proof commitment")?;
        ensure_hash_like(&self.transcript_root, "validity proof transcript root")?;
        ensure_non_empty(&self.prover_commitment, "validity proof prover commitment")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_VERIFIED,
                VALIDITY_STATUS_REJECTED,
                VALIDITY_STATUS_COMPRESSED,
                VALIDITY_STATUS_CHALLENGED,
                VALIDITY_STATUS_FALLBACK_REQUIRED,
            ],
            "validity proof status",
        )?;
        if self.proof_bytes == 0 {
            return Err("validity proof bytes cannot be zero".to_string());
        }
        if self.verified_at_height != 0 && self.verified_at_height < self.submitted_at_height {
            return Err("validity proof verification precedes submission".to_string());
        }
        let expected_id = validity_proof_id(
            self.proof_kind.as_str(),
            &self.manifest_id,
            &self.committee_id,
            &self.source_input_id,
            &self.public_input_root,
            &self.proof_commitment,
        );
        if self.proof_id != expected_id {
            return Err("validity proof id mismatch".to_string());
        }
        Ok(validity_proof_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofBatch {
    pub batch_id: String,
    pub batch_number: u64,
    pub parent_batch_id: String,
    pub plan_id: String,
    pub manifest_id: String,
    pub committee_id: String,
    pub low_fee_lane_id: String,
    pub child_proof_ids: Vec<String>,
    pub child_proof_root: String,
    pub state_transition_input_root: String,
    pub monero_bridge_input_root: String,
    pub contract_execution_input_root: String,
    pub public_input_root: String,
    pub accumulator_root: String,
    pub recursion_depth: u64,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub created_at_height: u64,
    pub sealed_at_height: u64,
    pub status: String,
}

impl RecursiveProofBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_number: u64,
        parent_batch_id: impl Into<String>,
        plan_id: impl Into<String>,
        manifest_id: impl Into<String>,
        committee_id: impl Into<String>,
        low_fee_lane_id: impl Into<String>,
        child_proofs: &[ValidityProofRecord],
        state_inputs: &[StateTransitionProofInput],
        bridge_inputs: &[MoneroBridgeProofInput],
        contract_inputs: &[ContractExecutionProofInput],
        recursion_depth: u64,
        l2_start_height: u64,
        l2_end_height: u64,
        created_at_height: u64,
    ) -> ValidityAggregationResult<Self> {
        if child_proofs.is_empty() {
            return Err("recursive proof batch requires child proofs".to_string());
        }
        if l2_end_height < l2_start_height {
            return Err("recursive proof batch ends before it starts".to_string());
        }
        let parent_batch_id = parent_batch_id.into();
        let plan_id = plan_id.into();
        let manifest_id = manifest_id.into();
        let committee_id = committee_id.into();
        let low_fee_lane_id = low_fee_lane_id.into();
        ensure_non_empty(&parent_batch_id, "recursive proof parent batch id")?;
        ensure_non_empty(&plan_id, "recursive proof plan id")?;
        ensure_non_empty(&manifest_id, "recursive proof manifest id")?;
        ensure_non_empty(&committee_id, "recursive proof committee id")?;
        let child_proof_ids = child_proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&child_proof_ids, "recursive proof child proof id")?;
        let child_proof_root = validity_proof_set_root(child_proofs);
        let state_transition_input_root = state_transition_proof_input_set_root(state_inputs);
        let monero_bridge_input_root = monero_bridge_proof_input_set_root(bridge_inputs);
        let contract_execution_input_root =
            contract_execution_proof_input_set_root(contract_inputs);
        let public_input_root = recursive_batch_public_input_root(
            batch_number,
            &parent_batch_id,
            &child_proof_root,
            &state_transition_input_root,
            &monero_bridge_input_root,
            &contract_execution_input_root,
            recursion_depth,
            l2_start_height,
            l2_end_height,
        );
        let accumulator_root = recursive_accumulator_root(
            &child_proof_root,
            &public_input_root,
            recursion_depth,
            child_proofs.len() as u64,
        );
        let batch_id = recursive_proof_batch_id(
            batch_number,
            &parent_batch_id,
            &plan_id,
            &manifest_id,
            &public_input_root,
            &accumulator_root,
        );
        let batch = Self {
            batch_id,
            batch_number,
            parent_batch_id,
            plan_id,
            manifest_id,
            committee_id,
            low_fee_lane_id,
            child_proof_ids,
            child_proof_root,
            state_transition_input_root,
            monero_bridge_input_root,
            contract_execution_input_root,
            public_input_root,
            accumulator_root,
            recursion_depth,
            l2_start_height,
            l2_end_height,
            created_at_height,
            sealed_at_height: 0,
            status: VALIDITY_STATUS_PENDING.to_string(),
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn seal(&self, height: u64) -> ValidityAggregationResult<Self> {
        if height < self.created_at_height {
            return Err("recursive proof batch seal height precedes creation".to_string());
        }
        let mut batch = self.clone();
        batch.sealed_at_height = height;
        batch.status = VALIDITY_STATUS_SEALED.to_string();
        batch.validate()?;
        Ok(batch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_batch",
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "batch_number": self.batch_number,
            "parent_batch_id": self.parent_batch_id,
            "plan_id": self.plan_id,
            "manifest_id": self.manifest_id,
            "committee_id": self.committee_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "child_proof_ids": self.child_proof_ids,
            "child_proof_root": self.child_proof_root,
            "state_transition_input_root": self.state_transition_input_root,
            "monero_bridge_input_root": self.monero_bridge_input_root,
            "contract_execution_input_root": self.contract_execution_input_root,
            "public_input_root": self.public_input_root,
            "accumulator_root": self.accumulator_root,
            "recursion_depth": self.recursion_depth,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "created_at_height": self.created_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.batch_id, "recursive proof batch id")?;
        ensure_non_empty(&self.parent_batch_id, "recursive proof parent batch id")?;
        ensure_non_empty(&self.plan_id, "recursive proof plan id")?;
        ensure_non_empty(&self.manifest_id, "recursive proof manifest id")?;
        ensure_non_empty(&self.committee_id, "recursive proof committee id")?;
        ensure_unique_strings(&self.child_proof_ids, "recursive proof child proof id")?;
        ensure_hash_like(&self.child_proof_root, "recursive proof child proof root")?;
        ensure_hash_like(
            &self.state_transition_input_root,
            "recursive proof state transition input root",
        )?;
        ensure_hash_like(
            &self.monero_bridge_input_root,
            "recursive proof Monero bridge input root",
        )?;
        ensure_hash_like(
            &self.contract_execution_input_root,
            "recursive proof contract execution input root",
        )?;
        ensure_hash_like(&self.public_input_root, "recursive proof public input root")?;
        ensure_hash_like(&self.accumulator_root, "recursive proof accumulator root")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_PENDING,
                VALIDITY_STATUS_ACTIVE,
                VALIDITY_STATUS_SEALED,
                VALIDITY_STATUS_VERIFIED,
                VALIDITY_STATUS_REJECTED,
                VALIDITY_STATUS_CHALLENGED,
                VALIDITY_STATUS_COMPRESSED,
                VALIDITY_STATUS_FALLBACK_REQUIRED,
            ],
            "recursive proof batch status",
        )?;
        if self.l2_end_height < self.l2_start_height {
            return Err("recursive proof batch ends before it starts".to_string());
        }
        if self.sealed_at_height != 0 && self.sealed_at_height < self.created_at_height {
            return Err("recursive proof batch seal height precedes creation".to_string());
        }
        let expected_public_input_root = recursive_batch_public_input_root(
            self.batch_number,
            &self.parent_batch_id,
            &self.child_proof_root,
            &self.state_transition_input_root,
            &self.monero_bridge_input_root,
            &self.contract_execution_input_root,
            self.recursion_depth,
            self.l2_start_height,
            self.l2_end_height,
        );
        if self.public_input_root != expected_public_input_root {
            return Err("recursive proof batch public input root mismatch".to_string());
        }
        let expected_accumulator_root = recursive_accumulator_root(
            &self.child_proof_root,
            &self.public_input_root,
            self.recursion_depth,
            self.child_proof_ids.len() as u64,
        );
        if self.accumulator_root != expected_accumulator_root {
            return Err("recursive proof batch accumulator root mismatch".to_string());
        }
        let expected_id = recursive_proof_batch_id(
            self.batch_number,
            &self.parent_batch_id,
            &self.plan_id,
            &self.manifest_id,
            &self.public_input_root,
            &self.accumulator_root,
        );
        if self.batch_id != expected_id {
            return Err("recursive proof batch id mismatch".to_string());
        }
        Ok(recursive_proof_batch_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCompressionReceipt {
    pub receipt_id: String,
    pub source_proof_ids: Vec<String>,
    pub source_proof_root: String,
    pub source_proof_bytes: u64,
    pub compressed_proof_id: String,
    pub compressed_proof_commitment: String,
    pub compressed_proof_bytes: u64,
    pub compression_scheme: String,
    pub compression_ratio_bps: u64,
    pub verifier_committee_id: String,
    pub transcript_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl ProofCompressionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_proofs: &[ValidityProofRecord],
        compressed_proof_id: impl Into<String>,
        compressed_proof_commitment: impl Into<String>,
        compressed_proof_bytes: u64,
        verifier_committee_id: impl Into<String>,
        transcript_root: impl Into<String>,
        created_at_height: u64,
    ) -> ValidityAggregationResult<Self> {
        if source_proofs.is_empty() {
            return Err("proof compression receipt requires source proofs".to_string());
        }
        if compressed_proof_bytes == 0 {
            return Err("proof compression receipt compressed bytes cannot be zero".to_string());
        }
        let source_proof_ids = source_proofs
            .iter()
            .map(|proof| proof.proof_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&source_proof_ids, "proof compression source proof id")?;
        let source_proof_root = validity_proof_set_root(source_proofs);
        let source_proof_bytes = source_proofs.iter().fold(0_u64, |total, proof| {
            total.saturating_add(proof.proof_bytes)
        });
        if source_proof_bytes == 0 {
            return Err("proof compression source bytes cannot be zero".to_string());
        }
        if compressed_proof_bytes >= source_proof_bytes {
            return Err("proof compression must reduce proof bytes".to_string());
        }
        let compression_ratio_bps = ratio_bps(compressed_proof_bytes, source_proof_bytes);
        let compressed_proof_id = compressed_proof_id.into();
        let compressed_proof_commitment = compressed_proof_commitment.into();
        let verifier_committee_id = verifier_committee_id.into();
        let transcript_root = transcript_root.into();
        ensure_non_empty(&compressed_proof_id, "compressed proof id")?;
        ensure_hash_like(&compressed_proof_commitment, "compressed proof commitment")?;
        ensure_non_empty(
            &verifier_committee_id,
            "proof compression verifier committee id",
        )?;
        ensure_hash_like(&transcript_root, "proof compression transcript root")?;
        let receipt_id = proof_compression_receipt_id(
            &source_proof_root,
            &compressed_proof_id,
            &compressed_proof_commitment,
            compression_ratio_bps,
            created_at_height,
        );
        let receipt = Self {
            receipt_id,
            source_proof_ids,
            source_proof_root,
            source_proof_bytes,
            compressed_proof_id,
            compressed_proof_commitment,
            compressed_proof_bytes,
            compression_scheme: VALIDITY_AGGREGATION_COMPRESSION_SCHEME.to_string(),
            compression_ratio_bps,
            verifier_committee_id,
            transcript_root,
            created_at_height,
            status: VALIDITY_STATUS_COMPRESSED.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_compression_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "source_proof_ids": self.source_proof_ids,
            "source_proof_root": self.source_proof_root,
            "source_proof_bytes": self.source_proof_bytes,
            "compressed_proof_id": self.compressed_proof_id,
            "compressed_proof_commitment": self.compressed_proof_commitment,
            "compressed_proof_bytes": self.compressed_proof_bytes,
            "compression_scheme": self.compression_scheme,
            "compression_ratio_bps": self.compression_ratio_bps,
            "verifier_committee_id": self.verifier_committee_id,
            "transcript_root": self.transcript_root,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.receipt_id, "proof compression receipt id")?;
        ensure_unique_strings(&self.source_proof_ids, "proof compression source proof id")?;
        ensure_hash_like(
            &self.source_proof_root,
            "proof compression source proof root",
        )?;
        ensure_non_empty(&self.compressed_proof_id, "compressed proof id")?;
        ensure_hash_like(
            &self.compressed_proof_commitment,
            "compressed proof commitment",
        )?;
        ensure_non_empty(&self.compression_scheme, "proof compression scheme")?;
        ensure_non_empty(
            &self.verifier_committee_id,
            "proof compression verifier committee id",
        )?;
        ensure_hash_like(&self.transcript_root, "proof compression transcript root")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_COMPRESSED,
                VALIDITY_STATUS_VERIFIED,
                VALIDITY_STATUS_CHALLENGED,
                VALIDITY_STATUS_REJECTED,
            ],
            "proof compression receipt status",
        )?;
        if self.source_proof_bytes == 0 || self.compressed_proof_bytes == 0 {
            return Err("proof compression receipt byte counts cannot be zero".to_string());
        }
        if self.compressed_proof_bytes >= self.source_proof_bytes {
            return Err("proof compression receipt does not reduce proof bytes".to_string());
        }
        let expected_ratio = ratio_bps(self.compressed_proof_bytes, self.source_proof_bytes);
        if self.compression_ratio_bps != expected_ratio {
            return Err("proof compression receipt ratio mismatch".to_string());
        }
        let expected_id = proof_compression_receipt_id(
            &self.source_proof_root,
            &self.compressed_proof_id,
            &self.compressed_proof_commitment,
            self.compression_ratio_bps,
            self.created_at_height,
        );
        if self.receipt_id != expected_id {
            return Err("proof compression receipt id mismatch".to_string());
        }
        Ok(proof_compression_receipt_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackChallengeRecord {
    pub challenge_id: String,
    pub challenge_kind: FallbackChallengeKind,
    pub target_kind: String,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub fallback_manifest_id: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub resolved_at_height: u64,
    pub outcome: FallbackChallengeOutcome,
    pub status: String,
}

impl FallbackChallengeRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_kind: FallbackChallengeKind,
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        fallback_manifest_id: impl Into<String>,
        bond_units: u64,
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> ValidityAggregationResult<Self> {
        if challenge_window_blocks == 0 {
            return Err("fallback challenge window cannot be zero".to_string());
        }
        let target_kind = normalize_label(target_kind.into());
        let target_id = target_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        let fallback_manifest_id = fallback_manifest_id.into();
        ensure_non_empty(&target_kind, "fallback challenge target kind")?;
        ensure_non_empty(&target_id, "fallback challenge target id")?;
        ensure_non_empty(
            &challenger_commitment,
            "fallback challenge challenger commitment",
        )?;
        ensure_hash_like(&evidence_root, "fallback challenge evidence root")?;
        ensure_non_empty(&fallback_manifest_id, "fallback challenge manifest id")?;
        let deadline_height = opened_at_height.saturating_add(challenge_window_blocks);
        let challenge_id = fallback_challenge_id(
            challenge_kind.as_str(),
            &target_kind,
            &target_id,
            &challenger_commitment,
            &evidence_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            challenge_kind,
            target_kind,
            target_id,
            challenger_commitment,
            evidence_root,
            fallback_manifest_id,
            bond_units,
            opened_at_height,
            deadline_height,
            resolved_at_height: 0,
            outcome: FallbackChallengeOutcome::Unresolved,
            status: VALIDITY_STATUS_CHALLENGED.to_string(),
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status == VALIDITY_STATUS_CHALLENGED
            && height >= self.opened_at_height
            && height <= self.deadline_height
    }

    pub fn resolve(
        &self,
        outcome: FallbackChallengeOutcome,
        resolved_at_height: u64,
    ) -> ValidityAggregationResult<Self> {
        if outcome == FallbackChallengeOutcome::Unresolved {
            return Err("fallback challenge resolution outcome cannot be unresolved".to_string());
        }
        if resolved_at_height < self.opened_at_height {
            return Err("fallback challenge resolution precedes opening".to_string());
        }
        let mut challenge = self.clone();
        challenge.outcome = outcome;
        challenge.resolved_at_height = resolved_at_height;
        challenge.status = match outcome {
            FallbackChallengeOutcome::ProofAccepted | FallbackChallengeOutcome::ExtendWindow => {
                VALIDITY_STATUS_RESOLVED.to_string()
            }
            FallbackChallengeOutcome::ProofRejected | FallbackChallengeOutcome::Reaggregate => {
                VALIDITY_STATUS_FALLBACK_REQUIRED.to_string()
            }
            FallbackChallengeOutcome::SlashCommittee => VALIDITY_STATUS_SLASHED.to_string(),
            FallbackChallengeOutcome::Unresolved => VALIDITY_STATUS_CHALLENGED.to_string(),
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fallback_challenge_record",
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "fallback_manifest_id": self.fallback_manifest_id,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "outcome": self.outcome.as_str(),
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        ensure_non_empty(&self.challenge_id, "fallback challenge id")?;
        ensure_non_empty(&self.target_kind, "fallback challenge target kind")?;
        ensure_non_empty(&self.target_id, "fallback challenge target id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "fallback challenge challenger commitment",
        )?;
        ensure_hash_like(&self.evidence_root, "fallback challenge evidence root")?;
        ensure_non_empty(&self.fallback_manifest_id, "fallback challenge manifest id")?;
        ensure_status(
            &self.status,
            &[
                VALIDITY_STATUS_CHALLENGED,
                VALIDITY_STATUS_RESOLVED,
                VALIDITY_STATUS_FALLBACK_REQUIRED,
                VALIDITY_STATUS_SLASHED,
                VALIDITY_STATUS_EXPIRED,
            ],
            "fallback challenge status",
        )?;
        if self.deadline_height <= self.opened_at_height {
            return Err("fallback challenge deadline must follow opening".to_string());
        }
        if self.resolved_at_height != 0 && self.resolved_at_height < self.opened_at_height {
            return Err("fallback challenge resolution precedes opening".to_string());
        }
        if self.status != VALIDITY_STATUS_CHALLENGED
            && self.outcome == FallbackChallengeOutcome::Unresolved
        {
            return Err("resolved fallback challenge requires an outcome".to_string());
        }
        let expected_id = fallback_challenge_id(
            self.challenge_kind.as_str(),
            &self.target_kind,
            &self.target_id,
            &self.challenger_commitment,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.challenge_id != expected_id {
            return Err("fallback challenge id mismatch".to_string());
        }
        Ok(fallback_challenge_root(self))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityAggregationState {
    pub height: u64,
    pub active_manifest_ids: BTreeMap<String, String>,
    pub active_committee_id: Option<String>,
    pub circuit_manifests: BTreeMap<String, CircuitFamilyManifest>,
    pub verifier_members: BTreeMap<String, PqVerifierMember>,
    pub verifier_committees: BTreeMap<String, PqVerifierCommittee>,
    pub low_fee_lanes: BTreeMap<String, LowFeeProofLane>,
    pub state_transition_inputs: BTreeMap<String, StateTransitionProofInput>,
    pub monero_bridge_inputs: BTreeMap<String, MoneroBridgeProofInput>,
    pub contract_execution_inputs: BTreeMap<String, ContractExecutionProofInput>,
    pub proof_records: BTreeMap<String, ValidityProofRecord>,
    pub recursive_batches: BTreeMap<String, RecursiveProofBatch>,
    pub compression_receipts: BTreeMap<String, ProofCompressionReceipt>,
    pub fallback_challenges: BTreeMap<String, FallbackChallengeRecord>,
}

impl ValidityAggregationState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> ValidityAggregationResult<Self> {
        let mut state = Self::new();
        state.set_height(24);

        let state_manifest = devnet_manifest(
            ValidityCircuitFamily::StateTransition,
            28,
            10 * 1024 * 1024,
            196_608,
            0,
            &json!({
                "input": "rollup batch roots",
                "mode": "deterministic_devnet",
            }),
        )?;
        let bridge_manifest = devnet_manifest(
            ValidityCircuitFamily::MoneroBridge,
            24,
            4 * 1024 * 1024,
            131_072,
            0,
            &json!({
                "input": "monero finality and bridge accounting",
                "mode": "deterministic_devnet",
            }),
        )?;
        let contract_manifest = devnet_manifest(
            ValidityCircuitFamily::ContractExecution,
            32,
            8 * 1024 * 1024,
            147_456,
            0,
            &json!({
                "input": "contract vm execution frame",
                "mode": "deterministic_devnet",
            }),
        )?;
        let recursive_manifest = devnet_manifest(
            ValidityCircuitFamily::RecursiveAggregation,
            48,
            6 * 1024 * 1024,
            98_304,
            VALIDITY_AGGREGATION_DEFAULT_MAX_CHILD_PROOFS,
            &json!({
                "input": "recursive batch accumulator",
                "mode": "deterministic_devnet",
            }),
        )?;

        for manifest in [
            state_manifest.clone(),
            bridge_manifest.clone(),
            contract_manifest.clone(),
            recursive_manifest.clone(),
        ] {
            state.insert_circuit_manifest(manifest)?;
        }
        state.publish_manifest(&state_manifest.manifest_id)?;
        state.publish_manifest(&bridge_manifest.manifest_id)?;
        state.publish_manifest(&contract_manifest.manifest_id)?;
        state.publish_manifest(&recursive_manifest.manifest_id)?;

        let members = vec![
            devnet_member(
                "devnet-aggregator-a",
                PqVerifierCommitteeRole::Aggregator,
                40,
                0,
            )?,
            devnet_member(
                "devnet-verifier-b",
                PqVerifierCommitteeRole::Verifier,
                35,
                0,
            )?,
            devnet_member(
                "devnet-watchtower-c",
                PqVerifierCommitteeRole::Watchtower,
                25,
                0,
            )?,
            devnet_member(
                "devnet-challenger-d",
                PqVerifierCommitteeRole::Challenger,
                20,
                0,
            )?,
        ];
        for member in &members {
            state.insert_verifier_member(member.clone())?;
        }
        let committee = PqVerifierCommittee::from_members(
            1,
            0,
            PqVerifierCommitteePolicy::WeightedThreshold,
            &members,
            6_700,
            VALIDITY_AGGREGATION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            0,
            0,
        )?;
        let committee_id = committee.committee_id.clone();
        state.insert_verifier_committee(committee)?;
        state.activate_committee(&committee_id)?;

        let proof_lane = LowFeeProofLane::new(
            LowFeeProofLaneKind::PublicGood,
            LowFeeProofLaneKind::PublicGood.default_lane_key(),
            "wxmr-devnet",
            0,
            0,
            VALIDITY_AGGREGATION_DEFAULT_LOW_FEE_EPOCH_BLOCKS - 1,
            VALIDITY_AGGREGATION_DEFAULT_LOW_FEE_PROOF_BUDGET_UNITS,
            5_000,
            VALIDITY_AGGREGATION_DEFAULT_MAX_CHILD_PROOFS,
            10,
            deterministic_commitment("validity-proof-public-good-sponsor"),
        )?;
        let bridge_lane = LowFeeProofLane::new(
            LowFeeProofLaneKind::MoneroBridge,
            LowFeeProofLaneKind::MoneroBridge.default_lane_key(),
            "wxmr-devnet",
            0,
            0,
            VALIDITY_AGGREGATION_DEFAULT_LOW_FEE_EPOCH_BLOCKS - 1,
            55_000,
            6_000,
            32,
            20,
            deterministic_commitment("validity-proof-bridge-sponsor"),
        )?;
        let contract_lane = LowFeeProofLane::new(
            LowFeeProofLaneKind::ContractMicroBatch,
            LowFeeProofLaneKind::ContractMicroBatch.default_lane_key(),
            "wxmr-devnet",
            0,
            0,
            VALIDITY_AGGREGATION_DEFAULT_LOW_FEE_EPOCH_BLOCKS - 1,
            40_000,
            4_000,
            48,
            15,
            deterministic_commitment("validity-proof-contract-sponsor"),
        )?;
        let proof_lane_id = proof_lane.lane_id.clone();
        state.insert_low_fee_lane(proof_lane)?;
        state.insert_low_fee_lane(bridge_lane)?;
        state.insert_low_fee_lane(contract_lane)?;

        let state_input = StateTransitionProofInput::new(
            "devnet-rollup-batch-0",
            deterministic_root("devnet-previous-state"),
            deterministic_root("devnet-next-state"),
            deterministic_root("devnet-transaction-root"),
            deterministic_root("devnet-receipt-root"),
            deterministic_root("devnet-da-root"),
            deterministic_root("devnet-forced-inclusion-root"),
            deterministic_root("devnet-withdrawal-root"),
            deterministic_root("devnet-fee-accounting-root"),
            pq_verifier_committee_root(
                state
                    .verifier_committees
                    .get(&committee_id)
                    .expect("devnet committee exists"),
            ),
            0,
            23,
        )?;
        let bridge_input = MoneroBridgeProofInput::new(
            "devnet-monero-bridge-event-0",
            "stagenet",
            deterministic_root("devnet-monero-txid"),
            deterministic_root("devnet-monero-block"),
            3_000_000,
            24,
            deterministic_root("devnet-reserve-root"),
            deterministic_root("devnet-deposit-root"),
            deterministic_root("devnet-withdrawal-queue-root"),
            deterministic_root("devnet-signer-set-root"),
            1_000_000,
            deterministic_commitment("devnet-recipient"),
        )?;
        let contract_input = ContractExecutionProofInput::new(
            "devnet-contract-execution-0",
            "devnet-contract-vault",
            "devnet-contract-call-0",
            deterministic_commitment("devnet-caller"),
            "swap_exact_private",
            deterministic_root("devnet-contract-pre-state"),
            deterministic_root("devnet-contract-post-state"),
            deterministic_root("devnet-contract-storage-read"),
            deterministic_root("devnet-contract-storage-write"),
            deterministic_root("devnet-contract-event"),
            deterministic_root("devnet-contract-host-receipt"),
            deterministic_root("devnet-contract-trap-empty"),
            42_000,
        )?;
        let state_input_id = state.insert_state_transition_input(state_input.clone())?;
        let bridge_input_id = state.insert_monero_bridge_input(bridge_input.clone())?;
        let contract_input_id = state.insert_contract_execution_input(contract_input.clone())?;

        let state_proof = ValidityProofRecord::new(
            ValidityProofKind::StateTransition,
            &state_manifest.manifest_id,
            &committee_id,
            &state_input_id,
            "devnet-rollup-batch-0",
            &state_input.public_input_root,
            deterministic_root("devnet-state-proof"),
            deterministic_root("devnet-state-proof-transcript"),
            state_manifest.target_proof_bytes,
            0,
            &proof_lane_id,
            deterministic_commitment("devnet-prover-state"),
            10,
        )?
        .mark_verified(11)?;
        let bridge_proof = ValidityProofRecord::new(
            ValidityProofKind::MoneroBridge,
            &bridge_manifest.manifest_id,
            &committee_id,
            &bridge_input_id,
            "devnet-rollup-batch-0",
            &bridge_input.public_input_root,
            deterministic_root("devnet-bridge-proof"),
            deterministic_root("devnet-bridge-proof-transcript"),
            bridge_manifest.target_proof_bytes,
            0,
            &proof_lane_id,
            deterministic_commitment("devnet-prover-bridge"),
            12,
        )?
        .mark_verified(13)?;
        let contract_proof = ValidityProofRecord::new(
            ValidityProofKind::ContractExecution,
            &contract_manifest.manifest_id,
            &committee_id,
            &contract_input_id,
            "devnet-rollup-batch-0",
            &contract_input.public_input_root,
            deterministic_root("devnet-contract-proof"),
            deterministic_root("devnet-contract-proof-transcript"),
            contract_manifest.target_proof_bytes,
            0,
            &proof_lane_id,
            deterministic_commitment("devnet-prover-contract"),
            14,
        )?
        .mark_verified(15)?;

        state.insert_proof_record(state_proof.clone())?;
        state.insert_proof_record(bridge_proof.clone())?;
        state.insert_proof_record(contract_proof.clone())?;

        let batch = RecursiveProofBatch::new(
            0,
            "genesis-validity-batch",
            "devnet-recursive-plan",
            &recursive_manifest.manifest_id,
            &committee_id,
            &proof_lane_id,
            &[
                state_proof.clone(),
                bridge_proof.clone(),
                contract_proof.clone(),
            ],
            &[state_input],
            &[bridge_input],
            &[contract_input],
            VALIDITY_AGGREGATION_DEFAULT_RECURSION_DEPTH,
            0,
            23,
            16,
        )?
        .seal(18)?;
        let batch_id = state.insert_recursive_batch(batch.clone())?;

        let aggregate_proof = ValidityProofRecord::new(
            ValidityProofKind::RecursiveBatch,
            &recursive_manifest.manifest_id,
            &committee_id,
            &batch_id,
            &batch.batch_id,
            &batch.public_input_root,
            deterministic_root("devnet-recursive-proof"),
            deterministic_root("devnet-recursive-proof-transcript"),
            recursive_manifest.target_proof_bytes,
            batch.recursion_depth,
            &proof_lane_id,
            deterministic_commitment("devnet-prover-recursive"),
            19,
        )?
        .mark_verified(20)?;
        state.insert_proof_record(aggregate_proof.clone())?;

        let compression = ProofCompressionReceipt::new(
            &[state_proof, bridge_proof, contract_proof, aggregate_proof],
            "devnet-compressed-validity-proof-0",
            deterministic_root("devnet-compressed-proof"),
            64_000,
            &committee_id,
            deterministic_root("devnet-compression-transcript"),
            21,
        )?;
        state.insert_compression_receipt(compression)?;

        let challenge = FallbackChallengeRecord::new(
            FallbackChallengeKind::Timeout,
            "recursive_proof_batch",
            &batch.batch_id,
            deterministic_commitment("devnet-watchtower"),
            deterministic_root("devnet-timeout-evidence"),
            &recursive_manifest.manifest_id,
            5,
            22,
            VALIDITY_AGGREGATION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        )?
        .resolve(FallbackChallengeOutcome::ProofAccepted, 23)?;
        state.insert_fallback_challenge(challenge)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for lane in self.low_fee_lanes.values_mut() {
            if height > lane.end_height && lane.status == VALIDITY_STATUS_ACTIVE {
                lane.status = VALIDITY_STATUS_EXPIRED.to_string();
            }
        }
        for member in self.verifier_members.values_mut() {
            if member.expires_at_height != 0
                && height >= member.expires_at_height
                && member.status == VALIDITY_STATUS_ACTIVE
            {
                member.status = VALIDITY_STATUS_EXPIRED.to_string();
            }
        }
        for committee in self.verifier_committees.values_mut() {
            if committee.expires_at_height != 0
                && height >= committee.expires_at_height
                && committee.status == VALIDITY_STATUS_ACTIVE
            {
                committee.status = VALIDITY_STATUS_EXPIRED.to_string();
            }
        }
        for challenge in self.fallback_challenges.values_mut() {
            if height > challenge.deadline_height && challenge.status == VALIDITY_STATUS_CHALLENGED
            {
                challenge.status = VALIDITY_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn insert_circuit_manifest(
        &mut self,
        manifest: CircuitFamilyManifest,
    ) -> ValidityAggregationResult<String> {
        manifest.validate()?;
        insert_unique_record(
            &mut self.circuit_manifests,
            manifest.manifest_id.clone(),
            manifest,
            "circuit family manifest",
        )
    }

    pub fn publish_manifest(
        &mut self,
        manifest_id: &str,
    ) -> ValidityAggregationResult<CircuitFamilyManifest> {
        let manifest = self
            .circuit_manifests
            .get(manifest_id)
            .ok_or_else(|| "unknown circuit family manifest".to_string())?
            .clone();
        if !manifest.is_active_at(self.height) {
            return Err("circuit family manifest is not active at current height".to_string());
        }
        self.active_manifest_ids.insert(
            manifest.family.as_str().to_string(),
            manifest_id.to_string(),
        );
        Ok(manifest)
    }

    pub fn insert_verifier_member(
        &mut self,
        member: PqVerifierMember,
    ) -> ValidityAggregationResult<String> {
        member.validate()?;
        insert_unique_record(
            &mut self.verifier_members,
            member.member_id.clone(),
            member,
            "PQ verifier member",
        )
    }

    pub fn insert_verifier_committee(
        &mut self,
        committee: PqVerifierCommittee,
    ) -> ValidityAggregationResult<String> {
        committee.validate()?;
        for member_id in &committee.member_ids {
            if !self.verifier_members.contains_key(member_id) {
                return Err("PQ verifier committee references unknown member".to_string());
            }
        }
        insert_unique_record(
            &mut self.verifier_committees,
            committee.committee_id.clone(),
            committee,
            "PQ verifier committee",
        )
    }

    pub fn activate_committee(
        &mut self,
        committee_id: &str,
    ) -> ValidityAggregationResult<PqVerifierCommittee> {
        let committee = self
            .verifier_committees
            .get(committee_id)
            .ok_or_else(|| "unknown PQ verifier committee".to_string())?
            .clone();
        if !committee.is_active_at(self.height) {
            return Err("PQ verifier committee is not active at current height".to_string());
        }
        self.active_committee_id = Some(committee_id.to_string());
        Ok(committee)
    }

    pub fn insert_low_fee_lane(
        &mut self,
        lane: LowFeeProofLane,
    ) -> ValidityAggregationResult<String> {
        lane.validate()?;
        insert_unique_record(
            &mut self.low_fee_lanes,
            lane.lane_id.clone(),
            lane,
            "low-fee proof lane",
        )
    }

    pub fn insert_state_transition_input(
        &mut self,
        input: StateTransitionProofInput,
    ) -> ValidityAggregationResult<String> {
        input.validate()?;
        insert_unique_record(
            &mut self.state_transition_inputs,
            input.input_id.clone(),
            input,
            "state transition proof input",
        )
    }

    pub fn insert_monero_bridge_input(
        &mut self,
        input: MoneroBridgeProofInput,
    ) -> ValidityAggregationResult<String> {
        input.validate()?;
        insert_unique_record(
            &mut self.monero_bridge_inputs,
            input.input_id.clone(),
            input,
            "Monero bridge proof input",
        )
    }

    pub fn insert_contract_execution_input(
        &mut self,
        input: ContractExecutionProofInput,
    ) -> ValidityAggregationResult<String> {
        input.validate()?;
        insert_unique_record(
            &mut self.contract_execution_inputs,
            input.input_id.clone(),
            input,
            "contract execution proof input",
        )
    }

    pub fn insert_proof_record(
        &mut self,
        proof: ValidityProofRecord,
    ) -> ValidityAggregationResult<String> {
        proof.validate()?;
        if !self.circuit_manifests.contains_key(&proof.manifest_id) {
            return Err("validity proof references unknown manifest".to_string());
        }
        if !self.verifier_committees.contains_key(&proof.committee_id) {
            return Err("validity proof references unknown committee".to_string());
        }
        if !proof.low_fee_lane_id.is_empty()
            && !self.low_fee_lanes.contains_key(&proof.low_fee_lane_id)
        {
            return Err("validity proof references unknown low-fee lane".to_string());
        }
        match proof.proof_kind {
            ValidityProofKind::StateTransition => {
                if !self
                    .state_transition_inputs
                    .contains_key(&proof.source_input_id)
                {
                    return Err("state transition proof references unknown input".to_string());
                }
            }
            ValidityProofKind::MoneroBridge => {
                if !self
                    .monero_bridge_inputs
                    .contains_key(&proof.source_input_id)
                {
                    return Err("Monero bridge proof references unknown input".to_string());
                }
            }
            ValidityProofKind::ContractExecution => {
                if !self
                    .contract_execution_inputs
                    .contains_key(&proof.source_input_id)
                {
                    return Err("contract execution proof references unknown input".to_string());
                }
            }
            ValidityProofKind::RecursiveBatch | ValidityProofKind::CompressedAggregate => {
                if !self.recursive_batches.contains_key(&proof.source_input_id) {
                    return Err("recursive proof references unknown batch".to_string());
                }
            }
        }
        insert_unique_record(
            &mut self.proof_records,
            proof.proof_id.clone(),
            proof,
            "validity proof",
        )
    }

    pub fn insert_recursive_batch(
        &mut self,
        batch: RecursiveProofBatch,
    ) -> ValidityAggregationResult<String> {
        batch.validate()?;
        if !self.circuit_manifests.contains_key(&batch.manifest_id) {
            return Err("recursive proof batch references unknown manifest".to_string());
        }
        if !self.verifier_committees.contains_key(&batch.committee_id) {
            return Err("recursive proof batch references unknown committee".to_string());
        }
        if !batch.low_fee_lane_id.is_empty()
            && !self.low_fee_lanes.contains_key(&batch.low_fee_lane_id)
        {
            return Err("recursive proof batch references unknown low-fee lane".to_string());
        }
        for proof_id in &batch.child_proof_ids {
            if !self.proof_records.contains_key(proof_id) {
                return Err("recursive proof batch references unknown child proof".to_string());
            }
        }
        insert_unique_record(
            &mut self.recursive_batches,
            batch.batch_id.clone(),
            batch,
            "recursive proof batch",
        )
    }

    pub fn insert_compression_receipt(
        &mut self,
        receipt: ProofCompressionReceipt,
    ) -> ValidityAggregationResult<String> {
        receipt.validate()?;
        if !self
            .verifier_committees
            .contains_key(&receipt.verifier_committee_id)
        {
            return Err("proof compression references unknown committee".to_string());
        }
        for proof_id in &receipt.source_proof_ids {
            if !self.proof_records.contains_key(proof_id) {
                return Err("proof compression references unknown source proof".to_string());
            }
        }
        insert_unique_record(
            &mut self.compression_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "proof compression receipt",
        )
    }

    pub fn insert_fallback_challenge(
        &mut self,
        challenge: FallbackChallengeRecord,
    ) -> ValidityAggregationResult<String> {
        challenge.validate()?;
        if !self
            .circuit_manifests
            .contains_key(&challenge.fallback_manifest_id)
        {
            return Err("fallback challenge references unknown fallback manifest".to_string());
        }
        insert_unique_record(
            &mut self.fallback_challenges,
            challenge.challenge_id.clone(),
            challenge,
            "fallback challenge",
        )
    }

    pub fn reserve_low_fee_proof_units(
        &mut self,
        lane_id: &str,
        units: u64,
    ) -> ValidityAggregationResult<()> {
        let lane = self
            .low_fee_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown low-fee proof lane".to_string())?;
        if !lane.contains_height(self.height) {
            return Err("low-fee proof lane is outside current height".to_string());
        }
        lane.reserve_units(units)
    }

    pub fn spend_low_fee_proof_units(
        &mut self,
        lane_id: &str,
        reserved_units: u64,
        spent_units: u64,
    ) -> ValidityAggregationResult<()> {
        let lane = self
            .low_fee_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown low-fee proof lane".to_string())?;
        lane.spend_reserved_units(reserved_units, spent_units);
        lane.validate()?;
        Ok(())
    }

    pub fn manifest_root(&self) -> String {
        circuit_family_manifest_set_root(
            &self.circuit_manifests.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn verifier_member_root(&self) -> String {
        pq_verifier_member_set_root(&self.verifier_members.values().cloned().collect::<Vec<_>>())
    }

    pub fn verifier_committee_root(&self) -> String {
        pq_verifier_committee_set_root(
            &self
                .verifier_committees
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_lane_root(&self) -> String {
        low_fee_proof_lane_set_root(&self.low_fee_lanes.values().cloned().collect::<Vec<_>>())
    }

    pub fn state_transition_input_root(&self) -> String {
        state_transition_proof_input_set_root(
            &self
                .state_transition_inputs
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn monero_bridge_input_root(&self) -> String {
        monero_bridge_proof_input_set_root(
            &self
                .monero_bridge_inputs
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn contract_execution_input_root(&self) -> String {
        contract_execution_proof_input_set_root(
            &self
                .contract_execution_inputs
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn proof_record_root(&self) -> String {
        validity_proof_set_root(&self.proof_records.values().cloned().collect::<Vec<_>>())
    }

    pub fn recursive_batch_root(&self) -> String {
        recursive_proof_batch_set_root(
            &self.recursive_batches.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn compression_receipt_root(&self) -> String {
        proof_compression_receipt_set_root(
            &self
                .compression_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn fallback_challenge_root(&self) -> String {
        fallback_challenge_set_root(
            &self
                .fallback_challenges
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_challenge_count(&self) -> u64 {
        self.fallback_challenges
            .values()
            .filter(|challenge| challenge.is_open_at(self.height))
            .count() as u64
    }

    pub fn verified_proof_count(&self) -> u64 {
        self.proof_records
            .values()
            .filter(|proof| proof.status == VALIDITY_STATUS_VERIFIED)
            .count() as u64
    }

    pub fn compressed_proof_bytes_saved(&self) -> u64 {
        self.compression_receipts
            .values()
            .fold(0_u64, |total, receipt| {
                total.saturating_add(
                    receipt
                        .source_proof_bytes
                        .saturating_sub(receipt.compressed_proof_bytes),
                )
            })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "validity_aggregation_state",
            "chain_id": CHAIN_ID,
            "protocol_version": VALIDITY_AGGREGATION_PROTOCOL_VERSION,
            "schema_version": VALIDITY_AGGREGATION_SCHEMA_VERSION,
            "height": self.height,
            "active_manifest_ids": self.active_manifest_ids,
            "active_committee_id": self.active_committee_id,
            "manifest_root": self.manifest_root(),
            "verifier_member_root": self.verifier_member_root(),
            "verifier_committee_root": self.verifier_committee_root(),
            "low_fee_lane_root": self.low_fee_lane_root(),
            "state_transition_input_root": self.state_transition_input_root(),
            "monero_bridge_input_root": self.monero_bridge_input_root(),
            "contract_execution_input_root": self.contract_execution_input_root(),
            "proof_record_root": self.proof_record_root(),
            "recursive_batch_root": self.recursive_batch_root(),
            "compression_receipt_root": self.compression_receipt_root(),
            "fallback_challenge_root": self.fallback_challenge_root(),
            "manifest_count": self.circuit_manifests.len() as u64,
            "verifier_member_count": self.verifier_members.len() as u64,
            "verifier_committee_count": self.verifier_committees.len() as u64,
            "low_fee_lane_count": self.low_fee_lanes.len() as u64,
            "state_transition_input_count": self.state_transition_inputs.len() as u64,
            "monero_bridge_input_count": self.monero_bridge_inputs.len() as u64,
            "contract_execution_input_count": self.contract_execution_inputs.len() as u64,
            "proof_record_count": self.proof_records.len() as u64,
            "verified_proof_count": self.verified_proof_count(),
            "recursive_batch_count": self.recursive_batches.len() as u64,
            "compression_receipt_count": self.compression_receipts.len() as u64,
            "compressed_proof_bytes_saved": self.compressed_proof_bytes_saved(),
            "fallback_challenge_count": self.fallback_challenges.len() as u64,
            "active_challenge_count": self.active_challenge_count(),
        })
    }

    pub fn state_root(&self) -> String {
        validity_aggregation_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("validity aggregation state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> ValidityAggregationResult<String> {
        for manifest in self.circuit_manifests.values() {
            manifest.validate()?;
        }
        for (family, manifest_id) in &self.active_manifest_ids {
            let manifest = self
                .circuit_manifests
                .get(manifest_id)
                .ok_or_else(|| "active validity manifest is missing".to_string())?;
            if manifest.family.as_str() != family {
                return Err("active validity manifest family mismatch".to_string());
            }
            if !manifest.is_active_at(self.height) {
                return Err("active validity manifest is not active at current height".to_string());
            }
        }
        for member in self.verifier_members.values() {
            member.validate()?;
        }
        for committee in self.verifier_committees.values() {
            committee.validate()?;
            for member_id in &committee.member_ids {
                if !self.verifier_members.contains_key(member_id) {
                    return Err("PQ verifier committee references unknown member".to_string());
                }
            }
        }
        if let Some(active_committee_id) = &self.active_committee_id {
            let committee = self
                .verifier_committees
                .get(active_committee_id)
                .ok_or_else(|| "active PQ verifier committee is missing".to_string())?;
            if !committee.is_active_at(self.height) {
                return Err(
                    "active PQ verifier committee is not active at current height".to_string(),
                );
            }
        }
        for lane in self.low_fee_lanes.values() {
            lane.validate()?;
        }
        for input in self.state_transition_inputs.values() {
            input.validate()?;
        }
        for input in self.monero_bridge_inputs.values() {
            input.validate()?;
        }
        for input in self.contract_execution_inputs.values() {
            input.validate()?;
        }
        for proof in self.proof_records.values() {
            proof.validate()?;
            if !self.circuit_manifests.contains_key(&proof.manifest_id) {
                return Err("validity proof references unknown manifest".to_string());
            }
            if !self.verifier_committees.contains_key(&proof.committee_id) {
                return Err("validity proof references unknown committee".to_string());
            }
        }
        for batch in self.recursive_batches.values() {
            batch.validate()?;
            for proof_id in &batch.child_proof_ids {
                if !self.proof_records.contains_key(proof_id) {
                    return Err("recursive proof batch references unknown child proof".to_string());
                }
            }
        }
        for receipt in self.compression_receipts.values() {
            receipt.validate()?;
            for proof_id in &receipt.source_proof_ids {
                if !self.proof_records.contains_key(proof_id) {
                    return Err("proof compression references unknown source proof".to_string());
                }
            }
        }
        for challenge in self.fallback_challenges.values() {
            challenge.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn validity_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(VALIDITY_AGGREGATION_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn validity_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(VALIDITY_AGGREGATION_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str) -> String {
    domain_hash(
        "VALIDITY-DETERMINISTIC-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_commitment(label: &str) -> String {
    domain_hash(
        "VALIDITY-DETERMINISTIC-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn validity_circuit_public_input_schema_root(
    family: &str,
    circuit_name: &str,
    manifest_version: u64,
    max_public_inputs: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "VALIDITY-CIRCUIT-PUBLIC-INPUT-SCHEMA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(manifest_version as i128),
            HashPart::Int(max_public_inputs as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn validity_circuit_witness_schema_root(
    family: &str,
    circuit_name: &str,
    manifest_version: u64,
    max_witness_bytes: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "VALIDITY-CIRCUIT-WITNESS-SCHEMA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(manifest_version as i128),
            HashPart::Int(max_witness_bytes as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn validity_compression_policy_root(
    family: &str,
    circuit_name: &str,
    target_proof_bytes: u64,
    max_child_proofs: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "VALIDITY-COMPRESSION-POLICY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(target_proof_bytes as i128),
            HashPart::Int(max_child_proofs as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn circuit_family_manifest_id(
    family: &str,
    circuit_name: &str,
    manifest_version: u64,
    proof_system: &str,
    verifier_key_root: &str,
    public_input_schema_root: &str,
) -> String {
    domain_hash(
        "VALIDITY-CIRCUIT-FAMILY-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(manifest_version as i128),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_root),
            HashPart::Str(public_input_schema_root),
        ],
        32,
    )
}

pub fn circuit_family_manifest_root(manifest: &CircuitFamilyManifest) -> String {
    domain_hash(
        "VALIDITY-CIRCUIT-FAMILY-MANIFEST",
        &[HashPart::Json(&manifest.public_record())],
        32,
    )
}

pub fn circuit_family_manifest_set_root(manifests: &[CircuitFamilyManifest]) -> String {
    let mut records = manifests
        .iter()
        .map(|manifest| (manifest.manifest_id.clone(), manifest.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-CIRCUIT-FAMILY-MANIFEST",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_verifier_member_id(
    operator_id: &str,
    role: &str,
    pq_public_key_root: &str,
    recovery_public_key_root: &str,
    joined_at_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-PQ-VERIFIER-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(role),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(recovery_public_key_root),
            HashPart::Int(joined_at_height as i128),
        ],
        32,
    )
}

pub fn pq_verifier_member_root(member: &PqVerifierMember) -> String {
    domain_hash(
        "VALIDITY-PQ-VERIFIER-MEMBER",
        &[HashPart::Json(&member.public_record())],
        32,
    )
}

pub fn pq_verifier_member_set_root(members: &[PqVerifierMember]) -> String {
    let mut records = members
        .iter()
        .map(|member| (member.member_id.clone(), member.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-PQ-VERIFIER-MEMBER",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_verifier_committee_id(
    committee_version: u64,
    epoch: u64,
    policy: &str,
    member_root: &str,
    threshold_weight: u64,
) -> String {
    domain_hash(
        "VALIDITY-PQ-VERIFIER-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(committee_version as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(policy),
            HashPart::Str(member_root),
            HashPart::Int(threshold_weight as i128),
        ],
        32,
    )
}

pub fn pq_verifier_committee_root(committee: &PqVerifierCommittee) -> String {
    domain_hash(
        "VALIDITY-PQ-VERIFIER-COMMITTEE",
        &[HashPart::Json(&committee.public_record())],
        32,
    )
}

pub fn pq_verifier_committee_set_root(committees: &[PqVerifierCommittee]) -> String {
    let mut records = committees
        .iter()
        .map(|committee| (committee.committee_id.clone(), committee.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-PQ-VERIFIER-COMMITTEE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_proof_lane_id(
    lane_kind: &str,
    lane_key: &str,
    fee_asset_id: &str,
    epoch: u64,
    start_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-LOW-FEE-PROOF-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind),
            HashPart::Str(lane_key),
            HashPart::Str(fee_asset_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn low_fee_proof_lane_root(lane: &LowFeeProofLane) -> String {
    domain_hash(
        "VALIDITY-LOW-FEE-PROOF-LANE",
        &[HashPart::Json(&lane.public_record())],
        32,
    )
}

pub fn low_fee_proof_lane_set_root(lanes: &[LowFeeProofLane]) -> String {
    let mut records = lanes
        .iter()
        .map(|lane| (lane.lane_id.clone(), lane.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-LOW-FEE-PROOF-LANE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn state_transition_public_input_root(
    batch_id: &str,
    previous_state_root: &str,
    next_state_root: &str,
    transaction_root: &str,
    receipt_root: &str,
    data_availability_root: &str,
    forced_inclusion_root: &str,
    withdrawal_root: &str,
    fee_accounting_root: &str,
    sequencer_committee_root: &str,
    l2_start_height: u64,
    l2_end_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-STATE-TRANSITION-PUBLIC-INPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(previous_state_root),
            HashPart::Str(next_state_root),
            HashPart::Str(transaction_root),
            HashPart::Str(receipt_root),
            HashPart::Str(data_availability_root),
            HashPart::Str(forced_inclusion_root),
            HashPart::Str(withdrawal_root),
            HashPart::Str(fee_accounting_root),
            HashPart::Str(sequencer_committee_root),
            HashPart::Int(l2_start_height as i128),
            HashPart::Int(l2_end_height as i128),
        ],
        32,
    )
}

pub fn state_transition_proof_input_id(
    batch_id: &str,
    previous_state_root: &str,
    next_state_root: &str,
    public_input_root: &str,
    l2_start_height: u64,
    l2_end_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-STATE-TRANSITION-INPUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(previous_state_root),
            HashPart::Str(next_state_root),
            HashPart::Str(public_input_root),
            HashPart::Int(l2_start_height as i128),
            HashPart::Int(l2_end_height as i128),
        ],
        32,
    )
}

pub fn state_transition_proof_input_root(input: &StateTransitionProofInput) -> String {
    domain_hash(
        "VALIDITY-STATE-TRANSITION-INPUT",
        &[HashPart::Json(&input.public_record())],
        32,
    )
}

pub fn state_transition_proof_input_set_root(inputs: &[StateTransitionProofInput]) -> String {
    let mut records = inputs
        .iter()
        .map(|input| (input.input_id.clone(), input.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-STATE-TRANSITION-INPUT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn monero_bridge_public_input_root(
    bridge_event_id: &str,
    monero_network: &str,
    monero_txid_hash: &str,
    monero_block_hash: &str,
    monero_block_height: u64,
    confirmation_depth: u64,
    reserve_root: &str,
    deposit_root: &str,
    withdrawal_root: &str,
    signer_set_root: &str,
    amount_bucket: u64,
    recipient_commitment: &str,
) -> String {
    domain_hash(
        "VALIDITY-MONERO-BRIDGE-PUBLIC-INPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bridge_event_id),
            HashPart::Str(monero_network),
            HashPart::Str(monero_txid_hash),
            HashPart::Str(monero_block_hash),
            HashPart::Int(monero_block_height as i128),
            HashPart::Int(confirmation_depth as i128),
            HashPart::Str(reserve_root),
            HashPart::Str(deposit_root),
            HashPart::Str(withdrawal_root),
            HashPart::Str(signer_set_root),
            HashPart::Int(amount_bucket as i128),
            HashPart::Str(recipient_commitment),
        ],
        32,
    )
}

pub fn monero_bridge_proof_input_id(
    bridge_event_id: &str,
    monero_network: &str,
    monero_txid_hash: &str,
    public_input_root: &str,
    monero_block_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-MONERO-BRIDGE-INPUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bridge_event_id),
            HashPart::Str(monero_network),
            HashPart::Str(monero_txid_hash),
            HashPart::Str(public_input_root),
            HashPart::Int(monero_block_height as i128),
        ],
        32,
    )
}

pub fn monero_bridge_proof_input_root(input: &MoneroBridgeProofInput) -> String {
    domain_hash(
        "VALIDITY-MONERO-BRIDGE-INPUT",
        &[HashPart::Json(&input.public_record())],
        32,
    )
}

pub fn monero_bridge_proof_input_set_root(inputs: &[MoneroBridgeProofInput]) -> String {
    let mut records = inputs
        .iter()
        .map(|input| (input.input_id.clone(), input.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-MONERO-BRIDGE-INPUT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn contract_execution_public_input_root(
    execution_id: &str,
    contract_id: &str,
    call_id: &str,
    caller_commitment: &str,
    method_id: &str,
    pre_state_root: &str,
    post_state_root: &str,
    storage_read_root: &str,
    storage_write_root: &str,
    event_root: &str,
    host_receipt_root: &str,
    trap_root: &str,
    gas_used: u64,
) -> String {
    domain_hash(
        "VALIDITY-CONTRACT-EXECUTION-PUBLIC-INPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(execution_id),
            HashPart::Str(contract_id),
            HashPart::Str(call_id),
            HashPart::Str(caller_commitment),
            HashPart::Str(method_id),
            HashPart::Str(pre_state_root),
            HashPart::Str(post_state_root),
            HashPart::Str(storage_read_root),
            HashPart::Str(storage_write_root),
            HashPart::Str(event_root),
            HashPart::Str(host_receipt_root),
            HashPart::Str(trap_root),
            HashPart::Int(gas_used as i128),
        ],
        32,
    )
}

pub fn contract_execution_proof_input_id(
    execution_id: &str,
    contract_id: &str,
    call_id: &str,
    post_state_root: &str,
    public_input_root: &str,
) -> String {
    domain_hash(
        "VALIDITY-CONTRACT-EXECUTION-INPUT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(execution_id),
            HashPart::Str(contract_id),
            HashPart::Str(call_id),
            HashPart::Str(post_state_root),
            HashPart::Str(public_input_root),
        ],
        32,
    )
}

pub fn contract_execution_proof_input_root(input: &ContractExecutionProofInput) -> String {
    domain_hash(
        "VALIDITY-CONTRACT-EXECUTION-INPUT",
        &[HashPart::Json(&input.public_record())],
        32,
    )
}

pub fn contract_execution_proof_input_set_root(inputs: &[ContractExecutionProofInput]) -> String {
    let mut records = inputs
        .iter()
        .map(|input| (input.input_id.clone(), input.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-CONTRACT-EXECUTION-INPUT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn validity_proof_id(
    proof_kind: &str,
    manifest_id: &str,
    committee_id: &str,
    source_input_id: &str,
    public_input_root: &str,
    proof_commitment: &str,
) -> String {
    domain_hash(
        "VALIDITY-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_kind),
            HashPart::Str(manifest_id),
            HashPart::Str(committee_id),
            HashPart::Str(source_input_id),
            HashPart::Str(public_input_root),
            HashPart::Str(proof_commitment),
        ],
        32,
    )
}

pub fn validity_proof_root(proof: &ValidityProofRecord) -> String {
    domain_hash(
        "VALIDITY-PROOF",
        &[HashPart::Json(&proof.public_record())],
        32,
    )
}

pub fn validity_proof_set_root(proofs: &[ValidityProofRecord]) -> String {
    let mut records = proofs
        .iter()
        .map(|proof| (proof.proof_id.clone(), proof.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-PROOF",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn recursive_batch_public_input_root(
    batch_number: u64,
    parent_batch_id: &str,
    child_proof_root: &str,
    state_transition_input_root: &str,
    monero_bridge_input_root: &str,
    contract_execution_input_root: &str,
    recursion_depth: u64,
    l2_start_height: u64,
    l2_end_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-RECURSIVE-BATCH-PUBLIC-INPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(batch_number as i128),
            HashPart::Str(parent_batch_id),
            HashPart::Str(child_proof_root),
            HashPart::Str(state_transition_input_root),
            HashPart::Str(monero_bridge_input_root),
            HashPart::Str(contract_execution_input_root),
            HashPart::Int(recursion_depth as i128),
            HashPart::Int(l2_start_height as i128),
            HashPart::Int(l2_end_height as i128),
        ],
        32,
    )
}

pub fn recursive_accumulator_root(
    child_proof_root: &str,
    public_input_root: &str,
    recursion_depth: u64,
    child_count: u64,
) -> String {
    domain_hash(
        "VALIDITY-RECURSIVE-ACCUMULATOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(child_proof_root),
            HashPart::Str(public_input_root),
            HashPart::Int(recursion_depth as i128),
            HashPart::Int(child_count as i128),
        ],
        32,
    )
}

pub fn recursive_proof_batch_id(
    batch_number: u64,
    parent_batch_id: &str,
    plan_id: &str,
    manifest_id: &str,
    public_input_root: &str,
    accumulator_root: &str,
) -> String {
    domain_hash(
        "VALIDITY-RECURSIVE-PROOF-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(batch_number as i128),
            HashPart::Str(parent_batch_id),
            HashPart::Str(plan_id),
            HashPart::Str(manifest_id),
            HashPart::Str(public_input_root),
            HashPart::Str(accumulator_root),
        ],
        32,
    )
}

pub fn recursive_proof_batch_root(batch: &RecursiveProofBatch) -> String {
    domain_hash(
        "VALIDITY-RECURSIVE-PROOF-BATCH",
        &[HashPart::Json(&batch.public_record())],
        32,
    )
}

pub fn recursive_proof_batch_set_root(batches: &[RecursiveProofBatch]) -> String {
    let mut records = batches
        .iter()
        .map(|batch| (batch.batch_id.clone(), batch.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-RECURSIVE-PROOF-BATCH",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn proof_compression_receipt_id(
    source_proof_root: &str,
    compressed_proof_id: &str,
    compressed_proof_commitment: &str,
    compression_ratio_bps: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-PROOF-COMPRESSION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(source_proof_root),
            HashPart::Str(compressed_proof_id),
            HashPart::Str(compressed_proof_commitment),
            HashPart::Int(compression_ratio_bps as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn proof_compression_receipt_root(receipt: &ProofCompressionReceipt) -> String {
    domain_hash(
        "VALIDITY-PROOF-COMPRESSION-RECEIPT",
        &[HashPart::Json(&receipt.public_record())],
        32,
    )
}

pub fn proof_compression_receipt_set_root(receipts: &[ProofCompressionReceipt]) -> String {
    let mut records = receipts
        .iter()
        .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-PROOF-COMPRESSION-RECEIPT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn fallback_challenge_id(
    challenge_kind: &str,
    target_kind: &str,
    target_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "VALIDITY-FALLBACK-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_kind),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn fallback_challenge_root(challenge: &FallbackChallengeRecord) -> String {
    domain_hash(
        "VALIDITY-FALLBACK-CHALLENGE",
        &[HashPart::Json(&challenge.public_record())],
        32,
    )
}

pub fn fallback_challenge_set_root(challenges: &[FallbackChallengeRecord]) -> String {
    let mut records = challenges
        .iter()
        .map(|challenge| (challenge.challenge_id.clone(), challenge.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "VALIDITY-FALLBACK-CHALLENGE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn validity_aggregation_state_root_from_record(record: &Value) -> String {
    domain_hash("VALIDITY-AGGREGATION-STATE", &[HashPart::Json(record)], 32)
}

pub fn validity_aggregation_state_root(state: &ValidityAggregationState) -> String {
    state.state_root()
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(VALIDITY_AGGREGATION_MAX_BPS)
        .checked_div(denominator)
        .unwrap_or(0)
}

pub fn mul_bps_round_up(value: u64, bps: u64) -> u64 {
    if value == 0 || bps == 0 {
        return 0;
    }
    value
        .saturating_mul(bps)
        .saturating_add(VALIDITY_AGGREGATION_MAX_BPS - 1)
        / VALIDITY_AGGREGATION_MAX_BPS
}

fn devnet_manifest(
    family: ValidityCircuitFamily,
    max_public_inputs: u64,
    max_witness_bytes: u64,
    target_proof_bytes: u64,
    max_child_proofs: u64,
    metadata: &Value,
) -> ValidityAggregationResult<CircuitFamilyManifest> {
    CircuitFamilyManifest::new(
        family,
        1,
        family.default_circuit_name(),
        deterministic_root(&format!("{}-verifier-key", family.as_str())),
        max_public_inputs,
        max_witness_bytes,
        target_proof_bytes,
        max_child_proofs,
        0,
        0,
        metadata,
    )
}

fn devnet_member(
    operator_id: &str,
    role: PqVerifierCommitteeRole,
    weight: u64,
    joined_at_height: u64,
) -> ValidityAggregationResult<PqVerifierMember> {
    PqVerifierMember::new(
        operator_id,
        role,
        weight,
        deterministic_root(&format!("{operator_id}-pq-public-key")),
        deterministic_root(&format!("{operator_id}-recovery-public-key")),
        deterministic_root(&format!("{operator_id}-stake")),
        deterministic_commitment(&format!("{operator_id}-endpoint")),
        joined_at_height,
        0,
    )
}

fn normalize_label(value: String) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn normalize_unique_strings(
    values: Vec<String>,
    label: &str,
) -> ValidityAggregationResult<Vec<String>> {
    let mut values = values
        .into_iter()
        .map(normalize_label)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    if values.is_empty() {
        return Err(format!("{label} list cannot be empty"));
    }
    Ok(values)
}

fn ensure_non_empty(value: &str, label: &str) -> ValidityAggregationResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(value: &str, label: &str) -> ValidityAggregationResult<()> {
    ensure_non_empty(value, label)?;
    if value.len() < 32 {
        return Err(format!("{label} is too short"));
    }
    if !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be hex encoded"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> ValidityAggregationResult<()> {
    if allowed.iter().any(|candidate| candidate == &value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported"))
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> ValidityAggregationResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> ValidityAggregationResult<String> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id.clone(), record);
    Ok(id)
}
