use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DecentralizedProverStakingResult<T> = Result<T, String>;

pub const DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION: &str =
    "nebula-l2-decentralized-prover-staking-v1";
pub const DECENTRALIZED_PROVER_STAKING_SCHEMA_VERSION: u64 = 1;
pub const DECENTRALIZED_PROVER_STAKING_HASH_SUITE: &str = "SHAKE256";
pub const DECENTRALIZED_PROVER_STAKING_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const DECENTRALIZED_PROVER_STAKING_PQ_DELEGATION_SCHEME: &str =
    "ML-DSA-65-delegated-stake-authorization-v1";
pub const DECENTRALIZED_PROVER_STAKING_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const DECENTRALIZED_PROVER_STAKING_PERFORMANCE_ATTESTATION_SCHEME: &str =
    "zk-private-prover-performance-attestation-v1";
pub const DECENTRALIZED_PROVER_STAKING_SLASHING_EVIDENCE_SCHEME: &str =
    "shake256-prover-slashing-evidence-v1";
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_UNBONDING_BLOCKS: u64 = 4_320;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_ASSIGNMENT_SLA_BLOCKS: u64 = 8;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_SECURITY_BITS: u64 = 128;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_PROVER_STAKE_UNITS: u64 = 10_000;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_DELEGATION_UNITS: u64 = 500;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_SPONSOR_POOL_UNITS: u64 = 100;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_MAX_ACTIVE_ASSIGNMENTS: u64 = 32;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_REWARD_TAKE_BPS: u64 = 1_000;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_DELEGATOR_REWARD_BPS: u64 = 7_000;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_LATE_SLASH_BPS: u64 = 1_500;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_FAULT_SLASH_BPS: u64 = 10_000;
pub const DECENTRALIZED_PROVER_STAKING_DEFAULT_PRIVACY_SET_SIZE: u64 = 64;
pub const DECENTRALIZED_PROVER_STAKING_LOW_FEE_TARGET_UNITS: u64 = 2;
pub const DECENTRALIZED_PROVER_STAKING_MAX_BPS: u64 = 10_000;
pub const DECENTRALIZED_PROVER_STAKING_MAX_RECORDS: usize = 8_192;

pub const DECENTRALIZED_PROVER_STATUS_ACTIVE: &str = "active";
pub const DECENTRALIZED_PROVER_STATUS_PAUSED: &str = "paused";
pub const DECENTRALIZED_PROVER_STATUS_UNBONDING: &str = "unbonding";
pub const DECENTRALIZED_PROVER_STATUS_SLASHED: &str = "slashed";
pub const DECENTRALIZED_PROVER_STATUS_EXITED: &str = "exited";
pub const DECENTRALIZED_PROVER_STATUS_OPEN: &str = "open";
pub const DECENTRALIZED_PROVER_STATUS_ASSIGNED: &str = "assigned";
pub const DECENTRALIZED_PROVER_STATUS_PROVING: &str = "proving";
pub const DECENTRALIZED_PROVER_STATUS_PROVED: &str = "proved";
pub const DECENTRALIZED_PROVER_STATUS_VERIFIED: &str = "verified";
pub const DECENTRALIZED_PROVER_STATUS_REWARDED: &str = "rewarded";
pub const DECENTRALIZED_PROVER_STATUS_EXPIRED: &str = "expired";
pub const DECENTRALIZED_PROVER_STATUS_CHALLENGED: &str = "challenged";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverStakeRole {
    Prover,
    Delegator,
    Sponsor,
    Verifier,
    Watchtower,
}

impl ProverStakeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prover => "prover",
            Self::Delegator => "delegator",
            Self::Sponsor => "sponsor",
            Self::Verifier => "verifier",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverWorkerClass {
    Cpu,
    Gpu,
    Fpga,
    Asic,
    RecursiveCluster,
    ConfidentialGpu,
    Verifier,
}

impl ProverWorkerClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Fpga => "fpga",
            Self::Asic => "asic",
            Self::RecursiveCluster => "recursive_cluster",
            Self::ConfidentialGpu => "confidential_gpu",
            Self::Verifier => "verifier",
        }
    }

    pub fn capacity_weight(self) -> u64 {
        match self {
            Self::Cpu => 1,
            Self::Gpu => 8,
            Self::Fpga => 12,
            Self::Asic => 18,
            Self::RecursiveCluster => 20,
            Self::ConfidentialGpu => 10,
            Self::Verifier => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverStakeBucketKind {
    BaseBond,
    CapacityBond,
    DelegatedStake,
    LowFeeLaneBond,
    BridgeRiskBond,
    RecursivePqBond,
    WatchtowerBond,
}

impl ProverStakeBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseBond => "base_bond",
            Self::CapacityBond => "capacity_bond",
            Self::DelegatedStake => "delegated_stake",
            Self::LowFeeLaneBond => "low_fee_lane_bond",
            Self::BridgeRiskBond => "bridge_risk_bond",
            Self::RecursivePqBond => "recursive_pq_bond",
            Self::WatchtowerBond => "watchtower_bond",
        }
    }

    pub fn slashable(self) -> bool {
        !matches!(self, Self::DelegatedStake)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverAssignmentLane {
    L2Batch,
    PrivateDefiCall,
    MoneroBridge,
    RecursivePqProof,
    LowFeeSponsored,
    SmartContractExecution,
    EmergencyExit,
}

impl ProverAssignmentLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L2Batch => "l2_batch",
            Self::PrivateDefiCall => "private_defi_call",
            Self::MoneroBridge => "monero_bridge",
            Self::RecursivePqProof => "recursive_pq_proof",
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::SmartContractExecution => "smart_contract_execution",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::MoneroBridge => 9_200,
            Self::PrivateDefiCall => 8_800,
            Self::SmartContractExecution => 8_000,
            Self::L2Batch => 7_500,
            Self::RecursivePqProof => 7_000,
            Self::LowFeeSponsored => 6_500,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateDefiCall
                | Self::MoneroBridge
                | Self::LowFeeSponsored
                | Self::SmartContractExecution
                | Self::EmergencyExit
        )
    }

    pub fn low_fee_lane(self) -> bool {
        matches!(self, Self::LowFeeSponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverAssignmentKind {
    BatchStateProof,
    PrivateDefiProof,
    BridgeValidityProof,
    RecursiveAggregationProof,
    PqVerificationProof,
    SponsoredFeeProof,
    ContractExecutionProof,
}

impl ProverAssignmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchStateProof => "batch_state_proof",
            Self::PrivateDefiProof => "private_defi_proof",
            Self::BridgeValidityProof => "bridge_validity_proof",
            Self::RecursiveAggregationProof => "recursive_aggregation_proof",
            Self::PqVerificationProof => "pq_verification_proof",
            Self::SponsoredFeeProof => "sponsored_fee_proof",
            Self::ContractExecutionProof => "contract_execution_proof",
        }
    }

    pub fn default_proof_system(self) -> &'static str {
        match self {
            Self::BatchStateProof => "nebula-devnet-pq-l2-batch-state-v1",
            Self::PrivateDefiProof => "nebula-devnet-pq-private-defi-call-v1",
            Self::BridgeValidityProof => "nebula-devnet-pq-monero-bridge-validity-v1",
            Self::RecursiveAggregationProof => "nebula-devnet-recursive-pq-aggregate-v1",
            Self::PqVerificationProof => "nebula-devnet-pq-proof-verification-v1",
            Self::SponsoredFeeProof => "nebula-devnet-low-fee-sponsored-proof-v1",
            Self::ContractExecutionProof => "nebula-devnet-confidential-contract-execution-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverAssignmentStatus {
    Open,
    Assigned,
    Proving,
    Proved,
    Verified,
    Rewarded,
    Expired,
    Challenged,
    Slashed,
}

impl ProverAssignmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => DECENTRALIZED_PROVER_STATUS_OPEN,
            Self::Assigned => DECENTRALIZED_PROVER_STATUS_ASSIGNED,
            Self::Proving => DECENTRALIZED_PROVER_STATUS_PROVING,
            Self::Proved => DECENTRALIZED_PROVER_STATUS_PROVED,
            Self::Verified => DECENTRALIZED_PROVER_STATUS_VERIFIED,
            Self::Rewarded => DECENTRALIZED_PROVER_STATUS_REWARDED,
            Self::Expired => DECENTRALIZED_PROVER_STATUS_EXPIRED,
            Self::Challenged => DECENTRALIZED_PROVER_STATUS_CHALLENGED,
            Self::Slashed => DECENTRALIZED_PROVER_STATUS_SLASHED,
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Assigned | Self::Proving)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    InvalidProof,
    LateProof,
    WithheldWitness,
    DoubleAssignmentEquivocation,
    IdentityKeyCompromise,
    PrivacyLeak,
    SponsorPoolAbuse,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProof => "invalid_proof",
            Self::LateProof => "late_proof",
            Self::WithheldWitness => "withheld_witness",
            Self::DoubleAssignmentEquivocation => "double_assignment_equivocation",
            Self::IdentityKeyCompromise => "identity_key_compromise",
            Self::PrivacyLeak => "privacy_leak",
            Self::SponsorPoolAbuse => "sponsor_pool_abuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceAttestationBucket {
    LowLatency,
    NormalLatency,
    Congested,
    HighReliability,
    PrivacyPreserving,
    LowFeeFriendly,
}

impl PerformanceAttestationBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowLatency => "low_latency",
            Self::NormalLatency => "normal_latency",
            Self::Congested => "congested",
            Self::HighReliability => "high_reliability",
            Self::PrivacyPreserving => "privacy_preserving",
            Self::LowFeeFriendly => "low_fee_friendly",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedProverStakingConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub unbonding_blocks: u64,
    pub assignment_sla_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_pq_security_bits: u64,
    pub min_prover_stake_units: u64,
    pub min_delegation_units: u64,
    pub min_sponsor_pool_units: u64,
    pub max_active_assignments_per_prover: u64,
    pub protocol_reward_take_bps: u64,
    pub delegator_reward_bps: u64,
    pub late_slash_bps: u64,
    pub fault_slash_bps: u64,
    pub privacy_set_size: u64,
    pub pq_signature_scheme: String,
    pub pq_delegation_scheme: String,
    pub pq_kem_scheme: String,
    pub performance_attestation_scheme: String,
    pub slashing_evidence_scheme: String,
}

impl Default for DecentralizedProverStakingConfig {
    fn default() -> Self {
        Self {
            protocol_version: DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION.to_string(),
            schema_version: DECENTRALIZED_PROVER_STAKING_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DECENTRALIZED_PROVER_STAKING_DEFAULT_FEE_ASSET_ID.to_string(),
            epoch_blocks: DECENTRALIZED_PROVER_STAKING_DEFAULT_EPOCH_BLOCKS,
            unbonding_blocks: DECENTRALIZED_PROVER_STAKING_DEFAULT_UNBONDING_BLOCKS,
            assignment_sla_blocks: DECENTRALIZED_PROVER_STAKING_DEFAULT_ASSIGNMENT_SLA_BLOCKS,
            challenge_window_blocks: DECENTRALIZED_PROVER_STAKING_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_pq_security_bits: DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_SECURITY_BITS,
            min_prover_stake_units: DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_PROVER_STAKE_UNITS,
            min_delegation_units: DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_DELEGATION_UNITS,
            min_sponsor_pool_units: DECENTRALIZED_PROVER_STAKING_DEFAULT_MIN_SPONSOR_POOL_UNITS,
            max_active_assignments_per_prover:
                DECENTRALIZED_PROVER_STAKING_DEFAULT_MAX_ACTIVE_ASSIGNMENTS,
            protocol_reward_take_bps: DECENTRALIZED_PROVER_STAKING_DEFAULT_REWARD_TAKE_BPS,
            delegator_reward_bps: DECENTRALIZED_PROVER_STAKING_DEFAULT_DELEGATOR_REWARD_BPS,
            late_slash_bps: DECENTRALIZED_PROVER_STAKING_DEFAULT_LATE_SLASH_BPS,
            fault_slash_bps: DECENTRALIZED_PROVER_STAKING_DEFAULT_FAULT_SLASH_BPS,
            privacy_set_size: DECENTRALIZED_PROVER_STAKING_DEFAULT_PRIVACY_SET_SIZE,
            pq_signature_scheme: DECENTRALIZED_PROVER_STAKING_PQ_SIGNATURE_SCHEME.to_string(),
            pq_delegation_scheme: DECENTRALIZED_PROVER_STAKING_PQ_DELEGATION_SCHEME.to_string(),
            pq_kem_scheme: DECENTRALIZED_PROVER_STAKING_PQ_KEM_SCHEME.to_string(),
            performance_attestation_scheme:
                DECENTRALIZED_PROVER_STAKING_PERFORMANCE_ATTESTATION_SCHEME.to_string(),
            slashing_evidence_scheme: DECENTRALIZED_PROVER_STAKING_SLASHING_EVIDENCE_SCHEME
                .to_string(),
        }
    }
}

impl DecentralizedProverStakingConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 240,
            unbonding_blocks: 1_440,
            assignment_sla_blocks: 6,
            challenge_window_blocks: 72,
            privacy_set_size: 32,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_prover_staking_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": DECENTRALIZED_PROVER_STAKING_HASH_SUITE,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "unbonding_blocks": self.unbonding_blocks,
            "assignment_sla_blocks": self.assignment_sla_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_prover_stake_units": self.min_prover_stake_units,
            "min_delegation_units": self.min_delegation_units,
            "min_sponsor_pool_units": self.min_sponsor_pool_units,
            "max_active_assignments_per_prover": self.max_active_assignments_per_prover,
            "protocol_reward_take_bps": self.protocol_reward_take_bps,
            "delegator_reward_bps": self.delegator_reward_bps,
            "late_slash_bps": self.late_slash_bps,
            "fault_slash_bps": self.fault_slash_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_delegation_scheme": self.pq_delegation_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "performance_attestation_scheme": self.performance_attestation_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_eq_str(
            &self.protocol_version,
            DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "protocol version",
        )?;
        ensure_eq_u64(
            self.schema_version,
            DECENTRALIZED_PROVER_STAKING_SCHEMA_VERSION,
            "schema version",
        )?;
        ensure_eq_str(&self.chain_id, CHAIN_ID, "chain id")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_positive(self.epoch_blocks, "epoch blocks")?;
        ensure_positive(self.unbonding_blocks, "unbonding blocks")?;
        ensure_positive(self.assignment_sla_blocks, "assignment SLA blocks")?;
        ensure_positive(self.challenge_window_blocks, "challenge window blocks")?;
        ensure_positive(self.min_pq_security_bits, "minimum PQ security bits")?;
        ensure_positive(self.min_prover_stake_units, "minimum prover stake")?;
        ensure_positive(self.min_delegation_units, "minimum delegation")?;
        ensure_positive(self.min_sponsor_pool_units, "minimum sponsor pool")?;
        ensure_positive(
            self.max_active_assignments_per_prover,
            "max active assignments per prover",
        )?;
        ensure_bps(self.protocol_reward_take_bps, "protocol reward take bps")?;
        ensure_bps(self.delegator_reward_bps, "delegator reward bps")?;
        ensure_bps(self.late_slash_bps, "late slash bps")?;
        ensure_bps(self.fault_slash_bps, "fault slash bps")?;
        ensure_positive(self.privacy_set_size, "privacy set size")?;
        ensure_non_empty(&self.pq_signature_scheme, "PQ signature scheme")?;
        ensure_non_empty(&self.pq_delegation_scheme, "PQ delegation scheme")?;
        ensure_non_empty(&self.pq_kem_scheme, "PQ KEM scheme")?;
        ensure_non_empty(
            &self.performance_attestation_scheme,
            "performance attestation scheme",
        )?;
        ensure_non_empty(&self.slashing_evidence_scheme, "slashing evidence scheme")?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqIdentityCommitment {
    pub identity_id: String,
    pub participant_label: String,
    pub role: ProverStakeRole,
    pub pq_public_key_root: String,
    pub pq_authorization_root: String,
    pub recovery_key_root: String,
    pub endpoint_commitment: String,
    pub rate_limit_nullifier_root: String,
    pub privacy_group_root: String,
    pub security_bits: u64,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl PqIdentityCommitment {
    pub fn new(
        participant_label: &str,
        role: ProverStakeRole,
        pq_public_key_root: &str,
        pq_authorization_root: &str,
        recovery_key_root: &str,
        endpoint_commitment: &str,
        security_bits: u64,
        registered_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(participant_label, "participant label")?;
        ensure_non_empty(pq_public_key_root, "PQ public key root")?;
        ensure_non_empty(pq_authorization_root, "PQ authorization root")?;
        ensure_non_empty(recovery_key_root, "recovery key root")?;
        ensure_non_empty(endpoint_commitment, "endpoint commitment")?;
        ensure_positive(security_bits, "security bits")?;
        if expires_at_height != 0 && expires_at_height < registered_at_height {
            return Err("identity expires before registration".to_string());
        }
        let identity_id = prover_identity_id(
            participant_label,
            role,
            pq_public_key_root,
            registered_at_height,
            nonce,
        );
        Ok(Self {
            identity_id,
            participant_label: participant_label.to_string(),
            role,
            pq_public_key_root: pq_public_key_root.to_string(),
            pq_authorization_root: pq_authorization_root.to_string(),
            recovery_key_root: recovery_key_root.to_string(),
            endpoint_commitment: endpoint_commitment.to_string(),
            rate_limit_nullifier_root: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-RATE-LIMIT-NULLIFIER",
                &[
                    HashPart::Str(participant_label),
                    HashPart::Str(role.as_str()),
                    HashPart::Int(nonce as i128),
                ],
                32,
            ),
            privacy_group_root: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-PRIVACY-GROUP",
                &[
                    HashPart::Str(role.as_str()),
                    HashPart::Str(pq_public_key_root),
                    HashPart::Int(registered_at_height as i128),
                ],
                32,
            ),
            security_bits,
            registered_at_height,
            expires_at_height,
            nonce,
            status: DECENTRALIZED_PROVER_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == DECENTRALIZED_PROVER_STATUS_ACTIVE
            && self.registered_at_height <= height
            && (self.expires_at_height == 0 || self.expires_at_height >= height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_identity_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "identity_id": self.identity_id,
            "participant_label": self.participant_label,
            "role": self.role.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "pq_authorization_root": self.pq_authorization_root,
            "recovery_key_root": self.recovery_key_root,
            "endpoint_commitment": self.endpoint_commitment,
            "rate_limit_nullifier_root": self.rate_limit_nullifier_root,
            "privacy_group_root": self.privacy_group_root,
            "security_bits": self.security_bits,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn commitment_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-IDENTITY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.identity_id, "identity id")?;
        ensure_non_empty(&self.participant_label, "participant label")?;
        ensure_non_empty(&self.pq_public_key_root, "PQ public key root")?;
        ensure_non_empty(&self.pq_authorization_root, "PQ authorization root")?;
        ensure_non_empty(&self.recovery_key_root, "recovery key root")?;
        ensure_non_empty(&self.endpoint_commitment, "endpoint commitment")?;
        ensure_non_empty(&self.rate_limit_nullifier_root, "rate limit nullifier root")?;
        ensure_non_empty(&self.privacy_group_root, "privacy group root")?;
        ensure_positive(self.security_bits, "security bits")?;
        if self.expires_at_height != 0 && self.expires_at_height < self.registered_at_height {
            return Err("identity expires before registration".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DECENTRALIZED_PROVER_STATUS_ACTIVE,
                DECENTRALIZED_PROVER_STATUS_PAUSED,
                DECENTRALIZED_PROVER_STATUS_SLASHED,
                DECENTRALIZED_PROVER_STATUS_EXITED,
            ],
            "identity status",
        )?;
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverStakeBucket {
    pub bucket_id: String,
    pub prover_id: String,
    pub owner_identity_id: String,
    pub bucket_kind: ProverStakeBucketKind,
    pub fee_asset_id: String,
    pub locked_units: u64,
    pub delegated_units: u64,
    pub slashable_units: u64,
    pub reserved_units: u64,
    pub reward_debt_units: u64,
    pub activation_height: u64,
    pub unlock_height: u64,
    pub nonce: u64,
    pub authorization_root: String,
    pub status: String,
}

impl ProverStakeBucket {
    pub fn new(
        prover_id: &str,
        owner_identity_id: &str,
        bucket_kind: ProverStakeBucketKind,
        fee_asset_id: &str,
        locked_units: u64,
        activation_height: u64,
        unlock_height: u64,
        authorization_root: &str,
        nonce: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(prover_id, "prover id")?;
        ensure_non_empty(owner_identity_id, "owner identity id")?;
        ensure_non_empty(fee_asset_id, "fee asset id")?;
        ensure_positive(locked_units, "locked units")?;
        ensure_non_empty(authorization_root, "authorization root")?;
        if unlock_height != 0 && unlock_height < activation_height {
            return Err("stake bucket unlocks before activation".to_string());
        }
        let bucket_id = prover_stake_bucket_id(
            prover_id,
            owner_identity_id,
            bucket_kind,
            activation_height,
            nonce,
        );
        let slashable_units = if bucket_kind.slashable() {
            locked_units
        } else {
            locked_units / 2
        };
        Ok(Self {
            bucket_id,
            prover_id: prover_id.to_string(),
            owner_identity_id: owner_identity_id.to_string(),
            bucket_kind,
            fee_asset_id: fee_asset_id.to_string(),
            locked_units,
            delegated_units: 0,
            slashable_units,
            reserved_units: 0,
            reward_debt_units: 0,
            activation_height,
            unlock_height,
            nonce,
            authorization_root: authorization_root.to_string(),
            status: DECENTRALIZED_PROVER_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.locked_units.saturating_sub(self.reserved_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == DECENTRALIZED_PROVER_STATUS_ACTIVE
            && self.activation_height <= height
            && (self.unlock_height == 0 || self.unlock_height >= height)
    }

    pub fn reserve(&mut self, units: u64) -> DecentralizedProverStakingResult<()> {
        ensure_positive(units, "reserve units")?;
        if self.available_units() < units {
            return Err("stake bucket has insufficient available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn release(&mut self, units: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(units);
    }

    pub fn apply_slash(&mut self, units: u64) -> u64 {
        let slash_units = units.min(self.slashable_units).min(self.locked_units);
        self.locked_units = self.locked_units.saturating_sub(slash_units);
        self.slashable_units = self.slashable_units.saturating_sub(slash_units);
        self.reserved_units = self.reserved_units.min(self.locked_units);
        if self.locked_units == 0 {
            self.status = DECENTRALIZED_PROVER_STATUS_SLASHED.to_string();
        }
        slash_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_stake_bucket",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "prover_id": self.prover_id,
            "owner_identity_id": self.owner_identity_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "locked_units": self.locked_units,
            "delegated_units": self.delegated_units,
            "slashable_units": self.slashable_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "reward_debt_units": self.reward_debt_units,
            "activation_height": self.activation_height,
            "unlock_height": self.unlock_height,
            "nonce": self.nonce,
            "authorization_root": self.authorization_root,
            "status": self.status,
        })
    }

    pub fn bucket_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-BUCKET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.bucket_id, "bucket id")?;
        ensure_non_empty(&self.prover_id, "bucket prover id")?;
        ensure_non_empty(&self.owner_identity_id, "bucket owner identity id")?;
        ensure_non_empty(&self.fee_asset_id, "bucket fee asset id")?;
        ensure_positive(self.locked_units, "bucket locked units")?;
        if self.slashable_units > self.locked_units {
            return Err("bucket slashable units exceed locked units".to_string());
        }
        if self.reserved_units > self.locked_units {
            return Err("bucket reserved units exceed locked units".to_string());
        }
        if self.unlock_height != 0 && self.unlock_height < self.activation_height {
            return Err("stake bucket unlocks before activation".to_string());
        }
        ensure_non_empty(&self.authorization_root, "bucket authorization root")?;
        ensure_status(
            &self.status,
            &[
                DECENTRALIZED_PROVER_STATUS_ACTIVE,
                DECENTRALIZED_PROVER_STATUS_PAUSED,
                DECENTRALIZED_PROVER_STATUS_UNBONDING,
                DECENTRALIZED_PROVER_STATUS_SLASHED,
                DECENTRALIZED_PROVER_STATUS_EXITED,
            ],
            "stake bucket status",
        )?;
        Ok(self.bucket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationBond {
    pub delegation_id: String,
    pub delegator_identity_id: String,
    pub prover_id: String,
    pub bucket_id: String,
    pub fee_asset_id: String,
    pub delegated_units: u64,
    pub reward_share_bps: u64,
    pub authorization_root: String,
    pub nullifier: String,
    pub start_height: u64,
    pub unlock_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl DelegationBond {
    pub fn new(
        delegator_identity_id: &str,
        prover_id: &str,
        bucket_id: &str,
        fee_asset_id: &str,
        delegated_units: u64,
        reward_share_bps: u64,
        authorization_root: &str,
        start_height: u64,
        unlock_height: u64,
        nonce: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(delegator_identity_id, "delegator identity id")?;
        ensure_non_empty(prover_id, "delegation prover id")?;
        ensure_non_empty(bucket_id, "delegation bucket id")?;
        ensure_non_empty(fee_asset_id, "delegation fee asset id")?;
        ensure_positive(delegated_units, "delegated units")?;
        ensure_bps(reward_share_bps, "delegation reward share bps")?;
        ensure_non_empty(authorization_root, "delegation authorization root")?;
        if unlock_height != 0 && unlock_height < start_height {
            return Err("delegation unlocks before start".to_string());
        }
        let delegation_id = delegation_bond_id(
            delegator_identity_id,
            prover_id,
            bucket_id,
            delegated_units,
            start_height,
            nonce,
        );
        let nullifier = domain_hash(
            "DECENTRALIZED-PROVER-STAKING-DELEGATION-NULLIFIER",
            &[
                HashPart::Str(delegator_identity_id),
                HashPart::Str(prover_id),
                HashPart::Str(bucket_id),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        Ok(Self {
            delegation_id,
            delegator_identity_id: delegator_identity_id.to_string(),
            prover_id: prover_id.to_string(),
            bucket_id: bucket_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            delegated_units,
            reward_share_bps,
            authorization_root: authorization_root.to_string(),
            nullifier,
            start_height,
            unlock_height,
            nonce,
            status: DECENTRALIZED_PROVER_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == DECENTRALIZED_PROVER_STATUS_ACTIVE
            && self.start_height <= height
            && (self.unlock_height == 0 || self.unlock_height >= height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "delegation_bond",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "delegation_id": self.delegation_id,
            "delegator_identity_id": self.delegator_identity_id,
            "prover_id": self.prover_id,
            "bucket_id": self.bucket_id,
            "fee_asset_id": self.fee_asset_id,
            "delegated_units": self.delegated_units,
            "reward_share_bps": self.reward_share_bps,
            "authorization_root": self.authorization_root,
            "nullifier": self.nullifier,
            "start_height": self.start_height,
            "unlock_height": self.unlock_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn delegation_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-DELEGATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.delegation_id, "delegation id")?;
        ensure_non_empty(&self.delegator_identity_id, "delegator identity id")?;
        ensure_non_empty(&self.prover_id, "delegation prover id")?;
        ensure_non_empty(&self.bucket_id, "delegation bucket id")?;
        ensure_non_empty(&self.fee_asset_id, "delegation fee asset id")?;
        ensure_positive(self.delegated_units, "delegated units")?;
        ensure_bps(self.reward_share_bps, "delegation reward share bps")?;
        ensure_non_empty(&self.authorization_root, "delegation authorization root")?;
        ensure_non_empty(&self.nullifier, "delegation nullifier")?;
        if self.unlock_height != 0 && self.unlock_height < self.start_height {
            return Err("delegation unlocks before start".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DECENTRALIZED_PROVER_STATUS_ACTIVE,
                DECENTRALIZED_PROVER_STATUS_PAUSED,
                DECENTRALIZED_PROVER_STATUS_UNBONDING,
                DECENTRALIZED_PROVER_STATUS_SLASHED,
                DECENTRALIZED_PROVER_STATUS_EXITED,
            ],
            "delegation status",
        )?;
        Ok(self.delegation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverCapabilityProfile {
    pub capability_id: String,
    pub prover_id: String,
    pub worker_class: ProverWorkerClass,
    pub worker_count: u64,
    pub parallel_slots: u64,
    pub supported_lanes: BTreeSet<ProverAssignmentLane>,
    pub supported_proof_systems: BTreeSet<String>,
    pub max_cycles_per_block: u64,
    pub memory_mib: u64,
    pub trusted_execution_root: String,
    pub locality_commitment: String,
    pub min_fee_units: u64,
    pub low_fee_quota_per_epoch: u64,
    pub registered_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl ProverCapabilityProfile {
    pub fn new(
        prover_id: &str,
        worker_class: ProverWorkerClass,
        worker_count: u64,
        parallel_slots: u64,
        supported_lanes: BTreeSet<ProverAssignmentLane>,
        supported_proof_systems: BTreeSet<String>,
        max_cycles_per_block: u64,
        min_fee_units: u64,
        registered_at_height: u64,
        nonce: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(prover_id, "capability prover id")?;
        ensure_positive(worker_count, "worker count")?;
        ensure_positive(parallel_slots, "parallel slots")?;
        ensure_positive(max_cycles_per_block, "max cycles per block")?;
        let capability_id = prover_capability_id(
            prover_id,
            worker_class,
            worker_count,
            max_cycles_per_block,
            registered_at_height,
            nonce,
        );
        Ok(Self {
            capability_id,
            prover_id: prover_id.to_string(),
            worker_class,
            worker_count,
            parallel_slots,
            supported_lanes,
            supported_proof_systems,
            max_cycles_per_block,
            memory_mib: worker_count
                .saturating_mul(worker_class.capacity_weight())
                .saturating_mul(8_192),
            trusted_execution_root: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-TEE-ROOT",
                &[
                    HashPart::Str(prover_id),
                    HashPart::Str(worker_class.as_str()),
                    HashPart::Int(nonce as i128),
                ],
                32,
            ),
            locality_commitment: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-LOCALITY-COMMITMENT",
                &[
                    HashPart::Str(prover_id),
                    HashPart::Int(registered_at_height as i128),
                    HashPart::Int(nonce as i128),
                ],
                32,
            ),
            min_fee_units,
            low_fee_quota_per_epoch: parallel_slots.saturating_mul(4),
            registered_at_height,
            nonce,
            status: DECENTRALIZED_PROVER_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn supports_lane(&self, lane: ProverAssignmentLane) -> bool {
        self.supported_lanes.is_empty() || self.supported_lanes.contains(&lane)
    }

    pub fn supports_proof_system(&self, proof_system: &str) -> bool {
        self.supported_proof_systems.is_empty()
            || self.supported_proof_systems.contains(proof_system)
    }

    pub fn effective_capacity_units(&self) -> u64 {
        self.worker_count
            .saturating_mul(self.parallel_slots)
            .saturating_mul(self.worker_class.capacity_weight())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_capability_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "capability_id": self.capability_id,
            "prover_id": self.prover_id,
            "worker_class": self.worker_class.as_str(),
            "worker_count": self.worker_count,
            "parallel_slots": self.parallel_slots,
            "supported_lanes": self.supported_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "supported_proof_systems": self.supported_proof_systems,
            "max_cycles_per_block": self.max_cycles_per_block,
            "memory_mib": self.memory_mib,
            "trusted_execution_root": self.trusted_execution_root,
            "locality_commitment": self.locality_commitment,
            "min_fee_units": self.min_fee_units,
            "low_fee_quota_per_epoch": self.low_fee_quota_per_epoch,
            "effective_capacity_units": self.effective_capacity_units(),
            "registered_at_height": self.registered_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn capability_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-CAPABILITY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.capability_id, "capability id")?;
        ensure_non_empty(&self.prover_id, "capability prover id")?;
        ensure_positive(self.worker_count, "worker count")?;
        ensure_positive(self.parallel_slots, "parallel slots")?;
        ensure_positive(self.max_cycles_per_block, "max cycles per block")?;
        ensure_non_empty(&self.trusted_execution_root, "trusted execution root")?;
        ensure_non_empty(&self.locality_commitment, "locality commitment")?;
        ensure_status(
            &self.status,
            &[
                DECENTRALIZED_PROVER_STATUS_ACTIVE,
                DECENTRALIZED_PROVER_STATUS_PAUSED,
                DECENTRALIZED_PROVER_STATUS_SLASHED,
                DECENTRALIZED_PROVER_STATUS_EXITED,
            ],
            "capability status",
        )?;
        Ok(self.capability_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAssignmentQueue {
    pub queue_id: String,
    pub lane: ProverAssignmentLane,
    pub epoch: u64,
    pub priority_weight: u64,
    pub max_queue_depth: u64,
    pub pending_assignment_ids: BTreeSet<String>,
    pub sponsor_pool_ids: BTreeSet<String>,
    pub randomness_root: String,
    pub opened_at_height: u64,
    pub closed_at_height: u64,
    pub status: String,
}

impl ProofAssignmentQueue {
    pub fn new(
        lane: ProverAssignmentLane,
        epoch: u64,
        max_queue_depth: u64,
        randomness_root: &str,
        opened_at_height: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_positive(max_queue_depth, "queue max depth")?;
        ensure_non_empty(randomness_root, "queue randomness root")?;
        let queue_id = proof_assignment_queue_id(lane, epoch, randomness_root, opened_at_height);
        Ok(Self {
            queue_id,
            lane,
            epoch,
            priority_weight: lane.default_priority_weight(),
            max_queue_depth,
            pending_assignment_ids: BTreeSet::new(),
            sponsor_pool_ids: BTreeSet::new(),
            randomness_root: randomness_root.to_string(),
            opened_at_height,
            closed_at_height: 0,
            status: DECENTRALIZED_PROVER_STATUS_OPEN.to_string(),
        })
    }

    pub fn has_capacity(&self) -> bool {
        (self.pending_assignment_ids.len() as u64) < self.max_queue_depth
    }

    pub fn enqueue(&mut self, assignment_id: &str) -> DecentralizedProverStakingResult<()> {
        ensure_non_empty(assignment_id, "assignment id")?;
        if !self.has_capacity() {
            return Err("assignment queue is full".to_string());
        }
        self.pending_assignment_ids
            .insert(assignment_id.to_string());
        Ok(())
    }

    pub fn remove_assignment(&mut self, assignment_id: &str) {
        self.pending_assignment_ids.remove(assignment_id);
    }

    pub fn attach_sponsor_pool(
        &mut self,
        sponsor_pool_id: &str,
    ) -> DecentralizedProverStakingResult<()> {
        ensure_non_empty(sponsor_pool_id, "sponsor pool id")?;
        self.sponsor_pool_ids.insert(sponsor_pool_id.to_string());
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_assignment_queue",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "queue_id": self.queue_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "priority_weight": self.priority_weight,
            "max_queue_depth": self.max_queue_depth,
            "pending_assignment_ids": self.pending_assignment_ids,
            "pending_assignment_count": self.pending_assignment_ids.len() as u64,
            "sponsor_pool_ids": self.sponsor_pool_ids,
            "randomness_root": self.randomness_root,
            "opened_at_height": self.opened_at_height,
            "closed_at_height": self.closed_at_height,
            "status": self.status,
        })
    }

    pub fn queue_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-QUEUE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.queue_id, "queue id")?;
        ensure_positive(self.max_queue_depth, "queue max depth")?;
        if (self.pending_assignment_ids.len() as u64) > self.max_queue_depth {
            return Err("queue pending assignments exceed max depth".to_string());
        }
        ensure_non_empty(&self.randomness_root, "queue randomness root")?;
        if self.closed_at_height != 0 && self.closed_at_height < self.opened_at_height {
            return Err("queue closes before opening".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DECENTRALIZED_PROVER_STATUS_OPEN,
                DECENTRALIZED_PROVER_STATUS_ACTIVE,
                DECENTRALIZED_PROVER_STATUS_EXPIRED,
            ],
            "queue status",
        )?;
        Ok(self.queue_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAssignment {
    pub assignment_id: String,
    pub queue_id: String,
    pub requester_commitment: String,
    pub lane: ProverAssignmentLane,
    pub assignment_kind: ProverAssignmentKind,
    pub proof_system: String,
    pub public_input_root: String,
    pub witness_commitment: String,
    pub privacy_bucket_root: String,
    pub requested_cycles: u64,
    pub max_fee_units: u64,
    pub sponsor_pool_id: String,
    pub assigned_prover_id: String,
    pub assigned_bucket_id: String,
    pub assignment_seed: String,
    pub posted_at_height: u64,
    pub assigned_at_height: u64,
    pub proof_deadline_height: u64,
    pub completed_at_height: u64,
    pub proof_root: String,
    pub receipt_id: String,
    pub nonce: u64,
    pub status: ProverAssignmentStatus,
}

impl ProofAssignment {
    pub fn new(
        queue_id: &str,
        requester_commitment: &str,
        lane: ProverAssignmentLane,
        assignment_kind: ProverAssignmentKind,
        public_input_root: &str,
        witness_commitment: &str,
        privacy_bucket_root: &str,
        requested_cycles: u64,
        max_fee_units: u64,
        sponsor_pool_id: &str,
        posted_at_height: u64,
        sla_blocks: u64,
        nonce: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(queue_id, "assignment queue id")?;
        ensure_non_empty(requester_commitment, "requester commitment")?;
        ensure_non_empty(public_input_root, "assignment public input root")?;
        ensure_non_empty(witness_commitment, "assignment witness commitment")?;
        ensure_non_empty(privacy_bucket_root, "assignment privacy bucket root")?;
        ensure_positive(requested_cycles, "assignment requested cycles")?;
        ensure_positive(max_fee_units, "assignment max fee units")?;
        ensure_positive(sla_blocks, "assignment SLA blocks")?;
        let proof_system = assignment_kind.default_proof_system().to_string();
        let assignment_id = proof_assignment_id(
            queue_id,
            requester_commitment,
            lane,
            assignment_kind,
            public_input_root,
            posted_at_height,
            nonce,
        );
        let assignment_seed = domain_hash(
            "DECENTRALIZED-PROVER-STAKING-ASSIGNMENT-SEED",
            &[
                HashPart::Str(&assignment_id),
                HashPart::Str(public_input_root),
                HashPart::Str(witness_commitment),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        Ok(Self {
            assignment_id,
            queue_id: queue_id.to_string(),
            requester_commitment: requester_commitment.to_string(),
            lane,
            assignment_kind,
            proof_system,
            public_input_root: public_input_root.to_string(),
            witness_commitment: witness_commitment.to_string(),
            privacy_bucket_root: privacy_bucket_root.to_string(),
            requested_cycles,
            max_fee_units,
            sponsor_pool_id: sponsor_pool_id.to_string(),
            assigned_prover_id: String::new(),
            assigned_bucket_id: String::new(),
            assignment_seed,
            posted_at_height,
            assigned_at_height: 0,
            proof_deadline_height: posted_at_height.saturating_add(sla_blocks),
            completed_at_height: 0,
            proof_root: String::new(),
            receipt_id: String::new(),
            nonce,
            status: ProverAssignmentStatus::Open,
        })
    }

    pub fn assign(
        &mut self,
        prover_id: &str,
        bucket_id: &str,
        assigned_at_height: u64,
        sla_blocks: u64,
    ) -> DecentralizedProverStakingResult<()> {
        ensure_non_empty(prover_id, "assigned prover id")?;
        ensure_non_empty(bucket_id, "assigned bucket id")?;
        ensure_positive(sla_blocks, "assignment SLA blocks")?;
        if self.status != ProverAssignmentStatus::Open {
            return Err("assignment is not open".to_string());
        }
        self.assigned_prover_id = prover_id.to_string();
        self.assigned_bucket_id = bucket_id.to_string();
        self.assigned_at_height = assigned_at_height;
        self.proof_deadline_height = assigned_at_height.saturating_add(sla_blocks);
        self.status = ProverAssignmentStatus::Assigned;
        Ok(())
    }

    pub fn mark_proved(
        &mut self,
        proof_root: &str,
        completed_at_height: u64,
    ) -> DecentralizedProverStakingResult<()> {
        ensure_non_empty(proof_root, "assignment proof root")?;
        if !matches!(
            self.status,
            ProverAssignmentStatus::Assigned | ProverAssignmentStatus::Proving
        ) {
            return Err("assignment is not assigned or proving".to_string());
        }
        self.proof_root = proof_root.to_string();
        self.completed_at_height = completed_at_height;
        self.status = ProverAssignmentStatus::Proved;
        Ok(())
    }

    pub fn mark_verified(&mut self, receipt_id: &str) -> DecentralizedProverStakingResult<()> {
        ensure_non_empty(receipt_id, "verified receipt id")?;
        if self.status != ProverAssignmentStatus::Proved {
            return Err("assignment is not proved".to_string());
        }
        self.receipt_id = receipt_id.to_string();
        self.status = ProverAssignmentStatus::Verified;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_assignment",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "assignment_id": self.assignment_id,
            "queue_id": self.queue_id,
            "requester_commitment": self.requester_commitment,
            "lane": self.lane.as_str(),
            "lane_priority_weight": self.lane.default_priority_weight(),
            "privacy_sensitive": self.lane.privacy_sensitive(),
            "assignment_kind": self.assignment_kind.as_str(),
            "proof_system": self.proof_system,
            "public_input_root": self.public_input_root,
            "witness_commitment": self.witness_commitment,
            "privacy_bucket_root": self.privacy_bucket_root,
            "requested_cycles": self.requested_cycles,
            "max_fee_units": self.max_fee_units,
            "sponsor_pool_id": self.sponsor_pool_id,
            "assigned_prover_id": self.assigned_prover_id,
            "assigned_bucket_id": self.assigned_bucket_id,
            "assignment_seed": self.assignment_seed,
            "posted_at_height": self.posted_at_height,
            "assigned_at_height": self.assigned_at_height,
            "proof_deadline_height": self.proof_deadline_height,
            "completed_at_height": self.completed_at_height,
            "proof_root": self.proof_root,
            "receipt_id": self.receipt_id,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn assignment_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-ASSIGNMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.assignment_id, "assignment id")?;
        ensure_non_empty(&self.queue_id, "assignment queue id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "assignment requester commitment",
        )?;
        ensure_non_empty(&self.proof_system, "assignment proof system")?;
        ensure_non_empty(&self.public_input_root, "assignment public input root")?;
        ensure_non_empty(&self.witness_commitment, "assignment witness commitment")?;
        ensure_non_empty(&self.privacy_bucket_root, "assignment privacy bucket root")?;
        ensure_positive(self.requested_cycles, "assignment requested cycles")?;
        ensure_positive(self.max_fee_units, "assignment max fee units")?;
        ensure_non_empty(&self.assignment_seed, "assignment seed")?;
        if self.proof_deadline_height < self.posted_at_height {
            return Err("assignment proof deadline is before posting".to_string());
        }
        if self.status != ProverAssignmentStatus::Open {
            ensure_non_empty(&self.assigned_prover_id, "assigned prover id")?;
            ensure_non_empty(&self.assigned_bucket_id, "assigned bucket id")?;
            if self.assigned_at_height < self.posted_at_height {
                return Err("assignment assigned before posting".to_string());
            }
        }
        if matches!(
            self.status,
            ProverAssignmentStatus::Proved
                | ProverAssignmentStatus::Verified
                | ProverAssignmentStatus::Rewarded
        ) {
            ensure_non_empty(&self.proof_root, "assignment proof root")?;
            if self.completed_at_height < self.assigned_at_height {
                return Err("assignment completed before assignment".to_string());
            }
        }
        if matches!(
            self.status,
            ProverAssignmentStatus::Verified | ProverAssignmentStatus::Rewarded
        ) {
            ensure_non_empty(&self.receipt_id, "assignment receipt id")?;
        }
        Ok(self.assignment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorPool {
    pub sponsor_pool_id: String,
    pub sponsor_identity_id: String,
    pub lane: ProverAssignmentLane,
    pub fee_asset_id: String,
    pub total_budget_units: u64,
    pub spent_units: u64,
    pub max_fee_per_assignment_units: u64,
    pub beneficiary_root: String,
    pub authorization_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl LowFeeSponsorPool {
    pub fn new(
        sponsor_identity_id: &str,
        lane: ProverAssignmentLane,
        fee_asset_id: &str,
        total_budget_units: u64,
        max_fee_per_assignment_units: u64,
        beneficiary_root: &str,
        authorization_root: &str,
        valid_from_height: u64,
        valid_until_height: u64,
        nonce: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(sponsor_identity_id, "sponsor identity id")?;
        ensure_non_empty(fee_asset_id, "sponsor pool fee asset id")?;
        ensure_positive(total_budget_units, "sponsor pool total budget")?;
        ensure_positive(
            max_fee_per_assignment_units,
            "sponsor pool max fee per assignment",
        )?;
        ensure_non_empty(beneficiary_root, "sponsor pool beneficiary root")?;
        ensure_non_empty(authorization_root, "sponsor pool authorization root")?;
        if valid_until_height != 0 && valid_until_height < valid_from_height {
            return Err("sponsor pool expires before it becomes valid".to_string());
        }
        let sponsor_pool_id = sponsor_pool_id(
            sponsor_identity_id,
            lane,
            fee_asset_id,
            beneficiary_root,
            valid_from_height,
            nonce,
        );
        Ok(Self {
            sponsor_pool_id,
            sponsor_identity_id: sponsor_identity_id.to_string(),
            lane,
            fee_asset_id: fee_asset_id.to_string(),
            total_budget_units,
            spent_units: 0,
            max_fee_per_assignment_units,
            beneficiary_root: beneficiary_root.to_string(),
            authorization_root: authorization_root.to_string(),
            valid_from_height,
            valid_until_height,
            nonce,
            status: DECENTRALIZED_PROVER_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.total_budget_units.saturating_sub(self.spent_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == DECENTRALIZED_PROVER_STATUS_ACTIVE
            && self.valid_from_height <= height
            && (self.valid_until_height == 0 || self.valid_until_height >= height)
    }

    pub fn spend(&mut self, units: u64) -> DecentralizedProverStakingResult<()> {
        ensure_positive(units, "sponsor spend units")?;
        if units > self.max_fee_per_assignment_units {
            return Err("sponsor spend exceeds per-assignment cap".to_string());
        }
        if self.available_units() < units {
            return Err("sponsor pool has insufficient budget".to_string());
        }
        self.spent_units = self.spent_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "sponsor_pool_id": self.sponsor_pool_id,
            "sponsor_identity_id": self.sponsor_identity_id,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "total_budget_units": self.total_budget_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_per_assignment_units": self.max_fee_per_assignment_units,
            "beneficiary_root": self.beneficiary_root,
            "authorization_root": self.authorization_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn pool_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-SPONSOR-POOL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.sponsor_pool_id, "sponsor pool id")?;
        ensure_non_empty(&self.sponsor_identity_id, "sponsor identity id")?;
        ensure_non_empty(&self.fee_asset_id, "sponsor pool fee asset id")?;
        ensure_positive(self.total_budget_units, "sponsor pool total budget")?;
        ensure_positive(
            self.max_fee_per_assignment_units,
            "sponsor pool max fee per assignment",
        )?;
        if self.spent_units > self.total_budget_units {
            return Err("sponsor pool spent units exceed total budget".to_string());
        }
        ensure_non_empty(&self.beneficiary_root, "sponsor pool beneficiary root")?;
        ensure_non_empty(&self.authorization_root, "sponsor pool authorization root")?;
        if self.valid_until_height != 0 && self.valid_until_height < self.valid_from_height {
            return Err("sponsor pool expires before it becomes valid".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DECENTRALIZED_PROVER_STATUS_ACTIVE,
                DECENTRALIZED_PROVER_STATUS_PAUSED,
                DECENTRALIZED_PROVER_STATUS_EXPIRED,
                DECENTRALIZED_PROVER_STATUS_SLASHED,
            ],
            "sponsor pool status",
        )?;
        Ok(self.pool_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverRewardReceipt {
    pub reward_receipt_id: String,
    pub assignment_id: String,
    pub prover_id: String,
    pub bucket_id: String,
    pub sponsor_pool_id: String,
    pub fee_asset_id: String,
    pub gross_reward_units: u64,
    pub protocol_take_units: u64,
    pub delegator_reward_units: u64,
    pub prover_reward_units: u64,
    pub proof_root: String,
    pub settlement_root: String,
    pub paid_at_height: u64,
    pub nonce: u64,
}

impl ProverRewardReceipt {
    pub fn new(
        assignment_id: &str,
        prover_id: &str,
        bucket_id: &str,
        sponsor_pool_id: &str,
        fee_asset_id: &str,
        gross_reward_units: u64,
        protocol_take_bps: u64,
        delegator_reward_bps: u64,
        proof_root: &str,
        paid_at_height: u64,
        nonce: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(assignment_id, "reward assignment id")?;
        ensure_non_empty(prover_id, "reward prover id")?;
        ensure_non_empty(bucket_id, "reward bucket id")?;
        ensure_non_empty(fee_asset_id, "reward fee asset id")?;
        ensure_positive(gross_reward_units, "gross reward units")?;
        ensure_bps(protocol_take_bps, "protocol take bps")?;
        ensure_bps(delegator_reward_bps, "delegator reward bps")?;
        ensure_non_empty(proof_root, "reward proof root")?;
        let protocol_take_units = bps_amount(gross_reward_units, protocol_take_bps);
        let reward_after_protocol = gross_reward_units.saturating_sub(protocol_take_units);
        let delegator_reward_units = bps_amount(reward_after_protocol, delegator_reward_bps);
        let prover_reward_units = reward_after_protocol.saturating_sub(delegator_reward_units);
        let settlement_root = domain_hash(
            "DECENTRALIZED-PROVER-STAKING-REWARD-SETTLEMENT",
            &[
                HashPart::Str(assignment_id),
                HashPart::Str(prover_id),
                HashPart::Int(gross_reward_units as i128),
                HashPart::Int(paid_at_height as i128),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let reward_receipt_id = reward_receipt_id(
            assignment_id,
            prover_id,
            proof_root,
            gross_reward_units,
            paid_at_height,
            nonce,
        );
        Ok(Self {
            reward_receipt_id,
            assignment_id: assignment_id.to_string(),
            prover_id: prover_id.to_string(),
            bucket_id: bucket_id.to_string(),
            sponsor_pool_id: sponsor_pool_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            gross_reward_units,
            protocol_take_units,
            delegator_reward_units,
            prover_reward_units,
            proof_root: proof_root.to_string(),
            settlement_root,
            paid_at_height,
            nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_reward_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "reward_receipt_id": self.reward_receipt_id,
            "assignment_id": self.assignment_id,
            "prover_id": self.prover_id,
            "bucket_id": self.bucket_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_reward_units": self.gross_reward_units,
            "protocol_take_units": self.protocol_take_units,
            "delegator_reward_units": self.delegator_reward_units,
            "prover_reward_units": self.prover_reward_units,
            "proof_root": self.proof_root,
            "settlement_root": self.settlement_root,
            "paid_at_height": self.paid_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn receipt_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-REWARD-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.reward_receipt_id, "reward receipt id")?;
        ensure_non_empty(&self.assignment_id, "reward assignment id")?;
        ensure_non_empty(&self.prover_id, "reward prover id")?;
        ensure_non_empty(&self.bucket_id, "reward bucket id")?;
        ensure_non_empty(&self.fee_asset_id, "reward fee asset id")?;
        ensure_positive(self.gross_reward_units, "gross reward units")?;
        let distributed = self
            .protocol_take_units
            .saturating_add(self.delegator_reward_units)
            .saturating_add(self.prover_reward_units);
        if distributed != self.gross_reward_units {
            return Err("reward receipt distribution does not equal gross reward".to_string());
        }
        ensure_non_empty(&self.proof_root, "reward proof root")?;
        ensure_non_empty(&self.settlement_root, "reward settlement root")?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidenceRecord {
    pub evidence_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub target_prover_id: String,
    pub target_assignment_id: String,
    pub target_bucket_id: String,
    pub reporter_identity_id: String,
    pub evidence_root: String,
    pub transcript_root: String,
    pub privacy_leak_commitment: String,
    pub slash_units: u64,
    pub slash_bps: u64,
    pub observed_at_height: u64,
    pub challenge_deadline_height: u64,
    pub applied_at_height: u64,
    pub status: String,
}

impl SlashingEvidenceRecord {
    pub fn new(
        evidence_kind: SlashingEvidenceKind,
        target_prover_id: &str,
        target_assignment_id: &str,
        target_bucket_id: &str,
        reporter_identity_id: &str,
        evidence_root: &str,
        transcript_root: &str,
        slash_units: u64,
        slash_bps: u64,
        observed_at_height: u64,
        challenge_window_blocks: u64,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(target_prover_id, "slashing target prover id")?;
        ensure_non_empty(target_bucket_id, "slashing target bucket id")?;
        ensure_non_empty(reporter_identity_id, "slashing reporter identity id")?;
        ensure_non_empty(evidence_root, "slashing evidence root")?;
        ensure_non_empty(transcript_root, "slashing transcript root")?;
        ensure_positive(slash_units, "slashing units")?;
        ensure_bps(slash_bps, "slashing bps")?;
        ensure_positive(challenge_window_blocks, "slashing challenge window")?;
        let evidence_id = slashing_evidence_id(
            evidence_kind,
            target_prover_id,
            target_assignment_id,
            target_bucket_id,
            evidence_root,
            observed_at_height,
        );
        let privacy_leak_commitment = domain_hash(
            "DECENTRALIZED-PROVER-STAKING-SLASHING-PRIVACY-COMMITMENT",
            &[
                HashPart::Str(target_prover_id),
                HashPart::Str(target_assignment_id),
                HashPart::Str(evidence_root),
                HashPart::Str(evidence_kind.as_str()),
            ],
            32,
        );
        Ok(Self {
            evidence_id,
            evidence_kind,
            target_prover_id: target_prover_id.to_string(),
            target_assignment_id: target_assignment_id.to_string(),
            target_bucket_id: target_bucket_id.to_string(),
            reporter_identity_id: reporter_identity_id.to_string(),
            evidence_root: evidence_root.to_string(),
            transcript_root: transcript_root.to_string(),
            privacy_leak_commitment,
            slash_units,
            slash_bps,
            observed_at_height,
            challenge_deadline_height: observed_at_height.saturating_add(challenge_window_blocks),
            applied_at_height: 0,
            status: DECENTRALIZED_PROVER_STATUS_CHALLENGED.to_string(),
        })
    }

    pub fn mark_applied(&mut self, applied_at_height: u64) {
        self.applied_at_height = applied_at_height;
        self.status = DECENTRALIZED_PROVER_STATUS_SLASHED.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_evidence_record",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "slashing_evidence_scheme": DECENTRALIZED_PROVER_STAKING_SLASHING_EVIDENCE_SCHEME,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "target_prover_id": self.target_prover_id,
            "target_assignment_id": self.target_assignment_id,
            "target_bucket_id": self.target_bucket_id,
            "reporter_identity_id": self.reporter_identity_id,
            "evidence_root": self.evidence_root,
            "transcript_root": self.transcript_root,
            "privacy_leak_commitment": self.privacy_leak_commitment,
            "slash_units": self.slash_units,
            "slash_bps": self.slash_bps,
            "observed_at_height": self.observed_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "applied_at_height": self.applied_at_height,
            "status": self.status,
        })
    }

    pub fn evidence_root_hash(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-SLASHING-EVIDENCE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(&self.target_prover_id, "slashing target prover id")?;
        ensure_non_empty(&self.target_bucket_id, "slashing target bucket id")?;
        ensure_non_empty(&self.reporter_identity_id, "slashing reporter identity id")?;
        ensure_non_empty(&self.evidence_root, "slashing evidence root")?;
        ensure_non_empty(&self.transcript_root, "slashing transcript root")?;
        ensure_non_empty(
            &self.privacy_leak_commitment,
            "slashing privacy leak commitment",
        )?;
        ensure_positive(self.slash_units, "slashing units")?;
        ensure_bps(self.slash_bps, "slashing bps")?;
        if self.challenge_deadline_height < self.observed_at_height {
            return Err("slashing challenge deadline before observation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                DECENTRALIZED_PROVER_STATUS_CHALLENGED,
                DECENTRALIZED_PROVER_STATUS_SLASHED,
                DECENTRALIZED_PROVER_STATUS_VERIFIED,
            ],
            "slashing status",
        )?;
        Ok(self.evidence_root_hash())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPreservingPerformanceAttestation {
    pub attestation_id: String,
    pub prover_id: String,
    pub epoch: u64,
    pub bucket: PerformanceAttestationBucket,
    pub lane: ProverAssignmentLane,
    pub sample_set_root: String,
    pub latency_bucket_root: String,
    pub reliability_commitment: String,
    pub privacy_set_root: String,
    pub proof_root: String,
    pub assignments_sampled: u64,
    pub success_count_commitment: String,
    pub median_latency_commitment: String,
    pub attested_at_height: u64,
    pub verifier_committee_root: String,
}

impl PrivacyPreservingPerformanceAttestation {
    pub fn new(
        prover_id: &str,
        epoch: u64,
        bucket: PerformanceAttestationBucket,
        lane: ProverAssignmentLane,
        sample_set_root: &str,
        proof_root: &str,
        assignments_sampled: u64,
        attested_at_height: u64,
        verifier_committee_root: &str,
    ) -> DecentralizedProverStakingResult<Self> {
        ensure_non_empty(prover_id, "attestation prover id")?;
        ensure_non_empty(sample_set_root, "attestation sample set root")?;
        ensure_non_empty(proof_root, "attestation proof root")?;
        ensure_positive(assignments_sampled, "assignments sampled")?;
        ensure_non_empty(verifier_committee_root, "verifier committee root")?;
        let attestation_id = performance_attestation_id(
            prover_id,
            epoch,
            bucket,
            lane,
            sample_set_root,
            attested_at_height,
        );
        Ok(Self {
            attestation_id,
            prover_id: prover_id.to_string(),
            epoch,
            bucket,
            lane,
            sample_set_root: sample_set_root.to_string(),
            latency_bucket_root: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-LATENCY-BUCKET",
                &[
                    HashPart::Str(prover_id),
                    HashPart::Str(lane.as_str()),
                    HashPart::Str(bucket.as_str()),
                    HashPart::Int(epoch as i128),
                ],
                32,
            ),
            reliability_commitment: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-RELIABILITY-COMMITMENT",
                &[
                    HashPart::Str(prover_id),
                    HashPart::Str(sample_set_root),
                    HashPart::Int(assignments_sampled as i128),
                ],
                32,
            ),
            privacy_set_root: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-PERFORMANCE-PRIVACY-SET",
                &[
                    HashPart::Str(prover_id),
                    HashPart::Str(lane.as_str()),
                    HashPart::Int(epoch as i128),
                ],
                32,
            ),
            proof_root: proof_root.to_string(),
            assignments_sampled,
            success_count_commitment: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-SUCCESS-COUNT-COMMITMENT",
                &[
                    HashPart::Str(prover_id),
                    HashPart::Str(sample_set_root),
                    HashPart::Str(proof_root),
                ],
                32,
            ),
            median_latency_commitment: domain_hash(
                "DECENTRALIZED-PROVER-STAKING-MEDIAN-LATENCY-COMMITMENT",
                &[
                    HashPart::Str(prover_id),
                    HashPart::Str(bucket.as_str()),
                    HashPart::Int(attested_at_height as i128),
                ],
                32,
            ),
            attested_at_height,
            verifier_committee_root: verifier_committee_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_preserving_performance_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "attestation_scheme": DECENTRALIZED_PROVER_STAKING_PERFORMANCE_ATTESTATION_SCHEME,
            "attestation_id": self.attestation_id,
            "prover_id": self.prover_id,
            "epoch": self.epoch,
            "bucket": self.bucket.as_str(),
            "lane": self.lane.as_str(),
            "sample_set_root": self.sample_set_root,
            "latency_bucket_root": self.latency_bucket_root,
            "reliability_commitment": self.reliability_commitment,
            "privacy_set_root": self.privacy_set_root,
            "proof_root": self.proof_root,
            "assignments_sampled": self.assignments_sampled,
            "success_count_commitment": self.success_count_commitment,
            "median_latency_commitment": self.median_latency_commitment,
            "attested_at_height": self.attested_at_height,
            "verifier_committee_root": self.verifier_committee_root,
        })
    }

    pub fn attestation_root(&self) -> String {
        decentralized_prover_staking_payload_root(
            "DECENTRALIZED-PROVER-STAKING-PERFORMANCE-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.prover_id, "attestation prover id")?;
        ensure_non_empty(&self.sample_set_root, "attestation sample set root")?;
        ensure_non_empty(&self.latency_bucket_root, "attestation latency bucket root")?;
        ensure_non_empty(
            &self.reliability_commitment,
            "attestation reliability commitment",
        )?;
        ensure_non_empty(&self.privacy_set_root, "attestation privacy set root")?;
        ensure_non_empty(&self.proof_root, "attestation proof root")?;
        ensure_positive(self.assignments_sampled, "assignments sampled")?;
        ensure_non_empty(
            &self.success_count_commitment,
            "attestation success count commitment",
        )?;
        ensure_non_empty(
            &self.median_latency_commitment,
            "attestation median latency commitment",
        )?;
        ensure_non_empty(&self.verifier_committee_root, "verifier committee root")?;
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedProverStakingRoots {
    pub config_root: String,
    pub identity_root: String,
    pub stake_bucket_root: String,
    pub delegation_root: String,
    pub capability_root: String,
    pub queue_root: String,
    pub assignment_root: String,
    pub reward_receipt_root: String,
    pub sponsor_pool_root: String,
    pub slashing_evidence_root: String,
    pub performance_attestation_root: String,
    pub active_lane_index_root: String,
}

impl DecentralizedProverStakingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_prover_staking_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "identity_root": self.identity_root,
            "stake_bucket_root": self.stake_bucket_root,
            "delegation_root": self.delegation_root,
            "capability_root": self.capability_root,
            "queue_root": self.queue_root,
            "assignment_root": self.assignment_root,
            "reward_receipt_root": self.reward_receipt_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "performance_attestation_root": self.performance_attestation_root,
            "active_lane_index_root": self.active_lane_index_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedProverStakingCounters {
    pub identity_count: u64,
    pub active_prover_count: u64,
    pub stake_bucket_count: u64,
    pub delegation_count: u64,
    pub capability_count: u64,
    pub queue_count: u64,
    pub open_assignment_count: u64,
    pub active_assignment_count: u64,
    pub verified_assignment_count: u64,
    pub reward_receipt_count: u64,
    pub sponsor_pool_count: u64,
    pub active_sponsor_pool_count: u64,
    pub slashing_evidence_count: u64,
    pub performance_attestation_count: u64,
    pub total_locked_stake_units: u64,
    pub total_delegated_units: u64,
    pub total_sponsor_budget_units: u64,
    pub total_rewarded_units: u64,
}

impl DecentralizedProverStakingCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_prover_staking_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "identity_count": self.identity_count,
            "active_prover_count": self.active_prover_count,
            "stake_bucket_count": self.stake_bucket_count,
            "delegation_count": self.delegation_count,
            "capability_count": self.capability_count,
            "queue_count": self.queue_count,
            "open_assignment_count": self.open_assignment_count,
            "active_assignment_count": self.active_assignment_count,
            "verified_assignment_count": self.verified_assignment_count,
            "reward_receipt_count": self.reward_receipt_count,
            "sponsor_pool_count": self.sponsor_pool_count,
            "active_sponsor_pool_count": self.active_sponsor_pool_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "performance_attestation_count": self.performance_attestation_count,
            "total_locked_stake_units": self.total_locked_stake_units,
            "total_delegated_units": self.total_delegated_units,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_rewarded_units": self.total_rewarded_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedProverStakingState {
    pub height: u64,
    pub config: DecentralizedProverStakingConfig,
    pub identities: BTreeMap<String, PqIdentityCommitment>,
    pub stake_buckets: BTreeMap<String, ProverStakeBucket>,
    pub delegations: BTreeMap<String, DelegationBond>,
    pub capabilities: BTreeMap<String, ProverCapabilityProfile>,
    pub queues: BTreeMap<String, ProofAssignmentQueue>,
    pub assignments: BTreeMap<String, ProofAssignment>,
    pub reward_receipts: BTreeMap<String, ProverRewardReceipt>,
    pub sponsor_pools: BTreeMap<String, LowFeeSponsorPool>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidenceRecord>,
    pub performance_attestations: BTreeMap<String, PrivacyPreservingPerformanceAttestation>,
    pub active_provers_by_lane: BTreeMap<String, BTreeSet<String>>,
}

impl Default for DecentralizedProverStakingState {
    fn default() -> Self {
        Self::new()
    }
}

impl DecentralizedProverStakingState {
    pub fn new() -> Self {
        Self {
            height: 0,
            config: DecentralizedProverStakingConfig::default(),
            identities: BTreeMap::new(),
            stake_buckets: BTreeMap::new(),
            delegations: BTreeMap::new(),
            capabilities: BTreeMap::new(),
            queues: BTreeMap::new(),
            assignments: BTreeMap::new(),
            reward_receipts: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            performance_attestations: BTreeMap::new(),
            active_provers_by_lane: BTreeMap::new(),
        }
    }

    pub fn with_config(config: DecentralizedProverStakingConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    pub fn set_height(&mut self, height: u64) -> DecentralizedProverStakingResult<()> {
        if height < self.height {
            return Err("cannot move prover staking height backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn register_identity(
        &mut self,
        identity: PqIdentityCommitment,
    ) -> DecentralizedProverStakingResult<String> {
        identity.validate()?;
        if identity.security_bits < self.config.min_pq_security_bits {
            return Err("identity security bits below staking minimum".to_string());
        }
        if self.identities.contains_key(&identity.identity_id) {
            return Err("identity already registered".to_string());
        }
        let identity_id = identity.identity_id.clone();
        self.identities.insert(identity_id.clone(), identity);
        Ok(identity_id)
    }

    pub fn add_stake_bucket(
        &mut self,
        bucket: ProverStakeBucket,
    ) -> DecentralizedProverStakingResult<String> {
        bucket.validate()?;
        if !self.identities.contains_key(&bucket.prover_id) {
            return Err("stake bucket prover identity is not registered".to_string());
        }
        if !self.identities.contains_key(&bucket.owner_identity_id) {
            return Err("stake bucket owner identity is not registered".to_string());
        }
        if bucket.locked_units < self.config.min_prover_stake_units
            && bucket.bucket_kind != ProverStakeBucketKind::DelegatedStake
        {
            return Err("stake bucket locked units below prover minimum".to_string());
        }
        if self.stake_buckets.contains_key(&bucket.bucket_id) {
            return Err("stake bucket already exists".to_string());
        }
        let bucket_id = bucket.bucket_id.clone();
        self.stake_buckets.insert(bucket_id.clone(), bucket);
        Ok(bucket_id)
    }

    pub fn add_delegation(
        &mut self,
        delegation: DelegationBond,
    ) -> DecentralizedProverStakingResult<String> {
        delegation.validate()?;
        if delegation.delegated_units < self.config.min_delegation_units {
            return Err("delegation below staking minimum".to_string());
        }
        if !self
            .identities
            .contains_key(&delegation.delegator_identity_id)
        {
            return Err("delegator identity is not registered".to_string());
        }
        let bucket = self
            .stake_buckets
            .get_mut(&delegation.bucket_id)
            .ok_or_else(|| "delegation stake bucket is missing".to_string())?;
        if bucket.prover_id != delegation.prover_id {
            return Err("delegation bucket belongs to another prover".to_string());
        }
        bucket.delegated_units = bucket
            .delegated_units
            .saturating_add(delegation.delegated_units);
        let delegation_id = delegation.delegation_id.clone();
        if self.delegations.contains_key(&delegation_id) {
            return Err("delegation already exists".to_string());
        }
        self.delegations.insert(delegation_id.clone(), delegation);
        Ok(delegation_id)
    }

    pub fn register_capability(
        &mut self,
        capability: ProverCapabilityProfile,
    ) -> DecentralizedProverStakingResult<String> {
        capability.validate()?;
        if !self.identities.contains_key(&capability.prover_id) {
            return Err("capability prover identity is not registered".to_string());
        }
        if self.capabilities.contains_key(&capability.capability_id) {
            return Err("capability already registered".to_string());
        }
        let capability_id = capability.capability_id.clone();
        for lane in &capability.supported_lanes {
            self.active_provers_by_lane
                .entry(lane.as_str().to_string())
                .or_default()
                .insert(capability.prover_id.clone());
        }
        if capability.supported_lanes.is_empty() {
            for lane in [
                ProverAssignmentLane::L2Batch,
                ProverAssignmentLane::PrivateDefiCall,
                ProverAssignmentLane::MoneroBridge,
                ProverAssignmentLane::RecursivePqProof,
                ProverAssignmentLane::LowFeeSponsored,
                ProverAssignmentLane::SmartContractExecution,
                ProverAssignmentLane::EmergencyExit,
            ] {
                self.active_provers_by_lane
                    .entry(lane.as_str().to_string())
                    .or_default()
                    .insert(capability.prover_id.clone());
            }
        }
        self.capabilities.insert(capability_id.clone(), capability);
        Ok(capability_id)
    }

    pub fn open_queue(
        &mut self,
        queue: ProofAssignmentQueue,
    ) -> DecentralizedProverStakingResult<String> {
        queue.validate()?;
        if self.queues.contains_key(&queue.queue_id) {
            return Err("assignment queue already exists".to_string());
        }
        let queue_id = queue.queue_id.clone();
        self.queues.insert(queue_id.clone(), queue);
        Ok(queue_id)
    }

    pub fn open_sponsor_pool(
        &mut self,
        pool: LowFeeSponsorPool,
    ) -> DecentralizedProverStakingResult<String> {
        pool.validate()?;
        if pool.total_budget_units < self.config.min_sponsor_pool_units {
            return Err("sponsor pool budget below minimum".to_string());
        }
        if !self.identities.contains_key(&pool.sponsor_identity_id) {
            return Err("sponsor identity is not registered".to_string());
        }
        if self.sponsor_pools.contains_key(&pool.sponsor_pool_id) {
            return Err("sponsor pool already exists".to_string());
        }
        let pool_id = pool.sponsor_pool_id.clone();
        self.sponsor_pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }

    pub fn attach_pool_to_queue(
        &mut self,
        queue_id: &str,
        sponsor_pool_id: &str,
    ) -> DecentralizedProverStakingResult<()> {
        if !self.sponsor_pools.contains_key(sponsor_pool_id) {
            return Err("sponsor pool is missing".to_string());
        }
        let queue = self
            .queues
            .get_mut(queue_id)
            .ok_or_else(|| "assignment queue is missing".to_string())?;
        queue.attach_sponsor_pool(sponsor_pool_id)
    }

    pub fn enqueue_assignment(
        &mut self,
        assignment: ProofAssignment,
    ) -> DecentralizedProverStakingResult<String> {
        assignment.validate()?;
        if self.assignments.contains_key(&assignment.assignment_id) {
            return Err("assignment already exists".to_string());
        }
        let queue = self
            .queues
            .get_mut(&assignment.queue_id)
            .ok_or_else(|| "assignment queue is missing".to_string())?;
        if queue.lane != assignment.lane {
            return Err("assignment lane does not match queue lane".to_string());
        }
        if !assignment.sponsor_pool_id.is_empty() {
            let sponsor_pool = self
                .sponsor_pools
                .get(&assignment.sponsor_pool_id)
                .ok_or_else(|| "assignment sponsor pool is missing".to_string())?;
            if sponsor_pool.lane != assignment.lane {
                return Err("assignment sponsor pool lane mismatch".to_string());
            }
        }
        let assignment_id = assignment.assignment_id.clone();
        queue.enqueue(&assignment_id)?;
        self.assignments.insert(assignment_id.clone(), assignment);
        Ok(assignment_id)
    }

    pub fn assign_prover(
        &mut self,
        assignment_id: &str,
        prover_id: &str,
        bucket_id: &str,
    ) -> DecentralizedProverStakingResult<String> {
        let active_count = self.active_assignment_count_for_prover(prover_id);
        if active_count >= self.config.max_active_assignments_per_prover {
            return Err("prover has reached active assignment limit".to_string());
        }
        let assignment_view = self
            .assignments
            .get(assignment_id)
            .ok_or_else(|| "assignment is missing".to_string())?;
        let lane = assignment_view.lane;
        let proof_system = assignment_view.proof_system.clone();
        let max_fee_units = assignment_view.max_fee_units;
        if !self.prover_supports(prover_id, lane, &proof_system) {
            return Err("prover does not support assignment lane or proof system".to_string());
        }
        let bucket = self
            .stake_buckets
            .get_mut(bucket_id)
            .ok_or_else(|| "assignment stake bucket is missing".to_string())?;
        if bucket.prover_id != prover_id {
            return Err("assignment bucket belongs to another prover".to_string());
        }
        if !bucket.active_at(self.height) {
            return Err("assignment stake bucket is not active".to_string());
        }
        let reserve_units = required_assignment_bond_units(max_fee_units);
        bucket.reserve(reserve_units)?;
        let assignment = self
            .assignments
            .get_mut(assignment_id)
            .ok_or_else(|| "assignment is missing".to_string())?;
        assignment.assign(
            prover_id,
            bucket_id,
            self.height,
            self.config.assignment_sla_blocks,
        )?;
        if let Some(queue) = self.queues.get_mut(&assignment.queue_id) {
            queue.remove_assignment(assignment_id);
        }
        Ok(assignment.assignment_root())
    }

    pub fn select_and_assign_next(
        &mut self,
        queue_id: &str,
    ) -> DecentralizedProverStakingResult<String> {
        let queue = self
            .queues
            .get(queue_id)
            .ok_or_else(|| "assignment queue is missing".to_string())?;
        let assignment_id = queue
            .pending_assignment_ids
            .iter()
            .next()
            .cloned()
            .ok_or_else(|| "assignment queue is empty".to_string())?;
        let assignment = self
            .assignments
            .get(&assignment_id)
            .ok_or_else(|| "queued assignment is missing".to_string())?;
        let prover_id = self
            .select_prover_for_assignment(assignment)
            .ok_or_else(|| "no eligible prover for assignment".to_string())?;
        let bucket_id = self
            .select_bucket_for_prover(&prover_id, assignment.max_fee_units)
            .ok_or_else(|| "no eligible stake bucket for assignment".to_string())?;
        self.assign_prover(&assignment_id, &prover_id, &bucket_id)
    }

    pub fn mark_assignment_proved(
        &mut self,
        assignment_id: &str,
        proof_root: &str,
    ) -> DecentralizedProverStakingResult<String> {
        let assignment = self
            .assignments
            .get_mut(assignment_id)
            .ok_or_else(|| "assignment is missing".to_string())?;
        assignment.mark_proved(proof_root, self.height)?;
        Ok(assignment.assignment_root())
    }

    pub fn record_reward(
        &mut self,
        reward: ProverRewardReceipt,
    ) -> DecentralizedProverStakingResult<String> {
        reward.validate()?;
        if self.reward_receipts.contains_key(&reward.reward_receipt_id) {
            return Err("reward receipt already exists".to_string());
        }
        let assignment = self
            .assignments
            .get_mut(&reward.assignment_id)
            .ok_or_else(|| "reward assignment is missing".to_string())?;
        if assignment.assigned_prover_id != reward.prover_id {
            return Err("reward prover does not match assignment".to_string());
        }
        if assignment.status != ProverAssignmentStatus::Verified {
            let receipt_id = reward.reward_receipt_id.clone();
            if assignment.status == ProverAssignmentStatus::Proved {
                assignment.mark_verified(&receipt_id)?;
            } else {
                return Err("reward assignment is not verified".to_string());
            }
        }
        assignment.status = ProverAssignmentStatus::Rewarded;
        if !reward.sponsor_pool_id.is_empty() {
            let pool = self
                .sponsor_pools
                .get_mut(&reward.sponsor_pool_id)
                .ok_or_else(|| "reward sponsor pool is missing".to_string())?;
            pool.spend(reward.gross_reward_units)?;
        }
        if let Some(bucket) = self.stake_buckets.get_mut(&reward.bucket_id) {
            bucket.release(required_assignment_bond_units(reward.gross_reward_units));
            bucket.reward_debt_units = bucket.reward_debt_units.saturating_add(
                reward
                    .delegator_reward_units
                    .saturating_add(reward.prover_reward_units),
            );
        }
        let reward_id = reward.reward_receipt_id.clone();
        self.reward_receipts.insert(reward_id.clone(), reward);
        Ok(reward_id)
    }

    pub fn record_slashing_evidence(
        &mut self,
        evidence: SlashingEvidenceRecord,
    ) -> DecentralizedProverStakingResult<String> {
        evidence.validate()?;
        if self.slashing_evidence.contains_key(&evidence.evidence_id) {
            return Err("slashing evidence already exists".to_string());
        }
        if !self.identities.contains_key(&evidence.reporter_identity_id) {
            return Err("slashing reporter identity is not registered".to_string());
        }
        if !self.identities.contains_key(&evidence.target_prover_id) {
            return Err("slashing target prover identity is not registered".to_string());
        }
        if !self.stake_buckets.contains_key(&evidence.target_bucket_id) {
            return Err("slashing target bucket is missing".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn apply_slashing(&mut self, evidence_id: &str) -> DecentralizedProverStakingResult<u64> {
        let evidence = self
            .slashing_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| "slashing evidence is missing".to_string())?;
        let bucket = self
            .stake_buckets
            .get_mut(&evidence.target_bucket_id)
            .ok_or_else(|| "slashing target bucket is missing".to_string())?;
        let slash_by_bps = bps_amount(bucket.locked_units, evidence.slash_bps);
        let slash_units = evidence.slash_units.max(slash_by_bps);
        let applied_units = bucket.apply_slash(slash_units);
        evidence.mark_applied(self.height);
        if let Some(assignment) = self.assignments.get_mut(&evidence.target_assignment_id) {
            assignment.status = ProverAssignmentStatus::Slashed;
        }
        Ok(applied_units)
    }

    pub fn record_performance_attestation(
        &mut self,
        attestation: PrivacyPreservingPerformanceAttestation,
    ) -> DecentralizedProverStakingResult<String> {
        attestation.validate()?;
        if !self.identities.contains_key(&attestation.prover_id) {
            return Err("performance attestation prover is not registered".to_string());
        }
        if self
            .performance_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err("performance attestation already exists".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.performance_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn roots(&self) -> DecentralizedProverStakingRoots {
        DecentralizedProverStakingRoots {
            config_root: self.config.config_root(),
            identity_root: self.identity_root(),
            stake_bucket_root: self.stake_bucket_root(),
            delegation_root: self.delegation_root(),
            capability_root: self.capability_root(),
            queue_root: self.queue_root(),
            assignment_root: self.assignment_root(),
            reward_receipt_root: self.reward_receipt_root(),
            sponsor_pool_root: self.sponsor_pool_root(),
            slashing_evidence_root: self.slashing_evidence_root(),
            performance_attestation_root: self.performance_attestation_root(),
            active_lane_index_root: self.active_lane_index_root(),
        }
    }

    pub fn counters(&self) -> DecentralizedProverStakingCounters {
        DecentralizedProverStakingCounters {
            identity_count: self.identities.len() as u64,
            active_prover_count: self.active_prover_count(),
            stake_bucket_count: self.stake_buckets.len() as u64,
            delegation_count: self.delegations.len() as u64,
            capability_count: self.capabilities.len() as u64,
            queue_count: self.queues.len() as u64,
            open_assignment_count: self.open_assignment_count(),
            active_assignment_count: self.active_assignment_count(),
            verified_assignment_count: self.verified_assignment_count(),
            reward_receipt_count: self.reward_receipts.len() as u64,
            sponsor_pool_count: self.sponsor_pools.len() as u64,
            active_sponsor_pool_count: self.active_sponsor_pool_count(),
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            performance_attestation_count: self.performance_attestations.len() as u64,
            total_locked_stake_units: self.total_locked_stake_units(),
            total_delegated_units: self.total_delegated_units(),
            total_sponsor_budget_units: self.total_sponsor_budget_units(),
            total_rewarded_units: self.total_rewarded_units(),
        }
    }

    pub fn identity_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-IDENTITY-SET",
            &self
                .identities
                .values()
                .map(PqIdentityCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn stake_bucket_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-BUCKET-SET",
            &self
                .stake_buckets
                .values()
                .map(ProverStakeBucket::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn delegation_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-DELEGATION-SET",
            &self
                .delegations
                .values()
                .map(DelegationBond::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn capability_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-CAPABILITY-SET",
            &self
                .capabilities
                .values()
                .map(ProverCapabilityProfile::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn queue_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-QUEUE-SET",
            &self
                .queues
                .values()
                .map(ProofAssignmentQueue::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn assignment_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-ASSIGNMENT-SET",
            &self
                .assignments
                .values()
                .map(ProofAssignment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn reward_receipt_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-REWARD-RECEIPT-SET",
            &self
                .reward_receipts
                .values()
                .map(ProverRewardReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsor_pool_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-SPONSOR-POOL-SET",
            &self
                .sponsor_pools
                .values()
                .map(LowFeeSponsorPool::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn slashing_evidence_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-SLASHING-EVIDENCE-SET",
            &self
                .slashing_evidence
                .values()
                .map(SlashingEvidenceRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn performance_attestation_root(&self) -> String {
        merkle_root(
            "DECENTRALIZED-PROVER-STAKING-PERFORMANCE-ATTESTATION-SET",
            &self
                .performance_attestations
                .values()
                .map(PrivacyPreservingPerformanceAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_lane_index_root(&self) -> String {
        let records = self
            .active_provers_by_lane
            .iter()
            .map(|(lane, provers)| {
                json!({
                    "lane": lane,
                    "prover_ids": provers,
                    "prover_count": provers.len() as u64,
                })
            })
            .collect::<Vec<_>>();
        merkle_root("DECENTRALIZED-PROVER-STAKING-ACTIVE-LANE-INDEX", &records)
    }

    pub fn state_root(&self) -> String {
        decentralized_prover_staking_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> DecentralizedProverStakingResult<String> {
        self.config.validate()?;
        ensure_max_records(self.identities.len(), "identities")?;
        ensure_max_records(self.stake_buckets.len(), "stake buckets")?;
        ensure_max_records(self.delegations.len(), "delegations")?;
        ensure_max_records(self.capabilities.len(), "capabilities")?;
        ensure_max_records(self.queues.len(), "queues")?;
        ensure_max_records(self.assignments.len(), "assignments")?;
        ensure_max_records(self.reward_receipts.len(), "reward receipts")?;
        ensure_max_records(self.sponsor_pools.len(), "sponsor pools")?;
        ensure_max_records(self.slashing_evidence.len(), "slashing evidence")?;
        ensure_max_records(
            self.performance_attestations.len(),
            "performance attestations",
        )?;
        for (id, identity) in &self.identities {
            if id != &identity.identity_id {
                return Err("identity map key does not match identity id".to_string());
            }
            identity.validate()?;
        }
        for (id, bucket) in &self.stake_buckets {
            if id != &bucket.bucket_id {
                return Err("stake bucket map key does not match bucket id".to_string());
            }
            bucket.validate()?;
            if !self.identities.contains_key(&bucket.prover_id) {
                return Err("stake bucket references unknown prover identity".to_string());
            }
            if !self.identities.contains_key(&bucket.owner_identity_id) {
                return Err("stake bucket references unknown owner identity".to_string());
            }
        }
        for (id, delegation) in &self.delegations {
            if id != &delegation.delegation_id {
                return Err("delegation map key does not match delegation id".to_string());
            }
            delegation.validate()?;
            if !self
                .identities
                .contains_key(&delegation.delegator_identity_id)
            {
                return Err("delegation references unknown delegator identity".to_string());
            }
            if !self.stake_buckets.contains_key(&delegation.bucket_id) {
                return Err("delegation references unknown stake bucket".to_string());
            }
        }
        for (id, capability) in &self.capabilities {
            if id != &capability.capability_id {
                return Err("capability map key does not match capability id".to_string());
            }
            capability.validate()?;
            if !self.identities.contains_key(&capability.prover_id) {
                return Err("capability references unknown prover identity".to_string());
            }
        }
        for (id, queue) in &self.queues {
            if id != &queue.queue_id {
                return Err("queue map key does not match queue id".to_string());
            }
            queue.validate()?;
            for assignment_id in &queue.pending_assignment_ids {
                if !self.assignments.contains_key(assignment_id) {
                    return Err("queue references unknown assignment".to_string());
                }
            }
            for sponsor_pool_id in &queue.sponsor_pool_ids {
                if !self.sponsor_pools.contains_key(sponsor_pool_id) {
                    return Err("queue references unknown sponsor pool".to_string());
                }
            }
        }
        for (id, assignment) in &self.assignments {
            if id != &assignment.assignment_id {
                return Err("assignment map key does not match assignment id".to_string());
            }
            assignment.validate()?;
            if !self.queues.contains_key(&assignment.queue_id) {
                return Err("assignment references unknown queue".to_string());
            }
            if !assignment.sponsor_pool_id.is_empty()
                && !self.sponsor_pools.contains_key(&assignment.sponsor_pool_id)
            {
                return Err("assignment references unknown sponsor pool".to_string());
            }
            if !assignment.assigned_prover_id.is_empty()
                && !self.identities.contains_key(&assignment.assigned_prover_id)
            {
                return Err("assignment references unknown prover".to_string());
            }
        }
        for (id, reward) in &self.reward_receipts {
            if id != &reward.reward_receipt_id {
                return Err("reward receipt map key does not match receipt id".to_string());
            }
            reward.validate()?;
            if !self.assignments.contains_key(&reward.assignment_id) {
                return Err("reward references unknown assignment".to_string());
            }
        }
        for (id, pool) in &self.sponsor_pools {
            if id != &pool.sponsor_pool_id {
                return Err("sponsor pool map key does not match pool id".to_string());
            }
            pool.validate()?;
            if !self.identities.contains_key(&pool.sponsor_identity_id) {
                return Err("sponsor pool references unknown identity".to_string());
            }
        }
        for (id, evidence) in &self.slashing_evidence {
            if id != &evidence.evidence_id {
                return Err("slashing evidence map key does not match evidence id".to_string());
            }
            evidence.validate()?;
            if !self.identities.contains_key(&evidence.target_prover_id) {
                return Err("slashing evidence references unknown target prover".to_string());
            }
        }
        for (id, attestation) in &self.performance_attestations {
            if id != &attestation.attestation_id {
                return Err("performance attestation map key does not match id".to_string());
            }
            attestation.validate()?;
            if !self.identities.contains_key(&attestation.prover_id) {
                return Err("performance attestation references unknown prover".to_string());
            }
        }
        Ok(self.state_root())
    }

    pub fn devnet() -> Self {
        let mut state = Self::with_config(DecentralizedProverStakingConfig::devnet());
        state.height = 42;

        let prover = PqIdentityCommitment::new(
            "devnet-recursive-prover-a",
            ProverStakeRole::Prover,
            &devnet_hash("prover-a-pq-key"),
            &devnet_hash("prover-a-auth"),
            &devnet_hash("prover-a-recovery"),
            &devnet_hash("prover-a-endpoint"),
            256,
            1,
            0,
            1,
        );
        let delegator = PqIdentityCommitment::new(
            "devnet-delegator-a",
            ProverStakeRole::Delegator,
            &devnet_hash("delegator-a-pq-key"),
            &devnet_hash("delegator-a-auth"),
            &devnet_hash("delegator-a-recovery"),
            &devnet_hash("delegator-a-endpoint"),
            256,
            1,
            0,
            2,
        );
        let sponsor = PqIdentityCommitment::new(
            "devnet-low-fee-sponsor-a",
            ProverStakeRole::Sponsor,
            &devnet_hash("sponsor-a-pq-key"),
            &devnet_hash("sponsor-a-auth"),
            &devnet_hash("sponsor-a-recovery"),
            &devnet_hash("sponsor-a-endpoint"),
            256,
            1,
            0,
            3,
        );
        let reporter = PqIdentityCommitment::new(
            "devnet-watchtower-a",
            ProverStakeRole::Watchtower,
            &devnet_hash("watchtower-a-pq-key"),
            &devnet_hash("watchtower-a-auth"),
            &devnet_hash("watchtower-a-recovery"),
            &devnet_hash("watchtower-a-endpoint"),
            256,
            1,
            0,
            4,
        );

        if let Ok(identity) = prover {
            let prover_id = identity.identity_id.clone();
            let _ = state.register_identity(identity);
            if let Ok(identity) = delegator {
                let delegator_id = identity.identity_id.clone();
                let _ = state.register_identity(identity);
                if let Ok(identity) = sponsor {
                    let sponsor_id = identity.identity_id.clone();
                    let _ = state.register_identity(identity);
                    if let Ok(identity) = reporter {
                        let reporter_id = identity.identity_id.clone();
                        let _ = state.register_identity(identity);
                        let bucket = ProverStakeBucket::new(
                            &prover_id,
                            &prover_id,
                            ProverStakeBucketKind::RecursivePqBond,
                            &state.config.fee_asset_id,
                            250_000,
                            2,
                            0,
                            &devnet_hash("prover-a-bucket-auth"),
                            10,
                        );
                        if let Ok(bucket) = bucket {
                            let bucket_id = bucket.bucket_id.clone();
                            let _ = state.add_stake_bucket(bucket);
                            let delegation = DelegationBond::new(
                                &delegator_id,
                                &prover_id,
                                &bucket_id,
                                &state.config.fee_asset_id,
                                25_000,
                                6_500,
                                &devnet_hash("delegation-a-auth"),
                                3,
                                0,
                                11,
                            );
                            if let Ok(delegation) = delegation {
                                let _ = state.add_delegation(delegation);
                            }
                            let mut lanes = BTreeSet::new();
                            lanes.insert(ProverAssignmentLane::L2Batch);
                            lanes.insert(ProverAssignmentLane::PrivateDefiCall);
                            lanes.insert(ProverAssignmentLane::MoneroBridge);
                            lanes.insert(ProverAssignmentLane::RecursivePqProof);
                            lanes.insert(ProverAssignmentLane::LowFeeSponsored);
                            let mut systems = BTreeSet::new();
                            systems.insert(
                                ProverAssignmentKind::BatchStateProof
                                    .default_proof_system()
                                    .to_string(),
                            );
                            systems.insert(
                                ProverAssignmentKind::PrivateDefiProof
                                    .default_proof_system()
                                    .to_string(),
                            );
                            systems.insert(
                                ProverAssignmentKind::RecursiveAggregationProof
                                    .default_proof_system()
                                    .to_string(),
                            );
                            if let Ok(capability) = ProverCapabilityProfile::new(
                                &prover_id,
                                ProverWorkerClass::RecursiveCluster,
                                4,
                                16,
                                lanes,
                                systems,
                                96_000_000,
                                DECENTRALIZED_PROVER_STAKING_LOW_FEE_TARGET_UNITS,
                                4,
                                12,
                            ) {
                                let _ = state.register_capability(capability);
                            }
                            if let Ok(queue) = ProofAssignmentQueue::new(
                                ProverAssignmentLane::LowFeeSponsored,
                                0,
                                64,
                                &devnet_hash("low-fee-queue-randomness"),
                                5,
                            ) {
                                let queue_id = queue.queue_id.clone();
                                let _ = state.open_queue(queue);
                                if let Ok(pool) = LowFeeSponsorPool::new(
                                    &sponsor_id,
                                    ProverAssignmentLane::LowFeeSponsored,
                                    &state.config.fee_asset_id,
                                    50_000,
                                    100,
                                    &devnet_hash("low-fee-beneficiaries"),
                                    &devnet_hash("sponsor-pool-auth"),
                                    5,
                                    240,
                                    13,
                                ) {
                                    let pool_id = pool.sponsor_pool_id.clone();
                                    let _ = state.open_sponsor_pool(pool);
                                    let _ = state.attach_pool_to_queue(&queue_id, &pool_id);
                                    if let Ok(assignment) = ProofAssignment::new(
                                        &queue_id,
                                        &devnet_hash("wallet-requester"),
                                        ProverAssignmentLane::LowFeeSponsored,
                                        ProverAssignmentKind::SponsoredFeeProof,
                                        &devnet_hash("public-input-low-fee"),
                                        &devnet_hash("witness-low-fee"),
                                        &devnet_hash("privacy-bucket-low-fee"),
                                        8_000_000,
                                        80,
                                        &pool_id,
                                        6,
                                        state.config.assignment_sla_blocks,
                                        14,
                                    ) {
                                        let assignment_id = assignment.assignment_id.clone();
                                        let _ = state.enqueue_assignment(assignment);
                                        let _ = state.assign_prover(
                                            &assignment_id,
                                            &prover_id,
                                            &bucket_id,
                                        );
                                        let _ = state.mark_assignment_proved(
                                            &assignment_id,
                                            &devnet_hash("proof-low-fee"),
                                        );
                                        if let Ok(reward) = ProverRewardReceipt::new(
                                            &assignment_id,
                                            &prover_id,
                                            &bucket_id,
                                            &pool_id,
                                            &state.config.fee_asset_id,
                                            80,
                                            state.config.protocol_reward_take_bps,
                                            state.config.delegator_reward_bps,
                                            &devnet_hash("proof-low-fee"),
                                            state.height,
                                            15,
                                        ) {
                                            let _ = state.record_reward(reward);
                                        }
                                    }
                                }
                            }
                            if let Ok(attestation) = PrivacyPreservingPerformanceAttestation::new(
                                &prover_id,
                                0,
                                PerformanceAttestationBucket::LowFeeFriendly,
                                ProverAssignmentLane::LowFeeSponsored,
                                &devnet_hash("sample-set-low-fee"),
                                &devnet_hash("performance-proof-low-fee"),
                                16,
                                state.height,
                                &devnet_hash("committee-a"),
                            ) {
                                let _ = state.record_performance_attestation(attestation);
                            }
                            if let Ok(evidence) = SlashingEvidenceRecord::new(
                                SlashingEvidenceKind::LateProof,
                                &prover_id,
                                "",
                                &bucket_id,
                                &reporter_id,
                                &devnet_hash("late-proof-evidence"),
                                &devnet_hash("late-proof-transcript"),
                                100,
                                state.config.late_slash_bps,
                                state.height,
                                state.config.challenge_window_blocks,
                            ) {
                                let _ = state.record_slashing_evidence(evidence);
                            }
                        }
                    }
                }
            }
        }
        state
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "decentralized_prover_staking_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION,
            "schema_version": DECENTRALIZED_PROVER_STAKING_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "identity_root": roots.identity_root,
            "stake_bucket_root": roots.stake_bucket_root,
            "delegation_root": roots.delegation_root,
            "capability_root": roots.capability_root,
            "queue_root": roots.queue_root,
            "assignment_root": roots.assignment_root,
            "reward_receipt_root": roots.reward_receipt_root,
            "sponsor_pool_root": roots.sponsor_pool_root,
            "slashing_evidence_root": roots.slashing_evidence_root,
            "performance_attestation_root": roots.performance_attestation_root,
            "active_lane_index_root": roots.active_lane_index_root,
        })
    }

    fn active_prover_count(&self) -> u64 {
        self.identities
            .values()
            .filter(|identity| {
                identity.role == ProverStakeRole::Prover && identity.active_at(self.height)
            })
            .count() as u64
    }

    fn active_sponsor_pool_count(&self) -> u64 {
        self.sponsor_pools
            .values()
            .filter(|pool| pool.active_at(self.height))
            .count() as u64
    }

    fn open_assignment_count(&self) -> u64 {
        self.assignments
            .values()
            .filter(|assignment| assignment.status == ProverAssignmentStatus::Open)
            .count() as u64
    }

    fn active_assignment_count(&self) -> u64 {
        self.assignments
            .values()
            .filter(|assignment| assignment.status.active())
            .count() as u64
    }

    fn verified_assignment_count(&self) -> u64 {
        self.assignments
            .values()
            .filter(|assignment| {
                matches!(
                    assignment.status,
                    ProverAssignmentStatus::Verified | ProverAssignmentStatus::Rewarded
                )
            })
            .count() as u64
    }

    fn active_assignment_count_for_prover(&self, prover_id: &str) -> u64 {
        self.assignments
            .values()
            .filter(|assignment| {
                assignment.assigned_prover_id == prover_id && assignment.status.active()
            })
            .count() as u64
    }

    fn total_locked_stake_units(&self) -> u64 {
        self.stake_buckets
            .values()
            .map(|bucket| bucket.locked_units)
            .sum()
    }

    fn total_delegated_units(&self) -> u64 {
        self.delegations
            .values()
            .map(|delegation| delegation.delegated_units)
            .sum()
    }

    fn total_sponsor_budget_units(&self) -> u64 {
        self.sponsor_pools
            .values()
            .map(|pool| pool.total_budget_units)
            .sum()
    }

    fn total_rewarded_units(&self) -> u64 {
        self.reward_receipts
            .values()
            .map(|receipt| receipt.gross_reward_units)
            .sum()
    }

    fn prover_supports(
        &self,
        prover_id: &str,
        lane: ProverAssignmentLane,
        proof_system: &str,
    ) -> bool {
        self.capabilities.values().any(|capability| {
            capability.prover_id == prover_id
                && capability.status == DECENTRALIZED_PROVER_STATUS_ACTIVE
                && capability.supports_lane(lane)
                && capability.supports_proof_system(proof_system)
        })
    }

    fn select_prover_for_assignment(&self, assignment: &ProofAssignment) -> Option<String> {
        let lane_key = assignment.lane.as_str().to_string();
        let lane_provers = match self.active_provers_by_lane.get(&lane_key) {
            Some(provers) => provers.clone(),
            None => BTreeSet::new(),
        };
        let mut candidates = lane_provers
            .into_iter()
            .filter(|prover_id| {
                self.prover_supports(prover_id, assignment.lane, &assignment.proof_system)
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            let left_score = self.assignment_score(left, assignment);
            let right_score = self.assignment_score(right, assignment);
            right_score.cmp(&left_score).then_with(|| left.cmp(right))
        });
        candidates.into_iter().next()
    }

    fn select_bucket_for_prover(&self, prover_id: &str, fee_units: u64) -> Option<String> {
        let required_units = required_assignment_bond_units(fee_units);
        self.stake_buckets
            .values()
            .filter(|bucket| {
                bucket.prover_id == prover_id
                    && bucket.active_at(self.height)
                    && bucket.available_units() >= required_units
            })
            .max_by(|left, right| {
                left.available_units()
                    .cmp(&right.available_units())
                    .then_with(|| right.bucket_id.cmp(&left.bucket_id))
            })
            .map(|bucket| bucket.bucket_id.clone())
    }

    fn assignment_score(&self, prover_id: &str, assignment: &ProofAssignment) -> u64 {
        let capacity_score = match self
            .capabilities
            .values()
            .filter(|capability| capability.prover_id == prover_id)
            .map(ProverCapabilityProfile::effective_capacity_units)
            .max()
        {
            Some(score) => score,
            None => 0,
        };
        let stake_score = self
            .stake_buckets
            .values()
            .filter(|bucket| bucket.prover_id == prover_id && bucket.active_at(self.height))
            .map(ProverStakeBucket::available_units)
            .sum::<u64>()
            .saturating_div(1_000);
        let load_penalty = self
            .active_assignment_count_for_prover(prover_id)
            .saturating_mul(100);
        capacity_score
            .saturating_add(stake_score)
            .saturating_add(assignment.lane.default_priority_weight())
            .saturating_sub(load_penalty)
    }
}

pub fn decentralized_prover_staking_state_root(state: &DecentralizedProverStakingState) -> String {
    state.state_root()
}

pub fn decentralized_prover_staking_state_root_from_record(record: &Value) -> String {
    decentralized_prover_staking_payload_root("DECENTRALIZED-PROVER-STAKING-STATE", record)
}

pub fn decentralized_prover_staking_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(DECENTRALIZED_PROVER_STAKING_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn prover_identity_id(
    participant_label: &str,
    role: ProverStakeRole,
    pq_public_key_root: &str,
    registered_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-IDENTITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(participant_label),
            HashPart::Str(role.as_str()),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(registered_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_stake_bucket_id(
    prover_id: &str,
    owner_identity_id: &str,
    bucket_kind: ProverStakeBucketKind,
    activation_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-BUCKET-ID",
        &[
            HashPart::Str(prover_id),
            HashPart::Str(owner_identity_id),
            HashPart::Str(bucket_kind.as_str()),
            HashPart::Int(activation_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn delegation_bond_id(
    delegator_identity_id: &str,
    prover_id: &str,
    bucket_id: &str,
    delegated_units: u64,
    start_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-DELEGATION-ID",
        &[
            HashPart::Str(delegator_identity_id),
            HashPart::Str(prover_id),
            HashPart::Str(bucket_id),
            HashPart::Int(delegated_units as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_capability_id(
    prover_id: &str,
    worker_class: ProverWorkerClass,
    worker_count: u64,
    max_cycles_per_block: u64,
    registered_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-CAPABILITY-ID",
        &[
            HashPart::Str(prover_id),
            HashPart::Str(worker_class.as_str()),
            HashPart::Int(worker_count as i128),
            HashPart::Int(max_cycles_per_block as i128),
            HashPart::Int(registered_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_assignment_queue_id(
    lane: ProverAssignmentLane,
    epoch: u64,
    randomness_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-QUEUE-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Int(epoch as i128),
            HashPart::Str(randomness_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn proof_assignment_id(
    queue_id: &str,
    requester_commitment: &str,
    lane: ProverAssignmentLane,
    assignment_kind: ProverAssignmentKind,
    public_input_root: &str,
    posted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-ASSIGNMENT-ID",
        &[
            HashPart::Str(queue_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(assignment_kind.as_str()),
            HashPart::Str(public_input_root),
            HashPart::Int(posted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn sponsor_pool_id(
    sponsor_identity_id: &str,
    lane: ProverAssignmentLane,
    fee_asset_id: &str,
    beneficiary_root: &str,
    valid_from_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-SPONSOR-POOL-ID",
        &[
            HashPart::Str(sponsor_identity_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Str(beneficiary_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn reward_receipt_id(
    assignment_id: &str,
    prover_id: &str,
    proof_root: &str,
    gross_reward_units: u64,
    paid_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-REWARD-RECEIPT-ID",
        &[
            HashPart::Str(assignment_id),
            HashPart::Str(prover_id),
            HashPart::Str(proof_root),
            HashPart::Int(gross_reward_units as i128),
            HashPart::Int(paid_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    evidence_kind: SlashingEvidenceKind,
    target_prover_id: &str,
    target_assignment_id: &str,
    target_bucket_id: &str,
    evidence_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(target_prover_id),
            HashPart::Str(target_assignment_id),
            HashPart::Str(target_bucket_id),
            HashPart::Str(evidence_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn performance_attestation_id(
    prover_id: &str,
    epoch: u64,
    bucket: PerformanceAttestationBucket,
    lane: ProverAssignmentLane,
    sample_set_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-PERFORMANCE-ATTESTATION-ID",
        &[
            HashPart::Str(prover_id),
            HashPart::Int(epoch as i128),
            HashPart::Str(bucket.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sample_set_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn required_assignment_bond_units(max_fee_units: u64) -> u64 {
    max_fee_units.saturating_mul(2).max(1)
}

pub fn bps_amount(units: u64, bps: u64) -> u64 {
    units
        .saturating_mul(bps)
        .saturating_add(DECENTRALIZED_PROVER_STAKING_MAX_BPS - 1)
        / DECENTRALIZED_PROVER_STAKING_MAX_BPS
}

fn devnet_hash(label: &str) -> String {
    domain_hash(
        "DECENTRALIZED-PROVER-STAKING-DEVNET-HASH",
        &[HashPart::Str(label)],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> DecentralizedProverStakingResult<()> {
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> DecentralizedProverStakingResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> DecentralizedProverStakingResult<()> {
    if value > DECENTRALIZED_PROVER_STAKING_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_eq_str(
    observed: &str,
    required: &str,
    label: &str,
) -> DecentralizedProverStakingResult<()> {
    if observed != required {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

fn ensure_eq_u64(
    observed: u64,
    required: u64,
    label: &str,
) -> DecentralizedProverStakingResult<()> {
    if observed != required {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

fn ensure_status(
    status: &str,
    allowed: &[&str],
    label: &str,
) -> DecentralizedProverStakingResult<()> {
    if allowed
        .iter()
        .any(|allowed_status| status == *allowed_status)
    {
        return Ok(());
    }
    Err(format!("{label} is not allowed"))
}

fn ensure_max_records(count: usize, label: &str) -> DecentralizedProverStakingResult<()> {
    if count > DECENTRALIZED_PROVER_STAKING_MAX_RECORDS {
        return Err(format!("{label} exceeds maximum record count"));
    }
    Ok(())
}
