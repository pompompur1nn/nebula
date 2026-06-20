use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-governance-upgrade-timelock-mesh-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_GOVERNANCE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-upgrade-mesh-v1";
pub const PRIVATE_VOTE_SCHEME: &str = "anonymous-nullifier-upgrade-vote-root-v1";
pub const TIMELOCK_MESH_SCHEME: &str = "confidential-cross-runtime-upgrade-timelock-mesh-v1";
pub const SAFETY_GATE_SCHEME: &str = "pq-confidential-upgrade-safety-gate-attestation-v1";
pub const LOW_FEE_EXECUTION_SCHEME: &str = "low-fee-upgrade-execution-reservation-v1";
pub const SELECTIVE_DISCLOSURE_SCHEME: &str = "sealed-governance-selective-disclosure-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_120_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_COMMITTEE_MEMBERS: usize = 262_144;
pub const DEFAULT_MAX_PROPOSALS: usize = 1_048_576;
pub const DEFAULT_MAX_VOTE_COMMITMENTS: usize = 8_388_608;
pub const DEFAULT_MAX_GATE_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_DEPENDENCIES: usize = 4_194_304;
pub const DEFAULT_MAX_TIMELOCK_SLOTS: usize = 1_048_576;
pub const DEFAULT_MAX_RESERVATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_DISCLOSURES: usize = 1_048_576;
pub const DEFAULT_MAX_VETOES: usize = 262_144;
pub const DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const DEFAULT_MAX_INCIDENTS: usize = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_COMMITTEE_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_VOTE_APPROVAL_BPS: u64 = 6_700;
pub const DEFAULT_MIN_EMERGENCY_VETO_BPS: u64 = 8_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_TIMELOCK_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_TIMELOCK_BLOCKS: u64 = 172_800;
pub const DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_VOTE_WINDOW_BLOCKS: u64 = 7_200;
pub const DEFAULT_EXECUTION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 = 12;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_EXECUTION_FEE_BPS: u64 = 16;
pub const DEFAULT_LOW_FEE_SPONSOR_COVERAGE_BPS: u64 = 9_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeSurface {
    CryptoPolicy,
    VerifierRegistry,
    ContractRuntime,
    TokenBridge,
    MoneroBridge,
    SequencerCommittee,
    DataAvailability,
    ProverMarket,
    FeePolicy,
    WalletPolicy,
    OracleMesh,
    GovernanceCore,
    EmergencyControlPlane,
}

impl UpgradeSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CryptoPolicy => "crypto_policy",
            Self::VerifierRegistry => "verifier_registry",
            Self::ContractRuntime => "contract_runtime",
            Self::TokenBridge => "token_bridge",
            Self::MoneroBridge => "monero_bridge",
            Self::SequencerCommittee => "sequencer_committee",
            Self::DataAvailability => "data_availability",
            Self::ProverMarket => "prover_market",
            Self::FeePolicy => "fee_policy",
            Self::WalletPolicy => "wallet_policy",
            Self::OracleMesh => "oracle_mesh",
            Self::GovernanceCore => "governance_core",
            Self::EmergencyControlPlane => "emergency_control_plane",
        }
    }

    pub fn bridge_critical(self) -> bool {
        matches!(
            self,
            Self::TokenBridge
                | Self::MoneroBridge
                | Self::SequencerCommittee
                | Self::EmergencyControlPlane
        )
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::CryptoPolicy
                | Self::VerifierRegistry
                | Self::ContractRuntime
                | Self::TokenBridge
                | Self::MoneroBridge
                | Self::WalletPolicy
                | Self::OracleMesh
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeKind {
    PqAlgorithmActivation,
    LegacyAlgorithmRetirement,
    VerifierKeyRotation,
    CircuitParameterPatch,
    ContractVmUpgrade,
    BridgeAdapterUpgrade,
    TokenCovenantUpgrade,
    FeeScheduleUpgrade,
    DaSamplingUpgrade,
    WalletPolicyUpgrade,
    EmergencyHotfix,
    Rollback,
}

impl UpgradeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqAlgorithmActivation => "pq_algorithm_activation",
            Self::LegacyAlgorithmRetirement => "legacy_algorithm_retirement",
            Self::VerifierKeyRotation => "verifier_key_rotation",
            Self::CircuitParameterPatch => "circuit_parameter_patch",
            Self::ContractVmUpgrade => "contract_vm_upgrade",
            Self::BridgeAdapterUpgrade => "bridge_adapter_upgrade",
            Self::TokenCovenantUpgrade => "token_covenant_upgrade",
            Self::FeeScheduleUpgrade => "fee_schedule_upgrade",
            Self::DaSamplingUpgrade => "da_sampling_upgrade",
            Self::WalletPolicyUpgrade => "wallet_policy_upgrade",
            Self::EmergencyHotfix => "emergency_hotfix",
            Self::Rollback => "rollback",
        }
    }

    pub fn emergency_eligible(self) -> bool {
        matches!(self, Self::EmergencyHotfix | Self::Rollback)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeRiskTier {
    Low,
    Medium,
    High,
    Critical,
    BridgeCritical,
    PrivacyCritical,
    GovernanceCritical,
}

impl UpgradeRiskTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::BridgeCritical => "bridge_critical",
            Self::PrivacyCritical => "privacy_critical",
            Self::GovernanceCritical => "governance_critical",
        }
    }

    pub fn min_timelock_blocks(self, config: &Config) -> u64 {
        match self {
            Self::Low => config.min_timelock_blocks,
            Self::Medium => config.min_timelock_blocks.saturating_mul(2),
            Self::High => config.min_timelock_blocks.saturating_mul(4),
            Self::Critical
            | Self::BridgeCritical
            | Self::PrivacyCritical
            | Self::GovernanceCritical => config.min_timelock_blocks.saturating_mul(8),
        }
        .min(config.max_timelock_blocks)
    }

    pub fn requires_extended_safety(self) -> bool {
        matches!(
            self,
            Self::Critical
                | Self::BridgeCritical
                | Self::PrivacyCritical
                | Self::GovernanceCritical
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Drafted,
    Submitted,
    GateReview,
    Voting,
    VoteApproved,
    Timelocked,
    Ready,
    Reserved,
    Executed,
    Rejected,
    Expired,
    Cancelled,
    EmergencyVetoed,
    RolledBack,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Submitted => "submitted",
            Self::GateReview => "gate_review",
            Self::Voting => "voting",
            Self::VoteApproved => "vote_approved",
            Self::Timelocked => "timelocked",
            Self::Ready => "ready",
            Self::Reserved => "reserved",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::EmergencyVetoed => "emergency_vetoed",
            Self::RolledBack => "rolled_back",
        }
    }

    pub fn accepts_gate(self) -> bool {
        matches!(self, Self::Submitted | Self::GateReview)
    }

    pub fn accepts_vote(self) -> bool {
        matches!(self, Self::GateReview | Self::Voting)
    }

    pub fn can_open_timelock(self) -> bool {
        matches!(self, Self::VoteApproved | Self::Voting)
    }

    pub fn executable(self) -> bool {
        matches!(self, Self::Ready | Self::Reserved | Self::Timelocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteKind {
    Approve,
    Reject,
    Abstain,
    EmergencyVeto,
}

impl VoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
            Self::EmergencyVeto => "emergency_veto",
        }
    }

    pub fn approval_weight(self, weight_bps: u64) -> u64 {
        if matches!(self, Self::Approve) {
            weight_bps
        } else {
            0
        }
    }

    pub fn veto_weight(self, weight_bps: u64) -> u64 {
        if matches!(self, Self::EmergencyVeto) {
            weight_bps
        } else {
            0
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyGateKind {
    PqSecurity,
    PrivacyRegression,
    BridgeLiquidity,
    MoneroFinality,
    TokenSupplyConservation,
    ContractStorageCompatibility,
    DataAvailability,
    FeeBound,
    RollbackPlan,
}

impl SafetyGateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSecurity => "pq_security",
            Self::PrivacyRegression => "privacy_regression",
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::MoneroFinality => "monero_finality",
            Self::TokenSupplyConservation => "token_supply_conservation",
            Self::ContractStorageCompatibility => "contract_storage_compatibility",
            Self::DataAvailability => "data_availability",
            Self::FeeBound => "fee_bound",
            Self::RollbackPlan => "rollback_plan",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    LowFeeBatch,
    FastTrack,
    Scheduled,
    Emergency,
    Rollback,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeBatch => "low_fee_batch",
            Self::FastTrack => "fast_track",
            Self::Scheduled => "scheduled",
            Self::Emergency => "emergency",
            Self::Rollback => "rollback",
        }
    }

    pub fn emergency(self) -> bool {
        matches!(self, Self::Emergency | Self::Rollback)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureKind {
    VerifierDiff,
    MigrationWitness,
    BridgeSignerSet,
    ContractStorageMap,
    TokenSupplyDelta,
    FeeImpact,
    RollbackWitness,
}

impl DisclosureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifierDiff => "verifier_diff",
            Self::MigrationWitness => "migration_witness",
            Self::BridgeSignerSet => "bridge_signer_set",
            Self::ContractStorageMap => "contract_storage_map",
            Self::TokenSupplyDelta => "token_supply_delta",
            Self::FeeImpact => "fee_impact",
            Self::RollbackWitness => "rollback_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshIncidentKind {
    GateFailure,
    VoteNullifierConflict,
    TimelockExpired,
    FeeReservationExpired,
    DependencyMismatch,
    DisclosureMissing,
    ExecutionRootMismatch,
    EmergencyVeto,
}

impl MeshIncidentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GateFailure => "gate_failure",
            Self::VoteNullifierConflict => "vote_nullifier_conflict",
            Self::TimelockExpired => "timelock_expired",
            Self::FeeReservationExpired => "fee_reservation_expired",
            Self::DependencyMismatch => "dependency_mismatch",
            Self::DisclosureMissing => "disclosure_missing",
            Self::ExecutionRootMismatch => "execution_root_mismatch",
            Self::EmergencyVeto => "emergency_veto",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake192f,
    SlhDsaShake256f,
    HybridMlDsa87SlhDsa256f,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
            Self::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
            Self::HybridMlDsa87SlhDsa256f => "ML-DSA-87+SLH-DSA-SHAKE-256f",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 | Self::SlhDsaShake192f => 192,
            Self::MlDsa87 | Self::SlhDsaShake256f | Self::HybridMlDsa87SlhDsa256f => 256,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub governance_operator_root: String,
    pub min_pq_security_bits: u16,
    pub min_committee_weight_bps: u64,
    pub min_vote_approval_bps: u64,
    pub min_emergency_veto_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_timelock_blocks: u64,
    pub max_timelock_blocks: u64,
    pub proposal_ttl_blocks: u64,
    pub vote_window_blocks: u64,
    pub execution_window_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub max_execution_fee_bps: u64,
    pub low_fee_sponsor_coverage_bps: u64,
    pub max_committee_members: usize,
    pub max_proposals: usize,
    pub max_vote_commitments: usize,
    pub max_gate_attestations: usize,
    pub max_dependencies: usize,
    pub max_timelock_slots: usize,
    pub max_reservations: usize,
    pub max_disclosures: usize,
    pub max_vetoes: usize,
    pub max_receipts: usize,
    pub max_incidents: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            governance_operator_root: string_root(
                "GOVERNANCE-OPERATOR",
                "nebula-devnet-pq-council",
            ),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_weight_bps: DEFAULT_MIN_COMMITTEE_WEIGHT_BPS,
            min_vote_approval_bps: DEFAULT_MIN_VOTE_APPROVAL_BPS,
            min_emergency_veto_bps: DEFAULT_MIN_EMERGENCY_VETO_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_timelock_blocks: DEFAULT_MIN_TIMELOCK_BLOCKS,
            max_timelock_blocks: DEFAULT_MAX_TIMELOCK_BLOCKS,
            proposal_ttl_blocks: DEFAULT_PROPOSAL_TTL_BLOCKS,
            vote_window_blocks: DEFAULT_VOTE_WINDOW_BLOCKS,
            execution_window_blocks: DEFAULT_EXECUTION_WINDOW_BLOCKS,
            emergency_delay_blocks: DEFAULT_EMERGENCY_DELAY_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            max_execution_fee_bps: DEFAULT_MAX_EXECUTION_FEE_BPS,
            low_fee_sponsor_coverage_bps: DEFAULT_LOW_FEE_SPONSOR_COVERAGE_BPS,
            max_committee_members: DEFAULT_MAX_COMMITTEE_MEMBERS,
            max_proposals: DEFAULT_MAX_PROPOSALS,
            max_vote_commitments: DEFAULT_MAX_VOTE_COMMITMENTS,
            max_gate_attestations: DEFAULT_MAX_GATE_ATTESTATIONS,
            max_dependencies: DEFAULT_MAX_DEPENDENCIES,
            max_timelock_slots: DEFAULT_MAX_TIMELOCK_SLOTS,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_disclosures: DEFAULT_MAX_DISCLOSURES,
            max_vetoes: DEFAULT_MAX_VETOES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_incidents: DEFAULT_MAX_INCIDENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("governance upgrade mesh protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("governance upgrade mesh chain id mismatch".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("governance upgrade mesh pq security below floor".to_string());
        }
        if self.min_committee_weight_bps > MAX_BPS
            || self.min_vote_approval_bps > MAX_BPS
            || self.min_emergency_veto_bps > MAX_BPS
            || self.max_execution_fee_bps > MAX_BPS
            || self.low_fee_sponsor_coverage_bps > MAX_BPS
        {
            return Err("governance upgrade mesh bps value above max".to_string());
        }
        if self.min_timelock_blocks == 0 || self.max_timelock_blocks < self.min_timelock_blocks {
            return Err("governance upgrade mesh timelock window invalid".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("governance upgrade mesh privacy set invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": HASH_SUITE,
            "pq_governance_suite": PQ_GOVERNANCE_SUITE,
            "private_vote_scheme": PRIVATE_VOTE_SCHEME,
            "timelock_mesh_scheme": TIMELOCK_MESH_SCHEME,
            "safety_gate_scheme": SAFETY_GATE_SCHEME,
            "low_fee_execution_scheme": LOW_FEE_EXECUTION_SCHEME,
            "selective_disclosure_scheme": SELECTIVE_DISCLOSURE_SCHEME,
            "governance_operator_root": self.governance_operator_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_committee_weight_bps": self.min_committee_weight_bps,
            "min_vote_approval_bps": self.min_vote_approval_bps,
            "min_emergency_veto_bps": self.min_emergency_veto_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_timelock_blocks": self.min_timelock_blocks,
            "max_timelock_blocks": self.max_timelock_blocks,
            "proposal_ttl_blocks": self.proposal_ttl_blocks,
            "vote_window_blocks": self.vote_window_blocks,
            "execution_window_blocks": self.execution_window_blocks,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "max_execution_fee_bps": self.max_execution_fee_bps,
            "low_fee_sponsor_coverage_bps": self.low_fee_sponsor_coverage_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub label_commitment: String,
    pub public_key_root: String,
    pub scheme: PqSignatureScheme,
    pub weight_bps: u64,
    pub privacy_set_size: u64,
    pub activation_height: u64,
    pub rotation_nonce_root: String,
    pub slashing_bond_root: String,
    pub active: bool,
}

impl CommitteeMember {
    pub fn new(
        label: &str,
        public_key: &Value,
        scheme: PqSignatureScheme,
        weight_bps: u64,
        privacy_set_size: u64,
        activation_height: u64,
        rotation_nonce: &Value,
        slashing_bond: &Value,
    ) -> Result<Self> {
        if label.is_empty() {
            return Err("committee member label cannot be empty".to_string());
        }
        if weight_bps == 0 || weight_bps > MAX_BPS {
            return Err("committee member weight invalid".to_string());
        }
        let label_commitment = string_root("GOVERNANCE-MEMBER-LABEL", label);
        let public_key_root = value_root("GOVERNANCE-MEMBER-PUBLIC-KEY", public_key);
        let rotation_nonce_root = value_root("GOVERNANCE-MEMBER-ROTATION-NONCE", rotation_nonce);
        let slashing_bond_root = value_root("GOVERNANCE-MEMBER-SLASHING-BOND", slashing_bond);
        let member_id = member_id(
            &label_commitment,
            &public_key_root,
            scheme,
            weight_bps,
            privacy_set_size,
            activation_height,
            &rotation_nonce_root,
        );
        Ok(Self {
            member_id,
            label_commitment,
            public_key_root,
            scheme,
            weight_bps,
            privacy_set_size,
            activation_height,
            rotation_nonce_root,
            slashing_bond_root,
            active: true,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.member_id
            != member_id(
                &self.label_commitment,
                &self.public_key_root,
                self.scheme,
                self.weight_bps,
                self.privacy_set_size,
                self.activation_height,
                &self.rotation_nonce_root,
            )
        {
            return Err("committee member id mismatch".to_string());
        }
        if self.scheme.security_bits() < config.min_pq_security_bits {
            return Err("committee member pq security below policy".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("committee member privacy set below policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "member_id": self.member_id,
            "label_commitment": self.label_commitment,
            "public_key_root": self.public_key_root,
            "scheme": self.scheme.as_str(),
            "weight_bps": self.weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "activation_height": self.activation_height,
            "rotation_nonce_root": self.rotation_nonce_root,
            "slashing_bond_root": self.slashing_bond_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitProposalRequest {
    pub proposer_root: String,
    pub surface: UpgradeSurface,
    pub kind: UpgradeKind,
    pub risk_tier: UpgradeRiskTier,
    pub title_root: String,
    pub current_runtime_root: String,
    pub proposed_runtime_root: String,
    pub migration_plan_root: String,
    pub rollback_plan_root: String,
    pub privacy_impact_root: String,
    pub fee_impact_root: String,
    pub bridge_impact_root: String,
    pub submitted_at_height: u64,
    pub requested_activation_height: u64,
    pub expires_at_height: u64,
    pub sponsor_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceUpgradeProposal {
    pub proposal_id: String,
    pub proposer_root: String,
    pub surface: UpgradeSurface,
    pub kind: UpgradeKind,
    pub risk_tier: UpgradeRiskTier,
    pub status: ProposalStatus,
    pub title_root: String,
    pub current_runtime_root: String,
    pub proposed_runtime_root: String,
    pub migration_plan_root: String,
    pub rollback_plan_root: String,
    pub privacy_impact_root: String,
    pub fee_impact_root: String,
    pub bridge_impact_root: String,
    pub dependency_root: String,
    pub gate_root: String,
    pub vote_root: String,
    pub disclosure_root: String,
    pub sponsor_root: String,
    pub submitted_at_height: u64,
    pub vote_opens_at_height: u64,
    pub vote_closes_at_height: u64,
    pub earliest_activation_height: u64,
    pub expires_at_height: u64,
    pub approval_weight_bps: u64,
    pub rejection_weight_bps: u64,
    pub abstain_weight_bps: u64,
    pub veto_weight_bps: u64,
    pub timelock_slot_id: Option<String>,
    pub reservation_id: Option<String>,
    pub execution_receipt_id: Option<String>,
}

impl GovernanceUpgradeProposal {
    pub fn from_request(request: SubmitProposalRequest, config: &Config) -> Result<Self> {
        if request.proposer_root.is_empty()
            || request.title_root.is_empty()
            || request.current_runtime_root.is_empty()
            || request.proposed_runtime_root.is_empty()
            || request.migration_plan_root.is_empty()
            || request.rollback_plan_root.is_empty()
        {
            return Err("upgrade proposal roots cannot be empty".to_string());
        }
        if request.expires_at_height <= request.submitted_at_height {
            return Err("upgrade proposal expiry must be after submission".to_string());
        }
        let minimum_delay = request.risk_tier.min_timelock_blocks(config);
        let earliest_activation_height = request
            .requested_activation_height
            .max(request.submitted_at_height.saturating_add(minimum_delay));
        let vote_opens_at_height = request.submitted_at_height.saturating_add(1);
        let vote_closes_at_height = vote_opens_at_height.saturating_add(config.vote_window_blocks);
        let dependency_root = string_set_root("GOVERNANCE-UPGRADE-DEPENDENCY-ROOT", &[]);
        let gate_root = string_set_root("GOVERNANCE-UPGRADE-GATE-ROOT", &[]);
        let vote_root = string_set_root("GOVERNANCE-UPGRADE-VOTE-ROOT", &[]);
        let disclosure_root = string_set_root("GOVERNANCE-UPGRADE-DISCLOSURE-ROOT", &[]);
        let proposal_id = proposal_id(
            &request.proposer_root,
            request.surface,
            request.kind,
            request.risk_tier,
            &request.title_root,
            &request.current_runtime_root,
            &request.proposed_runtime_root,
            &request.migration_plan_root,
            &request.rollback_plan_root,
            request.submitted_at_height,
        );
        Ok(Self {
            proposal_id,
            proposer_root: request.proposer_root,
            surface: request.surface,
            kind: request.kind,
            risk_tier: request.risk_tier,
            status: ProposalStatus::Submitted,
            title_root: request.title_root,
            current_runtime_root: request.current_runtime_root,
            proposed_runtime_root: request.proposed_runtime_root,
            migration_plan_root: request.migration_plan_root,
            rollback_plan_root: request.rollback_plan_root,
            privacy_impact_root: request.privacy_impact_root,
            fee_impact_root: request.fee_impact_root,
            bridge_impact_root: request.bridge_impact_root,
            dependency_root,
            gate_root,
            vote_root,
            disclosure_root,
            sponsor_root: request.sponsor_root,
            submitted_at_height: request.submitted_at_height,
            vote_opens_at_height,
            vote_closes_at_height,
            earliest_activation_height,
            expires_at_height: request.expires_at_height,
            approval_weight_bps: 0,
            rejection_weight_bps: 0,
            abstain_weight_bps: 0,
            veto_weight_bps: 0,
            timelock_slot_id: None,
            reservation_id: None,
            execution_receipt_id: None,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.proposal_id
            != proposal_id(
                &self.proposer_root,
                self.surface,
                self.kind,
                self.risk_tier,
                &self.title_root,
                &self.current_runtime_root,
                &self.proposed_runtime_root,
                &self.migration_plan_root,
                &self.rollback_plan_root,
                self.submitted_at_height,
            )
        {
            return Err("upgrade proposal id mismatch".to_string());
        }
        if self.vote_closes_at_height <= self.vote_opens_at_height {
            return Err("upgrade proposal vote window invalid".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("upgrade proposal expiry invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_proposal",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "proposal_id": self.proposal_id,
            "proposer_root": self.proposer_root,
            "surface": self.surface.as_str(),
            "upgrade_kind": self.kind.as_str(),
            "risk_tier": self.risk_tier.as_str(),
            "status": self.status.as_str(),
            "title_root": self.title_root,
            "current_runtime_root": self.current_runtime_root,
            "proposed_runtime_root": self.proposed_runtime_root,
            "migration_plan_root": self.migration_plan_root,
            "rollback_plan_root": self.rollback_plan_root,
            "privacy_impact_root": self.privacy_impact_root,
            "fee_impact_root": self.fee_impact_root,
            "bridge_impact_root": self.bridge_impact_root,
            "dependency_root": self.dependency_root,
            "gate_root": self.gate_root,
            "vote_root": self.vote_root,
            "disclosure_root": self.disclosure_root,
            "sponsor_root": self.sponsor_root,
            "submitted_at_height": self.submitted_at_height,
            "vote_opens_at_height": self.vote_opens_at_height,
            "vote_closes_at_height": self.vote_closes_at_height,
            "earliest_activation_height": self.earliest_activation_height,
            "expires_at_height": self.expires_at_height,
            "approval_weight_bps": self.approval_weight_bps,
            "rejection_weight_bps": self.rejection_weight_bps,
            "abstain_weight_bps": self.abstain_weight_bps,
            "veto_weight_bps": self.veto_weight_bps,
            "timelock_slot_id": self.timelock_slot_id,
            "reservation_id": self.reservation_id,
            "execution_receipt_id": self.execution_receipt_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SafetyGateAttestation {
    pub attestation_id: String,
    pub proposal_id: String,
    pub gate_kind: SafetyGateKind,
    pub attester_member_id: String,
    pub attestation_root: String,
    pub evidence_root: String,
    pub measured_score_bps: u64,
    pub min_required_score_bps: u64,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub attested_at_height: u64,
    pub passed: bool,
}

impl SafetyGateAttestation {
    pub fn new(
        proposal_id: &str,
        gate_kind: SafetyGateKind,
        attester_member_id: &str,
        attestation: &Value,
        evidence: &Value,
        measured_score_bps: u64,
        min_required_score_bps: u64,
        pq_signature: &Value,
        privacy_set_size: u64,
        attested_at_height: u64,
    ) -> Result<Self> {
        if proposal_id.is_empty() || attester_member_id.is_empty() {
            return Err("safety gate proposal and attester cannot be empty".to_string());
        }
        if measured_score_bps > MAX_BPS || min_required_score_bps > MAX_BPS {
            return Err("safety gate score invalid".to_string());
        }
        let attestation_root = value_root("GOVERNANCE-GATE-ATTESTATION", attestation);
        let evidence_root = value_root("GOVERNANCE-GATE-EVIDENCE", evidence);
        let pq_signature_root = value_root("GOVERNANCE-GATE-PQ-SIGNATURE", pq_signature);
        let passed = measured_score_bps >= min_required_score_bps;
        let attestation_id = gate_attestation_id(
            proposal_id,
            gate_kind,
            attester_member_id,
            &attestation_root,
            &evidence_root,
            measured_score_bps,
            min_required_score_bps,
            &pq_signature_root,
            attested_at_height,
        );
        Ok(Self {
            attestation_id,
            proposal_id: proposal_id.to_string(),
            gate_kind,
            attester_member_id: attester_member_id.to_string(),
            attestation_root,
            evidence_root,
            measured_score_bps,
            min_required_score_bps,
            pq_signature_root,
            privacy_set_size,
            attested_at_height,
            passed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_safety_gate",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "proposal_id": self.proposal_id,
            "gate_kind": self.gate_kind.as_str(),
            "attester_member_id": self.attester_member_id,
            "attestation_root": self.attestation_root,
            "evidence_root": self.evidence_root,
            "measured_score_bps": self.measured_score_bps,
            "min_required_score_bps": self.min_required_score_bps,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "attested_at_height": self.attested_at_height,
            "passed": self.passed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VoteCommitment {
    pub vote_id: String,
    pub proposal_id: String,
    pub nullifier_root: String,
    pub vote_kind: VoteKind,
    pub weight_bps: u64,
    pub encrypted_vote_root: String,
    pub eligibility_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub cast_at_height: u64,
}

impl VoteCommitment {
    pub fn new(
        proposal_id: &str,
        nullifier: &Value,
        vote_kind: VoteKind,
        weight_bps: u64,
        encrypted_vote: &Value,
        eligibility: &Value,
        pq_signature: &Value,
        privacy_set_size: u64,
        cast_at_height: u64,
    ) -> Result<Self> {
        if proposal_id.is_empty() {
            return Err("vote proposal id cannot be empty".to_string());
        }
        if weight_bps == 0 || weight_bps > MAX_BPS {
            return Err("vote weight invalid".to_string());
        }
        let nullifier_root = value_root("GOVERNANCE-VOTE-NULLIFIER", nullifier);
        let encrypted_vote_root = value_root("GOVERNANCE-VOTE-ENCRYPTED", encrypted_vote);
        let eligibility_root = value_root("GOVERNANCE-VOTE-ELIGIBILITY", eligibility);
        let pq_signature_root = value_root("GOVERNANCE-VOTE-PQ-SIGNATURE", pq_signature);
        let vote_id = vote_id(
            proposal_id,
            &nullifier_root,
            vote_kind,
            weight_bps,
            &encrypted_vote_root,
            &eligibility_root,
            &pq_signature_root,
            cast_at_height,
        );
        Ok(Self {
            vote_id,
            proposal_id: proposal_id.to_string(),
            nullifier_root,
            vote_kind,
            weight_bps,
            encrypted_vote_root,
            eligibility_root,
            pq_signature_root,
            privacy_set_size,
            cast_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_vote_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "nullifier_root": self.nullifier_root,
            "vote_kind": self.vote_kind.as_str(),
            "weight_bps": self.weight_bps,
            "encrypted_vote_root": self.encrypted_vote_root,
            "eligibility_root": self.eligibility_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "cast_at_height": self.cast_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossRuntimeDependency {
    pub dependency_id: String,
    pub proposal_id: String,
    pub runtime_label: String,
    pub required_state_root: String,
    pub observed_state_root: String,
    pub receipt_root: String,
    pub compatible: bool,
    pub checked_at_height: u64,
}

impl CrossRuntimeDependency {
    pub fn new(
        proposal_id: &str,
        runtime_label: &str,
        required_state_root: &str,
        observed_state_root: &str,
        receipt: &Value,
        checked_at_height: u64,
    ) -> Result<Self> {
        if proposal_id.is_empty() || runtime_label.is_empty() || required_state_root.is_empty() {
            return Err(
                "dependency proposal, runtime, and required root cannot be empty".to_string(),
            );
        }
        let receipt_root = value_root("GOVERNANCE-DEPENDENCY-RECEIPT", receipt);
        let compatible = required_state_root == observed_state_root;
        let dependency_id = dependency_id(
            proposal_id,
            runtime_label,
            required_state_root,
            observed_state_root,
            &receipt_root,
            checked_at_height,
        );
        Ok(Self {
            dependency_id,
            proposal_id: proposal_id.to_string(),
            runtime_label: runtime_label.to_string(),
            required_state_root: required_state_root.to_string(),
            observed_state_root: observed_state_root.to_string(),
            receipt_root,
            compatible,
            checked_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_cross_runtime_dependency",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "dependency_id": self.dependency_id,
            "proposal_id": self.proposal_id,
            "runtime_label": self.runtime_label,
            "required_state_root": self.required_state_root,
            "observed_state_root": self.observed_state_root,
            "receipt_root": self.receipt_root,
            "compatible": self.compatible,
            "checked_at_height": self.checked_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosure {
    pub disclosure_id: String,
    pub proposal_id: String,
    pub disclosure_kind: DisclosureKind,
    pub audience_root: String,
    pub sealed_payload_root: String,
    pub release_condition_root: String,
    pub nullifier_root: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl SelectiveDisclosure {
    pub fn new(
        proposal_id: &str,
        disclosure_kind: DisclosureKind,
        audience: &Value,
        sealed_payload: &Value,
        release_condition: &Value,
        nullifier: &Value,
        published_at_height: u64,
        expires_at_height: u64,
    ) -> Result<Self> {
        if proposal_id.is_empty() {
            return Err("disclosure proposal id cannot be empty".to_string());
        }
        if expires_at_height <= published_at_height {
            return Err("disclosure expiry invalid".to_string());
        }
        let audience_root = value_root("GOVERNANCE-DISCLOSURE-AUDIENCE", audience);
        let sealed_payload_root = value_root("GOVERNANCE-DISCLOSURE-PAYLOAD", sealed_payload);
        let release_condition_root =
            value_root("GOVERNANCE-DISCLOSURE-RELEASE-CONDITION", release_condition);
        let nullifier_root = value_root("GOVERNANCE-DISCLOSURE-NULLIFIER", nullifier);
        let disclosure_id = disclosure_id(
            proposal_id,
            disclosure_kind,
            &audience_root,
            &sealed_payload_root,
            &release_condition_root,
            &nullifier_root,
            published_at_height,
        );
        Ok(Self {
            disclosure_id,
            proposal_id: proposal_id.to_string(),
            disclosure_kind,
            audience_root,
            sealed_payload_root,
            release_condition_root,
            nullifier_root,
            published_at_height,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_selective_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "proposal_id": self.proposal_id,
            "disclosure_kind": self.disclosure_kind.as_str(),
            "audience_root": self.audience_root,
            "sealed_payload_root": self.sealed_payload_root,
            "release_condition_root": self.release_condition_root,
            "nullifier_root": self.nullifier_root,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimelockSlot {
    pub slot_id: String,
    pub proposal_id: String,
    pub scheduled_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub dependency_root: String,
    pub gate_root: String,
    pub vote_root: String,
    pub low_fee_reservation_root: String,
    pub emergency: bool,
    pub executed: bool,
}

impl TimelockSlot {
    pub fn new(
        proposal: &GovernanceUpgradeProposal,
        scheduled_at_height: u64,
        config: &Config,
        emergency: bool,
    ) -> Result<Self> {
        if !proposal.status.can_open_timelock() && !emergency {
            return Err("proposal status cannot open timelock".to_string());
        }
        let delay = if emergency {
            config.emergency_delay_blocks
        } else {
            proposal.risk_tier.min_timelock_blocks(config)
        };
        let executable_at_height = scheduled_at_height.saturating_add(delay);
        let expires_at_height = executable_at_height.saturating_add(config.execution_window_blocks);
        let low_fee_reservation_root = string_set_root("GOVERNANCE-TIMELOCK-RESERVATION-ROOT", &[]);
        let slot_id = timelock_slot_id(
            &proposal.proposal_id,
            scheduled_at_height,
            executable_at_height,
            expires_at_height,
            &proposal.dependency_root,
            &proposal.gate_root,
            &proposal.vote_root,
            emergency,
        );
        Ok(Self {
            slot_id,
            proposal_id: proposal.proposal_id.clone(),
            scheduled_at_height,
            executable_at_height,
            expires_at_height,
            dependency_root: proposal.dependency_root.clone(),
            gate_root: proposal.gate_root.clone(),
            vote_root: proposal.vote_root.clone(),
            low_fee_reservation_root,
            emergency,
            executed: false,
        })
    }

    pub fn ready_at(&self, height: u64) -> bool {
        height >= self.executable_at_height && height <= self.expires_at_height && !self.executed
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_timelock_slot",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "slot_id": self.slot_id,
            "proposal_id": self.proposal_id,
            "scheduled_at_height": self.scheduled_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "dependency_root": self.dependency_root,
            "gate_root": self.gate_root,
            "vote_root": self.vote_root,
            "low_fee_reservation_root": self.low_fee_reservation_root,
            "emergency": self.emergency,
            "executed": self.executed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeExecutionReservation {
    pub reservation_id: String,
    pub proposal_id: String,
    pub sponsor_root: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub reserved_execution_units: u64,
    pub proof_compression_credit_bps: u64,
    pub da_rebate_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeExecutionReservation {
    pub fn new(
        proposal_id: &str,
        sponsor: &Value,
        fee_asset_id: &str,
        max_fee_bps: u64,
        sponsor_coverage_bps: u64,
        reserved_execution_units: u64,
        proof_compression_credit_bps: u64,
        da_rebate: &Value,
        reserved_at_height: u64,
        config: &Config,
    ) -> Result<Self> {
        if proposal_id.is_empty() || fee_asset_id.is_empty() {
            return Err("reservation proposal and fee asset cannot be empty".to_string());
        }
        if max_fee_bps > config.max_execution_fee_bps || sponsor_coverage_bps > MAX_BPS {
            return Err("reservation fee bounds invalid".to_string());
        }
        let sponsor_root = value_root("GOVERNANCE-RESERVATION-SPONSOR", sponsor);
        let da_rebate_root = value_root("GOVERNANCE-RESERVATION-DA-REBATE", da_rebate);
        let expires_at_height = reserved_at_height.saturating_add(config.reservation_ttl_blocks);
        let reservation_id = reservation_id(
            proposal_id,
            &sponsor_root,
            fee_asset_id,
            max_fee_bps,
            sponsor_coverage_bps,
            reserved_execution_units,
            proof_compression_credit_bps,
            &da_rebate_root,
            reserved_at_height,
        );
        Ok(Self {
            reservation_id,
            proposal_id: proposal_id.to_string(),
            sponsor_root,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_bps,
            sponsor_coverage_bps,
            reserved_execution_units,
            proof_compression_credit_bps,
            da_rebate_root,
            reserved_at_height,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_low_fee_execution_reservation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reservation_id": self.reservation_id,
            "proposal_id": self.proposal_id,
            "sponsor_root": self.sponsor_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "reserved_execution_units": self.reserved_execution_units,
            "proof_compression_credit_bps": self.proof_compression_credit_bps,
            "da_rebate_root": self.da_rebate_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyVeto {
    pub veto_id: String,
    pub proposal_id: String,
    pub veto_committee_root: String,
    pub reason_root: String,
    pub evidence_root: String,
    pub veto_weight_bps: u64,
    pub pq_signature_root: String,
    pub filed_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub accepted: bool,
}

impl EmergencyVeto {
    pub fn new(
        proposal_id: &str,
        veto_committee: &Value,
        reason: &Value,
        evidence: &Value,
        veto_weight_bps: u64,
        pq_signature: &Value,
        filed_at_height: u64,
        config: &Config,
    ) -> Result<Self> {
        if proposal_id.is_empty() {
            return Err("veto proposal id cannot be empty".to_string());
        }
        if veto_weight_bps > MAX_BPS {
            return Err("veto weight invalid".to_string());
        }
        let veto_committee_root = value_root("GOVERNANCE-VETO-COMMITTEE", veto_committee);
        let reason_root = value_root("GOVERNANCE-VETO-REASON", reason);
        let evidence_root = value_root("GOVERNANCE-VETO-EVIDENCE", evidence);
        let pq_signature_root = value_root("GOVERNANCE-VETO-PQ-SIGNATURE", pq_signature);
        let accepted = veto_weight_bps >= config.min_emergency_veto_bps;
        let veto_id = veto_id(
            proposal_id,
            &veto_committee_root,
            &reason_root,
            &evidence_root,
            veto_weight_bps,
            &pq_signature_root,
            filed_at_height,
        );
        Ok(Self {
            veto_id,
            proposal_id: proposal_id.to_string(),
            veto_committee_root,
            reason_root,
            evidence_root,
            veto_weight_bps,
            pq_signature_root,
            filed_at_height,
            resolved_at_height: None,
            accepted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_emergency_veto",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "veto_id": self.veto_id,
            "proposal_id": self.proposal_id,
            "veto_committee_root": self.veto_committee_root,
            "reason_root": self.reason_root,
            "evidence_root": self.evidence_root,
            "veto_weight_bps": self.veto_weight_bps,
            "pq_signature_root": self.pq_signature_root,
            "filed_at_height": self.filed_at_height,
            "resolved_at_height": self.resolved_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub proposal_id: String,
    pub execution_mode: ExecutionMode,
    pub executor_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub runtime_receipt_root: String,
    pub fee_receipt_root: String,
    pub rollback_anchor_root: String,
    pub executed_at_height: u64,
    pub success: bool,
}

impl ExecutionReceipt {
    pub fn new(
        proposal_id: &str,
        execution_mode: ExecutionMode,
        executor: &Value,
        pre_state_root: &str,
        post_state_root: &str,
        runtime_receipt: &Value,
        fee_receipt: &Value,
        rollback_anchor: &Value,
        executed_at_height: u64,
        success: bool,
    ) -> Result<Self> {
        if proposal_id.is_empty() || pre_state_root.is_empty() || post_state_root.is_empty() {
            return Err("execution receipt roots cannot be empty".to_string());
        }
        let executor_root = value_root("GOVERNANCE-EXECUTOR", executor);
        let runtime_receipt_root = value_root("GOVERNANCE-RUNTIME-RECEIPT", runtime_receipt);
        let fee_receipt_root = value_root("GOVERNANCE-FEE-RECEIPT", fee_receipt);
        let rollback_anchor_root = value_root("GOVERNANCE-ROLLBACK-ANCHOR", rollback_anchor);
        let receipt_id = execution_receipt_id(
            proposal_id,
            execution_mode,
            &executor_root,
            pre_state_root,
            post_state_root,
            &runtime_receipt_root,
            &fee_receipt_root,
            &rollback_anchor_root,
            executed_at_height,
            success,
        );
        Ok(Self {
            receipt_id,
            proposal_id: proposal_id.to_string(),
            execution_mode,
            executor_root,
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            runtime_receipt_root,
            fee_receipt_root,
            rollback_anchor_root,
            executed_at_height,
            success,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_execution_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "proposal_id": self.proposal_id,
            "execution_mode": self.execution_mode.as_str(),
            "executor_root": self.executor_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "runtime_receipt_root": self.runtime_receipt_root,
            "fee_receipt_root": self.fee_receipt_root,
            "rollback_anchor_root": self.rollback_anchor_root,
            "executed_at_height": self.executed_at_height,
            "success": self.success,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeshIncident {
    pub incident_id: String,
    pub proposal_id: String,
    pub incident_kind: MeshIncidentKind,
    pub severity_bps: u64,
    pub evidence_root: String,
    pub mitigation_root: String,
    pub opened_at_height: u64,
    pub closed_at_height: Option<u64>,
}

impl MeshIncident {
    pub fn new(
        proposal_id: &str,
        incident_kind: MeshIncidentKind,
        severity_bps: u64,
        evidence: &Value,
        mitigation: &Value,
        opened_at_height: u64,
    ) -> Result<Self> {
        if proposal_id.is_empty() {
            return Err("incident proposal id cannot be empty".to_string());
        }
        if severity_bps > MAX_BPS {
            return Err("incident severity invalid".to_string());
        }
        let evidence_root = value_root("GOVERNANCE-INCIDENT-EVIDENCE", evidence);
        let mitigation_root = value_root("GOVERNANCE-INCIDENT-MITIGATION", mitigation);
        let incident_id = incident_id(
            proposal_id,
            incident_kind,
            severity_bps,
            &evidence_root,
            &mitigation_root,
            opened_at_height,
        );
        Ok(Self {
            incident_id,
            proposal_id: proposal_id.to_string(),
            incident_kind,
            severity_bps,
            evidence_root,
            mitigation_root,
            opened_at_height,
            closed_at_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_incident",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "incident_id": self.incident_id,
            "proposal_id": self.proposal_id,
            "incident_kind": self.incident_kind.as_str(),
            "severity_bps": self.severity_bps,
            "evidence_root": self.evidence_root,
            "mitigation_root": self.mitigation_root,
            "opened_at_height": self.opened_at_height,
            "closed_at_height": self.closed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub committee_root: String,
    pub proposal_root: String,
    pub gate_root: String,
    pub vote_root: String,
    pub dependency_root: String,
    pub timelock_root: String,
    pub reservation_root: String,
    pub disclosure_root: String,
    pub veto_root: String,
    pub receipt_root: String,
    pub incident_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "committee_root": self.committee_root,
            "proposal_root": self.proposal_root,
            "gate_root": self.gate_root,
            "vote_root": self.vote_root,
            "dependency_root": self.dependency_root,
            "timelock_root": self.timelock_root,
            "reservation_root": self.reservation_root,
            "disclosure_root": self.disclosure_root,
            "veto_root": self.veto_root,
            "receipt_root": self.receipt_root,
            "incident_root": self.incident_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committee_members: u64,
    pub active_committee_members: u64,
    pub proposals: u64,
    pub approved_proposals: u64,
    pub executable_proposals: u64,
    pub executed_proposals: u64,
    pub gate_attestations: u64,
    pub passed_gate_attestations: u64,
    pub vote_commitments: u64,
    pub dependencies: u64,
    pub compatible_dependencies: u64,
    pub timelock_slots: u64,
    pub reservations: u64,
    pub disclosures: u64,
    pub emergency_vetoes: u64,
    pub accepted_vetoes: u64,
    pub execution_receipts: u64,
    pub incidents: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_upgrade_mesh_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "committee_members": self.committee_members,
            "active_committee_members": self.active_committee_members,
            "proposals": self.proposals,
            "approved_proposals": self.approved_proposals,
            "executable_proposals": self.executable_proposals,
            "executed_proposals": self.executed_proposals,
            "gate_attestations": self.gate_attestations,
            "passed_gate_attestations": self.passed_gate_attestations,
            "vote_commitments": self.vote_commitments,
            "dependencies": self.dependencies,
            "compatible_dependencies": self.compatible_dependencies,
            "timelock_slots": self.timelock_slots,
            "reservations": self.reservations,
            "disclosures": self.disclosures,
            "emergency_vetoes": self.emergency_vetoes,
            "accepted_vetoes": self.accepted_vetoes,
            "execution_receipts": self.execution_receipts,
            "incidents": self.incidents,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub committee_members: BTreeMap<String, CommitteeMember>,
    pub proposals: BTreeMap<String, GovernanceUpgradeProposal>,
    pub gate_attestations: BTreeMap<String, SafetyGateAttestation>,
    pub vote_commitments: BTreeMap<String, VoteCommitment>,
    pub used_vote_nullifiers: BTreeSet<String>,
    pub dependencies: BTreeMap<String, CrossRuntimeDependency>,
    pub timelock_slots: BTreeMap<String, TimelockSlot>,
    pub reservations: BTreeMap<String, LowFeeExecutionReservation>,
    pub disclosures: BTreeMap<String, SelectiveDisclosure>,
    pub emergency_vetoes: BTreeMap<String, EmergencyVeto>,
    pub execution_receipts: BTreeMap<String, ExecutionReceipt>,
    pub incidents: BTreeMap<String, MeshIncident>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            committee_members: BTreeMap::new(),
            proposals: BTreeMap::new(),
            gate_attestations: BTreeMap::new(),
            vote_commitments: BTreeMap::new(),
            used_vote_nullifiers: BTreeSet::new(),
            dependencies: BTreeMap::new(),
            timelock_slots: BTreeMap::new(),
            reservations: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            emergency_vetoes: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            incidents: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT).unwrap_or_else(|_| Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            committee_members: BTreeMap::new(),
            proposals: BTreeMap::new(),
            gate_attestations: BTreeMap::new(),
            vote_commitments: BTreeMap::new(),
            used_vote_nullifiers: BTreeSet::new(),
            dependencies: BTreeMap::new(),
            timelock_slots: BTreeMap::new(),
            reservations: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            emergency_vetoes: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            incidents: BTreeMap::new(),
        });
        state.seed_devnet();
        state
    }

    fn seed_devnet(&mut self) {
        let member_specs = [
            (
                "devnet-upgrade-council-alpha",
                PqSignatureScheme::HybridMlDsa87SlhDsa256f,
                2_400,
            ),
            (
                "devnet-upgrade-council-beta",
                PqSignatureScheme::MlDsa87,
                2_200,
            ),
            (
                "devnet-upgrade-council-gamma",
                PqSignatureScheme::SlhDsaShake256f,
                2_100,
            ),
            (
                "devnet-bridge-guardian-delta",
                PqSignatureScheme::HybridMlDsa87SlhDsa256f,
                1_900,
            ),
            (
                "devnet-wallet-policy-epsilon",
                PqSignatureScheme::MlDsa87,
                1_400,
            ),
        ];
        for (index, (label, scheme, weight)) in member_specs.iter().enumerate() {
            if let Ok(member) = CommitteeMember::new(
                label,
                &json!({"member": label, "purpose": "pq_upgrade_mesh", "index": index}),
                *scheme,
                *weight,
                self.config.target_privacy_set_size,
                self.height,
                &json!({"rotation_epoch": 1, "member": label}),
                &json!({"asset": "wxmr-devnet", "amount_root": string_root("DEVNET-BOND", label)}),
            ) {
                let _ = self.register_committee_member(member);
            }
        }

        let request = SubmitProposalRequest {
            proposer_root: string_root("DEVNET-PROPOSER", "pq-upgrade-council"),
            surface: UpgradeSurface::VerifierRegistry,
            kind: UpgradeKind::VerifierKeyRotation,
            risk_tier: UpgradeRiskTier::PrivacyCritical,
            title_root: string_root(
                "DEVNET-PROPOSAL-TITLE",
                "rotate-recursive-private-vm-verifier",
            ),
            current_runtime_root: string_root("DEVNET-CURRENT-RUNTIME", "private-vm-verifier-v3"),
            proposed_runtime_root: string_root(
                "DEVNET-PROPOSED-RUNTIME",
                "private-vm-verifier-v4-pq",
            ),
            migration_plan_root: string_root(
                "DEVNET-MIGRATION",
                "two-phase-proof-carrying-rollout",
            ),
            rollback_plan_root: string_root("DEVNET-ROLLBACK", "bounded-emergency-rollback-anchor"),
            privacy_impact_root: string_root(
                "DEVNET-PRIVACY-IMPACT",
                "no-regression-262k-anon-set",
            ),
            fee_impact_root: string_root("DEVNET-FEE-IMPACT", "sponsor-covers-90-percent"),
            bridge_impact_root: string_root("DEVNET-BRIDGE-IMPACT", "monero-finality-unaffected"),
            submitted_at_height: self.height,
            requested_activation_height: self.height.saturating_add(14_400),
            expires_at_height: self.height.saturating_add(self.config.proposal_ttl_blocks),
            sponsor_root: string_root("DEVNET-SPONSOR", "low-fee-upgrade-vault"),
        };
        let proposal = self.submit_proposal(request).ok();
        let proposal_id = proposal.map(|value| value.proposal_id).unwrap_or_default();
        if proposal_id.is_empty() {
            return;
        }
        let member_ids = self.committee_members.keys().cloned().collect::<Vec<_>>();
        for (index, member_id) in member_ids.iter().enumerate() {
            let gate_kind = match index % 5 {
                0 => SafetyGateKind::PqSecurity,
                1 => SafetyGateKind::PrivacyRegression,
                2 => SafetyGateKind::MoneroFinality,
                3 => SafetyGateKind::FeeBound,
                _ => SafetyGateKind::RollbackPlan,
            };
            let _ = self.attest_safety_gate(
                &proposal_id,
                gate_kind,
                member_id,
                &json!({"gate": gate_kind.as_str(), "member": member_id}),
                &json!({"root": "devnet-evidence", "index": index}),
                9_200,
                8_500,
                &json!({"signature": member_id, "scheme": "hybrid-pq"}),
                self.config.target_privacy_set_size,
                self.height.saturating_add(1 + index as u64),
            );
            let _ = self.cast_vote(
                &proposal_id,
                &json!({"proposal": proposal_id, "member": member_id}),
                VoteKind::Approve,
                1_700,
                &json!({"sealed_vote": "approve", "member": member_id}),
                &json!({"eligible": true, "privacy_set": self.config.target_privacy_set_size}),
                &json!({"signature": member_id}),
                self.config.target_privacy_set_size,
                self.height.saturating_add(8 + index as u64),
            );
        }
        let _ = self.add_dependency(
            &proposal_id,
            "private_l2_pq_confidential_smart_contract_rollup_vm_runtime",
            "devnet-compatible-runtime-root",
            "devnet-compatible-runtime-root",
            &json!({"receipt": "compatible"}),
            self.height.saturating_add(16),
        );
        let _ = self.publish_disclosure(
            &proposal_id,
            DisclosureKind::VerifierDiff,
            &json!({"audience": "committee"}),
            &json!({"sealed_diff": "verifier-v3-to-v4"}),
            &json!({"release_after": self.height.saturating_add(2_880)}),
            &json!({"nullifier": "verifier-diff-devnet"}),
            self.height.saturating_add(18),
            self.height.saturating_add(21_600),
        );
        let _ = self.open_timelock(&proposal_id, self.height.saturating_add(32), false);
        let _ = self.reserve_low_fee_execution(
            &proposal_id,
            &json!({"sponsor": "low-fee-upgrade-vault"}),
            "wxmr-devnet",
            8,
            self.config.low_fee_sponsor_coverage_bps,
            8_192,
            1_200,
            &json!({"da_rebate_epoch": 1}),
            self.height.saturating_add(36),
        );
    }

    pub fn register_committee_member(
        &mut self,
        member: CommitteeMember,
    ) -> Result<CommitteeMember> {
        if self.committee_members.len() >= self.config.max_committee_members {
            return Err("committee member limit exceeded".to_string());
        }
        member.validate(&self.config)?;
        self.committee_members
            .insert(member.member_id.clone(), member.clone());
        Ok(member)
    }

    pub fn submit_proposal(
        &mut self,
        request: SubmitProposalRequest,
    ) -> Result<GovernanceUpgradeProposal> {
        if self.proposals.len() >= self.config.max_proposals {
            return Err("proposal limit exceeded".to_string());
        }
        let proposal = GovernanceUpgradeProposal::from_request(request, &self.config)?;
        proposal.validate()?;
        self.proposals
            .insert(proposal.proposal_id.clone(), proposal.clone());
        Ok(proposal)
    }

    pub fn attest_safety_gate(
        &mut self,
        proposal_id: &str,
        gate_kind: SafetyGateKind,
        attester_member_id: &str,
        attestation: &Value,
        evidence: &Value,
        measured_score_bps: u64,
        min_required_score_bps: u64,
        pq_signature: &Value,
        privacy_set_size: u64,
        attested_at_height: u64,
    ) -> Result<SafetyGateAttestation> {
        if self.gate_attestations.len() >= self.config.max_gate_attestations {
            return Err("gate attestation limit exceeded".to_string());
        }
        if !self.committee_members.contains_key(attester_member_id) {
            return Err("gate attester is not a committee member".to_string());
        }
        let proposal_status = self
            .proposals
            .get(proposal_id)
            .map(|proposal| proposal.status)
            .ok_or_else(|| "gate proposal not found".to_string())?;
        if !proposal_status.accepts_gate() {
            return Err("proposal does not accept gate attestations".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("gate attestation privacy set below policy".to_string());
        }
        let gate = SafetyGateAttestation::new(
            proposal_id,
            gate_kind,
            attester_member_id,
            attestation,
            evidence,
            measured_score_bps,
            min_required_score_bps,
            pq_signature,
            privacy_set_size,
            attested_at_height,
        )?;
        self.gate_attestations
            .insert(gate.attestation_id.clone(), gate.clone());
        self.refresh_proposal_roots(proposal_id);
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = ProposalStatus::GateReview;
        }
        Ok(gate)
    }

    pub fn cast_vote(
        &mut self,
        proposal_id: &str,
        nullifier: &Value,
        vote_kind: VoteKind,
        weight_bps: u64,
        encrypted_vote: &Value,
        eligibility: &Value,
        pq_signature: &Value,
        privacy_set_size: u64,
        cast_at_height: u64,
    ) -> Result<VoteCommitment> {
        if self.vote_commitments.len() >= self.config.max_vote_commitments {
            return Err("vote commitment limit exceeded".to_string());
        }
        let proposal_status = self
            .proposals
            .get(proposal_id)
            .map(|proposal| proposal.status)
            .ok_or_else(|| "vote proposal not found".to_string())?;
        if !proposal_status.accepts_vote() {
            return Err("proposal does not accept votes".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("vote privacy set below policy".to_string());
        }
        let vote = VoteCommitment::new(
            proposal_id,
            nullifier,
            vote_kind,
            weight_bps,
            encrypted_vote,
            eligibility,
            pq_signature,
            privacy_set_size,
            cast_at_height,
        )?;
        if self.used_vote_nullifiers.contains(&vote.nullifier_root) {
            let _ = self.open_incident(
                proposal_id,
                MeshIncidentKind::VoteNullifierConflict,
                7_500,
                &json!({"nullifier_root": vote.nullifier_root}),
                &json!({"action": "reject_duplicate_vote"}),
                cast_at_height,
            );
            return Err("vote nullifier already used".to_string());
        }
        self.used_vote_nullifiers
            .insert(vote.nullifier_root.clone());
        self.vote_commitments
            .insert(vote.vote_id.clone(), vote.clone());
        self.refresh_proposal_roots(proposal_id);
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = ProposalStatus::Voting;
            proposal.approval_weight_bps = proposal
                .approval_weight_bps
                .saturating_add(vote.vote_kind.approval_weight(vote.weight_bps))
                .min(MAX_BPS);
            proposal.veto_weight_bps = proposal
                .veto_weight_bps
                .saturating_add(vote.vote_kind.veto_weight(vote.weight_bps))
                .min(MAX_BPS);
            match vote.vote_kind {
                VoteKind::Reject => {
                    proposal.rejection_weight_bps = proposal
                        .rejection_weight_bps
                        .saturating_add(vote.weight_bps)
                        .min(MAX_BPS);
                }
                VoteKind::Abstain => {
                    proposal.abstain_weight_bps = proposal
                        .abstain_weight_bps
                        .saturating_add(vote.weight_bps)
                        .min(MAX_BPS);
                }
                VoteKind::Approve | VoteKind::EmergencyVeto => {}
            }
            if proposal.approval_weight_bps >= self.config.min_vote_approval_bps {
                proposal.status = ProposalStatus::VoteApproved;
            }
            if proposal.veto_weight_bps >= self.config.min_emergency_veto_bps {
                proposal.status = ProposalStatus::EmergencyVetoed;
            }
        }
        Ok(vote)
    }

    pub fn add_dependency(
        &mut self,
        proposal_id: &str,
        runtime_label: &str,
        required_state_root: &str,
        observed_state_root: &str,
        receipt: &Value,
        checked_at_height: u64,
    ) -> Result<CrossRuntimeDependency> {
        if self.dependencies.len() >= self.config.max_dependencies {
            return Err("dependency limit exceeded".to_string());
        }
        if !self.proposals.contains_key(proposal_id) {
            return Err("dependency proposal not found".to_string());
        }
        let dependency = CrossRuntimeDependency::new(
            proposal_id,
            runtime_label,
            required_state_root,
            observed_state_root,
            receipt,
            checked_at_height,
        )?;
        self.dependencies
            .insert(dependency.dependency_id.clone(), dependency.clone());
        self.refresh_proposal_roots(proposal_id);
        if !dependency.compatible {
            let _ = self.open_incident(
                proposal_id,
                MeshIncidentKind::DependencyMismatch,
                8_000,
                &dependency.public_record(),
                &json!({"action": "hold_timelock"}),
                checked_at_height,
            );
        }
        Ok(dependency)
    }

    pub fn publish_disclosure(
        &mut self,
        proposal_id: &str,
        disclosure_kind: DisclosureKind,
        audience: &Value,
        sealed_payload: &Value,
        release_condition: &Value,
        nullifier: &Value,
        published_at_height: u64,
        expires_at_height: u64,
    ) -> Result<SelectiveDisclosure> {
        if self.disclosures.len() >= self.config.max_disclosures {
            return Err("disclosure limit exceeded".to_string());
        }
        if !self.proposals.contains_key(proposal_id) {
            return Err("disclosure proposal not found".to_string());
        }
        let disclosure = SelectiveDisclosure::new(
            proposal_id,
            disclosure_kind,
            audience,
            sealed_payload,
            release_condition,
            nullifier,
            published_at_height,
            expires_at_height,
        )?;
        self.disclosures
            .insert(disclosure.disclosure_id.clone(), disclosure.clone());
        self.refresh_proposal_roots(proposal_id);
        Ok(disclosure)
    }

    pub fn open_timelock(
        &mut self,
        proposal_id: &str,
        scheduled_at_height: u64,
        emergency: bool,
    ) -> Result<TimelockSlot> {
        if self.timelock_slots.len() >= self.config.max_timelock_slots {
            return Err("timelock slot limit exceeded".to_string());
        }
        let proposal = self
            .proposals
            .get(proposal_id)
            .cloned()
            .ok_or_else(|| "timelock proposal not found".to_string())?;
        if !self.proposal_gates_passed(proposal_id) && !emergency {
            return Err("proposal safety gates have not passed".to_string());
        }
        if !self.proposal_dependencies_compatible(proposal_id) && !emergency {
            return Err("proposal dependencies are not compatible".to_string());
        }
        let slot = TimelockSlot::new(&proposal, scheduled_at_height, &self.config, emergency)?;
        self.timelock_slots
            .insert(slot.slot_id.clone(), slot.clone());
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = ProposalStatus::Timelocked;
            proposal.timelock_slot_id = Some(slot.slot_id.clone());
        }
        Ok(slot)
    }

    pub fn reserve_low_fee_execution(
        &mut self,
        proposal_id: &str,
        sponsor: &Value,
        fee_asset_id: &str,
        max_fee_bps: u64,
        sponsor_coverage_bps: u64,
        reserved_execution_units: u64,
        proof_compression_credit_bps: u64,
        da_rebate: &Value,
        reserved_at_height: u64,
    ) -> Result<LowFeeExecutionReservation> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("reservation limit exceeded".to_string());
        }
        if !self.proposals.contains_key(proposal_id) {
            return Err("reservation proposal not found".to_string());
        }
        let reservation = LowFeeExecutionReservation::new(
            proposal_id,
            sponsor,
            fee_asset_id,
            max_fee_bps,
            sponsor_coverage_bps,
            reserved_execution_units,
            proof_compression_credit_bps,
            da_rebate,
            reserved_at_height,
            &self.config,
        )?;
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = ProposalStatus::Reserved;
            proposal.reservation_id = Some(reservation.reservation_id.clone());
        }
        self.refresh_timelock_reservations(proposal_id);
        Ok(reservation)
    }

    pub fn file_emergency_veto(
        &mut self,
        proposal_id: &str,
        veto_committee: &Value,
        reason: &Value,
        evidence: &Value,
        veto_weight_bps: u64,
        pq_signature: &Value,
        filed_at_height: u64,
    ) -> Result<EmergencyVeto> {
        if self.emergency_vetoes.len() >= self.config.max_vetoes {
            return Err("emergency veto limit exceeded".to_string());
        }
        if !self.proposals.contains_key(proposal_id) {
            return Err("veto proposal not found".to_string());
        }
        let veto = EmergencyVeto::new(
            proposal_id,
            veto_committee,
            reason,
            evidence,
            veto_weight_bps,
            pq_signature,
            filed_at_height,
            &self.config,
        )?;
        self.emergency_vetoes
            .insert(veto.veto_id.clone(), veto.clone());
        if veto.accepted {
            if let Some(proposal) = self.proposals.get_mut(proposal_id) {
                proposal.status = ProposalStatus::EmergencyVetoed;
                proposal.veto_weight_bps = proposal
                    .veto_weight_bps
                    .saturating_add(veto_weight_bps)
                    .min(MAX_BPS);
            }
            let _ = self.open_incident(
                proposal_id,
                MeshIncidentKind::EmergencyVeto,
                9_000,
                &veto.public_record(),
                &json!({"action": "halt_execution"}),
                filed_at_height,
            );
        }
        Ok(veto)
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        execution_mode: ExecutionMode,
        executor: &Value,
        pre_state_root: &str,
        post_state_root: &str,
        runtime_receipt: &Value,
        fee_receipt: &Value,
        rollback_anchor: &Value,
        executed_at_height: u64,
    ) -> Result<ExecutionReceipt> {
        if self.execution_receipts.len() >= self.config.max_receipts {
            return Err("execution receipt limit exceeded".to_string());
        }
        let proposal = self
            .proposals
            .get(proposal_id)
            .cloned()
            .ok_or_else(|| "execution proposal not found".to_string())?;
        if !proposal.status.executable() && !execution_mode.emergency() {
            return Err("proposal is not executable".to_string());
        }
        if let Some(slot_id) = proposal.timelock_slot_id.as_ref() {
            let ready = self
                .timelock_slots
                .get(slot_id)
                .map(|slot| slot.ready_at(executed_at_height))
                .unwrap_or(false);
            if !ready && !execution_mode.emergency() {
                return Err("timelock slot is not ready".to_string());
            }
        }
        let receipt = ExecutionReceipt::new(
            proposal_id,
            execution_mode,
            executor,
            pre_state_root,
            post_state_root,
            runtime_receipt,
            fee_receipt,
            rollback_anchor,
            executed_at_height,
            true,
        )?;
        self.execution_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = if execution_mode == ExecutionMode::Rollback {
                ProposalStatus::RolledBack
            } else {
                ProposalStatus::Executed
            };
            proposal.execution_receipt_id = Some(receipt.receipt_id.clone());
        }
        if let Some(slot_id) = proposal.timelock_slot_id.as_ref() {
            if let Some(slot) = self.timelock_slots.get_mut(slot_id) {
                slot.executed = true;
            }
        }
        Ok(receipt)
    }

    pub fn open_incident(
        &mut self,
        proposal_id: &str,
        incident_kind: MeshIncidentKind,
        severity_bps: u64,
        evidence: &Value,
        mitigation: &Value,
        opened_at_height: u64,
    ) -> Result<MeshIncident> {
        if self.incidents.len() >= self.config.max_incidents {
            return Err("incident limit exceeded".to_string());
        }
        let incident = MeshIncident::new(
            proposal_id,
            incident_kind,
            severity_bps,
            evidence,
            mitigation,
            opened_at_height,
        )?;
        self.incidents
            .insert(incident.incident_id.clone(), incident.clone());
        Ok(incident)
    }

    pub fn advance_height(&mut self, height: u64) {
        self.height = self.height.max(height);
        let expired = self
            .proposals
            .iter()
            .filter(|(_, proposal)| {
                !matches!(
                    proposal.status,
                    ProposalStatus::Executed
                        | ProposalStatus::Rejected
                        | ProposalStatus::Cancelled
                        | ProposalStatus::Expired
                        | ProposalStatus::EmergencyVetoed
                        | ProposalStatus::RolledBack
                ) && proposal.expires_at_height < self.height
            })
            .map(|(proposal_id, _)| proposal_id.clone())
            .collect::<Vec<_>>();
        for proposal_id in expired {
            if let Some(proposal) = self.proposals.get_mut(&proposal_id) {
                proposal.status = ProposalStatus::Expired;
            }
        }
    }

    pub fn proposal_gates_passed(&self, proposal_id: &str) -> bool {
        let gates = self
            .gate_attestations
            .values()
            .filter(|gate| gate.proposal_id == proposal_id)
            .collect::<Vec<_>>();
        if gates.is_empty() {
            return false;
        }
        let gate_kinds = gates
            .iter()
            .filter(|gate| gate.passed)
            .map(|gate| gate.gate_kind.as_str().to_string())
            .collect::<BTreeSet<_>>();
        gate_kinds.contains(SafetyGateKind::PqSecurity.as_str())
            && gate_kinds.contains(SafetyGateKind::PrivacyRegression.as_str())
            && gate_kinds.contains(SafetyGateKind::FeeBound.as_str())
    }

    pub fn proposal_dependencies_compatible(&self, proposal_id: &str) -> bool {
        let dependencies = self
            .dependencies
            .values()
            .filter(|dependency| dependency.proposal_id == proposal_id)
            .collect::<Vec<_>>();
        !dependencies.is_empty() && dependencies.iter().all(|dependency| dependency.compatible)
    }

    fn refresh_proposal_roots(&mut self, proposal_id: &str) {
        let gate_ids = self
            .gate_attestations
            .values()
            .filter(|gate| gate.proposal_id == proposal_id)
            .map(|gate| gate.attestation_id.clone())
            .collect::<Vec<_>>();
        let vote_ids = self
            .vote_commitments
            .values()
            .filter(|vote| vote.proposal_id == proposal_id)
            .map(|vote| vote.vote_id.clone())
            .collect::<Vec<_>>();
        let dependency_ids = self
            .dependencies
            .values()
            .filter(|dependency| dependency.proposal_id == proposal_id)
            .map(|dependency| dependency.dependency_id.clone())
            .collect::<Vec<_>>();
        let disclosure_ids = self
            .disclosures
            .values()
            .filter(|disclosure| disclosure.proposal_id == proposal_id)
            .map(|disclosure| disclosure.disclosure_id.clone())
            .collect::<Vec<_>>();
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.gate_root = string_set_root("GOVERNANCE-UPGRADE-GATE-ROOT", &gate_ids);
            proposal.vote_root = string_set_root("GOVERNANCE-UPGRADE-VOTE-ROOT", &vote_ids);
            proposal.dependency_root =
                string_set_root("GOVERNANCE-UPGRADE-DEPENDENCY-ROOT", &dependency_ids);
            proposal.disclosure_root =
                string_set_root("GOVERNANCE-UPGRADE-DISCLOSURE-ROOT", &disclosure_ids);
        }
    }

    fn refresh_timelock_reservations(&mut self, proposal_id: &str) {
        let reservation_ids = self
            .reservations
            .values()
            .filter(|reservation| reservation.proposal_id == proposal_id)
            .map(|reservation| reservation.reservation_id.clone())
            .collect::<Vec<_>>();
        let reservation_root =
            string_set_root("GOVERNANCE-TIMELOCK-RESERVATION-ROOT", &reservation_ids);
        for slot in self
            .timelock_slots
            .values_mut()
            .filter(|slot| slot.proposal_id == proposal_id)
        {
            slot.low_fee_reservation_root = reservation_root.clone();
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            committee_members: self.committee_members.len() as u64,
            active_committee_members: self
                .committee_members
                .values()
                .filter(|member| member.active)
                .count() as u64,
            proposals: self.proposals.len() as u64,
            approved_proposals: self
                .proposals
                .values()
                .filter(|proposal| {
                    matches!(
                        proposal.status,
                        ProposalStatus::VoteApproved
                            | ProposalStatus::Timelocked
                            | ProposalStatus::Ready
                            | ProposalStatus::Reserved
                            | ProposalStatus::Executed
                    )
                })
                .count() as u64,
            executable_proposals: self
                .proposals
                .values()
                .filter(|proposal| proposal.status.executable())
                .count() as u64,
            executed_proposals: self
                .proposals
                .values()
                .filter(|proposal| proposal.status == ProposalStatus::Executed)
                .count() as u64,
            gate_attestations: self.gate_attestations.len() as u64,
            passed_gate_attestations: self
                .gate_attestations
                .values()
                .filter(|gate| gate.passed)
                .count() as u64,
            vote_commitments: self.vote_commitments.len() as u64,
            dependencies: self.dependencies.len() as u64,
            compatible_dependencies: self
                .dependencies
                .values()
                .filter(|dependency| dependency.compatible)
                .count() as u64,
            timelock_slots: self.timelock_slots.len() as u64,
            reservations: self.reservations.len() as u64,
            disclosures: self.disclosures.len() as u64,
            emergency_vetoes: self.emergency_vetoes.len() as u64,
            accepted_vetoes: self
                .emergency_vetoes
                .values()
                .filter(|veto| veto.accepted)
                .count() as u64,
            execution_receipts: self.execution_receipts.len() as u64,
            incidents: self.incidents.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = value_root(
            "GOVERNANCE-UPGRADE-MESH-CONFIG",
            &self.config.public_record(),
        );
        let committee_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-COMMITTEE",
            self.committee_members
                .values()
                .map(CommitteeMember::public_record)
                .collect::<Vec<_>>(),
        );
        let proposal_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-PROPOSALS",
            self.proposals
                .values()
                .map(GovernanceUpgradeProposal::public_record)
                .collect::<Vec<_>>(),
        );
        let gate_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-GATES",
            self.gate_attestations
                .values()
                .map(SafetyGateAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let vote_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-VOTES",
            self.vote_commitments
                .values()
                .map(VoteCommitment::public_record)
                .collect::<Vec<_>>(),
        );
        let dependency_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-DEPENDENCIES",
            self.dependencies
                .values()
                .map(CrossRuntimeDependency::public_record)
                .collect::<Vec<_>>(),
        );
        let timelock_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-TIMELOCKS",
            self.timelock_slots
                .values()
                .map(TimelockSlot::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-RESERVATIONS",
            self.reservations
                .values()
                .map(LowFeeExecutionReservation::public_record)
                .collect::<Vec<_>>(),
        );
        let disclosure_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-DISCLOSURES",
            self.disclosures
                .values()
                .map(SelectiveDisclosure::public_record)
                .collect::<Vec<_>>(),
        );
        let veto_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-VETOES",
            self.emergency_vetoes
                .values()
                .map(EmergencyVeto::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-RECEIPTS",
            self.execution_receipts
                .values()
                .map(ExecutionReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let incident_root = map_root(
            "GOVERNANCE-UPGRADE-MESH-INCIDENTS",
            self.incidents
                .values()
                .map(MeshIncident::public_record)
                .collect::<Vec<_>>(),
        );
        let state_root = domain_hash(
            "GOVERNANCE-UPGRADE-MESH-STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&committee_root),
                HashPart::Str(&proposal_root),
                HashPart::Str(&gate_root),
                HashPart::Str(&vote_root),
                HashPart::Str(&dependency_root),
                HashPart::Str(&timelock_root),
                HashPart::Str(&reservation_root),
                HashPart::Str(&disclosure_root),
                HashPart::Str(&veto_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&incident_root),
                HashPart::U64(self.height),
            ],
            32,
        );
        Roots {
            config_root,
            committee_root,
            proposal_root,
            gate_root,
            vote_root,
            dependency_root,
            timelock_root,
            reservation_root,
            disclosure_root,
            veto_root,
            receipt_root,
            incident_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "governance_upgrade_mesh_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Runtime {
    pub state: State,
}

impl Runtime {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        Ok(Self {
            state: State::new(config, height)?,
        })
    }

    pub fn devnet() -> Self {
        Self {
            state: State::devnet(),
        }
    }

    pub fn state_root(&self) -> String {
        self.state.state_root()
    }

    pub fn public_record(&self) -> Value {
        self.state.public_record()
    }
}

fn member_id(
    label_commitment: &str,
    public_key_root: &str,
    scheme: PqSignatureScheme,
    weight_bps: u64,
    privacy_set_size: u64,
    activation_height: u64,
    rotation_nonce_root: &str,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-MEMBER-ID",
        &[
            HashPart::Str(label_commitment),
            HashPart::Str(public_key_root),
            HashPart::Str(scheme.as_str()),
            HashPart::U64(weight_bps),
            HashPart::U64(privacy_set_size),
            HashPart::U64(activation_height),
            HashPart::Str(rotation_nonce_root),
        ],
        32,
    )
}

fn proposal_id(
    proposer_root: &str,
    surface: UpgradeSurface,
    kind: UpgradeKind,
    risk_tier: UpgradeRiskTier,
    title_root: &str,
    current_runtime_root: &str,
    proposed_runtime_root: &str,
    migration_plan_root: &str,
    rollback_plan_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-PROPOSAL-ID",
        &[
            HashPart::Str(proposer_root),
            HashPart::Str(surface.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(risk_tier.as_str()),
            HashPart::Str(title_root),
            HashPart::Str(current_runtime_root),
            HashPart::Str(proposed_runtime_root),
            HashPart::Str(migration_plan_root),
            HashPart::Str(rollback_plan_root),
            HashPart::U64(submitted_at_height),
        ],
        32,
    )
}

fn gate_attestation_id(
    proposal_id: &str,
    gate_kind: SafetyGateKind,
    attester_member_id: &str,
    attestation_root: &str,
    evidence_root: &str,
    measured_score_bps: u64,
    min_required_score_bps: u64,
    pq_signature_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-GATE-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(gate_kind.as_str()),
            HashPart::Str(attester_member_id),
            HashPart::Str(attestation_root),
            HashPart::Str(evidence_root),
            HashPart::U64(measured_score_bps),
            HashPart::U64(min_required_score_bps),
            HashPart::Str(pq_signature_root),
            HashPart::U64(attested_at_height),
        ],
        32,
    )
}

fn vote_id(
    proposal_id: &str,
    nullifier_root: &str,
    vote_kind: VoteKind,
    weight_bps: u64,
    encrypted_vote_root: &str,
    eligibility_root: &str,
    pq_signature_root: &str,
    cast_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-VOTE-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(vote_kind.as_str()),
            HashPart::U64(weight_bps),
            HashPart::Str(encrypted_vote_root),
            HashPart::Str(eligibility_root),
            HashPart::Str(pq_signature_root),
            HashPart::U64(cast_at_height),
        ],
        32,
    )
}

fn dependency_id(
    proposal_id: &str,
    runtime_label: &str,
    required_state_root: &str,
    observed_state_root: &str,
    receipt_root: &str,
    checked_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-DEPENDENCY-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(runtime_label),
            HashPart::Str(required_state_root),
            HashPart::Str(observed_state_root),
            HashPart::Str(receipt_root),
            HashPart::U64(checked_at_height),
        ],
        32,
    )
}

fn disclosure_id(
    proposal_id: &str,
    disclosure_kind: DisclosureKind,
    audience_root: &str,
    sealed_payload_root: &str,
    release_condition_root: &str,
    nullifier_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-DISCLOSURE-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(disclosure_kind.as_str()),
            HashPart::Str(audience_root),
            HashPart::Str(sealed_payload_root),
            HashPart::Str(release_condition_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(published_at_height),
        ],
        32,
    )
}

fn timelock_slot_id(
    proposal_id: &str,
    scheduled_at_height: u64,
    executable_at_height: u64,
    expires_at_height: u64,
    dependency_root: &str,
    gate_root: &str,
    vote_root: &str,
    emergency: bool,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-TIMELOCK-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::U64(scheduled_at_height),
            HashPart::U64(executable_at_height),
            HashPart::U64(expires_at_height),
            HashPart::Str(dependency_root),
            HashPart::Str(gate_root),
            HashPart::Str(vote_root),
            HashPart::U64(if emergency { 1 } else { 0 }),
        ],
        32,
    )
}

fn reservation_id(
    proposal_id: &str,
    sponsor_root: &str,
    fee_asset_id: &str,
    max_fee_bps: u64,
    sponsor_coverage_bps: u64,
    reserved_execution_units: u64,
    proof_compression_credit_bps: u64,
    da_rebate_root: &str,
    reserved_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-RESERVATION-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(sponsor_root),
            HashPart::Str(fee_asset_id),
            HashPart::U64(max_fee_bps),
            HashPart::U64(sponsor_coverage_bps),
            HashPart::U64(reserved_execution_units),
            HashPart::U64(proof_compression_credit_bps),
            HashPart::Str(da_rebate_root),
            HashPart::U64(reserved_at_height),
        ],
        32,
    )
}

fn veto_id(
    proposal_id: &str,
    veto_committee_root: &str,
    reason_root: &str,
    evidence_root: &str,
    veto_weight_bps: u64,
    pq_signature_root: &str,
    filed_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-VETO-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(veto_committee_root),
            HashPart::Str(reason_root),
            HashPart::Str(evidence_root),
            HashPart::U64(veto_weight_bps),
            HashPart::Str(pq_signature_root),
            HashPart::U64(filed_at_height),
        ],
        32,
    )
}

fn execution_receipt_id(
    proposal_id: &str,
    execution_mode: ExecutionMode,
    executor_root: &str,
    pre_state_root: &str,
    post_state_root: &str,
    runtime_receipt_root: &str,
    fee_receipt_root: &str,
    rollback_anchor_root: &str,
    executed_at_height: u64,
    success: bool,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-EXECUTION-RECEIPT-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(execution_mode.as_str()),
            HashPart::Str(executor_root),
            HashPart::Str(pre_state_root),
            HashPart::Str(post_state_root),
            HashPart::Str(runtime_receipt_root),
            HashPart::Str(fee_receipt_root),
            HashPart::Str(rollback_anchor_root),
            HashPart::U64(executed_at_height),
            HashPart::U64(if success { 1 } else { 0 }),
        ],
        32,
    )
}

fn incident_id(
    proposal_id: &str,
    incident_kind: MeshIncidentKind,
    severity_bps: u64,
    evidence_root: &str,
    mitigation_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "GOVERNANCE-UPGRADE-MESH-INCIDENT-ID",
        &[
            HashPart::Str(proposal_id),
            HashPart::Str(incident_kind.as_str()),
            HashPart::U64(severity_bps),
            HashPart::Str(evidence_root),
            HashPart::Str(mitigation_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_root(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by_key(|value| value_root("GOVERNANCE-UPGRADE-MESH-SORT", value));
    merkle_root(domain, &records)
}
