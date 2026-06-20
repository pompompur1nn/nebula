use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub type PrivateContractUpgradeSimulatorResult<T> = Result<T, String>;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_PROTOCOL_ID: &str =
    "nebula-private-contract-upgrade-simulator-v1";
pub const PROTOCOL_VERSION: &str = PRIVATE_CONTRACT_UPGRADE_SIMULATOR_PROTOCOL_ID;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEVNET_HEIGHT: u64 = 2_784;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_PQ_APPROVAL_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-contract-upgrade-v1";
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_ENVELOPE_SUITE: &str =
    "ML-KEM-1024+XChaCha20Poly1305-upgrade-envelope-v1";
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_BYTECODE_DIFF_SCHEME: &str =
    "private-bytecode-abi-commitment-diff-v1";
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_COMPATIBILITY_PROOF_SYSTEM: &str =
    "zk-private-contract-compatibility-proof-v1";
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DRY_RUN_TRACE_SCHEME: &str =
    "encrypted-contract-upgrade-dry-run-trace-v1";
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_APPROVAL_WINDOW_BLOCKS: u64 = 720;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 1_440;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 4_320;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_REQUIRED_APPROVAL_WEIGHT: u64 = 5;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_EMERGENCY_APPROVAL_WEIGHT: u64 = 3;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 900_000;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MAX_SPONSORED_FEE_UNITS: u64 = 18_000;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_SLASH_BOND_UNITS: u64 = 75_000;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MAX_RISK_SCORE: u64 = 10_000;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_RISK_REVIEW_THRESHOLD: u64 = 6_500;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CONTRACT_UPGRADE_SIMULATOR_MAX_RECORDS: usize = 1_048_576;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeScope {
    RuntimePatch,
    AbiExtension,
    StorageMigration,
    CircuitUpgrade,
    FeePolicyHook,
    OracleAdapter,
    BridgeAdapter,
    EmergencyHotfix,
}
#[rustfmt::skip]
impl UpgradeScope {
    pub fn as_str(self) -> &'static str { match self {
        Self::RuntimePatch => "runtime_patch", Self::AbiExtension => "abi_extension",
        Self::StorageMigration => "storage_migration", Self::CircuitUpgrade => "circuit_upgrade",
        Self::FeePolicyHook => "fee_policy_hook", Self::OracleAdapter => "oracle_adapter",
        Self::BridgeAdapter => "bridge_adapter", Self::EmergencyHotfix => "emergency_hotfix",
    }}
    pub fn requires_emergency_weight(self) -> bool {
        matches!(self, Self::EmergencyHotfix | Self::BridgeAdapter)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeStatus {
    Draft,
    Proposed,
    ApprovalOpen,
    Approved,
    Simulating,
    Ready,
    Executed,
    RolledBack,
    Rejected,
    Challenged,
    Expired,
}
#[rustfmt::skip]
impl UpgradeStatus {
    pub fn mutable(self) -> bool { matches!(self, Self::Draft | Self::Proposed | Self::ApprovalOpen | Self::Approved | Self::Simulating | Self::Ready | Self::Challenged) }
    pub fn terminal(self) -> bool { matches!(self, Self::Executed | Self::RolledBack | Self::Rejected | Self::Expired) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintainerRole {
    RuntimeMaintainer,
    CircuitMaintainer,
    StorageMaintainer,
    SecurityReviewer,
    FeeSponsor,
    EmergencyCouncil,
}
#[rustfmt::skip]
impl MaintainerRole {
    pub fn as_str(self) -> &'static str { match self {
        Self::RuntimeMaintainer => "runtime_maintainer", Self::CircuitMaintainer => "circuit_maintainer",
        Self::StorageMaintainer => "storage_maintainer", Self::SecurityReviewer => "security_reviewer",
        Self::FeeSponsor => "fee_sponsor", Self::EmergencyCouncil => "emergency_council",
    }}
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintainerStatus {
    Pending,
    Active,
    Warning,
    Suspended,
    Slashed,
    Retired,
}
#[rustfmt::skip]
impl MaintainerStatus {
    pub fn may_approve(self) -> bool { matches!(self, Self::Active | Self::Warning) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Sealed,
    Counted,
    Superseded,
    Challenged,
    Rejected,
    Slashed,
    Expired,
}
#[rustfmt::skip]
impl ApprovalStatus {
    pub fn active(self) -> bool { matches!(self, Self::Sealed | Self::Counted | Self::Challenged) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Bytecode,
    Abi,
    StorageLayout,
    VerifierKey,
    PermissionMap,
    FeeSchedule,
    RollbackBundle,
}
#[rustfmt::skip]
impl DiffKind {
    pub fn as_str(self) -> &'static str { match self {
        Self::Bytecode => "bytecode", Self::Abi => "abi", Self::StorageLayout => "storage_layout",
        Self::VerifierKey => "verifier_key", Self::PermissionMap => "permission_map",
        Self::FeeSchedule => "fee_schedule", Self::RollbackBundle => "rollback_bundle",
    }}
    pub fn risk_weight(self) -> u64 { match self {
        Self::Bytecode => 1_500, Self::StorageLayout => 1_350, Self::VerifierKey => 1_250,
        Self::PermissionMap => 1_050, Self::RollbackBundle => 900, Self::FeeSchedule => 650, Self::Abi => 500,
    }}
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Hidden,
    Committed,
    Reviewed,
    Accepted,
    Rejected,
    Superseded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Planned,
    Rehearsing,
    Rehearsed,
    Armed,
    Executed,
    Failed,
    Expired,
}
#[rustfmt::skip]
impl RollbackStatus {
    pub fn live(self) -> bool { matches!(self, Self::Planned | Self::Rehearsing | Self::Rehearsed | Self::Armed) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Reserved,
    Exhausted,
    Paused,
    Slashed,
    Closed,
}
#[rustfmt::skip]
impl SponsorStatus {
    pub fn spendable(self) -> bool { matches!(self, Self::Active | Self::Reserved) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Submitted,
    Verified,
    Waived,
    Failed,
    Challenged,
    Expired,
}
#[rustfmt::skip]
impl CompatibilityStatus {
    pub fn accepted(self) -> bool { matches!(self, Self::Verified | Self::Waived) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DryRunStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Redacted,
    Expired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidencePending,
    Sustained,
    Rejected,
    Slashed,
    Expired,
}
#[rustfmt::skip]
impl ChallengeStatus {
    pub fn open(self) -> bool { matches!(self, Self::Open | Self::EvidencePending) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidApproval,
    HiddenIncompatibility,
    DryRunFraud,
    RollbackFailure,
    SponsorAbuse,
    ChallengeFraud,
}
#[rustfmt::skip]
impl SlashReason {
    pub fn as_str(self) -> &'static str { match self {
        Self::InvalidApproval => "invalid_approval", Self::HiddenIncompatibility => "hidden_incompatibility",
        Self::DryRunFraud => "dry_run_fraud", Self::RollbackFailure => "rollback_failure",
        Self::SponsorAbuse => "sponsor_abuse", Self::ChallengeFraud => "challenge_fraud",
    }}
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractUpgradeSimulatorConfig {
    pub chain_id: String,
    pub protocol_id: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_approval_suite: String,
    pub envelope_suite: String,
    pub bytecode_diff_scheme: String,
    pub compatibility_proof_system: String,
    pub dry_run_trace_scheme: String,
    pub proposal_ttl_blocks: u64,
    pub approval_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub rollback_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub required_approval_weight: u64,
    pub emergency_approval_weight: u64,
    pub default_sponsor_budget_units: u64,
    pub max_sponsored_fee_units: u64,
    pub default_slash_bond_units: u64,
    pub max_risk_score: u64,
    pub risk_review_threshold: u64,
}
impl PrivateContractUpgradeSimulatorConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_id: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_PROTOCOL_ID.to_string(),
            schema_version: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_SCHEMA_VERSION,
            hash_suite: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_HASH_SUITE.to_string(),
            pq_approval_suite: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_PQ_APPROVAL_SUITE.to_string(),
            envelope_suite: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_ENVELOPE_SUITE.to_string(),
            bytecode_diff_scheme: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_BYTECODE_DIFF_SCHEME
                .to_string(),
            compatibility_proof_system:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_COMPATIBILITY_PROOF_SYSTEM.to_string(),
            dry_run_trace_scheme: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DRY_RUN_TRACE_SCHEME
                .to_string(),
            proposal_ttl_blocks: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_PROPOSAL_TTL_BLOCKS,
            approval_window_blocks:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_APPROVAL_WINDOW_BLOCKS,
            challenge_window_blocks:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            rollback_window_blocks:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MIN_PQ_SECURITY_BITS,
            required_approval_weight:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_REQUIRED_APPROVAL_WEIGHT,
            emergency_approval_weight:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_EMERGENCY_APPROVAL_WEIGHT,
            default_sponsor_budget_units:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_sponsored_fee_units:
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MAX_SPONSORED_FEE_UNITS,
            default_slash_bond_units: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_SLASH_BOND_UNITS,
            max_risk_score: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_MAX_RISK_SCORE,
            risk_review_threshold: PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEFAULT_RISK_REVIEW_THRESHOLD,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn config_root(&self) -> String {
        upgrade_json_root("CONFIG", &self.public_record())
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("private contract upgrade simulator chain id mismatch".to_string());
        }
        if self.protocol_id != PRIVATE_CONTRACT_UPGRADE_SIMULATOR_PROTOCOL_ID {
            return Err("private contract upgrade simulator protocol id mismatch".to_string());
        }
        if self.schema_version == 0 {
            return Err("private contract upgrade simulator schema version is zero".to_string());
        }
        if self.proposal_ttl_blocks == 0
            || self.approval_window_blocks == 0
            || self.challenge_window_blocks == 0
            || self.rollback_window_blocks == 0
        {
            return Err("private contract upgrade simulator windows must be non-zero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("private contract upgrade simulator pq security too low".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("private contract upgrade simulator privacy set is zero".to_string());
        }
        if self.required_approval_weight == 0 || self.emergency_approval_weight == 0 {
            return Err("private contract upgrade simulator approval weight is zero".to_string());
        }
        if self.max_sponsored_fee_units > self.default_sponsor_budget_units {
            return Err(
                "private contract upgrade simulator max sponsored fee exceeds budget".to_string(),
            );
        }
        if self.risk_review_threshold > self.max_risk_score {
            return Err(
                "private contract upgrade simulator risk threshold exceeds maximum".to_string(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeRiskScore {
    pub score_id: String,
    pub proposal_id: String,
    pub bytecode_delta_bps: u64,
    pub abi_delta_bps: u64,
    pub storage_delta_bps: u64,
    pub proof_delta_bps: u64,
    pub sponsor_exposure_bps: u64,
    pub rollback_confidence_bps: u64,
    pub aggregate_score: u64,
    pub review_required: bool,
    pub risk_model_root: String,
    pub evaluated_height: u64,
}
impl UpgradeRiskScore {
    pub fn new(
        proposal_id: &str,
        bytecode_delta_bps: u64,
        abi_delta_bps: u64,
        storage_delta_bps: u64,
        proof_delta_bps: u64,
        sponsor_exposure_bps: u64,
        rollback_confidence_bps: u64,
        evaluated_height: u64,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> Self {
        let risk_sum = bytecode_delta_bps
            .saturating_mul(24)
            .saturating_add(abi_delta_bps.saturating_mul(12))
            .saturating_add(storage_delta_bps.saturating_mul(22))
            .saturating_add(proof_delta_bps.saturating_mul(20))
            .saturating_add(sponsor_exposure_bps.saturating_mul(10))
            .saturating_add(
                PRIVATE_CONTRACT_UPGRADE_SIMULATOR_MAX_BPS
                    .saturating_sub(rollback_confidence_bps)
                    .saturating_mul(12),
            )
            / 100;
        let aggregate_score = risk_sum.min(config.max_risk_score);
        let score_id = upgrade_hash(
            "RISK-SCORE-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Int(evaluated_height as i128),
                HashPart::Int(aggregate_score as i128),
            ],
        );
        Self {
            score_id,
            proposal_id: proposal_id.to_string(),
            bytecode_delta_bps,
            abi_delta_bps,
            storage_delta_bps,
            proof_delta_bps,
            sponsor_exposure_bps,
            rollback_confidence_bps,
            aggregate_score,
            review_required: aggregate_score >= config.risk_review_threshold,
            risk_model_root: upgrade_hash(
                "RISK-MODEL",
                &[
                    HashPart::Str(proposal_id),
                    HashPart::Int(bytecode_delta_bps as i128),
                    HashPart::Int(abi_delta_bps as i128),
                    HashPart::Int(storage_delta_bps as i128),
                    HashPart::Int(proof_delta_bps as i128),
                    HashPart::Int(sponsor_exposure_bps as i128),
                    HashPart::Int(rollback_confidence_bps as i128),
                ],
            ),
            evaluated_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(
        &self,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.score_id.is_empty() || self.proposal_id.is_empty() {
            return Err("upgrade risk score id and proposal id must be non-empty".to_string());
        }
        for value in [
            self.bytecode_delta_bps,
            self.abi_delta_bps,
            self.storage_delta_bps,
            self.proof_delta_bps,
            self.sponsor_exposure_bps,
            self.rollback_confidence_bps,
        ] {
            if value > PRIVATE_CONTRACT_UPGRADE_SIMULATOR_MAX_BPS {
                return Err("upgrade risk score component exceeds bps denominator".to_string());
            }
        }
        if self.aggregate_score > config.max_risk_score {
            return Err("upgrade risk score exceeds configured maximum".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedUpgradeProposal {
    pub proposal_id: String,
    pub contract_id: String,
    pub scope: UpgradeScope,
    pub status: UpgradeStatus,
    pub proposer_commitment: String,
    pub current_package_root: String,
    pub proposed_package_root: String,
    pub private_envelope_root: String,
    pub metadata_commitment: String,
    pub sponsor_id: String,
    pub risk_score_id: String,
    pub min_privacy_set_size: u64,
    pub required_approval_weight: u64,
    pub created_height: u64,
    pub approval_deadline_height: u64,
    pub challenge_deadline_height: u64,
    pub expires_height: u64,
}
impl ShieldedUpgradeProposal {
    pub fn new(
        contract_id: &str,
        scope: UpgradeScope,
        proposer_commitment: &str,
        current_package_root: &str,
        proposed_package_root: &str,
        private_envelope_root: &str,
        metadata_commitment: &str,
        sponsor_id: &str,
        created_height: u64,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> Self {
        let proposal_id = upgrade_hash(
            "PROPOSAL-ID",
            &[
                HashPart::Str(contract_id),
                HashPart::Str(scope.as_str()),
                HashPart::Str(proposer_commitment),
                HashPart::Str(current_package_root),
                HashPart::Str(proposed_package_root),
                HashPart::Int(created_height as i128),
            ],
        );
        let required_approval_weight = if scope.requires_emergency_weight() {
            config.emergency_approval_weight
        } else {
            config.required_approval_weight
        };
        Self {
            proposal_id,
            contract_id: contract_id.to_string(),
            scope,
            status: UpgradeStatus::Proposed,
            proposer_commitment: proposer_commitment.to_string(),
            current_package_root: current_package_root.to_string(),
            proposed_package_root: proposed_package_root.to_string(),
            private_envelope_root: private_envelope_root.to_string(),
            metadata_commitment: metadata_commitment.to_string(),
            sponsor_id: sponsor_id.to_string(),
            risk_score_id: String::new(),
            min_privacy_set_size: config.min_privacy_set_size,
            required_approval_weight,
            created_height,
            approval_deadline_height: created_height.saturating_add(config.approval_window_blocks),
            challenge_deadline_height: created_height
                .saturating_add(config.approval_window_blocks)
                .saturating_add(config.challenge_window_blocks),
            expires_height: created_height.saturating_add(config.proposal_ttl_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(
        &self,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.proposal_id.is_empty() || self.contract_id.is_empty() {
            return Err(
                "shielded upgrade proposal id and contract id must be non-empty".to_string(),
            );
        }
        if self.current_package_root.is_empty() || self.proposed_package_root.is_empty() {
            return Err("shielded upgrade package roots must be non-empty".to_string());
        }
        if self.current_package_root == self.proposed_package_root {
            return Err("shielded upgrade proposal must change package root".to_string());
        }
        if self.private_envelope_root.is_empty() || self.metadata_commitment.is_empty() {
            return Err("shielded upgrade proposal commitments must be non-empty".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err(
                "shielded upgrade proposal privacy set below configured minimum".to_string(),
            );
        }
        if self.required_approval_weight == 0 {
            return Err("shielded upgrade proposal requires zero approval weight".to_string());
        }
        if self.approval_deadline_height <= self.created_height
            || self.challenge_deadline_height < self.approval_deadline_height
            || self.expires_height <= self.created_height
        {
            return Err("shielded upgrade proposal height window is invalid".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMaintainer {
    pub maintainer_id: String,
    pub role: MaintainerRole,
    pub status: MaintainerStatus,
    pub maintainer_commitment: String,
    pub pq_key_root: String,
    pub authorization_root: String,
    pub approval_weight: u64,
    pub bonded_units: u64,
    pub slashed_units: u64,
    pub registered_height: u64,
    pub updated_height: u64,
}
impl PqMaintainer {
    pub fn new(
        role: MaintainerRole,
        maintainer_commitment: &str,
        pq_key_root: &str,
        authorization_root: &str,
        approval_weight: u64,
        bonded_units: u64,
        registered_height: u64,
    ) -> Self {
        let maintainer_id = upgrade_hash(
            "MAINTAINER-ID",
            &[
                HashPart::Str(role.as_str()),
                HashPart::Str(maintainer_commitment),
                HashPart::Str(pq_key_root),
                HashPart::Int(registered_height as i128),
            ],
        );
        Self {
            maintainer_id,
            role,
            status: MaintainerStatus::Active,
            maintainer_commitment: maintainer_commitment.to_string(),
            pq_key_root: pq_key_root.to_string(),
            authorization_root: authorization_root.to_string(),
            approval_weight,
            bonded_units,
            slashed_units: 0,
            registered_height,
            updated_height: registered_height,
        }
    }
    pub fn available_bond_units(&self) -> u64 {
        self.bonded_units.saturating_sub(self.slashed_units)
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(
        &self,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.maintainer_id.is_empty()
            || self.maintainer_commitment.is_empty()
            || self.pq_key_root.is_empty()
        {
            return Err("pq maintainer identity roots must be non-empty".to_string());
        }
        if self.approval_weight == 0 {
            return Err("pq maintainer approval weight is zero".to_string());
        }
        if self.bonded_units < config.default_slash_bond_units {
            return Err("pq maintainer bond below configured slash bond".to_string());
        }
        if self.slashed_units > self.bonded_units {
            return Err("pq maintainer slashed units exceed bond".to_string());
        }
        if self.updated_height < self.registered_height {
            return Err("pq maintainer updated height precedes registration".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMaintainerApproval {
    pub approval_id: String,
    pub proposal_id: String,
    pub maintainer_id: String,
    pub role: MaintainerRole,
    pub status: ApprovalStatus,
    pub approval_weight: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub nullifier: String,
    pub min_pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
}
impl PqMaintainerApproval {
    pub fn new(
        proposal_id: &str,
        maintainer: &PqMaintainer,
        pq_signature_root: &str,
        transcript_root: &str,
        nullifier: &str,
        submitted_height: u64,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> Self {
        let approval_id = upgrade_hash(
            "APPROVAL-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Str(&maintainer.maintainer_id),
                HashPart::Str(nullifier),
                HashPart::Int(submitted_height as i128),
            ],
        );
        Self {
            approval_id,
            proposal_id: proposal_id.to_string(),
            maintainer_id: maintainer.maintainer_id.clone(),
            role: maintainer.role,
            status: ApprovalStatus::Sealed,
            approval_weight: maintainer.approval_weight,
            pq_signature_root: pq_signature_root.to_string(),
            transcript_root: transcript_root.to_string(),
            nullifier: nullifier.to_string(),
            min_pq_security_bits: config.min_pq_security_bits,
            submitted_height,
            expires_height: submitted_height.saturating_add(config.approval_window_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(
        &self,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.approval_id.is_empty()
            || self.proposal_id.is_empty()
            || self.maintainer_id.is_empty()
            || self.nullifier.is_empty()
        {
            return Err("pq maintainer approval identity fields must be non-empty".to_string());
        }
        if self.approval_weight == 0 {
            return Err("pq maintainer approval weight is zero".to_string());
        }
        if self.pq_signature_root.is_empty() || self.transcript_root.is_empty() {
            return Err("pq maintainer approval roots must be non-empty".to_string());
        }
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err("pq maintainer approval security bits below config minimum".to_string());
        }
        if self.expires_height <= self.submitted_height {
            return Err("pq maintainer approval expiry must exceed submitted height".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentDiff {
    pub diff_id: String,
    pub proposal_id: String,
    pub diff_kind: DiffKind,
    pub status: DiffStatus,
    pub old_commitment_root: String,
    pub new_commitment_root: String,
    pub encrypted_diff_root: String,
    pub semantic_summary_root: String,
    pub reviewer_policy_root: String,
    pub line_delta_bucket: u64,
    pub selector_delta_count: u64,
    pub storage_slot_delta_count: u64,
    pub risk_weight_bps: u64,
    pub committed_height: u64,
}
impl CommitmentDiff {
    pub fn new(
        proposal_id: &str,
        diff_kind: DiffKind,
        old_commitment_root: &str,
        new_commitment_root: &str,
        encrypted_diff_root: &str,
        semantic_summary_root: &str,
        reviewer_policy_root: &str,
        line_delta_bucket: u64,
        selector_delta_count: u64,
        storage_slot_delta_count: u64,
        committed_height: u64,
    ) -> Self {
        let diff_id = upgrade_hash(
            "DIFF-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Str(diff_kind.as_str()),
                HashPart::Str(old_commitment_root),
                HashPart::Str(new_commitment_root),
                HashPart::Int(committed_height as i128),
            ],
        );
        Self {
            diff_id,
            proposal_id: proposal_id.to_string(),
            diff_kind,
            status: DiffStatus::Committed,
            old_commitment_root: old_commitment_root.to_string(),
            new_commitment_root: new_commitment_root.to_string(),
            encrypted_diff_root: encrypted_diff_root.to_string(),
            semantic_summary_root: semantic_summary_root.to_string(),
            reviewer_policy_root: reviewer_policy_root.to_string(),
            line_delta_bucket,
            selector_delta_count,
            storage_slot_delta_count,
            risk_weight_bps: diff_kind.risk_weight(),
            committed_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.diff_id.is_empty() || self.proposal_id.is_empty() {
            return Err("commitment diff id and proposal id must be non-empty".to_string());
        }
        if self.old_commitment_root.is_empty()
            || self.new_commitment_root.is_empty()
            || self.encrypted_diff_root.is_empty()
        {
            return Err("commitment diff roots must be non-empty".to_string());
        }
        if self.old_commitment_root == self.new_commitment_root {
            return Err("commitment diff old and new roots must differ".to_string());
        }
        if self.risk_weight_bps > PRIVATE_CONTRACT_UPGRADE_SIMULATOR_MAX_BPS {
            return Err("commitment diff risk weight exceeds bps denominator".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRehearsal {
    pub rehearsal_id: String,
    pub proposal_id: String,
    pub status: RollbackStatus,
    pub rollback_bundle_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub invariant_result_root: String,
    pub operator_commitment: String,
    pub pq_attestation_root: String,
    pub max_revert_blocks: u64,
    pub simulated_loss_bucket: u64,
    pub confidence_bps: u64,
    pub scheduled_height: u64,
    pub completed_height: u64,
    pub expires_height: u64,
}
impl RollbackRehearsal {
    pub fn new(
        proposal_id: &str,
        rollback_bundle_root: &str,
        pre_state_root: &str,
        post_state_root: &str,
        invariant_result_root: &str,
        operator_commitment: &str,
        pq_attestation_root: &str,
        max_revert_blocks: u64,
        simulated_loss_bucket: u64,
        confidence_bps: u64,
        scheduled_height: u64,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> Self {
        let rehearsal_id = upgrade_hash(
            "ROLLBACK-REHEARSAL-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Str(rollback_bundle_root),
                HashPart::Str(pre_state_root),
                HashPart::Str(post_state_root),
                HashPart::Int(scheduled_height as i128),
            ],
        );
        Self {
            rehearsal_id,
            proposal_id: proposal_id.to_string(),
            status: RollbackStatus::Planned,
            rollback_bundle_root: rollback_bundle_root.to_string(),
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            invariant_result_root: invariant_result_root.to_string(),
            operator_commitment: operator_commitment.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            max_revert_blocks,
            simulated_loss_bucket,
            confidence_bps,
            scheduled_height,
            completed_height: 0,
            expires_height: scheduled_height.saturating_add(config.rollback_window_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.rehearsal_id.is_empty() || self.proposal_id.is_empty() {
            return Err("rollback rehearsal id and proposal id must be non-empty".to_string());
        }
        if self.rollback_bundle_root.is_empty()
            || self.pre_state_root.is_empty()
            || self.post_state_root.is_empty()
            || self.invariant_result_root.is_empty()
        {
            return Err("rollback rehearsal roots must be non-empty".to_string());
        }
        if self.pre_state_root == self.post_state_root {
            return Err("rollback rehearsal pre and post roots must differ".to_string());
        }
        if self.confidence_bps > PRIVATE_CONTRACT_UPGRADE_SIMULATOR_MAX_BPS {
            return Err("rollback rehearsal confidence exceeds bps denominator".to_string());
        }
        if self.expires_height <= self.scheduled_height {
            return Err("rollback rehearsal expiry must exceed scheduled height".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorBudget {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub status: SponsorStatus,
    pub budget_root: String,
    pub policy_root: String,
    pub asset_id: String,
    pub total_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_units_per_upgrade: u64,
    pub created_height: u64,
    pub expires_height: u64,
}
impl LowFeeSponsorBudget {
    pub fn new(
        sponsor_commitment: &str,
        budget_root: &str,
        policy_root: &str,
        asset_id: &str,
        total_units: u64,
        max_fee_units_per_upgrade: u64,
        created_height: u64,
        expires_height: u64,
    ) -> Self {
        let sponsor_id = upgrade_hash(
            "SPONSOR-ID",
            &[
                HashPart::Str(sponsor_commitment),
                HashPart::Str(budget_root),
                HashPart::Str(asset_id),
                HashPart::Int(created_height as i128),
            ],
        );
        Self {
            sponsor_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            status: SponsorStatus::Active,
            budget_root: budget_root.to_string(),
            policy_root: policy_root.to_string(),
            asset_id: asset_id.to_string(),
            total_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_units_per_upgrade,
            created_height,
            expires_height,
        }
    }
    pub fn available_units(&self) -> u64 {
        self.total_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(
        &self,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.sponsor_id.is_empty() || self.sponsor_commitment.is_empty() {
            return Err("low fee sponsor id and commitment must be non-empty".to_string());
        }
        if self.budget_root.is_empty() || self.policy_root.is_empty() || self.asset_id.is_empty() {
            return Err("low fee sponsor roots and asset id must be non-empty".to_string());
        }
        if self.max_fee_units_per_upgrade > config.max_sponsored_fee_units {
            return Err("low fee sponsor per-upgrade limit exceeds config".to_string());
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.total_units {
            return Err("low fee sponsor reserved plus spent exceeds total".to_string());
        }
        if self.expires_height <= self.created_height {
            return Err("low fee sponsor expiry must exceed creation height".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityProof {
    pub proof_id: String,
    pub proposal_id: String,
    pub status: CompatibilityStatus,
    pub proof_system: String,
    pub public_input_root: String,
    pub witness_commitment: String,
    pub old_abi_root: String,
    pub new_abi_root: String,
    pub storage_invariant_root: String,
    pub selector_compatibility_root: String,
    pub verifier_key_root: String,
    pub submitted_height: u64,
    pub verified_height: u64,
    pub expires_height: u64,
}
impl CompatibilityProof {
    pub fn new(
        proposal_id: &str,
        public_input_root: &str,
        witness_commitment: &str,
        old_abi_root: &str,
        new_abi_root: &str,
        storage_invariant_root: &str,
        selector_compatibility_root: &str,
        verifier_key_root: &str,
        submitted_height: u64,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> Self {
        let proof_id = upgrade_hash(
            "COMPATIBILITY-PROOF-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Str(public_input_root),
                HashPart::Str(old_abi_root),
                HashPart::Str(new_abi_root),
                HashPart::Int(submitted_height as i128),
            ],
        );
        Self {
            proof_id,
            proposal_id: proposal_id.to_string(),
            status: CompatibilityStatus::Submitted,
            proof_system: config.compatibility_proof_system.clone(),
            public_input_root: public_input_root.to_string(),
            witness_commitment: witness_commitment.to_string(),
            old_abi_root: old_abi_root.to_string(),
            new_abi_root: new_abi_root.to_string(),
            storage_invariant_root: storage_invariant_root.to_string(),
            selector_compatibility_root: selector_compatibility_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            submitted_height,
            verified_height: 0,
            expires_height: submitted_height.saturating_add(config.challenge_window_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.proof_id.is_empty() || self.proposal_id.is_empty() {
            return Err("compatibility proof id and proposal id must be non-empty".to_string());
        }
        if self.public_input_root.is_empty()
            || self.witness_commitment.is_empty()
            || self.old_abi_root.is_empty()
            || self.new_abi_root.is_empty()
            || self.verifier_key_root.is_empty()
        {
            return Err("compatibility proof roots must be non-empty".to_string());
        }
        if self.old_abi_root == self.new_abi_root {
            return Err("compatibility proof old and new abi roots must differ".to_string());
        }
        if self.expires_height <= self.submitted_height {
            return Err("compatibility proof expiry must exceed submission height".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDryRunTrace {
    pub trace_id: String,
    pub proposal_id: String,
    pub status: DryRunStatus,
    pub executor_commitment: String,
    pub encrypted_trace_root: String,
    pub trace_key_commitment: String,
    pub initial_state_root: String,
    pub final_state_root: String,
    pub gas_profile_root: String,
    pub event_log_root: String,
    pub invariant_result_root: String,
    pub call_count_bucket: u64,
    pub max_fee_units_observed: u64,
    pub queued_height: u64,
    pub completed_height: u64,
    pub expires_height: u64,
}
impl EncryptedDryRunTrace {
    pub fn new(
        proposal_id: &str,
        executor_commitment: &str,
        encrypted_trace_root: &str,
        trace_key_commitment: &str,
        initial_state_root: &str,
        final_state_root: &str,
        gas_profile_root: &str,
        event_log_root: &str,
        invariant_result_root: &str,
        call_count_bucket: u64,
        max_fee_units_observed: u64,
        queued_height: u64,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> Self {
        let trace_id = upgrade_hash(
            "DRY-RUN-TRACE-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Str(executor_commitment),
                HashPart::Str(encrypted_trace_root),
                HashPart::Int(queued_height as i128),
            ],
        );
        Self {
            trace_id,
            proposal_id: proposal_id.to_string(),
            status: DryRunStatus::Queued,
            executor_commitment: executor_commitment.to_string(),
            encrypted_trace_root: encrypted_trace_root.to_string(),
            trace_key_commitment: trace_key_commitment.to_string(),
            initial_state_root: initial_state_root.to_string(),
            final_state_root: final_state_root.to_string(),
            gas_profile_root: gas_profile_root.to_string(),
            event_log_root: event_log_root.to_string(),
            invariant_result_root: invariant_result_root.to_string(),
            call_count_bucket,
            max_fee_units_observed,
            queued_height,
            completed_height: 0,
            expires_height: queued_height.saturating_add(config.challenge_window_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.trace_id.is_empty()
            || self.proposal_id.is_empty()
            || self.executor_commitment.is_empty()
        {
            return Err("encrypted dry run trace identity fields must be non-empty".to_string());
        }
        if self.encrypted_trace_root.is_empty()
            || self.trace_key_commitment.is_empty()
            || self.initial_state_root.is_empty()
            || self.final_state_root.is_empty()
            || self.invariant_result_root.is_empty()
        {
            return Err("encrypted dry run trace roots must be non-empty".to_string());
        }
        if self.initial_state_root == self.final_state_root {
            return Err("encrypted dry run trace must change simulated state root".to_string());
        }
        if self.expires_height <= self.queued_height {
            return Err("encrypted dry run trace expiry must exceed queued height".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeChallenge {
    pub challenge_id: String,
    pub proposal_id: String,
    pub challenger_commitment: String,
    pub status: ChallengeStatus,
    pub evidence_root: String,
    pub disputed_object_id: String,
    pub disputed_object_kind: String,
    pub bond_commitment: String,
    pub bond_units: u64,
    pub opened_height: u64,
    pub resolved_height: u64,
    pub expires_height: u64,
}
impl UpgradeChallenge {
    pub fn new(
        proposal_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        disputed_object_id: &str,
        disputed_object_kind: &str,
        bond_commitment: &str,
        bond_units: u64,
        opened_height: u64,
        config: &PrivateContractUpgradeSimulatorConfig,
    ) -> Self {
        let challenge_id = upgrade_hash(
            "CHALLENGE-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Str(challenger_commitment),
                HashPart::Str(disputed_object_id),
                HashPart::Str(evidence_root),
                HashPart::Int(opened_height as i128),
            ],
        );
        Self {
            challenge_id,
            proposal_id: proposal_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            status: ChallengeStatus::Open,
            evidence_root: evidence_root.to_string(),
            disputed_object_id: disputed_object_id.to_string(),
            disputed_object_kind: disputed_object_kind.to_string(),
            bond_commitment: bond_commitment.to_string(),
            bond_units,
            opened_height,
            resolved_height: 0,
            expires_height: opened_height.saturating_add(config.challenge_window_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.challenge_id.is_empty()
            || self.proposal_id.is_empty()
            || self.challenger_commitment.is_empty()
        {
            return Err("upgrade challenge identity fields must be non-empty".to_string());
        }
        if self.evidence_root.is_empty()
            || self.disputed_object_id.is_empty()
            || self.disputed_object_kind.is_empty()
            || self.bond_commitment.is_empty()
        {
            return Err(
                "upgrade challenge roots and disputed object fields must be non-empty".to_string(),
            );
        }
        if self.bond_units == 0 {
            return Err("upgrade challenge bond units are zero".to_string());
        }
        if self.expires_height <= self.opened_height {
            return Err("upgrade challenge expiry must exceed opened height".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeSlashingRecord {
    pub slash_id: String,
    pub proposal_id: String,
    pub challenge_id: String,
    pub maintainer_id: String,
    pub sponsor_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub slash_units: u64,
    pub beneficiary_commitment: String,
    pub executed_height: u64,
}
impl UpgradeSlashingRecord {
    pub fn new(
        proposal_id: &str,
        challenge_id: &str,
        maintainer_id: &str,
        sponsor_id: &str,
        reason: SlashReason,
        evidence_root: &str,
        slash_units: u64,
        beneficiary_commitment: &str,
        executed_height: u64,
    ) -> Self {
        let slash_id = upgrade_hash(
            "SLASH-ID",
            &[
                HashPart::Str(proposal_id),
                HashPart::Str(challenge_id),
                HashPart::Str(maintainer_id),
                HashPart::Str(sponsor_id),
                HashPart::Str(reason.as_str()),
                HashPart::Int(executed_height as i128),
            ],
        );
        Self {
            slash_id,
            proposal_id: proposal_id.to_string(),
            challenge_id: challenge_id.to_string(),
            maintainer_id: maintainer_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            slash_units,
            beneficiary_commitment: beneficiary_commitment.to_string(),
            executed_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        if self.slash_id.is_empty()
            || self.proposal_id.is_empty()
            || self.challenge_id.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err(
                "upgrade slashing record identity and evidence fields must be non-empty"
                    .to_string(),
            );
        }
        if self.maintainer_id.is_empty() && self.sponsor_id.is_empty() {
            return Err("upgrade slashing record must target maintainer or sponsor".to_string());
        }
        if self.slash_units == 0 {
            return Err("upgrade slashing record units are zero".to_string());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractUpgradeSimulatorRoots {
    pub config_root: String,
    pub proposal_root: String,
    pub maintainer_root: String,
    pub approval_root: String,
    pub diff_root: String,
    pub rollback_root: String,
    pub sponsor_root: String,
    pub compatibility_root: String,
    pub risk_score_root: String,
    pub dry_run_root: String,
    pub challenge_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub counter_root: String,
}
impl PrivateContractUpgradeSimulatorRoots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractUpgradeSimulatorCounters {
    pub proposal_count: u64,
    pub active_proposal_count: u64,
    pub ready_proposal_count: u64,
    pub executed_proposal_count: u64,
    pub maintainer_count: u64,
    pub active_maintainer_count: u64,
    pub approval_count: u64,
    pub active_approval_count: u64,
    pub diff_count: u64,
    pub rollback_rehearsal_count: u64,
    pub live_rollback_rehearsal_count: u64,
    pub sponsor_count: u64,
    pub active_sponsor_count: u64,
    pub compatibility_proof_count: u64,
    pub accepted_compatibility_proof_count: u64,
    pub risk_score_count: u64,
    pub high_risk_score_count: u64,
    pub dry_run_trace_count: u64,
    pub completed_dry_run_trace_count: u64,
    pub challenge_count: u64,
    pub open_challenge_count: u64,
    pub slashing_count: u64,
    pub nullifier_count: u64,
    pub total_sponsor_units: u64,
    pub total_reserved_sponsor_units: u64,
    pub total_spent_sponsor_units: u64,
    pub total_slashed_units: u64,
}
impl PrivateContractUpgradeSimulatorCounters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractUpgradeSimulatorState {
    pub height: u64,
    pub config: PrivateContractUpgradeSimulatorConfig,
    pub proposals: BTreeMap<String, ShieldedUpgradeProposal>,
    pub maintainers: BTreeMap<String, PqMaintainer>,
    pub approvals: BTreeMap<String, PqMaintainerApproval>,
    pub diffs: BTreeMap<String, CommitmentDiff>,
    pub rollbacks: BTreeMap<String, RollbackRehearsal>,
    pub sponsors: BTreeMap<String, LowFeeSponsorBudget>,
    pub compatibility_proofs: BTreeMap<String, CompatibilityProof>,
    pub risk_scores: BTreeMap<String, UpgradeRiskScore>,
    pub dry_run_traces: BTreeMap<String, EncryptedDryRunTrace>,
    pub challenges: BTreeMap<String, UpgradeChallenge>,
    pub slashings: BTreeMap<String, UpgradeSlashingRecord>,
    pub approval_nullifiers: BTreeSet<String>,
    pub proposal_approval_index: BTreeMap<String, BTreeSet<String>>,
    pub proposal_diff_index: BTreeMap<String, BTreeSet<String>>,
    pub proposal_trace_index: BTreeMap<String, BTreeSet<String>>,
}
impl PrivateContractUpgradeSimulatorState {
    pub fn new(height: u64, config: PrivateContractUpgradeSimulatorConfig) -> Self {
        Self {
            height,
            config,
            proposals: BTreeMap::new(),
            maintainers: BTreeMap::new(),
            approvals: BTreeMap::new(),
            diffs: BTreeMap::new(),
            rollbacks: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            compatibility_proofs: BTreeMap::new(),
            risk_scores: BTreeMap::new(),
            dry_run_traces: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashings: BTreeMap::new(),
            approval_nullifiers: BTreeSet::new(),
            proposal_approval_index: BTreeMap::new(),
            proposal_diff_index: BTreeMap::new(),
            proposal_trace_index: BTreeMap::new(),
        }
    }
    pub fn devnet() -> PrivateContractUpgradeSimulatorResult<Self> {
        let config = PrivateContractUpgradeSimulatorConfig::devnet();
        let mut state = Self::new(
            PRIVATE_CONTRACT_UPGRADE_SIMULATOR_DEVNET_HEIGHT,
            config.clone(),
        );
        let sponsor = LowFeeSponsorBudget::new(
            &seeded("devnet-upgrade-sponsor"),
            &seeded("devnet-upgrade-sponsor-budget"),
            &seeded("devnet-upgrade-sponsor-policy"),
            "wxmr-devnet",
            config.default_sponsor_budget_units,
            config.max_sponsored_fee_units,
            state.height,
            state
                .height
                .saturating_add(config.proposal_ttl_blocks.saturating_mul(4)),
        );
        let sponsor_id = sponsor.sponsor_id.clone();
        state.insert_sponsor_budget(sponsor)?;
        for (index, role) in [
            MaintainerRole::RuntimeMaintainer,
            MaintainerRole::CircuitMaintainer,
            MaintainerRole::StorageMaintainer,
            MaintainerRole::SecurityReviewer,
            MaintainerRole::EmergencyCouncil,
        ]
        .iter()
        .copied()
        .enumerate()
        {
            let maintainer = PqMaintainer::new(
                role,
                &seeded(&format!("devnet-maintainer-{index}-commitment")),
                &seeded(&format!("devnet-maintainer-{index}-pq-key-root")),
                &seeded(&format!("devnet-maintainer-{index}-authorization")),
                if role == MaintainerRole::EmergencyCouncil {
                    2
                } else {
                    1
                },
                config.default_slash_bond_units.saturating_mul(2),
                state.height,
            );
            state.insert_maintainer(maintainer)?;
        }
        let mut proposal = ShieldedUpgradeProposal::new(
            "contract:shielded-vault:devnet",
            UpgradeScope::StorageMigration,
            &seeded("devnet-upgrade-proposer"),
            &seeded("devnet-current-package-root"),
            &seeded("devnet-proposed-package-root"),
            &seeded("devnet-private-upgrade-envelope"),
            &seeded("devnet-upgrade-metadata"),
            &sponsor_id,
            state.height,
            &config,
        );
        proposal.status = UpgradeStatus::ApprovalOpen;
        let proposal_id = proposal.proposal_id.clone();
        state.insert_proposal(proposal)?;
        let risk_score = UpgradeRiskScore::new(
            &proposal_id,
            5_900,
            1_200,
            6_500,
            3_600,
            900,
            8_500,
            state.height,
            &config,
        );
        state.attach_risk_score(risk_score)?;
        for diff_kind in [
            DiffKind::Bytecode,
            DiffKind::Abi,
            DiffKind::StorageLayout,
            DiffKind::RollbackBundle,
        ] {
            let diff = CommitmentDiff::new(
                &proposal_id,
                diff_kind,
                &seeded(&format!("devnet-{proposal_id}-old-{}", diff_kind.as_str())),
                &seeded(&format!("devnet-{proposal_id}-new-{}", diff_kind.as_str())),
                &seeded(&format!(
                    "devnet-{proposal_id}-encrypted-diff-{}",
                    diff_kind.as_str()
                )),
                &seeded(&format!(
                    "devnet-{proposal_id}-summary-{}",
                    diff_kind.as_str()
                )),
                &seeded(&format!(
                    "devnet-{proposal_id}-review-policy-{}",
                    diff_kind.as_str()
                )),
                8 + diff_kind.risk_weight() / 200,
                if diff_kind == DiffKind::Abi { 3 } else { 0 },
                if diff_kind == DiffKind::StorageLayout {
                    7
                } else {
                    0
                },
                state.height,
            );
            state.insert_diff(diff)?;
        }
        let maintainers = state.maintainers.values().cloned().collect::<Vec<_>>();
        for (index, maintainer) in maintainers.iter().take(4).enumerate() {
            let approval = PqMaintainerApproval::new(
                &proposal_id,
                maintainer,
                &seeded(&format!("devnet-approval-{index}-signature")),
                &seeded(&format!("devnet-approval-{index}-transcript")),
                &seeded(&format!("devnet-approval-{index}-nullifier")),
                state.height.saturating_add(index as u64),
                &config,
            );
            state.insert_approval(approval)?;
        }
        let proof = CompatibilityProof::new(
            &proposal_id,
            &seeded("devnet-compat-public-input"),
            &seeded("devnet-compat-witness"),
            &seeded("devnet-old-abi"),
            &seeded("devnet-new-abi"),
            &seeded("devnet-storage-invariants"),
            &seeded("devnet-selector-compat"),
            &seeded("devnet-verifier-key"),
            state.height.saturating_add(5),
            &config,
        );
        let proof_id = proof.proof_id.clone();
        state.insert_compatibility_proof(proof)?;
        state.mark_compatibility_verified(&proof_id, state.height.saturating_add(6))?;
        let trace = EncryptedDryRunTrace::new(
            &proposal_id,
            &seeded("devnet-dry-run-executor"),
            &seeded("devnet-dry-run-trace"),
            &seeded("devnet-dry-run-trace-key"),
            &seeded("devnet-dry-run-initial-state"),
            &seeded("devnet-dry-run-final-state"),
            &seeded("devnet-dry-run-gas-profile"),
            &seeded("devnet-dry-run-event-log"),
            &seeded("devnet-dry-run-invariants"),
            32,
            4_200,
            state.height.saturating_add(7),
            &config,
        );
        let trace_id = trace.trace_id.clone();
        state.insert_dry_run_trace(trace)?;
        state.mark_dry_run_completed(&trace_id, state.height.saturating_add(8))?;
        let rollback = RollbackRehearsal::new(
            &proposal_id,
            &seeded("devnet-rollback-bundle"),
            &seeded("devnet-rollback-pre-state"),
            &seeded("devnet-rollback-post-state"),
            &seeded("devnet-rollback-invariants"),
            &seeded("devnet-rollback-operator"),
            &seeded("devnet-rollback-pq-attestation"),
            96,
            2,
            9_100,
            state.height.saturating_add(9),
            &config,
        );
        let rehearsal_id = rollback.rehearsal_id.clone();
        state.insert_rollback_rehearsal(rollback)?;
        state.mark_rollback_rehearsed(&rehearsal_id, state.height.saturating_add(10))?;
        let challenge = UpgradeChallenge::new(
            &proposal_id,
            &seeded("devnet-watchtower"),
            &seeded("devnet-challenge-evidence"),
            &trace_id,
            "dry_run_trace",
            &seeded("devnet-challenge-bond"),
            config.default_slash_bond_units,
            state.height.saturating_add(11),
            &config,
        );
        let challenge_id = challenge.challenge_id.clone();
        state.insert_challenge(challenge)?;
        let maintainer_id = state
            .maintainers
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet upgrade simulator missing maintainer".to_string())?;
        let slash = UpgradeSlashingRecord::new(
            &proposal_id,
            &challenge_id,
            &maintainer_id,
            "",
            SlashReason::DryRunFraud,
            &seeded("devnet-slash-evidence"),
            config.default_slash_bond_units / 5,
            &seeded("devnet-slash-beneficiary"),
            state.height.saturating_add(12),
        );
        state.insert_slashing_record(slash)?;
        state.update_proposal_status(&proposal_id)?;
        state.validate()?;
        Ok(state)
    }
    pub fn update_height(&mut self, new_height: u64) -> PrivateContractUpgradeSimulatorResult<u64> {
        if new_height < self.height {
            return Err("private contract upgrade simulator height cannot decrease".to_string());
        }
        self.height = new_height;
        self.expire_records();
        self.validate()?;
        Ok(self.height)
    }
    pub fn insert_proposal(
        &mut self,
        proposal: ShieldedUpgradeProposal,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        proposal.validate(&self.config)?;
        if proposal.created_height > self.height {
            return Err(
                "shielded upgrade proposal created height exceeds state height".to_string(),
            );
        }
        if !self.sponsors.contains_key(&proposal.sponsor_id) {
            return Err("shielded upgrade proposal references unknown sponsor".to_string());
        }
        let proposal_id = proposal.proposal_id.clone();
        if self.proposals.contains_key(&proposal_id) {
            return Err("duplicate shielded upgrade proposal".to_string());
        }
        self.proposals.insert(proposal_id.clone(), proposal);
        Ok(proposal_id)
    }
    pub fn insert_maintainer(
        &mut self,
        maintainer: PqMaintainer,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        maintainer.validate(&self.config)?;
        if self.maintainers.contains_key(&maintainer.maintainer_id) {
            return Err("duplicate pq maintainer".to_string());
        }
        let maintainer_id = maintainer.maintainer_id.clone();
        self.maintainers.insert(maintainer_id.clone(), maintainer);
        Ok(maintainer_id)
    }
    pub fn insert_approval(
        &mut self,
        approval: PqMaintainerApproval,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        approval.validate(&self.config)?;
        if self.approvals.contains_key(&approval.approval_id) {
            return Err("duplicate pq maintainer approval".to_string());
        }
        if self.approval_nullifiers.contains(&approval.nullifier) {
            return Err("duplicate pq maintainer approval nullifier".to_string());
        }
        let proposal = self
            .proposals
            .get(&approval.proposal_id)
            .ok_or_else(|| "pq maintainer approval references unknown proposal".to_string())?;
        if proposal.status.terminal()
            || approval.submitted_height > proposal.approval_deadline_height
        {
            return Err("pq maintainer approval outside proposal approval window".to_string());
        }
        let maintainer = self
            .maintainers
            .get(&approval.maintainer_id)
            .ok_or_else(|| "pq maintainer approval references unknown maintainer".to_string())?;
        if !maintainer.status.may_approve() {
            return Err("pq maintainer approval references inactive maintainer".to_string());
        }
        if approval.approval_weight > maintainer.approval_weight {
            return Err("pq maintainer approval exceeds maintainer weight".to_string());
        }
        let approval_id = approval.approval_id.clone();
        let proposal_id = approval.proposal_id.clone();
        self.approval_nullifiers.insert(approval.nullifier.clone());
        self.proposal_approval_index
            .entry(proposal_id.clone())
            .or_default()
            .insert(approval_id.clone());
        self.approvals.insert(approval_id.clone(), approval);
        self.update_proposal_status(&proposal_id)?;
        Ok(approval_id)
    }
    pub fn insert_diff(
        &mut self,
        diff: CommitmentDiff,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        diff.validate()?;
        if self.diffs.contains_key(&diff.diff_id) {
            return Err("duplicate commitment diff".to_string());
        }
        if !self.proposals.contains_key(&diff.proposal_id) {
            return Err("commitment diff references unknown proposal".to_string());
        }
        let diff_id = diff.diff_id.clone();
        let proposal_id = diff.proposal_id.clone();
        self.proposal_diff_index
            .entry(proposal_id)
            .or_default()
            .insert(diff_id.clone());
        self.diffs.insert(diff_id.clone(), diff);
        Ok(diff_id)
    }
    pub fn insert_rollback_rehearsal(
        &mut self,
        rollback: RollbackRehearsal,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        rollback.validate()?;
        if self.rollbacks.contains_key(&rollback.rehearsal_id) {
            return Err("duplicate rollback rehearsal".to_string());
        }
        if !self.proposals.contains_key(&rollback.proposal_id) {
            return Err("rollback rehearsal references unknown proposal".to_string());
        }
        let rehearsal_id = rollback.rehearsal_id.clone();
        self.rollbacks.insert(rehearsal_id.clone(), rollback);
        Ok(rehearsal_id)
    }
    pub fn insert_sponsor_budget(
        &mut self,
        sponsor: LowFeeSponsorBudget,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        sponsor.validate(&self.config)?;
        if self.sponsors.contains_key(&sponsor.sponsor_id) {
            return Err("duplicate low fee sponsor budget".to_string());
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        self.sponsors.insert(sponsor_id.clone(), sponsor);
        Ok(sponsor_id)
    }
    pub fn reserve_sponsor_budget(
        &mut self,
        sponsor_id: &str,
        units: u64,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "cannot reserve unknown sponsor budget".to_string())?;
        if !sponsor.status.spendable() {
            return Err("cannot reserve paused or closed sponsor budget".to_string());
        }
        if units > sponsor.max_fee_units_per_upgrade {
            return Err("sponsor reservation exceeds per-upgrade cap".to_string());
        }
        if units > sponsor.available_units() {
            return Err("sponsor reservation exceeds available units".to_string());
        }
        sponsor.reserved_units = sponsor.reserved_units.saturating_add(units);
        sponsor.status = SponsorStatus::Reserved;
        Ok(())
    }
    pub fn insert_compatibility_proof(
        &mut self,
        proof: CompatibilityProof,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        proof.validate()?;
        if self.compatibility_proofs.contains_key(&proof.proof_id) {
            return Err("duplicate compatibility proof".to_string());
        }
        if !self.proposals.contains_key(&proof.proposal_id) {
            return Err("compatibility proof references unknown proposal".to_string());
        }
        let proof_id = proof.proof_id.clone();
        self.compatibility_proofs.insert(proof_id.clone(), proof);
        Ok(proof_id)
    }
    pub fn mark_compatibility_verified(
        &mut self,
        proof_id: &str,
        verified_height: u64,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        self.update_height_no_event(verified_height)?;
        let proof = self
            .compatibility_proofs
            .get_mut(proof_id)
            .ok_or_else(|| "cannot verify unknown compatibility proof".to_string())?;
        if matches!(
            proof.status,
            CompatibilityStatus::Failed | CompatibilityStatus::Expired
        ) {
            return Err("cannot verify failed or expired compatibility proof".to_string());
        }
        proof.status = CompatibilityStatus::Verified;
        proof.verified_height = verified_height;
        Ok(())
    }
    pub fn attach_risk_score(
        &mut self,
        risk_score: UpgradeRiskScore,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        risk_score.validate(&self.config)?;
        if self.risk_scores.contains_key(&risk_score.score_id) {
            return Err("duplicate upgrade risk score".to_string());
        }
        let proposal = self
            .proposals
            .get_mut(&risk_score.proposal_id)
            .ok_or_else(|| "upgrade risk score references unknown proposal".to_string())?;
        let score_id = risk_score.score_id.clone();
        proposal.risk_score_id = score_id.clone();
        self.risk_scores.insert(score_id.clone(), risk_score);
        Ok(score_id)
    }
    pub fn insert_dry_run_trace(
        &mut self,
        trace: EncryptedDryRunTrace,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        trace.validate()?;
        if self.dry_run_traces.contains_key(&trace.trace_id) {
            return Err("duplicate encrypted dry run trace".to_string());
        }
        if !self.proposals.contains_key(&trace.proposal_id) {
            return Err("encrypted dry run trace references unknown proposal".to_string());
        }
        let trace_id = trace.trace_id.clone();
        let proposal_id = trace.proposal_id.clone();
        self.proposal_trace_index
            .entry(proposal_id)
            .or_default()
            .insert(trace_id.clone());
        self.dry_run_traces.insert(trace_id.clone(), trace);
        Ok(trace_id)
    }
    pub fn mark_dry_run_completed(
        &mut self,
        trace_id: &str,
        completed_height: u64,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        self.update_height_no_event(completed_height)?;
        let trace = self
            .dry_run_traces
            .get_mut(trace_id)
            .ok_or_else(|| "cannot complete unknown encrypted dry run trace".to_string())?;
        if matches!(trace.status, DryRunStatus::Failed | DryRunStatus::Expired) {
            return Err("cannot complete failed or expired dry run trace".to_string());
        }
        trace.status = DryRunStatus::Completed;
        trace.completed_height = completed_height;
        Ok(())
    }
    pub fn mark_rollback_rehearsed(
        &mut self,
        rehearsal_id: &str,
        completed_height: u64,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        self.update_height_no_event(completed_height)?;
        let rollback = self
            .rollbacks
            .get_mut(rehearsal_id)
            .ok_or_else(|| "cannot rehearse unknown rollback".to_string())?;
        if !rollback.status.live() {
            return Err("cannot rehearse terminal rollback".to_string());
        }
        rollback.status = RollbackStatus::Rehearsed;
        rollback.completed_height = completed_height;
        Ok(())
    }
    pub fn insert_challenge(
        &mut self,
        challenge: UpgradeChallenge,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        challenge.validate()?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("duplicate upgrade challenge".to_string());
        }
        if !self.proposals.contains_key(&challenge.proposal_id) {
            return Err("upgrade challenge references unknown proposal".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        let proposal_id = challenge.proposal_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        if let Some(proposal) = self.proposals.get_mut(&proposal_id) {
            if proposal.status.mutable() {
                proposal.status = UpgradeStatus::Challenged;
            }
        }
        Ok(challenge_id)
    }
    pub fn insert_slashing_record(
        &mut self,
        slash: UpgradeSlashingRecord,
    ) -> PrivateContractUpgradeSimulatorResult<String> {
        self.ensure_capacity()?;
        slash.validate()?;
        if self.slashings.contains_key(&slash.slash_id) {
            return Err("duplicate upgrade slashing record".to_string());
        }
        if !self.proposals.contains_key(&slash.proposal_id)
            || !self.challenges.contains_key(&slash.challenge_id)
        {
            return Err(
                "upgrade slashing record references unknown proposal or challenge".to_string(),
            );
        }
        if !slash.maintainer_id.is_empty() {
            let maintainer = self
                .maintainers
                .get_mut(&slash.maintainer_id)
                .ok_or_else(|| {
                    "upgrade slashing record references unknown maintainer".to_string()
                })?;
            if slash.slash_units > maintainer.available_bond_units() {
                return Err("upgrade slashing record exceeds maintainer available bond".to_string());
            }
            maintainer.slashed_units = maintainer.slashed_units.saturating_add(slash.slash_units);
            maintainer.status = MaintainerStatus::Slashed;
            maintainer.updated_height = slash.executed_height;
        }
        if !slash.sponsor_id.is_empty() {
            let sponsor = self
                .sponsors
                .get_mut(&slash.sponsor_id)
                .ok_or_else(|| "upgrade slashing record references unknown sponsor".to_string())?;
            if slash.slash_units > sponsor.available_units() {
                return Err("upgrade slashing record exceeds sponsor available units".to_string());
            }
            sponsor.spent_units = sponsor.spent_units.saturating_add(slash.slash_units);
            sponsor.status = SponsorStatus::Slashed;
        }
        if let Some(challenge) = self.challenges.get_mut(&slash.challenge_id) {
            challenge.status = ChallengeStatus::Slashed;
            challenge.resolved_height = slash.executed_height;
        }
        let slash_id = slash.slash_id.clone();
        self.slashings.insert(slash_id.clone(), slash);
        Ok(slash_id)
    }
    pub fn approval_weight_for(&self, proposal_id: &str) -> u64 {
        self.proposal_approval_index
            .get(proposal_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|approval_id| self.approvals.get(approval_id))
            .filter(|approval| approval.status.active())
            .map(|approval| approval.approval_weight)
            .sum()
    }
    pub fn update_proposal_status(
        &mut self,
        proposal_id: &str,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        let approval_weight = self.approval_weight_for(proposal_id);
        let has_compatibility = self
            .compatibility_proofs
            .values()
            .any(|proof| proof.proposal_id == proposal_id && proof.status.accepted());
        let has_completed_trace = self.dry_run_traces.values().any(|trace| {
            trace.proposal_id == proposal_id && trace.status == DryRunStatus::Completed
        });
        let has_rehearsed_rollback = self.rollbacks.values().any(|rollback| {
            rollback.proposal_id == proposal_id && rollback.status == RollbackStatus::Rehearsed
        });
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| "cannot update unknown upgrade proposal".to_string())?;
        if !proposal.status.mutable() {
            return Ok(());
        }
        if self.height > proposal.expires_height {
            proposal.status = UpgradeStatus::Expired;
        } else if approval_weight >= proposal.required_approval_weight
            && has_compatibility
            && has_completed_trace
            && has_rehearsed_rollback
        {
            proposal.status = UpgradeStatus::Ready;
        } else if approval_weight >= proposal.required_approval_weight {
            proposal.status = UpgradeStatus::Approved;
        } else if self.height <= proposal.approval_deadline_height {
            proposal.status = UpgradeStatus::ApprovalOpen;
        }
        Ok(())
    }
    pub fn roots(&self) -> PrivateContractUpgradeSimulatorRoots {
        let counters = self.counters();
        PrivateContractUpgradeSimulatorRoots {
            config_root: self.config.config_root(),
            proposal_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-PROPOSALS",
                self.proposals
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            maintainer_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-MAINTAINERS",
                self.maintainers
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            approval_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-APPROVALS",
                self.approvals
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            diff_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-DIFFS",
                self.diffs
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            rollback_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-ROLLBACKS",
                self.rollbacks
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            sponsor_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-SPONSORS",
                self.sponsors
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            compatibility_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-COMPATIBILITY",
                self.compatibility_proofs
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            risk_score_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-RISK-SCORES",
                self.risk_scores
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            dry_run_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-DRY-RUNS",
                self.dry_run_traces
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            challenge_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-CHALLENGES",
                self.challenges
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            slashing_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-SLASHINGS",
                self.slashings
                    .iter()
                    .map(|(id, record)| json!({"id": id, "record": record.public_record()})),
            ),
            nullifier_root: map_root(
                "PRIVATE-CONTRACT-UPGRADE-NULLIFIERS",
                self.approval_nullifiers
                    .iter()
                    .map(|nullifier| json!({"nullifier": nullifier})),
            ),
            counter_root: upgrade_json_root("COUNTERS", &counters.public_record()),
        }
    }
    pub fn counters(&self) -> PrivateContractUpgradeSimulatorCounters {
        PrivateContractUpgradeSimulatorCounters {
            proposal_count: self.proposals.len() as u64,
            active_proposal_count: self
                .proposals
                .values()
                .filter(|proposal| proposal.status.mutable())
                .count() as u64,
            ready_proposal_count: self
                .proposals
                .values()
                .filter(|proposal| proposal.status == UpgradeStatus::Ready)
                .count() as u64,
            executed_proposal_count: self
                .proposals
                .values()
                .filter(|proposal| proposal.status == UpgradeStatus::Executed)
                .count() as u64,
            maintainer_count: self.maintainers.len() as u64,
            active_maintainer_count: self
                .maintainers
                .values()
                .filter(|maintainer| maintainer.status.may_approve())
                .count() as u64,
            approval_count: self.approvals.len() as u64,
            active_approval_count: self
                .approvals
                .values()
                .filter(|approval| approval.status.active())
                .count() as u64,
            diff_count: self.diffs.len() as u64,
            rollback_rehearsal_count: self.rollbacks.len() as u64,
            live_rollback_rehearsal_count: self
                .rollbacks
                .values()
                .filter(|rollback| rollback.status.live())
                .count() as u64,
            sponsor_count: self.sponsors.len() as u64,
            active_sponsor_count: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.spendable())
                .count() as u64,
            compatibility_proof_count: self.compatibility_proofs.len() as u64,
            accepted_compatibility_proof_count: self
                .compatibility_proofs
                .values()
                .filter(|proof| proof.status.accepted())
                .count() as u64,
            risk_score_count: self.risk_scores.len() as u64,
            high_risk_score_count: self
                .risk_scores
                .values()
                .filter(|score| score.review_required)
                .count() as u64,
            dry_run_trace_count: self.dry_run_traces.len() as u64,
            completed_dry_run_trace_count: self
                .dry_run_traces
                .values()
                .filter(|trace| trace.status == DryRunStatus::Completed)
                .count() as u64,
            challenge_count: self.challenges.len() as u64,
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.open())
                .count() as u64,
            slashing_count: self.slashings.len() as u64,
            nullifier_count: self.approval_nullifiers.len() as u64,
            total_sponsor_units: self
                .sponsors
                .values()
                .map(|sponsor| sponsor.total_units)
                .sum(),
            total_reserved_sponsor_units: self
                .sponsors
                .values()
                .map(|sponsor| sponsor.reserved_units)
                .sum(),
            total_spent_sponsor_units: self
                .sponsors
                .values()
                .map(|sponsor| sponsor.spent_units)
                .sum(),
            total_slashed_units: self.slashings.values().map(|slash| slash.slash_units).sum(),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_upgrade_simulator",
            "protocol_id": PRIVATE_CONTRACT_UPGRADE_SIMULATOR_PROTOCOL_ID,
            "schema_version": PRIVATE_CONTRACT_UPGRADE_SIMULATOR_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_proposal_ids": self.active_proposal_ids(),
            "ready_proposal_ids": self.ready_proposal_ids(),
            "open_challenge_ids": self.open_challenge_ids(),
        })
    }
    pub fn state_root(&self) -> String {
        private_contract_upgrade_simulator_state_root_from_record(&self.public_record())
    }
    pub fn validate(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        self.config.validate()?;
        self.ensure_capacity()?;
        for proposal in self.proposals.values() {
            proposal.validate(&self.config)?;
            if !self.sponsors.contains_key(&proposal.sponsor_id) {
                return Err("upgrade proposal references unknown sponsor".to_string());
            }
            if !proposal.risk_score_id.is_empty()
                && !self.risk_scores.contains_key(&proposal.risk_score_id)
            {
                return Err("upgrade proposal references unknown risk score".to_string());
            }
        }
        for maintainer in self.maintainers.values() {
            maintainer.validate(&self.config)?;
        }
        let mut seen_approval_nullifiers = BTreeSet::new();
        for approval in self.approvals.values() {
            approval.validate(&self.config)?;
            if !self.proposals.contains_key(&approval.proposal_id)
                || !self.maintainers.contains_key(&approval.maintainer_id)
            {
                return Err("upgrade approval has dangling reference".to_string());
            }
            if !seen_approval_nullifiers.insert(approval.nullifier.clone()) {
                return Err("duplicate upgrade approval nullifier".to_string());
            }
        }
        if seen_approval_nullifiers != self.approval_nullifiers {
            return Err("upgrade approval nullifier index mismatch".to_string());
        }
        for diff in self.diffs.values() {
            diff.validate()?;
            if !self.proposals.contains_key(&diff.proposal_id) {
                return Err("upgrade diff has dangling proposal reference".to_string());
            }
        }
        for rollback in self.rollbacks.values() {
            rollback.validate()?;
            if !self.proposals.contains_key(&rollback.proposal_id) {
                return Err("upgrade rollback has dangling proposal reference".to_string());
            }
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate(&self.config)?;
        }
        for proof in self.compatibility_proofs.values() {
            proof.validate()?;
            if !self.proposals.contains_key(&proof.proposal_id) {
                return Err(
                    "upgrade compatibility proof has dangling proposal reference".to_string(),
                );
            }
        }
        for score in self.risk_scores.values() {
            score.validate(&self.config)?;
            if !self.proposals.contains_key(&score.proposal_id) {
                return Err("upgrade risk score has dangling proposal reference".to_string());
            }
        }
        for trace in self.dry_run_traces.values() {
            trace.validate()?;
            if !self.proposals.contains_key(&trace.proposal_id) {
                return Err("upgrade dry run trace has dangling proposal reference".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.proposals.contains_key(&challenge.proposal_id) {
                return Err("upgrade challenge has dangling proposal reference".to_string());
            }
        }
        for slash in self.slashings.values() {
            slash.validate()?;
            if !self.proposals.contains_key(&slash.proposal_id)
                || !self.challenges.contains_key(&slash.challenge_id)
            {
                return Err(
                    "upgrade slashing record has dangling proposal or challenge reference"
                        .to_string(),
                );
            }
            if !slash.maintainer_id.is_empty()
                && !self.maintainers.contains_key(&slash.maintainer_id)
            {
                return Err("upgrade slashing record has dangling maintainer reference".to_string());
            }
            if !slash.sponsor_id.is_empty() && !self.sponsors.contains_key(&slash.sponsor_id) {
                return Err("upgrade slashing record has dangling sponsor reference".to_string());
            }
        }
        Ok(())
    }
    pub fn active_proposal_ids(&self) -> Vec<String> {
        self.proposals
            .values()
            .filter(|proposal| proposal.status.mutable())
            .map(|proposal| proposal.proposal_id.clone())
            .collect()
    }
    pub fn ready_proposal_ids(&self) -> Vec<String> {
        self.proposals
            .values()
            .filter(|proposal| proposal.status == UpgradeStatus::Ready)
            .map(|proposal| proposal.proposal_id.clone())
            .collect()
    }
    pub fn open_challenge_ids(&self) -> Vec<String> {
        self.challenges
            .values()
            .filter(|challenge| challenge.status.open())
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }
    fn update_height_no_event(
        &mut self,
        new_height: u64,
    ) -> PrivateContractUpgradeSimulatorResult<()> {
        if new_height < self.height {
            return Err("private contract upgrade simulator height cannot decrease".to_string());
        }
        self.height = new_height;
        self.expire_records();
        Ok(())
    }
    fn ensure_capacity(&self) -> PrivateContractUpgradeSimulatorResult<()> {
        let total_records = self
            .proposals
            .len()
            .saturating_add(self.maintainers.len())
            .saturating_add(self.approvals.len())
            .saturating_add(self.diffs.len())
            .saturating_add(self.rollbacks.len())
            .saturating_add(self.sponsors.len())
            .saturating_add(self.compatibility_proofs.len())
            .saturating_add(self.risk_scores.len())
            .saturating_add(self.dry_run_traces.len())
            .saturating_add(self.challenges.len())
            .saturating_add(self.slashings.len());
        if total_records > PRIVATE_CONTRACT_UPGRADE_SIMULATOR_MAX_RECORDS {
            return Err("private contract upgrade simulator record limit exceeded".to_string());
        }
        Ok(())
    }
    fn expire_records(&mut self) {
        for proposal in self.proposals.values_mut() {
            if self.height > proposal.expires_height && proposal.status.mutable() {
                proposal.status = UpgradeStatus::Expired;
            }
        }
        for approval in self.approvals.values_mut() {
            if self.height > approval.expires_height && approval.status.active() {
                approval.status = ApprovalStatus::Expired;
            }
        }
        for rollback in self.rollbacks.values_mut() {
            if self.height > rollback.expires_height && rollback.status.live() {
                rollback.status = RollbackStatus::Expired;
            }
        }
        for sponsor in self.sponsors.values_mut() {
            if self.height > sponsor.expires_height && sponsor.status.spendable() {
                sponsor.status = SponsorStatus::Closed;
            }
        }
        for proof in self.compatibility_proofs.values_mut() {
            if self.height > proof.expires_height && proof.status == CompatibilityStatus::Submitted
            {
                proof.status = CompatibilityStatus::Expired;
            }
        }
        for trace in self.dry_run_traces.values_mut() {
            if self.height > trace.expires_height
                && matches!(trace.status, DryRunStatus::Queued | DryRunStatus::Running)
            {
                trace.status = DryRunStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if self.height > challenge.expires_height && challenge.status.open() {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }
}
pub fn devnet() -> PrivateContractUpgradeSimulatorResult<PrivateContractUpgradeSimulatorState> {
    PrivateContractUpgradeSimulatorState::devnet()
}
pub fn private_contract_upgrade_simulator_state_root_from_record(record: &Value) -> String {
    upgrade_json_root("STATE-FROM-RECORD", record)
}
pub fn private_contract_upgrade_simulator_config_root(
    config: &PrivateContractUpgradeSimulatorConfig,
) -> String {
    config.config_root()
}
fn upgrade_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-CONTRACT-UPGRADE-SIMULATOR:{domain}"),
        parts,
        32,
    )
}
fn upgrade_json_root(domain: &str, value: &Value) -> String {
    upgrade_hash(domain, &[HashPart::Json(value)])
}
fn map_root<I>(domain: &str, leaves: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaf_values = leaves.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaf_values)
}
fn seeded(label: &str) -> String {
    upgrade_hash("DEVNET-SEED", &[HashPart::Str(label)])
}
