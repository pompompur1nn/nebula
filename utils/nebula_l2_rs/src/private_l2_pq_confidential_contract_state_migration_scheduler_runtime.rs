use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractStateMigrationSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_MIGRATION_SCHEDULER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-state-migration-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STATE_MIGRATION_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STORAGE_MIGRATION_SCHEME: &str =
    "confidential-contract-storage-migration-commitment-root-v1";
pub const BYTECODE_VERSION_SCHEME: &str =
    "pq-confidential-contract-bytecode-version-constraint-root-v1";
pub const CIRCUIT_VERSION_SCHEME: &str =
    "pq-confidential-contract-circuit-version-constraint-root-v1";
pub const WITNESS_RENT_SCHEME: &str = "confidential-contract-witness-rent-escrow-root-v1";
pub const STATE_EXPIRY_SCHEME: &str = "private-l2-contract-state-expiry-frontier-root-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "contract-migration-private-budget-ledger-root-v1";
pub const PQ_ATTESTATION_GATE_SCHEME: &str =
    "ml-dsa-87-slh-dsa-shake-256f-contract-migration-gate-root-v1";
pub const DEFI_DEPENDENCY_SCHEME: &str =
    "confidential-defi-vault-amm-lending-perps-migration-dependency-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str =
    "low-fee-private-contract-state-migration-batch-scheduler-root-v1";
pub const ROLLBACK_WINDOW_SCHEME: &str =
    "confidential-contract-state-migration-rollback-window-root-v1";
pub const RELEASE_READINESS_SCHEME: &str =
    "private-contract-state-migration-release-readiness-root-v1";
pub const DEVNET_HEIGHT: u64 = 921_600;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_LOW_FEE_BATCH_TARGET: usize = 192;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 2_048;
pub const DEFAULT_BATCH_GAS_LIMIT: u64 = 30_000_000;
pub const DEFAULT_BATCH_RENT_LIMIT: u64 = 250_000_000;
pub const DEFAULT_MIGRATION_TTL_BLOCKS: u64 = 960;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ROLLBACK_BLOCKS: u64 = 360;
pub const DEFAULT_EXPIRY_GRACE_BLOCKS: u64 = 43_200;
pub const DEFAULT_WITNESS_RENT_PER_KIB: u64 = 3;
pub const DEFAULT_MIN_RELEASE_SCORE: u64 = 900;
pub const MAX_CONTRACTS: usize = 262_144;
pub const MAX_MIGRATION_PLANS: usize = 524_288;
pub const MAX_STORAGE_SHARDS: usize = 2_097_152;
pub const MAX_VERSION_CONSTRAINTS: usize = 524_288;
pub const MAX_WITNESS_RENT_DEPOSITS: usize = 1_048_576;
pub const MAX_EXPIRY_FRONTIERS: usize = 524_288;
pub const MAX_PRIVACY_BUDGETS: usize = 524_288;
pub const MAX_PQ_GATES: usize = 1_048_576;
pub const MAX_DEFI_DEPENDENCIES: usize = 1_048_576;
pub const MAX_BATCHES: usize = 524_288;
pub const MAX_ROLLBACK_WINDOWS: usize = 524_288;
pub const MAX_RELEASE_READINESS: usize = 262_144;
pub const MAX_EVENTS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractKind {
    Application,
    Token,
    Vault,
    AmmPool,
    LendingMarket,
    PerpMarket,
    Oracle,
    BridgeAdapter,
    Governance,
    Custom,
}
impl ContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Token => "token",
            Self::Vault => "vault",
            Self::AmmPool => "amm_pool",
            Self::LendingMarket => "lending_market",
            Self::PerpMarket => "perp_market",
            Self::Oracle => "oracle",
            Self::BridgeAdapter => "bridge_adapter",
            Self::Governance => "governance",
            Self::Custom => "custom",
        }
    }
    pub fn defi_weight(self) -> u64 {
        match self {
            Self::Vault => 1_000,
            Self::AmmPool => 960,
            Self::LendingMarket => 940,
            Self::PerpMarket => 920,
            Self::Token => 880,
            Self::Oracle => 840,
            Self::BridgeAdapter => 820,
            Self::Governance => 760,
            Self::Application | Self::Custom => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationLane {
    SponsoredLowFee,
    SafetyPatch,
    ExpirySweep,
    DefiDependency,
    PrivacyBudgetRenewal,
    CircuitUpgrade,
    EmergencyFreeze,
}
impl MigrationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::SafetyPatch => "safety_patch",
            Self::ExpirySweep => "expiry_sweep",
            Self::DefiDependency => "defi_dependency",
            Self::PrivacyBudgetRenewal => "privacy_budget_renewal",
            Self::CircuitUpgrade => "circuit_upgrade",
            Self::EmergencyFreeze => "emergency_freeze",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyFreeze => 1_200,
            Self::SafetyPatch => 1_080,
            Self::DefiDependency => 1_000,
            Self::CircuitUpgrade => 940,
            Self::PrivacyBudgetRenewal => 860,
            Self::ExpirySweep => 820,
            Self::SponsoredLowFee => 780,
        }
    }
    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.max_user_fee_bps / 2,
            Self::ExpirySweep | Self::PrivacyBudgetRenewal => config.max_user_fee_bps,
            Self::DefiDependency | Self::CircuitUpgrade => {
                config.max_user_fee_bps.saturating_mul(3) / 2
            }
            Self::SafetyPatch | Self::EmergencyFreeze => config.max_user_fee_bps.saturating_mul(2),
        }
        .min(config.max_user_fee_bps.saturating_mul(3))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Draft,
    Registered,
    GatesPending,
    DependencyBlocked,
    Ready,
    Batched,
    Executing,
    Applied,
    RolledBack,
    Expired,
    Rejected,
}
impl PlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Registered => "registered",
            Self::GatesPending => "gates_pending",
            Self::DependencyBlocked => "dependency_blocked",
            Self::Ready => "ready",
            Self::Batched => "batched",
            Self::Executing => "executing",
            Self::Applied => "applied",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
    pub fn schedulable(self) -> bool {
        matches!(self, Self::Ready)
    }
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Applied | Self::RolledBack | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    BytecodeMin,
    BytecodeMax,
    CircuitMin,
    CircuitMax,
    StorageLayout,
    ProverKey,
    VerifierKey,
    VmFeature,
    HostCallSet,
}
impl ConstraintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BytecodeMin => "bytecode_min",
            Self::BytecodeMax => "bytecode_max",
            Self::CircuitMin => "circuit_min",
            Self::CircuitMax => "circuit_max",
            Self::StorageLayout => "storage_layout",
            Self::ProverKey => "prover_key",
            Self::VerifierKey => "verifier_key",
            Self::VmFeature => "vm_feature",
            Self::HostCallSet => "host_call_set",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqCommittee,
    CircuitAuditor,
    StorageWitness,
    ReleaseCouncil,
    DefiRiskCouncil,
    PrivacyBudgetAuditor,
    EmergencyCouncil,
}
impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqCommittee => "pq_committee",
            Self::CircuitAuditor => "circuit_auditor",
            Self::StorageWitness => "storage_witness",
            Self::ReleaseCouncil => "release_council",
            Self::DefiRiskCouncil => "defi_risk_council",
            Self::PrivacyBudgetAuditor => "privacy_budget_auditor",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiDependencyKind {
    TokenBeforeVault,
    VaultBeforeAmm,
    OracleBeforeLending,
    LendingBeforePerps,
    AmmBeforePerps,
    GovernanceBeforeRiskParams,
    BridgeBeforeWrappedAsset,
    Custom,
}
impl DefiDependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenBeforeVault => "token_before_vault",
            Self::VaultBeforeAmm => "vault_before_amm",
            Self::OracleBeforeLending => "oracle_before_lending",
            Self::LendingBeforePerps => "lending_before_perps",
            Self::AmmBeforePerps => "amm_before_perps",
            Self::GovernanceBeforeRiskParams => "governance_before_risk_params",
            Self::BridgeBeforeWrappedAsset => "bridge_before_wrapped_asset",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyStatus {
    Open,
    Satisfied,
    Waived,
    Failed,
}
impl DependencyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Satisfied => "satisfied",
            Self::Waived => "waived",
            Self::Failed => "failed",
        }
    }
    pub fn allows_schedule(self) -> bool {
        matches!(self, Self::Satisfied | Self::Waived)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Submitted,
    Applied,
    PartiallyApplied,
    RolledBack,
    Expired,
}
impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Applied => "applied",
            Self::PartiallyApplied => "partially_applied",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Collecting,
    Blocked,
    Ready,
    Released,
    Revoked,
}
impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Blocked => "blocked",
            Self::Ready => "ready",
            Self::Released => "released",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub low_fee_batch_target: usize,
    pub low_fee_batch_limit: usize,
    pub batch_gas_limit: u64,
    pub batch_rent_limit: u64,
    pub migration_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rollback_blocks: u64,
    pub expiry_grace_blocks: u64,
    pub witness_rent_per_kib: u64,
    pub min_release_score: u64,
    pub require_pq_attestation: bool,
    pub require_release_readiness: bool,
    pub allow_dependency_waivers: bool,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            devnet_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            low_fee_batch_target: DEFAULT_LOW_FEE_BATCH_TARGET,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            batch_gas_limit: DEFAULT_BATCH_GAS_LIMIT,
            batch_rent_limit: DEFAULT_BATCH_RENT_LIMIT,
            migration_ttl_blocks: DEFAULT_MIGRATION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rollback_blocks: DEFAULT_ROLLBACK_BLOCKS,
            expiry_grace_blocks: DEFAULT_EXPIRY_GRACE_BLOCKS,
            witness_rent_per_kib: DEFAULT_WITNESS_RENT_PER_KIB,
            min_release_score: DEFAULT_MIN_RELEASE_SCORE,
            require_pq_attestation: true,
            require_release_readiness: true,
            allow_dependency_waivers: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "low_fee_batch_target": self.low_fee_batch_target,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "batch_gas_limit": self.batch_gas_limit,
            "batch_rent_limit": self.batch_rent_limit,
            "migration_ttl_blocks": self.migration_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "rollback_blocks": self.rollback_blocks,
            "expiry_grace_blocks": self.expiry_grace_blocks,
            "witness_rent_per_kib": self.witness_rent_per_kib,
            "min_release_score": self.min_release_score,
            "require_pq_attestation": self.require_pq_attestation,
            "require_release_readiness": self.require_release_readiness,
            "allow_dependency_waivers": self.allow_dependency_waivers,
        })
    }
    pub fn root(&self) -> String {
        root_from_record("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub contracts: u64,
    pub migration_plans: u64,
    pub ready_plans: u64,
    pub blocked_plans: u64,
    pub applied_plans: u64,
    pub storage_shards: u64,
    pub version_constraints: u64,
    pub witness_rent_deposits: u64,
    pub expiry_frontiers: u64,
    pub privacy_budgets: u64,
    pub pq_gates: u64,
    pub open_dependencies: u64,
    pub satisfied_dependencies: u64,
    pub batches: u64,
    pub rollback_windows: u64,
    pub release_readiness: u64,
    pub events: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub contract_root: String,
    pub plan_root: String,
    pub storage_shard_root: String,
    pub version_constraint_root: String,
    pub witness_rent_root: String,
    pub state_expiry_root: String,
    pub privacy_budget_root: String,
    pub pq_attestation_gate_root: String,
    pub defi_dependency_root: String,
    pub batch_root: String,
    pub rollback_window_root: String,
    pub release_readiness_root: String,
    pub event_root: String,
    pub scheduler_queue_root: String,
    pub readiness_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
impl Default for Roots {
    fn default() -> Self {
        let empty = empty_root("DEFAULT");
        Self {
            config_root: empty.clone(),
            contract_root: empty.clone(),
            plan_root: empty.clone(),
            storage_shard_root: empty.clone(),
            version_constraint_root: empty.clone(),
            witness_rent_root: empty.clone(),
            state_expiry_root: empty.clone(),
            privacy_budget_root: empty.clone(),
            pq_attestation_gate_root: empty.clone(),
            defi_dependency_root: empty.clone(),
            batch_root: empty.clone(),
            rollback_window_root: empty.clone(),
            release_readiness_root: empty.clone(),
            event_root: empty.clone(),
            scheduler_queue_root: empty.clone(),
            readiness_root: empty.clone(),
            state_root: empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractRecord {
    pub contract_id: String,
    pub kind: ContractKind,
    pub owner_commitment: String,
    pub current_bytecode_version: u64,
    pub target_bytecode_version: u64,
    pub current_circuit_version: u64,
    pub target_circuit_version: u64,
    pub storage_layout_root: String,
    pub state_commitment_root: String,
    pub privacy_domain: String,
    pub active_plan_id: Option<String>,
    pub frozen: bool,
    pub registered_at_height: u64,
}
impl ContractRecord {
    pub fn new(request: RegisterContractRequest, height: u64) -> Self {
        Self {
            contract_id: request.contract_id,
            kind: request.kind,
            owner_commitment: request.owner_commitment,
            current_bytecode_version: request.current_bytecode_version,
            target_bytecode_version: request.target_bytecode_version,
            current_circuit_version: request.current_circuit_version,
            target_circuit_version: request.target_circuit_version,
            storage_layout_root: request.storage_layout_root,
            state_commitment_root: request.state_commitment_root,
            privacy_domain: request.privacy_domain,
            active_plan_id: None,
            frozen: false,
            registered_at_height: height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "active_plan_id": self.active_plan_id,
            "contract_id": self.contract_id,
            "current_bytecode_version": self.current_bytecode_version,
            "current_circuit_version": self.current_circuit_version,
            "frozen": self.frozen,
            "kind": self.kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "privacy_domain": self.privacy_domain,
            "registered_at_height": self.registered_at_height,
            "state_commitment_root": self.state_commitment_root,
            "storage_layout_root": self.storage_layout_root,
            "target_bytecode_version": self.target_bytecode_version,
            "target_circuit_version": self.target_circuit_version,
        })
    }
    pub fn root(&self) -> String {
        root_from_record("CONTRACT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterContractRequest {
    pub contract_id: String,
    pub kind: ContractKind,
    pub owner_commitment: String,
    pub current_bytecode_version: u64,
    pub target_bytecode_version: u64,
    pub current_circuit_version: u64,
    pub target_circuit_version: u64,
    pub storage_layout_root: String,
    pub state_commitment_root: String,
    pub privacy_domain: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationPlanRequest {
    pub plan_id: String,
    pub contract_id: String,
    pub lane: MigrationLane,
    pub target_storage_layout_root: String,
    pub target_state_commitment_root: String,
    pub migration_program_root: String,
    pub rollback_program_root: String,
    pub witness_bundle_root: String,
    pub required_privacy_set_size: u64,
    pub estimated_gas: u64,
    pub estimated_witness_kib: u64,
    pub max_fee_bps: u64,
    pub sponsor_commitment: Option<String>,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationPlanRecord {
    pub plan_id: String,
    pub contract_id: String,
    pub lane: MigrationLane,
    pub status: PlanStatus,
    pub target_storage_layout_root: String,
    pub target_state_commitment_root: String,
    pub migration_program_root: String,
    pub rollback_program_root: String,
    pub witness_bundle_root: String,
    pub required_privacy_set_size: u64,
    pub estimated_gas: u64,
    pub estimated_witness_kib: u64,
    pub max_fee_bps: u64,
    pub sponsor_commitment: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub ready_at_height: Option<u64>,
    pub batch_id: Option<String>,
    pub applied_at_height: Option<u64>,
    pub rejection_reason: Option<String>,
}
impl MigrationPlanRecord {
    pub fn new(request: MigrationPlanRequest, height: u64) -> Self {
        Self {
            plan_id: request.plan_id,
            contract_id: request.contract_id,
            lane: request.lane,
            status: PlanStatus::Registered,
            target_storage_layout_root: request.target_storage_layout_root,
            target_state_commitment_root: request.target_state_commitment_root,
            migration_program_root: request.migration_program_root,
            rollback_program_root: request.rollback_program_root,
            witness_bundle_root: request.witness_bundle_root,
            required_privacy_set_size: request.required_privacy_set_size,
            estimated_gas: request.estimated_gas,
            estimated_witness_kib: request.estimated_witness_kib,
            max_fee_bps: request.max_fee_bps,
            sponsor_commitment: request.sponsor_commitment,
            created_at_height: height,
            expires_at_height: request.expires_at_height,
            ready_at_height: None,
            batch_id: None,
            applied_at_height: None,
            rejection_reason: None,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "applied_at_height": self.applied_at_height,
            "batch_id": self.batch_id,
            "contract_id": self.contract_id,
            "created_at_height": self.created_at_height,
            "estimated_gas": self.estimated_gas,
            "estimated_witness_kib": self.estimated_witness_kib,
            "expires_at_height": self.expires_at_height,
            "lane": self.lane.as_str(),
            "max_fee_bps": self.max_fee_bps,
            "migration_program_root": self.migration_program_root,
            "plan_id": self.plan_id,
            "ready_at_height": self.ready_at_height,
            "rejection_reason": self.rejection_reason,
            "required_privacy_set_size": self.required_privacy_set_size,
            "rollback_program_root": self.rollback_program_root,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "target_state_commitment_root": self.target_state_commitment_root,
            "target_storage_layout_root": self.target_storage_layout_root,
            "witness_bundle_root": self.witness_bundle_root,
        })
    }
    pub fn root(&self) -> String {
        root_from_record("MIGRATION-PLAN", &self.public_record())
    }
    pub fn score(&self, config: &Config, contract_kind: ContractKind) -> u64 {
        let fee_bonus = config
            .max_user_fee_bps
            .saturating_mul(3)
            .saturating_sub(self.max_fee_bps)
            .saturating_mul(10);
        self.lane
            .priority_weight()
            .saturating_add(contract_kind.defi_weight())
            .saturating_add(fee_bonus)
            .saturating_add(self.required_privacy_set_size / 1_024)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageShardRequest {
    pub shard_id: String,
    pub plan_id: String,
    pub contract_id: String,
    pub old_shard_root: String,
    pub new_shard_root: String,
    pub witness_commitment_root: String,
    pub nullifier_root: String,
    pub slot_count: u64,
    pub encrypted_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageShardRecord {
    pub shard_id: String,
    pub plan_id: String,
    pub contract_id: String,
    pub old_shard_root: String,
    pub new_shard_root: String,
    pub witness_commitment_root: String,
    pub nullifier_root: String,
    pub slot_count: u64,
    pub encrypted_bytes: u64,
    pub posted_at_height: u64,
}
impl StorageShardRecord {
    pub fn new(request: StorageShardRequest, height: u64) -> Self {
        Self {
            shard_id: request.shard_id,
            plan_id: request.plan_id,
            contract_id: request.contract_id,
            old_shard_root: request.old_shard_root,
            new_shard_root: request.new_shard_root,
            witness_commitment_root: request.witness_commitment_root,
            nullifier_root: request.nullifier_root,
            slot_count: request.slot_count,
            encrypted_bytes: request.encrypted_bytes,
            posted_at_height: height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        root_from_record("STORAGE-SHARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VersionConstraintRecord {
    pub constraint_id: String,
    pub contract_id: String,
    pub plan_id: String,
    pub kind: ConstraintKind,
    pub required_version: u64,
    pub feature_root: String,
    pub enforced: bool,
    pub posted_at_height: u64,
}
impl VersionConstraintRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "constraint_id": self.constraint_id,
            "contract_id": self.contract_id,
            "enforced": self.enforced,
            "feature_root": self.feature_root,
            "kind": self.kind.as_str(),
            "plan_id": self.plan_id,
            "posted_at_height": self.posted_at_height,
            "required_version": self.required_version,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VersionConstraintRequest {
    pub constraint_id: String,
    pub contract_id: String,
    pub plan_id: String,
    pub kind: ConstraintKind,
    pub required_version: u64,
    pub feature_root: String,
    pub enforced: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessRentRecord {
    pub deposit_id: String,
    pub plan_id: String,
    pub payer_commitment: String,
    pub rent_asset_id: String,
    pub witness_kib: u64,
    pub prepaid_blocks: u64,
    pub amount: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}
impl WitnessRentRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn active_at(&self, height: u64) -> bool {
        !self.consumed && self.expires_at_height >= height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessRentRequest {
    pub deposit_id: String,
    pub plan_id: String,
    pub payer_commitment: String,
    pub rent_asset_id: String,
    pub witness_kib: u64,
    pub prepaid_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateExpiryRecord {
    pub expiry_id: String,
    pub contract_id: String,
    pub plan_id: String,
    pub expiry_frontier_root: String,
    pub expires_at_height: u64,
    pub grace_until_height: u64,
    pub refreshed: bool,
}
impl StateExpiryRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn expired_at(&self, height: u64) -> bool {
        !self.refreshed && self.grace_until_height < height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetRecord {
    pub budget_id: String,
    pub contract_id: String,
    pub plan_id: String,
    pub privacy_domain: String,
    pub available_budget: u64,
    pub reserved_budget: u64,
    pub min_anonymity_set: u64,
    pub spent_nullifier_root: String,
    pub renewed_at_height: u64,
}
impl PrivacyBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn can_reserve(&self, required: u64, min_set: u64) -> bool {
        self.available_budget >= self.reserved_budget.saturating_add(required)
            && self.min_anonymity_set >= min_set
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetRequest {
    pub budget_id: String,
    pub contract_id: String,
    pub plan_id: String,
    pub privacy_domain: String,
    pub available_budget: u64,
    pub min_anonymity_set: u64,
    pub spent_nullifier_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationGateRecord {
    pub gate_id: String,
    pub contract_id: String,
    pub plan_id: String,
    pub kind: AttestationKind,
    pub attester_commitment: String,
    pub attestation_root: String,
    pub signature_scheme: String,
    pub pq_security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub revoked: bool,
}
impl PqAttestationGateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_root": self.attestation_root,
            "attester_commitment": self.attester_commitment,
            "contract_id": self.contract_id,
            "gate_id": self.gate_id,
            "kind": self.kind.as_str(),
            "plan_id": self.plan_id,
            "pq_security_bits": self.pq_security_bits,
            "revoked": self.revoked,
            "signature_scheme": self.signature_scheme,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
    pub fn active_at(&self, height: u64, min_bits: u16) -> bool {
        !self.revoked
            && self.valid_from_height <= height
            && self.valid_until_height >= height
            && self.pq_security_bits >= min_bits
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationGateRequest {
    pub gate_id: String,
    pub contract_id: String,
    pub plan_id: String,
    pub kind: AttestationKind,
    pub attester_commitment: String,
    pub attestation_root: String,
    pub signature_scheme: String,
    pub pq_security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefiDependencyRecord {
    pub dependency_id: String,
    pub plan_id: String,
    pub contract_id: String,
    pub depends_on_plan_id: String,
    pub kind: DefiDependencyKind,
    pub status: DependencyStatus,
    pub proof_root: String,
    pub posted_at_height: u64,
}
impl DefiDependencyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "dependency_id": self.dependency_id,
            "depends_on_plan_id": self.depends_on_plan_id,
            "kind": self.kind.as_str(),
            "plan_id": self.plan_id,
            "posted_at_height": self.posted_at_height,
            "proof_root": self.proof_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefiDependencyRequest {
    pub dependency_id: String,
    pub plan_id: String,
    pub contract_id: String,
    pub depends_on_plan_id: String,
    pub kind: DefiDependencyKind,
    pub proof_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRecord {
    pub batch_id: String,
    pub lane: MigrationLane,
    pub status: BatchStatus,
    pub plan_ids: Vec<String>,
    pub aggregate_migration_root: String,
    pub aggregate_witness_root: String,
    pub aggregate_release_root: String,
    pub total_gas: u64,
    pub total_rent: u64,
    pub fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
}
impl BatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "aggregate_migration_root": self.aggregate_migration_root,
            "aggregate_release_root": self.aggregate_release_root,
            "aggregate_witness_root": self.aggregate_witness_root,
            "batch_id": self.batch_id,
            "fee_bps": self.fee_bps,
            "lane": self.lane.as_str(),
            "opened_at_height": self.opened_at_height,
            "plan_ids": self.plan_ids,
            "privacy_set_size": self.privacy_set_size,
            "sealed_at_height": self.sealed_at_height,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "status": self.status.as_str(),
            "total_gas": self.total_gas,
            "total_rent": self.total_rent,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackWindowRecord {
    pub rollback_id: String,
    pub plan_id: String,
    pub contract_id: String,
    pub batch_id: Option<String>,
    pub rollback_program_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub consumed: bool,
}
impl RollbackWindowRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn open_at(&self, height: u64) -> bool {
        !self.consumed && self.opens_at_height <= height && self.closes_at_height >= height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReadinessRecord {
    pub readiness_id: String,
    pub plan_id: String,
    pub contract_id: String,
    pub status: ReadinessStatus,
    pub storage_root: String,
    pub bytecode_root: String,
    pub circuit_root: String,
    pub witness_rent_root: String,
    pub privacy_budget_root: String,
    pub pq_gate_root: String,
    pub dependency_root: String,
    pub rollback_root: String,
    pub score: u64,
    pub blockers: Vec<String>,
    pub posted_at_height: u64,
}
impl ReleaseReadinessRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "blockers": self.blockers,
            "bytecode_root": self.bytecode_root,
            "circuit_root": self.circuit_root,
            "contract_id": self.contract_id,
            "dependency_root": self.dependency_root,
            "plan_id": self.plan_id,
            "posted_at_height": self.posted_at_height,
            "pq_gate_root": self.pq_gate_root,
            "privacy_budget_root": self.privacy_budget_root,
            "readiness_id": self.readiness_id,
            "rollback_root": self.rollback_root,
            "score": self.score,
            "status": self.status.as_str(),
            "storage_root": self.storage_root,
            "witness_rent_root": self.witness_rent_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_root: String,
    pub emitted_at_height: u64,
}
impl SchedulerEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub contracts: BTreeMap<String, ContractRecord>,
    pub migration_plans: BTreeMap<String, MigrationPlanRecord>,
    pub storage_shards: BTreeMap<String, StorageShardRecord>,
    pub version_constraints: BTreeMap<String, VersionConstraintRecord>,
    pub witness_rent_deposits: BTreeMap<String, WitnessRentRecord>,
    pub expiry_frontiers: BTreeMap<String, StateExpiryRecord>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetRecord>,
    pub pq_gates: BTreeMap<String, PqAttestationGateRecord>,
    pub defi_dependencies: BTreeMap<String, DefiDependencyRecord>,
    pub batches: BTreeMap<String, BatchRecord>,
    pub rollback_windows: BTreeMap<String, RollbackWindowRecord>,
    pub release_readiness: BTreeMap<String, ReleaseReadinessRecord>,
    pub events: BTreeMap<String, SchedulerEvent>,
    pub plan_dependencies: BTreeMap<String, BTreeSet<String>>,
    pub ready_queue: BTreeMap<u64, BTreeSet<String>>,
}
impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            current_height,
            contracts: BTreeMap::new(),
            migration_plans: BTreeMap::new(),
            storage_shards: BTreeMap::new(),
            version_constraints: BTreeMap::new(),
            witness_rent_deposits: BTreeMap::new(),
            expiry_frontiers: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            pq_gates: BTreeMap::new(),
            defi_dependencies: BTreeMap::new(),
            batches: BTreeMap::new(),
            rollback_windows: BTreeMap::new(),
            release_readiness: BTreeMap::new(),
            events: BTreeMap::new(),
            plan_dependencies: BTreeMap::new(),
            ready_queue: BTreeMap::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        let contract = RegisterContractRequest {
            contract_id: "devnet-confidential-vault".to_string(),
            kind: ContractKind::Vault,
            owner_commitment: "owner:devnet:vault-council".to_string(),
            current_bytecode_version: 1,
            target_bytecode_version: 2,
            current_circuit_version: 7,
            target_circuit_version: 8,
            storage_layout_root: "storage-layout:vault:v1".to_string(),
            state_commitment_root: "state:vault:pre-migration".to_string(),
            privacy_domain: "private-vaults".to_string(),
        };
        let _ = state.register_contract(contract);
        let plan = MigrationPlanRequest {
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            contract_id: "devnet-confidential-vault".to_string(),
            lane: MigrationLane::DefiDependency,
            target_storage_layout_root: "storage-layout:vault:v2".to_string(),
            target_state_commitment_root: "state:vault:target".to_string(),
            migration_program_root: "program:migrate-vault-v2".to_string(),
            rollback_program_root: "program:rollback-vault-v1".to_string(),
            witness_bundle_root: "witness:vault-v2".to_string(),
            required_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            estimated_gas: 2_700_000,
            estimated_witness_kib: 4_096,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_commitment: Some("sponsor:devnet:low-fee-pool".to_string()),
            expires_at_height: DEVNET_HEIGHT + DEFAULT_MIGRATION_TTL_BLOCKS,
        };
        let _ = state.register_migration_plan(plan);
        let _ = state.add_storage_shard(StorageShardRequest {
            shard_id: "shard-vault-positions".to_string(),
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            contract_id: "devnet-confidential-vault".to_string(),
            old_shard_root: "shard:positions:v1".to_string(),
            new_shard_root: "shard:positions:v2".to_string(),
            witness_commitment_root: "witness:positions:v2".to_string(),
            nullifier_root: "nullifier:positions:v2".to_string(),
            slot_count: 16_384,
            encrypted_bytes: 8_388_608,
        });
        let _ = state.add_version_constraint(VersionConstraintRequest {
            constraint_id: "constraint-vault-bytecode-min".to_string(),
            contract_id: "devnet-confidential-vault".to_string(),
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            kind: ConstraintKind::BytecodeMin,
            required_version: 2,
            feature_root: "bytecode:features:v2".to_string(),
            enforced: true,
        });
        let _ = state.add_version_constraint(VersionConstraintRequest {
            constraint_id: "constraint-vault-circuit-min".to_string(),
            contract_id: "devnet-confidential-vault".to_string(),
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            kind: ConstraintKind::CircuitMin,
            required_version: 8,
            feature_root: "circuit:features:v8".to_string(),
            enforced: true,
        });
        let _ = state.deposit_witness_rent(WitnessRentRequest {
            deposit_id: "rent-vault-witness".to_string(),
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            payer_commitment: "payer:devnet:vault".to_string(),
            rent_asset_id: "pnebula-devnet".to_string(),
            witness_kib: 4_096,
            prepaid_blocks: DEFAULT_ROLLBACK_BLOCKS + 120,
        });
        let _ = state.add_privacy_budget(PrivacyBudgetRequest {
            budget_id: "budget-vault-private-domain".to_string(),
            contract_id: "devnet-confidential-vault".to_string(),
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            privacy_domain: "private-vaults".to_string(),
            available_budget: 1_000_000,
            min_anonymity_set: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            spent_nullifier_root: "spent:nullifiers:vault".to_string(),
        });
        let _ = state.add_pq_gate(PqAttestationGateRequest {
            gate_id: "gate-vault-pq-committee".to_string(),
            contract_id: "devnet-confidential-vault".to_string(),
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            kind: AttestationKind::PqCommittee,
            attester_commitment: "committee:devnet:pq".to_string(),
            attestation_root: "attestation:pq:vault-v2".to_string(),
            signature_scheme: "ml-dsa-87+slh-dsa-shake-256f".to_string(),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
        });
        let _ = state.add_expiry_frontier(
            "expiry-vault-state".to_string(),
            "devnet-confidential-vault".to_string(),
            "plan-devnet-confidential-vault-v2".to_string(),
            "expiry-frontier:vault".to_string(),
            DEVNET_HEIGHT + DEFAULT_MIGRATION_TTL_BLOCKS,
        );
        let _ = state.refresh_plan_readiness("plan-devnet-confidential-vault-v2");
        state
    }
    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let token = RegisterContractRequest {
            contract_id: "devnet-private-token".to_string(),
            kind: ContractKind::Token,
            owner_commitment: "owner:devnet:token".to_string(),
            current_bytecode_version: 4,
            target_bytecode_version: 5,
            current_circuit_version: 10,
            target_circuit_version: 11,
            storage_layout_root: "storage-layout:token:v4".to_string(),
            state_commitment_root: "state:token:pre".to_string(),
            privacy_domain: "private-assets".to_string(),
        };
        let _ = state.register_contract(token);
        let plan = MigrationPlanRequest {
            plan_id: "plan-devnet-token-v5".to_string(),
            contract_id: "devnet-private-token".to_string(),
            lane: MigrationLane::SponsoredLowFee,
            target_storage_layout_root: "storage-layout:token:v5".to_string(),
            target_state_commitment_root: "state:token:target".to_string(),
            migration_program_root: "program:migrate-token-v5".to_string(),
            rollback_program_root: "program:rollback-token-v4".to_string(),
            witness_bundle_root: "witness:token-v5".to_string(),
            required_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            estimated_gas: 1_100_000,
            estimated_witness_kib: 1_024,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS / 2,
            sponsor_commitment: Some("sponsor:devnet:token".to_string()),
            expires_at_height: state.current_height + DEFAULT_MIGRATION_TTL_BLOCKS,
        };
        let _ = state.register_migration_plan(plan);
        let _ = state.add_defi_dependency(DefiDependencyRequest {
            dependency_id: "dep-vault-token-before-vault".to_string(),
            plan_id: "plan-devnet-confidential-vault-v2".to_string(),
            contract_id: "devnet-confidential-vault".to_string(),
            depends_on_plan_id: "plan-devnet-token-v5".to_string(),
            kind: DefiDependencyKind::TokenBeforeVault,
            proof_root: "dependency:token-before-vault".to_string(),
        });
        let _ = state.satisfy_dependency("dep-vault-token-before-vault", "proof:token-ready");
        let _ = state.refresh_plan_readiness("plan-devnet-confidential-vault-v2");
        state
    }
    pub fn register_contract(&mut self, request: RegisterContractRequest) -> Result<()> {
        validate_id("contract_id", &request.contract_id)?;
        validate_nonempty("owner_commitment", &request.owner_commitment)?;
        validate_nonempty("storage_layout_root", &request.storage_layout_root)?;
        validate_nonempty("state_commitment_root", &request.state_commitment_root)?;
        validate_nonempty("privacy_domain", &request.privacy_domain)?;
        if self.contracts.len() >= MAX_CONTRACTS {
            return Err("contract capacity reached".to_string());
        }
        if self.contracts.contains_key(&request.contract_id) {
            return Err("contract already registered".to_string());
        }
        let contract = ContractRecord::new(request, self.current_height);
        self.emit_event(
            "contract_registered",
            &contract.contract_id,
            &contract.public_record(),
        );
        self.contracts
            .insert(contract.contract_id.clone(), contract);
        Ok(())
    }
    pub fn register_migration_plan(&mut self, request: MigrationPlanRequest) -> Result<()> {
        validate_id("plan_id", &request.plan_id)?;
        validate_id("contract_id", &request.contract_id)?;
        validate_nonempty("migration_program_root", &request.migration_program_root)?;
        validate_nonempty("rollback_program_root", &request.rollback_program_root)?;
        validate_nonempty("witness_bundle_root", &request.witness_bundle_root)?;
        if self.migration_plans.len() >= MAX_MIGRATION_PLANS {
            return Err("migration plan capacity reached".to_string());
        }
        if self.migration_plans.contains_key(&request.plan_id) {
            return Err("migration plan already exists".to_string());
        }
        let contract = match self.contracts.get(&request.contract_id) {
            Some(value) => value,
            None => return Err("unknown contract".to_string()),
        };
        if contract.frozen {
            return Err("contract is frozen".to_string());
        }
        if request.required_privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        if request.estimated_gas > self.config.batch_gas_limit {
            return Err("plan gas exceeds batch limit".to_string());
        }
        if request.max_fee_bps > request.lane.fee_bps(&self.config) {
            return Err("plan fee exceeds lane limit".to_string());
        }
        let minimum_expiry = self.current_height.saturating_add(1);
        if request.expires_at_height < minimum_expiry {
            return Err("plan expiry is not in the future".to_string());
        }
        let plan_id = request.plan_id.clone();
        let contract_id = request.contract_id.clone();
        let plan = MigrationPlanRecord::new(request, self.current_height);
        self.migration_plans.insert(plan_id.clone(), plan);
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.active_plan_id = Some(plan_id.clone());
        }
        self.emit_event(
            "migration_plan_registered",
            &plan_id,
            &json!({ "contract_id": contract_id }),
        );
        Ok(())
    }
    pub fn add_storage_shard(&mut self, request: StorageShardRequest) -> Result<()> {
        validate_id("shard_id", &request.shard_id)?;
        self.ensure_plan_contract(&request.plan_id, &request.contract_id)?;
        if self.storage_shards.len() >= MAX_STORAGE_SHARDS {
            return Err("storage shard capacity reached".to_string());
        }
        if self.storage_shards.contains_key(&request.shard_id) {
            return Err("storage shard already exists".to_string());
        }
        let record = StorageShardRecord::new(request, self.current_height);
        self.emit_event(
            "storage_shard_posted",
            &record.shard_id,
            &record.public_record(),
        );
        self.storage_shards.insert(record.shard_id.clone(), record);
        Ok(())
    }
    pub fn add_version_constraint(&mut self, request: VersionConstraintRequest) -> Result<()> {
        validate_id("constraint_id", &request.constraint_id)?;
        self.ensure_plan_contract(&request.plan_id, &request.contract_id)?;
        if self.version_constraints.len() >= MAX_VERSION_CONSTRAINTS {
            return Err("version constraint capacity reached".to_string());
        }
        if self
            .version_constraints
            .contains_key(&request.constraint_id)
        {
            return Err("version constraint already exists".to_string());
        }
        let record = VersionConstraintRecord {
            constraint_id: request.constraint_id,
            contract_id: request.contract_id,
            plan_id: request.plan_id,
            kind: request.kind,
            required_version: request.required_version,
            feature_root: request.feature_root,
            enforced: request.enforced,
            posted_at_height: self.current_height,
        };
        self.emit_event(
            "version_constraint_posted",
            &record.constraint_id,
            &record.public_record(),
        );
        self.version_constraints
            .insert(record.constraint_id.clone(), record);
        Ok(())
    }
    pub fn deposit_witness_rent(&mut self, request: WitnessRentRequest) -> Result<()> {
        validate_id("deposit_id", &request.deposit_id)?;
        validate_id("plan_id", &request.plan_id)?;
        validate_nonempty("payer_commitment", &request.payer_commitment)?;
        validate_nonempty("rent_asset_id", &request.rent_asset_id)?;
        if self.witness_rent_deposits.len() >= MAX_WITNESS_RENT_DEPOSITS {
            return Err("witness rent capacity reached".to_string());
        }
        if !self.migration_plans.contains_key(&request.plan_id) {
            return Err("unknown plan".to_string());
        }
        let amount = request
            .witness_kib
            .saturating_mul(request.prepaid_blocks)
            .saturating_mul(self.config.witness_rent_per_kib);
        let record = WitnessRentRecord {
            deposit_id: request.deposit_id,
            plan_id: request.plan_id,
            payer_commitment: request.payer_commitment,
            rent_asset_id: request.rent_asset_id,
            witness_kib: request.witness_kib,
            prepaid_blocks: request.prepaid_blocks,
            amount,
            expires_at_height: self.current_height.saturating_add(request.prepaid_blocks),
            consumed: false,
        };
        self.emit_event(
            "witness_rent_deposited",
            &record.deposit_id,
            &record.public_record(),
        );
        self.witness_rent_deposits
            .insert(record.deposit_id.clone(), record);
        Ok(())
    }
    pub fn add_expiry_frontier(
        &mut self,
        expiry_id: String,
        contract_id: String,
        plan_id: String,
        expiry_frontier_root: String,
        expires_at_height: u64,
    ) -> Result<()> {
        validate_id("expiry_id", &expiry_id)?;
        self.ensure_plan_contract(&plan_id, &contract_id)?;
        if self.expiry_frontiers.len() >= MAX_EXPIRY_FRONTIERS {
            return Err("state expiry frontier capacity reached".to_string());
        }
        let record = StateExpiryRecord {
            expiry_id,
            contract_id,
            plan_id,
            expiry_frontier_root,
            expires_at_height,
            grace_until_height: expires_at_height.saturating_add(self.config.expiry_grace_blocks),
            refreshed: false,
        };
        self.emit_event(
            "state_expiry_frontier_posted",
            &record.expiry_id,
            &record.public_record(),
        );
        self.expiry_frontiers
            .insert(record.expiry_id.clone(), record);
        Ok(())
    }
    pub fn add_privacy_budget(&mut self, request: PrivacyBudgetRequest) -> Result<()> {
        validate_id("budget_id", &request.budget_id)?;
        self.ensure_plan_contract(&request.plan_id, &request.contract_id)?;
        if self.privacy_budgets.len() >= MAX_PRIVACY_BUDGETS {
            return Err("privacy budget capacity reached".to_string());
        }
        let record = PrivacyBudgetRecord {
            budget_id: request.budget_id,
            contract_id: request.contract_id,
            plan_id: request.plan_id,
            privacy_domain: request.privacy_domain,
            available_budget: request.available_budget,
            reserved_budget: 0,
            min_anonymity_set: request.min_anonymity_set,
            spent_nullifier_root: request.spent_nullifier_root,
            renewed_at_height: self.current_height,
        };
        self.emit_event(
            "privacy_budget_posted",
            &record.budget_id,
            &record.public_record(),
        );
        self.privacy_budgets
            .insert(record.budget_id.clone(), record);
        Ok(())
    }
    pub fn add_pq_gate(&mut self, request: PqAttestationGateRequest) -> Result<()> {
        validate_id("gate_id", &request.gate_id)?;
        self.ensure_plan_contract(&request.plan_id, &request.contract_id)?;
        if self.pq_gates.len() >= MAX_PQ_GATES {
            return Err("pq gate capacity reached".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq gate below minimum security bits".to_string());
        }
        if request.valid_until_height < request.valid_from_height {
            return Err("pq gate validity range is inverted".to_string());
        }
        let record = PqAttestationGateRecord {
            gate_id: request.gate_id,
            contract_id: request.contract_id,
            plan_id: request.plan_id,
            kind: request.kind,
            attester_commitment: request.attester_commitment,
            attestation_root: request.attestation_root,
            signature_scheme: request.signature_scheme,
            pq_security_bits: request.pq_security_bits,
            valid_from_height: request.valid_from_height,
            valid_until_height: request.valid_until_height,
            revoked: false,
        };
        self.emit_event(
            "pq_attestation_gate_posted",
            &record.gate_id,
            &record.public_record(),
        );
        self.pq_gates.insert(record.gate_id.clone(), record);
        Ok(())
    }
    pub fn add_defi_dependency(&mut self, request: DefiDependencyRequest) -> Result<()> {
        validate_id("dependency_id", &request.dependency_id)?;
        self.ensure_plan_contract(&request.plan_id, &request.contract_id)?;
        if self.defi_dependencies.len() >= MAX_DEFI_DEPENDENCIES {
            return Err("defi dependency capacity reached".to_string());
        }
        if !self
            .migration_plans
            .contains_key(&request.depends_on_plan_id)
        {
            return Err("dependency target plan is unknown".to_string());
        }
        let record = DefiDependencyRecord {
            dependency_id: request.dependency_id,
            plan_id: request.plan_id,
            contract_id: request.contract_id,
            depends_on_plan_id: request.depends_on_plan_id,
            kind: request.kind,
            status: DependencyStatus::Open,
            proof_root: request.proof_root,
            posted_at_height: self.current_height,
        };
        self.plan_dependencies
            .entry(record.plan_id.clone())
            .or_default()
            .insert(record.dependency_id.clone());
        self.emit_event(
            "defi_dependency_posted",
            &record.dependency_id,
            &record.public_record(),
        );
        self.defi_dependencies
            .insert(record.dependency_id.clone(), record);
        Ok(())
    }
    pub fn satisfy_dependency(&mut self, dependency_id: &str, proof_root: &str) -> Result<()> {
        let plan_id = match self.defi_dependencies.get_mut(dependency_id) {
            Some(record) => {
                record.status = DependencyStatus::Satisfied;
                record.proof_root = proof_root.to_string();
                record.plan_id.clone()
            }
            None => return Err("unknown dependency".to_string()),
        };
        self.emit_event(
            "defi_dependency_satisfied",
            dependency_id,
            &json!({ "plan_id": plan_id, "proof_root": proof_root }),
        );
        Ok(())
    }
    pub fn waive_dependency(&mut self, dependency_id: &str, proof_root: &str) -> Result<()> {
        if !self.config.allow_dependency_waivers {
            return Err("dependency waivers disabled".to_string());
        }
        let plan_id = match self.defi_dependencies.get_mut(dependency_id) {
            Some(record) => {
                record.status = DependencyStatus::Waived;
                record.proof_root = proof_root.to_string();
                record.plan_id.clone()
            }
            None => return Err("unknown dependency".to_string()),
        };
        self.emit_event(
            "defi_dependency_waived",
            dependency_id,
            &json!({ "plan_id": plan_id, "proof_root": proof_root }),
        );
        Ok(())
    }
    pub fn refresh_plan_readiness(&mut self, plan_id: &str) -> Result<ReleaseReadinessRecord> {
        let plan = match self.migration_plans.get(plan_id) {
            Some(value) => value.clone(),
            None => return Err("unknown plan".to_string()),
        };
        let contract = match self.contracts.get(&plan.contract_id) {
            Some(value) => value.clone(),
            None => return Err("plan contract missing".to_string()),
        };
        let mut blockers = Vec::new();
        if plan.expires_at_height < self.current_height {
            blockers.push("plan_expired".to_string());
        }
        if contract.frozen {
            blockers.push("contract_frozen".to_string());
        }
        if !self.version_constraints_satisfied(&contract, &plan) {
            blockers.push("version_constraints".to_string());
        }
        if !self.witness_rent_satisfied(&plan) {
            blockers.push("witness_rent".to_string());
        }
        if !self.privacy_budget_satisfied(&plan) {
            blockers.push("privacy_budget".to_string());
        }
        if self.config.require_pq_attestation && !self.pq_gates_satisfied(&plan) {
            blockers.push("pq_attestation_gate".to_string());
        }
        if !self.dependencies_satisfied(&plan.plan_id) {
            blockers.push("defi_dependencies".to_string());
        }
        if self.has_expired_state(&plan) {
            blockers.push("state_expired".to_string());
        }
        let score = self.readiness_score(&contract, &plan, blockers.len() as u64);
        let status = if blockers.is_empty() && score >= self.config.min_release_score {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::Blocked
        };
        let readiness = ReleaseReadinessRecord {
            readiness_id: format!("readiness-{plan_id}"),
            plan_id: plan_id.to_string(),
            contract_id: plan.contract_id.clone(),
            status,
            storage_root: self.storage_root_for_plan(plan_id),
            bytecode_root: self.constraint_root_for_plan(plan_id, "bytecode"),
            circuit_root: self.constraint_root_for_plan(plan_id, "circuit"),
            witness_rent_root: self.witness_rent_root_for_plan(plan_id),
            privacy_budget_root: self.privacy_budget_root_for_plan(plan_id),
            pq_gate_root: self.pq_gate_root_for_plan(plan_id),
            dependency_root: self.dependency_root_for_plan(plan_id),
            rollback_root: root_from_record(
                "ROLLBACK-READINESS",
                &json!({
                    "plan_id": plan_id,
                    "rollback_program_root": plan.rollback_program_root,
                    "rollback_blocks": self.config.rollback_blocks,
                }),
            ),
            score,
            blockers,
            posted_at_height: self.current_height,
        };
        if self.release_readiness.len() >= MAX_RELEASE_READINESS
            && !self.release_readiness.contains_key(&readiness.readiness_id)
        {
            return Err("release readiness capacity reached".to_string());
        }
        self.release_readiness
            .insert(readiness.readiness_id.clone(), readiness.clone());
        if let Some(plan_mut) = self.migration_plans.get_mut(plan_id) {
            if readiness.status == ReadinessStatus::Ready {
                plan_mut.status = PlanStatus::Ready;
                plan_mut.ready_at_height = Some(self.current_height);
                let score_key = u64::MAX.saturating_sub(score);
                self.ready_queue
                    .entry(score_key)
                    .or_default()
                    .insert(plan_id.to_string());
            } else if !plan_mut.status.terminal() {
                plan_mut.status = PlanStatus::DependencyBlocked;
            }
        }
        self.emit_event(
            "release_readiness_refreshed",
            &readiness.readiness_id,
            &readiness.public_record(),
        );
        Ok(readiness)
    }
    pub fn schedule_low_fee_batch(
        &mut self,
        batch_id: String,
        lane: MigrationLane,
    ) -> Result<BatchRecord> {
        validate_id("batch_id", &batch_id)?;
        if self.batches.len() >= MAX_BATCHES {
            return Err("batch capacity reached".to_string());
        }
        if self.batches.contains_key(&batch_id) {
            return Err("batch already exists".to_string());
        }
        let mut selected = Vec::new();
        let mut total_gas = 0_u64;
        let mut total_rent = 0_u64;
        let queue_snapshot = self.ready_queue.clone();
        for plan_ids in queue_snapshot.values() {
            for plan_id in plan_ids {
                if selected.len() >= self.config.low_fee_batch_limit {
                    break;
                }
                let plan = match self.migration_plans.get(plan_id) {
                    Some(value) => value,
                    None => continue,
                };
                if plan.lane != lane || !plan.status.schedulable() {
                    continue;
                }
                let rent = plan
                    .estimated_witness_kib
                    .saturating_mul(self.config.witness_rent_per_kib)
                    .saturating_mul(self.config.rollback_blocks);
                if total_gas.saturating_add(plan.estimated_gas) > self.config.batch_gas_limit {
                    continue;
                }
                if total_rent.saturating_add(rent) > self.config.batch_rent_limit {
                    continue;
                }
                selected.push(plan_id.clone());
                total_gas = total_gas.saturating_add(plan.estimated_gas);
                total_rent = total_rent.saturating_add(rent);
            }
            if selected.len() >= self.config.low_fee_batch_target {
                break;
            }
        }
        if selected.is_empty() {
            return Err("no ready plans available for lane".to_string());
        }
        let records = selected
            .iter()
            .filter_map(|plan_id| self.migration_plans.get(plan_id))
            .map(MigrationPlanRecord::public_record)
            .collect::<Vec<_>>();
        let aggregate_migration_root =
            merkle_root("private-contract-state-migration:batch:migration", &records);
        let aggregate_witness_root = merkle_root(
            "private-contract-state-migration:batch:witness",
            &selected
                .iter()
                .map(|plan_id| json!({ "plan_id": plan_id, "witness_root": self.witness_rent_root_for_plan(plan_id) }))
                .collect::<Vec<_>>(),
        );
        let aggregate_release_root = merkle_root(
            "private-contract-state-migration:batch:release",
            &selected
                .iter()
                .map(|plan_id| json!({ "plan_id": plan_id, "readiness_root": self.readiness_root_for_plan(plan_id) }))
                .collect::<Vec<_>>(),
        );
        let batch = BatchRecord {
            batch_id: batch_id.clone(),
            lane,
            status: BatchStatus::Sealed,
            plan_ids: selected.clone(),
            aggregate_migration_root,
            aggregate_witness_root,
            aggregate_release_root,
            total_gas,
            total_rent,
            fee_bps: lane.fee_bps(&self.config),
            sponsor_cover_bps: self.config.sponsor_cover_bps,
            privacy_set_size: self.config.batch_privacy_set_size,
            opened_at_height: self.current_height,
            sealed_at_height: Some(self.current_height),
        };
        for plan_id in &selected {
            if let Some(plan) = self.migration_plans.get_mut(plan_id) {
                plan.status = PlanStatus::Batched;
                plan.batch_id = Some(batch_id.clone());
            }
        }
        self.prune_ready_queue(&selected);
        self.emit_event("batch_sealed", &batch_id, &batch.public_record());
        self.batches.insert(batch_id, batch.clone());
        Ok(batch)
    }
    pub fn apply_batch(
        &mut self,
        batch_id: &str,
        post_state_roots: BTreeMap<String, String>,
    ) -> Result<()> {
        let plan_ids = match self.batches.get(batch_id) {
            Some(batch) => batch.plan_ids.clone(),
            None => return Err("unknown batch".to_string()),
        };
        for plan_id in &plan_ids {
            let post_state_root = match post_state_roots.get(plan_id) {
                Some(root) => root.clone(),
                None => "post-state-root-missing".to_string(),
            };
            self.apply_plan_from_batch(plan_id, Some(batch_id.to_string()), post_state_root)?;
        }
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = BatchStatus::Applied;
        }
        self.emit_event("batch_applied", batch_id, &json!({ "plan_ids": plan_ids }));
        Ok(())
    }
    pub fn apply_plan_from_batch(
        &mut self,
        plan_id: &str,
        batch_id: Option<String>,
        post_state_root: String,
    ) -> Result<()> {
        let (
            contract_id,
            rollback_program_root,
            pre_state_root,
            target_bytecode,
            target_circuit,
            target_layout,
        ) = match self.migration_plans.get(plan_id) {
            Some(plan) => {
                let contract = match self.contracts.get(&plan.contract_id) {
                    Some(value) => value,
                    None => return Err("contract missing for plan".to_string()),
                };
                (
                    plan.contract_id.clone(),
                    plan.rollback_program_root.clone(),
                    contract.state_commitment_root.clone(),
                    contract.target_bytecode_version,
                    contract.target_circuit_version,
                    plan.target_storage_layout_root.clone(),
                )
            }
            None => return Err("unknown plan".to_string()),
        };
        if let Some(plan) = self.migration_plans.get_mut(plan_id) {
            if plan.status != PlanStatus::Batched && plan.status != PlanStatus::Ready {
                return Err("plan is not applyable".to_string());
            }
            plan.status = PlanStatus::Applied;
            plan.applied_at_height = Some(self.current_height);
            plan.batch_id = batch_id.clone();
        }
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.current_bytecode_version = target_bytecode;
            contract.current_circuit_version = target_circuit;
            contract.storage_layout_root = target_layout;
            contract.state_commitment_root = post_state_root.clone();
            contract.active_plan_id = None;
        }
        let rollback = RollbackWindowRecord {
            rollback_id: format!("rollback-{plan_id}"),
            plan_id: plan_id.to_string(),
            contract_id: contract_id.clone(),
            batch_id,
            rollback_program_root,
            pre_state_root,
            post_state_root,
            opens_at_height: self.current_height,
            closes_at_height: self
                .current_height
                .saturating_add(self.config.rollback_blocks),
            consumed: false,
        };
        if self.rollback_windows.len() < MAX_ROLLBACK_WINDOWS
            || self.rollback_windows.contains_key(&rollback.rollback_id)
        {
            self.rollback_windows
                .insert(rollback.rollback_id.clone(), rollback.clone());
        }
        self.consume_witness_rent(plan_id);
        self.emit_event(
            "plan_applied",
            plan_id,
            &json!({ "contract_id": contract_id }),
        );
        Ok(())
    }
    pub fn rollback_plan(&mut self, rollback_id: &str) -> Result<()> {
        let (plan_id, contract_id, pre_state_root) = match self.rollback_windows.get(rollback_id) {
            Some(window) => {
                if !window.open_at(self.current_height) {
                    return Err("rollback window is closed".to_string());
                }
                (
                    window.plan_id.clone(),
                    window.contract_id.clone(),
                    window.pre_state_root.clone(),
                )
            }
            None => return Err("unknown rollback window".to_string()),
        };
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.state_commitment_root = pre_state_root;
            contract.frozen = true;
        }
        if let Some(plan) = self.migration_plans.get_mut(&plan_id) {
            plan.status = PlanStatus::RolledBack;
        }
        if let Some(window) = self.rollback_windows.get_mut(rollback_id) {
            window.consumed = true;
        }
        self.emit_event(
            "plan_rolled_back",
            rollback_id,
            &json!({ "plan_id": plan_id }),
        );
        Ok(())
    }
    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.current_height {
            return Err("height cannot move backwards".to_string());
        }
        self.current_height = height;
        self.expire_old_plans();
        Ok(())
    }
    pub fn counters(&self) -> Counters {
        let ready_plans = self
            .migration_plans
            .values()
            .filter(|plan| plan.status == PlanStatus::Ready)
            .count() as u64;
        let blocked_plans = self
            .migration_plans
            .values()
            .filter(|plan| {
                matches!(
                    plan.status,
                    PlanStatus::GatesPending | PlanStatus::DependencyBlocked
                )
            })
            .count() as u64;
        let applied_plans = self
            .migration_plans
            .values()
            .filter(|plan| plan.status == PlanStatus::Applied)
            .count() as u64;
        Counters {
            contracts: self.contracts.len() as u64,
            migration_plans: self.migration_plans.len() as u64,
            ready_plans,
            blocked_plans,
            applied_plans,
            storage_shards: self.storage_shards.len() as u64,
            version_constraints: self.version_constraints.len() as u64,
            witness_rent_deposits: self.witness_rent_deposits.len() as u64,
            expiry_frontiers: self.expiry_frontiers.len() as u64,
            privacy_budgets: self.privacy_budgets.len() as u64,
            pq_gates: self.pq_gates.len() as u64,
            open_dependencies: self
                .defi_dependencies
                .values()
                .filter(|dependency| dependency.status == DependencyStatus::Open)
                .count() as u64,
            satisfied_dependencies: self
                .defi_dependencies
                .values()
                .filter(|dependency| dependency.status.allows_schedule())
                .count() as u64,
            batches: self.batches.len() as u64,
            rollback_windows: self.rollback_windows.len() as u64,
            release_readiness: self.release_readiness.len() as u64,
            events: self.events.len() as u64,
        }
    }
    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let contract_root = map_root(
            "CONTRACTS",
            self.contracts.values().map(ContractRecord::public_record),
        );
        let plan_root = map_root(
            "PLANS",
            self.migration_plans
                .values()
                .map(MigrationPlanRecord::public_record),
        );
        let storage_shard_root = map_root(
            "STORAGE-SHARDS",
            self.storage_shards
                .values()
                .map(StorageShardRecord::public_record),
        );
        let version_constraint_root = map_root(
            "VERSION-CONSTRAINTS",
            self.version_constraints
                .values()
                .map(VersionConstraintRecord::public_record),
        );
        let witness_rent_root = map_root(
            "WITNESS-RENT",
            self.witness_rent_deposits
                .values()
                .map(WitnessRentRecord::public_record),
        );
        let state_expiry_root = map_root(
            "STATE-EXPIRY",
            self.expiry_frontiers
                .values()
                .map(StateExpiryRecord::public_record),
        );
        let privacy_budget_root = map_root(
            "PRIVACY-BUDGETS",
            self.privacy_budgets
                .values()
                .map(PrivacyBudgetRecord::public_record),
        );
        let pq_attestation_gate_root = map_root(
            "PQ-GATES",
            self.pq_gates
                .values()
                .map(PqAttestationGateRecord::public_record),
        );
        let defi_dependency_root = map_root(
            "DEFI-DEPENDENCIES",
            self.defi_dependencies
                .values()
                .map(DefiDependencyRecord::public_record),
        );
        let batch_root = map_root(
            "BATCHES",
            self.batches.values().map(BatchRecord::public_record),
        );
        let rollback_window_root = map_root(
            "ROLLBACK-WINDOWS",
            self.rollback_windows
                .values()
                .map(RollbackWindowRecord::public_record),
        );
        let release_readiness_root = map_root(
            "RELEASE-READINESS",
            self.release_readiness
                .values()
                .map(ReleaseReadinessRecord::public_record),
        );
        let event_root = map_root(
            "EVENTS",
            self.events.values().map(SchedulerEvent::public_record),
        );
        let scheduler_queue_root = map_root(
            "READY-QUEUE",
            self.ready_queue.iter().flat_map(|(score, ids)| {
                ids.iter()
                    .map(move |plan_id| json!({ "score_key": score, "plan_id": plan_id }))
            }),
        );
        let readiness_root = root_from_record(
            "READINESS-SUMMARY",
            &json!({
                "release_readiness_root": release_readiness_root,
                "scheduler_queue_root": scheduler_queue_root,
                "counters": self.counters().public_record(),
            }),
        );
        let state_root = state_root_from_record(&json!({
            "batch_root": batch_root,
            "chain_id": self.config.chain_id,
            "config_root": config_root,
            "contract_root": contract_root,
            "current_height": self.current_height,
            "defi_dependency_root": defi_dependency_root,
            "event_root": event_root,
            "plan_root": plan_root,
            "pq_attestation_gate_root": pq_attestation_gate_root,
            "privacy_budget_root": privacy_budget_root,
            "protocol_version": PROTOCOL_VERSION,
            "readiness_root": readiness_root,
            "release_readiness_root": release_readiness_root,
            "rollback_window_root": rollback_window_root,
            "scheduler_queue_root": scheduler_queue_root,
            "state_expiry_root": state_expiry_root,
            "storage_shard_root": storage_shard_root,
            "version_constraint_root": version_constraint_root,
            "witness_rent_root": witness_rent_root,
        }));
        Roots {
            config_root,
            contract_root,
            plan_root,
            storage_shard_root,
            version_constraint_root,
            witness_rent_root,
            state_expiry_root,
            privacy_budget_root,
            pq_attestation_gate_root,
            defi_dependency_root,
            batch_root,
            rollback_window_root,
            release_readiness_root,
            event_root,
            scheduler_queue_root,
            readiness_root,
            state_root,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "current_height": self.current_height,
            "protocol_version": PROTOCOL_VERSION,
            "roots": self.roots().public_record(),
            "schema_version": SCHEMA_VERSION,
        })
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    fn ensure_plan_contract(&self, plan_id: &str, contract_id: &str) -> Result<()> {
        match self.migration_plans.get(plan_id) {
            Some(plan) if plan.contract_id == contract_id => Ok(()),
            Some(_) => Err("plan contract mismatch".to_string()),
            None => Err("unknown plan".to_string()),
        }
    }
    fn version_constraints_satisfied(
        &self,
        contract: &ContractRecord,
        plan: &MigrationPlanRecord,
    ) -> bool {
        let constraints = self
            .version_constraints
            .values()
            .filter(|constraint| constraint.plan_id == plan.plan_id && constraint.enforced)
            .collect::<Vec<_>>();
        if constraints.is_empty() {
            return false;
        }
        for constraint in constraints {
            let ok = match constraint.kind {
                ConstraintKind::BytecodeMin => {
                    contract.target_bytecode_version >= constraint.required_version
                }
                ConstraintKind::BytecodeMax => {
                    contract.target_bytecode_version <= constraint.required_version
                }
                ConstraintKind::CircuitMin => {
                    contract.target_circuit_version >= constraint.required_version
                }
                ConstraintKind::CircuitMax => {
                    contract.target_circuit_version <= constraint.required_version
                }
                ConstraintKind::StorageLayout => !plan.target_storage_layout_root.is_empty(),
                ConstraintKind::ProverKey
                | ConstraintKind::VerifierKey
                | ConstraintKind::VmFeature
                | ConstraintKind::HostCallSet => !constraint.feature_root.is_empty(),
            };
            if !ok {
                return false;
            }
        }
        true
    }
    fn witness_rent_satisfied(&self, plan: &MigrationPlanRecord) -> bool {
        let required = plan
            .estimated_witness_kib
            .saturating_mul(self.config.rollback_blocks)
            .saturating_mul(self.config.witness_rent_per_kib);
        let paid = self
            .witness_rent_deposits
            .values()
            .filter(|deposit| {
                deposit.plan_id == plan.plan_id && deposit.active_at(self.current_height)
            })
            .map(|deposit| deposit.amount)
            .fold(0_u64, u64::saturating_add);
        paid >= required
    }
    fn privacy_budget_satisfied(&self, plan: &MigrationPlanRecord) -> bool {
        self.privacy_budgets.values().any(|budget| {
            budget.plan_id == plan.plan_id
                && budget.can_reserve(
                    plan.required_privacy_set_size,
                    self.config.min_privacy_set_size,
                )
        })
    }
    fn pq_gates_satisfied(&self, plan: &MigrationPlanRecord) -> bool {
        let active_kinds = self
            .pq_gates
            .values()
            .filter(|gate| {
                gate.plan_id == plan.plan_id
                    && gate.active_at(self.current_height, self.config.min_pq_security_bits)
            })
            .map(|gate| gate.kind)
            .collect::<BTreeSet<_>>();
        active_kinds.contains(&AttestationKind::PqCommittee)
            && (active_kinds.contains(&AttestationKind::CircuitAuditor)
                || active_kinds.contains(&AttestationKind::StorageWitness)
                || active_kinds.contains(&AttestationKind::ReleaseCouncil))
    }
    fn dependencies_satisfied(&self, plan_id: &str) -> bool {
        match self.plan_dependencies.get(plan_id) {
            Some(ids) => ids.iter().all(|dependency_id| {
                self.defi_dependencies
                    .get(dependency_id)
                    .map(|dependency| dependency.status.allows_schedule())
                    .is_some_and(|allowed| allowed)
            }),
            None => true,
        }
    }
    fn has_expired_state(&self, plan: &MigrationPlanRecord) -> bool {
        self.expiry_frontiers
            .values()
            .any(|expiry| expiry.plan_id == plan.plan_id && expiry.expired_at(self.current_height))
    }
    fn readiness_score(
        &self,
        contract: &ContractRecord,
        plan: &MigrationPlanRecord,
        blockers: u64,
    ) -> u64 {
        plan.score(&self.config, contract.kind)
            .saturating_sub(blockers.saturating_mul(250))
            .saturating_add(self.storage_shard_count(&plan.plan_id).saturating_mul(3))
    }
    fn storage_shard_count(&self, plan_id: &str) -> u64 {
        self.storage_shards
            .values()
            .filter(|shard| shard.plan_id == plan_id)
            .count() as u64
    }
    fn storage_root_for_plan(&self, plan_id: &str) -> String {
        map_root(
            "PLAN-STORAGE-SHARDS",
            self.storage_shards
                .values()
                .filter(|record| record.plan_id == plan_id)
                .map(StorageShardRecord::public_record),
        )
    }
    fn constraint_root_for_plan(&self, plan_id: &str, family: &str) -> String {
        map_root(
            "PLAN-VERSION-CONSTRAINTS",
            self.version_constraints
                .values()
                .filter(|record| {
                    record.plan_id == plan_id
                        && match family {
                            "bytecode" => matches!(
                                record.kind,
                                ConstraintKind::BytecodeMin | ConstraintKind::BytecodeMax
                            ),
                            "circuit" => matches!(
                                record.kind,
                                ConstraintKind::CircuitMin | ConstraintKind::CircuitMax
                            ),
                            _ => true,
                        }
                })
                .map(VersionConstraintRecord::public_record),
        )
    }
    fn witness_rent_root_for_plan(&self, plan_id: &str) -> String {
        map_root(
            "PLAN-WITNESS-RENT",
            self.witness_rent_deposits
                .values()
                .filter(|record| record.plan_id == plan_id)
                .map(WitnessRentRecord::public_record),
        )
    }
    fn privacy_budget_root_for_plan(&self, plan_id: &str) -> String {
        map_root(
            "PLAN-PRIVACY-BUDGET",
            self.privacy_budgets
                .values()
                .filter(|record| record.plan_id == plan_id)
                .map(PrivacyBudgetRecord::public_record),
        )
    }
    fn pq_gate_root_for_plan(&self, plan_id: &str) -> String {
        map_root(
            "PLAN-PQ-GATES",
            self.pq_gates
                .values()
                .filter(|record| record.plan_id == plan_id)
                .map(PqAttestationGateRecord::public_record),
        )
    }
    fn dependency_root_for_plan(&self, plan_id: &str) -> String {
        map_root(
            "PLAN-DEFI-DEPENDENCIES",
            self.defi_dependencies
                .values()
                .filter(|record| record.plan_id == plan_id)
                .map(DefiDependencyRecord::public_record),
        )
    }
    fn readiness_root_for_plan(&self, plan_id: &str) -> String {
        map_root(
            "PLAN-READINESS",
            self.release_readiness
                .values()
                .filter(|record| record.plan_id == plan_id)
                .map(ReleaseReadinessRecord::public_record),
        )
    }
    fn prune_ready_queue(&mut self, selected: &[String]) {
        let selected_set = selected.iter().cloned().collect::<BTreeSet<_>>();
        let keys = self.ready_queue.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            if let Some(ids) = self.ready_queue.get_mut(&key) {
                ids.retain(|plan_id| !selected_set.contains(plan_id));
            }
            let remove = self
                .ready_queue
                .get(&key)
                .map(BTreeSet::is_empty)
                .is_some_and(|empty| empty);
            if remove {
                self.ready_queue.remove(&key);
            }
        }
    }
    fn consume_witness_rent(&mut self, plan_id: &str) {
        for deposit in self.witness_rent_deposits.values_mut() {
            if deposit.plan_id == plan_id {
                deposit.consumed = true;
            }
        }
    }
    fn expire_old_plans(&mut self) {
        let expired = self
            .migration_plans
            .iter()
            .filter(|(_, plan)| {
                !plan.status.terminal() && plan.expires_at_height < self.current_height
            })
            .map(|(plan_id, _)| plan_id.clone())
            .collect::<Vec<_>>();
        for plan_id in expired {
            if let Some(plan) = self.migration_plans.get_mut(&plan_id) {
                plan.status = PlanStatus::Expired;
            }
            self.emit_event(
                "plan_expired",
                &plan_id,
                &json!({ "height": self.current_height }),
            );
        }
    }
    fn emit_event(&mut self, event_kind: &str, subject_id: &str, record: &Value) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_root = root_from_record(
            "EVENT-PAYLOAD",
            &json!({
                "event_kind": event_kind,
                "subject_id": subject_id,
                "record": record,
                "height": self.current_height,
            }),
        );
        let event_id = format!("event-{:016}-{}", self.events.len(), short_id(&event_root));
        let event = SchedulerEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            event_root,
            emitted_at_height: self.current_height,
        };
        self.events.insert(event_id, event);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONTRACT-STATE-MIGRATION-SCHEDULER-{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-contract-state-migration-scheduler:state-root",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-pq-contract-state-migration-scheduler:{domain}"),
        &leaves,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("private-l2-pq-contract-state-migration-scheduler:{domain}:empty"),
        &[],
    )
}

fn validate_id(field: &str, value: &str) -> Result<()> {
    validate_nonempty(field, value)?;
    let valid = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '.'));
    if valid {
        Ok(())
    } else {
        Err(format!("{field} contains unsupported characters"))
    }
}

fn validate_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} is empty"))
    } else {
        Ok(())
    }
}

fn short_id(root: &str) -> String {
    root.chars().take(16).collect()
}
