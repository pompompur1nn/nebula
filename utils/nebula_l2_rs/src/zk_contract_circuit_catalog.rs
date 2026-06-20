use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkContractCircuitCatalogResult<T> = Result<T, String>;

pub const ZK_CONTRACT_CIRCUIT_CATALOG_PROTOCOL_VERSION: &str =
    "nebula-l2-zk-contract-circuit-catalog-v1";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_SCHEMA_VERSION: u64 = 1;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEVNET_HEIGHT: u64 = 2_208;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_SECURITY_MODEL: &str =
    "deterministic-devnet-circuit-catalog-not-real-crypto";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_VERIFIER_KEY_SCHEME: &str =
    "shake256-verifier-key-manifest-v1";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_RECURSION_SCHEME: &str =
    "pq-recursive-contract-proof-envelope-v1";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_LOW_FEE_SCHEME: &str =
    "low-fee-private-contract-batching-lane-v1";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_UPGRADE_RISK_SCHEME: &str =
    "private-zk-circuit-upgrade-risk-v1";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_NAMESPACE: &str = "nebula.devnet.zk_contracts";
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_RECURSION_DEPTH: u64 = 8;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_MAX_AGGREGATED_PROOFS: u64 = 512;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_FEE_TARGET_MICRO_XMR: u64 = 850;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_EMERGENCY_REVIEW_BLOCKS: u64 = 24;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_ROUTINE_REVIEW_BLOCKS: u64 = 720;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 20_160;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_MAX_BPS: u64 = 10_000;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_MAX_PROFILES: usize = 128;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_MAX_CIRCUITS: usize = 512;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_MAX_LANES: usize = 64;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_MAX_POLICIES: usize = 256;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_MAX_RISK_RECORDS: usize = 512;
pub const ZK_CONTRACT_CIRCUIT_CATALOG_MAX_TAGS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkContractCircuitFamily {
    PrivateToken,
    PrivateAmm,
    PrivateLending,
    PrivatePerps,
    PrivateBridge,
    PrivateStablecoin,
    PrivateVault,
    PrivateGovernance,
    PrivateOracle,
    PrivatePaymaster,
    Custom,
}

impl ZkContractCircuitFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateToken => "private_token",
            Self::PrivateAmm => "private_amm",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerps => "private_perps",
            Self::PrivateBridge => "private_bridge",
            Self::PrivateStablecoin => "private_stablecoin",
            Self::PrivateVault => "private_vault",
            Self::PrivateGovernance => "private_governance",
            Self::PrivateOracle => "private_oracle",
            Self::PrivatePaymaster => "private_paymaster",
            Self::Custom => "custom",
        }
    }

    pub fn defi_weight(self) -> u64 {
        match self {
            Self::PrivateAmm => 96,
            Self::PrivateLending => 94,
            Self::PrivatePerps => 98,
            Self::PrivateStablecoin => 92,
            Self::PrivateVault => 88,
            Self::PrivateBridge => 86,
            Self::PrivateToken => 72,
            Self::PrivateOracle => 70,
            Self::PrivatePaymaster => 62,
            Self::PrivateGovernance => 58,
            Self::Custom => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkContractActionKind {
    TokenMint,
    TokenBurn,
    TokenTransfer,
    TokenShield,
    TokenUnshield,
    AmmSwap,
    AmmAddLiquidity,
    AmmRemoveLiquidity,
    LendingDeposit,
    LendingBorrow,
    LendingRepay,
    LendingLiquidate,
    PerpsOpenPosition,
    PerpsClosePosition,
    PerpsFundingSettlement,
    BridgeDeposit,
    BridgeWithdraw,
    BridgeMessageVerify,
    OracleUpdate,
    GovernanceVote,
    Custom,
}

impl ZkContractActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::TokenTransfer => "token_transfer",
            Self::TokenShield => "token_shield",
            Self::TokenUnshield => "token_unshield",
            Self::AmmSwap => "amm_swap",
            Self::AmmAddLiquidity => "amm_add_liquidity",
            Self::AmmRemoveLiquidity => "amm_remove_liquidity",
            Self::LendingDeposit => "lending_deposit",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::LendingLiquidate => "lending_liquidate",
            Self::PerpsOpenPosition => "perps_open_position",
            Self::PerpsClosePosition => "perps_close_position",
            Self::PerpsFundingSettlement => "perps_funding_settlement",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdraw => "bridge_withdraw",
            Self::BridgeMessageVerify => "bridge_message_verify",
            Self::OracleUpdate => "oracle_update",
            Self::GovernanceVote => "governance_vote",
            Self::Custom => "custom",
        }
    }

    pub fn touches_value_flow(self) -> bool {
        !matches!(
            self,
            Self::OracleUpdate | Self::GovernanceVote | Self::Custom
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkVerifierBackend {
    PlonkishPq,
    StarkPq,
    FoldingNovaPq,
    Halo2Pq,
    HybridGroth16PqWrapper,
}

impl ZkVerifierBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlonkishPq => "plonkish_pq",
            Self::StarkPq => "stark_pq",
            Self::FoldingNovaPq => "folding_nova_pq",
            Self::Halo2Pq => "halo2_pq",
            Self::HybridGroth16PqWrapper => "hybrid_groth16_pq_wrapper",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkRecursionCompatibility {
    Native,
    Wrapped,
    AggregateOnly,
    LeafOnly,
    Disabled,
}

impl ZkRecursionCompatibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Wrapped => "wrapped",
            Self::AggregateOnly => "aggregate_only",
            Self::LeafOnly => "leaf_only",
            Self::Disabled => "disabled",
        }
    }

    pub fn accepts_recursion(self) -> bool {
        matches!(self, Self::Native | Self::Wrapped | Self::AggregateOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkCircuitStatus {
    Draft,
    Auditing,
    Active,
    Deprecated,
    Frozen,
    EmergencyDisabled,
}

impl ZkCircuitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Auditing => "auditing",
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Frozen => "frozen",
            Self::EmergencyDisabled => "emergency_disabled",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Auditing | Self::Active)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Deprecated | Self::EmergencyDisabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkBatchLaneKind {
    Token,
    Amm,
    Lending,
    Perps,
    Bridge,
    Oracle,
    Governance,
    Emergency,
}

impl ZkBatchLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Bridge => "bridge",
            Self::Oracle => "oracle",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::Bridge => 94,
            Self::Perps => 90,
            Self::Lending => 86,
            Self::Amm => 82,
            Self::Token => 74,
            Self::Oracle => 66,
            Self::Governance => 48,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkUpgradeRiskTier {
    Routine,
    ParameterOnly,
    VerifierKeyRotation,
    ConstraintChange,
    DefiInvariantChange,
    BridgeCritical,
    EmergencyPatch,
}

impl ZkUpgradeRiskTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::ParameterOnly => "parameter_only",
            Self::VerifierKeyRotation => "verifier_key_rotation",
            Self::ConstraintChange => "constraint_change",
            Self::DefiInvariantChange => "defi_invariant_change",
            Self::BridgeCritical => "bridge_critical",
            Self::EmergencyPatch => "emergency_patch",
        }
    }

    pub fn minimum_review_blocks(self) -> u64 {
        match self {
            Self::EmergencyPatch => ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_EMERGENCY_REVIEW_BLOCKS,
            Self::Routine | Self::ParameterOnly => {
                ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_ROUTINE_REVIEW_BLOCKS
            }
            Self::VerifierKeyRotation => 1_440,
            Self::ConstraintChange => 2_880,
            Self::DefiInvariantChange => 4_320,
            Self::BridgeCritical => 7_200,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerifierProfile {
    pub profile_id: String,
    pub backend: ZkVerifierBackend,
    pub pq_signature_suite: String,
    pub pq_kem_suite: String,
    pub transcript_hash_suite: String,
    pub verifier_key_root: String,
    pub verifier_key_epoch: u64,
    pub supports_batch_verify: bool,
    pub supports_recursive_verify: bool,
    pub max_proof_bytes: u64,
    pub max_public_inputs: u64,
    pub target_security_bits: u64,
}

impl ZkVerifierProfile {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "backend": self.backend.as_str(),
            "pq_signature_suite": self.pq_signature_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "transcript_hash_suite": self.transcript_hash_suite,
            "verifier_key_root": self.verifier_key_root,
            "verifier_key_epoch": self.verifier_key_epoch,
            "supports_batch_verify": self.supports_batch_verify,
            "supports_recursive_verify": self.supports_recursive_verify,
            "max_proof_bytes": self.max_proof_bytes,
            "max_public_inputs": self.max_public_inputs,
            "target_security_bits": self.target_security_bits,
        })
    }

    pub fn profile_root(&self) -> String {
        zk_catalog_hash("VERIFIER-PROFILE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        require_non_empty("verifier profile id", &self.profile_id)?;
        require_non_empty("pq signature suite", &self.pq_signature_suite)?;
        require_non_empty("pq kem suite", &self.pq_kem_suite)?;
        require_non_empty("transcript hash suite", &self.transcript_hash_suite)?;
        require_non_empty("verifier key root", &self.verifier_key_root)?;
        if self.max_proof_bytes == 0 || self.max_public_inputs == 0 {
            return Err(format!(
                "verifier profile {} must declare proof and public input limits",
                self.profile_id
            ));
        }
        if self.target_security_bits < 128 {
            return Err(format!(
                "verifier profile {} target security below 128 bits",
                self.profile_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProvingCostHint {
    pub constraint_count: u64,
    pub witness_bytes: u64,
    pub proving_time_ms_p50: u64,
    pub proving_time_ms_p95: u64,
    pub verifier_time_ms_p95: u64,
    pub memory_mb_p95: u64,
    pub gpu_recommended: bool,
    pub aggregation_discount_bps: u64,
    pub fee_weight_units: u64,
}

impl ZkProvingCostHint {
    pub fn public_record(&self) -> Value {
        json!({
            "constraint_count": self.constraint_count,
            "witness_bytes": self.witness_bytes,
            "proving_time_ms_p50": self.proving_time_ms_p50,
            "proving_time_ms_p95": self.proving_time_ms_p95,
            "verifier_time_ms_p95": self.verifier_time_ms_p95,
            "memory_mb_p95": self.memory_mb_p95,
            "gpu_recommended": self.gpu_recommended,
            "aggregation_discount_bps": self.aggregation_discount_bps,
            "fee_weight_units": self.fee_weight_units,
        })
    }

    pub fn cost_root(&self) -> String {
        zk_catalog_hash("PROVING-COST", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        if self.constraint_count == 0
            || self.witness_bytes == 0
            || self.proving_time_ms_p50 == 0
            || self.proving_time_ms_p95 == 0
            || self.verifier_time_ms_p95 == 0
            || self.memory_mb_p95 == 0
            || self.fee_weight_units == 0
        {
            return Err("proving cost hints must be positive".to_string());
        }
        if self.proving_time_ms_p95 < self.proving_time_ms_p50 {
            return Err("proving p95 cannot be below p50".to_string());
        }
        if self.aggregation_discount_bps > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_BPS {
            return Err("aggregation discount exceeds max bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkRecursionProfile {
    pub recursion_id: String,
    pub compatibility: ZkRecursionCompatibility,
    pub parent_profile_id: String,
    pub aggregation_circuit_id: String,
    pub max_depth: u64,
    pub max_leaf_proofs: u64,
    pub public_input_compression: String,
    pub recursive_verifier_key_root: String,
    pub preserves_privacy_budget: bool,
}

impl ZkRecursionProfile {
    pub fn public_record(&self) -> Value {
        json!({
            "recursion_id": self.recursion_id,
            "compatibility": self.compatibility.as_str(),
            "parent_profile_id": self.parent_profile_id,
            "aggregation_circuit_id": self.aggregation_circuit_id,
            "max_depth": self.max_depth,
            "max_leaf_proofs": self.max_leaf_proofs,
            "public_input_compression": self.public_input_compression,
            "recursive_verifier_key_root": self.recursive_verifier_key_root,
            "preserves_privacy_budget": self.preserves_privacy_budget,
        })
    }

    pub fn recursion_root(&self) -> String {
        zk_catalog_hash(
            "RECURSION-PROFILE",
            &[HashPart::Json(&self.public_record())],
        )
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        require_non_empty("recursion id", &self.recursion_id)?;
        require_non_empty("parent profile id", &self.parent_profile_id)?;
        require_non_empty("aggregation circuit id", &self.aggregation_circuit_id)?;
        require_non_empty("public input compression", &self.public_input_compression)?;
        require_non_empty(
            "recursive verifier key root",
            &self.recursive_verifier_key_root,
        )?;
        if self.compatibility.accepts_recursion()
            && (self.max_depth == 0 || self.max_leaf_proofs == 0)
        {
            return Err(format!(
                "recursion profile {} must declare positive depth and leaves",
                self.recursion_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkLowFeeBatchLane {
    pub lane_id: String,
    pub lane_kind: ZkBatchLaneKind,
    pub fee_asset_id: String,
    pub target_fee_micro_xmr: u64,
    pub max_fee_micro_xmr: u64,
    pub batch_window_blocks: u64,
    pub max_actions_per_batch: u64,
    pub max_batch_weight_units: u64,
    pub sponsor_pool_id: String,
    pub privacy_floor_anonymity_set: u64,
    pub enabled: bool,
}

impl ZkLowFeeBatchLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "priority": self.lane_kind.priority(),
            "fee_asset_id": self.fee_asset_id,
            "target_fee_micro_xmr": self.target_fee_micro_xmr,
            "max_fee_micro_xmr": self.max_fee_micro_xmr,
            "batch_window_blocks": self.batch_window_blocks,
            "max_actions_per_batch": self.max_actions_per_batch,
            "max_batch_weight_units": self.max_batch_weight_units,
            "sponsor_pool_id": self.sponsor_pool_id,
            "privacy_floor_anonymity_set": self.privacy_floor_anonymity_set,
            "enabled": self.enabled,
        })
    }

    pub fn lane_root(&self) -> String {
        zk_catalog_hash("LOW-FEE-LANE", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        require_non_empty("lane id", &self.lane_id)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_non_empty("sponsor pool id", &self.sponsor_pool_id)?;
        if self.target_fee_micro_xmr == 0
            || self.max_fee_micro_xmr == 0
            || self.batch_window_blocks == 0
            || self.max_actions_per_batch == 0
            || self.max_batch_weight_units == 0
            || self.privacy_floor_anonymity_set == 0
        {
            return Err(format!("low-fee lane {} has a zero limit", self.lane_id));
        }
        if self.target_fee_micro_xmr > self.max_fee_micro_xmr {
            return Err(format!(
                "low-fee lane {} target fee exceeds max fee",
                self.lane_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkCircuitUpgradeRisk {
    pub risk_id: String,
    pub circuit_id: String,
    pub risk_tier: ZkUpgradeRiskTier,
    pub reviewer_quorum: u64,
    pub min_audit_score_bps: u64,
    pub review_delay_blocks: u64,
    pub rollback_window_blocks: u64,
    pub allowed_emergency: bool,
    pub invariant_commitment_root: String,
    pub migration_notes_hash: String,
}

impl ZkCircuitUpgradeRisk {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_id": self.risk_id,
            "circuit_id": self.circuit_id,
            "risk_tier": self.risk_tier.as_str(),
            "reviewer_quorum": self.reviewer_quorum,
            "min_audit_score_bps": self.min_audit_score_bps,
            "review_delay_blocks": self.review_delay_blocks,
            "rollback_window_blocks": self.rollback_window_blocks,
            "allowed_emergency": self.allowed_emergency,
            "invariant_commitment_root": self.invariant_commitment_root,
            "migration_notes_hash": self.migration_notes_hash,
        })
    }

    pub fn risk_root(&self) -> String {
        zk_catalog_hash("UPGRADE-RISK", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        require_non_empty("risk id", &self.risk_id)?;
        require_non_empty("risk circuit id", &self.circuit_id)?;
        require_non_empty("invariant commitment root", &self.invariant_commitment_root)?;
        require_non_empty("migration notes hash", &self.migration_notes_hash)?;
        if self.reviewer_quorum == 0 || self.rollback_window_blocks == 0 {
            return Err(format!(
                "upgrade risk {} quorum/window must be positive",
                self.risk_id
            ));
        }
        if self.min_audit_score_bps > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_BPS {
            return Err(format!(
                "upgrade risk {} audit score exceeds max bps",
                self.risk_id
            ));
        }
        if self.review_delay_blocks < self.risk_tier.minimum_review_blocks() {
            return Err(format!(
                "upgrade risk {} review delay below tier minimum",
                self.risk_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkContractCircuit {
    pub circuit_id: String,
    pub family: ZkContractCircuitFamily,
    pub action_kind: ZkContractActionKind,
    pub status: ZkCircuitStatus,
    pub verifier_profile_id: String,
    pub recursion_profile_id: String,
    pub low_fee_lane_id: String,
    pub upgrade_risk_id: String,
    pub version: u64,
    pub activated_at_height: u64,
    pub deprecated_at_height: Option<u64>,
    pub contract_namespace: String,
    pub circuit_commitment_root: String,
    pub verifier_key_root: String,
    pub public_input_schema_root: String,
    pub witness_schema_root: String,
    pub privacy_budget_bps: u64,
    pub cost_hint: ZkProvingCostHint,
    pub tags: Vec<String>,
}

impl ZkContractCircuit {
    pub fn public_record(&self) -> Value {
        json!({
            "circuit_id": self.circuit_id,
            "family": self.family.as_str(),
            "family_defi_weight": self.family.defi_weight(),
            "action_kind": self.action_kind.as_str(),
            "touches_value_flow": self.action_kind.touches_value_flow(),
            "status": self.status.as_str(),
            "verifier_profile_id": self.verifier_profile_id,
            "recursion_profile_id": self.recursion_profile_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "upgrade_risk_id": self.upgrade_risk_id,
            "version": self.version,
            "activated_at_height": self.activated_at_height,
            "deprecated_at_height": self.deprecated_at_height,
            "contract_namespace": self.contract_namespace,
            "circuit_commitment_root": self.circuit_commitment_root,
            "verifier_key_root": self.verifier_key_root,
            "public_input_schema_root": self.public_input_schema_root,
            "witness_schema_root": self.witness_schema_root,
            "privacy_budget_bps": self.privacy_budget_bps,
            "cost_hint": self.cost_hint.public_record(),
            "tags": self.tags,
        })
    }

    pub fn circuit_root(&self) -> String {
        zk_catalog_hash("CIRCUIT", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        require_non_empty("circuit id", &self.circuit_id)?;
        require_non_empty("verifier profile id", &self.verifier_profile_id)?;
        require_non_empty("recursion profile id", &self.recursion_profile_id)?;
        require_non_empty("low fee lane id", &self.low_fee_lane_id)?;
        require_non_empty("upgrade risk id", &self.upgrade_risk_id)?;
        require_non_empty("contract namespace", &self.contract_namespace)?;
        require_non_empty("circuit commitment root", &self.circuit_commitment_root)?;
        require_non_empty("verifier key root", &self.verifier_key_root)?;
        require_non_empty("public input schema root", &self.public_input_schema_root)?;
        require_non_empty("witness schema root", &self.witness_schema_root)?;
        if self.version == 0 {
            return Err(format!(
                "circuit {} version must be positive",
                self.circuit_id
            ));
        }
        if self.privacy_budget_bps > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_BPS {
            return Err(format!(
                "circuit {} privacy budget exceeds max bps",
                self.circuit_id
            ));
        }
        if let Some(deprecated_at_height) = self.deprecated_at_height {
            if deprecated_at_height < self.activated_at_height {
                return Err(format!(
                    "circuit {} deprecates before activation",
                    self.circuit_id
                ));
            }
        }
        if self.tags.len() > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_TAGS {
            return Err(format!("circuit {} has too many tags", self.circuit_id));
        }
        let mut tags = BTreeSet::new();
        for tag in &self.tags {
            require_non_empty("circuit tag", tag)?;
            if !tags.insert(tag) {
                return Err(format!("circuit {} duplicate tag {}", self.circuit_id, tag));
            }
        }
        self.cost_hint.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkCircuitPolicy {
    pub policy_id: String,
    pub circuit_id: String,
    pub allowed_profile_ids: Vec<String>,
    pub required_lane_ids: Vec<String>,
    pub max_proof_age_blocks: u64,
    pub min_privacy_anonymity_set: u64,
    pub requires_pq_attestation: bool,
    pub requires_recursive_envelope: bool,
    pub allow_low_fee_sponsorship: bool,
}

impl ZkCircuitPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "circuit_id": self.circuit_id,
            "allowed_profile_ids": self.allowed_profile_ids,
            "required_lane_ids": self.required_lane_ids,
            "max_proof_age_blocks": self.max_proof_age_blocks,
            "min_privacy_anonymity_set": self.min_privacy_anonymity_set,
            "requires_pq_attestation": self.requires_pq_attestation,
            "requires_recursive_envelope": self.requires_recursive_envelope,
            "allow_low_fee_sponsorship": self.allow_low_fee_sponsorship,
        })
    }

    pub fn policy_root(&self) -> String {
        zk_catalog_hash("CIRCUIT-POLICY", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        require_non_empty("policy id", &self.policy_id)?;
        require_non_empty("policy circuit id", &self.circuit_id)?;
        if self.allowed_profile_ids.is_empty() || self.required_lane_ids.is_empty() {
            return Err(format!(
                "policy {} must bind at least one verifier profile and lane",
                self.policy_id
            ));
        }
        if self.max_proof_age_blocks == 0 || self.min_privacy_anonymity_set == 0 {
            return Err(format!(
                "policy {} has a zero proof/privacy limit",
                self.policy_id
            ));
        }
        require_unique_strings("policy allowed profile", &self.allowed_profile_ids)?;
        require_unique_strings("policy required lane", &self.required_lane_ids)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkContractCircuitCatalogConfig {
    pub namespace: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub verifier_key_scheme: String,
    pub recursion_scheme: String,
    pub low_fee_scheme: String,
    pub upgrade_risk_scheme: String,
    pub default_fee_asset_id: String,
    pub default_batch_window_blocks: u64,
    pub default_recursion_depth: u64,
    pub default_max_aggregated_proofs: u64,
    pub default_fee_target_micro_xmr: u64,
    pub audit_ttl_blocks: u64,
}

impl ZkContractCircuitCatalogConfig {
    pub fn devnet() -> Self {
        Self {
            namespace: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_NAMESPACE.to_string(),
            hash_suite: ZK_CONTRACT_CIRCUIT_CATALOG_HASH_SUITE.to_string(),
            pq_suite: ZK_CONTRACT_CIRCUIT_CATALOG_PQ_SUITE.to_string(),
            verifier_key_scheme: ZK_CONTRACT_CIRCUIT_CATALOG_VERIFIER_KEY_SCHEME.to_string(),
            recursion_scheme: ZK_CONTRACT_CIRCUIT_CATALOG_RECURSION_SCHEME.to_string(),
            low_fee_scheme: ZK_CONTRACT_CIRCUIT_CATALOG_LOW_FEE_SCHEME.to_string(),
            upgrade_risk_scheme: ZK_CONTRACT_CIRCUIT_CATALOG_UPGRADE_RISK_SCHEME.to_string(),
            default_fee_asset_id: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_FEE_ASSET_ID.to_string(),
            default_batch_window_blocks: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_BATCH_WINDOW_BLOCKS,
            default_recursion_depth: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_RECURSION_DEPTH,
            default_max_aggregated_proofs:
                ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_MAX_AGGREGATED_PROOFS,
            default_fee_target_micro_xmr: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_FEE_TARGET_MICRO_XMR,
            audit_ttl_blocks: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_AUDIT_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "namespace": self.namespace,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "verifier_key_scheme": self.verifier_key_scheme,
            "recursion_scheme": self.recursion_scheme,
            "low_fee_scheme": self.low_fee_scheme,
            "upgrade_risk_scheme": self.upgrade_risk_scheme,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_batch_window_blocks": self.default_batch_window_blocks,
            "default_recursion_depth": self.default_recursion_depth,
            "default_max_aggregated_proofs": self.default_max_aggregated_proofs,
            "default_fee_target_micro_xmr": self.default_fee_target_micro_xmr,
            "audit_ttl_blocks": self.audit_ttl_blocks,
        })
    }

    pub fn config_root(&self) -> String {
        zk_catalog_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        require_non_empty("namespace", &self.namespace)?;
        require_non_empty("hash suite", &self.hash_suite)?;
        require_non_empty("pq suite", &self.pq_suite)?;
        require_non_empty("verifier key scheme", &self.verifier_key_scheme)?;
        require_non_empty("recursion scheme", &self.recursion_scheme)?;
        require_non_empty("low fee scheme", &self.low_fee_scheme)?;
        require_non_empty("upgrade risk scheme", &self.upgrade_risk_scheme)?;
        require_non_empty("default fee asset id", &self.default_fee_asset_id)?;
        if self.default_batch_window_blocks == 0
            || self.default_recursion_depth == 0
            || self.default_max_aggregated_proofs == 0
            || self.default_fee_target_micro_xmr == 0
            || self.audit_ttl_blocks == 0
        {
            return Err("catalog config limits must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkContractCircuitCatalogCounters {
    pub verifier_profiles: usize,
    pub circuits: usize,
    pub active_circuits: usize,
    pub low_fee_lanes: usize,
    pub enabled_lanes: usize,
    pub recursion_profiles: usize,
    pub policies: usize,
    pub upgrade_risk_records: usize,
    pub total_fee_weight_units: u64,
    pub max_constraint_count: u64,
}

impl ZkContractCircuitCatalogCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "verifier_profiles": self.verifier_profiles,
            "circuits": self.circuits,
            "active_circuits": self.active_circuits,
            "low_fee_lanes": self.low_fee_lanes,
            "enabled_lanes": self.enabled_lanes,
            "recursion_profiles": self.recursion_profiles,
            "policies": self.policies,
            "upgrade_risk_records": self.upgrade_risk_records,
            "total_fee_weight_units": self.total_fee_weight_units,
            "max_constraint_count": self.max_constraint_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkContractCircuitCatalogRoots {
    pub config_root: String,
    pub verifier_profile_root: String,
    pub circuit_root: String,
    pub low_fee_lane_root: String,
    pub recursion_profile_root: String,
    pub policy_root: String,
    pub upgrade_risk_root: String,
    pub counters_root: String,
}

impl ZkContractCircuitCatalogRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "verifier_profile_root": self.verifier_profile_root,
            "circuit_root": self.circuit_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "recursion_profile_root": self.recursion_profile_root,
            "policy_root": self.policy_root,
            "upgrade_risk_root": self.upgrade_risk_root,
            "counters_root": self.counters_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkContractCircuitCatalogState {
    pub height: u64,
    pub config: ZkContractCircuitCatalogConfig,
    pub verifier_profiles: Vec<ZkVerifierProfile>,
    pub circuits: Vec<ZkContractCircuit>,
    pub low_fee_lanes: Vec<ZkLowFeeBatchLane>,
    pub recursion_profiles: Vec<ZkRecursionProfile>,
    pub policies: Vec<ZkCircuitPolicy>,
    pub upgrade_risks: Vec<ZkCircuitUpgradeRisk>,
}

impl ZkContractCircuitCatalogState {
    pub fn devnet() -> Self {
        let config = ZkContractCircuitCatalogConfig::devnet();
        let verifier_profiles = vec![
            verifier_profile(
                "pq-plonk-fast",
                ZkVerifierBackend::PlonkishPq,
                true,
                true,
                98_304,
                64,
                192,
            ),
            verifier_profile(
                "pq-stark-bulk",
                ZkVerifierBackend::StarkPq,
                true,
                true,
                196_608,
                96,
                192,
            ),
            verifier_profile(
                "pq-folding-recursive",
                ZkVerifierBackend::FoldingNovaPq,
                true,
                true,
                131_072,
                80,
                192,
            ),
            verifier_profile(
                "pq-halo2-compat",
                ZkVerifierBackend::Halo2Pq,
                true,
                true,
                114_688,
                72,
                160,
            ),
        ];
        let low_fee_lanes = vec![
            low_fee_lane(
                "token-low-fee",
                ZkBatchLaneKind::Token,
                600,
                1_500,
                512,
                2_000_000,
                64,
            ),
            low_fee_lane(
                "amm-netting",
                ZkBatchLaneKind::Amm,
                850,
                2_250,
                384,
                4_000_000,
                128,
            ),
            low_fee_lane(
                "lending-rollup",
                ZkBatchLaneKind::Lending,
                950,
                2_500,
                256,
                5_000_000,
                128,
            ),
            low_fee_lane(
                "perps-funding",
                ZkBatchLaneKind::Perps,
                1_200,
                3_000,
                256,
                7_500_000,
                96,
            ),
            low_fee_lane(
                "bridge-safety",
                ZkBatchLaneKind::Bridge,
                1_400,
                4_000,
                128,
                8_500_000,
                64,
            ),
            low_fee_lane(
                "oracle-compact",
                ZkBatchLaneKind::Oracle,
                500,
                1_250,
                512,
                1_500_000,
                32,
            ),
            low_fee_lane(
                "governance-private",
                ZkBatchLaneKind::Governance,
                450,
                1_100,
                256,
                1_250_000,
                32,
            ),
            low_fee_lane(
                "emergency-zk",
                ZkBatchLaneKind::Emergency,
                2_000,
                6_000,
                64,
                10_000_000,
                16,
            ),
        ];
        let recursion_profiles = vec![
            recursion_profile(
                "native-fast-recursion",
                ZkRecursionCompatibility::Native,
                "pq-folding-recursive",
                "recursive-contract-aggregate-v1",
                8,
                512,
            ),
            recursion_profile(
                "wrapped-plonk-recursion",
                ZkRecursionCompatibility::Wrapped,
                "pq-plonk-fast",
                "wrapped-plonk-contract-aggregate-v1",
                4,
                256,
            ),
            recursion_profile(
                "stark-bulk-recursion",
                ZkRecursionCompatibility::AggregateOnly,
                "pq-stark-bulk",
                "stark-contract-bulk-aggregate-v1",
                6,
                1_024,
            ),
        ];
        let upgrade_risks = vec![
            upgrade_risk(
                "risk-token-routine",
                "private-token-transfer-v1",
                ZkUpgradeRiskTier::Routine,
                2,
                8_600,
                720,
                false,
            ),
            upgrade_risk(
                "risk-amm-invariant",
                "private-amm-swap-v1",
                ZkUpgradeRiskTier::DefiInvariantChange,
                4,
                9_000,
                4_320,
                false,
            ),
            upgrade_risk(
                "risk-lending-invariant",
                "private-lending-borrow-v1",
                ZkUpgradeRiskTier::DefiInvariantChange,
                4,
                9_100,
                4_320,
                false,
            ),
            upgrade_risk(
                "risk-perps-constraint",
                "private-perps-open-v1",
                ZkUpgradeRiskTier::ConstraintChange,
                4,
                9_000,
                2_880,
                false,
            ),
            upgrade_risk(
                "risk-bridge-critical",
                "private-bridge-withdraw-v1",
                ZkUpgradeRiskTier::BridgeCritical,
                5,
                9_400,
                7_200,
                true,
            ),
            upgrade_risk(
                "risk-oracle-parameter",
                "private-oracle-update-v1",
                ZkUpgradeRiskTier::ParameterOnly,
                2,
                8_500,
                720,
                false,
            ),
            upgrade_risk(
                "risk-governance-routine",
                "private-governance-vote-v1",
                ZkUpgradeRiskTier::Routine,
                2,
                8_500,
                720,
                false,
            ),
        ];
        let circuits = vec![
            circuit(
                "private-token-transfer-v1",
                ZkContractCircuitFamily::PrivateToken,
                ZkContractActionKind::TokenTransfer,
                "pq-plonk-fast",
                "wrapped-plonk-recursion",
                "token-low-fee",
                "risk-token-routine",
                220_000,
                92_000,
                650,
                vec!["token", "transfer", "confidential_balance"],
            ),
            circuit(
                "private-token-mint-v1",
                ZkContractCircuitFamily::PrivateToken,
                ZkContractActionKind::TokenMint,
                "pq-plonk-fast",
                "wrapped-plonk-recursion",
                "token-low-fee",
                "risk-token-routine",
                260_000,
                110_000,
                700,
                vec!["token", "mint", "supply_commitment"],
            ),
            circuit(
                "private-token-burn-v1",
                ZkContractCircuitFamily::PrivateToken,
                ZkContractActionKind::TokenBurn,
                "pq-plonk-fast",
                "wrapped-plonk-recursion",
                "token-low-fee",
                "risk-token-routine",
                240_000,
                96_000,
                680,
                vec!["token", "burn", "supply_commitment"],
            ),
            circuit(
                "private-amm-swap-v1",
                ZkContractCircuitFamily::PrivateAmm,
                ZkContractActionKind::AmmSwap,
                "pq-folding-recursive",
                "native-fast-recursion",
                "amm-netting",
                "risk-amm-invariant",
                740_000,
                340_000,
                1_350,
                vec!["amm", "swap", "constant_product"],
            ),
            circuit(
                "private-amm-add-liquidity-v1",
                ZkContractCircuitFamily::PrivateAmm,
                ZkContractActionKind::AmmAddLiquidity,
                "pq-folding-recursive",
                "native-fast-recursion",
                "amm-netting",
                "risk-amm-invariant",
                690_000,
                310_000,
                1_250,
                vec!["amm", "liquidity", "pool_share"],
            ),
            circuit(
                "private-amm-remove-liquidity-v1",
                ZkContractCircuitFamily::PrivateAmm,
                ZkContractActionKind::AmmRemoveLiquidity,
                "pq-folding-recursive",
                "native-fast-recursion",
                "amm-netting",
                "risk-amm-invariant",
                710_000,
                320_000,
                1_280,
                vec!["amm", "liquidity", "pool_share"],
            ),
            circuit(
                "private-lending-deposit-v1",
                ZkContractCircuitFamily::PrivateLending,
                ZkContractActionKind::LendingDeposit,
                "pq-folding-recursive",
                "native-fast-recursion",
                "lending-rollup",
                "risk-lending-invariant",
                560_000,
                260_000,
                1_050,
                vec!["lending", "deposit", "collateral"],
            ),
            circuit(
                "private-lending-borrow-v1",
                ZkContractCircuitFamily::PrivateLending,
                ZkContractActionKind::LendingBorrow,
                "pq-folding-recursive",
                "native-fast-recursion",
                "lending-rollup",
                "risk-lending-invariant",
                880_000,
                420_000,
                1_700,
                vec!["lending", "borrow", "health_factor"],
            ),
            circuit(
                "private-lending-repay-v1",
                ZkContractCircuitFamily::PrivateLending,
                ZkContractActionKind::LendingRepay,
                "pq-folding-recursive",
                "native-fast-recursion",
                "lending-rollup",
                "risk-lending-invariant",
                620_000,
                280_000,
                1_150,
                vec!["lending", "repay", "health_factor"],
            ),
            circuit(
                "private-lending-liquidate-v1",
                ZkContractCircuitFamily::PrivateLending,
                ZkContractActionKind::LendingLiquidate,
                "pq-stark-bulk",
                "stark-bulk-recursion",
                "lending-rollup",
                "risk-lending-invariant",
                1_120_000,
                540_000,
                2_100,
                vec!["lending", "liquidation", "oracle_bound"],
            ),
            circuit(
                "private-perps-open-v1",
                ZkContractCircuitFamily::PrivatePerps,
                ZkContractActionKind::PerpsOpenPosition,
                "pq-stark-bulk",
                "stark-bulk-recursion",
                "perps-funding",
                "risk-perps-constraint",
                1_480_000,
                720_000,
                2_600,
                vec!["perps", "position", "margin"],
            ),
            circuit(
                "private-perps-close-v1",
                ZkContractCircuitFamily::PrivatePerps,
                ZkContractActionKind::PerpsClosePosition,
                "pq-stark-bulk",
                "stark-bulk-recursion",
                "perps-funding",
                "risk-perps-constraint",
                1_220_000,
                600_000,
                2_250,
                vec!["perps", "settlement", "pnl"],
            ),
            circuit(
                "private-perps-funding-v1",
                ZkContractCircuitFamily::PrivatePerps,
                ZkContractActionKind::PerpsFundingSettlement,
                "pq-stark-bulk",
                "stark-bulk-recursion",
                "perps-funding",
                "risk-perps-constraint",
                980_000,
                460_000,
                1_900,
                vec!["perps", "funding", "netting"],
            ),
            circuit(
                "private-bridge-deposit-v1",
                ZkContractCircuitFamily::PrivateBridge,
                ZkContractActionKind::BridgeDeposit,
                "pq-halo2-compat",
                "wrapped-plonk-recursion",
                "bridge-safety",
                "risk-bridge-critical",
                760_000,
                360_000,
                1_600,
                vec!["bridge", "deposit", "reserve"],
            ),
            circuit(
                "private-bridge-withdraw-v1",
                ZkContractCircuitFamily::PrivateBridge,
                ZkContractActionKind::BridgeWithdraw,
                "pq-halo2-compat",
                "wrapped-plonk-recursion",
                "bridge-safety",
                "risk-bridge-critical",
                1_020_000,
                520_000,
                2_050,
                vec!["bridge", "withdraw", "reserve"],
            ),
            circuit(
                "private-oracle-update-v1",
                ZkContractCircuitFamily::PrivateOracle,
                ZkContractActionKind::OracleUpdate,
                "pq-plonk-fast",
                "wrapped-plonk-recursion",
                "oracle-compact",
                "risk-oracle-parameter",
                180_000,
                72_000,
                480,
                vec!["oracle", "price", "attestation"],
            ),
            circuit(
                "private-governance-vote-v1",
                ZkContractCircuitFamily::PrivateGovernance,
                ZkContractActionKind::GovernanceVote,
                "pq-plonk-fast",
                "wrapped-plonk-recursion",
                "governance-private",
                "risk-governance-routine",
                320_000,
                130_000,
                800,
                vec!["governance", "vote", "nullifier"],
            ),
        ];
        let policies = circuits
            .iter()
            .map(|circuit| ZkCircuitPolicy {
                policy_id: format!("policy-{}", circuit.circuit_id),
                circuit_id: circuit.circuit_id.clone(),
                allowed_profile_ids: vec![circuit.verifier_profile_id.clone()],
                required_lane_ids: vec![circuit.low_fee_lane_id.clone()],
                max_proof_age_blocks: 32,
                min_privacy_anonymity_set: if circuit.action_kind.touches_value_flow() {
                    64
                } else {
                    16
                },
                requires_pq_attestation: true,
                requires_recursive_envelope: !matches!(
                    circuit.family,
                    ZkContractCircuitFamily::PrivateOracle
                        | ZkContractCircuitFamily::PrivateGovernance
                ),
                allow_low_fee_sponsorship: true,
            })
            .collect::<Vec<_>>();
        Self {
            height: ZK_CONTRACT_CIRCUIT_CATALOG_DEVNET_HEIGHT,
            config,
            verifier_profiles,
            circuits,
            low_fee_lanes,
            recursion_profiles,
            policies,
            upgrade_risks,
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn verifier_profile_root(&self) -> String {
        merkle_root(
            "ZK-CONTRACT-CATALOG-VERIFIER-PROFILES",
            &self
                .verifier_profiles
                .iter()
                .map(ZkVerifierProfile::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn circuit_root(&self) -> String {
        merkle_root(
            "ZK-CONTRACT-CATALOG-CIRCUITS",
            &self
                .circuits
                .iter()
                .map(ZkContractCircuit::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_lane_root(&self) -> String {
        merkle_root(
            "ZK-CONTRACT-CATALOG-LOW-FEE-LANES",
            &self
                .low_fee_lanes
                .iter()
                .map(ZkLowFeeBatchLane::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn recursion_profile_root(&self) -> String {
        merkle_root(
            "ZK-CONTRACT-CATALOG-RECURSION-PROFILES",
            &self
                .recursion_profiles
                .iter()
                .map(ZkRecursionProfile::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn policy_root(&self) -> String {
        merkle_root(
            "ZK-CONTRACT-CATALOG-POLICIES",
            &self
                .policies
                .iter()
                .map(ZkCircuitPolicy::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn upgrade_risk_root(&self) -> String {
        merkle_root(
            "ZK-CONTRACT-CATALOG-UPGRADE-RISKS",
            &self
                .upgrade_risks
                .iter()
                .map(ZkCircuitUpgradeRisk::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> ZkContractCircuitCatalogRoots {
        let counters_record = self.counters().public_record();
        ZkContractCircuitCatalogRoots {
            config_root: self.config.config_root(),
            verifier_profile_root: self.verifier_profile_root(),
            circuit_root: self.circuit_root(),
            low_fee_lane_root: self.low_fee_lane_root(),
            recursion_profile_root: self.recursion_profile_root(),
            policy_root: self.policy_root(),
            upgrade_risk_root: self.upgrade_risk_root(),
            counters_root: zk_catalog_hash("COUNTERS", &[HashPart::Json(&counters_record)]),
        }
    }

    pub fn counters(&self) -> ZkContractCircuitCatalogCounters {
        ZkContractCircuitCatalogCounters {
            verifier_profiles: self.verifier_profiles.len(),
            circuits: self.circuits.len(),
            active_circuits: self
                .circuits
                .iter()
                .filter(|circuit| circuit.status == ZkCircuitStatus::Active)
                .count(),
            low_fee_lanes: self.low_fee_lanes.len(),
            enabled_lanes: self
                .low_fee_lanes
                .iter()
                .filter(|lane| lane.enabled)
                .count(),
            recursion_profiles: self.recursion_profiles.len(),
            policies: self.policies.len(),
            upgrade_risk_records: self.upgrade_risks.len(),
            total_fee_weight_units: self
                .circuits
                .iter()
                .map(|circuit| circuit.cost_hint.fee_weight_units)
                .sum(),
            max_constraint_count: self
                .circuits
                .iter()
                .map(|circuit| circuit.cost_hint.constraint_count)
                .max()
                .unwrap_or_default(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": ZK_CONTRACT_CIRCUIT_CATALOG_PROTOCOL_VERSION,
            "schema_version": ZK_CONTRACT_CIRCUIT_CATALOG_SCHEMA_VERSION,
            "security_model": ZK_CONTRACT_CIRCUIT_CATALOG_SECURITY_MODEL,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        zk_catalog_hash(
            "STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.height as i128),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
        )
    }

    pub fn validate(&self) -> ZkContractCircuitCatalogResult<()> {
        self.config.validate()?;
        if self.verifier_profiles.len() > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_PROFILES {
            return Err("too many verifier profiles in zk circuit catalog".to_string());
        }
        if self.circuits.len() > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_CIRCUITS {
            return Err("too many circuits in zk circuit catalog".to_string());
        }
        if self.low_fee_lanes.len() > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_LANES {
            return Err("too many low-fee lanes in zk circuit catalog".to_string());
        }
        if self.policies.len() > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_POLICIES {
            return Err("too many policies in zk circuit catalog".to_string());
        }
        if self.upgrade_risks.len() > ZK_CONTRACT_CIRCUIT_CATALOG_MAX_RISK_RECORDS {
            return Err("too many upgrade risk records in zk circuit catalog".to_string());
        }

        let profile_ids = validate_unique_by(
            "verifier profile",
            self.verifier_profiles
                .iter()
                .map(|profile| &profile.profile_id),
        )?;
        for profile in &self.verifier_profiles {
            profile.validate()?;
        }

        let lane_ids = validate_unique_by(
            "low-fee lane",
            self.low_fee_lanes.iter().map(|lane| &lane.lane_id),
        )?;
        for lane in &self.low_fee_lanes {
            lane.validate()?;
        }

        let recursion_ids = validate_unique_by(
            "recursion profile",
            self.recursion_profiles
                .iter()
                .map(|profile| &profile.recursion_id),
        )?;
        for recursion in &self.recursion_profiles {
            recursion.validate()?;
            if !profile_ids.contains(&recursion.parent_profile_id) {
                return Err(format!(
                    "recursion profile {} references unknown verifier profile {}",
                    recursion.recursion_id, recursion.parent_profile_id
                ));
            }
        }

        let risk_ids = validate_unique_by(
            "upgrade risk",
            self.upgrade_risks.iter().map(|risk| &risk.risk_id),
        )?;
        for risk in &self.upgrade_risks {
            risk.validate()?;
        }

        let circuit_ids = validate_unique_by(
            "circuit",
            self.circuits.iter().map(|circuit| &circuit.circuit_id),
        )?;
        for circuit in &self.circuits {
            circuit.validate()?;
            if !profile_ids.contains(&circuit.verifier_profile_id) {
                return Err(format!(
                    "circuit {} references unknown verifier profile {}",
                    circuit.circuit_id, circuit.verifier_profile_id
                ));
            }
            if !recursion_ids.contains(&circuit.recursion_profile_id) {
                return Err(format!(
                    "circuit {} references unknown recursion profile {}",
                    circuit.circuit_id, circuit.recursion_profile_id
                ));
            }
            if !lane_ids.contains(&circuit.low_fee_lane_id) {
                return Err(format!(
                    "circuit {} references unknown low-fee lane {}",
                    circuit.circuit_id, circuit.low_fee_lane_id
                ));
            }
            if !risk_ids.contains(&circuit.upgrade_risk_id) {
                return Err(format!(
                    "circuit {} references unknown upgrade risk {}",
                    circuit.circuit_id, circuit.upgrade_risk_id
                ));
            }
        }

        let policy_ids = validate_unique_by(
            "policy",
            self.policies.iter().map(|policy| &policy.policy_id),
        )?;
        if policy_ids.len() != self.policies.len() {
            return Err("policy id set length mismatch".to_string());
        }
        for policy in &self.policies {
            policy.validate()?;
            if !circuit_ids.contains(&policy.circuit_id) {
                return Err(format!(
                    "policy {} references unknown circuit {}",
                    policy.policy_id, policy.circuit_id
                ));
            }
            for profile_id in &policy.allowed_profile_ids {
                if !profile_ids.contains(profile_id) {
                    return Err(format!(
                        "policy {} references unknown verifier profile {}",
                        policy.policy_id, profile_id
                    ));
                }
            }
            for lane_id in &policy.required_lane_ids {
                if !lane_ids.contains(lane_id) {
                    return Err(format!(
                        "policy {} references unknown low-fee lane {}",
                        policy.policy_id, lane_id
                    ));
                }
            }
        }

        let circuit_id_to_risk = self
            .upgrade_risks
            .iter()
            .map(|risk| (risk.circuit_id.as_str(), risk.risk_id.as_str()))
            .collect::<BTreeMap<_, _>>();
        for circuit in &self.circuits {
            if circuit_id_to_risk.get(circuit.circuit_id.as_str())
                != Some(&circuit.upgrade_risk_id.as_str())
            {
                return Err(format!(
                    "circuit {} upgrade risk does not bind back to circuit id",
                    circuit.circuit_id
                ));
            }
        }
        Ok(())
    }
}

pub fn devnet() -> ZkContractCircuitCatalogState {
    ZkContractCircuitCatalogState::devnet()
}

pub fn zk_catalog_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("ZK-CONTRACT-CIRCUIT-CATALOG-{domain}"), parts, 32)
}

pub fn circuit_commitment(label: &str, version: u64) -> String {
    zk_catalog_hash(
        "CIRCUIT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(version as i128),
        ],
    )
}

pub fn schema_commitment(label: &str, schema_kind: &str) -> String {
    zk_catalog_hash(
        "SCHEMA-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(schema_kind),
        ],
    )
}

fn verifier_profile(
    profile_id: &str,
    backend: ZkVerifierBackend,
    supports_batch_verify: bool,
    supports_recursive_verify: bool,
    max_proof_bytes: u64,
    max_public_inputs: u64,
    target_security_bits: u64,
) -> ZkVerifierProfile {
    ZkVerifierProfile {
        profile_id: profile_id.to_string(),
        backend,
        pq_signature_suite: "ML-DSA-65+SLH-DSA-SHAKE-128s".to_string(),
        pq_kem_suite: "ML-KEM-768".to_string(),
        transcript_hash_suite: ZK_CONTRACT_CIRCUIT_CATALOG_HASH_SUITE.to_string(),
        verifier_key_root: circuit_commitment(profile_id, 1),
        verifier_key_epoch: 1,
        supports_batch_verify,
        supports_recursive_verify,
        max_proof_bytes,
        max_public_inputs,
        target_security_bits,
    }
}

fn low_fee_lane(
    lane_id: &str,
    lane_kind: ZkBatchLaneKind,
    target_fee_micro_xmr: u64,
    max_fee_micro_xmr: u64,
    max_actions_per_batch: u64,
    max_batch_weight_units: u64,
    privacy_floor_anonymity_set: u64,
) -> ZkLowFeeBatchLane {
    ZkLowFeeBatchLane {
        lane_id: lane_id.to_string(),
        lane_kind,
        fee_asset_id: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_FEE_ASSET_ID.to_string(),
        target_fee_micro_xmr,
        max_fee_micro_xmr,
        batch_window_blocks: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_BATCH_WINDOW_BLOCKS,
        max_actions_per_batch,
        max_batch_weight_units,
        sponsor_pool_id: format!("{lane_id}-sponsor-pool"),
        privacy_floor_anonymity_set,
        enabled: true,
    }
}

fn recursion_profile(
    recursion_id: &str,
    compatibility: ZkRecursionCompatibility,
    parent_profile_id: &str,
    aggregation_circuit_id: &str,
    max_depth: u64,
    max_leaf_proofs: u64,
) -> ZkRecursionProfile {
    ZkRecursionProfile {
        recursion_id: recursion_id.to_string(),
        compatibility,
        parent_profile_id: parent_profile_id.to_string(),
        aggregation_circuit_id: aggregation_circuit_id.to_string(),
        max_depth,
        max_leaf_proofs,
        public_input_compression: "poseidon-compatible-shake256-sponge-v1".to_string(),
        recursive_verifier_key_root: circuit_commitment(aggregation_circuit_id, 1),
        preserves_privacy_budget: true,
    }
}

fn upgrade_risk(
    risk_id: &str,
    circuit_id: &str,
    risk_tier: ZkUpgradeRiskTier,
    reviewer_quorum: u64,
    min_audit_score_bps: u64,
    review_delay_blocks: u64,
    allowed_emergency: bool,
) -> ZkCircuitUpgradeRisk {
    ZkCircuitUpgradeRisk {
        risk_id: risk_id.to_string(),
        circuit_id: circuit_id.to_string(),
        risk_tier,
        reviewer_quorum,
        min_audit_score_bps,
        review_delay_blocks,
        rollback_window_blocks: review_delay_blocks.saturating_mul(2).max(1_440),
        allowed_emergency,
        invariant_commitment_root: schema_commitment(circuit_id, "defi-invariant"),
        migration_notes_hash: zk_catalog_hash(
            "MIGRATION-NOTES",
            &[HashPart::Str(circuit_id), HashPart::Str(risk_tier.as_str())],
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn circuit(
    circuit_id: &str,
    family: ZkContractCircuitFamily,
    action_kind: ZkContractActionKind,
    verifier_profile_id: &str,
    recursion_profile_id: &str,
    low_fee_lane_id: &str,
    upgrade_risk_id: &str,
    constraint_count: u64,
    witness_bytes: u64,
    fee_weight_units: u64,
    tags: Vec<&str>,
) -> ZkContractCircuit {
    ZkContractCircuit {
        circuit_id: circuit_id.to_string(),
        family,
        action_kind,
        status: ZkCircuitStatus::Active,
        verifier_profile_id: verifier_profile_id.to_string(),
        recursion_profile_id: recursion_profile_id.to_string(),
        low_fee_lane_id: low_fee_lane_id.to_string(),
        upgrade_risk_id: upgrade_risk_id.to_string(),
        version: 1,
        activated_at_height: ZK_CONTRACT_CIRCUIT_CATALOG_DEVNET_HEIGHT,
        deprecated_at_height: None,
        contract_namespace: ZK_CONTRACT_CIRCUIT_CATALOG_DEFAULT_NAMESPACE.to_string(),
        circuit_commitment_root: circuit_commitment(circuit_id, 1),
        verifier_key_root: circuit_commitment(&format!("{circuit_id}-vk"), 1),
        public_input_schema_root: schema_commitment(circuit_id, "public-input"),
        witness_schema_root: schema_commitment(circuit_id, "witness"),
        privacy_budget_bps: if action_kind.touches_value_flow() {
            250
        } else {
            100
        },
        cost_hint: ZkProvingCostHint {
            constraint_count,
            witness_bytes,
            proving_time_ms_p50: constraint_count / 550 + 100,
            proving_time_ms_p95: constraint_count / 375 + 250,
            verifier_time_ms_p95: constraint_count / 25_000 + 12,
            memory_mb_p95: witness_bytes / 1_024 / 4 + 256,
            gpu_recommended: constraint_count >= 700_000,
            aggregation_discount_bps: 6_500,
            fee_weight_units,
        },
        tags: tags.into_iter().map(str::to_string).collect(),
    }
}

fn require_non_empty(label: &str, value: &str) -> ZkContractCircuitCatalogResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be populated"));
    }
    Ok(())
}

fn require_unique_strings(label: &str, values: &[String]) -> ZkContractCircuitCatalogResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value) {
            return Err(format!("duplicate {label}: {value}"));
        }
    }
    Ok(())
}

fn validate_unique_by<'a, I>(
    label: &str,
    values: I,
) -> ZkContractCircuitCatalogResult<BTreeSet<String>>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("duplicate {label}: {value}"));
        }
    }
    Ok(seen)
}
