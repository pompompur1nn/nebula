use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedCollateralRehypothecationGuardRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenizedCollateralRehypothecationGuardRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_COLLATERAL_REHYPOTHECATION_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-collateral-rehypothecation-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_COLLATERAL_REHYPOTHECATION_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_GUARD_ID: &str =
    "private-l2-pq-confidential-tokenized-collateral-rehypothecation-guard-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-collateral-guard-v1";
pub const LIEN_COMMITMENT_SCHEME: &str =
    "confidential-tokenized-collateral-lien-commitment-root-v1";
pub const VAULT_COMMITMENT_SCHEME: &str =
    "private-l2-confidential-collateral-vault-commitment-root-v1";
pub const ORACLE_ATTESTATION_SCHEME: &str = "pq-confidential-collateral-oracle-attestation-root-v1";
pub const LIQUIDATION_LOCK_SCHEME: &str = "private-l2-liquidation-lock-nullifier-root-v1";
pub const LOW_FEE_MONITORING_SCHEME: &str = "low-fee-collateral-guard-monitoring-root-v1";
pub const PRIVACY_REDACTION_SCHEME: &str = "privacy-redaction-budget-commitment-root-v1";
pub const POLICY_BREACH_SCHEME: &str = "rehypothecation-policy-breach-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_640_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_REUSE_BPS: u64 = 3_500;
pub const DEFAULT_WARNING_REUSE_BPS: u64 = 2_750;
pub const DEFAULT_MIN_HEALTH_FACTOR_BPS: u64 = 12_500;
pub const DEFAULT_LIQUIDATION_HEALTH_FACTOR_BPS: u64 = 10_500;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_LIEN_TTL_BLOCKS: u64 = 14_400;
pub const DEFAULT_LIQUIDATION_LOCK_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 43_200;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const DEFAULT_LOW_FEE_ALERT_BPS: u64 = 18;
pub const DEFAULT_MAX_VAULTS: usize = 1_048_576;
pub const DEFAULT_MAX_POSITIONS: usize = 4_194_304;
pub const DEFAULT_MAX_LIENS: usize = 8_388_608;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_LIQUIDATION_LOCKS: usize = 2_097_152;
pub const DEFAULT_MAX_POLICY_BREACHES: usize = 2_097_152;
pub const DEFAULT_MAX_FEE_SAMPLES: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralKind {
    WrappedMonero,
    ConfidentialStable,
    PrivateLpShare,
    TokenizedVaultShare,
    RealWorldAssetNote,
    SyntheticPerpMargin,
    GovernanceEscrow,
    InsuranceBackstop,
}

impl CollateralKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedMonero => "wrapped_monero",
            Self::ConfidentialStable => "confidential_stable",
            Self::PrivateLpShare => "private_lp_share",
            Self::TokenizedVaultShare => "tokenized_vault_share",
            Self::RealWorldAssetNote => "real_world_asset_note",
            Self::SyntheticPerpMargin => "synthetic_perp_margin",
            Self::GovernanceEscrow => "governance_escrow",
            Self::InsuranceBackstop => "insurance_backstop",
        }
    }

    pub fn default_haircut_bps(self) -> u64 {
        match self {
            Self::WrappedMonero => 1_500,
            Self::ConfidentialStable => 500,
            Self::PrivateLpShare => 2_500,
            Self::TokenizedVaultShare => 2_000,
            Self::RealWorldAssetNote => 3_000,
            Self::SyntheticPerpMargin => 3_500,
            Self::GovernanceEscrow => 4_000,
            Self::InsuranceBackstop => 2_250,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    Watchlisted,
    Throttled,
    LiquidationOnly,
    Frozen,
    Closed,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Watchlisted => "watchlisted",
            Self::Throttled => "throttled",
            Self::LiquidationOnly => "liquidation_only",
            Self::Frozen => "frozen",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_reuse(self) -> bool {
        matches!(self, Self::Open | Self::Watchlisted | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Active,
    Rebalanced,
    Matured,
    Locked,
    Liquidating,
    Settled,
    Defaulted,
}

impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rebalanced => "rebalanced",
            Self::Matured => "matured",
            Self::Locked => "locked",
            Self::Liquidating => "liquidating",
            Self::Settled => "settled",
            Self::Defaulted => "defaulted",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Rebalanced | Self::Locked | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LienStatus {
    Proposed,
    Committed,
    Encumbered,
    Released,
    Disputed,
    Slashed,
    Expired,
}

impl LienStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Committed => "committed",
            Self::Encumbered => "encumbered",
            Self::Released => "released",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Proposed | Self::Committed | Self::Encumbered)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    OraclePrice,
    ReserveCoverage,
    LienUniqueness,
    VaultSolvency,
    RedactionBudget,
    LowFeeSample,
    LiquidationAuthorization,
    PolicyOverride,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OraclePrice => "oracle_price",
            Self::ReserveCoverage => "reserve_coverage",
            Self::LienUniqueness => "lien_uniqueness",
            Self::VaultSolvency => "vault_solvency",
            Self::RedactionBudget => "redaction_budget",
            Self::LowFeeSample => "low_fee_sample",
            Self::LiquidationAuthorization => "liquidation_authorization",
            Self::PolicyOverride => "policy_override",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachKind {
    ReuseLimitExceeded,
    StaleOracle,
    MissingPqAttestation,
    DuplicateLienNullifier,
    LiquidationLockViolation,
    HealthFactorBelowMinimum,
    LowFeeBudgetExceeded,
    RedactionBudgetExceeded,
    UnauthorizedCollateralKind,
    PrivacySetTooSmall,
}

impl BreachKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReuseLimitExceeded => "reuse_limit_exceeded",
            Self::StaleOracle => "stale_oracle",
            Self::MissingPqAttestation => "missing_pq_attestation",
            Self::DuplicateLienNullifier => "duplicate_lien_nullifier",
            Self::LiquidationLockViolation => "liquidation_lock_violation",
            Self::HealthFactorBelowMinimum => "health_factor_below_minimum",
            Self::LowFeeBudgetExceeded => "low_fee_budget_exceeded",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::UnauthorizedCollateralKind => "unauthorized_collateral_kind",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
        }
    }

    pub fn severity(self) -> u8 {
        match self {
            Self::DuplicateLienNullifier | Self::LiquidationLockViolation => 5,
            Self::ReuseLimitExceeded | Self::HealthFactorBelowMinimum => 4,
            Self::MissingPqAttestation | Self::UnauthorizedCollateralKind => 3,
            Self::StaleOracle | Self::RedactionBudgetExceeded => 2,
            Self::LowFeeBudgetExceeded | Self::PrivacySetTooSmall => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStatus {
    Requested,
    Active,
    Executing,
    Released,
    Expired,
    Cancelled,
}

impl LockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::Executing => "executing",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn blocks_reuse(self) -> bool {
        matches!(self, Self::Requested | Self::Active | Self::Executing)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub guard_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub lien_commitment_scheme: String,
    pub vault_commitment_scheme: String,
    pub oracle_attestation_scheme: String,
    pub liquidation_lock_scheme: String,
    pub low_fee_monitoring_scheme: String,
    pub privacy_redaction_scheme: String,
    pub policy_breach_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub default_max_reuse_bps: u64,
    pub warning_reuse_bps: u64,
    pub min_health_factor_bps: u64,
    pub liquidation_health_factor_bps: u64,
    pub oracle_ttl_blocks: u64,
    pub lien_ttl_blocks: u64,
    pub liquidation_lock_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub low_fee_target_bps: u64,
    pub low_fee_alert_bps: u64,
    pub max_vaults: usize,
    pub max_positions: usize,
    pub max_liens: usize,
    pub max_oracle_attestations: usize,
    pub max_liquidation_locks: usize,
    pub max_policy_breaches: usize,
    pub max_fee_samples: usize,
    pub max_redaction_budgets: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            guard_id: DEVNET_GUARD_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            lien_commitment_scheme: LIEN_COMMITMENT_SCHEME.to_string(),
            vault_commitment_scheme: VAULT_COMMITMENT_SCHEME.to_string(),
            oracle_attestation_scheme: ORACLE_ATTESTATION_SCHEME.to_string(),
            liquidation_lock_scheme: LIQUIDATION_LOCK_SCHEME.to_string(),
            low_fee_monitoring_scheme: LOW_FEE_MONITORING_SCHEME.to_string(),
            privacy_redaction_scheme: PRIVACY_REDACTION_SCHEME.to_string(),
            policy_breach_scheme: POLICY_BREACH_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            default_max_reuse_bps: DEFAULT_MAX_REUSE_BPS,
            warning_reuse_bps: DEFAULT_WARNING_REUSE_BPS,
            min_health_factor_bps: DEFAULT_MIN_HEALTH_FACTOR_BPS,
            liquidation_health_factor_bps: DEFAULT_LIQUIDATION_HEALTH_FACTOR_BPS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            lien_ttl_blocks: DEFAULT_LIEN_TTL_BLOCKS,
            liquidation_lock_ttl_blocks: DEFAULT_LIQUIDATION_LOCK_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            low_fee_alert_bps: DEFAULT_LOW_FEE_ALERT_BPS,
            max_vaults: DEFAULT_MAX_VAULTS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_liens: DEFAULT_MAX_LIENS,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_liquidation_locks: DEFAULT_MAX_LIQUIDATION_LOCKS,
            max_policy_breaches: DEFAULT_MAX_POLICY_BREACHES,
            max_fee_samples: DEFAULT_MAX_FEE_SAMPLES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("guard_id", &self.guard_id)?;
        require_bps("default_max_reuse_bps", self.default_max_reuse_bps)?;
        require_bps("warning_reuse_bps", self.warning_reuse_bps)?;
        require_bps("min_health_factor_bps", self.min_health_factor_bps)?;
        require_bps(
            "liquidation_health_factor_bps",
            self.liquidation_health_factor_bps,
        )?;
        require_bps("low_fee_target_bps", self.low_fee_target_bps)?;
        require_bps("low_fee_alert_bps", self.low_fee_alert_bps)?;
        require_positive_u64("oracle_ttl_blocks", self.oracle_ttl_blocks)?;
        require_positive_u64("lien_ttl_blocks", self.lien_ttl_blocks)?;
        require_positive_u64(
            "liquidation_lock_ttl_blocks",
            self.liquidation_lock_ttl_blocks,
        )?;
        require_positive_u64("redaction_epoch_blocks", self.redaction_epoch_blocks)?;
        require_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive_u64("target_privacy_set_size", self.target_privacy_set_size)?;
        require_positive_usize("max_vaults", self.max_vaults)?;
        require_positive_usize("max_positions", self.max_positions)?;
        require_positive_usize("max_liens", self.max_liens)?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below supported PQ floor".to_string());
        }
        if self.warning_reuse_bps > self.default_max_reuse_bps {
            return Err("warning reuse bps cannot exceed max reuse bps".to_string());
        }
        if self.liquidation_health_factor_bps > self.min_health_factor_bps {
            return Err(
                "liquidation health factor cannot exceed minimum health factor".to_string(),
            );
        }
        if self.low_fee_target_bps > self.low_fee_alert_bps {
            return Err("low fee target cannot exceed alert threshold".to_string());
        }
        if self.min_privacy_set_size > self.target_privacy_set_size {
            return Err("minimum privacy set cannot exceed target privacy set".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub positions: u64,
    pub liens: u64,
    pub active_liens: u64,
    pub oracle_attestations: u64,
    pub liquidation_locks: u64,
    pub active_liquidation_locks: u64,
    pub policy_breaches: u64,
    pub critical_breaches: u64,
    pub fee_samples: u64,
    pub low_fee_alerts: u64,
    pub redaction_budgets: u64,
    pub exhausted_redaction_budgets: u64,
    pub unique_lien_nullifiers: u64,
    pub unique_reuse_nullifiers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub vaults_root: String,
    pub positions_root: String,
    pub liens_root: String,
    pub oracle_attestations_root: String,
    pub liquidation_locks_root: String,
    pub policy_breaches_root: String,
    pub fee_samples_root: String,
    pub redaction_budgets_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralVault {
    pub vault_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub collateral_kind: CollateralKind,
    pub status: VaultStatus,
    pub collateral_commitment_root: String,
    pub amount_commitment: String,
    pub valuation_commitment: String,
    pub oracle_attestation_id: String,
    pub max_reuse_bps: u64,
    pub current_reuse_bps: u64,
    pub health_factor_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub allowed_markets: BTreeSet<String>,
    pub policy_tags: BTreeSet<String>,
}

impl CollateralVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "asset_id": self.asset_id,
            "collateral_kind": self.collateral_kind.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "collateral_commitment_root": self.collateral_commitment_root,
            "amount_commitment": self.amount_commitment,
            "valuation_commitment": self.valuation_commitment,
            "oracle_attestation_id": self.oracle_attestation_id,
            "max_reuse_bps": self.max_reuse_bps,
            "current_reuse_bps": self.current_reuse_bps,
            "health_factor_bps": self.health_factor_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "allowed_markets": self.allowed_markets,
            "policy_tags": self.policy_tags,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn reuse_headroom_bps(&self) -> u64 {
        self.max_reuse_bps.saturating_sub(self.current_reuse_bps)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RehypothecationPosition {
    pub position_id: String,
    pub vault_id: String,
    pub market_id: String,
    pub borrower_commitment: String,
    pub token_contract_commitment: String,
    pub status: PositionStatus,
    pub notional_commitment: String,
    pub debt_commitment: String,
    pub reuse_bps: u64,
    pub health_factor_bps: u64,
    pub lien_ids: BTreeSet<String>,
    pub liquidation_lock_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl RehypothecationPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "vault_id": self.vault_id,
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "token_contract_commitment": self.token_contract_commitment,
            "status": self.status.as_str(),
            "notional_commitment": self.notional_commitment,
            "debt_commitment": self.debt_commitment,
            "reuse_bps": self.reuse_bps,
            "health_factor_bps": self.health_factor_bps,
            "lien_ids": self.lien_ids,
            "liquidation_lock_id": self.liquidation_lock_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LienCommitment {
    pub lien_id: String,
    pub vault_id: String,
    pub position_id: String,
    pub priority: u32,
    pub lien_nullifier: String,
    pub reuse_nullifier: String,
    pub commitment_root: String,
    pub creditor_commitment: String,
    pub encumbered_value_commitment: String,
    pub status: LienStatus,
    pub privacy_set_size: u64,
    pub pq_attestation_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LienCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "lien_id": self.lien_id,
            "vault_id": self.vault_id,
            "position_id": self.position_id,
            "priority": self.priority,
            "lien_nullifier": self.lien_nullifier,
            "reuse_nullifier": self.reuse_nullifier,
            "commitment_root": self.commitment_root,
            "creditor_commitment": self.creditor_commitment,
            "encumbered_value_commitment": self.encumbered_value_commitment,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_attestation_id": self.pq_attestation_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OraclePqAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub oracle_committee_root: String,
    pub payload_commitment_root: String,
    pub pq_signature_root: String,
    pub aggregate_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl OraclePqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "oracle_committee_root": self.oracle_committee_root,
            "payload_commitment_root": self.payload_commitment_root,
            "pq_signature_root": self.pq_signature_root,
            "aggregate_weight_bps": self.aggregate_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn fresh_at(&self, height: u64) -> bool {
        self.observed_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationLock {
    pub lock_id: String,
    pub vault_id: String,
    pub position_id: String,
    pub liquidator_commitment: String,
    pub authorization_root: String,
    pub lock_nullifier: String,
    pub status: LockStatus,
    pub reason: BreachKind,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidationLock {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "vault_id": self.vault_id,
            "position_id": self.position_id,
            "liquidator_commitment": self.liquidator_commitment,
            "authorization_root": self.authorization_root,
            "lock_nullifier": self.lock_nullifier,
            "status": self.status.as_str(),
            "reason": self.reason.as_str(),
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyBreach {
    pub breach_id: String,
    pub kind: BreachKind,
    pub subject_id: String,
    pub evidence_root: String,
    pub remediation_root: String,
    pub severity: u8,
    pub detected_at_height: u64,
    pub cleared_at_height: Option<u64>,
}

impl PolicyBreach {
    pub fn public_record(&self) -> Value {
        json!({
            "breach_id": self.breach_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "remediation_root": self.remediation_root,
            "severity": self.severity,
            "detected_at_height": self.detected_at_height,
            "cleared_at_height": self.cleared_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSample {
    pub sample_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub median_fee_bps: u64,
    pub p95_fee_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub batch_size: u64,
    pub observed_at_height: u64,
    pub attestation_id: String,
}

impl LowFeeSample {
    pub fn public_record(&self) -> Value {
        json!({
            "sample_id": self.sample_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "median_fee_bps": self.median_fee_bps,
            "p95_fee_bps": self.p95_fee_bps,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "batch_size": self.batch_size,
            "observed_at_height": self.observed_at_height,
            "attestation_id": self.attestation_id,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_commitment: String,
    pub epoch: u64,
    pub max_redactions: u64,
    pub used_redactions: u64,
    pub privacy_set_size: u64,
    pub policy_root: String,
    pub audit_commitment_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_commitment": self.subject_commitment,
            "epoch": self.epoch,
            "max_redactions": self.max_redactions,
            "used_redactions": self.used_redactions,
            "privacy_set_size": self.privacy_set_size,
            "policy_root": self.policy_root,
            "audit_commitment_root": self.audit_commitment_root,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn remaining(&self) -> u64 {
        self.max_redactions.saturating_sub(self.used_redactions)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub vaults: BTreeMap<String, CollateralVault>,
    pub positions: BTreeMap<String, RehypothecationPosition>,
    pub liens: BTreeMap<String, LienCommitment>,
    pub oracle_attestations: BTreeMap<String, OraclePqAttestation>,
    pub liquidation_locks: BTreeMap<String, LiquidationLock>,
    pub policy_breaches: BTreeMap<String, PolicyBreach>,
    pub fee_samples: BTreeMap<String, LowFeeSample>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub used_lien_nullifiers: BTreeSet<String>,
    pub used_reuse_nullifiers: BTreeSet<String>,
    pub paused_markets: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT)
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            current_height,
            vaults: BTreeMap::new(),
            positions: BTreeMap::new(),
            liens: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            liquidation_locks: BTreeMap::new(),
            policy_breaches: BTreeMap::new(),
            fee_samples: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            used_lien_nullifiers: BTreeSet::new(),
            used_reuse_nullifiers: BTreeSet::new(),
            paused_markets: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default(), DEVNET_HEIGHT);
        state.install_devnet_samples();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let breach = PolicyBreach {
            breach_id: stable_id("breach", "demo-reuse-warning"),
            kind: BreachKind::ReuseLimitExceeded,
            subject_id: "vault-wxmr-alpha".to_string(),
            evidence_root: deterministic_root("evidence", "demo-reuse-warning"),
            remediation_root: deterministic_root("remediation", "rebalance-alpha-vault"),
            severity: BreachKind::ReuseLimitExceeded.severity(),
            detected_at_height: state.current_height + 3,
            cleared_at_height: None,
        };
        let _ = state.record_policy_breach(breach);
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            vaults: self.vaults.len() as u64,
            positions: self.positions.len() as u64,
            liens: self.liens.len() as u64,
            active_liens: self
                .liens
                .values()
                .filter(|lien| lien.status.active())
                .count() as u64,
            oracle_attestations: self.oracle_attestations.len() as u64,
            liquidation_locks: self.liquidation_locks.len() as u64,
            active_liquidation_locks: self
                .liquidation_locks
                .values()
                .filter(|lock| lock.status.blocks_reuse())
                .count() as u64,
            policy_breaches: self.policy_breaches.len() as u64,
            critical_breaches: self
                .policy_breaches
                .values()
                .filter(|breach| breach.severity >= 4 && breach.cleared_at_height.is_none())
                .count() as u64,
            fee_samples: self.fee_samples.len() as u64,
            low_fee_alerts: self
                .fee_samples
                .values()
                .filter(|sample| sample.p95_fee_bps > self.config.low_fee_alert_bps)
                .count() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            exhausted_redaction_budgets: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.remaining() == 0)
                .count() as u64,
            unique_lien_nullifiers: self.used_lien_nullifiers.len() as u64,
            unique_reuse_nullifiers: self.used_reuse_nullifiers.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.state_root();
        let counters_root = self.counters().state_root();
        let vaults_root = collection_root(
            "vaults",
            self.vaults
                .values()
                .map(CollateralVault::state_root)
                .collect(),
        );
        let positions_root = collection_root(
            "positions",
            self.positions
                .values()
                .map(RehypothecationPosition::state_root)
                .collect(),
        );
        let liens_root = collection_root(
            "liens",
            self.liens
                .values()
                .map(LienCommitment::state_root)
                .collect(),
        );
        let oracle_attestations_root = collection_root(
            "oracle_attestations",
            self.oracle_attestations
                .values()
                .map(OraclePqAttestation::state_root)
                .collect(),
        );
        let liquidation_locks_root = collection_root(
            "liquidation_locks",
            self.liquidation_locks
                .values()
                .map(LiquidationLock::state_root)
                .collect(),
        );
        let policy_breaches_root = collection_root(
            "policy_breaches",
            self.policy_breaches
                .values()
                .map(PolicyBreach::state_root)
                .collect(),
        );
        let fee_samples_root = collection_root(
            "fee_samples",
            self.fee_samples
                .values()
                .map(LowFeeSample::state_root)
                .collect(),
        );
        let redaction_budgets_root = collection_root(
            "redaction_budgets",
            self.redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::state_root)
                .collect(),
        );
        let public_record_root = state_root_from_public_record(&json!({
            "protocol_version": self.config.protocol_version,
            "current_height": self.current_height,
            "config_root": config_root,
            "counters_root": counters_root,
            "vaults_root": vaults_root,
            "positions_root": positions_root,
            "liens_root": liens_root,
            "oracle_attestations_root": oracle_attestations_root,
            "liquidation_locks_root": liquidation_locks_root,
            "policy_breaches_root": policy_breaches_root,
            "fee_samples_root": fee_samples_root,
            "redaction_budgets_root": redaction_budgets_root,
        }));
        Roots {
            config_root,
            counters_root,
            vaults_root,
            positions_root,
            liens_root,
            oracle_attestations_root,
            liquidation_locks_root,
            policy_breaches_root,
            fee_samples_root,
            redaction_budgets_root,
            public_record_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "guard_id": self.config.guard_id,
            "current_height": self.current_height,
            "hash_suite": self.config.hash_suite,
            "pq_attestation_suite": self.config.pq_attestation_suite,
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "paused_markets": self.paused_markets,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn register_oracle_attestation(&mut self, attestation: OraclePqAttestation) -> Result<()> {
        self.config.validate()?;
        ensure_capacity(
            "oracle_attestations",
            self.oracle_attestations.len(),
            self.config.max_oracle_attestations,
        )?;
        ensure_absent(
            "oracle_attestation",
            &attestation.attestation_id,
            self.oracle_attestations
                .contains_key(&attestation.attestation_id),
        )?;
        validate_attestation(&attestation, &self.config, self.current_height)?;
        self.oracle_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn register_vault(&mut self, vault: CollateralVault) -> Result<()> {
        self.config.validate()?;
        ensure_capacity("vaults", self.vaults.len(), self.config.max_vaults)?;
        ensure_absent(
            "vault",
            &vault.vault_id,
            self.vaults.contains_key(&vault.vault_id),
        )?;
        validate_vault(&vault, &self.config)?;
        self.require_attestation_fresh(&vault.oracle_attestation_id, AttestationKind::OraclePrice)?;
        self.vaults.insert(vault.vault_id.clone(), vault);
        Ok(())
    }

    pub fn open_position(&mut self, position: RehypothecationPosition) -> Result<()> {
        self.config.validate()?;
        ensure_capacity("positions", self.positions.len(), self.config.max_positions)?;
        ensure_absent(
            "position",
            &position.position_id,
            self.positions.contains_key(&position.position_id),
        )?;
        validate_position(&position, &self.config, self.current_height)?;
        let vault = self
            .vaults
            .get(&position.vault_id)
            .ok_or_else(|| "position vault does not exist".to_string())?;
        if !vault.status.accepts_reuse() {
            return Err("vault status does not accept rehypothecation reuse".to_string());
        }
        if !vault.allowed_markets.is_empty() && !vault.allowed_markets.contains(&position.market_id)
        {
            return Err("position market is not allowed by vault policy".to_string());
        }
        if self.paused_markets.contains(&position.market_id) {
            return Err("position market is paused".to_string());
        }
        if vault.current_reuse_bps.saturating_add(position.reuse_bps) > vault.max_reuse_bps {
            return Err("position would exceed vault reuse limit".to_string());
        }
        self.positions
            .insert(position.position_id.clone(), position);
        Ok(())
    }

    pub fn commit_lien(&mut self, lien: LienCommitment) -> Result<()> {
        self.config.validate()?;
        ensure_capacity("liens", self.liens.len(), self.config.max_liens)?;
        ensure_absent(
            "lien",
            &lien.lien_id,
            self.liens.contains_key(&lien.lien_id),
        )?;
        ensure_unique_set(
            "lien_nullifier",
            &lien.lien_nullifier,
            &self.used_lien_nullifiers,
        )?;
        ensure_unique_set(
            "reuse_nullifier",
            &lien.reuse_nullifier,
            &self.used_reuse_nullifiers,
        )?;
        validate_lien(&lien, &self.config, self.current_height)?;
        self.require_attestation_fresh(&lien.pq_attestation_id, AttestationKind::LienUniqueness)?;
        let position = self
            .positions
            .get_mut(&lien.position_id)
            .ok_or_else(|| "lien position does not exist".to_string())?;
        if position.vault_id != lien.vault_id {
            return Err("lien vault does not match position vault".to_string());
        }
        if !position.status.live() {
            return Err("lien position is not live".to_string());
        }
        position.lien_ids.insert(lien.lien_id.clone());
        let vault = self
            .vaults
            .get_mut(&lien.vault_id)
            .ok_or_else(|| "lien vault does not exist".to_string())?;
        vault.current_reuse_bps = vault.current_reuse_bps.saturating_add(position.reuse_bps);
        vault.updated_at_height = self.current_height;
        if vault.current_reuse_bps > vault.max_reuse_bps {
            return Err("committed lien exceeds vault reuse limit".to_string());
        }
        self.used_lien_nullifiers
            .insert(lien.lien_nullifier.clone());
        self.used_reuse_nullifiers
            .insert(lien.reuse_nullifier.clone());
        self.liens.insert(lien.lien_id.clone(), lien);
        Ok(())
    }

    pub fn request_liquidation_lock(&mut self, lock: LiquidationLock) -> Result<()> {
        self.config.validate()?;
        ensure_capacity(
            "liquidation_locks",
            self.liquidation_locks.len(),
            self.config.max_liquidation_locks,
        )?;
        ensure_absent(
            "liquidation_lock",
            &lock.lock_id,
            self.liquidation_locks.contains_key(&lock.lock_id),
        )?;
        validate_liquidation_lock(&lock, &self.config, self.current_height)?;
        let position = self
            .positions
            .get_mut(&lock.position_id)
            .ok_or_else(|| "liquidation position does not exist".to_string())?;
        if position.vault_id != lock.vault_id {
            return Err("liquidation lock vault does not match position".to_string());
        }
        position.liquidation_lock_id = Some(lock.lock_id.clone());
        position.status = PositionStatus::Liquidating;
        if let Some(vault) = self.vaults.get_mut(&lock.vault_id) {
            vault.status = VaultStatus::LiquidationOnly;
            vault.updated_at_height = self.current_height;
        }
        self.liquidation_locks.insert(lock.lock_id.clone(), lock);
        Ok(())
    }

    pub fn record_policy_breach(&mut self, breach: PolicyBreach) -> Result<()> {
        ensure_capacity(
            "policy_breaches",
            self.policy_breaches.len(),
            self.config.max_policy_breaches,
        )?;
        ensure_absent(
            "policy_breach",
            &breach.breach_id,
            self.policy_breaches.contains_key(&breach.breach_id),
        )?;
        require_root("evidence_root", &breach.evidence_root)?;
        require_root("remediation_root", &breach.remediation_root)?;
        require_non_empty("subject_id", &breach.subject_id)?;
        self.policy_breaches
            .insert(breach.breach_id.clone(), breach);
        Ok(())
    }

    pub fn record_low_fee_sample(&mut self, sample: LowFeeSample) -> Result<()> {
        ensure_capacity(
            "fee_samples",
            self.fee_samples.len(),
            self.config.max_fee_samples,
        )?;
        ensure_absent(
            "fee_sample",
            &sample.sample_id,
            self.fee_samples.contains_key(&sample.sample_id),
        )?;
        validate_fee_sample(&sample)?;
        if sample.p95_fee_bps > self.config.low_fee_alert_bps {
            let breach = PolicyBreach {
                breach_id: stable_id("breach", &format!("low-fee-{}", sample.sample_id)),
                kind: BreachKind::LowFeeBudgetExceeded,
                subject_id: sample.lane_id.clone(),
                evidence_root: sample.state_root(),
                remediation_root: deterministic_root("remediation", "low-fee-sponsor-topup"),
                severity: BreachKind::LowFeeBudgetExceeded.severity(),
                detected_at_height: sample.observed_at_height,
                cleared_at_height: None,
            };
            self.record_policy_breach(breach)?;
        }
        self.fee_samples.insert(sample.sample_id.clone(), sample);
        Ok(())
    }

    pub fn set_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        ensure_capacity(
            "redaction_budgets",
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        ensure_absent(
            "redaction_budget",
            &budget.budget_id,
            self.redaction_budgets.contains_key(&budget.budget_id),
        )?;
        validate_redaction_budget(&budget, &self.config)?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn guard_vault(&mut self, vault_id: &str) -> Result<Vec<String>> {
        let mut breaches = Vec::new();
        let vault = self
            .vaults
            .get(vault_id)
            .ok_or_else(|| "vault does not exist".to_string())?
            .clone();
        if vault.current_reuse_bps > vault.max_reuse_bps {
            breaches.push(self.emit_breach(
                BreachKind::ReuseLimitExceeded,
                vault_id,
                "reuse-limit",
                "reduce-lien-notional",
            )?);
        }
        if vault.health_factor_bps < self.config.min_health_factor_bps {
            breaches.push(self.emit_breach(
                BreachKind::HealthFactorBelowMinimum,
                vault_id,
                "health-factor",
                "top-up-or-liquidate",
            )?);
        }
        if vault.privacy_set_size < self.config.min_privacy_set_size {
            breaches.push(self.emit_breach(
                BreachKind::PrivacySetTooSmall,
                vault_id,
                "privacy-set",
                "merge-privacy-bucket",
            )?);
        }
        if !self.attestation_is_fresh(&vault.oracle_attestation_id) {
            breaches.push(self.emit_breach(
                BreachKind::StaleOracle,
                vault_id,
                "oracle-stale",
                "refresh-pq-oracle-attestation",
            )?);
        }
        Ok(breaches)
    }

    pub fn pause_market(&mut self, market_id: impl Into<String>) {
        self.paused_markets.insert(market_id.into());
    }

    pub fn resume_market(&mut self, market_id: &str) {
        self.paused_markets.remove(market_id);
    }

    fn emit_breach(
        &mut self,
        kind: BreachKind,
        subject_id: &str,
        evidence_label: &str,
        remediation_label: &str,
    ) -> Result<String> {
        let id = stable_id(
            "breach",
            &format!("{}-{subject_id}-{evidence_label}", kind.as_str()),
        );
        if self.policy_breaches.contains_key(&id) {
            return Ok(id);
        }
        let breach = PolicyBreach {
            breach_id: id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            evidence_root: deterministic_root("evidence", evidence_label),
            remediation_root: deterministic_root("remediation", remediation_label),
            severity: kind.severity(),
            detected_at_height: self.current_height,
            cleared_at_height: None,
        };
        self.record_policy_breach(breach)?;
        Ok(id)
    }

    fn require_attestation_fresh(&self, attestation_id: &str, kind: AttestationKind) -> Result<()> {
        let attestation = self
            .oracle_attestations
            .get(attestation_id)
            .ok_or_else(|| "required PQ attestation is missing".to_string())?;
        if attestation.kind != kind {
            return Err("PQ attestation kind mismatch".to_string());
        }
        if !attestation.fresh_at(self.current_height) {
            return Err("PQ attestation is stale".to_string());
        }
        Ok(())
    }

    fn attestation_is_fresh(&self, attestation_id: &str) -> bool {
        self.oracle_attestations
            .get(attestation_id)
            .map(|attestation| attestation.fresh_at(self.current_height))
            .unwrap_or(false)
    }

    fn install_devnet_samples(&mut self) {
        let price_attestation = OraclePqAttestation {
            attestation_id: "attest-wxmr-price-alpha".to_string(),
            kind: AttestationKind::OraclePrice,
            subject_id: "vault-wxmr-alpha".to_string(),
            oracle_committee_root: deterministic_root("oracle-committee", "devnet-alpha"),
            payload_commitment_root: deterministic_root("oracle-payload", "wxmr-price-alpha"),
            pq_signature_root: deterministic_root("pq-signature", "wxmr-price-alpha"),
            aggregate_weight_bps: 8_250,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_at_height: DEVNET_HEIGHT - 8,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_ORACLE_TTL_BLOCKS,
        };
        let lien_attestation = OraclePqAttestation {
            attestation_id: "attest-lien-unique-alpha".to_string(),
            kind: AttestationKind::LienUniqueness,
            subject_id: "lien-alpha-001".to_string(),
            oracle_committee_root: deterministic_root("oracle-committee", "devnet-alpha"),
            payload_commitment_root: deterministic_root("lien-payload", "alpha-001"),
            pq_signature_root: deterministic_root("pq-signature", "lien-alpha-001"),
            aggregate_weight_bps: 8_800,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_at_height: DEVNET_HEIGHT - 6,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_LIEN_TTL_BLOCKS,
        };
        let _ = self.register_oracle_attestation(price_attestation);
        let _ = self.register_oracle_attestation(lien_attestation);

        let vault = CollateralVault {
            vault_id: "vault-wxmr-alpha".to_string(),
            owner_commitment: deterministic_root("owner", "alpha"),
            asset_id: "wxmr-devnet".to_string(),
            collateral_kind: CollateralKind::WrappedMonero,
            status: VaultStatus::Open,
            collateral_commitment_root: deterministic_root("vault", "wxmr-alpha"),
            amount_commitment: deterministic_root("amount", "wxmr-alpha"),
            valuation_commitment: deterministic_root("valuation", "wxmr-alpha"),
            oracle_attestation_id: "attest-wxmr-price-alpha".to_string(),
            max_reuse_bps: DEFAULT_MAX_REUSE_BPS,
            current_reuse_bps: 0,
            health_factor_bps: 14_750,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            created_at_height: DEVNET_HEIGHT - 120,
            updated_at_height: DEVNET_HEIGHT - 8,
            allowed_markets: BTreeSet::from([
                "private-aave-wxmr".to_string(),
                "confidential-perps-margin".to_string(),
            ]),
            policy_tags: BTreeSet::from([
                "no-unbounded-reuse".to_string(),
                "oracle-pq-required".to_string(),
            ]),
        };
        let _ = self.register_vault(vault);

        let position = RehypothecationPosition {
            position_id: "position-alpha-001".to_string(),
            vault_id: "vault-wxmr-alpha".to_string(),
            market_id: "private-aave-wxmr".to_string(),
            borrower_commitment: deterministic_root("borrower", "alpha-001"),
            token_contract_commitment: deterministic_root("token-contract", "private-aave-wxmr"),
            status: PositionStatus::Active,
            notional_commitment: deterministic_root("notional", "alpha-001"),
            debt_commitment: deterministic_root("debt", "alpha-001"),
            reuse_bps: 1_250,
            health_factor_bps: 13_900,
            lien_ids: BTreeSet::new(),
            liquidation_lock_id: None,
            opened_at_height: DEVNET_HEIGHT - 48,
            expires_at_height: DEVNET_HEIGHT + 9_000,
        };
        let _ = self.open_position(position);

        let lien = LienCommitment {
            lien_id: "lien-alpha-001".to_string(),
            vault_id: "vault-wxmr-alpha".to_string(),
            position_id: "position-alpha-001".to_string(),
            priority: 1,
            lien_nullifier: deterministic_root("lien-nullifier", "alpha-001"),
            reuse_nullifier: deterministic_root("reuse-nullifier", "alpha-001"),
            commitment_root: deterministic_root("lien-commitment", "alpha-001"),
            creditor_commitment: deterministic_root("creditor", "alpha-001"),
            encumbered_value_commitment: deterministic_root("encumbered", "alpha-001"),
            status: LienStatus::Committed,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_attestation_id: "attest-lien-unique-alpha".to_string(),
            created_at_height: DEVNET_HEIGHT - 40,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_LIEN_TTL_BLOCKS,
        };
        let _ = self.commit_lien(lien);

        let sample = LowFeeSample {
            sample_id: "fee-sample-alpha".to_string(),
            lane_id: "private-defi-reuse-guard".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            median_fee_bps: 6,
            p95_fee_bps: 11,
            sponsor_coverage_bps: 9_700,
            batch_size: 384,
            observed_at_height: DEVNET_HEIGHT - 4,
            attestation_id: "attest-wxmr-price-alpha".to_string(),
        };
        let _ = self.record_low_fee_sample(sample);

        let budget = PrivacyRedactionBudget {
            budget_id: "redaction-alpha-epoch".to_string(),
            subject_commitment: deterministic_root("redaction-subject", "alpha"),
            epoch: DEVNET_HEIGHT / DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_redactions: 24,
            used_redactions: 3,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            policy_root: deterministic_root("redaction-policy", "default"),
            audit_commitment_root: deterministic_root("redaction-audit", "alpha"),
        };
        let _ = self.set_redaction_budget(budget);
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

pub fn state_root_from_public_record(record: &Value) -> String {
    let encoded = serde_json::to_string(record).unwrap_or_else(|_| "null".to_string());
    domain_hash(
        "PRIVATE-L2-PQ-COLLATERAL-GUARD-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&encoded),
        ],
        32,
    )
}

fn validate_vault(vault: &CollateralVault, config: &Config) -> Result<()> {
    require_non_empty("vault_id", &vault.vault_id)?;
    require_non_empty("asset_id", &vault.asset_id)?;
    require_root("owner_commitment", &vault.owner_commitment)?;
    require_root(
        "collateral_commitment_root",
        &vault.collateral_commitment_root,
    )?;
    require_root("amount_commitment", &vault.amount_commitment)?;
    require_root("valuation_commitment", &vault.valuation_commitment)?;
    require_non_empty("oracle_attestation_id", &vault.oracle_attestation_id)?;
    require_bps("max_reuse_bps", vault.max_reuse_bps)?;
    require_bps("current_reuse_bps", vault.current_reuse_bps)?;
    require_bps("health_factor_bps", vault.health_factor_bps)?;
    validate_privacy_and_pq(
        vault.privacy_set_size,
        vault.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if vault.current_reuse_bps > vault.max_reuse_bps {
        return Err("vault current reuse exceeds max reuse".to_string());
    }
    if vault.max_reuse_bps > config.default_max_reuse_bps {
        return Err("vault max reuse exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_position(
    position: &RehypothecationPosition,
    config: &Config,
    current_height: u64,
) -> Result<()> {
    require_non_empty("position_id", &position.position_id)?;
    require_non_empty("vault_id", &position.vault_id)?;
    require_non_empty("market_id", &position.market_id)?;
    require_root("borrower_commitment", &position.borrower_commitment)?;
    require_root(
        "token_contract_commitment",
        &position.token_contract_commitment,
    )?;
    require_root("notional_commitment", &position.notional_commitment)?;
    require_root("debt_commitment", &position.debt_commitment)?;
    require_bps("reuse_bps", position.reuse_bps)?;
    require_bps("health_factor_bps", position.health_factor_bps)?;
    if position.reuse_bps > config.default_max_reuse_bps {
        return Err("position reuse exceeds configured maximum".to_string());
    }
    if position.health_factor_bps < config.liquidation_health_factor_bps {
        return Err("position health factor below liquidation threshold".to_string());
    }
    if position.expires_at_height <= current_height {
        return Err("position expiry must be in the future".to_string());
    }
    Ok(())
}

fn validate_lien(lien: &LienCommitment, config: &Config, current_height: u64) -> Result<()> {
    require_non_empty("lien_id", &lien.lien_id)?;
    require_non_empty("vault_id", &lien.vault_id)?;
    require_non_empty("position_id", &lien.position_id)?;
    require_root("lien_nullifier", &lien.lien_nullifier)?;
    require_root("reuse_nullifier", &lien.reuse_nullifier)?;
    require_root("commitment_root", &lien.commitment_root)?;
    require_root("creditor_commitment", &lien.creditor_commitment)?;
    require_root(
        "encumbered_value_commitment",
        &lien.encumbered_value_commitment,
    )?;
    require_non_empty("pq_attestation_id", &lien.pq_attestation_id)?;
    if lien.privacy_set_size < config.min_privacy_set_size {
        return Err("lien privacy set below minimum".to_string());
    }
    if lien.expires_at_height <= current_height {
        return Err("lien expiry must be in the future".to_string());
    }
    if lien
        .expires_at_height
        .saturating_sub(lien.created_at_height)
        > config.lien_ttl_blocks
    {
        return Err("lien TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_attestation(
    attestation: &OraclePqAttestation,
    config: &Config,
    current_height: u64,
) -> Result<()> {
    require_non_empty("attestation_id", &attestation.attestation_id)?;
    require_non_empty("subject_id", &attestation.subject_id)?;
    require_root("oracle_committee_root", &attestation.oracle_committee_root)?;
    require_root(
        "payload_commitment_root",
        &attestation.payload_commitment_root,
    )?;
    require_root("pq_signature_root", &attestation.pq_signature_root)?;
    require_bps("aggregate_weight_bps", attestation.aggregate_weight_bps)?;
    validate_privacy_and_pq(
        attestation.privacy_set_size,
        attestation.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if attestation.aggregate_weight_bps < 6_700 {
        return Err("PQ attestation aggregate weight below quorum".to_string());
    }
    if attestation.expires_at_height <= current_height {
        return Err("PQ attestation expiry must be in the future".to_string());
    }
    if attestation
        .expires_at_height
        .saturating_sub(attestation.observed_at_height)
        > config.lien_ttl_blocks
    {
        return Err("PQ attestation TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_liquidation_lock(
    lock: &LiquidationLock,
    config: &Config,
    current_height: u64,
) -> Result<()> {
    require_non_empty("lock_id", &lock.lock_id)?;
    require_non_empty("vault_id", &lock.vault_id)?;
    require_non_empty("position_id", &lock.position_id)?;
    require_root("liquidator_commitment", &lock.liquidator_commitment)?;
    require_root("authorization_root", &lock.authorization_root)?;
    require_root("lock_nullifier", &lock.lock_nullifier)?;
    if lock.expires_at_height <= current_height {
        return Err("liquidation lock expiry must be in the future".to_string());
    }
    if lock
        .expires_at_height
        .saturating_sub(lock.requested_at_height)
        > config.liquidation_lock_ttl_blocks
    {
        return Err("liquidation lock TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_fee_sample(sample: &LowFeeSample) -> Result<()> {
    require_non_empty("sample_id", &sample.sample_id)?;
    require_non_empty("lane_id", &sample.lane_id)?;
    require_non_empty("fee_asset_id", &sample.fee_asset_id)?;
    require_bps("median_fee_bps", sample.median_fee_bps)?;
    require_bps("p95_fee_bps", sample.p95_fee_bps)?;
    require_bps("sponsor_coverage_bps", sample.sponsor_coverage_bps)?;
    require_positive_u64("batch_size", sample.batch_size)?;
    require_non_empty("attestation_id", &sample.attestation_id)?;
    if sample.median_fee_bps > sample.p95_fee_bps {
        return Err("median fee cannot exceed p95 fee".to_string());
    }
    Ok(())
}

fn validate_redaction_budget(budget: &PrivacyRedactionBudget, config: &Config) -> Result<()> {
    require_non_empty("budget_id", &budget.budget_id)?;
    require_root("subject_commitment", &budget.subject_commitment)?;
    require_positive_u64("max_redactions", budget.max_redactions)?;
    require_root("policy_root", &budget.policy_root)?;
    require_root("audit_commitment_root", &budget.audit_commitment_root)?;
    if budget.used_redactions > budget.max_redactions {
        return Err("used redactions exceed budget".to_string());
    }
    if budget.privacy_set_size < config.min_privacy_set_size {
        return Err("redaction budget privacy set below minimum".to_string());
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("privacy set below configured minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("PQ security bits below configured minimum".to_string());
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 32 {
        return Err(format!("{field} must be a domain-separated root"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} cannot exceed {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(name: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{name} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_absent(name: &str, id: &str, present: bool) -> Result<()> {
    if present {
        Err(format!("{name} {id} already exists"))
    } else {
        Ok(())
    }
}

fn ensure_unique_set(name: &str, value: &str, set: &BTreeSet<String>) -> Result<()> {
    if set.contains(value) {
        Err(format!("{name} already used"))
    } else {
        Ok(())
    }
}

fn collection_root(label: &str, mut leaves: Vec<String>) -> String {
    leaves.sort();
    if leaves.is_empty() {
        empty_root(label)
    } else {
        let parts: Vec<Value> = leaves.into_iter().map(Value::String).collect();
        merkle_root(
            &format!(
                "PRIVATE-L2-PQ-COLLATERAL-GUARD-{}",
                label.to_ascii_uppercase()
            ),
            &parts,
        )
    }
}

fn empty_root(label: &str) -> String {
    merkle_root(
        &format!(
            "PRIVATE-L2-PQ-COLLATERAL-GUARD-EMPTY-{}",
            label.to_ascii_uppercase()
        ),
        &[],
    )
}

fn stable_id(domain: &str, label: &str) -> String {
    deterministic_root(domain, label)
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-COLLATERAL-GUARD-{}",
            domain.to_ascii_uppercase()
        ),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
