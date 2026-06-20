use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateDefiLiquidityRiskCircuitResult<T> = Result<T, String>;

pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PROTOCOL_ID: &str =
    "nebula-private-defi-liquidity-risk-circuit-v1";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PROTOCOL_VERSION: u64 = 1;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PQ_BACKUP_SIGNATURE_SCHEME: &str =
    "SLH-DSA-SHAKE-256f";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PROOF_SYSTEM: &str =
    "zk-private-defi-liquidity-risk-envelope-v1";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_LOW_FEE_CHECK_SYSTEM: &str =
    "zk-low-fee-risk-check-netting-v1";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_RECEIPT_SYSTEM: &str =
    "zk-private-risk-settlement-receipt-v1";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_CHALLENGE_SYSTEM: &str =
    "pq-risk-circuit-fraud-evidence-v1";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEVNET_HEIGHT: u64 = 1_024;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEVNET_EPOCH: u64 = 7;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 768;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_FEE_UNITS: u64 = 6;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_CHECK_WEIGHT: u64 = 50_000;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_STALENESS_BLOCKS: u64 = 16;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_LIQUIDATION_HALT_BPS: u64 = 1_250;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_LIQUIDATION_DISCOUNT_CAP_BPS: u64 = 650;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_POOL_RISK_BPS: u64 = 7_500;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_BUCKET_RISK_BPS: u64 = 8_500;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_CHALLENGE_BOND_UNITS: u64 = 25_000;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_SETTLEMENT_DELAY_BLOCKS: u64 = 12;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_POOLS: usize = 65_536;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_BUCKETS: usize = 262_144;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_ORACLE_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_VERIFIER_KEYS: usize = 16_384;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_GUARDRAILS: usize = 65_536;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_LOW_FEE_CHECKS: usize = 524_288;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_RECEIPTS: usize = 524_288;
pub const PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_CHALLENGES: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiVenueKind {
    Amm,
    Lending,
    Perps,
    Vault,
    StableSwap,
    DarkPool,
}

impl DefiVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Vault => "vault",
            Self::StableSwap => "stable_swap",
            Self::DarkPool => "dark_pool",
        }
    }

    pub fn default_circuit_class(self) -> RiskCircuitClass {
        match self {
            Self::Amm | Self::StableSwap | Self::DarkPool => RiskCircuitClass::LiquidityEnvelope,
            Self::Lending | Self::Vault => RiskCircuitClass::HealthFactorEnvelope,
            Self::Perps => RiskCircuitClass::MarginEnvelope,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureBucketKind {
    AmmInventory,
    AmmTwap,
    LendingCollateral,
    LendingDebt,
    PerpsOpenInterest,
    PerpsFunding,
    VaultShare,
    LiquidationQueue,
    OracleStaleness,
    FeeSponsor,
}

impl ExposureBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmmInventory => "amm_inventory",
            Self::AmmTwap => "amm_twap",
            Self::LendingCollateral => "lending_collateral",
            Self::LendingDebt => "lending_debt",
            Self::PerpsOpenInterest => "perps_open_interest",
            Self::PerpsFunding => "perps_funding",
            Self::VaultShare => "vault_share",
            Self::LiquidationQueue => "liquidation_queue",
            Self::OracleStaleness => "oracle_staleness",
            Self::FeeSponsor => "fee_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCircuitClass {
    LiquidityEnvelope,
    HealthFactorEnvelope,
    MarginEnvelope,
    OracleAttestation,
    LiquidationGuard,
    LowFeeRiskCheck,
    SettlementReceipt,
    ChallengeEvidence,
}

impl RiskCircuitClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiquidityEnvelope => "liquidity_envelope",
            Self::HealthFactorEnvelope => "health_factor_envelope",
            Self::MarginEnvelope => "margin_envelope",
            Self::OracleAttestation => "oracle_attestation",
            Self::LiquidationGuard => "liquidation_guard",
            Self::LowFeeRiskCheck => "low_fee_risk_check",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ChallengeEvidence => "challenge_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Green,
    Watch,
    Caution,
    Guarded,
    Halted,
    Quarantined,
}

impl RiskSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Watch => "watch",
            Self::Caution => "caution",
            Self::Guarded => "guarded",
            Self::Halted => "halted",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn allows_new_risk(self) -> bool {
        matches!(self, Self::Green | Self::Watch | Self::Caution)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(
            self,
            Self::Green | Self::Watch | Self::Caution | Self::Guarded
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolEnvelopeStatus {
    Draft,
    Active,
    Rebalanced,
    Guarded,
    Frozen,
    Retired,
}

impl PoolEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Rebalanced => "rebalanced",
            Self::Guarded => "guarded",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationStatus {
    Submitted,
    QuorumChecked,
    Counted,
    Rejected,
    Expired,
    Challenged,
}

impl OracleAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::QuorumChecked => "quorum_checked",
            Self::Counted => "counted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyStatus {
    Candidate,
    Active,
    Rotating,
    Revoked,
    Retired,
}

impl VerifierKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailStatus {
    Active,
    Tripped,
    CoolingDown,
    Paused,
    Retired,
}

impl GuardrailStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Tripped => "tripped",
            Self::CoolingDown => "cooling_down",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeRiskCheckStatus {
    Queued,
    Verified,
    Sponsored,
    Settled,
    Rejected,
    Expired,
}

impl LowFeeRiskCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Verified => "verified",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Pending,
    Published,
    Finalized,
    Disputed,
    Reversed,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceAccepted,
    Proving,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceAccepted => "evidence_accepted",
            Self::Proving => "proving",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiLiquidityRiskCircuitConfig {
    pub protocol_id: String,
    pub protocol_version: u64,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_units: u64,
    pub max_check_weight: u64,
    pub min_oracle_quorum_bps: u64,
    pub max_staleness_blocks: u64,
    pub liquidation_halt_bps: u64,
    pub liquidation_discount_cap_bps: u64,
    pub max_pool_risk_bps: u64,
    pub max_bucket_risk_bps: u64,
    pub challenge_bond_units: u64,
    pub max_settlement_delay_blocks: u64,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_backup_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub risk_proof_system: String,
    pub low_fee_check_system: String,
    pub receipt_system: String,
    pub challenge_system: String,
}

impl Default for PrivateDefiLiquidityRiskCircuitConfig {
    fn default() -> Self {
        Self {
            protocol_id: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PROTOCOL_ID.to_string(),
            protocol_version: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PROTOCOL_VERSION,
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_FEE_ASSET_ID.to_string(),
            epoch_blocks: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_EPOCH_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_ATTESTATION_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_RECEIPT_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_units: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_FEE_UNITS,
            max_check_weight: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_CHECK_WEIGHT,
            min_oracle_quorum_bps:
                PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_ORACLE_QUORUM_BPS,
            max_staleness_blocks: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_STALENESS_BLOCKS,
            liquidation_halt_bps: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_LIQUIDATION_HALT_BPS,
            liquidation_discount_cap_bps:
                PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_LIQUIDATION_DISCOUNT_CAP_BPS,
            max_pool_risk_bps: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_POOL_RISK_BPS,
            max_bucket_risk_bps: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_BUCKET_RISK_BPS,
            challenge_bond_units: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_CHALLENGE_BOND_UNITS,
            max_settlement_delay_blocks:
                PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MAX_SETTLEMENT_DELAY_BLOCKS,
            hash_suite: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PQ_SIGNATURE_SCHEME
                .to_string(),
            pq_backup_signature_scheme:
                PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PQ_BACKUP_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PQ_KEM_SCHEME.to_string(),
            risk_proof_system: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PROOF_SYSTEM.to_string(),
            low_fee_check_system: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_LOW_FEE_CHECK_SYSTEM
                .to_string(),
            receipt_system: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_RECEIPT_SYSTEM.to_string(),
            challenge_system: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_CHALLENGE_SYSTEM.to_string(),
        }
    }
}

impl PrivateDefiLiquidityRiskCircuitConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_id": self.protocol_id,
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_units": self.max_fee_units,
            "max_check_weight": self.max_check_weight,
            "min_oracle_quorum_bps": self.min_oracle_quorum_bps,
            "max_staleness_blocks": self.max_staleness_blocks,
            "liquidation_halt_bps": self.liquidation_halt_bps,
            "liquidation_discount_cap_bps": self.liquidation_discount_cap_bps,
            "max_pool_risk_bps": self.max_pool_risk_bps,
            "max_bucket_risk_bps": self.max_bucket_risk_bps,
            "challenge_bond_units": self.challenge_bond_units,
            "max_settlement_delay_blocks": self.max_settlement_delay_blocks,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_backup_signature_scheme": self.pq_backup_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "risk_proof_system": self.risk_proof_system,
            "low_fee_check_system": self.low_fee_check_system,
            "receipt_system": self.receipt_system,
            "challenge_system": self.challenge_system,
        })
    }

    pub fn config_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-RISK-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.protocol_id, "protocol id")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_empty(&self.hash_suite, "hash suite")?;
        ensure_non_empty(&self.pq_signature_scheme, "PQ signature scheme")?;
        ensure_non_empty(&self.pq_kem_scheme, "PQ KEM scheme")?;
        ensure_bps(self.min_oracle_quorum_bps, "min oracle quorum bps")?;
        ensure_bps(self.liquidation_halt_bps, "liquidation halt bps")?;
        ensure_bps(
            self.liquidation_discount_cap_bps,
            "liquidation discount cap bps",
        )?;
        ensure_bps(self.max_pool_risk_bps, "max pool risk bps")?;
        ensure_bps(self.max_bucket_risk_bps, "max bucket risk bps")?;
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security bits must be at least 192".to_string());
        }
        if self.epoch_blocks == 0
            || self.attestation_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
        {
            return Err("epoch and ttl windows must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPoolRiskEnvelope {
    pub pool_id: String,
    pub venue_kind: DefiVenueKind,
    pub circuit_class: RiskCircuitClass,
    pub pool_commitment: String,
    pub asset_commitment_root: String,
    pub lp_commitment_root: String,
    pub private_liquidity_lower_bound: u64,
    pub private_liquidity_upper_bound: u64,
    pub utilization_bps: u64,
    pub risk_score_bps: u64,
    pub severity: RiskSeverity,
    pub status: PoolEnvelopeStatus,
    pub oracle_attestation_ids: BTreeSet<String>,
    pub exposure_bucket_ids: BTreeSet<String>,
    pub verifier_key_id: String,
    pub guardrail_id: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub metadata_commitment: String,
}

impl ConfidentialPoolRiskEnvelope {
    pub fn new(
        label: &str,
        venue_kind: DefiVenueKind,
        private_liquidity_lower_bound: u64,
        private_liquidity_upper_bound: u64,
        utilization_bps: u64,
        risk_score_bps: u64,
        height: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(label, "pool label")?;
        ensure_bps(utilization_bps, "pool utilization bps")?;
        ensure_bps(risk_score_bps, "pool risk score bps")?;
        if private_liquidity_lower_bound > private_liquidity_upper_bound {
            return Err("pool liquidity lower bound exceeds upper bound".to_string());
        }
        let pool_id = private_defi_pool_id(label, venue_kind);
        let circuit_class = venue_kind.default_circuit_class();
        Ok(Self {
            pool_commitment: private_defi_commitment("POOL-COMMITMENT", label),
            asset_commitment_root: private_defi_commitment("POOL-ASSET-ROOT", label),
            lp_commitment_root: private_defi_commitment("POOL-LP-ROOT", label),
            verifier_key_id: private_defi_verifier_key_id(circuit_class, label, 1),
            guardrail_id: private_defi_guardrail_id(&pool_id, "baseline"),
            pool_id,
            venue_kind,
            circuit_class,
            private_liquidity_lower_bound,
            private_liquidity_upper_bound,
            utilization_bps,
            risk_score_bps,
            severity: severity_from_risk_score(risk_score_bps),
            status: PoolEnvelopeStatus::Active,
            oracle_attestation_ids: BTreeSet::new(),
            exposure_bucket_ids: BTreeSet::new(),
            created_at_height: height,
            updated_at_height: height,
            metadata_commitment: private_defi_commitment("POOL-METADATA", label),
        })
    }

    pub fn attach_oracle_attestation(&mut self, attestation_id: impl Into<String>, height: u64) {
        self.oracle_attestation_ids.insert(attestation_id.into());
        self.updated_at_height = height;
    }

    pub fn attach_exposure_bucket(&mut self, bucket_id: impl Into<String>, height: u64) {
        self.exposure_bucket_ids.insert(bucket_id.into());
        self.updated_at_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "venue_kind": self.venue_kind.as_str(),
            "circuit_class": self.circuit_class.as_str(),
            "pool_commitment": self.pool_commitment,
            "asset_commitment_root": self.asset_commitment_root,
            "lp_commitment_root": self.lp_commitment_root,
            "private_liquidity_lower_bound": self.private_liquidity_lower_bound,
            "private_liquidity_upper_bound": self.private_liquidity_upper_bound,
            "utilization_bps": self.utilization_bps,
            "risk_score_bps": self.risk_score_bps,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "oracle_attestation_root": string_set_root("PRIVATE-DEFI-POOL-ORACLE-IDS", &self.oracle_attestation_ids),
            "exposure_bucket_root": string_set_root("PRIVATE-DEFI-POOL-BUCKET-IDS", &self.exposure_bucket_ids),
            "verifier_key_id": self.verifier_key_id,
            "guardrail_id": self.guardrail_id,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn envelope_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-POOL-ENVELOPE",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.pool_id, "pool id")?;
        ensure_non_empty(&self.pool_commitment, "pool commitment")?;
        ensure_non_empty(&self.asset_commitment_root, "pool asset commitment root")?;
        ensure_non_empty(&self.lp_commitment_root, "pool LP commitment root")?;
        ensure_non_empty(&self.verifier_key_id, "pool verifier key id")?;
        ensure_non_empty(&self.guardrail_id, "pool guardrail id")?;
        ensure_bps(self.utilization_bps, "pool utilization bps")?;
        ensure_bps(self.risk_score_bps, "pool risk score bps")?;
        if self.private_liquidity_lower_bound > self.private_liquidity_upper_bound {
            return Err(format!(
                "pool {} liquidity lower bound exceeds upper bound",
                self.pool_id
            ));
        }
        if self.risk_score_bps > config.max_pool_risk_bps
            && self.status == PoolEnvelopeStatus::Active
        {
            return Err(format!(
                "pool {} is active above max pool risk",
                self.pool_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureBucket {
    pub bucket_id: String,
    pub pool_id: String,
    pub bucket_kind: ExposureBucketKind,
    pub asset_id: String,
    pub sealed_exposure_commitment: String,
    pub exposure_lower_bound: u64,
    pub exposure_upper_bound: u64,
    pub net_delta_bps: i64,
    pub concentration_bps: u64,
    pub stress_loss_bps: u64,
    pub risk_score_bps: u64,
    pub severity: RiskSeverity,
    pub circuit_class: RiskCircuitClass,
    pub verifier_key_id: String,
    pub last_update_height: u64,
    pub privacy_set_size: u64,
}

impl ExposureBucket {
    pub fn new(
        pool_id: &str,
        bucket_kind: ExposureBucketKind,
        asset_id: &str,
        exposure_lower_bound: u64,
        exposure_upper_bound: u64,
        concentration_bps: u64,
        stress_loss_bps: u64,
        height: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(pool_id, "bucket pool id")?;
        ensure_non_empty(asset_id, "bucket asset id")?;
        ensure_bps(concentration_bps, "bucket concentration bps")?;
        ensure_bps(stress_loss_bps, "bucket stress loss bps")?;
        if exposure_lower_bound > exposure_upper_bound {
            return Err("bucket exposure lower bound exceeds upper bound".to_string());
        }
        let bucket_id = private_defi_bucket_id(pool_id, bucket_kind, asset_id, height);
        let circuit_class = circuit_class_for_bucket(bucket_kind);
        let risk_score_bps = bucket_risk_score(concentration_bps, stress_loss_bps);
        Ok(Self {
            sealed_exposure_commitment: private_defi_commitment(
                "BUCKET-SEALED-EXPOSURE",
                &bucket_id,
            ),
            verifier_key_id: private_defi_verifier_key_id(circuit_class, asset_id, 1),
            bucket_id,
            pool_id: pool_id.to_string(),
            bucket_kind,
            asset_id: asset_id.to_string(),
            exposure_lower_bound,
            exposure_upper_bound,
            net_delta_bps: 0,
            concentration_bps,
            stress_loss_bps,
            risk_score_bps,
            severity: severity_from_risk_score(risk_score_bps),
            circuit_class,
            last_update_height: height,
            privacy_set_size: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_PRIVACY_SET_SIZE,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "pool_id": self.pool_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "asset_id": self.asset_id,
            "sealed_exposure_commitment": self.sealed_exposure_commitment,
            "exposure_lower_bound": self.exposure_lower_bound,
            "exposure_upper_bound": self.exposure_upper_bound,
            "net_delta_bps": self.net_delta_bps,
            "concentration_bps": self.concentration_bps,
            "stress_loss_bps": self.stress_loss_bps,
            "risk_score_bps": self.risk_score_bps,
            "severity": self.severity.as_str(),
            "circuit_class": self.circuit_class.as_str(),
            "verifier_key_id": self.verifier_key_id,
            "last_update_height": self.last_update_height,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn bucket_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-EXPOSURE-BUCKET",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.bucket_id, "bucket id")?;
        ensure_non_empty(&self.pool_id, "bucket pool id")?;
        ensure_non_empty(&self.asset_id, "bucket asset id")?;
        ensure_non_empty(
            &self.sealed_exposure_commitment,
            "sealed exposure commitment",
        )?;
        ensure_non_empty(&self.verifier_key_id, "bucket verifier key id")?;
        ensure_bps(self.concentration_bps, "bucket concentration bps")?;
        ensure_bps(self.stress_loss_bps, "bucket stress loss bps")?;
        ensure_bps(self.risk_score_bps, "bucket risk score bps")?;
        if self.exposure_lower_bound > self.exposure_upper_bound {
            return Err(format!(
                "bucket {} exposure lower bound exceeds upper bound",
                self.bucket_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "bucket {} privacy set is too small",
                self.bucket_id
            ));
        }
        if self.risk_score_bps > config.max_bucket_risk_bps {
            return Err(format!("bucket {} exceeds max bucket risk", self.bucket_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub feed_id: String,
    pub pool_id: String,
    pub committee_id: String,
    pub price_commitment: String,
    pub confidence_interval_bps: u64,
    pub quorum_bps: u64,
    pub median_age_blocks: u64,
    pub pq_signature_root: String,
    pub pq_public_key_root: String,
    pub kem_ciphertext_root: String,
    pub status: OracleAttestationStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_commitment: String,
}

impl PqOracleAttestation {
    pub fn new(
        feed_id: &str,
        pool_id: &str,
        committee_id: &str,
        confidence_interval_bps: u64,
        quorum_bps: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(feed_id, "oracle feed id")?;
        ensure_non_empty(pool_id, "oracle pool id")?;
        ensure_non_empty(committee_id, "oracle committee id")?;
        ensure_bps(confidence_interval_bps, "oracle confidence interval bps")?;
        ensure_bps(quorum_bps, "oracle quorum bps")?;
        let attestation_id =
            private_defi_oracle_attestation_id(feed_id, pool_id, submitted_at_height);
        Ok(Self {
            price_commitment: private_defi_commitment("ORACLE-PRICE", &attestation_id),
            pq_signature_root: private_defi_commitment("ORACLE-PQ-SIGS", &attestation_id),
            pq_public_key_root: private_defi_commitment("ORACLE-PQ-PUBLIC-KEYS", committee_id),
            kem_ciphertext_root: private_defi_commitment("ORACLE-KEM-CIPHERTEXTS", &attestation_id),
            metadata_commitment: private_defi_commitment("ORACLE-METADATA", feed_id),
            attestation_id,
            feed_id: feed_id.to_string(),
            pool_id: pool_id.to_string(),
            committee_id: committee_id.to_string(),
            confidence_interval_bps,
            quorum_bps,
            median_age_blocks: 1,
            status: OracleAttestationStatus::Counted,
            submitted_at_height,
            expires_at_height: submitted_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "feed_id": self.feed_id,
            "pool_id": self.pool_id,
            "committee_id": self.committee_id,
            "price_commitment": self.price_commitment,
            "confidence_interval_bps": self.confidence_interval_bps,
            "quorum_bps": self.quorum_bps,
            "median_age_blocks": self.median_age_blocks,
            "pq_signature_root": self.pq_signature_root,
            "pq_public_key_root": self.pq_public_key_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn attestation_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-PQ-ORACLE-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
        current_height: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.attestation_id, "oracle attestation id")?;
        ensure_non_empty(&self.feed_id, "oracle feed id")?;
        ensure_non_empty(&self.pool_id, "oracle pool id")?;
        ensure_non_empty(&self.committee_id, "oracle committee id")?;
        ensure_non_empty(&self.price_commitment, "oracle price commitment")?;
        ensure_bps(
            self.confidence_interval_bps,
            "oracle confidence interval bps",
        )?;
        ensure_bps(self.quorum_bps, "oracle quorum bps")?;
        if self.quorum_bps < config.min_oracle_quorum_bps {
            return Err(format!(
                "oracle attestation {} quorum is below minimum",
                self.attestation_id
            ));
        }
        if self.median_age_blocks > config.max_staleness_blocks {
            return Err(format!(
                "oracle attestation {} is stale",
                self.attestation_id
            ));
        }
        if current_height > self.expires_at_height
            && self.status == OracleAttestationStatus::Counted
        {
            return Err(format!(
                "oracle attestation {} is counted after expiry",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskCircuitVerifierKey {
    pub verifier_key_id: String,
    pub circuit_class: RiskCircuitClass,
    pub version: u64,
    pub verifying_key_commitment: String,
    pub proving_system: String,
    pub hash_suite: String,
    pub pq_security_bits: u16,
    pub recursion_depth: u16,
    pub supported_venue_kinds: BTreeSet<DefiVenueKind>,
    pub status: VerifierKeyStatus,
    pub activated_at_height: u64,
    pub retired_at_height: Option<u64>,
    pub governance_attestation_root: String,
}

impl RiskCircuitVerifierKey {
    pub fn new(
        label: &str,
        circuit_class: RiskCircuitClass,
        version: u64,
        activated_at_height: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(label, "verifier key label")?;
        if version == 0 {
            return Err("verifier key version must be non-zero".to_string());
        }
        let verifier_key_id = private_defi_verifier_key_id(circuit_class, label, version);
        Ok(Self {
            verifying_key_commitment: private_defi_commitment("VERIFIER-KEY", &verifier_key_id),
            proving_system: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_PROOF_SYSTEM.to_string(),
            hash_suite: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_HASH_SUITE.to_string(),
            pq_security_bits: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_MIN_PQ_SECURITY_BITS,
            recursion_depth: 2,
            supported_venue_kinds: supported_venues_for_circuit(circuit_class),
            status: VerifierKeyStatus::Active,
            governance_attestation_root: private_defi_commitment(
                "VERIFIER-GOVERNANCE",
                &verifier_key_id,
            ),
            verifier_key_id,
            circuit_class,
            version,
            activated_at_height,
            retired_at_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verifier_key_id": self.verifier_key_id,
            "circuit_class": self.circuit_class.as_str(),
            "version": self.version,
            "verifying_key_commitment": self.verifying_key_commitment,
            "proving_system": self.proving_system,
            "hash_suite": self.hash_suite,
            "pq_security_bits": self.pq_security_bits,
            "recursion_depth": self.recursion_depth,
            "supported_venue_root": venue_kind_set_root(&self.supported_venue_kinds),
            "status": self.status.as_str(),
            "activated_at_height": self.activated_at_height,
            "retired_at_height": self.retired_at_height,
            "governance_attestation_root": self.governance_attestation_root,
        })
    }

    pub fn key_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-RISK-VERIFIER-KEY",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.verifier_key_id, "verifier key id")?;
        ensure_non_empty(&self.verifying_key_commitment, "verifying key commitment")?;
        ensure_non_empty(&self.proving_system, "proving system")?;
        ensure_non_empty(&self.hash_suite, "verifier hash suite")?;
        if self.version == 0 {
            return Err(format!(
                "verifier key {} version must be non-zero",
                self.verifier_key_id
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "verifier key {} PQ security is below minimum",
                self.verifier_key_id
            ));
        }
        if self.status == VerifierKeyStatus::Active && self.retired_at_height.is_some() {
            return Err(format!(
                "verifier key {} is active with retirement height",
                self.verifier_key_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationGuardrail {
    pub guardrail_id: String,
    pub pool_id: String,
    pub severity: RiskSeverity,
    pub max_liquidation_notional_units: u64,
    pub liquidation_discount_cap_bps: u64,
    pub halt_threshold_bps: u64,
    pub keeper_privacy_set_root: String,
    pub protected_bucket_ids: BTreeSet<String>,
    pub status: GuardrailStatus,
    pub triggered_at_height: Option<u64>,
    pub cooldown_until_height: Option<u64>,
}

impl LiquidationGuardrail {
    pub fn new(
        pool_id: &str,
        label: &str,
        max_liquidation_notional_units: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(pool_id, "guardrail pool id")?;
        ensure_non_empty(label, "guardrail label")?;
        Ok(Self {
            guardrail_id: private_defi_guardrail_id(pool_id, label),
            pool_id: pool_id.to_string(),
            severity: RiskSeverity::Watch,
            max_liquidation_notional_units,
            liquidation_discount_cap_bps:
                PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_LIQUIDATION_DISCOUNT_CAP_BPS,
            halt_threshold_bps: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_LIQUIDATION_HALT_BPS,
            keeper_privacy_set_root: private_defi_commitment("KEEPER-PRIVACY-SET", pool_id),
            protected_bucket_ids: BTreeSet::new(),
            status: GuardrailStatus::Active,
            triggered_at_height: None,
            cooldown_until_height: None,
        })
    }

    pub fn protect_bucket(&mut self, bucket_id: impl Into<String>) {
        self.protected_bucket_ids.insert(bucket_id.into());
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guardrail_id": self.guardrail_id,
            "pool_id": self.pool_id,
            "severity": self.severity.as_str(),
            "max_liquidation_notional_units": self.max_liquidation_notional_units,
            "liquidation_discount_cap_bps": self.liquidation_discount_cap_bps,
            "halt_threshold_bps": self.halt_threshold_bps,
            "keeper_privacy_set_root": self.keeper_privacy_set_root,
            "protected_bucket_root": string_set_root("PRIVATE-DEFI-GUARDRAIL-BUCKETS", &self.protected_bucket_ids),
            "status": self.status.as_str(),
            "triggered_at_height": self.triggered_at_height,
            "cooldown_until_height": self.cooldown_until_height,
        })
    }

    pub fn guardrail_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-LIQUIDATION-GUARDRAIL",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.guardrail_id, "guardrail id")?;
        ensure_non_empty(&self.pool_id, "guardrail pool id")?;
        ensure_non_empty(&self.keeper_privacy_set_root, "keeper privacy set root")?;
        ensure_bps(
            self.liquidation_discount_cap_bps,
            "liquidation discount cap bps",
        )?;
        ensure_bps(self.halt_threshold_bps, "halt threshold bps")?;
        if self.liquidation_discount_cap_bps > config.liquidation_discount_cap_bps {
            return Err(format!(
                "guardrail {} discount cap exceeds config",
                self.guardrail_id
            ));
        }
        if self.halt_threshold_bps < config.liquidation_halt_bps {
            return Err(format!(
                "guardrail {} halt threshold is below config floor",
                self.guardrail_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRiskCheck {
    pub check_id: String,
    pub pool_id: String,
    pub bucket_ids: BTreeSet<String>,
    pub prover_commitment: String,
    pub risk_delta_bps: i64,
    pub check_weight: u64,
    pub fee_units: u64,
    pub sponsor_commitment: String,
    pub nullifier: String,
    pub verifier_key_id: String,
    pub status: LowFeeRiskCheckStatus,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRiskCheck {
    pub fn new(
        pool_id: &str,
        label: &str,
        risk_delta_bps: i64,
        check_weight: u64,
        fee_units: u64,
        queued_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(pool_id, "risk check pool id")?;
        ensure_non_empty(label, "risk check label")?;
        let check_id = private_defi_low_fee_check_id(pool_id, label, queued_at_height);
        Ok(Self {
            prover_commitment: private_defi_commitment("LOW-FEE-CHECK-PROVER", &check_id),
            sponsor_commitment: private_defi_commitment("LOW-FEE-CHECK-SPONSOR", &check_id),
            nullifier: private_defi_nullifier("LOW-FEE-CHECK", &check_id),
            verifier_key_id: private_defi_verifier_key_id(
                RiskCircuitClass::LowFeeRiskCheck,
                pool_id,
                1,
            ),
            check_id,
            pool_id: pool_id.to_string(),
            bucket_ids: BTreeSet::new(),
            risk_delta_bps,
            check_weight,
            fee_units,
            status: LowFeeRiskCheckStatus::Verified,
            queued_at_height,
            expires_at_height: queued_at_height.saturating_add(ttl_blocks),
        })
    }

    pub fn attach_bucket(&mut self, bucket_id: impl Into<String>) {
        self.bucket_ids.insert(bucket_id.into());
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "pool_id": self.pool_id,
            "bucket_root": string_set_root("PRIVATE-DEFI-LOW-FEE-CHECK-BUCKETS", &self.bucket_ids),
            "prover_commitment": self.prover_commitment,
            "risk_delta_bps": self.risk_delta_bps,
            "check_weight": self.check_weight,
            "fee_units": self.fee_units,
            "sponsor_commitment": self.sponsor_commitment,
            "nullifier": self.nullifier,
            "verifier_key_id": self.verifier_key_id,
            "status": self.status.as_str(),
            "queued_at_height": self.queued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn check_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-LOW-FEE-RISK-CHECK",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
        current_height: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.check_id, "risk check id")?;
        ensure_non_empty(&self.pool_id, "risk check pool id")?;
        ensure_non_empty(&self.prover_commitment, "risk check prover commitment")?;
        ensure_non_empty(&self.sponsor_commitment, "risk check sponsor commitment")?;
        ensure_non_empty(&self.nullifier, "risk check nullifier")?;
        ensure_non_empty(&self.verifier_key_id, "risk check verifier key id")?;
        if self.check_weight > config.max_check_weight {
            return Err(format!(
                "risk check {} exceeds max check weight",
                self.check_id
            ));
        }
        if self.fee_units > config.max_fee_units {
            return Err(format!("risk check {} exceeds low-fee cap", self.check_id));
        }
        if current_height > self.expires_at_height && self.status == LowFeeRiskCheckStatus::Verified
        {
            return Err(format!(
                "risk check {} is verified after expiry",
                self.check_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSettlementReceipt {
    pub receipt_id: String,
    pub check_id: String,
    pub pool_id: String,
    pub before_pool_root: String,
    pub after_pool_root: String,
    pub before_bucket_root: String,
    pub after_bucket_root: String,
    pub oracle_root: String,
    pub verifier_key_root: String,
    pub settlement_height: u64,
    pub finality_height: u64,
    pub status: SettlementReceiptStatus,
    pub receipt_proof_commitment: String,
}

impl RiskSettlementReceipt {
    pub fn new(
        check: &LowFeeRiskCheck,
        before_pool_root: &str,
        after_pool_root: &str,
        before_bucket_root: &str,
        after_bucket_root: &str,
        oracle_root: &str,
        verifier_key_root: &str,
        settlement_height: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(&check.check_id, "receipt check id")?;
        ensure_non_empty(before_pool_root, "receipt before pool root")?;
        ensure_non_empty(after_pool_root, "receipt after pool root")?;
        let receipt_id = private_defi_receipt_id(&check.check_id, settlement_height);
        Ok(Self {
            receipt_proof_commitment: private_defi_commitment("RECEIPT-PROOF", &receipt_id),
            receipt_id,
            check_id: check.check_id.clone(),
            pool_id: check.pool_id.clone(),
            before_pool_root: before_pool_root.to_string(),
            after_pool_root: after_pool_root.to_string(),
            before_bucket_root: before_bucket_root.to_string(),
            after_bucket_root: after_bucket_root.to_string(),
            oracle_root: oracle_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            settlement_height,
            finality_height: settlement_height.saturating_add(2),
            status: SettlementReceiptStatus::Finalized,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "check_id": self.check_id,
            "pool_id": self.pool_id,
            "before_pool_root": self.before_pool_root,
            "after_pool_root": self.after_pool_root,
            "before_bucket_root": self.before_bucket_root,
            "after_bucket_root": self.after_bucket_root,
            "oracle_root": self.oracle_root,
            "verifier_key_root": self.verifier_key_root,
            "settlement_height": self.settlement_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "receipt_proof_commitment": self.receipt_proof_commitment,
        })
    }

    pub fn receipt_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-RISK-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.check_id, "receipt check id")?;
        ensure_non_empty(&self.pool_id, "receipt pool id")?;
        ensure_non_empty(&self.before_pool_root, "receipt before pool root")?;
        ensure_non_empty(&self.after_pool_root, "receipt after pool root")?;
        ensure_non_empty(&self.before_bucket_root, "receipt before bucket root")?;
        ensure_non_empty(&self.after_bucket_root, "receipt after bucket root")?;
        ensure_non_empty(&self.receipt_proof_commitment, "receipt proof commitment")?;
        if self.finality_height < self.settlement_height {
            return Err(format!(
                "receipt {} finality precedes settlement",
                self.receipt_id
            ));
        }
        if self.finality_height.saturating_sub(self.settlement_height)
            > config.max_settlement_delay_blocks
        {
            return Err(format!(
                "receipt {} exceeds settlement delay",
                self.receipt_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub target_receipt_id: String,
    pub reporter_commitment: String,
    pub evidence_commitment_root: String,
    pub contradicted_oracle_attestation_ids: BTreeSet<String>,
    pub contradicted_bucket_ids: BTreeSet<String>,
    pub bond_units: u64,
    pub status: ChallengeStatus,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub slashing_receipt_root: String,
}

impl ChallengeEvidence {
    pub fn new(
        target_receipt_id: &str,
        reporter_label: &str,
        opened_at_height: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        ensure_non_empty(target_receipt_id, "challenge target receipt id")?;
        ensure_non_empty(reporter_label, "challenge reporter label")?;
        let challenge_id =
            private_defi_challenge_id(target_receipt_id, reporter_label, opened_at_height);
        Ok(Self {
            reporter_commitment: private_defi_commitment("CHALLENGE-REPORTER", reporter_label),
            evidence_commitment_root: private_defi_commitment("CHALLENGE-EVIDENCE", &challenge_id),
            bond_units: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEFAULT_CHALLENGE_BOND_UNITS,
            status: ChallengeStatus::EvidenceAccepted,
            slashing_receipt_root: private_defi_commitment(
                "CHALLENGE-SLASHING-RECEIPT",
                &challenge_id,
            ),
            challenge_id,
            target_receipt_id: target_receipt_id.to_string(),
            contradicted_oracle_attestation_ids: BTreeSet::new(),
            contradicted_bucket_ids: BTreeSet::new(),
            opened_at_height,
            resolved_at_height: None,
        })
    }

    pub fn add_oracle_contradiction(&mut self, attestation_id: impl Into<String>) {
        self.contradicted_oracle_attestation_ids
            .insert(attestation_id.into());
    }

    pub fn add_bucket_contradiction(&mut self, bucket_id: impl Into<String>) {
        self.contradicted_bucket_ids.insert(bucket_id.into());
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "target_receipt_id": self.target_receipt_id,
            "reporter_commitment": self.reporter_commitment,
            "evidence_commitment_root": self.evidence_commitment_root,
            "contradicted_oracle_attestation_root": string_set_root("PRIVATE-DEFI-CHALLENGE-ORACLE-IDS", &self.contradicted_oracle_attestation_ids),
            "contradicted_bucket_root": string_set_root("PRIVATE-DEFI-CHALLENGE-BUCKET-IDS", &self.contradicted_bucket_ids),
            "bond_units": self.bond_units,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "slashing_receipt_root": self.slashing_receipt_root,
        })
    }

    pub fn evidence_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-CHALLENGE-EVIDENCE",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &PrivateDefiLiquidityRiskCircuitConfig,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.target_receipt_id, "challenge target receipt id")?;
        ensure_non_empty(&self.reporter_commitment, "challenge reporter commitment")?;
        ensure_non_empty(
            &self.evidence_commitment_root,
            "challenge evidence commitment root",
        )?;
        if self.bond_units < config.challenge_bond_units {
            return Err(format!(
                "challenge {} bond is below minimum",
                self.challenge_id
            ));
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err(format!(
                    "challenge {} resolves before opening",
                    self.challenge_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiLiquidityRiskCircuitCounters {
    pub pools: u64,
    pub exposure_buckets: u64,
    pub oracle_attestations: u64,
    pub verifier_keys: u64,
    pub guardrails: u64,
    pub low_fee_checks: u64,
    pub settlement_receipts: u64,
    pub challenge_evidence: u64,
    pub active_pools: u64,
    pub guarded_pools: u64,
    pub halted_severity_items: u64,
    pub total_fee_units: u64,
    pub total_check_weight: u64,
}

impl PrivateDefiLiquidityRiskCircuitCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "pools": self.pools,
            "exposure_buckets": self.exposure_buckets,
            "oracle_attestations": self.oracle_attestations,
            "verifier_keys": self.verifier_keys,
            "guardrails": self.guardrails,
            "low_fee_checks": self.low_fee_checks,
            "settlement_receipts": self.settlement_receipts,
            "challenge_evidence": self.challenge_evidence,
            "active_pools": self.active_pools,
            "guarded_pools": self.guarded_pools,
            "halted_severity_items": self.halted_severity_items,
            "total_fee_units": self.total_fee_units,
            "total_check_weight": self.total_check_weight,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiLiquidityRiskCircuitRoots {
    pub config_root: String,
    pub pool_envelope_root: String,
    pub exposure_bucket_root: String,
    pub oracle_attestation_root: String,
    pub verifier_key_root: String,
    pub liquidation_guardrail_root: String,
    pub low_fee_risk_check_root: String,
    pub settlement_receipt_root: String,
    pub challenge_evidence_root: String,
    pub severity_index_root: String,
    pub counter_root: String,
}

impl PrivateDefiLiquidityRiskCircuitRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "pool_envelope_root": self.pool_envelope_root,
            "exposure_bucket_root": self.exposure_bucket_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "verifier_key_root": self.verifier_key_root,
            "liquidation_guardrail_root": self.liquidation_guardrail_root,
            "low_fee_risk_check_root": self.low_fee_risk_check_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "challenge_evidence_root": self.challenge_evidence_root,
            "severity_index_root": self.severity_index_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn roots_root(&self) -> String {
        private_defi_liquidity_risk_circuit_payload_root(
            "PRIVATE-DEFI-RISK-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiLiquidityRiskCircuitState {
    pub config: PrivateDefiLiquidityRiskCircuitConfig,
    pub current_height: u64,
    pub current_epoch: u64,
    pub pool_envelopes: BTreeMap<String, ConfidentialPoolRiskEnvelope>,
    pub exposure_buckets: BTreeMap<String, ExposureBucket>,
    pub oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub verifier_keys: BTreeMap<String, RiskCircuitVerifierKey>,
    pub liquidation_guardrails: BTreeMap<String, LiquidationGuardrail>,
    pub low_fee_risk_checks: BTreeMap<String, LowFeeRiskCheck>,
    pub settlement_receipts: BTreeMap<String, RiskSettlementReceipt>,
    pub challenge_evidence: BTreeMap<String, ChallengeEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for PrivateDefiLiquidityRiskCircuitState {
    fn default() -> Self {
        Self {
            config: PrivateDefiLiquidityRiskCircuitConfig::default(),
            current_height: 0,
            current_epoch: 0,
            pool_envelopes: BTreeMap::new(),
            exposure_buckets: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            verifier_keys: BTreeMap::new(),
            liquidation_guardrails: BTreeMap::new(),
            low_fee_risk_checks: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            challenge_evidence: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }
}

impl PrivateDefiLiquidityRiskCircuitState {
    pub fn new(
        config: PrivateDefiLiquidityRiskCircuitConfig,
    ) -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> PrivateDefiLiquidityRiskCircuitResult<Self> {
        let mut state = Self {
            current_height: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEVNET_HEIGHT,
            current_epoch: PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_DEVNET_EPOCH,
            ..Self::default()
        };

        let verifier_specs = [
            ("amm-liquidity", RiskCircuitClass::LiquidityEnvelope),
            ("lending-health", RiskCircuitClass::HealthFactorEnvelope),
            ("perps-margin", RiskCircuitClass::MarginEnvelope),
            ("oracle-attestation", RiskCircuitClass::OracleAttestation),
            ("liquidation-guard", RiskCircuitClass::LiquidationGuard),
            ("low-fee-check", RiskCircuitClass::LowFeeRiskCheck),
            ("settlement-receipt", RiskCircuitClass::SettlementReceipt),
            ("challenge-evidence", RiskCircuitClass::ChallengeEvidence),
        ];
        for (label, circuit_class) in verifier_specs {
            state.insert_verifier_key(RiskCircuitVerifierKey::new(
                label,
                circuit_class,
                1,
                state.current_height,
            )?)?;
        }

        let mut wxmr_pool = ConfidentialPoolRiskEnvelope::new(
            "wxmr-usdd-stableswap",
            DefiVenueKind::StableSwap,
            8_000_000,
            10_400_000,
            4_200,
            2_900,
            state.current_height,
        )?;
        let mut lending_pool = ConfidentialPoolRiskEnvelope::new(
            "wxmr-private-lending",
            DefiVenueKind::Lending,
            4_500_000,
            7_200_000,
            6_100,
            4_700,
            state.current_height,
        )?;
        let mut perps_pool = ConfidentialPoolRiskEnvelope::new(
            "xmr-perp-isolated-margin",
            DefiVenueKind::Perps,
            2_100_000,
            3_400_000,
            7_300,
            5_800,
            state.current_height,
        )?;

        let mut bucket_refs = Vec::new();
        for (pool_id, kind, asset, lower, upper, concentration, stress) in [
            (
                &wxmr_pool.pool_id,
                ExposureBucketKind::AmmInventory,
                "wxmr-devnet",
                3_000_000,
                4_100_000,
                3_200,
                1_400,
            ),
            (
                &wxmr_pool.pool_id,
                ExposureBucketKind::AmmTwap,
                "usdd-devnet",
                2_700_000,
                3_900_000,
                2_900,
                1_100,
            ),
            (
                &lending_pool.pool_id,
                ExposureBucketKind::LendingCollateral,
                "wxmr-devnet",
                5_500_000,
                6_800_000,
                4_100,
                2_000,
            ),
            (
                &lending_pool.pool_id,
                ExposureBucketKind::LendingDebt,
                "usdd-devnet",
                2_200_000,
                3_100_000,
                4_700,
                2_400,
            ),
            (
                &perps_pool.pool_id,
                ExposureBucketKind::PerpsOpenInterest,
                "xmr-usdd-perp",
                1_400_000,
                2_600_000,
                5_400,
                3_200,
            ),
            (
                &perps_pool.pool_id,
                ExposureBucketKind::PerpsFunding,
                "xmr-usdd-funding",
                200_000,
                360_000,
                2_000,
                1_800,
            ),
        ] {
            let bucket = ExposureBucket::new(
                pool_id,
                kind,
                asset,
                lower,
                upper,
                concentration,
                stress,
                state.current_height,
            )?;
            bucket_refs.push((pool_id.clone(), bucket.bucket_id.clone()));
            state.insert_exposure_bucket(bucket)?;
        }

        for (pool_id, bucket_id) in bucket_refs {
            if pool_id.as_str() == wxmr_pool.pool_id {
                wxmr_pool.attach_exposure_bucket(bucket_id, state.current_height);
            } else if pool_id.as_str() == lending_pool.pool_id {
                lending_pool.attach_exposure_bucket(bucket_id, state.current_height);
            } else if pool_id.as_str() == perps_pool.pool_id {
                perps_pool.attach_exposure_bucket(bucket_id, state.current_height);
            }
        }

        for (feed, pool_id, confidence, quorum) in [
            ("feed-wxmr-usdd-spot", wxmr_pool.pool_id.clone(), 95, 7_200),
            (
                "feed-wxmr-lending-health",
                lending_pool.pool_id.clone(),
                120,
                7_500,
            ),
            (
                "feed-xmr-perp-index",
                perps_pool.pool_id.clone(),
                160,
                7_100,
            ),
        ] {
            let attestation = PqOracleAttestation::new(
                feed,
                &pool_id,
                "committee-private-risk-devnet",
                confidence,
                quorum,
                state.current_height,
                state.config.attestation_ttl_blocks,
            )?;
            if pool_id == wxmr_pool.pool_id {
                wxmr_pool.attach_oracle_attestation(
                    attestation.attestation_id.clone(),
                    state.current_height,
                );
            } else if pool_id == lending_pool.pool_id {
                lending_pool.attach_oracle_attestation(
                    attestation.attestation_id.clone(),
                    state.current_height,
                );
            } else if pool_id == perps_pool.pool_id {
                perps_pool.attach_oracle_attestation(
                    attestation.attestation_id.clone(),
                    state.current_height,
                );
            }
            state.insert_oracle_attestation(attestation)?;
        }

        let mut wxmr_guard = LiquidationGuardrail::new(&wxmr_pool.pool_id, "baseline", 1_000_000)?;
        let mut lending_guard =
            LiquidationGuardrail::new(&lending_pool.pool_id, "health-factor", 750_000)?;
        let mut perps_guard =
            LiquidationGuardrail::new(&perps_pool.pool_id, "margin-shock", 500_000)?;
        for bucket in state.exposure_buckets.values() {
            if bucket.pool_id == wxmr_pool.pool_id {
                wxmr_guard.protect_bucket(bucket.bucket_id.clone());
            } else if bucket.pool_id == lending_pool.pool_id {
                lending_guard.protect_bucket(bucket.bucket_id.clone());
            } else if bucket.pool_id == perps_pool.pool_id {
                perps_guard.protect_bucket(bucket.bucket_id.clone());
            }
        }
        state.insert_liquidation_guardrail(wxmr_guard)?;
        state.insert_liquidation_guardrail(lending_guard)?;
        state.insert_liquidation_guardrail(perps_guard)?;

        let mut check = LowFeeRiskCheck::new(
            &lending_pool.pool_id,
            "rebalance-risk-after-private-borrow",
            180,
            22_000,
            4,
            state.current_height,
            state.config.receipt_ttl_blocks,
        )?;
        for bucket in state.exposure_buckets.values() {
            if bucket.pool_id == lending_pool.pool_id {
                check.attach_bucket(bucket.bucket_id.clone());
            }
        }
        let check_id = check.check_id.clone();
        state.insert_low_fee_risk_check(check)?;

        state.insert_pool_envelope(wxmr_pool)?;
        state.insert_pool_envelope(lending_pool)?;
        state.insert_pool_envelope(perps_pool)?;

        let before_pool_root = merkle_root("PRIVATE-DEFI-DEVNET-BEFORE-POOLS", &[]);
        let before_bucket_root = merkle_root("PRIVATE-DEFI-DEVNET-BEFORE-BUCKETS", &[]);
        let check = state
            .low_fee_risk_checks
            .get(&check_id)
            .cloned()
            .ok_or_else(|| "devnet risk check missing after insertion".to_string())?;
        let receipt = RiskSettlementReceipt::new(
            &check,
            &before_pool_root,
            &state.pool_envelope_root(),
            &before_bucket_root,
            &state.exposure_bucket_root(),
            &state.oracle_attestation_root(),
            &state.verifier_key_root(),
            state.current_height.saturating_add(1),
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.insert_settlement_receipt(receipt)?;

        let mut challenge = ChallengeEvidence::new(
            &receipt_id,
            "devnet-watchtower-alpha",
            state.current_height.saturating_add(2),
        )?;
        if let Some(attestation_id) = state.oracle_attestations.keys().next() {
            challenge.add_oracle_contradiction(attestation_id.clone());
        }
        if let Some(bucket_id) = state.exposure_buckets.keys().next() {
            challenge.add_bucket_contradiction(bucket_id.clone());
        }
        state.insert_challenge_evidence(challenge)?;

        state.validate()?;
        Ok(state)
    }

    pub fn insert_pool_envelope(
        &mut self,
        envelope: ConfidentialPoolRiskEnvelope,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.pool_envelopes.len() >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_POOLS {
            return Err("private DeFi risk pool limit reached".to_string());
        }
        envelope.validate(&self.config)?;
        self.pool_envelopes
            .insert(envelope.pool_id.clone(), envelope);
        Ok(())
    }

    pub fn insert_exposure_bucket(
        &mut self,
        bucket: ExposureBucket,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.exposure_buckets.len() >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_BUCKETS {
            return Err("private DeFi exposure bucket limit reached".to_string());
        }
        bucket.validate(&self.config)?;
        self.exposure_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        Ok(())
    }

    pub fn insert_oracle_attestation(
        &mut self,
        attestation: PqOracleAttestation,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.oracle_attestations.len()
            >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_ORACLE_ATTESTATIONS
        {
            return Err("private DeFi oracle attestation limit reached".to_string());
        }
        attestation.validate(&self.config, self.current_height)?;
        self.oracle_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_verifier_key(
        &mut self,
        key: RiskCircuitVerifierKey,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.verifier_keys.len() >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_VERIFIER_KEYS {
            return Err("private DeFi verifier key limit reached".to_string());
        }
        key.validate(&self.config)?;
        self.verifier_keys.insert(key.verifier_key_id.clone(), key);
        Ok(())
    }

    pub fn insert_liquidation_guardrail(
        &mut self,
        guardrail: LiquidationGuardrail,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.liquidation_guardrails.len() >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_GUARDRAILS {
            return Err("private DeFi liquidation guardrail limit reached".to_string());
        }
        guardrail.validate(&self.config)?;
        self.liquidation_guardrails
            .insert(guardrail.guardrail_id.clone(), guardrail);
        Ok(())
    }

    pub fn insert_low_fee_risk_check(
        &mut self,
        check: LowFeeRiskCheck,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.low_fee_risk_checks.len() >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_LOW_FEE_CHECKS
        {
            return Err("private DeFi low-fee risk check limit reached".to_string());
        }
        check.validate(&self.config, self.current_height)?;
        if self.consumed_nullifiers.contains(&check.nullifier) {
            return Err(format!(
                "risk check {} reuses a consumed nullifier",
                check.check_id
            ));
        }
        self.consumed_nullifiers.insert(check.nullifier.clone());
        self.low_fee_risk_checks
            .insert(check.check_id.clone(), check);
        Ok(())
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: RiskSettlementReceipt,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.settlement_receipts.len() >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_RECEIPTS {
            return Err("private DeFi settlement receipt limit reached".to_string());
        }
        receipt.validate(&self.config)?;
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_challenge_evidence(
        &mut self,
        evidence: ChallengeEvidence,
    ) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        if self.challenge_evidence.len() >= PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_CHALLENGES {
            return Err("private DeFi challenge evidence limit reached".to_string());
        }
        evidence.validate(&self.config)?;
        self.challenge_evidence
            .insert(evidence.challenge_id.clone(), evidence);
        Ok(())
    }

    pub fn counters(&self) -> PrivateDefiLiquidityRiskCircuitCounters {
        let active_pools = self
            .pool_envelopes
            .values()
            .filter(|pool| pool.status == PoolEnvelopeStatus::Active)
            .count() as u64;
        let guarded_pools = self
            .pool_envelopes
            .values()
            .filter(|pool| pool.status == PoolEnvelopeStatus::Guarded)
            .count() as u64;
        let halted_pool_count = self
            .pool_envelopes
            .values()
            .filter(|pool| {
                matches!(
                    pool.severity,
                    RiskSeverity::Halted | RiskSeverity::Quarantined
                )
            })
            .count() as u64;
        let halted_bucket_count = self
            .exposure_buckets
            .values()
            .filter(|bucket| {
                matches!(
                    bucket.severity,
                    RiskSeverity::Halted | RiskSeverity::Quarantined
                )
            })
            .count() as u64;
        let total_fee_units = self
            .low_fee_risk_checks
            .values()
            .map(|check| check.fee_units)
            .sum();
        let total_check_weight = self
            .low_fee_risk_checks
            .values()
            .map(|check| check.check_weight)
            .sum();
        PrivateDefiLiquidityRiskCircuitCounters {
            pools: self.pool_envelopes.len() as u64,
            exposure_buckets: self.exposure_buckets.len() as u64,
            oracle_attestations: self.oracle_attestations.len() as u64,
            verifier_keys: self.verifier_keys.len() as u64,
            guardrails: self.liquidation_guardrails.len() as u64,
            low_fee_checks: self.low_fee_risk_checks.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            challenge_evidence: self.challenge_evidence.len() as u64,
            active_pools,
            guarded_pools,
            halted_severity_items: halted_pool_count.saturating_add(halted_bucket_count),
            total_fee_units,
            total_check_weight,
        }
    }

    pub fn roots(&self) -> PrivateDefiLiquidityRiskCircuitRoots {
        PrivateDefiLiquidityRiskCircuitRoots {
            config_root: self.config.config_root(),
            pool_envelope_root: self.pool_envelope_root(),
            exposure_bucket_root: self.exposure_bucket_root(),
            oracle_attestation_root: self.oracle_attestation_root(),
            verifier_key_root: self.verifier_key_root(),
            liquidation_guardrail_root: self.liquidation_guardrail_root(),
            low_fee_risk_check_root: self.low_fee_risk_check_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            challenge_evidence_root: self.challenge_evidence_root(),
            severity_index_root: self.severity_index_root(),
            counter_root: private_defi_liquidity_risk_circuit_payload_root(
                "PRIVATE-DEFI-RISK-COUNTERS",
                &self.counters().public_record(),
            ),
        }
    }

    pub fn pool_envelope_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-POOL-ENVELOPES",
            &self.pool_envelopes,
            ConfidentialPoolRiskEnvelope::public_record,
        )
    }

    pub fn exposure_bucket_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-EXPOSURE-BUCKETS",
            &self.exposure_buckets,
            ExposureBucket::public_record,
        )
    }

    pub fn oracle_attestation_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-PQ-ORACLE-ATTESTATIONS",
            &self.oracle_attestations,
            PqOracleAttestation::public_record,
        )
    }

    pub fn verifier_key_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-RISK-VERIFIER-KEYS",
            &self.verifier_keys,
            RiskCircuitVerifierKey::public_record,
        )
    }

    pub fn liquidation_guardrail_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-LIQUIDATION-GUARDRAILS",
            &self.liquidation_guardrails,
            LiquidationGuardrail::public_record,
        )
    }

    pub fn low_fee_risk_check_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-LOW-FEE-RISK-CHECKS",
            &self.low_fee_risk_checks,
            LowFeeRiskCheck::public_record,
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-RISK-SETTLEMENT-RECEIPTS",
            &self.settlement_receipts,
            RiskSettlementReceipt::public_record,
        )
    }

    pub fn challenge_evidence_root(&self) -> String {
        map_root(
            "PRIVATE-DEFI-CHALLENGE-EVIDENCE-SET",
            &self.challenge_evidence,
            ChallengeEvidence::public_record,
        )
    }

    pub fn severity_index_root(&self) -> String {
        let mut leaves = Vec::new();
        for pool in self.pool_envelopes.values() {
            leaves.push(json!({
                "id": pool.pool_id,
                "kind": "pool",
                "severity": pool.severity.as_str(),
                "risk_score_bps": pool.risk_score_bps,
            }));
        }
        for bucket in self.exposure_buckets.values() {
            leaves.push(json!({
                "id": bucket.bucket_id,
                "kind": "bucket",
                "severity": bucket.severity.as_str(),
                "risk_score_bps": bucket.risk_score_bps,
            }));
        }
        merkle_root("PRIVATE-DEFI-SEVERITY-INDEX", &leaves)
    }

    pub fn state_root(&self) -> String {
        private_defi_liquidity_risk_circuit_state_root_from_record(
            &self.public_record_without_root(),
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "consumed_nullifier_root": string_set_root("PRIVATE-DEFI-CONSUMED-NULLIFIERS", &self.consumed_nullifiers),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateDefiLiquidityRiskCircuitResult<()> {
        self.config.validate()?;
        if self.pool_envelopes.len() > PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_POOLS {
            return Err("private DeFi risk pool limit exceeded".to_string());
        }
        if self.exposure_buckets.len() > PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_BUCKETS {
            return Err("private DeFi exposure bucket limit exceeded".to_string());
        }
        if self.oracle_attestations.len()
            > PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_ORACLE_ATTESTATIONS
        {
            return Err("private DeFi oracle attestation limit exceeded".to_string());
        }
        for key in self.verifier_keys.values() {
            key.validate(&self.config)?;
        }
        for pool in self.pool_envelopes.values() {
            pool.validate(&self.config)?;
            if !self.verifier_keys.contains_key(&pool.verifier_key_id) {
                return Err(format!(
                    "pool {} references missing verifier key",
                    pool.pool_id
                ));
            }
            if !self.liquidation_guardrails.contains_key(&pool.guardrail_id) {
                return Err(format!(
                    "pool {} references missing guardrail",
                    pool.pool_id
                ));
            }
            for bucket_id in &pool.exposure_bucket_ids {
                if !self.exposure_buckets.contains_key(bucket_id) {
                    return Err(format!(
                        "pool {} references missing bucket {}",
                        pool.pool_id, bucket_id
                    ));
                }
            }
            for attestation_id in &pool.oracle_attestation_ids {
                if !self.oracle_attestations.contains_key(attestation_id) {
                    return Err(format!(
                        "pool {} references missing oracle attestation {}",
                        pool.pool_id, attestation_id
                    ));
                }
            }
        }
        for bucket in self.exposure_buckets.values() {
            bucket.validate(&self.config)?;
            if !self.pool_envelopes.contains_key(&bucket.pool_id) {
                return Err(format!(
                    "bucket {} references missing pool",
                    bucket.bucket_id
                ));
            }
        }
        for attestation in self.oracle_attestations.values() {
            attestation.validate(&self.config, self.current_height)?;
            if !self.pool_envelopes.contains_key(&attestation.pool_id) {
                return Err(format!(
                    "oracle attestation {} references missing pool",
                    attestation.attestation_id
                ));
            }
        }
        for guardrail in self.liquidation_guardrails.values() {
            guardrail.validate(&self.config)?;
            if !self.pool_envelopes.contains_key(&guardrail.pool_id) {
                return Err(format!(
                    "guardrail {} references missing pool",
                    guardrail.guardrail_id
                ));
            }
        }
        for check in self.low_fee_risk_checks.values() {
            check.validate(&self.config, self.current_height)?;
            if !self.pool_envelopes.contains_key(&check.pool_id) {
                return Err(format!(
                    "risk check {} references missing pool",
                    check.check_id
                ));
            }
            for bucket_id in &check.bucket_ids {
                if !self.exposure_buckets.contains_key(bucket_id) {
                    return Err(format!(
                        "risk check {} references missing bucket {}",
                        check.check_id, bucket_id
                    ));
                }
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate(&self.config)?;
            if !self.low_fee_risk_checks.contains_key(&receipt.check_id) {
                return Err(format!(
                    "receipt {} references missing risk check",
                    receipt.receipt_id
                ));
            }
        }
        for evidence in self.challenge_evidence.values() {
            evidence.validate(&self.config)?;
            if !self
                .settlement_receipts
                .contains_key(&evidence.target_receipt_id)
            {
                return Err(format!(
                    "challenge {} references missing receipt",
                    evidence.challenge_id
                ));
            }
        }
        Ok(())
    }

    pub fn advance_devnet_height(
        &mut self,
        blocks: u64,
    ) -> PrivateDefiLiquidityRiskCircuitResult<String> {
        self.current_height = self.current_height.saturating_add(blocks);
        if self.config.epoch_blocks > 0 {
            self.current_epoch = self.current_height / self.config.epoch_blocks;
        }
        self.expire_old_items();
        self.validate()?;
        Ok(self.state_root())
    }

    fn expire_old_items(&mut self) {
        for attestation in self.oracle_attestations.values_mut() {
            if self.current_height > attestation.expires_at_height
                && matches!(
                    attestation.status,
                    OracleAttestationStatus::Submitted
                        | OracleAttestationStatus::QuorumChecked
                        | OracleAttestationStatus::Counted
                )
            {
                attestation.status = OracleAttestationStatus::Expired;
            }
        }
        for check in self.low_fee_risk_checks.values_mut() {
            if self.current_height > check.expires_at_height
                && matches!(
                    check.status,
                    LowFeeRiskCheckStatus::Queued
                        | LowFeeRiskCheckStatus::Verified
                        | LowFeeRiskCheckStatus::Sponsored
                )
            {
                check.status = LowFeeRiskCheckStatus::Expired;
            }
        }
    }
}

pub fn private_defi_liquidity_risk_circuit_state_root_from_record(record: &Value) -> String {
    private_defi_liquidity_risk_circuit_payload_root(
        "PRIVATE-DEFI-LIQUIDITY-RISK-CIRCUIT-STATE",
        record,
    )
}

pub fn private_defi_liquidity_risk_circuit_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_defi_pool_id(label: &str, venue_kind: DefiVenueKind) -> String {
    domain_hash(
        "PRIVATE-DEFI-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(venue_kind.as_str()),
        ],
        16,
    )
}

pub fn private_defi_bucket_id(
    pool_id: &str,
    bucket_kind: ExposureBucketKind,
    asset_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-BUCKET-ID",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(bucket_kind.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(height as i128),
        ],
        16,
    )
}

pub fn private_defi_oracle_attestation_id(feed_id: &str, pool_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-DEFI-ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(feed_id),
            HashPart::Str(pool_id),
            HashPart::Int(height as i128),
        ],
        16,
    )
}

pub fn private_defi_verifier_key_id(
    circuit_class: RiskCircuitClass,
    label: &str,
    version: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEFI-VERIFIER-KEY-ID",
        &[
            HashPart::Str(circuit_class.as_str()),
            HashPart::Str(label),
            HashPart::Int(version as i128),
        ],
        16,
    )
}

pub fn private_defi_guardrail_id(pool_id: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-DEFI-GUARDRAIL-ID",
        &[HashPart::Str(pool_id), HashPart::Str(label)],
        16,
    )
}

pub fn private_defi_low_fee_check_id(pool_id: &str, label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-DEFI-LOW-FEE-CHECK-ID",
        &[
            HashPart::Str(pool_id),
            HashPart::Str(label),
            HashPart::Int(height as i128),
        ],
        16,
    )
}

pub fn private_defi_receipt_id(check_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-DEFI-RECEIPT-ID",
        &[HashPart::Str(check_id), HashPart::Int(height as i128)],
        16,
    )
}

pub fn private_defi_challenge_id(receipt_id: &str, reporter_label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-DEFI-CHALLENGE-ID",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(reporter_label),
            HashPart::Int(height as i128),
        ],
        16,
    )
}

pub fn private_defi_commitment(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn private_defi_nullifier(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("{domain}-NULLIFIER"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateDefiLiquidityRiskCircuitResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> PrivateDefiLiquidityRiskCircuitResult<()> {
    if value > PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn bucket_risk_score(concentration_bps: u64, stress_loss_bps: u64) -> u64 {
    concentration_bps
        .saturating_mul(3)
        .saturating_add(stress_loss_bps.saturating_mul(4))
        .saturating_div(7)
        .min(PRIVATE_DEFI_LIQUIDITY_RISK_CIRCUIT_MAX_BPS)
}

fn severity_from_risk_score(risk_score_bps: u64) -> RiskSeverity {
    match risk_score_bps {
        0..=2_499 => RiskSeverity::Green,
        2_500..=3_999 => RiskSeverity::Watch,
        4_000..=5_999 => RiskSeverity::Caution,
        6_000..=7_499 => RiskSeverity::Guarded,
        7_500..=8_999 => RiskSeverity::Halted,
        _ => RiskSeverity::Quarantined,
    }
}

fn circuit_class_for_bucket(bucket_kind: ExposureBucketKind) -> RiskCircuitClass {
    match bucket_kind {
        ExposureBucketKind::AmmInventory | ExposureBucketKind::AmmTwap => {
            RiskCircuitClass::LiquidityEnvelope
        }
        ExposureBucketKind::LendingCollateral
        | ExposureBucketKind::LendingDebt
        | ExposureBucketKind::VaultShare => RiskCircuitClass::HealthFactorEnvelope,
        ExposureBucketKind::PerpsOpenInterest | ExposureBucketKind::PerpsFunding => {
            RiskCircuitClass::MarginEnvelope
        }
        ExposureBucketKind::LiquidationQueue => RiskCircuitClass::LiquidationGuard,
        ExposureBucketKind::OracleStaleness => RiskCircuitClass::OracleAttestation,
        ExposureBucketKind::FeeSponsor => RiskCircuitClass::LowFeeRiskCheck,
    }
}

fn supported_venues_for_circuit(circuit_class: RiskCircuitClass) -> BTreeSet<DefiVenueKind> {
    let mut venues = BTreeSet::new();
    match circuit_class {
        RiskCircuitClass::LiquidityEnvelope => {
            venues.insert(DefiVenueKind::Amm);
            venues.insert(DefiVenueKind::StableSwap);
            venues.insert(DefiVenueKind::DarkPool);
        }
        RiskCircuitClass::HealthFactorEnvelope => {
            venues.insert(DefiVenueKind::Lending);
            venues.insert(DefiVenueKind::Vault);
        }
        RiskCircuitClass::MarginEnvelope => {
            venues.insert(DefiVenueKind::Perps);
        }
        RiskCircuitClass::OracleAttestation
        | RiskCircuitClass::LiquidationGuard
        | RiskCircuitClass::LowFeeRiskCheck
        | RiskCircuitClass::SettlementReceipt
        | RiskCircuitClass::ChallengeEvidence => {
            venues.insert(DefiVenueKind::Amm);
            venues.insert(DefiVenueKind::Lending);
            venues.insert(DefiVenueKind::Perps);
            venues.insert(DefiVenueKind::Vault);
            venues.insert(DefiVenueKind::StableSwap);
            venues.insert(DefiVenueKind::DarkPool);
        }
    }
    venues
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn venue_kind_set_root(values: &BTreeSet<DefiVenueKind>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!(value.as_str()))
        .collect::<Vec<_>>();
    merkle_root("PRIVATE-DEFI-VERIFIER-SUPPORTED-VENUES", &leaves)
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_deterministic_root() {
        let state = PrivateDefiLiquidityRiskCircuitState::devnet();
        assert!(state.is_ok());
        let state = match state {
            Ok(value) => value,
            Err(error) => {
                assert!(error.is_empty());
                return;
            }
        };
        assert!(state.validate().is_ok());
        assert_eq!(
            state.state_root(),
            private_defi_liquidity_risk_circuit_state_root_from_record(
                &state.public_record_without_root()
            )
        );
        assert_eq!(state.counters().pools, 3);
        assert_eq!(state.counters().exposure_buckets, 6);
    }

    #[test]
    fn low_fee_check_rejects_reused_nullifier() {
        let mut state = PrivateDefiLiquidityRiskCircuitState::default();
        let pool =
            ConfidentialPoolRiskEnvelope::new("test-pool", DefiVenueKind::Amm, 1, 2, 100, 100, 1);
        let pool = match pool {
            Ok(value) => value,
            Err(error) => {
                assert!(error.is_empty());
                return;
            }
        };
        let check = LowFeeRiskCheck::new(&pool.pool_id, "same", 1, 1, 1, 1, 10);
        let check = match check {
            Ok(value) => value,
            Err(error) => {
                assert!(error.is_empty());
                return;
            }
        };
        let duplicate = check.clone();
        assert!(state.insert_low_fee_risk_check(check).is_ok());
        assert!(state.insert_low_fee_risk_check(duplicate).is_err());
    }
}
