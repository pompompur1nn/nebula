use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-defi-oracle-risk-circuit-breaker-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_PROTOCOL: &str =
    "pq-confidential-defi-oracle-risk-circuit-breaker";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-risk-oracle-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_ENCRYPTION_SUITE:
    &str = "ML-KEM-1024+Poseidon2-transcript+AEAD-risk-observation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEVNET_HEIGHT: u64 =
    1_872_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_DOMAINS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_OBSERVATIONS:
    usize = 67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_EXPOSURES:
    usize = 33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_WINDOWS:
    usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_RECEIPTS:
    usize = 67_108_864;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_CHALLENGES:
    usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_TICKETS:
    usize = 33_554_432;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_NULLIFIERS:
    usize = 134_217_728;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_SLASHING:
    usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_TARGET_PRIVACY_SET:
    u64 = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT:
    u64 = 67;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_OBSERVATION_TTL_BLOCKS:
    u64 = 180;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_GUARDRAIL_WINDOW_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_CHALLENGE_TTL_BLOCKS:
    u64 = 720;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS:
    u64 = 10_080;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_CHALLENGE_BOND_MILLIS:
    u64 = 25;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDomainKind {
    Lending,
    StableSwap,
    Perpetuals,
    Options,
    SyntheticAsset,
    BridgeReserve,
    LiquidationAuction,
    InsurancePool,
    GovernanceParameter,
    Custom,
}

impl RiskDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lending => "lending",
            Self::StableSwap => "stable_swap",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::SyntheticAsset => "synthetic_asset",
            Self::BridgeReserve => "bridge_reserve",
            Self::LiquidationAuction => "liquidation_auction",
            Self::InsurancePool => "insurance_pool",
            Self::GovernanceParameter => "governance_parameter",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDomainStatus {
    Proposed,
    Active,
    Watchlisted,
    Paused,
    Resuming,
    Retired,
}

impl RiskDomainStatus {
    pub fn accepts_observations(self) -> bool {
        matches!(self, Self::Active | Self::Watchlisted)
    }

    pub fn can_pause(self) -> bool {
        matches!(self, Self::Active | Self::Watchlisted | Self::Resuming)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskMetricKind {
    Volatility,
    LiquidationDepth,
    OracleDeviation,
    BridgeReserveRatio,
    StablecoinPeg,
    CollateralConcentration,
    FundingRate,
    OpenInterest,
    WithdrawalQueue,
    Composite,
}

impl RiskMetricKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Volatility => "volatility",
            Self::LiquidationDepth => "liquidation_depth",
            Self::OracleDeviation => "oracle_deviation",
            Self::BridgeReserveRatio => "bridge_reserve_ratio",
            Self::StablecoinPeg => "stablecoin_peg",
            Self::CollateralConcentration => "collateral_concentration",
            Self::FundingRate => "funding_rate",
            Self::OpenInterest => "open_interest",
            Self::WithdrawalQueue => "withdrawal_queue",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Encrypted,
    Attested,
    Windowed,
    Challenged,
    Stale,
    Rejected,
    Slashed,
}

impl ObservationStatus {
    pub fn can_attest(self) -> bool {
        matches!(self, Self::Encrypted | Self::Challenged)
    }

    pub fn anchors_guardrail(self) -> bool {
        matches!(self, Self::Attested | Self::Windowed | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreSigners,
    Quarantined,
    Invalid,
    Revoked,
}

impl AttestationVerdict {
    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarning)
    }

    pub fn is_fault(self) -> bool {
        matches!(self, Self::Invalid | Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailSeverity {
    Info,
    Watch,
    Throttle,
    FreezeLiquidations,
    EmergencyPause,
}

impl GuardrailSeverity {
    pub fn pauses_market(self) -> bool {
        matches!(self, Self::EmergencyPause)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseStatus {
    Requested,
    Active,
    ReceiptPublished,
    Resolved,
    Rejected,
}

impl PauseStatus {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Active | Self::ReceiptPublished
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Upheld,
    Rejected,
    Expired,
    Slashed,
}

impl ChallengeStatus {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketScope {
    Observation,
    Exposure,
    Guardrail,
    Pause,
    Challenge,
    Slashing,
}

impl TicketScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Exposure => "exposure",
            Self::Guardrail => "guardrail",
            Self::Pause => "pause",
            Self::Challenge => "challenge",
            Self::Slashing => "slashing",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Submitted,
    Verified,
    Executed,
    Rejected,
    Appealed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub max_domains: usize,
    pub max_observations: usize,
    pub max_attestations: usize,
    pub max_exposure_snapshots: usize,
    pub max_guardrail_windows: usize,
    pub max_pause_receipts: usize,
    pub max_challenges: usize,
    pub max_disclosure_tickets: usize,
    pub max_nullifiers: usize,
    pub max_slashing_evidence: usize,
    pub min_privacy_set: u64,
    pub target_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub min_committee_weight: u64,
    pub observation_ttl_blocks: u64,
    pub guardrail_window_blocks: u64,
    pub challenge_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_challenge_bond_millis: u64,
    pub require_selective_disclosure_ticket: bool,
    pub require_nullifier_fence: bool,
    pub allow_devnet_resume: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_domains:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_DOMAINS,
            max_observations:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_OBSERVATIONS,
            max_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_exposure_snapshots:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_EXPOSURES,
            max_guardrail_windows:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_WINDOWS,
            max_pause_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_challenges:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_CHALLENGES,
            max_disclosure_tickets:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_TICKETS,
            max_nullifiers:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_slashing_evidence:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_SLASHING,
            min_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_TARGET_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_weight:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT,
            observation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_OBSERVATION_TTL_BLOCKS,
            guardrail_window_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_GUARDRAIL_WINDOW_BLOCKS,
            challenge_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_CHALLENGE_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            max_challenge_bond_millis:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEFAULT_MAX_CHALLENGE_BOND_MILLIS,
            require_selective_disclosure_ticket: true,
            require_nullifier_fence: true,
            allow_devnet_resume: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        if self.max_domains == 0 {
            return Err("risk circuit breaker max_domains must be positive".to_string());
        }
        if self.max_observations == 0 {
            return Err("risk circuit breaker max_observations must be positive".to_string());
        }
        if self.max_attestations == 0 {
            return Err("risk circuit breaker max_attestations must be positive".to_string());
        }
        if self.max_exposure_snapshots == 0 {
            return Err("risk circuit breaker max_exposure_snapshots must be positive".to_string());
        }
        if self.max_guardrail_windows == 0 {
            return Err("risk circuit breaker max_guardrail_windows must be positive".to_string());
        }
        if self.max_pause_receipts == 0 {
            return Err("risk circuit breaker max_pause_receipts must be positive".to_string());
        }
        if self.max_challenges == 0 {
            return Err("risk circuit breaker max_challenges must be positive".to_string());
        }
        if self.max_disclosure_tickets == 0 {
            return Err("risk circuit breaker max_disclosure_tickets must be positive".to_string());
        }
        if self.max_nullifiers == 0 {
            return Err("risk circuit breaker max_nullifiers must be positive".to_string());
        }
        if self.max_slashing_evidence == 0 {
            return Err("risk circuit breaker max_slashing_evidence must be positive".to_string());
        }
        if self.min_privacy_set == 0 {
            return Err("risk circuit breaker min_privacy_set must be positive".to_string());
        }
        if self.target_privacy_set < self.min_privacy_set {
            return Err("risk circuit breaker target privacy set is below minimum".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("risk circuit breaker PQ security floor is too low".to_string());
        }
        if self.min_committee_weight == 0
            || self.min_committee_weight
                > PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_MAX_BPS
        {
            return Err("risk circuit breaker committee weight must be within BPS".to_string());
        }
        if self.observation_ttl_blocks == 0
            || self.guardrail_window_blocks == 0
            || self.challenge_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
        {
            return Err("risk circuit breaker TTL values must be positive".to_string());
        }
        if self.max_challenge_bond_millis
            > PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_MAX_BPS
        {
            return Err("risk circuit breaker challenge bond exceeds BPS scale".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_domains": self.max_domains,
            "max_observations": self.max_observations,
            "max_attestations": self.max_attestations,
            "max_exposure_snapshots": self.max_exposure_snapshots,
            "max_guardrail_windows": self.max_guardrail_windows,
            "max_pause_receipts": self.max_pause_receipts,
            "max_challenges": self.max_challenges,
            "max_disclosure_tickets": self.max_disclosure_tickets,
            "max_nullifiers": self.max_nullifiers,
            "max_slashing_evidence": self.max_slashing_evidence,
            "min_privacy_set": self.min_privacy_set,
            "target_privacy_set": self.target_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_committee_weight": self.min_committee_weight,
            "observation_ttl_blocks": self.observation_ttl_blocks,
            "guardrail_window_blocks": self.guardrail_window_blocks,
            "challenge_ttl_blocks": self.challenge_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_challenge_bond_millis": self.max_challenge_bond_millis,
            "require_selective_disclosure_ticket": self.require_selective_disclosure_ticket,
            "require_nullifier_fence": self.require_nullifier_fence,
            "allow_devnet_resume": self.allow_devnet_resume,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub domains_registered: u64,
    pub observations_submitted: u64,
    pub attestations_submitted: u64,
    pub exposure_snapshots_submitted: u64,
    pub guardrail_windows_opened: u64,
    pub market_pauses: u64,
    pub market_resumes: u64,
    pub pause_receipts_published: u64,
    pub challenges_opened: u64,
    pub challenges_upheld: u64,
    pub disclosure_tickets_issued: u64,
    pub nullifier_fences_inserted: u64,
    pub slashing_evidence_submitted: u64,
    pub slashing_executed: u64,
    pub total_challenge_bond_millis: u128,
    pub total_slashed_weight: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "domains_registered": self.domains_registered,
            "observations_submitted": self.observations_submitted,
            "attestations_submitted": self.attestations_submitted,
            "exposure_snapshots_submitted": self.exposure_snapshots_submitted,
            "guardrail_windows_opened": self.guardrail_windows_opened,
            "market_pauses": self.market_pauses,
            "market_resumes": self.market_resumes,
            "pause_receipts_published": self.pause_receipts_published,
            "challenges_opened": self.challenges_opened,
            "challenges_upheld": self.challenges_upheld,
            "disclosure_tickets_issued": self.disclosure_tickets_issued,
            "nullifier_fences_inserted": self.nullifier_fences_inserted,
            "slashing_evidence_submitted": self.slashing_evidence_submitted,
            "slashing_executed": self.slashing_executed,
            "total_challenge_bond_millis": self.total_challenge_bond_millis.to_string(),
            "total_slashed_weight": self.total_slashed_weight.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub domains_root: String,
    pub observations_root: String,
    pub attestations_root: String,
    pub exposures_root: String,
    pub guardrails_root: String,
    pub pauses_root: String,
    pub receipts_root: String,
    pub challenges_root: String,
    pub disclosure_tickets_root: String,
    pub nullifiers_root: String,
    pub slashing_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "domains_root": self.domains_root,
            "observations_root": self.observations_root,
            "attestations_root": self.attestations_root,
            "exposures_root": self.exposures_root,
            "guardrails_root": self.guardrails_root,
            "pauses_root": self.pauses_root,
            "receipts_root": self.receipts_root,
            "challenges_root": self.challenges_root,
            "disclosure_tickets_root": self.disclosure_tickets_root,
            "nullifiers_root": self.nullifiers_root,
            "slashing_root": self.slashing_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskThresholds {
    pub max_volatility_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub min_liquidation_depth_bps: u64,
    pub min_bridge_reserve_bps: u64,
    pub max_open_interest_bps: u64,
    pub max_concentration_bps: u64,
}

impl RiskThresholds {
    pub fn validate(&self) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let max_bps = PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_MAX_BPS;
        if self.max_volatility_bps > max_bps
            || self.max_oracle_deviation_bps > max_bps
            || self.min_liquidation_depth_bps > max_bps
            || self.min_bridge_reserve_bps > max_bps
            || self.max_open_interest_bps > max_bps
            || self.max_concentration_bps > max_bps
        {
            return Err("risk thresholds must be expressed in BPS".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_volatility_bps": self.max_volatility_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "min_liquidation_depth_bps": self.min_liquidation_depth_bps,
            "min_bridge_reserve_bps": self.min_bridge_reserve_bps,
            "max_open_interest_bps": self.max_open_interest_bps,
            "max_concentration_bps": self.max_concentration_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskDomain {
    pub domain_id: String,
    pub market_id: String,
    pub kind: RiskDomainKind,
    pub status: RiskDomainStatus,
    pub encrypted_policy_root: String,
    pub committee_root: String,
    pub thresholds: RiskThresholds,
    pub min_committee_weight: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_height: u64,
    pub updated_height: u64,
    pub last_observation_height: Option<u64>,
    pub active_pause_id: Option<String>,
    pub metadata_commitment: String,
}

impl RiskDomain {
    pub fn public_record(&self) -> Value {
        json!({
            "domain_id": self.domain_id,
            "market_id": self.market_id,
            "kind": self.kind,
            "status": self.status,
            "encrypted_policy_root": self.encrypted_policy_root,
            "committee_root": self.committee_root,
            "thresholds": self.thresholds.public_record(),
            "min_committee_weight": self.min_committee_weight,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "last_observation_height": self.last_observation_height,
            "active_pause_id": self.active_pause_id,
            "metadata_commitment": self.metadata_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedRiskObservation {
    pub observation_id: String,
    pub domain_id: String,
    pub metric: RiskMetricKind,
    pub status: ObservationStatus,
    pub ciphertext_root: String,
    pub encrypted_payload_hash: String,
    pub exposure_snapshot_id: Option<String>,
    pub reporter_commitment: String,
    pub committee_hint_root: String,
    pub nullifier: String,
    pub fee_millis: u64,
    pub observed_height: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

impl EncryptedRiskObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "domain_id": self.domain_id,
            "metric": self.metric,
            "status": self.status,
            "ciphertext_root": self.ciphertext_root,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "exposure_snapshot_id": self.exposure_snapshot_id,
            "reporter_commitment": self.reporter_commitment,
            "committee_hint_root": self.committee_hint_root,
            "nullifier": self.nullifier,
            "fee_millis": self.fee_millis,
            "observed_height": self.observed_height,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleCommitteeAttestation {
    pub attestation_id: String,
    pub observation_id: String,
    pub domain_id: String,
    pub committee_root: String,
    pub signer_bitmap_root: String,
    pub aggregate_signature_root: String,
    pub transcript_root: String,
    pub verdict: AttestationVerdict,
    pub signed_weight: u64,
    pub min_required_weight: u64,
    pub attested_height: u64,
    pub pq_security_bits: u16,
}

impl OracleCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "observation_id": self.observation_id,
            "domain_id": self.domain_id,
            "committee_root": self.committee_root,
            "signer_bitmap_root": self.signer_bitmap_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "transcript_root": self.transcript_root,
            "verdict": self.verdict,
            "signed_weight": self.signed_weight,
            "min_required_weight": self.min_required_weight,
            "attested_height": self.attested_height,
            "pq_security_bits": self.pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateMarketExposureSnapshot {
    pub snapshot_id: String,
    pub domain_id: String,
    pub encrypted_exposure_root: String,
    pub liability_commitment_root: String,
    pub collateral_commitment_root: String,
    pub liquidation_queue_root: String,
    pub maker_set_root: String,
    pub exposure_band_bps: u64,
    pub leverage_band_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub captured_height: u64,
    pub submitted_height: u64,
}

impl PrivateMarketExposureSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "domain_id": self.domain_id,
            "encrypted_exposure_root": self.encrypted_exposure_root,
            "liability_commitment_root": self.liability_commitment_root,
            "collateral_commitment_root": self.collateral_commitment_root,
            "liquidation_queue_root": self.liquidation_queue_root,
            "maker_set_root": self.maker_set_root,
            "exposure_band_bps": self.exposure_band_bps,
            "leverage_band_bps": self.leverage_band_bps,
            "privacy_set_size": self.privacy_set_size,
            "nullifier": self.nullifier,
            "captured_height": self.captured_height,
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardrailWindow {
    pub window_id: String,
    pub domain_id: String,
    pub observation_ids: Vec<String>,
    pub exposure_snapshot_id: Option<String>,
    pub severity: GuardrailSeverity,
    pub volatility_guard_bps: u64,
    pub liquidation_guard_bps: u64,
    pub oracle_deviation_guard_bps: u64,
    pub opens_height: u64,
    pub closes_height: u64,
    pub pause_id: Option<String>,
    pub guardrail_root: String,
}

impl GuardrailWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "domain_id": self.domain_id,
            "observation_ids": self.observation_ids,
            "exposure_snapshot_id": self.exposure_snapshot_id,
            "severity": self.severity,
            "volatility_guard_bps": self.volatility_guard_bps,
            "liquidation_guard_bps": self.liquidation_guard_bps,
            "oracle_deviation_guard_bps": self.oracle_deviation_guard_bps,
            "opens_height": self.opens_height,
            "closes_height": self.closes_height,
            "pause_id": self.pause_id,
            "guardrail_root": self.guardrail_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyPauseReceipt {
    pub pause_id: String,
    pub domain_id: String,
    pub market_id: String,
    pub window_id: Option<String>,
    pub status: PauseStatus,
    pub reason_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub requested_height: u64,
    pub activated_height: Option<u64>,
    pub resolved_height: Option<u64>,
    pub expires_height: u64,
}

impl EmergencyPauseReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "pause_id": self.pause_id,
            "domain_id": self.domain_id,
            "market_id": self.market_id,
            "window_id": self.window_id,
            "status": self.status,
            "reason_root": self.reason_root,
            "attestation_root": self.attestation_root,
            "receipt_root": self.receipt_root,
            "requested_height": self.requested_height,
            "activated_height": self.activated_height,
            "resolved_height": self.resolved_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeChallengeBond {
    pub challenge_id: String,
    pub observation_id: String,
    pub domain_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond_millis: u64,
    pub status: ChallengeStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub resolution_root: Option<String>,
}

impl LowFeeChallengeBond {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "observation_id": self.observation_id,
            "domain_id": self.domain_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "bond_millis": self.bond_millis,
            "status": self.status,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "resolution_root": self.resolution_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureTicket {
    pub ticket_id: String,
    pub scope: TicketScope,
    pub subject_id: String,
    pub domain_id: String,
    pub viewer_commitment: String,
    pub disclosure_root: String,
    pub policy_root: String,
    pub nullifier: String,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl SelectiveDisclosureTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "scope": self.scope,
            "subject_id": self.subject_id,
            "domain_id": self.domain_id,
            "viewer_commitment": self.viewer_commitment,
            "disclosure_root": self.disclosure_root,
            "policy_root": self.policy_root,
            "nullifier": self.nullifier,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub domain_id: String,
    pub attestation_id: String,
    pub observation_id: String,
    pub challenger_commitment: String,
    pub contradiction_root: String,
    pub disputed_signature_root: String,
    pub slashed_weight: u64,
    pub status: SlashingStatus,
    pub submitted_height: u64,
    pub executed_height: Option<u64>,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "domain_id": self.domain_id,
            "attestation_id": self.attestation_id,
            "observation_id": self.observation_id,
            "challenger_commitment": self.challenger_commitment,
            "contradiction_root": self.contradiction_root,
            "disputed_signature_root": self.disputed_signature_root,
            "slashed_weight": self.slashed_weight,
            "status": self.status,
            "submitted_height": self.submitted_height,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub domains: BTreeMap<String, RiskDomain>,
    pub observations: BTreeMap<String, EncryptedRiskObservation>,
    pub attestations: BTreeMap<String, OracleCommitteeAttestation>,
    pub exposure_snapshots: BTreeMap<String, PrivateMarketExposureSnapshot>,
    pub guardrail_windows: BTreeMap<String, GuardrailWindow>,
    pub pause_receipts: BTreeMap<String, EmergencyPauseReceipt>,
    pub challenges: BTreeMap<String, LowFeeChallengeBond>,
    pub disclosure_tickets: BTreeMap<String, SelectiveDisclosureTicket>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub nullifier_fences: BTreeSet<String>,
}

pub type Runtime = State;

impl State {
    pub fn new(
        config: Config,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            domains: BTreeMap::new(),
            observations: BTreeMap::new(),
            attestations: BTreeMap::new(),
            exposure_snapshots: BTreeMap::new(),
            guardrail_windows: BTreeMap::new(),
            pause_receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            disclosure_tickets: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            nullifier_fences: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet risk circuit breaker config")
    }

    pub fn register_risk_domain(
        &mut self,
        market_id: impl Into<String>,
        kind: RiskDomainKind,
        encrypted_policy_root: impl Into<String>,
        committee_root: impl Into<String>,
        thresholds: RiskThresholds,
        metadata_commitment: impl Into<String>,
        height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.domains.len() >= self.config.max_domains {
            return Err("risk domain capacity exhausted".to_string());
        }
        thresholds.validate()?;
        let market_id = market_id.into();
        let encrypted_policy_root = encrypted_policy_root.into();
        let committee_root = committee_root.into();
        let metadata_commitment = metadata_commitment.into();
        require_non_empty("market_id", &market_id)?;
        require_non_empty("encrypted_policy_root", &encrypted_policy_root)?;
        require_non_empty("committee_root", &committee_root)?;
        require_non_empty("metadata_commitment", &metadata_commitment)?;
        let domain_id = risk_domain_id(
            &market_id,
            kind,
            &encrypted_policy_root,
            &committee_root,
            height,
        );
        if self.domains.contains_key(&domain_id) {
            return Err("risk domain already registered".to_string());
        }
        let domain = RiskDomain {
            domain_id: domain_id.clone(),
            market_id,
            kind,
            status: RiskDomainStatus::Active,
            encrypted_policy_root,
            committee_root,
            thresholds,
            min_committee_weight: self.config.min_committee_weight,
            privacy_set_size: self.config.target_privacy_set,
            pq_security_bits: self.config.min_pq_security_bits,
            created_height: height,
            updated_height: height,
            last_observation_height: None,
            active_pause_id: None,
            metadata_commitment,
        };
        self.domains.insert(domain_id.clone(), domain);
        self.counters.domains_registered = self.counters.domains_registered.saturating_add(1);
        self.refresh_roots();
        Ok(domain_id)
    }

    pub fn submit_exposure_snapshot(
        &mut self,
        domain_id: impl Into<String>,
        encrypted_exposure_root: impl Into<String>,
        liability_commitment_root: impl Into<String>,
        collateral_commitment_root: impl Into<String>,
        liquidation_queue_root: impl Into<String>,
        maker_set_root: impl Into<String>,
        exposure_band_bps: u64,
        leverage_band_bps: u64,
        privacy_set_size: u64,
        nullifier: impl Into<String>,
        captured_height: u64,
        submitted_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.exposure_snapshots.len() >= self.config.max_exposure_snapshots {
            return Err("risk exposure snapshot capacity exhausted".to_string());
        }
        let domain_id = domain_id.into();
        let encrypted_exposure_root = encrypted_exposure_root.into();
        let liability_commitment_root = liability_commitment_root.into();
        let collateral_commitment_root = collateral_commitment_root.into();
        let liquidation_queue_root = liquidation_queue_root.into();
        let maker_set_root = maker_set_root.into();
        let nullifier = nullifier.into();
        require_non_empty("domain_id", &domain_id)?;
        require_non_empty("encrypted_exposure_root", &encrypted_exposure_root)?;
        require_non_empty("liability_commitment_root", &liability_commitment_root)?;
        require_non_empty("collateral_commitment_root", &collateral_commitment_root)?;
        require_non_empty("liquidation_queue_root", &liquidation_queue_root)?;
        require_non_empty("maker_set_root", &maker_set_root)?;
        require_non_empty("nullifier", &nullifier)?;
        self.require_domain_accepts_observations(&domain_id)?;
        self.insert_nullifier(&nullifier)?;
        if exposure_band_bps
            > PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_MAX_BPS
            || leverage_band_bps
                > PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_MAX_BPS
        {
            return Err("risk exposure bands must be expressed in BPS".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set {
            return Err("risk exposure privacy set is below minimum".to_string());
        }
        if submitted_height < captured_height {
            return Err("risk exposure cannot be submitted before capture".to_string());
        }
        let snapshot_id = exposure_snapshot_id(
            &domain_id,
            &encrypted_exposure_root,
            exposure_band_bps,
            leverage_band_bps,
            captured_height,
        );
        if self.exposure_snapshots.contains_key(&snapshot_id) {
            return Err("risk exposure snapshot already exists".to_string());
        }
        let snapshot = PrivateMarketExposureSnapshot {
            snapshot_id: snapshot_id.clone(),
            domain_id,
            encrypted_exposure_root,
            liability_commitment_root,
            collateral_commitment_root,
            liquidation_queue_root,
            maker_set_root,
            exposure_band_bps,
            leverage_band_bps,
            privacy_set_size,
            nullifier,
            captured_height,
            submitted_height,
        };
        self.exposure_snapshots
            .insert(snapshot_id.clone(), snapshot);
        self.counters.exposure_snapshots_submitted =
            self.counters.exposure_snapshots_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(snapshot_id)
    }

    pub fn submit_encrypted_observation(
        &mut self,
        domain_id: impl Into<String>,
        metric: RiskMetricKind,
        ciphertext_root: impl Into<String>,
        encrypted_payload_hash: impl Into<String>,
        exposure_snapshot_id: Option<String>,
        reporter_commitment: impl Into<String>,
        committee_hint_root: impl Into<String>,
        nullifier: impl Into<String>,
        fee_millis: u64,
        observed_height: u64,
        submitted_height: u64,
        pq_security_bits: u16,
        privacy_set_size: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.observations.len() >= self.config.max_observations {
            return Err("risk observation capacity exhausted".to_string());
        }
        let domain_id = domain_id.into();
        let ciphertext_root = ciphertext_root.into();
        let encrypted_payload_hash = encrypted_payload_hash.into();
        let reporter_commitment = reporter_commitment.into();
        let committee_hint_root = committee_hint_root.into();
        let nullifier = nullifier.into();
        require_non_empty("domain_id", &domain_id)?;
        require_non_empty("ciphertext_root", &ciphertext_root)?;
        require_non_empty("encrypted_payload_hash", &encrypted_payload_hash)?;
        require_non_empty("reporter_commitment", &reporter_commitment)?;
        require_non_empty("committee_hint_root", &committee_hint_root)?;
        require_non_empty("nullifier", &nullifier)?;
        self.require_domain_accepts_observations(&domain_id)?;
        self.insert_nullifier(&nullifier)?;
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("risk observation PQ security is below runtime floor".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set {
            return Err("risk observation privacy set is below minimum".to_string());
        }
        if submitted_height < observed_height {
            return Err("risk observation cannot be submitted before observation".to_string());
        }
        if let Some(snapshot_id) = exposure_snapshot_id.as_ref() {
            self.require_exposure_for_domain(snapshot_id, &domain_id)?;
        }
        let expires_height = submitted_height.saturating_add(self.config.observation_ttl_blocks);
        let observation_id = observation_id(
            &domain_id,
            metric,
            &ciphertext_root,
            &encrypted_payload_hash,
            observed_height,
        );
        if self.observations.contains_key(&observation_id) {
            return Err("risk observation already exists".to_string());
        }
        let observation = EncryptedRiskObservation {
            observation_id: observation_id.clone(),
            domain_id: domain_id.clone(),
            metric,
            status: ObservationStatus::Encrypted,
            ciphertext_root,
            encrypted_payload_hash,
            exposure_snapshot_id,
            reporter_commitment,
            committee_hint_root,
            nullifier,
            fee_millis,
            observed_height,
            submitted_height,
            expires_height,
            pq_security_bits,
            privacy_set_size,
        };
        self.observations
            .insert(observation_id.clone(), observation);
        if let Some(domain) = self.domains.get_mut(&domain_id) {
            domain.last_observation_height = Some(observed_height);
            domain.updated_height = submitted_height;
        }
        self.counters.observations_submitted =
            self.counters.observations_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(observation_id)
    }

    pub fn attest_committee(
        &mut self,
        observation_id: impl Into<String>,
        committee_root: impl Into<String>,
        signer_bitmap_root: impl Into<String>,
        aggregate_signature_root: impl Into<String>,
        transcript_root: impl Into<String>,
        verdict: AttestationVerdict,
        signed_weight: u64,
        attested_height: u64,
        pq_security_bits: u16,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("risk attestation capacity exhausted".to_string());
        }
        let observation_id = observation_id.into();
        let committee_root = committee_root.into();
        let signer_bitmap_root = signer_bitmap_root.into();
        let aggregate_signature_root = aggregate_signature_root.into();
        let transcript_root = transcript_root.into();
        require_non_empty("observation_id", &observation_id)?;
        require_non_empty("committee_root", &committee_root)?;
        require_non_empty("signer_bitmap_root", &signer_bitmap_root)?;
        require_non_empty("aggregate_signature_root", &aggregate_signature_root)?;
        require_non_empty("transcript_root", &transcript_root)?;
        let (domain_id, min_required_weight, expires_height, current_status) = {
            let observation = self
                .observations
                .get(&observation_id)
                .ok_or_else(|| "risk observation not found".to_string())?;
            (
                observation.domain_id.clone(),
                self.domains
                    .get(&observation.domain_id)
                    .ok_or_else(|| "risk domain not found".to_string())?
                    .min_committee_weight,
                observation.expires_height,
                observation.status,
            )
        };
        if !current_status.can_attest() {
            return Err(
                "risk observation cannot accept attestations in current status".to_string(),
            );
        }
        if attested_height > expires_height {
            return Err("risk observation is stale for attestation".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("risk attestation PQ security is below runtime floor".to_string());
        }
        if verdict.contributes_to_quorum() && signed_weight < min_required_weight {
            return Err("risk attestation signed weight is below quorum".to_string());
        }
        let attestation_id = attestation_id(
            &observation_id,
            &committee_root,
            &signer_bitmap_root,
            &aggregate_signature_root,
            attested_height,
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err("risk attestation already exists".to_string());
        }
        let attestation = OracleCommitteeAttestation {
            attestation_id: attestation_id.clone(),
            observation_id: observation_id.clone(),
            domain_id,
            committee_root,
            signer_bitmap_root,
            aggregate_signature_root,
            transcript_root,
            verdict,
            signed_weight,
            min_required_weight,
            attested_height,
            pq_security_bits,
        };
        self.attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(observation) = self.observations.get_mut(&observation_id) {
            observation.status = if verdict.contributes_to_quorum() {
                ObservationStatus::Attested
            } else if verdict.is_fault() {
                ObservationStatus::Rejected
            } else {
                ObservationStatus::Encrypted
            };
        }
        self.counters.attestations_submitted =
            self.counters.attestations_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn open_guardrail_window(
        &mut self,
        domain_id: impl Into<String>,
        observation_ids: Vec<String>,
        exposure_snapshot_id: Option<String>,
        severity: GuardrailSeverity,
        volatility_guard_bps: u64,
        liquidation_guard_bps: u64,
        oracle_deviation_guard_bps: u64,
        opens_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.guardrail_windows.len() >= self.config.max_guardrail_windows {
            return Err("risk guardrail window capacity exhausted".to_string());
        }
        let domain_id = domain_id.into();
        require_non_empty("domain_id", &domain_id)?;
        if observation_ids.is_empty() {
            return Err("risk guardrail window requires observations".to_string());
        }
        self.require_domain(&domain_id)?;
        for observation_id in &observation_ids {
            let observation = self
                .observations
                .get(observation_id)
                .ok_or_else(|| "risk guardrail observation not found".to_string())?;
            if observation.domain_id != domain_id {
                return Err("risk guardrail observation belongs to another domain".to_string());
            }
            if !observation.status.anchors_guardrail() {
                return Err("risk guardrail observation is not attested".to_string());
            }
            if opens_height > observation.expires_height {
                return Err("risk guardrail observation is stale".to_string());
            }
        }
        if let Some(snapshot_id) = exposure_snapshot_id.as_ref() {
            self.require_exposure_for_domain(snapshot_id, &domain_id)?;
        }
        let max_bps = PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_MAX_BPS;
        if volatility_guard_bps > max_bps
            || liquidation_guard_bps > max_bps
            || oracle_deviation_guard_bps > max_bps
        {
            return Err("risk guardrail values must be expressed in BPS".to_string());
        }
        let closes_height = opens_height.saturating_add(self.config.guardrail_window_blocks);
        let window_id = guardrail_window_id(
            &domain_id,
            &observation_ids,
            exposure_snapshot_id.as_deref(),
            severity,
            opens_height,
        );
        if self.guardrail_windows.contains_key(&window_id) {
            return Err("risk guardrail window already exists".to_string());
        }
        let guardrail_root = guardrail_root(
            &domain_id,
            &observation_ids,
            exposure_snapshot_id.as_deref(),
            severity,
            volatility_guard_bps,
            liquidation_guard_bps,
            oracle_deviation_guard_bps,
        );
        let window = GuardrailWindow {
            window_id: window_id.clone(),
            domain_id: domain_id.clone(),
            observation_ids: observation_ids.clone(),
            exposure_snapshot_id,
            severity,
            volatility_guard_bps,
            liquidation_guard_bps,
            oracle_deviation_guard_bps,
            opens_height,
            closes_height,
            pause_id: None,
            guardrail_root,
        };
        self.guardrail_windows.insert(window_id.clone(), window);
        for observation_id in observation_ids {
            if let Some(observation) = self.observations.get_mut(&observation_id) {
                observation.status = ObservationStatus::Windowed;
            }
        }
        if let Some(domain) = self.domains.get_mut(&domain_id) {
            if matches!(
                severity,
                GuardrailSeverity::Watch | GuardrailSeverity::Throttle
            ) {
                domain.status = RiskDomainStatus::Watchlisted;
            }
            domain.updated_height = opens_height;
        }
        self.counters.guardrail_windows_opened =
            self.counters.guardrail_windows_opened.saturating_add(1);
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn pause_market(
        &mut self,
        domain_id: impl Into<String>,
        window_id: Option<String>,
        reason_root: impl Into<String>,
        attestation_root: impl Into<String>,
        requested_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.pause_receipts.len() >= self.config.max_pause_receipts {
            return Err("risk pause receipt capacity exhausted".to_string());
        }
        let domain_id = domain_id.into();
        let reason_root = reason_root.into();
        let attestation_root = attestation_root.into();
        require_non_empty("domain_id", &domain_id)?;
        require_non_empty("reason_root", &reason_root)?;
        require_non_empty("attestation_root", &attestation_root)?;
        let market_id = {
            let domain = self
                .domains
                .get(&domain_id)
                .ok_or_else(|| "risk domain not found".to_string())?;
            if !domain.status.can_pause() {
                return Err("risk domain cannot be paused in current status".to_string());
            }
            if domain.active_pause_id.is_some() {
                return Err("risk domain already has an active pause".to_string());
            }
            domain.market_id.clone()
        };
        if let Some(window_id) = window_id.as_ref() {
            let window = self
                .guardrail_windows
                .get(window_id)
                .ok_or_else(|| "risk guardrail window not found".to_string())?;
            if window.domain_id != domain_id {
                return Err("risk pause guardrail belongs to another domain".to_string());
            }
            if requested_height > window.closes_height {
                return Err("risk pause guardrail window is closed".to_string());
            }
        }
        let receipt_root = pause_receipt_root(
            &domain_id,
            &market_id,
            window_id.as_deref(),
            &reason_root,
            &attestation_root,
        );
        let pause_id = pause_id(&domain_id, &market_id, &receipt_root, requested_height);
        let receipt = EmergencyPauseReceipt {
            pause_id: pause_id.clone(),
            domain_id: domain_id.clone(),
            market_id,
            window_id: window_id.clone(),
            status: PauseStatus::Active,
            reason_root,
            attestation_root,
            receipt_root,
            requested_height,
            activated_height: Some(requested_height),
            resolved_height: None,
            expires_height: requested_height.saturating_add(self.config.receipt_ttl_blocks),
        };
        self.pause_receipts.insert(pause_id.clone(), receipt);
        if let Some(domain) = self.domains.get_mut(&domain_id) {
            domain.status = RiskDomainStatus::Paused;
            domain.active_pause_id = Some(pause_id.clone());
            domain.updated_height = requested_height;
        }
        if let Some(window_id) = window_id {
            if let Some(window) = self.guardrail_windows.get_mut(&window_id) {
                window.pause_id = Some(pause_id.clone());
            }
        }
        self.counters.market_pauses = self.counters.market_pauses.saturating_add(1);
        self.refresh_roots();
        Ok(pause_id)
    }

    pub fn publish_pause_receipt(
        &mut self,
        pause_id: impl Into<String>,
        receipt_root: impl Into<String>,
        published_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let pause_id = pause_id.into();
        let receipt_root = receipt_root.into();
        require_non_empty("pause_id", &pause_id)?;
        require_non_empty("receipt_root", &receipt_root)?;
        let receipt = self
            .pause_receipts
            .get_mut(&pause_id)
            .ok_or_else(|| "risk pause receipt not found".to_string())?;
        if !receipt.status.is_active() {
            return Err("risk pause receipt cannot be published in current status".to_string());
        }
        if published_height > receipt.expires_height {
            return Err("risk pause receipt expired before publication".to_string());
        }
        receipt.receipt_root = receipt_root;
        receipt.status = PauseStatus::ReceiptPublished;
        self.counters.pause_receipts_published =
            self.counters.pause_receipts_published.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn resume_market(
        &mut self,
        domain_id: impl Into<String>,
        pause_id: impl Into<String>,
        resolution_root: impl Into<String>,
        resumed_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let domain_id = domain_id.into();
        let pause_id = pause_id.into();
        let resolution_root = resolution_root.into();
        require_non_empty("domain_id", &domain_id)?;
        require_non_empty("pause_id", &pause_id)?;
        require_non_empty("resolution_root", &resolution_root)?;
        let domain_pause = self
            .domains
            .get(&domain_id)
            .ok_or_else(|| "risk domain not found".to_string())?
            .active_pause_id
            .clone();
        if domain_pause.as_deref() != Some(pause_id.as_str()) {
            return Err("risk pause is not active for domain".to_string());
        }
        let receipt = self
            .pause_receipts
            .get_mut(&pause_id)
            .ok_or_else(|| "risk pause receipt not found".to_string())?;
        if receipt.domain_id != domain_id {
            return Err("risk pause receipt belongs to another domain".to_string());
        }
        if resumed_height < receipt.requested_height {
            return Err("risk market cannot resume before pause request".to_string());
        }
        receipt.status = PauseStatus::Resolved;
        receipt.reason_root = resolution_root;
        receipt.resolved_height = Some(resumed_height);
        if let Some(domain) = self.domains.get_mut(&domain_id) {
            domain.status = RiskDomainStatus::Active;
            domain.active_pause_id = None;
            domain.updated_height = resumed_height;
        }
        self.counters.market_resumes = self.counters.market_resumes.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn challenge_stale_oracle_data(
        &mut self,
        observation_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        bond_millis: u64,
        opened_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.challenges.len() >= self.config.max_challenges {
            return Err("risk challenge capacity exhausted".to_string());
        }
        let observation_id = observation_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        require_non_empty("observation_id", &observation_id)?;
        require_non_empty("challenger_commitment", &challenger_commitment)?;
        require_non_empty("evidence_root", &evidence_root)?;
        if bond_millis > self.config.max_challenge_bond_millis {
            return Err("risk challenge bond exceeds low-fee cap".to_string());
        }
        let (domain_id, expires_height) = {
            let observation = self
                .observations
                .get(&observation_id)
                .ok_or_else(|| "risk observation not found".to_string())?;
            (observation.domain_id.clone(), observation.expires_height)
        };
        if opened_height <= expires_height {
            return Err("risk challenge can only target stale oracle data".to_string());
        }
        let challenge_id = challenge_id(
            &observation_id,
            &challenger_commitment,
            &evidence_root,
            opened_height,
        );
        if self.challenges.contains_key(&challenge_id) {
            return Err("risk challenge already exists".to_string());
        }
        let challenge = LowFeeChallengeBond {
            challenge_id: challenge_id.clone(),
            observation_id: observation_id.clone(),
            domain_id,
            challenger_commitment,
            evidence_root,
            bond_millis,
            status: ChallengeStatus::Open,
            opened_height,
            expires_height: opened_height.saturating_add(self.config.challenge_ttl_blocks),
            resolution_root: None,
        };
        self.challenges.insert(challenge_id.clone(), challenge);
        if let Some(observation) = self.observations.get_mut(&observation_id) {
            observation.status = ObservationStatus::Challenged;
        }
        self.counters.challenges_opened = self.counters.challenges_opened.saturating_add(1);
        self.counters.total_challenge_bond_millis = self
            .counters
            .total_challenge_bond_millis
            .saturating_add(bond_millis as u128);
        self.refresh_roots();
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: impl Into<String>,
        uphold: bool,
        resolution_root: impl Into<String>,
        resolved_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let challenge_id = challenge_id.into();
        let resolution_root = resolution_root.into();
        require_non_empty("challenge_id", &challenge_id)?;
        require_non_empty("resolution_root", &resolution_root)?;
        let (observation_id, expires_height) = {
            let challenge = self
                .challenges
                .get(&challenge_id)
                .ok_or_else(|| "risk challenge not found".to_string())?;
            (challenge.observation_id.clone(), challenge.expires_height)
        };
        if resolved_height > expires_height {
            return Err("risk challenge expired before resolution".to_string());
        }
        let challenge = self
            .challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| "risk challenge not found".to_string())?;
        if !challenge.status.is_open() {
            return Err("risk challenge cannot be resolved in current status".to_string());
        }
        challenge.status = if uphold {
            ChallengeStatus::Upheld
        } else {
            ChallengeStatus::Rejected
        };
        challenge.resolution_root = Some(resolution_root);
        if let Some(observation) = self.observations.get_mut(&observation_id) {
            observation.status = if uphold {
                ObservationStatus::Stale
            } else {
                ObservationStatus::Attested
            };
        }
        if uphold {
            self.counters.challenges_upheld = self.counters.challenges_upheld.saturating_add(1);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn issue_selective_disclosure_ticket(
        &mut self,
        scope: TicketScope,
        subject_id: impl Into<String>,
        domain_id: impl Into<String>,
        viewer_commitment: impl Into<String>,
        disclosure_root: impl Into<String>,
        policy_root: impl Into<String>,
        nullifier: impl Into<String>,
        issued_height: u64,
        ttl_blocks: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.disclosure_tickets.len() >= self.config.max_disclosure_tickets {
            return Err("risk disclosure ticket capacity exhausted".to_string());
        }
        let subject_id = subject_id.into();
        let domain_id = domain_id.into();
        let viewer_commitment = viewer_commitment.into();
        let disclosure_root = disclosure_root.into();
        let policy_root = policy_root.into();
        let nullifier = nullifier.into();
        require_non_empty("subject_id", &subject_id)?;
        require_non_empty("domain_id", &domain_id)?;
        require_non_empty("viewer_commitment", &viewer_commitment)?;
        require_non_empty("disclosure_root", &disclosure_root)?;
        require_non_empty("policy_root", &policy_root)?;
        require_non_empty("nullifier", &nullifier)?;
        self.require_domain(&domain_id)?;
        self.require_subject(scope, &subject_id)?;
        self.insert_nullifier(&nullifier)?;
        if ttl_blocks == 0 {
            return Err("risk disclosure ticket ttl must be positive".to_string());
        }
        let ticket_id = disclosure_ticket_id(
            scope,
            &subject_id,
            &domain_id,
            &viewer_commitment,
            &disclosure_root,
            issued_height,
        );
        if self.disclosure_tickets.contains_key(&ticket_id) {
            return Err("risk disclosure ticket already exists".to_string());
        }
        let ticket = SelectiveDisclosureTicket {
            ticket_id: ticket_id.clone(),
            scope,
            subject_id,
            domain_id,
            viewer_commitment,
            disclosure_root,
            policy_root,
            nullifier,
            issued_height,
            expires_height: issued_height.saturating_add(ttl_blocks),
        };
        self.disclosure_tickets.insert(ticket_id.clone(), ticket);
        self.counters.disclosure_tickets_issued =
            self.counters.disclosure_tickets_issued.saturating_add(1);
        self.refresh_roots();
        Ok(ticket_id)
    }

    pub fn slash_false_attestation(
        &mut self,
        attestation_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        contradiction_root: impl Into<String>,
        disputed_signature_root: impl Into<String>,
        slashed_weight: u64,
        submitted_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<String> {
        if self.slashing_evidence.len() >= self.config.max_slashing_evidence {
            return Err("risk slashing evidence capacity exhausted".to_string());
        }
        let attestation_id = attestation_id.into();
        let challenger_commitment = challenger_commitment.into();
        let contradiction_root = contradiction_root.into();
        let disputed_signature_root = disputed_signature_root.into();
        require_non_empty("attestation_id", &attestation_id)?;
        require_non_empty("challenger_commitment", &challenger_commitment)?;
        require_non_empty("contradiction_root", &contradiction_root)?;
        require_non_empty("disputed_signature_root", &disputed_signature_root)?;
        if slashed_weight == 0 {
            return Err("risk slashing weight must be positive".to_string());
        }
        let (domain_id, observation_id, signed_weight) = {
            let attestation = self
                .attestations
                .get(&attestation_id)
                .ok_or_else(|| "risk attestation not found".to_string())?;
            (
                attestation.domain_id.clone(),
                attestation.observation_id.clone(),
                attestation.signed_weight,
            )
        };
        if slashed_weight > signed_weight {
            return Err("risk slashing weight exceeds attested signer weight".to_string());
        }
        let evidence_id = slashing_evidence_id(
            &attestation_id,
            &challenger_commitment,
            &contradiction_root,
            &disputed_signature_root,
            submitted_height,
        );
        if self.slashing_evidence.contains_key(&evidence_id) {
            return Err("risk slashing evidence already exists".to_string());
        }
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            domain_id,
            attestation_id: attestation_id.clone(),
            observation_id: observation_id.clone(),
            challenger_commitment,
            contradiction_root,
            disputed_signature_root,
            slashed_weight,
            status: SlashingStatus::Verified,
            submitted_height,
            executed_height: None,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        if let Some(observation) = self.observations.get_mut(&observation_id) {
            observation.status = ObservationStatus::Slashed;
        }
        if let Some(attestation) = self.attestations.get_mut(&attestation_id) {
            attestation.verdict = AttestationVerdict::Revoked;
        }
        self.counters.slashing_evidence_submitted =
            self.counters.slashing_evidence_submitted.saturating_add(1);
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn execute_slashing(
        &mut self,
        evidence_id: impl Into<String>,
        executed_height: u64,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let evidence_id = evidence_id.into();
        require_non_empty("evidence_id", &evidence_id)?;
        let evidence = self
            .slashing_evidence
            .get_mut(&evidence_id)
            .ok_or_else(|| "risk slashing evidence not found".to_string())?;
        if !matches!(evidence.status, SlashingStatus::Verified) {
            return Err("risk slashing evidence is not verified".to_string());
        }
        if executed_height < evidence.submitted_height {
            return Err("risk slashing cannot execute before submission".to_string());
        }
        evidence.status = SlashingStatus::Executed;
        evidence.executed_height = Some(executed_height);
        self.counters.slashing_executed = self.counters.slashing_executed.saturating_add(1);
        self.counters.total_slashed_weight = self
            .counters
            .total_slashed_weight
            .saturating_add(evidence.slashed_weight as u128);
        self.refresh_roots();
        Ok(())
    }

    pub fn expire_stale_observations(&mut self, height: u64) -> u64 {
        let mut expired = 0_u64;
        for observation in self.observations.values_mut() {
            if matches!(
                observation.status,
                ObservationStatus::Encrypted | ObservationStatus::Attested
            ) && height > observation.expires_height
            {
                observation.status = ObservationStatus::Stale;
                expired = expired.saturating_add(1);
            }
        }
        if expired > 0 {
            self.refresh_roots();
        }
        expired
    }

    pub fn state_root(&self) -> String {
        state_root_from_roots(&self.roots)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_PROTOCOL,
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_PQ_SUITE,
            "encryption_suite": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_ENCRYPTION_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn devnet_record(&self) -> Value {
        json!({
            "height": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_DEVNET_HEIGHT,
            "runtime": self.public_record(),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = config_root(&self.config);
        self.roots.domains_root = map_root(
            "private-l2-pq-risk-circuit-breaker:domains",
            self.domains.values().map(RiskDomain::public_record),
        );
        self.roots.observations_root = map_root(
            "private-l2-pq-risk-circuit-breaker:observations",
            self.observations
                .values()
                .map(EncryptedRiskObservation::public_record),
        );
        self.roots.attestations_root = map_root(
            "private-l2-pq-risk-circuit-breaker:attestations",
            self.attestations
                .values()
                .map(OracleCommitteeAttestation::public_record),
        );
        self.roots.exposures_root = map_root(
            "private-l2-pq-risk-circuit-breaker:exposures",
            self.exposure_snapshots
                .values()
                .map(PrivateMarketExposureSnapshot::public_record),
        );
        self.roots.guardrails_root = map_root(
            "private-l2-pq-risk-circuit-breaker:guardrails",
            self.guardrail_windows
                .values()
                .map(GuardrailWindow::public_record),
        );
        self.roots.pauses_root = map_root(
            "private-l2-pq-risk-circuit-breaker:pauses",
            self.pause_receipts
                .values()
                .map(EmergencyPauseReceipt::public_record),
        );
        self.roots.receipts_root = receipt_book_root(&self.pause_receipts);
        self.roots.challenges_root = map_root(
            "private-l2-pq-risk-circuit-breaker:challenges",
            self.challenges
                .values()
                .map(LowFeeChallengeBond::public_record),
        );
        self.roots.disclosure_tickets_root = map_root(
            "private-l2-pq-risk-circuit-breaker:disclosure-tickets",
            self.disclosure_tickets
                .values()
                .map(SelectiveDisclosureTicket::public_record),
        );
        self.roots.nullifiers_root = nullifier_root(&self.nullifier_fences);
        self.roots.slashing_root = map_root(
            "private-l2-pq-risk-circuit-breaker:slashing",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record),
        );
        self.roots.counters_root = counters_root(&self.counters);
        self.roots.state_root = state_root_from_roots(&self.roots);
    }

    fn require_domain(
        &self,
        domain_id: &str,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<&RiskDomain> {
        self.domains
            .get(domain_id)
            .ok_or_else(|| "risk domain not found".to_string())
    }

    fn require_domain_accepts_observations(
        &self,
        domain_id: &str,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let domain = self.require_domain(domain_id)?;
        if !domain.status.accepts_observations() {
            return Err("risk domain is not accepting observations".to_string());
        }
        if domain.privacy_set_size < self.config.min_privacy_set {
            return Err("risk domain privacy set is below runtime minimum".to_string());
        }
        if domain.pq_security_bits < self.config.min_pq_security_bits {
            return Err("risk domain PQ security is below runtime minimum".to_string());
        }
        Ok(())
    }

    fn require_exposure_for_domain(
        &self,
        snapshot_id: &str,
        domain_id: &str,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let snapshot = self
            .exposure_snapshots
            .get(snapshot_id)
            .ok_or_else(|| "risk exposure snapshot not found".to_string())?;
        if snapshot.domain_id != domain_id {
            return Err("risk exposure snapshot belongs to another domain".to_string());
        }
        Ok(())
    }

    fn require_subject(
        &self,
        scope: TicketScope,
        subject_id: &str,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        let found = match scope {
            TicketScope::Observation => self.observations.contains_key(subject_id),
            TicketScope::Exposure => self.exposure_snapshots.contains_key(subject_id),
            TicketScope::Guardrail => self.guardrail_windows.contains_key(subject_id),
            TicketScope::Pause => self.pause_receipts.contains_key(subject_id),
            TicketScope::Challenge => self.challenges.contains_key(subject_id),
            TicketScope::Slashing => self.slashing_evidence.contains_key(subject_id),
        };
        if !found {
            return Err("risk disclosure ticket subject not found".to_string());
        }
        Ok(())
    }

    fn insert_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
        if self.nullifier_fences.len() >= self.config.max_nullifiers {
            return Err("risk nullifier fence capacity exhausted".to_string());
        }
        if self.config.require_nullifier_fence && self.nullifier_fences.contains(nullifier) {
            return Err("risk nullifier already consumed".to_string());
        }
        self.nullifier_fences.insert(nullifier.to_string());
        self.counters.nullifier_fences_inserted =
            self.counters.nullifier_fences_inserted.saturating_add(1);
        Ok(())
    }
}

pub fn config_root(config: &Config) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:config",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(&config.public_record()),
        ],
        32,
    )
}

pub fn counters_root(counters: &Counters) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:counters",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&counters.public_record()),
        ],
        32,
    )
}

pub fn state_root_from_roots(roots: &Roots) -> String {
    let record = json!({
        "config_root": roots.config_root,
        "domains_root": roots.domains_root,
        "observations_root": roots.observations_root,
        "attestations_root": roots.attestations_root,
        "exposures_root": roots.exposures_root,
        "guardrails_root": roots.guardrails_root,
        "pauses_root": roots.pauses_root,
        "receipts_root": roots.receipts_root,
        "challenges_root": roots.challenges_root,
        "disclosure_tickets_root": roots.disclosure_tickets_root,
        "nullifiers_root": roots.nullifiers_root,
        "slashing_root": roots.slashing_root,
        "counters_root": roots.counters_root,
    });
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:state-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_ORACLE_RISK_CIRCUIT_BREAKER_PROTOCOL),
            HashPart::Json(&record),
        ],
        32,
    )
}

pub fn risk_domain_id(
    market_id: &str,
    kind: RiskDomainKind,
    encrypted_policy_root: &str,
    committee_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:risk-domain-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(encrypted_policy_root),
            HashPart::Str(committee_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn exposure_snapshot_id(
    domain_id: &str,
    encrypted_exposure_root: &str,
    exposure_band_bps: u64,
    leverage_band_bps: u64,
    captured_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:exposure-snapshot-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(encrypted_exposure_root),
            HashPart::U64(exposure_band_bps),
            HashPart::U64(leverage_band_bps),
            HashPart::U64(captured_height),
        ],
        32,
    )
}

pub fn observation_id(
    domain_id: &str,
    metric: RiskMetricKind,
    ciphertext_root: &str,
    encrypted_payload_hash: &str,
    observed_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:observation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(metric.as_str()),
            HashPart::Str(ciphertext_root),
            HashPart::Str(encrypted_payload_hash),
            HashPart::U64(observed_height),
        ],
        32,
    )
}

pub fn attestation_id(
    observation_id: &str,
    committee_root: &str,
    signer_bitmap_root: &str,
    aggregate_signature_root: &str,
    attested_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:attestation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(observation_id),
            HashPart::Str(committee_root),
            HashPart::Str(signer_bitmap_root),
            HashPart::Str(aggregate_signature_root),
            HashPart::U64(attested_height),
        ],
        32,
    )
}

pub fn guardrail_window_id(
    domain_id: &str,
    observation_ids: &[String],
    exposure_snapshot_id: Option<&str>,
    severity: GuardrailSeverity,
    opens_height: u64,
) -> String {
    let record = json!({
        "observation_ids": observation_ids,
        "exposure_snapshot_id": exposure_snapshot_id,
    });
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:guardrail-window-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Json(&record),
            HashPart::Str(match severity {
                GuardrailSeverity::Info => "info",
                GuardrailSeverity::Watch => "watch",
                GuardrailSeverity::Throttle => "throttle",
                GuardrailSeverity::FreezeLiquidations => "freeze_liquidations",
                GuardrailSeverity::EmergencyPause => "emergency_pause",
            }),
            HashPart::U64(opens_height),
        ],
        32,
    )
}

pub fn guardrail_root(
    domain_id: &str,
    observation_ids: &[String],
    exposure_snapshot_id: Option<&str>,
    severity: GuardrailSeverity,
    volatility_guard_bps: u64,
    liquidation_guard_bps: u64,
    oracle_deviation_guard_bps: u64,
) -> String {
    let record = json!({
        "domain_id": domain_id,
        "observation_ids": observation_ids,
        "exposure_snapshot_id": exposure_snapshot_id,
        "severity": severity,
        "volatility_guard_bps": volatility_guard_bps,
        "liquidation_guard_bps": liquidation_guard_bps,
        "oracle_deviation_guard_bps": oracle_deviation_guard_bps,
    });
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:guardrail-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(&record)],
        32,
    )
}

pub fn pause_receipt_root(
    domain_id: &str,
    market_id: &str,
    window_id: Option<&str>,
    reason_root: &str,
    attestation_root: &str,
) -> String {
    let record = json!({
        "domain_id": domain_id,
        "market_id": market_id,
        "window_id": window_id,
        "reason_root": reason_root,
        "attestation_root": attestation_root,
    });
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:pause-receipt-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(&record)],
        32,
    )
}

pub fn pause_id(
    domain_id: &str,
    market_id: &str,
    receipt_root: &str,
    requested_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:pause-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_id),
            HashPart::Str(market_id),
            HashPart::Str(receipt_root),
            HashPart::U64(requested_height),
        ],
        32,
    )
}

pub fn challenge_id(
    observation_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:challenge-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(observation_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn disclosure_ticket_id(
    scope: TicketScope,
    subject_id: &str,
    domain_id: &str,
    viewer_commitment: &str,
    disclosure_root: &str,
    issued_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:disclosure-ticket-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(domain_id),
            HashPart::Str(viewer_commitment),
            HashPart::Str(disclosure_root),
            HashPart::U64(issued_height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    attestation_id: &str,
    challenger_commitment: &str,
    contradiction_root: &str,
    disputed_signature_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "private-l2-pq-risk-circuit-breaker:slashing-evidence-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(attestation_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(contradiction_root),
            HashPart::Str(disputed_signature_root),
            HashPart::U64(submitted_height),
        ],
        32,
    )
}

pub fn receipt_book_root(receipts: &BTreeMap<String, EmergencyPauseReceipt>) -> String {
    map_root(
        "private-l2-pq-risk-circuit-breaker:receipt-book",
        receipts.values().map(EmergencyPauseReceipt::public_record),
    )
}

pub fn nullifier_root(nullifiers: &BTreeSet<String>) -> String {
    let leaves = nullifiers
        .iter()
        .map(|nullifier| json!({ "nullifier": nullifier }))
        .collect::<Vec<_>>();
    merkle_root("private-l2-pq-risk-circuit-breaker:nullifiers", &leaves)
}

pub fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn devnet_runtime() -> Runtime {
    State::devnet()
}

pub fn devnet_public_record() -> Value {
    State::devnet().devnet_record()
}

fn require_non_empty(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialDefiOracleRiskCircuitBreakerRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("risk circuit breaker {field} must not be empty"));
    }
    Ok(())
}
