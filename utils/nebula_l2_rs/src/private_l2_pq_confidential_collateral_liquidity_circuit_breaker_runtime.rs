use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialCollateralLiquidityCircuitBreakerRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialCollateralLiquidityCircuitBreakerRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_COLLATERAL_LIQUIDITY_CIRCUIT_BREAKER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-collateral-liquidity-circuit-breaker-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_COLLATERAL_LIQUIDITY_CIRCUIT_BREAKER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_RUNTIME_ID: &str =
    "private-l2-pq-confidential-collateral-liquidity-circuit-breaker-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-collateral-liquidity-breaker-v1";
pub const COLLATERAL_BUCKET_COMMITMENT_SCHEME: &str =
    "monero-l2-shielded-collateral-bucket-commitment-root-v1";
pub const LIQUIDITY_DEPTH_COMMITMENT_SCHEME: &str =
    "private-l2-confidential-liquidity-depth-commitment-root-v1";
pub const BREAKER_THRESHOLD_SCHEME: &str =
    "pq-confidential-collateral-liquidity-breaker-threshold-root-v1";
pub const KEEPER_CREDIT_SCHEME: &str = "low-fee-confidential-keeper-credit-root-v1";
pub const LIQUIDATION_DELAY_SCHEME: &str =
    "private-l2-confidential-liquidation-delay-record-root-v1";
pub const STALE_RISK_QUARANTINE_SCHEME: &str = "pq-confidential-stale-risk-quarantine-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-collateral-liquidity-breaker-public-record-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_918_400;
pub const DEVNET_EPOCH: u64 = 2_664;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_LIQUIDITY_DEPTH_BPS: u64 = 1_250;
pub const DEFAULT_WARN_LIQUIDITY_DEPTH_BPS: u64 = 1_750;
pub const DEFAULT_CRITICAL_LIQUIDITY_DEPTH_BPS: u64 = 900;
pub const DEFAULT_MAX_COLLATERAL_CONCENTRATION_BPS: u64 = 3_500;
pub const DEFAULT_MAX_STALE_RISK_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 14_400;
pub const DEFAULT_LIQUIDITY_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BREAKER_COOLDOWN_BLOCKS: u64 = 48;
pub const DEFAULT_DELAY_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_KEEPER_CREDIT_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_KEEPER_LOW_FEE_TARGET_BPS: u64 = 8;
pub const DEFAULT_KEEPER_LOW_FEE_ALERT_BPS: u64 = 18;
pub const DEFAULT_MIN_ATTESTATION_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_KEEPER_COVERAGE_BPS: u64 = 7_500;
pub const DEFAULT_MAX_BUCKETS: usize = 1_048_576;
pub const DEFAULT_MAX_LIQUIDITY_DEPTHS: usize = 4_194_304;
pub const DEFAULT_MAX_RISK_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_BREAKER_THRESHOLDS: usize = 1_048_576;
pub const DEFAULT_MAX_KEEPER_CREDITS: usize = 4_194_304;
pub const DEFAULT_MAX_LIQUIDATION_DELAYS: usize = 2_097_152;
pub const DEFAULT_MAX_QUARANTINES: usize = 2_097_152;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralClass {
    WrappedMonero,
    ConfidentialStable,
    PrivateLpShare,
    TokenizedVaultShare,
    SyntheticMargin,
    BridgeReserveNote,
    InsuranceBackstop,
    RealWorldAssetNote,
    GovernanceEscrow,
    Custom,
}

impl CollateralClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedMonero => "wrapped_monero",
            Self::ConfidentialStable => "confidential_stable",
            Self::PrivateLpShare => "private_lp_share",
            Self::TokenizedVaultShare => "tokenized_vault_share",
            Self::SyntheticMargin => "synthetic_margin",
            Self::BridgeReserveNote => "bridge_reserve_note",
            Self::InsuranceBackstop => "insurance_backstop",
            Self::RealWorldAssetNote => "real_world_asset_note",
            Self::GovernanceEscrow => "governance_escrow",
            Self::Custom => "custom",
        }
    }

    pub fn default_haircut_bps(self) -> u64 {
        match self {
            Self::WrappedMonero => 1_500,
            Self::ConfidentialStable => 500,
            Self::PrivateLpShare => 2_500,
            Self::TokenizedVaultShare => 2_000,
            Self::SyntheticMargin => 3_250,
            Self::BridgeReserveNote => 1_750,
            Self::InsuranceBackstop => 2_250,
            Self::RealWorldAssetNote => 3_000,
            Self::GovernanceEscrow => 4_000,
            Self::Custom => 3_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Proposed,
    Active,
    Watchlisted,
    Throttled,
    LiquidationOnly,
    Frozen,
    Retired,
}

impl BucketStatus {
    pub fn accepts_depth(self) -> bool {
        matches!(self, Self::Active | Self::Watchlisted | Self::Throttled)
    }

    pub fn can_trigger_breaker(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Watchlisted | Self::Throttled | Self::LiquidationOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityVenue {
    ConfidentialAmm,
    LendingPool,
    LiquidationBackstop,
    BridgeExitVault,
    RfqSolver,
    BatchAuction,
    StableSwap,
    CrossRuntimeMesh,
    Custom,
}

impl LiquidityVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAmm => "confidential_amm",
            Self::LendingPool => "lending_pool",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::BridgeExitVault => "bridge_exit_vault",
            Self::RfqSolver => "rfq_solver",
            Self::BatchAuction => "batch_auction",
            Self::StableSwap => "stable_swap",
            Self::CrossRuntimeMesh => "cross_runtime_mesh",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepthStatus {
    Sealed,
    Attested,
    Fresh,
    Degrading,
    Stale,
    Quarantined,
    Replaced,
}

impl DepthStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Attested | Self::Fresh | Self::Degrading)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    LiquidityDepth,
    CollateralValue,
    ConcentrationRisk,
    VolatilityShock,
    KeeperCoverage,
    LiquidationQueue,
    OracleFreshness,
    RecoveryProbe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiquidityDepth => "liquidity_depth",
            Self::CollateralValue => "collateral_value",
            Self::ConcentrationRisk => "concentration_risk",
            Self::VolatilityShock => "volatility_shock",
            Self::KeeperCoverage => "keeper_coverage",
            Self::LiquidationQueue => "liquidation_queue",
            Self::OracleFreshness => "oracle_freshness",
            Self::RecoveryProbe => "recovery_probe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarning,
    NeedsMoreWeight,
    Stale,
    Quarantined,
    Invalid,
    Revoked,
}

impl AttestationVerdict {
    pub fn contributes_weight(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarning)
    }

    pub fn quarantines_subject(self) -> bool {
        matches!(self, Self::Stale | Self::Quarantined | Self::Invalid)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerSeverity {
    Info,
    Watch,
    ThrottleBorrows,
    DelayLiquidations,
    LiquidationOnly,
    EmergencyFreeze,
}

impl BreakerSeverity {
    pub fn halts_new_risk(self) -> bool {
        matches!(
            self,
            Self::ThrottleBorrows
                | Self::DelayLiquidations
                | Self::LiquidationOnly
                | Self::EmergencyFreeze
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerStatus {
    Draft,
    Armed,
    Triggered,
    CoolingDown,
    Cleared,
    Retired,
}

impl BreakerStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Armed | Self::Triggered | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeeperCreditStatus {
    Minted,
    Reserved,
    Applied,
    Expired,
    Slashed,
    Cancelled,
}

impl KeeperCreditStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationDelayStatus {
    Scheduled,
    KeeperCovered,
    Challenged,
    Released,
    Extended,
    Cancelled,
    Expired,
}

impl LiquidationDelayStatus {
    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Scheduled | Self::KeeperCovered | Self::Challenged | Self::Extended
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleRisk,
    AttestationGap,
    LiquidityCliff,
    ConcentrationBreach,
    KeeperCoverageGap,
    OracleDivergence,
    GovernanceHold,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleRisk => "stale_risk",
            Self::AttestationGap => "attestation_gap",
            Self::LiquidityCliff => "liquidity_cliff",
            Self::ConcentrationBreach => "concentration_breach",
            Self::KeeperCoverageGap => "keeper_coverage_gap",
            Self::OracleDivergence => "oracle_divergence",
            Self::GovernanceHold => "governance_hold",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub runtime_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub deployment_height: u64,
    pub epoch: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub collateral_bucket_commitment_scheme: String,
    pub liquidity_depth_commitment_scheme: String,
    pub breaker_threshold_scheme: String,
    pub keeper_credit_scheme: String,
    pub liquidation_delay_scheme: String,
    pub stale_risk_quarantine_scheme: String,
    pub public_record_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_liquidity_depth_bps: u64,
    pub warn_liquidity_depth_bps: u64,
    pub critical_liquidity_depth_bps: u64,
    pub max_collateral_concentration_bps: u64,
    pub max_stale_risk_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub liquidity_ttl_blocks: u64,
    pub breaker_cooldown_blocks: u64,
    pub delay_window_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub keeper_credit_ttl_blocks: u64,
    pub keeper_low_fee_target_bps: u64,
    pub keeper_low_fee_alert_bps: u64,
    pub min_attestation_weight_bps: u64,
    pub min_keeper_coverage_bps: u64,
    pub max_buckets: usize,
    pub max_liquidity_depths: usize,
    pub max_risk_attestations: usize,
    pub max_breaker_thresholds: usize,
    pub max_keeper_credits: usize,
    pub max_liquidation_delays: usize,
    pub max_quarantines: usize,
    pub max_public_records: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            deployment_height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            collateral_bucket_commitment_scheme: COLLATERAL_BUCKET_COMMITMENT_SCHEME.to_string(),
            liquidity_depth_commitment_scheme: LIQUIDITY_DEPTH_COMMITMENT_SCHEME.to_string(),
            breaker_threshold_scheme: BREAKER_THRESHOLD_SCHEME.to_string(),
            keeper_credit_scheme: KEEPER_CREDIT_SCHEME.to_string(),
            liquidation_delay_scheme: LIQUIDATION_DELAY_SCHEME.to_string(),
            stale_risk_quarantine_scheme: STALE_RISK_QUARANTINE_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_liquidity_depth_bps: DEFAULT_MIN_LIQUIDITY_DEPTH_BPS,
            warn_liquidity_depth_bps: DEFAULT_WARN_LIQUIDITY_DEPTH_BPS,
            critical_liquidity_depth_bps: DEFAULT_CRITICAL_LIQUIDITY_DEPTH_BPS,
            max_collateral_concentration_bps: DEFAULT_MAX_COLLATERAL_CONCENTRATION_BPS,
            max_stale_risk_blocks: DEFAULT_MAX_STALE_RISK_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            liquidity_ttl_blocks: DEFAULT_LIQUIDITY_TTL_BLOCKS,
            breaker_cooldown_blocks: DEFAULT_BREAKER_COOLDOWN_BLOCKS,
            delay_window_blocks: DEFAULT_DELAY_WINDOW_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            keeper_credit_ttl_blocks: DEFAULT_KEEPER_CREDIT_TTL_BLOCKS,
            keeper_low_fee_target_bps: DEFAULT_KEEPER_LOW_FEE_TARGET_BPS,
            keeper_low_fee_alert_bps: DEFAULT_KEEPER_LOW_FEE_ALERT_BPS,
            min_attestation_weight_bps: DEFAULT_MIN_ATTESTATION_WEIGHT_BPS,
            min_keeper_coverage_bps: DEFAULT_MIN_KEEPER_COVERAGE_BPS,
            max_buckets: DEFAULT_MAX_BUCKETS,
            max_liquidity_depths: DEFAULT_MAX_LIQUIDITY_DEPTHS,
            max_risk_attestations: DEFAULT_MAX_RISK_ATTESTATIONS,
            max_breaker_thresholds: DEFAULT_MAX_BREAKER_THRESHOLDS,
            max_keeper_credits: DEFAULT_MAX_KEEPER_CREDITS,
            max_liquidation_delays: DEFAULT_MAX_LIQUIDATION_DELAYS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("runtime_id", &self.runtime_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_attestation_suite", &self.pq_attestation_suite)?;
        require_positive_u64("deployment_height", self.deployment_height)?;
        require_positive_u64("epoch", self.epoch)?;
        require_bps("min_liquidity_depth_bps", self.min_liquidity_depth_bps)?;
        require_bps("warn_liquidity_depth_bps", self.warn_liquidity_depth_bps)?;
        require_bps(
            "critical_liquidity_depth_bps",
            self.critical_liquidity_depth_bps,
        )?;
        require_bps(
            "max_collateral_concentration_bps",
            self.max_collateral_concentration_bps,
        )?;
        require_bps("keeper_low_fee_target_bps", self.keeper_low_fee_target_bps)?;
        require_bps("keeper_low_fee_alert_bps", self.keeper_low_fee_alert_bps)?;
        require_bps(
            "min_attestation_weight_bps",
            self.min_attestation_weight_bps,
        )?;
        require_bps("min_keeper_coverage_bps", self.min_keeper_coverage_bps)?;
        require_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive_u64("target_privacy_set_size", self.target_privacy_set_size)?;
        require_positive_u64("max_stale_risk_blocks", self.max_stale_risk_blocks)?;
        require_positive_u64("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        require_positive_u64("bucket_ttl_blocks", self.bucket_ttl_blocks)?;
        require_positive_u64("liquidity_ttl_blocks", self.liquidity_ttl_blocks)?;
        require_positive_u64("breaker_cooldown_blocks", self.breaker_cooldown_blocks)?;
        require_positive_u64("delay_window_blocks", self.delay_window_blocks)?;
        require_positive_u64("quarantine_ttl_blocks", self.quarantine_ttl_blocks)?;
        require_positive_u64("keeper_credit_ttl_blocks", self.keeper_credit_ttl_blocks)?;
        require_positive_usize("max_buckets", self.max_buckets)?;
        require_positive_usize("max_liquidity_depths", self.max_liquidity_depths)?;
        require_positive_usize("max_risk_attestations", self.max_risk_attestations)?;
        require_positive_usize("max_breaker_thresholds", self.max_breaker_thresholds)?;
        require_positive_usize("max_keeper_credits", self.max_keeper_credits)?;
        require_positive_usize("max_liquidation_delays", self.max_liquidation_delays)?;
        require_positive_usize("max_quarantines", self.max_quarantines)?;
        require_positive_usize("max_public_records", self.max_public_records)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema version".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("PQ security bits below generated runtime floor".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set below minimum".to_string());
        }
        if self.critical_liquidity_depth_bps > self.min_liquidity_depth_bps {
            return Err("critical liquidity depth cannot exceed minimum".to_string());
        }
        if self.min_liquidity_depth_bps > self.warn_liquidity_depth_bps {
            return Err("minimum liquidity depth cannot exceed warning depth".to_string());
        }
        if self.keeper_low_fee_target_bps > self.keeper_low_fee_alert_bps {
            return Err("keeper low-fee target cannot exceed alert".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "breaker_cooldown_blocks": self.breaker_cooldown_blocks,
            "breaker_threshold_scheme": self.breaker_threshold_scheme,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "collateral_bucket_commitment_scheme": self.collateral_bucket_commitment_scheme,
            "critical_liquidity_depth_bps": self.critical_liquidity_depth_bps,
            "delay_window_blocks": self.delay_window_blocks,
            "deployment_height": self.deployment_height,
            "epoch": self.epoch,
            "hash_suite": self.hash_suite,
            "keeper_credit_scheme": self.keeper_credit_scheme,
            "keeper_credit_ttl_blocks": self.keeper_credit_ttl_blocks,
            "keeper_low_fee_alert_bps": self.keeper_low_fee_alert_bps,
            "keeper_low_fee_target_bps": self.keeper_low_fee_target_bps,
            "l2_network": self.l2_network,
            "liquidation_delay_scheme": self.liquidation_delay_scheme,
            "liquidity_depth_commitment_scheme": self.liquidity_depth_commitment_scheme,
            "liquidity_ttl_blocks": self.liquidity_ttl_blocks,
            "max_breaker_thresholds": self.max_breaker_thresholds,
            "max_buckets": self.max_buckets,
            "max_collateral_concentration_bps": self.max_collateral_concentration_bps,
            "max_keeper_credits": self.max_keeper_credits,
            "max_liquidation_delays": self.max_liquidation_delays,
            "max_liquidity_depths": self.max_liquidity_depths,
            "max_public_records": self.max_public_records,
            "max_quarantines": self.max_quarantines,
            "max_risk_attestations": self.max_risk_attestations,
            "max_stale_risk_blocks": self.max_stale_risk_blocks,
            "min_attestation_weight_bps": self.min_attestation_weight_bps,
            "min_keeper_coverage_bps": self.min_keeper_coverage_bps,
            "min_liquidity_depth_bps": self.min_liquidity_depth_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "monero_network": self.monero_network,
            "pq_attestation_suite": self.pq_attestation_suite,
            "protocol_version": self.protocol_version,
            "public_record_scheme": self.public_record_scheme,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "runtime_id": self.runtime_id,
            "schema_version": self.schema_version,
            "stale_risk_quarantine_scheme": self.stale_risk_quarantine_scheme,
            "target_privacy_set_size": self.target_privacy_set_size,
            "warn_liquidity_depth_bps": self.warn_liquidity_depth_bps,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub buckets: u64,
    pub liquidity_depths: u64,
    pub risk_attestations: u64,
    pub breaker_thresholds: u64,
    pub keeper_credits: u64,
    pub liquidation_delays: u64,
    pub stale_risk_quarantines: u64,
    pub public_records: u64,
    pub active_breakers: u64,
    pub delayed_liquidations: u64,
    pub quarantined_buckets: u64,
    pub total_keeper_credit_millis: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "active_breakers": self.active_breakers,
            "breaker_thresholds": self.breaker_thresholds,
            "buckets": self.buckets,
            "delayed_liquidations": self.delayed_liquidations,
            "keeper_credits": self.keeper_credits,
            "liquidation_delays": self.liquidation_delays,
            "liquidity_depths": self.liquidity_depths,
            "public_records": self.public_records,
            "quarantined_buckets": self.quarantined_buckets,
            "risk_attestations": self.risk_attestations,
            "stale_risk_quarantines": self.stale_risk_quarantines,
            "total_keeper_credit_millis": self.total_keeper_credit_millis,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub buckets_root: String,
    pub liquidity_depths_root: String,
    pub risk_attestations_root: String,
    pub breaker_thresholds_root: String,
    pub keeper_credits_root: String,
    pub liquidation_delays_root: String,
    pub stale_risk_quarantines_root: String,
    pub public_records_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            buckets_root: empty_root("buckets"),
            liquidity_depths_root: empty_root("liquidity_depths"),
            risk_attestations_root: empty_root("risk_attestations"),
            breaker_thresholds_root: empty_root("breaker_thresholds"),
            keeper_credits_root: empty_root("keeper_credits"),
            liquidation_delays_root: empty_root("liquidation_delays"),
            stale_risk_quarantines_root: empty_root("stale_risk_quarantines"),
            public_records_root: empty_root("public_records"),
            nullifier_root: empty_root("nullifiers"),
            counters_root: empty_root("counters"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "breaker_thresholds_root": self.breaker_thresholds_root,
            "buckets_root": self.buckets_root,
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "keeper_credits_root": self.keeper_credits_root,
            "liquidation_delays_root": self.liquidation_delays_root,
            "liquidity_depths_root": self.liquidity_depths_root,
            "nullifier_root": self.nullifier_root,
            "public_records_root": self.public_records_root,
            "risk_attestations_root": self.risk_attestations_root,
            "stale_risk_quarantines_root": self.stale_risk_quarantines_root,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedCollateralBucket {
    pub bucket_id: String,
    pub asset_id: String,
    pub collateral_class: CollateralClass,
    pub owner_commitment: String,
    pub bucket_commitment_root: String,
    pub amount_commitment: String,
    pub haircut_bps: u64,
    pub concentration_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: BucketStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub latest_attestation_id: String,
}

impl ShieldedCollateralBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "amount_commitment": self.amount_commitment,
            "asset_id": self.asset_id,
            "bucket_commitment_root": self.bucket_commitment_root,
            "bucket_id": self.bucket_id,
            "collateral_class": self.collateral_class,
            "concentration_bps": self.concentration_bps,
            "expires_at_height": self.expires_at_height,
            "haircut_bps": self.haircut_bps,
            "latest_attestation_id": self.latest_attestation_id,
            "opened_at_height": self.opened_at_height,
            "owner_commitment": self.owner_commitment,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityDepthCommitment {
    pub depth_id: String,
    pub bucket_id: String,
    pub venue: LiquidityVenue,
    pub venue_commitment: String,
    pub depth_commitment_root: String,
    pub available_depth_bps: u64,
    pub slippage_bps: u64,
    pub liquidation_capacity_bps: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: DepthStatus,
    pub pq_attestation_id: String,
}

impl LiquidityDepthCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "available_depth_bps": self.available_depth_bps,
            "bucket_id": self.bucket_id,
            "depth_commitment_root": self.depth_commitment_root,
            "depth_id": self.depth_id,
            "expires_at_height": self.expires_at_height,
            "liquidation_capacity_bps": self.liquidation_capacity_bps,
            "observed_at_height": self.observed_at_height,
            "pq_attestation_id": self.pq_attestation_id,
            "slippage_bps": self.slippage_bps,
            "status": self.status,
            "venue": self.venue,
            "venue_commitment": self.venue_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("LIQUIDITY-DEPTH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRiskAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub payload_commitment_root: String,
    pub pq_signature_root: String,
    pub aggregate_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub verdict: AttestationVerdict,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRiskAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "aggregate_weight_bps": self.aggregate_weight_bps,
            "attestation_id": self.attestation_id,
            "committee_root": self.committee_root,
            "expires_at_height": self.expires_at_height,
            "kind": self.kind,
            "observed_at_height": self.observed_at_height,
            "payload_commitment_root": self.payload_commitment_root,
            "pq_security_bits": self.pq_security_bits,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "subject_id": self.subject_id,
            "verdict": self.verdict,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("PQ-RISK-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BreakerThreshold {
    pub threshold_id: String,
    pub bucket_id: String,
    pub severity: BreakerSeverity,
    pub min_depth_bps: u64,
    pub max_concentration_bps: u64,
    pub max_slippage_bps: u64,
    pub max_stale_blocks: u64,
    pub cooldown_blocks: u64,
    pub policy_root: String,
    pub status: BreakerStatus,
    pub triggered_at_height: Option<u64>,
    pub clears_after_height: u64,
}

impl BreakerThreshold {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "clears_after_height": self.clears_after_height,
            "cooldown_blocks": self.cooldown_blocks,
            "max_concentration_bps": self.max_concentration_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "max_stale_blocks": self.max_stale_blocks,
            "min_depth_bps": self.min_depth_bps,
            "policy_root": self.policy_root,
            "severity": self.severity,
            "status": self.status,
            "threshold_id": self.threshold_id,
            "triggered_at_height": self.triggered_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("BREAKER-THRESHOLD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeKeeperCredit {
    pub credit_id: String,
    pub keeper_commitment: String,
    pub bucket_id: String,
    pub fee_asset_id: String,
    pub credit_commitment_root: String,
    pub credit_millis: u64,
    pub median_fee_bps: u64,
    pub p95_fee_bps: u64,
    pub coverage_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: KeeperCreditStatus,
}

impl LowFeeKeeperCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "coverage_bps": self.coverage_bps,
            "credit_commitment_root": self.credit_commitment_root,
            "credit_id": self.credit_id,
            "credit_millis": self.credit_millis,
            "expires_at_height": self.expires_at_height,
            "fee_asset_id": self.fee_asset_id,
            "issued_at_height": self.issued_at_height,
            "keeper_commitment": self.keeper_commitment,
            "median_fee_bps": self.median_fee_bps,
            "p95_fee_bps": self.p95_fee_bps,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("LOW-FEE-KEEPER-CREDIT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationDelayRecord {
    pub delay_id: String,
    pub bucket_id: String,
    pub position_commitment: String,
    pub liquidation_nullifier: String,
    pub reason_root: String,
    pub keeper_credit_id: String,
    pub requested_at_height: u64,
    pub release_height: u64,
    pub status: LiquidationDelayStatus,
    pub severity: BreakerSeverity,
}

impl LiquidationDelayRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "delay_id": self.delay_id,
            "keeper_credit_id": self.keeper_credit_id,
            "liquidation_nullifier": self.liquidation_nullifier,
            "position_commitment": self.position_commitment,
            "reason_root": self.reason_root,
            "release_height": self.release_height,
            "requested_at_height": self.requested_at_height,
            "severity": self.severity,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("LIQUIDATION-DELAY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleRiskQuarantine {
    pub quarantine_id: String,
    pub bucket_id: String,
    pub subject_root: String,
    pub quarantine_nullifier: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub attestation_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub release_condition_root: String,
}

impl StaleRiskQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bucket_id": self.bucket_id,
            "evidence_root": self.evidence_root,
            "expires_at_height": self.expires_at_height,
            "opened_at_height": self.opened_at_height,
            "quarantine_id": self.quarantine_id,
            "quarantine_nullifier": self.quarantine_nullifier,
            "reason": self.reason,
            "release_condition_root": self.release_condition_root,
            "subject_root": self.subject_root,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("STALE-RISK-QUARANTINE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub public_root: String,
    pub sequence: u64,
    pub emitted_at_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "emitted_at_height": self.emitted_at_height,
            "public_root": self.public_root,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "sequence": self.sequence,
            "subject_id": self.subject_id,
        })
    }

    pub fn state_root(&self) -> String {
        canonical_record_root("DETERMINISTIC-PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub buckets: BTreeMap<String, ShieldedCollateralBucket>,
    pub liquidity_depths: BTreeMap<String, LiquidityDepthCommitment>,
    pub risk_attestations: BTreeMap<String, PqRiskAttestation>,
    pub breaker_thresholds: BTreeMap<String, BreakerThreshold>,
    pub keeper_credits: BTreeMap<String, LowFeeKeeperCredit>,
    pub liquidation_delays: BTreeMap<String, LiquidationDelayRecord>,
    pub stale_risk_quarantines: BTreeMap<String, StaleRiskQuarantine>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            buckets: BTreeMap::new(),
            liquidity_depths: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            breaker_thresholds: BTreeMap::new(),
            keeper_credits: BTreeMap::new(),
            liquidation_delays: BTreeMap::new(),
            stale_risk_quarantines: BTreeMap::new(),
            public_records: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        };
        state.recompute();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.install_demo_records();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        if self.buckets.len() > self.config.max_buckets {
            return Err("bucket capacity exceeded".to_string());
        }
        if self.liquidity_depths.len() > self.config.max_liquidity_depths {
            return Err("liquidity depth capacity exceeded".to_string());
        }
        if self.risk_attestations.len() > self.config.max_risk_attestations {
            return Err("risk attestation capacity exceeded".to_string());
        }
        if self.breaker_thresholds.len() > self.config.max_breaker_thresholds {
            return Err("breaker threshold capacity exceeded".to_string());
        }
        if self.keeper_credits.len() > self.config.max_keeper_credits {
            return Err("keeper credit capacity exceeded".to_string());
        }
        if self.liquidation_delays.len() > self.config.max_liquidation_delays {
            return Err("liquidation delay capacity exceeded".to_string());
        }
        if self.stale_risk_quarantines.len() > self.config.max_quarantines {
            return Err("quarantine capacity exceeded".to_string());
        }
        if self.public_records.len() > self.config.max_public_records {
            return Err("public record capacity exceeded".to_string());
        }
        for (id, bucket) in &self.buckets {
            if id != &bucket.bucket_id {
                return Err(format!("bucket key mismatch for {id}"));
            }
            validate_bucket(bucket, &self.config)?;
        }
        for (id, depth) in &self.liquidity_depths {
            if id != &depth.depth_id {
                return Err(format!("liquidity depth key mismatch for {id}"));
            }
            validate_depth(depth, &self.config, &self.buckets)?;
        }
        for (id, attestation) in &self.risk_attestations {
            if id != &attestation.attestation_id {
                return Err(format!("risk attestation key mismatch for {id}"));
            }
            validate_attestation(attestation, &self.config)?;
        }
        for (id, threshold) in &self.breaker_thresholds {
            if id != &threshold.threshold_id {
                return Err(format!("breaker threshold key mismatch for {id}"));
            }
            validate_threshold(threshold, &self.config, &self.buckets)?;
        }
        for (id, credit) in &self.keeper_credits {
            if id != &credit.credit_id {
                return Err(format!("keeper credit key mismatch for {id}"));
            }
            validate_keeper_credit(credit, &self.config, &self.buckets)?;
        }
        for (id, delay) in &self.liquidation_delays {
            if id != &delay.delay_id {
                return Err(format!("liquidation delay key mismatch for {id}"));
            }
            validate_liquidation_delay(delay, &self.config, &self.buckets, &self.nullifiers)?;
        }
        for (id, quarantine) in &self.stale_risk_quarantines {
            if id != &quarantine.quarantine_id {
                return Err(format!("quarantine key mismatch for {id}"));
            }
            validate_quarantine(quarantine, &self.config, &self.buckets, &self.nullifiers)?;
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err(format!("public record key mismatch for {id}"));
            }
            validate_public_record(record)?;
        }
        Ok(())
    }

    pub fn insert_bucket(&mut self, bucket: ShieldedCollateralBucket) -> Result<()> {
        self.config.validate()?;
        ensure_capacity("bucket", self.buckets.len(), self.config.max_buckets)?;
        ensure_absent(
            "bucket",
            &bucket.bucket_id,
            self.buckets.contains_key(&bucket.bucket_id),
        )?;
        validate_bucket(&bucket, &self.config)?;
        self.buckets.insert(bucket.bucket_id.clone(), bucket);
        self.recompute();
        Ok(())
    }

    pub fn insert_liquidity_depth(&mut self, depth: LiquidityDepthCommitment) -> Result<()> {
        ensure_capacity(
            "liquidity depth",
            self.liquidity_depths.len(),
            self.config.max_liquidity_depths,
        )?;
        ensure_absent(
            "liquidity depth",
            &depth.depth_id,
            self.liquidity_depths.contains_key(&depth.depth_id),
        )?;
        validate_depth(&depth, &self.config, &self.buckets)?;
        self.liquidity_depths.insert(depth.depth_id.clone(), depth);
        self.recompute();
        Ok(())
    }

    pub fn insert_attestation(&mut self, attestation: PqRiskAttestation) -> Result<()> {
        ensure_capacity(
            "risk attestation",
            self.risk_attestations.len(),
            self.config.max_risk_attestations,
        )?;
        ensure_absent(
            "risk attestation",
            &attestation.attestation_id,
            self.risk_attestations
                .contains_key(&attestation.attestation_id),
        )?;
        validate_attestation(&attestation, &self.config)?;
        self.risk_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute();
        Ok(())
    }

    pub fn insert_breaker_threshold(&mut self, threshold: BreakerThreshold) -> Result<()> {
        ensure_capacity(
            "breaker threshold",
            self.breaker_thresholds.len(),
            self.config.max_breaker_thresholds,
        )?;
        ensure_absent(
            "breaker threshold",
            &threshold.threshold_id,
            self.breaker_thresholds
                .contains_key(&threshold.threshold_id),
        )?;
        validate_threshold(&threshold, &self.config, &self.buckets)?;
        self.breaker_thresholds
            .insert(threshold.threshold_id.clone(), threshold);
        self.recompute();
        Ok(())
    }

    pub fn insert_keeper_credit(&mut self, credit: LowFeeKeeperCredit) -> Result<()> {
        ensure_capacity(
            "keeper credit",
            self.keeper_credits.len(),
            self.config.max_keeper_credits,
        )?;
        ensure_absent(
            "keeper credit",
            &credit.credit_id,
            self.keeper_credits.contains_key(&credit.credit_id),
        )?;
        validate_keeper_credit(&credit, &self.config, &self.buckets)?;
        self.keeper_credits.insert(credit.credit_id.clone(), credit);
        self.recompute();
        Ok(())
    }

    pub fn insert_liquidation_delay(&mut self, delay: LiquidationDelayRecord) -> Result<()> {
        ensure_capacity(
            "liquidation delay",
            self.liquidation_delays.len(),
            self.config.max_liquidation_delays,
        )?;
        ensure_absent(
            "liquidation delay",
            &delay.delay_id,
            self.liquidation_delays.contains_key(&delay.delay_id),
        )?;
        ensure_unique_set(
            "liquidation nullifier",
            &delay.liquidation_nullifier,
            &self.nullifiers,
        )?;
        let mut prospective_nullifiers = self.nullifiers.clone();
        prospective_nullifiers.insert(delay.liquidation_nullifier.clone());
        validate_liquidation_delay(&delay, &self.config, &self.buckets, &prospective_nullifiers)?;
        self.nullifiers.insert(delay.liquidation_nullifier.clone());
        self.liquidation_delays
            .insert(delay.delay_id.clone(), delay);
        self.recompute();
        Ok(())
    }

    pub fn insert_quarantine(&mut self, quarantine: StaleRiskQuarantine) -> Result<()> {
        ensure_capacity(
            "quarantine",
            self.stale_risk_quarantines.len(),
            self.config.max_quarantines,
        )?;
        ensure_absent(
            "quarantine",
            &quarantine.quarantine_id,
            self.stale_risk_quarantines
                .contains_key(&quarantine.quarantine_id),
        )?;
        ensure_unique_set(
            "quarantine nullifier",
            &quarantine.quarantine_nullifier,
            &self.nullifiers,
        )?;
        let mut prospective_nullifiers = self.nullifiers.clone();
        prospective_nullifiers.insert(quarantine.quarantine_nullifier.clone());
        validate_quarantine(
            &quarantine,
            &self.config,
            &self.buckets,
            &prospective_nullifiers,
        )?;
        self.nullifiers
            .insert(quarantine.quarantine_nullifier.clone());
        self.stale_risk_quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);
        self.recompute();
        Ok(())
    }

    pub fn insert_public_record(&mut self, record: DeterministicPublicRecord) -> Result<()> {
        ensure_capacity(
            "public record",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        ensure_absent(
            "public record",
            &record.record_id,
            self.public_records.contains_key(&record.record_id),
        )?;
        validate_public_record(&record)?;
        self.public_records.insert(record.record_id.clone(), record);
        self.recompute();
        Ok(())
    }

    pub fn recompute(&mut self) {
        self.counters = self.derived_counters();
        self.roots = Roots {
            config_root: self.config.state_root(),
            buckets_root: collection_root(
                "buckets",
                self.buckets
                    .values()
                    .map(|bucket| bucket.state_root())
                    .collect(),
            ),
            liquidity_depths_root: collection_root(
                "liquidity-depths",
                self.liquidity_depths
                    .values()
                    .map(|depth| depth.state_root())
                    .collect(),
            ),
            risk_attestations_root: collection_root(
                "risk-attestations",
                self.risk_attestations
                    .values()
                    .map(|attestation| attestation.state_root())
                    .collect(),
            ),
            breaker_thresholds_root: collection_root(
                "breaker-thresholds",
                self.breaker_thresholds
                    .values()
                    .map(|threshold| threshold.state_root())
                    .collect(),
            ),
            keeper_credits_root: collection_root(
                "keeper-credits",
                self.keeper_credits
                    .values()
                    .map(|credit| credit.state_root())
                    .collect(),
            ),
            liquidation_delays_root: collection_root(
                "liquidation-delays",
                self.liquidation_delays
                    .values()
                    .map(|delay| delay.state_root())
                    .collect(),
            ),
            stale_risk_quarantines_root: collection_root(
                "stale-risk-quarantines",
                self.stale_risk_quarantines
                    .values()
                    .map(|quarantine| quarantine.state_root())
                    .collect(),
            ),
            public_records_root: collection_root(
                "public-records",
                self.public_records
                    .values()
                    .map(|record| record.state_root())
                    .collect(),
            ),
            nullifier_root: collection_root(
                "nullifiers",
                self.nullifiers.iter().cloned().collect(),
            ),
            counters_root: self.counters.state_root(),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "protocol_version": PROTOCOL_VERSION,
            "roots": self.roots.public_record(),
            "schema_version": SCHEMA_VERSION,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = Value::String(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    fn derived_counters(&self) -> Counters {
        Counters {
            buckets: self.buckets.len() as u64,
            liquidity_depths: self.liquidity_depths.len() as u64,
            risk_attestations: self.risk_attestations.len() as u64,
            breaker_thresholds: self.breaker_thresholds.len() as u64,
            keeper_credits: self.keeper_credits.len() as u64,
            liquidation_delays: self.liquidation_delays.len() as u64,
            stale_risk_quarantines: self.stale_risk_quarantines.len() as u64,
            public_records: self.public_records.len() as u64,
            active_breakers: self
                .breaker_thresholds
                .values()
                .filter(|threshold| threshold.status.active())
                .count() as u64,
            delayed_liquidations: self
                .liquidation_delays
                .values()
                .filter(|delay| delay.status.pending())
                .count() as u64,
            quarantined_buckets: self.stale_risk_quarantines.len() as u64,
            total_keeper_credit_millis: self
                .keeper_credits
                .values()
                .map(|credit| credit.credit_millis)
                .sum(),
        }
    }

    fn install_demo_records(&mut self) {
        let bucket_id = stable_id("bucket", "wxmr-core-collateral");
        let attestation_id = stable_id("attestation", "wxmr-core-depth-freshness");
        let depth_id = stable_id("depth", "wxmr-core-amm-depth");
        let threshold_id = stable_id("threshold", "wxmr-core-critical-breaker");
        let credit_id = stable_id("keeper-credit", "keeper-low-fee-delay-credit");
        let delay_id = stable_id("delay", "wxmr-liquidation-delay");
        let quarantine_id = stable_id("quarantine", "stale-depth-probe");
        let record_id = stable_id("public-record", "devnet-collateral-liquidity-root");

        let bucket = ShieldedCollateralBucket {
            bucket_id: bucket_id.clone(),
            asset_id: "wxmr-devnet".to_string(),
            collateral_class: CollateralClass::WrappedMonero,
            owner_commitment: deterministic_root("owner", "wxmr-core-owner"),
            bucket_commitment_root: deterministic_root("bucket-commitment", "wxmr-core"),
            amount_commitment: deterministic_root("amount", "wxmr-core-amount"),
            haircut_bps: CollateralClass::WrappedMonero.default_haircut_bps(),
            concentration_bps: 2_100,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            status: BucketStatus::Watchlisted,
            opened_at_height: DEVNET_HEIGHT,
            expires_at_height: DEVNET_HEIGHT + self.config.bucket_ttl_blocks,
            latest_attestation_id: attestation_id.clone(),
        };
        let attestation = PqRiskAttestation {
            attestation_id: attestation_id.clone(),
            subject_id: bucket_id.clone(),
            kind: AttestationKind::LiquidityDepth,
            committee_root: deterministic_root("committee", "risk-committee-a"),
            payload_commitment_root: deterministic_root("payload", "wxmr-depth-payload"),
            pq_signature_root: deterministic_root("signature", "wxmr-depth-signature"),
            aggregate_weight_bps: 7_500,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            verdict: AttestationVerdict::ValidWithWarning,
            observed_at_height: DEVNET_HEIGHT + 12,
            expires_at_height: DEVNET_HEIGHT + 12 + self.config.attestation_ttl_blocks,
        };
        let depth = LiquidityDepthCommitment {
            depth_id: depth_id.clone(),
            bucket_id: bucket_id.clone(),
            venue: LiquidityVenue::ConfidentialAmm,
            venue_commitment: deterministic_root("venue", "wxmr-confidential-amm"),
            depth_commitment_root: deterministic_root("depth-commitment", "wxmr-depth"),
            available_depth_bps: 1_420,
            slippage_bps: 82,
            liquidation_capacity_bps: 1_050,
            observed_at_height: DEVNET_HEIGHT + 12,
            expires_at_height: DEVNET_HEIGHT + 12 + self.config.liquidity_ttl_blocks,
            status: DepthStatus::Degrading,
            pq_attestation_id: attestation_id.clone(),
        };
        let threshold = BreakerThreshold {
            threshold_id: threshold_id.clone(),
            bucket_id: bucket_id.clone(),
            severity: BreakerSeverity::DelayLiquidations,
            min_depth_bps: self.config.min_liquidity_depth_bps,
            max_concentration_bps: self.config.max_collateral_concentration_bps,
            max_slippage_bps: 120,
            max_stale_blocks: self.config.max_stale_risk_blocks,
            cooldown_blocks: self.config.breaker_cooldown_blocks,
            policy_root: deterministic_root("policy", "wxmr-breaker-policy"),
            status: BreakerStatus::Triggered,
            triggered_at_height: Some(DEVNET_HEIGHT + 18),
            clears_after_height: DEVNET_HEIGHT + 18 + self.config.breaker_cooldown_blocks,
        };
        let credit = LowFeeKeeperCredit {
            credit_id: credit_id.clone(),
            keeper_commitment: deterministic_root("keeper", "keeper-alpha"),
            bucket_id: bucket_id.clone(),
            fee_asset_id: "fee-credit-devnet".to_string(),
            credit_commitment_root: deterministic_root("credit", "keeper-alpha-credit"),
            credit_millis: 4_200_000,
            median_fee_bps: 6,
            p95_fee_bps: 14,
            coverage_bps: 8_200,
            issued_at_height: DEVNET_HEIGHT + 18,
            expires_at_height: DEVNET_HEIGHT + 18 + self.config.keeper_credit_ttl_blocks,
            status: KeeperCreditStatus::Reserved,
        };
        let delay = LiquidationDelayRecord {
            delay_id,
            bucket_id: bucket_id.clone(),
            position_commitment: deterministic_root("position", "wxmr-position-7"),
            liquidation_nullifier: deterministic_root("liquidation-nullifier", "wxmr-position-7"),
            reason_root: deterministic_root("delay-reason", "depth-degrading"),
            keeper_credit_id: credit_id,
            requested_at_height: DEVNET_HEIGHT + 18,
            release_height: DEVNET_HEIGHT + 18 + self.config.delay_window_blocks,
            status: LiquidationDelayStatus::KeeperCovered,
            severity: BreakerSeverity::DelayLiquidations,
        };
        let quarantine = StaleRiskQuarantine {
            quarantine_id,
            bucket_id: bucket_id.clone(),
            subject_root: deterministic_root("subject", "wxmr-stale-depth"),
            quarantine_nullifier: deterministic_root("quarantine-nullifier", "wxmr-stale-depth"),
            reason: QuarantineReason::StaleRisk,
            evidence_root: deterministic_root("evidence", "wxmr-stale-depth"),
            attestation_id,
            opened_at_height: DEVNET_HEIGHT + 22,
            expires_at_height: DEVNET_HEIGHT + 22 + self.config.quarantine_ttl_blocks,
            release_condition_root: deterministic_root("release", "fresh-attestation-required"),
        };

        self.insert_bucket(bucket).expect("generated demo bucket");
        self.insert_attestation(attestation)
            .expect("generated demo attestation");
        self.insert_liquidity_depth(depth)
            .expect("generated demo liquidity depth");
        self.insert_breaker_threshold(threshold)
            .expect("generated demo breaker threshold");
        self.insert_keeper_credit(credit)
            .expect("generated demo keeper credit");
        self.insert_liquidation_delay(delay)
            .expect("generated demo liquidation delay");
        self.insert_quarantine(quarantine)
            .expect("generated demo quarantine");

        let record = DeterministicPublicRecord {
            record_id,
            record_kind: "collateral_liquidity_breaker_root".to_string(),
            subject_id: bucket_id,
            public_root: self.state_root(),
            sequence: self.public_records.len() as u64,
            emitted_at_height: DEVNET_HEIGHT + 24,
        };
        self.insert_public_record(record)
            .expect("generated demo public record");
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
    canonical_record_root("STATE", record)
}

fn validate_bucket(bucket: &ShieldedCollateralBucket, config: &Config) -> Result<()> {
    require_non_empty("bucket_id", &bucket.bucket_id)?;
    require_non_empty("asset_id", &bucket.asset_id)?;
    require_root("owner_commitment", &bucket.owner_commitment)?;
    require_root("bucket_commitment_root", &bucket.bucket_commitment_root)?;
    require_root("amount_commitment", &bucket.amount_commitment)?;
    require_bps("haircut_bps", bucket.haircut_bps)?;
    require_bps("concentration_bps", bucket.concentration_bps)?;
    require_non_empty("latest_attestation_id", &bucket.latest_attestation_id)?;
    validate_privacy_and_pq(
        bucket.privacy_set_size,
        bucket.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if bucket.concentration_bps > config.max_collateral_concentration_bps {
        return Err("bucket concentration exceeds breaker maximum".to_string());
    }
    if bucket.expires_at_height <= bucket.opened_at_height {
        return Err("bucket expiry must be after open height".to_string());
    }
    if bucket
        .expires_at_height
        .saturating_sub(bucket.opened_at_height)
        > config.bucket_ttl_blocks
    {
        return Err("bucket TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_depth(
    depth: &LiquidityDepthCommitment,
    config: &Config,
    buckets: &BTreeMap<String, ShieldedCollateralBucket>,
) -> Result<()> {
    require_non_empty("depth_id", &depth.depth_id)?;
    require_non_empty("bucket_id", &depth.bucket_id)?;
    require_root("venue_commitment", &depth.venue_commitment)?;
    require_root("depth_commitment_root", &depth.depth_commitment_root)?;
    require_bps("available_depth_bps", depth.available_depth_bps)?;
    require_bps("slippage_bps", depth.slippage_bps)?;
    require_bps("liquidation_capacity_bps", depth.liquidation_capacity_bps)?;
    require_non_empty("pq_attestation_id", &depth.pq_attestation_id)?;
    if !buckets.contains_key(&depth.bucket_id) {
        return Err("liquidity depth references unknown bucket".to_string());
    }
    if depth.available_depth_bps < config.critical_liquidity_depth_bps {
        return Err("liquidity depth below critical breaker floor".to_string());
    }
    if depth.expires_at_height <= depth.observed_at_height {
        return Err("liquidity depth expiry must be after observation".to_string());
    }
    if depth
        .expires_at_height
        .saturating_sub(depth.observed_at_height)
        > config.liquidity_ttl_blocks
    {
        return Err("liquidity depth TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_attestation(attestation: &PqRiskAttestation, config: &Config) -> Result<()> {
    require_non_empty("attestation_id", &attestation.attestation_id)?;
    require_non_empty("subject_id", &attestation.subject_id)?;
    require_root("committee_root", &attestation.committee_root)?;
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
    if attestation.verdict.contributes_weight()
        && attestation.aggregate_weight_bps < config.min_attestation_weight_bps
    {
        return Err("PQ attestation aggregate weight below quorum".to_string());
    }
    if attestation.expires_at_height <= attestation.observed_at_height {
        return Err("PQ attestation expiry must be after observation".to_string());
    }
    if attestation
        .expires_at_height
        .saturating_sub(attestation.observed_at_height)
        > config.attestation_ttl_blocks
    {
        return Err("PQ attestation TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_threshold(
    threshold: &BreakerThreshold,
    config: &Config,
    buckets: &BTreeMap<String, ShieldedCollateralBucket>,
) -> Result<()> {
    require_non_empty("threshold_id", &threshold.threshold_id)?;
    require_non_empty("bucket_id", &threshold.bucket_id)?;
    require_root("policy_root", &threshold.policy_root)?;
    require_bps("min_depth_bps", threshold.min_depth_bps)?;
    require_bps("max_concentration_bps", threshold.max_concentration_bps)?;
    require_bps("max_slippage_bps", threshold.max_slippage_bps)?;
    require_positive_u64("max_stale_blocks", threshold.max_stale_blocks)?;
    require_positive_u64("cooldown_blocks", threshold.cooldown_blocks)?;
    if !buckets.contains_key(&threshold.bucket_id) {
        return Err("breaker threshold references unknown bucket".to_string());
    }
    if threshold.min_depth_bps < config.critical_liquidity_depth_bps {
        return Err("breaker minimum depth below critical floor".to_string());
    }
    if threshold.max_concentration_bps > config.max_collateral_concentration_bps {
        return Err("breaker concentration exceeds configured maximum".to_string());
    }
    if threshold.max_stale_blocks > config.max_stale_risk_blocks {
        return Err("breaker stale risk window exceeds configured maximum".to_string());
    }
    if threshold.cooldown_blocks > config.breaker_cooldown_blocks {
        return Err("breaker cooldown exceeds configured maximum".to_string());
    }
    if let Some(triggered_at_height) = threshold.triggered_at_height {
        if threshold.clears_after_height <= triggered_at_height {
            return Err("breaker clear height must follow trigger height".to_string());
        }
    }
    Ok(())
}

fn validate_keeper_credit(
    credit: &LowFeeKeeperCredit,
    config: &Config,
    buckets: &BTreeMap<String, ShieldedCollateralBucket>,
) -> Result<()> {
    require_non_empty("credit_id", &credit.credit_id)?;
    require_root("keeper_commitment", &credit.keeper_commitment)?;
    require_non_empty("bucket_id", &credit.bucket_id)?;
    require_non_empty("fee_asset_id", &credit.fee_asset_id)?;
    require_root("credit_commitment_root", &credit.credit_commitment_root)?;
    require_positive_u64("credit_millis", credit.credit_millis)?;
    require_bps("median_fee_bps", credit.median_fee_bps)?;
    require_bps("p95_fee_bps", credit.p95_fee_bps)?;
    require_bps("coverage_bps", credit.coverage_bps)?;
    if !buckets.contains_key(&credit.bucket_id) {
        return Err("keeper credit references unknown bucket".to_string());
    }
    if credit.median_fee_bps > credit.p95_fee_bps {
        return Err("median fee cannot exceed p95 fee".to_string());
    }
    if credit.median_fee_bps > config.keeper_low_fee_alert_bps {
        return Err("keeper credit fee sample above low-fee alert".to_string());
    }
    if credit.coverage_bps < config.min_keeper_coverage_bps {
        return Err("keeper credit coverage below configured minimum".to_string());
    }
    if credit.expires_at_height <= credit.issued_at_height {
        return Err("keeper credit expiry must be after issue height".to_string());
    }
    if credit
        .expires_at_height
        .saturating_sub(credit.issued_at_height)
        > config.keeper_credit_ttl_blocks
    {
        return Err("keeper credit TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_liquidation_delay(
    delay: &LiquidationDelayRecord,
    config: &Config,
    buckets: &BTreeMap<String, ShieldedCollateralBucket>,
    nullifiers: &BTreeSet<String>,
) -> Result<()> {
    require_non_empty("delay_id", &delay.delay_id)?;
    require_non_empty("bucket_id", &delay.bucket_id)?;
    require_root("position_commitment", &delay.position_commitment)?;
    require_root("liquidation_nullifier", &delay.liquidation_nullifier)?;
    require_root("reason_root", &delay.reason_root)?;
    require_non_empty("keeper_credit_id", &delay.keeper_credit_id)?;
    if !buckets.contains_key(&delay.bucket_id) {
        return Err("liquidation delay references unknown bucket".to_string());
    }
    if !nullifiers.contains(&delay.liquidation_nullifier)
        && delay.status != LiquidationDelayStatus::Scheduled
    {
        return Err("covered liquidation delay must have an inserted nullifier".to_string());
    }
    if delay.release_height <= delay.requested_at_height {
        return Err("liquidation delay release must follow request".to_string());
    }
    if delay
        .release_height
        .saturating_sub(delay.requested_at_height)
        > config.delay_window_blocks
    {
        return Err("liquidation delay window exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_quarantine(
    quarantine: &StaleRiskQuarantine,
    config: &Config,
    buckets: &BTreeMap<String, ShieldedCollateralBucket>,
    nullifiers: &BTreeSet<String>,
) -> Result<()> {
    require_non_empty("quarantine_id", &quarantine.quarantine_id)?;
    require_non_empty("bucket_id", &quarantine.bucket_id)?;
    require_root("subject_root", &quarantine.subject_root)?;
    require_root("quarantine_nullifier", &quarantine.quarantine_nullifier)?;
    require_root("evidence_root", &quarantine.evidence_root)?;
    require_non_empty("attestation_id", &quarantine.attestation_id)?;
    require_root("release_condition_root", &quarantine.release_condition_root)?;
    if !buckets.contains_key(&quarantine.bucket_id) {
        return Err("quarantine references unknown bucket".to_string());
    }
    if !nullifiers.contains(&quarantine.quarantine_nullifier) {
        return Err("quarantine must have an inserted nullifier".to_string());
    }
    if quarantine.expires_at_height <= quarantine.opened_at_height {
        return Err("quarantine expiry must follow open height".to_string());
    }
    if quarantine
        .expires_at_height
        .saturating_sub(quarantine.opened_at_height)
        > config.quarantine_ttl_blocks
    {
        return Err("quarantine TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_public_record(record: &DeterministicPublicRecord) -> Result<()> {
    require_non_empty("record_id", &record.record_id)?;
    require_non_empty("record_kind", &record.record_kind)?;
    require_non_empty("subject_id", &record.subject_id)?;
    require_root("public_root", &record.public_root)?;
    require_positive_u64("emitted_at_height", record.emitted_at_height)?;
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
                "PRIVATE-L2-PQ-COLLATERAL-LIQUIDITY-BREAKER-{}",
                label.to_ascii_uppercase()
            ),
            &parts,
        )
    }
}

fn empty_root(label: &str) -> String {
    merkle_root(
        &format!(
            "PRIVATE-L2-PQ-COLLATERAL-LIQUIDITY-BREAKER-EMPTY-{}",
            label.to_ascii_uppercase()
        ),
        &[],
    )
}

fn canonical_record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-COLLATERAL-LIQUIDITY-BREAKER-RECORD-{}",
            label.to_ascii_uppercase()
        ),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn stable_id(domain: &str, label: &str) -> String {
    deterministic_root(domain, label)
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-COLLATERAL-LIQUIDITY-BREAKER-{}",
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
