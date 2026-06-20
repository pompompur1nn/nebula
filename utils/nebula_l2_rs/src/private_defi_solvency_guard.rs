use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateDefiSolvencyGuardResult<T> = Result<T, String>;

pub const PRIVATE_DEFI_SOLVENCY_GUARD_PROTOCOL_VERSION: &str =
    "nebula-private-defi-solvency-guard-v1";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_PROOF_SYSTEM: &str = "zk-private-defi-solvency-envelope-v1";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_CREDIT_SCORE_ORACLE: &str = "private-credit-score-oracle-v1";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_LIQUIDATION_CIRCUIT: &str =
    "fee-bounded-private-liquidation-v1";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_SWAP_NETTING_SYSTEM: &str =
    "confidential-swap-netting-solvency-v1";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-256f";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEVNET_HEIGHT: u64 = 1_616;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_ORACLE_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_LIQUIDATION_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MIN_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_SOLVENCY_BUFFER_BPS: u64 = 1_250;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_LIQUIDATION_FEE_CAP_BPS: u64 = 550;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_HEALTH_DRIFT_BPS: u64 = 800;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_NETTING_IMBALANCE_BPS: u64 = 1_500;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_BUCKET_EXPOSURE_BPS: u64 = 2_500;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_FEE_UNITS: u64 = 8;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_VENUES: usize = 4_096;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_BUCKETS: usize = 16_384;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_POSITIONS: usize = 262_144;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_ORACLE_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_BREAKERS: usize = 65_536;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_LIQUIDATIONS: usize = 262_144;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_NETTING_WINDOWS: usize = 65_536;
pub const PRIVATE_DEFI_SOLVENCY_GUARD_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencyVenueKind {
    LendingMarket,
    StablecoinIssuer,
    DerivativesClearinghouse,
    TokenizedVault,
    ConfidentialAmm,
    CrossMarginDesk,
    LiquidationCircuit,
    CreditOracle,
}

impl SolvencyVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LendingMarket => "lending_market",
            Self::StablecoinIssuer => "stablecoin_issuer",
            Self::DerivativesClearinghouse => "derivatives_clearinghouse",
            Self::TokenizedVault => "tokenized_vault",
            Self::ConfidentialAmm => "confidential_amm",
            Self::CrossMarginDesk => "cross_margin_desk",
            Self::LiquidationCircuit => "liquidation_circuit",
            Self::CreditOracle => "credit_oracle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencyGuardStatus {
    Draft,
    Active,
    Watch,
    Guarded,
    Halted,
    Quarantined,
    Retired,
}

impl SolvencyGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Watch => "watch",
            Self::Guarded => "guarded",
            Self::Halted => "halted",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBucketKind {
    Prime,
    Core,
    Watch,
    Stressed,
    Distressed,
    LiquidationOnly,
    OracleReview,
    GovernanceHold,
}

impl RiskBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prime => "prime",
            Self::Core => "core",
            Self::Watch => "watch",
            Self::Stressed => "stressed",
            Self::Distressed => "distressed",
            Self::LiquidationOnly => "liquidation_only",
            Self::OracleReview => "oracle_review",
            Self::GovernanceHold => "governance_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralClass {
    Native,
    WrappedMonero,
    Stablecoin,
    LiquidStaking,
    TokenizedVaultShare,
    DerivativesMargin,
    CrossRollupReceipt,
    InsuranceClaim,
}

impl CollateralClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::WrappedMonero => "wrapped_monero",
            Self::Stablecoin => "stablecoin",
            Self::LiquidStaking => "liquid_staking",
            Self::TokenizedVaultShare => "tokenized_vault_share",
            Self::DerivativesMargin => "derivatives_margin",
            Self::CrossRollupReceipt => "cross_rollup_receipt",
            Self::InsuranceClaim => "insurance_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebtClass {
    VariableBorrow,
    FixedBorrow,
    StablecoinMint,
    PerpFunding,
    OptionPremium,
    VaultLeverage,
    CreditLine,
    SettlementAdvance,
}

impl DebtClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VariableBorrow => "variable_borrow",
            Self::FixedBorrow => "fixed_borrow",
            Self::StablecoinMint => "stablecoin_mint",
            Self::PerpFunding => "perp_funding",
            Self::OptionPremium => "option_premium",
            Self::VaultLeverage => "vault_leverage",
            Self::CreditLine => "credit_line",
            Self::SettlementAdvance => "settlement_advance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerKind {
    GlobalSolvency,
    VenueLiquidity,
    OracleStaleness,
    CollateralShock,
    StablecoinDepeg,
    DerivativeMargin,
    VaultDrawdown,
    LiquidationCongestion,
    CreditScoreDrift,
    SwapNettingImbalance,
}

impl CircuitBreakerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GlobalSolvency => "global_solvency",
            Self::VenueLiquidity => "venue_liquidity",
            Self::OracleStaleness => "oracle_staleness",
            Self::CollateralShock => "collateral_shock",
            Self::StablecoinDepeg => "stablecoin_depeg",
            Self::DerivativeMargin => "derivative_margin",
            Self::VaultDrawdown => "vault_drawdown",
            Self::LiquidationCongestion => "liquidation_congestion",
            Self::CreditScoreDrift => "credit_score_drift",
            Self::SwapNettingImbalance => "swap_netting_imbalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerStatus {
    Armed,
    Tripped,
    CoolingDown,
    GovernanceReview,
    Released,
    Expired,
}

impl BreakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Tripped => "tripped",
            Self::CoolingDown => "cooling_down",
            Self::GovernanceReview => "governance_review",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationMode {
    Disabled,
    PrivateDutchAuction,
    SealedBatch,
    KeeperNetting,
    ProtocolBackstop,
    InsuranceFund,
    GovernanceOnly,
}

impl LiquidationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::PrivateDutchAuction => "private_dutch_auction",
            Self::SealedBatch => "sealed_batch",
            Self::KeeperNetting => "keeper_netting",
            Self::ProtocolBackstop => "protocol_backstop",
            Self::InsuranceFund => "insurance_fund",
            Self::GovernanceOnly => "governance_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleLaneKind {
    PriceMedian,
    CreditScore,
    ReserveProof,
    VaultSharePrice,
    FundingRate,
    VolatilitySurface,
    LiquidityDepth,
    CrossRollupHealth,
}

impl OracleLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceMedian => "price_median",
            Self::CreditScore => "credit_score",
            Self::ReserveProof => "reserve_proof",
            Self::VaultSharePrice => "vault_share_price",
            Self::FundingRate => "funding_rate",
            Self::VolatilitySurface => "volatility_surface",
            Self::LiquidityDepth => "liquidity_depth",
            Self::CrossRollupHealth => "cross_rollup_health",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    QuorumChecked,
    Accepted,
    Rejected,
    Expired,
    Challenged,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::QuorumChecked => "quorum_checked",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingWindowStatus {
    Open,
    Sealed,
    Matched,
    Settled,
    Disputed,
    Cancelled,
}

impl NettingWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolvencyEventKind {
    BorrowAdmitted,
    MintBounded,
    DerivativeRiskPosted,
    VaultLimitUpdated,
    LiquidationQueued,
    BreakerTripped,
    BreakerReleased,
    OracleAttested,
    NettingSettled,
    RiskBucketRotated,
}

impl SolvencyEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BorrowAdmitted => "borrow_admitted",
            Self::MintBounded => "mint_bounded",
            Self::DerivativeRiskPosted => "derivative_risk_posted",
            Self::VaultLimitUpdated => "vault_limit_updated",
            Self::LiquidationQueued => "liquidation_queued",
            Self::BreakerTripped => "breaker_tripped",
            Self::BreakerReleased => "breaker_released",
            Self::OracleAttested => "oracle_attested",
            Self::NettingSettled => "netting_settled",
            Self::RiskBucketRotated => "risk_bucket_rotated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePolicyKind {
    FlatCap,
    NotionalBps,
    CongestionWeighted,
    KeeperAuction,
    ProtocolSubsidized,
    EmergencyZeroFee,
}

impl FeePolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FlatCap => "flat_cap",
            Self::NotionalBps => "notional_bps",
            Self::CongestionWeighted => "congestion_weighted",
            Self::KeeperAuction => "keeper_auction",
            Self::ProtocolSubsidized => "protocol_subsidized",
            Self::EmergencyZeroFee => "emergency_zero_fee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofEnvelopeKind {
    CollateralHealth,
    LiabilityBound,
    ReserveCoverage,
    CreditBucket,
    LiquidationFee,
    SwapNetting,
    BreakerWitness,
    PublicAudit,
}

impl ProofEnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CollateralHealth => "collateral_health",
            Self::LiabilityBound => "liability_bound",
            Self::ReserveCoverage => "reserve_coverage",
            Self::CreditBucket => "credit_bucket",
            Self::LiquidationFee => "liquidation_fee",
            Self::SwapNetting => "swap_netting",
            Self::BreakerWitness => "breaker_witness",
            Self::PublicAudit => "public_audit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthTrend {
    Improving,
    Stable,
    Watch,
    Deteriorating,
    Critical,
}

impl HealthTrend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Improving => "improving",
            Self::Stable => "stable",
            Self::Watch => "watch",
            Self::Deteriorating => "deteriorating",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantSeverity {
    Info,
    Watch,
    Caution,
    Critical,
    Halted,
}

impl InvariantSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Caution => "caution",
            Self::Critical => "critical",
            Self::Halted => "halted",
        }
    }
}

impl SolvencyVenueKind {
    pub fn default_health_floor_bps(self) -> u64 {
        match self {
            Self::LendingMarket => 12_500,
            Self::StablecoinIssuer => 11_000,
            Self::DerivativesClearinghouse => 13_500,
            Self::TokenizedVault => 10_750,
            Self::ConfidentialAmm => 10_250,
            Self::CrossMarginDesk => 14_000,
            Self::LiquidationCircuit => 10_500,
            Self::CreditOracle => 10_000,
        }
    }
}

impl RiskBucketKind {
    pub fn max_ltv_bps(self) -> u64 {
        match self {
            Self::Prime => 8_000,
            Self::Core => 7_000,
            Self::Watch => 5_500,
            Self::Stressed => 3_500,
            Self::Distressed => 1_500,
            Self::LiquidationOnly => 0,
            Self::OracleReview => 2_500,
            Self::GovernanceHold => 0,
        }
    }

    pub fn allows_new_debt(self) -> bool {
        matches!(self, Self::Prime | Self::Core | Self::Watch)
    }
}

impl BreakerStatus {
    pub fn blocks_new_risk(self) -> bool {
        matches!(
            self,
            Self::Tripped | Self::CoolingDown | Self::GovernanceReview
        )
    }
}

impl InvariantSeverity {
    pub fn rank(self) -> u64 {
        match self {
            Self::Info => 1,
            Self::Watch => 2,
            Self::Caution => 3,
            Self::Critical => 4,
            Self::Halted => 5,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub epoch_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub liquidation_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_oracle_quorum_bps: u64,
    pub solvency_buffer_bps: u64,
    pub liquidation_fee_cap_bps: u64,
    pub max_health_drift_bps: u64,
    pub max_netting_imbalance_bps: u64,
    pub max_bucket_exposure_bps: u64,
    pub max_fee_units: u64,
    pub max_venues: usize,
    pub max_buckets: usize,
    pub max_positions: usize,
    pub max_oracle_attestations: usize,
    pub max_breakers: usize,
    pub max_liquidations: usize,
    pub max_netting_windows: usize,
    pub max_events: usize,
    pub governance_commitment: String,
    pub fee_asset_id: String,
    pub proof_system: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolvencyVenue {
    pub venue_id: String,
    pub kind: SolvencyVenueKind,
    pub status: SolvencyGuardStatus,
    pub operator_commitment: String,
    pub asset_root: String,
    pub liability_root: String,
    pub health_floor_bps: u64,
    pub max_drawdown_bps: u64,
    pub oracle_lane_id: String,
    pub breaker_group_id: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskBucket {
    pub bucket_id: String,
    pub kind: RiskBucketKind,
    pub venue_id: String,
    pub privacy_set_size: u64,
    pub exposure_commitment: String,
    pub collateral_class: CollateralClass,
    pub debt_class: DebtClass,
    pub max_ltv_bps: u64,
    pub utilization_bps: u64,
    pub health_trend: HealthTrend,
    pub rotated_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialPositionHealth {
    pub position_id: String,
    pub venue_id: String,
    pub bucket_id: String,
    pub owner_nullifier: String,
    pub collateral_commitment: String,
    pub debt_commitment: String,
    pub health_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub credit_score_commitment: String,
    pub last_checked_height: u64,
    pub proof_envelope: ProofEnvelopeKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub kind: OracleLaneKind,
    pub status: AttestationStatus,
    pub committee_root: String,
    pub subject_commitment: String,
    pub value_commitment: String,
    pub quorum_bps: u64,
    pub staleness_blocks: u64,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub breaker_id: String,
    pub group_id: String,
    pub kind: CircuitBreakerKind,
    pub status: BreakerStatus,
    pub severity: InvariantSeverity,
    pub trip_reason_commitment: String,
    pub threshold_bps: u64,
    pub observed_bps: u64,
    pub cooldown_blocks: u64,
    pub tripped_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidationCircuit {
    pub liquidation_id: String,
    pub position_id: String,
    pub venue_id: String,
    pub mode: LiquidationMode,
    pub fee_policy: FeePolicyKind,
    pub status: SolvencyGuardStatus,
    pub seized_collateral_commitment: String,
    pub repaid_debt_commitment: String,
    pub max_fee_bps: u64,
    pub keeper_privacy_set_size: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapNettingWindow {
    pub window_id: String,
    pub venue_id: String,
    pub status: NettingWindowStatus,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub imbalance_bps: u64,
    pub privacy_set_size: u64,
    pub fee_cap_units: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolvencyEvent {
    pub event_id: String,
    pub kind: SolvencyEventKind,
    pub venue_id: String,
    pub subject_commitment: String,
    pub severity: InvariantSeverity,
    pub record_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub check_id: String,
    pub venue_id: String,
    pub severity: InvariantSeverity,
    pub message_commitment: String,
    pub target_bps: u64,
    pub observed_bps: u64,
    pub proof_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub venue_root: String,
    pub bucket_root: String,
    pub position_root: String,
    pub oracle_root: String,
    pub breaker_root: String,
    pub liquidation_root: String,
    pub netting_root: String,
    pub event_root: String,
    pub invariant_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counters {
    pub venues: usize,
    pub buckets: usize,
    pub positions: usize,
    pub oracle_attestations: usize,
    pub breakers: usize,
    pub liquidations: usize,
    pub netting_windows: usize,
    pub events: usize,
    pub invariant_checks: usize,
    pub halted_venues: usize,
    pub tripped_breakers: usize,
    pub open_liquidations: usize,
}

fn guard_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "private-defi-solvency-guard:commitment",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

fn root_for_values(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn bounded_bps(value: u64, label: &str) -> PrivateDefiSolvencyGuardResult<()> {
    if value > PRIVATE_DEFI_SOLVENCY_GUARD_MAX_BPS {
        return Err(format!("{label} exceeds bps range"));
    }
    Ok(())
}

fn non_empty(value: &str, label: &str) -> PrivateDefiSolvencyGuardResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_EPOCH_BLOCKS,
            oracle_ttl_blocks: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_ORACLE_TTL_BLOCKS,
            liquidation_ttl_blocks: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_LIQUIDATION_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_oracle_quorum_bps: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MIN_ORACLE_QUORUM_BPS,
            solvency_buffer_bps: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_SOLVENCY_BUFFER_BPS,
            liquidation_fee_cap_bps: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_LIQUIDATION_FEE_CAP_BPS,
            max_health_drift_bps: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_HEALTH_DRIFT_BPS,
            max_netting_imbalance_bps:
                PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_NETTING_IMBALANCE_BPS,
            max_bucket_exposure_bps: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_BUCKET_EXPOSURE_BPS,
            max_fee_units: PRIVATE_DEFI_SOLVENCY_GUARD_DEFAULT_MAX_FEE_UNITS,
            max_venues: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_VENUES,
            max_buckets: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_BUCKETS,
            max_positions: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_POSITIONS,
            max_oracle_attestations: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_ORACLE_ATTESTATIONS,
            max_breakers: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_BREAKERS,
            max_liquidations: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_LIQUIDATIONS,
            max_netting_windows: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_NETTING_WINDOWS,
            max_events: PRIVATE_DEFI_SOLVENCY_GUARD_MAX_EVENTS,
            governance_commitment: guard_commitment("governance", "devnet-solvency-council"),
            fee_asset_id: "asset:dxmr".to_string(),
            proof_system: PRIVATE_DEFI_SOLVENCY_GUARD_PROOF_SYSTEM.to_string(),
        }
    }

    pub fn validate(&self) -> PrivateDefiSolvencyGuardResult<()> {
        if self.epoch_blocks == 0 {
            return Err("solvency guard epoch blocks must be non-zero".to_string());
        }
        if self.oracle_ttl_blocks == 0 || self.oracle_ttl_blocks > self.epoch_blocks {
            return Err("solvency guard oracle ttl must fit inside an epoch".to_string());
        }
        if self.liquidation_ttl_blocks == 0 {
            return Err("solvency guard liquidation ttl must be non-zero".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("solvency guard privacy set size must be non-zero".to_string());
        }
        bounded_bps(self.min_oracle_quorum_bps, "oracle quorum")?;
        bounded_bps(self.solvency_buffer_bps, "solvency buffer")?;
        bounded_bps(self.liquidation_fee_cap_bps, "liquidation fee cap")?;
        bounded_bps(self.max_health_drift_bps, "health drift")?;
        bounded_bps(self.max_netting_imbalance_bps, "netting imbalance")?;
        bounded_bps(self.max_bucket_exposure_bps, "bucket exposure")?;
        if self.min_oracle_quorum_bps < 5_001 {
            return Err("solvency guard oracle quorum must be majority".to_string());
        }
        if self.max_fee_units == 0 {
            return Err("solvency guard max fee units must be non-zero".to_string());
        }
        if self.max_venues == 0 || self.max_buckets == 0 || self.max_positions == 0 {
            return Err("solvency guard primary capacities must be non-zero".to_string());
        }
        if self.max_oracle_attestations == 0
            || self.max_breakers == 0
            || self.max_liquidations == 0
            || self.max_netting_windows == 0
            || self.max_events == 0
        {
            return Err("solvency guard operational capacities must be non-zero".to_string());
        }
        non_empty(&self.governance_commitment, "governance commitment")?;
        non_empty(&self.fee_asset_id, "fee asset id")?;
        non_empty(&self.proof_system, "proof system")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks.to_string(), "oracle_ttl_blocks": self.oracle_ttl_blocks.to_string(), "liquidation_ttl_blocks": self.liquidation_ttl_blocks.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size.to_string(), "min_oracle_quorum_bps": self.min_oracle_quorum_bps.to_string(), "solvency_buffer_bps": self.solvency_buffer_bps.to_string(),
            "liquidation_fee_cap_bps": self.liquidation_fee_cap_bps.to_string(), "max_health_drift_bps": self.max_health_drift_bps.to_string(), "max_netting_imbalance_bps": self.max_netting_imbalance_bps.to_string(),
            "max_bucket_exposure_bps": self.max_bucket_exposure_bps.to_string(), "max_fee_units": self.max_fee_units.to_string(), "max_venues": self.max_venues.to_string(), "max_buckets": self.max_buckets.to_string(),
            "max_positions": self.max_positions.to_string(), "max_oracle_attestations": self.max_oracle_attestations.to_string(), "max_breakers": self.max_breakers.to_string(), "max_liquidations": self.max_liquidations.to_string(),
            "max_netting_windows": self.max_netting_windows.to_string(), "max_events": self.max_events.to_string(), "governance_commitment": self.governance_commitment, "fee_asset_id": self.fee_asset_id, "proof_system": self.proof_system,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl SolvencyVenue {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_id": self.venue_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "asset_root": self.asset_root,
            "liability_root": self.liability_root,
            "health_floor_bps": self.health_floor_bps.to_string(),
            "max_drawdown_bps": self.max_drawdown_bps.to_string(),
            "oracle_lane_id": self.oracle_lane_id,
            "breaker_group_id": self.breaker_group_id,
            "opened_at_height": self.opened_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl RiskBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "venue_id": self.venue_id,
            "privacy_set_size": self.privacy_set_size.to_string(),
            "exposure_commitment": self.exposure_commitment,
            "collateral_class": self.collateral_class.as_str(),
            "debt_class": self.debt_class.as_str(),
            "max_ltv_bps": self.max_ltv_bps.to_string(),
            "utilization_bps": self.utilization_bps.to_string(),
            "health_trend": self.health_trend.as_str(),
            "rotated_at_height": self.rotated_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl ConfidentialPositionHealth {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "venue_id": self.venue_id,
            "bucket_id": self.bucket_id,
            "owner_nullifier": self.owner_nullifier,
            "collateral_commitment": self.collateral_commitment,
            "debt_commitment": self.debt_commitment,
            "health_factor_bps": self.health_factor_bps.to_string(),
            "liquidation_threshold_bps": self.liquidation_threshold_bps.to_string(),
            "credit_score_commitment": self.credit_score_commitment,
            "last_checked_height": self.last_checked_height.to_string(),
            "proof_envelope": self.proof_envelope.as_str(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl OracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "committee_root": self.committee_root,
            "subject_commitment": self.subject_commitment,
            "value_commitment": self.value_commitment,
            "quorum_bps": self.quorum_bps.to_string(),
            "staleness_blocks": self.staleness_blocks.to_string(),
            "submitted_at_height": self.submitted_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl CircuitBreaker {
    pub fn public_record(&self) -> Value {
        json!({
            "breaker_id": self.breaker_id,
            "group_id": self.group_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "trip_reason_commitment": self.trip_reason_commitment,
            "threshold_bps": self.threshold_bps.to_string(),
            "observed_bps": self.observed_bps.to_string(),
            "cooldown_blocks": self.cooldown_blocks.to_string(),
            "tripped_at_height": self.tripped_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl LiquidationCircuit {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidation_id": self.liquidation_id,
            "position_id": self.position_id,
            "venue_id": self.venue_id,
            "mode": self.mode.as_str(),
            "fee_policy": self.fee_policy.as_str(),
            "status": self.status.as_str(),
            "seized_collateral_commitment": self.seized_collateral_commitment,
            "repaid_debt_commitment": self.repaid_debt_commitment,
            "max_fee_bps": self.max_fee_bps.to_string(),
            "keeper_privacy_set_size": self.keeper_privacy_set_size.to_string(),
            "expires_at_height": self.expires_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl SwapNettingWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "venue_id": self.venue_id,
            "status": self.status.as_str(),
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "imbalance_bps": self.imbalance_bps.to_string(),
            "privacy_set_size": self.privacy_set_size.to_string(),
            "fee_cap_units": self.fee_cap_units.to_string(),
            "opened_at_height": self.opened_at_height.to_string(),
            "sealed_at_height": self.sealed_at_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl SolvencyEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "venue_id": self.venue_id,
            "subject_commitment": self.subject_commitment,
            "severity": self.severity.as_str(),
            "record_root": self.record_root,
            "height": self.height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl InvariantCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "venue_id": self.venue_id,
            "severity": self.severity.as_str(),
            "message_commitment": self.message_commitment,
            "target_bps": self.target_bps.to_string(),
            "observed_bps": self.observed_bps.to_string(),
            "proof_root": self.proof_root,
            "height": self.height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "config_root": self.config_root, "venue_root": self.venue_root, "bucket_root": self.bucket_root, "position_root": self.position_root, "oracle_root": self.oracle_root, "breaker_root": self.breaker_root, "liquidation_root": self.liquidation_root, "netting_root": self.netting_root, "event_root": self.event_root, "invariant_root": self.invariant_root, "state_root": self.state_root })
    }
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({ "venues": self.venues.to_string(), "buckets": self.buckets.to_string(), "positions": self.positions.to_string(), "oracle_attestations": self.oracle_attestations.to_string(), "breakers": self.breakers.to_string(), "liquidations": self.liquidations.to_string(), "netting_windows": self.netting_windows.to_string(), "events": self.events.to_string(), "invariant_checks": self.invariant_checks.to_string(), "halted_venues": self.halted_venues.to_string(), "tripped_breakers": self.tripped_breakers.to_string(), "open_liquidations": self.open_liquidations.to_string() })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub venues: BTreeMap<String, SolvencyVenue>,
    pub buckets: BTreeMap<String, RiskBucket>,
    pub positions: BTreeMap<String, ConfidentialPositionHealth>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub breakers: BTreeMap<String, CircuitBreaker>,
    pub liquidations: BTreeMap<String, LiquidationCircuit>,
    pub netting_windows: BTreeMap<String, SwapNettingWindow>,
    pub events: BTreeMap<String, SolvencyEvent>,
    pub invariant_checks: BTreeMap<String, InvariantCheck>,
}

impl State {
    pub fn new(height: u64, config: Config) -> PrivateDefiSolvencyGuardResult<Self> {
        config.validate()?;
        Ok(Self {
            height,
            config,
            venues: BTreeMap::new(),
            buckets: BTreeMap::new(),
            positions: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            breakers: BTreeMap::new(),
            liquidations: BTreeMap::new(),
            netting_windows: BTreeMap::new(),
            events: BTreeMap::new(),
            invariant_checks: BTreeMap::new(),
        })
    }
    pub fn devnet() -> PrivateDefiSolvencyGuardResult<State> {
        let mut state = Self::new(PRIVATE_DEFI_SOLVENCY_GUARD_DEVNET_HEIGHT, Config::devnet())?;
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }
    fn seed_devnet_records(&mut self) -> PrivateDefiSolvencyGuardResult<()> {
        let venues = [
            (
                "lending-alpha",
                SolvencyVenueKind::LendingMarket,
                SolvencyGuardStatus::Active,
            ),
            (
                "stablecoin-dxusd",
                SolvencyVenueKind::StablecoinIssuer,
                SolvencyGuardStatus::Active,
            ),
            (
                "perps-core",
                SolvencyVenueKind::DerivativesClearinghouse,
                SolvencyGuardStatus::Watch,
            ),
            (
                "vault-yield",
                SolvencyVenueKind::TokenizedVault,
                SolvencyGuardStatus::Active,
            ),
            (
                "amm-confidential",
                SolvencyVenueKind::ConfidentialAmm,
                SolvencyGuardStatus::Guarded,
            ),
            (
                "cross-margin",
                SolvencyVenueKind::CrossMarginDesk,
                SolvencyGuardStatus::Watch,
            ),
            (
                "liquidation-backstop",
                SolvencyVenueKind::LiquidationCircuit,
                SolvencyGuardStatus::Active,
            ),
            (
                "credit-oracle",
                SolvencyVenueKind::CreditOracle,
                SolvencyGuardStatus::Active,
            ),
        ];
        for (index, (venue_id, kind, status)) in venues.iter().enumerate() {
            self.insert_venue(SolvencyVenue {
                venue_id: (*venue_id).to_string(),
                kind: *kind,
                status: *status,
                operator_commitment: guard_commitment("operator", venue_id),
                asset_root: guard_commitment("asset-root", venue_id),
                liability_root: guard_commitment("liability-root", venue_id),
                health_floor_bps: kind.default_health_floor_bps(),
                max_drawdown_bps: 700 + (index as u64 * 50),
                oracle_lane_id: format!("lane-{index}"),
                breaker_group_id: format!("breaker-group-{}", index % 3),
                opened_at_height: self.height.saturating_sub(80 + index as u64 * 7),
            })?;
        }

        let bucket_kinds = [
            RiskBucketKind::Prime,
            RiskBucketKind::Core,
            RiskBucketKind::Watch,
            RiskBucketKind::Stressed,
            RiskBucketKind::Distressed,
            RiskBucketKind::OracleReview,
            RiskBucketKind::LiquidationOnly,
            RiskBucketKind::GovernanceHold,
        ];
        let collateral_classes = [
            CollateralClass::Native,
            CollateralClass::WrappedMonero,
            CollateralClass::Stablecoin,
            CollateralClass::LiquidStaking,
            CollateralClass::TokenizedVaultShare,
            CollateralClass::DerivativesMargin,
            CollateralClass::CrossRollupReceipt,
            CollateralClass::InsuranceClaim,
        ];
        let debt_classes = [
            DebtClass::VariableBorrow,
            DebtClass::FixedBorrow,
            DebtClass::StablecoinMint,
            DebtClass::PerpFunding,
            DebtClass::OptionPremium,
            DebtClass::VaultLeverage,
            DebtClass::CreditLine,
            DebtClass::SettlementAdvance,
        ];
        let health_trends = [
            HealthTrend::Improving,
            HealthTrend::Stable,
            HealthTrend::Watch,
            HealthTrend::Deteriorating,
        ];
        for index in 0..16 {
            let bucket_id = format!("bucket-{index}");
            let kind = bucket_kinds[index % bucket_kinds.len()];
            self.insert_bucket(RiskBucket {
                bucket_id: bucket_id.clone(),
                kind,
                venue_id: venues[index % venues.len()].0.to_string(),
                privacy_set_size: self.config.min_privacy_set_size + index as u64 * 64,
                exposure_commitment: guard_commitment("bucket-exposure", &bucket_id),
                collateral_class: collateral_classes[index % collateral_classes.len()],
                debt_class: debt_classes[index % debt_classes.len()],
                max_ltv_bps: kind.max_ltv_bps(),
                utilization_bps: 3_200 + index as u64 * 210,
                health_trend: health_trends[index % health_trends.len()],
                rotated_at_height: self.height.saturating_sub(30 + index as u64),
            })?;
        }

        let proof_envelopes = [
            ProofEnvelopeKind::CollateralHealth,
            ProofEnvelopeKind::LiabilityBound,
            ProofEnvelopeKind::ReserveCoverage,
            ProofEnvelopeKind::CreditBucket,
            ProofEnvelopeKind::LiquidationFee,
            ProofEnvelopeKind::SwapNetting,
        ];
        for index in 0..24 {
            let position_id = format!("position-{index}");
            self.insert_position(ConfidentialPositionHealth {
                position_id: position_id.clone(),
                venue_id: venues[index % venues.len()].0.to_string(),
                bucket_id: format!("bucket-{}", index % 16),
                owner_nullifier: guard_commitment("owner-nullifier", &position_id),
                collateral_commitment: guard_commitment("collateral", &position_id),
                debt_commitment: guard_commitment("debt", &position_id),
                health_factor_bps: 10_800 + index as u64 * 137,
                liquidation_threshold_bps: 9_400 + (index as u64 % 5) * 100,
                credit_score_commitment: guard_commitment("credit-score", &position_id),
                last_checked_height: self.height.saturating_sub(index as u64 % 9),
                proof_envelope: proof_envelopes[index % proof_envelopes.len()],
            })?;
        }

        let oracle_kinds = [
            OracleLaneKind::PriceMedian,
            OracleLaneKind::CreditScore,
            OracleLaneKind::ReserveProof,
            OracleLaneKind::VaultSharePrice,
            OracleLaneKind::FundingRate,
            OracleLaneKind::VolatilitySurface,
            OracleLaneKind::LiquidityDepth,
            OracleLaneKind::CrossRollupHealth,
        ];
        let attestation_statuses = [
            AttestationStatus::Submitted,
            AttestationStatus::QuorumChecked,
            AttestationStatus::Accepted,
        ];
        for index in 0..12 {
            let attestation_id = format!("attestation-{index}");
            self.insert_oracle_attestation(OracleAttestation {
                attestation_id: attestation_id.clone(),
                lane_id: format!("lane-{}", index % 8),
                kind: oracle_kinds[index % oracle_kinds.len()],
                status: attestation_statuses[index % attestation_statuses.len()],
                committee_root: guard_commitment("committee", &format!("lane-{}", index % 8)),
                subject_commitment: guard_commitment("oracle-subject", &attestation_id),
                value_commitment: guard_commitment("oracle-value", &attestation_id),
                quorum_bps: 6_800 + index as u64 * 100,
                staleness_blocks: index as u64 % 12,
                submitted_at_height: self.height.saturating_sub(index as u64 + 1),
            })?;
        }

        let breaker_kinds = [
            CircuitBreakerKind::GlobalSolvency,
            CircuitBreakerKind::VenueLiquidity,
            CircuitBreakerKind::OracleStaleness,
            CircuitBreakerKind::CollateralShock,
            CircuitBreakerKind::StablecoinDepeg,
            CircuitBreakerKind::DerivativeMargin,
            CircuitBreakerKind::VaultDrawdown,
            CircuitBreakerKind::LiquidationCongestion,
            CircuitBreakerKind::CreditScoreDrift,
            CircuitBreakerKind::SwapNettingImbalance,
        ];
        let breaker_statuses = [
            BreakerStatus::Armed,
            BreakerStatus::Armed,
            BreakerStatus::Tripped,
            BreakerStatus::CoolingDown,
            BreakerStatus::Released,
        ];
        let severities = [
            InvariantSeverity::Info,
            InvariantSeverity::Watch,
            InvariantSeverity::Caution,
            InvariantSeverity::Critical,
        ];
        for index in 0..10 {
            let breaker_id = format!("breaker-{index}");
            self.insert_breaker(CircuitBreaker {
                breaker_id: breaker_id.clone(),
                group_id: format!("breaker-group-{}", index % 3),
                kind: breaker_kinds[index],
                status: breaker_statuses[index % breaker_statuses.len()],
                severity: severities[index % severities.len()],
                trip_reason_commitment: guard_commitment("breaker-reason", &breaker_id),
                threshold_bps: 500 + index as u64 * 80,
                observed_bps: 420 + index as u64 * 95,
                cooldown_blocks: 24 + index as u64,
                tripped_at_height: self.height.saturating_sub(index as u64 * 3 + 2),
            })?;
        }

        let liquidation_modes = [
            LiquidationMode::PrivateDutchAuction,
            LiquidationMode::SealedBatch,
            LiquidationMode::KeeperNetting,
            LiquidationMode::ProtocolBackstop,
            LiquidationMode::InsuranceFund,
        ];
        let fee_policies = [
            FeePolicyKind::FlatCap,
            FeePolicyKind::NotionalBps,
            FeePolicyKind::CongestionWeighted,
            FeePolicyKind::KeeperAuction,
            FeePolicyKind::ProtocolSubsidized,
        ];
        let guard_statuses = [
            SolvencyGuardStatus::Active,
            SolvencyGuardStatus::Watch,
            SolvencyGuardStatus::Guarded,
        ];
        for index in 0..10 {
            let liquidation_id = format!("liquidation-{index}");
            self.insert_liquidation(LiquidationCircuit {
                liquidation_id: liquidation_id.clone(),
                position_id: format!("position-{index}"),
                venue_id: venues[index % venues.len()].0.to_string(),
                mode: liquidation_modes[index % liquidation_modes.len()],
                fee_policy: fee_policies[index % fee_policies.len()],
                status: guard_statuses[index % guard_statuses.len()],
                seized_collateral_commitment: guard_commitment("seized", &liquidation_id),
                repaid_debt_commitment: guard_commitment("repaid", &liquidation_id),
                max_fee_bps: 250 + index as u64 * 20,
                keeper_privacy_set_size: self.config.min_privacy_set_size + index as u64 * 32,
                expires_at_height: self.height + self.config.liquidation_ttl_blocks + index as u64,
            })?;
        }

        let netting_statuses = [
            NettingWindowStatus::Open,
            NettingWindowStatus::Sealed,
            NettingWindowStatus::Matched,
            NettingWindowStatus::Settled,
        ];
        for index in 0..8 {
            let window_id = format!("netting-{index}");
            self.insert_netting_window(SwapNettingWindow {
                window_id: window_id.clone(),
                venue_id: venues[index % venues.len()].0.to_string(),
                status: netting_statuses[index % netting_statuses.len()],
                input_commitment_root: guard_commitment("netting-input", &window_id),
                output_commitment_root: guard_commitment("netting-output", &window_id),
                imbalance_bps: 100 + index as u64 * 90,
                privacy_set_size: self.config.min_privacy_set_size + index as u64 * 80,
                fee_cap_units: 2 + index as u64 % 4,
                opened_at_height: self.height.saturating_sub(20 + index as u64),
                sealed_at_height: self.height.saturating_sub(10 + index as u64),
            })?;
        }

        let event_kinds = [
            SolvencyEventKind::BorrowAdmitted,
            SolvencyEventKind::MintBounded,
            SolvencyEventKind::DerivativeRiskPosted,
            SolvencyEventKind::VaultLimitUpdated,
            SolvencyEventKind::LiquidationQueued,
            SolvencyEventKind::BreakerTripped,
            SolvencyEventKind::BreakerReleased,
            SolvencyEventKind::OracleAttested,
            SolvencyEventKind::NettingSettled,
            SolvencyEventKind::RiskBucketRotated,
        ];
        for index in 0..18 {
            let event_id = format!("event-{index}");
            self.insert_event(SolvencyEvent {
                event_id: event_id.clone(),
                kind: event_kinds[index % event_kinds.len()],
                venue_id: venues[index % venues.len()].0.to_string(),
                subject_commitment: guard_commitment("event-subject", &event_id),
                severity: severities[index % 3],
                record_root: guard_commitment("event-record", &event_id),
                height: self.height.saturating_sub(index as u64),
            })?;
        }

        for index in 0..14 {
            let check_id = format!("check-{index}");
            self.insert_invariant_check(InvariantCheck {
                check_id: check_id.clone(),
                venue_id: venues[index % venues.len()].0.to_string(),
                severity: severities[index % severities.len()],
                message_commitment: guard_commitment("invariant-message", &check_id),
                target_bps: 7_000 + index as u64 * 100,
                observed_bps: 6_600 + index as u64 * 120,
                proof_root: guard_commitment("invariant-proof", &check_id),
                height: self.height.saturating_sub(index as u64 % 11),
            })?;
        }
        Ok(())
    }

    pub fn insert_venue(&mut self, record: SolvencyVenue) -> PrivateDefiSolvencyGuardResult<()> {
        if self.venues.len() >= self.config.max_venues {
            return Err("solvency guard capacity exceeded for venues".to_string());
        }
        non_empty(&record.venue_id, "venue_id")?;
        self.venues.insert(record.venue_id.clone(), record);
        Ok(())
    }

    pub fn insert_bucket(&mut self, record: RiskBucket) -> PrivateDefiSolvencyGuardResult<()> {
        if self.buckets.len() >= self.config.max_buckets {
            return Err("solvency guard capacity exceeded for buckets".to_string());
        }
        non_empty(&record.bucket_id, "bucket_id")?;
        self.buckets.insert(record.bucket_id.clone(), record);
        Ok(())
    }

    pub fn insert_position(
        &mut self,
        record: ConfidentialPositionHealth,
    ) -> PrivateDefiSolvencyGuardResult<()> {
        if self.positions.len() >= self.config.max_positions {
            return Err("solvency guard capacity exceeded for positions".to_string());
        }
        non_empty(&record.position_id, "position_id")?;
        self.positions.insert(record.position_id.clone(), record);
        Ok(())
    }

    pub fn insert_oracle_attestation(
        &mut self,
        record: OracleAttestation,
    ) -> PrivateDefiSolvencyGuardResult<()> {
        if self.oracle_attestations.len() >= self.config.max_oracle_attestations {
            return Err("solvency guard capacity exceeded for oracle_attestations".to_string());
        }
        non_empty(&record.attestation_id, "attestation_id")?;
        self.oracle_attestations
            .insert(record.attestation_id.clone(), record);
        Ok(())
    }

    pub fn insert_breaker(&mut self, record: CircuitBreaker) -> PrivateDefiSolvencyGuardResult<()> {
        if self.breakers.len() >= self.config.max_breakers {
            return Err("solvency guard capacity exceeded for breakers".to_string());
        }
        non_empty(&record.breaker_id, "breaker_id")?;
        self.breakers.insert(record.breaker_id.clone(), record);
        Ok(())
    }

    pub fn insert_liquidation(
        &mut self,
        record: LiquidationCircuit,
    ) -> PrivateDefiSolvencyGuardResult<()> {
        if self.liquidations.len() >= self.config.max_liquidations {
            return Err("solvency guard capacity exceeded for liquidations".to_string());
        }
        non_empty(&record.liquidation_id, "liquidation_id")?;
        self.liquidations
            .insert(record.liquidation_id.clone(), record);
        Ok(())
    }

    pub fn insert_netting_window(
        &mut self,
        record: SwapNettingWindow,
    ) -> PrivateDefiSolvencyGuardResult<()> {
        if self.netting_windows.len() >= self.config.max_netting_windows {
            return Err("solvency guard capacity exceeded for netting_windows".to_string());
        }
        non_empty(&record.window_id, "window_id")?;
        self.netting_windows
            .insert(record.window_id.clone(), record);
        Ok(())
    }

    pub fn insert_event(&mut self, record: SolvencyEvent) -> PrivateDefiSolvencyGuardResult<()> {
        if self.events.len() >= self.config.max_events {
            return Err("solvency guard capacity exceeded for events".to_string());
        }
        non_empty(&record.event_id, "event_id")?;
        self.events.insert(record.event_id.clone(), record);
        Ok(())
    }

    pub fn insert_invariant_check(
        &mut self,
        record: InvariantCheck,
    ) -> PrivateDefiSolvencyGuardResult<()> {
        if self.invariant_checks.len() >= self.config.max_events {
            return Err("solvency guard capacity exceeded for invariant_checks".to_string());
        }
        non_empty(&record.check_id, "check_id")?;
        self.invariant_checks
            .insert(record.check_id.clone(), record);
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateDefiSolvencyGuardResult<()> {
        self.height = height;
        self.validate()
    }
    pub fn update_height(&mut self, height: u64) -> PrivateDefiSolvencyGuardResult<()> {
        self.set_height(height)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            venues: self.venues.len(),
            buckets: self.buckets.len(),
            positions: self.positions.len(),
            oracle_attestations: self.oracle_attestations.len(),
            breakers: self.breakers.len(),
            liquidations: self.liquidations.len(),
            netting_windows: self.netting_windows.len(),
            events: self.events.len(),
            invariant_checks: self.invariant_checks.len(),
            halted_venues: self
                .venues
                .values()
                .filter(|venue| {
                    matches!(
                        venue.status,
                        SolvencyGuardStatus::Halted | SolvencyGuardStatus::Quarantined
                    )
                })
                .count(),
            tripped_breakers: self
                .breakers
                .values()
                .filter(|breaker| breaker.status.blocks_new_risk())
                .count(),
            open_liquidations: self
                .liquidations
                .values()
                .filter(|liquidation| {
                    matches!(
                        liquidation.status,
                        SolvencyGuardStatus::Active
                            | SolvencyGuardStatus::Watch
                            | SolvencyGuardStatus::Guarded
                    )
                })
                .count(),
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let venue_root = root_for_values(
            "private-defi-solvency-guard:venues",
            self.venues
                .values()
                .map(SolvencyVenue::public_record)
                .collect(),
        );
        let bucket_root = root_for_values(
            "private-defi-solvency-guard:buckets",
            self.buckets
                .values()
                .map(RiskBucket::public_record)
                .collect(),
        );
        let position_root = root_for_values(
            "private-defi-solvency-guard:positions",
            self.positions
                .values()
                .map(ConfidentialPositionHealth::public_record)
                .collect(),
        );
        let oracle_root = root_for_values(
            "private-defi-solvency-guard:oracles",
            self.oracle_attestations
                .values()
                .map(OracleAttestation::public_record)
                .collect(),
        );
        let breaker_root = root_for_values(
            "private-defi-solvency-guard:breakers",
            self.breakers
                .values()
                .map(CircuitBreaker::public_record)
                .collect(),
        );
        let liquidation_root = root_for_values(
            "private-defi-solvency-guard:liquidations",
            self.liquidations
                .values()
                .map(LiquidationCircuit::public_record)
                .collect(),
        );
        let netting_root = root_for_values(
            "private-defi-solvency-guard:netting",
            self.netting_windows
                .values()
                .map(SwapNettingWindow::public_record)
                .collect(),
        );
        let event_root = root_for_values(
            "private-defi-solvency-guard:events",
            self.events
                .values()
                .map(SolvencyEvent::public_record)
                .collect(),
        );
        let invariant_root = root_for_values(
            "private-defi-solvency-guard:invariants",
            self.invariant_checks
                .values()
                .map(InvariantCheck::public_record)
                .collect(),
        );
        let state_payload = json!({ "height": self.height.to_string(), "protocol_version": PRIVATE_DEFI_SOLVENCY_GUARD_PROTOCOL_VERSION, "config_root": config_root, "venue_root": venue_root, "bucket_root": bucket_root, "position_root": position_root, "oracle_root": oracle_root, "breaker_root": breaker_root, "liquidation_root": liquidation_root, "netting_root": netting_root, "event_root": event_root, "invariant_root": invariant_root });
        let state_root = root_from_record(&state_payload);
        Roots {
            config_root,
            venue_root,
            bucket_root,
            position_root,
            oracle_root,
            breaker_root,
            liquidation_root,
            netting_root,
            event_root,
            invariant_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({ "protocol_version": PRIVATE_DEFI_SOLVENCY_GUARD_PROTOCOL_VERSION, "hash_suite": PRIVATE_DEFI_SOLVENCY_GUARD_HASH_SUITE, "proof_system": PRIVATE_DEFI_SOLVENCY_GUARD_PROOF_SYSTEM, "credit_score_oracle": PRIVATE_DEFI_SOLVENCY_GUARD_CREDIT_SCORE_ORACLE, "liquidation_circuit": PRIVATE_DEFI_SOLVENCY_GUARD_LIQUIDATION_CIRCUIT, "swap_netting_system": PRIVATE_DEFI_SOLVENCY_GUARD_SWAP_NETTING_SYSTEM, "signature_scheme": PRIVATE_DEFI_SOLVENCY_GUARD_SIGNATURE_SCHEME, "backup_signature_scheme": PRIVATE_DEFI_SOLVENCY_GUARD_BACKUP_SIGNATURE_SCHEME, "kem_scheme": PRIVATE_DEFI_SOLVENCY_GUARD_KEM_SCHEME, "height": self.height.to_string(), "config": self.config.public_record(), "roots": roots.public_record(), "counters": counters.public_record() })
    }

    pub fn validate(&self) -> PrivateDefiSolvencyGuardResult<()> {
        self.config.validate()?;
        if self.venues.len() > self.config.max_venues
            || self.buckets.len() > self.config.max_buckets
            || self.positions.len() > self.config.max_positions
            || self.oracle_attestations.len() > self.config.max_oracle_attestations
            || self.breakers.len() > self.config.max_breakers
            || self.liquidations.len() > self.config.max_liquidations
            || self.netting_windows.len() > self.config.max_netting_windows
            || self.events.len() > self.config.max_events
        {
            return Err("solvency guard state exceeds configured capacities".to_string());
        }
        let venue_ids = self.venues.keys().cloned().collect::<BTreeSet<_>>();
        for bucket in self.buckets.values() {
            if !venue_ids.contains(&bucket.venue_id) {
                return Err(format!(
                    "bucket {} references unknown venue",
                    bucket.bucket_id
                ));
            }
            if bucket.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!("bucket {} privacy set too small", bucket.bucket_id));
            }
            bounded_bps(bucket.max_ltv_bps, "bucket max ltv")?;
            bounded_bps(bucket.utilization_bps, "bucket utilization")?;
        }
        let bucket_ids = self.buckets.keys().cloned().collect::<BTreeSet<_>>();
        for position in self.positions.values() {
            if !venue_ids.contains(&position.venue_id) {
                return Err(format!(
                    "position {} references unknown venue",
                    position.position_id
                ));
            }
            if !bucket_ids.contains(&position.bucket_id) {
                return Err(format!(
                    "position {} references unknown bucket",
                    position.position_id
                ));
            }
            bounded_bps(position.health_factor_bps, "position health factor")?;
            bounded_bps(
                position.liquidation_threshold_bps,
                "position liquidation threshold",
            )?;
            if position.health_factor_bps + self.config.max_health_drift_bps
                < position.liquidation_threshold_bps
            {
                return Err(format!(
                    "position {} violates health drift guard",
                    position.position_id
                ));
            }
        }
        for attestation in self.oracle_attestations.values() {
            bounded_bps(attestation.quorum_bps, "oracle quorum")?;
            if attestation.quorum_bps < self.config.min_oracle_quorum_bps {
                return Err(format!(
                    "oracle attestation {} lacks quorum",
                    attestation.attestation_id
                ));
            }
            if attestation.staleness_blocks > self.config.oracle_ttl_blocks {
                return Err(format!(
                    "oracle attestation {} is stale",
                    attestation.attestation_id
                ));
            }
        }
        for breaker in self.breakers.values() {
            bounded_bps(breaker.threshold_bps, "breaker threshold")?;
            bounded_bps(breaker.observed_bps, "breaker observed")?;
            if matches!(breaker.status, BreakerStatus::Tripped)
                && breaker.observed_bps < breaker.threshold_bps
            {
                return Err(format!(
                    "breaker {} tripped below threshold",
                    breaker.breaker_id
                ));
            }
        }
        let position_ids = self.positions.keys().cloned().collect::<BTreeSet<_>>();
        for liquidation in self.liquidations.values() {
            if !position_ids.contains(&liquidation.position_id) {
                return Err(format!(
                    "liquidation {} references unknown position",
                    liquidation.liquidation_id
                ));
            }
            if !venue_ids.contains(&liquidation.venue_id) {
                return Err(format!(
                    "liquidation {} references unknown venue",
                    liquidation.liquidation_id
                ));
            }
            bounded_bps(liquidation.max_fee_bps, "liquidation max fee")?;
            if liquidation.max_fee_bps > self.config.liquidation_fee_cap_bps {
                return Err(format!(
                    "liquidation {} exceeds fee cap",
                    liquidation.liquidation_id
                ));
            }
            if liquidation.keeper_privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "liquidation {} keeper privacy set too small",
                    liquidation.liquidation_id
                ));
            }
        }
        for window in self.netting_windows.values() {
            if !venue_ids.contains(&window.venue_id) {
                return Err(format!(
                    "netting window {} references unknown venue",
                    window.window_id
                ));
            }
            bounded_bps(window.imbalance_bps, "netting imbalance")?;
            if window.imbalance_bps > self.config.max_netting_imbalance_bps {
                return Err(format!(
                    "netting window {} imbalance exceeds cap",
                    window.window_id
                ));
            }
            if window.fee_cap_units > self.config.max_fee_units {
                return Err(format!(
                    "netting window {} fee cap exceeds config",
                    window.window_id
                ));
            }
            if window.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "netting window {} privacy set too small",
                    window.window_id
                ));
            }
        }
        for event in self.events.values() {
            if !venue_ids.contains(&event.venue_id) {
                return Err(format!("event {} references unknown venue", event.event_id));
            }
        }
        for check in self.invariant_checks.values() {
            if !venue_ids.contains(&check.venue_id) {
                return Err(format!(
                    "invariant check {} references unknown venue",
                    check.check_id
                ));
            }
            bounded_bps(check.target_bps, "invariant target")?;
            bounded_bps(check.observed_bps, "invariant observed")?;
        }
        Ok(())
    }
}

pub fn root_from_record(record: &serde_json::Value) -> String {
    domain_hash(
        "private-defi-solvency-guard:record-root",
        &[HashPart::Json(record)],
        32,
    )
}
pub fn devnet() -> PrivateDefiSolvencyGuardResult<State> {
    State::devnet()
}

pub fn solvency_pressure_bps(
    collateral_bps: u64,
    liability_bps: u64,
    buffer_bps: u64,
) -> PrivateDefiSolvencyGuardResult<u64> {
    bounded_bps(collateral_bps, "collateral coverage")?;
    bounded_bps(liability_bps, "liability coverage")?;
    bounded_bps(buffer_bps, "solvency buffer")?;
    if collateral_bps >= liability_bps.saturating_add(buffer_bps) {
        return Ok(0);
    }
    Ok(liability_bps
        .saturating_add(buffer_bps)
        .saturating_sub(collateral_bps))
}

pub fn liquidation_fee_within_cap(
    proposed_fee_bps: u64,
    config: &Config,
) -> PrivateDefiSolvencyGuardResult<bool> {
    bounded_bps(proposed_fee_bps, "proposed liquidation fee")?;
    config.validate()?;
    Ok(proposed_fee_bps <= config.liquidation_fee_cap_bps)
}

pub fn privacy_set_margin(
    observed_privacy_set_size: u64,
    config: &Config,
) -> PrivateDefiSolvencyGuardResult<u64> {
    config.validate()?;
    if observed_privacy_set_size < config.min_privacy_set_size {
        return Err("observed privacy set is below configured minimum".to_string());
    }
    Ok(observed_privacy_set_size.saturating_sub(config.min_privacy_set_size))
}

pub fn risk_bucket_admission_record(bucket: RiskBucketKind, config: &Config) -> Value {
    json!({
        "bucket": bucket.as_str(),
        "allows_new_debt": bucket.allows_new_debt(),
        "max_ltv_bps": bucket.max_ltv_bps().to_string(),
        "configured_bucket_exposure_cap_bps": config.max_bucket_exposure_bps.to_string(),
        "configured_solvent_buffer_bps": config.solvency_buffer_bps.to_string(),
    })
}
