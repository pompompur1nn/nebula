use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedProverFailureInsurancePerpsAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_PERPS_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-prover-failure-insurance-perps-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_PERPS_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AMM_AUTHORIZATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-prover-failure-perps-amm-auth-v1";
pub const SEALED_POOL_SUITE: &str =
    "sealed-confidential-prover-failure-insurance-perps-amm-pool-root-v1";
pub const POSITION_NOTE_SUITE: &str =
    "sealed-confidential-prover-failure-insurance-perps-amm-position-note-root-v1";
pub const FUNDING_CURVE_SUITE: &str =
    "confidential-prover-failure-insurance-perps-amm-funding-curve-root-v1";
pub const FAILURE_OBSERVATION_SUITE: &str =
    "pq-confidential-prover-failure-insurance-perps-amm-observation-root-v1";
pub const AMM_LIQUIDITY_ROOT_SUITE: &str =
    "privacy-preserving-prover-failure-insurance-perps-amm-liquidity-root-v1";
pub const MARGIN_ROOT_SUITE: &str =
    "privacy-preserving-prover-failure-insurance-perps-amm-margin-root-v1";
pub const CLAIM_COUPON_ROOT_SUITE: &str =
    "pq-signed-prover-failure-insurance-perps-amm-claim-coupon-root-v1";
pub const LOW_FEE_SETTLEMENT_SUITE: &str =
    "low-fee-confidential-prover-failure-insurance-perps-amm-settlement-root-v1";
pub const NULLIFIER_ROOT_SUITE: &str =
    "anti-replay-prover-failure-insurance-perps-amm-nullifier-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-prover-failure-insurance-perps-amm-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-perps-amm-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-perps-amm-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-prover-failure-insurance-perps-amm-devnet";
pub const DEVNET_RUNTIME_ID: &str = "private-l2-pq-prover-failure-insurance-perps-amm-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_612_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 5_336_000;
pub const DEVNET_EPOCH: u64 = 24_192;
pub const DEVNET_FAILURE_INDEX_ID: &str = "monero-private-l2-prover-failure-index-devnet";
pub const DEVNET_INSURANCE_TOKEN_ID: &str = "tpfipamm-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_MARGIN_ASSET_ID: &str = "pxmr-margin-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_AMM_FEE_BPS: u64 = 4;
pub const DEFAULT_LOW_FEE_SETTLEMENT_BPS: u64 = 1;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 1_800;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_OBSERVER_QUORUM: u16 = 5;
pub const DEFAULT_FUNDING_QUORUM: u16 = 4;
pub const DEFAULT_SETTLEMENT_QUORUM: u16 = 3;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_750;
pub const DEFAULT_MIN_MARGIN_COVERAGE_BPS: u64 = 1_300;
pub const DEFAULT_MAX_POOL_UTILIZATION_BPS: u64 = 8_400;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_600;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 500;
pub const DEFAULT_MIN_FAILURE_BLOCKS: u64 = 8;
pub const DEFAULT_CATASTROPHIC_FAILURE_BLOCKS: u64 = 2_880;
pub const DEFAULT_FUNDING_INTERVAL_BLOCKS: u64 = 16;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_POSITION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 8_192;
pub const DEFAULT_MAX_POOLS: usize = 262_144;
pub const DEFAULT_MAX_POSITIONS: usize = 1_048_576;
pub const DEFAULT_MAX_FUNDING_CURVES: usize = 262_144;
pub const DEFAULT_MAX_OBSERVATIONS: usize = 524_288;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 262_144;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverFailureRiskKind {
    Timeout,
    InvalidProof,
    WitnessUnavailable,
    RecursiveProofStall,
    AggregatorOutage,
    CatastrophicFailure,
}

impl ProverFailureRiskKind {
    pub fn weight_bps(self) -> u64 {
        match self {
            Self::Timeout => 900,
            Self::InvalidProof => 1_500,
            Self::WitnessUnavailable => 1_250,
            Self::RecursiveProofStall => 1_800,
            Self::AggregatorOutage => 2_100,
            Self::CatastrophicFailure => 3_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongFailureProtection,
    ShortFailureProtection,
    LpBackstop,
    FundingMaker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Sealed,
    Active,
    FundingOnly,
    ReduceOnly,
    ClaimsOnly,
    Halted,
    Settled,
    Retired,
}

impl PoolStatus {
    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Active | Self::FundingOnly | Self::ReduceOnly)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::ClaimsOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    Open,
    FundingAccruing,
    FailureObserved,
    Claimable,
    Settling,
    Settled,
    Liquidated,
    Expired,
    Quarantined,
}

impl PositionStatus {
    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::FundingAccruing
                | Self::FailureObserved
                | Self::Claimable
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Submitted,
    PrivacyChecked,
    PqAttested,
    QuorumReached,
    Actionable,
    UsedInSettlement,
    Dismissed,
    Expired,
    Quarantined,
}

impl ObservationStatus {
    pub fn actionable(self) -> bool {
        matches!(
            self,
            Self::PqAttested | Self::QuorumReached | Self::Actionable | Self::UsedInSettlement
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingCurveStatus {
    Proposed,
    PqQuorumSigned,
    Active,
    Frozen,
    Superseded,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Collecting,
    Proving,
    Posted,
    Settled,
    Rejected,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub runtime_id: String,
    pub failure_index_id: String,
    pub insurance_token_id: String,
    pub collateral_asset_id: String,
    pub margin_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_amm_authorization_suite: String,
    pub replay_domain: String,
    pub protocol_fee_bps: u64,
    pub amm_fee_bps: u64,
    pub low_fee_settlement_bps: u64,
    pub maker_rebate_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub min_margin_coverage_bps: u64,
    pub max_pool_utilization_bps: u64,
    pub max_payout_bps: u64,
    pub max_funding_rate_bps: i64,
    pub min_failure_blocks: u64,
    pub catastrophic_failure_blocks: u64,
    pub funding_interval_blocks: u64,
    pub settlement_window_blocks: u64,
    pub position_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub observer_quorum: u16,
    pub funding_quorum: u16,
    pub settlement_quorum: u16,
    pub low_fee_batch_limit: usize,
    pub max_pools: usize,
    pub max_positions: usize,
    pub max_funding_curves: usize,
    pub max_observations: usize,
    pub max_settlements: usize,
    pub max_nullifiers: usize,
    pub require_roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            failure_index_id: DEVNET_FAILURE_INDEX_ID.to_string(),
            insurance_token_id: DEVNET_INSURANCE_TOKEN_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            margin_asset_id: DEVNET_MARGIN_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_amm_authorization_suite: PQ_AMM_AUTHORIZATION_SUITE.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            amm_fee_bps: DEFAULT_AMM_FEE_BPS,
            low_fee_settlement_bps: DEFAULT_LOW_FEE_SETTLEMENT_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            min_margin_coverage_bps: DEFAULT_MIN_MARGIN_COVERAGE_BPS,
            max_pool_utilization_bps: DEFAULT_MAX_POOL_UTILIZATION_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            min_failure_blocks: DEFAULT_MIN_FAILURE_BLOCKS,
            catastrophic_failure_blocks: DEFAULT_CATASTROPHIC_FAILURE_BLOCKS,
            funding_interval_blocks: DEFAULT_FUNDING_INTERVAL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            position_ttl_blocks: DEFAULT_POSITION_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observer_quorum: DEFAULT_OBSERVER_QUORUM,
            funding_quorum: DEFAULT_FUNDING_QUORUM,
            settlement_quorum: DEFAULT_SETTLEMENT_QUORUM,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_pools: DEFAULT_MAX_POOLS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_funding_curves: DEFAULT_MAX_FUNDING_CURVES,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            require_roots_only_public_records: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        require(self.protocol_version == PROTOCOL_VERSION, "bad protocol")?;
        require(self.schema_version == SCHEMA_VERSION, "bad schema")?;
        require_nonempty("runtime_id", &self.runtime_id)?;
        require_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("amm_fee_bps", self.amm_fee_bps)?;
        require_bps("low_fee_settlement_bps", self.low_fee_settlement_bps)?;
        require_bps("maker_rebate_bps", self.maker_rebate_bps)?;
        require_coverage_bps(
            "min_collateral_coverage_bps",
            self.min_collateral_coverage_bps,
        )?;
        require_coverage_bps("min_margin_coverage_bps", self.min_margin_coverage_bps)?;
        require_bps("max_pool_utilization_bps", self.max_pool_utilization_bps)?;
        require_bps("max_payout_bps", self.max_payout_bps)?;
        require(
            self.min_failure_blocks < self.catastrophic_failure_blocks,
            "failure thresholds are invalid",
        )?;
        require(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "privacy set bounds are invalid",
        )?;
        require(
            self.min_pq_security_bits >= 192,
            "pq security below policy floor",
        )
    }

    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "config",
            &self.runtime_id,
            &payload_root("config", &json!(self)),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub active_pools: u64,
    pub positions: u64,
    pub open_positions: u64,
    pub funding_curves: u64,
    pub active_funding_curves: u64,
    pub observations: u64,
    pub actionable_observations: u64,
    pub settlements: u64,
    pub settled_batches: u64,
    pub liquidity_roots: u64,
    pub margin_roots: u64,
    pub consumed_nullifiers: u64,
    pub public_records: u64,
    pub total_notional_units: u128,
    pub total_collateral_units: u128,
    pub total_margin_units: u128,
    pub total_funding_units: i128,
    pub total_low_fee_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "counters",
            "runtime-counters",
            &payload_root("counters", &json!(self)),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pools_root: String,
    pub positions_root: String,
    pub funding_curves_root: String,
    pub observations_root: String,
    pub settlements_root: String,
    pub liquidity_root: String,
    pub margin_root: String,
    pub nullifiers_root: String,
    pub public_records_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "pools_root": self.pools_root,
            "positions_root": self.positions_root,
            "funding_curves_root": self.funding_curves_root,
            "observations_root": self.observations_root,
            "settlements_root": self.settlements_root,
            "liquidity_root": self.liquidity_root,
            "margin_root": self.margin_root,
            "nullifiers_root": self.nullifiers_root,
            "public_records_root": self.public_records_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PoolInput {
    pub pool_id: String,
    pub risk_kind: ProverFailureRiskKind,
    pub notional_cap_units: u128,
    pub collateral_root: String,
    pub liquidity_root: String,
    pub funding_curve_id: String,
    pub failure_floor_blocks: u64,
    pub failure_cap_blocks: u64,
    pub leverage_bps: u64,
    pub utilization_bps: u64,
    pub sealed_terms_root: String,
    pub token_commitment_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedAmmPool {
    pub pool_id: String,
    pub risk_kind: ProverFailureRiskKind,
    pub status: PoolStatus,
    pub notional_cap_units: u128,
    pub collateral_root: String,
    pub liquidity_root: String,
    pub funding_curve_id: String,
    pub failure_floor_blocks: u64,
    pub failure_cap_blocks: u64,
    pub leverage_bps: u64,
    pub utilization_bps: u64,
    pub sealed_terms_root: String,
    pub token_commitment_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_l2_height: u64,
}

impl SealedAmmPool {
    pub fn public_record(&self) -> Value {
        roots_safe_record("pool", &self.pool_id, &payload_root("pool", &json!(self)))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PositionInput {
    pub position_id: String,
    pub pool_id: String,
    pub side: PositionSide,
    pub owner_commitment: String,
    pub note_commitment: String,
    pub collateral_commitment: String,
    pub margin_commitment: String,
    pub entry_funding_curve_id: String,
    pub notional_units: u128,
    pub collateral_units: u128,
    pub margin_units: u128,
    pub max_failure_blocks: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PositionNote {
    pub position_id: String,
    pub pool_id: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub owner_commitment: String,
    pub note_commitment: String,
    pub collateral_commitment: String,
    pub margin_commitment: String,
    pub entry_funding_curve_id: String,
    pub notional_units: u128,
    pub collateral_units: u128,
    pub margin_units: u128,
    pub max_failure_blocks: u64,
    pub entry_l2_height: u64,
    pub expiry_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl PositionNote {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "position",
            &self.position_id,
            &payload_root("position", &json!(self)),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FundingCurveInput {
    pub funding_curve_id: String,
    pub pool_id: String,
    pub private_curve_root: String,
    pub utilization_root: String,
    pub failure_surface_root: String,
    pub base_rate_bps: i64,
    pub slope_bps: i64,
    pub clamp_bps: i64,
    pub quorum_weight: u16,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FundingCurve {
    pub funding_curve_id: String,
    pub pool_id: String,
    pub status: FundingCurveStatus,
    pub private_curve_root: String,
    pub utilization_root: String,
    pub failure_surface_root: String,
    pub base_rate_bps: i64,
    pub slope_bps: i64,
    pub clamp_bps: i64,
    pub funding_interval_blocks: u64,
    pub quorum_weight: u16,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub effective_l2_height: u64,
}

impl FundingCurve {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "funding_curve",
            &self.funding_curve_id,
            &payload_root("funding_curve", &json!(self)),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservationInput {
    pub observation_id: String,
    pub pool_id: String,
    pub risk_kind: ProverFailureRiskKind,
    pub prover_set_root: String,
    pub circuit_root: String,
    pub failed_proof_root: String,
    pub fallback_proof_root: String,
    pub observed_failure_blocks: u64,
    pub oracle_attestation_root: String,
    pub observer_quorum_weight: u16,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProverFailureObservation {
    pub observation_id: String,
    pub pool_id: String,
    pub risk_kind: ProverFailureRiskKind,
    pub status: ObservationStatus,
    pub prover_set_root: String,
    pub circuit_root: String,
    pub failed_proof_root: String,
    pub fallback_proof_root: String,
    pub observed_failure_blocks: u64,
    pub oracle_attestation_root: String,
    pub observer_quorum_weight: u16,
    pub nullifier: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl ProverFailureObservation {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "observation",
            &self.observation_id,
            &payload_root("observation", &json!(self)),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementInput {
    pub settlement_id: String,
    pub pool_id: String,
    pub funding_curve_id: String,
    pub position_set_root: String,
    pub observation_root: String,
    pub debit_root: String,
    pub credit_root: String,
    pub fee_root: String,
    pub net_funding_units: i128,
    pub protocol_fee_units: u128,
    pub maker_rebate_units: u128,
    pub low_fee_units: u128,
    pub settled_positions: u64,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeAmmSettlement {
    pub settlement_id: String,
    pub pool_id: String,
    pub status: SettlementStatus,
    pub funding_curve_id: String,
    pub position_set_root: String,
    pub observation_root: String,
    pub debit_root: String,
    pub credit_root: String,
    pub fee_root: String,
    pub net_funding_units: i128,
    pub protocol_fee_units: u128,
    pub maker_rebate_units: u128,
    pub low_fee_units: u128,
    pub settled_positions: u64,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub posted_l2_height: u64,
}

impl LowFeeAmmSettlement {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "settlement",
            &self.settlement_id,
            &payload_root("settlement", &json!(self)),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub pools: BTreeMap<String, SealedAmmPool>,
    pub positions: BTreeMap<String, PositionNote>,
    pub funding_curves: BTreeMap<String, FundingCurve>,
    pub observations: BTreeMap<String, ProverFailureObservation>,
    pub settlements: BTreeMap<String, LowFeeAmmSettlement>,
    pub liquidity_roots: BTreeMap<String, String>,
    pub margin_roots: BTreeMap<String, String>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            pools: BTreeMap::new(),
            positions: BTreeMap::new(),
            funding_curves: BTreeMap::new(),
            observations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            liquidity_roots: BTreeMap::new(),
            margin_roots: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.seed_devnet();
        state.refresh();
        state
    }

    pub fn add_pool(&mut self, input: PoolInput) -> Result<SealedAmmPool> {
        self.config.validate()?;
        ensure_capacity("pool", self.pools.len(), self.config.max_pools)?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require_bps("leverage_bps", input.leverage_bps)?;
        require_bps("utilization_bps", input.utilization_bps)?;
        require(
            input.utilization_bps <= self.config.max_pool_utilization_bps,
            "pool utilization exceeds AMM risk limit",
        )?;
        require(
            input.failure_floor_blocks >= self.config.min_failure_blocks
                && input.failure_cap_blocks <= self.config.catastrophic_failure_blocks
                && input.failure_floor_blocks <= input.failure_cap_blocks,
            "failure block range is invalid",
        )?;
        let pool = SealedAmmPool {
            pool_id: input.pool_id,
            risk_kind: input.risk_kind,
            status: PoolStatus::Active,
            notional_cap_units: input.notional_cap_units,
            collateral_root: input.collateral_root,
            liquidity_root: input.liquidity_root,
            funding_curve_id: input.funding_curve_id,
            failure_floor_blocks: input.failure_floor_blocks,
            failure_cap_blocks: input.failure_cap_blocks,
            leverage_bps: input.leverage_bps,
            utilization_bps: input.utilization_bps,
            sealed_terms_root: input.sealed_terms_root,
            token_commitment_root: input.token_commitment_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            created_l2_height: self.l2_height,
        };
        insert_unique(&mut self.pools, pool.pool_id.clone(), pool.clone())?;
        self.publish_roots_only(format!("pool:{}", pool.pool_id), pool.public_record())?;
        self.refresh();
        Ok(pool)
    }

    pub fn add_position(&mut self, input: PositionInput) -> Result<PositionNote> {
        ensure_capacity("position", self.positions.len(), self.config.max_positions)?;
        let pool = self
            .pools
            .get(&input.pool_id)
            .ok_or_else(|| format!("missing pool {}", input.pool_id))?;
        require(
            pool.status.accepts_positions(),
            "pool does not accept positions",
        )?;
        require(input.notional_units > 0, "notional must be positive")?;
        require(input.collateral_units > 0, "collateral must be positive")?;
        require(input.margin_units > 0, "margin must be positive")?;
        require(
            coverage_bps(input.collateral_units, input.notional_units)?
                >= self.config.min_collateral_coverage_bps,
            "collateral coverage below policy floor",
        )?;
        require(
            coverage_bps(input.margin_units, input.notional_units)?
                >= self.config.min_margin_coverage_bps,
            "margin coverage below policy floor",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let position = PositionNote {
            position_id: input.position_id,
            pool_id: input.pool_id,
            side: input.side,
            status: PositionStatus::Open,
            owner_commitment: input.owner_commitment,
            note_commitment: input.note_commitment,
            collateral_commitment: input.collateral_commitment,
            margin_commitment: input.margin_commitment,
            entry_funding_curve_id: input.entry_funding_curve_id,
            notional_units: input.notional_units,
            collateral_units: input.collateral_units,
            margin_units: input.margin_units,
            max_failure_blocks: input.max_failure_blocks,
            entry_l2_height: self.l2_height,
            expiry_l2_height: self.l2_height + self.config.position_ttl_blocks,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        insert_unique(
            &mut self.positions,
            position.position_id.clone(),
            position.clone(),
        )?;
        self.refresh();
        Ok(position)
    }

    pub fn add_funding_curve(&mut self, input: FundingCurveInput) -> Result<FundingCurve> {
        ensure_capacity(
            "funding_curve",
            self.funding_curves.len(),
            self.config.max_funding_curves,
        )?;
        require(
            input.quorum_weight >= self.config.funding_quorum,
            "funding quorum not met",
        )?;
        require(
            input.clamp_bps >= 0 && input.clamp_bps <= self.config.max_funding_rate_bps,
            "funding clamp exceeds configured bound",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let curve = FundingCurve {
            funding_curve_id: input.funding_curve_id,
            pool_id: input.pool_id,
            status: FundingCurveStatus::Active,
            private_curve_root: input.private_curve_root,
            utilization_root: input.utilization_root,
            failure_surface_root: input.failure_surface_root,
            base_rate_bps: input.base_rate_bps,
            slope_bps: input.slope_bps,
            clamp_bps: input.clamp_bps,
            funding_interval_blocks: self.config.funding_interval_blocks,
            quorum_weight: input.quorum_weight,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            effective_l2_height: self.l2_height,
        };
        insert_unique(
            &mut self.funding_curves,
            curve.funding_curve_id.clone(),
            curve.clone(),
        )?;
        self.refresh();
        Ok(curve)
    }

    pub fn observe_failure(&mut self, input: ObservationInput) -> Result<ProverFailureObservation> {
        ensure_capacity(
            "observation",
            self.observations.len(),
            self.config.max_observations,
        )?;
        let pool = self
            .pools
            .get(&input.pool_id)
            .ok_or_else(|| format!("missing pool {}", input.pool_id))?;
        require(pool.status.accepts_claims(), "pool does not accept claims")?;
        require(
            input.observer_quorum_weight >= self.config.observer_quorum,
            "observer quorum not met",
        )?;
        require(
            input.observed_failure_blocks >= pool.failure_floor_blocks
                && input.observed_failure_blocks <= pool.failure_cap_blocks,
            "observed failure outside pool band",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.consume_nullifier(input.nullifier.clone())?;
        let observation = ProverFailureObservation {
            observation_id: input.observation_id,
            pool_id: input.pool_id,
            risk_kind: input.risk_kind,
            status: ObservationStatus::Actionable,
            prover_set_root: input.prover_set_root,
            circuit_root: input.circuit_root,
            failed_proof_root: input.failed_proof_root,
            fallback_proof_root: input.fallback_proof_root,
            observed_failure_blocks: input.observed_failure_blocks,
            oracle_attestation_root: input.oracle_attestation_root,
            observer_quorum_weight: input.observer_quorum_weight,
            nullifier: input.nullifier,
            l2_height: self.l2_height,
            monero_height: self.monero_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
        };
        insert_unique(
            &mut self.observations,
            observation.observation_id.clone(),
            observation.clone(),
        )?;
        self.refresh();
        Ok(observation)
    }

    pub fn add_low_fee_settlement(
        &mut self,
        input: SettlementInput,
    ) -> Result<LowFeeAmmSettlement> {
        ensure_capacity(
            "settlement",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        let pool = self
            .pools
            .get(&input.pool_id)
            .ok_or_else(|| format!("missing pool {}", input.pool_id))?;
        require(
            pool.status.accepts_funding(),
            "pool does not accept funding",
        )?;
        require(
            self.funding_curves.contains_key(&input.funding_curve_id),
            "missing funding curve",
        )?;
        require(
            input.settled_positions as usize <= self.config.low_fee_batch_limit,
            "low fee settlement batch too large",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let settlement = LowFeeAmmSettlement {
            settlement_id: input.settlement_id,
            pool_id: input.pool_id,
            status: SettlementStatus::Settled,
            funding_curve_id: input.funding_curve_id,
            position_set_root: input.position_set_root,
            observation_root: input.observation_root,
            debit_root: input.debit_root,
            credit_root: input.credit_root,
            fee_root: input.fee_root,
            net_funding_units: input.net_funding_units,
            protocol_fee_units: input.protocol_fee_units,
            maker_rebate_units: input.maker_rebate_units,
            low_fee_units: input.low_fee_units,
            settled_positions: input.settled_positions,
            pq_authorization_root: input.pq_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            posted_l2_height: self.l2_height,
        };
        insert_unique(
            &mut self.settlements,
            settlement.settlement_id.clone(),
            settlement.clone(),
        )?;
        self.refresh();
        Ok(settlement)
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "chain_id": self.config.chain_id,
            "runtime_id": self.config.runtime_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn counters(&self) -> Counters {
        Counters {
            pools: self.pools.len() as u64,
            active_pools: self
                .pools
                .values()
                .filter(|pool| pool.status.accepts_positions())
                .count() as u64,
            positions: self.positions.len() as u64,
            open_positions: self
                .positions
                .values()
                .filter(|position| position.status.open())
                .count() as u64,
            funding_curves: self.funding_curves.len() as u64,
            active_funding_curves: self
                .funding_curves
                .values()
                .filter(|curve| curve.status == FundingCurveStatus::Active)
                .count() as u64,
            observations: self.observations.len() as u64,
            actionable_observations: self
                .observations
                .values()
                .filter(|observation| observation.status.actionable())
                .count() as u64,
            settlements: self.settlements.len() as u64,
            settled_batches: self
                .settlements
                .values()
                .filter(|settlement| settlement.status == SettlementStatus::Settled)
                .count() as u64,
            liquidity_roots: self.liquidity_roots.len() as u64,
            margin_roots: self.margin_roots.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            public_records: self.public_records.len() as u64,
            total_notional_units: self
                .positions
                .values()
                .map(|position| position.notional_units)
                .sum(),
            total_collateral_units: self
                .positions
                .values()
                .map(|position| position.collateral_units)
                .sum(),
            total_margin_units: self
                .positions
                .values()
                .map(|position| position.margin_units)
                .sum(),
            total_funding_units: self
                .settlements
                .values()
                .map(|settlement| settlement.net_funding_units)
                .sum(),
            total_low_fee_units: self
                .settlements
                .values()
                .map(|settlement| settlement.low_fee_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: payload_root("config", &json!(self.config)),
            pools_root: map_public_root(
                SEALED_POOL_SUITE,
                &self.pools,
                SealedAmmPool::public_record,
            ),
            positions_root: map_public_root(
                POSITION_NOTE_SUITE,
                &self.positions,
                PositionNote::public_record,
            ),
            funding_curves_root: map_public_root(
                FUNDING_CURVE_SUITE,
                &self.funding_curves,
                FundingCurve::public_record,
            ),
            observations_root: map_public_root(
                FAILURE_OBSERVATION_SUITE,
                &self.observations,
                ProverFailureObservation::public_record,
            ),
            settlements_root: map_public_root(
                LOW_FEE_SETTLEMENT_SUITE,
                &self.settlements,
                LowFeeAmmSettlement::public_record,
            ),
            liquidity_root: map_root(AMM_LIQUIDITY_ROOT_SUITE, &self.liquidity_roots),
            margin_root: map_root(MARGIN_ROOT_SUITE, &self.margin_roots),
            nullifiers_root: set_root(NULLIFIER_ROOT_SUITE, &self.consumed_nullifiers),
            public_records_root: value_map_root(PUBLIC_RECORD_SUITE, &self.public_records),
            counters_root: payload_root("counters", &json!(counters)),
            state_root: String::new(),
        };
        roots.state_root = payload_root(
            STATE_ROOT_SUITE,
            &json!({
                "config_root": roots.config_root,
                "pools_root": roots.pools_root,
                "positions_root": roots.positions_root,
                "funding_curves_root": roots.funding_curves_root,
                "observations_root": roots.observations_root,
                "settlements_root": roots.settlements_root,
                "liquidity_root": roots.liquidity_root,
                "margin_root": roots.margin_root,
                "nullifiers_root": roots.nullifiers_root,
                "public_records_root": roots.public_records_root,
                "counters_root": roots.counters_root,
                "l2_height": self.l2_height,
                "monero_height": self.monero_height,
                "epoch": self.epoch,
            }),
        );
        roots
    }

    pub fn refresh(&mut self) {
        self.counters = self.counters();
        self.roots = self.roots();
    }

    fn publish_roots_only(&mut self, key: String, record: Value) -> Result<()> {
        require(
            record
                .get("roots_only")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "public record must be roots-only",
        )?;
        insert_unique(&mut self.public_records, key, record)
    }

    fn consume_nullifier(&mut self, nullifier: String) -> Result<()> {
        ensure_capacity(
            "nullifier",
            self.consumed_nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        if !self.consumed_nullifiers.insert(nullifier.clone()) {
            return Err(format!("duplicate nullifier {nullifier}"));
        }
        Ok(())
    }

    fn seed_devnet(&mut self) {
        let pool = self
            .add_pool(PoolInput {
                pool_id: "pf-perps-amm-senior-devnet".to_string(),
                risk_kind: ProverFailureRiskKind::RecursiveProofStall,
                notional_cap_units: 50_000_000_000,
                collateral_root: demo_root("collateral", "senior"),
                liquidity_root: demo_root("liquidity", "senior"),
                funding_curve_id: "curve-pf-recursive-stall-devnet".to_string(),
                failure_floor_blocks: 8,
                failure_cap_blocks: 2_880,
                leverage_bps: 2_000,
                utilization_bps: 3_200,
                sealed_terms_root: demo_root("terms", "senior"),
                token_commitment_root: demo_root("tokenized_pool", "senior"),
                privacy_set_size: self.config.target_privacy_set_size,
                pq_security_bits: self.config.min_pq_security_bits,
            })
            .expect("valid devnet pool");
        self.liquidity_roots
            .insert(pool.pool_id.clone(), demo_root("liquidity_book", "senior"));
        self.margin_roots
            .insert(pool.pool_id.clone(), demo_root("margin_book", "senior"));
        self.add_funding_curve(FundingCurveInput {
            funding_curve_id: "curve-pf-recursive-stall-devnet".to_string(),
            pool_id: pool.pool_id.clone(),
            private_curve_root: demo_root("curve", "recursive-stall"),
            utilization_root: demo_root("utilization", "recursive-stall"),
            failure_surface_root: demo_root("failure_surface", "recursive-stall"),
            base_rate_bps: 16,
            slope_bps: 260,
            clamp_bps: 300,
            quorum_weight: self.config.funding_quorum,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })
        .expect("valid devnet curve");
        self.add_position(PositionInput {
            position_id: "pos-pf-protection-devnet-0".to_string(),
            pool_id: pool.pool_id.clone(),
            side: PositionSide::LongFailureProtection,
            owner_commitment: demo_root("owner", "alice"),
            note_commitment: demo_root("note", "alice"),
            collateral_commitment: demo_root("collateral_commitment", "alice"),
            margin_commitment: demo_root("margin_commitment", "alice"),
            entry_funding_curve_id: "curve-pf-recursive-stall-devnet".to_string(),
            notional_units: 1_000_000_000,
            collateral_units: 1_250_000_000,
            margin_units: 150_000_000,
            max_failure_blocks: 2_880,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })
        .expect("valid devnet position");
        self.observe_failure(ObservationInput {
            observation_id: "obs-pf-recursive-stall-devnet-0".to_string(),
            pool_id: pool.pool_id.clone(),
            risk_kind: ProverFailureRiskKind::RecursiveProofStall,
            prover_set_root: demo_root("prover_set", "committee-a"),
            circuit_root: demo_root("circuit", "rollup-a"),
            failed_proof_root: demo_root("failed_proof", "batch-a"),
            fallback_proof_root: demo_root("fallback_proof", "batch-a"),
            observed_failure_blocks: 18,
            oracle_attestation_root: demo_root("oracle_attestation", "batch-a"),
            observer_quorum_weight: self.config.observer_quorum,
            nullifier: demo_root("nullifier", "obs-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })
        .expect("valid devnet observation");
        self.add_low_fee_settlement(SettlementInput {
            settlement_id: "settlement-pf-amm-devnet-0".to_string(),
            pool_id: pool.pool_id,
            funding_curve_id: "curve-pf-recursive-stall-devnet".to_string(),
            position_set_root: demo_root("position_set", "batch-0"),
            observation_root: demo_root("observation_set", "batch-0"),
            debit_root: demo_root("debits", "batch-0"),
            credit_root: demo_root("credits", "batch-0"),
            fee_root: demo_root("fees", "batch-0"),
            net_funding_units: -1_750_000,
            protocol_fee_units: 20_000,
            maker_rebate_units: 11_000,
            low_fee_units: 2_000,
            settled_positions: 1,
            pq_authorization_root: demo_root("pq_authorization", "settlement-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })
        .expect("valid devnet settlement");
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

fn roots_safe_record(kind: &str, id: &str, commitment_root: &str) -> Value {
    json!({
        "kind": kind,
        "id": id,
        "commitment_root": commitment_root,
        "roots_only": true,
        "protocol_version": PROTOCOL_VERSION,
    })
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        PAYLOAD_ROOT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(value),
        ],
        32,
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    domain_hash(
        &format!("{PAYLOAD_ROOT_SUITE}:devnet:{label}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(salt)],
        32,
    )
}

fn map_public_root<T, F>(label: &str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": f(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn map_root(label: &str, map: &BTreeMap<String, String>) -> String {
    let leaves = map
        .iter()
        .map(|(key, root)| {
            json!({
                "label": label,
                "key": key,
                "root": root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn value_map_root(label: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    if map.contains_key(&key) {
        Err(format!("duplicate key {key}"))
    } else {
        map.insert(key, value);
        Ok(())
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(value <= MAX_BPS, &format!("{label} exceeds MAX_BPS"))
}

fn require_coverage_bps(label: &str, value: u64) -> Result<()> {
    require(
        value <= MAX_BPS * 2,
        &format!("{label} exceeds coverage cap"),
    )
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "privacy set is below configured anonymity threshold",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "PQ authorization security bits below configured minimum",
    )
}

fn coverage_bps(numerator: u128, denominator: u128) -> Result<u64> {
    require(denominator > 0, "coverage denominator must be positive")?;
    Ok(((numerator.saturating_mul(MAX_BPS as u128)) / denominator) as u64)
}
