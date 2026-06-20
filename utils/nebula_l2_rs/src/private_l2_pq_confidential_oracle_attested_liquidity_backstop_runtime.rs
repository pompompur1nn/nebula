use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialOracleAttestedLiquidityBackstopRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-oracle-attested-liquidity-backstop-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ORACLE_ATTESTED_LIQUIDITY_BACKSTOP_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const BACKSTOP_SUITE: &str = "confidential-oracle-attested-liquidity-backstop-root-v1";
pub const REBATE_SUITE: &str = "oracle-attested-liquidity-backstop-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-liquidity-backstop-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_LIQUIDITY_ASSET_ID: &str = "xmr-liquidity-backstop-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BACKSTOP_WINDOW_SLOTS: u64 = 288;
pub const DEFAULT_ORACLE_STALENESS_SLOTS: u64 = 64;
pub const DEFAULT_MAX_BACKSTOP_FEE_BPS: u64 = 28;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_PROVIDER_BOND_MICRO_UNITS: u64 = 20_000_000;
pub const DEFAULT_MIN_POOL_LIQUIDITY_MICRO_UNITS: u64 = 5_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_STRESS_BPS: u64 = 4_000;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POOLS: usize = 524_288;
pub const MAX_PROVIDERS: usize = 524_288;
pub const MAX_REQUESTS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 7_424;
pub const DEVNET_SLOT: u64 = 113;
pub const DEVNET_L2_HEIGHT: u64 = 2_921_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopScope {
    MoneroExitQueue,
    PrivateAmmDepth,
    LendingLiquidation,
    PerpsInsuranceFund,
    StablecoinRedemption,
    TokenBridgeReserve,
    FeeSponsorReserve,
    EmergencyExitLane,
}

impl BackstopScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExitQueue => "monero_exit_queue",
            Self::PrivateAmmDepth => "private_amm_depth",
            Self::LendingLiquidation => "lending_liquidation",
            Self::PerpsInsuranceFund => "perps_insurance_fund",
            Self::StablecoinRedemption => "stablecoin_redemption",
            Self::TokenBridgeReserve => "token_bridge_reserve",
            Self::FeeSponsorReserve => "fee_sponsor_reserve",
            Self::EmergencyExitLane => "emergency_exit_lane",
        }
    }

    pub fn stress_weight(self) -> u64 {
        match self {
            Self::EmergencyExitLane => 9,
            Self::MoneroExitQueue => 8,
            Self::PerpsInsuranceFund => 7,
            Self::LendingLiquidation => 7,
            Self::TokenBridgeReserve => 6,
            Self::StablecoinRedemption => 5,
            Self::PrivateAmmDepth => 4,
            Self::FeeSponsorReserve => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Planned,
    Active,
    Throttled,
    Draining,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Candidate,
    Active,
    Exhausted,
    Throttled,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopRequestStatus {
    Submitted,
    Reserved,
    OracleAttested,
    Settled,
    RebateIssued,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqOracleSignatureVerified,
    StressWindowObserved,
    LiquidityCommitmentOpened,
    PriceImpactBounded,
    ReserveHintChecked,
    FeeCapObserved,
    PrivacyBoundaryObserved,
    SettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqOracleSignatureVerified => "pq_oracle_signature_verified",
            Self::StressWindowObserved => "stress_window_observed",
            Self::LiquidityCommitmentOpened => "liquidity_commitment_opened",
            Self::PriceImpactBounded => "price_impact_bounded",
            Self::ReserveHintChecked => "reserve_hint_checked",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::SettlementSafe => "settlement_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    Approve,
    ApproveWithRebate,
    PartialFill,
    Retry,
    Reject,
    Quarantine,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ApproveWithRebate => "approve_with_rebate",
            Self::PartialFill => "partial_fill",
            Self::Retry => "retry",
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Expire => "expire",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_oracle_suite: String,
    pub backstop_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub liquidity_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub backstop_window_slots: u64,
    pub oracle_staleness_slots: u64,
    pub max_backstop_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_provider_bond_micro_units: u64,
    pub min_pool_liquidity_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_stress_bps: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_oracle_suite: PQ_ORACLE_SUITE.to_string(),
            backstop_suite: BACKSTOP_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            liquidity_asset_id: DEFAULT_LIQUIDITY_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            backstop_window_slots: DEFAULT_BACKSTOP_WINDOW_SLOTS,
            oracle_staleness_slots: DEFAULT_ORACLE_STALENESS_SLOTS,
            max_backstop_fee_bps: DEFAULT_MAX_BACKSTOP_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_provider_bond_micro_units: DEFAULT_MIN_PROVIDER_BOND_MICRO_UNITS,
            min_pool_liquidity_micro_units: DEFAULT_MIN_POOL_LIQUIDITY_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_stress_bps: DEFAULT_MAX_STRESS_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_oracle_suite, "pq_oracle_suite")?;
        ensure_non_empty(&self.backstop_suite, "backstop_suite")?;
        ensure_non_empty(&self.rebate_suite, "rebate_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.liquidity_asset_id, "liquidity_asset_id")?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set must be >= minimum".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security bits below configured floor".to_string());
        }
        if self.backstop_window_slots == 0 || self.oracle_staleness_slots == 0 {
            return Err("backstop and oracle windows must be non-zero".to_string());
        }
        ensure_bps(self.max_backstop_fee_bps, "max_backstop_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        ensure_bps(self.max_stress_bps, "max_stress_bps")?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err("strong attestation quorum below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub providers: u64,
    pub requests: u64,
    pub attestations: u64,
    pub settlements: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_requests: u64,
    pub quarantined_requests: u64,
    pub expired_requests: u64,
    pub total_liquidity_micro_units: u64,
    pub reserved_liquidity_micro_units: u64,
    pub settled_liquidity_micro_units: u64,
    pub rebated_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pools": self.pools,
            "providers": self.providers,
            "requests": self.requests,
            "attestations": self.attestations,
            "settlements": self.settlements,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "settled_requests": self.settled_requests,
            "quarantined_requests": self.quarantined_requests,
            "expired_requests": self.expired_requests,
            "total_liquidity_micro_units": self.total_liquidity_micro_units,
            "reserved_liquidity_micro_units": self.reserved_liquidity_micro_units,
            "settled_liquidity_micro_units": self.settled_liquidity_micro_units,
            "rebated_micro_units": self.rebated_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub pool_root: String,
    pub provider_root: String,
    pub request_root: String,
    pub attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_root": self.pool_root,
            "provider_root": self.provider_root,
            "request_root": self.request_root,
            "attestation_root": self.attestation_root,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackstopPool {
    pub pool_id: String,
    pub scope: BackstopScope,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub liquidity_root: String,
    pub target_liquidity_micro_units: u64,
    pub fee_cap_bps: u64,
    pub stress_trigger_bps: u64,
    pub status: PoolStatus,
    pub opened_slot: u64,
    pub expires_slot: u64,
}

impl BackstopPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "scope": self.scope.as_str(),
            "public_hint_root": self.public_hint_root,
            "liquidity_root": self.liquidity_root,
            "target_liquidity_micro_units": self.target_liquidity_micro_units,
            "fee_cap_bps": self.fee_cap_bps,
            "stress_trigger_bps": self.stress_trigger_bps,
            "status": self.status,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityProvider {
    pub provider_id: String,
    pub provider_commitment: String,
    pub pq_verifying_key_root: String,
    pub liquidity_commitment_root: String,
    pub bond_micro_units: u64,
    pub available_micro_units: u64,
    pub privacy_set_size: u64,
    pub status: ProviderStatus,
    pub joined_slot: u64,
}

impl LiquidityProvider {
    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "pq_verifying_key_root": self.pq_verifying_key_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "bond_micro_units": self.bond_micro_units,
            "available_micro_units": self.available_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "joined_slot": self.joined_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackstopRequest {
    pub request_id: String,
    pub pool_id: String,
    pub provider_id: String,
    pub sealed_request_root: String,
    pub redacted_request_root: String,
    pub requested_micro_units: u64,
    pub max_fee_bps: u64,
    pub stress_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub status: BackstopRequestStatus,
}

impl BackstopRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "pool_id": self.pool_id,
            "provider_id": self.provider_id,
            "redacted_request_root": self.redacted_request_root,
            "requested_micro_units": self.requested_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "stress_bps": self.stress_bps,
            "rebate_bps": self.rebate_bps,
            "submitted_slot": self.submitted_slot,
            "expires_slot": self.expires_slot,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestation {
    pub attestation_id: String,
    pub request_id: String,
    pub kind: AttestationKind,
    pub oracle_committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub request_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_micro_units: u64,
    pub fee_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub request_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub pools: u64,
    pub providers: u64,
    pub open_requests: u64,
    pub settled_requests: u64,
    pub quarantined_requests: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub settled_liquidity_micro_units: u64,
    pub rebated_micro_units: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPoolRequest {
    pub scope: BackstopScope,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub liquidity_root: String,
    pub target_liquidity_micro_units: u64,
    pub fee_cap_bps: u64,
    pub stress_trigger_bps: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterProviderRequest {
    pub provider_commitment: String,
    pub pq_verifying_key_root: String,
    pub liquidity_commitment_root: String,
    pub bond_micro_units: u64,
    pub available_micro_units: u64,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitBackstopRequest {
    pub pool_id: String,
    pub provider_id: String,
    pub sealed_request_root: String,
    pub redacted_request_root: String,
    pub requested_micro_units: u64,
    pub max_fee_bps: u64,
    pub stress_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub request_id: String,
    pub kind: AttestationKind,
    pub oracle_committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleRequest {
    pub request_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub request_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub target_id: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, BackstopPool>,
    pub providers: BTreeMap<String, LiquidityProvider>,
    pub requests: BTreeMap<String, BackstopRequest>,
    pub attestations: BTreeMap<String, OracleAttestation>,
    pub settlements: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default oracle attested liquidity backstop config")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            providers: BTreeMap::new(),
            requests: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn open_pool(&mut self, request: OpenPoolRequest) -> Result<BackstopPool> {
        ensure_capacity(self.pools.len(), MAX_POOLS, "pools")?;
        ensure_non_empty(&request.sealed_pool_root, "sealed_pool_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_non_empty(&request.liquidity_root, "liquidity_root")?;
        ensure_bps(request.fee_cap_bps, "fee_cap_bps")?;
        ensure_bps(request.stress_trigger_bps, "stress_trigger_bps")?;
        if request.target_liquidity_micro_units < self.config.min_pool_liquidity_micro_units {
            return Err("pool liquidity below configured minimum".to_string());
        }
        if request.fee_cap_bps > self.config.max_backstop_fee_bps {
            return Err("pool fee cap exceeds configured maximum".to_string());
        }
        if request.stress_trigger_bps > self.config.max_stress_bps {
            return Err("pool stress trigger exceeds configured maximum".to_string());
        }
        let pool_id = stable_id(
            "pool",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.sealed_pool_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        let pool = BackstopPool {
            pool_id: pool_id.clone(),
            scope: request.scope,
            sealed_pool_root: request.sealed_pool_root,
            public_hint_root: request.public_hint_root,
            liquidity_root: request.liquidity_root,
            target_liquidity_micro_units: request.target_liquidity_micro_units,
            fee_cap_bps: request.fee_cap_bps,
            stress_trigger_bps: request.stress_trigger_bps,
            status: PoolStatus::Active,
            opened_slot: request.opened_slot,
            expires_slot: request.opened_slot + self.config.backstop_window_slots,
        };
        self.pools.insert(pool_id, pool.clone());
        self.refresh_roots();
        Ok(pool)
    }

    pub fn register_provider(
        &mut self,
        request: RegisterProviderRequest,
    ) -> Result<LiquidityProvider> {
        ensure_capacity(self.providers.len(), MAX_PROVIDERS, "providers")?;
        ensure_non_empty(&request.provider_commitment, "provider_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        ensure_non_empty(
            &request.liquidity_commitment_root,
            "liquidity_commitment_root",
        )?;
        if request.bond_micro_units < self.config.min_provider_bond_micro_units {
            return Err("provider bond below configured minimum".to_string());
        }
        if request.available_micro_units < self.config.min_pool_liquidity_micro_units {
            return Err("provider liquidity below configured minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("provider privacy set below configured minimum".to_string());
        }
        let provider_id = stable_id(
            "provider",
            &[
                HashPart::Str(&request.provider_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::Str(&request.liquidity_commitment_root),
            ],
        );
        let provider = LiquidityProvider {
            provider_id: provider_id.clone(),
            provider_commitment: request.provider_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            liquidity_commitment_root: request.liquidity_commitment_root,
            bond_micro_units: request.bond_micro_units,
            available_micro_units: request.available_micro_units,
            privacy_set_size: request.privacy_set_size,
            status: ProviderStatus::Active,
            joined_slot: request.joined_slot,
        };
        self.providers.insert(provider_id, provider.clone());
        self.refresh_roots();
        Ok(provider)
    }

    pub fn submit_backstop_request(
        &mut self,
        request: SubmitBackstopRequest,
    ) -> Result<BackstopRequest> {
        ensure_capacity(self.requests.len(), MAX_REQUESTS, "requests")?;
        ensure_non_empty(&request.sealed_request_root, "sealed_request_root")?;
        ensure_non_empty(&request.redacted_request_root, "redacted_request_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure_bps(request.stress_bps, "stress_bps")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("request rebate exceeds configured target".to_string());
        }
        let pool = self
            .pools
            .get(&request.pool_id)
            .ok_or_else(|| "pool not found".to_string())?
            .clone();
        if pool.status != PoolStatus::Active {
            return Err("pool is not active".to_string());
        }
        if request.max_fee_bps > pool.fee_cap_bps {
            return Err("request fee exceeds pool cap".to_string());
        }
        if request.stress_bps < pool.stress_trigger_bps {
            return Err("request stress is below pool trigger".to_string());
        }
        if request.requested_micro_units == 0
            || request.requested_micro_units > pool.target_liquidity_micro_units
        {
            return Err("request amount outside pool target".to_string());
        }
        let provider = self
            .providers
            .get_mut(&request.provider_id)
            .ok_or_else(|| "provider not found".to_string())?;
        if provider.status != ProviderStatus::Active {
            return Err("provider is not active".to_string());
        }
        if provider.available_micro_units < request.requested_micro_units {
            provider.status = ProviderStatus::Exhausted;
            return Err("provider liquidity below request amount".to_string());
        }
        provider.available_micro_units -= request.requested_micro_units;
        let request_id = stable_id(
            "request",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.provider_id),
                HashPart::Str(&request.redacted_request_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let record = BackstopRequest {
            request_id: request_id.clone(),
            pool_id: request.pool_id,
            provider_id: request.provider_id,
            sealed_request_root: request.sealed_request_root,
            redacted_request_root: request.redacted_request_root,
            requested_micro_units: request.requested_micro_units,
            max_fee_bps: request.max_fee_bps,
            stress_bps: request.stress_bps,
            rebate_bps: request.rebate_bps,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + self.config.backstop_window_slots,
            status: BackstopRequestStatus::Reserved,
        };
        self.counters.reserved_liquidity_micro_units = self
            .counters
            .reserved_liquidity_micro_units
            .saturating_add(record.requested_micro_units);
        self.requests.insert(request_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_attestation(
        &mut self,
        request: RecordAttestationRequest,
    ) -> Result<OracleAttestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.oracle_committee_root, "oracle_committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        self.ensure_request_exists(&request.request_id)?;
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.request_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.statement_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = OracleAttestation {
            attestation_id: attestation_id.clone(),
            request_id: request.request_id.clone(),
            kind: request.kind,
            oracle_committee_root: request.oracle_committee_root,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        if let Some(backstop) = self.requests.get_mut(&request.request_id) {
            if request.kind == AttestationKind::SettlementSafe {
                backstop.status = BackstopRequestStatus::OracleAttested;
            }
        }
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_request(&mut self, request: SettleRequest) -> Result<SettlementReceipt> {
        ensure_capacity(self.settlements.len(), MAX_SETTLEMENTS, "settlements")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let backstop = self
            .requests
            .get(&request.request_id)
            .ok_or_else(|| "request not found".to_string())?
            .clone();
        if request.settled_slot > backstop.expires_slot {
            return Err("settlement slot exceeds request expiry".to_string());
        }
        let settled_micro_units = match request.decision {
            SettlementDecision::Approve | SettlementDecision::ApproveWithRebate => {
                backstop.requested_micro_units
            }
            SettlementDecision::PartialFill => backstop.requested_micro_units / 2,
            _ => 0,
        };
        let fee_micro_units = settled_micro_units.saturating_mul(backstop.max_fee_bps) / MAX_BPS;
        let settlement_id = stable_id(
            "settlement",
            &[
                HashPart::Str(&request.request_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::U64(request.settled_slot),
            ],
        );
        let settlement = SettlementReceipt {
            settlement_id: settlement_id.clone(),
            request_id: request.request_id.clone(),
            settlement_root: request.settlement_root,
            decision: request.decision,
            settled_micro_units,
            fee_micro_units,
            settled_slot: request.settled_slot,
        };
        self.settlements.insert(settlement_id, settlement.clone());
        self.apply_settlement(&backstop, request.decision, settled_micro_units)?;
        self.refresh_roots();
        Ok(settlement)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.target_rebate_bps {
            return Err("rebate bps exceeds configured target".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("rebate expiry must be after issue slot".to_string());
        }
        let backstop = self
            .requests
            .get_mut(&request.request_id)
            .ok_or_else(|| "request not found".to_string())?;
        if backstop.status != BackstopRequestStatus::Settled {
            return Err("rebate requires a settled request".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.request_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let rebate = RebateReceipt {
            rebate_id: rebate_id.clone(),
            request_id: request.request_id.clone(),
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.rebates.insert(rebate_id, rebate.clone());
        self.counters.rebated_micro_units = self
            .counters
            .rebated_micro_units
            .saturating_add(request.amount_micro_units);
        backstop.status = BackstopRequestStatus::RebateIssued;
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction_budgets",
        )?;
        ensure_non_empty(&request.target_id, "target_id")?;
        if request.public_fields.is_empty() {
            return Err("redaction budget requires public fields".to_string());
        }
        if request.redacted_fields.is_empty() {
            return Err("redaction budget requires redacted fields".to_string());
        }
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("redaction budget exceeds configured public byte cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("redaction privacy set below configured minimum".to_string());
        }
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.target_id),
                HashPart::U64(request.max_public_bytes),
                HashPart::U64(request.actual_public_bytes),
            ],
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            target_id: request.target_id,
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
        };
        self.redaction_budgets.insert(budget_id, budget.clone());
        self.refresh_roots();
        Ok(budget)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator_summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let open_requests = self
            .requests
            .values()
            .filter(|request| {
                matches!(
                    request.status,
                    BackstopRequestStatus::Submitted
                        | BackstopRequestStatus::Reserved
                        | BackstopRequestStatus::OracleAttested
                )
            })
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[HashPart::U64(self.operator_summaries.len() as u64)],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            pools: self.pools.len() as u64,
            providers: self.providers.len() as u64,
            open_requests,
            settled_requests: self.counters.settled_requests,
            quarantined_requests: self.counters.quarantined_requests,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
            settled_liquidity_micro_units: self.counters.settled_liquidity_micro_units,
            rebated_micro_units: self.counters.rebated_micro_units,
            state_root: self.state_root(),
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.pools = self.pools.len() as u64;
        self.counters.providers = self.providers.len() as u64;
        self.counters.requests = self.requests.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.settlements = self.settlements.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.total_liquidity_micro_units = self
            .providers
            .values()
            .map(|provider| provider.available_micro_units)
            .sum();
        self.roots.pool_root = map_root("oracle-attested-liquidity-backstop:pools", &self.pools);
        self.roots.provider_root = map_root(
            "oracle-attested-liquidity-backstop:providers",
            &self.providers,
        );
        self.roots.request_root = map_root(
            "oracle-attested-liquidity-backstop:requests",
            &self.requests,
        );
        self.roots.attestation_root = map_root(
            "oracle-attested-liquidity-backstop:attestations",
            &self.attestations,
        );
        self.roots.settlement_root = map_root(
            "oracle-attested-liquidity-backstop:settlements",
            &self.settlements,
        );
        self.roots.rebate_root =
            map_root("oracle-attested-liquidity-backstop:rebates", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "oracle-attested-liquidity-backstop:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "oracle-attested-liquidity-backstop:operator-summaries",
            &self.operator_summaries,
        );
        self.roots.state_root = self.compute_state_root();
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_oracle_suite": self.config.pq_oracle_suite,
            "backstop_suite": self.config.backstop_suite,
            "rebate_suite": self.config.rebate_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "pools": self.pools,
            "providers": self.providers,
            "requests": self.requests,
            "attestations": self.attestations,
            "settlements": self.settlements,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
        })
    }

    fn compute_state_root(&self) -> String {
        let record = json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "pool_root": self.roots.pool_root,
            "provider_root": self.roots.provider_root,
            "request_root": self.roots.request_root,
            "attestation_root": self.roots.attestation_root,
            "settlement_root": self.roots.settlement_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "oracle-attested-liquidity-backstop:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn apply_settlement(
        &mut self,
        request: &BackstopRequest,
        decision: SettlementDecision,
        settled_micro_units: u64,
    ) -> Result<()> {
        match decision {
            SettlementDecision::Approve
            | SettlementDecision::ApproveWithRebate
            | SettlementDecision::PartialFill => {
                if request.status != BackstopRequestStatus::OracleAttested
                    && request.status != BackstopRequestStatus::Reserved
                {
                    return Err("request is not eligible for settlement".to_string());
                }
                if let Some(backstop) = self.requests.get_mut(&request.request_id) {
                    backstop.status = BackstopRequestStatus::Settled;
                }
                self.counters.settled_requests = self.counters.settled_requests.saturating_add(1);
                self.counters.settled_liquidity_micro_units = self
                    .counters
                    .settled_liquidity_micro_units
                    .saturating_add(settled_micro_units);
            }
            SettlementDecision::Retry => {
                if let Some(backstop) = self.requests.get_mut(&request.request_id) {
                    backstop.status = BackstopRequestStatus::Reserved;
                }
            }
            SettlementDecision::Reject | SettlementDecision::Quarantine => {
                if let Some(backstop) = self.requests.get_mut(&request.request_id) {
                    backstop.status = BackstopRequestStatus::Quarantined;
                }
                self.counters.quarantined_requests =
                    self.counters.quarantined_requests.saturating_add(1);
            }
            SettlementDecision::Expire => {
                if let Some(backstop) = self.requests.get_mut(&request.request_id) {
                    backstop.status = BackstopRequestStatus::Expired;
                }
                self.counters.expired_requests = self.counters.expired_requests.saturating_add(1);
            }
        }
        Ok(())
    }

    fn ensure_request_exists(&self, request_id: &str) -> Result<()> {
        ensure_non_empty(request_id, "request_id")?;
        if !self.requests.contains_key(request_id) {
            return Err(format!("request not found: {request_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool = state
        .open_pool(OpenPoolRequest {
            scope: BackstopScope::MoneroExitQueue,
            sealed_pool_root: sample_hash("sealed-pool", 1),
            public_hint_root: sample_hash("public-hint", 1),
            liquidity_root: sample_hash("liquidity", 1),
            target_liquidity_micro_units: 160_000_000,
            fee_cap_bps: 12,
            stress_trigger_bps: 1_600,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet backstop pool opened");
    let provider = state
        .register_provider(RegisterProviderRequest {
            provider_commitment: sample_hash("provider", 1),
            pq_verifying_key_root: sample_hash("provider-pq-key", 1),
            liquidity_commitment_root: sample_hash("provider-liquidity", 1),
            bond_micro_units: DEFAULT_MIN_PROVIDER_BOND_MICRO_UNITS * 3,
            available_micro_units: 220_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet provider registered");
    let backstop = state
        .submit_backstop_request(SubmitBackstopRequest {
            pool_id: pool.pool_id.clone(),
            provider_id: provider.provider_id,
            sealed_request_root: sample_hash("sealed-request", 1),
            redacted_request_root: sample_hash("redacted-request", 1),
            requested_micro_units: 48_000_000,
            max_fee_bps: 10,
            stress_bps: 1_900,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet backstop request submitted");
    state
        .record_attestation(RecordAttestationRequest {
            request_id: backstop.request_id.clone(),
            kind: AttestationKind::SettlementSafe,
            oracle_committee_root: sample_hash("oracle-committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 8,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet oracle attestation recorded");
    state
        .settle_request(SettleRequest {
            request_id: backstop.request_id.clone(),
            settlement_root: sample_hash("settlement", 1),
            decision: SettlementDecision::ApproveWithRebate,
            settled_slot: DEVNET_SLOT + 12,
        })
        .expect("devnet backstop request settled");
    state
        .issue_rebate(IssueRebateRequest {
            request_id: backstop.request_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 1_100,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 13,
            expires_slot: DEVNET_SLOT + DEFAULT_BACKSTOP_WINDOW_SLOTS,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: backstop.request_id,
            public_fields: [
                "request_id",
                "pool_id",
                "scope",
                "requested_micro_units",
                "stress_bps",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "provider_commitment",
                "sealed_request_root",
                "liquidity_commitment_root",
                "oracle_committee_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 832,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 10,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    state
        .open_pool(OpenPoolRequest {
            scope: BackstopScope::PerpsInsuranceFund,
            sealed_pool_root: sample_hash("sealed-pool", 2),
            public_hint_root: sample_hash("public-hint", 2),
            liquidity_root: sample_hash("liquidity", 2),
            target_liquidity_micro_units: 80_000_000,
            fee_cap_bps: 9,
            stress_trigger_bps: 1_400,
            opened_slot: DEVNET_SLOT + 32,
        })
        .expect("demo backstop pool opened");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!(state.public_record())
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("oracle-attested-liquidity-backstop:{domain}:id"),
        parts,
        24,
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "oracle-attested-liquidity-backstop:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn ensure_non_empty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, name: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
