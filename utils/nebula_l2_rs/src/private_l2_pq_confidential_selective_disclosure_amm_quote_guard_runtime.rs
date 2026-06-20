use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialSelectiveDisclosureAmmQuoteGuardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-selective-disclosure-amm-quote-guard-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SELECTIVE_DISCLOSURE_AMM_QUOTE_GUARD_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_QUOTE_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const QUOTE_GUARD_SUITE: &str = "confidential-selective-disclosure-amm-quote-guard-root-v1";
pub const DISCLOSURE_SUITE: &str = "amm-quote-selective-disclosure-policy-root-v1";
pub const REBATE_SUITE: &str = "selective-disclosure-amm-quote-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-amm-quote-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "confidential-amm-quote-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUOTE_WINDOW_SLOTS: u64 = 64;
pub const DEFAULT_DISCLOSURE_WINDOW_SLOTS: u64 = 288;
pub const DEFAULT_MAX_QUOTE_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MIN_GUARD_BOND_MICRO_UNITS: u64 = 18_000_000;
pub const DEFAULT_MIN_LP_PRIVACY_SET_SIZE: u64 = 32_768;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_SLIPPAGE_BPS: u64 = 400;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POOLS: usize = 524_288;
pub const MAX_GUARDS: usize = 1_048_576;
pub const MAX_QUOTES: usize = 2_097_152;
pub const MAX_DISCLOSURES: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 7_712;
pub const DEVNET_SLOT: u64 = 199;
pub const DEVNET_L2_HEIGHT: u64 = 3_200_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteScope {
    ConstantProductSwap,
    StableSwap,
    ConcentratedLiquidity,
    CrossPoolRoute,
    TokenBasketRebalance,
    BridgeExitAmm,
    LendingLiquidationSwap,
    PerpsFundingSwap,
}

impl QuoteScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProductSwap => "constant_product_swap",
            Self::StableSwap => "stable_swap",
            Self::ConcentratedLiquidity => "concentrated_liquidity",
            Self::CrossPoolRoute => "cross_pool_route",
            Self::TokenBasketRebalance => "token_basket_rebalance",
            Self::BridgeExitAmm => "bridge_exit_amm",
            Self::LendingLiquidationSwap => "lending_liquidation_swap",
            Self::PerpsFundingSwap => "perps_funding_swap",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::BridgeExitAmm => 9,
            Self::LendingLiquidationSwap => 8,
            Self::PerpsFundingSwap => 7,
            Self::CrossPoolRoute => 6,
            Self::TokenBasketRebalance => 5,
            Self::ConcentratedLiquidity => 5,
            Self::StableSwap => 3,
            Self::ConstantProductSwap => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Planned,
    Active,
    Throttled,
    DisclosureOnly,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Candidate,
    Active,
    Probation,
    Slashed,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Submitted,
    Guarded,
    DisclosureCommitted,
    Attested,
    Settled,
    RebateIssued,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosurePolicyKind {
    PriceBandOnly,
    LiquidityDepthOnly,
    FeeAndSlippage,
    RouteShapeOnly,
    CounterpartyCohort,
    EmergencyFullDisclosure,
    AuditorSealedDisclosure,
    LpRiskBucket,
}

impl DisclosurePolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceBandOnly => "price_band_only",
            Self::LiquidityDepthOnly => "liquidity_depth_only",
            Self::FeeAndSlippage => "fee_and_slippage",
            Self::RouteShapeOnly => "route_shape_only",
            Self::CounterpartyCohort => "counterparty_cohort",
            Self::EmergencyFullDisclosure => "emergency_full_disclosure",
            Self::AuditorSealedDisclosure => "auditor_sealed_disclosure",
            Self::LpRiskBucket => "lp_risk_bucket",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqGuardSignatureVerified,
    QuoteCommitmentOpened,
    DisclosurePolicyObserved,
    SlippageBoundObserved,
    LpPrivacyBudgetObserved,
    FeeCapObserved,
    MevBoundaryObserved,
    SettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqGuardSignatureVerified => "pq_guard_signature_verified",
            Self::QuoteCommitmentOpened => "quote_commitment_opened",
            Self::DisclosurePolicyObserved => "disclosure_policy_observed",
            Self::SlippageBoundObserved => "slippage_bound_observed",
            Self::LpPrivacyBudgetObserved => "lp_privacy_budget_observed",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::MevBoundaryObserved => "mev_boundary_observed",
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
    Reject,
    Retry,
    Quarantine,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ApproveWithRebate => "approve_with_rebate",
            Self::PartialFill => "partial_fill",
            Self::Reject => "reject",
            Self::Retry => "retry",
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
    pub pq_quote_suite: String,
    pub quote_guard_suite: String,
    pub disclosure_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub quote_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quote_window_slots: u64,
    pub disclosure_window_slots: u64,
    pub max_quote_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_guard_bond_micro_units: u64,
    pub min_lp_privacy_set_size: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_slippage_bps: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_quote_suite: PQ_QUOTE_SUITE.to_string(),
            quote_guard_suite: QUOTE_GUARD_SUITE.to_string(),
            disclosure_suite: DISCLOSURE_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quote_window_slots: DEFAULT_QUOTE_WINDOW_SLOTS,
            disclosure_window_slots: DEFAULT_DISCLOSURE_WINDOW_SLOTS,
            max_quote_fee_bps: DEFAULT_MAX_QUOTE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_guard_bond_micro_units: DEFAULT_MIN_GUARD_BOND_MICRO_UNITS,
            min_lp_privacy_set_size: DEFAULT_MIN_LP_PRIVACY_SET_SIZE,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools_opened: u64,
    pub guards_registered: u64,
    pub quotes_submitted: u64,
    pub disclosures_committed: u64,
    pub attestations_recorded: u64,
    pub settlements_recorded: u64,
    pub rebates_issued: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub quarantines: u64,
    pub total_guard_bond_micro_units: u64,
    pub total_quote_notional_micro_units: u64,
    pub total_fee_micro_units: u64,
    pub total_rebated_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pool_root: String,
    pub guard_root: String,
    pub quote_root: String,
    pub disclosure_root: String,
    pub attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            pool_root: empty_root("pools"),
            guard_root: empty_root("guards"),
            quote_root: empty_root("quotes"),
            disclosure_root: empty_root("disclosures"),
            attestation_root: empty_root("attestations"),
            settlement_root: empty_root("settlements"),
            rebate_root: empty_root("rebates"),
            redaction_root: empty_root("redactions"),
            operator_summary_root: empty_root("operator-summaries"),
            counters_root: empty_root("counters"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardedPool {
    pub pool_id: String,
    pub scope: QuoteScope,
    pub status: PoolStatus,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub liquidity_commitment_root: String,
    pub lp_privacy_set_size: u64,
    pub max_quote_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub opened_slot: u64,
    pub last_updated_slot: u64,
    pub active_guards: u64,
    pub guarded_quotes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteGuard {
    pub guard_id: String,
    pub pool_id: String,
    pub status: GuardStatus,
    pub guard_commitment: String,
    pub pq_verifying_key_root: String,
    pub disclosure_policy_root: String,
    pub bond_micro_units: u64,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
    pub quotes_guarded: u64,
    pub violations: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardedQuote {
    pub quote_id: String,
    pub pool_id: String,
    pub guard_id: String,
    pub status: QuoteStatus,
    pub sealed_quote_root: String,
    pub redacted_quote_root: String,
    pub route_commitment_root: String,
    pub notional_micro_units: u64,
    pub max_fee_bps: u64,
    pub slippage_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub disclosure_id: Option<String>,
    pub attestation_count: u64,
    pub quorum_weight_bps: u64,
    pub settlement_decision: Option<SettlementDecision>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DisclosureCommitment {
    pub disclosure_id: String,
    pub quote_id: String,
    pub policy_kind: DisclosurePolicyKind,
    pub disclosed_fields: BTreeSet<String>,
    pub sealed_payload_root: String,
    pub auditor_committee_root: String,
    pub committed_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteAttestation {
    pub attestation_id: String,
    pub quote_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub quote_id: String,
    pub pool_id: String,
    pub guard_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub filled_micro_units: u64,
    pub fee_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub quote_id: String,
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
    pub epoch: u64,
    pub slot: u64,
    pub l2_height: u64,
    pub active_pools: u64,
    pub active_guards: u64,
    pub guarded_quotes: u64,
    pub attested_quotes: u64,
    pub settled_quotes: u64,
    pub quarantined_quotes: u64,
    pub total_quote_notional_micro_units: u64,
    pub total_fee_micro_units: u64,
    pub total_rebated_micro_units: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPoolRequest {
    pub scope: QuoteScope,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub liquidity_commitment_root: String,
    pub lp_privacy_set_size: u64,
    pub max_quote_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPoolReceipt {
    pub pool_id: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterGuardRequest {
    pub pool_id: String,
    pub guard_commitment: String,
    pub pq_verifying_key_root: String,
    pub disclosure_policy_root: String,
    pub bond_micro_units: u64,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterGuardReceipt {
    pub guard_id: String,
    pub pool_id: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitQuoteRequest {
    pub pool_id: String,
    pub guard_id: String,
    pub sealed_quote_root: String,
    pub redacted_quote_root: String,
    pub route_commitment_root: String,
    pub notional_micro_units: u64,
    pub max_fee_bps: u64,
    pub slippage_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitQuoteReceipt {
    pub quote_id: String,
    pub expires_slot: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitDisclosureRequest {
    pub quote_id: String,
    pub policy_kind: DisclosurePolicyKind,
    pub disclosed_fields: BTreeSet<String>,
    pub sealed_payload_root: String,
    pub auditor_committee_root: String,
    pub committed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitDisclosureReceipt {
    pub disclosure_id: String,
    pub quote_id: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub quote_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleQuoteRequest {
    pub quote_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub filled_micro_units: u64,
    pub fee_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub quote_id: String,
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
    pub pools: BTreeMap<String, GuardedPool>,
    pub guards: BTreeMap<String, QuoteGuard>,
    pub quotes: BTreeMap<String, GuardedQuote>,
    pub disclosures: BTreeMap<String, DisclosureCommitment>,
    pub attestations: BTreeMap<String, QuoteAttestation>,
    pub settlements: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            guards: BTreeMap::new(),
            quotes: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn open_pool(&mut self, request: OpenPoolRequest) -> Result<OpenPoolReceipt> {
        ensure_capacity(self.pools.len(), MAX_POOLS, "pools")?;
        ensure_non_empty(&request.sealed_pool_root, "sealed_pool_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_non_empty(
            &request.liquidity_commitment_root,
            "liquidity_commitment_root",
        )?;
        ensure_bps(request.max_quote_fee_bps, "max_quote_fee_bps")?;
        ensure_bps(request.max_slippage_bps, "max_slippage_bps")?;
        if request.lp_privacy_set_size < self.config.min_lp_privacy_set_size {
            return Err("lp_privacy_set_size below minimum".to_string());
        }
        if request.max_quote_fee_bps > self.config.max_quote_fee_bps {
            return Err("max_quote_fee_bps exceeds configured maximum".to_string());
        }
        if request.max_slippage_bps > self.config.max_slippage_bps {
            return Err("max_slippage_bps exceeds configured maximum".to_string());
        }
        let pool_id = stable_id(
            "pool",
            &[
                HashPart::Str(request.scope.as_str()),
                HashPart::Str(&request.sealed_pool_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        if self.pools.contains_key(&pool_id) {
            return Err(format!("pool {pool_id} already exists"));
        }
        let pool = GuardedPool {
            pool_id: pool_id.clone(),
            scope: request.scope,
            status: PoolStatus::Active,
            sealed_pool_root: request.sealed_pool_root,
            public_hint_root: request.public_hint_root,
            liquidity_commitment_root: request.liquidity_commitment_root,
            lp_privacy_set_size: request.lp_privacy_set_size,
            max_quote_fee_bps: request.max_quote_fee_bps,
            max_slippage_bps: request.max_slippage_bps,
            opened_slot: request.opened_slot,
            last_updated_slot: request.opened_slot,
            active_guards: 0,
            guarded_quotes: 0,
        };
        self.pools.insert(pool_id.clone(), pool);
        self.counters.pools_opened = self.counters.pools_opened.saturating_add(1);
        self.refresh_roots();
        Ok(OpenPoolReceipt {
            pool_id,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn register_guard(
        &mut self,
        request: RegisterGuardRequest,
    ) -> Result<RegisterGuardReceipt> {
        ensure_capacity(self.guards.len(), MAX_GUARDS, "guards")?;
        ensure_non_empty(&request.pool_id, "pool_id")?;
        ensure_non_empty(&request.guard_commitment, "guard_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        ensure_non_empty(&request.disclosure_policy_root, "disclosure_policy_root")?;
        if request.bond_micro_units < self.config.min_guard_bond_micro_units {
            return Err("bond_micro_units below minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below minimum".to_string());
        }
        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        if !matches!(pool.status, PoolStatus::Active | PoolStatus::Throttled) {
            return Err("pool is not accepting guards".to_string());
        }
        let guard_id = stable_id(
            "guard",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.guard_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.joined_slot),
            ],
        );
        if self.guards.contains_key(&guard_id) {
            return Err(format!("guard {guard_id} already exists"));
        }
        let guard = QuoteGuard {
            guard_id: guard_id.clone(),
            pool_id: request.pool_id.clone(),
            status: GuardStatus::Active,
            guard_commitment: request.guard_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            disclosure_policy_root: request.disclosure_policy_root,
            bond_micro_units: request.bond_micro_units,
            privacy_set_size: request.privacy_set_size,
            joined_slot: request.joined_slot,
            quotes_guarded: 0,
            violations: 0,
        };
        pool.active_guards = pool.active_guards.saturating_add(1);
        pool.last_updated_slot = request.joined_slot;
        self.counters.guards_registered = self.counters.guards_registered.saturating_add(1);
        self.counters.total_guard_bond_micro_units = self
            .counters
            .total_guard_bond_micro_units
            .saturating_add(request.bond_micro_units);
        self.guards.insert(guard_id.clone(), guard);
        self.refresh_roots();
        Ok(RegisterGuardReceipt {
            guard_id,
            pool_id: request.pool_id,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn submit_quote(&mut self, request: SubmitQuoteRequest) -> Result<SubmitQuoteReceipt> {
        ensure_capacity(self.quotes.len(), MAX_QUOTES, "quotes")?;
        ensure_non_empty(&request.pool_id, "pool_id")?;
        ensure_non_empty(&request.guard_id, "guard_id")?;
        ensure_non_empty(&request.sealed_quote_root, "sealed_quote_root")?;
        ensure_non_empty(&request.redacted_quote_root, "redacted_quote_root")?;
        ensure_non_empty(&request.route_commitment_root, "route_commitment_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure_bps(request.slippage_bps, "slippage_bps")?;
        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        let guard = self
            .guards
            .get_mut(&request.guard_id)
            .ok_or_else(|| format!("unknown guard {}", request.guard_id))?;
        if guard.pool_id != request.pool_id {
            return Err("guard does not belong to pool".to_string());
        }
        if !matches!(guard.status, GuardStatus::Active | GuardStatus::Probation) {
            return Err("guard is not accepting quotes".to_string());
        }
        if request.max_fee_bps > pool.max_quote_fee_bps {
            return Err("quote fee exceeds pool cap".to_string());
        }
        if request.slippage_bps > pool.max_slippage_bps {
            return Err("slippage exceeds pool cap".to_string());
        }
        let quote_id = stable_id(
            "quote",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.guard_id),
                HashPart::Str(&request.sealed_quote_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        if self.quotes.contains_key(&quote_id) {
            return Err(format!("quote {quote_id} already exists"));
        }
        let expires_slot = request
            .submitted_slot
            .saturating_add(self.config.quote_window_slots);
        let quote = GuardedQuote {
            quote_id: quote_id.clone(),
            pool_id: request.pool_id.clone(),
            guard_id: request.guard_id.clone(),
            status: QuoteStatus::Guarded,
            sealed_quote_root: request.sealed_quote_root,
            redacted_quote_root: request.redacted_quote_root,
            route_commitment_root: request.route_commitment_root,
            notional_micro_units: request.notional_micro_units,
            max_fee_bps: request.max_fee_bps,
            slippage_bps: request.slippage_bps,
            submitted_slot: request.submitted_slot,
            expires_slot,
            disclosure_id: None,
            attestation_count: 0,
            quorum_weight_bps: 0,
            settlement_decision: None,
        };
        pool.guarded_quotes = pool.guarded_quotes.saturating_add(1);
        pool.last_updated_slot = request.submitted_slot;
        guard.quotes_guarded = guard.quotes_guarded.saturating_add(1);
        self.counters.quotes_submitted = self.counters.quotes_submitted.saturating_add(1);
        self.counters.total_quote_notional_micro_units = self
            .counters
            .total_quote_notional_micro_units
            .saturating_add(request.notional_micro_units);
        self.quotes.insert(quote_id.clone(), quote);
        self.refresh_roots();
        Ok(SubmitQuoteReceipt {
            quote_id,
            expires_slot,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn commit_disclosure(
        &mut self,
        request: CommitDisclosureRequest,
    ) -> Result<CommitDisclosureReceipt> {
        ensure_capacity(self.disclosures.len(), MAX_DISCLOSURES, "disclosures")?;
        ensure_non_empty(&request.quote_id, "quote_id")?;
        ensure_non_empty(&request.sealed_payload_root, "sealed_payload_root")?;
        ensure_non_empty(&request.auditor_committee_root, "auditor_committee_root")?;
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| format!("unknown quote {}", request.quote_id))?;
        if !matches!(quote.status, QuoteStatus::Guarded) {
            return Err("quote is not disclosure-committable".to_string());
        }
        if request.committed_slot > quote.expires_slot {
            return Err("disclosure committed after quote expiry".to_string());
        }
        let disclosure_id = stable_id(
            "disclosure",
            &[
                HashPart::Str(&request.quote_id),
                HashPart::Str(request.policy_kind.as_str()),
                HashPart::Str(&request.sealed_payload_root),
                HashPart::U64(request.committed_slot),
            ],
        );
        if self.disclosures.contains_key(&disclosure_id) {
            return Err(format!("disclosure {disclosure_id} already exists"));
        }
        let expires_slot = request
            .committed_slot
            .saturating_add(self.config.disclosure_window_slots);
        let disclosure = DisclosureCommitment {
            disclosure_id: disclosure_id.clone(),
            quote_id: request.quote_id.clone(),
            policy_kind: request.policy_kind,
            disclosed_fields: request.disclosed_fields,
            sealed_payload_root: request.sealed_payload_root,
            auditor_committee_root: request.auditor_committee_root,
            committed_slot: request.committed_slot,
            expires_slot,
        };
        quote.status = QuoteStatus::DisclosureCommitted;
        quote.disclosure_id = Some(disclosure_id.clone());
        self.counters.disclosures_committed = self.counters.disclosures_committed.saturating_add(1);
        self.disclosures.insert(disclosure_id.clone(), disclosure);
        self.refresh_roots();
        Ok(CommitDisclosureReceipt {
            disclosure_id,
            quote_id: request.quote_id,
            state_root: self.roots.state_root.clone(),
        })
    }

    pub fn record_attestation(&mut self, request: RecordAttestationRequest) -> Result<String> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.quote_id, "quote_id")?;
        ensure_non_empty(&request.committee_root, "committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| format!("unknown quote {}", request.quote_id))?;
        if !matches!(
            quote.status,
            QuoteStatus::DisclosureCommitted | QuoteStatus::Guarded
        ) {
            return Err("quote is not accepting attestations".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.quote_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.committee_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation {attestation_id} already exists"));
        }
        let accepted = request.quorum_weight_bps >= self.config.min_attestation_quorum_bps;
        let attestation = QuoteAttestation {
            attestation_id: attestation_id.clone(),
            quote_id: request.quote_id.clone(),
            kind: request.kind,
            committee_root: request.committee_root,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
            accepted,
        };
        quote.attestation_count = quote.attestation_count.saturating_add(1);
        quote.quorum_weight_bps = quote.quorum_weight_bps.max(request.quorum_weight_bps);
        if accepted {
            quote.status = QuoteStatus::Attested;
        }
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_quote(&mut self, request: SettleQuoteRequest) -> Result<String> {
        ensure_capacity(self.settlements.len(), MAX_SETTLEMENTS, "settlements")?;
        ensure_non_empty(&request.quote_id, "quote_id")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| format!("unknown quote {}", request.quote_id))?;
        if !matches!(
            quote.status,
            QuoteStatus::Attested | QuoteStatus::DisclosureCommitted
        ) {
            return Err("quote is not settleable".to_string());
        }
        if request.settled_slot
            > quote
                .expires_slot
                .saturating_add(self.config.disclosure_window_slots)
        {
            return Err("settled_slot exceeds disclosure window".to_string());
        }
        let fee_cap = quote.notional_micro_units.saturating_mul(quote.max_fee_bps) / MAX_BPS;
        if request.fee_micro_units > fee_cap {
            return Err("fee exceeds quote cap".to_string());
        }
        let settlement_id = stable_id(
            "settlement",
            &[
                HashPart::Str(&request.quote_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::Str(&request.settlement_root),
                HashPart::U64(request.settled_slot),
            ],
        );
        if self.settlements.contains_key(&settlement_id) {
            return Err(format!("settlement {settlement_id} already exists"));
        }
        quote.status = match request.decision {
            SettlementDecision::Reject => QuoteStatus::Expired,
            SettlementDecision::Quarantine => {
                self.counters.quarantines = self.counters.quarantines.saturating_add(1);
                QuoteStatus::Quarantined
            }
            SettlementDecision::Expire => QuoteStatus::Expired,
            _ => QuoteStatus::Settled,
        };
        quote.settlement_decision = Some(request.decision);
        let settlement = SettlementReceipt {
            settlement_id: settlement_id.clone(),
            quote_id: request.quote_id.clone(),
            pool_id: quote.pool_id.clone(),
            guard_id: quote.guard_id.clone(),
            settlement_root: request.settlement_root,
            decision: request.decision,
            filled_micro_units: request.filled_micro_units,
            fee_micro_units: request.fee_micro_units,
            settled_slot: request.settled_slot,
        };
        self.counters.settlements_recorded = self.counters.settlements_recorded.saturating_add(1);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(request.fee_micro_units);
        self.settlements.insert(settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<String> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_non_empty(&request.quote_id, "quote_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.expires_slot <= request.issued_slot {
            return Err("expires_slot must be greater than issued_slot".to_string());
        }
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| format!("unknown quote {}", request.quote_id))?;
        if !matches!(quote.status, QuoteStatus::Settled) {
            return Err("quote must be settled before rebate".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.quote_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::Str(&request.beneficiary_group_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!("rebate {rebate_id} already exists"));
        }
        let rebate = RebateReceipt {
            rebate_id: rebate_id.clone(),
            quote_id: request.quote_id.clone(),
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        quote.status = QuoteStatus::RebateIssued;
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.counters.total_rebated_micro_units = self
            .counters
            .total_rebated_micro_units
            .saturating_add(request.amount_micro_units);
        self.rebates.insert(rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn publish_redaction_budget(&mut self, request: RedactionBudgetRequest) -> Result<()> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction budgets",
        )?;
        ensure_non_empty(&request.target_id, "target_id")?;
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual_public_bytes exceeds max_public_bytes".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("max_public_bytes exceeds configured maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below minimum".to_string());
        }
        self.redaction_budgets.insert(
            request.target_id.clone(),
            RedactionBudget {
                target_id: request.target_id,
                public_fields: request.public_fields,
                redacted_fields: request.redacted_fields,
                max_public_bytes: request.max_public_bytes,
                actual_public_bytes: request.actual_public_bytes,
                privacy_set_size: request.privacy_set_size,
            },
        );
        self.counters.redaction_budgets_published =
            self.counters.redaction_budgets_published.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<()> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let active_pools = self
            .pools
            .values()
            .filter(|pool| matches!(pool.status, PoolStatus::Active | PoolStatus::Throttled))
            .count() as u64;
        let active_guards = self
            .guards
            .values()
            .filter(|guard| matches!(guard.status, GuardStatus::Active | GuardStatus::Probation))
            .count() as u64;
        let attested_quotes = self
            .quotes
            .values()
            .filter(|quote| matches!(quote.status, QuoteStatus::Attested))
            .count() as u64;
        let settled_quotes = self
            .quotes
            .values()
            .filter(|quote| {
                matches!(
                    quote.status,
                    QuoteStatus::Settled | QuoteStatus::RebateIssued
                )
            })
            .count() as u64;
        let quarantined_quotes = self
            .quotes
            .values()
            .filter(|quote| matches!(quote.status, QuoteStatus::Quarantined))
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::U64(DEVNET_EPOCH),
                HashPart::U64(DEVNET_SLOT),
                HashPart::Str(&self.roots.state_root),
            ],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            epoch: DEVNET_EPOCH,
            slot: DEVNET_SLOT,
            l2_height: DEVNET_L2_HEIGHT,
            active_pools,
            active_guards,
            guarded_quotes: self.counters.quotes_submitted,
            attested_quotes,
            settled_quotes,
            quarantined_quotes,
            total_quote_notional_micro_units: self.counters.total_quote_notional_micro_units,
            total_fee_micro_units: self.counters.total_fee_micro_units,
            total_rebated_micro_units: self.counters.total_rebated_micro_units,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
            state_root: self.roots.state_root.clone(),
        };
        self.operator_summaries.insert(summary_id, summary);
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = object_root("config", &self.config);
        self.roots.pool_root = map_root("pools", &self.pools);
        self.roots.guard_root = map_root("guards", &self.guards);
        self.roots.quote_root = map_root("quotes", &self.quotes);
        self.roots.disclosure_root = map_root("disclosures", &self.disclosures);
        self.roots.attestation_root = map_root("attestations", &self.attestations);
        self.roots.settlement_root = map_root("settlements", &self.settlements);
        self.roots.rebate_root = map_root("rebates", &self.rebates);
        self.roots.redaction_root = map_root("redactions", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("operator-summaries", &self.operator_summaries);
        self.roots.counters_root = object_root("counters", &self.counters);
        self.roots.state_root = merkle_root(
            "selective-disclosure-amm-quote-guard:state",
            &[
                json!({ "config_root": self.roots.config_root }),
                json!({ "pool_root": self.roots.pool_root }),
                json!({ "guard_root": self.roots.guard_root }),
                json!({ "quote_root": self.roots.quote_root }),
                json!({ "disclosure_root": self.roots.disclosure_root }),
                json!({ "attestation_root": self.roots.attestation_root }),
                json!({ "settlement_root": self.roots.settlement_root }),
                json!({ "rebate_root": self.roots.rebate_root }),
                json!({ "redaction_root": self.roots.redaction_root }),
                json!({ "operator_summary_root": self.roots.operator_summary_root }),
                json!({ "counters_root": self.roots.counters_root }),
            ],
        );
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": self.config.hash_suite,
            "pq_quote_suite": self.config.pq_quote_suite,
            "quote_guard_suite": self.config.quote_guard_suite,
            "disclosure_suite": self.config.disclosure_suite,
            "fee_asset_id": self.config.fee_asset_id,
            "quote_asset_id": self.config.quote_asset_id,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "target_privacy_set_size": self.config.target_privacy_set_size,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "quote_window_slots": self.config.quote_window_slots,
            "disclosure_window_slots": self.config.disclosure_window_slots,
            "max_quote_fee_bps": self.config.max_quote_fee_bps,
            "target_rebate_bps": self.config.target_rebate_bps,
            "max_slippage_bps": self.config.max_slippage_bps,
            "counters": self.counters,
            "roots": self.roots,
            "pool_count": self.pools.len(),
            "guard_count": self.guards.len(),
            "quote_count": self.quotes.len(),
            "disclosure_count": self.disclosures.len(),
            "attestation_count": self.attestations.len(),
            "settlement_count": self.settlements.len(),
            "rebate_count": self.rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "pools": self.pools.values().map(|pool| json!({
                "pool_id": pool.pool_id,
                "scope": pool.scope,
                "status": pool.status,
                "public_hint_root": pool.public_hint_root,
                "lp_privacy_set_size": pool.lp_privacy_set_size,
                "max_quote_fee_bps": pool.max_quote_fee_bps,
                "max_slippage_bps": pool.max_slippage_bps,
                "active_guards": pool.active_guards,
                "guarded_quotes": pool.guarded_quotes,
            })).collect::<Vec<_>>(),
            "guards": self.guards.values().map(|guard| json!({
                "guard_id": guard.guard_id,
                "pool_id": guard.pool_id,
                "status": guard.status,
                "bond_micro_units": guard.bond_micro_units,
                "privacy_set_size": guard.privacy_set_size,
                "joined_slot": guard.joined_slot,
                "quotes_guarded": guard.quotes_guarded,
                "violations": guard.violations,
            })).collect::<Vec<_>>(),
            "quotes": self.quotes.values().map(|quote| json!({
                "quote_id": quote.quote_id,
                "pool_id": quote.pool_id,
                "guard_id": quote.guard_id,
                "status": quote.status,
                "redacted_quote_root": quote.redacted_quote_root,
                "route_commitment_root": quote.route_commitment_root,
                "notional_micro_units": quote.notional_micro_units,
                "max_fee_bps": quote.max_fee_bps,
                "slippage_bps": quote.slippage_bps,
                "submitted_slot": quote.submitted_slot,
                "expires_slot": quote.expires_slot,
                "disclosure_id": quote.disclosure_id,
                "attestation_count": quote.attestation_count,
                "quorum_weight_bps": quote.quorum_weight_bps,
                "settlement_decision": quote.settlement_decision,
            })).collect::<Vec<_>>(),
            "disclosures": self.disclosures.values().collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(|attestation| json!({
                "attestation_id": attestation.attestation_id,
                "quote_id": attestation.quote_id,
                "kind": attestation.kind,
                "statement_root": attestation.statement_root,
                "observed_slot": attestation.observed_slot,
                "quorum_weight_bps": attestation.quorum_weight_bps,
                "accepted": attestation.accepted,
            })).collect::<Vec<_>>(),
            "settlements": self.settlements.values().collect::<Vec<_>>(),
            "rebates": self.rebates.values().collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().collect::<Vec<_>>(),
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool = state
        .open_pool(OpenPoolRequest {
            scope: QuoteScope::BridgeExitAmm,
            sealed_pool_root: sample_hash("sealed-pool", 1),
            public_hint_root: sample_hash("public-hint", 1),
            liquidity_commitment_root: sample_hash("liquidity", 1),
            lp_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_quote_fee_bps: 11,
            max_slippage_bps: 180,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet AMM quote guard pool opened");
    let guard = state
        .register_guard(RegisterGuardRequest {
            pool_id: pool.pool_id.clone(),
            guard_commitment: sample_hash("guard", 1),
            pq_verifying_key_root: sample_hash("guard-pq-key", 1),
            disclosure_policy_root: sample_hash("disclosure-policy", 1),
            bond_micro_units: DEFAULT_MIN_GUARD_BOND_MICRO_UNITS * 3,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet quote guard registered");
    let quote = state
        .submit_quote(SubmitQuoteRequest {
            pool_id: pool.pool_id.clone(),
            guard_id: guard.guard_id.clone(),
            sealed_quote_root: sample_hash("sealed-quote", 1),
            redacted_quote_root: sample_hash("redacted-quote", 1),
            route_commitment_root: sample_hash("route", 1),
            notional_micro_units: 42_000_000,
            max_fee_bps: 9,
            slippage_bps: 120,
            submitted_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet quote submitted");
    state
        .commit_disclosure(CommitDisclosureRequest {
            quote_id: quote.quote_id.clone(),
            policy_kind: DisclosurePolicyKind::FeeAndSlippage,
            disclosed_fields: ["quote_id", "pool_id", "max_fee_bps", "slippage_bps"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            sealed_payload_root: sample_hash("sealed-disclosure", 1),
            auditor_committee_root: sample_hash("auditor-committee", 1),
            committed_slot: DEVNET_SLOT + 5,
        })
        .expect("devnet disclosure committed");
    state
        .record_attestation(RecordAttestationRequest {
            quote_id: quote.quote_id.clone(),
            kind: AttestationKind::SettlementSafe,
            committee_root: sample_hash("committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 8,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet quote attested");
    state
        .settle_quote(SettleQuoteRequest {
            quote_id: quote.quote_id.clone(),
            settlement_root: sample_hash("settlement", 1),
            decision: SettlementDecision::ApproveWithRebate,
            filled_micro_units: 41_200_000,
            fee_micro_units: 340,
            settled_slot: DEVNET_SLOT + 11,
        })
        .expect("devnet quote settled");
    state
        .issue_rebate(IssueRebateRequest {
            quote_id: quote.quote_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 120,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 12,
            expires_slot: DEVNET_SLOT + DEFAULT_DISCLOSURE_WINDOW_SLOTS,
        })
        .expect("devnet quote rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: quote.quote_id,
            public_fields: [
                "quote_id",
                "pool_id",
                "guard_id",
                "redacted_quote_root",
                "max_fee_bps",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "sealed_quote_root",
                "guard_commitment",
                "liquidity_commitment_root",
                "sealed_payload_root",
                "pq_signature_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 920,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 9,
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
            scope: QuoteScope::LendingLiquidationSwap,
            sealed_pool_root: sample_hash("sealed-pool", 2),
            public_hint_root: sample_hash("public-hint", 2),
            liquidity_commitment_root: sample_hash("liquidity", 2),
            lp_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_quote_fee_bps: 10,
            max_slippage_bps: 150,
            opened_slot: DEVNET_SLOT + 40,
        })
        .expect("demo quote guard pool opened");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("selective-disclosure-amm-quote-guard:{domain}:id"),
        parts,
        24,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("selective-disclosure-amm-quote-guard:{domain}"),
        &[],
    )
}

fn object_root<T: Serialize>(domain: &str, value: &T) -> String {
    merkle_root(
        &format!("selective-disclosure-amm-quote-guard:{domain}"),
        &[json!(value)],
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("selective-disclosure-amm-quote-guard:{domain}"),
        &leaves,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "selective-disclosure-amm-quote-guard:devnet-sample",
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
