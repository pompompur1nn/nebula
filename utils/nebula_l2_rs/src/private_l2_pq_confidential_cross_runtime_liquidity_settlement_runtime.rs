use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialCrossRuntimeLiquiditySettlementRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-runtime-liquidity-settlement-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_RUNTIME_LIQUIDITY_SETTLEMENT_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SETTLEMENT_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const ROUTE_COMMITMENT_SUITE: &str = "confidential-cross-runtime-liquidity-route-root-v1";
pub const NETTING_SUITE: &str = "private-cross-runtime-liquidity-netting-root-v1";
pub const REBATE_SUITE: &str = "cross-runtime-liquidity-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-cross-runtime-liquidity-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_SETTLEMENT_ASSET_ID: &str = "xmr-liquidity-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SETTLEMENT_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_BATCH_EXPIRY_SLOTS: u64 = 512;
pub const DEFAULT_MAX_ROUTE_FEE_BPS: u64 = 24;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_MIN_LIQUIDITY_MICRO_UNITS: u64 = 1_000_000;
pub const DEFAULT_MIN_ROUTER_BOND_MICRO_UNITS: u64 = 20_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 180;
pub const DEFAULT_MAX_BATCH_RISK_BPS: u64 = 2_500;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VENUES: usize = 524_288;
pub const MAX_ROUTES: usize = 1_048_576;
pub const MAX_INTENTS: usize = 2_097_152;
pub const MAX_BATCHES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_RECEIPTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_INTENTS_PER_BATCH: usize = 512;
pub const DEVNET_EPOCH: u64 = 7_424;
pub const DEVNET_SLOT: u64 = 113;
pub const DEVNET_L2_HEIGHT: u64 = 2_921_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDomain {
    MoneroBridge,
    PrivateAmm,
    TokenRouter,
    LendingPool,
    PerpsClearing,
    StablecoinMint,
    ContractRollupVm,
    FeeSponsorVault,
}

impl RuntimeDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateAmm => "private_amm",
            Self::TokenRouter => "token_router",
            Self::LendingPool => "lending_pool",
            Self::PerpsClearing => "perps_clearing",
            Self::StablecoinMint => "stablecoin_mint",
            Self::ContractRollupVm => "contract_rollup_vm",
            Self::FeeSponsorVault => "fee_sponsor_vault",
        }
    }

    pub fn settlement_weight(self) -> u64 {
        match self {
            Self::MoneroBridge => 8,
            Self::PerpsClearing => 7,
            Self::LendingPool => 6,
            Self::TokenRouter => 5,
            Self::PrivateAmm => 5,
            Self::StablecoinMint => 4,
            Self::ContractRollupVm => 4,
            Self::FeeSponsorVault => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueStatus {
    Candidate,
    Active,
    Throttled,
    Draining,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Proposed,
    Open,
    Congested,
    Clearing,
    Paused,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Routed,
    Batched,
    Attested,
    Settled,
    RebateIssued,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Building,
    Sealed,
    Attested,
    Settled,
    Rejected,
    Quarantined,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqRouterSignatureVerified,
    VenueLiquidityCommitted,
    NettingEquationChecked,
    PriceImpactBounded,
    PrivacyBoundaryObserved,
    MoneroReserveHintChecked,
    FeeCapObserved,
    SettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqRouterSignatureVerified => "pq_router_signature_verified",
            Self::VenueLiquidityCommitted => "venue_liquidity_committed",
            Self::NettingEquationChecked => "netting_equation_checked",
            Self::PriceImpactBounded => "price_impact_bounded",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::MoneroReserveHintChecked => "monero_reserve_hint_checked",
            Self::FeeCapObserved => "fee_cap_observed",
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
    pub pq_settlement_suite: String,
    pub route_commitment_suite: String,
    pub netting_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub settlement_window_slots: u64,
    pub batch_expiry_slots: u64,
    pub max_route_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_liquidity_micro_units: u64,
    pub min_router_bond_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_batch_risk_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_settlement_suite: PQ_SETTLEMENT_SUITE.to_string(),
            route_commitment_suite: ROUTE_COMMITMENT_SUITE.to_string(),
            netting_suite: NETTING_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            settlement_asset_id: DEFAULT_SETTLEMENT_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            settlement_window_slots: DEFAULT_SETTLEMENT_WINDOW_SLOTS,
            batch_expiry_slots: DEFAULT_BATCH_EXPIRY_SLOTS,
            max_route_fee_bps: DEFAULT_MAX_ROUTE_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_liquidity_micro_units: DEFAULT_MIN_LIQUIDITY_MICRO_UNITS,
            min_router_bond_micro_units: DEFAULT_MIN_ROUTER_BOND_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_batch_risk_bps: DEFAULT_MAX_BATCH_RISK_BPS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_settlement_suite, "pq_settlement_suite")?;
        ensure_non_empty(&self.route_commitment_suite, "route_commitment_suite")?;
        ensure_non_empty(&self.netting_suite, "netting_suite")?;
        ensure_non_empty(&self.rebate_suite, "rebate_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.settlement_asset_id, "settlement_asset_id")?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set must be >= minimum".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security bits below configured floor".to_string());
        }
        if self.settlement_window_slots == 0 || self.batch_expiry_slots == 0 {
            return Err("settlement windows must be non-zero".to_string());
        }
        ensure_bps(self.max_route_fee_bps, "max_route_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        ensure_bps(self.max_price_impact_bps, "max_price_impact_bps")?;
        ensure_bps(self.max_batch_risk_bps, "max_batch_risk_bps")?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err("strong attestation quorum below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub venues: u64,
    pub routes: u64,
    pub intents: u64,
    pub batches: u64,
    pub attestations: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_batches: u64,
    pub settled_intents: u64,
    pub quarantined_batches: u64,
    pub quarantined_intents: u64,
    pub total_liquidity_micro_units: u64,
    pub netted_liquidity_micro_units: u64,
    pub rebated_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "venues": self.venues,
            "routes": self.routes,
            "intents": self.intents,
            "batches": self.batches,
            "attestations": self.attestations,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "settled_batches": self.settled_batches,
            "settled_intents": self.settled_intents,
            "quarantined_batches": self.quarantined_batches,
            "quarantined_intents": self.quarantined_intents,
            "total_liquidity_micro_units": self.total_liquidity_micro_units,
            "netted_liquidity_micro_units": self.netted_liquidity_micro_units,
            "rebated_micro_units": self.rebated_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub venue_root: String,
    pub route_root: String,
    pub intent_root: String,
    pub batch_root: String,
    pub attestation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_root": self.venue_root,
            "route_root": self.route_root,
            "intent_root": self.intent_root,
            "batch_root": self.batch_root,
            "attestation_root": self.attestation_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityVenue {
    pub venue_id: String,
    pub domain: RuntimeDomain,
    pub venue_commitment: String,
    pub pq_verifying_key_root: String,
    pub liquidity_root: String,
    pub bond_micro_units: u64,
    pub available_micro_units: u64,
    pub status: VenueStatus,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
}

impl LiquidityVenue {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_id": self.venue_id,
            "domain": self.domain.as_str(),
            "pq_verifying_key_root": self.pq_verifying_key_root,
            "liquidity_root": self.liquidity_root,
            "bond_micro_units": self.bond_micro_units,
            "available_micro_units": self.available_micro_units,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "joined_slot": self.joined_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRoute {
    pub route_id: String,
    pub source_venue_id: String,
    pub target_venue_id: String,
    pub source_domain: RuntimeDomain,
    pub target_domain: RuntimeDomain,
    pub sealed_route_root: String,
    pub public_hint_root: String,
    pub liquidity_limit_micro_units: u64,
    pub fee_cap_bps: u64,
    pub price_impact_limit_bps: u64,
    pub status: RouteStatus,
    pub opened_slot: u64,
    pub expires_slot: u64,
}

impl SettlementRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "source_venue_id": self.source_venue_id,
            "target_venue_id": self.target_venue_id,
            "source_domain": self.source_domain.as_str(),
            "target_domain": self.target_domain.as_str(),
            "public_hint_root": self.public_hint_root,
            "liquidity_limit_micro_units": self.liquidity_limit_micro_units,
            "fee_cap_bps": self.fee_cap_bps,
            "price_impact_limit_bps": self.price_impact_limit_bps,
            "status": self.status,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityIntent {
    pub intent_id: String,
    pub route_id: String,
    pub sender_commitment: String,
    pub sealed_intent_root: String,
    pub redacted_intent_root: String,
    pub amount_micro_units: u64,
    pub max_fee_bps: u64,
    pub max_price_impact_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub status: IntentStatus,
}

impl LiquidityIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "route_id": self.route_id,
            "redacted_intent_root": self.redacted_intent_root,
            "amount_micro_units": self.amount_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "rebate_bps": self.rebate_bps,
            "submitted_slot": self.submitted_slot,
            "expires_slot": self.expires_slot,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingBatch {
    pub batch_id: String,
    pub route_id: String,
    pub intent_ids: Vec<String>,
    pub sealed_batch_root: String,
    pub netted_liquidity_root: String,
    pub net_amount_micro_units: u64,
    pub fee_bps: u64,
    pub price_impact_bps: u64,
    pub risk_bps: u64,
    pub built_slot: u64,
    pub expires_slot: u64,
    pub status: BatchStatus,
}

impl NettingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "route_id": self.route_id,
            "intent_ids": self.intent_ids,
            "netted_liquidity_root": self.netted_liquidity_root,
            "net_amount_micro_units": self.net_amount_micro_units,
            "fee_bps": self.fee_bps,
            "price_impact_bps": self.price_impact_bps,
            "risk_bps": self.risk_bps,
            "built_slot": self.built_slot,
            "expires_slot": self.expires_slot,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub venue_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub route_id: String,
    pub settlement_root: String,
    pub filled_intents: u64,
    pub settled_micro_units: u64,
    pub fee_micro_units: u64,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub batch_id: String,
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
    pub venues: u64,
    pub routes: u64,
    pub open_intents: u64,
    pub sealed_batches: u64,
    pub settled_batches: u64,
    pub quarantined_batches: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
    pub netted_liquidity_micro_units: u64,
    pub rebated_micro_units: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterVenueRequest {
    pub domain: RuntimeDomain,
    pub venue_commitment: String,
    pub pq_verifying_key_root: String,
    pub liquidity_root: String,
    pub bond_micro_units: u64,
    pub available_micro_units: u64,
    pub privacy_set_size: u64,
    pub joined_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenRouteRequest {
    pub source_venue_id: String,
    pub target_venue_id: String,
    pub sealed_route_root: String,
    pub public_hint_root: String,
    pub liquidity_limit_micro_units: u64,
    pub fee_cap_bps: u64,
    pub price_impact_limit_bps: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitIntentRequest {
    pub route_id: String,
    pub sender_commitment: String,
    pub sealed_intent_root: String,
    pub redacted_intent_root: String,
    pub amount_micro_units: u64,
    pub max_fee_bps: u64,
    pub max_price_impact_bps: u64,
    pub rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildNettingBatchRequest {
    pub route_id: String,
    pub intent_ids: Vec<String>,
    pub sealed_batch_root: String,
    pub netted_liquidity_root: String,
    pub fee_bps: u64,
    pub price_impact_bps: u64,
    pub risk_bps: u64,
    pub built_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub batch_id: String,
    pub venue_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub batch_id: String,
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
    pub venues: BTreeMap<String, LiquidityVenue>,
    pub routes: BTreeMap<String, SettlementRoute>,
    pub intents: BTreeMap<String, LiquidityIntent>,
    pub batches: BTreeMap<String, NettingBatch>,
    pub attestations: BTreeMap<String, SettlementAttestation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default cross-runtime liquidity settlement config")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            venues: BTreeMap::new(),
            routes: BTreeMap::new(),
            intents: BTreeMap::new(),
            batches: BTreeMap::new(),
            attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn register_venue(&mut self, request: RegisterVenueRequest) -> Result<LiquidityVenue> {
        ensure_capacity(self.venues.len(), MAX_VENUES, "venues")?;
        ensure_non_empty(&request.venue_commitment, "venue_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        ensure_non_empty(&request.liquidity_root, "liquidity_root")?;
        if request.bond_micro_units < self.config.min_router_bond_micro_units {
            return Err("venue bond below configured minimum".to_string());
        }
        if request.available_micro_units < self.config.min_liquidity_micro_units {
            return Err("venue liquidity below configured minimum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("venue privacy set below configured minimum".to_string());
        }
        let venue_id = stable_id(
            "venue",
            &[
                HashPart::Str(request.domain.as_str()),
                HashPart::Str(&request.venue_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
            ],
        );
        let venue = LiquidityVenue {
            venue_id: venue_id.clone(),
            domain: request.domain,
            venue_commitment: request.venue_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            liquidity_root: request.liquidity_root,
            bond_micro_units: request.bond_micro_units,
            available_micro_units: request.available_micro_units,
            status: VenueStatus::Active,
            privacy_set_size: request.privacy_set_size,
            joined_slot: request.joined_slot,
        };
        self.venues.insert(venue_id, venue.clone());
        self.refresh_roots();
        Ok(venue)
    }

    pub fn open_route(&mut self, request: OpenRouteRequest) -> Result<SettlementRoute> {
        ensure_capacity(self.routes.len(), MAX_ROUTES, "routes")?;
        ensure_non_empty(&request.sealed_route_root, "sealed_route_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_bps(request.fee_cap_bps, "fee_cap_bps")?;
        ensure_bps(request.price_impact_limit_bps, "price_impact_limit_bps")?;
        if request.fee_cap_bps > self.config.max_route_fee_bps {
            return Err("route fee exceeds configured cap".to_string());
        }
        if request.price_impact_limit_bps > self.config.max_price_impact_bps {
            return Err("route price impact exceeds configured cap".to_string());
        }
        if request.liquidity_limit_micro_units < self.config.min_liquidity_micro_units {
            return Err("route liquidity limit below configured minimum".to_string());
        }
        let source = self
            .venues
            .get(&request.source_venue_id)
            .ok_or_else(|| "source venue not found".to_string())?;
        let target = self
            .venues
            .get(&request.target_venue_id)
            .ok_or_else(|| "target venue not found".to_string())?;
        if source.status != VenueStatus::Active || target.status != VenueStatus::Active {
            return Err("route venues must be active".to_string());
        }
        if source.venue_id == target.venue_id {
            return Err("route requires distinct venues".to_string());
        }
        let route_id = stable_id(
            "route",
            &[
                HashPart::Str(&request.source_venue_id),
                HashPart::Str(&request.target_venue_id),
                HashPart::Str(&request.sealed_route_root),
                HashPart::U64(request.opened_slot),
            ],
        );
        let route = SettlementRoute {
            route_id: route_id.clone(),
            source_venue_id: request.source_venue_id,
            target_venue_id: request.target_venue_id,
            source_domain: source.domain,
            target_domain: target.domain,
            sealed_route_root: request.sealed_route_root,
            public_hint_root: request.public_hint_root,
            liquidity_limit_micro_units: request.liquidity_limit_micro_units,
            fee_cap_bps: request.fee_cap_bps,
            price_impact_limit_bps: request.price_impact_limit_bps,
            status: RouteStatus::Open,
            opened_slot: request.opened_slot,
            expires_slot: request.opened_slot + self.config.batch_expiry_slots,
        };
        self.routes.insert(route_id, route.clone());
        self.refresh_roots();
        Ok(route)
    }

    pub fn submit_intent(&mut self, request: SubmitIntentRequest) -> Result<LiquidityIntent> {
        ensure_capacity(self.intents.len(), MAX_INTENTS, "intents")?;
        ensure_non_empty(&request.sender_commitment, "sender_commitment")?;
        ensure_non_empty(&request.sealed_intent_root, "sealed_intent_root")?;
        ensure_non_empty(&request.redacted_intent_root, "redacted_intent_root")?;
        ensure_bps(request.max_fee_bps, "max_fee_bps")?;
        ensure_bps(request.max_price_impact_bps, "max_price_impact_bps")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("intent rebate exceeds configured target".to_string());
        }
        let route = self
            .routes
            .get(&request.route_id)
            .ok_or_else(|| "route not found".to_string())?;
        if route.status != RouteStatus::Open {
            return Err("route is not open".to_string());
        }
        if request.max_fee_bps > route.fee_cap_bps {
            return Err("intent fee exceeds route cap".to_string());
        }
        if request.max_price_impact_bps > route.price_impact_limit_bps {
            return Err("intent price impact exceeds route cap".to_string());
        }
        if request.amount_micro_units == 0
            || request.amount_micro_units > route.liquidity_limit_micro_units
        {
            return Err("intent amount outside route liquidity limit".to_string());
        }
        let intent_id = stable_id(
            "intent",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(&request.redacted_intent_root),
                HashPart::U64(request.amount_micro_units),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let intent = LiquidityIntent {
            intent_id: intent_id.clone(),
            route_id: request.route_id,
            sender_commitment: request.sender_commitment,
            sealed_intent_root: request.sealed_intent_root,
            redacted_intent_root: request.redacted_intent_root,
            amount_micro_units: request.amount_micro_units,
            max_fee_bps: request.max_fee_bps,
            max_price_impact_bps: request.max_price_impact_bps,
            rebate_bps: request.rebate_bps,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + self.config.settlement_window_slots,
            status: IntentStatus::Routed,
        };
        self.intents.insert(intent_id, intent.clone());
        self.refresh_roots();
        Ok(intent)
    }

    pub fn build_netting_batch(
        &mut self,
        request: BuildNettingBatchRequest,
    ) -> Result<NettingBatch> {
        ensure_capacity(self.batches.len(), MAX_BATCHES, "batches")?;
        ensure_non_empty(&request.sealed_batch_root, "sealed_batch_root")?;
        ensure_non_empty(&request.netted_liquidity_root, "netted_liquidity_root")?;
        ensure_bps(request.fee_bps, "fee_bps")?;
        ensure_bps(request.price_impact_bps, "price_impact_bps")?;
        ensure_bps(request.risk_bps, "risk_bps")?;
        if request.risk_bps > self.config.max_batch_risk_bps {
            return Err("batch risk exceeds configured cap".to_string());
        }
        if request.intent_ids.is_empty() {
            return Err("batch requires at least one intent".to_string());
        }
        if request.intent_ids.len() > MAX_INTENTS_PER_BATCH {
            return Err("batch has too many intents".to_string());
        }
        let route = self
            .routes
            .get(&request.route_id)
            .ok_or_else(|| "route not found".to_string())?;
        if request.fee_bps > route.fee_cap_bps {
            return Err("batch fee exceeds route cap".to_string());
        }
        if request.price_impact_bps > route.price_impact_limit_bps {
            return Err("batch price impact exceeds route cap".to_string());
        }
        let mut unique = BTreeSet::new();
        let mut net_amount_micro_units = 0_u64;
        for intent_id in &request.intent_ids {
            if !unique.insert(intent_id.clone()) {
                return Err("batch includes duplicate intent".to_string());
            }
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("intent not found: {intent_id}"))?;
            if intent.route_id != request.route_id {
                return Err("batch intent route mismatch".to_string());
            }
            if intent.status != IntentStatus::Routed {
                return Err("batch intent is not routable".to_string());
            }
            if request.built_slot > intent.expires_slot {
                return Err("batch includes expired intent".to_string());
            }
            net_amount_micro_units =
                net_amount_micro_units.saturating_add(intent.amount_micro_units);
        }
        if net_amount_micro_units > route.liquidity_limit_micro_units {
            return Err("batch exceeds route liquidity limit".to_string());
        }
        let batch_id = stable_id(
            "batch",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(&request.sealed_batch_root),
                HashPart::U64(request.built_slot),
            ],
        );
        let batch = NettingBatch {
            batch_id: batch_id.clone(),
            route_id: request.route_id,
            intent_ids: request.intent_ids.clone(),
            sealed_batch_root: request.sealed_batch_root,
            netted_liquidity_root: request.netted_liquidity_root,
            net_amount_micro_units,
            fee_bps: request.fee_bps,
            price_impact_bps: request.price_impact_bps,
            risk_bps: request.risk_bps,
            built_slot: request.built_slot,
            expires_slot: request.built_slot + self.config.batch_expiry_slots,
            status: BatchStatus::Sealed,
        };
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Batched;
            }
        }
        self.batches.insert(batch_id, batch.clone());
        self.refresh_roots();
        Ok(batch)
    }

    pub fn record_attestation(
        &mut self,
        request: RecordAttestationRequest,
    ) -> Result<SettlementAttestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.committee_root, "committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        self.ensure_batch_exists(&request.batch_id)?;
        self.ensure_venue_exists(&request.venue_id)?;
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.venue_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = SettlementAttestation {
            attestation_id: attestation_id.clone(),
            batch_id: request.batch_id.clone(),
            venue_id: request.venue_id,
            kind: request.kind,
            committee_root: request.committee_root,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Attested;
            for intent_id in &batch.intent_ids {
                if let Some(intent) = self.intents.get_mut(intent_id) {
                    intent.status = IntentStatus::Attested;
                }
            }
        }
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_batch(&mut self, request: SettleBatchRequest) -> Result<SettlementReceipt> {
        ensure_capacity(self.receipts.len(), MAX_RECEIPTS, "receipts")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "batch not found".to_string())?
            .clone();
        if request.settled_slot > batch.expires_slot {
            return Err("batch settlement slot exceeds expiry".to_string());
        }
        let route = self
            .routes
            .get(&batch.route_id)
            .ok_or_else(|| "route not found".to_string())?
            .clone();
        let decision = request.decision;
        match decision {
            SettlementDecision::Approve
            | SettlementDecision::ApproveWithRebate
            | SettlementDecision::PartialFill => {
                if batch.status != BatchStatus::Attested && batch.status != BatchStatus::Sealed {
                    return Err("batch is not eligible for settlement".to_string());
                }
            }
            SettlementDecision::Retry => {}
            SettlementDecision::Reject
            | SettlementDecision::Quarantine
            | SettlementDecision::Expire => {}
        }
        let settled_micro_units = match decision {
            SettlementDecision::PartialFill => batch.net_amount_micro_units / 2,
            SettlementDecision::Approve | SettlementDecision::ApproveWithRebate => {
                batch.net_amount_micro_units
            }
            _ => 0,
        };
        let fee_micro_units = settled_micro_units.saturating_mul(batch.fee_bps) / MAX_BPS;
        let receipt_id = stable_id(
            "receipt",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.settlement_root),
                HashPart::Str(decision.as_str()),
                HashPart::U64(request.settled_slot),
            ],
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id.clone(),
            route_id: batch.route_id.clone(),
            settlement_root: request.settlement_root,
            filled_intents: batch.intent_ids.len() as u64,
            settled_micro_units,
            fee_micro_units,
            decision,
            settled_slot: request.settled_slot,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        self.apply_settlement(
            &request.batch_id,
            &batch.intent_ids,
            route,
            decision,
            settled_micro_units,
        )?;
        self.refresh_roots();
        Ok(receipt)
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
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "batch not found".to_string())?;
        if batch.status != BatchStatus::Settled {
            return Err("rebate requires a settled batch".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let receipt = RebateReceipt {
            rebate_id: rebate_id.clone(),
            batch_id: request.batch_id.clone(),
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.rebates.insert(rebate_id, receipt.clone());
        self.counters.rebated_micro_units = self
            .counters
            .rebated_micro_units
            .saturating_add(request.amount_micro_units);
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::RebateIssued;
            }
        }
        self.refresh_roots();
        Ok(receipt)
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
        let open_intents = self
            .intents
            .values()
            .filter(|intent| {
                matches!(
                    intent.status,
                    IntentStatus::Submitted
                        | IntentStatus::Routed
                        | IntentStatus::Batched
                        | IntentStatus::Attested
                )
            })
            .count() as u64;
        let sealed_batches = self
            .batches
            .values()
            .filter(|batch| matches!(batch.status, BatchStatus::Sealed | BatchStatus::Attested))
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[HashPart::U64(self.operator_summaries.len() as u64)],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            venues: self.venues.len() as u64,
            routes: self.routes.len() as u64,
            open_intents,
            sealed_batches,
            settled_batches: self.counters.settled_batches,
            quarantined_batches: self.counters.quarantined_batches,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
            netted_liquidity_micro_units: self.counters.netted_liquidity_micro_units,
            rebated_micro_units: self.counters.rebated_micro_units,
            state_root: self.state_root(),
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.venues = self.venues.len() as u64;
        self.counters.routes = self.routes.len() as u64;
        self.counters.intents = self.intents.len() as u64;
        self.counters.batches = self.batches.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.receipts = self.receipts.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots.venue_root = map_root("cross-runtime-liquidity-settlement:venues", &self.venues);
        self.roots.route_root = map_root("cross-runtime-liquidity-settlement:routes", &self.routes);
        self.roots.intent_root =
            map_root("cross-runtime-liquidity-settlement:intents", &self.intents);
        self.roots.batch_root =
            map_root("cross-runtime-liquidity-settlement:batches", &self.batches);
        self.roots.attestation_root = map_root(
            "cross-runtime-liquidity-settlement:attestations",
            &self.attestations,
        );
        self.roots.receipt_root = map_root(
            "cross-runtime-liquidity-settlement:receipts",
            &self.receipts,
        );
        self.roots.rebate_root =
            map_root("cross-runtime-liquidity-settlement:rebates", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "cross-runtime-liquidity-settlement:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "cross-runtime-liquidity-settlement:operator-summaries",
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
            "pq_settlement_suite": self.config.pq_settlement_suite,
            "route_commitment_suite": self.config.route_commitment_suite,
            "netting_suite": self.config.netting_suite,
            "rebate_suite": self.config.rebate_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "venues": self.venues,
            "routes": self.routes,
            "intents": self.intents,
            "batches": self.batches,
            "attestations": self.attestations,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
        })
    }

    fn compute_state_root(&self) -> String {
        let record = json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "venue_root": self.roots.venue_root,
            "route_root": self.roots.route_root,
            "intent_root": self.roots.intent_root,
            "batch_root": self.roots.batch_root,
            "attestation_root": self.roots.attestation_root,
            "receipt_root": self.roots.receipt_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "cross-runtime-liquidity-settlement:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn apply_settlement(
        &mut self,
        batch_id: &str,
        intent_ids: &[String],
        route: SettlementRoute,
        decision: SettlementDecision,
        settled_micro_units: u64,
    ) -> Result<()> {
        match decision {
            SettlementDecision::Approve
            | SettlementDecision::ApproveWithRebate
            | SettlementDecision::PartialFill => {
                if let Some(batch) = self.batches.get_mut(batch_id) {
                    batch.status = BatchStatus::Settled;
                }
                for intent_id in intent_ids {
                    if let Some(intent) = self.intents.get_mut(intent_id) {
                        intent.status = IntentStatus::Settled;
                    }
                }
                if let Some(source) = self.venues.get_mut(&route.source_venue_id) {
                    source.available_micro_units = source
                        .available_micro_units
                        .saturating_sub(settled_micro_units);
                }
                if let Some(target) = self.venues.get_mut(&route.target_venue_id) {
                    target.available_micro_units = target
                        .available_micro_units
                        .saturating_add(settled_micro_units);
                }
                self.counters.settled_batches = self.counters.settled_batches.saturating_add(1);
                self.counters.settled_intents = self
                    .counters
                    .settled_intents
                    .saturating_add(intent_ids.len() as u64);
                self.counters.netted_liquidity_micro_units = self
                    .counters
                    .netted_liquidity_micro_units
                    .saturating_add(settled_micro_units);
            }
            SettlementDecision::Quarantine | SettlementDecision::Reject => {
                if let Some(batch) = self.batches.get_mut(batch_id) {
                    batch.status = BatchStatus::Quarantined;
                }
                for intent_id in intent_ids {
                    if let Some(intent) = self.intents.get_mut(intent_id) {
                        intent.status = IntentStatus::Quarantined;
                    }
                }
                self.counters.quarantined_batches =
                    self.counters.quarantined_batches.saturating_add(1);
                self.counters.quarantined_intents = self
                    .counters
                    .quarantined_intents
                    .saturating_add(intent_ids.len() as u64);
            }
            SettlementDecision::Retry => {
                if let Some(batch) = self.batches.get_mut(batch_id) {
                    batch.status = BatchStatus::Sealed;
                }
            }
            SettlementDecision::Expire => {
                if let Some(batch) = self.batches.get_mut(batch_id) {
                    batch.status = BatchStatus::Expired;
                }
                for intent_id in intent_ids {
                    if let Some(intent) = self.intents.get_mut(intent_id) {
                        intent.status = IntentStatus::Expired;
                    }
                }
            }
        }
        Ok(())
    }

    fn ensure_batch_exists(&self, batch_id: &str) -> Result<()> {
        ensure_non_empty(batch_id, "batch_id")?;
        if !self.batches.contains_key(batch_id) {
            return Err(format!("batch not found: {batch_id}"));
        }
        Ok(())
    }

    fn ensure_venue_exists(&self, venue_id: &str) -> Result<()> {
        ensure_non_empty(venue_id, "venue_id")?;
        if !self.venues.contains_key(venue_id) {
            return Err(format!("venue not found: {venue_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let monero_bridge = state
        .register_venue(RegisterVenueRequest {
            domain: RuntimeDomain::MoneroBridge,
            venue_commitment: sample_hash("venue", 1),
            pq_verifying_key_root: sample_hash("venue-pq-key", 1),
            liquidity_root: sample_hash("liquidity", 1),
            bond_micro_units: DEFAULT_MIN_ROUTER_BOND_MICRO_UNITS * 3,
            available_micro_units: 250_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT,
        })
        .expect("devnet monero bridge venue registered");
    let token_router = state
        .register_venue(RegisterVenueRequest {
            domain: RuntimeDomain::TokenRouter,
            venue_commitment: sample_hash("venue", 2),
            pq_verifying_key_root: sample_hash("venue-pq-key", 2),
            liquidity_root: sample_hash("liquidity", 2),
            bond_micro_units: DEFAULT_MIN_ROUTER_BOND_MICRO_UNITS * 2,
            available_micro_units: 180_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet token router venue registered");
    let route = state
        .open_route(OpenRouteRequest {
            source_venue_id: monero_bridge.venue_id.clone(),
            target_venue_id: token_router.venue_id.clone(),
            sealed_route_root: sample_hash("sealed-route", 1),
            public_hint_root: sample_hash("public-hint", 1),
            liquidity_limit_micro_units: 75_000_000,
            fee_cap_bps: 14,
            price_impact_limit_bps: 90,
            opened_slot: DEVNET_SLOT + 2,
        })
        .expect("devnet route opened");
    let intent_a = state
        .submit_intent(SubmitIntentRequest {
            route_id: route.route_id.clone(),
            sender_commitment: sample_hash("sender", 1),
            sealed_intent_root: sample_hash("sealed-intent", 1),
            redacted_intent_root: sample_hash("redacted-intent", 1),
            amount_micro_units: 12_000_000,
            max_fee_bps: 12,
            max_price_impact_bps: 80,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 3,
        })
        .expect("devnet intent a submitted");
    let intent_b = state
        .submit_intent(SubmitIntentRequest {
            route_id: route.route_id.clone(),
            sender_commitment: sample_hash("sender", 2),
            sealed_intent_root: sample_hash("sealed-intent", 2),
            redacted_intent_root: sample_hash("redacted-intent", 2),
            amount_micro_units: 8_000_000,
            max_fee_bps: 12,
            max_price_impact_bps: 80,
            rebate_bps: 7,
            submitted_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet intent b submitted");
    let batch = state
        .build_netting_batch(BuildNettingBatchRequest {
            route_id: route.route_id.clone(),
            intent_ids: vec![intent_a.intent_id.clone(), intent_b.intent_id.clone()],
            sealed_batch_root: sample_hash("sealed-batch", 1),
            netted_liquidity_root: sample_hash("netted-liquidity", 1),
            fee_bps: 10,
            price_impact_bps: 45,
            risk_bps: 1_200,
            built_slot: DEVNET_SLOT + 8,
        })
        .expect("devnet netting batch built");
    state
        .record_attestation(RecordAttestationRequest {
            batch_id: batch.batch_id.clone(),
            venue_id: monero_bridge.venue_id,
            kind: AttestationKind::NettingEquationChecked,
            committee_root: sample_hash("committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 10,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet attestation recorded");
    state
        .settle_batch(SettleBatchRequest {
            batch_id: batch.batch_id.clone(),
            settlement_root: sample_hash("settlement", 1),
            decision: SettlementDecision::ApproveWithRebate,
            settled_slot: DEVNET_SLOT + 12,
        })
        .expect("devnet batch settled");
    state
        .issue_rebate(IssueRebateRequest {
            batch_id: batch.batch_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 1_000,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 13,
            expires_slot: DEVNET_SLOT + DEFAULT_BATCH_EXPIRY_SLOTS,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: batch.batch_id,
            public_fields: [
                "batch_id",
                "route_id",
                "intent_count",
                "net_amount_micro_units",
                "fee_bps",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "sender_commitment",
                "sealed_intent_root",
                "sealed_batch_root",
                "venue_commitment",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: 2_048,
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
    let lending = state
        .register_venue(RegisterVenueRequest {
            domain: RuntimeDomain::LendingPool,
            venue_commitment: sample_hash("venue", 3),
            pq_verifying_key_root: sample_hash("venue-pq-key", 3),
            liquidity_root: sample_hash("liquidity", 3),
            bond_micro_units: DEFAULT_MIN_ROUTER_BOND_MICRO_UNITS * 2,
            available_micro_units: 90_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 24,
        })
        .expect("demo lending venue registered");
    let fee_vault = state
        .register_venue(RegisterVenueRequest {
            domain: RuntimeDomain::FeeSponsorVault,
            venue_commitment: sample_hash("venue", 4),
            pq_verifying_key_root: sample_hash("venue-pq-key", 4),
            liquidity_root: sample_hash("liquidity", 4),
            bond_micro_units: DEFAULT_MIN_ROUTER_BOND_MICRO_UNITS,
            available_micro_units: 40_000_000,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            joined_slot: DEVNET_SLOT + 25,
        })
        .expect("demo fee vault venue registered");
    state
        .open_route(OpenRouteRequest {
            source_venue_id: lending.venue_id,
            target_venue_id: fee_vault.venue_id,
            sealed_route_root: sample_hash("sealed-route", 2),
            public_hint_root: sample_hash("public-hint", 2),
            liquidity_limit_micro_units: 25_000_000,
            fee_cap_bps: 8,
            price_impact_limit_bps: 50,
            opened_slot: DEVNET_SLOT + 26,
        })
        .expect("demo route opened");
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
        &format!("cross-runtime-liquidity-settlement:{domain}:id"),
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
        "cross-runtime-liquidity-settlement:devnet-sample",
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
