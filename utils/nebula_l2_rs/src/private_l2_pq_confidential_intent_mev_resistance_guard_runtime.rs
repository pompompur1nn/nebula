use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialIntentMevResistanceGuardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-intent-mev-resistance-guard-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_INTENT_MEV_RESISTANCE_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const INTENT_COMMITMENT_SUITE: &str = "threshold-encrypted-private-intent-root-v1";
pub const MEV_GUARD_SUITE: &str = "post-quantum-confidential-intent-mev-guard-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "intent-mev-guard-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-intent-redaction-budget-root-v1";
pub const DEVNET_EPOCH: u64 = 7_168;
pub const DEVNET_SLOT: u64 = 41;
pub const DEVNET_L2_HEIGHT: u64 = 2_780_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 180;
pub const DEFAULT_MAX_PRECONFIRMATION_MS: u64 = 700;
pub const DEFAULT_BATCH_WINDOW_SLOTS: u64 = 8;
pub const DEFAULT_INTENT_TTL_SLOTS: u64 = 64;
pub const DEFAULT_SOLVER_QUARANTINE_SLOTS: u64 = 512;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MIN_SOLVER_BOND_MICRO_UNITS: u64 = 10_000_000;
pub const DEFAULT_CONFLICT_RISK_LIMIT_BPS: u64 = 1_200;
pub const DEFAULT_BATCH_RISK_LIMIT_BPS: u64 = 2_500;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SOLVERS: usize = 262_144;
pub const MAX_INTENTS: usize = 2_097_152;
pub const MAX_BATCH_WINDOWS: usize = 524_288;
pub const MAX_CONFLICT_PROBES: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_PROTECTED_ROUTES: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_CONTRACTS_PER_INTENT: usize = 32;
pub const MAX_ASSETS_PER_INTENT: usize = 16;
pub const MAX_PROBES_PER_BATCH: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Swap,
    LimitOrder,
    LendingSupply,
    Borrow,
    Repay,
    LiquidationBackstop,
    CrossMarginRebalance,
    PerpetualsHedge,
    OptionsExercise,
    BridgeSettlement,
    TreasuryRebalance,
    EmergencyExit,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::LimitOrder => "limit_order",
            Self::LendingSupply => "lending_supply",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::CrossMarginRebalance => "cross_margin_rebalance",
            Self::PerpetualsHedge => "perpetuals_hedge",
            Self::OptionsExercise => "options_exercise",
            Self::BridgeSettlement => "bridge_settlement",
            Self::TreasuryRebalance => "treasury_rebalance",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn priority_weight_bps(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::BridgeSettlement => 9_800,
            Self::LiquidationBackstop => 9_500,
            Self::CrossMarginRebalance => 8_900,
            Self::PerpetualsHedge => 8_600,
            Self::OptionsExercise => 8_200,
            Self::TreasuryRebalance => 7_900,
            Self::Borrow => 7_600,
            Self::Repay => 7_400,
            Self::Swap => 7_100,
            Self::LimitOrder => 6_900,
            Self::LendingSupply => 6_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Batched,
    ConflictProbed,
    GuardAttested,
    RouteSealed,
    RebateIssued,
    Settled,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Candidate,
    Active,
    Throttled,
    Quarantined,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCapability {
    PrivateSwap,
    CrossContractRouting,
    LiquidationBackstop,
    OracleProtectedSettlement,
    BridgeRelay,
    ParallelExecution,
    LowFeeSponsorship,
    BatchAuction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    PriceDisplacement,
    SandwichRisk,
    BackrunLeakage,
    CrossContractConflict,
    OracleRace,
    BridgeQueueLeakage,
    SolverSelfDealing,
    FeeGriefing,
    PrivacySetRegression,
}

impl ConflictKind {
    pub fn base_risk_bps(self) -> u64 {
        match self {
            Self::PriceDisplacement => 1_100,
            Self::SandwichRisk => 2_400,
            Self::BackrunLeakage => 1_900,
            Self::CrossContractConflict => 1_600,
            Self::OracleRace => 2_200,
            Self::BridgeQueueLeakage => 1_450,
            Self::SolverSelfDealing => 3_000,
            Self::FeeGriefing => 1_250,
            Self::PrivacySetRegression => 2_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignatureVerified,
    BatchPrivacyFloor,
    ConflictProbeAccepted,
    SolverBondChecked,
    FeeCapObserved,
    RouteNonDisplacement,
    RedactionBudgetObserved,
    SettlementSafe,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardDecision {
    Accept,
    AcceptWithDelay,
    RequireMoreAttestations,
    Rebatch,
    QuarantineSolver,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub intent_commitment_suite: String,
    pub mev_guard_suite: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_preconfirmation_ms: u64,
    pub max_preconfirmation_ms: u64,
    pub batch_window_slots: u64,
    pub intent_ttl_slots: u64,
    pub solver_quarantine_slots: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_solver_bond_micro_units: u64,
    pub conflict_risk_limit_bps: u64,
    pub batch_risk_limit_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub operator_visibility_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            intent_commitment_suite: INTENT_COMMITMENT_SUITE.to_string(),
            mev_guard_suite: MEV_GUARD_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            max_preconfirmation_ms: DEFAULT_MAX_PRECONFIRMATION_MS,
            batch_window_slots: DEFAULT_BATCH_WINDOW_SLOTS,
            intent_ttl_slots: DEFAULT_INTENT_TTL_SLOTS,
            solver_quarantine_slots: DEFAULT_SOLVER_QUARANTINE_SLOTS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_solver_bond_micro_units: DEFAULT_MIN_SOLVER_BOND_MICRO_UNITS,
            conflict_risk_limit_bps: DEFAULT_CONFLICT_RISK_LIMIT_BPS,
            batch_risk_limit_bps: DEFAULT_BATCH_RISK_LIMIT_BPS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            operator_visibility_enabled: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.chain_id.trim().is_empty() {
            return Err("chain_id must be present".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set target must cover minimum".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime floor".to_string());
        }
        if self.max_preconfirmation_ms < self.target_preconfirmation_ms {
            return Err("max preconfirmation must be >= target".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.target_rebate_bps > MAX_BPS
            || self.conflict_risk_limit_bps > MAX_BPS
            || self.batch_risk_limit_bps > MAX_BPS
            || self.min_attestation_quorum_bps > MAX_BPS
            || self.strong_attestation_quorum_bps > MAX_BPS
        {
            return Err("bps fields must be <= 10000".to_string());
        }
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err("strong quorum must be >= minimum quorum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub solvers_registered: u64,
    pub intents_submitted: u64,
    pub batch_windows_opened: u64,
    pub conflict_probes_recorded: u64,
    pub guard_attestations_recorded: u64,
    pub protected_routes_sealed: u64,
    pub rebates_issued: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub solver_quarantines: u64,
    pub rejected_intents: u64,
    pub total_rebate_micro_units: u64,
    pub total_fee_cap_micro_units: u64,
    pub max_observed_conflict_risk_bps: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub state_root: String,
    pub config_root: String,
    pub solver_root: String,
    pub intent_root: String,
    pub batch_window_root: String,
    pub conflict_probe_root: String,
    pub attestation_root: String,
    pub protected_route_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverRecord {
    pub solver_id: String,
    pub operator_commitment: String,
    pub pq_key_commitment: String,
    pub status: SolverStatus,
    pub capabilities: BTreeSet<SolverCapability>,
    pub bond_micro_units: u64,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub accepted_privacy_floor: u64,
    pub success_count: u64,
    pub conflict_count: u64,
    pub quarantine_until_slot: Option<u64>,
    pub public_summary_root: String,
}

impl SolverRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "operator_commitment": self.operator_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "status": self.status,
            "capabilities": self.capabilities,
            "bond_micro_units": self.bond_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "target_latency_ms": self.target_latency_ms,
            "accepted_privacy_floor": self.accepted_privacy_floor,
            "success_count": self.success_count,
            "conflict_count": self.conflict_count,
            "quarantine_until_slot": self.quarantine_until_slot,
            "public_summary_root": self.public_summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntentEnvelope {
    pub intent_id: String,
    pub owner_commitment: String,
    pub kind: IntentKind,
    pub status: IntentStatus,
    pub encrypted_intent_root: String,
    pub nullifier_root: String,
    pub target_contracts: Vec<String>,
    pub asset_commitments: Vec<String>,
    pub route_hint_root: String,
    pub max_fee_micro_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub batch_id: Option<String>,
    pub protected_route_id: Option<String>,
    pub guard_decision: GuardDecision,
    pub public_summary_root: String,
}

impl IntentEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "kind": self.kind,
            "status": self.status,
            "target_contract_count": self.target_contracts.len(),
            "asset_commitment_count": self.asset_commitments.len(),
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "submitted_slot": self.submitted_slot,
            "expires_slot": self.expires_slot,
            "batch_id": self.batch_id,
            "protected_route_id": self.protected_route_id,
            "guard_decision": self.guard_decision,
            "encrypted_intent_root": self.encrypted_intent_root,
            "nullifier_root": self.nullifier_root,
            "route_hint_root": self.route_hint_root,
            "public_summary_root": self.public_summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchWindow {
    pub batch_id: String,
    pub opened_slot: u64,
    pub closes_slot: u64,
    pub max_preconfirmation_ms: u64,
    pub solver_allowlist_root: String,
    pub intent_ids: Vec<String>,
    pub aggregate_privacy_set_size: u64,
    pub aggregate_fee_cap_micro_units: u64,
    pub aggregate_conflict_risk_bps: u64,
    pub batch_commitment_root: String,
    pub status_root: String,
}

impl BatchWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "opened_slot": self.opened_slot,
            "closes_slot": self.closes_slot,
            "max_preconfirmation_ms": self.max_preconfirmation_ms,
            "solver_allowlist_root": self.solver_allowlist_root,
            "intent_count": self.intent_ids.len(),
            "aggregate_privacy_set_size": self.aggregate_privacy_set_size,
            "aggregate_fee_cap_micro_units": self.aggregate_fee_cap_micro_units,
            "aggregate_conflict_risk_bps": self.aggregate_conflict_risk_bps,
            "batch_commitment_root": self.batch_commitment_root,
            "status_root": self.status_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConflictProbe {
    pub probe_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub kind: ConflictKind,
    pub encrypted_probe_root: String,
    pub redacted_evidence_root: String,
    pub observed_slot: u64,
    pub risk_bps: u64,
    pub suggested_delay_slots: u64,
    pub decision: GuardDecision,
    pub public_summary_root: String,
}

impl ConflictProbe {
    pub fn public_record(&self) -> Value {
        json!({
            "probe_id": self.probe_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "solver_id": self.solver_id,
            "kind": self.kind,
            "redacted_evidence_root": self.redacted_evidence_root,
            "observed_slot": self.observed_slot,
            "risk_bps": self.risk_bps,
            "suggested_delay_slots": self.suggested_delay_slots,
            "decision": self.decision,
            "public_summary_root": self.public_summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardAttestation {
    pub attestation_id: String,
    pub target_id: String,
    pub attester_commitment: String,
    pub kind: AttestationKind,
    pub pq_signature_commitment: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub quorum_weight_bps: u64,
    pub accepted: bool,
    pub observed_slot: u64,
}

impl GuardAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "target_id": self.target_id,
            "kind": self.kind,
            "security_bits": self.security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "accepted": self.accepted,
            "observed_slot": self.observed_slot,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtectedRoute {
    pub route_id: String,
    pub batch_id: String,
    pub solver_id: String,
    pub intent_ids: Vec<String>,
    pub sealed_route_root: String,
    pub preconfirmation_receipt_root: String,
    pub settlement_plan_root: String,
    pub route_privacy_set_size: u64,
    pub effective_fee_bps: u64,
    pub effective_fee_micro_units: u64,
    pub conflict_risk_bps: u64,
    pub attestation_quorum_bps: u64,
    pub sealed_slot: u64,
    pub expires_slot: u64,
}

impl ProtectedRoute {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "batch_id": self.batch_id,
            "solver_id": self.solver_id,
            "intent_count": self.intent_ids.len(),
            "sealed_route_root": self.sealed_route_root,
            "preconfirmation_receipt_root": self.preconfirmation_receipt_root,
            "settlement_plan_root": self.settlement_plan_root,
            "route_privacy_set_size": self.route_privacy_set_size,
            "effective_fee_bps": self.effective_fee_bps,
            "effective_fee_micro_units": self.effective_fee_micro_units,
            "conflict_risk_bps": self.conflict_risk_bps,
            "attestation_quorum_bps": self.attestation_quorum_bps,
            "sealed_slot": self.sealed_slot,
            "expires_slot": self.expires_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub route_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

impl RebateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "route_id": self.route_id,
            "asset_id": self.asset_id,
            "sponsor_pool_root": self.sponsor_pool_root,
            "beneficiary_group_root": self.beneficiary_group_root,
            "amount_micro_units": self.amount_micro_units,
            "fee_rebate_bps": self.fee_rebate_bps,
            "issued_slot": self.issued_slot,
            "expires_slot": self.expires_slot,
        })
    }
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
    pub budget_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "target_id": self.target_id,
            "public_fields": self.public_fields,
            "redacted_field_count": self.redacted_fields.len(),
            "max_public_bytes": self.max_public_bytes,
            "actual_public_bytes": self.actual_public_bytes,
            "privacy_set_size": self.privacy_set_size,
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub batch_id: String,
    pub protected_route_count: u64,
    pub rejected_intent_count: u64,
    pub max_conflict_risk_bps: u64,
    pub median_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub attestation_quorum_bps: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "batch_id": self.batch_id,
            "protected_route_count": self.protected_route_count,
            "rejected_intent_count": self.rejected_intent_count,
            "max_conflict_risk_bps": self.max_conflict_risk_bps,
            "median_fee_bps": self.median_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "attestation_quorum_bps": self.attestation_quorum_bps,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSolverRequest {
    pub operator_commitment: String,
    pub pq_key_commitment: String,
    pub capabilities: BTreeSet<SolverCapability>,
    pub bond_micro_units: u64,
    pub max_fee_bps: u64,
    pub target_latency_ms: u64,
    pub accepted_privacy_floor: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitIntentRequest {
    pub owner_commitment: String,
    pub kind: IntentKind,
    pub encrypted_intent_root: String,
    pub nullifier_root: String,
    pub target_contracts: Vec<String>,
    pub asset_commitments: Vec<String>,
    pub route_hint_root: String,
    pub max_fee_micro_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenBatchWindowRequest {
    pub opened_slot: u64,
    pub solver_allowlist_root: String,
    pub intent_ids: Vec<String>,
    pub max_preconfirmation_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConflictProbeRequest {
    pub batch_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub kind: ConflictKind,
    pub encrypted_probe_root: String,
    pub redacted_evidence_root: String,
    pub observed_slot: u64,
    pub risk_bps: u64,
    pub suggested_delay_slots: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardAttestationRequest {
    pub target_id: String,
    pub attester_commitment: String,
    pub kind: AttestationKind,
    pub pq_signature_commitment: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub quorum_weight_bps: u64,
    pub observed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealProtectedRouteRequest {
    pub batch_id: String,
    pub solver_id: String,
    pub intent_ids: Vec<String>,
    pub sealed_route_root: String,
    pub preconfirmation_receipt_root: String,
    pub settlement_plan_root: String,
    pub route_privacy_set_size: u64,
    pub effective_fee_bps: u64,
    pub effective_fee_micro_units: u64,
    pub conflict_risk_bps: u64,
    pub sealed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub route_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
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
    pub batch_id: String,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub protocol_version: String,
    pub schema_version: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub config_root: String,
    pub active_solver_count: usize,
    pub open_intent_count: usize,
    pub batch_window_count: usize,
    pub protected_route_count: usize,
    pub operator_summary_count: usize,
    pub sample_solvers: Vec<Value>,
    pub sample_intents: Vec<Value>,
    pub sample_batches: Vec<Value>,
    pub sample_routes: Vec<Value>,
    pub sample_summaries: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub solvers: BTreeMap<String, SolverRecord>,
    pub intents: BTreeMap<String, IntentEnvelope>,
    pub batch_windows: BTreeMap<String, BatchWindow>,
    pub conflict_probes: BTreeMap<String, ConflictProbe>,
    pub guard_attestations: BTreeMap<String, GuardAttestation>,
    pub protected_routes: BTreeMap<String, ProtectedRoute>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            solvers: BTreeMap::new(),
            intents: BTreeMap::new(),
            batch_windows: BTreeMap::new(),
            conflict_probes: BTreeMap::new(),
            guard_attestations: BTreeMap::new(),
            protected_routes: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn register_solver(&mut self, request: RegisterSolverRequest) -> Result<SolverRecord> {
        self.ensure_capacity("solvers", self.solvers.len(), MAX_SOLVERS)?;
        self.ensure_fee_bps(request.max_fee_bps)?;
        self.ensure_privacy(request.accepted_privacy_floor)?;
        if request.bond_micro_units < self.config.min_solver_bond_micro_units {
            return Err("solver bond below runtime floor".to_string());
        }
        if request.capabilities.is_empty() {
            return Err("solver capabilities must not be empty".to_string());
        }
        let capabilities_value = serde_json::to_value(&request.capabilities)
            .map_err(|err| format!("capabilities serialization failed: {err}"))?;
        let solver_id = stable_id(
            "solver",
            &[
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(&request.pq_key_commitment),
                HashPart::Json(&capabilities_value),
            ],
        );
        let public_summary_root = domain_hash(
            "intent-mev-guard:solver-public-summary-root",
            &[
                HashPart::Str(&solver_id),
                HashPart::U64(request.bond_micro_units),
                HashPart::U64(request.max_fee_bps),
                HashPart::U64(request.accepted_privacy_floor),
            ],
            32,
        );
        let record = SolverRecord {
            solver_id: solver_id.clone(),
            operator_commitment: request.operator_commitment,
            pq_key_commitment: request.pq_key_commitment,
            status: SolverStatus::Active,
            capabilities: request.capabilities,
            bond_micro_units: request.bond_micro_units,
            max_fee_bps: request.max_fee_bps,
            target_latency_ms: request.target_latency_ms,
            accepted_privacy_floor: request.accepted_privacy_floor,
            success_count: 0,
            conflict_count: 0,
            quarantine_until_slot: None,
            public_summary_root,
        };
        self.solvers.insert(solver_id, record.clone());
        self.counters.solvers_registered += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn submit_intent(&mut self, request: SubmitIntentRequest) -> Result<IntentEnvelope> {
        self.ensure_capacity("intents", self.intents.len(), MAX_INTENTS)?;
        self.ensure_fee_bps(request.max_fee_bps)?;
        self.ensure_privacy(request.privacy_set_size)?;
        self.ensure_contracts(&request.target_contracts)?;
        self.ensure_assets(&request.asset_commitments)?;
        let target_contracts_value = serde_json::to_value(&request.target_contracts)
            .map_err(|err| format!("contract serialization failed: {err}"))?;
        let asset_commitments_value = serde_json::to_value(&request.asset_commitments)
            .map_err(|err| format!("asset serialization failed: {err}"))?;
        let intent_id = stable_id(
            "intent",
            &[
                HashPart::Str(&request.owner_commitment),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.encrypted_intent_root),
                HashPart::Str(&request.nullifier_root),
                HashPart::Json(&target_contracts_value),
                HashPart::Json(&asset_commitments_value),
                HashPart::U64(request.submitted_slot),
            ],
        );
        let public_summary_root = domain_hash(
            "intent-mev-guard:intent-public-summary-root",
            &[
                HashPart::Str(&intent_id),
                HashPart::U64(request.max_fee_micro_units),
                HashPart::U64(request.max_fee_bps),
                HashPart::U64(request.privacy_set_size),
            ],
            32,
        );
        let record = IntentEnvelope {
            intent_id: intent_id.clone(),
            owner_commitment: request.owner_commitment,
            kind: request.kind,
            status: IntentStatus::Submitted,
            encrypted_intent_root: request.encrypted_intent_root,
            nullifier_root: request.nullifier_root,
            target_contracts: request.target_contracts,
            asset_commitments: request.asset_commitments,
            route_hint_root: request.route_hint_root,
            max_fee_micro_units: request.max_fee_micro_units,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            submitted_slot: request.submitted_slot,
            expires_slot: request
                .submitted_slot
                .saturating_add(self.config.intent_ttl_slots),
            batch_id: None,
            protected_route_id: None,
            guard_decision: GuardDecision::RequireMoreAttestations,
            public_summary_root,
        };
        self.counters.total_fee_cap_micro_units = self
            .counters
            .total_fee_cap_micro_units
            .saturating_add(record.max_fee_micro_units);
        self.intents.insert(intent_id, record.clone());
        self.counters.intents_submitted += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_batch_window(&mut self, request: OpenBatchWindowRequest) -> Result<BatchWindow> {
        self.ensure_capacity("batch_windows", self.batch_windows.len(), MAX_BATCH_WINDOWS)?;
        if request.intent_ids.is_empty() {
            return Err("batch window requires at least one intent".to_string());
        }
        if request.max_preconfirmation_ms > self.config.max_preconfirmation_ms {
            return Err("batch preconfirmation exceeds runtime max".to_string());
        }
        let mut aggregate_privacy_set_size = u64::MAX;
        let mut aggregate_fee_cap_micro_units = 0_u64;
        let mut priority_sum = 0_u64;
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown intent_id {intent_id}"))?;
            aggregate_privacy_set_size = aggregate_privacy_set_size.min(intent.privacy_set_size);
            aggregate_fee_cap_micro_units =
                aggregate_fee_cap_micro_units.saturating_add(intent.max_fee_micro_units);
            priority_sum = priority_sum.saturating_add(intent.kind.priority_weight_bps());
        }
        let intent_ids_value = serde_json::to_value(&request.intent_ids)
            .map_err(|err| format!("intent_ids serialization failed: {err}"))?;
        let batch_id = stable_id(
            "batch-window",
            &[
                HashPart::U64(request.opened_slot),
                HashPart::Str(&request.solver_allowlist_root),
                HashPart::Json(&intent_ids_value),
            ],
        );
        let aggregate_conflict_risk_bps =
            estimated_batch_risk(priority_sum, request.intent_ids.len() as u64);
        if aggregate_conflict_risk_bps > self.config.batch_risk_limit_bps {
            return Err("batch aggregate conflict risk exceeds runtime limit".to_string());
        }
        let batch_commitment_root = domain_hash(
            "intent-mev-guard:batch-commitment-root",
            &[
                HashPart::Str(&batch_id),
                HashPart::Json(&intent_ids_value),
                HashPart::U64(aggregate_fee_cap_micro_units),
                HashPart::U64(aggregate_conflict_risk_bps),
            ],
            32,
        );
        let status_root = domain_hash(
            "intent-mev-guard:batch-status-root",
            &[
                HashPart::Str(&batch_id),
                HashPart::U64(request.opened_slot),
                HashPart::U64(request.max_preconfirmation_ms),
            ],
            32,
        );
        let record = BatchWindow {
            batch_id: batch_id.clone(),
            opened_slot: request.opened_slot,
            closes_slot: request
                .opened_slot
                .saturating_add(self.config.batch_window_slots),
            max_preconfirmation_ms: request.max_preconfirmation_ms,
            solver_allowlist_root: request.solver_allowlist_root,
            intent_ids: request.intent_ids,
            aggregate_privacy_set_size,
            aggregate_fee_cap_micro_units,
            aggregate_conflict_risk_bps,
            batch_commitment_root,
            status_root,
        };
        for intent_id in &record.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Batched;
                intent.batch_id = Some(batch_id.clone());
            }
        }
        self.batch_windows.insert(batch_id, record.clone());
        self.counters.batch_windows_opened += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_conflict_probe(
        &mut self,
        request: ConflictProbeRequest,
    ) -> Result<ConflictProbe> {
        self.ensure_capacity(
            "conflict_probes",
            self.conflict_probes.len(),
            MAX_CONFLICT_PROBES,
        )?;
        self.ensure_batch(&request.batch_id)?;
        self.ensure_solver_active(&request.solver_id, request.observed_slot)?;
        if !self.intents.contains_key(&request.intent_id) {
            return Err(format!("unknown intent_id {}", request.intent_id));
        }
        let risk_bps = request
            .risk_bps
            .saturating_add(request.kind.base_risk_bps() / 4)
            .min(MAX_BPS);
        let decision = if risk_bps > self.config.conflict_risk_limit_bps.saturating_mul(2) {
            GuardDecision::Reject
        } else if risk_bps > self.config.conflict_risk_limit_bps {
            GuardDecision::AcceptWithDelay
        } else {
            GuardDecision::Accept
        };
        let probe_id = stable_id(
            "conflict-probe",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.intent_id),
                HashPart::Str(&request.solver_id),
                HashPart::Str(conflict_kind_str(request.kind)),
                HashPart::U64(request.observed_slot),
                HashPart::U64(risk_bps),
            ],
        );
        let public_summary_root = domain_hash(
            "intent-mev-guard:conflict-probe-public-summary-root",
            &[
                HashPart::Str(&probe_id),
                HashPart::U64(risk_bps),
                HashPart::U64(request.suggested_delay_slots),
                HashPart::Str(guard_decision_str(decision)),
            ],
            32,
        );
        let record = ConflictProbe {
            probe_id: probe_id.clone(),
            batch_id: request.batch_id.clone(),
            intent_id: request.intent_id.clone(),
            solver_id: request.solver_id.clone(),
            kind: request.kind,
            encrypted_probe_root: request.encrypted_probe_root,
            redacted_evidence_root: request.redacted_evidence_root,
            observed_slot: request.observed_slot,
            risk_bps,
            suggested_delay_slots: request.suggested_delay_slots,
            decision,
            public_summary_root,
        };
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::ConflictProbed;
            intent.guard_decision = decision;
            if decision == GuardDecision::Reject {
                intent.status = IntentStatus::Rejected;
                self.counters.rejected_intents += 1;
            }
        }
        if let Some(solver) = self.solvers.get_mut(&request.solver_id) {
            solver.conflict_count = solver.conflict_count.saturating_add(1);
            if decision == GuardDecision::Reject {
                solver.status = SolverStatus::Throttled;
            }
        }
        self.counters.max_observed_conflict_risk_bps =
            self.counters.max_observed_conflict_risk_bps.max(risk_bps);
        self.conflict_probes.insert(probe_id, record.clone());
        self.counters.conflict_probes_recorded += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_attestation(
        &mut self,
        request: GuardAttestationRequest,
    ) -> Result<GuardAttestation> {
        self.ensure_capacity(
            "guard_attestations",
            self.guard_attestations.len(),
            MAX_ATTESTATIONS,
        )?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("attestation below pq security floor".to_string());
        }
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        let accepted = request.quorum_weight_bps >= self.config.min_attestation_quorum_bps;
        let attestation_id = stable_id(
            "guard-attestation",
            &[
                HashPart::Str(&request.target_id),
                HashPart::Str(&request.attester_commitment),
                HashPart::Str(attestation_kind_str(request.kind)),
                HashPart::Str(&request.pq_signature_commitment),
                HashPart::U64(request.observed_slot),
            ],
        );
        let record = GuardAttestation {
            attestation_id: attestation_id.clone(),
            target_id: request.target_id.clone(),
            attester_commitment: request.attester_commitment,
            kind: request.kind,
            pq_signature_commitment: request.pq_signature_commitment,
            transcript_root: request.transcript_root,
            security_bits: request.security_bits,
            quorum_weight_bps: request.quorum_weight_bps,
            accepted,
            observed_slot: request.observed_slot,
        };
        if accepted {
            if let Some(intent) = self.intents.get_mut(&request.target_id) {
                intent.status = IntentStatus::GuardAttested;
            }
        }
        self.guard_attestations
            .insert(attestation_id, record.clone());
        self.counters.guard_attestations_recorded += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn seal_protected_route(
        &mut self,
        request: SealProtectedRouteRequest,
    ) -> Result<ProtectedRoute> {
        self.ensure_capacity(
            "protected_routes",
            self.protected_routes.len(),
            MAX_PROTECTED_ROUTES,
        )?;
        self.ensure_batch(&request.batch_id)?;
        self.ensure_solver_active(&request.solver_id, request.sealed_slot)?;
        self.ensure_fee_bps(request.effective_fee_bps)?;
        self.ensure_privacy(request.route_privacy_set_size)?;
        if request.conflict_risk_bps > self.config.conflict_risk_limit_bps {
            return Err("protected route conflict risk exceeds guard limit".to_string());
        }
        let attestation_quorum_bps = self.attestation_quorum_for(&request.batch_id);
        if attestation_quorum_bps < self.config.min_attestation_quorum_bps {
            return Err("route lacks sufficient guard attestations".to_string());
        }
        for intent_id in &request.intent_ids {
            if !self.intents.contains_key(intent_id) {
                return Err(format!("unknown intent_id {intent_id}"));
            }
        }
        let intent_ids_value = serde_json::to_value(&request.intent_ids)
            .map_err(|err| format!("intent_ids serialization failed: {err}"))?;
        let route_id = stable_id(
            "protected-route",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.solver_id),
                HashPart::Json(&intent_ids_value),
                HashPart::Str(&request.sealed_route_root),
                HashPart::U64(request.sealed_slot),
            ],
        );
        let record = ProtectedRoute {
            route_id: route_id.clone(),
            batch_id: request.batch_id,
            solver_id: request.solver_id.clone(),
            intent_ids: request.intent_ids,
            sealed_route_root: request.sealed_route_root,
            preconfirmation_receipt_root: request.preconfirmation_receipt_root,
            settlement_plan_root: request.settlement_plan_root,
            route_privacy_set_size: request.route_privacy_set_size,
            effective_fee_bps: request.effective_fee_bps,
            effective_fee_micro_units: request.effective_fee_micro_units,
            conflict_risk_bps: request.conflict_risk_bps,
            attestation_quorum_bps,
            sealed_slot: request.sealed_slot,
            expires_slot: request
                .sealed_slot
                .saturating_add(self.config.intent_ttl_slots),
        };
        for intent_id in &record.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::RouteSealed;
                intent.protected_route_id = Some(route_id.clone());
                intent.guard_decision = GuardDecision::Accept;
            }
        }
        if let Some(solver) = self.solvers.get_mut(&request.solver_id) {
            solver.success_count = solver.success_count.saturating_add(1);
        }
        self.protected_routes.insert(route_id, record.clone());
        self.counters.protected_routes_sealed += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        self.ensure_capacity("rebates", self.rebates.len(), MAX_REBATES)?;
        self.ensure_fee_bps(request.fee_rebate_bps)?;
        let route = self
            .protected_routes
            .get(&request.route_id)
            .ok_or_else(|| format!("unknown route_id {}", request.route_id))?;
        if request.fee_rebate_bps < self.config.target_rebate_bps {
            return Err("rebate below configured target".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.route_id),
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.amount_micro_units),
                HashPart::U64(request.issued_slot),
            ],
        );
        let record = RebateReceipt {
            rebate_id: rebate_id.clone(),
            route_id: request.route_id.clone(),
            asset_id: request.asset_id,
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        for intent_id in &route.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::RebateIssued;
            }
        }
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(record.amount_micro_units);
        self.rebates.insert(rebate_id, record.clone());
        self.counters.rebates_issued += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn publish_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        self.ensure_capacity(
            "redaction_budgets",
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
        )?;
        self.ensure_privacy(request.privacy_set_size)?;
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("redaction budget exceeded".to_string());
        }
        let public_fields_value = serde_json::to_value(&request.public_fields)
            .map_err(|err| format!("public field serialization failed: {err}"))?;
        let redacted_fields_value = serde_json::to_value(&request.redacted_fields)
            .map_err(|err| format!("redacted field serialization failed: {err}"))?;
        let budget_id = stable_id(
            "redaction-budget",
            &[
                HashPart::Str(&request.target_id),
                HashPart::Json(&public_fields_value),
                HashPart::Json(&redacted_fields_value),
                HashPart::U64(request.actual_public_bytes),
            ],
        );
        let budget_root = domain_hash(
            REDACTION_SUITE,
            &[
                HashPart::Str(&budget_id),
                HashPart::U64(request.max_public_bytes),
                HashPart::U64(request.actual_public_bytes),
                HashPart::U64(request.privacy_set_size),
            ],
            32,
        );
        let record = RedactionBudget {
            budget_id: budget_id.clone(),
            target_id: request.target_id,
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
            budget_root,
        };
        self.redaction_budgets.insert(budget_id, record.clone());
        self.counters.redaction_budgets_published += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        self.ensure_capacity(
            "operator_summaries",
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
        )?;
        self.ensure_batch(&request.batch_id)?;
        self.ensure_fee_bps(request.median_fee_bps)?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let routes = self
            .protected_routes
            .values()
            .filter(|route| route.batch_id == request.batch_id)
            .collect::<Vec<_>>();
        let protected_route_count = routes.len() as u64;
        let max_conflict_risk_bps = routes
            .iter()
            .map(|route| route.conflict_risk_bps)
            .max()
            .unwrap_or(0);
        let min_privacy_set_size = routes
            .iter()
            .map(|route| route.route_privacy_set_size)
            .min()
            .unwrap_or(self.config.target_privacy_set_size);
        let rejected_intent_count = self
            .intents
            .values()
            .filter(|intent| {
                intent.batch_id.as_deref() == Some(request.batch_id.as_str())
                    && intent.status == IntentStatus::Rejected
            })
            .count() as u64;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::U64(protected_route_count),
                HashPart::U64(rejected_intent_count),
                HashPart::U64(max_conflict_risk_bps),
                HashPart::U64(request.median_fee_bps),
            ],
        );
        let summary_root = domain_hash(
            "intent-mev-guard:operator-summary-root",
            &[
                HashPart::Str(&summary_id),
                HashPart::U64(protected_route_count),
                HashPart::U64(rejected_intent_count),
                HashPart::U64(max_conflict_risk_bps),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(request.attestation_quorum_bps),
            ],
            32,
        );
        let record = OperatorSummary {
            summary_id: summary_id.clone(),
            batch_id: request.batch_id,
            protected_route_count,
            rejected_intent_count,
            max_conflict_risk_bps,
            median_fee_bps: request.median_fee_bps,
            min_privacy_set_size,
            attestation_quorum_bps: request.attestation_quorum_bps,
            summary_root,
        };
        self.operator_summaries.insert(summary_id, record.clone());
        self.counters.operator_summaries_published += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn quarantine_solver(
        &mut self,
        solver_id: &str,
        observed_slot: u64,
        evidence_root: &str,
    ) -> Result<()> {
        let solver = self
            .solvers
            .get_mut(solver_id)
            .ok_or_else(|| format!("unknown solver_id {solver_id}"))?;
        solver.status = SolverStatus::Quarantined;
        solver.quarantine_until_slot =
            Some(observed_slot.saturating_add(self.config.solver_quarantine_slots));
        solver.public_summary_root = domain_hash(
            "intent-mev-guard:solver-quarantine-summary-root",
            &[
                HashPart::Str(solver_id),
                HashPart::Str(evidence_root),
                HashPart::U64(observed_slot),
            ],
            32,
        );
        self.counters.solver_quarantines += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        let config_value = serde_json::to_value(&self.config)
            .unwrap_or_else(|_| json!({ "config": "serialization-error" }));
        self.roots.config_root = domain_hash(
            "intent-mev-guard:config-root",
            &[HashPart::Json(&config_value)],
            32,
        );
        self.roots.solver_root = map_root("intent-mev-guard:solver-root", &self.solvers);
        self.roots.intent_root = map_root("intent-mev-guard:intent-root", &self.intents);
        self.roots.batch_window_root =
            map_root("intent-mev-guard:batch-window-root", &self.batch_windows);
        self.roots.conflict_probe_root = map_root(
            "intent-mev-guard:conflict-probe-root",
            &self.conflict_probes,
        );
        self.roots.attestation_root = map_root(
            "intent-mev-guard:attestation-root",
            &self.guard_attestations,
        );
        self.roots.protected_route_root = map_root(
            "intent-mev-guard:protected-route-root",
            &self.protected_routes,
        );
        self.roots.rebate_root = map_root("intent-mev-guard:rebate-root", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "intent-mev-guard:redaction-budget-root",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "intent-mev-guard:operator-summary-root",
            &self.operator_summaries,
        );
        self.roots.state_root = domain_hash(
            "intent-mev-guard:state-root",
            &[
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.solver_root),
                HashPart::Str(&self.roots.intent_root),
                HashPart::Str(&self.roots.batch_window_root),
                HashPart::Str(&self.roots.conflict_probe_root),
                HashPart::Str(&self.roots.attestation_root),
                HashPart::Str(&self.roots.protected_route_root),
                HashPart::Str(&self.roots.rebate_root),
                HashPart::Str(&self.roots.redaction_budget_root),
                HashPart::Str(&self.roots.operator_summary_root),
            ],
            32,
        );
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord {
            protocol_version: self.config.protocol_version.clone(),
            schema_version: SCHEMA_VERSION,
            roots: self.roots.clone(),
            counters: self.counters.clone(),
            config_root: self.roots.config_root.clone(),
            active_solver_count: self
                .solvers
                .values()
                .filter(|solver| solver.status == SolverStatus::Active)
                .count(),
            open_intent_count: self
                .intents
                .values()
                .filter(|intent| {
                    matches!(
                        intent.status,
                        IntentStatus::Submitted
                            | IntentStatus::Batched
                            | IntentStatus::ConflictProbed
                            | IntentStatus::GuardAttested
                    )
                })
                .count(),
            batch_window_count: self.batch_windows.len(),
            protected_route_count: self.protected_routes.len(),
            operator_summary_count: self.operator_summaries.len(),
            sample_solvers: self
                .solvers
                .values()
                .take(8)
                .map(SolverRecord::public_record)
                .collect(),
            sample_intents: self
                .intents
                .values()
                .take(8)
                .map(IntentEnvelope::public_record)
                .collect(),
            sample_batches: self
                .batch_windows
                .values()
                .take(8)
                .map(BatchWindow::public_record)
                .collect(),
            sample_routes: self
                .protected_routes
                .values()
                .take(8)
                .map(ProtectedRoute::public_record)
                .collect(),
            sample_summaries: self
                .operator_summaries
                .values()
                .take(8)
                .map(OperatorSummary::public_record)
                .collect(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn ensure_capacity(&self, name: &str, len: usize, max: usize) -> Result<()> {
        if len >= max {
            return Err(format!("{name} capacity reached"));
        }
        Ok(())
    }

    fn ensure_fee_bps(&self, fee_bps: u64) -> Result<()> {
        if fee_bps > self.config.max_user_fee_bps
            && fee_bps != self.config.min_attestation_quorum_bps
        {
            return Err("fee bps exceeds guard cap".to_string());
        }
        Ok(())
    }

    fn ensure_privacy(&self, privacy_set_size: u64) -> Result<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below guard floor".to_string());
        }
        Ok(())
    }

    fn ensure_contracts(&self, contracts: &[String]) -> Result<()> {
        if contracts.is_empty() {
            return Err("intent must target at least one contract".to_string());
        }
        if contracts.len() > MAX_CONTRACTS_PER_INTENT {
            return Err("too many target contracts".to_string());
        }
        Ok(())
    }

    fn ensure_assets(&self, assets: &[String]) -> Result<()> {
        if assets.is_empty() {
            return Err("intent must include at least one asset commitment".to_string());
        }
        if assets.len() > MAX_ASSETS_PER_INTENT {
            return Err("too many asset commitments".to_string());
        }
        Ok(())
    }

    fn ensure_batch(&self, batch_id: &str) -> Result<()> {
        if !self.batch_windows.contains_key(batch_id) {
            return Err(format!("unknown batch_id {batch_id}"));
        }
        Ok(())
    }

    fn ensure_solver_active(&self, solver_id: &str, current_slot: u64) -> Result<()> {
        let solver = self
            .solvers
            .get(solver_id)
            .ok_or_else(|| format!("unknown solver_id {solver_id}"))?;
        match solver.status {
            SolverStatus::Active | SolverStatus::Candidate => {}
            SolverStatus::Quarantined => match solver.quarantine_until_slot {
                Some(until) if until <= current_slot => {}
                _ => return Err("solver remains quarantined".to_string()),
            },
            _ => return Err("solver is not eligible for guard work".to_string()),
        }
        Ok(())
    }

    fn attestation_quorum_for(&self, target_id: &str) -> u64 {
        self.guard_attestations
            .values()
            .filter(|attestation| attestation.target_id == target_id && attestation.accepted)
            .map(|attestation| attestation.quorum_weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default()).expect("intent mev guard config is valid");
    let mut capabilities = BTreeSet::new();
    capabilities.insert(SolverCapability::PrivateSwap);
    capabilities.insert(SolverCapability::CrossContractRouting);
    capabilities.insert(SolverCapability::LowFeeSponsorship);
    capabilities.insert(SolverCapability::ParallelExecution);
    let solver = state
        .register_solver(RegisterSolverRequest {
            operator_commitment: sample_hash("operator", 1),
            pq_key_commitment: sample_hash("pq-key", 1),
            capabilities,
            bond_micro_units: DEFAULT_MIN_SOLVER_BOND_MICRO_UNITS.saturating_mul(2),
            max_fee_bps: 8,
            target_latency_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            accepted_privacy_floor: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet solver registered");
    let intent = state
        .submit_intent(SubmitIntentRequest {
            owner_commitment: sample_hash("owner", 1),
            kind: IntentKind::Swap,
            encrypted_intent_root: sample_hash("intent-root", 1),
            nullifier_root: sample_hash("nullifier", 1),
            target_contracts: vec![
                "confidential-amm.devnet".to_string(),
                "private-fee-router.devnet".to_string(),
            ],
            asset_commitments: vec![sample_hash("asset", 1), sample_hash("asset", 2)],
            route_hint_root: sample_hash("route-hint", 1),
            max_fee_micro_units: 7_500,
            max_fee_bps: 8,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT,
        })
        .expect("devnet intent submitted");
    let batch = state
        .open_batch_window(OpenBatchWindowRequest {
            opened_slot: DEVNET_SLOT + 1,
            solver_allowlist_root: sample_hash("solver-allowlist", 1),
            intent_ids: vec![intent.intent_id.clone()],
            max_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
        })
        .expect("devnet batch opened");
    state
        .record_conflict_probe(ConflictProbeRequest {
            batch_id: batch.batch_id.clone(),
            intent_id: intent.intent_id.clone(),
            solver_id: solver.solver_id.clone(),
            kind: ConflictKind::PriceDisplacement,
            encrypted_probe_root: sample_hash("encrypted-probe", 1),
            redacted_evidence_root: sample_hash("redacted-evidence", 1),
            observed_slot: DEVNET_SLOT + 2,
            risk_bps: 400,
            suggested_delay_slots: 0,
        })
        .expect("devnet conflict probe recorded");
    state
        .record_attestation(GuardAttestationRequest {
            target_id: batch.batch_id.clone(),
            attester_commitment: sample_hash("attester", 1),
            kind: AttestationKind::ConflictProbeAccepted,
            pq_signature_commitment: sample_hash("pq-signature", 1),
            transcript_root: sample_hash("transcript", 1),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            observed_slot: DEVNET_SLOT + 3,
        })
        .expect("devnet attestation recorded");
    let route = state
        .seal_protected_route(SealProtectedRouteRequest {
            batch_id: batch.batch_id.clone(),
            solver_id: solver.solver_id,
            intent_ids: vec![intent.intent_id],
            sealed_route_root: sample_hash("sealed-route", 1),
            preconfirmation_receipt_root: sample_hash("preconfirmation", 1),
            settlement_plan_root: sample_hash("settlement-plan", 1),
            route_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            effective_fee_bps: 6,
            effective_fee_micro_units: 4_200,
            conflict_risk_bps: 675,
            sealed_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet route sealed");
    state
        .issue_rebate(IssueRebateRequest {
            route_id: route.route_id,
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            amount_micro_units: 1_100,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 5,
            expires_slot: DEVNET_SLOT + 512,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: batch.batch_id.clone(),
            public_fields: ["batch_id", "intent_count", "max_conflict_risk_bps"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            redacted_fields: [
                "owner_commitment",
                "encrypted_intent_root",
                "route_hint_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: 2_048,
            actual_public_bytes: 712,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            batch_id: batch.batch_id,
            median_fee_bps: 6,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let intent = state
        .submit_intent(SubmitIntentRequest {
            owner_commitment: sample_hash("owner", 2),
            kind: IntentKind::LiquidationBackstop,
            encrypted_intent_root: sample_hash("intent-root", 2),
            nullifier_root: sample_hash("nullifier", 2),
            target_contracts: vec![
                "private-lending-pool.devnet".to_string(),
                "confidential-liquidation-vault.devnet".to_string(),
            ],
            asset_commitments: vec![sample_hash("asset", 3)],
            route_hint_root: sample_hash("route-hint", 2),
            max_fee_micro_units: 12_000,
            max_fee_bps: 10,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT + 24,
        })
        .expect("demo liquidation intent submitted");
    let batch = state
        .open_batch_window(OpenBatchWindowRequest {
            opened_slot: DEVNET_SLOT + 25,
            solver_allowlist_root: sample_hash("solver-allowlist", 2),
            intent_ids: vec![intent.intent_id.clone()],
            max_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS + 50,
        })
        .expect("demo batch opened");
    let solver_id = state
        .solvers
        .keys()
        .next()
        .cloned()
        .expect("devnet has a solver");
    state
        .record_conflict_probe(ConflictProbeRequest {
            batch_id: batch.batch_id,
            intent_id: intent.intent_id,
            solver_id,
            kind: ConflictKind::OracleRace,
            encrypted_probe_root: sample_hash("encrypted-probe", 2),
            redacted_evidence_root: sample_hash("redacted-evidence", 2),
            observed_slot: DEVNET_SLOT + 26,
            risk_bps: 950,
            suggested_delay_slots: 2,
        })
        .expect("demo oracle race probe recorded");
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
    domain_hash(&format!("intent-mev-guard:{domain}:id"), parts, 24)
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
        "intent-mev-guard:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn estimated_batch_risk(priority_sum: u64, count: u64) -> u64 {
    if count == 0 {
        return MAX_BPS;
    }
    let average_priority = priority_sum.checked_div(count).unwrap_or(0);
    MAX_BPS.saturating_sub(average_priority).min(MAX_BPS)
}

fn ensure_bps(value: u64, name: &str) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} must be <= 10000"));
    }
    Ok(())
}

fn conflict_kind_str(kind: ConflictKind) -> &'static str {
    match kind {
        ConflictKind::PriceDisplacement => "price_displacement",
        ConflictKind::SandwichRisk => "sandwich_risk",
        ConflictKind::BackrunLeakage => "backrun_leakage",
        ConflictKind::CrossContractConflict => "cross_contract_conflict",
        ConflictKind::OracleRace => "oracle_race",
        ConflictKind::BridgeQueueLeakage => "bridge_queue_leakage",
        ConflictKind::SolverSelfDealing => "solver_self_dealing",
        ConflictKind::FeeGriefing => "fee_griefing",
        ConflictKind::PrivacySetRegression => "privacy_set_regression",
    }
}

fn attestation_kind_str(kind: AttestationKind) -> &'static str {
    match kind {
        AttestationKind::PqSignatureVerified => "pq_signature_verified",
        AttestationKind::BatchPrivacyFloor => "batch_privacy_floor",
        AttestationKind::ConflictProbeAccepted => "conflict_probe_accepted",
        AttestationKind::SolverBondChecked => "solver_bond_checked",
        AttestationKind::FeeCapObserved => "fee_cap_observed",
        AttestationKind::RouteNonDisplacement => "route_non_displacement",
        AttestationKind::RedactionBudgetObserved => "redaction_budget_observed",
        AttestationKind::SettlementSafe => "settlement_safe",
    }
}

fn guard_decision_str(decision: GuardDecision) -> &'static str {
    match decision {
        GuardDecision::Accept => "accept",
        GuardDecision::AcceptWithDelay => "accept_with_delay",
        GuardDecision::RequireMoreAttestations => "require_more_attestations",
        GuardDecision::Rebatch => "rebatch",
        GuardDecision::QuarantineSolver => "quarantine_solver",
        GuardDecision::Reject => "reject",
    }
}
