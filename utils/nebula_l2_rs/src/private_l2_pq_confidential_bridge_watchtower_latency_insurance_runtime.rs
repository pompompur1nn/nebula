use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialBridgeWatchtowerLatencyInsuranceRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-bridge-watchtower-latency-insurance-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_BRIDGE_WATCHTOWER_LATENCY_INSURANCE_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_WATCHTOWER_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const LATENCY_POLICY_SUITE: &str = "confidential-bridge-watchtower-latency-policy-root-v1";
pub const CLAIM_SUITE: &str = "confidential-watchtower-latency-claim-root-v1";
pub const REBATE_SUITE: &str = "watchtower-latency-insurance-low-fee-rebate-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-watchtower-latency-insurance-redaction-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_COVERAGE_ASSET_ID: &str = "xmr-watchtower-latency-insurance-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POLICY_WINDOW_SLOTS: u64 = 720;
pub const DEFAULT_CLAIM_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_MAX_PREMIUM_BPS: u64 = 20;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MIN_POOL_RESERVE_MICRO_UNITS: u64 = 96_000_000;
pub const DEFAULT_MIN_POLICY_COVERAGE_MICRO_UNITS: u64 = 1_000_000;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 4_000;
pub const DEFAULT_MAX_LATENCY_SLOTS: u64 = 64;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_POOLS: usize = 524_288;
pub const MAX_POLICIES: usize = 2_097_152;
pub const MAX_CLAIMS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_PAYOUTS: usize = 1_048_576;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 7_808;
pub const DEVNET_SLOT: u64 = 227;
pub const DEVNET_L2_HEIGHT: u64 = 3_296_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyScope {
    DepositFinality,
    WithdrawalFinality,
    ReserveProofPublication,
    WatchtowerDisputeResponse,
    FastExitRelayAck,
    EmergencyExitAck,
    AtomicSwapProofRelay,
    BridgeReceiptPublication,
}

impl LatencyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositFinality => "deposit_finality",
            Self::WithdrawalFinality => "withdrawal_finality",
            Self::ReserveProofPublication => "reserve_proof_publication",
            Self::WatchtowerDisputeResponse => "watchtower_dispute_response",
            Self::FastExitRelayAck => "fast_exit_relay_ack",
            Self::EmergencyExitAck => "emergency_exit_ack",
            Self::AtomicSwapProofRelay => "atomic_swap_proof_relay",
            Self::BridgeReceiptPublication => "bridge_receipt_publication",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::EmergencyExitAck => 10,
            Self::WithdrawalFinality => 9,
            Self::WatchtowerDisputeResponse => 8,
            Self::ReserveProofPublication => 7,
            Self::DepositFinality => 6,
            Self::FastExitRelayAck => 5,
            Self::AtomicSwapProofRelay => 5,
            Self::BridgeReceiptPublication => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Planned,
    Open,
    Throttled,
    ClaimsOnly,
    Quarantined,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Quoted,
    Active,
    ClaimPending,
    Paid,
    Expired,
    Quarantined,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    EvidenceLocked,
    Attested,
    Settled,
    RebateIssued,
    Rejected,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyCause {
    WatchtowerSlowQuorum,
    MoneroFinalityLag,
    ReserveProofLag,
    RelayCongestion,
    FeeSpikeBackpressure,
    ReorgObservationDelay,
    DisputeResponseDelay,
    PrivacyCooldown,
}

impl LatencyCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatchtowerSlowQuorum => "watchtower_slow_quorum",
            Self::MoneroFinalityLag => "monero_finality_lag",
            Self::ReserveProofLag => "reserve_proof_lag",
            Self::RelayCongestion => "relay_congestion",
            Self::FeeSpikeBackpressure => "fee_spike_backpressure",
            Self::ReorgObservationDelay => "reorg_observation_delay",
            Self::DisputeResponseDelay => "dispute_response_delay",
            Self::PrivacyCooldown => "privacy_cooldown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqWatchtowerSignatureVerified,
    LatencyWindowObserved,
    BridgeReceiptChecked,
    FinalityLagMeasured,
    FeeCapObserved,
    PrivacyBoundaryObserved,
    ReserveHintChecked,
    PayoutSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqWatchtowerSignatureVerified => "pq_watchtower_signature_verified",
            Self::LatencyWindowObserved => "latency_window_observed",
            Self::BridgeReceiptChecked => "bridge_receipt_checked",
            Self::FinalityLagMeasured => "finality_lag_measured",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::PrivacyBoundaryObserved => "privacy_boundary_observed",
            Self::ReserveHintChecked => "reserve_hint_checked",
            Self::PayoutSafe => "payout_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    ApprovePayout,
    ApprovePayoutWithRebate,
    PartialPayout,
    Reject,
    Retry,
    Quarantine,
    Expire,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApprovePayout => "approve_payout",
            Self::ApprovePayoutWithRebate => "approve_payout_with_rebate",
            Self::PartialPayout => "partial_payout",
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
    pub pq_watchtower_suite: String,
    pub latency_policy_suite: String,
    pub claim_suite: String,
    pub rebate_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub coverage_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub policy_window_slots: u64,
    pub claim_window_slots: u64,
    pub max_premium_bps: u64,
    pub target_rebate_bps: u64,
    pub min_pool_reserve_micro_units: u64,
    pub min_policy_coverage_micro_units: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub max_payout_bps: u64,
    pub max_latency_slots: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_watchtower_suite: PQ_WATCHTOWER_SUITE.to_string(),
            latency_policy_suite: LATENCY_POLICY_SUITE.to_string(),
            claim_suite: CLAIM_SUITE.to_string(),
            rebate_suite: REBATE_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            coverage_asset_id: DEFAULT_COVERAGE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            policy_window_slots: DEFAULT_POLICY_WINDOW_SLOTS,
            claim_window_slots: DEFAULT_CLAIM_WINDOW_SLOTS,
            max_premium_bps: DEFAULT_MAX_PREMIUM_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_pool_reserve_micro_units: DEFAULT_MIN_POOL_RESERVE_MICRO_UNITS,
            min_policy_coverage_micro_units: DEFAULT_MIN_POLICY_COVERAGE_MICRO_UNITS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_latency_slots: DEFAULT_MAX_LATENCY_SLOTS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools_opened: u64,
    pub policies_underwritten: u64,
    pub claims_submitted: u64,
    pub attestations_recorded: u64,
    pub payouts_recorded: u64,
    pub rebates_issued: u64,
    pub redaction_budgets_published: u64,
    pub operator_summaries_published: u64,
    pub quarantines: u64,
    pub total_reserve_micro_units: u64,
    pub total_covered_micro_units: u64,
    pub total_premium_micro_units: u64,
    pub total_payout_micro_units: u64,
    pub total_rebated_micro_units: u64,
    pub total_latency_slots: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub pool_root: String,
    pub policy_root: String,
    pub claim_root: String,
    pub attestation_root: String,
    pub payout_root: String,
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
            policy_root: empty_root("policies"),
            claim_root: empty_root("claims"),
            attestation_root: empty_root("attestations"),
            payout_root: empty_root("payouts"),
            rebate_root: empty_root("rebates"),
            redaction_root: empty_root("redactions"),
            operator_summary_root: empty_root("operator-summaries"),
            counters_root: empty_root("counters"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyPool {
    pub pool_id: String,
    pub scope: LatencyScope,
    pub status: PoolStatus,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub reserve_commitment_root: String,
    pub reserve_micro_units: u64,
    pub available_reserve_micro_units: u64,
    pub covered_micro_units: u64,
    pub premium_bps: u64,
    pub payout_cap_bps: u64,
    pub max_latency_slots: u64,
    pub opened_slot: u64,
    pub last_updated_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyPolicy {
    pub policy_id: String,
    pub pool_id: String,
    pub status: PolicyStatus,
    pub insured_bridge_root: String,
    pub claimant_commitment: String,
    pub latency_hint_root: String,
    pub coverage_micro_units: u64,
    pub premium_micro_units: u64,
    pub premium_bps: u64,
    pub privacy_set_size: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
    pub claim_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyClaim {
    pub claim_id: String,
    pub policy_id: String,
    pub pool_id: String,
    pub cause: LatencyCause,
    pub status: ClaimStatus,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub latency_commitment_root: String,
    pub observed_latency_slots: u64,
    pub requested_payout_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub attestation_count: u64,
    pub quorum_weight_bps: u64,
    pub settled_slot: Option<u64>,
    pub settlement_decision: Option<SettlementDecision>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyAttestation {
    pub attestation_id: String,
    pub claim_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayoutReceipt {
    pub payout_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub pool_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub payout_bps: u64,
    pub payout_micro_units: u64,
    pub reserve_remainder_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub claim_id: String,
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
    pub open_pools: u64,
    pub active_policies: u64,
    pub pending_claims: u64,
    pub settled_claims: u64,
    pub quarantined_claims: u64,
    pub total_reserve_micro_units: u64,
    pub total_covered_micro_units: u64,
    pub total_payout_micro_units: u64,
    pub total_latency_slots: u64,
    pub median_premium_bps: u64,
    pub attestation_quorum_bps: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPoolRequest {
    pub scope: LatencyScope,
    pub sealed_pool_root: String,
    pub public_hint_root: String,
    pub reserve_commitment_root: String,
    pub reserve_micro_units: u64,
    pub premium_bps: u64,
    pub payout_cap_bps: u64,
    pub max_latency_slots: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnderwritePolicyRequest {
    pub pool_id: String,
    pub insured_bridge_root: String,
    pub claimant_commitment: String,
    pub latency_hint_root: String,
    pub coverage_micro_units: u64,
    pub premium_bps: u64,
    pub privacy_set_size: u64,
    pub issued_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitClaimRequest {
    pub policy_id: String,
    pub cause: LatencyCause,
    pub sealed_evidence_root: String,
    pub redacted_evidence_root: String,
    pub latency_commitment_root: String,
    pub observed_latency_slots: u64,
    pub requested_payout_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub claim_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleClaimRequest {
    pub claim_id: String,
    pub settlement_root: String,
    pub decision: SettlementDecision,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub claim_id: String,
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
    pub median_premium_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, LatencyPool>,
    pub policies: BTreeMap<String, LatencyPolicy>,
    pub claims: BTreeMap<String, LatencyClaim>,
    pub attestations: BTreeMap<String, LatencyAttestation>,
    pub payouts: BTreeMap<String, PayoutReceipt>,
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
            policies: BTreeMap::new(),
            claims: BTreeMap::new(),
            attestations: BTreeMap::new(),
            payouts: BTreeMap::new(),
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

    pub fn open_pool(&mut self, request: OpenPoolRequest) -> Result<String> {
        ensure_capacity(self.pools.len(), MAX_POOLS, "latency pools")?;
        ensure_non_empty(&request.sealed_pool_root, "sealed_pool_root")?;
        ensure_non_empty(&request.public_hint_root, "public_hint_root")?;
        ensure_non_empty(&request.reserve_commitment_root, "reserve_commitment_root")?;
        ensure_bps(request.premium_bps, "premium_bps")?;
        ensure_bps(request.payout_cap_bps, "payout_cap_bps")?;
        if request.reserve_micro_units < self.config.min_pool_reserve_micro_units {
            return Err("reserve_micro_units below minimum pool reserve".to_string());
        }
        if request.premium_bps > self.config.max_premium_bps {
            return Err("premium_bps exceeds configured maximum".to_string());
        }
        if request.payout_cap_bps > self.config.max_payout_bps {
            return Err("payout_cap_bps exceeds configured maximum".to_string());
        }
        if request.max_latency_slots > self.config.max_latency_slots {
            return Err("max_latency_slots exceeds configured maximum".to_string());
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
            return Err(format!("latency pool {pool_id} already exists"));
        }
        let pool = LatencyPool {
            pool_id: pool_id.clone(),
            scope: request.scope,
            status: PoolStatus::Open,
            sealed_pool_root: request.sealed_pool_root,
            public_hint_root: request.public_hint_root,
            reserve_commitment_root: request.reserve_commitment_root,
            reserve_micro_units: request.reserve_micro_units,
            available_reserve_micro_units: request.reserve_micro_units,
            covered_micro_units: 0,
            premium_bps: request.premium_bps,
            payout_cap_bps: request.payout_cap_bps,
            max_latency_slots: request.max_latency_slots,
            opened_slot: request.opened_slot,
            last_updated_slot: request.opened_slot,
        };
        self.pools.insert(pool_id.clone(), pool);
        self.counters.pools_opened = self.counters.pools_opened.saturating_add(1);
        self.counters.total_reserve_micro_units = self
            .counters
            .total_reserve_micro_units
            .saturating_add(request.reserve_micro_units);
        self.refresh_roots();
        Ok(pool_id)
    }

    pub fn underwrite_policy(&mut self, request: UnderwritePolicyRequest) -> Result<String> {
        ensure_capacity(self.policies.len(), MAX_POLICIES, "latency policies")?;
        ensure_non_empty(&request.pool_id, "pool_id")?;
        ensure_non_empty(&request.insured_bridge_root, "insured_bridge_root")?;
        ensure_non_empty(&request.claimant_commitment, "claimant_commitment")?;
        ensure_non_empty(&request.latency_hint_root, "latency_hint_root")?;
        ensure_bps(request.premium_bps, "premium_bps")?;
        if request.coverage_micro_units < self.config.min_policy_coverage_micro_units {
            return Err("coverage_micro_units below minimum policy coverage".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below minimum".to_string());
        }
        let pool = self
            .pools
            .get_mut(&request.pool_id)
            .ok_or_else(|| format!("unknown pool {}", request.pool_id))?;
        if !matches!(pool.status, PoolStatus::Open | PoolStatus::Throttled) {
            return Err("latency pool is not accepting policies".to_string());
        }
        if request.coverage_micro_units > pool.available_reserve_micro_units {
            return Err("coverage exceeds available reserve".to_string());
        }
        let policy_id = stable_id(
            "policy",
            &[
                HashPart::Str(&request.pool_id),
                HashPart::Str(&request.insured_bridge_root),
                HashPart::Str(&request.claimant_commitment),
                HashPart::U64(request.issued_slot),
            ],
        );
        if self.policies.contains_key(&policy_id) {
            return Err(format!("policy {policy_id} already exists"));
        }
        let premium_micro_units = request
            .coverage_micro_units
            .saturating_mul(request.premium_bps)
            / MAX_BPS;
        let expires_slot = request
            .issued_slot
            .saturating_add(self.config.policy_window_slots);
        let policy = LatencyPolicy {
            policy_id: policy_id.clone(),
            pool_id: request.pool_id.clone(),
            status: PolicyStatus::Active,
            insured_bridge_root: request.insured_bridge_root,
            claimant_commitment: request.claimant_commitment,
            latency_hint_root: request.latency_hint_root,
            coverage_micro_units: request.coverage_micro_units,
            premium_micro_units,
            premium_bps: request.premium_bps,
            privacy_set_size: request.privacy_set_size,
            issued_slot: request.issued_slot,
            expires_slot,
            claim_count: 0,
        };
        pool.available_reserve_micro_units = pool
            .available_reserve_micro_units
            .saturating_sub(request.coverage_micro_units);
        pool.covered_micro_units = pool
            .covered_micro_units
            .saturating_add(request.coverage_micro_units);
        pool.last_updated_slot = request.issued_slot;
        self.counters.policies_underwritten = self.counters.policies_underwritten.saturating_add(1);
        self.counters.total_covered_micro_units = self
            .counters
            .total_covered_micro_units
            .saturating_add(request.coverage_micro_units);
        self.counters.total_premium_micro_units = self
            .counters
            .total_premium_micro_units
            .saturating_add(premium_micro_units);
        self.policies.insert(policy_id.clone(), policy);
        self.refresh_roots();
        Ok(policy_id)
    }

    pub fn submit_claim(&mut self, request: SubmitClaimRequest) -> Result<String> {
        ensure_capacity(self.claims.len(), MAX_CLAIMS, "latency claims")?;
        ensure_non_empty(&request.policy_id, "policy_id")?;
        ensure_non_empty(&request.sealed_evidence_root, "sealed_evidence_root")?;
        ensure_non_empty(&request.redacted_evidence_root, "redacted_evidence_root")?;
        ensure_non_empty(&request.latency_commitment_root, "latency_commitment_root")?;
        ensure_bps(request.requested_payout_bps, "requested_payout_bps")?;
        ensure_bps(request.requested_rebate_bps, "requested_rebate_bps")?;
        let policy = self
            .policies
            .get_mut(&request.policy_id)
            .ok_or_else(|| format!("unknown policy {}", request.policy_id))?;
        let pool = self
            .pools
            .get(&policy.pool_id)
            .ok_or_else(|| format!("unknown pool {}", policy.pool_id))?;
        if !matches!(policy.status, PolicyStatus::Active) {
            return Err("policy is not claimable".to_string());
        }
        if request.submitted_slot > policy.expires_slot {
            return Err("claim submitted after policy expiry".to_string());
        }
        if request.observed_latency_slots <= pool.max_latency_slots {
            return Err("observed latency does not exceed policy threshold".to_string());
        }
        if request.requested_payout_bps > pool.payout_cap_bps {
            return Err("requested_payout_bps exceeds pool cap".to_string());
        }
        let claim_id = stable_id(
            "claim",
            &[
                HashPart::Str(&request.policy_id),
                HashPart::Str(request.cause.as_str()),
                HashPart::Str(&request.sealed_evidence_root),
                HashPart::U64(request.submitted_slot),
            ],
        );
        if self.claims.contains_key(&claim_id) {
            return Err(format!("claim {claim_id} already exists"));
        }
        let expires_slot = request
            .submitted_slot
            .saturating_add(self.config.claim_window_slots);
        let claim = LatencyClaim {
            claim_id: claim_id.clone(),
            policy_id: request.policy_id.clone(),
            pool_id: policy.pool_id.clone(),
            cause: request.cause,
            status: ClaimStatus::Submitted,
            sealed_evidence_root: request.sealed_evidence_root,
            redacted_evidence_root: request.redacted_evidence_root,
            latency_commitment_root: request.latency_commitment_root,
            observed_latency_slots: request.observed_latency_slots,
            requested_payout_bps: request.requested_payout_bps,
            requested_rebate_bps: request.requested_rebate_bps,
            submitted_slot: request.submitted_slot,
            expires_slot,
            attestation_count: 0,
            quorum_weight_bps: 0,
            settled_slot: None,
            settlement_decision: None,
        };
        policy.status = PolicyStatus::ClaimPending;
        policy.claim_count = policy.claim_count.saturating_add(1);
        self.counters.claims_submitted = self.counters.claims_submitted.saturating_add(1);
        self.counters.total_latency_slots = self
            .counters
            .total_latency_slots
            .saturating_add(request.observed_latency_slots);
        self.claims.insert(claim_id.clone(), claim);
        self.refresh_roots();
        Ok(claim_id)
    }

    pub fn record_attestation(&mut self, request: RecordAttestationRequest) -> Result<String> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.claim_id, "claim_id")?;
        ensure_non_empty(&request.committee_root, "committee_root")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        let claim = self
            .claims
            .get_mut(&request.claim_id)
            .ok_or_else(|| format!("unknown claim {}", request.claim_id))?;
        if !matches!(
            claim.status,
            ClaimStatus::Submitted | ClaimStatus::EvidenceLocked
        ) {
            return Err("claim is not accepting attestations".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.claim_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.committee_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!("attestation {attestation_id} already exists"));
        }
        let accepted = request.quorum_weight_bps >= self.config.min_attestation_quorum_bps;
        let attestation = LatencyAttestation {
            attestation_id: attestation_id.clone(),
            claim_id: request.claim_id.clone(),
            kind: request.kind,
            committee_root: request.committee_root,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
            accepted,
        };
        claim.attestation_count = claim.attestation_count.saturating_add(1);
        claim.quorum_weight_bps = claim.quorum_weight_bps.max(request.quorum_weight_bps);
        claim.status = if accepted {
            ClaimStatus::Attested
        } else {
            ClaimStatus::EvidenceLocked
        };
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_claim(&mut self, request: SettleClaimRequest) -> Result<String> {
        ensure_capacity(self.payouts.len(), MAX_PAYOUTS, "payouts")?;
        ensure_non_empty(&request.claim_id, "claim_id")?;
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let claim = self
            .claims
            .get_mut(&request.claim_id)
            .ok_or_else(|| format!("unknown claim {}", request.claim_id))?;
        if !matches!(
            claim.status,
            ClaimStatus::Attested | ClaimStatus::EvidenceLocked
        ) {
            return Err("claim is not settleable".to_string());
        }
        if request.settled_slot > claim.expires_slot {
            return Err("settled_slot exceeds claim expiry".to_string());
        }
        let policy = self
            .policies
            .get_mut(&claim.policy_id)
            .ok_or_else(|| format!("unknown policy {}", claim.policy_id))?;
        let pool = self
            .pools
            .get_mut(&claim.pool_id)
            .ok_or_else(|| format!("unknown pool {}", claim.pool_id))?;
        let requested_payout = policy
            .coverage_micro_units
            .saturating_mul(claim.requested_payout_bps)
            / MAX_BPS;
        let payout_micro_units = match request.decision {
            SettlementDecision::ApprovePayout | SettlementDecision::ApprovePayoutWithRebate => {
                requested_payout
            }
            SettlementDecision::PartialPayout => requested_payout / 2,
            SettlementDecision::Reject | SettlementDecision::Retry | SettlementDecision::Expire => {
                0
            }
            SettlementDecision::Quarantine => requested_payout,
        };
        if payout_micro_units > pool.reserve_micro_units {
            return Err("payout exceeds reserve".to_string());
        }
        let payout_id = stable_id(
            "payout",
            &[
                HashPart::Str(&request.claim_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::Str(&request.settlement_root),
                HashPart::U64(request.settled_slot),
            ],
        );
        if self.payouts.contains_key(&payout_id) {
            return Err(format!("payout {payout_id} already exists"));
        }
        pool.reserve_micro_units = pool.reserve_micro_units.saturating_sub(payout_micro_units);
        pool.covered_micro_units = pool
            .covered_micro_units
            .saturating_sub(policy.coverage_micro_units);
        pool.available_reserve_micro_units = pool.available_reserve_micro_units.saturating_add(
            policy
                .coverage_micro_units
                .saturating_sub(payout_micro_units),
        );
        pool.last_updated_slot = request.settled_slot;
        policy.status = match request.decision {
            SettlementDecision::ApprovePayout
            | SettlementDecision::ApprovePayoutWithRebate
            | SettlementDecision::PartialPayout => PolicyStatus::Paid,
            SettlementDecision::Reject | SettlementDecision::Retry => PolicyStatus::Active,
            SettlementDecision::Quarantine => {
                self.counters.quarantines = self.counters.quarantines.saturating_add(1);
                PolicyStatus::Quarantined
            }
            SettlementDecision::Expire => PolicyStatus::Expired,
        };
        claim.status = match request.decision {
            SettlementDecision::Reject => ClaimStatus::Rejected,
            SettlementDecision::Expire => ClaimStatus::Expired,
            SettlementDecision::Quarantine => ClaimStatus::Quarantined,
            _ => ClaimStatus::Settled,
        };
        claim.settled_slot = Some(request.settled_slot);
        claim.settlement_decision = Some(request.decision);
        let payout = PayoutReceipt {
            payout_id: payout_id.clone(),
            claim_id: request.claim_id.clone(),
            policy_id: claim.policy_id.clone(),
            pool_id: claim.pool_id.clone(),
            settlement_root: request.settlement_root,
            decision: request.decision,
            payout_bps: claim.requested_payout_bps,
            payout_micro_units,
            reserve_remainder_micro_units: pool.reserve_micro_units,
            settled_slot: request.settled_slot,
        };
        self.counters.payouts_recorded = self.counters.payouts_recorded.saturating_add(1);
        self.counters.total_payout_micro_units = self
            .counters
            .total_payout_micro_units
            .saturating_add(payout_micro_units);
        self.payouts.insert(payout_id.clone(), payout);
        self.refresh_roots();
        Ok(payout_id)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<String> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        ensure_non_empty(&request.claim_id, "claim_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.expires_slot <= request.issued_slot {
            return Err("expires_slot must be greater than issued_slot".to_string());
        }
        let claim = self
            .claims
            .get_mut(&request.claim_id)
            .ok_or_else(|| format!("unknown claim {}", request.claim_id))?;
        if !matches!(claim.status, ClaimStatus::Settled) {
            return Err("claim must be settled before rebate".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.claim_id),
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
            claim_id: request.claim_id.clone(),
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        claim.status = ClaimStatus::RebateIssued;
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
        ensure_bps(request.median_premium_bps, "median_premium_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let open_pools = self
            .pools
            .values()
            .filter(|pool| matches!(pool.status, PoolStatus::Open | PoolStatus::Throttled))
            .count() as u64;
        let active_policies = self
            .policies
            .values()
            .filter(|policy| matches!(policy.status, PolicyStatus::Active))
            .count() as u64;
        let pending_claims = self
            .claims
            .values()
            .filter(|claim| matches!(claim.status, ClaimStatus::Submitted | ClaimStatus::Attested))
            .count() as u64;
        let settled_claims = self
            .claims
            .values()
            .filter(|claim| {
                matches!(
                    claim.status,
                    ClaimStatus::Settled | ClaimStatus::RebateIssued
                )
            })
            .count() as u64;
        let quarantined_claims = self
            .claims
            .values()
            .filter(|claim| matches!(claim.status, ClaimStatus::Quarantined))
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
            open_pools,
            active_policies,
            pending_claims,
            settled_claims,
            quarantined_claims,
            total_reserve_micro_units: self.counters.total_reserve_micro_units,
            total_covered_micro_units: self.counters.total_covered_micro_units,
            total_payout_micro_units: self.counters.total_payout_micro_units,
            total_latency_slots: self.counters.total_latency_slots,
            median_premium_bps: request.median_premium_bps,
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
        self.roots.policy_root = map_root("policies", &self.policies);
        self.roots.claim_root = map_root("claims", &self.claims);
        self.roots.attestation_root = map_root("attestations", &self.attestations);
        self.roots.payout_root = map_root("payouts", &self.payouts);
        self.roots.rebate_root = map_root("rebates", &self.rebates);
        self.roots.redaction_root = map_root("redactions", &self.redaction_budgets);
        self.roots.operator_summary_root = map_root("operator-summaries", &self.operator_summaries);
        self.roots.counters_root = object_root("counters", &self.counters);
        self.roots.state_root = merkle_root(
            "bridge-watchtower-latency-insurance:state",
            &[
                json!({ "config_root": self.roots.config_root }),
                json!({ "pool_root": self.roots.pool_root }),
                json!({ "policy_root": self.roots.policy_root }),
                json!({ "claim_root": self.roots.claim_root }),
                json!({ "attestation_root": self.roots.attestation_root }),
                json!({ "payout_root": self.roots.payout_root }),
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
            "pq_watchtower_suite": self.config.pq_watchtower_suite,
            "latency_policy_suite": self.config.latency_policy_suite,
            "claim_suite": self.config.claim_suite,
            "fee_asset_id": self.config.fee_asset_id,
            "coverage_asset_id": self.config.coverage_asset_id,
            "min_privacy_set_size": self.config.min_privacy_set_size,
            "target_privacy_set_size": self.config.target_privacy_set_size,
            "min_pq_security_bits": self.config.min_pq_security_bits,
            "policy_window_slots": self.config.policy_window_slots,
            "claim_window_slots": self.config.claim_window_slots,
            "max_premium_bps": self.config.max_premium_bps,
            "target_rebate_bps": self.config.target_rebate_bps,
            "max_payout_bps": self.config.max_payout_bps,
            "max_latency_slots": self.config.max_latency_slots,
            "counters": self.counters,
            "roots": self.roots,
            "pool_count": self.pools.len(),
            "policy_count": self.policies.len(),
            "claim_count": self.claims.len(),
            "attestation_count": self.attestations.len(),
            "payout_count": self.payouts.len(),
            "rebate_count": self.rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "pools": self.pools.values().map(|pool| json!({
                "pool_id": pool.pool_id,
                "scope": pool.scope,
                "status": pool.status,
                "public_hint_root": pool.public_hint_root,
                "reserve_micro_units": pool.reserve_micro_units,
                "available_reserve_micro_units": pool.available_reserve_micro_units,
                "covered_micro_units": pool.covered_micro_units,
                "premium_bps": pool.premium_bps,
                "payout_cap_bps": pool.payout_cap_bps,
                "max_latency_slots": pool.max_latency_slots,
            })).collect::<Vec<_>>(),
            "policies": self.policies.values().map(|policy| json!({
                "policy_id": policy.policy_id,
                "pool_id": policy.pool_id,
                "status": policy.status,
                "latency_hint_root": policy.latency_hint_root,
                "coverage_micro_units": policy.coverage_micro_units,
                "premium_micro_units": policy.premium_micro_units,
                "premium_bps": policy.premium_bps,
                "privacy_set_size": policy.privacy_set_size,
                "issued_slot": policy.issued_slot,
                "expires_slot": policy.expires_slot,
                "claim_count": policy.claim_count,
            })).collect::<Vec<_>>(),
            "claims": self.claims.values().map(|claim| json!({
                "claim_id": claim.claim_id,
                "policy_id": claim.policy_id,
                "pool_id": claim.pool_id,
                "cause": claim.cause,
                "status": claim.status,
                "redacted_evidence_root": claim.redacted_evidence_root,
                "latency_commitment_root": claim.latency_commitment_root,
                "observed_latency_slots": claim.observed_latency_slots,
                "requested_payout_bps": claim.requested_payout_bps,
                "requested_rebate_bps": claim.requested_rebate_bps,
                "submitted_slot": claim.submitted_slot,
                "expires_slot": claim.expires_slot,
                "attestation_count": claim.attestation_count,
                "quorum_weight_bps": claim.quorum_weight_bps,
                "settled_slot": claim.settled_slot,
                "settlement_decision": claim.settlement_decision,
            })).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(|attestation| json!({
                "attestation_id": attestation.attestation_id,
                "claim_id": attestation.claim_id,
                "kind": attestation.kind,
                "statement_root": attestation.statement_root,
                "observed_slot": attestation.observed_slot,
                "quorum_weight_bps": attestation.quorum_weight_bps,
                "accepted": attestation.accepted,
            })).collect::<Vec<_>>(),
            "payouts": self.payouts.values().collect::<Vec<_>>(),
            "rebates": self.rebates.values().collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().collect::<Vec<_>>(),
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let pool_id = state
        .open_pool(OpenPoolRequest {
            scope: LatencyScope::WithdrawalFinality,
            sealed_pool_root: sample_hash("sealed-pool", 1),
            public_hint_root: sample_hash("public-hint", 1),
            reserve_commitment_root: sample_hash("reserve", 1),
            reserve_micro_units: 220_000_000,
            premium_bps: 10,
            payout_cap_bps: 2_000,
            max_latency_slots: 28,
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet watchtower latency insurance pool opened");
    let policy_id = state
        .underwrite_policy(UnderwritePolicyRequest {
            pool_id: pool_id.clone(),
            insured_bridge_root: sample_hash("bridge", 1),
            claimant_commitment: sample_hash("claimant", 1),
            latency_hint_root: sample_hash("latency-hint", 1),
            coverage_micro_units: 44_000_000,
            premium_bps: 9,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            issued_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet latency policy underwritten");
    let claim_id = state
        .submit_claim(SubmitClaimRequest {
            policy_id: policy_id.clone(),
            cause: LatencyCause::WatchtowerSlowQuorum,
            sealed_evidence_root: sample_hash("sealed-evidence", 1),
            redacted_evidence_root: sample_hash("redacted-evidence", 1),
            latency_commitment_root: sample_hash("latency", 1),
            observed_latency_slots: 47,
            requested_payout_bps: 1_200,
            requested_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            submitted_slot: DEVNET_SLOT + 12,
        })
        .expect("devnet latency claim submitted");
    state
        .record_attestation(RecordAttestationRequest {
            claim_id: claim_id.clone(),
            kind: AttestationKind::PayoutSafe,
            committee_root: sample_hash("committee", 1),
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 16,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet latency claim attested");
    state
        .settle_claim(SettleClaimRequest {
            claim_id: claim_id.clone(),
            settlement_root: sample_hash("settlement", 1),
            decision: SettlementDecision::ApprovePayoutWithRebate,
            settled_slot: DEVNET_SLOT + 22,
        })
        .expect("devnet latency claim settled");
    state
        .issue_rebate(IssueRebateRequest {
            claim_id: claim_id.clone(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_micro_units: 880,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 23,
            expires_slot: DEVNET_SLOT + DEFAULT_POLICY_WINDOW_SLOTS,
        })
        .expect("devnet latency rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: claim_id,
            public_fields: [
                "claim_id",
                "policy_id",
                "pool_id",
                "cause",
                "observed_latency_slots",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            redacted_fields: [
                "insured_bridge_root",
                "claimant_commitment",
                "sealed_evidence_root",
                "committee_root",
                "pq_signature_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            actual_public_bytes: 872,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_premium_bps: 9,
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
            scope: LatencyScope::ReserveProofPublication,
            sealed_pool_root: sample_hash("sealed-pool", 2),
            public_hint_root: sample_hash("public-hint", 2),
            reserve_commitment_root: sample_hash("reserve", 2),
            reserve_micro_units: 150_000_000,
            premium_bps: 11,
            payout_cap_bps: 1_800,
            max_latency_slots: 32,
            opened_slot: DEVNET_SLOT + 40,
        })
        .expect("demo watchtower latency insurance pool opened");
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
        &format!("bridge-watchtower-latency-insurance:{domain}:id"),
        parts,
        24,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("bridge-watchtower-latency-insurance:{domain}"),
        &[],
    )
}

fn object_root<T: Serialize>(domain: &str, value: &T) -> String {
    merkle_root(
        &format!("bridge-watchtower-latency-insurance:{domain}"),
        &[json!(value)],
    )
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("bridge-watchtower-latency-insurance:{domain}"),
        &leaves,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "bridge-watchtower-latency-insurance:devnet-sample",
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
