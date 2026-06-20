use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-contract-mev-shield-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const CONFIDENTIAL_COMMITMENT_SUITE: &str =
    "sealed-cross-contract-private-orderflow-commitment-v1";
pub const CALLBACK_ENCRYPTION_SUITE: &str = "threshold-encrypted-cross-contract-callback-bundle-v1";
pub const MEV_SHIELD_SUITE: &str = "cross-contract-mev-shield-session-root-v1";
pub const SOLVER_QUARANTINE_SUITE: &str = "solver-quarantine-risk-fence-root-v1";
pub const LOW_FEE_BUNDLE_SUITE: &str = "low-fee-protected-confidential-bundle-root-v1";
pub const RISK_AUCTION_SUITE: &str = "sealed-defi-risk-auction-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "operator-safe-redaction-budget-root-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_620_000;
pub const DEVNET_EPOCH: u64 = 6_144;
pub const DEVNET_SLOT: u64 = 27;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 32_768;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 220;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 900;
pub const DEFAULT_CALLBACK_TTL_SLOTS: u64 = 48;
pub const DEFAULT_COMMITMENT_TTL_SLOTS: u64 = 64;
pub const DEFAULT_QUARANTINE_TTL_SLOTS: u64 = 384;
pub const DEFAULT_RISK_AUCTION_TTL_SLOTS: u64 = 96;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 15;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MAX_RED_ACTIONS_PER_OPERATOR: u64 = 2_048;
pub const DEFAULT_MIN_SOLVER_BOND_MICRO_UNITS: u64 = 10_000_000;
pub const DEFAULT_MIN_ATTESTER_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_MIN_AUCTION_BOND_MICRO_UNITS: u64 = 5_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_BPS: u64 = 8_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SESSIONS: usize = 1_048_576;
pub const MAX_COMMITMENTS: usize = 4_194_304;
pub const MAX_SOLVERS: usize = 262_144;
pub const MAX_CALLBACK_BUNDLES: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_PROTECTED_BUNDLES: usize = 1_048_576;
pub const MAX_RISK_AUCTIONS: usize = 524_288;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_CONTRACTS_PER_SESSION: usize = 64;
pub const MAX_CALLBACKS_PER_BUNDLE: usize = 512;
pub const MAX_BIDS_PER_AUCTION: usize = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    ConfidentialSwap,
    CrossContractArbitrage,
    LiquidationBackstop,
    BatchSettlement,
    LendingRebalance,
    PerpetualsMargin,
    OptionsExercise,
    OracleProtectedCall,
    BridgeSettlement,
    EmergencyUnwind,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialSwap => "confidential_swap",
            Self::CrossContractArbitrage => "cross_contract_arbitrage",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::BatchSettlement => "batch_settlement",
            Self::LendingRebalance => "lending_rebalance",
            Self::PerpetualsMargin => "perpetuals_margin",
            Self::OptionsExercise => "options_exercise",
            Self::OracleProtectedCall => "oracle_protected_call",
            Self::BridgeSettlement => "bridge_settlement",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 10_000,
            Self::BridgeSettlement => 9_700,
            Self::LiquidationBackstop => 9_400,
            Self::OracleProtectedCall => 9_000,
            Self::PerpetualsMargin => 8_700,
            Self::CrossContractArbitrage => 8_500,
            Self::ConfidentialSwap => 8_200,
            Self::BatchSettlement => 7_800,
            Self::LendingRebalance => 7_600,
            Self::OptionsExercise => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Open,
    OrderflowCommitted,
    Attested,
    CallbacksSealed,
    Bundled,
    RiskAuctioned,
    Executed,
    Settled,
    Challenged,
    Expired,
    Cancelled,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::OrderflowCommitted => "orderflow_committed",
            Self::Attested => "attested",
            Self::CallbacksSealed => "callbacks_sealed",
            Self::Bundled => "bundled",
            Self::RiskAuctioned => "risk_auctioned",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::OrderflowCommitted
                | Self::Attested
                | Self::CallbacksSealed
                | Self::Bundled
                | Self::RiskAuctioned
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentKind {
    IntentEnvelope,
    RouteConstraint,
    SlippageFence,
    NullifierFence,
    PriceWitness,
    CallbackWitness,
    FeeSponsorWitness,
    PrivateRiskLimit,
}

impl CommitmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentEnvelope => "intent_envelope",
            Self::RouteConstraint => "route_constraint",
            Self::SlippageFence => "slippage_fence",
            Self::NullifierFence => "nullifier_fence",
            Self::PriceWitness => "price_witness",
            Self::CallbackWitness => "callback_witness",
            Self::FeeSponsorWitness => "fee_sponsor_witness",
            Self::PrivateRiskLimit => "private_risk_limit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Submitted,
    Accepted,
    Fenced,
    Bundled,
    RevealedToCircuit,
    Spent,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Active,
    Watchlisted,
    Quarantined,
    SlashPending,
    Slashed,
    Reinstated,
}

impl SolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Watchlisted => "watchlisted",
            Self::Quarantined => "quarantined",
            Self::SlashPending => "slash_pending",
            Self::Slashed => "slashed",
            Self::Reinstated => "reinstated",
        }
    }

    pub fn accepts_flow(self) -> bool {
        matches!(self, Self::Active | Self::Reinstated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    LatencyLeakage,
    BundleCensorship,
    ToxicFlowReplay,
    CallbackTampering,
    RiskLimitBypass,
    FeeGriefing,
    PqAttestationFailure,
    OperatorChallenge,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencyLeakage => "latency_leakage",
            Self::BundleCensorship => "bundle_censorship",
            Self::ToxicFlowReplay => "toxic_flow_replay",
            Self::CallbackTampering => "callback_tampering",
            Self::RiskLimitBypass => "risk_limit_bypass",
            Self::FeeGriefing => "fee_griefing",
            Self::PqAttestationFailure => "pq_attestation_failure",
            Self::OperatorChallenge => "operator_challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackBundleStatus {
    Sealed,
    Attested,
    Scheduled,
    Executed,
    ReplayedSafely,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    SolverAuthorization,
    BundleIntegrity,
    CallbackDecryption,
    RiskAuctionClearing,
    RedactionBudget,
    LowFeeSponsorship,
    OperatorSummary,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SolverAuthorization => "solver_authorization",
            Self::BundleIntegrity => "bundle_integrity",
            Self::CallbackDecryption => "callback_decryption",
            Self::RiskAuctionClearing => "risk_auction_clearing",
            Self::RedactionBudget => "redaction_budget",
            Self::LowFeeSponsorship => "low_fee_sponsorship",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedBundleStatus {
    Proposed,
    FeeCapped,
    Attested,
    Scheduled,
    Executed,
    Rebated,
    Challenged,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAuctionStatus {
    Open,
    Sealed,
    Cleared,
    Settled,
    Cancelled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionBudgetStatus {
    Active,
    Throttled,
    Exhausted,
    Rotated,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub callback_ttl_slots: u64,
    pub commitment_ttl_slots: u64,
    pub quarantine_ttl_slots: u64,
    pub risk_auction_ttl_slots: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_redactions_per_operator: u64,
    pub min_solver_bond_micro_units: u64,
    pub min_attester_bond_micro_units: u64,
    pub min_auction_bond_micro_units: u64,
    pub slash_bps: u64,
    pub quorum_bps: u64,
    pub supermajority_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            callback_ttl_slots: DEFAULT_CALLBACK_TTL_SLOTS,
            commitment_ttl_slots: DEFAULT_COMMITMENT_TTL_SLOTS,
            quarantine_ttl_slots: DEFAULT_QUARANTINE_TTL_SLOTS,
            risk_auction_ttl_slots: DEFAULT_RISK_AUCTION_TTL_SLOTS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_redactions_per_operator: DEFAULT_MAX_RED_ACTIONS_PER_OPERATOR,
            min_solver_bond_micro_units: DEFAULT_MIN_SOLVER_BOND_MICRO_UNITS,
            min_attester_bond_micro_units: DEFAULT_MIN_ATTESTER_BOND_MICRO_UNITS,
            min_auction_bond_micro_units: DEFAULT_MIN_AUCTION_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.chain_id.is_empty() {
            return Err("chain_id must not be empty".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "protocol_version mismatch: expected {PROTOCOL_VERSION}, got {}",
                self.protocol_version
            ));
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must be at least 192".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("target_privacy_set_size must cover min_privacy_set_size".to_string());
        }
        if self.target_latency_ms == 0 || self.max_latency_ms < self.target_latency_ms {
            return Err("max_latency_ms must cover target_latency_ms".to_string());
        }
        for (name, value) in [
            ("max_user_fee_bps", self.max_user_fee_bps),
            ("target_rebate_bps", self.target_rebate_bps),
            ("slash_bps", self.slash_bps),
            ("quorum_bps", self.quorum_bps),
            ("supermajority_bps", self.supermajority_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{name} exceeds {MAX_BPS} bps"));
            }
        }
        if self.supermajority_bps < self.quorum_bps {
            return Err("supermajority_bps must be at least quorum_bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sessions_opened: u64,
    pub commitments_accepted: u64,
    pub solvers_quarantined: u64,
    pub callback_bundles_sealed: u64,
    pub pq_attestations_recorded: u64,
    pub low_fee_bundles_built: u64,
    pub risk_auctions_opened: u64,
    pub risk_auctions_cleared: u64,
    pub redaction_budgets_allocated: u64,
    pub operator_summaries_published: u64,
    pub rejected_requests: u64,
    pub total_fee_cap_micro_units: u64,
    pub total_rebate_target_micro_units: u64,
    pub total_quarantined_bond_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub session_root: String,
    pub commitment_root: String,
    pub solver_quarantine_root: String,
    pub callback_bundle_root: String,
    pub pq_attestation_root: String,
    pub protected_bundle_root: String,
    pub risk_auction_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub global_state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = domain_hash("private-l2-pq-mev-shield:empty-root", &[], 32);
        Self {
            session_root: empty.clone(),
            commitment_root: empty.clone(),
            solver_quarantine_root: empty.clone(),
            callback_bundle_root: empty.clone(),
            pq_attestation_root: empty.clone(),
            protected_bundle_root: empty.clone(),
            risk_auction_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            operator_summary_root: empty.clone(),
            global_state_root: empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MevShieldSessionRequest {
    pub session_kind: SessionKind,
    pub account_commitment: String,
    pub source_contract: String,
    pub target_contracts: Vec<String>,
    pub encrypted_policy_root: String,
    pub route_hint_root: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub solver_allowlist_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MevShieldSessionRecord {
    pub session_id: String,
    pub session_kind: SessionKind,
    pub status: SessionStatus,
    pub account_commitment: String,
    pub source_contract: String,
    pub target_contracts: Vec<String>,
    pub encrypted_policy_root: String,
    pub route_hint_root: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub solver_allowlist_root: String,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub priority_weight: u64,
    pub commitment_count: u64,
    pub callback_bundle_count: u64,
    pub attestation_count: u64,
    pub protected_bundle_count: u64,
    pub risk_auction_count: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateOrderflowCommitmentRequest {
    pub session_id: String,
    pub commitment_kind: CommitmentKind,
    pub encrypted_orderflow_root: String,
    pub nullifier_root: String,
    pub contract_call_graph_root: String,
    pub min_output_commitment: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateOrderflowCommitmentRecord {
    pub commitment_id: String,
    pub session_id: String,
    pub commitment_kind: CommitmentKind,
    pub status: CommitmentStatus,
    pub encrypted_orderflow_root: String,
    pub nullifier_root: String,
    pub contract_call_graph_root: String,
    pub min_output_commitment: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_slot: u64,
    pub expires_slot: u64,
    pub mev_fence_hash: String,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverQuarantineRequest {
    pub solver_id: String,
    pub solver_pq_key_commitment: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub session_id: Option<String>,
    pub bond_micro_units: u64,
    pub observed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverQuarantineRecord {
    pub quarantine_id: String,
    pub solver_id: String,
    pub solver_pq_key_commitment: String,
    pub status: SolverStatus,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub session_id: Option<String>,
    pub bond_micro_units: u64,
    pub observed_slot: u64,
    pub release_slot: u64,
    pub slash_amount_micro_units: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCallbackBundleRequest {
    pub session_id: String,
    pub solver_id: String,
    pub callback_contracts: Vec<String>,
    pub encrypted_callback_root: String,
    pub callback_order_root: String,
    pub replay_fence_root: String,
    pub expected_gas_micro_units: u64,
    pub sealed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCallbackBundleRecord {
    pub bundle_id: String,
    pub session_id: String,
    pub solver_id: String,
    pub status: CallbackBundleStatus,
    pub callback_contracts: Vec<String>,
    pub encrypted_callback_root: String,
    pub callback_order_root: String,
    pub replay_fence_root: String,
    pub expected_gas_micro_units: u64,
    pub sealed_slot: u64,
    pub expires_slot: u64,
    pub callback_count: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRequest {
    pub session_id: String,
    pub attestation_kind: AttestationKind,
    pub attester_id: String,
    pub pq_public_key_commitment: String,
    pub attestation_payload_root: String,
    pub signature_commitment: String,
    pub weight_bps: u64,
    pub attester_bond_micro_units: u64,
    pub attested_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub session_id: String,
    pub attestation_kind: AttestationKind,
    pub attester_id: String,
    pub pq_public_key_commitment: String,
    pub attestation_payload_root: String,
    pub signature_commitment: String,
    pub weight_bps: u64,
    pub attester_bond_micro_units: u64,
    pub attested_slot: u64,
    pub quorum_met: bool,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProtectedBundleRequest {
    pub session_id: String,
    pub solver_id: String,
    pub commitment_ids: Vec<String>,
    pub callback_bundle_ids: Vec<String>,
    pub fee_cap_micro_units: u64,
    pub sponsor_commitment: String,
    pub compression_proof_root: String,
    pub target_rebate_micro_units: u64,
    pub scheduled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProtectedBundleRecord {
    pub protected_bundle_id: String,
    pub session_id: String,
    pub solver_id: String,
    pub status: ProtectedBundleStatus,
    pub commitment_ids: Vec<String>,
    pub callback_bundle_ids: Vec<String>,
    pub fee_cap_micro_units: u64,
    pub sponsor_commitment: String,
    pub compression_proof_root: String,
    pub target_rebate_micro_units: u64,
    pub scheduled_slot: u64,
    pub effective_fee_bps: u64,
    pub low_fee_score: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskAuctionBid {
    pub bidder_id: String,
    pub sealed_bid_commitment: String,
    pub risk_capacity_micro_units: u64,
    pub requested_premium_micro_units: u64,
    pub pq_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskAuctionRequest {
    pub session_id: String,
    pub protected_bundle_id: Option<String>,
    pub risk_envelope_root: String,
    pub min_risk_capacity_micro_units: u64,
    pub max_premium_micro_units: u64,
    pub settlement_contract: String,
    pub bids: Vec<RiskAuctionBid>,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskAuctionRecord {
    pub auction_id: String,
    pub session_id: String,
    pub protected_bundle_id: Option<String>,
    pub status: RiskAuctionStatus,
    pub risk_envelope_root: String,
    pub min_risk_capacity_micro_units: u64,
    pub max_premium_micro_units: u64,
    pub settlement_contract: String,
    pub bids: Vec<RiskAuctionBid>,
    pub winning_bidder_id: Option<String>,
    pub clearing_premium_micro_units: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRequest {
    pub operator_id: String,
    pub session_id: Option<String>,
    pub redaction_policy_root: String,
    pub fields_allowed_root: String,
    pub max_redactions: u64,
    pub privacy_floor: u64,
    pub pq_authorization_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRecord {
    pub budget_id: String,
    pub operator_id: String,
    pub session_id: Option<String>,
    pub status: RedactionBudgetStatus,
    pub redaction_policy_root: String,
    pub fields_allowed_root: String,
    pub max_redactions: u64,
    pub redactions_used: u64,
    pub privacy_floor: u64,
    pub pq_authorization_root: String,
    pub opened_slot: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub operator_id: String,
    pub window_slot: u64,
    pub session_ids: Vec<String>,
    pub summary_scope_root: String,
    pub redaction_budget_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafeSummaryRecord {
    pub summary_id: String,
    pub operator_id: String,
    pub window_slot: u64,
    pub session_ids: Vec<String>,
    pub summary_scope_root: String,
    pub redaction_budget_id: Option<String>,
    pub live_sessions: u64,
    pub protected_bundles: u64,
    pub quarantined_solvers: u64,
    pub total_fee_cap_micro_units: u64,
    pub total_rebate_target_micro_units: u64,
    pub public_summary_root: String,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub mev_shield_suite: String,
    pub fee_asset_id: String,
    pub counters: Counters,
    pub roots: Roots,
    pub live_sessions: u64,
    pub quarantined_solvers: u64,
    pub active_redaction_budgets: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sessions: BTreeMap<String, MevShieldSessionRecord>,
    pub commitments: BTreeMap<String, PrivateOrderflowCommitmentRecord>,
    pub solver_quarantines: BTreeMap<String, SolverQuarantineRecord>,
    pub callback_bundles: BTreeMap<String, EncryptedCallbackBundleRecord>,
    pub pq_attestations: BTreeMap<String, PqAttestationRecord>,
    pub protected_bundles: BTreeMap<String, LowFeeProtectedBundleRecord>,
    pub risk_auctions: BTreeMap<String, RiskAuctionRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummaryRecord>,
    pub session_commitment_index: BTreeMap<String, BTreeSet<String>>,
    pub session_callback_index: BTreeMap<String, BTreeSet<String>>,
    pub session_attestation_index: BTreeMap<String, BTreeSet<String>>,
    pub session_bundle_index: BTreeMap<String, BTreeSet<String>>,
    pub solver_status: BTreeMap<String, SolverStatus>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default MEV shield config is valid")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sessions: BTreeMap::new(),
            commitments: BTreeMap::new(),
            solver_quarantines: BTreeMap::new(),
            callback_bundles: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            protected_bundles: BTreeMap::new(),
            risk_auctions: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            session_commitment_index: BTreeMap::new(),
            session_callback_index: BTreeMap::new(),
            session_attestation_index: BTreeMap::new(),
            session_bundle_index: BTreeMap::new(),
            solver_status: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn open_session(
        &mut self,
        request: MevShieldSessionRequest,
    ) -> Result<MevShieldSessionRecord> {
        self.ensure_capacity("sessions", self.sessions.len(), MAX_SESSIONS)?;
        self.validate_contract_set(&request.target_contracts)?;
        self.ensure_fee_bps(request.max_user_fee_bps)?;
        self.ensure_privacy(request.privacy_set_size)?;
        let session_id = self.session_id(&request);
        if self.sessions.contains_key(&session_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("session already exists: {session_id}"));
        }
        let mut record = MevShieldSessionRecord {
            session_id: session_id.clone(),
            session_kind: request.session_kind,
            status: SessionStatus::Open,
            account_commitment: request.account_commitment,
            source_contract: request.source_contract,
            target_contracts: request.target_contracts,
            encrypted_policy_root: request.encrypted_policy_root,
            route_hint_root: request.route_hint_root,
            max_user_fee_bps: request.max_user_fee_bps,
            privacy_set_size: request.privacy_set_size,
            solver_allowlist_root: request.solver_allowlist_root,
            opened_slot: request.opened_slot,
            expires_slot: request.opened_slot + self.config.commitment_ttl_slots,
            priority_weight: request.session_kind.priority_weight(),
            commitment_count: 0,
            callback_bundle_count: 0,
            attestation_count: 0,
            protected_bundle_count: 0,
            risk_auction_count: 0,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("session", &record);
        self.sessions.insert(session_id.clone(), record.clone());
        self.session_commitment_index
            .insert(session_id.clone(), BTreeSet::new());
        self.session_callback_index
            .insert(session_id.clone(), BTreeSet::new());
        self.session_attestation_index
            .insert(session_id.clone(), BTreeSet::new());
        self.session_bundle_index
            .insert(session_id, BTreeSet::new());
        self.counters.sessions_opened += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn commit_private_orderflow(
        &mut self,
        request: PrivateOrderflowCommitmentRequest,
    ) -> Result<PrivateOrderflowCommitmentRecord> {
        self.ensure_capacity("commitments", self.commitments.len(), MAX_COMMITMENTS)?;
        self.ensure_session_live(&request.session_id)?;
        self.ensure_privacy(request.privacy_set_size)?;
        let commitment_id = self.commitment_id(&request);
        if self.commitments.contains_key(&commitment_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("commitment already exists: {commitment_id}"));
        }
        let mev_fence_hash = domain_hash(
            "private-l2-pq-mev-shield:commitment-fence",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(request.commitment_kind.as_str()),
                HashPart::Str(&request.nullifier_root),
                HashPart::Str(&request.contract_call_graph_root),
            ],
            32,
        );
        let mut record = PrivateOrderflowCommitmentRecord {
            commitment_id: commitment_id.clone(),
            session_id: request.session_id.clone(),
            commitment_kind: request.commitment_kind,
            status: CommitmentStatus::Fenced,
            encrypted_orderflow_root: request.encrypted_orderflow_root,
            nullifier_root: request.nullifier_root,
            contract_call_graph_root: request.contract_call_graph_root,
            min_output_commitment: request.min_output_commitment,
            max_fee_micro_units: request.max_fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            submitted_slot: request.submitted_slot,
            expires_slot: request.submitted_slot + self.config.commitment_ttl_slots,
            mev_fence_hash,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("orderflow-commitment", &record);
        self.commitments
            .insert(commitment_id.clone(), record.clone());
        self.session_commitment_index
            .entry(request.session_id.clone())
            .or_default()
            .insert(commitment_id);
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::OrderflowCommitted;
            session.commitment_count += 1;
            session.record_hash = record_hash("session", session);
        }
        self.counters.commitments_accepted += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn quarantine_solver(
        &mut self,
        request: SolverQuarantineRequest,
    ) -> Result<SolverQuarantineRecord> {
        self.ensure_capacity(
            "solver_quarantines",
            self.solver_quarantines.len(),
            MAX_SOLVERS,
        )?;
        if request.bond_micro_units < self.config.min_solver_bond_micro_units {
            self.counters.rejected_requests += 1;
            return Err("solver bond below minimum quarantine bond".to_string());
        }
        if let Some(session_id) = &request.session_id {
            self.ensure_session_exists(session_id)?;
        }
        let quarantine_id = self.quarantine_id(&request);
        if self.solver_quarantines.contains_key(&quarantine_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("quarantine already exists: {quarantine_id}"));
        }
        let slash_amount_micro_units =
            bps_amount(request.bond_micro_units, self.config.slash_bps).unwrap_or(0);
        let mut record = SolverQuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            solver_id: request.solver_id.clone(),
            solver_pq_key_commitment: request.solver_pq_key_commitment,
            status: SolverStatus::Quarantined,
            reason: request.reason,
            evidence_root: request.evidence_root,
            session_id: request.session_id,
            bond_micro_units: request.bond_micro_units,
            observed_slot: request.observed_slot,
            release_slot: request.observed_slot + self.config.quarantine_ttl_slots,
            slash_amount_micro_units,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("solver-quarantine", &record);
        self.solver_status
            .insert(request.solver_id, SolverStatus::Quarantined);
        self.solver_quarantines
            .insert(quarantine_id, record.clone());
        self.counters.solvers_quarantined += 1;
        self.counters.total_quarantined_bond_micro_units = self
            .counters
            .total_quarantined_bond_micro_units
            .saturating_add(record.bond_micro_units);
        self.refresh_roots();
        Ok(record)
    }

    pub fn enqueue_encrypted_callback_bundle(
        &mut self,
        request: EncryptedCallbackBundleRequest,
    ) -> Result<EncryptedCallbackBundleRecord> {
        self.ensure_capacity(
            "callback_bundles",
            self.callback_bundles.len(),
            MAX_CALLBACK_BUNDLES,
        )?;
        self.ensure_session_live(&request.session_id)?;
        self.ensure_solver_accepts_flow(&request.solver_id)?;
        if request.callback_contracts.is_empty()
            || request.callback_contracts.len() > MAX_CALLBACKS_PER_BUNDLE
        {
            self.counters.rejected_requests += 1;
            return Err(format!(
                "callback_contracts must contain 1..={MAX_CALLBACKS_PER_BUNDLE} contracts"
            ));
        }
        let bundle_id = self.callback_bundle_id(&request);
        if self.callback_bundles.contains_key(&bundle_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("callback bundle already exists: {bundle_id}"));
        }
        let mut record = EncryptedCallbackBundleRecord {
            bundle_id: bundle_id.clone(),
            session_id: request.session_id.clone(),
            solver_id: request.solver_id,
            status: CallbackBundleStatus::Sealed,
            callback_contracts: request.callback_contracts,
            encrypted_callback_root: request.encrypted_callback_root,
            callback_order_root: request.callback_order_root,
            replay_fence_root: request.replay_fence_root,
            expected_gas_micro_units: request.expected_gas_micro_units,
            sealed_slot: request.sealed_slot,
            expires_slot: request.sealed_slot + self.config.callback_ttl_slots,
            callback_count: 0,
            record_hash: String::new(),
        };
        record.callback_count = record.callback_contracts.len() as u64;
        record.record_hash = record_hash("callback-bundle", &record);
        self.callback_bundles
            .insert(bundle_id.clone(), record.clone());
        self.session_callback_index
            .entry(request.session_id.clone())
            .or_default()
            .insert(bundle_id);
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::CallbacksSealed;
            session.callback_bundle_count += 1;
            session.record_hash = record_hash("session", session);
        }
        self.counters.callback_bundles_sealed += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_pq_attestation(
        &mut self,
        request: PqAttestationRequest,
    ) -> Result<PqAttestationRecord> {
        self.ensure_capacity(
            "pq_attestations",
            self.pq_attestations.len(),
            MAX_ATTESTATIONS,
        )?;
        self.ensure_session_exists(&request.session_id)?;
        if request.weight_bps > MAX_BPS {
            self.counters.rejected_requests += 1;
            return Err("attestation weight exceeds MAX_BPS".to_string());
        }
        if request.attester_bond_micro_units < self.config.min_attester_bond_micro_units {
            self.counters.rejected_requests += 1;
            return Err("attester bond below configured minimum".to_string());
        }
        let attestation_id = self.attestation_id(&request);
        if self.pq_attestations.contains_key(&attestation_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("attestation already exists: {attestation_id}"));
        }
        let current_weight = self.session_attestation_weight_bps(&request.session_id);
        let quorum_met =
            current_weight.saturating_add(request.weight_bps) >= self.config.quorum_bps;
        let mut record = PqAttestationRecord {
            attestation_id: attestation_id.clone(),
            session_id: request.session_id.clone(),
            attestation_kind: request.attestation_kind,
            attester_id: request.attester_id,
            pq_public_key_commitment: request.pq_public_key_commitment,
            attestation_payload_root: request.attestation_payload_root,
            signature_commitment: request.signature_commitment,
            weight_bps: request.weight_bps,
            attester_bond_micro_units: request.attester_bond_micro_units,
            attested_slot: request.attested_slot,
            quorum_met,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("pq-attestation", &record);
        self.pq_attestations
            .insert(attestation_id.clone(), record.clone());
        self.session_attestation_index
            .entry(request.session_id.clone())
            .or_default()
            .insert(attestation_id);
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            if quorum_met {
                session.status = SessionStatus::Attested;
            }
            session.attestation_count += 1;
            session.record_hash = record_hash("session", session);
        }
        self.counters.pq_attestations_recorded += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn build_low_fee_protected_bundle(
        &mut self,
        request: LowFeeProtectedBundleRequest,
    ) -> Result<LowFeeProtectedBundleRecord> {
        self.ensure_capacity(
            "protected_bundles",
            self.protected_bundles.len(),
            MAX_PROTECTED_BUNDLES,
        )?;
        self.ensure_session_live(&request.session_id)?;
        self.ensure_solver_accepts_flow(&request.solver_id)?;
        self.ensure_commitments_belong_to_session(&request.session_id, &request.commitment_ids)?;
        self.ensure_callbacks_belong_to_session(&request.session_id, &request.callback_bundle_ids)?;
        let protected_bundle_id = self.protected_bundle_id(&request);
        if self.protected_bundles.contains_key(&protected_bundle_id) {
            self.counters.rejected_requests += 1;
            return Err(format!(
                "protected bundle already exists: {protected_bundle_id}"
            ));
        }
        let effective_fee_bps = fee_bps_for_bundle(
            request.fee_cap_micro_units,
            request.target_rebate_micro_units,
        );
        self.ensure_fee_bps(effective_fee_bps)?;
        let low_fee_score = low_fee_score(effective_fee_bps, self.config.target_rebate_bps);
        let mut record = LowFeeProtectedBundleRecord {
            protected_bundle_id: protected_bundle_id.clone(),
            session_id: request.session_id.clone(),
            solver_id: request.solver_id,
            status: ProtectedBundleStatus::FeeCapped,
            commitment_ids: request.commitment_ids,
            callback_bundle_ids: request.callback_bundle_ids,
            fee_cap_micro_units: request.fee_cap_micro_units,
            sponsor_commitment: request.sponsor_commitment,
            compression_proof_root: request.compression_proof_root,
            target_rebate_micro_units: request.target_rebate_micro_units,
            scheduled_slot: request.scheduled_slot,
            effective_fee_bps,
            low_fee_score,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("protected-bundle", &record);
        self.protected_bundles
            .insert(protected_bundle_id.clone(), record.clone());
        self.session_bundle_index
            .entry(request.session_id.clone())
            .or_default()
            .insert(protected_bundle_id);
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::Bundled;
            session.protected_bundle_count += 1;
            session.record_hash = record_hash("session", session);
        }
        self.counters.low_fee_bundles_built += 1;
        self.counters.total_fee_cap_micro_units = self
            .counters
            .total_fee_cap_micro_units
            .saturating_add(record.fee_cap_micro_units);
        self.counters.total_rebate_target_micro_units = self
            .counters
            .total_rebate_target_micro_units
            .saturating_add(record.target_rebate_micro_units);
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_risk_auction(&mut self, request: RiskAuctionRequest) -> Result<RiskAuctionRecord> {
        self.ensure_capacity("risk_auctions", self.risk_auctions.len(), MAX_RISK_AUCTIONS)?;
        self.ensure_session_live(&request.session_id)?;
        if let Some(bundle_id) = &request.protected_bundle_id {
            self.ensure_protected_bundle_belongs_to_session(&request.session_id, bundle_id)?;
        }
        if request.bids.len() > MAX_BIDS_PER_AUCTION {
            self.counters.rejected_requests += 1;
            return Err(format!("risk auction exceeds {MAX_BIDS_PER_AUCTION} bids"));
        }
        if request.min_risk_capacity_micro_units < self.config.min_auction_bond_micro_units {
            self.counters.rejected_requests += 1;
            return Err("risk capacity below configured auction bond minimum".to_string());
        }
        let auction_id = self.risk_auction_id(&request);
        if self.risk_auctions.contains_key(&auction_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("risk auction already exists: {auction_id}"));
        }
        let winner = select_winning_bid(
            &request.bids,
            request.min_risk_capacity_micro_units,
            request.max_premium_micro_units,
        );
        let (status, winning_bidder_id, clearing_premium_micro_units) = match winner {
            Some(bid) => (
                RiskAuctionStatus::Cleared,
                Some(bid.bidder_id.clone()),
                bid.requested_premium_micro_units,
            ),
            None => (RiskAuctionStatus::Open, None, 0),
        };
        let mut record = RiskAuctionRecord {
            auction_id: auction_id.clone(),
            session_id: request.session_id.clone(),
            protected_bundle_id: request.protected_bundle_id,
            status,
            risk_envelope_root: request.risk_envelope_root,
            min_risk_capacity_micro_units: request.min_risk_capacity_micro_units,
            max_premium_micro_units: request.max_premium_micro_units,
            settlement_contract: request.settlement_contract,
            bids: request.bids,
            winning_bidder_id,
            clearing_premium_micro_units,
            opened_slot: request.opened_slot,
            expires_slot: request.opened_slot + self.config.risk_auction_ttl_slots,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("risk-auction", &record);
        self.risk_auctions.insert(auction_id, record.clone());
        if let Some(session) = self.sessions.get_mut(&request.session_id) {
            session.status = SessionStatus::RiskAuctioned;
            session.risk_auction_count += 1;
            session.record_hash = record_hash("session", session);
        }
        self.counters.risk_auctions_opened += 1;
        if record.status == RiskAuctionStatus::Cleared {
            self.counters.risk_auctions_cleared += 1;
        }
        self.refresh_roots();
        Ok(record)
    }

    pub fn settle_risk_auction(&mut self, auction_id: &str) -> Result<RiskAuctionRecord> {
        let record = self
            .risk_auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown risk auction: {auction_id}"))?;
        if record.status != RiskAuctionStatus::Cleared {
            self.counters.rejected_requests += 1;
            return Err("only cleared risk auctions can settle".to_string());
        }
        record.status = RiskAuctionStatus::Settled;
        record.record_hash = record_hash("risk-auction", record);
        let output = record.clone();
        self.refresh_roots();
        Ok(output)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudgetRecord> {
        self.ensure_capacity(
            "redaction_budgets",
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
        )?;
        if let Some(session_id) = &request.session_id {
            self.ensure_session_exists(session_id)?;
        }
        if request.max_redactions == 0
            || request.max_redactions > self.config.max_redactions_per_operator
        {
            self.counters.rejected_requests += 1;
            return Err("max_redactions outside configured operator budget".to_string());
        }
        if request.privacy_floor < self.config.min_privacy_set_size {
            self.counters.rejected_requests += 1;
            return Err("redaction privacy floor below configured minimum".to_string());
        }
        let budget_id = self.redaction_budget_id(&request);
        if self.redaction_budgets.contains_key(&budget_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("redaction budget already exists: {budget_id}"));
        }
        let mut record = RedactionBudgetRecord {
            budget_id: budget_id.clone(),
            operator_id: request.operator_id,
            session_id: request.session_id,
            status: RedactionBudgetStatus::Active,
            redaction_policy_root: request.redaction_policy_root,
            fields_allowed_root: request.fields_allowed_root,
            max_redactions: request.max_redactions,
            redactions_used: 0,
            privacy_floor: request.privacy_floor,
            pq_authorization_root: request.pq_authorization_root,
            opened_slot: request.opened_slot,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("redaction-budget", &record);
        self.redaction_budgets.insert(budget_id, record.clone());
        self.counters.redaction_budgets_allocated += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn operator_safe_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSafeSummaryRecord> {
        self.ensure_capacity(
            "operator_summaries",
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
        )?;
        for session_id in &request.session_ids {
            self.ensure_session_exists(session_id)?;
        }
        if let Some(budget_id) = &request.redaction_budget_id {
            let budget = self
                .redaction_budgets
                .get_mut(budget_id)
                .ok_or_else(|| format!("unknown redaction budget: {budget_id}"))?;
            if budget.status != RedactionBudgetStatus::Active {
                self.counters.rejected_requests += 1;
                return Err("redaction budget is not active".to_string());
            }
            budget.redactions_used = budget.redactions_used.saturating_add(1);
            if budget.redactions_used >= budget.max_redactions {
                budget.status = RedactionBudgetStatus::Exhausted;
            }
            budget.record_hash = record_hash("redaction-budget", budget);
        }
        let summary_id = self.operator_summary_id(&request);
        if self.operator_summaries.contains_key(&summary_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("operator summary already exists: {summary_id}"));
        }
        let session_set = request.session_ids.iter().cloned().collect::<BTreeSet<_>>();
        let live_sessions = request
            .session_ids
            .iter()
            .filter_map(|id| self.sessions.get(id))
            .filter(|session| session.status.live())
            .count() as u64;
        let protected_bundles = self
            .protected_bundles
            .values()
            .filter(|bundle| session_set.contains(&bundle.session_id))
            .count() as u64;
        let quarantined_solvers = self
            .solver_quarantines
            .values()
            .filter(|record| {
                record.status == SolverStatus::Quarantined
                    && record
                        .session_id
                        .as_ref()
                        .map(|id| session_set.contains(id))
                        .unwrap_or(true)
            })
            .count() as u64;
        let public_summary_root = domain_hash(
            "private-l2-pq-mev-shield:operator-safe-summary",
            &[
                HashPart::Str(&request.operator_id),
                HashPart::U64(request.window_slot),
                HashPart::U64(live_sessions),
                HashPart::U64(protected_bundles),
                HashPart::U64(quarantined_solvers),
            ],
            32,
        );
        let mut record = OperatorSafeSummaryRecord {
            summary_id: summary_id.clone(),
            operator_id: request.operator_id,
            window_slot: request.window_slot,
            session_ids: request.session_ids,
            summary_scope_root: request.summary_scope_root,
            redaction_budget_id: request.redaction_budget_id,
            live_sessions,
            protected_bundles,
            quarantined_solvers,
            total_fee_cap_micro_units: self.counters.total_fee_cap_micro_units,
            total_rebate_target_micro_units: self.counters.total_rebate_target_micro_units,
            public_summary_root,
            record_hash: String::new(),
        };
        record.record_hash = record_hash("operator-summary", &record);
        self.operator_summaries.insert(summary_id, record.clone());
        self.counters.operator_summaries_published += 1;
        self.refresh_roots();
        Ok(record)
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord {
            chain_id: self.config.chain_id.clone(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            mev_shield_suite: MEV_SHIELD_SUITE.to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            counters: self.counters.clone(),
            roots: self.roots.clone(),
            live_sessions: self
                .sessions
                .values()
                .filter(|session| session.status.live())
                .count() as u64,
            quarantined_solvers: self
                .solver_status
                .values()
                .filter(|status| **status == SolverStatus::Quarantined)
                .count() as u64,
            active_redaction_budgets: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.status == RedactionBudgetStatus::Active)
                .count() as u64,
            state_root: self.state_root(),
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.roots.session_root),
                HashPart::Str(&self.roots.commitment_root),
                HashPart::Str(&self.roots.solver_quarantine_root),
                HashPart::Str(&self.roots.callback_bundle_root),
                HashPart::Str(&self.roots.pq_attestation_root),
                HashPart::Str(&self.roots.protected_bundle_root),
                HashPart::Str(&self.roots.risk_auction_root),
                HashPart::Str(&self.roots.redaction_budget_root),
                HashPart::Str(&self.roots.operator_summary_root),
                HashPart::U64(self.counters.sessions_opened),
                HashPart::U64(self.counters.commitments_accepted),
                HashPart::U64(self.counters.low_fee_bundles_built),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) -> Roots {
        self.roots.session_root = map_root("private-l2-pq-mev-shield:sessions", &self.sessions);
        self.roots.commitment_root =
            map_root("private-l2-pq-mev-shield:commitments", &self.commitments);
        self.roots.solver_quarantine_root = map_root(
            "private-l2-pq-mev-shield:solver-quarantines",
            &self.solver_quarantines,
        );
        self.roots.callback_bundle_root = map_root(
            "private-l2-pq-mev-shield:callback-bundles",
            &self.callback_bundles,
        );
        self.roots.pq_attestation_root = map_root(
            "private-l2-pq-mev-shield:pq-attestations",
            &self.pq_attestations,
        );
        self.roots.protected_bundle_root = map_root(
            "private-l2-pq-mev-shield:protected-bundles",
            &self.protected_bundles,
        );
        self.roots.risk_auction_root = map_root(
            "private-l2-pq-mev-shield:risk-auctions",
            &self.risk_auctions,
        );
        self.roots.redaction_budget_root = map_root(
            "private-l2-pq-mev-shield:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "private-l2-pq-mev-shield:operator-summaries",
            &self.operator_summaries,
        );
        self.roots.global_state_root = self.state_root();
        self.roots.clone()
    }

    fn ensure_capacity(&mut self, name: &str, len: usize, max: usize) -> Result<()> {
        if len >= max {
            self.counters.rejected_requests += 1;
            return Err(format!("{name} capacity exhausted at {max}"));
        }
        Ok(())
    }

    fn ensure_fee_bps(&mut self, fee_bps: u64) -> Result<()> {
        if fee_bps > self.config.max_user_fee_bps {
            self.counters.rejected_requests += 1;
            return Err(format!(
                "fee bps {fee_bps} exceeds max_user_fee_bps {}",
                self.config.max_user_fee_bps
            ));
        }
        Ok(())
    }

    fn ensure_privacy(&mut self, privacy_set_size: u64) -> Result<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            self.counters.rejected_requests += 1;
            return Err(format!(
                "privacy set {privacy_set_size} below minimum {}",
                self.config.min_privacy_set_size
            ));
        }
        Ok(())
    }

    fn validate_contract_set(&mut self, contracts: &[String]) -> Result<()> {
        if contracts.is_empty() || contracts.len() > MAX_CONTRACTS_PER_SESSION {
            self.counters.rejected_requests += 1;
            return Err(format!(
                "target_contracts must contain 1..={MAX_CONTRACTS_PER_SESSION} contracts"
            ));
        }
        let unique = contracts.iter().collect::<BTreeSet<_>>();
        if unique.len() != contracts.len() {
            self.counters.rejected_requests += 1;
            return Err("target_contracts must be unique".to_string());
        }
        Ok(())
    }

    fn ensure_session_exists(&mut self, session_id: &str) -> Result<()> {
        if !self.sessions.contains_key(session_id) {
            self.counters.rejected_requests += 1;
            return Err(format!("unknown session: {session_id}"));
        }
        Ok(())
    }

    fn ensure_session_live(&mut self, session_id: &str) -> Result<()> {
        match self.sessions.get(session_id) {
            Some(session) if session.status.live() => Ok(()),
            Some(session) => {
                self.counters.rejected_requests += 1;
                Err(format!(
                    "session {session_id} is not live: {}",
                    session.status.as_str()
                ))
            }
            None => {
                self.counters.rejected_requests += 1;
                Err(format!("unknown session: {session_id}"))
            }
        }
    }

    fn ensure_solver_accepts_flow(&mut self, solver_id: &str) -> Result<()> {
        let status = self
            .solver_status
            .get(solver_id)
            .copied()
            .unwrap_or(SolverStatus::Active);
        if !status.accepts_flow() {
            self.counters.rejected_requests += 1;
            return Err(format!(
                "solver {solver_id} cannot accept flow while {}",
                status.as_str()
            ));
        }
        Ok(())
    }

    fn ensure_commitments_belong_to_session(
        &mut self,
        session_id: &str,
        commitment_ids: &[String],
    ) -> Result<()> {
        if commitment_ids.is_empty() {
            self.counters.rejected_requests += 1;
            return Err("protected bundle requires at least one commitment".to_string());
        }
        for commitment_id in commitment_ids {
            match self.commitments.get(commitment_id) {
                Some(record) if record.session_id == session_id => {}
                Some(_) => {
                    self.counters.rejected_requests += 1;
                    return Err(format!(
                        "commitment {commitment_id} does not belong to session {session_id}"
                    ));
                }
                None => {
                    self.counters.rejected_requests += 1;
                    return Err(format!("unknown commitment: {commitment_id}"));
                }
            }
        }
        Ok(())
    }

    fn ensure_callbacks_belong_to_session(
        &mut self,
        session_id: &str,
        callback_bundle_ids: &[String],
    ) -> Result<()> {
        for bundle_id in callback_bundle_ids {
            match self.callback_bundles.get(bundle_id) {
                Some(record) if record.session_id == session_id => {}
                Some(_) => {
                    self.counters.rejected_requests += 1;
                    return Err(format!(
                        "callback bundle {bundle_id} does not belong to session {session_id}"
                    ));
                }
                None => {
                    self.counters.rejected_requests += 1;
                    return Err(format!("unknown callback bundle: {bundle_id}"));
                }
            }
        }
        Ok(())
    }

    fn ensure_protected_bundle_belongs_to_session(
        &mut self,
        session_id: &str,
        protected_bundle_id: &str,
    ) -> Result<()> {
        match self.protected_bundles.get(protected_bundle_id) {
            Some(record) if record.session_id == session_id => Ok(()),
            Some(_) => {
                self.counters.rejected_requests += 1;
                Err(format!(
                    "protected bundle {protected_bundle_id} does not belong to session {session_id}"
                ))
            }
            None => {
                self.counters.rejected_requests += 1;
                Err(format!("unknown protected bundle: {protected_bundle_id}"))
            }
        }
    }

    fn session_attestation_weight_bps(&self, session_id: &str) -> u64 {
        self.session_attestation_index
            .get(session_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.pq_attestations.get(id))
            .map(|record| record.weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    fn session_id(&self, request: &MevShieldSessionRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:session-id",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(request.session_kind.as_str()),
                HashPart::Str(&request.account_commitment),
                HashPart::Str(&request.source_contract),
                HashPart::Str(&request.encrypted_policy_root),
                HashPart::U64(request.opened_slot),
            ],
            16,
        )
    }

    fn commitment_id(&self, request: &PrivateOrderflowCommitmentRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:commitment-id",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(request.commitment_kind.as_str()),
                HashPart::Str(&request.encrypted_orderflow_root),
                HashPart::Str(&request.nullifier_root),
                HashPart::U64(request.submitted_slot),
            ],
            16,
        )
    }

    fn quarantine_id(&self, request: &SolverQuarantineRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:quarantine-id",
            &[
                HashPart::Str(&request.solver_id),
                HashPart::Str(request.reason.as_str()),
                HashPart::Str(&request.evidence_root),
                HashPart::U64(request.observed_slot),
            ],
            16,
        )
    }

    fn callback_bundle_id(&self, request: &EncryptedCallbackBundleRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:callback-bundle-id",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(&request.solver_id),
                HashPart::Str(&request.encrypted_callback_root),
                HashPart::Str(&request.callback_order_root),
                HashPart::U64(request.sealed_slot),
            ],
            16,
        )
    }

    fn attestation_id(&self, request: &PqAttestationRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:attestation-id",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(request.attestation_kind.as_str()),
                HashPart::Str(&request.attester_id),
                HashPart::Str(&request.signature_commitment),
                HashPart::U64(request.attested_slot),
            ],
            16,
        )
    }

    fn protected_bundle_id(&self, request: &LowFeeProtectedBundleRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:protected-bundle-id",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(&request.solver_id),
                HashPart::Str(&request.sponsor_commitment),
                HashPart::Str(&request.compression_proof_root),
                HashPart::U64(request.scheduled_slot),
            ],
            16,
        )
    }

    fn risk_auction_id(&self, request: &RiskAuctionRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:risk-auction-id",
            &[
                HashPart::Str(&request.session_id),
                HashPart::Str(&request.risk_envelope_root),
                HashPart::Str(&request.settlement_contract),
                HashPart::U64(request.opened_slot),
            ],
            16,
        )
    }

    fn redaction_budget_id(&self, request: &RedactionBudgetRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:redaction-budget-id",
            &[
                HashPart::Str(&request.operator_id),
                HashPart::Str(&request.redaction_policy_root),
                HashPart::Str(&request.fields_allowed_root),
                HashPart::U64(request.opened_slot),
            ],
            16,
        )
    }

    fn operator_summary_id(&self, request: &OperatorSummaryRequest) -> String {
        domain_hash(
            "private-l2-pq-mev-shield:operator-summary-id",
            &[
                HashPart::Str(&request.operator_id),
                HashPart::Str(&request.summary_scope_root),
                HashPart::U64(request.window_slot),
            ],
            16,
        )
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default()).expect("devnet config is valid");
    let session = state
        .open_session(MevShieldSessionRequest {
            session_kind: SessionKind::ConfidentialSwap,
            account_commitment: sample_hash("account", 1),
            source_contract: "confidential-amm-router.devnet".to_string(),
            target_contracts: vec![
                "confidential-stableswap.devnet".to_string(),
                "private-lending-pool.devnet".to_string(),
                "low-fee-paymaster.devnet".to_string(),
            ],
            encrypted_policy_root: sample_hash("policy", 1),
            route_hint_root: sample_hash("route-hint", 1),
            max_user_fee_bps: 12,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            solver_allowlist_root: sample_hash("solver-allowlist", 1),
            opened_slot: DEVNET_SLOT,
        })
        .expect("devnet session opens");
    let commitment = state
        .commit_private_orderflow(PrivateOrderflowCommitmentRequest {
            session_id: session.session_id.clone(),
            commitment_kind: CommitmentKind::IntentEnvelope,
            encrypted_orderflow_root: sample_hash("encrypted-orderflow", 1),
            nullifier_root: sample_hash("nullifier", 1),
            contract_call_graph_root: sample_hash("call-graph", 1),
            min_output_commitment: sample_hash("min-output", 1),
            max_fee_micro_units: 7_500,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet commitment accepted");
    let callback = state
        .enqueue_encrypted_callback_bundle(EncryptedCallbackBundleRequest {
            session_id: session.session_id.clone(),
            solver_id: "solver-fast-pq-01".to_string(),
            callback_contracts: vec![
                "confidential-stableswap.devnet".to_string(),
                "low-fee-paymaster.devnet".to_string(),
            ],
            encrypted_callback_root: sample_hash("callback-root", 1),
            callback_order_root: sample_hash("callback-order", 1),
            replay_fence_root: sample_hash("replay-fence", 1),
            expected_gas_micro_units: 6_400,
            sealed_slot: DEVNET_SLOT + 2,
        })
        .expect("devnet callback sealed");
    state
        .record_pq_attestation(PqAttestationRequest {
            session_id: session.session_id.clone(),
            attestation_kind: AttestationKind::BundleIntegrity,
            attester_id: "attester-ml-dsa-01".to_string(),
            pq_public_key_commitment: sample_hash("pq-key", 1),
            attestation_payload_root: sample_hash("attestation-payload", 1),
            signature_commitment: sample_hash("signature", 1),
            weight_bps: DEFAULT_QUORUM_BPS,
            attester_bond_micro_units: DEFAULT_MIN_ATTESTER_BOND_MICRO_UNITS,
            attested_slot: DEVNET_SLOT + 3,
        })
        .expect("devnet attestation recorded");
    let protected_bundle = state
        .build_low_fee_protected_bundle(LowFeeProtectedBundleRequest {
            session_id: session.session_id.clone(),
            solver_id: "solver-fast-pq-01".to_string(),
            commitment_ids: vec![commitment.commitment_id],
            callback_bundle_ids: vec![callback.bundle_id],
            fee_cap_micro_units: 7_500,
            sponsor_commitment: sample_hash("sponsor", 1),
            compression_proof_root: sample_hash("compression", 1),
            target_rebate_micro_units: 1_500,
            scheduled_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet protected bundle built");
    state
        .open_risk_auction(RiskAuctionRequest {
            session_id: session.session_id.clone(),
            protected_bundle_id: Some(protected_bundle.protected_bundle_id),
            risk_envelope_root: sample_hash("risk-envelope", 1),
            min_risk_capacity_micro_units: DEFAULT_MIN_AUCTION_BOND_MICRO_UNITS,
            max_premium_micro_units: 12_000,
            settlement_contract: "private-risk-vault.devnet".to_string(),
            bids: vec![
                RiskAuctionBid {
                    bidder_id: "risk-maker-01".to_string(),
                    sealed_bid_commitment: sample_hash("sealed-bid", 1),
                    risk_capacity_micro_units: 8_000_000,
                    requested_premium_micro_units: 8_500,
                    pq_signature_commitment: sample_hash("bid-sig", 1),
                },
                RiskAuctionBid {
                    bidder_id: "risk-maker-02".to_string(),
                    sealed_bid_commitment: sample_hash("sealed-bid", 2),
                    risk_capacity_micro_units: 6_000_000,
                    requested_premium_micro_units: 7_200,
                    pq_signature_commitment: sample_hash("bid-sig", 2),
                },
            ],
            opened_slot: DEVNET_SLOT + 5,
        })
        .expect("devnet risk auction opens");
    let budget = state
        .allocate_redaction_budget(RedactionBudgetRequest {
            operator_id: "operator-safe-summary-01".to_string(),
            session_id: Some(session.session_id.clone()),
            redaction_policy_root: sample_hash("redaction-policy", 1),
            fields_allowed_root: sample_hash("fields-allowed", 1),
            max_redactions: 32,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_authorization_root: sample_hash("redaction-pq-auth", 1),
            opened_slot: DEVNET_SLOT + 6,
        })
        .expect("devnet redaction budget allocated");
    state
        .operator_safe_summary(OperatorSummaryRequest {
            operator_id: "operator-safe-summary-01".to_string(),
            window_slot: DEVNET_SLOT + 7,
            session_ids: vec![session.session_id],
            summary_scope_root: sample_hash("summary-scope", 1),
            redaction_budget_id: Some(budget.budget_id),
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let session = state
        .open_session(MevShieldSessionRequest {
            session_kind: SessionKind::LiquidationBackstop,
            account_commitment: sample_hash("account", 2),
            source_contract: "private-lending-liquidator.devnet".to_string(),
            target_contracts: vec![
                "private-lending-pool.devnet".to_string(),
                "confidential-oracle-feed.devnet".to_string(),
                "risk-backstop-vault.devnet".to_string(),
            ],
            encrypted_policy_root: sample_hash("policy", 2),
            route_hint_root: sample_hash("route-hint", 2),
            max_user_fee_bps: 10,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            solver_allowlist_root: sample_hash("solver-allowlist", 2),
            opened_slot: DEVNET_SLOT + 16,
        })
        .expect("demo session opens");
    state
        .quarantine_solver(SolverQuarantineRequest {
            solver_id: "solver-watchlisted-07".to_string(),
            solver_pq_key_commitment: sample_hash("solver-pq-key", 7),
            reason: QuarantineReason::LatencyLeakage,
            evidence_root: sample_hash("quarantine-evidence", 7),
            session_id: Some(session.session_id.clone()),
            bond_micro_units: DEFAULT_MIN_SOLVER_BOND_MICRO_UNITS,
            observed_slot: DEVNET_SLOT + 17,
        })
        .expect("demo solver quarantine recorded");
    state
        .commit_private_orderflow(PrivateOrderflowCommitmentRequest {
            session_id: session.session_id,
            commitment_kind: CommitmentKind::PrivateRiskLimit,
            encrypted_orderflow_root: sample_hash("encrypted-orderflow", 2),
            nullifier_root: sample_hash("nullifier", 2),
            contract_call_graph_root: sample_hash("call-graph", 2),
            min_output_commitment: sample_hash("min-output", 2),
            max_fee_micro_units: 8_100,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_slot: DEVNET_SLOT + 18,
        })
        .expect("demo orderflow commitment accepted");
    state.refresh_roots();
    state
}

fn map_root<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_hash<T: Serialize>(label: &str, record: &T) -> String {
    let value = serde_json::to_value(record).unwrap_or_else(|_| json!({ "record": "invalid" }));
    domain_hash(
        &format!("private-l2-pq-mev-shield:{label}:record-hash"),
        &[HashPart::Json(&value)],
        32,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-pq-mev-shield:devnet-sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn bps_amount(amount: u64, bps: u64) -> Option<u64> {
    amount.checked_mul(bps)?.checked_div(MAX_BPS)
}

fn fee_bps_for_bundle(fee_cap_micro_units: u64, target_rebate_micro_units: u64) -> u64 {
    if fee_cap_micro_units == 0 {
        return 0;
    }
    let retained_fee = fee_cap_micro_units.saturating_sub(target_rebate_micro_units);
    retained_fee
        .saturating_mul(MAX_BPS)
        .checked_div(fee_cap_micro_units)
        .unwrap_or(MAX_BPS)
}

fn low_fee_score(effective_fee_bps: u64, target_rebate_bps: u64) -> u64 {
    let fee_component = MAX_BPS.saturating_sub(effective_fee_bps.min(MAX_BPS));
    let rebate_component = target_rebate_bps.min(MAX_BPS);
    fee_component.saturating_add(rebate_component).min(MAX_BPS)
}

fn select_winning_bid(
    bids: &[RiskAuctionBid],
    min_risk_capacity_micro_units: u64,
    max_premium_micro_units: u64,
) -> Option<&RiskAuctionBid> {
    bids.iter()
        .filter(|bid| {
            bid.risk_capacity_micro_units >= min_risk_capacity_micro_units
                && bid.requested_premium_micro_units <= max_premium_micro_units
        })
        .min_by(|left, right| {
            left.requested_premium_micro_units
                .cmp(&right.requested_premium_micro_units)
                .then_with(|| {
                    right
                        .risk_capacity_micro_units
                        .cmp(&left.risk_capacity_micro_units)
                })
                .then_with(|| left.bidder_id.cmp(&right.bidder_id))
        })
}
