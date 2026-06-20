use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialRecursiveFraudProofBondMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-recursive-fraud-proof-bond-market-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_RECURSIVE_FRAUD_PROOF_BOND_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f";
pub const RECURSIVE_PROOF_SUITE: &str = "recursive-fraud-proof-commitment-tree-v1";
pub const BOND_MARKET_SUITE: &str = "confidential-fraud-proof-bond-auction-root-v1";
pub const REDACTION_SUITE: &str = "operator-safe-fraud-proof-redaction-budget-root-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BOND_ASSET_ID: &str = "confidential-bond-note-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_CHALLENGE_WINDOW_SLOTS: u64 = 512;
pub const DEFAULT_RECURSION_DEPTH_LIMIT: u16 = 32;
pub const DEFAULT_MIN_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_MAX_BOND_FEE_BPS: u64 = 16;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ATTESTATION_QUORUM_BPS: u64 = 8_200;
pub const DEFAULT_SLASHING_PENALTY_BPS: u64 = 2_500;
pub const DEFAULT_MAX_DISPUTE_RISK_BPS: u64 = 2_400;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_MARKETS: usize = 262_144;
pub const MAX_BONDERS: usize = 524_288;
pub const MAX_CHALLENGES: usize = 1_048_576;
pub const MAX_PROOF_SEGMENTS: usize = 4_194_304;
pub const MAX_BOND_QUOTES: usize = 2_097_152;
pub const MAX_SETTLEMENTS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_REDACTION_BUDGETS: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_SEGMENTS_PER_CHALLENGE: usize = 1024;
pub const DEVNET_EPOCH: u64 = 7_296;
pub const DEVNET_SLOT: u64 = 55;
pub const DEVNET_L2_HEIGHT: u64 = 2_845_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeKind {
    InvalidStateTransition,
    InvalidWithdrawal,
    DataAvailabilityWithholding,
    BridgeReserveMismatch,
    SequencerEquivocation,
    ContractExecutionFault,
    OracleFeedFault,
    PrivacyRegression,
}

impl DisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidStateTransition => "invalid_state_transition",
            Self::InvalidWithdrawal => "invalid_withdrawal",
            Self::DataAvailabilityWithholding => "data_availability_withholding",
            Self::BridgeReserveMismatch => "bridge_reserve_mismatch",
            Self::SequencerEquivocation => "sequencer_equivocation",
            Self::ContractExecutionFault => "contract_execution_fault",
            Self::OracleFeedFault => "oracle_feed_fault",
            Self::PrivacyRegression => "privacy_regression",
        }
    }

    pub fn base_risk_bps(self) -> u64 {
        match self {
            Self::InvalidStateTransition => 2_200,
            Self::InvalidWithdrawal => 2_400,
            Self::DataAvailabilityWithholding => 1_900,
            Self::BridgeReserveMismatch => 2_100,
            Self::SequencerEquivocation => 2_300,
            Self::ContractExecutionFault => 1_700,
            Self::OracleFeedFault => 1_500,
            Self::PrivacyRegression => 2_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Draft,
    Open,
    Bonding,
    Challenging,
    Settling,
    Settled,
    Paused,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BonderStatus {
    Candidate,
    Active,
    Throttled,
    Quarantined,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Submitted,
    BondQuoted,
    Segmented,
    Recursed,
    Attested,
    Settled,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSegmentStatus {
    Reserved,
    WitnessFetched,
    RecursionCommitted,
    Verified,
    Disputed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignatureVerified,
    BondEscrowed,
    SegmentWitnessAvailable,
    RecursiveAccumulatorValid,
    FraudClaimConsistent,
    FeeCapObserved,
    PrivacyFloorSatisfied,
    SettlementSafe,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureVerified => "pq_signature_verified",
            Self::BondEscrowed => "bond_escrowed",
            Self::SegmentWitnessAvailable => "segment_witness_available",
            Self::RecursiveAccumulatorValid => "recursive_accumulator_valid",
            Self::FraudClaimConsistent => "fraud_claim_consistent",
            Self::FeeCapObserved => "fee_cap_observed",
            Self::PrivacyFloorSatisfied => "privacy_floor_satisfied",
            Self::SettlementSafe => "settlement_safe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    AcceptChallenge,
    RejectChallenge,
    SlashBonder,
    SlashDefender,
    RequireMoreSegments,
    ExtendWindow,
    EmergencyPause,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptChallenge => "accept_challenge",
            Self::RejectChallenge => "reject_challenge",
            Self::SlashBonder => "slash_bonder",
            Self::SlashDefender => "slash_defender",
            Self::RequireMoreSegments => "require_more_segments",
            Self::ExtendWindow => "extend_window",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub recursive_proof_suite: String,
    pub bond_market_suite: String,
    pub redaction_suite: String,
    pub fee_asset_id: String,
    pub bond_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub challenge_window_slots: u64,
    pub recursion_depth_limit: u16,
    pub min_bond_micro_units: u64,
    pub max_bond_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_attestation_quorum_bps: u64,
    pub strong_attestation_quorum_bps: u64,
    pub slashing_penalty_bps: u64,
    pub max_dispute_risk_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            recursive_proof_suite: RECURSIVE_PROOF_SUITE.to_string(),
            bond_market_suite: BOND_MARKET_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            bond_asset_id: DEFAULT_BOND_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            recursion_depth_limit: DEFAULT_RECURSION_DEPTH_LIMIT,
            min_bond_micro_units: DEFAULT_MIN_BOND_MICRO_UNITS,
            max_bond_fee_bps: DEFAULT_MAX_BOND_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            strong_attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
            slashing_penalty_bps: DEFAULT_SLASHING_PENALTY_BPS,
            max_dispute_risk_bps: DEFAULT_MAX_DISPUTE_RISK_BPS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_auth_suite, "pq_auth_suite")?;
        ensure_non_empty(&self.recursive_proof_suite, "recursive_proof_suite")?;
        ensure_non_empty(&self.bond_market_suite, "bond_market_suite")?;
        ensure_non_empty(&self.redaction_suite, "redaction_suite")?;
        ensure_non_empty(&self.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&self.bond_asset_id, "bond_asset_id")?;
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target_privacy_set_size must be >= min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below configured target".to_string());
        }
        if self.challenge_window_slots == 0 {
            return Err("challenge_window_slots must be non-zero".to_string());
        }
        if self.recursion_depth_limit == 0 {
            return Err("recursion_depth_limit must be non-zero".to_string());
        }
        if self.min_bond_micro_units == 0 {
            return Err("min_bond_micro_units must be non-zero".to_string());
        }
        ensure_bps(self.max_bond_fee_bps, "max_bond_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        ensure_bps(
            self.min_attestation_quorum_bps,
            "min_attestation_quorum_bps",
        )?;
        ensure_bps(
            self.strong_attestation_quorum_bps,
            "strong_attestation_quorum_bps",
        )?;
        ensure_bps(self.slashing_penalty_bps, "slashing_penalty_bps")?;
        ensure_bps(self.max_dispute_risk_bps, "max_dispute_risk_bps")?;
        if self.strong_attestation_quorum_bps < self.min_attestation_quorum_bps {
            return Err(
                "strong_attestation_quorum_bps must be >= min_attestation_quorum_bps".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub bonders: u64,
    pub challenges: u64,
    pub proof_segments: u64,
    pub bond_quotes: u64,
    pub settlements: u64,
    pub attestations: u64,
    pub rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub slashed_bonders: u64,
    pub slashed_defenders: u64,
    pub paused_markets: u64,
    pub accepted_challenges: u64,
    pub rejected_challenges: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets,
            "bonders": self.bonders,
            "challenges": self.challenges,
            "proof_segments": self.proof_segments,
            "bond_quotes": self.bond_quotes,
            "settlements": self.settlements,
            "attestations": self.attestations,
            "rebates": self.rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "slashed_bonders": self.slashed_bonders,
            "slashed_defenders": self.slashed_defenders,
            "paused_markets": self.paused_markets,
            "accepted_challenges": self.accepted_challenges,
            "rejected_challenges": self.rejected_challenges,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub bonder_root: String,
    pub challenge_root: String,
    pub proof_segment_root: String,
    pub bond_quote_root: String,
    pub settlement_root: String,
    pub attestation_root: String,
    pub rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = domain_hash("recursive-fraud-proof-bond-market:empty-root", &[], 32);
        Self {
            market_root: empty.clone(),
            bonder_root: empty.clone(),
            challenge_root: empty.clone(),
            proof_segment_root: empty.clone(),
            bond_quote_root: empty.clone(),
            settlement_root: empty.clone(),
            attestation_root: empty.clone(),
            rebate_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            operator_summary_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "bonder_root": self.bonder_root,
            "challenge_root": self.challenge_root,
            "proof_segment_root": self.proof_segment_root,
            "bond_quote_root": self.bond_quote_root,
            "settlement_root": self.settlement_root,
            "attestation_root": self.attestation_root,
            "rebate_root": self.rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Market {
    pub market_id: String,
    pub rollup_id: String,
    pub settlement_contract_root: String,
    pub allowed_dispute_kinds: BTreeSet<DisputeKind>,
    pub min_bond_micro_units: u64,
    pub max_bond_fee_bps: u64,
    pub challenge_window_slots: u64,
    pub recursion_depth_limit: u16,
    pub privacy_set_size: u64,
    pub status: MarketStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Bonder {
    pub bonder_id: String,
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_micro_units: u64,
    pub supported_dispute_kinds: BTreeSet<DisputeKind>,
    pub status: BonderStatus,
    pub successful_settlements: u64,
    pub failed_settlements: u64,
    pub quarantine_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub market_id: String,
    pub challenger_commitment: String,
    pub defendant_commitment: String,
    pub dispute_kind: DisputeKind,
    pub disputed_state_root: String,
    pub claimed_correct_state_root: String,
    pub encrypted_witness_root: String,
    pub challenge_slot: u64,
    pub expires_slot: u64,
    pub risk_bps: u64,
    pub status: ChallengeStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofSegment {
    pub segment_id: String,
    pub challenge_id: String,
    pub segment_index: u64,
    pub recursion_depth: u16,
    pub witness_commitment_root: String,
    pub accumulator_root: String,
    pub verifier_hint_root: String,
    pub status: ProofSegmentStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BondQuote {
    pub quote_id: String,
    pub challenge_id: String,
    pub bonder_id: String,
    pub bond_asset_id: String,
    pub bond_micro_units: u64,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub fee_bps: u64,
    pub sponsor_pool_root: String,
    pub valid_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Attestation {
    pub attestation_id: String,
    pub challenge_id: String,
    pub segment_id: Option<String>,
    pub bonder_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Settlement {
    pub settlement_id: String,
    pub challenge_id: String,
    pub quote_id: String,
    pub decision: SettlementDecision,
    pub settlement_root: String,
    pub slashed_micro_units: u64,
    pub rebate_micro_units: u64,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub rebate_id: String,
    pub challenge_id: String,
    pub quote_id: String,
    pub asset_id: String,
    pub sponsor_pool_root: String,
    pub beneficiary_group_root: String,
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
    pub market_id: String,
    pub accepted_challenges: u64,
    pub rejected_challenges: u64,
    pub slashed_bonders: u64,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenMarketRequest {
    pub rollup_id: String,
    pub settlement_contract_root: String,
    pub allowed_dispute_kinds: BTreeSet<DisputeKind>,
    pub min_bond_micro_units: u64,
    pub max_bond_fee_bps: u64,
    pub challenge_window_slots: u64,
    pub recursion_depth_limit: u16,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterBonderRequest {
    pub operator_commitment: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_micro_units: u64,
    pub supported_dispute_kinds: BTreeSet<DisputeKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitChallengeRequest {
    pub market_id: String,
    pub challenger_commitment: String,
    pub defendant_commitment: String,
    pub dispute_kind: DisputeKind,
    pub disputed_state_root: String,
    pub claimed_correct_state_root: String,
    pub encrypted_witness_root: String,
    pub challenge_slot: u64,
    pub risk_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddProofSegmentRequest {
    pub challenge_id: String,
    pub segment_index: u64,
    pub recursion_depth: u16,
    pub witness_commitment_root: String,
    pub accumulator_root: String,
    pub verifier_hint_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteBondRequest {
    pub challenge_id: String,
    pub bonder_id: String,
    pub bond_asset_id: String,
    pub bond_micro_units: u64,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub fee_bps: u64,
    pub sponsor_pool_root: String,
    pub valid_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub challenge_id: String,
    pub segment_id: Option<String>,
    pub bonder_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub observed_slot: u64,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleChallengeRequest {
    pub challenge_id: String,
    pub quote_id: String,
    pub decision: SettlementDecision,
    pub settlement_root: String,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub challenge_id: String,
    pub quote_id: String,
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
    pub market_id: String,
    pub median_fee_bps: u64,
    pub attestation_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub markets: BTreeMap<String, Market>,
    pub bonders: BTreeMap<String, Bonder>,
    pub challenges: BTreeMap<String, Challenge>,
    pub proof_segments: BTreeMap<String, ProofSegment>,
    pub bond_quotes: BTreeMap<String, BondQuote>,
    pub attestations: BTreeMap<String, Attestation>,
    pub settlements: BTreeMap<String, Settlement>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default recursive fraud proof bond market config")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            markets: BTreeMap::new(),
            bonders: BTreeMap::new(),
            challenges: BTreeMap::new(),
            proof_segments: BTreeMap::new(),
            bond_quotes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn open_market(&mut self, request: OpenMarketRequest) -> Result<Market> {
        ensure_capacity(self.markets.len(), MAX_MARKETS, "markets")?;
        ensure_non_empty(&request.rollup_id, "rollup_id")?;
        ensure_non_empty(
            &request.settlement_contract_root,
            "settlement_contract_root",
        )?;
        if request.allowed_dispute_kinds.is_empty() {
            return Err("market requires at least one dispute kind".to_string());
        }
        if request.min_bond_micro_units < self.config.min_bond_micro_units {
            return Err("market bond floor below configured minimum".to_string());
        }
        ensure_bps(request.max_bond_fee_bps, "max_bond_fee_bps")?;
        if request.max_bond_fee_bps > self.config.max_bond_fee_bps {
            return Err("market fee cap exceeds configured cap".to_string());
        }
        if request.challenge_window_slots == 0 {
            return Err("challenge window must be non-zero".to_string());
        }
        if request.recursion_depth_limit == 0
            || request.recursion_depth_limit > self.config.recursion_depth_limit
        {
            return Err("recursion depth limit is invalid".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("market privacy set below configured minimum".to_string());
        }
        let market_id = stable_id(
            "market",
            &[
                HashPart::Str(&request.rollup_id),
                HashPart::Str(&request.settlement_contract_root),
                HashPart::U64(request.min_bond_micro_units),
            ],
        );
        let market = Market {
            market_id: market_id.clone(),
            rollup_id: request.rollup_id,
            settlement_contract_root: request.settlement_contract_root,
            allowed_dispute_kinds: request.allowed_dispute_kinds,
            min_bond_micro_units: request.min_bond_micro_units,
            max_bond_fee_bps: request.max_bond_fee_bps,
            challenge_window_slots: request.challenge_window_slots,
            recursion_depth_limit: request.recursion_depth_limit,
            privacy_set_size: request.privacy_set_size,
            status: MarketStatus::Open,
        };
        self.markets.insert(market_id, market.clone());
        self.refresh_roots();
        Ok(market)
    }

    pub fn register_bonder(&mut self, request: RegisterBonderRequest) -> Result<Bonder> {
        ensure_capacity(self.bonders.len(), MAX_BONDERS, "bonders")?;
        ensure_non_empty(&request.operator_commitment, "operator_commitment")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        if request.stake_bond_micro_units < self.config.min_bond_micro_units {
            return Err("bonder stake below configured minimum".to_string());
        }
        if request.supported_dispute_kinds.is_empty() {
            return Err("bonder must support at least one dispute kind".to_string());
        }
        let bonder_id = stable_id(
            "bonder",
            &[
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.stake_bond_micro_units),
            ],
        );
        let bonder = Bonder {
            bonder_id: bonder_id.clone(),
            operator_commitment: request.operator_commitment,
            pq_verifying_key_root: request.pq_verifying_key_root,
            stake_bond_micro_units: request.stake_bond_micro_units,
            supported_dispute_kinds: request.supported_dispute_kinds,
            status: BonderStatus::Active,
            successful_settlements: 0,
            failed_settlements: 0,
            quarantine_until_slot: 0,
        };
        self.bonders.insert(bonder_id, bonder.clone());
        self.refresh_roots();
        Ok(bonder)
    }

    pub fn submit_challenge(&mut self, request: SubmitChallengeRequest) -> Result<Challenge> {
        ensure_capacity(self.challenges.len(), MAX_CHALLENGES, "challenges")?;
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "market not found".to_string())?;
        if market.status != MarketStatus::Open && market.status != MarketStatus::Bonding {
            return Err("market is not accepting challenges".to_string());
        }
        if !market.allowed_dispute_kinds.contains(&request.dispute_kind) {
            return Err("market does not allow this dispute kind".to_string());
        }
        ensure_non_empty(&request.challenger_commitment, "challenger_commitment")?;
        ensure_non_empty(&request.defendant_commitment, "defendant_commitment")?;
        ensure_non_empty(&request.disputed_state_root, "disputed_state_root")?;
        ensure_non_empty(
            &request.claimed_correct_state_root,
            "claimed_correct_state_root",
        )?;
        ensure_non_empty(&request.encrypted_witness_root, "encrypted_witness_root")?;
        ensure_bps(request.risk_bps, "risk_bps")?;
        let derived_risk = request.risk_bps.max(request.dispute_kind.base_risk_bps());
        if derived_risk > self.config.max_dispute_risk_bps {
            return Err("challenge risk exceeds configured bound".to_string());
        }
        let challenge_id = stable_id(
            "challenge",
            &[
                HashPart::Str(&request.market_id),
                HashPart::Str(request.dispute_kind.as_str()),
                HashPart::Str(&request.disputed_state_root),
                HashPart::U64(request.challenge_slot),
            ],
        );
        let challenge = Challenge {
            challenge_id: challenge_id.clone(),
            market_id: request.market_id.clone(),
            challenger_commitment: request.challenger_commitment,
            defendant_commitment: request.defendant_commitment,
            dispute_kind: request.dispute_kind,
            disputed_state_root: request.disputed_state_root,
            claimed_correct_state_root: request.claimed_correct_state_root,
            encrypted_witness_root: request.encrypted_witness_root,
            challenge_slot: request.challenge_slot,
            expires_slot: request.challenge_slot + market.challenge_window_slots,
            risk_bps: derived_risk,
            status: ChallengeStatus::Submitted,
        };
        self.challenges.insert(challenge_id, challenge.clone());
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market.status = MarketStatus::Bonding;
        }
        self.refresh_roots();
        Ok(challenge)
    }

    pub fn quote_bond(&mut self, request: QuoteBondRequest) -> Result<BondQuote> {
        ensure_capacity(self.bond_quotes.len(), MAX_BOND_QUOTES, "bond_quotes")?;
        let challenge = self
            .challenges
            .get(&request.challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        let market = self
            .markets
            .get(&challenge.market_id)
            .ok_or_else(|| "market not found".to_string())?;
        let bonder = self
            .bonders
            .get(&request.bonder_id)
            .ok_or_else(|| "bonder not found".to_string())?;
        if bonder.status != BonderStatus::Active {
            return Err("bonder is not active".to_string());
        }
        if !bonder
            .supported_dispute_kinds
            .contains(&challenge.dispute_kind)
        {
            return Err("bonder does not support challenge dispute kind".to_string());
        }
        ensure_non_empty(&request.bond_asset_id, "bond_asset_id")?;
        ensure_non_empty(&request.fee_asset_id, "fee_asset_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        if request.bond_micro_units < market.min_bond_micro_units {
            return Err("quoted bond below market minimum".to_string());
        }
        ensure_bps(request.fee_bps, "fee_bps")?;
        if request.fee_bps > market.max_bond_fee_bps {
            return Err("quoted fee exceeds market cap".to_string());
        }
        if request.valid_until_slot <= challenge.challenge_slot {
            return Err("quote validity must extend past challenge slot".to_string());
        }
        let quote_id = stable_id(
            "bond-quote",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::Str(&request.bonder_id),
                HashPart::U64(request.bond_micro_units),
                HashPart::U64(request.valid_until_slot),
            ],
        );
        let quote = BondQuote {
            quote_id: quote_id.clone(),
            challenge_id: request.challenge_id.clone(),
            bonder_id: request.bonder_id,
            bond_asset_id: request.bond_asset_id,
            bond_micro_units: request.bond_micro_units,
            fee_asset_id: request.fee_asset_id,
            fee_micro_units: request.fee_micro_units,
            fee_bps: request.fee_bps,
            sponsor_pool_root: request.sponsor_pool_root,
            valid_until_slot: request.valid_until_slot,
        };
        self.bond_quotes.insert(quote_id, quote.clone());
        if let Some(challenge) = self.challenges.get_mut(&request.challenge_id) {
            challenge.status = ChallengeStatus::BondQuoted;
        }
        self.refresh_roots();
        Ok(quote)
    }

    pub fn add_proof_segment(&mut self, request: AddProofSegmentRequest) -> Result<ProofSegment> {
        ensure_capacity(
            self.proof_segments.len(),
            MAX_PROOF_SEGMENTS,
            "proof_segments",
        )?;
        let challenge = self
            .challenges
            .get(&request.challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        let market = self
            .markets
            .get(&challenge.market_id)
            .ok_or_else(|| "market not found".to_string())?;
        let existing = self
            .proof_segments
            .values()
            .filter(|segment| segment.challenge_id == request.challenge_id)
            .count();
        if existing >= MAX_SEGMENTS_PER_CHALLENGE {
            return Err("challenge has too many proof segments".to_string());
        }
        if request.recursion_depth > market.recursion_depth_limit {
            return Err("segment recursion depth exceeds market limit".to_string());
        }
        ensure_non_empty(&request.witness_commitment_root, "witness_commitment_root")?;
        ensure_non_empty(&request.accumulator_root, "accumulator_root")?;
        ensure_non_empty(&request.verifier_hint_root, "verifier_hint_root")?;
        let segment_id = stable_id(
            "proof-segment",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::U64(request.segment_index),
                HashPart::U64(request.recursion_depth as u64),
                HashPart::Str(&request.accumulator_root),
            ],
        );
        let segment = ProofSegment {
            segment_id: segment_id.clone(),
            challenge_id: request.challenge_id.clone(),
            segment_index: request.segment_index,
            recursion_depth: request.recursion_depth,
            witness_commitment_root: request.witness_commitment_root,
            accumulator_root: request.accumulator_root,
            verifier_hint_root: request.verifier_hint_root,
            status: ProofSegmentStatus::RecursionCommitted,
        };
        self.proof_segments.insert(segment_id, segment.clone());
        if let Some(challenge) = self.challenges.get_mut(&request.challenge_id) {
            challenge.status = ChallengeStatus::Segmented;
        }
        self.refresh_roots();
        Ok(segment)
    }

    pub fn record_attestation(&mut self, request: RecordAttestationRequest) -> Result<Attestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        self.ensure_challenge_exists(&request.challenge_id)?;
        self.ensure_bonder_exists(&request.bonder_id)?;
        if let Some(segment_id) = &request.segment_id {
            self.ensure_segment_exists(segment_id)?;
        }
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        if request.quorum_weight_bps < self.config.min_attestation_quorum_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::Str(&request.bonder_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::U64(request.observed_slot),
            ],
        );
        let attestation = Attestation {
            attestation_id: attestation_id.clone(),
            challenge_id: request.challenge_id.clone(),
            segment_id: request.segment_id,
            bonder_id: request.bonder_id,
            kind: request.kind,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            observed_slot: request.observed_slot,
            quorum_weight_bps: request.quorum_weight_bps,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        if let Some(challenge) = self.challenges.get_mut(&request.challenge_id) {
            challenge.status = ChallengeStatus::Attested;
        }
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn settle_challenge(&mut self, request: SettleChallengeRequest) -> Result<Settlement> {
        ensure_capacity(self.settlements.len(), MAX_SETTLEMENTS, "settlements")?;
        let quote = self
            .bond_quotes
            .get(&request.quote_id)
            .ok_or_else(|| "bond quote not found".to_string())?;
        if quote.challenge_id != request.challenge_id {
            return Err("quote does not match challenge".to_string());
        }
        let challenge = self
            .challenges
            .get(&request.challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        if request.settled_slot < challenge.challenge_slot {
            return Err("settled_slot must be >= challenge_slot".to_string());
        }
        ensure_non_empty(&request.settlement_root, "settlement_root")?;
        let slashed_micro_units = match request.decision {
            SettlementDecision::SlashBonder => {
                quote.bond_micro_units * self.config.slashing_penalty_bps / MAX_BPS
            }
            SettlementDecision::SlashDefender => quote.bond_micro_units,
            _ => 0,
        };
        let rebate_micro_units = match request.decision {
            SettlementDecision::AcceptChallenge | SettlementDecision::RejectChallenge => {
                quote.fee_micro_units * self.config.target_rebate_bps / MAX_BPS
            }
            _ => 0,
        };
        let settlement_id = stable_id(
            "settlement",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::Str(&request.quote_id),
                HashPart::Str(request.decision.as_str()),
                HashPart::U64(request.settled_slot),
            ],
        );
        let settlement = Settlement {
            settlement_id: settlement_id.clone(),
            challenge_id: request.challenge_id.clone(),
            quote_id: request.quote_id.clone(),
            decision: request.decision,
            settlement_root: request.settlement_root,
            slashed_micro_units,
            rebate_micro_units,
            settled_slot: request.settled_slot,
        };
        self.settlements.insert(settlement_id, settlement.clone());
        self.apply_settlement_effects(&request.challenge_id, &request.quote_id, request.decision)?;
        self.refresh_roots();
        Ok(settlement)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<RebateReceipt> {
        ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        let quote = self
            .bond_quotes
            .get(&request.quote_id)
            .ok_or_else(|| "bond quote not found".to_string())?;
        if quote.challenge_id != request.challenge_id {
            return Err("rebate quote does not match challenge".to_string());
        }
        ensure_non_empty(&request.asset_id, "asset_id")?;
        ensure_non_empty(&request.sponsor_pool_root, "sponsor_pool_root")?;
        ensure_non_empty(&request.beneficiary_group_root, "beneficiary_group_root")?;
        ensure_bps(request.fee_rebate_bps, "fee_rebate_bps")?;
        if request.fee_rebate_bps > self.config.target_rebate_bps {
            return Err("rebate exceeds configured target".to_string());
        }
        if request.amount_micro_units > quote.fee_micro_units {
            return Err("rebate amount exceeds quoted fee".to_string());
        }
        if request.expires_slot <= request.issued_slot {
            return Err("rebate expiry must be after issue slot".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.challenge_id),
                HashPart::Str(&request.quote_id),
                HashPart::Str(&request.sponsor_pool_root),
                HashPart::U64(request.issued_slot),
            ],
        );
        let receipt = RebateReceipt {
            rebate_id: rebate_id.clone(),
            challenge_id: request.challenge_id,
            quote_id: request.quote_id,
            asset_id: request.asset_id,
            sponsor_pool_root: request.sponsor_pool_root,
            beneficiary_group_root: request.beneficiary_group_root,
            amount_micro_units: request.amount_micro_units,
            fee_rebate_bps: request.fee_rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.rebates.insert(rebate_id, receipt.clone());
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
        self.ensure_market_exists(&request.market_id)?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.attestation_quorum_bps, "attestation_quorum_bps")?;
        let summary_id = stable_id(
            "operator-summary",
            &[
                HashPart::Str(&request.market_id),
                HashPart::U64(self.operator_summaries.len() as u64),
            ],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            market_id: request.market_id,
            accepted_challenges: self.counters.accepted_challenges,
            rejected_challenges: self.counters.rejected_challenges,
            slashed_bonders: self.counters.slashed_bonders,
            median_fee_bps: request.median_fee_bps,
            attestation_quorum_bps: request.attestation_quorum_bps,
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.markets = self.markets.len() as u64;
        self.counters.bonders = self.bonders.len() as u64;
        self.counters.challenges = self.challenges.len() as u64;
        self.counters.proof_segments = self.proof_segments.len() as u64;
        self.counters.bond_quotes = self.bond_quotes.len() as u64;
        self.counters.settlements = self.settlements.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.roots.market_root =
            map_root("recursive-fraud-proof-bond-market:markets", &self.markets);
        self.roots.bonder_root =
            map_root("recursive-fraud-proof-bond-market:bonders", &self.bonders);
        self.roots.challenge_root = map_root(
            "recursive-fraud-proof-bond-market:challenges",
            &self.challenges,
        );
        self.roots.proof_segment_root = map_root(
            "recursive-fraud-proof-bond-market:proof-segments",
            &self.proof_segments,
        );
        self.roots.bond_quote_root = map_root(
            "recursive-fraud-proof-bond-market:bond-quotes",
            &self.bond_quotes,
        );
        self.roots.settlement_root = map_root(
            "recursive-fraud-proof-bond-market:settlements",
            &self.settlements,
        );
        self.roots.attestation_root = map_root(
            "recursive-fraud-proof-bond-market:attestations",
            &self.attestations,
        );
        self.roots.rebate_root =
            map_root("recursive-fraud-proof-bond-market:rebates", &self.rebates);
        self.roots.redaction_budget_root = map_root(
            "recursive-fraud-proof-bond-market:redaction-budgets",
            &self.redaction_budgets,
        );
        self.roots.operator_summary_root = map_root(
            "recursive-fraud-proof-bond-market:operator-summaries",
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
            "pq_auth_suite": self.config.pq_auth_suite,
            "recursive_proof_suite": self.config.recursive_proof_suite,
            "bond_market_suite": self.config.bond_market_suite,
            "redaction_suite": self.config.redaction_suite,
            "l2_height": DEVNET_L2_HEIGHT,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "markets": self.markets,
            "bonders": self.bonders,
            "challenges": self.challenges,
            "proof_segments": self.proof_segments,
            "bond_quotes": self.bond_quotes,
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
            "market_root": self.roots.market_root,
            "bonder_root": self.roots.bonder_root,
            "challenge_root": self.roots.challenge_root,
            "proof_segment_root": self.roots.proof_segment_root,
            "bond_quote_root": self.roots.bond_quote_root,
            "settlement_root": self.roots.settlement_root,
            "attestation_root": self.roots.attestation_root,
            "rebate_root": self.roots.rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "recursive-fraud-proof-bond-market:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn apply_settlement_effects(
        &mut self,
        challenge_id: &str,
        quote_id: &str,
        decision: SettlementDecision,
    ) -> Result<()> {
        let quote = self
            .bond_quotes
            .get(quote_id)
            .ok_or_else(|| "bond quote not found".to_string())?;
        if let Some(challenge) = self.challenges.get_mut(challenge_id) {
            challenge.status = match decision {
                SettlementDecision::AcceptChallenge
                | SettlementDecision::SlashDefender
                | SettlementDecision::SlashBonder => ChallengeStatus::Settled,
                SettlementDecision::RejectChallenge => ChallengeStatus::Rejected,
                SettlementDecision::RequireMoreSegments | SettlementDecision::ExtendWindow => {
                    ChallengeStatus::Recursed
                }
                SettlementDecision::EmergencyPause => ChallengeStatus::Attested,
            };
        }
        if let Some(bonder) = self.bonders.get_mut(&quote.bonder_id) {
            match decision {
                SettlementDecision::AcceptChallenge | SettlementDecision::RejectChallenge => {
                    bonder.successful_settlements = bonder.successful_settlements.saturating_add(1)
                }
                SettlementDecision::SlashBonder => {
                    bonder.status = BonderStatus::Slashed;
                    bonder.failed_settlements = bonder.failed_settlements.saturating_add(1);
                    self.counters.slashed_bonders = self.counters.slashed_bonders.saturating_add(1);
                }
                _ => {}
            }
        }
        match decision {
            SettlementDecision::AcceptChallenge | SettlementDecision::SlashDefender => {
                self.counters.accepted_challenges =
                    self.counters.accepted_challenges.saturating_add(1);
                self.counters.slashed_defenders = self
                    .counters
                    .slashed_defenders
                    .saturating_add(u64::from(decision == SettlementDecision::SlashDefender));
            }
            SettlementDecision::RejectChallenge | SettlementDecision::SlashBonder => {
                self.counters.rejected_challenges =
                    self.counters.rejected_challenges.saturating_add(1);
            }
            SettlementDecision::EmergencyPause => {
                if let Some(challenge) = self.challenges.get(challenge_id) {
                    if let Some(market) = self.markets.get_mut(&challenge.market_id) {
                        market.status = MarketStatus::Paused;
                        self.counters.paused_markets =
                            self.counters.paused_markets.saturating_add(1);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn ensure_market_exists(&self, market_id: &str) -> Result<()> {
        ensure_non_empty(market_id, "market_id")?;
        if !self.markets.contains_key(market_id) {
            return Err(format!("market not found: {market_id}"));
        }
        Ok(())
    }

    fn ensure_challenge_exists(&self, challenge_id: &str) -> Result<()> {
        ensure_non_empty(challenge_id, "challenge_id")?;
        if !self.challenges.contains_key(challenge_id) {
            return Err(format!("challenge not found: {challenge_id}"));
        }
        Ok(())
    }

    fn ensure_bonder_exists(&self, bonder_id: &str) -> Result<()> {
        ensure_non_empty(bonder_id, "bonder_id")?;
        if !self.bonders.contains_key(bonder_id) {
            return Err(format!("bonder not found: {bonder_id}"));
        }
        Ok(())
    }

    fn ensure_segment_exists(&self, segment_id: &str) -> Result<()> {
        ensure_non_empty(segment_id, "segment_id")?;
        if !self.proof_segments.contains_key(segment_id) {
            return Err(format!("segment not found: {segment_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let market = state
        .open_market(OpenMarketRequest {
            rollup_id: "nebula-private-l2-devnet-rollup".to_string(),
            settlement_contract_root: sample_hash("settlement-contract", 1),
            allowed_dispute_kinds: [
                DisputeKind::InvalidStateTransition,
                DisputeKind::InvalidWithdrawal,
                DisputeKind::DataAvailabilityWithholding,
                DisputeKind::PrivacyRegression,
            ]
            .into_iter()
            .collect(),
            min_bond_micro_units: DEFAULT_MIN_BOND_MICRO_UNITS,
            max_bond_fee_bps: DEFAULT_MAX_BOND_FEE_BPS,
            challenge_window_slots: DEFAULT_CHALLENGE_WINDOW_SLOTS,
            recursion_depth_limit: DEFAULT_RECURSION_DEPTH_LIMIT,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet market opened");
    let bonder = state
        .register_bonder(RegisterBonderRequest {
            operator_commitment: sample_hash("bonder-operator", 1),
            pq_verifying_key_root: sample_hash("pq-key", 1),
            stake_bond_micro_units: DEFAULT_MIN_BOND_MICRO_UNITS * 4,
            supported_dispute_kinds: [
                DisputeKind::InvalidStateTransition,
                DisputeKind::InvalidWithdrawal,
                DisputeKind::DataAvailabilityWithholding,
                DisputeKind::PrivacyRegression,
            ]
            .into_iter()
            .collect(),
        })
        .expect("devnet bonder registered");
    let challenge = state
        .submit_challenge(SubmitChallengeRequest {
            market_id: market.market_id.clone(),
            challenger_commitment: sample_hash("challenger", 1),
            defendant_commitment: sample_hash("defendant", 1),
            dispute_kind: DisputeKind::InvalidStateTransition,
            disputed_state_root: sample_hash("bad-state", 1),
            claimed_correct_state_root: sample_hash("correct-state", 1),
            encrypted_witness_root: sample_hash("encrypted-witness", 1),
            challenge_slot: DEVNET_SLOT,
            risk_bps: 1_900,
        })
        .expect("devnet challenge submitted");
    let quote = state
        .quote_bond(QuoteBondRequest {
            challenge_id: challenge.challenge_id.clone(),
            bonder_id: bonder.bonder_id.clone(),
            bond_asset_id: DEFAULT_BOND_ASSET_ID.to_string(),
            bond_micro_units: DEFAULT_MIN_BOND_MICRO_UNITS * 2,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            fee_micro_units: 5_200,
            fee_bps: 9,
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            valid_until_slot: DEVNET_SLOT + 128,
        })
        .expect("devnet bond quoted");
    let segment = state
        .add_proof_segment(AddProofSegmentRequest {
            challenge_id: challenge.challenge_id.clone(),
            segment_index: 0,
            recursion_depth: 4,
            witness_commitment_root: sample_hash("witness-segment", 1),
            accumulator_root: sample_hash("accumulator", 1),
            verifier_hint_root: sample_hash("verifier-hint", 1),
        })
        .expect("devnet proof segment added");
    state
        .record_attestation(RecordAttestationRequest {
            challenge_id: challenge.challenge_id.clone(),
            segment_id: Some(segment.segment_id),
            bonder_id: bonder.bonder_id,
            kind: AttestationKind::RecursiveAccumulatorValid,
            statement_root: sample_hash("statement", 1),
            pq_signature_root: sample_hash("pq-signature", 1),
            observed_slot: DEVNET_SLOT + 4,
            quorum_weight_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet attestation recorded");
    state
        .settle_challenge(SettleChallengeRequest {
            challenge_id: challenge.challenge_id.clone(),
            quote_id: quote.quote_id.clone(),
            decision: SettlementDecision::AcceptChallenge,
            settlement_root: sample_hash("settlement", 1),
            settled_slot: DEVNET_SLOT + 8,
        })
        .expect("devnet challenge settled");
    state
        .issue_rebate(IssueRebateRequest {
            challenge_id: challenge.challenge_id.clone(),
            quote_id: quote.quote_id,
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_pool_root: sample_hash("sponsor-pool", 1),
            beneficiary_group_root: sample_hash("beneficiary-group", 1),
            amount_micro_units: 1_000,
            fee_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            issued_slot: DEVNET_SLOT + 9,
            expires_slot: DEVNET_SLOT + 512,
        })
        .expect("devnet rebate issued");
    state
        .publish_redaction_budget(RedactionBudgetRequest {
            target_id: challenge.challenge_id,
            public_fields: ["challenge_id", "dispute_kind", "risk_bps"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            redacted_fields: [
                "challenger_commitment",
                "defendant_commitment",
                "encrypted_witness_root",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            max_public_bytes: 2_048,
            actual_public_bytes: 704,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("devnet redaction budget published");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            market_id: market.market_id,
            median_fee_bps: 9,
            attestation_quorum_bps: DEFAULT_STRONG_ATTESTATION_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let market_id = state
        .markets
        .keys()
        .next()
        .cloned()
        .expect("devnet has market");
    state
        .submit_challenge(SubmitChallengeRequest {
            market_id,
            challenger_commitment: sample_hash("challenger", 2),
            defendant_commitment: sample_hash("defendant", 2),
            dispute_kind: DisputeKind::DataAvailabilityWithholding,
            disputed_state_root: sample_hash("bad-state", 2),
            claimed_correct_state_root: sample_hash("correct-state", 2),
            encrypted_witness_root: sample_hash("encrypted-witness", 2),
            challenge_slot: DEVNET_SLOT + 32,
            risk_bps: 1_450,
        })
        .expect("demo challenge submitted");
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
        &format!("recursive-fraud-proof-bond-market:{domain}:id"),
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
        "recursive-fraud-proof-bond-market:devnet-sample",
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
