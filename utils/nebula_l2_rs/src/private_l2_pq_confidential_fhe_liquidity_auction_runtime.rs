use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_FHE_LIQUIDITY_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-fhe-liquidity-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_FHE_LIQUIDITY_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_CURVE_SUITE: &str = "bfv-ckks-hybrid-encrypted-liquidity-curve-v1";
pub const SEALED_BID_SUITE: &str = "ml-kem-1024+threshold-fhe-sealed-liquidity-bid-v1";
pub const AUCTIONEER_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-pq-auctioneer-attestation-v1";
pub const BATCH_CLEARING_SUITE: &str = "deterministic-confidential-fhe-liquidity-clearing-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "roots-only-low-fee-liquidity-rebate-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "privacy-redaction-budget-liquidity-auction-v1";
pub const SOLVER_QUARANTINE_SUITE: &str = "pq-solver-quarantine-liquidity-auction-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-public-liquidity-auction-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 3_284_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_548_000;
pub const DEVNET_EPOCH: u64 = 8_144;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_CURVE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_MAX_AUCTIONEER_FEE_BPS: u64 = 18;
pub const DEFAULT_MIN_LOW_FEE_REBATE_BPS: u64 = 6;
pub const DEFAULT_TARGET_LOW_FEE_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 120;
pub const DEFAULT_REBATE_BUDGET_MICRO_UNITS: u64 = 750_000_000;
pub const DEFAULT_SOLVER_BOND_MICRO_UNITS: u64 = 8_000_000;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 32_000;
pub const MAX_CURVES: usize = 1_048_576;
pub const MAX_BIDS: usize = 4_194_304;
pub const MAX_AUCTIONEERS: usize = 65_536;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_CLEARING_BATCHES: usize = 1_048_576;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_QUARANTINES: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 4_194_304;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionVenue {
    MoneroBridgeExit,
    ConfidentialAmm,
    PrivateRfq,
    InternalNetting,
    CrossRollupLiquidity,
    EmergencyBackstop,
}

impl AuctionVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::ConfidentialAmm => "confidential_amm",
            Self::PrivateRfq => "private_rfq",
            Self::InternalNetting => "internal_netting",
            Self::CrossRollupLiquidity => "cross_rollup_liquidity",
            Self::EmergencyBackstop => "emergency_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurveKind {
    StableCurve,
    PiecewiseLinear,
    BridgeExitDepth,
}

impl CurveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableCurve => "stable_curve",
            Self::PiecewiseLinear => "piecewise_linear",
            Self::BridgeExitDepth => "bridge_exit_depth",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurveStatus {
    Open,
    Bidding,
    Cleared,
    Quarantined,
}

impl CurveStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Bidding)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidSide {
    BuyLiquidity,
    SellLiquidity,
    Rebalance,
    ExitFill,
    BackstopFill,
}

impl BidSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuyLiquidity => "buy_liquidity",
            Self::SellLiquidity => "sell_liquidity",
            Self::Rebalance => "rebalance",
            Self::ExitFill => "exit_fill",
            Self::BackstopFill => "backstop_fill",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Admitted,
    PrivacyChecked,
    Won,
    Rebated,
    Quarantined,
}

impl BidStatus {
    pub fn batchable(self) -> bool {
        matches!(self, Self::Admitted | Self::PrivacyChecked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctioneerStatus {
    Registered,
    Active,
    RateLimited,
    Quarantined,
    Retired,
}

impl AuctioneerStatus {
    pub fn can_clear(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    Degraded,
    Invalid,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Degraded => "degraded",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Cleared,
    Settled,
    Rebated,
    Disputed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    LowFeeLane,
    SolverSurplus,
    BatchedClearing,
    MoneroExitSubsidy,
    PrivacyPreservingRoute,
    BackstopReuse,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeLane => "low_fee_lane",
            Self::SolverSurplus => "solver_surplus",
            Self::BatchedClearing => "batched_clearing",
            Self::MoneroExitSubsidy => "monero_exit_subsidy",
            Self::PrivacyPreservingRoute => "privacy_preserving_route",
            Self::BackstopReuse => "backstop_reuse",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionKind {
    BidAmount,
    CurveDepth,
    SolverIdentity,
    ClearingPrice,
    RouteWitness,
    CounterpartySet,
    SettlementNote,
}

impl RedactionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BidAmount => "bid_amount",
            Self::CurveDepth => "curve_depth",
            Self::SolverIdentity => "solver_identity",
            Self::ClearingPrice => "clearing_price",
            Self::RouteWitness => "route_witness",
            Self::CounterpartySet => "counterparty_set",
            Self::SettlementNote => "settlement_note",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    InvalidCiphertext,
    MissingPqAttestation,
    FheNoiseOverflow,
    RedactionBudgetExceeded,
    DeterminismMismatch,
    SettlementRootMismatch,
    SolverTimeout,
    MaliciousReveal,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::MissingPqAttestation => "missing_pq_attestation",
            Self::FheNoiseOverflow => "fhe_noise_overflow",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::DeterminismMismatch => "determinism_mismatch",
            Self::SettlementRootMismatch => "settlement_root_mismatch",
            Self::SolverTimeout => "solver_timeout",
            Self::MaliciousReveal => "malicious_reveal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    Curve,
    Bid,
    Attestation,
    ClearingBatch,
    Rebate,
    RedactionBudget,
    Quarantine,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Curve => "curve",
            Self::Bid => "bid",
            Self::Attestation => "attestation",
            Self::ClearingBatch => "clearing_batch",
            Self::Rebate => "rebate",
            Self::RedactionBudget => "redaction_budget",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_curve_suite: String,
    pub sealed_bid_suite: String,
    pub auctioneer_attestation_suite: String,
    pub batch_clearing_suite: String,
    pub low_fee_rebate_suite: String,
    pub privacy_redaction_suite: String,
    pub solver_quarantine_suite: String,
    pub public_record_suite: String,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub curve_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_auctioneer_fee_bps: u64,
    pub min_low_fee_rebate_bps: u64,
    pub target_low_fee_rebate_bps: u64,
    pub max_price_impact_bps: u64,
    pub rebate_budget_micro_units: u64,
    pub solver_bond_micro_units: u64,
    pub redaction_budget_units: u64,
    pub allowed_venues: Vec<AuctionVenue>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_curve_suite: ENCRYPTED_CURVE_SUITE.to_string(),
            sealed_bid_suite: SEALED_BID_SUITE.to_string(),
            auctioneer_attestation_suite: AUCTIONEER_ATTESTATION_SUITE.to_string(),
            batch_clearing_suite: BATCH_CLEARING_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            privacy_redaction_suite: PRIVACY_REDACTION_SUITE.to_string(),
            solver_quarantine_suite: SOLVER_QUARANTINE_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            curve_ttl_blocks: DEFAULT_CURVE_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_auctioneer_fee_bps: DEFAULT_MAX_AUCTIONEER_FEE_BPS,
            min_low_fee_rebate_bps: DEFAULT_MIN_LOW_FEE_REBATE_BPS,
            target_low_fee_rebate_bps: DEFAULT_TARGET_LOW_FEE_REBATE_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            rebate_budget_micro_units: DEFAULT_REBATE_BUDGET_MICRO_UNITS,
            solver_bond_micro_units: DEFAULT_SOLVER_BOND_MICRO_UNITS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            allowed_venues: vec![
                AuctionVenue::MoneroBridgeExit,
                AuctionVenue::ConfidentialAmm,
                AuctionVenue::PrivateRfq,
                AuctionVenue::InternalNetting,
                AuctionVenue::CrossRollupLiquidity,
                AuctionVenue::EmergencyBackstop,
            ],
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "encrypted_curve_suite": self.encrypted_curve_suite,
            "sealed_bid_suite": self.sealed_bid_suite,
            "auctioneer_attestation_suite": self.auctioneer_attestation_suite,
            "batch_clearing_suite": self.batch_clearing_suite,
            "low_fee_rebate_suite": self.low_fee_rebate_suite,
            "privacy_redaction_suite": self.privacy_redaction_suite,
            "solver_quarantine_suite": self.solver_quarantine_suite,
            "public_record_suite": self.public_record_suite,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "curve_ttl_blocks": self.curve_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "clearing_ttl_blocks": self.clearing_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_auctioneer_fee_bps": self.max_auctioneer_fee_bps,
            "min_low_fee_rebate_bps": self.min_low_fee_rebate_bps,
            "target_low_fee_rebate_bps": self.target_low_fee_rebate_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "rebate_budget_micro_units": self.rebate_budget_micro_units,
            "solver_bond_micro_units": self.solver_bond_micro_units,
            "redaction_budget_units": self.redaction_budget_units,
            "allowed_venues": self.allowed_venues.iter().map(|venue| venue.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub curves_registered: u64,
    pub bids_admitted: u64,
    pub auctioneers_registered: u64,
    pub attestations_recorded: u64,
    pub batches_cleared: u64,
    pub rebates_issued: u64,
    pub redactions_charged: u64,
    pub solvers_quarantined: u64,
    pub public_records_emitted: u64,
    pub state_transitions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "curves_registered": self.curves_registered,
            "bids_admitted": self.bids_admitted,
            "auctioneers_registered": self.auctioneers_registered,
            "attestations_recorded": self.attestations_recorded,
            "batches_cleared": self.batches_cleared,
            "rebates_issued": self.rebates_issued,
            "redactions_charged": self.redactions_charged,
            "solvers_quarantined": self.solvers_quarantined,
            "public_records_emitted": self.public_records_emitted,
            "state_transitions": self.state_transitions,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub curves_root: String,
    pub bids_root: String,
    pub auctioneers_root: String,
    pub attestations_root: String,
    pub clearing_batches_root: String,
    pub rebates_root: String,
    pub redaction_budgets_root: String,
    pub quarantines_root: String,
    pub public_records_root: String,
    pub counters_root: String,
    pub config_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedLiquidityCurve {
    pub curve_id: String,
    pub provider_commitment: String,
    pub venue: AuctionVenue,
    pub curve_kind: CurveKind,
    pub status: CurveStatus,
    pub asset_pair_root: String,
    pub encrypted_curve_root: String,
    pub liquidity_commitment_root: String,
    pub fee_commitment_root: String,
    pub invariant_commitment_root: String,
    pub privacy_set_size: u64,
    pub max_price_impact_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub attestation_id: Option<String>,
}

impl EncryptedLiquidityCurve {
    pub fn public_record(&self) -> Value {
        json!({
            "curve_id": self.curve_id,
            "provider_commitment": self.provider_commitment,
            "venue": self.venue.as_str(),
            "curve_kind": self.curve_kind.as_str(),
            "status": self.status,
            "asset_pair_root": self.asset_pair_root,
            "encrypted_curve_root": self.encrypted_curve_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "invariant_commitment_root": self.invariant_commitment_root,
            "privacy_set_size": self.privacy_set_size,
            "max_price_impact_bps": self.max_price_impact_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "attestation_id": self.attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedBid {
    pub bid_id: String,
    pub curve_id: String,
    pub bidder_commitment: String,
    pub solver_id: String,
    pub side: BidSide,
    pub status: BidStatus,
    pub sealed_bid_root: String,
    pub amount_ciphertext_root: String,
    pub limit_price_ciphertext_root: String,
    pub fee_budget_commitment_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "curve_id": self.curve_id,
            "bidder_commitment": self.bidder_commitment,
            "solver_id": self.solver_id,
            "side": self.side.as_str(),
            "status": self.status,
            "sealed_bid_root": self.sealed_bid_root,
            "amount_ciphertext_root": self.amount_ciphertext_root,
            "limit_price_ciphertext_root": self.limit_price_ciphertext_root,
            "fee_budget_commitment_root": self.fee_budget_commitment_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "user_fee_bps": self.user_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Auctioneer {
    pub auctioneer_id: String,
    pub operator_commitment: String,
    pub status: AuctioneerStatus,
    pub pq_public_key_root: String,
    pub fhe_eval_key_root: String,
    pub stake_commitment_root: String,
    pub bond_micro_units: u64,
    pub fee_bps: u64,
    pub registered_at_height: u64,
    pub latest_attestation_id: Option<String>,
}

impl Auctioneer {
    pub fn public_record(&self) -> Value {
        json!({
            "auctioneer_id": self.auctioneer_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status,
            "pq_public_key_root": self.pq_public_key_root,
            "fhe_eval_key_root": self.fhe_eval_key_root,
            "stake_commitment_root": self.stake_commitment_root,
            "bond_micro_units": self.bond_micro_units,
            "fee_bps": self.fee_bps,
            "registered_at_height": self.registered_at_height,
            "latest_attestation_id": self.latest_attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuctioneerAttestation {
    pub attestation_id: String,
    pub auctioneer_id: String,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub fhe_circuit_root: String,
    pub enclave_measurement_root: String,
    pub transcript_root: String,
    pub min_pq_security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl AuctioneerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "auctioneer_id": self.auctioneer_id,
            "verdict": self.verdict.as_str(),
            "pq_signature_root": self.pq_signature_root,
            "fhe_circuit_root": self.fhe_circuit_root,
            "enclave_measurement_root": self.enclave_measurement_root,
            "transcript_root": self.transcript_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub auctioneer_id: String,
    pub status: BatchStatus,
    pub curve_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub aggregate_curve_root: String,
    pub aggregate_bid_root: String,
    pub clearing_price_root: String,
    pub allocation_root: String,
    pub settlement_root: String,
    pub public_output_root: String,
    pub privacy_set_size: u64,
    pub auctioneer_fee_bps: u64,
    pub built_at_height: u64,
    pub clears_at_height: u64,
}

impl ClearingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "auctioneer_id": self.auctioneer_id,
            "status": self.status,
            "curve_ids": self.curve_ids,
            "bid_ids": self.bid_ids,
            "aggregate_curve_root": self.aggregate_curve_root,
            "aggregate_bid_root": self.aggregate_bid_root,
            "clearing_price_root": self.clearing_price_root,
            "allocation_root": self.allocation_root,
            "settlement_root": self.settlement_root,
            "public_output_root": self.public_output_root,
            "privacy_set_size": self.privacy_set_size,
            "auctioneer_fee_bps": self.auctioneer_fee_bps,
            "built_at_height": self.built_at_height,
            "clears_at_height": self.clears_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub bid_id: String,
    pub recipient_commitment: String,
    pub reason: RebateReason,
    pub rebate_note_commitment: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "bid_id": self.bid_id,
            "recipient_commitment": self.recipient_commitment,
            "reason": self.reason.as_str(),
            "rebate_note_commitment": self.rebate_note_commitment,
            "amount_micro_units": self.amount_micro_units,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_id: String,
    pub kind: RedactionKind,
    pub epoch: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub redaction_root: String,
    pub charged_at_height: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "epoch": self.epoch,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units,
            "redaction_root": self.redaction_root,
            "charged_at_height": self.charged_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SolverQuarantine {
    pub quarantine_id: String,
    pub solver_id: String,
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub started_at_height: u64,
    pub expires_at_height: u64,
    pub slash_bps: u64,
}

impl SolverQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "solver_id": self.solver_id,
            "subject_id": self.subject_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "started_at_height": self.started_at_height,
            "expires_at_height": self.expires_at_height,
            "slash_bps": self.slash_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root: String,
    pub emitted_at_height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "state_root": self.state_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterAuctioneerRequest {
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub fhe_eval_key_root: String,
    pub stake_commitment_root: String,
    pub bond_micro_units: u64,
    pub fee_bps: u64,
    pub registered_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecordAuctioneerAttestationRequest {
    pub auctioneer_id: String,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub fhe_circuit_root: String,
    pub enclave_measurement_root: String,
    pub transcript_root: String,
    pub min_pq_security_bits: u16,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterEncryptedCurveRequest {
    pub provider_commitment: String,
    pub venue: AuctionVenue,
    pub curve_kind: CurveKind,
    pub asset_pair_root: String,
    pub encrypted_curve_root: String,
    pub liquidity_commitment_root: String,
    pub fee_commitment_root: String,
    pub invariant_commitment_root: String,
    pub privacy_set_size: u64,
    pub max_price_impact_bps: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdmitSealedBidRequest {
    pub curve_id: String,
    pub bidder_commitment: String,
    pub solver_id: String,
    pub side: BidSide,
    pub sealed_bid_root: String,
    pub amount_ciphertext_root: String,
    pub limit_price_ciphertext_root: String,
    pub fee_budget_commitment_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub user_fee_bps: u64,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuildClearingBatchRequest {
    pub auctioneer_id: String,
    pub curve_ids: Vec<String>,
    pub bid_ids: Vec<String>,
    pub aggregate_curve_root: String,
    pub aggregate_bid_root: String,
    pub clearing_price_root: String,
    pub allocation_root: String,
    pub settlement_root: String,
    pub public_output_root: String,
    pub privacy_set_size: u64,
    pub auctioneer_fee_bps: u64,
    pub built_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueLowFeeRebateRequest {
    pub batch_id: String,
    pub bid_id: String,
    pub recipient_commitment: String,
    pub reason: RebateReason,
    pub rebate_note_commitment: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChargeRedactionBudgetRequest {
    pub subject_id: String,
    pub kind: RedactionKind,
    pub epoch: u64,
    pub spent_units: u64,
    pub redaction_root: String,
    pub charged_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuarantineSolverRequest {
    pub solver_id: String,
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub started_at_height: u64,
    pub slash_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub curves: BTreeMap<String, EncryptedLiquidityCurve>,
    pub bids: BTreeMap<String, SealedBid>,
    pub auctioneers: BTreeMap<String, Auctioneer>,
    pub attestations: BTreeMap<String, AuctioneerAttestation>,
    pub clearing_batches: BTreeMap<String, ClearingBatch>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub quarantines: BTreeMap<String, SolverQuarantine>,
    pub public_records: BTreeMap<String, PublicRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            curves: BTreeMap::new(),
            bids: BTreeMap::new(),
            auctioneers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let auctioneer = state
            .register_auctioneer(RegisterAuctioneerRequest {
                operator_commitment: demo_root("operator-commitment"),
                pq_public_key_root: demo_root("pq-public-key"),
                fhe_eval_key_root: demo_root("fhe-eval-key"),
                stake_commitment_root: demo_root("stake-commitment"),
                bond_micro_units: DEFAULT_SOLVER_BOND_MICRO_UNITS,
                fee_bps: 9,
                registered_at_height: DEVNET_L2_HEIGHT,
            })
            .expect("demo auctioneer registers");
        let attestation = state
            .record_auctioneer_attestation(RecordAuctioneerAttestationRequest {
                auctioneer_id: auctioneer.auctioneer_id.clone(),
                verdict: AttestationVerdict::Valid,
                pq_signature_root: demo_root("attestation-signature"),
                fhe_circuit_root: demo_root("fhe-circuit"),
                enclave_measurement_root: demo_root("enclave-measurement"),
                transcript_root: demo_root("attestation-transcript"),
                min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                attested_at_height: DEVNET_L2_HEIGHT + 1,
            })
            .expect("demo attestation records");
        let curve = state
            .register_encrypted_curve(RegisterEncryptedCurveRequest {
                provider_commitment: demo_root("provider-commitment"),
                venue: AuctionVenue::MoneroBridgeExit,
                curve_kind: CurveKind::BridgeExitDepth,
                asset_pair_root: demo_root("xmr-usdc-asset-pair"),
                encrypted_curve_root: demo_root("encrypted-liquidity-curve"),
                liquidity_commitment_root: demo_root("liquidity-commitment"),
                fee_commitment_root: demo_root("fee-commitment"),
                invariant_commitment_root: demo_root("invariant-commitment"),
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                max_price_impact_bps: 42,
                opened_at_height: DEVNET_L2_HEIGHT + 2,
            })
            .expect("demo curve registers");
        let bid = state
            .admit_sealed_bid(AdmitSealedBidRequest {
                curve_id: curve.curve_id.clone(),
                bidder_commitment: demo_root("bidder-commitment"),
                solver_id: auctioneer.auctioneer_id.clone(),
                side: BidSide::ExitFill,
                sealed_bid_root: demo_root("sealed-bid"),
                amount_ciphertext_root: demo_root("amount-ciphertext"),
                limit_price_ciphertext_root: demo_root("limit-price-ciphertext"),
                fee_budget_commitment_root: demo_root("fee-budget"),
                nullifier_root: demo_root("bid-nullifier"),
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                user_fee_bps: 6,
                submitted_at_height: DEVNET_L2_HEIGHT + 3,
            })
            .expect("demo bid admits");
        let batch = state
            .build_clearing_batch(BuildClearingBatchRequest {
                auctioneer_id: auctioneer.auctioneer_id.clone(),
                curve_ids: vec![curve.curve_id.clone()],
                bid_ids: vec![bid.bid_id.clone()],
                aggregate_curve_root: demo_root("aggregate-curve"),
                aggregate_bid_root: demo_root("aggregate-bid"),
                clearing_price_root: demo_root("clearing-price"),
                allocation_root: demo_root("allocation"),
                settlement_root: demo_root("settlement"),
                public_output_root: demo_root("public-output"),
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                auctioneer_fee_bps: 9,
                built_at_height: DEVNET_L2_HEIGHT + 4,
            })
            .expect("demo batch clears");
        state
            .issue_low_fee_rebate(IssueLowFeeRebateRequest {
                batch_id: batch.batch_id.clone(),
                bid_id: bid.bid_id.clone(),
                recipient_commitment: demo_root("rebate-recipient"),
                reason: RebateReason::LowFeeLane,
                rebate_note_commitment: demo_root("rebate-note"),
                amount_micro_units: 3_200,
                rebate_bps: DEFAULT_MIN_LOW_FEE_REBATE_BPS,
                issued_at_height: DEVNET_L2_HEIGHT + 5,
            })
            .expect("demo rebate issues");
        state
            .charge_redaction_budget(ChargeRedactionBudgetRequest {
                subject_id: batch.batch_id.clone(),
                kind: RedactionKind::ClearingPrice,
                epoch: DEVNET_EPOCH,
                spent_units: 48,
                redaction_root: demo_root("clearing-redaction"),
                charged_at_height: DEVNET_L2_HEIGHT + 5,
            })
            .expect("demo redaction charges");
        let _ = attestation;
        state
    }

    pub fn register_auctioneer(
        &mut self,
        request: RegisterAuctioneerRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<Auctioneer> {
        ensure!(
            self.auctioneers.len() < MAX_AUCTIONEERS,
            "auctioneer capacity exceeded"
        );
        require_root("operator_commitment", &request.operator_commitment)?;
        require_root("pq_public_key_root", &request.pq_public_key_root)?;
        require_root("fhe_eval_key_root", &request.fhe_eval_key_root)?;
        require_root("stake_commitment_root", &request.stake_commitment_root)?;
        require_bps("fee_bps", request.fee_bps)?;
        ensure!(
            request.fee_bps <= self.config.max_auctioneer_fee_bps,
            "auctioneer fee {} exceeds configured max {}",
            request.fee_bps,
            self.config.max_auctioneer_fee_bps
        );
        ensure!(
            request.bond_micro_units >= self.config.solver_bond_micro_units,
            "auctioneer bond below configured minimum"
        );

        let auctioneer_id = auctioneer_id(&request, self.counters.auctioneers_registered + 1);
        let auctioneer = Auctioneer {
            auctioneer_id: auctioneer_id.clone(),
            operator_commitment: request.operator_commitment,
            status: AuctioneerStatus::Registered,
            pq_public_key_root: request.pq_public_key_root,
            fhe_eval_key_root: request.fhe_eval_key_root,
            stake_commitment_root: request.stake_commitment_root,
            bond_micro_units: request.bond_micro_units,
            fee_bps: request.fee_bps,
            registered_at_height: request.registered_at_height,
            latest_attestation_id: None,
        };
        self.auctioneers.insert(auctioneer_id, auctioneer.clone());
        self.counters.auctioneers_registered += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::Attestation,
            &auctioneer.auctioneer_id,
            &auctioneer.public_record(),
            request.registered_at_height,
        )?;
        Ok(auctioneer)
    }

    pub fn record_auctioneer_attestation(
        &mut self,
        request: RecordAuctioneerAttestationRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<AuctioneerAttestation> {
        ensure!(
            self.attestations.len() < MAX_ATTESTATIONS,
            "attestation capacity exceeded"
        );
        let status = self
            .auctioneers
            .get(&request.auctioneer_id)
            .map(|auctioneer| auctioneer.status)
            .ok_or_else(|| format!("unknown auctioneer {}", request.auctioneer_id))?;
        ensure!(
            !matches!(
                status,
                AuctioneerStatus::Quarantined | AuctioneerStatus::Retired
            ),
            "auctioneer cannot be attested while in terminal status"
        );
        require_root("pq_signature_root", &request.pq_signature_root)?;
        require_root("fhe_circuit_root", &request.fhe_circuit_root)?;
        require_root(
            "enclave_measurement_root",
            &request.enclave_measurement_root,
        )?;
        require_root("transcript_root", &request.transcript_root)?;
        ensure!(
            request.min_pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security below minimum"
        );

        let attestation_id = attestation_id(&request, self.counters.attestations_recorded + 1);
        let attestation = AuctioneerAttestation {
            attestation_id: attestation_id.clone(),
            auctioneer_id: request.auctioneer_id.clone(),
            verdict: request.verdict,
            pq_signature_root: request.pq_signature_root,
            fhe_circuit_root: request.fhe_circuit_root,
            enclave_measurement_root: request.enclave_measurement_root,
            transcript_root: request.transcript_root,
            min_pq_security_bits: request.min_pq_security_bits,
            attested_at_height: request.attested_at_height,
            expires_at_height: request
                .attested_at_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        if let Some(auctioneer) = self.auctioneers.get_mut(&request.auctioneer_id) {
            auctioneer.latest_attestation_id = Some(attestation_id.clone());
            auctioneer.status = if matches!(request.verdict, AttestationVerdict::Valid) {
                AuctioneerStatus::Active
            } else {
                AuctioneerStatus::RateLimited
            };
        }
        self.attestations
            .insert(attestation_id, attestation.clone());
        self.counters.attestations_recorded += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::Attestation,
            &attestation.attestation_id,
            &attestation.public_record(),
            request.attested_at_height,
        )?;
        Ok(attestation)
    }

    pub fn register_encrypted_curve(
        &mut self,
        request: RegisterEncryptedCurveRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<EncryptedLiquidityCurve> {
        ensure!(self.curves.len() < MAX_CURVES, "curve capacity exceeded");
        ensure!(
            self.config.allowed_venues.contains(&request.venue),
            "venue is not enabled"
        );
        require_root("provider_commitment", &request.provider_commitment)?;
        require_root("asset_pair_root", &request.asset_pair_root)?;
        require_root("encrypted_curve_root", &request.encrypted_curve_root)?;
        require_root(
            "liquidity_commitment_root",
            &request.liquidity_commitment_root,
        )?;
        require_root("fee_commitment_root", &request.fee_commitment_root)?;
        require_root(
            "invariant_commitment_root",
            &request.invariant_commitment_root,
        )?;
        require_bps("max_price_impact_bps", request.max_price_impact_bps)?;
        ensure!(
            request.max_price_impact_bps <= self.config.max_price_impact_bps,
            "curve price impact exceeds configured maximum"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "curve privacy set below minimum"
        );

        let curve_id = curve_id(&request, self.counters.curves_registered + 1);
        let curve = EncryptedLiquidityCurve {
            curve_id: curve_id.clone(),
            provider_commitment: request.provider_commitment,
            venue: request.venue,
            curve_kind: request.curve_kind,
            status: CurveStatus::Open,
            asset_pair_root: request.asset_pair_root,
            encrypted_curve_root: request.encrypted_curve_root,
            liquidity_commitment_root: request.liquidity_commitment_root,
            fee_commitment_root: request.fee_commitment_root,
            invariant_commitment_root: request.invariant_commitment_root,
            privacy_set_size: request.privacy_set_size,
            max_price_impact_bps: request.max_price_impact_bps,
            opened_at_height: request.opened_at_height,
            expires_at_height: request
                .opened_at_height
                .saturating_add(self.config.curve_ttl_blocks),
            attestation_id: None,
        };
        self.curves.insert(curve_id, curve.clone());
        self.counters.curves_registered += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::Curve,
            &curve.curve_id,
            &curve.public_record(),
            request.opened_at_height,
        )?;
        Ok(curve)
    }

    pub fn admit_sealed_bid(
        &mut self,
        request: AdmitSealedBidRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<SealedBid> {
        ensure!(self.bids.len() < MAX_BIDS, "bid capacity exceeded");
        let curve = self
            .curves
            .get(&request.curve_id)
            .ok_or_else(|| format!("unknown curve {}", request.curve_id))?;
        ensure!(curve.status.live(), "curve is not accepting bids");
        ensure!(
            request.submitted_at_height <= curve.expires_at_height,
            "bid submitted after curve expiry"
        );
        ensure!(
            !self
                .quarantines
                .values()
                .any(|q| q.solver_id == request.solver_id
                    && q.expires_at_height >= request.submitted_at_height),
            "solver is quarantined"
        );
        require_root("bidder_commitment", &request.bidder_commitment)?;
        require_non_empty("solver_id", &request.solver_id)?;
        require_root("sealed_bid_root", &request.sealed_bid_root)?;
        require_root("amount_ciphertext_root", &request.amount_ciphertext_root)?;
        require_root(
            "limit_price_ciphertext_root",
            &request.limit_price_ciphertext_root,
        )?;
        require_root(
            "fee_budget_commitment_root",
            &request.fee_budget_commitment_root,
        )?;
        require_root("nullifier_root", &request.nullifier_root)?;
        require_bps("user_fee_bps", request.user_fee_bps)?;
        ensure!(
            request.user_fee_bps <= self.config.max_user_fee_bps,
            "user fee exceeds configured maximum"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "bid privacy set below minimum"
        );

        let bid_id = bid_id(&request, self.counters.bids_admitted + 1);
        let bid = SealedBid {
            bid_id: bid_id.clone(),
            curve_id: request.curve_id.clone(),
            bidder_commitment: request.bidder_commitment,
            solver_id: request.solver_id,
            side: request.side,
            status: BidStatus::Admitted,
            sealed_bid_root: request.sealed_bid_root,
            amount_ciphertext_root: request.amount_ciphertext_root,
            limit_price_ciphertext_root: request.limit_price_ciphertext_root,
            fee_budget_commitment_root: request.fee_budget_commitment_root,
            nullifier_root: request.nullifier_root,
            privacy_set_size: request.privacy_set_size,
            user_fee_bps: request.user_fee_bps,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.bid_ttl_blocks),
        };
        if let Some(curve) = self.curves.get_mut(&request.curve_id) {
            curve.status = CurveStatus::Bidding;
        }
        self.bids.insert(bid_id, bid.clone());
        self.counters.bids_admitted += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::Bid,
            &bid.bid_id,
            &bid.public_record(),
            request.submitted_at_height,
        )?;
        Ok(bid)
    }

    pub fn build_clearing_batch(
        &mut self,
        request: BuildClearingBatchRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<ClearingBatch> {
        ensure!(
            self.clearing_batches.len() < MAX_CLEARING_BATCHES,
            "clearing batch capacity exceeded"
        );
        ensure!(!request.curve_ids.is_empty(), "batch requires curves");
        ensure!(!request.bid_ids.is_empty(), "batch requires bids");
        ensure!(unique_strings(&request.curve_ids), "duplicate curve ids");
        ensure!(unique_strings(&request.bid_ids), "duplicate bid ids");
        let auctioneer = self
            .auctioneers
            .get(&request.auctioneer_id)
            .ok_or_else(|| format!("unknown auctioneer {}", request.auctioneer_id))?;
        ensure!(
            auctioneer.status.can_clear(),
            "auctioneer is not allowed to clear"
        );
        ensure!(
            auctioneer.latest_attestation_id.is_some(),
            "auctioneer missing pq attestation"
        );
        for curve_id in &request.curve_ids {
            let curve = self
                .curves
                .get(curve_id)
                .ok_or_else(|| format!("unknown curve {curve_id}"))?;
            ensure!(curve.status.live(), "curve {curve_id} is not live");
            ensure!(
                request.built_at_height <= curve.expires_at_height,
                "curve {curve_id} expired before clearing"
            );
        }
        for bid_id in &request.bid_ids {
            let bid = self
                .bids
                .get(bid_id)
                .ok_or_else(|| format!("unknown bid {bid_id}"))?;
            ensure!(bid.status.batchable(), "bid {bid_id} is not batchable");
            ensure!(
                request.built_at_height <= bid.expires_at_height,
                "bid {bid_id} expired before clearing"
            );
        }
        require_root("aggregate_curve_root", &request.aggregate_curve_root)?;
        require_root("aggregate_bid_root", &request.aggregate_bid_root)?;
        require_root("clearing_price_root", &request.clearing_price_root)?;
        require_root("allocation_root", &request.allocation_root)?;
        require_root("settlement_root", &request.settlement_root)?;
        require_root("public_output_root", &request.public_output_root)?;
        require_bps("auctioneer_fee_bps", request.auctioneer_fee_bps)?;
        ensure!(
            request.auctioneer_fee_bps <= self.config.max_auctioneer_fee_bps,
            "auctioneer fee exceeds configured maximum"
        );
        ensure!(
            request.privacy_set_size >= self.config.batch_privacy_set_size,
            "batch privacy set below minimum"
        );

        let before_root = self.state_root();
        let batch_id = batch_id(&request, &before_root, self.counters.batches_cleared + 1);
        let batch = ClearingBatch {
            batch_id: batch_id.clone(),
            auctioneer_id: request.auctioneer_id.clone(),
            status: BatchStatus::Cleared,
            curve_ids: request.curve_ids.clone(),
            bid_ids: request.bid_ids.clone(),
            aggregate_curve_root: request.aggregate_curve_root,
            aggregate_bid_root: request.aggregate_bid_root,
            clearing_price_root: request.clearing_price_root,
            allocation_root: request.allocation_root,
            settlement_root: request.settlement_root,
            public_output_root: request.public_output_root,
            privacy_set_size: request.privacy_set_size,
            auctioneer_fee_bps: request.auctioneer_fee_bps,
            built_at_height: request.built_at_height,
            clears_at_height: request
                .built_at_height
                .saturating_add(self.config.clearing_ttl_blocks),
        };
        for curve_id in &request.curve_ids {
            if let Some(curve) = self.curves.get_mut(curve_id) {
                curve.status = CurveStatus::Cleared;
            }
        }
        for bid_id in &request.bid_ids {
            if let Some(bid) = self.bids.get_mut(bid_id) {
                bid.status = BidStatus::Won;
            }
        }
        self.clearing_batches.insert(batch_id, batch.clone());
        self.counters.batches_cleared += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::ClearingBatch,
            &batch.batch_id,
            &batch.public_record(),
            request.built_at_height,
        )?;
        Ok(batch)
    }

    pub fn issue_low_fee_rebate(
        &mut self,
        request: IssueLowFeeRebateRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<LowFeeRebate> {
        ensure!(self.rebates.len() < MAX_REBATES, "rebate capacity exceeded");
        ensure!(
            self.clearing_batches.contains_key(&request.batch_id),
            "unknown clearing batch"
        );
        let bid = self
            .bids
            .get_mut(&request.bid_id)
            .ok_or_else(|| format!("unknown bid {}", request.bid_id))?;
        require_root("recipient_commitment", &request.recipient_commitment)?;
        require_root("rebate_note_commitment", &request.rebate_note_commitment)?;
        require_bps("rebate_bps", request.rebate_bps)?;
        ensure!(
            request.rebate_bps >= self.config.min_low_fee_rebate_bps,
            "rebate bps below configured minimum"
        );
        ensure!(
            request.amount_micro_units <= self.config.rebate_budget_micro_units,
            "rebate amount exceeds configured budget"
        );

        let rebate_id = rebate_id(&request, self.counters.rebates_issued + 1);
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            batch_id: request.batch_id,
            bid_id: request.bid_id.clone(),
            recipient_commitment: request.recipient_commitment,
            reason: request.reason,
            rebate_note_commitment: request.rebate_note_commitment,
            amount_micro_units: request.amount_micro_units,
            rebate_bps: request.rebate_bps,
            issued_at_height: request.issued_at_height,
        };
        bid.status = BidStatus::Rebated;
        self.rebates.insert(rebate_id, rebate.clone());
        self.counters.rebates_issued += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::Rebate,
            &rebate.rebate_id,
            &rebate.public_record(),
            request.issued_at_height,
        )?;
        Ok(rebate)
    }

    pub fn charge_redaction_budget(
        &mut self,
        request: ChargeRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<RedactionBudget> {
        ensure!(
            self.redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity exceeded"
        );
        require_non_empty("subject_id", &request.subject_id)?;
        require_root("redaction_root", &request.redaction_root)?;
        ensure!(
            request.spent_units <= self.config.redaction_budget_units,
            "redaction spend exceeds configured budget"
        );
        let remaining_units = self
            .config
            .redaction_budget_units
            .saturating_sub(request.spent_units);
        let budget_id = redaction_budget_id(&request, self.counters.redactions_charged + 1);
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            subject_id: request.subject_id,
            kind: request.kind,
            epoch: request.epoch,
            spent_units: request.spent_units,
            remaining_units,
            redaction_root: request.redaction_root,
            charged_at_height: request.charged_at_height,
        };
        self.redaction_budgets.insert(budget_id, budget.clone());
        self.counters.redactions_charged += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::RedactionBudget,
            &budget.budget_id,
            &budget.public_record(),
            request.charged_at_height,
        )?;
        Ok(budget)
    }

    pub fn quarantine_solver(
        &mut self,
        request: QuarantineSolverRequest,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<SolverQuarantine> {
        ensure!(
            self.quarantines.len() < MAX_QUARANTINES,
            "quarantine capacity exceeded"
        );
        require_non_empty("solver_id", &request.solver_id)?;
        require_non_empty("subject_id", &request.subject_id)?;
        require_root("evidence_root", &request.evidence_root)?;
        require_bps("slash_bps", request.slash_bps)?;
        let quarantine_id = quarantine_id(&request, self.counters.solvers_quarantined + 1);
        let quarantine = SolverQuarantine {
            quarantine_id: quarantine_id.clone(),
            solver_id: request.solver_id.clone(),
            subject_id: request.subject_id,
            reason: request.reason,
            evidence_root: request.evidence_root,
            started_at_height: request.started_at_height,
            expires_at_height: request
                .started_at_height
                .saturating_add(self.config.quarantine_ttl_blocks),
            slash_bps: request.slash_bps,
        };
        if let Some(auctioneer) = self.auctioneers.get_mut(&request.solver_id) {
            auctioneer.status = AuctioneerStatus::Quarantined;
        }
        for bid in self.bids.values_mut() {
            if bid.solver_id == request.solver_id && bid.status.batchable() {
                bid.status = BidStatus::Quarantined;
            }
        }
        self.quarantines.insert(quarantine_id, quarantine.clone());
        self.counters.solvers_quarantined += 1;
        self.bump_transition();
        self.record_public_roots(
            PublicRecordKind::Quarantine,
            &quarantine.quarantine_id,
            &quarantine.public_record(),
            request.started_at_height,
        )?;
        Ok(quarantine)
    }

    pub fn record_public_roots(
        &mut self,
        kind: PublicRecordKind,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
    ) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<PublicRecord> {
        ensure!(
            self.public_records.len() < MAX_PUBLIC_RECORDS,
            "public record capacity exceeded"
        );
        require_non_empty("subject_id", subject_id)?;
        let payload_root = public_record_root(payload);
        let current_root = self.state_root();
        let record_id = public_record_id(kind, subject_id, &payload_root, &current_root);
        let record = PublicRecord {
            record_id: record_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            payload_root,
            state_root: current_root,
            emitted_at_height,
        };
        self.public_records.insert(record_id, record.clone());
        self.counters.public_records_emitted += 1;
        self.bump_transition();
        Ok(record)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_fhe_liquidity_auction_runtime",
            "protocol_version": self.config.protocol_version,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "curves_root": self.roots.curves_root,
                "bids_root": self.roots.bids_root,
                "auctioneers_root": self.roots.auctioneers_root,
                "attestations_root": self.roots.attestations_root,
                "clearing_batches_root": self.roots.clearing_batches_root,
                "rebates_root": self.roots.rebates_root,
                "redaction_budgets_root": self.roots.redaction_budgets_root,
                "quarantines_root": self.roots.quarantines_root,
                "public_records_root": self.roots.public_records_root,
                "counters_root": self.roots.counters_root,
                "config_root": self.roots.config_root,
            },
            "counts": {
                "curves": self.curves.len(),
                "bids": self.bids.len(),
                "auctioneers": self.auctioneers.len(),
                "attestations": self.attestations.len(),
                "clearing_batches": self.clearing_batches.len(),
                "rebates": self.rebates.len(),
                "redaction_budgets": self.redaction_budgets.len(),
                "quarantines": self.quarantines.len(),
                "public_records": self.public_records.len(),
            },
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    fn bump_transition(&mut self) {
        self.counters.state_transitions += 1;
        self.recompute_roots();
    }

    fn recompute_roots(&mut self) {
        self.roots.curves_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-CURVES",
            self.curves
                .values()
                .map(EncryptedLiquidityCurve::public_record)
                .collect(),
        );
        self.roots.bids_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-BIDS",
            self.bids.values().map(SealedBid::public_record).collect(),
        );
        self.roots.auctioneers_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-AUCTIONEERS",
            self.auctioneers
                .values()
                .map(Auctioneer::public_record)
                .collect(),
        );
        self.roots.attestations_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-ATTESTATIONS",
            self.attestations
                .values()
                .map(AuctioneerAttestation::public_record)
                .collect(),
        );
        self.roots.clearing_batches_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-BATCHES",
            self.clearing_batches
                .values()
                .map(ClearingBatch::public_record)
                .collect(),
        );
        self.roots.rebates_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-REBATES",
            self.rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect(),
        );
        self.roots.redaction_budgets_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-REDACTIONS",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect(),
        );
        self.roots.quarantines_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-QUARANTINES",
            self.quarantines
                .values()
                .map(SolverQuarantine::public_record)
                .collect(),
        );
        self.roots.public_records_root = map_root(
            "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-PUBLIC-RECORDS",
            self.public_records
                .values()
                .map(PublicRecord::public_record)
                .collect(),
        );
        self.roots.counters_root = public_record_root(&self.counters.public_record());
        self.roots.config_root = public_record_root(&self.config.public_record());
        self.roots.state_root = self.state_root();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> serde_json::Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-FHE-LIQUIDITY-AUCTION-PUBLIC-RECORD-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-FHE-LIQUIDITY-AUCTION-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn auctioneer_id(request: &RegisterAuctioneerRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-AUCTIONEER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.fhe_eval_key_root),
            HashPart::Int(request.registered_at_height as i128),
        ],
        32,
    )
}

pub fn attestation_id(request: &RecordAuctioneerAttestationRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.auctioneer_id),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.fhe_circuit_root),
            HashPart::Int(request.attested_at_height as i128),
        ],
        32,
    )
}

pub fn curve_id(request: &RegisterEncryptedCurveRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-CURVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.provider_commitment),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(request.curve_kind.as_str()),
            HashPart::Str(&request.asset_pair_root),
            HashPart::Str(&request.encrypted_curve_root),
            HashPart::Int(request.opened_at_height as i128),
        ],
        32,
    )
}

pub fn bid_id(request: &AdmitSealedBidRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.curve_id),
            HashPart::Str(&request.bidder_commitment),
            HashPart::Str(&request.solver_id),
            HashPart::Str(request.side.as_str()),
            HashPart::Str(&request.sealed_bid_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Int(request.submitted_at_height as i128),
        ],
        32,
    )
}

pub fn batch_id(
    request: &BuildClearingBatchRequest,
    state_root_before: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.auctioneer_id),
            HashPart::Str(&list_root("BATCH-CURVES", &request.curve_ids)),
            HashPart::Str(&list_root("BATCH-BIDS", &request.bid_ids)),
            HashPart::Str(&request.aggregate_curve_root),
            HashPart::Str(&request.aggregate_bid_root),
            HashPart::Str(&request.clearing_price_root),
            HashPart::Str(state_root_before),
            HashPart::Int(request.built_at_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(request: &IssueLowFeeRebateRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.bid_id),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.recipient_commitment),
            HashPart::Str(&request.rebate_note_commitment),
            HashPart::Int(request.amount_micro_units as i128),
        ],
        32,
    )
}

pub fn redaction_budget_id(request: &ChargeRedactionBudgetRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Int(request.epoch as i128),
            HashPart::Str(&request.redaction_root),
        ],
        32,
    )
}

pub fn quarantine_id(request: &QuarantineSolverRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Int(request.started_at_height as i128),
        ],
        32,
    )
}

pub fn public_record_id(
    kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    state_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Str(state_root),
        ],
        32,
    )
}

fn map_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn list_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn unique_strings(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<()> {
    if value > MAX_BPS {
        return Err(format!("{label} cannot exceed {MAX_BPS}"));
    }
    Ok(())
}

fn require_root(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialFheLiquidityAuctionRuntimeResult<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn demo_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-LIQUIDITY-AUCTION-DEMO-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}
