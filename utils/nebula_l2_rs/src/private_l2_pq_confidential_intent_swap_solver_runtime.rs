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
    "nebula-private-l2-pq-confidential-intent-swap-solver-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_INTENT_SUITE: &str = "ML-KEM-1024+zk-sealed-confidential-swap-intent-v1";
pub const SOLVER_COMMITMENT_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-commit-reveal-route-v1";
pub const ROUTE_QUOTE_SUITE: &str = "roots-only-confidential-route-quote-v1";
pub const CLEARING_SUITE: &str = "deterministic-batch-clearing-private-swap-v1";
pub const PRIVACY_FENCE_SUITE: &str = "zk-nullifier-mev-privacy-fence-v1";
pub const FEE_REBATE_SUITE: &str = "confidential-intent-solver-fee-rebate-v1";
pub const SLASHING_EVIDENCE_SUITE: &str = "pq-signed-private-swap-solver-slashing-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_772_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_512_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_COMMIT_REVEAL_BLOCKS: u64 = 6;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_MAX_INTENTS_PER_BATCH: usize = 1_024;
pub const DEFAULT_MAX_QUOTES_PER_INTENT: usize = 32;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 24;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_SURPLUS_REBATE_BPS: u64 = 5;
pub const DEFAULT_REBATE_BUDGET_MICRO_UNITS: u64 = 250_000_000;
pub const DEFAULT_SOLVER_BOND_MICRO_UNITS: u64 = 4_000_000;
pub const DEFAULT_SLASHING_ESCROW_MICRO_UNITS: u64 = 80_000_000;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 150;
pub const DEFAULT_MAX_FENCE_DELAY_MS: u64 = 2_000;
pub const MAX_INTENTS: usize = 262_144;
pub const MAX_SOLVERS: usize = 65_536;
pub const MAX_COMMITMENTS: usize = 1_048_576;
pub const MAX_QUOTES: usize = 1_048_576;
pub const MAX_BATCHES: usize = 262_144;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_SLASHES: usize = 262_144;
pub const MAX_FENCES: usize = 1_048_576;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapIntentKind {
    ExactInput,
    ExactOutput,
    LimitBuy,
    LimitSell,
    TwapSlice,
    CrossPoolArbShield,
    BridgeThenSwap,
    SwapThenBridge,
}

impl SwapIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactInput => "exact_input",
            Self::ExactOutput => "exact_output",
            Self::LimitBuy => "limit_buy",
            Self::LimitSell => "limit_sell",
            Self::TwapSlice => "twap_slice",
            Self::CrossPoolArbShield => "cross_pool_arb_shield",
            Self::BridgeThenSwap => "bridge_then_swap",
            Self::SwapThenBridge => "swap_then_bridge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapVenueKind {
    ConfidentialAmm,
    StableSwap,
    Darkpool,
    PrivateRfq,
    InternalNetting,
    MoneroBridgeLiquidity,
    CrossRollupLiquidity,
    VaultRouter,
}

impl SwapVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAmm => "confidential_amm",
            Self::StableSwap => "stable_swap",
            Self::Darkpool => "darkpool",
            Self::PrivateRfq => "private_rfq",
            Self::InternalNetting => "internal_netting",
            Self::MoneroBridgeLiquidity => "monero_bridge_liquidity",
            Self::CrossRollupLiquidity => "cross_rollup_liquidity",
            Self::VaultRouter => "vault_router",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    SolverCommitted,
    QuoteRevealed,
    PrivacyFenced,
    Batched,
    Clearing,
    Settled,
    RebateIssued,
    Slashed,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::SolverCommitted => "solver_committed",
            Self::QuoteRevealed => "quote_revealed",
            Self::PrivacyFenced => "privacy_fenced",
            Self::Batched => "batched",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::RebateIssued => "rebate_issued",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::Admitted
                | Self::SolverCommitted
                | Self::QuoteRevealed
                | Self::PrivacyFenced
        )
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Admitted | Self::SolverCommitted | Self::QuoteRevealed | Self::PrivacyFenced
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Registered,
    Active,
    RateLimited,
    Quarantined,
    Slashed,
    Retired,
}

impl SolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_quote(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Committed,
    Revealed,
    Selected,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Published,
    Eligible,
    Selected,
    Settled,
    Rejected,
    Expired,
    Disputed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingStatus {
    Built,
    PrivacyLocked,
    SolverSelected,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl ClearingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::PrivacyLocked => "privacy_locked",
            Self::SolverSelected => "solver_selected",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Nullifier,
    AccountEpoch,
    RouteEntropy,
    SolverConflict,
    BatchOrdering,
    BridgeExit,
    PriceImpact,
    Replay,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::AccountEpoch => "account_epoch",
            Self::RouteEntropy => "route_entropy",
            Self::SolverConflict => "solver_conflict",
            Self::BatchOrdering => "batch_ordering",
            Self::BridgeExit => "bridge_exit",
            Self::PriceImpact => "price_impact",
            Self::Replay => "replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceVerdict {
    Pass,
    Delay,
    Quarantine,
    Reject,
}

impl FenceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Delay => "delay",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    BatchNetting,
    SolverSurplusShare,
    LowFeeLane,
    MevFenceDelay,
    RouteCompression,
    SponsorTopup,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchNetting => "batch_netting",
            Self::SolverSurplusShare => "solver_surplus_share",
            Self::LowFeeLane => "low_fee_lane",
            Self::MevFenceDelay => "mev_fence_delay",
            Self::RouteCompression => "route_compression",
            Self::SponsorTopup => "sponsor_topup",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidReveal,
    QuoteWithholding,
    PriceManipulation,
    FenceBypass,
    DuplicateNullifier,
    SettlementFailure,
    PqSignatureFailure,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidReveal => "invalid_reveal",
            Self::QuoteWithholding => "quote_withholding",
            Self::PriceManipulation => "price_manipulation",
            Self::FenceBypass => "fence_bypass",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::SettlementFailure => "settlement_failure",
            Self::PqSignatureFailure => "pq_signature_failure",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    Config,
    Solver,
    Intent,
    Commitment,
    Quote,
    Fence,
    ClearingBatch,
    Rebate,
    SlashingEvidence,
    StateCheckpoint,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Solver => "solver",
            Self::Intent => "intent",
            Self::Commitment => "commitment",
            Self::Quote => "quote",
            Self::Fence => "fence",
            Self::ClearingBatch => "clearing_batch",
            Self::Rebate => "rebate",
            Self::SlashingEvidence => "slashing_evidence",
            Self::StateCheckpoint => "state_checkpoint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub sealed_intent_suite: String,
    pub solver_commitment_suite: String,
    pub route_quote_suite: String,
    pub clearing_suite: String,
    pub privacy_fence_suite: String,
    pub fee_rebate_suite: String,
    pub slashing_evidence_suite: String,
    pub public_record_suite: String,
    pub intent_ttl_blocks: u64,
    pub commit_reveal_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub max_intents_per_batch: usize,
    pub max_quotes_per_intent: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_surplus_rebate_bps: u64,
    pub rebate_budget_micro_units: u64,
    pub solver_bond_micro_units: u64,
    pub slashing_escrow_micro_units: u64,
    pub max_price_impact_bps: u64,
    pub max_fence_delay_ms: u64,
    pub require_pq_attestations: bool,
    pub require_roots_only_records: bool,
    pub reject_duplicate_nullifiers: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            sealed_intent_suite: SEALED_INTENT_SUITE.to_string(),
            solver_commitment_suite: SOLVER_COMMITMENT_SUITE.to_string(),
            route_quote_suite: ROUTE_QUOTE_SUITE.to_string(),
            clearing_suite: CLEARING_SUITE.to_string(),
            privacy_fence_suite: PRIVACY_FENCE_SUITE.to_string(),
            fee_rebate_suite: FEE_REBATE_SUITE.to_string(),
            slashing_evidence_suite: SLASHING_EVIDENCE_SUITE.to_string(),
            public_record_suite: PUBLIC_RECORD_SUITE.to_string(),
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            commit_reveal_blocks: DEFAULT_COMMIT_REVEAL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            max_intents_per_batch: DEFAULT_MAX_INTENTS_PER_BATCH,
            max_quotes_per_intent: DEFAULT_MAX_QUOTES_PER_INTENT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            min_surplus_rebate_bps: DEFAULT_MIN_SURPLUS_REBATE_BPS,
            rebate_budget_micro_units: DEFAULT_REBATE_BUDGET_MICRO_UNITS,
            solver_bond_micro_units: DEFAULT_SOLVER_BOND_MICRO_UNITS,
            slashing_escrow_micro_units: DEFAULT_SLASHING_ESCROW_MICRO_UNITS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_fence_delay_ms: DEFAULT_MAX_FENCE_DELAY_MS,
            require_pq_attestations: true,
            require_roots_only_records: true,
            reject_duplicate_nullifiers: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("chain id", &self.chain_id)?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version",
        )?;
        require(self.intent_ttl_blocks > 0, "intent ttl must be positive")?;
        require(
            self.commit_reveal_blocks > 0,
            "commit reveal blocks must be positive",
        )?;
        require(self.quote_ttl_blocks > 0, "quote ttl must be positive")?;
        require(
            self.clearing_ttl_blocks > 0,
            "clearing ttl must be positive",
        )?;
        require(
            self.max_intents_per_batch > 0 && self.max_intents_per_batch <= MAX_INTENTS,
            "max intents per batch out of range",
        )?;
        require(
            self.max_quotes_per_intent > 0 && self.max_quotes_per_intent <= MAX_SOLVERS,
            "max quotes per intent out of range",
        )?;
        require(
            self.min_privacy_set_size > 0
                && self.batch_privacy_set_size >= self.min_privacy_set_size,
            "privacy set sizes are inconsistent",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "post-quantum security below policy",
        )?;
        require_bps("max user fee bps", self.max_user_fee_bps)?;
        require_bps("max solver fee bps", self.max_solver_fee_bps)?;
        require_bps("min surplus rebate bps", self.min_surplus_rebate_bps)?;
        require_bps("max price impact bps", self.max_price_impact_bps)?;
        require(
            self.rebate_budget_micro_units > 0,
            "rebate budget must be positive",
        )?;
        require(
            self.solver_bond_micro_units > 0,
            "solver bond must be positive",
        )?;
        require(
            self.slashing_escrow_micro_units >= self.solver_bond_micro_units,
            "slashing escrow must cover at least one solver bond",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_solver_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_suite": self.sealed_intent_suite,
            "solver_commitment_suite": self.solver_commitment_suite,
            "route_quote_suite": self.route_quote_suite,
            "clearing_suite": self.clearing_suite,
            "privacy_fence_suite": self.privacy_fence_suite,
            "fee_rebate_suite": self.fee_rebate_suite,
            "slashing_evidence_suite": self.slashing_evidence_suite,
            "public_record_suite": self.public_record_suite,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "commit_reveal_blocks": self.commit_reveal_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "clearing_ttl_blocks": self.clearing_ttl_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_quotes_per_intent": self.max_quotes_per_intent,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_surplus_rebate_bps": self.min_surplus_rebate_bps,
            "rebate_budget_micro_units": self.rebate_budget_micro_units,
            "solver_bond_micro_units": self.solver_bond_micro_units,
            "slashing_escrow_micro_units": self.slashing_escrow_micro_units,
            "max_price_impact_bps": self.max_price_impact_bps,
            "max_fence_delay_ms": self.max_fence_delay_ms,
            "require_pq_attestations": self.require_pq_attestations,
            "require_roots_only_records": self.require_roots_only_records,
            "reject_duplicate_nullifiers": self.reject_duplicate_nullifiers,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_solver_nonce: u64,
    pub next_intent_nonce: u64,
    pub next_commitment_nonce: u64,
    pub next_quote_nonce: u64,
    pub next_fence_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_rebate_nonce: u64,
    pub next_slash_nonce: u64,
    pub solvers_registered: u64,
    pub intents_admitted: u64,
    pub commitments_recorded: u64,
    pub quotes_published: u64,
    pub fences_recorded: u64,
    pub batches_cleared: u64,
    pub rebates_issued: u64,
    pub slashes_recorded: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_solver_counters",
            "next_solver_nonce": self.next_solver_nonce,
            "next_intent_nonce": self.next_intent_nonce,
            "next_commitment_nonce": self.next_commitment_nonce,
            "next_quote_nonce": self.next_quote_nonce,
            "next_fence_nonce": self.next_fence_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "next_rebate_nonce": self.next_rebate_nonce,
            "next_slash_nonce": self.next_slash_nonce,
            "solvers_registered": self.solvers_registered,
            "intents_admitted": self.intents_admitted,
            "commitments_recorded": self.commitments_recorded,
            "quotes_published": self.quotes_published,
            "fences_recorded": self.fences_recorded,
            "batches_cleared": self.batches_cleared,
            "rebates_issued": self.rebates_issued,
            "slashes_recorded": self.slashes_recorded,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSolverRequest {
    pub operator_commitment: String,
    pub pq_public_key_root: String,
    pub bond_note_commitment: String,
    pub allowed_venue_kinds: Vec<SwapVenueKind>,
    pub max_quote_notional_micro_units: u64,
    pub solver_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
}

impl RegisterSolverRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("operator commitment", &self.operator_commitment)?;
        require_root("pq public key root", &self.pq_public_key_root)?;
        require_root("bond note commitment", &self.bond_note_commitment)?;
        require(
            !self.allowed_venue_kinds.is_empty(),
            "solver venues cannot be empty",
        )?;
        require(
            self.max_quote_notional_micro_units > 0,
            "max quote notional must be positive",
        )?;
        require_bps("solver fee bps", self.solver_fee_bps)?;
        require(
            self.solver_fee_bps <= config.max_solver_fee_bps,
            "solver fee exceeds config cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "solver privacy set below config minimum",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "solver pq security below config minimum",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitSealedSwapIntentRequest {
    pub account_commitment: String,
    pub intent_kind: SwapIntentKind,
    pub input_asset_root: String,
    pub output_asset_root: String,
    pub sealed_intent_root: String,
    pub amount_commitment_root: String,
    pub limit_price_root: String,
    pub nullifier_root: String,
    pub refund_note_commitment: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitSealedSwapIntentRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("account commitment", &self.account_commitment)?;
        require_root("input asset root", &self.input_asset_root)?;
        require_root("output asset root", &self.output_asset_root)?;
        require_root("sealed intent root", &self.sealed_intent_root)?;
        require_root("amount commitment root", &self.amount_commitment_root)?;
        require_root("limit price root", &self.limit_price_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_root("refund note commitment", &self.refund_note_commitment)?;
        require_bps("max user fee bps", self.max_user_fee_bps)?;
        require(
            self.max_user_fee_bps <= config.max_user_fee_bps,
            "user fee exceeds config cap",
        )?;
        require(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "intent privacy set below config minimum",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "intent pq security below config minimum",
        )?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "intent expiry must be after submission",
        )?;
        require(
            self.expires_at_height - self.submitted_at_height <= config.intent_ttl_blocks,
            "intent ttl exceeds config",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSolverRouteRequest {
    pub solver_id: String,
    pub intent_id: String,
    pub route_commitment_root: String,
    pub quote_commitment_root: String,
    pub mev_fence_commitment_root: String,
    pub pq_signature_root: String,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
}

impl CommitSolverRouteRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("solver id", &self.solver_id)?;
        require_root("intent id", &self.intent_id)?;
        require_root("route commitment root", &self.route_commitment_root)?;
        require_root("quote commitment root", &self.quote_commitment_root)?;
        require_root("mev fence commitment root", &self.mev_fence_commitment_root)?;
        require_root("pq signature root", &self.pq_signature_root)?;
        require(
            self.reveal_deadline_height > self.committed_at_height,
            "reveal deadline must be after commitment",
        )?;
        require(
            self.reveal_deadline_height - self.committed_at_height <= config.commit_reveal_blocks,
            "commit reveal window exceeds config",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevealRouteQuoteRequest {
    pub commitment_id: String,
    pub solver_id: String,
    pub intent_id: String,
    pub venues: Vec<SwapVenueKind>,
    pub route_leaf_root: String,
    pub expected_output_commitment: String,
    pub solver_fee_bps: u64,
    pub price_impact_bps: u64,
    pub surplus_commitment_root: String,
    pub rebate_commitment_root: String,
    pub settlement_calldata_root: String,
    pub quote_valid_until_height: u64,
    pub revealed_at_height: u64,
}

impl RevealRouteQuoteRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("commitment id", &self.commitment_id)?;
        require_root("solver id", &self.solver_id)?;
        require_root("intent id", &self.intent_id)?;
        require(!self.venues.is_empty(), "route venues cannot be empty")?;
        require_root("route leaf root", &self.route_leaf_root)?;
        require_root(
            "expected output commitment",
            &self.expected_output_commitment,
        )?;
        require_bps("solver fee bps", self.solver_fee_bps)?;
        require(
            self.solver_fee_bps <= config.max_solver_fee_bps,
            "solver fee exceeds config cap",
        )?;
        require_bps("price impact bps", self.price_impact_bps)?;
        require(
            self.price_impact_bps <= config.max_price_impact_bps,
            "price impact exceeds config cap",
        )?;
        require_root("surplus commitment root", &self.surplus_commitment_root)?;
        require_root("rebate commitment root", &self.rebate_commitment_root)?;
        require_root("settlement calldata root", &self.settlement_calldata_root)?;
        require(
            self.quote_valid_until_height > self.revealed_at_height,
            "quote validity must be after reveal",
        )?;
        require(
            self.quote_valid_until_height - self.revealed_at_height <= config.quote_ttl_blocks,
            "quote ttl exceeds config",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPrivacyFenceRequest {
    pub intent_id: String,
    pub solver_id: Option<String>,
    pub quote_id: Option<String>,
    pub fence_kind: FenceKind,
    pub verdict: FenceVerdict,
    pub fence_root: String,
    pub evidence_root: String,
    pub delay_ms: u64,
    pub privacy_set_size: u64,
    pub recorded_at_height: u64,
}

impl RecordPrivacyFenceRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("intent id", &self.intent_id)?;
        if let Some(solver_id) = &self.solver_id {
            require_root("solver id", solver_id)?;
        }
        if let Some(quote_id) = &self.quote_id {
            require_root("quote id", quote_id)?;
        }
        require_root("fence root", &self.fence_root)?;
        require_root("evidence root", &self.evidence_root)?;
        require(
            self.delay_ms <= config.max_fence_delay_ms,
            "fence delay exceeds config cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "fence privacy set below config minimum",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildClearingBatchRequest {
    pub batch_label: String,
    pub intent_ids: Vec<String>,
    pub selected_quote_ids: Vec<String>,
    pub aggregate_intent_root: String,
    pub aggregate_quote_root: String,
    pub clearing_price_root: String,
    pub netted_flow_root: String,
    pub mev_fence_root: String,
    pub batch_privacy_set_size: u64,
    pub selected_solver_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildClearingBatchRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch label", &self.batch_label)?;
        require(!self.intent_ids.is_empty(), "batch intents cannot be empty")?;
        require(
            self.intent_ids.len() <= config.max_intents_per_batch,
            "batch has too many intents",
        )?;
        require(
            self.intent_ids.len() == self.selected_quote_ids.len(),
            "intent and selected quote counts must match",
        )?;
        for intent_id in &self.intent_ids {
            require_root("intent id", intent_id)?;
        }
        for quote_id in &self.selected_quote_ids {
            require_root("selected quote id", quote_id)?;
        }
        require_root("aggregate intent root", &self.aggregate_intent_root)?;
        require_root("aggregate quote root", &self.aggregate_quote_root)?;
        require_root("clearing price root", &self.clearing_price_root)?;
        require_root("netted flow root", &self.netted_flow_root)?;
        require_root("mev fence root", &self.mev_fence_root)?;
        require(
            self.batch_privacy_set_size >= config.batch_privacy_set_size,
            "batch privacy set below config minimum",
        )?;
        require_bps("selected solver fee bps", self.selected_solver_fee_bps)?;
        require(
            self.selected_solver_fee_bps <= config.max_solver_fee_bps,
            "selected solver fee exceeds config cap",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleClearingBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub output_note_root: String,
    pub fee_note_root: String,
    pub runtime_state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettleClearingBatchRequest {
    pub fn validate(&self) -> Result<()> {
        require_root("batch id", &self.batch_id)?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("settlement proof root", &self.settlement_proof_root)?;
        require_root("output note root", &self.output_note_root)?;
        require_root("fee note root", &self.fee_note_root)?;
        require_root("runtime state root after", &self.runtime_state_root_after)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            require(
                finalized_at_height >= self.settled_at_height,
                "finalized height cannot precede settled height",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueFeeRebateRequest {
    pub intent_id: String,
    pub quote_id: Option<String>,
    pub batch_id: Option<String>,
    pub recipient_commitment: String,
    pub rebate_reason: RebateReason,
    pub rebate_note_commitment: String,
    pub amount_micro_units: u64,
    pub issued_at_height: u64,
}

impl IssueFeeRebateRequest {
    pub fn validate(&self) -> Result<()> {
        require_root("intent id", &self.intent_id)?;
        if let Some(quote_id) = &self.quote_id {
            require_root("quote id", quote_id)?;
        }
        if let Some(batch_id) = &self.batch_id {
            require_root("batch id", batch_id)?;
        }
        require_root("recipient commitment", &self.recipient_commitment)?;
        require_root("rebate note commitment", &self.rebate_note_commitment)?;
        require(
            self.amount_micro_units > 0,
            "rebate amount must be positive",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitSlashingEvidenceRequest {
    pub solver_id: String,
    pub commitment_id: Option<String>,
    pub quote_id: Option<String>,
    pub batch_id: Option<String>,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slash_amount_micro_units: u64,
    pub submitted_at_height: u64,
}

impl SubmitSlashingEvidenceRequest {
    pub fn validate(&self) -> Result<()> {
        require_root("solver id", &self.solver_id)?;
        if let Some(commitment_id) = &self.commitment_id {
            require_root("commitment id", commitment_id)?;
        }
        if let Some(quote_id) = &self.quote_id {
            require_root("quote id", quote_id)?;
        }
        if let Some(batch_id) = &self.batch_id {
            require_root("batch id", batch_id)?;
        }
        require_root("evidence root", &self.evidence_root)?;
        require_root("challenger commitment", &self.challenger_commitment)?;
        require(
            self.slash_amount_micro_units > 0,
            "slash amount must be positive",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverRecord {
    pub solver_id: String,
    pub request: RegisterSolverRequest,
    pub status: SolverStatus,
    pub bond_locked_micro_units: u64,
    pub total_quotes: u64,
    pub total_selected: u64,
    pub total_settled: u64,
    pub total_slashed_micro_units: u64,
}

impl SolverRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_solver",
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "request": self.request,
            "bond_locked_micro_units": self.bond_locked_micro_units,
            "total_quotes": self.total_quotes,
            "total_selected": self.total_selected,
            "total_settled": self.total_settled,
            "total_slashed_micro_units": self.total_slashed_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSwapIntentRecord {
    pub intent_id: String,
    pub request: SubmitSealedSwapIntentRequest,
    pub status: IntentStatus,
    pub selected_quote_id: Option<String>,
    pub batch_id: Option<String>,
    pub fence_ids: Vec<String>,
    pub rebate_ids: Vec<String>,
}

impl SealedSwapIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_swap_intent",
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "request": self.request,
            "selected_quote_id": self.selected_quote_id,
            "batch_id": self.batch_id,
            "fence_ids": self.fence_ids,
            "rebate_ids": self.rebate_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitmentRecord {
    pub commitment_id: String,
    pub request: CommitSolverRouteRequest,
    pub status: CommitmentStatus,
    pub quote_id: Option<String>,
    pub score: u128,
}

impl SolverCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_solver_commitment",
            "commitment_id": self.commitment_id,
            "request": self.request,
            "status": self.status.as_str(),
            "quote_id": self.quote_id,
            "score": self.score.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteQuoteRecord {
    pub quote_id: String,
    pub request: RevealRouteQuoteRequest,
    pub status: QuoteStatus,
    pub score: u128,
    pub selected_at_height: Option<u64>,
}

impl RouteQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_route_quote",
            "quote_id": self.quote_id,
            "request": self.request,
            "status": self.status.as_str(),
            "score": self.score.to_string(),
            "selected_at_height": self.selected_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub request: RecordPrivacyFenceRequest,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_swap_privacy_fence",
            "fence_id": self.fence_id,
            "intent_id": self.request.intent_id,
            "solver_id": self.request.solver_id,
            "quote_id": self.request.quote_id,
            "fence_kind": self.request.fence_kind.as_str(),
            "verdict": self.request.verdict.as_str(),
            "fence_root": self.request.fence_root,
            "evidence_root": self.request.evidence_root,
            "delay_ms": self.request.delay_ms,
            "privacy_set_size": self.request.privacy_set_size,
            "recorded_at_height": self.request.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearingBatchRecord {
    pub batch_id: String,
    pub request: BuildClearingBatchRequest,
    pub status: ClearingStatus,
    pub state_root_before: String,
    pub state_root_after: Option<String>,
    pub settlement_deadline_height: u64,
    pub settled_at_height: Option<u64>,
}

impl ClearingBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_clearing_batch",
            "batch_id": self.batch_id,
            "request": self.request,
            "status": self.status.as_str(),
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "settlement_deadline_height": self.settlement_deadline_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub request: IssueFeeRebateRequest,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_fee_rebate",
            "rebate_id": self.rebate_id,
            "intent_id": self.request.intent_id,
            "quote_id": self.request.quote_id,
            "batch_id": self.request.batch_id,
            "recipient_commitment": self.request.recipient_commitment,
            "rebate_reason": self.request.rebate_reason.as_str(),
            "rebate_note_commitment": self.request.rebate_note_commitment,
            "amount_micro_units": self.request.amount_micro_units,
            "issued_at_height": self.request.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidenceRecord {
    pub slash_id: String,
    pub request: SubmitSlashingEvidenceRequest,
    pub state_root_before: String,
    pub state_root_after: String,
}

impl SlashingEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_slashing_evidence",
            "slash_id": self.slash_id,
            "solver_id": self.request.solver_id,
            "commitment_id": self.request.commitment_id,
            "quote_id": self.request.quote_id,
            "batch_id": self.request.batch_id,
            "reason": self.request.reason.as_str(),
            "evidence_root": self.request.evidence_root,
            "challenger_commitment": self.request.challenger_commitment,
            "slash_amount_micro_units": self.request.slash_amount_micro_units,
            "submitted_at_height": self.request.submitted_at_height,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root: String,
    pub height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "state_root": self.state_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub solver_root: String,
    pub intent_root: String,
    pub commitment_root: String,
    pub quote_root: String,
    pub fence_root: String,
    pub batch_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_roots",
            "config_root": self.config_root,
            "solver_root": self.solver_root,
            "intent_root": self.intent_root,
            "commitment_root": self.commitment_root,
            "quote_root": self.quote_root,
            "fence_root": self.fence_root,
            "batch_root": self.batch_root,
            "rebate_root": self.rebate_root,
            "slashing_root": self.slashing_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub rebate_budget_remaining_micro_units: u64,
    pub slashing_escrow_remaining_micro_units: u64,
    pub runtime_root: String,
    pub solvers: BTreeMap<String, SolverRecord>,
    pub intents: BTreeMap<String, SealedSwapIntentRecord>,
    pub commitments: BTreeMap<String, SolverCommitmentRecord>,
    pub quotes: BTreeMap<String, RouteQuoteRecord>,
    pub fences: BTreeMap<String, PrivacyFenceRecord>,
    pub batches: BTreeMap<String, ClearingBatchRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub slashes: BTreeMap<String, SlashingEvidenceRecord>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub spent_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_monero_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            rebate_budget_remaining_micro_units: config.rebate_budget_micro_units,
            slashing_escrow_remaining_micro_units: config.slashing_escrow_micro_units,
            config,
            counters: Counters::default(),
            current_l2_height,
            current_monero_height,
            runtime_root: deterministic_root("RUNTIME", "genesis"),
            solvers: BTreeMap::new(),
            intents: BTreeMap::new(),
            commitments: BTreeMap::new(),
            quotes: BTreeMap::new(),
            fences: BTreeMap::new(),
            batches: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashes: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifier_roots: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default(), DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT)
            .expect("devnet config");
        let solver_a = state
            .register_solver(RegisterSolverRequest {
                operator_commitment: deterministic_root("OPERATOR", "solver-alpha"),
                pq_public_key_root: deterministic_root("PQ-PK", "solver-alpha"),
                bond_note_commitment: deterministic_root("BOND", "solver-alpha"),
                allowed_venue_kinds: vec![
                    SwapVenueKind::ConfidentialAmm,
                    SwapVenueKind::StableSwap,
                    SwapVenueKind::InternalNetting,
                ],
                max_quote_notional_micro_units: 50_000_000,
                solver_fee_bps: 12,
                privacy_set_size: 512,
                pq_security_bits: 256,
                registered_at_height: DEVNET_L2_HEIGHT,
            })
            .expect("devnet solver alpha");
        let solver_b = state
            .register_solver(RegisterSolverRequest {
                operator_commitment: deterministic_root("OPERATOR", "solver-beta"),
                pq_public_key_root: deterministic_root("PQ-PK", "solver-beta"),
                bond_note_commitment: deterministic_root("BOND", "solver-beta"),
                allowed_venue_kinds: vec![
                    SwapVenueKind::Darkpool,
                    SwapVenueKind::PrivateRfq,
                    SwapVenueKind::MoneroBridgeLiquidity,
                ],
                max_quote_notional_micro_units: 75_000_000,
                solver_fee_bps: 14,
                privacy_set_size: 768,
                pq_security_bits: 256,
                registered_at_height: DEVNET_L2_HEIGHT,
            })
            .expect("devnet solver beta");
        let intent_a = state
            .submit_sealed_intent(SubmitSealedSwapIntentRequest {
                account_commitment: deterministic_root("ACCOUNT", "alice"),
                intent_kind: SwapIntentKind::ExactInput,
                input_asset_root: deterministic_root("ASSET", "dxmr"),
                output_asset_root: deterministic_root("ASSET", "dusd"),
                sealed_intent_root: deterministic_root("SEALED-INTENT", "alice-swap"),
                amount_commitment_root: deterministic_root("AMOUNT", "alice-swap"),
                limit_price_root: deterministic_root("PRICE", "alice-swap"),
                nullifier_root: deterministic_root("NULLIFIER", "alice-swap"),
                refund_note_commitment: deterministic_root("REFUND", "alice-swap"),
                max_user_fee_bps: 18,
                min_privacy_set_size: 512,
                pq_security_bits: 256,
                submitted_at_height: DEVNET_L2_HEIGHT + 1,
                expires_at_height: DEVNET_L2_HEIGHT + 20,
            })
            .expect("devnet intent alice");
        let intent_b = state
            .submit_sealed_intent(SubmitSealedSwapIntentRequest {
                account_commitment: deterministic_root("ACCOUNT", "bob"),
                intent_kind: SwapIntentKind::LimitSell,
                input_asset_root: deterministic_root("ASSET", "dusd"),
                output_asset_root: deterministic_root("ASSET", "dxmr"),
                sealed_intent_root: deterministic_root("SEALED-INTENT", "bob-swap"),
                amount_commitment_root: deterministic_root("AMOUNT", "bob-swap"),
                limit_price_root: deterministic_root("PRICE", "bob-swap"),
                nullifier_root: deterministic_root("NULLIFIER", "bob-swap"),
                refund_note_commitment: deterministic_root("REFUND", "bob-swap"),
                max_user_fee_bps: 16,
                min_privacy_set_size: 512,
                pq_security_bits: 256,
                submitted_at_height: DEVNET_L2_HEIGHT + 1,
                expires_at_height: DEVNET_L2_HEIGHT + 20,
            })
            .expect("devnet intent bob");
        let commitment_a = state
            .commit_solver_route(CommitSolverRouteRequest {
                solver_id: solver_a.clone(),
                intent_id: intent_a.clone(),
                route_commitment_root: deterministic_root("ROUTE-COMMIT", "alpha-alice"),
                quote_commitment_root: deterministic_root("QUOTE-COMMIT", "alpha-alice"),
                mev_fence_commitment_root: deterministic_root("MEV-COMMIT", "alpha-alice"),
                pq_signature_root: deterministic_root("SIG", "alpha-alice"),
                committed_at_height: DEVNET_L2_HEIGHT + 2,
                reveal_deadline_height: DEVNET_L2_HEIGHT + 6,
            })
            .expect("devnet commitment a");
        let commitment_b = state
            .commit_solver_route(CommitSolverRouteRequest {
                solver_id: solver_b.clone(),
                intent_id: intent_b.clone(),
                route_commitment_root: deterministic_root("ROUTE-COMMIT", "beta-bob"),
                quote_commitment_root: deterministic_root("QUOTE-COMMIT", "beta-bob"),
                mev_fence_commitment_root: deterministic_root("MEV-COMMIT", "beta-bob"),
                pq_signature_root: deterministic_root("SIG", "beta-bob"),
                committed_at_height: DEVNET_L2_HEIGHT + 2,
                reveal_deadline_height: DEVNET_L2_HEIGHT + 6,
            })
            .expect("devnet commitment b");
        let quote_a = state
            .reveal_route_quote(RevealRouteQuoteRequest {
                commitment_id: commitment_a.clone(),
                solver_id: solver_a,
                intent_id: intent_a.clone(),
                venues: vec![
                    SwapVenueKind::ConfidentialAmm,
                    SwapVenueKind::InternalNetting,
                ],
                route_leaf_root: deterministic_root("ROUTE", "alpha-alice"),
                expected_output_commitment: deterministic_root("OUTPUT", "alpha-alice"),
                solver_fee_bps: 12,
                price_impact_bps: 31,
                surplus_commitment_root: deterministic_root("SURPLUS", "alpha-alice"),
                rebate_commitment_root: deterministic_root("REBATE-COMMIT", "alpha-alice"),
                settlement_calldata_root: deterministic_root("CALLDATA", "alpha-alice"),
                quote_valid_until_height: DEVNET_L2_HEIGHT + 14,
                revealed_at_height: DEVNET_L2_HEIGHT + 4,
            })
            .expect("devnet quote a");
        let quote_b = state
            .reveal_route_quote(RevealRouteQuoteRequest {
                commitment_id: commitment_b,
                solver_id: solver_b,
                intent_id: intent_b.clone(),
                venues: vec![SwapVenueKind::Darkpool, SwapVenueKind::PrivateRfq],
                route_leaf_root: deterministic_root("ROUTE", "beta-bob"),
                expected_output_commitment: deterministic_root("OUTPUT", "beta-bob"),
                solver_fee_bps: 14,
                price_impact_bps: 28,
                surplus_commitment_root: deterministic_root("SURPLUS", "beta-bob"),
                rebate_commitment_root: deterministic_root("REBATE-COMMIT", "beta-bob"),
                settlement_calldata_root: deterministic_root("CALLDATA", "beta-bob"),
                quote_valid_until_height: DEVNET_L2_HEIGHT + 14,
                revealed_at_height: DEVNET_L2_HEIGHT + 4,
            })
            .expect("devnet quote b");
        state
            .record_privacy_fence(RecordPrivacyFenceRequest {
                intent_id: intent_a.clone(),
                solver_id: None,
                quote_id: Some(quote_a.clone()),
                fence_kind: FenceKind::Nullifier,
                verdict: FenceVerdict::Pass,
                fence_root: deterministic_root("FENCE", "alice-nullifier"),
                evidence_root: deterministic_root("FENCE-EVIDENCE", "alice-nullifier"),
                delay_ms: 180,
                privacy_set_size: 768,
                recorded_at_height: DEVNET_L2_HEIGHT + 5,
            })
            .expect("devnet fence a");
        state
            .record_privacy_fence(RecordPrivacyFenceRequest {
                intent_id: intent_b.clone(),
                solver_id: None,
                quote_id: Some(quote_b.clone()),
                fence_kind: FenceKind::BatchOrdering,
                verdict: FenceVerdict::Pass,
                fence_root: deterministic_root("FENCE", "bob-ordering"),
                evidence_root: deterministic_root("FENCE-EVIDENCE", "bob-ordering"),
                delay_ms: 220,
                privacy_set_size: 768,
                recorded_at_height: DEVNET_L2_HEIGHT + 5,
            })
            .expect("devnet fence b");
        let batch = state
            .build_clearing_batch(BuildClearingBatchRequest {
                batch_label: "devnet-dxmr-dusd-clearing-1".to_string(),
                intent_ids: vec![intent_a.clone(), intent_b.clone()],
                selected_quote_ids: vec![quote_a.clone(), quote_b],
                aggregate_intent_root: deterministic_vec_root(
                    "DEVNET-BATCH-INTENTS",
                    &[intent_a.clone(), intent_b.clone()],
                ),
                aggregate_quote_root: deterministic_root("DEVNET-BATCH-QUOTES", "round-1"),
                clearing_price_root: deterministic_root("CLEARING-PRICE", "round-1"),
                netted_flow_root: deterministic_root("NETTED-FLOW", "round-1"),
                mev_fence_root: deterministic_root("MEV-FENCE", "round-1"),
                batch_privacy_set_size: 1_024,
                selected_solver_fee_bps: 13,
                built_at_height: DEVNET_L2_HEIGHT + 6,
            })
            .expect("devnet batch");
        state
            .settle_clearing_batch(SettleClearingBatchRequest {
                batch_id: batch,
                settlement_tx_root: deterministic_root("SETTLEMENT-TX", "round-1"),
                settlement_proof_root: deterministic_root("SETTLEMENT-PROOF", "round-1"),
                output_note_root: deterministic_root("OUTPUT-NOTES", "round-1"),
                fee_note_root: deterministic_root("FEE-NOTES", "round-1"),
                runtime_state_root_after: deterministic_root("RUNTIME-AFTER", "round-1"),
                settled_at_height: DEVNET_L2_HEIGHT + 8,
                finalized_at_height: Some(DEVNET_L2_HEIGHT + 10),
            })
            .expect("devnet settle");
        state
    }

    pub fn advance_heights(&mut self, l2_height: u64, monero_height: u64) {
        self.current_l2_height = self.current_l2_height.max(l2_height);
        self.current_monero_height = self.current_monero_height.max(monero_height);
    }

    pub fn roots(&self) -> Roots {
        let public_without_roots = self.public_record_without_roots();
        let state_root = state_root_from_record(&public_without_roots);
        Roots {
            config_root: public_record_root(&self.config.public_record()),
            solver_root: map_root(
                "SOLVERS",
                self.solvers
                    .values()
                    .map(SolverRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            intent_root: map_root(
                "INTENTS",
                self.intents
                    .values()
                    .map(SealedSwapIntentRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            commitment_root: map_root(
                "COMMITMENTS",
                self.commitments
                    .values()
                    .map(SolverCommitmentRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            quote_root: map_root(
                "QUOTES",
                self.quotes
                    .values()
                    .map(RouteQuoteRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            fence_root: map_root(
                "FENCES",
                self.fences
                    .values()
                    .map(PrivacyFenceRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            batch_root: map_root(
                "BATCHES",
                self.batches
                    .values()
                    .map(ClearingBatchRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: map_root(
                "REBATES",
                self.rebates
                    .values()
                    .map(FeeRebateRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            slashing_root: map_root(
                "SLASHES",
                self.slashes
                    .values()
                    .map(SlashingEvidenceRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_record_root: map_root(
                "PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(PublicRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            state_root,
        }
    }

    pub fn public_record_without_roots(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_intent_swap_solver_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "rebate_budget_remaining_micro_units": self.rebate_budget_remaining_micro_units,
            "slashing_escrow_remaining_micro_units": self.slashing_escrow_remaining_micro_units,
            "runtime_root": self.runtime_root,
            "spent_nullifier_root": map_root(
                "SPENT-NULLIFIERS",
                self.spent_nullifier_roots.iter().map(|root| json!(root)).collect(),
            ),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_roots();
        if let Value::Object(values) = &mut record {
            values.insert("roots".to_string(), self.roots().public_record());
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_roots())
    }

    pub fn register_solver(&mut self, request: RegisterSolverRequest) -> Result<String> {
        require(self.solvers.len() < MAX_SOLVERS, "solver registry full")?;
        request.validate(&self.config)?;
        let solver_id = solver_id(&request, self.counters.next_solver_nonce);
        require(
            !self.solvers.contains_key(&solver_id),
            "solver already registered",
        )?;
        let record = SolverRecord {
            solver_id: solver_id.clone(),
            request,
            status: SolverStatus::Active,
            bond_locked_micro_units: self.config.solver_bond_micro_units,
            total_quotes: 0,
            total_selected: 0,
            total_settled: 0,
            total_slashed_micro_units: 0,
        };
        self.solvers.insert(solver_id.clone(), record.clone());
        self.counters.next_solver_nonce = self.counters.next_solver_nonce.saturating_add(1);
        self.counters.solvers_registered = self.counters.solvers_registered.saturating_add(1);
        self.publish_public_record(PublicRecordKind::Solver, &solver_id, record.public_record());
        Ok(solver_id)
    }

    pub fn submit_sealed_intent(
        &mut self,
        request: SubmitSealedSwapIntentRequest,
    ) -> Result<String> {
        require(self.intents.len() < MAX_INTENTS, "intent registry full")?;
        request.validate(&self.config)?;
        if self.config.reject_duplicate_nullifiers {
            require(
                !self.spent_nullifier_roots.contains(&request.nullifier_root),
                "duplicate nullifier root",
            )?;
        }
        let intent_id = intent_id(&request, self.counters.next_intent_nonce);
        let nullifier = request.nullifier_root.clone();
        let record = SealedSwapIntentRecord {
            intent_id: intent_id.clone(),
            request,
            status: IntentStatus::Admitted,
            selected_quote_id: None,
            batch_id: None,
            fence_ids: Vec::new(),
            rebate_ids: Vec::new(),
        };
        self.intents.insert(intent_id.clone(), record.clone());
        self.spent_nullifier_roots.insert(nullifier);
        self.counters.next_intent_nonce = self.counters.next_intent_nonce.saturating_add(1);
        self.counters.intents_admitted = self.counters.intents_admitted.saturating_add(1);
        self.publish_public_record(PublicRecordKind::Intent, &intent_id, record.public_record());
        Ok(intent_id)
    }

    pub fn commit_solver_route(&mut self, request: CommitSolverRouteRequest) -> Result<String> {
        require(
            self.commitments.len() < MAX_COMMITMENTS,
            "commitment registry full",
        )?;
        request.validate(&self.config)?;
        let solver = self
            .solvers
            .get(&request.solver_id)
            .ok_or_else(|| "unknown solver".to_string())?;
        require(solver.status.can_quote(), "solver cannot quote")?;
        let intent = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "unknown intent".to_string())?;
        require(intent.status.batchable(), "intent is not batchable")?;
        require(
            request.committed_at_height <= intent.request.expires_at_height,
            "commitment after intent expiry",
        )?;
        let score = commitment_score(&request);
        let commitment_id = commitment_id(&request, score, self.counters.next_commitment_nonce);
        let record = SolverCommitmentRecord {
            commitment_id: commitment_id.clone(),
            request: request.clone(),
            status: CommitmentStatus::Committed,
            quote_id: None,
            score,
        };
        self.commitments
            .insert(commitment_id.clone(), record.clone());
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::SolverCommitted;
        }
        self.counters.next_commitment_nonce = self.counters.next_commitment_nonce.saturating_add(1);
        self.counters.commitments_recorded = self.counters.commitments_recorded.saturating_add(1);
        self.publish_public_record(
            PublicRecordKind::Commitment,
            &commitment_id,
            record.public_record(),
        );
        self.refresh_intent_record(&request.intent_id);
        Ok(commitment_id)
    }

    pub fn reveal_route_quote(&mut self, request: RevealRouteQuoteRequest) -> Result<String> {
        require(self.quotes.len() < MAX_QUOTES, "quote registry full")?;
        request.validate(&self.config)?;
        let commitment = self
            .commitments
            .get(&request.commitment_id)
            .ok_or_else(|| "unknown commitment".to_string())?
            .clone();
        require(
            commitment.request.solver_id == request.solver_id,
            "quote solver does not match commitment",
        )?;
        require(
            commitment.request.intent_id == request.intent_id,
            "quote intent does not match commitment",
        )?;
        require(
            request.revealed_at_height <= commitment.request.reveal_deadline_height,
            "quote revealed after deadline",
        )?;
        let solver = self
            .solvers
            .get(&request.solver_id)
            .ok_or_else(|| "unknown solver".to_string())?;
        require(
            venues_allowed(&solver.request.allowed_venue_kinds, &request.venues),
            "quote route contains venue not allowed for solver",
        )?;
        require(
            self.quotes_for_intent(&request.intent_id) < self.config.max_quotes_per_intent,
            "too many quotes for intent",
        )?;
        let score = quote_score(&request);
        let quote_id = quote_id(&request, score, self.counters.next_quote_nonce);
        let record = RouteQuoteRecord {
            quote_id: quote_id.clone(),
            request: request.clone(),
            status: QuoteStatus::Eligible,
            score,
            selected_at_height: None,
        };
        self.quotes.insert(quote_id.clone(), record.clone());
        if let Some(commitment) = self.commitments.get_mut(&request.commitment_id) {
            commitment.status = CommitmentStatus::Revealed;
            commitment.quote_id = Some(quote_id.clone());
        }
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::QuoteRevealed;
        }
        if let Some(solver) = self.solvers.get_mut(&request.solver_id) {
            solver.total_quotes = solver.total_quotes.saturating_add(1);
        }
        self.counters.next_quote_nonce = self.counters.next_quote_nonce.saturating_add(1);
        self.counters.quotes_published = self.counters.quotes_published.saturating_add(1);
        self.publish_public_record(PublicRecordKind::Quote, &quote_id, record.public_record());
        self.refresh_commitment_record(&request.commitment_id);
        self.refresh_intent_record(&request.intent_id);
        self.refresh_solver_record(&request.solver_id);
        Ok(quote_id)
    }

    pub fn record_privacy_fence(&mut self, request: RecordPrivacyFenceRequest) -> Result<String> {
        require(
            self.fences.len() < MAX_FENCES,
            "privacy fence registry full",
        )?;
        request.validate(&self.config)?;
        require(
            self.intents.contains_key(&request.intent_id),
            "unknown intent for fence",
        )?;
        if let Some(solver_id) = &request.solver_id {
            require(
                self.solvers.contains_key(solver_id),
                "unknown solver for fence",
            )?;
        }
        if let Some(quote_id) = &request.quote_id {
            require(
                self.quotes.contains_key(quote_id),
                "unknown quote for fence",
            )?;
        }
        let fence_id = fence_id(&request, self.counters.next_fence_nonce);
        let record = PrivacyFenceRecord {
            fence_id: fence_id.clone(),
            request: request.clone(),
        };
        self.fences.insert(fence_id.clone(), record.clone());
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.fence_ids.push(fence_id.clone());
            intent.status = match request.verdict {
                FenceVerdict::Pass | FenceVerdict::Delay => IntentStatus::PrivacyFenced,
                FenceVerdict::Quarantine | FenceVerdict::Reject => IntentStatus::Rejected,
            };
        }
        self.counters.next_fence_nonce = self.counters.next_fence_nonce.saturating_add(1);
        self.counters.fences_recorded = self.counters.fences_recorded.saturating_add(1);
        self.publish_public_record(PublicRecordKind::Fence, &fence_id, record.public_record());
        self.refresh_intent_record(&request.intent_id);
        Ok(fence_id)
    }

    pub fn build_clearing_batch(&mut self, request: BuildClearingBatchRequest) -> Result<String> {
        require(self.batches.len() < MAX_BATCHES, "batch registry full")?;
        request.validate(&self.config)?;
        require(
            unique_strings(&request.intent_ids),
            "batch contains duplicate intents",
        )?;
        require(
            unique_strings(&request.selected_quote_ids),
            "batch contains duplicate quotes",
        )?;
        for (intent_id, quote_id) in request.intent_ids.iter().zip(&request.selected_quote_ids) {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown intent {intent_id}"))?;
            require(intent.status.batchable(), "intent is not batchable")?;
            let quote = self
                .quotes
                .get(quote_id)
                .ok_or_else(|| format!("unknown quote {quote_id}"))?;
            require(
                quote.request.intent_id == *intent_id,
                "selected quote does not target paired intent",
            )?;
            require(
                matches!(quote.status, QuoteStatus::Eligible | QuoteStatus::Published),
                "selected quote is not eligible",
            )?;
            require(
                request.built_at_height <= quote.request.quote_valid_until_height,
                "selected quote expired before batch build",
            )?;
        }
        let state_root_before = self.state_root();
        let batch_id = batch_id(&request, &state_root_before, self.counters.next_batch_nonce);
        let record = ClearingBatchRecord {
            batch_id: batch_id.clone(),
            request: request.clone(),
            status: ClearingStatus::SettlementReady,
            state_root_before,
            state_root_after: None,
            settlement_deadline_height: request
                .built_at_height
                .saturating_add(self.config.clearing_ttl_blocks),
            settled_at_height: None,
        };
        self.batches.insert(batch_id.clone(), record.clone());
        for (intent_id, quote_id) in request.intent_ids.iter().zip(&request.selected_quote_ids) {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Batched;
                intent.selected_quote_id = Some(quote_id.clone());
                intent.batch_id = Some(batch_id.clone());
            }
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Selected;
                quote.selected_at_height = Some(request.built_at_height);
                if let Some(solver) = self.solvers.get_mut(&quote.request.solver_id) {
                    solver.total_selected = solver.total_selected.saturating_add(1);
                }
            }
        }
        self.counters.next_batch_nonce = self.counters.next_batch_nonce.saturating_add(1);
        self.counters.batches_cleared = self.counters.batches_cleared.saturating_add(1);
        self.publish_public_record(
            PublicRecordKind::ClearingBatch,
            &batch_id,
            record.public_record(),
        );
        self.refresh_intent_records(&request.intent_ids);
        self.refresh_quote_records(&request.selected_quote_ids);
        Ok(batch_id)
    }

    pub fn settle_clearing_batch(&mut self, request: SettleClearingBatchRequest) -> Result<String> {
        request.validate()?;
        let batch = self
            .batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| "unknown clearing batch".to_string())?;
        require(
            batch.status.can_settle(),
            "batch cannot settle in current status",
        )?;
        require(
            request.settled_at_height <= batch.settlement_deadline_height,
            "settlement after batch deadline",
        )?;
        let state_root_after = request.runtime_state_root_after.clone();
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = ClearingStatus::Settled;
            batch.state_root_after = Some(state_root_after.clone());
            batch.settled_at_height = Some(request.settled_at_height);
        }
        for (intent_id, quote_id) in batch
            .request
            .intent_ids
            .iter()
            .zip(&batch.request.selected_quote_ids)
        {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
            }
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Settled;
                if let Some(solver) = self.solvers.get_mut(&quote.request.solver_id) {
                    solver.total_settled = solver.total_settled.saturating_add(1);
                }
                if let Some(commitment) = self.commitments.get_mut(&quote.request.commitment_id) {
                    commitment.status = CommitmentStatus::Settled;
                }
            }
        }
        self.runtime_root = state_root_after;
        self.current_l2_height = self.current_l2_height.max(request.settled_at_height);
        let settlement_root = settlement_receipt_root(&request, &batch.state_root_before);
        self.publish_public_record(
            PublicRecordKind::StateCheckpoint,
            &request.batch_id,
            json!({
                "kind": "private_l2_pq_confidential_intent_swap_settlement",
                "batch_id": request.batch_id,
                "settlement_root": settlement_root,
                "settlement_tx_root": request.settlement_tx_root,
                "settlement_proof_root": request.settlement_proof_root,
                "output_note_root": request.output_note_root,
                "fee_note_root": request.fee_note_root,
                "settled_at_height": request.settled_at_height,
                "finalized_at_height": request.finalized_at_height,
            }),
        );
        self.refresh_batch_record(&batch.batch_id);
        self.refresh_intent_records(&batch.request.intent_ids);
        self.refresh_quote_records(&batch.request.selected_quote_ids);
        Ok(settlement_root)
    }

    pub fn issue_fee_rebate(&mut self, request: IssueFeeRebateRequest) -> Result<String> {
        require(self.rebates.len() < MAX_REBATES, "rebate registry full")?;
        request.validate()?;
        require(
            self.intents.contains_key(&request.intent_id),
            "unknown intent for rebate",
        )?;
        require(
            self.rebate_budget_remaining_micro_units >= request.amount_micro_units,
            "insufficient rebate budget",
        )?;
        let rebate_id = rebate_id(&request, self.counters.next_rebate_nonce);
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            request: request.clone(),
        };
        self.rebates.insert(rebate_id.clone(), record.clone());
        self.rebate_budget_remaining_micro_units = self
            .rebate_budget_remaining_micro_units
            .saturating_sub(request.amount_micro_units);
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::RebateIssued;
            intent.rebate_ids.push(rebate_id.clone());
        }
        self.counters.next_rebate_nonce = self.counters.next_rebate_nonce.saturating_add(1);
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.publish_public_record(PublicRecordKind::Rebate, &rebate_id, record.public_record());
        self.refresh_intent_record(&request.intent_id);
        Ok(rebate_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        request: SubmitSlashingEvidenceRequest,
    ) -> Result<String> {
        require(self.slashes.len() < MAX_SLASHES, "slashing registry full")?;
        request.validate()?;
        require(
            self.solvers.contains_key(&request.solver_id),
            "unknown solver for slash",
        )?;
        require(
            self.slashing_escrow_remaining_micro_units >= request.slash_amount_micro_units,
            "insufficient slashing escrow",
        )?;
        let state_root_before = self.state_root();
        let slash_id = slash_id(&request, &state_root_before, self.counters.next_slash_nonce);
        if let Some(solver) = self.solvers.get_mut(&request.solver_id) {
            solver.status = SolverStatus::Slashed;
            solver.total_slashed_micro_units = solver
                .total_slashed_micro_units
                .saturating_add(request.slash_amount_micro_units);
        }
        if let Some(commitment_id) = &request.commitment_id {
            if let Some(commitment) = self.commitments.get_mut(commitment_id) {
                commitment.status = CommitmentStatus::Slashed;
            }
        }
        if let Some(quote_id) = &request.quote_id {
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Disputed;
            }
        }
        if let Some(batch_id) = &request.batch_id {
            if let Some(batch) = self.batches.get_mut(batch_id) {
                batch.status = ClearingStatus::Disputed;
            }
        }
        self.slashing_escrow_remaining_micro_units = self
            .slashing_escrow_remaining_micro_units
            .saturating_sub(request.slash_amount_micro_units);
        let state_root_after = self.state_root();
        let record = SlashingEvidenceRecord {
            slash_id: slash_id.clone(),
            request: request.clone(),
            state_root_before,
            state_root_after,
        };
        self.slashes.insert(slash_id.clone(), record.clone());
        self.counters.next_slash_nonce = self.counters.next_slash_nonce.saturating_add(1);
        self.counters.slashes_recorded = self.counters.slashes_recorded.saturating_add(1);
        self.publish_public_record(
            PublicRecordKind::SlashingEvidence,
            &slash_id,
            record.public_record(),
        );
        self.refresh_solver_record(&request.solver_id);
        Ok(slash_id)
    }

    pub fn expire_old_records(&mut self, at_height: u64) {
        self.current_l2_height = self.current_l2_height.max(at_height);
        for intent in self.intents.values_mut() {
            if intent.status.live() && intent.request.expires_at_height < at_height {
                intent.status = IntentStatus::Expired;
            }
        }
        for commitment in self.commitments.values_mut() {
            if commitment.status == CommitmentStatus::Committed
                && commitment.request.reveal_deadline_height < at_height
            {
                commitment.status = CommitmentStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if matches!(quote.status, QuoteStatus::Eligible | QuoteStatus::Published)
                && quote.request.quote_valid_until_height < at_height
            {
                quote.status = QuoteStatus::Expired;
            }
        }
        for batch in self.batches.values_mut() {
            if matches!(
                batch.status,
                ClearingStatus::Built
                    | ClearingStatus::PrivacyLocked
                    | ClearingStatus::SolverSelected
                    | ClearingStatus::SettlementReady
            ) && batch.settlement_deadline_height < at_height
            {
                batch.status = ClearingStatus::Expired;
            }
        }
    }

    fn quotes_for_intent(&self, intent_id: &str) -> usize {
        self.quotes
            .values()
            .filter(|quote| quote.request.intent_id == intent_id)
            .count()
    }

    fn publish_public_record(
        &mut self,
        record_kind: PublicRecordKind,
        subject_id: &str,
        payload: Value,
    ) {
        if self.public_records.len() >= MAX_PUBLIC_RECORDS {
            return;
        }
        let payload_root = public_record_root(&payload);
        let state_root = self.state_root();
        let record_id = public_record_id(record_kind, subject_id, &payload_root, &state_root);
        self.public_records.insert(
            record_id.clone(),
            PublicRecord {
                record_id,
                record_kind,
                subject_id: subject_id.to_string(),
                payload_root,
                state_root,
                height: self.current_l2_height,
            },
        );
    }

    fn refresh_solver_record(&mut self, solver_id: &str) {
        if let Some(payload) = self.solvers.get(solver_id).map(SolverRecord::public_record) {
            self.publish_public_record(PublicRecordKind::Solver, solver_id, payload);
        }
    }

    fn refresh_intent_record(&mut self, intent_id: &str) {
        if let Some(payload) = self
            .intents
            .get(intent_id)
            .map(SealedSwapIntentRecord::public_record)
        {
            self.publish_public_record(PublicRecordKind::Intent, intent_id, payload);
        }
    }

    fn refresh_intent_records(&mut self, intent_ids: &[String]) {
        for intent_id in intent_ids {
            self.refresh_intent_record(intent_id);
        }
    }

    fn refresh_commitment_record(&mut self, commitment_id: &str) {
        if let Some(payload) = self
            .commitments
            .get(commitment_id)
            .map(SolverCommitmentRecord::public_record)
        {
            self.publish_public_record(PublicRecordKind::Commitment, commitment_id, payload);
        }
    }

    fn refresh_quote_records(&mut self, quote_ids: &[String]) {
        for quote_id in quote_ids {
            if let Some(payload) = self
                .quotes
                .get(quote_id)
                .map(RouteQuoteRecord::public_record)
            {
                self.publish_public_record(PublicRecordKind::Quote, quote_id, payload);
            }
        }
    }

    fn refresh_batch_record(&mut self, batch_id: &str) {
        if let Some(payload) = self
            .batches
            .get(batch_id)
            .map(ClearingBatchRecord::public_record)
        {
            self.publish_public_record(PublicRecordKind::ClearingBatch, batch_id, payload);
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-SOLVER-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    payload_root("PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("STATE", record)
}

pub fn map_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-SOLVER-{domain}"),
        &leaves,
    )
}

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-SOLVER-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn deterministic_vec_root(domain: &str, values: &[String]) -> String {
    map_root(domain, values.iter().map(|value| json!(value)).collect())
}

pub fn solver_id(request: &RegisterSolverRequest, nonce: u64) -> String {
    let venue_root = map_root(
        "SOLVER-ID-VENUES",
        request
            .allowed_venue_kinds
            .iter()
            .map(|venue| json!(venue.as_str()))
            .collect(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-SOLVER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.pq_public_key_root),
            HashPart::Str(&request.bond_note_commitment),
            HashPart::Str(&venue_root),
            HashPart::Int(request.solver_fee_bps as i128),
        ],
        32,
    )
}

pub fn intent_id(request: &SubmitSealedSwapIntentRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.intent_kind.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.input_asset_root),
            HashPart::Str(&request.output_asset_root),
            HashPart::Str(&request.sealed_intent_root),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn commitment_id(request: &CommitSolverRouteRequest, score: u128, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&request.intent_id),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Str(&request.quote_commitment_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn quote_id(request: &RevealRouteQuoteRequest, score: u128, nonce: u64) -> String {
    let venue_root = map_root(
        "QUOTE-ID-VENUES",
        request
            .venues
            .iter()
            .map(|venue| json!(venue.as_str()))
            .collect(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.commitment_id),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&request.intent_id),
            HashPart::Str(&venue_root),
            HashPart::Str(&request.route_leaf_root),
            HashPart::Str(&request.expected_output_commitment),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn fence_id(request: &RecordPrivacyFenceRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.intent_id),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.fence_root),
            HashPart::Str(&request.evidence_root),
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_label),
            HashPart::Str(&request.aggregate_intent_root),
            HashPart::Str(&request.aggregate_quote_root),
            HashPart::Str(&request.clearing_price_root),
            HashPart::Str(&request.netted_flow_root),
            HashPart::Str(&request.mev_fence_root),
            HashPart::Str(state_root_before),
            HashPart::Int(request.built_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_root(
    request: &SettleClearingBatchRequest,
    state_root_before: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-SETTLEMENT-RECEIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.output_note_root),
            HashPart::Str(&request.fee_note_root),
            HashPart::Str(state_root_before),
            HashPart::Str(&request.runtime_state_root_after),
            HashPart::Int(request.settled_at_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(request: &IssueFeeRebateRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.intent_id),
            HashPart::Str(request.rebate_reason.as_str()),
            HashPart::Str(&request.recipient_commitment),
            HashPart::Str(&request.rebate_note_commitment),
            HashPart::Int(request.amount_micro_units as i128),
        ],
        32,
    )
}

pub fn slash_id(
    request: &SubmitSlashingEvidenceRequest,
    state_root_before: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-SLASH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_id),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(state_root_before),
            HashPart::Int(request.slash_amount_micro_units as i128),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    state_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-INTENT-SWAP-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Str(state_root),
        ],
        32,
    )
}

pub fn roots_only_payload(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload: &Value,
) -> Value {
    json!({
        "kind": "private_l2_pq_confidential_intent_swap_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind.as_str(),
        "subject_id": subject_id,
        "payload_root": public_record_root(payload),
    })
}

fn commitment_score(request: &CommitSolverRouteRequest) -> u128 {
    let reveal_span = request
        .reveal_deadline_height
        .saturating_sub(request.committed_at_height) as u128;
    1_000_000_000_u128.saturating_sub(reveal_span.saturating_mul(1_000))
}

fn quote_score(request: &RevealRouteQuoteRequest) -> u128 {
    let fee_penalty = request.solver_fee_bps as u128 * 1_000_000;
    let impact_penalty = request.price_impact_bps as u128 * 500_000;
    let venue_bonus = request.venues.len() as u128 * 25_000;
    10_000_000_000_u128
        .saturating_add(venue_bonus)
        .saturating_sub(fee_penalty)
        .saturating_sub(impact_penalty)
}

fn venues_allowed(allowed: &[SwapVenueKind], requested: &[SwapVenueKind]) -> bool {
    let allowed = allowed.iter().collect::<BTreeSet<_>>();
    requested.iter().all(|venue| allowed.contains(venue))
}

fn unique_strings(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(message.to_string());
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} cannot exceed {MAX_BPS}"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}
