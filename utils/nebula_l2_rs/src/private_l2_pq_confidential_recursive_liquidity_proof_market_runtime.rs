use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_RECURSIVE_LIQUIDITY_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-recursive-liquidity-proof-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_RECURSIVE_LIQUIDITY_PROOF_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_HEIGHT: u64 = 2_884_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-recursive-liquidity-proof-market-v1";
pub const WITNESS_SCHEME: &str = "sealed-recursive-liquidity-witness-root-v1";
pub const DEPTH_COMMITMENT_SCHEME: &str = "sealed-liquidity-depth-commitment-root-v1";
pub const PROVER_ATTESTATION_SCHEME: &str = "pq-recursive-liquidity-prover-attestation-root-v1";
pub const QUOTE_AUCTION_SCHEME: &str = "sealed-proof-quote-auction-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-recursive-liquidity-proof-rebate-root-v1";
pub const QUARANTINE_SCHEME: &str = "stale-recursive-proof-quarantine-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "privacy-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-recursive-liquidity-proof-market-record-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_RECURSION_DEPTH: u64 = 2;
pub const DEFAULT_MAX_RECURSION_DEPTH: u64 = 64;
pub const DEFAULT_MIN_LIQUIDITY_COVER_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_LIQUIDITY_COVER_BPS: u64 = 12_500;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_WITNESS_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_DEPTH_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_WITNESSES: usize = 1_048_576;
pub const DEFAULT_MAX_DEPTH_COMMITMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_AUCTIONS: usize = 524_288;
pub const DEFAULT_MAX_QUOTES: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_QUARANTINES: usize = 524_288;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityLane {
    LowFee,
    FastExit,
    DefiRebalance,
    ReserveAudit,
    BridgeBackstop,
    Emergency,
}

impl LiquidityLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::FastExit => "fast_exit",
            Self::DefiRebalance => "defi_rebalance",
            Self::ReserveAudit => "reserve_audit",
            Self::BridgeBackstop => "bridge_backstop",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::ReserveAudit => config.target_rebate_bps,
            Self::DefiRebalance => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::FastExit | Self::BridgeBackstop => config.max_user_fee_bps,
            Self::Emergency => config.max_user_fee_bps.saturating_mul(3) / 2,
        }
        .min(MAX_BPS)
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::FastExit => 940,
            Self::BridgeBackstop => 900,
            Self::LowFee => 820,
            Self::DefiRebalance => 760,
            Self::ReserveAudit => 680,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessKind {
    ReserveDepth,
    ExitQueue,
    RebalancePath,
    AmmInventory,
    SponsorPool,
    FeeNetting,
    WatchtowerSample,
    EmergencyBackstop,
}

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveDepth => "reserve_depth",
            Self::ExitQueue => "exit_queue",
            Self::RebalancePath => "rebalance_path",
            Self::AmmInventory => "amm_inventory",
            Self::SponsorPool => "sponsor_pool",
            Self::FeeNetting => "fee_netting",
            Self::WatchtowerSample => "watchtower_sample",
            Self::EmergencyBackstop => "emergency_backstop",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::EmergencyBackstop => 1_000,
            Self::RebalancePath => 930,
            Self::ReserveDepth => 880,
            Self::AmmInventory => 820,
            Self::ExitQueue => 760,
            Self::SponsorPool => 700,
            Self::FeeNetting => 640,
            Self::WatchtowerSample => 580,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    Submitted,
    DepthCommitted,
    Quoted,
    Proving,
    Proven,
    Settled,
    Stale,
    Quarantined,
}

impl WitnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::DepthCommitted => "depth_committed",
            Self::Quoted => "quoted",
            Self::Proving => "proving",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_quote(self) -> bool {
        matches!(self, Self::Submitted | Self::DepthCommitted | Self::Quoted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepthStatus {
    Sealed,
    OpenedForProof,
    Attested,
    Settled,
    Expired,
    Disputed,
}

impl DepthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::OpenedForProof => "opened_for_proof",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    Superseded,
    Rejected,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Quorum => "quorum",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Clearing,
    Awarded,
    Proving,
    Settled,
    Expired,
    Disputed,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Clearing => "clearing",
            Self::Awarded => "awarded",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Shortlisted,
    Awarded,
    Replaced,
    Expired,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Shortlisted => "shortlisted",
            Self::Awarded => "awarded",
            Self::Replaced => "replaced",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Settled,
    Expired,
    ClawedBack,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Earned => "earned",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::ClawedBack => "clawed_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleDepth,
    ExpiredQuote,
    InvalidPqAttestation,
    LiquidityCoverageDrift,
    RedactionBudgetExceeded,
    DuplicateNullifier,
    WatchtowerChallenge,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleDepth => "stale_depth",
            Self::ExpiredQuote => "expired_quote",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::LiquidityCoverageDrift => "liquidity_coverage_drift",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::WatchtowerChallenge => "watchtower_challenge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub witness_scheme: String,
    pub depth_commitment_scheme: String,
    pub prover_attestation_scheme: String,
    pub quote_auction_scheme: String,
    pub rebate_scheme: String,
    pub quarantine_scheme: String,
    pub redaction_budget_scheme: String,
    pub public_record_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_recursion_depth: u64,
    pub max_recursion_depth: u64,
    pub min_liquidity_cover_bps: u64,
    pub target_liquidity_cover_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub witness_ttl_blocks: u64,
    pub depth_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_witnesses: usize,
    pub max_depth_commitments: usize,
    pub max_attestations: usize,
    pub max_auctions: usize,
    pub max_quotes: usize,
    pub max_rebates: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_public_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            witness_scheme: WITNESS_SCHEME.to_string(),
            depth_commitment_scheme: DEPTH_COMMITMENT_SCHEME.to_string(),
            prover_attestation_scheme: PROVER_ATTESTATION_SCHEME.to_string(),
            quote_auction_scheme: QUOTE_AUCTION_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            quarantine_scheme: QUARANTINE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_recursion_depth: DEFAULT_MIN_RECURSION_DEPTH,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
            min_liquidity_cover_bps: DEFAULT_MIN_LIQUIDITY_COVER_BPS,
            target_liquidity_cover_bps: DEFAULT_TARGET_LIQUIDITY_COVER_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            witness_ttl_blocks: DEFAULT_WITNESS_TTL_BLOCKS,
            depth_ttl_blocks: DEFAULT_DEPTH_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_witnesses: DEFAULT_MAX_WITNESSES,
            max_depth_commitments: DEFAULT_MAX_DEPTH_COMMITMENTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_quotes: DEFAULT_MAX_QUOTES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "asset_id": self.asset_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "witness_scheme": self.witness_scheme,
            "depth_commitment_scheme": self.depth_commitment_scheme,
            "prover_attestation_scheme": self.prover_attestation_scheme,
            "quote_auction_scheme": self.quote_auction_scheme,
            "rebate_scheme": self.rebate_scheme,
            "quarantine_scheme": self.quarantine_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "public_record_scheme": self.public_record_scheme,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_recursion_depth": self.min_recursion_depth,
            "max_recursion_depth": self.max_recursion_depth,
            "min_liquidity_cover_bps": self.min_liquidity_cover_bps,
            "target_liquidity_cover_bps": self.target_liquidity_cover_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "witness_ttl_blocks": self.witness_ttl_blocks,
            "depth_ttl_blocks": self.depth_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_witnesses": self.max_witnesses,
            "max_depth_commitments": self.max_depth_commitments,
            "max_attestations": self.max_attestations,
            "max_auctions": self.max_auctions,
            "max_quotes": self.max_quotes,
            "max_rebates": self.max_rebates,
            "max_quarantines": self.max_quarantines,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_public_events": self.max_public_events,
        })
    }

    pub fn validate(
        &self,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.l2_network, "l2 network")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_empty(&self.asset_id, "asset id")?;
        ensure_non_empty(&self.hash_suite, "hash suite")?;
        ensure_non_empty(&self.pq_auth_suite, "pq auth suite")?;
        ensure_bps(self.min_liquidity_cover_bps, "minimum liquidity cover bps")?;
        ensure_bps(
            self.target_liquidity_cover_bps,
            "target liquidity cover bps",
        )?;
        ensure_bps(self.max_user_fee_bps, "max user fee bps")?;
        ensure_bps(self.target_rebate_bps, "target rebate bps")?;
        ensure_bps(self.sponsor_cover_bps, "sponsor cover bps")?;
        if self.min_pq_security_bits < 192 {
            return Err("minimum pq security must be at least 192 bits".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("minimum privacy set size must be positive".to_string());
        }
        if self.min_recursion_depth == 0 || self.min_recursion_depth > self.max_recursion_depth {
            return Err("invalid recursion depth bounds".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub witnesses: u64,
    pub depth_commitments: u64,
    pub attestations: u64,
    pub auctions: u64,
    pub quotes: u64,
    pub rebates: u64,
    pub quarantines: u64,
    pub redaction_budgets: u64,
    pub public_events: u64,
    pub settled_proofs: u64,
    pub stale_proofs: u64,
    pub total_fee_piconero: u128,
    pub total_rebate_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "witnesses": self.witnesses,
            "depth_commitments": self.depth_commitments,
            "attestations": self.attestations,
            "auctions": self.auctions,
            "quotes": self.quotes,
            "rebates": self.rebates,
            "quarantines": self.quarantines,
            "redaction_budgets": self.redaction_budgets,
            "public_events": self.public_events,
            "settled_proofs": self.settled_proofs,
            "stale_proofs": self.stale_proofs,
            "total_fee_piconero": self.total_fee_piconero.to_string(),
            "total_rebate_piconero": self.total_rebate_piconero.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub witness_root: String,
    pub depth_commitment_root: String,
    pub attestation_root: String,
    pub auction_root: String,
    pub quote_root: String,
    pub rebate_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub public_event_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "witness_root": self.witness_root,
            "depth_commitment_root": self.depth_commitment_root,
            "attestation_root": self.attestation_root,
            "auction_root": self.auction_root,
            "quote_root": self.quote_root,
            "rebate_root": self.rebate_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_event_root": self.public_event_root,
            "nullifier_root": self.nullifier_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn root(&self) -> String {
        module_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveLiquidityWitness {
    pub witness_id: String,
    pub lane: LiquidityLane,
    pub kind: WitnessKind,
    pub status: WitnessStatus,
    pub submitter_commitment: String,
    pub sealed_witness_root: String,
    pub prior_recursive_root: String,
    pub liquidity_bucket_commitment: String,
    pub redacted_context_root: String,
    pub privacy_nullifier: String,
    pub recursion_depth: u64,
    pub min_liquidity_cover_bps: u64,
    pub privacy_set_size: u64,
    pub fee_cap_piconero: u128,
    pub created_height: u64,
    pub expires_height: u64,
    pub metadata_root: String,
}

impl RecursiveLiquidityWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: LiquidityLane,
        kind: WitnessKind,
        submitter_commitment: impl Into<String>,
        prior_recursive_root: impl Into<String>,
        liquidity_bucket_commitment: impl Into<String>,
        redacted_context_root: impl Into<String>,
        privacy_nullifier: impl Into<String>,
        recursion_depth: u64,
        min_liquidity_cover_bps: u64,
        privacy_set_size: u64,
        fee_cap_piconero: u128,
        created_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let submitter_commitment = submitter_commitment.into();
        let prior_recursive_root = prior_recursive_root.into();
        let liquidity_bucket_commitment = liquidity_bucket_commitment.into();
        let redacted_context_root = redacted_context_root.into();
        let privacy_nullifier = privacy_nullifier.into();
        ensure_non_empty(&submitter_commitment, "witness submitter commitment")?;
        ensure_non_empty(&prior_recursive_root, "witness prior recursive root")?;
        ensure_non_empty(
            &liquidity_bucket_commitment,
            "witness liquidity bucket commitment",
        )?;
        ensure_non_empty(&redacted_context_root, "witness redacted context root")?;
        ensure_non_empty(&privacy_nullifier, "witness privacy nullifier")?;
        ensure_depth(config, recursion_depth)?;
        ensure_bps(
            min_liquidity_cover_bps,
            "witness minimum liquidity cover bps",
        )?;
        if privacy_set_size < config.min_privacy_set_size {
            return Err("witness privacy set below configured minimum".to_string());
        }
        let metadata_root = module_hash(
            "WITNESS-METADATA",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(kind.as_str()),
                HashPart::U64(recursion_depth),
                HashPart::U64(created_height),
            ],
        );
        let sealed_witness_root = module_hash(
            "SEALED-WITNESS",
            &[
                HashPart::Str(&config.witness_scheme),
                HashPart::Str(&submitter_commitment),
                HashPart::Str(&prior_recursive_root),
                HashPart::Str(&liquidity_bucket_commitment),
                HashPart::Str(&redacted_context_root),
                HashPart::Str(&privacy_nullifier),
                HashPart::U64(recursion_depth),
                HashPart::Str(&metadata_root),
            ],
        );
        let witness_id = module_hash(
            "WITNESS-ID",
            &[
                HashPart::Str(&sealed_witness_root),
                HashPart::Str(&privacy_nullifier),
                HashPart::U64(created_height),
            ],
        );
        Ok(Self {
            witness_id,
            lane,
            kind,
            status: WitnessStatus::Submitted,
            submitter_commitment,
            sealed_witness_root,
            prior_recursive_root,
            liquidity_bucket_commitment,
            redacted_context_root,
            privacy_nullifier,
            recursion_depth,
            min_liquidity_cover_bps,
            privacy_set_size,
            fee_cap_piconero,
            created_height,
            expires_height: created_height.saturating_add(config.witness_ttl_blocks),
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_liquidity_witness",
            "witness_id": self.witness_id,
            "lane": self.lane.as_str(),
            "witness_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "sealed_witness_root": self.sealed_witness_root,
            "prior_recursive_root": self.prior_recursive_root,
            "liquidity_bucket_commitment": self.liquidity_bucket_commitment,
            "redacted_context_root": self.redacted_context_root,
            "recursion_depth": self.recursion_depth,
            "min_liquidity_cover_bps": self.min_liquidity_cover_bps,
            "privacy_set_size": self.privacy_set_size,
            "fee_cap_piconero": self.fee_cap_piconero.to_string(),
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        module_hash("WITNESS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedDepthCommitment {
    pub commitment_id: String,
    pub witness_id: String,
    pub status: DepthStatus,
    pub sealed_depth_root: String,
    pub cover_band_root: String,
    pub depth_range_commitment: String,
    pub recursive_parent_root: String,
    pub blinding_root: String,
    pub observed_height: u64,
    pub expires_height: u64,
    pub min_depth: u64,
    pub max_depth: u64,
}

impl SealedDepthCommitment {
    pub fn new(
        witness: &RecursiveLiquidityWitness,
        depth_range_commitment: impl Into<String>,
        recursive_parent_root: impl Into<String>,
        blinding_root: impl Into<String>,
        observed_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let depth_range_commitment = depth_range_commitment.into();
        let recursive_parent_root = recursive_parent_root.into();
        let blinding_root = blinding_root.into();
        ensure_non_empty(&depth_range_commitment, "depth range commitment")?;
        ensure_non_empty(&recursive_parent_root, "depth recursive parent root")?;
        ensure_non_empty(&blinding_root, "depth blinding root")?;
        let min_depth = witness.recursion_depth;
        let max_depth = witness
            .recursion_depth
            .saturating_add(config.max_recursion_depth);
        let cover_band_root = module_hash(
            "DEPTH-COVER-BAND",
            &[
                HashPart::Str(&witness.witness_id),
                HashPart::U64(min_depth),
                HashPart::U64(max_depth),
                HashPart::U64(witness.min_liquidity_cover_bps),
            ],
        );
        let sealed_depth_root = module_hash(
            "SEALED-DEPTH",
            &[
                HashPart::Str(&config.depth_commitment_scheme),
                HashPart::Str(&witness.sealed_witness_root),
                HashPart::Str(&depth_range_commitment),
                HashPart::Str(&recursive_parent_root),
                HashPart::Str(&blinding_root),
                HashPart::Str(&cover_band_root),
            ],
        );
        let commitment_id = module_hash(
            "DEPTH-ID",
            &[
                HashPart::Str(&witness.witness_id),
                HashPart::Str(&sealed_depth_root),
                HashPart::U64(observed_height),
            ],
        );
        Ok(Self {
            commitment_id,
            witness_id: witness.witness_id.clone(),
            status: DepthStatus::Sealed,
            sealed_depth_root,
            cover_band_root,
            depth_range_commitment,
            recursive_parent_root,
            blinding_root,
            observed_height,
            expires_height: observed_height.saturating_add(config.depth_ttl_blocks),
            min_depth,
            max_depth,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_depth_commitment",
            "commitment_id": self.commitment_id,
            "witness_id": self.witness_id,
            "status": self.status.as_str(),
            "sealed_depth_root": self.sealed_depth_root,
            "cover_band_root": self.cover_band_root,
            "depth_range_commitment": self.depth_range_commitment,
            "recursive_parent_root": self.recursive_parent_root,
            "observed_height": self.observed_height,
            "expires_height": self.expires_height,
            "min_depth": self.min_depth,
            "max_depth": self.max_depth,
        })
    }

    pub fn root(&self) -> String {
        module_hash("DEPTH-COMMITMENT", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqProverAttestation {
    pub attestation_id: String,
    pub witness_id: String,
    pub commitment_id: String,
    pub prover_commitment: String,
    pub status: AttestationStatus,
    pub pq_signature_root: String,
    pub prover_capability_root: String,
    pub proof_system_root: String,
    pub quote_floor_piconero: u128,
    pub max_depth_supported: u64,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}

impl PqProverAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        witness_id: impl Into<String>,
        commitment_id: impl Into<String>,
        prover_commitment: impl Into<String>,
        prover_capability_root: impl Into<String>,
        proof_system_root: impl Into<String>,
        quote_floor_piconero: u128,
        max_depth_supported: u64,
        pq_security_bits: u16,
        attested_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let witness_id = witness_id.into();
        let commitment_id = commitment_id.into();
        let prover_commitment = prover_commitment.into();
        let prover_capability_root = prover_capability_root.into();
        let proof_system_root = proof_system_root.into();
        ensure_non_empty(&witness_id, "attestation witness id")?;
        ensure_non_empty(&commitment_id, "attestation commitment id")?;
        ensure_non_empty(&prover_commitment, "attestation prover commitment")?;
        ensure_non_empty(
            &prover_capability_root,
            "attestation prover capability root",
        )?;
        ensure_non_empty(&proof_system_root, "attestation proof system root")?;
        if pq_security_bits < config.min_pq_security_bits {
            return Err("attestation pq security below configured minimum".to_string());
        }
        if max_depth_supported < config.min_recursion_depth {
            return Err("attestation max depth below configured minimum".to_string());
        }
        let pq_signature_root = module_hash(
            "PQ-PROVER-SIGNATURE",
            &[
                HashPart::Str(&config.prover_attestation_scheme),
                HashPart::Str(&witness_id),
                HashPart::Str(&commitment_id),
                HashPart::Str(&prover_commitment),
                HashPart::Str(&prover_capability_root),
                HashPart::Str(&proof_system_root),
                HashPart::U64(u64::from(pq_security_bits)),
                HashPart::U64(attested_height),
            ],
        );
        let attestation_id = module_hash(
            "ATTESTATION-ID",
            &[
                HashPart::Str(&witness_id),
                HashPart::Str(&commitment_id),
                HashPart::Str(&prover_commitment),
                HashPart::Str(&pq_signature_root),
            ],
        );
        Ok(Self {
            attestation_id,
            witness_id,
            commitment_id,
            prover_commitment,
            status: AttestationStatus::Submitted,
            pq_signature_root,
            prover_capability_root,
            proof_system_root,
            quote_floor_piconero,
            max_depth_supported,
            pq_security_bits,
            attested_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_prover_attestation",
            "attestation_id": self.attestation_id,
            "witness_id": self.witness_id,
            "commitment_id": self.commitment_id,
            "prover_commitment": self.prover_commitment,
            "status": self.status.as_str(),
            "pq_signature_root": self.pq_signature_root,
            "prover_capability_root": self.prover_capability_root,
            "proof_system_root": self.proof_system_root,
            "quote_floor_piconero": self.quote_floor_piconero.to_string(),
            "max_depth_supported": self.max_depth_supported,
            "pq_security_bits": self.pq_security_bits,
            "attested_height": self.attested_height,
        })
    }

    pub fn root(&self) -> String {
        module_hash("ATTESTATION", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofQuoteAuction {
    pub auction_id: String,
    pub witness_id: String,
    pub commitment_id: String,
    pub lane: LiquidityLane,
    pub status: AuctionStatus,
    pub sealed_auction_root: String,
    pub quote_commitment_root: String,
    pub clearing_rule_root: String,
    pub max_fee_piconero: u128,
    pub min_rebate_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub awarded_quote_id: Option<String>,
}

impl ProofQuoteAuction {
    pub fn new(
        witness: &RecursiveLiquidityWitness,
        commitment: &SealedDepthCommitment,
        quote_commitment_root: impl Into<String>,
        clearing_rule_root: impl Into<String>,
        max_fee_piconero: u128,
        min_rebate_bps: u64,
        opened_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let quote_commitment_root = quote_commitment_root.into();
        let clearing_rule_root = clearing_rule_root.into();
        ensure_non_empty(&quote_commitment_root, "auction quote commitment root")?;
        ensure_non_empty(&clearing_rule_root, "auction clearing rule root")?;
        ensure_bps(min_rebate_bps, "auction minimum rebate bps")?;
        let sealed_auction_root = module_hash(
            "SEALED-AUCTION",
            &[
                HashPart::Str(&config.quote_auction_scheme),
                HashPart::Str(&witness.witness_id),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(witness.lane.as_str()),
                HashPart::Str(&quote_commitment_root),
                HashPart::Str(&clearing_rule_root),
                HashPart::U64(min_rebate_bps),
            ],
        );
        let auction_id = module_hash(
            "AUCTION-ID",
            &[
                HashPart::Str(&witness.witness_id),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&sealed_auction_root),
                HashPart::U64(opened_height),
            ],
        );
        Ok(Self {
            auction_id,
            witness_id: witness.witness_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            lane: witness.lane,
            status: AuctionStatus::Open,
            sealed_auction_root,
            quote_commitment_root,
            clearing_rule_root,
            max_fee_piconero,
            min_rebate_bps,
            opened_height,
            expires_height: opened_height.saturating_add(config.quote_ttl_blocks),
            awarded_quote_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_quote_auction",
            "auction_id": self.auction_id,
            "witness_id": self.witness_id,
            "commitment_id": self.commitment_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "sealed_auction_root": self.sealed_auction_root,
            "quote_commitment_root": self.quote_commitment_root,
            "clearing_rule_root": self.clearing_rule_root,
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "min_rebate_bps": self.min_rebate_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "awarded_quote_id": self.awarded_quote_id,
        })
    }

    pub fn root(&self) -> String {
        module_hash("AUCTION", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofQuote {
    pub quote_id: String,
    pub auction_id: String,
    pub attestation_id: String,
    pub prover_commitment: String,
    pub status: QuoteStatus,
    pub sealed_quote_root: String,
    pub fee_piconero: u128,
    pub rebate_bps: u64,
    pub estimated_latency_ms: u64,
    pub recursion_depth_bid: u64,
    pub posted_height: u64,
    pub expires_height: u64,
}

impl ProofQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction: &ProofQuoteAuction,
        attestation: &PqProverAttestation,
        fee_piconero: u128,
        rebate_bps: u64,
        estimated_latency_ms: u64,
        recursion_depth_bid: u64,
        posted_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        ensure_bps(rebate_bps, "quote rebate bps")?;
        if fee_piconero > auction.max_fee_piconero {
            return Err("quote fee exceeds auction cap".to_string());
        }
        if rebate_bps < auction.min_rebate_bps {
            return Err("quote rebate below auction minimum".to_string());
        }
        ensure_depth(config, recursion_depth_bid)?;
        if recursion_depth_bid > attestation.max_depth_supported {
            return Err("quote recursion depth exceeds prover attestation".to_string());
        }
        let sealed_quote_root = module_hash(
            "SEALED-QUOTE",
            &[
                HashPart::Str(&config.quote_auction_scheme),
                HashPart::Str(&auction.auction_id),
                HashPart::Str(&attestation.attestation_id),
                HashPart::Str(&attestation.prover_commitment),
                HashPart::U64(rebate_bps),
                HashPart::U64(estimated_latency_ms),
                HashPart::U64(recursion_depth_bid),
            ],
        );
        let quote_id = module_hash(
            "QUOTE-ID",
            &[
                HashPart::Str(&auction.auction_id),
                HashPart::Str(&attestation.attestation_id),
                HashPart::Str(&sealed_quote_root),
                HashPart::U64(posted_height),
            ],
        );
        Ok(Self {
            quote_id,
            auction_id: auction.auction_id.clone(),
            attestation_id: attestation.attestation_id.clone(),
            prover_commitment: attestation.prover_commitment.clone(),
            status: QuoteStatus::Posted,
            sealed_quote_root,
            fee_piconero,
            rebate_bps,
            estimated_latency_ms,
            recursion_depth_bid,
            posted_height,
            expires_height: posted_height.saturating_add(config.quote_ttl_blocks),
        })
    }

    pub fn score(&self, lane: LiquidityLane) -> u128 {
        let fee_score = self.fee_piconero;
        let latency_penalty = u128::from(self.estimated_latency_ms).saturating_mul(100);
        let rebate_credit = u128::from(self.rebate_bps)
            .saturating_mul(u128::from(lane.priority_weight()))
            .saturating_mul(10);
        fee_score
            .saturating_add(latency_penalty)
            .saturating_sub(rebate_credit)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_quote",
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "attestation_id": self.attestation_id,
            "prover_commitment": self.prover_commitment,
            "status": self.status.as_str(),
            "sealed_quote_root": self.sealed_quote_root,
            "fee_piconero": self.fee_piconero.to_string(),
            "rebate_bps": self.rebate_bps,
            "estimated_latency_ms": self.estimated_latency_ms,
            "recursion_depth_bid": self.recursion_depth_bid,
            "posted_height": self.posted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        module_hash("QUOTE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofRebate {
    pub rebate_id: String,
    pub witness_id: String,
    pub quote_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub rebate_root: String,
    pub fee_paid_piconero: u128,
    pub rebate_piconero: u128,
    pub sponsor_cover_bps: u64,
    pub earned_height: u64,
    pub expires_height: u64,
}

impl LowFeeProofRebate {
    pub fn new(
        witness_id: impl Into<String>,
        quote: &ProofQuote,
        beneficiary_commitment: impl Into<String>,
        earned_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let witness_id = witness_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        ensure_non_empty(&witness_id, "rebate witness id")?;
        ensure_non_empty(&beneficiary_commitment, "rebate beneficiary commitment")?;
        let sponsored = quote
            .fee_piconero
            .saturating_mul(u128::from(config.sponsor_cover_bps))
            / u128::from(MAX_BPS);
        let quote_rebate = quote
            .fee_piconero
            .saturating_mul(u128::from(quote.rebate_bps))
            / u128::from(MAX_BPS);
        let rebate_piconero = sponsored.min(quote_rebate);
        let rebate_root = module_hash(
            "REBATE",
            &[
                HashPart::Str(&config.rebate_scheme),
                HashPart::Str(&witness_id),
                HashPart::Str(&quote.quote_id),
                HashPart::Str(&beneficiary_commitment),
                HashPart::U64(quote.rebate_bps),
                HashPart::U64(earned_height),
            ],
        );
        let rebate_id = module_hash(
            "REBATE-ID",
            &[
                HashPart::Str(&witness_id),
                HashPart::Str(&quote.quote_id),
                HashPart::Str(&rebate_root),
            ],
        );
        Ok(Self {
            rebate_id,
            witness_id,
            quote_id: quote.quote_id.clone(),
            beneficiary_commitment,
            status: RebateStatus::Reserved,
            rebate_root,
            fee_paid_piconero: quote.fee_piconero,
            rebate_piconero,
            sponsor_cover_bps: config.sponsor_cover_bps,
            earned_height,
            expires_height: earned_height.saturating_add(config.rebate_ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_rebate",
            "rebate_id": self.rebate_id,
            "witness_id": self.witness_id,
            "quote_id": self.quote_id,
            "status": self.status.as_str(),
            "rebate_root": self.rebate_root,
            "fee_paid_piconero": self.fee_paid_piconero.to_string(),
            "rebate_piconero": self.rebate_piconero.to_string(),
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "earned_height": self.earned_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        module_hash("LOW-FEE-REBATE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleProofQuarantine {
    pub quarantine_id: String,
    pub witness_id: String,
    pub quote_id: Option<String>,
    pub reason: QuarantineReason,
    pub quarantine_root: String,
    pub evidence_root: String,
    pub released: bool,
    pub quarantined_height: u64,
    pub release_height: u64,
}

impl StaleProofQuarantine {
    pub fn new(
        witness_id: impl Into<String>,
        quote_id: Option<String>,
        reason: QuarantineReason,
        evidence_root: impl Into<String>,
        quarantined_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let witness_id = witness_id.into();
        let evidence_root = evidence_root.into();
        ensure_non_empty(&witness_id, "quarantine witness id")?;
        ensure_non_empty(&evidence_root, "quarantine evidence root")?;
        let quote_hash_part = quote_id.as_deref().unwrap_or("none");
        let quarantine_root = module_hash(
            "QUARANTINE",
            &[
                HashPart::Str(&config.quarantine_scheme),
                HashPart::Str(&witness_id),
                HashPart::Str(quote_hash_part),
                HashPart::Str(reason.as_str()),
                HashPart::Str(&evidence_root),
                HashPart::U64(quarantined_height),
            ],
        );
        let quarantine_id = module_hash(
            "QUARANTINE-ID",
            &[
                HashPart::Str(&witness_id),
                HashPart::Str(quote_hash_part),
                HashPart::Str(&quarantine_root),
            ],
        );
        Ok(Self {
            quarantine_id,
            witness_id,
            quote_id,
            reason,
            quarantine_root,
            evidence_root,
            released: false,
            quarantined_height,
            release_height: quarantined_height.saturating_add(config.quarantine_ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stale_proof_quarantine",
            "quarantine_id": self.quarantine_id,
            "witness_id": self.witness_id,
            "quote_id": self.quote_id,
            "reason": self.reason.as_str(),
            "quarantine_root": self.quarantine_root,
            "evidence_root": self.evidence_root,
            "released": self.released,
            "quarantined_height": self.quarantined_height,
            "release_height": self.release_height,
        })
    }

    pub fn root(&self) -> String {
        module_hash(
            "STALE-PROOF-QUARANTINE",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub epoch: u64,
    pub budget_root: String,
    pub allowed_redactions: u64,
    pub consumed_redactions: u64,
    pub min_public_fields: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn new(
        owner_commitment: impl Into<String>,
        epoch: u64,
        allowed_redactions: u64,
        min_public_fields: u64,
        created_height: u64,
        config: &Config,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let owner_commitment = owner_commitment.into();
        ensure_non_empty(&owner_commitment, "redaction budget owner commitment")?;
        if allowed_redactions == 0 {
            return Err("redaction budget must allow at least one redaction".to_string());
        }
        let budget_root = module_hash(
            "REDACTION-BUDGET",
            &[
                HashPart::Str(&config.redaction_budget_scheme),
                HashPart::Str(&owner_commitment),
                HashPart::U64(epoch),
                HashPart::U64(allowed_redactions),
                HashPart::U64(min_public_fields),
                HashPart::U64(created_height),
            ],
        );
        let budget_id = module_hash(
            "REDACTION-BUDGET-ID",
            &[
                HashPart::Str(&owner_commitment),
                HashPart::U64(epoch),
                HashPart::Str(&budget_root),
            ],
        );
        Ok(Self {
            budget_id,
            owner_commitment,
            epoch,
            budget_root,
            allowed_redactions,
            consumed_redactions: 0,
            min_public_fields,
            created_height,
            expires_height: created_height.saturating_add(config.redaction_epoch_blocks),
        })
    }

    pub fn consume(
        &mut self,
        count: u64,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<()> {
        let next = self.consumed_redactions.saturating_add(count);
        if next > self.allowed_redactions {
            return Err("privacy redaction budget exceeded".to_string());
        }
        self.consumed_redactions = next;
        Ok(())
    }

    pub fn remaining_redactions(&self) -> u64 {
        self.allowed_redactions
            .saturating_sub(self.consumed_redactions)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_redaction_budget",
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "epoch": self.epoch,
            "budget_root": self.budget_root,
            "allowed_redactions": self.allowed_redactions,
            "consumed_redactions": self.consumed_redactions,
            "remaining_redactions": self.remaining_redactions(),
            "min_public_fields": self.min_public_fields,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        module_hash("REDACTION-BUDGET", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicMarketEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub public_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl PublicMarketEvent {
    pub fn new(
        event_kind: impl Into<String>,
        subject_id: impl Into<String>,
        public_root: impl Into<String>,
        height: u64,
        sequence: u64,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<Self> {
        let event_kind = event_kind.into();
        let subject_id = subject_id.into();
        let public_root = public_root.into();
        ensure_non_empty(&event_kind, "public event kind")?;
        ensure_non_empty(&subject_id, "public event subject id")?;
        ensure_non_empty(&public_root, "public event root")?;
        let event_id = module_hash(
            "PUBLIC-EVENT-ID",
            &[
                HashPart::Str(&event_kind),
                HashPart::Str(&subject_id),
                HashPart::Str(&public_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
        );
        Ok(Self {
            event_id,
            event_kind,
            subject_id,
            public_root,
            height,
            sequence,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "public_market_event",
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "public_root": self.public_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        module_hash("PUBLIC-EVENT", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub witnesses: BTreeMap<String, RecursiveLiquidityWitness>,
    pub depth_commitments: BTreeMap<String, SealedDepthCommitment>,
    pub attestations: BTreeMap<String, PqProverAttestation>,
    pub auctions: BTreeMap<String, ProofQuoteAuction>,
    pub quotes: BTreeMap<String, ProofQuote>,
    pub rebates: BTreeMap<String, LowFeeProofRebate>,
    pub quarantines: BTreeMap<String, StaleProofQuarantine>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_events: BTreeMap<String, PublicMarketEvent>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            witnesses: BTreeMap::new(),
            depth_commitments: BTreeMap::new(),
            attestations: BTreeMap::new(),
            auctions: BTreeMap::new(),
            quotes: BTreeMap::new(),
            rebates: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_events: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn insert_witness(
        &mut self,
        witness: RecursiveLiquidityWitness,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        self.config.validate()?;
        ensure_capacity(self.witnesses.len(), self.config.max_witnesses, "witnesses")?;
        if self.spent_nullifiers.contains(&witness.privacy_nullifier) {
            return Err("duplicate witness privacy nullifier".to_string());
        }
        let witness_id = witness.witness_id.clone();
        self.spent_nullifiers
            .insert(witness.privacy_nullifier.clone());
        self.counters.witnesses = self.counters.witnesses.saturating_add(1);
        self.emit_public_event(
            "witness_submitted",
            &witness_id,
            &witness.root(),
            witness.created_height,
        )?;
        self.witnesses.insert(witness_id.clone(), witness);
        Ok(witness_id)
    }

    pub fn insert_depth_commitment(
        &mut self,
        commitment: SealedDepthCommitment,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        ensure_capacity(
            self.depth_commitments.len(),
            self.config.max_depth_commitments,
            "depth commitments",
        )?;
        let witness = self
            .witnesses
            .get_mut(&commitment.witness_id)
            .ok_or_else(|| "depth commitment references unknown witness".to_string())?;
        witness.status = WitnessStatus::DepthCommitted;
        let commitment_id = commitment.commitment_id.clone();
        self.counters.depth_commitments = self.counters.depth_commitments.saturating_add(1);
        self.emit_public_event(
            "depth_committed",
            &commitment_id,
            &commitment.root(),
            commitment.observed_height,
        )?;
        self.depth_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn insert_attestation(
        &mut self,
        mut attestation: PqProverAttestation,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        if !self.witnesses.contains_key(&attestation.witness_id) {
            return Err("attestation references unknown witness".to_string());
        }
        if !self
            .depth_commitments
            .contains_key(&attestation.commitment_id)
        {
            return Err("attestation references unknown depth commitment".to_string());
        }
        attestation.status = AttestationStatus::Accepted;
        let attestation_id = attestation.attestation_id.clone();
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        self.emit_public_event(
            "pq_prover_attested",
            &attestation_id,
            &attestation.root(),
            attestation.attested_height,
        )?;
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn open_auction(
        &mut self,
        auction: ProofQuoteAuction,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        ensure_capacity(self.auctions.len(), self.config.max_auctions, "auctions")?;
        let witness = self
            .witnesses
            .get_mut(&auction.witness_id)
            .ok_or_else(|| "auction references unknown witness".to_string())?;
        if !witness.status.accepts_quote() {
            return Err("witness cannot accept quotes in current status".to_string());
        }
        if !self.depth_commitments.contains_key(&auction.commitment_id) {
            return Err("auction references unknown depth commitment".to_string());
        }
        witness.status = WitnessStatus::Quoted;
        let auction_id = auction.auction_id.clone();
        self.counters.auctions = self.counters.auctions.saturating_add(1);
        self.emit_public_event(
            "auction_opened",
            &auction_id,
            &auction.root(),
            auction.opened_height,
        )?;
        self.auctions.insert(auction_id.clone(), auction);
        Ok(auction_id)
    }

    pub fn post_quote(
        &mut self,
        quote: ProofQuote,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        ensure_capacity(self.quotes.len(), self.config.max_quotes, "quotes")?;
        let auction = self
            .auctions
            .get(&quote.auction_id)
            .ok_or_else(|| "quote references unknown auction".to_string())?;
        if !self.attestations.contains_key(&quote.attestation_id) {
            return Err("quote references unknown attestation".to_string());
        }
        let quote_id = quote.quote_id.clone();
        self.counters.quotes = self.counters.quotes.saturating_add(1);
        self.emit_public_event(
            "quote_posted",
            &quote_id,
            &quote.root(),
            quote.posted_height,
        )?;
        if quote.score(auction.lane) == 0 {
            self.counters.total_fee_piconero = self
                .counters
                .total_fee_piconero
                .saturating_add(quote.fee_piconero);
        }
        self.quotes.insert(quote_id.clone(), quote);
        Ok(quote_id)
    }

    pub fn award_best_quote(
        &mut self,
        auction_id: &str,
        height: u64,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        let auction = self
            .auctions
            .get(auction_id)
            .ok_or_else(|| "unknown auction".to_string())?;
        let lane = auction.lane;
        let best_quote_id = self
            .quotes
            .values()
            .filter(|quote| quote.auction_id == auction_id && quote.status == QuoteStatus::Posted)
            .min_by_key(|quote| quote.score(lane))
            .map(|quote| quote.quote_id.clone())
            .ok_or_else(|| "auction has no posted quotes".to_string())?;
        for quote in self.quotes.values_mut() {
            if quote.auction_id == auction_id {
                quote.status = if quote.quote_id == best_quote_id {
                    QuoteStatus::Awarded
                } else {
                    QuoteStatus::Replaced
                };
            }
        }
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| "unknown auction".to_string())?;
        auction.status = AuctionStatus::Awarded;
        auction.awarded_quote_id = Some(best_quote_id.clone());
        let root = auction.root();
        self.emit_public_event("quote_awarded", &best_quote_id, &root, height)?;
        Ok(best_quote_id)
    }

    pub fn reserve_rebate(
        &mut self,
        rebate: LowFeeProofRebate,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        if !self.witnesses.contains_key(&rebate.witness_id) {
            return Err("rebate references unknown witness".to_string());
        }
        if !self.quotes.contains_key(&rebate.quote_id) {
            return Err("rebate references unknown quote".to_string());
        }
        let rebate_id = rebate.rebate_id.clone();
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.counters.total_rebate_piconero = self
            .counters
            .total_rebate_piconero
            .saturating_add(rebate.rebate_piconero);
        self.emit_public_event(
            "rebate_reserved",
            &rebate_id,
            &rebate.root(),
            rebate.earned_height,
        )?;
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn quarantine(
        &mut self,
        quarantine: StaleProofQuarantine,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        ensure_capacity(
            self.quarantines.len(),
            self.config.max_quarantines,
            "quarantines",
        )?;
        let witness = self
            .witnesses
            .get_mut(&quarantine.witness_id)
            .ok_or_else(|| "quarantine references unknown witness".to_string())?;
        witness.status = WitnessStatus::Quarantined;
        if let Some(quote_id) = quarantine.quote_id.as_ref() {
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = QuoteStatus::Slashed;
            }
        }
        let quarantine_id = quarantine.quarantine_id.clone();
        self.counters.quarantines = self.counters.quarantines.saturating_add(1);
        self.counters.stale_proofs = self.counters.stale_proofs.saturating_add(1);
        self.emit_public_event(
            "proof_quarantined",
            &quarantine_id,
            &quarantine.root(),
            quarantine.quarantined_height,
        )?;
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        Ok(quarantine_id)
    }

    pub fn insert_redaction_budget(
        &mut self,
        budget: PrivacyRedactionBudget,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction budgets",
        )?;
        let budget_id = budget.budget_id.clone();
        self.counters.redaction_budgets = self.counters.redaction_budgets.saturating_add(1);
        self.emit_public_event(
            "redaction_budget_opened",
            &budget_id,
            &budget.root(),
            budget.created_height,
        )?;
        self.redaction_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn settle_witness(
        &mut self,
        witness_id: &str,
        quote_id: &str,
        height: u64,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<String> {
        let witness = self
            .witnesses
            .get_mut(witness_id)
            .ok_or_else(|| "unknown witness".to_string())?;
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| "unknown quote".to_string())?;
        if quote.status != QuoteStatus::Awarded {
            return Err("only awarded quote can settle witness".to_string());
        }
        witness.status = WitnessStatus::Settled;
        quote.status = QuoteStatus::Awarded;
        self.counters.settled_proofs = self.counters.settled_proofs.saturating_add(1);
        self.counters.total_fee_piconero = self
            .counters
            .total_fee_piconero
            .saturating_add(quote.fee_piconero);
        let settlement_root = module_hash(
            "SETTLED-WITNESS",
            &[
                HashPart::Str(witness_id),
                HashPart::Str(quote_id),
                HashPart::Str(&witness.root()),
                HashPart::Str(&quote.root()),
                HashPart::U64(height),
            ],
        );
        self.emit_public_event("witness_settled", witness_id, &settlement_root, height)?;
        Ok(settlement_root)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: module_hash("CONFIG", &[HashPart::Json(&self.config.public_record())]),
            witness_root: collection_root(
                "WITNESSES",
                self.witnesses
                    .values()
                    .map(RecursiveLiquidityWitness::public_record),
            ),
            depth_commitment_root: collection_root(
                "DEPTH-COMMITMENTS",
                self.depth_commitments
                    .values()
                    .map(SealedDepthCommitment::public_record),
            ),
            attestation_root: collection_root(
                "ATTESTATIONS",
                self.attestations
                    .values()
                    .map(PqProverAttestation::public_record),
            ),
            auction_root: collection_root(
                "AUCTIONS",
                self.auctions.values().map(ProofQuoteAuction::public_record),
            ),
            quote_root: collection_root(
                "QUOTES",
                self.quotes.values().map(ProofQuote::public_record),
            ),
            rebate_root: collection_root(
                "REBATES",
                self.rebates.values().map(LowFeeProofRebate::public_record),
            ),
            quarantine_root: collection_root(
                "QUARANTINES",
                self.quarantines
                    .values()
                    .map(StaleProofQuarantine::public_record),
            ),
            redaction_budget_root: collection_root(
                "REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(PrivacyRedactionBudget::public_record),
            ),
            public_event_root: collection_root(
                "PUBLIC-EVENTS",
                self.public_events
                    .values()
                    .map(PublicMarketEvent::public_record),
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-RECURSIVE-LIQUIDITY-PROOF-MARKET:NULLIFIERS",
                &self
                    .spent_nullifiers
                    .iter()
                    .map(|nullifier| Value::String(nullifier.clone()))
                    .collect::<Vec<_>>(),
            ),
            counters_root: module_hash(
                "COUNTERS",
                &[HashPart::Json(&self.counters.public_record())],
            ),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_recursive_liquidity_proof_market_runtime",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.root(),
            "witnesses": public_values(self.witnesses.values().map(RecursiveLiquidityWitness::public_record)),
            "depth_commitments": public_values(self.depth_commitments.values().map(SealedDepthCommitment::public_record)),
            "attestations": public_values(self.attestations.values().map(PqProverAttestation::public_record)),
            "auctions": public_values(self.auctions.values().map(ProofQuoteAuction::public_record)),
            "quotes": public_values(self.quotes.values().map(ProofQuote::public_record)),
            "rebates": public_values(self.rebates.values().map(LowFeeProofRebate::public_record)),
            "quarantines": public_values(self.quarantines.values().map(StaleProofQuarantine::public_record)),
            "redaction_budgets": public_values(self.redaction_budgets.values().map(PrivacyRedactionBudget::public_record)),
            "public_events": public_values(self.public_events.values().map(PublicMarketEvent::public_record)),
            "spent_nullifier_count": self.spent_nullifiers.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        module_hash(
            "STATE",
            &[HashPart::Json(&self.public_record_without_root())],
        )
    }

    fn emit_public_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        public_root: &str,
        height: u64,
    ) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<()> {
        ensure_capacity(
            self.public_events.len(),
            self.config.max_public_events,
            "public events",
        )?;
        let sequence = self.counters.public_events.saturating_add(1);
        let event = PublicMarketEvent::new(event_kind, subject_id, public_root, height, sequence)?;
        self.counters.public_events = sequence;
        self.public_events.insert(event.event_id.clone(), event);
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let config = state.config.clone();
    let height = DEVNET_HEIGHT;
    let budget = PrivacyRedactionBudget::new(
        "devnet-redaction-owner-commitment",
        0,
        24,
        8,
        height,
        &config,
    )
    .expect("valid devnet redaction budget");
    state
        .insert_redaction_budget(budget)
        .expect("insert devnet redaction budget");
    let witness = RecursiveLiquidityWitness::new(
        LiquidityLane::LowFee,
        WitnessKind::ReserveDepth,
        "devnet-liquidity-submitment-commitment",
        "devnet-prior-recursive-root",
        "devnet-liquidity-bucket-commitment",
        "devnet-redacted-context-root",
        "devnet-private-nullifier-0",
        8,
        config.min_liquidity_cover_bps,
        config.min_privacy_set_size,
        2_500_000,
        height,
        &config,
    )
    .expect("valid devnet witness");
    let witness_id = state
        .insert_witness(witness)
        .expect("insert devnet witness");
    let witness_ref = state
        .witnesses
        .get(&witness_id)
        .expect("devnet witness exists")
        .clone();
    let commitment = SealedDepthCommitment::new(
        &witness_ref,
        "devnet-depth-range-commitment",
        "devnet-depth-parent-root",
        "devnet-depth-blinding-root",
        height + 1,
        &config,
    )
    .expect("valid devnet depth commitment");
    let commitment_id = state
        .insert_depth_commitment(commitment)
        .expect("insert devnet depth commitment");
    let attestation = PqProverAttestation::new(
        &witness_id,
        &commitment_id,
        "devnet-prover-commitment",
        "devnet-prover-capability-root",
        "devnet-proof-system-root",
        900_000,
        32,
        config.min_pq_security_bits,
        height + 2,
        &config,
    )
    .expect("valid devnet attestation");
    state
        .insert_attestation(attestation)
        .expect("insert devnet attestation");
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let config = state.config.clone();
    let height = DEVNET_HEIGHT + 4;
    let witness = state
        .witnesses
        .values()
        .next()
        .expect("demo witness")
        .clone();
    let commitment = state
        .depth_commitments
        .values()
        .next()
        .expect("demo commitment")
        .clone();
    let auction = ProofQuoteAuction::new(
        &witness,
        &commitment,
        "demo-sealed-quote-set-root",
        "demo-low-fee-clearing-rule-root",
        1_200_000,
        config.target_rebate_bps,
        height,
        &config,
    )
    .expect("valid demo auction");
    let auction_id = state.open_auction(auction).expect("open demo auction");
    let attestation = state
        .attestations
        .values()
        .next()
        .expect("demo attestation")
        .clone();
    let auction_ref = state
        .auctions
        .get(&auction_id)
        .expect("demo auction")
        .clone();
    let quote = ProofQuote::new(
        &auction_ref,
        &attestation,
        820_000,
        config.target_rebate_bps.saturating_add(2),
        640,
        16,
        height + 1,
        &config,
    )
    .expect("valid demo quote");
    let quote_id = state.post_quote(quote).expect("post demo quote");
    state
        .award_best_quote(&auction_id, height + 2)
        .expect("award demo quote");
    let quote_ref = state.quotes.get(&quote_id).expect("demo quote").clone();
    let rebate = LowFeeProofRebate::new(
        &witness.witness_id,
        &quote_ref,
        "demo-beneficiary-commitment",
        height + 3,
        &config,
    )
    .expect("valid demo rebate");
    state.reserve_rebate(rebate).expect("reserve demo rebate");
    state
        .settle_witness(&witness.witness_id, &quote_id, height + 4)
        .expect("settle demo witness");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure_non_empty(
    value: &str,
    label: &str,
) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(
    value: u64,
    label: &str,
) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_depth(
    config: &Config,
    depth: u64,
) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<()> {
    if depth < config.min_recursion_depth || depth > config.max_recursion_depth {
        Err("recursion depth outside configured bounds".to_string())
    } else {
        Ok(())
    }
}

fn ensure_capacity(
    current_len: usize,
    max_len: usize,
    label: &str,
) -> PrivateL2PqConfidentialRecursiveLiquidityProofMarketRuntimeResult<()> {
    if current_len >= max_len {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn module_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-RECURSIVE-LIQUIDITY-PROOF-MARKET:{domain}"),
        parts,
        32,
    )
}

fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-RECURSIVE-LIQUIDITY-PROOF-MARKET:{domain}"),
        &records.into_iter().collect::<Vec<_>>(),
    )
}

fn public_values<I>(records: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    records.into_iter().collect::<Vec<_>>()
}
