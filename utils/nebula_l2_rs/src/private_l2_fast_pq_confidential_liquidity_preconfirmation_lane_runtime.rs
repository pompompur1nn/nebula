use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialLiquidityPreconfirmationLaneRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_LIQUIDITY_PRECONFIRMATION_LANE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-liquidity-preconfirmation-lane-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_LIQUIDITY_PRECONFIRMATION_LANE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-liquidity-preconfirmation-v1";
pub const INTENT_ENVELOPE_SCHEME: &str = "ml-kem-sealed-confidential-liquidity-intent-envelope-v1";
pub const PRECONFIRMATION_COMMITTEE_SCHEME: &str =
    "pq-confidential-liquidity-preconfirmation-committee-root-v1";
pub const MICROBATCH_RECEIPT_SCHEME: &str =
    "pq-confidential-liquidity-preconfirmation-microbatch-receipt-root-v1";
pub const SOLVER_COMMITMENT_SCHEME: &str = "confidential-liquidity-solver-commitment-root-v1";
pub const LATENCY_SLA_WINDOW_SCHEME: &str =
    "fast-confidential-liquidity-preconfirmation-latency-sla-window-root-v1";
pub const PROOF_CACHE_HINT_SCHEME: &str =
    "pq-confidential-liquidity-preconfirmation-proof-cache-hint-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str =
    "low-fee-confidential-liquidity-preconfirmation-rebate-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str =
    "monero-private-l2-confidential-liquidity-nullifier-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-confidential-liquidity-preconfirmation-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_790_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "piconero-devnet-rebate";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_SOLVER_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_MAX_INTENT_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 9;
pub const DEFAULT_CACHE_HINT_REBATE_BPS: u64 = 5;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_PRECONFIRMATION_TTL_MS: u64 = 1_200;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 6;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 750;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 250;
pub const DEFAULT_MICROBATCH_MAX_INTENTS: u32 = 256;
pub const DEFAULT_MICROBATCH_TARGET_MS: u64 = 400;
pub const DEFAULT_MIN_LANE_BOND: u64 = 3_000_000;
pub const DEFAULT_MIN_SOLVER_BOND: u64 = 1_000_000;
pub const DEFAULT_MAX_LANES: usize = 262_144;
pub const DEFAULT_MAX_INTENTS: usize = 8_388_608;
pub const DEFAULT_MAX_COMMITTEES: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_SOLVER_COMMITMENTS: usize = 8_388_608;
pub const DEFAULT_MAX_SLA_WINDOWS: usize = 4_194_304;
pub const DEFAULT_MAX_PROOF_CACHE_HINTS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 2_097_152;
pub const DEFAULT_MAX_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquiditySide {
    Bid,
    Ask,
    TwoSided,
    Rebalance,
    Shield,
    Unshield,
}

impl LiquiditySide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bid => "bid",
            Self::Ask => "ask",
            Self::TwoSided => "two_sided",
            Self::Rebalance => "rebalance",
            Self::Shield => "shield",
            Self::Unshield => "unshield",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Registered,
    Active,
    Saturated,
    Paused,
    Draining,
    Slashed,
    Retired,
}

impl LaneStatus {
    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::Saturated)
    }

    pub fn slashable(self) -> bool {
        !matches!(self, Self::Slashed | Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    CommitteeAssigned,
    SolverCommitted,
    Preconfirmed,
    Microbatched,
    Settled,
    RebateSettled,
    Expired,
    Challenged,
    Slashed,
    Rejected,
}

impl IntentStatus {
    pub fn awaiting_preconfirmation(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::CommitteeAssigned | Self::SolverCommitted
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::RebateSettled | Self::Expired | Self::Slashed | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Registered,
    Assigned,
    Attesting,
    QuorumReached,
    WeakQuorum,
    Rotating,
    Challenged,
    Slashed,
    Retired,
}

impl CommitteeStatus {
    pub fn can_attest(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Assigned | Self::Attesting | Self::WeakQuorum
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    RebateQueued,
    Challenged,
    Reorged,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Posted,
    Matched,
    Preconfirmed,
    Revealed,
    Settled,
    Challenged,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaWindowStatus {
    Open,
    SoftBreached,
    HardBreached,
    Satisfied,
    Challenged,
    Slashed,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCacheHintStatus {
    Advertised,
    CommitteeMatched,
    Used,
    RebateEligible,
    Rejected,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Queued,
    Settled,
    Expired,
    ClawedBack,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceStatus {
    Active,
    Spent,
    Rotated,
    Challenged,
    Burned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    EquivocatedPreconfirmation,
    InvalidEncryptedIntent,
    LatencySlaHardBreach,
    LiquidityWithheld,
    SolverCommitmentMismatch,
    PrivacyFenceLeak,
    ProofCachePoisoning,
    FeeOvercharge,
    InvalidMicrobatchReceipt,
    CommitteeKeyCompromise,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EquivocatedPreconfirmation => "equivocated_preconfirmation",
            Self::InvalidEncryptedIntent => "invalid_encrypted_intent",
            Self::LatencySlaHardBreach => "latency_sla_hard_breach",
            Self::LiquidityWithheld => "liquidity_withheld",
            Self::SolverCommitmentMismatch => "solver_commitment_mismatch",
            Self::PrivacyFenceLeak => "privacy_fence_leak",
            Self::ProofCachePoisoning => "proof_cache_poisoning",
            Self::FeeOvercharge => "fee_overcharge",
            Self::InvalidMicrobatchReceipt => "invalid_microbatch_receipt",
            Self::CommitteeKeyCompromise => "committee_key_compromise",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    LaneRegistered,
    IntentSubmitted,
    CommitteeAssigned,
    SolverCommitted,
    IntentPreconfirmed,
    MicrobatchPublished,
    SlaWindowOpened,
    ProofCacheHintAdvertised,
    RebateQueued,
    PrivacyFenceInserted,
    SlashingEvidencePublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LaneRegistered => "lane_registered",
            Self::IntentSubmitted => "intent_submitted",
            Self::CommitteeAssigned => "committee_assigned",
            Self::SolverCommitted => "solver_committed",
            Self::IntentPreconfirmed => "intent_preconfirmed",
            Self::MicrobatchPublished => "microbatch_published",
            Self::SlaWindowOpened => "sla_window_opened",
            Self::ProofCacheHintAdvertised => "proof_cache_hint_advertised",
            Self::RebateQueued => "rebate_queued",
            Self::PrivacyFenceInserted => "privacy_fence_inserted",
            Self::SlashingEvidencePublished => "slashing_evidence_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub intent_envelope_scheme: String,
    pub preconfirmation_committee_scheme: String,
    pub microbatch_receipt_scheme: String,
    pub solver_commitment_scheme: String,
    pub latency_sla_window_scheme: String,
    pub proof_cache_hint_scheme: String,
    pub low_fee_rebate_scheme: String,
    pub privacy_fence_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub committee_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub solver_quorum_bps: u64,
    pub max_intent_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub cache_hint_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub lane_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub preconfirmation_ttl_ms: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub soft_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub microbatch_max_intents: u32,
    pub microbatch_target_ms: u64,
    pub min_lane_bond: u64,
    pub min_solver_bond: u64,
    pub max_lanes: usize,
    pub max_intents: usize,
    pub max_committees: usize,
    pub max_receipts: usize,
    pub max_solver_commitments: usize,
    pub max_sla_windows: usize,
    pub max_proof_cache_hints: usize,
    pub max_rebates: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_evidence: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            intent_envelope_scheme: INTENT_ENVELOPE_SCHEME.to_string(),
            preconfirmation_committee_scheme: PRECONFIRMATION_COMMITTEE_SCHEME.to_string(),
            microbatch_receipt_scheme: MICROBATCH_RECEIPT_SCHEME.to_string(),
            solver_commitment_scheme: SOLVER_COMMITMENT_SCHEME.to_string(),
            latency_sla_window_scheme: LATENCY_SLA_WINDOW_SCHEME.to_string(),
            proof_cache_hint_scheme: PROOF_CACHE_HINT_SCHEME.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            solver_quorum_bps: DEFAULT_SOLVER_QUORUM_BPS,
            max_intent_fee_bps: DEFAULT_MAX_INTENT_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            cache_hint_rebate_bps: DEFAULT_CACHE_HINT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            preconfirmation_ttl_ms: DEFAULT_PRECONFIRMATION_TTL_MS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            microbatch_max_intents: DEFAULT_MICROBATCH_MAX_INTENTS,
            microbatch_target_ms: DEFAULT_MICROBATCH_TARGET_MS,
            min_lane_bond: DEFAULT_MIN_LANE_BOND,
            min_solver_bond: DEFAULT_MIN_SOLVER_BOND,
            max_lanes: DEFAULT_MAX_LANES,
            max_intents: DEFAULT_MAX_INTENTS,
            max_committees: DEFAULT_MAX_COMMITTEES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_solver_commitments: DEFAULT_MAX_SOLVER_COMMITMENTS,
            max_sla_windows: DEFAULT_MAX_SLA_WINDOWS,
            max_proof_cache_hints: DEFAULT_MAX_PROOF_CACHE_HINTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("rebate_asset_id", &self.rebate_asset_id)?;
        ensure_bps("committee_quorum_bps", self.committee_quorum_bps)?;
        ensure_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        ensure_bps("solver_quorum_bps", self.solver_quorum_bps)?;
        ensure_bps("max_intent_fee_bps", self.max_intent_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("cache_hint_rebate_bps", self.cache_hint_rebate_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.committee_quorum_bps > self.strong_quorum_bps {
            return Err("committee_quorum_bps must be <= strong_quorum_bps".to_string());
        }
        if self.soft_latency_ms > self.hard_latency_ms {
            return Err("soft_latency_ms must be <= hard_latency_ms".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below protocol floor".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set sizes are inconsistent".to_string());
        }
        if self.microbatch_max_intents == 0 {
            return Err("microbatch_max_intents must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_count: u64,
    pub intent_count: u64,
    pub committee_count: u64,
    pub receipt_count: u64,
    pub solver_commitment_count: u64,
    pub sla_window_count: u64,
    pub proof_cache_hint_count: u64,
    pub rebate_count: u64,
    pub privacy_fence_count: u64,
    pub slashing_evidence_count: u64,
    pub event_count: u64,
    pub total_liquidity_micro_units: u64,
    pub total_fee_charged_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_slashed_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lanes_root: String,
    pub intents_root: String,
    pub committees_root: String,
    pub receipts_root: String,
    pub solver_commitments_root: String,
    pub sla_windows_root: String,
    pub proof_cache_hints_root: String,
    pub rebates_root: String,
    pub privacy_fences_root: String,
    pub slashing_evidence_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            lanes_root: empty_root("lanes"),
            intents_root: empty_root("intents"),
            committees_root: empty_root("committees"),
            receipts_root: empty_root("receipts"),
            solver_commitments_root: empty_root("solver-commitments"),
            sla_windows_root: empty_root("sla-windows"),
            proof_cache_hints_root: empty_root("proof-cache-hints"),
            rebates_root: empty_root("rebates"),
            privacy_fences_root: empty_root("privacy-fences"),
            slashing_evidence_root: empty_root("slashing-evidence"),
            events_root: empty_root("events"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityLane {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_status: LaneStatus,
    pub supported_sides: BTreeSet<LiquiditySide>,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub liquidity_pool_commitment: String,
    pub capacity_micro_units: u64,
    pub reserved_micro_units: u64,
    pub min_fill_micro_units: u64,
    pub max_fee_bps: u64,
    pub lane_bond_micro_units: u64,
    pub pq_verifying_key_root: String,
    pub committee_roster_root: String,
    pub privacy_policy_root: String,
    pub proof_cache_policy_root: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub last_heartbeat_ms: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedLiquidityIntent {
    pub intent_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub side: LiquiditySide,
    pub encrypted_envelope_root: String,
    pub amount_commitment: String,
    pub price_limit_commitment: String,
    pub liquidity_nullifier: String,
    pub change_note_commitment: String,
    pub fee_cap_micro_units: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub pq_signature_root: String,
    pub cache_hint_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub submitted_at_ms: u64,
    pub status: IntentStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPreconfirmationCommittee {
    pub committee_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub member_commitments_root: String,
    pub aggregate_pq_key_root: String,
    pub threshold: u16,
    pub member_count: u16,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub assigned_intent_root: String,
    pub preconfirmation_transcript_root: String,
    pub status: CommitteeStatus,
    pub assigned_height: u64,
    pub rotates_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MicrobatchReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub microbatch_id: String,
    pub intent_root: String,
    pub solver_commitment_root: String,
    pub fill_commitment_root: String,
    pub residual_commitment_root: String,
    pub fee_commitment_root: String,
    pub rebate_commitment_root: String,
    pub latency_root: String,
    pub aggregate_signature_root: String,
    pub status: ReceiptStatus,
    pub intent_count: u32,
    pub published_height: u64,
    pub finalizes_height: u64,
    pub published_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverCommitment {
    pub solver_commitment_id: String,
    pub lane_id: String,
    pub intent_id: String,
    pub solver_commitment: String,
    pub solver_bond_commitment: String,
    pub inventory_commitment_root: String,
    pub fill_path_commitment_root: String,
    pub max_latency_ms: u64,
    pub quoted_fee_micro_units: u64,
    pub quoted_rebate_micro_units: u64,
    pub solver_pq_signature_root: String,
    pub status: SolverCommitmentStatus,
    pub posted_height: u64,
    pub expires_height: u64,
    pub posted_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencySlaWindow {
    pub window_id: String,
    pub lane_id: String,
    pub intent_id: String,
    pub committee_id: String,
    pub soft_deadline_ms: u64,
    pub hard_deadline_ms: u64,
    pub opened_at_ms: u64,
    pub satisfied_at_ms: Option<u64>,
    pub observed_latency_ms: Option<u64>,
    pub status: SlaWindowStatus,
    pub penalty_bps: u64,
    pub evidence_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheHint {
    pub hint_id: String,
    pub lane_id: String,
    pub intent_id: String,
    pub cache_key_root: String,
    pub proof_family: String,
    pub expected_witness_root: String,
    pub cached_output_root: String,
    pub hit_weight: u64,
    pub rebate_bps: u64,
    pub status: ProofCacheHintStatus,
    pub advertised_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub lane_id: String,
    pub intent_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub fee_charged_micro_units: u64,
    pub rebate_micro_units: u64,
    pub sponsor_cover_micro_units: u64,
    pub asset_id: String,
    pub status: RebateStatus,
    pub queued_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub nullifier_or_seed: String,
    pub privacy_set_root: String,
    pub view_tag_root: String,
    pub minimum_set_size: u64,
    pub status: PrivacyFenceStatus,
    pub inserted_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub slash_amount_micro_units: u64,
    pub published_height: u64,
    pub adjudication_deadline_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub height: u64,
    pub index: u64,
    pub event_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, LiquidityLane>,
    pub intents: BTreeMap<String, EncryptedLiquidityIntent>,
    pub committees: BTreeMap<String, PqPreconfirmationCommittee>,
    pub receipts: BTreeMap<String, MicrobatchReceipt>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub sla_windows: BTreeMap<String, LatencySlaWindow>,
    pub proof_cache_hints: BTreeMap<String, ProofCacheHint>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            intents: BTreeMap::new(),
            committees: BTreeMap::new(),
            receipts: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            sla_windows: BTreeMap::new(),
            proof_cache_hints: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::default())?;
        let lane = state.register_lane(
            "devnet-liquidity-operator-commitment",
            vec![
                LiquiditySide::Bid,
                LiquiditySide::Ask,
                LiquiditySide::TwoSided,
            ],
            "xmr-devnet-base-asset-commitment",
            "pxmr-devnet-quote-asset-commitment",
            "devnet-confidential-liquidity-pool-root",
            9_000_000_000,
            25_000,
            10,
            "devnet-lane-pq-verifying-key-root",
            "devnet-lane-committee-roster-root",
            "devnet-lane-privacy-policy-root",
            "devnet-lane-proof-cache-policy-root",
            DEVNET_HEIGHT,
            1_000,
            "devnet-lane-metadata-root",
        )?;
        let intent = state.submit_intent(
            &lane.lane_id,
            "devnet-account-commitment",
            LiquiditySide::TwoSided,
            "devnet-encrypted-liquidity-intent-envelope-root",
            "devnet-amount-commitment",
            "devnet-price-limit-commitment",
            "devnet-liquidity-nullifier",
            "devnet-change-note-commitment",
            3_200,
            9,
            DEFAULT_BATCH_PRIVACY_SET_SIZE,
            "devnet-intent-pq-ciphertext-root",
            "devnet-intent-pq-signature-root",
            "devnet-cache-hint-root",
            DEVNET_HEIGHT + 1,
            1_010,
        )?;
        let committee = state.assign_committee(
            &lane.lane_id,
            42,
            "devnet-committee-members-root",
            "devnet-committee-aggregate-pq-key-root",
            5,
            7,
            &intent.intent_id,
            "devnet-preconfirmation-transcript-root",
            DEVNET_HEIGHT + 1,
        )?;
        let solver = state.post_solver_commitment(
            &lane.lane_id,
            &intent.intent_id,
            "devnet-solver-commitment",
            "devnet-solver-bond-commitment",
            "devnet-inventory-commitment-root",
            "devnet-fill-path-commitment-root",
            210,
            1_200,
            180,
            "devnet-solver-pq-signature-root",
            DEVNET_HEIGHT + 1,
            1_025,
        )?;
        state.open_sla_window(
            &lane.lane_id,
            &intent.intent_id,
            &committee.committee_id,
            1_010,
            "devnet-sla-evidence-root",
        )?;
        state.advertise_proof_cache_hint(
            &lane.lane_id,
            &intent.intent_id,
            "devnet-cache-key-root",
            "liquidity-membership+range-proof",
            "devnet-expected-witness-root",
            "devnet-cached-output-root",
            3,
            DEVNET_HEIGHT + 1,
        )?;
        let receipt = state.publish_microbatch_receipt(
            &lane.lane_id,
            &committee.committee_id,
            vec![intent.intent_id.clone()],
            vec![solver.solver_commitment_id.clone()],
            "devnet-fill-commitment-root",
            "devnet-residual-commitment-root",
            "devnet-fee-commitment-root",
            "devnet-rebate-commitment-root",
            "devnet-latency-root",
            "devnet-aggregate-signature-root",
            DEVNET_HEIGHT + 2,
            1_180,
        )?;
        state.queue_rebate(
            &lane.lane_id,
            &intent.intent_id,
            &receipt.receipt_id,
            "devnet-beneficiary-commitment",
            1_200,
            1,
            DEVNET_HEIGHT + 2,
        )?;
        state.insert_privacy_fence(
            &lane.lane_id,
            &intent.intent_id,
            "devnet-liquidity-nullifier",
            "devnet-privacy-set-root",
            "devnet-view-tag-root",
            DEFAULT_BATCH_PRIVACY_SET_SIZE,
            DEVNET_HEIGHT + 2,
        )?;
        Ok(state)
    }

    pub fn devnet_public_record() -> Result<Value> {
        Ok(Self::devnet()?.public_record())
    }

    pub fn register_lane(
        &mut self,
        operator_commitment: &str,
        supported_sides: Vec<LiquiditySide>,
        base_asset_commitment: &str,
        quote_asset_commitment: &str,
        liquidity_pool_commitment: &str,
        capacity_micro_units: u64,
        min_fill_micro_units: u64,
        max_fee_bps: u64,
        pq_verifying_key_root: &str,
        committee_roster_root: &str,
        privacy_policy_root: &str,
        proof_cache_policy_root: &str,
        created_height: u64,
        last_heartbeat_ms: u64,
        metadata_root: &str,
    ) -> Result<LiquidityLane> {
        self.config.validate()?;
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_nonempty("operator_commitment", operator_commitment)?;
        ensure_nonempty("base_asset_commitment", base_asset_commitment)?;
        ensure_nonempty("quote_asset_commitment", quote_asset_commitment)?;
        ensure_nonempty("liquidity_pool_commitment", liquidity_pool_commitment)?;
        ensure_bps("max_fee_bps", max_fee_bps)?;
        if max_fee_bps > self.config.max_intent_fee_bps {
            return Err("lane max_fee_bps exceeds configured fee cap".to_string());
        }
        if capacity_micro_units == 0 {
            return Err("capacity_micro_units must be positive".to_string());
        }
        if min_fill_micro_units > capacity_micro_units {
            return Err("min_fill_micro_units exceeds capacity".to_string());
        }
        let supported_sides = supported_sides.into_iter().collect::<BTreeSet<_>>();
        if supported_sides.is_empty() {
            return Err("supported_sides must not be empty".to_string());
        }
        let lane_id = lane_id(
            operator_commitment,
            liquidity_pool_commitment,
            pq_verifying_key_root,
            created_height,
        );
        let lane = LiquidityLane {
            lane_id: lane_id.clone(),
            operator_commitment: operator_commitment.to_string(),
            lane_status: LaneStatus::Active,
            supported_sides,
            base_asset_commitment: base_asset_commitment.to_string(),
            quote_asset_commitment: quote_asset_commitment.to_string(),
            liquidity_pool_commitment: liquidity_pool_commitment.to_string(),
            capacity_micro_units,
            reserved_micro_units: 0,
            min_fill_micro_units,
            max_fee_bps,
            lane_bond_micro_units: self.config.min_lane_bond,
            pq_verifying_key_root: pq_verifying_key_root.to_string(),
            committee_roster_root: committee_roster_root.to_string(),
            privacy_policy_root: privacy_policy_root.to_string(),
            proof_cache_policy_root: proof_cache_policy_root.to_string(),
            created_height,
            expires_height: created_height.saturating_add(self.config.lane_ttl_blocks),
            last_heartbeat_ms,
            metadata_root: metadata_root.to_string(),
        };
        self.lanes.insert(lane_id.clone(), lane.clone());
        self.counters.lane_count = self.lanes.len() as u64;
        self.push_event(EventKind::LaneRegistered, &lane_id, created_height)?;
        self.refresh_roots();
        Ok(lane)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_intent(
        &mut self,
        lane_id_ref: &str,
        account_commitment: &str,
        side: LiquiditySide,
        encrypted_envelope_root: &str,
        amount_commitment: &str,
        price_limit_commitment: &str,
        liquidity_nullifier: &str,
        change_note_commitment: &str,
        fee_cap_micro_units: u64,
        max_fee_bps: u64,
        privacy_set_size: u64,
        pq_ciphertext_root: &str,
        pq_signature_root: &str,
        cache_hint_root: &str,
        submitted_height: u64,
        submitted_at_ms: u64,
    ) -> Result<EncryptedLiquidityIntent> {
        ensure_capacity("intents", self.intents.len(), self.config.max_intents)?;
        ensure_bps("max_fee_bps", max_fee_bps)?;
        let lane = self
            .lanes
            .get_mut(lane_id_ref)
            .ok_or_else(|| format!("lane {lane_id_ref} not found"))?;
        if !lane.lane_status.accepts_intents() {
            return Err("lane does not accept intents".to_string());
        }
        if !lane.supported_sides.contains(&side) {
            return Err("lane does not support requested side".to_string());
        }
        if max_fee_bps > lane.max_fee_bps {
            return Err("intent max_fee_bps exceeds lane fee cap".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below configured minimum".to_string());
        }
        for (label, value) in [
            ("account_commitment", account_commitment),
            ("encrypted_envelope_root", encrypted_envelope_root),
            ("amount_commitment", amount_commitment),
            ("price_limit_commitment", price_limit_commitment),
            ("liquidity_nullifier", liquidity_nullifier),
            ("change_note_commitment", change_note_commitment),
            ("pq_ciphertext_root", pq_ciphertext_root),
            ("pq_signature_root", pq_signature_root),
        ] {
            ensure_nonempty(label, value)?;
        }
        let intent_id = intent_id(
            lane_id_ref,
            account_commitment,
            encrypted_envelope_root,
            liquidity_nullifier,
            submitted_height,
        );
        let reserve = fee_cap_micro_units.max(lane.min_fill_micro_units);
        if lane.reserved_micro_units.saturating_add(reserve) > lane.capacity_micro_units {
            lane.lane_status = LaneStatus::Saturated;
            return Err("lane liquidity capacity exceeded".to_string());
        }
        lane.reserved_micro_units = lane.reserved_micro_units.saturating_add(reserve);
        let intent = EncryptedLiquidityIntent {
            intent_id: intent_id.clone(),
            lane_id: lane_id_ref.to_string(),
            account_commitment: account_commitment.to_string(),
            side,
            encrypted_envelope_root: encrypted_envelope_root.to_string(),
            amount_commitment: amount_commitment.to_string(),
            price_limit_commitment: price_limit_commitment.to_string(),
            liquidity_nullifier: liquidity_nullifier.to_string(),
            change_note_commitment: change_note_commitment.to_string(),
            fee_cap_micro_units,
            max_fee_bps,
            privacy_set_size,
            pq_ciphertext_root: pq_ciphertext_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            cache_hint_root: cache_hint_root.to_string(),
            submitted_height,
            expires_height: submitted_height.saturating_add(self.config.intent_ttl_blocks),
            submitted_at_ms,
            status: IntentStatus::Submitted,
        };
        self.intents.insert(intent_id.clone(), intent.clone());
        self.counters.intent_count = self.intents.len() as u64;
        self.counters.total_liquidity_micro_units = self
            .counters
            .total_liquidity_micro_units
            .saturating_add(reserve);
        self.push_event(EventKind::IntentSubmitted, &intent_id, submitted_height)?;
        self.refresh_roots();
        Ok(intent)
    }

    pub fn assign_committee(
        &mut self,
        lane_id_ref: &str,
        epoch: u64,
        member_commitments_root: &str,
        aggregate_pq_key_root: &str,
        threshold: u16,
        member_count: u16,
        assigned_intent_id: &str,
        preconfirmation_transcript_root: &str,
        assigned_height: u64,
    ) -> Result<PqPreconfirmationCommittee> {
        ensure_capacity(
            "committees",
            self.committees.len(),
            self.config.max_committees,
        )?;
        self.require_lane(lane_id_ref)?;
        let intent = self
            .intents
            .get_mut(assigned_intent_id)
            .ok_or_else(|| format!("intent {assigned_intent_id} not found"))?;
        if intent.lane_id != lane_id_ref {
            return Err("intent belongs to a different lane".to_string());
        }
        if threshold == 0 || member_count == 0 || threshold > member_count {
            return Err("committee threshold/member_count invalid".to_string());
        }
        ensure_nonempty("member_commitments_root", member_commitments_root)?;
        ensure_nonempty("aggregate_pq_key_root", aggregate_pq_key_root)?;
        let committee_id = committee_id(
            lane_id_ref,
            epoch,
            member_commitments_root,
            aggregate_pq_key_root,
        );
        let committee = PqPreconfirmationCommittee {
            committee_id: committee_id.clone(),
            lane_id: lane_id_ref.to_string(),
            epoch,
            member_commitments_root: member_commitments_root.to_string(),
            aggregate_pq_key_root: aggregate_pq_key_root.to_string(),
            threshold,
            member_count,
            quorum_bps: self.config.committee_quorum_bps,
            strong_quorum_bps: self.config.strong_quorum_bps,
            assigned_intent_root: public_subject_root("assigned-intent", assigned_intent_id),
            preconfirmation_transcript_root: preconfirmation_transcript_root.to_string(),
            status: CommitteeStatus::Assigned,
            assigned_height,
            rotates_height: assigned_height.saturating_add(self.config.intent_ttl_blocks),
        };
        intent.status = IntentStatus::CommitteeAssigned;
        self.committees
            .insert(committee_id.clone(), committee.clone());
        self.counters.committee_count = self.committees.len() as u64;
        self.push_event(EventKind::CommitteeAssigned, &committee_id, assigned_height)?;
        self.refresh_roots();
        Ok(committee)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn post_solver_commitment(
        &mut self,
        lane_id_ref: &str,
        intent_id_ref: &str,
        solver_commitment_value: &str,
        solver_bond_commitment: &str,
        inventory_commitment_root: &str,
        fill_path_commitment_root: &str,
        max_latency_ms: u64,
        quoted_fee_micro_units: u64,
        quoted_rebate_micro_units: u64,
        solver_pq_signature_root: &str,
        posted_height: u64,
        posted_at_ms: u64,
    ) -> Result<SolverCommitment> {
        ensure_capacity(
            "solver_commitments",
            self.solver_commitments.len(),
            self.config.max_solver_commitments,
        )?;
        self.require_lane(lane_id_ref)?;
        let intent = self
            .intents
            .get_mut(intent_id_ref)
            .ok_or_else(|| format!("intent {intent_id_ref} not found"))?;
        if intent.lane_id != lane_id_ref {
            return Err("intent belongs to a different lane".to_string());
        }
        if max_latency_ms > self.config.hard_latency_ms {
            return Err("solver max_latency_ms exceeds hard SLA".to_string());
        }
        if quoted_fee_micro_units > intent.fee_cap_micro_units {
            return Err("quoted_fee_micro_units exceeds intent fee cap".to_string());
        }
        for (label, value) in [
            ("solver_commitment", solver_commitment_value),
            ("solver_bond_commitment", solver_bond_commitment),
            ("inventory_commitment_root", inventory_commitment_root),
            ("fill_path_commitment_root", fill_path_commitment_root),
            ("solver_pq_signature_root", solver_pq_signature_root),
        ] {
            ensure_nonempty(label, value)?;
        }
        let solver_commitment_id = solver_commitment_id(
            lane_id_ref,
            intent_id_ref,
            solver_commitment_value,
            inventory_commitment_root,
        );
        let commitment = SolverCommitment {
            solver_commitment_id: solver_commitment_id.clone(),
            lane_id: lane_id_ref.to_string(),
            intent_id: intent_id_ref.to_string(),
            solver_commitment: solver_commitment_value.to_string(),
            solver_bond_commitment: solver_bond_commitment.to_string(),
            inventory_commitment_root: inventory_commitment_root.to_string(),
            fill_path_commitment_root: fill_path_commitment_root.to_string(),
            max_latency_ms,
            quoted_fee_micro_units,
            quoted_rebate_micro_units,
            solver_pq_signature_root: solver_pq_signature_root.to_string(),
            status: SolverCommitmentStatus::Posted,
            posted_height,
            expires_height: posted_height.saturating_add(self.config.intent_ttl_blocks),
            posted_at_ms,
        };
        intent.status = IntentStatus::SolverCommitted;
        self.solver_commitments
            .insert(solver_commitment_id.clone(), commitment.clone());
        self.counters.solver_commitment_count = self.solver_commitments.len() as u64;
        self.push_event(
            EventKind::SolverCommitted,
            &solver_commitment_id,
            posted_height,
        )?;
        self.refresh_roots();
        Ok(commitment)
    }

    pub fn open_sla_window(
        &mut self,
        lane_id_ref: &str,
        intent_id_ref: &str,
        committee_id_ref: &str,
        opened_at_ms: u64,
        evidence_root: &str,
    ) -> Result<LatencySlaWindow> {
        ensure_capacity(
            "sla_windows",
            self.sla_windows.len(),
            self.config.max_sla_windows,
        )?;
        self.require_lane(lane_id_ref)?;
        self.require_intent(intent_id_ref, lane_id_ref)?;
        let committee = self
            .committees
            .get(committee_id_ref)
            .ok_or_else(|| format!("committee {committee_id_ref} not found"))?;
        if committee.lane_id != lane_id_ref {
            return Err("committee belongs to a different lane".to_string());
        }
        let soft_deadline_ms = opened_at_ms.saturating_add(self.config.soft_latency_ms);
        let hard_deadline_ms = opened_at_ms.saturating_add(self.config.hard_latency_ms);
        let window_id = sla_window_id(lane_id_ref, intent_id_ref, committee_id_ref, opened_at_ms);
        let window = LatencySlaWindow {
            window_id: window_id.clone(),
            lane_id: lane_id_ref.to_string(),
            intent_id: intent_id_ref.to_string(),
            committee_id: committee_id_ref.to_string(),
            soft_deadline_ms,
            hard_deadline_ms,
            opened_at_ms,
            satisfied_at_ms: None,
            observed_latency_ms: None,
            status: SlaWindowStatus::Open,
            penalty_bps: 0,
            evidence_root: evidence_root.to_string(),
        };
        self.sla_windows.insert(window_id.clone(), window.clone());
        self.counters.sla_window_count = self.sla_windows.len() as u64;
        self.push_event(EventKind::SlaWindowOpened, &window_id, 0)?;
        self.refresh_roots();
        Ok(window)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn advertise_proof_cache_hint(
        &mut self,
        lane_id_ref: &str,
        intent_id_ref: &str,
        cache_key_root: &str,
        proof_family: &str,
        expected_witness_root: &str,
        cached_output_root: &str,
        hit_weight: u64,
        advertised_height: u64,
    ) -> Result<ProofCacheHint> {
        ensure_capacity(
            "proof_cache_hints",
            self.proof_cache_hints.len(),
            self.config.max_proof_cache_hints,
        )?;
        self.require_lane(lane_id_ref)?;
        self.require_intent(intent_id_ref, lane_id_ref)?;
        for (label, value) in [
            ("cache_key_root", cache_key_root),
            ("proof_family", proof_family),
            ("expected_witness_root", expected_witness_root),
            ("cached_output_root", cached_output_root),
        ] {
            ensure_nonempty(label, value)?;
        }
        let hint_id = proof_cache_hint_id(lane_id_ref, intent_id_ref, cache_key_root);
        let hint = ProofCacheHint {
            hint_id: hint_id.clone(),
            lane_id: lane_id_ref.to_string(),
            intent_id: intent_id_ref.to_string(),
            cache_key_root: cache_key_root.to_string(),
            proof_family: proof_family.to_string(),
            expected_witness_root: expected_witness_root.to_string(),
            cached_output_root: cached_output_root.to_string(),
            hit_weight,
            rebate_bps: self.config.cache_hint_rebate_bps,
            status: ProofCacheHintStatus::Advertised,
            advertised_height,
            expires_height: advertised_height.saturating_add(self.config.intent_ttl_blocks),
        };
        self.proof_cache_hints.insert(hint_id.clone(), hint.clone());
        self.counters.proof_cache_hint_count = self.proof_cache_hints.len() as u64;
        self.push_event(
            EventKind::ProofCacheHintAdvertised,
            &hint_id,
            advertised_height,
        )?;
        self.refresh_roots();
        Ok(hint)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn publish_microbatch_receipt(
        &mut self,
        lane_id_ref: &str,
        committee_id_ref: &str,
        intent_ids: Vec<String>,
        solver_commitment_ids: Vec<String>,
        fill_commitment_root: &str,
        residual_commitment_root: &str,
        fee_commitment_root: &str,
        rebate_commitment_root: &str,
        latency_root: &str,
        aggregate_signature_root: &str,
        published_height: u64,
        published_at_ms: u64,
    ) -> Result<MicrobatchReceipt> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        self.require_lane(lane_id_ref)?;
        {
            let committee = self
                .committees
                .get(committee_id_ref)
                .ok_or_else(|| format!("committee {committee_id_ref} not found"))?;
            if committee.lane_id != lane_id_ref {
                return Err("committee belongs to a different lane".to_string());
            }
        }
        if intent_ids.is_empty() {
            return Err("microbatch must include at least one intent".to_string());
        }
        if intent_ids.len() > self.config.microbatch_max_intents as usize {
            return Err("microbatch intent count exceeds configured maximum".to_string());
        }
        for intent_id_ref in &intent_ids {
            self.require_intent(intent_id_ref, lane_id_ref)?;
        }
        for solver_commitment_id_ref in &solver_commitment_ids {
            let commitment = self
                .solver_commitments
                .get_mut(solver_commitment_id_ref)
                .ok_or_else(|| format!("solver commitment {solver_commitment_id_ref} not found"))?;
            if commitment.lane_id != lane_id_ref {
                return Err("solver commitment belongs to a different lane".to_string());
            }
            commitment.status = SolverCommitmentStatus::Preconfirmed;
        }
        let intent_root = list_root("microbatch-intents", &intent_ids);
        let solver_commitment_root =
            list_root("microbatch-solver-commitments", &solver_commitment_ids);
        let microbatch_id = microbatch_id(
            lane_id_ref,
            committee_id_ref,
            &intent_root,
            published_height,
            published_at_ms,
        );
        let receipt_id = receipt_id(
            lane_id_ref,
            &microbatch_id,
            &intent_root,
            fill_commitment_root,
            published_height,
        );
        let receipt = MicrobatchReceipt {
            receipt_id: receipt_id.clone(),
            lane_id: lane_id_ref.to_string(),
            committee_id: committee_id_ref.to_string(),
            microbatch_id,
            intent_root,
            solver_commitment_root,
            fill_commitment_root: fill_commitment_root.to_string(),
            residual_commitment_root: residual_commitment_root.to_string(),
            fee_commitment_root: fee_commitment_root.to_string(),
            rebate_commitment_root: rebate_commitment_root.to_string(),
            latency_root: latency_root.to_string(),
            aggregate_signature_root: aggregate_signature_root.to_string(),
            status: ReceiptStatus::Published,
            intent_count: intent_ids.len() as u32,
            published_height,
            finalizes_height: published_height.saturating_add(self.config.receipt_finality_blocks),
            published_at_ms,
        };
        if let Some(committee) = self.committees.get_mut(committee_id_ref) {
            committee.status = CommitteeStatus::QuorumReached;
        }
        for intent_id_ref in intent_ids {
            if let Some(intent) = self.intents.get_mut(&intent_id_ref) {
                intent.status = IntentStatus::Preconfirmed;
            }
        }
        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.counters.receipt_count = self.receipts.len() as u64;
        self.push_event(
            EventKind::MicrobatchPublished,
            &receipt_id,
            published_height,
        )?;
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn queue_rebate(
        &mut self,
        lane_id_ref: &str,
        intent_id_ref: &str,
        receipt_id_ref: &str,
        beneficiary_commitment: &str,
        fee_charged_micro_units: u64,
        cache_hint_count: u64,
        queued_height: u64,
    ) -> Result<LowFeeRebate> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        self.require_lane(lane_id_ref)?;
        self.require_intent(intent_id_ref, lane_id_ref)?;
        let receipt = self
            .receipts
            .get(receipt_id_ref)
            .ok_or_else(|| format!("receipt {receipt_id_ref} not found"))?;
        if receipt.lane_id != lane_id_ref {
            return Err("receipt belongs to a different lane".to_string());
        }
        ensure_nonempty("beneficiary_commitment", beneficiary_commitment)?;
        let rebate_micro_units = compute_rebate(
            fee_charged_micro_units,
            self.config.target_rebate_bps,
            cache_hint_count,
            self.config.cache_hint_rebate_bps,
        );
        let sponsor_cover_micro_units = mul_bps(rebate_micro_units, self.config.sponsor_cover_bps);
        let rebate_id = rebate_id(receipt_id_ref, intent_id_ref, beneficiary_commitment);
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            lane_id: lane_id_ref.to_string(),
            intent_id: intent_id_ref.to_string(),
            receipt_id: receipt_id_ref.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            fee_charged_micro_units,
            rebate_micro_units,
            sponsor_cover_micro_units,
            asset_id: self.config.rebate_asset_id.clone(),
            status: RebateStatus::Queued,
            queued_height,
            expires_height: queued_height.saturating_add(self.config.rebate_ttl_blocks),
        };
        if let Some(intent) = self.intents.get_mut(intent_id_ref) {
            intent.status = IntentStatus::RebateSettled;
        }
        self.rebates.insert(rebate_id.clone(), rebate.clone());
        self.counters.rebate_count = self.rebates.len() as u64;
        self.counters.total_fee_charged_micro_units = self
            .counters
            .total_fee_charged_micro_units
            .saturating_add(fee_charged_micro_units);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(rebate_micro_units);
        self.push_event(EventKind::RebateQueued, &rebate_id, queued_height)?;
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn insert_privacy_fence(
        &mut self,
        lane_id_ref: &str,
        subject_id: &str,
        nullifier_or_seed: &str,
        privacy_set_root: &str,
        view_tag_root: &str,
        minimum_set_size: u64,
        inserted_height: u64,
    ) -> Result<PrivacyFence> {
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        self.require_lane(lane_id_ref)?;
        if minimum_set_size < self.config.min_privacy_set_size {
            return Err("minimum_set_size below configured minimum".to_string());
        }
        let fence_id = privacy_fence_id(lane_id_ref, subject_id, nullifier_or_seed);
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            lane_id: lane_id_ref.to_string(),
            subject_id: subject_id.to_string(),
            nullifier_or_seed: nullifier_or_seed.to_string(),
            privacy_set_root: privacy_set_root.to_string(),
            view_tag_root: view_tag_root.to_string(),
            minimum_set_size,
            status: PrivacyFenceStatus::Active,
            inserted_height,
        };
        self.privacy_fences.insert(fence_id.clone(), fence.clone());
        self.counters.privacy_fence_count = self.privacy_fences.len() as u64;
        self.push_event(EventKind::PrivacyFenceInserted, &fence_id, inserted_height)?;
        self.refresh_roots();
        Ok(fence)
    }

    pub fn publish_slashing_evidence(
        &mut self,
        lane_id_ref: &str,
        subject_id: &str,
        reason: SlashingReason,
        evidence_root: &str,
        reporter_commitment: &str,
        slash_amount_micro_units: u64,
        published_height: u64,
    ) -> Result<SlashingEvidence> {
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        let lane = self
            .lanes
            .get_mut(lane_id_ref)
            .ok_or_else(|| format!("lane {lane_id_ref} not found"))?;
        if !lane.lane_status.slashable() {
            return Err("lane is not slashable".to_string());
        }
        ensure_nonempty("subject_id", subject_id)?;
        ensure_nonempty("evidence_root", evidence_root)?;
        ensure_nonempty("reporter_commitment", reporter_commitment)?;
        let evidence_id = slashing_evidence_id(
            lane_id_ref,
            subject_id,
            reason,
            evidence_root,
            published_height,
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            lane_id: lane_id_ref.to_string(),
            subject_id: subject_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            reporter_commitment: reporter_commitment.to_string(),
            slash_amount_micro_units,
            published_height,
            adjudication_deadline_height: published_height
                .saturating_add(self.config.receipt_finality_blocks),
        };
        lane.lane_status = LaneStatus::Slashed;
        lane.lane_bond_micro_units = lane
            .lane_bond_micro_units
            .saturating_sub(slash_amount_micro_units);
        self.slashing_evidence
            .insert(evidence_id.clone(), evidence.clone());
        self.counters.slashing_evidence_count = self.slashing_evidence.len() as u64;
        self.counters.total_slashed_micro_units = self
            .counters
            .total_slashed_micro_units
            .saturating_add(slash_amount_micro_units);
        self.push_event(
            EventKind::SlashingEvidencePublished,
            &evidence_id,
            published_height,
        )?;
        self.refresh_roots();
        Ok(evidence)
    }

    pub fn satisfy_sla_window(&mut self, window_id_ref: &str, satisfied_at_ms: u64) -> Result<()> {
        let window = self
            .sla_windows
            .get_mut(window_id_ref)
            .ok_or_else(|| format!("sla window {window_id_ref} not found"))?;
        let observed = satisfied_at_ms.saturating_sub(window.opened_at_ms);
        window.satisfied_at_ms = Some(satisfied_at_ms);
        window.observed_latency_ms = Some(observed);
        if satisfied_at_ms <= window.soft_deadline_ms {
            window.status = SlaWindowStatus::Satisfied;
            window.penalty_bps = 0;
        } else if satisfied_at_ms <= window.hard_deadline_ms {
            window.status = SlaWindowStatus::SoftBreached;
            window.penalty_bps = 1_000;
        } else {
            window.status = SlaWindowStatus::HardBreached;
            window.penalty_bps = 5_000;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn mark_proof_cache_hint_used(&mut self, hint_id_ref: &str) -> Result<()> {
        let hint = self
            .proof_cache_hints
            .get_mut(hint_id_ref)
            .ok_or_else(|| format!("proof cache hint {hint_id_ref} not found"))?;
        hint.status = ProofCacheHintStatus::RebateEligible;
        self.refresh_roots();
        Ok(())
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_liquidity_preconfirmation_lane_runtime",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "rebate_asset_id": self.config.rebate_asset_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "intent_envelope_scheme": self.config.intent_envelope_scheme,
            "preconfirmation_committee_scheme": self.config.preconfirmation_committee_scheme,
            "microbatch_receipt_scheme": self.config.microbatch_receipt_scheme,
            "solver_commitment_scheme": self.config.solver_commitment_scheme,
            "latency_sla_window_scheme": self.config.latency_sla_window_scheme,
            "proof_cache_hint_scheme": self.config.proof_cache_hint_scheme,
            "low_fee_rebate_scheme": self.config.low_fee_rebate_scheme,
            "privacy_fence_scheme": self.config.privacy_fence_scheme,
            "slashing_evidence_scheme": self.config.slashing_evidence_scheme,
            "counters": self.counters,
            "roots": {
                "lanes_root": self.roots.lanes_root,
                "intents_root": self.roots.intents_root,
                "committees_root": self.roots.committees_root,
                "receipts_root": self.roots.receipts_root,
                "solver_commitments_root": self.roots.solver_commitments_root,
                "sla_windows_root": self.roots.sla_windows_root,
                "proof_cache_hints_root": self.roots.proof_cache_hints_root,
                "rebates_root": self.roots.rebates_root,
                "privacy_fences_root": self.roots.privacy_fences_root,
                "slashing_evidence_root": self.roots.slashing_evidence_root,
                "events_root": self.roots.events_root,
            },
            "lane_ids": self.lanes.keys().collect::<Vec<_>>(),
            "intent_ids": self.intents.keys().collect::<Vec<_>>(),
            "committee_ids": self.committees.keys().collect::<Vec<_>>(),
            "receipt_ids": self.receipts.keys().collect::<Vec<_>>(),
            "solver_commitment_ids": self.solver_commitments.keys().collect::<Vec<_>>(),
            "sla_window_ids": self.sla_windows.keys().collect::<Vec<_>>(),
            "proof_cache_hint_ids": self.proof_cache_hints.keys().collect::<Vec<_>>(),
            "rebate_ids": self.rebates.keys().collect::<Vec<_>>(),
            "privacy_fence_ids": self.privacy_fences.keys().collect::<Vec<_>>(),
            "slashing_evidence_ids": self.slashing_evidence.keys().collect::<Vec<_>>(),
            "event_ids": self.events.keys().collect::<Vec<_>>(),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.roots.lanes_root = map_root("lanes", &self.lanes);
        self.roots.intents_root = map_root("intents", &self.intents);
        self.roots.committees_root = map_root("committees", &self.committees);
        self.roots.receipts_root = map_root("receipts", &self.receipts);
        self.roots.solver_commitments_root =
            map_root("solver-commitments", &self.solver_commitments);
        self.roots.sla_windows_root = map_root("sla-windows", &self.sla_windows);
        self.roots.proof_cache_hints_root = map_root("proof-cache-hints", &self.proof_cache_hints);
        self.roots.rebates_root = map_root("rebates", &self.rebates);
        self.roots.privacy_fences_root = map_root("privacy-fences", &self.privacy_fences);
        self.roots.slashing_evidence_root = map_root("slashing-evidence", &self.slashing_evidence);
        self.roots.events_root = map_root("events", &self.events);
        self.roots.state_root = state_root_from_public_record(&self.public_record_without_state());
    }

    fn public_record_without_state(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_liquidity_preconfirmation_lane_runtime",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "counters": self.counters,
            "roots": {
                "lanes_root": self.roots.lanes_root,
                "intents_root": self.roots.intents_root,
                "committees_root": self.roots.committees_root,
                "receipts_root": self.roots.receipts_root,
                "solver_commitments_root": self.roots.solver_commitments_root,
                "sla_windows_root": self.roots.sla_windows_root,
                "proof_cache_hints_root": self.roots.proof_cache_hints_root,
                "rebates_root": self.roots.rebates_root,
                "privacy_fences_root": self.roots.privacy_fences_root,
                "slashing_evidence_root": self.roots.slashing_evidence_root,
                "events_root": self.roots.events_root,
            }
        })
    }

    fn require_lane(&self, lane_id_ref: &str) -> Result<&LiquidityLane> {
        self.lanes
            .get(lane_id_ref)
            .ok_or_else(|| format!("lane {lane_id_ref} not found"))
    }

    fn require_intent(
        &self,
        intent_id_ref: &str,
        expected_lane_id: &str,
    ) -> Result<&EncryptedLiquidityIntent> {
        let intent = self
            .intents
            .get(intent_id_ref)
            .ok_or_else(|| format!("intent {intent_id_ref} not found"))?;
        ensure_eq("intent lane", &intent.lane_id, expected_lane_id)?;
        Ok(intent)
    }

    fn push_event(&mut self, kind: EventKind, subject_id: &str, height: u64) -> Result<()> {
        ensure_capacity("events", self.events.len(), self.config.max_events)?;
        let index = self.counters.event_count;
        let event_id = event_id(kind, subject_id, height, index);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            height,
            index,
            event_root: public_subject_root(kind.as_str(), subject_id),
        };
        self.events.insert(event_id, event);
        self.counters.event_count = self.events.len() as u64;
        Ok(())
    }
}

pub fn lane_id(
    operator_commitment: &str,
    liquidity_pool_commitment: &str,
    pq_verifying_key_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:lane-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(liquidity_pool_commitment),
            HashPart::Str(pq_verifying_key_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn intent_id(
    lane_id: &str,
    account_commitment: &str,
    encrypted_envelope_root: &str,
    liquidity_nullifier: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:intent-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(account_commitment),
            HashPart::Str(encrypted_envelope_root),
            HashPart::Str(liquidity_nullifier),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn committee_id(
    lane_id: &str,
    epoch: u64,
    member_commitments_root: &str,
    aggregate_pq_key_root: &str,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:committee-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::U64(epoch),
            HashPart::Str(member_commitments_root),
            HashPart::Str(aggregate_pq_key_root),
        ],
        32,
    )
}

pub fn solver_commitment_id(
    lane_id: &str,
    intent_id: &str,
    solver_commitment: &str,
    inventory_commitment_root: &str,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:solver-commitment-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(intent_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(inventory_commitment_root),
        ],
        32,
    )
}

pub fn sla_window_id(
    lane_id: &str,
    intent_id: &str,
    committee_id: &str,
    opened_at_ms: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:sla-window-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(intent_id),
            HashPart::Str(committee_id),
            HashPart::U64(opened_at_ms),
        ],
        32,
    )
}

pub fn proof_cache_hint_id(lane_id: &str, intent_id: &str, cache_key_root: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:proof-cache-hint-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(intent_id),
            HashPart::Str(cache_key_root),
        ],
        32,
    )
}

pub fn microbatch_id(
    lane_id: &str,
    committee_id: &str,
    intent_root: &str,
    height: u64,
    published_at_ms: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:microbatch-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(committee_id),
            HashPart::Str(intent_root),
            HashPart::U64(height),
            HashPart::U64(published_at_ms),
        ],
        32,
    )
}

pub fn receipt_id(
    lane_id: &str,
    microbatch_id: &str,
    intent_root: &str,
    fill_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(microbatch_id),
            HashPart::Str(intent_root),
            HashPart::Str(fill_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, intent_id: &str, beneficiary_commitment: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(intent_id),
            HashPart::Str(beneficiary_commitment),
        ],
        32,
    )
}

pub fn privacy_fence_id(lane_id: &str, subject_id: &str, nullifier_or_seed: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:privacy-fence-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_or_seed),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    lane_id: &str,
    subject_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:slashing-evidence-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn event_id(kind: EventKind, subject_id: &str, height: u64, index: u64) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:event-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::U64(index),
        ],
        32,
    )
}

pub fn public_subject_root(domain: &str, subject_id: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:public-subject-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(subject_id),
        ],
        32,
    )
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:state-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-liquidity-preconfirmation:public-record-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn devnet_state_root() -> Result<String> {
    Ok(State::devnet()?.roots.state_root)
}

pub fn devnet_public_record() -> Result<Value> {
    State::devnet_public_record()
}

fn empty_root(name: &str) -> String {
    merkle_root(
        &format!("private-l2-fast-pq-confidential-liquidity-preconfirmation:{name}"),
        &Vec::<Value>::new(),
    )
}

fn map_root<T: Serialize>(name: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-liquidity-preconfirmation:{name}"),
        &leaves,
    )
}

fn list_root(name: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .enumerate()
        .map(|(index, value)| json!({ "index": index, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-liquidity-preconfirmation:{name}"),
        &leaves,
    )
}

fn compute_rebate(
    fee_charged_micro_units: u64,
    target_rebate_bps: u64,
    cache_hint_count: u64,
    cache_hint_rebate_bps: u64,
) -> u64 {
    mul_bps(fee_charged_micro_units, target_rebate_bps).saturating_add(
        mul_bps(fee_charged_micro_units, cache_hint_rebate_bps).saturating_mul(cache_hint_count),
    )
}

fn mul_bps(value: u64, bps: u64) -> u64 {
    value.saturating_mul(bps) / MAX_BPS
}

fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_eq(label: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ))
    } else {
        Ok(())
    }
}
