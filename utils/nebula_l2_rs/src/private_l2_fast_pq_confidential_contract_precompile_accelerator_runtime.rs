use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialContractPrecompileAcceleratorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_CONTRACT_PRECOMPILE_ACCELERATOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-contract-precompile-accelerator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_CONTRACT_PRECOMPILE_ACCELERATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-precompile-accelerator-v1";
pub const ENCRYPTED_CALL_ENVELOPE_SCHEME: &str =
    "ml-kem-sealed-confidential-contract-precompile-call-envelope-v1";
pub const ACCELERATOR_COMMITTEE_ATTESTATION_SCHEME: &str =
    "pq-confidential-precompile-accelerator-committee-attestation-root-v1";
pub const WARM_PRECOMPILE_SLOT_SCHEME: &str =
    "low-latency-private-contract-warm-precompile-slot-root-v1";
pub const BATCHED_EXECUTION_RECEIPT_SCHEME: &str =
    "batched-confidential-precompile-execution-receipt-root-v1";
pub const PROOF_CACHE_HIT_SCHEME: &str = "pq-confidential-precompile-proof-cache-hit-root-v1";
pub const FEE_REBATE_SCHEME: &str = "low-fee-confidential-precompile-accelerator-rebate-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str =
    "monero-private-l2-confidential-precompile-nullifier-fence-root-v1";
pub const LATENCY_SLA_CHALLENGE_SCHEME: &str =
    "pq-confidential-precompile-latency-sla-challenge-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-confidential-precompile-accelerator-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_790_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_CALL_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 11;
pub const DEFAULT_CACHE_HIT_REBATE_BPS: u64 = 7;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_750;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_CALL_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 6;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 900;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 350;
pub const DEFAULT_MIN_ACCELERATOR_BOND: u64 = 2_500_000;
pub const DEFAULT_MAX_LANES: usize = 262_144;
pub const DEFAULT_MAX_SLOTS: usize = 4_194_304;
pub const DEFAULT_MAX_CALLS: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_CACHE_HITS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 8_388_608;
pub const DEFAULT_MAX_CHALLENGES: usize = 2_097_152;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecompileClass {
    PqSignatureVerify,
    PqKemOpen,
    RangeProofVerify,
    MembershipProofVerify,
    RecursiveProofVerify,
    MoneroViewTagScan,
    MoneroKeyImageCheck,
    ConfidentialSwapMath,
    ConfidentialCreditMath,
    ContractStateDiffVerify,
}

impl PrecompileClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignatureVerify => "pq_signature_verify",
            Self::PqKemOpen => "pq_kem_open",
            Self::RangeProofVerify => "range_proof_verify",
            Self::MembershipProofVerify => "membership_proof_verify",
            Self::RecursiveProofVerify => "recursive_proof_verify",
            Self::MoneroViewTagScan => "monero_view_tag_scan",
            Self::MoneroKeyImageCheck => "monero_key_image_check",
            Self::ConfidentialSwapMath => "confidential_swap_math",
            Self::ConfidentialCreditMath => "confidential_credit_math",
            Self::ContractStateDiffVerify => "contract_state_diff_verify",
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::RecursiveProofVerify => 1_000,
            Self::ContractStateDiffVerify => 940,
            Self::RangeProofVerify => 900,
            Self::MembershipProofVerify => 880,
            Self::PqSignatureVerify => 820,
            Self::PqKemOpen => 780,
            Self::MoneroKeyImageCheck => 740,
            Self::MoneroViewTagScan => 700,
            Self::ConfidentialSwapMath => 660,
            Self::ConfidentialCreditMath => 620,
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
    pub fn accepts_calls(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::Saturated)
    }

    pub fn slashable(self) -> bool {
        !matches!(self, Self::Slashed | Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmSlotStatus {
    Reserved,
    Bound,
    Executing,
    ReceiptPublished,
    RebateQueued,
    Released,
    Expired,
    Challenged,
    Slashed,
}

impl WarmSlotStatus {
    pub fn reservable_successor(self) -> bool {
        matches!(self, Self::Reserved | Self::Bound)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Submitted,
    SlotBound,
    CommitteeAttested,
    Executed,
    ReceiptPublished,
    RebateSettled,
    Expired,
    Challenged,
    Slashed,
    Rejected,
}

impl CallStatus {
    pub fn awaiting_execution(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::SlotBound | Self::CommitteeAttested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accepted,
    WeakQuorum,
    StrongQuorum,
    WrongResult,
    LatencyBreach,
    PrivacyBreach,
    Rejected,
}

impl AttestationVerdict {
    pub fn favorable(self) -> bool {
        matches!(self, Self::Accepted | Self::WeakQuorum | Self::StrongQuorum)
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
pub enum CacheHitStatus {
    Claimed,
    Attested,
    Applied,
    Rejected,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimable,
    Settled,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceStatus {
    Open,
    Spent,
    Quarantined,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    LatencySla,
    WrongResult,
    MissingReceipt,
    BadCacheHit,
    PrivacyFenceLeak,
    CommitteeEquivocation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencySla => "latency_sla",
            Self::WrongResult => "wrong_result",
            Self::MissingReceipt => "missing_receipt",
            Self::BadCacheHit => "bad_cache_hit",
            Self::PrivacyFenceLeak => "privacy_fence_leak",
            Self::CommitteeEquivocation => "committee_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    UnderReview,
    Upheld,
    Rejected,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    LatencySlaBreach,
    WrongResult,
    InvalidAttestation,
    PrivacyFenceLeak,
    DuplicateReceipt,
    CacheFraud,
    BondExhausted,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencySlaBreach => "latency_sla_breach",
            Self::WrongResult => "wrong_result",
            Self::InvalidAttestation => "invalid_attestation",
            Self::PrivacyFenceLeak => "privacy_fence_leak",
            Self::DuplicateReceipt => "duplicate_receipt",
            Self::CacheFraud => "cache_fraud",
            Self::BondExhausted => "bond_exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    LaneRegistered,
    WarmSlotReserved,
    EncryptedCallSubmitted,
    ExecutionAttested,
    ReceiptPublished,
    ProofCacheHitRecorded,
    RebateSettled,
    PrivacyFenceOpened,
    ChallengeFiled,
    AcceleratorSlashed,
    RuntimeRootPublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LaneRegistered => "lane_registered",
            Self::WarmSlotReserved => "warm_slot_reserved",
            Self::EncryptedCallSubmitted => "encrypted_call_submitted",
            Self::ExecutionAttested => "execution_attested",
            Self::ReceiptPublished => "receipt_published",
            Self::ProofCacheHitRecorded => "proof_cache_hit_recorded",
            Self::RebateSettled => "rebate_settled",
            Self::PrivacyFenceOpened => "privacy_fence_opened",
            Self::ChallengeFiled => "challenge_filed",
            Self::AcceleratorSlashed => "accelerator_slashed",
            Self::RuntimeRootPublished => "runtime_root_published",
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
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub encrypted_call_envelope_scheme: String,
    pub committee_attestation_scheme: String,
    pub warm_slot_scheme: String,
    pub receipt_scheme: String,
    pub proof_cache_hit_scheme: String,
    pub fee_rebate_scheme: String,
    pub privacy_fence_scheme: String,
    pub challenge_scheme: String,
    pub slashing_evidence_scheme: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub committee_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_call_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub cache_hit_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub slot_ttl_blocks: u64,
    pub call_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_latency_ms: u64,
    pub soft_latency_ms: u64,
    pub min_accelerator_bond: u64,
    pub max_lanes: usize,
    pub max_slots: usize,
    pub max_calls: usize,
    pub max_attestations: usize,
    pub max_receipts: usize,
    pub max_cache_hits: usize,
    pub max_rebates: usize,
    pub max_fences: usize,
    pub max_challenges: usize,
    pub max_slashing_evidence: usize,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            encrypted_call_envelope_scheme: ENCRYPTED_CALL_ENVELOPE_SCHEME.to_string(),
            committee_attestation_scheme: ACCELERATOR_COMMITTEE_ATTESTATION_SCHEME.to_string(),
            warm_slot_scheme: WARM_PRECOMPILE_SLOT_SCHEME.to_string(),
            receipt_scheme: BATCHED_EXECUTION_RECEIPT_SCHEME.to_string(),
            proof_cache_hit_scheme: PROOF_CACHE_HIT_SCHEME.to_string(),
            fee_rebate_scheme: FEE_REBATE_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            challenge_scheme: LATENCY_SLA_CHALLENGE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_call_fee_bps: DEFAULT_MAX_CALL_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            cache_hit_rebate_bps: DEFAULT_CACHE_HIT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            call_ttl_blocks: DEFAULT_CALL_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            min_accelerator_bond: DEFAULT_MIN_ACCELERATOR_BOND,
            max_lanes: DEFAULT_MAX_LANES,
            max_slots: DEFAULT_MAX_SLOTS,
            max_calls: DEFAULT_MAX_CALLS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_cache_hits: DEFAULT_MAX_CACHE_HITS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_fences: DEFAULT_MAX_FENCES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            devnet_height: DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        ensure_eq("hash_suite", &self.hash_suite, HASH_SUITE)?;
        ensure_eq("pq_auth_suite", &self.pq_auth_suite, PQ_AUTH_SUITE)?;
        ensure_bps("committee_quorum_bps", self.committee_quorum_bps)?;
        ensure_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        ensure_bps("max_call_fee_bps", self.max_call_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("cache_hit_rebate_bps", self.cache_hit_rebate_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.strong_quorum_bps < self.committee_quorum_bps {
            return Err("strong quorum must be >= committee quorum".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below devnet floor".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("invalid privacy set sizing".to_string());
        }
        if self.soft_latency_ms > self.max_latency_ms {
            return Err("soft latency cannot exceed max latency".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub slots_reserved: u64,
    pub encrypted_calls_submitted: u64,
    pub execution_attestations: u64,
    pub receipts_published: u64,
    pub cache_hits_recorded: u64,
    pub rebates_settled: u64,
    pub privacy_fences_opened: u64,
    pub latency_challenges: u64,
    pub wrong_result_challenges: u64,
    pub slashing_events: u64,
    pub total_fee_charged: u64,
    pub total_fee_rebated: u64,
    pub total_bond_slashed: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lanes_root: String,
    pub slots_root: String,
    pub encrypted_calls_root: String,
    pub attestations_root: String,
    pub receipts_root: String,
    pub cache_hits_root: String,
    pub rebates_root: String,
    pub privacy_fences_root: String,
    pub challenges_root: String,
    pub slashing_evidence_root: String,
    pub events_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceleratorLane {
    pub lane_id: String,
    pub operator_id: String,
    pub committee_id: String,
    pub precompile_class: PrecompileClass,
    pub status: LaneStatus,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub max_parallel_slots: u64,
    pub reserved_slots: u64,
    pub active_calls: u64,
    pub bond_micro_units: u64,
    pub slashed_micro_units: u64,
    pub fee_cap_bps: u64,
    pub latency_sla_ms: u64,
    pub registered_height: u64,
    pub last_attested_height: u64,
    pub metadata_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WarmPrecompileSlot {
    pub slot_id: String,
    pub lane_id: String,
    pub reserver_id: String,
    pub precompile_class: PrecompileClass,
    pub status: WarmSlotStatus,
    pub reservation_height: u64,
    pub expires_height: u64,
    pub max_calls: u64,
    pub bound_call_ids: BTreeSet<String>,
    pub priority_fee_micro_units: u64,
    pub privacy_fence_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCallEnvelope {
    pub call_id: String,
    pub lane_id: String,
    pub slot_id: Option<String>,
    pub caller_commitment: String,
    pub contract_commitment: String,
    pub precompile_class: PrecompileClass,
    pub encrypted_payload_root: String,
    pub calldata_ciphertext_hash: String,
    pub access_list_root: String,
    pub nullifier: String,
    pub fee_commitment: String,
    pub max_fee_micro_units: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: CallStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub call_id: String,
    pub committee_id: String,
    pub verdict: AttestationVerdict,
    pub attested_output_root: String,
    pub execution_trace_root: String,
    pub signer_bitmap_root: String,
    pub quorum_bps: u64,
    pub latency_ms: u64,
    pub cache_hit_id: Option<String>,
    pub attested_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchedExecutionReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub batch_id: String,
    pub call_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub status: ReceiptStatus,
    pub output_root: String,
    pub state_diff_root: String,
    pub gas_used_micro_units: u64,
    pub fee_charged_micro_units: u64,
    pub rebate_micro_units: u64,
    pub cache_hit_count: u64,
    pub published_height: u64,
    pub finalizes_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheHit {
    pub cache_hit_id: String,
    pub call_id: String,
    pub lane_id: String,
    pub precompile_class: PrecompileClass,
    pub proof_key_root: String,
    pub cached_output_root: String,
    pub witness_commitment: String,
    pub status: CacheHitStatus,
    pub discount_bps: u64,
    pub recorded_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub call_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub fee_charged_micro_units: u64,
    pub rebate_micro_units: u64,
    pub cache_hit_bonus_micro_units: u64,
    pub claimable_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub lane_id: String,
    pub call_id: String,
    pub nullifier: String,
    pub status: PrivacyFenceStatus,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub spent_height: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlaChallenge {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub lane_id: String,
    pub call_id: String,
    pub receipt_id: Option<String>,
    pub challenger_id: String,
    pub evidence_root: String,
    pub claimed_latency_ms: u64,
    pub expected_output_root: Option<String>,
    pub observed_output_root: Option<String>,
    pub status: ChallengeStatus,
    pub filed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub lane_id: String,
    pub challenge_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub slashed_micro_units: u64,
    pub remaining_bond_micro_units: u64,
    pub slashed_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub height: u64,
    pub root: String,
    pub public: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, AcceleratorLane>,
    pub slots: BTreeMap<String, WarmPrecompileSlot>,
    pub encrypted_calls: BTreeMap<String, EncryptedCallEnvelope>,
    pub attestations: BTreeMap<String, CommitteeAttestation>,
    pub receipts: BTreeMap<String, BatchedExecutionReceipt>,
    pub cache_hits: BTreeMap<String, ProofCacheHit>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub challenges: BTreeMap<String, SlaChallenge>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            slots: BTreeMap::new(),
            encrypted_calls: BTreeMap::new(),
            attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            cache_hits: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet())?;
        let lane_id = state.register_accelerator_lane(
            "devnet-accelerator-committee-a",
            "devnet-operator-fast-pq-a",
            PrecompileClass::RecursiveProofVerify,
            256,
            DEFAULT_BATCH_PRIVACY_SET_SIZE,
            128,
            9,
            DEFAULT_MAX_LATENCY_MS,
            DEFAULT_MIN_ACCELERATOR_BOND * 4,
            "devnet-recursive-proof-accelerator-manifest",
            DEVNET_HEIGHT,
        )?;
        let slot_id = state.reserve_warm_slot(
            &lane_id,
            "devnet-private-contract-batcher",
            16,
            4_200,
            "devnet-slot-privacy-fence",
            DEVNET_HEIGHT + 1,
        )?;
        let call_id = state.submit_encrypted_call(
            &lane_id,
            Some(&slot_id),
            "devnet-caller-commitment",
            "devnet-contract-commitment",
            PrecompileClass::RecursiveProofVerify,
            "devnet-encrypted-payload-root",
            "devnet-ciphertext-hash",
            "devnet-access-list-root",
            "devnet-nullifier-001",
            "devnet-fee-commitment",
            21_000,
            DEFAULT_BATCH_PRIVACY_SET_SIZE,
            256,
            DEVNET_HEIGHT + 2,
        )?;
        let cache_hit_id = state.record_proof_cache_hit(
            &lane_id,
            &call_id,
            PrecompileClass::RecursiveProofVerify,
            "devnet-proof-key-root",
            "devnet-cached-output-root",
            "devnet-witness-commitment",
            3_000,
            DEVNET_HEIGHT + 3,
        )?;
        let attestation_id = state.attest_execution(
            &lane_id,
            &call_id,
            AttestationVerdict::StrongQuorum,
            "devnet-output-root",
            "devnet-trace-root",
            "devnet-signer-bitmap-root",
            8_100,
            240,
            Some(&cache_hit_id),
            DEVNET_HEIGHT + 3,
        )?;
        let mut calls = BTreeSet::new();
        calls.insert(call_id.clone());
        let mut attestations = BTreeSet::new();
        attestations.insert(attestation_id);
        let receipt_id = state.publish_receipt(
            &lane_id,
            "devnet-batch-001",
            calls,
            attestations,
            "devnet-output-root",
            "devnet-state-diff-root",
            13_000,
            18_000,
            DEVNET_HEIGHT + 4,
        )?;
        state.settle_rebate(
            &receipt_id,
            &call_id,
            "devnet-caller-commitment",
            DEVNET_HEIGHT + 5,
        )?;
        Ok(state)
    }

    pub fn register_accelerator_lane(
        &mut self,
        committee_id: &str,
        operator_id: &str,
        precompile_class: PrecompileClass,
        pq_security_bits: u16,
        privacy_set_size: u64,
        max_parallel_slots: u64,
        fee_cap_bps: u64,
        latency_sla_ms: u64,
        bond_micro_units: u64,
        metadata_commitment: &str,
        height: u64,
    ) -> Result<String> {
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_nonempty("committee_id", committee_id)?;
        ensure_nonempty("operator_id", operator_id)?;
        ensure_nonempty("metadata_commitment", metadata_commitment)?;
        ensure_bps("fee_cap_bps", fee_cap_bps)?;
        if fee_cap_bps > self.config.max_call_fee_bps {
            return Err("lane fee cap exceeds runtime fee cap".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("lane pq security below runtime floor".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("lane privacy set below runtime floor".to_string());
        }
        if max_parallel_slots == 0 {
            return Err("max_parallel_slots must be positive".to_string());
        }
        if latency_sla_ms == 0 || latency_sla_ms > self.config.max_latency_ms {
            return Err("latency_sla_ms outside runtime bounds".to_string());
        }
        if bond_micro_units < self.config.min_accelerator_bond {
            return Err("accelerator bond below runtime minimum".to_string());
        }
        let lane_id = lane_id(
            committee_id,
            operator_id,
            precompile_class,
            metadata_commitment,
            height,
        );
        if self.lanes.contains_key(&lane_id) {
            return Err("accelerator lane already registered".to_string());
        }
        let lane = AcceleratorLane {
            lane_id: lane_id.clone(),
            operator_id: operator_id.to_string(),
            committee_id: committee_id.to_string(),
            precompile_class,
            status: LaneStatus::Registered,
            pq_security_bits,
            privacy_set_size,
            max_parallel_slots,
            reserved_slots: 0,
            active_calls: 0,
            bond_micro_units,
            slashed_micro_units: 0,
            fee_cap_bps,
            latency_sla_ms,
            registered_height: height,
            last_attested_height: height,
            metadata_commitment: metadata_commitment.to_string(),
        };
        self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_registered += 1;
        self.push_event(EventKind::LaneRegistered, &lane_id, height)?;
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn reserve_warm_slot(
        &mut self,
        lane_id: &str,
        reserver_id: &str,
        max_calls: u64,
        priority_fee_micro_units: u64,
        privacy_fence_seed: &str,
        height: u64,
    ) -> Result<String> {
        ensure_capacity("slots", self.slots.len(), self.config.max_slots)?;
        ensure_nonempty("reserver_id", reserver_id)?;
        ensure_nonempty("privacy_fence_seed", privacy_fence_seed)?;
        if max_calls == 0 {
            return Err("warm slot max_calls must be positive".to_string());
        }
        let lane = self.require_lane_mut(lane_id)?;
        if !lane.status.accepts_calls() {
            return Err("lane does not accept warm slots".to_string());
        }
        if lane.reserved_slots >= lane.max_parallel_slots {
            lane.status = LaneStatus::Saturated;
            return Err("lane slot capacity saturated".to_string());
        }
        lane.reserved_slots += 1;
        if lane.status == LaneStatus::Registered {
            lane.status = LaneStatus::Active;
        }
        let precompile_class = lane.precompile_class;
        let slot_id = warm_slot_id(lane_id, reserver_id, privacy_fence_seed, height);
        if self.slots.contains_key(&slot_id) {
            return Err("warm slot already reserved".to_string());
        }
        let fence_id = privacy_fence_id(lane_id, &slot_id, privacy_fence_seed);
        let slot = WarmPrecompileSlot {
            slot_id: slot_id.clone(),
            lane_id: lane_id.to_string(),
            reserver_id: reserver_id.to_string(),
            precompile_class,
            status: WarmSlotStatus::Reserved,
            reservation_height: height,
            expires_height: height + self.config.slot_ttl_blocks,
            max_calls,
            bound_call_ids: BTreeSet::new(),
            priority_fee_micro_units,
            privacy_fence_id: fence_id,
        };
        self.slots.insert(slot_id.clone(), slot);
        self.counters.slots_reserved += 1;
        self.push_event(EventKind::WarmSlotReserved, &slot_id, height)?;
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn submit_encrypted_call(
        &mut self,
        lane_id: &str,
        slot_id: Option<&str>,
        caller_commitment: &str,
        contract_commitment: &str,
        precompile_class: PrecompileClass,
        encrypted_payload_root: &str,
        calldata_ciphertext_hash: &str,
        access_list_root: &str,
        nullifier: &str,
        fee_commitment: &str,
        max_fee_micro_units: u64,
        privacy_set_size: u64,
        pq_security_bits: u16,
        height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "encrypted_calls",
            self.encrypted_calls.len(),
            self.config.max_calls,
        )?;
        ensure_nonempty("caller_commitment", caller_commitment)?;
        ensure_nonempty("contract_commitment", contract_commitment)?;
        ensure_nonempty("encrypted_payload_root", encrypted_payload_root)?;
        ensure_nonempty("calldata_ciphertext_hash", calldata_ciphertext_hash)?;
        ensure_nonempty("access_list_root", access_list_root)?;
        ensure_nonempty("nullifier", nullifier)?;
        ensure_nonempty("fee_commitment", fee_commitment)?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("call privacy set below runtime floor".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("call pq security below runtime floor".to_string());
        }
        let lane = self.require_lane(lane_id)?;
        if !lane.status.accepts_calls() {
            return Err("lane does not accept encrypted calls".to_string());
        }
        if lane.precompile_class != precompile_class {
            return Err("call precompile class does not match lane".to_string());
        }
        let call_id = encrypted_call_id(
            lane_id,
            caller_commitment,
            contract_commitment,
            encrypted_payload_root,
            nullifier,
            height,
        );
        if self.encrypted_calls.contains_key(&call_id) {
            return Err("encrypted call already submitted".to_string());
        }
        if self.privacy_fences.values().any(|fence| {
            fence.nullifier == nullifier && fence.status != PrivacyFenceStatus::Tombstoned
        }) {
            return Err("privacy fence nullifier already opened".to_string());
        }
        let mut status = CallStatus::Submitted;
        if let Some(slot_id) = slot_id {
            let slot = self
                .slots
                .get_mut(slot_id)
                .ok_or_else(|| "warm slot not found".to_string())?;
            if slot.lane_id != lane_id {
                return Err("warm slot lane mismatch".to_string());
            }
            if !slot.status.reservable_successor() {
                return Err("warm slot cannot bind call".to_string());
            }
            if height > slot.expires_height {
                slot.status = WarmSlotStatus::Expired;
                return Err("warm slot expired".to_string());
            }
            if slot.bound_call_ids.len() as u64 >= slot.max_calls {
                return Err("warm slot call capacity exhausted".to_string());
            }
            slot.bound_call_ids.insert(call_id.clone());
            slot.status = WarmSlotStatus::Bound;
            status = CallStatus::SlotBound;
        }
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.active_calls += 1;
        }
        let call = EncryptedCallEnvelope {
            call_id: call_id.clone(),
            lane_id: lane_id.to_string(),
            slot_id: slot_id.map(str::to_string),
            caller_commitment: caller_commitment.to_string(),
            contract_commitment: contract_commitment.to_string(),
            precompile_class,
            encrypted_payload_root: encrypted_payload_root.to_string(),
            calldata_ciphertext_hash: calldata_ciphertext_hash.to_string(),
            access_list_root: access_list_root.to_string(),
            nullifier: nullifier.to_string(),
            fee_commitment: fee_commitment.to_string(),
            max_fee_micro_units,
            submitted_height: height,
            expires_height: height + self.config.call_ttl_blocks,
            privacy_set_size,
            pq_security_bits,
            status,
        };
        let fence_id = privacy_fence_id(lane_id, &call_id, nullifier);
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            lane_id: lane_id.to_string(),
            call_id: call_id.clone(),
            nullifier: nullifier.to_string(),
            status: PrivacyFenceStatus::Open,
            privacy_set_size,
            opened_height: height,
            spent_height: None,
        };
        self.encrypted_calls.insert(call_id.clone(), call);
        self.privacy_fences.insert(fence_id, fence);
        self.counters.encrypted_calls_submitted += 1;
        self.counters.privacy_fences_opened += 1;
        self.push_event(EventKind::PrivacyFenceOpened, &call_id, height)?;
        self.push_event(EventKind::EncryptedCallSubmitted, &call_id, height)?;
        self.refresh_roots();
        Ok(call_id)
    }

    pub fn record_proof_cache_hit(
        &mut self,
        lane_id: &str,
        call_id: &str,
        precompile_class: PrecompileClass,
        proof_key_root: &str,
        cached_output_root: &str,
        witness_commitment: &str,
        discount_bps: u64,
        height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "cache_hits",
            self.cache_hits.len(),
            self.config.max_cache_hits,
        )?;
        ensure_bps("discount_bps", discount_bps)?;
        ensure_nonempty("proof_key_root", proof_key_root)?;
        ensure_nonempty("cached_output_root", cached_output_root)?;
        ensure_nonempty("witness_commitment", witness_commitment)?;
        self.require_lane(lane_id)?;
        let call = self.require_call(call_id)?;
        if call.lane_id != lane_id {
            return Err("cache hit lane mismatch".to_string());
        }
        if call.precompile_class != precompile_class {
            return Err("cache hit precompile class mismatch".to_string());
        }
        if !call.status.awaiting_execution() {
            return Err("call no longer accepts proof cache hits".to_string());
        }
        let cache_hit_id = proof_cache_hit_id(lane_id, call_id, proof_key_root, cached_output_root);
        if self.cache_hits.contains_key(&cache_hit_id) {
            return Err("proof cache hit already recorded".to_string());
        }
        let hit = ProofCacheHit {
            cache_hit_id: cache_hit_id.clone(),
            call_id: call_id.to_string(),
            lane_id: lane_id.to_string(),
            precompile_class,
            proof_key_root: proof_key_root.to_string(),
            cached_output_root: cached_output_root.to_string(),
            witness_commitment: witness_commitment.to_string(),
            status: CacheHitStatus::Claimed,
            discount_bps,
            recorded_height: height,
        };
        self.cache_hits.insert(cache_hit_id.clone(), hit);
        self.counters.cache_hits_recorded += 1;
        self.push_event(EventKind::ProofCacheHitRecorded, &cache_hit_id, height)?;
        self.refresh_roots();
        Ok(cache_hit_id)
    }

    pub fn attest_execution(
        &mut self,
        lane_id: &str,
        call_id: &str,
        verdict: AttestationVerdict,
        attested_output_root: &str,
        execution_trace_root: &str,
        signer_bitmap_root: &str,
        quorum_bps: u64,
        latency_ms: u64,
        cache_hit_id: Option<&str>,
        height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_bps("quorum_bps", quorum_bps)?;
        ensure_nonempty("attested_output_root", attested_output_root)?;
        ensure_nonempty("execution_trace_root", execution_trace_root)?;
        ensure_nonempty("signer_bitmap_root", signer_bitmap_root)?;
        let committee_id = {
            let lane = self.require_lane(lane_id)?;
            if quorum_bps < self.config.committee_quorum_bps {
                return Err("attestation quorum below runtime threshold".to_string());
            }
            if latency_ms > lane.latency_sla_ms && verdict.favorable() {
                return Err("favorable attestation exceeds lane latency sla".to_string());
            }
            lane.committee_id.clone()
        };
        {
            let call = self.require_call_mut(call_id)?;
            if call.lane_id != lane_id {
                return Err("attestation lane mismatch".to_string());
            }
            if height > call.expires_height {
                call.status = CallStatus::Expired;
                return Err("encrypted call expired".to_string());
            }
            if !call.status.awaiting_execution() {
                return Err("call cannot be attested in current status".to_string());
            }
        }
        if let Some(cache_hit_id) = cache_hit_id {
            let hit = self
                .cache_hits
                .get_mut(cache_hit_id)
                .ok_or_else(|| "proof cache hit not found".to_string())?;
            if hit.call_id != call_id || hit.lane_id != lane_id {
                return Err("proof cache hit mismatch".to_string());
            }
            hit.status = if verdict.favorable() {
                CacheHitStatus::Attested
            } else {
                CacheHitStatus::Rejected
            };
        }
        if let Some(call) = self.encrypted_calls.get_mut(call_id) {
            call.status = if verdict.favorable() {
                CallStatus::CommitteeAttested
            } else {
                CallStatus::Rejected
            };
        }
        let attestation_id = attestation_id(
            lane_id,
            call_id,
            attested_output_root,
            execution_trace_root,
            quorum_bps,
            height,
        );
        if self.attestations.contains_key(&attestation_id) {
            return Err("attestation already exists".to_string());
        }
        let attestation = CommitteeAttestation {
            attestation_id: attestation_id.clone(),
            lane_id: lane_id.to_string(),
            call_id: call_id.to_string(),
            committee_id,
            verdict,
            attested_output_root: attested_output_root.to_string(),
            execution_trace_root: execution_trace_root.to_string(),
            signer_bitmap_root: signer_bitmap_root.to_string(),
            quorum_bps,
            latency_ms,
            cache_hit_id: cache_hit_id.map(str::to_string),
            attested_height: height,
        };
        if let Some(lane) = self.lanes.get_mut(lane_id) {
            lane.last_attested_height = height;
        }
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.execution_attestations += 1;
        self.push_event(EventKind::ExecutionAttested, &attestation_id, height)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn publish_receipt(
        &mut self,
        lane_id: &str,
        batch_id: &str,
        call_ids: BTreeSet<String>,
        attestation_ids: BTreeSet<String>,
        output_root: &str,
        state_diff_root: &str,
        gas_used_micro_units: u64,
        fee_charged_micro_units: u64,
        height: u64,
    ) -> Result<String> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        ensure_nonempty("batch_id", batch_id)?;
        ensure_nonempty("output_root", output_root)?;
        ensure_nonempty("state_diff_root", state_diff_root)?;
        if call_ids.is_empty() || attestation_ids.is_empty() {
            return Err("receipt requires calls and attestations".to_string());
        }
        self.require_lane(lane_id)?;
        let mut cache_hit_count = 0_u64;
        for call_id in &call_ids {
            let call = self.require_call_mut(call_id)?;
            if call.lane_id != lane_id {
                return Err("receipt call lane mismatch".to_string());
            }
            if !matches!(call.status, CallStatus::CommitteeAttested) {
                return Err("receipt call is not committee attested".to_string());
            }
            call.status = CallStatus::ReceiptPublished;
            if let Some(slot_id) = call.slot_id.clone() {
                if let Some(slot) = self.slots.get_mut(&slot_id) {
                    slot.status = WarmSlotStatus::ReceiptPublished;
                }
            }
        }
        for attestation_id in &attestation_ids {
            let attestation = self
                .attestations
                .get(attestation_id)
                .ok_or_else(|| "receipt attestation missing".to_string())?;
            if attestation.lane_id != lane_id {
                return Err("receipt attestation lane mismatch".to_string());
            }
            if !attestation.verdict.favorable() {
                return Err("receipt cannot include unfavorable attestation".to_string());
            }
            if let Some(cache_hit_id) = &attestation.cache_hit_id {
                if let Some(hit) = self.cache_hits.get_mut(cache_hit_id) {
                    hit.status = CacheHitStatus::Applied;
                    cache_hit_count += 1;
                }
            }
        }
        let rebate_micro_units = compute_rebate(
            fee_charged_micro_units,
            self.config.target_rebate_bps,
            cache_hit_count,
            self.config.cache_hit_rebate_bps,
        );
        let receipt_id = receipt_id(lane_id, batch_id, output_root, state_diff_root, height);
        if self.receipts.contains_key(&receipt_id) {
            return Err("receipt already published".to_string());
        }
        let receipt = BatchedExecutionReceipt {
            receipt_id: receipt_id.clone(),
            lane_id: lane_id.to_string(),
            batch_id: batch_id.to_string(),
            call_ids,
            attestation_ids,
            status: ReceiptStatus::Published,
            output_root: output_root.to_string(),
            state_diff_root: state_diff_root.to_string(),
            gas_used_micro_units,
            fee_charged_micro_units,
            rebate_micro_units,
            cache_hit_count,
            published_height: height,
            finalizes_height: height + self.config.receipt_finality_blocks,
        };
        self.receipts.insert(receipt_id.clone(), receipt);
        self.counters.receipts_published += 1;
        self.counters.total_fee_charged += fee_charged_micro_units;
        self.push_event(EventKind::ReceiptPublished, &receipt_id, height)?;
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn settle_rebate(
        &mut self,
        receipt_id: &str,
        call_id: &str,
        beneficiary_commitment: &str,
        height: u64,
    ) -> Result<String> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        ensure_nonempty("beneficiary_commitment", beneficiary_commitment)?;
        let (receipt_call_count, receipt_fee_charged, receipt_rebate_micro_units) = {
            let receipt = self
                .receipts
                .get(receipt_id)
                .ok_or_else(|| "receipt not found".to_string())?;
            if !receipt.call_ids.contains(call_id) {
                return Err("rebate call not included in receipt".to_string());
            }
            if matches!(
                receipt.status,
                ReceiptStatus::Challenged | ReceiptStatus::Slashed
            ) {
                return Err("cannot settle rebate for challenged receipt".to_string());
            }
            (
                receipt.call_ids.len() as u64,
                receipt.fee_charged_micro_units,
                receipt.rebate_micro_units,
            )
        };
        let call = self.require_call_mut(call_id)?;
        if call.status != CallStatus::ReceiptPublished {
            return Err("call not ready for rebate settlement".to_string());
        }
        let base_rebate = receipt_rebate_micro_units / receipt_call_count;
        let cache_bonus = if self
            .cache_hits
            .values()
            .any(|hit| hit.call_id == call_id && hit.status == CacheHitStatus::Applied)
        {
            mul_bps(receipt_fee_charged, self.config.cache_hit_rebate_bps)
        } else {
            0
        };
        let rebate_id = rebate_id(receipt_id, call_id, beneficiary_commitment);
        if self.rebates.contains_key(&rebate_id) {
            return Err("rebate already settled".to_string());
        }
        let call = self.require_call_mut(call_id)?;
        call.status = CallStatus::RebateSettled;
        if let Some(receipt) = self.receipts.get_mut(receipt_id) {
            receipt.status = ReceiptStatus::RebateQueued;
        }
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            call_id: call_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            status: RebateStatus::Claimable,
            fee_charged_micro_units: receipt_fee_charged,
            rebate_micro_units: base_rebate,
            cache_hit_bonus_micro_units: cache_bonus,
            claimable_height: height,
            expires_height: height + self.config.rebate_ttl_blocks,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates_settled += 1;
        self.counters.total_fee_rebated += base_rebate + cache_bonus;
        self.push_event(EventKind::RebateSettled, &rebate_id, height)?;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn challenge_latency(
        &mut self,
        lane_id: &str,
        call_id: &str,
        receipt_id: Option<&str>,
        challenger_id: &str,
        evidence_root: &str,
        claimed_latency_ms: u64,
        height: u64,
    ) -> Result<String> {
        self.file_challenge(
            ChallengeKind::LatencySla,
            lane_id,
            call_id,
            receipt_id,
            challenger_id,
            evidence_root,
            claimed_latency_ms,
            None,
            None,
            height,
        )
    }

    pub fn challenge_wrong_result(
        &mut self,
        lane_id: &str,
        call_id: &str,
        receipt_id: &str,
        challenger_id: &str,
        evidence_root: &str,
        expected_output_root: &str,
        observed_output_root: &str,
        height: u64,
    ) -> Result<String> {
        self.file_challenge(
            ChallengeKind::WrongResult,
            lane_id,
            call_id,
            Some(receipt_id),
            challenger_id,
            evidence_root,
            0,
            Some(expected_output_root),
            Some(observed_output_root),
            height,
        )
    }

    pub fn file_challenge(
        &mut self,
        kind: ChallengeKind,
        lane_id: &str,
        call_id: &str,
        receipt_id: Option<&str>,
        challenger_id: &str,
        evidence_root: &str,
        claimed_latency_ms: u64,
        expected_output_root: Option<&str>,
        observed_output_root: Option<&str>,
        height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        ensure_nonempty("challenger_id", challenger_id)?;
        ensure_nonempty("evidence_root", evidence_root)?;
        let lane = self.require_lane(lane_id)?;
        if kind == ChallengeKind::LatencySla && claimed_latency_ms <= lane.latency_sla_ms {
            return Err("latency challenge does not exceed lane sla".to_string());
        }
        let call = self.require_call(call_id)?;
        if call.lane_id != lane_id {
            return Err("challenge call lane mismatch".to_string());
        }
        if kind == ChallengeKind::WrongResult {
            ensure_nonempty("expected_output_root", expected_output_root.unwrap_or(""))?;
            ensure_nonempty("observed_output_root", observed_output_root.unwrap_or(""))?;
            if expected_output_root == observed_output_root {
                return Err("wrong result challenge requires mismatched roots".to_string());
            }
        }
        if let Some(receipt_id) = receipt_id {
            let receipt = self
                .receipts
                .get(receipt_id)
                .ok_or_else(|| "challenge receipt missing".to_string())?;
            if receipt.lane_id != lane_id || !receipt.call_ids.contains(call_id) {
                return Err("challenge receipt mismatch".to_string());
            }
        }
        if let Some(receipt_id) = receipt_id {
            if let Some(receipt) = self.receipts.get_mut(receipt_id) {
                receipt.status = ReceiptStatus::Challenged;
            }
        }
        if let Some(call) = self.encrypted_calls.get_mut(call_id) {
            call.status = CallStatus::Challenged;
        }
        let challenge_id = challenge_id(kind, lane_id, call_id, evidence_root, height);
        if self.challenges.contains_key(&challenge_id) {
            return Err("challenge already filed".to_string());
        }
        let challenge = SlaChallenge {
            challenge_id: challenge_id.clone(),
            kind,
            lane_id: lane_id.to_string(),
            call_id: call_id.to_string(),
            receipt_id: receipt_id.map(str::to_string),
            challenger_id: challenger_id.to_string(),
            evidence_root: evidence_root.to_string(),
            claimed_latency_ms,
            expected_output_root: expected_output_root.map(str::to_string),
            observed_output_root: observed_output_root.map(str::to_string),
            status: ChallengeStatus::Filed,
            filed_height: height,
        };
        self.challenges.insert(challenge_id.clone(), challenge);
        match kind {
            ChallengeKind::LatencySla => self.counters.latency_challenges += 1,
            ChallengeKind::WrongResult => self.counters.wrong_result_challenges += 1,
            _ => {}
        }
        self.push_event(EventKind::ChallengeFiled, &challenge_id, height)?;
        self.refresh_roots();
        Ok(challenge_id)
    }

    pub fn slash_accelerator(
        &mut self,
        lane_id: &str,
        challenge_id: &str,
        reason: SlashingReason,
        evidence_root: &str,
        slash_bps: u64,
        height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        ensure_bps("slash_bps", slash_bps)?;
        ensure_nonempty("evidence_root", evidence_root)?;
        let challenge_lane = self
            .challenges
            .get(challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?
            .lane_id
            .clone();
        if challenge_lane != lane_id {
            return Err("slashing challenge lane mismatch".to_string());
        }
        let lane = self.require_lane_mut(lane_id)?;
        if !lane.status.slashable() {
            return Err("lane cannot be slashed".to_string());
        }
        let available = lane
            .bond_micro_units
            .saturating_sub(lane.slashed_micro_units);
        if available == 0 {
            lane.status = LaneStatus::Slashed;
            return Err("lane bond exhausted".to_string());
        }
        let slashed = mul_bps(available, slash_bps).max(1).min(available);
        lane.slashed_micro_units += slashed;
        if lane.slashed_micro_units >= lane.bond_micro_units {
            lane.status = LaneStatus::Slashed;
        } else {
            lane.status = LaneStatus::Paused;
        }
        let remaining_bond_micro_units = lane.bond_micro_units - lane.slashed_micro_units;
        if let Some(challenge) = self.challenges.get_mut(challenge_id) {
            challenge.status = ChallengeStatus::Slashed;
        }
        for call in self.encrypted_calls.values_mut() {
            if call.lane_id == lane_id && call.status == CallStatus::Challenged {
                call.status = CallStatus::Slashed;
            }
        }
        for slot in self.slots.values_mut() {
            if slot.lane_id == lane_id && slot.status == WarmSlotStatus::Challenged {
                slot.status = WarmSlotStatus::Slashed;
            }
        }
        let evidence_id =
            slashing_evidence_id(lane_id, challenge_id, reason, evidence_root, height);
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            lane_id: lane_id.to_string(),
            challenge_id: challenge_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            slashed_micro_units: slashed,
            remaining_bond_micro_units,
            slashed_height: height,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.counters.slashing_events += 1;
        self.counters.total_bond_slashed += slashed;
        self.push_event(EventKind::AcceleratorSlashed, &evidence_id, height)?;
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots_without_state(),
            "lane_count": self.lanes.len(),
            "slot_count": self.slots.len(),
            "encrypted_call_count": self.encrypted_calls.len(),
            "attestation_count": self.attestations.len(),
            "receipt_count": self.receipts.len(),
            "cache_hit_count": self.cache_hits.len(),
            "rebate_count": self.rebates.len(),
            "privacy_fence_count": self.privacy_fences.len(),
            "challenge_count": self.challenges.len(),
            "slashing_evidence_count": self.slashing_evidence.len(),
        })
    }

    pub fn devnet_public_record() -> Result<Value> {
        Ok(Self::devnet()?.public_record())
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            lanes_root: map_root("lanes", &self.lanes),
            slots_root: map_root("slots", &self.slots),
            encrypted_calls_root: map_root("encrypted-calls", &self.encrypted_calls),
            attestations_root: map_root("attestations", &self.attestations),
            receipts_root: map_root("receipts", &self.receipts),
            cache_hits_root: map_root("cache-hits", &self.cache_hits),
            rebates_root: map_root("rebates", &self.rebates),
            privacy_fences_root: map_root("privacy-fences", &self.privacy_fences),
            challenges_root: map_root("challenges", &self.challenges),
            slashing_evidence_root: map_root("slashing-evidence", &self.slashing_evidence),
            events_root: map_root("events", &self.events),
            state_root: String::new(),
        };
        self.roots.state_root = self.state_root();
    }

    fn roots_without_state(&self) -> Value {
        json!({
            "lanes_root": self.roots.lanes_root,
            "slots_root": self.roots.slots_root,
            "encrypted_calls_root": self.roots.encrypted_calls_root,
            "attestations_root": self.roots.attestations_root,
            "receipts_root": self.roots.receipts_root,
            "cache_hits_root": self.roots.cache_hits_root,
            "rebates_root": self.roots.rebates_root,
            "privacy_fences_root": self.roots.privacy_fences_root,
            "challenges_root": self.roots.challenges_root,
            "slashing_evidence_root": self.roots.slashing_evidence_root,
            "events_root": self.roots.events_root,
        })
    }

    fn require_lane(&self, lane_id: &str) -> Result<&AcceleratorLane> {
        self.lanes
            .get(lane_id)
            .ok_or_else(|| "accelerator lane not found".to_string())
    }

    fn require_lane_mut(&mut self, lane_id: &str) -> Result<&mut AcceleratorLane> {
        self.lanes
            .get_mut(lane_id)
            .ok_or_else(|| "accelerator lane not found".to_string())
    }

    fn require_call(&self, call_id: &str) -> Result<&EncryptedCallEnvelope> {
        self.encrypted_calls
            .get(call_id)
            .ok_or_else(|| "encrypted call not found".to_string())
    }

    fn require_call_mut(&mut self, call_id: &str) -> Result<&mut EncryptedCallEnvelope> {
        self.encrypted_calls
            .get_mut(call_id)
            .ok_or_else(|| "encrypted call not found".to_string())
    }

    fn push_event(&mut self, kind: EventKind, subject_id: &str, height: u64) -> Result<()> {
        let root = public_subject_root(kind.as_str(), subject_id);
        let event_id = event_id(kind, subject_id, height, self.events.len() as u64);
        let public = json!({
            "kind": kind.as_str(),
            "subject_id": subject_id,
            "height": height,
            "root": root,
        });
        self.events.insert(
            event_id.clone(),
            RuntimeEvent {
                event_id,
                kind,
                subject_id: subject_id.to_string(),
                height,
                root,
                public,
            },
        );
        Ok(())
    }
}
pub fn lane_id(
    committee_id: &str,
    operator_id: &str,
    precompile_class: PrecompileClass,
    metadata_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:lane-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(operator_id),
            HashPart::Str(precompile_class.as_str()),
            HashPart::Str(metadata_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn warm_slot_id(
    lane_id: &str,
    reserver_id: &str,
    privacy_fence_seed: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:warm-slot-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(reserver_id),
            HashPart::Str(privacy_fence_seed),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn encrypted_call_id(
    lane_id: &str,
    caller_commitment: &str,
    contract_commitment: &str,
    encrypted_payload_root: &str,
    nullifier: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:encrypted-call-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(caller_commitment),
            HashPart::Str(contract_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(nullifier),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn attestation_id(
    lane_id: &str,
    call_id: &str,
    output_root: &str,
    trace_root: &str,
    quorum_bps: u64,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:attestation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(call_id),
            HashPart::Str(output_root),
            HashPart::Str(trace_root),
            HashPart::U64(quorum_bps),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn receipt_id(
    lane_id: &str,
    batch_id: &str,
    output_root: &str,
    state_diff_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(batch_id),
            HashPart::Str(output_root),
            HashPart::Str(state_diff_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn proof_cache_hit_id(
    lane_id: &str,
    call_id: &str,
    proof_key_root: &str,
    cached_output_root: &str,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:proof-cache-hit-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(call_id),
            HashPart::Str(proof_key_root),
            HashPart::Str(cached_output_root),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, call_id: &str, beneficiary_commitment: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(call_id),
            HashPart::Str(beneficiary_commitment),
        ],
        32,
    )
}

pub fn privacy_fence_id(lane_id: &str, subject_id: &str, nullifier_or_seed: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:privacy-fence-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_or_seed),
        ],
        32,
    )
}

pub fn challenge_id(
    kind: ChallengeKind,
    lane_id: &str,
    call_id: &str,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:challenge-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane_id),
            HashPart::Str(call_id),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    lane_id: &str,
    challenge_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:slashing-evidence-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(challenge_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn event_id(kind: EventKind, subject_id: &str, height: u64, index: u64) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:event-id",
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
        "private-l2-fast-pq-precompile-accelerator:public-subject-root",
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
        "private-l2-fast-pq-precompile-accelerator:state-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-precompile-accelerator:public-record-root",
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

fn map_root<T: Serialize>(name: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-precompile-accelerator:{name}"),
        &leaves,
    )
}

fn compute_rebate(
    fee_charged_micro_units: u64,
    target_rebate_bps: u64,
    cache_hit_count: u64,
    cache_hit_rebate_bps: u64,
) -> u64 {
    mul_bps(fee_charged_micro_units, target_rebate_bps)
        + mul_bps(fee_charged_micro_units, cache_hit_rebate_bps).saturating_mul(cache_hit_count)
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
