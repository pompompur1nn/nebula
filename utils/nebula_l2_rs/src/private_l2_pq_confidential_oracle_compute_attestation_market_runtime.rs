use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialOracleComputeAttestationMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-oracle-compute-attestation-market-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-confidential-oracle-compute-request-v1";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-oracle-compute-attestation-v1";
pub const REQUEST_ENCRYPTION_SCHEME: &str = "pq-sealed-confidential-oracle-compute-request-v1";
pub const RESULT_COMMITMENT_SCHEME: &str = "zk-oracle-compute-result-commitment-v1";
pub const COMMITTEE_ATTESTATION_SCHEME: &str =
    "weighted-pq-oracle-compute-committee-attestation-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-confidential-oracle-result-batch-v1";
pub const REBATE_RECEIPT_SCHEME: &str = "confidential-oracle-compute-rebate-receipt-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "oracle-compute-privacy-fence-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-oracle-compute-slashing-evidence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_COMMITTEE_ID: &str = "pq-confidential-oracle-compute-devnet-committee";
pub const DEVNET_HEIGHT: u64 = 2_048_512;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_REQUEST_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_COMPUTE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 7;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 20;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_MIN_ORACLE_BOND_MICRO_UNITS: u64 = 5_000_000;
pub const DEFAULT_MIN_BATCHER_BOND_MICRO_UNITS: u64 = 8_000_000;
pub const MAX_REQUESTS: usize = 4_194_304;
pub const MAX_BIDS: usize = 8_388_608;
pub const MAX_MEMBERS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_RESULTS: usize = 4_194_304;
pub const MAX_BATCHES: usize = 2_097_152;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_FENCES: usize = 8_388_608;
pub const MAX_EVIDENCE: usize = 2_097_152;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleComputeKind {
    PriceVector,
    RiskVector,
    LiquidityDepth,
    ReserveProof,
    VolatilitySurface,
    FundingCurve,
    CrossContractState,
    ContractEventFilter,
    MoneroViewTagScan,
    ProofFeeIndex,
    BridgeHealth,
    EmergencyCircuit,
}

impl OracleComputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceVector => "price_vector",
            Self::RiskVector => "risk_vector",
            Self::LiquidityDepth => "liquidity_depth",
            Self::ReserveProof => "reserve_proof",
            Self::VolatilitySurface => "volatility_surface",
            Self::FundingCurve => "funding_curve",
            Self::CrossContractState => "cross_contract_state",
            Self::ContractEventFilter => "contract_event_filter",
            Self::MoneroViewTagScan => "monero_view_tag_scan",
            Self::ProofFeeIndex => "proof_fee_index",
            Self::BridgeHealth => "bridge_health",
            Self::EmergencyCircuit => "emergency_circuit",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::EmergencyCircuit => 1_000,
            Self::BridgeHealth => 920,
            Self::ReserveProof => 880,
            Self::RiskVector => 840,
            Self::PriceVector => 800,
            Self::LiquidityDepth => 760,
            Self::VolatilitySurface => 720,
            Self::FundingCurve => 680,
            Self::CrossContractState => 640,
            Self::ContractEventFilter => 600,
            Self::MoneroViewTagScan => 560,
            Self::ProofFeeIndex => 520,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Submitted,
    Bidding,
    Assigned,
    Computing,
    Attested,
    Committed,
    Batched,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl RequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Bidding => "bidding",
            Self::Assigned => "assigned",
            Self::Computing => "computing",
            Self::Attested => "attested",
            Self::Committed => "committed",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Bidding
                | Self::Assigned
                | Self::Computing
                | Self::Attested
                | Self::Committed
        )
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Committed | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Selected,
    Outbid,
    Accepted,
    Settled,
    Rebated,
    Rejected,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Selected => "selected",
            Self::Outbid => "outbid",
            Self::Accepted => "accepted",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    ComputeAttester,
    ResultVerifier,
    BatchAggregator,
    PrivacyWatcher,
    FeeSponsor,
    SlashingJudge,
    EmergencySigner,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ComputeAttester => "compute_attester",
            Self::ResultVerifier => "result_verifier",
            Self::BatchAggregator => "batch_aggregator",
            Self::PrivacyWatcher => "privacy_watcher",
            Self::FeeSponsor => "fee_sponsor",
            Self::SlashingJudge => "slashing_judge",
            Self::EmergencySigner => "emergency_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Pending,
    Active,
    Degraded,
    Suspended,
    Jailed,
    Slashed,
    Retired,
}

impl MemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Suspended => "suspended",
            Self::Jailed => "jailed",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn can_accept_work(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    InvalidCiphertext,
    InvalidComputation,
    StaleInput,
    WeakPrivacySet,
    FeeTooHigh,
    FenceViolation,
    NeedsReview,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::InvalidComputation => "invalid_computation",
            Self::StaleInput => "stale_input",
            Self::WeakPrivacySet => "weak_privacy_set",
            Self::FeeTooHigh => "fee_too_high",
            Self::FenceViolation => "fence_violation",
            Self::NeedsReview => "needs_review",
        }
    }

    pub fn accepts_result(self) -> bool {
        matches!(self, Self::Valid | Self::NeedsReview)
    }

    pub fn severity(self) -> u64 {
        match self {
            Self::Valid => 0,
            Self::NeedsReview => 1,
            Self::StaleInput | Self::WeakPrivacySet | Self::FeeTooHigh => 2,
            Self::InvalidCiphertext | Self::InvalidComputation | Self::FenceViolation => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Committed,
    QuorumAccepted,
    Batched,
    Settled,
    Disputed,
    Rejected,
    Expired,
}

impl ResultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Attested,
    Settled,
    Disputed,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    NullifierReplay,
    RequesterLinkage,
    CommitteeOverlap,
    ResultCorrelation,
    FeeFingerprint,
    TimeWindowLeak,
    CrossContractDomain,
    EmergencyPause,
}

impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierReplay => "nullifier_replay",
            Self::RequesterLinkage => "requester_linkage",
            Self::CommitteeOverlap => "committee_overlap",
            Self::ResultCorrelation => "result_correlation",
            Self::FeeFingerprint => "fee_fingerprint",
            Self::TimeWindowLeak => "time_window_leak",
            Self::CrossContractDomain => "cross_contract_domain",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimable,
    Paid,
    Cancelled,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimable => "claimable",
            Self::Paid => "paid",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    Equivocation,
    BadResult,
    WithheldResult,
    InvalidAttestation,
    PrivacyLeak,
    FeeOvercharge,
    LateBatch,
    ReplayEvidence,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::BadResult => "bad_result",
            Self::WithheldResult => "withheld_result",
            Self::InvalidAttestation => "invalid_attestation",
            Self::PrivacyLeak => "privacy_leak",
            Self::FeeOvercharge => "fee_overcharge",
            Self::LateBatch => "late_batch",
            Self::ReplayEvidence => "replay_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Settled,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    Request,
    Bid,
    Assignment,
    Attestation,
    ResultCommitment,
    Batch,
    Rebate,
    PrivacyFence,
    SlashingEvidence,
    Epoch,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Bid => "bid",
            Self::Assignment => "assignment",
            Self::Attestation => "attestation",
            Self::ResultCommitment => "result_commitment",
            Self::Batch => "batch",
            Self::Rebate => "rebate",
            Self::PrivacyFence => "privacy_fence",
            Self::SlashingEvidence => "slashing_evidence",
            Self::Epoch => "epoch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeTier {
    UltraLow,
    Low,
    Standard,
    Fast,
    Emergency,
}

impl FeeTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraLow => "ultra_low",
            Self::Low => "low",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Emergency => "emergency",
        }
    }

    pub fn max_latency_blocks(self) -> u64 {
        match self {
            Self::UltraLow => 24,
            Self::Low => 18,
            Self::Standard => 12,
            Self::Fast => 6,
            Self::Emergency => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchPolicy {
    LowestFeeFirst,
    PrivacySetFirst,
    DeadlineFirst,
    FeeThenDeadline,
    EmergencyOnly,
}

impl BatchPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowestFeeFirst => "lowest_fee_first",
            Self::PrivacySetFirst => "privacy_set_first",
            Self::DeadlineFirst => "deadline_first",
            Self::FeeThenDeadline => "fee_then_deadline",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeEnvironment {
    Tee,
    ZkVm,
    Mpc,
    Hybrid,
    ExternalOracle,
    ContractView,
}

impl ComputeEnvironment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tee => "tee",
            Self::ZkVm => "zk_vm",
            Self::Mpc => "mpc",
            Self::Hybrid => "hybrid",
            Self::ExternalOracle => "external_oracle",
            Self::ContractView => "contract_view",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkCommitmentScheme {
    Plonk,
    Halo2,
    Nova,
    Stark,
    Groth16,
    PqRecursive,
}

impl ZkCommitmentScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plonk => "plonk",
            Self::Halo2 => "halo2",
            Self::Nova => "nova",
            Self::Stark => "stark",
            Self::Groth16 => "groth16",
            Self::PqRecursive => "pq_recursive",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionDomain {
    Requester,
    Committee,
    Contract,
    Batch,
    Rebate,
    Evidence,
}

impl EncryptionDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requester => "requester",
            Self::Committee => "committee",
            Self::Contract => "contract",
            Self::Batch => "batch",
            Self::Rebate => "rebate",
            Self::Evidence => "evidence",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub network: String,
    pub monero_network: String,
    pub market_id: String,
    pub committee_id: String,
    pub genesis_height: u64,
    pub epoch: u64,
    pub request_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub compute_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub evidence_ttl_blocks: u64,
    pub min_committee_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_oracle_bond_micro_units: u64,
    pub min_batcher_bond_micro_units: u64,
    pub allow_emergency_batches: bool,
    pub require_zk_result_commitments: bool,
    pub require_privacy_fences: bool,
    pub slash_for_missed_attestation: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedComputeRequest {
    pub request_id: String,
    pub requester_commitment: String,
    pub contract_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub encryption_domain: EncryptionDomain,
    pub encrypted_payload_root: String,
    pub input_commitment_root: String,
    pub callback_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub tip_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: RequestStatus,
    pub nullifier: String,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleFeeBid {
    pub bid_id: String,
    pub request_id: String,
    pub provider_id: String,
    pub sealed_quote_root: String,
    pub fee_micro_units: u64,
    pub rebate_bps: u64,
    pub compute_deadline_height: u64,
    pub posted_height: u64,
    pub expires_height: u64,
    pub status: BidStatus,
    pub bond_id: String,
    pub privacy_quote_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub role: CommitteeRole,
    pub status: MemberStatus,
    pub weight: u64,
    pub bond_micro_units: u64,
    pub pq_security_bits: u16,
    pub pq_public_key_root: String,
    pub attestation_key_root: String,
    pub joined_height: u64,
    pub last_seen_height: u64,
    pub slash_count: u64,
    pub reputation_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComputeAssignment {
    pub assignment_id: String,
    pub request_id: String,
    pub bid_id: String,
    pub provider_id: String,
    pub committee_id: String,
    pub assigned_height: u64,
    pub deadline_height: u64,
    pub sealed_session_key_root: String,
    pub assignment_commitment: String,
    pub status: RequestStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub request_id: String,
    pub result_id: String,
    pub member_id: String,
    pub verdict: AttestationVerdict,
    pub weight: u64,
    pub observed_height: u64,
    pub posted_height: u64,
    pub result_commitment: String,
    pub input_opening_root: String,
    pub pq_signature_root: String,
    pub privacy_fence_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZkResultCommitment {
    pub result_id: String,
    pub request_id: String,
    pub provider_id: String,
    pub scheme: ZkCommitmentScheme,
    pub status: ResultStatus,
    pub result_commitment: String,
    pub proof_commitment: String,
    pub public_output_root: String,
    pub encrypted_result_root: String,
    pub callback_record_root: String,
    pub compute_started_height: u64,
    pub committed_height: u64,
    pub settled_height: u64,
    pub attested_weight: u64,
    pub attestation_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeResultBatch {
    pub batch_id: String,
    pub policy: BatchPolicy,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub settled_height: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub result_ids: Vec<String>,
    pub result_root: String,
    pub fee_root: String,
    pub attestation_root: String,
    pub rebate_root: String,
    pub publisher_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: PrivacyFenceKind,
    pub subject_id: String,
    pub domain_separator: String,
    pub nullifier_root: String,
    pub fence_root: String,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub batch_id: String,
    pub recipient_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub sponsor_cover_micro_units: u64,
    pub issued_height: u64,
    pub expires_height: u64,
    pub status: RebateStatus,
    pub claim_nullifier: String,
    pub receipt_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashingReason,
    pub status: EvidenceStatus,
    pub accused_id: String,
    pub request_id: String,
    pub batch_id: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub slash_amount_micro_units: u64,
    pub public_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EpochRecord {
    pub epoch_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub committee_root: String,
    pub request_root: String,
    pub result_root: String,
    pub batch_root: String,
    pub rebate_root: String,
    pub evidence_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketEvent {
    pub event_id: String,
    pub kind: PublicRecordKind,
    pub subject_id: String,
    pub height: u64,
    pub record_root: String,
    pub state_root_after: String,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "network": self.network,
            "monero_network": self.monero_network,
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "genesis_height": self.genesis_height,
            "epoch": self.epoch,
            "request_ttl_blocks": self.request_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "compute_ttl_blocks": self.compute_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "evidence_ttl_blocks": self.evidence_ttl_blocks,
            "min_committee_weight": self.min_committee_weight,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "min_oracle_bond_micro_units": self.min_oracle_bond_micro_units,
            "min_batcher_bond_micro_units": self.min_batcher_bond_micro_units,
            "allow_emergency_batches": self.allow_emergency_batches,
            "require_zk_result_commitments": self.require_zk_result_commitments,
            "require_privacy_fences": self.require_privacy_fences,
            "slash_for_missed_attestation": self.slash_for_missed_attestation,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("Config", &self.public_record())
    }
}

impl EncryptedComputeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "requester_commitment": self.requester_commitment,
            "contract_id": self.contract_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "encryption_domain": self.encryption_domain.as_str(),
            "encrypted_payload_root": self.encrypted_payload_root,
            "input_commitment_root": self.input_commitment_root,
            "callback_commitment": self.callback_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "tip_micro_units": self.tip_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "nullifier": self.nullifier,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("EncryptedComputeRequest", &self.public_record())
    }
}

impl OracleFeeBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "request_id": self.request_id,
            "provider_id": self.provider_id,
            "sealed_quote_root": self.sealed_quote_root,
            "fee_micro_units": self.fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "compute_deadline_height": self.compute_deadline_height,
            "posted_height": self.posted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "bond_id": self.bond_id,
            "privacy_quote_root": self.privacy_quote_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("OracleFeeBid", &self.public_record())
    }
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "bond_micro_units": self.bond_micro_units,
            "pq_security_bits": self.pq_security_bits,
            "pq_public_key_root": self.pq_public_key_root,
            "attestation_key_root": self.attestation_key_root,
            "joined_height": self.joined_height,
            "last_seen_height": self.last_seen_height,
            "slash_count": self.slash_count,
            "reputation_root": self.reputation_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("CommitteeMember", &self.public_record())
    }
}

impl ComputeAssignment {
    pub fn public_record(&self) -> Value {
        json!({
            "assignment_id": self.assignment_id,
            "request_id": self.request_id,
            "bid_id": self.bid_id,
            "provider_id": self.provider_id,
            "committee_id": self.committee_id,
            "assigned_height": self.assigned_height,
            "deadline_height": self.deadline_height,
            "sealed_session_key_root": self.sealed_session_key_root,
            "assignment_commitment": self.assignment_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        root_value("ComputeAssignment", &self.public_record())
    }
}

impl CommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request_id": self.request_id,
            "result_id": self.result_id,
            "member_id": self.member_id,
            "verdict": self.verdict.as_str(),
            "weight": self.weight,
            "observed_height": self.observed_height,
            "posted_height": self.posted_height,
            "result_commitment": self.result_commitment,
            "input_opening_root": self.input_opening_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_fence_root": self.privacy_fence_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("CommitteeAttestation", &self.public_record())
    }
}

impl ZkResultCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "result_id": self.result_id,
            "request_id": self.request_id,
            "provider_id": self.provider_id,
            "scheme": self.scheme.as_str(),
            "status": self.status.as_str(),
            "result_commitment": self.result_commitment,
            "proof_commitment": self.proof_commitment,
            "public_output_root": self.public_output_root,
            "encrypted_result_root": self.encrypted_result_root,
            "callback_record_root": self.callback_record_root,
            "compute_started_height": self.compute_started_height,
            "committed_height": self.committed_height,
            "settled_height": self.settled_height,
            "attested_weight": self.attested_weight,
            "attestation_root": self.attestation_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("ZkResultCommitment", &self.public_record())
    }
}

impl LowFeeResultBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "policy": self.policy.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "settled_height": self.settled_height,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "result_ids": self.result_ids,
            "result_root": self.result_root,
            "fee_root": self.fee_root,
            "attestation_root": self.attestation_root,
            "rebate_root": self.rebate_root,
            "publisher_id": self.publisher_id,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("LowFeeResultBatch", &self.public_record())
    }
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "domain_separator": self.domain_separator,
            "nullifier_root": self.nullifier_root,
            "fence_root": self.fence_root,
            "privacy_set_size": self.privacy_set_size,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "active": self.active,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("PrivacyFence", &self.public_record())
    }
}

impl RebateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "batch_id": self.batch_id,
            "recipient_commitment": self.recipient_commitment,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "sponsor_cover_micro_units": self.sponsor_cover_micro_units,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "claim_nullifier": self.claim_nullifier,
            "receipt_root": self.receipt_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("RebateReceipt", &self.public_record())
    }
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reason": self.reason.as_str(),
            "status": self.status.as_str(),
            "accused_id": self.accused_id,
            "request_id": self.request_id,
            "batch_id": self.batch_id,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "public_summary_root": self.public_summary_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("SlashingEvidence", &self.public_record())
    }
}

impl EpochRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "committee_root": self.committee_root,
            "request_root": self.request_root,
            "result_root": self.result_root,
            "batch_root": self.batch_root,
            "rebate_root": self.rebate_root,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("EpochRecord", &self.public_record())
    }
}

impl MarketEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "height": self.height,
            "record_root": self.record_root,
            "state_root_after": self.state_root_after,
        })
    }

    pub fn record_root(&self) -> String {
        root_value("MarketEvent", &self.public_record())
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            market_id: "pq-confidential-oracle-compute-attestation-market-devnet".to_string(),
            committee_id: DEVNET_COMMITTEE_ID.to_string(),
            genesis_height: DEVNET_HEIGHT,
            epoch: 0,
            request_ttl_blocks: DEFAULT_REQUEST_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            compute_ttl_blocks: DEFAULT_COMPUTE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            evidence_ttl_blocks: DEFAULT_EVIDENCE_TTL_BLOCKS,
            min_committee_weight: DEFAULT_MIN_COMMITTEE_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_oracle_bond_micro_units: DEFAULT_MIN_ORACLE_BOND_MICRO_UNITS,
            min_batcher_bond_micro_units: DEFAULT_MIN_BATCHER_BOND_MICRO_UNITS,
            allow_emergency_batches: true,
            require_zk_result_commitments: true,
            require_privacy_fences: true,
            slash_for_missed_attestation: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub next_nonce: u64,
    pub requests: BTreeMap<String, EncryptedComputeRequest>,
    pub bids: BTreeMap<String, OracleFeeBid>,
    pub members: BTreeMap<String, CommitteeMember>,
    pub assignments: BTreeMap<String, ComputeAssignment>,
    pub attestations: BTreeMap<String, CommitteeAttestation>,
    pub results: BTreeMap<String, ZkResultCommitment>,
    pub batches: BTreeMap<String, LowFeeResultBatch>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub rebates: BTreeMap<String, RebateReceipt>,
    pub evidence: BTreeMap<String, SlashingEvidence>,
    pub epochs: BTreeMap<String, EpochRecord>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: Vec<MarketEvent>,
}

pub fn root_value(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}

pub fn root_strings(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &leaves)
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{PROTOCOL_VERSION}:id:{domain}"), parts, 32)
}

pub fn deterministic_record_root(kind: PublicRecordKind, record: &Value) -> String {
    root_value(kind.as_str(), record)
}

pub fn deterministic_batch_root(records: &[Value]) -> String {
    merkle_root(&format!("{PROTOCOL_VERSION}:deterministic-batch"), records)
}

pub fn is_valid_bps(value: u64) -> bool {
    value <= MAX_BPS
}

pub fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

pub fn require_hash_like(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} must be a commitment-like value"));
    }
    Ok(())
}

pub fn checked_add_height(height: u64, delta: u64) -> Result<u64> {
    height
        .checked_add(delta)
        .ok_or_else(|| "height overflow".to_string())
}

pub fn fee_bps(amount: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    amount.saturating_mul(MAX_BPS) / denominator
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            height: config.genesis_height,
            config,
            next_nonce: 1,
            requests: BTreeMap::new(),
            bids: BTreeMap::new(),
            members: BTreeMap::new(),
            assignments: BTreeMap::new(),
            attestations: BTreeMap::new(),
            results: BTreeMap::new(),
            batches: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            rebates: BTreeMap::new(),
            evidence: BTreeMap::new(),
            epochs: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.seed_devnet_committee();
        state
    }

    fn seed_devnet_committee(&mut self) {
        for index in 0..7_u64 {
            let member_id = deterministic_id(
                "devnet-member",
                &[
                    HashPart::Str(&self.config.committee_id),
                    HashPart::U64(index),
                ],
            );
            let member = CommitteeMember {
                member_id: member_id.clone(),
                operator_commitment: deterministic_id("operator", &[HashPart::Str(&member_id)]),
                role: if index == 0 {
                    CommitteeRole::BatchAggregator
                } else {
                    CommitteeRole::ComputeAttester
                },
                status: MemberStatus::Active,
                weight: 1,
                bond_micro_units: self.config.min_oracle_bond_micro_units,
                pq_security_bits: self.config.min_pq_security_bits,
                pq_public_key_root: deterministic_id("member-pq-key", &[HashPart::Str(&member_id)]),
                attestation_key_root: deterministic_id(
                    "member-attestation-key",
                    &[HashPart::Str(&member_id)],
                ),
                joined_height: self.height,
                last_seen_height: self.height,
                slash_count: 0,
                reputation_root: deterministic_id(
                    "member-reputation",
                    &[HashPart::Str(&member_id)],
                ),
            };
            self.members.insert(member_id, member);
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": HASH_SUITE,
            "pq_kem_suite": PQ_KEM_SUITE,
            "pq_signature_suite": PQ_SIGNATURE_SUITE,
            "request_encryption_scheme": REQUEST_ENCRYPTION_SCHEME,
            "result_commitment_scheme": RESULT_COMMITMENT_SCHEME,
            "committee_attestation_scheme": COMMITTEE_ATTESTATION_SCHEME,
            "low_fee_batch_scheme": LOW_FEE_BATCH_SCHEME,
            "rebate_receipt_scheme": REBATE_RECEIPT_SCHEME,
            "privacy_fence_scheme": PRIVACY_FENCE_SCHEME,
            "slashing_evidence_scheme": SLASHING_EVIDENCE_SCHEME,
            "height": self.height,
            "next_nonce": self.next_nonce,
            "config": self.config.public_record(),
            "requests_root": self.collection_root("requests", self.requests.values().map(|r| r.public_record()).collect()),
            "bids_root": self.collection_root("bids", self.bids.values().map(|r| r.public_record()).collect()),
            "members_root": self.collection_root("members", self.members.values().map(|r| r.public_record()).collect()),
            "assignments_root": self.collection_root("assignments", self.assignments.values().map(|r| r.public_record()).collect()),
            "attestations_root": self.collection_root("attestations", self.attestations.values().map(|r| r.public_record()).collect()),
            "results_root": self.collection_root("results", self.results.values().map(|r| r.public_record()).collect()),
            "batches_root": self.collection_root("batches", self.batches.values().map(|r| r.public_record()).collect()),
            "privacy_fences_root": self.collection_root("privacy_fences", self.privacy_fences.values().map(|r| r.public_record()).collect()),
            "rebates_root": self.collection_root("rebates", self.rebates.values().map(|r| r.public_record()).collect()),
            "evidence_root": self.collection_root("evidence", self.evidence.values().map(|r| r.public_record()).collect()),
            "epochs_root": self.collection_root("epochs", self.epochs.values().map(|r| r.public_record()).collect()),
            "spent_nullifiers_root": root_strings("spent-nullifiers", &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>()),
            "events_root": self.collection_root("events", self.events.iter().map(|r| r.public_record()).collect()),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut value = self.public_record_without_state_root();
        if let Value::Object(ref mut map) = value {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        value
    }

    pub fn state_root(&self) -> String {
        root_value("state", &self.public_record_without_state_root())
    }

    pub fn collection_root(&self, domain: &str, records: Vec<Value>) -> String {
        merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &records)
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        if new_height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = new_height;
        Ok(())
    }

    fn take_nonce(&mut self) -> u64 {
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.saturating_add(1);
        nonce
    }

    fn emit_event(&mut self, kind: PublicRecordKind, subject_id: String, record_root: String) {
        let event_id = deterministic_id(
            "event",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_id),
                HashPart::U64(self.height),
                HashPart::U64(self.events.len() as u64),
            ],
        );
        let event = MarketEvent {
            event_id,
            kind,
            subject_id,
            height: self.height,
            record_root,
            state_root_after: self.state_root(),
        };
        self.events.push(event);
        if self.events.len() > MAX_EVENTS {
            self.events.remove(0);
        }
    }

    pub fn validate_config(config: &Config) -> Result<()> {
        require_non_empty("network", &config.network)?;
        require_non_empty("monero_network", &config.monero_network)?;
        require_non_empty("market_id", &config.market_id)?;
        require_non_empty("committee_id", &config.committee_id)?;
        if config.request_ttl_blocks == 0
            || config.bid_ttl_blocks == 0
            || config.compute_ttl_blocks == 0
        {
            return Err("ttl values must be non-zero".to_string());
        }
        if config.min_committee_weight == 0 {
            return Err("min committee weight must be non-zero".to_string());
        }
        if !is_valid_bps(config.quorum_bps)
            || !is_valid_bps(config.strong_quorum_bps)
            || !is_valid_bps(config.max_user_fee_bps)
            || !is_valid_bps(config.target_rebate_bps)
            || !is_valid_bps(config.sponsor_cover_bps)
        {
            return Err("basis point config out of range".to_string());
        }
        if config.strong_quorum_bps < config.quorum_bps {
            return Err("strong quorum must be at least normal quorum".to_string());
        }
        Ok(())
    }

    pub fn register_member(
        &mut self,
        operator_commitment: String,
        role: CommitteeRole,
        weight: u64,
        bond_micro_units: u64,
        pq_security_bits: u16,
        pq_public_key_root: String,
        attestation_key_root: String,
    ) -> Result<String> {
        if self.members.len() >= MAX_MEMBERS {
            return Err("member capacity reached".to_string());
        }
        require_hash_like("operator_commitment", &operator_commitment)?;
        require_hash_like("pq_public_key_root", &pq_public_key_root)?;
        require_hash_like("attestation_key_root", &attestation_key_root)?;
        if weight == 0 {
            return Err("member weight must be non-zero".to_string());
        }
        if bond_micro_units < self.config.min_oracle_bond_micro_units {
            return Err("member bond below minimum".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security below runtime minimum".to_string());
        }
        let nonce = self.take_nonce();
        let member_id = deterministic_id(
            "member",
            &[
                HashPart::Str(&self.config.market_id),
                HashPart::Str(&operator_commitment),
                HashPart::U64(nonce),
            ],
        );
        let member = CommitteeMember {
            member_id: member_id.clone(),
            operator_commitment,
            role,
            status: MemberStatus::Pending,
            weight,
            bond_micro_units,
            pq_security_bits,
            pq_public_key_root,
            attestation_key_root,
            joined_height: self.height,
            last_seen_height: self.height,
            slash_count: 0,
            reputation_root: deterministic_id("member-reputation", &[HashPart::Str(&member_id)]),
        };
        let root = member.record_root();
        self.members.insert(member_id.clone(), member);
        self.emit_event(PublicRecordKind::Epoch, member_id.clone(), root);
        Ok(member_id)
    }

    pub fn activate_member(&mut self, member_id: &str) -> Result<()> {
        let member = self
            .members
            .get_mut(member_id)
            .ok_or_else(|| "unknown member".to_string())?;
        if matches!(member.status, MemberStatus::Slashed | MemberStatus::Retired) {
            return Err("member cannot be activated".to_string());
        }
        member.status = MemberStatus::Active;
        member.last_seen_height = self.height;
        let root = member.record_root();
        self.emit_event(PublicRecordKind::Epoch, member_id.to_string(), root);
        Ok(())
    }

    pub fn submit_request(
        &mut self,
        requester_commitment: String,
        contract_id: String,
        compute_kind: OracleComputeKind,
        fee_tier: FeeTier,
        environment: ComputeEnvironment,
        encrypted_payload_root: String,
        input_commitment_root: String,
        callback_commitment: String,
        fee_asset_id: String,
        max_fee_micro_units: u64,
        tip_micro_units: u64,
        privacy_set_size: u64,
        pq_security_bits: u16,
        nullifier: String,
        metadata_root: String,
    ) -> Result<String> {
        if self.requests.len() >= MAX_REQUESTS {
            return Err("request capacity reached".to_string());
        }
        require_hash_like("requester_commitment", &requester_commitment)?;
        require_non_empty("contract_id", &contract_id)?;
        require_hash_like("encrypted_payload_root", &encrypted_payload_root)?;
        require_hash_like("input_commitment_root", &input_commitment_root)?;
        require_hash_like("callback_commitment", &callback_commitment)?;
        require_non_empty("fee_asset_id", &fee_asset_id)?;
        require_hash_like("nullifier", &nullifier)?;
        require_hash_like("metadata_root", &metadata_root)?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below minimum".to_string());
        }
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security below runtime minimum".to_string());
        }
        if self.spent_nullifiers.contains(&nullifier) {
            return Err("request nullifier already spent".to_string());
        }
        let expires_height = checked_add_height(
            self.height,
            self.config
                .request_ttl_blocks
                .min(fee_tier.max_latency_blocks()),
        )?;
        let nonce = self.take_nonce();
        let request_id = deterministic_id(
            "request",
            &[
                HashPart::Str(&requester_commitment),
                HashPart::Str(&contract_id),
                HashPart::Str(compute_kind.as_str()),
                HashPart::Str(&encrypted_payload_root),
                HashPart::Str(&nullifier),
                HashPart::U64(nonce),
            ],
        );
        let request = EncryptedComputeRequest {
            request_id: request_id.clone(),
            requester_commitment,
            contract_id,
            compute_kind,
            fee_tier,
            environment,
            encryption_domain: EncryptionDomain::Requester,
            encrypted_payload_root,
            input_commitment_root,
            callback_commitment,
            fee_asset_id,
            max_fee_micro_units,
            tip_micro_units,
            privacy_set_size,
            pq_security_bits,
            submitted_height: self.height,
            expires_height,
            status: RequestStatus::Submitted,
            nullifier: nullifier.clone(),
            metadata_root,
        };
        let root = request.record_root();
        self.requests.insert(request_id.clone(), request);
        self.spent_nullifiers.insert(nullifier);
        self.emit_event(PublicRecordKind::Request, request_id.clone(), root);
        Ok(request_id)
    }

    pub fn post_fee_bid(
        &mut self,
        request_id: String,
        provider_id: String,
        sealed_quote_root: String,
        fee_micro_units: u64,
        rebate_bps: u64,
        compute_deadline_height: u64,
        bond_id: String,
        privacy_quote_root: String,
    ) -> Result<String> {
        if self.bids.len() >= MAX_BIDS {
            return Err("bid capacity reached".to_string());
        }
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| "unknown request".to_string())?;
        if !request.status.live() {
            return Err("request is not live".to_string());
        }
        if self.height > request.expires_height {
            request.status = RequestStatus::Expired;
            return Err("request expired".to_string());
        }
        let provider = self
            .members
            .get(&provider_id)
            .ok_or_else(|| "unknown provider".to_string())?;
        if !provider.status.can_accept_work() {
            return Err("provider cannot accept work".to_string());
        }
        require_hash_like("sealed_quote_root", &sealed_quote_root)?;
        require_hash_like("privacy_quote_root", &privacy_quote_root)?;
        require_non_empty("bond_id", &bond_id)?;
        if fee_micro_units > request.max_fee_micro_units {
            return Err("bid exceeds request fee cap".to_string());
        }
        if !is_valid_bps(rebate_bps) || rebate_bps < self.config.target_rebate_bps {
            return Err("rebate below market target".to_string());
        }
        if compute_deadline_height <= self.height
            || compute_deadline_height > request.expires_height
        {
            return Err("compute deadline outside request window".to_string());
        }
        let expires_height = checked_add_height(self.height, self.config.bid_ttl_blocks)?;
        let nonce = self.take_nonce();
        let bid_id = deterministic_id(
            "bid",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&provider_id),
                HashPart::Str(&sealed_quote_root),
                HashPart::U64(fee_micro_units),
                HashPart::U64(nonce),
            ],
        );
        let bid = OracleFeeBid {
            bid_id: bid_id.clone(),
            request_id: request_id.clone(),
            provider_id,
            sealed_quote_root,
            fee_micro_units,
            rebate_bps,
            compute_deadline_height,
            posted_height: self.height,
            expires_height,
            status: BidStatus::Posted,
            bond_id,
            privacy_quote_root,
        };
        request.status = RequestStatus::Bidding;
        let root = bid.record_root();
        self.bids.insert(bid_id.clone(), bid);
        self.emit_event(PublicRecordKind::Bid, bid_id.clone(), root);
        Ok(bid_id)
    }

    pub fn select_bid(
        &mut self,
        request_id: &str,
        bid_id: &str,
        sealed_session_key_root: String,
    ) -> Result<String> {
        require_hash_like("sealed_session_key_root", &sealed_session_key_root)?;
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "unknown request".to_string())?;
        if !request.status.live() {
            return Err("request is not assignable".to_string());
        }
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| "unknown bid".to_string())?;
        if bid.request_id != request_id {
            return Err("bid request mismatch".to_string());
        }
        if !bid.status.selectable() || self.height > bid.expires_height {
            return Err("bid is not selectable".to_string());
        }
        let provider = self
            .members
            .get(&bid.provider_id)
            .ok_or_else(|| "unknown provider".to_string())?;
        if !provider.status.can_accept_work() {
            return Err("provider cannot accept work".to_string());
        }
        let assignment_id = deterministic_id(
            "assignment",
            &[
                HashPart::Str(request_id),
                HashPart::Str(bid_id),
                HashPart::Str(&bid.provider_id),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let deadline_height = bid.compute_deadline_height.min(checked_add_height(
            self.height,
            self.config.compute_ttl_blocks,
        )?);
        let assignment = ComputeAssignment {
            assignment_id: assignment_id.clone(),
            request_id: request_id.to_string(),
            bid_id: bid_id.to_string(),
            provider_id: bid.provider_id.clone(),
            committee_id: self.config.committee_id.clone(),
            assigned_height: self.height,
            deadline_height,
            sealed_session_key_root,
            assignment_commitment: deterministic_id(
                "assignment-commitment",
                &[HashPart::Str(&assignment_id)],
            ),
            status: RequestStatus::Assigned,
        };
        bid.status = BidStatus::Selected;
        request.status = RequestStatus::Assigned;
        let root = assignment.record_root();
        self.assignments.insert(assignment_id.clone(), assignment);
        self.emit_event(PublicRecordKind::Assignment, assignment_id.clone(), root);
        Ok(assignment_id)
    }

    pub fn commit_result(
        &mut self,
        request_id: String,
        provider_id: String,
        scheme: ZkCommitmentScheme,
        result_commitment: String,
        proof_commitment: String,
        public_output_root: String,
        encrypted_result_root: String,
        callback_record_root: String,
    ) -> Result<String> {
        if self.results.len() >= MAX_RESULTS {
            return Err("result capacity reached".to_string());
        }
        require_hash_like("result_commitment", &result_commitment)?;
        require_hash_like("proof_commitment", &proof_commitment)?;
        require_hash_like("public_output_root", &public_output_root)?;
        require_hash_like("encrypted_result_root", &encrypted_result_root)?;
        require_hash_like("callback_record_root", &callback_record_root)?;
        let request = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| "unknown request".to_string())?;
        if !matches!(
            request.status,
            RequestStatus::Assigned | RequestStatus::Computing
        ) {
            return Err("request is not awaiting result".to_string());
        }
        let has_assignment = self.assignments.values().any(|assignment| {
            assignment.request_id == request_id && assignment.provider_id == provider_id
        });
        if !has_assignment {
            return Err("provider has no assignment for request".to_string());
        }
        let result_id = deterministic_id(
            "result",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&provider_id),
                HashPart::Str(&result_commitment),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let result = ZkResultCommitment {
            result_id: result_id.clone(),
            request_id: request_id.clone(),
            provider_id,
            scheme,
            status: ResultStatus::Committed,
            result_commitment,
            proof_commitment,
            public_output_root,
            encrypted_result_root,
            callback_record_root,
            compute_started_height: request.submitted_height,
            committed_height: self.height,
            settled_height: 0,
            attested_weight: 0,
            attestation_root: root_strings("empty-attestations", &[]),
        };
        request.status = RequestStatus::Committed;
        let root = result.record_root();
        self.results.insert(result_id.clone(), result);
        self.emit_event(PublicRecordKind::ResultCommitment, result_id.clone(), root);
        Ok(result_id)
    }

    pub fn post_attestation(
        &mut self,
        request_id: String,
        result_id: String,
        member_id: String,
        verdict: AttestationVerdict,
        input_opening_root: String,
        pq_signature_root: String,
        privacy_fence_root: String,
    ) -> Result<String> {
        if self.attestations.len() >= MAX_ATTESTATIONS {
            return Err("attestation capacity reached".to_string());
        }
        require_hash_like("input_opening_root", &input_opening_root)?;
        require_hash_like("pq_signature_root", &pq_signature_root)?;
        require_hash_like("privacy_fence_root", &privacy_fence_root)?;
        let member = self
            .members
            .get_mut(&member_id)
            .ok_or_else(|| "unknown member".to_string())?;
        if !member.status.can_attest() {
            return Err("member cannot attest".to_string());
        }
        let result = self
            .results
            .get_mut(&result_id)
            .ok_or_else(|| "unknown result".to_string())?;
        if result.request_id != request_id {
            return Err("result request mismatch".to_string());
        }
        if !matches!(
            result.status,
            ResultStatus::Committed | ResultStatus::QuorumAccepted
        ) {
            return Err("result no longer accepts attestations".to_string());
        }
        let duplicate = self.attestations.values().any(|attestation| {
            attestation.result_id == result_id && attestation.member_id == member_id
        });
        if duplicate {
            return Err("member already attested to result".to_string());
        }
        let attestation_id = deterministic_id(
            "attestation",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&result_id),
                HashPart::Str(&member_id),
                HashPart::Str(verdict.as_str()),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let attestation = CommitteeAttestation {
            attestation_id: attestation_id.clone(),
            request_id: request_id.clone(),
            result_id: result_id.clone(),
            member_id: member_id.clone(),
            verdict,
            weight: member.weight,
            observed_height: self.height,
            posted_height: self.height,
            result_commitment: result.result_commitment.clone(),
            input_opening_root,
            pq_signature_root,
            privacy_fence_root,
        };
        member.last_seen_height = self.height;
        let root = attestation.record_root();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_result_quorum(&result_id)?;
        self.emit_event(PublicRecordKind::Attestation, attestation_id.clone(), root);
        Ok(attestation_id)
    }

    pub fn refresh_result_quorum(&mut self, result_id: &str) -> Result<()> {
        let result = self
            .results
            .get_mut(result_id)
            .ok_or_else(|| "unknown result".to_string())?;
        let attestations = self
            .attestations
            .values()
            .filter(|a| a.result_id == result_id)
            .collect::<Vec<_>>();
        let accepted_weight = attestations
            .iter()
            .filter(|a| a.verdict.accepts_result())
            .map(|a| a.weight)
            .sum::<u64>();
        let total_weight = self
            .members
            .values()
            .filter(|m| m.status.can_attest())
            .map(|m| m.weight)
            .sum::<u64>();
        let quorum_weight = total_weight.saturating_mul(self.config.quorum_bps) / MAX_BPS;
        result.attested_weight = accepted_weight;
        let leaves = attestations
            .iter()
            .map(|a| a.public_record())
            .collect::<Vec<_>>();
        result.attestation_root =
            merkle_root(&format!("{PROTOCOL_VERSION}:result-attestations"), &leaves);
        if accepted_weight >= self.config.min_committee_weight && accepted_weight >= quorum_weight {
            result.status = ResultStatus::QuorumAccepted;
            if let Some(request) = self.requests.get_mut(&result.request_id) {
                request.status = RequestStatus::Attested;
            }
        }
        Ok(())
    }

    pub fn open_privacy_fence(
        &mut self,
        kind: PrivacyFenceKind,
        subject_id: String,
        domain_separator: String,
        nullifier_root: String,
        privacy_set_size: u64,
    ) -> Result<String> {
        if self.privacy_fences.len() >= MAX_FENCES {
            return Err("privacy fence capacity reached".to_string());
        }
        require_non_empty("subject_id", &subject_id)?;
        require_non_empty("domain_separator", &domain_separator)?;
        require_hash_like("nullifier_root", &nullifier_root)?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy fence set below minimum".to_string());
        }
        let fence_id = deterministic_id(
            "privacy-fence",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_id),
                HashPart::Str(&domain_separator),
                HashPart::Str(&nullifier_root),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let fence_root = deterministic_id(
            "privacy-fence-root",
            &[HashPart::Str(&fence_id), HashPart::Str(&nullifier_root)],
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind,
            subject_id,
            domain_separator,
            nullifier_root,
            fence_root,
            privacy_set_size,
            opened_height: self.height,
            expires_height: checked_add_height(self.height, self.config.request_ttl_blocks)?,
            active: true,
        };
        let root = fence.record_root();
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.emit_event(PublicRecordKind::PrivacyFence, fence_id.clone(), root);
        Ok(fence_id)
    }

    pub fn create_low_fee_batch(
        &mut self,
        policy: BatchPolicy,
        publisher_id: String,
        result_ids: Vec<String>,
    ) -> Result<String> {
        if self.batches.len() >= MAX_BATCHES {
            return Err("batch capacity reached".to_string());
        }
        require_non_empty("publisher_id", &publisher_id)?;
        if result_ids.is_empty() {
            return Err("batch must include at least one result".to_string());
        }
        let publisher = self
            .members
            .get(&publisher_id)
            .ok_or_else(|| "unknown publisher".to_string())?;
        if !matches!(
            publisher.role,
            CommitteeRole::BatchAggregator
                | CommitteeRole::FeeSponsor
                | CommitteeRole::EmergencySigner
        ) {
            return Err("publisher role cannot batch".to_string());
        }
        if publisher.bond_micro_units < self.config.min_batcher_bond_micro_units {
            return Err("publisher bond below batcher minimum".to_string());
        }
        let mut result_records = Vec::new();
        let mut total_fee_micro_units = 0_u64;
        let mut total_rebate_micro_units = 0_u64;
        for result_id in &result_ids {
            let result = self
                .results
                .get(result_id)
                .ok_or_else(|| format!("unknown result {result_id}"))?;
            if !matches!(
                result.status,
                ResultStatus::QuorumAccepted | ResultStatus::Committed
            ) {
                return Err(format!("result {result_id} is not batchable"));
            }
            let request = self
                .requests
                .get(&result.request_id)
                .ok_or_else(|| "missing request for result".to_string())?;
            total_fee_micro_units =
                total_fee_micro_units.saturating_add(request.max_fee_micro_units);
            total_rebate_micro_units = total_rebate_micro_units.saturating_add(
                request
                    .max_fee_micro_units
                    .saturating_mul(self.config.target_rebate_bps)
                    / MAX_BPS,
            );
            result_records.push(result.public_record());
        }
        let batch_id = deterministic_id(
            "batch",
            &[
                HashPart::Str(policy.as_str()),
                HashPart::Str(&publisher_id),
                HashPart::U64(self.height),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let result_root = merkle_root(
            &format!("{PROTOCOL_VERSION}:batch-results"),
            &result_records,
        );
        let fee_root = deterministic_id(
            "batch-fee-root",
            &[
                HashPart::Str(&batch_id),
                HashPart::U64(total_fee_micro_units),
            ],
        );
        let attestation_root = deterministic_id(
            "batch-attestation-root",
            &[HashPart::Str(&batch_id), HashPart::Str(&result_root)],
        );
        let rebate_root = deterministic_id(
            "batch-rebate-root",
            &[
                HashPart::Str(&batch_id),
                HashPart::U64(total_rebate_micro_units),
            ],
        );
        let batch = LowFeeResultBatch {
            batch_id: batch_id.clone(),
            policy,
            status: BatchStatus::Sealed,
            opened_height: self.height,
            sealed_height: self.height,
            settled_height: 0,
            total_fee_micro_units,
            total_rebate_micro_units,
            privacy_set_size: self.config.batch_privacy_set_size,
            result_ids: result_ids.clone(),
            result_root,
            fee_root,
            attestation_root,
            rebate_root,
            publisher_id,
        };
        for result_id in &result_ids {
            if let Some(result) = self.results.get_mut(result_id) {
                result.status = ResultStatus::Batched;
            }
            if let Some(request_id) = self.results.get(result_id).map(|r| r.request_id.clone()) {
                if let Some(request) = self.requests.get_mut(&request_id) {
                    request.status = RequestStatus::Batched;
                }
            }
        }
        let root = batch.record_root();
        self.batches.insert(batch_id.clone(), batch);
        self.emit_event(PublicRecordKind::Batch, batch_id.clone(), root);
        Ok(batch_id)
    }

    pub fn issue_rebate_receipt(
        &mut self,
        request_id: String,
        batch_id: String,
        recipient_commitment: String,
        fee_paid_micro_units: u64,
        sponsor_cover_micro_units: u64,
        claim_nullifier: String,
    ) -> Result<String> {
        if self.rebates.len() >= MAX_REBATES {
            return Err("rebate capacity reached".to_string());
        }
        require_hash_like("recipient_commitment", &recipient_commitment)?;
        require_hash_like("claim_nullifier", &claim_nullifier)?;
        if self.spent_nullifiers.contains(&claim_nullifier) {
            return Err("claim nullifier already spent".to_string());
        }
        let batch = self
            .batches
            .get(&batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        if !batch.result_ids.iter().any(|result_id| {
            self.results.get(result_id).map(|r| r.request_id.as_str()) == Some(request_id.as_str())
        }) {
            return Err("request is not part of batch".to_string());
        }
        let rebate_micro_units =
            fee_paid_micro_units.saturating_mul(self.config.target_rebate_bps) / MAX_BPS;
        let receipt_id = deterministic_id(
            "rebate",
            &[
                HashPart::Str(&request_id),
                HashPart::Str(&batch_id),
                HashPart::Str(&recipient_commitment),
                HashPart::Str(&claim_nullifier),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let receipt_root = deterministic_id(
            "rebate-root",
            &[
                HashPart::Str(&receipt_id),
                HashPart::U64(rebate_micro_units),
            ],
        );
        let receipt = RebateReceipt {
            receipt_id: receipt_id.clone(),
            request_id,
            batch_id,
            recipient_commitment,
            fee_paid_micro_units,
            rebate_micro_units,
            sponsor_cover_micro_units,
            issued_height: self.height,
            expires_height: checked_add_height(self.height, self.config.rebate_ttl_blocks)?,
            status: RebateStatus::Queued,
            claim_nullifier: claim_nullifier.clone(),
            receipt_root,
        };
        let root = receipt.record_root();
        self.rebates.insert(receipt_id.clone(), receipt);
        self.spent_nullifiers.insert(claim_nullifier);
        self.emit_event(PublicRecordKind::Rebate, receipt_id.clone(), root);
        Ok(receipt_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        reason: SlashingReason,
        accused_id: String,
        request_id: String,
        batch_id: String,
        evidence_root: String,
        challenger_commitment: String,
        slash_amount_micro_units: u64,
        public_summary_root: String,
    ) -> Result<String> {
        if self.evidence.len() >= MAX_EVIDENCE {
            return Err("evidence capacity reached".to_string());
        }
        require_non_empty("accused_id", &accused_id)?;
        require_hash_like("evidence_root", &evidence_root)?;
        require_hash_like("challenger_commitment", &challenger_commitment)?;
        require_hash_like("public_summary_root", &public_summary_root)?;
        if slash_amount_micro_units == 0 {
            return Err("slash amount must be non-zero".to_string());
        }
        let evidence_id = deterministic_id(
            "evidence",
            &[
                HashPart::Str(reason.as_str()),
                HashPart::Str(&accused_id),
                HashPart::Str(&request_id),
                HashPart::Str(&batch_id),
                HashPart::Str(&evidence_root),
                HashPart::U64(self.take_nonce()),
            ],
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            reason,
            status: EvidenceStatus::Submitted,
            accused_id,
            request_id,
            batch_id,
            evidence_root,
            challenger_commitment,
            submitted_height: self.height,
            expires_height: checked_add_height(self.height, self.config.evidence_ttl_blocks)?,
            slash_amount_micro_units,
            public_summary_root,
        };
        let root = evidence.record_root();
        self.evidence.insert(evidence_id.clone(), evidence);
        self.emit_event(
            PublicRecordKind::SlashingEvidence,
            evidence_id.clone(),
            root,
        );
        Ok(evidence_id)
    }

    pub fn accept_slashing_evidence(&mut self, evidence_id: &str) -> Result<()> {
        let evidence = self
            .evidence
            .get_mut(evidence_id)
            .ok_or_else(|| "unknown evidence".to_string())?;
        if !matches!(evidence.status, EvidenceStatus::Submitted) {
            return Err("evidence is not pending".to_string());
        }
        evidence.status = EvidenceStatus::Accepted;
        if let Some(member) = self.members.get_mut(&evidence.accused_id) {
            member.bond_micro_units = member
                .bond_micro_units
                .saturating_sub(evidence.slash_amount_micro_units);
            member.slash_count = member.slash_count.saturating_add(1);
            member.status = if member.bond_micro_units == 0 {
                MemberStatus::Slashed
            } else {
                MemberStatus::Jailed
            };
        }
        let root = evidence.record_root();
        self.emit_event(
            PublicRecordKind::SlashingEvidence,
            evidence_id.to_string(),
            root,
        );
        Ok(())
    }

    pub fn settle_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        if !matches!(batch.status, BatchStatus::Sealed | BatchStatus::Attested) {
            return Err("batch is not settleable".to_string());
        }
        batch.status = BatchStatus::Settled;
        batch.settled_height = self.height;
        let result_ids = batch.result_ids.clone();
        for result_id in result_ids {
            if let Some(result) = self.results.get_mut(&result_id) {
                result.status = ResultStatus::Settled;
                result.settled_height = self.height;
                if let Some(request) = self.requests.get_mut(&result.request_id) {
                    request.status = RequestStatus::Settled;
                }
            }
        }
        let root = batch.record_root();
        self.emit_event(PublicRecordKind::Batch, batch_id.to_string(), root);
        Ok(())
    }

    pub fn claim_rebate(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .rebates
            .get_mut(receipt_id)
            .ok_or_else(|| "unknown rebate receipt".to_string())?;
        if self.height > receipt.expires_height {
            receipt.status = RebateStatus::Expired;
            return Err("rebate receipt expired".to_string());
        }
        if !matches!(
            receipt.status,
            RebateStatus::Queued | RebateStatus::Claimable
        ) {
            return Err("rebate is not claimable".to_string());
        }
        receipt.status = RebateStatus::Paid;
        let root = receipt.record_root();
        self.emit_event(PublicRecordKind::Rebate, receipt_id.to_string(), root);
        Ok(())
    }

    pub fn expire_old_records(&mut self) -> usize {
        let mut expired = 0_usize;
        for request in self.requests.values_mut() {
            if request.status.live() && self.height > request.expires_height {
                request.status = RequestStatus::Expired;
                expired += 1;
            }
        }
        for bid in self.bids.values_mut() {
            if matches!(bid.status, BidStatus::Posted | BidStatus::Accepted)
                && self.height > bid.expires_height
            {
                bid.status = BidStatus::Expired;
                expired += 1;
            }
        }
        for fence in self.privacy_fences.values_mut() {
            if fence.active && self.height > fence.expires_height {
                fence.active = false;
                expired += 1;
            }
        }
        for receipt in self.rebates.values_mut() {
            if matches!(
                receipt.status,
                RebateStatus::Queued | RebateStatus::Claimable
            ) && self.height > receipt.expires_height
            {
                receipt.status = RebateStatus::Expired;
                expired += 1;
            }
        }
        for evidence in self.evidence.values_mut() {
            if matches!(evidence.status, EvidenceStatus::Submitted)
                && self.height > evidence.expires_height
            {
                evidence.status = EvidenceStatus::Expired;
                expired += 1;
            }
        }
        expired
    }

    pub fn request_score(&self, request_id: &str) -> Result<u64> {
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| "unknown request".to_string())?;
        let fee_score = fee_bps(request.tip_micro_units, request.max_fee_micro_units.max(1));
        let privacy_score = request.privacy_set_size / self.config.min_privacy_set_size.max(1);
        Ok(request
            .compute_kind
            .base_priority()
            .saturating_add(fee_score)
            .saturating_add(privacy_score))
    }

    pub fn eligible_results_for_batch(&self, limit: usize) -> Vec<String> {
        let mut scored = self
            .results
            .values()
            .filter_map(|result| {
                if !matches!(
                    result.status,
                    ResultStatus::QuorumAccepted | ResultStatus::Committed
                ) {
                    return None;
                }
                let request = self.requests.get(&result.request_id)?;
                let score = request.compute_kind.base_priority().saturating_add(
                    MAX_BPS.saturating_sub(fee_bps(
                        request.max_fee_micro_units,
                        request
                            .max_fee_micro_units
                            .saturating_add(request.tip_micro_units)
                            .max(1),
                    )),
                );
                Some((score, result.committed_height, result.result_id.clone()))
            })
            .collect::<Vec<_>>();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        scored
            .into_iter()
            .take(limit)
            .map(|(_, _, id)| id)
            .collect()
    }

    pub fn deterministic_public_records(&self) -> Vec<Value> {
        let mut records = Vec::new();
        records.extend(self.requests.values().map(|r| r.public_record()));
        records.extend(self.bids.values().map(|r| r.public_record()));
        records.extend(self.members.values().map(|r| r.public_record()));
        records.extend(self.assignments.values().map(|r| r.public_record()));
        records.extend(self.attestations.values().map(|r| r.public_record()));
        records.extend(self.results.values().map(|r| r.public_record()));
        records.extend(self.batches.values().map(|r| r.public_record()));
        records.extend(self.privacy_fences.values().map(|r| r.public_record()));
        records.extend(self.rebates.values().map(|r| r.public_record()));
        records.extend(self.evidence.values().map(|r| r.public_record()));
        records.extend(self.epochs.values().map(|r| r.public_record()));
        records.extend(self.events.iter().map(|r| r.public_record()));
        records
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleComputePolicyProfile00 {
    pub profile_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub required_quorum_bps: u64,
    pub allow_low_fee_batching: bool,
    pub require_rebate_receipt: bool,
    pub public_policy_root: String,
}

impl OracleComputePolicyProfile00 {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "required_quorum_bps": self.required_quorum_bps,
            "allow_low_fee_batching": self.allow_low_fee_batching,
            "require_rebate_receipt": self.require_rebate_receipt,
            "public_policy_root": self.public_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("profile_id", &self.profile_id)?;
        require_hash_like("public_policy_root", &self.public_policy_root)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if !is_valid_bps(self.max_fee_bps) || !is_valid_bps(self.required_quorum_bps) {
            return Err("policy bps out of range".to_string());
        }
        if self.required_quorum_bps < config.quorum_bps {
            return Err("policy quorum below runtime quorum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleComputePolicyProfile01 {
    pub profile_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub required_quorum_bps: u64,
    pub allow_low_fee_batching: bool,
    pub require_rebate_receipt: bool,
    pub public_policy_root: String,
}

impl OracleComputePolicyProfile01 {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "required_quorum_bps": self.required_quorum_bps,
            "allow_low_fee_batching": self.allow_low_fee_batching,
            "require_rebate_receipt": self.require_rebate_receipt,
            "public_policy_root": self.public_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("profile_id", &self.profile_id)?;
        require_hash_like("public_policy_root", &self.public_policy_root)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if !is_valid_bps(self.max_fee_bps) || !is_valid_bps(self.required_quorum_bps) {
            return Err("policy bps out of range".to_string());
        }
        if self.required_quorum_bps < config.quorum_bps {
            return Err("policy quorum below runtime quorum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleComputePolicyProfile02 {
    pub profile_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub required_quorum_bps: u64,
    pub allow_low_fee_batching: bool,
    pub require_rebate_receipt: bool,
    pub public_policy_root: String,
}

impl OracleComputePolicyProfile02 {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "required_quorum_bps": self.required_quorum_bps,
            "allow_low_fee_batching": self.allow_low_fee_batching,
            "require_rebate_receipt": self.require_rebate_receipt,
            "public_policy_root": self.public_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("profile_id", &self.profile_id)?;
        require_hash_like("public_policy_root", &self.public_policy_root)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if !is_valid_bps(self.max_fee_bps) || !is_valid_bps(self.required_quorum_bps) {
            return Err("policy bps out of range".to_string());
        }
        if self.required_quorum_bps < config.quorum_bps {
            return Err("policy quorum below runtime quorum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleComputePolicyProfile03 {
    pub profile_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub required_quorum_bps: u64,
    pub allow_low_fee_batching: bool,
    pub require_rebate_receipt: bool,
    pub public_policy_root: String,
}

impl OracleComputePolicyProfile03 {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "required_quorum_bps": self.required_quorum_bps,
            "allow_low_fee_batching": self.allow_low_fee_batching,
            "require_rebate_receipt": self.require_rebate_receipt,
            "public_policy_root": self.public_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("profile_id", &self.profile_id)?;
        require_hash_like("public_policy_root", &self.public_policy_root)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if !is_valid_bps(self.max_fee_bps) || !is_valid_bps(self.required_quorum_bps) {
            return Err("policy bps out of range".to_string());
        }
        if self.required_quorum_bps < config.quorum_bps {
            return Err("policy quorum below runtime quorum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleComputePolicyProfile04 {
    pub profile_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub required_quorum_bps: u64,
    pub allow_low_fee_batching: bool,
    pub require_rebate_receipt: bool,
    pub public_policy_root: String,
}

impl OracleComputePolicyProfile04 {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "required_quorum_bps": self.required_quorum_bps,
            "allow_low_fee_batching": self.allow_low_fee_batching,
            "require_rebate_receipt": self.require_rebate_receipt,
            "public_policy_root": self.public_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("profile_id", &self.profile_id)?;
        require_hash_like("public_policy_root", &self.public_policy_root)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if !is_valid_bps(self.max_fee_bps) || !is_valid_bps(self.required_quorum_bps) {
            return Err("policy bps out of range".to_string());
        }
        if self.required_quorum_bps < config.quorum_bps {
            return Err("policy quorum below runtime quorum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleComputePolicyProfile05 {
    pub profile_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub required_quorum_bps: u64,
    pub allow_low_fee_batching: bool,
    pub require_rebate_receipt: bool,
    pub public_policy_root: String,
}

impl OracleComputePolicyProfile05 {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "required_quorum_bps": self.required_quorum_bps,
            "allow_low_fee_batching": self.allow_low_fee_batching,
            "require_rebate_receipt": self.require_rebate_receipt,
            "public_policy_root": self.public_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("profile_id", &self.profile_id)?;
        require_hash_like("public_policy_root", &self.public_policy_root)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if !is_valid_bps(self.max_fee_bps) || !is_valid_bps(self.required_quorum_bps) {
            return Err("policy bps out of range".to_string());
        }
        if self.required_quorum_bps < config.quorum_bps {
            return Err("policy quorum below runtime quorum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleComputePolicyProfile06 {
    pub profile_id: String,
    pub compute_kind: OracleComputeKind,
    pub fee_tier: FeeTier,
    pub environment: ComputeEnvironment,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub required_quorum_bps: u64,
    pub allow_low_fee_batching: bool,
    pub require_rebate_receipt: bool,
    pub public_policy_root: String,
}

impl OracleComputePolicyProfile06 {
    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "compute_kind": self.compute_kind.as_str(),
            "fee_tier": self.fee_tier.as_str(),
            "environment": self.environment.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "required_quorum_bps": self.required_quorum_bps,
            "allow_low_fee_batching": self.allow_low_fee_batching,
            "require_rebate_receipt": self.require_rebate_receipt,
            "public_policy_root": self.public_policy_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("profile_id", &self.profile_id)?;
        require_hash_like("public_policy_root", &self.public_policy_root)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy privacy set below runtime minimum".to_string());
        }
        if !is_valid_bps(self.max_fee_bps) || !is_valid_bps(self.required_quorum_bps) {
            return Err("policy bps out of range".to_string());
        }
        if self.required_quorum_bps < config.quorum_bps {
            return Err("policy quorum below runtime quorum".to_string());
        }
        Ok(())
    }
}
