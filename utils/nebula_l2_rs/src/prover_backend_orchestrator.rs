use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ProverBackendOrchestratorResult<T> = Result<T, String>;

pub const PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION: &str =
    "nebula-l2-prover-backend-orchestrator-v1";
pub const PROVER_BACKEND_ORCHESTRATOR_SCHEMA_VERSION: u64 = 1;
pub const PROVER_BACKEND_ORCHESTRATOR_HASH_SUITE: &str = "SHAKE256";
pub const PROVER_BACKEND_ORCHESTRATOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PROVER_BACKEND_ORCHESTRATOR_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PROVER_BACKEND_ORCHESTRATOR_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const PROVER_BACKEND_ORCHESTRATOR_ARTIFACT_SCHEME: &str =
    "shake256-proof-artifact-commitment-v1";
pub const PROVER_BACKEND_ORCHESTRATOR_WITNESS_SCHEME: &str =
    "canonical-json-witness-fetch-manifest-v1";
pub const PROVER_BACKEND_ORCHESTRATOR_RECURSION_SCHEME: &str = "nebula-devnet-recursive-folding-v1";
pub const PROVER_BACKEND_ORCHESTRATOR_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PROVER_BACKEND_ROLLUP_PROOF_SYSTEM: &str = "nebula-devnet-pq-rollup-state-validity-v1";
pub const PROVER_BACKEND_MONERO_BRIDGE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-monero-bridge-validity-v1";
pub const PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-private-contract-validity-v1";
pub const PROVER_BACKEND_FEE_REBATE_PROOF_SYSTEM: &str = "nebula-devnet-pq-fee-rebate-validity-v1";
pub const PROVER_BACKEND_RECURSIVE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-recursive-backend-validity-v1";
pub const PROVER_BACKEND_COMPRESSION_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-proof-compression-validity-v1";
pub const PROVER_BACKEND_WATCHTOWER_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-watchtower-fallback-validity-v1";

pub const PROVER_BACKEND_DEFAULT_LEASE_BLOCKS: u64 = 12;
pub const PROVER_BACKEND_DEFAULT_FETCH_TIMEOUT_BLOCKS: u64 = 4;
pub const PROVER_BACKEND_DEFAULT_PROOF_TIMEOUT_BLOCKS: u64 = 16;
pub const PROVER_BACKEND_DEFAULT_QUARANTINE_BLOCKS: u64 = 96;
pub const PROVER_BACKEND_DEFAULT_RETRY_BACKOFF_BLOCKS: u64 = 3;
pub const PROVER_BACKEND_DEFAULT_MAX_RETRIES: u64 = 3;
pub const PROVER_BACKEND_DEFAULT_MAX_WORKERS: u64 = 2_048;
pub const PROVER_BACKEND_DEFAULT_MAX_LEASES: u64 = 8_192;
pub const PROVER_BACKEND_DEFAULT_MAX_ARTIFACTS: u64 = 16_384;
pub const PROVER_BACKEND_DEFAULT_MAX_BATCH_CHILDREN: u64 = 64;
pub const PROVER_BACKEND_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 128;
pub const PROVER_BACKEND_DEFAULT_LOW_FEE_FLOOR_UNITS: u64 = 4;
pub const PROVER_BACKEND_DEFAULT_PROTOCOL_FEE_BPS: u64 = 250;
pub const PROVER_BACKEND_DEFAULT_SPONSOR_REBATE_BPS: u64 = 1_500;
pub const PROVER_BACKEND_DEFAULT_STALE_HEARTBEAT_BLOCKS: u64 = 24;
pub const PROVER_BACKEND_MAX_BPS: u64 = 10_000;

pub const PROVER_BACKEND_STATUS_REGISTERED: &str = "registered";
pub const PROVER_BACKEND_STATUS_ACTIVE: &str = "active";
pub const PROVER_BACKEND_STATUS_DRAINING: &str = "draining";
pub const PROVER_BACKEND_STATUS_QUARANTINED: &str = "quarantined";
pub const PROVER_BACKEND_STATUS_OFFLINE: &str = "offline";
pub const PROVER_BACKEND_STATUS_RETIRED: &str = "retired";
pub const PROVER_BACKEND_STATUS_PENDING: &str = "pending";
pub const PROVER_BACKEND_STATUS_READY: &str = "ready";
pub const PROVER_BACKEND_STATUS_ASSIGNED: &str = "assigned";
pub const PROVER_BACKEND_STATUS_EXPIRED: &str = "expired";
pub const PROVER_BACKEND_STATUS_REVOKED: &str = "revoked";
pub const PROVER_BACKEND_STATUS_OFFERED: &str = "offered";
pub const PROVER_BACKEND_STATUS_SUBMITTED: &str = "submitted";
pub const PROVER_BACKEND_STATUS_COMPLETED: &str = "completed";
pub const PROVER_BACKEND_STATUS_TIMED_OUT: &str = "timed_out";
pub const PROVER_BACKEND_STATUS_RETRIED: &str = "retried";
pub const PROVER_BACKEND_STATUS_CANCELLED: &str = "cancelled";
pub const PROVER_BACKEND_STATUS_OPEN: &str = "open";
pub const PROVER_BACKEND_STATUS_LOCKED: &str = "locked";
pub const PROVER_BACKEND_STATUS_PROVING: &str = "proving";
pub const PROVER_BACKEND_STATUS_PROVED: &str = "proved";
pub const PROVER_BACKEND_STATUS_VERIFIED: &str = "verified";
pub const PROVER_BACKEND_STATUS_REJECTED: &str = "rejected";
pub const PROVER_BACKEND_STATUS_FAILED: &str = "failed";
pub const PROVER_BACKEND_STATUS_STORED: &str = "stored";
pub const PROVER_BACKEND_STATUS_ACCEPTED: &str = "accepted";
pub const PROVER_BACKEND_STATUS_NEEDS_RETRY: &str = "needs_retry";
pub const PROVER_BACKEND_STATUS_DRAFT: &str = "draft";
pub const PROVER_BACKEND_STATUS_RELEASED: &str = "released";
pub const PROVER_BACKEND_STATUS_ESCALATED: &str = "escalated";
pub const PROVER_BACKEND_STATUS_PLEDGED: &str = "pledged";
pub const PROVER_BACKEND_STATUS_RESERVED: &str = "reserved";
pub const PROVER_BACKEND_STATUS_APPLIED: &str = "applied";
pub const PROVER_BACKEND_STATUS_EXHAUSTED: &str = "exhausted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendWorkerClass {
    Cpu,
    Gpu,
    Hybrid,
    Aggregator,
    Verifier,
    Watchtower,
}

impl BackendWorkerClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Hybrid => "hybrid",
            Self::Aggregator => "aggregator",
            Self::Verifier => "verifier",
            Self::Watchtower => "watchtower",
        }
    }

    pub fn capacity_weight(self) -> u64 {
        match self {
            Self::Cpu => 1,
            Self::Gpu => 8,
            Self::Hybrid => 6,
            Self::Aggregator => 10,
            Self::Verifier => 3,
            Self::Watchtower => 2,
        }
    }

    pub fn has_gpu_capacity(self) -> bool {
        matches!(self, Self::Gpu | Self::Hybrid | Self::Aggregator)
    }

    pub fn can_verify(self) -> bool {
        matches!(self, Self::Verifier | Self::Watchtower | Self::Aggregator)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRegistryStatus {
    Registered,
    Active,
    Draining,
    Quarantined,
    Offline,
    Retired,
}

impl WorkerRegistryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => PROVER_BACKEND_STATUS_REGISTERED,
            Self::Active => PROVER_BACKEND_STATUS_ACTIVE,
            Self::Draining => PROVER_BACKEND_STATUS_DRAINING,
            Self::Quarantined => PROVER_BACKEND_STATUS_QUARANTINED,
            Self::Offline => PROVER_BACKEND_STATUS_OFFLINE,
            Self::Retired => PROVER_BACKEND_STATUS_RETIRED,
        }
    }

    pub fn accepts_leases(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthenticationStatus {
    Pending,
    Active,
    Expired,
    Revoked,
}

impl PqAuthenticationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => PROVER_BACKEND_STATUS_PENDING,
            Self::Active => PROVER_BACKEND_STATUS_ACTIVE,
            Self::Expired => PROVER_BACKEND_STATUS_EXPIRED,
            Self::Revoked => PROVER_BACKEND_STATUS_REVOKED,
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackendJobKind {
    RollupValidity,
    MoneroBridge,
    PrivateContract,
    FeeRebateAccounting,
    RecursiveAggregation,
    ProofCompression,
    WatchtowerFallback,
}

impl ProofBackendJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupValidity => "rollup_validity",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateContract => "private_contract",
            Self::FeeRebateAccounting => "fee_rebate_accounting",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::ProofCompression => "proof_compression",
            Self::WatchtowerFallback => "watchtower_fallback",
        }
    }

    pub fn default_proof_system(self) -> &'static str {
        match self {
            Self::RollupValidity => PROVER_BACKEND_ROLLUP_PROOF_SYSTEM,
            Self::MoneroBridge => PROVER_BACKEND_MONERO_BRIDGE_PROOF_SYSTEM,
            Self::PrivateContract => PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM,
            Self::FeeRebateAccounting => PROVER_BACKEND_FEE_REBATE_PROOF_SYSTEM,
            Self::RecursiveAggregation => PROVER_BACKEND_RECURSIVE_PROOF_SYSTEM,
            Self::ProofCompression => PROVER_BACKEND_COMPRESSION_PROOF_SYSTEM,
            Self::WatchtowerFallback => PROVER_BACKEND_WATCHTOWER_PROOF_SYSTEM,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MoneroBridge | Self::PrivateContract | Self::FeeRebateAccounting
        )
    }

    pub fn recursive(self) -> bool {
        matches!(self, Self::RecursiveAggregation | Self::ProofCompression)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackendPriority {
    Emergency,
    BridgeExit,
    InteractivePrivate,
    PublicRollup,
    SponsoredLowFee,
    RecursiveMaintenance,
}

impl ProofBackendPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::BridgeExit => "bridge_exit",
            Self::InteractivePrivate => "interactive_private",
            Self::PublicRollup => "public_rollup",
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::RecursiveMaintenance => "recursive_maintenance",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::BridgeExit => 9_200,
            Self::InteractivePrivate => 8_500,
            Self::PublicRollup => 6_800,
            Self::SponsoredLowFee => 6_200,
            Self::RecursiveMaintenance => 3_500,
        }
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(self, Self::SponsoredLowFee | Self::RecursiveMaintenance)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyStatus {
    Active,
    Rotating,
    Revoked,
    Expired,
}

impl VerifierKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => PROVER_BACKEND_STATUS_ACTIVE,
            Self::Rotating => "rotating",
            Self::Revoked => PROVER_BACKEND_STATUS_REVOKED,
            Self::Expired => PROVER_BACKEND_STATUS_EXPIRED,
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessManifestStatus {
    Pending,
    Ready,
    Assigned,
    Expired,
    Revoked,
}

impl WitnessManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => PROVER_BACKEND_STATUS_PENDING,
            Self::Ready => PROVER_BACKEND_STATUS_READY,
            Self::Assigned => PROVER_BACKEND_STATUS_ASSIGNED,
            Self::Expired => PROVER_BACKEND_STATUS_EXPIRED,
            Self::Revoked => PROVER_BACKEND_STATUS_REVOKED,
        }
    }

    pub fn fetchable(self) -> bool {
        matches!(self, Self::Ready | Self::Assigned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeQuoteStatus {
    Quoted,
    Reserved,
    Applied,
    Expired,
    Cancelled,
}

impl FeeQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => PROVER_BACKEND_STATUS_RESERVED,
            Self::Applied => PROVER_BACKEND_STATUS_APPLIED,
            Self::Expired => PROVER_BACKEND_STATUS_EXPIRED,
            Self::Cancelled => PROVER_BACKEND_STATUS_CANCELLED,
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Quoted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLeaseStatus {
    Offered,
    Active,
    Submitted,
    Completed,
    TimedOut,
    Retried,
    Cancelled,
    Quarantined,
}

impl ProofLeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => PROVER_BACKEND_STATUS_OFFERED,
            Self::Active => PROVER_BACKEND_STATUS_ACTIVE,
            Self::Submitted => PROVER_BACKEND_STATUS_SUBMITTED,
            Self::Completed => PROVER_BACKEND_STATUS_COMPLETED,
            Self::TimedOut => PROVER_BACKEND_STATUS_TIMED_OUT,
            Self::Retried => PROVER_BACKEND_STATUS_RETRIED,
            Self::Cancelled => PROVER_BACKEND_STATUS_CANCELLED,
            Self::Quarantined => PROVER_BACKEND_STATUS_QUARANTINED,
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Offered | Self::Active | Self::Submitted)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::TimedOut | Self::Retried | Self::Cancelled | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationBatchStatus {
    Open,
    Locked,
    Proving,
    Proved,
    Verified,
    Failed,
    Cancelled,
}

impl AggregationBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => PROVER_BACKEND_STATUS_OPEN,
            Self::Locked => PROVER_BACKEND_STATUS_LOCKED,
            Self::Proving => PROVER_BACKEND_STATUS_PROVING,
            Self::Proved => PROVER_BACKEND_STATUS_PROVED,
            Self::Verified => PROVER_BACKEND_STATUS_VERIFIED,
            Self::Failed => PROVER_BACKEND_STATUS_FAILED,
            Self::Cancelled => PROVER_BACKEND_STATUS_CANCELLED,
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Locked | Self::Proving)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCommitmentKind {
    Proof,
    RecursiveProof,
    CompressedProof,
    WitnessBundle,
    Transcript,
    VerifierKey,
}

impl ArtifactCommitmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proof => "proof",
            Self::RecursiveProof => "recursive_proof",
            Self::CompressedProof => "compressed_proof",
            Self::WitnessBundle => "witness_bundle",
            Self::Transcript => "transcript",
            Self::VerifierKey => "verifier_key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCommitmentStatus {
    Submitted,
    Stored,
    Verified,
    Rejected,
    Quarantined,
}

impl ArtifactCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => PROVER_BACKEND_STATUS_SUBMITTED,
            Self::Stored => PROVER_BACKEND_STATUS_STORED,
            Self::Verified => PROVER_BACKEND_STATUS_VERIFIED,
            Self::Rejected => PROVER_BACKEND_STATUS_REJECTED,
            Self::Quarantined => PROVER_BACKEND_STATUS_QUARANTINED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Accepted,
    Rejected,
    NeedsRetry,
    Quarantined,
}

impl VerificationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => PROVER_BACKEND_STATUS_ACCEPTED,
            Self::Rejected => PROVER_BACKEND_STATUS_REJECTED,
            Self::NeedsRetry => PROVER_BACKEND_STATUS_NEEDS_RETRY,
            Self::Quarantined => PROVER_BACKEND_STATUS_QUARANTINED,
        }
    }

    pub fn status(self) -> &'static str {
        match self {
            Self::Accepted => PROVER_BACKEND_STATUS_VERIFIED,
            Self::Rejected => PROVER_BACKEND_STATUS_REJECTED,
            Self::NeedsRetry => PROVER_BACKEND_STATUS_RETRIED,
            Self::Quarantined => PROVER_BACKEND_STATUS_QUARANTINED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    RetrySameWorker,
    RetryDifferentWorker,
    QuarantineWorker,
    AbortJob,
    SponsorAndRetry,
}

impl RetryDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetrySameWorker => "retry_same_worker",
            Self::RetryDifferentWorker => "retry_different_worker",
            Self::QuarantineWorker => "quarantine_worker",
            Self::AbortJob => "abort_job",
            Self::SponsorAndRetry => "sponsor_and_retry",
        }
    }

    pub fn status(self) -> &'static str {
        match self {
            Self::RetrySameWorker | Self::RetryDifferentWorker | Self::SponsorAndRetry => {
                PROVER_BACKEND_STATUS_RETRIED
            }
            Self::QuarantineWorker => PROVER_BACKEND_STATUS_QUARANTINED,
            Self::AbortJob => PROVER_BACKEND_STATUS_FAILED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryPolicyStatus {
    Draft,
    Active,
    Retired,
}

impl RetryPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => PROVER_BACKEND_STATUS_DRAFT,
            Self::Active => PROVER_BACKEND_STATUS_ACTIVE,
            Self::Retired => PROVER_BACKEND_STATUS_RETIRED,
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Active,
    Released,
    Escalated,
    Expired,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => PROVER_BACKEND_STATUS_ACTIVE,
            Self::Released => PROVER_BACKEND_STATUS_RELEASED,
            Self::Escalated => PROVER_BACKEND_STATUS_ESCALATED,
            Self::Expired => PROVER_BACKEND_STATUS_EXPIRED,
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Active | Self::Escalated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Pledged,
    Reserved,
    Applied,
    Exhausted,
    Cancelled,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pledged => PROVER_BACKEND_STATUS_PLEDGED,
            Self::Reserved => PROVER_BACKEND_STATUS_RESERVED,
            Self::Applied => PROVER_BACKEND_STATUS_APPLIED,
            Self::Exhausted => PROVER_BACKEND_STATUS_EXHAUSTED,
            Self::Cancelled => PROVER_BACKEND_STATUS_CANCELLED,
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Pledged | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBackendPolicy {
    pub protocol_version: String,
    pub schema_version: u64,
    pub lease_blocks: u64,
    pub fetch_timeout_blocks: u64,
    pub proof_timeout_blocks: u64,
    pub quarantine_blocks: u64,
    pub retry_backoff_blocks: u64,
    pub max_retries: u64,
    pub max_workers: u64,
    pub max_leases: u64,
    pub max_artifacts: u64,
    pub max_batch_children: u64,
    pub min_pq_security_bits: u64,
    pub low_fee_floor_units: u64,
    pub protocol_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub stale_heartbeat_blocks: u64,
    pub pq_signature_scheme: String,
    pub pq_recovery_scheme: String,
    pub pq_kem_scheme: String,
    pub default_fee_asset_id: String,
}

impl Default for ProverBackendPolicy {
    fn default() -> Self {
        Self {
            protocol_version: PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION.to_string(),
            schema_version: PROVER_BACKEND_ORCHESTRATOR_SCHEMA_VERSION,
            lease_blocks: PROVER_BACKEND_DEFAULT_LEASE_BLOCKS,
            fetch_timeout_blocks: PROVER_BACKEND_DEFAULT_FETCH_TIMEOUT_BLOCKS,
            proof_timeout_blocks: PROVER_BACKEND_DEFAULT_PROOF_TIMEOUT_BLOCKS,
            quarantine_blocks: PROVER_BACKEND_DEFAULT_QUARANTINE_BLOCKS,
            retry_backoff_blocks: PROVER_BACKEND_DEFAULT_RETRY_BACKOFF_BLOCKS,
            max_retries: PROVER_BACKEND_DEFAULT_MAX_RETRIES,
            max_workers: PROVER_BACKEND_DEFAULT_MAX_WORKERS,
            max_leases: PROVER_BACKEND_DEFAULT_MAX_LEASES,
            max_artifacts: PROVER_BACKEND_DEFAULT_MAX_ARTIFACTS,
            max_batch_children: PROVER_BACKEND_DEFAULT_MAX_BATCH_CHILDREN,
            min_pq_security_bits: PROVER_BACKEND_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_floor_units: PROVER_BACKEND_DEFAULT_LOW_FEE_FLOOR_UNITS,
            protocol_fee_bps: PROVER_BACKEND_DEFAULT_PROTOCOL_FEE_BPS,
            sponsor_rebate_bps: PROVER_BACKEND_DEFAULT_SPONSOR_REBATE_BPS,
            stale_heartbeat_blocks: PROVER_BACKEND_DEFAULT_STALE_HEARTBEAT_BLOCKS,
            pq_signature_scheme: PROVER_BACKEND_ORCHESTRATOR_PQ_SIGNATURE_SCHEME.to_string(),
            pq_recovery_scheme: PROVER_BACKEND_ORCHESTRATOR_PQ_RECOVERY_SCHEME.to_string(),
            pq_kem_scheme: PROVER_BACKEND_ORCHESTRATOR_PQ_KEM_SCHEME.to_string(),
            default_fee_asset_id: PROVER_BACKEND_ORCHESTRATOR_DEFAULT_FEE_ASSET_ID.to_string(),
        }
    }
}

impl ProverBackendPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_backend_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": PROVER_BACKEND_ORCHESTRATOR_HASH_SUITE,
            "lease_blocks": self.lease_blocks,
            "fetch_timeout_blocks": self.fetch_timeout_blocks,
            "proof_timeout_blocks": self.proof_timeout_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "retry_backoff_blocks": self.retry_backoff_blocks,
            "max_retries": self.max_retries,
            "max_workers": self.max_workers,
            "max_leases": self.max_leases,
            "max_artifacts": self.max_artifacts,
            "max_batch_children": self.max_batch_children,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_floor_units": self.low_fee_floor_units,
            "protocol_fee_bps": self.protocol_fee_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "stale_heartbeat_blocks": self.stale_heartbeat_blocks,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_recovery_scheme": self.pq_recovery_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "default_fee_asset_id": self.default_fee_asset_id,
        })
    }

    pub fn policy_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.protocol_version, "prover backend protocol version")?;
        ensure_non_empty(
            &self.pq_signature_scheme,
            "prover backend PQ signature scheme",
        )?;
        ensure_non_empty(
            &self.pq_recovery_scheme,
            "prover backend PQ recovery scheme",
        )?;
        ensure_non_empty(&self.pq_kem_scheme, "prover backend PQ KEM scheme")?;
        ensure_non_empty(&self.default_fee_asset_id, "prover backend fee asset id")?;
        ensure_positive(self.schema_version, "prover backend schema version")?;
        ensure_positive(self.lease_blocks, "prover backend lease blocks")?;
        ensure_positive(
            self.fetch_timeout_blocks,
            "prover backend fetch timeout blocks",
        )?;
        ensure_positive(
            self.proof_timeout_blocks,
            "prover backend proof timeout blocks",
        )?;
        ensure_positive(self.quarantine_blocks, "prover backend quarantine blocks")?;
        ensure_positive(self.max_workers, "prover backend max workers")?;
        ensure_positive(self.max_leases, "prover backend max leases")?;
        ensure_positive(self.max_artifacts, "prover backend max artifacts")?;
        ensure_positive(self.max_batch_children, "prover backend max batch children")?;
        ensure_positive(
            self.min_pq_security_bits,
            "prover backend minimum PQ security bits",
        )?;
        ensure_bps(self.protocol_fee_bps, "prover backend protocol fee bps")?;
        ensure_bps(self.sponsor_rebate_bps, "prover backend sponsor rebate bps")?;
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBackendWorker {
    pub worker_id: String,
    pub operator_id: String,
    pub worker_label: String,
    pub worker_class: BackendWorkerClass,
    pub status: WorkerRegistryStatus,
    pub pq_signature_scheme: String,
    pub pq_public_key_root: String,
    pub pq_attestation_root: String,
    pub supported_proof_systems: Vec<String>,
    pub region: String,
    pub registered_at_height: u64,
    pub last_heartbeat_height: u64,
    pub quarantine_until_height: u64,
    pub max_parallel_leases: u64,
    pub nonce: u64,
}

impl ProverBackendWorker {
    pub fn new(
        operator_id: impl Into<String>,
        worker_label: impl Into<String>,
        worker_class: BackendWorkerClass,
        supported_proof_systems: &[String],
        pq_public_key_root: impl Into<String>,
        pq_attestation_root: impl Into<String>,
        region: impl Into<String>,
        registered_at_height: u64,
        max_parallel_leases: u64,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let operator_id = operator_id.into();
        let worker_label = worker_label.into();
        let pq_public_key_root = pq_public_key_root.into();
        let pq_attestation_root = pq_attestation_root.into();
        let region = region.into();
        ensure_non_empty(&operator_id, "prover backend worker operator id")?;
        ensure_non_empty(&worker_label, "prover backend worker label")?;
        ensure_non_empty(&pq_public_key_root, "prover backend worker PQ key root")?;
        ensure_non_empty(
            &pq_attestation_root,
            "prover backend worker PQ attestation root",
        )?;
        ensure_non_empty(&region, "prover backend worker region")?;
        ensure_positive(max_parallel_leases, "prover backend worker parallel leases")?;
        let supported_proof_systems = normalize_nonempty_strings(
            supported_proof_systems,
            "prover backend worker proof systems",
        )?;
        let worker_id = prover_backend_worker_id(&operator_id, &worker_label, nonce);
        Ok(Self {
            worker_id,
            operator_id,
            worker_label,
            worker_class,
            status: WorkerRegistryStatus::Registered,
            pq_signature_scheme: PROVER_BACKEND_ORCHESTRATOR_PQ_SIGNATURE_SCHEME.to_string(),
            pq_public_key_root,
            pq_attestation_root,
            supported_proof_systems,
            region,
            registered_at_height,
            last_heartbeat_height: registered_at_height,
            quarantine_until_height: 0,
            max_parallel_leases,
            nonce,
        })
    }

    pub fn supports(&self, proof_system: &str) -> bool {
        self.supported_proof_systems
            .iter()
            .any(|supported| supported == proof_system)
    }

    pub fn is_available_at(&self, height: u64, stale_heartbeat_blocks: u64) -> bool {
        self.status.accepts_leases()
            && height >= self.quarantine_until_height
            && self
                .last_heartbeat_height
                .saturating_add(stale_heartbeat_blocks)
                >= height
    }

    pub fn is_quarantined_at(&self, height: u64) -> bool {
        self.status == WorkerRegistryStatus::Quarantined || height < self.quarantine_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_backend_worker",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "worker_id": self.worker_id,
            "operator_id": self.operator_id,
            "worker_label": self.worker_label,
            "worker_class": self.worker_class.as_str(),
            "status": self.status.as_str(),
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_attestation_root": self.pq_attestation_root,
            "supported_proof_systems": self.supported_proof_systems,
            "supported_proof_system_root": prover_backend_string_set_root(
                "PROVER-BACKEND-WORKER-PROOF-SYSTEMS",
                &self.supported_proof_systems
            ),
            "region": self.region,
            "registered_at_height": self.registered_at_height,
            "last_heartbeat_height": self.last_heartbeat_height,
            "quarantine_until_height": self.quarantine_until_height,
            "max_parallel_leases": self.max_parallel_leases,
            "nonce": self.nonce,
        })
    }

    pub fn worker_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-WORKER", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.worker_id, "prover backend worker id")?;
        ensure_non_empty(&self.operator_id, "prover backend worker operator id")?;
        ensure_non_empty(&self.worker_label, "prover backend worker label")?;
        ensure_non_empty(&self.pq_signature_scheme, "prover backend worker PQ scheme")?;
        ensure_non_empty(
            &self.pq_public_key_root,
            "prover backend worker PQ key root",
        )?;
        ensure_non_empty(
            &self.pq_attestation_root,
            "prover backend worker PQ attestation root",
        )?;
        ensure_non_empty(&self.region, "prover backend worker region")?;
        ensure_positive(self.max_parallel_leases, "prover backend worker max leases")?;
        if self.supported_proof_systems.is_empty() {
            return Err("prover backend worker requires proof systems".to_string());
        }
        let worker_id = prover_backend_worker_id(&self.operator_id, &self.worker_label, self.nonce);
        if self.worker_id != worker_id {
            return Err("prover backend worker id mismatch".to_string());
        }
        Ok(self.worker_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWorkerAuthentication {
    pub authentication_id: String,
    pub worker_id: String,
    pub session_key_commitment: String,
    pub auth_transcript_root: String,
    pub pq_signature_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub issued_at_height: u64,
    pub status: PqAuthenticationStatus,
    pub nonce: u64,
}

impl PqWorkerAuthentication {
    pub fn new(
        worker_id: impl Into<String>,
        session_key_commitment: impl Into<String>,
        auth_transcript_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        valid_from_height: u64,
        valid_until_height: u64,
        issued_at_height: u64,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let worker_id = worker_id.into();
        let session_key_commitment = session_key_commitment.into();
        let auth_transcript_root = auth_transcript_root.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&worker_id, "PQ worker authentication worker id")?;
        ensure_non_empty(
            &session_key_commitment,
            "PQ worker authentication session key commitment",
        )?;
        ensure_non_empty(
            &auth_transcript_root,
            "PQ worker authentication transcript root",
        )?;
        ensure_non_empty(
            &pq_signature_root,
            "PQ worker authentication signature root",
        )?;
        ensure_window(
            valid_from_height,
            valid_until_height,
            "PQ worker authentication validity",
        )?;
        let authentication_id = prover_backend_pq_authentication_id(
            &worker_id,
            &session_key_commitment,
            valid_from_height,
            valid_until_height,
            nonce,
        );
        Ok(Self {
            authentication_id,
            worker_id,
            session_key_commitment,
            auth_transcript_root,
            pq_signature_root,
            valid_from_height,
            valid_until_height,
            issued_at_height,
            status: PqAuthenticationStatus::Pending,
            nonce,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.usable()
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_worker_authentication",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "authentication_id": self.authentication_id,
            "worker_id": self.worker_id,
            "session_key_commitment": self.session_key_commitment,
            "auth_transcript_root": self.auth_transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_signature_scheme": PROVER_BACKEND_ORCHESTRATOR_PQ_SIGNATURE_SCHEME,
            "pq_kem_scheme": PROVER_BACKEND_ORCHESTRATOR_PQ_KEM_SCHEME,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "issued_at_height": self.issued_at_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn authentication_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-PQ-AUTHENTICATION", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.authentication_id, "PQ worker authentication id")?;
        ensure_non_empty(&self.worker_id, "PQ worker authentication worker id")?;
        ensure_non_empty(
            &self.session_key_commitment,
            "PQ worker authentication session key commitment",
        )?;
        ensure_non_empty(
            &self.auth_transcript_root,
            "PQ worker authentication transcript root",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "PQ worker authentication signature root",
        )?;
        ensure_window(
            self.valid_from_height,
            self.valid_until_height,
            "PQ worker authentication validity",
        )?;
        if self.issued_at_height > self.valid_until_height {
            return Err("PQ worker authentication issued after validity".to_string());
        }
        let authentication_id = prover_backend_pq_authentication_id(
            &self.worker_id,
            &self.session_key_commitment,
            self.valid_from_height,
            self.valid_until_height,
            self.nonce,
        );
        if self.authentication_id != authentication_id {
            return Err("PQ worker authentication id mismatch".to_string());
        }
        Ok(self.authentication_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapacitySnapshot {
    pub capacity_id: String,
    pub worker_id: String,
    pub worker_class: BackendWorkerClass,
    pub measured_at_height: u64,
    pub cpu_threads: u64,
    pub gpu_devices: u64,
    pub gpu_memory_mib: u64,
    pub cpu_compute_units: u64,
    pub gpu_compute_units: u64,
    pub reserved_compute_units: u64,
    pub max_parallel_slots: u64,
    pub active_leases: u64,
    pub queue_depth: u64,
    pub thermal_limit_bps: u64,
    pub nonce: u64,
}

impl WorkerCapacitySnapshot {
    pub fn new(
        worker_id: impl Into<String>,
        worker_class: BackendWorkerClass,
        measured_at_height: u64,
        cpu_threads: u64,
        gpu_devices: u64,
        gpu_memory_mib: u64,
        cpu_compute_units: u64,
        gpu_compute_units: u64,
        reserved_compute_units: u64,
        max_parallel_slots: u64,
        active_leases: u64,
        queue_depth: u64,
        thermal_limit_bps: u64,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let worker_id = worker_id.into();
        ensure_non_empty(&worker_id, "worker capacity worker id")?;
        ensure_positive(max_parallel_slots, "worker capacity max parallel slots")?;
        ensure_bps(thermal_limit_bps, "worker capacity thermal limit bps")?;
        let capacity_id =
            prover_backend_capacity_id(&worker_id, measured_at_height, worker_class, nonce);
        let snapshot = Self {
            capacity_id,
            worker_id,
            worker_class,
            measured_at_height,
            cpu_threads,
            gpu_devices,
            gpu_memory_mib,
            cpu_compute_units,
            gpu_compute_units,
            reserved_compute_units,
            max_parallel_slots,
            active_leases,
            queue_depth,
            thermal_limit_bps,
            nonce,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn total_compute_units(&self) -> u64 {
        self.cpu_compute_units
            .saturating_add(self.gpu_compute_units)
            .saturating_mul(self.worker_class.capacity_weight())
            .saturating_mul(self.thermal_limit_bps)
            .saturating_div(PROVER_BACKEND_MAX_BPS)
    }

    pub fn available_compute_units(&self) -> u64 {
        self.total_compute_units()
            .saturating_sub(self.reserved_compute_units)
    }

    pub fn utilization_bps(&self) -> u64 {
        let total = self.total_compute_units();
        if total == 0 {
            return 0;
        }
        self.reserved_compute_units
            .saturating_mul(PROVER_BACKEND_MAX_BPS)
            .saturating_div(total)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "worker_capacity_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "capacity_id": self.capacity_id,
            "worker_id": self.worker_id,
            "worker_class": self.worker_class.as_str(),
            "measured_at_height": self.measured_at_height,
            "cpu_threads": self.cpu_threads,
            "gpu_devices": self.gpu_devices,
            "gpu_memory_mib": self.gpu_memory_mib,
            "cpu_compute_units": self.cpu_compute_units,
            "gpu_compute_units": self.gpu_compute_units,
            "total_compute_units": self.total_compute_units(),
            "reserved_compute_units": self.reserved_compute_units,
            "available_compute_units": self.available_compute_units(),
            "utilization_bps": self.utilization_bps(),
            "max_parallel_slots": self.max_parallel_slots,
            "active_leases": self.active_leases,
            "queue_depth": self.queue_depth,
            "thermal_limit_bps": self.thermal_limit_bps,
            "nonce": self.nonce,
        })
    }

    pub fn capacity_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-CAPACITY", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.capacity_id, "worker capacity id")?;
        ensure_non_empty(&self.worker_id, "worker capacity worker id")?;
        ensure_positive(self.max_parallel_slots, "worker capacity max slots")?;
        ensure_bps(self.thermal_limit_bps, "worker capacity thermal bps")?;
        if self.cpu_threads == 0 && self.gpu_devices == 0 {
            return Err("worker capacity requires CPU threads or GPU devices".to_string());
        }
        if self.cpu_compute_units == 0 && self.gpu_compute_units == 0 {
            return Err("worker capacity requires compute units".to_string());
        }
        if self.active_leases > self.max_parallel_slots {
            return Err("worker capacity active leases exceed slots".to_string());
        }
        if self.reserved_compute_units > self.total_compute_units() {
            return Err("worker capacity reserved units exceed total".to_string());
        }
        if self.worker_class.has_gpu_capacity() && self.gpu_devices == 0 {
            return Err("GPU-capable worker capacity requires GPU devices".to_string());
        }
        let capacity_id = prover_backend_capacity_id(
            &self.worker_id,
            self.measured_at_height,
            self.worker_class,
            self.nonce,
        );
        if self.capacity_id != capacity_id {
            return Err("worker capacity id mismatch".to_string());
        }
        Ok(self.capacity_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKeyRecord {
    pub key_id: String,
    pub proof_system: String,
    pub circuit_version: String,
    pub verifier_key_root: String,
    pub key_format: String,
    pub recursion_compatible: bool,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
    pub publisher_worker_id: String,
    pub pq_signature_root: String,
    pub status: VerifierKeyStatus,
    pub nonce: u64,
}

impl VerifierKeyRecord {
    pub fn new(
        proof_system: impl Into<String>,
        circuit_version: impl Into<String>,
        verifier_key_root: impl Into<String>,
        key_format: impl Into<String>,
        recursion_compatible: bool,
        effective_from_height: u64,
        expires_at_height: u64,
        publisher_worker_id: impl Into<String>,
        pq_signature_root: impl Into<String>,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let proof_system = proof_system.into();
        let circuit_version = circuit_version.into();
        let verifier_key_root = verifier_key_root.into();
        let key_format = key_format.into();
        let publisher_worker_id = publisher_worker_id.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&proof_system, "verifier key proof system")?;
        ensure_non_empty(&circuit_version, "verifier key circuit version")?;
        ensure_non_empty(&verifier_key_root, "verifier key root")?;
        ensure_non_empty(&key_format, "verifier key format")?;
        ensure_non_empty(&publisher_worker_id, "verifier key publisher worker id")?;
        ensure_non_empty(&pq_signature_root, "verifier key PQ signature root")?;
        ensure_window(
            effective_from_height,
            expires_at_height,
            "verifier key validity",
        )?;
        let key_id = prover_backend_verifier_key_id(
            &proof_system,
            &circuit_version,
            &verifier_key_root,
            nonce,
        );
        Ok(Self {
            key_id,
            proof_system,
            circuit_version,
            verifier_key_root,
            key_format,
            recursion_compatible,
            effective_from_height,
            expires_at_height,
            publisher_worker_id,
            pq_signature_root,
            status: VerifierKeyStatus::Active,
            nonce,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.usable()
            && height >= self.effective_from_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_key_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "key_id": self.key_id,
            "proof_system": self.proof_system,
            "circuit_version": self.circuit_version,
            "verifier_key_root": self.verifier_key_root,
            "key_format": self.key_format,
            "recursion_compatible": self.recursion_compatible,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
            "publisher_worker_id": self.publisher_worker_id,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn key_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-VERIFIER-KEY", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.key_id, "verifier key id")?;
        ensure_non_empty(&self.proof_system, "verifier key proof system")?;
        ensure_non_empty(&self.circuit_version, "verifier key circuit version")?;
        ensure_non_empty(&self.verifier_key_root, "verifier key root")?;
        ensure_non_empty(&self.key_format, "verifier key format")?;
        ensure_non_empty(
            &self.publisher_worker_id,
            "verifier key publisher worker id",
        )?;
        ensure_non_empty(&self.pq_signature_root, "verifier key signature root")?;
        ensure_window(
            self.effective_from_height,
            self.expires_at_height,
            "verifier key validity",
        )?;
        let key_id = prover_backend_verifier_key_id(
            &self.proof_system,
            &self.circuit_version,
            &self.verifier_key_root,
            self.nonce,
        );
        if self.key_id != key_id {
            return Err("verifier key id mismatch".to_string());
        }
        Ok(self.key_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFetchManifest {
    pub manifest_id: String,
    pub job_id: String,
    pub job_kind: ProofBackendJobKind,
    pub proof_system: String,
    pub witness_root: String,
    pub public_input_root: String,
    pub private_input_commitment: String,
    pub source_manifest_root: String,
    pub fetch_uri_commitments: Vec<String>,
    pub access_policy_root: String,
    pub encryption_key_commitment: String,
    pub required_worker_class: BackendWorkerClass,
    pub created_at_height: u64,
    pub fetch_deadline_height: u64,
    pub status: WitnessManifestStatus,
    pub nonce: u64,
}

impl WitnessFetchManifest {
    pub fn new(
        job_id: impl Into<String>,
        job_kind: ProofBackendJobKind,
        proof_system: impl Into<String>,
        witness_root: impl Into<String>,
        public_input_root: impl Into<String>,
        private_input_commitment: impl Into<String>,
        source_manifest_root: impl Into<String>,
        fetch_uri_commitments: &[String],
        access_policy_root: impl Into<String>,
        encryption_key_commitment: impl Into<String>,
        required_worker_class: BackendWorkerClass,
        created_at_height: u64,
        fetch_deadline_height: u64,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let job_id = job_id.into();
        let proof_system = normalize_proof_system(proof_system.into(), job_kind);
        let witness_root = witness_root.into();
        let public_input_root = public_input_root.into();
        let private_input_commitment = private_input_commitment.into();
        let source_manifest_root = source_manifest_root.into();
        let access_policy_root = access_policy_root.into();
        let encryption_key_commitment = encryption_key_commitment.into();
        ensure_non_empty(&job_id, "witness fetch manifest job id")?;
        ensure_non_empty(&proof_system, "witness fetch manifest proof system")?;
        ensure_non_empty(&witness_root, "witness fetch manifest witness root")?;
        ensure_non_empty(
            &public_input_root,
            "witness fetch manifest public input root",
        )?;
        ensure_non_empty(
            &private_input_commitment,
            "witness fetch manifest private input commitment",
        )?;
        ensure_non_empty(
            &source_manifest_root,
            "witness fetch manifest source manifest root",
        )?;
        ensure_non_empty(
            &access_policy_root,
            "witness fetch manifest access policy root",
        )?;
        ensure_non_empty(
            &encryption_key_commitment,
            "witness fetch manifest encryption key commitment",
        )?;
        ensure_window(
            created_at_height,
            fetch_deadline_height,
            "witness fetch manifest availability",
        )?;
        let fetch_uri_commitments = normalize_nonempty_strings(
            fetch_uri_commitments,
            "witness fetch manifest URI commitments",
        )?;
        let manifest_id = prover_backend_witness_manifest_id(
            &job_id,
            &proof_system,
            &witness_root,
            created_at_height,
            nonce,
        );
        Ok(Self {
            manifest_id,
            job_id,
            job_kind,
            proof_system,
            witness_root,
            public_input_root,
            private_input_commitment,
            source_manifest_root,
            fetch_uri_commitments,
            access_policy_root,
            encryption_key_commitment,
            required_worker_class,
            created_at_height,
            fetch_deadline_height,
            status: WitnessManifestStatus::Ready,
            nonce,
        })
    }

    pub fn is_fetchable_at(&self, height: u64) -> bool {
        self.status.fetchable()
            && height >= self.created_at_height
            && height <= self.fetch_deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_fetch_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "witness_scheme": PROVER_BACKEND_ORCHESTRATOR_WITNESS_SCHEME,
            "manifest_id": self.manifest_id,
            "job_id": self.job_id,
            "job_kind": self.job_kind.as_str(),
            "proof_system": self.proof_system,
            "witness_root": self.witness_root,
            "public_input_root": self.public_input_root,
            "private_input_commitment": self.private_input_commitment,
            "source_manifest_root": self.source_manifest_root,
            "fetch_uri_commitments": self.fetch_uri_commitments,
            "fetch_uri_root": prover_backend_string_set_root(
                "PROVER-BACKEND-WITNESS-FETCH-URIS",
                &self.fetch_uri_commitments
            ),
            "access_policy_root": self.access_policy_root,
            "encryption_key_commitment": self.encryption_key_commitment,
            "required_worker_class": self.required_worker_class.as_str(),
            "created_at_height": self.created_at_height,
            "fetch_deadline_height": self.fetch_deadline_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn manifest_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-WITNESS-MANIFEST", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.manifest_id, "witness fetch manifest id")?;
        ensure_non_empty(&self.job_id, "witness fetch manifest job id")?;
        ensure_non_empty(&self.proof_system, "witness fetch manifest proof system")?;
        ensure_non_empty(&self.witness_root, "witness fetch manifest witness root")?;
        ensure_non_empty(
            &self.public_input_root,
            "witness fetch manifest public input root",
        )?;
        ensure_non_empty(
            &self.private_input_commitment,
            "witness fetch manifest private input commitment",
        )?;
        ensure_non_empty(
            &self.source_manifest_root,
            "witness fetch manifest source manifest root",
        )?;
        ensure_non_empty(
            &self.access_policy_root,
            "witness fetch manifest access policy root",
        )?;
        ensure_non_empty(
            &self.encryption_key_commitment,
            "witness fetch manifest encryption key commitment",
        )?;
        ensure_window(
            self.created_at_height,
            self.fetch_deadline_height,
            "witness fetch manifest availability",
        )?;
        if self.fetch_uri_commitments.is_empty() {
            return Err("witness fetch manifest requires URI commitments".to_string());
        }
        let manifest_id = prover_backend_witness_manifest_id(
            &self.job_id,
            &self.proof_system,
            &self.witness_root,
            self.created_at_height,
            self.nonce,
        );
        if self.manifest_id != manifest_id {
            return Err("witness fetch manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeQuote {
    pub quote_id: String,
    pub job_id: String,
    pub job_kind: ProofBackendJobKind,
    pub priority: ProofBackendPriority,
    pub proof_system: String,
    pub fee_asset_id: String,
    pub estimated_cycles: u64,
    pub estimated_bytes: u64,
    pub base_fee_units: u64,
    pub priority_fee_units: u64,
    pub privacy_fee_units: u64,
    pub recursive_fee_units: u64,
    pub sponsor_credit_units: u64,
    pub max_fee_units: u64,
    pub quote_height: u64,
    pub expires_at_height: u64,
    pub status: FeeQuoteStatus,
    pub nonce: u64,
}

impl ProofFeeQuote {
    pub fn new(
        job_id: impl Into<String>,
        job_kind: ProofBackendJobKind,
        priority: ProofBackendPriority,
        proof_system: impl Into<String>,
        fee_asset_id: impl Into<String>,
        estimated_cycles: u64,
        estimated_bytes: u64,
        base_fee_units: u64,
        priority_fee_units: u64,
        privacy_fee_units: u64,
        recursive_fee_units: u64,
        sponsor_credit_units: u64,
        max_fee_units: u64,
        quote_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let job_id = job_id.into();
        let proof_system = normalize_proof_system(proof_system.into(), job_kind);
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&job_id, "proof fee quote job id")?;
        ensure_non_empty(&proof_system, "proof fee quote proof system")?;
        ensure_non_empty(&fee_asset_id, "proof fee quote fee asset id")?;
        ensure_positive(estimated_cycles, "proof fee quote estimated cycles")?;
        ensure_positive(estimated_bytes, "proof fee quote estimated bytes")?;
        ensure_positive(base_fee_units, "proof fee quote base fee units")?;
        ensure_positive(max_fee_units, "proof fee quote max fee units")?;
        ensure_window(quote_height, expires_at_height, "proof fee quote validity")?;
        let quote_id = prover_backend_fee_quote_id(
            &job_id,
            &proof_system,
            quote_height,
            expires_at_height,
            nonce,
        );
        let quote = Self {
            quote_id,
            job_id,
            job_kind,
            priority,
            proof_system,
            fee_asset_id,
            estimated_cycles,
            estimated_bytes,
            base_fee_units,
            priority_fee_units,
            privacy_fee_units,
            recursive_fee_units,
            sponsor_credit_units,
            max_fee_units,
            quote_height,
            expires_at_height,
            status: FeeQuoteStatus::Quoted,
            nonce,
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn quoted_fee_units(&self) -> u64 {
        self.base_fee_units
            .saturating_add(self.priority_fee_units)
            .saturating_add(self.privacy_fee_units)
            .saturating_add(self.recursive_fee_units)
    }

    pub fn payable_fee_units(&self) -> u64 {
        self.quoted_fee_units()
            .saturating_sub(self.sponsor_credit_units)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.usable() && height >= self.quote_height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_quote",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "job_id": self.job_id,
            "job_kind": self.job_kind.as_str(),
            "priority": self.priority.as_str(),
            "priority_weight": self.priority.default_weight(),
            "proof_system": self.proof_system,
            "fee_asset_id": self.fee_asset_id,
            "estimated_cycles": self.estimated_cycles,
            "estimated_bytes": self.estimated_bytes,
            "base_fee_units": self.base_fee_units,
            "priority_fee_units": self.priority_fee_units,
            "privacy_fee_units": self.privacy_fee_units,
            "recursive_fee_units": self.recursive_fee_units,
            "quoted_fee_units": self.quoted_fee_units(),
            "sponsor_credit_units": self.sponsor_credit_units,
            "payable_fee_units": self.payable_fee_units(),
            "max_fee_units": self.max_fee_units,
            "quote_height": self.quote_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn quote_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-FEE-QUOTE", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.quote_id, "proof fee quote id")?;
        ensure_non_empty(&self.job_id, "proof fee quote job id")?;
        ensure_non_empty(&self.proof_system, "proof fee quote proof system")?;
        ensure_non_empty(&self.fee_asset_id, "proof fee quote fee asset id")?;
        ensure_positive(self.estimated_cycles, "proof fee quote estimated cycles")?;
        ensure_positive(self.estimated_bytes, "proof fee quote estimated bytes")?;
        ensure_positive(self.base_fee_units, "proof fee quote base fee")?;
        ensure_positive(self.max_fee_units, "proof fee quote max fee")?;
        ensure_window(
            self.quote_height,
            self.expires_at_height,
            "proof fee quote validity",
        )?;
        if self.payable_fee_units() > self.max_fee_units {
            return Err("proof fee quote payable fee exceeds max fee".to_string());
        }
        let quote_id = prover_backend_fee_quote_id(
            &self.job_id,
            &self.proof_system,
            self.quote_height,
            self.expires_at_height,
            self.nonce,
        );
        if self.quote_id != quote_id {
            return Err("proof fee quote id mismatch".to_string());
        }
        Ok(self.quote_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobLease {
    pub lease_id: String,
    pub job_id: String,
    pub worker_id: String,
    pub manifest_id: String,
    pub quote_id: String,
    pub verifier_key_id: String,
    pub job_kind: ProofBackendJobKind,
    pub priority: ProofBackendPriority,
    pub proof_system: String,
    pub attempt: u64,
    pub lease_start_height: u64,
    pub lease_end_height: u64,
    pub assigned_compute_units: u64,
    pub reserved_gpu_units: u64,
    pub reserved_cpu_units: u64,
    pub collateral_units: u64,
    pub status: ProofLeaseStatus,
    pub nonce: u64,
}

impl ProofJobLease {
    pub fn new(
        job_id: impl Into<String>,
        worker_id: impl Into<String>,
        manifest_id: impl Into<String>,
        quote_id: impl Into<String>,
        verifier_key_id: impl Into<String>,
        job_kind: ProofBackendJobKind,
        priority: ProofBackendPriority,
        proof_system: impl Into<String>,
        attempt: u64,
        lease_start_height: u64,
        lease_end_height: u64,
        reserved_gpu_units: u64,
        reserved_cpu_units: u64,
        collateral_units: u64,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let job_id = job_id.into();
        let worker_id = worker_id.into();
        let manifest_id = manifest_id.into();
        let quote_id = quote_id.into();
        let verifier_key_id = verifier_key_id.into();
        let proof_system = normalize_proof_system(proof_system.into(), job_kind);
        ensure_non_empty(&job_id, "proof job lease job id")?;
        ensure_non_empty(&worker_id, "proof job lease worker id")?;
        ensure_non_empty(&manifest_id, "proof job lease manifest id")?;
        ensure_non_empty(&quote_id, "proof job lease quote id")?;
        ensure_non_empty(&verifier_key_id, "proof job lease verifier key id")?;
        ensure_non_empty(&proof_system, "proof job lease proof system")?;
        ensure_positive(attempt, "proof job lease attempt")?;
        ensure_window(
            lease_start_height,
            lease_end_height,
            "proof job lease validity",
        )?;
        let assigned_compute_units = reserved_gpu_units.saturating_add(reserved_cpu_units);
        ensure_positive(assigned_compute_units, "proof job lease compute units")?;
        let lease_id = prover_backend_job_lease_id(
            &job_id,
            &worker_id,
            &manifest_id,
            attempt,
            lease_start_height,
            nonce,
        );
        Ok(Self {
            lease_id,
            job_id,
            worker_id,
            manifest_id,
            quote_id,
            verifier_key_id,
            job_kind,
            priority,
            proof_system,
            attempt,
            lease_start_height,
            lease_end_height,
            assigned_compute_units,
            reserved_gpu_units,
            reserved_cpu_units,
            collateral_units,
            status: ProofLeaseStatus::Offered,
            nonce,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.active() && height >= self.lease_start_height && height <= self.lease_end_height
    }

    pub fn timed_out_at(&self, height: u64) -> bool {
        self.status.active() && height > self.lease_end_height
    }

    pub fn gpu_heavy(&self) -> bool {
        self.reserved_gpu_units > self.reserved_cpu_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_job_lease",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "lease_id": self.lease_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "manifest_id": self.manifest_id,
            "quote_id": self.quote_id,
            "verifier_key_id": self.verifier_key_id,
            "job_kind": self.job_kind.as_str(),
            "priority": self.priority.as_str(),
            "proof_system": self.proof_system,
            "attempt": self.attempt,
            "lease_start_height": self.lease_start_height,
            "lease_end_height": self.lease_end_height,
            "assigned_compute_units": self.assigned_compute_units,
            "reserved_gpu_units": self.reserved_gpu_units,
            "reserved_cpu_units": self.reserved_cpu_units,
            "collateral_units": self.collateral_units,
            "status": self.status.as_str(),
            "terminal": self.status.terminal(),
            "nonce": self.nonce,
        })
    }

    pub fn lease_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-JOB-LEASE", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.lease_id, "proof job lease id")?;
        ensure_non_empty(&self.job_id, "proof job lease job id")?;
        ensure_non_empty(&self.worker_id, "proof job lease worker id")?;
        ensure_non_empty(&self.manifest_id, "proof job lease manifest id")?;
        ensure_non_empty(&self.quote_id, "proof job lease quote id")?;
        ensure_non_empty(&self.verifier_key_id, "proof job lease verifier key id")?;
        ensure_non_empty(&self.proof_system, "proof job lease proof system")?;
        ensure_positive(self.attempt, "proof job lease attempt")?;
        ensure_window(
            self.lease_start_height,
            self.lease_end_height,
            "proof job lease validity",
        )?;
        let assigned = self
            .reserved_gpu_units
            .saturating_add(self.reserved_cpu_units);
        if assigned == 0 {
            return Err("proof job lease requires reserved compute units".to_string());
        }
        if self.assigned_compute_units != assigned {
            return Err("proof job lease assigned units mismatch".to_string());
        }
        let lease_id = prover_backend_job_lease_id(
            &self.job_id,
            &self.worker_id,
            &self.manifest_id,
            self.attempt,
            self.lease_start_height,
            self.nonce,
        );
        if self.lease_id != lease_id {
            return Err("proof job lease id mismatch".to_string());
        }
        Ok(self.lease_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveAggregationBatch {
    pub batch_id: String,
    pub batch_label: String,
    pub aggregator_worker_id: String,
    pub lease_ids: Vec<String>,
    pub child_artifact_ids: Vec<String>,
    pub child_job_ids: Vec<String>,
    pub recursion_depth: u64,
    pub target_proof_system: String,
    pub verifier_key_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub aggregate_public_input_root: String,
    pub aggregate_witness_root: String,
    pub status: AggregationBatchStatus,
    pub nonce: u64,
}

impl RecursiveAggregationBatch {
    pub fn new(
        batch_label: impl Into<String>,
        aggregator_worker_id: impl Into<String>,
        lease_ids: &[String],
        child_artifact_ids: &[String],
        child_job_ids: &[String],
        recursion_depth: u64,
        target_proof_system: impl Into<String>,
        verifier_key_id: impl Into<String>,
        window_start_height: u64,
        window_end_height: u64,
        aggregate_public_input_root: impl Into<String>,
        aggregate_witness_root: impl Into<String>,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let batch_label = batch_label.into();
        let aggregator_worker_id = aggregator_worker_id.into();
        let target_proof_system = target_proof_system.into();
        let verifier_key_id = verifier_key_id.into();
        let aggregate_public_input_root = aggregate_public_input_root.into();
        let aggregate_witness_root = aggregate_witness_root.into();
        ensure_non_empty(&batch_label, "recursive aggregation batch label")?;
        ensure_non_empty(
            &aggregator_worker_id,
            "recursive aggregation batch aggregator worker id",
        )?;
        ensure_non_empty(
            &target_proof_system,
            "recursive aggregation batch proof system",
        )?;
        ensure_non_empty(
            &verifier_key_id,
            "recursive aggregation batch verifier key id",
        )?;
        ensure_non_empty(
            &aggregate_public_input_root,
            "recursive aggregation batch public input root",
        )?;
        ensure_non_empty(
            &aggregate_witness_root,
            "recursive aggregation batch witness root",
        )?;
        ensure_window(
            window_start_height,
            window_end_height,
            "recursive aggregation batch window",
        )?;
        let lease_ids =
            normalize_nonempty_strings(lease_ids, "recursive aggregation batch lease ids")?;
        let child_artifact_ids = normalize_nonempty_strings(
            child_artifact_ids,
            "recursive aggregation batch child artifacts",
        )?;
        let child_job_ids =
            normalize_nonempty_strings(child_job_ids, "recursive aggregation batch child jobs")?;
        let batch_id = prover_backend_aggregation_batch_id(
            &batch_label,
            &aggregator_worker_id,
            &target_proof_system,
            window_start_height,
            nonce,
        );
        let batch = Self {
            batch_id,
            batch_label,
            aggregator_worker_id,
            lease_ids,
            child_artifact_ids,
            child_job_ids,
            recursion_depth,
            target_proof_system,
            verifier_key_id,
            window_start_height,
            window_end_height,
            aggregate_public_input_root,
            aggregate_witness_root,
            status: AggregationBatchStatus::Open,
            nonce,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn child_artifact_root(&self) -> String {
        prover_backend_string_set_root(
            "PROVER-BACKEND-AGGREGATION-CHILD-ARTIFACTS",
            &self.child_artifact_ids,
        )
    }

    pub fn child_job_root(&self) -> String {
        prover_backend_string_set_root("PROVER-BACKEND-AGGREGATION-CHILD-JOBS", &self.child_job_ids)
    }

    pub fn lease_root(&self) -> String {
        prover_backend_string_set_root("PROVER-BACKEND-AGGREGATION-LEASES", &self.lease_ids)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_aggregation_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "recursion_scheme": PROVER_BACKEND_ORCHESTRATOR_RECURSION_SCHEME,
            "batch_id": self.batch_id,
            "batch_label": self.batch_label,
            "aggregator_worker_id": self.aggregator_worker_id,
            "lease_ids": self.lease_ids,
            "lease_root": self.lease_root(),
            "child_artifact_ids": self.child_artifact_ids,
            "child_artifact_root": self.child_artifact_root(),
            "child_job_ids": self.child_job_ids,
            "child_job_root": self.child_job_root(),
            "recursion_depth": self.recursion_depth,
            "target_proof_system": self.target_proof_system,
            "verifier_key_id": self.verifier_key_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "aggregate_public_input_root": self.aggregate_public_input_root,
            "aggregate_witness_root": self.aggregate_witness_root,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn batch_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-AGGREGATION-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.batch_id, "recursive aggregation batch id")?;
        ensure_non_empty(&self.batch_label, "recursive aggregation batch label")?;
        ensure_non_empty(
            &self.aggregator_worker_id,
            "recursive aggregation batch aggregator worker id",
        )?;
        ensure_non_empty(
            &self.target_proof_system,
            "recursive aggregation batch proof system",
        )?;
        ensure_non_empty(
            &self.verifier_key_id,
            "recursive aggregation batch verifier key id",
        )?;
        ensure_non_empty(
            &self.aggregate_public_input_root,
            "recursive aggregation batch public input root",
        )?;
        ensure_non_empty(
            &self.aggregate_witness_root,
            "recursive aggregation batch witness root",
        )?;
        ensure_window(
            self.window_start_height,
            self.window_end_height,
            "recursive aggregation batch window",
        )?;
        if self.lease_ids.is_empty() {
            return Err("recursive aggregation batch requires leases".to_string());
        }
        if self.child_artifact_ids.is_empty() {
            return Err("recursive aggregation batch requires child artifacts".to_string());
        }
        if self.child_job_ids.is_empty() {
            return Err("recursive aggregation batch requires child jobs".to_string());
        }
        if self.child_artifact_ids.len() != self.child_job_ids.len() {
            return Err("recursive aggregation batch child counts mismatch".to_string());
        }
        let batch_id = prover_backend_aggregation_batch_id(
            &self.batch_label,
            &self.aggregator_worker_id,
            &self.target_proof_system,
            self.window_start_height,
            self.nonce,
        );
        if self.batch_id != batch_id {
            return Err("recursive aggregation batch id mismatch".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifactCommitment {
    pub artifact_id: String,
    pub job_id: String,
    pub lease_id: String,
    pub worker_id: String,
    pub artifact_kind: ArtifactCommitmentKind,
    pub proof_system: String,
    pub artifact_root: String,
    pub public_inputs_root: String,
    pub transcript_root: String,
    pub verifier_key_id: String,
    pub produced_at_height: u64,
    pub byte_len: u64,
    pub recursive_depth: u64,
    pub pq_signature_root: String,
    pub status: ArtifactCommitmentStatus,
    pub nonce: u64,
}

impl ProofArtifactCommitment {
    pub fn new(
        job_id: impl Into<String>,
        lease_id: impl Into<String>,
        worker_id: impl Into<String>,
        artifact_kind: ArtifactCommitmentKind,
        proof_system: impl Into<String>,
        artifact_root: impl Into<String>,
        public_inputs_root: impl Into<String>,
        transcript_root: impl Into<String>,
        verifier_key_id: impl Into<String>,
        produced_at_height: u64,
        byte_len: u64,
        recursive_depth: u64,
        pq_signature_root: impl Into<String>,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let job_id = job_id.into();
        let lease_id = lease_id.into();
        let worker_id = worker_id.into();
        let proof_system = proof_system.into();
        let artifact_root = artifact_root.into();
        let public_inputs_root = public_inputs_root.into();
        let transcript_root = transcript_root.into();
        let verifier_key_id = verifier_key_id.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&job_id, "proof artifact commitment job id")?;
        ensure_non_empty(&lease_id, "proof artifact commitment lease id")?;
        ensure_non_empty(&worker_id, "proof artifact commitment worker id")?;
        ensure_non_empty(&proof_system, "proof artifact commitment proof system")?;
        ensure_non_empty(&artifact_root, "proof artifact commitment artifact root")?;
        ensure_non_empty(
            &public_inputs_root,
            "proof artifact commitment public inputs root",
        )?;
        ensure_non_empty(
            &transcript_root,
            "proof artifact commitment transcript root",
        )?;
        ensure_non_empty(
            &verifier_key_id,
            "proof artifact commitment verifier key id",
        )?;
        ensure_non_empty(
            &pq_signature_root,
            "proof artifact commitment PQ signature root",
        )?;
        ensure_positive(byte_len, "proof artifact commitment byte length")?;
        let artifact_id = prover_backend_artifact_id(
            &job_id,
            &lease_id,
            artifact_kind,
            &artifact_root,
            produced_at_height,
            nonce,
        );
        Ok(Self {
            artifact_id,
            job_id,
            lease_id,
            worker_id,
            artifact_kind,
            proof_system,
            artifact_root,
            public_inputs_root,
            transcript_root,
            verifier_key_id,
            produced_at_height,
            byte_len,
            recursive_depth,
            pq_signature_root,
            status: ArtifactCommitmentStatus::Submitted,
            nonce,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_artifact_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "artifact_scheme": PROVER_BACKEND_ORCHESTRATOR_ARTIFACT_SCHEME,
            "artifact_id": self.artifact_id,
            "job_id": self.job_id,
            "lease_id": self.lease_id,
            "worker_id": self.worker_id,
            "artifact_kind": self.artifact_kind.as_str(),
            "proof_system": self.proof_system,
            "artifact_root": self.artifact_root,
            "public_inputs_root": self.public_inputs_root,
            "transcript_root": self.transcript_root,
            "verifier_key_id": self.verifier_key_id,
            "produced_at_height": self.produced_at_height,
            "byte_len": self.byte_len,
            "recursive_depth": self.recursive_depth,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn commitment_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-ARTIFACT-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.artifact_id, "proof artifact commitment id")?;
        ensure_non_empty(&self.job_id, "proof artifact commitment job id")?;
        ensure_non_empty(&self.lease_id, "proof artifact commitment lease id")?;
        ensure_non_empty(&self.worker_id, "proof artifact commitment worker id")?;
        ensure_non_empty(&self.proof_system, "proof artifact commitment proof system")?;
        ensure_non_empty(
            &self.artifact_root,
            "proof artifact commitment artifact root",
        )?;
        ensure_non_empty(
            &self.public_inputs_root,
            "proof artifact commitment public inputs root",
        )?;
        ensure_non_empty(
            &self.transcript_root,
            "proof artifact commitment transcript root",
        )?;
        ensure_non_empty(
            &self.verifier_key_id,
            "proof artifact commitment verifier key id",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "proof artifact commitment PQ signature root",
        )?;
        ensure_positive(self.byte_len, "proof artifact commitment byte length")?;
        let artifact_id = prover_backend_artifact_id(
            &self.job_id,
            &self.lease_id,
            self.artifact_kind,
            &self.artifact_root,
            self.produced_at_height,
            self.nonce,
        );
        if self.artifact_id != artifact_id {
            return Err("proof artifact commitment id mismatch".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVerificationReceipt {
    pub receipt_id: String,
    pub artifact_id: String,
    pub job_id: String,
    pub verifier_worker_id: String,
    pub verifier_key_id: String,
    pub outcome: VerificationOutcome,
    pub retry_disposition: RetryDisposition,
    pub artifact_root: String,
    pub public_inputs_root: String,
    pub verification_height: u64,
    pub verifier_notes_root: String,
    pub pq_signature_root: String,
    pub status: String,
    pub nonce: u64,
}

impl ProofVerificationReceipt {
    pub fn new(
        artifact_id: impl Into<String>,
        job_id: impl Into<String>,
        verifier_worker_id: impl Into<String>,
        verifier_key_id: impl Into<String>,
        outcome: VerificationOutcome,
        retry_disposition: RetryDisposition,
        artifact_root: impl Into<String>,
        public_inputs_root: impl Into<String>,
        verification_height: u64,
        verifier_notes_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let artifact_id = artifact_id.into();
        let job_id = job_id.into();
        let verifier_worker_id = verifier_worker_id.into();
        let verifier_key_id = verifier_key_id.into();
        let artifact_root = artifact_root.into();
        let public_inputs_root = public_inputs_root.into();
        let verifier_notes_root = verifier_notes_root.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&artifact_id, "proof verification receipt artifact id")?;
        ensure_non_empty(&job_id, "proof verification receipt job id")?;
        ensure_non_empty(
            &verifier_worker_id,
            "proof verification receipt verifier worker id",
        )?;
        ensure_non_empty(
            &verifier_key_id,
            "proof verification receipt verifier key id",
        )?;
        ensure_non_empty(&artifact_root, "proof verification receipt artifact root")?;
        ensure_non_empty(
            &public_inputs_root,
            "proof verification receipt public inputs root",
        )?;
        ensure_non_empty(
            &verifier_notes_root,
            "proof verification receipt verifier notes root",
        )?;
        ensure_non_empty(
            &pq_signature_root,
            "proof verification receipt PQ signature root",
        )?;
        let receipt_id = prover_backend_verification_receipt_id(
            &artifact_id,
            &job_id,
            &verifier_worker_id,
            outcome,
            verification_height,
            nonce,
        );
        Ok(Self {
            receipt_id,
            artifact_id,
            job_id,
            verifier_worker_id,
            verifier_key_id,
            outcome,
            retry_disposition,
            artifact_root,
            public_inputs_root,
            verification_height,
            verifier_notes_root,
            pq_signature_root,
            status: outcome.status().to_string(),
            nonce,
        })
    }

    pub fn accepted(&self) -> bool {
        self.outcome == VerificationOutcome::Accepted
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_verification_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "artifact_id": self.artifact_id,
            "job_id": self.job_id,
            "verifier_worker_id": self.verifier_worker_id,
            "verifier_key_id": self.verifier_key_id,
            "outcome": self.outcome.as_str(),
            "retry_disposition": self.retry_disposition.as_str(),
            "retry_status": self.retry_disposition.status(),
            "artifact_root": self.artifact_root,
            "public_inputs_root": self.public_inputs_root,
            "verification_height": self.verification_height,
            "verifier_notes_root": self.verifier_notes_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status,
            "nonce": self.nonce,
        })
    }

    pub fn receipt_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-VERIFICATION-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.receipt_id, "proof verification receipt id")?;
        ensure_non_empty(&self.artifact_id, "proof verification receipt artifact id")?;
        ensure_non_empty(&self.job_id, "proof verification receipt job id")?;
        ensure_non_empty(
            &self.verifier_worker_id,
            "proof verification receipt verifier worker id",
        )?;
        ensure_non_empty(
            &self.verifier_key_id,
            "proof verification receipt verifier key id",
        )?;
        ensure_non_empty(
            &self.artifact_root,
            "proof verification receipt artifact root",
        )?;
        ensure_non_empty(
            &self.public_inputs_root,
            "proof verification receipt public inputs root",
        )?;
        ensure_non_empty(
            &self.verifier_notes_root,
            "proof verification receipt notes root",
        )?;
        ensure_non_empty(
            &self.pq_signature_root,
            "proof verification receipt signature root",
        )?;
        if self.status != self.outcome.status() {
            return Err("proof verification receipt status mismatch".to_string());
        }
        let receipt_id = prover_backend_verification_receipt_id(
            &self.artifact_id,
            &self.job_id,
            &self.verifier_worker_id,
            self.outcome,
            self.verification_height,
            self.nonce,
        );
        if self.receipt_id != receipt_id {
            return Err("proof verification receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicyRecord {
    pub policy_id: String,
    pub job_kind: ProofBackendJobKind,
    pub max_attempts: u64,
    pub timeout_blocks: u64,
    pub retry_backoff_blocks: u64,
    pub quarantine_after_failures: u64,
    pub sponsor_after_attempt: u64,
    pub require_fresh_witness: bool,
    pub require_different_worker: bool,
    pub status: RetryPolicyStatus,
    pub nonce: u64,
}

impl RetryPolicyRecord {
    pub fn new(
        job_kind: ProofBackendJobKind,
        max_attempts: u64,
        timeout_blocks: u64,
        retry_backoff_blocks: u64,
        quarantine_after_failures: u64,
        sponsor_after_attempt: u64,
        require_fresh_witness: bool,
        require_different_worker: bool,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        ensure_positive(max_attempts, "retry policy max attempts")?;
        ensure_positive(timeout_blocks, "retry policy timeout blocks")?;
        let policy_id =
            prover_backend_retry_policy_id(job_kind, max_attempts, timeout_blocks, nonce);
        Ok(Self {
            policy_id,
            job_kind,
            max_attempts,
            timeout_blocks,
            retry_backoff_blocks,
            quarantine_after_failures,
            sponsor_after_attempt,
            require_fresh_witness,
            require_different_worker,
            status: RetryPolicyStatus::Active,
            nonce,
        })
    }

    pub fn disposition_for(&self, attempt: u64, failure_count: u64) -> RetryDisposition {
        if failure_count >= self.quarantine_after_failures && self.quarantine_after_failures > 0 {
            return RetryDisposition::QuarantineWorker;
        }
        if attempt >= self.max_attempts {
            return RetryDisposition::AbortJob;
        }
        if self.sponsor_after_attempt > 0 && attempt >= self.sponsor_after_attempt {
            return RetryDisposition::SponsorAndRetry;
        }
        if self.require_different_worker {
            return RetryDisposition::RetryDifferentWorker;
        }
        RetryDisposition::RetrySameWorker
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "retry_policy_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "job_kind": self.job_kind.as_str(),
            "max_attempts": self.max_attempts,
            "timeout_blocks": self.timeout_blocks,
            "retry_backoff_blocks": self.retry_backoff_blocks,
            "quarantine_after_failures": self.quarantine_after_failures,
            "sponsor_after_attempt": self.sponsor_after_attempt,
            "require_fresh_witness": self.require_fresh_witness,
            "require_different_worker": self.require_different_worker,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn policy_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-RETRY-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.policy_id, "retry policy id")?;
        ensure_positive(self.max_attempts, "retry policy max attempts")?;
        ensure_positive(self.timeout_blocks, "retry policy timeout blocks")?;
        if self.quarantine_after_failures > self.max_attempts {
            return Err("retry policy quarantine threshold exceeds attempts".to_string());
        }
        let policy_id = prover_backend_retry_policy_id(
            self.job_kind,
            self.max_attempts,
            self.timeout_blocks,
            self.nonce,
        );
        if self.policy_id != policy_id {
            return Err("retry policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerQuarantineRecord {
    pub quarantine_id: String,
    pub worker_id: String,
    pub job_id: String,
    pub reason_code: String,
    pub evidence_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub failure_count: u64,
    pub retry_disposition: RetryDisposition,
    pub status: QuarantineStatus,
    pub nonce: u64,
}

impl WorkerQuarantineRecord {
    pub fn new(
        worker_id: impl Into<String>,
        job_id: impl Into<String>,
        reason_code: impl Into<String>,
        evidence_root: impl Into<String>,
        starts_at_height: u64,
        expires_at_height: u64,
        failure_count: u64,
        retry_disposition: RetryDisposition,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let worker_id = worker_id.into();
        let job_id = job_id.into();
        let reason_code = reason_code.into();
        let evidence_root = evidence_root.into();
        ensure_non_empty(&worker_id, "worker quarantine worker id")?;
        ensure_non_empty(&job_id, "worker quarantine job id")?;
        ensure_non_empty(&reason_code, "worker quarantine reason code")?;
        ensure_non_empty(&evidence_root, "worker quarantine evidence root")?;
        ensure_window(
            starts_at_height,
            expires_at_height,
            "worker quarantine validity",
        )?;
        let quarantine_id = prover_backend_quarantine_id(
            &worker_id,
            &job_id,
            &reason_code,
            starts_at_height,
            nonce,
        );
        Ok(Self {
            quarantine_id,
            worker_id,
            job_id,
            reason_code,
            evidence_root,
            starts_at_height,
            expires_at_height,
            failure_count,
            retry_disposition,
            status: QuarantineStatus::Active,
            nonce,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.active() && height >= self.starts_at_height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "worker_quarantine_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "quarantine_id": self.quarantine_id,
            "worker_id": self.worker_id,
            "job_id": self.job_id,
            "reason_code": self.reason_code,
            "evidence_root": self.evidence_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "failure_count": self.failure_count,
            "retry_disposition": self.retry_disposition.as_str(),
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn quarantine_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-QUARANTINE", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.quarantine_id, "worker quarantine id")?;
        ensure_non_empty(&self.worker_id, "worker quarantine worker id")?;
        ensure_non_empty(&self.job_id, "worker quarantine job id")?;
        ensure_non_empty(&self.reason_code, "worker quarantine reason code")?;
        ensure_non_empty(&self.evidence_root, "worker quarantine evidence root")?;
        ensure_window(
            self.starts_at_height,
            self.expires_at_height,
            "worker quarantine validity",
        )?;
        let quarantine_id = prover_backend_quarantine_id(
            &self.worker_id,
            &self.job_id,
            &self.reason_code,
            self.starts_at_height,
            self.nonce,
        );
        if self.quarantine_id != quarantine_id {
            return Err("worker quarantine id mismatch".to_string());
        }
        Ok(self.quarantine_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub lane_label: String,
    pub job_kind: ProofBackendJobKind,
    pub fee_asset_id: String,
    pub deposited_units: u64,
    pub reserved_units: u64,
    pub applied_units: u64,
    pub max_fee_per_job_units: u64,
    pub eligibility_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
    pub nonce: u64,
}

impl LowFeeProofSponsorship {
    pub fn new(
        sponsor_id: impl Into<String>,
        lane_label: impl Into<String>,
        job_kind: ProofBackendJobKind,
        fee_asset_id: impl Into<String>,
        deposited_units: u64,
        reserved_units: u64,
        applied_units: u64,
        max_fee_per_job_units: u64,
        eligibility_root: impl Into<String>,
        starts_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ProverBackendOrchestratorResult<Self> {
        let sponsor_id = sponsor_id.into();
        let lane_label = lane_label.into();
        let fee_asset_id = fee_asset_id.into();
        let eligibility_root = eligibility_root.into();
        ensure_non_empty(&sponsor_id, "low fee sponsorship sponsor id")?;
        ensure_non_empty(&lane_label, "low fee sponsorship lane label")?;
        ensure_non_empty(&fee_asset_id, "low fee sponsorship fee asset id")?;
        ensure_non_empty(&eligibility_root, "low fee sponsorship eligibility root")?;
        ensure_positive(deposited_units, "low fee sponsorship deposit")?;
        ensure_positive(max_fee_per_job_units, "low fee sponsorship max fee per job")?;
        ensure_window(
            starts_at_height,
            expires_at_height,
            "low fee sponsorship validity",
        )?;
        let sponsorship_id = prover_backend_sponsorship_id(
            &sponsor_id,
            &lane_label,
            job_kind,
            starts_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_id,
            lane_label,
            job_kind,
            fee_asset_id,
            deposited_units,
            reserved_units,
            applied_units,
            max_fee_per_job_units,
            eligibility_root,
            starts_at_height,
            expires_at_height,
            status: SponsorshipStatus::Pledged,
            nonce,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_units(&self) -> u64 {
        self.deposited_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.applied_units)
    }

    pub fn can_sponsor(&self, fee_units: u64, height: u64) -> bool {
        self.status.spendable()
            && height >= self.starts_at_height
            && height <= self.expires_at_height
            && fee_units <= self.max_fee_per_job_units
            && self.available_units() >= fee_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "lane_label": self.lane_label,
            "job_kind": self.job_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "deposited_units": self.deposited_units,
            "reserved_units": self.reserved_units,
            "applied_units": self.applied_units,
            "available_units": self.available_units(),
            "max_fee_per_job_units": self.max_fee_per_job_units,
            "eligibility_root": self.eligibility_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "nonce": self.nonce,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        prover_backend_payload_root("PROVER-BACKEND-LOW-FEE-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(&self.sponsorship_id, "low fee sponsorship id")?;
        ensure_non_empty(&self.sponsor_id, "low fee sponsorship sponsor id")?;
        ensure_non_empty(&self.lane_label, "low fee sponsorship lane label")?;
        ensure_non_empty(&self.fee_asset_id, "low fee sponsorship fee asset id")?;
        ensure_non_empty(
            &self.eligibility_root,
            "low fee sponsorship eligibility root",
        )?;
        ensure_positive(self.deposited_units, "low fee sponsorship deposit")?;
        ensure_positive(
            self.max_fee_per_job_units,
            "low fee sponsorship max fee per job",
        )?;
        ensure_window(
            self.starts_at_height,
            self.expires_at_height,
            "low fee sponsorship validity",
        )?;
        if self.reserved_units.saturating_add(self.applied_units) > self.deposited_units {
            return Err("low fee sponsorship reserved and applied exceed deposit".to_string());
        }
        let sponsorship_id = prover_backend_sponsorship_id(
            &self.sponsor_id,
            &self.lane_label,
            self.job_kind,
            self.starts_at_height,
            self.nonce,
        );
        if self.sponsorship_id != sponsorship_id {
            return Err("low fee sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBackendOrchestratorRoots {
    pub policy_root: String,
    pub worker_root: String,
    pub pq_authentication_root: String,
    pub capacity_root: String,
    pub verifier_key_root: String,
    pub witness_manifest_root: String,
    pub fee_quote_root: String,
    pub job_lease_root: String,
    pub aggregation_batch_root: String,
    pub artifact_commitment_root: String,
    pub verification_receipt_root: String,
    pub retry_policy_root: String,
    pub quarantine_root: String,
    pub sponsorship_root: String,
    pub worker_lease_index_root: String,
    pub completed_job_root: String,
    pub state_root: String,
}

impl ProverBackendOrchestratorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_backend_orchestrator_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "policy_root": self.policy_root,
            "worker_root": self.worker_root,
            "pq_authentication_root": self.pq_authentication_root,
            "capacity_root": self.capacity_root,
            "verifier_key_root": self.verifier_key_root,
            "witness_manifest_root": self.witness_manifest_root,
            "fee_quote_root": self.fee_quote_root,
            "job_lease_root": self.job_lease_root,
            "aggregation_batch_root": self.aggregation_batch_root,
            "artifact_commitment_root": self.artifact_commitment_root,
            "verification_receipt_root": self.verification_receipt_root,
            "retry_policy_root": self.retry_policy_root,
            "quarantine_root": self.quarantine_root,
            "sponsorship_root": self.sponsorship_root,
            "worker_lease_index_root": self.worker_lease_index_root,
            "completed_job_root": self.completed_job_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBackendOrchestratorCounters {
    pub workers: u64,
    pub active_workers: u64,
    pub quarantined_workers: u64,
    pub offline_workers: u64,
    pub cpu_workers: u64,
    pub gpu_workers: u64,
    pub verifier_workers: u64,
    pub pq_authentications: u64,
    pub live_pq_authentications: u64,
    pub capacity_snapshots: u64,
    pub verifier_keys: u64,
    pub active_verifier_keys: u64,
    pub witness_manifests: u64,
    pub fetchable_witness_manifests: u64,
    pub fee_quotes: u64,
    pub live_fee_quotes: u64,
    pub job_leases: u64,
    pub active_job_leases: u64,
    pub completed_job_leases: u64,
    pub timed_out_job_leases: u64,
    pub retried_job_leases: u64,
    pub quarantined_job_leases: u64,
    pub aggregation_batches: u64,
    pub active_aggregation_batches: u64,
    pub artifact_commitments: u64,
    pub stored_artifacts: u64,
    pub verification_receipts: u64,
    pub accepted_receipts: u64,
    pub rejected_receipts: u64,
    pub retry_receipts: u64,
    pub retry_policies: u64,
    pub active_retry_policies: u64,
    pub quarantines: u64,
    pub active_quarantines: u64,
    pub sponsorships: u64,
    pub active_sponsorships: u64,
    pub completed_jobs: u64,
    pub total_cpu_threads: u64,
    pub total_gpu_devices: u64,
    pub total_gpu_memory_mib: u64,
    pub total_compute_units: u64,
    pub total_reserved_compute_units: u64,
    pub total_available_compute_units: u64,
    pub total_parallel_slots: u64,
    pub total_quote_fee_units: u64,
    pub total_payable_fee_units: u64,
    pub total_sponsor_credit_units: u64,
    pub total_sponsor_available_units: u64,
    pub total_artifact_bytes: u64,
}

impl ProverBackendOrchestratorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prover_backend_orchestrator_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "workers": self.workers,
            "active_workers": self.active_workers,
            "quarantined_workers": self.quarantined_workers,
            "offline_workers": self.offline_workers,
            "cpu_workers": self.cpu_workers,
            "gpu_workers": self.gpu_workers,
            "verifier_workers": self.verifier_workers,
            "pq_authentications": self.pq_authentications,
            "live_pq_authentications": self.live_pq_authentications,
            "capacity_snapshots": self.capacity_snapshots,
            "verifier_keys": self.verifier_keys,
            "active_verifier_keys": self.active_verifier_keys,
            "witness_manifests": self.witness_manifests,
            "fetchable_witness_manifests": self.fetchable_witness_manifests,
            "fee_quotes": self.fee_quotes,
            "live_fee_quotes": self.live_fee_quotes,
            "job_leases": self.job_leases,
            "active_job_leases": self.active_job_leases,
            "completed_job_leases": self.completed_job_leases,
            "timed_out_job_leases": self.timed_out_job_leases,
            "retried_job_leases": self.retried_job_leases,
            "quarantined_job_leases": self.quarantined_job_leases,
            "aggregation_batches": self.aggregation_batches,
            "active_aggregation_batches": self.active_aggregation_batches,
            "artifact_commitments": self.artifact_commitments,
            "stored_artifacts": self.stored_artifacts,
            "verification_receipts": self.verification_receipts,
            "accepted_receipts": self.accepted_receipts,
            "rejected_receipts": self.rejected_receipts,
            "retry_receipts": self.retry_receipts,
            "retry_policies": self.retry_policies,
            "active_retry_policies": self.active_retry_policies,
            "quarantines": self.quarantines,
            "active_quarantines": self.active_quarantines,
            "sponsorships": self.sponsorships,
            "active_sponsorships": self.active_sponsorships,
            "completed_jobs": self.completed_jobs,
            "total_cpu_threads": self.total_cpu_threads,
            "total_gpu_devices": self.total_gpu_devices,
            "total_gpu_memory_mib": self.total_gpu_memory_mib,
            "total_compute_units": self.total_compute_units,
            "total_reserved_compute_units": self.total_reserved_compute_units,
            "total_available_compute_units": self.total_available_compute_units,
            "total_parallel_slots": self.total_parallel_slots,
            "total_quote_fee_units": self.total_quote_fee_units,
            "total_payable_fee_units": self.total_payable_fee_units,
            "total_sponsor_credit_units": self.total_sponsor_credit_units,
            "total_sponsor_available_units": self.total_sponsor_available_units,
            "total_artifact_bytes": self.total_artifact_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBackendOrchestratorState {
    pub height: u64,
    pub orchestrator_label: String,
    pub policy: ProverBackendPolicy,
    pub workers: BTreeMap<String, ProverBackendWorker>,
    pub pq_authentications: BTreeMap<String, PqWorkerAuthentication>,
    pub capacity_snapshots: BTreeMap<String, WorkerCapacitySnapshot>,
    pub verifier_keys: BTreeMap<String, VerifierKeyRecord>,
    pub witness_manifests: BTreeMap<String, WitnessFetchManifest>,
    pub fee_quotes: BTreeMap<String, ProofFeeQuote>,
    pub job_leases: BTreeMap<String, ProofJobLease>,
    pub aggregation_batches: BTreeMap<String, RecursiveAggregationBatch>,
    pub artifact_commitments: BTreeMap<String, ProofArtifactCommitment>,
    pub verification_receipts: BTreeMap<String, ProofVerificationReceipt>,
    pub retry_policies: BTreeMap<String, RetryPolicyRecord>,
    pub quarantines: BTreeMap<String, WorkerQuarantineRecord>,
    pub sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub worker_lease_index: BTreeMap<String, BTreeSet<String>>,
    pub completed_job_ids: BTreeSet<String>,
}

impl ProverBackendOrchestratorState {
    pub fn new(
        orchestrator_label: impl Into<String>,
        policy: ProverBackendPolicy,
    ) -> ProverBackendOrchestratorResult<Self> {
        policy.validate()?;
        let orchestrator_label = orchestrator_label.into();
        ensure_non_empty(&orchestrator_label, "prover backend orchestrator label")?;
        Ok(Self {
            height: 0,
            orchestrator_label,
            policy,
            workers: BTreeMap::new(),
            pq_authentications: BTreeMap::new(),
            capacity_snapshots: BTreeMap::new(),
            verifier_keys: BTreeMap::new(),
            witness_manifests: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            job_leases: BTreeMap::new(),
            aggregation_batches: BTreeMap::new(),
            artifact_commitments: BTreeMap::new(),
            verification_receipts: BTreeMap::new(),
            retry_policies: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            worker_lease_index: BTreeMap::new(),
            completed_job_ids: BTreeSet::new(),
        })
    }

    pub fn devnet() -> ProverBackendOrchestratorResult<Self> {
        let mut state = Self::new(
            "devnet-prover-backend-orchestrator",
            ProverBackendPolicy::default(),
        )?;
        state.set_height(120);

        for (nonce, kind) in [
            ProofBackendJobKind::RollupValidity,
            ProofBackendJobKind::MoneroBridge,
            ProofBackendJobKind::PrivateContract,
            ProofBackendJobKind::FeeRebateAccounting,
            ProofBackendJobKind::RecursiveAggregation,
            ProofBackendJobKind::ProofCompression,
            ProofBackendJobKind::WatchtowerFallback,
        ]
        .into_iter()
        .enumerate()
        {
            let policy = RetryPolicyRecord::new(
                kind,
                state.policy.max_retries.saturating_add(1),
                state.policy.proof_timeout_blocks,
                state.policy.retry_backoff_blocks,
                2,
                2,
                kind.privacy_sensitive(),
                true,
                nonce as u64,
            )?;
            state.insert_retry_policy(policy)?;
        }

        let gpu_systems = vec![
            PROVER_BACKEND_ROLLUP_PROOF_SYSTEM.to_string(),
            PROVER_BACKEND_MONERO_BRIDGE_PROOF_SYSTEM.to_string(),
            PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM.to_string(),
        ];
        let recursive_systems = vec![
            PROVER_BACKEND_RECURSIVE_PROOF_SYSTEM.to_string(),
            PROVER_BACKEND_COMPRESSION_PROOF_SYSTEM.to_string(),
        ];
        let verifier_systems = vec![
            PROVER_BACKEND_ROLLUP_PROOF_SYSTEM.to_string(),
            PROVER_BACKEND_MONERO_BRIDGE_PROOF_SYSTEM.to_string(),
            PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM.to_string(),
            PROVER_BACKEND_RECURSIVE_PROOF_SYSTEM.to_string(),
            PROVER_BACKEND_WATCHTOWER_PROOF_SYSTEM.to_string(),
        ];

        let mut gpu_worker = ProverBackendWorker::new(
            "devnet-operator-a",
            "devnet-gpu-prover-a",
            BackendWorkerClass::Gpu,
            &gpu_systems,
            "devnet-gpu-pq-key-root",
            "devnet-gpu-attestation-root",
            "iad",
            96,
            8,
            0,
        )?;
        gpu_worker.status = WorkerRegistryStatus::Active;
        gpu_worker.last_heartbeat_height = state.height;
        let gpu_worker_id = state.insert_worker(gpu_worker)?;

        let mut aggregator_worker = ProverBackendWorker::new(
            "devnet-operator-b",
            "devnet-recursive-aggregator",
            BackendWorkerClass::Aggregator,
            &recursive_systems,
            "devnet-aggregator-pq-key-root",
            "devnet-aggregator-attestation-root",
            "ord",
            96,
            4,
            1,
        )?;
        aggregator_worker.status = WorkerRegistryStatus::Active;
        aggregator_worker.last_heartbeat_height = state.height;
        let aggregator_worker_id = state.insert_worker(aggregator_worker)?;

        let mut verifier_worker = ProverBackendWorker::new(
            "devnet-operator-c",
            "devnet-pq-verifier",
            BackendWorkerClass::Verifier,
            &verifier_systems,
            "devnet-verifier-pq-key-root",
            "devnet-verifier-attestation-root",
            "nyc",
            96,
            16,
            2,
        )?;
        verifier_worker.status = WorkerRegistryStatus::Active;
        verifier_worker.last_heartbeat_height = state.height;
        let verifier_worker_id = state.insert_worker(verifier_worker)?;

        let mut cpu_worker = ProverBackendWorker::new(
            "devnet-operator-d",
            "devnet-cpu-fallback",
            BackendWorkerClass::Cpu,
            &[PROVER_BACKEND_WATCHTOWER_PROOF_SYSTEM.to_string()],
            "devnet-cpu-pq-key-root",
            "devnet-cpu-attestation-root",
            "sfo",
            96,
            2,
            3,
        )?;
        cpu_worker.status = WorkerRegistryStatus::Quarantined;
        cpu_worker.last_heartbeat_height = state.height.saturating_sub(1);
        cpu_worker.quarantine_until_height = state.height.saturating_add(64);
        let cpu_worker_id = state.insert_worker(cpu_worker)?;

        for (index, worker_id) in [
            gpu_worker_id.clone(),
            aggregator_worker_id.clone(),
            verifier_worker_id.clone(),
            cpu_worker_id.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            let mut auth = PqWorkerAuthentication::new(
                worker_id.clone(),
                format!("{worker_id}:session-key"),
                format!("{worker_id}:auth-transcript"),
                format!("{worker_id}:pq-signature"),
                96,
                192,
                96,
                index as u64,
            )?;
            auth.status = if worker_id == cpu_worker_id {
                PqAuthenticationStatus::Pending
            } else {
                PqAuthenticationStatus::Active
            };
            state.insert_pq_authentication(auth)?;
        }

        state.insert_capacity_snapshot(WorkerCapacitySnapshot::new(
            gpu_worker_id.clone(),
            BackendWorkerClass::Gpu,
            state.height,
            32,
            4,
            98_304,
            4_000,
            56_000,
            18_000,
            8,
            3,
            2,
            9_200,
            0,
        )?)?;
        state.insert_capacity_snapshot(WorkerCapacitySnapshot::new(
            aggregator_worker_id.clone(),
            BackendWorkerClass::Aggregator,
            state.height,
            24,
            2,
            49_152,
            3_000,
            32_000,
            12_000,
            4,
            2,
            1,
            8_800,
            1,
        )?)?;
        state.insert_capacity_snapshot(WorkerCapacitySnapshot::new(
            verifier_worker_id.clone(),
            BackendWorkerClass::Verifier,
            state.height,
            48,
            0,
            0,
            7_500,
            0,
            1_500,
            16,
            2,
            0,
            10_000,
            2,
        )?)?;
        state.insert_capacity_snapshot(WorkerCapacitySnapshot::new(
            cpu_worker_id.clone(),
            BackendWorkerClass::Cpu,
            state.height,
            16,
            0,
            0,
            2_000,
            0,
            0,
            2,
            0,
            0,
            10_000,
            3,
        )?)?;

        let verifier_keys = vec![
            (
                PROVER_BACKEND_ROLLUP_PROOF_SYSTEM,
                "rollup-state-v1",
                "devnet-rollup-vk-root",
                false,
                0_u64,
            ),
            (
                PROVER_BACKEND_MONERO_BRIDGE_PROOF_SYSTEM,
                "monero-bridge-v1",
                "devnet-bridge-vk-root",
                false,
                1_u64,
            ),
            (
                PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM,
                "private-contract-v1",
                "devnet-private-contract-vk-root",
                false,
                2_u64,
            ),
            (
                PROVER_BACKEND_RECURSIVE_PROOF_SYSTEM,
                "recursive-backend-v1",
                "devnet-recursive-vk-root",
                true,
                3_u64,
            ),
            (
                PROVER_BACKEND_WATCHTOWER_PROOF_SYSTEM,
                "watchtower-fallback-v1",
                "devnet-watchtower-vk-root",
                false,
                4_u64,
            ),
        ];
        let mut key_ids = BTreeMap::new();
        for (proof_system, version, key_root, recursion_compatible, nonce) in verifier_keys {
            let key = VerifierKeyRecord::new(
                proof_system,
                version,
                key_root,
                "plonkish-shake256-vk",
                recursion_compatible,
                80,
                240,
                verifier_worker_id.clone(),
                format!("{proof_system}:vk-signature"),
                nonce,
            )?;
            let key_id = state.insert_verifier_key(key)?;
            key_ids.insert(proof_system.to_string(), key_id);
        }

        let sponsorship = LowFeeProofSponsorship::new(
            "devnet-proof-sponsor-dao",
            "devnet-low-fee-rollup",
            ProofBackendJobKind::RollupValidity,
            &state.policy.default_fee_asset_id,
            50_000,
            6_000,
            4_000,
            2_500,
            "devnet-low-fee-eligibility-root",
            90,
            220,
            0,
        )?;
        state.insert_sponsorship(sponsorship)?;

        let rollup_job_id = prover_backend_job_id("devnet-rollup-batch-120", 120, 0);
        let bridge_job_id = prover_backend_job_id("devnet-bridge-finality-120", 120, 1);
        let private_job_id = prover_backend_job_id("devnet-private-contract-120", 120, 2);

        let rollup_manifest = WitnessFetchManifest::new(
            rollup_job_id.clone(),
            ProofBackendJobKind::RollupValidity,
            "",
            "devnet-rollup-witness-root",
            "devnet-rollup-public-input-root",
            "devnet-rollup-private-input-commitment",
            "devnet-rollup-source-manifest-root",
            &[
                "blob:rollup:120".to_string(),
                "blob:rollup:state-diff".to_string(),
            ],
            "devnet-rollup-access-policy-root",
            "devnet-rollup-encryption-key",
            BackendWorkerClass::Gpu,
            118,
            124,
            0,
        )?;
        let rollup_manifest_id = state.insert_witness_manifest(rollup_manifest)?;

        let bridge_manifest = WitnessFetchManifest::new(
            bridge_job_id.clone(),
            ProofBackendJobKind::MoneroBridge,
            "",
            "devnet-bridge-witness-root",
            "devnet-bridge-public-input-root",
            "devnet-bridge-private-input-commitment",
            "devnet-bridge-source-manifest-root",
            &["blob:bridge:120".to_string()],
            "devnet-bridge-access-policy-root",
            "devnet-bridge-encryption-key",
            BackendWorkerClass::Gpu,
            118,
            124,
            1,
        )?;
        let bridge_manifest_id = state.insert_witness_manifest(bridge_manifest)?;

        let private_manifest = WitnessFetchManifest::new(
            private_job_id.clone(),
            ProofBackendJobKind::PrivateContract,
            "",
            "devnet-private-witness-root",
            "devnet-private-public-input-root",
            "devnet-private-input-commitment",
            "devnet-private-source-manifest-root",
            &["blob:private:120".to_string()],
            "devnet-private-access-policy-root",
            "devnet-private-encryption-key",
            BackendWorkerClass::Gpu,
            118,
            124,
            2,
        )?;
        let private_manifest_id = state.insert_witness_manifest(private_manifest)?;

        let rollup_quote = ProofFeeQuote::new(
            rollup_job_id.clone(),
            ProofBackendJobKind::RollupValidity,
            ProofBackendPriority::SponsoredLowFee,
            "",
            &state.policy.default_fee_asset_id,
            24_000_000,
            500_000,
            2_400,
            250,
            0,
            300,
            1_200,
            2_000,
            119,
            128,
            0,
        )?;
        let rollup_quote_id = state.insert_fee_quote(rollup_quote)?;

        let bridge_quote = ProofFeeQuote::new(
            bridge_job_id.clone(),
            ProofBackendJobKind::MoneroBridge,
            ProofBackendPriority::BridgeExit,
            "",
            &state.policy.default_fee_asset_id,
            18_500_000,
            420_000,
            3_250,
            800,
            600,
            450,
            0,
            5_500,
            119,
            128,
            1,
        )?;
        let bridge_quote_id = state.insert_fee_quote(bridge_quote)?;

        let private_quote = ProofFeeQuote::new(
            private_job_id.clone(),
            ProofBackendJobKind::PrivateContract,
            ProofBackendPriority::InteractivePrivate,
            "",
            &state.policy.default_fee_asset_id,
            16_000_000,
            390_000,
            2_900,
            550,
            700,
            350,
            0,
            5_000,
            119,
            128,
            2,
        )?;
        let private_quote_id = state.insert_fee_quote(private_quote)?;

        let rollup_key_id = require_map_value(
            &key_ids,
            PROVER_BACKEND_ROLLUP_PROOF_SYSTEM,
            "devnet rollup verifier key id",
        )?;
        let bridge_key_id = require_map_value(
            &key_ids,
            PROVER_BACKEND_MONERO_BRIDGE_PROOF_SYSTEM,
            "devnet bridge verifier key id",
        )?;
        let private_key_id = require_map_value(
            &key_ids,
            PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM,
            "devnet private contract verifier key id",
        )?;

        let mut rollup_lease = ProofJobLease::new(
            rollup_job_id.clone(),
            gpu_worker_id.clone(),
            rollup_manifest_id,
            rollup_quote_id,
            rollup_key_id.clone(),
            ProofBackendJobKind::RollupValidity,
            ProofBackendPriority::SponsoredLowFee,
            PROVER_BACKEND_ROLLUP_PROOF_SYSTEM,
            1,
            120,
            132,
            9_000,
            1_000,
            500,
            0,
        )?;
        rollup_lease.status = ProofLeaseStatus::Completed;
        let rollup_lease_id = state.insert_job_lease(rollup_lease)?;

        let mut bridge_lease = ProofJobLease::new(
            bridge_job_id.clone(),
            gpu_worker_id.clone(),
            bridge_manifest_id,
            bridge_quote_id,
            bridge_key_id.clone(),
            ProofBackendJobKind::MoneroBridge,
            ProofBackendPriority::BridgeExit,
            PROVER_BACKEND_MONERO_BRIDGE_PROOF_SYSTEM,
            1,
            120,
            132,
            7_500,
            1_000,
            700,
            1,
        )?;
        bridge_lease.status = ProofLeaseStatus::Active;
        let _bridge_lease_id = state.insert_job_lease(bridge_lease)?;

        let mut private_lease = ProofJobLease::new(
            private_job_id.clone(),
            gpu_worker_id.clone(),
            private_manifest_id,
            private_quote_id,
            private_key_id.clone(),
            ProofBackendJobKind::PrivateContract,
            ProofBackendPriority::InteractivePrivate,
            PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM,
            1,
            120,
            132,
            6_000,
            1_500,
            650,
            2,
        )?;
        private_lease.status = ProofLeaseStatus::Completed;
        let private_lease_id = state.insert_job_lease(private_lease)?;

        let mut rollup_artifact = ProofArtifactCommitment::new(
            rollup_job_id.clone(),
            rollup_lease_id.clone(),
            gpu_worker_id.clone(),
            ArtifactCommitmentKind::Proof,
            PROVER_BACKEND_ROLLUP_PROOF_SYSTEM,
            "devnet-rollup-proof-root",
            "devnet-rollup-public-input-root",
            "devnet-rollup-transcript-root",
            rollup_key_id.clone(),
            122,
            96_000,
            0,
            "devnet-rollup-proof-signature-root",
            0,
        )?;
        rollup_artifact.status = ArtifactCommitmentStatus::Stored;
        let rollup_artifact_root = rollup_artifact.artifact_root.clone();
        let rollup_public_input_root = rollup_artifact.public_inputs_root.clone();
        let rollup_artifact_id = state.insert_artifact_commitment(rollup_artifact)?;

        let mut private_artifact = ProofArtifactCommitment::new(
            private_job_id.clone(),
            private_lease_id.clone(),
            gpu_worker_id.clone(),
            ArtifactCommitmentKind::Proof,
            PROVER_BACKEND_PRIVATE_CONTRACT_PROOF_SYSTEM,
            "devnet-private-proof-root",
            "devnet-private-public-input-root",
            "devnet-private-transcript-root",
            private_key_id.clone(),
            122,
            88_000,
            0,
            "devnet-private-proof-signature-root",
            1,
        )?;
        private_artifact.status = ArtifactCommitmentStatus::Stored;
        let private_artifact_root = private_artifact.artifact_root.clone();
        let private_public_input_root = private_artifact.public_inputs_root.clone();
        let private_artifact_id = state.insert_artifact_commitment(private_artifact)?;

        let rollup_receipt = ProofVerificationReceipt::new(
            rollup_artifact_id.clone(),
            rollup_job_id.clone(),
            verifier_worker_id.clone(),
            rollup_key_id,
            VerificationOutcome::Accepted,
            RetryDisposition::RetryDifferentWorker,
            rollup_artifact_root,
            rollup_public_input_root,
            123,
            "devnet-rollup-verifier-notes-root",
            "devnet-rollup-verifier-signature-root",
            0,
        )?;
        state.insert_verification_receipt(rollup_receipt)?;

        let private_receipt = ProofVerificationReceipt::new(
            private_artifact_id.clone(),
            private_job_id.clone(),
            verifier_worker_id,
            private_key_id,
            VerificationOutcome::Accepted,
            RetryDisposition::RetryDifferentWorker,
            private_artifact_root,
            private_public_input_root,
            123,
            "devnet-private-verifier-notes-root",
            "devnet-private-verifier-signature-root",
            1,
        )?;
        state.insert_verification_receipt(private_receipt)?;

        let recursive_key_id = require_map_value(
            &key_ids,
            PROVER_BACKEND_RECURSIVE_PROOF_SYSTEM,
            "devnet recursive verifier key id",
        )?;
        let mut batch = RecursiveAggregationBatch::new(
            "devnet-recursive-batch-120",
            aggregator_worker_id,
            &[rollup_lease_id, private_lease_id],
            &[rollup_artifact_id, private_artifact_id],
            &[rollup_job_id, private_job_id],
            1,
            PROVER_BACKEND_RECURSIVE_PROOF_SYSTEM,
            recursive_key_id,
            120,
            136,
            "devnet-recursive-public-input-root",
            "devnet-recursive-witness-root",
            0,
        )?;
        batch.status = AggregationBatchStatus::Locked;
        state.insert_aggregation_batch(batch)?;

        let quarantine = WorkerQuarantineRecord::new(
            cpu_worker_id,
            bridge_job_id,
            "timeout_after_fetch",
            "devnet-timeout-evidence-root",
            118,
            184,
            2,
            RetryDisposition::QuarantineWorker,
            0,
        )?;
        state.insert_quarantine(quarantine)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_worker(
        &mut self,
        worker: ProverBackendWorker,
    ) -> ProverBackendOrchestratorResult<String> {
        worker.validate()?;
        if self.workers.contains_key(&worker.worker_id) {
            return Err("prover backend worker already exists".to_string());
        }
        let worker_id = worker.worker_id.clone();
        self.worker_lease_index
            .entry(worker_id.clone())
            .or_default();
        self.workers.insert(worker_id.clone(), worker);
        Ok(worker_id)
    }

    pub fn set_worker_status(
        &mut self,
        worker_id: &str,
        status: WorkerRegistryStatus,
    ) -> ProverBackendOrchestratorResult<()> {
        let worker = self
            .workers
            .get_mut(worker_id)
            .ok_or_else(|| "prover backend worker is missing".to_string())?;
        worker.status = status;
        Ok(())
    }

    pub fn insert_pq_authentication(
        &mut self,
        authentication: PqWorkerAuthentication,
    ) -> ProverBackendOrchestratorResult<String> {
        authentication.validate()?;
        if !self.workers.contains_key(&authentication.worker_id) {
            return Err("PQ authentication references unknown worker".to_string());
        }
        if self
            .pq_authentications
            .contains_key(&authentication.authentication_id)
        {
            return Err("PQ authentication already exists".to_string());
        }
        let authentication_id = authentication.authentication_id.clone();
        self.pq_authentications
            .insert(authentication_id.clone(), authentication);
        Ok(authentication_id)
    }

    pub fn insert_capacity_snapshot(
        &mut self,
        snapshot: WorkerCapacitySnapshot,
    ) -> ProverBackendOrchestratorResult<String> {
        snapshot.validate()?;
        let worker = self
            .workers
            .get(&snapshot.worker_id)
            .ok_or_else(|| "capacity snapshot references unknown worker".to_string())?;
        if worker.worker_class != snapshot.worker_class {
            return Err("capacity snapshot worker class mismatch".to_string());
        }
        if self.capacity_snapshots.contains_key(&snapshot.capacity_id) {
            return Err("capacity snapshot already exists".to_string());
        }
        let capacity_id = snapshot.capacity_id.clone();
        self.capacity_snapshots
            .insert(capacity_id.clone(), snapshot);
        Ok(capacity_id)
    }

    pub fn insert_verifier_key(
        &mut self,
        key: VerifierKeyRecord,
    ) -> ProverBackendOrchestratorResult<String> {
        key.validate()?;
        if !self.workers.contains_key(&key.publisher_worker_id) {
            return Err("verifier key references unknown publisher worker".to_string());
        }
        if self.verifier_keys.contains_key(&key.key_id) {
            return Err("verifier key already exists".to_string());
        }
        let key_id = key.key_id.clone();
        self.verifier_keys.insert(key_id.clone(), key);
        Ok(key_id)
    }

    pub fn insert_witness_manifest(
        &mut self,
        manifest: WitnessFetchManifest,
    ) -> ProverBackendOrchestratorResult<String> {
        manifest.validate()?;
        if self.witness_manifests.contains_key(&manifest.manifest_id) {
            return Err("witness manifest already exists".to_string());
        }
        let manifest_id = manifest.manifest_id.clone();
        self.witness_manifests.insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn insert_fee_quote(
        &mut self,
        quote: ProofFeeQuote,
    ) -> ProverBackendOrchestratorResult<String> {
        quote.validate()?;
        if self.fee_quotes.contains_key(&quote.quote_id) {
            return Err("proof fee quote already exists".to_string());
        }
        let quote_id = quote.quote_id.clone();
        self.fee_quotes.insert(quote_id.clone(), quote);
        Ok(quote_id)
    }

    pub fn insert_job_lease(
        &mut self,
        lease: ProofJobLease,
    ) -> ProverBackendOrchestratorResult<String> {
        lease.validate()?;
        let worker = self
            .workers
            .get(&lease.worker_id)
            .ok_or_else(|| "job lease references unknown worker".to_string())?;
        if !worker.supports(&lease.proof_system) {
            return Err("job lease worker does not support proof system".to_string());
        }
        let manifest = self
            .witness_manifests
            .get(&lease.manifest_id)
            .ok_or_else(|| "job lease references unknown witness manifest".to_string())?;
        if manifest.job_id != lease.job_id || manifest.proof_system != lease.proof_system {
            return Err("job lease manifest mismatch".to_string());
        }
        let quote = self
            .fee_quotes
            .get(&lease.quote_id)
            .ok_or_else(|| "job lease references unknown fee quote".to_string())?;
        if quote.job_id != lease.job_id || quote.proof_system != lease.proof_system {
            return Err("job lease fee quote mismatch".to_string());
        }
        let verifier_key = self
            .verifier_keys
            .get(&lease.verifier_key_id)
            .ok_or_else(|| "job lease references unknown verifier key".to_string())?;
        if verifier_key.proof_system != lease.proof_system {
            return Err("job lease verifier key proof system mismatch".to_string());
        }
        if self.job_leases.contains_key(&lease.lease_id) {
            return Err("job lease already exists".to_string());
        }
        let lease_id = lease.lease_id.clone();
        self.worker_lease_index
            .entry(lease.worker_id.clone())
            .or_default()
            .insert(lease_id.clone());
        self.job_leases.insert(lease_id.clone(), lease);
        Ok(lease_id)
    }

    pub fn insert_aggregation_batch(
        &mut self,
        batch: RecursiveAggregationBatch,
    ) -> ProverBackendOrchestratorResult<String> {
        batch.validate()?;
        let worker = self
            .workers
            .get(&batch.aggregator_worker_id)
            .ok_or_else(|| "aggregation batch references unknown worker".to_string())?;
        if worker.worker_class != BackendWorkerClass::Aggregator {
            return Err("aggregation batch worker is not an aggregator".to_string());
        }
        if batch.child_artifact_ids.len() as u64 > self.policy.max_batch_children {
            return Err("aggregation batch exceeds child limit".to_string());
        }
        for lease_id in &batch.lease_ids {
            if !self.job_leases.contains_key(lease_id) {
                return Err("aggregation batch references unknown lease".to_string());
            }
        }
        for artifact_id in &batch.child_artifact_ids {
            if !self.artifact_commitments.contains_key(artifact_id) {
                return Err("aggregation batch references unknown artifact".to_string());
            }
        }
        if !self.verifier_keys.contains_key(&batch.verifier_key_id) {
            return Err("aggregation batch references unknown verifier key".to_string());
        }
        if self.aggregation_batches.contains_key(&batch.batch_id) {
            return Err("aggregation batch already exists".to_string());
        }
        let batch_id = batch.batch_id.clone();
        self.aggregation_batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn insert_artifact_commitment(
        &mut self,
        artifact: ProofArtifactCommitment,
    ) -> ProverBackendOrchestratorResult<String> {
        artifact.validate()?;
        let lease = self
            .job_leases
            .get(&artifact.lease_id)
            .ok_or_else(|| "artifact references unknown lease".to_string())?;
        if lease.job_id != artifact.job_id || lease.worker_id != artifact.worker_id {
            return Err("artifact lease mismatch".to_string());
        }
        if lease.proof_system != artifact.proof_system {
            return Err("artifact proof system mismatch".to_string());
        }
        if !self.verifier_keys.contains_key(&artifact.verifier_key_id) {
            return Err("artifact references unknown verifier key".to_string());
        }
        if self
            .artifact_commitments
            .contains_key(&artifact.artifact_id)
        {
            return Err("artifact commitment already exists".to_string());
        }
        let artifact_id = artifact.artifact_id.clone();
        self.artifact_commitments
            .insert(artifact_id.clone(), artifact);
        Ok(artifact_id)
    }

    pub fn insert_verification_receipt(
        &mut self,
        receipt: ProofVerificationReceipt,
    ) -> ProverBackendOrchestratorResult<String> {
        receipt.validate()?;
        let artifact = self
            .artifact_commitments
            .get(&receipt.artifact_id)
            .ok_or_else(|| "verification receipt references unknown artifact".to_string())?;
        if artifact.job_id != receipt.job_id {
            return Err("verification receipt job mismatch".to_string());
        }
        if artifact.artifact_root != receipt.artifact_root {
            return Err("verification receipt artifact root mismatch".to_string());
        }
        if artifact.public_inputs_root != receipt.public_inputs_root {
            return Err("verification receipt public input root mismatch".to_string());
        }
        let worker = self
            .workers
            .get(&receipt.verifier_worker_id)
            .ok_or_else(|| "verification receipt references unknown verifier worker".to_string())?;
        if !worker.worker_class.can_verify() {
            return Err("verification receipt worker cannot verify".to_string());
        }
        if !self.verifier_keys.contains_key(&receipt.verifier_key_id) {
            return Err("verification receipt references unknown verifier key".to_string());
        }
        if self.verification_receipts.contains_key(&receipt.receipt_id) {
            return Err("verification receipt already exists".to_string());
        }
        if receipt.accepted() {
            self.completed_job_ids.insert(receipt.job_id.clone());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.verification_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_retry_policy(
        &mut self,
        policy: RetryPolicyRecord,
    ) -> ProverBackendOrchestratorResult<String> {
        policy.validate()?;
        if self.retry_policies.contains_key(&policy.policy_id) {
            return Err("retry policy already exists".to_string());
        }
        let policy_id = policy.policy_id.clone();
        self.retry_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn insert_quarantine(
        &mut self,
        quarantine: WorkerQuarantineRecord,
    ) -> ProverBackendOrchestratorResult<String> {
        quarantine.validate()?;
        if !self.workers.contains_key(&quarantine.worker_id) {
            return Err("quarantine references unknown worker".to_string());
        }
        if self.quarantines.contains_key(&quarantine.quarantine_id) {
            return Err("quarantine already exists".to_string());
        }
        let quarantine_id = quarantine.quarantine_id.clone();
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        Ok(quarantine_id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorship,
    ) -> ProverBackendOrchestratorResult<String> {
        sponsorship.validate()?;
        if self.sponsorships.contains_key(&sponsorship.sponsorship_id) {
            return Err("low fee sponsorship already exists".to_string());
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn worker_root(&self) -> String {
        let records = self
            .workers
            .values()
            .map(ProverBackendWorker::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-WORKER-SET", &records)
    }

    pub fn pq_authentication_root(&self) -> String {
        let records = self
            .pq_authentications
            .values()
            .map(PqWorkerAuthentication::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-PQ-AUTHENTICATION-SET", &records)
    }

    pub fn capacity_root(&self) -> String {
        let records = self
            .capacity_snapshots
            .values()
            .map(WorkerCapacitySnapshot::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-CAPACITY-SET", &records)
    }

    pub fn verifier_key_root(&self) -> String {
        let records = self
            .verifier_keys
            .values()
            .map(VerifierKeyRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-VERIFIER-KEY-SET", &records)
    }

    pub fn witness_manifest_root(&self) -> String {
        let records = self
            .witness_manifests
            .values()
            .map(WitnessFetchManifest::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-WITNESS-MANIFEST-SET", &records)
    }

    pub fn fee_quote_root(&self) -> String {
        let records = self
            .fee_quotes
            .values()
            .map(ProofFeeQuote::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-FEE-QUOTE-SET", &records)
    }

    pub fn job_lease_root(&self) -> String {
        let records = self
            .job_leases
            .values()
            .map(ProofJobLease::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-JOB-LEASE-SET", &records)
    }

    pub fn aggregation_batch_root(&self) -> String {
        let records = self
            .aggregation_batches
            .values()
            .map(RecursiveAggregationBatch::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-AGGREGATION-BATCH-SET", &records)
    }

    pub fn artifact_commitment_root(&self) -> String {
        let records = self
            .artifact_commitments
            .values()
            .map(ProofArtifactCommitment::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-ARTIFACT-COMMITMENT-SET", &records)
    }

    pub fn verification_receipt_root(&self) -> String {
        let records = self
            .verification_receipts
            .values()
            .map(ProofVerificationReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-VERIFICATION-RECEIPT-SET", &records)
    }

    pub fn retry_policy_root(&self) -> String {
        let records = self
            .retry_policies
            .values()
            .map(RetryPolicyRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-RETRY-POLICY-SET", &records)
    }

    pub fn quarantine_root(&self) -> String {
        let records = self
            .quarantines
            .values()
            .map(WorkerQuarantineRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-QUARANTINE-SET", &records)
    }

    pub fn sponsorship_root(&self) -> String {
        let records = self
            .sponsorships
            .values()
            .map(LowFeeProofSponsorship::public_record)
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-SPONSORSHIP-SET", &records)
    }

    pub fn worker_lease_index_root(&self) -> String {
        let records = self
            .worker_lease_index
            .iter()
            .map(|(worker_id, lease_ids)| {
                let lease_ids = lease_ids.iter().cloned().collect::<Vec<_>>();
                json!({
                    "worker_id": worker_id,
                    "lease_ids": lease_ids,
                    "lease_count": lease_ids.len() as u64,
                    "lease_root": prover_backend_string_set_root(
                        "PROVER-BACKEND-WORKER-LEASE-IDS",
                        &lease_ids
                    ),
                })
            })
            .collect::<Vec<_>>();
        merkle_root("PROVER-BACKEND-WORKER-LEASE-INDEX", &records)
    }

    pub fn completed_job_root(&self) -> String {
        let completed_job_ids = self.completed_job_ids.iter().cloned().collect::<Vec<_>>();
        prover_backend_string_set_root("PROVER-BACKEND-COMPLETED-JOBS", &completed_job_ids)
    }

    pub fn roots(&self) -> ProverBackendOrchestratorRoots {
        let policy_root = self.policy.policy_root();
        let worker_root = self.worker_root();
        let pq_authentication_root = self.pq_authentication_root();
        let capacity_root = self.capacity_root();
        let verifier_key_root = self.verifier_key_root();
        let witness_manifest_root = self.witness_manifest_root();
        let fee_quote_root = self.fee_quote_root();
        let job_lease_root = self.job_lease_root();
        let aggregation_batch_root = self.aggregation_batch_root();
        let artifact_commitment_root = self.artifact_commitment_root();
        let verification_receipt_root = self.verification_receipt_root();
        let retry_policy_root = self.retry_policy_root();
        let quarantine_root = self.quarantine_root();
        let sponsorship_root = self.sponsorship_root();
        let worker_lease_index_root = self.worker_lease_index_root();
        let completed_job_root = self.completed_job_root();
        let state_record = json!({
            "kind": "prover_backend_orchestrator_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "schema_version": PROVER_BACKEND_ORCHESTRATOR_SCHEMA_VERSION,
            "height": self.height,
            "orchestrator_label_root": prover_backend_string_root(
                "PROVER-BACKEND-ORCHESTRATOR-LABEL",
                &self.orchestrator_label
            ),
            "policy_root": policy_root,
            "worker_root": worker_root,
            "pq_authentication_root": pq_authentication_root,
            "capacity_root": capacity_root,
            "verifier_key_root": verifier_key_root,
            "witness_manifest_root": witness_manifest_root,
            "fee_quote_root": fee_quote_root,
            "job_lease_root": job_lease_root,
            "aggregation_batch_root": aggregation_batch_root,
            "artifact_commitment_root": artifact_commitment_root,
            "verification_receipt_root": verification_receipt_root,
            "retry_policy_root": retry_policy_root,
            "quarantine_root": quarantine_root,
            "sponsorship_root": sponsorship_root,
            "worker_lease_index_root": worker_lease_index_root,
            "completed_job_root": completed_job_root,
            "counters": self.counters().public_record(),
        });
        let state_root = prover_backend_state_root_from_record(&state_record);
        ProverBackendOrchestratorRoots {
            policy_root,
            worker_root,
            pq_authentication_root,
            capacity_root,
            verifier_key_root,
            witness_manifest_root,
            fee_quote_root,
            job_lease_root,
            aggregation_batch_root,
            artifact_commitment_root,
            verification_receipt_root,
            retry_policy_root,
            quarantine_root,
            sponsorship_root,
            worker_lease_index_root,
            completed_job_root,
            state_root,
        }
    }

    pub fn counters(&self) -> ProverBackendOrchestratorCounters {
        let mut counters = ProverBackendOrchestratorCounters {
            workers: self.workers.len() as u64,
            pq_authentications: self.pq_authentications.len() as u64,
            capacity_snapshots: self.capacity_snapshots.len() as u64,
            verifier_keys: self.verifier_keys.len() as u64,
            witness_manifests: self.witness_manifests.len() as u64,
            fee_quotes: self.fee_quotes.len() as u64,
            job_leases: self.job_leases.len() as u64,
            aggregation_batches: self.aggregation_batches.len() as u64,
            artifact_commitments: self.artifact_commitments.len() as u64,
            verification_receipts: self.verification_receipts.len() as u64,
            retry_policies: self.retry_policies.len() as u64,
            quarantines: self.quarantines.len() as u64,
            sponsorships: self.sponsorships.len() as u64,
            completed_jobs: self.completed_job_ids.len() as u64,
            ..ProverBackendOrchestratorCounters::default()
        };
        for worker in self.workers.values() {
            if worker.is_available_at(self.height, self.policy.stale_heartbeat_blocks) {
                counters.active_workers = counters.active_workers.saturating_add(1);
            }
            if worker.is_quarantined_at(self.height) {
                counters.quarantined_workers = counters.quarantined_workers.saturating_add(1);
            }
            if worker.status == WorkerRegistryStatus::Offline {
                counters.offline_workers = counters.offline_workers.saturating_add(1);
            }
            match worker.worker_class {
                BackendWorkerClass::Cpu => {
                    counters.cpu_workers = counters.cpu_workers.saturating_add(1)
                }
                BackendWorkerClass::Gpu
                | BackendWorkerClass::Hybrid
                | BackendWorkerClass::Aggregator => {
                    counters.gpu_workers = counters.gpu_workers.saturating_add(1)
                }
                BackendWorkerClass::Verifier | BackendWorkerClass::Watchtower => {
                    counters.verifier_workers = counters.verifier_workers.saturating_add(1)
                }
            }
        }
        for authentication in self.pq_authentications.values() {
            if authentication.is_live_at(self.height) {
                counters.live_pq_authentications =
                    counters.live_pq_authentications.saturating_add(1);
            }
        }
        for snapshot in self.capacity_snapshots.values() {
            counters.total_cpu_threads = counters
                .total_cpu_threads
                .saturating_add(snapshot.cpu_threads);
            counters.total_gpu_devices = counters
                .total_gpu_devices
                .saturating_add(snapshot.gpu_devices);
            counters.total_gpu_memory_mib = counters
                .total_gpu_memory_mib
                .saturating_add(snapshot.gpu_memory_mib);
            counters.total_compute_units = counters
                .total_compute_units
                .saturating_add(snapshot.total_compute_units());
            counters.total_reserved_compute_units = counters
                .total_reserved_compute_units
                .saturating_add(snapshot.reserved_compute_units);
            counters.total_available_compute_units = counters
                .total_available_compute_units
                .saturating_add(snapshot.available_compute_units());
            counters.total_parallel_slots = counters
                .total_parallel_slots
                .saturating_add(snapshot.max_parallel_slots);
        }
        for key in self.verifier_keys.values() {
            if key.is_active_at(self.height) {
                counters.active_verifier_keys = counters.active_verifier_keys.saturating_add(1);
            }
        }
        for manifest in self.witness_manifests.values() {
            if manifest.is_fetchable_at(self.height) {
                counters.fetchable_witness_manifests =
                    counters.fetchable_witness_manifests.saturating_add(1);
            }
        }
        for quote in self.fee_quotes.values() {
            if quote.is_live_at(self.height) {
                counters.live_fee_quotes = counters.live_fee_quotes.saturating_add(1);
            }
            counters.total_quote_fee_units = counters
                .total_quote_fee_units
                .saturating_add(quote.quoted_fee_units());
            counters.total_payable_fee_units = counters
                .total_payable_fee_units
                .saturating_add(quote.payable_fee_units());
            counters.total_sponsor_credit_units = counters
                .total_sponsor_credit_units
                .saturating_add(quote.sponsor_credit_units);
        }
        for lease in self.job_leases.values() {
            match lease.status {
                ProofLeaseStatus::Offered
                | ProofLeaseStatus::Active
                | ProofLeaseStatus::Submitted => {
                    if lease.is_active_at(self.height) {
                        counters.active_job_leases = counters.active_job_leases.saturating_add(1);
                    }
                    if lease.timed_out_at(self.height) {
                        counters.timed_out_job_leases =
                            counters.timed_out_job_leases.saturating_add(1);
                    }
                }
                ProofLeaseStatus::Completed => {
                    counters.completed_job_leases = counters.completed_job_leases.saturating_add(1)
                }
                ProofLeaseStatus::TimedOut => {
                    counters.timed_out_job_leases = counters.timed_out_job_leases.saturating_add(1)
                }
                ProofLeaseStatus::Retried => {
                    counters.retried_job_leases = counters.retried_job_leases.saturating_add(1)
                }
                ProofLeaseStatus::Quarantined => {
                    counters.quarantined_job_leases =
                        counters.quarantined_job_leases.saturating_add(1)
                }
                ProofLeaseStatus::Cancelled => {}
            }
        }
        for batch in self.aggregation_batches.values() {
            if batch.status.active() {
                counters.active_aggregation_batches =
                    counters.active_aggregation_batches.saturating_add(1);
            }
        }
        for artifact in self.artifact_commitments.values() {
            if matches!(
                artifact.status,
                ArtifactCommitmentStatus::Stored | ArtifactCommitmentStatus::Verified
            ) {
                counters.stored_artifacts = counters.stored_artifacts.saturating_add(1);
            }
            counters.total_artifact_bytes = counters
                .total_artifact_bytes
                .saturating_add(artifact.byte_len);
        }
        for receipt in self.verification_receipts.values() {
            match receipt.outcome {
                VerificationOutcome::Accepted => {
                    counters.accepted_receipts = counters.accepted_receipts.saturating_add(1)
                }
                VerificationOutcome::Rejected => {
                    counters.rejected_receipts = counters.rejected_receipts.saturating_add(1)
                }
                VerificationOutcome::NeedsRetry => {
                    counters.retry_receipts = counters.retry_receipts.saturating_add(1)
                }
                VerificationOutcome::Quarantined => {
                    counters.retry_receipts = counters.retry_receipts.saturating_add(1)
                }
            }
        }
        for policy in self.retry_policies.values() {
            if policy.status.active() {
                counters.active_retry_policies = counters.active_retry_policies.saturating_add(1);
            }
        }
        for quarantine in self.quarantines.values() {
            if quarantine.is_active_at(self.height) {
                counters.active_quarantines = counters.active_quarantines.saturating_add(1);
            }
        }
        for sponsorship in self.sponsorships.values() {
            if sponsorship.status.spendable()
                && self.height >= sponsorship.starts_at_height
                && self.height <= sponsorship.expires_at_height
            {
                counters.active_sponsorships = counters.active_sponsorships.saturating_add(1);
            }
            counters.total_sponsor_available_units = counters
                .total_sponsor_available_units
                .saturating_add(sponsorship.available_units());
        }
        counters
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "prover_backend_orchestrator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROVER_BACKEND_ORCHESTRATOR_PROTOCOL_VERSION,
            "schema_version": PROVER_BACKEND_ORCHESTRATOR_SCHEMA_VERSION,
            "height": self.height,
            "orchestrator_label": self.orchestrator_label,
            "policy": self.policy.public_record(),
            "workers": self.workers.values().map(ProverBackendWorker::public_record).collect::<Vec<_>>(),
            "pq_authentications": self.pq_authentications.values().map(PqWorkerAuthentication::public_record).collect::<Vec<_>>(),
            "capacity_snapshots": self.capacity_snapshots.values().map(WorkerCapacitySnapshot::public_record).collect::<Vec<_>>(),
            "verifier_keys": self.verifier_keys.values().map(VerifierKeyRecord::public_record).collect::<Vec<_>>(),
            "witness_manifests": self.witness_manifests.values().map(WitnessFetchManifest::public_record).collect::<Vec<_>>(),
            "fee_quotes": self.fee_quotes.values().map(ProofFeeQuote::public_record).collect::<Vec<_>>(),
            "job_leases": self.job_leases.values().map(ProofJobLease::public_record).collect::<Vec<_>>(),
            "aggregation_batches": self.aggregation_batches.values().map(RecursiveAggregationBatch::public_record).collect::<Vec<_>>(),
            "artifact_commitments": self.artifact_commitments.values().map(ProofArtifactCommitment::public_record).collect::<Vec<_>>(),
            "verification_receipts": self.verification_receipts.values().map(ProofVerificationReceipt::public_record).collect::<Vec<_>>(),
            "retry_policies": self.retry_policies.values().map(RetryPolicyRecord::public_record).collect::<Vec<_>>(),
            "quarantines": self.quarantines.values().map(WorkerQuarantineRecord::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(LowFeeProofSponsorship::public_record).collect::<Vec<_>>(),
            "worker_lease_index": self.worker_lease_index,
            "completed_job_ids": self.completed_job_ids.iter().cloned().collect::<Vec<_>>(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> ProverBackendOrchestratorResult<String> {
        ensure_non_empty(
            &self.orchestrator_label,
            "prover backend orchestrator label",
        )?;
        self.policy.validate()?;
        if self.workers.len() as u64 > self.policy.max_workers {
            return Err("prover backend worker limit exceeded".to_string());
        }
        if self.job_leases.len() as u64 > self.policy.max_leases {
            return Err("prover backend lease limit exceeded".to_string());
        }
        if self.artifact_commitments.len() as u64 > self.policy.max_artifacts {
            return Err("prover backend artifact limit exceeded".to_string());
        }
        for (worker_id, worker) in &self.workers {
            if worker_id != &worker.worker_id {
                return Err("prover backend worker map key mismatch".to_string());
            }
            worker.validate()?;
        }
        for (authentication_id, authentication) in &self.pq_authentications {
            if authentication_id != &authentication.authentication_id {
                return Err("PQ authentication map key mismatch".to_string());
            }
            authentication.validate()?;
            if !self.workers.contains_key(&authentication.worker_id) {
                return Err("PQ authentication references unknown worker".to_string());
            }
        }
        for (capacity_id, snapshot) in &self.capacity_snapshots {
            if capacity_id != &snapshot.capacity_id {
                return Err("capacity snapshot map key mismatch".to_string());
            }
            snapshot.validate()?;
            let worker = self
                .workers
                .get(&snapshot.worker_id)
                .ok_or_else(|| "capacity snapshot references unknown worker".to_string())?;
            if worker.worker_class != snapshot.worker_class {
                return Err("capacity snapshot worker class mismatch".to_string());
            }
        }
        for (key_id, key) in &self.verifier_keys {
            if key_id != &key.key_id {
                return Err("verifier key map key mismatch".to_string());
            }
            key.validate()?;
            if !self.workers.contains_key(&key.publisher_worker_id) {
                return Err("verifier key references unknown publisher worker".to_string());
            }
        }
        for (manifest_id, manifest) in &self.witness_manifests {
            if manifest_id != &manifest.manifest_id {
                return Err("witness manifest map key mismatch".to_string());
            }
            manifest.validate()?;
        }
        for (quote_id, quote) in &self.fee_quotes {
            if quote_id != &quote.quote_id {
                return Err("fee quote map key mismatch".to_string());
            }
            quote.validate()?;
        }
        let mut active_leases_by_worker: BTreeMap<String, u64> = BTreeMap::new();
        for (lease_id, lease) in &self.job_leases {
            if lease_id != &lease.lease_id {
                return Err("job lease map key mismatch".to_string());
            }
            lease.validate()?;
            let worker = self
                .workers
                .get(&lease.worker_id)
                .ok_or_else(|| "job lease references unknown worker".to_string())?;
            if !worker.supports(&lease.proof_system) {
                return Err("job lease worker proof system mismatch".to_string());
            }
            let manifest = self
                .witness_manifests
                .get(&lease.manifest_id)
                .ok_or_else(|| "job lease references unknown witness manifest".to_string())?;
            if manifest.job_id != lease.job_id || manifest.proof_system != lease.proof_system {
                return Err("job lease manifest mismatch".to_string());
            }
            let quote = self
                .fee_quotes
                .get(&lease.quote_id)
                .ok_or_else(|| "job lease references unknown fee quote".to_string())?;
            if quote.job_id != lease.job_id || quote.proof_system != lease.proof_system {
                return Err("job lease fee quote mismatch".to_string());
            }
            let verifier_key = self
                .verifier_keys
                .get(&lease.verifier_key_id)
                .ok_or_else(|| "job lease references unknown verifier key".to_string())?;
            if verifier_key.proof_system != lease.proof_system {
                return Err("job lease verifier key mismatch".to_string());
            }
            if lease.attempt > self.policy.max_retries.saturating_add(1) {
                return Err("job lease attempt exceeds retry policy".to_string());
            }
            if lease.is_active_at(self.height) {
                let entry = active_leases_by_worker
                    .entry(lease.worker_id.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }
        for (worker_id, active_leases) in active_leases_by_worker {
            let worker = self
                .workers
                .get(&worker_id)
                .ok_or_else(|| "active lease references unknown worker".to_string())?;
            if active_leases > worker.max_parallel_leases {
                return Err("active leases exceed worker parallel limit".to_string());
            }
        }
        for (batch_id, batch) in &self.aggregation_batches {
            if batch_id != &batch.batch_id {
                return Err("aggregation batch map key mismatch".to_string());
            }
            batch.validate()?;
            if batch.child_artifact_ids.len() as u64 > self.policy.max_batch_children {
                return Err("aggregation batch child limit exceeded".to_string());
            }
            let worker = self
                .workers
                .get(&batch.aggregator_worker_id)
                .ok_or_else(|| "aggregation batch references unknown worker".to_string())?;
            if worker.worker_class != BackendWorkerClass::Aggregator {
                return Err("aggregation batch worker is not an aggregator".to_string());
            }
            if !self.verifier_keys.contains_key(&batch.verifier_key_id) {
                return Err("aggregation batch references unknown verifier key".to_string());
            }
            for lease_id in &batch.lease_ids {
                if !self.job_leases.contains_key(lease_id) {
                    return Err("aggregation batch references unknown lease".to_string());
                }
            }
            for artifact_id in &batch.child_artifact_ids {
                if !self.artifact_commitments.contains_key(artifact_id) {
                    return Err("aggregation batch references unknown artifact".to_string());
                }
            }
        }
        for (artifact_id, artifact) in &self.artifact_commitments {
            if artifact_id != &artifact.artifact_id {
                return Err("artifact map key mismatch".to_string());
            }
            artifact.validate()?;
            let lease = self
                .job_leases
                .get(&artifact.lease_id)
                .ok_or_else(|| "artifact references unknown lease".to_string())?;
            if lease.job_id != artifact.job_id || lease.worker_id != artifact.worker_id {
                return Err("artifact lease mismatch".to_string());
            }
            if lease.proof_system != artifact.proof_system {
                return Err("artifact proof system mismatch".to_string());
            }
            if !self.verifier_keys.contains_key(&artifact.verifier_key_id) {
                return Err("artifact references unknown verifier key".to_string());
            }
        }
        for (receipt_id, receipt) in &self.verification_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("verification receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            let artifact = self
                .artifact_commitments
                .get(&receipt.artifact_id)
                .ok_or_else(|| "verification receipt references unknown artifact".to_string())?;
            if artifact.job_id != receipt.job_id {
                return Err("verification receipt job mismatch".to_string());
            }
            if artifact.artifact_root != receipt.artifact_root {
                return Err("verification receipt artifact root mismatch".to_string());
            }
            if artifact.public_inputs_root != receipt.public_inputs_root {
                return Err("verification receipt public input root mismatch".to_string());
            }
            let worker = self
                .workers
                .get(&receipt.verifier_worker_id)
                .ok_or_else(|| {
                    "verification receipt references unknown verifier worker".to_string()
                })?;
            if !worker.worker_class.can_verify() {
                return Err("verification receipt worker cannot verify".to_string());
            }
            if !self.verifier_keys.contains_key(&receipt.verifier_key_id) {
                return Err("verification receipt references unknown verifier key".to_string());
            }
        }
        let mut active_policy_kinds = BTreeSet::new();
        for (policy_id, policy) in &self.retry_policies {
            if policy_id != &policy.policy_id {
                return Err("retry policy map key mismatch".to_string());
            }
            policy.validate()?;
            if policy.status.active() && !active_policy_kinds.insert(policy.job_kind.as_str()) {
                return Err("duplicate active retry policy for job kind".to_string());
            }
        }
        for (quarantine_id, quarantine) in &self.quarantines {
            if quarantine_id != &quarantine.quarantine_id {
                return Err("quarantine map key mismatch".to_string());
            }
            quarantine.validate()?;
            if !self.workers.contains_key(&quarantine.worker_id) {
                return Err("quarantine references unknown worker".to_string());
            }
        }
        for (sponsorship_id, sponsorship) in &self.sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
        }
        for (worker_id, lease_ids) in &self.worker_lease_index {
            if !self.workers.contains_key(worker_id) {
                return Err("worker lease index references unknown worker".to_string());
            }
            for lease_id in lease_ids {
                let lease = self
                    .job_leases
                    .get(lease_id)
                    .ok_or_else(|| "worker lease index references unknown lease".to_string())?;
                if &lease.worker_id != worker_id {
                    return Err("worker lease index worker mismatch".to_string());
                }
            }
        }
        for job_id in &self.completed_job_ids {
            let has_receipt = self
                .verification_receipts
                .values()
                .any(|receipt| &receipt.job_id == job_id && receipt.accepted());
            if !has_receipt {
                return Err("completed job id has no accepted receipt".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn prover_backend_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn prover_backend_state_root_from_record(record: &Value) -> String {
    prover_backend_payload_root("PROVER-BACKEND-ORCHESTRATOR-STATE", record)
}

pub fn prover_backend_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn prover_backend_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn prover_backend_worker_id(operator_id: &str, worker_label: &str, nonce: u64) -> String {
    domain_hash(
        "PROVER-BACKEND-WORKER-ID",
        &[
            HashPart::Str(operator_id),
            HashPart::Str(worker_label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_pq_authentication_id(
    worker_id: &str,
    session_key_commitment: &str,
    valid_from_height: u64,
    valid_until_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-PQ-AUTHENTICATION-ID",
        &[
            HashPart::Str(worker_id),
            HashPart::Str(session_key_commitment),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(valid_until_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_capacity_id(
    worker_id: &str,
    measured_at_height: u64,
    worker_class: BackendWorkerClass,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-CAPACITY-ID",
        &[
            HashPart::Str(worker_id),
            HashPart::Str(worker_class.as_str()),
            HashPart::Int(measured_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_verifier_key_id(
    proof_system: &str,
    circuit_version: &str,
    verifier_key_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-VERIFIER-KEY-ID",
        &[
            HashPart::Str(proof_system),
            HashPart::Str(circuit_version),
            HashPart::Str(verifier_key_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_witness_manifest_id(
    job_id: &str,
    proof_system: &str,
    witness_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-WITNESS-MANIFEST-ID",
        &[
            HashPart::Str(job_id),
            HashPart::Str(proof_system),
            HashPart::Str(witness_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_fee_quote_id(
    job_id: &str,
    proof_system: &str,
    quote_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-FEE-QUOTE-ID",
        &[
            HashPart::Str(job_id),
            HashPart::Str(proof_system),
            HashPart::Int(quote_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_job_lease_id(
    job_id: &str,
    worker_id: &str,
    manifest_id: &str,
    attempt: u64,
    lease_start_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-JOB-LEASE-ID",
        &[
            HashPart::Str(job_id),
            HashPart::Str(worker_id),
            HashPart::Str(manifest_id),
            HashPart::Int(attempt as i128),
            HashPart::Int(lease_start_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_aggregation_batch_id(
    batch_label: &str,
    aggregator_worker_id: &str,
    target_proof_system: &str,
    window_start_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-AGGREGATION-BATCH-ID",
        &[
            HashPart::Str(batch_label),
            HashPart::Str(aggregator_worker_id),
            HashPart::Str(target_proof_system),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_artifact_id(
    job_id: &str,
    lease_id: &str,
    artifact_kind: ArtifactCommitmentKind,
    artifact_root: &str,
    produced_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-ARTIFACT-ID",
        &[
            HashPart::Str(job_id),
            HashPart::Str(lease_id),
            HashPart::Str(artifact_kind.as_str()),
            HashPart::Str(artifact_root),
            HashPart::Int(produced_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_verification_receipt_id(
    artifact_id: &str,
    job_id: &str,
    verifier_worker_id: &str,
    outcome: VerificationOutcome,
    verification_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-VERIFICATION-RECEIPT-ID",
        &[
            HashPart::Str(artifact_id),
            HashPart::Str(job_id),
            HashPart::Str(verifier_worker_id),
            HashPart::Str(outcome.as_str()),
            HashPart::Int(verification_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_retry_policy_id(
    job_kind: ProofBackendJobKind,
    max_attempts: u64,
    timeout_blocks: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-RETRY-POLICY-ID",
        &[
            HashPart::Str(job_kind.as_str()),
            HashPart::Int(max_attempts as i128),
            HashPart::Int(timeout_blocks as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_quarantine_id(
    worker_id: &str,
    job_id: &str,
    reason_code: &str,
    starts_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-QUARANTINE-ID",
        &[
            HashPart::Str(worker_id),
            HashPart::Str(job_id),
            HashPart::Str(reason_code),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_sponsorship_id(
    sponsor_id: &str,
    lane_label: &str,
    job_kind: ProofBackendJobKind,
    starts_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROVER-BACKEND-SPONSORSHIP-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_label),
            HashPart::Str(job_kind.as_str()),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn prover_backend_job_id(job_label: &str, height: u64, nonce: u64) -> String {
    domain_hash(
        "PROVER-BACKEND-JOB-ID",
        &[
            HashPart::Str(job_label),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn normalize_proof_system(proof_system: String, job_kind: ProofBackendJobKind) -> String {
    if proof_system.is_empty() {
        return job_kind.default_proof_system().to_string();
    }
    proof_system
}

fn normalize_nonempty_strings(
    values: &[String],
    field_name: &str,
) -> ProverBackendOrchestratorResult<Vec<String>> {
    let normalized = values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return Err(format!("{field_name} requires at least one value"));
    }
    Ok(normalized)
}

fn ensure_non_empty(value: &str, field_name: &str) -> ProverBackendOrchestratorResult<()> {
    if value.is_empty() {
        return Err(format!("{field_name} is required"));
    }
    Ok(())
}

fn ensure_positive(value: u64, field_name: &str) -> ProverBackendOrchestratorResult<()> {
    if value == 0 {
        return Err(format!("{field_name} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, field_name: &str) -> ProverBackendOrchestratorResult<()> {
    if value > PROVER_BACKEND_MAX_BPS {
        return Err(format!("{field_name} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_window(
    start_height: u64,
    end_height: u64,
    field_name: &str,
) -> ProverBackendOrchestratorResult<()> {
    if end_height < start_height {
        return Err(format!("{field_name} ends before it starts"));
    }
    Ok(())
}

fn require_map_value(
    values: &BTreeMap<String, String>,
    key: &str,
    field_name: &str,
) -> ProverBackendOrchestratorResult<String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| format!("{field_name} is missing"))
}
