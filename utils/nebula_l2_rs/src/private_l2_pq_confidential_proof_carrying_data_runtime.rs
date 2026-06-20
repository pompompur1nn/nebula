use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialProofCarryingDataRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-proof-carrying-data-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_POLICY_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-proof-carrying-data-policy-v1";
pub const PQ_VERIFIER_POLICY_ROOT_SCHEME: &str = "pq-confidential-contract-verifier-policy-root-v1";
pub const CIRCUIT_DESCRIPTOR_SCHEME: &str = "confidential-pcd-circuit-descriptor-root-v1";
pub const PROOF_DESCRIPTOR_SCHEME: &str = "confidential-pcd-proof-descriptor-root-v1";
pub const ENCRYPTED_WITNESS_COMMITMENT_SCHEME: &str =
    "pq-encrypted-confidential-witness-commitment-root-v1";
pub const FAST_VERIFY_BATCH_SCHEME: &str = "fast-confidential-pcd-verification-batch-root-v1";
pub const RECURSIVE_RECEIPT_SCHEME: &str = "recursive-confidential-pcd-receipt-root-v1";
pub const SPONSOR_RESERVATION_SCHEME: &str = "low-fee-confidential-pcd-sponsor-reservation-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "confidential-pcd-nullifier-privacy-fence-v1";
pub const REBATE_SCHEME: &str = "low-fee-confidential-pcd-rebate-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "confidential-pcd-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_928_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_CIRCUIT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_WITNESS_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FAST_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_VERIFY_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 12;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 1_024;
pub const MAX_POLICY_ROOTS: usize = 1_048_576;
pub const MAX_CIRCUITS: usize = 1_048_576;
pub const MAX_PROOFS: usize = 4_194_304;
pub const MAX_WITNESS_COMMITMENTS: usize = 4_194_304;
pub const MAX_BATCHES: usize = 2_097_152;
pub const MAX_RECEIPTS: usize = 2_097_152;
pub const MAX_RESERVATIONS: usize = 2_097_152;
pub const MAX_FENCES: usize = 4_194_304;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Defi,
    Token,
    Swap,
    Lending,
    Derivatives,
    Governance,
    Oracle,
    Bridge,
    Treasury,
    General,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Defi => "defi",
            Self::Token => "token",
            Self::Swap => "swap",
            Self::Lending => "lending",
            Self::Derivatives => "derivatives",
            Self::Governance => "governance",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::General => "general",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Active,
    Grace,
    Frozen,
    Superseded,
    Revoked,
}

impl PolicyStatus {
    pub fn accepts_descriptors(self) -> bool {
        matches!(self, Self::Active | Self::Grace | Self::Frozen)
    }

    pub fn accepts_proofs(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitKind {
    CallAuthorization,
    StateTransition,
    StorageRead,
    StorageWrite,
    EventDisclosure,
    TokenTransfer,
    DefiSettlement,
    OracleUpdate,
    RecursiveJoin,
    PrivacyFence,
}

impl CircuitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallAuthorization => "call_authorization",
            Self::StateTransition => "state_transition",
            Self::StorageRead => "storage_read",
            Self::StorageWrite => "storage_write",
            Self::EventDisclosure => "event_disclosure",
            Self::TokenTransfer => "token_transfer",
            Self::DefiSettlement => "defi_settlement",
            Self::OracleUpdate => "oracle_update",
            Self::RecursiveJoin => "recursive_join",
            Self::PrivacyFence => "privacy_fence",
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::StorageRead => 80,
            Self::CallAuthorization => 120,
            Self::EventDisclosure => 140,
            Self::TokenTransfer => 180,
            Self::StorageWrite => 220,
            Self::OracleUpdate => 240,
            Self::DefiSettlement => 320,
            Self::StateTransition => 360,
            Self::PrivacyFence => 420,
            Self::RecursiveJoin => 480,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitStatus {
    Proposed,
    Active,
    Hot,
    Frozen,
    Deprecated,
    Revoked,
}

impl CircuitStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Hot | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSystem {
    Stark,
    Plonkish,
    BulletproofsPlus,
    Halo2,
    Nova,
    Miden,
    RiscZero,
    Sp1,
    CustomPq,
}

impl ProofSystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stark => "stark",
            Self::Plonkish => "plonkish",
            Self::BulletproofsPlus => "bulletproofs_plus",
            Self::Halo2 => "halo2",
            Self::Nova => "nova",
            Self::Miden => "miden",
            Self::RiscZero => "risc_zero",
            Self::Sp1 => "sp1",
            Self::CustomPq => "custom_pq",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    PolicyMatched,
    WitnessBound,
    BatchQueued,
    FastVerified,
    Recursed,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl ProofStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::PolicyMatched
                | Self::WitnessBound
                | Self::BatchQueued
                | Self::FastVerified
                | Self::Recursed
        )
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::PolicyMatched | Self::WitnessBound | Self::BatchQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    Committed,
    Bound,
    OpenedForVerifier,
    Consumed,
    Expired,
    Quarantined,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchLane {
    UltraFast,
    LowFee,
    Defi,
    BridgeSafety,
    Recursive,
    Emergency,
}

impl BatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFast => "ultra_fast",
            Self::LowFee => "low_fee",
            Self::Defi => "defi",
            Self::BridgeSafety => "bridge_safety",
            Self::Recursive => "recursive",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::BridgeSafety => 900,
            Self::UltraFast => 840,
            Self::Defi => 760,
            Self::Recursive => 680,
            Self::LowFee => 520,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Locked,
    Verifying,
    Verified,
    Recursed,
    Settled,
    Disputed,
    Cancelled,
    Expired,
}

impl BatchStatus {
    pub fn accepts_items(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Verified,
    Finalized,
    Reorged,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    PartiallyConsumed,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Spent,
    Tombstoned,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimable,
    Claimed,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    InvalidPolicyRoot,
    InvalidCircuitDescriptor,
    InvalidProofDescriptor,
    WitnessMismatch,
    BatchEquivocation,
    ReceiptEquivocation,
    PrivacyFenceViolation,
    SponsorUnderfunded,
    RebateFraud,
    TimeoutFault,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPolicyRoot => "invalid_policy_root",
            Self::InvalidCircuitDescriptor => "invalid_circuit_descriptor",
            Self::InvalidProofDescriptor => "invalid_proof_descriptor",
            Self::WitnessMismatch => "witness_mismatch",
            Self::BatchEquivocation => "batch_equivocation",
            Self::ReceiptEquivocation => "receipt_equivocation",
            Self::PrivacyFenceViolation => "privacy_fence_violation",
            Self::SponsorUnderfunded => "sponsor_underfunded",
            Self::RebateFraud => "rebate_fraud",
            Self::TimeoutFault => "timeout_fault",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    PolicyRootRegistered,
    PolicyRootRotated,
    CircuitDescriptorRegistered,
    ProofDescriptorSubmitted,
    WitnessCommitted,
    WitnessBound,
    FastBatchOpened,
    ProofAddedToBatch,
    FastBatchVerified,
    RecursiveReceiptPublished,
    SponsorReserved,
    ReservationConsumed,
    PrivacyFenceOpened,
    PrivacyFenceSpent,
    RebateQueued,
    RebateClaimed,
    SlashingEvidenceSubmitted,
    SlashingApplied,
    RuntimeRootPublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyRootRegistered => "policy_root_registered",
            Self::PolicyRootRotated => "policy_root_rotated",
            Self::CircuitDescriptorRegistered => "circuit_descriptor_registered",
            Self::ProofDescriptorSubmitted => "proof_descriptor_submitted",
            Self::WitnessCommitted => "witness_committed",
            Self::WitnessBound => "witness_bound",
            Self::FastBatchOpened => "fast_batch_opened",
            Self::ProofAddedToBatch => "proof_added_to_batch",
            Self::FastBatchVerified => "fast_batch_verified",
            Self::RecursiveReceiptPublished => "recursive_receipt_published",
            Self::SponsorReserved => "sponsor_reserved",
            Self::ReservationConsumed => "reservation_consumed",
            Self::PrivacyFenceOpened => "privacy_fence_opened",
            Self::PrivacyFenceSpent => "privacy_fence_spent",
            Self::RebateQueued => "rebate_queued",
            Self::RebateClaimed => "rebate_claimed",
            Self::SlashingEvidenceSubmitted => "slashing_evidence_submitted",
            Self::SlashingApplied => "slashing_applied",
            Self::RuntimeRootPublished => "runtime_root_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub schema_version: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub policy_ttl_blocks: u64,
    pub circuit_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub witness_ttl_blocks: u64,
    pub fast_batch_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_verify_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_batch_items: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            schema_version: SCHEMA_VERSION,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            circuit_ttl_blocks: DEFAULT_CIRCUIT_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            witness_ttl_blocks: DEFAULT_WITNESS_TTL_BLOCKS,
            fast_batch_window_blocks: DEFAULT_FAST_BATCH_WINDOW_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_verify_fee_bps: DEFAULT_MAX_VERIFY_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "schema_version": self.schema_version,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "circuit_ttl_blocks": self.circuit_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "witness_ttl_blocks": self.witness_ttl_blocks,
            "fast_batch_window_blocks": self.fast_batch_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "max_verify_fee_bps": self.max_verify_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "max_batch_items": self.max_batch_items,
        })
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_at_least_u16(
            "min_pq_security_bits",
            self.min_pq_security_bits,
            DEFAULT_MIN_PQ_SECURITY_BITS,
        )?;
        require_at_least("min_privacy_set_size", self.min_privacy_set_size, 1)?;
        require_at_least(
            "batch_privacy_set_size",
            self.batch_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        require_bps("max_verify_fee_bps", self.max_verify_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        require_bps("quorum_bps", self.quorum_bps)?;
        require_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        require_at_least("strong_quorum_bps", self.strong_quorum_bps, self.quorum_bps)?;
        if self.max_batch_items == 0 {
            return Err("max_batch_items must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub policy_roots: u64,
    pub circuits: u64,
    pub proofs: u64,
    pub witness_commitments: u64,
    pub batches: u64,
    pub receipts: u64,
    pub reservations: u64,
    pub fences: u64,
    pub rebates: u64,
    pub slashing_evidence: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_roots": self.policy_roots,
            "circuits": self.circuits,
            "proofs": self.proofs,
            "witness_commitments": self.witness_commitments,
            "batches": self.batches,
            "receipts": self.receipts,
            "reservations": self.reservations,
            "fences": self.fences,
            "rebates": self.rebates,
            "slashing_evidence": self.slashing_evidence,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub policy_roots_root: String,
    pub circuit_descriptors_root: String,
    pub proof_descriptors_root: String,
    pub witness_commitments_root: String,
    pub fast_batches_root: String,
    pub recursive_receipts_root: String,
    pub sponsor_reservations_root: String,
    pub privacy_fences_root: String,
    pub rebates_root: String,
    pub slashing_evidence_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            policy_roots_root: empty_root("policy_roots"),
            circuit_descriptors_root: empty_root("circuit_descriptors"),
            proof_descriptors_root: empty_root("proof_descriptors"),
            witness_commitments_root: empty_root("witness_commitments"),
            fast_batches_root: empty_root("fast_batches"),
            recursive_receipts_root: empty_root("recursive_receipts"),
            sponsor_reservations_root: empty_root("sponsor_reservations"),
            privacy_fences_root: empty_root("privacy_fences"),
            rebates_root: empty_root("rebates"),
            slashing_evidence_root: empty_root("slashing_evidence"),
            events_root: empty_root("events"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_roots_root": self.policy_roots_root,
            "circuit_descriptors_root": self.circuit_descriptors_root,
            "proof_descriptors_root": self.proof_descriptors_root,
            "witness_commitments_root": self.witness_commitments_root,
            "fast_batches_root": self.fast_batches_root,
            "recursive_receipts_root": self.recursive_receipts_root,
            "sponsor_reservations_root": self.sponsor_reservations_root,
            "privacy_fences_root": self.privacy_fences_root,
            "rebates_root": self.rebates_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifierPolicyRoot {
    pub policy_id: String,
    pub contract_id: String,
    pub domain: ContractDomain,
    pub policy_root: String,
    pub verifier_set_root: String,
    pub allowed_circuit_kinds: BTreeSet<CircuitKind>,
    pub allowed_proof_systems: BTreeSet<ProofSystem>,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_verify_fee_bps: u64,
    pub quorum_bps: u64,
    pub status: PolicyStatus,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub supersedes_policy_id: Option<String>,
    pub metadata: Value,
}

impl VerifierPolicyRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "domain": self.domain,
            "policy_root": self.policy_root,
            "verifier_set_root": self.verifier_set_root,
            "allowed_circuit_kinds": self.allowed_circuit_kinds,
            "allowed_proof_systems": self.allowed_proof_systems,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_verify_fee_bps": self.max_verify_fee_bps,
            "quorum_bps": self.quorum_bps,
            "status": self.status,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "supersedes_policy_id": self.supersedes_policy_id,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(PQ_VERIFIER_POLICY_ROOT_SCHEME, &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("policy_id", &self.policy_id)?;
        require_id("contract_id", &self.contract_id)?;
        require_root("policy_root", &self.policy_root)?;
        require_root("verifier_set_root", &self.verifier_set_root)?;
        require_at_least_u16(
            "min_pq_security_bits",
            self.min_pq_security_bits,
            config.min_pq_security_bits,
        )?;
        require_at_least(
            "min_privacy_set_size",
            self.min_privacy_set_size,
            config.min_privacy_set_size,
        )?;
        require_bps("max_verify_fee_bps", self.max_verify_fee_bps)?;
        require_bps("quorum_bps", self.quorum_bps)?;
        if self.max_verify_fee_bps > config.max_verify_fee_bps {
            return Err("policy max verify fee exceeds config limit".to_string());
        }
        if self.allowed_circuit_kinds.is_empty() {
            return Err("policy must allow at least one circuit kind".to_string());
        }
        if self.allowed_proof_systems.is_empty() {
            return Err("policy must allow at least one proof system".to_string());
        }
        require_expiry(
            "policy",
            self.activated_at_height,
            self.expires_at_height,
            config.policy_ttl_blocks,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitDescriptor {
    pub circuit_id: String,
    pub policy_id: String,
    pub contract_id: String,
    pub circuit_kind: CircuitKind,
    pub proof_system: ProofSystem,
    pub circuit_commitment_root: String,
    pub verifier_key_root: String,
    pub public_input_schema_root: String,
    pub private_witness_schema_root: String,
    pub recursive_parent_circuit_id: Option<String>,
    pub pq_security_bits: u16,
    pub max_constraints: u64,
    pub estimated_verify_micros: u64,
    pub fee_weight: u64,
    pub status: CircuitStatus,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl CircuitDescriptor {
    pub fn public_record(&self) -> Value {
        json!({
            "circuit_id": self.circuit_id,
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "circuit_kind": self.circuit_kind,
            "proof_system": self.proof_system,
            "circuit_commitment_root": self.circuit_commitment_root,
            "verifier_key_root": self.verifier_key_root,
            "public_input_schema_root": self.public_input_schema_root,
            "private_witness_schema_root": self.private_witness_schema_root,
            "recursive_parent_circuit_id": self.recursive_parent_circuit_id,
            "pq_security_bits": self.pq_security_bits,
            "max_constraints": self.max_constraints,
            "estimated_verify_micros": self.estimated_verify_micros,
            "fee_weight": self.fee_weight,
            "status": self.status,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(CIRCUIT_DESCRIPTOR_SCHEME, &self.public_record())
    }

    pub fn validate(&self, policy: &VerifierPolicyRoot, config: &Config) -> Result<()> {
        require_id("circuit_id", &self.circuit_id)?;
        require_id("policy_id", &self.policy_id)?;
        require_id("contract_id", &self.contract_id)?;
        require_root("circuit_commitment_root", &self.circuit_commitment_root)?;
        require_root("verifier_key_root", &self.verifier_key_root)?;
        require_root("public_input_schema_root", &self.public_input_schema_root)?;
        require_root(
            "private_witness_schema_root",
            &self.private_witness_schema_root,
        )?;
        require_at_least_u16(
            "pq_security_bits",
            self.pq_security_bits,
            config.min_pq_security_bits,
        )?;
        require_at_least("max_constraints", self.max_constraints, 1)?;
        require_at_least("estimated_verify_micros", self.estimated_verify_micros, 1)?;
        require_at_least(
            "fee_weight",
            self.fee_weight,
            self.circuit_kind.base_weight(),
        )?;
        require_expiry(
            "circuit",
            self.published_at_height,
            self.expires_at_height,
            config.circuit_ttl_blocks,
        )?;
        if self.policy_id != policy.policy_id {
            return Err("circuit policy id mismatch".to_string());
        }
        if self.contract_id != policy.contract_id {
            return Err("circuit contract id mismatch".to_string());
        }
        if !policy.allowed_circuit_kinds.contains(&self.circuit_kind) {
            return Err("circuit kind not allowed by policy".to_string());
        }
        if !policy.allowed_proof_systems.contains(&self.proof_system) {
            return Err("proof system not allowed by policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProofDescriptor {
    pub proof_id: String,
    pub circuit_id: String,
    pub policy_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub public_input_root: String,
    pub proof_commitment_root: String,
    pub transcript_root: String,
    pub nullifier_root: String,
    pub witness_commitment_id: Option<String>,
    pub sponsor_reservation_id: Option<String>,
    pub privacy_fence_id: Option<String>,
    pub requested_lane: BatchLane,
    pub verify_fee_microunits: u64,
    pub privacy_set_size: u64,
    pub status: ProofStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl ProofDescriptor {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "circuit_id": self.circuit_id,
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "public_input_root": self.public_input_root,
            "proof_commitment_root": self.proof_commitment_root,
            "transcript_root": self.transcript_root,
            "nullifier_root": self.nullifier_root,
            "witness_commitment_id": self.witness_commitment_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "privacy_fence_id": self.privacy_fence_id,
            "requested_lane": self.requested_lane,
            "verify_fee_microunits": self.verify_fee_microunits,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(PROOF_DESCRIPTOR_SCHEME, &self.public_record())
    }

    pub fn validate(
        &self,
        policy: &VerifierPolicyRoot,
        circuit: &CircuitDescriptor,
        config: &Config,
    ) -> Result<()> {
        require_id("proof_id", &self.proof_id)?;
        require_id("circuit_id", &self.circuit_id)?;
        require_id("policy_id", &self.policy_id)?;
        require_id("contract_id", &self.contract_id)?;
        require_root("caller_commitment", &self.caller_commitment)?;
        require_root("public_input_root", &self.public_input_root)?;
        require_root("proof_commitment_root", &self.proof_commitment_root)?;
        require_root("transcript_root", &self.transcript_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_at_least(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        require_expiry(
            "proof",
            self.submitted_at_height,
            self.expires_at_height,
            config.proof_ttl_blocks,
        )?;
        if self.policy_id != policy.policy_id || self.policy_id != circuit.policy_id {
            return Err("proof policy id mismatch".to_string());
        }
        if self.circuit_id != circuit.circuit_id {
            return Err("proof circuit id mismatch".to_string());
        }
        if self.contract_id != policy.contract_id || self.contract_id != circuit.contract_id {
            return Err("proof contract id mismatch".to_string());
        }
        if !policy.accepts_proofs(self.submitted_at_height) {
            return Err("policy does not accept proof descriptors".to_string());
        }
        if !circuit.status.usable() {
            return Err("circuit is not usable".to_string());
        }
        Ok(())
    }
}

trait TimedPolicy {
    fn accepts_proofs(&self, height: u64) -> bool;
}

impl TimedPolicy for VerifierPolicyRoot {
    fn accepts_proofs(&self, height: u64) -> bool {
        self.status.accepts_proofs()
            && self.activated_at_height <= height
            && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedWitnessCommitment {
    pub witness_commitment_id: String,
    pub proof_id: String,
    pub circuit_id: String,
    pub encrypted_witness_root: String,
    pub witness_ciphertext_root: String,
    pub recipient_verifier_set_root: String,
    pub ephemeral_pq_key_root: String,
    pub disclosure_policy_root: String,
    pub blinding_root: String,
    pub byte_size: u64,
    pub status: WitnessStatus,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl EncryptedWitnessCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_commitment_id": self.witness_commitment_id,
            "proof_id": self.proof_id,
            "circuit_id": self.circuit_id,
            "encrypted_witness_root": self.encrypted_witness_root,
            "witness_ciphertext_root": self.witness_ciphertext_root,
            "recipient_verifier_set_root": self.recipient_verifier_set_root,
            "ephemeral_pq_key_root": self.ephemeral_pq_key_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "blinding_root": self.blinding_root,
            "byte_size": self.byte_size,
            "status": self.status,
            "committed_at_height": self.committed_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(ENCRYPTED_WITNESS_COMMITMENT_SCHEME, &self.public_record())
    }

    pub fn validate(&self, proof: &ProofDescriptor, config: &Config) -> Result<()> {
        require_id("witness_commitment_id", &self.witness_commitment_id)?;
        require_id("proof_id", &self.proof_id)?;
        require_id("circuit_id", &self.circuit_id)?;
        require_root("encrypted_witness_root", &self.encrypted_witness_root)?;
        require_root("witness_ciphertext_root", &self.witness_ciphertext_root)?;
        require_root(
            "recipient_verifier_set_root",
            &self.recipient_verifier_set_root,
        )?;
        require_root("ephemeral_pq_key_root", &self.ephemeral_pq_key_root)?;
        require_root("disclosure_policy_root", &self.disclosure_policy_root)?;
        require_root("blinding_root", &self.blinding_root)?;
        require_at_least("byte_size", self.byte_size, 1)?;
        require_expiry(
            "witness",
            self.committed_at_height,
            self.expires_at_height,
            config.witness_ttl_blocks,
        )?;
        if self.proof_id != proof.proof_id {
            return Err("witness proof id mismatch".to_string());
        }
        if self.circuit_id != proof.circuit_id {
            return Err("witness circuit id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FastVerificationBatch {
    pub batch_id: String,
    pub lane: BatchLane,
    pub policy_root: String,
    pub proof_ids: BTreeSet<String>,
    pub proof_root: String,
    pub witness_root: String,
    pub aggregate_public_input_root: String,
    pub verifier_committee_root: String,
    pub quorum_bps: u64,
    pub aggregate_fee_microunits: u64,
    pub aggregate_weight: u64,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub locked_at_height: Option<u64>,
    pub verified_at_height: Option<u64>,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl FastVerificationBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane,
            "policy_root": self.policy_root,
            "proof_ids": self.proof_ids,
            "proof_root": self.proof_root,
            "witness_root": self.witness_root,
            "aggregate_public_input_root": self.aggregate_public_input_root,
            "verifier_committee_root": self.verifier_committee_root,
            "quorum_bps": self.quorum_bps,
            "aggregate_fee_microunits": self.aggregate_fee_microunits,
            "aggregate_weight": self.aggregate_weight,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "locked_at_height": self.locked_at_height,
            "verified_at_height": self.verified_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(FAST_VERIFY_BATCH_SCHEME, &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("batch_id", &self.batch_id)?;
        require_root("policy_root", &self.policy_root)?;
        require_root("proof_root", &self.proof_root)?;
        require_root("witness_root", &self.witness_root)?;
        require_root(
            "aggregate_public_input_root",
            &self.aggregate_public_input_root,
        )?;
        require_root("verifier_committee_root", &self.verifier_committee_root)?;
        require_bps("quorum_bps", self.quorum_bps)?;
        require_at_least("quorum_bps", self.quorum_bps, config.quorum_bps)?;
        require_expiry(
            "batch",
            self.opened_at_height,
            self.expires_at_height,
            config.fast_batch_window_blocks,
        )?;
        if self.proof_ids.len() > config.max_batch_items {
            return Err("batch exceeds max item count".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecursiveProofReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub parent_receipt_id: Option<String>,
    pub recursion_depth: u16,
    pub recursive_circuit_id: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub accumulator_root: String,
    pub settled_state_root: String,
    pub verifier_attestation_root: String,
    pub covered_proof_count: u64,
    pub covered_fee_microunits: u64,
    pub status: ReceiptStatus,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl RecursiveProofReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "parent_receipt_id": self.parent_receipt_id,
            "recursion_depth": self.recursion_depth,
            "recursive_circuit_id": self.recursive_circuit_id,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "accumulator_root": self.accumulator_root,
            "settled_state_root": self.settled_state_root,
            "verifier_attestation_root": self.verifier_attestation_root,
            "covered_proof_count": self.covered_proof_count,
            "covered_fee_microunits": self.covered_fee_microunits,
            "status": self.status,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(RECURSIVE_RECEIPT_SCHEME, &self.public_record())
    }

    pub fn validate(&self, batch: &FastVerificationBatch, config: &Config) -> Result<()> {
        require_id("receipt_id", &self.receipt_id)?;
        require_id("batch_id", &self.batch_id)?;
        require_id("recursive_circuit_id", &self.recursive_circuit_id)?;
        require_root("batch_root", &self.batch_root)?;
        require_root("receipt_root", &self.receipt_root)?;
        require_root("accumulator_root", &self.accumulator_root)?;
        require_root("settled_state_root", &self.settled_state_root)?;
        require_root("verifier_attestation_root", &self.verifier_attestation_root)?;
        require_at_least("covered_proof_count", self.covered_proof_count, 1)?;
        require_expiry(
            "receipt",
            self.published_at_height,
            self.expires_at_height,
            config.receipt_ttl_blocks,
        )?;
        if self.batch_id != batch.batch_id {
            return Err("receipt batch id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub proof_id: Option<String>,
    pub batch_id: Option<String>,
    pub reserved_fee_microunits: u64,
    pub consumed_fee_microunits: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "reserved_fee_microunits": self.reserved_fee_microunits,
            "consumed_fee_microunits": self.consumed_fee_microunits,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(SPONSOR_RESERVATION_SCHEME, &self.public_record())
    }

    pub fn remaining_fee_microunits(&self) -> u64 {
        self.reserved_fee_microunits
            .saturating_sub(self.consumed_fee_microunits)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("reservation_id", &self.reservation_id)?;
        require_id("sponsor_id", &self.sponsor_id)?;
        require_root("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_at_least("reserved_fee_microunits", self.reserved_fee_microunits, 1)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require_expiry(
            "reservation",
            self.opened_at_height,
            self.expires_at_height,
            config.reservation_ttl_blocks,
        )?;
        if self.consumed_fee_microunits > self.reserved_fee_microunits {
            return Err("reservation consumed fee exceeds reserved fee".to_string());
        }
        if self.sponsor_cover_bps < config.sponsor_cover_bps {
            return Err("reservation sponsor cover below runtime minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub proof_id: String,
    pub nullifier_root: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub anonymity_set_root: String,
    pub privacy_set_size: u64,
    pub status: FenceStatus,
    pub opened_at_height: u64,
    pub spent_at_height: Option<u64>,
    pub metadata: Value,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "proof_id": self.proof_id,
            "nullifier_root": self.nullifier_root,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "anonymity_set_root": self.anonymity_set_root,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "spent_at_height": self.spent_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(PRIVACY_FENCE_SCHEME, &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("fence_id", &self.fence_id)?;
        require_id("proof_id", &self.proof_id)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_id("contract_id", &self.contract_id)?;
        require_root("caller_commitment", &self.caller_commitment)?;
        require_root("anonymity_set_root", &self.anonymity_set_root)?;
        require_at_least(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub reservation_id: String,
    pub proof_id: Option<String>,
    pub batch_id: Option<String>,
    pub recipient_commitment: String,
    pub rebate_microunits: u64,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub queued_at_height: u64,
    pub claimable_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.reservation_id,
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_microunits": self.rebate_microunits,
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "queued_at_height": self.queued_at_height,
            "claimable_at_height": self.claimable_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(REBATE_SCHEME, &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_id("rebate_id", &self.rebate_id)?;
        require_id("reservation_id", &self.reservation_id)?;
        require_root("recipient_commitment", &self.recipient_commitment)?;
        require_at_least("rebate_microunits", self.rebate_microunits, 1)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require_expiry(
            "rebate",
            self.queued_at_height,
            self.expires_at_height,
            config.rebate_ttl_blocks,
        )?;
        if self.claimable_at_height < self.queued_at_height {
            return Err("rebate claimable height precedes queued height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub subject_id: String,
    pub subject_root: String,
    pub reporter_commitment: String,
    pub accused_commitment: String,
    pub evidence_root: String,
    pub penalty_microunits: u64,
    pub status: EvidenceStatus,
    pub submitted_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub metadata: Value,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "reporter_commitment": self.reporter_commitment,
            "accused_commitment": self.accused_commitment,
            "evidence_root": self.evidence_root,
            "penalty_microunits": self.penalty_microunits,
            "status": self.status,
            "submitted_at_height": self.submitted_at_height,
            "resolved_at_height": self.resolved_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        record_root(SLASHING_EVIDENCE_SCHEME, &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require_id("evidence_id", &self.evidence_id)?;
        require_id("subject_id", &self.subject_id)?;
        require_root("subject_root", &self.subject_root)?;
        require_root("reporter_commitment", &self.reporter_commitment)?;
        require_root("accused_commitment", &self.accused_commitment)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_at_least("penalty_microunits", self.penalty_microunits, 1)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
    pub payload_root: String,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
            "payload_root": self.payload_root,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("confidential_pcd_event", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub policy_roots: BTreeMap<String, VerifierPolicyRoot>,
    pub circuits: BTreeMap<String, CircuitDescriptor>,
    pub proofs: BTreeMap<String, ProofDescriptor>,
    pub witness_commitments: BTreeMap<String, EncryptedWitnessCommitment>,
    pub fast_batches: BTreeMap<String, FastVerificationBatch>,
    pub recursive_receipts: BTreeMap<String, RecursiveProofReceipt>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            policy_roots: BTreeMap::new(),
            circuits: BTreeMap::new(),
            proofs: BTreeMap::new(),
            witness_commitments: BTreeMap::new(),
            fast_batches: BTreeMap::new(),
            recursive_receipts: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_policy_suite": PQ_POLICY_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root_with(&self.roots)
    }

    fn compute_state_root_with(&self, roots: &Roots) -> String {
        domain_hash(
            "private_l2_pq_confidential_pcd_state_root",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            policy_roots_root: map_root("policy_roots", &self.policy_roots, |v| v.public_record()),
            circuit_descriptors_root: map_root("circuit_descriptors", &self.circuits, |v| {
                v.public_record()
            }),
            proof_descriptors_root: map_root("proof_descriptors", &self.proofs, |v| {
                v.public_record()
            }),
            witness_commitments_root: map_root(
                "witness_commitments",
                &self.witness_commitments,
                |v| v.public_record(),
            ),
            fast_batches_root: map_root("fast_batches", &self.fast_batches, |v| v.public_record()),
            recursive_receipts_root: map_root(
                "recursive_receipts",
                &self.recursive_receipts,
                |v| v.public_record(),
            ),
            sponsor_reservations_root: map_root(
                "sponsor_reservations",
                &self.sponsor_reservations,
                |v| v.public_record(),
            ),
            privacy_fences_root: map_root("privacy_fences", &self.privacy_fences, |v| {
                v.public_record()
            }),
            rebates_root: map_root("rebates", &self.rebates, |v| v.public_record()),
            slashing_evidence_root: map_root("slashing_evidence", &self.slashing_evidence, |v| {
                v.public_record()
            }),
            events_root: map_root("events", &self.events, |v| v.public_record()),
        };
    }

    pub fn register_policy_root(
        &mut self,
        contract_id: String,
        domain: ContractDomain,
        policy_root_value: String,
        verifier_set_root: String,
        allowed_circuit_kinds: BTreeSet<CircuitKind>,
        allowed_proof_systems: BTreeSet<ProofSystem>,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        self.config.validate()?;
        require_capacity("policy_roots", self.policy_roots.len(), MAX_POLICY_ROOTS)?;
        let policy_id = policy_id(
            &contract_id,
            &policy_root_value,
            height,
            self.counters.policy_roots,
        );
        let policy = VerifierPolicyRoot {
            policy_id: policy_id.clone(),
            contract_id,
            domain,
            policy_root: policy_root_value,
            verifier_set_root,
            allowed_circuit_kinds,
            allowed_proof_systems,
            min_pq_security_bits: self.config.min_pq_security_bits,
            min_privacy_set_size: self.config.min_privacy_set_size,
            max_verify_fee_bps: self.config.max_verify_fee_bps,
            quorum_bps: self.config.quorum_bps,
            status: PolicyStatus::Active,
            activated_at_height: height,
            expires_at_height: height.saturating_add(self.config.policy_ttl_blocks),
            supersedes_policy_id: None,
            metadata,
        };
        policy.validate(&self.config)?;
        let root = policy.record_root();
        self.policy_roots.insert(policy_id.clone(), policy);
        self.counters.policy_roots = self.counters.policy_roots.saturating_add(1);
        self.push_event(EventKind::PolicyRootRegistered, &policy_id, &root, height);
        self.refresh_roots();
        Ok(policy_id)
    }

    pub fn rotate_policy_root(
        &mut self,
        old_policy_id: &str,
        new_policy_root: String,
        new_verifier_set_root: String,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        let old = self
            .policy_roots
            .get_mut(old_policy_id)
            .ok_or_else(|| "old policy not found".to_string())?;
        if !old.status.accepts_descriptors() {
            return Err("old policy cannot be rotated from its current status".to_string());
        }
        old.status = PolicyStatus::Superseded;
        let contract_id = old.contract_id.clone();
        let domain = old.domain;
        let allowed_circuit_kinds = old.allowed_circuit_kinds.clone();
        let allowed_proof_systems = old.allowed_proof_systems.clone();
        let policy_id = policy_id(
            &contract_id,
            &new_policy_root,
            height,
            self.counters.policy_roots,
        );
        let policy = VerifierPolicyRoot {
            policy_id: policy_id.clone(),
            contract_id,
            domain,
            policy_root: new_policy_root,
            verifier_set_root: new_verifier_set_root,
            allowed_circuit_kinds,
            allowed_proof_systems,
            min_pq_security_bits: self.config.min_pq_security_bits,
            min_privacy_set_size: self.config.min_privacy_set_size,
            max_verify_fee_bps: self.config.max_verify_fee_bps,
            quorum_bps: self.config.quorum_bps,
            status: PolicyStatus::Active,
            activated_at_height: height,
            expires_at_height: height.saturating_add(self.config.policy_ttl_blocks),
            supersedes_policy_id: Some(old_policy_id.to_string()),
            metadata,
        };
        policy.validate(&self.config)?;
        let root = policy.record_root();
        self.policy_roots.insert(policy_id.clone(), policy);
        self.counters.policy_roots = self.counters.policy_roots.saturating_add(1);
        self.push_event(EventKind::PolicyRootRotated, &policy_id, &root, height);
        self.refresh_roots();
        Ok(policy_id)
    }

    pub fn register_circuit_descriptor(
        &mut self,
        policy_id_value: &str,
        circuit_kind: CircuitKind,
        proof_system: ProofSystem,
        circuit_commitment_root: String,
        verifier_key_root: String,
        public_input_schema_root: String,
        private_witness_schema_root: String,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity("circuits", self.circuits.len(), MAX_CIRCUITS)?;
        let policy = self
            .policy_roots
            .get(policy_id_value)
            .ok_or_else(|| "policy not found".to_string())?;
        if !policy.accepts_proofs(height) {
            return Err("policy is not active at circuit height".to_string());
        }
        let circuit_id_value = circuit_id(
            policy_id_value,
            circuit_kind,
            proof_system,
            &circuit_commitment_root,
            height,
            self.counters.circuits,
        );
        let circuit = CircuitDescriptor {
            circuit_id: circuit_id_value.clone(),
            policy_id: policy_id_value.to_string(),
            contract_id: policy.contract_id.clone(),
            circuit_kind,
            proof_system,
            circuit_commitment_root,
            verifier_key_root,
            public_input_schema_root,
            private_witness_schema_root,
            recursive_parent_circuit_id: None,
            pq_security_bits: self.config.min_pq_security_bits,
            max_constraints: circuit_kind.base_weight().saturating_mul(1_000),
            estimated_verify_micros: circuit_kind.base_weight().saturating_mul(25),
            fee_weight: circuit_kind.base_weight(),
            status: CircuitStatus::Active,
            published_at_height: height,
            expires_at_height: height.saturating_add(self.config.circuit_ttl_blocks),
            metadata,
        };
        circuit.validate(policy, &self.config)?;
        let root = circuit.record_root();
        self.circuits.insert(circuit_id_value.clone(), circuit);
        self.counters.circuits = self.counters.circuits.saturating_add(1);
        self.push_event(
            EventKind::CircuitDescriptorRegistered,
            &circuit_id_value,
            &root,
            height,
        );
        self.refresh_roots();
        Ok(circuit_id_value)
    }

    pub fn submit_proof_descriptor(
        &mut self,
        circuit_id_value: &str,
        caller_commitment: String,
        public_input_root: String,
        proof_commitment_root: String,
        transcript_root: String,
        nullifier_root: String,
        requested_lane: BatchLane,
        verify_fee_microunits: u64,
        privacy_set_size: u64,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity("proofs", self.proofs.len(), MAX_PROOFS)?;
        let circuit = self
            .circuits
            .get(circuit_id_value)
            .ok_or_else(|| "circuit not found".to_string())?;
        let policy = self
            .policy_roots
            .get(&circuit.policy_id)
            .ok_or_else(|| "policy not found".to_string())?;
        let proof_id_value = proof_id(
            circuit_id_value,
            &public_input_root,
            &proof_commitment_root,
            &nullifier_root,
            height,
            self.counters.proofs,
        );
        let proof = ProofDescriptor {
            proof_id: proof_id_value.clone(),
            circuit_id: circuit_id_value.to_string(),
            policy_id: circuit.policy_id.clone(),
            contract_id: circuit.contract_id.clone(),
            caller_commitment,
            public_input_root,
            proof_commitment_root,
            transcript_root,
            nullifier_root,
            witness_commitment_id: None,
            sponsor_reservation_id: None,
            privacy_fence_id: None,
            requested_lane,
            verify_fee_microunits,
            privacy_set_size,
            status: ProofStatus::Submitted,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(self.config.proof_ttl_blocks),
            metadata,
        };
        proof.validate(policy, circuit, &self.config)?;
        let root = proof.record_root();
        self.proofs.insert(proof_id_value.clone(), proof);
        self.counters.proofs = self.counters.proofs.saturating_add(1);
        self.push_event(
            EventKind::ProofDescriptorSubmitted,
            &proof_id_value,
            &root,
            height,
        );
        self.refresh_roots();
        Ok(proof_id_value)
    }

    pub fn commit_encrypted_witness(
        &mut self,
        proof_id_value: &str,
        encrypted_witness_root: String,
        witness_ciphertext_root: String,
        recipient_verifier_set_root: String,
        ephemeral_pq_key_root: String,
        disclosure_policy_root: String,
        blinding_root: String,
        byte_size: u64,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity(
            "witness_commitments",
            self.witness_commitments.len(),
            MAX_WITNESS_COMMITMENTS,
        )?;
        let proof = self
            .proofs
            .get(proof_id_value)
            .ok_or_else(|| "proof not found".to_string())?;
        let witness_id = witness_commitment_id(
            proof_id_value,
            &encrypted_witness_root,
            &witness_ciphertext_root,
            height,
            self.counters.witness_commitments,
        );
        let witness = EncryptedWitnessCommitment {
            witness_commitment_id: witness_id.clone(),
            proof_id: proof_id_value.to_string(),
            circuit_id: proof.circuit_id.clone(),
            encrypted_witness_root,
            witness_ciphertext_root,
            recipient_verifier_set_root,
            ephemeral_pq_key_root,
            disclosure_policy_root,
            blinding_root,
            byte_size,
            status: WitnessStatus::Committed,
            committed_at_height: height,
            expires_at_height: height.saturating_add(self.config.witness_ttl_blocks),
            metadata,
        };
        witness.validate(proof, &self.config)?;
        let root = witness.record_root();
        self.witness_commitments.insert(witness_id.clone(), witness);
        if let Some(proof) = self.proofs.get_mut(proof_id_value) {
            proof.witness_commitment_id = Some(witness_id.clone());
            proof.status = ProofStatus::WitnessBound;
        }
        self.counters.witness_commitments = self.counters.witness_commitments.saturating_add(1);
        self.push_event(EventKind::WitnessCommitted, &witness_id, &root, height);
        self.push_event(EventKind::WitnessBound, proof_id_value, &root, height);
        self.refresh_roots();
        Ok(witness_id)
    }

    pub fn reserve_sponsor_fee(
        &mut self,
        sponsor_id: String,
        beneficiary_commitment: String,
        proof_id_value: Option<String>,
        reserved_fee_microunits: u64,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            MAX_RESERVATIONS,
        )?;
        let reservation_id_value = reservation_id(
            &sponsor_id,
            proof_id_value.as_deref().unwrap_or("batch"),
            reserved_fee_microunits,
            height,
            self.counters.reservations,
        );
        let reservation = SponsorReservation {
            reservation_id: reservation_id_value.clone(),
            sponsor_id,
            beneficiary_commitment,
            proof_id: proof_id_value.clone(),
            batch_id: None,
            reserved_fee_microunits,
            consumed_fee_microunits: 0,
            sponsor_cover_bps: self.config.sponsor_cover_bps,
            rebate_bps: self.config.target_rebate_bps,
            status: ReservationStatus::Reserved,
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.reservation_ttl_blocks),
            metadata,
        };
        reservation.validate(&self.config)?;
        let root = reservation.record_root();
        self.sponsor_reservations
            .insert(reservation_id_value.clone(), reservation);
        if let Some(proof_id) = proof_id_value {
            if let Some(proof) = self.proofs.get_mut(&proof_id) {
                proof.sponsor_reservation_id = Some(reservation_id_value.clone());
                proof.status = ProofStatus::PolicyMatched;
            }
        }
        self.counters.reservations = self.counters.reservations.saturating_add(1);
        self.push_event(
            EventKind::SponsorReserved,
            &reservation_id_value,
            &root,
            height,
        );
        self.refresh_roots();
        Ok(reservation_id_value)
    }

    pub fn open_privacy_fence(
        &mut self,
        proof_id_value: &str,
        anonymity_set_root: String,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity("privacy_fences", self.privacy_fences.len(), MAX_FENCES)?;
        let proof = self
            .proofs
            .get(proof_id_value)
            .ok_or_else(|| "proof not found".to_string())?;
        if self.privacy_fences.values().any(|fence| {
            fence.nullifier_root == proof.nullifier_root && fence.status != FenceStatus::Tombstoned
        }) {
            return Err("nullifier already fenced".to_string());
        }
        let fence_id_value = fence_id(
            proof_id_value,
            &proof.nullifier_root,
            &anonymity_set_root,
            height,
            self.counters.fences,
        );
        let fence = PrivacyFence {
            fence_id: fence_id_value.clone(),
            proof_id: proof_id_value.to_string(),
            nullifier_root: proof.nullifier_root.clone(),
            contract_id: proof.contract_id.clone(),
            caller_commitment: proof.caller_commitment.clone(),
            anonymity_set_root,
            privacy_set_size: proof.privacy_set_size,
            status: FenceStatus::Open,
            opened_at_height: height,
            spent_at_height: None,
            metadata,
        };
        fence.validate(&self.config)?;
        let root = fence.record_root();
        self.privacy_fences.insert(fence_id_value.clone(), fence);
        if let Some(proof) = self.proofs.get_mut(proof_id_value) {
            proof.privacy_fence_id = Some(fence_id_value.clone());
        }
        self.counters.fences = self.counters.fences.saturating_add(1);
        self.push_event(
            EventKind::PrivacyFenceOpened,
            &fence_id_value,
            &root,
            height,
        );
        self.refresh_roots();
        Ok(fence_id_value)
    }

    pub fn open_fast_batch(
        &mut self,
        lane: BatchLane,
        policy_id_value: &str,
        verifier_committee_root: String,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity("fast_batches", self.fast_batches.len(), MAX_BATCHES)?;
        let policy = self
            .policy_roots
            .get(policy_id_value)
            .ok_or_else(|| "policy not found".to_string())?;
        let batch_id_value = batch_id(
            lane,
            &policy.policy_root,
            &verifier_committee_root,
            height,
            self.counters.batches,
        );
        let batch = FastVerificationBatch {
            batch_id: batch_id_value.clone(),
            lane,
            policy_root: policy.policy_root.clone(),
            proof_ids: BTreeSet::new(),
            proof_root: empty_root("batch_proofs"),
            witness_root: empty_root("batch_witnesses"),
            aggregate_public_input_root: empty_root("batch_public_inputs"),
            verifier_committee_root,
            quorum_bps: policy.quorum_bps,
            aggregate_fee_microunits: 0,
            aggregate_weight: lane.priority(),
            status: BatchStatus::Open,
            opened_at_height: height,
            locked_at_height: None,
            verified_at_height: None,
            expires_at_height: height.saturating_add(self.config.fast_batch_window_blocks),
            metadata,
        };
        batch.validate(&self.config)?;
        let root = batch.record_root();
        self.fast_batches.insert(batch_id_value.clone(), batch);
        self.counters.batches = self.counters.batches.saturating_add(1);
        self.push_event(EventKind::FastBatchOpened, &batch_id_value, &root, height);
        self.refresh_roots();
        Ok(batch_id_value)
    }

    pub fn add_proof_to_fast_batch(
        &mut self,
        batch_id_value: &str,
        proof_id_value: &str,
        height: u64,
    ) -> Result<()> {
        let proof = self
            .proofs
            .get(proof_id_value)
            .ok_or_else(|| "proof not found".to_string())?
            .clone();
        if !proof.status.batchable() {
            return Err("proof is not batchable".to_string());
        }
        let witness_id = proof
            .witness_commitment_id
            .clone()
            .ok_or_else(|| "proof has no witness commitment".to_string())?;
        let witness = self
            .witness_commitments
            .get(&witness_id)
            .ok_or_else(|| "witness commitment not found".to_string())?;
        let batch = self
            .fast_batches
            .get_mut(batch_id_value)
            .ok_or_else(|| "batch not found".to_string())?;
        if !batch.status.accepts_items() {
            return Err("batch is not open".to_string());
        }
        if batch.proof_ids.len() >= self.config.max_batch_items {
            return Err("batch is full".to_string());
        }
        batch.proof_ids.insert(proof_id_value.to_string());
        batch.aggregate_fee_microunits = batch
            .aggregate_fee_microunits
            .saturating_add(proof.verify_fee_microunits);
        batch.aggregate_weight = batch
            .aggregate_weight
            .saturating_add(proof.requested_lane.priority());
        batch.proof_root = merkle_root(
            "confidential_pcd_batch_proofs",
            &batch
                .proof_ids
                .iter()
                .filter_map(|id| self.proofs.get(id))
                .map(ProofDescriptor::public_record)
                .collect::<Vec<_>>(),
        );
        batch.witness_root = merkle_root(
            "confidential_pcd_batch_witnesses",
            &[witness.public_record()],
        );
        batch.aggregate_public_input_root = domain_hash(
            "confidential_pcd_batch_public_inputs",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&proof.public_input_root),
                HashPart::Str(&batch.proof_root),
            ],
            32,
        );
        batch.validate(&self.config)?;
        if let Some(proof) = self.proofs.get_mut(proof_id_value) {
            proof.status = ProofStatus::BatchQueued;
        }
        let root = batch.record_root();
        self.push_event(EventKind::ProofAddedToBatch, proof_id_value, &root, height);
        self.refresh_roots();
        Ok(())
    }

    pub fn verify_fast_batch(&mut self, batch_id_value: &str, height: u64) -> Result<()> {
        let batch = self
            .fast_batches
            .get_mut(batch_id_value)
            .ok_or_else(|| "batch not found".to_string())?;
        if batch.proof_ids.is_empty() {
            return Err("cannot verify empty batch".to_string());
        }
        if height > batch.expires_at_height {
            batch.status = BatchStatus::Expired;
            return Err("batch expired".to_string());
        }
        batch.status = BatchStatus::Verified;
        batch.locked_at_height = batch.locked_at_height.or(Some(height));
        batch.verified_at_height = Some(height);
        let proof_ids = batch.proof_ids.iter().cloned().collect::<Vec<_>>();
        let root = batch.record_root();
        for proof_id in proof_ids {
            if let Some(proof) = self.proofs.get_mut(&proof_id) {
                proof.status = ProofStatus::FastVerified;
            }
        }
        self.push_event(EventKind::FastBatchVerified, batch_id_value, &root, height);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_recursive_receipt(
        &mut self,
        batch_id_value: &str,
        recursive_circuit_id: String,
        accumulator_root: String,
        settled_state_root: String,
        verifier_attestation_root: String,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity(
            "recursive_receipts",
            self.recursive_receipts.len(),
            MAX_RECEIPTS,
        )?;
        let batch = self
            .fast_batches
            .get(batch_id_value)
            .ok_or_else(|| "batch not found".to_string())?;
        if batch.status != BatchStatus::Verified {
            return Err("batch must be verified before recursive receipt".to_string());
        }
        let receipt_id_value = receipt_id(
            batch_id_value,
            &batch.proof_root,
            &accumulator_root,
            height,
            self.counters.receipts,
        );
        let receipt_root_value = domain_hash(
            "confidential_pcd_recursive_receipt_payload",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(batch_id_value),
                HashPart::Str(&accumulator_root),
                HashPart::Str(&settled_state_root),
            ],
            32,
        );
        let receipt = RecursiveProofReceipt {
            receipt_id: receipt_id_value.clone(),
            batch_id: batch_id_value.to_string(),
            parent_receipt_id: None,
            recursion_depth: 1,
            recursive_circuit_id,
            batch_root: batch.record_root(),
            receipt_root: receipt_root_value,
            accumulator_root,
            settled_state_root,
            verifier_attestation_root,
            covered_proof_count: batch.proof_ids.len() as u64,
            covered_fee_microunits: batch.aggregate_fee_microunits,
            status: ReceiptStatus::Published,
            published_at_height: height,
            finalized_at_height: None,
            expires_at_height: height.saturating_add(self.config.receipt_ttl_blocks),
            metadata,
        };
        receipt.validate(batch, &self.config)?;
        let root = receipt.record_root();
        self.recursive_receipts
            .insert(receipt_id_value.clone(), receipt);
        if let Some(batch) = self.fast_batches.get_mut(batch_id_value) {
            batch.status = BatchStatus::Recursed;
        }
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        self.push_event(
            EventKind::RecursiveReceiptPublished,
            &receipt_id_value,
            &root,
            height,
        );
        self.refresh_roots();
        Ok(receipt_id_value)
    }

    pub fn consume_reservation(
        &mut self,
        reservation_id_value: &str,
        amount_microunits: u64,
        batch_id_value: Option<String>,
        height: u64,
    ) -> Result<()> {
        let reservation = self
            .sponsor_reservations
            .get_mut(reservation_id_value)
            .ok_or_else(|| "reservation not found".to_string())?;
        if height > reservation.expires_at_height {
            reservation.status = ReservationStatus::Expired;
            return Err("reservation expired".to_string());
        }
        require_at_least("amount_microunits", amount_microunits, 1)?;
        if amount_microunits > reservation.remaining_fee_microunits() {
            return Err("reservation has insufficient remaining fee".to_string());
        }
        reservation.consumed_fee_microunits = reservation
            .consumed_fee_microunits
            .saturating_add(amount_microunits);
        reservation.batch_id = batch_id_value;
        reservation.status = if reservation.remaining_fee_microunits() == 0 {
            ReservationStatus::Consumed
        } else {
            ReservationStatus::PartiallyConsumed
        };
        let root = reservation.record_root();
        self.push_event(
            EventKind::ReservationConsumed,
            reservation_id_value,
            &root,
            height,
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn queue_rebate(
        &mut self,
        reservation_id_value: &str,
        recipient_commitment: String,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity("rebates", self.rebates.len(), MAX_REBATES)?;
        let reservation = self
            .sponsor_reservations
            .get(reservation_id_value)
            .ok_or_else(|| "reservation not found".to_string())?;
        let basis = reservation.consumed_fee_microunits.max(1);
        let amount = basis.saturating_mul(reservation.rebate_bps) / MAX_BPS;
        let rebate_id_value = rebate_id(
            reservation_id_value,
            &recipient_commitment,
            amount,
            height,
            self.counters.rebates,
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id_value.clone(),
            reservation_id: reservation_id_value.to_string(),
            proof_id: reservation.proof_id.clone(),
            batch_id: reservation.batch_id.clone(),
            recipient_commitment,
            rebate_microunits: amount.max(1),
            rebate_bps: reservation.rebate_bps,
            status: RebateStatus::Queued,
            queued_at_height: height,
            claimable_at_height: height.saturating_add(1),
            expires_at_height: height.saturating_add(self.config.rebate_ttl_blocks),
            metadata,
        };
        rebate.validate(&self.config)?;
        let root = rebate.record_root();
        self.rebates.insert(rebate_id_value.clone(), rebate);
        if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id_value) {
            reservation.status = ReservationStatus::RebateQueued;
        }
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.push_event(EventKind::RebateQueued, &rebate_id_value, &root, height);
        self.refresh_roots();
        Ok(rebate_id_value)
    }

    pub fn claim_rebate(&mut self, rebate_id_value: &str, height: u64) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id_value)
            .ok_or_else(|| "rebate not found".to_string())?;
        if height < rebate.claimable_at_height {
            return Err("rebate is not claimable yet".to_string());
        }
        if height > rebate.expires_at_height {
            rebate.status = RebateStatus::Expired;
            return Err("rebate expired".to_string());
        }
        rebate.status = RebateStatus::Claimed;
        let root = rebate.record_root();
        self.push_event(EventKind::RebateClaimed, rebate_id_value, &root, height);
        self.refresh_roots();
        Ok(())
    }

    pub fn spend_privacy_fence(&mut self, fence_id_value: &str, height: u64) -> Result<()> {
        let fence = self
            .privacy_fences
            .get_mut(fence_id_value)
            .ok_or_else(|| "privacy fence not found".to_string())?;
        if fence.status != FenceStatus::Open {
            return Err("privacy fence is not open".to_string());
        }
        fence.status = FenceStatus::Spent;
        fence.spent_at_height = Some(height);
        let root = fence.record_root();
        self.push_event(EventKind::PrivacyFenceSpent, fence_id_value, &root, height);
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_slashing_evidence(
        &mut self,
        kind: EvidenceKind,
        subject_id: String,
        subject_root: String,
        reporter_commitment: String,
        accused_commitment: String,
        evidence_root: String,
        penalty_microunits: u64,
        height: u64,
        metadata: Value,
    ) -> Result<String> {
        require_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
        )?;
        let evidence_id_value = evidence_id(
            kind,
            &subject_id,
            &subject_root,
            &evidence_root,
            height,
            self.counters.slashing_evidence,
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id_value.clone(),
            kind,
            subject_id,
            subject_root,
            reporter_commitment,
            accused_commitment,
            evidence_root,
            penalty_microunits,
            status: EvidenceStatus::Submitted,
            submitted_at_height: height,
            resolved_at_height: None,
            metadata,
        };
        evidence.validate()?;
        let root = evidence.record_root();
        self.slashing_evidence
            .insert(evidence_id_value.clone(), evidence);
        self.counters.slashing_evidence = self.counters.slashing_evidence.saturating_add(1);
        self.push_event(
            EventKind::SlashingEvidenceSubmitted,
            &evidence_id_value,
            &root,
            height,
        );
        self.refresh_roots();
        Ok(evidence_id_value)
    }

    pub fn apply_slashing_evidence(&mut self, evidence_id_value: &str, height: u64) -> Result<()> {
        let evidence = self
            .slashing_evidence
            .get_mut(evidence_id_value)
            .ok_or_else(|| "slashing evidence not found".to_string())?;
        evidence.status = EvidenceStatus::Slashed;
        evidence.resolved_at_height = Some(height);
        match evidence.kind {
            EvidenceKind::InvalidPolicyRoot => {
                if let Some(policy) = self.policy_roots.get_mut(&evidence.subject_id) {
                    policy.status = PolicyStatus::Revoked;
                }
            }
            EvidenceKind::InvalidCircuitDescriptor => {
                if let Some(circuit) = self.circuits.get_mut(&evidence.subject_id) {
                    circuit.status = CircuitStatus::Revoked;
                }
            }
            EvidenceKind::InvalidProofDescriptor | EvidenceKind::WitnessMismatch => {
                if let Some(proof) = self.proofs.get_mut(&evidence.subject_id) {
                    proof.status = ProofStatus::Slashed;
                }
            }
            EvidenceKind::BatchEquivocation | EvidenceKind::TimeoutFault => {
                if let Some(batch) = self.fast_batches.get_mut(&evidence.subject_id) {
                    batch.status = BatchStatus::Disputed;
                }
            }
            EvidenceKind::ReceiptEquivocation => {
                if let Some(receipt) = self.recursive_receipts.get_mut(&evidence.subject_id) {
                    receipt.status = ReceiptStatus::Slashed;
                }
            }
            EvidenceKind::PrivacyFenceViolation => {
                if let Some(fence) = self.privacy_fences.get_mut(&evidence.subject_id) {
                    fence.status = FenceStatus::Quarantined;
                }
            }
            EvidenceKind::SponsorUnderfunded => {
                if let Some(reservation) = self.sponsor_reservations.get_mut(&evidence.subject_id) {
                    reservation.status = ReservationStatus::Slashed;
                }
            }
            EvidenceKind::RebateFraud => {
                if let Some(rebate) = self.rebates.get_mut(&evidence.subject_id) {
                    rebate.status = RebateStatus::Slashed;
                }
            }
        }
        let root = evidence.record_root();
        self.push_event(EventKind::SlashingApplied, evidence_id_value, &root, height);
        self.refresh_roots();
        Ok(())
    }

    fn push_event(&mut self, kind: EventKind, subject_id: &str, subject_root: &str, height: u64) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let sequence = self.counters.events;
        let payload_root = event_payload_root(kind, subject_id, subject_root, height, sequence);
        let event_id = event_id(kind, subject_id, subject_root, height, sequence);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height,
            sequence,
            payload_root,
        };
        self.events.insert(event_id, event);
        self.counters.events = self.counters.events.saturating_add(1);
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_record_root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_state_record_root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, value: &str) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_deterministic_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn policy_id(contract_id: &str, policy_root: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_policy_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(policy_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn circuit_id(
    policy_id: &str,
    circuit_kind: CircuitKind,
    proof_system: ProofSystem,
    circuit_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_circuit_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(circuit_kind.as_str()),
            HashPart::Str(proof_system.as_str()),
            HashPart::Str(circuit_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn proof_id(
    circuit_id: &str,
    public_input_root: &str,
    proof_commitment_root: &str,
    nullifier_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_proof_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit_id),
            HashPart::Str(public_input_root),
            HashPart::Str(proof_commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn witness_commitment_id(
    proof_id: &str,
    encrypted_witness_root: &str,
    ciphertext_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_witness_commitment_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_id),
            HashPart::Str(encrypted_witness_root),
            HashPart::Str(ciphertext_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn batch_id(
    lane: BatchLane,
    policy_root: &str,
    verifier_committee_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_batch_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(policy_root),
            HashPart::Str(verifier_committee_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_id(
    batch_id: &str,
    proof_root: &str,
    accumulator_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_receipt_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(proof_root),
            HashPart::Str(accumulator_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn reservation_id(
    sponsor_id: &str,
    subject: &str,
    reserved_fee: u64,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_reservation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(subject),
            HashPart::U64(reserved_fee),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fence_id(
    proof_id: &str,
    nullifier_root: &str,
    anonymity_set_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_fence_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(anonymity_set_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(
    reservation_id: &str,
    recipient_commitment: &str,
    amount: u64,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_rebate_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reservation_id),
            HashPart::Str(recipient_commitment),
            HashPart::U64(amount),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn evidence_id(
    kind: EvidenceKind,
    subject_id: &str,
    subject_root: &str,
    evidence_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_evidence_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn event_id(
    kind: EventKind,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_event_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn event_payload_root(
    kind: EventKind,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_pcd_event_payload_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn map_root<T, F>(domain: &str, records: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = records
        .iter()
        .map(|(id, record)| json!({ "id": id, "record": public_record(record) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn require_id(name: &str, value: &str) -> Result<()> {
    require_non_empty(name, value)?;
    if value.len() > 256 {
        return Err(format!("{name} is too long"));
    }
    Ok(())
}

fn require_root(name: &str, value: &str) -> Result<()> {
    require_non_empty(name, value)?;
    if value.len() < 16 {
        return Err(format!("{name} must be a commitment/root-like value"));
    }
    Ok(())
}

fn require_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} exceeds {MAX_BPS} bps"));
    }
    Ok(())
}

fn require_at_least(name: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        return Err(format!("{name} must be at least {min}"));
    }
    Ok(())
}

fn require_at_least_u16(name: &str, value: u16, min: u16) -> Result<()> {
    if value < min {
        return Err(format!("{name} must be at least {min}"));
    }
    Ok(())
}

fn require_expiry(name: &str, start: u64, expiry: u64, max_ttl: u64) -> Result<()> {
    if expiry <= start {
        return Err(format!("{name} expiry must be after start"));
    }
    if expiry.saturating_sub(start) > max_ttl {
        return Err(format!("{name} ttl exceeds runtime limit"));
    }
    Ok(())
}

fn require_capacity(name: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        return Err(format!("{name} capacity exceeded"));
    }
    Ok(())
}
