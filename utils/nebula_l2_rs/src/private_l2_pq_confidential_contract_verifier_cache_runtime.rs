use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_VERIFIER_CACHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-verifier-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_VERIFIER_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_VERIFIER_CACHE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-contract-verifier-cache-v1";
pub const VERIFIER_KEY_SCHEME: &str = "pq-verifier-key-cache-ml-dsa-slh-dsa-root-v1";
pub const CIRCUIT_MANIFEST_SCHEME: &str = "confidential-contract-circuit-manifest-root-v1";
pub const TRANSCRIPT_COMMITMENT_SCHEME: &str = "roots-only-proof-transcript-commitment-v1";
pub const COMMITTEE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-verifier-committee-attestation-v1";
pub const PROOF_CACHE_TICKET_SCHEME: &str = "low-latency-confidential-proof-cache-ticket-v1";
pub const SPONSOR_RESERVATION_SCHEME: &str = "private-proof-verification-sponsor-reservation-v1";
pub const BATCH_RECEIPT_SCHEME: &str = "recursive-pq-batch-verification-receipt-v1";
pub const REBATE_SCHEME: &str = "low-fee-verifier-cache-rebate-root-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "monero-l2-private-nullifier-fence-root-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_HEIGHT: u64 = 812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 20_160;
pub const DEFAULT_MANIFEST_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_LOOKUP_FEE_BPS: u64 = 16;
pub const DEFAULT_REBATE_BPS: u64 = 10;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 768;
pub const MAX_VERIFIER_KEYS: usize = 1_048_576;
pub const MAX_MANIFESTS: usize = 1_048_576;
pub const MAX_TRANSCRIPTS: usize = 4_194_304;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_TICKETS: usize = 4_194_304;
pub const MAX_RESERVATIONS: usize = 2_097_152;
pub const MAX_BATCH_RECEIPTS: usize = 2_097_152;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_FENCES: usize = 4_194_304;
pub const MAX_EVENTS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCircuitKind {
    CallAuthorization,
    StateTransition,
    StorageRead,
    StorageWrite,
    EventDisclosure,
    CrossContractMessage,
    FeeRebate,
    NullifierFence,
}

impl ContractCircuitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallAuthorization => "call_authorization",
            Self::StateTransition => "state_transition",
            Self::StorageRead => "storage_read",
            Self::StorageWrite => "storage_write",
            Self::EventDisclosure => "event_disclosure",
            Self::CrossContractMessage => "cross_contract_message",
            Self::FeeRebate => "fee_rebate",
            Self::NullifierFence => "nullifier_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyStatus {
    Proposed,
    Active,
    Hot,
    Rotating,
    Deprecated,
    Revoked,
}

impl VerifierKeyStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Hot | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    Active,
    Frozen,
    Superseded,
    Revoked,
}

impl ManifestStatus {
    pub fn accepts_proofs(self) -> bool {
        matches!(self, Self::Active | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatus {
    Submitted,
    KeyMatched,
    Attested,
    Ticketed,
    Batched,
    Settled,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    StrongQuorum,
    Rejected,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Issued,
    Reserved,
    Consumed,
    Batched,
    Settled,
    Expired,
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
pub enum BatchStatus {
    Proposed,
    Verifying,
    QuorumAttested,
    Settled,
    Disputed,
    Cancelled,
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
pub enum FenceStatus {
    Open,
    Spent,
    Tombstoned,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    VerifierKeyCached,
    CircuitManifestPublished,
    TranscriptCommitted,
    CommitteeAttested,
    TicketIssued,
    SponsorReserved,
    BatchReceiptPublished,
    RebateQueued,
    NullifierFenced,
    RuntimeRootPublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifierKeyCached => "verifier_key_cached",
            Self::CircuitManifestPublished => "circuit_manifest_published",
            Self::TranscriptCommitted => "transcript_committed",
            Self::CommitteeAttested => "committee_attested",
            Self::TicketIssued => "ticket_issued",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchReceiptPublished => "batch_receipt_published",
            Self::RebateQueued => "rebate_queued",
            Self::NullifierFenced => "nullifier_fenced",
            Self::RuntimeRootPublished => "runtime_root_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub verifier_key_scheme: String,
    pub circuit_manifest_scheme: String,
    pub transcript_commitment_scheme: String,
    pub committee_attestation_scheme: String,
    pub proof_cache_ticket_scheme: String,
    pub sponsor_reservation_scheme: String,
    pub batch_receipt_scheme: String,
    pub rebate_scheme: String,
    pub nullifier_fence_scheme: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub committee_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_lookup_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub cache_ttl_blocks: u64,
    pub manifest_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_batch_items: usize,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_VERIFIER_CACHE_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            verifier_key_scheme: VERIFIER_KEY_SCHEME.to_string(),
            circuit_manifest_scheme: CIRCUIT_MANIFEST_SCHEME.to_string(),
            transcript_commitment_scheme: TRANSCRIPT_COMMITMENT_SCHEME.to_string(),
            committee_attestation_scheme: COMMITTEE_ATTESTATION_SCHEME.to_string(),
            proof_cache_ticket_scheme: PROOF_CACHE_TICKET_SCHEME.to_string(),
            sponsor_reservation_scheme: SPONSOR_RESERVATION_SCHEME.to_string(),
            batch_receipt_scheme: BATCH_RECEIPT_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            nullifier_fence_scheme: NULLIFIER_FENCE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_lookup_fee_bps: DEFAULT_MAX_LOOKUP_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            manifest_ttl_blocks: DEFAULT_MANIFEST_TTL_BLOCKS,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            devnet_height: DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_bps("committee_quorum_bps", self.committee_quorum_bps)?;
        require_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        require_bps("max_lookup_fee_bps", self.max_lookup_fee_bps)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.strong_quorum_bps < self.committee_quorum_bps {
            return Err("strong_quorum_bps cannot be below committee_quorum_bps".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        if self.target_pq_security_bits < self.min_pq_security_bits {
            return Err("target_pq_security_bits cannot be below min_pq_security_bits".to_string());
        }
        require_positive_u64("cache_ttl_blocks", self.cache_ttl_blocks)?;
        require_positive_u64("manifest_ttl_blocks", self.manifest_ttl_blocks)?;
        require_positive_u64("ticket_ttl_blocks", self.ticket_ttl_blocks)?;
        require_positive_u64("reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        require_positive_u64("batch_window_blocks", self.batch_window_blocks)?;
        require_positive_u64("rebate_ttl_blocks", self.rebate_ttl_blocks)?;
        require_positive_usize("max_batch_items", self.max_batch_items)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub verifier_key_counter: u64,
    pub circuit_manifest_counter: u64,
    pub transcript_counter: u64,
    pub attestation_counter: u64,
    pub ticket_counter: u64,
    pub reservation_counter: u64,
    pub batch_receipt_counter: u64,
    pub rebate_counter: u64,
    pub fence_counter: u64,
    pub event_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierKeyCacheEntry {
    pub verifier_key_id: String,
    pub contract_id: String,
    pub circuit_kind: ContractCircuitKind,
    pub key_commitment_root: String,
    pub verifying_program_root: String,
    pub pq_key_package_root: String,
    pub committee_policy_root: String,
    pub min_pq_security_bits: u16,
    pub status: VerifierKeyStatus,
    pub cached_at_height: u64,
    pub expires_at_height: u64,
    pub rotation_nonce: String,
}

impl VerifierKeyCacheEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("verifier_key_id", &self.verifier_key_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_root("key_commitment_root", &self.key_commitment_root)?;
        require_root("verifying_program_root", &self.verifying_program_root)?;
        require_root("pq_key_package_root", &self.pq_key_package_root)?;
        require_root("committee_policy_root", &self.committee_policy_root)?;
        require_non_empty("rotation_nonce", &self.rotation_nonce)?;
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err("verifier key pq security below runtime minimum".to_string());
        }
        if self.expires_at_height <= self.cached_at_height {
            return Err(
                "verifier key expires_at_height must be after cached_at_height".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub circuit_kind: ContractCircuitKind,
    pub verifier_key_id: String,
    pub abi_commitment_root: String,
    pub public_input_schema_root: String,
    pub private_witness_schema_root: String,
    pub constraint_system_root: String,
    pub recursion_policy_root: String,
    pub allowed_nullifier_domain_root: String,
    pub status: ManifestStatus,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl CircuitManifest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("verifier_key_id", &self.verifier_key_id)?;
        require_root("abi_commitment_root", &self.abi_commitment_root)?;
        require_root("public_input_schema_root", &self.public_input_schema_root)?;
        require_root(
            "private_witness_schema_root",
            &self.private_witness_schema_root,
        )?;
        require_root("constraint_system_root", &self.constraint_system_root)?;
        require_root("recursion_policy_root", &self.recursion_policy_root)?;
        require_root(
            "allowed_nullifier_domain_root",
            &self.allowed_nullifier_domain_root,
        )?;
        if self.expires_at_height <= self.published_at_height {
            return Err("manifest expires_at_height must be after published_at_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofTranscriptCommitment {
    pub transcript_id: String,
    pub manifest_id: String,
    pub verifier_key_id: String,
    pub prover_commitment: String,
    pub public_input_root: String,
    pub transcript_root: String,
    pub proof_commitment_root: String,
    pub nullifier_root: String,
    pub output_commitment_root: String,
    pub privacy_set_size: u64,
    pub lookup_fee_bps: u64,
    pub status: TranscriptStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl ProofTranscriptCommitment {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("transcript_id", &self.transcript_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("verifier_key_id", &self.verifier_key_id)?;
        require_non_empty("prover_commitment", &self.prover_commitment)?;
        require_root("public_input_root", &self.public_input_root)?;
        require_root("transcript_root", &self.transcript_root)?;
        require_root("proof_commitment_root", &self.proof_commitment_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("output_commitment_root", &self.output_commitment_root)?;
        require_bps("lookup_fee_bps", self.lookup_fee_bps)?;
        if self.lookup_fee_bps > config.max_lookup_fee_bps {
            return Err("lookup_fee_bps exceeds runtime maximum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy_set_size below runtime minimum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err(
                "transcript expires_at_height must be after submitted_at_height".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierCommitteeAttestation {
    pub attestation_id: String,
    pub transcript_id: String,
    pub committee_id: String,
    pub committee_member_root: String,
    pub attested_transcript_root: String,
    pub aggregate_signature_root: String,
    pub signer_weight: u64,
    pub quorum_bps: u64,
    pub status: AttestationStatus,
    pub attested_at_height: u64,
}

impl VerifierCommitteeAttestation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_non_empty("transcript_id", &self.transcript_id)?;
        require_non_empty("committee_id", &self.committee_id)?;
        require_root("committee_member_root", &self.committee_member_root)?;
        require_root("attested_transcript_root", &self.attested_transcript_root)?;
        require_root("aggregate_signature_root", &self.aggregate_signature_root)?;
        require_bps("quorum_bps", self.quorum_bps)?;
        require_positive_u64("signer_weight", self.signer_weight)?;
        if self.quorum_bps < config.committee_quorum_bps {
            return Err("attestation quorum below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheTicket {
    pub ticket_id: String,
    pub transcript_id: String,
    pub verifier_key_id: String,
    pub manifest_id: String,
    pub attestation_id: String,
    pub ticket_commitment_root: String,
    pub reusable_lookup_limit: u64,
    pub lookups_consumed: u64,
    pub fee_bps: u64,
    pub status: TicketStatus,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl ProofCacheTicket {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("transcript_id", &self.transcript_id)?;
        require_non_empty("verifier_key_id", &self.verifier_key_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_root("ticket_commitment_root", &self.ticket_commitment_root)?;
        require_positive_u64("reusable_lookup_limit", self.reusable_lookup_limit)?;
        require_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_lookup_fee_bps {
            return Err("ticket fee_bps exceeds runtime maximum".to_string());
        }
        if self.lookups_consumed > self.reusable_lookup_limit {
            return Err("lookups_consumed cannot exceed reusable_lookup_limit".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("ticket expires_at_height must be after issued_at_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_id: String,
    pub ticket_id: String,
    pub beneficiary_commitment: String,
    pub reserved_fee_units: u64,
    pub consumed_fee_units: u64,
    pub sponsor_cover_bps: u64,
    pub status: ReservationStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("reservation_id", &self.reservation_id)?;
        require_non_empty("sponsor_id", &self.sponsor_id)?;
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_positive_u64("reserved_fee_units", self.reserved_fee_units)?;
        require_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        if self.sponsor_cover_bps < config.sponsor_cover_bps {
            return Err("sponsor_cover_bps below runtime minimum".to_string());
        }
        if self.consumed_fee_units > self.reserved_fee_units {
            return Err("consumed_fee_units cannot exceed reserved_fee_units".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err(
                "reservation expires_at_height must be after reserved_at_height".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchVerificationReceipt {
    pub batch_receipt_id: String,
    pub batch_id: String,
    pub ticket_root: String,
    pub transcript_root: String,
    pub attestation_root: String,
    pub recursive_proof_root: String,
    pub settlement_state_root: String,
    pub item_count: usize,
    pub privacy_set_size: u64,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl BatchVerificationReceipt {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_receipt_id", &self.batch_receipt_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("ticket_root", &self.ticket_root)?;
        require_root("transcript_root", &self.transcript_root)?;
        require_root("attestation_root", &self.attestation_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_root("settlement_state_root", &self.settlement_state_root)?;
        require_positive_usize("item_count", self.item_count)?;
        if self.item_count > config.max_batch_items {
            return Err("batch item_count exceeds runtime maximum".to_string());
        }
        if self.privacy_set_size < config.batch_privacy_set_size {
            return Err("batch privacy_set_size below runtime minimum".to_string());
        }
        if let Some(settled_at_height) = self.settled_at_height {
            if settled_at_height < self.opened_at_height {
                return Err("settled_at_height cannot be before opened_at_height".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationRebate {
    pub rebate_id: String,
    pub reservation_id: String,
    pub ticket_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
}

impl VerificationRebate {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("rebate_id", &self.rebate_id)?;
        require_non_empty("reservation_id", &self.reservation_id)?;
        require_non_empty("ticket_id", &self.ticket_id)?;
        require_non_empty("sponsor_id", &self.sponsor_id)?;
        require_non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_positive_u64("rebate_units", self.rebate_units)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps < config.rebate_bps {
            return Err("rebate_bps below runtime target".to_string());
        }
        if self.expires_at_height <= self.queued_at_height {
            return Err("rebate expires_at_height must be after queued_at_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub nullifier_root: String,
    pub contract_id: String,
    pub manifest_id: String,
    pub transcript_id: String,
    pub spend_domain_root: String,
    pub privacy_epoch: u64,
    pub status: FenceStatus,
    pub opened_at_height: u64,
}

impl PrivacyNullifierFence {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("fence_id", &self.fence_id)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("transcript_id", &self.transcript_id)?;
        require_root("spend_domain_root", &self.spend_domain_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: EventKind,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root_after: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("event_id", &self.event_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("payload_root", &self.payload_root)?;
        require_root("state_root_after", &self.state_root_after)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub verifier_key_root: String,
    pub circuit_manifest_root: String,
    pub transcript_commitment_root: String,
    pub committee_attestation_root: String,
    pub proof_cache_ticket_root: String,
    pub sponsor_reservation_root: String,
    pub batch_receipt_root: String,
    pub rebate_root: String,
    pub nullifier_fence_root: String,
    pub spent_nullifier_root: String,
    pub active_contract_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            verifier_key_root: merkle_root("PQ-CONTRACT-VERIFIER-KEYS", &[]),
            circuit_manifest_root: merkle_root("PQ-CONTRACT-CIRCUIT-MANIFESTS", &[]),
            transcript_commitment_root: merkle_root("PQ-CONTRACT-PROOF-TRANSCRIPTS", &[]),
            committee_attestation_root: merkle_root("PQ-CONTRACT-COMMITTEE-ATTESTATIONS", &[]),
            proof_cache_ticket_root: merkle_root("PQ-CONTRACT-PROOF-CACHE-TICKETS", &[]),
            sponsor_reservation_root: merkle_root("PQ-CONTRACT-SPONSOR-RESERVATIONS", &[]),
            batch_receipt_root: merkle_root("PQ-CONTRACT-BATCH-RECEIPTS", &[]),
            rebate_root: merkle_root("PQ-CONTRACT-REBATES", &[]),
            nullifier_fence_root: merkle_root("PQ-CONTRACT-NULLIFIER-FENCES", &[]),
            spent_nullifier_root: merkle_root("PQ-CONTRACT-SPENT-NULLIFIERS", &[]),
            active_contract_root: merkle_root("PQ-CONTRACT-ACTIVE-CONTRACTS", &[]),
            event_root: merkle_root("PQ-CONTRACT-RUNTIME-EVENTS", &[]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub verifier_keys: BTreeMap<String, VerifierKeyCacheEntry>,
    pub circuit_manifests: BTreeMap<String, CircuitManifest>,
    pub proof_transcripts: BTreeMap<String, ProofTranscriptCommitment>,
    pub committee_attestations: BTreeMap<String, VerifierCommitteeAttestation>,
    pub proof_cache_tickets: BTreeMap<String, ProofCacheTicket>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub batch_receipts: BTreeMap<String, BatchVerificationReceipt>,
    pub rebates: BTreeMap<String, VerificationRebate>,
    pub privacy_nullifier_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub spent_nullifier_roots: BTreeSet<String>,
    pub active_contract_ids: BTreeSet<String>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

pub type Runtime = State;

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            verifier_keys: BTreeMap::new(),
            circuit_manifests: BTreeMap::new(),
            proof_transcripts: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            proof_cache_tickets: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            batch_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_nullifier_fences: BTreeMap::new(),
            spent_nullifier_roots: BTreeSet::new(),
            active_contract_ids: BTreeSet::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet verifier cache config");
        let height = state.config.devnet_height;
        let contract_id = deterministic_contract_id("devnet-confidential-swap", "wxmr-usdc");
        let committee_root = payload_root(
            "DEVNET-COMMITTEE",
            &json!(["vk-fast-0", "vk-fast-1", "vk-fast-2"]),
        );
        let key_id = verifier_key_id(
            &contract_id,
            ContractCircuitKind::StateTransition,
            "devnet-state-transition-v1",
            height,
            0,
        );
        let manifest_id =
            circuit_manifest_id(&contract_id, &key_id, "devnet-manifest-v1", height, 0);
        let transcript_id =
            transcript_commitment_id(&manifest_id, &key_id, "devnet-prover-commitment", height, 0);
        let attestation_id = committee_attestation_id(
            &transcript_id,
            "devnet-verifier-committee",
            &committee_root,
            height + 1,
            0,
        );
        let ticket_id = proof_cache_ticket_id(&transcript_id, &attestation_id, height + 1, 0);
        let reservation_id = sponsor_reservation_id("devnet-sponsor", &ticket_id, height + 2, 0);
        let batch_receipt_id = batch_receipt_id("devnet-batch", &ticket_id, height + 3, 0);
        let rebate_id = rebate_id(&reservation_id, &ticket_id, "devnet-sponsor", height + 4, 0);
        let nullifier_root = payload_root(
            "DEVNET-NULLIFIER",
            &json!({"contract_id": contract_id, "slot": 0}),
        );
        let fence_id = nullifier_fence_id(&contract_id, &manifest_id, &nullifier_root, 0);

        state
            .cache_verifier_key(VerifierKeyCacheEntry {
                verifier_key_id: key_id.clone(),
                contract_id: contract_id.clone(),
                circuit_kind: ContractCircuitKind::StateTransition,
                key_commitment_root: payload_root(
                    "DEVNET-KEY-COMMITMENT",
                    &json!({"key": "state-v1"}),
                ),
                verifying_program_root: payload_root(
                    "DEVNET-PROGRAM",
                    &json!({"wasm": "confidential-swap"}),
                ),
                pq_key_package_root: payload_root(
                    "DEVNET-PQ-KEY-PACKAGE",
                    &json!({"suite": PQ_AUTH_SUITE}),
                ),
                committee_policy_root: committee_root.clone(),
                min_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
                status: VerifierKeyStatus::Hot,
                cached_at_height: height,
                expires_at_height: height + DEFAULT_CACHE_TTL_BLOCKS,
                rotation_nonce: "devnet-vk-rotation-0".to_string(),
            })
            .expect("devnet verifier key");
        state
            .publish_circuit_manifest(CircuitManifest {
                manifest_id: manifest_id.clone(),
                contract_id: contract_id.clone(),
                circuit_kind: ContractCircuitKind::StateTransition,
                verifier_key_id: key_id.clone(),
                abi_commitment_root: payload_root("DEVNET-ABI", &json!({"method": "private_swap"})),
                public_input_schema_root: payload_root(
                    "DEVNET-PUBLIC-SCHEMA",
                    &json!(["asset_pair_root", "fee_root"]),
                ),
                private_witness_schema_root: payload_root(
                    "DEVNET-WITNESS-SCHEMA",
                    &json!(["note", "path", "blinding"]),
                ),
                constraint_system_root: payload_root(
                    "DEVNET-CONSTRAINTS",
                    &json!({"rows": 1_572_864_u64}),
                ),
                recursion_policy_root: payload_root("DEVNET-RECURSION", &json!({"depth": 2})),
                allowed_nullifier_domain_root: payload_root(
                    "DEVNET-NULLIFIER-DOMAINS",
                    &json!(["swap", "refund"]),
                ),
                status: ManifestStatus::Active,
                published_at_height: height,
                expires_at_height: height + DEFAULT_MANIFEST_TTL_BLOCKS,
            })
            .expect("devnet manifest");
        state
            .commit_proof_transcript(ProofTranscriptCommitment {
                transcript_id: transcript_id.clone(),
                manifest_id: manifest_id.clone(),
                verifier_key_id: key_id.clone(),
                prover_commitment: "devnet-prover-commitment".to_string(),
                public_input_root: payload_root(
                    "DEVNET-PUBLIC-INPUT",
                    &json!({"pair": "wxmr-usdc"}),
                ),
                transcript_root: payload_root("DEVNET-TRANSCRIPT", &json!({"rounds": 7})),
                proof_commitment_root: payload_root("DEVNET-PROOF", &json!({"proof": "sealed"})),
                nullifier_root: nullifier_root.clone(),
                output_commitment_root: payload_root("DEVNET-OUTPUT", &json!({"output": "note"})),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                lookup_fee_bps: DEFAULT_REBATE_BPS,
                status: TranscriptStatus::Attested,
                submitted_at_height: height + 1,
                expires_at_height: height + DEFAULT_TICKET_TTL_BLOCKS,
            })
            .expect("devnet transcript");
        state
            .record_committee_attestation(VerifierCommitteeAttestation {
                attestation_id: attestation_id.clone(),
                transcript_id: transcript_id.clone(),
                committee_id: "devnet-verifier-committee".to_string(),
                committee_member_root: committee_root.clone(),
                attested_transcript_root: payload_root(
                    "DEVNET-ATTESTED-TRANSCRIPT",
                    &json!({"transcript_id": transcript_id}),
                ),
                aggregate_signature_root: payload_root(
                    "DEVNET-AGG-SIG",
                    &json!({"sig": "pq-aggregate"}),
                ),
                signer_weight: 4,
                quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
                status: AttestationStatus::StrongQuorum,
                attested_at_height: height + 1,
            })
            .expect("devnet attestation");
        state
            .issue_proof_cache_ticket(ProofCacheTicket {
                ticket_id: ticket_id.clone(),
                transcript_id: transcript_id.clone(),
                verifier_key_id: key_id,
                manifest_id: manifest_id.clone(),
                attestation_id,
                ticket_commitment_root: payload_root(
                    "DEVNET-TICKET",
                    &json!({"ticket": "fast-hit"}),
                ),
                reusable_lookup_limit: 64,
                lookups_consumed: 1,
                fee_bps: DEFAULT_REBATE_BPS,
                status: TicketStatus::Reserved,
                issued_at_height: height + 1,
                expires_at_height: height + DEFAULT_TICKET_TTL_BLOCKS,
            })
            .expect("devnet ticket");
        state
            .reserve_sponsor(SponsorReservation {
                reservation_id: reservation_id.clone(),
                sponsor_id: "devnet-sponsor".to_string(),
                ticket_id: ticket_id.clone(),
                beneficiary_commitment: "devnet-beneficiary-commitment".to_string(),
                reserved_fee_units: 10_000,
                consumed_fee_units: 2_500,
                sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
                status: ReservationStatus::RebateQueued,
                reserved_at_height: height + 2,
                expires_at_height: height + DEFAULT_RESERVATION_TTL_BLOCKS,
            })
            .expect("devnet reservation");
        state
            .publish_batch_receipt(BatchVerificationReceipt {
                batch_receipt_id: batch_receipt_id.clone(),
                batch_id: "devnet-batch".to_string(),
                ticket_root: merkle_root(
                    "DEVNET-BATCH-TICKETS",
                    &[Value::String(ticket_id.clone())],
                ),
                transcript_root: merkle_root(
                    "DEVNET-BATCH-TRANSCRIPTS",
                    &[Value::String(transcript_id.clone())],
                ),
                attestation_root: merkle_root(
                    "DEVNET-BATCH-ATTESTATIONS",
                    &[Value::String(batch_receipt_id.clone())],
                ),
                recursive_proof_root: payload_root(
                    "DEVNET-RECURSIVE-PROOF",
                    &json!({"proof": "batch"}),
                ),
                settlement_state_root: payload_root(
                    "DEVNET-SETTLEMENT",
                    &json!({"height": height + 3}),
                ),
                item_count: 1,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                status: BatchStatus::Settled,
                opened_at_height: height + 3,
                settled_at_height: Some(height + 4),
            })
            .expect("devnet batch");
        state
            .queue_rebate(VerificationRebate {
                rebate_id,
                reservation_id,
                ticket_id,
                sponsor_id: "devnet-sponsor".to_string(),
                beneficiary_commitment: "devnet-beneficiary-commitment".to_string(),
                rebate_units: 1_000,
                rebate_bps: DEFAULT_REBATE_BPS,
                status: RebateStatus::Claimable,
                queued_at_height: height + 4,
                expires_at_height: height + DEFAULT_REBATE_TTL_BLOCKS,
            })
            .expect("devnet rebate");
        state
            .open_nullifier_fence(PrivacyNullifierFence {
                fence_id,
                nullifier_root,
                contract_id,
                manifest_id,
                transcript_id,
                spend_domain_root: payload_root("DEVNET-SPEND-DOMAIN", &json!({"domain": "swap"})),
                privacy_epoch: 0,
                status: FenceStatus::Open,
                opened_at_height: height + 1,
            })
            .expect("devnet fence");
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            verifier_key_counter: self.verifier_keys.len() as u64,
            circuit_manifest_counter: self.circuit_manifests.len() as u64,
            transcript_counter: self.proof_transcripts.len() as u64,
            attestation_counter: self.committee_attestations.len() as u64,
            ticket_counter: self.proof_cache_tickets.len() as u64,
            reservation_counter: self.sponsor_reservations.len() as u64,
            batch_receipt_counter: self.batch_receipts.len() as u64,
            rebate_counter: self.rebates.len() as u64,
            fence_counter: self.privacy_nullifier_fences.len() as u64,
            event_counter: self.events.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            verifier_key_root: map_root("PQ-CONTRACT-VERIFIER-KEYS", &self.verifier_keys),
            circuit_manifest_root: map_root(
                "PQ-CONTRACT-CIRCUIT-MANIFESTS",
                &self.circuit_manifests,
            ),
            transcript_commitment_root: map_root(
                "PQ-CONTRACT-PROOF-TRANSCRIPTS",
                &self.proof_transcripts,
            ),
            committee_attestation_root: map_root(
                "PQ-CONTRACT-COMMITTEE-ATTESTATIONS",
                &self.committee_attestations,
            ),
            proof_cache_ticket_root: map_root(
                "PQ-CONTRACT-PROOF-CACHE-TICKETS",
                &self.proof_cache_tickets,
            ),
            sponsor_reservation_root: map_root(
                "PQ-CONTRACT-SPONSOR-RESERVATIONS",
                &self.sponsor_reservations,
            ),
            batch_receipt_root: map_root("PQ-CONTRACT-BATCH-RECEIPTS", &self.batch_receipts),
            rebate_root: map_root("PQ-CONTRACT-REBATES", &self.rebates),
            nullifier_fence_root: map_root(
                "PQ-CONTRACT-NULLIFIER-FENCES",
                &self.privacy_nullifier_fences,
            ),
            spent_nullifier_root: set_root(
                "PQ-CONTRACT-SPENT-NULLIFIERS",
                &self.spent_nullifier_roots,
            ),
            active_contract_root: set_root(
                "PQ-CONTRACT-ACTIVE-CONTRACTS",
                &self.active_contract_ids,
            ),
            event_root: map_root("PQ-CONTRACT-RUNTIME-EVENTS", &self.events),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        }))
    }

    pub fn cache_verifier_key(&mut self, entry: VerifierKeyCacheEntry) -> Result<String> {
        entry.validate(&self.config)?;
        ensure_capacity("verifier_keys", self.verifier_keys.len(), MAX_VERIFIER_KEYS)?;
        if self.verifier_keys.contains_key(&entry.verifier_key_id) {
            return Err("verifier key already cached".to_string());
        }
        self.active_contract_ids.insert(entry.contract_id.clone());
        let id = entry.verifier_key_id.clone();
        let payload = entry.public_record();
        self.verifier_keys.insert(id.clone(), entry);
        self.emit_event(EventKind::VerifierKeyCached, &id, &payload)?;
        Ok(id)
    }

    pub fn publish_circuit_manifest(&mut self, manifest: CircuitManifest) -> Result<String> {
        manifest.validate()?;
        ensure_capacity(
            "circuit_manifests",
            self.circuit_manifests.len(),
            MAX_MANIFESTS,
        )?;
        let key = self
            .verifier_keys
            .get(&manifest.verifier_key_id)
            .ok_or_else(|| "manifest verifier key is missing".to_string())?;
        if key.contract_id != manifest.contract_id || key.circuit_kind != manifest.circuit_kind {
            return Err(
                "manifest does not match verifier key contract or circuit kind".to_string(),
            );
        }
        if !key.status.usable() {
            return Err("manifest verifier key is not usable".to_string());
        }
        if self.circuit_manifests.contains_key(&manifest.manifest_id) {
            return Err("circuit manifest already exists".to_string());
        }
        self.active_contract_ids
            .insert(manifest.contract_id.clone());
        let id = manifest.manifest_id.clone();
        let payload = manifest.public_record();
        self.circuit_manifests.insert(id.clone(), manifest);
        self.emit_event(EventKind::CircuitManifestPublished, &id, &payload)?;
        Ok(id)
    }

    pub fn commit_proof_transcript(
        &mut self,
        transcript: ProofTranscriptCommitment,
    ) -> Result<String> {
        transcript.validate(&self.config)?;
        ensure_capacity(
            "proof_transcripts",
            self.proof_transcripts.len(),
            MAX_TRANSCRIPTS,
        )?;
        if self
            .spent_nullifier_roots
            .contains(&transcript.nullifier_root)
        {
            return Err("transcript nullifier root has already been spent".to_string());
        }
        let manifest = self
            .circuit_manifests
            .get(&transcript.manifest_id)
            .ok_or_else(|| "transcript manifest is missing".to_string())?;
        if !manifest.status.accepts_proofs() {
            return Err("transcript manifest does not accept proofs".to_string());
        }
        if transcript.verifier_key_id != manifest.verifier_key_id {
            return Err("transcript verifier key does not match manifest".to_string());
        }
        if self
            .proof_transcripts
            .contains_key(&transcript.transcript_id)
        {
            return Err("proof transcript already exists".to_string());
        }
        let id = transcript.transcript_id.clone();
        let payload = transcript.public_record();
        self.proof_transcripts.insert(id.clone(), transcript);
        self.emit_event(EventKind::TranscriptCommitted, &id, &payload)?;
        Ok(id)
    }

    pub fn record_committee_attestation(
        &mut self,
        attestation: VerifierCommitteeAttestation,
    ) -> Result<String> {
        attestation.validate(&self.config)?;
        ensure_capacity(
            "committee_attestations",
            self.committee_attestations.len(),
            MAX_ATTESTATIONS,
        )?;
        if !self
            .proof_transcripts
            .contains_key(&attestation.transcript_id)
        {
            return Err("attestation transcript is missing".to_string());
        }
        if self
            .committee_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err("committee attestation already exists".to_string());
        }
        let id = attestation.attestation_id.clone();
        let payload = attestation.public_record();
        self.committee_attestations.insert(id.clone(), attestation);
        self.emit_event(EventKind::CommitteeAttested, &id, &payload)?;
        Ok(id)
    }

    pub fn issue_proof_cache_ticket(&mut self, ticket: ProofCacheTicket) -> Result<String> {
        ticket.validate(&self.config)?;
        ensure_capacity(
            "proof_cache_tickets",
            self.proof_cache_tickets.len(),
            MAX_TICKETS,
        )?;
        let transcript = self
            .proof_transcripts
            .get(&ticket.transcript_id)
            .ok_or_else(|| "ticket transcript is missing".to_string())?;
        if transcript.manifest_id != ticket.manifest_id
            || transcript.verifier_key_id != ticket.verifier_key_id
        {
            return Err("ticket does not match transcript manifest or verifier key".to_string());
        }
        let attestation = self
            .committee_attestations
            .get(&ticket.attestation_id)
            .ok_or_else(|| "ticket attestation is missing".to_string())?;
        if attestation.transcript_id != ticket.transcript_id {
            return Err("ticket attestation does not match transcript".to_string());
        }
        if !matches!(
            attestation.status,
            AttestationStatus::WeakQuorum
                | AttestationStatus::StrongQuorum
                | AttestationStatus::Accepted
        ) {
            return Err("ticket attestation has not reached an acceptable status".to_string());
        }
        if self.proof_cache_tickets.contains_key(&ticket.ticket_id) {
            return Err("proof cache ticket already exists".to_string());
        }
        let id = ticket.ticket_id.clone();
        let payload = ticket.public_record();
        self.proof_cache_tickets.insert(id.clone(), ticket);
        self.emit_event(EventKind::TicketIssued, &id, &payload)?;
        Ok(id)
    }

    pub fn reserve_sponsor(&mut self, reservation: SponsorReservation) -> Result<String> {
        reservation.validate(&self.config)?;
        ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            MAX_RESERVATIONS,
        )?;
        if !self
            .proof_cache_tickets
            .contains_key(&reservation.ticket_id)
        {
            return Err("reservation ticket is missing".to_string());
        }
        if self
            .sponsor_reservations
            .contains_key(&reservation.reservation_id)
        {
            return Err("sponsor reservation already exists".to_string());
        }
        let id = reservation.reservation_id.clone();
        let payload = reservation.public_record();
        self.sponsor_reservations.insert(id.clone(), reservation);
        self.emit_event(EventKind::SponsorReserved, &id, &payload)?;
        Ok(id)
    }

    pub fn publish_batch_receipt(&mut self, receipt: BatchVerificationReceipt) -> Result<String> {
        receipt.validate(&self.config)?;
        ensure_capacity(
            "batch_receipts",
            self.batch_receipts.len(),
            MAX_BATCH_RECEIPTS,
        )?;
        if self.batch_receipts.contains_key(&receipt.batch_receipt_id) {
            return Err("batch receipt already exists".to_string());
        }
        let id = receipt.batch_receipt_id.clone();
        let payload = receipt.public_record();
        self.batch_receipts.insert(id.clone(), receipt);
        self.emit_event(EventKind::BatchReceiptPublished, &id, &payload)?;
        Ok(id)
    }

    pub fn queue_rebate(&mut self, rebate: VerificationRebate) -> Result<String> {
        rebate.validate(&self.config)?;
        ensure_capacity("rebates", self.rebates.len(), MAX_REBATES)?;
        if !self
            .sponsor_reservations
            .contains_key(&rebate.reservation_id)
        {
            return Err("rebate reservation is missing".to_string());
        }
        if !self.proof_cache_tickets.contains_key(&rebate.ticket_id) {
            return Err("rebate ticket is missing".to_string());
        }
        if self.rebates.contains_key(&rebate.rebate_id) {
            return Err("rebate already exists".to_string());
        }
        let id = rebate.rebate_id.clone();
        let payload = rebate.public_record();
        self.rebates.insert(id.clone(), rebate);
        self.emit_event(EventKind::RebateQueued, &id, &payload)?;
        Ok(id)
    }

    pub fn open_nullifier_fence(&mut self, fence: PrivacyNullifierFence) -> Result<String> {
        fence.validate()?;
        ensure_capacity(
            "privacy_nullifier_fences",
            self.privacy_nullifier_fences.len(),
            MAX_FENCES,
        )?;
        if self.spent_nullifier_roots.contains(&fence.nullifier_root) {
            return Err("fence nullifier root has already been spent".to_string());
        }
        if self.privacy_nullifier_fences.contains_key(&fence.fence_id) {
            return Err("privacy nullifier fence already exists".to_string());
        }
        let id = fence.fence_id.clone();
        let payload = fence.public_record();
        self.privacy_nullifier_fences.insert(id.clone(), fence);
        self.emit_event(EventKind::NullifierFenced, &id, &payload)?;
        Ok(id)
    }

    pub fn mark_nullifier_spent(&mut self, nullifier_root: String) -> Result<()> {
        require_root("nullifier_root", &nullifier_root)?;
        self.spent_nullifier_roots.insert(nullifier_root);
        Ok(())
    }

    pub fn verifier_key_available(&self, verifier_key_id: &str, height: u64) -> bool {
        self.verifier_keys
            .get(verifier_key_id)
            .map(|entry| entry.status.usable() && entry.expires_at_height > height)
            .unwrap_or(false)
    }

    pub fn manifest_available(&self, manifest_id: &str, height: u64) -> bool {
        self.circuit_manifests
            .get(manifest_id)
            .map(|manifest| manifest.status.accepts_proofs() && manifest.expires_at_height > height)
            .unwrap_or(false)
    }

    pub fn ticket_remaining_lookups(&self, ticket_id: &str) -> Option<u64> {
        self.proof_cache_tickets.get(ticket_id).map(|ticket| {
            ticket
                .reusable_lookup_limit
                .saturating_sub(ticket.lookups_consumed)
        })
    }

    pub fn transcripts_by_manifest(&self, manifest_id: &str) -> Vec<&ProofTranscriptCommitment> {
        self.proof_transcripts
            .values()
            .filter(|transcript| transcript.manifest_id == manifest_id)
            .collect()
    }

    pub fn attestations_by_transcript(
        &self,
        transcript_id: &str,
    ) -> Vec<&VerifierCommitteeAttestation> {
        self.committee_attestations
            .values()
            .filter(|attestation| attestation.transcript_id == transcript_id)
            .collect()
    }

    pub fn tickets_by_manifest(&self, manifest_id: &str) -> Vec<&ProofCacheTicket> {
        self.proof_cache_tickets
            .values()
            .filter(|ticket| ticket.manifest_id == manifest_id)
            .collect()
    }

    pub fn reservations_by_ticket(&self, ticket_id: &str) -> Vec<&SponsorReservation> {
        self.sponsor_reservations
            .values()
            .filter(|reservation| reservation.ticket_id == ticket_id)
            .collect()
    }

    pub fn rebates_by_ticket(&self, ticket_id: &str) -> Vec<&VerificationRebate> {
        self.rebates
            .values()
            .filter(|rebate| rebate.ticket_id == ticket_id)
            .collect()
    }

    pub fn fences_by_contract(&self, contract_id: &str) -> Vec<&PrivacyNullifierFence> {
        self.privacy_nullifier_fences
            .values()
            .filter(|fence| fence.contract_id == contract_id)
            .collect()
    }

    pub fn public_record_for_subject(&self, subject_id: &str) -> Option<Value> {
        self.verifier_keys
            .get(subject_id)
            .map(VerifierKeyCacheEntry::public_record)
            .or_else(|| {
                self.circuit_manifests
                    .get(subject_id)
                    .map(CircuitManifest::public_record)
            })
            .or_else(|| {
                self.proof_transcripts
                    .get(subject_id)
                    .map(ProofTranscriptCommitment::public_record)
            })
            .or_else(|| {
                self.committee_attestations
                    .get(subject_id)
                    .map(VerifierCommitteeAttestation::public_record)
            })
            .or_else(|| {
                self.proof_cache_tickets
                    .get(subject_id)
                    .map(ProofCacheTicket::public_record)
            })
            .or_else(|| {
                self.sponsor_reservations
                    .get(subject_id)
                    .map(SponsorReservation::public_record)
            })
            .or_else(|| {
                self.batch_receipts
                    .get(subject_id)
                    .map(BatchVerificationReceipt::public_record)
            })
            .or_else(|| {
                self.rebates
                    .get(subject_id)
                    .map(VerificationRebate::public_record)
            })
            .or_else(|| {
                self.privacy_nullifier_fences
                    .get(subject_id)
                    .map(PrivacyNullifierFence::public_record)
            })
            .or_else(|| self.events.get(subject_id).map(RuntimeEvent::public_record))
    }

    pub fn compact_public_snapshot(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
        })
    }

    fn emit_event(
        &mut self,
        event_kind: EventKind,
        subject_id: &str,
        payload: &Value,
    ) -> Result<()> {
        ensure_capacity("events", self.events.len(), MAX_EVENTS)?;
        let sequence = self.events.len() as u64;
        let payload_root = payload_root(event_kind.as_str(), payload);
        let state_root_after = self.state_root();
        let event_id = event_id(
            event_kind,
            subject_id,
            &payload_root,
            self.config.devnet_height,
            sequence,
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind,
            subject_id: subject_id.to_string(),
            payload_root,
            state_root_after,
            height: self.config.devnet_height,
            sequence,
        };
        event.validate()?;
        self.events.insert(event_id, event);
        Ok(())
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PQ-CONFIDENTIAL-CONTRACT-VERIFIER-CACHE-PAYLOAD-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-VERIFIER-CACHE-RECORD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-VERIFIER-CACHE-PUBLIC-RECORD-ROOT",
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
        "PQ-CONFIDENTIAL-CONTRACT-VERIFIER-CACHE-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn deterministic_contract_id(label: &str, salt: &str) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(salt),
        ],
        32,
    )
}

pub fn verifier_key_id(
    contract_id: &str,
    circuit_kind: ContractCircuitKind,
    key_commitment_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-VERIFIER-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(circuit_kind.as_str()),
            HashPart::Str(key_commitment_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn circuit_manifest_id(
    contract_id: &str,
    verifier_key_id: &str,
    manifest_nonce: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-CIRCUIT-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(verifier_key_id),
            HashPart::Str(manifest_nonce),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn transcript_commitment_id(
    manifest_id: &str,
    verifier_key_id: &str,
    prover_commitment: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-TRANSCRIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(verifier_key_id),
            HashPart::Str(prover_commitment),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn committee_attestation_id(
    transcript_id: &str,
    committee_id: &str,
    committee_member_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-COMMITTEE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transcript_id),
            HashPart::Str(committee_id),
            HashPart::Str(committee_member_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn proof_cache_ticket_id(
    transcript_id: &str,
    attestation_id: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-PROOF-CACHE-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transcript_id),
            HashPart::Str(attestation_id),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_id: &str,
    ticket_id: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(ticket_id),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn batch_receipt_id(batch_id: &str, ticket_root: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-BATCH-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(ticket_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(
    reservation_id: &str,
    ticket_id: &str,
    sponsor_id: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reservation_id),
            HashPart::Str(ticket_id),
            HashPart::Str(sponsor_id),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn nullifier_fence_id(
    contract_id: &str,
    manifest_id: &str,
    nullifier_root: &str,
    privacy_epoch: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(manifest_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(privacy_epoch),
        ],
        32,
    )
}

pub fn event_id(
    event_kind: EventKind,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-CONFIDENTIAL-CONTRACT-RUNTIME-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"id": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 32 {
        return Err(format!("{field} must be a domain-separated root"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} cannot exceed {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(name: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{name} capacity exhausted"))
    } else {
        Ok(())
    }
}
