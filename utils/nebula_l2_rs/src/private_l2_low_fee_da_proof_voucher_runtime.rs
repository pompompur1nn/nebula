use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeDaProofVoucherRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-da-proof-voucher-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DA_SUITE: &str =
    "encrypted-erasure-coded-da-with-private-retrieval-v1";
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_PROOF_SUITE: &str =
    "recursive-stark-proof-market-voucher-v1";
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEVNET_HEIGHT: u64 = 220_000;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_VOUCHERS: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_DA_COMMITMENTS: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_QUOTES: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 32_768;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherLane {
    PrivateContractCall,
    PrivateDefiSwap,
    ConfidentialToken,
    ConfidentialStablecoin,
    PrivateLending,
    PrivatePerps,
    MoneroFastExit,
    RuntimeCheckpoint,
    EmergencyEscape,
}

impl VoucherLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::ConfidentialToken => "confidential_token",
            Self::ConfidentialStablecoin => "confidential_stablecoin",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerps => "private_perps",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::RuntimeCheckpoint => "runtime_checkpoint",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn latency_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::MoneroFastExit => 9_600,
            Self::PrivatePerps => 9_100,
            Self::PrivateDefiSwap => 8_800,
            Self::PrivateLending => 8_500,
            Self::ConfidentialStablecoin => 8_300,
            Self::PrivateContractCall => 8_000,
            Self::ConfidentialToken => 7_600,
            Self::RuntimeCheckpoint => 6_700,
        }
    }

    pub fn defi(self) -> bool {
        matches!(
            self,
            Self::PrivateDefiSwap
                | Self::PrivateLending
                | Self::PrivatePerps
                | Self::ConfidentialStablecoin
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Open,
    DaAttached,
    Quoted,
    Reserved,
    SettlementReady,
    Settled,
    Rebated,
    Expired,
    Rejected,
}

impl VoucherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::DaAttached => "da_attached",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::DaAttached | Self::Quoted | Self::Reserved | Self::SettlementReady
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaCommitmentKind {
    EncryptedWitness,
    ErasureShard,
    StateDiff,
    CallTrace,
    MoneroAnchorHint,
    RecursiveProofHint,
    SettlementManifest,
}

impl DaCommitmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedWitness => "encrypted_witness",
            Self::ErasureShard => "erasure_shard",
            Self::StateDiff => "state_diff",
            Self::CallTrace => "call_trace",
            Self::MoneroAnchorHint => "monero_anchor_hint",
            Self::RecursiveProofHint => "recursive_proof_hint",
            Self::SettlementManifest => "settlement_manifest",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofServiceKind {
    RecursiveStark,
    ContractExecution,
    DefiNetting,
    ConfidentialToken,
    MoneroExit,
    DaAvailability,
    BatchSettlement,
}

impl ProofServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecursiveStark => "recursive_stark",
            Self::ContractExecution => "contract_execution",
            Self::DefiNetting => "defi_netting",
            Self::ConfidentialToken => "confidential_token",
            Self::MoneroExit => "monero_exit",
            Self::DaAvailability => "da_availability",
            Self::BatchSettlement => "batch_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Selected,
    Reserved,
    Filled,
    Expired,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Selected => "selected",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    ProofSubmitted,
    DaPublished,
    SettlementReady,
    Settled,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::ProofSubmitted => "proof_submitted",
            Self::DaPublished => "da_published",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Ready,
    Settled,
    Rebated,
    Disputed,
    Failed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Failed => "failed",
        }
    }

    pub fn successful(self) -> bool {
        matches!(self, Self::Settled | Self::Rebated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub da_suite: String,
    pub proof_suite: String,
    pub max_vouchers: usize,
    pub max_da_commitments: usize,
    pub max_quotes: usize,
    pub max_reservations: usize,
    pub max_receipts: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub voucher_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub roots_only: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_PQ_SUITE.to_string(),
            da_suite: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DA_SUITE.to_string(),
            proof_suite: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_PROOF_SUITE.to_string(),
            max_vouchers: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_VOUCHERS,
            max_da_commitments:
                PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_DA_COMMITMENTS,
            max_quotes: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_QUOTES,
            max_reservations: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_receipts: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps:
                PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_REBATE_BPS,
            voucher_ttl_blocks:
                PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_VOUCHER_TTL_BLOCKS,
            quote_ttl_blocks: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        required("protocol_version", &self.protocol_version)?;
        required("chain_id", &self.chain_id)?;
        required("hash_suite", &self.hash_suite)?;
        required("pq_suite", &self.pq_suite)?;
        required("da_suite", &self.da_suite)?;
        required("proof_suite", &self.proof_suite)?;
        if self.chain_id != CHAIN_ID {
            return Err("DA/proof voucher chain id mismatch".to_string());
        }
        if !self.roots_only {
            return Err("DA/proof voucher runtime requires roots-only privacy".to_string());
        }
        if self.max_vouchers == 0
            || self.max_da_commitments == 0
            || self.max_quotes == 0
            || self.max_reservations == 0
            || self.max_receipts == 0
        {
            return Err("DA/proof voucher capacities must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("DA/proof voucher privacy set policy is invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("DA/proof voucher PQ security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_MAX_BPS
            || self.sponsor_cover_bps > PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_MAX_BPS
            || self.rebate_bps > PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_MAX_BPS
        {
            return Err("DA/proof voucher bps policy is invalid".to_string());
        }
        if self.voucher_ttl_blocks == 0
            || self.quote_ttl_blocks == 0
            || self.reservation_ttl_blocks == 0
        {
            return Err("DA/proof voucher TTLs must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "da_suite": self.da_suite,
            "proof_suite": self.proof_suite,
            "max_vouchers": self.max_vouchers,
            "max_da_commitments": self.max_da_commitments,
            "max_quotes": self.max_quotes,
            "max_reservations": self.max_reservations,
            "max_receipts": self.max_receipts,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "roots_only": self.roots_only,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub voucher_counter: u64,
    pub da_commitment_counter: u64,
    pub proof_quote_counter: u64,
    pub reservation_counter: u64,
    pub settlement_counter: u64,
    pub rebate_counter: u64,
    pub consumed_nullifier_counter: u64,
    pub fee_rejection_counter: u64,
    pub privacy_rejection_counter: u64,
    pub pq_rejection_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_counter": self.voucher_counter,
            "da_commitment_counter": self.da_commitment_counter,
            "proof_quote_counter": self.proof_quote_counter,
            "reservation_counter": self.reservation_counter,
            "settlement_counter": self.settlement_counter,
            "rebate_counter": self.rebate_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
            "fee_rejection_counter": self.fee_rejection_counter,
            "privacy_rejection_counter": self.privacy_rejection_counter,
            "pq_rejection_counter": self.pq_rejection_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVoucherRequest {
    pub lane: VoucherLane,
    pub owner_commitment: String,
    pub workflow_root: String,
    pub state_read_root: String,
    pub expected_state_write_root: String,
    pub max_fee_bps: u64,
    pub low_fee_sponsor_root: String,
    pub rebate_claim_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub voucher_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl OpenVoucherRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        required("owner_commitment", &self.owner_commitment)?;
        required("workflow_root", &self.workflow_root)?;
        required("state_read_root", &self.state_read_root)?;
        required("expected_state_write_root", &self.expected_state_write_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("replay_fence_root", &self.replay_fence_root)?;
        required("voucher_nullifier", &self.voucher_nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
            required("rebate_claim_root", &self.rebate_claim_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("DA/proof voucher fee cap exceeds low-fee policy".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("DA/proof voucher expires before it can be used".to_string());
        }
        if self.expires_at_height - self.opened_at_height > config.voucher_ttl_blocks {
            return Err("DA/proof voucher TTL exceeds policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "owner_commitment": self.owner_commitment,
            "workflow_root": self.workflow_root,
            "state_read_root": self.state_read_root,
            "expected_state_write_root": self.expected_state_write_root,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "rebate_claim_root": self.rebate_claim_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "voucher_nullifier": self.voucher_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachDaCommitmentRequest {
    pub voucher_id: String,
    pub commitment_kind: DaCommitmentKind,
    pub encrypted_payload_root: String,
    pub erasure_coding_root: String,
    pub retrieval_hint_root: String,
    pub availability_committee_root: String,
    pub da_pq_signature_root: String,
    pub privacy_proof_root: String,
    pub da_nullifier: String,
    pub byte_size_commitment: u64,
    pub shard_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attached_at_height: u64,
}

impl AttachDaCommitmentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        required("voucher_id", &self.voucher_id)?;
        required("encrypted_payload_root", &self.encrypted_payload_root)?;
        required("erasure_coding_root", &self.erasure_coding_root)?;
        required("retrieval_hint_root", &self.retrieval_hint_root)?;
        required(
            "availability_committee_root",
            &self.availability_committee_root,
        )?;
        required("da_pq_signature_root", &self.da_pq_signature_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("da_nullifier", &self.da_nullifier)?;
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.byte_size_commitment == 0 || self.shard_count == 0 {
            return Err("DA commitment size and shard count must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "commitment_kind": self.commitment_kind.as_str(),
            "encrypted_payload_root": self.encrypted_payload_root,
            "erasure_coding_root": self.erasure_coding_root,
            "retrieval_hint_root": self.retrieval_hint_root,
            "availability_committee_root": self.availability_committee_root,
            "da_pq_signature_root": self.da_pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "da_nullifier": self.da_nullifier,
            "byte_size_commitment": self.byte_size_commitment,
            "shard_count": self.shard_count,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attached_at_height": self.attached_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostProofQuoteRequest {
    pub voucher_id: String,
    pub service_kind: ProofServiceKind,
    pub prover_commitment: String,
    pub proof_capacity_root: String,
    pub service_level_root: String,
    pub quote_terms_root: String,
    pub prover_pq_authorization_root: String,
    pub prover_bond_root: String,
    pub max_fee_bps: u64,
    pub estimated_latency_ms: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub quote_nonce: String,
}

impl PostProofQuoteRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        required("voucher_id", &self.voucher_id)?;
        required("prover_commitment", &self.prover_commitment)?;
        required("proof_capacity_root", &self.proof_capacity_root)?;
        required("service_level_root", &self.service_level_root)?;
        required("quote_terms_root", &self.quote_terms_root)?;
        required(
            "prover_pq_authorization_root",
            &self.prover_pq_authorization_root,
        )?;
        required("prover_bond_root", &self.prover_bond_root)?;
        required("quote_nonce", &self.quote_nonce)?;
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("proof quote exceeds voucher low-fee cap".to_string());
        }
        if self.estimated_latency_ms == 0 {
            return Err("proof quote latency must be positive".to_string());
        }
        if self.expires_at_height <= self.posted_at_height {
            return Err("proof quote expiry must follow posting height".to_string());
        }
        if self.expires_at_height - self.posted_at_height > config.quote_ttl_blocks {
            return Err("proof quote TTL exceeds policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "service_kind": self.service_kind.as_str(),
            "prover_commitment": self.prover_commitment,
            "proof_capacity_root": self.proof_capacity_root,
            "service_level_root": self.service_level_root,
            "quote_terms_root": self.quote_terms_root,
            "prover_pq_authorization_root": self.prover_pq_authorization_root,
            "prover_bond_root": self.prover_bond_root,
            "max_fee_bps": self.max_fee_bps,
            "estimated_latency_ms": self.estimated_latency_ms,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "quote_nonce": self.quote_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveProofCapacityRequest {
    pub voucher_id: String,
    pub proof_quote_id: String,
    pub da_commitment_ids: Vec<String>,
    pub reservation_commitment_root: String,
    pub recursive_proof_hint_root: String,
    pub fee_sponsor_root: String,
    pub capacity_nullifier: String,
    pub privacy_proof_root: String,
    pub pq_signature_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveProofCapacityRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        required("voucher_id", &self.voucher_id)?;
        required("proof_quote_id", &self.proof_quote_id)?;
        required(
            "reservation_commitment_root",
            &self.reservation_commitment_root,
        )?;
        required("recursive_proof_hint_root", &self.recursive_proof_hint_root)?;
        required("fee_sponsor_root", &self.fee_sponsor_root)?;
        required("capacity_nullifier", &self.capacity_nullifier)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("pq_signature_root", &self.pq_signature_root)?;
        if self.da_commitment_ids.is_empty() {
            return Err("proof capacity reservation requires DA commitments".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err("proof reservation expiry must follow reservation height".to_string());
        }
        if self.expires_at_height - self.reserved_at_height > config.reservation_ttl_blocks {
            return Err("proof reservation TTL exceeds policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "proof_quote_id": self.proof_quote_id,
            "da_commitment_ids": self.da_commitment_ids,
            "reservation_commitment_root": self.reservation_commitment_root,
            "recursive_proof_hint_root": self.recursive_proof_hint_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "capacity_nullifier": self.capacity_nullifier,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleVoucherRequest {
    pub voucher_id: String,
    pub reservation_id: String,
    pub settlement_status: SettlementStatus,
    pub proof_output_root: String,
    pub da_publication_root: String,
    pub settlement_tx_root: String,
    pub fee_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleVoucherRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        required("voucher_id", &self.voucher_id)?;
        required("reservation_id", &self.reservation_id)?;
        required("proof_output_root", &self.proof_output_root)?;
        required("da_publication_root", &self.da_publication_root)?;
        required("settlement_tx_root", &self.settlement_tx_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("low_fee_rebate_root", &self.low_fee_rebate_root)?;
        required("pq_settlement_root", &self.pq_settlement_root)?;
        required("state_root_after", &self.state_root_after)?;
        if self.settled_fee_bps > config.max_user_fee_bps {
            return Err("voucher settlement fee exceeds low-fee policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "reservation_id": self.reservation_id,
            "settlement_status": self.settlement_status.as_str(),
            "proof_output_root": self.proof_output_root,
            "da_publication_root": self.da_publication_root,
            "settlement_tx_root": self.settlement_tx_root,
            "fee_receipt_root": self.fee_receipt_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishRebateReceiptRequest {
    pub voucher_id: String,
    pub settlement_receipt_id: String,
    pub sponsor_commitment: String,
    pub rebate_commitment_root: String,
    pub rebate_note_root: String,
    pub privacy_proof_root: String,
    pub pq_signature_root: String,
    pub published_at_height: u64,
}

impl PublishRebateReceiptRequest {
    pub fn validate(&self) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        required("voucher_id", &self.voucher_id)?;
        required("settlement_receipt_id", &self.settlement_receipt_id)?;
        required("sponsor_commitment", &self.sponsor_commitment)?;
        required("rebate_commitment_root", &self.rebate_commitment_root)?;
        required("rebate_note_root", &self.rebate_note_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("pq_signature_root", &self.pq_signature_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "settlement_receipt_id": self.settlement_receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_commitment_root": self.rebate_commitment_root,
            "rebate_note_root": self.rebate_note_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherRecord {
    pub voucher_id: String,
    pub lane: VoucherLane,
    pub owner_commitment: String,
    pub workflow_root: String,
    pub state_read_root: String,
    pub expected_state_write_root: String,
    pub max_fee_bps: u64,
    pub low_fee_sponsor_root: String,
    pub rebate_claim_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub voucher_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: VoucherStatus,
    pub priority_score: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub da_commitment_ids: Vec<String>,
    pub proof_quote_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub settlement_receipt_ids: Vec<String>,
    pub rebate_receipt_ids: Vec<String>,
}

impl VoucherRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_id": self.voucher_id,
            "lane": self.lane.as_str(),
            "owner_commitment": self.owner_commitment,
            "workflow_root": self.workflow_root,
            "state_read_root": self.state_read_root,
            "expected_state_write_root": self.expected_state_write_root,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "rebate_claim_root": self.rebate_claim_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "voucher_nullifier": self.voucher_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "priority_score": self.priority_score,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "da_commitment_ids": self.da_commitment_ids,
            "proof_quote_ids": self.proof_quote_ids,
            "reservation_ids": self.reservation_ids,
            "settlement_receipt_ids": self.settlement_receipt_ids,
            "rebate_receipt_ids": self.rebate_receipt_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommitmentRecord {
    pub da_commitment_id: String,
    pub voucher_id: String,
    pub commitment_kind: DaCommitmentKind,
    pub encrypted_payload_root: String,
    pub erasure_coding_root: String,
    pub retrieval_hint_root: String,
    pub availability_committee_root: String,
    pub da_pq_signature_root: String,
    pub privacy_proof_root: String,
    pub da_nullifier: String,
    pub byte_size_commitment: u64,
    pub shard_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attached_at_height: u64,
}

impl DaCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "da_commitment_id": self.da_commitment_id,
            "voucher_id": self.voucher_id,
            "commitment_kind": self.commitment_kind.as_str(),
            "encrypted_payload_root": self.encrypted_payload_root,
            "erasure_coding_root": self.erasure_coding_root,
            "retrieval_hint_root": self.retrieval_hint_root,
            "availability_committee_root": self.availability_committee_root,
            "da_pq_signature_root": self.da_pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "da_nullifier": self.da_nullifier,
            "byte_size_commitment": self.byte_size_commitment,
            "shard_count": self.shard_count,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attached_at_height": self.attached_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofQuoteRecord {
    pub proof_quote_id: String,
    pub voucher_id: String,
    pub service_kind: ProofServiceKind,
    pub prover_commitment: String,
    pub proof_capacity_root: String,
    pub service_level_root: String,
    pub quote_terms_root: String,
    pub prover_pq_authorization_root: String,
    pub prover_bond_root: String,
    pub max_fee_bps: u64,
    pub estimated_latency_ms: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: QuoteStatus,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub quote_nonce: String,
}

impl ProofQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_quote_id": self.proof_quote_id,
            "voucher_id": self.voucher_id,
            "service_kind": self.service_kind.as_str(),
            "prover_commitment": self.prover_commitment,
            "proof_capacity_root": self.proof_capacity_root,
            "service_level_root": self.service_level_root,
            "quote_terms_root": self.quote_terms_root,
            "prover_pq_authorization_root": self.prover_pq_authorization_root,
            "prover_bond_root": self.prover_bond_root,
            "max_fee_bps": self.max_fee_bps,
            "estimated_latency_ms": self.estimated_latency_ms,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "quote_nonce": self.quote_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityReservationRecord {
    pub reservation_id: String,
    pub voucher_id: String,
    pub proof_quote_id: String,
    pub da_commitment_ids: Vec<String>,
    pub reservation_commitment_root: String,
    pub recursive_proof_hint_root: String,
    pub fee_sponsor_root: String,
    pub capacity_nullifier: String,
    pub privacy_proof_root: String,
    pub pq_signature_root: String,
    pub status: ReservationStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl CapacityReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "voucher_id": self.voucher_id,
            "proof_quote_id": self.proof_quote_id,
            "da_commitment_ids": self.da_commitment_ids,
            "reservation_commitment_root": self.reservation_commitment_root,
            "recursive_proof_hint_root": self.recursive_proof_hint_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "capacity_nullifier": self.capacity_nullifier,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherSettlementReceipt {
    pub settlement_receipt_id: String,
    pub voucher_id: String,
    pub reservation_id: String,
    pub settlement_status: SettlementStatus,
    pub proof_output_root: String,
    pub da_publication_root: String,
    pub settlement_tx_root: String,
    pub fee_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl VoucherSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_receipt_id": self.settlement_receipt_id,
            "voucher_id": self.voucher_id,
            "reservation_id": self.reservation_id,
            "settlement_status": self.settlement_status.as_str(),
            "proof_output_root": self.proof_output_root,
            "da_publication_root": self.da_publication_root,
            "settlement_tx_root": self.settlement_tx_root,
            "fee_receipt_root": self.fee_receipt_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateReceiptRecord {
    pub rebate_receipt_id: String,
    pub voucher_id: String,
    pub settlement_receipt_id: String,
    pub sponsor_commitment: String,
    pub rebate_commitment_root: String,
    pub rebate_note_root: String,
    pub privacy_proof_root: String,
    pub pq_signature_root: String,
    pub published_at_height: u64,
}

impl RebateReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_receipt_id": self.rebate_receipt_id,
            "voucher_id": self.voucher_id,
            "settlement_receipt_id": self.settlement_receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_commitment_root": self.rebate_commitment_root,
            "rebate_note_root": self.rebate_note_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub voucher_root: String,
    pub da_commitment_root: String,
    pub proof_quote_root: String,
    pub reservation_root: String,
    pub settlement_receipt_root: String,
    pub rebate_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_root": self.voucher_root,
            "da_commitment_root": self.da_commitment_root,
            "proof_quote_root": self.proof_quote_root,
            "reservation_root": self.reservation_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub vouchers: BTreeMap<String, VoucherRecord>,
    pub da_commitments: BTreeMap<String, DaCommitmentRecord>,
    pub proof_quotes: BTreeMap<String, ProofQuoteRecord>,
    pub reservations: BTreeMap<String, CapacityReservationRecord>,
    pub settlement_receipts: BTreeMap<String, VoucherSettlementReceipt>,
    pub rebate_receipts: BTreeMap<String, RebateReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2LowFeeDaProofVoucherRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_DEVNET_HEIGHT,
            vouchers: BTreeMap::new(),
            da_commitments: BTreeMap::new(),
            proof_quotes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebate_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_voucher(
        &mut self,
        request: OpenVoucherRequest,
    ) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<VoucherRecord> {
        self.config.validate()?;
        if let Err(error) = request.validate(&self.config) {
            self.observe_policy_error(&error);
            return Err(error);
        }
        if self.vouchers.len() >= self.config.max_vouchers {
            return Err("DA/proof voucher capacity exhausted".to_string());
        }
        self.consume_nullifier(&request.voucher_nullifier)?;
        self.counters.voucher_counter = self.counters.voucher_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let voucher_id = voucher_id(&request, self.counters.voucher_counter);
        let priority_score = request
            .lane
            .latency_priority()
            .saturating_add(if request.lane.defi() { 350 } else { 0 });
        let voucher = VoucherRecord {
            voucher_id: voucher_id.clone(),
            lane: request.lane,
            owner_commitment: request.owner_commitment,
            workflow_root: request.workflow_root,
            state_read_root: request.state_read_root,
            expected_state_write_root: request.expected_state_write_root,
            max_fee_bps: request.max_fee_bps,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            rebate_claim_root: request.rebate_claim_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            replay_fence_root: request.replay_fence_root,
            voucher_nullifier: request.voucher_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: VoucherStatus::Open,
            priority_score,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            da_commitment_ids: Vec::new(),
            proof_quote_ids: Vec::new(),
            reservation_ids: Vec::new(),
            settlement_receipt_ids: Vec::new(),
            rebate_receipt_ids: Vec::new(),
        };
        self.vouchers.insert(voucher_id, voucher.clone());
        Ok(voucher)
    }

    pub fn attach_da_commitment(
        &mut self,
        request: AttachDaCommitmentRequest,
    ) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<DaCommitmentRecord> {
        self.config.validate()?;
        if let Err(error) = request.validate(&self.config) {
            self.observe_policy_error(&error);
            return Err(error);
        }
        if self.da_commitments.len() >= self.config.max_da_commitments {
            return Err("DA commitment capacity exhausted".to_string());
        }
        let voucher = self
            .vouchers
            .get(&request.voucher_id)
            .ok_or_else(|| "DA/proof voucher not found for DA commitment".to_string())?;
        if !voucher.status.live() {
            return Err("DA/proof voucher is not live for DA attachment".to_string());
        }
        if request.attached_at_height >= voucher.expires_at_height {
            return Err("DA/proof voucher expired before DA attachment".to_string());
        }
        self.consume_nullifier(&request.da_nullifier)?;
        self.counters.da_commitment_counter = self.counters.da_commitment_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.attached_at_height);
        let da_commitment_id = da_commitment_id(&request, self.counters.da_commitment_counter);
        let record = DaCommitmentRecord {
            da_commitment_id: da_commitment_id.clone(),
            voucher_id: request.voucher_id.clone(),
            commitment_kind: request.commitment_kind,
            encrypted_payload_root: request.encrypted_payload_root,
            erasure_coding_root: request.erasure_coding_root,
            retrieval_hint_root: request.retrieval_hint_root,
            availability_committee_root: request.availability_committee_root,
            da_pq_signature_root: request.da_pq_signature_root,
            privacy_proof_root: request.privacy_proof_root,
            da_nullifier: request.da_nullifier,
            byte_size_commitment: request.byte_size_commitment,
            shard_count: request.shard_count,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attached_at_height: request.attached_at_height,
        };
        if let Some(voucher) = self.vouchers.get_mut(&request.voucher_id) {
            voucher.status = VoucherStatus::DaAttached;
            voucher.da_commitment_ids.push(da_commitment_id.clone());
        }
        self.da_commitments.insert(da_commitment_id, record.clone());
        Ok(record)
    }

    pub fn post_proof_quote(
        &mut self,
        request: PostProofQuoteRequest,
    ) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<ProofQuoteRecord> {
        self.config.validate()?;
        if let Err(error) = request.validate(&self.config) {
            self.observe_policy_error(&error);
            return Err(error);
        }
        if self.proof_quotes.len() >= self.config.max_quotes {
            return Err("proof quote capacity exhausted".to_string());
        }
        let voucher = self
            .vouchers
            .get(&request.voucher_id)
            .ok_or_else(|| "DA/proof voucher not found for proof quote".to_string())?;
        if !voucher.status.live() {
            return Err("DA/proof voucher is not live for proof quote".to_string());
        }
        if request.posted_at_height >= voucher.expires_at_height {
            return Err("DA/proof voucher expired before proof quote".to_string());
        }
        if request.max_fee_bps > voucher.max_fee_bps {
            return Err("proof quote exceeds voucher-specific fee cap".to_string());
        }
        self.counters.proof_quote_counter = self.counters.proof_quote_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.posted_at_height);
        let proof_quote_id = proof_quote_id(&request, self.counters.proof_quote_counter);
        let quote = ProofQuoteRecord {
            proof_quote_id: proof_quote_id.clone(),
            voucher_id: request.voucher_id.clone(),
            service_kind: request.service_kind,
            prover_commitment: request.prover_commitment,
            proof_capacity_root: request.proof_capacity_root,
            service_level_root: request.service_level_root,
            quote_terms_root: request.quote_terms_root,
            prover_pq_authorization_root: request.prover_pq_authorization_root,
            prover_bond_root: request.prover_bond_root,
            max_fee_bps: request.max_fee_bps,
            estimated_latency_ms: request.estimated_latency_ms,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: QuoteStatus::Posted,
            posted_at_height: request.posted_at_height,
            expires_at_height: request.expires_at_height,
            quote_nonce: request.quote_nonce,
        };
        if let Some(voucher) = self.vouchers.get_mut(&request.voucher_id) {
            voucher.status = VoucherStatus::Quoted;
            voucher.proof_quote_ids.push(proof_quote_id.clone());
        }
        self.proof_quotes.insert(proof_quote_id, quote.clone());
        Ok(quote)
    }

    pub fn reserve_proof_capacity(
        &mut self,
        request: ReserveProofCapacityRequest,
    ) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<CapacityReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("proof capacity reservation capacity exhausted".to_string());
        }
        {
            let voucher = self
                .vouchers
                .get(&request.voucher_id)
                .ok_or_else(|| "DA/proof voucher not found for capacity reservation".to_string())?;
            if !voucher.status.live() {
                return Err("DA/proof voucher is not live for capacity reservation".to_string());
            }
            if request.reserved_at_height >= voucher.expires_at_height {
                return Err("DA/proof voucher expired before capacity reservation".to_string());
            }
            let quote = self
                .proof_quotes
                .get(&request.proof_quote_id)
                .ok_or_else(|| "proof quote not found for capacity reservation".to_string())?;
            if quote.voucher_id != request.voucher_id {
                return Err("proof quote belongs to a different voucher".to_string());
            }
            if !quote.status.selectable() {
                return Err("proof quote is not selectable".to_string());
            }
            if request.reserved_at_height >= quote.expires_at_height {
                return Err("proof quote expired before reservation".to_string());
            }
            for da_commitment_id in &request.da_commitment_ids {
                let commitment = self.da_commitments.get(da_commitment_id).ok_or_else(|| {
                    format!("DA commitment {da_commitment_id} not found for reservation")
                })?;
                if commitment.voucher_id != request.voucher_id {
                    return Err("DA commitment belongs to a different voucher".to_string());
                }
            }
        }
        self.consume_nullifier(&request.capacity_nullifier)?;
        self.counters.reservation_counter = self.counters.reservation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let reservation_id = reservation_id(&request, self.counters.reservation_counter);
        let reservation = CapacityReservationRecord {
            reservation_id: reservation_id.clone(),
            voucher_id: request.voucher_id.clone(),
            proof_quote_id: request.proof_quote_id.clone(),
            da_commitment_ids: request.da_commitment_ids,
            reservation_commitment_root: request.reservation_commitment_root,
            recursive_proof_hint_root: request.recursive_proof_hint_root,
            fee_sponsor_root: request.fee_sponsor_root,
            capacity_nullifier: request.capacity_nullifier,
            privacy_proof_root: request.privacy_proof_root,
            pq_signature_root: request.pq_signature_root,
            status: ReservationStatus::Reserved,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(voucher) = self.vouchers.get_mut(&request.voucher_id) {
            voucher.status = VoucherStatus::Reserved;
            voucher.reservation_ids.push(reservation_id.clone());
        }
        if let Some(quote) = self.proof_quotes.get_mut(&request.proof_quote_id) {
            quote.status = QuoteStatus::Reserved;
        }
        self.reservations
            .insert(reservation_id, reservation.clone());
        Ok(reservation)
    }

    pub fn settle_voucher(
        &mut self,
        request: SettleVoucherRequest,
    ) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<VoucherSettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.settlement_receipts.len() >= self.config.max_receipts {
            return Err("voucher settlement receipt capacity exhausted".to_string());
        }
        {
            let voucher = self
                .vouchers
                .get(&request.voucher_id)
                .ok_or_else(|| "DA/proof voucher not found for settlement".to_string())?;
            if !voucher.status.live() {
                return Err("DA/proof voucher is not live for settlement".to_string());
            }
            if request.settled_at_height >= voucher.expires_at_height {
                return Err("DA/proof voucher expired before settlement".to_string());
            }
            let reservation = self
                .reservations
                .get(&request.reservation_id)
                .ok_or_else(|| "capacity reservation not found for settlement".to_string())?;
            if reservation.voucher_id != request.voucher_id {
                return Err("capacity reservation belongs to a different voucher".to_string());
            }
            if request.settled_at_height >= reservation.expires_at_height {
                return Err("capacity reservation expired before settlement".to_string());
            }
        }
        self.counters.settlement_counter = self.counters.settlement_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let settlement_receipt_id =
            settlement_receipt_id(&request, self.counters.settlement_counter);
        let receipt = VoucherSettlementReceipt {
            settlement_receipt_id: settlement_receipt_id.clone(),
            voucher_id: request.voucher_id.clone(),
            reservation_id: request.reservation_id.clone(),
            settlement_status: request.settlement_status,
            proof_output_root: request.proof_output_root,
            da_publication_root: request.da_publication_root,
            settlement_tx_root: request.settlement_tx_root,
            fee_receipt_root: request.fee_receipt_root,
            low_fee_rebate_root: request.low_fee_rebate_root,
            pq_settlement_root: request.pq_settlement_root,
            state_root_after: request.state_root_after,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        if let Some(voucher) = self.vouchers.get_mut(&request.voucher_id) {
            voucher.status = if request.settlement_status.successful() {
                VoucherStatus::Settled
            } else {
                VoucherStatus::Rejected
            };
            voucher
                .settlement_receipt_ids
                .push(settlement_receipt_id.clone());
        }
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = if request.settlement_status.successful() {
                ReservationStatus::Settled
            } else {
                ReservationStatus::Slashed
            };
        }
        self.settlement_receipts
            .insert(settlement_receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn publish_rebate_receipt(
        &mut self,
        request: PublishRebateReceiptRequest,
    ) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<RebateReceiptRecord> {
        self.config.validate()?;
        request.validate()?;
        if self.rebate_receipts.len() >= self.config.max_receipts {
            return Err("voucher rebate receipt capacity exhausted".to_string());
        }
        let voucher = self
            .vouchers
            .get(&request.voucher_id)
            .ok_or_else(|| "DA/proof voucher not found for rebate".to_string())?;
        if voucher.status != VoucherStatus::Settled {
            return Err("DA/proof voucher must settle before rebate".to_string());
        }
        let settlement = self
            .settlement_receipts
            .get(&request.settlement_receipt_id)
            .ok_or_else(|| "voucher settlement receipt not found for rebate".to_string())?;
        if settlement.voucher_id != request.voucher_id {
            return Err("settlement receipt belongs to a different voucher".to_string());
        }
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.published_at_height);
        let rebate_receipt_id = rebate_receipt_id(&request, self.counters.rebate_counter);
        let receipt = RebateReceiptRecord {
            rebate_receipt_id: rebate_receipt_id.clone(),
            voucher_id: request.voucher_id.clone(),
            settlement_receipt_id: request.settlement_receipt_id,
            sponsor_commitment: request.sponsor_commitment,
            rebate_commitment_root: request.rebate_commitment_root,
            rebate_note_root: request.rebate_note_root,
            privacy_proof_root: request.privacy_proof_root,
            pq_signature_root: request.pq_signature_root,
            published_at_height: request.published_at_height,
        };
        if let Some(voucher) = self.vouchers.get_mut(&request.voucher_id) {
            voucher.status = VoucherStatus::Rebated;
            voucher.rebate_receipt_ids.push(rebate_receipt_id.clone());
        }
        self.rebate_receipts
            .insert(rebate_receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let voucher_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-VOUCHERS",
            &self
                .vouchers
                .values()
                .map(VoucherRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let da_commitment_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-DA-COMMITMENTS",
            &self
                .da_commitments
                .values()
                .map(DaCommitmentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let proof_quote_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-QUOTES",
            &self
                .proof_quotes
                .values()
                .map(ProofQuoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(CapacityReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-SETTLEMENT-RECEIPTS",
            &self
                .settlement_receipts
                .values()
                .map(VoucherSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_receipt_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-REBATE-RECEIPTS",
            &self
                .rebate_receipts
                .values()
                .map(RebateReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-STATE",
            &json!({
                "protocol_version": self.config.protocol_version,
                "chain_id": self.config.chain_id,
                "current_height": self.current_height,
                "voucher_root": voucher_root,
                "da_commitment_root": da_commitment_root,
                "proof_quote_root": proof_quote_root,
                "reservation_root": reservation_root,
                "settlement_receipt_root": settlement_receipt_root,
                "rebate_receipt_root": rebate_receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            voucher_root,
            da_commitment_root,
            proof_quote_root,
            reservation_root,
            settlement_receipt_root,
            rebate_receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_suite": self.config.pq_suite,
            "da_suite": self.config.da_suite,
            "proof_suite": self.config.proof_suite,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "voucher_ids": self.vouchers.keys().cloned().collect::<Vec<_>>(),
            "da_commitment_ids": self.da_commitments.keys().cloned().collect::<Vec<_>>(),
            "proof_quote_ids": self.proof_quotes.keys().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservations.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
            "rebate_receipt_ids": self.rebate_receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
        let nullifier_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-DA-PROOF-NULLIFIER",
            &json!({ "nullifier": nullifier }),
        );
        if !self.consumed_nullifiers.insert(nullifier_root) {
            return Err("DA/proof voucher nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }

    fn observe_policy_error(&mut self, error: &str) {
        if error.contains("privacy") {
            self.counters.privacy_rejection_counter =
                self.counters.privacy_rejection_counter.saturating_add(1);
        }
        if error.contains("PQ") || error.contains("pq") {
            self.counters.pq_rejection_counter =
                self.counters.pq_rejection_counter.saturating_add(1);
        }
        if error.contains("fee") {
            self.counters.fee_rejection_counter =
                self.counters.fee_rejection_counter.saturating_add(1);
        }
    }
}

pub fn voucher_id(request: &OpenVoucherRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-DA-PROOF-VOUCHER-ID",
        &json!({
            "counter": counter,
            "lane": request.lane.as_str(),
            "owner_commitment": request.owner_commitment,
            "workflow_root": request.workflow_root,
            "voucher_nullifier": request.voucher_nullifier,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn da_commitment_id(request: &AttachDaCommitmentRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-DA-PROOF-DA-COMMITMENT-ID",
        &json!({
            "counter": counter,
            "voucher_id": request.voucher_id,
            "commitment_kind": request.commitment_kind.as_str(),
            "encrypted_payload_root": request.encrypted_payload_root,
            "da_nullifier": request.da_nullifier,
            "attached_at_height": request.attached_at_height,
        }),
    )
}

pub fn proof_quote_id(request: &PostProofQuoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-DA-PROOF-QUOTE-ID",
        &json!({
            "counter": counter,
            "voucher_id": request.voucher_id,
            "service_kind": request.service_kind.as_str(),
            "prover_commitment": request.prover_commitment,
            "quote_terms_root": request.quote_terms_root,
            "quote_nonce": request.quote_nonce,
            "posted_at_height": request.posted_at_height,
        }),
    )
}

pub fn reservation_id(request: &ReserveProofCapacityRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-DA-PROOF-RESERVATION-ID",
        &json!({
            "counter": counter,
            "voucher_id": request.voucher_id,
            "proof_quote_id": request.proof_quote_id,
            "da_commitment_ids": request.da_commitment_ids,
            "reservation_commitment_root": request.reservation_commitment_root,
            "capacity_nullifier": request.capacity_nullifier,
            "reserved_at_height": request.reserved_at_height,
        }),
    )
}

pub fn settlement_receipt_id(request: &SettleVoucherRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-DA-PROOF-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "voucher_id": request.voucher_id,
            "reservation_id": request.reservation_id,
            "proof_output_root": request.proof_output_root,
            "da_publication_root": request.da_publication_root,
            "settlement_tx_root": request.settlement_tx_root,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn rebate_receipt_id(request: &PublishRebateReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-DA-PROOF-REBATE-RECEIPT-ID",
        &json!({
            "counter": counter,
            "voucher_id": request.voucher_id,
            "settlement_receipt_id": request.settlement_receipt_id,
            "sponsor_commitment": request.sponsor_commitment,
            "rebate_commitment_root": request.rebate_commitment_root,
            "published_at_height": request.published_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_DA_PROOF_VOUCHER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(
        &format!("PRIVATE-L2-LOW-FEE-DA-PROOF-PAYLOAD-{domain}"),
        payload,
    )
}

fn required(field: &str, value: &str) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("DA/proof voucher field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2LowFeeDaProofVoucherRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("DA/proof voucher privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("DA/proof voucher PQ security bits below minimum".to_string());
    }
    Ok(())
}
