use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeProofCacheMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-proof-cache-market-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-proof-cache-market-v1";
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 702_000;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_CACHE_ENTRIES: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_LOOKUPS: usize = 8_388_608;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 64;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize = 512;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_LOOKUP_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_CACHE_TTL_BLOCKS: u64 = 20_160;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCacheKind {
    RecursiveValidity,
    ContractExecution,
    TokenTransfer,
    BridgeExit,
    OracleUpdate,
    CreditRisk,
    PerpMargin,
    SyntheticAsset,
}

impl ProofCacheKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecursiveValidity => "recursive_validity",
            Self::ContractExecution => "contract_execution",
            Self::TokenTransfer => "token_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::CreditRisk => "credit_risk",
            Self::PerpMargin => "perp_margin",
            Self::SyntheticAsset => "synthetic_asset",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEntryStatus {
    Proposed,
    Active,
    Warm,
    Expiring,
    Evicted,
    Slashed,
}

impl CacheEntryStatus {
    pub fn lookup_allowed(self) -> bool {
        matches!(self, Self::Active | Self::Warm | Self::Expiring)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupStatus {
    Submitted,
    Hit,
    Miss,
    Sponsored,
    Batched,
    Settled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Executing,
    Settled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    CacheEntryRegistered,
    LookupSubmitted,
    SponsorReserved,
    BatchBuilt,
    SettlementPublished,
    RebatePublished,
    EntrySlashed,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CacheEntryRegistered => "cache_entry_registered",
            Self::LookupSubmitted => "lookup_submitted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchBuilt => "batch_built",
            Self::SettlementPublished => "settlement_published",
            Self::RebatePublished => "rebate_published",
            Self::EntrySlashed => "entry_slashed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_cache_entries: usize,
    pub max_lookups: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub min_privacy_set_size: usize,
    pub batch_privacy_set_size: usize,
    pub max_lookup_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub cache_ttl_blocks: u64,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PQ_AUTH_SUITE.to_string(),
            max_cache_entries:
                PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_CACHE_ENTRIES,
            max_lookups: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_LOOKUPS,
            max_reservations:
                PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            max_lookup_fee_bps:
                PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_MAX_LOOKUP_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            cache_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEFAULT_CACHE_TTL_BLOCKS,
            devnet_height: PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_positive("max_cache_entries", self.max_cache_entries)?;
        require_positive("max_lookups", self.max_lookups)?;
        require_positive("max_reservations", self.max_reservations)?;
        require_positive("max_batches", self.max_batches)?;
        require_positive("max_receipts", self.max_receipts)?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("batch_privacy_set_size", self.batch_privacy_set_size)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        require_bps("max_lookup_fee_bps", self.max_lookup_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.target_rebate_bps > self.max_lookup_fee_bps {
            return Err("target_rebate_bps cannot exceed max_lookup_fee_bps".to_string());
        }
        if self.cache_ttl_blocks == 0 {
            return Err("cache_ttl_blocks must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub cache_entry_counter: u64,
    pub lookup_counter: u64,
    pub reservation_counter: u64,
    pub batch_counter: u64,
    pub receipt_counter: u64,
    pub rebate_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterProofCacheEntryRequest {
    pub prover_commitment: String,
    pub proof_kind: ProofCacheKind,
    pub proof_key_root: String,
    pub public_input_root: String,
    pub proof_commitment_root: String,
    pub verifier_program_root: String,
    pub pq_authorization_root: String,
    pub reusable_lookup_limit: u64,
    pub lookup_fee_bps: u64,
    pub expires_at_height: u64,
    pub cache_nonce: String,
}

impl RegisterProofCacheEntryRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
        require_non_empty("prover_commitment", &self.prover_commitment)?;
        require_root("proof_key_root", &self.proof_key_root)?;
        require_root("public_input_root", &self.public_input_root)?;
        require_root("proof_commitment_root", &self.proof_commitment_root)?;
        require_root("verifier_program_root", &self.verifier_program_root)?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require_non_empty("cache_nonce", &self.cache_nonce)?;
        if self.reusable_lookup_limit == 0 {
            return Err("reusable_lookup_limit must be positive".to_string());
        }
        require_bps("lookup_fee_bps", self.lookup_fee_bps)?;
        if self.lookup_fee_bps > config.max_lookup_fee_bps {
            return Err("lookup_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.expires_at_height <= config.devnet_height {
            return Err("cache entry must expire in the future".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitProofCacheLookupRequest {
    pub cache_entry_id: String,
    pub caller_commitment: String,
    pub private_input_commitment_root: String,
    pub expected_output_root: String,
    pub lookup_nullifier_root: String,
    pub pq_call_authorization_root: String,
    pub privacy_set_size: usize,
    pub max_lookup_fee_bps: u64,
    pub expires_at_height: u64,
    pub lookup_nonce: String,
}

impl SubmitProofCacheLookupRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
        require_non_empty("cache_entry_id", &self.cache_entry_id)?;
        require_non_empty("caller_commitment", &self.caller_commitment)?;
        require_root(
            "private_input_commitment_root",
            &self.private_input_commitment_root,
        )?;
        require_root("expected_output_root", &self.expected_output_root)?;
        require_root("lookup_nullifier_root", &self.lookup_nullifier_root)?;
        require_root(
            "pq_call_authorization_root",
            &self.pq_call_authorization_root,
        )?;
        require_non_empty("lookup_nonce", &self.lookup_nonce)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("lookup privacy set below runtime minimum".to_string());
        }
        require_bps("max_lookup_fee_bps", self.max_lookup_fee_bps)?;
        if self.max_lookup_fee_bps > config.max_lookup_fee_bps {
            return Err("max_lookup_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.expires_at_height <= config.devnet_height {
            return Err("lookup must expire in the future".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveProofCacheSponsorRequest {
    pub lookup_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_commitment_root: String,
    pub rebate_policy_root: String,
    pub pq_sponsor_authorization_root: String,
    pub reserved_fee_bps: u64,
    pub reserved_until_height: u64,
    pub reservation_nonce: String,
}

impl ReserveProofCacheSponsorRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
        if self.lookup_ids.is_empty() {
            return Err("lookup_ids cannot be empty".to_string());
        }
        require_unique("lookup_ids", &self.lookup_ids)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_root("budget_commitment_root", &self.budget_commitment_root)?;
        require_root("rebate_policy_root", &self.rebate_policy_root)?;
        require_root(
            "pq_sponsor_authorization_root",
            &self.pq_sponsor_authorization_root,
        )?;
        require_non_empty("reservation_nonce", &self.reservation_nonce)?;
        require_bps("reserved_fee_bps", self.reserved_fee_bps)?;
        if self.reserved_fee_bps > config.max_lookup_fee_bps {
            return Err("reserved_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.reserved_until_height <= config.devnet_height {
            return Err("reserved_until_height must be in the future".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildProofCacheSettlementBatchRequest {
    pub cache_entry_ids: Vec<String>,
    pub lookup_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub batch_builder_commitment: String,
    pub cache_hit_bitmap_root: String,
    pub output_batch_root: String,
    pub recursive_proof_root: String,
    pub batch_privacy_set_size: usize,
    pub total_fee_bps: u64,
    pub built_at_height: u64,
    pub batch_nonce: String,
}

impl BuildProofCacheSettlementBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
        if self.cache_entry_ids.is_empty() {
            return Err("cache_entry_ids cannot be empty".to_string());
        }
        if self.lookup_ids.is_empty() {
            return Err("lookup_ids cannot be empty".to_string());
        }
        require_unique("cache_entry_ids", &self.cache_entry_ids)?;
        require_unique("lookup_ids", &self.lookup_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_non_empty("batch_builder_commitment", &self.batch_builder_commitment)?;
        require_root("cache_hit_bitmap_root", &self.cache_hit_bitmap_root)?;
        require_root("output_batch_root", &self.output_batch_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_non_empty("batch_nonce", &self.batch_nonce)?;
        if self.batch_privacy_set_size < config.batch_privacy_set_size {
            return Err("batch_privacy_set_size below runtime target".to_string());
        }
        require_bps("total_fee_bps", self.total_fee_bps)?;
        if self.total_fee_bps > config.max_lookup_fee_bps {
            return Err("total_fee_bps exceeds runtime ceiling".to_string());
        }
        if self.built_at_height == 0 {
            return Err("built_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishProofCacheReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub pq_receipt_signature_root: String,
    pub emitted_at_height: u64,
    pub receipt_nonce: String,
}

impl PublishProofCacheReceiptRequest {
    pub fn validate(&self) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("settlement_root", &self.settlement_root)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("state_root_after", &self.state_root_after)?;
        require_root("pq_receipt_signature_root", &self.pq_receipt_signature_root)?;
        require_non_empty("receipt_nonce", &self.receipt_nonce)?;
        if self.emitted_at_height == 0 {
            return Err("emitted_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishProofCacheRebateRequest {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_commitment_root: String,
    pub settlement_receipt_id: String,
    pub pq_rebate_signature_root: String,
    pub rebate_bps: u64,
    pub emitted_at_height: u64,
    pub rebate_nonce: String,
}

impl PublishProofCacheRebateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
        require_non_empty("reservation_id", &self.reservation_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("rebate_asset_id", &self.rebate_asset_id)?;
        require_root("rebate_commitment_root", &self.rebate_commitment_root)?;
        require_non_empty("settlement_receipt_id", &self.settlement_receipt_id)?;
        require_root("pq_rebate_signature_root", &self.pq_rebate_signature_root)?;
        require_non_empty("rebate_nonce", &self.rebate_nonce)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.max_lookup_fee_bps {
            return Err("rebate_bps exceeds runtime ceiling".to_string());
        }
        if self.emitted_at_height == 0 {
            return Err("emitted_at_height must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheEntryRecord {
    pub cache_entry_id: String,
    pub request: RegisterProofCacheEntryRequest,
    pub status: CacheEntryStatus,
    pub cache_entry_root: String,
    pub remaining_lookup_limit: u64,
    pub registered_at_height: u64,
}

impl ProofCacheEntryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "cache_entry_id": self.cache_entry_id,
            "prover_commitment": self.request.prover_commitment,
            "proof_kind": self.request.proof_kind,
            "proof_key_root": self.request.proof_key_root,
            "public_input_root": self.request.public_input_root,
            "proof_commitment_root": self.request.proof_commitment_root,
            "verifier_program_root": self.request.verifier_program_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "reusable_lookup_limit": self.request.reusable_lookup_limit,
            "lookup_fee_bps": self.request.lookup_fee_bps,
            "expires_at_height": self.request.expires_at_height,
            "status": self.status,
            "remaining_lookup_limit": self.remaining_lookup_limit,
            "cache_entry_root": self.cache_entry_root,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheLookupRecord {
    pub lookup_id: String,
    pub request: SubmitProofCacheLookupRequest,
    pub status: LookupStatus,
    pub lookup_root: String,
    pub submitted_at_height: u64,
}

impl ProofCacheLookupRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lookup_id": self.lookup_id,
            "cache_entry_id": self.request.cache_entry_id,
            "caller_commitment": self.request.caller_commitment,
            "private_input_commitment_root": self.request.private_input_commitment_root,
            "expected_output_root": self.request.expected_output_root,
            "lookup_nullifier_root": self.request.lookup_nullifier_root,
            "pq_call_authorization_root": self.request.pq_call_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "max_lookup_fee_bps": self.request.max_lookup_fee_bps,
            "expires_at_height": self.request.expires_at_height,
            "status": self.status,
            "lookup_root": self.lookup_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveProofCacheSponsorRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
    pub reserved_at_height: u64,
}

impl ProofCacheSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "lookup_ids": self.request.lookup_ids,
            "sponsor_commitment": self.request.sponsor_commitment,
            "fee_asset_id": self.request.fee_asset_id,
            "budget_commitment_root": self.request.budget_commitment_root,
            "rebate_policy_root": self.request.rebate_policy_root,
            "pq_sponsor_authorization_root": self.request.pq_sponsor_authorization_root,
            "reserved_fee_bps": self.request.reserved_fee_bps,
            "reserved_until_height": self.request.reserved_until_height,
            "status": self.status,
            "reservation_root": self.reservation_root,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheSettlementBatchRecord {
    pub batch_id: String,
    pub request: BuildProofCacheSettlementBatchRequest,
    pub status: BatchStatus,
    pub batch_root: String,
    pub state_root_after: String,
}

impl ProofCacheSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "cache_entry_ids": self.request.cache_entry_ids,
            "lookup_ids": self.request.lookup_ids,
            "reservation_ids": self.request.reservation_ids,
            "batch_builder_commitment": self.request.batch_builder_commitment,
            "cache_hit_bitmap_root": self.request.cache_hit_bitmap_root,
            "output_batch_root": self.request.output_batch_root,
            "recursive_proof_root": self.request.recursive_proof_root,
            "batch_privacy_set_size": self.request.batch_privacy_set_size,
            "total_fee_bps": self.request.total_fee_bps,
            "built_at_height": self.request.built_at_height,
            "status": self.status,
            "batch_root": self.batch_root,
            "state_root_after": self.state_root_after,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheReceiptRecord {
    pub receipt_id: String,
    pub request: PublishProofCacheReceiptRequest,
    pub receipt_root: String,
}

impl ProofCacheReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.request.subject_id,
            "receipt_kind": self.request.receipt_kind,
            "settlement_root": self.request.settlement_root,
            "state_root_before": self.request.state_root_before,
            "state_root_after": self.request.state_root_after,
            "pq_receipt_signature_root": self.request.pq_receipt_signature_root,
            "emitted_at_height": self.request.emitted_at_height,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheRebateRecord {
    pub rebate_id: String,
    pub request: PublishProofCacheRebateRequest,
    pub rebate_root: String,
}

impl ProofCacheRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.request.reservation_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "rebate_asset_id": self.request.rebate_asset_id,
            "rebate_commitment_root": self.request.rebate_commitment_root,
            "settlement_receipt_id": self.request.settlement_receipt_id,
            "pq_rebate_signature_root": self.request.pq_rebate_signature_root,
            "rebate_bps": self.request.rebate_bps,
            "emitted_at_height": self.request.emitted_at_height,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub cache_entry_root: String,
    pub lookup_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub cache_entries: BTreeMap<String, ProofCacheEntryRecord>,
    pub lookups: BTreeMap<String, ProofCacheLookupRecord>,
    pub reservations: BTreeMap<String, ProofCacheSponsorReservationRecord>,
    pub batches: BTreeMap<String, ProofCacheSettlementBatchRecord>,
    pub receipts: BTreeMap<String, ProofCacheReceiptRecord>,
    pub rebates: BTreeMap<String, ProofCacheRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2LowFeeProofCacheMarketRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            cache_entries: BTreeMap::new(),
            lookups: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_cache_entry(
        &mut self,
        request: RegisterProofCacheEntryRequest,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<ProofCacheEntryRecord> {
        request.validate(&self.config)?;
        if self.cache_entries.len() >= self.config.max_cache_entries {
            return Err("proof cache entry capacity exhausted".to_string());
        }
        self.counters.cache_entry_counter = self.counters.cache_entry_counter.saturating_add(1);
        let cache_entry_id = proof_cache_entry_id(&request, self.counters.cache_entry_counter);
        let cache_entry_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-ENTRY",
            &request.public_record(),
        );
        let record = ProofCacheEntryRecord {
            cache_entry_id: cache_entry_id.clone(),
            remaining_lookup_limit: request.reusable_lookup_limit,
            request,
            status: CacheEntryStatus::Active,
            cache_entry_root,
            registered_at_height: self.config.devnet_height,
        };
        self.cache_entries.insert(cache_entry_id, record.clone());
        Ok(record)
    }

    pub fn submit_lookup(
        &mut self,
        request: SubmitProofCacheLookupRequest,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<ProofCacheLookupRecord> {
        request.validate(&self.config)?;
        if self.lookups.len() >= self.config.max_lookups {
            return Err("proof cache lookup capacity exhausted".to_string());
        }
        let cache_entry = self.require_cache_entry(&request.cache_entry_id)?;
        if !cache_entry.status.lookup_allowed() {
            return Err(format!(
                "cache entry {} does not accept lookups",
                request.cache_entry_id
            ));
        }
        if cache_entry.remaining_lookup_limit == 0 {
            return Err("cache entry lookup limit exhausted".to_string());
        }
        if self
            .consumed_nullifiers
            .contains(&request.lookup_nullifier_root)
        {
            return Err("proof cache lookup nullifier replay detected".to_string());
        }
        let cached_public_input_root = cache_entry.request.public_input_root.clone();
        self.counters.lookup_counter = self.counters.lookup_counter.saturating_add(1);
        let lookup_id = proof_cache_lookup_id(&request, self.counters.lookup_counter);
        let lookup_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-LOOKUP",
            &request.public_record(),
        );
        let status = if cached_public_input_root == request.expected_output_root {
            LookupStatus::Hit
        } else {
            LookupStatus::Submitted
        };
        let record = ProofCacheLookupRecord {
            lookup_id: lookup_id.clone(),
            request: request.clone(),
            status,
            lookup_root,
            submitted_at_height: self.config.devnet_height,
        };
        self.consumed_nullifiers
            .insert(request.lookup_nullifier_root.clone());
        if let Some(entry) = self.cache_entries.get_mut(&request.cache_entry_id) {
            entry.remaining_lookup_limit = entry.remaining_lookup_limit.saturating_sub(1);
            if entry.remaining_lookup_limit <= 8 {
                entry.status = CacheEntryStatus::Expiring;
            }
        }
        self.lookups.insert(lookup_id, record.clone());
        Ok(record)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveProofCacheSponsorRequest,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<ProofCacheSponsorReservationRecord> {
        request.validate(&self.config)?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("proof cache sponsor reservation capacity exhausted".to_string());
        }
        for lookup_id in &request.lookup_ids {
            self.require_lookup(lookup_id)?;
        }
        self.counters.reservation_counter = self.counters.reservation_counter.saturating_add(1);
        let reservation_id =
            proof_cache_sponsor_reservation_id(&request, self.counters.reservation_counter);
        let reservation_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-SPONSOR",
            &request.public_record(),
        );
        let record = ProofCacheSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request: request.clone(),
            status: ReservationStatus::Reserved,
            reservation_root,
            reserved_at_height: self.config.devnet_height,
        };
        for lookup_id in &request.lookup_ids {
            if let Some(lookup) = self.lookups.get_mut(lookup_id) {
                lookup.status = LookupStatus::Sponsored;
            }
        }
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildProofCacheSettlementBatchRequest,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<ProofCacheSettlementBatchRecord> {
        request.validate(&self.config)?;
        if self.batches.len() >= self.config.max_batches {
            return Err("proof cache settlement batch capacity exhausted".to_string());
        }
        for cache_entry_id in &request.cache_entry_ids {
            self.require_cache_entry(cache_entry_id)?;
        }
        for lookup_id in &request.lookup_ids {
            self.require_lookup(lookup_id)?;
        }
        for reservation_id in &request.reservation_ids {
            self.require_reservation(reservation_id)?;
        }
        self.counters.batch_counter = self.counters.batch_counter.saturating_add(1);
        let batch_id = proof_cache_settlement_batch_id(&request, self.counters.batch_counter);
        let batch_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-BATCH",
            &request.public_record(),
        );
        for lookup_id in &request.lookup_ids {
            if let Some(lookup) = self.lookups.get_mut(lookup_id) {
                lookup.status = LookupStatus::Batched;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let state_root_after = state_root_from_record(&json!({
            "batch_root": batch_root,
            "previous_state_root": self.state_root(),
            "batch_counter": self.counters.batch_counter,
        }));
        let record = ProofCacheSettlementBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: BatchStatus::Proposed,
            batch_root,
            state_root_after,
        };
        self.batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishProofCacheReceiptRequest,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<ProofCacheReceiptRecord> {
        request.validate()?;
        if self.receipts.len() >= self.config.max_receipts {
            return Err("proof cache receipt capacity exhausted".to_string());
        }
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let receipt_id = proof_cache_receipt_id(&request, self.counters.receipt_counter);
        let receipt_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-RECEIPT",
            &request.public_record(),
        );
        let record = ProofCacheReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            receipt_root,
        };
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishProofCacheRebateRequest,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<ProofCacheRebateRecord> {
        request.validate(&self.config)?;
        if self.rebates.len() >= self.config.max_receipts {
            return Err("proof cache rebate capacity exhausted".to_string());
        }
        self.require_reservation(&request.reservation_id)?;
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        let rebate_id = proof_cache_rebate_id(&request, self.counters.rebate_counter);
        let rebate_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-REBATE",
            &request.public_record(),
        );
        let record = ProofCacheRebateRecord {
            rebate_id: rebate_id.clone(),
            request: request.clone(),
            rebate_root,
        };
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::RebateQueued;
        }
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let cache_entry_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-ENTRIES",
            &self
                .cache_entries
                .values()
                .map(ProofCacheEntryRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let lookup_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-LOOKUPS",
            &self
                .lookups
                .values()
                .map(ProofCacheLookupRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(ProofCacheSponsorReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-BATCHES",
            &self
                .batches
                .values()
                .map(ProofCacheSettlementBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-RECEIPTS",
            &self
                .receipts
                .values()
                .map(ProofCacheReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-REBATES",
            &self
                .rebates
                .values()
                .map(ProofCacheRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = public_record_root(
            "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_record = json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "cache_entry_root": cache_entry_root,
            "lookup_root": lookup_root,
            "reservation_root": reservation_root,
            "batch_root": batch_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            cache_entry_root,
            lookup_root,
            reservation_root,
            batch_root,
            receipt_root,
            rebate_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_cache_entry(
        &self,
        cache_entry_id: &str,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<&ProofCacheEntryRecord> {
        self.cache_entries
            .get(cache_entry_id)
            .ok_or_else(|| format!("unknown proof cache entry {cache_entry_id}"))
    }

    fn require_lookup(
        &self,
        lookup_id: &str,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<&ProofCacheLookupRecord> {
        self.lookups
            .get(lookup_id)
            .ok_or_else(|| format!("unknown proof cache lookup {lookup_id}"))
    }

    fn require_reservation(
        &self,
        reservation_id: &str,
    ) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<&ProofCacheSponsorReservationRecord> {
        self.reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown proof cache sponsor reservation {reservation_id}"))
    }
}

pub type Runtime = State;

pub fn proof_cache_entry_id(request: &RegisterProofCacheEntryRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.proof_kind.as_str()),
            HashPart::Str(&request.prover_commitment),
            HashPart::Str(&request.proof_key_root),
            HashPart::Str(&request.public_input_root),
            HashPart::Str(&request.cache_nonce),
        ],
        32,
    )
}

pub fn proof_cache_lookup_id(request: &SubmitProofCacheLookupRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-LOOKUP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.cache_entry_id),
            HashPart::Str(&request.caller_commitment),
            HashPart::Str(&request.private_input_commitment_root),
            HashPart::Str(&request.lookup_nullifier_root),
            HashPart::Str(&request.lookup_nonce),
        ],
        32,
    )
}

pub fn proof_cache_sponsor_reservation_id(
    request: &ReserveProofCacheSponsorRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("lookups", &request.lookup_ids)),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.budget_commitment_root),
            HashPart::Str(&request.reservation_nonce),
        ],
        32,
    )
}

pub fn proof_cache_settlement_batch_id(
    request: &BuildProofCacheSettlementBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&id_list_root("cache_entries", &request.cache_entry_ids)),
            HashPart::Str(&id_list_root("lookups", &request.lookup_ids)),
            HashPart::Str(&request.cache_hit_bitmap_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn proof_cache_receipt_id(request: &PublishProofCacheReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.receipt_nonce),
        ],
        32,
    )
}

pub fn proof_cache_rebate_id(request: &PublishProofCacheRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.reservation_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-STATE", record)
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-LOW-FEE-PROOF-CACHE-MARKET-ID-LIST-{domain}"),
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn require_non_empty(field: &str, value: &str) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn require_positive(field: &str, value: usize) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
    if value > PRIVATE_L2_LOW_FEE_PROOF_CACHE_MARKET_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2LowFeeProofCacheMarketRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(field, value)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value {value}"));
        }
    }
    Ok(())
}
