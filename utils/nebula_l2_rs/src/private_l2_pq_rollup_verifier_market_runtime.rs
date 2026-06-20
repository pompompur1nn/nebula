use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const PRIVATE_L2_PQ_ROLLUP_VERIFIER_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-rollup-verifier-market-runtime-v1";
pub const PROTOCOL_VERSION: &str = PRIVATE_L2_PQ_ROLLUP_VERIFIER_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_ROLLUP_VERIFIER_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_HEIGHT: u64 = 1_444_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-rollup-verifier-market-v1";
pub const MARKET_COMMITMENT_SCHEME: &str = "pq-rollup-verifier-bid-commitment-root-v1";
pub const PROOF_CACHE_SCHEME: &str = "private-l2-proof-cache-inventory-root-v1";
pub const RECURSIVE_JOB_SCHEME: &str = "low-latency-recursive-proof-job-root-v1";
pub const CHALLENGE_ESCROW_SCHEME: &str = "fraud-challenge-escrow-pq-aggregate-root-v1";
pub const SPONSOR_RESERVATION_SCHEME: &str = "private-l2-fee-sponsor-reservation-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "pq-rollup-market-settlement-receipt-root-v1";
pub const SLASHING_SCHEME: &str = "verifier-performance-slashing-root-v1";
pub const SCHEDULING_SCHEME: &str = "low-latency-verifier-scheduling-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 850;
pub const DEFAULT_MAX_VERIFY_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_RECURSION_FEE_BPS: u64 = 18;
pub const DEFAULT_MIN_BOND_PICONERO: u128 = 250_000_000_000;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 20_160;
pub const DEFAULT_JOB_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_PERFORMANCE_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_SLASH_BPS: u64 = 750;
pub const DEFAULT_REBATE_BPS: u64 = 8;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 2_048;
pub const MAX_VERIFIER_PROFILES: usize = 1_048_576;
pub const MAX_VERIFIER_BIDS: usize = 4_194_304;
pub const MAX_PROOF_CACHE_INVENTORY: usize = 8_388_608;
pub const MAX_RECURSIVE_JOBS: usize = 4_194_304;
pub const MAX_CHALLENGE_ESCROWS: usize = 2_097_152;
pub const MAX_SPONSOR_RESERVATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENT_RECEIPTS: usize = 8_388_608;
pub const MAX_PERFORMANCE_REPORTS: usize = 4_194_304;
pub const MAX_SCHEDULE_SLOTS: usize = 4_194_304;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupCircuitKind {
    BatchValidity,
    StateTransition,
    DataAvailability,
    BridgeExit,
    ContractCall,
    FeeAccounting,
    NullifierFence,
    RecursiveAggregate,
}

impl RollupCircuitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchValidity => "batch_validity",
            Self::StateTransition => "state_transition",
            Self::DataAvailability => "data_availability",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::FeeAccounting => "fee_accounting",
            Self::NullifierFence => "nullifier_fence",
            Self::RecursiveAggregate => "recursive_aggregate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierProfileStatus {
    Proposed,
    Active,
    Preferred,
    Congested,
    Quarantined,
    Retired,
    Slashed,
}

impl VerifierProfileStatus {
    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Active | Self::Preferred | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Open,
    Matched,
    Reserved,
    Executing,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl BidStatus {
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Matched | Self::Reserved | Self::Executing
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheItemStatus {
    Advertised,
    Hot,
    Reserved,
    Consumed,
    Refreshing,
    Expired,
    Disputed,
    Slashed,
}

impl CacheItemStatus {
    pub fn can_schedule(self) -> bool {
        matches!(self, Self::Advertised | Self::Hot | Self::Refreshing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveJobStatus {
    Queued,
    Assigned,
    Proving,
    ProofReady,
    Submitted,
    Settled,
    Challenged,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Escalated,
    Slashed,
    Refunded,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    BoundToJob,
    PartiallyConsumed,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Posted,
    Finalized,
    Challenged,
    Reverted,
    Repriced,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    MissedLatency,
    InvalidProof,
    UnavailableCache,
    DoubleAssignment,
    FeeOvercharge,
    ChallengeLoss,
    PqKeyRevoked,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissedLatency => "missed_latency",
            Self::InvalidProof => "invalid_proof",
            Self::UnavailableCache => "unavailable_cache",
            Self::DoubleAssignment => "double_assignment",
            Self::FeeOvercharge => "fee_overcharge",
            Self::ChallengeLoss => "challenge_loss",
            Self::PqKeyRevoked => "pq_key_revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    Open,
    Assigned,
    Locked,
    Executed,
    Missed,
    Requeued,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    VerifierRegistered,
    BidPosted,
    CacheAdvertised,
    RecursiveJobQueued,
    JobScheduled,
    ChallengeEscrowed,
    SponsorReserved,
    SettlementPosted,
    PerformanceReported,
    VerifierSlashed,
    RuntimeRootPublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifierRegistered => "verifier_registered",
            Self::BidPosted => "bid_posted",
            Self::CacheAdvertised => "cache_advertised",
            Self::RecursiveJobQueued => "recursive_job_queued",
            Self::JobScheduled => "job_scheduled",
            Self::ChallengeEscrowed => "challenge_escrowed",
            Self::SponsorReserved => "sponsor_reserved",
            Self::SettlementPosted => "settlement_posted",
            Self::PerformanceReported => "performance_reported",
            Self::VerifierSlashed => "verifier_slashed",
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
    pub market_commitment_scheme: String,
    pub proof_cache_scheme: String,
    pub recursive_job_scheme: String,
    pub challenge_escrow_scheme: String,
    pub sponsor_reservation_scheme: String,
    pub settlement_receipt_scheme: String,
    pub slashing_scheme: String,
    pub scheduling_scheme: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_latency_ms: u64,
    pub max_verify_fee_bps: u64,
    pub max_recursion_fee_bps: u64,
    pub min_bond_piconero: u128,
    pub challenge_window_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub cache_ttl_blocks: u64,
    pub job_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub performance_epoch_blocks: u64,
    pub default_slash_bps: u64,
    pub rebate_bps: u64,
    pub max_batch_items: usize,
    pub devnet_height: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_ROLLUP_VERIFIER_MARKET_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            market_commitment_scheme: MARKET_COMMITMENT_SCHEME.to_string(),
            proof_cache_scheme: PROOF_CACHE_SCHEME.to_string(),
            recursive_job_scheme: RECURSIVE_JOB_SCHEME.to_string(),
            challenge_escrow_scheme: CHALLENGE_ESCROW_SCHEME.to_string(),
            sponsor_reservation_scheme: SPONSOR_RESERVATION_SCHEME.to_string(),
            settlement_receipt_scheme: SETTLEMENT_RECEIPT_SCHEME.to_string(),
            slashing_scheme: SLASHING_SCHEME.to_string(),
            scheduling_scheme: SCHEDULING_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            max_verify_fee_bps: DEFAULT_MAX_VERIFY_FEE_BPS,
            max_recursion_fee_bps: DEFAULT_MAX_RECURSION_FEE_BPS,
            min_bond_piconero: DEFAULT_MIN_BOND_PICONERO,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            job_ttl_blocks: DEFAULT_JOB_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            performance_epoch_blocks: DEFAULT_PERFORMANCE_EPOCH_BLOCKS,
            default_slash_bps: DEFAULT_SLASH_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
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
        require_bps("max_verify_fee_bps", self.max_verify_fee_bps)?;
        require_bps("max_recursion_fee_bps", self.max_recursion_fee_bps)?;
        require_bps("default_slash_bps", self.default_slash_bps)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive_u64("batch_privacy_set_size", self.batch_privacy_set_size)?;
        require_positive_u64("target_latency_ms", self.target_latency_ms)?;
        require_positive_u64("challenge_window_blocks", self.challenge_window_blocks)?;
        require_positive_u64("bid_ttl_blocks", self.bid_ttl_blocks)?;
        require_positive_u64("cache_ttl_blocks", self.cache_ttl_blocks)?;
        require_positive_u64("job_ttl_blocks", self.job_ttl_blocks)?;
        require_positive_u64("reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        require_positive_u64("settlement_ttl_blocks", self.settlement_ttl_blocks)?;
        require_positive_u64("performance_epoch_blocks", self.performance_epoch_blocks)?;
        require_positive_usize("max_batch_items", self.max_batch_items)?;
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch_privacy_set_size cannot be below min_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits must stay at post-quantum strength".to_string());
        }
        if self.min_bond_piconero == 0 {
            return Err("min_bond_piconero must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub verifier_profiles: u64,
    pub verifier_bids: u64,
    pub proof_cache_items: u64,
    pub recursive_jobs: u64,
    pub challenge_escrows: u64,
    pub sponsor_reservations: u64,
    pub settlement_receipts: u64,
    pub performance_reports: u64,
    pub schedule_slots: u64,
    pub events: u64,
    pub live_bids: u64,
    pub assigned_jobs: u64,
    pub settled_jobs: u64,
    pub challenged_jobs: u64,
    pub slashed_verifiers: u64,
    pub total_fee_reserved_piconero: u128,
    pub total_fee_paid_piconero: u128,
    pub total_rebate_piconero: u128,
    pub total_slashed_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierProfile {
    pub verifier_id: String,
    pub operator_commitment: String,
    pub pq_identity_root: String,
    pub stake_bond_piconero: u128,
    pub supported_circuit_root: String,
    pub endpoint_commitment_root: String,
    pub performance_oracle_root: String,
    pub max_parallel_jobs: u32,
    pub target_latency_ms: u64,
    pub min_fee_bps: u64,
    pub pq_security_bits: u16,
    pub status: VerifierProfileStatus,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl VerifierProfile {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("verifier_id", &self.verifier_id)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_root("pq_identity_root", &self.pq_identity_root)?;
        require_root("supported_circuit_root", &self.supported_circuit_root)?;
        require_root("endpoint_commitment_root", &self.endpoint_commitment_root)?;
        require_root("performance_oracle_root", &self.performance_oracle_root)?;
        require_root("metadata_root", &self.metadata_root)?;
        require_positive_u64("target_latency_ms", self.target_latency_ms)?;
        require_bps("min_fee_bps", self.min_fee_bps)?;
        if self.stake_bond_piconero < config.min_bond_piconero {
            return Err("verifier stake bond below runtime minimum".to_string());
        }
        if self.max_parallel_jobs == 0 {
            return Err("max_parallel_jobs must be positive".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("verifier pq security below runtime minimum".to_string());
        }
        if self.expires_at_height <= self.registered_at_height {
            return Err(
                "verifier expires_at_height must be after registered_at_height".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierBid {
    pub bid_id: String,
    pub verifier_id: String,
    pub circuit_kind: RollupCircuitKind,
    pub market_lane: String,
    pub bid_commitment_root: String,
    pub max_batch_items: usize,
    pub verify_fee_bps: u64,
    pub recursion_fee_bps: u64,
    pub latency_target_ms: u64,
    pub available_job_slots: u32,
    pub collateral_piconero: u128,
    pub status: BidStatus,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl VerifierBid {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("bid_id", &self.bid_id)?;
        require_non_empty("verifier_id", &self.verifier_id)?;
        require_non_empty("market_lane", &self.market_lane)?;
        require_root("bid_commitment_root", &self.bid_commitment_root)?;
        require_positive_usize("max_batch_items", self.max_batch_items)?;
        require_bps("verify_fee_bps", self.verify_fee_bps)?;
        require_bps("recursion_fee_bps", self.recursion_fee_bps)?;
        require_positive_u64("latency_target_ms", self.latency_target_ms)?;
        if self.max_batch_items > config.max_batch_items {
            return Err("bid max_batch_items exceeds runtime maximum".to_string());
        }
        if self.verify_fee_bps > config.max_verify_fee_bps {
            return Err("verify_fee_bps exceeds runtime maximum".to_string());
        }
        if self.recursion_fee_bps > config.max_recursion_fee_bps {
            return Err("recursion_fee_bps exceeds runtime maximum".to_string());
        }
        if self.available_job_slots == 0 {
            return Err("available_job_slots must be positive".to_string());
        }
        if self.collateral_piconero == 0 {
            return Err("collateral_piconero must be positive".to_string());
        }
        if self.expires_at_height <= self.posted_at_height {
            return Err("bid expires_at_height must be after posted_at_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheInventoryItem {
    pub cache_item_id: String,
    pub verifier_id: String,
    pub circuit_kind: RollupCircuitKind,
    pub verifier_key_root: String,
    pub proof_commitment_root: String,
    pub public_input_schema_root: String,
    pub recursive_hint_root: String,
    pub privacy_set_size: u64,
    pub reuse_limit: u64,
    pub reuse_count: u64,
    pub lookup_fee_bps: u64,
    pub status: CacheItemStatus,
    pub advertised_at_height: u64,
    pub expires_at_height: u64,
}

impl ProofCacheInventoryItem {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("cache_item_id", &self.cache_item_id)?;
        require_non_empty("verifier_id", &self.verifier_id)?;
        require_root("verifier_key_root", &self.verifier_key_root)?;
        require_root("proof_commitment_root", &self.proof_commitment_root)?;
        require_root("public_input_schema_root", &self.public_input_schema_root)?;
        require_root("recursive_hint_root", &self.recursive_hint_root)?;
        require_positive_u64("privacy_set_size", self.privacy_set_size)?;
        require_positive_u64("reuse_limit", self.reuse_limit)?;
        require_bps("lookup_fee_bps", self.lookup_fee_bps)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("cache privacy_set_size below runtime minimum".to_string());
        }
        if self.reuse_count > self.reuse_limit {
            return Err("cache reuse_count cannot exceed reuse_limit".to_string());
        }
        if self.lookup_fee_bps > config.max_verify_fee_bps {
            return Err("cache lookup_fee_bps exceeds runtime maximum".to_string());
        }
        if self.expires_at_height <= self.advertised_at_height {
            return Err("cache expires_at_height must be after advertised_at_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofJob {
    pub job_id: String,
    pub requester_commitment: String,
    pub circuit_kind: RollupCircuitKind,
    pub input_root: String,
    pub witness_commitment_root: String,
    pub required_cache_root: String,
    pub assigned_verifier_id: Option<String>,
    pub bid_id: Option<String>,
    pub cache_item_id: Option<String>,
    pub batch_item_count: usize,
    pub privacy_set_size: u64,
    pub max_fee_piconero: u128,
    pub priority_fee_piconero: u128,
    pub deadline_height: u64,
    pub status: RecursiveJobStatus,
    pub queued_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl RecursiveProofJob {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("job_id", &self.job_id)?;
        require_non_empty("requester_commitment", &self.requester_commitment)?;
        require_root("input_root", &self.input_root)?;
        require_root("witness_commitment_root", &self.witness_commitment_root)?;
        require_root("required_cache_root", &self.required_cache_root)?;
        require_positive_usize("batch_item_count", self.batch_item_count)?;
        require_positive_u64("privacy_set_size", self.privacy_set_size)?;
        if self.batch_item_count > config.max_batch_items {
            return Err("job batch_item_count exceeds runtime maximum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("job privacy_set_size below runtime minimum".to_string());
        }
        if self.max_fee_piconero == 0 {
            return Err("max_fee_piconero must be positive".to_string());
        }
        if self.deadline_height <= self.queued_at_height {
            return Err("job deadline_height must be after queued_at_height".to_string());
        }
        if let Some(settled_at_height) = self.settled_at_height {
            if settled_at_height < self.queued_at_height {
                return Err("settled_at_height cannot be before queued_at_height".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeEscrow {
    pub challenge_id: String,
    pub challenger_commitment: String,
    pub job_id: String,
    pub verifier_id: String,
    pub challenged_receipt_id: Option<String>,
    pub evidence_root: String,
    pub escrow_piconero: u128,
    pub slash_bps: u64,
    pub status: ChallengeStatus,
    pub opened_at_height: u64,
    pub deadline_height: u64,
}

impl ChallengeEscrow {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("challenge_id", &self.challenge_id)?;
        require_non_empty("challenger_commitment", &self.challenger_commitment)?;
        require_non_empty("job_id", &self.job_id)?;
        require_non_empty("verifier_id", &self.verifier_id)?;
        require_root("evidence_root", &self.evidence_root)?;
        require_bps("slash_bps", self.slash_bps)?;
        if self.escrow_piconero == 0 {
            return Err("escrow_piconero must be positive".to_string());
        }
        if self.slash_bps < config.default_slash_bps {
            return Err("challenge slash_bps below runtime default".to_string());
        }
        if self.deadline_height <= self.opened_at_height {
            return Err("challenge deadline_height must be after opened_at_height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub job_id: String,
    pub beneficiary_commitment: String,
    pub reserved_fee_piconero: u128,
    pub consumed_fee_piconero: u128,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorReservation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("reservation_id", &self.reservation_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("job_id", &self.job_id)?;
        require_non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.reserved_fee_piconero == 0 {
            return Err("reserved_fee_piconero must be positive".to_string());
        }
        if self.consumed_fee_piconero > self.reserved_fee_piconero {
            return Err("consumed_fee_piconero cannot exceed reserved_fee_piconero".to_string());
        }
        if self.rebate_bps < config.rebate_bps {
            return Err("reservation rebate_bps below runtime target".to_string());
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
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub job_id: String,
    pub verifier_id: String,
    pub bid_id: String,
    pub sponsor_reservation_id: Option<String>,
    pub recursive_proof_root: String,
    pub public_output_root: String,
    pub settlement_state_root: String,
    pub fee_paid_piconero: u128,
    pub rebate_piconero: u128,
    pub latency_ms: u64,
    pub status: SettlementStatus,
    pub posted_at_height: u64,
    pub finality_height: u64,
}

impl SettlementReceipt {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("job_id", &self.job_id)?;
        require_non_empty("verifier_id", &self.verifier_id)?;
        require_non_empty("bid_id", &self.bid_id)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_root("public_output_root", &self.public_output_root)?;
        require_root("settlement_state_root", &self.settlement_state_root)?;
        require_positive_u64("latency_ms", self.latency_ms)?;
        if self.fee_paid_piconero == 0 {
            return Err("fee_paid_piconero must be positive".to_string());
        }
        if self.rebate_piconero > self.fee_paid_piconero {
            return Err("rebate_piconero cannot exceed fee_paid_piconero".to_string());
        }
        if self.finality_height <= self.posted_at_height {
            return Err("finality_height must be after posted_at_height".to_string());
        }
        if self.latency_ms > config.target_latency_ms * 16 {
            return Err("latency_ms is outside market safety envelope".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PerformanceReport {
    pub report_id: String,
    pub verifier_id: String,
    pub epoch: u64,
    pub jobs_assigned: u64,
    pub jobs_settled: u64,
    pub jobs_missed: u64,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub invalid_proof_count: u64,
    pub availability_bps: u64,
    pub slash_reason: Option<SlashingReason>,
    pub slash_amount_piconero: u128,
    pub oracle_signature_root: String,
    pub reported_at_height: u64,
}

impl PerformanceReport {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("report_id", &self.report_id)?;
        require_non_empty("verifier_id", &self.verifier_id)?;
        require_bps("availability_bps", self.availability_bps)?;
        require_root("oracle_signature_root", &self.oracle_signature_root)?;
        if self.jobs_settled > self.jobs_assigned {
            return Err("jobs_settled cannot exceed jobs_assigned".to_string());
        }
        if self.jobs_missed > self.jobs_assigned {
            return Err("jobs_missed cannot exceed jobs_assigned".to_string());
        }
        if self.p95_latency_ms < self.median_latency_ms {
            return Err("p95_latency_ms cannot be below median_latency_ms".to_string());
        }
        if self.slash_amount_piconero > 0 && self.slash_reason.is_none() {
            return Err("slash_amount_piconero requires slash_reason".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleSlot {
    pub slot_id: String,
    pub job_id: String,
    pub verifier_id: String,
    pub bid_id: String,
    pub cache_item_id: Option<String>,
    pub lane: String,
    pub priority_score: u128,
    pub scheduled_height: u64,
    pub lock_expires_height: u64,
    pub expected_latency_ms: u64,
    pub status: ScheduleStatus,
}

impl ScheduleSlot {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("slot_id", &self.slot_id)?;
        require_non_empty("job_id", &self.job_id)?;
        require_non_empty("verifier_id", &self.verifier_id)?;
        require_non_empty("bid_id", &self.bid_id)?;
        require_non_empty("lane", &self.lane)?;
        require_positive_u64("expected_latency_ms", self.expected_latency_ms)?;
        if self.lock_expires_height <= self.scheduled_height {
            return Err("lock_expires_height must be after scheduled_height".to_string());
        }
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
    pub config_root: String,
    pub verifier_profile_root: String,
    pub verifier_bid_root: String,
    pub proof_cache_inventory_root: String,
    pub recursive_job_root: String,
    pub challenge_escrow_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub performance_report_root: String,
    pub schedule_slot_root: String,
    pub active_verifier_root: String,
    pub live_bid_root: String,
    pub assigned_job_root: String,
    pub slashed_verifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: config_root(config),
            verifier_profile_root: merkle_root("PQ-ROLLUP-MARKET-VERIFIER-PROFILES", &[]),
            verifier_bid_root: merkle_root("PQ-ROLLUP-MARKET-BIDS", &[]),
            proof_cache_inventory_root: merkle_root("PQ-ROLLUP-MARKET-PROOF-CACHE", &[]),
            recursive_job_root: merkle_root("PQ-ROLLUP-MARKET-RECURSIVE-JOBS", &[]),
            challenge_escrow_root: merkle_root("PQ-ROLLUP-MARKET-CHALLENGE-ESCROWS", &[]),
            sponsor_reservation_root: merkle_root("PQ-ROLLUP-MARKET-SPONSOR-RESERVATIONS", &[]),
            settlement_receipt_root: merkle_root("PQ-ROLLUP-MARKET-SETTLEMENT-RECEIPTS", &[]),
            performance_report_root: merkle_root("PQ-ROLLUP-MARKET-PERFORMANCE-REPORTS", &[]),
            schedule_slot_root: merkle_root("PQ-ROLLUP-MARKET-SCHEDULE-SLOTS", &[]),
            active_verifier_root: merkle_root("PQ-ROLLUP-MARKET-ACTIVE-VERIFIERS", &[]),
            live_bid_root: merkle_root("PQ-ROLLUP-MARKET-LIVE-BIDS", &[]),
            assigned_job_root: merkle_root("PQ-ROLLUP-MARKET-ASSIGNED-JOBS", &[]),
            slashed_verifier_root: merkle_root("PQ-ROLLUP-MARKET-SLASHED-VERIFIERS", &[]),
            event_root: merkle_root("PQ-ROLLUP-MARKET-EVENTS", &[]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub verifier_profiles: BTreeMap<String, VerifierProfile>,
    pub verifier_bids: BTreeMap<String, VerifierBid>,
    pub proof_cache_inventory: BTreeMap<String, ProofCacheInventoryItem>,
    pub recursive_jobs: BTreeMap<String, RecursiveProofJob>,
    pub challenge_escrows: BTreeMap<String, ChallengeEscrow>,
    pub sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub performance_reports: BTreeMap<String, PerformanceReport>,
    pub schedule_slots: BTreeMap<String, ScheduleSlot>,
    pub active_verifier_ids: BTreeSet<String>,
    pub live_bid_ids: BTreeSet<String>,
    pub assigned_job_ids: BTreeSet<String>,
    pub slashed_verifier_ids: BTreeSet<String>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

pub type Runtime = State;

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet()).expect("valid default rollup verifier market config")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            verifier_profiles: BTreeMap::new(),
            verifier_bids: BTreeMap::new(),
            proof_cache_inventory: BTreeMap::new(),
            recursive_jobs: BTreeMap::new(),
            challenge_escrows: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            performance_reports: BTreeMap::new(),
            schedule_slots: BTreeMap::new(),
            active_verifier_ids: BTreeSet::new(),
            live_bid_ids: BTreeSet::new(),
            assigned_job_ids: BTreeSet::new(),
            slashed_verifier_ids: BTreeSet::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet market config");
        let height = state.config.devnet_height;
        let primary_verifier_id = verifier_id("devnet-fast-verifier", "region-us-east", height, 0);
        let backup_verifier_id = verifier_id("devnet-backup-verifier", "region-us-west", height, 1);
        let circuit_root = payload_root(
            "DEVNET-MARKET-CIRCUITS",
            &json!([
                RollupCircuitKind::BatchValidity.as_str(),
                RollupCircuitKind::RecursiveAggregate.as_str(),
                RollupCircuitKind::ContractCall.as_str()
            ]),
        );
        let endpoint_root = payload_root(
            "DEVNET-MARKET-ENDPOINTS",
            &json!(["quic://verifier-a.devnet", "tor://verifier-a-hidden"]),
        );
        let oracle_root = payload_root(
            "DEVNET-MARKET-ORACLE",
            &json!(["latency-feed", "invalid-proof-feed"]),
        );
        state
            .register_verifier(VerifierProfile {
                verifier_id: primary_verifier_id.clone(),
                operator_commitment: commitment("operator", "devnet-fast-verifier"),
                pq_identity_root: payload_root("DEVNET-PQ-ID", &json!({"key": "ml-dsa-87-a"})),
                stake_bond_piconero: DEFAULT_MIN_BOND_PICONERO * 4,
                supported_circuit_root: circuit_root.clone(),
                endpoint_commitment_root: endpoint_root,
                performance_oracle_root: oracle_root.clone(),
                max_parallel_jobs: 256,
                target_latency_ms: 420,
                min_fee_bps: 4,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                status: VerifierProfileStatus::Preferred,
                registered_at_height: height,
                expires_at_height: height + DEFAULT_CACHE_TTL_BLOCKS,
                metadata_root: payload_root(
                    "DEVNET-VERIFIER-METADATA",
                    &json!({"lane": "fast", "hardware": "gpu+fpga"}),
                ),
            })
            .expect("devnet primary verifier");
        state
            .register_verifier(VerifierProfile {
                verifier_id: backup_verifier_id.clone(),
                operator_commitment: commitment("operator", "devnet-backup-verifier"),
                pq_identity_root: payload_root("DEVNET-PQ-ID", &json!({"key": "slh-dsa-backup"})),
                stake_bond_piconero: DEFAULT_MIN_BOND_PICONERO * 2,
                supported_circuit_root: circuit_root,
                endpoint_commitment_root: payload_root(
                    "DEVNET-MARKET-ENDPOINTS",
                    &json!(["quic://verifier-b.devnet"]),
                ),
                performance_oracle_root: oracle_root,
                max_parallel_jobs: 96,
                target_latency_ms: 700,
                min_fee_bps: 5,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                status: VerifierProfileStatus::Active,
                registered_at_height: height,
                expires_at_height: height + DEFAULT_CACHE_TTL_BLOCKS,
                metadata_root: payload_root(
                    "DEVNET-VERIFIER-METADATA",
                    &json!({"lane": "cheap", "hardware": "gpu"}),
                ),
            })
            .expect("devnet backup verifier");

        let bid_id = bid_id(
            &primary_verifier_id,
            RollupCircuitKind::RecursiveAggregate,
            "fast-lane",
            height + 1,
            0,
        );
        state
            .post_bid(VerifierBid {
                bid_id: bid_id.clone(),
                verifier_id: primary_verifier_id.clone(),
                circuit_kind: RollupCircuitKind::RecursiveAggregate,
                market_lane: "fast-lane".to_string(),
                bid_commitment_root: payload_root(
                    "DEVNET-BID",
                    &json!({"latency_ms": 420, "fee_bps": 6}),
                ),
                max_batch_items: 512,
                verify_fee_bps: 6,
                recursion_fee_bps: 10,
                latency_target_ms: 420,
                available_job_slots: 64,
                collateral_piconero: DEFAULT_MIN_BOND_PICONERO,
                status: BidStatus::Open,
                posted_at_height: height + 1,
                expires_at_height: height + DEFAULT_BID_TTL_BLOCKS,
            })
            .expect("devnet bid");
        let cache_item_id = cache_item_id(
            &primary_verifier_id,
            RollupCircuitKind::RecursiveAggregate,
            "devnet-rollup-vk",
            height + 1,
            0,
        );
        state
            .advertise_cache_item(ProofCacheInventoryItem {
                cache_item_id: cache_item_id.clone(),
                verifier_id: primary_verifier_id.clone(),
                circuit_kind: RollupCircuitKind::RecursiveAggregate,
                verifier_key_root: payload_root("DEVNET-VK", &json!({"vk": "rollup-v1"})),
                proof_commitment_root: payload_root(
                    "DEVNET-PROOF-CACHE",
                    &json!({"cache": "warm"}),
                ),
                public_input_schema_root: payload_root(
                    "DEVNET-PUBLIC-INPUT-SCHEMA",
                    &json!(["state_root", "withdrawal_root", "fee_root"]),
                ),
                recursive_hint_root: payload_root("DEVNET-RECURSION-HINT", &json!({"fold": 8})),
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                reuse_limit: 1_024,
                reuse_count: 2,
                lookup_fee_bps: 3,
                status: CacheItemStatus::Hot,
                advertised_at_height: height + 1,
                expires_at_height: height + DEFAULT_CACHE_TTL_BLOCKS,
            })
            .expect("devnet cache");
        let job_id = recursive_job_id(
            "devnet-requester",
            "devnet-rollup-batch-0001",
            height + 2,
            0,
        );
        state
            .queue_recursive_job(RecursiveProofJob {
                job_id: job_id.clone(),
                requester_commitment: commitment("requester", "devnet-rollup-operator"),
                circuit_kind: RollupCircuitKind::RecursiveAggregate,
                input_root: payload_root(
                    "DEVNET-JOB-INPUT",
                    &json!({"batch": "0001", "items": 128}),
                ),
                witness_commitment_root: payload_root(
                    "DEVNET-JOB-WITNESS",
                    &json!({"witness": "encrypted"}),
                ),
                required_cache_root: payload_root(
                    "DEVNET-JOB-CACHE-REQ",
                    &json!({"vk": "rollup-v1"}),
                ),
                assigned_verifier_id: None,
                bid_id: None,
                cache_item_id: None,
                batch_item_count: 128,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                max_fee_piconero: 15_000_000,
                priority_fee_piconero: 800_000,
                deadline_height: height + DEFAULT_JOB_TTL_BLOCKS,
                status: RecursiveJobStatus::Queued,
                queued_at_height: height + 2,
                settled_at_height: None,
            })
            .expect("devnet job");
        let slot_id = state
            .schedule_job(&job_id, &bid_id, Some(&cache_item_id), height + 3)
            .expect("devnet schedule");
        let reservation_id = sponsor_reservation_id("devnet-sponsor", &job_id, height + 3, 0);
        state
            .reserve_sponsor(FeeSponsorReservation {
                reservation_id: reservation_id.clone(),
                sponsor_commitment: commitment("sponsor", "devnet-low-fee-sponsor"),
                job_id: job_id.clone(),
                beneficiary_commitment: commitment("beneficiary", "devnet-requester"),
                reserved_fee_piconero: 15_000_000,
                consumed_fee_piconero: 12_000_000,
                rebate_bps: DEFAULT_REBATE_BPS,
                status: ReservationStatus::PartiallyConsumed,
                reserved_at_height: height + 3,
                expires_at_height: height + DEFAULT_RESERVATION_TTL_BLOCKS,
            })
            .expect("devnet sponsor");
        let receipt_id =
            settlement_receipt_id(&job_id, &primary_verifier_id, "devnet-proof", height + 4, 0);
        state
            .post_settlement_receipt(SettlementReceipt {
                receipt_id: receipt_id.clone(),
                job_id: job_id.clone(),
                verifier_id: primary_verifier_id.clone(),
                bid_id: bid_id.clone(),
                sponsor_reservation_id: Some(reservation_id),
                recursive_proof_root: payload_root(
                    "DEVNET-RECURSIVE-PROOF",
                    &json!({"proof": "submitted"}),
                ),
                public_output_root: payload_root(
                    "DEVNET-JOB-OUTPUT",
                    &json!({"new_state_root": "hidden"}),
                ),
                settlement_state_root: payload_root(
                    "DEVNET-SETTLEMENT-STATE",
                    &json!({"slot_id": slot_id}),
                ),
                fee_paid_piconero: 12_000_000,
                rebate_piconero: 600_000,
                latency_ms: 390,
                status: SettlementStatus::Finalized,
                posted_at_height: height + 4,
                finality_height: height + 8,
            })
            .expect("devnet receipt");
        state
            .record_performance(PerformanceReport {
                report_id: performance_report_id(&primary_verifier_id, 1, height + 8, 0),
                verifier_id: primary_verifier_id,
                epoch: 1,
                jobs_assigned: 128,
                jobs_settled: 127,
                jobs_missed: 1,
                median_latency_ms: 410,
                p95_latency_ms: 780,
                invalid_proof_count: 0,
                availability_bps: 9_950,
                slash_reason: None,
                slash_amount_piconero: 0,
                oracle_signature_root: payload_root(
                    "DEVNET-PERFORMANCE-ORACLE-SIG",
                    &json!({"sig": "pq-oracle"}),
                ),
                reported_at_height: height + 8,
            })
            .expect("devnet performance");
        let challenge_id = challenge_escrow_id(
            "devnet-challenger",
            &backup_verifier_id,
            &job_id,
            height + 9,
            0,
        );
        state
            .open_challenge(ChallengeEscrow {
                challenge_id,
                challenger_commitment: commitment("challenger", "devnet-watchtower"),
                job_id,
                verifier_id: backup_verifier_id,
                challenged_receipt_id: Some(receipt_id),
                evidence_root: payload_root(
                    "DEVNET-CHALLENGE-EVIDENCE",
                    &json!({"kind": "latency-sample"}),
                ),
                escrow_piconero: 25_000_000,
                slash_bps: DEFAULT_SLASH_BPS,
                status: ChallengeStatus::Open,
                opened_at_height: height + 9,
                deadline_height: height + DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            })
            .expect("devnet challenge");
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            verifier_profiles: self.verifier_profiles.len() as u64,
            verifier_bids: self.verifier_bids.len() as u64,
            proof_cache_items: self.proof_cache_inventory.len() as u64,
            recursive_jobs: self.recursive_jobs.len() as u64,
            challenge_escrows: self.challenge_escrows.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            performance_reports: self.performance_reports.len() as u64,
            schedule_slots: self.schedule_slots.len() as u64,
            events: self.events.len() as u64,
            live_bids: self.live_bid_ids.len() as u64,
            assigned_jobs: self.assigned_job_ids.len() as u64,
            settled_jobs: self
                .recursive_jobs
                .values()
                .filter(|job| job.status == RecursiveJobStatus::Settled)
                .count() as u64,
            challenged_jobs: self
                .recursive_jobs
                .values()
                .filter(|job| job.status == RecursiveJobStatus::Challenged)
                .count() as u64,
            slashed_verifiers: self.slashed_verifier_ids.len() as u64,
            total_fee_reserved_piconero: self
                .sponsor_reservations
                .values()
                .map(|reservation| reservation.reserved_fee_piconero)
                .sum(),
            total_fee_paid_piconero: self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.fee_paid_piconero)
                .sum(),
            total_rebate_piconero: self
                .settlement_receipts
                .values()
                .map(|receipt| receipt.rebate_piconero)
                .sum(),
            total_slashed_piconero: self
                .performance_reports
                .values()
                .map(|report| report.slash_amount_piconero)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: config_root(&self.config),
            verifier_profile_root: map_root(
                "PQ-ROLLUP-MARKET-VERIFIER-PROFILES",
                &self.verifier_profiles,
            ),
            verifier_bid_root: map_root("PQ-ROLLUP-MARKET-BIDS", &self.verifier_bids),
            proof_cache_inventory_root: map_root(
                "PQ-ROLLUP-MARKET-PROOF-CACHE",
                &self.proof_cache_inventory,
            ),
            recursive_job_root: map_root("PQ-ROLLUP-MARKET-RECURSIVE-JOBS", &self.recursive_jobs),
            challenge_escrow_root: map_root(
                "PQ-ROLLUP-MARKET-CHALLENGE-ESCROWS",
                &self.challenge_escrows,
            ),
            sponsor_reservation_root: map_root(
                "PQ-ROLLUP-MARKET-SPONSOR-RESERVATIONS",
                &self.sponsor_reservations,
            ),
            settlement_receipt_root: map_root(
                "PQ-ROLLUP-MARKET-SETTLEMENT-RECEIPTS",
                &self.settlement_receipts,
            ),
            performance_report_root: map_root(
                "PQ-ROLLUP-MARKET-PERFORMANCE-REPORTS",
                &self.performance_reports,
            ),
            schedule_slot_root: map_root("PQ-ROLLUP-MARKET-SCHEDULE-SLOTS", &self.schedule_slots),
            active_verifier_root: set_root(
                "PQ-ROLLUP-MARKET-ACTIVE-VERIFIERS",
                &self.active_verifier_ids,
            ),
            live_bid_root: set_root("PQ-ROLLUP-MARKET-LIVE-BIDS", &self.live_bid_ids),
            assigned_job_root: set_root("PQ-ROLLUP-MARKET-ASSIGNED-JOBS", &self.assigned_job_ids),
            slashed_verifier_root: set_root(
                "PQ-ROLLUP-MARKET-SLASHED-VERIFIERS",
                &self.slashed_verifier_ids,
            ),
            event_root: map_root("PQ-ROLLUP-MARKET-EVENTS", &self.events),
        }
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

    pub fn register_verifier(&mut self, profile: VerifierProfile) -> Result<String> {
        profile.validate(&self.config)?;
        ensure_capacity(
            "verifier_profiles",
            self.verifier_profiles.len(),
            MAX_VERIFIER_PROFILES,
        )?;
        if self.verifier_profiles.contains_key(&profile.verifier_id) {
            return Err("verifier profile already exists".to_string());
        }
        let id = profile.verifier_id.clone();
        let payload = profile.public_record();
        if profile.status.accepts_work() {
            self.active_verifier_ids.insert(id.clone());
        }
        self.verifier_profiles.insert(id.clone(), profile);
        self.emit_event(EventKind::VerifierRegistered, &id, &payload)?;
        Ok(id)
    }

    pub fn post_bid(&mut self, bid: VerifierBid) -> Result<String> {
        bid.validate(&self.config)?;
        ensure_capacity("verifier_bids", self.verifier_bids.len(), MAX_VERIFIER_BIDS)?;
        let profile = self
            .verifier_profiles
            .get(&bid.verifier_id)
            .ok_or_else(|| "bid verifier profile is missing".to_string())?;
        if !profile.status.accepts_work() {
            return Err("bid verifier cannot accept work".to_string());
        }
        if bid.verify_fee_bps < profile.min_fee_bps {
            return Err("bid verify_fee_bps below verifier min_fee_bps".to_string());
        }
        if self.verifier_bids.contains_key(&bid.bid_id) {
            return Err("verifier bid already exists".to_string());
        }
        let id = bid.bid_id.clone();
        let payload = bid.public_record();
        if bid.status.is_live() {
            self.live_bid_ids.insert(id.clone());
        }
        self.verifier_bids.insert(id.clone(), bid);
        self.emit_event(EventKind::BidPosted, &id, &payload)?;
        Ok(id)
    }

    pub fn advertise_cache_item(&mut self, item: ProofCacheInventoryItem) -> Result<String> {
        item.validate(&self.config)?;
        ensure_capacity(
            "proof_cache_inventory",
            self.proof_cache_inventory.len(),
            MAX_PROOF_CACHE_INVENTORY,
        )?;
        if !self.verifier_profiles.contains_key(&item.verifier_id) {
            return Err("cache item verifier profile is missing".to_string());
        }
        if self.proof_cache_inventory.contains_key(&item.cache_item_id) {
            return Err("proof cache item already exists".to_string());
        }
        let id = item.cache_item_id.clone();
        let payload = item.public_record();
        self.proof_cache_inventory.insert(id.clone(), item);
        self.emit_event(EventKind::CacheAdvertised, &id, &payload)?;
        Ok(id)
    }

    pub fn queue_recursive_job(&mut self, job: RecursiveProofJob) -> Result<String> {
        job.validate(&self.config)?;
        ensure_capacity(
            "recursive_jobs",
            self.recursive_jobs.len(),
            MAX_RECURSIVE_JOBS,
        )?;
        if self.recursive_jobs.contains_key(&job.job_id) {
            return Err("recursive job already exists".to_string());
        }
        if job.assigned_verifier_id.is_some() || job.bid_id.is_some() || job.cache_item_id.is_some()
        {
            return Err("queued recursive jobs must not be pre-assigned".to_string());
        }
        let id = job.job_id.clone();
        let payload = job.public_record();
        self.recursive_jobs.insert(id.clone(), job);
        self.emit_event(EventKind::RecursiveJobQueued, &id, &payload)?;
        Ok(id)
    }

    pub fn schedule_job(
        &mut self,
        job_id: &str,
        bid_id: &str,
        cache_item_id: Option<&str>,
        scheduled_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "schedule_slots",
            self.schedule_slots.len(),
            MAX_SCHEDULE_SLOTS,
        )?;
        let bid = self
            .verifier_bids
            .get(bid_id)
            .ok_or_else(|| "schedule bid is missing".to_string())?
            .clone();
        if !bid.status.is_live() {
            return Err("schedule bid is not live".to_string());
        }
        let verifier = self
            .verifier_profiles
            .get(&bid.verifier_id)
            .ok_or_else(|| "schedule verifier is missing".to_string())?;
        if !verifier.status.accepts_work() {
            return Err("schedule verifier cannot accept work".to_string());
        }
        if let Some(cache_id) = cache_item_id {
            let cache = self
                .proof_cache_inventory
                .get(cache_id)
                .ok_or_else(|| "schedule cache item is missing".to_string())?;
            if cache.verifier_id != bid.verifier_id {
                return Err("schedule cache item belongs to a different verifier".to_string());
            }
            if !cache.status.can_schedule() {
                return Err("schedule cache item is not available".to_string());
            }
        }
        let slot_sequence = self.schedule_slots.len() as u64;
        let lock_expires_height = scheduled_height + self.config.job_ttl_blocks;
        let cache_item_id = cache_item_id.map(str::to_string);
        let priority_score = {
            let job = self
                .recursive_jobs
                .get_mut(job_id)
                .ok_or_else(|| "schedule job is missing".to_string())?;
            if job.status != RecursiveJobStatus::Queued {
                return Err("only queued jobs can be scheduled".to_string());
            }
            if job.circuit_kind != bid.circuit_kind {
                return Err("schedule bid circuit_kind does not match job".to_string());
            }
            if job.batch_item_count > bid.max_batch_items {
                return Err("schedule job exceeds bid max_batch_items".to_string());
            }
            job.assigned_verifier_id = Some(bid.verifier_id.clone());
            job.bid_id = Some(bid_id.to_string());
            job.cache_item_id = cache_item_id.clone();
            job.status = RecursiveJobStatus::Assigned;
            scheduling_score(job, &bid, scheduled_height)
        };
        self.assigned_job_ids.insert(job_id.to_string());
        let slot = ScheduleSlot {
            slot_id: schedule_slot_id(job_id, bid_id, scheduled_height, slot_sequence),
            job_id: job_id.to_string(),
            verifier_id: bid.verifier_id.clone(),
            bid_id: bid_id.to_string(),
            cache_item_id,
            lane: bid.market_lane.clone(),
            priority_score,
            scheduled_height,
            lock_expires_height,
            expected_latency_ms: bid.latency_target_ms,
            status: ScheduleStatus::Assigned,
        };
        slot.validate()?;
        let id = slot.slot_id.clone();
        let payload = slot.public_record();
        self.schedule_slots.insert(id.clone(), slot);
        self.emit_event(EventKind::JobScheduled, &id, &payload)?;
        Ok(id)
    }

    pub fn open_challenge(&mut self, challenge: ChallengeEscrow) -> Result<String> {
        challenge.validate(&self.config)?;
        ensure_capacity(
            "challenge_escrows",
            self.challenge_escrows.len(),
            MAX_CHALLENGE_ESCROWS,
        )?;
        if !self.recursive_jobs.contains_key(&challenge.job_id) {
            return Err("challenge job is missing".to_string());
        }
        if !self.verifier_profiles.contains_key(&challenge.verifier_id) {
            return Err("challenge verifier is missing".to_string());
        }
        if self.challenge_escrows.contains_key(&challenge.challenge_id) {
            return Err("challenge escrow already exists".to_string());
        }
        let id = challenge.challenge_id.clone();
        let payload = challenge.public_record();
        if let Some(job) = self.recursive_jobs.get_mut(&challenge.job_id) {
            job.status = RecursiveJobStatus::Challenged;
        }
        self.challenge_escrows.insert(id.clone(), challenge);
        self.emit_event(EventKind::ChallengeEscrowed, &id, &payload)?;
        Ok(id)
    }

    pub fn reserve_sponsor(&mut self, reservation: FeeSponsorReservation) -> Result<String> {
        reservation.validate(&self.config)?;
        ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            MAX_SPONSOR_RESERVATIONS,
        )?;
        if !self.recursive_jobs.contains_key(&reservation.job_id) {
            return Err("reservation job is missing".to_string());
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

    pub fn post_settlement_receipt(&mut self, receipt: SettlementReceipt) -> Result<String> {
        receipt.validate(&self.config)?;
        ensure_capacity(
            "settlement_receipts",
            self.settlement_receipts.len(),
            MAX_SETTLEMENT_RECEIPTS,
        )?;
        if !self.verifier_profiles.contains_key(&receipt.verifier_id) {
            return Err("receipt verifier is missing".to_string());
        }
        if !self.verifier_bids.contains_key(&receipt.bid_id) {
            return Err("receipt bid is missing".to_string());
        }
        if let Some(reservation_id) = &receipt.sponsor_reservation_id {
            if !self.sponsor_reservations.contains_key(reservation_id) {
                return Err("receipt sponsor reservation is missing".to_string());
            }
        }
        let job = self
            .recursive_jobs
            .get_mut(&receipt.job_id)
            .ok_or_else(|| "receipt job is missing".to_string())?;
        if job.assigned_verifier_id.as_deref() != Some(receipt.verifier_id.as_str()) {
            return Err("receipt verifier does not match assigned job".to_string());
        }
        job.status = if receipt.status == SettlementStatus::Challenged {
            RecursiveJobStatus::Challenged
        } else {
            RecursiveJobStatus::Settled
        };
        job.settled_at_height = Some(receipt.posted_at_height);
        self.assigned_job_ids.remove(&receipt.job_id);
        let id = receipt.receipt_id.clone();
        let payload = receipt.public_record();
        self.settlement_receipts.insert(id.clone(), receipt);
        self.emit_event(EventKind::SettlementPosted, &id, &payload)?;
        Ok(id)
    }

    pub fn record_performance(&mut self, report: PerformanceReport) -> Result<String> {
        report.validate()?;
        ensure_capacity(
            "performance_reports",
            self.performance_reports.len(),
            MAX_PERFORMANCE_REPORTS,
        )?;
        if !self.verifier_profiles.contains_key(&report.verifier_id) {
            return Err("performance verifier is missing".to_string());
        }
        if self.performance_reports.contains_key(&report.report_id) {
            return Err("performance report already exists".to_string());
        }
        let id = report.report_id.clone();
        let payload = report.public_record();
        if report.slash_amount_piconero > 0 {
            self.slashed_verifier_ids.insert(report.verifier_id.clone());
        }
        self.performance_reports.insert(id.clone(), report);
        self.emit_event(EventKind::PerformanceReported, &id, &payload)?;
        Ok(id)
    }

    pub fn slash_verifier(
        &mut self,
        verifier_id: &str,
        reason: SlashingReason,
        amount_piconero: u128,
        height: u64,
    ) -> Result<String> {
        if amount_piconero == 0 {
            return Err("slash amount_piconero must be positive".to_string());
        }
        let profile = self
            .verifier_profiles
            .get_mut(verifier_id)
            .ok_or_else(|| "slash verifier is missing".to_string())?;
        if amount_piconero > profile.stake_bond_piconero {
            return Err("slash amount exceeds verifier stake bond".to_string());
        }
        profile.stake_bond_piconero -= amount_piconero;
        profile.status = VerifierProfileStatus::Slashed;
        self.active_verifier_ids.remove(verifier_id);
        self.slashed_verifier_ids.insert(verifier_id.to_string());
        let report = PerformanceReport {
            report_id: performance_report_id(
                verifier_id,
                height / self.config.performance_epoch_blocks,
                height,
                self.performance_reports.len() as u64,
            ),
            verifier_id: verifier_id.to_string(),
            epoch: height / self.config.performance_epoch_blocks,
            jobs_assigned: 0,
            jobs_settled: 0,
            jobs_missed: 0,
            median_latency_ms: 0,
            p95_latency_ms: 0,
            invalid_proof_count: if reason == SlashingReason::InvalidProof {
                1
            } else {
                0
            },
            availability_bps: 0,
            slash_reason: Some(reason),
            slash_amount_piconero: amount_piconero,
            oracle_signature_root: payload_root(
                "PQ-ROLLUP-MARKET-SLASH-ORACLE",
                &json!({"verifier_id": verifier_id, "reason": reason.as_str()}),
            ),
            reported_at_height: height,
        };
        let id = report.report_id.clone();
        let payload = report.public_record();
        self.performance_reports.insert(id.clone(), report);
        self.emit_event(EventKind::VerifierSlashed, verifier_id, &payload)?;
        Ok(id)
    }

    pub fn public_record_for_subject(&self, subject_id: &str) -> Option<Value> {
        self.verifier_profiles
            .get(subject_id)
            .map(VerifierProfile::public_record)
            .or_else(|| {
                self.verifier_bids
                    .get(subject_id)
                    .map(VerifierBid::public_record)
            })
            .or_else(|| {
                self.proof_cache_inventory
                    .get(subject_id)
                    .map(ProofCacheInventoryItem::public_record)
            })
            .or_else(|| {
                self.recursive_jobs
                    .get(subject_id)
                    .map(RecursiveProofJob::public_record)
            })
            .or_else(|| {
                self.challenge_escrows
                    .get(subject_id)
                    .map(ChallengeEscrow::public_record)
            })
            .or_else(|| {
                self.sponsor_reservations
                    .get(subject_id)
                    .map(FeeSponsorReservation::public_record)
            })
            .or_else(|| {
                self.settlement_receipts
                    .get(subject_id)
                    .map(SettlementReceipt::public_record)
            })
            .or_else(|| {
                self.performance_reports
                    .get(subject_id)
                    .map(PerformanceReport::public_record)
            })
            .or_else(|| {
                self.schedule_slots
                    .get(subject_id)
                    .map(ScheduleSlot::public_record)
            })
            .or_else(|| self.events.get(subject_id).map(RuntimeEvent::public_record))
    }

    fn emit_event(
        &mut self,
        event_kind: EventKind,
        subject_id: &str,
        payload: &Value,
    ) -> Result<()> {
        ensure_capacity("events", self.events.len(), MAX_EVENTS)?;
        let payload_root = public_record_root(payload);
        let sequence = self.events.len() as u64;
        let event_id = event_id(
            event_kind,
            subject_id,
            &payload_root,
            self.config.devnet_height + sequence,
            sequence,
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind,
            subject_id: subject_id.to_string(),
            payload_root,
            state_root_after: state_root_from_record(&json!({
                "roots": self.roots().public_record(),
                "sequence": sequence,
            })),
            height: self.config.devnet_height + sequence,
            sequence,
        };
        event.validate()?;
        self.events.insert(event_id, event);
        Ok(())
    }
}

pub fn verifier_id(operator_label: &str, region_label: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-VERIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(region_label),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn bid_id(
    verifier_id: &str,
    circuit_kind: RollupCircuitKind,
    market_lane: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(verifier_id),
            HashPart::Str(circuit_kind.as_str()),
            HashPart::Str(market_lane),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn cache_item_id(
    verifier_id: &str,
    circuit_kind: RollupCircuitKind,
    verifier_key_label: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-CACHE-ITEM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(verifier_id),
            HashPart::Str(circuit_kind.as_str()),
            HashPart::Str(verifier_key_label),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn recursive_job_id(requester: &str, batch_label: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-RECURSIVE-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(requester),
            HashPart::Str(batch_label),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn challenge_escrow_id(
    challenger: &str,
    verifier_id: &str,
    job_id: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenger),
            HashPart::Str(verifier_id),
            HashPart::Str(job_id),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_label: &str,
    job_id: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(job_id),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    job_id: &str,
    verifier_id: &str,
    proof_label: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(verifier_id),
            HashPart::Str(proof_label),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn performance_report_id(verifier_id: &str, epoch: u64, height: u64, sequence: u64) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-PERFORMANCE-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(verifier_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn schedule_slot_id(job_id: &str, bid_id: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-SCHEDULE-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(bid_id),
            HashPart::U64(height),
            HashPart::U64(sequence),
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
        "PQ-ROLLUP-MARKET-EVENT-ID",
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

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-PUBLIC-RECORD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn config_root(config: &Config) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-CONFIG-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&config.public_record()),
        ],
        32,
    )
}

pub fn commitment(domain: &str, value: &str) -> String {
    domain_hash(
        "PQ-ROLLUP-MARKET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn scheduling_score(job: &RecursiveProofJob, bid: &VerifierBid, height: u64) -> u128 {
    let fee_pressure = job
        .max_fee_piconero
        .saturating_add(job.priority_fee_piconero);
    let latency_discount = u128::from(bid.latency_target_ms.max(1));
    let age_bonus = u128::from(height.saturating_sub(job.queued_at_height) + 1);
    fee_pressure
        .saturating_mul(age_bonus)
        .saturating_mul(u128::from(job.batch_item_count as u64))
        / latency_discount
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
