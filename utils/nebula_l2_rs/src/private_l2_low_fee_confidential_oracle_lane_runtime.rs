use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeeConfidentialOracleLaneRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_CONFIDENTIAL_ORACLE_LANE_RUNTIME_PROTOCOL_VERSION: &str =
    "private-l2-low-fee-confidential-oracle-lane-runtime-v1";
const CHAIN_ID: &str = "nebula-l2-devnet";
const MAX_BPS: u64 = 10_000;
const MAX_FEEDS: usize = 4096;
const MAX_UPDATES_PER_BATCH: usize = 128;
const MAX_ATTESTERS_PER_BATCH: usize = 64;
const MAX_EVENTS: usize = 8192;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum OracleLane {
    Spot,
    Twap,
    Volatility,
    Funding,
    Risk,
    Emergency,
}

impl OracleLane {
    pub fn as_str(self) -> &'static str {
        match self {
            OracleLane::Spot => "spot",
            OracleLane::Twap => "twap",
            OracleLane::Volatility => "volatility",
            OracleLane::Funding => "funding",
            OracleLane::Risk => "risk",
            OracleLane::Emergency => "emergency",
        }
    }

    pub fn target_latency_ms(self) -> u64 {
        match self {
            OracleLane::Spot => 300,
            OracleLane::Twap => 500,
            OracleLane::Volatility => 750,
            OracleLane::Funding => 600,
            OracleLane::Risk => 400,
            OracleLane::Emergency => 150,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeedKind {
    Price,
    Reserve,
    InterestRate,
    FundingRate,
    LiquidityDepth,
    RiskCircuit,
}

impl FeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FeedKind::Price => "price",
            FeedKind::Reserve => "reserve",
            FeedKind::InterestRate => "interest_rate",
            FeedKind::FundingRate => "funding_rate",
            FeedKind::LiquidityDepth => "liquidity_depth",
            FeedKind::RiskCircuit => "risk_circuit",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeedStatus {
    Pending,
    Active,
    Paused,
    Retired,
}

impl FeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FeedStatus::Pending => "pending",
            FeedStatus::Active => "active",
            FeedStatus::Paused => "paused",
            FeedStatus::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdateStatus {
    Queued,
    Batched,
    Rejected,
}

impl UpdateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            UpdateStatus::Queued => "queued",
            UpdateStatus::Batched => "batched",
            UpdateStatus::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum BatchStatus {
    Open,
    Attested,
    Settled,
    Disputed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            BatchStatus::Open => "open",
            BatchStatus::Attested => "attested",
            BatchStatus::Settled => "settled",
            BatchStatus::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestationVerdict {
    Valid,
    Stale,
    Manipulated,
    InsufficientSources,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            AttestationVerdict::Valid => "valid",
            AttestationVerdict::Stale => "stale",
            AttestationVerdict::Manipulated => "manipulated",
            AttestationVerdict::InsufficientSources => "insufficient_sources",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SponsorStatus {
    Reserved,
    Applied,
    Refunded,
    Slashed,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SponsorStatus::Reserved => "reserved",
            SponsorStatus::Applied => "applied",
            SponsorStatus::Refunded => "refunded",
            SponsorStatus::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReceiptKind {
    FastOracleInclusion,
    DefiSettlement,
    CircuitBreaker,
    MoneroAnchor,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptKind::FastOracleInclusion => "fast_oracle_inclusion",
            ReceiptKind::DefiSettlement => "defi_settlement",
            ReceiptKind::CircuitBreaker => "circuit_breaker",
            ReceiptKind::MoneroAnchor => "monero_anchor",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RebateStatus {
    Queued,
    Paid,
    Cancelled,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RebateStatus::Queued => "queued",
            RebateStatus::Paid => "paid",
            RebateStatus::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FenceKind {
    NullifierReplay,
    FeedPublisher,
    BatchAttester,
    EmergencyPause,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FenceKind::NullifierReplay => "nullifier_replay",
            FenceKind::FeedPublisher => "feed_publisher",
            FenceKind::BatchAttester => "batch_attester",
            FenceKind::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeEventKind {
    FeedRegistered,
    UpdateSubmitted,
    BatchBuilt,
    SponsorReserved,
    BatchAttested,
    ReceiptPublished,
    RebateQueued,
    PrivacyFenceOpened,
}

impl RuntimeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeEventKind::FeedRegistered => "feed_registered",
            RuntimeEventKind::UpdateSubmitted => "update_submitted",
            RuntimeEventKind::BatchBuilt => "batch_built",
            RuntimeEventKind::SponsorReserved => "sponsor_reserved",
            RuntimeEventKind::BatchAttested => "batch_attested",
            RuntimeEventKind::ReceiptPublished => "receipt_published",
            RuntimeEventKind::RebateQueued => "rebate_queued",
            RuntimeEventKind::PrivacyFenceOpened => "privacy_fence_opened",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub runtime_version: String,
    pub max_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub min_source_count: u64,
    pub max_update_age_ms: u64,
    pub max_updates_per_batch: usize,
    pub max_attesters_per_batch: usize,
    pub pq_attestation_scheme_root: String,
    pub emergency_lane_enabled: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            runtime_version: PRIVATE_L2_LOW_FEE_CONFIDENTIAL_ORACLE_LANE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            max_fee_bps: 60,
            low_fee_rebate_bps: 2800,
            min_source_count: 5,
            max_update_age_ms: 2_000,
            max_updates_per_batch: 64,
            max_attesters_per_batch: 32,
            pq_attestation_scheme_root: commitment("oracle lane ML-DSA aggregate attestation"),
            emergency_lane_enabled: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        require_non_empty("runtime_version", &self.runtime_version)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.min_source_count == 0 {
            return Err("min_source_count must be non-zero".to_string());
        }
        if self.max_update_age_ms == 0 {
            return Err("max_update_age_ms must be non-zero".to_string());
        }
        if self.max_updates_per_batch == 0 || self.max_updates_per_batch > MAX_UPDATES_PER_BATCH {
            return Err(format!(
                "max_updates_per_batch must be between 1 and {MAX_UPDATES_PER_BATCH}"
            ));
        }
        if self.max_attesters_per_batch == 0
            || self.max_attesters_per_batch > MAX_ATTESTERS_PER_BATCH
        {
            return Err(format!(
                "max_attesters_per_batch must be between 1 and {MAX_ATTESTERS_PER_BATCH}"
            ));
        }
        require_root(
            "pq_attestation_scheme_root",
            &self.pq_attestation_scheme_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "runtime_version": self.runtime_version,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_source_count": self.min_source_count,
            "max_update_age_ms": self.max_update_age_ms,
            "max_updates_per_batch": self.max_updates_per_batch,
            "max_attesters_per_batch": self.max_attesters_per_batch,
            "pq_attestation_scheme_root": self.pq_attestation_scheme_root,
            "emergency_lane_enabled": self.emergency_lane_enabled,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub feeds: u64,
    pub updates: u64,
    pub batches: u64,
    pub sponsor_reservations: u64,
    pub attestations: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub runtime_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "feeds": self.feeds,
            "updates": self.updates,
            "batches": self.batches,
            "sponsor_reservations": self.sponsor_reservations,
            "attestations": self.attestations,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "privacy_fences": self.privacy_fences,
            "runtime_events": self.runtime_events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub feeds_root: String,
    pub updates_root: String,
    pub batches_root: String,
    pub sponsor_reservations_root: String,
    pub attestations_root: String,
    pub receipts_root: String,
    pub rebates_root: String,
    pub privacy_fences_root: String,
    pub spent_nullifiers_root: String,
    pub runtime_events_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            feeds_root: empty_root("FEEDS"),
            updates_root: empty_root("UPDATES"),
            batches_root: empty_root("BATCHES"),
            sponsor_reservations_root: empty_root("SPONSOR-RESERVATIONS"),
            attestations_root: empty_root("ATTESTATIONS"),
            receipts_root: empty_root("RECEIPTS"),
            rebates_root: empty_root("REBATES"),
            privacy_fences_root: empty_root("PRIVACY-FENCES"),
            spent_nullifiers_root: empty_root("SPENT-NULLIFIERS"),
            runtime_events_root: empty_root("RUNTIME-EVENTS"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feeds_root": self.feeds_root,
            "updates_root": self.updates_root,
            "batches_root": self.batches_root,
            "sponsor_reservations_root": self.sponsor_reservations_root,
            "attestations_root": self.attestations_root,
            "receipts_root": self.receipts_root,
            "rebates_root": self.rebates_root,
            "privacy_fences_root": self.privacy_fences_root,
            "spent_nullifiers_root": self.spent_nullifiers_root,
            "runtime_events_root": self.runtime_events_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterFeedRequest {
    pub lane: OracleLane,
    pub feed_kind: FeedKind,
    pub feed_label: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub publisher_set_root: String,
    pub source_policy_root: String,
    pub fee_limit_bps: u64,
    pub registered_at_height: u64,
}

impl RegisterFeedRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("feed_label", &self.feed_label)?;
        require_root("base_asset_commitment", &self.base_asset_commitment)?;
        require_root("quote_asset_commitment", &self.quote_asset_commitment)?;
        require_root("publisher_set_root", &self.publisher_set_root)?;
        require_root("source_policy_root", &self.source_policy_root)?;
        require_bps("fee_limit_bps", self.fee_limit_bps)?;
        if self.fee_limit_bps > config.max_fee_bps {
            return Err("feed fee_limit_bps exceeds runtime fee cap".to_string());
        }
        if self.lane == OracleLane::Emergency && !config.emergency_lane_enabled {
            return Err("emergency oracle lane disabled".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeedRecord {
    pub feed_id: String,
    pub lane: OracleLane,
    pub feed_kind: FeedKind,
    pub feed_label: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub publisher_set_root: String,
    pub source_policy_root: String,
    pub fee_limit_bps: u64,
    pub registered_at_height: u64,
    pub latest_update_id: Option<String>,
    pub status: FeedStatus,
}

impl FeedRecord {
    pub fn from_request(request: RegisterFeedRequest, config: &Config) -> Result<Self> {
        request.validate(config)?;
        let feed_id = feed_id(&request);
        Ok(Self {
            feed_id,
            lane: request.lane,
            feed_kind: request.feed_kind,
            feed_label: request.feed_label,
            base_asset_commitment: request.base_asset_commitment,
            quote_asset_commitment: request.quote_asset_commitment,
            publisher_set_root: request.publisher_set_root,
            source_policy_root: request.source_policy_root,
            fee_limit_bps: request.fee_limit_bps,
            registered_at_height: request.registered_at_height,
            latest_update_id: None,
            status: FeedStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feed_id": self.feed_id,
            "lane": self.lane.as_str(),
            "feed_kind": self.feed_kind.as_str(),
            "feed_label": self.feed_label,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "publisher_set_root": self.publisher_set_root,
            "source_policy_root": self.source_policy_root,
            "fee_limit_bps": self.fee_limit_bps,
            "registered_at_height": self.registered_at_height,
            "latest_update_id": self.latest_update_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitEncryptedUpdateRequest {
    pub feed_id: String,
    pub publisher_commitment: String,
    pub encrypted_value_root: String,
    pub source_set_root: String,
    pub confidence_interval_root: String,
    pub source_count: u64,
    pub observed_at_ms: u64,
    pub submitted_at_height: u64,
    pub fee_bid_bps: u64,
    pub nullifier_root: String,
}

impl SubmitEncryptedUpdateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("feed_id", &self.feed_id)?;
        require_root("publisher_commitment", &self.publisher_commitment)?;
        require_root("encrypted_value_root", &self.encrypted_value_root)?;
        require_root("source_set_root", &self.source_set_root)?;
        require_root("confidence_interval_root", &self.confidence_interval_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_bps("fee_bid_bps", self.fee_bid_bps)?;
        if self.source_count < config.min_source_count {
            return Err("source_count below configured minimum".to_string());
        }
        if self.fee_bid_bps > config.max_fee_bps {
            return Err("fee_bid_bps exceeds runtime fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedOracleUpdate {
    pub update_id: String,
    pub feed_id: String,
    pub publisher_commitment: String,
    pub encrypted_value_root: String,
    pub source_set_root: String,
    pub confidence_interval_root: String,
    pub source_count: u64,
    pub observed_at_ms: u64,
    pub submitted_at_height: u64,
    pub fee_bid_bps: u64,
    pub nullifier_root: String,
    pub status: UpdateStatus,
}

impl EncryptedOracleUpdate {
    pub fn from_request(
        request: SubmitEncryptedUpdateRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let update_id = update_id(&request, sequence);
        Ok(Self {
            update_id,
            feed_id: request.feed_id,
            publisher_commitment: request.publisher_commitment,
            encrypted_value_root: request.encrypted_value_root,
            source_set_root: request.source_set_root,
            confidence_interval_root: request.confidence_interval_root,
            source_count: request.source_count,
            observed_at_ms: request.observed_at_ms,
            submitted_at_height: request.submitted_at_height,
            fee_bid_bps: request.fee_bid_bps,
            nullifier_root: request.nullifier_root,
            status: UpdateStatus::Queued,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "update_id": self.update_id,
            "feed_id": self.feed_id,
            "publisher_commitment": self.publisher_commitment,
            "encrypted_value_root": self.encrypted_value_root,
            "source_set_root": self.source_set_root,
            "confidence_interval_root": self.confidence_interval_root,
            "source_count": self.source_count,
            "observed_at_ms": self.observed_at_ms,
            "submitted_at_height": self.submitted_at_height,
            "fee_bid_bps": self.fee_bid_bps,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildBatchRequest {
    pub lane: OracleLane,
    pub update_ids: Vec<String>,
    pub batch_policy_root: String,
    pub target_contract_root: String,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildBatchRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.update_ids.is_empty() {
            return Err("update_ids must not be empty".to_string());
        }
        if self.update_ids.len() > config.max_updates_per_batch {
            return Err("update_ids exceeds max_updates_per_batch".to_string());
        }
        require_root("batch_policy_root", &self.batch_policy_root)?;
        require_root("target_contract_root", &self.target_contract_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("batch max_fee_bps exceeds runtime fee cap".to_string());
        }
        if self.lane == OracleLane::Emergency && !config.emergency_lane_enabled {
            return Err("emergency oracle lane disabled".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleUpdateBatch {
    pub batch_id: String,
    pub lane: OracleLane,
    pub update_ids: Vec<String>,
    pub update_set_root: String,
    pub batch_policy_root: String,
    pub target_contract_root: String,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
    pub sponsor_reservation_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub status: BatchStatus,
}

impl OracleUpdateBatch {
    pub fn from_request(
        request: BuildBatchRequest,
        update_set_root: String,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let batch_id = batch_id(&request, &update_set_root, sequence);
        Ok(Self {
            batch_id,
            lane: request.lane,
            update_ids: request.update_ids,
            update_set_root,
            batch_policy_root: request.batch_policy_root,
            target_contract_root: request.target_contract_root,
            max_fee_bps: request.max_fee_bps,
            built_at_height: request.built_at_height,
            sponsor_reservation_ids: Vec::new(),
            attestation_ids: Vec::new(),
            receipt_ids: Vec::new(),
            status: BatchStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "update_ids": self.update_ids,
            "update_set_root": self.update_set_root,
            "batch_policy_root": self.batch_policy_root,
            "target_contract_root": self.target_contract_root,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "attestation_ids": self.attestation_ids,
            "receipt_ids": self.receipt_ids,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReserveSponsorRequest {
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
}

impl ReserveSponsorRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("sponsor_commitment", &self.sponsor_commitment)?;
        require_root("fee_note_root", &self.fee_note_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_fee_bps {
            return Err("sponsor max_fee_bps exceeds runtime fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub fee_note_root: String,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
    pub status: SponsorStatus,
}

impl SponsorReservation {
    pub fn from_request(
        request: ReserveSponsorRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let reservation_id = sponsor_reservation_id(&request, sequence);
        Ok(Self {
            reservation_id,
            batch_id: request.batch_id,
            sponsor_commitment: request.sponsor_commitment,
            fee_note_root: request.fee_note_root,
            max_fee_bps: request.max_fee_bps,
            expires_at_height: request.expires_at_height,
            nullifier_root: request.nullifier_root,
            status: SponsorStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_note_root": self.fee_note_root,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestBatchRequest {
    pub batch_id: String,
    pub attester_commitment: String,
    pub pq_signature_root: String,
    pub decrypted_value_root: String,
    pub source_audit_root: String,
    pub verdict: AttestationVerdict,
    pub attested_at_height: u64,
    pub nullifier_root: String,
}

impl AttestBatchRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("attester_commitment", &self.attester_commitment)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_root("decrypted_value_root", &self.decrypted_value_root)?;
        require_root("source_audit_root", &self.source_audit_root)?;
        require_root("nullifier_root", &self.nullifier_root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub attester_commitment: String,
    pub pq_signature_root: String,
    pub decrypted_value_root: String,
    pub source_audit_root: String,
    pub verdict: AttestationVerdict,
    pub attested_at_height: u64,
    pub nullifier_root: String,
}

impl BatchAttestation {
    pub fn from_request(request: AttestBatchRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let attestation_id = attestation_id(&request, sequence);
        Ok(Self {
            attestation_id,
            batch_id: request.batch_id,
            attester_commitment: request.attester_commitment,
            pq_signature_root: request.pq_signature_root,
            decrypted_value_root: request.decrypted_value_root,
            source_audit_root: request.source_audit_root,
            verdict: request.verdict,
            attested_at_height: request.attested_at_height,
            nullifier_root: request.nullifier_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "attester_commitment": self.attester_commitment,
            "pq_signature_root": self.pq_signature_root,
            "decrypted_value_root": self.decrypted_value_root,
            "source_audit_root": self.source_audit_root,
            "verdict": self.verdict.as_str(),
            "attested_at_height": self.attested_at_height,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishReceiptRequest {
    pub batch_id: String,
    pub receipt_kind: ReceiptKind,
    pub attestation_root: String,
    pub target_state_root: String,
    pub settlement_root: String,
    pub fee_charged_bps: u64,
    pub settled_at_height: u64,
}

impl PublishReceiptRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("attestation_root", &self.attestation_root)?;
        require_root("target_state_root", &self.target_state_root)?;
        require_root("settlement_root", &self.settlement_root)?;
        require_bps("fee_charged_bps", self.fee_charged_bps)?;
        if self.fee_charged_bps > config.max_fee_bps {
            return Err("fee_charged_bps exceeds runtime fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub receipt_kind: ReceiptKind,
    pub attestation_root: String,
    pub target_state_root: String,
    pub settlement_root: String,
    pub fee_charged_bps: u64,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn from_request(
        request: PublishReceiptRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let receipt_id = settlement_receipt_id(&request, sequence);
        Ok(Self {
            receipt_id,
            batch_id: request.batch_id,
            receipt_kind: request.receipt_kind,
            attestation_root: request.attestation_root,
            target_state_root: request.target_state_root,
            settlement_root: request.settlement_root,
            fee_charged_bps: request.fee_charged_bps,
            settled_at_height: request.settled_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "attestation_root": self.attestation_root,
            "target_state_root": self.target_state_root,
            "settlement_root": self.settlement_root,
            "fee_charged_bps": self.fee_charged_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssueRebateRequest {
    pub batch_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
}

impl IssueRebateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_root("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_root("rebate_note_root", &self.rebate_note_root)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        if self.rebate_bps > config.low_fee_rebate_bps {
            return Err("rebate_bps exceeds configured rebate cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub status: RebateStatus,
}

impl FeeRebate {
    pub fn from_request(
        request: IssueRebateRequest,
        sequence: u64,
        config: &Config,
    ) -> Result<Self> {
        request.validate(config)?;
        let rebate_id = rebate_id(&request, sequence);
        Ok(Self {
            rebate_id,
            batch_id: request.batch_id,
            receipt_id: request.receipt_id,
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_note_root: request.rebate_note_root,
            rebate_bps: request.rebate_bps,
            status: RebateStatus::Queued,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenPrivacyFenceRequest {
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub nullifier_root: String,
    pub effective_height: u64,
}

impl OpenPrivacyFenceRequest {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("commitment_root", &self.commitment_root)?;
        require_non_empty("replay_domain", &self.replay_domain)?;
        require_root("nullifier_root", &self.nullifier_root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub fence_kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub nullifier_root: String,
    pub effective_height: u64,
}

impl PrivacyFence {
    pub fn from_request(request: OpenPrivacyFenceRequest, sequence: u64) -> Result<Self> {
        request.validate()?;
        let fence_id = privacy_fence_id(&request, sequence);
        Ok(Self {
            fence_id,
            fence_kind: request.fence_kind,
            subject_id: request.subject_id,
            commitment_root: request.commitment_root,
            replay_domain: request.replay_domain,
            nullifier_root: request.nullifier_root,
            effective_height: request.effective_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "replay_domain": self.replay_domain,
            "nullifier_root": self.nullifier_root,
            "effective_height": self.effective_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: RuntimeEventKind,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn new(
        event_kind: RuntimeEventKind,
        subject_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> Self {
        let payload_root = payload_root("RUNTIME-EVENT", payload);
        Self {
            event_id: runtime_event_id(event_kind, subject_id, &payload_root, height, sequence),
            event_kind,
            subject_id: subject_id.to_string(),
            payload_root,
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub feeds: BTreeMap<String, FeedRecord>,
    pub updates: BTreeMap<String, EncryptedOracleUpdate>,
    pub batches: BTreeMap<String, OracleUpdateBatch>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub attestations: BTreeMap<String, BatchAttestation>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub spent_nullifiers: BTreeSet<String>,
    pub runtime_events: Vec<RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            feeds: BTreeMap::new(),
            updates: BTreeMap::new(),
            batches: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            attestations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            runtime_events: Vec::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config must validate");
        let feed = state
            .register_feed(RegisterFeedRequest {
                lane: OracleLane::Spot,
                feed_kind: FeedKind::Price,
                feed_label: "private-xmr-usd".to_string(),
                base_asset_commitment: commitment("xmr asset"),
                quote_asset_commitment: commitment("usd stable asset"),
                publisher_set_root: commitment("oracle publisher set"),
                source_policy_root: commitment("min five source policy"),
                fee_limit_bps: 12,
                registered_at_height: 1,
            })
            .expect("devnet feed must register");
        let update_a = state
            .submit_update(SubmitEncryptedUpdateRequest {
                feed_id: feed.feed_id.clone(),
                publisher_commitment: commitment("publisher a"),
                encrypted_value_root: commitment("encrypted xmr usd price a"),
                source_set_root: commitment("source set a"),
                confidence_interval_root: commitment("confidence interval a"),
                source_count: 7,
                observed_at_ms: 1_000,
                submitted_at_height: 4,
                fee_bid_bps: 9,
                nullifier_root: commitment("update a nullifier"),
            })
            .expect("devnet update a must submit");
        let update_b = state
            .submit_update(SubmitEncryptedUpdateRequest {
                feed_id: feed.feed_id.clone(),
                publisher_commitment: commitment("publisher b"),
                encrypted_value_root: commitment("encrypted xmr usd price b"),
                source_set_root: commitment("source set b"),
                confidence_interval_root: commitment("confidence interval b"),
                source_count: 8,
                observed_at_ms: 1_050,
                submitted_at_height: 4,
                fee_bid_bps: 8,
                nullifier_root: commitment("update b nullifier"),
            })
            .expect("devnet update b must submit");
        let batch = state
            .build_batch(BuildBatchRequest {
                lane: OracleLane::Spot,
                update_ids: vec![update_a.update_id.clone(), update_b.update_id.clone()],
                batch_policy_root: commitment("batch median policy"),
                target_contract_root: commitment("defi contracts reading xmr usd"),
                max_fee_bps: 12,
                built_at_height: 5,
            })
            .expect("devnet batch must build");
        let reservation = state
            .reserve_sponsor(ReserveSponsorRequest {
                batch_id: batch.batch_id.clone(),
                sponsor_commitment: commitment("oracle sponsor"),
                fee_note_root: commitment("oracle sponsor fee note"),
                max_fee_bps: 12,
                expires_at_height: 16,
                nullifier_root: commitment("oracle sponsor nullifier"),
            })
            .expect("devnet sponsor must reserve");
        let attestation = state
            .attest_batch(AttestBatchRequest {
                batch_id: batch.batch_id.clone(),
                attester_commitment: commitment("pq oracle attester"),
                pq_signature_root: commitment("oracle pq signature"),
                decrypted_value_root: commitment("batched decrypted oracle values"),
                source_audit_root: commitment("source audit"),
                verdict: AttestationVerdict::Valid,
                attested_at_height: 6,
                nullifier_root: commitment("oracle attestation nullifier"),
            })
            .expect("devnet attestation must record");
        let receipt = state
            .publish_receipt(PublishReceiptRequest {
                batch_id: batch.batch_id.clone(),
                receipt_kind: ReceiptKind::DefiSettlement,
                attestation_root: attestation.pq_signature_root.clone(),
                target_state_root: commitment("updated defi oracle state"),
                settlement_root: commitment("oracle settlement"),
                fee_charged_bps: 8,
                settled_at_height: 7,
            })
            .expect("devnet receipt must publish");
        let _rebate = state
            .issue_rebate(IssueRebateRequest {
                batch_id: batch.batch_id.clone(),
                receipt_id: receipt.receipt_id.clone(),
                beneficiary_commitment: reservation.sponsor_commitment.clone(),
                rebate_note_root: commitment("oracle fee rebate"),
                rebate_bps: 600,
            })
            .expect("devnet rebate must queue");
        let _fence = state
            .open_privacy_fence(OpenPrivacyFenceRequest {
                fence_kind: FenceKind::NullifierReplay,
                subject_id: batch.batch_id.clone(),
                commitment_root: commitment("oracle batch replay fence"),
                replay_domain: "devnet-oracle-lane".to_string(),
                nullifier_root: commitment("oracle fence nullifier"),
                effective_height: 7,
            })
            .expect("devnet fence must open");
        state
    }

    pub fn register_feed(&mut self, request: RegisterFeedRequest) -> Result<FeedRecord> {
        self.ensure_feed_capacity()?;
        let feed = FeedRecord::from_request(request, &self.config)?;
        if self.feeds.contains_key(&feed.feed_id) {
            return Err("feed already registered".to_string());
        }
        self.counters.feeds = self.counters.feeds.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::FeedRegistered,
            &feed.feed_id,
            &feed.public_record(),
            feed.registered_at_height,
        );
        self.feeds.insert(feed.feed_id.clone(), feed.clone());
        self.recompute_roots();
        Ok(feed)
    }

    pub fn submit_update(
        &mut self,
        request: SubmitEncryptedUpdateRequest,
    ) -> Result<EncryptedOracleUpdate> {
        request.validate(&self.config)?;
        self.ensure_feed_active(&request.feed_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let update = EncryptedOracleUpdate::from_request(
            request,
            self.counters.updates.saturating_add(1),
            &self.config,
        )?;
        if let Some(feed) = self.feeds.get_mut(&update.feed_id) {
            feed.latest_update_id = Some(update.update_id.clone());
        }
        self.counters.updates = self.counters.updates.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::UpdateSubmitted,
            &update.update_id,
            &update.public_record(),
            update.submitted_at_height,
        );
        self.updates
            .insert(update.update_id.clone(), update.clone());
        self.recompute_roots();
        Ok(update)
    }

    pub fn build_batch(&mut self, request: BuildBatchRequest) -> Result<OracleUpdateBatch> {
        request.validate(&self.config)?;
        for update_id in &request.update_ids {
            let update = self
                .updates
                .get(update_id)
                .ok_or_else(|| format!("update {update_id} missing"))?;
            if update.status != UpdateStatus::Queued {
                return Err(format!("update {update_id} is not queued"));
            }
        }
        let update_records = request
            .update_ids
            .iter()
            .filter_map(|id| self.updates.get(id))
            .map(EncryptedOracleUpdate::public_record)
            .collect::<Vec<_>>();
        let update_set_root = public_record_root("BATCH-UPDATE-SET", &update_records);
        let batch = OracleUpdateBatch::from_request(
            request,
            update_set_root,
            self.counters.batches.saturating_add(1),
            &self.config,
        )?;
        for update_id in &batch.update_ids {
            if let Some(update) = self.updates.get_mut(update_id) {
                update.status = UpdateStatus::Batched;
            }
        }
        self.counters.batches = self.counters.batches.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::BatchBuilt,
            &batch.batch_id,
            &batch.public_record(),
            batch.built_at_height,
        );
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        self.recompute_roots();
        Ok(batch)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveSponsorRequest,
    ) -> Result<SponsorReservation> {
        request.validate(&self.config)?;
        self.ensure_batch_exists(&request.batch_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let reservation = SponsorReservation::from_request(
            request,
            self.counters.sponsor_reservations.saturating_add(1),
            &self.config,
        )?;
        if let Some(batch) = self.batches.get_mut(&reservation.batch_id) {
            batch
                .sponsor_reservation_ids
                .push(reservation.reservation_id.clone());
        }
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::SponsorReserved,
            &reservation.reservation_id,
            &reservation.public_record(),
            reservation.expires_at_height,
        );
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.recompute_roots();
        Ok(reservation)
    }

    pub fn attest_batch(&mut self, request: AttestBatchRequest) -> Result<BatchAttestation> {
        request.validate()?;
        self.ensure_batch_open(&request.batch_id)?;
        self.spend_nullifier(&request.nullifier_root)?;
        let batch_id = request.batch_id.clone();
        let attestation =
            BatchAttestation::from_request(request, self.counters.attestations.saturating_add(1))?;
        let batch = self
            .batches
            .get_mut(&batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        if batch.attestation_ids.len() >= self.config.max_attesters_per_batch {
            return Err("batch attester cap reached".to_string());
        }
        batch
            .attestation_ids
            .push(attestation.attestation_id.clone());
        if attestation.verdict == AttestationVerdict::Valid {
            batch.status = BatchStatus::Attested;
        } else {
            batch.status = BatchStatus::Disputed;
        }
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::BatchAttested,
            &attestation.attestation_id,
            &attestation.public_record(),
            attestation.attested_at_height,
        );
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.recompute_roots();
        Ok(attestation)
    }

    pub fn publish_receipt(&mut self, request: PublishReceiptRequest) -> Result<SettlementReceipt> {
        request.validate(&self.config)?;
        self.ensure_batch_exists(&request.batch_id)?;
        let receipt = SettlementReceipt::from_request(
            request,
            self.counters.receipts.saturating_add(1),
            &self.config,
        )?;
        let batch = self
            .batches
            .get_mut(&receipt.batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        if !matches!(batch.status, BatchStatus::Open | BatchStatus::Attested) {
            return Err("batch not settleable".to_string());
        }
        batch.status = BatchStatus::Settled;
        batch.receipt_ids.push(receipt.receipt_id.clone());
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::ReceiptPublished,
            &receipt.receipt_id,
            &receipt.public_record(),
            receipt.settled_at_height,
        );
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<FeeRebate> {
        request.validate(&self.config)?;
        self.ensure_batch_exists(&request.batch_id)?;
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("receipt missing for rebate".to_string());
        }
        let rebate = FeeRebate::from_request(
            request,
            self.counters.rebates.saturating_add(1),
            &self.config,
        )?;
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::RebateQueued,
            &rebate.rebate_id,
            &rebate.public_record(),
            0,
        );
        self.rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        self.recompute_roots();
        Ok(rebate)
    }

    pub fn open_privacy_fence(&mut self, request: OpenPrivacyFenceRequest) -> Result<PrivacyFence> {
        request.validate()?;
        self.spend_nullifier(&request.nullifier_root)?;
        let fence =
            PrivacyFence::from_request(request, self.counters.privacy_fences.saturating_add(1))?;
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.emit_event(
            RuntimeEventKind::PrivacyFenceOpened,
            &fence.fence_id,
            &fence.public_record(),
            fence.effective_height,
        );
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.recompute_roots();
        Ok(fence)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_LOW_FEE_CONFIDENTIAL_ORACLE_LANE_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_LOW_FEE_CONFIDENTIAL_ORACLE_LANE_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    fn ensure_feed_capacity(&self) -> Result<()> {
        if self.feeds.len() >= MAX_FEEDS {
            Err("feed capacity reached".to_string())
        } else {
            Ok(())
        }
    }

    fn ensure_feed_active(&self, feed_id: &str) -> Result<()> {
        let feed = self
            .feeds
            .get(feed_id)
            .ok_or_else(|| "feed missing".to_string())?;
        if feed.status == FeedStatus::Active {
            Ok(())
        } else {
            Err("feed is not active".to_string())
        }
    }

    fn ensure_batch_exists(&self, batch_id: &str) -> Result<()> {
        if self.batches.contains_key(batch_id) {
            Ok(())
        } else {
            Err("batch missing".to_string())
        }
    }

    fn ensure_batch_open(&self, batch_id: &str) -> Result<()> {
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| "batch missing".to_string())?;
        if batch.status == BatchStatus::Open {
            Ok(())
        } else {
            Err("batch is not open".to_string())
        }
    }

    fn spend_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        require_root("nullifier_root", nullifier_root)?;
        if self.spent_nullifiers.contains(nullifier_root) {
            Err("nullifier already spent".to_string())
        } else {
            self.spent_nullifiers.insert(nullifier_root.to_string());
            Ok(())
        }
    }

    fn emit_event(
        &mut self,
        event_kind: RuntimeEventKind,
        subject_id: &str,
        payload: &Value,
        height: u64,
    ) {
        let sequence = self.counters.runtime_events.saturating_add(1);
        let event = RuntimeEvent::new(event_kind, subject_id, payload, height, sequence);
        self.runtime_events.push(event);
        self.counters.runtime_events = sequence;
        if self.runtime_events.len() > MAX_EVENTS {
            let drain = self.runtime_events.len().saturating_sub(MAX_EVENTS);
            self.runtime_events.drain(0..drain);
        }
    }

    fn recompute_roots(&mut self) {
        self.roots = Roots {
            feeds_root: map_root("FEEDS", self.feeds.values().map(FeedRecord::public_record)),
            updates_root: map_root(
                "UPDATES",
                self.updates
                    .values()
                    .map(EncryptedOracleUpdate::public_record),
            ),
            batches_root: map_root(
                "BATCHES",
                self.batches.values().map(OracleUpdateBatch::public_record),
            ),
            sponsor_reservations_root: map_root(
                "SPONSOR-RESERVATIONS",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservation::public_record),
            ),
            attestations_root: map_root(
                "ATTESTATIONS",
                self.attestations
                    .values()
                    .map(BatchAttestation::public_record),
            ),
            receipts_root: map_root(
                "RECEIPTS",
                self.receipts.values().map(SettlementReceipt::public_record),
            ),
            rebates_root: map_root(
                "REBATES",
                self.rebates.values().map(FeeRebate::public_record),
            ),
            privacy_fences_root: map_root(
                "PRIVACY-FENCES",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record),
            ),
            spent_nullifiers_root: id_list_root(
                "SPENT-NULLIFIERS",
                &self.spent_nullifiers.iter().cloned().collect::<Vec<_>>(),
            ),
            runtime_events_root: map_root(
                "RUNTIME-EVENTS",
                self.runtime_events.iter().map(RuntimeEvent::public_record),
            ),
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_low_fee_confidential_oracle_lane_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_low_fee_confidential_oracle_lane_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn feed_id(request: &RegisterFeedRequest) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-FEED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(request.feed_kind.as_str()),
            HashPart::Str(&request.feed_label),
            HashPart::Str(&request.base_asset_commitment),
            HashPart::Str(&request.quote_asset_commitment),
            HashPart::Str(&request.source_policy_root),
        ],
        32,
    )
}

pub fn update_id(request: &SubmitEncryptedUpdateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-UPDATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.feed_id),
            HashPart::Str(&request.publisher_commitment),
            HashPart::Str(&request.encrypted_value_root),
            HashPart::Str(&request.source_set_root),
            HashPart::U64(request.observed_at_ms),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn batch_id(request: &BuildBatchRequest, update_set_root: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(update_set_root),
            HashPart::Str(&request.batch_policy_root),
            HashPart::Str(&request.target_contract_root),
            HashPart::U64(request.built_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_note_root),
            HashPart::U64(request.max_fee_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn attestation_id(request: &AttestBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.attester_commitment),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(&request.decrypted_value_root),
            HashPart::Str(request.verdict.as_str()),
            HashPart::U64(request.attested_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &PublishReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(request.receipt_kind.as_str()),
            HashPart::Str(&request.attestation_root),
            HashPart::Str(&request.target_state_root),
            HashPart::Str(&request.settlement_root),
            HashPart::U64(request.settled_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(request: &IssueRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.receipt_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_note_root),
            HashPart::U64(request.rebate_bps),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &OpenPrivacyFenceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.commitment_root),
            HashPart::Str(&request.replay_domain),
            HashPart::Str(&request.nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: RuntimeEventKind,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-RUNTIME-EVENT-ID",
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

pub fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(&format!("{domain}-ROOT"), record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-CONFIDENTIAL-ORACLE-{domain}"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

pub fn id_list_root(domain: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records = records.into_iter().collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn require_eq(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} must equal {expected}"))
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        Err(format!("{field} must be a commitment root"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}
