use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-blob-witness-prefetch-orchestrator-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-prefetch-attestation-v1";
pub const ENCRYPTED_WITNESS_SUITE: &str = "ML-KEM-1024+HPKE-XChaCha20Poly1305-witness-bundle-v1";
pub const BLOB_PRIVACY_SUITE: &str = "monero-ringct-viewkey-minimized-blob-lane-v1";
pub const PREFETCH_SCHEDULER_SUITE: &str = "deterministic-speed-weighted-prefetch-v1";
pub const PRECONFIRMATION_HINT_SUITE: &str = "operator-safe-pq-preconfirmation-hint-v1";
pub const LOW_FEE_SPONSORSHIP_SUITE: &str = "privacy-preserving-contract-fee-sponsor-v1";
pub const CONTRACT_EXECUTION_SUITE: &str = "confidential-l2-contract-witness-execution-v1";
pub const DEVNET_HEIGHT: u64 = 12_288;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_LANES: usize = 64;
pub const MAX_SHARDS: usize = 256;
pub const MAX_BUNDLES: usize = 16_384;
pub const MAX_ATTESTATIONS: usize = 65_536;
pub const MAX_HINTS: usize = 65_536;
pub const MAX_CACHE_ITEMS: usize = 32_768;
pub const MAX_SPONSORS: usize = 1_024;
pub const DEFAULT_FAST_WINDOW_MS: u64 = 420;
pub const DEFAULT_PREFETCH_LOOKAHEAD_BLOCKS: u64 = 6;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 4;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_MAX_PREFETCH_BYTES_PER_BLOCK: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_WITNESS_BYTES_PER_BUNDLE: u64 = 384 * 1024;
pub const DEFAULT_PRESSURE_SOFT_BPS: u64 = 6_500;
pub const DEFAULT_PRESSURE_HARD_BPS: u64 = 8_500;
pub const DEFAULT_BACKPRESSURE_BPS: u64 = 7_500;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_XMR: u64 = 500_000;
pub const DEFAULT_MIN_CONTRACT_GAS: u64 = 21_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    BlobFast,
    WitnessFast,
    ContractExecution,
    Settlement,
    PrivacyRefresh,
    Recovery,
    Maintenance,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobFast => "blob_fast",
            Self::WitnessFast => "witness_fast",
            Self::ContractExecution => "contract_execution",
            Self::Settlement => "settlement",
            Self::PrivacyRefresh => "privacy_refresh",
            Self::Recovery => "recovery",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::WitnessFast => 10_000,
            Self::BlobFast => 9_600,
            Self::ContractExecution => 9_000,
            Self::Settlement => 8_200,
            Self::Recovery => 7_400,
            Self::PrivacyRefresh => 6_200,
            Self::Maintenance => 3_500,
        }
    }

    pub fn contract_capable(self) -> bool {
        matches!(
            self,
            Self::ContractExecution | Self::WitnessFast | Self::BlobFast
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Active,
    Paused,
    Draining,
    Backpressured,
    Quarantined,
}

impl LaneStatus {
    pub fn accepts_new_work(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Backpressured => "backpressured",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Announced,
    Prefetched,
    DecryptedEnvelopeReady,
    Attested,
    Preconfirmed,
    Executed,
    Evicted,
    Expired,
    Rejected,
}

impl BundleStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::Prefetched
                | Self::DecryptedEnvelopeReady
                | Self::Attested
                | Self::Preconfirmed
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Prefetched => "prefetched",
            Self::DecryptedEnvelopeReady => "decrypted_envelope_ready",
            Self::Attested => "attested",
            Self::Preconfirmed => "preconfirmed",
            Self::Executed => "executed",
            Self::Evicted => "evicted",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureLevel {
    Cool,
    Warm,
    SoftLimit,
    HardLimit,
    Emergency,
}

impl PressureLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cool => "cool",
            Self::Warm => "warm",
            Self::SoftLimit => "soft_limit",
            Self::HardLimit => "hard_limit",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HintStatus {
    Draft,
    Published,
    Consumed,
    Expired,
    Revoked,
}

impl HintStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Draft | Self::Published)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheDecision {
    KeepHot,
    KeepWarm,
    DemoteCold,
    EvictExpired,
    EvictPressure,
    Quarantine,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Exhausted,
    Paused,
    Quarantined,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fast_window_ms: u64,
    pub prefetch_lookahead_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub cache_ttl_blocks: u64,
    pub max_prefetch_bytes_per_block: u64,
    pub max_witness_bytes_per_bundle: u64,
    pub pressure_soft_bps: u64,
    pub pressure_hard_bps: u64,
    pub backpressure_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub default_sponsor_budget_micro_xmr: u64,
    pub min_contract_gas: u64,
    pub allow_low_fee_sponsorship: bool,
    pub operator_summary_redaction: bool,
    pub deterministic_devnet: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            fast_window_ms: DEFAULT_FAST_WINDOW_MS,
            prefetch_lookahead_blocks: DEFAULT_PREFETCH_LOOKAHEAD_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            max_prefetch_bytes_per_block: DEFAULT_MAX_PREFETCH_BYTES_PER_BLOCK,
            max_witness_bytes_per_bundle: DEFAULT_MAX_WITNESS_BYTES_PER_BUNDLE,
            pressure_soft_bps: DEFAULT_PRESSURE_SOFT_BPS,
            pressure_hard_bps: DEFAULT_PRESSURE_HARD_BPS,
            backpressure_bps: DEFAULT_BACKPRESSURE_BPS,
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            default_sponsor_budget_micro_xmr: DEFAULT_SPONSOR_BUDGET_MICRO_XMR,
            min_contract_gas: DEFAULT_MIN_CONTRACT_GAS,
            allow_low_fee_sponsorship: true,
            operator_summary_redaction: true,
            deterministic_devnet: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "config.chain_id")?;
        ensure_eq(
            &self.protocol_version,
            PROTOCOL_VERSION,
            "config.protocol_version",
        )?;
        ensure_nonzero(self.fast_window_ms, "config.fast_window_ms")?;
        ensure_nonzero(
            self.prefetch_lookahead_blocks,
            "config.prefetch_lookahead_blocks",
        )?;
        ensure_nonzero(self.bundle_ttl_blocks, "config.bundle_ttl_blocks")?;
        ensure_nonzero(self.hint_ttl_blocks, "config.hint_ttl_blocks")?;
        ensure_nonzero(self.cache_ttl_blocks, "config.cache_ttl_blocks")?;
        ensure_nonzero(
            self.max_prefetch_bytes_per_block,
            "config.max_prefetch_bytes_per_block",
        )?;
        ensure_nonzero(
            self.max_witness_bytes_per_bundle,
            "config.max_witness_bytes_per_bundle",
        )?;
        ensure_bps(self.pressure_soft_bps, "config.pressure_soft_bps")?;
        ensure_bps(self.pressure_hard_bps, "config.pressure_hard_bps")?;
        ensure_bps(self.backpressure_bps, "config.backpressure_bps")?;
        if self.pressure_soft_bps >= self.pressure_hard_bps {
            return Err("config.pressure_soft_bps must be below pressure_hard_bps".to_string());
        }
        if self.backpressure_bps > self.pressure_hard_bps {
            return Err("config.backpressure_bps must not exceed pressure_hard_bps".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("config.min_pq_security_bits below PQ policy floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub shards_tracked: u64,
    pub bundles_announced: u64,
    pub bundles_prefetched: u64,
    pub bundles_attested: u64,
    pub bundles_preconfirmed: u64,
    pub bundles_executed: u64,
    pub bundles_rejected: u64,
    pub bundles_evicted: u64,
    pub attestations_recorded: u64,
    pub hints_published: u64,
    pub hints_consumed: u64,
    pub sponsorships_applied: u64,
    pub sponsored_fee_micro_xmr: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub backpressure_events: u64,
    pub pressure_rebalances: u64,
    pub operator_summaries: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub lanes_root: String,
    pub shards_root: String,
    pub bundles_root: String,
    pub attestations_root: String,
    pub hints_root: String,
    pub cache_root: String,
    pub sponsors_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            lanes_root: empty_root("lanes"),
            shards_root: empty_root("shards"),
            bundles_root: empty_root("bundles"),
            attestations_root: empty_root("attestations"),
            hints_root: empty_root("hints"),
            cache_root: empty_root("cache"),
            sponsors_root: empty_root("sponsors"),
            counters_root: empty_root("counters"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaneConfig {
    pub lane_id: String,
    pub kind: LaneKind,
    pub status: LaneStatus,
    pub shard_ids: Vec<String>,
    pub max_inflight_bundles: u64,
    pub max_bytes_per_window: u64,
    pub priority_boost_bps: u64,
    pub require_pq_attestation: bool,
    pub allow_sponsorship: bool,
    pub contract_execution_enabled: bool,
}

impl LaneConfig {
    pub fn new(lane_id: impl Into<String>, kind: LaneKind, shard_ids: Vec<String>) -> Self {
        Self {
            lane_id: lane_id.into(),
            kind,
            status: LaneStatus::Active,
            shard_ids,
            max_inflight_bundles: 512,
            max_bytes_per_window: DEFAULT_MAX_PREFETCH_BYTES_PER_BLOCK / 4,
            priority_boost_bps: 0,
            require_pq_attestation: true,
            allow_sponsorship: kind.contract_capable(),
            contract_execution_enabled: kind.contract_capable(),
        }
    }

    pub fn priority_score(&self) -> u64 {
        self.kind
            .base_priority()
            .saturating_add(self.priority_boost_bps)
            .min(MAX_BPS)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardPressure {
    pub shard_id: String,
    pub lane_id: String,
    pub pressure_bps: u64,
    pub pending_bytes: u64,
    pub pending_bundles: u64,
    pub privacy_set: u64,
    pub execution_gas_pending: u64,
    pub last_rebalanced_height: u64,
    pub level: PressureLevel,
}

impl ShardPressure {
    pub fn new(shard_id: impl Into<String>, lane_id: impl Into<String>) -> Self {
        Self {
            shard_id: shard_id.into(),
            lane_id: lane_id.into(),
            pressure_bps: 0,
            pending_bytes: 0,
            pending_bundles: 0,
            privacy_set: DEFAULT_MIN_PRIVACY_SET,
            execution_gas_pending: 0,
            last_rebalanced_height: 0,
            level: PressureLevel::Cool,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedWitnessBundle {
    pub bundle_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub contract_id: String,
    pub blob_commitment: String,
    pub witness_commitment: String,
    pub encrypted_witness_bytes: u64,
    pub execution_gas: u64,
    pub privacy_set: u64,
    pub fee_micro_xmr: u64,
    pub sponsor_id: Option<String>,
    pub announced_height: u64,
    pub expires_height: u64,
    pub status: BundleStatus,
    pub prefetch_score: u64,
    pub cache_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAttestationRecord {
    pub attestation_id: String,
    pub bundle_id: String,
    pub operator_id_hash: String,
    pub suite: String,
    pub pq_security_bits: u16,
    pub transcript_hash: String,
    pub accepted: bool,
    pub recorded_height: u64,
    pub reason_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreconfirmationHint {
    pub hint_id: String,
    pub bundle_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub target_height: u64,
    pub expires_height: u64,
    pub confidence_bps: u64,
    pub operator_hint_hash: String,
    pub redacted_execution_shape: String,
    pub status: HintStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub cache_key: String,
    pub bundle_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub bytes: u64,
    pub hot_score: u64,
    pub last_access_height: u64,
    pub expires_height: u64,
    pub decision: CacheDecision,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: String,
    pub policy_hash: String,
    pub status: SponsorStatus,
    pub remaining_budget_micro_xmr: u64,
    pub max_fee_per_bundle_micro_xmr: u64,
    pub sponsored_bundles: u64,
    pub privacy_floor: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub height: u64,
    pub lanes_root: String,
    pub bundles_root: String,
    pub hints_root: String,
    pub state_root: String,
    pub live_bundles: u64,
    pub pressure_level: PressureLevel,
    pub backpressure_active: bool,
    pub sponsored_fee_micro_xmr: u64,
    pub redacted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterLaneRequest {
    pub lane_id: String,
    pub kind: LaneKind,
    pub shard_ids: Vec<String>,
    pub max_inflight_bundles: u64,
    pub max_bytes_per_window: u64,
    pub priority_boost_bps: u64,
    pub allow_sponsorship: bool,
    pub contract_execution_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnounceBundleRequest {
    pub lane_id: String,
    pub shard_id: String,
    pub contract_id: String,
    pub blob_commitment: String,
    pub witness_commitment: String,
    pub encrypted_witness_bytes: u64,
    pub execution_gas: u64,
    pub privacy_set: u64,
    pub fee_micro_xmr: u64,
    pub sponsor_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrefetchRequest {
    pub bundle_id: String,
    pub observed_height: u64,
    pub cache_hot_score: u64,
    pub operator_id_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestRequest {
    pub bundle_id: String,
    pub operator_id_hash: String,
    pub transcript_hash: String,
    pub pq_security_bits: u16,
    pub accepted: bool,
    pub reason_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreconfirmRequest {
    pub bundle_id: String,
    pub operator_hint_hash: String,
    pub confidence_bps: u64,
    pub redacted_execution_shape: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorRequest {
    pub sponsor_id: String,
    pub policy_hash: String,
    pub budget_micro_xmr: u64,
    pub max_fee_per_bundle_micro_xmr: u64,
    pub privacy_floor: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackpressureRequest {
    pub lane_id: String,
    pub shard_id: String,
    pub pressure_bps: u64,
    pub pending_bytes: u64,
    pub pending_bundles: u64,
    pub execution_gas_pending: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvictionRequest {
    pub current_height: u64,
    pub target_free_bytes: u64,
    pub pressure_eviction: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub lanes: BTreeMap<String, LaneConfig>,
    pub shards: BTreeMap<String, ShardPressure>,
    pub bundles: BTreeMap<String, EncryptedWitnessBundle>,
    pub attestations: BTreeMap<String, PqAttestationRecord>,
    pub hints: BTreeMap<String, PreconfirmationHint>,
    pub cache: BTreeMap<String, CacheEntry>,
    pub sponsors: BTreeMap<String, SponsorAccount>,
    pub consumed_hints: BTreeSet<String>,
    pub counters: Counters,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            height: 0,
            lanes: BTreeMap::new(),
            shards: BTreeMap::new(),
            bundles: BTreeMap::new(),
            attestations: BTreeMap::new(),
            hints: BTreeMap::new(),
            cache: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            consumed_hints: BTreeSet::new(),
            counters: Counters::default(),
            roots: Roots::default(),
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

    pub fn register_lane(&mut self, request: RegisterLaneRequest) -> Result<String> {
        self.config.validate()?;
        validate_id(&request.lane_id, "lane_id")?;
        if self.lanes.len() >= MAX_LANES && !self.lanes.contains_key(&request.lane_id) {
            return Err("lane registry capacity reached".to_string());
        }
        if request.shard_ids.is_empty() {
            return Err("lane must include at least one shard".to_string());
        }
        ensure_nonzero(request.max_inflight_bundles, "max_inflight_bundles")?;
        ensure_nonzero(request.max_bytes_per_window, "max_bytes_per_window")?;
        ensure_bps(request.priority_boost_bps, "priority_boost_bps")?;

        let lane = LaneConfig {
            lane_id: request.lane_id.clone(),
            kind: request.kind,
            status: LaneStatus::Active,
            shard_ids: request.shard_ids.clone(),
            max_inflight_bundles: request.max_inflight_bundles,
            max_bytes_per_window: request.max_bytes_per_window,
            priority_boost_bps: request.priority_boost_bps,
            require_pq_attestation: true,
            allow_sponsorship: request.allow_sponsorship,
            contract_execution_enabled: request.contract_execution_enabled,
        };
        for shard_id in &request.shard_ids {
            validate_id(shard_id, "shard_id")?;
            if self.shards.len() >= MAX_SHARDS && !self.shards.contains_key(shard_id) {
                return Err("shard registry capacity reached".to_string());
            }
            self.shards
                .entry(shard_id.clone())
                .or_insert_with(|| ShardPressure::new(shard_id, &request.lane_id));
        }
        if self.lanes.insert(request.lane_id.clone(), lane).is_none() {
            self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        }
        self.counters.shards_tracked = self.shards.len() as u64;
        self.refresh_roots();
        Ok(request.lane_id)
    }

    pub fn register_sponsor(&mut self, request: SponsorRequest) -> Result<String> {
        validate_id(&request.sponsor_id, "sponsor_id")?;
        validate_hash_like(&request.policy_hash, "policy_hash")?;
        ensure_nonzero(request.budget_micro_xmr, "budget_micro_xmr")?;
        ensure_nonzero(
            request.max_fee_per_bundle_micro_xmr,
            "max_fee_per_bundle_micro_xmr",
        )?;
        if request.privacy_floor < self.config.min_privacy_set {
            return Err("sponsor privacy floor below runtime minimum".to_string());
        }
        if self.sponsors.len() >= MAX_SPONSORS && !self.sponsors.contains_key(&request.sponsor_id) {
            return Err("sponsor registry capacity reached".to_string());
        }
        let sponsor = SponsorAccount {
            sponsor_id: request.sponsor_id.clone(),
            policy_hash: request.policy_hash,
            status: SponsorStatus::Active,
            remaining_budget_micro_xmr: request.budget_micro_xmr,
            max_fee_per_bundle_micro_xmr: request.max_fee_per_bundle_micro_xmr,
            sponsored_bundles: 0,
            privacy_floor: request.privacy_floor,
        };
        self.sponsors.insert(request.sponsor_id.clone(), sponsor);
        self.refresh_roots();
        Ok(request.sponsor_id)
    }

    pub fn announce_bundle(&mut self, request: AnnounceBundleRequest) -> Result<String> {
        if self.bundles.len() >= MAX_BUNDLES {
            return Err("bundle registry capacity reached".to_string());
        }
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| "unknown lane_id".to_string())?;
        if !lane.status.accepts_new_work() {
            return Err(format!(
                "lane {} does not accept work",
                lane.status.as_str()
            ));
        }
        if !lane.shard_ids.contains(&request.shard_id) {
            return Err("shard_id is not assigned to lane".to_string());
        }
        let lane_allow_sponsorship = lane.allow_sponsorship;
        let lane_contract_execution_enabled = lane.contract_execution_enabled;
        let lane_priority_score = lane.priority_score();
        if request.encrypted_witness_bytes > self.config.max_witness_bytes_per_bundle {
            return Err("encrypted witness bundle exceeds byte limit".to_string());
        }
        if request.privacy_set < self.config.min_privacy_set {
            return Err("bundle privacy set below runtime minimum".to_string());
        }
        if request.execution_gas < self.config.min_contract_gas && lane_contract_execution_enabled {
            return Err("contract execution gas below runtime minimum".to_string());
        }
        validate_hash_like(&request.blob_commitment, "blob_commitment")?;
        validate_hash_like(&request.witness_commitment, "witness_commitment")?;

        let sponsored = self.apply_sponsorship(
            request.sponsor_id.as_deref(),
            request.fee_micro_xmr,
            request.privacy_set,
            lane_allow_sponsorship,
        )?;
        let bundle_id = deterministic_id(
            "bundle",
            &[
                HashPart::Str(&request.lane_id),
                HashPart::Str(&request.shard_id),
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.blob_commitment),
                HashPart::Str(&request.witness_commitment),
                HashPart::U64(self.height),
            ],
        );
        let score = lane_priority_score
            .saturating_add(request.privacy_set.min(512))
            .saturating_sub(request.encrypted_witness_bytes / 1024)
            .saturating_add(if sponsored { 250 } else { 0 });
        let cache_key = deterministic_id(
            "cache-key",
            &[
                HashPart::Str(&bundle_id),
                HashPart::Str(&request.witness_commitment),
            ],
        );
        let bundle = EncryptedWitnessBundle {
            bundle_id: bundle_id.clone(),
            lane_id: request.lane_id.clone(),
            shard_id: request.shard_id.clone(),
            contract_id: request.contract_id,
            blob_commitment: request.blob_commitment,
            witness_commitment: request.witness_commitment,
            encrypted_witness_bytes: request.encrypted_witness_bytes,
            execution_gas: request.execution_gas,
            privacy_set: request.privacy_set,
            fee_micro_xmr: request.fee_micro_xmr,
            sponsor_id: request.sponsor_id,
            announced_height: self.height,
            expires_height: self.height.saturating_add(self.config.bundle_ttl_blocks),
            status: BundleStatus::Announced,
            prefetch_score: score,
            cache_key,
        };
        self.bump_shard_load(
            &request.shard_id,
            request.encrypted_witness_bytes,
            1,
            request.execution_gas,
        )?;
        self.bundles.insert(bundle_id.clone(), bundle);
        self.counters.bundles_announced = self.counters.bundles_announced.saturating_add(1);
        self.refresh_roots();
        Ok(bundle_id)
    }

    pub fn prefetch_bundle(&mut self, request: PrefetchRequest) -> Result<String> {
        let bundle = self
            .bundles
            .get_mut(&request.bundle_id)
            .ok_or_else(|| "unknown bundle_id".to_string())?;
        if !bundle.status.live() {
            return Err("bundle is not live".to_string());
        }
        if request.observed_height > bundle.expires_height {
            bundle.status = BundleStatus::Expired;
            self.refresh_roots();
            return Err("bundle expired before prefetch".to_string());
        }
        validate_hash_like(&request.operator_id_hash, "operator_id_hash")?;
        let cache_key = bundle.cache_key.clone();
        let cache_entry = CacheEntry {
            cache_key: cache_key.clone(),
            bundle_id: bundle.bundle_id.clone(),
            lane_id: bundle.lane_id.clone(),
            shard_id: bundle.shard_id.clone(),
            bytes: bundle.encrypted_witness_bytes,
            hot_score: request
                .cache_hot_score
                .saturating_add(bundle.prefetch_score),
            last_access_height: request.observed_height,
            expires_height: request
                .observed_height
                .saturating_add(self.config.cache_ttl_blocks),
            decision: CacheDecision::KeepHot,
        };
        bundle.status = BundleStatus::Prefetched;
        self.cache.insert(cache_key.clone(), cache_entry);
        self.counters.bundles_prefetched = self.counters.bundles_prefetched.saturating_add(1);
        self.counters.cache_misses = self.counters.cache_misses.saturating_add(1);
        self.refresh_roots();
        Ok(cache_key)
    }

    pub fn record_pq_attestation(&mut self, request: AttestRequest) -> Result<String> {
        if self.attestations.len() >= MAX_ATTESTATIONS {
            return Err("attestation registry capacity reached".to_string());
        }
        let bundle = self
            .bundles
            .get_mut(&request.bundle_id)
            .ok_or_else(|| "unknown bundle_id".to_string())?;
        validate_hash_like(&request.operator_id_hash, "operator_id_hash")?;
        validate_hash_like(&request.transcript_hash, "transcript_hash")?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("PQ attestation security bits below runtime minimum".to_string());
        }
        let attestation_id = deterministic_id(
            "pq-attestation",
            &[
                HashPart::Str(&request.bundle_id),
                HashPart::Str(&request.operator_id_hash),
                HashPart::Str(&request.transcript_hash),
                HashPart::U64(self.counters.attestations_recorded),
            ],
        );
        let record = PqAttestationRecord {
            attestation_id: attestation_id.clone(),
            bundle_id: request.bundle_id.clone(),
            operator_id_hash: request.operator_id_hash,
            suite: PQ_ATTESTATION_SUITE.to_string(),
            pq_security_bits: request.pq_security_bits,
            transcript_hash: request.transcript_hash,
            accepted: request.accepted,
            recorded_height: self.height,
            reason_code: request.reason_code,
        };
        bundle.status = if request.accepted {
            BundleStatus::Attested
        } else {
            BundleStatus::Rejected
        };
        self.attestations.insert(attestation_id.clone(), record);
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        if request.accepted {
            self.counters.bundles_attested = self.counters.bundles_attested.saturating_add(1);
        } else {
            self.counters.bundles_rejected = self.counters.bundles_rejected.saturating_add(1);
        }
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn publish_preconfirmation_hint(&mut self, request: PreconfirmRequest) -> Result<String> {
        if self.hints.len() >= MAX_HINTS {
            return Err("preconfirmation hint registry capacity reached".to_string());
        }
        let bundle = self
            .bundles
            .get_mut(&request.bundle_id)
            .ok_or_else(|| "unknown bundle_id".to_string())?;
        if bundle.status != BundleStatus::Attested && bundle.status != BundleStatus::Prefetched {
            return Err("bundle must be prefetched or attested before preconfirmation".to_string());
        }
        validate_hash_like(&request.operator_hint_hash, "operator_hint_hash")?;
        ensure_bps(request.confidence_bps, "confidence_bps")?;
        let hint_id = deterministic_id(
            "preconfirmation-hint",
            &[
                HashPart::Str(&request.bundle_id),
                HashPart::Str(&request.operator_hint_hash),
                HashPart::U64(self.height),
            ],
        );
        let hint = PreconfirmationHint {
            hint_id: hint_id.clone(),
            bundle_id: request.bundle_id.clone(),
            lane_id: bundle.lane_id.clone(),
            shard_id: bundle.shard_id.clone(),
            target_height: self.height.saturating_add(1),
            expires_height: self.height.saturating_add(self.config.hint_ttl_blocks),
            confidence_bps: request.confidence_bps,
            operator_hint_hash: request.operator_hint_hash,
            redacted_execution_shape: request.redacted_execution_shape,
            status: HintStatus::Published,
        };
        bundle.status = BundleStatus::Preconfirmed;
        self.hints.insert(hint_id.clone(), hint);
        self.counters.hints_published = self.counters.hints_published.saturating_add(1);
        self.counters.bundles_preconfirmed = self.counters.bundles_preconfirmed.saturating_add(1);
        self.refresh_roots();
        Ok(hint_id)
    }

    pub fn consume_hint_and_execute(&mut self, hint_id: &str) -> Result<String> {
        let hint = self
            .hints
            .get_mut(hint_id)
            .ok_or_else(|| "unknown hint_id".to_string())?;
        if !hint.status.live() {
            return Err("hint is not live".to_string());
        }
        if self.height > hint.expires_height {
            hint.status = HintStatus::Expired;
            self.refresh_roots();
            return Err("hint expired".to_string());
        }
        let bundle = self
            .bundles
            .get_mut(&hint.bundle_id)
            .ok_or_else(|| "hint references unknown bundle".to_string())?;
        bundle.status = BundleStatus::Executed;
        let bundle_id = bundle.bundle_id.clone();
        hint.status = HintStatus::Consumed;
        self.consumed_hints.insert(hint_id.to_string());
        self.counters.hints_consumed = self.counters.hints_consumed.saturating_add(1);
        self.counters.bundles_executed = self.counters.bundles_executed.saturating_add(1);
        self.refresh_roots();
        Ok(bundle_id)
    }

    pub fn update_backpressure(&mut self, request: BackpressureRequest) -> Result<PressureLevel> {
        ensure_bps(request.pressure_bps, "pressure_bps")?;
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "unknown lane_id".to_string())?;
        let shard = self
            .shards
            .get_mut(&request.shard_id)
            .ok_or_else(|| "unknown shard_id".to_string())?;
        if shard.lane_id != request.lane_id {
            return Err("shard does not belong to lane".to_string());
        }
        shard.pressure_bps = request.pressure_bps;
        shard.pending_bytes = request.pending_bytes;
        shard.pending_bundles = request.pending_bundles;
        shard.execution_gas_pending = request.execution_gas_pending;
        shard.last_rebalanced_height = self.height;
        shard.level = pressure_level(
            request.pressure_bps,
            self.config.pressure_soft_bps,
            self.config.pressure_hard_bps,
        );
        if request.pressure_bps >= self.config.backpressure_bps {
            lane.status = LaneStatus::Backpressured;
            self.counters.backpressure_events = self.counters.backpressure_events.saturating_add(1);
        } else if lane.status == LaneStatus::Backpressured {
            lane.status = LaneStatus::Active;
        }
        self.counters.pressure_rebalances = self.counters.pressure_rebalances.saturating_add(1);
        self.refresh_roots();
        Ok(shard.level)
    }

    pub fn evict_cache(&mut self, request: EvictionRequest) -> Result<Vec<String>> {
        let mut candidates = self
            .cache
            .values()
            .map(|entry| {
                let expired = request.current_height > entry.expires_height;
                let priority = if expired {
                    0
                } else {
                    entry.hot_score.saturating_add(entry.bytes / 1024)
                };
                (priority, entry.cache_key.clone(), expired, entry.bytes)
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

        let mut freed = 0_u64;
        let mut evicted = Vec::new();
        for (_, cache_key, expired, bytes) in candidates {
            if !expired && !request.pressure_eviction && freed >= request.target_free_bytes {
                break;
            }
            if let Some(entry) = self.cache.get_mut(&cache_key) {
                entry.decision = if expired {
                    CacheDecision::EvictExpired
                } else {
                    CacheDecision::EvictPressure
                };
            }
            if let Some(entry) = self.cache.remove(&cache_key) {
                if let Some(bundle) = self.bundles.get_mut(&entry.bundle_id) {
                    if bundle.status.live() {
                        bundle.status = BundleStatus::Evicted;
                    }
                }
                freed = freed.saturating_add(bytes);
                evicted.push(cache_key);
                self.counters.bundles_evicted = self.counters.bundles_evicted.saturating_add(1);
            }
            if freed >= request.target_free_bytes && !request.pressure_eviction {
                break;
            }
        }
        self.refresh_roots();
        Ok(evicted)
    }

    pub fn operator_safe_summary(&mut self) -> OperatorSafeSummary {
        let live_bundles = self
            .bundles
            .values()
            .filter(|bundle| bundle.status.live())
            .count() as u64;
        let pressure_level = self
            .shards
            .values()
            .map(|shard| shard.level)
            .max()
            .unwrap_or(PressureLevel::Cool);
        let backpressure_active = self
            .lanes
            .values()
            .any(|lane| lane.status == LaneStatus::Backpressured);
        let summary_id = deterministic_id(
            "operator-safe-summary",
            &[
                HashPart::U64(self.height),
                HashPart::Str(&self.roots.state_root),
                HashPart::U64(self.counters.operator_summaries),
            ],
        );
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        OperatorSafeSummary {
            summary_id,
            height: self.height,
            lanes_root: self.roots.lanes_root.clone(),
            bundles_root: self.roots.bundles_root.clone(),
            hints_root: self.roots.hints_root.clone(),
            state_root: self.roots.state_root.clone(),
            live_bundles,
            pressure_level,
            backpressure_active,
            sponsored_fee_micro_xmr: self.counters.sponsored_fee_micro_xmr,
            redacted: self.config.operator_summary_redaction,
        }
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.expire_records();
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "suites": {
                "hash": HASH_SUITE,
                "pq_attestation": PQ_ATTESTATION_SUITE,
                "encrypted_witness": ENCRYPTED_WITNESS_SUITE,
                "blob_privacy": BLOB_PRIVACY_SUITE,
                "prefetch_scheduler": PREFETCH_SCHEDULER_SUITE,
                "preconfirmation_hint": PRECONFIRMATION_HINT_SUITE,
                "low_fee_sponsorship": LOW_FEE_SPONSORSHIP_SUITE,
                "contract_execution": CONTRACT_EXECUTION_SUITE
            },
            "config": {
                "fast_window_ms": self.config.fast_window_ms,
                "prefetch_lookahead_blocks": self.config.prefetch_lookahead_blocks,
                "bundle_ttl_blocks": self.config.bundle_ttl_blocks,
                "hint_ttl_blocks": self.config.hint_ttl_blocks,
                "cache_ttl_blocks": self.config.cache_ttl_blocks,
                "max_prefetch_bytes_per_block": self.config.max_prefetch_bytes_per_block,
                "max_witness_bytes_per_bundle": self.config.max_witness_bytes_per_bundle,
                "pressure_soft_bps": self.config.pressure_soft_bps,
                "pressure_hard_bps": self.config.pressure_hard_bps,
                "backpressure_bps": self.config.backpressure_bps,
                "min_privacy_set": self.config.min_privacy_set,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "allow_low_fee_sponsorship": self.config.allow_low_fee_sponsorship,
                "operator_summary_redaction": self.config.operator_summary_redaction
            },
            "counters": self.counters,
            "roots": self.roots,
            "lane_count": self.lanes.len(),
            "shard_count": self.shards.len(),
            "bundle_count": self.bundles.len(),
            "attestation_count": self.attestations.len(),
            "hint_count": self.hints.len(),
            "cache_count": self.cache.len(),
            "sponsor_count": self.sponsors.len()
        })
    }

    pub fn state_root(&self) -> String {
        let record = self.public_record();
        domain_hash(
            "private-l2-fast-pq-prefetch-orchestrator:state-root",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&record)],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.lanes_root = map_root("lanes", &self.lanes);
        self.roots.shards_root = map_root("shards", &self.shards);
        self.roots.bundles_root = map_root("bundles", &self.bundles);
        self.roots.attestations_root = map_root("attestations", &self.attestations);
        self.roots.hints_root = map_root("hints", &self.hints);
        self.roots.cache_root = map_root("cache", &self.cache);
        self.roots.sponsors_root = map_root("sponsors", &self.sponsors);
        let counters = serde_json::to_value(&self.counters).expect("counters serialize");
        self.roots.counters_root = merkle_root(
            "private-l2-fast-pq-prefetch-orchestrator:counters",
            &[counters],
        );
        let state_record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "lanes_root": self.roots.lanes_root,
            "shards_root": self.roots.shards_root,
            "bundles_root": self.roots.bundles_root,
            "attestations_root": self.roots.attestations_root,
            "hints_root": self.roots.hints_root,
            "cache_root": self.roots.cache_root,
            "sponsors_root": self.roots.sponsors_root,
            "counters_root": self.roots.counters_root
        });
        self.roots.state_root = domain_hash(
            "private-l2-fast-pq-prefetch-orchestrator:state",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&state_record)],
            32,
        );
    }

    fn apply_sponsorship(
        &mut self,
        sponsor_id: Option<&str>,
        fee_micro_xmr: u64,
        privacy_set: u64,
        lane_allows_sponsorship: bool,
    ) -> Result<bool> {
        let Some(sponsor_id) = sponsor_id else {
            return Ok(false);
        };
        if !self.config.allow_low_fee_sponsorship || !lane_allows_sponsorship {
            return Err("low-fee sponsorship is not allowed for this lane".to_string());
        }
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "unknown sponsor_id".to_string())?;
        if !sponsor.status.usable() {
            return Err("sponsor is not active".to_string());
        }
        if privacy_set < sponsor.privacy_floor {
            return Err("bundle privacy set below sponsor policy floor".to_string());
        }
        if fee_micro_xmr > sponsor.max_fee_per_bundle_micro_xmr {
            return Err("bundle fee exceeds sponsor policy".to_string());
        }
        if sponsor.remaining_budget_micro_xmr < fee_micro_xmr {
            sponsor.status = SponsorStatus::Exhausted;
            return Err("sponsor budget exhausted".to_string());
        }
        sponsor.remaining_budget_micro_xmr = sponsor
            .remaining_budget_micro_xmr
            .saturating_sub(fee_micro_xmr);
        sponsor.sponsored_bundles = sponsor.sponsored_bundles.saturating_add(1);
        self.counters.sponsorships_applied = self.counters.sponsorships_applied.saturating_add(1);
        self.counters.sponsored_fee_micro_xmr = self
            .counters
            .sponsored_fee_micro_xmr
            .saturating_add(fee_micro_xmr);
        Ok(true)
    }

    fn bump_shard_load(
        &mut self,
        shard_id: &str,
        bytes: u64,
        bundles: u64,
        execution_gas: u64,
    ) -> Result<()> {
        let shard = self
            .shards
            .get_mut(shard_id)
            .ok_or_else(|| "unknown shard_id".to_string())?;
        shard.pending_bytes = shard.pending_bytes.saturating_add(bytes);
        shard.pending_bundles = shard.pending_bundles.saturating_add(bundles);
        shard.execution_gas_pending = shard.execution_gas_pending.saturating_add(execution_gas);
        let byte_bps = shard
            .pending_bytes
            .saturating_mul(MAX_BPS)
            .checked_div(self.config.max_prefetch_bytes_per_block)
            .unwrap_or(MAX_BPS);
        let gas_bps = shard
            .execution_gas_pending
            .saturating_mul(MAX_BPS)
            .checked_div(self.config.min_contract_gas.saturating_mul(512))
            .unwrap_or(MAX_BPS);
        shard.pressure_bps = byte_bps.max(gas_bps).min(MAX_BPS);
        shard.level = pressure_level(
            shard.pressure_bps,
            self.config.pressure_soft_bps,
            self.config.pressure_hard_bps,
        );
        Ok(())
    }

    fn expire_records(&mut self) {
        for bundle in self.bundles.values_mut() {
            if bundle.status.live() && self.height > bundle.expires_height {
                bundle.status = BundleStatus::Expired;
            }
        }
        for hint in self.hints.values_mut() {
            if hint.status.live() && self.height > hint.expires_height {
                hint.status = HintStatus::Expired;
            }
        }
        for entry in self.cache.values_mut() {
            if self.height > entry.expires_height {
                entry.decision = CacheDecision::EvictExpired;
            } else if entry.hot_score < 1_000 {
                entry.decision = CacheDecision::DemoteCold;
            }
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default()).expect("valid devnet config");
    state.height = DEVNET_HEIGHT;
    state
        .register_lane(RegisterLaneRequest {
            lane_id: "devnet-blob-fast".to_string(),
            kind: LaneKind::BlobFast,
            shard_ids: vec!["blob-shard-a".to_string(), "blob-shard-b".to_string()],
            max_inflight_bundles: 768,
            max_bytes_per_window: DEFAULT_MAX_PREFETCH_BYTES_PER_BLOCK / 2,
            priority_boost_bps: 150,
            allow_sponsorship: true,
            contract_execution_enabled: true,
        })
        .expect("register blob lane");
    state
        .register_lane(RegisterLaneRequest {
            lane_id: "devnet-witness-fast".to_string(),
            kind: LaneKind::WitnessFast,
            shard_ids: vec!["witness-shard-a".to_string(), "witness-shard-b".to_string()],
            max_inflight_bundles: 1_024,
            max_bytes_per_window: DEFAULT_MAX_PREFETCH_BYTES_PER_BLOCK / 2,
            priority_boost_bps: 250,
            allow_sponsorship: true,
            contract_execution_enabled: true,
        })
        .expect("register witness lane");
    state
        .register_lane(RegisterLaneRequest {
            lane_id: "devnet-contract-execution".to_string(),
            kind: LaneKind::ContractExecution,
            shard_ids: vec!["contract-shard-a".to_string()],
            max_inflight_bundles: 512,
            max_bytes_per_window: DEFAULT_MAX_PREFETCH_BYTES_PER_BLOCK / 4,
            priority_boost_bps: 100,
            allow_sponsorship: true,
            contract_execution_enabled: true,
        })
        .expect("register contract lane");
    state
        .register_sponsor(SponsorRequest {
            sponsor_id: "devnet-low-fee-paymaster".to_string(),
            policy_hash: fixed_hash("sponsor-policy"),
            budget_micro_xmr: DEFAULT_SPONSOR_BUDGET_MICRO_XMR,
            max_fee_per_bundle_micro_xmr: 2_500,
            privacy_floor: DEFAULT_MIN_PRIVACY_SET,
        })
        .expect("register sponsor");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let bundle_id = state
        .announce_bundle(AnnounceBundleRequest {
            lane_id: "devnet-witness-fast".to_string(),
            shard_id: "witness-shard-a".to_string(),
            contract_id: "confidential-swap-router".to_string(),
            blob_commitment: fixed_hash("blob-commitment-demo"),
            witness_commitment: fixed_hash("witness-commitment-demo"),
            encrypted_witness_bytes: 96 * 1024,
            execution_gas: 180_000,
            privacy_set: 128,
            fee_micro_xmr: 1_250,
            sponsor_id: Some("devnet-low-fee-paymaster".to_string()),
        })
        .expect("announce demo bundle");
    state
        .prefetch_bundle(PrefetchRequest {
            bundle_id: bundle_id.clone(),
            observed_height: DEVNET_HEIGHT,
            cache_hot_score: 7_500,
            operator_id_hash: fixed_hash("operator-a"),
        })
        .expect("prefetch demo bundle");
    state
        .record_pq_attestation(AttestRequest {
            bundle_id: bundle_id.clone(),
            operator_id_hash: fixed_hash("operator-a"),
            transcript_hash: fixed_hash("attestation-transcript"),
            pq_security_bits: 256,
            accepted: true,
            reason_code: "accepted_fast_prefetch".to_string(),
        })
        .expect("attest demo bundle");
    let hint_id = state
        .publish_preconfirmation_hint(PreconfirmRequest {
            bundle_id,
            operator_hint_hash: fixed_hash("operator-hint"),
            confidence_bps: 9_250,
            redacted_execution_shape: "swap_router:2_inputs:1_output:redacted".to_string(),
        })
        .expect("publish demo hint");
    state
        .consume_hint_and_execute(&hint_id)
        .expect("execute demo preconfirmation");
    state.refresh_roots();
    state
}

fn pressure_level(pressure_bps: u64, soft_bps: u64, hard_bps: u64) -> PressureLevel {
    if pressure_bps >= MAX_BPS {
        PressureLevel::Emergency
    } else if pressure_bps >= hard_bps {
        PressureLevel::HardLimit
    } else if pressure_bps >= soft_bps {
        PressureLevel::SoftLimit
    } else if pressure_bps >= soft_bps / 2 {
        PressureLevel::Warm
    } else {
        PressureLevel::Cool
    }
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).expect("record serialize")
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-prefetch-orchestrator:{label}"),
        &leaves,
    )
}

fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("private-l2-fast-pq-prefetch-orchestrator:{label}"),
        &[],
    )
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("private-l2-fast-pq-prefetch-orchestrator:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Bytes(join_hash_parts(parts).as_bytes()),
        ],
        16,
    )
}

fn fixed_hash(label: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-prefetch-orchestrator:devnet-fixture",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn join_hash_parts(parts: &[HashPart<'_>]) -> String {
    parts
        .iter()
        .map(|part| match part {
            HashPart::Bytes(value) => hex::encode(value),
            HashPart::Str(value) => value.to_string(),
            HashPart::U64(value) => value.to_string(),
            HashPart::Int(value) => value.to_string(),
            HashPart::Json(value) => value.to_string(),
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn validate_id(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > 128 {
        return Err(format!("{field} exceeds 128 bytes"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("{field} contains unsupported characters"));
    }
    Ok(())
}

fn validate_hash_like(value: &str, field: &str) -> Result<()> {
    if value.len() < 16 {
        return Err(format!("{field} must be at least 16 hex characters"));
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must be hex encoded"));
    }
    Ok(())
}

fn ensure_nonzero(value: u64, field: &str) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be non-zero"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, field: &str) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_eq(actual: &str, expected: &str, field: &str) -> Result<()> {
    if actual != expected {
        Err(format!(
            "{field} mismatch: expected {expected}, got {actual}"
        ))
    } else {
        Ok(())
    }
}
