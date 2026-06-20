use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialDaPrefetchSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_DA_PREFETCH_SCHEDULER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-da-prefetch-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_DA_PREFETCH_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DA_RESERVATION_SUITE: &str = "confidential-da-prefetch-reservation-v1";
pub const ENCRYPTED_BLOB_HINT_SUITE: &str = "ML-KEM-1024+HPKE-XChaCha20Poly1305-da-hint-v1";
pub const WITNESS_FETCH_LANE_SUITE: &str = "deterministic-pq-witness-fetch-lane-v1";
pub const PQ_AVAILABILITY_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-availability-attestation-v1";
pub const LOW_FEE_PRIORITY_SUITE: &str = "low-fee-confidential-da-priority-lane-v1";
pub const STALE_BLOB_QUARANTINE_SUITE: &str = "stale-confidential-da-blob-quarantine-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_410_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_530_000;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_PREFETCH_LOOKAHEAD_SLOTS: u64 = 12;
pub const DEFAULT_RESERVATION_TTL_SLOTS: u64 = 48;
pub const DEFAULT_HINT_TTL_SLOTS: u64 = 18;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 64;
pub const DEFAULT_QUARANTINE_TTL_SLOTS: u64 = 192;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 80;
pub const DEFAULT_FAST_TARGET_MS: u64 = 220;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_LOW_FEE_BOOST_BPS: u64 = 650;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_STALE_AFTER_SLOTS: u64 = 72;
pub const DEFAULT_MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_RESERVED_BYTES_PER_SLOT: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_WITNESS_BYTES_PER_FETCH: u64 = 768 * 1024;
pub const DEFAULT_MAX_FETCH_LANES: usize = 16_384;
pub const DEFAULT_MAX_RESERVATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_HINTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIORITY_LANES: usize = 65_536;
pub const DEFAULT_MAX_QUARANTINED_BLOBS: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchLaneKind {
    BlobFast,
    WitnessFast,
    RecursiveProof,
    ContractState,
    BridgeExit,
    LowFee,
    Recovery,
}

impl FetchLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobFast => "blob_fast",
            Self::WitnessFast => "witness_fast",
            Self::RecursiveProof => "recursive_proof",
            Self::ContractState => "contract_state",
            Self::BridgeExit => "bridge_exit",
            Self::LowFee => "low_fee",
            Self::Recovery => "recovery",
        }
    }

    pub fn base_priority(self) -> u64 {
        match self {
            Self::WitnessFast => 10_000,
            Self::BlobFast => 9_600,
            Self::LowFee => 9_250,
            Self::ContractState => 8_800,
            Self::RecursiveProof => 8_300,
            Self::BridgeExit => 7_800,
            Self::Recovery => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Draining,
    Paused,
    Quarantined,
    Retired,
}

impl LaneStatus {
    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Requested,
    Reserved,
    Scheduled,
    Fetching,
    Warmed,
    Consumed,
    Expired,
    Quarantined,
    Rejected,
}

impl ReservationStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Reserved | Self::Scheduled | Self::Fetching | Self::Warmed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobHintStatus {
    Draft,
    Published,
    Selected,
    Fetching,
    Attested,
    Consumed,
    Expired,
    Quarantined,
    Revoked,
}

impl BlobHintStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Published | Self::Selected | Self::Fetching | Self::Attested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityVerdict {
    Available,
    Partial,
    Delayed,
    Withheld,
    Invalid,
}

impl AvailabilityVerdict {
    pub fn is_positive(self) -> bool {
        matches!(self, Self::Available | Self::Partial)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityLaneStatus {
    Active,
    Exhausted,
    Paused,
    Quarantined,
    Retired,
}

impl PriorityLaneStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleBlob,
    MissingShard,
    InvalidPqAttestation,
    FeeOverCap,
    PrivacySetTooSmall,
    LaneBackpressure,
    SchedulerEquivocation,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub prefetch_lookahead_slots: u64,
    pub reservation_ttl_slots: u64,
    pub hint_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub quarantine_ttl_slots: u64,
    pub slot_width_ms: u64,
    pub fast_target_ms: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_boost_bps: u64,
    pub quorum_weight_bps: u64,
    pub strong_quorum_weight_bps: u64,
    pub stale_after_slots: u64,
    pub max_blob_bytes: u64,
    pub max_reserved_bytes_per_slot: u64,
    pub max_witness_bytes_per_fetch: u64,
    pub max_fetch_lanes: usize,
    pub max_reservations: usize,
    pub max_hints: usize,
    pub max_attestations: usize,
    pub max_priority_lanes: usize,
    pub max_quarantined_blobs: usize,
    pub max_public_records: usize,
    pub deterministic_devnet: bool,
    pub allow_devnet_shortcuts: bool,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            prefetch_lookahead_slots: DEFAULT_PREFETCH_LOOKAHEAD_SLOTS,
            reservation_ttl_slots: DEFAULT_RESERVATION_TTL_SLOTS,
            hint_ttl_slots: DEFAULT_HINT_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            quarantine_ttl_slots: DEFAULT_QUARANTINE_TTL_SLOTS,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            fast_target_ms: DEFAULT_FAST_TARGET_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_boost_bps: DEFAULT_LOW_FEE_BOOST_BPS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            stale_after_slots: DEFAULT_STALE_AFTER_SLOTS,
            max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
            max_reserved_bytes_per_slot: DEFAULT_MAX_RESERVED_BYTES_PER_SLOT,
            max_witness_bytes_per_fetch: DEFAULT_MAX_WITNESS_BYTES_PER_FETCH,
            max_fetch_lanes: DEFAULT_MAX_FETCH_LANES,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_hints: DEFAULT_MAX_HINTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_priority_lanes: DEFAULT_MAX_PRIORITY_LANES,
            max_quarantined_blobs: DEFAULT_MAX_QUARANTINED_BLOBS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            deterministic_devnet: true,
            allow_devnet_shortcuts: false,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_lane_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_hint_nonce: u64,
    pub next_attestation_nonce: u64,
    pub next_priority_lane_nonce: u64,
    pub next_quarantine_nonce: u64,
    pub reservations_opened: u64,
    pub reservations_scheduled: u64,
    pub reservations_consumed: u64,
    pub hints_published: u64,
    pub hints_selected: u64,
    pub witness_fetches_started: u64,
    pub attestations_recorded: u64,
    pub availability_quorum_reached: u64,
    pub low_fee_promotions: u64,
    pub quarantine_events: u64,
    pub total_reserved_bytes: u128,
    pub total_witness_bytes: u128,
    pub total_fee_budget_microunits: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub fetch_lanes_root: String,
    pub reservations_root: String,
    pub encrypted_blob_hints_root: String,
    pub availability_attestations_root: String,
    pub priority_lanes_root: String,
    pub quarantined_blobs_root: String,
    pub consumed_nullifiers_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("ROOTS", &self.public_record())
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            fetch_lanes_root: empty_root("fetch_lanes"),
            reservations_root: empty_root("reservations"),
            encrypted_blob_hints_root: empty_root("encrypted_blob_hints"),
            availability_attestations_root: empty_root("availability_attestations"),
            priority_lanes_root: empty_root("priority_lanes"),
            quarantined_blobs_root: empty_root("quarantined_blobs"),
            consumed_nullifiers_root: empty_root("consumed_nullifiers"),
            public_records_root: empty_root("public_records"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct WitnessFetchLane {
    pub lane_id: String,
    pub kind: FetchLaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub shard_set_root: String,
    pub max_inflight_reservations: u64,
    pub max_bytes_per_slot: u64,
    pub reserved_bytes_current_slot: u64,
    pub priority_weight: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub opened_at_slot: u64,
    pub updated_at_slot: u64,
}

impl WitnessFetchLane {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("WITNESSFETCHLANE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DaReservation {
    pub reservation_id: String,
    pub lane_id: String,
    pub blob_hint_id: String,
    pub requester_commitment: String,
    pub reservation_nullifier: String,
    pub status: ReservationStatus,
    pub blob_bytes: u64,
    pub witness_bytes: u64,
    pub max_fee_microunits: u128,
    pub priority_score: u64,
    pub scheduled_slot: u64,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub availability_root: String,
}

impl DaReservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("DARESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedBlobHint {
    pub blob_hint_id: String,
    pub lane_id: String,
    pub encrypted_blob_root: String,
    pub encrypted_metadata_root: String,
    pub ciphertext_bytes: u64,
    pub erasure_shard_root: String,
    pub witness_root: String,
    pub fee_cap_microunits: u128,
    pub privacy_set_size: u64,
    pub pq_key_commitment: String,
    pub status: BlobHintStatus,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
}

impl EncryptedBlobHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("ENCRYPTEDBLOBHINT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqAvailabilityAttestation {
    pub attestation_id: String,
    pub reservation_id: String,
    pub blob_hint_id: String,
    pub attester_commitment: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub availability_root: String,
    pub verdict: AvailabilityVerdict,
    pub attester_weight_bps: u64,
    pub observed_slot: u64,
    pub expires_at_slot: u64,
}

impl PqAvailabilityAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("PQAVAILABILITYATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeePriorityLane {
    pub priority_lane_id: String,
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub status: PriorityLaneStatus,
    pub fee_asset_id: String,
    pub remaining_budget_microunits: u128,
    pub max_fee_bps: u64,
    pub priority_boost_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_slot: u64,
    pub expires_at_slot: u64,
}

impl LowFeePriorityLane {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("LOWFEEPRIORITYLANE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct QuarantinedBlob {
    pub quarantine_id: String,
    pub blob_hint_id: String,
    pub reservation_id: Option<String>,
    pub lane_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub quarantined_at_slot: u64,
    pub releases_at_slot: u64,
    pub stale_after_slot: u64,
}

impl QuarantinedBlob {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        record_root("QUARANTINEDBLOB", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub current_slot: u64,
    pub fetch_lanes: BTreeMap<String, WitnessFetchLane>,
    pub reservations: BTreeMap<String, DaReservation>,
    pub encrypted_blob_hints: BTreeMap<String, EncryptedBlobHint>,
    pub availability_attestations: BTreeMap<String, PqAvailabilityAttestation>,
    pub priority_lanes: BTreeMap<String, LowFeePriorityLane>,
    pub quarantined_blobs: BTreeMap<String, QuarantinedBlob>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        ensure(!config.l2_network.is_empty(), "l2 network is required")?;
        ensure(
            !config.monero_network.is_empty(),
            "monero network is required",
        )?;
        ensure(!config.fee_asset_id.is_empty(), "fee asset id is required")?;
        ensure(
            config.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security bits too low",
        )?;
        ensure(
            config.min_privacy_set_size > 0
                && config.target_privacy_set_size >= config.min_privacy_set_size,
            "invalid privacy set bounds",
        )?;
        ensure(config.slot_width_ms > 0, "slot width is zero")?;
        ensure(config.fast_target_ms > 0, "fast target is zero")?;
        ensure(
            config.max_user_fee_bps <= MAX_BPS && config.low_fee_boost_bps <= MAX_BPS,
            "fee bps out of range",
        )?;
        ensure(
            config.quorum_weight_bps <= config.strong_quorum_weight_bps
                && config.strong_quorum_weight_bps <= MAX_BPS,
            "invalid quorum bounds",
        )?;

        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            l2_height: 0,
            monero_height: 0,
            current_slot: 0,
            fetch_lanes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            encrypted_blob_hints: BTreeMap::new(),
            availability_attestations: BTreeMap::new(),
            priority_lanes: BTreeMap::new(),
            quarantined_blobs: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: Vec::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "current_slot": self.current_slot,
            "suites": {
                "hash": HASH_SUITE,
                "da_reservation": DA_RESERVATION_SUITE,
                "encrypted_blob_hint": ENCRYPTED_BLOB_HINT_SUITE,
                "witness_fetch_lane": WITNESS_FETCH_LANE_SUITE,
                "pq_availability_attestation": PQ_AVAILABILITY_ATTESTATION_SUITE,
                "low_fee_priority": LOW_FEE_PRIORITY_SUITE,
                "stale_blob_quarantine": STALE_BLOB_QUARANTINE_SUITE
            },
            "config": self.config,
            "counters": self.counters,
            "roots": {
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "fetch_lanes_root": self.roots.fetch_lanes_root,
                "reservations_root": self.roots.reservations_root,
                "encrypted_blob_hints_root": self.roots.encrypted_blob_hints_root,
                "availability_attestations_root": self.roots.availability_attestations_root,
                "priority_lanes_root": self.roots.priority_lanes_root,
                "quarantined_blobs_root": self.roots.quarantined_blobs_root,
                "consumed_nullifiers_root": self.roots.consumed_nullifiers_root,
                "public_records_root": self.roots.public_records_root
            }
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.root();
        self.roots.counters_root = self.counters.root();
        self.roots.fetch_lanes_root = map_root("fetch_lanes", &self.fetch_lanes);
        self.roots.reservations_root = map_root("reservations", &self.reservations);
        self.roots.encrypted_blob_hints_root =
            map_root("encrypted_blob_hints", &self.encrypted_blob_hints);
        self.roots.availability_attestations_root =
            map_root("availability_attestations", &self.availability_attestations);
        self.roots.priority_lanes_root = map_root("priority_lanes", &self.priority_lanes);
        self.roots.quarantined_blobs_root = map_root("quarantined_blobs", &self.quarantined_blobs);
        self.roots.consumed_nullifiers_root =
            set_root("consumed_nullifiers", &self.consumed_nullifiers);
        self.roots.public_records_root = merkle_root(
            "private-l2-fast-pq-confidential-da-prefetch-scheduler:public-records",
            &self.public_records,
        );
        let record = self.public_record();
        self.roots.state_root = domain_hash(
            "private-l2-fast-pq-confidential-da-prefetch-scheduler:state-root",
            &[HashPart::Str(CHAIN_ID), HashPart::Json(&record)],
            32,
        );
    }

    pub fn advance_slot(&mut self, l2_height: u64, monero_height: u64, slot: u64) {
        self.l2_height = l2_height;
        self.monero_height = monero_height;
        self.current_slot = slot;
        self.expire_stale_records();
        self.refresh_roots();
    }

    pub fn register_fetch_lane(&mut self, request: RegisterFetchLaneRequest) -> Result<String> {
        ensure(
            self.fetch_lanes.len() < self.config.max_fetch_lanes,
            "fetch lane capacity reached",
        )?;
        ensure(!request.operator_commitment.is_empty(), "operator required")?;
        ensure(
            !request.shard_set_root.is_empty(),
            "shard set root required",
        )?;
        ensure(
            request.max_inflight_reservations > 0,
            "inflight limit is zero",
        )?;
        ensure(request.max_bytes_per_slot > 0, "byte limit is zero")?;
        ensure(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "lane pq security too low",
        )?;
        ensure(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set too small",
        )?;
        self.counters.next_lane_nonce += 1;
        let lane_id = request.lane_id.unwrap_or_else(|| {
            deterministic_id(
                "lane",
                self.counters.next_lane_nonce,
                request.kind.as_str(),
                &request.operator_commitment,
            )
        });
        ensure(!self.fetch_lanes.contains_key(&lane_id), "lane exists")?;
        let lane = WitnessFetchLane {
            lane_id: lane_id.clone(),
            kind: request.kind,
            status: LaneStatus::Open,
            operator_commitment: request.operator_commitment,
            shard_set_root: request.shard_set_root,
            max_inflight_reservations: request.max_inflight_reservations,
            max_bytes_per_slot: request.max_bytes_per_slot,
            reserved_bytes_current_slot: 0,
            priority_weight: request.kind.base_priority() + request.priority_weight,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            opened_at_slot: self.current_slot,
            updated_at_slot: self.current_slot,
        };
        self.append_public_record(lane.public_record());
        self.fetch_lanes.insert(lane_id.clone(), lane);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn publish_encrypted_blob_hint(
        &mut self,
        request: PublishEncryptedBlobHintRequest,
    ) -> Result<String> {
        ensure(
            self.encrypted_blob_hints.len() < self.config.max_hints,
            "hint capacity reached",
        )?;
        let lane = self
            .fetch_lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane not found".to_string())?;
        ensure(lane.status.accepts_work(), "lane does not accept work")?;
        ensure(
            !request.encrypted_blob_root.is_empty(),
            "blob root required",
        )?;
        ensure(
            !request.encrypted_metadata_root.is_empty(),
            "metadata root required",
        )?;
        ensure(
            !request.erasure_shard_root.is_empty(),
            "shard root required",
        )?;
        ensure(!request.witness_root.is_empty(), "witness root required")?;
        ensure(
            !request.pq_key_commitment.is_empty(),
            "pq key commitment required",
        )?;
        ensure(request.ciphertext_bytes > 0, "ciphertext bytes is zero")?;
        ensure(
            request.ciphertext_bytes <= self.config.max_blob_bytes,
            "ciphertext too large",
        )?;
        ensure(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "hint privacy set too small",
        )?;
        self.counters.next_hint_nonce += 1;
        let blob_hint_id = deterministic_id(
            "blob-hint",
            self.counters.next_hint_nonce,
            &request.lane_id,
            &request.encrypted_blob_root,
        );
        let hint = EncryptedBlobHint {
            blob_hint_id: blob_hint_id.clone(),
            lane_id: request.lane_id,
            encrypted_blob_root: request.encrypted_blob_root,
            encrypted_metadata_root: request.encrypted_metadata_root,
            ciphertext_bytes: request.ciphertext_bytes,
            erasure_shard_root: request.erasure_shard_root,
            witness_root: request.witness_root,
            fee_cap_microunits: request.fee_cap_microunits,
            privacy_set_size: request.privacy_set_size,
            pq_key_commitment: request.pq_key_commitment,
            status: BlobHintStatus::Published,
            created_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.hint_ttl_slots,
        };
        self.counters.hints_published += 1;
        self.append_public_record(hint.public_record());
        self.encrypted_blob_hints.insert(blob_hint_id.clone(), hint);
        self.refresh_roots();
        Ok(blob_hint_id)
    }

    pub fn reserve_da(&mut self, request: ReserveDaRequest) -> Result<String> {
        ensure(
            self.reservations.len() < self.config.max_reservations,
            "reservation capacity reached",
        )?;
        ensure(
            !self
                .consumed_nullifiers
                .contains(&request.reservation_nullifier),
            "reservation nullifier already used",
        )?;
        ensure(
            !request.requester_commitment.is_empty(),
            "requester commitment required",
        )?;
        ensure(
            !request.reservation_nullifier.is_empty(),
            "reservation nullifier required",
        )?;
        let hint = self
            .encrypted_blob_hints
            .get(&request.blob_hint_id)
            .ok_or_else(|| "hint not found".to_string())?;
        ensure(hint.status.live(), "hint is not live")?;
        ensure(
            request.max_fee_microunits <= hint.fee_cap_microunits,
            "reservation fee exceeds hint cap",
        )?;
        let lane = self
            .fetch_lanes
            .get(&hint.lane_id)
            .ok_or_else(|| "lane not found".to_string())?;
        ensure(lane.status.accepts_work(), "lane does not accept work")?;
        ensure(
            lane.reserved_bytes_current_slot + hint.ciphertext_bytes
                <= lane
                    .max_bytes_per_slot
                    .min(self.config.max_reserved_bytes_per_slot),
            "lane slot byte limit reached",
        )?;
        self.counters.next_reservation_nonce += 1;
        let priority_score = lane.priority_weight
            + request.priority_boost_bps
            + privacy_bonus(hint.privacy_set_size, self.config.target_privacy_set_size);
        let reservation_id = deterministic_id(
            "da-reservation",
            self.counters.next_reservation_nonce,
            &request.blob_hint_id,
            &request.reservation_nullifier,
        );
        let reservation = DaReservation {
            reservation_id: reservation_id.clone(),
            lane_id: hint.lane_id.clone(),
            blob_hint_id: request.blob_hint_id.clone(),
            requester_commitment: request.requester_commitment,
            reservation_nullifier: request.reservation_nullifier.clone(),
            status: ReservationStatus::Reserved,
            blob_bytes: hint.ciphertext_bytes,
            witness_bytes: request
                .witness_bytes
                .min(self.config.max_witness_bytes_per_fetch),
            max_fee_microunits: request.max_fee_microunits,
            priority_score,
            scheduled_slot: self.current_slot + self.config.prefetch_lookahead_slots,
            created_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.reservation_ttl_slots,
            availability_root: empty_root("availability"),
        };
        if let Some(lane) = self.fetch_lanes.get_mut(&reservation.lane_id) {
            lane.reserved_bytes_current_slot += reservation.blob_bytes;
            lane.updated_at_slot = self.current_slot;
        }
        if let Some(hint) = self.encrypted_blob_hints.get_mut(&request.blob_hint_id) {
            hint.status = BlobHintStatus::Selected;
        }
        self.consumed_nullifiers
            .insert(request.reservation_nullifier);
        self.counters.reservations_opened += 1;
        self.counters.total_reserved_bytes += u128::from(reservation.blob_bytes);
        self.counters.total_witness_bytes += u128::from(reservation.witness_bytes);
        self.counters.total_fee_budget_microunits += reservation.max_fee_microunits;
        self.append_public_record(reservation.public_record());
        self.reservations
            .insert(reservation_id.clone(), reservation);
        self.refresh_roots();
        Ok(reservation_id)
    }

    pub fn schedule_fetch(&mut self, reservation_id: &str, slot: u64) -> Result<()> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?;
        ensure(reservation.status.live(), "reservation is not live")?;
        ensure(
            slot <= reservation.expires_at_slot,
            "slot exceeds reservation ttl",
        )?;
        reservation.scheduled_slot = slot;
        reservation.status = ReservationStatus::Scheduled;
        self.counters.reservations_scheduled += 1;
        self.append_public_record(reservation.public_record());
        self.refresh_roots();
        Ok(())
    }

    pub fn start_witness_fetch(&mut self, reservation_id: &str, observed_slot: u64) -> Result<()> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?;
        ensure(reservation.status.live(), "reservation is not live")?;
        ensure(
            observed_slot <= reservation.expires_at_slot,
            "reservation expired",
        )?;
        reservation.status = ReservationStatus::Fetching;
        let blob_hint_id = reservation.blob_hint_id.clone();
        if let Some(hint) = self.encrypted_blob_hints.get_mut(&blob_hint_id) {
            hint.status = BlobHintStatus::Fetching;
        }
        self.counters.witness_fetches_started += 1;
        self.append_public_record(reservation.public_record());
        self.refresh_roots();
        Ok(())
    }

    pub fn attest_availability(&mut self, request: AttestAvailabilityRequest) -> Result<String> {
        ensure(
            self.availability_attestations.len() < self.config.max_attestations,
            "attestation capacity reached",
        )?;
        ensure(!request.attester_commitment.is_empty(), "attester required")?;
        ensure(
            !request.pq_public_key_root.is_empty(),
            "pq key root required",
        )?;
        ensure(
            !request.pq_signature_root.is_empty(),
            "pq signature required",
        )?;
        ensure(
            !request.availability_root.is_empty(),
            "availability root required",
        )?;
        ensure(
            request.attester_weight_bps <= MAX_BPS,
            "attester weight too high",
        )?;
        let reservation = self
            .reservations
            .get(&request.reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?;
        ensure(reservation.status.live(), "reservation is not live")?;
        let blob_hint_id = reservation.blob_hint_id.clone();
        self.counters.next_attestation_nonce += 1;
        let attestation_id = deterministic_id(
            "availability-attestation",
            self.counters.next_attestation_nonce,
            &request.reservation_id,
            &request.attester_commitment,
        );
        let attestation = PqAvailabilityAttestation {
            attestation_id: attestation_id.clone(),
            reservation_id: request.reservation_id.clone(),
            blob_hint_id: blob_hint_id.clone(),
            attester_commitment: request.attester_commitment,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            availability_root: request.availability_root,
            verdict: request.verdict,
            attester_weight_bps: request.attester_weight_bps,
            observed_slot: request.observed_slot,
            expires_at_slot: request.observed_slot + self.config.attestation_ttl_slots,
        };
        self.availability_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.counters.attestations_recorded += 1;
        if request.verdict.is_positive() {
            let weight = self.positive_attestation_weight(&request.reservation_id);
            if weight >= self.config.quorum_weight_bps {
                self.mark_available(&request.reservation_id, &attestation.availability_root)?;
            }
        }
        self.append_public_record(attestation.public_record());
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn open_low_fee_priority_lane(
        &mut self,
        request: OpenLowFeePriorityLaneRequest,
    ) -> Result<String> {
        ensure(
            self.priority_lanes.len() < self.config.max_priority_lanes,
            "priority lane capacity reached",
        )?;
        ensure(
            self.fetch_lanes.contains_key(&request.lane_id),
            "fetch lane not found",
        )?;
        ensure(!request.sponsor_commitment.is_empty(), "sponsor required")?;
        ensure(!request.fee_asset_id.is_empty(), "fee asset required")?;
        ensure(request.remaining_budget_microunits > 0, "budget is zero")?;
        ensure(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "max fee bps too high",
        )?;
        ensure(
            request.priority_boost_bps <= self.config.low_fee_boost_bps,
            "priority boost too high",
        )?;
        ensure(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "priority lane privacy set too small",
        )?;
        self.counters.next_priority_lane_nonce += 1;
        let priority_lane_id = deterministic_id(
            "low-fee-priority-lane",
            self.counters.next_priority_lane_nonce,
            &request.lane_id,
            &request.sponsor_commitment,
        );
        let lane = LowFeePriorityLane {
            priority_lane_id: priority_lane_id.clone(),
            lane_id: request.lane_id,
            sponsor_commitment: request.sponsor_commitment,
            status: PriorityLaneStatus::Active,
            fee_asset_id: request.fee_asset_id,
            remaining_budget_microunits: request.remaining_budget_microunits,
            max_fee_bps: request.max_fee_bps,
            priority_boost_bps: request.priority_boost_bps,
            privacy_set_size: request.privacy_set_size,
            opened_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + request.ttl_slots,
        };
        self.append_public_record(lane.public_record());
        self.priority_lanes.insert(priority_lane_id.clone(), lane);
        self.refresh_roots();
        Ok(priority_lane_id)
    }

    pub fn promote_low_fee_reservation(
        &mut self,
        reservation_id: &str,
        priority_lane_id: &str,
    ) -> Result<()> {
        let priority_lane = self
            .priority_lanes
            .get_mut(priority_lane_id)
            .ok_or_else(|| "priority lane not found".to_string())?;
        ensure(priority_lane.status.usable(), "priority lane not usable")?;
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?;
        ensure(reservation.status.live(), "reservation is not live")?;
        ensure(
            reservation.lane_id == priority_lane.lane_id,
            "priority lane mismatch",
        )?;
        ensure(
            reservation.max_fee_microunits <= priority_lane.remaining_budget_microunits,
            "priority lane budget too low",
        )?;
        reservation.priority_score += priority_lane.priority_boost_bps;
        priority_lane.remaining_budget_microunits -= reservation.max_fee_microunits;
        if priority_lane.remaining_budget_microunits == 0 {
            priority_lane.status = PriorityLaneStatus::Exhausted;
        }
        self.counters.low_fee_promotions += 1;
        self.append_public_record(reservation.public_record());
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_blob(&mut self, request: QuarantineBlobRequest) -> Result<String> {
        ensure(
            self.quarantined_blobs.len() < self.config.max_quarantined_blobs,
            "quarantine capacity reached",
        )?;
        let hint = self
            .encrypted_blob_hints
            .get_mut(&request.blob_hint_id)
            .ok_or_else(|| "hint not found".to_string())?;
        ensure(!request.evidence_root.is_empty(), "evidence root required")?;
        self.counters.next_quarantine_nonce += 1;
        let quarantine_id = deterministic_id(
            "quarantined-blob",
            self.counters.next_quarantine_nonce,
            &request.blob_hint_id,
            &request.evidence_root,
        );
        hint.status = BlobHintStatus::Quarantined;
        let reservation_id = request.reservation_id.clone();
        if let Some(reservation_id) = reservation_id.as_ref() {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Quarantined;
            }
        }
        let quarantined = QuarantinedBlob {
            quarantine_id: quarantine_id.clone(),
            blob_hint_id: request.blob_hint_id,
            reservation_id,
            lane_id: hint.lane_id.clone(),
            reason: request.reason,
            evidence_root: request.evidence_root,
            quarantined_at_slot: self.current_slot,
            releases_at_slot: self.current_slot + self.config.quarantine_ttl_slots,
            stale_after_slot: self.current_slot + self.config.stale_after_slots,
        };
        self.counters.quarantine_events += 1;
        self.append_public_record(quarantined.public_record());
        self.quarantined_blobs
            .insert(quarantine_id.clone(), quarantined);
        self.refresh_roots();
        Ok(quarantine_id)
    }

    pub fn deterministic_schedule(&self, limit: usize) -> Vec<String> {
        let mut scored = self
            .reservations
            .values()
            .filter(|reservation| reservation.status.live())
            .map(|reservation| {
                let age = self
                    .current_slot
                    .saturating_sub(reservation.created_at_slot);
                let urgency = reservation
                    .expires_at_slot
                    .saturating_sub(self.current_slot)
                    .max(1);
                let score =
                    reservation.priority_score + age.saturating_mul(10) + (10_000 / urgency);
                (std::cmp::Reverse(score), reservation.reservation_id.clone())
            })
            .collect::<Vec<_>>();
        scored.sort();
        scored.into_iter().take(limit).map(|(_, id)| id).collect()
    }

    fn positive_attestation_weight(&self, reservation_id: &str) -> u64 {
        self.availability_attestations
            .values()
            .filter(|attestation| {
                attestation.reservation_id == reservation_id && attestation.verdict.is_positive()
            })
            .map(|attestation| attestation.attester_weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    fn mark_available(&mut self, reservation_id: &str, availability_root: &str) -> Result<()> {
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?;
        reservation.status = ReservationStatus::Warmed;
        reservation.availability_root = availability_root.to_string();
        if let Some(hint) = self.encrypted_blob_hints.get_mut(&reservation.blob_hint_id) {
            hint.status = BlobHintStatus::Attested;
        }
        self.counters.availability_quorum_reached += 1;
        Ok(())
    }

    fn expire_stale_records(&mut self) {
        for reservation in self.reservations.values_mut() {
            if reservation.status.live() && reservation.expires_at_slot <= self.current_slot {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for hint in self.encrypted_blob_hints.values_mut() {
            if hint.status.live() && hint.expires_at_slot <= self.current_slot {
                hint.status = BlobHintStatus::Expired;
            }
        }
        for priority_lane in self.priority_lanes.values_mut() {
            if priority_lane.status.usable() && priority_lane.expires_at_slot <= self.current_slot {
                priority_lane.status = PriorityLaneStatus::Retired;
            }
        }
        for lane in self.fetch_lanes.values_mut() {
            lane.reserved_bytes_current_slot = 0;
        }
    }

    fn append_public_record(&mut self, value: Value) {
        self.public_records.push(value);
        trim_vec(&mut self.public_records, self.config.max_public_records);
    }
}

impl Default for State {
    fn default() -> Self {
        State::new(Config::default()).expect("default config")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RegisterFetchLaneRequest {
    pub lane_id: Option<String>,
    pub kind: FetchLaneKind,
    pub operator_commitment: String,
    pub shard_set_root: String,
    pub max_inflight_reservations: u64,
    pub max_bytes_per_slot: u64,
    pub priority_weight: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublishEncryptedBlobHintRequest {
    pub lane_id: String,
    pub encrypted_blob_root: String,
    pub encrypted_metadata_root: String,
    pub ciphertext_bytes: u64,
    pub erasure_shard_root: String,
    pub witness_root: String,
    pub fee_cap_microunits: u128,
    pub privacy_set_size: u64,
    pub pq_key_commitment: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReserveDaRequest {
    pub blob_hint_id: String,
    pub requester_commitment: String,
    pub reservation_nullifier: String,
    pub witness_bytes: u64,
    pub max_fee_microunits: u128,
    pub priority_boost_bps: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AttestAvailabilityRequest {
    pub reservation_id: String,
    pub attester_commitment: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub availability_root: String,
    pub verdict: AvailabilityVerdict,
    pub attester_weight_bps: u64,
    pub observed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenLowFeePriorityLaneRequest {
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub remaining_budget_microunits: u128,
    pub max_fee_bps: u64,
    pub priority_boost_bps: u64,
    pub privacy_set_size: u64,
    pub ttl_slots: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct QuarantineBlobRequest {
    pub blob_hint_id: String,
    pub reservation_id: Option<String>,
    pub reason: QuarantineReason,
    pub evidence_root: String,
}

pub fn devnet() -> State {
    let mut config = Config::default();
    config.allow_devnet_shortcuts = true;
    let mut state = State::new(config).expect("devnet config");
    state.l2_height = DEVNET_L2_HEIGHT;
    state.monero_height = DEVNET_MONERO_HEIGHT;
    state.current_slot = 8_192;
    state
        .register_fetch_lane(RegisterFetchLaneRequest {
            lane_id: Some("devnet-da-blob-fast".to_string()),
            kind: FetchLaneKind::BlobFast,
            operator_commitment: fixed_hash("devnet-da-operator-a"),
            shard_set_root: fixed_hash("devnet-da-shard-set-a"),
            max_inflight_reservations: 2_048,
            max_bytes_per_slot: 32 * 1024 * 1024,
            priority_weight: 240,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("register blob lane");
    state
        .register_fetch_lane(RegisterFetchLaneRequest {
            lane_id: Some("devnet-witness-fetch-fast".to_string()),
            kind: FetchLaneKind::WitnessFast,
            operator_commitment: fixed_hash("devnet-da-operator-b"),
            shard_set_root: fixed_hash("devnet-witness-shard-set-a"),
            max_inflight_reservations: 4_096,
            max_bytes_per_slot: 48 * 1024 * 1024,
            priority_weight: 320,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        })
        .expect("register witness lane");
    state
        .open_low_fee_priority_lane(OpenLowFeePriorityLaneRequest {
            lane_id: "devnet-witness-fetch-fast".to_string(),
            sponsor_commitment: fixed_hash("devnet-low-fee-da-sponsor"),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            remaining_budget_microunits: 2_500_000,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            priority_boost_bps: DEFAULT_LOW_FEE_BOOST_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            ttl_slots: 512,
        })
        .expect("open low fee priority lane");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let hint_id = state
        .publish_encrypted_blob_hint(PublishEncryptedBlobHintRequest {
            lane_id: "devnet-witness-fetch-fast".to_string(),
            encrypted_blob_root: fixed_hash("demo-encrypted-da-blob"),
            encrypted_metadata_root: fixed_hash("demo-encrypted-da-metadata"),
            ciphertext_bytes: 384 * 1024,
            erasure_shard_root: fixed_hash("demo-erasure-shards"),
            witness_root: fixed_hash("demo-witness-root"),
            fee_cap_microunits: 12_500,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_key_commitment: fixed_hash("demo-pq-key-commitment"),
        })
        .expect("publish demo hint");
    let reservation_id = state
        .reserve_da(ReserveDaRequest {
            blob_hint_id: hint_id.clone(),
            requester_commitment: fixed_hash("demo-requester"),
            reservation_nullifier: fixed_hash("demo-reservation-nullifier"),
            witness_bytes: 128 * 1024,
            max_fee_microunits: 9_000,
            priority_boost_bps: 100,
        })
        .expect("reserve demo da");
    state
        .promote_low_fee_reservation(&reservation_id, "low-fee-priority-lane-1e26fd9e8cf46a5f")
        .ok();
    state
        .schedule_fetch(&reservation_id, state.current_slot + 2)
        .expect("schedule demo fetch");
    state
        .start_witness_fetch(&reservation_id, state.current_slot + 2)
        .expect("start demo fetch");
    state
        .attest_availability(AttestAvailabilityRequest {
            reservation_id: reservation_id.clone(),
            attester_commitment: fixed_hash("demo-attester-a"),
            pq_public_key_root: fixed_hash("demo-attester-pq-key-a"),
            pq_signature_root: fixed_hash("demo-attester-pq-signature-a"),
            availability_root: fixed_hash("demo-availability-root"),
            verdict: AvailabilityVerdict::Available,
            attester_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            observed_slot: state.current_slot + 2,
        })
        .expect("attest demo availability");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn privacy_bonus(privacy_set_size: u64, target_privacy_set_size: u64) -> u64 {
    if target_privacy_set_size == 0 {
        return 0;
    }
    privacy_set_size
        .saturating_mul(1_000)
        .checked_div(target_privacy_set_size)
        .unwrap_or(0)
        .min(1_000)
}

fn fixed_hash(label: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-da-prefetch-scheduler:fixed",
        &[HashPart::Str(label)],
        32,
    )
}

fn deterministic_id(prefix: &str, nonce: u64, left: &str, right: &str) -> String {
    let digest = domain_hash(
        "private-l2-fast-pq-confidential-da-prefetch-scheduler:id",
        &[
            HashPart::Str(prefix),
            HashPart::U64(nonce),
            HashPart::Str(left),
            HashPart::Str(right),
        ],
        8,
    );
    format!("{prefix}-{digest}")
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-da-prefetch-scheduler:empty",
        &[HashPart::Str(label)],
        32,
    )
}

fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-da-prefetch-scheduler:record",
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn map_root<T>(label: &str, map: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-da-prefetch-scheduler:{label}"),
        &leaves,
    )
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-da-prefetch-scheduler:{label}"),
        &leaves,
    )
}

fn trim_vec<T>(items: &mut Vec<T>, max_len: usize) {
    if items.len() > max_len {
        let remove = items.len() - max_len;
        items.drain(0..remove);
    }
}
