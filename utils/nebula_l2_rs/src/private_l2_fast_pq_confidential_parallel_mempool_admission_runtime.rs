use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelMempoolAdmissionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-parallel-mempool-admission-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_PROTOCOL_VERSION;
pub const MODULE_PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_INTENT_SCHEME: &str =
    "x25519-ml-kem-1024-confidential-intent-envelope-v1";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_ATTESTATION_SCHEME:
    &str = "ml-dsa-87+slh-dsa-shake-192f-admission-attestation-v1";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_FAIR_ORDERING_SCHEME: &str =
    "vrf-commit-reveal-deficit-round-robin-private-mempool-v1";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_PRECONF_SCHEME: &str =
    "low-latency-confidential-preconfirmation-window-v1";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_BACKPRESSURE_SCHEME:
    &str = "privacy-preserving-shard-backpressure-and-dos-budget-v1";
pub const DEFAULT_SHARD_COUNT: u16 = 16;
pub const DEFAULT_SHARD_QUEUE_LIMIT: usize = 2_048;
pub const DEFAULT_LOW_FEE_QUEUE_LIMIT: usize = 8_192;
pub const DEFAULT_PARALLEL_WORKERS: u16 = 8;
pub const DEFAULT_MAX_INTENT_BYTES: u64 = 96_000;
pub const DEFAULT_MAX_BUNDLE_BYTES: u64 = 384_000;
pub const DEFAULT_PRECONF_WINDOW_MS: u64 = 450;
pub const DEFAULT_PRECONF_MAX_INTENTS: u16 = 256;
pub const DEFAULT_PRECONF_MAX_WEIGHT: u64 = 2_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_FAIR_ORDERING_EPOCH_BLOCKS: u64 = 4;
pub const DEFAULT_LOW_FEE_LANE_WEIGHT_BPS: u16 = 1_500;
pub const DEFAULT_PRIORITY_LANE_WEIGHT_BPS: u16 = 6_500;
pub const DEFAULT_BACKGROUND_LANE_WEIGHT_BPS: u16 = 2_000;
pub const DEFAULT_MIN_FEE_MICRO_UNITS: u64 = 10;
pub const DEFAULT_LOW_FEE_MICRO_UNITS: u64 = 25;
pub const DEFAULT_PRIORITY_FEE_MICRO_UNITS: u64 = 250;
pub const DEFAULT_ACCOUNT_BURST_CREDITS: u64 = 64;
pub const DEFAULT_ACCOUNT_REFILL_PER_WINDOW: u64 = 8;
pub const DEFAULT_NULLIFIER_REPLAY_CACHE_LIMIT: usize = 262_144;
pub const DEFAULT_ATTESTATION_CACHE_LIMIT: usize = 524_288;
pub const DEFAULT_PUBLIC_RECORD_LIMIT: usize = 1_048_576;
pub const DEFAULT_BACKPRESSURE_SOFT_BPS: u16 = 7_000;
pub const DEFAULT_BACKPRESSURE_HARD_BPS: u16 = 9_000;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Priority,
    Standard,
    LowFee,
    Background,
    Quarantine,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::Standard => "standard",
            Self::LowFee => "low_fee",
            Self::Background => "background",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn service_weight_bps(self, config: &Config) -> u16 {
        match self {
            Self::Priority => config.priority_lane_weight_bps,
            Self::Standard => 10_000_u16.saturating_sub(
                config
                    .priority_lane_weight_bps
                    .saturating_add(config.low_fee_lane_weight_bps)
                    .saturating_add(config.background_lane_weight_bps),
            ),
            Self::LowFee => config.low_fee_lane_weight_bps,
            Self::Background => config.background_lane_weight_bps,
            Self::Quarantine => 0,
        }
    }

    pub fn admits_user_flow(self) -> bool {
        matches!(
            self,
            Self::Priority | Self::Standard | Self::LowFee | Self::Background
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Received,
    Queued,
    Attested,
    Preconfirmed,
    Admitted,
    Deferred,
    Rejected,
    Quarantined,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Queued => "queued",
            Self::Attested => "attested",
            Self::Preconfirmed => "preconfirmed",
            Self::Admitted => "admitted",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Received | Self::Queued | Self::Attested | Self::Preconfirmed | Self::Deferred
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Admitted | Self::Rejected | Self::Quarantined | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Accept,
    Defer,
    LowFeeLane,
    Backpressure,
    Reject,
    Quarantine,
}

impl AdmissionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Defer => "defer",
            Self::LowFeeLane => "low_fee_lane",
            Self::Backpressure => "backpressure",
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakSecurity,
    BadDomain,
    Replayed,
    Expired,
    Revoked,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakSecurity => "weak_security",
            Self::BadDomain => "bad_domain",
            Self::Replayed => "replayed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Open,
    Filling,
    Sealed,
    Published,
    Expired,
}

impl PreconfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Filling => "filling",
            Self::Sealed => "sealed",
            Self::Published => "published",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureLevel {
    Clear,
    Soft,
    Hard,
    ShedLowFee,
    Emergency,
}

impl BackpressureLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Soft => "soft",
            Self::Hard => "hard",
            Self::ShedLowFee => "shed_low_fee",
            Self::Emergency => "emergency",
        }
    }

    pub fn admits_low_fee(self) -> bool {
        matches!(self, Self::Clear | Self::Soft)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DosSignalKind {
    AccountBurst,
    NullifierReplay,
    OversizeEnvelope,
    WeakPqProof,
    ShardFlood,
    DuplicateCommitment,
    FeeStarvation,
    ExpiredIntent,
}

impl DosSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountBurst => "account_burst",
            Self::NullifierReplay => "nullifier_replay",
            Self::OversizeEnvelope => "oversize_envelope",
            Self::WeakPqProof => "weak_pq_proof",
            Self::ShardFlood => "shard_flood",
            Self::DuplicateCommitment => "duplicate_commitment",
            Self::FeeStarvation => "fee_starvation",
            Self::ExpiredIntent => "expired_intent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub monero_network: String,
    pub l2_network: String,
    pub shard_count: u16,
    pub shard_queue_limit: usize,
    pub low_fee_queue_limit: usize,
    pub parallel_workers: u16,
    pub max_intent_bytes: u64,
    pub max_bundle_bytes: u64,
    pub preconfirmation_window_ms: u64,
    pub preconfirmation_max_intents: u16,
    pub preconfirmation_max_weight: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub fair_ordering_epoch_blocks: u64,
    pub low_fee_lane_weight_bps: u16,
    pub priority_lane_weight_bps: u16,
    pub background_lane_weight_bps: u16,
    pub min_fee_micro_units: u64,
    pub low_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub account_burst_credits: u64,
    pub account_refill_per_window: u64,
    pub nullifier_replay_cache_limit: usize,
    pub attestation_cache_limit: usize,
    pub public_record_limit: usize,
    pub backpressure_soft_bps: u16,
    pub backpressure_hard_bps: u16,
    pub quarantine_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            monero_network:
                PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_MONERO_NETWORK
                    .to_string(),
            l2_network:
                PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_L2_NETWORK
                    .to_string(),
            shard_count: DEFAULT_SHARD_COUNT,
            shard_queue_limit: DEFAULT_SHARD_QUEUE_LIMIT,
            low_fee_queue_limit: DEFAULT_LOW_FEE_QUEUE_LIMIT,
            parallel_workers: DEFAULT_PARALLEL_WORKERS,
            max_intent_bytes: DEFAULT_MAX_INTENT_BYTES,
            max_bundle_bytes: DEFAULT_MAX_BUNDLE_BYTES,
            preconfirmation_window_ms: DEFAULT_PRECONF_WINDOW_MS,
            preconfirmation_max_intents: DEFAULT_PRECONF_MAX_INTENTS,
            preconfirmation_max_weight: DEFAULT_PRECONF_MAX_WEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            fair_ordering_epoch_blocks: DEFAULT_FAIR_ORDERING_EPOCH_BLOCKS,
            low_fee_lane_weight_bps: DEFAULT_LOW_FEE_LANE_WEIGHT_BPS,
            priority_lane_weight_bps: DEFAULT_PRIORITY_LANE_WEIGHT_BPS,
            background_lane_weight_bps: DEFAULT_BACKGROUND_LANE_WEIGHT_BPS,
            min_fee_micro_units: DEFAULT_MIN_FEE_MICRO_UNITS,
            low_fee_micro_units: DEFAULT_LOW_FEE_MICRO_UNITS,
            priority_fee_micro_units: DEFAULT_PRIORITY_FEE_MICRO_UNITS,
            account_burst_credits: DEFAULT_ACCOUNT_BURST_CREDITS,
            account_refill_per_window: DEFAULT_ACCOUNT_REFILL_PER_WINDOW,
            nullifier_replay_cache_limit: DEFAULT_NULLIFIER_REPLAY_CACHE_LIMIT,
            attestation_cache_limit: DEFAULT_ATTESTATION_CACHE_LIMIT,
            public_record_limit: DEFAULT_PUBLIC_RECORD_LIMIT,
            backpressure_soft_bps: DEFAULT_BACKPRESSURE_SOFT_BPS,
            backpressure_hard_bps: DEFAULT_BACKPRESSURE_HARD_BPS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.shard_count == 0 {
            return Err("shard count must be nonzero".to_string());
        }
        if self.parallel_workers == 0 {
            return Err("parallel worker count must be nonzero".to_string());
        }
        if self.shard_queue_limit == 0 {
            return Err("shard queue limit must be nonzero".to_string());
        }
        if self.low_fee_queue_limit == 0 {
            return Err("low fee queue limit must be nonzero".to_string());
        }
        if self.max_intent_bytes == 0 || self.max_bundle_bytes < self.max_intent_bytes {
            return Err("invalid intent byte limits".to_string());
        }
        if self.preconfirmation_window_ms == 0
            || self.preconfirmation_max_intents == 0
            || self.preconfirmation_max_weight == 0
        {
            return Err("preconfirmation window limits must be nonzero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("pq security floor is below 128 bits".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("privacy set size must be nonzero".to_string());
        }
        let lane_weight = self
            .priority_lane_weight_bps
            .saturating_add(self.low_fee_lane_weight_bps)
            .saturating_add(self.background_lane_weight_bps);
        if lane_weight > 10_000 {
            return Err("lane service weights exceed 10000 bps".to_string());
        }
        if self.min_fee_micro_units > self.low_fee_micro_units
            || self.low_fee_micro_units > self.priority_fee_micro_units
        {
            return Err("fee floors must be monotonic".to_string());
        }
        if self.backpressure_soft_bps >= self.backpressure_hard_bps
            || self.backpressure_hard_bps > 10_000
        {
            return Err("invalid backpressure thresholds".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_SCHEMA_VERSION,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "hash_suite": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_HASH_SUITE,
            "intent_scheme": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_INTENT_SCHEME,
            "attestation_scheme": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_ATTESTATION_SCHEME,
            "fair_ordering_scheme": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_FAIR_ORDERING_SCHEME,
            "preconfirmation_scheme": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_PRECONF_SCHEME,
            "backpressure_scheme": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_BACKPRESSURE_SCHEME,
            "shard_count": self.shard_count,
            "shard_queue_limit": self.shard_queue_limit,
            "low_fee_queue_limit": self.low_fee_queue_limit,
            "parallel_workers": self.parallel_workers,
            "max_intent_bytes": self.max_intent_bytes,
            "max_bundle_bytes": self.max_bundle_bytes,
            "preconfirmation_window_ms": self.preconfirmation_window_ms,
            "preconfirmation_max_intents": self.preconfirmation_max_intents,
            "preconfirmation_max_weight": self.preconfirmation_max_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "fair_ordering_epoch_blocks": self.fair_ordering_epoch_blocks,
            "low_fee_lane_weight_bps": self.low_fee_lane_weight_bps,
            "priority_lane_weight_bps": self.priority_lane_weight_bps,
            "background_lane_weight_bps": self.background_lane_weight_bps,
            "min_fee_micro_units": self.min_fee_micro_units,
            "low_fee_micro_units": self.low_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "account_burst_credits": self.account_burst_credits,
            "account_refill_per_window": self.account_refill_per_window,
            "nullifier_replay_cache_limit": self.nullifier_replay_cache_limit,
            "attestation_cache_limit": self.attestation_cache_limit,
            "public_record_limit": self.public_record_limit,
            "backpressure_soft_bps": self.backpressure_soft_bps,
            "backpressure_hard_bps": self.backpressure_hard_bps,
            "quarantine_blocks": self.quarantine_blocks,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub encrypted_intents: u64,
    pub queued_intents: u64,
    pub attested_intents: u64,
    pub preconfirmed_intents: u64,
    pub admitted_intents: u64,
    pub deferred_intents: u64,
    pub rejected_intents: u64,
    pub quarantined_intents: u64,
    pub expired_intents: u64,
    pub pq_attestations: u64,
    pub accepted_pq_attestations: u64,
    pub replayed_pq_attestations: u64,
    pub fair_ordering_slots: u64,
    pub preconfirmation_windows: u64,
    pub sealed_preconfirmation_windows: u64,
    pub backpressure_events: u64,
    pub dos_signals: u64,
    pub low_fee_lane_entries: u64,
    pub low_fee_lane_admissions: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "encrypted_intents": self.encrypted_intents,
            "queued_intents": self.queued_intents,
            "attested_intents": self.attested_intents,
            "preconfirmed_intents": self.preconfirmed_intents,
            "admitted_intents": self.admitted_intents,
            "deferred_intents": self.deferred_intents,
            "rejected_intents": self.rejected_intents,
            "quarantined_intents": self.quarantined_intents,
            "expired_intents": self.expired_intents,
            "pq_attestations": self.pq_attestations,
            "accepted_pq_attestations": self.accepted_pq_attestations,
            "replayed_pq_attestations": self.replayed_pq_attestations,
            "fair_ordering_slots": self.fair_ordering_slots,
            "preconfirmation_windows": self.preconfirmation_windows,
            "sealed_preconfirmation_windows": self.sealed_preconfirmation_windows,
            "backpressure_events": self.backpressure_events,
            "dos_signals": self.dos_signals,
            "low_fee_lane_entries": self.low_fee_lane_entries,
            "low_fee_lane_admissions": self.low_fee_lane_admissions,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub intent_root: String,
    pub queue_root: String,
    pub attestation_root: String,
    pub ordering_root: String,
    pub preconfirmation_root: String,
    pub backpressure_root: String,
    pub low_fee_lane_root: String,
    pub dos_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        let empty = private_l2_fast_pq_confidential_parallel_mempool_admission_empty_root;
        let mut roots = Self {
            config_root: config.root(),
            intent_root: empty("INTENTS"),
            queue_root: empty("QUEUES"),
            attestation_root: empty("ATTESTATIONS"),
            ordering_root: empty("ORDERING"),
            preconfirmation_root: empty("PRECONFIRMATIONS"),
            backpressure_root: empty("BACKPRESSURE"),
            low_fee_lane_root: empty("LOW-FEE-LANES"),
            dos_root: empty("DOS"),
            public_record_root: empty("PUBLIC-RECORDS"),
            state_root: String::new(),
        };
        roots.state_root =
            private_l2_fast_pq_confidential_parallel_mempool_admission_roots_state_root(&roots);
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "queue_root": self.queue_root,
            "attestation_root": self.attestation_root,
            "ordering_root": self.ordering_root,
            "preconfirmation_root": self.preconfirmation_root,
            "backpressure_root": self.backpressure_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "dos_root": self.dos_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub account_bucket: String,
    pub shard_id: u16,
    pub lane: LaneKind,
    pub fee_micro_units: u64,
    pub weight_units: u64,
    pub encrypted_payload_root: String,
    pub ciphertext_bytes: u64,
    pub payload_commitment: String,
    pub nullifier_commitment: String,
    pub note_commitment_root: String,
    pub dependency_root: String,
    pub privacy_set_size: u64,
    pub pq_public_key_root: String,
    pub admission_hint_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: IntentStatus,
}

impl EncryptedIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: impl Into<String>,
        account_bucket: impl Into<String>,
        shard_id: u16,
        lane: LaneKind,
        fee_micro_units: u64,
        weight_units: u64,
        encrypted_payload_root: impl Into<String>,
        ciphertext_bytes: u64,
        payload_commitment: impl Into<String>,
        nullifier_commitment: impl Into<String>,
        note_commitment_root: impl Into<String>,
        dependency_root: impl Into<String>,
        privacy_set_size: u64,
        pq_public_key_root: impl Into<String>,
        admission_hint_root: impl Into<String>,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> Self {
        let owner_commitment = owner_commitment.into();
        let account_bucket = account_bucket.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let payload_commitment = payload_commitment.into();
        let nullifier_commitment = nullifier_commitment.into();
        let note_commitment_root = note_commitment_root.into();
        let dependency_root = dependency_root.into();
        let pq_public_key_root = pq_public_key_root.into();
        let admission_hint_root = admission_hint_root.into();
        let intent_id = private_l2_fast_pq_confidential_parallel_mempool_admission_intent_id(
            &owner_commitment,
            &account_bucket,
            shard_id,
            lane,
            &payload_commitment,
            &nullifier_commitment,
            submitted_at_height,
            nonce,
        );
        Self {
            intent_id,
            owner_commitment,
            account_bucket,
            shard_id,
            lane,
            fee_micro_units,
            weight_units,
            encrypted_payload_root,
            ciphertext_bytes,
            payload_commitment,
            nullifier_commitment,
            note_commitment_root,
            dependency_root,
            privacy_set_size,
            pq_public_key_root,
            admission_hint_root,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: IntentStatus::Received,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "account_bucket": self.account_bucket,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "fee_micro_units": self.fee_micro_units,
            "weight_units": self.weight_units,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_bytes": self.ciphertext_bytes,
            "payload_commitment": self.payload_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "note_commitment_root": self.note_commitment_root,
            "dependency_root": self.dependency_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_public_key_root": self.pq_public_key_root,
            "admission_hint_root": self.admission_hint_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "ENCRYPTED-INTENT",
            &self.public_record(),
        )
    }

    pub fn fair_key(&self, epoch_seed: &str) -> String {
        domain_hash(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-FAIR-KEY",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(epoch_seed),
                HashPart::Str(&self.intent_id),
                HashPart::Str(self.lane.as_str()),
                HashPart::Int(self.fee_micro_units as i128),
                HashPart::Int(self.weight_units as i128),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionAttestation {
    pub attestation_id: String,
    pub intent_id: String,
    pub attester_id: String,
    pub committee_root: String,
    pub admission_domain: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub decision: AdmissionDecision,
    pub status: AttestationStatus,
    pub security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl AdmissionAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        attester_id: impl Into<String>,
        committee_root: impl Into<String>,
        admission_domain: impl Into<String>,
        pq_signature_root: impl Into<String>,
        transcript_root: impl Into<String>,
        decision: AdmissionDecision,
        security_bits: u16,
        issued_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> Self {
        let intent_id = intent_id.into();
        let attester_id = attester_id.into();
        let committee_root = committee_root.into();
        let admission_domain = admission_domain.into();
        let pq_signature_root = pq_signature_root.into();
        let transcript_root = transcript_root.into();
        let attestation_id =
            private_l2_fast_pq_confidential_parallel_mempool_admission_attestation_id(
                &intent_id,
                &attester_id,
                &committee_root,
                &admission_domain,
                &pq_signature_root,
                issued_at_height,
                nonce,
            );
        Self {
            attestation_id,
            intent_id,
            attester_id,
            committee_root,
            admission_domain,
            pq_signature_root,
            transcript_root,
            decision,
            status: AttestationStatus::Submitted,
            security_bits,
            issued_at_height,
            expires_at_height,
            nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "intent_id": self.intent_id,
            "attester_id": self.attester_id,
            "committee_root": self.committee_root,
            "admission_domain": self.admission_domain,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "decision": self.decision.as_str(),
            "status": self.status.as_str(),
            "security_bits": self.security_bits,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "ADMISSION-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingSlot {
    pub slot_id: String,
    pub epoch: u64,
    pub shard_id: u16,
    pub lane: LaneKind,
    pub service_weight_bps: u16,
    pub ordering_seed: String,
    pub intent_root: String,
    pub ordered_intent_ids: Vec<String>,
    pub total_weight_units: u64,
    pub opened_at_height: u64,
    pub sequence: u64,
}

impl FairOrderingSlot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        shard_id: u16,
        lane: LaneKind,
        service_weight_bps: u16,
        ordering_seed: impl Into<String>,
        ordered_intent_ids: Vec<String>,
        total_weight_units: u64,
        opened_at_height: u64,
        sequence: u64,
    ) -> Self {
        let ordering_seed = ordering_seed.into();
        let intent_leaves = ordered_intent_ids
            .iter()
            .map(|intent_id| json!(intent_id))
            .collect::<Vec<_>>();
        let intent_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-ORDERED-INTENTS",
            &intent_leaves,
        );
        let slot_id = private_l2_fast_pq_confidential_parallel_mempool_admission_ordering_slot_id(
            epoch,
            shard_id,
            lane,
            &ordering_seed,
            &intent_root,
            opened_at_height,
            sequence,
        );
        Self {
            slot_id,
            epoch,
            shard_id,
            lane,
            service_weight_bps,
            ordering_seed,
            intent_root,
            ordered_intent_ids,
            total_weight_units,
            opened_at_height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "epoch": self.epoch,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "service_weight_bps": self.service_weight_bps,
            "ordering_seed": self.ordering_seed,
            "intent_root": self.intent_root,
            "ordered_intent_ids": self.ordered_intent_ids,
            "total_weight_units": self.total_weight_units,
            "opened_at_height": self.opened_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "FAIR-ORDERING-SLOT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationWindow {
    pub window_id: String,
    pub epoch: u64,
    pub shard_id: u16,
    pub lane: LaneKind,
    pub opened_at_height: u64,
    pub opened_at_ms: u64,
    pub closes_at_ms: u64,
    pub max_intents: u16,
    pub max_weight_units: u64,
    pub ordered_intent_root: String,
    pub admitted_intent_ids: Vec<String>,
    pub attestation_root: String,
    pub status: PreconfirmationStatus,
    pub preconfirmation_root: String,
    pub sequence: u64,
}

impl PreconfirmationWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        shard_id: u16,
        lane: LaneKind,
        opened_at_height: u64,
        opened_at_ms: u64,
        closes_at_ms: u64,
        max_intents: u16,
        max_weight_units: u64,
        admitted_intent_ids: Vec<String>,
        attestation_root: impl Into<String>,
        sequence: u64,
    ) -> Self {
        let attestation_root = attestation_root.into();
        let intent_leaves = admitted_intent_ids
            .iter()
            .map(|intent_id| json!(intent_id))
            .collect::<Vec<_>>();
        let ordered_intent_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-PRECONF-INTENTS",
            &intent_leaves,
        );
        let window_id =
            private_l2_fast_pq_confidential_parallel_mempool_admission_preconfirmation_window_id(
                epoch,
                shard_id,
                lane,
                opened_at_height,
                opened_at_ms,
                &ordered_intent_root,
                sequence,
            );
        let preconfirmation_root = domain_hash(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-PRECONFIRMATION-ROOT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&window_id),
                HashPart::Str(&ordered_intent_root),
                HashPart::Str(&attestation_root),
                HashPart::Int(max_weight_units as i128),
            ],
            32,
        );
        Self {
            window_id,
            epoch,
            shard_id,
            lane,
            opened_at_height,
            opened_at_ms,
            closes_at_ms,
            max_intents,
            max_weight_units,
            ordered_intent_root,
            admitted_intent_ids,
            attestation_root,
            status: PreconfirmationStatus::Open,
            preconfirmation_root,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "epoch": self.epoch,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "opened_at_height": self.opened_at_height,
            "opened_at_ms": self.opened_at_ms,
            "closes_at_ms": self.closes_at_ms,
            "max_intents": self.max_intents,
            "max_weight_units": self.max_weight_units,
            "ordered_intent_root": self.ordered_intent_root,
            "admitted_intent_ids": self.admitted_intent_ids,
            "attestation_root": self.attestation_root,
            "status": self.status.as_str(),
            "preconfirmation_root": self.preconfirmation_root,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "PRECONFIRMATION-WINDOW",
            &self.public_record(),
        )
    }

    pub fn remaining_slots(&self) -> usize {
        (self.max_intents as usize).saturating_sub(self.admitted_intent_ids.len())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardQueue {
    pub shard_id: u16,
    pub queue_id: String,
    pub priority: Vec<String>,
    pub standard: Vec<String>,
    pub low_fee: Vec<String>,
    pub background: Vec<String>,
    pub quarantine: Vec<String>,
    pub inflight: Vec<String>,
    pub dropped: Vec<String>,
    pub backpressure_level: BackpressureLevel,
    pub last_ordering_seed: String,
    pub last_updated_height: u64,
}

impl ShardQueue {
    pub fn new(shard_id: u16, last_updated_height: u64) -> Self {
        let queue_id = private_l2_fast_pq_confidential_parallel_mempool_admission_queue_id(
            shard_id,
            last_updated_height,
        );
        Self {
            shard_id,
            queue_id,
            priority: Vec::new(),
            standard: Vec::new(),
            low_fee: Vec::new(),
            background: Vec::new(),
            quarantine: Vec::new(),
            inflight: Vec::new(),
            dropped: Vec::new(),
            backpressure_level: BackpressureLevel::Clear,
            last_ordering_seed:
                private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                    "queue-seed",
                    &format!("shard-{shard_id}"),
                ),
            last_updated_height,
        }
    }

    pub fn len(&self) -> usize {
        self.priority.len()
            + self.standard.len()
            + self.low_fee.len()
            + self.background.len()
            + self.quarantine.len()
            + self.inflight.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lane_len(&self, lane: LaneKind) -> usize {
        match lane {
            LaneKind::Priority => self.priority.len(),
            LaneKind::Standard => self.standard.len(),
            LaneKind::LowFee => self.low_fee.len(),
            LaneKind::Background => self.background.len(),
            LaneKind::Quarantine => self.quarantine.len(),
        }
    }

    pub fn push(&mut self, lane: LaneKind, intent_id: String) {
        match lane {
            LaneKind::Priority => self.priority.push(intent_id),
            LaneKind::Standard => self.standard.push(intent_id),
            LaneKind::LowFee => self.low_fee.push(intent_id),
            LaneKind::Background => self.background.push(intent_id),
            LaneKind::Quarantine => self.quarantine.push(intent_id),
        }
    }

    pub fn remove_intent(&mut self, intent_id: &str) -> bool {
        remove_first(&mut self.priority, intent_id)
            || remove_first(&mut self.standard, intent_id)
            || remove_first(&mut self.low_fee, intent_id)
            || remove_first(&mut self.background, intent_id)
            || remove_first(&mut self.quarantine, intent_id)
            || remove_first(&mut self.inflight, intent_id)
    }

    pub fn pop_lane(&mut self, lane: LaneKind) -> Option<String> {
        match lane {
            LaneKind::Priority => pop_front_vec(&mut self.priority),
            LaneKind::Standard => pop_front_vec(&mut self.standard),
            LaneKind::LowFee => pop_front_vec(&mut self.low_fee),
            LaneKind::Background => pop_front_vec(&mut self.background),
            LaneKind::Quarantine => None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "queue_id": self.queue_id,
            "priority": self.priority,
            "standard": self.standard,
            "low_fee": self.low_fee,
            "background": self.background,
            "quarantine": self.quarantine,
            "inflight": self.inflight,
            "dropped": self.dropped,
            "backpressure_level": self.backpressure_level.as_str(),
            "last_ordering_seed": self.last_ordering_seed,
            "last_updated_height": self.last_updated_height,
            "length": self.len(),
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "SHARD-QUEUE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeLane {
    pub lane_id: String,
    pub shard_id: u16,
    pub reserve_weight_bps: u16,
    pub fee_floor_micro_units: u64,
    pub queue_limit: usize,
    pub sponsor_pool_root: String,
    pub queued_intent_ids: Vec<String>,
    pub admitted_intent_ids: Vec<String>,
    pub rebate_policy_root: String,
    pub opened_at_height: u64,
    pub sequence: u64,
}

impl LowFeeLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: u16,
        reserve_weight_bps: u16,
        fee_floor_micro_units: u64,
        queue_limit: usize,
        sponsor_pool_root: impl Into<String>,
        rebate_policy_root: impl Into<String>,
        opened_at_height: u64,
        sequence: u64,
    ) -> Self {
        let sponsor_pool_root = sponsor_pool_root.into();
        let rebate_policy_root = rebate_policy_root.into();
        let lane_id = private_l2_fast_pq_confidential_parallel_mempool_admission_low_fee_lane_id(
            shard_id,
            reserve_weight_bps,
            fee_floor_micro_units,
            &sponsor_pool_root,
            opened_at_height,
            sequence,
        );
        Self {
            lane_id,
            shard_id,
            reserve_weight_bps,
            fee_floor_micro_units,
            queue_limit,
            sponsor_pool_root,
            queued_intent_ids: Vec::new(),
            admitted_intent_ids: Vec::new(),
            rebate_policy_root,
            opened_at_height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "reserve_weight_bps": self.reserve_weight_bps,
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "queue_limit": self.queue_limit,
            "sponsor_pool_root": self.sponsor_pool_root,
            "queued_intent_ids": self.queued_intent_ids,
            "admitted_intent_ids": self.admitted_intent_ids,
            "rebate_policy_root": self.rebate_policy_root,
            "opened_at_height": self.opened_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "LOW-FEE-LANE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureSignal {
    pub signal_id: String,
    pub shard_id: u16,
    pub level: BackpressureLevel,
    pub queue_depth: usize,
    pub queue_limit: usize,
    pub low_fee_depth: usize,
    pub inflight_depth: usize,
    pub target_admission_rate: u64,
    pub shed_lane: Option<LaneKind>,
    pub reason_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl BackpressureSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: u16,
        level: BackpressureLevel,
        queue_depth: usize,
        queue_limit: usize,
        low_fee_depth: usize,
        inflight_depth: usize,
        target_admission_rate: u64,
        shed_lane: Option<LaneKind>,
        reason_root: impl Into<String>,
        emitted_at_height: u64,
        sequence: u64,
    ) -> Self {
        let reason_root = reason_root.into();
        let signal_id =
            private_l2_fast_pq_confidential_parallel_mempool_admission_backpressure_signal_id(
                shard_id,
                level,
                queue_depth,
                queue_limit,
                &reason_root,
                emitted_at_height,
                sequence,
            );
        Self {
            signal_id,
            shard_id,
            level,
            queue_depth,
            queue_limit,
            low_fee_depth,
            inflight_depth,
            target_admission_rate,
            shed_lane,
            reason_root,
            emitted_at_height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "shard_id": self.shard_id,
            "level": self.level.as_str(),
            "queue_depth": self.queue_depth,
            "queue_limit": self.queue_limit,
            "low_fee_depth": self.low_fee_depth,
            "inflight_depth": self.inflight_depth,
            "target_admission_rate": self.target_admission_rate,
            "shed_lane": self.shed_lane.map(LaneKind::as_str),
            "reason_root": self.reason_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "BACKPRESSURE-SIGNAL",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DosProfile {
    pub profile_id: String,
    pub account_bucket: String,
    pub burst_credits_remaining: u64,
    pub refill_per_window: u64,
    pub signal_counts: BTreeMap<String, u64>,
    pub quarantine_until_height: u64,
    pub last_seen_height: u64,
    pub total_rejections: u64,
}

impl DosProfile {
    pub fn new(account_bucket: impl Into<String>, config: &Config, height: u64) -> Self {
        let account_bucket = account_bucket.into();
        let profile_id = private_l2_fast_pq_confidential_parallel_mempool_admission_dos_profile_id(
            &account_bucket,
            height,
        );
        Self {
            profile_id,
            account_bucket,
            burst_credits_remaining: config.account_burst_credits,
            refill_per_window: config.account_refill_per_window,
            signal_counts: BTreeMap::new(),
            quarantine_until_height: 0,
            last_seen_height: height,
            total_rejections: 0,
        }
    }

    pub fn charge(&mut self, kind: DosSignalKind, height: u64, quarantine_blocks: u64) {
        let key = kind.as_str().to_string();
        *self.signal_counts.entry(key).or_default() += 1;
        self.total_rejections = self.total_rejections.saturating_add(1);
        self.last_seen_height = height;
        if matches!(
            kind,
            DosSignalKind::NullifierReplay
                | DosSignalKind::WeakPqProof
                | DosSignalKind::DuplicateCommitment
        ) {
            self.quarantine_until_height = height.saturating_add(quarantine_blocks);
        }
    }

    pub fn refill(&mut self, config: &Config, height: u64) {
        self.burst_credits_remaining = self
            .burst_credits_remaining
            .saturating_add(config.account_refill_per_window)
            .min(config.account_burst_credits);
        self.last_seen_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "profile_id": self.profile_id,
            "account_bucket": self.account_bucket,
            "burst_credits_remaining": self.burst_credits_remaining,
            "refill_per_window": self.refill_per_window,
            "signal_counts": self.signal_counts,
            "quarantine_until_height": self.quarantine_until_height,
            "last_seen_height": self.last_seen_height,
            "total_rejections": self.total_rejections,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "DOS-PROFILE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl PublicRecord {
    pub fn new(
        record_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> Self {
        let record_kind = record_kind.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let payload_root = private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "PUBLIC-PAYLOAD",
            payload,
        );
        let record_id = private_l2_fast_pq_confidential_parallel_mempool_admission_public_record_id(
            &record_kind,
            &subject_id,
            &subject_root,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        Self {
            record_id,
            record_kind,
            subject_id,
            subject_root,
            payload_root,
            emitted_at_height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
            "PUBLIC-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_time_ms: u64,
    pub current_epoch: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub intents: BTreeMap<String, EncryptedIntent>,
    pub attestations: BTreeMap<String, AdmissionAttestation>,
    pub queues: BTreeMap<u16, ShardQueue>,
    pub ordering_slots: BTreeMap<String, FairOrderingSlot>,
    pub preconfirmation_windows: BTreeMap<String, PreconfirmationWindow>,
    pub backpressure_signals: BTreeMap<String, BackpressureSignal>,
    pub low_fee_lanes: BTreeMap<u16, LowFeeLane>,
    pub dos_profiles: BTreeMap<String, DosProfile>,
    pub nullifier_replay_cache: BTreeSet<String>,
    pub attestation_replay_cache: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub sequence: u64,
}

impl State {
    pub fn new(config: Config, current_height: u64, current_time_ms: u64) -> Result<Self> {
        config.validate()?;
        let current_epoch = current_height / config.fair_ordering_epoch_blocks.max(1);
        let mut queues = BTreeMap::new();
        let mut low_fee_lanes = BTreeMap::new();
        for shard_id in 0..config.shard_count {
            queues.insert(shard_id, ShardQueue::new(shard_id, current_height));
            low_fee_lanes.insert(
                shard_id,
                LowFeeLane::new(
                    shard_id,
                    config.low_fee_lane_weight_bps,
                    config.min_fee_micro_units,
                    config.low_fee_queue_limit,
                    private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                        "sponsor-pool",
                        &format!("shard-{shard_id}"),
                    ),
                    private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                        "rebate-policy",
                        &format!("shard-{shard_id}"),
                    ),
                    current_height,
                    shard_id as u64,
                ),
            );
        }
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            current_height,
            current_time_ms,
            current_epoch,
            roots,
            counters: Counters::default(),
            intents: BTreeMap::new(),
            attestations: BTreeMap::new(),
            queues,
            ordering_slots: BTreeMap::new(),
            preconfirmation_windows: BTreeMap::new(),
            backpressure_signals: BTreeMap::new(),
            low_fee_lanes,
            dos_profiles: BTreeMap::new(),
            nullifier_replay_cache: BTreeSet::new(),
            attestation_replay_cache: BTreeSet::new(),
            public_records: BTreeMap::new(),
            sequence: 0,
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        Self::new(Config::devnet(), 640_000, 1_700_000_000_000)
    }

    pub fn demo() -> Result<Self> {
        let mut state = Self::devnet()?;
        let intent_a = EncryptedIntent::new(
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root("owner", "alice"),
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "account-bucket",
                "alice-fast",
            ),
            1,
            LaneKind::Priority,
            500,
            12_000,
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "payload",
                "alice-intent",
            ),
            4_096,
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "payload-commitment",
                "alice-intent",
            ),
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "nullifier",
                "alice-intent",
            ),
            private_l2_fast_pq_confidential_parallel_mempool_admission_empty_root("notes-alice"),
            private_l2_fast_pq_confidential_parallel_mempool_admission_empty_root(
                "dependencies-alice",
            ),
            8_192,
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "pq-key", "alice",
            ),
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "admission-hint",
                "alice",
            ),
            state.current_height,
            state.current_height + 8,
            7,
        );
        let intent_b = EncryptedIntent::new(
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root("owner", "bob"),
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "account-bucket",
                "bob-low-fee",
            ),
            1,
            LaneKind::LowFee,
            20,
            8_000,
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "payload",
                "bob-intent",
            ),
            3_072,
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "payload-commitment",
                "bob-intent",
            ),
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "nullifier",
                "bob-intent",
            ),
            private_l2_fast_pq_confidential_parallel_mempool_admission_empty_root("notes-bob"),
            private_l2_fast_pq_confidential_parallel_mempool_admission_empty_root(
                "dependencies-bob",
            ),
            4_096,
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root("pq-key", "bob"),
            private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "admission-hint",
                "bob",
            ),
            state.current_height,
            state.current_height + 8,
            9,
        );
        state.submit_intent(intent_a)?;
        state.submit_intent(intent_b)?;

        let intent_ids = state.intents.keys().cloned().collect::<Vec<_>>();
        for (index, intent_id) in intent_ids.iter().enumerate() {
            let attestation = AdmissionAttestation::new(
                intent_id,
                format!("devnet-admitter-{index}"),
                private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                    "committee",
                    "devnet",
                ),
                PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_ATTESTATION_SCHEME,
                private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                    "pq-signature",
                    intent_id,
                ),
                private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                    "transcript",
                    intent_id,
                ),
                AdmissionDecision::Accept,
                256,
                state.current_height,
                state.current_height + 4,
                index as u64,
            );
            state.submit_attestation(attestation)?;
        }
        state.admit_parallel_round(1, state.current_time_ms + 100)?;
        Ok(state)
    }

    pub fn submit_intent(&mut self, mut intent: EncryptedIntent) -> Result<String> {
        self.config.validate()?;
        if intent.shard_id >= self.config.shard_count {
            return Err("intent shard is outside configured shard range".to_string());
        }
        if intent.ciphertext_bytes > self.config.max_intent_bytes {
            self.charge_dos(
                &intent.account_bucket,
                DosSignalKind::OversizeEnvelope,
                self.current_height,
            );
            intent.status = IntentStatus::Rejected;
            self.counters.rejected_intents = self.counters.rejected_intents.saturating_add(1);
            return Err("intent ciphertext exceeds maximum intent bytes".to_string());
        }
        if intent.privacy_set_size < self.config.min_privacy_set_size {
            self.charge_dos(
                &intent.account_bucket,
                DosSignalKind::WeakPqProof,
                self.current_height,
            );
            intent.status = IntentStatus::Quarantined;
            self.counters.quarantined_intents = self.counters.quarantined_intents.saturating_add(1);
            return Err("intent privacy set is below configured minimum".to_string());
        }
        if intent.expires_at_height <= self.current_height {
            self.charge_dos(
                &intent.account_bucket,
                DosSignalKind::ExpiredIntent,
                self.current_height,
            );
            intent.status = IntentStatus::Expired;
            self.counters.expired_intents = self.counters.expired_intents.saturating_add(1);
            return Err("intent is already expired".to_string());
        }
        if self
            .nullifier_replay_cache
            .contains(&intent.nullifier_commitment)
        {
            self.charge_dos(
                &intent.account_bucket,
                DosSignalKind::NullifierReplay,
                self.current_height,
            );
            intent.status = IntentStatus::Quarantined;
            self.counters.quarantined_intents = self.counters.quarantined_intents.saturating_add(1);
            return Err("intent nullifier commitment is replayed".to_string());
        }
        let depth = self
            .queues
            .get(&intent.shard_id)
            .map(ShardQueue::len)
            .unwrap_or_default();
        if depth >= self.config.shard_queue_limit {
            self.charge_dos(
                &intent.account_bucket,
                DosSignalKind::ShardFlood,
                self.current_height,
            );
            self.emit_backpressure_for_shard(intent.shard_id, self.current_height)?;
            self.counters.deferred_intents = self.counters.deferred_intents.saturating_add(1);
            return Err("shard queue is at capacity".to_string());
        }
        let profile = self
            .dos_profiles
            .entry(intent.account_bucket.clone())
            .or_insert_with(|| {
                DosProfile::new(&intent.account_bucket, &self.config, self.current_height)
            });
        if profile.quarantine_until_height > self.current_height {
            intent.status = IntentStatus::Quarantined;
            self.counters.quarantined_intents = self.counters.quarantined_intents.saturating_add(1);
            return Err("account bucket is quarantined".to_string());
        }
        if profile.burst_credits_remaining == 0 {
            profile.charge(
                DosSignalKind::AccountBurst,
                self.current_height,
                self.config.quarantine_blocks,
            );
            self.counters.dos_signals = self.counters.dos_signals.saturating_add(1);
            self.counters.deferred_intents = self.counters.deferred_intents.saturating_add(1);
            return Err("account bucket has exhausted burst credits".to_string());
        }
        profile.burst_credits_remaining = profile.burst_credits_remaining.saturating_sub(1);

        let lane = self.classify_lane(intent.lane, intent.fee_micro_units);
        if lane == LaneKind::LowFee {
            let low_fee_lane_full = self
                .low_fee_lanes
                .get(&intent.shard_id)
                .map(|low_fee_lane| {
                    low_fee_lane.queued_intent_ids.len() >= low_fee_lane.queue_limit
                })
                .ok_or_else(|| "missing low fee lane for shard".to_string())?;
            if low_fee_lane_full {
                self.charge_dos(
                    &intent.account_bucket,
                    DosSignalKind::FeeStarvation,
                    self.current_height,
                );
                self.counters.deferred_intents = self.counters.deferred_intents.saturating_add(1);
                return Err("low fee lane is at capacity".to_string());
            }
            self.low_fee_lanes
                .get_mut(&intent.shard_id)
                .ok_or_else(|| "missing low fee lane for shard".to_string())?
                .queued_intent_ids
                .push(intent.intent_id.clone());
            self.counters.low_fee_lane_entries =
                self.counters.low_fee_lane_entries.saturating_add(1);
        }
        intent.lane = lane;
        intent.status = IntentStatus::Queued;
        let intent_id = intent.intent_id.clone();
        let intent_root = intent.root();
        self.nullifier_replay_cache
            .insert(intent.nullifier_commitment.clone());
        self.prune_replay_caches();
        let queue = self
            .queues
            .get_mut(&intent.shard_id)
            .ok_or_else(|| "missing shard queue".to_string())?;
        queue.push(lane, intent_id.clone());
        queue.last_updated_height = self.current_height;
        self.intents.insert(intent_id.clone(), intent);
        self.counters.encrypted_intents = self.counters.encrypted_intents.saturating_add(1);
        self.counters.queued_intents = self.counters.queued_intents.saturating_add(1);
        self.publish_public_record(
            "encrypted_intent_queued",
            &intent_id,
            &intent_root,
            self.current_height,
        )?;
        self.refresh_roots();
        Ok(intent_id)
    }

    pub fn submit_attestation(&mut self, mut attestation: AdmissionAttestation) -> Result<String> {
        if !self.intents.contains_key(&attestation.intent_id) {
            return Err("attestation references unknown intent".to_string());
        }
        if attestation.expires_at_height <= self.current_height {
            attestation.status = AttestationStatus::Expired;
            return Err("attestation is expired".to_string());
        }
        if attestation.admission_domain
            != PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_ATTESTATION_SCHEME
        {
            attestation.status = AttestationStatus::BadDomain;
            return Err("attestation domain mismatch".to_string());
        }
        if attestation.security_bits < self.config.min_pq_security_bits {
            attestation.status = AttestationStatus::WeakSecurity;
            let account_bucket = self
                .intents
                .get(&attestation.intent_id)
                .map(|intent| intent.account_bucket.clone())
                .unwrap_or_default();
            self.charge_dos(
                &account_bucket,
                DosSignalKind::WeakPqProof,
                self.current_height,
            );
            return Err("attestation pq security bits below configured minimum".to_string());
        }
        if self
            .attestation_replay_cache
            .contains(&attestation.pq_signature_root)
        {
            attestation.status = AttestationStatus::Replayed;
            self.counters.replayed_pq_attestations =
                self.counters.replayed_pq_attestations.saturating_add(1);
            return Err("attestation signature root replayed".to_string());
        }
        attestation.status = AttestationStatus::Accepted;
        let attestation_id = attestation.attestation_id.clone();
        let intent_id = attestation.intent_id.clone();
        let root = attestation.root();
        self.attestation_replay_cache
            .insert(attestation.pq_signature_root.clone());
        self.prune_replay_caches();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(intent) = self.intents.get_mut(&intent_id) {
            if intent.status == IntentStatus::Queued {
                intent.status = IntentStatus::Attested;
                self.counters.attested_intents = self.counters.attested_intents.saturating_add(1);
            }
        }
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.counters.accepted_pq_attestations =
            self.counters.accepted_pq_attestations.saturating_add(1);
        self.publish_public_record(
            "pq_admission_attestation",
            &attestation_id,
            &root,
            self.current_height,
        )?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn admit_parallel_round(
        &mut self,
        max_per_shard: usize,
        now_ms: u64,
    ) -> Result<Vec<String>> {
        if max_per_shard == 0 {
            return Err("max_per_shard must be nonzero".to_string());
        }
        self.current_time_ms = now_ms;
        self.current_epoch = self.current_height / self.config.fair_ordering_epoch_blocks.max(1);
        let mut admitted = Vec::new();
        let shard_ids = self.queues.keys().copied().collect::<Vec<_>>();
        for shard_id in shard_ids {
            self.emit_backpressure_for_shard(shard_id, self.current_height)?;
            let level = self
                .queues
                .get(&shard_id)
                .map(|queue| queue.backpressure_level)
                .unwrap_or(BackpressureLevel::Emergency);
            let lane_plan = self.lane_plan_for_level(level);
            let mut local_admitted = Vec::new();
            let seed = self.ordering_seed(shard_id, self.current_epoch);
            for lane in lane_plan {
                if local_admitted.len() >= max_per_shard {
                    break;
                }
                let candidate_count = max_per_shard.saturating_sub(local_admitted.len());
                let candidates =
                    self.take_ordered_lane_candidates(shard_id, lane, candidate_count, &seed)?;
                if candidates.is_empty() {
                    continue;
                }
                let total_weight = candidates
                    .iter()
                    .filter_map(|intent_id| self.intents.get(intent_id))
                    .map(|intent| intent.weight_units)
                    .sum::<u64>();
                let slot = FairOrderingSlot::new(
                    self.current_epoch,
                    shard_id,
                    lane,
                    lane.service_weight_bps(&self.config),
                    seed.clone(),
                    candidates.clone(),
                    total_weight,
                    self.current_height,
                    self.next_sequence(),
                );
                let slot_id = slot.slot_id.clone();
                let slot_root = slot.root();
                self.ordering_slots.insert(slot_id.clone(), slot);
                self.counters.fair_ordering_slots =
                    self.counters.fair_ordering_slots.saturating_add(1);
                self.publish_public_record(
                    "fair_ordering_slot",
                    &slot_id,
                    &slot_root,
                    self.current_height,
                )?;
                local_admitted.extend(candidates);
            }
            if !local_admitted.is_empty() {
                let window = self.open_preconfirmation_window(
                    shard_id,
                    LaneKind::Standard,
                    local_admitted.clone(),
                    now_ms,
                )?;
                for intent_id in &local_admitted {
                    if let Some(intent) = self.intents.get_mut(intent_id) {
                        intent.status = IntentStatus::Preconfirmed;
                    }
                }
                self.seal_preconfirmation_window(&window)?;
                admitted.extend(local_admitted);
            }
        }
        self.refresh_roots();
        Ok(admitted)
    }

    pub fn open_preconfirmation_window(
        &mut self,
        shard_id: u16,
        lane: LaneKind,
        admitted_intent_ids: Vec<String>,
        opened_at_ms: u64,
    ) -> Result<String> {
        if shard_id >= self.config.shard_count {
            return Err("preconfirmation shard outside configured range".to_string());
        }
        if admitted_intent_ids.len() > self.config.preconfirmation_max_intents as usize {
            return Err("preconfirmation window exceeds max intents".to_string());
        }
        let total_weight = admitted_intent_ids
            .iter()
            .filter_map(|intent_id| self.intents.get(intent_id))
            .map(|intent| intent.weight_units)
            .sum::<u64>();
        if total_weight > self.config.preconfirmation_max_weight {
            return Err("preconfirmation window exceeds max weight".to_string());
        }
        let attestation_records = self
            .attestations
            .values()
            .filter(|attestation| admitted_intent_ids.contains(&attestation.intent_id))
            .map(|attestation| attestation.public_record())
            .collect::<Vec<_>>();
        let attestation_root = merkle_root(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-PRECONF-ATTESTATIONS",
            &attestation_records,
        );
        let window = PreconfirmationWindow::new(
            self.current_epoch,
            shard_id,
            lane,
            self.current_height,
            opened_at_ms,
            opened_at_ms.saturating_add(self.config.preconfirmation_window_ms),
            self.config.preconfirmation_max_intents,
            self.config.preconfirmation_max_weight,
            admitted_intent_ids,
            attestation_root,
            self.next_sequence(),
        );
        let window_id = window.window_id.clone();
        let window_root = window.root();
        self.preconfirmation_windows
            .insert(window_id.clone(), window);
        self.counters.preconfirmation_windows =
            self.counters.preconfirmation_windows.saturating_add(1);
        self.publish_public_record(
            "preconfirmation_window_opened",
            &window_id,
            &window_root,
            self.current_height,
        )?;
        Ok(window_id)
    }

    pub fn seal_preconfirmation_window(&mut self, window_id: &str) -> Result<()> {
        let intent_ids = {
            let window = self
                .preconfirmation_windows
                .get_mut(window_id)
                .ok_or_else(|| "missing preconfirmation window".to_string())?;
            window.status = PreconfirmationStatus::Sealed;
            window.admitted_intent_ids.clone()
        };
        for intent_id in &intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                if intent.status == IntentStatus::Preconfirmed {
                    intent.status = IntentStatus::Admitted;
                    self.counters.admitted_intents =
                        self.counters.admitted_intents.saturating_add(1);
                    if intent.lane == LaneKind::LowFee {
                        self.counters.low_fee_lane_admissions =
                            self.counters.low_fee_lane_admissions.saturating_add(1);
                        if let Some(lane) = self.low_fee_lanes.get_mut(&intent.shard_id) {
                            remove_first(&mut lane.queued_intent_ids, intent_id);
                            lane.admitted_intent_ids.push(intent_id.clone());
                        }
                    }
                }
            }
        }
        let window_root = self
            .preconfirmation_windows
            .get(window_id)
            .map(PreconfirmationWindow::root)
            .ok_or_else(|| "missing preconfirmation window after seal".to_string())?;
        self.counters.sealed_preconfirmation_windows = self
            .counters
            .sealed_preconfirmation_windows
            .saturating_add(1);
        self.counters.preconfirmed_intents = self
            .counters
            .preconfirmed_intents
            .saturating_add(intent_ids.len() as u64);
        self.publish_public_record(
            "preconfirmation_window_sealed",
            window_id,
            &window_root,
            self.current_height,
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn expire_height(&mut self, height: u64) -> Result<()> {
        self.current_height = height;
        self.current_epoch = height / self.config.fair_ordering_epoch_blocks.max(1);
        let expired = self
            .intents
            .iter()
            .filter(|(_, intent)| intent.status.active() && intent.expires_at_height <= height)
            .map(|(intent_id, intent)| (intent_id.clone(), intent.shard_id))
            .collect::<Vec<_>>();
        for (intent_id, shard_id) in expired {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::Expired;
                self.counters.expired_intents = self.counters.expired_intents.saturating_add(1);
            }
            if let Some(queue) = self.queues.get_mut(&shard_id) {
                queue.remove_intent(&intent_id);
            }
        }
        for profile in self.dos_profiles.values_mut() {
            profile.refill(&self.config, height);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) -> Roots {
        self.roots = Roots {
            config_root: self.config.root(),
            intent_root: private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                "INTENTS",
                self.intents
                    .values()
                    .map(EncryptedIntent::public_record)
                    .collect::<Vec<_>>(),
            ),
            queue_root: private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                "QUEUES",
                self.queues
                    .values()
                    .map(ShardQueue::public_record)
                    .collect::<Vec<_>>(),
            ),
            attestation_root:
                private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                    "ATTESTATIONS",
                    self.attestations
                        .values()
                        .map(AdmissionAttestation::public_record)
                        .collect::<Vec<_>>(),
                ),
            ordering_root:
                private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                    "ORDERING",
                    self.ordering_slots
                        .values()
                        .map(FairOrderingSlot::public_record)
                        .collect::<Vec<_>>(),
                ),
            preconfirmation_root:
                private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                    "PRECONFIRMATIONS",
                    self.preconfirmation_windows
                        .values()
                        .map(PreconfirmationWindow::public_record)
                        .collect::<Vec<_>>(),
                ),
            backpressure_root:
                private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                    "BACKPRESSURE",
                    self.backpressure_signals
                        .values()
                        .map(BackpressureSignal::public_record)
                        .collect::<Vec<_>>(),
                ),
            low_fee_lane_root:
                private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                    "LOW-FEE-LANES",
                    self.low_fee_lanes
                        .values()
                        .map(LowFeeLane::public_record)
                        .collect::<Vec<_>>(),
                ),
            dos_root: private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                "DOS",
                self.dos_profiles
                    .values()
                    .map(DosProfile::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_record_root:
                private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
                    "PUBLIC-RECORDS",
                    self.public_records
                        .values()
                        .map(PublicRecord::public_record)
                        .collect::<Vec<_>>(),
                ),
            state_root: String::new(),
        };
        self.roots.state_root =
            private_l2_fast_pq_confidential_parallel_mempool_admission_state_root_from_record(
                &self.public_record_without_state_root(),
            );
        self.roots.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_SCHEMA_VERSION,
            "current_height": self.current_height,
            "current_time_ms": self.current_time_ms,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "sequence": self.sequence,
        })
    }

    fn public_record_without_state_root(&self) -> Value {
        let mut roots = self.roots.clone();
        roots.state_root.clear();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MEMPOOL_ADMISSION_RUNTIME_SCHEMA_VERSION,
            "current_height": self.current_height,
            "current_time_ms": self.current_time_ms,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
            "sequence": self.sequence,
        })
    }

    fn classify_lane(&self, requested: LaneKind, fee_micro_units: u64) -> LaneKind {
        if requested == LaneKind::Quarantine {
            return LaneKind::Quarantine;
        }
        if fee_micro_units >= self.config.priority_fee_micro_units {
            LaneKind::Priority
        } else if fee_micro_units <= self.config.low_fee_micro_units {
            LaneKind::LowFee
        } else if requested == LaneKind::Background {
            LaneKind::Background
        } else {
            LaneKind::Standard
        }
    }

    fn lane_plan_for_level(&self, level: BackpressureLevel) -> Vec<LaneKind> {
        match level {
            BackpressureLevel::Clear => vec![
                LaneKind::Priority,
                LaneKind::Standard,
                LaneKind::LowFee,
                LaneKind::Background,
            ],
            BackpressureLevel::Soft => {
                vec![LaneKind::Priority, LaneKind::Standard, LaneKind::LowFee]
            }
            BackpressureLevel::Hard => vec![LaneKind::Priority, LaneKind::Standard],
            BackpressureLevel::ShedLowFee => vec![LaneKind::Priority, LaneKind::Standard],
            BackpressureLevel::Emergency => vec![LaneKind::Priority],
        }
    }

    fn take_ordered_lane_candidates(
        &mut self,
        shard_id: u16,
        lane: LaneKind,
        count: usize,
        seed: &str,
    ) -> Result<Vec<String>> {
        let mut candidates = Vec::new();
        let queue = self
            .queues
            .get_mut(&shard_id)
            .ok_or_else(|| "missing shard queue".to_string())?;
        for _ in 0..count {
            let Some(intent_id) = queue.pop_lane(lane) else {
                break;
            };
            candidates.push(intent_id);
        }
        candidates.sort_by(|left, right| {
            let left_key = self
                .intents
                .get(left)
                .map(|intent| intent.fair_key(seed))
                .unwrap_or_default();
            let right_key = self
                .intents
                .get(right)
                .map(|intent| intent.fair_key(seed))
                .unwrap_or_default();
            left_key.cmp(&right_key).then_with(|| left.cmp(right))
        });
        if let Some(queue) = self.queues.get_mut(&shard_id) {
            queue.inflight.extend(candidates.iter().cloned());
            queue.last_ordering_seed = seed.to_string();
            queue.last_updated_height = self.current_height;
        }
        Ok(candidates)
    }

    fn emit_backpressure_for_shard(&mut self, shard_id: u16, height: u64) -> Result<()> {
        let (queue_depth, low_fee_depth, inflight_depth) = {
            let queue = self
                .queues
                .get(&shard_id)
                .ok_or_else(|| "missing shard queue for backpressure".to_string())?;
            (queue.len(), queue.low_fee.len(), queue.inflight.len())
        };
        let level = self.backpressure_level(queue_depth);
        let shed_lane = match level {
            BackpressureLevel::Clear | BackpressureLevel::Soft => None,
            BackpressureLevel::Hard | BackpressureLevel::ShedLowFee => Some(LaneKind::LowFee),
            BackpressureLevel::Emergency => Some(LaneKind::Background),
        };
        if let Some(queue) = self.queues.get_mut(&shard_id) {
            queue.backpressure_level = level;
        }
        if level != BackpressureLevel::Clear {
            let reason_root = private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
                "backpressure",
                &format!("shard-{shard_id}-depth-{queue_depth}"),
            );
            let signal = BackpressureSignal::new(
                shard_id,
                level,
                queue_depth,
                self.config.shard_queue_limit,
                low_fee_depth,
                inflight_depth,
                self.config.preconfirmation_max_intents as u64,
                shed_lane,
                reason_root,
                height,
                self.next_sequence(),
            );
            let signal_id = signal.signal_id.clone();
            let signal_root = signal.root();
            self.backpressure_signals.insert(signal_id.clone(), signal);
            self.counters.backpressure_events = self.counters.backpressure_events.saturating_add(1);
            self.publish_public_record("backpressure_signal", &signal_id, &signal_root, height)?;
        }
        Ok(())
    }

    fn backpressure_level(&self, queue_depth: usize) -> BackpressureLevel {
        if self.config.shard_queue_limit == 0 {
            return BackpressureLevel::Emergency;
        }
        let utilization_bps = (queue_depth as u128)
            .saturating_mul(10_000)
            .checked_div(self.config.shard_queue_limit as u128)
            .unwrap_or(10_000) as u16;
        if utilization_bps >= 9_800 {
            BackpressureLevel::Emergency
        } else if utilization_bps >= self.config.backpressure_hard_bps {
            BackpressureLevel::ShedLowFee
        } else if utilization_bps >= self.config.backpressure_soft_bps {
            BackpressureLevel::Soft
        } else {
            BackpressureLevel::Clear
        }
    }

    fn charge_dos(&mut self, account_bucket: &str, kind: DosSignalKind, height: u64) {
        let profile = self
            .dos_profiles
            .entry(account_bucket.to_string())
            .or_insert_with(|| DosProfile::new(account_bucket, &self.config, height));
        profile.charge(kind, height, self.config.quarantine_blocks);
        self.counters.dos_signals = self.counters.dos_signals.saturating_add(1);
    }

    fn ordering_seed(&self, shard_id: u16, epoch: u64) -> String {
        domain_hash(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-ORDERING-SEED",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Int(shard_id as i128),
                HashPart::Int(epoch as i128),
                HashPart::Str(&self.roots.intent_root),
                HashPart::Str(&self.roots.attestation_root),
            ],
            32,
        )
    }

    fn publish_public_record(
        &mut self,
        kind: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
    ) -> Result<()> {
        if self.public_records.len() >= self.config.public_record_limit {
            return Err("public record limit reached".to_string());
        }
        let payload = json!({
            "kind": kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "height": height,
        });
        let record = PublicRecord::new(
            kind,
            subject_id,
            subject_root,
            &payload,
            height,
            self.next_sequence(),
        );
        self.counters.public_records = self.counters.public_records.saturating_add(1);
        self.public_records.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn prune_replay_caches(&mut self) {
        while self.nullifier_replay_cache.len() > self.config.nullifier_replay_cache_limit {
            if let Some(first) = self.nullifier_replay_cache.iter().next().cloned() {
                self.nullifier_replay_cache.remove(&first);
            } else {
                break;
            }
        }
        while self.attestation_replay_cache.len() > self.config.attestation_cache_limit {
            if let Some(first) = self.attestation_replay_cache.iter().next().cloned() {
                self.attestation_replay_cache.remove(&first);
            } else {
                break;
            }
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.sequence;
        self.sequence = self.sequence.saturating_add(1);
        sequence
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn demo() -> Result<State> {
    State::demo()
}

fn remove_first(items: &mut Vec<String>, needle: &str) -> bool {
    if let Some(index) = items.iter().position(|item| item == needle) {
        items.remove(index);
        true
    } else {
        false
    }
}

fn pop_front_vec(items: &mut Vec<String>) -> Option<String> {
    if items.is_empty() {
        None
    } else {
        Some(items.remove(0))
    }
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-{domain}"),
        &[],
    )
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_collection_root(
    domain: &str,
    records: Vec<Value>,
) -> String {
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-{domain}"),
        &records,
    )
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_record_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_state_root_from_record(
    payload: &Value,
) -> String {
    private_l2_fast_pq_confidential_parallel_mempool_admission_record_root("STATE", payload)
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_roots_state_root(
    roots: &Roots,
) -> String {
    let payload = json!({
        "config_root": roots.config_root,
        "intent_root": roots.intent_root,
        "queue_root": roots.queue_root,
        "attestation_root": roots.attestation_root,
        "ordering_root": roots.ordering_root,
        "preconfirmation_root": roots.preconfirmation_root,
        "backpressure_root": roots.backpressure_root,
        "low_fee_lane_root": roots.low_fee_lane_root,
        "dos_root": roots.dos_root,
        "public_record_root": roots.public_record_root,
    });
    private_l2_fast_pq_confidential_parallel_mempool_admission_state_root_from_record(&payload)
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_label_root(
    label: &str,
    value: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-LABEL",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_l2_fast_pq_confidential_parallel_mempool_admission_intent_id(
    owner_commitment: &str,
    account_bucket: &str,
    shard_id: u16,
    lane: LaneKind,
    payload_commitment: &str,
    nullifier_commitment: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-INTENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(account_bucket),
            HashPart::Int(shard_id as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(payload_commitment),
            HashPart::Str(nullifier_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_l2_fast_pq_confidential_parallel_mempool_admission_attestation_id(
    intent_id: &str,
    attester_id: &str,
    committee_root: &str,
    admission_domain: &str,
    pq_signature_root: &str,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(attester_id),
            HashPart::Str(committee_root),
            HashPart::Str(admission_domain),
            HashPart::Str(pq_signature_root),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_queue_id(
    shard_id: u16,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-QUEUE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(shard_id as i128),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_l2_fast_pq_confidential_parallel_mempool_admission_ordering_slot_id(
    epoch: u64,
    shard_id: u16,
    lane: LaneKind,
    ordering_seed: &str,
    intent_root: &str,
    opened_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-ORDERING-SLOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(shard_id as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(ordering_seed),
            HashPart::Str(intent_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_l2_fast_pq_confidential_parallel_mempool_admission_preconfirmation_window_id(
    epoch: u64,
    shard_id: u16,
    lane: LaneKind,
    opened_at_height: u64,
    opened_at_ms: u64,
    ordered_intent_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-PRECONFIRMATION-WINDOW-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(shard_id as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(opened_at_ms as i128),
            HashPart::Str(ordered_intent_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_l2_fast_pq_confidential_parallel_mempool_admission_low_fee_lane_id(
    shard_id: u16,
    reserve_weight_bps: u16,
    fee_floor_micro_units: u64,
    sponsor_pool_root: &str,
    opened_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-LOW-FEE-LANE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(shard_id as i128),
            HashPart::Int(reserve_weight_bps as i128),
            HashPart::Int(fee_floor_micro_units as i128),
            HashPart::Str(sponsor_pool_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_l2_fast_pq_confidential_parallel_mempool_admission_backpressure_signal_id(
    shard_id: u16,
    level: BackpressureLevel,
    queue_depth: usize,
    queue_limit: usize,
    reason_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-BACKPRESSURE-SIGNAL-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Int(shard_id as i128),
            HashPart::Str(level.as_str()),
            HashPart::Int(queue_depth as i128),
            HashPart::Int(queue_limit as i128),
            HashPart::Str(reason_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn private_l2_fast_pq_confidential_parallel_mempool_admission_dos_profile_id(
    account_bucket: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-DOS-PROFILE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_bucket),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_l2_fast_pq_confidential_parallel_mempool_admission_public_record_id(
    record_kind: &str,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MEMPOOL-ADMISSION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}
