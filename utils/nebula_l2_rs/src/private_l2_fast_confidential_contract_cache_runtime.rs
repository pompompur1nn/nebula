use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str = "nebula-private-l2-fast-confidential-contract-cache-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_CACHE_LINE_SCHEME: &str =
    "ml-kem-1024+view-key-partitioned-confidential-cache-line-v1";
pub const HOT_STATE_HINT_SCHEME: &str = "private-hot-state-hint-roots-only-v1";
pub const WITNESS_RESERVATION_SCHEME: &str = "parallel-private-witness-cache-reservation-v1";
pub const PRECONFIRMED_TICKET_SCHEME: &str = "fast-confidential-cache-preconfirmation-ticket-v1";
pub const INVALIDATION_FENCE_SCHEME: &str = "monero-l2-private-cache-invalidation-fence-v1";
pub const LOW_FEE_RECEIPT_SCHEME: &str = "low-fee-cache-execution-receipt-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-cache-runtime-attestation-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_HEIGHT: u64 = 914_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_CACHE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_HOT_HINT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_LATENCY_US: u64 = 80_000;
pub const DEFAULT_HARD_LATENCY_US: u64 = 300_000;
pub const DEFAULT_MAX_LOOKUP_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_PARALLEL_SHARDS: u16 = 256;
pub const DEFAULT_MAX_CACHE_LINES: usize = 4_194_304;
pub const DEFAULT_MAX_HOT_HINTS: usize = 2_097_152;
pub const DEFAULT_MAX_RESERVATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_TICKETS: usize = 4_194_304;
pub const DEFAULT_MAX_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLineKind {
    ReadOnly,
    WriteBack,
    WriteThrough,
    WitnessOnly,
    NullifierWindow,
    ContractCode,
    MerklePath,
    EventBuffer,
}
impl CacheLineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::WriteBack => "write_back",
            Self::WriteThrough => "write_through",
            Self::WitnessOnly => "witness_only",
            Self::NullifierWindow => "nullifier_window",
            Self::ContractCode => "contract_code",
            Self::MerklePath => "merkle_path",
            Self::EventBuffer => "event_buffer",
        }
    }
    pub fn allows_write(self) -> bool {
        matches!(
            self,
            Self::WriteBack | Self::WriteThrough | Self::EventBuffer
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLineStatus {
    Proposed,
    Active,
    Hot,
    Dirty,
    Flushing,
    Fenced,
    Evicted,
    Slashed,
}
impl CacheLineStatus {
    pub fn readable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Hot | Self::Dirty | Self::Flushing
        )
    }
    pub fn writable(self) -> bool {
        matches!(self, Self::Active | Self::Hot | Self::Dirty)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HotHintKind {
    ReadHeat,
    WriteHeat,
    WitnessHeat,
    CodePath,
    NullifierPressure,
    FeePressure,
    ShardAffinity,
    PrefetchBundle,
}
impl HotHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadHeat => "read_heat",
            Self::WriteHeat => "write_heat",
            Self::WitnessHeat => "witness_heat",
            Self::CodePath => "code_path",
            Self::NullifierPressure => "nullifier_pressure",
            Self::FeePressure => "fee_pressure",
            Self::ShardAffinity => "shard_affinity",
            Self::PrefetchBundle => "prefetch_bundle",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationKind {
    ReadWitness,
    WriteWitness,
    MixedWitness,
    RecursiveWitness,
    NullifierWitness,
    EventWitness,
    CodeWitness,
    PrefetchWitness,
}
impl ReservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadWitness => "read_witness",
            Self::WriteWitness => "write_witness",
            Self::MixedWitness => "mixed_witness",
            Self::RecursiveWitness => "recursive_witness",
            Self::NullifierWitness => "nullifier_witness",
            Self::EventWitness => "event_witness",
            Self::CodeWitness => "code_witness",
            Self::PrefetchWitness => "prefetch_witness",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Assigned,
    Fulfilled,
    PartiallyFulfilled,
    Ticketed,
    Refunded,
    Expired,
    Slashed,
}
impl ReservationStatus {
    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Assigned | Self::PartiallyFulfilled
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketKind {
    ReadHit,
    WriteIntent,
    WitnessReady,
    CacheFlush,
    BatchPrefetch,
    LowFeeBundle,
    EmergencyFenceBypass,
}
impl TicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadHit => "read_hit",
            Self::WriteIntent => "write_intent",
            Self::WitnessReady => "witness_ready",
            Self::CacheFlush => "cache_flush",
            Self::BatchPrefetch => "batch_prefetch",
            Self::LowFeeBundle => "low_fee_bundle",
            Self::EmergencyFenceBypass => "emergency_fence_bypass",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Issued,
    Reserved,
    Consumed,
    Flushed,
    Settled,
    Expired,
    Rejected,
    Slashed,
}
impl TicketStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Issued | Self::Reserved)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    ContractEpoch,
    StoragePrefix,
    NullifierSet,
    ViewKeyEpoch,
    ShardRebalance,
    EmergencyHalt,
    SequencerReorg,
    PQKeyRotation,
}
impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractEpoch => "contract_epoch",
            Self::StoragePrefix => "storage_prefix",
            Self::NullifierSet => "nullifier_set",
            Self::ViewKeyEpoch => "view_key_epoch",
            Self::ShardRebalance => "shard_rebalance",
            Self::EmergencyHalt => "emergency_halt",
            Self::SequencerReorg => "sequencer_reorg",
            Self::PQKeyRotation => "pq_key_rotation",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Applied,
    Superseded,
    Expired,
    Cancelled,
}
impl FenceStatus {
    pub fn blocks_cache(self) -> bool {
        matches!(self, Self::Open | Self::Applied)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    CacheLineInserted,
    CacheLineRead,
    CacheLineWritten,
    HotHintPublished,
    WitnessReserved,
    TicketIssued,
    FenceOpened,
    FenceApplied,
    LowFeeSettled,
    AttestationAccepted,
    CacheLineEvicted,
}
impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CacheLineInserted => "cache_line_inserted",
            Self::CacheLineRead => "cache_line_read",
            Self::CacheLineWritten => "cache_line_written",
            Self::HotHintPublished => "hot_hint_published",
            Self::WitnessReserved => "witness_reserved",
            Self::TicketIssued => "ticket_issued",
            Self::FenceOpened => "fence_opened",
            Self::FenceApplied => "fence_applied",
            Self::LowFeeSettled => "low_fee_settled",
            Self::AttestationAccepted => "attestation_accepted",
            Self::CacheLineEvicted => "cache_line_evicted",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Sequencer,
    WitnessProvider,
    CacheCommittee,
    ViewKeyGuardian,
    FenceWatcher,
    FeeSponsor,
    BatchBuilder,
}
impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::WitnessProvider => "witness_provider",
            Self::CacheCommittee => "cache_committee",
            Self::ViewKeyGuardian => "view_key_guardian",
            Self::FenceWatcher => "fence_watcher",
            Self::FeeSponsor => "fee_sponsor",
            Self::BatchBuilder => "batch_builder",
        }
    }
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
    Expired,
}
impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::WeakQuorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub encrypted_cache_line_scheme: String,
    pub hot_state_hint_scheme: String,
    pub witness_reservation_scheme: String,
    pub preconfirmed_ticket_scheme: String,
    pub invalidation_fence_scheme: String,
    pub low_fee_receipt_scheme: String,
    pub pq_attestation_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub devnet_height: u64,
    pub cache_ttl_blocks: u64,
    pub hot_hint_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_latency_us: u64,
    pub hard_latency_us: u64,
    pub max_lookup_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_parallel_shards: u16,
    pub max_cache_lines: usize,
    pub max_hot_hints: usize,
    pub max_reservations: usize,
    pub max_tickets: usize,
    pub max_fences: usize,
    pub max_receipts: usize,
    pub max_attestations: usize,
    pub max_events: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            encrypted_cache_line_scheme: ENCRYPTED_CACHE_LINE_SCHEME.to_string(),
            hot_state_hint_scheme: HOT_STATE_HINT_SCHEME.to_string(),
            witness_reservation_scheme: WITNESS_RESERVATION_SCHEME.to_string(),
            preconfirmed_ticket_scheme: PRECONFIRMED_TICKET_SCHEME.to_string(),
            invalidation_fence_scheme: INVALIDATION_FENCE_SCHEME.to_string(),
            low_fee_receipt_scheme: LOW_FEE_RECEIPT_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            devnet_height: DEVNET_HEIGHT,
            cache_ttl_blocks: DEFAULT_CACHE_TTL_BLOCKS,
            hot_hint_ttl_blocks: DEFAULT_HOT_HINT_TTL_BLOCKS,
            reservation_ttl_blocks: DEFAULT_RESERVATION_TTL_BLOCKS,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_latency_us: DEFAULT_TARGET_LATENCY_US,
            hard_latency_us: DEFAULT_HARD_LATENCY_US,
            max_lookup_fee_bps: DEFAULT_MAX_LOOKUP_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_parallel_shards: DEFAULT_MAX_PARALLEL_SHARDS,
            max_cache_lines: DEFAULT_MAX_CACHE_LINES,
            max_hot_hints: DEFAULT_MAX_HOT_HINTS,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_fences: DEFAULT_MAX_FENCES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure_bps("max_lookup_fee_bps", self.max_lookup_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("sponsor_cover_bps", self.sponsor_cover_bps)?;
        ensure_bps("quorum_bps", self.quorum_bps)?;
        ensure_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        if self.quorum_bps > self.strong_quorum_bps {
            return Err("quorum cannot exceed strong quorum".to_string());
        }
        if self.target_latency_us > self.hard_latency_us {
            return Err("target latency cannot exceed hard latency".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set must cover minimum privacy set".to_string());
        }
        if self.max_parallel_shards == 0 {
            return Err("max_parallel_shards must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl ReadPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("read"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WritePolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl WritePolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("write"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl WitnessPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("witness"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TicketPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl TicketPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("ticket"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FencePolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl FencePolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("fence"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl ReceiptPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("receipt"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl AttestationPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("attestation"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl ShardPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("shard"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl PrefetchPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("prefetch"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl NullifierPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("nullifier"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl ViewKeyPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("viewkey"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl SponsorPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("sponsor"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencerPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl SequencerPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("sequencer"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl BatchPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("batch"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FlushPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl FlushPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("flush"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvictionPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl EvictionPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("eviction"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl LatencyPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("latency"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl PrivacyPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("privacy"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeePolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl FeePolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("fee"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PQPolicyProfile {
    pub profile_id: String,
    pub domain_root: String,
    pub min_privacy_set_size: u64,
    pub target_latency_us: u64,
    pub max_fee_bps: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}
impl PQPolicyProfile {
    pub fn new(
        domain_root: impl Into<String>,
        min_privacy_set_size: u64,
        target_latency_us: u64,
        max_fee_bps: u64,
        pq_security_bits: u16,
    ) -> Self {
        let domain_root = domain_root.into();
        let profile_id = domain_hash(
            "private-l2-fast-cache-policy-profile",
            &[
                HashPart::Str("pq"),
                HashPart::Str(&domain_root),
                HashPart::U64(min_privacy_set_size),
                HashPart::U64(target_latency_us),
                HashPart::U64(max_fee_bps),
                HashPart::U64(pq_security_bits as u64),
            ],
            32,
        );
        Self {
            profile_id,
            domain_root,
            min_privacy_set_size,
            target_latency_us,
            max_fee_bps,
            pq_security_bits,
            enabled: true,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"profile_id": self.profile_id, "domain_root": self.domain_root, "min_privacy_set_size": self.min_privacy_set_size, "target_latency_us": self.target_latency_us, "max_fee_bps": self.max_fee_bps, "pq_security_bits": self.pq_security_bits, "enabled": self.enabled})
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("profile_max_fee_bps", self.max_fee_bps)?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("policy profile privacy set below minimum".to_string());
        }
        if self.target_latency_us > config.hard_latency_us {
            return Err("policy profile latency exceeds hard limit".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("policy profile pq security below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCacheLine {
    pub cache_line_id: String,
    pub contract_id: String,
    pub shard_id: u16,
    pub kind: CacheLineKind,
    pub status: CacheLineStatus,
    pub storage_domain_root: String,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub read_nullifier_root: String,
    pub write_nullifier_root: String,
    pub view_tag_root: String,
    pub epoch: u64,
    pub version: u64,
    pub byte_len: u64,
    pub privacy_set_size: u64,
    pub fee_floor_micro_units: u64,
    pub last_access_height: u64,
    pub expires_at_height: u64,
    pub pq_security_bits: u16,
    pub owner_commitment: String,
    pub metadata_root: String,
}
impl EncryptedCacheLine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        shard_id: u16,
        kind: CacheLineKind,
        storage_domain_root: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        ciphertext_commitment: impl Into<String>,
        read_nullifier_root: impl Into<String>,
        write_nullifier_root: impl Into<String>,
        view_tag_root: impl Into<String>,
        epoch: u64,
        byte_len: u64,
        privacy_set_size: u64,
        fee_floor_micro_units: u64,
        height: u64,
        ttl_blocks: u64,
        pq_security_bits: u16,
        owner_commitment: impl Into<String>,
        metadata_root: impl Into<String>,
    ) -> Self {
        let contract_id = contract_id.into();
        let storage_domain_root = storage_domain_root.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let ciphertext_commitment = ciphertext_commitment.into();
        let read_nullifier_root = read_nullifier_root.into();
        let write_nullifier_root = write_nullifier_root.into();
        let view_tag_root = view_tag_root.into();
        let owner_commitment = owner_commitment.into();
        let metadata_root = metadata_root.into();
        let cache_line_id = cache_line_id(
            &contract_id,
            shard_id,
            kind,
            &storage_domain_root,
            &encrypted_payload_root,
            epoch,
            1,
        );
        Self {
            cache_line_id,
            contract_id,
            shard_id,
            kind,
            status: CacheLineStatus::Active,
            storage_domain_root,
            encrypted_payload_root,
            ciphertext_commitment,
            read_nullifier_root,
            write_nullifier_root,
            view_tag_root,
            epoch,
            version: 1,
            byte_len,
            privacy_set_size,
            fee_floor_micro_units,
            last_access_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
            pq_security_bits,
            owner_commitment,
            metadata_root,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateHotStateHint {
    pub hint_id: String,
    pub contract_id: String,
    pub shard_id: u16,
    pub kind: HotHintKind,
    pub heat_commitment: String,
    pub access_pattern_root: String,
    pub prefetch_group_root: String,
    pub privacy_set_size: u64,
    pub confidence_bps: u64,
    pub target_latency_us: u64,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub publisher_commitment: String,
}
impl PrivateHotStateHint {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParallelWitnessReservation {
    pub reservation_id: String,
    pub contract_id: String,
    pub shard_ids: BTreeSet<u16>,
    pub kind: ReservationKind,
    pub status: ReservationStatus,
    pub cache_line_roots: Vec<String>,
    pub witness_root: String,
    pub reserved_parallelism: u16,
    pub reserved_weight: u64,
    pub max_fee_micro_units: u64,
    pub sponsor_commitment: String,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub assigned_ticket_ids: BTreeSet<String>,
}
impl ParallelWitnessReservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmedCacheTicket {
    pub ticket_id: String,
    pub contract_id: String,
    pub cache_line_id: String,
    pub reservation_id: Option<String>,
    pub kind: TicketKind,
    pub status: TicketStatus,
    pub read_set_root: String,
    pub write_set_root: String,
    pub witness_root: String,
    pub sequencer_commitment: String,
    pub priority_score: u64,
    pub fee_micro_units: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_at_height: Option<u64>,
}
impl PreconfirmedCacheTicket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub contract_id: String,
    pub kind: FenceKind,
    pub status: FenceStatus,
    pub fence_root: String,
    pub affected_cache_line_root: String,
    pub invalidated_cache_line_ids: BTreeSet<String>,
    pub nullifier_root: String,
    pub reason_commitment: String,
    pub opened_at_height: u64,
    pub applies_from_height: u64,
    pub expires_at_height: u64,
    pub watcher_commitment: String,
}
impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCacheReceipt {
    pub receipt_id: String,
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub contract_id: String,
    pub cache_line_id: Option<String>,
    pub ticket_id: Option<String>,
    pub reservation_id: Option<String>,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub latency_us: u64,
    pub privacy_set_size: u64,
    pub receipt_root: String,
    pub emitted_at_height: u64,
    pub expires_at_height: u64,
}
impl LowFeeCacheReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PQCacheAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub subject_id: String,
    pub committee_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub privacy_set_size: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}
impl PQCacheAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheMetrics {
    pub inserted_lines: u64,
    pub read_hits: u64,
    pub write_hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub fences_applied: u64,
    pub reservations_fulfilled: u64,
    pub tickets_consumed: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub max_observed_latency_us: u64,
}
impl CacheMetrics {
    pub fn devnet() -> Self {
        Self {
            inserted_lines: 0,
            read_hits: 0,
            write_hits: 0,
            misses: 0,
            evictions: 0,
            fences_applied: 0,
            reservations_fulfilled: 0,
            tickets_consumed: 0,
            total_fee_micro_units: 0,
            total_rebate_micro_units: 0,
            max_observed_latency_us: 0,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub state_root_after: String,
}
impl CacheEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub cache_lines: BTreeMap<String, EncryptedCacheLine>,
    pub hot_hints: BTreeMap<String, PrivateHotStateHint>,
    pub reservations: BTreeMap<String, ParallelWitnessReservation>,
    pub tickets: BTreeMap<String, PreconfirmedCacheTicket>,
    pub fences: BTreeMap<String, InvalidationFence>,
    pub receipts: BTreeMap<String, LowFeeCacheReceipt>,
    pub attestations: BTreeMap<String, PQCacheAttestation>,
    pub contract_index: BTreeMap<String, BTreeSet<String>>,
    pub shard_index: BTreeMap<u16, BTreeSet<String>>,
    pub dirty_lines: BTreeSet<String>,
    pub fenced_lines: BTreeSet<String>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub events: Vec<CacheEvent>,
    pub metrics: CacheMetrics,
}
impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            cache_lines: BTreeMap::new(),
            hot_hints: BTreeMap::new(),
            reservations: BTreeMap::new(),
            tickets: BTreeMap::new(),
            fences: BTreeMap::new(),
            receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            contract_index: BTreeMap::new(),
            shard_index: BTreeMap::new(),
            dirty_lines: BTreeSet::new(),
            fenced_lines: BTreeSet::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            events: Vec::new(),
            metrics: CacheMetrics::devnet(),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"config":self.config,"height":self.height,"cache_line_count":self.cache_lines.len(),"hot_hint_count":self.hot_hints.len(),"reservation_count":self.reservations.len(),"ticket_count":self.tickets.len(),"fence_count":self.fences.len(),"receipt_count":self.receipts.len(),"attestation_count":self.attestations.len(),"metrics":self.metrics.public_record(),"state_root":self.state_root()})
    }
    pub fn state_root(&self) -> String {
        let record = json!({"protocol_version":self.config.protocol_version,"schema_version":self.config.schema_version,"chain_id":self.config.chain_id,"height":self.height,"cache_lines_root":map_root("cache-lines",self.cache_lines.values().map(EncryptedCacheLine::public_record)),"hot_hints_root":map_root("hot-hints",self.hot_hints.values().map(PrivateHotStateHint::public_record)),"reservations_root":map_root("reservations",self.reservations.values().map(ParallelWitnessReservation::public_record)),"tickets_root":map_root("tickets",self.tickets.values().map(PreconfirmedCacheTicket::public_record)),"fences_root":map_root("fences",self.fences.values().map(InvalidationFence::public_record)),"receipts_root":map_root("receipts",self.receipts.values().map(LowFeeCacheReceipt::public_record)),"attestations_root":map_root("attestations",self.attestations.values().map(PQCacheAttestation::public_record)),"events_root":map_root("events",self.events.iter().map(CacheEvent::public_record)),"metrics":self.metrics.public_record()});
        domain_hash(
            "private-l2-fast-confidential-contract-cache-state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }
    pub fn insert_cache_line(&mut self, line: EncryptedCacheLine) -> Result<String> {
        ensure_capacity(
            "cache_lines",
            self.cache_lines.len(),
            self.config.max_cache_lines,
        )?;
        if line.privacy_set_size < self.config.min_privacy_set_size {
            return Err("cache line privacy set below minimum".to_string());
        }
        if line.pq_security_bits < self.config.min_pq_security_bits {
            return Err("cache line pq security below minimum".to_string());
        }
        let id = line.cache_line_id.clone();
        if self.cache_lines.contains_key(&id) {
            return Err(format!("cache line already exists: {id}"));
        }
        self.contract_index
            .entry(line.contract_id.clone())
            .or_default()
            .insert(id.clone());
        self.shard_index
            .entry(line.shard_id)
            .or_default()
            .insert(id.clone());
        self.cache_lines.insert(id.clone(), line);
        self.metrics.inserted_lines = self.metrics.inserted_lines.saturating_add(1);
        Ok(id)
    }
    pub fn read_cache_line(
        &mut self,
        cache_line_id: &str,
        read_nullifier_root: &str,
        latency_us: u64,
    ) -> Result<LowFeeCacheReceipt> {
        let (contract_id, fee_floor_micro_units, privacy_set_size) = {
            let line = self
                .cache_lines
                .get_mut(cache_line_id)
                .ok_or_else(|| format!("unknown cache line: {cache_line_id}"))?;
            if !line.status.readable() || line.is_expired(self.height) {
                return Err("cache line is not readable".to_string());
            }
            if self.fenced_lines.contains(cache_line_id) {
                return Err("cache line is fenced".to_string());
            }
            if !self
                .consumed_nullifier_roots
                .insert(read_nullifier_root.to_string())
            {
                return Err("read nullifier root already consumed".to_string());
            }
            line.last_access_height = self.height;
            (
                line.contract_id.clone(),
                line.fee_floor_micro_units,
                line.privacy_set_size,
            )
        };
        self.metrics.read_hits = self.metrics.read_hits.saturating_add(1);
        self.metrics.max_observed_latency_us = self.metrics.max_observed_latency_us.max(latency_us);
        let receipt = receipt(
            ReceiptKind::CacheLineRead,
            cache_line_id,
            contract_id.as_str(),
            Some(cache_line_id),
            None,
            None,
            fee_floor_micro_units,
            self.rebate_for_fee(fee_floor_micro_units),
            latency_us,
            privacy_set_size,
            self.height,
            self.config.receipt_ttl_blocks,
        );
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }
    pub fn write_cache_line(
        &mut self,
        cache_line_id: &str,
        new_payload: impl Into<String>,
        write_nullifier_root: &str,
        latency_us: u64,
    ) -> Result<LowFeeCacheReceipt> {
        let rebate_bps = self.config.target_rebate_bps;
        let (contract_id, fee_floor_micro_units, privacy_set_size) = {
            let line = self
                .cache_lines
                .get_mut(cache_line_id)
                .ok_or_else(|| format!("unknown cache line: {cache_line_id}"))?;
            if !line.kind.allows_write() || !line.status.writable() {
                return Err("cache line is not writable".to_string());
            }
            if !self
                .consumed_nullifier_roots
                .insert(write_nullifier_root.to_string())
            {
                return Err("write nullifier root already consumed".to_string());
            }
            line.encrypted_payload_root = new_payload.into();
            line.write_nullifier_root = write_nullifier_root.to_string();
            line.version = line.version.saturating_add(1);
            line.status = CacheLineStatus::Dirty;
            (
                line.contract_id.clone(),
                line.fee_floor_micro_units,
                line.privacy_set_size,
            )
        };
        self.dirty_lines.insert(cache_line_id.to_string());
        self.metrics.write_hits = self.metrics.write_hits.saturating_add(1);
        let rebate = fee_floor_micro_units.saturating_mul(rebate_bps) / MAX_BPS;
        let receipt = receipt(
            ReceiptKind::CacheLineWritten,
            cache_line_id,
            contract_id.as_str(),
            Some(cache_line_id),
            None,
            None,
            fee_floor_micro_units,
            rebate,
            latency_us,
            privacy_set_size,
            self.height,
            self.config.receipt_ttl_blocks,
        );
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }
    pub fn publish_hot_hint(&mut self, hint: PrivateHotStateHint) -> Result<String> {
        ensure_capacity("hot_hints", self.hot_hints.len(), self.config.max_hot_hints)?;
        ensure_bps("confidence_bps", hint.confidence_bps)?;
        let id = hint.hint_id.clone();
        self.hot_hints.insert(id.clone(), hint);
        Ok(id)
    }
    pub fn reserve_parallel_witness(
        &mut self,
        reservation: ParallelWitnessReservation,
    ) -> Result<String> {
        ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        let id = reservation.reservation_id.clone();
        self.reservations.insert(id.clone(), reservation);
        Ok(id)
    }
    pub fn issue_preconfirmed_ticket(&mut self, ticket: PreconfirmedCacheTicket) -> Result<String> {
        ensure_capacity("tickets", self.tickets.len(), self.config.max_tickets)?;
        let id = ticket.ticket_id.clone();
        self.tickets.insert(id.clone(), ticket);
        Ok(id)
    }
    pub fn consume_ticket(
        &mut self,
        ticket_id: &str,
        latency_us: u64,
    ) -> Result<LowFeeCacheReceipt> {
        let rebate_bps = self.config.target_rebate_bps;
        let (contract_id, cache_line_id, reservation_id, fee_micro_units, privacy_set_size) = {
            let ticket = self
                .tickets
                .get_mut(ticket_id)
                .ok_or_else(|| format!("unknown ticket: {ticket_id}"))?;
            if !ticket.status.usable() {
                return Err("ticket is not usable".to_string());
            }
            ticket.status = TicketStatus::Consumed;
            ticket.consumed_at_height = Some(self.height);
            (
                ticket.contract_id.clone(),
                ticket.cache_line_id.clone(),
                ticket.reservation_id.clone(),
                ticket.fee_micro_units,
                ticket.privacy_set_size,
            )
        };
        self.metrics.tickets_consumed = self.metrics.tickets_consumed.saturating_add(1);
        let rebate = fee_micro_units.saturating_mul(rebate_bps) / MAX_BPS;
        let receipt = receipt(
            ReceiptKind::LowFeeSettled,
            ticket_id,
            contract_id.as_str(),
            Some(cache_line_id.as_str()),
            Some(ticket_id),
            reservation_id.as_deref(),
            fee_micro_units,
            rebate,
            latency_us,
            privacy_set_size,
            self.height,
            self.config.receipt_ttl_blocks,
        );
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }
    pub fn open_invalidation_fence(&mut self, fence: InvalidationFence) -> Result<String> {
        ensure_capacity("fences", self.fences.len(), self.config.max_fences)?;
        let id = fence.fence_id.clone();
        self.fences.insert(id.clone(), fence);
        Ok(id)
    }
    pub fn apply_invalidation_fence(&mut self, fence_id: &str) -> Result<()> {
        let ids = self
            .fences
            .get(fence_id)
            .ok_or_else(|| format!("unknown fence: {fence_id}"))?
            .invalidated_cache_line_ids
            .clone();
        for id in ids {
            self.fenced_lines.insert(id.clone());
            if let Some(line) = self.cache_lines.get_mut(&id) {
                line.status = CacheLineStatus::Fenced;
            }
        }
        if let Some(fence) = self.fences.get_mut(fence_id) {
            fence.status = FenceStatus::Applied;
        }
        self.metrics.fences_applied = self.metrics.fences_applied.saturating_add(1);
        Ok(())
    }
    pub fn accept_pq_attestation(&mut self, mut attestation: PQCacheAttestation) -> Result<String> {
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        attestation.status = if attestation.quorum_bps >= self.config.strong_quorum_bps {
            AttestationStatus::StrongQuorum
        } else if attestation.quorum_bps >= self.config.quorum_bps {
            AttestationStatus::WeakQuorum
        } else {
            AttestationStatus::Accepted
        };
        let id = attestation.attestation_id.clone();
        self.attestations.insert(id.clone(), attestation);
        Ok(id)
    }
    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("height cannot go backwards".to_string());
        }
        self.height = height;
        Ok(())
    }
    pub fn public_record_for_subject(&self, id: &str) -> Option<Value> {
        self.cache_lines
            .get(id)
            .map(EncryptedCacheLine::public_record)
            .or_else(|| {
                self.hot_hints
                    .get(id)
                    .map(PrivateHotStateHint::public_record)
            })
            .or_else(|| {
                self.reservations
                    .get(id)
                    .map(ParallelWitnessReservation::public_record)
            })
            .or_else(|| {
                self.tickets
                    .get(id)
                    .map(PreconfirmedCacheTicket::public_record)
            })
            .or_else(|| self.fences.get(id).map(InvalidationFence::public_record))
            .or_else(|| self.receipts.get(id).map(LowFeeCacheReceipt::public_record))
            .or_else(|| {
                self.attestations
                    .get(id)
                    .map(PQCacheAttestation::public_record)
            })
    }
    fn rebate_for_fee(&self, fee: u64) -> u64 {
        fee.saturating_mul(self.config.target_rebate_bps) / MAX_BPS
    }
}
pub fn cache_line_id(
    contract_id: &str,
    shard_id: u16,
    kind: CacheLineKind,
    storage_domain_root: &str,
    encrypted_payload_root: &str,
    epoch: u64,
    version: u64,
) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-line-id",
        &[
            HashPart::Str(contract_id),
            HashPart::U64(shard_id as u64),
            HashPart::Str(kind.as_str()),
            HashPart::Str(storage_domain_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::U64(epoch),
            HashPart::U64(version),
        ],
        32,
    )
}
pub fn hot_hint_id(
    contract_id: &str,
    shard_id: u16,
    kind: HotHintKind,
    heat_commitment: &str,
    access_pattern_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-hot-hint-id",
        &[
            HashPart::Str(contract_id),
            HashPart::U64(shard_id as u64),
            HashPart::Str(kind.as_str()),
            HashPart::Str(heat_commitment),
            HashPart::Str(access_pattern_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn reservation_id(
    contract_id: &str,
    kind: ReservationKind,
    shard_root: &str,
    line_root: &str,
    witness_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-reservation-id",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(shard_root),
            HashPart::Str(line_root),
            HashPart::Str(witness_root),
            HashPart::U64(height),
        ],
        32,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn ticket_id(
    contract_id: &str,
    cache_line_id: &str,
    reservation_id: &str,
    kind: TicketKind,
    read_set_root: &str,
    write_set_root: &str,
    witness_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-ticket-id",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(cache_line_id),
            HashPart::Str(reservation_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(read_set_root),
            HashPart::Str(write_set_root),
            HashPart::Str(witness_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn fence_id(contract_id: &str, kind: FenceKind, fence_root: &str, height: u64) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-fence-id",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(fence_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn attestation_id(
    kind: AttestationKind,
    subject_id: &str,
    committee_root: &str,
    signature_root: &str,
    transcript_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-attestation-id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(committee_root),
            HashPart::Str(signature_root),
            HashPart::Str(transcript_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn event_id(
    kind: ReceiptKind,
    subject_id: &str,
    height: u64,
    state_root_after: &str,
) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-event-id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::Str(state_root_after),
        ],
        32,
    )
}
pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "private-l2-fast-confidential-cache-public-record-root",
        &[HashPart::Json(record)],
        32,
    )
}
#[allow(clippy::too_many_arguments)]
fn receipt(
    kind: ReceiptKind,
    subject_id: &str,
    contract_id: &str,
    cache_line_id: Option<&str>,
    ticket_id: Option<&str>,
    reservation_id: Option<&str>,
    fee_micro_units: u64,
    rebate_micro_units: u64,
    latency_us: u64,
    privacy_set_size: u64,
    height: u64,
    ttl: u64,
) -> LowFeeCacheReceipt {
    let receipt_root = domain_hash(
        "private-l2-fast-cache-receipt-root",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(contract_id),
            HashPart::U64(fee_micro_units),
            HashPart::U64(rebate_micro_units),
            HashPart::U64(latency_us),
            HashPart::U64(height),
        ],
        32,
    );
    let receipt_id = domain_hash(
        "private-l2-fast-cache-receipt-id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(&receipt_root),
            HashPart::U64(height),
        ],
        32,
    );
    LowFeeCacheReceipt {
        receipt_id,
        kind,
        subject_id: subject_id.to_string(),
        contract_id: contract_id.to_string(),
        cache_line_id: cache_line_id.map(str::to_string),
        ticket_id: ticket_id.map(str::to_string),
        reservation_id: reservation_id.map(str::to_string),
        fee_micro_units,
        rebate_micro_units,
        latency_us,
        privacy_set_size,
        receipt_root,
        emitted_at_height: height,
        expires_at_height: height.saturating_add(ttl),
    }
}
fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}
fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}
