#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2FastPqConfidentialRollupStateDeltaMulticastRuntimeResult<T>;
pub type PrivateL2FastPqConfidentialRollupStateDeltaMulticastRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ROLLUP_STATE_DELTA_MULTICAST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-rollup-state-delta-multicast-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ROLLUP_STATE_DELTA_MULTICAST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MULTICAST_LANE_SUITE: &str = "fast-confidential-rollup-state-delta-multicast-lane-v1";
pub const ENCRYPTED_PACKET_SUITE: &str = "ML-KEM-1024+XWing-encrypted-state-delta-packet-v1";
pub const PQ_BROADCASTER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-state-delta-broadcaster-attestation-v1";
pub const SHARD_FANOUT_SUITE: &str = "confidential-rollup-state-delta-shard-fanout-v1";
pub const CACHE_LEASE_SUITE: &str = "state-delta-multicast-cache-lease-ticket-v1";
pub const INVALIDATION_FENCE_SUITE: &str = "state-delta-multicast-invalidation-fence-v1";
pub const LATENCY_BUCKET_SUITE: &str = "state-delta-multicast-latency-bucket-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "state-delta-multicast-low-fee-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "state-delta-multicast-redaction-budget-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_420_096;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_690_240;
pub const DEVNET_EPOCH: u64 = 17_408;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_MULTICAST_MS: u64 = 18;
pub const DEFAULT_MAX_MULTICAST_MS: u64 = 96;
pub const DEFAULT_PACKET_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_CACHE_LEASE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 256;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_REDACTION_BUDGET_BPS: u64 = 320;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_LANES: usize = 131_072;
pub const DEFAULT_MAX_PACKETS: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_SHARD_FANOUTS: usize = 4_194_304;
pub const DEFAULT_MAX_CACHE_LEASES: usize = 4_194_304;
pub const DEFAULT_MAX_INVALIDATION_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_LATENCY_BUCKETS: usize = 1_048_576;
pub const DEFAULT_MAX_LOW_FEE_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 2_097_152;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

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
pub enum MulticastLaneKind {
    HotAccountDelta,
    ContractStorageDelta,
    BridgeExitDelta,
    DefiNettingDelta,
    CrossShardReceiptDelta,
    WitnessDelta,
    EscapeHatchDelta,
}

impl MulticastLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotAccountDelta => "hot_account_delta",
            Self::ContractStorageDelta => "contract_storage_delta",
            Self::BridgeExitDelta => "bridge_exit_delta",
            Self::DefiNettingDelta => "defi_netting_delta",
            Self::CrossShardReceiptDelta => "cross_shard_receipt_delta",
            Self::WitnessDelta => "witness_delta",
            Self::EscapeHatchDelta => "escape_hatch_delta",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EscapeHatchDelta => 10_000,
            Self::BridgeExitDelta => 9_600,
            Self::DefiNettingDelta => 9_200,
            Self::CrossShardReceiptDelta => 8_800,
            Self::HotAccountDelta => 8_400,
            Self::ContractStorageDelta => 8_000,
            Self::WitnessDelta => 7_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Hot,
    Backpressured,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_packets(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::Backpressured)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketStatus {
    Draft,
    Encrypted,
    Multicast,
    FanoutAcked,
    Attested,
    Cached,
    Rebated,
    Settled,
    Expired,
    Rejected,
}

impl PacketStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Multicast | Self::FanoutAcked | Self::Attested | Self::Cached
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Broadcast,
    Delayed,
    Withheld,
    Invalid,
}

impl AttestationVerdict {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Broadcast | Self::Delayed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Active,
    Matched,
    Consumed,
    Frozen,
    Released,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_multicast_ms: u64,
    pub max_multicast_ms: u64,
    pub packet_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub cache_lease_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub redaction_budget_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_lanes: usize,
    pub max_packets: usize,
    pub max_attestations: usize,
    pub max_shard_fanouts: usize,
    pub max_cache_leases: usize,
    pub max_invalidation_fences: usize,
    pub max_latency_buckets: usize,
    pub max_low_fee_rebates: usize,
    pub max_redaction_budgets: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_multicast_ms: DEFAULT_TARGET_MULTICAST_MS,
            max_multicast_ms: DEFAULT_MAX_MULTICAST_MS,
            packet_ttl_blocks: DEFAULT_PACKET_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            cache_lease_ttl_blocks: DEFAULT_CACHE_LEASE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            redaction_budget_bps: DEFAULT_REDACTION_BUDGET_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_lanes: DEFAULT_MAX_LANES,
            max_packets: DEFAULT_MAX_PACKETS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_shard_fanouts: DEFAULT_MAX_SHARD_FANOUTS,
            max_cache_leases: DEFAULT_MAX_CACHE_LEASES,
            max_invalidation_fences: DEFAULT_MAX_INVALIDATION_FENCES,
            max_latency_buckets: DEFAULT_MAX_LATENCY_BUCKETS,
            max_low_fee_rebates: DEFAULT_MAX_LOW_FEE_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "mode": self.mode.as_str(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_multicast_ms": self.target_multicast_ms,
            "max_multicast_ms": self.max_multicast_ms,
            "redaction_budget_bps": self.redaction_budget_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_count: u64,
    pub packet_count: u64,
    pub live_packet_count: u64,
    pub attestation_count: u64,
    pub accepted_attestation_count: u64,
    pub shard_fanout_count: u64,
    pub cache_lease_count: u64,
    pub active_cache_lease_count: u64,
    pub invalidation_fence_count: u64,
    pub active_invalidation_fence_count: u64,
    pub latency_bucket_count: u64,
    pub low_fee_rebate_count: u64,
    pub redeemed_rebate_count: u64,
    pub redaction_budget_count: u64,
    pub encrypted_packet_bytes: u128,
    pub fanout_target_count: u64,
    pub rebate_micro_units: u128,
    pub root_updates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub packet_root: String,
    pub attestation_root: String,
    pub shard_fanout_root: String,
    pub cache_lease_root: String,
    pub invalidation_fence_root: String,
    pub latency_bucket_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub public_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Roots {
    fn default() -> Self {
        let empty = merkle_root("STATE-DELTA-MULTICAST-EMPTY", &[]);
        Self {
            config_root: empty.clone(),
            lane_root: empty.clone(),
            packet_root: empty.clone(),
            attestation_root: empty.clone(),
            shard_fanout_root: empty.clone(),
            cache_lease_root: empty.clone(),
            invalidation_fence_root: empty.clone(),
            latency_bucket_root: empty.clone(),
            low_fee_rebate_root: empty.clone(),
            redaction_budget_root: empty.clone(),
            public_root: empty.clone(),
            state_root: empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MulticastLane {
    pub lane_id: String,
    pub lane_kind: MulticastLaneKind,
    pub shard_id: String,
    pub status: LaneStatus,
    pub sequencer_commitment: String,
    pub lane_capacity_bytes: u64,
    pub inflight_bytes: u64,
    pub multicast_hit_bps: u64,
    pub backpressure_bps: u64,
    pub priority_weight: u64,
    pub current_epoch: u64,
}

impl MulticastLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "shard_id": self.shard_id,
            "status": self.status,
            "lane_capacity_bytes": self.lane_capacity_bytes,
            "inflight_bytes": self.inflight_bytes,
            "multicast_hit_bps": self.multicast_hit_bps,
            "backpressure_bps": self.backpressure_bps,
            "priority_weight": self.priority_weight,
            "current_epoch": self.current_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateDeltaPacket {
    pub packet_id: String,
    pub lane_id: String,
    pub fanout_id: String,
    pub previous_state_root: String,
    pub post_state_root: String,
    pub delta_commitment_root: String,
    pub ciphertext_root: String,
    pub key_committee_root: String,
    pub packet_bytes: u64,
    pub status: PacketStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedStateDeltaPacket {
    pub fn public_record(&self) -> Value {
        json!({
            "packet_id": self.packet_id,
            "lane_id": self.lane_id,
            "fanout_id": self.fanout_id,
            "previous_state_root": self.previous_state_root,
            "post_state_root": self.post_state_root,
            "delta_commitment_root": self.delta_commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "key_committee_root": self.key_committee_root,
            "packet_bytes": self.packet_bytes,
            "status": self.status,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqBroadcasterAttestation {
    pub attestation_id: String,
    pub packet_id: String,
    pub broadcaster_commitment: String,
    pub broadcast_root: String,
    pub signature_root: String,
    pub verdict: AttestationVerdict,
    pub observed_latency_ms: u64,
    pub pq_security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqBroadcasterAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardFanout {
    pub fanout_id: String,
    pub lane_id: String,
    pub source_shard_id: String,
    pub target_shard_ids: Vec<String>,
    pub acked_shards: BTreeSet<String>,
    pub fanout_committee_root: String,
    pub fanout_root: String,
    pub quorum_threshold: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ShardFanout {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub packet_id: String,
    pub lane_id: String,
    pub cache_node_commitment: String,
    pub lease_root: String,
    pub lease_bytes: u64,
    pub price_micro_units: u128,
    pub active: bool,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl CacheLease {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub previous_state_root: String,
    pub invalidates_before_root: String,
    pub fence_root: String,
    pub status: FenceStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub packet_count: u64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub bucket_root: String,
}

impl LatencyBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub packet_id: String,
    pub sponsor_commitment: String,
    pub user_commitment: String,
    pub rebate_root: String,
    pub rebate_bps: u64,
    pub rebate_micro_units: u128,
    pub redeemed: bool,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub packet_id: String,
    pub lane_id: String,
    pub redaction_root: String,
    pub budget_bps: u64,
    pub spent_bps: u64,
    pub hidden_field_count: u64,
    pub public_field_count: u64,
    pub min_privacy_set_size: u64,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, MulticastLane>,
    pub packets: BTreeMap<String, EncryptedStateDeltaPacket>,
    pub attestations: BTreeMap<String, PqBroadcasterAttestation>,
    pub shard_fanouts: BTreeMap<String, ShardFanout>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub latency_buckets: BTreeMap<String, LatencyBucket>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        ensure!(
            config.min_pq_security_bits >= 128,
            "min PQ security too low: {}",
            config.min_pq_security_bits
        );
        ensure!(
            config.target_multicast_ms <= config.max_multicast_ms,
            "target multicast latency exceeds max multicast latency"
        );
        ensure!(
            config.redaction_budget_bps <= MAX_BPS,
            "redaction budget exceeds MAX_BPS"
        );
        ensure!(
            config.low_fee_rebate_bps <= MAX_BPS,
            "low fee rebate exceeds MAX_BPS"
        );
        let mut state = Self {
            config,
            l2_height,
            monero_height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            packets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            shard_fanouts: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "lanes": self.lanes.values().map(MulticastLane::public_record).collect::<Vec<_>>(),
            "packets": self.packets.values().map(EncryptedStateDeltaPacket::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqBroadcasterAttestation::public_record).collect::<Vec<_>>(),
            "shard_fanouts": self.shard_fanouts.values().map(ShardFanout::public_record).collect::<Vec<_>>(),
            "cache_leases": self.cache_leases.values().map(CacheLease::public_record).collect::<Vec<_>>(),
            "invalidation_fences": self.invalidation_fences.values().map(InvalidationFence::public_record).collect::<Vec<_>>(),
            "latency_buckets": self.latency_buckets.values().map(LatencyBucket::public_record).collect::<Vec<_>>(),
            "low_fee_rebates": self.low_fee_rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn register_lane(&mut self, lane: MulticastLane) -> Result<()> {
        ensure!(
            self.lanes.len() < self.config.max_lanes || self.lanes.contains_key(&lane.lane_id),
            "multicast lane capacity exceeded"
        );
        ensure!(
            lane.backpressure_bps <= MAX_BPS,
            "lane backpressure exceeds MAX_BPS"
        );
        ensure!(
            lane.status.accepts_packets(),
            "lane does not accept packets"
        );
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_shard_fanout(&mut self, fanout: ShardFanout) -> Result<()> {
        ensure!(
            self.shard_fanouts.len() < self.config.max_shard_fanouts
                || self.shard_fanouts.contains_key(&fanout.fanout_id),
            "shard fanout capacity exceeded"
        );
        ensure!(
            self.lanes.contains_key(&fanout.lane_id),
            "unknown multicast lane for fanout {}",
            fanout.lane_id
        );
        self.shard_fanouts.insert(fanout.fanout_id.clone(), fanout);
        self.refresh_roots();
        Ok(())
    }

    pub fn multicast_packet(&mut self, packet: EncryptedStateDeltaPacket) -> Result<()> {
        ensure!(
            self.packets.len() < self.config.max_packets
                || self.packets.contains_key(&packet.packet_id),
            "packet capacity exceeded"
        );
        ensure!(
            self.lanes.contains_key(&packet.lane_id),
            "unknown multicast lane for packet {}",
            packet.lane_id
        );
        ensure!(
            self.shard_fanouts.contains_key(&packet.fanout_id),
            "unknown shard fanout for packet {}",
            packet.fanout_id
        );
        self.packets.insert(packet.packet_id.clone(), packet);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_attestation(&mut self, attestation: PqBroadcasterAttestation) -> Result<()> {
        ensure!(
            self.attestations.len() < self.config.max_attestations
                || self.attestations.contains_key(&attestation.attestation_id),
            "attestation capacity exceeded"
        );
        ensure!(
            self.packets.contains_key(&attestation.packet_id),
            "unknown packet for attestation {}",
            attestation.packet_id
        );
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_cache_lease(&mut self, lease: CacheLease) -> Result<()> {
        ensure!(
            self.cache_leases.len() < self.config.max_cache_leases
                || self.cache_leases.contains_key(&lease.lease_id),
            "cache lease capacity exceeded"
        );
        ensure!(
            self.packets.contains_key(&lease.packet_id),
            "unknown packet for cache lease {}",
            lease.packet_id
        );
        self.cache_leases.insert(lease.lease_id.clone(), lease);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_invalidation_fence(&mut self, fence: InvalidationFence) -> Result<()> {
        ensure!(
            self.invalidation_fences.len() < self.config.max_invalidation_fences
                || self.invalidation_fences.contains_key(&fence.fence_id),
            "invalidation fence capacity exceeded"
        );
        self.invalidation_fences
            .insert(fence.fence_id.clone(), fence);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_latency_bucket(&mut self, bucket: LatencyBucket) -> Result<()> {
        ensure!(
            self.latency_buckets.len() < self.config.max_latency_buckets
                || self.latency_buckets.contains_key(&bucket.bucket_id),
            "latency bucket capacity exceeded"
        );
        self.latency_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_low_fee_rebate(&mut self, rebate: LowFeeRebate) -> Result<()> {
        ensure!(
            self.low_fee_rebates.len() < self.config.max_low_fee_rebates
                || self.low_fee_rebates.contains_key(&rebate.rebate_id),
            "low fee rebate capacity exceeded"
        );
        ensure!(rebate.rebate_bps <= MAX_BPS, "rebate bps exceeds MAX_BPS");
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets
                || self.redaction_budgets.contains_key(&budget.budget_id),
            "redaction budget capacity exceeded"
        );
        ensure!(
            budget.spent_bps <= budget.budget_bps,
            "redaction budget overspent"
        );
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.derive_counters();
        let config_root = payload_root(
            "STATE-DELTA-MULTICAST-CONFIG-ROOT",
            &self.config.public_record(),
        );
        let lane_root = map_root(
            "STATE-DELTA-MULTICAST-LANE-ROOT",
            &self.lanes,
            MulticastLane::public_record,
        );
        let packet_root = map_root(
            "STATE-DELTA-MULTICAST-PACKET-ROOT",
            &self.packets,
            EncryptedStateDeltaPacket::public_record,
        );
        let attestation_root = map_root(
            "STATE-DELTA-MULTICAST-ATTESTATION-ROOT",
            &self.attestations,
            PqBroadcasterAttestation::public_record,
        );
        let shard_fanout_root = map_root(
            "STATE-DELTA-MULTICAST-SHARD-FANOUT-ROOT",
            &self.shard_fanouts,
            ShardFanout::public_record,
        );
        let cache_lease_root = map_root(
            "STATE-DELTA-MULTICAST-CACHE-LEASE-ROOT",
            &self.cache_leases,
            CacheLease::public_record,
        );
        let invalidation_fence_root = map_root(
            "STATE-DELTA-MULTICAST-INVALIDATION-FENCE-ROOT",
            &self.invalidation_fences,
            InvalidationFence::public_record,
        );
        let latency_bucket_root = map_root(
            "STATE-DELTA-MULTICAST-LATENCY-BUCKET-ROOT",
            &self.latency_buckets,
            LatencyBucket::public_record,
        );
        let low_fee_rebate_root = map_root(
            "STATE-DELTA-MULTICAST-LOW-FEE-REBATE-ROOT",
            &self.low_fee_rebates,
            LowFeeRebate::public_record,
        );
        let redaction_budget_root = map_root(
            "STATE-DELTA-MULTICAST-REDACTION-BUDGET-ROOT",
            &self.redaction_budgets,
            RedactionBudget::public_record,
        );
        let public_root = payload_root(
            "STATE-DELTA-MULTICAST-PUBLIC-ROOT",
            &json!({
                "config_root": config_root,
                "lane_root": lane_root,
                "packet_root": packet_root,
                "attestation_root": attestation_root,
                "shard_fanout_root": shard_fanout_root,
                "cache_lease_root": cache_lease_root,
                "invalidation_fence_root": invalidation_fence_root,
                "latency_bucket_root": latency_bucket_root,
                "low_fee_rebate_root": low_fee_rebate_root,
                "redaction_budget_root": redaction_budget_root,
                "counters": self.counters.public_record(),
            }),
        );
        let state_root_value = payload_root(
            "STATE-DELTA-MULTICAST-STATE-ROOT",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "l2_height": self.l2_height,
                "monero_height": self.monero_height,
                "epoch": self.epoch,
                "public_root": public_root,
            }),
        );
        self.roots = Roots {
            config_root,
            lane_root,
            packet_root,
            attestation_root,
            shard_fanout_root,
            cache_lease_root,
            invalidation_fence_root,
            latency_bucket_root,
            low_fee_rebate_root,
            redaction_budget_root,
            public_root,
            state_root: state_root_value,
        };
        self.counters.root_updates = self.counters.root_updates.saturating_add(1);
    }

    fn derive_counters(&self) -> Counters {
        let fanout_target_count = self
            .shard_fanouts
            .values()
            .map(|fanout| fanout.target_shard_ids.len() as u64)
            .sum();
        Counters {
            lane_count: self.lanes.len() as u64,
            packet_count: self.packets.len() as u64,
            live_packet_count: self
                .packets
                .values()
                .filter(|packet| packet.status.live())
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            accepted_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.verdict.accepted())
                .count() as u64,
            shard_fanout_count: self.shard_fanouts.len() as u64,
            cache_lease_count: self.cache_leases.len() as u64,
            active_cache_lease_count: self
                .cache_leases
                .values()
                .filter(|lease| lease.active)
                .count() as u64,
            invalidation_fence_count: self.invalidation_fences.len() as u64,
            active_invalidation_fence_count: self
                .invalidation_fences
                .values()
                .filter(|fence| matches!(fence.status, FenceStatus::Active | FenceStatus::Matched))
                .count() as u64,
            latency_bucket_count: self.latency_buckets.len() as u64,
            low_fee_rebate_count: self.low_fee_rebates.len() as u64,
            redeemed_rebate_count: self
                .low_fee_rebates
                .values()
                .filter(|rebate| rebate.redeemed)
                .count() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            encrypted_packet_bytes: self
                .packets
                .values()
                .map(|packet| packet.packet_bytes as u128)
                .sum(),
            fanout_target_count,
            rebate_micro_units: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.rebate_micro_units)
                .sum(),
            root_updates: self.counters.root_updates,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet state delta multicast config")
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let lane = sample_lane(
        "lane-state-delta-contract-a",
        MulticastLaneKind::ContractStorageDelta,
        "shard-0007",
        LaneStatus::Hot,
        96 * 1024 * 1024,
        9_540,
        180,
    );
    state.register_lane(lane).expect("sample multicast lane");

    let fanout = sample_fanout(
        "fanout-state-delta-contract-a",
        "lane-state-delta-contract-a",
        "shard-0007",
        &["shard-0008", "shard-0009", "shard-0010"],
        DEVNET_L2_HEIGHT,
    );
    state
        .register_shard_fanout(fanout)
        .expect("sample shard fanout");

    let packet_id = packet_id(
        "lane-state-delta-contract-a",
        "fanout-state-delta-contract-a",
        &sample_root("previous-state", "contract-a"),
        &sample_root("post-state", "contract-a"),
        DEVNET_L2_HEIGHT,
    );
    let packet = EncryptedStateDeltaPacket {
        packet_id: packet_id.clone(),
        lane_id: "lane-state-delta-contract-a".to_string(),
        fanout_id: "fanout-state-delta-contract-a".to_string(),
        previous_state_root: sample_root("previous-state", "contract-a"),
        post_state_root: sample_root("post-state", "contract-a"),
        delta_commitment_root: sample_root("delta-commitment", "contract-a"),
        ciphertext_root: sample_root("ciphertext", "contract-a"),
        key_committee_root: sample_root("key-committee", "contract-a"),
        packet_bytes: 1_572_864,
        status: PacketStatus::Attested,
        opened_at_height: DEVNET_L2_HEIGHT,
        expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_PACKET_TTL_BLOCKS,
    };
    state.multicast_packet(packet).expect("sample packet");
    state
        .record_attestation(sample_attestation(
            "attestation-state-delta-contract-a",
            &packet_id,
            AttestationVerdict::Broadcast,
            DEVNET_L2_HEIGHT + 1,
        ))
        .expect("sample attestation");
    state
        .register_cache_lease(sample_cache_lease(
            "lease-state-delta-contract-a",
            &packet_id,
            "lane-state-delta-contract-a",
            DEVNET_L2_HEIGHT + 1,
        ))
        .expect("sample cache lease");
    state
        .register_invalidation_fence(sample_fence(
            "fence-state-delta-contract-a",
            "lane-state-delta-contract-a",
            "shard-0007",
            DEVNET_L2_HEIGHT,
        ))
        .expect("sample invalidation fence");
    state
        .register_latency_bucket(sample_latency_bucket(
            "latency-state-delta-contract-a",
            "lane-state-delta-contract-a",
            "shard-0007",
        ))
        .expect("sample latency bucket");
    state
        .register_low_fee_rebate(sample_rebate(
            "rebate-state-delta-contract-a",
            &packet_id,
            DEVNET_L2_HEIGHT + 1,
        ))
        .expect("sample low fee rebate");
    state
        .register_redaction_budget(sample_redaction_budget(
            "budget-state-delta-contract-a",
            &packet_id,
            "lane-state-delta-contract-a",
        ))
        .expect("sample redaction budget");
    state
}

pub fn demo() -> Value {
    devnet().public_record()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values.values().map(public_record).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn packet_id(
    lane_id: &str,
    fanout_id: &str,
    previous_state_root: &str,
    post_state_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "STATE-DELTA-MULTICAST-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ENCRYPTED_PACKET_SUITE),
            HashPart::Str(lane_id),
            HashPart::Str(fanout_id),
            HashPart::Str(previous_state_root),
            HashPart::Str(post_state_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn sample_root(domain: &str, label: &str) -> String {
    domain_hash(
        "STATE-DELTA-MULTICAST-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn sample_lane(
    lane_id: &str,
    lane_kind: MulticastLaneKind,
    shard_id: &str,
    status: LaneStatus,
    lane_capacity_bytes: u64,
    multicast_hit_bps: u64,
    backpressure_bps: u64,
) -> MulticastLane {
    MulticastLane {
        lane_id: lane_id.to_string(),
        lane_kind,
        shard_id: shard_id.to_string(),
        status,
        sequencer_commitment: sample_root("sequencer", lane_id),
        lane_capacity_bytes,
        inflight_bytes: 0,
        multicast_hit_bps,
        backpressure_bps,
        priority_weight: lane_kind.priority_weight(),
        current_epoch: DEVNET_EPOCH,
    }
}

fn sample_fanout(
    fanout_id: &str,
    lane_id: &str,
    source_shard_id: &str,
    target_shard_ids: &[&str],
    opened_at_height: u64,
) -> ShardFanout {
    ShardFanout {
        fanout_id: fanout_id.to_string(),
        lane_id: lane_id.to_string(),
        source_shard_id: source_shard_id.to_string(),
        target_shard_ids: target_shard_ids
            .iter()
            .map(|target| (*target).to_string())
            .collect(),
        acked_shards: BTreeSet::from(["shard-0008".to_string(), "shard-0009".to_string()]),
        fanout_committee_root: sample_root("fanout-committee", fanout_id),
        fanout_root: sample_root("fanout", fanout_id),
        quorum_threshold: 2,
        opened_at_height,
        expires_at_height: opened_at_height + DEFAULT_PACKET_TTL_BLOCKS,
    }
}

fn sample_attestation(
    attestation_id: &str,
    packet_id: &str,
    verdict: AttestationVerdict,
    issued_at_height: u64,
) -> PqBroadcasterAttestation {
    PqBroadcasterAttestation {
        attestation_id: attestation_id.to_string(),
        packet_id: packet_id.to_string(),
        broadcaster_commitment: sample_root("broadcaster", attestation_id),
        broadcast_root: sample_root("broadcast", packet_id),
        signature_root: sample_root("pq-signature", attestation_id),
        verdict,
        observed_latency_ms: 14,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        issued_at_height,
        expires_at_height: issued_at_height + DEFAULT_ATTESTATION_TTL_BLOCKS,
    }
}

fn sample_cache_lease(
    lease_id: &str,
    packet_id: &str,
    lane_id: &str,
    opened_at_height: u64,
) -> CacheLease {
    CacheLease {
        lease_id: lease_id.to_string(),
        packet_id: packet_id.to_string(),
        lane_id: lane_id.to_string(),
        cache_node_commitment: sample_root("cache-node", lease_id),
        lease_root: sample_root("cache-lease", lease_id),
        lease_bytes: 1_572_864,
        price_micro_units: 23,
        active: true,
        opened_at_height,
        expires_at_height: opened_at_height + DEFAULT_CACHE_LEASE_TTL_BLOCKS,
    }
}

fn sample_fence(
    fence_id: &str,
    lane_id: &str,
    shard_id: &str,
    opened_at_height: u64,
) -> InvalidationFence {
    InvalidationFence {
        fence_id: fence_id.to_string(),
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        previous_state_root: sample_root("previous-state", fence_id),
        invalidates_before_root: sample_root("invalidates-before", fence_id),
        fence_root: sample_root("fence", fence_id),
        status: FenceStatus::Active,
        opened_at_height,
        expires_at_height: opened_at_height + DEFAULT_FENCE_TTL_BLOCKS,
    }
}

fn sample_latency_bucket(bucket_id: &str, lane_id: &str, shard_id: &str) -> LatencyBucket {
    LatencyBucket {
        bucket_id: bucket_id.to_string(),
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        min_latency_ms: 0,
        max_latency_ms: DEFAULT_MAX_MULTICAST_MS,
        packet_count: 1,
        p50_latency_ms: 14,
        p95_latency_ms: 32,
        bucket_root: sample_root("latency-bucket", bucket_id),
    }
}

fn sample_rebate(rebate_id: &str, packet_id: &str, issued_at_height: u64) -> LowFeeRebate {
    LowFeeRebate {
        rebate_id: rebate_id.to_string(),
        packet_id: packet_id.to_string(),
        sponsor_commitment: sample_root("sponsor", rebate_id),
        user_commitment: sample_root("user", rebate_id),
        rebate_root: sample_root("rebate", rebate_id),
        rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
        rebate_micro_units: 8,
        redeemed: false,
        issued_at_height,
        expires_at_height: issued_at_height + DEFAULT_REBATE_TTL_BLOCKS,
    }
}

fn sample_redaction_budget(budget_id: &str, packet_id: &str, lane_id: &str) -> RedactionBudget {
    RedactionBudget {
        budget_id: budget_id.to_string(),
        packet_id: packet_id.to_string(),
        lane_id: lane_id.to_string(),
        redaction_root: sample_root("redaction-budget", budget_id),
        budget_bps: DEFAULT_REDACTION_BUDGET_BPS,
        spent_bps: 210,
        hidden_field_count: 19,
        public_field_count: 10,
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
    }
}
