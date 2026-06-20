#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialStateDiffAuctionSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_DIFF_AUCTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-state-diff-auction-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_DIFF_AUCTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SCHEDULER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-state-diff-scheduler-v1";
pub const SEALED_BID_QUEUE_SUITE: &str =
    "ML-KEM-1024-sealed-confidential-state-diff-producer-bid-queue-v1";
pub const WITNESS_COMMITMENT_SUITE: &str =
    "recursive-confidential-state-witness-commitment-root-v1";
pub const PRECONFIRMATION_SLA_SUITE: &str =
    "fast-private-l2-state-diff-preconfirmation-sla-lane-v1";
pub const BACKLOG_CONTROL_SUITE: &str = "state-diff-auction-backlog-control-and-load-shed-root-v1";
pub const REBATE_SUITE: &str = "low-fee-confidential-state-diff-producer-rebate-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "operator-safe-confidential-state-diff-auction-scheduler-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_512_448;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_734_016;
pub const DEVNET_EPOCH: u64 = 18_432;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_SCHEDULE_MS: u64 = 18;
pub const DEFAULT_HARD_SLA_MS: u64 = 120;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_WITNESS_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_TARGET_BACKLOG_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_BACKLOG_BYTES: u64 = 384 * 1024 * 1024;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_REBATE_BPS: u64 = 5;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_200;
pub const DEFAULT_MAX_AUCTIONS: usize = 4_194_304;
pub const DEFAULT_MAX_PRODUCERS: usize = 524_288;
pub const DEFAULT_MAX_BID_QUEUES: usize = 2_097_152;
pub const DEFAULT_MAX_WITNESS_COMMITMENTS: usize = 8_388_608;
pub const DEFAULT_MAX_SLA_LANES: usize = 131_072;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_BACKLOG_CONTROLS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;

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
pub enum DiffLaneKind {
    HotAccountDelta,
    ContractStorageDelta,
    MoneroExitDelta,
    DefiNettingDelta,
    CrossRuntimeReceiptDelta,
    OracleUpdateDelta,
    RecursiveWitnessDelta,
    EmergencyEscapeDelta,
}

impl DiffLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotAccountDelta => "hot_account_delta",
            Self::ContractStorageDelta => "contract_storage_delta",
            Self::MoneroExitDelta => "monero_exit_delta",
            Self::DefiNettingDelta => "defi_netting_delta",
            Self::CrossRuntimeReceiptDelta => "cross_runtime_receipt_delta",
            Self::OracleUpdateDelta => "oracle_update_delta",
            Self::RecursiveWitnessDelta => "recursive_witness_delta",
            Self::EmergencyEscapeDelta => "emergency_escape_delta",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscapeDelta => 10_000,
            Self::MoneroExitDelta => 9_700,
            Self::DefiNettingDelta => 9_200,
            Self::CrossRuntimeReceiptDelta => 8_900,
            Self::HotAccountDelta => 8_500,
            Self::ContractStorageDelta => 8_100,
            Self::OracleUpdateDelta => 7_500,
            Self::RecursiveWitnessDelta => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Clearing,
    Scheduled,
    Preconfirmed,
    Settled,
    Expired,
    Cancelled,
}

impl AuctionStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Sealed | Self::Clearing | Self::Scheduled | Self::Preconfirmed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidQueueStatus {
    Accepting,
    Sealed,
    Clearing,
    Draining,
    Paused,
}

impl BidQueueStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Accepting | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaLaneClass {
    Instant,
    Fast,
    Economy,
    Bulk,
    Emergency,
}

impl SlaLaneClass {
    pub fn target_ms(self) -> u64 {
        match self {
            Self::Emergency => 6,
            Self::Instant => 12,
            Self::Fast => 30,
            Self::Economy => 90,
            Self::Bulk => 240,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Schedulable,
    Congested,
    WitnessMissing,
    Invalid,
}

impl AttestationVerdict {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Schedulable | Self::Congested)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub runtime_mode: RuntimeMode,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_schedule_ms: u64,
    pub hard_sla_ms: u64,
    pub auction_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub witness_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub target_backlog_bytes: u64,
    pub max_backlog_bytes: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_auctions: usize,
    pub max_producers: usize,
    pub max_bid_queues: usize,
    pub max_witness_commitments: usize,
    pub max_sla_lanes: usize,
    pub max_attestations: usize,
    pub max_backlog_controls: usize,
    pub max_rebates: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            runtime_mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_schedule_ms: DEFAULT_TARGET_SCHEDULE_MS,
            hard_sla_ms: DEFAULT_HARD_SLA_MS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            witness_ttl_blocks: DEFAULT_WITNESS_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            target_backlog_bytes: DEFAULT_TARGET_BACKLOG_BYTES,
            max_backlog_bytes: DEFAULT_MAX_BACKLOG_BYTES,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_producers: DEFAULT_MAX_PRODUCERS,
            max_bid_queues: DEFAULT_MAX_BID_QUEUES,
            max_witness_commitments: DEFAULT_MAX_WITNESS_COMMITMENTS,
            max_sla_lanes: DEFAULT_MAX_SLA_LANES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_backlog_controls: DEFAULT_MAX_BACKLOG_CONTROLS,
            max_rebates: DEFAULT_MAX_REBATES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_pq_security_bits >= 128,
            "min PQ security too low: {}",
            self.min_pq_security_bits
        );
        ensure!(
            self.target_schedule_ms <= self.hard_sla_ms,
            "target schedule ms exceeds hard SLA"
        );
        ensure!(
            self.target_backlog_bytes <= self.max_backlog_bytes,
            "target backlog exceeds max backlog"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS,
            "max user fee exceeds MAX_BPS"
        );
        ensure!(
            self.rebate_bps <= self.sponsor_cover_bps,
            "rebate exceeds sponsor cover"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub auction_count: u64,
    pub live_auction_count: u64,
    pub producer_count: u64,
    pub bid_queue_count: u64,
    pub sealed_bid_count: u64,
    pub witness_commitment_count: u64,
    pub sla_lane_count: u64,
    pub attestation_count: u64,
    pub accepted_attestation_count: u64,
    pub backlog_control_count: u64,
    pub rebate_count: u64,
    pub redeemed_rebate_count: u64,
    pub active_nullifier_count: u64,
    pub total_backlog_bytes: u64,
    pub scheduled_diff_bytes: u64,
    pub fee_savings_piconero: u64,
    pub root_updates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub auction_root: String,
    pub producer_root: String,
    pub bid_queue_root: String,
    pub witness_commitment_root: String,
    pub sla_lane_root: String,
    pub attestation_root: String,
    pub backlog_control_root: String,
    pub rebate_root: String,
    pub active_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiffProducer {
    pub producer_id: String,
    pub operator_commitment: String,
    pub pq_attestation_key_root: String,
    pub bonded_stake_piconero: u64,
    pub max_parallel_diffs: u32,
    pub median_schedule_ms: u64,
    pub fee_ceiling_bps: u64,
    pub reliability_bps: u64,
    pub active: bool,
}

impl DiffProducer {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateDiffAuction {
    pub auction_id: String,
    pub lane_id: String,
    pub queue_id: String,
    pub status: AuctionStatus,
    pub previous_state_root: String,
    pub target_state_root: String,
    pub state_diff_commitment_root: String,
    pub encrypted_diff_payload_root: String,
    pub public_delta_root: String,
    pub diff_bytes: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub max_user_fee_bps: u64,
    pub selected_producer_id: Option<String>,
}

impl StateDiffAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lane_id": self.lane_id,
            "queue_id": self.queue_id,
            "status": self.status,
            "previous_state_root": self.previous_state_root,
            "target_state_root": self.target_state_root,
            "state_diff_commitment_root": self.state_diff_commitment_root,
            "encrypted_diff_payload_root": self.encrypted_diff_payload_root,
            "public_delta_root": self.public_delta_root,
            "diff_bytes": self.diff_bytes,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "max_user_fee_bps": self.max_user_fee_bps,
            "selected_producer_id": self.selected_producer_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedBidQueue {
    pub queue_id: String,
    pub lane_id: String,
    pub status: BidQueueStatus,
    pub sealed_bid_root: String,
    pub bid_count: u64,
    pub lowest_fee_hint_bps: u64,
    pub target_clear_ms: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedBidQueue {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCommitment {
    pub witness_id: String,
    pub auction_id: String,
    pub producer_id: String,
    pub witness_commitment_root: String,
    pub encrypted_witness_ref_root: String,
    pub recursive_witness_hint_root: String,
    pub witness_bytes: u64,
    pub availability_height: u64,
    pub expires_at_height: u64,
}

impl WitnessCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationSlaLane {
    pub lane_id: String,
    pub lane_class: SlaLaneClass,
    pub kind: DiffLaneKind,
    pub status: BidQueueStatus,
    pub target_ms: u64,
    pub hard_sla_ms: u64,
    pub inflight_bytes: u64,
    pub backlog_bytes: u64,
    pub max_backlog_bytes: u64,
    pub fee_cap_bps: u64,
}

impl PreconfirmationSlaLane {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSchedulerAttestation {
    pub attestation_id: String,
    pub auction_id: String,
    pub producer_id: String,
    pub scheduler_commitment_root: String,
    pub verdict: AttestationVerdict,
    pub pq_security_bits: u16,
    pub schedule_ms: u64,
    pub fee_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSchedulerAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BacklogControl {
    pub control_id: String,
    pub lane_id: String,
    pub backlog_bytes: u64,
    pub shed_bps: u64,
    pub rebalance_to_lane_ids: Vec<String>,
    pub active: bool,
    pub opened_at_height: u64,
}

impl BacklogControl {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProducerRebate {
    pub rebate_id: String,
    pub auction_id: String,
    pub producer_id: String,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub fee_savings_piconero: u64,
    pub settlement_commitment_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub redeemed: bool,
}

impl ProducerRebate {
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
    pub auctions: BTreeMap<String, StateDiffAuction>,
    pub producers: BTreeMap<String, DiffProducer>,
    pub bid_queues: BTreeMap<String, SealedBidQueue>,
    pub witness_commitments: BTreeMap<String, WitnessCommitment>,
    pub sla_lanes: BTreeMap<String, PreconfirmationSlaLane>,
    pub attestations: BTreeMap<String, PqSchedulerAttestation>,
    pub backlog_controls: BTreeMap<String, BacklogControl>,
    pub rebates: BTreeMap<String, ProducerRebate>,
    pub active_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            l2_height,
            monero_height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            auctions: BTreeMap::new(),
            producers: BTreeMap::new(),
            bid_queues: BTreeMap::new(),
            witness_commitments: BTreeMap::new(),
            sla_lanes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            backlog_controls: BTreeMap::new(),
            rebates: BTreeMap::new(),
            active_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet config is valid");
        seed_devnet(&mut state);
        state.refresh_roots();
        state
    }

    pub fn register_sla_lane(&mut self, lane: PreconfirmationSlaLane) -> Result<()> {
        ensure!(
            self.sla_lanes.len() < self.config.max_sla_lanes
                || self.sla_lanes.contains_key(&lane.lane_id),
            "SLA lane capacity exhausted"
        );
        ensure!(
            lane.fee_cap_bps <= self.config.max_user_fee_bps,
            "lane fee cap too high"
        );
        ensure!(
            lane.target_ms <= lane.hard_sla_ms,
            "lane target exceeds hard SLA"
        );
        self.sla_lanes.insert(lane.lane_id.clone(), lane);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_producer(&mut self, producer: DiffProducer) -> Result<()> {
        ensure!(
            self.producers.len() < self.config.max_producers
                || self.producers.contains_key(&producer.producer_id),
            "producer capacity exhausted"
        );
        ensure!(
            producer.fee_ceiling_bps <= MAX_BPS,
            "producer fee exceeds MAX_BPS"
        );
        ensure!(
            producer.reliability_bps <= MAX_BPS,
            "producer reliability exceeds MAX_BPS"
        );
        self.producers
            .insert(producer.producer_id.clone(), producer);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_bid_queue(&mut self, queue: SealedBidQueue) -> Result<()> {
        ensure!(
            self.bid_queues.len() < self.config.max_bid_queues
                || self.bid_queues.contains_key(&queue.queue_id),
            "bid queue capacity exhausted"
        );
        ensure!(
            self.sla_lanes.contains_key(&queue.lane_id),
            "unknown SLA lane"
        );
        self.bid_queues.insert(queue.queue_id.clone(), queue);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_auction(&mut self, auction: StateDiffAuction) -> Result<()> {
        ensure!(
            self.auctions.len() < self.config.max_auctions
                || self.auctions.contains_key(&auction.auction_id),
            "auction capacity exhausted"
        );
        ensure!(
            self.sla_lanes.contains_key(&auction.lane_id),
            "unknown SLA lane"
        );
        let queue = self
            .bid_queues
            .get(&auction.queue_id)
            .ok_or_else(|| format!("unknown bid queue {}", auction.queue_id))?;
        ensure!(
            queue.status.accepts_bids(),
            "bid queue does not accept bids"
        );
        ensure!(
            auction.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small: {}",
            auction.privacy_set_size
        );
        ensure!(
            auction.max_user_fee_bps <= self.config.max_user_fee_bps,
            "auction fee exceeds configured maximum"
        );
        if let Some(lane) = self.sla_lanes.get_mut(&auction.lane_id) {
            ensure!(
                lane.backlog_bytes.saturating_add(auction.diff_bytes) <= lane.max_backlog_bytes,
                "lane backlog capacity exceeded"
            );
            lane.backlog_bytes = lane.backlog_bytes.saturating_add(auction.diff_bytes);
        }
        self.auctions.insert(auction.auction_id.clone(), auction);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_witness_commitment(&mut self, witness: WitnessCommitment) -> Result<()> {
        ensure!(
            self.witness_commitments.len() < self.config.max_witness_commitments
                || self.witness_commitments.contains_key(&witness.witness_id),
            "witness commitment capacity exhausted"
        );
        ensure!(
            self.auctions.contains_key(&witness.auction_id),
            "unknown auction"
        );
        ensure!(
            self.producers.contains_key(&witness.producer_id),
            "unknown producer"
        );
        self.witness_commitments
            .insert(witness.witness_id.clone(), witness);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_scheduler_attestation(&mut self, attestation: PqSchedulerAttestation) -> Result<()> {
        ensure!(
            self.attestations.len() < self.config.max_attestations
                || self.attestations.contains_key(&attestation.attestation_id),
            "attestation capacity exhausted"
        );
        ensure!(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation PQ security below configured minimum"
        );
        ensure!(
            attestation.fee_bps <= self.config.max_user_fee_bps,
            "attested fee too high"
        );
        if let Some(auction) = self.auctions.get_mut(&attestation.auction_id) {
            if attestation.verdict.accepted() && auction.status.live() {
                auction.status = AuctionStatus::Scheduled;
                auction.selected_producer_id = Some(attestation.producer_id.clone());
            }
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn update_backlog_control(&mut self, control: BacklogControl) -> Result<()> {
        ensure!(
            self.backlog_controls.len() < self.config.max_backlog_controls
                || self.backlog_controls.contains_key(&control.control_id),
            "backlog control capacity exhausted"
        );
        ensure!(control.shed_bps <= MAX_BPS, "shed bps exceeds MAX_BPS");
        if let Some(lane) = self.sla_lanes.get_mut(&control.lane_id) {
            lane.backlog_bytes = control.backlog_bytes;
            lane.status = if control.active && control.shed_bps > 0 {
                BidQueueStatus::Draining
            } else {
                BidQueueStatus::Accepting
            };
        }
        self.backlog_controls
            .insert(control.control_id.clone(), control);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_rebate(&mut self, rebate: ProducerRebate) -> Result<()> {
        ensure!(
            self.rebates.len() < self.config.max_rebates
                || self.rebates.contains_key(&rebate.rebate_id),
            "rebate capacity exhausted"
        );
        ensure!(
            rebate.rebate_bps <= self.config.rebate_bps,
            "rebate bps too high"
        );
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.refresh_roots();
        Ok(())
    }

    pub fn redeem_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate {rebate_id}"))?;
        ensure!(!rebate.redeemed, "rebate already redeemed");
        ensure!(self.l2_height <= rebate.expires_at_height, "rebate expired");
        rebate.redeemed = true;
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_scheduler_attestation_suite": PQ_SCHEDULER_ATTESTATION_SUITE,
            "sealed_bid_queue_suite": SEALED_BID_QUEUE_SUITE,
            "witness_commitment_suite": WITNESS_COMMITMENT_SUITE,
            "preconfirmation_sla_suite": PRECONFIRMATION_SLA_SUITE,
            "backlog_control_suite": BACKLOG_CONTROL_SUITE,
            "rebate_suite": REBATE_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "chain_id": CHAIN_ID,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        if self.roots.state_root.is_empty() {
            return self.compute_state_root();
        }
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.derive_counters();
        self.roots.config_root = payload_root(
            "STATE-DIFF-AUCTION-SCHEDULER-CONFIG",
            &self.config.public_record(),
        );
        self.roots.counter_root = payload_root(
            "STATE-DIFF-AUCTION-SCHEDULER-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots.auction_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-AUCTIONS",
            &self.auctions,
            StateDiffAuction::public_record,
        );
        self.roots.producer_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-PRODUCERS",
            &self.producers,
            DiffProducer::public_record,
        );
        self.roots.bid_queue_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-BID-QUEUES",
            &self.bid_queues,
            SealedBidQueue::public_record,
        );
        self.roots.witness_commitment_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-WITNESSES",
            &self.witness_commitments,
            WitnessCommitment::public_record,
        );
        self.roots.sla_lane_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-SLA-LANES",
            &self.sla_lanes,
            PreconfirmationSlaLane::public_record,
        );
        self.roots.attestation_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-ATTESTATIONS",
            &self.attestations,
            PqSchedulerAttestation::public_record,
        );
        self.roots.backlog_control_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-BACKLOG-CONTROLS",
            &self.backlog_controls,
            BacklogControl::public_record,
        );
        self.roots.rebate_root = map_root(
            "STATE-DIFF-AUCTION-SCHEDULER-REBATES",
            &self.rebates,
            ProducerRebate::public_record,
        );
        self.roots.active_nullifier_root = set_root(
            "STATE-DIFF-AUCTION-SCHEDULER-ACTIVE-NULLIFIERS",
            &self.active_nullifiers,
        );
        self.roots.public_record_root = payload_root(
            "STATE-DIFF-AUCTION-SCHEDULER-PUBLIC-RECORD",
            &self.public_record_without_state_root(),
        );
        self.counters.root_updates = self.counters.root_updates.saturating_add(1);
        self.roots.counter_root = payload_root(
            "STATE-DIFF-AUCTION-SCHEDULER-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots.state_root = self.compute_state_root();
    }

    fn derive_counters(&self) -> Counters {
        Counters {
            auction_count: self.auctions.len() as u64,
            live_auction_count: self
                .auctions
                .values()
                .filter(|auction| auction.status.live())
                .count() as u64,
            producer_count: self.producers.len() as u64,
            bid_queue_count: self.bid_queues.len() as u64,
            sealed_bid_count: self.bid_queues.values().map(|queue| queue.bid_count).sum(),
            witness_commitment_count: self.witness_commitments.len() as u64,
            sla_lane_count: self.sla_lanes.len() as u64,
            attestation_count: self.attestations.len() as u64,
            accepted_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.verdict.accepted())
                .count() as u64,
            backlog_control_count: self.backlog_controls.len() as u64,
            rebate_count: self.rebates.len() as u64,
            redeemed_rebate_count: self
                .rebates
                .values()
                .filter(|rebate| rebate.redeemed)
                .count() as u64,
            active_nullifier_count: self.active_nullifiers.len() as u64,
            total_backlog_bytes: self.sla_lanes.values().map(|lane| lane.backlog_bytes).sum(),
            scheduled_diff_bytes: self
                .auctions
                .values()
                .filter(|auction| {
                    matches!(
                        auction.status,
                        AuctionStatus::Scheduled
                            | AuctionStatus::Preconfirmed
                            | AuctionStatus::Settled
                    )
                })
                .map(|auction| auction.diff_bytes)
                .sum(),
            fee_savings_piconero: self
                .rebates
                .values()
                .map(|rebate| rebate.fee_savings_piconero)
                .sum(),
            root_updates: self.counters.root_updates,
        }
    }

    fn compute_state_root(&self) -> String {
        let payload = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config_root": self.roots.config_root,
            "counter_root": self.roots.counter_root,
            "auction_root": self.roots.auction_root,
            "producer_root": self.roots.producer_root,
            "bid_queue_root": self.roots.bid_queue_root,
            "witness_commitment_root": self.roots.witness_commitment_root,
            "sla_lane_root": self.roots.sla_lane_root,
            "attestation_root": self.roots.attestation_root,
            "backlog_control_root": self.roots.backlog_control_root,
            "rebate_root": self.roots.rebate_root,
            "active_nullifier_root": self.roots.active_nullifier_root,
            "public_record_root": self.roots.public_record_root,
        });
        payload_root("STATE-DIFF-AUCTION-SCHEDULER-STATE-ROOT", &payload)
    }

    fn public_record_without_state_root(&self) -> Value {
        let mut roots = self.roots.clone();
        roots.state_root.clear();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn seed_devnet(state: &mut State) {
    let instant_lane = PreconfirmationSlaLane {
        lane_id: "sla:instant-monero-exit".to_string(),
        lane_class: SlaLaneClass::Instant,
        kind: DiffLaneKind::MoneroExitDelta,
        status: BidQueueStatus::Accepting,
        target_ms: SlaLaneClass::Instant.target_ms(),
        hard_sla_ms: 80,
        inflight_bytes: 1_572_864,
        backlog_bytes: 9_437_184,
        max_backlog_bytes: 96 * 1024 * 1024,
        fee_cap_bps: 7,
    };
    let bulk_lane = PreconfirmationSlaLane {
        lane_id: "sla:bulk-contract-storage".to_string(),
        lane_class: SlaLaneClass::Bulk,
        kind: DiffLaneKind::ContractStorageDelta,
        status: BidQueueStatus::Accepting,
        target_ms: SlaLaneClass::Bulk.target_ms(),
        hard_sla_ms: 400,
        inflight_bytes: 6_291_456,
        backlog_bytes: 41_943_040,
        max_backlog_bytes: 256 * 1024 * 1024,
        fee_cap_bps: 5,
    };
    let producer = DiffProducer {
        producer_id: "producer:diff-forge-01".to_string(),
        operator_commitment: fixture_hash("operator", "diff-forge-01"),
        pq_attestation_key_root: fixture_hash("pq-key-root", "diff-forge-01"),
        bonded_stake_piconero: 5_000_000_000,
        max_parallel_diffs: 256,
        median_schedule_ms: 15,
        fee_ceiling_bps: 5,
        reliability_bps: 9_970,
        active: true,
    };
    let queue = SealedBidQueue {
        queue_id: "queue:monero-exit-fast".to_string(),
        lane_id: instant_lane.lane_id.clone(),
        status: BidQueueStatus::Sealed,
        sealed_bid_root: fixture_hash("sealed-bid-root", "monero-exit-fast"),
        bid_count: 37,
        lowest_fee_hint_bps: 3,
        target_clear_ms: 12,
        opened_at_height: state.l2_height,
        expires_at_height: state.l2_height + state.config.bid_ttl_blocks,
    };
    let auction = StateDiffAuction {
        auction_id: "auction:state-diff:devnet:0001".to_string(),
        lane_id: instant_lane.lane_id.clone(),
        queue_id: queue.queue_id.clone(),
        status: AuctionStatus::Open,
        previous_state_root: fixture_hash("previous-state-root", "devnet-0001"),
        target_state_root: fixture_hash("target-state-root", "devnet-0001"),
        state_diff_commitment_root: fixture_hash("diff-commitment", "devnet-0001"),
        encrypted_diff_payload_root: fixture_hash("encrypted-diff", "devnet-0001"),
        public_delta_root: fixture_hash("public-delta", "devnet-0001"),
        diff_bytes: 1_048_576,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        opened_at_height: state.l2_height,
        expires_at_height: state.l2_height + state.config.auction_ttl_blocks,
        max_user_fee_bps: 5,
        selected_producer_id: None,
    };
    let witness = WitnessCommitment {
        witness_id: "witness:devnet:0001".to_string(),
        auction_id: auction.auction_id.clone(),
        producer_id: producer.producer_id.clone(),
        witness_commitment_root: fixture_hash("witness-commitment", "devnet-0001"),
        encrypted_witness_ref_root: fixture_hash("encrypted-witness-ref", "devnet-0001"),
        recursive_witness_hint_root: fixture_hash("recursive-witness", "devnet-0001"),
        witness_bytes: 2_621_440,
        availability_height: state.l2_height + 1,
        expires_at_height: state.l2_height + state.config.witness_ttl_blocks,
    };
    let attestation = PqSchedulerAttestation {
        attestation_id: "attestation:scheduler:devnet:0001".to_string(),
        auction_id: auction.auction_id.clone(),
        producer_id: producer.producer_id.clone(),
        scheduler_commitment_root: fixture_hash("scheduler-commitment", "devnet-0001"),
        verdict: AttestationVerdict::Schedulable,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        schedule_ms: 14,
        fee_bps: 4,
        issued_at_height: state.l2_height + 1,
        expires_at_height: state.l2_height + state.config.attestation_ttl_blocks,
    };
    let control = BacklogControl {
        control_id: "backlog:instant-monero-exit:0001".to_string(),
        lane_id: instant_lane.lane_id.clone(),
        backlog_bytes: instant_lane.backlog_bytes,
        shed_bps: 0,
        rebalance_to_lane_ids: vec![bulk_lane.lane_id.clone()],
        active: false,
        opened_at_height: state.l2_height,
    };
    let rebate = ProducerRebate {
        rebate_id: "rebate:state-diff:devnet:0001".to_string(),
        auction_id: auction.auction_id.clone(),
        producer_id: producer.producer_id.clone(),
        fee_asset_id: state.config.fee_asset_id.clone(),
        rebate_bps: state.config.rebate_bps,
        fee_savings_piconero: 420_000,
        settlement_commitment_root: fixture_hash("rebate-settlement", "devnet-0001"),
        issued_at_height: state.l2_height + 2,
        expires_at_height: state.l2_height + state.config.rebate_ttl_blocks,
        redeemed: false,
    };
    state
        .register_sla_lane(instant_lane)
        .expect("seed instant lane");
    state.register_sla_lane(bulk_lane).expect("seed bulk lane");
    state.register_producer(producer).expect("seed producer");
    state.open_bid_queue(queue).expect("seed queue");
    state.open_auction(auction).expect("seed auction");
    state
        .add_witness_commitment(witness)
        .expect("seed witness commitment");
    state
        .add_scheduler_attestation(attestation)
        .expect("seed scheduler attestation");
    state
        .update_backlog_control(control)
        .expect("seed backlog control");
    state.add_rebate(rebate).expect("seed rebate");
    state
        .active_nullifiers
        .insert(fixture_hash("active-nullifier", "devnet-0001"));
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn fixture_hash(domain: &str, label: &str) -> String {
    domain_hash(
        "STATE-DIFF-AUCTION-SCHEDULER-FIXTURE",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}
