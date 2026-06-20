use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelMerkleReceiptPrefetchRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MERKLE_RECEIPT_PREFETCH_RUNTIME_PROTOCOL_VERSION:
    &str =
    "nebula-private-l2-fast-pq-confidential-parallel-merkle-receipt-prefetch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_MERKLE_RECEIPT_PREFETCH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ZERO_COPY_RECEIPT_LANE_SUITE: &str = "private-l2-zero-copy-confidential-receipt-lanes-v1";
pub const PARALLEL_MERKLE_PREFETCH_SUITE: &str =
    "private-l2-parallel-merkle-receipt-prefetch-root-v1";
pub const PQ_WORKER_QUORUM_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-worker-quorum-prefetch-attestation-v1";
pub const LOW_FEE_BATCH_SCHEDULER_SUITE: &str =
    "private-l2-low-fee-parallel-receipt-prefetch-batch-scheduler-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-parallel-merkle-receipt-prefetch-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_120_000;
pub const DEVNET_EPOCH: u64 = 16_384;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_RECEIPT_LANES: usize = 128;
pub const DEFAULT_MAX_PREFETCH_WINDOWS: usize = 1_048_576;
pub const DEFAULT_WORKER_COUNT: u16 = 32;
pub const DEFAULT_QUORUM_THRESHOLD: u16 = 22;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 80;
pub const DEFAULT_TARGET_MERKLE_BUILD_MS: u64 = 160;
pub const DEFAULT_RECEIPT_WINDOW_TTL_SLOTS: u64 = 32;
pub const DEFAULT_BATCH_FEE_CEILING_MICROS: u64 = 18;
pub const DEFAULT_LOW_FEE_DISCOUNT_BPS: u64 = 1_250;
pub const DEFAULT_MAX_ZERO_COPY_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:LANES";
const D_WINDOWS: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:WINDOWS";
const D_QUORUMS: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:QUORUMS";
const D_BATCHES: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:BATCHES";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-PARALLEL-MERKLE-RECEIPT-PREFETCH:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLaneKind {
    Wallet,
    Payment,
    ContractCall,
    BridgeExit,
    DefiSwap,
    Liquidation,
    RecursiveProof,
    BackgroundWarmup,
}

impl ReceiptLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Payment => "payment",
            Self::ContractCall => "contract_call",
            Self::BridgeExit => "bridge_exit",
            Self::DefiSwap => "defi_swap",
            Self::Liquidation => "liquidation",
            Self::RecursiveProof => "recursive_proof",
            Self::BackgroundWarmup => "background_warmup",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::BridgeExit => 10_000,
            Self::Liquidation => 9_700,
            Self::DefiSwap => 9_250,
            Self::Payment => 8_900,
            Self::ContractCall => 8_500,
            Self::Wallet => 8_000,
            Self::RecursiveProof => 7_600,
            Self::BackgroundWarmup => 4_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Saturated,
    LowFeeOnly,
    Draining,
    Paused,
}

impl LaneStatus {
    pub fn accepts_prefetch(self) -> bool {
        matches!(self, Self::Open | Self::Saturated | Self::LowFeeOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchStatus {
    Planned,
    ReadingZeroCopy,
    BuildingMerkle,
    QuorumAttested,
    Scheduled,
    Finalized,
    Invalidated,
    Expired,
}

impl PrefetchStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::ReadingZeroCopy | Self::BuildingMerkle | Self::QuorumAttested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumStatus {
    Collecting,
    Verified,
    Degraded,
    Slashed,
    Expired,
}

impl QuorumStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchClass {
    UltraFast,
    LowFee,
    PrivacyFirst,
    Recovery,
}

impl BatchClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFast => "ultra_fast",
            Self::LowFee => "low_fee",
            Self::PrivacyFirst => "privacy_first",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub zero_copy_receipt_lane_suite: String,
    pub parallel_merkle_prefetch_suite: String,
    pub pq_worker_quorum_suite: String,
    pub low_fee_batch_scheduler_suite: String,
    pub public_record_scheme: String,
    pub max_receipt_lanes: usize,
    pub max_prefetch_windows: usize,
    pub worker_count: u16,
    pub quorum_threshold: u16,
    pub min_pq_security_bits: u16,
    pub target_prefetch_ms: u64,
    pub target_merkle_build_ms: u64,
    pub receipt_window_ttl_slots: u64,
    pub batch_fee_ceiling_micros: u64,
    pub low_fee_discount_bps: u64,
    pub max_zero_copy_bytes: u64,
    pub min_privacy_set_size: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            zero_copy_receipt_lane_suite: ZERO_COPY_RECEIPT_LANE_SUITE.to_string(),
            parallel_merkle_prefetch_suite: PARALLEL_MERKLE_PREFETCH_SUITE.to_string(),
            pq_worker_quorum_suite: PQ_WORKER_QUORUM_SUITE.to_string(),
            low_fee_batch_scheduler_suite: LOW_FEE_BATCH_SCHEDULER_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            max_receipt_lanes: DEFAULT_MAX_RECEIPT_LANES,
            max_prefetch_windows: DEFAULT_MAX_PREFETCH_WINDOWS,
            worker_count: DEFAULT_WORKER_COUNT,
            quorum_threshold: DEFAULT_QUORUM_THRESHOLD,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            target_merkle_build_ms: DEFAULT_TARGET_MERKLE_BUILD_MS,
            receipt_window_ttl_slots: DEFAULT_RECEIPT_WINDOW_TTL_SLOTS,
            batch_fee_ceiling_micros: DEFAULT_BATCH_FEE_CEILING_MICROS,
            low_fee_discount_bps: DEFAULT_LOW_FEE_DISCOUNT_BPS,
            max_zero_copy_bytes: DEFAULT_MAX_ZERO_COPY_BYTES,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.quorum_threshold == 0 || self.quorum_threshold > self.worker_count {
            return Err("worker quorum threshold must fit configured workers".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below 192 bits".to_string());
        }
        if self.low_fee_discount_bps > MAX_BPS {
            return Err("low-fee discount exceeds basis point ceiling".to_string());
        }
        if self.max_zero_copy_bytes == 0 {
            return Err("zero-copy byte ceiling must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub zero_copy_receipts_mapped: u64,
    pub zero_copy_bytes_mapped: u64,
    pub prefetch_windows_opened: u64,
    pub merkle_roots_prefetched: u64,
    pub pq_worker_quorums_verified: u64,
    pub batches_scheduled: u64,
    pub low_fee_batches_scheduled: u64,
    pub fees_discounted_micros: u64,
    pub deterministic_roots_emitted: u64,
    pub invalidations: u64,
    pub public_records_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub receipt_lanes_root: String,
    pub prefetch_windows_root: String,
    pub worker_quorums_root: String,
    pub batch_schedules_root: String,
    pub public_records_root: String,
    pub deterministic_state_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZeroCopyReceiptLane {
    pub lane_id: String,
    pub kind: ReceiptLaneKind,
    pub status: LaneStatus,
    pub priority_weight: u64,
    pub mapped_receipts: u64,
    pub mapped_bytes: u64,
    pub capacity_receipts: u64,
    pub privacy_set_size: u64,
    pub lane_root: String,
}

impl ZeroCopyReceiptLane {
    pub fn new(lane_id: impl Into<String>, kind: ReceiptLaneKind, capacity_receipts: u64) -> Self {
        let mut lane = Self {
            lane_id: lane_id.into(),
            kind,
            status: LaneStatus::Open,
            priority_weight: kind.default_priority(),
            mapped_receipts: 0,
            mapped_bytes: 0,
            capacity_receipts,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            lane_root: String::new(),
        };
        lane.refresh_root();
        lane
    }

    pub fn map_receipts(&mut self, receipts: u64, bytes: u64) {
        self.mapped_receipts = self.mapped_receipts.saturating_add(receipts);
        self.mapped_bytes = self.mapped_bytes.saturating_add(bytes);
        self.refresh_root();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "priority_weight": self.priority_weight,
            "mapped_receipts": self.mapped_receipts,
            "mapped_bytes": self.mapped_bytes,
            "capacity_receipts": self.capacity_receipts,
            "privacy_set_size": self.privacy_set_size,
            "lane_root": self.lane_root
        })
    }

    fn refresh_root(&mut self) {
        self.lane_root = record_root("ZERO-COPY-RECEIPT-LANE", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: PrefetchStatus,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub receipt_count: u64,
    pub zero_copy_bytes: u64,
    pub merkle_leaf_root: String,
    pub deterministic_receipt_root: String,
    pub window_root: String,
}

impl PrefetchWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.window_root = record_root("PREFETCH-WINDOW", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWorkerQuorum {
    pub quorum_id: String,
    pub window_id: String,
    pub status: QuorumStatus,
    pub worker_count: u16,
    pub threshold: u16,
    pub signatures_verified: u16,
    pub pq_suite: String,
    pub security_bits: u16,
    pub aggregate_signature_root: String,
    pub quorum_root: String,
}

impl PqWorkerQuorum {
    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && self.security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.signatures_verified >= self.threshold
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.quorum_root = record_root("PQ-WORKER-QUORUM", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchSchedule {
    pub batch_id: String,
    pub window_id: String,
    pub class: BatchClass,
    pub scheduled_slot: u64,
    pub max_fee_micros: u64,
    pub discount_bps: u64,
    pub discounted_fee_micros: u64,
    pub deterministic_root: String,
    pub schedule_root: String,
}

impl LowFeeBatchSchedule {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "window_id": self.window_id,
            "class": self.class.as_str(),
            "scheduled_slot": self.scheduled_slot,
            "max_fee_micros": self.max_fee_micros,
            "discount_bps": self.discount_bps,
            "discounted_fee_micros": self.discounted_fee_micros,
            "deterministic_root": self.deterministic_root,
            "schedule_root": self.schedule_root
        })
    }

    fn refresh_root(&mut self) {
        self.schedule_root = record_root("LOW-FEE-BATCH-SCHEDULE", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub lane_count: usize,
    pub prefetch_window_count: usize,
    pub worker_quorum_count: usize,
    pub batch_schedule_count: usize,
    pub zero_copy_bytes_mapped: u64,
    pub merkle_roots_prefetched: u64,
    pub roots: Roots,
    pub record_root: String,
}

impl OperatorPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub current_slot: u64,
    pub receipt_lanes: BTreeMap<String, ZeroCopyReceiptLane>,
    pub prefetch_windows: BTreeMap<String, PrefetchWindow>,
    pub worker_quorums: BTreeMap<String, PqWorkerQuorum>,
    pub batch_schedules: BTreeMap<String, LowFeeBatchSchedule>,
    pub public_records: BTreeMap<String, OperatorPublicRecord>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            current_slot: 0,
            receipt_lanes: BTreeMap::new(),
            prefetch_windows: BTreeMap::new(),
            worker_quorums: BTreeMap::new(),
            batch_schedules: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.current_slot = 64;
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn register_lane(&mut self, lane: ZeroCopyReceiptLane) -> Result<String> {
        if self.receipt_lanes.len() >= self.config.max_receipt_lanes {
            return Err("receipt lane capacity exceeded".to_string());
        }
        if !lane.status.accepts_prefetch() {
            return Err("receipt lane does not accept prefetch".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
        self.receipt_lanes.insert(lane_id.clone(), lane);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_prefetch_window(
        &mut self,
        lane_id: &str,
        first_sequence: u64,
        receipt_count: u64,
        zero_copy_bytes: u64,
    ) -> Result<String> {
        if self.prefetch_windows.len() >= self.config.max_prefetch_windows {
            return Err("prefetch window capacity exceeded".to_string());
        }
        if zero_copy_bytes > self.config.max_zero_copy_bytes {
            return Err("zero-copy receipt window exceeds byte ceiling".to_string());
        }
        let lane = self
            .receipt_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "receipt lane not found".to_string())?;
        if !lane.status.accepts_prefetch() {
            return Err("receipt lane does not accept prefetch".to_string());
        }
        lane.map_receipts(receipt_count, zero_copy_bytes);
        self.counters.zero_copy_receipts_mapped = self
            .counters
            .zero_copy_receipts_mapped
            .saturating_add(receipt_count);
        self.counters.zero_copy_bytes_mapped = self
            .counters
            .zero_copy_bytes_mapped
            .saturating_add(zero_copy_bytes);
        self.counters.prefetch_windows_opened =
            self.counters.prefetch_windows_opened.saturating_add(1);
        let last_sequence = first_sequence.saturating_add(receipt_count.saturating_sub(1));
        let lane_root = lane.lane_root.clone();
        let leaf_root = deterministic_leaf_root(lane_id, first_sequence, last_sequence);
        let deterministic_receipt_root = deterministic_receipt_root(
            lane_id,
            self.current_slot,
            &lane_root,
            &leaf_root,
            receipt_count,
        );
        let mut window = PrefetchWindow {
            window_id: format!("prefetch-window-{}-{}", lane_id, first_sequence),
            lane_id: lane_id.to_string(),
            status: PrefetchStatus::BuildingMerkle,
            first_sequence,
            last_sequence,
            slot: self.current_slot,
            expires_at_slot: self
                .current_slot
                .saturating_add(self.config.receipt_window_ttl_slots),
            receipt_count,
            zero_copy_bytes,
            merkle_leaf_root: leaf_root,
            deterministic_receipt_root,
            window_root: String::new(),
        };
        window.refresh_root();
        let window_id = window.window_id.clone();
        self.prefetch_windows.insert(window_id.clone(), window);
        self.counters.merkle_roots_prefetched =
            self.counters.merkle_roots_prefetched.saturating_add(1);
        self.counters.deterministic_roots_emitted =
            self.counters.deterministic_roots_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn attest_worker_quorum(
        &mut self,
        window_id: &str,
        signatures_verified: u16,
    ) -> Result<()> {
        let window = self
            .prefetch_windows
            .get_mut(window_id)
            .ok_or_else(|| "prefetch window not found".to_string())?;
        let status = if signatures_verified >= self.config.quorum_threshold {
            QuorumStatus::Verified
        } else {
            QuorumStatus::Degraded
        };
        let mut quorum = PqWorkerQuorum {
            quorum_id: format!("pq-worker-quorum-{window_id}"),
            window_id: window_id.to_string(),
            status,
            worker_count: self.config.worker_count,
            threshold: self.config.quorum_threshold,
            signatures_verified,
            pq_suite: PQ_WORKER_QUORUM_SUITE.to_string(),
            security_bits: self.config.min_pq_security_bits,
            aggregate_signature_root: dev_hash(
                "worker-quorum-signature",
                signatures_verified as u64,
            ),
            quorum_root: String::new(),
        };
        quorum.refresh_root();
        if quorum.accepted() {
            window.status = PrefetchStatus::QuorumAttested;
            self.counters.pq_worker_quorums_verified =
                self.counters.pq_worker_quorums_verified.saturating_add(1);
        }
        self.worker_quorums.insert(quorum.quorum_id.clone(), quorum);
        self.refresh_roots();
        Ok(())
    }

    pub fn schedule_low_fee_batch(&mut self, window_id: &str, class: BatchClass) -> Result<String> {
        let window = self
            .prefetch_windows
            .get_mut(window_id)
            .ok_or_else(|| "prefetch window not found".to_string())?;
        if !matches!(
            window.status,
            PrefetchStatus::QuorumAttested | PrefetchStatus::BuildingMerkle
        ) {
            return Err("prefetch window is not schedulable".to_string());
        }
        let discounted_fee_micros = self
            .config
            .batch_fee_ceiling_micros
            .saturating_mul(MAX_BPS.saturating_sub(self.config.low_fee_discount_bps))
            / MAX_BPS;
        let mut batch = LowFeeBatchSchedule {
            batch_id: format!("low-fee-batch-{window_id}"),
            window_id: window_id.to_string(),
            class,
            scheduled_slot: self.current_slot.saturating_add(1),
            max_fee_micros: self.config.batch_fee_ceiling_micros,
            discount_bps: self.config.low_fee_discount_bps,
            discounted_fee_micros,
            deterministic_root: window.deterministic_receipt_root.clone(),
            schedule_root: String::new(),
        };
        batch.refresh_root();
        window.status = PrefetchStatus::Scheduled;
        let batch_id = batch.batch_id.clone();
        self.batch_schedules.insert(batch_id.clone(), batch);
        self.counters.batches_scheduled = self.counters.batches_scheduled.saturating_add(1);
        if class == BatchClass::LowFee {
            self.counters.low_fee_batches_scheduled =
                self.counters.low_fee_batches_scheduled.saturating_add(1);
        }
        self.counters.fees_discounted_micros = self.counters.fees_discounted_micros.saturating_add(
            self.config
                .batch_fee_ceiling_micros
                .saturating_sub(discounted_fee_micros),
        );
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "receipt_lanes": self.receipt_lanes.values().map(ZeroCopyReceiptLane::public_record).collect::<Vec<_>>(),
            "prefetch_windows": self.prefetch_windows.values().map(PrefetchWindow::public_record).collect::<Vec<_>>(),
            "worker_quorums": self.worker_quorums.values().map(PqWorkerQuorum::public_record).collect::<Vec<_>>(),
            "batch_schedules": self.batch_schedules.values().map(LowFeeBatchSchedule::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(OperatorPublicRecord::public_record).collect::<Vec<_>>(),
            "operator_safe": true,
            "confidential_receipt_payloads_redacted": true,
            "deterministic_roots": true
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            receipt_lanes_root: merkle_records(D_LANES, &self.receipt_lanes),
            prefetch_windows_root: merkle_records(D_WINDOWS, &self.prefetch_windows),
            worker_quorums_root: merkle_records(D_QUORUMS, &self.worker_quorums),
            batch_schedules_root: merkle_records(D_BATCHES, &self.batch_schedules),
            public_records_root: merkle_records(D_PUBLIC, &self.public_records),
            deterministic_state_root: String::new(),
            state_root: String::new(),
        };
        roots.deterministic_state_root = roots.root();
        roots.state_root = payload_root(D_ROOTS, &roots.public_record());
        self.roots = roots;
    }

    fn seed_devnet(&mut self) {
        let lanes = [
            (ReceiptLaneKind::Wallet, 6_000),
            (ReceiptLaneKind::Payment, 8_000),
            (ReceiptLaneKind::ContractCall, 5_500),
            (ReceiptLaneKind::BridgeExit, 3_000),
            (ReceiptLaneKind::DefiSwap, 7_500),
            (ReceiptLaneKind::Liquidation, 2_000),
        ];
        for (index, (kind, capacity)) in lanes.iter().enumerate() {
            let lane_id = format!("zero-copy-lane-devnet-{:02}", index + 1);
            let mut lane = ZeroCopyReceiptLane::new(lane_id.clone(), *kind, *capacity);
            if matches!(kind, ReceiptLaneKind::Payment | ReceiptLaneKind::Wallet) {
                lane.status = LaneStatus::LowFeeOnly;
                lane.refresh_root();
            }
            let _ = self.register_lane(lane);
            let receipt_count = 384 + index as u64 * 96;
            let zero_copy_bytes = receipt_count.saturating_mul(192);
            let window_id = self
                .open_prefetch_window(
                    &lane_id,
                    250_000 + index as u64 * 20_000,
                    receipt_count,
                    zero_copy_bytes,
                )
                .expect("devnet lane accepts prefetch");
            let signatures = self
                .config
                .quorum_threshold
                .saturating_add((index as u16) % 3)
                .min(self.config.worker_count);
            let _ = self.attest_worker_quorum(&window_id, signatures);
            let batch_class = if matches!(kind, ReceiptLaneKind::Payment | ReceiptLaneKind::Wallet)
            {
                BatchClass::LowFee
            } else if matches!(
                kind,
                ReceiptLaneKind::BridgeExit | ReceiptLaneKind::Liquidation
            ) {
                BatchClass::UltraFast
            } else {
                BatchClass::PrivacyFirst
            };
            let _ = self.schedule_low_fee_batch(&window_id, batch_class);
        }
    }

    fn emit_public_record(&mut self) {
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-parallel-merkle-receipt-prefetch".to_string(),
            height: self.height,
            epoch: self.epoch,
            lane_count: self.receipt_lanes.len(),
            prefetch_window_count: self.prefetch_windows.len(),
            worker_quorum_count: self.worker_quorums.len(),
            batch_schedule_count: self.batch_schedules.len(),
            zero_copy_bytes_mapped: self.counters.zero_copy_bytes_mapped,
            merkle_roots_prefetched: self.counters.merkle_roots_prefetched,
            roots: self.roots.clone(),
            record_root: String::new(),
        };
        record.record_root = record_root("OPERATOR-PUBLIC-RECORD", &record.public_record());
        self.public_records.insert(record.record_id.clone(), record);
        self.counters.public_records_emitted = self.public_records.len() as u64;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-MERKLE-RECEIPT-PREFETCH-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn deterministic_leaf_root(lane_id: &str, first_sequence: u64, last_sequence: u64) -> String {
    domain_hash(
        ZERO_COPY_RECEIPT_LANE_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(first_sequence),
            HashPart::U64(last_sequence),
        ],
        32,
    )
}

fn deterministic_receipt_root(
    lane_id: &str,
    slot: u64,
    lane_root: &str,
    leaf_root: &str,
    receipt_count: u64,
) -> String {
    domain_hash(
        PARALLEL_MERKLE_PREFETCH_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(slot),
            HashPart::Str(lane_root),
            HashPart::Str(leaf_root),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

fn merkle_records<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn dev_hash(label: &str, index: u64) -> String {
    domain_hash(
        D_DEVNET,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
        32,
    )
}
