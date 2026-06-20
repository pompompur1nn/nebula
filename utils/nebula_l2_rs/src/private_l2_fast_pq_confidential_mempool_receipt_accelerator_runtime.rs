use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialMempoolReceiptAcceleratorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MEMPOOL_RECEIPT_ACCELERATOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-mempool-receipt-accelerator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MEMPOOL_RECEIPT_ACCELERATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 3_360_000;
pub const DEVNET_EPOCH: u64 = 10_240;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_RECEIPT_QUEUE_SUITE: &str =
    "ml-kem-1024+xwing-encrypted-mempool-receipt-queue-v1";
pub const FAST_ACK_LANE_SUITE: &str = "pq-fast-acknowledgement-lane-v1";
pub const PQ_RECEIPT_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256s-receipt-accelerator-attestation-v1";
pub const PRECONFIRMATION_ROOT_SUITE: &str = "roots-only-preconfirmation-receipt-accumulator-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-receipt-acceleration-rebate-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-mempool-receipt-accelerator-public-record-v1";
pub const DEFAULT_SHARD_COUNT: u16 = 8;
pub const DEFAULT_FAST_ACK_TARGET_MS: u64 = 120;
pub const DEFAULT_RECEIPT_TTL_SLOTS: u64 = 48;
pub const DEFAULT_QUEUE_SOFT_LIMIT: u32 = 32_768;
pub const DEFAULT_QUEUE_HARD_LIMIT: u32 = 65_536;
pub const DEFAULT_WALLET_CURSOR_WINDOW: u64 = 8_192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_250;
pub const DEFAULT_ACCELERATION_FEE_MICROS: u64 = 9;
pub const DEFAULT_MAX_BACKPRESSURE_SCORE: u16 = 10_000;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:ROOTS";
const D_QUEUES: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:QUEUES";
const D_ACK_LANES: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:ACK-LANES";
const D_CURSORS: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:CURSORS";
const D_BACKPRESSURE: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:BACKPRESSURE";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:ATTESTATIONS";
const D_PRECONFIRMATIONS: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:PRECONFIRMATIONS";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:REBATES";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-MEMPOOL-RECEIPT-ACCELERATOR:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLane {
    WalletSync,
    Payment,
    SwapIntent,
    ContractCall,
    BridgeExit,
    Liquidation,
    ProofCarry,
    Recovery,
}

impl ReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSync => "wallet_sync",
            Self::Payment => "payment",
            Self::SwapIntent => "swap_intent",
            Self::ContractCall => "contract_call",
            Self::BridgeExit => "bridge_exit",
            Self::Liquidation => "liquidation",
            Self::ProofCarry => "proof_carry",
            Self::Recovery => "recovery",
        }
    }

    pub fn speed_weight(self) -> u64 {
        match self {
            Self::Liquidation => 10_000,
            Self::BridgeExit => 9_200,
            Self::Recovery => 8_800,
            Self::Payment => 8_000,
            Self::SwapIntent => 7_400,
            Self::ContractCall => 6_800,
            Self::ProofCarry => 6_000,
            Self::WalletSync => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Open,
    Accelerating,
    Throttled,
    Draining,
    Paused,
}

impl QueueStatus {
    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Open | Self::Accelerating | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AckStatus {
    Pending,
    Sent,
    Witnessed,
    Quorum,
    Expired,
}

impl AckStatus {
    pub fn acknowledged(self) -> bool {
        matches!(self, Self::Witnessed | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureMode {
    Accepting,
    PrioritizingFastAck,
    RebatingLowFee,
    SheddingLowFee,
    Paused,
}

impl BackpressureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::PrioritizingFastAck => "prioritizing_fast_ack",
            Self::RebatingLowFee => "rebating_low_fee",
            Self::SheddingLowFee => "shedding_low_fee",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Observed,
    Verified,
    Counted,
    Rejected,
    Superseded,
}

impl AttestationStatus {
    pub fn counts_for_root(self) -> bool {
        matches!(self, Self::Verified | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    Settled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub shard_count: u16,
    pub queue_soft_limit: u32,
    pub queue_hard_limit: u32,
    pub fast_ack_target_ms: u64,
    pub receipt_ttl_slots: u64,
    pub wallet_cursor_window: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub fee_asset_id: String,
    pub acceleration_fee_micros: u64,
    pub low_fee_rebate_bps: u64,
    pub max_backpressure_score: u16,
    pub enable_low_fee_rebates: bool,
    pub enable_preconfirmation_roots: bool,
    pub enable_operator_safe_public_records: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            shard_count: DEFAULT_SHARD_COUNT,
            queue_soft_limit: DEFAULT_QUEUE_SOFT_LIMIT,
            queue_hard_limit: DEFAULT_QUEUE_HARD_LIMIT,
            fast_ack_target_ms: DEFAULT_FAST_ACK_TARGET_MS,
            receipt_ttl_slots: DEFAULT_RECEIPT_TTL_SLOTS,
            wallet_cursor_window: DEFAULT_WALLET_CURSOR_WINDOW,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: 65_536,
            fee_asset_id: "piconero-devnet".to_string(),
            acceleration_fee_micros: DEFAULT_ACCELERATION_FEE_MICROS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_backpressure_score: DEFAULT_MAX_BACKPRESSURE_SCORE,
            enable_low_fee_rebates: true,
            enable_preconfirmation_roots: true,
            enable_operator_safe_public_records: true,
        }
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
    pub encrypted_receipts_queued: u64,
    pub receipts_accelerated: u64,
    pub fast_acks_sent: u64,
    pub fast_acks_quorum: u64,
    pub wallet_cursors_advanced: u64,
    pub shard_backpressure_events: u64,
    pub pq_attestations_verified: u64,
    pub preconfirmation_roots_sealed: u64,
    pub low_fee_rebates_reserved: u64,
    pub low_fee_rebates_settled: u64,
    pub receipts_expired: u64,
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
    pub queues_root: String,
    pub ack_lanes_root: String,
    pub wallet_cursors_root: String,
    pub shard_backpressure_root: String,
    pub pq_attestations_root: String,
    pub preconfirmation_roots_root: String,
    pub low_fee_rebates_root: String,
    pub public_records_root: String,
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
pub struct EncryptedReceiptQueue {
    pub queue_id: String,
    pub shard_id: u16,
    pub lane: ReceiptLane,
    pub status: QueueStatus,
    pub encrypted_head_root: String,
    pub encrypted_tail_root: String,
    pub receipt_count: u32,
    pub accelerated_count: u32,
    pub oldest_slot: u64,
    pub latest_slot: u64,
    pub avg_ack_latency_ms: u64,
    pub queue_root: String,
}

impl EncryptedReceiptQueue {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "encrypted_head_root": self.encrypted_head_root,
            "encrypted_tail_root": self.encrypted_tail_root,
            "receipt_count": self.receipt_count,
            "accelerated_count": self.accelerated_count,
            "oldest_slot": self.oldest_slot,
            "latest_slot": self.latest_slot,
            "avg_ack_latency_ms": self.avg_ack_latency_ms,
            "queue_root": self.queue_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastAcknowledgementLane {
    pub ack_id: String,
    pub queue_id: String,
    pub shard_id: u16,
    pub lane: ReceiptLane,
    pub receipt_commitment: String,
    pub status: AckStatus,
    pub ack_slot: u64,
    pub target_ms: u64,
    pub observed_ms: u64,
    pub witness_weight: u64,
    pub ack_root: String,
}

impl FastAcknowledgementLane {
    pub fn public_record(&self) -> Value {
        json!({
            "ack_id": self.ack_id,
            "queue_id": self.queue_id,
            "shard_id": self.shard_id,
            "lane": self.lane.as_str(),
            "receipt_commitment": self.receipt_commitment,
            "status": self.status,
            "ack_slot": self.ack_slot,
            "target_ms": self.target_ms,
            "observed_ms": self.observed_ms,
            "witness_weight": self.witness_weight,
            "ack_root": self.ack_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCursor {
    pub wallet_cursor_id: String,
    pub wallet_tag_root: String,
    pub shard_id: u16,
    pub next_sequence: u64,
    pub last_ack_id: String,
    pub visible_receipt_count: u64,
    pub cursor_window: u64,
    pub cursor_root: String,
}

impl WalletCursor {
    pub fn public_record(&self) -> Value {
        json!({
            "wallet_cursor_id": self.wallet_cursor_id,
            "wallet_tag_root": self.wallet_tag_root,
            "shard_id": self.shard_id,
            "next_sequence": self.next_sequence,
            "last_ack_id": self.last_ack_id,
            "visible_receipt_count": self.visible_receipt_count,
            "cursor_window": self.cursor_window,
            "cursor_root": self.cursor_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardBackpressure {
    pub shard_id: u16,
    pub mode: BackpressureMode,
    pub queue_depth: u32,
    pub soft_limit: u32,
    pub hard_limit: u32,
    pub pressure_score: u16,
    pub low_fee_shed_count: u64,
    pub backpressure_root: String,
}

impl ShardBackpressure {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "mode": self.mode.as_str(),
            "queue_depth": self.queue_depth,
            "soft_limit": self.soft_limit,
            "hard_limit": self.hard_limit,
            "pressure_score": self.pressure_score,
            "low_fee_shed_count": self.low_fee_shed_count,
            "backpressure_root": self.backpressure_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqReceiptAttestation {
    pub attestation_id: String,
    pub ack_id: String,
    pub signer_id: String,
    pub signer_weight: u64,
    pub status: AttestationStatus,
    pub pq_suite: String,
    pub receipt_root: String,
    pub signature_root: String,
    pub attestation_root: String,
}

impl PqReceiptAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "ack_id": self.ack_id,
            "signer_id": self.signer_id,
            "signer_weight": self.signer_weight,
            "status": self.status,
            "pq_suite": self.pq_suite,
            "receipt_root": self.receipt_root,
            "signature_root": self.signature_root,
            "attestation_root": self.attestation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationRoot {
    pub preconfirmation_id: String,
    pub shard_id: u16,
    pub slot: u64,
    pub queue_root: String,
    pub ack_root: String,
    pub attestation_root: String,
    pub deterministic_root: String,
    pub preconfirmation_root: String,
}

impl PreconfirmationRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "shard_id": self.shard_id,
            "slot": self.slot,
            "queue_root": self.queue_root,
            "ack_root": self.ack_root,
            "attestation_root": self.attestation_root,
            "deterministic_root": self.deterministic_root,
            "preconfirmation_root": self.preconfirmation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAccelerationRebate {
    pub rebate_id: String,
    pub ack_id: String,
    pub wallet_cursor_id: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub accelerated_fee_micros: u64,
    pub rebate_bps: u64,
    pub rebate_micros: u64,
    pub settlement_root: String,
    pub rebate_root: String,
}

impl LowFeeAccelerationRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "ack_id": self.ack_id,
            "wallet_cursor_id": self.wallet_cursor_id,
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "accelerated_fee_micros": self.accelerated_fee_micros,
            "rebate_bps": self.rebate_bps,
            "rebate_micros": self.rebate_micros,
            "settlement_root": self.settlement_root,
            "rebate_root": self.rebate_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub shard_count: u16,
    pub queue_count: usize,
    pub fast_ack_count: usize,
    pub wallet_cursor_count: usize,
    pub preconfirmation_count: usize,
    pub total_queue_depth: u64,
    pub max_backpressure_mode: BackpressureMode,
    pub low_fee_rebate_micros: u64,
    pub roots: Roots,
    pub record_root: String,
}

impl OperatorPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "height": self.height,
            "epoch": self.epoch,
            "shard_count": self.shard_count,
            "queue_count": self.queue_count,
            "fast_ack_count": self.fast_ack_count,
            "wallet_cursor_count": self.wallet_cursor_count,
            "preconfirmation_count": self.preconfirmation_count,
            "total_queue_depth": self.total_queue_depth,
            "max_backpressure_mode": self.max_backpressure_mode.as_str(),
            "low_fee_rebate_micros": self.low_fee_rebate_micros,
            "roots": self.roots.public_record(),
            "record_root": self.record_root,
            "operator_safe": true,
            "encrypted_payloads_redacted": true
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_slot: u64,
    pub queues: BTreeMap<String, EncryptedReceiptQueue>,
    pub ack_lanes: BTreeMap<String, FastAcknowledgementLane>,
    pub wallet_cursors: BTreeMap<String, WalletCursor>,
    pub shard_backpressure: BTreeMap<String, ShardBackpressure>,
    pub pq_attestations: BTreeMap<String, PqReceiptAttestation>,
    pub preconfirmation_roots: BTreeMap<String, PreconfirmationRoot>,
    pub low_fee_rebates: BTreeMap<String, LowFeeAccelerationRebate>,
    pub public_records: BTreeMap<String, OperatorPublicRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_slot: DEVNET_EPOCH * 32,
            queues: BTreeMap::new(),
            ack_lanes: BTreeMap::new(),
            wallet_cursors: BTreeMap::new(),
            shard_backpressure: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            preconfirmation_roots: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.counters.receipts_accelerated = state.counters.receipts_accelerated.saturating_add(4);
        state.counters.fast_acks_quorum = state.counters.fast_acks_quorum.saturating_add(2);
        state.counters.low_fee_rebates_settled =
            state.counters.low_fee_rebates_settled.saturating_add(1);
        if let Some(rebate) = state.low_fee_rebates.values_mut().next() {
            rebate.status = RebateStatus::Settled;
            rebate.rebate_root = record_root("REBATE", &rebate.public_record());
        }
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "queue_count": self.queues.len(),
            "ack_lane_count": self.ack_lanes.len(),
            "wallet_cursor_count": self.wallet_cursors.len(),
            "shard_backpressure_count": self.shard_backpressure.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "preconfirmation_root_count": self.preconfirmation_roots.len(),
            "low_fee_rebate_count": self.low_fee_rebates.len(),
            "public_records": public_record_map(&self.public_records),
            "operator_safe": true,
            "encrypted_receipts_redacted": true
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            queues_root: merkle_records(D_QUEUES, &self.queues),
            ack_lanes_root: merkle_records(D_ACK_LANES, &self.ack_lanes),
            wallet_cursors_root: merkle_records(D_CURSORS, &self.wallet_cursors),
            shard_backpressure_root: merkle_records(D_BACKPRESSURE, &self.shard_backpressure),
            pq_attestations_root: merkle_records(D_ATTESTATIONS, &self.pq_attestations),
            preconfirmation_roots_root: merkle_records(
                D_PRECONFIRMATIONS,
                &self.preconfirmation_roots,
            ),
            low_fee_rebates_root: merkle_records(D_REBATES, &self.low_fee_rebates),
            public_records_root: merkle_records(D_PUBLIC, &self.public_records),
            state_root: String::new(),
        };
        roots.state_root = payload_root(D_ROOTS, &roots.public_record());
        self.roots = roots;
    }

    fn seed_devnet(&mut self) {
        let lanes = [
            ReceiptLane::WalletSync,
            ReceiptLane::Payment,
            ReceiptLane::SwapIntent,
            ReceiptLane::BridgeExit,
        ];
        let mut seen_shards = BTreeSet::new();
        for (index, lane) in lanes.iter().enumerate() {
            let shard_id = index as u16;
            seen_shards.insert(shard_id);
            let queue_id = format!("queue-devnet-shard-{}-{}", shard_id, lane.as_str());
            let receipt_count = 512 + (index as u32 * 128);
            let status = if index == 3 {
                QueueStatus::Accelerating
            } else {
                QueueStatus::Open
            };
            let mut queue = EncryptedReceiptQueue {
                queue_id: queue_id.clone(),
                shard_id,
                lane: *lane,
                status,
                encrypted_head_root: dev_hash("encrypted-head", index as u64),
                encrypted_tail_root: dev_hash("encrypted-tail", index as u64),
                receipt_count,
                accelerated_count: 128 + (index as u32 * 24),
                oldest_slot: self.current_slot.saturating_sub(12 + index as u64),
                latest_slot: self.current_slot.saturating_sub(index as u64),
                avg_ack_latency_ms: DEFAULT_FAST_ACK_TARGET_MS.saturating_sub(index as u64 * 9),
                queue_root: String::new(),
            };
            queue.queue_root = record_root("QUEUE", &queue.public_record());
            self.counters.encrypted_receipts_queued = self
                .counters
                .encrypted_receipts_queued
                .saturating_add(queue.receipt_count as u64);
            self.counters.receipts_accelerated = self
                .counters
                .receipts_accelerated
                .saturating_add(queue.accelerated_count as u64);
            self.queues.insert(queue_id.clone(), queue);

            let ack_id = format!("ack-devnet-{:02}", index + 1);
            let mut ack = FastAcknowledgementLane {
                ack_id: ack_id.clone(),
                queue_id: queue_id.clone(),
                shard_id,
                lane: *lane,
                receipt_commitment: dev_hash("receipt-commitment", index as u64),
                status: if index % 2 == 0 {
                    AckStatus::Quorum
                } else {
                    AckStatus::Witnessed
                },
                ack_slot: self.current_slot.saturating_add(index as u64),
                target_ms: self.config.fast_ack_target_ms,
                observed_ms: DEFAULT_FAST_ACK_TARGET_MS.saturating_sub(index as u64 * 11),
                witness_weight: 67 + index as u64 * 8,
                ack_root: String::new(),
            };
            ack.ack_root = record_root("FAST-ACK", &ack.public_record());
            self.counters.fast_acks_sent = self.counters.fast_acks_sent.saturating_add(1);
            if ack.status.acknowledged() {
                self.counters.fast_acks_quorum = self.counters.fast_acks_quorum.saturating_add(1);
            }
            self.ack_lanes.insert(ack_id.clone(), ack);

            let cursor_id = format!("wallet-cursor-devnet-{:02}", index + 1);
            let mut cursor = WalletCursor {
                wallet_cursor_id: cursor_id.clone(),
                wallet_tag_root: dev_hash("wallet-tag", index as u64),
                shard_id,
                next_sequence: 10_000 + index as u64 * 512,
                last_ack_id: ack_id.clone(),
                visible_receipt_count: 96 + index as u64 * 16,
                cursor_window: self.config.wallet_cursor_window,
                cursor_root: String::new(),
            };
            cursor.cursor_root = record_root("WALLET-CURSOR", &cursor.public_record());
            self.counters.wallet_cursors_advanced =
                self.counters.wallet_cursors_advanced.saturating_add(1);
            self.wallet_cursors.insert(cursor_id.clone(), cursor);

            let mut attestation = PqReceiptAttestation {
                attestation_id: format!("pq-attestation-devnet-{:02}", index + 1),
                ack_id: ack_id.clone(),
                signer_id: format!("operator-pq-signer-{:02}", index + 1),
                signer_weight: 24 + index as u64 * 7,
                status: AttestationStatus::Verified,
                pq_suite: PQ_RECEIPT_ATTESTATION_SUITE.to_string(),
                receipt_root: dev_hash("attested-receipt", index as u64),
                signature_root: dev_hash("pq-signature", index as u64),
                attestation_root: String::new(),
            };
            attestation.attestation_root =
                record_root("PQ-ATTESTATION", &attestation.public_record());
            if attestation.status.counts_for_root() {
                self.counters.pq_attestations_verified =
                    self.counters.pq_attestations_verified.saturating_add(1);
            }
            self.pq_attestations
                .insert(attestation.attestation_id.clone(), attestation);

            if index < 3 {
                let queue_root = self
                    .queues
                    .get(&queue_id)
                    .map(|queue| queue.queue_root.clone())
                    .unwrap_or_default();
                let ack_root = self
                    .ack_lanes
                    .get(&ack_id)
                    .map(|ack| ack.ack_root.clone())
                    .unwrap_or_default();
                let attestation_root = self
                    .pq_attestations
                    .values()
                    .find(|attestation| attestation.ack_id == ack_id)
                    .map(|attestation| attestation.attestation_root.clone())
                    .unwrap_or_default();
                let deterministic_root = deterministic_preconfirmation_root(
                    shard_id,
                    self.current_slot + index as u64,
                    &queue_root,
                    &ack_root,
                    &attestation_root,
                );
                let mut preconfirmation = PreconfirmationRoot {
                    preconfirmation_id: format!("preconfirm-devnet-{:02}", index + 1),
                    shard_id,
                    slot: self.current_slot + index as u64,
                    queue_root,
                    ack_root,
                    attestation_root,
                    deterministic_root,
                    preconfirmation_root: String::new(),
                };
                preconfirmation.preconfirmation_root =
                    record_root("PRECONFIRMATION", &preconfirmation.public_record());
                self.counters.preconfirmation_roots_sealed =
                    self.counters.preconfirmation_roots_sealed.saturating_add(1);
                self.preconfirmation_roots
                    .insert(preconfirmation.preconfirmation_id.clone(), preconfirmation);
            }

            if matches!(lane, ReceiptLane::WalletSync | ReceiptLane::Payment) {
                let rebate_micros = self
                    .config
                    .acceleration_fee_micros
                    .saturating_mul(self.config.low_fee_rebate_bps)
                    / MAX_BPS;
                let mut rebate = LowFeeAccelerationRebate {
                    rebate_id: format!("rebate-devnet-{:02}", index + 1),
                    ack_id,
                    wallet_cursor_id: cursor_id,
                    status: RebateStatus::Reserved,
                    fee_asset_id: self.config.fee_asset_id.clone(),
                    accelerated_fee_micros: self.config.acceleration_fee_micros,
                    rebate_bps: self.config.low_fee_rebate_bps,
                    rebate_micros,
                    settlement_root: dev_hash("rebate-settlement", index as u64),
                    rebate_root: String::new(),
                };
                rebate.rebate_root = record_root("REBATE", &rebate.public_record());
                self.counters.low_fee_rebates_reserved =
                    self.counters.low_fee_rebates_reserved.saturating_add(1);
                self.low_fee_rebates
                    .insert(rebate.rebate_id.clone(), rebate);
            }
        }

        for shard_id in seen_shards {
            let queue_depth = self
                .queues
                .values()
                .filter(|queue| queue.shard_id == shard_id)
                .map(|queue| queue.receipt_count)
                .sum::<u32>();
            let pressure_score = pressure_score(
                queue_depth,
                self.config.queue_soft_limit,
                self.config.queue_hard_limit,
                self.config.max_backpressure_score,
            );
            let mode = if pressure_score > 8_500 {
                BackpressureMode::SheddingLowFee
            } else if pressure_score > 5_000 {
                BackpressureMode::PrioritizingFastAck
            } else {
                BackpressureMode::Accepting
            };
            let mut backpressure = ShardBackpressure {
                shard_id,
                mode,
                queue_depth,
                soft_limit: self.config.queue_soft_limit,
                hard_limit: self.config.queue_hard_limit,
                pressure_score,
                low_fee_shed_count: 0,
                backpressure_root: String::new(),
            };
            backpressure.backpressure_root =
                record_root("BACKPRESSURE", &backpressure.public_record());
            if mode != BackpressureMode::Accepting {
                self.counters.shard_backpressure_events =
                    self.counters.shard_backpressure_events.saturating_add(1);
            }
            self.shard_backpressure
                .insert(format!("shard-{:04}", shard_id), backpressure);
        }
    }

    fn emit_public_record(&mut self) {
        let total_queue_depth = self
            .queues
            .values()
            .map(|queue| queue.receipt_count as u64)
            .sum();
        let max_backpressure_mode = self
            .shard_backpressure
            .values()
            .max_by_key(|backpressure| backpressure.pressure_score)
            .map(|backpressure| backpressure.mode)
            .unwrap_or(BackpressureMode::Accepting);
        let low_fee_rebate_micros = self
            .low_fee_rebates
            .values()
            .map(|rebate| rebate.rebate_micros)
            .sum();
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-mempool-receipt-accelerator".to_string(),
            height: DEVNET_HEIGHT + self.counters.fast_acks_sent,
            epoch: DEVNET_EPOCH,
            shard_count: self.config.shard_count,
            queue_count: self.queues.len(),
            fast_ack_count: self.ack_lanes.len(),
            wallet_cursor_count: self.wallet_cursors.len(),
            preconfirmation_count: self.preconfirmation_roots.len(),
            total_queue_depth,
            max_backpressure_mode,
            low_fee_rebate_micros,
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
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MEMPOOL-RECEIPT-ACCELERATOR-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn deterministic_preconfirmation_root(
    shard_id: u16,
    slot: u64,
    queue_root: &str,
    ack_root: &str,
    attestation_root: &str,
) -> String {
    domain_hash(
        PRECONFIRMATION_ROOT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(shard_id as u64),
            HashPart::U64(slot),
            HashPart::Str(queue_root),
            HashPart::Str(ack_root),
            HashPart::Str(attestation_root),
        ],
        32,
    )
}

fn pressure_score(queue_depth: u32, soft_limit: u32, hard_limit: u32, max_score: u16) -> u16 {
    if queue_depth <= soft_limit {
        return (queue_depth as u64 * (max_score as u64 / 2) / soft_limit.max(1) as u64) as u16;
    }
    let over_soft = queue_depth.saturating_sub(soft_limit) as u64;
    let range = hard_limit.saturating_sub(soft_limit).max(1) as u64;
    ((max_score as u64 / 2) + (over_soft * (max_score as u64 / 2) / range)).min(max_score as u64)
        as u16
}

fn merkle_records<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn public_record_map(records: &BTreeMap<String, OperatorPublicRecord>) -> BTreeMap<String, Value> {
    records
        .iter()
        .map(|(key, record)| (key.clone(), record.public_record()))
        .collect()
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
