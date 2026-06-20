use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialMultilanePreconfirmationRelayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MULTILANE_PRECONFIRMATION_RELAY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-multilane-preconfirmation-relay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MULTILANE_PRECONFIRMATION_RELAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_864_000;
pub const DEVNET_EPOCH: u64 = 12_800;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELAY_PACKET_SUITE: &str = "ml-kem-1024+xwing-confidential-relay-packet-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256s-preconfirmation-relay-attestation-v1";
pub const RECEIPT_ROOT_SUITE: &str = "roots-only-confidential-multilane-receipt-root-v1";
pub const THROTTLE_SUITE: &str = "queue-pressure-fast-lane-throttle-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "roots-only-low-fee-relay-rebate-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "redacted-fast-relay-operator-summary-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ATTESTATION_WEIGHT: u64 = 67;
pub const DEFAULT_PRECONFIRMATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_PRECONFIRMATION_BPS: u64 = 8_000;
pub const DEFAULT_MAX_RELAY_FEE_BPS: u64 = 18;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 6;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 12;
pub const DEFAULT_BASE_REBATE_MICRO_UNITS: u64 = 850;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 850;
pub const DEFAULT_MAX_QUEUE_DEPTH: u64 = 65_536;
pub const DEFAULT_PRESSURE_THROTTLE_BPS: u64 = 7_500;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_PACKET_TTL_SLOTS: u64 = 8;
pub const DEFAULT_OPERATOR_SUMMARY_WINDOW_SLOTS: u64 = 64;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_LANES: usize = 64;
pub const MAX_OPERATORS: usize = 4_096;
pub const MAX_PACKETS: usize = 4_194_304;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_THROTTLES: usize = 524_288;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_SUMMARIES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayLaneKind {
    InstantPayment,
    DexIntent,
    BridgeIngress,
    BridgeEgress,
    LiquidityRebalance,
    Watchtower,
    SettlementCallback,
    EmergencyExit,
}

impl RelayLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InstantPayment => "instant_payment",
            Self::DexIntent => "dex_intent",
            Self::BridgeIngress => "bridge_ingress",
            Self::BridgeEgress => "bridge_egress",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::Watchtower => "watchtower",
            Self::SettlementCallback => "settlement_callback",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::SettlementCallback => 9_700,
            Self::InstantPayment => 9_400,
            Self::BridgeEgress => 9_100,
            Self::BridgeIngress => 8_900,
            Self::DexIntent => 8_700,
            Self::LiquidityRebalance => 8_400,
            Self::Watchtower => 8_100,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Hot,
    RebateOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_packets(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::RebateOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketKind {
    Payment,
    Swap,
    BridgeLock,
    BridgeRelease,
    LiquidityMove,
    WatchtowerProof,
    Callback,
    Escape,
}

impl PacketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::Swap => "swap",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::LiquidityMove => "liquidity_move",
            Self::WatchtowerProof => "watchtower_proof",
            Self::Callback => "callback",
            Self::Escape => "escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketStatus {
    Sealed,
    Queued,
    Throttled,
    Relayed,
    Preconfirmed,
    Rooted,
    Rebated,
    Expired,
    Rejected,
}

impl PacketStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Queued | Self::Throttled | Self::Relayed | Self::Preconfirmed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    Active,
    Preferred,
    Probation,
    Throttled,
    Paused,
    Slashed,
    Retired,
}

impl OperatorStatus {
    pub fn accepts_relay(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Preferred | Self::Probation | Self::Throttled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Strong,
    Rejected,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleReason {
    QueuePressure,
    LatencySpike,
    FeeCapExceeded,
    OperatorSaturation,
    PrivacySetThin,
    EmergencyReserve,
}

impl ThrottleReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueuePressure => "queue_pressure",
            Self::LatencySpike => "latency_spike",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::OperatorSaturation => "operator_saturation",
            Self::PrivacySetThin => "privacy_set_thin",
            Self::EmergencyReserve => "emergency_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Reserved,
    Claimed,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub relay_packet_suite: String,
    pub pq_attestation_suite: String,
    pub receipt_root_suite: String,
    pub throttle_suite: String,
    pub low_fee_rebate_suite: String,
    pub operator_summary_suite: String,
    pub min_pq_security_bits: u16,
    pub min_attestation_weight: u64,
    pub preconfirmation_quorum_bps: u64,
    pub strong_preconfirmation_bps: u64,
    pub max_relay_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub max_rebate_bps: u64,
    pub base_rebate_micro_units: u64,
    pub target_latency_ms: u64,
    pub max_queue_depth: u64,
    pub pressure_throttle_bps: u64,
    pub receipt_ttl_blocks: u64,
    pub packet_ttl_slots: u64,
    pub operator_summary_window_slots: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MULTILANE_PRECONFIRMATION_RELAY_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-devnet".to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            relay_packet_suite: RELAY_PACKET_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            receipt_root_suite: RECEIPT_ROOT_SUITE.to_string(),
            throttle_suite: THROTTLE_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_attestation_weight: DEFAULT_MIN_ATTESTATION_WEIGHT,
            preconfirmation_quorum_bps: DEFAULT_PRECONFIRMATION_QUORUM_BPS,
            strong_preconfirmation_bps: DEFAULT_STRONG_PRECONFIRMATION_BPS,
            max_relay_fee_bps: DEFAULT_MAX_RELAY_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            base_rebate_micro_units: DEFAULT_BASE_REBATE_MICRO_UNITS,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            pressure_throttle_bps: DEFAULT_PRESSURE_THROTTLE_BPS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            packet_ttl_slots: DEFAULT_PACKET_TTL_SLOTS,
            operator_summary_window_slots: DEFAULT_OPERATOR_SUMMARY_WINDOW_SLOTS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "relay_packet_suite": self.relay_packet_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "receipt_root_suite": self.receipt_root_suite,
            "throttle_suite": self.throttle_suite,
            "low_fee_rebate_suite": self.low_fee_rebate_suite,
            "operator_summary_suite": self.operator_summary_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_attestation_weight": self.min_attestation_weight,
            "preconfirmation_quorum_bps": self.preconfirmation_quorum_bps,
            "strong_preconfirmation_bps": self.strong_preconfirmation_bps,
            "max_relay_fee_bps": self.max_relay_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "base_rebate_micro_units": self.base_rebate_micro_units,
            "target_latency_ms": self.target_latency_ms,
            "max_queue_depth": self.max_queue_depth,
            "pressure_throttle_bps": self.pressure_throttle_bps,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "packet_ttl_slots": self.packet_ttl_slots,
            "operator_summary_window_slots": self.operator_summary_window_slots,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes: u64,
    pub operators: u64,
    pub packets: u64,
    pub queued_packets: u64,
    pub relayed_packets: u64,
    pub preconfirmed_packets: u64,
    pub rooted_packets: u64,
    pub throttled_packets: u64,
    pub expired_packets: u64,
    pub rejected_packets: u64,
    pub attestations: u64,
    pub accepted_attestations: u64,
    pub strong_attestations: u64,
    pub throttles: u64,
    pub rebates: u64,
    pub claimed_rebates: u64,
    pub rebate_micro_units: u64,
    pub summaries: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub lane_root: String,
    pub operator_root: String,
    pub packet_root: String,
    pub receipt_root: String,
    pub attestation_root: String,
    pub throttle_root: String,
    pub rebate_root: String,
    pub operator_summary_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            counter_root: empty_root("COUNTERS"),
            lane_root: empty_root("LANES"),
            operator_root: empty_root("OPERATORS"),
            packet_root: empty_root("PACKETS"),
            receipt_root: empty_root("RECEIPTS"),
            attestation_root: empty_root("ATTESTATIONS"),
            throttle_root: empty_root("THROTTLES"),
            rebate_root: empty_root("REBATES"),
            operator_summary_root: empty_root("OPERATOR-SUMMARIES"),
            event_root: empty_root("EVENTS"),
            state_root: empty_root("STATE"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "lane_root": self.lane_root,
            "operator_root": self.operator_root,
            "packet_root": self.packet_root,
            "receipt_root": self.receipt_root,
            "attestation_root": self.attestation_root,
            "throttle_root": self.throttle_root,
            "rebate_root": self.rebate_root,
            "operator_summary_root": self.operator_summary_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayLane {
    pub lane_id: String,
    pub kind: RelayLaneKind,
    pub status: LaneStatus,
    pub priority: u64,
    pub fee_cap_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub queue_depth: u64,
    pub max_queue_depth: u64,
    pub pressure_bps: u64,
    pub median_latency_ms: u64,
    pub target_latency_ms: u64,
    pub active_operator_ids: BTreeSet<String>,
    pub packet_root: String,
    pub receipt_root: String,
    pub throttle_root: String,
    pub opened_height: u64,
    pub last_slot: u64,
}

impl RelayLane {
    pub fn new(kind: RelayLaneKind, opened_height: u64, ordinal: u64, config: &Config) -> Self {
        let lane_id = relay_lane_id(kind, opened_height, ordinal);
        Self {
            lane_id,
            kind,
            status: LaneStatus::Open,
            priority: kind.default_priority(),
            fee_cap_bps: lane_fee_cap_bps(kind, config),
            low_fee_rebate_bps: config.max_rebate_bps.min(config.low_fee_target_bps + 2),
            queue_depth: 0,
            max_queue_depth: config.max_queue_depth,
            pressure_bps: 0,
            median_latency_ms: config.target_latency_ms,
            target_latency_ms: config.target_latency_ms,
            active_operator_ids: BTreeSet::new(),
            packet_root: empty_root("LANE-PACKETS"),
            receipt_root: empty_root("LANE-RECEIPTS"),
            throttle_root: empty_root("LANE-THROTTLES"),
            opened_height,
            last_slot: 0,
        }
    }

    pub fn accepts_packet(&self) -> bool {
        self.status.accepts_packets() && self.queue_depth < self.max_queue_depth
    }

    pub fn update_pressure(&mut self) {
        self.pressure_bps = if self.max_queue_depth == 0 {
            MAX_BPS
        } else {
            self.queue_depth.saturating_mul(MAX_BPS) / self.max_queue_depth
        }
        .min(MAX_BPS);
        if self.pressure_bps >= 8_500 && self.status == LaneStatus::Open {
            self.status = LaneStatus::Hot;
        } else if self.pressure_bps < 5_500 && self.status == LaneStatus::Hot {
            self.status = LaneStatus::Open;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind,
            "status": self.status,
            "priority": self.priority,
            "fee_cap_bps": self.fee_cap_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "queue_depth": self.queue_depth,
            "max_queue_depth": self.max_queue_depth,
            "pressure_bps": self.pressure_bps,
            "median_latency_ms": self.median_latency_ms,
            "target_latency_ms": self.target_latency_ms,
            "active_operator_count": self.active_operator_ids.len(),
            "packet_root": self.packet_root,
            "receipt_root": self.receipt_root,
            "throttle_root": self.throttle_root,
            "opened_height": self.opened_height,
            "last_slot": self.last_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayOperator {
    pub operator_id: String,
    pub operator_commitment: String,
    pub status: OperatorStatus,
    pub lane_ids: BTreeSet<String>,
    pub pq_public_key_commitment: String,
    pub stake_commitment: String,
    pub relay_weight: u64,
    pub max_inflight_packets: u64,
    pub inflight_packets: u64,
    pub rolling_success_bps: u64,
    pub median_latency_ms: u64,
    pub fee_discount_bps: u64,
    pub accepted_attestation_weight: u64,
    pub redaction_salt_commitment: String,
    pub joined_height: u64,
}

impl RelayOperator {
    pub fn new(
        label: &str,
        lane_ids: BTreeSet<String>,
        relay_weight: u64,
        joined_height: u64,
        ordinal: u64,
    ) -> Self {
        let operator_commitment = commitment("operator", label, ordinal);
        let operator_id = relay_operator_id(&operator_commitment, joined_height, ordinal);
        Self {
            pq_public_key_commitment: commitment("pq-key", &operator_id, ordinal),
            stake_commitment: commitment("stake", &operator_id, relay_weight),
            redaction_salt_commitment: commitment("redaction", &operator_id, ordinal),
            operator_id,
            operator_commitment,
            status: OperatorStatus::Active,
            lane_ids,
            relay_weight,
            max_inflight_packets: 16_384,
            inflight_packets: 0,
            rolling_success_bps: 9_900,
            median_latency_ms: 620,
            fee_discount_bps: 2,
            accepted_attestation_weight: 0,
            joined_height,
        }
    }

    pub fn available_capacity(&self) -> u64 {
        self.max_inflight_packets
            .saturating_sub(self.inflight_packets)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status,
            "lane_count": self.lane_ids.len(),
            "lane_root": records_root("OPERATOR-LANES", self.lane_ids.iter().map(|id| json!(id)).collect()),
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "stake_commitment": self.stake_commitment,
            "relay_weight": self.relay_weight,
            "available_capacity": self.available_capacity(),
            "rolling_success_bps": self.rolling_success_bps,
            "median_latency_ms": self.median_latency_ms,
            "fee_discount_bps": self.fee_discount_bps,
            "accepted_attestation_weight": self.accepted_attestation_weight,
            "redaction_salt_commitment": self.redaction_salt_commitment,
            "joined_height": self.joined_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptPacket {
    pub packet_id: String,
    pub lane_id: String,
    pub kind: PacketKind,
    pub status: PacketStatus,
    pub sender_commitment: String,
    pub recipient_commitment: String,
    pub encrypted_payload_root: String,
    pub nullifier_commitment: String,
    pub fee_asset_id: String,
    pub max_relay_fee_bps: u64,
    pub offered_relay_fee_micro_units: u64,
    pub priority_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub receipt_root: String,
    pub assigned_operator_id: Option<String>,
    pub attestation_ids: BTreeSet<String>,
    pub accepted_weight: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub submitted_slot: u64,
    pub preconfirmed_slot: Option<u64>,
}

impl ReceiptPacket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        kind: PacketKind,
        sender_commitment: &str,
        recipient_commitment: &str,
        encrypted_payload_root: &str,
        offered_relay_fee_micro_units: u64,
        max_relay_fee_bps: u64,
        privacy_set_size: u64,
        height: u64,
        slot: u64,
        ordinal: u64,
        config: &Config,
    ) -> Self {
        let nullifier_commitment =
            packet_nullifier(lane_id, sender_commitment, encrypted_payload_root);
        let packet_id = receipt_packet_id(lane_id, &nullifier_commitment, height, ordinal);
        let pq_ciphertext_root = commitment("pq-ciphertext", &packet_id, ordinal);
        let receipt_root = receipt_root_for_packet(
            &packet_id,
            lane_id,
            encrypted_payload_root,
            &pq_ciphertext_root,
        );
        Self {
            packet_id,
            lane_id: lane_id.to_string(),
            kind,
            status: PacketStatus::Sealed,
            sender_commitment: sender_commitment.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            nullifier_commitment,
            fee_asset_id: config.fee_asset_id.clone(),
            max_relay_fee_bps,
            offered_relay_fee_micro_units,
            priority_fee_micro_units: offered_relay_fee_micro_units / 4,
            privacy_set_size,
            pq_ciphertext_root,
            receipt_root,
            assigned_operator_id: None,
            attestation_ids: BTreeSet::new(),
            accepted_weight: 0,
            submitted_height: height,
            expires_height: height + config.receipt_ttl_blocks,
            submitted_slot: slot,
            preconfirmed_slot: None,
        }
    }

    pub fn expired(&self, height: u64) -> bool {
        height > self.expires_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "packet_id": self.packet_id,
            "lane_id": self.lane_id,
            "kind": self.kind,
            "status": self.status,
            "sender_commitment": self.sender_commitment,
            "recipient_commitment": self.recipient_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier_commitment": self.nullifier_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_relay_fee_bps": self.max_relay_fee_bps,
            "offered_relay_fee_micro_units": self.offered_relay_fee_micro_units,
            "priority_fee_micro_units": self.priority_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "receipt_root": self.receipt_root,
            "assigned_operator_id": self.assigned_operator_id,
            "attestation_root": records_root("PACKET-ATTESTATIONS", self.attestation_ids.iter().map(|id| json!(id)).collect()),
            "accepted_weight": self.accepted_weight,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "submitted_slot": self.submitted_slot,
            "preconfirmed_slot": self.preconfirmed_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub packet_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub status: AttestationStatus,
    pub attested_receipt_root: String,
    pub pq_signature_commitment: String,
    pub signature_scheme: String,
    pub pq_security_bits: u16,
    pub relay_weight: u64,
    pub latency_ms: u64,
    pub observed_slot: u64,
    pub accepted_slot: Option<u64>,
}

impl PqAttestation {
    pub fn new(
        packet: &ReceiptPacket,
        operator: &RelayOperator,
        latency_ms: u64,
        observed_slot: u64,
        ordinal: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = pq_attestation_id(&packet.packet_id, &operator.operator_id, ordinal);
        Self {
            pq_signature_commitment: commitment(
                "pq-attestation-signature",
                &attestation_id,
                ordinal,
            ),
            attestation_id,
            packet_id: packet.packet_id.clone(),
            lane_id: packet.lane_id.clone(),
            operator_id: operator.operator_id.clone(),
            status: AttestationStatus::Pending,
            attested_receipt_root: packet.receipt_root.clone(),
            signature_scheme: config.pq_attestation_suite.clone(),
            pq_security_bits: config.min_pq_security_bits,
            relay_weight: operator.relay_weight,
            latency_ms,
            observed_slot,
            accepted_slot: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "packet_id": self.packet_id,
            "lane_id": self.lane_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "attested_receipt_root": self.attested_receipt_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "signature_scheme": self.signature_scheme,
            "pq_security_bits": self.pq_security_bits,
            "relay_weight": self.relay_weight,
            "latency_ms": self.latency_ms,
            "observed_slot": self.observed_slot,
            "accepted_slot": self.accepted_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueThrottle {
    pub throttle_id: String,
    pub lane_id: String,
    pub reason: ThrottleReason,
    pub pressure_bps: u64,
    pub queue_depth: u64,
    pub dropped_packet_root: String,
    pub deferred_packet_root: String,
    pub rebate_boost_bps: u64,
    pub opened_slot: u64,
    pub expires_slot: u64,
}

impl QueueThrottle {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub packet_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub relay_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub receipt_root: String,
    pub accrued_height: u64,
    pub claimed_height: Option<u64>,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "packet_id": self.packet_id,
            "lane_id": self.lane_id,
            "operator_id": self.operator_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "status": self.status,
            "fee_asset_id": self.fee_asset_id,
            "relay_fee_micro_units": self.relay_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_bps": self.rebate_bps,
            "receipt_root": self.receipt_root,
            "accrued_height": self.accrued_height,
            "claimed_height": self.claimed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub summary_window: u64,
    pub redacted_operator_commitment: String,
    pub lane_root: String,
    pub packet_count: u64,
    pub preconfirmed_count: u64,
    pub median_latency_bucket: String,
    pub fee_discount_bps: u64,
    pub rebate_micro_units: u64,
    pub receipt_root: String,
    pub attestation_root: String,
    pub generated_slot: u64,
}

impl OperatorSummary {
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
    pub slot: u64,
    pub lanes: BTreeMap<String, RelayLane>,
    pub operators: BTreeMap<String, RelayOperator>,
    pub packets: BTreeMap<String, ReceiptPacket>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub throttles: BTreeMap<String, QueueThrottle>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub seen_nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            slot: 0,
            lanes: BTreeMap::new(),
            operators: BTreeMap::new(),
            packets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            throttles: BTreeMap::new(),
            rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let kinds = [
            RelayLaneKind::InstantPayment,
            RelayLaneKind::DexIntent,
            RelayLaneKind::BridgeIngress,
            RelayLaneKind::BridgeEgress,
            RelayLaneKind::LiquidityRebalance,
            RelayLaneKind::Watchtower,
            RelayLaneKind::SettlementCallback,
            RelayLaneKind::EmergencyExit,
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            let lane = RelayLane::new(kind, state.height, index as u64, &state.config);
            state.lanes.insert(lane.lane_id.clone(), lane);
        }
        let all_lane_ids = state.lanes.keys().cloned().collect::<BTreeSet<_>>();
        for index in 0..4 {
            let mut operator = RelayOperator::new(
                &format!("devnet-fast-relay-{index}"),
                all_lane_ids.clone(),
                25 + index as u64 * 5,
                state.height,
                index as u64,
            );
            if index == 0 {
                operator.status = OperatorStatus::Preferred;
                operator.median_latency_ms = 410;
            }
            for lane_id in &operator.lane_ids {
                if let Some(lane) = state.lanes.get_mut(lane_id) {
                    lane.active_operator_ids
                        .insert(operator.operator_id.clone());
                }
            }
            state
                .operators
                .insert(operator.operator_id.clone(), operator);
        }
        state.counters.lanes = state.lanes.len() as u64;
        state.counters.operators = state.operators.len() as u64;
        state.record_event("devnet_initialized", "runtime", state.height);
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let lane_ids = state.lanes.keys().cloned().collect::<Vec<_>>();
        let operator_ids = state.operators.keys().cloned().collect::<Vec<_>>();
        for index in 0..12 {
            let lane_id = &lane_ids[index % lane_ids.len()];
            let kind = match index % 8 {
                0 => PacketKind::Payment,
                1 => PacketKind::Swap,
                2 => PacketKind::BridgeLock,
                3 => PacketKind::BridgeRelease,
                4 => PacketKind::LiquidityMove,
                5 => PacketKind::WatchtowerProof,
                6 => PacketKind::Callback,
                _ => PacketKind::Escape,
            };
            let packet = ReceiptPacket::new(
                lane_id,
                kind,
                &commitment("sender", "demo", index as u64),
                &commitment("recipient", "demo", index as u64),
                &commitment("encrypted-payload", "demo", index as u64),
                2_000 + index as u64 * 75,
                state.config.low_fee_target_bps + index as u64 % 5,
                65_536 + index as u64 * 4_096,
                state.height,
                state.slot + index as u64,
                index as u64,
                &state.config,
            );
            let packet_id = packet.packet_id.clone();
            let _ = state.enqueue_packet(packet);
            let operator_id = &operator_ids[index % operator_ids.len()];
            let _ = state.assign_operator(&packet_id, operator_id);
            let _ = state.add_pq_attestation(&packet_id, operator_id, 420 + index as u64 * 25);
            if index % 3 == 0 {
                let second = &operator_ids[(index + 1) % operator_ids.len()];
                let _ = state.add_pq_attestation(&packet_id, second, 540 + index as u64 * 20);
            }
            if index % 2 == 0 {
                let _ = state.accrue_low_fee_rebate(&packet_id);
            }
        }
        let hot_lane_id = lane_ids[0].clone();
        if let Some(lane) = state.lanes.get_mut(&hot_lane_id) {
            lane.queue_depth = lane.max_queue_depth * 9 / 10;
            lane.update_pressure();
        }
        let _ = state.apply_queue_throttle(&hot_lane_id, ThrottleReason::QueuePressure);
        for operator_id in operator_ids {
            let _ = state.generate_operator_summary(&operator_id);
        }
        state.refresh_roots();
        state
    }

    pub fn enqueue_packet(&mut self, mut packet: ReceiptPacket) -> Result<String> {
        if self.packets.len() >= MAX_PACKETS {
            return Err("packet capacity exceeded".to_string());
        }
        let lane = self
            .lanes
            .get_mut(&packet.lane_id)
            .ok_or_else(|| "unknown relay lane".to_string())?;
        if !lane.accepts_packet() {
            packet.status = PacketStatus::Throttled;
            self.counters.throttled_packets += 1;
        } else if packet.max_relay_fee_bps > lane.fee_cap_bps {
            packet.status = PacketStatus::Rejected;
            self.counters.rejected_packets += 1;
        } else if self.seen_nullifiers.contains(&packet.nullifier_commitment) {
            packet.status = PacketStatus::Rejected;
            self.counters.rejected_packets += 1;
        } else {
            packet.status = PacketStatus::Queued;
            lane.queue_depth += 1;
            lane.last_slot = packet.submitted_slot;
            lane.update_pressure();
            self.seen_nullifiers
                .insert(packet.nullifier_commitment.clone());
            self.counters.queued_packets += 1;
        }
        let packet_id = packet.packet_id.clone();
        self.counters.packets += 1;
        self.packets.insert(packet_id.clone(), packet);
        self.record_event("packet_enqueued", &packet_id, self.height);
        self.refresh_roots();
        Ok(packet_id)
    }

    pub fn assign_operator(&mut self, packet_id: &str, operator_id: &str) -> Result<()> {
        let packet = self
            .packets
            .get_mut(packet_id)
            .ok_or_else(|| "unknown receipt packet".to_string())?;
        let operator = self
            .operators
            .get_mut(operator_id)
            .ok_or_else(|| "unknown relay operator".to_string())?;
        if !operator.status.accepts_relay() {
            return Err("operator does not accept relay".to_string());
        }
        if !operator.lane_ids.contains(&packet.lane_id) {
            return Err("operator is not assigned to lane".to_string());
        }
        if operator.available_capacity() == 0 {
            return Err("operator capacity exhausted".to_string());
        }
        packet.assigned_operator_id = Some(operator_id.to_string());
        packet.status = PacketStatus::Relayed;
        operator.inflight_packets += 1;
        self.counters.relayed_packets += 1;
        self.record_event("operator_assigned", packet_id, self.height);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_pq_attestation(
        &mut self,
        packet_id: &str,
        operator_id: &str,
        latency_ms: u64,
    ) -> Result<String> {
        if self.attestations.len() >= MAX_ATTESTATIONS {
            return Err("attestation capacity exceeded".to_string());
        }
        let packet = self
            .packets
            .get(packet_id)
            .ok_or_else(|| "unknown receipt packet".to_string())?
            .clone();
        let operator = self
            .operators
            .get(operator_id)
            .ok_or_else(|| "unknown relay operator".to_string())?
            .clone();
        let mut attestation = PqAttestation::new(
            &packet,
            &operator,
            latency_ms,
            self.slot,
            self.counters.attestations,
            &self.config,
        );
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            attestation.status = AttestationStatus::Rejected;
        } else {
            attestation.status = AttestationStatus::Accepted;
            attestation.accepted_slot = Some(self.slot);
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.counters.attestations += 1;
        if attestation.status == AttestationStatus::Accepted {
            self.counters.accepted_attestations += 1;
            let total_weight = self.total_lane_weight(&packet.lane_id).max(1);
            if let Some(packet) = self.packets.get_mut(packet_id) {
                packet.attestation_ids.insert(attestation_id.clone());
                packet.accepted_weight =
                    packet.accepted_weight.saturating_add(operator.relay_weight);
                if packet.accepted_weight >= self.config.min_attestation_weight {
                    packet.status = PacketStatus::Preconfirmed;
                    packet.preconfirmed_slot = Some(self.slot);
                    self.counters.preconfirmed_packets += 1;
                }
                let attested_bps = packet.accepted_weight.saturating_mul(MAX_BPS) / total_weight;
                if attested_bps >= self.config.strong_preconfirmation_bps {
                    if let Some(stored) = self.attestations.get_mut(&attestation_id) {
                        stored.status = AttestationStatus::Strong;
                    }
                    self.counters.strong_attestations += 1;
                }
            }
            if let Some(operator) = self.operators.get_mut(operator_id) {
                operator.accepted_attestation_weight = operator
                    .accepted_attestation_weight
                    .saturating_add(attestation.relay_weight);
                operator.median_latency_ms =
                    rolling_median_hint(operator.median_latency_ms, latency_ms);
            }
        }
        self.record_event("pq_attestation_added", &attestation_id, self.height);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn apply_queue_throttle(
        &mut self,
        lane_id: &str,
        reason: ThrottleReason,
    ) -> Result<String> {
        if self.throttles.len() >= MAX_THROTTLES {
            return Err("throttle capacity exceeded".to_string());
        }
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown relay lane".to_string())?;
        lane.update_pressure();
        let deferred = self
            .packets
            .values()
            .filter(|packet| packet.lane_id == lane_id && packet.status.active())
            .map(ReceiptPacket::public_record)
            .collect::<Vec<_>>();
        let throttle_id = queue_throttle_id(lane_id, reason, self.slot, self.counters.throttles);
        let throttle = QueueThrottle {
            throttle_id: throttle_id.clone(),
            lane_id: lane_id.to_string(),
            reason,
            pressure_bps: lane.pressure_bps,
            queue_depth: lane.queue_depth,
            dropped_packet_root: empty_root("THROTTLE-DROPPED-PACKETS"),
            deferred_packet_root: records_root("THROTTLE-DEFERRED-PACKETS", deferred),
            rebate_boost_bps: (lane.pressure_bps / 1_000).min(self.config.max_rebate_bps),
            opened_slot: self.slot,
            expires_slot: self.slot + self.config.packet_ttl_slots,
        };
        lane.throttle_root = root_from_record("LANE-THROTTLE", &throttle.public_record());
        if lane.status == LaneStatus::Open || lane.status == LaneStatus::Hot {
            lane.status = LaneStatus::RebateOnly;
        }
        self.throttles.insert(throttle_id.clone(), throttle);
        self.counters.throttles += 1;
        self.record_event(reason.as_str(), lane_id, self.height);
        self.refresh_roots();
        Ok(throttle_id)
    }

    pub fn accrue_low_fee_rebate(&mut self, packet_id: &str) -> Result<String> {
        if self.rebates.len() >= MAX_REBATES {
            return Err("rebate capacity exceeded".to_string());
        }
        let packet = self
            .packets
            .get(packet_id)
            .ok_or_else(|| "unknown receipt packet".to_string())?
            .clone();
        let lane = self
            .lanes
            .get(&packet.lane_id)
            .ok_or_else(|| "unknown relay lane".to_string())?
            .clone();
        let operator_id = packet
            .assigned_operator_id
            .clone()
            .ok_or_else(|| "packet has no assigned operator".to_string())?;
        let rebate_bps = if packet.max_relay_fee_bps <= self.config.low_fee_target_bps {
            lane.low_fee_rebate_bps
        } else {
            lane.low_fee_rebate_bps / 2
        }
        .min(self.config.max_rebate_bps);
        let rebate_micro_units = self.config.base_rebate_micro_units.saturating_add(
            packet
                .offered_relay_fee_micro_units
                .saturating_mul(rebate_bps)
                / MAX_BPS,
        );
        let rebate_id = low_fee_rebate_id(packet_id, &operator_id, rebate_micro_units);
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            packet_id: packet_id.to_string(),
            lane_id: packet.lane_id.clone(),
            operator_id,
            beneficiary_commitment: packet.sender_commitment.clone(),
            status: RebateStatus::Accrued,
            fee_asset_id: packet.fee_asset_id.clone(),
            relay_fee_micro_units: packet.offered_relay_fee_micro_units,
            rebate_micro_units,
            rebate_bps,
            receipt_root: packet.receipt_root.clone(),
            accrued_height: self.height,
            claimed_height: None,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebates += 1;
        self.counters.rebate_micro_units = self
            .counters
            .rebate_micro_units
            .saturating_add(rebate_micro_units);
        if let Some(packet) = self.packets.get_mut(packet_id) {
            packet.status = PacketStatus::Rebated;
        }
        self.record_event("low_fee_rebate_accrued", &rebate_id, self.height);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn claim_rebate(&mut self, rebate_id: &str, height: u64) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| "unknown rebate".to_string())?;
        if rebate.status != RebateStatus::Accrued && rebate.status != RebateStatus::Reserved {
            return Err("rebate is not claimable".to_string());
        }
        rebate.status = RebateStatus::Claimed;
        rebate.claimed_height = Some(height);
        self.counters.claimed_rebates += 1;
        self.record_event("low_fee_rebate_claimed", rebate_id, height);
        self.refresh_roots();
        Ok(())
    }

    pub fn generate_operator_summary(&mut self, operator_id: &str) -> Result<String> {
        if self.operator_summaries.len() >= MAX_SUMMARIES {
            return Err("operator summary capacity exceeded".to_string());
        }
        let operator = self
            .operators
            .get(operator_id)
            .ok_or_else(|| "unknown relay operator".to_string())?
            .clone();
        let packet_records = self
            .packets
            .values()
            .filter(|packet| packet.assigned_operator_id.as_deref() == Some(operator_id))
            .map(ReceiptPacket::public_record)
            .collect::<Vec<_>>();
        let preconfirmed_count = self
            .packets
            .values()
            .filter(|packet| {
                packet.assigned_operator_id.as_deref() == Some(operator_id)
                    && matches!(
                        packet.status,
                        PacketStatus::Preconfirmed | PacketStatus::Rooted | PacketStatus::Rebated
                    )
            })
            .count() as u64;
        let attestation_records = self
            .attestations
            .values()
            .filter(|attestation| attestation.operator_id == operator_id)
            .map(PqAttestation::public_record)
            .collect::<Vec<_>>();
        let rebate_micro_units = self
            .rebates
            .values()
            .filter(|rebate| rebate.operator_id == operator_id)
            .map(|rebate| rebate.rebate_micro_units)
            .sum::<u64>();
        let summary_window = self.slot / self.config.operator_summary_window_slots.max(1);
        let summary_id = operator_summary_id(operator_id, summary_window, self.counters.summaries);
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_id: operator_id.to_string(),
            summary_window,
            redacted_operator_commitment: redacted_operator_commitment(
                &operator.operator_commitment,
                summary_window,
            ),
            lane_root: records_root(
                "SUMMARY-LANES",
                operator
                    .lane_ids
                    .iter()
                    .map(|lane_id| json!(lane_id))
                    .collect(),
            ),
            packet_count: packet_records.len() as u64,
            preconfirmed_count,
            median_latency_bucket: latency_bucket(operator.median_latency_ms).to_string(),
            fee_discount_bps: operator.fee_discount_bps,
            rebate_micro_units,
            receipt_root: records_root("SUMMARY-PACKETS", packet_records),
            attestation_root: records_root("SUMMARY-ATTESTATIONS", attestation_records),
            generated_slot: self.slot,
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.counters.summaries += 1;
        self.record_event("operator_summary_generated", operator_id, self.height);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn expire_stale_packets(&mut self, height: u64) -> u64 {
        let mut expired = 0;
        for packet in self.packets.values_mut() {
            if packet.status.active() && packet.expired(height) {
                packet.status = PacketStatus::Expired;
                expired += 1;
            }
        }
        self.counters.expired_packets = self.counters.expired_packets.saturating_add(expired);
        if expired > 0 {
            self.record_event("packets_expired", "ttl", height);
            self.refresh_roots();
        }
        expired
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "epoch": self.epoch,
            "slot": self.slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "height": self.height,
            "epoch": self.epoch,
            "slot": self.slot,
            "config_root": self.roots.config_root,
            "counter_root": self.roots.counter_root,
            "lane_root": self.roots.lane_root,
            "operator_root": self.roots.operator_root,
            "packet_root": self.roots.packet_root,
            "receipt_root": self.roots.receipt_root,
            "attestation_root": self.roots.attestation_root,
            "throttle_root": self.roots.throttle_root,
            "rebate_root": self.roots.rebate_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "event_root": self.roots.event_root,
        }))
    }

    pub fn refresh_roots(&mut self) {
        for lane in self.lanes.values_mut() {
            lane.packet_root = records_root(
                "LANE-PACKETS",
                self.packets
                    .values()
                    .filter(|packet| packet.lane_id == lane.lane_id)
                    .map(ReceiptPacket::public_record)
                    .collect(),
            );
            lane.receipt_root = records_root(
                "LANE-RECEIPTS",
                self.packets
                    .values()
                    .filter(|packet| packet.lane_id == lane.lane_id)
                    .map(|packet| json!(packet.receipt_root))
                    .collect(),
            );
        }
        self.counters.lanes = self.lanes.len() as u64;
        self.counters.operators = self.operators.len() as u64;
        self.roots.config_root = root_from_record("CONFIG", &self.config.public_record());
        self.roots.counter_root = root_from_record("COUNTERS", &self.counters.public_record());
        self.roots.lane_root = map_root("LANES", &self.lanes);
        self.roots.operator_root = map_root("OPERATORS", &self.operators);
        self.roots.packet_root = map_root("PACKETS", &self.packets);
        self.roots.receipt_root = records_root(
            "RECEIPTS",
            self.packets
                .values()
                .map(|packet| json!(packet.receipt_root))
                .collect(),
        );
        self.roots.attestation_root = map_root("ATTESTATIONS", &self.attestations);
        self.roots.throttle_root = map_root("THROTTLES", &self.throttles);
        self.roots.rebate_root = map_root("REBATES", &self.rebates);
        self.roots.operator_summary_root = map_root("OPERATOR-SUMMARIES", &self.operator_summaries);
        self.roots.event_root = records_root("EVENTS", self.events.clone());
        self.roots.state_root = self.state_root();
    }

    fn total_lane_weight(&self, lane_id: &str) -> u64 {
        self.operators
            .values()
            .filter(|operator| operator.lane_ids.contains(lane_id))
            .map(|operator| operator.relay_weight)
            .sum()
    }

    fn record_event(&mut self, kind: &str, subject_id: &str, height: u64) {
        let event = json!({
            "event_id": event_id(kind, subject_id, self.counters.events, height),
            "kind": kind,
            "subject_id": subject_id,
            "height": height,
            "slot": self.slot,
        });
        self.counters.events += 1;
        self.events.push(event);
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

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for RelayLane {
    fn public_record(&self) -> Value {
        RelayLane::public_record(self)
    }
}

impl PublicRecord for RelayOperator {
    fn public_record(&self) -> Value {
        RelayOperator::public_record(self)
    }
}

impl PublicRecord for ReceiptPacket {
    fn public_record(&self) -> Value {
        ReceiptPacket::public_record(self)
    }
}

impl PublicRecord for PqAttestation {
    fn public_record(&self) -> Value {
        PqAttestation::public_record(self)
    }
}

impl PublicRecord for QueueThrottle {
    fn public_record(&self) -> Value {
        QueueThrottle::public_record(self)
    }
}

impl PublicRecord for LowFeeRebate {
    fn public_record(&self) -> Value {
        LowFeeRebate::public_record(self)
    }
}

impl PublicRecord for OperatorSummary {
    fn public_record(&self) -> Value {
        OperatorSummary::public_record(self)
    }
}

pub fn relay_lane_id(kind: RelayLaneKind, height: u64, ordinal: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::U64(height),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn relay_operator_id(operator_commitment: &str, height: u64, ordinal: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:OPERATOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::U64(height),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn receipt_packet_id(
    lane_id: &str,
    nullifier_commitment: &str,
    height: u64,
    ordinal: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(nullifier_commitment),
            HashPart::U64(height),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn packet_nullifier(
    lane_id: &str,
    sender_commitment: &str,
    encrypted_payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:PACKET-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(sender_commitment),
            HashPart::Str(encrypted_payload_root),
        ],
        32,
    )
}

pub fn receipt_root_for_packet(
    packet_id: &str,
    lane_id: &str,
    encrypted_payload_root: &str,
    pq_ciphertext_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(lane_id),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(pq_ciphertext_root),
        ],
        32,
    )
}

pub fn pq_attestation_id(packet_id: &str, operator_id: &str, ordinal: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(operator_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn queue_throttle_id(lane_id: &str, reason: ThrottleReason, slot: u64, ordinal: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:THROTTLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(reason.as_str()),
            HashPart::U64(slot),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn low_fee_rebate_id(packet_id: &str, operator_id: &str, rebate_micro_units: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(packet_id),
            HashPart::Str(operator_id),
            HashPart::U64(rebate_micro_units),
        ],
        32,
    )
}

pub fn operator_summary_id(operator_id: &str, summary_window: u64, ordinal: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::U64(summary_window),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn redacted_operator_commitment(operator_commitment: &str, summary_window: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:REDACTED-OPERATOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::U64(summary_window),
        ],
        16,
    )
}

pub fn event_id(kind: &str, subject_id: &str, ordinal: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::U64(ordinal),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn commitment(domain: &str, label: &str, nonce: u64) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:COMMITMENT:{domain}"
        ),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE-ROOT", record)
}

fn empty_root(domain: &str) -> String {
    records_root(domain, Vec::new())
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-PRECONFIRMATION-RELAY:{domain}"),
        &records,
    )
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    records_root(
        domain,
        values
            .iter()
            .map(|(id, value)| json!({ "id": id, "record": value.public_record() }))
            .collect(),
    )
}

fn lane_fee_cap_bps(kind: RelayLaneKind, config: &Config) -> u64 {
    match kind {
        RelayLaneKind::InstantPayment => config.low_fee_target_bps + 1,
        RelayLaneKind::DexIntent => config.low_fee_target_bps + 3,
        RelayLaneKind::BridgeIngress | RelayLaneKind::BridgeEgress => config.low_fee_target_bps + 5,
        RelayLaneKind::LiquidityRebalance | RelayLaneKind::Watchtower => {
            config.low_fee_target_bps + 6
        }
        RelayLaneKind::SettlementCallback => config.low_fee_target_bps + 8,
        RelayLaneKind::EmergencyExit => config.max_relay_fee_bps,
    }
    .min(config.max_relay_fee_bps)
}

fn rolling_median_hint(current: u64, observed: u64) -> u64 {
    current
        .saturating_mul(7)
        .saturating_add(observed.saturating_mul(3))
        / 10
}

fn latency_bucket(latency_ms: u64) -> &'static str {
    match latency_ms {
        0..=499 => "sub_500ms",
        500..=999 => "sub_second",
        1_000..=1_999 => "one_to_two_seconds",
        2_000..=4_999 => "two_to_five_seconds",
        _ => "over_five_seconds",
    }
}
