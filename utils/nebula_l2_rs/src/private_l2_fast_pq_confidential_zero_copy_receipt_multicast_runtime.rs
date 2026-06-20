use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialZeroCopyReceiptMulticastRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_COPY_RECEIPT_MULTICAST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-zero-copy-receipt-multicast-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_COPY_RECEIPT_MULTICAST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ZERO_COPY_MULTICAST_SUITE: &str =
    "private-l2-fast-confidential-zero-copy-receipt-multicast-v1";
pub const PQ_LANE_AUTH_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-lane-auth-v1";
pub const CONFIDENTIAL_DELIVERY_GROUP_SUITE: &str =
    "ml-kem-1024-confidential-receipt-delivery-group-v1";
pub const RETRANSMISSION_FEE_CAP_SUITE: &str =
    "private-l2-receipt-multicast-retransmission-fee-cap-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-zero-copy-receipt-multicast-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_receipts_addresses_view_keys_group_members_or_payload_bytes";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_280_000;
pub const DEVNET_EPOCH: u64 = 16_896;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_LANES: usize = 256;
pub const DEFAULT_MAX_GROUPS: usize = 65_536;
pub const DEFAULT_MAX_SEGMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_RETRANSMISSIONS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const DEFAULT_FANOUT_WIDTH: u16 = 64;
pub const DEFAULT_FANOUT_QUORUM: u16 = 43;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_SEGMENT_TTL_SLOTS: u64 = 80;
pub const DEFAULT_TARGET_MULTICAST_MS: u64 = 32;
pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
pub const DEFAULT_RETRANSMIT_BASE_FEE_MICROS: u64 = 10;
pub const DEFAULT_RETRANSMIT_FEE_CAP_MICROS: u64 = 80;
pub const DEFAULT_CONGESTION_MULTIPLIER_BPS: u64 = 1_250;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:LANES";
const D_GROUPS: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:GROUPS";
const D_SEGMENTS: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:SEGMENTS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:ATTESTATIONS";
const D_RETRANSMIT: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:RETRANSMIT";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-ZC-RECEIPT-MULTICAST:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MulticastLaneKind {
    WalletSync,
    MerchantReceipt,
    BridgeExit,
    RfqSettlement,
    DarkpoolFill,
    OperatorMirror,
    RecoveryReplay,
}

impl MulticastLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSync => "wallet_sync",
            Self::MerchantReceipt => "merchant_receipt",
            Self::BridgeExit => "bridge_exit",
            Self::RfqSettlement => "rfq_settlement",
            Self::DarkpoolFill => "darkpool_fill",
            Self::OperatorMirror => "operator_mirror",
            Self::RecoveryReplay => "recovery_replay",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 10_000,
            Self::OperatorMirror => 9_700,
            Self::DarkpoolFill => 9_200,
            Self::RfqSettlement => 8_800,
            Self::MerchantReceipt => 8_400,
            Self::WalletSync => 7_500,
            Self::RecoveryReplay => 5_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Hot,
    FeeCapped,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_segments(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::FeeCapped)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryGroupStatus {
    Open,
    Sealed,
    RotatingKeys,
    Suspended,
    Retired,
}

impl DeliveryGroupStatus {
    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentStatus {
    Staged,
    ZeroCopyPinned,
    PqAuthenticated,
    Multicast,
    RetransmitQueued,
    Delivered,
    Expired,
}

impl SegmentStatus {
    pub fn can_multicast(self) -> bool {
        matches!(self, Self::ZeroCopyPinned | Self::PqAuthenticated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Collecting,
    Verified,
    Partial,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetransmitReason {
    FeeCapPreserve,
    PeerTimeout,
    GroupKeyRotation,
    FanoutGap,
    RecoveryReplay,
}

impl RetransmitReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeCapPreserve => "fee_cap_preserve",
            Self::PeerTimeout => "peer_timeout",
            Self::GroupKeyRotation => "group_key_rotation",
            Self::FanoutGap => "fanout_gap",
            Self::RecoveryReplay => "recovery_replay",
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
    pub zero_copy_multicast_suite: String,
    pub pq_lane_auth_suite: String,
    pub confidential_delivery_group_suite: String,
    pub retransmission_fee_cap_suite: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub max_lanes: usize,
    pub max_groups: usize,
    pub max_segments: usize,
    pub max_attestations: usize,
    pub max_retransmissions: usize,
    pub max_public_records: usize,
    pub fanout_width: u16,
    pub fanout_quorum: u16,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub segment_ttl_slots: u64,
    pub target_multicast_ms: u64,
    pub max_segment_bytes: u64,
    pub retransmit_base_fee_micros: u64,
    pub retransmit_fee_cap_micros: u64,
    pub congestion_multiplier_bps: u64,
    pub require_zero_copy_segments: bool,
    pub require_confidential_groups: bool,
    pub require_deterministic_roots: bool,
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
            zero_copy_multicast_suite: ZERO_COPY_MULTICAST_SUITE.to_string(),
            pq_lane_auth_suite: PQ_LANE_AUTH_SUITE.to_string(),
            confidential_delivery_group_suite: CONFIDENTIAL_DELIVERY_GROUP_SUITE.to_string(),
            retransmission_fee_cap_suite: RETRANSMISSION_FEE_CAP_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            max_lanes: DEFAULT_MAX_LANES,
            max_groups: DEFAULT_MAX_GROUPS,
            max_segments: DEFAULT_MAX_SEGMENTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_retransmissions: DEFAULT_MAX_RETRANSMISSIONS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            fanout_width: DEFAULT_FANOUT_WIDTH,
            fanout_quorum: DEFAULT_FANOUT_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            segment_ttl_slots: DEFAULT_SEGMENT_TTL_SLOTS,
            target_multicast_ms: DEFAULT_TARGET_MULTICAST_MS,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            retransmit_base_fee_micros: DEFAULT_RETRANSMIT_BASE_FEE_MICROS,
            retransmit_fee_cap_micros: DEFAULT_RETRANSMIT_FEE_CAP_MICROS,
            congestion_multiplier_bps: DEFAULT_CONGESTION_MULTIPLIER_BPS,
            require_zero_copy_segments: true,
            require_confidential_groups: true,
            require_deterministic_roots: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.fanout_quorum == 0 || self.fanout_quorum > self.fanout_width {
            return Err("fanout quorum must fit configured fanout width".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below 192 bits".to_string());
        }
        if self.max_lanes == 0 || self.max_groups == 0 || self.max_segments == 0 {
            return Err("multicast capacities must be non-zero".to_string());
        }
        if self.max_segment_bytes == 0 {
            return Err("zero-copy segment byte ceiling must be non-zero".to_string());
        }
        if self.retransmit_base_fee_micros > self.retransmit_fee_cap_micros {
            return Err("retransmit base fee exceeds cap".to_string());
        }
        if self.congestion_multiplier_bps > MAX_BPS {
            return Err("congestion multiplier exceeds basis point ceiling".to_string());
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
    pub delivery_groups_opened: u64,
    pub receipt_segments_staged: u64,
    pub zero_copy_segments_pinned: u64,
    pub zero_copy_bytes_multicast: u64,
    pub pq_attestations_verified: u64,
    pub authenticated_lane_peers: u64,
    pub multicast_segments_sent: u64,
    pub multicast_recipients_committed: u64,
    pub retransmissions_queued: u64,
    pub retransmissions_delivered: u64,
    pub retransmission_fees_micros: u64,
    pub fee_cap_savings_micros: u64,
    pub deterministic_roots_emitted: u64,
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
    pub multicast_lanes_root: String,
    pub delivery_groups_root: String,
    pub receipt_segments_root: String,
    pub pq_lane_attestations_root: String,
    pub retransmissions_root: String,
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
pub struct MulticastLane {
    pub lane_id: String,
    pub kind: MulticastLaneKind,
    pub status: LaneStatus,
    pub priority_weight: u64,
    pub segments_staged: u64,
    pub segments_multicast: u64,
    pub zero_copy_bytes: u64,
    pub lane_root: String,
}

impl MulticastLane {
    pub fn new(lane_id: impl Into<String>, kind: MulticastLaneKind) -> Self {
        let mut lane = Self {
            lane_id: lane_id.into(),
            kind,
            status: LaneStatus::Open,
            priority_weight: kind.priority_weight(),
            segments_staged: 0,
            segments_multicast: 0,
            zero_copy_bytes: 0,
            lane_root: String::new(),
        };
        lane.refresh_root();
        lane
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "priority_weight": self.priority_weight,
            "segments_staged": self.segments_staged,
            "segments_multicast": self.segments_multicast,
            "zero_copy_bytes": self.zero_copy_bytes,
            "lane_root": self.lane_root
        })
    }

    fn refresh_root(&mut self) {
        self.lane_root = record_root("MULTICAST-LANE", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialDeliveryGroup {
    pub group_id: String,
    pub status: DeliveryGroupStatus,
    pub recipient_commitment_count: u64,
    pub privacy_set_size: u64,
    pub epoch: u64,
    pub encrypted_group_key_root: String,
    pub membership_commitment_root: String,
    pub group_root: String,
}

impl ConfidentialDeliveryGroup {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.group_root = record_root("CONFIDENTIAL-DELIVERY-GROUP", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZeroCopyReceiptSegment {
    pub segment_id: String,
    pub lane_id: String,
    pub group_id: String,
    pub status: SegmentStatus,
    pub first_receipt_index: u64,
    pub receipt_count: u64,
    pub segment_bytes: u64,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub zero_copy_region_id: String,
    pub encrypted_receipt_root: String,
    pub receipt_commitment_root: String,
    pub delivery_group_root: String,
    pub deterministic_multicast_root: String,
    pub segment_root: String,
}

impl ZeroCopyReceiptSegment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.segment_root = record_root("ZERO-COPY-RECEIPT-SEGMENT", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub segment_id: String,
    pub lane_id: String,
    pub status: AttestationStatus,
    pub fanout_width: u16,
    pub quorum_threshold: u16,
    pub authenticated_peers: u16,
    pub pq_suite: String,
    pub security_bits: u16,
    pub aggregate_signature_root: String,
    pub attestation_root: String,
}

impl PqLaneAttestation {
    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && self.security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.authenticated_peers >= self.quorum_threshold
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.attestation_root = record_root("PQ-LANE-ATTESTATION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCappedRetransmission {
    pub retransmission_id: String,
    pub segment_id: String,
    pub reason: RetransmitReason,
    pub retry_count: u64,
    pub scheduled_slot: u64,
    pub uncapped_fee_micros: u64,
    pub charged_fee_micros: u64,
    pub fee_cap_micros: u64,
    pub deterministic_root: String,
    pub retransmission_root: String,
}

impl FeeCappedRetransmission {
    pub fn public_record(&self) -> Value {
        json!({
            "retransmission_id": self.retransmission_id,
            "segment_id": self.segment_id,
            "reason": self.reason.as_str(),
            "retry_count": self.retry_count,
            "scheduled_slot": self.scheduled_slot,
            "uncapped_fee_micros": self.uncapped_fee_micros,
            "charged_fee_micros": self.charged_fee_micros,
            "fee_cap_micros": self.fee_cap_micros,
            "deterministic_root": self.deterministic_root,
            "retransmission_root": self.retransmission_root
        })
    }

    fn refresh_root(&mut self) {
        self.retransmission_root = record_root("FEE-CAPPED-RETRANSMISSION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub lane_count: usize,
    pub delivery_group_count: usize,
    pub receipt_segment_count: usize,
    pub pq_attestation_count: usize,
    pub retransmission_count: usize,
    pub zero_copy_bytes_multicast: u64,
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
    pub multicast_lanes: BTreeMap<String, MulticastLane>,
    pub delivery_groups: BTreeMap<String, ConfidentialDeliveryGroup>,
    pub receipt_segments: BTreeMap<String, ZeroCopyReceiptSegment>,
    pub pq_lane_attestations: BTreeMap<String, PqLaneAttestation>,
    pub retransmissions: BTreeMap<String, FeeCappedRetransmission>,
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
            multicast_lanes: BTreeMap::new(),
            delivery_groups: BTreeMap::new(),
            receipt_segments: BTreeMap::new(),
            pq_lane_attestations: BTreeMap::new(),
            retransmissions: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.current_slot = 72;
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn register_lane(&mut self, lane: MulticastLane) -> Result<String> {
        if self.multicast_lanes.len() >= self.config.max_lanes {
            return Err("multicast lane capacity exceeded".to_string());
        }
        if !lane.status.accepts_segments() {
            return Err("multicast lane does not accept zero-copy segments".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.multicast_lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_delivery_group(
        &mut self,
        group_id: impl Into<String>,
        recipient_commitment_count: u64,
    ) -> Result<String> {
        if self.delivery_groups.len() >= self.config.max_groups {
            return Err("delivery group capacity exceeded".to_string());
        }
        let group_id = group_id.into();
        let mut group = ConfidentialDeliveryGroup {
            encrypted_group_key_root: group_key_root(&group_id, self.epoch),
            membership_commitment_root: membership_root(&group_id, recipient_commitment_count),
            group_id: group_id.clone(),
            status: DeliveryGroupStatus::Open,
            recipient_commitment_count,
            privacy_set_size: self.config.min_privacy_set_size,
            epoch: self.epoch,
            group_root: String::new(),
        };
        group.refresh_root();
        self.delivery_groups.insert(group_id.clone(), group);
        self.counters.delivery_groups_opened =
            self.counters.delivery_groups_opened.saturating_add(1);
        self.refresh_roots();
        Ok(group_id)
    }

    pub fn stage_receipt_segment(
        &mut self,
        lane_id: &str,
        group_id: &str,
        first_receipt_index: u64,
        receipt_count: u64,
        segment_bytes: u64,
    ) -> Result<String> {
        if self.receipt_segments.len() >= self.config.max_segments {
            return Err("receipt segment capacity exceeded".to_string());
        }
        if segment_bytes > self.config.max_segment_bytes {
            return Err("zero-copy receipt segment exceeds byte ceiling".to_string());
        }
        let lane = self
            .multicast_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "multicast lane not found".to_string())?;
        if !lane.status.accepts_segments() {
            return Err("multicast lane does not accept zero-copy segments".to_string());
        }
        let group = self
            .delivery_groups
            .get(group_id)
            .ok_or_else(|| "confidential delivery group not found".to_string())?;
        if !group.status.accepts_receipts() {
            return Err("confidential delivery group does not accept receipts".to_string());
        }
        lane.segments_staged = lane.segments_staged.saturating_add(1);
        lane.zero_copy_bytes = lane.zero_copy_bytes.saturating_add(segment_bytes);
        lane.refresh_root();
        let encrypted_receipt_root =
            encrypted_receipt_root(lane_id, group_id, first_receipt_index, receipt_count);
        let receipt_commitment_root =
            receipt_commitment_root(lane_id, first_receipt_index, receipt_count, segment_bytes);
        let deterministic_multicast_root = deterministic_multicast_root(
            lane_id,
            group_id,
            self.current_slot,
            &encrypted_receipt_root,
            &receipt_commitment_root,
            &group.group_root,
        );
        let mut segment = ZeroCopyReceiptSegment {
            segment_id: format!("zc-receipt-segment-{lane_id}-{group_id}-{first_receipt_index}"),
            lane_id: lane_id.to_string(),
            group_id: group_id.to_string(),
            status: SegmentStatus::ZeroCopyPinned,
            first_receipt_index,
            receipt_count,
            segment_bytes,
            slot: self.current_slot,
            expires_at_slot: self
                .current_slot
                .saturating_add(self.config.segment_ttl_slots),
            zero_copy_region_id: format!("zc-region-{lane_id}-{first_receipt_index}"),
            encrypted_receipt_root,
            receipt_commitment_root,
            delivery_group_root: group.group_root.clone(),
            deterministic_multicast_root,
            segment_root: String::new(),
        };
        segment.refresh_root();
        let segment_id = segment.segment_id.clone();
        self.receipt_segments.insert(segment_id.clone(), segment);
        self.counters.receipt_segments_staged =
            self.counters.receipt_segments_staged.saturating_add(1);
        self.counters.zero_copy_segments_pinned =
            self.counters.zero_copy_segments_pinned.saturating_add(1);
        self.counters.zero_copy_bytes_multicast = self
            .counters
            .zero_copy_bytes_multicast
            .saturating_add(segment_bytes);
        self.counters.deterministic_roots_emitted =
            self.counters.deterministic_roots_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(segment_id)
    }

    pub fn authenticate_lane(&mut self, segment_id: &str, authenticated_peers: u16) -> Result<()> {
        if self.pq_lane_attestations.len() >= self.config.max_attestations {
            return Err("PQ lane attestation capacity exceeded".to_string());
        }
        let segment = self
            .receipt_segments
            .get_mut(segment_id)
            .ok_or_else(|| "receipt segment not found".to_string())?;
        let status = if authenticated_peers >= self.config.fanout_quorum {
            AttestationStatus::Verified
        } else {
            AttestationStatus::Partial
        };
        let mut attestation = PqLaneAttestation {
            attestation_id: format!("pq-lane-attestation-{segment_id}"),
            segment_id: segment_id.to_string(),
            lane_id: segment.lane_id.clone(),
            status,
            fanout_width: self.config.fanout_width,
            quorum_threshold: self.config.fanout_quorum,
            authenticated_peers,
            pq_suite: PQ_LANE_AUTH_SUITE.to_string(),
            security_bits: self.config.min_pq_security_bits,
            aggregate_signature_root: dev_hash("lane-signature", authenticated_peers as u64),
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        if attestation.accepted() {
            segment.status = SegmentStatus::PqAuthenticated;
            segment.refresh_root();
            self.counters.pq_attestations_verified =
                self.counters.pq_attestations_verified.saturating_add(1);
            self.counters.authenticated_lane_peers = self
                .counters
                .authenticated_lane_peers
                .saturating_add(authenticated_peers as u64);
        }
        self.pq_lane_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn multicast_segment(&mut self, segment_id: &str) -> Result<()> {
        let segment = self
            .receipt_segments
            .get_mut(segment_id)
            .ok_or_else(|| "receipt segment not found".to_string())?;
        if !segment.status.can_multicast() {
            return Err("receipt segment is not ready for multicast".to_string());
        }
        segment.status = SegmentStatus::Multicast;
        segment.refresh_root();
        if let Some(lane) = self.multicast_lanes.get_mut(&segment.lane_id) {
            lane.segments_multicast = lane.segments_multicast.saturating_add(1);
            lane.refresh_root();
        }
        if let Some(group) = self.delivery_groups.get(&segment.group_id) {
            self.counters.multicast_recipients_committed = self
                .counters
                .multicast_recipients_committed
                .saturating_add(group.recipient_commitment_count);
        }
        self.counters.multicast_segments_sent =
            self.counters.multicast_segments_sent.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn queue_retransmission(
        &mut self,
        segment_id: &str,
        reason: RetransmitReason,
        retry_count: u64,
    ) -> Result<String> {
        if self.retransmissions.len() >= self.config.max_retransmissions {
            return Err("retransmission capacity exceeded".to_string());
        }
        let segment = self
            .receipt_segments
            .get_mut(segment_id)
            .ok_or_else(|| "receipt segment not found".to_string())?;
        let scaled_base = self
            .config
            .retransmit_base_fee_micros
            .saturating_mul(retry_count.saturating_add(1));
        let uncapped_fee_micros =
            scaled_base.saturating_mul(self.config.congestion_multiplier_bps) / MAX_BPS;
        let charged_fee_micros = uncapped_fee_micros.min(self.config.retransmit_fee_cap_micros);
        let mut retransmission = FeeCappedRetransmission {
            retransmission_id: format!("fee-capped-retransmit-{segment_id}-{retry_count}"),
            segment_id: segment_id.to_string(),
            reason,
            retry_count,
            scheduled_slot: self.current_slot.saturating_add(1),
            uncapped_fee_micros,
            charged_fee_micros,
            fee_cap_micros: self.config.retransmit_fee_cap_micros,
            deterministic_root: segment.deterministic_multicast_root.clone(),
            retransmission_root: String::new(),
        };
        retransmission.refresh_root();
        segment.status = SegmentStatus::RetransmitQueued;
        segment.refresh_root();
        let retransmission_id = retransmission.retransmission_id.clone();
        self.retransmissions
            .insert(retransmission_id.clone(), retransmission);
        self.counters.retransmissions_queued =
            self.counters.retransmissions_queued.saturating_add(1);
        self.counters.retransmission_fees_micros = self
            .counters
            .retransmission_fees_micros
            .saturating_add(charged_fee_micros);
        self.counters.fee_cap_savings_micros = self
            .counters
            .fee_cap_savings_micros
            .saturating_add(uncapped_fee_micros.saturating_sub(charged_fee_micros));
        self.refresh_roots();
        Ok(retransmission_id)
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
            "multicast_lanes": self.multicast_lanes.values().map(MulticastLane::public_record).collect::<Vec<_>>(),
            "delivery_groups": self.delivery_groups.values().map(ConfidentialDeliveryGroup::public_record).collect::<Vec<_>>(),
            "receipt_segments": self.receipt_segments.values().map(ZeroCopyReceiptSegment::public_record).collect::<Vec<_>>(),
            "pq_lane_attestations": self.pq_lane_attestations.values().map(PqLaneAttestation::public_record).collect::<Vec<_>>(),
            "retransmissions": self.retransmissions.values().map(FeeCappedRetransmission::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(OperatorPublicRecord::public_record).collect::<Vec<_>>(),
            "operator_safe": true,
            "zero_copy_receipt_payloads_redacted": true,
            "pq_authenticated_lanes": true,
            "confidential_delivery_groups": true,
            "retransmission_fee_caps": true,
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
            multicast_lanes_root: merkle_records(D_LANES, &self.multicast_lanes),
            delivery_groups_root: merkle_records(D_GROUPS, &self.delivery_groups),
            receipt_segments_root: merkle_records(D_SEGMENTS, &self.receipt_segments),
            pq_lane_attestations_root: merkle_records(D_ATTESTATIONS, &self.pq_lane_attestations),
            retransmissions_root: merkle_records(D_RETRANSMIT, &self.retransmissions),
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
            MulticastLaneKind::WalletSync,
            MulticastLaneKind::MerchantReceipt,
            MulticastLaneKind::BridgeExit,
            MulticastLaneKind::RfqSettlement,
            MulticastLaneKind::DarkpoolFill,
            MulticastLaneKind::OperatorMirror,
        ];
        for (index, kind) in lanes.into_iter().enumerate() {
            let lane_id = format!("zc-multicast-lane-devnet-{:02}", index + 1);
            let mut lane = MulticastLane::new(lane_id.clone(), kind);
            if matches!(
                kind,
                MulticastLaneKind::BridgeExit | MulticastLaneKind::DarkpoolFill
            ) {
                lane.status = LaneStatus::Hot;
                lane.refresh_root();
            } else if index % 2 == 1 {
                lane.status = LaneStatus::FeeCapped;
                lane.refresh_root();
            }
            let _ = self.register_lane(lane);
            let group_id = self
                .open_delivery_group(
                    format!("confidential-delivery-group-devnet-{:02}", index + 1),
                    1_024 + index as u64 * 256,
                )
                .expect("devnet group capacity");
            let receipt_count = 192 + index as u64 * 32;
            let segment_bytes = receipt_count.saturating_mul(208);
            let segment_id = self
                .stage_receipt_segment(
                    &lane_id,
                    &group_id,
                    800_000 + index as u64 * 20_000,
                    receipt_count,
                    segment_bytes,
                )
                .expect("devnet lane and group accept segments");
            let authenticated_peers = self
                .config
                .fanout_quorum
                .saturating_add((index as u16) % 7)
                .min(self.config.fanout_width);
            let _ = self.authenticate_lane(&segment_id, authenticated_peers);
            let _ = self.multicast_segment(&segment_id);
            if index % 2 == 0 {
                let _ = self.queue_retransmission(
                    &segment_id,
                    RetransmitReason::FeeCapPreserve,
                    index as u64 + 1,
                );
            }
        }
    }

    fn emit_public_record(&mut self) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-zero-copy-receipt-multicast".to_string(),
            height: self.height,
            epoch: self.epoch,
            lane_count: self.multicast_lanes.len(),
            delivery_group_count: self.delivery_groups.len(),
            receipt_segment_count: self.receipt_segments.len(),
            pq_attestation_count: self.pq_lane_attestations.len(),
            retransmission_count: self.retransmissions.len(),
            zero_copy_bytes_multicast: self.counters.zero_copy_bytes_multicast,
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

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-ZERO-COPY-RECEIPT-MULTICAST-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn zero_copy_segment_digest(record: &ZeroCopyReceiptSegment) -> String {
    payload_root(ZERO_COPY_MULTICAST_SUITE, &record.public_record())
}

pub fn delivery_group_digest(record: &ConfidentialDeliveryGroup) -> String {
    payload_root(CONFIDENTIAL_DELIVERY_GROUP_SUITE, &record.public_record())
}

pub fn pq_lane_attestation_digest(record: &PqLaneAttestation) -> String {
    payload_root(PQ_LANE_AUTH_SUITE, &record.public_record())
}

pub fn retransmission_digest(record: &FeeCappedRetransmission) -> String {
    payload_root(RETRANSMISSION_FEE_CAP_SUITE, &record.public_record())
}

fn group_key_root(group_id: &str, epoch: u64) -> String {
    domain_hash(
        CONFIDENTIAL_DELIVERY_GROUP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(epoch),
        ],
        32,
    )
}

fn membership_root(group_id: &str, recipient_commitment_count: u64) -> String {
    domain_hash(
        CONFIDENTIAL_DELIVERY_GROUP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(recipient_commitment_count),
        ],
        32,
    )
}

fn encrypted_receipt_root(
    lane_id: &str,
    group_id: &str,
    first_receipt_index: u64,
    receipt_count: u64,
) -> String {
    domain_hash(
        ZERO_COPY_MULTICAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(group_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

fn receipt_commitment_root(
    lane_id: &str,
    first_receipt_index: u64,
    receipt_count: u64,
    segment_bytes: u64,
) -> String {
    domain_hash(
        ZERO_COPY_MULTICAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(receipt_count),
            HashPart::U64(segment_bytes),
        ],
        32,
    )
}

fn deterministic_multicast_root(
    lane_id: &str,
    group_id: &str,
    slot: u64,
    encrypted_receipt_root: &str,
    receipt_commitment_root: &str,
    group_root: &str,
) -> String {
    domain_hash(
        ZERO_COPY_MULTICAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(group_id),
            HashPart::U64(slot),
            HashPart::Str(encrypted_receipt_root),
            HashPart::Str(receipt_commitment_root),
            HashPart::Str(group_root),
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
