use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialMultilaneReceiptDiffBroadcastRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MULTILANE_RECEIPT_DIFF_BROADCAST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-multilane-receipt-diff-broadcast-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MULTILANE_RECEIPT_DIFF_BROADCAST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MULTILANE_BROADCAST_SUITE: &str =
    "private-l2-fast-confidential-multilane-receipt-diff-broadcast-v1";
pub const PQ_FANOUT_AUTH_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-fanout-auth-v1";
pub const CONFIDENTIAL_DIFF_BUCKET_SUITE: &str =
    "hybrid-pq-confidential-receipt-diff-bucket-root-v1";
pub const FEE_AWARE_RETRANSMISSION_SUITE: &str =
    "private-l2-fee-aware-receipt-diff-retransmission-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-multilane-receipt-diff-broadcast-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_amounts_addresses_view_keys_key_images_or_diff_bytes";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_120_000;
pub const DEVNET_EPOCH: u64 = 16_384;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_LANES: usize = 256;
pub const DEFAULT_MAX_DIFF_BUCKETS: usize = 1_048_576;
pub const DEFAULT_MAX_FANOUT_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_RETRANSMISSIONS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const DEFAULT_FANOUT_WIDTH: u16 = 48;
pub const DEFAULT_FANOUT_QUORUM: u16 = 32;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_BUCKET_TTL_SLOTS: u64 = 96;
pub const DEFAULT_TARGET_BROADCAST_MS: u64 = 45;
pub const DEFAULT_RETRANSMIT_BASE_FEE_MICROS: u64 = 12;
pub const DEFAULT_RETRANSMIT_FEE_CAP_MICROS: u64 = 96;
pub const DEFAULT_LOW_FEE_RETRY_DISCOUNT_BPS: u64 = 1_500;
pub const DEFAULT_MAX_BUCKET_BYTES: u64 = 8 * 1024 * 1024;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:LANES";
const D_BUCKETS: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:BUCKETS";
const D_FANOUT: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:FANOUT";
const D_RETRANSMIT: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:RETRANSMIT";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-MULTILANE-RECEIPT-DIFF-BROADCAST:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastLaneKind {
    WalletSync,
    PaymentReceipt,
    BridgeExit,
    RfqSettlement,
    DarkpoolFill,
    FeeRebate,
    OperatorNetting,
    RecoveryReplay,
}

impl BroadcastLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSync => "wallet_sync",
            Self::PaymentReceipt => "payment_receipt",
            Self::BridgeExit => "bridge_exit",
            Self::RfqSettlement => "rfq_settlement",
            Self::DarkpoolFill => "darkpool_fill",
            Self::FeeRebate => "fee_rebate",
            Self::OperatorNetting => "operator_netting",
            Self::RecoveryReplay => "recovery_replay",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 10_000,
            Self::OperatorNetting => 9_800,
            Self::DarkpoolFill => 9_300,
            Self::RfqSettlement => 8_900,
            Self::PaymentReceipt => 8_500,
            Self::WalletSync => 7_400,
            Self::FeeRebate => 6_900,
            Self::RecoveryReplay => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Hot,
    LowFeeOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_bucket(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::LowFeeOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Staged,
    Sealed,
    FanoutAuthenticated,
    Broadcast,
    RetransmitQueued,
    Delivered,
    Expired,
    Invalidated,
}

impl BucketStatus {
    pub fn can_broadcast(self) -> bool {
        matches!(self, Self::Sealed | Self::FanoutAuthenticated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutStatus {
    Collecting,
    Verified,
    Partial,
    Slashed,
    Expired,
}

impl FanoutStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetransmitReason {
    FeeMarketMoved,
    PeerTimeout,
    FanoutGap,
    BucketExpired,
    RecoveryReplay,
}

impl RetransmitReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeMarketMoved => "fee_market_moved",
            Self::PeerTimeout => "peer_timeout",
            Self::FanoutGap => "fanout_gap",
            Self::BucketExpired => "bucket_expired",
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
    pub multilane_broadcast_suite: String,
    pub pq_fanout_auth_suite: String,
    pub confidential_diff_bucket_suite: String,
    pub fee_aware_retransmission_suite: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub max_lanes: usize,
    pub max_diff_buckets: usize,
    pub max_fanout_attestations: usize,
    pub max_retransmissions: usize,
    pub max_public_records: usize,
    pub fanout_width: u16,
    pub fanout_quorum: u16,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub bucket_ttl_slots: u64,
    pub target_broadcast_ms: u64,
    pub retransmit_base_fee_micros: u64,
    pub retransmit_fee_cap_micros: u64,
    pub low_fee_retry_discount_bps: u64,
    pub max_bucket_bytes: u64,
    pub require_confidential_buckets: bool,
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
            multilane_broadcast_suite: MULTILANE_BROADCAST_SUITE.to_string(),
            pq_fanout_auth_suite: PQ_FANOUT_AUTH_SUITE.to_string(),
            confidential_diff_bucket_suite: CONFIDENTIAL_DIFF_BUCKET_SUITE.to_string(),
            fee_aware_retransmission_suite: FEE_AWARE_RETRANSMISSION_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            max_lanes: DEFAULT_MAX_LANES,
            max_diff_buckets: DEFAULT_MAX_DIFF_BUCKETS,
            max_fanout_attestations: DEFAULT_MAX_FANOUT_ATTESTATIONS,
            max_retransmissions: DEFAULT_MAX_RETRANSMISSIONS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            fanout_width: DEFAULT_FANOUT_WIDTH,
            fanout_quorum: DEFAULT_FANOUT_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            bucket_ttl_slots: DEFAULT_BUCKET_TTL_SLOTS,
            target_broadcast_ms: DEFAULT_TARGET_BROADCAST_MS,
            retransmit_base_fee_micros: DEFAULT_RETRANSMIT_BASE_FEE_MICROS,
            retransmit_fee_cap_micros: DEFAULT_RETRANSMIT_FEE_CAP_MICROS,
            low_fee_retry_discount_bps: DEFAULT_LOW_FEE_RETRY_DISCOUNT_BPS,
            max_bucket_bytes: DEFAULT_MAX_BUCKET_BYTES,
            require_confidential_buckets: true,
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
        if self.max_lanes == 0 || self.max_diff_buckets == 0 {
            return Err("multilane broadcast capacities must be non-zero".to_string());
        }
        if self.retransmit_base_fee_micros > self.retransmit_fee_cap_micros {
            return Err("retransmit base fee exceeds cap".to_string());
        }
        if self.low_fee_retry_discount_bps > MAX_BPS {
            return Err("low-fee retry discount exceeds basis point ceiling".to_string());
        }
        if self.max_bucket_bytes == 0 {
            return Err("confidential bucket byte ceiling must be non-zero".to_string());
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
    pub diff_buckets_staged: u64,
    pub diff_buckets_broadcast: u64,
    pub confidential_bytes_bucketed: u64,
    pub pq_fanouts_verified: u64,
    pub fanout_peers_authenticated: u64,
    pub retransmissions_queued: u64,
    pub retransmissions_delivered: u64,
    pub retransmission_fees_micros: u64,
    pub low_fee_retries_discounted: u64,
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
    pub broadcast_lanes_root: String,
    pub diff_buckets_root: String,
    pub fanout_attestations_root: String,
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
pub struct BroadcastLane {
    pub lane_id: String,
    pub kind: BroadcastLaneKind,
    pub status: LaneStatus,
    pub priority_weight: u64,
    pub buckets_staged: u64,
    pub buckets_broadcast: u64,
    pub confidential_bytes: u64,
    pub privacy_set_size: u64,
    pub lane_root: String,
}

impl BroadcastLane {
    pub fn new(lane_id: impl Into<String>, kind: BroadcastLaneKind) -> Self {
        let mut lane = Self {
            lane_id: lane_id.into(),
            kind,
            status: LaneStatus::Open,
            priority_weight: kind.priority_weight(),
            buckets_staged: 0,
            buckets_broadcast: 0,
            confidential_bytes: 0,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            lane_root: String::new(),
        };
        lane.refresh_root();
        lane
    }

    pub fn stage_bucket(&mut self, bytes: u64) {
        self.buckets_staged = self.buckets_staged.saturating_add(1);
        self.confidential_bytes = self.confidential_bytes.saturating_add(bytes);
        self.refresh_root();
    }

    pub fn mark_broadcast(&mut self) {
        self.buckets_broadcast = self.buckets_broadcast.saturating_add(1);
        self.refresh_root();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "priority_weight": self.priority_weight,
            "buckets_staged": self.buckets_staged,
            "buckets_broadcast": self.buckets_broadcast,
            "confidential_bytes": self.confidential_bytes,
            "privacy_set_size": self.privacy_set_size,
            "lane_root": self.lane_root
        })
    }

    fn refresh_root(&mut self) {
        self.lane_root = record_root("BROADCAST-LANE", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialDiffBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub status: BucketStatus,
    pub first_receipt_index: u64,
    pub diff_count: u64,
    pub bucket_bytes: u64,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub encrypted_diff_root: String,
    pub receipt_commitment_root: String,
    pub bucket_root: String,
    pub deterministic_broadcast_root: String,
}

impl ConfidentialDiffBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.bucket_root = record_root("CONFIDENTIAL-DIFF-BUCKET", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqFanoutAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub status: FanoutStatus,
    pub fanout_width: u16,
    pub quorum_threshold: u16,
    pub authenticated_peers: u16,
    pub pq_suite: String,
    pub security_bits: u16,
    pub aggregate_signature_root: String,
    pub attestation_root: String,
}

impl PqFanoutAttestation {
    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && self.security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.authenticated_peers >= self.quorum_threshold
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.attestation_root = record_root("PQ-FANOUT-ATTESTATION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeAwareRetransmission {
    pub retransmission_id: String,
    pub bucket_id: String,
    pub reason: RetransmitReason,
    pub retry_count: u64,
    pub scheduled_slot: u64,
    pub max_fee_micros: u64,
    pub charged_fee_micros: u64,
    pub low_fee_discount_bps: u64,
    pub deterministic_root: String,
    pub retransmission_root: String,
}

impl FeeAwareRetransmission {
    pub fn public_record(&self) -> Value {
        json!({
            "retransmission_id": self.retransmission_id,
            "bucket_id": self.bucket_id,
            "reason": self.reason.as_str(),
            "retry_count": self.retry_count,
            "scheduled_slot": self.scheduled_slot,
            "max_fee_micros": self.max_fee_micros,
            "charged_fee_micros": self.charged_fee_micros,
            "low_fee_discount_bps": self.low_fee_discount_bps,
            "deterministic_root": self.deterministic_root,
            "retransmission_root": self.retransmission_root
        })
    }

    fn refresh_root(&mut self) {
        self.retransmission_root = record_root("FEE-AWARE-RETRANSMISSION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub lane_count: usize,
    pub diff_bucket_count: usize,
    pub fanout_attestation_count: usize,
    pub retransmission_count: usize,
    pub confidential_bytes_bucketed: u64,
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
    pub broadcast_lanes: BTreeMap<String, BroadcastLane>,
    pub diff_buckets: BTreeMap<String, ConfidentialDiffBucket>,
    pub fanout_attestations: BTreeMap<String, PqFanoutAttestation>,
    pub retransmissions: BTreeMap<String, FeeAwareRetransmission>,
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
            broadcast_lanes: BTreeMap::new(),
            diff_buckets: BTreeMap::new(),
            fanout_attestations: BTreeMap::new(),
            retransmissions: BTreeMap::new(),
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

    pub fn register_lane(&mut self, lane: BroadcastLane) -> Result<String> {
        if self.broadcast_lanes.len() >= self.config.max_lanes {
            return Err("broadcast lane capacity exceeded".to_string());
        }
        if !lane.status.accepts_bucket() {
            return Err("broadcast lane does not accept diff buckets".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
        self.broadcast_lanes.insert(lane_id.clone(), lane);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn stage_diff_bucket(
        &mut self,
        lane_id: &str,
        first_receipt_index: u64,
        diff_count: u64,
        bucket_bytes: u64,
    ) -> Result<String> {
        if self.diff_buckets.len() >= self.config.max_diff_buckets {
            return Err("diff bucket capacity exceeded".to_string());
        }
        if bucket_bytes > self.config.max_bucket_bytes {
            return Err("confidential diff bucket exceeds byte ceiling".to_string());
        }
        let lane = self
            .broadcast_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "broadcast lane not found".to_string())?;
        if !lane.status.accepts_bucket() {
            return Err("broadcast lane does not accept diff buckets".to_string());
        }
        lane.stage_bucket(bucket_bytes);
        let encrypted_diff_root =
            confidential_bucket_root(lane_id, first_receipt_index, diff_count, bucket_bytes);
        let receipt_commitment_root =
            receipt_commitment_root(lane_id, first_receipt_index, diff_count);
        let deterministic_broadcast_root = deterministic_broadcast_root(
            lane_id,
            self.current_slot,
            &lane.lane_root,
            &encrypted_diff_root,
            &receipt_commitment_root,
        );
        let mut bucket = ConfidentialDiffBucket {
            bucket_id: format!("diff-bucket-{lane_id}-{first_receipt_index}"),
            lane_id: lane_id.to_string(),
            status: BucketStatus::Sealed,
            first_receipt_index,
            diff_count,
            bucket_bytes,
            slot: self.current_slot,
            expires_at_slot: self
                .current_slot
                .saturating_add(self.config.bucket_ttl_slots),
            encrypted_diff_root,
            receipt_commitment_root,
            bucket_root: String::new(),
            deterministic_broadcast_root,
        };
        bucket.refresh_root();
        let bucket_id = bucket.bucket_id.clone();
        self.diff_buckets.insert(bucket_id.clone(), bucket);
        self.counters.diff_buckets_staged = self.counters.diff_buckets_staged.saturating_add(1);
        self.counters.confidential_bytes_bucketed = self
            .counters
            .confidential_bytes_bucketed
            .saturating_add(bucket_bytes);
        self.counters.deterministic_roots_emitted =
            self.counters.deterministic_roots_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn authenticate_fanout(&mut self, bucket_id: &str, authenticated_peers: u16) -> Result<()> {
        if self.fanout_attestations.len() >= self.config.max_fanout_attestations {
            return Err("fanout attestation capacity exceeded".to_string());
        }
        let bucket = self
            .diff_buckets
            .get_mut(bucket_id)
            .ok_or_else(|| "diff bucket not found".to_string())?;
        let status = if authenticated_peers >= self.config.fanout_quorum {
            FanoutStatus::Verified
        } else {
            FanoutStatus::Partial
        };
        let mut attestation = PqFanoutAttestation {
            attestation_id: format!("pq-fanout-{bucket_id}"),
            bucket_id: bucket_id.to_string(),
            status,
            fanout_width: self.config.fanout_width,
            quorum_threshold: self.config.fanout_quorum,
            authenticated_peers,
            pq_suite: PQ_FANOUT_AUTH_SUITE.to_string(),
            security_bits: self.config.min_pq_security_bits,
            aggregate_signature_root: dev_hash("fanout-signature", authenticated_peers as u64),
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        if attestation.accepted() {
            bucket.status = BucketStatus::FanoutAuthenticated;
            self.counters.pq_fanouts_verified = self.counters.pq_fanouts_verified.saturating_add(1);
            self.counters.fanout_peers_authenticated = self
                .counters
                .fanout_peers_authenticated
                .saturating_add(authenticated_peers as u64);
        }
        self.fanout_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn broadcast_bucket(&mut self, bucket_id: &str) -> Result<()> {
        let bucket = self
            .diff_buckets
            .get_mut(bucket_id)
            .ok_or_else(|| "diff bucket not found".to_string())?;
        if !bucket.status.can_broadcast() {
            return Err("diff bucket is not ready for broadcast".to_string());
        }
        bucket.status = BucketStatus::Broadcast;
        bucket.refresh_root();
        if let Some(lane) = self.broadcast_lanes.get_mut(&bucket.lane_id) {
            lane.mark_broadcast();
        }
        self.counters.diff_buckets_broadcast =
            self.counters.diff_buckets_broadcast.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn queue_retransmission(
        &mut self,
        bucket_id: &str,
        reason: RetransmitReason,
        retry_count: u64,
        low_fee_retry: bool,
    ) -> Result<String> {
        if self.retransmissions.len() >= self.config.max_retransmissions {
            return Err("retransmission capacity exceeded".to_string());
        }
        let bucket = self
            .diff_buckets
            .get_mut(bucket_id)
            .ok_or_else(|| "diff bucket not found".to_string())?;
        let base_fee = self
            .config
            .retransmit_base_fee_micros
            .saturating_mul(retry_count.saturating_add(1))
            .min(self.config.retransmit_fee_cap_micros);
        let discount_bps = if low_fee_retry {
            self.config.low_fee_retry_discount_bps
        } else {
            0
        };
        let charged_fee_micros =
            base_fee.saturating_mul(MAX_BPS.saturating_sub(discount_bps)) / MAX_BPS;
        let mut retransmission = FeeAwareRetransmission {
            retransmission_id: format!("retransmit-{bucket_id}-{retry_count}"),
            bucket_id: bucket_id.to_string(),
            reason,
            retry_count,
            scheduled_slot: self.current_slot.saturating_add(1),
            max_fee_micros: self.config.retransmit_fee_cap_micros,
            charged_fee_micros,
            low_fee_discount_bps: discount_bps,
            deterministic_root: bucket.deterministic_broadcast_root.clone(),
            retransmission_root: String::new(),
        };
        retransmission.refresh_root();
        bucket.status = BucketStatus::RetransmitQueued;
        bucket.refresh_root();
        let retransmission_id = retransmission.retransmission_id.clone();
        self.retransmissions
            .insert(retransmission_id.clone(), retransmission);
        self.counters.retransmissions_queued =
            self.counters.retransmissions_queued.saturating_add(1);
        self.counters.retransmission_fees_micros = self
            .counters
            .retransmission_fees_micros
            .saturating_add(charged_fee_micros);
        if low_fee_retry {
            self.counters.low_fee_retries_discounted =
                self.counters.low_fee_retries_discounted.saturating_add(1);
        }
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
            "broadcast_lanes": self.broadcast_lanes.values().map(BroadcastLane::public_record).collect::<Vec<_>>(),
            "diff_buckets": self.diff_buckets.values().map(ConfidentialDiffBucket::public_record).collect::<Vec<_>>(),
            "fanout_attestations": self.fanout_attestations.values().map(PqFanoutAttestation::public_record).collect::<Vec<_>>(),
            "retransmissions": self.retransmissions.values().map(FeeAwareRetransmission::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(OperatorPublicRecord::public_record).collect::<Vec<_>>(),
            "operator_safe": true,
            "confidential_diff_payloads_redacted": true,
            "pq_authenticated_fanout": true,
            "fee_aware_retransmission": true,
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
            broadcast_lanes_root: merkle_records(D_LANES, &self.broadcast_lanes),
            diff_buckets_root: merkle_records(D_BUCKETS, &self.diff_buckets),
            fanout_attestations_root: merkle_records(D_FANOUT, &self.fanout_attestations),
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
            (BroadcastLaneKind::WalletSync, true),
            (BroadcastLaneKind::PaymentReceipt, true),
            (BroadcastLaneKind::BridgeExit, false),
            (BroadcastLaneKind::RfqSettlement, false),
            (BroadcastLaneKind::DarkpoolFill, false),
            (BroadcastLaneKind::OperatorNetting, false),
        ];
        for (index, (kind, low_fee)) in lanes.iter().enumerate() {
            let lane_id = format!("multilane-broadcast-devnet-{:02}", index + 1);
            let mut lane = BroadcastLane::new(lane_id.clone(), *kind);
            if *low_fee {
                lane.status = LaneStatus::LowFeeOnly;
                lane.refresh_root();
            } else if matches!(
                kind,
                BroadcastLaneKind::BridgeExit | BroadcastLaneKind::DarkpoolFill
            ) {
                lane.status = LaneStatus::Hot;
                lane.refresh_root();
            }
            let _ = self.register_lane(lane);
            let diff_count = 256 + index as u64 * 64;
            let bucket_bytes = diff_count.saturating_mul(224);
            let bucket_id = self
                .stage_diff_bucket(
                    &lane_id,
                    400_000 + index as u64 * 25_000,
                    diff_count,
                    bucket_bytes,
                )
                .expect("devnet lane accepts buckets");
            let authenticated_peers = self
                .config
                .fanout_quorum
                .saturating_add((index as u16) % 5)
                .min(self.config.fanout_width);
            let _ = self.authenticate_fanout(&bucket_id, authenticated_peers);
            let _ = self.broadcast_bucket(&bucket_id);
            if index % 2 == 0 {
                let _ = self.queue_retransmission(
                    &bucket_id,
                    RetransmitReason::FeeMarketMoved,
                    index as u64 + 1,
                    *low_fee,
                );
            }
        }
    }

    fn emit_public_record(&mut self) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-multilane-receipt-diff-broadcast".to_string(),
            height: self.height,
            epoch: self.epoch,
            lane_count: self.broadcast_lanes.len(),
            diff_bucket_count: self.diff_buckets.len(),
            fanout_attestation_count: self.fanout_attestations.len(),
            retransmission_count: self.retransmissions.len(),
            confidential_bytes_bucketed: self.counters.confidential_bytes_bucketed,
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
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-MULTILANE-RECEIPT-DIFF-BROADCAST-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn confidential_bucket_root(
    lane_id: &str,
    first_receipt_index: u64,
    diff_count: u64,
    bucket_bytes: u64,
) -> String {
    domain_hash(
        CONFIDENTIAL_DIFF_BUCKET_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(diff_count),
            HashPart::U64(bucket_bytes),
        ],
        32,
    )
}

fn receipt_commitment_root(lane_id: &str, first_receipt_index: u64, diff_count: u64) -> String {
    domain_hash(
        MULTILANE_BROADCAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(diff_count),
        ],
        32,
    )
}

fn deterministic_broadcast_root(
    lane_id: &str,
    slot: u64,
    lane_root: &str,
    encrypted_diff_root: &str,
    receipt_commitment_root: &str,
) -> String {
    domain_hash(
        MULTILANE_BROADCAST_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(slot),
            HashPart::Str(lane_root),
            HashPart::Str(encrypted_diff_root),
            HashPart::Str(receipt_commitment_root),
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
