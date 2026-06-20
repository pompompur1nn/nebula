use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialErasurecastReceiptRepairSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ERASURECAST_RECEIPT_REPAIR_SCHEDULER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-erasurecast-receipt-repair-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ERASURECAST_RECEIPT_REPAIR_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const REPAIR_SCHEDULER_SUITE: &str =
    "private-l2-fast-confidential-erasurecast-receipt-repair-scheduler-v1";
pub const PQ_REPAIR_LANE_AUTH_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-repair-lane-auth-v1";
pub const CONFIDENTIAL_SHARD_GROUP_SUITE: &str = "ml-kem-1024-confidential-receipt-shard-group-v1";
pub const LOW_FEE_RETRY_CAP_SUITE: &str = "private-l2-low-fee-repair-retry-cap-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-erasurecast-receipt-repair-scheduler-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_receipts_addresses_view_keys_group_members_or_shard_payload_bytes";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_360_000;
pub const DEVNET_EPOCH: u64 = 17_088;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_LANES: usize = 128;
pub const DEFAULT_MAX_GROUPS: usize = 65_536;
pub const DEFAULT_MAX_REQUESTS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const DEFAULT_FANOUT_WIDTH: u16 = 96;
pub const DEFAULT_FANOUT_QUORUM: u16 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_REPAIR_TTL_SLOTS: u64 = 48;
pub const DEFAULT_TARGET_REPAIR_MS: u64 = 24;
pub const DEFAULT_MAX_MISSING_SHARDS: u16 = 24;
pub const DEFAULT_BASE_RETRY_FEE_MICROS: u64 = 3;
pub const DEFAULT_RETRY_FEE_CAP_MICROS: u64 = 36;
pub const DEFAULT_MAX_RETRY_COUNT: u64 = 5;
pub const DEFAULT_CONGESTION_MULTIPLIER_BPS: u64 = 1_150;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:LANES";
const D_GROUPS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:GROUPS";
const D_REQUESTS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:REQUESTS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:ATTESTATIONS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-ERASURECAST-RECEIPT-REPAIR-SCHEDULER:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairLaneKind {
    WalletFast,
    MerchantFast,
    BridgeExit,
    DefiSettlement,
    OperatorMirror,
    RecoveryArchive,
}

impl RepairLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletFast => "wallet_fast",
            Self::MerchantFast => "merchant_fast",
            Self::BridgeExit => "bridge_exit",
            Self::DefiSettlement => "defi_settlement",
            Self::OperatorMirror => "operator_mirror",
            Self::RecoveryArchive => "recovery_archive",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 10_000,
            Self::OperatorMirror => 9_700,
            Self::DefiSettlement => 9_100,
            Self::MerchantFast => 8_500,
            Self::WalletFast => 8_000,
            Self::RecoveryArchive => 5_500,
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
    pub fn accepts_repairs(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::FeeCapped)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardGroupStatus {
    Open,
    Sealed,
    RotatingKeys,
    Suspended,
    Retired,
}

impl ShardGroupStatus {
    pub fn accepts_repairs(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairStatus {
    Queued,
    PqAuthenticated,
    Scheduled,
    Delivered,
    RetryCapped,
    Expired,
}

impl RepairStatus {
    pub fn accepts_delivery(self) -> bool {
        matches!(self, Self::PqAuthenticated | Self::Scheduled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairReason {
    AvailabilityGap,
    FanoutTimeout,
    ShardDigestMismatch,
    GroupKeyRotation,
    RecoveryReplay,
    LowFeeRetryPreserve,
}

impl RepairReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AvailabilityGap => "availability_gap",
            Self::FanoutTimeout => "fanout_timeout",
            Self::ShardDigestMismatch => "shard_digest_mismatch",
            Self::GroupKeyRotation => "group_key_rotation",
            Self::RecoveryReplay => "recovery_replay",
            Self::LowFeeRetryPreserve => "low_fee_retry_preserve",
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
    pub repair_scheduler_suite: String,
    pub pq_repair_lane_auth_suite: String,
    pub confidential_shard_group_suite: String,
    pub low_fee_retry_cap_suite: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub max_lanes: usize,
    pub max_groups: usize,
    pub max_requests: usize,
    pub max_attestations: usize,
    pub max_public_records: usize,
    pub fanout_width: u16,
    pub fanout_quorum: u16,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub repair_ttl_slots: u64,
    pub target_repair_ms: u64,
    pub max_missing_shards: u16,
    pub base_retry_fee_micros: u64,
    pub retry_fee_cap_micros: u64,
    pub max_retry_count: u64,
    pub congestion_multiplier_bps: u64,
    pub require_pq_authenticated_repair_lanes: bool,
    pub require_confidential_shard_groups: bool,
    pub require_low_fee_retry_caps: bool,
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
            repair_scheduler_suite: REPAIR_SCHEDULER_SUITE.to_string(),
            pq_repair_lane_auth_suite: PQ_REPAIR_LANE_AUTH_SUITE.to_string(),
            confidential_shard_group_suite: CONFIDENTIAL_SHARD_GROUP_SUITE.to_string(),
            low_fee_retry_cap_suite: LOW_FEE_RETRY_CAP_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            max_lanes: DEFAULT_MAX_LANES,
            max_groups: DEFAULT_MAX_GROUPS,
            max_requests: DEFAULT_MAX_REQUESTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            fanout_width: DEFAULT_FANOUT_WIDTH,
            fanout_quorum: DEFAULT_FANOUT_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            repair_ttl_slots: DEFAULT_REPAIR_TTL_SLOTS,
            target_repair_ms: DEFAULT_TARGET_REPAIR_MS,
            max_missing_shards: DEFAULT_MAX_MISSING_SHARDS,
            base_retry_fee_micros: DEFAULT_BASE_RETRY_FEE_MICROS,
            retry_fee_cap_micros: DEFAULT_RETRY_FEE_CAP_MICROS,
            max_retry_count: DEFAULT_MAX_RETRY_COUNT,
            congestion_multiplier_bps: DEFAULT_CONGESTION_MULTIPLIER_BPS,
            require_pq_authenticated_repair_lanes: true,
            require_confidential_shard_groups: true,
            require_low_fee_retry_caps: true,
            require_deterministic_roots: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.max_lanes == 0 || self.max_groups == 0 || self.max_requests == 0 {
            return Err("repair scheduler capacities must be non-zero".to_string());
        }
        if self.fanout_quorum == 0 || self.fanout_quorum > self.fanout_width {
            return Err("repair fanout quorum must fit configured width".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below 192 bits".to_string());
        }
        if self.max_missing_shards == 0 {
            return Err("missing shard ceiling must be non-zero".to_string());
        }
        if self.base_retry_fee_micros > self.retry_fee_cap_micros {
            return Err("base retry fee exceeds retry cap".to_string());
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
    pub shard_groups_opened: u64,
    pub repair_requests_queued: u64,
    pub repair_requests_scheduled: u64,
    pub repair_requests_delivered: u64,
    pub missing_shards_scheduled: u64,
    pub pq_attestations_verified: u64,
    pub authenticated_repair_peers: u64,
    pub retry_fees_micros: u64,
    pub retry_fee_cap_savings_micros: u64,
    pub retry_caps_applied: u64,
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
    pub repair_lanes_root: String,
    pub shard_groups_root: String,
    pub repair_requests_root: String,
    pub pq_repair_attestations_root: String,
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
pub struct RepairLane {
    pub lane_id: String,
    pub kind: RepairLaneKind,
    pub status: LaneStatus,
    pub priority_weight: u64,
    pub scheduled_repairs: u64,
    pub delivered_repairs: u64,
    pub lane_root: String,
}

impl RepairLane {
    pub fn new(lane_id: impl Into<String>, kind: RepairLaneKind) -> Self {
        let mut lane = Self {
            lane_id: lane_id.into(),
            kind,
            status: LaneStatus::Open,
            priority_weight: kind.priority_weight(),
            scheduled_repairs: 0,
            delivered_repairs: 0,
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
            "scheduled_repairs": self.scheduled_repairs,
            "delivered_repairs": self.delivered_repairs,
            "lane_root": self.lane_root
        })
    }

    fn refresh_root(&mut self) {
        self.lane_root = record_root("REPAIR-LANE", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialShardGroup {
    pub group_id: String,
    pub status: ShardGroupStatus,
    pub receipt_commitment_count: u64,
    pub privacy_set_size: u64,
    pub epoch: u64,
    pub encrypted_group_key_root: String,
    pub membership_commitment_root: String,
    pub group_root: String,
}

impl ConfidentialShardGroup {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.group_root = record_root("CONFIDENTIAL-SHARD-GROUP", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepairRequest {
    pub request_id: String,
    pub lane_id: String,
    pub group_id: String,
    pub reason: RepairReason,
    pub status: RepairStatus,
    pub missing_shards: u16,
    pub retry_count: u64,
    pub queued_slot: u64,
    pub scheduled_slot: u64,
    pub expires_at_slot: u64,
    pub uncapped_fee_micros: u64,
    pub charged_fee_micros: u64,
    pub fee_cap_micros: u64,
    pub receipt_commitment_root: String,
    pub missing_shard_set_root: String,
    pub deterministic_repair_root: String,
    pub request_root: String,
}

impl RepairRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "lane_id": self.lane_id,
            "group_id": self.group_id,
            "reason": self.reason.as_str(),
            "status": self.status,
            "missing_shards": self.missing_shards,
            "retry_count": self.retry_count,
            "queued_slot": self.queued_slot,
            "scheduled_slot": self.scheduled_slot,
            "expires_at_slot": self.expires_at_slot,
            "uncapped_fee_micros": self.uncapped_fee_micros,
            "charged_fee_micros": self.charged_fee_micros,
            "fee_cap_micros": self.fee_cap_micros,
            "receipt_commitment_root": self.receipt_commitment_root,
            "missing_shard_set_root": self.missing_shard_set_root,
            "deterministic_repair_root": self.deterministic_repair_root,
            "request_root": self.request_root
        })
    }

    fn refresh_root(&mut self) {
        self.request_root = record_root("REPAIR-REQUEST", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRepairAttestation {
    pub attestation_id: String,
    pub request_id: String,
    pub lane_id: String,
    pub status_accepted: bool,
    pub fanout_width: u16,
    pub quorum_threshold: u16,
    pub authenticated_peers: u16,
    pub pq_suite: String,
    pub security_bits: u16,
    pub attested_request_root: String,
    pub aggregate_signature_root: String,
    pub attestation_root: String,
}

impl PqRepairAttestation {
    pub fn accepted(&self) -> bool {
        self.status_accepted
            && self.security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.authenticated_peers >= self.quorum_threshold
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    fn refresh_root(&mut self) {
        self.attestation_root = record_root("PQ-REPAIR-ATTESTATION", &self.public_record());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub epoch: u64,
    pub lane_count: usize,
    pub shard_group_count: usize,
    pub repair_request_count: usize,
    pub pq_attestation_count: usize,
    pub missing_shards_scheduled: u64,
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
    pub repair_lanes: BTreeMap<String, RepairLane>,
    pub shard_groups: BTreeMap<String, ConfidentialShardGroup>,
    pub repair_requests: BTreeMap<String, RepairRequest>,
    pub pq_repair_attestations: BTreeMap<String, PqRepairAttestation>,
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
            repair_lanes: BTreeMap::new(),
            shard_groups: BTreeMap::new(),
            repair_requests: BTreeMap::new(),
            pq_repair_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.current_slot = 84;
        state.seed_devnet();
        state.refresh_roots();
        state.emit_public_record();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn register_lane(&mut self, lane: RepairLane) -> Result<()> {
        if self.repair_lanes.len() >= self.config.max_lanes {
            return Err("repair lane capacity exceeded".to_string());
        }
        self.repair_lanes.insert(lane.lane_id.clone(), lane);
        self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_shard_group(
        &mut self,
        group_id: impl Into<String>,
        receipt_commitment_count: u64,
    ) -> Result<String> {
        if self.shard_groups.len() >= self.config.max_groups {
            return Err("confidential shard group capacity exceeded".to_string());
        }
        let group_id = group_id.into();
        let mut group = ConfidentialShardGroup {
            encrypted_group_key_root: group_key_root(&group_id, self.epoch),
            membership_commitment_root: membership_root(&group_id, receipt_commitment_count),
            group_id: group_id.clone(),
            status: ShardGroupStatus::Open,
            receipt_commitment_count,
            privacy_set_size: self.config.min_privacy_set_size,
            epoch: self.epoch,
            group_root: String::new(),
        };
        group.refresh_root();
        self.shard_groups.insert(group_id.clone(), group);
        self.counters.shard_groups_opened = self.counters.shard_groups_opened.saturating_add(1);
        self.refresh_roots();
        Ok(group_id)
    }

    pub fn queue_repair(
        &mut self,
        lane_id: &str,
        group_id: &str,
        reason: RepairReason,
        missing_shards: u16,
        retry_count: u64,
        first_receipt_index: u64,
        receipt_count: u64,
    ) -> Result<String> {
        if self.repair_requests.len() >= self.config.max_requests {
            return Err("repair request capacity exceeded".to_string());
        }
        if missing_shards == 0 || missing_shards > self.config.max_missing_shards {
            return Err("missing shard count outside scheduler bounds".to_string());
        }
        if retry_count > self.config.max_retry_count {
            return Err("retry count exceeds low-fee cap policy".to_string());
        }
        let lane = self
            .repair_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "repair lane not found".to_string())?;
        if !lane.status.accepts_repairs() {
            return Err("repair lane does not accept requests".to_string());
        }
        let group = self
            .shard_groups
            .get(group_id)
            .ok_or_else(|| "confidential shard group not found".to_string())?;
        if !group.status.accepts_repairs() {
            return Err("confidential shard group does not accept repairs".to_string());
        }

        let scaled_base = self
            .config
            .base_retry_fee_micros
            .saturating_mul(retry_count.saturating_add(1))
            .saturating_mul(missing_shards as u64);
        let uncapped_fee_micros =
            scaled_base.saturating_mul(self.config.congestion_multiplier_bps) / MAX_BPS;
        let charged_fee_micros = uncapped_fee_micros.min(self.config.retry_fee_cap_micros);
        let receipt_commitment_root =
            receipt_commitment_root(group_id, first_receipt_index, receipt_count);
        let missing_shard_set_root = missing_shard_set_root(lane_id, group_id, missing_shards);
        let deterministic_repair_root = deterministic_repair_root(
            lane_id,
            group_id,
            self.current_slot,
            &receipt_commitment_root,
            &missing_shard_set_root,
            &group.group_root,
        );
        let status = if uncapped_fee_micros > charged_fee_micros {
            RepairStatus::RetryCapped
        } else {
            RepairStatus::Queued
        };
        let mut request = RepairRequest {
            request_id: format!(
                "repair-request-{lane_id}-{group_id}-{first_receipt_index}-{retry_count}"
            ),
            lane_id: lane_id.to_string(),
            group_id: group_id.to_string(),
            reason,
            status,
            missing_shards,
            retry_count,
            queued_slot: self.current_slot,
            scheduled_slot: self.current_slot.saturating_add(1),
            expires_at_slot: self
                .current_slot
                .saturating_add(self.config.repair_ttl_slots),
            uncapped_fee_micros,
            charged_fee_micros,
            fee_cap_micros: self.config.retry_fee_cap_micros,
            receipt_commitment_root,
            missing_shard_set_root,
            deterministic_repair_root,
            request_root: String::new(),
        };
        request.refresh_root();
        lane.scheduled_repairs = lane.scheduled_repairs.saturating_add(1);
        lane.refresh_root();
        let request_id = request.request_id.clone();
        self.repair_requests.insert(request_id.clone(), request);
        self.counters.repair_requests_queued =
            self.counters.repair_requests_queued.saturating_add(1);
        self.counters.missing_shards_scheduled = self
            .counters
            .missing_shards_scheduled
            .saturating_add(missing_shards as u64);
        self.counters.retry_fees_micros = self
            .counters
            .retry_fees_micros
            .saturating_add(charged_fee_micros);
        self.counters.retry_fee_cap_savings_micros = self
            .counters
            .retry_fee_cap_savings_micros
            .saturating_add(uncapped_fee_micros.saturating_sub(charged_fee_micros));
        if status == RepairStatus::RetryCapped {
            self.counters.retry_caps_applied = self.counters.retry_caps_applied.saturating_add(1);
        }
        self.counters.deterministic_roots_emitted =
            self.counters.deterministic_roots_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(request_id)
    }

    pub fn authenticate_repair_lane(
        &mut self,
        request_id: &str,
        authenticated_peers: u16,
    ) -> Result<()> {
        if self.pq_repair_attestations.len() >= self.config.max_attestations {
            return Err("PQ repair attestation capacity exceeded".to_string());
        }
        let request = self
            .repair_requests
            .get_mut(request_id)
            .ok_or_else(|| "repair request not found".to_string())?;
        let accepted = authenticated_peers >= self.config.fanout_quorum;
        let mut attestation = PqRepairAttestation {
            attestation_id: format!("pq-repair-attestation-{request_id}"),
            request_id: request_id.to_string(),
            lane_id: request.lane_id.clone(),
            status_accepted: accepted,
            fanout_width: self.config.fanout_width,
            quorum_threshold: self.config.fanout_quorum,
            authenticated_peers,
            pq_suite: PQ_REPAIR_LANE_AUTH_SUITE.to_string(),
            security_bits: self.config.min_pq_security_bits,
            attested_request_root: request.request_root.clone(),
            aggregate_signature_root: dev_hash("repair-lane-signature", authenticated_peers as u64),
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        if attestation.accepted() {
            request.status = RepairStatus::PqAuthenticated;
            request.refresh_root();
            self.counters.pq_attestations_verified =
                self.counters.pq_attestations_verified.saturating_add(1);
            self.counters.authenticated_repair_peers = self
                .counters
                .authenticated_repair_peers
                .saturating_add(authenticated_peers as u64);
        }
        self.pq_repair_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn schedule_repair(&mut self, request_id: &str) -> Result<()> {
        let request = self
            .repair_requests
            .get_mut(request_id)
            .ok_or_else(|| "repair request not found".to_string())?;
        if request.status != RepairStatus::PqAuthenticated {
            return Err("repair request is not PQ authenticated".to_string());
        }
        request.status = RepairStatus::Scheduled;
        request.refresh_root();
        self.counters.repair_requests_scheduled =
            self.counters.repair_requests_scheduled.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn mark_delivered(&mut self, request_id: &str) -> Result<()> {
        let request = self
            .repair_requests
            .get_mut(request_id)
            .ok_or_else(|| "repair request not found".to_string())?;
        if !request.status.accepts_delivery() {
            return Err("repair request is not ready for delivery".to_string());
        }
        request.status = RepairStatus::Delivered;
        request.refresh_root();
        if let Some(lane) = self.repair_lanes.get_mut(&request.lane_id) {
            lane.delivered_repairs = lane.delivered_repairs.saturating_add(1);
            lane.refresh_root();
        }
        self.counters.repair_requests_delivered =
            self.counters.repair_requests_delivered.saturating_add(1);
        self.refresh_roots();
        Ok(())
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
            "repair_lanes": self.repair_lanes.values().map(RepairLane::public_record).collect::<Vec<_>>(),
            "shard_groups": self.shard_groups.values().map(ConfidentialShardGroup::public_record).collect::<Vec<_>>(),
            "repair_requests": self.repair_requests.values().map(RepairRequest::public_record).collect::<Vec<_>>(),
            "pq_repair_attestations": self.pq_repair_attestations.values().map(PqRepairAttestation::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(OperatorPublicRecord::public_record).collect::<Vec<_>>(),
            "operator_safe": true,
            "receipt_payloads_redacted": true,
            "pq_authenticated_repair_lanes": true,
            "confidential_receipt_shard_groups": true,
            "low_fee_retry_caps": true,
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
            repair_lanes_root: merkle_records(D_LANES, &self.repair_lanes),
            shard_groups_root: merkle_records(D_GROUPS, &self.shard_groups),
            repair_requests_root: merkle_records(D_REQUESTS, &self.repair_requests),
            pq_repair_attestations_root: merkle_records(
                D_ATTESTATIONS,
                &self.pq_repair_attestations,
            ),
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
            RepairLaneKind::WalletFast,
            RepairLaneKind::MerchantFast,
            RepairLaneKind::BridgeExit,
            RepairLaneKind::DefiSettlement,
            RepairLaneKind::OperatorMirror,
            RepairLaneKind::RecoveryArchive,
        ];
        for (index, kind) in lanes.into_iter().enumerate() {
            let lane_id = format!("repair-lane-devnet-{:02}", index + 1);
            let mut lane = RepairLane::new(lane_id.clone(), kind);
            if matches!(
                kind,
                RepairLaneKind::BridgeExit | RepairLaneKind::OperatorMirror
            ) {
                lane.status = LaneStatus::Hot;
                lane.refresh_root();
            } else if index % 2 == 1 {
                lane.status = LaneStatus::FeeCapped;
                lane.refresh_root();
            }
            let _ = self.register_lane(lane);
            let group_id = self
                .open_shard_group(
                    format!("confidential-shard-group-devnet-{:02}", index + 1),
                    1_536 + index as u64 * 384,
                )
                .expect("devnet shard group capacity");
            let request_id = self
                .queue_repair(
                    &lane_id,
                    &group_id,
                    if index % 2 == 0 {
                        RepairReason::LowFeeRetryPreserve
                    } else {
                        RepairReason::AvailabilityGap
                    },
                    2 + index as u16,
                    (index as u64 % self.config.max_retry_count).saturating_add(1),
                    900_000 + index as u64 * 30_000,
                    240 + index as u64 * 48,
                )
                .expect("devnet repair request queues");
            let authenticated_peers = self
                .config
                .fanout_quorum
                .saturating_add((index as u16) % 9)
                .min(self.config.fanout_width);
            let _ = self.authenticate_repair_lane(&request_id, authenticated_peers);
            let _ = self.schedule_repair(&request_id);
            if index % 3 != 0 {
                let _ = self.mark_delivered(&request_id);
            }
        }
    }

    fn emit_public_record(&mut self) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let mut record = OperatorPublicRecord {
            record_id: "operator-public-record-devnet-erasurecast-receipt-repair-scheduler"
                .to_string(),
            height: self.height,
            epoch: self.epoch,
            lane_count: self.repair_lanes.len(),
            shard_group_count: self.shard_groups.len(),
            repair_request_count: self.repair_requests.len(),
            pq_attestation_count: self.pq_repair_attestations.len(),
            missing_shards_scheduled: self.counters.missing_shards_scheduled,
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
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-ERASURECAST-RECEIPT-REPAIR-SCHEDULER-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn repair_lane_digest(record: &RepairLane) -> String {
    payload_root(PQ_REPAIR_LANE_AUTH_SUITE, &record.public_record())
}

pub fn shard_group_digest(record: &ConfidentialShardGroup) -> String {
    payload_root(CONFIDENTIAL_SHARD_GROUP_SUITE, &record.public_record())
}

pub fn repair_request_digest(record: &RepairRequest) -> String {
    payload_root(REPAIR_SCHEDULER_SUITE, &record.public_record())
}

pub fn pq_repair_attestation_digest(record: &PqRepairAttestation) -> String {
    payload_root(PQ_REPAIR_LANE_AUTH_SUITE, &record.public_record())
}

fn group_key_root(group_id: &str, epoch: u64) -> String {
    domain_hash(
        CONFIDENTIAL_SHARD_GROUP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(epoch),
        ],
        32,
    )
}

fn membership_root(group_id: &str, receipt_commitment_count: u64) -> String {
    domain_hash(
        CONFIDENTIAL_SHARD_GROUP_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(receipt_commitment_count),
        ],
        32,
    )
}

fn receipt_commitment_root(group_id: &str, first_receipt_index: u64, receipt_count: u64) -> String {
    domain_hash(
        REPAIR_SCHEDULER_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(group_id),
            HashPart::U64(first_receipt_index),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

fn missing_shard_set_root(lane_id: &str, group_id: &str, missing_shards: u16) -> String {
    domain_hash(
        REPAIR_SCHEDULER_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(group_id),
            HashPart::U64(missing_shards as u64),
            HashPart::Str("missing-shard-index-set-redacted"),
        ],
        32,
    )
}

fn deterministic_repair_root(
    lane_id: &str,
    group_id: &str,
    slot: u64,
    receipt_commitment_root: &str,
    missing_shard_set_root: &str,
    group_root: &str,
) -> String {
    domain_hash(
        REPAIR_SCHEDULER_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(group_id),
            HashPart::U64(slot),
            HashPart::Str(receipt_commitment_root),
            HashPart::Str(missing_shard_set_root),
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
