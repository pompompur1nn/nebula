use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as raw_domain_hash, merkle_root as raw_merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialSequencerFailoverRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SEQUENCER_FAILOVER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-sequencer-failover-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SEQUENCER_FAILOVER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-sequencer-failover-v1";
pub const HOT_STANDBY_SUITE: &str = "pq-confidential-hot-standby-lane-root-v1";
pub const PRECONFIRMATION_CONTINUITY_SUITE: &str =
    "pq-confidential-preconfirmation-continuity-root-v1";
pub const MEMPOOL_LEASE_TRANSFER_SUITE: &str = "pq-confidential-mempool-lease-transfer-root-v1";
pub const PROPOSER_ROTATION_SUITE: &str = "pq-confidential-fast-proposer-rotation-root-v1";
pub const BACKLOG_DRAIN_SUITE: &str = "pq-confidential-backlog-drain-plan-root-v1";
pub const FEE_CAP_PRESERVATION_SUITE: &str = "pq-confidential-fee-cap-preservation-root-v1";
pub const OPERATOR_TELEMETRY_SUITE: &str =
    "privacy-preserving-confidential-operator-telemetry-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_080_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 120;
pub const DEFAULT_FAILOVER_GRACE_MS: u64 = 360;
pub const DEFAULT_HOT_STANDBY_LANES: usize = 4;
pub const DEFAULT_ROTATION_WINDOW_SLOTS: u64 = 8;
pub const DEFAULT_LEASE_TTL_SLOTS: u64 = 24;
pub const DEFAULT_PRECONFIRMATION_TTL_SLOTS: u64 = 16;
pub const DEFAULT_DRAIN_BATCH_LIMIT: u64 = 512;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_FEE_CAP_GRACE_SLOTS: u64 = 64;
pub const DEFAULT_TELEMETRY_BUCKET_MIN_SIZE: u64 = 64;
pub const DEFAULT_MAX_OPERATORS: usize = 4096;
pub const DEFAULT_MAX_LANES: usize = 8192;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_LEASE_TRANSFERS: usize = 524_288;
pub const DEFAULT_MAX_ROTATIONS: usize = 524_288;
pub const DEFAULT_MAX_DRAIN_PLANS: usize = 262_144;
pub const DEFAULT_MAX_FEE_CAPS: usize = 524_288;
pub const DEFAULT_MAX_TELEMETRY: usize = 524_288;
pub const DEFAULT_MAX_EVENTS: usize = 1_048_576;

fn hp(value: impl ToString) -> HashPart<'static> {
    HashPart::Str(Box::leak(value.to_string().into_boxed_str()))
}

trait LocalHashPart {
    fn to_hash_part(&self) -> HashPart<'_>;
}

impl LocalHashPart for &str {
    fn to_hash_part(&self) -> HashPart<'_> {
        HashPart::Str(*self)
    }
}

impl LocalHashPart for String {
    fn to_hash_part(&self) -> HashPart<'_> {
        HashPart::Str(self.as_str())
    }
}

impl LocalHashPart for &String {
    fn to_hash_part(&self) -> HashPart<'_> {
        HashPart::Str(self.as_str())
    }
}

impl<'a> LocalHashPart for HashPart<'a> {
    fn to_hash_part(&self) -> HashPart<'_> {
        match self {
            HashPart::Bytes(value) => HashPart::Bytes(value),
            HashPart::Str(value) => HashPart::Str(value),
            HashPart::U64(value) => HashPart::U64(*value),
            HashPart::Int(value) => HashPart::Int(*value),
            HashPart::Json(value) => HashPart::Json(value),
        }
    }
}

fn domain_hash<T: LocalHashPart>(domain: &str, parts: &[T]) -> String {
    let hash_parts = parts
        .iter()
        .map(LocalHashPart::to_hash_part)
        .collect::<Vec<_>>();
    raw_domain_hash(domain, &hash_parts, 32)
}

trait MerkleLeaf {
    fn to_merkle_leaf(&self) -> Value;
}

impl<'a> MerkleLeaf for HashPart<'a> {
    fn to_merkle_leaf(&self) -> Value {
        match self {
            HashPart::Bytes(value) => Value::String(hex::encode(value)),
            HashPart::Str(value) => Value::String((*value).to_string()),
            HashPart::U64(value) => json!(value),
            HashPart::Int(value) => json!(value),
            HashPart::Json(value) => (*value).clone(),
        }
    }
}

fn merkle_root<T: MerkleLeaf>(domain: &str, leaves: Vec<T>) -> String {
    let values = leaves
        .iter()
        .map(MerkleLeaf::to_merkle_leaf)
        .collect::<Vec<_>>();
    raw_merkle_root(domain, &values)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Primary,
    HotStandby,
    ColdStandby,
    Emergency,
    Watchtower,
    MempoolKeyholder,
    FeeCapKeeper,
}

impl OperatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::HotStandby => "hot_standby",
            Self::ColdStandby => "cold_standby",
            Self::Emergency => "emergency",
            Self::Watchtower => "watchtower",
            Self::MempoolKeyholder => "mempool_keyholder",
            Self::FeeCapKeeper => "fee_cap_keeper",
        }
    }

    pub fn can_propose(self) -> bool {
        matches!(self, Self::Primary | Self::HotStandby | Self::Emergency)
    }

    pub fn priority_bonus(self) -> u64 {
        match self {
            Self::Primary => 250,
            Self::HotStandby => 200,
            Self::Emergency => 175,
            Self::MempoolKeyholder => 90,
            Self::FeeCapKeeper => 70,
            Self::Watchtower => 50,
            Self::ColdStandby => 25,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    Active,
    Warm,
    Cooling,
    Suspect,
    Missing,
    Draining,
    Retired,
    Slashed,
}

impl OperatorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Warm => "warm",
            Self::Cooling => "cooling",
            Self::Suspect => "suspect",
            Self::Missing => "missing",
            Self::Draining => "draining",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn is_available(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Warm | Self::Cooling | Self::Draining
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    UserFlow,
    ContractFlow,
    ExitFlow,
    ForcedInclusion,
    MakerFlow,
    WatchtowerFlow,
    EmergencyFlow,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserFlow => "user_flow",
            Self::ContractFlow => "contract_flow",
            Self::ExitFlow => "exit_flow",
            Self::ForcedInclusion => "forced_inclusion",
            Self::MakerFlow => "maker_flow",
            Self::WatchtowerFlow => "watchtower_flow",
            Self::EmergencyFlow => "emergency_flow",
        }
    }

    pub fn drain_priority(self) -> u64 {
        match self {
            Self::EmergencyFlow => 10_000,
            Self::ForcedInclusion => 9_600,
            Self::ExitFlow => 9_100,
            Self::ContractFlow => 8_700,
            Self::UserFlow => 8_400,
            Self::MakerFlow => 7_900,
            Self::WatchtowerFlow => 7_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Registered,
    Hot,
    Mirroring,
    FailingOver,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Hot => "hot",
            Self::Mirroring => "mirroring",
            Self::FailingOver => "failing_over",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_leases(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Hot | Self::Mirroring | Self::FailingOver
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Issued,
    Mirrored,
    Continued,
    Rebound,
    Settled,
    Expired,
    Revoked,
}

impl PreconfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Mirrored => "mirrored",
            Self::Continued => "continued",
            Self::Rebound => "rebound",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Proposed,
    Accepted,
    Transferred,
    Draining,
    Completed,
    Expired,
    Rejected,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::Transferred => "transferred",
            Self::Draining => "draining",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    Scheduled,
    MissedHeartbeat,
    LeaseExpired,
    Congestion,
    WatchtowerSignal,
    Emergency,
    ManualDevnet,
}

impl RotationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::MissedHeartbeat => "missed_heartbeat",
            Self::LeaseExpired => "lease_expired",
            Self::Congestion => "congestion",
            Self::WatchtowerSignal => "watchtower_signal",
            Self::Emergency => "emergency",
            Self::ManualDevnet => "manual_devnet",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainStatus {
    Planned,
    Admitted,
    Executing,
    Completed,
    Superseded,
    Cancelled,
}

impl DrainStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Admitted => "admitted",
            Self::Executing => "executing",
            Self::Completed => "completed",
            Self::Superseded => "superseded",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_preconfirmation_ms: u64,
    pub failover_grace_ms: u64,
    pub hot_standby_lanes: usize,
    pub rotation_window_slots: u64,
    pub lease_ttl_slots: u64,
    pub preconfirmation_ttl_slots: u64,
    pub drain_batch_limit: u64,
    pub max_user_fee_bps: u64,
    pub fee_cap_grace_slots: u64,
    pub telemetry_bucket_min_size: u64,
    pub max_operators: usize,
    pub max_lanes: usize,
    pub max_preconfirmations: usize,
    pub max_lease_transfers: usize,
    pub max_rotations: usize,
    pub max_drain_plans: usize,
    pub max_fee_caps: usize,
    pub max_telemetry: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            failover_grace_ms: DEFAULT_FAILOVER_GRACE_MS,
            hot_standby_lanes: DEFAULT_HOT_STANDBY_LANES,
            rotation_window_slots: DEFAULT_ROTATION_WINDOW_SLOTS,
            lease_ttl_slots: DEFAULT_LEASE_TTL_SLOTS,
            preconfirmation_ttl_slots: DEFAULT_PRECONFIRMATION_TTL_SLOTS,
            drain_batch_limit: DEFAULT_DRAIN_BATCH_LIMIT,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            fee_cap_grace_slots: DEFAULT_FEE_CAP_GRACE_SLOTS,
            telemetry_bucket_min_size: DEFAULT_TELEMETRY_BUCKET_MIN_SIZE,
            max_operators: DEFAULT_MAX_OPERATORS,
            max_lanes: DEFAULT_MAX_LANES,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
            max_lease_transfers: DEFAULT_MAX_LEASE_TRANSFERS,
            max_rotations: DEFAULT_MAX_ROTATIONS,
            max_drain_plans: DEFAULT_MAX_DRAIN_PLANS,
            max_fee_caps: DEFAULT_MAX_FEE_CAPS,
            max_telemetry: DEFAULT_MAX_TELEMETRY,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub operators_registered: u64,
    pub lanes_registered: u64,
    pub hot_standby_promotions: u64,
    pub preconfirmations_recorded: u64,
    pub preconfirmations_continued: u64,
    pub preconfirmations_rebound: u64,
    pub lease_transfers_recorded: u64,
    pub lease_transfers_completed: u64,
    pub rotations_recorded: u64,
    pub emergency_rotations: u64,
    pub drain_plans_recorded: u64,
    pub drain_items_planned: u64,
    pub drain_items_completed: u64,
    pub fee_caps_preserved: u64,
    pub fee_cap_rejections: u64,
    pub telemetry_samples_recorded: u64,
    pub redacted_telemetry_samples: u64,
    pub events_recorded: u64,
    pub rejected_requests: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub operators_root: String,
    pub lanes_root: String,
    pub preconfirmations_root: String,
    pub lease_transfers_root: String,
    pub rotations_root: String,
    pub drain_plans_root: String,
    pub fee_caps_root: String,
    pub telemetry_root: String,
    pub events_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorRecord {
    pub operator_id: String,
    pub role: OperatorRole,
    pub status: OperatorStatus,
    pub pq_auth_root: String,
    pub stake_weight: u64,
    pub privacy_set_size: u64,
    pub last_heartbeat_slot: u64,
    pub active_lane_ids: BTreeSet<String>,
    pub redacted_label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterOperatorRequest {
    pub operator_id: String,
    pub role: OperatorRole,
    pub pq_auth_root: String,
    pub stake_weight: u64,
    pub privacy_set_size: u64,
    pub heartbeat_slot: u64,
    pub redacted_label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneRecord {
    pub lane_id: String,
    pub lane_kind: LaneKind,
    pub status: LaneStatus,
    pub primary_operator_id: String,
    pub standby_operator_ids: Vec<String>,
    pub encrypted_mempool_root: String,
    pub preconfirmation_cursor: u64,
    pub backlog_items: u64,
    pub backlog_bytes: u64,
    pub fee_cap_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterLaneRequest {
    pub lane_id: String,
    pub lane_kind: LaneKind,
    pub primary_operator_id: String,
    pub standby_operator_ids: Vec<String>,
    pub encrypted_mempool_root: String,
    pub preconfirmation_cursor: u64,
    pub backlog_items: u64,
    pub backlog_bytes: u64,
    pub fee_cap_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationRecord {
    pub preconfirmation_id: String,
    pub lane_id: String,
    pub issuer_operator_id: String,
    pub successor_operator_id: String,
    pub status: PreconfirmationStatus,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub confidential_receipt_root: String,
    pub continuity_root: String,
    pub fee_cap_bps: u64,
    pub cursor_before: u64,
    pub cursor_after: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordPreconfirmationRequest {
    pub preconfirmation_id: String,
    pub lane_id: String,
    pub issuer_operator_id: String,
    pub successor_operator_id: String,
    pub slot: u64,
    pub confidential_receipt_root: String,
    pub continuity_root: String,
    pub fee_cap_bps: u64,
    pub cursor_after: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseTransferRecord {
    pub transfer_id: String,
    pub lane_id: String,
    pub from_operator_id: String,
    pub to_operator_id: String,
    pub status: LeaseStatus,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub encrypted_mempool_root_before: String,
    pub encrypted_mempool_root_after: String,
    pub lease_auth_root: String,
    pub backlog_items: u64,
    pub preserved_fee_cap_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordLeaseTransferRequest {
    pub transfer_id: String,
    pub lane_id: String,
    pub from_operator_id: String,
    pub to_operator_id: String,
    pub slot: u64,
    pub encrypted_mempool_root_after: String,
    pub lease_auth_root: String,
    pub backlog_items: u64,
    pub preserved_fee_cap_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationRecord {
    pub rotation_id: String,
    pub lane_id: String,
    pub previous_operator_id: String,
    pub next_operator_id: String,
    pub reason: RotationReason,
    pub slot: u64,
    pub pq_rotation_root: String,
    pub preconfirmation_cursor: u64,
    pub inherited_fee_cap_bps: u64,
    pub continuity_gap_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordRotationRequest {
    pub rotation_id: String,
    pub lane_id: String,
    pub previous_operator_id: String,
    pub next_operator_id: String,
    pub reason: RotationReason,
    pub slot: u64,
    pub pq_rotation_root: String,
    pub continuity_gap_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrainPlanRecord {
    pub drain_plan_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub status: DrainStatus,
    pub slot: u64,
    pub drain_until_slot: u64,
    pub batch_limit: u64,
    pub planned_items: u64,
    pub completed_items: u64,
    pub encrypted_backlog_root: String,
    pub public_priority_score: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordDrainPlanRequest {
    pub drain_plan_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub slot: u64,
    pub drain_until_slot: u64,
    pub batch_limit: u64,
    pub planned_items: u64,
    pub encrypted_backlog_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCapRecord {
    pub fee_cap_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub user_cap_commitment_root: String,
    pub preserved_across_failover: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordFeeCapRequest {
    pub fee_cap_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub slot: u64,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub user_cap_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TelemetryRecord {
    pub telemetry_id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub slot_bucket: u64,
    pub privacy_bucket_size: u64,
    pub redacted_operator_label: String,
    pub latency_bucket_ms: u64,
    pub backlog_bucket_items: u64,
    pub failover_count_bucket: u64,
    pub encrypted_detail_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordTelemetryRequest {
    pub telemetry_id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub slot_bucket: u64,
    pub privacy_bucket_size: u64,
    pub redacted_operator_label: String,
    pub latency_bucket_ms: u64,
    pub backlog_bucket_items: u64,
    pub failover_count_bucket: u64,
    pub encrypted_detail_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    pub event_id: u64,
    pub slot: u64,
    pub kind: String,
    pub subject_id: String,
    pub root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailoverReadinessRecord {
    pub lane_id: String,
    pub primary_operator_id: String,
    pub preferred_successor_operator_id: String,
    pub available_standby_count: u64,
    pub preconfirmation_cursor: u64,
    pub backlog_items: u64,
    pub preserved_fee_cap_bps: u64,
    pub estimated_continuity_gap_ms: u64,
    pub ready: bool,
    pub readiness_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContinuityWindowRecord {
    pub lane_id: String,
    pub open_preconfirmations: u64,
    pub mirrored_preconfirmations: u64,
    pub expiring_preconfirmations: u64,
    pub highest_cursor_after: u64,
    pub lowest_fee_cap_bps: u64,
    pub continuity_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorScoreRecord {
    pub operator_id: String,
    pub role: OperatorRole,
    pub status: OperatorStatus,
    pub lane_count: u64,
    pub stake_weight: u64,
    pub privacy_set_size: u64,
    pub proposer_score: u64,
    pub redacted_label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BacklogPressureRecord {
    pub lane_id: String,
    pub lane_kind: LaneKind,
    pub status: LaneStatus,
    pub backlog_items: u64,
    pub backlog_bytes: u64,
    pub public_priority_score: u64,
    pub suggested_batch_limit: u64,
    pub drain_needed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub chain_id: String,
    pub height: u64,
    pub current_slot: u64,
    pub active_operator_id: String,
    pub operators: BTreeMap<String, OperatorRecord>,
    pub lanes: BTreeMap<String, LaneRecord>,
    pub preconfirmations: BTreeMap<String, PreconfirmationRecord>,
    pub lease_transfers: BTreeMap<String, LeaseTransferRecord>,
    pub rotations: BTreeMap<String, RotationRecord>,
    pub drain_plans: BTreeMap<String, DrainPlanRecord>,
    pub fee_caps: BTreeMap<String, FeeCapRecord>,
    pub telemetry: BTreeMap<String, TelemetryRecord>,
    pub event_log: VecDeque<EventRecord>,
    pub counters: Counters,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            chain_id: CHAIN_ID.to_string(),
            height: DEVNET_HEIGHT,
            current_slot: 0,
            active_operator_id: String::new(),
            operators: BTreeMap::new(),
            lanes: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            lease_transfers: BTreeMap::new(),
            rotations: BTreeMap::new(),
            drain_plans: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            telemetry: BTreeMap::new(),
            event_log: VecDeque::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.recompute_roots();
        state
    }

    pub fn register_operator(&mut self, request: RegisterOperatorRequest) -> Result<()> {
        self.validate_id("operator_id", &request.operator_id)?;
        self.validate_root("pq_auth_root", &request.pq_auth_root)?;
        if self.operators.len() >= self.config.max_operators
            && !self.operators.contains_key(&request.operator_id)
        {
            return self.reject("operator capacity exceeded");
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return self.reject("operator privacy set too small");
        }
        let operator = OperatorRecord {
            operator_id: request.operator_id.clone(),
            role: request.role,
            status: if request.role == OperatorRole::Primary {
                OperatorStatus::Active
            } else {
                OperatorStatus::Warm
            },
            pq_auth_root: request.pq_auth_root,
            stake_weight: request.stake_weight,
            privacy_set_size: request.privacy_set_size,
            last_heartbeat_slot: request.heartbeat_slot,
            active_lane_ids: BTreeSet::new(),
            redacted_label: request.redacted_label,
        };
        if self.active_operator_id.is_empty() && operator.role.can_propose() {
            self.active_operator_id = operator.operator_id.clone();
        }
        self.operators
            .insert(operator.operator_id.clone(), operator.clone());
        self.counters.operators_registered = self.counters.operators_registered.saturating_add(1);
        self.record_event(
            request.heartbeat_slot,
            "operator_registered",
            &operator.operator_id,
            &operator_root(&operator),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn register_lane(&mut self, request: RegisterLaneRequest) -> Result<()> {
        self.validate_id("lane_id", &request.lane_id)?;
        self.validate_root("encrypted_mempool_root", &request.encrypted_mempool_root)?;
        if self.lanes.len() >= self.config.max_lanes && !self.lanes.contains_key(&request.lane_id) {
            return self.reject("lane capacity exceeded");
        }
        if request.fee_cap_bps > self.config.max_user_fee_bps {
            self.counters.fee_cap_rejections = self.counters.fee_cap_rejections.saturating_add(1);
            return self.reject("lane fee cap exceeds configured maximum");
        }
        if !self.operator_can_propose(&request.primary_operator_id) {
            return self.reject("primary operator cannot propose");
        }
        let mut standby_operator_ids = Vec::new();
        for operator_id in request.standby_operator_ids.iter() {
            if self.operator_can_propose(operator_id)
                && standby_operator_ids.len() < self.config.hot_standby_lanes
            {
                standby_operator_ids.push(operator_id.clone());
            }
        }
        let lane = LaneRecord {
            lane_id: request.lane_id.clone(),
            lane_kind: request.lane_kind,
            status: LaneStatus::Hot,
            primary_operator_id: request.primary_operator_id.clone(),
            standby_operator_ids,
            encrypted_mempool_root: request.encrypted_mempool_root,
            preconfirmation_cursor: request.preconfirmation_cursor,
            backlog_items: request.backlog_items,
            backlog_bytes: request.backlog_bytes,
            fee_cap_bps: request.fee_cap_bps,
        };
        self.attach_lane_to_operator(&lane.primary_operator_id, &lane.lane_id);
        for standby_id in lane.standby_operator_ids.iter() {
            self.attach_lane_to_operator(standby_id, &lane.lane_id);
        }
        self.lanes.insert(lane.lane_id.clone(), lane.clone());
        self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        self.record_event(
            self.current_slot,
            "lane_registered",
            &lane.lane_id,
            &lane_root(&lane),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn record_preconfirmation(&mut self, request: RecordPreconfirmationRequest) -> Result<()> {
        self.validate_id("preconfirmation_id", &request.preconfirmation_id)?;
        self.validate_root(
            "confidential_receipt_root",
            &request.confidential_receipt_root,
        )?;
        self.validate_root("continuity_root", &request.continuity_root)?;
        if self.preconfirmations.len() >= self.config.max_preconfirmations
            && !self
                .preconfirmations
                .contains_key(&request.preconfirmation_id)
        {
            return self.reject("preconfirmation capacity exceeded");
        }
        if request.fee_cap_bps > self.config.max_user_fee_bps {
            self.counters.fee_cap_rejections = self.counters.fee_cap_rejections.saturating_add(1);
            return self.reject("preconfirmation fee cap exceeds configured maximum");
        }
        let lane = self
            .lanes
            .get(&request.lane_id)
            .cloned()
            .ok_or_else(|| "unknown lane".to_string())?;
        if !lane.status.accepts_leases() {
            return self.reject("lane does not accept preconfirmations");
        }
        if !self.operator_can_propose(&request.issuer_operator_id) {
            return self.reject("issuer operator cannot propose");
        }
        let cursor_before = lane.preconfirmation_cursor;
        let cursor_after = if request.cursor_after > cursor_before {
            request.cursor_after
        } else {
            cursor_before.saturating_add(1)
        };
        let status = if request.successor_operator_id == request.issuer_operator_id {
            PreconfirmationStatus::Issued
        } else {
            PreconfirmationStatus::Mirrored
        };
        let record = PreconfirmationRecord {
            preconfirmation_id: request.preconfirmation_id.clone(),
            lane_id: request.lane_id.clone(),
            issuer_operator_id: request.issuer_operator_id,
            successor_operator_id: request.successor_operator_id,
            status,
            slot: request.slot,
            expires_at_slot: request
                .slot
                .saturating_add(self.config.preconfirmation_ttl_slots),
            confidential_receipt_root: request.confidential_receipt_root,
            continuity_root: request.continuity_root,
            fee_cap_bps: request.fee_cap_bps,
            cursor_before,
            cursor_after,
        };
        if let Some(lane_mut) = self.lanes.get_mut(&record.lane_id) {
            lane_mut.preconfirmation_cursor = cursor_after;
            lane_mut.fee_cap_bps = lane_mut.fee_cap_bps.min(record.fee_cap_bps);
        }
        self.preconfirmations
            .insert(record.preconfirmation_id.clone(), record.clone());
        self.counters.preconfirmations_recorded =
            self.counters.preconfirmations_recorded.saturating_add(1);
        if status == PreconfirmationStatus::Mirrored {
            self.counters.preconfirmations_continued =
                self.counters.preconfirmations_continued.saturating_add(1);
        }
        self.record_event(
            record.slot,
            "preconfirmation_recorded",
            &record.preconfirmation_id,
            &preconfirmation_root(&record),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn record_lease_transfer(&mut self, request: RecordLeaseTransferRequest) -> Result<()> {
        self.validate_id("transfer_id", &request.transfer_id)?;
        self.validate_root(
            "encrypted_mempool_root_after",
            &request.encrypted_mempool_root_after,
        )?;
        self.validate_root("lease_auth_root", &request.lease_auth_root)?;
        if self.lease_transfers.len() >= self.config.max_lease_transfers
            && !self.lease_transfers.contains_key(&request.transfer_id)
        {
            return self.reject("lease transfer capacity exceeded");
        }
        if request.preserved_fee_cap_bps > self.config.max_user_fee_bps {
            self.counters.fee_cap_rejections = self.counters.fee_cap_rejections.saturating_add(1);
            return self.reject("lease transfer fee cap exceeds configured maximum");
        }
        let lane = self
            .lanes
            .get(&request.lane_id)
            .cloned()
            .ok_or_else(|| "unknown lane".to_string())?;
        if !self.operator_can_propose(&request.to_operator_id) {
            return self.reject("target operator cannot propose");
        }
        let record = LeaseTransferRecord {
            transfer_id: request.transfer_id.clone(),
            lane_id: request.lane_id.clone(),
            from_operator_id: request.from_operator_id,
            to_operator_id: request.to_operator_id.clone(),
            status: LeaseStatus::Transferred,
            slot: request.slot,
            expires_at_slot: request.slot.saturating_add(self.config.lease_ttl_slots),
            encrypted_mempool_root_before: lane.encrypted_mempool_root,
            encrypted_mempool_root_after: request.encrypted_mempool_root_after,
            lease_auth_root: request.lease_auth_root,
            backlog_items: request.backlog_items,
            preserved_fee_cap_bps: request.preserved_fee_cap_bps,
        };
        if let Some(lane_mut) = self.lanes.get_mut(&record.lane_id) {
            lane_mut.primary_operator_id = record.to_operator_id.clone();
            lane_mut.status = LaneStatus::FailingOver;
            lane_mut.encrypted_mempool_root = record.encrypted_mempool_root_after.clone();
            lane_mut.backlog_items = request.backlog_items;
            lane_mut.fee_cap_bps = lane_mut.fee_cap_bps.min(record.preserved_fee_cap_bps);
        }
        self.attach_lane_to_operator(&record.to_operator_id, &record.lane_id);
        self.lease_transfers
            .insert(record.transfer_id.clone(), record.clone());
        self.counters.lease_transfers_recorded =
            self.counters.lease_transfers_recorded.saturating_add(1);
        self.counters.lease_transfers_completed =
            self.counters.lease_transfers_completed.saturating_add(1);
        self.counters.fee_caps_preserved = self.counters.fee_caps_preserved.saturating_add(1);
        self.record_event(
            record.slot,
            "lease_transfer_recorded",
            &record.transfer_id,
            &lease_transfer_root(&record),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn record_rotation(&mut self, request: RecordRotationRequest) -> Result<()> {
        self.validate_id("rotation_id", &request.rotation_id)?;
        self.validate_root("pq_rotation_root", &request.pq_rotation_root)?;
        if self.rotations.len() >= self.config.max_rotations
            && !self.rotations.contains_key(&request.rotation_id)
        {
            return self.reject("rotation capacity exceeded");
        }
        if !self.operator_can_propose(&request.next_operator_id) {
            return self.reject("next operator cannot propose");
        }
        let lane = self
            .lanes
            .get(&request.lane_id)
            .cloned()
            .ok_or_else(|| "unknown lane".to_string())?;
        let record = RotationRecord {
            rotation_id: request.rotation_id.clone(),
            lane_id: request.lane_id.clone(),
            previous_operator_id: request.previous_operator_id,
            next_operator_id: request.next_operator_id.clone(),
            reason: request.reason,
            slot: request.slot,
            pq_rotation_root: request.pq_rotation_root,
            preconfirmation_cursor: lane.preconfirmation_cursor,
            inherited_fee_cap_bps: lane.fee_cap_bps,
            continuity_gap_ms: request.continuity_gap_ms,
        };
        if let Some(lane_mut) = self.lanes.get_mut(&record.lane_id) {
            lane_mut.primary_operator_id = record.next_operator_id.clone();
            lane_mut.status = LaneStatus::Mirroring;
        }
        if self.active_operator_id == record.previous_operator_id
            || self.active_operator_id.is_empty()
        {
            self.active_operator_id = record.next_operator_id.clone();
        }
        self.attach_lane_to_operator(&record.next_operator_id, &record.lane_id);
        self.rotations
            .insert(record.rotation_id.clone(), record.clone());
        self.counters.rotations_recorded = self.counters.rotations_recorded.saturating_add(1);
        if record.reason == RotationReason::Emergency {
            self.counters.emergency_rotations = self.counters.emergency_rotations.saturating_add(1);
        }
        if request.continuity_gap_ms <= self.config.failover_grace_ms {
            self.counters.hot_standby_promotions =
                self.counters.hot_standby_promotions.saturating_add(1);
        }
        self.record_event(
            record.slot,
            "rotation_recorded",
            &record.rotation_id,
            &rotation_root(&record),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn record_drain_plan(&mut self, request: RecordDrainPlanRequest) -> Result<()> {
        self.validate_id("drain_plan_id", &request.drain_plan_id)?;
        self.validate_root("encrypted_backlog_root", &request.encrypted_backlog_root)?;
        if self.drain_plans.len() >= self.config.max_drain_plans
            && !self.drain_plans.contains_key(&request.drain_plan_id)
        {
            return self.reject("drain plan capacity exceeded");
        }
        let lane = self
            .lanes
            .get(&request.lane_id)
            .cloned()
            .ok_or_else(|| "unknown lane".to_string())?;
        let batch_limit = request.batch_limit.min(self.config.drain_batch_limit);
        let public_priority_score = lane
            .lane_kind
            .drain_priority()
            .saturating_add(lane.backlog_items.min(10_000));
        let record = DrainPlanRecord {
            drain_plan_id: request.drain_plan_id.clone(),
            lane_id: request.lane_id.clone(),
            operator_id: request.operator_id,
            status: DrainStatus::Planned,
            slot: request.slot,
            drain_until_slot: request.drain_until_slot,
            batch_limit,
            planned_items: request.planned_items,
            completed_items: 0,
            encrypted_backlog_root: request.encrypted_backlog_root,
            public_priority_score,
        };
        if let Some(lane_mut) = self.lanes.get_mut(&record.lane_id) {
            lane_mut.status = LaneStatus::Draining;
            lane_mut.backlog_items = lane_mut.backlog_items.max(record.planned_items);
        }
        self.drain_plans
            .insert(record.drain_plan_id.clone(), record.clone());
        self.counters.drain_plans_recorded = self.counters.drain_plans_recorded.saturating_add(1);
        self.counters.drain_items_planned = self
            .counters
            .drain_items_planned
            .saturating_add(record.planned_items);
        self.record_event(
            record.slot,
            "drain_plan_recorded",
            &record.drain_plan_id,
            &drain_plan_root(&record),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn complete_drain_batch(
        &mut self,
        drain_plan_id: &str,
        completed_items: u64,
    ) -> Result<()> {
        let mut lane_id = String::new();
        if let Some(plan) = self.drain_plans.get_mut(drain_plan_id) {
            plan.completed_items = plan
                .completed_items
                .saturating_add(completed_items)
                .min(plan.planned_items);
            plan.status = if plan.completed_items >= plan.planned_items {
                DrainStatus::Completed
            } else {
                DrainStatus::Executing
            };
            lane_id = plan.lane_id.clone();
        } else {
            return self.reject("unknown drain plan");
        }
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.backlog_items = lane.backlog_items.saturating_sub(completed_items);
            if lane.backlog_items == 0 {
                lane.status = LaneStatus::Hot;
            }
        }
        self.counters.drain_items_completed = self
            .counters
            .drain_items_completed
            .saturating_add(completed_items);
        let root = self
            .drain_plans
            .get(drain_plan_id)
            .map(drain_plan_root)
            .unwrap_or_else(String::new);
        self.record_event(
            self.current_slot,
            "drain_batch_completed",
            drain_plan_id,
            &root,
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn record_fee_cap(&mut self, request: RecordFeeCapRequest) -> Result<()> {
        self.validate_id("fee_cap_id", &request.fee_cap_id)?;
        self.validate_root(
            "user_cap_commitment_root",
            &request.user_cap_commitment_root,
        )?;
        if self.fee_caps.len() >= self.config.max_fee_caps
            && !self.fee_caps.contains_key(&request.fee_cap_id)
        {
            return self.reject("fee cap capacity exceeded");
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            self.counters.fee_cap_rejections = self.counters.fee_cap_rejections.saturating_add(1);
            return self.reject("fee cap exceeds configured maximum");
        }
        let record = FeeCapRecord {
            fee_cap_id: request.fee_cap_id.clone(),
            lane_id: request.lane_id,
            operator_id: request.operator_id,
            slot: request.slot,
            expires_at_slot: request.slot.saturating_add(self.config.fee_cap_grace_slots),
            fee_asset_id: request.fee_asset_id,
            max_fee_bps: request.max_fee_bps,
            user_cap_commitment_root: request.user_cap_commitment_root,
            preserved_across_failover: true,
        };
        if let Some(lane) = self.lanes.get_mut(&record.lane_id) {
            lane.fee_cap_bps = lane.fee_cap_bps.min(record.max_fee_bps);
        }
        self.fee_caps
            .insert(record.fee_cap_id.clone(), record.clone());
        self.counters.fee_caps_preserved = self.counters.fee_caps_preserved.saturating_add(1);
        self.record_event(
            record.slot,
            "fee_cap_recorded",
            &record.fee_cap_id,
            &fee_cap_root(&record),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn record_telemetry(&mut self, request: RecordTelemetryRequest) -> Result<()> {
        self.validate_id("telemetry_id", &request.telemetry_id)?;
        self.validate_root("encrypted_detail_root", &request.encrypted_detail_root)?;
        if self.telemetry.len() >= self.config.max_telemetry
            && !self.telemetry.contains_key(&request.telemetry_id)
        {
            return self.reject("telemetry capacity exceeded");
        }
        if request.privacy_bucket_size < self.config.telemetry_bucket_min_size {
            return self.reject("telemetry bucket too small");
        }
        let record = TelemetryRecord {
            telemetry_id: request.telemetry_id,
            operator_id: request.operator_id,
            lane_id: request.lane_id,
            slot_bucket: request.slot_bucket,
            privacy_bucket_size: request.privacy_bucket_size,
            redacted_operator_label: request.redacted_operator_label,
            latency_bucket_ms: round_bucket(request.latency_bucket_ms, 25),
            backlog_bucket_items: round_bucket(request.backlog_bucket_items, 32),
            failover_count_bucket: request.failover_count_bucket,
            encrypted_detail_root: request.encrypted_detail_root,
        };
        self.telemetry
            .insert(record.telemetry_id.clone(), record.clone());
        self.counters.telemetry_samples_recorded =
            self.counters.telemetry_samples_recorded.saturating_add(1);
        self.counters.redacted_telemetry_samples =
            self.counters.redacted_telemetry_samples.saturating_add(1);
        self.record_event(
            record.slot_bucket,
            "telemetry_recorded",
            &record.telemetry_id,
            &telemetry_root(&record),
        );
        self.recompute_roots();
        Ok(())
    }

    pub fn advance_slot(&mut self, slot: u64) {
        self.current_slot = self.current_slot.max(slot);
        self.expire_records();
        self.recompute_roots();
    }

    pub fn plan_fast_failover(
        &self,
        lane_id: &str,
        reason: RotationReason,
        slot: u64,
    ) -> Option<RecordRotationRequest> {
        let lane = self.lanes.get(lane_id)?;
        let next = self.next_standby_for_lane(lane)?;
        Some(RecordRotationRequest {
            rotation_id: deterministic_id(
                "rotation",
                &[
                    lane_id,
                    &lane.primary_operator_id,
                    &next,
                    &slot.to_string(),
                    reason.as_str(),
                ],
            ),
            lane_id: lane_id.to_string(),
            previous_operator_id: lane.primary_operator_id.clone(),
            next_operator_id: next,
            reason,
            slot,
            pq_rotation_root: domain_hash(
                PROPOSER_ROTATION_SUITE,
                &[
                    hp(lane_id),
                    hp(lane.primary_operator_id.as_str()),
                    hp(slot.to_string()),
                ],
            ),
            continuity_gap_ms: self.config.target_preconfirmation_ms,
        })
    }

    pub fn backlog_drain_queue(&self) -> Vec<DrainPlanRecord> {
        let mut plans: Vec<DrainPlanRecord> = self.drain_plans.values().cloned().collect();
        plans.sort_by(|a, b| {
            b.public_priority_score
                .cmp(&a.public_priority_score)
                .then_with(|| a.slot.cmp(&b.slot))
                .then_with(|| a.drain_plan_id.cmp(&b.drain_plan_id))
        });
        plans
    }

    pub fn failover_readiness(&self, lane_id: &str) -> Option<FailoverReadinessRecord> {
        let lane = self.lanes.get(lane_id)?;
        let preferred_successor_operator_id =
            self.next_standby_for_lane(lane).unwrap_or_else(String::new);
        let available_standby_count = lane
            .standby_operator_ids
            .iter()
            .filter(|operator_id| self.operator_can_propose(operator_id))
            .count() as u64;
        let estimated_continuity_gap_ms = if preferred_successor_operator_id.is_empty() {
            self.config
                .failover_grace_ms
                .saturating_add(self.config.target_preconfirmation_ms)
        } else {
            self.config.target_preconfirmation_ms
        };
        let ready = !preferred_successor_operator_id.is_empty()
            && lane.status.accepts_leases()
            && lane.fee_cap_bps <= self.config.max_user_fee_bps
            && estimated_continuity_gap_ms <= self.config.failover_grace_ms;
        let readiness_root = domain_hash(
            "failover_readiness_record",
            &[
                hp(lane.lane_id.as_str()),
                hp(lane.primary_operator_id.as_str()),
                hp(preferred_successor_operator_id.as_str()),
                hp(available_standby_count.to_string()),
                hp(lane.preconfirmation_cursor.to_string()),
                hp(lane.backlog_items.to_string()),
                hp(lane.fee_cap_bps.to_string()),
                hp(estimated_continuity_gap_ms.to_string()),
                hp(ready.to_string()),
            ],
        );
        Some(FailoverReadinessRecord {
            lane_id: lane.lane_id.clone(),
            primary_operator_id: lane.primary_operator_id.clone(),
            preferred_successor_operator_id,
            available_standby_count,
            preconfirmation_cursor: lane.preconfirmation_cursor,
            backlog_items: lane.backlog_items,
            preserved_fee_cap_bps: lane.fee_cap_bps,
            estimated_continuity_gap_ms,
            ready,
            readiness_root,
        })
    }

    pub fn continuity_window(
        &self,
        lane_id: &str,
        horizon_slot: u64,
    ) -> Option<ContinuityWindowRecord> {
        let lane = self.lanes.get(lane_id)?;
        let mut open_preconfirmations = 0_u64;
        let mut mirrored_preconfirmations = 0_u64;
        let mut expiring_preconfirmations = 0_u64;
        let mut highest_cursor_after = lane.preconfirmation_cursor;
        let mut lowest_fee_cap_bps = self.config.max_user_fee_bps;
        let mut leaf_parts = Vec::new();
        for record in self.preconfirmations.values() {
            if record.lane_id == lane_id {
                if matches!(
                    record.status,
                    PreconfirmationStatus::Issued
                        | PreconfirmationStatus::Mirrored
                        | PreconfirmationStatus::Continued
                        | PreconfirmationStatus::Rebound
                ) {
                    open_preconfirmations = open_preconfirmations.saturating_add(1);
                    highest_cursor_after = highest_cursor_after.max(record.cursor_after);
                    lowest_fee_cap_bps = lowest_fee_cap_bps.min(record.fee_cap_bps);
                    leaf_parts.push(hp(preconfirmation_root(record)));
                }
                if record.status == PreconfirmationStatus::Mirrored {
                    mirrored_preconfirmations = mirrored_preconfirmations.saturating_add(1);
                }
                if record.expires_at_slot <= horizon_slot {
                    expiring_preconfirmations = expiring_preconfirmations.saturating_add(1);
                }
            }
        }
        let continuity_root = domain_hash(
            "continuity_window_record",
            &[
                hp(lane_id),
                hp(open_preconfirmations.to_string()),
                hp(mirrored_preconfirmations.to_string()),
                hp(expiring_preconfirmations.to_string()),
                hp(highest_cursor_after.to_string()),
                hp(lowest_fee_cap_bps.to_string()),
                hp(merkle_root("continuity_window_leaves", leaf_parts).as_str()),
            ],
        );
        Some(ContinuityWindowRecord {
            lane_id: lane_id.to_string(),
            open_preconfirmations,
            mirrored_preconfirmations,
            expiring_preconfirmations,
            highest_cursor_after,
            lowest_fee_cap_bps,
            continuity_root,
        })
    }

    pub fn operator_scores(&self) -> Vec<OperatorScoreRecord> {
        let mut scores = self
            .operators
            .values()
            .map(|operator| {
                let lane_count = operator.active_lane_ids.len() as u64;
                let availability_bonus = if operator.status.is_available() {
                    1_000
                } else {
                    0
                };
                let proposer_score = operator
                    .stake_weight
                    .saturating_add(operator.role.priority_bonus())
                    .saturating_add(availability_bonus)
                    .saturating_add(
                        operator.privacy_set_size / self.config.min_privacy_set_size.max(1),
                    )
                    .saturating_sub(lane_count.saturating_mul(10));
                OperatorScoreRecord {
                    operator_id: operator.operator_id.clone(),
                    role: operator.role,
                    status: operator.status,
                    lane_count,
                    stake_weight: operator.stake_weight,
                    privacy_set_size: operator.privacy_set_size,
                    proposer_score,
                    redacted_label: operator.redacted_label.clone(),
                }
            })
            .collect::<Vec<OperatorScoreRecord>>();
        scores.sort_by(|a, b| {
            b.proposer_score
                .cmp(&a.proposer_score)
                .then_with(|| a.operator_id.cmp(&b.operator_id))
        });
        scores
    }

    pub fn backlog_pressure(&self) -> Vec<BacklogPressureRecord> {
        let mut pressure = self
            .lanes
            .values()
            .map(|lane| {
                let public_priority_score = lane
                    .lane_kind
                    .drain_priority()
                    .saturating_add(lane.backlog_items.min(10_000));
                let suggested_batch_limit = lane.backlog_items.min(self.config.drain_batch_limit);
                BacklogPressureRecord {
                    lane_id: lane.lane_id.clone(),
                    lane_kind: lane.lane_kind,
                    status: lane.status,
                    backlog_items: lane.backlog_items,
                    backlog_bytes: lane.backlog_bytes,
                    public_priority_score,
                    suggested_batch_limit,
                    drain_needed: lane.backlog_items > self.config.drain_batch_limit
                        || lane.status == LaneStatus::Draining,
                }
            })
            .collect::<Vec<BacklogPressureRecord>>();
        pressure.sort_by(|a, b| {
            b.public_priority_score
                .cmp(&a.public_priority_score)
                .then_with(|| a.lane_id.cmp(&b.lane_id))
        });
        pressure
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn reject<T>(&mut self, reason: &str) -> Result<T> {
        self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
        Err(reason.to_string())
    }

    fn validate_id(&mut self, label: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            return self.reject(&format!("{label} is empty"));
        }
        if value.len() > 160 {
            return self.reject(&format!("{label} is too long"));
        }
        Ok(())
    }

    fn validate_root(&mut self, label: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            return self.reject(&format!("{label} is empty"));
        }
        if value.len() > 256 {
            return self.reject(&format!("{label} is too long"));
        }
        Ok(())
    }

    fn operator_can_propose(&self, operator_id: &str) -> bool {
        self.operators
            .get(operator_id)
            .map(|operator| operator.role.can_propose() && operator.status.is_available())
            .unwrap_or(false)
    }

    fn next_standby_for_lane(&self, lane: &LaneRecord) -> Option<String> {
        for operator_id in lane.standby_operator_ids.iter() {
            if self.operator_can_propose(operator_id) {
                return Some(operator_id.clone());
            }
        }
        for (operator_id, operator) in self.operators.iter() {
            if operator_id != &lane.primary_operator_id
                && operator.role.can_propose()
                && operator.status.is_available()
            {
                return Some(operator_id.clone());
            }
        }
        None
    }

    fn attach_lane_to_operator(&mut self, operator_id: &str, lane_id: &str) {
        if let Some(operator) = self.operators.get_mut(operator_id) {
            operator.active_lane_ids.insert(lane_id.to_string());
        }
    }

    fn expire_records(&mut self) {
        for preconfirmation in self.preconfirmations.values_mut() {
            if preconfirmation.expires_at_slot < self.current_slot
                && matches!(
                    preconfirmation.status,
                    PreconfirmationStatus::Issued
                        | PreconfirmationStatus::Mirrored
                        | PreconfirmationStatus::Continued
                        | PreconfirmationStatus::Rebound
                )
            {
                preconfirmation.status = PreconfirmationStatus::Expired;
            }
        }
        for transfer in self.lease_transfers.values_mut() {
            if transfer.expires_at_slot < self.current_slot
                && matches!(
                    transfer.status,
                    LeaseStatus::Proposed | LeaseStatus::Accepted | LeaseStatus::Transferred
                )
            {
                transfer.status = LeaseStatus::Expired;
            }
        }
    }

    fn record_event(&mut self, slot: u64, kind: &str, subject_id: &str, root: &str) {
        if self.event_log.len() >= self.config.max_events {
            self.event_log.pop_front();
        }
        let event = EventRecord {
            event_id: self.counters.events_recorded.saturating_add(1),
            slot,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            root: root.to_string(),
        };
        self.event_log.push_back(event);
        self.counters.events_recorded = self.counters.events_recorded.saturating_add(1);
    }

    fn recompute_roots(&mut self) {
        let operators_root = merkle_map_root(
            "operators",
            self.operators
                .iter()
                .map(|(id, record)| (id.as_str(), operator_root(record))),
        );
        let lanes_root = merkle_map_root(
            "lanes",
            self.lanes
                .iter()
                .map(|(id, record)| (id.as_str(), lane_root(record))),
        );
        let preconfirmations_root = merkle_map_root(
            "preconfirmations",
            self.preconfirmations
                .iter()
                .map(|(id, record)| (id.as_str(), preconfirmation_root(record))),
        );
        let lease_transfers_root = merkle_map_root(
            "lease_transfers",
            self.lease_transfers
                .iter()
                .map(|(id, record)| (id.as_str(), lease_transfer_root(record))),
        );
        let rotations_root = merkle_map_root(
            "rotations",
            self.rotations
                .iter()
                .map(|(id, record)| (id.as_str(), rotation_root(record))),
        );
        let drain_plans_root = merkle_map_root(
            "drain_plans",
            self.drain_plans
                .iter()
                .map(|(id, record)| (id.as_str(), drain_plan_root(record))),
        );
        let fee_caps_root = merkle_map_root(
            "fee_caps",
            self.fee_caps
                .iter()
                .map(|(id, record)| (id.as_str(), fee_cap_root(record))),
        );
        let telemetry_root = merkle_map_root(
            "telemetry",
            self.telemetry
                .iter()
                .map(|(id, record)| (id.as_str(), telemetry_root(record))),
        );
        let events_root = merkle_root(
            "sequencer_failover_events",
            self.event_log
                .iter()
                .map(event_root)
                .map(hp)
                .collect::<Vec<HashPart>>(),
        );
        let state_root = domain_hash(
            PROTOCOL_VERSION,
            &[
                hp(self.chain_id.as_str()),
                hp(self.height.to_string()),
                hp(self.current_slot.to_string()),
                hp(self.active_operator_id.as_str()),
                hp(operators_root.as_str()),
                hp(lanes_root.as_str()),
                hp(preconfirmations_root.as_str()),
                hp(lease_transfers_root.as_str()),
                hp(rotations_root.as_str()),
                hp(drain_plans_root.as_str()),
                hp(fee_caps_root.as_str()),
                hp(telemetry_root.as_str()),
                hp(events_root.as_str()),
            ],
        );
        self.roots = Roots {
            operators_root,
            lanes_root,
            preconfirmations_root,
            lease_transfers_root,
            rotations_root,
            drain_plans_root,
            fee_caps_root,
            telemetry_root,
            events_root,
            state_root,
        };
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let operators = [
        ("sequencer-primary-devnet", OperatorRole::Primary, 40_000),
        ("sequencer-hot-standby-a", OperatorRole::HotStandby, 32_000),
        ("sequencer-hot-standby-b", OperatorRole::HotStandby, 31_000),
        (
            "sequencer-emergency-devnet",
            OperatorRole::Emergency,
            28_000,
        ),
        ("watchtower-devnet-a", OperatorRole::Watchtower, 12_000),
    ];
    for (idx, (operator_id, role, stake_weight)) in operators.iter().enumerate() {
        let request = RegisterOperatorRequest {
            operator_id: (*operator_id).to_string(),
            role: *role,
            pq_auth_root: domain_hash(PQ_AUTH_SUITE, &[hp(*operator_id), hp(idx.to_string())]),
            stake_weight: *stake_weight,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
            heartbeat_slot: idx as u64,
            redacted_label: format!("operator-bucket-{idx}"),
        };
        let _ = state.register_operator(request);
    }
    let lane_request = RegisterLaneRequest {
        lane_id: "private-fast-lane-0".to_string(),
        lane_kind: LaneKind::UserFlow,
        primary_operator_id: "sequencer-primary-devnet".to_string(),
        standby_operator_ids: vec![
            "sequencer-hot-standby-a".to_string(),
            "sequencer-hot-standby-b".to_string(),
            "sequencer-emergency-devnet".to_string(),
        ],
        encrypted_mempool_root: domain_hash(
            MEMPOOL_LEASE_TRANSFER_SUITE,
            &[hp("devnet-mempool-0")],
        ),
        preconfirmation_cursor: 100,
        backlog_items: 768,
        backlog_bytes: 1_572_864,
        fee_cap_bps: DEFAULT_MAX_USER_FEE_BPS,
    };
    let _ = state.register_lane(lane_request);
    let _ = state.record_fee_cap(RecordFeeCapRequest {
        fee_cap_id: "fee-cap-devnet-0".to_string(),
        lane_id: "private-fast-lane-0".to_string(),
        operator_id: "sequencer-primary-devnet".to_string(),
        slot: 1,
        fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
        max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        user_cap_commitment_root: domain_hash(
            FEE_CAP_PRESERVATION_SUITE,
            &[hp("devnet-fee-cap-0")],
        ),
    });
    let _ = state.record_preconfirmation(RecordPreconfirmationRequest {
        preconfirmation_id: "preconf-devnet-0".to_string(),
        lane_id: "private-fast-lane-0".to_string(),
        issuer_operator_id: "sequencer-primary-devnet".to_string(),
        successor_operator_id: "sequencer-hot-standby-a".to_string(),
        slot: 2,
        confidential_receipt_root: domain_hash(
            PRECONFIRMATION_CONTINUITY_SUITE,
            &[hp("receipt-0")],
        ),
        continuity_root: domain_hash(PRECONFIRMATION_CONTINUITY_SUITE, &[hp("continuity-0")]),
        fee_cap_bps: DEFAULT_MAX_USER_FEE_BPS,
        cursor_after: 101,
    });
    if let Some(rotation) =
        state.plan_fast_failover("private-fast-lane-0", RotationReason::MissedHeartbeat, 3)
    {
        let _ = state.record_rotation(rotation);
    }
    let _ = state.record_lease_transfer(RecordLeaseTransferRequest {
        transfer_id: "lease-transfer-devnet-0".to_string(),
        lane_id: "private-fast-lane-0".to_string(),
        from_operator_id: "sequencer-primary-devnet".to_string(),
        to_operator_id: "sequencer-hot-standby-a".to_string(),
        slot: 3,
        encrypted_mempool_root_after: domain_hash(
            MEMPOOL_LEASE_TRANSFER_SUITE,
            &[hp("devnet-mempool-1")],
        ),
        lease_auth_root: domain_hash(PQ_AUTH_SUITE, &[hp("lease-auth-0")]),
        backlog_items: 640,
        preserved_fee_cap_bps: DEFAULT_MAX_USER_FEE_BPS,
    });
    let _ = state.record_drain_plan(RecordDrainPlanRequest {
        drain_plan_id: "drain-devnet-0".to_string(),
        lane_id: "private-fast-lane-0".to_string(),
        operator_id: "sequencer-hot-standby-a".to_string(),
        slot: 4,
        drain_until_slot: 12,
        batch_limit: 512,
        planned_items: 640,
        encrypted_backlog_root: domain_hash(BACKLOG_DRAIN_SUITE, &[hp("devnet-backlog-0")]),
    });
    let _ = state.record_telemetry(RecordTelemetryRequest {
        telemetry_id: "telemetry-devnet-0".to_string(),
        operator_id: "sequencer-hot-standby-a".to_string(),
        lane_id: "private-fast-lane-0".to_string(),
        slot_bucket: 4,
        privacy_bucket_size: DEFAULT_TELEMETRY_BUCKET_MIN_SIZE,
        redacted_operator_label: "standby-bucket-a".to_string(),
        latency_bucket_ms: 113,
        backlog_bucket_items: 640,
        failover_count_bucket: 1,
        encrypted_detail_root: domain_hash(OPERATOR_TELEMETRY_SUITE, &[hp("telemetry-detail-0")]),
    });
    state.advance_slot(4);
    state
}

pub fn demo() -> Value {
    devnet().public_record()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "pq_auth_suite": PQ_AUTH_SUITE,
        "chain_id": state.chain_id,
        "height": state.height,
        "current_slot": state.current_slot,
        "active_operator_id": state.active_operator_id,
        "config": {
            "l2_network": state.config.l2_network,
            "monero_network": state.config.monero_network,
            "fee_asset_id": state.config.fee_asset_id,
            "min_pq_security_bits": state.config.min_pq_security_bits,
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "target_preconfirmation_ms": state.config.target_preconfirmation_ms,
            "failover_grace_ms": state.config.failover_grace_ms,
            "hot_standby_lanes": state.config.hot_standby_lanes,
            "rotation_window_slots": state.config.rotation_window_slots,
            "lease_ttl_slots": state.config.lease_ttl_slots,
            "preconfirmation_ttl_slots": state.config.preconfirmation_ttl_slots,
            "drain_batch_limit": state.config.drain_batch_limit,
            "max_user_fee_bps": state.config.max_user_fee_bps,
            "telemetry_bucket_min_size": state.config.telemetry_bucket_min_size,
        },
        "counters": state.counters,
        "roots": state.roots,
        "operators": state.operators.values().map(public_operator).collect::<Vec<Value>>(),
        "lanes": state.lanes.values().map(public_lane).collect::<Vec<Value>>(),
        "preconfirmations": state.preconfirmations.values().map(public_preconfirmation).collect::<Vec<Value>>(),
        "lease_transfers": state.lease_transfers.values().map(public_lease_transfer).collect::<Vec<Value>>(),
        "rotations": state.rotations.values().map(public_rotation).collect::<Vec<Value>>(),
        "drain_queue": state.backlog_drain_queue().iter().map(public_drain_plan).collect::<Vec<Value>>(),
        "failover_readiness": state.lanes.keys().filter_map(|lane_id| state.failover_readiness(lane_id)).map(public_failover_readiness).collect::<Vec<Value>>(),
        "continuity_windows": state.lanes.keys().filter_map(|lane_id| state.continuity_window(lane_id, state.current_slot.saturating_add(state.config.preconfirmation_ttl_slots))).map(public_continuity_window).collect::<Vec<Value>>(),
        "operator_scores": state.operator_scores().iter().map(public_operator_score).collect::<Vec<Value>>(),
        "backlog_pressure": state.backlog_pressure().iter().map(public_backlog_pressure).collect::<Vec<Value>>(),
        "fee_caps": state.fee_caps.values().map(public_fee_cap).collect::<Vec<Value>>(),
        "telemetry": state.telemetry.values().map(public_telemetry).collect::<Vec<Value>>(),
        "events": state.event_log.iter().map(public_event).collect::<Vec<Value>>(),
    })
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn public_operator(record: &OperatorRecord) -> Value {
    json!({
        "operator_id": record.operator_id,
        "role": record.role.as_str(),
        "status": record.status.as_str(),
        "pq_auth_root": record.pq_auth_root,
        "stake_weight": record.stake_weight,
        "privacy_set_size": record.privacy_set_size,
        "last_heartbeat_slot": record.last_heartbeat_slot,
        "active_lane_count": record.active_lane_ids.len(),
        "redacted_label": record.redacted_label,
    })
}

fn public_lane(record: &LaneRecord) -> Value {
    json!({
        "lane_id": record.lane_id,
        "lane_kind": record.lane_kind.as_str(),
        "status": record.status.as_str(),
        "primary_operator_id": record.primary_operator_id,
        "standby_operator_ids": record.standby_operator_ids,
        "encrypted_mempool_root": record.encrypted_mempool_root,
        "preconfirmation_cursor": record.preconfirmation_cursor,
        "backlog_items": record.backlog_items,
        "backlog_bytes": record.backlog_bytes,
        "fee_cap_bps": record.fee_cap_bps,
    })
}

fn public_preconfirmation(record: &PreconfirmationRecord) -> Value {
    json!({
        "preconfirmation_id": record.preconfirmation_id,
        "lane_id": record.lane_id,
        "issuer_operator_id": record.issuer_operator_id,
        "successor_operator_id": record.successor_operator_id,
        "status": record.status.as_str(),
        "slot": record.slot,
        "expires_at_slot": record.expires_at_slot,
        "confidential_receipt_root": record.confidential_receipt_root,
        "continuity_root": record.continuity_root,
        "fee_cap_bps": record.fee_cap_bps,
        "cursor_before": record.cursor_before,
        "cursor_after": record.cursor_after,
    })
}

fn public_lease_transfer(record: &LeaseTransferRecord) -> Value {
    json!({
        "transfer_id": record.transfer_id,
        "lane_id": record.lane_id,
        "from_operator_id": record.from_operator_id,
        "to_operator_id": record.to_operator_id,
        "status": record.status.as_str(),
        "slot": record.slot,
        "expires_at_slot": record.expires_at_slot,
        "encrypted_mempool_root_before": record.encrypted_mempool_root_before,
        "encrypted_mempool_root_after": record.encrypted_mempool_root_after,
        "lease_auth_root": record.lease_auth_root,
        "backlog_items": record.backlog_items,
        "preserved_fee_cap_bps": record.preserved_fee_cap_bps,
    })
}

fn public_rotation(record: &RotationRecord) -> Value {
    json!({
        "rotation_id": record.rotation_id,
        "lane_id": record.lane_id,
        "previous_operator_id": record.previous_operator_id,
        "next_operator_id": record.next_operator_id,
        "reason": record.reason.as_str(),
        "slot": record.slot,
        "pq_rotation_root": record.pq_rotation_root,
        "preconfirmation_cursor": record.preconfirmation_cursor,
        "inherited_fee_cap_bps": record.inherited_fee_cap_bps,
        "continuity_gap_ms": record.continuity_gap_ms,
    })
}

fn public_drain_plan(record: &DrainPlanRecord) -> Value {
    json!({
        "drain_plan_id": record.drain_plan_id,
        "lane_id": record.lane_id,
        "operator_id": record.operator_id,
        "status": record.status.as_str(),
        "slot": record.slot,
        "drain_until_slot": record.drain_until_slot,
        "batch_limit": record.batch_limit,
        "planned_items": record.planned_items,
        "completed_items": record.completed_items,
        "encrypted_backlog_root": record.encrypted_backlog_root,
        "public_priority_score": record.public_priority_score,
    })
}

fn public_failover_readiness(record: FailoverReadinessRecord) -> Value {
    json!({
        "lane_id": record.lane_id,
        "primary_operator_id": record.primary_operator_id,
        "preferred_successor_operator_id": record.preferred_successor_operator_id,
        "available_standby_count": record.available_standby_count,
        "preconfirmation_cursor": record.preconfirmation_cursor,
        "backlog_items": record.backlog_items,
        "preserved_fee_cap_bps": record.preserved_fee_cap_bps,
        "estimated_continuity_gap_ms": record.estimated_continuity_gap_ms,
        "ready": record.ready,
        "readiness_root": record.readiness_root,
    })
}

fn public_continuity_window(record: ContinuityWindowRecord) -> Value {
    json!({
        "lane_id": record.lane_id,
        "open_preconfirmations": record.open_preconfirmations,
        "mirrored_preconfirmations": record.mirrored_preconfirmations,
        "expiring_preconfirmations": record.expiring_preconfirmations,
        "highest_cursor_after": record.highest_cursor_after,
        "lowest_fee_cap_bps": record.lowest_fee_cap_bps,
        "continuity_root": record.continuity_root,
    })
}

fn public_operator_score(record: &OperatorScoreRecord) -> Value {
    json!({
        "operator_id": record.operator_id,
        "role": record.role.as_str(),
        "status": record.status.as_str(),
        "lane_count": record.lane_count,
        "stake_weight": record.stake_weight,
        "privacy_set_size": record.privacy_set_size,
        "proposer_score": record.proposer_score,
        "redacted_label": record.redacted_label,
    })
}

fn public_backlog_pressure(record: &BacklogPressureRecord) -> Value {
    json!({
        "lane_id": record.lane_id,
        "lane_kind": record.lane_kind.as_str(),
        "status": record.status.as_str(),
        "backlog_items": record.backlog_items,
        "backlog_bytes": record.backlog_bytes,
        "public_priority_score": record.public_priority_score,
        "suggested_batch_limit": record.suggested_batch_limit,
        "drain_needed": record.drain_needed,
    })
}

fn public_fee_cap(record: &FeeCapRecord) -> Value {
    json!({
        "fee_cap_id": record.fee_cap_id,
        "lane_id": record.lane_id,
        "operator_id": record.operator_id,
        "slot": record.slot,
        "expires_at_slot": record.expires_at_slot,
        "fee_asset_id": record.fee_asset_id,
        "max_fee_bps": record.max_fee_bps,
        "user_cap_commitment_root": record.user_cap_commitment_root,
        "preserved_across_failover": record.preserved_across_failover,
    })
}

fn public_telemetry(record: &TelemetryRecord) -> Value {
    json!({
        "telemetry_id": record.telemetry_id,
        "operator_id": record.operator_id,
        "lane_id": record.lane_id,
        "slot_bucket": record.slot_bucket,
        "privacy_bucket_size": record.privacy_bucket_size,
        "redacted_operator_label": record.redacted_operator_label,
        "latency_bucket_ms": record.latency_bucket_ms,
        "backlog_bucket_items": record.backlog_bucket_items,
        "failover_count_bucket": record.failover_count_bucket,
        "encrypted_detail_root": record.encrypted_detail_root,
    })
}

fn public_event(record: &EventRecord) -> Value {
    json!({
        "event_id": record.event_id,
        "slot": record.slot,
        "kind": record.kind,
        "subject_id": record.subject_id,
        "root": record.root,
    })
}

fn operator_root(record: &OperatorRecord) -> String {
    let lanes_root = merkle_root(
        "operator_active_lanes",
        record
            .active_lane_ids
            .iter()
            .map(|lane| hp(lane.as_str()))
            .collect::<Vec<HashPart>>(),
    );
    domain_hash(
        "operator_record",
        &[
            hp(record.operator_id.as_str()),
            hp(record.role.as_str()),
            hp(record.status.as_str()),
            hp(record.pq_auth_root.as_str()),
            hp(record.stake_weight.to_string()),
            hp(record.privacy_set_size.to_string()),
            hp(record.last_heartbeat_slot.to_string()),
            hp(lanes_root.as_str()),
            hp(record.redacted_label.as_str()),
        ],
    )
}

fn lane_root(record: &LaneRecord) -> String {
    let standbys_root = merkle_root(
        "lane_standby_operators",
        record
            .standby_operator_ids
            .iter()
            .map(|id| hp(id.as_str()))
            .collect::<Vec<HashPart>>(),
    );
    domain_hash(
        HOT_STANDBY_SUITE,
        &[
            hp(record.lane_id.as_str()),
            hp(record.lane_kind.as_str()),
            hp(record.status.as_str()),
            hp(record.primary_operator_id.as_str()),
            hp(standbys_root.as_str()),
            hp(record.encrypted_mempool_root.as_str()),
            hp(record.preconfirmation_cursor.to_string()),
            hp(record.backlog_items.to_string()),
            hp(record.backlog_bytes.to_string()),
            hp(record.fee_cap_bps.to_string()),
        ],
    )
}

fn preconfirmation_root(record: &PreconfirmationRecord) -> String {
    domain_hash(
        PRECONFIRMATION_CONTINUITY_SUITE,
        &[
            hp(record.preconfirmation_id.as_str()),
            hp(record.lane_id.as_str()),
            hp(record.issuer_operator_id.as_str()),
            hp(record.successor_operator_id.as_str()),
            hp(record.status.as_str()),
            hp(record.slot.to_string()),
            hp(record.expires_at_slot.to_string()),
            hp(record.confidential_receipt_root.as_str()),
            hp(record.continuity_root.as_str()),
            hp(record.fee_cap_bps.to_string()),
            hp(record.cursor_before.to_string()),
            hp(record.cursor_after.to_string()),
        ],
    )
}

fn lease_transfer_root(record: &LeaseTransferRecord) -> String {
    domain_hash(
        MEMPOOL_LEASE_TRANSFER_SUITE,
        &[
            hp(record.transfer_id.as_str()),
            hp(record.lane_id.as_str()),
            hp(record.from_operator_id.as_str()),
            hp(record.to_operator_id.as_str()),
            hp(record.status.as_str()),
            hp(record.slot.to_string()),
            hp(record.expires_at_slot.to_string()),
            hp(record.encrypted_mempool_root_before.as_str()),
            hp(record.encrypted_mempool_root_after.as_str()),
            hp(record.lease_auth_root.as_str()),
            hp(record.backlog_items.to_string()),
            hp(record.preserved_fee_cap_bps.to_string()),
        ],
    )
}

fn rotation_root(record: &RotationRecord) -> String {
    domain_hash(
        PROPOSER_ROTATION_SUITE,
        &[
            hp(record.rotation_id.as_str()),
            hp(record.lane_id.as_str()),
            hp(record.previous_operator_id.as_str()),
            hp(record.next_operator_id.as_str()),
            hp(record.reason.as_str()),
            hp(record.slot.to_string()),
            hp(record.pq_rotation_root.as_str()),
            hp(record.preconfirmation_cursor.to_string()),
            hp(record.inherited_fee_cap_bps.to_string()),
            hp(record.continuity_gap_ms.to_string()),
        ],
    )
}

fn drain_plan_root(record: &DrainPlanRecord) -> String {
    domain_hash(
        BACKLOG_DRAIN_SUITE,
        &[
            hp(record.drain_plan_id.as_str()),
            hp(record.lane_id.as_str()),
            hp(record.operator_id.as_str()),
            hp(record.status.as_str()),
            hp(record.slot.to_string()),
            hp(record.drain_until_slot.to_string()),
            hp(record.batch_limit.to_string()),
            hp(record.planned_items.to_string()),
            hp(record.completed_items.to_string()),
            hp(record.encrypted_backlog_root.as_str()),
            hp(record.public_priority_score.to_string()),
        ],
    )
}

fn fee_cap_root(record: &FeeCapRecord) -> String {
    domain_hash(
        FEE_CAP_PRESERVATION_SUITE,
        &[
            hp(record.fee_cap_id.as_str()),
            hp(record.lane_id.as_str()),
            hp(record.operator_id.as_str()),
            hp(record.slot.to_string()),
            hp(record.expires_at_slot.to_string()),
            hp(record.fee_asset_id.as_str()),
            hp(record.max_fee_bps.to_string()),
            hp(record.user_cap_commitment_root.as_str()),
            hp(record.preserved_across_failover.to_string()),
        ],
    )
}

fn telemetry_root(record: &TelemetryRecord) -> String {
    domain_hash(
        OPERATOR_TELEMETRY_SUITE,
        &[
            hp(record.telemetry_id.as_str()),
            hp(record.operator_id.as_str()),
            hp(record.lane_id.as_str()),
            hp(record.slot_bucket.to_string()),
            hp(record.privacy_bucket_size.to_string()),
            hp(record.redacted_operator_label.as_str()),
            hp(record.latency_bucket_ms.to_string()),
            hp(record.backlog_bucket_items.to_string()),
            hp(record.failover_count_bucket.to_string()),
            hp(record.encrypted_detail_root.as_str()),
        ],
    )
}

fn event_root(record: &EventRecord) -> String {
    domain_hash(
        "sequencer_failover_event",
        &[
            hp(record.event_id.to_string()),
            hp(record.slot.to_string()),
            hp(record.kind.as_str()),
            hp(record.subject_id.as_str()),
            hp(record.root.as_str()),
        ],
    )
}

fn merkle_map_root<'a, I>(domain: &str, pairs: I) -> String
where
    I: Iterator<Item = (&'a str, String)>,
{
    let leaves = pairs
        .map(|(id, root)| domain_hash(domain, &[hp(id), hp(root.as_str())]))
        .map(hp)
        .collect::<Vec<HashPart>>();
    merkle_root(domain, leaves)
}

fn deterministic_id(prefix: &str, parts: &[&str]) -> String {
    let hash = domain_hash(
        prefix,
        &parts
            .iter()
            .map(|part| hp(*part))
            .collect::<Vec<HashPart>>(),
    );
    format!("{prefix}-{hash}")
}

fn round_bucket(value: u64, width: u64) -> u64 {
    if width == 0 {
        value
    } else {
        value.saturating_add(width.saturating_sub(1)) / width * width
    }
}
