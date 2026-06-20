use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialWitnessDeltaLatencyMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DELTA_LATENCY_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-witness-delta-latency-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DELTA_LATENCY_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const WITNESS_DELTA_MARKET_SUITE: &str =
    "private-l2-fast-pq-confidential-witness-delta-latency-market-v1";
pub const PRECONFIRMATION_LATENCY_BID_SUITE: &str =
    "ml-kem-1024-sealed-preconfirmation-latency-bid-root-v1";
pub const PQ_LANE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-witness-delta-lane-attestation-v1";
pub const RECEIPT_DELTA_QOS_SUITE: &str = "private-l2-fast-confidential-receipt-delta-qos-score-v1";
pub const FEE_AWARE_SCHEDULER_SUITE: &str =
    "private-l2-fast-confidential-witness-delta-fee-aware-scheduler-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "privacy-preserving-public-witness-delta-latency-market-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_witness_deltas_addresses_view_keys_receipts_payloads_or_bid_amounts";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_EPOCH: u64 = 24_576;
pub const DEVNET_HEIGHT: u64 = 6_420_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 110;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 180;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 480;
pub const DEFAULT_BID_TTL_SLOTS: u64 = 12;
pub const DEFAULT_DELTA_TTL_SLOTS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 128;
pub const DEFAULT_QOS_WINDOW_SLOTS: u64 = 64;
pub const DEFAULT_MAX_LANES: usize = 65_536;
pub const DEFAULT_MAX_DELTAS: usize = 1_048_576;
pub const DEFAULT_MAX_BIDS: usize = 1_048_576;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPT_QOS: usize = 1_048_576;
pub const DEFAULT_MAX_SCHEDULES: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 131_072;
pub const DEFAULT_MIN_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MIN_RECEIPT_DELTA_QOS_BPS: u64 = 8_200;
pub const DEFAULT_TARGET_DELTA_HIT_BPS: u64 = 8_800;
pub const DEFAULT_LOW_FEE_BONUS_BPS: u64 = 700;
pub const DEFAULT_PRIVACY_BONUS_BPS: u64 = 350;
pub const DEFAULT_CONGESTION_PENALTY_BPS: u64 = 1_100;
pub const DEFAULT_MISSED_DELTA_PENALTY_BPS: u64 = 1_500;
pub const DEFAULT_PRIORITY_FEE_CAP_MICROS: u64 = 95;
pub const DEFAULT_BASE_SCHEDULING_FEE_MICROS: u64 = 3;
pub const DEFAULT_BID_REVEAL_GRACE_SLOTS: u64 = 3;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:LANES";
const D_DELTAS: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:DELTAS";
const D_BIDS: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:BIDS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:ATTESTATIONS";
const D_QOS: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:QOS";
const D_SCHEDULES: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:SCHEDULES";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-WITNESS-DELTA-LATENCY-MARKET:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    WalletFast,
    MerchantPos,
    DefiIntent,
    BridgeExit,
    ContractCall,
    ProofCarry,
    OperatorMirror,
    EmergencyCancel,
}

impl LaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletFast => "wallet_fast",
            Self::MerchantPos => "merchant_pos",
            Self::DefiIntent => "defi_intent",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::ProofCarry => "proof_carry",
            Self::OperatorMirror => "operator_mirror",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_800,
            Self::BridgeExit => 10_200,
            Self::MerchantPos => 9_700,
            Self::DefiIntent => 9_450,
            Self::ContractCall => 9_100,
            Self::WalletFast => 8_900,
            Self::ProofCarry => 8_450,
            Self::OperatorMirror => 7_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Registered,
    Open,
    Hot,
    Congested,
    Draining,
    Paused,
    Quarantined,
    Retired,
}

impl LaneStatus {
    pub fn accepts_market(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Open | Self::Hot | Self::Congested
        )
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Open | Self::Hot | Self::Congested | Self::Draining
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Open => "open",
            Self::Hot => "hot",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessDeltaKind {
    ReadSet,
    WriteSet,
    ReceiptDelta,
    InclusionPath,
    NullifierSet,
    BridgeOutput,
    ContractStorage,
    RepairShard,
}

impl WitnessDeltaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadSet => "read_set",
            Self::WriteSet => "write_set",
            Self::ReceiptDelta => "receipt_delta",
            Self::InclusionPath => "inclusion_path",
            Self::NullifierSet => "nullifier_set",
            Self::BridgeOutput => "bridge_output",
            Self::ContractStorage => "contract_storage",
            Self::RepairShard => "repair_shard",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::BridgeOutput => 1_080,
            Self::ContractStorage => 1_020,
            Self::WriteSet => 980,
            Self::ReceiptDelta => 930,
            Self::RepairShard => 850,
            Self::NullifierSet => 810,
            Self::ReadSet => 760,
            Self::InclusionPath => 690,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaStatus {
    Proposed,
    BidOpen,
    BidSelected,
    Prefetching,
    Attested,
    Scheduled,
    Delivered,
    Late,
    Missing,
    Expired,
    Slashed,
}

impl DeltaStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::BidOpen
                | Self::BidSelected
                | Self::Prefetching
                | Self::Attested
                | Self::Scheduled
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Delivered | Self::Late | Self::Missing | Self::Expired | Self::Slashed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidClass {
    Instant,
    Fast,
    Standard,
    LowFee,
    Sponsored,
    Emergency,
}

impl BidClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::LowFee => "low_fee",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
        }
    }

    pub fn target_ms(self, config: &Config) -> u64 {
        match self {
            Self::Instant => config.target_preconfirmation_ms.saturating_div(2).max(1),
            Self::Fast => config.target_preconfirmation_ms,
            Self::Standard => config.target_preconfirmation_ms.saturating_mul(3),
            Self::LowFee => config.target_preconfirmation_ms.saturating_mul(8),
            Self::Sponsored => config.target_preconfirmation_ms.saturating_mul(5),
            Self::Emergency => config.target_preconfirmation_ms.saturating_div(3).max(1),
        }
    }

    pub fn multiplier_bps(self) -> u64 {
        match self {
            Self::Emergency => 11_500,
            Self::Instant => 11_000,
            Self::Fast => 10_200,
            Self::Standard => 9_200,
            Self::Sponsored => 8_800,
            Self::LowFee => 8_100,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Open,
    Selected,
    Revealed,
    Filled,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl BidStatus {
    pub fn marketable(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Open | Self::Selected | Self::Revealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyBand {
    UltraFast,
    Target,
    SoftLate,
    HardLate,
    Missing,
}

impl LatencyBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFast => "ultra_fast",
            Self::Target => "target",
            Self::SoftLate => "soft_late",
            Self::HardLate => "hard_late",
            Self::Missing => "missing",
        }
    }

    pub fn from_latency_ms(config: &Config, latency_ms: Option<u64>) -> Self {
        match latency_ms {
            None => Self::Missing,
            Some(ms) if ms <= config.target_preconfirmation_ms / 2 => Self::UltraFast,
            Some(ms) if ms <= config.target_preconfirmation_ms => Self::Target,
            Some(ms) if ms <= config.soft_latency_ms => Self::SoftLate,
            Some(ms) if ms <= config.hard_latency_ms => Self::HardLate,
            Some(_) => Self::Missing,
        }
    }

    pub fn qos_multiplier_bps(self) -> u64 {
        match self {
            Self::UltraFast => 10_900,
            Self::Target => 10_000,
            Self::SoftLate => 8_700,
            Self::HardLate => 6_900,
            Self::Missing => 4_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QosGrade {
    Excellent,
    Good,
    Degraded,
    Missing,
}

impl QosGrade {
    pub fn from_score(config: &Config, score_bps: u64) -> Self {
        if score_bps >= config.strong_quorum_weight_bps {
            Self::Excellent
        } else if score_bps >= config.min_receipt_delta_qos_bps {
            Self::Good
        } else if score_bps > 0 {
            Self::Degraded
        } else {
            Self::Missing
        }
    }

    pub fn multiplier_bps(self) -> u64 {
        match self {
            Self::Excellent => 10_600,
            Self::Good => 10_000,
            Self::Degraded => 7_600,
            Self::Missing => 4_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    PqVerified,
    QuorumCounted,
    Superseded,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleReason {
    LatencyAuction,
    ReceiptDeltaQos,
    FeeEfficient,
    PrivacySetGrowth,
    CongestionRelief,
    BridgeExitPriority,
    EmergencyCancelPriority,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub mode: RuntimeMode,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub slot_width_ms: u64,
    pub target_preconfirmation_ms: u64,
    pub soft_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub bid_ttl_slots: u64,
    pub delta_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub qos_window_slots: u64,
    pub max_lanes: usize,
    pub max_deltas: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_receipt_qos: usize,
    pub max_schedules: usize,
    pub max_public_records: usize,
    pub min_quorum_weight_bps: u64,
    pub strong_quorum_weight_bps: u64,
    pub min_receipt_delta_qos_bps: u64,
    pub target_delta_hit_bps: u64,
    pub low_fee_bonus_bps: u64,
    pub privacy_bonus_bps: u64,
    pub congestion_penalty_bps: u64,
    pub missed_delta_penalty_bps: u64,
    pub priority_fee_cap_micros: u64,
    pub base_scheduling_fee_micros: u64,
    pub bid_reveal_grace_slots: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            bid_ttl_slots: DEFAULT_BID_TTL_SLOTS,
            delta_ttl_slots: DEFAULT_DELTA_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            qos_window_slots: DEFAULT_QOS_WINDOW_SLOTS,
            max_lanes: DEFAULT_MAX_LANES,
            max_deltas: DEFAULT_MAX_DELTAS,
            max_bids: DEFAULT_MAX_BIDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_receipt_qos: DEFAULT_MAX_RECEIPT_QOS,
            max_schedules: DEFAULT_MAX_SCHEDULES,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            min_quorum_weight_bps: DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            min_receipt_delta_qos_bps: DEFAULT_MIN_RECEIPT_DELTA_QOS_BPS,
            target_delta_hit_bps: DEFAULT_TARGET_DELTA_HIT_BPS,
            low_fee_bonus_bps: DEFAULT_LOW_FEE_BONUS_BPS,
            privacy_bonus_bps: DEFAULT_PRIVACY_BONUS_BPS,
            congestion_penalty_bps: DEFAULT_CONGESTION_PENALTY_BPS,
            missed_delta_penalty_bps: DEFAULT_MISSED_DELTA_PENALTY_BPS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            base_scheduling_fee_micros: DEFAULT_BASE_SCHEDULING_FEE_MICROS,
            bid_reveal_grace_slots: DEFAULT_BID_REVEAL_GRACE_SLOTS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_positive_u64("schema_version", self.schema_version)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive_u64("slot_width_ms", self.slot_width_ms)?;
        ensure_positive_u64("target_preconfirmation_ms", self.target_preconfirmation_ms)?;
        ensure_positive_u64("soft_latency_ms", self.soft_latency_ms)?;
        ensure_positive_u64("hard_latency_ms", self.hard_latency_ms)?;
        ensure_positive_u64("bid_ttl_slots", self.bid_ttl_slots)?;
        ensure_positive_u64("delta_ttl_slots", self.delta_ttl_slots)?;
        ensure_positive_u64("attestation_ttl_slots", self.attestation_ttl_slots)?;
        ensure_positive_u64("qos_window_slots", self.qos_window_slots)?;
        ensure_positive_usize("max_lanes", self.max_lanes)?;
        ensure_positive_usize("max_deltas", self.max_deltas)?;
        ensure_positive_usize("max_bids", self.max_bids)?;
        ensure_positive_usize("max_attestations", self.max_attestations)?;
        ensure_positive_usize("max_receipt_qos", self.max_receipt_qos)?;
        ensure_positive_usize("max_schedules", self.max_schedules)?;
        ensure_positive_usize("max_public_records", self.max_public_records)?;
        ensure_bps("min_quorum_weight_bps", self.min_quorum_weight_bps)?;
        ensure_bps("strong_quorum_weight_bps", self.strong_quorum_weight_bps)?;
        ensure_bps("min_receipt_delta_qos_bps", self.min_receipt_delta_qos_bps)?;
        ensure_bps("target_delta_hit_bps", self.target_delta_hit_bps)?;
        ensure_bps("low_fee_bonus_bps", self.low_fee_bonus_bps)?;
        ensure_bps("privacy_bonus_bps", self.privacy_bonus_bps)?;
        ensure_bps("congestion_penalty_bps", self.congestion_penalty_bps)?;
        ensure_bps("missed_delta_penalty_bps", self.missed_delta_penalty_bps)?;
        ensure_positive_u64("priority_fee_cap_micros", self.priority_fee_cap_micros)?;
        ensure_positive_u64(
            "base_scheduling_fee_micros",
            self.base_scheduling_fee_micros,
        )?;
        if self.target_preconfirmation_ms > self.soft_latency_ms {
            return Err("target_preconfirmation_ms cannot exceed soft_latency_ms".to_string());
        }
        if self.soft_latency_ms > self.hard_latency_ms {
            return Err("soft_latency_ms cannot exceed hard_latency_ms".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Some(object) = record.as_object_mut() {
            object.insert("hash_suite".to_string(), json!(HASH_SUITE));
            object.insert(
                "market_suite".to_string(),
                json!(WITNESS_DELTA_MARKET_SUITE),
            );
            object.insert(
                "preconfirmation_latency_bid_suite".to_string(),
                json!(PRECONFIRMATION_LATENCY_BID_SUITE),
            );
            object.insert(
                "pq_lane_attestation_suite".to_string(),
                json!(PQ_LANE_ATTESTATION_SUITE),
            );
            object.insert(
                "receipt_delta_qos_suite".to_string(),
                json!(RECEIPT_DELTA_QOS_SUITE),
            );
            object.insert(
                "fee_aware_scheduler_suite".to_string(),
                json!(FEE_AWARE_SCHEDULER_SUITE),
            );
            object.insert("privacy_boundary".to_string(), json!(PRIVACY_BOUNDARY));
        }
        record
    }

    pub fn state_root(&self) -> String {
        payload_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub witness_deltas_posted: u64,
    pub latency_bids_submitted: u64,
    pub latency_bids_selected: u64,
    pub pq_attestations_submitted: u64,
    pub pq_attestations_counted: u64,
    pub receipt_delta_qos_samples: u64,
    pub schedules_created: u64,
    pub deltas_delivered: u64,
    pub deltas_late: u64,
    pub deltas_missing: u64,
    pub public_records_emitted: u64,
    pub nullifiers_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({ "serialization": "failed" }))
    }

    pub fn state_root(&self) -> String {
        payload_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lane_root: String,
    pub witness_delta_root: String,
    pub latency_bid_root: String,
    pub pq_attestation_root: String,
    pub receipt_delta_qos_root: String,
    pub schedule_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            lane_root: empty_root("lanes"),
            witness_delta_root: empty_root("witness-deltas"),
            latency_bid_root: empty_root("latency-bids"),
            pq_attestation_root: empty_root("pq-attestations"),
            receipt_delta_qos_root: empty_root("receipt-delta-qos"),
            schedule_root: empty_root("schedules"),
            nullifier_root: empty_root("nullifiers"),
            public_record_root: empty_root("public-records"),
            state_root: empty_root("state"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({ "serialization": "failed" }))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneRegistrationInput {
    pub lane_id: String,
    pub lane_class: LaneClass,
    pub operator_commitment: String,
    pub pq_key_root: String,
    pub scheduling_policy_root: String,
    pub max_priority_fee_micros: u64,
    pub target_delta_hit_bps: u64,
    pub privacy_set_size: u64,
    pub starting_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessDeltaInput {
    pub lane_id: String,
    pub delta_kind: WitnessDeltaKind,
    pub state_root_before: String,
    pub state_root_after: String,
    pub witness_delta_root: String,
    pub receipt_delta_root: String,
    pub encrypted_delta_bytes: u64,
    pub privacy_set_size: u64,
    pub requested_slot: u64,
    pub max_latency_ms: u64,
    pub max_fee_micros: u64,
    pub delta_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreconfirmationLatencyBidInput {
    pub lane_id: String,
    pub delta_id: String,
    pub bidder_commitment: String,
    pub bid_class: BidClass,
    pub sealed_bid_root: String,
    pub max_latency_ms: u64,
    pub fee_cap_micros: u64,
    pub bond_root: String,
    pub privacy_set_size: u64,
    pub submit_slot: u64,
    pub bid_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqLaneAttestationInput {
    pub lane_id: String,
    pub delta_id: String,
    pub attester_commitment: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub observed_latency_ms: Option<u64>,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub attested_slot: u64,
    pub attestation_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptDeltaQosInput {
    pub lane_id: String,
    pub delta_id: String,
    pub receipt_delta_root: String,
    pub delivered_slot: Option<u64>,
    pub observed_latency_ms: Option<u64>,
    pub availability_bps: u64,
    pub repair_count: u64,
    pub sample_count: u64,
    pub qos_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeAwareScheduleInput {
    pub lane_id: String,
    pub delta_id: String,
    pub bid_id: Option<String>,
    pub requested_slot: u64,
    pub max_fee_micros: u64,
    pub reason: ScheduleReason,
    pub scheduler_commitment: String,
    pub schedule_nullifier: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialLaneEntry {
    pub lane_id: String,
    pub lane_class: LaneClass,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub pq_key_root: String,
    pub scheduling_policy_root: String,
    pub max_priority_fee_micros: u64,
    pub target_delta_hit_bps: u64,
    pub privacy_set_size: u64,
    pub starting_slot: u64,
    pub latest_delta_id: Option<String>,
    pub latest_bid_id: Option<String>,
    pub latest_qos_id: Option<String>,
    pub rolling_latency_score_bps: u64,
    pub rolling_qos_score_bps: u64,
    pub rolling_delta_hit_bps: u64,
    pub fee_efficiency_score_bps: u64,
    pub root: String,
}

impl ConfidentialLaneEntry {
    pub fn public_record(&self) -> Value {
        record_with_kind("confidential_witness_delta_lane", self)
    }

    pub fn refresh_root(&mut self) {
        self.root = payload_root(D_LANES, &record_without_root(self));
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessDeltaEntry {
    pub delta_id: String,
    pub lane_id: String,
    pub delta_kind: WitnessDeltaKind,
    pub status: DeltaStatus,
    pub state_root_before: String,
    pub state_root_after: String,
    pub witness_delta_root: String,
    pub receipt_delta_root: String,
    pub encrypted_delta_bytes: u64,
    pub privacy_set_size: u64,
    pub requested_slot: u64,
    pub expiry_slot: u64,
    pub max_latency_ms: u64,
    pub max_fee_micros: u64,
    pub latency_band: LatencyBand,
    pub selected_bid_id: Option<String>,
    pub latest_attestation_id: Option<String>,
    pub latest_qos_id: Option<String>,
    pub scheduling_score_bps: u64,
    pub root: String,
}

impl WitnessDeltaEntry {
    pub fn public_record(&self) -> Value {
        record_with_kind("witness_delta", self)
    }

    pub fn refresh_root(&mut self) {
        self.root = payload_root(D_DELTAS, &record_without_root(self));
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreconfirmationLatencyBid {
    pub bid_id: String,
    pub lane_id: String,
    pub delta_id: String,
    pub bidder_commitment: String,
    pub bid_class: BidClass,
    pub status: BidStatus,
    pub sealed_bid_root: String,
    pub max_latency_ms: u64,
    pub fee_cap_micros: u64,
    pub bond_root: String,
    pub privacy_set_size: u64,
    pub submit_slot: u64,
    pub expiry_slot: u64,
    pub score_bps: u64,
    pub root: String,
}

impl PreconfirmationLatencyBid {
    pub fn public_record(&self) -> Value {
        record_with_kind("preconfirmation_latency_bid", self)
    }

    pub fn refresh_root(&mut self) {
        self.root = payload_root(D_BIDS, &record_without_root(self));
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub delta_id: String,
    pub attester_commitment: String,
    pub status: AttestationStatus,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub observed_latency_ms: Option<u64>,
    pub latency_band: LatencyBand,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub attested_slot: u64,
    pub expiry_slot: u64,
    pub root: String,
}

impl PqLaneAttestation {
    pub fn public_record(&self) -> Value {
        record_with_kind("pq_lane_attestation", self)
    }

    pub fn refresh_root(&mut self) {
        self.root = payload_root(D_ATTESTATIONS, &record_without_root(self));
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptDeltaQosScore {
    pub qos_id: String,
    pub lane_id: String,
    pub delta_id: String,
    pub receipt_delta_root: String,
    pub delivered_slot: Option<u64>,
    pub observed_latency_ms: Option<u64>,
    pub latency_band: LatencyBand,
    pub availability_bps: u64,
    pub repair_count: u64,
    pub sample_count: u64,
    pub score_bps: u64,
    pub grade: QosGrade,
    pub root: String,
}

impl ReceiptDeltaQosScore {
    pub fn public_record(&self) -> Value {
        record_with_kind("receipt_delta_qos_score", self)
    }

    pub fn refresh_root(&mut self) {
        self.root = payload_root(D_QOS, &record_without_root(self));
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeAwareScheduleDecision {
    pub schedule_id: String,
    pub lane_id: String,
    pub delta_id: String,
    pub bid_id: Option<String>,
    pub requested_slot: u64,
    pub assigned_slot: u64,
    pub max_fee_micros: u64,
    pub fee_capped: bool,
    pub reason: ScheduleReason,
    pub scheduler_commitment: String,
    pub score_bps: u64,
    pub root: String,
}

impl FeeAwareScheduleDecision {
    pub fn public_record(&self) -> Value {
        record_with_kind("fee_aware_schedule_decision", self)
    }

    pub fn refresh_root(&mut self) {
        self.root = payload_root(D_SCHEDULES, &record_without_root(self));
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, ConfidentialLaneEntry>,
    pub witness_deltas: BTreeMap<String, WitnessDeltaEntry>,
    pub latency_bids: BTreeMap<String, PreconfirmationLatencyBid>,
    pub pq_attestations: BTreeMap<String, PqLaneAttestation>,
    pub receipt_delta_qos: BTreeMap<String, ReceiptDeltaQosScore>,
    pub schedule_decisions: BTreeMap<String, FeeAwareScheduleDecision>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default config is valid")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            witness_deltas: BTreeMap::new(),
            latency_bids: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            receipt_delta_qos: BTreeMap::new(),
            schedule_decisions: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: Vec::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn register_lane(&mut self, input: LaneRegistrationInput) -> Result<String> {
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_absent("lane", &self.lanes, &input.lane_id)?;
        ensure_root("operator_commitment", &input.operator_commitment)?;
        ensure_root("pq_key_root", &input.pq_key_root)?;
        ensure_root("scheduling_policy_root", &input.scheduling_policy_root)?;
        ensure_bps("target_delta_hit_bps", input.target_delta_hit_bps)?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below configured minimum".to_string());
        }
        let mut lane = ConfidentialLaneEntry {
            lane_id: input.lane_id.clone(),
            lane_class: input.lane_class,
            status: LaneStatus::Registered,
            operator_commitment: input.operator_commitment,
            pq_key_root: input.pq_key_root,
            scheduling_policy_root: input.scheduling_policy_root,
            max_priority_fee_micros: input.max_priority_fee_micros,
            target_delta_hit_bps: input.target_delta_hit_bps,
            privacy_set_size: input.privacy_set_size,
            starting_slot: input.starting_slot,
            latest_delta_id: None,
            latest_bid_id: None,
            latest_qos_id: None,
            rolling_latency_score_bps: MAX_BPS,
            rolling_qos_score_bps: MAX_BPS,
            rolling_delta_hit_bps: input.target_delta_hit_bps,
            fee_efficiency_score_bps: fee_efficiency_score_bps(
                input.max_priority_fee_micros,
                &self.config,
            ),
            root: String::new(),
        };
        lane.refresh_root();
        let lane_id = lane.lane_id.clone();
        self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn post_witness_delta(&mut self, input: WitnessDeltaInput) -> Result<String> {
        ensure_capacity(
            "witness_deltas",
            self.witness_deltas.len(),
            self.config.max_deltas,
        )?;
        let lane_status = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("lane {} not found", input.lane_id))?
            .status;
        if !lane_status.accepts_market() {
            return Err("lane does not accept witness delta market entries".to_string());
        }
        ensure_root("state_root_before", &input.state_root_before)?;
        ensure_root("state_root_after", &input.state_root_after)?;
        ensure_root("witness_delta_root", &input.witness_delta_root)?;
        ensure_root("receipt_delta_root", &input.receipt_delta_root)?;
        ensure_positive_u64("encrypted_delta_bytes", input.encrypted_delta_bytes)?;
        ensure_positive_u64("max_latency_ms", input.max_latency_ms)?;
        ensure_positive_u64("max_fee_micros", input.max_fee_micros)?;
        ensure_nullifier_available(&self.consumed_nullifiers, &input.delta_nullifier)?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("witness delta privacy set below configured minimum".to_string());
        }
        let sequence = self.counters.witness_deltas_posted.saturating_add(1);
        let delta_id = witness_delta_id(&input, sequence);
        ensure_absent("witness_delta", &self.witness_deltas, &delta_id)?;
        let mut delta = WitnessDeltaEntry {
            delta_id: delta_id.clone(),
            lane_id: input.lane_id.clone(),
            delta_kind: input.delta_kind,
            status: DeltaStatus::BidOpen,
            state_root_before: input.state_root_before,
            state_root_after: input.state_root_after,
            witness_delta_root: input.witness_delta_root,
            receipt_delta_root: input.receipt_delta_root,
            encrypted_delta_bytes: input.encrypted_delta_bytes,
            privacy_set_size: input.privacy_set_size,
            requested_slot: input.requested_slot,
            expiry_slot: input
                .requested_slot
                .saturating_add(self.config.delta_ttl_slots),
            max_latency_ms: input.max_latency_ms,
            max_fee_micros: input.max_fee_micros,
            latency_band: LatencyBand::from_latency_ms(&self.config, Some(input.max_latency_ms)),
            selected_bid_id: None,
            latest_attestation_id: None,
            latest_qos_id: None,
            scheduling_score_bps: 0,
            root: String::new(),
        };
        delta.scheduling_score_bps = witness_delta_market_score(&delta, &self.config);
        delta.refresh_root();
        if let Some(lane) = self.lanes.get_mut(&input.lane_id) {
            lane.latest_delta_id = Some(delta_id.clone());
            lane.refresh_root();
        }
        self.consumed_nullifiers.insert(input.delta_nullifier);
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        self.counters.witness_deltas_posted = self.counters.witness_deltas_posted.saturating_add(1);
        self.witness_deltas.insert(delta_id.clone(), delta);
        self.refresh_roots();
        Ok(delta_id)
    }

    pub fn submit_latency_bid(&mut self, input: PreconfirmationLatencyBidInput) -> Result<String> {
        ensure_capacity(
            "latency_bids",
            self.latency_bids.len(),
            self.config.max_bids,
        )?;
        ensure_root("bidder_commitment", &input.bidder_commitment)?;
        ensure_root("sealed_bid_root", &input.sealed_bid_root)?;
        ensure_root("bond_root", &input.bond_root)?;
        ensure_positive_u64("max_latency_ms", input.max_latency_ms)?;
        ensure_positive_u64("fee_cap_micros", input.fee_cap_micros)?;
        ensure_nullifier_available(&self.consumed_nullifiers, &input.bid_nullifier)?;
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("lane {} not found", input.lane_id))?;
        if !lane.status.accepts_market() {
            return Err("lane does not accept preconfirmation latency bids".to_string());
        }
        let delta = self
            .witness_deltas
            .get(&input.delta_id)
            .ok_or_else(|| format!("delta {} not found", input.delta_id))?;
        if delta.lane_id != input.lane_id {
            return Err("bid lane does not match witness delta lane".to_string());
        }
        if !delta.status.live() {
            return Err("witness delta no longer accepts latency bids".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("bid privacy set below configured minimum".to_string());
        }
        let sequence = self.counters.latency_bids_submitted.saturating_add(1);
        let bid_id = latency_bid_id(&input, sequence);
        ensure_absent("latency_bid", &self.latency_bids, &bid_id)?;
        let mut bid = PreconfirmationLatencyBid {
            bid_id: bid_id.clone(),
            lane_id: input.lane_id.clone(),
            delta_id: input.delta_id.clone(),
            bidder_commitment: input.bidder_commitment,
            bid_class: input.bid_class,
            status: BidStatus::Sealed,
            sealed_bid_root: input.sealed_bid_root,
            max_latency_ms: input.max_latency_ms,
            fee_cap_micros: input.fee_cap_micros,
            bond_root: input.bond_root,
            privacy_set_size: input.privacy_set_size,
            submit_slot: input.submit_slot,
            expiry_slot: input.submit_slot.saturating_add(self.config.bid_ttl_slots),
            score_bps: latency_bid_score(lane, delta, &input, &self.config),
            root: String::new(),
        };
        bid.refresh_root();
        if let Some(delta) = self.witness_deltas.get_mut(&input.delta_id) {
            if delta
                .selected_bid_id
                .as_ref()
                .and_then(|id| self.latency_bids.get(id))
                .map(|current| bid.score_bps > current.score_bps)
                .unwrap_or(true)
            {
                delta.selected_bid_id = Some(bid_id.clone());
                delta.status = DeltaStatus::BidSelected;
                delta.refresh_root();
                self.counters.latency_bids_selected =
                    self.counters.latency_bids_selected.saturating_add(1);
            }
        }
        if let Some(lane) = self.lanes.get_mut(&input.lane_id) {
            lane.latest_bid_id = Some(bid_id.clone());
            lane.refresh_root();
        }
        self.consumed_nullifiers.insert(input.bid_nullifier);
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        self.counters.latency_bids_submitted =
            self.counters.latency_bids_submitted.saturating_add(1);
        self.latency_bids.insert(bid_id.clone(), bid);
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn attest_pq_lane(&mut self, input: PqLaneAttestationInput) -> Result<String> {
        ensure_capacity(
            "pq_attestations",
            self.pq_attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_root("attester_commitment", &input.attester_commitment)?;
        ensure_root("pq_signature_root", &input.pq_signature_root)?;
        ensure_root("transcript_root", &input.transcript_root)?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;
        ensure_nullifier_available(&self.consumed_nullifiers, &input.attestation_nullifier)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq_security_bits below configured minimum".to_string());
        }
        let lane_status = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("lane {} not found", input.lane_id))?
            .status;
        if !lane_status.accepts_attestations() {
            return Err("lane does not accept PQ attestations".to_string());
        }
        let delta = self
            .witness_deltas
            .get(&input.delta_id)
            .ok_or_else(|| format!("delta {} not found", input.delta_id))?;
        if delta.lane_id != input.lane_id {
            return Err("attestation lane does not match witness delta lane".to_string());
        }
        let sequence = self.counters.pq_attestations_submitted.saturating_add(1);
        let attestation_id = pq_attestation_id(&input, sequence);
        ensure_absent("pq_attestation", &self.pq_attestations, &attestation_id)?;
        let status = if input.quorum_weight_bps >= self.config.min_quorum_weight_bps {
            AttestationStatus::QuorumCounted
        } else {
            AttestationStatus::PqVerified
        };
        let mut attestation = PqLaneAttestation {
            attestation_id: attestation_id.clone(),
            lane_id: input.lane_id.clone(),
            delta_id: input.delta_id.clone(),
            attester_commitment: input.attester_commitment,
            status,
            pq_signature_root: input.pq_signature_root,
            transcript_root: input.transcript_root,
            observed_latency_ms: input.observed_latency_ms,
            latency_band: LatencyBand::from_latency_ms(&self.config, input.observed_latency_ms),
            quorum_weight_bps: input.quorum_weight_bps,
            pq_security_bits: input.pq_security_bits,
            attested_slot: input.attested_slot,
            expiry_slot: input
                .attested_slot
                .saturating_add(self.config.attestation_ttl_slots),
            root: String::new(),
        };
        attestation.refresh_root();
        if let Some(delta) = self.witness_deltas.get_mut(&input.delta_id) {
            delta.latest_attestation_id = Some(attestation_id.clone());
            if status == AttestationStatus::QuorumCounted {
                delta.status = DeltaStatus::Attested;
                self.counters.pq_attestations_counted =
                    self.counters.pq_attestations_counted.saturating_add(1);
            }
            delta.latency_band = attestation.latency_band;
            delta.scheduling_score_bps = witness_delta_market_score(delta, &self.config);
            delta.refresh_root();
        }
        self.consumed_nullifiers.insert(input.attestation_nullifier);
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        self.counters.pq_attestations_submitted =
            self.counters.pq_attestations_submitted.saturating_add(1);
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_lane_scores(&input.lane_id)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn score_receipt_delta_qos(&mut self, input: ReceiptDeltaQosInput) -> Result<String> {
        ensure_capacity(
            "receipt_delta_qos",
            self.receipt_delta_qos.len(),
            self.config.max_receipt_qos,
        )?;
        ensure_root("receipt_delta_root", &input.receipt_delta_root)?;
        ensure_bps("availability_bps", input.availability_bps)?;
        ensure_positive_u64("sample_count", input.sample_count)?;
        ensure_nullifier_available(&self.consumed_nullifiers, &input.qos_nullifier)?;
        let delta = self
            .witness_deltas
            .get(&input.delta_id)
            .ok_or_else(|| format!("delta {} not found", input.delta_id))?;
        if delta.lane_id != input.lane_id {
            return Err("QoS lane does not match witness delta lane".to_string());
        }
        let sequence = self.counters.receipt_delta_qos_samples.saturating_add(1);
        let qos_id = receipt_qos_id(&input, sequence);
        ensure_absent("receipt_delta_qos", &self.receipt_delta_qos, &qos_id)?;
        let latency_band = LatencyBand::from_latency_ms(&self.config, input.observed_latency_ms);
        let score_bps = receipt_delta_qos_score(
            latency_band,
            input.availability_bps,
            input.repair_count,
            input.sample_count,
            &self.config,
        );
        let grade = QosGrade::from_score(&self.config, score_bps);
        let mut qos = ReceiptDeltaQosScore {
            qos_id: qos_id.clone(),
            lane_id: input.lane_id.clone(),
            delta_id: input.delta_id.clone(),
            receipt_delta_root: input.receipt_delta_root,
            delivered_slot: input.delivered_slot,
            observed_latency_ms: input.observed_latency_ms,
            latency_band,
            availability_bps: input.availability_bps,
            repair_count: input.repair_count,
            sample_count: input.sample_count,
            score_bps,
            grade,
            root: String::new(),
        };
        qos.refresh_root();
        if let Some(delta) = self.witness_deltas.get_mut(&input.delta_id) {
            delta.latest_qos_id = Some(qos_id.clone());
            delta.latency_band = latency_band;
            delta.status = match latency_band {
                LatencyBand::UltraFast | LatencyBand::Target | LatencyBand::SoftLate => {
                    DeltaStatus::Delivered
                }
                LatencyBand::HardLate => DeltaStatus::Late,
                LatencyBand::Missing => DeltaStatus::Missing,
            };
            delta.scheduling_score_bps = witness_delta_market_score(delta, &self.config);
            delta.refresh_root();
        }
        if let Some(lane) = self.lanes.get_mut(&input.lane_id) {
            lane.latest_qos_id = Some(qos_id.clone());
            lane.refresh_root();
        }
        match latency_band {
            LatencyBand::UltraFast | LatencyBand::Target | LatencyBand::SoftLate => {
                self.counters.deltas_delivered = self.counters.deltas_delivered.saturating_add(1)
            }
            LatencyBand::HardLate => {
                self.counters.deltas_late = self.counters.deltas_late.saturating_add(1)
            }
            LatencyBand::Missing => {
                self.counters.deltas_missing = self.counters.deltas_missing.saturating_add(1)
            }
        }
        self.consumed_nullifiers.insert(input.qos_nullifier);
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        self.counters.receipt_delta_qos_samples =
            self.counters.receipt_delta_qos_samples.saturating_add(1);
        self.receipt_delta_qos.insert(qos_id.clone(), qos);
        self.refresh_lane_scores(&input.lane_id)?;
        self.refresh_roots();
        Ok(qos_id)
    }

    pub fn schedule_fee_aware(&mut self, input: FeeAwareScheduleInput) -> Result<String> {
        ensure_capacity(
            "schedule_decisions",
            self.schedule_decisions.len(),
            self.config.max_schedules,
        )?;
        ensure_root("scheduler_commitment", &input.scheduler_commitment)?;
        ensure_positive_u64("max_fee_micros", input.max_fee_micros)?;
        ensure_nullifier_available(&self.consumed_nullifiers, &input.schedule_nullifier)?;
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("lane {} not found", input.lane_id))?;
        if !lane.status.accepts_market() {
            return Err("lane does not accept scheduling decisions".to_string());
        }
        let delta = self
            .witness_deltas
            .get(&input.delta_id)
            .ok_or_else(|| format!("delta {} not found", input.delta_id))?;
        if delta.lane_id != input.lane_id {
            return Err("schedule lane does not match witness delta lane".to_string());
        }
        if let Some(bid_id) = &input.bid_id {
            let bid = self
                .latency_bids
                .get(bid_id)
                .ok_or_else(|| format!("bid {bid_id} not found"))?;
            if bid.delta_id != input.delta_id {
                return Err("schedule bid does not match witness delta".to_string());
            }
        }
        let sequence = self.counters.schedules_created.saturating_add(1);
        let schedule_id = schedule_id(&input, sequence);
        ensure_absent("schedule_decision", &self.schedule_decisions, &schedule_id)?;
        let score_bps = fee_aware_schedule_score(lane, delta, input.bid_id.as_ref(), self, &input);
        let fee_capped = input.max_fee_micros < self.config.base_scheduling_fee_micros;
        let assigned_slot = assign_slot(input.requested_slot, score_bps, fee_capped);
        let mut decision = FeeAwareScheduleDecision {
            schedule_id: schedule_id.clone(),
            lane_id: input.lane_id.clone(),
            delta_id: input.delta_id.clone(),
            bid_id: input.bid_id.clone(),
            requested_slot: input.requested_slot,
            assigned_slot,
            max_fee_micros: input.max_fee_micros,
            fee_capped,
            reason: input.reason,
            scheduler_commitment: input.scheduler_commitment,
            score_bps,
            root: String::new(),
        };
        decision.refresh_root();
        if let Some(delta) = self.witness_deltas.get_mut(&input.delta_id) {
            delta.status = DeltaStatus::Scheduled;
            delta.scheduling_score_bps = score_bps;
            if let Some(bid_id) = &input.bid_id {
                delta.selected_bid_id = Some(bid_id.clone());
            }
            delta.refresh_root();
        }
        if let Some(bid_id) = &input.bid_id {
            if let Some(bid) = self.latency_bids.get_mut(bid_id) {
                bid.status = BidStatus::Selected;
                bid.refresh_root();
            }
        }
        self.consumed_nullifiers.insert(input.schedule_nullifier);
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        self.counters.schedules_created = self.counters.schedules_created.saturating_add(1);
        self.schedule_decisions
            .insert(schedule_id.clone(), decision);
        self.refresh_lane_scores(&input.lane_id)?;
        self.refresh_roots();
        Ok(schedule_id)
    }

    pub fn emit_public_record(&mut self) -> Result<Value> {
        ensure_capacity(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        self.refresh_roots();
        let record = self.public_record();
        self.public_records.push(record.clone());
        self.counters.public_records_emitted =
            self.counters.public_records_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_witness_delta_latency_market_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "lane_root": self.roots.lane_root,
                "witness_delta_root": self.roots.witness_delta_root,
                "latency_bid_root": self.roots.latency_bid_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "receipt_delta_qos_root": self.roots.receipt_delta_qos_root,
                "schedule_root": self.roots.schedule_root,
                "nullifier_root": self.roots.nullifier_root,
                "public_record_root": self.roots.public_record_root,
            },
            "sizes": {
                "lanes": self.lanes.len(),
                "witness_deltas": self.witness_deltas.len(),
                "latency_bids": self.latency_bids.len(),
                "pq_attestations": self.pq_attestations.len(),
                "receipt_delta_qos": self.receipt_delta_qos.len(),
                "schedule_decisions": self.schedule_decisions.len(),
                "consumed_nullifiers": self.consumed_nullifiers.len(),
                "public_records": self.public_records.len(),
            },
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default()).expect("devnet config is valid");
        let lane_a = state
            .register_lane(LaneRegistrationInput {
                lane_id: "devnet-witness-delta-wallet-fast".to_string(),
                lane_class: LaneClass::WalletFast,
                operator_commitment: dev_hash("operator-wallet", 1),
                pq_key_root: dev_hash("pq-key-wallet", 1),
                scheduling_policy_root: dev_hash("policy-wallet", 1),
                max_priority_fee_micros: 14,
                target_delta_hit_bps: 9_200,
                privacy_set_size: 524_288,
                starting_slot: DEVNET_HEIGHT,
            })
            .expect("register wallet lane");
        let lane_b = state
            .register_lane(LaneRegistrationInput {
                lane_id: "devnet-witness-delta-bridge-exit".to_string(),
                lane_class: LaneClass::BridgeExit,
                operator_commitment: dev_hash("operator-bridge", 2),
                pq_key_root: dev_hash("pq-key-bridge", 2),
                scheduling_policy_root: dev_hash("policy-bridge", 2),
                max_priority_fee_micros: 18,
                target_delta_hit_bps: 9_500,
                privacy_set_size: 786_432,
                starting_slot: DEVNET_HEIGHT.saturating_add(1),
            })
            .expect("register bridge lane");
        let delta_a = state
            .post_witness_delta(WitnessDeltaInput {
                lane_id: lane_a.clone(),
                delta_kind: WitnessDeltaKind::ReceiptDelta,
                state_root_before: dev_hash("state-before-wallet", 1),
                state_root_after: dev_hash("state-after-wallet", 1),
                witness_delta_root: dev_hash("witness-delta-wallet", 1),
                receipt_delta_root: dev_hash("receipt-delta-wallet", 1),
                encrypted_delta_bytes: 48 * 1024,
                privacy_set_size: 524_288,
                requested_slot: DEVNET_HEIGHT.saturating_add(4),
                max_latency_ms: 95,
                max_fee_micros: 18,
                delta_nullifier: dev_hash("delta-nullifier-wallet", 1),
            })
            .expect("post wallet delta");
        let delta_b = state
            .post_witness_delta(WitnessDeltaInput {
                lane_id: lane_b.clone(),
                delta_kind: WitnessDeltaKind::BridgeOutput,
                state_root_before: dev_hash("state-before-bridge", 2),
                state_root_after: dev_hash("state-after-bridge", 2),
                witness_delta_root: dev_hash("witness-delta-bridge", 2),
                receipt_delta_root: dev_hash("receipt-delta-bridge", 2),
                encrypted_delta_bytes: 96 * 1024,
                privacy_set_size: 786_432,
                requested_slot: DEVNET_HEIGHT.saturating_add(5),
                max_latency_ms: 120,
                max_fee_micros: 24,
                delta_nullifier: dev_hash("delta-nullifier-bridge", 2),
            })
            .expect("post bridge delta");
        let bid_a = state
            .submit_latency_bid(PreconfirmationLatencyBidInput {
                lane_id: lane_a.clone(),
                delta_id: delta_a.clone(),
                bidder_commitment: dev_hash("bidder-wallet", 1),
                bid_class: BidClass::Fast,
                sealed_bid_root: dev_hash("sealed-bid-wallet", 1),
                max_latency_ms: 90,
                fee_cap_micros: 12,
                bond_root: dev_hash("bond-wallet", 1),
                privacy_set_size: 524_288,
                submit_slot: DEVNET_HEIGHT.saturating_add(4),
                bid_nullifier: dev_hash("bid-nullifier-wallet", 1),
            })
            .expect("submit wallet bid");
        let bid_b = state
            .submit_latency_bid(PreconfirmationLatencyBidInput {
                lane_id: lane_b.clone(),
                delta_id: delta_b.clone(),
                bidder_commitment: dev_hash("bidder-bridge", 2),
                bid_class: BidClass::Emergency,
                sealed_bid_root: dev_hash("sealed-bid-bridge", 2),
                max_latency_ms: 80,
                fee_cap_micros: 20,
                bond_root: dev_hash("bond-bridge", 2),
                privacy_set_size: 786_432,
                submit_slot: DEVNET_HEIGHT.saturating_add(5),
                bid_nullifier: dev_hash("bid-nullifier-bridge", 2),
            })
            .expect("submit bridge bid");
        state
            .attest_pq_lane(PqLaneAttestationInput {
                lane_id: lane_a.clone(),
                delta_id: delta_a.clone(),
                attester_commitment: dev_hash("attester-wallet", 1),
                pq_signature_root: dev_hash("pq-sig-wallet", 1),
                transcript_root: dev_hash("transcript-wallet", 1),
                observed_latency_ms: Some(88),
                quorum_weight_bps: 7_100,
                pq_security_bits: 256,
                attested_slot: DEVNET_HEIGHT.saturating_add(5),
                attestation_nullifier: dev_hash("attestation-nullifier-wallet", 1),
            })
            .expect("attest wallet lane");
        state
            .attest_pq_lane(PqLaneAttestationInput {
                lane_id: lane_b.clone(),
                delta_id: delta_b.clone(),
                attester_commitment: dev_hash("attester-bridge", 2),
                pq_signature_root: dev_hash("pq-sig-bridge", 2),
                transcript_root: dev_hash("transcript-bridge", 2),
                observed_latency_ms: Some(72),
                quorum_weight_bps: 8_200,
                pq_security_bits: 256,
                attested_slot: DEVNET_HEIGHT.saturating_add(6),
                attestation_nullifier: dev_hash("attestation-nullifier-bridge", 2),
            })
            .expect("attest bridge lane");
        state
            .schedule_fee_aware(FeeAwareScheduleInput {
                lane_id: lane_a.clone(),
                delta_id: delta_a.clone(),
                bid_id: Some(bid_a),
                requested_slot: DEVNET_HEIGHT.saturating_add(6),
                max_fee_micros: 12,
                reason: ScheduleReason::LatencyAuction,
                scheduler_commitment: dev_hash("scheduler-wallet", 1),
                schedule_nullifier: dev_hash("schedule-nullifier-wallet", 1),
            })
            .expect("schedule wallet delta");
        state
            .schedule_fee_aware(FeeAwareScheduleInput {
                lane_id: lane_b.clone(),
                delta_id: delta_b.clone(),
                bid_id: Some(bid_b),
                requested_slot: DEVNET_HEIGHT.saturating_add(7),
                max_fee_micros: 20,
                reason: ScheduleReason::BridgeExitPriority,
                scheduler_commitment: dev_hash("scheduler-bridge", 2),
                schedule_nullifier: dev_hash("schedule-nullifier-bridge", 2),
            })
            .expect("schedule bridge delta");
        state
            .score_receipt_delta_qos(ReceiptDeltaQosInput {
                lane_id: lane_a,
                delta_id: delta_a,
                receipt_delta_root: dev_hash("qos-receipt-wallet", 1),
                delivered_slot: Some(DEVNET_HEIGHT.saturating_add(7)),
                observed_latency_ms: Some(96),
                availability_bps: 9_300,
                repair_count: 0,
                sample_count: 24,
                qos_nullifier: dev_hash("qos-nullifier-wallet", 1),
            })
            .expect("score wallet qos");
        state
            .score_receipt_delta_qos(ReceiptDeltaQosInput {
                lane_id: lane_b,
                delta_id: delta_b,
                receipt_delta_root: dev_hash("qos-receipt-bridge", 2),
                delivered_slot: Some(DEVNET_HEIGHT.saturating_add(8)),
                observed_latency_ms: Some(82),
                availability_bps: 9_650,
                repair_count: 1,
                sample_count: 32,
                qos_nullifier: dev_hash("qos-nullifier-bridge", 2),
            })
            .expect("score bridge qos");
        state.refresh_roots();
        state
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.lane_root = merkle_records(D_LANES, &self.public_lane_records());
        self.roots.witness_delta_root = merkle_records(D_DELTAS, &self.public_delta_records());
        self.roots.latency_bid_root = merkle_records(D_BIDS, &self.public_bid_records());
        self.roots.pq_attestation_root =
            merkle_records(D_ATTESTATIONS, &self.public_attestation_records());
        self.roots.receipt_delta_qos_root = merkle_records(D_QOS, &self.public_qos_records());
        self.roots.schedule_root = merkle_records(D_SCHEDULES, &self.public_schedule_records());
        self.roots.nullifier_root = set_root(D_PUBLIC, &self.consumed_nullifiers);
        self.roots.public_record_root = merkle_root(D_PUBLIC, &self.public_records);
        self.roots.state_root = state_root_from_public_record(&self.public_record());
    }

    fn refresh_lane_scores(&mut self, lane_id: &str) -> Result<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("lane {lane_id} not found"))?;
        let lane_attestations = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.lane_id == lane_id)
            .collect::<Vec<_>>();
        if !lane_attestations.is_empty() {
            let total = lane_attestations.iter().fold(0_u64, |acc, attestation| {
                acc.saturating_add(attestation.latency_band.qos_multiplier_bps())
            });
            lane.rolling_latency_score_bps = total / lane_attestations.len() as u64;
        }
        let lane_qos = self
            .receipt_delta_qos
            .values()
            .filter(|qos| qos.lane_id == lane_id)
            .collect::<Vec<_>>();
        if !lane_qos.is_empty() {
            let total_qos = lane_qos
                .iter()
                .fold(0_u64, |acc, qos| acc.saturating_add(qos.score_bps));
            let delivered = lane_qos
                .iter()
                .filter(|qos| {
                    matches!(
                        qos.latency_band,
                        LatencyBand::UltraFast | LatencyBand::Target | LatencyBand::SoftLate
                    )
                })
                .count() as u64;
            lane.rolling_qos_score_bps = total_qos / lane_qos.len() as u64;
            lane.rolling_delta_hit_bps = ratio_bps(delivered, lane_qos.len() as u64);
        }
        lane.fee_efficiency_score_bps =
            fee_efficiency_score_bps(lane.max_priority_fee_micros, &self.config);
        lane.status = if lane.rolling_qos_score_bps < self.config.min_receipt_delta_qos_bps {
            LaneStatus::Congested
        } else if lane.rolling_delta_hit_bps >= lane.target_delta_hit_bps {
            LaneStatus::Hot
        } else if lane.status == LaneStatus::Registered {
            LaneStatus::Open
        } else {
            lane.status
        };
        lane.refresh_root();
        Ok(())
    }

    fn public_lane_records(&self) -> BTreeMap<String, Value> {
        self.lanes
            .iter()
            .map(|(key, lane)| (key.clone(), lane.public_record()))
            .collect()
    }

    fn public_delta_records(&self) -> BTreeMap<String, Value> {
        self.witness_deltas
            .iter()
            .map(|(key, delta)| (key.clone(), delta.public_record()))
            .collect()
    }

    fn public_bid_records(&self) -> BTreeMap<String, Value> {
        self.latency_bids
            .iter()
            .map(|(key, bid)| (key.clone(), bid.public_record()))
            .collect()
    }

    fn public_attestation_records(&self) -> BTreeMap<String, Value> {
        self.pq_attestations
            .iter()
            .map(|(key, attestation)| (key.clone(), attestation.public_record()))
            .collect()
    }

    fn public_qos_records(&self) -> BTreeMap<String, Value> {
        self.receipt_delta_qos
            .iter()
            .map(|(key, qos)| (key.clone(), qos.public_record()))
            .collect()
    }

    fn public_schedule_records(&self) -> BTreeMap<String, Value> {
        self.schedule_decisions
            .iter()
            .map(|(key, decision)| (key.clone(), decision.public_record()))
            .collect()
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

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    payload_root(D_STATE, record)
}

pub fn witness_delta_id(input: &WitnessDeltaInput, sequence: u64) -> String {
    domain_hash(
        WITNESS_DELTA_MARKET_SUITE,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&input.lane_id),
            HashPart::Str(input.delta_kind.as_str()),
            HashPart::Str(&input.state_root_before),
            HashPart::Str(&input.state_root_after),
            HashPart::Str(&input.witness_delta_root),
            HashPart::Str(&input.receipt_delta_root),
        ],
        24,
    )
}

pub fn latency_bid_id(input: &PreconfirmationLatencyBidInput, sequence: u64) -> String {
    domain_hash(
        PRECONFIRMATION_LATENCY_BID_SUITE,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&input.lane_id),
            HashPart::Str(&input.delta_id),
            HashPart::Str(&input.bidder_commitment),
            HashPart::Str(input.bid_class.as_str()),
            HashPart::Str(&input.sealed_bid_root),
        ],
        24,
    )
}

pub fn pq_attestation_id(input: &PqLaneAttestationInput, sequence: u64) -> String {
    domain_hash(
        PQ_LANE_ATTESTATION_SUITE,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&input.lane_id),
            HashPart::Str(&input.delta_id),
            HashPart::Str(&input.attester_commitment),
            HashPart::Str(&input.pq_signature_root),
            HashPart::Str(&input.transcript_root),
        ],
        24,
    )
}

pub fn receipt_qos_id(input: &ReceiptDeltaQosInput, sequence: u64) -> String {
    domain_hash(
        RECEIPT_DELTA_QOS_SUITE,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&input.lane_id),
            HashPart::Str(&input.delta_id),
            HashPart::Str(&input.receipt_delta_root),
            HashPart::U64(input.sample_count),
        ],
        24,
    )
}

pub fn schedule_id(input: &FeeAwareScheduleInput, sequence: u64) -> String {
    domain_hash(
        FEE_AWARE_SCHEDULER_SUITE,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&input.lane_id),
            HashPart::Str(&input.delta_id),
            HashPart::U64(input.requested_slot),
            HashPart::Str(&input.scheduler_commitment),
        ],
        24,
    )
}

pub fn witness_delta_market_score(delta: &WitnessDeltaEntry, config: &Config) -> u64 {
    let privacy_bonus = if delta.privacy_set_size >= config.min_privacy_set_size.saturating_mul(2) {
        config.privacy_bonus_bps
    } else {
        0
    };
    delta
        .delta_kind
        .complexity_weight()
        .saturating_mul(8)
        .saturating_add(delta.latency_band.qos_multiplier_bps() / 2)
        .saturating_add(fee_efficiency_score_bps(delta.max_fee_micros, config) / 3)
        .saturating_add(privacy_bonus)
        .min(12_500)
}

pub fn latency_bid_score(
    lane: &ConfidentialLaneEntry,
    delta: &WitnessDeltaEntry,
    input: &PreconfirmationLatencyBidInput,
    config: &Config,
) -> u64 {
    let target = input.bid_class.target_ms(config);
    let latency_component = if input.max_latency_ms <= target {
        input.bid_class.multiplier_bps()
    } else {
        input
            .bid_class
            .multiplier_bps()
            .saturating_sub(config.congestion_penalty_bps)
    };
    let fee_component = fee_efficiency_score_bps(input.fee_cap_micros, config);
    let privacy_component = ratio_bps(input.privacy_set_size, config.min_privacy_set_size.max(1));
    lane.lane_class
        .priority_weight()
        .saturating_add(delta.delta_kind.complexity_weight())
        .saturating_add(latency_component / 2)
        .saturating_add(fee_component / 3)
        .saturating_add(privacy_component.min(config.privacy_bonus_bps))
        .min(13_000)
}

pub fn receipt_delta_qos_score(
    latency_band: LatencyBand,
    availability_bps: u64,
    repair_count: u64,
    sample_count: u64,
    config: &Config,
) -> u64 {
    let repair_penalty = repair_count
        .saturating_mul(config.missed_delta_penalty_bps)
        .saturating_div(sample_count.max(1));
    latency_band
        .qos_multiplier_bps()
        .saturating_mul(6)
        .saturating_div(10)
        .saturating_add(availability_bps.min(MAX_BPS).saturating_mul(4) / 10)
        .saturating_sub(repair_penalty)
        .min(MAX_BPS)
}

pub fn fee_aware_schedule_score(
    lane: &ConfidentialLaneEntry,
    delta: &WitnessDeltaEntry,
    bid_id: Option<&String>,
    state: &State,
    input: &FeeAwareScheduleInput,
) -> u64 {
    let bid_bonus = bid_id
        .and_then(|id| state.latency_bids.get(id))
        .map(|bid| bid.score_bps / 5)
        .unwrap_or(0);
    let reason_bonus = match input.reason {
        ScheduleReason::BridgeExitPriority if lane.lane_class == LaneClass::BridgeExit => 1_200,
        ScheduleReason::EmergencyCancelPriority
            if lane.lane_class == LaneClass::EmergencyCancel =>
        {
            1_300
        }
        ScheduleReason::FeeEfficient => state.config.low_fee_bonus_bps,
        ScheduleReason::PrivacySetGrowth
            if delta.privacy_set_size >= state.config.min_privacy_set_size.saturating_mul(2) =>
        {
            state.config.privacy_bonus_bps
        }
        ScheduleReason::ReceiptDeltaQos => 450,
        ScheduleReason::LatencyAuction => 350,
        ScheduleReason::CongestionRelief => 250,
        _ => 0,
    };
    lane.lane_class
        .priority_weight()
        .saturating_add(delta.scheduling_score_bps / 2)
        .saturating_add(lane.rolling_qos_score_bps / 4)
        .saturating_add(lane.fee_efficiency_score_bps / 4)
        .saturating_add(bid_bonus)
        .saturating_add(reason_bonus)
        .saturating_sub(
            if input.max_fee_micros < state.config.base_scheduling_fee_micros {
                state.config.congestion_penalty_bps
            } else {
                0
            },
        )
        .min(13_500)
}

pub fn assign_slot(requested_slot: u64, score_bps: u64, fee_capped: bool) -> u64 {
    if fee_capped {
        requested_slot.saturating_add(3)
    } else if score_bps >= 11_000 {
        requested_slot
    } else if score_bps >= 9_500 {
        requested_slot.saturating_add(1)
    } else {
        requested_slot.saturating_add(2)
    }
}

pub fn fee_efficiency_score_bps(max_priority_fee_micros: u64, config: &Config) -> u64 {
    if max_priority_fee_micros <= config.base_scheduling_fee_micros {
        MAX_BPS.saturating_add(config.low_fee_bonus_bps)
    } else if max_priority_fee_micros >= config.priority_fee_cap_micros {
        MAX_BPS.saturating_sub(config.congestion_penalty_bps)
    } else {
        let used_bps =
            max_priority_fee_micros.saturating_mul(MAX_BPS) / config.priority_fee_cap_micros.max(1);
        MAX_BPS.saturating_sub(used_bps / 3)
    }
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator
            .saturating_mul(MAX_BPS)
            .saturating_div(denominator)
            .min(MAX_BPS)
    }
}

pub fn merkle_records(domain: &str, records: &BTreeMap<String, Value>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn record_with_kind<T: Serialize>(kind: &str, value: &T) -> Value {
    let mut record = serde_json::to_value(value).unwrap_or_else(|_| json!({}));
    if let Some(object) = record.as_object_mut() {
        object.insert("kind".to_string(), json!(kind));
        object.insert("protocol_version".to_string(), json!(PROTOCOL_VERSION));
    }
    record
}

pub fn record_without_root<T: Serialize>(value: &T) -> Value {
    let mut record = serde_json::to_value(value).unwrap_or_else(|_| json!({}));
    if let Some(object) = record.as_object_mut() {
        object.remove("root");
    }
    record
}

fn empty_root(label: &str) -> String {
    payload_root(
        "EMPTY-PRIVATE-L2-WITNESS-DELTA-LATENCY-MARKET-ROOT",
        &json!({ "label": label }),
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

fn ensure_eq(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{field} expected {expected}, got {actual}"))
    }
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_root(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn ensure_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_nullifier_available(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    ensure_root("nullifier", nullifier)?;
    if nullifiers.contains(nullifier) {
        Err(format!("nullifier {nullifier} already consumed"))
    } else {
        Ok(())
    }
}
