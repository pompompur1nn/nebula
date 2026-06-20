use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialMicrobatchLatencyOracleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MICROBATCH_LATENCY_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-microbatch-latency-oracle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_MICROBATCH_LATENCY_ORACLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const LATENCY_ORACLE_SUITE: &str =
    "private-l2-fast-pq-confidential-microbatch-latency-oracle-v1";
pub const PRECONFIRMATION_BUCKET_SUITE: &str =
    "private-l2-fast-confidential-preconfirmation-timing-buckets-v1";
pub const RECEIPT_AVAILABILITY_SIGNAL_SUITE: &str =
    "private-l2-fast-confidential-receipt-availability-signal-v1";
pub const PQ_LANE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-confidential-lane-latency-attestation-v1";
pub const FEE_AWARE_SCHEDULING_SUITE: &str =
    "private-l2-low-fee-microbatch-latency-aware-scheduler-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-microbatch-latency-oracle-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_payloads_addresses_view_keys_receipts_lane_members_or_fee_bids";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_EPOCH: u64 = 22_144;
pub const DEVNET_HEIGHT: u64 = 6_120_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 120;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 180;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 520;
pub const DEFAULT_BUCKET_WIDTH_MS: u64 = 40;
pub const DEFAULT_BUCKET_COUNT: u16 = 16;
pub const DEFAULT_WINDOW_SLOTS: u64 = 64;
pub const DEFAULT_MAX_LANES: usize = 65_536;
pub const DEFAULT_MAX_MICROBATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_BUCKETS: usize = 262_144;
pub const DEFAULT_MAX_AVAILABILITY_SIGNALS: usize = 1_048_576;
pub const DEFAULT_MAX_LANE_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_SCHEDULING_DECISIONS: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 65_536;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MIN_RECEIPT_AVAILABILITY_BPS: u64 = 8_500;
pub const DEFAULT_MIN_SAMPLE_COUNT: u64 = 8;
pub const DEFAULT_LOW_FEE_BONUS_BPS: u64 = 600;
pub const DEFAULT_CONGESTION_PENALTY_BPS: u64 = 1_200;
pub const DEFAULT_MISSED_RECEIPT_PENALTY_BPS: u64 = 1_600;
pub const DEFAULT_PRIORITY_FEE_CAP_MICROS: u64 = 90;
pub const DEFAULT_BASE_SCHEDULING_FEE_MICROS: u64 = 3;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:LANES";
const D_MICROBATCHES: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:MICROBATCHES";
const D_BUCKETS: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:BUCKETS";
const D_SIGNALS: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:SIGNALS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:ATTESTATIONS";
const D_SCHEDULE: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:SCHEDULE";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-MICROBATCH-LATENCY-ORACLE:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    WalletFast,
    MerchantPointOfSale,
    DefiIntent,
    BridgeExit,
    ContractCall,
    OracleUpdate,
    OperatorMirror,
    EmergencyCancel,
}

impl LaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletFast => "wallet_fast",
            Self::MerchantPointOfSale => "merchant_point_of_sale",
            Self::DefiIntent => "defi_intent",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::OracleUpdate => "oracle_update",
            Self::OperatorMirror => "operator_mirror",
            Self::EmergencyCancel => "emergency_cancel",
        }
    }

    pub fn base_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_000,
            Self::BridgeExit => 9_700,
            Self::MerchantPointOfSale => 9_350,
            Self::DefiIntent => 9_100,
            Self::ContractCall => 8_850,
            Self::WalletFast => 8_600,
            Self::OracleUpdate => 7_800,
            Self::OperatorMirror => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Registered,
    Open,
    Congested,
    Draining,
    Paused,
    Quarantined,
    Retired,
}

impl LaneStatus {
    pub fn accepts_samples(self) -> bool {
        matches!(
            self,
            Self::Registered | Self::Open | Self::Congested | Self::Draining
        )
    }

    pub fn accepts_schedule(self) -> bool {
        matches!(self, Self::Registered | Self::Open | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrobatchStatus {
    Observed,
    Bucketed,
    Attested,
    Scheduled,
    Preconfirmed,
    Receipted,
    Late,
    AvailabilityMissing,
    Expired,
}

impl MicrobatchStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Receipted | Self::Late | Self::AvailabilityMissing | Self::Expired
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

    pub fn scheduling_multiplier_bps(self) -> u64 {
        match self {
            Self::UltraFast => 10_600,
            Self::Target => 10_000,
            Self::SoftLate => 8_800,
            Self::HardLate => 7_200,
            Self::Missing => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityGrade {
    Strong,
    Sufficient,
    Weak,
    Missing,
}

impl AvailabilityGrade {
    pub fn from_bps(config: &Config, availability_bps: u64) -> Self {
        if availability_bps >= config.strong_quorum_weight_bps {
            Self::Strong
        } else if availability_bps >= config.min_receipt_availability_bps {
            Self::Sufficient
        } else if availability_bps > 0 {
            Self::Weak
        } else {
            Self::Missing
        }
    }

    pub fn multiplier_bps(self) -> u64 {
        match self {
            Self::Strong => 10_500,
            Self::Sufficient => 10_000,
            Self::Weak => 7_700,
            Self::Missing => 5_000,
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
pub enum SchedulingReason {
    LowLatency,
    ReceiptAvailability,
    FeeEfficient,
    CongestionRelief,
    PrivacySetGrowth,
    BridgeExitPriority,
    EmergencyCancelPriority,
}

impl SchedulingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowLatency => "low_latency",
            Self::ReceiptAvailability => "receipt_availability",
            Self::FeeEfficient => "fee_efficient",
            Self::CongestionRelief => "congestion_relief",
            Self::PrivacySetGrowth => "privacy_set_growth",
            Self::BridgeExitPriority => "bridge_exit_priority",
            Self::EmergencyCancelPriority => "emergency_cancel_priority",
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
    pub latency_oracle_suite: String,
    pub preconfirmation_bucket_suite: String,
    pub receipt_availability_signal_suite: String,
    pub pq_lane_attestation_suite: String,
    pub fee_aware_scheduling_suite: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub slot_width_ms: u64,
    pub target_preconfirmation_ms: u64,
    pub soft_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub bucket_width_ms: u64,
    pub bucket_count: u16,
    pub window_slots: u64,
    pub max_lanes: usize,
    pub max_microbatches: usize,
    pub max_buckets: usize,
    pub max_availability_signals: usize,
    pub max_lane_attestations: usize,
    pub max_scheduling_decisions: usize,
    pub max_public_records: usize,
    pub quorum_weight_bps: u64,
    pub strong_quorum_weight_bps: u64,
    pub min_receipt_availability_bps: u64,
    pub min_sample_count: u64,
    pub low_fee_bonus_bps: u64,
    pub congestion_penalty_bps: u64,
    pub missed_receipt_penalty_bps: u64,
    pub priority_fee_cap_micros: u64,
    pub base_scheduling_fee_micros: u64,
    pub require_pq_lane_attestations: bool,
    pub require_receipt_availability_signals: bool,
    pub require_fee_aware_scheduling: bool,
    pub require_privacy_preserving_records: bool,
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
            latency_oracle_suite: LATENCY_ORACLE_SUITE.to_string(),
            preconfirmation_bucket_suite: PRECONFIRMATION_BUCKET_SUITE.to_string(),
            receipt_availability_signal_suite: RECEIPT_AVAILABILITY_SIGNAL_SUITE.to_string(),
            pq_lane_attestation_suite: PQ_LANE_ATTESTATION_SUITE.to_string(),
            fee_aware_scheduling_suite: FEE_AWARE_SCHEDULING_SUITE.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            bucket_width_ms: DEFAULT_BUCKET_WIDTH_MS,
            bucket_count: DEFAULT_BUCKET_COUNT,
            window_slots: DEFAULT_WINDOW_SLOTS,
            max_lanes: DEFAULT_MAX_LANES,
            max_microbatches: DEFAULT_MAX_MICROBATCHES,
            max_buckets: DEFAULT_MAX_BUCKETS,
            max_availability_signals: DEFAULT_MAX_AVAILABILITY_SIGNALS,
            max_lane_attestations: DEFAULT_MAX_LANE_ATTESTATIONS,
            max_scheduling_decisions: DEFAULT_MAX_SCHEDULING_DECISIONS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            min_receipt_availability_bps: DEFAULT_MIN_RECEIPT_AVAILABILITY_BPS,
            min_sample_count: DEFAULT_MIN_SAMPLE_COUNT,
            low_fee_bonus_bps: DEFAULT_LOW_FEE_BONUS_BPS,
            congestion_penalty_bps: DEFAULT_CONGESTION_PENALTY_BPS,
            missed_receipt_penalty_bps: DEFAULT_MISSED_RECEIPT_PENALTY_BPS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            base_scheduling_fee_micros: DEFAULT_BASE_SCHEDULING_FEE_MICROS,
            require_pq_lane_attestations: true,
            require_receipt_availability_signals: true,
            require_fee_aware_scheduling: true,
            require_privacy_preserving_records: true,
            require_deterministic_roots: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain_id does not match crate CHAIN_ID".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unexpected protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unexpected schema version".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min pq security bits below runtime floor".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("min privacy set size must be nonzero".to_string());
        }
        if self.slot_width_ms == 0 || self.bucket_width_ms == 0 {
            return Err("slot and bucket widths must be nonzero".to_string());
        }
        if self.target_preconfirmation_ms > self.soft_latency_ms
            || self.soft_latency_ms > self.hard_latency_ms
        {
            return Err("latency thresholds must be monotonic".to_string());
        }
        if self.bucket_count == 0 || self.window_slots == 0 {
            return Err("bucket_count and window_slots must be nonzero".to_string());
        }
        if self.quorum_weight_bps > MAX_BPS
            || self.strong_quorum_weight_bps > MAX_BPS
            || self.min_receipt_availability_bps > MAX_BPS
        {
            return Err("basis point thresholds exceed MAX_BPS".to_string());
        }
        if self.quorum_weight_bps > self.strong_quorum_weight_bps {
            return Err("quorum threshold cannot exceed strong quorum threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_lane_index: u64,
    pub next_microbatch_index: u64,
    pub next_bucket_index: u64,
    pub next_signal_index: u64,
    pub next_attestation_index: u64,
    pub next_schedule_index: u64,
    pub observed_microbatches: u64,
    pub preconfirmed_microbatches: u64,
    pub late_microbatches: u64,
    pub missing_receipts: u64,
    pub pq_verified_attestations: u64,
    pub fee_capped_decisions: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self {
            next_lane_index: 1,
            next_microbatch_index: 1,
            next_bucket_index: 1,
            next_signal_index: 1,
            next_attestation_index: 1,
            next_schedule_index: 1,
            observed_microbatches: 0,
            preconfirmed_microbatches: 0,
            late_microbatches: 0,
            missing_receipts: 0,
            pq_verified_attestations: 0,
            fee_capped_decisions: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lanes_root: String,
    pub microbatches_root: String,
    pub buckets_root: String,
    pub availability_signals_root: String,
    pub lane_attestations_root: String,
    pub scheduling_decisions_root: String,
    pub public_records_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        Self {
            config_root: payload_root(D_CONFIG, &config.public_record()),
            counters_root: payload_root(D_COUNTERS, &counters.public_record()),
            lanes_root: merkle_root(D_LANES, &[]),
            microbatches_root: merkle_root(D_MICROBATCHES, &[]),
            buckets_root: merkle_root(D_BUCKETS, &[]),
            availability_signals_root: merkle_root(D_SIGNALS, &[]),
            lane_attestations_root: merkle_root(D_ATTESTATIONS, &[]),
            scheduling_decisions_root: merkle_root(D_SCHEDULE, &[]),
            public_records_root: merkle_root(D_PUBLIC, &[]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneRegistrationInput {
    pub lane_id: String,
    pub class: LaneClass,
    pub operator_commitment: String,
    pub encrypted_lane_root: String,
    pub pq_verifying_key_commitment: String,
    pub initial_privacy_set_size: u64,
    pub max_priority_fee_micros: u64,
    pub slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialLaneEntry {
    pub lane_id: String,
    pub lane_index: u64,
    pub class: LaneClass,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub encrypted_lane_root: String,
    pub pq_verifying_key_commitment: String,
    pub privacy_set_size: u64,
    pub max_priority_fee_micros: u64,
    pub registered_slot: u64,
    pub latest_bucket_id: Option<String>,
    pub latest_availability_signal_id: Option<String>,
    pub latest_attestation_id: Option<String>,
    pub rolling_latency_score_bps: u64,
    pub rolling_availability_bps: u64,
    pub fee_efficiency_score_bps: u64,
    pub lane_record_root: String,
}

impl ConfidentialLaneEntry {
    pub fn from_input(index: u64, input: LaneRegistrationInput, config: &Config) -> Result<Self> {
        if input.lane_id.is_empty() {
            return Err("lane_id is required".to_string());
        }
        if input.operator_commitment.is_empty()
            || input.encrypted_lane_root.is_empty()
            || input.pq_verifying_key_commitment.is_empty()
        {
            return Err("lane commitments are required".to_string());
        }
        if input.initial_privacy_set_size < config.min_privacy_set_size {
            return Err("lane privacy set below config minimum".to_string());
        }
        let mut entry = Self {
            lane_id: input.lane_id,
            lane_index: index,
            class: input.class,
            status: LaneStatus::Registered,
            operator_commitment: input.operator_commitment,
            encrypted_lane_root: input.encrypted_lane_root,
            pq_verifying_key_commitment: input.pq_verifying_key_commitment,
            privacy_set_size: input.initial_privacy_set_size,
            max_priority_fee_micros: input.max_priority_fee_micros,
            registered_slot: input.slot,
            latest_bucket_id: None,
            latest_availability_signal_id: None,
            latest_attestation_id: None,
            rolling_latency_score_bps: MAX_BPS,
            rolling_availability_bps: MAX_BPS,
            fee_efficiency_score_bps: MAX_BPS,
            lane_record_root: String::new(),
        };
        entry.refresh_root();
        Ok(entry)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn refresh_root(&mut self) {
        self.lane_record_root = payload_root(
            D_LANES,
            &json!({
                "lane_id": self.lane_id,
                "lane_index": self.lane_index,
                "class": self.class.as_str(),
                "status": self.status,
                "operator_commitment": self.operator_commitment,
                "encrypted_lane_root": self.encrypted_lane_root,
                "pq_verifying_key_commitment": self.pq_verifying_key_commitment,
                "privacy_set_size": self.privacy_set_size,
                "max_priority_fee_micros": self.max_priority_fee_micros,
                "rolling_latency_score_bps": self.rolling_latency_score_bps,
                "rolling_availability_bps": self.rolling_availability_bps,
            }),
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MicrobatchObservationInput {
    pub microbatch_id: String,
    pub lane_id: String,
    pub sealed_payload_root: String,
    pub encrypted_receipt_root: String,
    pub observed_slot: u64,
    pub observed_at_ms: u64,
    pub preconfirmed_at_ms: Option<u64>,
    pub item_count: u32,
    pub byte_count: u64,
    pub offered_fee_micros: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MicrobatchLatencyEntry {
    pub microbatch_id: String,
    pub microbatch_index: u64,
    pub lane_id: String,
    pub status: MicrobatchStatus,
    pub sealed_payload_root: String,
    pub encrypted_receipt_root: String,
    pub observed_slot: u64,
    pub observed_at_ms: u64,
    pub preconfirmed_at_ms: Option<u64>,
    pub latency_ms: Option<u64>,
    pub latency_band: LatencyBand,
    pub bucket_id: String,
    pub item_count: u32,
    pub byte_count: u64,
    pub offered_fee_micros: u64,
    pub privacy_set_size: u64,
    pub availability_signal_id: Option<String>,
    pub attestation_ids: BTreeSet<String>,
    pub microbatch_record_root: String,
}

impl MicrobatchLatencyEntry {
    pub fn from_input(
        index: u64,
        bucket_id: String,
        input: MicrobatchObservationInput,
        config: &Config,
    ) -> Result<Self> {
        if input.microbatch_id.is_empty() || input.lane_id.is_empty() {
            return Err("microbatch_id and lane_id are required".to_string());
        }
        if input.sealed_payload_root.is_empty() || input.encrypted_receipt_root.is_empty() {
            return Err("sealed payload and receipt roots are required".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("microbatch privacy set below config minimum".to_string());
        }
        let latency_ms = input
            .preconfirmed_at_ms
            .map(|confirmed| confirmed.saturating_sub(input.observed_at_ms));
        let latency_band = LatencyBand::from_latency_ms(config, latency_ms);
        let status = if input.preconfirmed_at_ms.is_some() {
            MicrobatchStatus::Preconfirmed
        } else {
            MicrobatchStatus::Observed
        };
        let mut entry = Self {
            microbatch_id: input.microbatch_id,
            microbatch_index: index,
            lane_id: input.lane_id,
            status,
            sealed_payload_root: input.sealed_payload_root,
            encrypted_receipt_root: input.encrypted_receipt_root,
            observed_slot: input.observed_slot,
            observed_at_ms: input.observed_at_ms,
            preconfirmed_at_ms: input.preconfirmed_at_ms,
            latency_ms,
            latency_band,
            bucket_id,
            item_count: input.item_count,
            byte_count: input.byte_count,
            offered_fee_micros: input.offered_fee_micros,
            privacy_set_size: input.privacy_set_size,
            availability_signal_id: None,
            attestation_ids: BTreeSet::new(),
            microbatch_record_root: String::new(),
        };
        entry.refresh_root();
        Ok(entry)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn refresh_root(&mut self) {
        self.microbatch_record_root = payload_root(
            D_MICROBATCHES,
            &json!({
                "microbatch_id": self.microbatch_id,
                "microbatch_index": self.microbatch_index,
                "lane_id": self.lane_id,
                "status": self.status,
                "sealed_payload_root": self.sealed_payload_root,
                "encrypted_receipt_root": self.encrypted_receipt_root,
                "observed_slot": self.observed_slot,
                "latency_ms": self.latency_ms,
                "latency_band": self.latency_band.as_str(),
                "bucket_id": self.bucket_id,
                "offered_fee_micros": self.offered_fee_micros,
                "privacy_set_size": self.privacy_set_size,
            }),
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationTimingBucket {
    pub bucket_id: String,
    pub bucket_index: u64,
    pub lane_id: String,
    pub window_start_slot: u64,
    pub window_end_slot: u64,
    pub lower_bound_ms: u64,
    pub upper_bound_ms: u64,
    pub latency_band: LatencyBand,
    pub sample_count: u64,
    pub preconfirmed_count: u64,
    pub late_count: u64,
    pub missing_count: u64,
    pub total_latency_ms: u128,
    pub max_latency_ms: u64,
    pub fee_weighted_score_bps: u64,
    pub bucket_commitment_root: String,
}

impl PreconfirmationTimingBucket {
    pub fn new(index: u64, lane_id: &str, slot: u64, band: LatencyBand, config: &Config) -> Self {
        let window_start_slot = (slot / config.window_slots) * config.window_slots;
        let lower_bound_ms = match band {
            LatencyBand::UltraFast => 0,
            LatencyBand::Target => config.target_preconfirmation_ms / 2 + 1,
            LatencyBand::SoftLate => config.target_preconfirmation_ms + 1,
            LatencyBand::HardLate => config.soft_latency_ms + 1,
            LatencyBand::Missing => config.hard_latency_ms + 1,
        };
        let upper_bound_ms = match band {
            LatencyBand::UltraFast => config.target_preconfirmation_ms / 2,
            LatencyBand::Target => config.target_preconfirmation_ms,
            LatencyBand::SoftLate => config.soft_latency_ms,
            LatencyBand::HardLate => config.hard_latency_ms,
            LatencyBand::Missing => u64::MAX,
        };
        let bucket_id = bucket_id(lane_id, window_start_slot, band);
        let mut bucket = Self {
            bucket_id,
            bucket_index: index,
            lane_id: lane_id.to_string(),
            window_start_slot,
            window_end_slot: window_start_slot + config.window_slots - 1,
            lower_bound_ms,
            upper_bound_ms,
            latency_band: band,
            sample_count: 0,
            preconfirmed_count: 0,
            late_count: 0,
            missing_count: 0,
            total_latency_ms: 0,
            max_latency_ms: 0,
            fee_weighted_score_bps: 0,
            bucket_commitment_root: String::new(),
        };
        bucket.refresh_root();
        bucket
    }

    pub fn observe(&mut self, latency_ms: Option<u64>, offered_fee_micros: u64, config: &Config) {
        self.sample_count = self.sample_count.saturating_add(1);
        match latency_ms {
            Some(ms) => {
                self.preconfirmed_count = self.preconfirmed_count.saturating_add(1);
                self.total_latency_ms = self.total_latency_ms.saturating_add(ms as u128);
                self.max_latency_ms = self.max_latency_ms.max(ms);
                if ms > config.target_preconfirmation_ms {
                    self.late_count = self.late_count.saturating_add(1);
                }
            }
            None => {
                self.missing_count = self.missing_count.saturating_add(1);
            }
        }
        self.fee_weighted_score_bps =
            fee_weighted_score_bps(self.latency_band, offered_fee_micros, config);
        self.refresh_root();
    }

    pub fn average_latency_ms(&self) -> Option<u64> {
        if self.preconfirmed_count == 0 {
            None
        } else {
            Some((self.total_latency_ms / self.preconfirmed_count as u128) as u64)
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn refresh_root(&mut self) {
        self.bucket_commitment_root = payload_root(
            D_BUCKETS,
            &json!({
                "bucket_id": self.bucket_id,
                "bucket_index": self.bucket_index,
                "lane_id": self.lane_id,
                "window_start_slot": self.window_start_slot,
                "window_end_slot": self.window_end_slot,
                "latency_band": self.latency_band.as_str(),
                "sample_count": self.sample_count,
                "preconfirmed_count": self.preconfirmed_count,
                "late_count": self.late_count,
                "missing_count": self.missing_count,
                "average_latency_ms": self.average_latency_ms(),
                "fee_weighted_score_bps": self.fee_weighted_score_bps,
            }),
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptAvailabilitySignalInput {
    pub signal_id: String,
    pub microbatch_id: String,
    pub lane_id: String,
    pub receipt_commitment_root: String,
    pub availability_bitmap_root: String,
    pub available_receipts: u64,
    pub expected_receipts: u64,
    pub reporting_slot: u64,
    pub reporter_set_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptAvailabilitySignal {
    pub signal_id: String,
    pub signal_index: u64,
    pub microbatch_id: String,
    pub lane_id: String,
    pub receipt_commitment_root: String,
    pub availability_bitmap_root: String,
    pub available_receipts: u64,
    pub expected_receipts: u64,
    pub availability_bps: u64,
    pub grade: AvailabilityGrade,
    pub reporting_slot: u64,
    pub reporter_set_commitment: String,
    pub signal_root: String,
}

impl ReceiptAvailabilitySignal {
    pub fn from_input(
        index: u64,
        input: ReceiptAvailabilitySignalInput,
        config: &Config,
    ) -> Result<Self> {
        if input.signal_id.is_empty() || input.microbatch_id.is_empty() || input.lane_id.is_empty()
        {
            return Err("signal_id, microbatch_id, and lane_id are required".to_string());
        }
        if input.expected_receipts == 0 {
            return Err("expected_receipts must be nonzero".to_string());
        }
        if input.available_receipts > input.expected_receipts {
            return Err("available_receipts cannot exceed expected_receipts".to_string());
        }
        let availability_bps =
            input.available_receipts.saturating_mul(MAX_BPS) / input.expected_receipts.max(1);
        let grade = AvailabilityGrade::from_bps(config, availability_bps);
        let mut signal = Self {
            signal_id: input.signal_id,
            signal_index: index,
            microbatch_id: input.microbatch_id,
            lane_id: input.lane_id,
            receipt_commitment_root: input.receipt_commitment_root,
            availability_bitmap_root: input.availability_bitmap_root,
            available_receipts: input.available_receipts,
            expected_receipts: input.expected_receipts,
            availability_bps,
            grade,
            reporting_slot: input.reporting_slot,
            reporter_set_commitment: input.reporter_set_commitment,
            signal_root: String::new(),
        };
        signal.refresh_root();
        Ok(signal)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn refresh_root(&mut self) {
        self.signal_root = payload_root(
            D_SIGNALS,
            &json!({
                "signal_id": self.signal_id,
                "signal_index": self.signal_index,
                "microbatch_id": self.microbatch_id,
                "lane_id": self.lane_id,
                "receipt_commitment_root": self.receipt_commitment_root,
                "availability_bitmap_root": self.availability_bitmap_root,
                "availability_bps": self.availability_bps,
                "grade": self.grade,
                "reporting_slot": self.reporting_slot,
                "reporter_set_commitment": self.reporter_set_commitment,
            }),
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqLaneAttestationInput {
    pub attestation_id: String,
    pub lane_id: String,
    pub microbatch_id: String,
    pub bucket_id: String,
    pub signer_commitment: String,
    pub lane_statement_root: String,
    pub pq_signature_root: String,
    pub attested_latency_ms: Option<u64>,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub attestation_index: u64,
    pub lane_id: String,
    pub microbatch_id: String,
    pub bucket_id: String,
    pub signer_commitment: String,
    pub lane_statement_root: String,
    pub pq_signature_root: String,
    pub attested_latency_ms: Option<u64>,
    pub latency_band: LatencyBand,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub status: AttestationStatus,
    pub slot: u64,
    pub attestation_root: String,
}

impl PqLaneAttestation {
    pub fn from_input(index: u64, input: PqLaneAttestationInput, config: &Config) -> Result<Self> {
        if input.attestation_id.is_empty()
            || input.lane_id.is_empty()
            || input.microbatch_id.is_empty()
            || input.bucket_id.is_empty()
        {
            return Err("attestation identifiers are required".to_string());
        }
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("attestation pq security below config minimum".to_string());
        }
        if input.quorum_weight_bps > MAX_BPS {
            return Err("attestation quorum weight exceeds MAX_BPS".to_string());
        }
        let latency_band = LatencyBand::from_latency_ms(config, input.attested_latency_ms);
        let status = if input.quorum_weight_bps >= config.quorum_weight_bps {
            AttestationStatus::QuorumCounted
        } else {
            AttestationStatus::PqVerified
        };
        let mut attestation = Self {
            attestation_id: input.attestation_id,
            attestation_index: index,
            lane_id: input.lane_id,
            microbatch_id: input.microbatch_id,
            bucket_id: input.bucket_id,
            signer_commitment: input.signer_commitment,
            lane_statement_root: input.lane_statement_root,
            pq_signature_root: input.pq_signature_root,
            attested_latency_ms: input.attested_latency_ms,
            latency_band,
            quorum_weight_bps: input.quorum_weight_bps,
            pq_security_bits: input.pq_security_bits,
            status,
            slot: input.slot,
            attestation_root: String::new(),
        };
        attestation.refresh_root();
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn refresh_root(&mut self) {
        self.attestation_root = payload_root(
            D_ATTESTATIONS,
            &json!({
                "attestation_id": self.attestation_id,
                "attestation_index": self.attestation_index,
                "lane_id": self.lane_id,
                "microbatch_id": self.microbatch_id,
                "bucket_id": self.bucket_id,
                "signer_commitment": self.signer_commitment,
                "lane_statement_root": self.lane_statement_root,
                "pq_signature_root": self.pq_signature_root,
                "attested_latency_ms": self.attested_latency_ms,
                "latency_band": self.latency_band.as_str(),
                "quorum_weight_bps": self.quorum_weight_bps,
                "pq_security_bits": self.pq_security_bits,
                "status": self.status,
                "slot": self.slot,
            }),
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeAwareSchedulingInput {
    pub schedule_id: String,
    pub lane_id: String,
    pub microbatch_id: String,
    pub requested_slot: u64,
    pub max_fee_micros: u64,
    pub reason: SchedulingReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeAwareSchedulingDecision {
    pub schedule_id: String,
    pub schedule_index: u64,
    pub lane_id: String,
    pub microbatch_id: String,
    pub requested_slot: u64,
    pub assigned_slot: u64,
    pub max_fee_micros: u64,
    pub charged_fee_micros: u64,
    pub scheduling_score_bps: u64,
    pub reason: SchedulingReason,
    pub fee_capped: bool,
    pub schedule_root: String,
}

impl FeeAwareSchedulingDecision {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn refresh_root(&mut self) {
        self.schedule_root = payload_root(
            D_SCHEDULE,
            &json!({
                "schedule_id": self.schedule_id,
                "schedule_index": self.schedule_index,
                "lane_id": self.lane_id,
                "microbatch_id": self.microbatch_id,
                "requested_slot": self.requested_slot,
                "assigned_slot": self.assigned_slot,
                "charged_fee_micros": self.charged_fee_micros,
                "scheduling_score_bps": self.scheduling_score_bps,
                "reason": self.reason.as_str(),
                "fee_capped": self.fee_capped,
            }),
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub epoch: u64,
    pub height: u64,
    pub current_slot: u64,
    pub lanes: BTreeMap<String, ConfidentialLaneEntry>,
    pub microbatches: BTreeMap<String, MicrobatchLatencyEntry>,
    pub timing_buckets: BTreeMap<String, PreconfirmationTimingBucket>,
    pub availability_signals: BTreeMap<String, ReceiptAvailabilitySignal>,
    pub lane_attestations: BTreeMap<String, PqLaneAttestation>,
    pub scheduling_decisions: BTreeMap<String, FeeAwareSchedulingDecision>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let counters = Counters::devnet();
        let roots = Roots::empty(&config, &counters);
        Ok(Self {
            config,
            counters,
            roots,
            epoch: DEVNET_EPOCH,
            height: DEVNET_HEIGHT,
            current_slot: 0,
            lanes: BTreeMap::new(),
            microbatches: BTreeMap::new(),
            timing_buckets: BTreeMap::new(),
            availability_signals: BTreeMap::new(),
            lane_attestations: BTreeMap::new(),
            scheduling_decisions: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet config is valid");
        state.current_slot = 1_024;
        state.seed_devnet();
        state.refresh_roots();
        state
    }

    pub fn register_lane(&mut self, input: LaneRegistrationInput) -> Result<String> {
        self.ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        if self.lanes.contains_key(&input.lane_id) {
            return Err("lane already registered".to_string());
        }
        let lane_id = input.lane_id.clone();
        let lane =
            ConfidentialLaneEntry::from_input(self.counters.next_lane_index, input, &self.config)?;
        self.counters.next_lane_index = self.counters.next_lane_index.saturating_add(1);
        self.lanes.insert(lane_id.clone(), lane);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn observe_microbatch(&mut self, input: MicrobatchObservationInput) -> Result<String> {
        self.ensure_capacity(
            self.microbatches.len(),
            self.config.max_microbatches,
            "microbatches",
        )?;
        if self.microbatches.contains_key(&input.microbatch_id) {
            return Err("microbatch already observed".to_string());
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| "lane not registered".to_string())?;
        if !lane.status.accepts_samples() {
            return Err("lane does not accept latency samples".to_string());
        }
        let latency = input
            .preconfirmed_at_ms
            .map(|confirmed| confirmed.saturating_sub(input.observed_at_ms));
        let band = LatencyBand::from_latency_ms(&self.config, latency);
        let bucket_key = bucket_id(
            &input.lane_id,
            window_start(input.observed_slot, &self.config),
            band,
        );
        if !self.timing_buckets.contains_key(&bucket_key) {
            self.ensure_capacity(
                self.timing_buckets.len(),
                self.config.max_buckets,
                "timing buckets",
            )?;
            let bucket = PreconfirmationTimingBucket::new(
                self.counters.next_bucket_index,
                &input.lane_id,
                input.observed_slot,
                band,
                &self.config,
            );
            self.counters.next_bucket_index = self.counters.next_bucket_index.saturating_add(1);
            self.timing_buckets.insert(bucket_key.clone(), bucket);
        }
        let microbatch_id = input.microbatch_id.clone();
        let lane_id = input.lane_id.clone();
        let offered_fee_micros = input.offered_fee_micros;
        let entry = MicrobatchLatencyEntry::from_input(
            self.counters.next_microbatch_index,
            bucket_key.clone(),
            input,
            &self.config,
        )?;
        self.counters.next_microbatch_index = self.counters.next_microbatch_index.saturating_add(1);
        self.counters.observed_microbatches = self.counters.observed_microbatches.saturating_add(1);
        if latency.is_some() {
            self.counters.preconfirmed_microbatches =
                self.counters.preconfirmed_microbatches.saturating_add(1);
        }
        if matches!(
            band,
            LatencyBand::SoftLate | LatencyBand::HardLate | LatencyBand::Missing
        ) {
            self.counters.late_microbatches = self.counters.late_microbatches.saturating_add(1);
        }
        self.timing_buckets
            .get_mut(&bucket_key)
            .expect("bucket exists")
            .observe(latency, offered_fee_micros, &self.config);
        self.microbatches.insert(microbatch_id.clone(), entry);
        self.update_lane_scores(&lane_id)?;
        self.refresh_roots();
        Ok(microbatch_id)
    }

    pub fn submit_availability_signal(
        &mut self,
        input: ReceiptAvailabilitySignalInput,
    ) -> Result<String> {
        self.ensure_capacity(
            self.availability_signals.len(),
            self.config.max_availability_signals,
            "availability signals",
        )?;
        if self.availability_signals.contains_key(&input.signal_id) {
            return Err("availability signal already exists".to_string());
        }
        let microbatch_id = input.microbatch_id.clone();
        let lane_id = input.lane_id.clone();
        if !self.microbatches.contains_key(&microbatch_id) {
            return Err("microbatch not observed".to_string());
        }
        let signal = ReceiptAvailabilitySignal::from_input(
            self.counters.next_signal_index,
            input,
            &self.config,
        )?;
        let signal_id = signal.signal_id.clone();
        if matches!(
            signal.grade,
            AvailabilityGrade::Missing | AvailabilityGrade::Weak
        ) {
            self.counters.missing_receipts = self.counters.missing_receipts.saturating_add(1);
        }
        self.counters.next_signal_index = self.counters.next_signal_index.saturating_add(1);
        self.microbatches
            .get_mut(&microbatch_id)
            .expect("microbatch exists")
            .availability_signal_id = Some(signal_id.clone());
        self.availability_signals.insert(signal_id.clone(), signal);
        self.update_lane_scores(&lane_id)?;
        self.refresh_roots();
        Ok(signal_id)
    }

    pub fn submit_lane_attestation(&mut self, input: PqLaneAttestationInput) -> Result<String> {
        self.ensure_capacity(
            self.lane_attestations.len(),
            self.config.max_lane_attestations,
            "lane attestations",
        )?;
        if self.lane_attestations.contains_key(&input.attestation_id) {
            return Err("lane attestation already exists".to_string());
        }
        let microbatch = self
            .microbatches
            .get(&input.microbatch_id)
            .ok_or_else(|| "microbatch not observed".to_string())?;
        if microbatch.lane_id != input.lane_id {
            return Err("attestation lane does not match microbatch lane".to_string());
        }
        if microbatch.bucket_id != input.bucket_id {
            return Err("attestation bucket does not match microbatch bucket".to_string());
        }
        let attestation = PqLaneAttestation::from_input(
            self.counters.next_attestation_index,
            input,
            &self.config,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        let lane_id = attestation.lane_id.clone();
        let microbatch_id = attestation.microbatch_id.clone();
        if matches!(
            attestation.status,
            AttestationStatus::PqVerified | AttestationStatus::QuorumCounted
        ) {
            self.counters.pq_verified_attestations =
                self.counters.pq_verified_attestations.saturating_add(1);
        }
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.microbatches
            .get_mut(&microbatch_id)
            .expect("microbatch exists")
            .attestation_ids
            .insert(attestation_id.clone());
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.latest_attestation_id = Some(attestation_id.clone());
            lane.refresh_root();
        }
        self.lane_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn schedule_microbatch(&mut self, input: FeeAwareSchedulingInput) -> Result<String> {
        self.ensure_capacity(
            self.scheduling_decisions.len(),
            self.config.max_scheduling_decisions,
            "scheduling decisions",
        )?;
        if self.scheduling_decisions.contains_key(&input.schedule_id) {
            return Err("schedule decision already exists".to_string());
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| "lane not registered".to_string())?;
        if !lane.status.accepts_schedule() {
            return Err("lane does not accept scheduling".to_string());
        }
        let microbatch = self
            .microbatches
            .get(&input.microbatch_id)
            .ok_or_else(|| "microbatch not observed".to_string())?;
        if microbatch.lane_id != input.lane_id {
            return Err("schedule lane does not match microbatch lane".to_string());
        }
        let score = scheduling_score_bps(lane, microbatch, &input, &self.config);
        let lane_fee_cap = lane
            .max_priority_fee_micros
            .min(self.config.priority_fee_cap_micros);
        let charged_fee_micros = self
            .config
            .base_scheduling_fee_micros
            .saturating_add(microbatch.offered_fee_micros.min(lane_fee_cap));
        let fee_capped = charged_fee_micros > input.max_fee_micros;
        if fee_capped {
            self.counters.fee_capped_decisions =
                self.counters.fee_capped_decisions.saturating_add(1);
        }
        let assigned_slot = assign_slot(input.requested_slot, score, fee_capped);
        let mut decision = FeeAwareSchedulingDecision {
            schedule_id: input.schedule_id,
            schedule_index: self.counters.next_schedule_index,
            lane_id: input.lane_id,
            microbatch_id: input.microbatch_id,
            requested_slot: input.requested_slot,
            assigned_slot,
            max_fee_micros: input.max_fee_micros,
            charged_fee_micros: charged_fee_micros.min(input.max_fee_micros),
            scheduling_score_bps: score,
            reason: input.reason,
            fee_capped,
            schedule_root: String::new(),
        };
        decision.refresh_root();
        let schedule_id = decision.schedule_id.clone();
        self.counters.next_schedule_index = self.counters.next_schedule_index.saturating_add(1);
        if let Some(microbatch) = self.microbatches.get_mut(&decision.microbatch_id) {
            microbatch.status = MicrobatchStatus::Scheduled;
            microbatch.refresh_root();
        }
        self.scheduling_decisions
            .insert(schedule_id.clone(), decision);
        self.refresh_roots();
        Ok(schedule_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "privacy_boundary": PRIVACY_BOUNDARY,
            "epoch": self.epoch,
            "height": self.height,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "lane_count": self.lanes.len(),
            "microbatch_count": self.microbatches.len(),
            "timing_bucket_count": self.timing_buckets.len(),
            "availability_signal_count": self.availability_signals.len(),
            "lane_attestation_count": self.lane_attestations.len(),
            "scheduling_decision_count": self.scheduling_decisions.len(),
            "lane_summaries": self.lanes.values().map(|lane| lane.public_record()).collect::<Vec<_>>(),
            "timing_bucket_summaries": self.timing_buckets.values().map(|bucket| bucket.public_record()).collect::<Vec<_>>(),
            "availability_signal_summaries": self.availability_signals.values().map(|signal| signal.public_record()).collect::<Vec<_>>(),
            "scheduling_decision_summaries": self.scheduling_decisions.values().map(|decision| decision.public_record()).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: payload_root(D_CONFIG, &self.config.public_record()),
            counters_root: payload_root(D_COUNTERS, &self.counters.public_record()),
            lanes_root: merkle_records(D_LANES, &self.public_lane_records()),
            microbatches_root: merkle_records(D_MICROBATCHES, &self.public_microbatch_records()),
            buckets_root: merkle_records(D_BUCKETS, &self.public_bucket_records()),
            availability_signals_root: merkle_records(D_SIGNALS, &self.public_signal_records()),
            lane_attestations_root: merkle_records(
                D_ATTESTATIONS,
                &self.public_attestation_records(),
            ),
            scheduling_decisions_root: merkle_records(D_SCHEDULE, &self.public_schedule_records()),
            public_records_root: merkle_records(D_PUBLIC, &self.public_records),
        };
        self.public_records
            .insert("latest_state".to_string(), self.public_record());
    }

    fn seed_devnet(&mut self) {
        for (lane_id, class, index) in [
            ("lane-wallet-fast-devnet", LaneClass::WalletFast, 1),
            (
                "lane-merchant-pos-devnet",
                LaneClass::MerchantPointOfSale,
                2,
            ),
            ("lane-bridge-exit-devnet", LaneClass::BridgeExit, 3),
        ] {
            let _ = self.register_lane(LaneRegistrationInput {
                lane_id: lane_id.to_string(),
                class,
                operator_commitment: dev_hash("operator", index),
                encrypted_lane_root: dev_hash("encrypted-lane", index),
                pq_verifying_key_commitment: dev_hash("pq-key", index),
                initial_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE + index * 65_536,
                max_priority_fee_micros: 18 + index,
                slot: self.current_slot,
            });
        }
        for (index, lane_id, latency_ms, reason) in [
            (
                1,
                "lane-wallet-fast-devnet",
                74,
                SchedulingReason::LowLatency,
            ),
            (
                2,
                "lane-merchant-pos-devnet",
                118,
                SchedulingReason::FeeEfficient,
            ),
            (
                3,
                "lane-bridge-exit-devnet",
                164,
                SchedulingReason::BridgeExitPriority,
            ),
        ] {
            self.seed_devnet_microbatch(index, lane_id, latency_ms, reason);
        }
    }

    fn seed_devnet_microbatch(
        &mut self,
        index: u64,
        lane_id: &str,
        latency_ms: u64,
        reason: SchedulingReason,
    ) {
        let microbatch_id = format!("microbatch-latency-devnet-{index}");
        let observed_at_ms = 1_000_000 + index * 48;
        let _ = self.observe_microbatch(MicrobatchObservationInput {
            microbatch_id: microbatch_id.clone(),
            lane_id: lane_id.to_string(),
            sealed_payload_root: dev_hash("sealed-payload", index),
            encrypted_receipt_root: dev_hash("encrypted-receipt", index),
            observed_slot: self.current_slot + index,
            observed_at_ms,
            preconfirmed_at_ms: Some(observed_at_ms + latency_ms),
            item_count: 64 + index as u32,
            byte_count: 32_768 + index * 512,
            offered_fee_micros: 5 + index,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE + 131_072,
        });
        let bucket_id = self
            .microbatches
            .get(&microbatch_id)
            .map(|entry| entry.bucket_id.clone())
            .unwrap_or_else(|| bucket_id(lane_id, self.current_slot, LatencyBand::Target));
        let _ = self.submit_availability_signal(ReceiptAvailabilitySignalInput {
            signal_id: format!("availability-signal-devnet-{index}"),
            microbatch_id: microbatch_id.clone(),
            lane_id: lane_id.to_string(),
            receipt_commitment_root: dev_hash("receipt-commitment", index),
            availability_bitmap_root: dev_hash("availability-bitmap", index),
            available_receipts: 96 + index,
            expected_receipts: 100 + index,
            reporting_slot: self.current_slot + index + 1,
            reporter_set_commitment: dev_hash("reporter-set", index),
        });
        let _ = self.submit_lane_attestation(PqLaneAttestationInput {
            attestation_id: format!("pq-lane-attestation-devnet-{index}"),
            lane_id: lane_id.to_string(),
            microbatch_id: microbatch_id.clone(),
            bucket_id,
            signer_commitment: dev_hash("attestor", index),
            lane_statement_root: dev_hash("lane-statement", index),
            pq_signature_root: dev_hash("pq-signature", index),
            attested_latency_ms: Some(latency_ms),
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS + 100,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            slot: self.current_slot + index + 2,
        });
        let _ = self.schedule_microbatch(FeeAwareSchedulingInput {
            schedule_id: format!("fee-aware-schedule-devnet-{index}"),
            lane_id: lane_id.to_string(),
            microbatch_id,
            requested_slot: self.current_slot + index + 3,
            max_fee_micros: 40,
            reason,
        });
    }

    fn ensure_capacity(&self, len: usize, max: usize, label: &str) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }

    fn update_lane_scores(&mut self, lane_id: &str) -> Result<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| "lane not registered".to_string())?;
        let lane_buckets = self
            .timing_buckets
            .values()
            .filter(|bucket| bucket.lane_id == lane_id)
            .collect::<Vec<_>>();
        let total_samples = lane_buckets
            .iter()
            .fold(0_u64, |acc, bucket| acc.saturating_add(bucket.sample_count));
        if total_samples > 0 {
            let weighted = lane_buckets.iter().fold(0_u128, |acc, bucket| {
                acc.saturating_add(
                    bucket.sample_count as u128
                        * bucket.latency_band.scheduling_multiplier_bps() as u128,
                )
            });
            lane.rolling_latency_score_bps = (weighted / total_samples as u128) as u64;
            lane.latest_bucket_id = lane_buckets
                .iter()
                .max_by_key(|bucket| bucket.window_end_slot)
                .map(|bucket| bucket.bucket_id.clone());
        }
        let lane_signals = self
            .availability_signals
            .values()
            .filter(|signal| signal.lane_id == lane_id)
            .collect::<Vec<_>>();
        if !lane_signals.is_empty() {
            let total = lane_signals.iter().fold(0_u64, |acc, signal| {
                acc.saturating_add(signal.availability_bps)
            });
            lane.rolling_availability_bps = total / lane_signals.len() as u64;
            lane.latest_availability_signal_id = lane_signals
                .iter()
                .max_by_key(|signal| signal.reporting_slot)
                .map(|signal| signal.signal_id.clone());
        }
        lane.fee_efficiency_score_bps =
            fee_efficiency_score_bps(lane.max_priority_fee_micros, &self.config);
        lane.status = if lane.rolling_availability_bps < self.config.min_receipt_availability_bps {
            LaneStatus::Congested
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

    fn public_microbatch_records(&self) -> BTreeMap<String, Value> {
        self.microbatches
            .iter()
            .map(|(key, microbatch)| (key.clone(), microbatch.public_record()))
            .collect()
    }

    fn public_bucket_records(&self) -> BTreeMap<String, Value> {
        self.timing_buckets
            .iter()
            .map(|(key, bucket)| (key.clone(), bucket.public_record()))
            .collect()
    }

    fn public_signal_records(&self) -> BTreeMap<String, Value> {
        self.availability_signals
            .iter()
            .map(|(key, signal)| (key.clone(), signal.public_record()))
            .collect()
    }

    fn public_attestation_records(&self) -> BTreeMap<String, Value> {
        self.lane_attestations
            .iter()
            .map(|(key, attestation)| (key.clone(), attestation.public_record()))
            .collect()
    }

    fn public_schedule_records(&self) -> BTreeMap<String, Value> {
        self.scheduling_decisions
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

fn window_start(slot: u64, config: &Config) -> u64 {
    (slot / config.window_slots) * config.window_slots
}

fn bucket_id(lane_id: &str, window_start_slot: u64, band: LatencyBand) -> String {
    domain_hash(
        PRECONFIRMATION_BUCKET_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(window_start_slot),
            HashPart::Str(band.as_str()),
        ],
        20,
    )
}

fn scheduling_score_bps(
    lane: &ConfidentialLaneEntry,
    microbatch: &MicrobatchLatencyEntry,
    input: &FeeAwareSchedulingInput,
    config: &Config,
) -> u64 {
    let reason_bonus = match input.reason {
        SchedulingReason::BridgeExitPriority if lane.class == LaneClass::BridgeExit => 1_100,
        SchedulingReason::EmergencyCancelPriority if lane.class == LaneClass::EmergencyCancel => {
            1_200
        }
        SchedulingReason::FeeEfficient => config.low_fee_bonus_bps,
        SchedulingReason::PrivacySetGrowth
            if microbatch.privacy_set_size >= config.min_privacy_set_size.saturating_mul(2) =>
        {
            450
        }
        SchedulingReason::ReceiptAvailability => 350,
        SchedulingReason::LowLatency => 300,
        SchedulingReason::CongestionRelief => 250,
        _ => 0,
    };
    let fee_cap_penalty = if input.max_fee_micros < config.base_scheduling_fee_micros {
        config.congestion_penalty_bps
    } else {
        0
    };
    let raw = lane
        .class
        .base_priority_weight()
        .saturating_mul(microbatch.latency_band.scheduling_multiplier_bps())
        / MAX_BPS;
    raw.saturating_add(lane.rolling_availability_bps / 20)
        .saturating_add(lane.fee_efficiency_score_bps / 25)
        .saturating_add(reason_bonus)
        .saturating_sub(fee_cap_penalty)
        .min(12_500)
}

fn assign_slot(requested_slot: u64, score_bps: u64, fee_capped: bool) -> u64 {
    if fee_capped {
        requested_slot.saturating_add(3)
    } else if score_bps >= 10_500 {
        requested_slot
    } else if score_bps >= 9_000 {
        requested_slot.saturating_add(1)
    } else {
        requested_slot.saturating_add(2)
    }
}

fn fee_efficiency_score_bps(max_priority_fee_micros: u64, config: &Config) -> u64 {
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

fn fee_weighted_score_bps(band: LatencyBand, offered_fee_micros: u64, config: &Config) -> u64 {
    let latency_score = band.scheduling_multiplier_bps();
    let fee_score = fee_efficiency_score_bps(offered_fee_micros, config);
    latency_score.saturating_mul(7) / 10 + fee_score.saturating_mul(3) / 10
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
