use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialRecursiveProofLatencyClearingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_PROOF_LATENCY_CLEARING_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-recursive-proof-latency-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_PROOF_LATENCY_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const RECURSIVE_PROOF_CLEARING_SUITE: &str =
    "private-l2-fast-pq-confidential-recursive-proof-latency-clearing-v1";
pub const PRECONFIRMATION_CLEARING_CURVE_SUITE: &str =
    "ml-kem-1024-sealed-preconfirmation-recursive-proof-clearing-curve-v1";
pub const PQ_LANE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-recursive-proof-clearing-lane-attestation-v1";
pub const PROOF_DELIVERY_QOS_SUITE: &str =
    "private-l2-fast-confidential-recursive-proof-delivery-qos-score-v1";
pub const FEE_AWARE_SETTLEMENT_SUITE: &str =
    "private-l2-fast-confidential-recursive-proof-clearing-fee-aware-settlement-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "privacy-preserving-public-recursive-proof-latency-clearing-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_proofs_addresses_view_keys_payloads_curve_points_fee_amounts_or_witnesses";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_EPOCH: u64 = 40_960;
pub const DEVNET_HEIGHT: u64 = 7_360_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 85;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 145;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 380;
pub const DEFAULT_CLEARING_TTL_SLOTS: u64 = 88;
pub const DEFAULT_CURVE_TTL_SLOTS: u64 = 30;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 128;
pub const DEFAULT_QOS_WINDOW_SLOTS: u64 = 64;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 2;
pub const DEFAULT_MAX_LANES: usize = 65_536;
pub const DEFAULT_MAX_CLEARING_ORDERS: usize = 1_048_576;
pub const DEFAULT_MAX_CURVES: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_QOS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 262_144;
pub const DEFAULT_MIN_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_WEIGHT_BPS: u64 = 8_250;
pub const DEFAULT_MIN_DELIVERY_QOS_BPS: u64 = 8_550;
pub const DEFAULT_TARGET_RECURSION_FILL_BPS: u64 = 8_950;
pub const DEFAULT_LOW_FEE_BONUS_BPS: u64 = 675;
pub const DEFAULT_PRIVACY_BONUS_BPS: u64 = 450;
pub const DEFAULT_RECURSION_DEPTH_BONUS_BPS: u64 = 320;
pub const DEFAULT_CONGESTION_PENALTY_BPS: u64 = 1_075;
pub const DEFAULT_LATE_PROOF_PENALTY_BPS: u64 = 1_725;
pub const DEFAULT_PRIORITY_FEE_CAP_MICROS: u64 = 86;
pub const DEFAULT_BASE_SETTLEMENT_FEE_MICROS: u64 = 4;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 130;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 230;
pub const DEFAULT_MAX_RECURSION_DEPTH: u16 = 32;
pub const DEFAULT_MAX_AGGREGATE_WIDTH: u16 = 256;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:LANES";
const D_ORDERS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:ORDERS";
const D_CURVES: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:CURVES";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:ATTESTATIONS";
const D_QOS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:QOS";
const D_SETTLEMENTS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:SETTLEMENTS";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:NULLIFIERS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-RECURSIVE-PROOF-LATENCY-CLEARING:DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    WalletFast,
    MerchantPos,
    DefiIntent,
    BridgeExit,
    ContractCall,
    RecursiveAggregator,
    ProofCourier,
    EmergencyCancel,
}

impl LaneClass {
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_980,
            Self::BridgeExit => 10_360,
            Self::MerchantPos => 9_920,
            Self::DefiIntent => 9_680,
            Self::ContractCall => 9_300,
            Self::WalletFast => 9_080,
            Self::RecursiveAggregator => 8_940,
            Self::ProofCourier => 8_620,
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
    pub fn accepts_orders(self) -> bool {
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveProofClass {
    ValidityRollup,
    StateTransition,
    ReceiptInclusion,
    NullifierBatch,
    BridgeExit,
    ContractExecution,
    AggregationLayer,
    RepairShard,
}

impl RecursiveProofClass {
    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 1_180,
            Self::AggregationLayer => 1_150,
            Self::StateTransition => 1_100,
            Self::ContractExecution => 1_050,
            Self::ValidityRollup => 1_000,
            Self::NullifierBatch => 940,
            Self::ReceiptInclusion => 830,
            Self::RepairShard => 760,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingSide {
    BuyLatency,
    SellRecursiveCapacity,
    SponsorPreconfirmation,
    BackstopDelivery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingStatus {
    Open,
    CurveMatched,
    Recursing,
    Attested,
    Delivered,
    Settled,
    Late,
    Expired,
    Cancelled,
    Slashed,
}

impl ClearingStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::CurveMatched | Self::Recursing | Self::Attested | Self::Delivered
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurveKind {
    FixedDeadline,
    StepDownRebate,
    LinearDecay,
    CongestionIndexed,
    PrivacyWeighted,
    RecursionPremium,
    EmergencyCap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Reject,
    Slash,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QosGrade {
    Excellent,
    Good,
    Degraded,
    Failed,
}

impl QosGrade {
    pub fn from_score(config: &Config, score_bps: u64) -> Self {
        if score_bps >= config.strong_quorum_weight_bps {
            Self::Excellent
        } else if score_bps >= config.min_delivery_qos_bps {
            Self::Good
        } else if score_bps > 0 {
            Self::Degraded
        } else {
            Self::Failed
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    FeeChecked,
    Settled,
    Repriced,
    Rejected,
    Slashed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub runtime_mode: RuntimeMode,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub slot_width_ms: u64,
    pub target_preconfirmation_ms: u64,
    pub soft_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub clearing_ttl_slots: u64,
    pub curve_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub qos_window_slots: u64,
    pub settlement_delay_slots: u64,
    pub max_lanes: usize,
    pub max_clearing_orders: usize,
    pub max_curves: usize,
    pub max_attestations: usize,
    pub max_delivery_qos: usize,
    pub max_settlements: usize,
    pub max_public_records: usize,
    pub min_quorum_weight_bps: u64,
    pub strong_quorum_weight_bps: u64,
    pub min_delivery_qos_bps: u64,
    pub target_recursion_fill_bps: u64,
    pub low_fee_bonus_bps: u64,
    pub privacy_bonus_bps: u64,
    pub recursion_depth_bonus_bps: u64,
    pub congestion_penalty_bps: u64,
    pub late_proof_penalty_bps: u64,
    pub priority_fee_cap_micros: u64,
    pub base_settlement_fee_micros: u64,
    pub maker_rebate_bps: u64,
    pub taker_fee_bps: u64,
    pub max_recursion_depth: u16,
    pub max_aggregate_width: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            runtime_mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            clearing_ttl_slots: DEFAULT_CLEARING_TTL_SLOTS,
            curve_ttl_slots: DEFAULT_CURVE_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            qos_window_slots: DEFAULT_QOS_WINDOW_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            max_lanes: DEFAULT_MAX_LANES,
            max_clearing_orders: DEFAULT_MAX_CLEARING_ORDERS,
            max_curves: DEFAULT_MAX_CURVES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_delivery_qos: DEFAULT_MAX_QOS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            min_quorum_weight_bps: DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            min_delivery_qos_bps: DEFAULT_MIN_DELIVERY_QOS_BPS,
            target_recursion_fill_bps: DEFAULT_TARGET_RECURSION_FILL_BPS,
            low_fee_bonus_bps: DEFAULT_LOW_FEE_BONUS_BPS,
            privacy_bonus_bps: DEFAULT_PRIVACY_BONUS_BPS,
            recursion_depth_bonus_bps: DEFAULT_RECURSION_DEPTH_BONUS_BPS,
            congestion_penalty_bps: DEFAULT_CONGESTION_PENALTY_BPS,
            late_proof_penalty_bps: DEFAULT_LATE_PROOF_PENALTY_BPS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            base_settlement_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
            max_aggregate_width: DEFAULT_MAX_AGGREGATE_WIDTH,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_positive_u64("schema_version", self.schema_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive_u64("slot_width_ms", self.slot_width_ms)?;
        ensure_positive_u64("target_preconfirmation_ms", self.target_preconfirmation_ms)?;
        ensure_positive_u64("soft_latency_ms", self.soft_latency_ms)?;
        ensure_positive_u64("hard_latency_ms", self.hard_latency_ms)?;
        ensure_positive_u64("clearing_ttl_slots", self.clearing_ttl_slots)?;
        ensure_positive_u64("curve_ttl_slots", self.curve_ttl_slots)?;
        ensure_positive_u64("attestation_ttl_slots", self.attestation_ttl_slots)?;
        ensure_positive_u64("qos_window_slots", self.qos_window_slots)?;
        ensure_positive_u64("settlement_delay_slots", self.settlement_delay_slots)?;
        ensure_positive_usize("max_lanes", self.max_lanes)?;
        ensure_positive_usize("max_clearing_orders", self.max_clearing_orders)?;
        ensure_positive_usize("max_curves", self.max_curves)?;
        ensure_positive_usize("max_attestations", self.max_attestations)?;
        ensure_positive_usize("max_delivery_qos", self.max_delivery_qos)?;
        ensure_positive_usize("max_settlements", self.max_settlements)?;
        ensure_positive_usize("max_public_records", self.max_public_records)?;
        ensure_bps("min_quorum_weight_bps", self.min_quorum_weight_bps)?;
        ensure_bps("strong_quorum_weight_bps", self.strong_quorum_weight_bps)?;
        ensure_bps("min_delivery_qos_bps", self.min_delivery_qos_bps)?;
        ensure_bps("target_recursion_fill_bps", self.target_recursion_fill_bps)?;
        ensure_bps("low_fee_bonus_bps", self.low_fee_bonus_bps)?;
        ensure_bps("privacy_bonus_bps", self.privacy_bonus_bps)?;
        ensure_bps("recursion_depth_bonus_bps", self.recursion_depth_bonus_bps)?;
        ensure_bps("congestion_penalty_bps", self.congestion_penalty_bps)?;
        ensure_bps("late_proof_penalty_bps", self.late_proof_penalty_bps)?;
        ensure_bps("maker_rebate_bps", self.maker_rebate_bps)?;
        ensure_bps("taker_fee_bps", self.taker_fee_bps)?;
        if self.target_preconfirmation_ms > self.soft_latency_ms {
            return Err("target_preconfirmation_ms cannot exceed soft_latency_ms".to_string());
        }
        if self.soft_latency_ms > self.hard_latency_ms {
            return Err("soft_latency_ms cannot exceed hard_latency_ms".to_string());
        }
        if self.max_recursion_depth == 0 {
            return Err("max_recursion_depth must be positive".to_string());
        }
        if self.max_aggregate_width == 0 {
            return Err("max_aggregate_width must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "runtime_mode": self.runtime_mode,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "recursive_proof_clearing_suite": RECURSIVE_PROOF_CLEARING_SUITE,
            "preconfirmation_clearing_curve_suite": PRECONFIRMATION_CLEARING_CURVE_SUITE,
            "pq_lane_attestation_suite": PQ_LANE_ATTESTATION_SUITE,
            "proof_delivery_qos_suite": PROOF_DELIVERY_QOS_SUITE,
            "fee_aware_settlement_suite": FEE_AWARE_SETTLEMENT_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "slot_width_ms": self.slot_width_ms,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "soft_latency_ms": self.soft_latency_ms,
            "hard_latency_ms": self.hard_latency_ms,
            "max_recursion_depth": self.max_recursion_depth,
            "max_aggregate_width": self.max_aggregate_width,
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub clearing_orders_opened: u64,
    pub curves_posted: u64,
    pub curves_matched: u64,
    pub recursive_segments_requested: u64,
    pub recursive_segments_attested: u64,
    pub pq_attestations: u64,
    pub delivery_qos_scores: u64,
    pub settlements: u64,
    pub late_settlements: u64,
    pub slashed_orders: u64,
    pub expired_orders: u64,
    pub cancelled_orders: u64,
    pub total_fee_micros: u64,
    pub maker_rebates_micros: u64,
    pub taker_fees_micros: u64,
    pub public_records: u64,
    pub state_root_updates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        record_with_kind("counters", self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lanes_root: String,
    pub clearing_orders_root: String,
    pub curves_root: String,
    pub attestations_root: String,
    pub delivery_qos_root: String,
    pub settlements_root: String,
    pub nullifier_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root(D_CONFIG),
            counters_root: empty_root(D_COUNTERS),
            lanes_root: empty_root(D_LANES),
            clearing_orders_root: empty_root(D_ORDERS),
            curves_root: empty_root(D_CURVES),
            attestations_root: empty_root(D_ATTESTATIONS),
            delivery_qos_root: empty_root(D_QOS),
            settlements_root: empty_root(D_SETTLEMENTS),
            nullifier_root: empty_root(D_NULLIFIERS),
            public_records_root: empty_root(D_PUBLIC),
            state_root: empty_root(D_STATE),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        record_with_kind("roots", self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ConfidentialRecursiveProofLane {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_class: LaneClass,
    pub status: LaneStatus,
    pub pq_attestation_key_root: String,
    pub recursion_capacity_commitment: String,
    pub fee_escrow_commitment: String,
    pub privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub congestion_bps: u64,
    pub rolling_qos_bps: u64,
    pub rolling_fill_bps: u64,
    pub max_recursion_depth: u16,
    pub max_aggregate_width: u16,
    pub created_at_height: u64,
    pub last_attested_height: u64,
    pub sequence: u64,
    pub root: String,
}

impl ConfidentialRecursiveProofLane {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_recursive_proof_lane",
            "lane_id": self.lane_id,
            "lane_class": self.lane_class,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "quorum_weight_bps": self.quorum_weight_bps,
            "congestion_bps": self.congestion_bps,
            "rolling_qos_bps": self.rolling_qos_bps,
            "rolling_fill_bps": self.rolling_fill_bps,
            "max_recursion_depth": self.max_recursion_depth,
            "max_aggregate_width": self.max_aggregate_width,
            "created_at_height": self.created_at_height,
            "last_attested_height": self.last_attested_height,
            "sequence": self.sequence,
            "root": self.root,
        })
    }

    pub fn privacy_bonus_bps(&self, config: &Config) -> u64 {
        if self.privacy_set_size >= config.target_privacy_set_size {
            config.privacy_bonus_bps
        } else if self.privacy_set_size >= config.min_privacy_set_size {
            config.privacy_bonus_bps / 2
        } else {
            0
        }
    }

    pub fn recursion_bonus_bps(&self, config: &Config, depth: u16) -> u64 {
        let depth_bps = ratio_bps(depth as u64, config.max_recursion_depth.max(1) as u64);
        config
            .recursion_depth_bonus_bps
            .saturating_mul(depth_bps)
            .saturating_div(MAX_BPS)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RegisterLaneInput {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_class: LaneClass,
    pub pq_attestation_key_root: String,
    pub recursion_capacity_commitment: String,
    pub fee_escrow_commitment: String,
    pub privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub congestion_bps: u64,
    pub max_recursion_depth: u16,
    pub max_aggregate_width: u16,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecursiveProofClearingOrder {
    pub clearing_id: String,
    pub lane_id: String,
    pub side: ClearingSide,
    pub proof_class: RecursiveProofClass,
    pub status: ClearingStatus,
    pub encrypted_proof_hint_root: String,
    pub recursive_input_root: String,
    pub recursion_plan_root: String,
    pub state_root_before: String,
    pub expected_state_root_after: String,
    pub privacy_fence_root: String,
    pub nullifier: String,
    pub notional_fee_micros: u64,
    pub max_priority_fee_micros: u64,
    pub target_latency_ms: u64,
    pub requested_recursion_depth: u16,
    pub requested_aggregate_width: u16,
    pub deadline_slot: u64,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub matched_curve_id: Option<String>,
    pub qos_score_id: Option<String>,
    pub settlement_id: Option<String>,
    pub sequence: u64,
    pub root: String,
}

impl RecursiveProofClearingOrder {
    pub fn is_expired(&self, slot: u64) -> bool {
        self.status.live() && slot > self.expires_at_slot
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_clearing_order",
            "clearing_id": self.clearing_id,
            "lane_id": self.lane_id,
            "side": self.side,
            "proof_class": self.proof_class,
            "status": self.status,
            "recursive_input_root": self.recursive_input_root,
            "recursion_plan_root": self.recursion_plan_root,
            "state_root_before": self.state_root_before,
            "expected_state_root_after": self.expected_state_root_after,
            "privacy_fence_root": self.privacy_fence_root,
            "target_latency_ms": self.target_latency_ms,
            "requested_recursion_depth": self.requested_recursion_depth,
            "requested_aggregate_width": self.requested_aggregate_width,
            "deadline_slot": self.deadline_slot,
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "matched_curve_id": self.matched_curve_id,
            "qos_score_id": self.qos_score_id,
            "settlement_id": self.settlement_id,
            "sequence": self.sequence,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenClearingOrderInput {
    pub clearing_id: String,
    pub lane_id: String,
    pub side: ClearingSide,
    pub proof_class: RecursiveProofClass,
    pub encrypted_proof_hint_root: String,
    pub recursive_input_root: String,
    pub recursion_plan_root: String,
    pub state_root_before: String,
    pub expected_state_root_after: String,
    pub privacy_fence_root: String,
    pub nullifier: String,
    pub notional_fee_micros: u64,
    pub max_priority_fee_micros: u64,
    pub target_latency_ms: u64,
    pub requested_recursion_depth: u16,
    pub requested_aggregate_width: u16,
    pub deadline_slot: u64,
    pub created_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PreconfirmationClearingCurve {
    pub curve_id: String,
    pub lane_id: String,
    pub curve_kind: CurveKind,
    pub sealed_curve_root: String,
    pub maker_commitment: String,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub base_fee_micros: u64,
    pub priority_fee_cap_micros: u64,
    pub min_delivery_qos_bps: u64,
    pub max_recursion_depth: u16,
    pub max_aggregate_width: u16,
    pub capacity_units: u64,
    pub filled_units: u64,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
    pub status: ClearingStatus,
    pub sequence: u64,
    pub root: String,
}

impl PreconfirmationClearingCurve {
    pub fn accepts(&self, order: &RecursiveProofClearingOrder, slot: u64) -> bool {
        self.status.live()
            && self.lane_id == order.lane_id
            && slot >= self.valid_from_slot
            && slot <= self.valid_until_slot
            && self.filled_units < self.capacity_units
            && self.target_latency_ms <= order.target_latency_ms
            && self.priority_fee_cap_micros <= order.max_priority_fee_micros
            && self.max_recursion_depth >= order.requested_recursion_depth
            && self.max_aggregate_width >= order.requested_aggregate_width
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_clearing_curve",
            "curve_id": self.curve_id,
            "lane_id": self.lane_id,
            "curve_kind": self.curve_kind,
            "target_latency_ms": self.target_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "min_delivery_qos_bps": self.min_delivery_qos_bps,
            "max_recursion_depth": self.max_recursion_depth,
            "max_aggregate_width": self.max_aggregate_width,
            "capacity_units": self.capacity_units,
            "filled_units": self.filled_units,
            "valid_from_slot": self.valid_from_slot,
            "valid_until_slot": self.valid_until_slot,
            "status": self.status,
            "sequence": self.sequence,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PostCurveInput {
    pub curve_id: String,
    pub lane_id: String,
    pub curve_kind: CurveKind,
    pub sealed_curve_root: String,
    pub maker_commitment: String,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub base_fee_micros: u64,
    pub priority_fee_cap_micros: u64,
    pub min_delivery_qos_bps: u64,
    pub max_recursion_depth: u16,
    pub max_aggregate_width: u16,
    pub capacity_units: u64,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub clearing_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub recursive_proof_root: String,
    pub aggregation_transcript_root: String,
    pub state_root_claim: String,
    pub quorum_weight_bps: u64,
    pub verdict: AttestationVerdict,
    pub attested_latency_ms: u64,
    pub recursion_depth_observed: u16,
    pub aggregate_width_observed: u16,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub sequence: u64,
    pub root: String,
}

impl PqLaneAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_lane_attestation",
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "clearing_id": self.clearing_id,
            "recursive_proof_root": self.recursive_proof_root,
            "aggregation_transcript_root": self.aggregation_transcript_root,
            "state_root_claim": self.state_root_claim,
            "quorum_weight_bps": self.quorum_weight_bps,
            "verdict": self.verdict,
            "attested_latency_ms": self.attested_latency_ms,
            "recursion_depth_observed": self.recursion_depth_observed,
            "aggregate_width_observed": self.aggregate_width_observed,
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "sequence": self.sequence,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubmitAttestationInput {
    pub attestation_id: String,
    pub lane_id: String,
    pub clearing_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub recursive_proof_root: String,
    pub aggregation_transcript_root: String,
    pub state_root_claim: String,
    pub quorum_weight_bps: u64,
    pub verdict: AttestationVerdict,
    pub attested_latency_ms: u64,
    pub recursion_depth_observed: u16,
    pub aggregate_width_observed: u16,
    pub created_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProofDeliveryQosScore {
    pub qos_id: String,
    pub lane_id: String,
    pub clearing_id: String,
    pub recursive_proof_root: String,
    pub delivery_commitment: String,
    pub observed_latency_ms: u64,
    pub target_latency_ms: u64,
    pub availability_bps: u64,
    pub correctness_bps: u64,
    pub recursion_integrity_bps: u64,
    pub privacy_bps: u64,
    pub fee_efficiency_bps: u64,
    pub aggregate_qos_bps: u64,
    pub grade: QosGrade,
    pub scored_at_slot: u64,
    pub sequence: u64,
    pub root: String,
}

impl ProofDeliveryQosScore {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_delivery_qos_score",
            "qos_id": self.qos_id,
            "lane_id": self.lane_id,
            "clearing_id": self.clearing_id,
            "recursive_proof_root": self.recursive_proof_root,
            "delivery_commitment": self.delivery_commitment,
            "observed_latency_ms": self.observed_latency_ms,
            "target_latency_ms": self.target_latency_ms,
            "availability_bps": self.availability_bps,
            "correctness_bps": self.correctness_bps,
            "recursion_integrity_bps": self.recursion_integrity_bps,
            "privacy_bps": self.privacy_bps,
            "fee_efficiency_bps": self.fee_efficiency_bps,
            "aggregate_qos_bps": self.aggregate_qos_bps,
            "grade": self.grade,
            "scored_at_slot": self.scored_at_slot,
            "sequence": self.sequence,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ScoreDeliveryInput {
    pub qos_id: String,
    pub lane_id: String,
    pub clearing_id: String,
    pub recursive_proof_root: String,
    pub delivery_commitment: String,
    pub observed_latency_ms: u64,
    pub availability_bps: u64,
    pub correctness_bps: u64,
    pub recursion_integrity_bps: u64,
    pub privacy_bps: u64,
    pub fee_efficiency_bps: u64,
    pub scored_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeAwareSettlement {
    pub settlement_id: String,
    pub clearing_id: String,
    pub curve_id: String,
    pub lane_id: String,
    pub settlement_status: SettlementStatus,
    pub fee_asset_id: String,
    pub gross_fee_micros: u64,
    pub priority_fee_micros: u64,
    pub maker_rebate_micros: u64,
    pub taker_fee_micros: u64,
    pub privacy_rebate_micros: u64,
    pub recursion_rebate_micros: u64,
    pub late_penalty_micros: u64,
    pub congestion_penalty_micros: u64,
    pub net_settlement_micros: u64,
    pub delivery_qos_bps: u64,
    pub settlement_root: String,
    pub settled_at_slot: u64,
    pub sequence: u64,
    pub root: String,
}

impl FeeAwareSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_aware_settlement",
            "settlement_id": self.settlement_id,
            "clearing_id": self.clearing_id,
            "curve_id": self.curve_id,
            "lane_id": self.lane_id,
            "settlement_status": self.settlement_status,
            "fee_asset_id": self.fee_asset_id,
            "delivery_qos_bps": self.delivery_qos_bps,
            "settlement_root": self.settlement_root,
            "settled_at_slot": self.settled_at_slot,
            "sequence": self.sequence,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettleClearingInput {
    pub settlement_id: String,
    pub clearing_id: String,
    pub curve_id: String,
    pub settlement_root: String,
    pub priority_fee_micros: u64,
    pub settled_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub scheme: String,
    pub protocol_version: String,
    pub state_root: String,
    pub public_root: String,
    pub lane_root: String,
    pub clearing_orders_root: String,
    pub curves_root: String,
    pub attestations_root: String,
    pub delivery_qos_root: String,
    pub settlements_root: String,
    pub counters_root: String,
    pub nullifier_root: String,
    pub privacy_boundary: String,
    pub height: u64,
    pub epoch: u64,
    pub sequence: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        record_with_kind("public_record", self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, ConfidentialRecursiveProofLane>,
    pub clearing_orders: BTreeMap<String, RecursiveProofClearingOrder>,
    pub curves: BTreeMap<String, PreconfirmationClearingCurve>,
    pub attestations: BTreeMap<String, PqLaneAttestation>,
    pub delivery_qos: BTreeMap<String, ProofDeliveryQosScore>,
    pub settlements: BTreeMap<String, FeeAwareSettlement>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        config
            .validate()
            .expect("recursive proof latency clearing config must validate");
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            clearing_orders: BTreeMap::new(),
            curves: BTreeMap::new(),
            attestations: BTreeMap::new(),
            delivery_qos: BTreeMap::new(),
            settlements: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_lane(&mut self, input: RegisterLaneInput) -> Result<String> {
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_root("operator_commitment", &input.operator_commitment)?;
        ensure_root("pq_attestation_key_root", &input.pq_attestation_key_root)?;
        ensure_root(
            "recursion_capacity_commitment",
            &input.recursion_capacity_commitment,
        )?;
        ensure_root("fee_escrow_commitment", &input.fee_escrow_commitment)?;
        ensure_absent("lane", &self.lanes, &input.lane_id)?;
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;
        ensure_bps("congestion_bps", input.congestion_bps)?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        if input.quorum_weight_bps < self.config.min_quorum_weight_bps {
            return Err("lane quorum weight below configured minimum".to_string());
        }
        if input.max_recursion_depth == 0
            || input.max_recursion_depth > self.config.max_recursion_depth
        {
            return Err("lane max_recursion_depth outside configured bounds".to_string());
        }
        if input.max_aggregate_width == 0
            || input.max_aggregate_width > self.config.max_aggregate_width
        {
            return Err("lane max_aggregate_width outside configured bounds".to_string());
        }

        let mut lane = ConfidentialRecursiveProofLane {
            lane_id: input.lane_id.clone(),
            operator_commitment: input.operator_commitment,
            lane_class: input.lane_class,
            status: LaneStatus::Registered,
            pq_attestation_key_root: input.pq_attestation_key_root,
            recursion_capacity_commitment: input.recursion_capacity_commitment,
            fee_escrow_commitment: input.fee_escrow_commitment,
            privacy_set_size: input.privacy_set_size,
            quorum_weight_bps: input.quorum_weight_bps,
            congestion_bps: input.congestion_bps,
            rolling_qos_bps: MAX_BPS,
            rolling_fill_bps: 0,
            max_recursion_depth: input.max_recursion_depth,
            max_aggregate_width: input.max_aggregate_width,
            created_at_height: input.created_at_height,
            last_attested_height: input.created_at_height,
            sequence: self.counters.lanes_registered.saturating_add(1),
            root: String::new(),
        };
        lane.root = payload_root(D_LANES, &record_without_root(&lane));
        self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        self.lanes.insert(input.lane_id.clone(), lane);
        self.refresh_roots();
        Ok(input.lane_id)
    }

    pub fn set_lane_status(&mut self, lane_id: &str, status: LaneStatus) -> Result<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane `{lane_id}`"))?;
        lane.status = status;
        lane.sequence = lane.sequence.saturating_add(1);
        lane.root = payload_root(D_LANES, &record_without_root(lane));
        self.refresh_roots();
        Ok(())
    }

    pub fn open_clearing_order(&mut self, input: OpenClearingOrderInput) -> Result<String> {
        ensure_nonempty("clearing_id", &input.clearing_id)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_root(
            "encrypted_proof_hint_root",
            &input.encrypted_proof_hint_root,
        )?;
        ensure_root("recursive_input_root", &input.recursive_input_root)?;
        ensure_root("recursion_plan_root", &input.recursion_plan_root)?;
        ensure_root("state_root_before", &input.state_root_before)?;
        ensure_root(
            "expected_state_root_after",
            &input.expected_state_root_after,
        )?;
        ensure_root("privacy_fence_root", &input.privacy_fence_root)?;
        ensure_nonempty("nullifier", &input.nullifier)?;
        ensure_absent("clearing_order", &self.clearing_orders, &input.clearing_id)?;
        ensure_capacity(
            "clearing_orders",
            self.clearing_orders.len(),
            self.config.max_clearing_orders,
        )?;
        if self.consumed_nullifiers.contains(&input.nullifier) {
            return Err("clearing order nullifier already consumed".to_string());
        }
        if input.notional_fee_micros == 0 {
            return Err("notional_fee_micros must be positive".to_string());
        }
        if input.max_priority_fee_micros > self.config.priority_fee_cap_micros {
            return Err("max_priority_fee_micros exceeds configured cap".to_string());
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_orders() {
            return Err("lane does not accept clearing orders".to_string());
        }
        if input.requested_recursion_depth == 0
            || input.requested_recursion_depth > lane.max_recursion_depth
        {
            return Err("requested_recursion_depth exceeds lane capacity".to_string());
        }
        if input.requested_aggregate_width == 0
            || input.requested_aggregate_width > lane.max_aggregate_width
        {
            return Err("requested_aggregate_width exceeds lane capacity".to_string());
        }
        if input.target_latency_ms > self.config.hard_latency_ms {
            return Err("target latency exceeds configured hard latency".to_string());
        }
        if input.deadline_slot <= input.created_at_slot {
            return Err("deadline_slot must be after created_at_slot".to_string());
        }

        let expires_at_slot = input
            .created_at_slot
            .saturating_add(self.config.clearing_ttl_slots);
        let mut order = RecursiveProofClearingOrder {
            clearing_id: input.clearing_id.clone(),
            lane_id: input.lane_id,
            side: input.side,
            proof_class: input.proof_class,
            status: ClearingStatus::Open,
            encrypted_proof_hint_root: input.encrypted_proof_hint_root,
            recursive_input_root: input.recursive_input_root,
            recursion_plan_root: input.recursion_plan_root,
            state_root_before: input.state_root_before,
            expected_state_root_after: input.expected_state_root_after,
            privacy_fence_root: input.privacy_fence_root,
            nullifier: input.nullifier.clone(),
            notional_fee_micros: input.notional_fee_micros,
            max_priority_fee_micros: input.max_priority_fee_micros,
            target_latency_ms: input.target_latency_ms,
            requested_recursion_depth: input.requested_recursion_depth,
            requested_aggregate_width: input.requested_aggregate_width,
            deadline_slot: input.deadline_slot,
            created_at_slot: input.created_at_slot,
            expires_at_slot,
            matched_curve_id: None,
            qos_score_id: None,
            settlement_id: None,
            sequence: self.counters.clearing_orders_opened.saturating_add(1),
            root: String::new(),
        };
        order.root = payload_root(D_ORDERS, &record_without_root(&order));
        self.counters.clearing_orders_opened =
            self.counters.clearing_orders_opened.saturating_add(1);
        self.counters.recursive_segments_requested = self
            .counters
            .recursive_segments_requested
            .saturating_add(input.requested_recursion_depth as u64);
        self.consumed_nullifiers.insert(input.nullifier);
        self.clearing_orders
            .insert(input.clearing_id.clone(), order);
        self.refresh_roots();
        Ok(input.clearing_id)
    }

    pub fn post_curve(&mut self, input: PostCurveInput) -> Result<String> {
        ensure_nonempty("curve_id", &input.curve_id)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_root("sealed_curve_root", &input.sealed_curve_root)?;
        ensure_root("maker_commitment", &input.maker_commitment)?;
        ensure_absent("curve", &self.curves, &input.curve_id)?;
        ensure_capacity("curves", self.curves.len(), self.config.max_curves)?;
        ensure_bps("min_delivery_qos_bps", input.min_delivery_qos_bps)?;
        if input.target_latency_ms > input.max_latency_ms {
            return Err("curve target latency cannot exceed max latency".to_string());
        }
        if input.max_latency_ms > self.config.hard_latency_ms {
            return Err("curve max latency exceeds configured hard latency".to_string());
        }
        if input.priority_fee_cap_micros > self.config.priority_fee_cap_micros {
            return Err("curve priority fee cap exceeds configured cap".to_string());
        }
        if input.valid_until_slot <= input.valid_from_slot {
            return Err("curve valid_until_slot must be after valid_from_slot".to_string());
        }
        if input.capacity_units == 0 {
            return Err("curve capacity_units must be positive".to_string());
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if input.max_recursion_depth == 0 || input.max_recursion_depth > lane.max_recursion_depth {
            return Err("curve max_recursion_depth exceeds lane capacity".to_string());
        }
        if input.max_aggregate_width == 0 || input.max_aggregate_width > lane.max_aggregate_width {
            return Err("curve max_aggregate_width exceeds lane capacity".to_string());
        }

        let mut curve = PreconfirmationClearingCurve {
            curve_id: input.curve_id.clone(),
            lane_id: input.lane_id,
            curve_kind: input.curve_kind,
            sealed_curve_root: input.sealed_curve_root,
            maker_commitment: input.maker_commitment,
            target_latency_ms: input.target_latency_ms,
            max_latency_ms: input.max_latency_ms,
            base_fee_micros: input.base_fee_micros,
            priority_fee_cap_micros: input.priority_fee_cap_micros,
            min_delivery_qos_bps: input.min_delivery_qos_bps,
            max_recursion_depth: input.max_recursion_depth,
            max_aggregate_width: input.max_aggregate_width,
            capacity_units: input.capacity_units,
            filled_units: 0,
            valid_from_slot: input.valid_from_slot,
            valid_until_slot: input.valid_until_slot,
            status: ClearingStatus::Open,
            sequence: self.counters.curves_posted.saturating_add(1),
            root: String::new(),
        };
        curve.root = payload_root(D_CURVES, &record_without_root(&curve));
        self.counters.curves_posted = self.counters.curves_posted.saturating_add(1);
        self.curves.insert(input.curve_id.clone(), curve);
        self.refresh_roots();
        Ok(input.curve_id)
    }

    pub fn match_curve(&mut self, clearing_id: &str, curve_id: &str, slot: u64) -> Result<()> {
        let order = self
            .clearing_orders
            .get(clearing_id)
            .ok_or_else(|| format!("unknown clearing order `{clearing_id}`"))?
            .clone();
        let curve = self
            .curves
            .get(curve_id)
            .ok_or_else(|| format!("unknown curve `{curve_id}`"))?
            .clone();
        if !curve.accepts(&order, slot) {
            return Err("curve does not accept clearing order at slot".to_string());
        }

        if let Some(order) = self.clearing_orders.get_mut(clearing_id) {
            order.status = ClearingStatus::CurveMatched;
            order.matched_curve_id = Some(curve_id.to_string());
            order.sequence = order.sequence.saturating_add(1);
            order.root = payload_root(D_ORDERS, &record_without_root(order));
        }
        if let Some(curve) = self.curves.get_mut(curve_id) {
            curve.filled_units = curve
                .filled_units
                .saturating_add(order.requested_aggregate_width as u64);
            curve.status = if curve.filled_units >= curve.capacity_units {
                ClearingStatus::Recursing
            } else {
                curve.status
            };
            curve.sequence = curve.sequence.saturating_add(1);
            curve.root = payload_root(D_CURVES, &record_without_root(curve));
        }
        self.counters.curves_matched = self.counters.curves_matched.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_attestation(&mut self, input: SubmitAttestationInput) -> Result<String> {
        ensure_nonempty("attestation_id", &input.attestation_id)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_nonempty("clearing_id", &input.clearing_id)?;
        ensure_root("attestor_commitment", &input.attestor_commitment)?;
        ensure_root("pq_signature_root", &input.pq_signature_root)?;
        ensure_root("recursive_proof_root", &input.recursive_proof_root)?;
        ensure_root(
            "aggregation_transcript_root",
            &input.aggregation_transcript_root,
        )?;
        ensure_root("state_root_claim", &input.state_root_claim)?;
        ensure_absent("attestation", &self.attestations, &input.attestation_id)?;
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_attestations() {
            return Err("lane does not accept attestations".to_string());
        }
        let order = self
            .clearing_orders
            .get(&input.clearing_id)
            .ok_or_else(|| format!("unknown clearing order `{}`", input.clearing_id))?;
        if order.lane_id != input.lane_id {
            return Err("attestation lane does not match clearing order".to_string());
        }
        if input.quorum_weight_bps < self.config.min_quorum_weight_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }
        if input.recursion_depth_observed < order.requested_recursion_depth {
            return Err("attested recursion depth below requested depth".to_string());
        }
        if input.aggregate_width_observed < order.requested_aggregate_width {
            return Err("attested aggregate width below requested width".to_string());
        }

        let mut attestation = PqLaneAttestation {
            attestation_id: input.attestation_id.clone(),
            lane_id: input.lane_id.clone(),
            clearing_id: input.clearing_id.clone(),
            attestor_commitment: input.attestor_commitment,
            pq_signature_root: input.pq_signature_root,
            recursive_proof_root: input.recursive_proof_root,
            aggregation_transcript_root: input.aggregation_transcript_root,
            state_root_claim: input.state_root_claim,
            quorum_weight_bps: input.quorum_weight_bps,
            verdict: input.verdict,
            attested_latency_ms: input.attested_latency_ms,
            recursion_depth_observed: input.recursion_depth_observed,
            aggregate_width_observed: input.aggregate_width_observed,
            created_at_slot: input.created_at_slot,
            expires_at_slot: input
                .created_at_slot
                .saturating_add(self.config.attestation_ttl_slots),
            sequence: self.counters.pq_attestations.saturating_add(1),
            root: String::new(),
        };
        attestation.root = payload_root(D_ATTESTATIONS, &record_without_root(&attestation));
        if matches!(input.verdict, AttestationVerdict::Slash) {
            self.mark_order_slashed(&input.clearing_id)?;
        } else if let Some(order) = self.clearing_orders.get_mut(&input.clearing_id) {
            order.status = if matches!(input.verdict, AttestationVerdict::Include) {
                ClearingStatus::Attested
            } else {
                ClearingStatus::Recursing
            };
            order.sequence = order.sequence.saturating_add(1);
            order.root = payload_root(D_ORDERS, &record_without_root(order));
        }
        if let Some(lane) = self.lanes.get_mut(&input.lane_id) {
            lane.last_attested_height = lane
                .last_attested_height
                .max(DEVNET_HEIGHT.saturating_add(input.created_at_slot));
            lane.sequence = lane.sequence.saturating_add(1);
            lane.root = payload_root(D_LANES, &record_without_root(lane));
        }
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.counters.recursive_segments_attested = self
            .counters
            .recursive_segments_attested
            .saturating_add(input.recursion_depth_observed as u64);
        self.attestations
            .insert(input.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(input.attestation_id)
    }

    pub fn score_delivery(&mut self, input: ScoreDeliveryInput) -> Result<String> {
        ensure_nonempty("qos_id", &input.qos_id)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_nonempty("clearing_id", &input.clearing_id)?;
        ensure_root("recursive_proof_root", &input.recursive_proof_root)?;
        ensure_root("delivery_commitment", &input.delivery_commitment)?;
        ensure_absent("delivery_qos", &self.delivery_qos, &input.qos_id)?;
        ensure_capacity(
            "delivery_qos",
            self.delivery_qos.len(),
            self.config.max_delivery_qos,
        )?;
        ensure_bps("availability_bps", input.availability_bps)?;
        ensure_bps("correctness_bps", input.correctness_bps)?;
        ensure_bps("recursion_integrity_bps", input.recursion_integrity_bps)?;
        ensure_bps("privacy_bps", input.privacy_bps)?;
        ensure_bps("fee_efficiency_bps", input.fee_efficiency_bps)?;
        let order = self
            .clearing_orders
            .get(&input.clearing_id)
            .ok_or_else(|| format!("unknown clearing order `{}`", input.clearing_id))?
            .clone();
        if order.lane_id != input.lane_id {
            return Err("qos lane does not match clearing order".to_string());
        }

        let latency_bps = latency_score_bps(input.observed_latency_ms, order.target_latency_ms);
        let aggregate_qos_bps = weighted_average_bps(&[
            (latency_bps, 30),
            (input.availability_bps, 18),
            (input.correctness_bps, 24),
            (input.recursion_integrity_bps, 16),
            (input.privacy_bps, 8),
            (input.fee_efficiency_bps, 4),
        ]);
        let grade = QosGrade::from_score(&self.config, aggregate_qos_bps);
        let mut score = ProofDeliveryQosScore {
            qos_id: input.qos_id.clone(),
            lane_id: input.lane_id.clone(),
            clearing_id: input.clearing_id.clone(),
            recursive_proof_root: input.recursive_proof_root,
            delivery_commitment: input.delivery_commitment,
            observed_latency_ms: input.observed_latency_ms,
            target_latency_ms: order.target_latency_ms,
            availability_bps: input.availability_bps,
            correctness_bps: input.correctness_bps,
            recursion_integrity_bps: input.recursion_integrity_bps,
            privacy_bps: input.privacy_bps,
            fee_efficiency_bps: input.fee_efficiency_bps,
            aggregate_qos_bps,
            grade,
            scored_at_slot: input.scored_at_slot,
            sequence: self.counters.delivery_qos_scores.saturating_add(1),
            root: String::new(),
        };
        score.root = payload_root(D_QOS, &record_without_root(&score));
        self.counters.delivery_qos_scores = self.counters.delivery_qos_scores.saturating_add(1);
        self.delivery_qos.insert(input.qos_id.clone(), score);
        if let Some(order) = self.clearing_orders.get_mut(&input.clearing_id) {
            order.qos_score_id = Some(input.qos_id.clone());
            order.status = if aggregate_qos_bps >= self.config.min_delivery_qos_bps {
                ClearingStatus::Delivered
            } else {
                ClearingStatus::Late
            };
            order.sequence = order.sequence.saturating_add(1);
            order.root = payload_root(D_ORDERS, &record_without_root(order));
        }
        self.refresh_lane_scores(&input.lane_id)?;
        self.refresh_roots();
        Ok(input.qos_id)
    }

    pub fn settle_clearing(&mut self, input: SettleClearingInput) -> Result<String> {
        ensure_nonempty("settlement_id", &input.settlement_id)?;
        ensure_nonempty("clearing_id", &input.clearing_id)?;
        ensure_nonempty("curve_id", &input.curve_id)?;
        ensure_root("settlement_root", &input.settlement_root)?;
        ensure_absent("settlement", &self.settlements, &input.settlement_id)?;
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        if input.priority_fee_micros > self.config.priority_fee_cap_micros {
            return Err("settlement priority fee exceeds configured cap".to_string());
        }

        let order = self
            .clearing_orders
            .get(&input.clearing_id)
            .ok_or_else(|| format!("unknown clearing order `{}`", input.clearing_id))?
            .clone();
        let curve = self
            .curves
            .get(&input.curve_id)
            .ok_or_else(|| format!("unknown curve `{}`", input.curve_id))?
            .clone();
        if order.matched_curve_id.as_deref() != Some(input.curve_id.as_str()) {
            return Err("clearing order is not matched to settlement curve".to_string());
        }
        if input.settled_at_slot
            < order
                .created_at_slot
                .saturating_add(self.config.settlement_delay_slots)
        {
            return Err("settlement before configured delay".to_string());
        }
        let qos_id = order
            .qos_score_id
            .as_ref()
            .ok_or_else(|| "clearing order has no proof delivery qos score".to_string())?;
        let qos = self
            .delivery_qos
            .get(qos_id)
            .ok_or_else(|| format!("unknown delivery qos `{qos_id}`"))?;
        let lane = self
            .lanes
            .get(&order.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", order.lane_id))?;
        let pricing =
            self.compute_settlement_pricing(&order, &curve, qos, lane, input.priority_fee_micros);
        let status = if qos.aggregate_qos_bps >= curve.min_delivery_qos_bps {
            SettlementStatus::Settled
        } else if matches!(order.status, ClearingStatus::Late) {
            SettlementStatus::Repriced
        } else {
            SettlementStatus::Rejected
        };

        let mut settlement = FeeAwareSettlement {
            settlement_id: input.settlement_id.clone(),
            clearing_id: input.clearing_id.clone(),
            curve_id: input.curve_id,
            lane_id: order.lane_id.clone(),
            settlement_status: status,
            fee_asset_id: self.config.fee_asset_id.clone(),
            gross_fee_micros: pricing.gross_fee_micros,
            priority_fee_micros: input.priority_fee_micros,
            maker_rebate_micros: pricing.maker_rebate_micros,
            taker_fee_micros: pricing.taker_fee_micros,
            privacy_rebate_micros: pricing.privacy_rebate_micros,
            recursion_rebate_micros: pricing.recursion_rebate_micros,
            late_penalty_micros: pricing.late_penalty_micros,
            congestion_penalty_micros: pricing.congestion_penalty_micros,
            net_settlement_micros: pricing.net_settlement_micros,
            delivery_qos_bps: qos.aggregate_qos_bps,
            settlement_root: input.settlement_root,
            settled_at_slot: input.settled_at_slot,
            sequence: self.counters.settlements.saturating_add(1),
            root: String::new(),
        };
        settlement.root = payload_root(D_SETTLEMENTS, &record_without_root(&settlement));
        self.counters.settlements = self.counters.settlements.saturating_add(1);
        if matches!(status, SettlementStatus::Repriced) {
            self.counters.late_settlements = self.counters.late_settlements.saturating_add(1);
        }
        self.counters.total_fee_micros = self
            .counters
            .total_fee_micros
            .saturating_add(settlement.net_settlement_micros);
        self.counters.maker_rebates_micros = self
            .counters
            .maker_rebates_micros
            .saturating_add(settlement.maker_rebate_micros);
        self.counters.taker_fees_micros = self
            .counters
            .taker_fees_micros
            .saturating_add(settlement.taker_fee_micros);
        if let Some(order) = self.clearing_orders.get_mut(&input.clearing_id) {
            order.status = if matches!(status, SettlementStatus::Rejected) {
                ClearingStatus::Late
            } else {
                ClearingStatus::Settled
            };
            order.settlement_id = Some(input.settlement_id.clone());
            order.sequence = order.sequence.saturating_add(1);
            order.root = payload_root(D_ORDERS, &record_without_root(order));
        }
        self.settlements
            .insert(input.settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(input.settlement_id)
    }

    pub fn cancel_order(&mut self, clearing_id: &str) -> Result<()> {
        let order = self
            .clearing_orders
            .get_mut(clearing_id)
            .ok_or_else(|| format!("unknown clearing order `{clearing_id}`"))?;
        if !matches!(
            order.status,
            ClearingStatus::Open | ClearingStatus::CurveMatched
        ) {
            return Err("only open or curve-matched clearing orders can be cancelled".to_string());
        }
        order.status = ClearingStatus::Cancelled;
        order.sequence = order.sequence.saturating_add(1);
        order.root = payload_root(D_ORDERS, &record_without_root(order));
        self.counters.cancelled_orders = self.counters.cancelled_orders.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn expire_orders(&mut self, slot: u64) -> Vec<String> {
        let mut expired = Vec::new();
        for (clearing_id, order) in self.clearing_orders.iter_mut() {
            if order.is_expired(slot) {
                order.status = ClearingStatus::Expired;
                order.sequence = order.sequence.saturating_add(1);
                order.root = payload_root(D_ORDERS, &record_without_root(order));
                expired.push(clearing_id.clone());
            }
        }
        if !expired.is_empty() {
            self.counters.expired_orders = self
                .counters
                .expired_orders
                .saturating_add(expired.len() as u64);
            self.refresh_roots();
        }
        expired
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&mut self, height: u64, epoch: u64) -> Result<PublicRecord> {
        ensure_capacity(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        self.refresh_roots();
        let sequence = self.counters.public_records.saturating_add(1);
        let public_root = payload_root(
            D_PUBLIC,
            &json!({
                "state_root": self.roots.state_root,
                "lanes_root": self.roots.lanes_root,
                "clearing_orders_root": self.roots.clearing_orders_root,
                "curves_root": self.roots.curves_root,
                "attestations_root": self.roots.attestations_root,
                "delivery_qos_root": self.roots.delivery_qos_root,
                "settlements_root": self.roots.settlements_root,
                "nullifier_root": self.roots.nullifier_root,
                "height": height,
                "epoch": epoch,
                "sequence": sequence,
            }),
        );
        let record_id = domain_hash(
            D_PUBLIC,
            &[
                HashPart::Str(PUBLIC_RECORD_SCHEME),
                HashPart::Str(&public_root),
                HashPart::U64(sequence),
            ],
            32,
        );
        let record = PublicRecord {
            record_id: record_id.clone(),
            scheme: PUBLIC_RECORD_SCHEME.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            state_root: self.roots.state_root.clone(),
            public_root,
            lane_root: self.roots.lanes_root.clone(),
            clearing_orders_root: self.roots.clearing_orders_root.clone(),
            curves_root: self.roots.curves_root.clone(),
            attestations_root: self.roots.attestations_root.clone(),
            delivery_qos_root: self.roots.delivery_qos_root.clone(),
            settlements_root: self.roots.settlements_root.clone(),
            counters_root: self.roots.counters_root.clone(),
            nullifier_root: self.roots.nullifier_root.clone(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            height,
            epoch,
            sequence,
        };
        self.counters.public_records = sequence;
        self.public_records.insert(record_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = payload_root(D_CONFIG, &self.config.public_record());
        self.roots.counters_root = payload_root(D_COUNTERS, &self.counters.public_record());
        self.roots.lanes_root = merkle_records(D_LANES, &self.public_lane_records());
        self.roots.clearing_orders_root =
            merkle_records(D_ORDERS, &self.public_clearing_order_records());
        self.roots.curves_root = merkle_records(D_CURVES, &self.public_curve_records());
        self.roots.attestations_root =
            merkle_records(D_ATTESTATIONS, &self.public_attestation_records());
        self.roots.delivery_qos_root = merkle_records(D_QOS, &self.public_qos_records());
        self.roots.settlements_root =
            merkle_records(D_SETTLEMENTS, &self.public_settlement_records());
        self.roots.nullifier_root = set_root(D_NULLIFIERS, &self.consumed_nullifiers);
        self.roots.public_records_root =
            merkle_records(D_PUBLIC, &public_record_map(&self.public_records));
        self.counters.state_root_updates = self.counters.state_root_updates.saturating_add(1);
        self.roots.counters_root = payload_root(D_COUNTERS, &self.counters.public_record());
        self.roots.state_root = payload_root(
            D_STATE,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "schema_version": SCHEMA_VERSION,
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "lanes_root": self.roots.lanes_root,
                "clearing_orders_root": self.roots.clearing_orders_root,
                "curves_root": self.roots.curves_root,
                "attestations_root": self.roots.attestations_root,
                "delivery_qos_root": self.roots.delivery_qos_root,
                "settlements_root": self.roots.settlements_root,
                "nullifier_root": self.roots.nullifier_root,
                "public_records_root": self.roots.public_records_root,
            }),
        );
    }

    fn mark_order_slashed(&mut self, clearing_id: &str) -> Result<()> {
        let order = self
            .clearing_orders
            .get_mut(clearing_id)
            .ok_or_else(|| format!("unknown clearing order `{clearing_id}`"))?;
        order.status = ClearingStatus::Slashed;
        order.sequence = order.sequence.saturating_add(1);
        order.root = payload_root(D_ORDERS, &record_without_root(order));
        self.counters.slashed_orders = self.counters.slashed_orders.saturating_add(1);
        Ok(())
    }

    fn refresh_lane_scores(&mut self, lane_id: &str) -> Result<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("unknown lane `{lane_id}`"))?;
        let qos_entries = self
            .delivery_qos
            .values()
            .filter(|qos| qos.lane_id == lane_id)
            .collect::<Vec<_>>();
        if !qos_entries.is_empty() {
            let qos_total = qos_entries
                .iter()
                .fold(0_u64, |acc, qos| acc.saturating_add(qos.aggregate_qos_bps));
            let fill_total = qos_entries.iter().fold(0_u64, |acc, qos| {
                acc.saturating_add(ratio_bps(
                    qos.observed_latency_ms,
                    qos.target_latency_ms.max(1),
                ))
            });
            lane.rolling_qos_bps = qos_total / qos_entries.len() as u64;
            lane.rolling_fill_bps = MAX_BPS.saturating_sub(fill_total / qos_entries.len() as u64);
        }
        lane.status = if lane.rolling_qos_bps < self.config.min_delivery_qos_bps {
            LaneStatus::Congested
        } else if lane.rolling_fill_bps >= self.config.target_recursion_fill_bps {
            LaneStatus::Hot
        } else if lane.status == LaneStatus::Registered {
            LaneStatus::Open
        } else {
            lane.status
        };
        lane.sequence = lane.sequence.saturating_add(1);
        lane.root = payload_root(D_LANES, &record_without_root(lane));
        Ok(())
    }

    fn compute_settlement_pricing(
        &self,
        order: &RecursiveProofClearingOrder,
        curve: &PreconfirmationClearingCurve,
        qos: &ProofDeliveryQosScore,
        lane: &ConfidentialRecursiveProofLane,
        priority_fee_micros: u64,
    ) -> SettlementPricing {
        let complexity_fee = order
            .notional_fee_micros
            .saturating_mul(order.proof_class.complexity_weight())
            .saturating_div(1_000);
        let lane_fee = complexity_fee
            .saturating_mul(lane.lane_class.priority_weight())
            .saturating_div(MAX_BPS);
        let recursion_fee = lane_fee
            .saturating_mul(order.requested_recursion_depth as u64)
            .saturating_div(curve.max_recursion_depth.max(1) as u64);
        let width_fee = lane_fee
            .saturating_mul(order.requested_aggregate_width as u64)
            .saturating_div(curve.max_aggregate_width.max(1) as u64)
            .saturating_div(2);
        let gross_fee_micros = curve
            .base_fee_micros
            .saturating_add(lane_fee)
            .saturating_add(recursion_fee)
            .saturating_add(width_fee)
            .saturating_add(priority_fee_micros)
            .saturating_add(self.config.base_settlement_fee_micros);
        let maker_rebate_micros = gross_fee_micros
            .saturating_mul(self.config.maker_rebate_bps)
            .saturating_div(MAX_BPS);
        let taker_fee_micros = gross_fee_micros
            .saturating_mul(self.config.taker_fee_bps)
            .saturating_div(MAX_BPS);
        let privacy_rebate_micros = gross_fee_micros
            .saturating_mul(lane.privacy_bonus_bps(&self.config))
            .saturating_div(MAX_BPS);
        let recursion_rebate_micros = gross_fee_micros
            .saturating_mul(lane.recursion_bonus_bps(&self.config, order.requested_recursion_depth))
            .saturating_div(MAX_BPS);
        let late_penalty_micros = if qos.aggregate_qos_bps < self.config.min_delivery_qos_bps {
            gross_fee_micros
                .saturating_mul(self.config.late_proof_penalty_bps)
                .saturating_div(MAX_BPS)
        } else {
            0
        };
        let congestion_penalty_micros = gross_fee_micros
            .saturating_mul(lane.congestion_bps.min(self.config.congestion_penalty_bps))
            .saturating_div(MAX_BPS);
        let qos_rebate_micros = gross_fee_micros
            .saturating_mul(qos.aggregate_qos_bps)
            .saturating_div(MAX_BPS)
            .saturating_div(25);
        let net_settlement_micros = gross_fee_micros
            .saturating_add(taker_fee_micros)
            .saturating_add(late_penalty_micros)
            .saturating_add(congestion_penalty_micros)
            .saturating_sub(maker_rebate_micros)
            .saturating_sub(privacy_rebate_micros)
            .saturating_sub(recursion_rebate_micros)
            .saturating_sub(qos_rebate_micros);
        SettlementPricing {
            gross_fee_micros,
            maker_rebate_micros,
            taker_fee_micros,
            privacy_rebate_micros,
            recursion_rebate_micros,
            late_penalty_micros,
            congestion_penalty_micros,
            net_settlement_micros,
        }
    }

    fn public_lane_records(&self) -> BTreeMap<String, Value> {
        self.lanes
            .iter()
            .map(|(key, lane)| (key.clone(), lane.public_record()))
            .collect()
    }

    fn public_clearing_order_records(&self) -> BTreeMap<String, Value> {
        self.clearing_orders
            .iter()
            .map(|(key, order)| (key.clone(), order.public_record()))
            .collect()
    }

    fn public_curve_records(&self) -> BTreeMap<String, Value> {
        self.curves
            .iter()
            .map(|(key, curve)| (key.clone(), curve.public_record()))
            .collect()
    }

    fn public_attestation_records(&self) -> BTreeMap<String, Value> {
        self.attestations
            .iter()
            .map(|(key, attestation)| (key.clone(), attestation.public_record()))
            .collect()
    }

    fn public_qos_records(&self) -> BTreeMap<String, Value> {
        self.delivery_qos
            .iter()
            .map(|(key, qos)| (key.clone(), qos.public_record()))
            .collect()
    }

    fn public_settlement_records(&self) -> BTreeMap<String, Value> {
        self.settlements
            .iter()
            .map(|(key, settlement)| (key.clone(), settlement.public_record()))
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct SettlementPricing {
    gross_fee_micros: u64,
    maker_rebate_micros: u64,
    taker_fee_micros: u64,
    privacy_rebate_micros: u64,
    recursion_rebate_micros: u64,
    late_penalty_micros: u64,
    congestion_penalty_micros: u64,
    net_settlement_micros: u64,
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let lane_id = "devnet-recursive-proof-latency-clearing-lane-0".to_string();
    state
        .register_lane(RegisterLaneInput {
            lane_id: lane_id.clone(),
            operator_commitment: dev_hash("operator", 0),
            lane_class: LaneClass::RecursiveAggregator,
            pq_attestation_key_root: dev_hash("pq-key-root", 0),
            recursion_capacity_commitment: dev_hash("recursion-capacity", 0),
            fee_escrow_commitment: dev_hash("fee-escrow", 0),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            congestion_bps: 210,
            max_recursion_depth: 16,
            max_aggregate_width: 128,
            created_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet lane must register");
    state
        .set_lane_status(&lane_id, LaneStatus::Hot)
        .expect("devnet lane status must update");
    state
        .post_curve(PostCurveInput {
            curve_id: "devnet-preconfirmation-recursive-clearing-curve-0".to_string(),
            lane_id,
            curve_kind: CurveKind::RecursionPremium,
            sealed_curve_root: dev_hash("sealed-curve", 0),
            maker_commitment: dev_hash("maker", 0),
            target_latency_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            max_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            base_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            min_delivery_qos_bps: DEFAULT_MIN_DELIVERY_QOS_BPS,
            max_recursion_depth: 16,
            max_aggregate_width: 128,
            capacity_units: 4_096,
            valid_from_slot: DEVNET_EPOCH,
            valid_until_slot: DEVNET_EPOCH + DEFAULT_CURVE_TTL_SLOTS,
        })
        .expect("devnet curve must post");
    state.refresh_roots();
    state
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &mut State, height: u64, epoch: u64) -> Result<PublicRecord> {
    state.public_record(height, epoch)
}

pub fn devnet_state_root() -> String {
    devnet().state_root()
}

pub fn devnet_public_record() -> PublicRecord {
    devnet()
        .public_record(DEVNET_HEIGHT, DEVNET_EPOCH)
        .expect("devnet public record")
}

pub fn latency_score_bps(observed_latency_ms: u64, target_latency_ms: u64) -> u64 {
    if observed_latency_ms <= target_latency_ms {
        return MAX_BPS;
    }
    let overage = observed_latency_ms.saturating_sub(target_latency_ms);
    let penalty = overage
        .saturating_mul(MAX_BPS)
        .saturating_div(target_latency_ms.max(1));
    MAX_BPS.saturating_sub(penalty.min(MAX_BPS))
}

pub fn weighted_average_bps(parts: &[(u64, u64)]) -> u64 {
    let total_weight: u64 = parts.iter().map(|(_, weight)| *weight).sum();
    if total_weight == 0 {
        return 0;
    }
    parts
        .iter()
        .map(|(value, weight)| value.min(&MAX_BPS).saturating_mul(*weight))
        .sum::<u64>()
        .saturating_div(total_weight)
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

fn public_record_map(records: &BTreeMap<String, PublicRecord>) -> BTreeMap<String, Value> {
    records
        .iter()
        .map(|(key, record)| (key.clone(), record.public_record()))
        .collect()
}

fn empty_root(label: &str) -> String {
    payload_root(
        "EMPTY-RECURSIVE-PROOF-LATENCY-CLEARING-ROOT",
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
