use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelProofLatencySwapRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_PROOF_LATENCY_SWAP_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-parallel-proof-latency-swap-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_PROOF_LATENCY_SWAP_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const PARALLEL_PROOF_LATENCY_SWAP_SUITE: &str =
    "private-l2-fast-pq-confidential-parallel-proof-latency-swap-v1";
pub const PRECONFIRMATION_SWAP_CURVE_SUITE: &str =
    "ml-kem-1024-sealed-preconfirmation-latency-swap-curve-v1";
pub const PQ_LANE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-parallel-proof-lane-attestation-v1";
pub const PROOF_DELIVERY_QOS_SUITE: &str =
    "private-l2-fast-confidential-proof-delivery-qos-score-v1";
pub const FEE_AWARE_SETTLEMENT_SUITE: &str =
    "private-l2-fast-confidential-parallel-proof-latency-fee-aware-settlement-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "privacy-preserving-public-parallel-proof-latency-swap-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_proofs_addresses_view_keys_payloads_curve_points_or_fee_amounts";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_EPOCH: u64 = 36_864;
pub const DEVNET_HEIGHT: u64 = 7_040_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 90;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 150;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 390;
pub const DEFAULT_SWAP_TTL_SLOTS: u64 = 80;
pub const DEFAULT_CURVE_TTL_SLOTS: u64 = 28;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 128;
pub const DEFAULT_QOS_WINDOW_SLOTS: u64 = 64;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 2;
pub const DEFAULT_MAX_LANES: usize = 65_536;
pub const DEFAULT_MAX_SWAPS: usize = 1_048_576;
pub const DEFAULT_MAX_CURVES: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_QOS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 262_144;
pub const DEFAULT_MIN_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_WEIGHT_BPS: u64 = 8_200;
pub const DEFAULT_MIN_DELIVERY_QOS_BPS: u64 = 8_500;
pub const DEFAULT_TARGET_PARALLEL_FILL_BPS: u64 = 8_900;
pub const DEFAULT_LOW_FEE_BONUS_BPS: u64 = 650;
pub const DEFAULT_PRIVACY_BONUS_BPS: u64 = 425;
pub const DEFAULT_CONGESTION_PENALTY_BPS: u64 = 1_050;
pub const DEFAULT_LATE_PROOF_PENALTY_BPS: u64 = 1_700;
pub const DEFAULT_PRIORITY_FEE_CAP_MICROS: u64 = 88;
pub const DEFAULT_BASE_SETTLEMENT_FEE_MICROS: u64 = 4;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 125;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 235;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:LANES";
const D_SWAPS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:SWAPS";
const D_CURVES: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:CURVES";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:ATTESTATIONS";
const D_QOS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:QOS";
const D_SETTLEMENTS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:SETTLEMENTS";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:NULLIFIERS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-PARALLEL-PROOF-LATENCY-SWAP:DEVNET";

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
    ProofCarry,
    AggregatorRelay,
    EmergencyCancel,
}

impl LaneClass {
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_950,
            Self::BridgeExit => 10_300,
            Self::MerchantPos => 9_900,
            Self::DefiIntent => 9_650,
            Self::ContractCall => 9_250,
            Self::WalletFast => 9_050,
            Self::ProofCarry => 8_800,
            Self::AggregatorRelay => 8_450,
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
    pub fn accepts_swaps(self) -> bool {
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
pub enum ProofClass {
    ValidityRollup,
    ReceiptInclusion,
    StateTransition,
    BridgeExit,
    NullifierBatch,
    ContractExecution,
    FraudChallenge,
    RepairShard,
}

impl ProofClass {
    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::FraudChallenge => 1_220,
            Self::BridgeExit => 1_140,
            Self::StateTransition => 1_080,
            Self::ContractExecution => 1_030,
            Self::ValidityRollup => 990,
            Self::NullifierBatch => 930,
            Self::ReceiptInclusion => 820,
            Self::RepairShard => 760,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapSide {
    BuyLatency,
    SellProofCapacity,
    SponsorPreconfirmation,
    InsuranceBackstop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapStatus {
    Open,
    CurveMatched,
    Parallelizing,
    Attested,
    Delivered,
    Settled,
    Late,
    Expired,
    Cancelled,
    Slashed,
}

impl SwapStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::CurveMatched
                | Self::Parallelizing
                | Self::Attested
                | Self::Delivered
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
    ParallelPremium,
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
    pub swap_ttl_slots: u64,
    pub curve_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub qos_window_slots: u64,
    pub settlement_delay_slots: u64,
    pub max_lanes: usize,
    pub max_swaps: usize,
    pub max_curves: usize,
    pub max_attestations: usize,
    pub max_delivery_qos: usize,
    pub max_settlements: usize,
    pub max_public_records: usize,
    pub min_quorum_weight_bps: u64,
    pub strong_quorum_weight_bps: u64,
    pub min_delivery_qos_bps: u64,
    pub target_parallel_fill_bps: u64,
    pub low_fee_bonus_bps: u64,
    pub privacy_bonus_bps: u64,
    pub congestion_penalty_bps: u64,
    pub late_proof_penalty_bps: u64,
    pub priority_fee_cap_micros: u64,
    pub base_settlement_fee_micros: u64,
    pub maker_rebate_bps: u64,
    pub taker_fee_bps: u64,
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
            swap_ttl_slots: DEFAULT_SWAP_TTL_SLOTS,
            curve_ttl_slots: DEFAULT_CURVE_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            qos_window_slots: DEFAULT_QOS_WINDOW_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            max_lanes: DEFAULT_MAX_LANES,
            max_swaps: DEFAULT_MAX_SWAPS,
            max_curves: DEFAULT_MAX_CURVES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_delivery_qos: DEFAULT_MAX_QOS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            min_quorum_weight_bps: DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            min_delivery_qos_bps: DEFAULT_MIN_DELIVERY_QOS_BPS,
            target_parallel_fill_bps: DEFAULT_TARGET_PARALLEL_FILL_BPS,
            low_fee_bonus_bps: DEFAULT_LOW_FEE_BONUS_BPS,
            privacy_bonus_bps: DEFAULT_PRIVACY_BONUS_BPS,
            congestion_penalty_bps: DEFAULT_CONGESTION_PENALTY_BPS,
            late_proof_penalty_bps: DEFAULT_LATE_PROOF_PENALTY_BPS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            base_settlement_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
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
        ensure_positive_u64("swap_ttl_slots", self.swap_ttl_slots)?;
        ensure_positive_u64("curve_ttl_slots", self.curve_ttl_slots)?;
        ensure_positive_u64("attestation_ttl_slots", self.attestation_ttl_slots)?;
        ensure_positive_u64("qos_window_slots", self.qos_window_slots)?;
        ensure_positive_u64("settlement_delay_slots", self.settlement_delay_slots)?;
        ensure_positive_usize("max_lanes", self.max_lanes)?;
        ensure_positive_usize("max_swaps", self.max_swaps)?;
        ensure_positive_usize("max_curves", self.max_curves)?;
        ensure_positive_usize("max_attestations", self.max_attestations)?;
        ensure_positive_usize("max_delivery_qos", self.max_delivery_qos)?;
        ensure_positive_usize("max_settlements", self.max_settlements)?;
        ensure_positive_usize("max_public_records", self.max_public_records)?;
        ensure_bps("min_quorum_weight_bps", self.min_quorum_weight_bps)?;
        ensure_bps("strong_quorum_weight_bps", self.strong_quorum_weight_bps)?;
        ensure_bps("min_delivery_qos_bps", self.min_delivery_qos_bps)?;
        ensure_bps("target_parallel_fill_bps", self.target_parallel_fill_bps)?;
        ensure_bps("low_fee_bonus_bps", self.low_fee_bonus_bps)?;
        ensure_bps("privacy_bonus_bps", self.privacy_bonus_bps)?;
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
            "swap_suite": PARALLEL_PROOF_LATENCY_SWAP_SUITE,
            "curve_suite": PRECONFIRMATION_SWAP_CURVE_SUITE,
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
            "privacy_boundary": PRIVACY_BOUNDARY,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub swaps_opened: u64,
    pub curves_posted: u64,
    pub curves_matched: u64,
    pub parallel_segments_requested: u64,
    pub parallel_segments_attested: u64,
    pub pq_attestations: u64,
    pub delivery_qos_scores: u64,
    pub settlements: u64,
    pub late_settlements: u64,
    pub slashed_swaps: u64,
    pub expired_swaps: u64,
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
    pub swaps_root: String,
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
            swaps_root: empty_root(D_SWAPS),
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
pub struct ConfidentialProofLane {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_class: LaneClass,
    pub status: LaneStatus,
    pub pq_attestation_key_root: String,
    pub proof_capacity_commitment: String,
    pub fee_escrow_commitment: String,
    pub privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub congestion_bps: u64,
    pub rolling_qos_bps: u64,
    pub rolling_fill_bps: u64,
    pub max_parallel_segments: u16,
    pub created_at_height: u64,
    pub last_attested_height: u64,
    pub sequence: u64,
    pub root: String,
}

impl ConfidentialProofLane {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_proof_lane",
            "lane_id": self.lane_id,
            "lane_class": self.lane_class,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "quorum_weight_bps": self.quorum_weight_bps,
            "congestion_bps": self.congestion_bps,
            "rolling_qos_bps": self.rolling_qos_bps,
            "rolling_fill_bps": self.rolling_fill_bps,
            "max_parallel_segments": self.max_parallel_segments,
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RegisterLaneInput {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_class: LaneClass,
    pub pq_attestation_key_root: String,
    pub proof_capacity_commitment: String,
    pub fee_escrow_commitment: String,
    pub privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub congestion_bps: u64,
    pub max_parallel_segments: u16,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ParallelProofLatencySwap {
    pub swap_id: String,
    pub lane_id: String,
    pub side: SwapSide,
    pub proof_class: ProofClass,
    pub status: SwapStatus,
    pub encrypted_proof_hint_root: String,
    pub proof_request_commitment: String,
    pub state_root_before: String,
    pub expected_state_root_after: String,
    pub proof_output_root: String,
    pub privacy_fence_root: String,
    pub requested_parallel_segments: u16,
    pub attested_parallel_segments: u16,
    pub notional_fee_micros: u64,
    pub max_priority_fee_micros: u64,
    pub target_latency_ms: u64,
    pub deadline_slot: u64,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub matched_curve_id: Option<String>,
    pub delivery_qos_id: Option<String>,
    pub settlement_id: Option<String>,
    pub sequence: u64,
    pub root: String,
}

impl ParallelProofLatencySwap {
    pub fn is_expired(&self, slot: u64) -> bool {
        self.status.live() && slot > self.expires_at_slot
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_proof_latency_swap",
            "swap_id": self.swap_id,
            "lane_id": self.lane_id,
            "side": self.side,
            "proof_class": self.proof_class,
            "status": self.status,
            "state_root_before": self.state_root_before,
            "expected_state_root_after": self.expected_state_root_after,
            "proof_output_root": self.proof_output_root,
            "requested_parallel_segments": self.requested_parallel_segments,
            "attested_parallel_segments": self.attested_parallel_segments,
            "target_latency_ms": self.target_latency_ms,
            "deadline_slot": self.deadline_slot,
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "matched_curve_id": self.matched_curve_id,
            "delivery_qos_id": self.delivery_qos_id,
            "settlement_id": self.settlement_id,
            "sequence": self.sequence,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenSwapInput {
    pub swap_id: String,
    pub lane_id: String,
    pub side: SwapSide,
    pub proof_class: ProofClass,
    pub encrypted_proof_hint_root: String,
    pub proof_request_commitment: String,
    pub state_root_before: String,
    pub expected_state_root_after: String,
    pub proof_output_root: String,
    pub privacy_fence_root: String,
    pub requested_parallel_segments: u16,
    pub notional_fee_micros: u64,
    pub max_priority_fee_micros: u64,
    pub target_latency_ms: u64,
    pub deadline_slot: u64,
    pub created_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PreconfirmationLatencySwapCurve {
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
    pub max_parallel_segments: u16,
    pub capacity_units: u64,
    pub filled_units: u64,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
    pub active: bool,
    pub sequence: u64,
    pub root: String,
}

impl PreconfirmationLatencySwapCurve {
    pub fn accepts(&self, swap: &ParallelProofLatencySwap, slot: u64) -> bool {
        let swap_window_ms = swap
            .deadline_slot
            .saturating_sub(swap.created_at_slot)
            .saturating_mul(DEFAULT_SLOT_WIDTH_MS);
        self.active
            && self.lane_id == swap.lane_id
            && slot >= self.valid_from_slot
            && slot <= self.valid_until_slot
            && self.filled_units < self.capacity_units
            && self.target_latency_ms <= swap.target_latency_ms
            && self.max_latency_ms <= swap_window_ms
            && self.priority_fee_cap_micros <= swap.max_priority_fee_micros
            && self.max_parallel_segments >= swap.requested_parallel_segments
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_latency_swap_curve",
            "curve_id": self.curve_id,
            "lane_id": self.lane_id,
            "curve_kind": self.curve_kind,
            "target_latency_ms": self.target_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "min_delivery_qos_bps": self.min_delivery_qos_bps,
            "max_parallel_segments": self.max_parallel_segments,
            "capacity_units": self.capacity_units,
            "filled_units": self.filled_units,
            "valid_from_slot": self.valid_from_slot,
            "valid_until_slot": self.valid_until_slot,
            "active": self.active,
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
    pub max_parallel_segments: u16,
    pub capacity_units: u64,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub swap_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub proof_segment_root: String,
    pub state_root_claim: String,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub segment_index: u16,
    pub segment_count: u16,
    pub verdict: AttestationVerdict,
    pub attested_latency_ms: u64,
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
            "swap_id": self.swap_id,
            "state_root_claim": self.state_root_claim,
            "quorum_weight_bps": self.quorum_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "segment_index": self.segment_index,
            "segment_count": self.segment_count,
            "verdict": self.verdict,
            "attested_latency_ms": self.attested_latency_ms,
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
    pub swap_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub proof_segment_root: String,
    pub state_root_claim: String,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub segment_index: u16,
    pub segment_count: u16,
    pub verdict: AttestationVerdict,
    pub attested_latency_ms: u64,
    pub created_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProofDeliveryQosScore {
    pub qos_id: String,
    pub lane_id: String,
    pub swap_id: String,
    pub proof_output_root: String,
    pub delivery_commitment: String,
    pub observed_latency_ms: u64,
    pub target_latency_ms: u64,
    pub availability_bps: u64,
    pub correctness_bps: u64,
    pub privacy_bps: u64,
    pub parallelism_bps: u64,
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
            "swap_id": self.swap_id,
            "proof_output_root": self.proof_output_root,
            "observed_latency_ms": self.observed_latency_ms,
            "target_latency_ms": self.target_latency_ms,
            "availability_bps": self.availability_bps,
            "correctness_bps": self.correctness_bps,
            "privacy_bps": self.privacy_bps,
            "parallelism_bps": self.parallelism_bps,
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
    pub swap_id: String,
    pub proof_output_root: String,
    pub delivery_commitment: String,
    pub observed_latency_ms: u64,
    pub availability_bps: u64,
    pub correctness_bps: u64,
    pub privacy_bps: u64,
    pub fee_efficiency_bps: u64,
    pub scored_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeAwareSettlement {
    pub settlement_id: String,
    pub swap_id: String,
    pub curve_id: String,
    pub lane_id: String,
    pub settlement_status: SettlementStatus,
    pub fee_asset_id: String,
    pub gross_fee_micros: u64,
    pub priority_fee_micros: u64,
    pub maker_rebate_micros: u64,
    pub taker_fee_micros: u64,
    pub privacy_rebate_micros: u64,
    pub parallelism_rebate_micros: u64,
    pub late_penalty_micros: u64,
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
            "swap_id": self.swap_id,
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
pub struct SettleSwapInput {
    pub settlement_id: String,
    pub swap_id: String,
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
    pub swaps_root: String,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, ConfidentialProofLane>,
    pub swaps: BTreeMap<String, ParallelProofLatencySwap>,
    pub curves: BTreeMap<String, PreconfirmationLatencySwapCurve>,
    pub attestations: BTreeMap<String, PqLaneAttestation>,
    pub delivery_qos: BTreeMap<String, ProofDeliveryQosScore>,
    pub settlements: BTreeMap<String, FeeAwareSettlement>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRecord>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            swaps: BTreeMap::new(),
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
        self.config.validate()?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_root("operator_commitment", &input.operator_commitment)?;
        ensure_root("pq_attestation_key_root", &input.pq_attestation_key_root)?;
        ensure_root(
            "proof_capacity_commitment",
            &input.proof_capacity_commitment,
        )?;
        ensure_root("fee_escrow_commitment", &input.fee_escrow_commitment)?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;
        ensure_bps("congestion_bps", input.congestion_bps)?;
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_absent("lane", &self.lanes, &input.lane_id)?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy_set_size below configured minimum".to_string());
        }
        if input.quorum_weight_bps < self.config.min_quorum_weight_bps {
            return Err("quorum_weight_bps below configured minimum".to_string());
        }
        if input.max_parallel_segments == 0 {
            return Err("max_parallel_segments must be positive".to_string());
        }
        let mut lane = ConfidentialProofLane {
            lane_id: input.lane_id.clone(),
            operator_commitment: input.operator_commitment,
            lane_class: input.lane_class,
            status: LaneStatus::Registered,
            pq_attestation_key_root: input.pq_attestation_key_root,
            proof_capacity_commitment: input.proof_capacity_commitment,
            fee_escrow_commitment: input.fee_escrow_commitment,
            privacy_set_size: input.privacy_set_size,
            quorum_weight_bps: input.quorum_weight_bps,
            congestion_bps: input.congestion_bps,
            rolling_qos_bps: self.config.min_delivery_qos_bps,
            rolling_fill_bps: 0,
            max_parallel_segments: input.max_parallel_segments,
            created_at_height: input.created_at_height,
            last_attested_height: input.created_at_height,
            sequence: self.counters.lanes_registered.saturating_add(1),
            root: String::new(),
        };
        lane.root = payload_root(D_LANES, &record_without_root(&lane));
        self.counters.lanes_registered = lane.sequence;
        self.lanes.insert(input.lane_id.clone(), lane);
        self.refresh_roots();
        Ok(input.lane_id)
    }

    pub fn set_lane_status(&mut self, lane_id: &str, status: LaneStatus) -> Result<()> {
        ensure_nonempty("lane_id", lane_id)?;
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

    pub fn open_swap(&mut self, input: OpenSwapInput) -> Result<String> {
        ensure_nonempty("swap_id", &input.swap_id)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_root(
            "encrypted_proof_hint_root",
            &input.encrypted_proof_hint_root,
        )?;
        ensure_root("proof_request_commitment", &input.proof_request_commitment)?;
        ensure_root("state_root_before", &input.state_root_before)?;
        ensure_root(
            "expected_state_root_after",
            &input.expected_state_root_after,
        )?;
        ensure_root("proof_output_root", &input.proof_output_root)?;
        ensure_root("privacy_fence_root", &input.privacy_fence_root)?;
        ensure_capacity("swaps", self.swaps.len(), self.config.max_swaps)?;
        ensure_absent("swap", &self.swaps, &input.swap_id)?;
        if input.max_priority_fee_micros > self.config.priority_fee_cap_micros {
            return Err("max_priority_fee_micros exceeds configured cap".to_string());
        }
        if input.target_latency_ms > self.config.hard_latency_ms {
            return Err("target_latency_ms exceeds hard latency limit".to_string());
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_swaps() {
            return Err("lane does not accept proof latency swaps".to_string());
        }
        if input.requested_parallel_segments == 0
            || input.requested_parallel_segments > lane.max_parallel_segments
        {
            return Err("requested_parallel_segments outside lane capacity".to_string());
        }
        let mut swap = ParallelProofLatencySwap {
            swap_id: input.swap_id.clone(),
            lane_id: input.lane_id.clone(),
            side: input.side,
            proof_class: input.proof_class,
            status: SwapStatus::Open,
            encrypted_proof_hint_root: input.encrypted_proof_hint_root,
            proof_request_commitment: input.proof_request_commitment,
            state_root_before: input.state_root_before,
            expected_state_root_after: input.expected_state_root_after,
            proof_output_root: input.proof_output_root,
            privacy_fence_root: input.privacy_fence_root,
            requested_parallel_segments: input.requested_parallel_segments,
            attested_parallel_segments: 0,
            notional_fee_micros: input.notional_fee_micros,
            max_priority_fee_micros: input.max_priority_fee_micros,
            target_latency_ms: input.target_latency_ms,
            deadline_slot: input.deadline_slot,
            created_at_slot: input.created_at_slot,
            expires_at_slot: input
                .created_at_slot
                .saturating_add(self.config.swap_ttl_slots),
            matched_curve_id: None,
            delivery_qos_id: None,
            settlement_id: None,
            sequence: self.counters.swaps_opened.saturating_add(1),
            root: String::new(),
        };
        swap.root = payload_root(D_SWAPS, &record_without_root(&swap));
        self.counters.swaps_opened = swap.sequence;
        self.counters.parallel_segments_requested = self
            .counters
            .parallel_segments_requested
            .saturating_add(input.requested_parallel_segments as u64);
        self.swaps.insert(input.swap_id.clone(), swap);
        self.refresh_roots();
        Ok(input.swap_id)
    }

    pub fn post_curve(&mut self, input: PostCurveInput) -> Result<String> {
        ensure_nonempty("curve_id", &input.curve_id)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_root("sealed_curve_root", &input.sealed_curve_root)?;
        ensure_root("maker_commitment", &input.maker_commitment)?;
        ensure_bps("min_delivery_qos_bps", input.min_delivery_qos_bps)?;
        ensure_capacity("curves", self.curves.len(), self.config.max_curves)?;
        ensure_absent("curve", &self.curves, &input.curve_id)?;
        if input.valid_until_slot < input.valid_from_slot {
            return Err("curve valid_until_slot precedes valid_from_slot".to_string());
        }
        if input.capacity_units == 0 || input.max_parallel_segments == 0 {
            return Err("curve capacity and max_parallel_segments must be positive".to_string());
        }
        if input.priority_fee_cap_micros > self.config.priority_fee_cap_micros {
            return Err("curve priority fee cap exceeds configured cap".to_string());
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_swaps() {
            return Err("lane does not accept preconfirmation curves".to_string());
        }
        let mut curve = PreconfirmationLatencySwapCurve {
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
            max_parallel_segments: input.max_parallel_segments,
            capacity_units: input.capacity_units,
            filled_units: 0,
            valid_from_slot: input.valid_from_slot,
            valid_until_slot: input.valid_until_slot,
            active: true,
            sequence: self.counters.curves_posted.saturating_add(1),
            root: String::new(),
        };
        curve.root = payload_root(D_CURVES, &record_without_root(&curve));
        self.counters.curves_posted = curve.sequence;
        self.curves.insert(input.curve_id.clone(), curve);
        self.refresh_roots();
        Ok(input.curve_id)
    }

    pub fn match_curve(&mut self, swap_id: &str, curve_id: &str, slot: u64) -> Result<()> {
        let swap = self
            .swaps
            .get(swap_id)
            .ok_or_else(|| format!("unknown swap `{swap_id}`"))?
            .clone();
        let curve = self
            .curves
            .get(curve_id)
            .ok_or_else(|| format!("unknown curve `{curve_id}`"))?
            .clone();
        if !curve.accepts(&swap, slot) {
            return Err("curve does not accept swap at requested slot".to_string());
        }
        if let Some(swap) = self.swaps.get_mut(swap_id) {
            swap.status = SwapStatus::CurveMatched;
            swap.matched_curve_id = Some(curve_id.to_string());
            swap.sequence = swap.sequence.saturating_add(1);
            swap.root = payload_root(D_SWAPS, &record_without_root(swap));
        }
        if let Some(curve) = self.curves.get_mut(curve_id) {
            curve.filled_units = curve.filled_units.saturating_add(1);
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
        ensure_nonempty("swap_id", &input.swap_id)?;
        ensure_root("attestor_commitment", &input.attestor_commitment)?;
        ensure_root("pq_signature_root", &input.pq_signature_root)?;
        ensure_root("transcript_root", &input.transcript_root)?;
        ensure_root("proof_segment_root", &input.proof_segment_root)?;
        ensure_root("state_root_claim", &input.state_root_claim)?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_absent("attestation", &self.attestations, &input.attestation_id)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq_security_bits below configured minimum".to_string());
        }
        if input.segment_count == 0 || input.segment_index >= input.segment_count {
            return Err("invalid proof segment index/count".to_string());
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_attestations() {
            return Err("lane does not accept PQ attestations".to_string());
        }
        let swap = self
            .swaps
            .get(&input.swap_id)
            .ok_or_else(|| format!("unknown swap `{}`", input.swap_id))?;
        if swap.lane_id != input.lane_id {
            return Err("attestation lane does not match swap lane".to_string());
        }
        if input.segment_count != swap.requested_parallel_segments {
            return Err("attestation segment_count does not match swap request".to_string());
        }
        let mut attestation = PqLaneAttestation {
            attestation_id: input.attestation_id.clone(),
            lane_id: input.lane_id.clone(),
            swap_id: input.swap_id.clone(),
            attestor_commitment: input.attestor_commitment,
            pq_signature_root: input.pq_signature_root,
            transcript_root: input.transcript_root,
            proof_segment_root: input.proof_segment_root,
            state_root_claim: input.state_root_claim,
            quorum_weight_bps: input.quorum_weight_bps,
            pq_security_bits: input.pq_security_bits,
            segment_index: input.segment_index,
            segment_count: input.segment_count,
            verdict: input.verdict,
            attested_latency_ms: input.attested_latency_ms,
            created_at_slot: input.created_at_slot,
            expires_at_slot: input
                .created_at_slot
                .saturating_add(self.config.attestation_ttl_slots),
            sequence: self.counters.pq_attestations.saturating_add(1),
            root: String::new(),
        };
        attestation.root = payload_root(D_ATTESTATIONS, &record_without_root(&attestation));
        self.attestations
            .insert(input.attestation_id.clone(), attestation);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        if matches!(input.verdict, AttestationVerdict::Slash) {
            self.mark_swap_slashed(&input.swap_id)?;
        } else if matches!(input.verdict, AttestationVerdict::Include) {
            self.counters.parallel_segments_attested =
                self.counters.parallel_segments_attested.saturating_add(1);
            if let Some(swap) = self.swaps.get_mut(&input.swap_id) {
                swap.attested_parallel_segments = swap.attested_parallel_segments.saturating_add(1);
                swap.status = if swap.attested_parallel_segments >= swap.requested_parallel_segments
                {
                    SwapStatus::Attested
                } else {
                    SwapStatus::Parallelizing
                };
                swap.sequence = swap.sequence.saturating_add(1);
                swap.root = payload_root(D_SWAPS, &record_without_root(swap));
            }
        }
        if let Some(lane) = self.lanes.get_mut(&input.lane_id) {
            lane.last_attested_height = input.created_at_slot;
            lane.sequence = lane.sequence.saturating_add(1);
            lane.root = payload_root(D_LANES, &record_without_root(lane));
        }
        self.refresh_roots();
        Ok(input.attestation_id)
    }

    pub fn score_delivery_qos(&mut self, input: ScoreDeliveryInput) -> Result<String> {
        ensure_nonempty("qos_id", &input.qos_id)?;
        ensure_nonempty("lane_id", &input.lane_id)?;
        ensure_nonempty("swap_id", &input.swap_id)?;
        ensure_root("proof_output_root", &input.proof_output_root)?;
        ensure_root("delivery_commitment", &input.delivery_commitment)?;
        ensure_bps("availability_bps", input.availability_bps)?;
        ensure_bps("correctness_bps", input.correctness_bps)?;
        ensure_bps("privacy_bps", input.privacy_bps)?;
        ensure_bps("fee_efficiency_bps", input.fee_efficiency_bps)?;
        ensure_capacity(
            "delivery_qos",
            self.delivery_qos.len(),
            self.config.max_delivery_qos,
        )?;
        ensure_absent("delivery_qos", &self.delivery_qos, &input.qos_id)?;
        let swap = self
            .swaps
            .get(&input.swap_id)
            .ok_or_else(|| format!("unknown swap `{}`", input.swap_id))?
            .clone();
        if swap.lane_id != input.lane_id {
            return Err("delivery QoS lane does not match swap lane".to_string());
        }
        let parallelism_bps = ratio_bps(
            swap.attested_parallel_segments as u64,
            swap.requested_parallel_segments as u64,
        );
        let latency_bps = latency_score_bps(input.observed_latency_ms, swap.target_latency_ms);
        let aggregate_qos_bps = weighted_average_bps(&[
            (latency_bps, 32),
            (input.availability_bps, 18),
            (input.correctness_bps, 22),
            (input.privacy_bps, 12),
            (parallelism_bps, 10),
            (input.fee_efficiency_bps, 6),
        ]);
        let grade = QosGrade::from_score(&self.config, aggregate_qos_bps);
        let mut qos = ProofDeliveryQosScore {
            qos_id: input.qos_id.clone(),
            lane_id: input.lane_id.clone(),
            swap_id: input.swap_id.clone(),
            proof_output_root: input.proof_output_root,
            delivery_commitment: input.delivery_commitment,
            observed_latency_ms: input.observed_latency_ms,
            target_latency_ms: swap.target_latency_ms,
            availability_bps: input.availability_bps,
            correctness_bps: input.correctness_bps,
            privacy_bps: input.privacy_bps,
            parallelism_bps,
            fee_efficiency_bps: input.fee_efficiency_bps,
            aggregate_qos_bps,
            grade,
            scored_at_slot: input.scored_at_slot,
            sequence: self.counters.delivery_qos_scores.saturating_add(1),
            root: String::new(),
        };
        qos.root = payload_root(D_QOS, &record_without_root(&qos));
        self.delivery_qos.insert(input.qos_id.clone(), qos);
        self.counters.delivery_qos_scores = self.counters.delivery_qos_scores.saturating_add(1);
        if let Some(swap) = self.swaps.get_mut(&input.swap_id) {
            swap.delivery_qos_id = Some(input.qos_id.clone());
            swap.status = if aggregate_qos_bps >= self.config.min_delivery_qos_bps {
                SwapStatus::Delivered
            } else {
                SwapStatus::Late
            };
            swap.sequence = swap.sequence.saturating_add(1);
            swap.root = payload_root(D_SWAPS, &record_without_root(swap));
        }
        self.refresh_lane_scores(&input.lane_id)?;
        self.refresh_roots();
        Ok(input.qos_id)
    }

    pub fn settle_swap(&mut self, input: SettleSwapInput) -> Result<String> {
        ensure_nonempty("settlement_id", &input.settlement_id)?;
        ensure_nonempty("swap_id", &input.swap_id)?;
        ensure_nonempty("curve_id", &input.curve_id)?;
        ensure_root("settlement_root", &input.settlement_root)?;
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        ensure_absent("settlement", &self.settlements, &input.settlement_id)?;
        if input.priority_fee_micros > self.config.priority_fee_cap_micros {
            return Err("settlement priority fee exceeds configured cap".to_string());
        }
        let swap = self
            .swaps
            .get(&input.swap_id)
            .ok_or_else(|| format!("unknown swap `{}`", input.swap_id))?
            .clone();
        let curve = self
            .curves
            .get(&input.curve_id)
            .ok_or_else(|| format!("unknown curve `{}`", input.curve_id))?
            .clone();
        if swap.matched_curve_id.as_deref() != Some(input.curve_id.as_str()) {
            return Err("swap is not matched to settlement curve".to_string());
        }
        if input.settled_at_slot
            < swap
                .created_at_slot
                .saturating_add(self.config.settlement_delay_slots)
        {
            return Err("settlement before configured delay".to_string());
        }
        let qos_id = swap
            .delivery_qos_id
            .as_ref()
            .ok_or_else(|| "swap has no proof delivery QoS score".to_string())?;
        let qos = self
            .delivery_qos
            .get(qos_id)
            .ok_or_else(|| format!("unknown delivery QoS `{qos_id}`"))?;
        let lane = self
            .lanes
            .get(&swap.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", swap.lane_id))?;
        let pricing =
            self.compute_settlement_pricing(&swap, &curve, qos, lane, input.priority_fee_micros);
        let status = if qos.aggregate_qos_bps >= curve.min_delivery_qos_bps {
            SettlementStatus::Settled
        } else if matches!(swap.status, SwapStatus::Late) {
            SettlementStatus::Repriced
        } else {
            SettlementStatus::Rejected
        };
        let mut settlement = FeeAwareSettlement {
            settlement_id: input.settlement_id.clone(),
            swap_id: input.swap_id.clone(),
            curve_id: input.curve_id,
            lane_id: swap.lane_id.clone(),
            settlement_status: status,
            fee_asset_id: self.config.fee_asset_id.clone(),
            gross_fee_micros: pricing.gross_fee_micros,
            priority_fee_micros: input.priority_fee_micros,
            maker_rebate_micros: pricing.maker_rebate_micros,
            taker_fee_micros: pricing.taker_fee_micros,
            privacy_rebate_micros: pricing.privacy_rebate_micros,
            parallelism_rebate_micros: pricing.parallelism_rebate_micros,
            late_penalty_micros: pricing.late_penalty_micros,
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
        if let Some(swap) = self.swaps.get_mut(&input.swap_id) {
            swap.status = if matches!(status, SettlementStatus::Rejected) {
                SwapStatus::Late
            } else {
                SwapStatus::Settled
            };
            swap.settlement_id = Some(input.settlement_id.clone());
            swap.sequence = swap.sequence.saturating_add(1);
            swap.root = payload_root(D_SWAPS, &record_without_root(swap));
        }
        self.settlements
            .insert(input.settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(input.settlement_id)
    }

    pub fn expire_swaps(&mut self, slot: u64) -> Vec<String> {
        let mut expired = Vec::new();
        for (swap_id, swap) in self.swaps.iter_mut() {
            if swap.is_expired(slot) {
                swap.status = SwapStatus::Expired;
                swap.sequence = swap.sequence.saturating_add(1);
                swap.root = payload_root(D_SWAPS, &record_without_root(swap));
                expired.push(swap_id.clone());
            }
        }
        if !expired.is_empty() {
            self.counters.expired_swaps = self
                .counters
                .expired_swaps
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
                "swaps_root": self.roots.swaps_root,
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
            swaps_root: self.roots.swaps_root.clone(),
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
        self.roots.swaps_root = merkle_records(D_SWAPS, &self.public_swap_records());
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
                "swaps_root": self.roots.swaps_root,
                "curves_root": self.roots.curves_root,
                "attestations_root": self.roots.attestations_root,
                "delivery_qos_root": self.roots.delivery_qos_root,
                "settlements_root": self.roots.settlements_root,
                "nullifier_root": self.roots.nullifier_root,
                "public_records_root": self.roots.public_records_root,
            }),
        );
    }

    fn mark_swap_slashed(&mut self, swap_id: &str) -> Result<()> {
        let swap = self
            .swaps
            .get_mut(swap_id)
            .ok_or_else(|| format!("unknown swap `{swap_id}`"))?;
        swap.status = SwapStatus::Slashed;
        swap.sequence = swap.sequence.saturating_add(1);
        swap.root = payload_root(D_SWAPS, &record_without_root(swap));
        self.counters.slashed_swaps = self.counters.slashed_swaps.saturating_add(1);
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
            let fill_total = qos_entries
                .iter()
                .fold(0_u64, |acc, qos| acc.saturating_add(qos.parallelism_bps));
            lane.rolling_qos_bps = qos_total / qos_entries.len() as u64;
            lane.rolling_fill_bps = fill_total / qos_entries.len() as u64;
        }
        lane.status = if lane.rolling_qos_bps < self.config.min_delivery_qos_bps {
            LaneStatus::Congested
        } else if lane.rolling_fill_bps >= self.config.target_parallel_fill_bps {
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
        swap: &ParallelProofLatencySwap,
        curve: &PreconfirmationLatencySwapCurve,
        qos: &ProofDeliveryQosScore,
        lane: &ConfidentialProofLane,
        priority_fee_micros: u64,
    ) -> SettlementPricing {
        let complexity_fee = swap
            .notional_fee_micros
            .saturating_mul(swap.proof_class.complexity_weight())
            .saturating_div(1_000);
        let lane_fee = complexity_fee
            .saturating_mul(lane.lane_class.priority_weight())
            .saturating_div(MAX_BPS);
        let parallel_fee = lane_fee
            .saturating_mul(swap.requested_parallel_segments as u64)
            .saturating_div(curve.max_parallel_segments.max(1) as u64);
        let gross_fee_micros = curve
            .base_fee_micros
            .saturating_add(lane_fee)
            .saturating_add(parallel_fee)
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
        let parallelism_rebate_micros = gross_fee_micros
            .saturating_mul(qos.parallelism_bps)
            .saturating_div(MAX_BPS)
            .saturating_div(20);
        let late_penalty_micros = if qos.aggregate_qos_bps < self.config.min_delivery_qos_bps {
            gross_fee_micros
                .saturating_mul(self.config.late_proof_penalty_bps)
                .saturating_div(MAX_BPS)
        } else {
            0
        };
        let congestion_penalty = gross_fee_micros
            .saturating_mul(lane.congestion_bps.min(self.config.congestion_penalty_bps))
            .saturating_div(MAX_BPS);
        let net_settlement_micros = gross_fee_micros
            .saturating_add(taker_fee_micros)
            .saturating_add(late_penalty_micros)
            .saturating_add(congestion_penalty)
            .saturating_sub(maker_rebate_micros)
            .saturating_sub(privacy_rebate_micros)
            .saturating_sub(parallelism_rebate_micros);
        SettlementPricing {
            gross_fee_micros,
            maker_rebate_micros,
            taker_fee_micros,
            privacy_rebate_micros,
            parallelism_rebate_micros,
            late_penalty_micros,
            net_settlement_micros,
        }
    }

    fn public_lane_records(&self) -> BTreeMap<String, Value> {
        self.lanes
            .iter()
            .map(|(key, lane)| (key.clone(), lane.public_record()))
            .collect()
    }

    fn public_swap_records(&self) -> BTreeMap<String, Value> {
        self.swaps
            .iter()
            .map(|(key, swap)| (key.clone(), swap.public_record()))
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
    parallelism_rebate_micros: u64,
    late_penalty_micros: u64,
    net_settlement_micros: u64,
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let lane_id = "devnet-parallel-proof-latency-swap-lane-0".to_string();
    state
        .register_lane(RegisterLaneInput {
            lane_id: lane_id.clone(),
            operator_commitment: dev_hash("operator", 0),
            lane_class: LaneClass::ProofCarry,
            pq_attestation_key_root: dev_hash("pq-key-root", 0),
            proof_capacity_commitment: dev_hash("proof-capacity", 0),
            fee_escrow_commitment: dev_hash("fee-escrow", 0),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            congestion_bps: 220,
            max_parallel_segments: 8,
            created_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet lane must register");
    state
        .set_lane_status(&lane_id, LaneStatus::Hot)
        .expect("devnet lane status must update");
    state
        .post_curve(PostCurveInput {
            curve_id: "devnet-preconfirmation-proof-swap-curve-0".to_string(),
            lane_id,
            curve_kind: CurveKind::ParallelPremium,
            sealed_curve_root: dev_hash("sealed-curve", 0),
            maker_commitment: dev_hash("maker", 0),
            target_latency_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            max_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            base_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            min_delivery_qos_bps: DEFAULT_MIN_DELIVERY_QOS_BPS,
            max_parallel_segments: 8,
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
        .map(|(key, record)| (key.clone(), record_with_kind("public_record", record)))
        .collect()
}

fn empty_root(label: &str) -> String {
    payload_root(
        "EMPTY-PARALLEL-PROOF-LATENCY-SWAP-ROOT",
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
