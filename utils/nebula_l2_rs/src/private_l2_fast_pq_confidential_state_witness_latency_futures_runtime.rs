use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialStateWitnessLatencyFuturesRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_LATENCY_FUTURES_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-state-witness-latency-futures-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_LATENCY_FUTURES_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const LATENCY_FUTURES_SUITE: &str =
    "private-l2-fast-pq-confidential-state-witness-latency-futures-v1";
pub const PRECONFIRMATION_CURVE_SUITE: &str =
    "ml-kem-1024-sealed-preconfirmation-latency-futures-curve-v1";
pub const PQ_LANE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-state-witness-latency-lane-attestation-v1";
pub const RECEIPT_DELTA_DELIVERY_SCORE_SUITE: &str =
    "private-l2-fast-confidential-receipt-delta-delivery-score-v1";
pub const FEE_AWARE_SETTLEMENT_SUITE: &str =
    "private-l2-fast-confidential-state-witness-latency-fee-aware-settlement-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "privacy-preserving-public-state-witness-latency-futures-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_state_witnesses_addresses_view_keys_payloads_or_bid_amounts";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_EPOCH: u64 = 32_768;
pub const DEVNET_HEIGHT: u64 = 6_880_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 95;
pub const DEFAULT_SOFT_LATENCY_MS: u64 = 160;
pub const DEFAULT_HARD_LATENCY_MS: u64 = 420;
pub const DEFAULT_FUTURE_TTL_SLOTS: u64 = 96;
pub const DEFAULT_CURVE_TTL_SLOTS: u64 = 32;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 128;
pub const DEFAULT_SCORE_WINDOW_SLOTS: u64 = 64;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 3;
pub const DEFAULT_MAX_LANES: usize = 65_536;
pub const DEFAULT_MAX_FUTURES: usize = 1_048_576;
pub const DEFAULT_MAX_CURVES: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_DELIVERY_SCORES: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 524_288;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 262_144;
pub const DEFAULT_MIN_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MIN_DELIVERY_SCORE_BPS: u64 = 8_400;
pub const DEFAULT_TARGET_HEDGE_FILL_BPS: u64 = 8_700;
pub const DEFAULT_LOW_FEE_BONUS_BPS: u64 = 650;
pub const DEFAULT_PRIVACY_BONUS_BPS: u64 = 400;
pub const DEFAULT_CONGESTION_PENALTY_BPS: u64 = 1_050;
pub const DEFAULT_LATE_DELIVERY_PENALTY_BPS: u64 = 1_600;
pub const DEFAULT_PRIORITY_FEE_CAP_MICROS: u64 = 90;
pub const DEFAULT_BASE_SETTLEMENT_FEE_MICROS: u64 = 4;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 120;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 240;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:LANES";
const D_FUTURES: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:FUTURES";
const D_CURVES: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:CURVES";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:ATTESTATIONS";
const D_SCORES: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:SCORES";
const D_SETTLEMENTS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:SETTLEMENTS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:PUBLIC";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-LATENCY-FUTURES:DEVNET";

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
    StateOracle,
    EmergencyCancel,
}

impl LaneClass {
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 10_900,
            Self::BridgeExit => 10_250,
            Self::MerchantPos => 9_850,
            Self::DefiIntent => 9_600,
            Self::ContractCall => 9_250,
            Self::WalletFast => 9_000,
            Self::StateOracle => 8_700,
            Self::ProofCarry => 8_350,
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
    pub fn accepts_futures(self) -> bool {
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
pub enum WitnessScope {
    AccountReadSet,
    ContractStorage,
    NullifierSet,
    ReceiptDelta,
    InclusionPath,
    BridgeOutput,
    StateRootDelta,
    RepairShard,
}

impl WitnessScope {
    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::BridgeOutput => 1_120,
            Self::ContractStorage => 1_060,
            Self::StateRootDelta => 1_020,
            Self::ReceiptDelta => 960,
            Self::RepairShard => 880,
            Self::NullifierSet => 840,
            Self::AccountReadSet => 780,
            Self::InclusionPath => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureSide {
    HedgeLatency,
    SellCapacity,
    SponsorUser,
    InsuranceBackstop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureStatus {
    Open,
    CurveMatched,
    Attested,
    Delivered,
    Settled,
    Late,
    Expired,
    Cancelled,
    Slashed,
}

impl FutureStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::CurveMatched | Self::Attested | Self::Delivered
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
    pub chain_id: String,
    pub runtime_mode: RuntimeMode,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub slot_width_ms: u64,
    pub target_preconfirmation_ms: u64,
    pub soft_latency_ms: u64,
    pub hard_latency_ms: u64,
    pub future_ttl_slots: u64,
    pub curve_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub score_window_slots: u64,
    pub settlement_delay_slots: u64,
    pub max_lanes: usize,
    pub max_futures: usize,
    pub max_curves: usize,
    pub max_attestations: usize,
    pub max_delivery_scores: usize,
    pub max_settlements: usize,
    pub max_public_records: usize,
    pub min_quorum_weight_bps: u64,
    pub strong_quorum_weight_bps: u64,
    pub min_delivery_score_bps: u64,
    pub target_hedge_fill_bps: u64,
    pub low_fee_bonus_bps: u64,
    pub privacy_bonus_bps: u64,
    pub congestion_penalty_bps: u64,
    pub late_delivery_penalty_bps: u64,
    pub priority_fee_cap_micros: u64,
    pub base_settlement_fee_micros: u64,
    pub maker_rebate_bps: u64,
    pub taker_fee_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            runtime_mode: RuntimeMode::Devnet,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            soft_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            hard_latency_ms: DEFAULT_HARD_LATENCY_MS,
            future_ttl_slots: DEFAULT_FUTURE_TTL_SLOTS,
            curve_ttl_slots: DEFAULT_CURVE_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            score_window_slots: DEFAULT_SCORE_WINDOW_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            max_lanes: DEFAULT_MAX_LANES,
            max_futures: DEFAULT_MAX_FUTURES,
            max_curves: DEFAULT_MAX_CURVES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_delivery_scores: DEFAULT_MAX_DELIVERY_SCORES,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            min_quorum_weight_bps: DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            min_delivery_score_bps: DEFAULT_MIN_DELIVERY_SCORE_BPS,
            target_hedge_fill_bps: DEFAULT_TARGET_HEDGE_FILL_BPS,
            low_fee_bonus_bps: DEFAULT_LOW_FEE_BONUS_BPS,
            privacy_bonus_bps: DEFAULT_PRIVACY_BONUS_BPS,
            congestion_penalty_bps: DEFAULT_CONGESTION_PENALTY_BPS,
            late_delivery_penalty_bps: DEFAULT_LATE_DELIVERY_PENALTY_BPS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            base_settlement_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub futures_opened: u64,
    pub curves_posted: u64,
    pub curves_matched: u64,
    pub pq_attestations: u64,
    pub delivery_scores: u64,
    pub settlements: u64,
    pub late_settlements: u64,
    pub slashed_futures: u64,
    pub expired_futures: u64,
    pub total_fee_micros: u64,
    pub maker_rebates_micros: u64,
    pub taker_fees_micros: u64,
    pub public_records: u64,
    pub state_root_updates: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub lanes_root: String,
    pub futures_root: String,
    pub curves_root: String,
    pub attestations_root: String,
    pub delivery_scores_root: String,
    pub settlements_root: String,
    pub public_records_root: String,
    pub counters_root: String,
    pub config_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            lanes_root: empty_root(D_LANES),
            futures_root: empty_root(D_FUTURES),
            curves_root: empty_root(D_CURVES),
            attestations_root: empty_root(D_ATTESTATIONS),
            delivery_scores_root: empty_root(D_SCORES),
            settlements_root: empty_root(D_SETTLEMENTS),
            public_records_root: empty_root(D_PUBLIC),
            counters_root: empty_root(D_COUNTERS),
            config_root: empty_root(D_CONFIG),
            state_root: empty_root(D_STATE),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Lane {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_class: LaneClass,
    pub status: LaneStatus,
    pub pq_attestation_key_root: String,
    pub capacity_commitment: String,
    pub fee_escrow_commitment: String,
    pub privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub congestion_bps: u64,
    pub created_at_height: u64,
    pub last_attested_height: u64,
    pub sequence: u64,
}

impl Lane {
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
    pub capacity_commitment: String,
    pub fee_escrow_commitment: String,
    pub privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub congestion_bps: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StateWitnessLatencyFuture {
    pub future_id: String,
    pub lane_id: String,
    pub side: FutureSide,
    pub witness_scope: WitnessScope,
    pub status: FutureStatus,
    pub encrypted_witness_hint_root: String,
    pub state_access_commitment: String,
    pub state_root_before: String,
    pub expected_state_root_after: String,
    pub receipt_delta_root: String,
    pub privacy_fence_root: String,
    pub notional_fee_micros: u64,
    pub max_priority_fee_micros: u64,
    pub target_latency_ms: u64,
    pub deadline_slot: u64,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub matched_curve_id: Option<String>,
    pub delivery_score_id: Option<String>,
    pub settlement_id: Option<String>,
    pub sequence: u64,
}

impl StateWitnessLatencyFuture {
    pub fn is_expired(&self, slot: u64) -> bool {
        self.status.live() && slot > self.expires_at_slot
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenFutureInput {
    pub future_id: String,
    pub lane_id: String,
    pub side: FutureSide,
    pub witness_scope: WitnessScope,
    pub encrypted_witness_hint_root: String,
    pub state_access_commitment: String,
    pub state_root_before: String,
    pub expected_state_root_after: String,
    pub receipt_delta_root: String,
    pub privacy_fence_root: String,
    pub notional_fee_micros: u64,
    pub max_priority_fee_micros: u64,
    pub target_latency_ms: u64,
    pub deadline_slot: u64,
    pub created_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PreconfirmationLatencyCurve {
    pub curve_id: String,
    pub lane_id: String,
    pub curve_kind: CurveKind,
    pub sealed_curve_root: String,
    pub maker_commitment: String,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub base_fee_micros: u64,
    pub priority_fee_cap_micros: u64,
    pub min_delivery_score_bps: u64,
    pub capacity_units: u64,
    pub filled_units: u64,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
    pub status: FutureStatus,
    pub sequence: u64,
}

impl PreconfirmationLatencyCurve {
    pub fn accepts(&self, future: &StateWitnessLatencyFuture, slot: u64) -> bool {
        self.status.live()
            && self.lane_id == future.lane_id
            && slot >= self.valid_from_slot
            && slot <= self.valid_until_slot
            && self.filled_units < self.capacity_units
            && self.target_latency_ms <= future.target_latency_ms
            && self.priority_fee_cap_micros <= future.max_priority_fee_micros
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
    pub min_delivery_score_bps: u64,
    pub capacity_units: u64,
    pub valid_from_slot: u64,
    pub valid_until_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub future_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub witness_availability_root: String,
    pub state_root_claim: String,
    pub receipt_delta_root: String,
    pub quorum_weight_bps: u64,
    pub verdict: AttestationVerdict,
    pub attested_latency_ms: u64,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubmitAttestationInput {
    pub attestation_id: String,
    pub lane_id: String,
    pub future_id: String,
    pub attestor_commitment: String,
    pub pq_signature_root: String,
    pub witness_availability_root: String,
    pub state_root_claim: String,
    pub receipt_delta_root: String,
    pub quorum_weight_bps: u64,
    pub verdict: AttestationVerdict,
    pub attested_latency_ms: u64,
    pub created_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReceiptDeltaDeliveryScore {
    pub score_id: String,
    pub lane_id: String,
    pub future_id: String,
    pub receipt_delta_root: String,
    pub delivery_commitment: String,
    pub observed_latency_ms: u64,
    pub target_latency_ms: u64,
    pub availability_bps: u64,
    pub correctness_bps: u64,
    pub privacy_bps: u64,
    pub fee_efficiency_bps: u64,
    pub aggregate_score_bps: u64,
    pub scored_at_slot: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ScoreDeliveryInput {
    pub score_id: String,
    pub lane_id: String,
    pub future_id: String,
    pub receipt_delta_root: String,
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
    pub future_id: String,
    pub curve_id: String,
    pub lane_id: String,
    pub settlement_status: SettlementStatus,
    pub fee_asset_id: String,
    pub gross_fee_micros: u64,
    pub priority_fee_micros: u64,
    pub maker_rebate_micros: u64,
    pub taker_fee_micros: u64,
    pub privacy_rebate_micros: u64,
    pub late_penalty_micros: u64,
    pub net_settlement_micros: u64,
    pub delivery_score_bps: u64,
    pub settlement_root: String,
    pub settled_at_slot: u64,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettleFutureInput {
    pub settlement_id: String,
    pub future_id: String,
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
    pub futures_root: String,
    pub curves_root: String,
    pub attestations_root: String,
    pub delivery_scores_root: String,
    pub settlements_root: String,
    pub counters_root: String,
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
    pub lanes: BTreeMap<String, Lane>,
    pub futures: BTreeMap<String, StateWitnessLatencyFuture>,
    pub curves: BTreeMap<String, PreconfirmationLatencyCurve>,
    pub attestations: BTreeMap<String, PqLaneAttestation>,
    pub delivery_scores: BTreeMap<String, ReceiptDeltaDeliveryScore>,
    pub settlements: BTreeMap<String, FeeAwareSettlement>,
    pub public_records: BTreeMap<String, PublicRecord>,
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
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            futures: BTreeMap::new(),
            curves: BTreeMap::new(),
            attestations: BTreeMap::new(),
            delivery_scores: BTreeMap::new(),
            settlements: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_lane(&mut self, input: RegisterLaneInput) -> Result<String> {
        ensure_non_empty("lane_id", &input.lane_id)?;
        ensure_non_empty("operator_commitment", &input.operator_commitment)?;
        ensure_non_empty("pq_attestation_key_root", &input.pq_attestation_key_root)?;
        ensure_non_empty("capacity_commitment", &input.capacity_commitment)?;
        ensure_non_empty("fee_escrow_commitment", &input.fee_escrow_commitment)?;
        ensure_unique(&self.lanes, "lane", &input.lane_id)?;
        ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;
        ensure_bps("congestion_bps", input.congestion_bps)?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("lane privacy set below configured minimum".to_string());
        }
        if input.quorum_weight_bps < self.config.min_quorum_weight_bps {
            return Err("lane quorum weight below configured minimum".to_string());
        }

        let lane = Lane {
            lane_id: input.lane_id.clone(),
            operator_commitment: input.operator_commitment,
            lane_class: input.lane_class,
            status: LaneStatus::Registered,
            pq_attestation_key_root: input.pq_attestation_key_root,
            capacity_commitment: input.capacity_commitment,
            fee_escrow_commitment: input.fee_escrow_commitment,
            privacy_set_size: input.privacy_set_size,
            quorum_weight_bps: input.quorum_weight_bps,
            congestion_bps: input.congestion_bps,
            created_at_height: input.created_at_height,
            last_attested_height: input.created_at_height,
            sequence: self.counters.lanes_registered.saturating_add(1),
        };

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
        self.refresh_roots();
        Ok(())
    }

    pub fn open_future(&mut self, input: OpenFutureInput) -> Result<String> {
        ensure_non_empty("future_id", &input.future_id)?;
        ensure_non_empty("lane_id", &input.lane_id)?;
        ensure_non_empty(
            "encrypted_witness_hint_root",
            &input.encrypted_witness_hint_root,
        )?;
        ensure_non_empty("state_access_commitment", &input.state_access_commitment)?;
        ensure_non_empty("state_root_before", &input.state_root_before)?;
        ensure_non_empty(
            "expected_state_root_after",
            &input.expected_state_root_after,
        )?;
        ensure_non_empty("receipt_delta_root", &input.receipt_delta_root)?;
        ensure_non_empty("privacy_fence_root", &input.privacy_fence_root)?;
        ensure_unique(&self.futures, "future", &input.future_id)?;
        ensure_capacity(self.futures.len(), self.config.max_futures, "futures")?;
        if input.max_priority_fee_micros > self.config.priority_fee_cap_micros {
            return Err("future priority fee exceeds configured cap".to_string());
        }
        if input.deadline_slot <= input.created_at_slot {
            return Err("future deadline must be after creation slot".to_string());
        }

        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_futures() {
            return Err("lane does not accept latency futures".to_string());
        }

        let expires_at_slot = input
            .created_at_slot
            .saturating_add(self.config.future_ttl_slots);
        let future = StateWitnessLatencyFuture {
            future_id: input.future_id.clone(),
            lane_id: input.lane_id.clone(),
            side: input.side,
            witness_scope: input.witness_scope,
            status: FutureStatus::Open,
            encrypted_witness_hint_root: input.encrypted_witness_hint_root,
            state_access_commitment: input.state_access_commitment,
            state_root_before: input.state_root_before,
            expected_state_root_after: input.expected_state_root_after,
            receipt_delta_root: input.receipt_delta_root,
            privacy_fence_root: input.privacy_fence_root,
            notional_fee_micros: input.notional_fee_micros,
            max_priority_fee_micros: input.max_priority_fee_micros,
            target_latency_ms: input
                .target_latency_ms
                .max(self.config.target_preconfirmation_ms),
            deadline_slot: input.deadline_slot,
            created_at_slot: input.created_at_slot,
            expires_at_slot,
            matched_curve_id: None,
            delivery_score_id: None,
            settlement_id: None,
            sequence: self.counters.futures_opened.saturating_add(1),
        };

        self.counters.futures_opened = self.counters.futures_opened.saturating_add(1);
        self.futures.insert(input.future_id.clone(), future);
        self.refresh_roots();
        Ok(input.future_id)
    }

    pub fn post_curve(&mut self, input: PostCurveInput) -> Result<String> {
        ensure_non_empty("curve_id", &input.curve_id)?;
        ensure_non_empty("lane_id", &input.lane_id)?;
        ensure_non_empty("sealed_curve_root", &input.sealed_curve_root)?;
        ensure_non_empty("maker_commitment", &input.maker_commitment)?;
        ensure_unique(&self.curves, "curve", &input.curve_id)?;
        ensure_capacity(self.curves.len(), self.config.max_curves, "curves")?;
        ensure_bps("min_delivery_score_bps", input.min_delivery_score_bps)?;
        if input.valid_until_slot <= input.valid_from_slot {
            return Err("curve valid_until_slot must be after valid_from_slot".to_string());
        }
        if input.valid_until_slot.saturating_sub(input.valid_from_slot)
            > self.config.curve_ttl_slots
        {
            return Err("curve validity exceeds configured ttl".to_string());
        }
        if input.capacity_units == 0 {
            return Err("curve capacity_units must be non-zero".to_string());
        }
        if input.priority_fee_cap_micros > self.config.priority_fee_cap_micros {
            return Err("curve priority fee cap exceeds configured cap".to_string());
        }

        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_futures() {
            return Err("lane does not accept latency curves".to_string());
        }

        let curve = PreconfirmationLatencyCurve {
            curve_id: input.curve_id.clone(),
            lane_id: input.lane_id,
            curve_kind: input.curve_kind,
            sealed_curve_root: input.sealed_curve_root,
            maker_commitment: input.maker_commitment,
            target_latency_ms: input.target_latency_ms,
            max_latency_ms: input.max_latency_ms,
            base_fee_micros: input.base_fee_micros,
            priority_fee_cap_micros: input.priority_fee_cap_micros,
            min_delivery_score_bps: input.min_delivery_score_bps,
            capacity_units: input.capacity_units,
            filled_units: 0,
            valid_from_slot: input.valid_from_slot,
            valid_until_slot: input.valid_until_slot,
            status: FutureStatus::Open,
            sequence: self.counters.curves_posted.saturating_add(1),
        };

        self.counters.curves_posted = self.counters.curves_posted.saturating_add(1);
        self.curves.insert(input.curve_id.clone(), curve);
        self.refresh_roots();
        Ok(input.curve_id)
    }

    pub fn match_curve(&mut self, future_id: &str, curve_id: &str, slot: u64) -> Result<()> {
        let future = self
            .futures
            .get(future_id)
            .ok_or_else(|| format!("unknown future `{future_id}`"))?
            .clone();
        let curve = self
            .curves
            .get(curve_id)
            .ok_or_else(|| format!("unknown curve `{curve_id}`"))?
            .clone();
        if !future.status.live() || future.status != FutureStatus::Open {
            return Err("future is not open for curve matching".to_string());
        }
        if future.is_expired(slot) {
            return Err("future expired before curve match".to_string());
        }
        if !curve.accepts(&future, slot) {
            return Err("curve does not accept future at this slot".to_string());
        }

        let future_mut = self
            .futures
            .get_mut(future_id)
            .ok_or_else(|| format!("unknown future `{future_id}`"))?;
        future_mut.status = FutureStatus::CurveMatched;
        future_mut.matched_curve_id = Some(curve_id.to_string());
        future_mut.sequence = future_mut.sequence.saturating_add(1);

        let curve_mut = self
            .curves
            .get_mut(curve_id)
            .ok_or_else(|| format!("unknown curve `{curve_id}`"))?;
        curve_mut.filled_units = curve_mut.filled_units.saturating_add(1);
        curve_mut.sequence = curve_mut.sequence.saturating_add(1);
        if curve_mut.filled_units >= curve_mut.capacity_units {
            curve_mut.status = FutureStatus::CurveMatched;
        }

        self.counters.curves_matched = self.counters.curves_matched.saturating_add(1);
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_attestation(&mut self, input: SubmitAttestationInput) -> Result<String> {
        ensure_non_empty("attestation_id", &input.attestation_id)?;
        ensure_non_empty("lane_id", &input.lane_id)?;
        ensure_non_empty("future_id", &input.future_id)?;
        ensure_non_empty("attestor_commitment", &input.attestor_commitment)?;
        ensure_non_empty("pq_signature_root", &input.pq_signature_root)?;
        ensure_non_empty(
            "witness_availability_root",
            &input.witness_availability_root,
        )?;
        ensure_non_empty("state_root_claim", &input.state_root_claim)?;
        ensure_non_empty("receipt_delta_root", &input.receipt_delta_root)?;
        ensure_unique(&self.attestations, "attestation", &input.attestation_id)?;
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;

        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", input.lane_id))?;
        if !lane.status.accepts_attestations() {
            return Err("lane does not accept attestations".to_string());
        }
        let future = self
            .futures
            .get(&input.future_id)
            .ok_or_else(|| format!("unknown future `{}`", input.future_id))?;
        if future.lane_id != input.lane_id {
            return Err("attestation lane does not match future lane".to_string());
        }
        if future.receipt_delta_root != input.receipt_delta_root {
            return Err("attestation receipt delta root mismatch".to_string());
        }
        if input.quorum_weight_bps < self.config.min_quorum_weight_bps {
            return Err("attestation quorum below configured minimum".to_string());
        }

        let attestation = PqLaneAttestation {
            attestation_id: input.attestation_id.clone(),
            lane_id: input.lane_id.clone(),
            future_id: input.future_id.clone(),
            attestor_commitment: input.attestor_commitment,
            pq_signature_root: input.pq_signature_root,
            witness_availability_root: input.witness_availability_root,
            state_root_claim: input.state_root_claim,
            receipt_delta_root: input.receipt_delta_root,
            quorum_weight_bps: input.quorum_weight_bps,
            verdict: input.verdict,
            attested_latency_ms: input.attested_latency_ms,
            created_at_slot: input.created_at_slot,
            expires_at_slot: input
                .created_at_slot
                .saturating_add(self.config.attestation_ttl_slots),
            sequence: self.counters.pq_attestations.saturating_add(1),
        };

        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.attestations
            .insert(input.attestation_id.clone(), attestation);

        if matches!(input.verdict, AttestationVerdict::Include) {
            if let Some(future) = self.futures.get_mut(&input.future_id) {
                future.status = FutureStatus::Attested;
                future.sequence = future.sequence.saturating_add(1);
            }
        } else if matches!(input.verdict, AttestationVerdict::Slash) {
            self.mark_future_slashed(&input.future_id)?;
        }

        self.refresh_roots();
        Ok(input.attestation_id)
    }

    pub fn score_delivery(&mut self, input: ScoreDeliveryInput) -> Result<String> {
        ensure_non_empty("score_id", &input.score_id)?;
        ensure_non_empty("lane_id", &input.lane_id)?;
        ensure_non_empty("future_id", &input.future_id)?;
        ensure_non_empty("receipt_delta_root", &input.receipt_delta_root)?;
        ensure_non_empty("delivery_commitment", &input.delivery_commitment)?;
        ensure_unique(&self.delivery_scores, "delivery score", &input.score_id)?;
        ensure_capacity(
            self.delivery_scores.len(),
            self.config.max_delivery_scores,
            "delivery_scores",
        )?;
        ensure_bps("availability_bps", input.availability_bps)?;
        ensure_bps("correctness_bps", input.correctness_bps)?;
        ensure_bps("privacy_bps", input.privacy_bps)?;
        ensure_bps("fee_efficiency_bps", input.fee_efficiency_bps)?;

        let future = self
            .futures
            .get(&input.future_id)
            .ok_or_else(|| format!("unknown future `{}`", input.future_id))?;
        if future.lane_id != input.lane_id {
            return Err("delivery score lane does not match future lane".to_string());
        }
        if future.receipt_delta_root != input.receipt_delta_root {
            return Err("delivery score receipt delta root mismatch".to_string());
        }

        let latency_bps = latency_score_bps(input.observed_latency_ms, future.target_latency_ms);
        let aggregate_score_bps = weighted_average_bps(&[
            (input.availability_bps, 2_800),
            (input.correctness_bps, 2_700),
            (latency_bps, 2_000),
            (input.privacy_bps, 1_500),
            (input.fee_efficiency_bps, 1_000),
        ]);

        let score = ReceiptDeltaDeliveryScore {
            score_id: input.score_id.clone(),
            lane_id: input.lane_id,
            future_id: input.future_id.clone(),
            receipt_delta_root: input.receipt_delta_root,
            delivery_commitment: input.delivery_commitment,
            observed_latency_ms: input.observed_latency_ms,
            target_latency_ms: future.target_latency_ms,
            availability_bps: input.availability_bps,
            correctness_bps: input.correctness_bps,
            privacy_bps: input.privacy_bps,
            fee_efficiency_bps: input.fee_efficiency_bps,
            aggregate_score_bps,
            scored_at_slot: input.scored_at_slot,
            sequence: self.counters.delivery_scores.saturating_add(1),
        };

        self.counters.delivery_scores = self.counters.delivery_scores.saturating_add(1);
        self.delivery_scores.insert(input.score_id.clone(), score);
        if let Some(future) = self.futures.get_mut(&input.future_id) {
            future.delivery_score_id = Some(input.score_id.clone());
            future.status = if aggregate_score_bps >= self.config.min_delivery_score_bps {
                FutureStatus::Delivered
            } else {
                FutureStatus::Late
            };
            future.sequence = future.sequence.saturating_add(1);
        }
        self.refresh_roots();
        Ok(input.score_id)
    }

    pub fn settle_future(&mut self, input: SettleFutureInput) -> Result<String> {
        ensure_non_empty("settlement_id", &input.settlement_id)?;
        ensure_non_empty("future_id", &input.future_id)?;
        ensure_non_empty("curve_id", &input.curve_id)?;
        ensure_non_empty("settlement_root", &input.settlement_root)?;
        ensure_unique(&self.settlements, "settlement", &input.settlement_id)?;
        ensure_capacity(
            self.settlements.len(),
            self.config.max_settlements,
            "settlements",
        )?;
        if input.priority_fee_micros > self.config.priority_fee_cap_micros {
            return Err("settlement priority fee exceeds configured cap".to_string());
        }

        let future = self
            .futures
            .get(&input.future_id)
            .ok_or_else(|| format!("unknown future `{}`", input.future_id))?
            .clone();
        let curve = self
            .curves
            .get(&input.curve_id)
            .ok_or_else(|| format!("unknown curve `{}`", input.curve_id))?
            .clone();
        if future.matched_curve_id.as_deref() != Some(input.curve_id.as_str()) {
            return Err("future is not matched to settlement curve".to_string());
        }
        if input.settled_at_slot
            < future
                .created_at_slot
                .saturating_add(self.config.settlement_delay_slots)
        {
            return Err("settlement before configured delay".to_string());
        }

        let score_id = future
            .delivery_score_id
            .as_ref()
            .ok_or_else(|| "future has no receipt-delta delivery score".to_string())?;
        let score = self
            .delivery_scores
            .get(score_id)
            .ok_or_else(|| format!("unknown delivery score `{score_id}`"))?;
        let lane = self
            .lanes
            .get(&future.lane_id)
            .ok_or_else(|| format!("unknown lane `{}`", future.lane_id))?;

        let pricing = self.compute_settlement_pricing(
            &future,
            &curve,
            score,
            lane,
            input.priority_fee_micros,
        );
        let status = if score.aggregate_score_bps >= curve.min_delivery_score_bps {
            SettlementStatus::Settled
        } else if matches!(future.status, FutureStatus::Late) {
            SettlementStatus::Repriced
        } else {
            SettlementStatus::Rejected
        };

        let settlement = FeeAwareSettlement {
            settlement_id: input.settlement_id.clone(),
            future_id: input.future_id.clone(),
            curve_id: input.curve_id,
            lane_id: future.lane_id.clone(),
            settlement_status: status,
            fee_asset_id: self.config.fee_asset_id.clone(),
            gross_fee_micros: pricing.gross_fee_micros,
            priority_fee_micros: input.priority_fee_micros,
            maker_rebate_micros: pricing.maker_rebate_micros,
            taker_fee_micros: pricing.taker_fee_micros,
            privacy_rebate_micros: pricing.privacy_rebate_micros,
            late_penalty_micros: pricing.late_penalty_micros,
            net_settlement_micros: pricing.net_settlement_micros,
            delivery_score_bps: score.aggregate_score_bps,
            settlement_root: input.settlement_root,
            settled_at_slot: input.settled_at_slot,
            sequence: self.counters.settlements.saturating_add(1),
        };

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

        if let Some(future) = self.futures.get_mut(&input.future_id) {
            future.status = if matches!(status, SettlementStatus::Rejected) {
                FutureStatus::Late
            } else {
                FutureStatus::Settled
            };
            future.settlement_id = Some(input.settlement_id.clone());
            future.sequence = future.sequence.saturating_add(1);
        }

        self.settlements
            .insert(input.settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(input.settlement_id)
    }

    pub fn expire_futures(&mut self, slot: u64) -> Vec<String> {
        let mut expired = Vec::new();
        for (future_id, future) in self.futures.iter_mut() {
            if future.is_expired(slot) {
                future.status = FutureStatus::Expired;
                future.sequence = future.sequence.saturating_add(1);
                expired.push(future_id.clone());
            }
        }
        if !expired.is_empty() {
            self.counters.expired_futures = self
                .counters
                .expired_futures
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
            self.public_records.len(),
            self.config.max_public_records,
            "public_records",
        )?;
        self.refresh_roots();
        let sequence = self.counters.public_records.saturating_add(1);
        let public_root = domain_hash(
            D_PUBLIC,
            &[
                HashPart::from(self.roots.state_root.as_str()),
                HashPart::from(self.roots.lanes_root.as_str()),
                HashPart::from(self.roots.futures_root.as_str()),
                HashPart::from(self.roots.curves_root.as_str()),
                HashPart::from(self.roots.attestations_root.as_str()),
                HashPart::from(self.roots.delivery_scores_root.as_str()),
                HashPart::from(self.roots.settlements_root.as_str()),
                HashPart::from(height),
                HashPart::from(epoch),
                HashPart::from(sequence),
            ],
        );
        let record_id = domain_hash(
            D_PUBLIC,
            &[
                HashPart::from(PUBLIC_RECORD_SCHEME),
                HashPart::from(public_root.as_str()),
                HashPart::from(sequence),
            ],
        );
        let record = PublicRecord {
            record_id: record_id.clone(),
            scheme: PUBLIC_RECORD_SCHEME.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            state_root: self.roots.state_root.clone(),
            public_root,
            lane_root: self.roots.lanes_root.clone(),
            futures_root: self.roots.futures_root.clone(),
            curves_root: self.roots.curves_root.clone(),
            attestations_root: self.roots.attestations_root.clone(),
            delivery_scores_root: self.roots.delivery_scores_root.clone(),
            settlements_root: self.roots.settlements_root.clone(),
            counters_root: self.roots.counters_root.clone(),
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
        self.roots.config_root = canonical_root(D_CONFIG, &self.config);
        self.roots.counters_root = canonical_root(D_COUNTERS, &self.counters);
        self.roots.lanes_root = map_root(D_LANES, &self.lanes);
        self.roots.futures_root = map_root(D_FUTURES, &self.futures);
        self.roots.curves_root = map_root(D_CURVES, &self.curves);
        self.roots.attestations_root = map_root(D_ATTESTATIONS, &self.attestations);
        self.roots.delivery_scores_root = map_root(D_SCORES, &self.delivery_scores);
        self.roots.settlements_root = map_root(D_SETTLEMENTS, &self.settlements);
        self.roots.public_records_root = map_root(D_PUBLIC, &self.public_records);
        self.roots.state_root = domain_hash(
            D_STATE,
            &[
                HashPart::from(PROTOCOL_VERSION),
                HashPart::from(SCHEMA_VERSION),
                HashPart::from(self.roots.config_root.as_str()),
                HashPart::from(self.roots.counters_root.as_str()),
                HashPart::from(self.roots.lanes_root.as_str()),
                HashPart::from(self.roots.futures_root.as_str()),
                HashPart::from(self.roots.curves_root.as_str()),
                HashPart::from(self.roots.attestations_root.as_str()),
                HashPart::from(self.roots.delivery_scores_root.as_str()),
                HashPart::from(self.roots.settlements_root.as_str()),
                HashPart::from(self.roots.public_records_root.as_str()),
            ],
        );
        self.counters.state_root_updates = self.counters.state_root_updates.saturating_add(1);
        self.roots.counters_root = canonical_root(D_COUNTERS, &self.counters);
        self.roots.state_root = domain_hash(
            D_STATE,
            &[
                HashPart::from(PROTOCOL_VERSION),
                HashPart::from(SCHEMA_VERSION),
                HashPart::from(self.roots.config_root.as_str()),
                HashPart::from(self.roots.counters_root.as_str()),
                HashPart::from(self.roots.lanes_root.as_str()),
                HashPart::from(self.roots.futures_root.as_str()),
                HashPart::from(self.roots.curves_root.as_str()),
                HashPart::from(self.roots.attestations_root.as_str()),
                HashPart::from(self.roots.delivery_scores_root.as_str()),
                HashPart::from(self.roots.settlements_root.as_str()),
                HashPart::from(self.roots.public_records_root.as_str()),
            ],
        );
    }

    fn mark_future_slashed(&mut self, future_id: &str) -> Result<()> {
        let future = self
            .futures
            .get_mut(future_id)
            .ok_or_else(|| format!("unknown future `{future_id}`"))?;
        future.status = FutureStatus::Slashed;
        future.sequence = future.sequence.saturating_add(1);
        self.counters.slashed_futures = self.counters.slashed_futures.saturating_add(1);
        Ok(())
    }

    fn compute_settlement_pricing(
        &self,
        future: &StateWitnessLatencyFuture,
        curve: &PreconfirmationLatencyCurve,
        score: &ReceiptDeltaDeliveryScore,
        lane: &Lane,
        priority_fee_micros: u64,
    ) -> SettlementPricing {
        let scope_weight = future.witness_scope.complexity_weight();
        let lane_weight = lane.lane_class.priority_weight();
        let complexity_fee = future
            .notional_fee_micros
            .saturating_mul(scope_weight)
            .saturating_div(1_000);
        let lane_fee = complexity_fee
            .saturating_mul(lane_weight)
            .saturating_div(MAX_BPS);
        let gross_fee_micros = curve
            .base_fee_micros
            .saturating_add(lane_fee)
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
        let late_penalty_micros = if score.aggregate_score_bps < self.config.min_delivery_score_bps
        {
            gross_fee_micros
                .saturating_mul(self.config.late_delivery_penalty_bps)
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
            .saturating_sub(privacy_rebate_micros);

        SettlementPricing {
            gross_fee_micros,
            maker_rebate_micros,
            taker_fee_micros,
            privacy_rebate_micros,
            late_penalty_micros,
            net_settlement_micros,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct SettlementPricing {
    gross_fee_micros: u64,
    maker_rebate_micros: u64,
    taker_fee_micros: u64,
    privacy_rebate_micros: u64,
    late_penalty_micros: u64,
    net_settlement_micros: u64,
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let lane_id = "devnet-state-witness-latency-lane-0".to_string();
    state
        .register_lane(RegisterLaneInput {
            lane_id: lane_id.clone(),
            operator_commitment: devnet_commitment("operator", 0),
            lane_class: LaneClass::StateOracle,
            pq_attestation_key_root: devnet_commitment("pq-key-root", 0),
            capacity_commitment: devnet_commitment("capacity", 0),
            fee_escrow_commitment: devnet_commitment("fee-escrow", 0),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            congestion_bps: 250,
            created_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet lane must register");
    state
        .set_lane_status(&lane_id, LaneStatus::Hot)
        .expect("devnet lane status must update");
    state
        .post_curve(PostCurveInput {
            curve_id: "devnet-preconfirmation-latency-curve-0".to_string(),
            lane_id: lane_id.clone(),
            curve_kind: CurveKind::PrivacyWeighted,
            sealed_curve_root: devnet_commitment("sealed-curve", 0),
            maker_commitment: devnet_commitment("maker", 0),
            target_latency_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            max_latency_ms: DEFAULT_SOFT_LATENCY_MS,
            base_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            min_delivery_score_bps: DEFAULT_MIN_DELIVERY_SCORE_BPS,
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

fn latency_score_bps(observed_latency_ms: u64, target_latency_ms: u64) -> u64 {
    if observed_latency_ms <= target_latency_ms {
        return MAX_BPS;
    }
    let overage = observed_latency_ms.saturating_sub(target_latency_ms);
    let target = target_latency_ms.max(1);
    let penalty = overage.saturating_mul(MAX_BPS).saturating_div(target);
    MAX_BPS.saturating_sub(penalty.min(MAX_BPS))
}

fn weighted_average_bps(parts: &[(u64, u64)]) -> u64 {
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

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(len: usize, max: usize, label: &str) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_unique<T>(map: &BTreeMap<String, T>, label: &str, id: &str) -> Result<()> {
    if map.contains_key(id) {
        Err(format!("{label} `{id}` already exists"))
    } else {
        Ok(())
    }
}

fn canonical_root<T: Serialize>(domain: &'static str, value: &T) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    domain_hash(domain, &[HashPart::from(encoded.as_str())])
}

fn map_root<T: Serialize>(domain: &'static str, map: &BTreeMap<String, T>) -> String {
    if map.is_empty() {
        return empty_root(domain);
    }
    let leaves = map
        .iter()
        .map(|(key, value)| {
            let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
            domain_hash(
                domain,
                &[
                    HashPart::from(key.as_str()),
                    HashPart::from(encoded.as_str()),
                ],
            )
        })
        .collect::<Vec<_>>();
    merkle_root(
        domain,
        leaves.iter().map(|leaf| HashPart::from(leaf.as_str())),
    )
}

fn empty_root(domain: &'static str) -> String {
    merkle_root(domain, std::iter::empty::<HashPart>())
}

fn devnet_commitment(label: &str, sequence: u64) -> String {
    domain_hash(
        D_DEVNET,
        &[
            HashPart::from(label),
            HashPart::from(DEVNET_L2_NETWORK),
            HashPart::from(DEVNET_HEIGHT),
            HashPart::from(DEVNET_EPOCH),
            HashPart::from(sequence),
        ],
    )
}
