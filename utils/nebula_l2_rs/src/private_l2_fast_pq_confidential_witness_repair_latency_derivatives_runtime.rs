use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialWitnessRepairLatencyDerivativesRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_REPAIR_LATENCY_DERIVATIVES_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-fast-pq-confidential-witness-repair-latency-derivatives-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_REPAIR_LATENCY_DERIVATIVES_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "shake256-domain-separated-canonical-json-v1";
pub const LATENCY_DERIVATIVES_SUITE: &str =
    "private-l2-fast-pq-confidential-witness-repair-latency-derivatives-v1";
pub const LATENCY_FUTURES_SUITE: &str = "ml-kem-1024-sealed-witness-repair-latency-futures-root-v1";
pub const LATENCY_OPTIONS_SUITE: &str = "ml-kem-1024-sealed-witness-repair-latency-options-root-v1";
pub const PQ_LANE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-witness-repair-latency-lane-attestation-v1";
pub const REPAIR_TICKET_COMMITMENT_SUITE: &str =
    "confidential-witness-repair-ticket-commitment-root-v1";
pub const PRECONFIRMATION_LATENCY_CURVE_SUITE: &str =
    "sealed-preconfirmation-witness-repair-latency-curve-root-v1";
pub const RELIABILITY_SCORE_SUITE: &str =
    "private-l2-witness-repair-lane-reliability-score-root-v1";
pub const FEE_REBATE_SETTLEMENT_SUITE: &str =
    "low-fee-confidential-witness-repair-derivatives-rebate-settlement-root-v1";
pub const ANTI_REPLAY_RECEIPT_SUITE: &str =
    "monero-private-l2-witness-repair-latency-derivative-anti-replay-receipt-root-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-witness-repair-latency-derivatives-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_witnesses_addresses_view_keys_repair_payloads_fee_amounts_or_strategy";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_EPOCH: u64 = 39_936;
pub const DEVNET_HEIGHT: u64 = 7_140_000;
pub const MAX_BPS: u64 = 10_000;
pub const SCORE_SCALE: u64 = 1_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_SLOT_WIDTH_MS: u64 = 40;
pub const DEFAULT_TARGET_REPAIR_MS: u64 = 120;
pub const DEFAULT_SOFT_REPAIR_MS: u64 = 210;
pub const DEFAULT_HARD_REPAIR_MS: u64 = 520;
pub const DEFAULT_FUTURE_TTL_SLOTS: u64 = 96;
pub const DEFAULT_OPTION_TTL_SLOTS: u64 = 192;
pub const DEFAULT_CURVE_TTL_SLOTS: u64 = 32;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 128;
pub const DEFAULT_SCORE_WINDOW_SLOTS: u64 = 96;
pub const DEFAULT_SETTLEMENT_DELAY_SLOTS: u64 = 3;
pub const DEFAULT_MAX_LANES: usize = 65_536;
pub const DEFAULT_MAX_TICKETS: usize = 1_048_576;
pub const DEFAULT_MAX_FUTURES: usize = 1_048_576;
pub const DEFAULT_MAX_OPTIONS: usize = 524_288;
pub const DEFAULT_MAX_CURVES: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_RELIABILITY_SCORES: usize = 1_048_576;
pub const DEFAULT_MAX_REBATE_SETTLEMENTS: usize = 524_288;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 262_144;
pub const DEFAULT_MIN_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MIN_RELIABILITY_BPS: u64 = 8_400;
pub const DEFAULT_TARGET_HEDGE_FILL_BPS: u64 = 8_800;
pub const DEFAULT_LOW_FEE_BONUS_BPS: u64 = 700;
pub const DEFAULT_PRIVACY_BONUS_BPS: u64 = 420;
pub const DEFAULT_CONGESTION_PENALTY_BPS: u64 = 1_100;
pub const DEFAULT_LATE_REPAIR_PENALTY_BPS: u64 = 1_650;
pub const DEFAULT_REPLAY_PENALTY_BPS: u64 = 2_000;
pub const DEFAULT_PRIORITY_FEE_CAP_MICROS: u64 = 88;
pub const DEFAULT_BASE_SETTLEMENT_FEE_MICROS: u64 = 3;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 140;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 220;
pub const DEFAULT_OPTION_PREMIUM_FLOOR_MICROS: u64 = 2;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:STATE";
const D_LANES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:LANES";
const D_TICKETS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:TICKETS";
const D_FUTURES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:FUTURES";
const D_OPTIONS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:OPTIONS";
const D_CURVES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:CURVES";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:ATTESTATIONS";
const D_SCORES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:SCORES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:REBATES";
const D_RECEIPTS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:RECEIPTS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:PUBLIC";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:EVENTS";
const D_DEVNET: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-LAT-DERIV:DEVNET";

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairLaneClass {
    WalletFast,
    MerchantPos,
    DefiIntent,
    BridgeExit,
    ContractCall,
    RecursiveProof,
    StateOracle,
    Watchtower,
    EmergencyCancel,
    BulkRepair,
}

impl RepairLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletFast => "wallet_fast",
            Self::MerchantPos => "merchant_pos",
            Self::DefiIntent => "defi_intent",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::RecursiveProof => "recursive_proof",
            Self::StateOracle => "state_oracle",
            Self::Watchtower => "watchtower",
            Self::EmergencyCancel => "emergency_cancel",
            Self::BulkRepair => "bulk_repair",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyCancel => 11_200,
            Self::BridgeExit => 10_500,
            Self::MerchantPos => 10_050,
            Self::DefiIntent => 9_800,
            Self::ContractCall => 9_450,
            Self::RecursiveProof => 9_300,
            Self::WalletFast => 9_000,
            Self::StateOracle => 8_650,
            Self::Watchtower => 8_250,
            Self::BulkRepair => 7_100,
        }
    }
    pub fn privacy_floor(self) -> u64 {
        match self {
            Self::BridgeExit | Self::DefiIntent | Self::MerchantPos => 524_288,
            Self::ContractCall | Self::RecursiveProof | Self::StateOracle => 262_144,
            Self::EmergencyCancel | Self::Watchtower => 131_072,
            Self::WalletFast => 196_608,
            Self::BulkRepair => 65_536,
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
    Slashed,
    Retired,
}

impl LaneStatus {
    pub fn accepts_derivatives(self) -> bool {
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
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRepairScope {
    AccountReadSet,
    ContractStorage,
    NullifierSet,
    ReceiptDelta,
    InclusionPath,
    BridgeOutput,
    StateRootDelta,
    RepairShard,
    RecursiveProofLeaf,
    WatchtowerEvidence,
    FeeRebateProof,
    EmergencyCancelPath,
}

impl WitnessRepairScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountReadSet => "account_read_set",
            Self::ContractStorage => "contract_storage",
            Self::NullifierSet => "nullifier_set",
            Self::ReceiptDelta => "receipt_delta",
            Self::InclusionPath => "inclusion_path",
            Self::BridgeOutput => "bridge_output",
            Self::StateRootDelta => "state_root_delta",
            Self::RepairShard => "repair_shard",
            Self::RecursiveProofLeaf => "recursive_proof_leaf",
            Self::WatchtowerEvidence => "watchtower_evidence",
            Self::FeeRebateProof => "fee_rebate_proof",
            Self::EmergencyCancelPath => "emergency_cancel_path",
        }
    }
    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::EmergencyCancelPath => 1_280,
            Self::BridgeOutput => 1_170,
            Self::RecursiveProofLeaf => 1_120,
            Self::ContractStorage => 1_070,
            Self::StateRootDelta => 1_030,
            Self::ReceiptDelta => 970,
            Self::WatchtowerEvidence => 920,
            Self::RepairShard => 880,
            Self::NullifierSet => 840,
            Self::FeeRebateProof => 800,
            Self::AccountReadSet => 760,
            Self::InclusionPath => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    Hedged,
    CurveMatched,
    Attested,
    Repairing,
    Delivered,
    Settled,
    Late,
    Expired,
    Cancelled,
    Slashed,
}

impl TicketStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Hedged
                | Self::CurveMatched
                | Self::Attested
                | Self::Repairing
                | Self::Delivered
        )
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Hedged => "hedged",
            Self::CurveMatched => "curve_matched",
            Self::Attested => "attested",
            Self::Repairing => "repairing",
            Self::Delivered => "delivered",
            Self::Settled => "settled",
            Self::Late => "late",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureSide {
    HedgeLatency,
    SellRepairCapacity,
    SponsorUserRebate,
    InsuranceBackstop,
    MakerInventory,
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
pub enum OptionKind {
    CallOnFastRepair,
    PutOnLateRepair,
    StraddleLatency,
    RebateFloor,
    CongestionCap,
    EmergencyTail,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStatus {
    Open,
    CurveMatched,
    Exercisable,
    Exercised,
    Expired,
    Settled,
    Cancelled,
    Slashed,
}

impl OptionStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::CurveMatched | Self::Exercisable)
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
    ReliabilityWeighted,
    EmergencyCap,
    OptionVolatilitySmile,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    LaneOpen,
    RepairAccepted,
    RepairDelivered,
    CurveSigned,
    FutureHedged,
    OptionWritten,
    RebateCommitted,
    ReplayReceiptBound,
    ReliabilityCheckpoint,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Nettable,
    Settled,
    Rebated,
    Slashed,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Fresh,
    Accepted,
    Duplicate,
    Expired,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct Config { pub protocol_version: String, pub schema_version: u64, pub runtime_mode: RuntimeMode, pub l2_network: String, pub fee_asset_id: String, pub min_pq_security_bits: u16, pub min_privacy_set_size: u64, pub target_privacy_set_size: u64, pub slot_width_ms: u64, pub target_repair_ms: u64, pub soft_repair_ms: u64, pub hard_repair_ms: u64, pub future_ttl_slots: u64, pub option_ttl_slots: u64, pub curve_ttl_slots: u64, pub attestation_ttl_slots: u64, pub score_window_slots: u64, pub settlement_delay_slots: u64, pub max_lanes: usize, pub max_tickets: usize, pub max_futures: usize, pub max_options: usize, pub max_curves: usize, pub max_attestations: usize, pub max_reliability_scores: usize, pub max_rebate_settlements: usize, pub max_receipts: usize, pub max_public_records: usize, pub min_quorum_weight_bps: u64, pub strong_quorum_weight_bps: u64, pub min_reliability_bps: u64, pub target_hedge_fill_bps: u64, pub low_fee_bonus_bps: u64, pub privacy_bonus_bps: u64, pub congestion_penalty_bps: u64, pub late_repair_penalty_bps: u64, pub replay_penalty_bps: u64, pub priority_fee_cap_micros: u64, pub base_settlement_fee_micros: u64, pub maker_rebate_bps: u64, pub taker_fee_bps: u64, pub option_premium_floor_micros: u64, pub roots_only_public_records: bool, pub reject_plaintext_witness_payloads: bool, pub require_anti_replay_receipts: bool, pub require_pq_lane_attestations: bool, pub enable_fee_rebate_netting: bool }

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            runtime_mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            slot_width_ms: DEFAULT_SLOT_WIDTH_MS,
            target_repair_ms: DEFAULT_TARGET_REPAIR_MS,
            soft_repair_ms: DEFAULT_SOFT_REPAIR_MS,
            hard_repair_ms: DEFAULT_HARD_REPAIR_MS,
            future_ttl_slots: DEFAULT_FUTURE_TTL_SLOTS,
            option_ttl_slots: DEFAULT_OPTION_TTL_SLOTS,
            curve_ttl_slots: DEFAULT_CURVE_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            score_window_slots: DEFAULT_SCORE_WINDOW_SLOTS,
            settlement_delay_slots: DEFAULT_SETTLEMENT_DELAY_SLOTS,
            max_lanes: DEFAULT_MAX_LANES,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_futures: DEFAULT_MAX_FUTURES,
            max_options: DEFAULT_MAX_OPTIONS,
            max_curves: DEFAULT_MAX_CURVES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_reliability_scores: DEFAULT_MAX_RELIABILITY_SCORES,
            max_rebate_settlements: DEFAULT_MAX_REBATE_SETTLEMENTS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
            min_quorum_weight_bps: DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            min_reliability_bps: DEFAULT_MIN_RELIABILITY_BPS,
            target_hedge_fill_bps: DEFAULT_TARGET_HEDGE_FILL_BPS,
            low_fee_bonus_bps: DEFAULT_LOW_FEE_BONUS_BPS,
            privacy_bonus_bps: DEFAULT_PRIVACY_BONUS_BPS,
            congestion_penalty_bps: DEFAULT_CONGESTION_PENALTY_BPS,
            late_repair_penalty_bps: DEFAULT_LATE_REPAIR_PENALTY_BPS,
            replay_penalty_bps: DEFAULT_REPLAY_PENALTY_BPS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            base_settlement_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            option_premium_floor_micros: DEFAULT_OPTION_PREMIUM_FLOOR_MICROS,
            roots_only_public_records: true,
            reject_plaintext_witness_payloads: true,
            require_anti_replay_receipts: true,
            require_pq_lane_attestations: true,
            enable_fee_rebate_netting: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct Counters { pub lanes_registered: u64, pub tickets_opened: u64, pub tickets_delivered: u64, pub tickets_settled: u64, pub futures_opened: u64, pub futures_settled: u64, pub options_written: u64, pub options_exercised: u64, pub curves_posted: u64, pub attestations_recorded: u64, pub reliability_scores_recorded: u64, pub rebate_settlements_recorded: u64, pub anti_replay_receipts_recorded: u64, pub duplicate_replay_receipts: u64, pub public_records_emitted: u64, pub expired_positions: u64, pub slashed_positions: u64, pub total_notional_micros: u128, pub total_rebate_micros: u128, pub total_penalty_micros: u128, pub total_priority_fee_micros: u128, pub total_fee_savings_micros: u128, pub peak_open_interest_micros: u128, pub last_height: u64, pub last_epoch: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct Roots { pub config_root: String, pub counters_root: String, pub lanes_root: String, pub ticket_commitments_root: String, pub latency_futures_root: String, pub latency_options_root: String, pub preconfirmation_curves_root: String, pub pq_attestations_root: String, pub reliability_scores_root: String, pub fee_rebate_settlements_root: String, pub anti_replay_receipts_root: String, pub event_root: String, pub public_records_root: String, pub state_root: String }

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root(D_CONFIG),
            counters_root: empty_root(D_COUNTERS),
            lanes_root: empty_root(D_LANES),
            ticket_commitments_root: empty_root(D_TICKETS),
            latency_futures_root: empty_root(D_FUTURES),
            latency_options_root: empty_root(D_OPTIONS),
            preconfirmation_curves_root: empty_root(D_CURVES),
            pq_attestations_root: empty_root(D_ATTESTATIONS),
            reliability_scores_root: empty_root(D_SCORES),
            fee_rebate_settlements_root: empty_root(D_REBATES),
            anti_replay_receipts_root: empty_root(D_RECEIPTS),
            event_root: empty_root(D_EVENTS),
            public_records_root: empty_root(D_PUBLIC),
            state_root: empty_root(D_STATE),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct RepairLane { pub lane_id: String, pub operator_commitment: String, pub lane_class: RepairLaneClass, pub status: LaneStatus, pub pq_attestation_key_root: String, pub lane_secret_commitment_root: String, pub capacity_commitment: String, pub fee_escrow_commitment: String, pub privacy_set_size: u64, pub quorum_weight_bps: u64, pub reliability_bps: u64, pub congestion_bps: u64, pub target_repair_ms: u64, pub max_repair_ms: u64, pub priority_fee_cap_micros: u64, pub open_interest_limit_micros: u128, pub open_interest_micros: u128, pub active_ticket_count: u64, pub active_future_count: u64, pub active_option_count: u64, pub delivered_count: u64, pub late_count: u64, pub replay_fault_count: u64, pub last_attested_slot: u64, pub created_at_height: u64, pub updated_at_height: u64 }

impl RepairLane {
    pub fn accepts_work(&self) -> bool {
        self.status.accepts_derivatives()
            && self.privacy_set_size >= self.lane_class.privacy_floor()
            && self.quorum_weight_bps >= DEFAULT_MIN_QUORUM_WEIGHT_BPS
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
    pub fn low_fee_bonus_bps(&self, config: &Config) -> u64 {
        if self.priority_fee_cap_micros <= config.priority_fee_cap_micros {
            config.low_fee_bonus_bps
        } else {
            0
        }
    }
    pub fn available_open_interest(&self) -> u128 {
        self.open_interest_limit_micros
            .saturating_sub(self.open_interest_micros)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct RepairTicketCommitment { pub ticket_id: String, pub lane_id: String, pub owner_commitment: String, pub repair_scope: WitnessRepairScope, pub ticket_commitment_root: String, pub sealed_witness_root: String, pub nullifier_root: String, pub fee_escrow_commitment: String, pub notional_fee_micros: u64, pub priority_fee_micros: u64, pub target_latency_ms: u64, pub max_latency_ms: u64, pub privacy_set_size: u64, pub opened_slot: u64, pub expires_slot: u64, pub delivered_slot: Option<u64>, pub observed_latency_ms: Option<u64>, pub matched_curve_id: Option<String>, pub matched_future_id: Option<String>, pub matched_option_id: Option<String>, pub anti_replay_receipt_id: Option<String>, pub status: TicketStatus, pub settlement_root: Option<String>, pub created_at_height: u64, pub updated_at_height: u64 }

impl RepairTicketCommitment {
    pub fn live(&self) -> bool {
        self.status.live()
    }
    pub fn is_expired(&self, slot: u64) -> bool {
        slot > self.expires_slot && self.live()
    }
    pub fn latency_score_bps(&self) -> u64 {
        latency_score_bps(
            self.observed_latency_ms.unwrap_or(self.max_latency_ms),
            self.target_latency_ms,
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct LatencyFuture { pub future_id: String, pub ticket_id: String, pub lane_id: String, pub side: FutureSide, pub maker_commitment: String, pub taker_commitment: String, pub sealed_terms_root: String, pub margin_commitment: String, pub notional_micros: u64, pub target_latency_ms: u64, pub max_latency_ms: u64, pub strike_latency_ms: u64, pub premium_micros: u64, pub priority_fee_cap_micros: u64, pub maker_rebate_bps: u64, pub taker_fee_bps: u64, pub opened_slot: u64, pub expires_slot: u64, pub matched_curve_id: Option<String>, pub attestation_id: Option<String>, pub settlement_id: Option<String>, pub status: FutureStatus, pub created_at_height: u64, pub updated_at_height: u64 }

impl LatencyFuture {
    pub fn live(&self) -> bool {
        self.status.live()
    }
    pub fn is_expired(&self, slot: u64) -> bool {
        slot > self.expires_slot && self.live()
    }
    pub fn payoff_micros(&self, observed_latency_ms: u64) -> u64 {
        if observed_latency_ms <= self.strike_latency_ms {
            self.premium_micros
        } else {
            let over = observed_latency_ms.saturating_sub(self.strike_latency_ms);
            self.notional_micros
                .saturating_mul(over)
                .saturating_div(self.max_latency_ms.max(1))
                .saturating_add(self.premium_micros)
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct LatencyOption { pub option_id: String, pub ticket_id: String, pub lane_id: String, pub option_kind: OptionKind, pub writer_commitment: String, pub holder_commitment: String, pub sealed_terms_root: String, pub collateral_commitment: String, pub notional_micros: u64, pub premium_micros: u64, pub strike_latency_ms: u64, pub barrier_latency_ms: u64, pub max_payout_micros: u64, pub rebate_floor_micros: u64, pub opened_slot: u64, pub exercise_start_slot: u64, pub expires_slot: u64, pub matched_curve_id: Option<String>, pub exercise_receipt_id: Option<String>, pub settlement_id: Option<String>, pub status: OptionStatus, pub created_at_height: u64, pub updated_at_height: u64 }

impl LatencyOption {
    pub fn live(&self) -> bool {
        self.status.live()
    }
    pub fn is_expired(&self, slot: u64) -> bool {
        slot > self.expires_slot && self.live()
    }
    pub fn intrinsic_value_micros(&self, observed_latency_ms: u64) -> u64 {
        let raw = match self.option_kind {
            OptionKind::CallOnFastRepair => self
                .strike_latency_ms
                .saturating_sub(observed_latency_ms)
                .saturating_mul(self.notional_micros)
                .saturating_div(self.strike_latency_ms.max(1)),
            OptionKind::PutOnLateRepair => observed_latency_ms
                .saturating_sub(self.strike_latency_ms)
                .saturating_mul(self.notional_micros)
                .saturating_div(self.barrier_latency_ms.max(1)),
            OptionKind::StraddleLatency => observed_latency_ms
                .abs_diff(self.strike_latency_ms)
                .saturating_mul(self.notional_micros)
                .saturating_div(self.barrier_latency_ms.max(1)),
            OptionKind::RebateFloor => self.rebate_floor_micros,
            OptionKind::CongestionCap => observed_latency_ms
                .saturating_sub(self.barrier_latency_ms)
                .saturating_mul(self.notional_micros)
                .saturating_div(self.barrier_latency_ms.max(1)),
            OptionKind::EmergencyTail => observed_latency_ms
                .saturating_sub(self.strike_latency_ms)
                .saturating_mul(self.notional_micros)
                .saturating_div(1_000),
        };
        raw.min(self.max_payout_micros)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct PreconfirmationLatencyCurve { pub curve_id: String, pub lane_id: String, pub curve_kind: CurveKind, pub sealed_curve_root: String, pub maker_commitment: String, pub base_fee_micros: u64, pub priority_fee_cap_micros: u64, pub target_latency_ms: u64, pub soft_latency_ms: u64, pub hard_latency_ms: u64, pub min_reliability_bps: u64, pub min_quorum_weight_bps: u64, pub capacity_units: u64, pub filled_units: u64, pub slope_bps: u64, pub volatility_bps: u64, pub privacy_discount_bps: u64, pub low_fee_discount_bps: u64, pub valid_from_slot: u64, pub valid_until_slot: u64, pub posted_at_height: u64, pub updated_at_height: u64 }

impl PreconfirmationLatencyCurve {
    pub fn accepts(&self, slot: u64, lane: &RepairLane, notional_micros: u64) -> bool {
        slot >= self.valid_from_slot
            && slot <= self.valid_until_slot
            && self.filled_units < self.capacity_units
            && lane.reliability_bps >= self.min_reliability_bps
            && lane.quorum_weight_bps >= self.min_quorum_weight_bps
            && lane.available_open_interest() >= notional_micros as u128
    }
    pub fn quote_fee_micros(
        &self,
        scope: WitnessRepairScope,
        lane: &RepairLane,
        priority_fee_micros: u64,
    ) -> u64 {
        let complexity = scope.complexity_weight();
        let lane_weight = lane.lane_class.priority_weight();
        let curve_fee = self
            .base_fee_micros
            .saturating_mul(complexity)
            .saturating_div(1_000)
            .saturating_mul(lane_weight)
            .saturating_div(MAX_BPS);
        let congestion_fee = curve_fee
            .saturating_mul(lane.congestion_bps)
            .saturating_div(MAX_BPS);
        curve_fee
            .saturating_add(congestion_fee)
            .saturating_add(priority_fee_micros.min(self.priority_fee_cap_micros))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct PqLaneAttestation { pub attestation_id: String, pub lane_id: String, pub ticket_id: Option<String>, pub derivative_id: Option<String>, pub attestation_kind: AttestationKind, pub attestor_commitment: String, pub pq_signature_root: String, pub transcript_root: String, pub anti_replay_nonce_root: String, pub claimed_latency_ms: u64, pub claimed_reliability_bps: u64, pub claimed_quorum_weight_bps: u64, pub claimed_privacy_set_size: u64, pub issued_slot: u64, pub expires_slot: u64, pub issued_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct ReliabilityScore { pub score_id: String, pub lane_id: String, pub window_start_slot: u64, pub window_end_slot: u64, pub tickets_observed: u64, pub delivered_count: u64, pub late_count: u64, pub replay_fault_count: u64, pub median_latency_ms: u64, pub p95_latency_ms: u64, pub target_latency_ms: u64, pub delivery_score_bps: u64, pub latency_score_bps: u64, pub replay_score_bps: u64, pub privacy_score_bps: u64, pub fee_score_bps: u64, pub aggregate_score_bps: u64, pub score_root: String, pub recorded_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct FeeRebateSettlement { pub settlement_id: String, pub lane_id: String, pub ticket_id: String, pub future_id: Option<String>, pub option_id: Option<String>, pub score_id: Option<String>, pub payer_commitment: String, pub receiver_commitment: String, pub gross_fee_micros: u64, pub maker_rebate_micros: u64, pub low_fee_rebate_micros: u64, pub privacy_rebate_micros: u64, pub reliability_rebate_micros: u64, pub option_payout_micros: u64, pub late_penalty_micros: u64, pub replay_penalty_micros: u64, pub taker_fee_micros: u64, pub net_settlement_micros: u64, pub settlement_commitment_root: String, pub status: SettlementStatus, pub settlement_slot: u64, pub recorded_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct AntiReplayReceipt { pub receipt_id: String, pub lane_id: String, pub ticket_id: Option<String>, pub derivative_id: Option<String>, pub nullifier_root: String, pub nonce_commitment_root: String, pub transcript_root: String, pub receipt_root: String, pub status: ReceiptStatus, pub first_seen_slot: u64, pub expires_slot: u64, pub recorded_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct PublicRecord { pub protocol_version: String, pub schema_version: u64, pub l2_network: String, pub height: u64, pub epoch: u64, pub privacy_boundary: String, pub hash_suite: String, pub latency_derivatives_suite: String, pub pq_lane_attestation_suite: String, pub repair_ticket_commitment_suite: String, pub preconfirmation_latency_curve_suite: String, pub fee_rebate_settlement_suite: String, pub anti_replay_receipt_suite: String, pub roots: Roots, pub counters: Counters, pub lane_count: usize, pub ticket_count: usize, pub future_count: usize, pub option_count: usize, pub curve_count: usize, pub attestation_count: usize, pub reliability_score_count: usize, pub rebate_settlement_count: usize, pub anti_replay_receipt_count: usize, pub record_root: String }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct RegisterLaneInput { pub lane_id: String, pub operator_commitment: String, pub lane_class: RepairLaneClass, pub pq_attestation_key_root: String, pub lane_secret_commitment_root: String, pub capacity_commitment: String, pub fee_escrow_commitment: String, pub privacy_set_size: u64, pub quorum_weight_bps: u64, pub target_repair_ms: u64, pub max_repair_ms: u64, pub priority_fee_cap_micros: u64, pub open_interest_limit_micros: u128, pub created_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct OpenTicketInput { pub ticket_id: String, pub lane_id: String, pub owner_commitment: String, pub repair_scope: WitnessRepairScope, pub ticket_commitment_root: String, pub sealed_witness_root: String, pub nullifier_root: String, pub fee_escrow_commitment: String, pub notional_fee_micros: u64, pub priority_fee_micros: u64, pub target_latency_ms: u64, pub max_latency_ms: u64, pub privacy_set_size: u64, pub opened_slot: u64, pub expires_slot: u64, pub created_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct OpenFutureInput { pub future_id: String, pub ticket_id: String, pub lane_id: String, pub side: FutureSide, pub maker_commitment: String, pub taker_commitment: String, pub sealed_terms_root: String, pub margin_commitment: String, pub notional_micros: u64, pub target_latency_ms: u64, pub max_latency_ms: u64, pub strike_latency_ms: u64, pub premium_micros: u64, pub priority_fee_cap_micros: u64, pub maker_rebate_bps: u64, pub taker_fee_bps: u64, pub opened_slot: u64, pub expires_slot: u64, pub created_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct WriteOptionInput { pub option_id: String, pub ticket_id: String, pub lane_id: String, pub option_kind: OptionKind, pub writer_commitment: String, pub holder_commitment: String, pub sealed_terms_root: String, pub collateral_commitment: String, pub notional_micros: u64, pub premium_micros: u64, pub strike_latency_ms: u64, pub barrier_latency_ms: u64, pub max_payout_micros: u64, pub rebate_floor_micros: u64, pub opened_slot: u64, pub exercise_start_slot: u64, pub expires_slot: u64, pub created_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct PostCurveInput { pub curve_id: String, pub lane_id: String, pub curve_kind: CurveKind, pub sealed_curve_root: String, pub maker_commitment: String, pub base_fee_micros: u64, pub priority_fee_cap_micros: u64, pub target_latency_ms: u64, pub soft_latency_ms: u64, pub hard_latency_ms: u64, pub min_reliability_bps: u64, pub min_quorum_weight_bps: u64, pub capacity_units: u64, pub slope_bps: u64, pub volatility_bps: u64, pub privacy_discount_bps: u64, pub low_fee_discount_bps: u64, pub valid_from_slot: u64, pub valid_until_slot: u64, pub posted_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct RecordAttestationInput { pub attestation_id: String, pub lane_id: String, pub ticket_id: Option<String>, pub derivative_id: Option<String>, pub attestation_kind: AttestationKind, pub attestor_commitment: String, pub pq_signature_root: String, pub transcript_root: String, pub anti_replay_nonce_root: String, pub claimed_latency_ms: u64, pub claimed_reliability_bps: u64, pub claimed_quorum_weight_bps: u64, pub claimed_privacy_set_size: u64, pub issued_slot: u64, pub expires_slot: u64, pub issued_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct RecordDeliveryInput { pub ticket_id: String, pub lane_id: String, pub observed_latency_ms: u64, pub delivered_slot: u64, pub attestation_id: String, pub receipt_id: String, pub updated_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct RecordReceiptInput { pub receipt_id: String, pub lane_id: String, pub ticket_id: Option<String>, pub derivative_id: Option<String>, pub nullifier_root: String, pub nonce_commitment_root: String, pub transcript_root: String, pub first_seen_slot: u64, pub expires_slot: u64, pub recorded_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct SettleInput { pub settlement_id: String, pub ticket_id: String, pub future_id: Option<String>, pub option_id: Option<String>, pub payer_commitment: String, pub receiver_commitment: String, pub settlement_slot: u64, pub recorded_at_height: u64 }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[rustfmt::skip]
pub struct State { pub config: Config, pub counters: Counters, pub roots: Roots, pub lanes: BTreeMap<String, RepairLane>, pub tickets: BTreeMap<String, RepairTicketCommitment>, pub futures: BTreeMap<String, LatencyFuture>, pub options: BTreeMap<String, LatencyOption>, pub curves: BTreeMap<String, PreconfirmationLatencyCurve>, pub attestations: BTreeMap<String, PqLaneAttestation>, pub reliability_scores: BTreeMap<String, ReliabilityScore>, pub rebate_settlements: BTreeMap<String, FeeRebateSettlement>, pub anti_replay_receipts: BTreeMap<String, AntiReplayReceipt>, pub seen_receipt_roots: BTreeSet<String>, pub events: VecDeque<String>, pub public_records: BTreeMap<String, PublicRecord> }

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            tickets: BTreeMap::new(),
            futures: BTreeMap::new(),
            options: BTreeMap::new(),
            curves: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reliability_scores: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
            anti_replay_receipts: BTreeMap::new(),
            seen_receipt_roots: BTreeSet::new(),
            events: VecDeque::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
    pub fn devnet() -> Self {
        devnet()
    }
    pub fn register_lane(&mut self, input: RegisterLaneInput) -> Result<()> {
        ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        ensure_unique(&self.lanes, "lane", &input.lane_id)?;
        ensure_non_empty("lane_id", &input.lane_id)?;
        ensure_non_empty("operator_commitment", &input.operator_commitment)?;
        ensure_bps("quorum_weight_bps", input.quorum_weight_bps)?;
        if input.privacy_set_size < self.config.min_privacy_set_size
            || input.privacy_set_size < input.lane_class.privacy_floor()
        {
            return Err("privacy set below lane floor".to_string());
        }
        if input.max_repair_ms < input.target_repair_ms {
            return Err("max_repair_ms must be >= target_repair_ms".to_string());
        }
        let lane = RepairLane {
            lane_id: input.lane_id.clone(),
            operator_commitment: input.operator_commitment,
            lane_class: input.lane_class,
            status: LaneStatus::Registered,
            pq_attestation_key_root: input.pq_attestation_key_root,
            lane_secret_commitment_root: input.lane_secret_commitment_root,
            capacity_commitment: input.capacity_commitment,
            fee_escrow_commitment: input.fee_escrow_commitment,
            privacy_set_size: input.privacy_set_size,
            quorum_weight_bps: input.quorum_weight_bps,
            reliability_bps: MAX_BPS,
            congestion_bps: 0,
            target_repair_ms: input.target_repair_ms,
            max_repair_ms: input.max_repair_ms,
            priority_fee_cap_micros: input.priority_fee_cap_micros,
            open_interest_limit_micros: input.open_interest_limit_micros,
            open_interest_micros: 0,
            active_ticket_count: 0,
            active_future_count: 0,
            active_option_count: 0,
            delivered_count: 0,
            late_count: 0,
            replay_fault_count: 0,
            last_attested_slot: 0,
            created_at_height: input.created_at_height,
            updated_at_height: input.created_at_height,
        };
        self.lanes.insert(input.lane_id, lane);
        self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        self.push_event("lane_registered");
        self.refresh_roots();
        Ok(())
    }
    pub fn set_lane_status(
        &mut self,
        lane_id: &str,
        status: LaneStatus,
        height: u64,
    ) -> Result<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("lane `{lane_id}` not found"))?;
        lane.status = status;
        lane.updated_at_height = height;
        self.push_event("lane_status_updated");
        self.refresh_roots();
        Ok(())
    }
    pub fn post_curve(&mut self, input: PostCurveInput) -> Result<()> {
        ensure_capacity(self.curves.len(), self.config.max_curves, "curves")?;
        ensure_unique(&self.curves, "curve", &input.curve_id)?;
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
        if !lane.accepts_work() {
            return Err("lane does not accept curves".to_string());
        }
        ensure_bps("min_reliability_bps", input.min_reliability_bps)?;
        ensure_bps("min_quorum_weight_bps", input.min_quorum_weight_bps)?;
        ensure_bps("slope_bps", input.slope_bps)?;
        ensure_bps("volatility_bps", input.volatility_bps)?;
        ensure_bps("privacy_discount_bps", input.privacy_discount_bps)?;
        ensure_bps("low_fee_discount_bps", input.low_fee_discount_bps)?;
        if input.valid_until_slot <= input.valid_from_slot {
            return Err("curve expiry must be after start".to_string());
        }
        let curve = PreconfirmationLatencyCurve {
            curve_id: input.curve_id.clone(),
            lane_id: input.lane_id,
            curve_kind: input.curve_kind,
            sealed_curve_root: input.sealed_curve_root,
            maker_commitment: input.maker_commitment,
            base_fee_micros: input.base_fee_micros,
            priority_fee_cap_micros: input
                .priority_fee_cap_micros
                .min(self.config.priority_fee_cap_micros),
            target_latency_ms: input.target_latency_ms,
            soft_latency_ms: input.soft_latency_ms,
            hard_latency_ms: input.hard_latency_ms,
            min_reliability_bps: input.min_reliability_bps,
            min_quorum_weight_bps: input.min_quorum_weight_bps,
            capacity_units: input.capacity_units,
            filled_units: 0,
            slope_bps: input.slope_bps,
            volatility_bps: input.volatility_bps,
            privacy_discount_bps: input.privacy_discount_bps,
            low_fee_discount_bps: input.low_fee_discount_bps,
            valid_from_slot: input.valid_from_slot,
            valid_until_slot: input.valid_until_slot,
            posted_at_height: input.posted_at_height,
            updated_at_height: input.posted_at_height,
        };
        self.curves.insert(input.curve_id, curve);
        self.counters.curves_posted = self.counters.curves_posted.saturating_add(1);
        self.push_event("curve_posted");
        self.refresh_roots();
        Ok(())
    }
    pub fn open_ticket(&mut self, input: OpenTicketInput) -> Result<()> {
        ensure_capacity(self.tickets.len(), self.config.max_tickets, "tickets")?;
        ensure_unique(&self.tickets, "ticket", &input.ticket_id)?;
        ensure_non_empty("ticket_commitment_root", &input.ticket_commitment_root)?;
        let matched_curve_id = {
            let lane = self
                .lanes
                .get(&input.lane_id)
                .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
            if !lane.accepts_work() {
                return Err("lane does not accept repair tickets".to_string());
            }
            if input.priority_fee_micros > lane.priority_fee_cap_micros
                || input.priority_fee_micros > self.config.priority_fee_cap_micros
            {
                return Err("priority fee cap exceeded".to_string());
            }
            let notional = input.notional_fee_micros as u128;
            if lane.available_open_interest() < notional {
                return Err("lane open interest exhausted".to_string());
            }
            self.best_curve_for(
                input.opened_slot,
                lane.lane_id.as_str(),
                input.repair_scope,
                input.notional_fee_micros,
            )
        };
        let lane = self
            .lanes
            .get_mut(&input.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("ticket privacy set below floor".to_string());
        }
        if input.expires_slot <= input.opened_slot {
            return Err("ticket expiry must be after open slot".to_string());
        }
        let notional = input.notional_fee_micros as u128;
        lane.open_interest_micros = lane.open_interest_micros.saturating_add(notional);
        lane.active_ticket_count = lane.active_ticket_count.saturating_add(1);
        lane.updated_at_height = input.created_at_height;
        let ticket = RepairTicketCommitment {
            ticket_id: input.ticket_id.clone(),
            lane_id: input.lane_id,
            owner_commitment: input.owner_commitment,
            repair_scope: input.repair_scope,
            ticket_commitment_root: input.ticket_commitment_root,
            sealed_witness_root: input.sealed_witness_root,
            nullifier_root: input.nullifier_root,
            fee_escrow_commitment: input.fee_escrow_commitment,
            notional_fee_micros: input.notional_fee_micros,
            priority_fee_micros: input.priority_fee_micros,
            target_latency_ms: input.target_latency_ms,
            max_latency_ms: input.max_latency_ms,
            privacy_set_size: input.privacy_set_size,
            opened_slot: input.opened_slot,
            expires_slot: input.expires_slot,
            delivered_slot: None,
            observed_latency_ms: None,
            matched_curve_id,
            matched_future_id: None,
            matched_option_id: None,
            anti_replay_receipt_id: None,
            status: TicketStatus::Open,
            settlement_root: None,
            created_at_height: input.created_at_height,
            updated_at_height: input.created_at_height,
        };
        self.counters.tickets_opened = self.counters.tickets_opened.saturating_add(1);
        self.counters.total_notional_micros = self
            .counters
            .total_notional_micros
            .saturating_add(input.notional_fee_micros as u128);
        self.update_peak_open_interest();
        self.tickets.insert(input.ticket_id, ticket);
        self.push_event("ticket_opened");
        self.refresh_roots();
        Ok(())
    }
    pub fn open_future(&mut self, input: OpenFutureInput) -> Result<()> {
        ensure_capacity(self.futures.len(), self.config.max_futures, "futures")?;
        ensure_unique(&self.futures, "future", &input.future_id)?;
        let ticket_scope = {
            let ticket = self
                .tickets
                .get(&input.ticket_id)
                .ok_or_else(|| format!("ticket `{}` not found", input.ticket_id))?;
            if ticket.lane_id != input.lane_id {
                return Err("future lane does not match ticket".to_string());
            }
            if !ticket.live() {
                return Err("future cannot attach to inactive ticket or lane".to_string());
            }
            ticket.repair_scope
        };
        let lane_view = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
        if !lane_view.accepts_work() {
            return Err("future cannot attach to inactive ticket or lane".to_string());
        }
        let matched_curve_id = self.best_curve_for(
            input.opened_slot,
            &input.lane_id,
            ticket_scope,
            input.notional_micros,
        );
        let ticket = self
            .tickets
            .get_mut(&input.ticket_id)
            .ok_or_else(|| format!("ticket `{}` not found", input.ticket_id))?;
        let lane = self
            .lanes
            .get_mut(&input.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
        ensure_bps("maker_rebate_bps", input.maker_rebate_bps)?;
        ensure_bps("taker_fee_bps", input.taker_fee_bps)?;
        if input.expires_slot <= input.opened_slot {
            return Err("future expiry must be after open slot".to_string());
        }
        if input.priority_fee_cap_micros > self.config.priority_fee_cap_micros {
            return Err("future priority fee cap exceeded".to_string());
        }
        let notional = input.notional_micros as u128;
        if lane.available_open_interest() < notional {
            return Err("lane open interest exhausted".to_string());
        }
        lane.open_interest_micros = lane.open_interest_micros.saturating_add(notional);
        lane.active_future_count = lane.active_future_count.saturating_add(1);
        lane.updated_at_height = input.created_at_height;
        ticket.status = TicketStatus::Hedged;
        ticket.matched_future_id = Some(input.future_id.clone());
        ticket.updated_at_height = input.created_at_height;
        let status = if matched_curve_id.is_some() {
            FutureStatus::CurveMatched
        } else {
            FutureStatus::Open
        };
        let future = LatencyFuture {
            future_id: input.future_id.clone(),
            ticket_id: input.ticket_id,
            lane_id: input.lane_id,
            side: input.side,
            maker_commitment: input.maker_commitment,
            taker_commitment: input.taker_commitment,
            sealed_terms_root: input.sealed_terms_root,
            margin_commitment: input.margin_commitment,
            notional_micros: input.notional_micros,
            target_latency_ms: input.target_latency_ms,
            max_latency_ms: input.max_latency_ms,
            strike_latency_ms: input.strike_latency_ms,
            premium_micros: input.premium_micros,
            priority_fee_cap_micros: input.priority_fee_cap_micros,
            maker_rebate_bps: input.maker_rebate_bps,
            taker_fee_bps: input.taker_fee_bps,
            opened_slot: input.opened_slot,
            expires_slot: input.expires_slot,
            matched_curve_id,
            attestation_id: None,
            settlement_id: None,
            status,
            created_at_height: input.created_at_height,
            updated_at_height: input.created_at_height,
        };
        self.counters.futures_opened = self.counters.futures_opened.saturating_add(1);
        self.counters.total_notional_micros = self
            .counters
            .total_notional_micros
            .saturating_add(input.notional_micros as u128);
        self.update_peak_open_interest();
        self.futures.insert(input.future_id, future);
        self.push_event("future_opened");
        self.refresh_roots();
        Ok(())
    }
    pub fn write_option(&mut self, input: WriteOptionInput) -> Result<()> {
        ensure_capacity(self.options.len(), self.config.max_options, "options")?;
        ensure_unique(&self.options, "option", &input.option_id)?;
        let ticket_scope = {
            let ticket = self
                .tickets
                .get(&input.ticket_id)
                .ok_or_else(|| format!("ticket `{}` not found", input.ticket_id))?;
            if ticket.lane_id != input.lane_id {
                return Err("option lane does not match ticket".to_string());
            }
            ticket.repair_scope
        };
        let matched_curve_id = self.best_curve_for(
            input.opened_slot,
            &input.lane_id,
            ticket_scope,
            input.notional_micros,
        );
        let ticket = self
            .tickets
            .get_mut(&input.ticket_id)
            .ok_or_else(|| format!("ticket `{}` not found", input.ticket_id))?;
        let lane = self
            .lanes
            .get_mut(&input.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
        if input.premium_micros < self.config.option_premium_floor_micros {
            return Err("option premium below floor".to_string());
        }
        if input.expires_slot <= input.opened_slot || input.exercise_start_slot < input.opened_slot
        {
            return Err("invalid option exercise window".to_string());
        }
        let notional = input.notional_micros as u128;
        if lane.available_open_interest() < notional {
            return Err("lane open interest exhausted".to_string());
        }
        lane.open_interest_micros = lane.open_interest_micros.saturating_add(notional);
        lane.active_option_count = lane.active_option_count.saturating_add(1);
        ticket.matched_option_id = Some(input.option_id.clone());
        ticket.updated_at_height = input.created_at_height;
        let status = if matched_curve_id.is_some() {
            OptionStatus::CurveMatched
        } else {
            OptionStatus::Open
        };
        let option = LatencyOption {
            option_id: input.option_id.clone(),
            ticket_id: input.ticket_id,
            lane_id: input.lane_id,
            option_kind: input.option_kind,
            writer_commitment: input.writer_commitment,
            holder_commitment: input.holder_commitment,
            sealed_terms_root: input.sealed_terms_root,
            collateral_commitment: input.collateral_commitment,
            notional_micros: input.notional_micros,
            premium_micros: input.premium_micros,
            strike_latency_ms: input.strike_latency_ms,
            barrier_latency_ms: input.barrier_latency_ms,
            max_payout_micros: input.max_payout_micros,
            rebate_floor_micros: input.rebate_floor_micros,
            opened_slot: input.opened_slot,
            exercise_start_slot: input.exercise_start_slot,
            expires_slot: input.expires_slot,
            matched_curve_id,
            exercise_receipt_id: None,
            settlement_id: None,
            status,
            created_at_height: input.created_at_height,
            updated_at_height: input.created_at_height,
        };
        self.counters.options_written = self.counters.options_written.saturating_add(1);
        self.counters.total_notional_micros = self
            .counters
            .total_notional_micros
            .saturating_add(input.notional_micros as u128);
        self.update_peak_open_interest();
        self.options.insert(input.option_id, option);
        self.push_event("option_written");
        self.refresh_roots();
        Ok(())
    }
    pub fn record_receipt(&mut self, input: RecordReceiptInput) -> Result<ReceiptStatus> {
        ensure_capacity(
            self.anti_replay_receipts.len(),
            self.config.max_receipts,
            "anti replay receipts",
        )?;
        ensure_unique(&self.anti_replay_receipts, "receipt", &input.receipt_id)?;
        ensure_non_empty("nullifier_root", &input.nullifier_root)?;
        let receipt_root = domain_hash(
            D_RECEIPTS,
            &[
                HashPart::from(input.lane_id.as_str()),
                HashPart::from(input.nullifier_root.as_str()),
                HashPart::from(input.nonce_commitment_root.as_str()),
                HashPart::from(input.transcript_root.as_str()),
                HashPart::from(input.first_seen_slot),
            ],
        );
        let status = if self.seen_receipt_roots.contains(&receipt_root) {
            self.counters.duplicate_replay_receipts =
                self.counters.duplicate_replay_receipts.saturating_add(1);
            ReceiptStatus::Duplicate
        } else {
            self.seen_receipt_roots.insert(receipt_root.clone());
            self.counters.anti_replay_receipts_recorded = self
                .counters
                .anti_replay_receipts_recorded
                .saturating_add(1);
            ReceiptStatus::Fresh
        };
        let receipt = AntiReplayReceipt {
            receipt_id: input.receipt_id.clone(),
            lane_id: input.lane_id,
            ticket_id: input.ticket_id,
            derivative_id: input.derivative_id,
            nullifier_root: input.nullifier_root,
            nonce_commitment_root: input.nonce_commitment_root,
            transcript_root: input.transcript_root,
            receipt_root,
            status,
            first_seen_slot: input.first_seen_slot,
            expires_slot: input.expires_slot,
            recorded_at_height: input.recorded_at_height,
        };
        self.anti_replay_receipts.insert(input.receipt_id, receipt);
        self.push_event("anti_replay_receipt_recorded");
        self.refresh_roots();
        Ok(status)
    }
    pub fn record_attestation(&mut self, input: RecordAttestationInput) -> Result<()> {
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        ensure_unique(&self.attestations, "attestation", &input.attestation_id)?;
        let lane = self
            .lanes
            .get_mut(&input.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
        if !lane.status.accepts_attestations() {
            return Err("lane does not accept attestations".to_string());
        }
        ensure_bps("claimed_reliability_bps", input.claimed_reliability_bps)?;
        ensure_bps("claimed_quorum_weight_bps", input.claimed_quorum_weight_bps)?;
        lane.last_attested_slot = lane.last_attested_slot.max(input.issued_slot);
        lane.reliability_bps = weighted_average_bps(&[
            (lane.reliability_bps, 3),
            (input.claimed_reliability_bps, 1),
        ]);
        lane.quorum_weight_bps = lane.quorum_weight_bps.max(input.claimed_quorum_weight_bps);
        lane.privacy_set_size = lane.privacy_set_size.max(input.claimed_privacy_set_size);
        lane.updated_at_height = input.issued_at_height;
        let attestation = PqLaneAttestation {
            attestation_id: input.attestation_id.clone(),
            lane_id: input.lane_id,
            ticket_id: input.ticket_id,
            derivative_id: input.derivative_id,
            attestation_kind: input.attestation_kind,
            attestor_commitment: input.attestor_commitment,
            pq_signature_root: input.pq_signature_root,
            transcript_root: input.transcript_root,
            anti_replay_nonce_root: input.anti_replay_nonce_root,
            claimed_latency_ms: input.claimed_latency_ms,
            claimed_reliability_bps: input.claimed_reliability_bps,
            claimed_quorum_weight_bps: input.claimed_quorum_weight_bps,
            claimed_privacy_set_size: input.claimed_privacy_set_size,
            issued_slot: input.issued_slot,
            expires_slot: input.expires_slot,
            issued_at_height: input.issued_at_height,
        };
        self.attestations.insert(input.attestation_id, attestation);
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.push_event("pq_attestation_recorded");
        self.refresh_roots();
        Ok(())
    }
    pub fn record_delivery(&mut self, input: RecordDeliveryInput) -> Result<()> {
        if !self.anti_replay_receipts.contains_key(&input.receipt_id) {
            return Err("missing anti-replay receipt".to_string());
        }
        if !self.attestations.contains_key(&input.attestation_id) {
            return Err("missing delivery attestation".to_string());
        }
        let ticket = self
            .tickets
            .get_mut(&input.ticket_id)
            .ok_or_else(|| format!("ticket `{}` not found", input.ticket_id))?;
        let lane = self
            .lanes
            .get_mut(&input.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", input.lane_id))?;
        if ticket.lane_id != input.lane_id {
            return Err("delivery lane mismatch".to_string());
        }
        ticket.observed_latency_ms = Some(input.observed_latency_ms);
        ticket.delivered_slot = Some(input.delivered_slot);
        ticket.anti_replay_receipt_id = Some(input.receipt_id);
        ticket.status = if input.observed_latency_ms <= ticket.max_latency_ms {
            TicketStatus::Delivered
        } else {
            TicketStatus::Late
        };
        ticket.updated_at_height = input.updated_at_height;
        lane.delivered_count = lane.delivered_count.saturating_add(1);
        if input.observed_latency_ms > ticket.max_latency_ms {
            lane.late_count = lane.late_count.saturating_add(1);
            self.counters.total_penalty_micros = self.counters.total_penalty_micros.saturating_add(
                ticket
                    .notional_fee_micros
                    .saturating_mul(self.config.late_repair_penalty_bps)
                    .saturating_div(MAX_BPS) as u128,
            );
        }
        self.counters.tickets_delivered = self.counters.tickets_delivered.saturating_add(1);
        self.mark_derivatives_delivered(
            &input.ticket_id,
            input.observed_latency_ms,
            input.updated_at_height,
        );
        self.record_reliability_for_lane(
            &input.lane_id,
            input.delivered_slot,
            input.updated_at_height,
        )?;
        self.push_event("ticket_delivered");
        self.refresh_roots();
        Ok(())
    }
    pub fn settle(&mut self, input: SettleInput) -> Result<FeeRebateSettlement> {
        ensure_capacity(
            self.rebate_settlements.len(),
            self.config.max_rebate_settlements,
            "rebate settlements",
        )?;
        ensure_unique(&self.rebate_settlements, "settlement", &input.settlement_id)?;
        let ticket = self
            .tickets
            .get(&input.ticket_id)
            .ok_or_else(|| format!("ticket `{}` not found", input.ticket_id))?
            .clone();
        let lane = self
            .lanes
            .get(&ticket.lane_id)
            .ok_or_else(|| format!("lane `{}` not found", ticket.lane_id))?
            .clone();
        if !matches!(ticket.status, TicketStatus::Delivered | TicketStatus::Late) {
            return Err("ticket must be delivered or late before settlement".to_string());
        }
        let observed = ticket.observed_latency_ms.unwrap_or(ticket.max_latency_ms);
        let future_payoff = input
            .future_id
            .as_ref()
            .and_then(|id| self.futures.get(id))
            .map(|future| future.payoff_micros(observed))
            .unwrap_or(0);
        let option_payout = input
            .option_id
            .as_ref()
            .and_then(|id| self.options.get(id))
            .map(|option| option.intrinsic_value_micros(observed))
            .unwrap_or(0);
        let score = self.latest_score_for_lane(&ticket.lane_id);
        let pricing = self.compute_settlement_pricing(
            &ticket,
            &lane,
            score.as_ref(),
            future_payoff,
            option_payout,
        );
        let settlement_commitment_root = domain_hash(
            D_REBATES,
            &[
                HashPart::from(input.settlement_id.as_str()),
                HashPart::from(input.ticket_id.as_str()),
                HashPart::from(ticket.ticket_commitment_root.as_str()),
                HashPart::from(pricing.net_settlement_micros),
                HashPart::from(input.settlement_slot),
            ],
        );
        let settlement = FeeRebateSettlement {
            settlement_id: input.settlement_id.clone(),
            lane_id: ticket.lane_id.clone(),
            ticket_id: input.ticket_id.clone(),
            future_id: input.future_id.clone(),
            option_id: input.option_id.clone(),
            score_id: score.map(|s| s.score_id),
            payer_commitment: input.payer_commitment,
            receiver_commitment: input.receiver_commitment,
            gross_fee_micros: pricing.gross_fee_micros,
            maker_rebate_micros: pricing.maker_rebate_micros,
            low_fee_rebate_micros: pricing.low_fee_rebate_micros,
            privacy_rebate_micros: pricing.privacy_rebate_micros,
            reliability_rebate_micros: pricing.reliability_rebate_micros,
            option_payout_micros: pricing.option_payout_micros,
            late_penalty_micros: pricing.late_penalty_micros,
            replay_penalty_micros: pricing.replay_penalty_micros,
            taker_fee_micros: pricing.taker_fee_micros,
            net_settlement_micros: pricing.net_settlement_micros,
            settlement_commitment_root,
            status: SettlementStatus::Settled,
            settlement_slot: input.settlement_slot,
            recorded_at_height: input.recorded_at_height,
        };
        self.rebate_settlements
            .insert(input.settlement_id.clone(), settlement.clone());
        if let Some(ticket_mut) = self.tickets.get_mut(&input.ticket_id) {
            ticket_mut.status = TicketStatus::Settled;
            ticket_mut.settlement_root = Some(settlement.settlement_commitment_root.clone());
            ticket_mut.updated_at_height = input.recorded_at_height;
        }
        if let Some(id) = input.future_id {
            if let Some(future) = self.futures.get_mut(&id) {
                future.status = FutureStatus::Settled;
                future.settlement_id = Some(input.settlement_id.clone());
                future.updated_at_height = input.recorded_at_height;
                self.counters.futures_settled = self.counters.futures_settled.saturating_add(1);
            }
        }
        if let Some(id) = input.option_id {
            if let Some(option) = self.options.get_mut(&id) {
                option.status = OptionStatus::Settled;
                option.settlement_id = Some(input.settlement_id.clone());
                option.updated_at_height = input.recorded_at_height;
            }
        }
        if let Some(lane_mut) = self.lanes.get_mut(&ticket.lane_id) {
            lane_mut.open_interest_micros = lane_mut
                .open_interest_micros
                .saturating_sub(ticket.notional_fee_micros as u128);
            lane_mut.active_ticket_count = lane_mut.active_ticket_count.saturating_sub(1);
            lane_mut.updated_at_height = input.recorded_at_height;
        }
        self.counters.tickets_settled = self.counters.tickets_settled.saturating_add(1);
        self.counters.rebate_settlements_recorded =
            self.counters.rebate_settlements_recorded.saturating_add(1);
        self.counters.total_rebate_micros = self.counters.total_rebate_micros.saturating_add(
            (pricing.maker_rebate_micros
                + pricing.low_fee_rebate_micros
                + pricing.privacy_rebate_micros
                + pricing.reliability_rebate_micros) as u128,
        );
        self.counters.total_priority_fee_micros = self
            .counters
            .total_priority_fee_micros
            .saturating_add(ticket.priority_fee_micros as u128);
        self.push_event("settlement_recorded");
        self.refresh_roots();
        Ok(settlement)
    }
    pub fn expire_positions(&mut self, slot: u64, height: u64) -> u64 {
        let mut expired = 0u64;
        for ticket in self.tickets.values_mut() {
            if ticket.is_expired(slot) {
                ticket.status = TicketStatus::Expired;
                ticket.updated_at_height = height;
                expired = expired.saturating_add(1);
            }
        }
        for future in self.futures.values_mut() {
            if future.is_expired(slot) {
                future.status = FutureStatus::Expired;
                future.updated_at_height = height;
                expired = expired.saturating_add(1);
            }
        }
        for option in self.options.values_mut() {
            if option.is_expired(slot) {
                option.status = OptionStatus::Expired;
                option.updated_at_height = height;
                expired = expired.saturating_add(1);
            }
        }
        for receipt in self.anti_replay_receipts.values_mut() {
            if slot > receipt.expires_slot
                && matches!(
                    receipt.status,
                    ReceiptStatus::Fresh | ReceiptStatus::Accepted
                )
            {
                receipt.status = ReceiptStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        self.counters.expired_positions = self.counters.expired_positions.saturating_add(expired);
        if expired > 0 {
            self.push_event("positions_expired");
            self.refresh_roots();
        }
        expired
    }
    pub fn public_record(&mut self, height: u64, epoch: u64) -> Result<PublicRecord> {
        ensure_capacity(
            self.public_records.len(),
            self.config.max_public_records,
            "public records",
        )?;
        self.counters.last_height = height;
        self.counters.last_epoch = epoch;
        self.refresh_roots();
        let mut record = PublicRecord {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: self.config.l2_network.clone(),
            height,
            epoch,
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            latency_derivatives_suite: LATENCY_DERIVATIVES_SUITE.to_string(),
            pq_lane_attestation_suite: PQ_LANE_ATTESTATION_SUITE.to_string(),
            repair_ticket_commitment_suite: REPAIR_TICKET_COMMITMENT_SUITE.to_string(),
            preconfirmation_latency_curve_suite: PRECONFIRMATION_LATENCY_CURVE_SUITE.to_string(),
            fee_rebate_settlement_suite: FEE_REBATE_SETTLEMENT_SUITE.to_string(),
            anti_replay_receipt_suite: ANTI_REPLAY_RECEIPT_SUITE.to_string(),
            roots: self.roots.clone(),
            counters: self.counters.clone(),
            lane_count: self.lanes.len(),
            ticket_count: self.tickets.len(),
            future_count: self.futures.len(),
            option_count: self.options.len(),
            curve_count: self.curves.len(),
            attestation_count: self.attestations.len(),
            reliability_score_count: self.reliability_scores.len(),
            rebate_settlement_count: self.rebate_settlements.len(),
            anti_replay_receipt_count: self.anti_replay_receipts.len(),
            record_root: String::new(),
        };
        record.record_root = canonical_root(
            D_PUBLIC,
            &json!({"protocol_version": record.protocol_version, "height": height, "epoch": epoch, "roots": record.roots, "counters": record.counters, "privacy_boundary": record.privacy_boundary}),
        );
        let key = domain_hash(
            D_PUBLIC,
            &[
                HashPart::from(height),
                HashPart::from(epoch),
                HashPart::from(record.record_root.as_str()),
            ],
        );
        self.public_records.insert(key, record.clone());
        self.counters.public_records_emitted =
            self.counters.public_records_emitted.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }
    pub fn public_record_value(&mut self, height: u64, epoch: u64) -> Result<Value> {
        self.public_record(height, epoch)
            .map(|record| json!(record))
    }
    pub fn state_root(&self) -> String {
        canonical_root(
            D_STATE,
            &json!({"protocol_version": PROTOCOL_VERSION, "roots": self.roots, "counters": self.counters, "privacy_boundary": PRIVACY_BOUNDARY}),
        )
    }
    pub fn refresh_roots(&mut self) {
        self.roots.config_root = canonical_root(D_CONFIG, &self.config);
        self.roots.counters_root = canonical_root(D_COUNTERS, &self.counters);
        self.roots.lanes_root = map_root(D_LANES, &self.lanes);
        self.roots.ticket_commitments_root = map_root(D_TICKETS, &self.tickets);
        self.roots.latency_futures_root = map_root(D_FUTURES, &self.futures);
        self.roots.latency_options_root = map_root(D_OPTIONS, &self.options);
        self.roots.preconfirmation_curves_root = map_root(D_CURVES, &self.curves);
        self.roots.pq_attestations_root = map_root(D_ATTESTATIONS, &self.attestations);
        self.roots.reliability_scores_root = map_root(D_SCORES, &self.reliability_scores);
        self.roots.fee_rebate_settlements_root = map_root(D_REBATES, &self.rebate_settlements);
        self.roots.anti_replay_receipts_root = map_root(D_RECEIPTS, &self.anti_replay_receipts);
        self.roots.event_root = deque_root(D_EVENTS, &self.events);
        self.roots.public_records_root = map_root(D_PUBLIC, &self.public_records);
        self.roots.state_root = self.state_root();
    }
    fn best_curve_for(
        &self,
        slot: u64,
        lane_id: &str,
        scope: WitnessRepairScope,
        notional_micros: u64,
    ) -> Option<String> {
        let lane = self.lanes.get(lane_id)?;
        self.curves
            .values()
            .filter(|curve| curve.lane_id == lane_id && curve.accepts(slot, lane, notional_micros))
            .min_by_key(|curve| curve.quote_fee_micros(scope, lane, 0))
            .map(|curve| curve.curve_id.clone())
    }
    fn mark_derivatives_delivered(
        &mut self,
        ticket_id: &str,
        observed_latency_ms: u64,
        height: u64,
    ) {
        for future in self
            .futures
            .values_mut()
            .filter(|future| future.ticket_id == ticket_id && future.live())
        {
            future.status = if observed_latency_ms <= future.max_latency_ms {
                FutureStatus::Delivered
            } else {
                FutureStatus::Late
            };
            future.updated_at_height = height;
        }
        for option in self
            .options
            .values_mut()
            .filter(|option| option.ticket_id == ticket_id && option.live())
        {
            option.status = if observed_latency_ms >= option.strike_latency_ms
                || observed_latency_ms <= option.strike_latency_ms
            {
                OptionStatus::Exercisable
            } else {
                OptionStatus::Expired
            };
            option.updated_at_height = height;
        }
    }
    fn record_reliability_for_lane(&mut self, lane_id: &str, slot: u64, height: u64) -> Result<()> {
        ensure_capacity(
            self.reliability_scores.len(),
            self.config.max_reliability_scores,
            "reliability scores",
        )?;
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| format!("lane `{lane_id}` not found"))?
            .clone();
        let mut latencies = self
            .tickets
            .values()
            .filter(|ticket| ticket.lane_id == lane_id)
            .filter_map(|ticket| ticket.observed_latency_ms)
            .collect::<Vec<_>>();
        latencies.sort_unstable();
        let tickets_observed = self
            .tickets
            .values()
            .filter(|ticket| ticket.lane_id == lane_id && ticket.delivered_slot.is_some())
            .count() as u64;
        let delivered_count = lane.delivered_count;
        let late_count = lane.late_count;
        let median_latency_ms = percentile(&latencies, 50).unwrap_or(lane.target_repair_ms);
        let p95_latency_ms = percentile(&latencies, 95).unwrap_or(lane.max_repair_ms);
        let delivery_score_bps = if tickets_observed == 0 {
            MAX_BPS
        } else {
            delivered_count
                .saturating_sub(late_count)
                .saturating_mul(MAX_BPS)
                .saturating_div(tickets_observed)
        };
        let latency_score = latency_score_bps(p95_latency_ms, lane.target_repair_ms);
        let replay_score =
            MAX_BPS.saturating_sub(lane.replay_fault_count.saturating_mul(500).min(MAX_BPS));
        let privacy_score = if lane.privacy_set_size >= self.config.target_privacy_set_size {
            MAX_BPS
        } else {
            lane.privacy_set_size
                .saturating_mul(MAX_BPS)
                .saturating_div(self.config.target_privacy_set_size.max(1))
        };
        let fee_score = MAX_BPS.saturating_sub(
            lane.priority_fee_cap_micros
                .saturating_mul(MAX_BPS)
                .saturating_div(self.config.priority_fee_cap_micros.max(1))
                .min(MAX_BPS),
        );
        let aggregate_score_bps = weighted_average_bps(&[
            (delivery_score_bps, 35),
            (latency_score, 25),
            (replay_score, 15),
            (privacy_score, 15),
            (fee_score, 10),
        ]);
        let score_id = domain_hash(
            D_SCORES,
            &[
                HashPart::from(lane_id),
                HashPart::from(slot),
                HashPart::from(height),
                HashPart::from(aggregate_score_bps),
            ],
        );
        let score_root = domain_hash(
            D_SCORES,
            &[
                HashPart::from(score_id.as_str()),
                HashPart::from(lane_id),
                HashPart::from(aggregate_score_bps),
                HashPart::from(p95_latency_ms),
            ],
        );
        let score = ReliabilityScore {
            score_id: score_id.clone(),
            lane_id: lane_id.to_string(),
            window_start_slot: slot.saturating_sub(self.config.score_window_slots),
            window_end_slot: slot,
            tickets_observed,
            delivered_count,
            late_count,
            replay_fault_count: lane.replay_fault_count,
            median_latency_ms,
            p95_latency_ms,
            target_latency_ms: lane.target_repair_ms,
            delivery_score_bps,
            latency_score_bps: latency_score,
            replay_score_bps: replay_score,
            privacy_score_bps: privacy_score,
            fee_score_bps: fee_score,
            aggregate_score_bps,
            score_root,
            recorded_at_height: height,
        };
        if let Some(lane_mut) = self.lanes.get_mut(lane_id) {
            lane_mut.reliability_bps = aggregate_score_bps;
            lane_mut.congestion_bps =
                congestion_from_latency(p95_latency_ms, lane_mut.target_repair_ms);
            lane_mut.updated_at_height = height;
        }
        self.reliability_scores.insert(score_id, score);
        self.counters.reliability_scores_recorded =
            self.counters.reliability_scores_recorded.saturating_add(1);
        Ok(())
    }
    fn latest_score_for_lane(&self, lane_id: &str) -> Option<ReliabilityScore> {
        self.reliability_scores
            .values()
            .filter(|score| score.lane_id == lane_id)
            .max_by_key(|score| score.window_end_slot)
            .cloned()
    }
    fn compute_settlement_pricing(
        &self,
        ticket: &RepairTicketCommitment,
        lane: &RepairLane,
        score: Option<&ReliabilityScore>,
        future_payoff: u64,
        option_payout: u64,
    ) -> SettlementPricing {
        let curve_fee = ticket
            .notional_fee_micros
            .saturating_mul(ticket.repair_scope.complexity_weight())
            .saturating_div(1_000)
            .saturating_mul(lane.lane_class.priority_weight())
            .saturating_div(MAX_BPS);
        let gross_fee_micros = curve_fee
            .saturating_add(ticket.priority_fee_micros)
            .saturating_add(self.config.base_settlement_fee_micros)
            .saturating_add(future_payoff);
        let maker_rebate_micros = gross_fee_micros
            .saturating_mul(self.config.maker_rebate_bps)
            .saturating_div(MAX_BPS);
        let low_fee_rebate_micros = gross_fee_micros
            .saturating_mul(lane.low_fee_bonus_bps(&self.config))
            .saturating_div(MAX_BPS);
        let privacy_rebate_micros = gross_fee_micros
            .saturating_mul(lane.privacy_bonus_bps(&self.config))
            .saturating_div(MAX_BPS);
        let reliability_bps = score
            .map(|s| s.aggregate_score_bps)
            .unwrap_or(lane.reliability_bps);
        let reliability_rebate_micros = if reliability_bps >= self.config.min_reliability_bps {
            gross_fee_micros
                .saturating_mul(reliability_bps.saturating_sub(self.config.min_reliability_bps))
                .saturating_div(MAX_BPS)
                .saturating_div(10)
        } else {
            0
        };
        let late_penalty_micros = if ticket.observed_latency_ms.unwrap_or(ticket.max_latency_ms)
            > ticket.max_latency_ms
        {
            gross_fee_micros
                .saturating_mul(self.config.late_repair_penalty_bps)
                .saturating_div(MAX_BPS)
        } else {
            0
        };
        let replay_penalty_micros = if ticket.anti_replay_receipt_id.is_none() {
            gross_fee_micros
                .saturating_mul(self.config.replay_penalty_bps)
                .saturating_div(MAX_BPS)
        } else {
            0
        };
        let taker_fee_micros = gross_fee_micros
            .saturating_mul(self.config.taker_fee_bps)
            .saturating_div(MAX_BPS);
        let net_settlement_micros = gross_fee_micros
            .saturating_add(taker_fee_micros)
            .saturating_add(late_penalty_micros)
            .saturating_add(replay_penalty_micros)
            .saturating_add(option_payout)
            .saturating_sub(maker_rebate_micros)
            .saturating_sub(low_fee_rebate_micros)
            .saturating_sub(privacy_rebate_micros)
            .saturating_sub(reliability_rebate_micros);
        SettlementPricing {
            gross_fee_micros,
            maker_rebate_micros,
            low_fee_rebate_micros,
            privacy_rebate_micros,
            reliability_rebate_micros,
            option_payout_micros: option_payout,
            late_penalty_micros,
            replay_penalty_micros,
            taker_fee_micros,
            net_settlement_micros,
        }
    }
    fn update_peak_open_interest(&mut self) {
        let open = self
            .lanes
            .values()
            .map(|lane| lane.open_interest_micros)
            .sum::<u128>();
        self.counters.peak_open_interest_micros = self.counters.peak_open_interest_micros.max(open);
    }
    fn push_event(&mut self, event: &str) {
        if self.events.len() >= 512 {
            self.events.pop_front();
        }
        self.events.push_back(domain_hash(
            D_EVENTS,
            &[
                HashPart::from(event),
                HashPart::from(self.events.len() as u64),
                HashPart::from(self.counters.last_height),
            ],
        ));
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct SettlementPricing {
    gross_fee_micros: u64,
    maker_rebate_micros: u64,
    low_fee_rebate_micros: u64,
    privacy_rebate_micros: u64,
    reliability_rebate_micros: u64,
    option_payout_micros: u64,
    late_penalty_micros: u64,
    replay_penalty_micros: u64,
    taker_fee_micros: u64,
    net_settlement_micros: u64,
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let lane_id = "devnet-witness-repair-latency-derivatives-lane-0".to_string();
    state
        .register_lane(RegisterLaneInput {
            lane_id: lane_id.clone(),
            operator_commitment: devnet_commitment("operator", 0),
            lane_class: RepairLaneClass::StateOracle,
            pq_attestation_key_root: devnet_commitment("pq-key-root", 0),
            lane_secret_commitment_root: devnet_commitment("lane-secret-root", 0),
            capacity_commitment: devnet_commitment("capacity", 0),
            fee_escrow_commitment: devnet_commitment("fee-escrow", 0),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            quorum_weight_bps: DEFAULT_STRONG_QUORUM_WEIGHT_BPS,
            target_repair_ms: DEFAULT_TARGET_REPAIR_MS,
            max_repair_ms: DEFAULT_SOFT_REPAIR_MS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            open_interest_limit_micros: 4_000_000_000,
            created_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet lane must register");
    state
        .set_lane_status(&lane_id, LaneStatus::Hot, DEVNET_HEIGHT)
        .expect("devnet lane status must update");
    state
        .post_curve(PostCurveInput {
            curve_id: "devnet-witness-repair-latency-curve-0".to_string(),
            lane_id: lane_id.clone(),
            curve_kind: CurveKind::ReliabilityWeighted,
            sealed_curve_root: devnet_commitment("sealed-curve", 0),
            maker_commitment: devnet_commitment("maker", 0),
            base_fee_micros: DEFAULT_BASE_SETTLEMENT_FEE_MICROS,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            target_latency_ms: DEFAULT_TARGET_REPAIR_MS,
            soft_latency_ms: DEFAULT_SOFT_REPAIR_MS,
            hard_latency_ms: DEFAULT_HARD_REPAIR_MS,
            min_reliability_bps: DEFAULT_MIN_RELIABILITY_BPS,
            min_quorum_weight_bps: DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            capacity_units: 16_384,
            slope_bps: 320,
            volatility_bps: 450,
            privacy_discount_bps: DEFAULT_PRIVACY_BONUS_BPS,
            low_fee_discount_bps: DEFAULT_LOW_FEE_BONUS_BPS,
            valid_from_slot: DEVNET_EPOCH,
            valid_until_slot: DEVNET_EPOCH + DEFAULT_CURVE_TTL_SLOTS,
            posted_at_height: DEVNET_HEIGHT,
        })
        .expect("devnet curve must post");
    state
        .open_ticket(OpenTicketInput {
            ticket_id: "devnet-witness-repair-ticket-0".to_string(),
            lane_id: lane_id.clone(),
            owner_commitment: devnet_commitment("owner", 0),
            repair_scope: WitnessRepairScope::StateRootDelta,
            ticket_commitment_root: devnet_commitment("ticket", 0),
            sealed_witness_root: devnet_commitment("sealed-witness", 0),
            nullifier_root: devnet_commitment("nullifier", 0),
            fee_escrow_commitment: devnet_commitment("ticket-fee", 0),
            notional_fee_micros: 25_000,
            priority_fee_micros: 7,
            target_latency_ms: DEFAULT_TARGET_REPAIR_MS,
            max_latency_ms: DEFAULT_SOFT_REPAIR_MS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            opened_slot: DEVNET_EPOCH + 1,
            expires_slot: DEVNET_EPOCH + DEFAULT_FUTURE_TTL_SLOTS,
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet ticket must open");
    state
        .open_future(OpenFutureInput {
            future_id: "devnet-witness-repair-latency-future-0".to_string(),
            ticket_id: "devnet-witness-repair-ticket-0".to_string(),
            lane_id: lane_id.clone(),
            side: FutureSide::HedgeLatency,
            maker_commitment: devnet_commitment("future-maker", 0),
            taker_commitment: devnet_commitment("future-taker", 0),
            sealed_terms_root: devnet_commitment("future-terms", 0),
            margin_commitment: devnet_commitment("future-margin", 0),
            notional_micros: 25_000,
            target_latency_ms: DEFAULT_TARGET_REPAIR_MS,
            max_latency_ms: DEFAULT_HARD_REPAIR_MS,
            strike_latency_ms: DEFAULT_SOFT_REPAIR_MS,
            premium_micros: 11,
            priority_fee_cap_micros: DEFAULT_PRIORITY_FEE_CAP_MICROS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            opened_slot: DEVNET_EPOCH + 1,
            expires_slot: DEVNET_EPOCH + DEFAULT_FUTURE_TTL_SLOTS,
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet future must open");
    state
        .write_option(WriteOptionInput {
            option_id: "devnet-witness-repair-latency-option-0".to_string(),
            ticket_id: "devnet-witness-repair-ticket-0".to_string(),
            lane_id,
            option_kind: OptionKind::PutOnLateRepair,
            writer_commitment: devnet_commitment("option-writer", 0),
            holder_commitment: devnet_commitment("option-holder", 0),
            sealed_terms_root: devnet_commitment("option-terms", 0),
            collateral_commitment: devnet_commitment("option-collateral", 0),
            notional_micros: 20_000,
            premium_micros: DEFAULT_OPTION_PREMIUM_FLOOR_MICROS,
            strike_latency_ms: DEFAULT_SOFT_REPAIR_MS,
            barrier_latency_ms: DEFAULT_HARD_REPAIR_MS,
            max_payout_micros: 5_000,
            rebate_floor_micros: 3,
            opened_slot: DEVNET_EPOCH + 1,
            exercise_start_slot: DEVNET_EPOCH + 2,
            expires_slot: DEVNET_EPOCH + DEFAULT_OPTION_TTL_SLOTS,
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("devnet option must write");
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
fn congestion_from_latency(p95_latency_ms: u64, target_latency_ms: u64) -> u64 {
    if p95_latency_ms <= target_latency_ms {
        0
    } else {
        p95_latency_ms
            .saturating_sub(target_latency_ms)
            .saturating_mul(MAX_BPS)
            .saturating_div(target_latency_ms.max(1))
            .min(MAX_BPS)
    }
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
fn percentile(values: &[u64], pct: u64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let idx = ((values.len().saturating_sub(1)) as u64)
        .saturating_mul(pct.min(100))
        .saturating_div(100) as usize;
    values.get(idx).copied()
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
fn deque_root(domain: &'static str, events: &VecDeque<String>) -> String {
    if events.is_empty() {
        return empty_root(domain);
    }
    merkle_root(
        domain,
        events.iter().map(|event| HashPart::from(event.as_str())),
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
