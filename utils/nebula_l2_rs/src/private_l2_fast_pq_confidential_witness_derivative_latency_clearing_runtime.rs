use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialWitnessDerivativeLatencyClearingRuntimeResult<T> = Result<T>;
pub type Runtime = State;
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DERIVATIVE_LATENCY_CLEARING_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-fast-pq-confidential-witness-derivative-latency-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_DERIVATIVE_LATENCY_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1440000;
pub const DEVNET_EPOCH: u64 = 77;
pub const MAX_BPS: u64 = 10000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65536;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_FEE_BPS: u64 = 22;
pub const DEFAULT_REBATE_BPS: u64 = 35;
pub const DEFAULT_RELIABILITY_FLOOR_BPS: u64 = 8200;
pub const DEFAULT_SLIPPAGE_FLOOR_BPS: u64 = 15;
pub const DEFAULT_SLIPPAGE_CAP_BPS: u64 = 240;
pub const DEFAULT_MAX_LANES: usize = 131072;
pub const DEFAULT_MAX_BOOKS: usize = 262144;
pub const DEFAULT_MAX_TICKETS: usize = 1048576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 1048576;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_witnesses_addresses_view_keys_ticket_payloads_or_secret_keys";
pub const REBATE_SETTLEMENT_SCHEME: &str = "low-fee-witness-repair-rebate-settlement-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-witness-lane-attestation-root-v1";
pub const ANTI_REPLAY_RECEIPT_SCHEME: &str =
    "anti-replay-witness-derivative-receipt-nullifier-root-v1";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-public-witness-derivative-latency-clearing-record-v1";
pub const DERIVATIVE_BOOK_SCHEME: &str =
    "roots-only-private-witness-latency-derivative-book-root-v1";
pub const TICKET_COMMITMENT_SCHEME: &str = "ml-kem-1024-sealed-repair-ticket-commitment-root-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CLEARING_CURVE_SCHEME: &str = "confidential-witness-latency-clearing-curve-root-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    EmergencyRepair,
    FastPreconfirmation,
    BridgeExitWitness,
    ContractWitness,
    DaBlobRepair,
    WalletRecovery,
    AuditBackfill,
    BulkLowFee,
}
impl LaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmergencyRepair => "emergency_repair",
            Self::FastPreconfirmation => "fast_preconfirmation",
            Self::BridgeExitWitness => "bridge_exit_witness",
            Self::ContractWitness => "contract_witness",
            Self::DaBlobRepair => "da_blob_repair",
            Self::WalletRecovery => "wallet_recovery",
            Self::AuditBackfill => "audit_backfill",
            Self::BulkLowFee => "bulk_low_fee",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Guarded,
    Congested,
    RepairOnly,
    Paused,
    Draining,
    Sealed,
}
impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Guarded => "guarded",
            Self::Congested => "congested",
            Self::RepairOnly => "repair_only",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Sealed => "sealed",
        }
    }
    pub fn accepts_tickets(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Guarded | Self::Congested | Self::RepairOnly
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeKind {
    LatencyFuture,
    RepairSlaSwap,
    WitnessDelayOption,
    PreconfirmationSlippageNote,
    AvailabilityVarianceSwap,
    FeeRebateForward,
    ReliabilityCreditDefaultSwap,
    EmergencyRepairCall,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Committed,
    Attested,
    Booked,
    Matched,
    Clearing,
    Settled,
    Rebated,
    Expired,
    Rejected,
}
impl TicketStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Attested | Self::Booked | Self::Matched | Self::Clearing
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    QuorumSatisfied,
    Disputed,
    Expired,
    Slashed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    Netting,
    Cleared,
    RebateQueued,
    Finalized,
    Cancelled,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_scheme: String,
    pub ticket_commitment_scheme: String,
    pub derivative_book_scheme: String,
    pub clearing_curve_scheme: String,
    pub rebate_settlement_scheme: String,
    pub anti_replay_receipt_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub low_fee_bps: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub reliability_floor_bps: u64,
    pub slippage_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub max_lanes: usize,
    pub max_books: usize,
    pub max_tickets: usize,
    pub max_settlements: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            ticket_commitment_scheme: TICKET_COMMITMENT_SCHEME.to_string(),
            derivative_book_scheme: DERIVATIVE_BOOK_SCHEME.to_string(),
            clearing_curve_scheme: CLEARING_CURVE_SCHEME.to_string(),
            rebate_settlement_scheme: REBATE_SETTLEMENT_SCHEME.to_string(),
            anti_replay_receipt_scheme: ANTI_REPLAY_RECEIPT_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            reliability_floor_bps: DEFAULT_RELIABILITY_FLOOR_BPS,
            slippage_floor_bps: DEFAULT_SLIPPAGE_FLOOR_BPS,
            slippage_cap_bps: DEFAULT_SLIPPAGE_CAP_BPS,
            max_lanes: DEFAULT_MAX_LANES,
            max_books: DEFAULT_MAX_BOOKS,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_bps("low_fee_bps", self.low_fee_bps)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below PQ safety floor".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub books_opened: u64,
    pub tickets_committed: u64,
    pub attestations_recorded: u64,
    pub curves_posted: u64,
    pub reliability_updates: u64,
    pub slippage_bands_posted: u64,
    pub settlements_queued: u64,
    pub settlements_finalized: u64,
    pub rebates_settled: u64,
    pub replay_receipts_consumed: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_notional_micro_units: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lanes_root: String,
    pub books_root: String,
    pub ticket_commitments_root: String,
    pub pq_attestations_root: String,
    pub clearing_curves_root: String,
    pub reliability_scores_root: String,
    pub slippage_bands_root: String,
    pub rebate_settlements_root: String,
    pub anti_replay_receipts_root: String,
    pub public_record_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessRepairLaneInput {
    pub lane_id: String,
    pub lane_class: LaneClass,
    pub operator_commitment_root: String,
    pub encrypted_route_root: String,
    pub capacity_units_per_block: u64,
    pub base_fee_micro_units: u64,
    pub max_latency_ms: u64,
    pub min_reliability_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessRepairLane {
    pub lane_id: String,
    pub lane_class: LaneClass,
    pub status: LaneStatus,
    pub operator_commitment_root: String,
    pub encrypted_route_root: String,
    pub capacity_units_per_block: u64,
    pub reserved_units: u64,
    pub base_fee_micro_units: u64,
    pub max_latency_ms: u64,
    pub min_reliability_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_height: u64,
    pub updated_height: u64,
    pub ticket_count: u64,
    pub attestation_count: u64,
    pub settlement_count: u64,
}
impl WitnessRepairLane {
    pub fn from_input(i: WitnessRepairLaneInput, h: u64) -> Self {
        Self {
            lane_id: i.lane_id,
            lane_class: i.lane_class,
            status: LaneStatus::Open,
            operator_commitment_root: i.operator_commitment_root,
            encrypted_route_root: i.encrypted_route_root,
            capacity_units_per_block: i.capacity_units_per_block,
            reserved_units: 0,
            base_fee_micro_units: i.base_fee_micro_units,
            max_latency_ms: i.max_latency_ms,
            min_reliability_bps: i.min_reliability_bps,
            privacy_set_size: i.privacy_set_size,
            pq_security_bits: i.pq_security_bits,
            created_height: h,
            updated_height: h,
            ticket_count: 0,
            attestation_count: 0,
            settlement_count: 0,
        }
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DerivativeBookInput {
    pub book_id: String,
    pub lane_id: String,
    pub derivative_kind: DerivativeKind,
    pub base_curve_id: String,
    pub quote_root: String,
    pub margin_commitment_root: String,
    pub max_notional_micro_units: u64,
    pub tick_size_micro_units: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyDerivativeBook {
    pub book_id: String,
    pub lane_id: String,
    pub derivative_kind: DerivativeKind,
    pub status: LaneStatus,
    pub base_curve_id: String,
    pub quote_root: String,
    pub margin_commitment_root: String,
    pub open_interest_micro_units: u64,
    pub max_notional_micro_units: u64,
    pub tick_size_micro_units: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub best_bid_micro_units: u64,
    pub best_ask_micro_units: u64,
    pub matched_ticket_count: u64,
    pub created_height: u64,
    pub updated_height: u64,
}
impl LatencyDerivativeBook {
    pub fn from_input(i: DerivativeBookInput, h: u64) -> Self {
        Self {
            book_id: i.book_id,
            lane_id: i.lane_id,
            derivative_kind: i.derivative_kind,
            status: LaneStatus::Open,
            base_curve_id: i.base_curve_id,
            quote_root: i.quote_root,
            margin_commitment_root: i.margin_commitment_root,
            open_interest_micro_units: 0,
            max_notional_micro_units: i.max_notional_micro_units,
            tick_size_micro_units: i.tick_size_micro_units,
            maker_fee_bps: i.maker_fee_bps,
            taker_fee_bps: i.taker_fee_bps,
            best_bid_micro_units: 0,
            best_ask_micro_units: 0,
            matched_ticket_count: 0,
            created_height: h,
            updated_height: h,
        }
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepairTicketCommitmentInput {
    pub ticket_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub commitment_root: String,
    pub encrypted_terms_root: String,
    pub replay_nullifier: String,
    pub latency_target_ms: u64,
    pub witness_units: u64,
    pub notional_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub expires_height: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepairTicketCommitment {
    pub ticket_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub status: TicketStatus,
    pub commitment_root: String,
    pub encrypted_terms_root: String,
    pub replay_nullifier: String,
    pub latency_target_ms: u64,
    pub witness_units: u64,
    pub notional_micro_units: u64,
    pub fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub matched_height: Option<u64>,
}
impl RepairTicketCommitment {
    pub fn from_input(
        i: RepairTicketCommitmentInput,
        fee_micro_units: u64,
        rebate_micro_units: u64,
        h: u64,
    ) -> Self {
        Self {
            ticket_id: i.ticket_id,
            lane_id: i.lane_id,
            book_id: i.book_id,
            status: TicketStatus::Committed,
            commitment_root: i.commitment_root,
            encrypted_terms_root: i.encrypted_terms_root,
            replay_nullifier: i.replay_nullifier,
            latency_target_ms: i.latency_target_ms,
            witness_units: i.witness_units,
            notional_micro_units: i.notional_micro_units,
            fee_micro_units,
            rebate_micro_units,
            created_height: h,
            expires_height: i.expires_height,
            matched_height: None,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({"ticket_id":self.ticket_id,"lane_id":self.lane_id,"book_id":self.book_id,"status":format!("{:?}",self.status),"commitment_root":self.commitment_root,"encrypted_terms_root":self.encrypted_terms_root,"replay_nullifier_root":payload_root("WITNESS-DERIVATIVE-REPLAY-NULLIFIER-REDACTED",&json!({"nullifier":self.replay_nullifier})),"latency_target_ms":self.latency_target_ms,"witness_units":self.witness_units,"notional_micro_units":self.notional_micro_units,"fee_micro_units":self.fee_micro_units,"rebate_micro_units":self.rebate_micro_units,"created_height":self.created_height,"expires_height":self.expires_height,"matched_height":self.matched_height})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqLaneAttestationInput {
    pub attestation_id: String,
    pub lane_id: String,
    pub attestor_committee_root: String,
    pub pq_signature_root: String,
    pub measured_latency_ms: u64,
    pub availability_bps: u64,
    pub repair_success_bps: u64,
    pub security_bits: u16,
    pub valid_until_height: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub status: AttestationStatus,
    pub attestor_committee_root: String,
    pub pq_signature_root: String,
    pub measured_latency_ms: u64,
    pub availability_bps: u64,
    pub repair_success_bps: u64,
    pub security_bits: u16,
    pub valid_until_height: u64,
    pub recorded_height: u64,
}
impl PqLaneAttestation {
    pub fn from_input(i: PqLaneAttestationInput, h: u64, c: &Config) -> Self {
        let status = if i.availability_bps >= c.reliability_floor_bps
            && i.security_bits >= c.min_pq_security_bits
        {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::Pending
        };
        Self {
            attestation_id: i.attestation_id,
            lane_id: i.lane_id,
            status,
            attestor_committee_root: i.attestor_committee_root,
            pq_signature_root: i.pq_signature_root,
            measured_latency_ms: i.measured_latency_ms,
            availability_bps: i.availability_bps,
            repair_success_bps: i.repair_success_bps,
            security_bits: i.security_bits,
            valid_until_height: i.valid_until_height,
            recorded_height: h,
        }
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingCurveInput {
    pub curve_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub curve_commitment_root: String,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub base_price_micro_units: u64,
    pub slope_micro_units_per_ms: u64,
    pub convexity_bps: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingCurve {
    pub curve_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub curve_commitment_root: String,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub base_price_micro_units: u64,
    pub slope_micro_units_per_ms: u64,
    pub convexity_bps: u64,
    pub created_height: u64,
    pub updated_height: u64,
}
impl ClearingCurve {
    pub fn from_input(i: ClearingCurveInput, h: u64) -> Self {
        Self {
            curve_id: i.curve_id,
            lane_id: i.lane_id,
            book_id: i.book_id,
            curve_commitment_root: i.curve_commitment_root,
            target_latency_ms: i.target_latency_ms,
            max_latency_ms: i.max_latency_ms,
            base_price_micro_units: i.base_price_micro_units,
            slope_micro_units_per_ms: i.slope_micro_units_per_ms,
            convexity_bps: i.convexity_bps,
            created_height: h,
            updated_height: h,
        }
    }
    pub fn price_for_latency(&self, ms: u64) -> u64 {
        let excess = ms.saturating_sub(self.target_latency_ms);
        let linear = excess.saturating_mul(self.slope_micro_units_per_ms);
        self.base_price_micro_units
            .saturating_add(linear)
            .saturating_add(
                linear
                    .saturating_mul(self.convexity_bps.min(MAX_BPS))
                    .saturating_div(MAX_BPS),
            )
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReliabilityScoreInput {
    pub score_id: String,
    pub lane_id: String,
    pub operator_commitment_root: String,
    pub observation_root: String,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub repair_success_bps: u64,
    pub availability_bps: u64,
    pub dispute_bps: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReliabilityScore {
    pub score_id: String,
    pub lane_id: String,
    pub operator_commitment_root: String,
    pub observation_root: String,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub repair_success_bps: u64,
    pub availability_bps: u64,
    pub dispute_bps: u64,
    pub composite_bps: u64,
    pub recorded_height: u64,
}
impl ReliabilityScore {
    pub fn from_input(i: ReliabilityScoreInput, h: u64) -> Self {
        let composite_bps = weighted_reliability_bps(
            latency_reliability_bps(i.latency_p95_ms),
            i.repair_success_bps,
            i.availability_bps,
            i.dispute_bps,
        );
        Self {
            score_id: i.score_id,
            lane_id: i.lane_id,
            operator_commitment_root: i.operator_commitment_root,
            observation_root: i.observation_root,
            latency_p50_ms: i.latency_p50_ms,
            latency_p95_ms: i.latency_p95_ms,
            repair_success_bps: i.repair_success_bps,
            availability_bps: i.availability_bps,
            dispute_bps: i.dispute_bps,
            composite_bps,
            recorded_height: h,
        }
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreconfirmationSlippageBandInput {
    pub band_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub band_commitment_root: String,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub min_slippage_bps: u64,
    pub max_slippage_bps: u64,
    pub liquidity_depth_micro_units: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreconfirmationSlippageBand {
    pub band_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub band_commitment_root: String,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub min_slippage_bps: u64,
    pub max_slippage_bps: u64,
    pub liquidity_depth_micro_units: u64,
    pub recorded_height: u64,
}
impl PreconfirmationSlippageBand {
    pub fn from_input(i: PreconfirmationSlippageBandInput, h: u64) -> Self {
        Self {
            band_id: i.band_id,
            lane_id: i.lane_id,
            book_id: i.book_id,
            band_commitment_root: i.band_commitment_root,
            min_latency_ms: i.min_latency_ms,
            max_latency_ms: i.max_latency_ms,
            min_slippage_bps: i.min_slippage_bps,
            max_slippage_bps: i.max_slippage_bps,
            liquidity_depth_micro_units: i.liquidity_depth_micro_units,
            recorded_height: h,
        }
    }
    pub fn slippage_for_latency(&self, ms: u64) -> u64 {
        if ms <= self.min_latency_ms {
            return self.min_slippage_bps;
        }
        if ms >= self.max_latency_ms {
            return self.max_slippage_bps;
        }
        let span = self
            .max_latency_ms
            .saturating_sub(self.min_latency_ms)
            .max(1);
        self.min_slippage_bps.saturating_add(
            self.max_slippage_bps
                .saturating_sub(self.min_slippage_bps)
                .saturating_mul(ms.saturating_sub(self.min_latency_ms))
                .saturating_div(span),
        )
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateSettlementInput {
    pub settlement_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub settlement_commitment_root: String,
    pub fee_paid_micro_units: u64,
    pub maker_rebate_micro_units: u64,
    pub taker_rebate_micro_units: u64,
    pub repair_provider_rebate_micro_units: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateSettlement {
    pub settlement_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub book_id: String,
    pub status: SettlementStatus,
    pub settlement_commitment_root: String,
    pub fee_paid_micro_units: u64,
    pub maker_rebate_micro_units: u64,
    pub taker_rebate_micro_units: u64,
    pub repair_provider_rebate_micro_units: u64,
    pub net_fee_micro_units: u64,
    pub queued_height: u64,
    pub finalized_height: Option<u64>,
}
impl FeeRebateSettlement {
    pub fn from_input(i: FeeRebateSettlementInput, h: u64) -> Self {
        let total = i
            .maker_rebate_micro_units
            .saturating_add(i.taker_rebate_micro_units)
            .saturating_add(i.repair_provider_rebate_micro_units);
        Self {
            settlement_id: i.settlement_id,
            ticket_id: i.ticket_id,
            lane_id: i.lane_id,
            book_id: i.book_id,
            status: SettlementStatus::Queued,
            settlement_commitment_root: i.settlement_commitment_root,
            fee_paid_micro_units: i.fee_paid_micro_units,
            maker_rebate_micro_units: i.maker_rebate_micro_units,
            taker_rebate_micro_units: i.taker_rebate_micro_units,
            repair_provider_rebate_micro_units: i.repair_provider_rebate_micro_units,
            net_fee_micro_units: i.fee_paid_micro_units.saturating_sub(total),
            queued_height: h,
            finalized_height: None,
        }
    }
    pub fn total_rebate_micro_units(&self) -> u64 {
        self.maker_rebate_micro_units
            .saturating_add(self.taker_rebate_micro_units)
            .saturating_add(self.repair_provider_rebate_micro_units)
    }
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AntiReplayReceipt {
    pub receipt_id: String,
    pub replay_nullifier_root: String,
    pub lane_id: String,
    pub ticket_id: String,
    pub consumed_height: u64,
    pub expires_height: u64,
}
impl AntiReplayReceipt {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicRecord {
    pub protocol_version: String,
    pub height: u64,
    pub epoch: u64,
    pub public_bucket: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub privacy_boundary: String,
}
impl PublicRecord {
    pub fn as_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"serialization":"failed"}))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, WitnessRepairLane>,
    pub books: BTreeMap<String, LatencyDerivativeBook>,
    pub ticket_commitments: BTreeMap<String, RepairTicketCommitment>,
    pub pq_attestations: BTreeMap<String, PqLaneAttestation>,
    pub clearing_curves: BTreeMap<String, ClearingCurve>,
    pub reliability_scores: BTreeMap<String, ReliabilityScore>,
    pub slippage_bands: BTreeMap<String, PreconfirmationSlippageBand>,
    pub rebate_settlements: BTreeMap<String, FeeRebateSettlement>,
    pub anti_replay_receipts: BTreeMap<String, AntiReplayReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}
impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("valid witness derivative latency clearing config")
    }
}
impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut s = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            books: BTreeMap::new(),
            ticket_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            clearing_curves: BTreeMap::new(),
            reliability_scores: BTreeMap::new(),
            slippage_bands: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
            anti_replay_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        s.refresh_roots();
        Ok(s)
    }
    pub fn register_lane(&mut self, i: WitnessRepairLaneInput, h: u64) -> Result<String> {
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_absent("lane", &self.lanes, &i.lane_id)?;
        ensure_root("operator_commitment_root", &i.operator_commitment_root)?;
        ensure_root("encrypted_route_root", &i.encrypted_route_root)?;
        if i.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below runtime floor".into());
        }
        if i.pq_security_bits < self.config.min_pq_security_bits {
            return Err("lane PQ security below runtime floor".into());
        }
        let id = i.lane_id.clone();
        self.lanes
            .insert(id.clone(), WitnessRepairLane::from_input(i, h));
        self.counters.lanes_registered += 1;
        self.refresh_roots();
        Ok(id)
    }
    pub fn open_book(&mut self, i: DerivativeBookInput, h: u64) -> Result<String> {
        ensure_capacity("books", self.books.len(), self.config.max_books)?;
        ensure_absent("book", &self.books, &i.book_id)?;
        ensure_present("lane", &self.lanes, &i.lane_id)?;
        let id = i.book_id.clone();
        self.books
            .insert(id.clone(), LatencyDerivativeBook::from_input(i, h));
        self.counters.books_opened += 1;
        self.refresh_roots();
        Ok(id)
    }
    pub fn post_clearing_curve(&mut self, i: ClearingCurveInput, h: u64) -> Result<String> {
        ensure_absent("curve", &self.clearing_curves, &i.curve_id)?;
        ensure_present("lane", &self.lanes, &i.lane_id)?;
        ensure_present("book", &self.books, &i.book_id)?;
        ensure_root("curve_commitment_root", &i.curve_commitment_root)?;
        let id = i.curve_id.clone();
        self.clearing_curves
            .insert(id.clone(), ClearingCurve::from_input(i, h));
        self.counters.curves_posted += 1;
        self.refresh_roots();
        Ok(id)
    }
    pub fn commit_ticket(&mut self, i: RepairTicketCommitmentInput, h: u64) -> Result<String> {
        ensure_capacity(
            "tickets",
            self.ticket_commitments.len(),
            self.config.max_tickets,
        )?;
        ensure_absent("ticket", &self.ticket_commitments, &i.ticket_id)?;
        ensure_present("lane", &self.lanes, &i.lane_id)?;
        ensure_present("book", &self.books, &i.book_id)?;
        ensure_root("commitment_root", &i.commitment_root)?;
        ensure_root("encrypted_terms_root", &i.encrypted_terms_root)?;
        ensure_nullifier_available(&self.consumed_nullifiers, &i.replay_nullifier)?;
        let lane = self
            .lanes
            .get(&i.lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        if !lane.status.accepts_tickets() {
            return Err("lane is not accepting tickets".into());
        }
        let fee = ticket_fee_micro_units(
            i.notional_micro_units,
            self.config.low_fee_bps,
            self.config.max_fee_bps,
            i.max_fee_micro_units,
        );
        let reb = rebate_micro_units(fee, self.config.rebate_bps);
        let id = i.ticket_id.clone();
        let nul = i.replay_nullifier.clone();
        let lane_id = i.lane_id.clone();
        let book_id = i.book_id.clone();
        let notional = i.notional_micro_units;
        self.ticket_commitments.insert(
            id.clone(),
            RepairTicketCommitment::from_input(i, fee, reb, h),
        );
        self.consumed_nullifiers.insert(nul.clone());
        let r = AntiReplayReceipt {
            receipt_id: receipt_id(&id, &nul),
            replay_nullifier_root: payload_root(
                "WITNESS-DERIVATIVE-CONSUMED-NULLIFIER",
                &json!({"nullifier":nul}),
            ),
            lane_id: lane_id.clone(),
            ticket_id: id.clone(),
            consumed_height: h,
            expires_height: h + 720,
        };
        self.anti_replay_receipts.insert(r.receipt_id.clone(), r);
        if let Some(l) = self.lanes.get_mut(&lane_id) {
            l.ticket_count += 1;
            l.reserved_units += 1;
            l.updated_height = h
        }
        if let Some(b) = self.books.get_mut(&book_id) {
            b.open_interest_micro_units = b.open_interest_micro_units.saturating_add(fee);
            b.updated_height = h
        }
        self.counters.tickets_committed += 1;
        self.counters.replay_receipts_consumed += 1;
        self.counters.total_fee_micro_units =
            self.counters.total_fee_micro_units.saturating_add(fee);
        self.counters.total_rebate_micro_units =
            self.counters.total_rebate_micro_units.saturating_add(reb);
        self.counters.total_notional_micro_units = self
            .counters
            .total_notional_micro_units
            .saturating_add(notional);
        self.refresh_roots();
        Ok(id)
    }
    pub fn attest_lane(&mut self, i: PqLaneAttestationInput, h: u64) -> Result<String> {
        ensure_absent("attestation", &self.pq_attestations, &i.attestation_id)?;
        ensure_present("lane", &self.lanes, &i.lane_id)?;
        let id = i.attestation_id.clone();
        let lane_id = i.lane_id.clone();
        self.pq_attestations.insert(
            id.clone(),
            PqLaneAttestation::from_input(i, h, &self.config),
        );
        if let Some(l) = self.lanes.get_mut(&lane_id) {
            l.attestation_count += 1;
            l.updated_height = h
        }
        self.counters.attestations_recorded += 1;
        self.refresh_roots();
        Ok(id)
    }
    pub fn record_reliability_score(&mut self, i: ReliabilityScoreInput, h: u64) -> Result<String> {
        ensure_absent("score", &self.reliability_scores, &i.score_id)?;
        ensure_present("lane", &self.lanes, &i.lane_id)?;
        let id = i.score_id.clone();
        let lane_id = i.lane_id.clone();
        let score = ReliabilityScore::from_input(i, h);
        if let Some(l) = self.lanes.get_mut(&lane_id) {
            l.min_reliability_bps = score.composite_bps;
            l.status = if score.composite_bps >= self.config.reliability_floor_bps {
                LaneStatus::Open
            } else {
                LaneStatus::Guarded
            };
            l.updated_height = h
        }
        self.reliability_scores.insert(id.clone(), score);
        self.counters.reliability_updates += 1;
        self.refresh_roots();
        Ok(id)
    }
    pub fn post_slippage_band(
        &mut self,
        i: PreconfirmationSlippageBandInput,
        h: u64,
    ) -> Result<String> {
        ensure_absent("band", &self.slippage_bands, &i.band_id)?;
        ensure_present("lane", &self.lanes, &i.lane_id)?;
        ensure_present("book", &self.books, &i.book_id)?;
        let id = i.band_id.clone();
        self.slippage_bands
            .insert(id.clone(), PreconfirmationSlippageBand::from_input(i, h));
        self.counters.slippage_bands_posted += 1;
        self.refresh_roots();
        Ok(id)
    }
    pub fn queue_rebate_settlement(
        &mut self,
        i: FeeRebateSettlementInput,
        h: u64,
    ) -> Result<String> {
        ensure_capacity(
            "settlements",
            self.rebate_settlements.len(),
            self.config.max_settlements,
        )?;
        ensure_absent("settlement", &self.rebate_settlements, &i.settlement_id)?;
        ensure_present("ticket", &self.ticket_commitments, &i.ticket_id)?;
        let id = i.settlement_id.clone();
        let ticket = i.ticket_id.clone();
        let s = FeeRebateSettlement::from_input(i, h);
        let total = s.total_rebate_micro_units();
        self.rebate_settlements.insert(id.clone(), s);
        if let Some(t) = self.ticket_commitments.get_mut(&ticket) {
            t.status = TicketStatus::Clearing
        }
        self.counters.settlements_queued += 1;
        self.counters.total_rebate_micro_units =
            self.counters.total_rebate_micro_units.saturating_add(total);
        self.refresh_roots();
        Ok(id)
    }
    pub fn finalize_settlement(&mut self, id: &str, h: u64) -> Result<()> {
        let s = self
            .rebate_settlements
            .get_mut(id)
            .ok_or_else(|| format!("settlement {id} missing"))?;
        s.status = SettlementStatus::Finalized;
        s.finalized_height = Some(h);
        if let Some(t) = self.ticket_commitments.get_mut(&s.ticket_id) {
            t.status = TicketStatus::Rebated;
            t.matched_height = Some(h)
        }
        self.counters.settlements_finalized += 1;
        self.counters.rebates_settled += 1;
        self.refresh_roots();
        Ok(())
    }
    pub fn expire_tickets(&mut self, h: u64) -> u64 {
        let mut n = 0;
        for t in self.ticket_commitments.values_mut() {
            if t.status.live() && t.expires_height <= h {
                t.status = TicketStatus::Expired;
                n += 1
            }
        }
        self.refresh_roots();
        n
    }
    pub fn quote_latency_clear_price(&self, id: &str, ms: u64, rel: u64) -> Result<u64> {
        let c = self
            .clearing_curves
            .get(id)
            .ok_or_else(|| format!("curve {id} missing"))?;
        let p = c.price_for_latency(ms);
        Ok(p.saturating_add(
            p.saturating_mul(MAX_BPS.saturating_sub(rel.min(MAX_BPS)))
                .saturating_div(MAX_BPS),
        ))
    }
    pub fn quote_slippage_bps(&self, id: &str, ms: u64) -> Result<u64> {
        let b = self
            .slippage_bands
            .get(id)
            .ok_or_else(|| format!("band {id} missing"))?;
        Ok(b.slippage_for_latency(ms)
            .clamp(self.config.slippage_floor_bps, self.config.slippage_cap_bps))
    }
    pub fn public_record(&self) -> Value {
        let mut c = self.clone();
        c.refresh_roots();
        json!({"protocol_version":PROTOCOL_VERSION,"schema_version":SCHEMA_VERSION,"chain_id":CHAIN_ID,"height":DEVNET_HEIGHT,"epoch":DEVNET_EPOCH,"public_bucket":public_bucket(DEVNET_HEIGHT,32),"config":self.config.public_record(),"counters":self.counters.public_record(),"roots":c.roots.public_record(),"aggregate_counts":{"lanes":self.lanes.len(),"books":self.books.len(),"ticket_commitments":self.ticket_commitments.len(),"pq_attestations":self.pq_attestations.len(),"clearing_curves":self.clearing_curves.len(),"reliability_scores":self.reliability_scores.len(),"slippage_bands":self.slippage_bands.len(),"rebate_settlements":self.rebate_settlements.len(),"anti_replay_receipts":self.anti_replay_receipts.len()},"privacy_boundary":PRIVACY_BOUNDARY})
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
    pub fn refresh_roots(&mut self) {
        self.roots.config_root =
            payload_root("WITNESS-DERIVATIVE-CONFIG", &self.config.public_record());
        self.roots.counters_root = payload_root(
            "WITNESS-DERIVATIVE-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots.lanes_root = value_map_root(
            "WITNESS-DERIVATIVE-LANES",
            self.lanes
                .values()
                .map(WitnessRepairLane::public_record)
                .collect(),
        );
        self.roots.books_root = value_map_root(
            "WITNESS-DERIVATIVE-BOOKS",
            self.books
                .values()
                .map(LatencyDerivativeBook::public_record)
                .collect(),
        );
        self.roots.ticket_commitments_root = value_map_root(
            "WITNESS-DERIVATIVE-TICKETS",
            self.ticket_commitments
                .values()
                .map(RepairTicketCommitment::public_record)
                .collect(),
        );
        self.roots.pq_attestations_root = value_map_root(
            "WITNESS-DERIVATIVE-ATTESTATIONS",
            self.pq_attestations
                .values()
                .map(PqLaneAttestation::public_record)
                .collect(),
        );
        self.roots.clearing_curves_root = value_map_root(
            "WITNESS-DERIVATIVE-CURVES",
            self.clearing_curves
                .values()
                .map(ClearingCurve::public_record)
                .collect(),
        );
        self.roots.reliability_scores_root = value_map_root(
            "WITNESS-DERIVATIVE-RELIABILITY",
            self.reliability_scores
                .values()
                .map(ReliabilityScore::public_record)
                .collect(),
        );
        self.roots.slippage_bands_root = value_map_root(
            "WITNESS-DERIVATIVE-SLIPPAGE",
            self.slippage_bands
                .values()
                .map(PreconfirmationSlippageBand::public_record)
                .collect(),
        );
        self.roots.rebate_settlements_root = value_map_root(
            "WITNESS-DERIVATIVE-REBATES",
            self.rebate_settlements
                .values()
                .map(FeeRebateSettlement::public_record)
                .collect(),
        );
        self.roots.anti_replay_receipts_root = value_map_root(
            "WITNESS-DERIVATIVE-REPLAY",
            self.anti_replay_receipts
                .values()
                .map(AntiReplayReceipt::public_record)
                .collect(),
        );
        let r = json!({"config_root":self.roots.config_root,"counters_root":self.roots.counters_root,"lanes_root":self.roots.lanes_root,"books_root":self.roots.books_root,"ticket_commitments_root":self.roots.ticket_commitments_root,"pq_attestations_root":self.roots.pq_attestations_root,"clearing_curves_root":self.roots.clearing_curves_root,"reliability_scores_root":self.roots.reliability_scores_root,"slippage_bands_root":self.roots.slippage_bands_root,"rebate_settlements_root":self.roots.rebate_settlements_root,"anti_replay_receipts_root":self.roots.anti_replay_receipts_root});
        self.roots.public_record_root = payload_root(PUBLIC_RECORD_SCHEME, &r);
        self.roots.state_root = state_root_from_record(&r)
    }
}
pub fn devnet() -> State {
    let mut s = State::default();
    let lane = WitnessRepairLaneInput {
        lane_id: demo_root("lane"),
        lane_class: LaneClass::FastPreconfirmation,
        operator_commitment_root: demo_root("operator"),
        encrypted_route_root: demo_root("route"),
        capacity_units_per_block: 24000,
        base_fee_micro_units: 2500,
        max_latency_ms: 2000,
        min_reliability_bps: DEFAULT_RELIABILITY_FLOOR_BPS,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
    };
    let lane_id = lane.lane_id.clone();
    s.register_lane(lane, DEVNET_HEIGHT).expect("lane");
    let book = DerivativeBookInput {
        book_id: demo_root("book"),
        lane_id: lane_id.clone(),
        derivative_kind: DerivativeKind::LatencyFuture,
        base_curve_id: demo_root("curve"),
        quote_root: demo_root("quote"),
        margin_commitment_root: demo_root("margin"),
        max_notional_micro_units: 5000000000,
        tick_size_micro_units: 10,
        maker_fee_bps: 12,
        taker_fee_bps: 8,
    };
    let book_id = book.book_id.clone();
    let curve_id = book.base_curve_id.clone();
    s.open_book(book, DEVNET_HEIGHT + 1).expect("book");
    s.post_clearing_curve(
        ClearingCurveInput {
            curve_id,
            lane_id: lane_id.clone(),
            book_id: book_id.clone(),
            curve_commitment_root: demo_root("curve-commitment"),
            target_latency_ms: 180,
            max_latency_ms: 2000,
            base_price_micro_units: 1000,
            slope_micro_units_per_ms: 4,
            convexity_bps: 140,
        },
        DEVNET_HEIGHT + 2,
    )
    .expect("curve");
    s.attest_lane(
        PqLaneAttestationInput {
            attestation_id: demo_root("att"),
            lane_id: lane_id.clone(),
            attestor_committee_root: demo_root("committee"),
            pq_signature_root: demo_root("sig"),
            measured_latency_ms: 142,
            availability_bps: 9930,
            repair_success_bps: 9890,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            valid_until_height: DEVNET_HEIGHT + 96,
        },
        DEVNET_HEIGHT + 3,
    )
    .expect("att");
    s.record_reliability_score(
        ReliabilityScoreInput {
            score_id: demo_root("score"),
            lane_id: lane_id.clone(),
            operator_commitment_root: demo_root("operator"),
            observation_root: demo_root("obs"),
            latency_p50_ms: 118,
            latency_p95_ms: 188,
            repair_success_bps: 9870,
            availability_bps: 9940,
            dispute_bps: 20,
        },
        DEVNET_HEIGHT + 4,
    )
    .expect("score");
    s.post_slippage_band(
        PreconfirmationSlippageBandInput {
            band_id: demo_root("band"),
            lane_id: lane_id.clone(),
            book_id: book_id.clone(),
            band_commitment_root: demo_root("band-root"),
            min_latency_ms: 80,
            max_latency_ms: 900,
            min_slippage_bps: DEFAULT_SLIPPAGE_FLOOR_BPS,
            max_slippage_bps: DEFAULT_SLIPPAGE_CAP_BPS,
            liquidity_depth_micro_units: 2000000000,
        },
        DEVNET_HEIGHT + 5,
    )
    .expect("band");
    let ticket_id = demo_root("ticket");
    s.commit_ticket(
        RepairTicketCommitmentInput {
            ticket_id: ticket_id.clone(),
            lane_id: lane_id.clone(),
            book_id: book_id.clone(),
            commitment_root: demo_root("ticket-root"),
            encrypted_terms_root: demo_root("terms"),
            replay_nullifier: demo_root("nullifier"),
            latency_target_ms: 160,
            witness_units: 12,
            notional_micro_units: 100000000,
            max_fee_micro_units: 50000,
            expires_height: DEVNET_HEIGHT + 32,
        },
        DEVNET_HEIGHT + 6,
    )
    .expect("ticket");
    let set = demo_root("settlement");
    s.queue_rebate_settlement(
        FeeRebateSettlementInput {
            settlement_id: set.clone(),
            ticket_id,
            lane_id,
            book_id,
            settlement_commitment_root: demo_root("set-root"),
            fee_paid_micro_units: 30000,
            maker_rebate_micro_units: 360,
            taker_rebate_micro_units: 240,
            repair_provider_rebate_micro_units: 1050,
        },
        DEVNET_HEIGHT + 7,
    )
    .expect("settlement");
    s.finalize_settlement(&set, DEVNET_HEIGHT + 8)
        .expect("finalize");
    s
}
pub fn public_record(state: &State) -> Value {
    state.public_record()
}
pub fn state_root(state: &State) -> String {
    state.state_root()
}
pub fn devnet_public_record() -> Value {
    devnet().public_record()
}
pub fn latency_reliability_bps(ms: u64) -> u64 {
    if ms <= 180 {
        MAX_BPS
    } else {
        MAX_BPS
            .saturating_sub(ms.saturating_sub(180).saturating_mul(8))
            .min(MAX_BPS)
    }
}
pub fn weighted_reliability_bps(l: u64, r: u64, a: u64, d: u64) -> u64 {
    l.min(MAX_BPS)
        .saturating_mul(25)
        .saturating_add(r.min(MAX_BPS).saturating_mul(35))
        .saturating_add(a.min(MAX_BPS).saturating_mul(40))
        .saturating_div(100)
        .saturating_sub(d.min(MAX_BPS) / 2)
        .min(MAX_BPS)
}
pub fn ticket_fee_micro_units(n: u64, low: u64, max: u64, cap: u64) -> u64 {
    n.saturating_mul(low.min(max).min(MAX_BPS))
        .saturating_div(MAX_BPS)
        .min(cap)
}
pub fn rebate_micro_units(f: u64, b: u64) -> u64 {
    f.saturating_mul(b.min(MAX_BPS)).saturating_div(MAX_BPS)
}
pub fn public_bucket(h: u64, b: u64) -> u64 {
    if b == 0 {
        h
    } else {
        h / b
    }
}
pub fn payload_root(d: &str, p: &Value) -> String {
    domain_hash(
        d,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(p),
        ],
        32,
    )
}
pub fn state_root_from_record(r: &Value) -> String {
    payload_root(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-WITNESS-DERIVATIVE-LATENCY-CLEARING-STATE-ROOT",
        r,
    )
}
pub fn value_map_root(d: &str, v: Vec<Value>) -> String {
    merkle_root(d, &v)
}
pub fn receipt_id(t: &str, n: &str) -> String {
    payload_root(
        "WITNESS-DERIVATIVE-RECEIPT-ID",
        &json!({"ticket_id":t,"replay_nullifier":n}),
    )
}
fn demo_root(l: &str) -> String {
    payload_root("WITNESS-DERIVATIVE-DEVNET-DEMO-ROOT", &json!({"label":l}))
}
fn ensure_nonempty(f: &str, v: &str) -> Result<()> {
    if v.trim().is_empty() {
        Err(format!("{f} cannot be empty"))
    } else {
        Ok(())
    }
}
fn ensure_root(f: &str, v: &str) -> Result<()> {
    ensure_nonempty(f, v)?;
    if v.len() < 16 {
        Err(format!("{f} must look like a commitment root"))
    } else {
        Ok(())
    }
}
fn ensure_bps(f: &str, v: u64) -> Result<()> {
    if v > MAX_BPS {
        Err(format!("{f} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}
fn ensure_absent<T>(l: &str, m: &BTreeMap<String, T>, k: &str) -> Result<()> {
    if m.contains_key(k) {
        Err(format!("{l} {k} already exists"))
    } else {
        Ok(())
    }
}
fn ensure_present<T>(l: &str, m: &BTreeMap<String, T>, k: &str) -> Result<()> {
    if m.contains_key(k) {
        Ok(())
    } else {
        Err(format!("{l} {k} missing"))
    }
}
fn ensure_capacity(l: &str, c: usize, m: usize) -> Result<()> {
    if c >= m {
        Err(format!("{l} capacity exhausted"))
    } else {
        Ok(())
    }
}
fn ensure_nullifier_available(s: &BTreeSet<String>, n: &str) -> Result<()> {
    if s.contains(n) {
        Err(format!("nullifier {n} already consumed"))
    } else {
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile1 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile1 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile2 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile2 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile3 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile3 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile4 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile4 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile5 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile5 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile6 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile6 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile7 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile7 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile8 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile8 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile9 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile9 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile10 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile10 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile11 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile11 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile12 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile12 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile13 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile13 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile14 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile14 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile15 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile15 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile16 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile16 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile17 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile17 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile18 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile18 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile19 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile19 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile20 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile20 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile21 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile21 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile22 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile22 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile23 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile23 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile24 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile24 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyClearingRiskProfile25 {
    pub profile_id: String,
    pub lane_root: String,
    pub book_root: String,
    pub ticket_commitment_root: String,
    pub pq_attestation_root: String,
    pub clearing_curve_root: String,
    pub reliability_floor_bps: u64,
    pub slippage_cap_bps: u64,
    pub rebate_bps: u64,
}
impl LatencyClearingRiskProfile25 {
    pub fn public_record(&self) -> Value {
        json!({"profile_id":self.profile_id,"lane_root":self.lane_root,"book_root":self.book_root,"ticket_commitment_root":self.ticket_commitment_root,"pq_attestation_root":self.pq_attestation_root,"clearing_curve_root":self.clearing_curve_root,"reliability_floor_bps":self.reliability_floor_bps,"slippage_cap_bps":self.slippage_cap_bps,"rebate_bps":self.rebate_bps})
    }
}
