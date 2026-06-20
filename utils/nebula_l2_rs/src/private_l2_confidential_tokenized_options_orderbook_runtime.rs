use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenizedOptionsOrderbookRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-tokenized-options-orderbook-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORDER_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-sealed-options-order-v1";
pub const PQ_RISK_SCHEME: &str = "ML-DSA-87+SLH-DSA-SHAKE-256s-confidential-options-risk-v1";
pub const SETTLEMENT_SCHEME: &str = "zk-pq-confidential-tokenized-options-settlement-v1";
pub const EXERCISE_SCHEME: &str = "zk-pq-confidential-tokenized-options-exercise-v1";
pub const DEVNET_HEIGHT: u64 = 876_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    Call,
    Put,
    BinaryCall,
    BinaryPut,
    BarrierCall,
    BarrierPut,
}

impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::BinaryCall => "binary_call",
            Self::BinaryPut => "binary_put",
            Self::BarrierCall => "barrier_call",
            Self::BarrierPut => "barrier_put",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStyle {
    European,
    American,
    Bermudan,
}

impl OptionStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::European => "european",
            Self::American => "american",
            Self::Bermudan => "bermudan",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Bid,
    Ask,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bid => "bid",
            Self::Ask => "ask",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Sealed,
    RiskAttested,
    SponsorReserved,
    BatchQueued,
    PartiallyFilled,
    Filled,
    Cancelled,
    Expired,
    Rejected,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::RiskAttested => "risk_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchQueued => "batch_queued",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::RiskAttested | Self::SponsorReserved | Self::BatchQueued
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    Proved,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub low_fee_lane_id: String,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub max_series: usize,
    pub max_orders: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_sponsor_reservations: usize,
    pub max_rebates: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub matching_window_blocks: u64,
    pub order_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub exercise_ttl_blocks: u64,
    pub quantum_resistance_required: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-devnet".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            low_fee_lane_id: "devnet-private-l2-tokenized-options-orderbook-low-fee".to_string(),
            collateral_asset_id: "asset:wxmr".to_string(),
            quote_asset_id: "asset:private-dusd".to_string(),
            fee_asset_id: "asset:private-dusd".to_string(),
            max_series: 65_536,
            max_orders: 2_097_152,
            max_batches: 65_536,
            max_receipts: 2_097_152,
            max_sponsor_reservations: 524_288,
            max_rebates: 524_288,
            min_privacy_set_size: 4_096,
            batch_privacy_set_size: 65_536,
            min_pq_security_bits: 256,
            max_user_fee_bps: 18,
            max_sponsor_fee_bps: 24,
            min_rebate_bps: 2,
            max_rebate_bps: 16,
            matching_window_blocks: 3,
            order_ttl_blocks: 48,
            settlement_ttl_blocks: 12,
            exercise_ttl_blocks: 72,
            quantum_resistance_required: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "low_fee_lane_id": self.low_fee_lane_id,
            "collateral_asset_id": self.collateral_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "limits": {
                "max_series": self.max_series,
                "max_orders": self.max_orders,
                "max_batches": self.max_batches,
                "max_receipts": self.max_receipts,
                "max_sponsor_reservations": self.max_sponsor_reservations,
                "max_rebates": self.max_rebates
            },
            "privacy": {
                "min_privacy_set_size": self.min_privacy_set_size,
                "batch_privacy_set_size": self.batch_privacy_set_size
            },
            "fees": {
                "max_user_fee_bps": self.max_user_fee_bps,
                "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
                "min_rebate_bps": self.min_rebate_bps,
                "max_rebate_bps": self.max_rebate_bps
            },
            "timing": {
                "matching_window_blocks": self.matching_window_blocks,
                "order_ttl_blocks": self.order_ttl_blocks,
                "settlement_ttl_blocks": self.settlement_ttl_blocks,
                "exercise_ttl_blocks": self.exercise_ttl_blocks
            },
            "pq": {
                "min_pq_security_bits": self.min_pq_security_bits,
                "quantum_resistance_required": self.quantum_resistance_required
            }
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub series: u64,
    pub encrypted_orders: u64,
    pub matching_batches: u64,
    pub risk_attestations: u64,
    pub exercise_receipts: u64,
    pub settlement_receipts: u64,
    pub sponsor_reservations: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub consumed_nullifiers: u64,
    pub open_interest_units: u64,
    pub matched_notional_micro_units: u64,
    pub fee_saved_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "series": self.series,
            "encrypted_orders": self.encrypted_orders,
            "matching_batches": self.matching_batches,
            "risk_attestations": self.risk_attestations,
            "exercise_receipts": self.exercise_receipts,
            "settlement_receipts": self.settlement_receipts,
            "sponsor_reservations": self.sponsor_reservations,
            "rebates": self.rebates,
            "privacy_fences": self.privacy_fences,
            "consumed_nullifiers": self.consumed_nullifiers,
            "open_interest_units": self.open_interest_units,
            "matched_notional_micro_units": self.matched_notional_micro_units,
            "fee_saved_micro_units": self.fee_saved_micro_units
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOptionSeries {
    pub series_id: String,
    pub market_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub collateral_asset_id: String,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub token_id: String,
    pub strike_commitment: String,
    pub expiry_height: u64,
    pub settlement_oracle_commitment: String,
    pub payoff_circuit_id: String,
    pub collateral_commitment: String,
    pub metadata_ciphertext_root: String,
    pub privacy_set_size: u64,
    pub pq_policy_id: String,
    pub created_height: u64,
    pub active: bool,
}

impl ConfidentialOptionSeries {
    pub fn public_record(&self) -> Value {
        json!({
            "series_id": self.series_id,
            "market_id": self.market_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "option_kind": self.option_kind.as_str(),
            "option_style": self.option_style.as_str(),
            "token_id": self.token_id,
            "strike_commitment": self.strike_commitment,
            "expiry_height": self.expiry_height,
            "settlement_oracle_commitment": self.settlement_oracle_commitment,
            "payoff_circuit_id": self.payoff_circuit_id,
            "collateral_commitment": self.collateral_commitment,
            "metadata_ciphertext_root": self.metadata_ciphertext_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_policy_id": self.pq_policy_id,
            "created_height": self.created_height,
            "active": self.active
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOrder {
    pub order_id: String,
    pub series_id: String,
    pub owner_commitment: String,
    pub side: OrderSide,
    pub status: OrderStatus,
    pub encrypted_terms_root: String,
    pub price_commitment: String,
    pub size_commitment: String,
    pub collateral_note_commitment: String,
    pub fee_note_commitment: String,
    pub order_nullifier: String,
    pub replay_fence_id: String,
    pub sponsor_reservation_id: Option<String>,
    pub risk_attestation_id: Option<String>,
    pub min_fill_commitment: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_envelope_id: String,
    pub created_height: u64,
    pub expiry_height: u64,
}

impl EncryptedOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "series_id": self.series_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "price_commitment": self.price_commitment,
            "size_commitment": self.size_commitment,
            "collateral_note_commitment": self.collateral_note_commitment,
            "fee_note_commitment": self.fee_note_commitment,
            "order_nullifier": self.order_nullifier,
            "replay_fence_id": self.replay_fence_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "risk_attestation_id": self.risk_attestation_id,
            "min_fill_commitment": self.min_fill_commitment,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_envelope_id": self.pq_envelope_id,
            "created_height": self.created_height,
            "expiry_height": self.expiry_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMatchingBatch {
    pub batch_id: String,
    pub market_id: String,
    pub series_id: String,
    pub status: BatchStatus,
    pub sealed_bid_root: String,
    pub sealed_ask_root: String,
    pub match_commitment_root: String,
    pub clearing_price_commitment: String,
    pub matched_size_commitment: String,
    pub solver_commitment: String,
    pub proof_commitment: String,
    pub consumed_nullifier_root: String,
    pub output_note_root: String,
    pub rebate_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub built_height: u64,
    pub settlement_deadline_height: u64,
}

impl PrivateMatchingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "market_id": self.market_id,
            "series_id": self.series_id,
            "status": self.status.as_str(),
            "sealed_bid_root": self.sealed_bid_root,
            "sealed_ask_root": self.sealed_ask_root,
            "match_commitment_root": self.match_commitment_root,
            "clearing_price_commitment": self.clearing_price_commitment,
            "matched_size_commitment": self.matched_size_commitment,
            "solver_commitment": self.solver_commitment,
            "proof_commitment": self.proof_commitment,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "output_note_root": self.output_note_root,
            "rebate_root": self.rebate_root,
            "privacy_set_size": self.privacy_set_size,
            "fee_bps": self.fee_bps,
            "built_height": self.built_height,
            "settlement_deadline_height": self.settlement_deadline_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAttestation {
    pub attestation_id: String,
    pub series_id: String,
    pub order_id: Option<String>,
    pub attestor_committee_id: String,
    pub risk_model_id: String,
    pub margin_commitment: String,
    pub volatility_commitment: String,
    pub liquidity_commitment: String,
    pub worst_case_loss_commitment: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl PqRiskAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "series_id": self.series_id,
            "order_id": self.order_id,
            "attestor_committee_id": self.attestor_committee_id,
            "risk_model_id": self.risk_model_id,
            "margin_commitment": self.margin_commitment,
            "volatility_commitment": self.volatility_commitment,
            "liquidity_commitment": self.liquidity_commitment,
            "worst_case_loss_commitment": self.worst_case_loss_commitment,
            "pq_signature_root": self.pq_signature_root,
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseReceipt {
    pub receipt_id: String,
    pub series_id: String,
    pub option_token_commitment: String,
    pub holder_commitment: String,
    pub exercise_nullifier: String,
    pub payoff_note_commitment: String,
    pub settlement_price_commitment: String,
    pub proof_commitment: String,
    pub oracle_root: String,
    pub status: ReceiptStatus,
    pub exercised_height: u64,
}

impl ExerciseReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "series_id": self.series_id,
            "option_token_commitment": self.option_token_commitment,
            "holder_commitment": self.holder_commitment,
            "exercise_nullifier": self.exercise_nullifier,
            "payoff_note_commitment": self.payoff_note_commitment,
            "settlement_price_commitment": self.settlement_price_commitment,
            "proof_commitment": self.proof_commitment,
            "oracle_root": self.oracle_root,
            "status": self.status.as_str(),
            "exercised_height": self.exercised_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub series_id: String,
    pub input_order_root: String,
    pub consumed_nullifier_root: String,
    pub minted_option_token_root: String,
    pub transferred_collateral_root: String,
    pub fee_note_root: String,
    pub rebate_root: String,
    pub proof_commitment: String,
    pub status: ReceiptStatus,
    pub settled_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "series_id": self.series_id,
            "input_order_root": self.input_order_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "minted_option_token_root": self.minted_option_token_root,
            "transferred_collateral_root": self.transferred_collateral_root,
            "fee_note_root": self.fee_note_root,
            "rebate_root": self.rebate_root,
            "proof_commitment": self.proof_commitment,
            "status": self.status.as_str(),
            "settled_height": self.settled_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_id: String,
    pub order_id: String,
    pub reserved_fee_commitment: String,
    pub max_fee_bps: u64,
    pub status: ReservationStatus,
    pub reservation_nullifier: String,
    pub expires_height: u64,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_id": self.sponsor_id,
            "order_id": self.order_id,
            "reserved_fee_commitment": self.reserved_fee_commitment,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "reservation_nullifier": self.reservation_nullifier,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub rebate_note_commitment: String,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub reason_code: String,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_note_commitment": self.rebate_note_commitment,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "reason_code": self.reason_code
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub scope: String,
    pub anchor_root: String,
    pub nullifier_root: String,
    pub commitment_root: String,
    pub min_privacy_set_size: u64,
    pub epoch: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "scope": self.scope,
            "anchor_root": self.anchor_root,
            "nullifier_root": self.nullifier_root,
            "commitment_root": self.commitment_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "epoch": self.epoch
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub series_root: String,
    pub encrypted_order_root: String,
    pub matching_batch_root: String,
    pub pq_risk_attestation_root: String,
    pub exercise_receipt_root: String,
    pub settlement_receipt_root: String,
    pub sponsor_reservation_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "series_root": self.series_root,
            "encrypted_order_root": self.encrypted_order_root,
            "matching_batch_root": self.matching_batch_root,
            "pq_risk_attestation_root": self.pq_risk_attestation_root,
            "exercise_receipt_root": self.exercise_receipt_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub series: BTreeMap<String, ConfidentialOptionSeries>,
    pub encrypted_orders: BTreeMap<String, EncryptedOrder>,
    pub matching_batches: BTreeMap<String, PrivateMatchingBatch>,
    pub pq_risk_attestations: BTreeMap<String, PqRiskAttestation>,
    pub exercise_receipts: BTreeMap<String, ExerciseReceipt>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub rebates: BTreeMap<String, Rebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        let counters = Counters::default();
        let mut state = Self {
            config,
            counters,
            series: BTreeMap::new(),
            encrypted_orders: BTreeMap::new(),
            matching_batches: BTreeMap::new(),
            pq_risk_attestations: BTreeMap::new(),
            exercise_receipts: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            roots: empty_roots(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::default();
        let mut state = Self {
            config: config.clone(),
            ..Self::default()
        };

        let series_a = ConfidentialOptionSeries {
            series_id: series_id(
                "devnet-wxmr-call-001",
                "asset:wxmr",
                "asset:private-dusd",
                DEVNET_HEIGHT + 72_000,
            ),
            market_id: market_id("wxmr-dusd-options"),
            base_asset_id: "asset:wxmr".to_string(),
            quote_asset_id: config.quote_asset_id.clone(),
            collateral_asset_id: config.collateral_asset_id.clone(),
            option_kind: OptionKind::Call,
            option_style: OptionStyle::European,
            token_id: option_token_id("devnet-wxmr-call-001"),
            strike_commitment: commitment_id("strike", "wxmr-190-dusd"),
            expiry_height: DEVNET_HEIGHT + 72_000,
            settlement_oracle_commitment: commitment_id("oracle", "wxmr-usd-devnet-median"),
            payoff_circuit_id: circuit_id("european-call-cash-settled"),
            collateral_commitment: commitment_id("collateral", "wxmr-covered-call-pool-a"),
            metadata_ciphertext_root: ciphertext_root("series-metadata", "wxmr-call-001"),
            privacy_set_size: config.min_privacy_set_size,
            pq_policy_id: pq_policy_id("ml-kem-1024-ml-dsa-87-slh-dsa"),
            created_height: DEVNET_HEIGHT,
            active: true,
        };
        let series_b = ConfidentialOptionSeries {
            series_id: series_id(
                "devnet-wxmr-put-001",
                "asset:wxmr",
                "asset:private-dusd",
                DEVNET_HEIGHT + 72_000,
            ),
            market_id: market_id("wxmr-dusd-options"),
            base_asset_id: "asset:wxmr".to_string(),
            quote_asset_id: config.quote_asset_id.clone(),
            collateral_asset_id: config.quote_asset_id.clone(),
            option_kind: OptionKind::Put,
            option_style: OptionStyle::American,
            token_id: option_token_id("devnet-wxmr-put-001"),
            strike_commitment: commitment_id("strike", "wxmr-150-dusd"),
            expiry_height: DEVNET_HEIGHT + 72_000,
            settlement_oracle_commitment: commitment_id("oracle", "wxmr-usd-devnet-median"),
            payoff_circuit_id: circuit_id("american-put-cash-settled"),
            collateral_commitment: commitment_id("collateral", "dusd-secured-put-pool-a"),
            metadata_ciphertext_root: ciphertext_root("series-metadata", "wxmr-put-001"),
            privacy_set_size: config.min_privacy_set_size + 512,
            pq_policy_id: pq_policy_id("ml-kem-1024-ml-dsa-87-slh-dsa"),
            created_height: DEVNET_HEIGHT,
            active: true,
        };

        state
            .series
            .insert(series_a.series_id.clone(), series_a.clone());
        state
            .series
            .insert(series_b.series_id.clone(), series_b.clone());

        let order_a = sample_order(
            "alice-bid-call",
            &series_a.series_id,
            OrderSide::Bid,
            OrderStatus::SponsorReserved,
            DEVNET_HEIGHT + 1,
            &config,
        );
        let order_b = sample_order(
            "bob-ask-call",
            &series_a.series_id,
            OrderSide::Ask,
            OrderStatus::RiskAttested,
            DEVNET_HEIGHT + 1,
            &config,
        );
        let order_c = sample_order(
            "carol-bid-put",
            &series_b.series_id,
            OrderSide::Bid,
            OrderStatus::BatchQueued,
            DEVNET_HEIGHT + 2,
            &config,
        );
        let order_d = sample_order(
            "dave-ask-put",
            &series_b.series_id,
            OrderSide::Ask,
            OrderStatus::Sealed,
            DEVNET_HEIGHT + 2,
            &config,
        );

        for order in [
            order_a.clone(),
            order_b.clone(),
            order_c.clone(),
            order_d.clone(),
        ] {
            state.encrypted_orders.insert(order.order_id.clone(), order);
        }

        let attestation_a = PqRiskAttestation {
            attestation_id: risk_attestation_id(
                &series_a.series_id,
                order_a.order_id.as_str(),
                DEVNET_HEIGHT + 3,
            ),
            series_id: series_a.series_id.clone(),
            order_id: Some(order_a.order_id.clone()),
            attestor_committee_id: committee_id("devnet-options-risk-committee-a"),
            risk_model_id: risk_model_id("sabr-pq-private-v1"),
            margin_commitment: commitment_id("margin", "alice-call-margin-ok"),
            volatility_commitment: commitment_id("volatility", "wxmr-iv-band-42"),
            liquidity_commitment: commitment_id("liquidity", "wxmr-options-depth-a"),
            worst_case_loss_commitment: commitment_id("loss", "covered-call-capped"),
            pq_signature_root: ciphertext_root("pq-risk-signatures", "attestation-a"),
            security_bits: 256,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + 10_000,
        };
        let attestation_b = PqRiskAttestation {
            attestation_id: risk_attestation_id(
                &series_b.series_id,
                order_c.order_id.as_str(),
                DEVNET_HEIGHT + 3,
            ),
            series_id: series_b.series_id.clone(),
            order_id: Some(order_c.order_id.clone()),
            attestor_committee_id: committee_id("devnet-options-risk-committee-a"),
            risk_model_id: risk_model_id("jump-diffusion-pq-private-v1"),
            margin_commitment: commitment_id("margin", "carol-put-margin-ok"),
            volatility_commitment: commitment_id("volatility", "wxmr-iv-band-44"),
            liquidity_commitment: commitment_id("liquidity", "wxmr-options-depth-b"),
            worst_case_loss_commitment: commitment_id("loss", "cash-secured-put-capped"),
            pq_signature_root: ciphertext_root("pq-risk-signatures", "attestation-b"),
            security_bits: 256,
            valid_from_height: DEVNET_HEIGHT,
            valid_until_height: DEVNET_HEIGHT + 10_000,
        };
        state
            .pq_risk_attestations
            .insert(attestation_a.attestation_id.clone(), attestation_a.clone());
        state
            .pq_risk_attestations
            .insert(attestation_b.attestation_id.clone(), attestation_b.clone());

        let reservation = SponsorReservation {
            reservation_id: sponsor_reservation_id(
                "devnet-sponsor-a",
                &order_a.order_id,
                DEVNET_HEIGHT + 2,
            ),
            sponsor_id: sponsor_id("devnet-sponsor-a"),
            order_id: order_a.order_id.clone(),
            reserved_fee_commitment: commitment_id("fee-reservation", "alice-call-gas"),
            max_fee_bps: config.max_sponsor_fee_bps,
            status: ReservationStatus::Reserved,
            reservation_nullifier: nullifier_id("reservation", "alice-call-gas"),
            expires_height: DEVNET_HEIGHT + config.order_ttl_blocks,
        };
        state
            .sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());

        let batch = PrivateMatchingBatch {
            batch_id: matching_batch_id(&series_a.series_id, DEVNET_HEIGHT + 4, 0),
            market_id: series_a.market_id.clone(),
            series_id: series_a.series_id.clone(),
            status: BatchStatus::Proved,
            sealed_bid_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-BIDS",
                &[order_a.public_record()],
            ),
            sealed_ask_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-ASKS",
                &[order_b.public_record()],
            ),
            match_commitment_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-MATCHES",
                &[json!({
                    "bid_order_id": order_a.order_id,
                    "ask_order_id": order_b.order_id,
                    "match_commitment": commitment_id("match", "alice-bob-call-001")
                })],
            ),
            clearing_price_commitment: commitment_id("clearing-price", "wxmr-call-001"),
            matched_size_commitment: commitment_id("matched-size", "wxmr-call-001"),
            solver_commitment: commitment_id("solver", "solver-a"),
            proof_commitment: commitment_id("batch-proof", "call-batch-001"),
            consumed_nullifier_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-CONSUMED",
                &[Value::String(order_b.order_nullifier.clone())],
            ),
            output_note_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-OUTPUTS",
                &[json!({
                    "option_token_note": commitment_id("option-token-note", "alice-call-token"),
                    "premium_note": commitment_id("premium-note", "bob-call-premium")
                })],
            ),
            rebate_root: merkle_json_root("OPTIONS-ORDERBOOK-DEVNET-REBATES", &[]),
            privacy_set_size: config.batch_privacy_set_size,
            fee_bps: 9,
            built_height: DEVNET_HEIGHT + 4,
            settlement_deadline_height: DEVNET_HEIGHT + 4 + config.settlement_ttl_blocks,
        };
        state
            .matching_batches
            .insert(batch.batch_id.clone(), batch.clone());

        let rebate = Rebate {
            rebate_id: rebate_id(&batch.batch_id, "alice-bid-call"),
            batch_id: batch.batch_id.clone(),
            beneficiary_commitment: commitment_id("beneficiary", "alice"),
            rebate_note_commitment: commitment_id("rebate-note", "alice-low-fee-rebate"),
            rebate_bps: config.min_rebate_bps + 2,
            privacy_set_size: config.min_privacy_set_size,
            reason_code: "maker_depth".to_string(),
        };
        state
            .rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());

        let settlement = SettlementReceipt {
            receipt_id: settlement_receipt_id(&batch.batch_id, DEVNET_HEIGHT + 5),
            batch_id: batch.batch_id.clone(),
            series_id: series_a.series_id.clone(),
            input_order_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-SETTLEMENT-INPUTS",
                &[order_a.public_record(), order_b.public_record()],
            ),
            consumed_nullifier_root: batch.consumed_nullifier_root.clone(),
            minted_option_token_root: commitment_id("minted-option-token-root", "alice-call"),
            transferred_collateral_root: commitment_id("transferred-collateral-root", "bob-call"),
            fee_note_root: commitment_id("fee-note-root", "call-batch-fees"),
            rebate_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-SETTLEMENT-REBATES",
                &[rebate.public_record()],
            ),
            proof_commitment: commitment_id("settlement-proof", "call-batch-001"),
            status: ReceiptStatus::Finalized,
            settled_height: DEVNET_HEIGHT + 5,
        };
        state
            .settlement_receipts
            .insert(settlement.receipt_id.clone(), settlement);

        let exercise = ExerciseReceipt {
            receipt_id: exercise_receipt_id(
                &series_a.series_id,
                "alice-call-token",
                DEVNET_HEIGHT + 70_000,
            ),
            series_id: series_a.series_id.clone(),
            option_token_commitment: commitment_id("option-token-note", "alice-call-token"),
            holder_commitment: commitment_id("holder", "alice"),
            exercise_nullifier: nullifier_id("exercise", "alice-call-token"),
            payoff_note_commitment: commitment_id("payoff-note", "alice-call-profit"),
            settlement_price_commitment: commitment_id("settlement-price", "wxmr-210-dusd"),
            proof_commitment: commitment_id("exercise-proof", "alice-call-profit"),
            oracle_root: commitment_id("oracle-root", "wxmr-210-dusd"),
            status: ReceiptStatus::Published,
            exercised_height: DEVNET_HEIGHT + 70_000,
        };
        state
            .exercise_receipts
            .insert(exercise.receipt_id.clone(), exercise);

        let fence = PrivacyFence {
            fence_id: privacy_fence_id("devnet-options-epoch", DEVNET_HEIGHT / 720),
            scope: "tokenized_options_orderbook".to_string(),
            anchor_root: commitment_id("anchor-root", "devnet-options-epoch"),
            nullifier_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-FENCE-NULLIFIERS",
                &[
                    Value::String(order_b.order_nullifier.clone()),
                    Value::String(reservation.reservation_nullifier.clone()),
                ],
            ),
            commitment_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-DEVNET-FENCE-COMMITMENTS",
                &[series_a.public_record(), series_b.public_record()],
            ),
            min_privacy_set_size: config.min_privacy_set_size,
            epoch: DEVNET_HEIGHT / 720,
        };
        state.privacy_fences.insert(fence.fence_id.clone(), fence);
        state
            .consumed_nullifiers
            .insert(order_b.order_nullifier.clone());
        state
            .consumed_nullifiers
            .insert(reservation.reservation_nullifier.clone());

        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let roots_without_self = self.roots.public_record();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_order_scheme": PQ_ORDER_SCHEME,
            "pq_risk_scheme": PQ_RISK_SCHEME,
            "settlement_scheme": SETTLEMENT_SCHEME,
            "exercise_scheme": EXERCISE_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots_without_self,
            "series": records_from_map(&self.series),
            "encrypted_orders": records_from_map(&self.encrypted_orders),
            "matching_batches": records_from_map(&self.matching_batches),
            "pq_risk_attestations": records_from_map(&self.pq_risk_attestations),
            "exercise_receipts": records_from_map(&self.exercise_receipts),
            "settlement_receipts": records_from_map(&self.settlement_receipts),
            "sponsor_reservations": records_from_map(&self.sponsor_reservations),
            "rebates": records_from_map(&self.rebates),
            "privacy_fences": records_from_map(&self.privacy_fences),
            "consumed_nullifiers": self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>()
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn refresh_counters(&mut self) {
        self.counters.series = self.series.len() as u64;
        self.counters.encrypted_orders = self.encrypted_orders.len() as u64;
        self.counters.matching_batches = self.matching_batches.len() as u64;
        self.counters.risk_attestations = self.pq_risk_attestations.len() as u64;
        self.counters.exercise_receipts = self.exercise_receipts.len() as u64;
        self.counters.settlement_receipts = self.settlement_receipts.len() as u64;
        self.counters.sponsor_reservations = self.sponsor_reservations.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.privacy_fences = self.privacy_fences.len() as u64;
        self.counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        self.counters.open_interest_units = self
            .encrypted_orders
            .values()
            .filter(|order| order.status.matchable())
            .count() as u64;
        self.counters.matched_notional_micro_units =
            self.matching_batches.len() as u64 * 10_000_000;
        self.counters.fee_saved_micro_units = self.rebates.len() as u64 * 25_000;
    }

    pub fn refresh_roots(&mut self) {
        let config_record = self.config.public_record();
        let series_records = records_from_map(&self.series);
        let order_records = records_from_map(&self.encrypted_orders);
        let batch_records = records_from_map(&self.matching_batches);
        let risk_records = records_from_map(&self.pq_risk_attestations);
        let exercise_records = records_from_map(&self.exercise_receipts);
        let settlement_records = records_from_map(&self.settlement_receipts);
        let sponsor_records = records_from_map(&self.sponsor_reservations);
        let rebate_records = records_from_map(&self.rebates);
        let fence_records = records_from_map(&self.privacy_fences);
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .cloned()
            .map(Value::String)
            .collect::<Vec<_>>();

        let partial = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": config_record,
            "counters": self.counters.public_record(),
            "series_root": merkle_json_root("OPTIONS-ORDERBOOK-SERIES", &series_records),
            "encrypted_order_root": merkle_json_root("OPTIONS-ORDERBOOK-ENCRYPTED-ORDER", &order_records),
            "matching_batch_root": merkle_json_root("OPTIONS-ORDERBOOK-MATCHING-BATCH", &batch_records),
            "pq_risk_attestation_root": merkle_json_root("OPTIONS-ORDERBOOK-PQ-RISK-ATTESTATION", &risk_records),
            "exercise_receipt_root": merkle_json_root("OPTIONS-ORDERBOOK-EXERCISE-RECEIPT", &exercise_records),
            "settlement_receipt_root": merkle_json_root("OPTIONS-ORDERBOOK-SETTLEMENT-RECEIPT", &settlement_records),
            "sponsor_reservation_root": merkle_json_root("OPTIONS-ORDERBOOK-SPONSOR-RESERVATION", &sponsor_records),
            "rebate_root": merkle_json_root("OPTIONS-ORDERBOOK-REBATE", &rebate_records),
            "privacy_fence_root": merkle_json_root("OPTIONS-ORDERBOOK-PRIVACY-FENCE", &fence_records),
            "consumed_nullifier_root": merkle_json_root("OPTIONS-ORDERBOOK-CONSUMED-NULLIFIER", &nullifier_records)
        });

        let public_root = public_record_root(&partial);
        self.roots = Roots {
            config_root: root_from_record("OPTIONS-ORDERBOOK-CONFIG", &self.config.public_record()),
            series_root: merkle_json_root("OPTIONS-ORDERBOOK-SERIES", &series_records),
            encrypted_order_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-ENCRYPTED-ORDER",
                &order_records,
            ),
            matching_batch_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-MATCHING-BATCH",
                &batch_records,
            ),
            pq_risk_attestation_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-PQ-RISK-ATTESTATION",
                &risk_records,
            ),
            exercise_receipt_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-EXERCISE-RECEIPT",
                &exercise_records,
            ),
            settlement_receipt_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-SETTLEMENT-RECEIPT",
                &settlement_records,
            ),
            sponsor_reservation_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-SPONSOR-RESERVATION",
                &sponsor_records,
            ),
            rebate_root: merkle_json_root("OPTIONS-ORDERBOOK-REBATE", &rebate_records),
            privacy_fence_root: merkle_json_root("OPTIONS-ORDERBOOK-PRIVACY-FENCE", &fence_records),
            consumed_nullifier_root: merkle_json_root(
                "OPTIONS-ORDERBOOK-CONSUMED-NULLIFIER",
                &nullifier_records,
            ),
            public_record_root: public_root,
            state_root: state_root_from_record(&partial),
        };
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for ConfidentialOptionSeries {
    fn public_record(&self) -> Value {
        ConfidentialOptionSeries::public_record(self)
    }
}

impl PublicRecord for EncryptedOrder {
    fn public_record(&self) -> Value {
        EncryptedOrder::public_record(self)
    }
}

impl PublicRecord for PrivateMatchingBatch {
    fn public_record(&self) -> Value {
        PrivateMatchingBatch::public_record(self)
    }
}

impl PublicRecord for PqRiskAttestation {
    fn public_record(&self) -> Value {
        PqRiskAttestation::public_record(self)
    }
}

impl PublicRecord for ExerciseReceipt {
    fn public_record(&self) -> Value {
        ExerciseReceipt::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for SponsorReservation {
    fn public_record(&self) -> Value {
        SponsorReservation::public_record(self)
    }
}

impl PublicRecord for Rebate {
    fn public_record(&self) -> Value {
        Rebate::public_record(self)
    }
}

impl PublicRecord for PrivacyFence {
    fn public_record(&self) -> Value {
        PrivacyFence::public_record(self)
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-PAYLOAD-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-PUBLIC-RECORD-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn series_id(
    label: &str,
    base_asset_id: &str,
    quote_asset_id: &str,
    expiry_height: u64,
) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-SERIES-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::U64(expiry_height),
        ],
        32,
    )
}

pub fn market_id(label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-MARKET-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn option_token_id(label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-OPTION-TOKEN-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn encrypted_order_id(series_id: &str, owner_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-ENCRYPTED-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::Str(owner_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn matching_batch_id(series_id: &str, height: u64, ordinal: u64) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-MATCHING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::U64(height),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn risk_attestation_id(series_id: &str, order_id: &str, height: u64) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-PQ-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::Str(order_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn exercise_receipt_id(series_id: &str, option_token_commitment: &str, height: u64) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-EXERCISE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::Str(option_token_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, height: u64) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(sponsor_label: &str, order_id: &str, height: u64) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(order_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn rebate_id(batch_id: &str, beneficiary_label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(beneficiary_label),
        ],
        32,
    )
}

pub fn privacy_fence_id(scope: &str, epoch: u64) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn nullifier_id(scope: &str, secret_label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(secret_label),
        ],
        32,
    )
}

pub fn commitment_id(scope: &str, label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn ciphertext_root(scope: &str, label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-CIPHERTEXT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn pq_policy_id(label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-PQ-POLICY-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn circuit_id(label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-PAYOFF-CIRCUIT-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn committee_id(label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-COMMITTEE-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn risk_model_id(label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-RISK-MODEL-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn sponsor_id(label: &str) -> String {
    domain_hash(
        "OPTIONS-ORDERBOOK-SPONSOR-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn merkle_json_root(domain: &str, leaves: &[Value]) -> String {
    merkle_root(domain, leaves)
}

fn records_from_map<T: PublicRecord>(items: &BTreeMap<String, T>) -> Vec<Value> {
    items.values().map(PublicRecord::public_record).collect()
}

fn empty_roots() -> Roots {
    let empty: Vec<Value> = Vec::new();
    let empty_record = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION
    });
    Roots {
        config_root: root_from_record(
            "OPTIONS-ORDERBOOK-CONFIG",
            &Config::default().public_record(),
        ),
        series_root: merkle_json_root("OPTIONS-ORDERBOOK-SERIES", &empty),
        encrypted_order_root: merkle_json_root("OPTIONS-ORDERBOOK-ENCRYPTED-ORDER", &empty),
        matching_batch_root: merkle_json_root("OPTIONS-ORDERBOOK-MATCHING-BATCH", &empty),
        pq_risk_attestation_root: merkle_json_root("OPTIONS-ORDERBOOK-PQ-RISK-ATTESTATION", &empty),
        exercise_receipt_root: merkle_json_root("OPTIONS-ORDERBOOK-EXERCISE-RECEIPT", &empty),
        settlement_receipt_root: merkle_json_root("OPTIONS-ORDERBOOK-SETTLEMENT-RECEIPT", &empty),
        sponsor_reservation_root: merkle_json_root("OPTIONS-ORDERBOOK-SPONSOR-RESERVATION", &empty),
        rebate_root: merkle_json_root("OPTIONS-ORDERBOOK-REBATE", &empty),
        privacy_fence_root: merkle_json_root("OPTIONS-ORDERBOOK-PRIVACY-FENCE", &empty),
        consumed_nullifier_root: merkle_json_root("OPTIONS-ORDERBOOK-CONSUMED-NULLIFIER", &empty),
        public_record_root: public_record_root(&empty_record),
        state_root: state_root_from_record(&empty_record),
    }
}

fn sample_order(
    label: &str,
    series_id: &str,
    side: OrderSide,
    status: OrderStatus,
    created_height: u64,
    config: &Config,
) -> EncryptedOrder {
    let owner_commitment = commitment_id("owner", label);
    let order_id = encrypted_order_id(series_id, &owner_commitment, created_height);
    EncryptedOrder {
        order_id: order_id.clone(),
        series_id: series_id.to_string(),
        owner_commitment,
        side,
        status,
        encrypted_terms_root: ciphertext_root("order-terms", label),
        price_commitment: commitment_id("order-price", label),
        size_commitment: commitment_id("order-size", label),
        collateral_note_commitment: commitment_id("collateral-note", label),
        fee_note_commitment: commitment_id("fee-note", label),
        order_nullifier: nullifier_id("order", label),
        replay_fence_id: privacy_fence_id("order-replay", created_height / 720),
        sponsor_reservation_id: None,
        risk_attestation_id: None,
        min_fill_commitment: commitment_id("min-fill", label),
        max_fee_bps: config.max_user_fee_bps,
        privacy_set_size: config.min_privacy_set_size,
        pq_envelope_id: ciphertext_root("pq-envelope", label),
        created_height,
        expiry_height: created_height + config.order_ttl_blocks,
    }
}
