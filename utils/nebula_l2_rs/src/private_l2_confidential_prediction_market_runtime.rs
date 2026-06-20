use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialPredictionMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-prediction-market-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-prediction-market-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 744_000;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_MARKETS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_OUTCOMES: usize = 2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_ORDERS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 256;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize =
    1_024;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 22;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 14;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MARKET_TTL_BLOCKS: u64 = 43_200;
pub const PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionMarketKind {
    Binary,
    Scalar,
    Categorical,
    Parimutuel,
    Conditional,
    OracleResolved,
    GovernanceSignal,
    BridgeRisk,
}

impl PredictionMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Scalar => "scalar",
            Self::Categorical => "categorical",
            Self::Parimutuel => "parimutuel",
            Self::Conditional => "conditional",
            Self::OracleResolved => "oracle_resolved",
            Self::GovernanceSignal => "governance_signal",
            Self::BridgeRisk => "bridge_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Proposed,
    Active,
    Paused,
    Resolving,
    Resolved,
    Disputed,
    Cancelled,
}

impl MarketStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    Proposed,
    Tradeable,
    Suspended,
    Winning,
    Losing,
    Invalidated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Buy,
    Sell,
    MintSet,
    RedeemSet,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
            Self::MintSet => "mint_set",
            Self::RedeemSet => "redeem_set",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Submitted,
    Accepted,
    Matched,
    PartiallyMatched,
    Settled,
    Cancelled,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Low,
    Medium,
    High,
    Pause,
    Cancel,
    Escalate,
}

impl RiskVerdict {
    pub fn allows_market(self) -> bool {
        matches!(self, Self::Low | Self::Medium)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Matching,
    Settled,
    PartiallySettled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    MarketOpened,
    OutcomeRegistered,
    OrderAccepted,
    OrderMatched,
    BatchSettled,
    MarketResolved,
    RebatePaid,
    DisputeRaised,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_markets: usize,
    pub max_outcomes: usize,
    pub max_orders: usize,
    pub max_risk_attestations: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub min_privacy_set: usize,
    pub batch_privacy_set: usize,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub market_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_PQ_AUTH_SUITE
                .to_string(),
            max_markets: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_MARKETS,
            max_outcomes: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_OUTCOMES,
            max_orders: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_ORDERS,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_sponsor_reservations:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            market_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_MARKET_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.chain_id.is_empty()
            || self.protocol_version.is_empty()
            || self.hash_suite.is_empty()
            || self.pq_auth_suite.is_empty()
        {
            return Err("prediction market config identifiers cannot be empty".to_string());
        }
        if self.schema_version == 0 || self.devnet_height == 0 {
            return Err("prediction market config version/height must be positive".to_string());
        }
        if self.max_markets == 0
            || self.max_outcomes == 0
            || self.max_orders == 0
            || self.max_risk_attestations == 0
            || self.max_sponsor_reservations == 0
            || self.max_batches == 0
            || self.max_receipts == 0
        {
            return Err("prediction market config capacities must be positive".to_string());
        }
        if self.min_privacy_set == 0 || self.batch_privacy_set < self.min_privacy_set {
            return Err("prediction market privacy set bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("prediction market pq security target is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_MAX_BPS
            || self.target_rebate_bps > PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_MAX_BPS
        {
            return Err("prediction market fee/rebate bps exceed max".to_string());
        }
        if self.market_ttl_blocks == 0 || self.reservation_ttl_blocks == 0 {
            return Err("prediction market ttl windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_market_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "max_markets": self.max_markets,
            "max_outcomes": self.max_outcomes,
            "max_orders": self.max_orders,
            "max_risk_attestations": self.max_risk_attestations,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "min_privacy_set": self.min_privacy_set,
            "batch_privacy_set": self.batch_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "market_ttl_blocks": self.market_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets_opened: u64,
    pub outcomes_registered: u64,
    pub orders_submitted: u64,
    pub risk_attestations_posted: u64,
    pub sponsor_reservations_opened: u64,
    pub settlement_batches_built: u64,
    pub receipts_published: u64,
    pub rebates_published: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_market_counters",
            "markets_opened": self.markets_opened,
            "outcomes_registered": self.outcomes_registered,
            "orders_submitted": self.orders_submitted,
            "risk_attestations_posted": self.risk_attestations_posted,
            "sponsor_reservations_opened": self.sponsor_reservations_opened,
            "settlement_batches_built": self.settlement_batches_built,
            "receipts_published": self.receipts_published,
            "rebates_published": self.rebates_published,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPredictionMarketRequest {
    pub market_kind: PredictionMarketKind,
    pub creator_commitment: String,
    pub collateral_asset_id: String,
    pub market_metadata_root: String,
    pub oracle_committee_root: String,
    pub question_commitment: String,
    pub outcome_count: u16,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub resolves_after_height: u64,
    pub fee_bps: u64,
    pub privacy_set_size: usize,
    pub pq_creator_auth_root: String,
}

impl OpenPredictionMarketRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "open_prediction_market_request",
            "market_kind": self.market_kind.as_str(),
            "creator_commitment": self.creator_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "market_metadata_root": self.market_metadata_root,
            "oracle_committee_root": self.oracle_committee_root,
            "question_commitment": self.question_commitment,
            "outcome_count": self.outcome_count,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "resolves_after_height": self.resolves_after_height,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_creator_auth_root": self.pq_creator_auth_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterOutcomeRequest {
    pub market_id: String,
    pub outcome_index: u16,
    pub outcome_commitment: String,
    pub payout_hint_root: String,
    pub metadata_root: String,
    pub maker_commitment: String,
    pub pq_authorization_root: String,
}

impl RegisterOutcomeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "register_prediction_outcome_request",
            "market_id": self.market_id,
            "outcome_index": self.outcome_index,
            "outcome_commitment": self.outcome_commitment,
            "payout_hint_root": self.payout_hint_root,
            "metadata_root": self.metadata_root,
            "maker_commitment": self.maker_commitment,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPrivateOrderRequest {
    pub market_id: String,
    pub outcome_id: String,
    pub side: OrderSide,
    pub trader_commitment: String,
    pub encrypted_order_note_root: String,
    pub price_commitment: String,
    pub size_commitment: String,
    pub collateral_note_root: String,
    pub nullifier: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: usize,
    pub expires_at_height: u64,
    pub pq_authorization_root: String,
}

impl SubmitPrivateOrderRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "submit_private_prediction_order_request",
            "market_id": self.market_id,
            "outcome_id": self.outcome_id,
            "side": self.side.as_str(),
            "trader_commitment": self.trader_commitment,
            "encrypted_order_note_root": self.encrypted_order_note_root,
            "price_commitment": self.price_commitment,
            "size_commitment": self.size_commitment,
            "collateral_note_root": self.collateral_note_root,
            "nullifier": self.nullifier,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_height": self.expires_at_height,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestPredictionRiskRequest {
    pub market_id: String,
    pub attester_commitment: String,
    pub verdict: RiskVerdict,
    pub risk_window_start: u64,
    pub risk_window_end: u64,
    pub oracle_feed_root: String,
    pub evidence_root: String,
    pub pq_attestation_root: String,
    pub min_pq_security_bits: u16,
}

impl AttestPredictionRiskRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "attest_prediction_risk_request",
            "market_id": self.market_id,
            "attester_commitment": self.attester_commitment,
            "verdict": format!("{:?}", self.verdict).to_lowercase(),
            "risk_window_start": self.risk_window_start,
            "risk_window_end": self.risk_window_end,
            "oracle_feed_root": self.oracle_feed_root,
            "evidence_root": self.evidence_root,
            "pq_attestation_root": self.pq_attestation_root,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReservePredictionFeeSponsorRequest {
    pub market_id: String,
    pub order_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub coverage_bps: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: usize,
    pub pq_sponsor_auth_root: String,
}

impl ReservePredictionFeeSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_prediction_fee_sponsor_request",
            "market_id": self.market_id,
            "order_id": self.order_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "coverage_bps": self.coverage_bps,
            "expires_at_height": self.expires_at_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_sponsor_auth_root": self.pq_sponsor_auth_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildPredictionSettlementBatchRequest {
    pub market_id: String,
    pub batch_height: u64,
    pub order_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub risk_attestation_ids: Vec<String>,
    pub matching_engine_root: String,
    pub encrypted_netting_root: String,
    pub settlement_proof_root: String,
    pub pq_batch_authorization_root: String,
    pub batch_privacy_set_size: usize,
}

impl BuildPredictionSettlementBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "build_prediction_settlement_batch_request",
            "market_id": self.market_id,
            "batch_height": self.batch_height,
            "order_ids": self.order_ids,
            "reservation_ids": self.reservation_ids,
            "risk_attestation_ids": self.risk_attestation_ids,
            "matching_engine_root": self.matching_engine_root,
            "encrypted_netting_root": self.encrypted_netting_root,
            "settlement_proof_root": self.settlement_proof_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishPredictionReceiptRequest {
    pub market_id: String,
    pub batch_id: String,
    pub receipt_kind: ReceiptKind,
    pub outcome_id: Option<String>,
    pub order_id: Option<String>,
    pub recipient_commitment: String,
    pub settlement_root: String,
    pub fee_charged_bps: u64,
    pub rebate_bps: u64,
    pub pq_receipt_root: String,
}

impl PublishPredictionReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "publish_prediction_receipt_request",
            "market_id": self.market_id,
            "batch_id": self.batch_id,
            "receipt_kind": format!("{:?}", self.receipt_kind).to_lowercase(),
            "outcome_id": self.outcome_id,
            "order_id": self.order_id,
            "recipient_commitment": self.recipient_commitment,
            "settlement_root": self.settlement_root,
            "fee_charged_bps": self.fee_charged_bps,
            "rebate_bps": self.rebate_bps,
            "pq_receipt_root": self.pq_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishPredictionRebateRequest {
    pub market_id: String,
    pub reservation_id: String,
    pub receipt_id: String,
    pub sponsor_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub pq_rebate_root: String,
}

impl PublishPredictionRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "publish_prediction_rebate_request",
            "market_id": self.market_id,
            "reservation_id": self.reservation_id,
            "receipt_id": self.receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "pq_rebate_root": self.pq_rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionMarketRecord {
    pub market_id: String,
    pub request: OpenPredictionMarketRequest,
    pub status: MarketStatus,
    pub created_sequence: u64,
    pub outcome_ids: Vec<String>,
    pub latest_risk_attestation_id: Option<String>,
}

impl PredictionMarketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_market",
            "market_id": self.market_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "outcome_ids": self.outcome_ids,
            "latest_risk_attestation_id": self.latest_risk_attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionOutcomeRecord {
    pub outcome_id: String,
    pub request: RegisterOutcomeRequest,
    pub status: OutcomeStatus,
    pub created_sequence: u64,
}

impl PredictionOutcomeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_outcome",
            "outcome_id": self.outcome_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivatePredictionOrderRecord {
    pub order_id: String,
    pub request: SubmitPrivateOrderRequest,
    pub status: OrderStatus,
    pub created_sequence: u64,
    pub matched_batch_id: Option<String>,
}

impl PrivatePredictionOrderRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_order",
            "order_id": self.order_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "matched_batch_id": self.matched_batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionRiskAttestationRecord {
    pub attestation_id: String,
    pub request: AttestPredictionRiskRequest,
    pub created_sequence: u64,
}

impl PredictionRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_risk_attestation",
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReservePredictionFeeSponsorRequest,
    pub status: SponsorReservationStatus,
    pub created_sequence: u64,
    pub consumed_by_batch_id: Option<String>,
}

impl PredictionSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "consumed_by_batch_id": self.consumed_by_batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionSettlementBatchRecord {
    pub batch_id: String,
    pub request: BuildPredictionSettlementBatchRequest,
    pub status: BatchStatus,
    pub created_sequence: u64,
}

impl PredictionSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_settlement_batch",
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionReceiptRecord {
    pub receipt_id: String,
    pub request: PublishPredictionReceiptRequest,
    pub created_sequence: u64,
}

impl PredictionReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PredictionRebateRecord {
    pub rebate_id: String,
    pub request: PublishPredictionRebateRequest,
    pub created_sequence: u64,
}

impl PredictionRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_rebate",
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub market_root: String,
    pub outcome_root: String,
    pub order_root: String,
    pub risk_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_market_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "market_root": self.market_root,
            "outcome_root": self.outcome_root,
            "order_root": self.order_root,
            "risk_attestation_root": self.risk_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub markets: BTreeMap<String, PredictionMarketRecord>,
    pub outcomes: BTreeMap<String, PredictionOutcomeRecord>,
    pub orders: BTreeMap<String, PrivatePredictionOrderRecord>,
    pub risk_attestations: BTreeMap<String, PredictionRiskAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, PredictionSponsorReservationRecord>,
    pub settlement_batches: BTreeMap<String, PredictionSettlementBatchRecord>,
    pub receipts: BTreeMap<String, PredictionReceiptRecord>,
    pub rebates: BTreeMap<String, PredictionRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialPredictionMarketRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            markets: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            orders: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn open_market(
        &mut self,
        request: OpenPredictionMarketRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_market_capacity()?;
        require_nonempty("creator_commitment", &request.creator_commitment)?;
        require_nonempty("collateral_asset_id", &request.collateral_asset_id)?;
        require_nonempty("market_metadata_root", &request.market_metadata_root)?;
        require_nonempty("oracle_committee_root", &request.oracle_committee_root)?;
        require_nonempty("question_commitment", &request.question_commitment)?;
        require_nonempty("pq_creator_auth_root", &request.pq_creator_auth_root)?;
        if request.outcome_count < 2 {
            return Err("prediction market must have at least two outcomes".to_string());
        }
        if request.opens_at_height >= request.closes_at_height
            || request.closes_at_height >= request.resolves_after_height
        {
            return Err("prediction market height windows are invalid".to_string());
        }
        if request.fee_bps > self.config.max_user_fee_bps {
            return Err("prediction market fee exceeds configured max".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("prediction market privacy set is too small".to_string());
        }
        let sequence = self.counters.markets_opened.saturating_add(1);
        let market_id = prediction_market_id(&request, sequence);
        if self.markets.contains_key(&market_id) {
            return Err("prediction market id collision".to_string());
        }
        let record = PredictionMarketRecord {
            market_id: market_id.clone(),
            request,
            status: MarketStatus::Active,
            created_sequence: sequence,
            outcome_ids: Vec::new(),
            latest_risk_attestation_id: None,
        };
        self.markets.insert(market_id.clone(), record);
        self.counters.markets_opened = sequence;
        Ok(market_id)
    }

    pub fn register_outcome(
        &mut self,
        request: RegisterOutcomeRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_outcome_capacity()?;
        require_nonempty("market_id", &request.market_id)?;
        require_nonempty("outcome_commitment", &request.outcome_commitment)?;
        require_nonempty("payout_hint_root", &request.payout_hint_root)?;
        require_nonempty("metadata_root", &request.metadata_root)?;
        require_nonempty("maker_commitment", &request.maker_commitment)?;
        require_nonempty("pq_authorization_root", &request.pq_authorization_root)?;
        let market = self
            .markets
            .get_mut(&request.market_id)
            .ok_or_else(|| "prediction market not found".to_string())?;
        if !market.status.accepts_orders() {
            return Err("prediction market is not accepting outcomes".to_string());
        }
        if request.outcome_index >= market.request.outcome_count {
            return Err("prediction outcome index exceeds market count".to_string());
        }
        let sequence = self.counters.outcomes_registered.saturating_add(1);
        let outcome_id = prediction_outcome_id(&request, sequence);
        if self.outcomes.contains_key(&outcome_id) || market.outcome_ids.contains(&outcome_id) {
            return Err("prediction outcome id collision".to_string());
        }
        let record = PredictionOutcomeRecord {
            outcome_id: outcome_id.clone(),
            request,
            status: OutcomeStatus::Tradeable,
            created_sequence: sequence,
        };
        market.outcome_ids.push(outcome_id.clone());
        self.outcomes.insert(outcome_id.clone(), record);
        self.counters.outcomes_registered = sequence;
        Ok(outcome_id)
    }

    pub fn submit_private_order(
        &mut self,
        request: SubmitPrivateOrderRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_order_capacity()?;
        require_nonempty("market_id", &request.market_id)?;
        require_nonempty("outcome_id", &request.outcome_id)?;
        require_nonempty("trader_commitment", &request.trader_commitment)?;
        require_nonempty(
            "encrypted_order_note_root",
            &request.encrypted_order_note_root,
        )?;
        require_nonempty("price_commitment", &request.price_commitment)?;
        require_nonempty("size_commitment", &request.size_commitment)?;
        require_nonempty("collateral_note_root", &request.collateral_note_root)?;
        require_nonempty("nullifier", &request.nullifier)?;
        require_nonempty("pq_authorization_root", &request.pq_authorization_root)?;
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err("prediction order nullifier already consumed".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "prediction market not found".to_string())?;
        if !market.status.accepts_orders() {
            return Err("prediction market is not accepting private orders".to_string());
        }
        let outcome = self
            .outcomes
            .get(&request.outcome_id)
            .ok_or_else(|| "prediction outcome not found".to_string())?;
        if outcome.request.market_id != request.market_id {
            return Err("prediction outcome belongs to another market".to_string());
        }
        if outcome.status != OutcomeStatus::Tradeable {
            return Err("prediction outcome is not tradeable".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("prediction order max fee exceeds configured max".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("prediction order privacy set is too small".to_string());
        }
        let sequence = self.counters.orders_submitted.saturating_add(1);
        let order_id = private_prediction_order_id(&request, sequence);
        if self.orders.contains_key(&order_id) {
            return Err("prediction order id collision".to_string());
        }
        let nullifier = request.nullifier.clone();
        let record = PrivatePredictionOrderRecord {
            order_id: order_id.clone(),
            request,
            status: OrderStatus::Accepted,
            created_sequence: sequence,
            matched_batch_id: None,
        };
        self.consumed_nullifiers.insert(nullifier);
        self.orders.insert(order_id.clone(), record);
        self.counters.orders_submitted = sequence;
        Ok(order_id)
    }

    pub fn attest_risk(
        &mut self,
        request: AttestPredictionRiskRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_risk_capacity()?;
        require_nonempty("market_id", &request.market_id)?;
        require_nonempty("attester_commitment", &request.attester_commitment)?;
        require_nonempty("oracle_feed_root", &request.oracle_feed_root)?;
        require_nonempty("evidence_root", &request.evidence_root)?;
        require_nonempty("pq_attestation_root", &request.pq_attestation_root)?;
        if request.risk_window_start >= request.risk_window_end {
            return Err("prediction risk window is invalid".to_string());
        }
        if request.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("prediction risk pq security below runtime target".to_string());
        }
        let sequence = self.counters.risk_attestations_posted.saturating_add(1);
        let attestation_id = prediction_risk_attestation_id(&request, sequence);
        if self.risk_attestations.contains_key(&attestation_id) {
            return Err("prediction risk attestation id collision".to_string());
        }
        let market = self
            .markets
            .get_mut(&request.market_id)
            .ok_or_else(|| "prediction market not found".to_string())?;
        if !request.verdict.allows_market() {
            market.status = match request.verdict {
                RiskVerdict::Pause | RiskVerdict::Escalate => MarketStatus::Paused,
                RiskVerdict::Cancel => MarketStatus::Cancelled,
                _ => market.status,
            };
        }
        let record = PredictionRiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            created_sequence: sequence,
        };
        market.latest_risk_attestation_id = Some(attestation_id.clone());
        self.risk_attestations
            .insert(attestation_id.clone(), record);
        self.counters.risk_attestations_posted = sequence;
        Ok(attestation_id)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReservePredictionFeeSponsorRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_reservation_capacity()?;
        require_nonempty("market_id", &request.market_id)?;
        require_nonempty("order_id", &request.order_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("fee_asset_id", &request.fee_asset_id)?;
        require_nonempty("pq_sponsor_auth_root", &request.pq_sponsor_auth_root)?;
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("prediction sponsor fee exceeds configured max".to_string());
        }
        if request.coverage_bps > PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_MAX_BPS {
            return Err("prediction sponsor coverage exceeds max bps".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("prediction sponsor privacy set is too small".to_string());
        }
        let order = self
            .orders
            .get(&request.order_id)
            .ok_or_else(|| "prediction order not found".to_string())?;
        if order.request.market_id != request.market_id {
            return Err("prediction sponsor order belongs to another market".to_string());
        }
        if order.status != OrderStatus::Accepted {
            return Err("prediction sponsor order is not sponsorable".to_string());
        }
        let sequence = self.counters.sponsor_reservations_opened.saturating_add(1);
        let reservation_id = prediction_sponsor_reservation_id(&request, sequence);
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err("prediction sponsor reservation id collision".to_string());
        }
        let record = PredictionSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: SponsorReservationStatus::Reserved,
            created_sequence: sequence,
            consumed_by_batch_id: None,
        };
        self.sponsor_reservations
            .insert(reservation_id.clone(), record);
        self.counters.sponsor_reservations_opened = sequence;
        Ok(reservation_id)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildPredictionSettlementBatchRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_batch_capacity()?;
        require_nonempty("market_id", &request.market_id)?;
        require_nonempty("matching_engine_root", &request.matching_engine_root)?;
        require_nonempty("encrypted_netting_root", &request.encrypted_netting_root)?;
        require_nonempty("settlement_proof_root", &request.settlement_proof_root)?;
        require_nonempty(
            "pq_batch_authorization_root",
            &request.pq_batch_authorization_root,
        )?;
        require_unique("prediction batch order ids", &request.order_ids)?;
        require_unique("prediction batch reservation ids", &request.reservation_ids)?;
        require_unique(
            "prediction batch risk attestation ids",
            &request.risk_attestation_ids,
        )?;
        if request.order_ids.is_empty() {
            return Err("prediction settlement batch needs orders".to_string());
        }
        if request.batch_privacy_set_size < self.config.batch_privacy_set {
            return Err("prediction settlement batch privacy set is too small".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "prediction market not found".to_string())?;
        if !matches!(
            market.status,
            MarketStatus::Active | MarketStatus::Resolving | MarketStatus::Disputed
        ) {
            return Err("prediction market cannot settle batches".to_string());
        }
        for order_id in &request.order_ids {
            let order = self
                .orders
                .get(order_id)
                .ok_or_else(|| format!("prediction batch order {order_id} not found"))?;
            if order.request.market_id != request.market_id {
                return Err("prediction batch order belongs to another market".to_string());
            }
            if !matches!(
                order.status,
                OrderStatus::Accepted | OrderStatus::PartiallyMatched
            ) {
                return Err("prediction batch order is not matchable".to_string());
            }
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .sponsor_reservations
                .get(reservation_id)
                .ok_or_else(|| format!("prediction reservation {reservation_id} not found"))?;
            if reservation.request.market_id != request.market_id {
                return Err("prediction reservation belongs to another market".to_string());
            }
            if reservation.status != SponsorReservationStatus::Reserved {
                return Err("prediction reservation is not active".to_string());
            }
        }
        for attestation_id in &request.risk_attestation_ids {
            let attestation = self
                .risk_attestations
                .get(attestation_id)
                .ok_or_else(|| format!("prediction risk attestation {attestation_id} not found"))?;
            if attestation.request.market_id != request.market_id {
                return Err("prediction risk attestation belongs to another market".to_string());
            }
        }
        let sequence = self.counters.settlement_batches_built.saturating_add(1);
        let batch_id = prediction_settlement_batch_id(&request, sequence);
        if self.settlement_batches.contains_key(&batch_id) {
            return Err("prediction settlement batch id collision".to_string());
        }
        for order_id in &request.order_ids {
            if let Some(order) = self.orders.get_mut(order_id) {
                order.status = OrderStatus::Matched;
                order.matched_batch_id = Some(batch_id.clone());
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
                reservation.consumed_by_batch_id = Some(batch_id.clone());
            }
        }
        let record = PredictionSettlementBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: BatchStatus::Matching,
            created_sequence: sequence,
        };
        self.settlement_batches.insert(batch_id.clone(), record);
        self.counters.settlement_batches_built = sequence;
        Ok(batch_id)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishPredictionReceiptRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_receipt_capacity()?;
        require_nonempty("market_id", &request.market_id)?;
        require_nonempty("batch_id", &request.batch_id)?;
        require_nonempty("recipient_commitment", &request.recipient_commitment)?;
        require_nonempty("settlement_root", &request.settlement_root)?;
        require_nonempty("pq_receipt_root", &request.pq_receipt_root)?;
        if request.fee_charged_bps > self.config.max_user_fee_bps {
            return Err("prediction receipt fee exceeds configured max".to_string());
        }
        if request.rebate_bps > PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_MAX_BPS {
            return Err("prediction receipt rebate exceeds max bps".to_string());
        }
        let batch = self
            .settlement_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "prediction settlement batch not found".to_string())?;
        if batch.request.market_id != request.market_id {
            return Err("prediction receipt batch belongs to another market".to_string());
        }
        batch.status = BatchStatus::Settled;
        for order_id in &batch.request.order_ids {
            if let Some(order) = self.orders.get_mut(order_id) {
                order.status = OrderStatus::Settled;
            }
        }
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt_id = prediction_receipt_id(&request, sequence);
        if self.receipts.contains_key(&receipt_id) {
            return Err("prediction receipt id collision".to_string());
        }
        let record = PredictionReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            created_sequence: sequence,
        };
        self.receipts.insert(receipt_id.clone(), record);
        self.counters.receipts_published = sequence;
        Ok(receipt_id)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishPredictionRebateRequest,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<String> {
        self.require_receipt_capacity()?;
        require_nonempty("market_id", &request.market_id)?;
        require_nonempty("reservation_id", &request.reservation_id)?;
        require_nonempty("receipt_id", &request.receipt_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("rebate_note_root", &request.rebate_note_root)?;
        require_nonempty("pq_rebate_root", &request.pq_rebate_root)?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("prediction rebate exceeds runtime target".to_string());
        }
        let reservation = self
            .sponsor_reservations
            .get_mut(&request.reservation_id)
            .ok_or_else(|| "prediction sponsor reservation not found".to_string())?;
        if reservation.request.market_id != request.market_id {
            return Err("prediction rebate reservation belongs to another market".to_string());
        }
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("prediction rebate receipt not found".to_string());
        }
        reservation.status = SponsorReservationStatus::RebateQueued;
        let sequence = self.counters.rebates_published.saturating_add(1);
        let rebate_id = prediction_rebate_id(&request, sequence);
        if self.rebates.contains_key(&rebate_id) {
            return Err("prediction rebate id collision".to_string());
        }
        let record = PredictionRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            created_sequence: sequence,
        };
        self.rebates.insert(rebate_id.clone(), record);
        self.counters.rebates_published = sequence;
        Ok(rebate_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: root_from_record(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-COUNTERS",
                &self.counters.public_record(),
            ),
            market_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-MARKETS",
                &self
                    .markets
                    .values()
                    .map(PredictionMarketRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            outcome_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-OUTCOMES",
                &self
                    .outcomes
                    .values()
                    .map(PredictionOutcomeRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            order_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-ORDERS",
                &self
                    .orders
                    .values()
                    .map(PrivatePredictionOrderRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            risk_attestation_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-RISK-ATTESTATIONS",
                &self
                    .risk_attestations
                    .values()
                    .map(PredictionRiskAttestationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            sponsor_reservation_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-SPONSOR-RESERVATIONS",
                &self
                    .sponsor_reservations
                    .values()
                    .map(PredictionSponsorReservationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_batch_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-SETTLEMENT-BATCHES",
                &self
                    .settlement_batches
                    .values()
                    .map(PredictionSettlementBatchRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-RECEIPTS",
                &self
                    .receipts
                    .values()
                    .map(PredictionReceiptRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: public_record_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-REBATES",
                &self
                    .rebates
                    .values()
                    .map(PredictionRebateRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_prediction_market_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "consumed_nullifier_root": id_list_root(
                "PRIVATE-L2-CONFIDENTIAL-PREDICTION-CONSUMED-NULLIFIERS",
                self.consumed_nullifiers.iter(),
            ),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn require_market_capacity(&self) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.markets.len() >= self.config.max_markets {
            return Err("prediction market capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_outcome_capacity(&self) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.outcomes.len() >= self.config.max_outcomes {
            return Err("prediction outcome capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_order_capacity(&self) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.orders.len() >= self.config.max_orders {
            return Err("prediction order capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_risk_capacity(&self) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("prediction risk attestation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_reservation_capacity(
        &self,
    ) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("prediction sponsor reservation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_batch_capacity(&self) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.settlement_batches.len() >= self.config.max_batches {
            return Err("prediction settlement batch capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_receipt_capacity(&self) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("prediction receipt capacity exhausted".to_string());
        }
        Ok(())
    }
}

pub type Runtime = State;

pub fn prediction_market_id(request: &OpenPredictionMarketRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-MARKET-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn prediction_outcome_id(request: &RegisterOutcomeRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-OUTCOME-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn private_prediction_order_id(request: &SubmitPrivateOrderRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-ORDER-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn prediction_risk_attestation_id(
    request: &AttestPredictionRiskRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-RISK-ATTESTATION-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn prediction_sponsor_reservation_id(
    request: &ReservePredictionFeeSponsorRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-SPONSOR-RESERVATION-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn prediction_settlement_batch_id(
    request: &BuildPredictionSettlementBatchRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-SETTLEMENT-BATCH-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn prediction_receipt_id(request: &PublishPredictionReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-RECEIPT-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn prediction_rebate_id(request: &PublishPredictionRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-REBATE-ID",
        &json!({
            "sequence": sequence,
            "request": request.public_record(),
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            Value::String(root_from_record(
                domain,
                &json!({
                    "index": index,
                    "record": record,
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PREDICTION-MARKET-STATE-ROOT",
        record,
    )
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_PREDICTION_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn id_list_root<'a, I>(domain: &str, ids: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = ids
        .enumerate()
        .map(|(index, id)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::U64(index as u64), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_nonempty(
    field: &str,
    value: &str,
) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn require_unique(
    field: &str,
    values: &[String],
) -> PrivateL2ConfidentialPredictionMarketRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!("{field} cannot contain empty ids"));
        }
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate id {value}"));
        }
    }
    Ok(())
}
