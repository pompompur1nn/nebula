use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialRfqMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-rfq-market-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-rfq-v1";
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 904_000;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_PAIRS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_QUOTES: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_ORDERS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_TAKER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_MAKER_FEE_BPS: u64 = 6;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 72;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RfqVenueKind {
    PrivateTokenSwap,
    PrivateStableSwap,
    PrivateLendingRefinance,
    PrivatePerpHedge,
    PrivateOptionsExercise,
    ContractTreasuryRebalance,
    MoneroBridgeLiquidity,
    CrossRollupInventory,
}

impl RfqVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTokenSwap => "private_token_swap",
            Self::PrivateStableSwap => "private_stable_swap",
            Self::PrivateLendingRefinance => "private_lending_refinance",
            Self::PrivatePerpHedge => "private_perp_hedge",
            Self::PrivateOptionsExercise => "private_options_exercise",
            Self::ContractTreasuryRebalance => "contract_treasury_rebalance",
            Self::MoneroBridgeLiquidity => "monero_bridge_liquidity",
            Self::CrossRollupInventory => "cross_rollup_inventory",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairStatus {
    Open,
    Paused,
    Draining,
    Retired,
}

impl PairStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteSide {
    BuyBase,
    SellBase,
    TwoSided,
}

impl QuoteSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuyBase => "buy_base",
            Self::SellBase => "sell_base",
            Self::TwoSided => "two_sided",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Reserved,
    Filled,
    Cancelled,
    Expired,
    Disputed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FillStatus {
    Pending,
    Batched,
    Settled,
    Reverted,
    Disputed,
}

impl FillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Eligible,
    RiskLimited,
    Quarantined,
    Rejected,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::RiskLimited => "risk_limited",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Recorded,
    Applied,
    Superseded,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Open,
    Sealed,
    Settled,
    Disputed,
    Expired,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    FillSettlement,
    MakerRebate,
    TakerRebate,
    SponsorSettlement,
    DisputeResolution,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FillSettlement => "fill_settlement",
            Self::MakerRebate => "maker_rebate",
            Self::TakerRebate => "taker_rebate",
            Self::SponsorSettlement => "sponsor_settlement",
            Self::DisputeResolution => "dispute_resolution",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub schema_version: u64,
    pub devnet_height: u64,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub max_pairs: usize,
    pub max_quotes: usize,
    pub max_fills: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_taker_fee_bps: u64,
    pub max_maker_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            schema_version: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEVNET_HEIGHT,
            fee_asset_id: "piconero-devnet".to_string(),
            settlement_asset_id: "wxmr-devnet".to_string(),
            max_pairs: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_PAIRS,
            max_quotes: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_QUOTES,
            max_fills: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_ORDERS,
            max_attestations: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_reservations: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_REBATES,
            max_batch_items: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_taker_fee_bps: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_TAKER_FEE_BPS,
            max_maker_fee_bps: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_MAKER_FEE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            quote_ttl_blocks: PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("settlement_asset_id", &self.settlement_asset_id)?;
        ensure_positive_usize("max_pairs", self.max_pairs)?;
        ensure_positive_usize("max_quotes", self.max_quotes)?;
        ensure_positive_usize("max_fills", self.max_fills)?;
        ensure_positive_usize("max_attestations", self.max_attestations)?;
        ensure_positive_usize("max_reservations", self.max_reservations)?;
        ensure_positive_usize("max_batches", self.max_batches)?;
        ensure_positive_usize("max_receipts", self.max_receipts)?;
        ensure_positive_usize("max_rebates", self.max_rebates)?;
        ensure_positive_usize("max_batch_items", self.max_batch_items)?;
        ensure_min_u64("min_privacy_set_size", self.min_privacy_set_size, 128)?;
        ensure_min_u64(
            "batch_privacy_set_size",
            self.batch_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        if self.min_pq_security_bits
            < PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("RFQ market PQ security bits below configured floor".to_string());
        }
        ensure_bps("max_taker_fee_bps", self.max_taker_fee_bps)?;
        ensure_bps("max_maker_fee_bps", self.max_maker_fee_bps)?;
        ensure_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_positive_u64("quote_ttl_blocks", self.quote_ttl_blocks)?;
        ensure_positive_u64("reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        ensure_positive_u64("settlement_ttl_blocks", self.settlement_ttl_blocks)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "fee_asset_id": self.fee_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "max_pairs": self.max_pairs,
            "max_quotes": self.max_quotes,
            "max_fills": self.max_fills,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_taker_fee_bps": self.max_taker_fee_bps,
            "max_maker_fee_bps": self.max_maker_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pairs_opened: u64,
    pub quotes_submitted: u64,
    pub fills_accepted: u64,
    pub attestations_recorded: u64,
    pub reservations_opened: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub rebates_published: u64,
    pub stale_records_expired: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pairs_opened": self.pairs_opened,
            "quotes_submitted": self.quotes_submitted,
            "fills_accepted": self.fills_accepted,
            "attestations_recorded": self.attestations_recorded,
            "reservations_opened": self.reservations_opened,
            "batches_built": self.batches_built,
            "receipts_published": self.receipts_published,
            "rebates_published": self.rebates_published,
            "stale_records_expired": self.stale_records_expired,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenRfqPairRequest {
    pub venue_kind: RfqVenueKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub maker_commitment_root: String,
    pub inventory_commitment_root: String,
    pub price_oracle_root: String,
    pub compliance_rule_root: String,
    pub pq_maker_auth_root: String,
    pub min_order_units: u128,
    pub max_order_units: u128,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
}

impl OpenRfqPairRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_kind": self.venue_kind.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "maker_commitment_root": self.maker_commitment_root,
            "inventory_commitment_root": self.inventory_commitment_root,
            "price_oracle_root": self.price_oracle_root,
            "compliance_rule_root": self.compliance_rule_root,
            "pq_maker_auth_root": self.pq_maker_auth_root,
            "min_order_units": self.min_order_units.to_string(),
            "max_order_units": self.max_order_units.to_string(),
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitConfidentialQuoteRequest {
    pub pair_id: String,
    pub side: QuoteSide,
    pub maker_commitment: String,
    pub encrypted_quote_note_root: String,
    pub price_commitment_root: String,
    pub size_commitment_root: String,
    pub quote_nullifier: String,
    pub pq_quote_auth_root: String,
    pub fee_sponsor_policy_root: String,
    pub privacy_set_size: u64,
    pub taker_fee_bps: u64,
    pub expires_at_height: u64,
}

impl SubmitConfidentialQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pair_id": self.pair_id,
            "side": self.side.as_str(),
            "maker_commitment": self.maker_commitment,
            "encrypted_quote_note_root": self.encrypted_quote_note_root,
            "price_commitment_root": self.price_commitment_root,
            "size_commitment_root": self.size_commitment_root,
            "quote_nullifier": self.quote_nullifier,
            "pq_quote_auth_root": self.pq_quote_auth_root,
            "fee_sponsor_policy_root": self.fee_sponsor_policy_root,
            "privacy_set_size": self.privacy_set_size,
            "taker_fee_bps": self.taker_fee_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestQuoteEligibilityRequest {
    pub quote_id: String,
    pub pair_id: String,
    pub attestor_commitment: String,
    pub verdict: AttestationVerdict,
    pub risk_score_bps: u64,
    pub pq_attestation_root: String,
    pub selective_disclosure_root: String,
    pub valid_until_height: u64,
}

impl AttestQuoteEligibilityRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "pair_id": self.pair_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "pq_attestation_root": self.pq_attestation_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveRfqSponsorRequest {
    pub quote_id: String,
    pub pair_id: String,
    pub sponsor_commitment: String,
    pub sponsored_fee_asset_id: String,
    pub reserved_fee_commitment_root: String,
    pub sponsor_auth_root: String,
    pub max_sponsor_fee_bps: u64,
    pub expires_at_height: u64,
}

impl ReserveRfqSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "pair_id": self.pair_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsored_fee_asset_id": self.sponsored_fee_asset_id,
            "reserved_fee_commitment_root": self.reserved_fee_commitment_root,
            "sponsor_auth_root": self.sponsor_auth_root,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptConfidentialQuoteRequest {
    pub quote_id: String,
    pub pair_id: String,
    pub taker_commitment: String,
    pub encrypted_fill_note_root: String,
    pub settlement_commitment_root: String,
    pub taker_nullifier: String,
    pub quote_nullifier: String,
    pub pq_taker_auth_root: String,
    pub sponsor_reservation_id: String,
    pub accepted_at_height: u64,
}

impl AcceptConfidentialQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "pair_id": self.pair_id,
            "taker_commitment": self.taker_commitment,
            "encrypted_fill_note_root": self.encrypted_fill_note_root,
            "settlement_commitment_root": self.settlement_commitment_root,
            "taker_nullifier": self.taker_nullifier,
            "quote_nullifier": self.quote_nullifier,
            "pq_taker_auth_root": self.pq_taker_auth_root,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildRfqSettlementBatchRequest {
    pub pair_id: String,
    pub fill_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub solver_commitment: String,
    pub batch_execution_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_privacy_proof_root: String,
    pub aggregate_fee_root: String,
    pub target_fee_bps: u64,
    pub batch_privacy_set_size: u64,
    pub expires_at_height: u64,
}

impl BuildRfqSettlementBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "pair_id": self.pair_id,
            "fill_ids": self.fill_ids,
            "sponsor_reservation_ids": self.sponsor_reservation_ids,
            "solver_commitment": self.solver_commitment,
            "batch_execution_root": self.batch_execution_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "aggregate_fee_root": self.aggregate_fee_root,
            "target_fee_bps": self.target_fee_bps,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRfqReceiptRequest {
    pub batch_id: String,
    pub pair_id: String,
    pub fill_id: String,
    pub receipt_kind: ReceiptKind,
    pub settlement_root: String,
    pub fee_paid_commitment_root: String,
    pub pq_receipt_auth_root: String,
    pub published_at_height: u64,
}

impl PublishRfqReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pair_id": self.pair_id,
            "fill_id": self.fill_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "settlement_root": self.settlement_root,
            "fee_paid_commitment_root": self.fee_paid_commitment_root,
            "pq_receipt_auth_root": self.pq_receipt_auth_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRfqRebateRequest {
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_commitment_root: String,
    pub fee_credit_root: String,
    pub pq_rebate_auth_root: String,
    pub published_at_height: u64,
}

impl PublishRfqRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_commitment_root": self.rebate_commitment_root,
            "fee_credit_root": self.fee_credit_root,
            "pq_rebate_auth_root": self.pq_rebate_auth_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RfqPairRecord {
    pub pair_id: String,
    pub request: OpenRfqPairRequest,
    pub status: PairStatus,
    pub opened_sequence: u64,
    pub quote_count: u64,
    pub fill_count: u64,
}

impl RfqPairRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pair_id": self.pair_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "opened_sequence": self.opened_sequence,
            "quote_count": self.quote_count,
            "fill_count": self.fill_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialQuoteRecord {
    pub quote_id: String,
    pub request: SubmitConfidentialQuoteRequest,
    pub status: QuoteStatus,
    pub submitted_sequence: u64,
    pub reserved_by: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub fill_id: String,
}

impl ConfidentialQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "submitted_sequence": self.submitted_sequence,
            "reserved_by": self.reserved_by,
            "attestation_ids": self.attestation_ids,
            "fill_id": self.fill_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteEligibilityAttestationRecord {
    pub attestation_id: String,
    pub request: AttestQuoteEligibilityRequest,
    pub status: AttestationStatus,
    pub recorded_sequence: u64,
}

impl QuoteEligibilityAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "recorded_sequence": self.recorded_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RfqSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveRfqSponsorRequest,
    pub status: SponsorReservationStatus,
    pub reserved_sequence: u64,
}

impl RfqSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reserved_sequence": self.reserved_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialFillRecord {
    pub fill_id: String,
    pub request: AcceptConfidentialQuoteRequest,
    pub status: FillStatus,
    pub accepted_sequence: u64,
    pub batch_id: String,
}

impl ConfidentialFillRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fill_id": self.fill_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "accepted_sequence": self.accepted_sequence,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RfqSettlementBatchRecord {
    pub batch_id: String,
    pub request: BuildRfqSettlementBatchRequest,
    pub status: SettlementBatchStatus,
    pub built_sequence: u64,
    pub fill_root: String,
    pub reservation_root: String,
}

impl RfqSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "built_sequence": self.built_sequence,
            "fill_root": self.fill_root,
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RfqReceiptRecord {
    pub receipt_id: String,
    pub request: PublishRfqReceiptRequest,
    pub published_sequence: u64,
}

impl RfqReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "published_sequence": self.published_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RfqRebateRecord {
    pub rebate_id: String,
    pub request: PublishRfqRebateRequest,
    pub published_sequence: u64,
}

impl RfqRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "published_sequence": self.published_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub pair_root: String,
    pub quote_root: String,
    pub fill_root: String,
    pub attestation_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pair_root": self.pair_root,
            "quote_root": self.quote_root,
            "fill_root": self.fill_root,
            "attestation_root": self.attestation_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub current_height: u64,
    pub config: Config,
    pub counters: Counters,
    pub pairs: BTreeMap<String, RfqPairRecord>,
    pub quotes: BTreeMap<String, ConfidentialQuoteRecord>,
    pub fills: BTreeMap<String, ConfidentialFillRecord>,
    pub attestations: BTreeMap<String, QuoteEligibilityAttestationRecord>,
    pub reservations: BTreeMap<String, RfqSponsorReservationRecord>,
    pub batches: BTreeMap<String, RfqSettlementBatchRecord>,
    pub receipts: BTreeMap<String, RfqReceiptRecord>,
    pub rebates: BTreeMap<String, RfqRebateRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ConfidentialRfqMarketRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2ConfidentialRfqMarketRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            current_height: config.devnet_height,
            config,
            counters: Counters::default(),
            pairs: BTreeMap::new(),
            quotes: BTreeMap::new(),
            fills: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    pub fn open_pair(
        &mut self,
        request: OpenRfqPairRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity("pairs", self.pairs.len(), self.config.max_pairs)?;
        self.validate_pair_request(&request)?;
        let sequence = self.counters.pairs_opened.saturating_add(1);
        let pair_id = rfq_pair_id(&request, sequence);
        if self.pairs.contains_key(&pair_id) {
            return Err("RFQ pair id collision".to_string());
        }
        self.pairs.insert(
            pair_id.clone(),
            RfqPairRecord {
                pair_id: pair_id.clone(),
                request,
                status: PairStatus::Open,
                opened_sequence: sequence,
                quote_count: 0,
                fill_count: 0,
            },
        );
        self.counters.pairs_opened = sequence;
        Ok(pair_id)
    }

    pub fn submit_quote(
        &mut self,
        request: SubmitConfidentialQuoteRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity("quotes", self.quotes.len(), self.config.max_quotes)?;
        self.validate_quote_request(&request)?;
        if !self
            .consumed_nullifiers
            .insert(request.quote_nullifier.clone())
        {
            return Err("RFQ quote nullifier already consumed".to_string());
        }
        let sequence = self.counters.quotes_submitted.saturating_add(1);
        let quote_id = confidential_quote_id(&request, sequence);
        if self.quotes.contains_key(&quote_id) {
            return Err("RFQ quote id collision".to_string());
        }
        self.quotes.insert(
            quote_id.clone(),
            ConfidentialQuoteRecord {
                quote_id: quote_id.clone(),
                request: request.clone(),
                status: QuoteStatus::Open,
                submitted_sequence: sequence,
                reserved_by: Vec::new(),
                attestation_ids: Vec::new(),
                fill_id: String::new(),
            },
        );
        if let Some(pair) = self.pairs.get_mut(&request.pair_id) {
            pair.quote_count = pair.quote_count.saturating_add(1);
        }
        self.counters.quotes_submitted = sequence;
        Ok(quote_id)
    }

    pub fn attest_quote(
        &mut self,
        request: AttestQuoteEligibilityRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        self.validate_attestation_request(&request)?;
        let sequence = self.counters.attestations_recorded.saturating_add(1);
        let attestation_id = rfq_attestation_id(&request, sequence);
        if self.attestations.contains_key(&attestation_id) {
            return Err("RFQ attestation id collision".to_string());
        }
        self.attestations.insert(
            attestation_id.clone(),
            QuoteEligibilityAttestationRecord {
                attestation_id: attestation_id.clone(),
                request: request.clone(),
                status: AttestationStatus::Recorded,
                recorded_sequence: sequence,
            },
        );
        if let Some(quote) = self.quotes.get_mut(&request.quote_id) {
            quote.attestation_ids.push(attestation_id.clone());
        }
        self.counters.attestations_recorded = sequence;
        Ok(attestation_id)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveRfqSponsorRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        self.validate_reservation_request(&request)?;
        let sequence = self.counters.reservations_opened.saturating_add(1);
        let reservation_id = rfq_sponsor_reservation_id(&request, sequence);
        if self.reservations.contains_key(&reservation_id) {
            return Err("RFQ sponsor reservation id collision".to_string());
        }
        self.reservations.insert(
            reservation_id.clone(),
            RfqSponsorReservationRecord {
                reservation_id: reservation_id.clone(),
                request: request.clone(),
                status: SponsorReservationStatus::Reserved,
                reserved_sequence: sequence,
            },
        );
        if let Some(quote) = self.quotes.get_mut(&request.quote_id) {
            quote.reserved_by.push(reservation_id.clone());
            if quote.status == QuoteStatus::Open {
                quote.status = QuoteStatus::Reserved;
            }
        }
        self.counters.reservations_opened = sequence;
        Ok(reservation_id)
    }

    pub fn accept_quote(
        &mut self,
        request: AcceptConfidentialQuoteRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity("fills", self.fills.len(), self.config.max_fills)?;
        self.validate_fill_request(&request)?;
        if !self
            .consumed_nullifiers
            .insert(request.taker_nullifier.clone())
        {
            return Err("RFQ taker nullifier already consumed".to_string());
        }
        let sequence = self.counters.fills_accepted.saturating_add(1);
        let fill_id = confidential_fill_id(&request, sequence);
        if self.fills.contains_key(&fill_id) {
            return Err("RFQ fill id collision".to_string());
        }
        self.fills.insert(
            fill_id.clone(),
            ConfidentialFillRecord {
                fill_id: fill_id.clone(),
                request: request.clone(),
                status: FillStatus::Pending,
                accepted_sequence: sequence,
                batch_id: String::new(),
            },
        );
        if let Some(quote) = self.quotes.get_mut(&request.quote_id) {
            quote.status = QuoteStatus::Filled;
            quote.fill_id = fill_id.clone();
        }
        if let Some(pair) = self.pairs.get_mut(&request.pair_id) {
            pair.fill_count = pair.fill_count.saturating_add(1);
        }
        if let Some(reservation) = self.reservations.get_mut(&request.sponsor_reservation_id) {
            reservation.status = SponsorReservationStatus::Consumed;
        }
        self.counters.fills_accepted = sequence;
        Ok(fill_id)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildRfqSettlementBatchRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity("batches", self.batches.len(), self.config.max_batches)?;
        self.validate_batch_request(&request)?;
        let sequence = self.counters.batches_built.saturating_add(1);
        let batch_id = rfq_settlement_batch_id(&request, sequence);
        if self.batches.contains_key(&batch_id) {
            return Err("RFQ settlement batch id collision".to_string());
        }
        let fill_root = id_list_root(
            "PRIVATE-L2-CONFIDENTIAL-RFQ-BATCH-FILL-ROOT",
            request.fill_ids.iter(),
        );
        let reservation_root = id_list_root(
            "PRIVATE-L2-CONFIDENTIAL-RFQ-BATCH-RESERVATION-ROOT",
            request.sponsor_reservation_ids.iter(),
        );
        self.batches.insert(
            batch_id.clone(),
            RfqSettlementBatchRecord {
                batch_id: batch_id.clone(),
                request: request.clone(),
                status: SettlementBatchStatus::Sealed,
                built_sequence: sequence,
                fill_root,
                reservation_root,
            },
        );
        for fill_id in &request.fill_ids {
            if let Some(fill) = self.fills.get_mut(fill_id) {
                fill.status = FillStatus::Batched;
                fill.batch_id = batch_id.clone();
            }
        }
        self.counters.batches_built = sequence;
        Ok(batch_id)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishRfqReceiptRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        self.validate_receipt_request(&request)?;
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt_id = rfq_receipt_id(&request, sequence);
        if self.receipts.contains_key(&receipt_id) {
            return Err("RFQ receipt id collision".to_string());
        }
        self.receipts.insert(
            receipt_id.clone(),
            RfqReceiptRecord {
                receipt_id: receipt_id.clone(),
                request: request.clone(),
                published_sequence: sequence,
            },
        );
        if let Some(fill) = self.fills.get_mut(&request.fill_id) {
            fill.status = FillStatus::Settled;
        }
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = SettlementBatchStatus::Settled;
        }
        self.counters.receipts_published = sequence;
        Ok(receipt_id)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishRfqRebateRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<String> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        self.validate_rebate_request(&request)?;
        let sequence = self.counters.rebates_published.saturating_add(1);
        let rebate_id = rfq_rebate_id(&request, sequence);
        if self.rebates.contains_key(&rebate_id) {
            return Err("RFQ rebate id collision".to_string());
        }
        self.rebates.insert(
            rebate_id.clone(),
            RfqRebateRecord {
                rebate_id: rebate_id.clone(),
                request,
                published_sequence: sequence,
            },
        );
        self.counters.rebates_published = sequence;
        Ok(rebate_id)
    }

    pub fn cancel_quote(
        &mut self,
        quote_id: &str,
        maker_commitment: &str,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| "RFQ quote not found".to_string())?;
        if quote.request.maker_commitment != maker_commitment {
            return Err("RFQ quote cancel maker mismatch".to_string());
        }
        if !matches!(quote.status, QuoteStatus::Open | QuoteStatus::Reserved) {
            return Err("RFQ quote cannot be cancelled in current state".to_string());
        }
        quote.status = QuoteStatus::Cancelled;
        Ok(())
    }

    pub fn expire_stale(&mut self, height: u64) -> u64 {
        self.current_height = self.current_height.max(height);
        let mut expired = 0_u64;
        for quote in self.quotes.values_mut() {
            if matches!(quote.status, QuoteStatus::Open | QuoteStatus::Reserved)
                && quote.request.expires_at_height <= height
            {
                quote.status = QuoteStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.status == SponsorReservationStatus::Reserved
                && reservation.request.expires_at_height <= height
            {
                reservation.status = SponsorReservationStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for attestation in self.attestations.values_mut() {
            if matches!(
                attestation.status,
                AttestationStatus::Recorded | AttestationStatus::Applied
            ) && attestation.request.valid_until_height <= height
            {
                attestation.status = AttestationStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for batch in self.batches.values_mut() {
            if batch.status == SettlementBatchStatus::Sealed
                && batch.request.expires_at_height <= height
            {
                batch.status = SettlementBatchStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        self.counters.stale_records_expired =
            self.counters.stale_records_expired.saturating_add(expired);
        expired
    }

    pub fn roots(&self) -> Roots {
        Roots {
            pair_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-PAIR-ROOT",
                self.pairs.values().map(RfqPairRecord::public_record),
            ),
            quote_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-QUOTE-ROOT",
                self.quotes
                    .values()
                    .map(ConfidentialQuoteRecord::public_record),
            ),
            fill_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-FILL-ROOT",
                self.fills
                    .values()
                    .map(ConfidentialFillRecord::public_record),
            ),
            attestation_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-ATTESTATION-ROOT",
                self.attestations
                    .values()
                    .map(QuoteEligibilityAttestationRecord::public_record),
            ),
            reservation_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-RESERVATION-ROOT",
                self.reservations
                    .values()
                    .map(RfqSponsorReservationRecord::public_record),
            ),
            batch_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-BATCH-ROOT",
                self.batches
                    .values()
                    .map(RfqSettlementBatchRecord::public_record),
            ),
            receipt_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-RECEIPT-ROOT",
                self.receipts.values().map(RfqReceiptRecord::public_record),
            ),
            rebate_root: record_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-REBATE-ROOT",
                self.rebates.values().map(RfqRebateRecord::public_record),
            ),
            nullifier_root: id_list_root(
                "PRIVATE-L2-CONFIDENTIAL-RFQ-NULLIFIER-ROOT",
                self.consumed_nullifiers.iter(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_rfq_market_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_PROTOCOL_VERSION,
            "hash_suite": PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_PQ_AUTH_SUITE,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("RFQ runtime public record is an object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn validate_pair_request(
        &self,
        request: &OpenRfqPairRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        ensure_non_empty("base_asset_id", &request.base_asset_id)?;
        ensure_non_empty("quote_asset_id", &request.quote_asset_id)?;
        ensure_non_empty("maker_commitment_root", &request.maker_commitment_root)?;
        ensure_non_empty(
            "inventory_commitment_root",
            &request.inventory_commitment_root,
        )?;
        ensure_non_empty("price_oracle_root", &request.price_oracle_root)?;
        ensure_non_empty("compliance_rule_root", &request.compliance_rule_root)?;
        ensure_non_empty("pq_maker_auth_root", &request.pq_maker_auth_root)?;
        if request.base_asset_id == request.quote_asset_id {
            return Err("RFQ pair assets must differ".to_string());
        }
        if request.min_order_units == 0 || request.min_order_units > request.max_order_units {
            return Err("RFQ pair order bounds are invalid".to_string());
        }
        if request.maker_fee_bps > self.config.max_maker_fee_bps {
            return Err("RFQ pair maker fee exceeds configured maximum".to_string());
        }
        if request.taker_fee_bps > self.config.max_taker_fee_bps {
            return Err("RFQ pair taker fee exceeds configured maximum".to_string());
        }
        ensure_min_u64(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )
    }

    fn validate_quote_request(
        &self,
        request: &SubmitConfidentialQuoteRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        let pair = self
            .pairs
            .get(&request.pair_id)
            .ok_or_else(|| "RFQ quote pair not found".to_string())?;
        if pair.status != PairStatus::Open {
            return Err("RFQ pair is not open for quotes".to_string());
        }
        ensure_non_empty("maker_commitment", &request.maker_commitment)?;
        ensure_non_empty(
            "encrypted_quote_note_root",
            &request.encrypted_quote_note_root,
        )?;
        ensure_non_empty("price_commitment_root", &request.price_commitment_root)?;
        ensure_non_empty("size_commitment_root", &request.size_commitment_root)?;
        ensure_non_empty("quote_nullifier", &request.quote_nullifier)?;
        ensure_non_empty("pq_quote_auth_root", &request.pq_quote_auth_root)?;
        ensure_non_empty("fee_sponsor_policy_root", &request.fee_sponsor_policy_root)?;
        ensure_min_u64(
            "privacy_set_size",
            request.privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        if request.taker_fee_bps > self.config.max_taker_fee_bps {
            return Err("RFQ quote taker fee exceeds configured maximum".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("RFQ quote expiry must be in the future".to_string());
        }
        if request.expires_at_height - self.current_height > self.config.quote_ttl_blocks {
            return Err("RFQ quote ttl exceeds configured maximum".to_string());
        }
        Ok(())
    }

    fn validate_attestation_request(
        &self,
        request: &AttestQuoteEligibilityRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| "RFQ attestation quote not found".to_string())?;
        if quote.request.pair_id != request.pair_id {
            return Err("RFQ attestation pair mismatch".to_string());
        }
        ensure_non_empty("attestor_commitment", &request.attestor_commitment)?;
        ensure_non_empty("pq_attestation_root", &request.pq_attestation_root)?;
        ensure_non_empty(
            "selective_disclosure_root",
            &request.selective_disclosure_root,
        )?;
        ensure_bps("risk_score_bps", request.risk_score_bps)?;
        if request.valid_until_height <= self.current_height {
            return Err("RFQ attestation expiry must be in the future".to_string());
        }
        if request.verdict == AttestationVerdict::Rejected {
            return Err("RFQ rejected attestation is not accepted into active book".to_string());
        }
        Ok(())
    }

    fn validate_reservation_request(
        &self,
        request: &ReserveRfqSponsorRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| "RFQ reservation quote not found".to_string())?;
        if quote.request.pair_id != request.pair_id {
            return Err("RFQ reservation pair mismatch".to_string());
        }
        if !matches!(quote.status, QuoteStatus::Open | QuoteStatus::Reserved) {
            return Err("RFQ quote cannot accept sponsor reservation".to_string());
        }
        ensure_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        ensure_non_empty("sponsored_fee_asset_id", &request.sponsored_fee_asset_id)?;
        ensure_non_empty(
            "reserved_fee_commitment_root",
            &request.reserved_fee_commitment_root,
        )?;
        ensure_non_empty("sponsor_auth_root", &request.sponsor_auth_root)?;
        if request.max_sponsor_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("RFQ sponsor fee exceeds configured maximum".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("RFQ sponsor reservation expiry must be in the future".to_string());
        }
        if request.expires_at_height - self.current_height > self.config.reservation_ttl_blocks {
            return Err("RFQ sponsor reservation ttl exceeds configured maximum".to_string());
        }
        Ok(())
    }

    fn validate_fill_request(
        &self,
        request: &AcceptConfidentialQuoteRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| "RFQ fill quote not found".to_string())?;
        if quote.request.pair_id != request.pair_id {
            return Err("RFQ fill pair mismatch".to_string());
        }
        if !matches!(quote.status, QuoteStatus::Open | QuoteStatus::Reserved) {
            return Err("RFQ quote cannot be filled in current state".to_string());
        }
        ensure_non_empty("taker_commitment", &request.taker_commitment)?;
        ensure_non_empty(
            "encrypted_fill_note_root",
            &request.encrypted_fill_note_root,
        )?;
        ensure_non_empty(
            "settlement_commitment_root",
            &request.settlement_commitment_root,
        )?;
        ensure_non_empty("taker_nullifier", &request.taker_nullifier)?;
        ensure_non_empty("quote_nullifier", &request.quote_nullifier)?;
        ensure_non_empty("pq_taker_auth_root", &request.pq_taker_auth_root)?;
        if request.quote_nullifier != quote.request.quote_nullifier {
            return Err("RFQ fill quote nullifier mismatch".to_string());
        }
        if !request.sponsor_reservation_id.is_empty() {
            let reservation = self
                .reservations
                .get(&request.sponsor_reservation_id)
                .ok_or_else(|| "RFQ fill sponsor reservation not found".to_string())?;
            if reservation.request.quote_id != request.quote_id {
                return Err("RFQ fill sponsor reservation quote mismatch".to_string());
            }
            if reservation.status != SponsorReservationStatus::Reserved {
                return Err("RFQ fill sponsor reservation is not active".to_string());
            }
        }
        Ok(())
    }

    fn validate_batch_request(
        &self,
        request: &BuildRfqSettlementBatchRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        ensure_non_empty("pair_id", &request.pair_id)?;
        if !self.pairs.contains_key(&request.pair_id) {
            return Err("RFQ settlement batch pair not found".to_string());
        }
        ensure_unique("fill_ids", &request.fill_ids)?;
        ensure_unique("sponsor_reservation_ids", &request.sponsor_reservation_ids)?;
        if request.fill_ids.is_empty() {
            return Err("RFQ settlement batch needs at least one fill".to_string());
        }
        if request.fill_ids.len() > self.config.max_batch_items {
            return Err("RFQ settlement batch exceeds item limit".to_string());
        }
        ensure_non_empty("solver_commitment", &request.solver_commitment)?;
        ensure_non_empty("batch_execution_root", &request.batch_execution_root)?;
        ensure_non_empty(
            "aggregate_pq_authorization_root",
            &request.aggregate_pq_authorization_root,
        )?;
        ensure_non_empty(
            "aggregate_privacy_proof_root",
            &request.aggregate_privacy_proof_root,
        )?;
        ensure_non_empty("aggregate_fee_root", &request.aggregate_fee_root)?;
        ensure_bps("target_fee_bps", request.target_fee_bps)?;
        ensure_min_u64(
            "batch_privacy_set_size",
            request.batch_privacy_set_size,
            self.config.batch_privacy_set_size,
        )?;
        if request.expires_at_height <= self.current_height {
            return Err("RFQ settlement batch expiry must be in the future".to_string());
        }
        if request.expires_at_height - self.current_height > self.config.settlement_ttl_blocks {
            return Err("RFQ settlement batch ttl exceeds configured maximum".to_string());
        }
        for fill_id in &request.fill_ids {
            let fill = self
                .fills
                .get(fill_id)
                .ok_or_else(|| format!("RFQ settlement fill {fill_id} not found"))?;
            if fill.request.pair_id != request.pair_id {
                return Err(format!("RFQ settlement fill {fill_id} pair mismatch"));
            }
            if fill.status != FillStatus::Pending {
                return Err(format!("RFQ settlement fill {fill_id} not pending"));
            }
        }
        for reservation_id in &request.sponsor_reservation_ids {
            let reservation = self
                .reservations
                .get(reservation_id)
                .ok_or_else(|| format!("RFQ reservation {reservation_id} not found"))?;
            if reservation.request.pair_id != request.pair_id {
                return Err(format!("RFQ reservation {reservation_id} pair mismatch"));
            }
        }
        Ok(())
    }

    fn validate_receipt_request(
        &self,
        request: &PublishRfqReceiptRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "RFQ receipt batch not found".to_string())?;
        if batch.request.pair_id != request.pair_id {
            return Err("RFQ receipt pair mismatch".to_string());
        }
        if !batch
            .request
            .fill_ids
            .iter()
            .any(|id| id == &request.fill_id)
        {
            return Err("RFQ receipt fill is not part of batch".to_string());
        }
        ensure_non_empty("settlement_root", &request.settlement_root)?;
        ensure_non_empty(
            "fee_paid_commitment_root",
            &request.fee_paid_commitment_root,
        )?;
        ensure_non_empty("pq_receipt_auth_root", &request.pq_receipt_auth_root)?;
        Ok(())
    }

    fn validate_rebate_request(
        &self,
        request: &PublishRfqRebateRequest,
    ) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("RFQ rebate receipt not found".to_string());
        }
        ensure_non_empty("beneficiary_commitment", &request.beneficiary_commitment)?;
        ensure_non_empty("rebate_asset_id", &request.rebate_asset_id)?;
        ensure_non_empty("rebate_commitment_root", &request.rebate_commitment_root)?;
        ensure_non_empty("fee_credit_root", &request.fee_credit_root)?;
        ensure_non_empty("pq_rebate_auth_root", &request.pq_rebate_auth_root)?;
        Ok(())
    }
}

pub type Runtime = State;

pub fn rfq_pair_id(request: &OpenRfqPairRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-PAIR-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn confidential_quote_id(request: &SubmitConfidentialQuoteRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-QUOTE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn rfq_attestation_id(request: &AttestQuoteEligibilityRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-ATTESTATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn rfq_sponsor_reservation_id(request: &ReserveRfqSponsorRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-SPONSOR-RESERVATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn confidential_fill_id(request: &AcceptConfidentialQuoteRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-FILL-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn rfq_settlement_batch_id(request: &BuildRfqSettlementBatchRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-SETTLEMENT-BATCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn rfq_receipt_id(request: &PublishRfqReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-RECEIPT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn rfq_rebate_id(request: &PublishRfqRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-CONFIDENTIAL-RFQ-REBATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
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
                &json!({ "index": index, "record": record }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-RFQ-MARKET-STATE-ROOT", record)
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn record_root<I>(domain: &str, records: I) -> String
where
    I: Iterator<Item = Value>,
{
    public_record_root(domain, &records.collect::<Vec<_>>())
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
                &[HashPart::Int(index as i128), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(name: &str, value: &str) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("RFQ market {name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive_usize(
    name: &str,
    value: usize,
) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
    if value == 0 {
        Err(format!("RFQ market {name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_positive_u64(name: &str, value: u64) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
    if value == 0 {
        Err(format!("RFQ market {name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_min_u64(
    name: &str,
    value: u64,
    min: u64,
) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
    if value < min {
        Err(format!("RFQ market {name} must be at least {min}"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_RFQ_MARKET_RUNTIME_MAX_BPS {
        Err(format!("RFQ market {name} exceeds basis-point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(
    name: &str,
    current: usize,
    max: usize,
) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
    if current >= max {
        Err(format!("RFQ market {name} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_unique(name: &str, values: &[String]) -> PrivateL2ConfidentialRfqMarketRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(name, value)?;
        if !seen.insert(value) {
            return Err(format!("RFQ market {name} contains duplicate id {value}"));
        }
    }
    Ok(())
}
