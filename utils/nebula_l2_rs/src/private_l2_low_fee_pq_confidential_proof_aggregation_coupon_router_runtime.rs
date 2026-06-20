use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialProofAggregationCouponRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialProofAggregationCouponRouterRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_AGGREGATION_COUPON_ROUTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-proof-aggregation-coupon-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_AGGREGATION_COUPON_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SPONSOR_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-sponsor-coupon-router-v1";
pub const PRIVACY_SCHEME: &str =
    "confidential-coupon-lot-nullifier-redaction-budget-aggregation-router-v1";
pub const LOW_FEE_SCHEME: &str = "recursive-proof-aggregation-sponsored-coupon-low-fee-rebate-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-proof-aggregation-coupon-router-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_AGGREGATION_FEE_BPS: u64 = 12;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 3;
pub const DEFAULT_REBATE_BPS: u64 = 8;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET: u64 = 48;
pub const DEFAULT_MIN_COUPON_LOT_SIZE: u64 = 64;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponBookStatus {
    Draft,
    Open,
    Sealed,
    Exhausted,
    Paused,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Quoted,
    Attested,
    Redeemable,
    Settled,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Sponsor,
    Aggregator,
    Redeemer,
    Route,
    Receipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_sponsor_attestation_suite: String,
    pub privacy_scheme: String,
    pub low_fee_scheme: String,
    pub public_record_scheme: String,
    pub min_pq_security_bits: u16,
    pub max_aggregation_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub rebate_bps: u64,
    pub route_ttl_blocks: u64,
    pub default_privacy_redaction_budget: u64,
    pub min_coupon_lot_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_sponsor_attestation_suite: PQ_SPONSOR_ATTESTATION_SUITE.to_string(),
            privacy_scheme: PRIVACY_SCHEME.to_string(),
            low_fee_scheme: LOW_FEE_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_aggregation_fee_bps: DEFAULT_MAX_AGGREGATION_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            default_privacy_redaction_budget: DEFAULT_PRIVACY_REDACTION_BUDGET,
            min_coupon_lot_size: DEFAULT_MIN_COUPON_LOT_SIZE,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub sponsor_coupon_books: u64,
    pub aggregation_fee_quotes: u64,
    pub sealed_coupon_lots: u64,
    pub pq_sponsor_attestations: u64,
    pub redemption_receipts: u64,
    pub route_caps: u64,
    pub rebate_accounts: u64,
    pub privacy_redaction_budgets: u64,
    pub redeemed_coupons: u64,
    pub rejected_redemptions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub sponsor_coupon_book_root: String,
    pub aggregation_fee_quote_root: String,
    pub sealed_coupon_lot_root: String,
    pub pq_sponsor_attestation_root: String,
    pub redemption_receipt_root: String,
    pub route_cap_root: String,
    pub rebate_accounting_root: String,
    pub privacy_redaction_budget_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorCouponBook {
    pub id: String,
    pub sponsor_commitment: String,
    pub book_commitment: String,
    pub fee_asset_id: String,
    pub total_coupons: u64,
    pub remaining_coupons: u64,
    pub max_discount_bps: u64,
    pub status: CouponBookStatus,
}

impl SponsorCouponBook {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "sponsor_commitment": self.sponsor_commitment,
            "book_commitment": self.book_commitment,
            "fee_asset_id": self.fee_asset_id,
            "total_coupons": self.total_coupons,
            "remaining_coupons": self.remaining_coupons,
            "max_discount_bps": self.max_discount_bps,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregationFeeQuote {
    pub id: String,
    pub route_id: String,
    pub aggregator_commitment: String,
    pub proof_count: u64,
    pub base_fee_piconero: u64,
    pub aggregation_fee_bps: u64,
    pub sponsored_discount_bps: u64,
    pub expires_at_height: u64,
    pub status: RouteStatus,
}

impl AggregationFeeQuote {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedCouponLot {
    pub id: String,
    pub book_id: String,
    pub lot_commitment: String,
    pub coupon_count: u64,
    pub sealed_at_height: u64,
    pub encrypted_payload_root: String,
}

impl SealedCouponLot {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "book_id": self.book_id,
            "lot_commitment": self.lot_commitment,
            "coupon_count": self.coupon_count,
            "sealed_at_height": self.sealed_at_height,
            "encrypted_payload_root": self.encrypted_payload_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSponsorAttestation {
    pub id: String,
    pub sponsor_commitment: String,
    pub book_id: String,
    pub quote_id: String,
    pub pq_key_commitment: String,
    pub signature_commitment: String,
    pub security_bits: u16,
}

impl PqSponsorAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedemptionReceipt {
    pub id: String,
    pub quote_id: String,
    pub lot_id: String,
    pub redeemer_nullifier: String,
    pub redeemed_coupon_count: u64,
    pub aggregation_fee_paid_piconero: u64,
    pub rebate_piconero: u64,
    pub receipt_commitment: String,
}

impl RedemptionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "quote_id": self.quote_id,
            "lot_id": self.lot_id,
            "redeemer_nullifier": self.redeemer_nullifier,
            "redeemed_coupon_count": self.redeemed_coupon_count,
            "aggregation_fee_paid_piconero": self.aggregation_fee_paid_piconero,
            "rebate_piconero": self.rebate_piconero,
            "receipt_commitment": self.receipt_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteCap {
    pub id: String,
    pub route_id: String,
    pub max_proofs_per_batch: u64,
    pub max_fee_bps: u64,
    pub max_rebate_piconero: u64,
    pub expires_at_height: u64,
}

impl RouteCap {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateAccounting {
    pub id: String,
    pub sponsor_commitment: String,
    pub route_id: String,
    pub accrued_rebate_piconero: u64,
    pub paid_rebate_piconero: u64,
    pub liability_commitment: String,
}

impl RebateAccounting {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionBudget {
    pub id: String,
    pub scope: RedactionScope,
    pub subject_commitment: String,
    pub remaining_disclosures: u64,
    pub deterministic_redaction_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub epoch: u64,
    pub sponsor_coupon_books: BTreeMap<String, SponsorCouponBook>,
    pub aggregation_fee_quotes: BTreeMap<String, AggregationFeeQuote>,
    pub sealed_coupon_lots: BTreeMap<String, SealedCouponLot>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub route_caps: BTreeMap<String, RouteCap>,
    pub rebate_accounting: BTreeMap<String, RebateAccounting>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub spent_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            height: 2_884_320,
            epoch: 42,
            sponsor_coupon_books: BTreeMap::new(),
            aggregation_fee_quotes: BTreeMap::new(),
            sealed_coupon_lots: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            rebate_accounting: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.install_demo_fixtures();
        state.refresh_counters();
        state.refresh_public_records();
        state
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_low_fee_pq_confidential_proof_aggregation_coupon_router_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "privacy_scheme": PRIVACY_SCHEME,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.state_root(),
            sponsor_coupon_book_root: map_root(
                "LOW-FEE-COUPON-ROUTER-SPONSOR-BOOK-ROOT",
                &self.sponsor_coupon_books,
                SponsorCouponBook::public_record,
            ),
            aggregation_fee_quote_root: map_root(
                "LOW-FEE-COUPON-ROUTER-FEE-QUOTE-ROOT",
                &self.aggregation_fee_quotes,
                AggregationFeeQuote::public_record,
            ),
            sealed_coupon_lot_root: map_root(
                "LOW-FEE-COUPON-ROUTER-SEALED-LOT-ROOT",
                &self.sealed_coupon_lots,
                SealedCouponLot::public_record,
            ),
            pq_sponsor_attestation_root: map_root(
                "LOW-FEE-COUPON-ROUTER-PQ-SPONSOR-ATTESTATION-ROOT",
                &self.pq_sponsor_attestations,
                PqSponsorAttestation::public_record,
            ),
            redemption_receipt_root: map_root(
                "LOW-FEE-COUPON-ROUTER-REDEMPTION-RECEIPT-ROOT",
                &self.redemption_receipts,
                RedemptionReceipt::public_record,
            ),
            route_cap_root: map_root(
                "LOW-FEE-COUPON-ROUTER-ROUTE-CAP-ROOT",
                &self.route_caps,
                RouteCap::public_record,
            ),
            rebate_accounting_root: map_root(
                "LOW-FEE-COUPON-ROUTER-REBATE-ACCOUNTING-ROOT",
                &self.rebate_accounting,
                RebateAccounting::public_record,
            ),
            privacy_redaction_budget_root: map_root(
                "LOW-FEE-COUPON-ROUTER-PRIVACY-REDACTION-BUDGET-ROOT",
                &self.privacy_redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            nullifier_root: set_root(
                "LOW-FEE-COUPON-ROUTER-SPENT-NULLIFIER-ROOT",
                &self.spent_nullifiers,
            ),
            public_record_root: value_map_root(
                "LOW-FEE-COUPON-ROUTER-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "kind": "private_l2_low_fee_pq_confidential_proof_aggregation_coupon_router_roots",
            "protocol_version": PROTOCOL_VERSION,
            "config_root": roots.config_root,
            "sponsor_coupon_book_root": roots.sponsor_coupon_book_root,
            "aggregation_fee_quote_root": roots.aggregation_fee_quote_root,
            "sealed_coupon_lot_root": roots.sealed_coupon_lot_root,
            "pq_sponsor_attestation_root": roots.pq_sponsor_attestation_root,
            "redemption_receipt_root": roots.redemption_receipt_root,
            "route_cap_root": roots.route_cap_root,
            "rebate_accounting_root": roots.rebate_accounting_root,
            "privacy_redaction_budget_root": roots.privacy_redaction_budget_root,
            "nullifier_root": roots.nullifier_root,
            "public_record_root": roots.public_record_root,
            "counters_root": roots.counters_root,
        }));
        roots
    }

    fn install_demo_fixtures(&mut self) {
        let book = SponsorCouponBook {
            id: "book:devnet-sponsor-alpha".to_string(),
            sponsor_commitment: "sponsor_commitment:alpha-low-fee".to_string(),
            book_commitment: "coupon_book_commitment:alpha-2026q2".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            total_coupons: 10_000,
            remaining_coupons: 9_744,
            max_discount_bps: 75,
            status: CouponBookStatus::Open,
        };
        let quote = AggregationFeeQuote {
            id: "quote:devnet-aggregation-route-a".to_string(),
            route_id: "route:proof-aggregation-a".to_string(),
            aggregator_commitment: "aggregator_commitment:devnet-a".to_string(),
            proof_count: 512,
            base_fee_piconero: 18_000,
            aggregation_fee_bps: self.config.low_fee_target_bps,
            sponsored_discount_bps: 42,
            expires_at_height: self.height + self.config.route_ttl_blocks,
            status: RouteStatus::Redeemable,
        };
        let lot = SealedCouponLot {
            id: "lot:sealed-alpha-0001".to_string(),
            book_id: book.id.clone(),
            lot_commitment: "sealed_coupon_lot_commitment:alpha-0001".to_string(),
            coupon_count: 256,
            sealed_at_height: self.height,
            encrypted_payload_root: deterministic_id(
                "LOW-FEE-COUPON-ROUTER-ENCRYPTED-LOT-PAYLOAD",
                "alpha-0001",
            ),
        };
        let attestation = PqSponsorAttestation {
            id: "pq_attestation:alpha-route-a".to_string(),
            sponsor_commitment: book.sponsor_commitment.clone(),
            book_id: book.id.clone(),
            quote_id: quote.id.clone(),
            pq_key_commitment: "pq_key_commitment:ml-dsa-87-alpha".to_string(),
            signature_commitment: "pq_signature_commitment:alpha-route-a".to_string(),
            security_bits: self.config.min_pq_security_bits,
        };
        let receipt = RedemptionReceipt {
            id: "receipt:redemption-alpha-0001".to_string(),
            quote_id: quote.id.clone(),
            lot_id: lot.id.clone(),
            redeemer_nullifier: "nullifier:redemption-alpha-0001".to_string(),
            redeemed_coupon_count: 256,
            aggregation_fee_paid_piconero: 12_960,
            rebate_piconero: 1_440,
            receipt_commitment: "receipt_commitment:redacted-alpha-0001".to_string(),
        };
        let cap = RouteCap {
            id: "cap:route-proof-aggregation-a".to_string(),
            route_id: quote.route_id.clone(),
            max_proofs_per_batch: 2_048,
            max_fee_bps: self.config.max_aggregation_fee_bps,
            max_rebate_piconero: 25_000,
            expires_at_height: quote.expires_at_height,
        };
        let rebate = RebateAccounting {
            id: "rebate:sponsor-alpha-route-a".to_string(),
            sponsor_commitment: book.sponsor_commitment.clone(),
            route_id: quote.route_id.clone(),
            accrued_rebate_piconero: 1_440,
            paid_rebate_piconero: 0,
            liability_commitment: "rebate_liability_commitment:alpha-route-a".to_string(),
        };
        let budget = PrivacyRedactionBudget {
            id: "redaction:sponsor-alpha".to_string(),
            scope: RedactionScope::Sponsor,
            subject_commitment: book.sponsor_commitment.clone(),
            remaining_disclosures: self.config.default_privacy_redaction_budget,
            deterministic_redaction_root: deterministic_id(
                "LOW-FEE-COUPON-ROUTER-REDACTION-BUDGET",
                "sponsor-alpha",
            ),
        };

        self.spent_nullifiers
            .insert(receipt.redeemer_nullifier.clone());
        self.sponsor_coupon_books.insert(book.id.clone(), book);
        self.aggregation_fee_quotes.insert(quote.id.clone(), quote);
        self.sealed_coupon_lots.insert(lot.id.clone(), lot);
        self.pq_sponsor_attestations
            .insert(attestation.id.clone(), attestation);
        self.redemption_receipts.insert(receipt.id.clone(), receipt);
        self.route_caps.insert(cap.id.clone(), cap);
        self.rebate_accounting.insert(rebate.id.clone(), rebate);
        self.privacy_redaction_budgets
            .insert(budget.id.clone(), budget);
    }

    fn refresh_counters(&mut self) {
        self.counters.sponsor_coupon_books = self.sponsor_coupon_books.len() as u64;
        self.counters.aggregation_fee_quotes = self.aggregation_fee_quotes.len() as u64;
        self.counters.sealed_coupon_lots = self.sealed_coupon_lots.len() as u64;
        self.counters.pq_sponsor_attestations = self.pq_sponsor_attestations.len() as u64;
        self.counters.redemption_receipts = self.redemption_receipts.len() as u64;
        self.counters.route_caps = self.route_caps.len() as u64;
        self.counters.rebate_accounts = self.rebate_accounting.len() as u64;
        self.counters.privacy_redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        self.counters.redeemed_coupons = self
            .redemption_receipts
            .values()
            .map(|receipt| receipt.redeemed_coupon_count)
            .sum();
        self.counters.rejected_redemptions = self
            .aggregation_fee_quotes
            .values()
            .filter(|quote| quote.status == RouteStatus::Rejected)
            .count() as u64;
    }

    fn refresh_public_records(&mut self) {
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        self.public_records
            .insert("counters".to_string(), self.counters.public_record());
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-PROOF-AGGREGATION-COUPON-ROUTER-RUNTIME-STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "nullifier": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn deterministic_id(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}
