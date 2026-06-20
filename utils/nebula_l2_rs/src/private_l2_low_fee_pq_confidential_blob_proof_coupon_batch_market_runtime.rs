use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBlobProofCouponBatchMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_PROOF_COUPON_BATCH_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-blob-proof-coupon-batch-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_PROOF_COUPON_BATCH_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-private-l2-devnet";
pub const DEVNET_COUPON_ASSET_ID: &str = "blob-proof-coupon-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MARKET_SCHEME: &str = "low-fee-confidential-blob-proof-coupon-batch-market-v1";
pub const SPONSOR_BOOK_SCHEME: &str = "confidential-sponsor-coupon-book-root-v1";
pub const FEE_CLASS_QUOTE_SCHEME: &str = "proof-da-fee-class-quote-root-v1";
pub const SEALED_COUPON_LOT_SCHEME: &str = "ml-kem-1024-sealed-blob-proof-coupon-lot-root-v1";
pub const PQ_SPONSOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-blob-proof-sponsor-attestation-v1";
pub const REDEMPTION_RECEIPT_SCHEME: &str = "confidential-blob-proof-coupon-redemption-receipt-v1";
pub const ROUTE_CAP_SCHEME: &str = "blob-proof-low-fee-route-cap-root-v1";
pub const REBATE_ACCOUNTING_SCHEME: &str = "blob-proof-sponsor-rebate-accounting-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str =
    "blob-proof-coupon-market-privacy-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "roots-only-blob-proof-coupon-batch-market-operator-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_sponsor_balances_coupon_amounts_blob_payloads_proof_bytes_accounts_or_decryption_keys";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_600;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_ROUTE_SPONSORS: usize = 8;
pub const DEFAULT_OPERATOR_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeClass {
    BlobDa,
    ProofVerification,
    BlobAndProof,
    FastSettlement,
    EmergencyInclusion,
}

impl FeeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobDa => "blob_da",
            Self::ProofVerification => "proof_verification",
            Self::BlobAndProof => "blob_and_proof",
            Self::FastSettlement => "fast_settlement",
            Self::EmergencyInclusion => "emergency_inclusion",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    Quoting,
    BatchSealing,
    Attesting,
    Redeeming,
    Rebating,
    Paused,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponBookStatus {
    Draft,
    Funding,
    Active,
    Draining,
    Settled,
    Paused,
    Quarantined,
    Expired,
}

impl CouponBookStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Reserved,
    Sealed,
    Attested,
    Redeemed,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponLotStatus {
    Sealed,
    Advertised,
    Reserved,
    PartiallyRedeemed,
    Exhausted,
    Revoked,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum | Self::StrongQuorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Observed,
    Included,
    Finalized,
    Rebated,
    Disputed,
    Reversed,
    Redacted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapStatus {
    Open,
    Warm,
    Hot,
    SoftLimited,
    HardLimited,
    Exhausted,
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Posted,
    Netted,
    Donated,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Reserved,
    Applied,
    Exhausted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub coupon_asset_id: String,
    pub hash_suite: String,
    pub market_scheme: String,
    pub sponsor_book_scheme: String,
    pub fee_class_quote_scheme: String,
    pub sealed_coupon_lot_scheme: String,
    pub pq_sponsor_attestation_scheme: String,
    pub redemption_receipt_scheme: String,
    pub route_cap_scheme: String,
    pub rebate_accounting_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub privacy_boundary: String,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub attestation_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_route_sponsors: usize,
    pub operator_bucket_size: u64,
    pub enabled_fee_classes: BTreeSet<FeeClass>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            coupon_asset_id: DEVNET_COUPON_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            market_scheme: MARKET_SCHEME.to_string(),
            sponsor_book_scheme: SPONSOR_BOOK_SCHEME.to_string(),
            fee_class_quote_scheme: FEE_CLASS_QUOTE_SCHEME.to_string(),
            sealed_coupon_lot_scheme: SEALED_COUPON_LOT_SCHEME.to_string(),
            pq_sponsor_attestation_scheme: PQ_SPONSOR_ATTESTATION_SCHEME.to_string(),
            redemption_receipt_scheme: REDEMPTION_RECEIPT_SCHEME.to_string(),
            route_cap_scheme: ROUTE_CAP_SCHEME.to_string(),
            rebate_accounting_scheme: REBATE_ACCOUNTING_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_route_sponsors: DEFAULT_MAX_ROUTE_SPONSORS,
            operator_bucket_size: DEFAULT_OPERATOR_BUCKET_SIZE,
            enabled_fee_classes: BTreeSet::from([
                FeeClass::BlobDa,
                FeeClass::ProofVerification,
                FeeClass::BlobAndProof,
                FeeClass::FastSettlement,
            ]),
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "coupon_asset_id": self.coupon_asset_id,
            "hash_suite": self.hash_suite,
            "market_scheme": self.market_scheme,
            "sponsor_book_scheme": self.sponsor_book_scheme,
            "fee_class_quote_scheme": self.fee_class_quote_scheme,
            "sealed_coupon_lot_scheme": self.sealed_coupon_lot_scheme,
            "pq_sponsor_attestation_scheme": self.pq_sponsor_attestation_scheme,
            "redemption_receipt_scheme": self.redemption_receipt_scheme,
            "route_cap_scheme": self.route_cap_scheme,
            "rebate_accounting_scheme": self.rebate_accounting_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "privacy_boundary": self.privacy_boundary,
            "low_fee_bps": self.low_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_route_sponsors": self.max_route_sponsors,
            "operator_bucket_size": self.operator_bucket_size,
            "enabled_fee_classes": self.enabled_fee_classes.iter().map(|class| class.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_coupon_books: u64,
    pub fee_class_quotes: u64,
    pub sealed_coupon_lots: u64,
    pub pq_sponsor_attestations: u64,
    pub redemption_receipts: u64,
    pub route_caps: u64,
    pub rebate_accounts: u64,
    pub redaction_budgets: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_coupon_books": self.sponsor_coupon_books,
            "fee_class_quotes": self.fee_class_quotes,
            "sealed_coupon_lots": self.sealed_coupon_lots,
            "pq_sponsor_attestations": self.pq_sponsor_attestations,
            "redemption_receipts": self.redemption_receipts,
            "route_caps": self.route_caps,
            "rebate_accounts": self.rebate_accounts,
            "redaction_budgets": self.redaction_budgets,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub sponsor_coupon_books_root: String,
    pub fee_class_quotes_root: String,
    pub sealed_coupon_lots_root: String,
    pub pq_sponsor_attestations_root: String,
    pub redemption_receipts_root: String,
    pub route_caps_root: String,
    pub rebate_accounting_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = root_from_values("EMPTY", &[]);
        Self {
            config_root: empty.clone(),
            counters_root: empty.clone(),
            sponsor_coupon_books_root: empty.clone(),
            fee_class_quotes_root: empty.clone(),
            sealed_coupon_lots_root: empty.clone(),
            pq_sponsor_attestations_root: empty.clone(),
            redemption_receipts_root: empty.clone(),
            route_caps_root: empty.clone(),
            rebate_accounting_root: empty.clone(),
            redaction_budgets_root: empty.clone(),
            operator_summaries_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "sponsor_coupon_books_root": self.sponsor_coupon_books_root,
            "fee_class_quotes_root": self.fee_class_quotes_root,
            "sealed_coupon_lots_root": self.sealed_coupon_lots_root,
            "pq_sponsor_attestations_root": self.pq_sponsor_attestations_root,
            "redemption_receipts_root": self.redemption_receipts_root,
            "route_caps_root": self.route_caps_root,
            "rebate_accounting_root": self.rebate_accounting_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCouponBook {
    pub book_id: String,
    pub sponsor_commitment: String,
    pub fee_classes: BTreeSet<FeeClass>,
    pub status: CouponBookStatus,
    pub sealed_balance_commitment: String,
    pub coverage_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl SponsorCouponBook {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_classes": self.fee_classes.iter().map(|class| class.as_str()).collect::<Vec<_>>(),
            "status": self.status,
            "sealed_balance_commitment": self.sealed_balance_commitment,
            "coverage_bps": self.coverage_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeClassQuote {
    pub quote_id: String,
    pub fee_class: FeeClass,
    pub status: QuoteStatus,
    pub route_id: String,
    pub proof_units: u64,
    pub blob_bytes: u64,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub quote_commitment: String,
    pub expires_height: u64,
}

impl FeeClassQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "fee_class": self.fee_class,
            "status": self.status,
            "route_id": self.route_id,
            "proof_units": self.proof_units,
            "blob_bytes": self.blob_bytes,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "quote_commitment": self.quote_commitment,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCouponLot {
    pub lot_id: String,
    pub book_id: String,
    pub status: CouponLotStatus,
    pub fee_class: FeeClass,
    pub sealed_lot_root: String,
    pub coupon_count: u64,
    pub face_value_commitment: String,
    pub nullifier_root: String,
}

impl SealedCouponLot {
    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "book_id": self.book_id,
            "status": self.status,
            "fee_class": self.fee_class,
            "sealed_lot_root": self.sealed_lot_root,
            "coupon_count": self.coupon_count,
            "face_value_commitment": self.face_value_commitment,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub status: AttestationStatus,
    pub signer_set_root: String,
    pub pq_signature_root: String,
    pub min_security_bits: u16,
    pub expires_height: u64,
}

impl PqSponsorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "status": self.status,
            "signer_set_root": self.signer_set_root,
            "pq_signature_root": self.pq_signature_root,
            "min_security_bits": self.min_security_bits,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionReceipt {
    pub receipt_id: String,
    pub lot_id: String,
    pub quote_id: String,
    pub status: ReceiptStatus,
    pub redemption_nullifier: String,
    pub fee_paid_commitment: String,
    pub rebate_commitment: String,
    pub included_height: u64,
}

impl RedemptionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lot_id": self.lot_id,
            "quote_id": self.quote_id,
            "status": self.status,
            "redemption_nullifier": self.redemption_nullifier,
            "fee_paid_commitment": self.fee_paid_commitment,
            "rebate_commitment": self.rebate_commitment,
            "included_height": self.included_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCap {
    pub route_id: String,
    pub status: CapStatus,
    pub fee_class: FeeClass,
    pub cap_commitment: String,
    pub used_commitment: String,
    pub sponsor_count: usize,
    pub resets_height: u64,
}

impl RouteCap {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "status": self.status,
            "fee_class": self.fee_class,
            "cap_commitment": self.cap_commitment,
            "used_commitment": self.used_commitment,
            "sponsor_count": self.sponsor_count,
            "resets_height": self.resets_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAccount {
    pub account_id: String,
    pub sponsor_commitment: String,
    pub status: RebateStatus,
    pub accrued_commitment: String,
    pub posted_commitment: String,
    pub receipts_root: String,
}

impl RebateAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status,
            "accrued_commitment": self.accrued_commitment,
            "posted_commitment": self.posted_commitment,
            "receipts_root": self.receipts_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub status: BudgetStatus,
    pub epoch: u64,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub redacted_fields_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "status": self.status,
            "epoch": self.epoch,
            "budget_units": self.budget_units,
            "consumed_units": self.consumed_units,
            "redacted_fields_root": self.redacted_fields_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub market_status: MarketStatus,
    pub current_height: u64,
    pub current_epoch: u64,
    pub sponsor_coupon_books: BTreeMap<String, SponsorCouponBook>,
    pub fee_class_quotes: BTreeMap<String, FeeClassQuote>,
    pub sealed_coupon_lots: BTreeMap<String, SealedCouponLot>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub route_caps: BTreeMap<String, RouteCap>,
    pub rebate_accounts: BTreeMap<String, RebateAccount>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub operator_summaries: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            market_status: MarketStatus::Open,
            current_height: 4_240_000,
            current_epoch: 42_400,
            sponsor_coupon_books: BTreeMap::new(),
            fee_class_quotes: BTreeMap::new(),
            sealed_coupon_lots: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            rebate_accounts: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let book_id = record_id("book", "demo-sponsor", 1);
        let lot_id = record_id("lot", &book_id, 1);
        let quote_id = record_id("quote", "route:blob-proof-fast", 1);
        let receipt_id = record_id("receipt", &lot_id, 1);
        let attestation_id = record_id("attestation", &book_id, 1);
        let rebate_id = record_id("rebate", "demo-sponsor", 1);
        let budget_id = record_id("budget", "epoch:42400", 1);

        state.sponsor_coupon_books.insert(
            book_id.clone(),
            SponsorCouponBook {
                book_id: book_id.clone(),
                sponsor_commitment: commitment("sponsor", "demo-sponsor"),
                fee_classes: BTreeSet::from([FeeClass::BlobDa, FeeClass::ProofVerification]),
                status: CouponBookStatus::Active,
                sealed_balance_commitment: amount_commitment("book-balance", 10_000_000),
                coverage_bps: state.config.sponsor_cover_bps,
                opened_height: state.current_height,
                expires_height: state.current_height + state.config.coupon_ttl_blocks,
            },
        );
        state.fee_class_quotes.insert(
            quote_id.clone(),
            FeeClassQuote {
                quote_id: quote_id.clone(),
                fee_class: FeeClass::BlobAndProof,
                status: QuoteStatus::Attested,
                route_id: "route:blob-proof-fast".to_string(),
                proof_units: 512,
                blob_bytes: 1_048_576,
                user_fee_bps: state.config.low_fee_bps,
                sponsor_cover_bps: state.config.sponsor_cover_bps,
                quote_commitment: commitment("quote", "blob-proof-fast"),
                expires_height: state.current_height + state.config.quote_ttl_blocks,
            },
        );
        state.sealed_coupon_lots.insert(
            lot_id.clone(),
            SealedCouponLot {
                lot_id: lot_id.clone(),
                book_id: book_id.clone(),
                status: CouponLotStatus::PartiallyRedeemed,
                fee_class: FeeClass::BlobAndProof,
                sealed_lot_root: root_from_values(
                    "DEMO-SEALED-LOT",
                    &[json!({"lot": "demo", "redacted": true})],
                ),
                coupon_count: 4_096,
                face_value_commitment: amount_commitment("lot-face-value", 4_096_000),
                nullifier_root: root_from_values("DEMO-NULLIFIERS", &[json!("redacted")]),
            },
        );
        state.pq_sponsor_attestations.insert(
            attestation_id.clone(),
            PqSponsorAttestation {
                attestation_id,
                subject_id: book_id.clone(),
                status: AttestationStatus::StrongQuorum,
                signer_set_root: root_from_values("DEMO-SIGNERS", &[json!("committee-a")]),
                pq_signature_root: root_from_values("DEMO-PQ-SIGNATURES", &[json!("redacted")]),
                min_security_bits: state.config.min_pq_security_bits,
                expires_height: state.current_height + state.config.attestation_ttl_blocks,
            },
        );
        state.redemption_receipts.insert(
            receipt_id.clone(),
            RedemptionReceipt {
                receipt_id: receipt_id.clone(),
                lot_id,
                quote_id,
                status: ReceiptStatus::Rebated,
                redemption_nullifier: commitment("nullifier", "demo-redemption"),
                fee_paid_commitment: amount_commitment("fee-paid", 300),
                rebate_commitment: amount_commitment("rebate", 500),
                included_height: state.current_height + 1,
            },
        );
        state.route_caps.insert(
            "route:blob-proof-fast".to_string(),
            RouteCap {
                route_id: "route:blob-proof-fast".to_string(),
                status: CapStatus::Warm,
                fee_class: FeeClass::BlobAndProof,
                cap_commitment: amount_commitment("route-cap", 64_000_000),
                used_commitment: amount_commitment("route-used", 1_048_576),
                sponsor_count: 2,
                resets_height: state.current_height + state.config.redaction_epoch_blocks,
            },
        );
        state.rebate_accounts.insert(
            rebate_id.clone(),
            RebateAccount {
                account_id: rebate_id,
                sponsor_commitment: commitment("sponsor", "demo-sponsor"),
                status: RebateStatus::Posted,
                accrued_commitment: amount_commitment("rebate-accrued", 5_000),
                posted_commitment: amount_commitment("rebate-posted", 500),
                receipts_root: root_from_values("DEMO-REBATE-RECEIPTS", &[json!(receipt_id)]),
            },
        );
        state.redaction_budgets.insert(
            budget_id.clone(),
            PrivacyRedactionBudget {
                budget_id,
                status: BudgetStatus::Applied,
                epoch: state.current_epoch,
                budget_units: 4_096,
                consumed_units: 64,
                redacted_fields_root: root_from_values(
                    "DEMO-REDACTED-FIELDS",
                    &[json!("coupon_amount"), json!("sponsor_account")],
                ),
            },
        );
        state.operator_summaries.insert(
            "summary:demo".to_string(),
            json!({
                "summary_id": "summary:demo",
                "status": "operator_safe",
                "market_status": state.market_status,
                "redaction": PRIVACY_BOUNDARY,
            }),
        );
        state.recount();
        state.refresh_roots();
        state
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_pq_confidential_blob_proof_coupon_batch_market_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "chain_id": self.config.chain_id,
            "market_status": self.market_status,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
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
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = root_from_record("CONFIG", &self.config.public_record());
        self.roots.counters_root = root_from_record("COUNTERS", &self.counters.public_record());
        self.roots.sponsor_coupon_books_root = map_root(
            SPONSOR_BOOK_SCHEME,
            self.sponsor_coupon_books
                .values()
                .map(SponsorCouponBook::public_record),
        );
        self.roots.fee_class_quotes_root = map_root(
            FEE_CLASS_QUOTE_SCHEME,
            self.fee_class_quotes
                .values()
                .map(FeeClassQuote::public_record),
        );
        self.roots.sealed_coupon_lots_root = map_root(
            SEALED_COUPON_LOT_SCHEME,
            self.sealed_coupon_lots
                .values()
                .map(SealedCouponLot::public_record),
        );
        self.roots.pq_sponsor_attestations_root = map_root(
            PQ_SPONSOR_ATTESTATION_SCHEME,
            self.pq_sponsor_attestations
                .values()
                .map(PqSponsorAttestation::public_record),
        );
        self.roots.redemption_receipts_root = map_root(
            REDEMPTION_RECEIPT_SCHEME,
            self.redemption_receipts
                .values()
                .map(RedemptionReceipt::public_record),
        );
        self.roots.route_caps_root = map_root(
            ROUTE_CAP_SCHEME,
            self.route_caps.values().map(RouteCap::public_record),
        );
        self.roots.rebate_accounting_root = map_root(
            REBATE_ACCOUNTING_SCHEME,
            self.rebate_accounts
                .values()
                .map(RebateAccount::public_record),
        );
        self.roots.redaction_budgets_root = map_root(
            REDACTION_BUDGET_SCHEME,
            self.redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record),
        );
        self.roots.operator_summaries_root = map_root(
            OPERATOR_SUMMARY_SCHEME,
            self.operator_summaries.values().cloned(),
        );
        let state_record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "market_status": self.market_status,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "roots": {
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "sponsor_coupon_books_root": self.roots.sponsor_coupon_books_root,
                "fee_class_quotes_root": self.roots.fee_class_quotes_root,
                "sealed_coupon_lots_root": self.roots.sealed_coupon_lots_root,
                "pq_sponsor_attestations_root": self.roots.pq_sponsor_attestations_root,
                "redemption_receipts_root": self.roots.redemption_receipts_root,
                "route_caps_root": self.roots.route_caps_root,
                "rebate_accounting_root": self.roots.rebate_accounting_root,
                "redaction_budgets_root": self.roots.redaction_budgets_root,
                "operator_summaries_root": self.roots.operator_summaries_root,
            }
        });
        self.roots.state_root = root_from_record("STATE", &state_record);
    }

    pub fn recount(&mut self) {
        self.counters.sponsor_coupon_books = self.sponsor_coupon_books.len() as u64;
        self.counters.fee_class_quotes = self.fee_class_quotes.len() as u64;
        self.counters.sealed_coupon_lots = self.sealed_coupon_lots.len() as u64;
        self.counters.pq_sponsor_attestations = self.pq_sponsor_attestations.len() as u64;
        self.counters.redemption_receipts = self.redemption_receipts.len() as u64;
        self.counters.route_caps = self.route_caps.len() as u64;
        self.counters.rebate_accounts = self.rebate_accounts.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn root_from_values(domain: &str, leaves: &[Value]) -> String {
    let domain =
        format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-PROOF-COUPON-BATCH-MARKET:{domain}");
    merkle_root(&domain, leaves)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-PROOF-COUPON-BATCH-MARKET:RECORD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &values)
}

fn commitment(domain: &str, subject: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-PROOF-COUPON-BATCH-MARKET:COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(subject),
        ],
    )
}

fn amount_commitment(domain: &str, amount: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-PROOF-COUPON-BATCH-MARKET:AMOUNT-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::U64(amount),
        ],
    )
}

fn record_id(kind: &str, subject: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-PROOF-COUPON-BATCH-MARKET:RECORD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(subject),
            HashPart::U64(sequence),
        ],
    )
}
