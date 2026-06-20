use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialRecursiveVerifierCouponMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_RECURSIVE_VERIFIER_COUPON_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-recursive-verifier-coupon-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_RECURSIVE_VERIFIER_COUPON_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SPONSOR_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-recursive-verifier-coupon-sponsor-v1";
pub const SEALED_COUPON_LOT_SUITE: &str =
    "ML-KEM-1024+xwing-sealed-recursive-verifier-coupon-lot-v1";
pub const REDEMPTION_RECEIPT_SUITE: &str =
    "recursive-verifier-coupon-redemption-receipt-nullifier-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-recursive-verifier-market-rebate-accounting-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "confidential-recursive-verifier-coupon-market-redaction-budget-v1";
pub const DEVNET_L2_HEIGHT: u64 = 4_480_000;
pub const DEVNET_EPOCH: u64 = 14_336;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "recursive-verifier-coupon-credit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_ROUTE_CAP_MICRO_UNITS: u64 = 250_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 24;
pub const DEFAULT_SPONSOR_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_LOT_TTL_SLOTS: u64 = 2_048;
pub const DEFAULT_RECEIPT_TTL_SLOTS: u64 = 4_096;
pub const DEFAULT_REDACTION_BUDGET_BYTES: u64 = 128 * 1024;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:STATE";
const D_CONFIG: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:CONFIG";
const D_COUNTERS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:COUNTERS";
const D_ROOTS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:ROOTS";
const D_BOOKS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:BOOKS";
const D_CLASSES: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:CLASSES";
const D_LOTS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:LOTS";
const D_ATTESTATIONS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:ATTESTATIONS";
const D_RECEIPTS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:RECEIPTS";
const D_CAPS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:CAPS";
const D_REBATES: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:REBATES";
const D_REDACTIONS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:REDACTIONS";
const D_EVENTS: &str = "PL2-LOW-FEE-PQ-CONF-RECURSIVE-VERIFIER-COUPON-MARKET:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierFeeClass {
    Micro,
    Standard,
    RecursiveBatch,
    Emergency,
}

impl VerifierFeeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Standard => "standard",
            Self::RecursiveBatch => "recursive_batch",
            Self::Emergency => "emergency",
        }
    }

    pub fn max_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::Micro => config.max_user_fee_bps / 2,
            Self::Standard => config.max_user_fee_bps,
            Self::RecursiveBatch => config.max_user_fee_bps.saturating_add(4),
            Self::Emergency => config.max_user_fee_bps.saturating_add(12),
        }
        .min(MAX_BPS)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponLotStatus {
    Draft,
    Sealed,
    Listed,
    Exhausted,
    Expired,
}

impl CouponLotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Listed => "listed",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub default_route_cap_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub sponsor_bond_micro_units: u64,
    pub lot_ttl_slots: u64,
    pub receipt_ttl_slots: u64,
    pub redaction_budget_bytes: u64,
    pub devnet_l2_height: u64,
    pub devnet_epoch: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            default_route_cap_micro_units: DEFAULT_ROUTE_CAP_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            sponsor_bond_micro_units: DEFAULT_SPONSOR_BOND_MICRO_UNITS,
            lot_ttl_slots: DEFAULT_LOT_TTL_SLOTS,
            receipt_ttl_slots: DEFAULT_RECEIPT_TTL_SLOTS,
            redaction_budget_bytes: DEFAULT_REDACTION_BUDGET_BYTES,
            devnet_l2_height: DEVNET_L2_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_sponsor_attestation_suite": PQ_SPONSOR_ATTESTATION_SUITE,
            "sealed_coupon_lot_suite": SEALED_COUPON_LOT_SUITE,
            "redemption_receipt_suite": REDEMPTION_RECEIPT_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "default_route_cap_micro_units": self.default_route_cap_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "sponsor_bond_micro_units": self.sponsor_bond_micro_units,
            "lot_ttl_slots": self.lot_ttl_slots,
            "receipt_ttl_slots": self.receipt_ttl_slots,
            "redaction_budget_bytes": self.redaction_budget_bytes,
            "devnet_l2_height": self.devnet_l2_height,
            "devnet_epoch": self.devnet_epoch
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_coupon_books: u64,
    pub verifier_fee_classes: u64,
    pub sealed_coupon_lots: u64,
    pub pq_sponsor_attestations: u64,
    pub redemption_receipts: u64,
    pub route_caps: u64,
    pub rebate_accounts: u64,
    pub redaction_budgets: u64,
    pub public_events: u64,
    pub total_coupon_units: u64,
    pub redeemed_coupon_units: u64,
    pub rebated_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_coupon_books": self.sponsor_coupon_books,
            "verifier_fee_classes": self.verifier_fee_classes,
            "sealed_coupon_lots": self.sealed_coupon_lots,
            "pq_sponsor_attestations": self.pq_sponsor_attestations,
            "redemption_receipts": self.redemption_receipts,
            "route_caps": self.route_caps,
            "rebate_accounts": self.rebate_accounts,
            "redaction_budgets": self.redaction_budgets,
            "public_events": self.public_events,
            "total_coupon_units": self.total_coupon_units,
            "redeemed_coupon_units": self.redeemed_coupon_units,
            "rebated_micro_units": self.rebated_micro_units
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub sponsor_coupon_books_root: String,
    pub verifier_fee_classes_root: String,
    pub sealed_coupon_lots_root: String,
    pub pq_sponsor_attestations_root: String,
    pub redemption_receipts_root: String,
    pub route_caps_root: String,
    pub rebate_accounting_root: String,
    pub privacy_redaction_budgets_root: String,
    pub public_events_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "sponsor_coupon_books_root": self.sponsor_coupon_books_root,
            "verifier_fee_classes_root": self.verifier_fee_classes_root,
            "sealed_coupon_lots_root": self.sealed_coupon_lots_root,
            "pq_sponsor_attestations_root": self.pq_sponsor_attestations_root,
            "redemption_receipts_root": self.redemption_receipts_root,
            "route_caps_root": self.route_caps_root,
            "rebate_accounting_root": self.rebate_accounting_root,
            "privacy_redaction_budgets_root": self.privacy_redaction_budgets_root,
            "public_events_root": self.public_events_root,
            "deterministic_state_root": self.deterministic_state_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCouponBook {
    pub book_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub bond_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_slot: u64,
    pub active: bool,
}

impl SponsorCouponBook {
    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "sponsor_commitment": redacted_commitment(&self.sponsor_commitment),
            "fee_asset_id": self.fee_asset_id,
            "bond_micro_units": self.bond_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_slot": self.opened_slot,
            "active": self.active
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierFeeClassRecord {
    pub class_id: String,
    pub fee_class: VerifierFeeClass,
    pub max_fee_bps: u64,
    pub recursive_depth_limit: u16,
    pub proof_system: String,
    pub route_label: String,
}

impl VerifierFeeClassRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "class_id": self.class_id,
            "fee_class": self.fee_class.as_str(),
            "max_fee_bps": self.max_fee_bps,
            "recursive_depth_limit": self.recursive_depth_limit,
            "proof_system": self.proof_system,
            "route_label": self.route_label
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCouponLot {
    pub lot_id: String,
    pub book_id: String,
    pub class_id: String,
    pub sealed_lot_root: String,
    pub encrypted_coupon_count: u64,
    pub available_coupon_count: u64,
    pub unit_fee_micro_units: u64,
    pub expires_slot: u64,
    pub status: CouponLotStatus,
}

impl SealedCouponLot {
    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "book_id": self.book_id,
            "class_id": self.class_id,
            "sealed_lot_root": self.sealed_lot_root,
            "encrypted_coupon_count": self.encrypted_coupon_count,
            "available_coupon_count": self.available_coupon_count,
            "unit_fee_micro_units": self.unit_fee_micro_units,
            "expires_slot": self.expires_slot,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub book_id: String,
    pub lot_id: String,
    pub sponsor_pq_key_commitment: String,
    pub attestation_root: String,
    pub signature_commitment: String,
    pub security_bits: u16,
    pub slot: u64,
}

impl PqSponsorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "book_id": self.book_id,
            "lot_id": self.lot_id,
            "sponsor_pq_key_commitment": redacted_commitment(&self.sponsor_pq_key_commitment),
            "attestation_root": self.attestation_root,
            "signature_commitment": redacted_commitment(&self.signature_commitment),
            "security_bits": self.security_bits,
            "slot": self.slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionReceipt {
    pub receipt_id: String,
    pub lot_id: String,
    pub route_id: String,
    pub coupon_nullifier: String,
    pub verifier_commitment: String,
    pub redeemed_units: u64,
    pub paid_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub slot: u64,
}

impl RedemptionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lot_id": self.lot_id,
            "route_id": self.route_id,
            "coupon_nullifier": self.coupon_nullifier,
            "verifier_commitment": redacted_commitment(&self.verifier_commitment),
            "redeemed_units": self.redeemed_units,
            "paid_fee_micro_units": self.paid_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "slot": self.slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCap {
    pub route_id: String,
    pub class_id: String,
    pub max_fee_micro_units: u64,
    pub max_coupon_units_per_slot: u64,
    pub privacy_floor: u64,
}

impl RouteCap {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "class_id": self.class_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_coupon_units_per_slot": self.max_coupon_units_per_slot,
            "privacy_floor": self.privacy_floor
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAccount {
    pub account_id: String,
    pub sponsor_commitment: String,
    pub accrued_micro_units: u64,
    pub paid_micro_units: u64,
    pub coupon_units_redeemed: u64,
}

impl RebateAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "sponsor_commitment": redacted_commitment(&self.sponsor_commitment),
            "accrued_micro_units": self.accrued_micro_units,
            "paid_micro_units": self.paid_micro_units,
            "coupon_units_redeemed": self.coupon_units_redeemed
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_commitment: String,
    pub allowed_bytes: u64,
    pub spent_bytes: u64,
    pub fields_redacted: BTreeSet<String>,
    pub expires_slot: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_commitment": redacted_commitment(&self.subject_commitment),
            "allowed_bytes": self.allowed_bytes,
            "spent_bytes": self.spent_bytes,
            "fields_redacted": self.fields_redacted,
            "expires_slot": self.expires_slot
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsor_coupon_books: BTreeMap<String, SponsorCouponBook>,
    pub verifier_fee_classes: BTreeMap<String, VerifierFeeClassRecord>,
    pub sealed_coupon_lots: BTreeMap<String, SealedCouponLot>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub route_caps: BTreeMap<String, RouteCap>,
    pub rebate_accounting: BTreeMap<String, RebateAccount>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub public_events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            sponsor_coupon_books: BTreeMap::new(),
            verifier_fee_classes: BTreeMap::new(),
            sealed_coupon_lots: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            rebate_accounting: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            public_events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn open_sponsor_coupon_book(
        &mut self,
        sponsor_commitment: impl Into<String>,
        privacy_set_size: u64,
        opened_slot: u64,
    ) -> Result<String> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("sponsor coupon book privacy set below configured floor".to_string());
        }
        let sponsor_commitment = sponsor_commitment.into();
        let opened_slot_text = opened_slot.to_string();
        let book_id = deterministic_id("book", &[&sponsor_commitment, &opened_slot_text]);
        let book = SponsorCouponBook {
            book_id: book_id.clone(),
            sponsor_commitment,
            fee_asset_id: self.config.fee_asset_id.clone(),
            bond_micro_units: self.config.sponsor_bond_micro_units,
            privacy_set_size,
            opened_slot,
            active: true,
        };
        self.sponsor_coupon_books.insert(book_id.clone(), book);
        self.counters.sponsor_coupon_books = self.sponsor_coupon_books.len() as u64;
        self.record_event("sponsor_coupon_book_opened", &book_id);
        self.recompute_roots();
        Ok(book_id)
    }

    pub fn install_fee_class(
        &mut self,
        fee_class: VerifierFeeClass,
        recursive_depth_limit: u16,
        proof_system: impl Into<String>,
        route_label: impl Into<String>,
    ) -> Result<String> {
        let proof_system = proof_system.into();
        let route_label = route_label.into();
        let class_id = deterministic_id(
            "fee-class",
            &[
                fee_class.as_str(),
                &recursive_depth_limit.to_string(),
                &route_label,
            ],
        );
        let record = VerifierFeeClassRecord {
            class_id: class_id.clone(),
            fee_class,
            max_fee_bps: fee_class.max_fee_bps(&self.config),
            recursive_depth_limit,
            proof_system,
            route_label,
        };
        self.verifier_fee_classes.insert(class_id.clone(), record);
        self.counters.verifier_fee_classes = self.verifier_fee_classes.len() as u64;
        self.record_event("verifier_fee_class_installed", &class_id);
        self.recompute_roots();
        Ok(class_id)
    }

    pub fn seal_coupon_lot(
        &mut self,
        book_id: impl Into<String>,
        class_id: impl Into<String>,
        encrypted_coupon_count: u64,
        unit_fee_micro_units: u64,
        current_slot: u64,
    ) -> Result<String> {
        let book_id = book_id.into();
        let class_id = class_id.into();
        if !self.sponsor_coupon_books.contains_key(&book_id) {
            return Err("unknown sponsor coupon book".to_string());
        }
        if !self.verifier_fee_classes.contains_key(&class_id) {
            return Err("unknown verifier fee class".to_string());
        }
        let lot_id = deterministic_id(
            "lot",
            &[
                &book_id,
                &class_id,
                &encrypted_coupon_count.to_string(),
                &current_slot.to_string(),
            ],
        );
        let sealed_lot_root = deterministic_leaf(
            "sealed-lot",
            &[
                &lot_id,
                &book_id,
                &class_id,
                &encrypted_coupon_count.to_string(),
            ],
        );
        let lot = SealedCouponLot {
            lot_id: lot_id.clone(),
            book_id,
            class_id,
            sealed_lot_root,
            encrypted_coupon_count,
            available_coupon_count: encrypted_coupon_count,
            unit_fee_micro_units,
            expires_slot: current_slot.saturating_add(self.config.lot_ttl_slots),
            status: CouponLotStatus::Sealed,
        };
        self.counters.total_coupon_units = self
            .counters
            .total_coupon_units
            .saturating_add(encrypted_coupon_count);
        self.sealed_coupon_lots.insert(lot_id.clone(), lot);
        self.counters.sealed_coupon_lots = self.sealed_coupon_lots.len() as u64;
        self.record_event("sealed_coupon_lot_created", &lot_id);
        self.recompute_roots();
        Ok(lot_id)
    }

    pub fn attest_sponsor_lot(
        &mut self,
        book_id: impl Into<String>,
        lot_id: impl Into<String>,
        sponsor_pq_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        slot: u64,
    ) -> Result<String> {
        let book_id = book_id.into();
        let lot_id = lot_id.into();
        if !self.sealed_coupon_lots.contains_key(&lot_id) {
            return Err("unknown sealed coupon lot".to_string());
        }
        let sponsor_pq_key_commitment = sponsor_pq_key_commitment.into();
        let signature_commitment = signature_commitment.into();
        let attestation_id =
            deterministic_id("pq-attestation", &[&book_id, &lot_id, &slot.to_string()]);
        let attestation_root = deterministic_leaf(
            "pq-sponsor-attestation",
            &[
                &attestation_id,
                &book_id,
                &lot_id,
                &sponsor_pq_key_commitment,
                &signature_commitment,
            ],
        );
        let attestation = PqSponsorAttestation {
            attestation_id: attestation_id.clone(),
            book_id,
            lot_id,
            sponsor_pq_key_commitment,
            attestation_root,
            signature_commitment,
            security_bits: self.config.min_pq_security_bits,
            slot,
        };
        self.pq_sponsor_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_sponsor_attestations = self.pq_sponsor_attestations.len() as u64;
        self.record_event("pq_sponsor_attestation_recorded", &attestation_id);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn set_route_cap(
        &mut self,
        route_id: impl Into<String>,
        class_id: impl Into<String>,
        max_fee_micro_units: u64,
        max_coupon_units_per_slot: u64,
    ) -> Result<String> {
        let route_id = route_id.into();
        let class_id = class_id.into();
        if !self.verifier_fee_classes.contains_key(&class_id) {
            return Err("unknown verifier fee class for route cap".to_string());
        }
        let cap = RouteCap {
            route_id: route_id.clone(),
            class_id,
            max_fee_micro_units,
            max_coupon_units_per_slot,
            privacy_floor: self.config.min_privacy_set_size,
        };
        self.route_caps.insert(route_id.clone(), cap);
        self.counters.route_caps = self.route_caps.len() as u64;
        self.record_event("route_cap_set", &route_id);
        self.recompute_roots();
        Ok(route_id)
    }

    pub fn redeem_coupon(
        &mut self,
        lot_id: impl Into<String>,
        route_id: impl Into<String>,
        verifier_commitment: impl Into<String>,
        redeemed_units: u64,
        paid_fee_micro_units: u64,
        slot: u64,
    ) -> Result<String> {
        let lot_id = lot_id.into();
        let route_id = route_id.into();
        let verifier_commitment = verifier_commitment.into();
        let cap = self
            .route_caps
            .get(&route_id)
            .ok_or_else(|| "unknown route cap".to_string())?;
        if paid_fee_micro_units > cap.max_fee_micro_units {
            return Err("paid fee exceeds route cap".to_string());
        }
        let lot = self
            .sealed_coupon_lots
            .get_mut(&lot_id)
            .ok_or_else(|| "unknown sealed coupon lot".to_string())?;
        if redeemed_units == 0 || redeemed_units > lot.available_coupon_count {
            return Err("coupon redemption units unavailable".to_string());
        }
        lot.available_coupon_count = lot.available_coupon_count.saturating_sub(redeemed_units);
        if lot.available_coupon_count == 0 {
            lot.status = CouponLotStatus::Exhausted;
        } else {
            lot.status = CouponLotStatus::Listed;
        }
        let receipt_id = deterministic_id(
            "receipt",
            &[
                &lot_id,
                &route_id,
                &verifier_commitment,
                &redeemed_units.to_string(),
                &slot.to_string(),
            ],
        );
        let coupon_nullifier =
            deterministic_leaf("coupon-nullifier", &[&receipt_id, &lot_id, &route_id]);
        let rebate_micro_units = paid_fee_micro_units
            .saturating_mul(self.config.target_rebate_bps)
            .saturating_div(MAX_BPS);
        let receipt = RedemptionReceipt {
            receipt_id: receipt_id.clone(),
            lot_id: lot_id.clone(),
            route_id,
            coupon_nullifier,
            verifier_commitment: verifier_commitment.clone(),
            redeemed_units,
            paid_fee_micro_units,
            rebate_micro_units,
            slot,
        };
        self.redemption_receipts.insert(receipt_id.clone(), receipt);
        self.counters.redemption_receipts = self.redemption_receipts.len() as u64;
        self.counters.redeemed_coupon_units = self
            .counters
            .redeemed_coupon_units
            .saturating_add(redeemed_units);
        self.counters.rebated_micro_units = self
            .counters
            .rebated_micro_units
            .saturating_add(rebate_micro_units);
        let account = self
            .rebate_accounting
            .entry(lot_id.clone())
            .or_insert_with(|| RebateAccount {
                account_id: lot_id.clone(),
                sponsor_commitment: format!("sponsor-for:{lot_id}"),
                accrued_micro_units: 0,
                paid_micro_units: 0,
                coupon_units_redeemed: 0,
            });
        account.accrued_micro_units = account
            .accrued_micro_units
            .saturating_add(rebate_micro_units);
        account.coupon_units_redeemed =
            account.coupon_units_redeemed.saturating_add(redeemed_units);
        self.counters.rebate_accounts = self.rebate_accounting.len() as u64;
        self.record_event("coupon_redeemed", &receipt_id);
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn open_redaction_budget(
        &mut self,
        subject_commitment: impl Into<String>,
        fields_redacted: BTreeSet<String>,
        current_slot: u64,
    ) -> Result<String> {
        let subject_commitment = subject_commitment.into();
        let budget_id = deterministic_id("redaction-budget", &[&subject_commitment]);
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            subject_commitment,
            allowed_bytes: self.config.redaction_budget_bytes,
            spent_bytes: 0,
            fields_redacted,
            expires_slot: current_slot.saturating_add(self.config.receipt_ttl_slots),
        };
        self.privacy_redaction_budgets
            .insert(budget_id.clone(), budget);
        self.counters.redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        self.record_event("privacy_redaction_budget_opened", &budget_id);
        self.recompute_roots();
        Ok(budget_id)
    }

    pub fn recompute_roots(&mut self) {
        self.counters.sponsor_coupon_books = self.sponsor_coupon_books.len() as u64;
        self.counters.verifier_fee_classes = self.verifier_fee_classes.len() as u64;
        self.counters.sealed_coupon_lots = self.sealed_coupon_lots.len() as u64;
        self.counters.pq_sponsor_attestations = self.pq_sponsor_attestations.len() as u64;
        self.counters.redemption_receipts = self.redemption_receipts.len() as u64;
        self.counters.route_caps = self.route_caps.len() as u64;
        self.counters.rebate_accounts = self.rebate_accounting.len() as u64;
        self.counters.redaction_budgets = self.privacy_redaction_budgets.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.sponsor_coupon_books_root = map_root(
            D_BOOKS,
            &self.sponsor_coupon_books,
            SponsorCouponBook::public_record,
        );
        self.roots.verifier_fee_classes_root = map_root(
            D_CLASSES,
            &self.verifier_fee_classes,
            VerifierFeeClassRecord::public_record,
        );
        self.roots.sealed_coupon_lots_root = map_root(
            D_LOTS,
            &self.sealed_coupon_lots,
            SealedCouponLot::public_record,
        );
        self.roots.pq_sponsor_attestations_root = map_root(
            D_ATTESTATIONS,
            &self.pq_sponsor_attestations,
            PqSponsorAttestation::public_record,
        );
        self.roots.redemption_receipts_root = map_root(
            D_RECEIPTS,
            &self.redemption_receipts,
            RedemptionReceipt::public_record,
        );
        self.roots.route_caps_root = map_root(D_CAPS, &self.route_caps, RouteCap::public_record);
        self.roots.rebate_accounting_root = map_root(
            D_REBATES,
            &self.rebate_accounting,
            RebateAccount::public_record,
        );
        self.roots.privacy_redaction_budgets_root = map_root(
            D_REDACTIONS,
            &self.privacy_redaction_budgets,
            PrivacyRedactionBudget::public_record,
        );
        self.roots.public_events_root = list_root(D_EVENTS, &self.public_events);
        self.roots.deterministic_state_root = self.state_root();
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "sponsor_coupon_books": public_map(&self.sponsor_coupon_books, SponsorCouponBook::public_record),
            "verifier_fee_classes": public_map(&self.verifier_fee_classes, VerifierFeeClassRecord::public_record),
            "sealed_coupon_lots": public_map(&self.sealed_coupon_lots, SealedCouponLot::public_record),
            "pq_sponsor_attestations": public_map(&self.pq_sponsor_attestations, PqSponsorAttestation::public_record),
            "redemption_receipts": public_map(&self.redemption_receipts, RedemptionReceipt::public_record),
            "route_caps": public_map(&self.route_caps, RouteCap::public_record),
            "rebate_accounting": public_map(&self.rebate_accounting, RebateAccount::public_record),
            "privacy_redaction_budgets": public_map(&self.privacy_redaction_budgets, PrivacyRedactionBudget::public_record),
            "public_events": self.public_events
        })
    }

    fn record_event(&mut self, kind: &str, subject_id: &str) {
        self.public_events.push(json!({
            "kind": kind,
            "subject_id": subject_id,
            "event_index": self.public_events.len() as u64,
            "event_root": deterministic_leaf(kind, &[subject_id, &self.public_events.len().to_string()])
        }));
        self.counters.public_events = self.public_events.len() as u64;
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let micro_class = state
        .install_fee_class(
            VerifierFeeClass::Micro,
            8,
            "nova+cyclefold-devnet",
            "private-payment-recursive-verify",
        )
        .expect("devnet micro fee class installs");
    let batch_class = state
        .install_fee_class(
            VerifierFeeClass::RecursiveBatch,
            32,
            "nova+halo2-devnet",
            "rollup-batch-recursive-verify",
        )
        .expect("devnet batch fee class installs");
    let book = state
        .open_sponsor_coupon_book(
            "sponsor_commitment:devnet-low-fee-market-maker",
            DEFAULT_TARGET_PRIVACY_SET_SIZE,
            DEVNET_EPOCH,
        )
        .expect("devnet sponsor book opens");
    let lot = state
        .seal_coupon_lot(book.clone(), micro_class.clone(), 10_000, 2, DEVNET_EPOCH)
        .expect("devnet coupon lot seals");
    state
        .attest_sponsor_lot(
            book,
            lot,
            "pq_key_commitment:devnet-sponsor-ml-dsa-87",
            "pq_signature_commitment:devnet-sponsor-lot",
            DEVNET_EPOCH + 1,
        )
        .expect("devnet attestation records");
    state
        .set_route_cap(
            "route:devnet-private-payment",
            micro_class,
            DEFAULT_ROUTE_CAP_MICRO_UNITS,
            512,
        )
        .expect("devnet route cap sets");
    state
        .set_route_cap(
            "route:devnet-recursive-batch",
            batch_class,
            DEFAULT_ROUTE_CAP_MICRO_UNITS.saturating_mul(4),
            128,
        )
        .expect("devnet batch route cap sets");
    let mut fields = BTreeSet::new();
    fields.insert("sponsor_identity".to_string());
    fields.insert("coupon_plaintext".to_string());
    fields.insert("verifier_return_address".to_string());
    state
        .open_redaction_budget(
            "subject:devnet-recursive-verifier-market",
            fields,
            DEVNET_EPOCH,
        )
        .expect("devnet redaction budget opens");
    state.recompute_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let lot_id = state
        .sealed_coupon_lots
        .keys()
        .next()
        .cloned()
        .expect("demo has coupon lot");
    state
        .redeem_coupon(
            lot_id,
            "route:devnet-private-payment",
            "verifier_commitment:wallet-alpha-recursive-proof",
            3,
            120,
            DEVNET_EPOCH + 4,
        )
        .expect("demo redemption succeeds");
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn public_map<T>(map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> Vec<Value> {
    map.iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect()
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>, public_record: fn(&T) -> Value) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record_root": record_root(domain, &json!({ "key": key, "record": public_record(value) }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn list_root(domain: &str, values: &[Value]) -> String {
    let leaves: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json!({
                "index": index,
                "record_root": record_root(domain, &json!({ "index": index, "record": value }))
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn state_root_from_public_record(record: &Value) -> String {
    record_root(D_STATE, record)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn deterministic_id(label: &str, parts: &[&str]) -> String {
    format!("{label}:{}", deterministic_leaf(label, parts))
}

fn deterministic_leaf(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-RECURSIVE-VERIFIER-COUPON-MARKET:{domain}"),
        &hash_parts,
        32,
    )
}

fn redacted_commitment(commitment: &str) -> String {
    if commitment.is_empty() {
        return "redacted:empty".to_string();
    }
    let digest = domain_hash(
        "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-RECURSIVE-VERIFIER-COUPON-MARKET:REDACTED-COMMITMENT",
        &[HashPart::Str(commitment)],
        16,
    );
    format!("redacted:{digest}")
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(object) = record {
        object.insert(key.to_string(), value);
    }
}
