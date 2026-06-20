use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2LowFeePqConfidentialStateWitnessFeeCouponRuntimeResult<T>;
pub type PrivateL2LowFeePqConfidentialStateWitnessFeeCouponRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_STATE_WITNESS_FEE_COUPON_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-state-witness-fee-coupon-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_STATE_WITNESS_FEE_COUPON_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-state-witness-fee-coupon-v1";
pub const SPONSOR_TREASURY_SCHEME: &str = "state-witness-fee-coupon-sponsor-treasury-root-v1";
pub const WITNESS_CLASS_COUPON_SCHEME: &str = "state-witness-class-fee-coupon-root-v1";
pub const WALLET_ELIGIBILITY_CAP_SCHEME: &str = "state-witness-wallet-eligibility-cap-root-v1";
pub const PREFETCH_CREDIT_SCHEME: &str = "state-witness-prefetch-credit-root-v1";
pub const PQ_COUPON_ATTESTATION_SCHEME: &str = "pq-state-witness-coupon-attestation-root-v1";
pub const REDEMPTION_RECEIPT_SCHEME: &str = "state-witness-fee-coupon-redemption-receipt-root-v1";
pub const RESERVE_ACCOUNTING_SCHEME: &str = "state-witness-fee-coupon-reserve-accounting-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-state-witness-fee-coupon-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_860_128;
pub const DEVNET_EPOCH: u64 = 19_212;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_PREFETCH_REBATE_BPS: u64 = 1_200;
pub const DEFAULT_WALLET_DAILY_CAP_MICRO_UNITS: u64 = 28_000;
pub const DEFAULT_TREASURY_MIN_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_PREFETCH_CREDIT_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_SPONSOR_TREASURIES: usize = 262_144;
pub const DEFAULT_MAX_WITNESS_CLASS_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_WALLET_ELIGIBILITY_CAPS: usize = 4_194_304;
pub const DEFAULT_MAX_PREFETCH_CREDITS: usize = 8_388_608;
pub const DEFAULT_MAX_PQ_COUPON_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_REDEMPTION_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_RESERVE_ACCOUNTS: usize = 1_048_576;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessClass {
    HotAccount,
    ContractStorage,
    RecursiveProof,
    MoneroBridgeOutput,
    DefiNetting,
    CrossShardReceipt,
    OracleUpdate,
    EscapeHatch,
}

impl WitnessClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotAccount => "hot_account",
            Self::ContractStorage => "contract_storage",
            Self::RecursiveProof => "recursive_proof",
            Self::MoneroBridgeOutput => "monero_bridge_output",
            Self::DefiNetting => "defi_netting",
            Self::CrossShardReceipt => "cross_shard_receipt",
            Self::OracleUpdate => "oracle_update",
            Self::EscapeHatch => "escape_hatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryStatus {
    Funding,
    Active,
    Throttled,
    Depleted,
    Paused,
    Retired,
}

impl TreasuryStatus {
    pub fn accepts_redemptions(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Depleted => "depleted",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Attested,
    Reserved,
    Redeemed,
    Refunded,
    Expired,
    Quarantined,
}

impl CouponStatus {
    pub fn is_live(self) -> bool {
        matches!(self, Self::Issued | Self::Attested | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapStatus {
    Active,
    Saturated,
    CoolingDown,
    Suspended,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchCreditStatus {
    Granted,
    Warmed,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approved,
    NeedsMorePrivacy,
    FeeCapExceeded,
    SponsorReserveLow,
    DuplicateNullifier,
    Rejected,
}

impl AttestationVerdict {
    pub fn approves_redemption(self) -> bool {
        matches!(self, Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    Reconciled,
    Disputed,
    Reversed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveStatus {
    Balanced,
    UnderReserved,
    Rebalancing,
    Frozen,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub prefetch_rebate_bps: u64,
    pub wallet_daily_cap_micro_units: u64,
    pub treasury_min_reserve_bps: u64,
    pub coupon_ttl_blocks: u64,
    pub prefetch_credit_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_sponsor_treasuries: usize,
    pub max_witness_class_coupons: usize,
    pub max_wallet_eligibility_caps: usize,
    pub max_prefetch_credits: usize,
    pub max_pq_coupon_attestations: usize,
    pub max_redemption_receipts: usize,
    pub max_reserve_accounts: usize,
    pub max_public_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            prefetch_rebate_bps: DEFAULT_PREFETCH_REBATE_BPS,
            wallet_daily_cap_micro_units: DEFAULT_WALLET_DAILY_CAP_MICRO_UNITS,
            treasury_min_reserve_bps: DEFAULT_TREASURY_MIN_RESERVE_BPS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            prefetch_credit_ttl_blocks: DEFAULT_PREFETCH_CREDIT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_sponsor_treasuries: DEFAULT_MAX_SPONSOR_TREASURIES,
            max_witness_class_coupons: DEFAULT_MAX_WITNESS_CLASS_COUPONS,
            max_wallet_eligibility_caps: DEFAULT_MAX_WALLET_ELIGIBILITY_CAPS,
            max_prefetch_credits: DEFAULT_MAX_PREFETCH_CREDITS,
            max_pq_coupon_attestations: DEFAULT_MAX_PQ_COUPON_ATTESTATIONS,
            max_redemption_receipts: DEFAULT_MAX_REDEMPTION_RECEIPTS,
            max_reserve_accounts: DEFAULT_MAX_RESERVE_ACCOUNTS,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_treasuries: u64,
    pub witness_class_coupons: u64,
    pub wallet_eligibility_caps: u64,
    pub prefetch_credits: u64,
    pub pq_coupon_attestations: u64,
    pub redemption_receipts: u64,
    pub reserve_accounts: u64,
    pub redeemed_coupon_micro_units: u64,
    pub sponsor_debits_micro_units: u64,
    pub prefetched_witness_bytes: u64,
    pub public_events: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub sponsor_treasury_root: String,
    pub witness_class_coupon_root: String,
    pub wallet_eligibility_cap_root: String,
    pub prefetch_credit_root: String,
    pub pq_coupon_attestation_root: String,
    pub redemption_receipt_root: String,
    pub reserve_accounting_root: String,
    pub public_event_root: String,
    pub deterministic_state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            sponsor_treasury_root: empty_root(SPONSOR_TREASURY_SCHEME),
            witness_class_coupon_root: empty_root(WITNESS_CLASS_COUPON_SCHEME),
            wallet_eligibility_cap_root: empty_root(WALLET_ELIGIBILITY_CAP_SCHEME),
            prefetch_credit_root: empty_root(PREFETCH_CREDIT_SCHEME),
            pq_coupon_attestation_root: empty_root(PQ_COUPON_ATTESTATION_SCHEME),
            redemption_receipt_root: empty_root(REDEMPTION_RECEIPT_SCHEME),
            reserve_accounting_root: empty_root(RESERVE_ACCOUNTING_SCHEME),
            public_event_root: empty_root(PUBLIC_RECORD_SCHEME),
            deterministic_state_root: empty_root("state-witness-fee-coupon-state-root-v1"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorTreasury {
    pub treasury_id: String,
    pub sponsor_id: String,
    pub operator_id: String,
    pub asset_id: String,
    pub status: TreasuryStatus,
    pub committed_micro_units: u64,
    pub reserved_micro_units: u64,
    pub redeemed_micro_units: u64,
    pub reserve_floor_micro_units: u64,
    pub max_coupon_micro_units: u64,
    pub witness_classes: BTreeSet<WitnessClass>,
    pub treasury_commitment_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessClassCoupon {
    pub coupon_id: String,
    pub treasury_id: String,
    pub wallet_cap_id: String,
    pub witness_class: WitnessClass,
    pub status: CouponStatus,
    pub coupon_value_micro_units: u64,
    pub user_fee_cap_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub privacy_set_size: u64,
    pub encrypted_coupon_root: String,
    pub nullifier_commitment_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletEligibilityCap {
    pub cap_id: String,
    pub wallet_tag: String,
    pub sponsor_id: String,
    pub status: CapStatus,
    pub daily_cap_micro_units: u64,
    pub used_today_micro_units: u64,
    pub coupon_count_cap: u64,
    pub coupon_count_used: u64,
    pub eligibility_root: String,
    pub rolling_window_start_height: u64,
    pub rolling_window_end_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchCredit {
    pub credit_id: String,
    pub coupon_id: String,
    pub witness_class: WitnessClass,
    pub status: PrefetchCreditStatus,
    pub witness_bytes: u64,
    pub credit_micro_units: u64,
    pub prefetch_rebate_bps: u64,
    pub cache_leaf_root: String,
    pub witness_hint_root: String,
    pub granted_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCouponAttestation {
    pub attestation_id: String,
    pub coupon_id: String,
    pub credit_id: String,
    pub operator_id: String,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub attestation_transcript_root: String,
    pub privacy_set_size: u64,
    pub measured_prefetch_ms: u64,
    pub fee_cap_micro_units: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionReceipt {
    pub receipt_id: String,
    pub coupon_id: String,
    pub treasury_id: String,
    pub wallet_cap_id: String,
    pub status: ReceiptStatus,
    pub redeemed_micro_units: u64,
    pub user_paid_micro_units: u64,
    pub sponsor_debit_micro_units: u64,
    pub receipt_commitment_root: String,
    pub reserve_after_micro_units: u64,
    pub redeemed_at_height: u64,
    pub finalizes_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveAccount {
    pub reserve_id: String,
    pub treasury_id: String,
    pub asset_id: String,
    pub status: ReserveStatus,
    pub opening_balance_micro_units: u64,
    pub committed_micro_units: u64,
    pub reserved_micro_units: u64,
    pub redeemed_micro_units: u64,
    pub pending_refund_micro_units: u64,
    pub closing_balance_micro_units: u64,
    pub accounting_root: String,
    pub epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub operator_safe_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsor_treasuries: BTreeMap<String, SponsorTreasury>,
    pub witness_class_coupons: BTreeMap<String, WitnessClassCoupon>,
    pub wallet_eligibility_caps: BTreeMap<String, WalletEligibilityCap>,
    pub prefetch_credits: BTreeMap<String, PrefetchCredit>,
    pub pq_coupon_attestations: BTreeMap<String, PqCouponAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub reserve_accounts: BTreeMap<String, ReserveAccount>,
    pub public_events: Vec<PublicEvent>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sponsor_treasuries: BTreeMap::new(),
            witness_class_coupons: BTreeMap::new(),
            wallet_eligibility_caps: BTreeMap::new(),
            prefetch_credits: BTreeMap::new(),
            pq_coupon_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            reserve_accounts: BTreeMap::new(),
            public_events: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            sponsor_treasuries: self.sponsor_treasuries.len() as u64,
            witness_class_coupons: self.witness_class_coupons.len() as u64,
            wallet_eligibility_caps: self.wallet_eligibility_caps.len() as u64,
            prefetch_credits: self.prefetch_credits.len() as u64,
            pq_coupon_attestations: self.pq_coupon_attestations.len() as u64,
            redemption_receipts: self.redemption_receipts.len() as u64,
            reserve_accounts: self.reserve_accounts.len() as u64,
            redeemed_coupon_micro_units: self
                .redemption_receipts
                .values()
                .map(|receipt| receipt.redeemed_micro_units)
                .sum(),
            sponsor_debits_micro_units: self
                .redemption_receipts
                .values()
                .map(|receipt| receipt.sponsor_debit_micro_units)
                .sum(),
            prefetched_witness_bytes: self
                .prefetch_credits
                .values()
                .map(|credit| credit.witness_bytes)
                .sum(),
            public_events: self.public_events.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.recompute_counters();
        self.roots.sponsor_treasury_root = root_from_public_records(
            SPONSOR_TREASURY_SCHEME,
            self.sponsor_treasuries
                .values()
                .map(SponsorTreasury::operator_record),
        );
        self.roots.witness_class_coupon_root = root_from_public_records(
            WITNESS_CLASS_COUPON_SCHEME,
            self.witness_class_coupons
                .values()
                .map(WitnessClassCoupon::operator_record),
        );
        self.roots.wallet_eligibility_cap_root = root_from_public_records(
            WALLET_ELIGIBILITY_CAP_SCHEME,
            self.wallet_eligibility_caps
                .values()
                .map(WalletEligibilityCap::operator_record),
        );
        self.roots.prefetch_credit_root = root_from_public_records(
            PREFETCH_CREDIT_SCHEME,
            self.prefetch_credits
                .values()
                .map(PrefetchCredit::operator_record),
        );
        self.roots.pq_coupon_attestation_root = root_from_public_records(
            PQ_COUPON_ATTESTATION_SCHEME,
            self.pq_coupon_attestations
                .values()
                .map(PqCouponAttestation::operator_record),
        );
        self.roots.redemption_receipt_root = root_from_public_records(
            REDEMPTION_RECEIPT_SCHEME,
            self.redemption_receipts
                .values()
                .map(RedemptionReceipt::operator_record),
        );
        self.roots.reserve_accounting_root = root_from_public_records(
            RESERVE_ACCOUNTING_SCHEME,
            self.reserve_accounts
                .values()
                .map(ReserveAccount::operator_record),
        );
        self.roots.public_event_root = root_from_public_records(
            PUBLIC_RECORD_SCHEME,
            self.public_events.iter().map(PublicEvent::operator_record),
        );
        self.roots.deterministic_state_root = deterministic_state_root(self);
    }
}

impl SponsorTreasury {
    pub fn available_micro_units(&self) -> u64 {
        self.committed_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.redeemed_micro_units)
    }

    pub fn operator_record(&self) -> Value {
        json!({
            "treasury_id": self.treasury_id,
            "sponsor_id": self.sponsor_id,
            "operator_id": self.operator_id,
            "asset_id": self.asset_id,
            "status": self.status.as_str(),
            "committed_micro_units": self.committed_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "redeemed_micro_units": self.redeemed_micro_units,
            "reserve_floor_micro_units": self.reserve_floor_micro_units,
            "available_micro_units": self.available_micro_units(),
            "witness_classes": self.witness_classes.iter().map(|class| class.as_str()).collect::<Vec<_>>(),
            "treasury_commitment_root": self.treasury_commitment_root,
        })
    }
}

impl WitnessClassCoupon {
    pub fn operator_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "treasury_id": self.treasury_id,
            "wallet_cap_id": self.wallet_cap_id,
            "witness_class": self.witness_class.as_str(),
            "status": self.status,
            "coupon_value_micro_units": self.coupon_value_micro_units,
            "user_fee_cap_micro_units": self.user_fee_cap_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "privacy_set_size": self.privacy_set_size,
            "encrypted_coupon_root": self.encrypted_coupon_root,
            "nullifier_commitment_root": self.nullifier_commitment_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl WalletEligibilityCap {
    pub fn remaining_micro_units(&self) -> u64 {
        self.daily_cap_micro_units
            .saturating_sub(self.used_today_micro_units)
    }

    pub fn operator_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "wallet_tag": self.wallet_tag,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "daily_cap_micro_units": self.daily_cap_micro_units,
            "used_today_micro_units": self.used_today_micro_units,
            "remaining_micro_units": self.remaining_micro_units(),
            "coupon_count_cap": self.coupon_count_cap,
            "coupon_count_used": self.coupon_count_used,
            "eligibility_root": self.eligibility_root,
            "rolling_window_end_height": self.rolling_window_end_height,
        })
    }
}

impl PrefetchCredit {
    pub fn operator_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "coupon_id": self.coupon_id,
            "witness_class": self.witness_class.as_str(),
            "status": self.status,
            "witness_bytes": self.witness_bytes,
            "credit_micro_units": self.credit_micro_units,
            "prefetch_rebate_bps": self.prefetch_rebate_bps,
            "cache_leaf_root": self.cache_leaf_root,
            "witness_hint_root": self.witness_hint_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl PqCouponAttestation {
    pub fn operator_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "coupon_id": self.coupon_id,
            "credit_id": self.credit_id,
            "operator_id": self.operator_id,
            "verdict": self.verdict,
            "approved": self.verdict.approves_redemption(),
            "pq_signature_root": self.pq_signature_root,
            "attestation_transcript_root": self.attestation_transcript_root,
            "privacy_set_size": self.privacy_set_size,
            "measured_prefetch_ms": self.measured_prefetch_ms,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "expires_at_height": self.expires_at_height,
        })
    }
}

impl RedemptionReceipt {
    pub fn operator_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "coupon_id": self.coupon_id,
            "treasury_id": self.treasury_id,
            "wallet_cap_id": self.wallet_cap_id,
            "status": self.status,
            "redeemed_micro_units": self.redeemed_micro_units,
            "user_paid_micro_units": self.user_paid_micro_units,
            "sponsor_debit_micro_units": self.sponsor_debit_micro_units,
            "receipt_commitment_root": self.receipt_commitment_root,
            "reserve_after_micro_units": self.reserve_after_micro_units,
            "finalizes_at_height": self.finalizes_at_height,
        })
    }
}

impl ReserveAccount {
    pub fn operator_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "treasury_id": self.treasury_id,
            "asset_id": self.asset_id,
            "status": self.status,
            "opening_balance_micro_units": self.opening_balance_micro_units,
            "committed_micro_units": self.committed_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "redeemed_micro_units": self.redeemed_micro_units,
            "pending_refund_micro_units": self.pending_refund_micro_units,
            "closing_balance_micro_units": self.closing_balance_micro_units,
            "accounting_root": self.accounting_root,
            "epoch": self.epoch,
        })
    }
}

impl PublicEvent {
    pub fn operator_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "operator_safe_root": self.operator_safe_root,
            "height": self.height,
        })
    }
}

pub fn devnet() -> State {
    let mut classes = BTreeSet::new();
    classes.insert(WitnessClass::HotAccount);
    classes.insert(WitnessClass::ContractStorage);
    classes.insert(WitnessClass::RecursiveProof);

    let mut state = State::new(Config::default());
    let treasury = SponsorTreasury {
        treasury_id: "treasury:devnet:sponsor-a".to_string(),
        sponsor_id: "sponsor:wallet-growth-a".to_string(),
        operator_id: "operator:coupon-clearer-01".to_string(),
        asset_id: DEVNET_FEE_ASSET_ID.to_string(),
        status: TreasuryStatus::Active,
        committed_micro_units: 18_000_000,
        reserved_micro_units: 3_200_000,
        redeemed_micro_units: 420_000,
        reserve_floor_micro_units: 2_700_000,
        max_coupon_micro_units: 14_000,
        witness_classes: classes,
        treasury_commitment_root: sample_root("treasury-commitment", "treasury:devnet:sponsor-a"),
        opened_at_height: DEVNET_HEIGHT - 720,
        updated_at_height: DEVNET_HEIGHT,
    };
    let cap = WalletEligibilityCap {
        cap_id: "cap:wallet-tag:alpha".to_string(),
        wallet_tag: "wallet-tag:8f6f-redacted".to_string(),
        sponsor_id: treasury.sponsor_id.clone(),
        status: CapStatus::Active,
        daily_cap_micro_units: DEFAULT_WALLET_DAILY_CAP_MICRO_UNITS,
        used_today_micro_units: 9_800,
        coupon_count_cap: 8,
        coupon_count_used: 3,
        eligibility_root: sample_root("wallet-eligibility", "cap:wallet-tag:alpha"),
        rolling_window_start_height: DEVNET_HEIGHT - 180,
        rolling_window_end_height: DEVNET_HEIGHT + 540,
    };
    let coupon = WitnessClassCoupon {
        coupon_id: coupon_id(
            &treasury.treasury_id,
            &cap.cap_id,
            WitnessClass::ContractStorage,
            7,
        ),
        treasury_id: treasury.treasury_id.clone(),
        wallet_cap_id: cap.cap_id.clone(),
        witness_class: WitnessClass::ContractStorage,
        status: CouponStatus::Attested,
        coupon_value_micro_units: 12_400,
        user_fee_cap_micro_units: 880,
        sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        encrypted_coupon_root: sample_root("encrypted-coupon", "coupon:contract-storage:alpha"),
        nullifier_commitment_root: sample_root("coupon-nullifier", "coupon:contract-storage:alpha"),
        issued_at_height: DEVNET_HEIGHT - 8,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_COUPON_TTL_BLOCKS,
    };
    let credit = PrefetchCredit {
        credit_id: sample_root("prefetch-credit-id", &coupon.coupon_id),
        coupon_id: coupon.coupon_id.clone(),
        witness_class: coupon.witness_class,
        status: PrefetchCreditStatus::Warmed,
        witness_bytes: 46_592,
        credit_micro_units: 1_488,
        prefetch_rebate_bps: DEFAULT_PREFETCH_REBATE_BPS,
        cache_leaf_root: sample_root("prefetch-cache-leaf", &coupon.coupon_id),
        witness_hint_root: sample_root("prefetch-witness-hint", &coupon.coupon_id),
        granted_at_height: DEVNET_HEIGHT - 5,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_PREFETCH_CREDIT_TTL_BLOCKS,
    };
    let attestation = PqCouponAttestation {
        attestation_id: sample_root("pq-coupon-attestation-id", &coupon.coupon_id),
        coupon_id: coupon.coupon_id.clone(),
        credit_id: credit.credit_id.clone(),
        operator_id: treasury.operator_id.clone(),
        verdict: AttestationVerdict::Approved,
        pq_signature_root: sample_root("pq-coupon-signature", &coupon.coupon_id),
        attestation_transcript_root: sample_root("pq-coupon-transcript", &coupon.coupon_id),
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        measured_prefetch_ms: 11,
        fee_cap_micro_units: coupon.user_fee_cap_micro_units,
        attested_at_height: DEVNET_HEIGHT - 4,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
    };
    let receipt = RedemptionReceipt {
        receipt_id: sample_root("redemption-receipt-id", &coupon.coupon_id),
        coupon_id: coupon.coupon_id.clone(),
        treasury_id: treasury.treasury_id.clone(),
        wallet_cap_id: cap.cap_id.clone(),
        status: ReceiptStatus::Finalized,
        redeemed_micro_units: 12_400,
        user_paid_micro_units: 720,
        sponsor_debit_micro_units: 11_680,
        receipt_commitment_root: sample_root("redemption-receipt", &coupon.coupon_id),
        reserve_after_micro_units: 14_380_000,
        redeemed_at_height: DEVNET_HEIGHT - 2,
        finalizes_at_height: DEVNET_HEIGHT + DEFAULT_RECEIPT_FINALITY_BLOCKS,
    };
    let reserve = ReserveAccount {
        reserve_id: "reserve:devnet:sponsor-a:epoch-19212".to_string(),
        treasury_id: treasury.treasury_id.clone(),
        asset_id: DEVNET_FEE_ASSET_ID.to_string(),
        status: ReserveStatus::Balanced,
        opening_balance_micro_units: 18_000_000,
        committed_micro_units: treasury.committed_micro_units,
        reserved_micro_units: treasury.reserved_micro_units,
        redeemed_micro_units: treasury.redeemed_micro_units + receipt.sponsor_debit_micro_units,
        pending_refund_micro_units: 96_000,
        closing_balance_micro_units: 14_368_320,
        accounting_root: sample_root("reserve-accounting", "reserve:devnet:sponsor-a:epoch-19212"),
        epoch: DEVNET_EPOCH,
    };

    state
        .sponsor_treasuries
        .insert(treasury.treasury_id.clone(), treasury);
    state
        .wallet_eligibility_caps
        .insert(cap.cap_id.clone(), cap);
    state
        .witness_class_coupons
        .insert(coupon.coupon_id.clone(), coupon);
    state
        .prefetch_credits
        .insert(credit.credit_id.clone(), credit);
    state
        .pq_coupon_attestations
        .insert(attestation.attestation_id.clone(), attestation);
    state
        .redemption_receipts
        .insert(receipt.receipt_id.clone(), receipt);
    state
        .reserve_accounts
        .insert(reserve.reserve_id.clone(), reserve);
    state.public_events = vec![
        sample_event(
            "event:coupon-issued:alpha",
            "coupon_issued",
            "coupon:contract-storage:alpha",
        ),
        sample_event(
            "event:prefetch-credit-warmed:alpha",
            "prefetch_credit_warmed",
            "coupon:contract-storage:alpha",
        ),
        sample_event(
            "event:redemption-finalized:alpha",
            "redemption_finalized",
            "coupon:contract-storage:alpha",
        ),
    ];
    state.recompute_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "chain_id": state.config.chain_id,
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "pq_auth_suite": PQ_AUTH_SUITE,
        "l2_network": state.config.l2_network,
        "monero_network": state.config.monero_network,
        "fee_asset_id": state.config.fee_asset_id,
        "height": DEVNET_HEIGHT,
        "epoch": DEVNET_EPOCH,
        "counters": state.counters,
        "roots": state.roots,
        "operator_safe": {
            "target_user_fee_bps": state.config.target_user_fee_bps,
            "max_user_fee_bps": state.config.max_user_fee_bps,
            "sponsor_cover_bps": state.config.sponsor_cover_bps,
            "prefetch_rebate_bps": state.config.prefetch_rebate_bps,
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "min_pq_security_bits": state.config.min_pq_security_bits,
        },
        "public_events": state.public_events.iter().map(PublicEvent::operator_record).collect::<Vec<_>>(),
        "state_root": state.state_root(),
    })
}

pub fn state_root(state: &State) -> String {
    deterministic_state_root(state)
}

fn deterministic_state_root(state: &State) -> String {
    merkle_root(
        "private-l2-low-fee-pq-confidential-state-witness-fee-coupon:state-root",
        &[
            json!(PROTOCOL_VERSION),
            json!(state.config.chain_id),
            json!(state.roots.sponsor_treasury_root),
            json!(state.roots.witness_class_coupon_root),
            json!(state.roots.wallet_eligibility_cap_root),
            json!(state.roots.prefetch_credit_root),
            json!(state.roots.pq_coupon_attestation_root),
            json!(state.roots.redemption_receipt_root),
            json!(state.roots.reserve_accounting_root),
            json!(state.roots.public_event_root),
            json!(state.counters),
        ],
    )
}

fn root_from_public_records<I>(domain: &str, values: I) -> String
where
    I: Iterator<Item = Value>,
{
    merkle_root(domain, &values.collect::<Vec<_>>())
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &Vec::<Value>::new())
}

fn sample_root(domain: &str, id: &str) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(id)],
        32,
    )
}

fn coupon_id(treasury_id: &str, cap_id: &str, witness_class: WitnessClass, nonce: u64) -> String {
    domain_hash(
        "private-l2-low-fee-pq-confidential-state-witness-fee-coupon:coupon-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(treasury_id),
            HashPart::Str(cap_id),
            HashPart::Str(witness_class.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn sample_event(event_id: &str, kind: &str, subject_id: &str) -> PublicEvent {
    PublicEvent {
        event_id: event_id.to_string(),
        kind: kind.to_string(),
        subject_id: subject_id.to_string(),
        operator_safe_root: sample_root("operator-safe-event", event_id),
        height: DEVNET_HEIGHT,
    }
}
