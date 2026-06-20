use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialMultiSponsorFeeVoucherRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_SPONSOR_FEE_VOUCHER_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-multi-sponsor-fee-voucher-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_SPONSOR_FEE_VOUCHER_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-private-l2-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROUTER_SCHEME: &str = "low-fee-private-multi-sponsor-fee-voucher-router-v1";
pub const VOUCHER_LOT_SCHEME: &str = "ml-kem-1024-sealed-fee-voucher-lot-v1";
pub const PQ_SPONSOR_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-sponsor-attestation-v1";
pub const REDEMPTION_RECEIPT_SCHEME: &str = "confidential-fee-voucher-redemption-receipt-v1";
pub const ROUTE_CAP_SCHEME: &str = "low-fee-route-cap-root-v1";
pub const REBATE_ACCOUNTING_SCHEME: &str = "multi-sponsor-rebate-accounting-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "voucher-router-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "operator-safe-voucher-router-summary-root-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_sponsor_balances_voucher_amounts_accounts_or_decryption_keys";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_FAST_PATH_LATENCY_MS: u64 = 450;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_ROUTE_SPONSORS: usize = 8;
pub const DEFAULT_OPERATOR_BUCKET_SIZE: u64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCohortStatus {
    Open,
    Funding,
    Attesting,
    Active,
    Draining,
    Settling,
    Settled,
    Paused,
    Quarantined,
    Expired,
}

impl SponsorCohortStatus {
    pub fn accepts_lots(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Funding | Self::Attesting | Self::Active
        )
    }
    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }
    pub fn operator_visible(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Draining | Self::Settling | Self::Paused | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherRouteStatus {
    Draft,
    PrivacyChecked,
    CapChecked,
    SponsorMatched,
    Sealed,
    Attested,
    FastPathReady,
    Redeemed,
    Rebated,
    Throttled,
    Rejected,
    Expired,
}

impl VoucherRouteStatus {
    pub fn redeemable(self) -> bool {
        matches!(self, Self::FastPathReady | Self::Attested | Self::Sealed)
    }
    pub fn charged(self) -> bool {
        matches!(self, Self::Redeemed | Self::Rebated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherLotStatus {
    Sealed,
    Advertised,
    Reserved,
    PartiallyRedeemed,
    Exhausted,
    Revoked,
    Expired,
    Quarantined,
}
impl VoucherLotStatus {
    pub fn available(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Advertised | Self::PartiallyRedeemed
        )
    }
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryAudience {
    Operator,
    Sponsor,
    Watchtower,
    Auditor,
    Public,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    CohortOpened,
    LotSealed,
    RouteMatched,
    AttestationAccepted,
    VoucherRedeemed,
    RebatePosted,
    CapLimited,
    RedactionApplied,
    SummaryPublished,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub router_scheme: String,
    pub voucher_lot_scheme: String,
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
    pub fast_path_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub attestation_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_route_sponsors: usize,
    pub operator_bucket_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            router_scheme: ROUTER_SCHEME.to_string(),
            voucher_lot_scheme: VOUCHER_LOT_SCHEME.to_string(),
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
            fast_path_latency_ms: DEFAULT_FAST_PATH_LATENCY_MS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_route_sponsors: DEFAULT_MAX_ROUTE_SPONSORS,
            operator_bucket_size: DEFAULT_OPERATOR_BUCKET_SIZE,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.low_fee_bps > self.max_user_fee_bps {
            return Err("low_fee_bps must not exceed max_user_fee_bps".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS {
            return Err("max_user_fee_bps exceeds MAX_BPS".to_string());
        }
        if self.sponsor_cover_bps > MAX_BPS {
            return Err("sponsor_cover_bps exceeds MAX_BPS".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits too low".to_string());
        }
        if self.target_pq_security_bits < self.min_pq_security_bits {
            return Err("target_pq_security_bits below minimum".to_string());
        }
        if self.max_route_sponsors == 0 {
            return Err("max_route_sponsors must be positive".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "chain_id": self.chain_id, "l2_network": self.l2_network, "fee_asset_id": self.fee_asset_id, "hash_suite": self.hash_suite, "router_scheme": self.router_scheme, "voucher_lot_scheme": self.voucher_lot_scheme, "pq_sponsor_attestation_scheme": self.pq_sponsor_attestation_scheme, "redemption_receipt_scheme": self.redemption_receipt_scheme, "route_cap_scheme": self.route_cap_scheme, "rebate_accounting_scheme": self.rebate_accounting_scheme, "redaction_budget_scheme": self.redaction_budget_scheme, "operator_summary_scheme": self.operator_summary_scheme, "privacy_boundary": self.privacy_boundary, "low_fee_bps": self.low_fee_bps, "max_user_fee_bps": self.max_user_fee_bps, "target_rebate_bps": self.target_rebate_bps, "sponsor_cover_bps": self.sponsor_cover_bps, "fast_path_latency_ms": self.fast_path_latency_ms, "min_privacy_set_size": self.min_privacy_set_size, "target_privacy_set_size": self.target_privacy_set_size, "min_pq_security_bits": self.min_pq_security_bits, "target_pq_security_bits": self.target_pq_security_bits, "attestation_ttl_blocks": self.attestation_ttl_blocks, "voucher_ttl_blocks": self.voucher_ttl_blocks, "redaction_epoch_blocks": self.redaction_epoch_blocks, "max_route_sponsors": self.max_route_sponsors, "operator_bucket_size": self.operator_bucket_size })
    }
    pub fn config_root(&self) -> String {
        runtime_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_cohorts: u64,
    pub voucher_routes: u64,
    pub sealed_voucher_lots: u64,
    pub pq_sponsor_attestations: u64,
    pub redemption_receipts: u64,
    pub route_caps: u64,
    pub rebate_accounts: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub runtime_events: u64,
    pub fast_path_routes: u64,
    pub private_routes: u64,
    pub rejected_routes: u64,
    pub total_voucher_units: u64,
    pub redeemed_voucher_units: u64,
    pub rebated_fee_units: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({ "sponsor_cohorts": self.sponsor_cohorts, "voucher_routes": self.voucher_routes, "sealed_voucher_lots": self.sealed_voucher_lots, "pq_sponsor_attestations": self.pq_sponsor_attestations, "redemption_receipts": self.redemption_receipts, "route_caps": self.route_caps, "rebate_accounts": self.rebate_accounts, "redaction_budgets": self.redaction_budgets, "operator_summaries": self.operator_summaries, "runtime_events": self.runtime_events, "fast_path_routes": self.fast_path_routes, "private_routes": self.private_routes, "rejected_routes": self.rejected_routes, "total_voucher_units": self.total_voucher_units, "redeemed_voucher_units": self.redeemed_voucher_units, "rebated_fee_units": self.rebated_fee_units })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub sponsor_cohort_root: String,
    pub voucher_route_root: String,
    pub sealed_voucher_lot_root: String,
    pub pq_sponsor_attestation_root: String,
    pub redemption_receipt_root: String,
    pub route_cap_root: String,
    pub rebate_accounting_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub runtime_event_root: String,
    pub public_record_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({ "config_root": self.config_root, "sponsor_cohort_root": self.sponsor_cohort_root, "voucher_route_root": self.voucher_route_root, "sealed_voucher_lot_root": self.sealed_voucher_lot_root, "pq_sponsor_attestation_root": self.pq_sponsor_attestation_root, "redemption_receipt_root": self.redemption_receipt_root, "route_cap_root": self.route_cap_root, "rebate_accounting_root": self.rebate_accounting_root, "redaction_budget_root": self.redaction_budget_root, "operator_summary_root": self.operator_summary_root, "runtime_event_root": self.runtime_event_root, "public_record_root": self.public_record_root })
    }
    pub fn roots_root(&self) -> String {
        runtime_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCohort {
    pub cohort_id: String,
    pub sponsor_commitment_root: String,
    pub funding_nullifier_root: String,
    pub status: SponsorCohortStatus,
    pub sponsor_count: u64,
    pub available_voucher_units: u64,
    pub reserved_voucher_units: u64,
    pub redeemed_voucher_units: u64,
    pub low_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub labels: BTreeSet<String>,
}
impl SponsorCohort {
    pub fn new(
        cohort_id: impl Into<String>,
        opened_height: u64,
        sponsor_count: u64,
        units: u64,
        config: &Config,
    ) -> Self {
        let cohort_id = cohort_id.into();
        let commitment = runtime_id(
            "COHORT-COMMITMENT",
            &[HashPart::Str(&cohort_id), HashPart::U64(opened_height)],
        );
        Self {
            cohort_id,
            sponsor_commitment_root: commitment,
            funding_nullifier_root: runtime_empty_root("COHORT-NULLIFIERS"),
            status: SponsorCohortStatus::Open,
            sponsor_count,
            available_voucher_units: units,
            reserved_voucher_units: 0,
            redeemed_voucher_units: 0,
            low_fee_bps: config.low_fee_bps,
            sponsor_cover_bps: config.sponsor_cover_bps,
            pq_security_bits: config.target_pq_security_bits,
            privacy_set_size: config.target_privacy_set_size,
            opened_height,
            expires_height: opened_height.saturating_add(config.voucher_ttl_blocks),
            labels: BTreeSet::new(),
        }
    }
    pub fn reserve(&mut self, units: u64) -> Result<()> {
        if !self.status.spendable() && self.status != SponsorCohortStatus::Open {
            return Err("cohort is not spendable".to_string());
        }
        if units > self.available_voucher_units {
            return Err("insufficient cohort voucher units".to_string());
        }
        self.available_voucher_units = self.available_voucher_units.saturating_sub(units);
        self.reserved_voucher_units = self.reserved_voucher_units.saturating_add(units);
        if self.status == SponsorCohortStatus::Open {
            self.status = SponsorCohortStatus::Active;
        }
        Ok(())
    }
    pub fn redeem_reserved(&mut self, units: u64) -> Result<()> {
        if units > self.reserved_voucher_units {
            return Err("redeem exceeds reserved units".to_string());
        }
        self.reserved_voucher_units = self.reserved_voucher_units.saturating_sub(units);
        self.redeemed_voucher_units = self.redeemed_voucher_units.saturating_add(units);
        if self.available_voucher_units == 0 && self.reserved_voucher_units == 0 {
            self.status = SponsorCohortStatus::Settling;
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "sponsor_cohort", "protocol_version": PROTOCOL_VERSION, "cohort_id": self.cohort_id, "sponsor_commitment_root": self.sponsor_commitment_root, "funding_nullifier_root": self.funding_nullifier_root, "status": self.status, "sponsor_count": self.sponsor_count, "available_voucher_units": self.available_voucher_units, "reserved_voucher_units": self.reserved_voucher_units, "redeemed_voucher_units": self.redeemed_voucher_units, "low_fee_bps": self.low_fee_bps, "sponsor_cover_bps": self.sponsor_cover_bps, "pq_security_bits": self.pq_security_bits, "privacy_set_size": self.privacy_set_size, "opened_height": self.opened_height, "expires_height": self.expires_height, "labels": self.labels.iter().cloned().collect::<Vec<_>>() })
    }
    pub fn cohort_root(&self) -> String {
        runtime_root("SPONSOR-COHORT", &self.public_record())
    }
    pub fn utilization_bps(&self) -> u64 {
        bps(
            self.reserved_voucher_units
                .saturating_add(self.redeemed_voucher_units),
            self.available_voucher_units
                .saturating_add(self.reserved_voucher_units)
                .saturating_add(self.redeemed_voucher_units),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VoucherRoute {
    pub route_id: String,
    pub cohort_id: String,
    pub cap_id: String,
    pub lot_id: String,
    pub route_commitment: String,
    pub payer_note_commitment: String,
    pub fee_asset_id: String,
    pub voucher_units: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub expected_latency_ms: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: VoucherRouteStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub sponsor_commitments: Vec<String>,
}
impl VoucherRoute {
    pub fn new(
        route_id: impl Into<String>,
        cohort_id: impl Into<String>,
        cap_id: impl Into<String>,
        lot_id: impl Into<String>,
        units: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let route_id = route_id.into();
        let cohort_id = cohort_id.into();
        let cap_id = cap_id.into();
        let lot_id = lot_id.into();
        Self {
            route_commitment: runtime_id(
                "ROUTE-COMMITMENT",
                &[
                    HashPart::Str(&route_id),
                    HashPart::Str(&cohort_id),
                    HashPart::U64(units),
                ],
            ),
            payer_note_commitment: runtime_id(
                "PAYER-NOTE",
                &[HashPart::Str(&route_id), HashPart::U64(height)],
            ),
            route_id,
            cohort_id,
            cap_id,
            lot_id,
            fee_asset_id: config.fee_asset_id.clone(),
            voucher_units: units,
            max_user_fee_bps: config.max_user_fee_bps,
            sponsor_cover_bps: config.sponsor_cover_bps,
            expected_latency_ms: config.fast_path_latency_ms,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.target_pq_security_bits,
            status: VoucherRouteStatus::Draft,
            created_height: height,
            expires_height: height.saturating_add(config.voucher_ttl_blocks),
            sponsor_commitments: Vec::new(),
        }
    }
    pub fn attach_sponsor_commitment(
        &mut self,
        commitment: impl Into<String>,
        config: &Config,
    ) -> Result<()> {
        if self.sponsor_commitments.len() >= config.max_route_sponsors {
            return Err("route sponsor fanout exceeds config".to_string());
        }
        self.sponsor_commitments.push(commitment.into());
        self.status = VoucherRouteStatus::SponsorMatched;
        Ok(())
    }
    pub fn mark_attested(&mut self) {
        self.status = VoucherRouteStatus::Attested;
    }
    pub fn mark_redeemed(&mut self) -> Result<()> {
        if !self.status.redeemable() {
            return Err("route is not redeemable".to_string());
        }
        self.status = VoucherRouteStatus::Redeemed;
        Ok(())
    }
    pub fn effective_user_fee_units(&self) -> u64 {
        self.voucher_units.saturating_mul(self.max_user_fee_bps) / MAX_BPS
    }
    pub fn sponsor_cover_units(&self) -> u64 {
        self.voucher_units.saturating_mul(self.sponsor_cover_bps) / MAX_BPS
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "voucher_route", "protocol_version": PROTOCOL_VERSION, "route_id": self.route_id, "cohort_id": self.cohort_id, "cap_id": self.cap_id, "lot_id": self.lot_id, "route_commitment": self.route_commitment, "payer_note_commitment": self.payer_note_commitment, "fee_asset_id": self.fee_asset_id, "voucher_units": self.voucher_units, "max_user_fee_bps": self.max_user_fee_bps, "sponsor_cover_bps": self.sponsor_cover_bps, "expected_latency_ms": self.expected_latency_ms, "privacy_set_size": self.privacy_set_size, "pq_security_bits": self.pq_security_bits, "status": self.status, "created_height": self.created_height, "expires_height": self.expires_height, "sponsor_commitments": self.sponsor_commitments })
    }
    pub fn route_root(&self) -> String {
        runtime_root("VOUCHER-ROUTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedVoucherLot {
    pub lot_id: String,
    pub cohort_id: String,
    pub sealed_ciphertext_root: String,
    pub voucher_commitment_root: String,
    pub nullifier_root: String,
    pub units_total: u64,
    pub units_reserved: u64,
    pub units_redeemed: u64,
    pub min_split_units: u64,
    pub max_split_units: u64,
    pub status: VoucherLotStatus,
    pub pq_kem: String,
    pub opened_height: u64,
    pub expires_height: u64,
}
impl SealedVoucherLot {
    pub fn new(
        lot_id: impl Into<String>,
        cohort_id: impl Into<String>,
        units: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let lot_id = lot_id.into();
        let cohort_id = cohort_id.into();
        Self {
            sealed_ciphertext_root: runtime_id(
                "SEALED-LOT-CIPHERTEXT",
                &[HashPart::Str(&lot_id), HashPart::Str(&cohort_id)],
            ),
            voucher_commitment_root: runtime_id(
                "VOUCHER-COMMITMENTS",
                &[HashPart::Str(&lot_id), HashPart::U64(units)],
            ),
            nullifier_root: runtime_empty_root("LOT-NULLIFIERS"),
            lot_id,
            cohort_id,
            units_total: units,
            units_reserved: 0,
            units_redeemed: 0,
            min_split_units: 1,
            max_split_units: units.max(1) / 4 + 1,
            status: VoucherLotStatus::Sealed,
            pq_kem: "ML-KEM-1024".to_string(),
            opened_height: height,
            expires_height: height.saturating_add(config.voucher_ttl_blocks),
        }
    }
    pub fn reserve(&mut self, units: u64) -> Result<()> {
        if !self.status.available() {
            return Err("voucher lot is unavailable".to_string());
        }
        if self.remaining_units() < units {
            return Err("voucher lot capacity exceeded".to_string());
        }
        self.units_reserved = self.units_reserved.saturating_add(units);
        self.status = VoucherLotStatus::Reserved;
        Ok(())
    }
    pub fn redeem(&mut self, units: u64) -> Result<()> {
        if units > self.units_reserved {
            return Err("redeem exceeds lot reservation".to_string());
        }
        self.units_reserved = self.units_reserved.saturating_sub(units);
        self.units_redeemed = self.units_redeemed.saturating_add(units);
        self.status = if self.remaining_units() == 0 && self.units_reserved == 0 {
            VoucherLotStatus::Exhausted
        } else {
            VoucherLotStatus::PartiallyRedeemed
        };
        Ok(())
    }
    pub fn remaining_units(&self) -> u64 {
        self.units_total
            .saturating_sub(self.units_reserved)
            .saturating_sub(self.units_redeemed)
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "sealed_voucher_lot", "protocol_version": PROTOCOL_VERSION, "lot_id": self.lot_id, "cohort_id": self.cohort_id, "sealed_ciphertext_root": self.sealed_ciphertext_root, "voucher_commitment_root": self.voucher_commitment_root, "nullifier_root": self.nullifier_root, "units_total": self.units_total, "units_reserved": self.units_reserved, "units_redeemed": self.units_redeemed, "min_split_units": self.min_split_units, "max_split_units": self.max_split_units, "status": self.status, "pq_kem": self.pq_kem, "opened_height": self.opened_height, "expires_height": self.expires_height })
    }
    pub fn lot_root(&self) -> String {
        runtime_root("SEALED-VOUCHER-LOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSponsorAttestation {
    pub attestation_id: String,
    pub cohort_id: String,
    pub sponsor_set_root: String,
    pub route_root: String,
    pub signature_root: String,
    pub algorithm_suite: String,
    pub security_bits: u16,
    pub quorum_weight_bps: u64,
    pub status: AttestationStatus,
    pub issued_height: u64,
    pub expires_height: u64,
}
impl PqSponsorAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        cohort_id: impl Into<String>,
        route_root: impl Into<String>,
        height: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let cohort_id = cohort_id.into();
        Self {
            sponsor_set_root: runtime_id("SPONSOR-SET", &[HashPart::Str(&cohort_id)]),
            signature_root: runtime_id("PQ-SPONSOR-SIGNATURE", &[HashPart::Str(&attestation_id)]),
            attestation_id,
            cohort_id,
            route_root: route_root.into(),
            algorithm_suite: PQ_SPONSOR_ATTESTATION_SCHEME.to_string(),
            security_bits: config.target_pq_security_bits,
            quorum_weight_bps: 8_000,
            status: AttestationStatus::Submitted,
            issued_height: height,
            expires_height: height.saturating_add(config.attestation_ttl_blocks),
        }
    }
    pub fn accept(&mut self) {
        self.status = if self.quorum_weight_bps >= 8_000 {
            AttestationStatus::StrongQuorum
        } else {
            AttestationStatus::Accepted
        };
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "pq_sponsor_attestation", "protocol_version": PROTOCOL_VERSION, "attestation_id": self.attestation_id, "cohort_id": self.cohort_id, "sponsor_set_root": self.sponsor_set_root, "route_root": self.route_root, "signature_root": self.signature_root, "algorithm_suite": self.algorithm_suite, "security_bits": self.security_bits, "quorum_weight_bps": self.quorum_weight_bps, "status": self.status, "issued_height": self.issued_height, "expires_height": self.expires_height })
    }
    pub fn attestation_root(&self) -> String {
        runtime_root("PQ-SPONSOR-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionReceipt {
    pub receipt_id: String,
    pub route_id: String,
    pub lot_id: String,
    pub cohort_id: String,
    pub redemption_nullifier: String,
    pub inclusion_root: String,
    pub redeemed_units: u64,
    pub charged_fee_units: u64,
    pub rebated_fee_units: u64,
    pub latency_ms: u64,
    pub status: ReceiptStatus,
    pub observed_height: u64,
    pub finalized_height: u64,
}
impl RedemptionReceipt {
    pub fn from_route(
        receipt_id: impl Into<String>,
        route: &VoucherRoute,
        height: u64,
        config: &Config,
    ) -> Self {
        let receipt_id = receipt_id.into();
        let charged_fee_units = route.effective_user_fee_units();
        let rebated_fee_units =
            route.voucher_units.saturating_mul(config.target_rebate_bps) / MAX_BPS;
        Self {
            redemption_nullifier: runtime_id(
                "REDEMPTION-NULLIFIER",
                &[HashPart::Str(&receipt_id), HashPart::Str(&route.route_id)],
            ),
            inclusion_root: runtime_id(
                "REDEMPTION-INCLUSION",
                &[HashPart::Str(&route.route_id), HashPart::U64(height)],
            ),
            receipt_id,
            route_id: route.route_id.clone(),
            lot_id: route.lot_id.clone(),
            cohort_id: route.cohort_id.clone(),
            redeemed_units: route.voucher_units,
            charged_fee_units,
            rebated_fee_units,
            latency_ms: route.expected_latency_ms,
            status: ReceiptStatus::Observed,
            observed_height: height,
            finalized_height: height,
        }
    }
    pub fn finalize(&mut self, height: u64) {
        self.status = ReceiptStatus::Finalized;
        self.finalized_height = height;
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "redemption_receipt", "protocol_version": PROTOCOL_VERSION, "receipt_id": self.receipt_id, "route_id": self.route_id, "lot_id": self.lot_id, "cohort_id": self.cohort_id, "redemption_nullifier": self.redemption_nullifier, "inclusion_root": self.inclusion_root, "redeemed_units": self.redeemed_units, "charged_fee_units": self.charged_fee_units, "rebated_fee_units": self.rebated_fee_units, "latency_ms": self.latency_ms, "status": self.status, "observed_height": self.observed_height, "finalized_height": self.finalized_height })
    }
    pub fn receipt_root(&self) -> String {
        runtime_root("REDEMPTION-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCap {
    pub cap_id: String,
    pub cohort_id: String,
    pub max_units_per_epoch: u64,
    pub used_units: u64,
    pub max_routes_per_epoch: u64,
    pub used_routes: u64,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub status: CapStatus,
    pub epoch: u64,
}
impl RouteCap {
    pub fn new(
        cap_id: impl Into<String>,
        cohort_id: impl Into<String>,
        epoch: u64,
        config: &Config,
    ) -> Self {
        Self {
            cap_id: cap_id.into(),
            cohort_id: cohort_id.into(),
            max_units_per_epoch: 1_000_000,
            used_units: 0,
            max_routes_per_epoch: 4_096,
            used_routes: 0,
            min_privacy_set_size: config.min_privacy_set_size,
            max_user_fee_bps: config.max_user_fee_bps,
            status: CapStatus::Open,
            epoch,
        }
    }
    pub fn consume(&mut self, units: u64) -> Result<()> {
        if matches!(
            self.status,
            CapStatus::HardLimited | CapStatus::Exhausted | CapStatus::Disabled
        ) {
            return Err("route cap is closed".to_string());
        }
        if self.used_units.saturating_add(units) > self.max_units_per_epoch {
            self.status = CapStatus::Exhausted;
            return Err("route cap units exhausted".to_string());
        }
        if self.used_routes.saturating_add(1) > self.max_routes_per_epoch {
            self.status = CapStatus::HardLimited;
            return Err("route cap count exhausted".to_string());
        }
        self.used_units = self.used_units.saturating_add(units);
        self.used_routes = self.used_routes.saturating_add(1);
        self.status = if self.utilization_bps() > 8_500 {
            CapStatus::Hot
        } else if self.utilization_bps() > 6_000 {
            CapStatus::Warm
        } else {
            CapStatus::Open
        };
        Ok(())
    }
    pub fn utilization_bps(&self) -> u64 {
        bps(self.used_units, self.max_units_per_epoch)
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "route_cap", "protocol_version": PROTOCOL_VERSION, "cap_id": self.cap_id, "cohort_id": self.cohort_id, "max_units_per_epoch": self.max_units_per_epoch, "used_units": self.used_units, "max_routes_per_epoch": self.max_routes_per_epoch, "used_routes": self.used_routes, "min_privacy_set_size": self.min_privacy_set_size, "max_user_fee_bps": self.max_user_fee_bps, "status": self.status, "epoch": self.epoch })
    }
    pub fn cap_root(&self) -> String {
        runtime_root("ROUTE-CAP", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAccounting {
    pub account_id: String,
    pub sponsor_id_commitment: String,
    pub cohort_id: String,
    pub accrued_fee_units: u64,
    pub claimable_fee_units: u64,
    pub posted_fee_units: u64,
    pub slashed_fee_units: u64,
    pub status: RebateStatus,
    pub accounting_root: String,
}
impl RebateAccounting {
    pub fn new(account_id: impl Into<String>, cohort_id: impl Into<String>) -> Self {
        let account_id = account_id.into();
        let cohort_id = cohort_id.into();
        Self {
            sponsor_id_commitment: runtime_id("SPONSOR-ID", &[HashPart::Str(&account_id)]),
            accounting_root: runtime_empty_root("REBATE-ACCOUNTING"),
            account_id,
            cohort_id,
            accrued_fee_units: 0,
            claimable_fee_units: 0,
            posted_fee_units: 0,
            slashed_fee_units: 0,
            status: RebateStatus::Accruing,
        }
    }
    pub fn accrue(&mut self, units: u64) {
        self.accrued_fee_units = self.accrued_fee_units.saturating_add(units);
        self.claimable_fee_units = self.claimable_fee_units.saturating_add(units);
        self.status = RebateStatus::Claimable;
        self.accounting_root = runtime_id(
            "REBATE-ACCOUNTING",
            &[
                HashPart::Str(&self.account_id),
                HashPart::U64(self.accrued_fee_units),
                HashPart::U64(self.posted_fee_units),
            ],
        );
    }
    pub fn post(&mut self, units: u64) -> Result<()> {
        if units > self.claimable_fee_units {
            return Err("post exceeds claimable rebate".to_string());
        }
        self.claimable_fee_units = self.claimable_fee_units.saturating_sub(units);
        self.posted_fee_units = self.posted_fee_units.saturating_add(units);
        self.status = RebateStatus::Posted;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "rebate_accounting", "protocol_version": PROTOCOL_VERSION, "account_id": self.account_id, "sponsor_id_commitment": self.sponsor_id_commitment, "cohort_id": self.cohort_id, "accrued_fee_units": self.accrued_fee_units, "claimable_fee_units": self.claimable_fee_units, "posted_fee_units": self.posted_fee_units, "slashed_fee_units": self.slashed_fee_units, "status": self.status, "accounting_root": self.accounting_root })
    }
    pub fn rebate_root(&self) -> String {
        runtime_root("REBATE-ACCOUNTING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_root: String,
    pub epoch: u64,
    pub available_units: u64,
    pub reserved_units: u64,
    pub applied_units: u64,
    pub status: BudgetStatus,
}
impl RedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        subject_root: impl Into<String>,
        epoch: u64,
        units: u64,
    ) -> Self {
        Self {
            budget_id: budget_id.into(),
            subject_root: subject_root.into(),
            epoch,
            available_units: units,
            reserved_units: 0,
            applied_units: 0,
            status: BudgetStatus::Open,
        }
    }
    pub fn reserve(&mut self, units: u64) -> Result<()> {
        if units > self.available_units {
            self.status = BudgetStatus::Exhausted;
            return Err("redaction budget exhausted".to_string());
        }
        self.available_units = self.available_units.saturating_sub(units);
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.status = BudgetStatus::Reserved;
        Ok(())
    }
    pub fn apply(&mut self, units: u64) -> Result<()> {
        if units > self.reserved_units {
            return Err("redaction apply exceeds reservation".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.applied_units = self.applied_units.saturating_add(units);
        self.status = if self.available_units == 0 && self.reserved_units == 0 {
            BudgetStatus::Exhausted
        } else {
            BudgetStatus::Applied
        };
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "redaction_budget", "protocol_version": PROTOCOL_VERSION, "budget_id": self.budget_id, "subject_root": self.subject_root, "epoch": self.epoch, "available_units": self.available_units, "reserved_units": self.reserved_units, "applied_units": self.applied_units, "status": self.status })
    }
    pub fn budget_root(&self) -> String {
        runtime_root("REDACTION-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub audience: SummaryAudience,
    pub height: u64,
    pub cohort_root: String,
    pub route_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub active_cohorts: u64,
    pub fast_path_routes: u64,
    pub median_latency_ms: u64,
    pub low_fee_bps: u64,
    pub public_record_root: String,
}
impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({ "kind": "operator_summary", "protocol_version": PROTOCOL_VERSION, "summary_id": self.summary_id, "audience": self.audience, "height": self.height, "cohort_root": self.cohort_root, "route_root": self.route_root, "receipt_root": self.receipt_root, "rebate_root": self.rebate_root, "redaction_root": self.redaction_root, "active_cohorts": self.active_cohorts, "fast_path_routes": self.fast_path_routes, "median_latency_ms": self.median_latency_ms, "low_fee_bps": self.low_fee_bps, "public_record_root": self.public_record_root })
    }
    pub fn summary_root(&self) -> String {
        runtime_root("OPERATOR-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: RuntimeEventKind,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub public_payload: Value,
}
impl RuntimeEvent {
    pub fn new(
        kind: RuntimeEventKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        height: u64,
        public_payload: Value,
    ) -> Self {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        Self {
            event_id: runtime_id(
                "EVENT",
                &[
                    HashPart::Str(&format!("{:?}", kind)),
                    HashPart::Str(&subject_id),
                    HashPart::U64(height),
                ],
            ),
            kind,
            subject_id,
            subject_root,
            height,
            public_payload,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({ "kind": "runtime_event", "protocol_version": PROTOCOL_VERSION, "event_id": self.event_id, "event_kind": self.kind, "subject_id": self.subject_id, "subject_root": self.subject_root, "height": self.height, "public_payload": self.public_payload })
    }
    pub fn event_root(&self) -> String {
        runtime_root("RUNTIME-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsor_cohorts: BTreeMap<String, SponsorCohort>,
    pub voucher_routes: BTreeMap<String, VoucherRoute>,
    pub sealed_voucher_lots: BTreeMap<String, SealedVoucherLot>,
    pub pq_sponsor_attestations: BTreeMap<String, PqSponsorAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub route_caps: BTreeMap<String, RouteCap>,
    pub rebate_accounting: BTreeMap<String, RebateAccounting>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub runtime_events: Vec<RuntimeEvent>,
    pub public_records: BTreeMap<String, Value>,
    pub state_root: String,
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
            sponsor_cohorts: BTreeMap::new(),
            voucher_routes: BTreeMap::new(),
            sealed_voucher_lots: BTreeMap::new(),
            pq_sponsor_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            rebate_accounting: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            runtime_events: Vec::new(),
            public_records: BTreeMap::new(),
            state_root: String::new(),
        };
        state.refresh();
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
    pub fn insert_sponsor_cohort(&mut self, cohort: SponsorCohort) -> Result<()> {
        self.config.validate()?;
        if self.sponsor_cohorts.contains_key(&cohort.cohort_id) {
            return Err("duplicate sponsor cohort".to_string());
        }
        self.emit(
            RuntimeEventKind::CohortOpened,
            &cohort.cohort_id,
            &cohort.cohort_root(),
            cohort.opened_height,
            json!({"status": cohort.status, "privacy_set_size": cohort.privacy_set_size}),
        );
        self.sponsor_cohorts
            .insert(cohort.cohort_id.clone(), cohort);
        self.refresh();
        Ok(())
    }
    pub fn insert_voucher_lot(&mut self, lot: SealedVoucherLot) -> Result<()> {
        if !self.sponsor_cohorts.contains_key(&lot.cohort_id) {
            return Err("lot references unknown cohort".to_string());
        }
        self.emit(
            RuntimeEventKind::LotSealed,
            &lot.lot_id,
            &lot.lot_root(),
            lot.opened_height,
            json!({"units_total": lot.units_total}),
        );
        self.sealed_voucher_lots.insert(lot.lot_id.clone(), lot);
        self.refresh();
        Ok(())
    }
    pub fn insert_route_cap(&mut self, cap: RouteCap) -> Result<()> {
        if !self.sponsor_cohorts.contains_key(&cap.cohort_id) {
            return Err("cap references unknown cohort".to_string());
        }
        self.route_caps.insert(cap.cap_id.clone(), cap);
        self.refresh();
        Ok(())
    }
    pub fn insert_rebate_account(&mut self, account: RebateAccounting) -> Result<()> {
        if !self.sponsor_cohorts.contains_key(&account.cohort_id) {
            return Err("rebate account references unknown cohort".to_string());
        }
        self.rebate_accounting
            .insert(account.account_id.clone(), account);
        self.refresh();
        Ok(())
    }
    pub fn reserve_route(&mut self, mut route: VoucherRoute) -> Result<String> {
        self.config.validate()?;
        let cohort = self
            .sponsor_cohorts
            .get_mut(&route.cohort_id)
            .ok_or_else(|| "route references unknown cohort".to_string())?;
        let lot = self
            .sealed_voucher_lots
            .get_mut(&route.lot_id)
            .ok_or_else(|| "route references unknown voucher lot".to_string())?;
        let cap = self
            .route_caps
            .get_mut(&route.cap_id)
            .ok_or_else(|| "route references unknown cap".to_string())?;
        if route.privacy_set_size < self.config.min_privacy_set_size {
            route.status = VoucherRouteStatus::Rejected;
            return Err("route privacy set below minimum".to_string());
        }
        cap.consume(route.voucher_units)?;
        cohort.reserve(route.voucher_units)?;
        lot.reserve(route.voucher_units)?;
        route.status = VoucherRouteStatus::FastPathReady;
        let route_id = route.route_id.clone();
        self.emit(
            RuntimeEventKind::RouteMatched,
            &route_id,
            &route.route_root(),
            route.created_height,
            json!({"voucher_units": route.voucher_units, "latency_ms": route.expected_latency_ms}),
        );
        self.voucher_routes.insert(route_id.clone(), route);
        self.refresh();
        Ok(route_id)
    }
    pub fn accept_attestation(&mut self, mut attestation: PqSponsorAttestation) -> Result<()> {
        if !self.sponsor_cohorts.contains_key(&attestation.cohort_id) {
            return Err("attestation references unknown cohort".to_string());
        }
        attestation.accept();
        self.emit(RuntimeEventKind::AttestationAccepted, &attestation.attestation_id, &attestation.attestation_root(), attestation.issued_height, json!({"security_bits": attestation.security_bits, "quorum_weight_bps": attestation.quorum_weight_bps}));
        self.pq_sponsor_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh();
        Ok(())
    }
    pub fn redeem_route(
        &mut self,
        route_id: &str,
        receipt_id: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        let route = self
            .voucher_routes
            .get_mut(route_id)
            .ok_or_else(|| "unknown route".to_string())?;
        route.mark_redeemed()?;
        let receipt = RedemptionReceipt::from_route(receipt_id, route, height, &self.config);
        if let Some(cohort) = self.sponsor_cohorts.get_mut(&route.cohort_id) {
            cohort.redeem_reserved(route.voucher_units)?;
        }
        if let Some(lot) = self.sealed_voucher_lots.get_mut(&route.lot_id) {
            lot.redeem(route.voucher_units)?;
        }
        for account in self
            .rebate_accounting
            .values_mut()
            .filter(|account| account.cohort_id == route.cohort_id)
        {
            account.accrue(receipt.rebated_fee_units);
        }
        let receipt_id = receipt.receipt_id.clone();
        self.emit(RuntimeEventKind::VoucherRedeemed, &receipt_id, &receipt.receipt_root(), height, json!({"redeemed_units": receipt.redeemed_units, "rebated_fee_units": receipt.rebated_fee_units}));
        self.redemption_receipts.insert(receipt_id.clone(), receipt);
        self.refresh();
        Ok(receipt_id)
    }
    pub fn apply_redaction_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let height = self
            .runtime_events
            .last()
            .map(|event| event.height)
            .unwrap_or_default();
        let (subject_root, event_root) = {
            let budget = self
                .redaction_budgets
                .get_mut(budget_id)
                .ok_or_else(|| "unknown redaction budget".to_string())?;
            budget.reserve(units)?;
            budget.apply(units)?;
            (budget.subject_root.clone(), budget.budget_root())
        };
        self.emit(
            RuntimeEventKind::RedactionApplied,
            budget_id,
            &event_root,
            height,
            json!({"subject_root": subject_root, "units": units}),
        );
        self.refresh();
        Ok(())
    }
    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) {
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh();
    }
    pub fn publish_operator_summary(
        &mut self,
        summary_id: impl Into<String>,
        audience: SummaryAudience,
        height: u64,
    ) -> String {
        self.refresh();
        let summary_id = summary_id.into();
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            audience,
            height,
            cohort_root: self.roots.sponsor_cohort_root.clone(),
            route_root: self.roots.voucher_route_root.clone(),
            receipt_root: self.roots.redemption_receipt_root.clone(),
            rebate_root: self.roots.rebate_accounting_root.clone(),
            redaction_root: self.roots.redaction_budget_root.clone(),
            active_cohorts: self
                .sponsor_cohorts
                .values()
                .filter(|cohort| cohort.status.spendable())
                .count() as u64,
            fast_path_routes: self
                .voucher_routes
                .values()
                .filter(|route| {
                    route.status == VoucherRouteStatus::FastPathReady || route.status.charged()
                })
                .count() as u64,
            median_latency_ms: self.config.fast_path_latency_ms,
            low_fee_bps: self.config.low_fee_bps,
            public_record_root: self.roots.public_record_root.clone(),
        };
        self.emit(
            RuntimeEventKind::SummaryPublished,
            &summary_id,
            &summary.summary_root(),
            height,
            json!({"audience": audience}),
        );
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.refresh();
        summary_id
    }
    pub fn privacy_score_bps(&self) -> u64 {
        let private_routes = self
            .voucher_routes
            .values()
            .filter(|route| {
                route.privacy_set_size >= self.config.target_privacy_set_size
                    && route.pq_security_bits >= self.config.target_pq_security_bits
            })
            .count() as u64;
        bps(private_routes, self.voucher_routes.len() as u64)
    }
    pub fn speed_score_bps(&self) -> u64 {
        let fast_routes = self
            .voucher_routes
            .values()
            .filter(|route| route.expected_latency_ms <= self.config.fast_path_latency_ms)
            .count() as u64;
        bps(fast_routes, self.voucher_routes.len() as u64)
    }
    pub fn low_fee_score_bps(&self) -> u64 {
        let low_fee_routes = self
            .voucher_routes
            .values()
            .filter(|route| route.max_user_fee_bps <= self.config.max_user_fee_bps)
            .count() as u64;
        bps(low_fee_routes, self.voucher_routes.len() as u64)
    }
    pub fn pq_score_bps(&self) -> u64 {
        let pq_routes = self
            .voucher_routes
            .values()
            .filter(|route| route.pq_security_bits >= self.config.min_pq_security_bits)
            .count() as u64;
        bps(pq_routes, self.voucher_routes.len() as u64)
    }
    pub fn operator_health_record(&self) -> Value {
        json!({ "privacy_score_bps": self.privacy_score_bps(), "speed_score_bps": self.speed_score_bps(), "low_fee_score_bps": self.low_fee_score_bps(), "pq_score_bps": self.pq_score_bps(), "state_root": self.state_root })
    }
    fn emit(
        &mut self,
        kind: RuntimeEventKind,
        subject_id: &str,
        subject_root: &str,
        height: u64,
        public_payload: Value,
    ) {
        self.runtime_events.push(RuntimeEvent::new(
            kind,
            subject_id,
            subject_root,
            height,
            public_payload,
        ));
    }
    fn refresh(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.compute_roots();
        self.refresh_public_records();
        self.roots.public_record_root = map_root("PUBLIC-RECORDS", &self.public_records);
        self.state_root = private_l2_low_fee_pq_confidential_multi_sponsor_fee_voucher_router_state_root_from_record(&self.public_record_without_state_root());
    }
    fn compute_counters(&self) -> Counters {
        Counters {
            sponsor_cohorts: self.sponsor_cohorts.len() as u64,
            voucher_routes: self.voucher_routes.len() as u64,
            sealed_voucher_lots: self.sealed_voucher_lots.len() as u64,
            pq_sponsor_attestations: self.pq_sponsor_attestations.len() as u64,
            redemption_receipts: self.redemption_receipts.len() as u64,
            route_caps: self.route_caps.len() as u64,
            rebate_accounts: self.rebate_accounting.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            runtime_events: self.runtime_events.len() as u64,
            fast_path_routes: self
                .voucher_routes
                .values()
                .filter(|route| {
                    route.status == VoucherRouteStatus::FastPathReady || route.status.charged()
                })
                .count() as u64,
            private_routes: self
                .voucher_routes
                .values()
                .filter(|route| route.privacy_set_size >= self.config.min_privacy_set_size)
                .count() as u64,
            rejected_routes: self
                .voucher_routes
                .values()
                .filter(|route| route.status == VoucherRouteStatus::Rejected)
                .count() as u64,
            total_voucher_units: self
                .sealed_voucher_lots
                .values()
                .map(|lot| lot.units_total)
                .sum(),
            redeemed_voucher_units: self
                .redemption_receipts
                .values()
                .map(|receipt| receipt.redeemed_units)
                .sum(),
            rebated_fee_units: self
                .redemption_receipts
                .values()
                .map(|receipt| receipt.rebated_fee_units)
                .sum(),
        }
    }
    fn compute_roots(&self) -> Roots {
        Roots {
            config_root: self.config.config_root(),
            sponsor_cohort_root: collection_root(
                "SPONSOR-COHORTS",
                self.sponsor_cohorts
                    .values()
                    .map(SponsorCohort::public_record)
                    .collect(),
            ),
            voucher_route_root: collection_root(
                "VOUCHER-ROUTES",
                self.voucher_routes
                    .values()
                    .map(VoucherRoute::public_record)
                    .collect(),
            ),
            sealed_voucher_lot_root: collection_root(
                "SEALED-VOUCHER-LOTS",
                self.sealed_voucher_lots
                    .values()
                    .map(SealedVoucherLot::public_record)
                    .collect(),
            ),
            pq_sponsor_attestation_root: collection_root(
                "PQ-SPONSOR-ATTESTATIONS",
                self.pq_sponsor_attestations
                    .values()
                    .map(PqSponsorAttestation::public_record)
                    .collect(),
            ),
            redemption_receipt_root: collection_root(
                "REDEMPTION-RECEIPTS",
                self.redemption_receipts
                    .values()
                    .map(RedemptionReceipt::public_record)
                    .collect(),
            ),
            route_cap_root: collection_root(
                "ROUTE-CAPS",
                self.route_caps
                    .values()
                    .map(RouteCap::public_record)
                    .collect(),
            ),
            rebate_accounting_root: collection_root(
                "REBATE-ACCOUNTING",
                self.rebate_accounting
                    .values()
                    .map(RebateAccounting::public_record)
                    .collect(),
            ),
            redaction_budget_root: collection_root(
                "REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record)
                    .collect(),
            ),
            operator_summary_root: collection_root(
                "OPERATOR-SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record)
                    .collect(),
            ),
            runtime_event_root: collection_root(
                "RUNTIME-EVENTS",
                self.runtime_events
                    .iter()
                    .map(RuntimeEvent::public_record)
                    .collect(),
            ),
            public_record_root: runtime_empty_root("PUBLIC-RECORDS"),
        }
    }
    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        self.public_records
            .insert("counters".to_string(), self.counters.public_record());
        self.public_records
            .insert("roots".to_string(), self.roots.public_record());
        insert_records(
            &mut self.public_records,
            "cohort",
            &self.sponsor_cohorts,
            SponsorCohort::public_record,
        );
        insert_records(
            &mut self.public_records,
            "route",
            &self.voucher_routes,
            VoucherRoute::public_record,
        );
        insert_records(
            &mut self.public_records,
            "lot",
            &self.sealed_voucher_lots,
            SealedVoucherLot::public_record,
        );
        insert_records(
            &mut self.public_records,
            "attestation",
            &self.pq_sponsor_attestations,
            PqSponsorAttestation::public_record,
        );
        insert_records(
            &mut self.public_records,
            "receipt",
            &self.redemption_receipts,
            RedemptionReceipt::public_record,
        );
        insert_records(
            &mut self.public_records,
            "cap",
            &self.route_caps,
            RouteCap::public_record,
        );
        insert_records(
            &mut self.public_records,
            "rebate",
            &self.rebate_accounting,
            RebateAccounting::public_record,
        );
        insert_records(
            &mut self.public_records,
            "redaction",
            &self.redaction_budgets,
            RedactionBudget::public_record,
        );
        insert_records(
            &mut self.public_records,
            "summary",
            &self.operator_summaries,
            OperatorSummary::public_record,
        );
        for event in &self.runtime_events {
            self.public_records
                .insert(format!("event:{}", event.event_id), event.public_record());
        }
    }
    fn public_record_without_state_root(&self) -> Value {
        json!({ "kind": "private_l2_low_fee_pq_confidential_multi_sponsor_fee_voucher_router_runtime", "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "config": self.config.public_record(), "roots": self.roots.public_record(), "counters": self.counters.public_record(), "sponsor_cohorts": self.sponsor_cohorts.values().map(SponsorCohort::public_record).collect::<Vec<_>>(), "voucher_routes": self.voucher_routes.values().map(VoucherRoute::public_record).collect::<Vec<_>>(), "sealed_voucher_lots": self.sealed_voucher_lots.values().map(SealedVoucherLot::public_record).collect::<Vec<_>>(), "pq_sponsor_attestations": self.pq_sponsor_attestations.values().map(PqSponsorAttestation::public_record).collect::<Vec<_>>(), "redemption_receipts": self.redemption_receipts.values().map(RedemptionReceipt::public_record).collect::<Vec<_>>(), "route_caps": self.route_caps.values().map(RouteCap::public_record).collect::<Vec<_>>(), "rebate_accounting": self.rebate_accounting.values().map(RebateAccounting::public_record).collect::<Vec<_>>(), "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(), "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(), "runtime_events": self.runtime_events.iter().map(RuntimeEvent::public_record).collect::<Vec<_>>(), "public_records": self.public_records })
    }
}
impl State {
    pub fn generated_operator_bucket_001_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (1u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":1,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_001_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_001_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_002_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (2u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":2,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_002_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_002_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_003_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (3u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":3,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_003_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_003_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_004_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (4u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":4,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_004_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_004_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_005_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (5u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":5,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_005_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_005_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_006_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (6u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":6,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_006_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_006_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_007_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (7u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":7,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_007_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_007_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_008_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (8u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":8,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_008_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_008_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_009_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (9u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":9,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_009_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_009_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_010_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (10u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":10,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_010_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_010_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_011_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (11u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":11,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_011_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_011_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_012_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (12u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":12,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_012_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_012_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_013_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (13u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":13,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_013_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_013_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_014_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (14u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":14,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_014_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_014_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_015_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (15u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":15,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_015_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_015_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_016_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (16u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":16,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_016_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_016_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_017_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (17u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":17,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_017_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_017_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_018_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (18u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":18,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_018_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_018_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_019_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (19u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":19,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_019_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_019_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_020_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (20u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":20,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_020_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_020_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_021_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (21u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":21,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_021_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_021_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_022_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (22u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":22,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_022_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_022_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_023_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (23u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":23,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_023_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_023_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_024_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (24u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":24,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_024_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_024_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_025_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (25u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":25,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_025_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_025_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_026_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (26u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":26,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_026_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_026_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_027_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (27u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":27,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_027_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_027_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_028_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (28u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":28,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_028_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_028_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_029_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (29u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":29,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_029_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_029_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_030_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (30u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":30,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_030_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_030_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_031_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (31u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":31,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_031_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_031_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_032_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (32u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":32,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_032_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_032_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_033_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (33u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":33,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_033_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_033_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_034_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (34u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":34,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_034_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_034_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_035_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (35u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":35,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_035_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_035_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_036_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (36u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":36,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_036_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_036_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_037_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (37u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":37,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_037_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_037_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_038_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (38u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":38,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_038_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_038_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_039_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (39u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":39,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_039_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_039_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_040_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (40u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":40,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_040_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_040_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_041_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (41u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":41,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_041_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_041_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_042_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (42u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":42,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_042_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_042_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_043_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (43u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":43,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_043_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_043_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_044_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (44u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":44,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_044_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_044_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_045_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (45u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":45,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_045_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_045_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_046_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (46u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":46,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_046_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_046_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_047_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (47u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":47,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_047_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_047_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_048_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (48u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":48,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_048_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_048_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_049_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (49u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":49,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_049_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_049_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_050_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (50u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":50,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_050_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_050_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_051_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (51u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":51,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_051_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_051_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_052_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (52u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":52,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_052_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_052_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_053_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (53u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":53,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_053_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_053_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_054_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (54u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":54,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_054_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_054_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_055_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (55u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":55,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_055_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_055_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_056_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (56u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":56,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_056_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_056_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_057_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (57u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":57,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_057_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_057_record(),
        )
    }
}

impl State {
    pub fn generated_operator_bucket_058_record(&self) -> Value {
        let bucket_size = self.config.operator_bucket_size.max(1);
        let route_count = self.voucher_routes.len() as u64;
        let receipt_count = self.redemption_receipts.len() as u64;
        let bucket_floor = (58u64 - 1).saturating_mul(bucket_size);
        json!({"kind":"operator_bucket","bucket_index":58,"protocol_version":PROTOCOL_VERSION,"bucket_floor":bucket_floor,"bucket_ceiling":bucket_floor.saturating_add(bucket_size),"route_count":route_count,"receipt_count":receipt_count,"low_fee_score_bps":self.low_fee_score_bps(),"privacy_score_bps":self.privacy_score_bps(),"speed_score_bps":self.speed_score_bps(),"pq_score_bps":self.pq_score_bps(),"state_root":self.state_root})
    }

    pub fn generated_operator_bucket_058_root(&self) -> String {
        runtime_root(
            "GENERATED-OPERATOR-BUCKET",
            &self.generated_operator_bucket_058_record(),
        )
    }
}

pub fn devnet() -> State {
    demo()
}

pub fn demo() -> State {
    let config = Config::default();
    let mut state = State::new(config.clone());
    let cohort_a = SponsorCohort::new("cohort-low-fee-alpha", 1_000, 12, 900_000, &config);
    let cohort_b = SponsorCohort::new("cohort-fast-private-beta", 1_002, 9, 640_000, &config);
    state
        .insert_sponsor_cohort(cohort_a)
        .expect("valid devnet cohort alpha");
    state
        .insert_sponsor_cohort(cohort_b)
        .expect("valid devnet cohort beta");
    state
        .insert_voucher_lot(SealedVoucherLot::new(
            "lot-alpha-0001",
            "cohort-low-fee-alpha",
            360_000,
            1_004,
            &config,
        ))
        .expect("valid devnet lot alpha");
    state
        .insert_voucher_lot(SealedVoucherLot::new(
            "lot-beta-0001",
            "cohort-fast-private-beta",
            240_000,
            1_006,
            &config,
        ))
        .expect("valid devnet lot beta");
    state
        .insert_route_cap(RouteCap::new(
            "cap-alpha-epoch-1",
            "cohort-low-fee-alpha",
            1,
            &config,
        ))
        .expect("valid alpha cap");
    state
        .insert_route_cap(RouteCap::new(
            "cap-beta-epoch-1",
            "cohort-fast-private-beta",
            1,
            &config,
        ))
        .expect("valid beta cap");
    state
        .insert_rebate_account(RebateAccounting::new(
            "rebate-alpha-sponsor-root",
            "cohort-low-fee-alpha",
        ))
        .expect("valid alpha rebate account");
    state
        .insert_rebate_account(RebateAccounting::new(
            "rebate-beta-sponsor-root",
            "cohort-fast-private-beta",
        ))
        .expect("valid beta rebate account");
    let mut route_a = VoucherRoute::new(
        "route-alpha-0001",
        "cohort-low-fee-alpha",
        "cap-alpha-epoch-1",
        "lot-alpha-0001",
        24_000,
        1_008,
        &config,
    );
    route_a
        .attach_sponsor_commitment("sponsor-alpha-commitment-a", &config)
        .expect("sponsor fanout");
    route_a
        .attach_sponsor_commitment("sponsor-alpha-commitment-b", &config)
        .expect("sponsor fanout");
    state.reserve_route(route_a).expect("valid route alpha");
    let mut route_b = VoucherRoute::new(
        "route-beta-0001",
        "cohort-fast-private-beta",
        "cap-beta-epoch-1",
        "lot-beta-0001",
        12_500,
        1_009,
        &config,
    );
    route_b.expected_latency_ms = 320;
    route_b
        .attach_sponsor_commitment("sponsor-beta-commitment-a", &config)
        .expect("sponsor fanout");
    state.reserve_route(route_b).expect("valid route beta");
    let route_alpha_root = state
        .voucher_routes
        .get("route-alpha-0001")
        .expect("route exists")
        .route_root();
    state
        .accept_attestation(PqSponsorAttestation::new(
            "att-alpha-0001",
            "cohort-low-fee-alpha",
            route_alpha_root,
            1_010,
            &config,
        ))
        .expect("valid alpha attestation");
    let route_beta_root = state
        .voucher_routes
        .get("route-beta-0001")
        .expect("route exists")
        .route_root();
    state
        .accept_attestation(PqSponsorAttestation::new(
            "att-beta-0001",
            "cohort-fast-private-beta",
            route_beta_root,
            1_011,
            &config,
        ))
        .expect("valid beta attestation");
    state
        .redeem_route("route-alpha-0001", "receipt-alpha-0001", 1_012)
        .expect("valid alpha redemption");
    state
        .redeem_route("route-beta-0001", "receipt-beta-0001", 1_013)
        .expect("valid beta redemption");
    let subject_root = state.roots.redemption_receipt_root.clone();
    state.insert_redaction_budget(RedactionBudget::new(
        "redaction-receipts-epoch-1",
        subject_root,
        1,
        256,
    ));
    state
        .apply_redaction_budget("redaction-receipts-epoch-1", 12)
        .expect("valid redaction budget");
    state.publish_operator_summary("summary-operator-epoch-1", SummaryAudience::Operator, 1_014);
    state
}

pub fn public_record(state: &State) -> Value {
    let mut record = state.public_record_without_state_root();
    if let Value::Object(ref mut object) = record {
        object.insert(
            "state_root".to_string(),
            Value::String(state.state_root.clone()),
        );
    }
    record
}

pub fn state_root(state: &State) -> String {
    private_l2_low_fee_pq_confidential_multi_sponsor_fee_voucher_router_state_root_from_record(
        &state.public_record_without_state_root(),
    )
}

pub fn private_l2_low_fee_pq_confidential_multi_sponsor_fee_voucher_router_state_root_from_record(
    record: &Value,
) -> String {
    runtime_root("STATE", record)
}

fn insert_records<T>(
    records: &mut BTreeMap<String, Value>,
    prefix: &str,
    values: &BTreeMap<String, T>,
    record_fn: fn(&T) -> Value,
) {
    for (id, value) in values {
        records.insert(format!("{prefix}:{id}"), record_fn(value));
    }
}
fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &records)
}
fn map_root(domain: &str, records: &BTreeMap<String, Value>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    collection_root(domain, leaves)
}
fn runtime_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("{PROTOCOL_VERSION}:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}
fn runtime_empty_root(domain: &str) -> String {
    domain_hash(&format!("{PROTOCOL_VERSION}:{domain}:empty"), &[], 32)
}
fn runtime_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{PROTOCOL_VERSION}:{domain}:id"), parts, 16)
}
fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}
